//! Explicit valuation releases accompany, and never replace, historical-cost
//! settlement legs. Every amount is an assertion checked against the source
//! fold; this extension grants no permission to supply a balancing amount.

use super::*;
use fa_model::entry::{FX_ITEM_CARRYING_SCHEMA_MINOR, FX_SETTLEMENT_VALUATION_EXTENSION};
use fa_model::{BaseTotals, FxSettlementValuationBasis, FxSettlementValuationRelease, LegPayload};
use fa_money::UnitRegistry;

pub(crate) fn has_allocated_basis(proposal: &EntryPayload) -> bool {
    proposal
        .extensions
        .iter()
        .any(|(tag, _)| *tag == FX_SETTLEMENT_VALUATION_EXTENSION)
        || proposal
            .base_totals
            .as_ref()
            .is_some_and(|total| total.fx_law_oid == FxLawId::SettlementAllocatedCarrying.oid())
}

pub(crate) fn basis(proposal: &EntryPayload) -> Result<FxSettlementValuationBasis, Refusal> {
    if proposal
        .base_totals
        .as_ref()
        .is_none_or(|total| total.fx_law_oid != FxLawId::SettlementAllocatedCarrying.oid())
    {
        return Err(invalid(
            "valuation-release provenance requires its exact SettlementAllocatedCarrying law",
        ));
    }
    let Some((_, raw)) = proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == FX_SETTLEMENT_VALUATION_EXTENSION)
    else {
        return Err(invalid(
            "allocated settlement requires its complete immutable release basis",
        ));
    };
    FxSettlementValuationBasis::decode(raw).map_err(invalid)
}

/// Parsed immutable release metadata for all items in one recorded group.
/// Keep a failed range law until its original use point: check_release first
/// compares the declaration, while retained_shape and coverage read ranges
/// first. Caching must preserve those refusal priorities.
pub(crate) struct ReleaseIndex {
    declared: FxSettlementValuationBasis,
    by_ordinal: BTreeMap<u16, usize>,
    by_valuation: BTreeMap<VId, Vec<usize>>,
    account_legs: BTreeMap<VId, Vec<usize>>,
    ranges: Result<Vec<core::ops::Range<usize>>, Refusal>,
    range_by_ordinal: BTreeMap<usize, usize>,
}

impl ReleaseIndex {
    pub(crate) fn new(
        proposal: &EntryPayload,
        work: &mut CarryingPopulationWork,
    ) -> Result<Self, Refusal> {
        let declared = basis(proposal)?;
        let ranges = settlement_ranges_counted(proposal, &mut work.settlement_legs_examined);
        let range_by_ordinal = ranges.as_ref().map_or_else(
            |_| BTreeMap::new(),
            |ranges| {
                ranges
                    .iter()
                    .enumerate()
                    .map(|(index, range)| (range.start, index))
                    .collect()
            },
        );
        let mut by_ordinal = BTreeMap::new();
        let mut by_valuation: BTreeMap<VId, Vec<usize>> = BTreeMap::new();
        for (index, release) in declared.items.iter().enumerate() {
            work.release_items_examined += 1;
            by_ordinal.insert(release.applying_ordinal, index);
            by_valuation
                .entry(release.valuation_account)
                .or_default()
                .push(index);
        }
        let mut account_legs: BTreeMap<VId, Vec<usize>> = BTreeMap::new();
        for (ordinal, leg) in proposal.legs.iter().enumerate() {
            work.release_legs_examined += 1;
            account_legs
                .entry(leg.account_ref)
                .or_default()
                .push(ordinal);
        }
        Ok(Self {
            declared,
            by_ordinal,
            by_valuation,
            account_legs,
            ranges,
            range_by_ordinal,
        })
    }

    fn ranges(&self) -> Result<&[core::ops::Range<usize>], Refusal> {
        self.ranges
            .as_ref()
            .map(Vec::as_slice)
            .map_err(Clone::clone)
    }

    pub(super) fn retained_shape(
        &self,
        proposal: &EntryPayload,
        work: &mut CarryingPopulationWork,
    ) -> Result<(), Refusal> {
        let ranges = self.ranges()?;
        if self.declared.items.len() != ranges.len() {
            return Err(invalid(
                "retained valuation release does not cover its complete settlement components",
            ));
        }
        for (release, range) in self.declared.items.iter().zip(ranges) {
            work.release_items_examined += 1;
            if usize::from(release.applying_ordinal) != range.start {
                return Err(invalid(
                    "retained valuation release does not cover its complete settlement components",
                ));
            }
        }
        for release in &self.declared.items {
            self.check_release(proposal, release, work)?;
        }
        Ok(())
    }

    pub(super) fn valuation_accounts(&self) -> impl Iterator<Item = VId> + '_ {
        self.by_valuation
            .keys()
            .chain(self.account_legs.keys())
            .copied()
    }

    pub(crate) fn covers_valuation_account(
        &self,
        proposal: &EntryPayload,
        source: VId,
        route: &crate::chart::FxRevaluationRoute,
        work: &mut CarryingPopulationWork,
    ) -> Result<(), Refusal> {
        let ranges = self.ranges()?;
        let mut covered = BTreeSet::new();
        if let Some(releases) = self.by_valuation.get(&route.valuation_account) {
            for &index in releases {
                work.release_items_examined += 1;
                let release = &self.declared.items[index];
                let range = self
                    .range_by_ordinal
                    .get(&usize::from(release.applying_ordinal))
                    .map(|index| &ranges[*index])
                    .ok_or_else(|| invalid("valuation release has no authenticated component"))?;
                if proposal.legs[range.start].account_ref != source
                    || release.unrealized_account != route.unrealized_account
                {
                    return Err(invalid(
                        "a valuation leaf is used by another source's release",
                    ));
                }
                self.check_release(proposal, release, work)?;
                if release.valuation_relief.mantissa != 0 {
                    covered.insert(range.end - 2);
                }
            }
        }
        if let Some(legs) = self.account_legs.get(&route.valuation_account) {
            for ordinal in legs {
                work.release_legs_examined += 1;
                if !covered.contains(ordinal) {
                    return Err(invalid(
                        "the dedicated valuation leaf contains a settlement leg outside its exact allocated release",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn check_release(
        &self,
        proposal: &EntryPayload,
        expected: &FxSettlementValuationRelease,
        work: &mut CarryingPopulationWork,
    ) -> Result<(), Refusal> {
        work.release_items_examined += 1;
        if self
            .by_ordinal
            .get(&expected.applying_ordinal)
            .map(|index| &self.declared.items[*index])
            != Some(expected)
        {
            return Err(invalid(
                "valuation release or its original carrying source differs from retained history",
            ));
        }
        let ranges = self.ranges()?;
        let range = self
            .range_by_ordinal
            .get(&usize::from(expected.applying_ordinal))
            .map(|index| &ranges[*index])
            .ok_or_else(|| invalid("valuation release names no complete settlement component"))?;
        check_release_legs(&proposal.legs[range.clone()], expected, work)
    }

    pub(super) fn ranges_valid(&self) -> bool {
        self.ranges.is_ok()
    }
}

pub(super) fn retained_shape(proposal: &EntryPayload) -> Result<(), Refusal> {
    let mut work = CarryingPopulationWork::default();
    ReleaseIndex::new(proposal, &mut work)?.retained_shape(proposal, &mut work)
}

pub(crate) fn covers_valuation_account(
    proposal: &EntryPayload,
    source: VId,
    route: &crate::chart::FxRevaluationRoute,
) -> Result<(), Refusal> {
    let mut work = CarryingPopulationWork::default();
    ReleaseIndex::new(proposal, &mut work)?
        .covers_valuation_account(proposal, source, route, &mut work)
}

pub(super) fn release_basis(
    applying_ordinal: usize,
    source_digest: [u8; 32],
    historical_relief: Amount,
    total_relief: Amount,
    route: Option<crate::chart::FxRevaluationRoute>,
    routes_entry: Option<VId>,
    routes_digest: Option<[u8; 32]>,
) -> Result<FxSettlementValuationRelease, Refusal> {
    let (Some(route), Some(routes_entry), Some(routes_digest)) =
        (route, routes_entry, routes_digest)
    else {
        return Err(invalid(
            "allocated settlement has no authenticated item allocation and route",
        ));
    };
    Ok(FxSettlementValuationRelease {
        applying_ordinal: u16::try_from(applying_ordinal).map_err(invalid)?,
        source_digest,
        historical_relief,
        total_relief,
        valuation_relief: total_relief
            .checked_sub(historical_relief)
            .map_err(invalid)?,
        routes_entry,
        routes_digest,
        valuation_account: route.valuation_account,
        unrealized_account: route.unrealized_account,
    })
}

fn release_legs(
    applying: &LegPayload,
    release: &FxSettlementValuationRelease,
) -> Result<Vec<LegPayload>, Refusal> {
    if release.valuation_relief.mantissa == 0 {
        return Ok(Vec::new());
    }
    let magnitude = release
        .valuation_relief
        .mantissa
        .checked_abs()
        .ok_or_else(|| invalid("valuation release magnitude overflow"))?;
    let side = if release.valuation_relief.mantissa > 0 {
        applying.side
    } else {
        applying.side.flipped()
    };
    let amount = Amount::new(release.valuation_relief.unit, magnitude);
    Ok([
        (release.valuation_account, side),
        (release.unrealized_account, side.flipped()),
    ]
    .into_iter()
    .map(|(account, side)| {
        let mut leg = LegPayload::simple(side, account, amount);
        leg.base_amount = Some(amount);
        leg.dimension_set = applying.dimension_set.clone();
        leg
    })
    .collect())
}

pub(crate) fn check_release(
    proposal: &EntryPayload,
    expected: &FxSettlementValuationRelease,
) -> Result<(), Refusal> {
    if proposal
        .base_totals
        .as_ref()
        .is_none_or(|total| total.fx_law_oid != FxLawId::SettlementAllocatedCarrying.oid())
    {
        return Err(invalid(
            "allocated valuation relief requires SettlementAllocatedCarrying",
        ));
    }
    let declared = basis(proposal)?;
    if declared
        .items
        .iter()
        .find(|item| item.applying_ordinal == expected.applying_ordinal)
        != Some(expected)
    {
        return Err(invalid(
            "valuation release or its original carrying source differs from retained history",
        ));
    }
    let range = settlement_ranges(proposal)?
        .into_iter()
        .find(|range| range.start == usize::from(expected.applying_ordinal))
        .ok_or_else(|| invalid("valuation release names no complete settlement component"))?;
    check_release_legs(
        &proposal.legs[range],
        expected,
        &mut CarryingPopulationWork::default(),
    )
}

fn check_release_legs(
    legs: &[LegPayload],
    expected: &FxSettlementValuationRelease,
    work: &mut CarryingPopulationWork,
) -> Result<(), Refusal> {
    let tail = release_legs(&legs[0], expected)?;
    if tail.len() > legs.len() || !legs.ends_with(&tail) {
        return Err(invalid(
            "valuation release must explicitly reverse the allocated valuation and unrealized accounts",
        ));
    }
    if expected.valuation_account == expected.unrealized_account {
        return Err(invalid(
            "valuation and unrealized destinations must be distinct from every settlement core account",
        ));
    }
    for leg in &legs[..legs.len() - tail.len()] {
        work.release_legs_examined += 1;
        if leg.account_ref == expected.valuation_account
            || leg.account_ref == expected.unrealized_account
        {
            return Err(invalid(
                "valuation and unrealized destinations must be distinct from every settlement core account",
            ));
        }
    }
    Ok(())
}

pub(super) fn append_release(
    proposal: &mut EntryPayload,
    release: FxSettlementValuationRelease,
) -> Result<(), Refusal> {
    let tail = release_legs(&proposal.legs[0], &release)?;
    proposal.legs.extend(tail);
    proposal.schema_minor = proposal.schema_minor.max(FX_ITEM_CARRYING_SCHEMA_MINOR);
    let bytes = FxSettlementValuationBasis {
            items: vec![release],
        }
        .canonical_bytes()
        .map_err(invalid)?;
    match proposal.extensions.binary_search_by_key(&FX_SETTLEMENT_VALUATION_EXTENSION, |(tag, _)| *tag) {
        Ok(index) => proposal.extensions[index].1 = bytes,
        Err(index) => proposal.extensions.insert(index, (FX_SETTLEMENT_VALUATION_EXTENSION, bytes)),
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).map_err(invalid)?;
    let totals = proposal
        .base_totals
        .as_mut()
        .ok_or_else(|| invalid("allocated settlement has no FX claim"))?;
    totals.fx_law_oid = FxLawId::SettlementAllocatedCarrying.oid();
    recompute_totals(totals, &proposal.legs)?;
    proposal.validate().map_err(invalid)
}

fn recompute_totals(totals: &mut BaseTotals, legs: &[LegPayload]) -> Result<(), Refusal> {
    totals.debits = 0;
    totals.credits = 0;
    for leg in legs {
        let amount = leg
            .base_amount
            .ok_or_else(|| invalid("allocated settlement leg has no valuation"))?;
        let sum = if leg.side == Side::Debit {
            &mut totals.debits
        } else {
            &mut totals.credits
        };
        *sum = sum
            .checked_add(amount.mantissa)
            .ok_or_else(|| invalid("allocated settlement base total overflow"))?;
    }
    Ok(())
}

pub(crate) fn verify_allocated_fx_structure(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    proposal: &EntryPayload,
    spec: &crate::genesis::BookSpec,
    units: &UnitRegistry,
    leg_entities: &[Option<String>],
    rates: &[FxRateDocument],
) -> Result<(), Refusal> {
    let declared = basis(proposal)?;
    let ranges = settlement_ranges(proposal)?;
    let terms = differences::bound_terms(proposal, &ranges)?;
    if declared.items.len() != ranges.len() {
        return Err(invalid(
            "every allocated settlement component requires exactly one release basis",
        ));
    }
    let mut ordinary = proposal.clone();
    ordinary.legs.clear();
    ordinary.extensions.clear();
    let mut entities = Vec::new();
    let mut ordinary_terms = fa_model::FxSettlementTerms { components: Vec::new() };
    for (range, release) in ranges.into_iter().zip(&declared.items) {
        if usize::from(release.applying_ordinal) != range.start {
            return Err(invalid(
                "valuation release ordinals do not match settlement execution order",
            ));
        }
        check_release(proposal, release)?;
        let tail = usize::from(release.valuation_relief.mantissa != 0) * 2;
        let end = range
            .end
            .checked_sub(tail)
            .ok_or_else(|| invalid("allocated settlement release tail is incomplete"))?;
        if let Some(component) = terms.as_ref().and_then(|terms| terms.component(range.start)) {
            let mut component = component.clone();
            differences::rebase(&mut component, range.start, ordinary.legs.len())?;
            ordinary_terms.components.push(component);
        }
        ordinary
            .legs
            .extend_from_slice(&proposal.legs[range.start..end]);
        entities.extend_from_slice(
            leg_entities
                .get(range.start..end)
                .ok_or_else(|| invalid("allocated settlement entity closure is incomplete"))?,
        );
    }
    if !ordinary_terms.components.is_empty() {
        ordinary.set_fx_settlement_terms(&ordinary_terms).map_err(invalid)?;
    }
    ordinary.unit_totals = EntryPayload::fold_unit_totals(&ordinary.legs).map_err(invalid)?;
    let totals = ordinary
        .base_totals
        .as_mut()
        .ok_or_else(|| invalid("allocated settlement has no FX totals"))?;
    totals.fx_law_oid = FxLawId::SettlementCarryingBasis.oid();
    recompute_totals(totals, &ordinary.legs)?;
    crate::fx::verify_realized_fx_settlement(budget, &ordinary, spec, units, &entities, rates)
}
