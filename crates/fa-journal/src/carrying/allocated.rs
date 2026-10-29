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

pub(super) fn retained_shape(proposal: &EntryPayload) -> Result<(), Refusal> {
    let declared = basis(proposal)?;
    let ranges = settlement_ranges(proposal)?;
    if declared.items.len() != ranges.len()
        || declared
            .items
            .iter()
            .zip(ranges)
            .any(|(row, range)| usize::from(row.applying_ordinal) != range.start)
    {
        return Err(invalid(
            "retained valuation release does not cover its complete settlement components",
        ));
    }
    for release in &declared.items {
        check_release(proposal, release)?;
    }
    Ok(())
}

pub(crate) fn covers_valuation_account(
    proposal: &EntryPayload,
    source: VId,
    route: &crate::chart::FxRevaluationRoute,
) -> Result<(), Refusal> {
    let declared = basis(proposal)?;
    let ranges = settlement_ranges(proposal)?;
    let mut covered = BTreeSet::new();
    for release in &declared.items {
        if release.valuation_account != route.valuation_account {
            continue;
        }
        let range = ranges
            .iter()
            .find(|range| range.start == usize::from(release.applying_ordinal))
            .ok_or_else(|| invalid("valuation release has no authenticated component"))?;
        if proposal.legs[range.start].account_ref != source
            || release.unrealized_account != route.unrealized_account
        {
            return Err(invalid(
                "a valuation leaf is used by another source's release",
            ));
        }
        check_release(proposal, release)?;
        if release.valuation_relief.mantissa != 0 {
            covered.insert(range.end - 2);
        }
    }
    if proposal.legs.iter().enumerate().any(|(ordinal, leg)| {
        leg.account_ref == route.valuation_account && !covered.contains(&ordinal)
    }) {
        return Err(invalid(
            "the dedicated valuation leaf contains a settlement leg outside its exact allocated release",
        ));
    }
    Ok(())
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
    let legs = &proposal.legs[range];
    let tail = release_legs(&legs[0], expected)?;
    if tail.len() > legs.len() || !legs.ends_with(&tail) {
        return Err(invalid(
            "valuation release must explicitly reverse the allocated valuation and unrealized accounts",
        ));
    }
    if expected.valuation_account == expected.unrealized_account
        || legs[..legs.len() - tail.len()].iter().any(|leg| {
            leg.account_ref == expected.valuation_account
                || leg.account_ref == expected.unrealized_account
        })
    {
        return Err(invalid(
            "valuation and unrealized destinations must be distinct from every settlement core account",
        ));
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
    proposal.extensions.push((
        FX_SETTLEMENT_VALUATION_EXTENSION,
        FxSettlementValuationBasis {
            items: vec![release],
        }
        .canonical_bytes()
        .map_err(invalid)?,
    ));
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
    if declared.items.len() != ranges.len() {
        return Err(invalid(
            "every allocated settlement component requires exactly one release basis",
        ));
    }
    let mut ordinary = proposal.clone();
    ordinary.legs.clear();
    ordinary.extensions.clear();
    let mut entities = Vec::new();
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
        ordinary
            .legs
            .extend_from_slice(&proposal.legs[range.start..end]);
        entities.extend_from_slice(
            leg_entities
                .get(range.start..end)
                .ok_or_else(|| invalid("allocated settlement entity closure is incomplete"))?,
        );
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
