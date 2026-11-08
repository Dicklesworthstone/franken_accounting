//! Source-bound RemainingCarryingValue replay, independent of journal code.
//!
//! A recorded application consumes its target's remaining native and base
//! amounts. Exact reversals negate the recorded effect, including a reversal
//! of a reversal; they never reprice an old application against a new pool.

mod allocated;
mod terms;

use super::{
    BookParameters, LeafEnvelope, Leg, ParsedEntry, Rate, Reader, ReportError, failed, law_oid,
    metadata, registry,
};
use std::collections::{BTreeMap, BTreeSet};

type Target = (usize, u16);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct AllocationRoute {
    pub(super) entry: u128,
    pub(super) digest: [u8; 32],
    pub(super) valuation: u128,
    pub(super) unrealized: u128,
}

pub(super) struct AllocationUpdate {
    pub(super) target: Target,
    pub(super) valuation: i128,
    pub(super) route: AllocationRoute,
    pub(super) date: i32,
}

#[derive(Clone)]
struct ReleaseCoverage {
    source: u128,
    route: AllocationRoute,
    valuation_ordinal: Option<usize>,
}

/// Checked carrying components, retained only at publications that change a
/// target. Revaluation and allocated settlement consume these snapshots
/// instead of trusting amounts or source digests asserted by their own bases.
#[derive(Clone, Copy)]
pub(super) struct Remaining {
    pub(super) native: i128,
    pub(super) historical: i128,
    pub(super) valuation: i128,
    pub(super) allocated: Option<AllocationRoute>,
    pub(super) source_digest: [u8; 32],
    pub(super) latest_effective: i32,
}

#[derive(Default)]
pub(super) struct CheckedCarrying {
    pub(super) changes: BTreeMap<Target, Vec<(u64, Remaining)>>,
    pub(super) reversals: BTreeMap<usize, usize>,
    allocations: BTreeSet<usize>,
    releases: BTreeMap<usize, Vec<ReleaseCoverage>>,
}

impl CheckedCarrying {
    pub(super) fn covers_valuation(
        &self,
        index: usize,
        source: u128,
        valuation: u128,
        unrealized: u128,
        legs: &[Vec<Leg>],
    ) -> Result<(), ReportError> {
        let releases = self.releases.get(&index).ok_or_else(|| {
            invalid("dedicated valuation history contains an unrelated or unchecked adjustment")
        })?;
        check_release_coverage(releases, index, source, valuation, unrealized, legs)
    }

    fn record(&mut self, target: Target, sequence: u64, state: &Carrying) {
        self.changes.entry(target).or_default().push((
            sequence,
            Remaining {
                native: state.native,
                historical: state.base,
                valuation: state.valuation,
                allocated: state.allocated,
                source_digest: state.source_hash.finalize(),
                latest_effective: state.latest_effective,
            },
        ));
    }

    pub(super) fn remaining(&self, target: Target, at: u64) -> Option<Remaining> {
        let changes = self.changes.get(&target)?;
        let end = changes.partition_point(|(sequence, _)| *sequence <= at);
        end.checked_sub(1).map(|last| changes[last].1)
    }

    /// Effective-date selection is needed for the complete closing
    /// population; the full-prefix check separately rejects a later undo.
    pub(super) fn is_live(
        &self,
        source: usize,
        at: u64,
        day: i32,
        envelopes: &[LeafEnvelope],
    ) -> Result<bool, ReportError> {
        let mut live = true;
        let mut parent = source;
        while let Some(&child) = self.reversals.get(&parent) {
            if envelopes[child].commit_seq > at {
                break;
            }
            if effective(&envelopes[child])? <= day {
                if effective(&envelopes[parent])? > day {
                    return Err(invalid(
                        "a selected reversal's parent is outside the effective population",
                    ));
                }
                live = !live;
            }
            parent = child;
        }
        Ok(live)
    }
}

fn check_release_coverage(
    releases: &[ReleaseCoverage],
    index: usize,
    source: u128,
    valuation: u128,
    unrealized: u128,
    legs: &[Vec<Leg>],
) -> Result<(), ReportError> {
    let mut covered = BTreeSet::new();
    for release in releases
        .iter()
        .filter(|release| release.route.valuation == valuation)
    {
        if release.source != source || release.route.unrealized != unrealized {
            return Err(invalid(
                "a valuation release belongs to another source or route",
            ));
        }
        covered.extend(release.valuation_ordinal);
    }
    if legs[index]
        .iter()
        .enumerate()
        .any(|(ordinal, leg)| leg.account == valuation && !covered.contains(&ordinal))
    {
        return Err(invalid(
            "dedicated valuation account contains an uncovered settlement leg",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Effect {
    target: Target,
    native: i128,
    base: i128,
    valuation: i128,
}
struct Carrying {
    original_native: i128,
    original_base: i128,
    native: i128,
    base: i128,
    valuation: i128,
    allocated: Option<AllocationRoute>,
    source_hash: crate::blake3::Hasher,
    latest_effective: i32,
}
struct History<'a> {
    spec: &'a BookParameters,
    registry: &'a registry::FunctionalRegistry,
    rates: &'a BTreeMap<[u8; 32], Rate>,
    envelopes: &'a [LeafEnvelope],
    legs: &'a [Vec<Leg>],
    parsed: &'a BTreeMap<usize, ParsedEntry>,
    migration_activations: &'a BTreeMap<u64, u64>,
    releases: BTreeMap<usize, Vec<allocated::Release>>,
    terms: BTreeMap<usize, terms::Components>,
}

pub(super) fn source_hasher(
    identity: u128,
    digest: [u8; 32],
    ordinal: u16,
) -> crate::blake3::Hasher {
    let mut hash = crate::blake3::Hasher::new();
    hash.update(b"fa:allocated-carrying-source:v1");
    hash.update(&identity.to_le_bytes());
    hash.update(&digest);
    hash.update(&ordinal.to_le_bytes());
    hash
}

fn bind_effect(
    state: &mut Carrying,
    index: usize,
    envelopes: &[LeafEnvelope],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
) {
    state
        .source_hash
        .update(&envelopes[index].commit_seq.to_le_bytes());
    state
        .source_hash
        .update(&infos[&index].identity.to_le_bytes());
    state.source_hash.update(&envelopes[index].record_digest);
}

fn invalid(detail: &str) -> ReportError {
    failed("functional_carrying", detail)
}
fn sub(a: i128, b: i128) -> Result<i128, ReportError> {
    a.checked_sub(b)
        .ok_or_else(|| invalid("remaining carrying amount overflow"))
}
fn negate(value: i128) -> Result<i128, ReportError> {
    value
        .checked_neg()
        .ok_or_else(|| invalid("recorded carrying undo overflow"))
}
fn effective(envelope: &LeafEnvelope) -> Result<i32, ReportError> {
    envelope
        .effective_day
        .ok_or_else(|| invalid("a carrying source or application has no effective date"))
}
/// The three independently checked source-bound carrying laws.
fn carries(entry: &ParsedEntry) -> bool {
    entry
        .base
        .as_ref()
        .is_some_and(|claim| [law_oid(4), law_oid(10), law_oid(11)].contains(&claim.law))
}
/// A foreign-unit leg's application outside a carrying law, or any
/// application a reversal authors. Checked whether or not the prefix holds a
/// carrying entry, so such an application never passes vacuously.
fn unsupported_application(
    spec: &BookParameters,
    envelope: &LeafEnvelope,
    entry: &ParsedEntry,
    legs: &[Leg],
) -> bool {
    entry.details.iter().zip(legs).any(|(detail, leg)| {
        !detail.settlements.is_empty()
            && (envelope.class == 4 || leg.unit != spec.base && !carries(entry))
    })
}
fn unsupported_application_error() -> ReportError {
    failed(
        "supported_report",
        "foreign applications require source-bound SettlementCarryingBasis and reversals cannot author fresh applications",
    )
}

/// Decode all declared route epochs, including future-effective maps. The
/// native carrying law refuses aggregate adjustments without an item-level
/// allocation even when the route was declared after the original invoice.
fn add_routes(
    raw: &[u8],
    base: u32,
    routes: &mut BTreeMap<u128, (u128, u128)>,
) -> Result<(), ReportError> {
    let mut r = Reader::new(raw);
    if r.fixed::<13>("fx_routes.magic")? != *b"FA-FX-ROUTES\0" || r.u16("fx_routes.version")? != 1 {
        return Err(invalid("unsupported FX revaluation route declaration"));
    }
    r.i32("fx_routes.effective_from")?;
    if r.u32("fx_routes.base")? != base {
        return Err(invalid("FX route base differs from the functional unit"));
    }
    let count = r.count(4096, 48, "fx_routes.routes")?;
    if count == 0 {
        return Err(invalid("FX revaluation route map is empty"));
    }
    let mut previous = None;
    let mut epoch = BTreeMap::new();
    for _ in 0..count {
        let source = r.u128("fx_routes.source")?;
        let valuation = r.u128("fx_routes.valuation")?;
        let unrealized = r.u128("fx_routes.unrealized")?;
        if previous.is_some_and(|last| last >= source)
            || source == valuation
            || source == unrealized
            || valuation == unrealized
        {
            return Err(invalid(
                "FX routes must be ordered and use distinct accounts",
            ));
        }
        previous = Some(source);
        epoch.insert(source, (valuation, unrealized));
    }
    r.finish("FX revaluation routes")?;
    if routes
        .iter()
        .any(|(source, route)| epoch.get(source) != Some(route))
    {
        return Err(invalid(
            "an established FX source/valuation route cannot be removed or reassigned",
        ));
    }
    *routes = epoch;
    Ok(())
}

impl History<'_> {
    fn initial(
        &self,
        target: Target,
        infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    ) -> Result<Carrying, ReportError> {
        let (source, ordinal) = target;
        let native = self.legs[source][usize::from(ordinal)].mantissa;
        let base = self.parsed[&source].amounts[usize::from(ordinal)];
        Ok(Carrying {
            original_native: native,
            original_base: base,
            native,
            base,
            valuation: 0,
            allocated: None,
            source_hash: source_hasher(
                infos[&source].identity,
                self.envelopes[source].record_digest,
                ordinal,
            ),
            latest_effective: effective(&self.envelopes[source])?,
        })
    }

    fn target(
        &self,
        entry: usize,
        ordinal: usize,
        identities: &BTreeMap<u128, usize>,
    ) -> Result<Target, ReportError> {
        let leg = &self.legs[entry][ordinal];
        let [reference] = self.parsed[&entry].details[ordinal].settlements.as_slice() else {
            return Err(invalid("each FX applying leg must name exactly one target"));
        };
        let target = *identities
            .get(&reference.target)
            .ok_or_else(|| invalid("carrying target identity is absent from the prefix"))?;
        let source_envelope = &self.envelopes[target];
        let envelope = &self.envelopes[entry];
        if reference.digest != source_envelope.record_digest
            || source_envelope.book_id != envelope.book_id
            || source_envelope.branch_id != envelope.branch_id
            || source_envelope.commit_seq >= envelope.commit_seq
            || source_envelope.class == 12
                && self
                    .migration_activations
                    .get(&(target as u64))
                    .is_none_or(|activated| *activated >= envelope.commit_seq)
            || !matches!(source_envelope.class, 1 | 3 | 5..=15)
            || reference.unit != leg.unit
            || reference.amount <= 0
            || reference.amount > leg.mantissa
            || reference.amount != leg.mantissa
                && self.parsed[&entry]
                    .base
                    .as_ref()
                    .is_none_or(|claim| claim.law != law_oid(11))
        {
            return Err(invalid(
                "application must fully name a matching posted target from an earlier publication",
            ));
        }
        let source = self.legs[target]
            .get(usize::from(reference.ordinal))
            .ok_or_else(|| invalid("carrying target leg ordinal is absent"))?;
        let details = &self.parsed[&target].details[usize::from(reference.ordinal)];
        let original = &self.parsed[&target];
        if source.unit == self.spec.base
            || source.unit != leg.unit
            || source.account != leg.account
            || source.debit == leg.debit
            || source.mantissa <= 0
            || details.base_amount.is_none()
            || !details.settlements.is_empty()
            || details.dimensions != self.parsed[&entry].details[ordinal].dimensions
            || original
                .base
                .as_ref()
                .is_none_or(|claim| claim.law != law_oid(1) && claim.law != law_oid(3))
        {
            return Err(invalid(
                "carrying relief requires the opposite side of one original SpotClose/PeriodAverage foreign item with identical dimensions and no outgoing applications",
            ));
        }
        Ok((target, reference.ordinal))
    }

    fn ranges(&self, index: usize) -> Result<Vec<std::ops::Range<usize>>, ReportError> {
        if self.parsed[&index]
            .base
            .as_ref()
            .is_some_and(|claim| claim.law == law_oid(11))
        {
            let ranges: Vec<_> = self.parsed[&index]
                .details
                .iter()
                .zip(&self.legs[index])
                .enumerate()
                .filter(|(_, (detail, leg))| {
                    leg.unit != self.spec.base && !detail.settlements.is_empty()
                })
                .map(|(ordinal, _)| ordinal..ordinal + 1)
                .collect();
            if ranges.is_empty() {
                return Err(invalid(
                    "SettlementSpotCarrying requires a foreign application",
                ));
            }
            return Ok(ranges);
        }
        let mut starts = Vec::new();
        for (ordinal, detail) in self.parsed[&index].details.iter().enumerate() {
            if !detail.settlements.is_empty() {
                starts.push(ordinal);
            }
        }
        if starts.first() != Some(&0) {
            return Err(failed(
                "supported_report",
                "SettlementCarryingBasis requires complete ordered source-bound components beginning with an explicit application",
            ));
        }
        starts.push(self.legs[index].len());
        Ok(starts.windows(2).map(|pair| pair[0]..pair[1]).collect())
    }

    fn component(
        &self,
        index: usize,
        range: std::ops::Range<usize>,
        target: Target,
        carrying: &Carrying,
    ) -> Result<Effect, ReportError> {
        let entry = &self.parsed[&index];
        let claim = entry.base.as_ref().expect("settlement claim checked");
        if claim.law == law_oid(11) {
            return self.spot_component(index, range.start, target, carrying);
        }
        let [rate_oid] = claim.rates.as_slice() else {
            return Err(invalid(
                "settlement requires exactly one authenticated Settlement Rate",
            ));
        };
        let rate = &self.rates[rate_oid];
        let date = effective(&self.envelopes[index])?;
        if claim.residual.is_some()
            || rate.purpose != 4
            || rate.date > date
            || date < carrying.latest_effective
        {
            return Err(invalid(
                "settlement requires no residual, an eligible Settlement Rate, and a date no earlier than the target or any recorded application/undo",
            ));
        }
        let legs = &self.legs[index][range.clone()];
        let details = &entry.details[range.clone()];
        let amounts = &entry.amounts[range.clone()];
        let entities = &entry.entities[range.clone()];
        let settled = &legs[0];
        if settled.unit != rate.quote
            || settled.mantissa > carrying.native
            || carrying.native <= 0
            || entities.iter().any(|entity| entity != &entities[0])
        {
            return Err(invalid(
                "settlement exceeds its open native item or mixes currencies/entities",
            ));
        }
        let relief = if settled.mantissa == carrying.native {
            carrying.base
        } else {
            super::super::arithmetic::convert(
                carrying.base,
                0,
                0,
                settled.mantissa as u128,
                carrying.native as u128,
            )?
        };
        if let Some(differences) = self
            .terms
            .get(&index)
            .and_then(|components| components.get(&range.start))
        {
            return terms::component(self, index, range, target, relief, differences);
        }
        let core = if relief == 0 { 3 } else { 4 };
        if !(core..=core + 1).contains(&legs.len()) || amounts[0] != relief {
            return Err(invalid(
                "settlement shape or recorded relief differs from RemainingCarryingValue",
            ));
        }
        let conversion = &legs[1];
        let cash = &legs[core - 1];
        let expected_cash = super::super::arithmetic::convert(
            settled.mantissa,
            self.registry.units[&rate.quote].scale,
            self.registry.units[&self.spec.base].scale,
            rate.numerator,
            rate.denominator,
        )?;
        if BTreeSet::from([settled.account, conversion.account, cash.account]).len() != 3
            || conversion.unit != settled.unit
            || conversion.mantissa != settled.mantissa
            || conversion.debit == settled.debit
            || amounts[1] != relief
            || cash.unit != self.spec.base
            || cash.debit == settled.debit
            || cash.mantissa != expected_cash
            || amounts[core - 1] != expected_cash
            || details
                .iter()
                .any(|detail| detail.dimensions != details[0].dimensions)
        {
            return Err(invalid(
                "settlement does not reproduce its foreign relief, conversion pair, dimensions and exact Rate-valued cash",
            ));
        }
        if relief != 0 {
            let base_conversion = &legs[2];
            if base_conversion.account != conversion.account
                || base_conversion.unit != self.spec.base
                || base_conversion.debit != settled.debit
                || base_conversion.mantissa != relief
                || amounts[2] != relief
            {
                return Err(invalid(
                    "base conversion leg differs from the recorded carrying relief",
                ));
            }
        }
        let difference = sub(expected_cash, relief)?;
        if difference == 0 {
            if legs.len() != core {
                return Err(invalid("zero realized FX has no additional posting"));
            }
        } else {
            let Some(realized) = legs.get(core) else {
                return Err(invalid(
                    "nonzero realized FX requires its complete explicit posting",
                ));
            };
            let magnitude = difference
                .checked_abs()
                .ok_or_else(|| invalid("realized FX magnitude overflow"))?;
            if BTreeSet::from([
                settled.account,
                conversion.account,
                cash.account,
                realized.account,
            ])
            .len()
                != 4
                || realized.unit != self.spec.base
                || realized.debit
                    != if difference > 0 {
                        settled.debit
                    } else {
                        !settled.debit
                    }
                || realized.mantissa != magnitude
                || amounts[core] != magnitude
            {
                return Err(invalid(
                    "realized FX differs from cash minus exact recorded relief",
                ));
            }
        }
        Ok(Effect {
            target,
            native: settled.mantissa,
            base: relief,
            valuation: 0,
        })
    }

    fn spot_component(
        &self,
        index: usize,
        ordinal: usize,
        target: Target,
        carrying: &Carrying,
    ) -> Result<Effect, ReportError> {
        let entry = &self.parsed[&index];
        let claim = entry.base.as_ref().expect("spot claim checked");
        let leg = &self.legs[index][ordinal];
        let [reference] = entry.details[ordinal].settlements.as_slice() else {
            return Err(invalid("spot application needs one target"));
        };
        let date = effective(&self.envelopes[index])?;
        let mut quotes = claim
            .rates
            .iter()
            .map(|oid| &self.rates[oid])
            .filter(|rate| rate.quote == leg.unit);
        let Some(rate) = quotes.next() else {
            return Err(invalid("spot application has no retained quote"));
        };
        if quotes.next().is_some()
            || rate.purpose != 4
            || rate.date != date
            || rate.base != self.spec.base
            || claim.residual.is_some()
            || date < carrying.latest_effective
            || reference.amount > carrying.native
            || carrying.native <= 0
        {
            return Err(invalid(
                "spot application quote, chronology or remaining native amount differs",
            ));
        }
        let expected = if reference.amount == carrying.native {
            carrying.base
        } else {
            super::super::arithmetic::convert(
                carrying.base,
                0,
                0,
                reference.amount as u128,
                carrying.native as u128,
            )?
        };
        let recorded = super::super::arithmetic::convert(
            reference.amount,
            self.registry.units[&leg.unit].scale,
            self.registry.units[&self.spec.base].scale,
            rate.numerator,
            rate.denominator,
        )?;
        if recorded != expected {
            return Err(invalid(
                "spot quote relief differs from RemainingCarryingValue; explicit FX effects are required",
            ));
        }
        Ok(Effect {
            target,
            native: reference.amount,
            base: recorded,
            valuation: 0,
        })
    }
}

fn set_live(
    root: usize,
    is_live: bool,
    live: &mut BTreeSet<usize>,
    postings: &mut BTreeMap<u128, BTreeSet<(u64, usize)>>,
    envelopes: &[LeafEnvelope],
    legs: &[Vec<Leg>],
) {
    let key = (envelopes[root].commit_seq, root);
    if is_live {
        live.insert(root);
        for leg in &legs[root] {
            postings.entry(leg.account).or_default().insert(key);
        }
    } else {
        live.remove(&root);
        for leg in &legs[root] {
            if let Some(entries) = postings.get_mut(&leg.account) {
                entries.remove(&key);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify(
    spec: &BookParameters,
    registry: &registry::FunctionalRegistry,
    rates: &BTreeMap<[u8; 32], Rate>,
    envelopes: &[LeafEnvelope],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    legs: &[Vec<Leg>],
    parsed: &BTreeMap<usize, ParsedEntry>,
    parents: &BTreeMap<usize, usize>,
    migration_activations: &BTreeMap<u64, u64>,
    revaluations: &super::revaluation::Prepared<'_>,
) -> Result<(), ReportError> {
    let mut checked = CheckedCarrying::default();
    let history = History {
        spec,
        registry,
        rates,
        envelopes,
        legs,
        parsed,
        migration_activations,
        releases: allocated::read_history(spec, registry, envelopes, infos, parsed, parents)?,
        terms: terms::read_history(infos)?,
    };
    if !parsed.values().any(|entry| {
        carries(entry)
            || entry
                .base
                .as_ref()
                .is_some_and(|claim| claim.law == law_oid(9))
    }) {
        if parsed.iter().any(|(&index, entry)| {
            unsupported_application(spec, &envelopes[index], entry, &legs[index])
        }) {
            return Err(unsupported_application_error());
        }
        // Preserve the legacy direct/native reversal scope. Aggregate
        // revaluation still runs both complete source proofs, in publication
        // order, without imposing carrying-only reversal admission rules.
        let mut order: Vec<_> = parsed.keys().copied().collect();
        order.sort_by_key(|index| (envelopes[*index].commit_seq, infos[index].identity));
        for index in order {
            if !revaluations.verify_entry(index, &checked)?.is_empty() {
                return Err(invalid(
                    "item allocation requires the chronological carrying replay",
                ));
            }
        }
        return Ok(());
    }
    let mut identities = BTreeMap::new();
    for (&index, info) in infos {
        for identity in info.identities() {
            if identities
                .insert(identity, index)
                .is_some_and(|other| other != index)
            {
                return Err(invalid(
                    "carrying history has an ambiguous derived entry identity",
                ));
            }
        }
    }
    let mut order: Vec<_> = parsed.keys().copied().collect();
    order.sort_by_key(|index| (envelopes[*index].commit_seq, infos[index].identity));
    let mut roots = BTreeMap::new();
    let mut children = BTreeSet::new();
    for &index in &order {
        if let Some(&parent) = parents.get(&index) {
            if envelopes[parent].commit_seq >= envelopes[index].commit_seq
                || !children.insert(parent)
            {
                return Err(invalid(
                    "carrying reversals require a unique earlier-publication target",
                ));
            }
            checked.reversals.insert(parent, index);
            roots.insert(index, roots[&parent]);
        } else {
            roots.insert(index, index);
        }
        if unsupported_application(spec, &envelopes[index], &parsed[&index], &legs[index]) {
            return Err(unsupported_application_error());
        }
    }
    let mut targets: BTreeMap<Target, Carrying> = BTreeMap::new();
    let mut components: BTreeMap<usize, Vec<(std::ops::Range<usize>, Target)>> = BTreeMap::new();
    for &index in &order {
        if envelopes[index].class == 4 || !carries(&parsed[&index]) {
            continue;
        }
        if !matches!(envelopes[index].class, 1 | 3 | 7) {
            return Err(invalid(
                "entry class cannot originate SettlementCarryingBasis",
            ));
        }
        let law = parsed[&index].base.as_ref().expect("carrying claim").law;
        if law == law_oid(11) && !matches!(envelopes[index].class, 1 | 3) {
            return Err(invalid(
                "entry class cannot originate SettlementSpotCarrying",
            ));
        }
        if law == law_oid(10) && !matches!(envelopes[index].class, 1 | 7) {
            return Err(invalid(
                "entry class cannot originate SettlementAllocatedCarrying",
            ));
        }
        let ranges = history.ranges(index)?;
        if let Some(declarations) = history.terms.get(&index) {
            terms::check_ranges(declarations, &ranges)?;
        }
        if law == law_oid(10) {
            allocated::check_ranges(&history.releases[&index], &ranges)?;
        }
        let mut seen = BTreeSet::new();
        for range in ranges {
            let target = history.target(index, range.start, &identities)?;
            if !seen.insert(target) {
                return Err(invalid(
                    "settlement components must name distinct target legs",
                ));
            }
            if let std::collections::btree_map::Entry::Vacant(slot) = targets.entry(target) {
                slot.insert(history.initial(target, infos)?);
            }
            components.entry(index).or_default().push((range, target));
        }
    }
    let mut effects: BTreeMap<usize, Vec<Effect>> = BTreeMap::new();
    let mut live = BTreeSet::new();
    let mut postings = BTreeMap::<u128, BTreeSet<(u64, usize)>>::new();
    let mut routes = BTreeMap::<u128, (u128, u128)>::new();
    let mut cursor = 0;
    while cursor < order.len() {
        let seq = envelopes[order[cursor]].commit_seq;
        let end =
            cursor + order[cursor..].partition_point(|index| envelopes[*index].commit_seq == seq);
        let group = &order[cursor..end];
        let mut impacts: BTreeMap<Target, Vec<(usize, Effect)>> = BTreeMap::new();
        let mut allocations = Vec::new();
        let mut release_coverage = BTreeMap::new();
        // Every new operation observes the same complete pre-publication
        // prefix. Revaluation itself forbids monetary/schema siblings.
        for &index in group {
            for update in revaluations.verify_entry(index, &checked)? {
                allocations.push((index, update));
            }
            let current = if let Some(&parent) = parents.get(&index) {
                // Reversing a source cannot leave valuation behind, even if
                // this is the final record and no later report reprices it.
                for (_, state) in targets.range((parent, 0)..=(parent, u16::MAX)) {
                    if state.allocated.is_some()
                        && (state.valuation != 0
                            || effective(&envelopes[index])? < state.latest_effective)
                    {
                        return Err(invalid(
                            "source undo strands an allocated valuation or predates its carrying history",
                        ));
                    }
                }
                if let Some(coverage) = checked.releases.get(&parent) {
                    for effect in effects.get(&parent).into_iter().flatten() {
                        if effective(&envelopes[index])? < targets[&effect.target].latest_effective
                        {
                            return Err(invalid(
                                "allocated-settlement undo precedes a later item allocation or application",
                            ));
                        }
                    }
                    release_coverage.insert(index, coverage.clone());
                }
                effects
                    .get(&parent)
                    .into_iter()
                    .flatten()
                    .map(|effect| {
                        Ok(Effect {
                            target: effect.target,
                            native: negate(effect.native)?,
                            base: negate(effect.base)?,
                            valuation: negate(effect.valuation)?,
                        })
                    })
                    .collect::<Result<Vec<_>, ReportError>>()?
            } else {
                let mut current = Vec::new();
                for (range, target) in components.get(&index).into_iter().flatten() {
                    if !live.contains(&target.0) {
                        return Err(invalid(
                            "settlement target is reversed at its precommit prefix",
                        ));
                    }
                    let state = &targets[target];
                    let account = legs[target.0][usize::from(target.1)].account;
                    let source_seq = envelopes[target.0].commit_seq;
                    if routes.get(&account).is_some_and(|(valuation, _)| {
                        postings.get(valuation).is_some_and(|entries| {
                            entries
                                .range((source_seq, 0)..(seq, 0))
                                .any(|(_, adjustment)| {
                                    !checked.allocations.contains(adjustment)
                                        && !checked.releases.contains_key(adjustment)
                                })
                        })
                    }) {
                        return Err(failed(
                            "supported_report",
                            "aggregate valuation adjustments have no registered per-item carrying allocation",
                        ));
                    }
                    let is_allocated = parsed[&index]
                        .base
                        .as_ref()
                        .is_some_and(|claim| claim.law == law_oid(10));
                    if state.allocated.is_some() && !is_allocated {
                        return Err(failed(
                            "supported_report",
                            "this target requires its registered allocated carrying relief",
                        ));
                    }
                    current.push(if is_allocated {
                        let before = seq
                            .checked_sub(1)
                            .ok_or_else(|| invalid("allocated application has sequence zero"))?;
                        let source_digest = checked
                            .remaining(*target, before)
                            .ok_or_else(|| {
                                invalid("allocated application has no checked carrying snapshot")
                            })?
                            .source_digest;
                        allocated::component(
                            &history,
                            index,
                            range.clone(),
                            *target,
                            state,
                            source_digest,
                        )?
                    } else {
                        history.component(index, range.clone(), *target, state)?
                    });
                }
                if let Some(releases) = history.releases.get(&index) {
                    let ranges = components.get(&index).expect("allocated component ranges");
                    let coverage = allocated::coverage(index, releases, ranges, legs);
                    // Dedicated valuation leaves of every retained route are
                    // reserved, including routes for other sources and epochs
                    // whose effective date lies after this payment.
                    for (&source, &(valuation, unrealized)) in &routes {
                        check_release_coverage(
                            &coverage, index, source, valuation, unrealized, legs,
                        )?;
                    }
                    release_coverage.insert(index, coverage);
                }
                current
            };
            for &effect in &current {
                impacts
                    .entry(effect.target)
                    .or_default()
                    .push((index, effect));
            }
            if !current.is_empty() {
                effects.insert(index, current);
            }
        }
        let mut affected_sources: BTreeSet<_> = impacts.keys().map(|target| target.0).collect();
        for (target, changes) in impacts {
            if changes.len() > 1
                && !changes.iter().all(|(index, effect)| {
                    envelopes[*index].class == 4 && effect.native < 0 && effect.base <= 0
                })
            {
                return Err(invalid(
                    "multiple carrying effects on one target share a publication without an execution order",
                ));
            }
            let state = targets.get_mut(&target).expect("authenticated target");
            for (index, effect) in changes {
                state.native = sub(state.native, effect.native)?;
                state.base = sub(state.base, effect.base)?;
                state.valuation = sub(state.valuation, effect.valuation)?;
                state.latest_effective = state.latest_effective.max(effective(&envelopes[index])?);
                bind_effect(state, index, envelopes, infos);
            }
            check_state(state)?;
            checked.record(target, seq, state);
        }
        for (index, update) in allocations {
            let state = match targets.entry(update.target) {
                std::collections::btree_map::Entry::Occupied(slot) => slot.into_mut(),
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(history.initial(update.target, infos)?)
                }
            };
            state.valuation = update.valuation;
            state.allocated = Some(update.route);
            state.latest_effective = update.date;
            bind_effect(state, index, envelopes, infos);
            check_state(state)?;
            checked.record(update.target, seq, state);
            checked.allocations.insert(index);
            affected_sources.insert(update.target.0);
        }
        checked.releases.extend(release_coverage);
        for &index in group {
            let root = roots[&index];
            affected_sources.insert(root);
            let is_live = if parents.contains_key(&index) {
                !live.contains(&root)
            } else {
                true
            };
            set_live(root, is_live, &mut live, &mut postings, envelopes, legs);
            if let Some((14, raw)) = infos[&index].schema {
                add_routes(raw, spec.base, &mut routes)?;
            }
        }
        for source in affected_sources {
            if !live.contains(&source)
                && targets
                    .range((source, 0)..=(source, u16::MAX))
                    .any(|(_, state)| {
                        state.native != state.original_native
                            || state.base != state.original_base
                            || state.valuation != 0
                    })
            {
                return Err(invalid(
                    "a committed frontier strands carrying relief or valuation on a reversed source",
                ));
            }
        }
        cursor = end;
    }
    Ok(())
}

fn check_state(state: &Carrying) -> Result<(), ReportError> {
    let total = state
        .base
        .checked_add(state.valuation)
        .ok_or_else(|| invalid("remaining allocated carrying total overflow"))?;
    if state.native < 0
        || state.native > state.original_native
        || state.base < 0
        || state.base > state.original_base
        || total < 0
        || state.native == 0 && (state.base != 0 || state.valuation != 0)
    {
        return Err(invalid(
            "an application or exact undo exceeds its original capacity or strands carrying value",
        ));
    }
    Ok(())
}
