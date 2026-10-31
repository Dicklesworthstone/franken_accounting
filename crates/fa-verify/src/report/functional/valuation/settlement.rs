//! Source-bound RemainingCarryingValue replay, independent of journal code.
//!
//! A recorded application consumes its target's remaining native and base
//! amounts. Exact reversals negate the recorded effect, including a reversal
//! of a reversal; they never reprice an old application against a new pool.

use super::{
    BookParameters, LeafEnvelope, Leg, ParsedEntry, Rate, Reader, ReportError, failed, law_oid,
    metadata, registry,
};
use std::collections::{BTreeMap, BTreeSet};

type Target = (usize, u16);

#[derive(Clone, Copy)]
struct Effect {
    target: Target,
    native: i128,
    base: i128,
}
struct Carrying {
    original_native: i128,
    original_base: i128,
    native: i128,
    base: i128,
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
        let entities = &entry.entities[range];
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
) -> Result<(), ReportError> {
    if !parsed.values().any(|entry| {
        entry
            .base
            .as_ref()
            .is_some_and(|base| [law_oid(4), law_oid(11)].contains(&base.law))
    }) {
        return Ok(());
    }
    let history = History {
        spec,
        registry,
        rates,
        envelopes,
        legs,
        parsed,
        migration_activations,
    };
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
            roots.insert(index, roots[&parent]);
        } else {
            roots.insert(index, index);
        }
        let entry = &parsed[&index];
        if entry.details.iter().zip(&legs[index]).any(|(detail, leg)| {
            !detail.settlements.is_empty()
                && (envelopes[index].class == 4
                    || leg.unit != spec.base
                        && entry
                            .base
                            .as_ref()
                            .is_none_or(|claim| ![law_oid(4), law_oid(11)].contains(&claim.law)))
        }) {
            return Err(failed(
                "supported_report",
                "foreign applications require source-bound SettlementCarryingBasis and reversals cannot author fresh applications",
            ));
        }
    }
    let mut targets: BTreeMap<Target, Carrying> = BTreeMap::new();
    let mut components: BTreeMap<usize, Vec<(std::ops::Range<usize>, Target)>> = BTreeMap::new();
    for &index in &order {
        if envelopes[index].class == 4
            || parsed[&index]
                .base
                .as_ref()
                .is_none_or(|claim| ![law_oid(4), law_oid(11)].contains(&claim.law))
        {
            continue;
        }
        if !matches!(envelopes[index].class, 1 | 3 | 7) {
            return Err(invalid(
                "entry class cannot originate SettlementCarryingBasis",
            ));
        }
        if parsed[&index]
            .base
            .as_ref()
            .is_some_and(|claim| claim.law == law_oid(11))
            && !matches!(envelopes[index].class, 1 | 3)
        {
            return Err(invalid(
                "entry class cannot originate SettlementSpotCarrying",
            ));
        }
        let mut seen = BTreeSet::new();
        for range in history.ranges(index)? {
            let target = history.target(index, range.start, &identities)?;
            if !seen.insert(target) {
                return Err(invalid(
                    "settlement components must name distinct target legs",
                ));
            }
            if let std::collections::btree_map::Entry::Vacant(slot) = targets.entry(target) {
                let (source, ordinal) = target;
                let native = legs[source][usize::from(ordinal)].mantissa;
                let base = parsed[&source].amounts[usize::from(ordinal)];
                slot.insert(Carrying {
                    original_native: native,
                    original_base: base,
                    native,
                    base,
                    latest_effective: effective(&envelopes[source])?,
                });
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
        // Every fresh application observes the complete prefix before this
        // publication, never an arbitrary order of entries inside the commit.
        for &index in group {
            let current = if let Some(&parent) = parents.get(&index) {
                effects
                    .get(&parent)
                    .into_iter()
                    .flatten()
                    .map(|effect| {
                        Ok(Effect {
                            target: effect.target,
                            native: negate(effect.native)?,
                            base: negate(effect.base)?,
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
                    let account = legs[target.0][usize::from(target.1)].account;
                    let source_seq = envelopes[target.0].commit_seq;
                    if routes.get(&account).is_some_and(|(valuation, _)| {
                        postings.get(valuation).is_some_and(|entries| {
                            entries.range((source_seq, 0)..(seq, 0)).next().is_some()
                        })
                    }) {
                        return Err(failed(
                            "supported_report",
                            "aggregate valuation adjustments have no registered per-item carrying allocation",
                        ));
                    }
                    current.push(history.component(
                        index,
                        range.clone(),
                        *target,
                        &targets[target],
                    )?);
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
                state.latest_effective = state.latest_effective.max(effective(&envelopes[index])?);
            }
            if state.native < 0
                || state.native > state.original_native
                || state.base < 0
                || state.base > state.original_base
            {
                return Err(invalid(
                    "an application or undo exceeds its original native/base capacity",
                ));
            }
        }
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
                        state.native != state.original_native || state.base != state.original_base
                    })
            {
                return Err(invalid(
                    "a committed frontier strands carrying relief on a reversed source",
                ));
            }
        }
        cursor = end;
    }
    Ok(())
}
