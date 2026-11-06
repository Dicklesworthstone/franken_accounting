//! Complete, independently allocated open-item populations for FX law 9.
//!
//! Historical relief comes from the checked settlement replay. Allocation
//! state is recorded only after both retained-prefix proofs succeed.

use super::*;

#[derive(Clone)]
pub(super) struct Item {
    pub(super) target: u128,
    digest: [u8; 32],
    pub(super) ordinal: u16,
    native_unit: u32,
    base_unit: u32,
    native: i128,
    historical: i128,
    prior: i128,
    target_base: i128,
}

pub(super) fn read(r: &mut Reader<'_>) -> Result<Vec<Item>, ReportError> {
    if r.u16("item_allocation.law")? != 1 || r.u16("item_allocation.version")? != 1 {
        return Err(failed(
            "supported_report",
            "item revaluation requires LargestRemainder v1",
        ));
    }
    let count = r.count(2048, 130, "item_allocation.items")?;
    if count == 0 {
        return Err(invalid(
            "item revaluation requires a nonempty complete population",
        ));
    }
    let mut items = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let target = r.u128("item.target")?;
        let digest = r.fixed("item.digest")?;
        let ordinal = r.u16("item.ordinal")?;
        let native_unit = r.u32("item.native.unit")?;
        let native = r.i128("item.native.amount")?;
        let base_unit = r.u32("item.historical.unit")?;
        let historical = r.i128("item.historical.amount")?;
        let prior_unit = r.u32("item.prior.unit")?;
        let prior = r.i128("item.prior.amount")?;
        let target_unit = r.u32("item.target_base.unit")?;
        let target_base = r.i128("item.target_base.amount")?;
        if previous.is_some_and(|last| last >= (target, ordinal))
            || ordinal >= 4096
            || native_unit == base_unit
            || prior_unit != base_unit
            || target_unit != base_unit
            || native <= 0
            || historical < 0
            || target_base < 0
            || historical.checked_add(prior).is_none_or(|total| total < 0)
        {
            return Err(invalid(
                "item allocation coordinates, units or carrying components are invalid",
            ));
        }
        previous = Some((target, ordinal));
        items.push(Item {
            target,
            digest,
            ordinal,
            native_unit,
            base_unit,
            native,
            historical,
            prior,
            target_base,
        });
    }
    Ok(items)
}

fn remaining(
    history: &Prepared<'_>,
    target: (usize, u16),
    at: u64,
    carrying: &settlement::CheckedCarrying,
) -> Result<settlement::Remaining, ReportError> {
    if let Some(remaining) = carrying.remaining(target, at) {
        return Ok(remaining);
    }
    let (source, ordinal) = target;
    Ok(settlement::Remaining {
        native: history.legs[source][usize::from(ordinal)].mantissa,
        historical: history.parsed[&source].amounts[usize::from(ordinal)],
        valuation: 0,
        allocated: None,
        source_digest: settlement::source_hasher(
            history.infos[&source].identity,
            history.envelopes[source].record_digest,
            ordinal,
        )
        .finalize(),
        latest_effective: history.envelopes[source]
            .effective_day
            .ok_or_else(|| invalid("item source has no effective date"))?,
    })
}

pub(super) fn shape(
    history: &Prepared<'_>,
    index: usize,
    basis: &Basis,
    route: Route,
) -> Result<(), ReportError> {
    let entry = &history.parsed[&index];
    let Some(claim) = &entry.base else {
        return Err(invalid("item revaluation has no functional totals"));
    };
    let legs = &history.legs[index];
    if !history.registry.item_revaluation
        || history.envelopes[index].class != 10
        || history.envelopes[index].effective_day != Some(basis.date)
        || history.infos[&index].period
            != Some((history.spec.calendar.as_str(), basis.period.as_str()))
        || basis.observed_at >= history.envelopes[index].commit_seq
        || claim.law != law_oid(9)
        || claim.rates != [basis.rate]
        || claim.residual.is_some()
        || legs.is_empty()
        || legs.len() > 4096
        || !legs.len().is_multiple_of(2)
        || basis
            .entity
            .is_some_and(|entity| !history.spec.entities.contains_key(&entity))
        || basis.entity.is_none() && !history.spec.entities.is_empty()
    {
        return Err(invalid(
            "item revaluation law, class, entity or closing coordinate differs",
        ));
    }
    for (ordinal, pair) in legs.as_chunks::<2>().0.iter().enumerate() {
        let first = &pair[0];
        let second = &pair[1];
        let start = ordinal * 2;
        if first.account != route.valuation
            || second.account != route.unrealized
            || first.debit == second.debit
            || first.unit != history.spec.base
            || second.unit != history.spec.base
            || first.mantissa <= 0
            || first.mantissa != second.mantissa
            || entry.details[start].dimensions != entry.details[start + 1].dimensions
        {
            return Err(invalid(
                "item adjustment must contain ordered opposite route pairs",
            ));
        }
        for (offset, detail) in entry.details[start..start + 2].iter().enumerate() {
            let leg_ordinal = start + offset;
            if !detail.settlements.is_empty()
                || detail.base_amount != Some((history.spec.base, first.mantissa))
                || history.item_entity(index, leg_ordinal) != basis.entity
            {
                return Err(invalid(
                    "item adjustment changed its base amount, entity or applications",
                ));
            }
        }
    }
    Ok(())
}

struct Source {
    index: usize,
    ordinal: u16,
    native: i128,
    historical: i128,
    valuation: i128,
}

fn add(sum: &mut i128, value: i128, debit: bool) -> Result<(), ReportError> {
    *sum = if debit {
        sum.checked_add(value)
    } else {
        sum.checked_sub(value)
    }
    .ok_or_else(|| invalid("item population sum exceeds i128"))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn reproduce(
    history: &Prepared<'_>,
    index: usize,
    basis: &Basis,
    at: u64,
    route: Route,
    native_unit: u32,
    totals: [i128; 4],
    carrying: &settlement::CheckedCarrying,
) -> Result<(), ReportError> {
    let mut sources = Vec::new();
    let mut sums = [0i128; 3];
    let mut side = None;
    for &source in &history.order {
        let envelope = &history.envelopes[source];
        if envelope.commit_seq > at {
            break;
        }
        if envelope.class == 2
            || envelope.class >= 16
            || envelope.effective_day.is_none_or(|date| date > basis.date)
            || envelope.class == 12
                && history
                    .activations
                    .get(&(source as u64))
                    .is_none_or(|sequence| *sequence > at)
        {
            continue;
        }
        for (ordinal, leg) in history.legs[source].iter().enumerate() {
            if leg.account != basis.source
                || history.item_entity(source, ordinal) != basis.entity
                || envelope.class == 4
            {
                continue;
            }
            let detail = &history.parsed[&source].details[ordinal];
            let law = history.parsed[&source].base.as_ref().map(|claim| claim.law);
            if !detail.settlements.is_empty() {
                if !law.is_some_and(|law| [law_oid(4), law_oid(10), law_oid(11)].contains(&law)) {
                    return Err(invalid(
                        "item population contains an application without checked carrying relief",
                    ));
                }
                continue;
            }
            if !matches!(envelope.class, 1 | 3 | 5..=15)
                || !law.is_some_and(|law| [law_oid(1), law_oid(3)].contains(&law))
                || detail.base_amount.is_none()
                || leg.unit != native_unit
                || leg.mantissa <= 0
            {
                return Err(failed(
                    "supported_report",
                    "item population requires valued original SpotClose/PeriodAverage open items",
                ));
            }
            if !carrying.is_live(source, at, basis.date, history.envelopes)? {
                continue;
            }
            if !carrying.is_live(source, at, i32::MAX, history.envelopes)? {
                return Err(invalid(
                    "item source is reversed after the selected closing date",
                ));
            }
            // An unallocated adjustment cannot be distributed implicitly,
            // even if offsetting adjustments make its net balance zero.
            if history.bases.iter().any(|(&prior, old)| {
                old.source == basis.source
                    && old.items.is_none()
                    && history.envelopes[prior].commit_seq >= envelope.commit_seq
                    && history.envelopes[prior].commit_seq <= at
            }) {
                return Err(failed(
                    "supported_report",
                    "item source has an aggregate adjustment without a carrying allocation",
                ));
            }
            let target = (source, ordinal as u16);
            let remaining = remaining(history, target, at, carrying)?;
            let allocated = remaining.allocated;
            let valuation = remaining.valuation;
            if remaining.latest_effective > basis.date
                || allocated.is_some_and(|prior| {
                    prior.valuation != route.valuation || prior.unrealized != route.unrealized
                })
            {
                return Err(invalid(
                    "item closing date or route precedes its checked carrying history",
                ));
            }
            let total = remaining
                .historical
                .checked_add(valuation)
                .ok_or_else(|| invalid("item carrying total exceeds i128"))?;
            if remaining.native < 0
                || remaining.historical < 0
                || total < 0
                || remaining.native == 0 && (remaining.historical != 0 || valuation != 0)
            {
                return Err(invalid(
                    "item population contains negative or stranded carrying components",
                ));
            }
            if remaining.native == 0 {
                continue;
            }
            if side.is_some_and(|debit| debit != leg.debit) {
                return Err(failed(
                    "supported_report",
                    "item revaluation requires a same-sided complete population",
                ));
            }
            side = Some(leg.debit);
            add(&mut sums[0], remaining.native, leg.debit)?;
            add(&mut sums[1], remaining.historical, leg.debit)?;
            add(&mut sums[2], valuation, leg.debit)?;
            sources.push(Source {
                index: source,
                ordinal: ordinal as u16,
                native: remaining.native,
                historical: remaining.historical,
                valuation,
            });
        }
    }
    if sources.is_empty() || sources.len() > 2048 || sums != totals[..3] {
        return Err(invalid(
            "complete item population does not reproduce source and valuation account balances",
        ));
    }
    sources.sort_by_key(|source| (history.infos[&source.index].identity, source.ordinal));
    let asserted = basis.items.as_ref().expect("item basis");
    if asserted.len() != sources.len() {
        return Err(invalid("item basis omits or invents an open source"));
    }
    let target = totals[3]
        .checked_abs()
        .ok_or_else(|| invalid("item target magnitude exceeds i128"))?;
    let weights: Vec<_> = sources.iter().map(|source| source.native).collect();
    let shares = super::super::super::arithmetic::largest_remainder(target, &weights)?;
    let mut leg_ordinal = 0;
    for ((source, item), target_base) in sources.iter().zip(asserted).zip(shares) {
        let original = &history.legs[source.index][usize::from(source.ordinal)];
        if item.target != history.infos[&source.index].identity
            || item.digest != history.envelopes[source.index].record_digest
            || item.ordinal != source.ordinal
            || item.native_unit != native_unit
            || item.base_unit != history.spec.base
            || item.native != source.native
            || item.historical != source.historical
            || item.prior != source.valuation
            || item.target_base != target_base
        {
            return Err(invalid(
                "item basis does not reproduce its authenticated remaining components and allocation",
            ));
        }
        let delta = source
            .historical
            .checked_add(source.valuation)
            .and_then(|carrying| target_base.checked_sub(carrying))
            .ok_or_else(|| invalid("item adjustment delta exceeds i128"))?;
        if delta == 0 {
            continue;
        }
        let magnitude = delta
            .checked_abs()
            .ok_or_else(|| invalid("item adjustment magnitude exceeds i128"))?;
        let debit = if delta > 0 {
            original.debit
        } else {
            !original.debit
        };
        let dimensions =
            &history.parsed[&source.index].details[usize::from(source.ordinal)].dimensions;
        for (account, debit) in [(route.valuation, debit), (route.unrealized, !debit)] {
            let Some(leg) = history.legs[index].get(leg_ordinal) else {
                return Err(invalid("item adjustment omits a nonzero allocated pair"));
            };
            if leg.account != account
                || leg.debit != debit
                || leg.unit != history.spec.base
                || leg.mantissa != magnitude
                || &history.parsed[&index].details[leg_ordinal].dimensions != dimensions
            {
                return Err(invalid(
                    "item adjustment amount, direction, order or source dimensions differ",
                ));
            }
            leg_ordinal += 1;
        }
    }
    if leg_ordinal != history.legs[index].len() {
        return Err(invalid("item adjustment contains unallocated extra legs"));
    }
    Ok(())
}

pub(super) fn updates(
    history: &Prepared<'_>,
    index: usize,
) -> Result<Vec<settlement::AllocationUpdate>, ReportError> {
    let basis = &history.bases[&index];
    let Some(items) = &basis.items else {
        return Ok(Vec::new());
    };
    let identities: BTreeMap<_, _> = history
        .infos
        .iter()
        .map(|(&source, info)| (info.identity, source))
        .collect();
    let route = settlement::AllocationRoute {
        entry: basis.routes_entry,
        digest: basis.routes_digest,
        valuation: history.legs[index][0].account,
        unrealized: history.legs[index][1].account,
    };
    items
        .iter()
        .map(|item| {
            Ok(settlement::AllocationUpdate {
                target: (identities[&item.target], item.ordinal),
                valuation: item
                    .target_base
                    .checked_sub(item.historical)
                    .ok_or_else(|| invalid("allocated carrying amount exceeds i128"))?,
                route,
                date: basis.date,
            })
        })
        .collect()
}
