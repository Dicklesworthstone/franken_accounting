//! Independently replay exact asset-account round trips and temporal cycles.
//!
//! The complete source determines every allocated transfer, its historical
//! account type and period. Ordered availability sets choose the earliest
//! unused opposite direction from a distinct entry. Work charges follow the
//! authenticated algorithm's examined index intervals, without taking a count
//! or pair from the producer. Longer paths use an independent bounded,
//! iterative search over the same complete allocated transfer population.

mod cycles;

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Entry, MAX_FINDINGS, Reader, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureParameters, VerifiedProcedureStatistic, failed, structuring, text,
};

pub(super) const DEFAULTS: [(&str, u32); 4] = [
    ("max_hops", 2),
    ("max_search_steps", 250_000),
    ("period_end_days", 7),
    ("window_days", 5),
];

fn invalid(message: &str) -> ReportError {
    failed("procedure_profile", message)
}

pub(super) fn decode(reader: &mut Reader<'_>) -> Result<VerifiedProcedureParameters, ReportError> {
    if reader.count(DEFAULTS.len(), 20, "procedure.parameters")? != DEFAULTS.len() {
        return Err(invalid("round trips require all four explicit parameters"));
    }
    let mut values = [0u32; 4];
    for (index, (name, _)) in DEFAULTS.iter().enumerate() {
        if text(reader, 64, "procedure.parameter")? != *name {
            return Err(invalid(
                "round-trip parameters must be unique and lexically ordered",
            ));
        }
        values[index] = u32::try_from(reader.i128("procedure.parameter_value")?)
            .map_err(|_| invalid("round-trip parameters require unsigned 32-bit integers"))?;
    }
    if !(2..=8).contains(&values[0]) || !(1..=10_000_000).contains(&values[1]) {
        return Err(invalid(
            "portable round trips require max_hops in 2..=8 and max_search_steps in 1..=10000000",
        ));
    }
    Ok(VerifiedProcedureParameters::GraphRoundTrips {
        max_hops: values[0],
        max_search_steps: values[1],
        period_end_days: values[2],
        window_days: values[3],
    })
}

fn charge(comparisons: &mut u64, count: u64) -> Result<(), ReportError> {
    *comparisons = comparisons
        .checked_add(count)
        .ok_or_else(|| failed("procedure_arithmetic", "round-trip work count exceeds u64"))?;
    Ok(())
}

type Bucket = (Option<u128>, u128, u128, u32, i128);

pub(super) fn replay(
    profile: VerifiedProcedureParameters,
    live: &[&Entry],
    registry: &Registry,
) -> Result<(Vec<VerifiedProcedureFinding>, u64, u64), ReportError> {
    let VerifiedProcedureParameters::GraphRoundTrips {
        max_hops,
        period_end_days,
        window_days,
        ..
    } = profile
    else {
        return Err(invalid("expected graph round trips"));
    };
    let transfers = structuring::flow(live, registry)?;
    if max_hops != 2 {
        return multi_hop(profile, &transfers, live, registry);
    }
    let entries: BTreeMap<_, _> = live.iter().map(|entry| (entry.identity, *entry)).collect();
    let mut buckets: BTreeMap<Bucket, Vec<&structuring::Transfer>> = BTreeMap::new();
    let mut candidates = 0u64;
    for transfer in &transfers {
        if transfer.amount == 0
            || transfer.from == transfer.to
            || registry.account_types.get(&transfer.from) != Some(&1)
            || registry.account_types.get(&transfer.to) != Some(&1)
        {
            continue;
        }
        candidates += 1;
        let (first, second) = if transfer.from < transfer.to {
            (transfer.from, transfer.to)
        } else {
            (transfer.to, transfer.from)
        };
        buckets
            .entry((
                transfer.entity,
                first,
                second,
                transfer.unit,
                transfer.amount,
            ))
            .or_default()
            .push(transfer);
    }
    let mut findings = Vec::new();
    let mut comparisons = 0u64;
    for ((entity, first_account, second_account, unit, amount), mut bucket) in buckets {
        let count = bucket.len();
        charge(
            &mut comparisons,
            (count as u64).saturating_mul(u64::from((count as u64).max(1).ilog2())),
        )?;
        bucket.sort_by_key(|transfer| {
            (
                transfer.effective,
                transfer.recorded,
                transfer.entry,
                transfer.from,
                transfer.to,
            )
        });
        let direction = |index: usize| {
            usize::from(bucket[index].from != first_account || bucket[index].to != second_account)
        };
        let mut available: [BTreeSet<usize>; 2] = std::array::from_fn(|_| BTreeSet::new());
        for index in 0..count {
            available[direction(index)].insert(index);
        }
        let mut frontier = [0usize; 2];
        for index in 0..count {
            let outgoing_direction = direction(index);
            if !available[outgoing_direction].contains(&index) {
                continue;
            }
            let opposite = 1 - outgoing_direction;
            let start = frontier[opposite].max(index + 1);
            let first_available = available[opposite]
                .range(start..)
                .next()
                .copied()
                .unwrap_or(count);
            charge(&mut comparisons, (first_available - start) as u64)?;
            frontier[opposite] = first_available;
            let returned_index = available[opposite]
                .range(first_available..)
                .copied()
                .find(|&candidate| bucket[candidate].entry != bucket[index].entry)
                .unwrap_or(count);
            charge(&mut comparisons, (returned_index - first_available) as u64)?;
            if returned_index == count {
                continue;
            }
            charge(&mut comparisons, 1)?;
            let outgoing = bucket[index];
            let returned = bucket[returned_index];
            let gap = i64::from(returned.effective) - i64::from(outgoing.effective);
            if !(0..=i64::from(window_days)).contains(&gap) {
                continue;
            }
            available[outgoing_direction].remove(&index);
            available[opposite].remove(&returned_index);
            if returned_index == frontier[opposite] {
                frontier[opposite] += 1;
            }
            let until_end = |transfer: &structuring::Transfer| {
                entries[&transfer.entry]
                    .period
                    .as_ref()
                    .map(|period| i64::from(period.end) - 1 - i64::from(transfer.effective))
            };
            let outgoing_days = until_end(outgoing);
            let return_days = until_end(returned);
            let near_end = [outgoing_days, return_days]
                .iter()
                .flatten()
                .any(|days| (0..=i64::from(period_end_days)).contains(days));
            let scale = registry
                .unit_scales
                .get(&unit)
                .copied()
                .ok_or_else(|| invalid("round-trip unit has no authenticated scale"))?;
            if findings.len() >= MAX_FINDINGS {
                return Err(failed(
                    "bounded_input",
                    "round-trip findings exceed the certificate bound",
                ));
            }
            let entity_text = entity.map_or_else(
                || "implicit book entity".into(),
                |entity| format!("entity {entity:032x}"),
            );
            let day_text =
                |days: Option<i64>| days.map_or_else(|| "?".into(), |days| days.to_string());
            findings.push(VerifiedProcedureFinding {
                entry: None,
                severity: if near_end { 3 } else { 2 },
                statistic: VerifiedProcedureStatistic::RoundTrip {
                    outbound: outgoing.entry,
                    returned: returned.entry,
                    from: outgoing.from,
                    to: outgoing.to,
                    unit,
                    entity,
                    mantissa: amount,
                    scale,
                },
                population: candidates,
                narrative: format!(
                    "unit {unit}, {entity_text}: {amount} (mantissa) out and back in {gap} day(s); outbound {} and return {} day(s) before their period ends{}",
                    day_text(outgoing_days), day_text(return_days),
                    if near_end { "; within the period-end window" } else { "" },
                ),
            });
        }
    }
    Ok((findings, transfers.len() as u64, comparisons))
}

fn multi_hop(
    profile: VerifiedProcedureParameters,
    transfers: &[structuring::Transfer],
    live: &[&Entry],
    registry: &Registry,
) -> Result<(Vec<VerifiedProcedureFinding>, u64, u64), ReportError> {
    let VerifiedProcedureParameters::GraphRoundTrips {
        max_hops,
        max_search_steps,
        period_end_days,
        window_days,
    } = profile
    else {
        return Err(invalid("expected bounded graph round trips"));
    };
    let candidates: Vec<_> = transfers
        .iter()
        .filter(|transfer| {
            transfer.from != transfer.to
                && registry.account_types.get(&transfer.from) == Some(&1)
                && registry.account_types.get(&transfer.to) == Some(&1)
        })
        .collect();
    let edges: Vec<_> = candidates
        .iter()
        .map(|transfer| cycles::Edge {
            day: transfer.effective,
            recorded: transfer.recorded,
            entry: transfer.entry,
            from: transfer.from,
            to: transfer.to,
            unit: transfer.unit,
            amount: transfer.amount,
            entity: transfer.entity,
        })
        .collect();
    let cycles = cycles::find(
        &edges,
        max_hops as usize,
        i64::from(window_days),
        u64::from(max_search_steps),
    )
    .map_err(|error| match error {
        cycles::Error::Parameters => invalid("invalid bounded circular-flow search parameters"),
        cycles::Error::NonPositiveAmount => {
            failed("procedure_arithmetic", "nonpositive circular-flow transfer")
        }
        cycles::Error::SearchLimit => failed(
            "procedure_search_limit",
            "circular-flow search limit reached; no partial findings returned; narrow the population or increase max_search_steps (at most 10000000)",
        ),
    })?;
    let population = candidates.len() as u64;
    let mut comparisons = population.saturating_mul(u64::from(population.max(1).ilog2()));
    charge(&mut comparisons, cycles.search_steps)?;
    let entries: BTreeMap<_, _> = live.iter().map(|entry| (entry.identity, *entry)).collect();
    let near_period_end = |transfer: &structuring::Transfer| {
        entries[&transfer.entry]
            .period
            .as_ref()
            .is_some_and(|period| {
                let days = i64::from(period.end) - 1 - i64::from(transfer.effective);
                (0..=i64::from(period_end_days)).contains(&days)
            })
    };
    let mut findings = Vec::new();
    for path in cycles.paths {
        let first = candidates[*path
            .first()
            .ok_or_else(|| invalid("empty circular-flow path"))?];
        let last = candidates[*path
            .last()
            .ok_or_else(|| invalid("empty circular-flow path"))?];
        let near_end = near_period_end(first) || near_period_end(last);
        let scale = registry
            .unit_scales
            .get(&first.unit)
            .copied()
            .ok_or_else(|| invalid("round-trip unit has no authenticated scale"))?;
        if findings.len() >= MAX_FINDINGS {
            return Err(failed(
                "bounded_input",
                "round-trip findings exceed the certificate bound",
            ));
        }
        let entity = first.entity.map_or_else(
            || "implicit book entity".into(),
            |entity| format!("entity {entity:032x}"),
        );
        let gap = i64::from(last.effective) - i64::from(first.effective);
        findings.push(VerifiedProcedureFinding {
            entry: None,
            severity: if near_end { 3 } else { 2 },
            statistic: VerifiedProcedureStatistic::RoundTripCycle {
                hops: path
                    .iter()
                    .map(|&index| (candidates[index].entry, candidates[index].from))
                    .collect(),
                unit: first.unit,
                entity: first.entity,
                mantissa: first.amount,
                scale,
            },
            population,
            narrative: format!(
                "unit {}, {entity}: {} (mantissa) out and back through {} asset accounts in {gap} day(s); canonical edge-disjoint temporal cycle{}; a motif, not a tracing-law conclusion",
                first.unit, first.amount, path.len(),
                if near_end { "; within the period-end window" } else { "" },
            ),
        });
    }
    Ok((findings, transfers.len() as u64, comparisons))
}

#[cfg(test)]
mod tests;
