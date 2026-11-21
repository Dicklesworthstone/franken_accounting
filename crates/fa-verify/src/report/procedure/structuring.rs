//! Independent account-to-account structuring replay from original legs.
//!
//! Each credit is distributed over the still-unfilled debit capacities under
//! exact Hamilton allocation. Both margins must conserve within a native unit
//! and legal entity before any transfer becomes a candidate. The procedure's
//! consecutive-gap chain is distinct from a fixed-width date window.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Entry, MAX_CITES, MAX_FINDINGS, Reader, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureParameters, VerifiedProcedureStatistic, failed, text,
};
use crate::report::functional::arithmetic::capacity_allocation;
use crate::report::statement::Sum;

pub(super) const DEFAULTS: [(&str, u32); 5] = [
    ("currency_iso4217", 840),
    ("floor", 800_000),
    ("min_count", 3),
    ("threshold", 1_000_000),
    ("window_days", 7),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Transfer {
    pub(super) entry: u128,
    pub(super) recorded: u64,
    pub(super) effective: i32,
    pub(super) from: u128,
    pub(super) to: u128,
    pub(super) unit: u32,
    pub(super) entity: Option<u128>,
    pub(super) amount: i128,
}

type Group = (Option<u128>, u128, u128, u32);
type Sides = (Vec<(u128, i128)>, Vec<(u128, i128)>);

// A compact entry can expand quadratically. Refuse before its allocation
// cells alone exceed the report input budget; never drop cells to fit it.
const MAX_ALLOCATION_CELLS: u64 =
    (super::MAX_REPORT_BUNDLE_BYTES / std::mem::size_of::<Transfer>()) as u64;

fn invalid(message: &str) -> ReportError {
    failed("procedure_profile", message)
}

fn arithmetic() -> ReportError {
    failed(
        "procedure_arithmetic",
        "structuring transfer arithmetic exceeds its exact domain",
    )
}

fn allocation_budget(current: u64, additional: u64) -> Result<u64, ReportError> {
    current
        .checked_add(additional)
        .filter(|total| *total <= MAX_ALLOCATION_CELLS)
        .ok_or_else(|| {
            failed(
                "bounded_input",
                "money-flow allocation exceeds the independent replay budget; no transfers were omitted",
            )
        })
}

pub(super) fn decode(reader: &mut Reader<'_>) -> Result<VerifiedProcedureParameters, ReportError> {
    if reader.count(DEFAULTS.len(), 20, "procedure.parameters")? != DEFAULTS.len() {
        return Err(invalid(
            "graph structuring requires all five explicit parameters",
        ));
    }
    let mut values = [0i128; 5];
    for (index, (name, _)) in DEFAULTS.iter().enumerate() {
        if text(reader, 64, "procedure.parameter")? != *name {
            return Err(invalid(
                "graph structuring parameters must be unique and lexically ordered",
            ));
        }
        values[index] = reader.i128("procedure.parameter_value")?;
    }
    let unsigned = |index: usize| {
        u32::try_from(values[index])
            .map_err(|_| invalid("graph structuring currency, count and window require u32"))
    };
    let currency_iso4217 = unsigned(0)?;
    let min_count = unsigned(2)?;
    if !(1..=999).contains(&currency_iso4217)
        || values[1] < 0
        || values[1] >= values[3]
        || min_count == 0
    {
        return Err(invalid(
            "graph structuring requires a currency, 0 <= floor < threshold and at least one transfer",
        ));
    }
    Ok(VerifiedProcedureParameters::GraphStructuring {
        currency_iso4217,
        floor: values[1],
        min_count,
        threshold: values[3],
        window_days: unsigned(4)?,
    })
}

pub(super) fn flow(live: &[&Entry], registry: &Registry) -> Result<Vec<Transfer>, ReportError> {
    let context = registry
        .trace
        .as_ref()
        .ok_or_else(|| invalid("money-flow replay lacks authenticated legal-entity dimensions"))?;
    let mut named_entities = BTreeSet::new();
    for entry in live {
        let facts = context
            .entries
            .get(&entry.identity)
            .filter(|facts| {
                facts.entities.len() == entry.legs.len()
                    && entry.leg_accounts.len() == entry.legs.len()
            })
            .ok_or_else(|| invalid("money-flow original leg identities are incomplete"))?;
        for entities in &facts.entities {
            if entities.len() > 1 {
                return Err(invalid("a money-flow leg has multiple legal entities"));
            }
            named_entities.extend(entities.iter().copied());
        }
    }
    let mut transfers = Vec::new();
    let mut cells = 0u64;
    for entry in live {
        let effective = entry
            .effective
            .ok_or_else(|| invalid("a money-flow posting has no effective date"))?;
        let facts = &context.entries[&entry.identity];
        let mut partitions: BTreeMap<(u32, Option<u128>), Sides> = BTreeMap::new();
        for ((&(unit, amount), &(account, debit)), entities) in entry
            .legs
            .iter()
            .zip(&entry.leg_accounts)
            .zip(&facts.entities)
        {
            if amount < 0 {
                return Err(invalid("a money-flow leg has a negative magnitude"));
            }
            let entity = if let Some(entity) = entities.first() {
                Some(*entity)
            } else if named_entities.len() > 1 {
                return Err(invalid(
                    "a multi-entity money-flow population has an unassigned leg",
                ));
            } else {
                named_entities.first().copied()
            };
            let sides = partitions.entry((unit, entity)).or_default();
            if debit {
                sides.1.push((account, amount));
            } else {
                sides.0.push((account, amount));
            }
        }
        for ((unit, entity), (mut credits, mut debits)) in partitions {
            let mut difference = Sum::default();
            for (_, amount) in &credits {
                difference.add(*amount, false).ok_or_else(arithmetic)?;
            }
            for (_, amount) in &debits {
                difference.add(*amount, true).ok_or_else(arithmetic)?;
            }
            if difference.value() != Some(0) {
                return Err(invalid(
                    "money-flow debit and credit margins do not conserve within their unit/entity",
                ));
            }
            credits.sort_unstable();
            debits.sort_unstable();
            let positive_credits = credits.iter().filter(|(_, amount)| *amount != 0).count();
            cells = allocation_budget(
                cells,
                (positive_credits as u64)
                    .checked_mul(debits.len() as u64)
                    .ok_or_else(arithmetic)?,
            )?;
            let mut remaining: Vec<_> = debits.iter().map(|(_, amount)| *amount).collect();
            for (from, amount) in credits {
                if amount == 0 {
                    continue;
                }
                let shares = capacity_allocation(amount, &remaining)?;
                for (index, share) in shares.into_iter().enumerate() {
                    remaining[index] = remaining[index]
                        .checked_sub(share)
                        .filter(|capacity| *capacity >= 0)
                        .ok_or_else(arithmetic)?;
                    if share != 0 {
                        transfers.push(Transfer {
                            entry: entry.identity,
                            recorded: entry.recorded_at,
                            effective,
                            from,
                            to: debits[index].0,
                            unit,
                            entity,
                            amount: share,
                        });
                    }
                }
            }
            if remaining.iter().any(|amount| *amount != 0) {
                return Err(invalid(
                    "money-flow allocation left a debit margin unfilled",
                ));
            }
        }
    }
    transfers.sort_by_key(|transfer| {
        (
            transfer.entry,
            transfer.unit,
            transfer.from,
            transfer.to,
            transfer.amount,
            transfer.entity,
        )
    });
    Ok(transfers)
}

struct Rule {
    currency: u32,
    floor: i128,
    min_count: u32,
    threshold: i128,
    window_days: u32,
}

impl Rule {
    fn emit(
        &self,
        findings: &mut Vec<VerifiedProcedureFinding>,
        chain: &[&Transfer],
        group: Group,
        population: u64,
        scale: u8,
    ) -> Result<(), ReportError> {
        if chain.len() < self.min_count as usize {
            return Ok(());
        }
        let amount = chain.iter().try_fold(0i128, |sum, transfer| {
            sum.checked_add(transfer.amount).ok_or_else(arithmetic)
        })?;
        if amount < self.threshold {
            return Ok(());
        }
        let (Some(first), Some(last)) = (chain.first(), chain.last()) else {
            return Ok(());
        };
        if findings.len() >= MAX_FINDINGS {
            return Err(failed(
                "bounded_input",
                "structuring findings exceed the certificate bound",
            ));
        }
        let (entity, from, to, unit) = group;
        let mut seen = BTreeSet::new();
        let entries = chain
            .iter()
            .map(|transfer| transfer.entry)
            .filter(|entry| seen.insert(*entry))
            .take(MAX_CITES - 2)
            .collect();
        let high = amount - self.threshold >= self.threshold
            || chain.len() >= (self.min_count as usize).saturating_mul(2);
        let span = i64::from(last.effective) - i64::from(first.effective);
        let entity_text = entity.map_or_else(
            || "implicit book entity".to_string(),
            |entity| format!("entity {entity:032x}"),
        );
        findings.push(VerifiedProcedureFinding {
            entry: None,
            severity: if high { 3 } else { 2 },
            statistic: VerifiedProcedureStatistic::StructuredTransfers {
                from,
                to,
                unit,
                entity,
                transfers: chain.len() as u64,
                mantissa: amount,
                scale,
                entries,
            },
            population,
            narrative: format!(
                "unit {unit} (ISO 4217 {}), {entity_text}: {} transfer(s) each in {}..{} (mantissas) within {span} day(s) summing to {amount}",
                self.currency, chain.len(), self.floor, self.threshold,
            ),
        });
        Ok(())
    }
}

pub(super) fn replay(
    profile: VerifiedProcedureParameters,
    live: &[&Entry],
    registry: &Registry,
) -> Result<(Vec<VerifiedProcedureFinding>, u64, u64), ReportError> {
    let VerifiedProcedureParameters::GraphStructuring {
        currency_iso4217,
        floor,
        min_count,
        threshold,
        window_days,
    } = profile
    else {
        return Err(invalid("expected graph structuring"));
    };
    let rule = Rule {
        currency: currency_iso4217,
        floor,
        min_count,
        threshold,
        window_days,
    };
    let transfers = flow(live, registry)?;
    let mut candidates = 0u64;
    let mut groups: BTreeMap<Group, Vec<&Transfer>> = BTreeMap::new();
    for transfer in &transfers {
        if registry.unit_currencies.get(&transfer.unit).copied() != Some(currency_iso4217 as u16)
            || transfer.from == transfer.to
            || transfer.amount < floor
            || transfer.amount >= threshold
        {
            continue;
        }
        candidates += 1;
        groups
            .entry((transfer.entity, transfer.from, transfer.to, transfer.unit))
            .or_default()
            .push(transfer);
    }
    let mut findings = Vec::new();
    for (group, mut transfers) in groups {
        let scale = registry
            .unit_scales
            .get(&group.3)
            .copied()
            .ok_or_else(|| invalid("structuring currency has no authenticated scale"))?;
        transfers.sort_by_key(|transfer| (transfer.effective, transfer.recorded, transfer.entry));
        let mut start = 0;
        for index in 1..=transfers.len() {
            if index == transfers.len()
                || i64::from(transfers[index].effective) - i64::from(transfers[index - 1].effective)
                    > i64::from(rule.window_days)
            {
                rule.emit(
                    &mut findings,
                    &transfers[start..index],
                    group,
                    candidates,
                    scale,
                )?;
                start = index;
            }
        }
    }
    Ok((findings, transfers.len() as u64, candidates))
}

#[cfg(test)]
mod tests;
