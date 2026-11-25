//! Independent reconstruction of native declared intercompany coverage.
//!
//! The authenticated journal supplies pair keys, original ordinals and exact
//! monetary reversal inheritance. Roles select additional uncovered legs.
//! Literal entity dimensions and per-entity balance are checked here; the
//! native book's balancing-entity admission and current authority are not
//! asserted by this portable statistical profile.

use std::collections::{BTreeMap, BTreeSet};

use crate::envelope::{Leg, LegDetails};
use super::{
    Entry, Registry, ReportError, VerifiedProcedureFinding, VerifiedProcedureStatistic,
    MAX_FINDINGS, failed, in_window, liveness,
};

#[derive(Clone)]
struct Facts {
    declaration: Option<Vec<u8>>,
    details: Vec<LegDetails>,
    period: String,
    period_declared: bool,
}

/// Built only from original authenticated proposals and historical periods.
#[derive(Clone, Default)]
pub(crate) struct Context {
    entries: BTreeMap<u128, Facts>,
}

impl Context {
    pub(crate) fn capture(
        &mut self,
        identity: u128,
        declaration: Option<&[u8]>,
        details: Vec<LegDetails>,
        period: String,
        period_declared: bool,
    ) -> Result<(), ReportError> {
        if self.entries.insert(identity, Facts {
            declaration: declaration.map(<[u8]>::to_vec),
            details,
            period,
            period_declared,
        }).is_some() {
            return Err(invalid("duplicate authenticated intercompany entry"));
        }
        Ok(())
    }
}

fn invalid(message: &'static str) -> ReportError {
    failed("procedure_intercompany", message)
}

fn add(total: &mut u64, count: usize) -> Result<(), ReportError> {
    *total = total.checked_add(u64::try_from(count)
        .map_err(|_| invalid("intercompany work count exceeds u64"))?)
        .ok_or_else(|| invalid("intercompany work count overflows"))?;
    Ok(())
}

pub(super) fn replay(
    entries: &[Entry],
    live: &[&Entry],
    cutoff: Option<i32>,
    registry: &Registry,
    context: &Context,
) -> Result<(Vec<VerifiedProcedureFinding>, u64, u64, u64), ReportError> {
    // Validate the entire recorded history, including cycles and targets
    // outside the requested effective window.
    liveness(entries, None)?;
    let by_id: BTreeMap<_, _> = entries.iter().map(|entry| (entry.identity, entry)).collect();
    if by_id.len() != entries.len() || context.entries.len() != entries.len() {
        return Err(invalid("intercompany entry context is incomplete or duplicated"));
    }
    let entry_work = u64::try_from(entries.len())
        .map_err(|_| invalid("intercompany population exceeds u64"))?;
    let mut comparisons = entry_work;
    let mut leg_work = 0;
    let mut original_keys = BTreeSet::new();
    let mut covered = BTreeMap::<u128, BTreeSet<usize>>::new();
    let mut selected_declaration = false;
    for entry in entries {
        let facts = context.entries.get(&entry.identity)
            .ok_or_else(|| invalid("intercompany entry context is absent"))?;
        if entry.legs.len() != entry.leg_accounts.len()
            || entry.legs.len() != facts.details.len()
        {
            return Err(invalid("intercompany original leg metadata is incomplete"));
        }
        add(&mut leg_work, entry.legs.len())?;
        if let Some(bytes) = &facts.declaration {
            if !matches!(entry.class, 1 | 4 | 7) || entry.effective.is_none() {
                return Err(invalid("a declaration requires an original, adjusting or reversal posting"));
            }
            let legs: Vec<_> = entry.legs.iter().zip(&entry.leg_accounts)
                .map(|(&(unit, mantissa), &(account, debit))| Leg {
                    unit, mantissa, account, debit,
                }).collect();
            if legs.iter().any(|leg| !registry.unit_scales.contains_key(&leg.unit)) {
                return Err(invalid("declared intercompany unit is not registered"));
            }
            let pairs = super::super::metadata::intercompany::validate_pairs(
                bytes, &legs, &facts.details,
            )?;
            // Each declared entry contributes one check per legal-entity
            // balance cell, including reversal entries.
            let entities: BTreeSet<_> = facts.details.iter()
                .flat_map(|leg| leg.dimensions.iter()
                    .filter(|(kind, _)| *kind == 1)
                    .map(|(_, entity)| *entity))
                .collect();
            add(&mut comparisons, entities.len())?;
            add(&mut comparisons, pairs.len())?;
            selected_declaration |= in_window(entry, cutoff);
            let ordinals = covered.entry(entry.identity).or_default();
            for pair in pairs {
                if entry.class != 4 && !original_keys.insert(pair.key) {
                    return Err(invalid("an original intercompany pair key is reused"));
                }
                ordinals.insert(pair.left);
                ordinals.insert(pair.right);
            }
        }
        if entry.class != 4 {
            continue;
        }
        let [(target_id, digest, 1)] = entry.supersession.as_slice() else {
            return Err(invalid("a reversal requires exactly one Reverses target"));
        };
        let target = by_id.get(target_id)
            .ok_or_else(|| invalid("intercompany reversal target is absent"))?;
        let original = context.entries.get(target_id)
            .ok_or_else(|| invalid("intercompany reversal target metadata is absent"))?;
        if facts.declaration.is_none() && original.declaration.is_none() {
            continue;
        }
        if *target_id == entry.identity || target.recorded_at > entry.recorded_at
            || target.digest != *digest
            || facts.declaration != original.declaration
            || target.legs.len() != entry.legs.len()
            || original.details.len() != entry.legs.len()
            || target.leg_accounts.len() != entry.legs.len()
        {
            return Err(invalid("a pair reversal does not preserve its original declaration"));
        }
        for index in 0..entry.legs.len() {
            add(&mut comparisons, 1)?;
            let before = &original.details[index];
            let after = &facts.details[index];
            let (original_account, original_debit) = target.leg_accounts[index];
            let (account, debit) = entry.leg_accounts[index];
            if original_account != account || original_debit == debit
                || target.legs[index] != entry.legs[index]
                || before.base_amount != after.base_amount
                || before.dimensions != after.dimensions
            {
                return Err(invalid("a pair reversal must be the exact monetary side swap"));
            }
            // Applications deliberately do not participate in side-swap
            // inheritance; the native reversal law excludes them too.
        }
    }
    let roles: BTreeSet<_> = registry.account_roles.iter()
        .filter(|(_, roles)| roles.contains("intercompany") || roles.contains("intercompany_activity"))
        .map(|(&account, _)| account).collect();
    if roles.is_empty() && !selected_declaration {
        return Err(invalid("neither intercompany role nor in-window declared history exists"));
    }
    let mut population = 0_u64;
    let mut findings = Vec::new();
    for entry in live {
        add(&mut comparisons, entry.legs.len())?;
        let facts = context.entries.get(&entry.identity)
            .ok_or_else(|| invalid("live intercompany metadata is absent"))?;
        for (ordinal, (&(unit, amount), &(account, _))) in entry.legs.iter()
            .zip(&entry.leg_accounts).enumerate()
        {
            if amount <= 0 {
                continue;
            }
            let declared = covered.get(&entry.identity)
                .is_some_and(|ordinals| ordinals.contains(&ordinal));
            let selected_role = roles.contains(&account);
            if !declared && !selected_role {
                continue;
            }
            population = population.checked_add(1)
                .ok_or_else(|| invalid("intercompany candidate population overflows"))?;
            if !selected_role || declared {
                continue;
            }
            if findings.len() == MAX_FINDINGS {
                return Err(failed("bounded_input", "intercompany findings exceed the certificate bound"));
            }
            let ordinal = u16::try_from(ordinal)
                .map_err(|_| invalid("intercompany leg ordinal exceeds u16"))?;
            let scale = *registry.unit_scales.get(&unit)
                .ok_or_else(|| invalid("intercompany finding unit is not registered"))?;
            findings.push(VerifiedProcedureFinding {
                entry: Some(entry.identity),
                severity: 4,
                statistic: VerifiedProcedureStatistic::IntercompanyUndeclared {
                    account, ordinal, unit, amount, scale,
                    period: facts.period_declared.then(|| facts.period.clone()),
                },
                population: 0,
                narrative: format!(
                    "intercompany leg {ordinal} in entry {:032x} on account {account:032x} in period {} unit {unit} has no declared reciprocal pair",
                    entry.identity, facts.period,
                ),
            });
        }
    }
    for finding in &mut findings {
        finding.population = population;
    }
    Ok((findings, entry_work, leg_work, comparisons))
}

#[cfg(test)]
mod tests;
