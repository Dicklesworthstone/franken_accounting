//! Independent management-override observations from the complete journal.
//!
//! Preparer and source-kind populations are sets of immutable entry identities,
//! not leg counts or producer-supplied frequencies. Reversal observations use
//! all recorded entries, including canceled postings and reversals of reversals;
//! the other two procedures use the independently reconstructed live population.
//! These are statistical observations, not approval or rule-execution proofs.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Entry, MAX_FINDINGS, Reader, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureParameters, VerifiedProcedureStatistic, failed, text,
};

pub(super) const PREPARER_DEFAULTS: [(&str, u32); 2] =
    [("max_preparer_count", 1), ("min_account_entries", 3)];
pub(super) const MANUAL_DEFAULTS: [(&str, u32); 2] =
    [("min_account_entries", 3), ("min_rule_share_bps", 6000)];
pub(super) const REVERSAL_DEFAULTS: [(&str, u32); 2] = [("round_power", 3), ("window_days", 15)];

fn invalid(detail: &str) -> ReportError {
    failed("procedure_profile", detail)
}

fn overflow() -> ReportError {
    failed(
        "procedure_arithmetic",
        "JET population arithmetic overflows",
    )
}

pub(super) fn decode(
    reader: &mut Reader<'_>,
    id: &str,
) -> Result<VerifiedProcedureParameters, ReportError> {
    let defaults = match id {
        "jet.unusual_preparers" => &PREPARER_DEFAULTS,
        "jet.manual_vs_rule" => &MANUAL_DEFAULTS,
        "jet.large_round_reversals" => &REVERSAL_DEFAULTS,
        _ => return Err(invalid("unknown management-override JET profile")),
    };
    if reader.count(2, 20, "procedure.parameters")? != 2 {
        return Err(invalid("JET requires both explicit parameters"));
    }
    let mut values = [0; 2];
    for (index, (name, _)) in defaults.iter().enumerate() {
        if text(reader, 64, "procedure.parameter")? != *name {
            return Err(invalid(
                "JET parameters must be complete, unique and lexically ordered",
            ));
        }
        values[index] = u32::try_from(reader.i128("procedure.parameter_value")?)
            .map_err(|_| invalid("JET parameters must be unsigned 32-bit integers"))?;
    }
    Ok(match id {
        "jet.unusual_preparers" => VerifiedProcedureParameters::UnusualPreparers {
            max_preparer_count: values[0],
            min_account_entries: values[1],
        },
        "jet.manual_vs_rule" => VerifiedProcedureParameters::ManualVsRule {
            min_account_entries: values[0],
            min_rule_share_bps: values[1],
        },
        _ => {
            if values[0] > 30 {
                return Err(invalid("round_power must be in 0..=30"));
            }
            VerifiedProcedureParameters::LargeRoundReversals {
                round_power: values[0],
                window_days: values[1],
            }
        }
    })
}

#[derive(Default)]
struct AccountPopulation {
    entries: BTreeSet<u128>,
    preparers: BTreeMap<u128, BTreeSet<u128>>,
    rule_entries: BTreeSet<u128>,
}

fn push(
    findings: &mut Vec<VerifiedProcedureFinding>,
    finding: VerifiedProcedureFinding,
) -> Result<(), ReportError> {
    if findings.len() >= MAX_FINDINGS {
        return Err(failed(
            "bounded_input",
            "JET findings exceed the certificate bound; none were omitted",
        ));
    }
    findings.push(finding);
    Ok(())
}

pub(super) fn replay(
    profile: VerifiedProcedureParameters,
    entries: &[Entry],
    live: &[&Entry],
    registry: &Registry,
) -> Result<(Vec<VerifiedProcedureFinding>, u64, u64, u64), ReportError> {
    if let VerifiedProcedureParameters::LargeRoundReversals {
        round_power,
        window_days,
    } = profile
    {
        return reversals(entries, registry, round_power, window_days);
    }
    if !matches!(
        profile,
        VerifiedProcedureParameters::UnusualPreparers { .. }
            | VerifiedProcedureParameters::ManualVsRule { .. }
    ) {
        return Err(invalid("expected preparer or manual-source JET profile"));
    }
    let mut accounts: BTreeMap<u128, AccountPopulation> = BTreeMap::new();
    let mut entry_accounts = Vec::with_capacity(live.len());
    let mut legs = 0u64;
    for entry in live {
        if entry.legs.len() != entry.leg_accounts.len() {
            return Err(invalid("JET leg account identities are incomplete"));
        }
        let facts = registry
            .entry_facts
            .get(&entry.identity)
            .ok_or_else(|| invalid("JET principal or origin facts are absent"))?;
        legs = legs
            .checked_add(entry.legs.len() as u64)
            .ok_or_else(overflow)?;
        let selected: BTreeSet<_> = entry
            .leg_accounts
            .iter()
            .map(|&(account, _)| account)
            .filter(|account| registry.account_types.contains_key(account))
            .collect();
        for &account in &selected {
            let population = accounts.entry(account).or_default();
            population.entries.insert(entry.identity);
            population
                .preparers
                .entry(facts.principal)
                .or_default()
                .insert(entry.identity);
            if facts.origin == 1 {
                population.rule_entries.insert(entry.identity);
            }
        }
        entry_accounts.push((entry.identity, facts, selected));
    }
    let mut findings = Vec::new();
    let mut comparisons = 0u64;
    for (identity, facts, selected) in entry_accounts {
        if matches!(profile, VerifiedProcedureParameters::ManualVsRule { .. }) && facts.origin != 0
        {
            continue;
        }
        comparisons = comparisons.checked_add(1).ok_or_else(overflow)?;
        for account in selected {
            let population = &accounts[&account];
            let total = population.entries.len() as u64;
            let finding = match profile {
                VerifiedProcedureParameters::UnusualPreparers {
                    max_preparer_count,
                    min_account_entries,
                } => {
                    let distinct = population.preparers.len();
                    let count = population.preparers[&facts.principal].len() as u64;
                    if total < u64::from(min_account_entries)
                        || distinct < 2
                        || count > u64::from(max_preparer_count)
                    {
                        continue;
                    }
                    VerifiedProcedureFinding {
                        entry: Some(identity),
                        severity: 1,
                        statistic: VerifiedProcedureStatistic::PreparerAccountPostings {
                            account,
                            count,
                        },
                        population: total,
                        narrative: format!(
                            "preparer has {count} of {total} live posting(s) on this account across {distinct} preparers"
                        ),
                    }
                }
                VerifiedProcedureParameters::ManualVsRule {
                    min_account_entries,
                    min_rule_share_bps,
                } => {
                    if total < u64::from(min_account_entries) {
                        continue;
                    }
                    let rules = population.rule_entries.len() as u64;
                    let share = i128::from(rules)
                        .checked_mul(10_000)
                        .and_then(|numerator| numerator.checked_div(i128::from(total)))
                        .ok_or_else(overflow)?;
                    if share < i128::from(min_rule_share_bps) {
                        continue;
                    }
                    VerifiedProcedureFinding {
                        entry: Some(identity),
                        severity: 2,
                        statistic: VerifiedProcedureStatistic::RuleShare {
                            account,
                            basis_points: share,
                        },
                        population: total,
                        narrative: format!(
                            "manual entry on an account where {rules} of {total} postings ({share} bps) are rule-derived"
                        ),
                    }
                }
                _ => return Err(invalid("unexpected JET profile")),
            };
            push(&mut findings, finding)?;
            // Each entry cites its first qualifying account in canonical order.
            break;
        }
    }
    Ok((findings, live.len() as u64, legs, comparisons))
}

fn reversals(
    entries: &[Entry],
    registry: &Registry,
    round_power: u32,
    window_days: u32,
) -> Result<(Vec<VerifiedProcedureFinding>, u64, u64, u64), ReportError> {
    if round_power > 30 {
        return Err(invalid("round_power must be in 0..=30"));
    }
    let factor = 10i128.checked_pow(round_power).ok_or_else(overflow)?;
    let by_identity: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| (entry.identity, entry))
        .collect();
    let population = entries.len() as u64;
    let mut findings = Vec::new();
    let mut legs = 0u64;
    let mut comparisons = 0u64;
    for reversal in entries.iter().filter(|entry| entry.class == 4) {
        for &(target, _, kind) in &reversal.supersession {
            if kind != 1 {
                continue;
            }
            let Some(original) = by_identity.get(&target) else {
                continue;
            };
            comparisons = comparisons.checked_add(1).ok_or_else(overflow)?;
            let (Some(original_period), Some(reversal_period)) =
                (&original.period, &reversal.period)
            else {
                continue;
            };
            if original_period.code.is_empty()
                || reversal_period.code.is_empty()
                || original_period.code == reversal_period.code
            {
                continue;
            }
            let days = i64::from(reversal_period.effective) - i64::from(original_period.effective);
            if !(0..=i64::from(window_days)).contains(&days) {
                continue;
            }
            let mut round = false;
            for &(unit, mantissa) in &original.legs {
                legs = legs.checked_add(1).ok_or_else(overflow)?;
                let scale = registry.unit_scales.get(&unit).ok_or_else(|| {
                    failed("procedure_units", "posting uses an unregistered unit")
                })?;
                let base = 10i128
                    .checked_pow(u32::from(*scale))
                    .and_then(|one| one.checked_mul(factor))
                    .ok_or_else(overflow)?;
                round |= mantissa != 0 && mantissa.checked_rem(base) == Some(0);
            }
            if !round {
                continue;
            }
            let days = u32::try_from(days).map_err(|_| overflow())?;
            push(
                &mut findings,
                VerifiedProcedureFinding {
                    entry: Some(original.identity.min(reversal.identity)),
                    severity: 3,
                    statistic: VerifiedProcedureStatistic::DaysToReversal {
                        original: original.identity,
                        reversal: reversal.identity,
                        days,
                    },
                    population,
                    narrative: format!(
                        "round-amount entry in {} reversed {} day(s) later in {}",
                        original_period.code, days, reversal_period.code
                    ),
                },
            )?;
        }
    }
    Ok((findings, population, legs, comparisons))
}

#[cfg(test)]
mod tests;
