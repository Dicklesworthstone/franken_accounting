//! Account-role screens from the authenticated historical chart and entries.
//!
//! Suspense aging consumes the independently reconstructed application fold,
//! including cleared rows for the work transcript. Equal opposing residuals
//! are still uncleared items. Capitalization reads original leg identities and
//! the journaled fixed-asset/accrued-expense roles; account names never select
//! the population. Neither computation establishes improper accounting intent.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Entry, MAX_CITES, MAX_FINDINGS, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureParameters, VerifiedProcedureStatistic, failed,
};

pub(super) const SUSPENSE_DEFAULTS: [(&str, u32); 1] = [("max_age_days", 7)];

type Replay = (Vec<VerifiedProcedureFinding>, u64, u64, u64);

fn arithmetic() -> ReportError {
    failed(
        "procedure_arithmetic",
        "account screen exceeds its exact amount or work-count bounds",
    )
}

fn count(value: usize) -> Result<u64, ReportError> {
    u64::try_from(value).map_err(|_| arithmetic())
}

fn role_accounts(registry: &Registry, role: &str) -> Result<BTreeSet<u128>, ReportError> {
    let mut accounts = BTreeSet::new();
    for (account, roles) in &registry.account_roles {
        if !roles.contains(role) {
            continue;
        }
        if !registry.account_types.contains_key(account) {
            return Err(failed(
                "procedure_roles",
                "account role has no authenticated historical account declaration",
            ));
        }
        accounts.insert(*account);
    }
    Ok(accounts)
}

fn required_role(registry: &Registry, role: &str) -> Result<BTreeSet<u128>, ReportError> {
    let accounts = role_accounts(registry, role)?;
    if accounts.is_empty() {
        return Err(failed(
            "procedure_roles",
            format!("the required {role} role is unassigned at the selected frontier"),
        ));
    }
    Ok(accounts)
}

pub(super) fn replay(
    profile: VerifiedProcedureParameters,
    entries: &[Entry],
    live: &[&Entry],
    effective_through: Option<i32>,
    registry: &Registry,
) -> Result<Replay, ReportError> {
    match profile {
        VerifiedProcedureParameters::SuspenseAging { max_age_days } => {
            suspense(entries, live, effective_through, max_age_days, registry)
        }
        VerifiedProcedureParameters::ExpenseCapitalization => {
            if effective_through.is_some() {
                return Err(failed(
                    "procedure_selection",
                    "capitalization v2 requires its complete all-date population",
                ));
            }
            capitalization(live, registry)
        }
        _ => Err(failed(
            "procedure_profile",
            "expected an account-role screen",
        )),
    }
}

struct OpenBalance {
    net: i128,
    oldest: i32,
    entries: Vec<(i32, u128)>,
}

fn suspense(
    entries: &[Entry],
    live: &[&Entry],
    effective_through: Option<i32>,
    max_age_days: u32,
    registry: &Registry,
) -> Result<Replay, ReportError> {
    let suspense = required_role(registry, "suspense")?;
    let as_of = effective_through.or_else(|| live.iter().filter_map(|entry| entry.effective).max());
    let Some(as_of) = as_of else {
        return Ok((Vec::new(), 0, 0, 0));
    };
    let items = registry.open_items.as_ref().ok_or_else(|| {
        failed(
            "procedure_inputs",
            "suspense aging requires independently reconstructed open-item residuals",
        )
    })?;

    // The registered v3 transcript charges the full source, including entries
    // after the effective cutoff, before its historical application fold.
    let entry_work = count(entries.len())?;
    let mut original_legs = 0u64;
    let mut applications = 0u64;
    for entry in entries {
        original_legs = original_legs
            .checked_add(count(entry.legs.len())?)
            .ok_or_else(arithmetic)?;
        applications = applications
            .checked_add(count(entry.settlements.len())?)
            .ok_or_else(arithmetic)?;
    }
    let input_size = entry_work
        .checked_add(original_legs)
        .and_then(|value| value.checked_add(applications))
        .ok_or_else(arithmetic)?;
    let ordering = input_size
        .checked_mul(u64::from(input_size.max(1).ilog2()) + 1)
        .and_then(|value| value.checked_mul(8))
        .ok_or_else(arithmetic)?;
    let mut comparisons = applications.checked_add(ordering).ok_or_else(arithmetic)?;
    let leg_work = original_legs
        .checked_add(count(items.len())?)
        .ok_or_else(arithmetic)?;
    let population = count(live.len())?;
    let mut balances: BTreeMap<(u128, u32), OpenBalance> = BTreeMap::new();
    for item in items {
        let expected = item
            .original
            .checked_sub(item.applied)
            .and_then(|value| value.checked_sub(item.applied_out))
            .ok_or_else(arithmetic)?;
        if item.original < 0
            || item.applied < 0
            || item.applied_out < 0
            || item.open < 0
            || item.open != expected
            || item.effective_date > as_of
        {
            return Err(failed(
                "procedure_inputs",
                "suspense residual or historical effective-date selection is inconsistent",
            ));
        }
        if item.open == 0 || !suspense.contains(&item.account) {
            continue;
        }
        let signed = if item.debit {
            item.open
        } else {
            item.open.checked_neg().ok_or_else(arithmetic)?
        };
        let balance = balances
            .entry((item.account, item.unit_id))
            .or_insert_with(|| OpenBalance {
                net: 0,
                oldest: item.effective_date,
                entries: Vec::new(),
            });
        balance.net = balance.net.checked_add(signed).ok_or_else(arithmetic)?;
        balance.oldest = balance.oldest.min(item.effective_date);
        balance.entries.push((item.effective_date, item.entry));
    }
    let mut findings = Vec::new();
    for ((account, unit), mut balance) in balances {
        comparisons = comparisons.checked_add(1).ok_or_else(arithmetic)?;
        let age = i64::from(as_of) - i64::from(balance.oldest);
        let max_age = i64::from(max_age_days);
        if age <= max_age {
            continue;
        }
        // Select oldest distinct entries before applying the citation budget;
        // numeric identity only determines the order of the retained citations.
        balance.entries.sort_unstable();
        let mut cited = BTreeSet::new();
        for (_, entry) in balance.entries {
            if cited.len() == MAX_CITES - 1 {
                break;
            }
            cited.insert(entry);
        }
        if findings.len() == MAX_FINDINGS {
            return Err(failed(
                "bounded_input",
                "suspense findings exceed the certificate bound",
            ));
        }
        findings.push(VerifiedProcedureFinding {
            entry: None,
            severity: if age > max_age * 2 { 3 } else { 2 },
            statistic: VerifiedProcedureStatistic::SuspenseAge {
                account,
                age: u64::try_from(age).map_err(|_| arithmetic())?,
                entries: cited.into_iter().collect(),
            },
            population,
            narrative: format!(
                "suspense/clearing account retains uncleared items with net balance {} in unit {unit} aged {age} day(s) (max_age_days {max_age}); opposing items are not implicitly settled",
                balance.net,
            ),
        });
    }
    Ok((findings, entry_work, leg_work, comparisons))
}

fn capitalization(live: &[&Entry], registry: &Registry) -> Result<Replay, ReportError> {
    let fixed_assets = required_role(registry, "fixed_asset")?;
    let accrued = role_accounts(registry, "accrued_expense")?;
    let population = count(live.len())?;
    let mut leg_work = 0u64;
    let mut findings = Vec::new();
    for entry in live {
        if entry.legs.len() != entry.leg_accounts.len() {
            return Err(failed(
                "procedure_inputs",
                "capitalization requires every original leg's account and side",
            ));
        }
        let mut debits = Vec::new();
        let mut credits = BTreeSet::new();
        for (&(unit, amount), &(account, debit)) in entry.legs.iter().zip(&entry.leg_accounts) {
            leg_work = leg_work.checked_add(1).ok_or_else(arithmetic)?;
            let account_type = registry.account_types.get(&account).ok_or_else(|| {
                failed(
                    "procedure_accounts",
                    "capitalization leg lacks an authenticated historical account",
                )
            })?;
            if amount < 0 {
                return Err(failed(
                    "procedure_inputs",
                    "capitalization requires nonnegative original leg magnitudes",
                ));
            }
            if debit && fixed_assets.contains(&account) {
                debits.push((account, unit, amount));
            } else if !debit && (*account_type == 5 || accrued.contains(&account)) {
                credits.insert(account);
            }
        }
        if debits.is_empty() || credits.is_empty() {
            continue;
        }
        if findings.len() == MAX_FINDINGS || credits.len() > MAX_CITES - 2 {
            return Err(failed(
                "bounded_input",
                "capitalization findings or account citations exceed the certificate bound",
            ));
        }
        // Version 2 reports the first (account, unit, amount), not a sum or the
        // largest debit. Preserve its deterministic original accounting scope.
        debits.sort_unstable();
        let (capital_asset, unit, amount) = debits[0];
        let first_credit = *credits.first().ok_or_else(arithmetic)?;
        let scale = *registry.unit_scales.get(&unit).ok_or_else(|| {
            failed(
                "procedure_units",
                "capitalized amount uses an unregistered unit",
            )
        })?;
        let code = |account| {
            registry.account_codes.get(&account).ok_or_else(|| {
                failed(
                    "procedure_accounts",
                    "capitalization narrative requires an authenticated account code",
                )
            })
        };
        findings.push(VerifiedProcedureFinding {
            entry: Some(entry.identity),
            severity: 3,
            statistic: VerifiedProcedureStatistic::CapitalizedExpense {
                capital_asset,
                cost_accounts: credits.into_iter().collect(),
                unit,
                amount,
                scale,
            },
            population,
            narrative: format!(
                "entry capitalizes {amount} in unit {unit} by debiting capital asset {} and crediting operating cost {}",
                code(capital_asset)?,
                code(first_credit)?,
            ),
        });
    }
    Ok((findings, population, leg_work, 0))
}

#[cfg(test)]
mod tests;
