//! Independent posted-principal schedule from authenticated original legs.
//!
//! Cash attribution uses each party's own counter-leg margin. Principal
//! transfers are a separate, explicitly marked, cash-free operation. Neither
//! a finding nor a native read witness supplies parties, roles or amounts.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Entry, MAX_CITES, MAX_FINDINGS, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureStatistic, failed,
};
use crate::report::{dimension, metadata, native_subledger};

const RULE: &str = "posted_principal_transfer_v1";
const MAX_CITATION_MEMBERSHIPS: usize = super::MAX_REPORT_BUNDLE_BYTES / 32;

/// The complete historically selected Party declarations and original party
/// dimensions. Unknown values keep their literal identity, as the v5 law says.
#[derive(Clone, Default)]
pub(crate) struct Context {
    pub(crate) codes: BTreeMap<u128, String>,
    aliases: BTreeMap<u128, u128>,
    pub(crate) legs: BTreeMap<u128, Vec<Vec<u128>>>,
}

impl Context {
    pub(crate) fn declare(&mut self, book: &[u8; 16], body: &[u8]) -> Result<(), ReportError> {
        let code = native_subledger::party_code(body)?;
        let party = metadata::framed_identity(b"fa:vid:party:v1", &[book, code.as_bytes()]);
        let value = dimension::value_vid(book, "party", &code);
        if self.codes.insert(party, code).is_some() {
            return Err(invalid("duplicate investor Party declaration"));
        }
        for alias in [party, value] {
            if self
                .aliases
                .insert(alias, party)
                .is_some_and(|previous| previous != party)
            {
                return Err(invalid("ambiguous investor Party identity"));
            }
        }
        Ok(())
    }

    fn name(&self, values: &[u128]) -> Named {
        let named: BTreeSet<_> = values
            .iter()
            .map(|value| self.aliases.get(value).copied().unwrap_or(*value))
            .collect();
        match named.len() {
            0 => Named::Absent,
            1 => named.first().copied().map_or(Named::Absent, Named::Party),
            _ => Named::Ambiguous,
        }
    }

    fn code(&self, party: u128) -> String {
        self.codes
            .get(&party)
            .cloned()
            .unwrap_or_else(|| format!("{party:032x}"))
    }
}

fn invalid(detail: &str) -> ReportError {
    failed("procedure_profile", detail)
}
fn arithmetic() -> ReportError {
    failed(
        "procedure_arithmetic",
        "investor amount or work count overflows",
    )
}
fn add(a: i128, b: i128) -> Result<i128, ReportError> {
    a.checked_add(b).ok_or_else(arithmetic)
}
fn sub(a: i128, b: i128) -> Result<i128, ReportError> {
    a.checked_sub(b).ok_or_else(arithmetic)
}
fn count(count: &mut u64, n: usize) -> Result<(), ReportError> {
    *count = count.checked_add(n as u64).ok_or_else(arithmetic)?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Named {
    Absent,
    Party(u128),
    Ambiguous,
}

#[derive(Clone, Copy)]
struct Leg {
    amount: i128,
    party: Named,
    debit: bool,
}

#[derive(Default)]
struct Partition {
    receipts: Vec<Leg>,
    payments: Vec<Leg>,
    credits: Vec<Leg>,
    debits: Vec<Leg>,
    investors: Vec<Leg>,
    clearing: Vec<Leg>,
    other: bool,
    accounts: BTreeSet<u128>,
}

#[derive(Default)]
struct Flow {
    cash: BTreeMap<u128, i128>,
    unresolved: i128,
}

/// Attribute by margins, never proportionally. Full coverage uses each
/// counter-leg's amount; short coverage needs either one owner or individually
/// identified cash legs. Unnamed margins remain explicitly unresolved.
fn attribute(cash: &[Leg], counterpart: &[Leg]) -> Result<Flow, ReportError> {
    let mut out = Flow::default();
    let total = cash.iter().try_fold(0, |sum, leg| add(sum, leg.amount))?;
    if total == 0
        || cash
            .iter()
            .chain(counterpart)
            .all(|leg| leg.party == Named::Absent)
    {
        return Ok(out);
    }
    let inherited = if counterpart.iter().all(|leg| leg.party == Named::Absent)
        && !cash.iter().any(|leg| leg.party == Named::Ambiguous)
    {
        let names: BTreeSet<_> = cash
            .iter()
            .filter_map(|leg| {
                if let Named::Party(party) = leg.party {
                    Some(party)
                } else {
                    None
                }
            })
            .collect();
        (names.len() == 1).then(|| names.first().copied()).flatten()
    } else {
        None
    };
    let mut margins = BTreeMap::new();
    let mut unnamed = 0;
    for leg in counterpart {
        let owner = match leg.party {
            Named::Party(party) => Some(party),
            Named::Absent => inherited,
            Named::Ambiguous => None,
        };
        if let Some(party) = owner {
            let margin = margins.entry(party).or_insert(0);
            *margin = add(*margin, leg.amount)?;
        } else {
            unnamed = add(unnamed, leg.amount)?;
        }
    }
    let covered = margins
        .values()
        .try_fold(unnamed, |sum, &margin| add(sum, margin))?;
    if total >= covered {
        out.cash = margins;
        out.unresolved = unnamed;
    } else if unnamed == 0 && margins.len() == 1 {
        out.cash
            .insert(*margins.first_key_value().ok_or_else(arithmetic)?.0, total);
    } else {
        out.cash.extend(margins.keys().map(|&party| (party, 0)));
        let mut assigned = 0;
        for leg in cash {
            if let Named::Party(party) = leg.party
                && let (Some(&limit), Some(given)) = (margins.get(&party), out.cash.get_mut(&party))
            {
                let share = leg.amount.min(sub(limit, *given)?);
                *given = add(*given, share)?;
                assigned = add(assigned, share)?;
            }
        }
        out.unresolved = sub(total, assigned)?;
    }
    Ok(out)
}

/// Credits add posted principal; debits remove it. This law admits one named
/// investor against unnamed marked clearing, or a balanced two-party transfer.
fn transfers(
    part: &Partition,
    comparisons: &mut u64,
) -> Result<BTreeMap<u128, [i128; 2]>, ReportError> {
    let has_cash = !part.receipts.is_empty() || !part.payments.is_empty();
    if !part.clearing.is_empty() && (part.investors.is_empty() || has_cash || part.other) {
        return Err(invalid(
            "marked principal transfer mixes cash, other accounts or lacks an investor",
        ));
    }
    if part.clearing.is_empty() && (has_cash || part.other) {
        count(comparisons, part.investors.len())?;
        if part.investors.iter().any(|leg| leg.debit) && part.investors.iter().any(|leg| !leg.debit)
        {
            return Err(invalid(
                "direct principal transfer is mixed with cash or other accounts",
            ));
        }
        return Ok(BTreeMap::new());
    }
    if part.investors.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut owners: BTreeMap<u128, [i128; 2]> = BTreeMap::new();
    let mut debit = 0;
    let mut credit = 0;
    for leg in &part.investors {
        count(comparisons, 1)?;
        let Named::Party(party) = leg.party else {
            return Err(invalid("principal transfer investor has no unique party"));
        };
        if leg.amount <= 0 {
            return Err(invalid("principal transfer amount must be positive"));
        }
        let movement = owners.entry(party).or_default();
        let side = usize::from(leg.debit);
        movement[side] = add(movement[side], leg.amount)?;
        if leg.debit {
            debit = add(debit, leg.amount)?;
        } else {
            credit = add(credit, leg.amount)?;
        }
    }
    if part.clearing.is_empty() {
        if owners.len() == 1 && debit == credit {
            return Ok(BTreeMap::new());
        }
        if owners.len() != 2 {
            return Err(invalid(
                "direct principal transfer must name exactly two parties",
            ));
        }
    } else if part.investors.len() != 1 {
        return Err(invalid(
            "clearing principal transfer must have exactly one investor leg",
        ));
    }
    for leg in &part.clearing {
        count(comparisons, 1)?;
        if leg.party != Named::Absent || leg.amount <= 0 {
            return Err(invalid("principal clearing leg is named or nonpositive"));
        }
        if leg.debit {
            debit = add(debit, leg.amount)?;
        } else {
            credit = add(credit, leg.amount)?;
        }
    }
    if debit != credit {
        return Err(invalid("principal transfer partition is unbalanced"));
    }
    Ok(owners)
}

#[derive(Default)]
struct Position {
    amounts: [i128; 4], // cash in, cash out, transfer in, transfer out
    first_funding: Option<i32>,
    accounts: BTreeSet<u128>,
    entries: BTreeSet<u128>,
    investor: bool,
}

#[derive(Default)]
struct Unresolved {
    amount: i128,
    accounts: BTreeSet<u128>,
    entries: BTreeSet<u128>,
    parties: BTreeSet<u128>,
}

fn insert(set: &mut BTreeSet<u128>, value: u128, retained: &mut usize) -> Result<(), ReportError> {
    if set.insert(value) {
        *retained = retained.checked_add(1).ok_or_else(arithmetic)?;
        if *retained > MAX_CITATION_MEMBERSHIPS {
            return Err(failed(
                "bounded_input",
                "investor citation closure exceeds the independent replay budget; no rows were omitted",
            ));
        }
    }
    Ok(())
}

pub(super) fn replay(
    live: &[&Entry],
    cohort_window_days: u32,
    registry: &Registry,
) -> Result<(Vec<VerifiedProcedureFinding>, u64, u64), ReportError> {
    if cohort_window_days == 0 {
        return Err(invalid("cohort_window_days must be positive"));
    }
    let source = registry
        .trace
        .as_ref()
        .ok_or_else(|| invalid("investor entity source is absent"))?;
    let context = source
        .investors
        .as_ref()
        .ok_or_else(|| invalid("investor Party source is absent"))?;
    let role = |account: u128, name: &str| {
        registry
            .account_roles
            .get(&account)
            .is_some_and(|roles| roles.contains(name))
    };
    if !registry
        .account_roles
        .values()
        .any(|roles| roles.contains("cash"))
    {
        return Err(invalid(
            "investor schedule requires a historically declared cash account role",
        ));
    }
    let mut entities = BTreeSet::new();
    for entry in live {
        let facts = source
            .entries
            .get(&entry.identity)
            .ok_or_else(|| invalid("investor legal-entity dimensions are incomplete"))?;
        let parties = context
            .legs
            .get(&entry.identity)
            .ok_or_else(|| invalid("investor party dimensions are incomplete"))?;
        if facts.entities.len() != entry.legs.len()
            || parties.len() != entry.legs.len()
            || entry.leg_accounts.len() != entry.legs.len()
        {
            return Err(invalid("investor original leg metadata is incomplete"));
        }
        for values in &facts.entities {
            if values.len() > 1 {
                return Err(invalid("investor leg has multiple legal entities"));
            }
            entities.extend(values.iter().copied());
        }
    }
    let mut ordered = live.to_vec();
    ordered.sort_by_key(|entry| (entry.effective, entry.identity));
    let mut positions: BTreeMap<(u128, u32), Position> = BTreeMap::new();
    let mut unresolved: BTreeMap<u32, Unresolved> = BTreeMap::new();
    let mut cash_balances = BTreeMap::new();
    let (mut legs, mut comparisons, mut population, mut retained) = (0, 0, 0_u64, 0);
    for entry in ordered {
        let day = entry
            .effective
            .ok_or_else(|| invalid("investor posting has no effective date"))?;
        let facts = &source.entries[&entry.identity];
        let parties = &context.legs[&entry.identity];
        let mut parts: BTreeMap<(u32, Option<u128>), Partition> = BTreeMap::new();
        for (ordinal, (&(unit, amount), &(account, debit))) in
            entry.legs.iter().zip(&entry.leg_accounts).enumerate()
        {
            count(&mut legs, 1)?;
            let Some(&account_type) = registry.account_types.get(&account) else {
                continue;
            };
            let amount = amount.checked_abs().ok_or_else(arithmetic)?;
            let entity = if let Some(entity) = facts.entities[ordinal].first() {
                Some(*entity)
            } else if entities.len() > 1 {
                return Err(invalid(
                    "multi-entity investor population has an unassigned leg",
                ));
            } else {
                entities.first().copied()
            };
            let part = parts.entry((unit, entity)).or_default();
            part.accounts.insert(account);
            let leg = Leg {
                amount,
                party: context.name(&parties[ordinal]),
                debit,
            };
            let cash = role(account, "cash");
            let investor = account_type == 3 || role(account, "investor_capital");
            let clearing = role(account, "investor_transfer");
            if clearing && (cash || investor) {
                return Err(invalid(
                    "investor_transfer role overlaps cash or investor capital",
                ));
            }
            if cash {
                let balance = cash_balances.entry(unit).or_insert(0);
                *balance = if debit {
                    add(*balance, amount)?
                } else {
                    sub(*balance, amount)?
                };
                if debit {
                    part.receipts.push(leg);
                } else {
                    part.payments.push(leg);
                }
            } else {
                if investor {
                    part.investors.push(leg);
                } else if clearing {
                    part.clearing.push(leg);
                } else {
                    part.other = true;
                }
                if debit {
                    part.debits.push(leg);
                } else {
                    part.credits.push(leg);
                }
            }
        }
        for ((unit, _), part) in parts {
            let principal = transfers(&part, &mut comparisons)?;
            let incoming = attribute(&part.receipts, &part.credits)?;
            let outgoing = attribute(&part.payments, &part.debits)?;
            for (flow, cash, group) in [
                (&incoming, &part.receipts, &part.credits),
                (&outgoing, &part.payments, &part.debits),
            ] {
                if flow.unresolved > 0 {
                    let u = unresolved.entry(unit).or_default();
                    u.amount = add(u.amount, flow.unresolved)?;
                    insert(&mut u.entries, entry.identity, &mut retained)?;
                    for &account in &part.accounts {
                        insert(&mut u.accounts, account, &mut retained)?;
                    }
                    for leg in cash.iter().chain(group) {
                        if let Named::Party(party) = leg.party {
                            insert(&mut u.parties, party, &mut retained)?;
                        }
                    }
                }
            }
            let names: BTreeSet<_> = incoming
                .cash
                .keys()
                .chain(outgoing.cash.keys())
                .chain(principal.keys())
                .copied()
                .collect();
            for party in names {
                let transfer = principal.get(&party).copied().unwrap_or_default();
                let amounts = [
                    incoming.cash.get(&party).copied().unwrap_or(0),
                    outgoing.cash.get(&party).copied().unwrap_or(0),
                    transfer[0],
                    transfer[1],
                ];
                if amounts == [0; 4] {
                    continue;
                }
                count(&mut population, 1)?;
                let position = positions.entry((party, unit)).or_default();
                position.investor |= !part.investors.is_empty();
                for (total, amount) in position.amounts.iter_mut().zip(amounts) {
                    *total = add(*total, amount)?;
                }
                if (amounts[0] > 0 || amounts[2] > 0)
                    && position.first_funding.is_none_or(|first| day < first)
                {
                    position.first_funding = Some(day);
                }
                insert(&mut position.entries, entry.identity, &mut retained)?;
                for &account in &part.accounts {
                    insert(&mut position.accounts, account, &mut retained)?;
                }
                if positions.len() > MAX_FINDINGS {
                    return Err(failed(
                        "bounded_input",
                        "investor population exceeds its independent bound",
                    ));
                }
            }
        }
    }
    positions.retain(|_, position| position.investor);
    let earliest = positions
        .values()
        .filter_map(|position| position.first_funding)
        .min()
        .unwrap_or(0);
    let mut findings = Vec::new();
    for ((party, unit), position) in positions {
        count(&mut comparisons, 1)?;
        let scale = *registry
            .unit_scales
            .get(&unit)
            .ok_or_else(|| invalid("investor unit is unregistered"))?;
        let principal_in = add(position.amounts[0], position.amounts[2])?;
        let principal_out = add(position.amounts[1], position.amounts[3])?;
        if principal_in == principal_out {
            continue;
        }
        let net_winner = principal_out > principal_in;
        let amount = if net_winner {
            sub(principal_out, principal_in)?
        } else {
            sub(principal_in, principal_out)?
        };
        let cohort = position.first_funding.map_or(1, |first| {
            (i64::from(first) - i64::from(earliest)).unsigned_abs() / u64::from(cohort_window_days)
                + 1
        });
        let incomplete = unresolved
            .get(&unit)
            .is_some_and(|u| u.parties.contains(&party));
        let status = if net_winner {
            "net_winner"
        } else {
            "net_loser"
        };
        let statistic_name = if net_winner {
            "fictitious_profit_clawback"
        } else {
            "net_equity_claim"
        };
        let attribution = if incomplete { "incomplete" } else { "complete" };
        if position.accounts.len() > MAX_CITES {
            return Err(failed(
                "bounded_input",
                "investor account citations exceed the native bound",
            ));
        }
        let entries = position
            .entries
            .into_iter()
            .take(MAX_CITES - position.accounts.len())
            .collect();
        findings.push(VerifiedProcedureFinding {
            entry: None, severity: if net_winner { 3 } else { 2 }, population: population.max(1),
            statistic: VerifiedProcedureStatistic::InvestorPrincipal { party, unit, net_winner, amount, scale, accounts: position.accounts.into_iter().collect(), entries },
            narrative: format!("investor {} (cohort {cohort}, status={status}): cash_in={}, cash_out={}, transfer_in={}, transfer_out={}, {statistic_name}={amount}, principal_rule={RULE}, attribution={attribution}", context.code(party), position.amounts[0], position.amounts[1], position.amounts[2], position.amounts[3]),
        });
    }
    for (unit, u) in unresolved {
        let scale = *registry
            .unit_scales
            .get(&unit)
            .ok_or_else(|| invalid("unresolved investor unit is unregistered"))?;
        let mut names: Vec<_> = u.parties.iter().map(|&party| context.code(party)).collect();
        names.sort();
        let entry_count = u.entries.len();
        let entries: Vec<_> = u.entries.into_iter().take(MAX_CITES).collect();
        let accounts = u
            .accounts
            .into_iter()
            .take(MAX_CITES - entries.len())
            .collect();
        findings.push(VerifiedProcedureFinding {
            entry: None, severity: 2, population: population.max(1),
            statistic: VerifiedProcedureStatistic::UnresolvedInvestorCash { unit, amount: u.amount, scale, accounts, entries },
            narrative: format!("unresolved attribution: {} of cash in {entry_count} entries is not accounted for by any one party's own legs (parties named: [{}]); the net investment of each investor named is incomplete", u.amount, names.join(", ")),
        });
    }
    if findings.len() > MAX_FINDINGS {
        return Err(failed(
            "bounded_input",
            "investor findings exceed the certificate bound",
        ));
    }
    Ok((findings, legs, comparisons))
}

#[cfg(test)]
mod tests;
