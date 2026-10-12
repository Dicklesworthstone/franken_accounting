//! Literal financial-statement arithmetic and classification (plan §12.1).
//!
//! The oracle owns its account-kind vocabulary, mappings, journal selection,
//! and arithmetic. It imports no model, money, register, or statement engine.
//! Amounts remain in their native units. A balance sheet includes all unclosed
//! nominal balances in equity; an income statement excludes closing transfers
//! and their exact reversal lineage, never ordinary operating adjustments.

use std::collections::{BTreeMap, BTreeSet};

use crate::{Entry, Int, Side};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    BalanceSheet,
    IncomeStatement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountKind {
    Asset,
    Liability,
    Equity,
    Revenue,
    Expense,
    Memo,
    Statistical,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub code: String,
    pub kind: AccountKind,
    pub is_leaf: bool,
}

/// The posted columns of one authoritative account fold. Reservations are
/// deliberately absent from this input: they are not financial positions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Balance {
    pub account: String,
    pub unit: u32,
    pub debits: i128,
    pub credits: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    DuplicateAccount(String),
    UnknownAccount(String),
    NonLeaf(String),
    DuplicateBalance { account: String, unit: u32 },
    NegativeAmount { account: String, unit: u32 },
    DuplicateUnit(u32),
    UnknownUnit(u32),
    MissingMapping(String),
    RepeatedMapping(String),
    OutsideCoverage(String),
    DuplicateLine(String),
    Overflow { unit: u32, line: String },
    Identity { unit: u32, residual: Int },
    InvalidPrefix,
    InvalidReversal(usize),
    AmbiguousMigrationClosing { entry: usize, period: String },
}

fn covered(kind: Kind, account: AccountKind) -> bool {
    match kind {
        Kind::BalanceSheet => !matches!(account, AccountKind::Memo | AccountKind::Statistical),
        Kind::IncomeStatement => matches!(account, AccountKind::Revenue | AccountKind::Expense),
    }
}

fn chart(accounts: &[Account]) -> Result<BTreeMap<&str, &Account>, Error> {
    let mut result = BTreeMap::new();
    for account in accounts {
        if result.insert(account.code.as_str(), account).is_some() {
            return Err(Error::DuplicateAccount(account.code.clone()));
        }
    }
    Ok(result)
}

/// Check a literal account-to-line partition independently of any expression
/// parser. Every covered leaf is required, including leaves with zero balance.
/// Parent rows, duplicate leaves and leaves outside the definition's coverage
/// are refused; computed lines do not participate in this mapping list.
pub fn validate_partition(
    kind: Kind,
    accounts: &[Account],
    mappings: &[(&str, &[&str])],
) -> Result<(), Error> {
    let accounts = chart(accounts)?;
    let mut seen = BTreeSet::new();
    let mut lines = BTreeSet::new();
    for (line, mapped) in mappings {
        if !lines.insert(*line) {
            return Err(Error::DuplicateLine((*line).into()));
        }
        for code in *mapped {
            let account = accounts
                .get(code)
                .ok_or_else(|| Error::UnknownAccount((*code).into()))?;
            if !account.is_leaf {
                return Err(Error::NonLeaf((*code).into()));
            }
            if !covered(kind, account.kind) {
                return Err(Error::OutsideCoverage((*code).into()));
            }
            if !seen.insert(*code) {
                return Err(Error::RepeatedMapping((*code).into()));
            }
        }
    }
    for account in accounts.values() {
        if account.is_leaf && covered(kind, account.kind) && !seen.contains(account.code.as_str()) {
            return Err(Error::MissingMapping(account.code.clone()));
        }
    }
    Ok(())
}

fn base_line(kind: Kind, account: AccountKind) -> Option<(&'static str, bool)> {
    match (kind, account) {
        (Kind::BalanceSheet, AccountKind::Asset) => Some(("assets", false)),
        (Kind::BalanceSheet, AccountKind::Liability) => Some(("liabilities", true)),
        (Kind::BalanceSheet, AccountKind::Equity) => Some(("equity", true)),
        (Kind::BalanceSheet, AccountKind::Revenue) => Some(("unclosed_revenue", true)),
        (Kind::BalanceSheet, AccountKind::Expense) => Some(("unclosed_expense", false)),
        (Kind::IncomeStatement, AccountKind::Revenue) => Some(("revenue", true)),
        (Kind::IncomeStatement, AccountKind::Expense) => Some(("expense", false)),
        _ => None,
    }
}

/// Standard statements over the source-selected posted balances. Balance-sheet
/// input is stock from inception, not year-to-date; income input is selected
/// period activity with closing transfers removed at the journal-entry level.
///
/// Each supplied unit appears even when it has no balances. All summation uses
/// the oracle's independent unbounded integer, then each reported line must fit
/// the public i128 mantissa. This accepts large cancelling intermediates without
/// accepting an unrepresentable output or netting different units together.
pub fn render(
    kind: Kind,
    accounts: &[Account],
    balances: &[Balance],
    units: &[u32],
) -> Result<BTreeMap<u32, BTreeMap<String, Int>>, Error> {
    let accounts = chart(accounts)?;
    let mut result = BTreeMap::new();
    let base_names: &[&str] = match kind {
        Kind::BalanceSheet => &[
            "assets",
            "liabilities",
            "equity",
            "unclosed_revenue",
            "unclosed_expense",
        ],
        Kind::IncomeStatement => &["revenue", "expense"],
    };
    for unit in units {
        let rows: BTreeMap<String, Int> = base_names
            .iter()
            .map(|name| ((*name).into(), Int::zero()))
            .collect();
        if result.insert(*unit, rows).is_some() {
            return Err(Error::DuplicateUnit(*unit));
        }
    }
    let mut seen = BTreeSet::new();
    for balance in balances {
        let account = accounts
            .get(balance.account.as_str())
            .ok_or_else(|| Error::UnknownAccount(balance.account.clone()))?;
        if !account.is_leaf {
            return Err(Error::NonLeaf(balance.account.clone()));
        }
        if !seen.insert((balance.account.as_str(), balance.unit)) {
            return Err(Error::DuplicateBalance {
                account: balance.account.clone(),
                unit: balance.unit,
            });
        }
        if balance.debits < 0 || balance.credits < 0 {
            return Err(Error::NegativeAmount {
                account: balance.account.clone(),
                unit: balance.unit,
            });
        }
        let lines = result
            .get_mut(&balance.unit)
            .ok_or(Error::UnknownUnit(balance.unit))?;
        if let Some((line, credit_sign)) = base_line(kind, account.kind) {
            let debit = Int::from_i128(balance.debits);
            let credit = Int::from_i128(balance.credits);
            let value = if credit_sign {
                credit.sub(&debit)
            } else {
                debit.sub(&credit)
            };
            let total = lines
                .get_mut(line)
                .expect("the literal base line was initialized");
            *total = total.add(&value);
        }
    }
    for (unit, lines) in &mut result {
        match kind {
            Kind::BalanceSheet => {
                let unclosed = lines["unclosed_revenue"].sub(&lines["unclosed_expense"]);
                let equity = lines["equity"].add(&unclosed);
                let liabilities_and_equity = lines["liabilities"].add(&equity);
                let residual = lines["assets"].sub(&liabilities_and_equity);
                lines.insert("unclosed_earnings".into(), unclosed);
                lines.insert("total_equity".into(), equity);
                lines.insert("liabilities_and_equity".into(), liabilities_and_equity);
                lines.insert("balance_check".into(), residual);
            }
            Kind::IncomeStatement => {
                let income = lines["revenue"].sub(&lines["expense"]);
                lines.insert("net_income".into(), income);
            }
        }
        for (line, value) in lines.iter() {
            if value.to_i128().is_none() {
                return Err(Error::Overflow {
                    unit: *unit,
                    line: line.clone(),
                });
            }
        }
        if kind == Kind::BalanceSheet && !lines["balance_check"].is_zero() {
            return Err(Error::Identity {
                unit: *unit,
                residual: lines["balance_check"].clone(),
            });
        }
    }
    Ok(result)
}

/// Select the reference journal's income activity independently of the native
/// fold. `accepted_prefix` is an oracle entry count, never a CommitSeq. The
/// caller supplies the already-visible migration history and Closing-kind
/// period codes; a Migration into such a period lacks the original class and
/// cannot safely be classified as either an operating or closing transfer.
pub fn activity_balances(
    entries: &[Entry],
    periods: &[&str],
    closing_periods: &[&str],
    accepted_prefix: usize,
) -> Result<Vec<Balance>, Error> {
    let entries = entries.get(..accepted_prefix).ok_or(Error::InvalidPrefix)?;
    let mut values: BTreeMap<(String, u32), (Int, Int)> = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        if entry.class == "Pending"
            || entry.legs.is_empty()
            || !periods.contains(&entry.period.as_str())
        {
            continue;
        }
        let mut original = index;
        while entries[original].class == "Reversal" {
            let target = entries[original]
                .reverses
                .ok_or(Error::InvalidReversal(original))?;
            if target >= original {
                return Err(Error::InvalidReversal(original));
            }
            original = target;
        }
        let source = &entries[original];
        if source.class == "Closing" {
            continue;
        }
        if source.class == "Migration" && closing_periods.contains(&source.period.as_str()) {
            return Err(Error::AmbiguousMigrationClosing {
                entry: original,
                period: source.period.clone(),
            });
        }
        for leg in &entry.legs {
            if leg.mantissa < 0 {
                return Err(Error::NegativeAmount {
                    account: leg.account.clone(),
                    unit: leg.unit,
                });
            }
            let value = values
                .entry((leg.account.clone(), leg.unit))
                .or_insert_with(|| (Int::zero(), Int::zero()));
            let amount = Int::from_i128(leg.mantissa);
            match leg.side {
                Side::Debit => value.0 = value.0.add(&amount),
                Side::Credit => value.1 = value.1.add(&amount),
            }
        }
    }
    values
        .into_iter()
        .map(|((account, unit), (debits, credits))| {
            let overflow = || Error::Overflow {
                unit,
                line: account.clone(),
            };
            Ok(Balance {
                account: account.clone(),
                unit,
                debits: debits.to_i128().ok_or_else(overflow)?,
                credits: credits.to_i128().ok_or_else(overflow)?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Leg;
    use fa_time::DateDay;

    fn account(code: &str, kind: AccountKind) -> Account {
        Account {
            code: code.into(),
            kind,
            is_leaf: true,
        }
    }

    fn balance(code: &str, unit: u32, debits: i128, credits: i128) -> Balance {
        Balance {
            account: code.into(),
            unit,
            debits,
            credits,
        }
    }

    fn chart() -> Vec<Account> {
        vec![
            account("cash", AccountKind::Asset),
            account("accumulated", AccountKind::Asset),
            account("debt", AccountKind::Liability),
            account("capital", AccountKind::Equity),
            account("revenue", AccountKind::Revenue),
            account("expense", AccountKind::Expense),
            account("unused", AccountKind::Expense),
        ]
    }

    #[test]
    fn balance_sheet_keeps_all_unclosed_earnings_and_contra_signs() {
        let before = vec![
            balance("cash", 1, 1_300, 0),
            balance("accumulated", 1, 0, 50),
            balance("debt", 1, 0, 300),
            balance("capital", 1, 0, 500),
            balance("revenue", 1, 0, 700),
            balance("expense", 1, 250, 0),
        ];
        let result = render(Kind::BalanceSheet, &chart(), &before, &[1]).unwrap();
        assert_eq!(result[&1]["assets"].to_i128(), Some(1_250));
        assert_eq!(result[&1]["unclosed_earnings"].to_i128(), Some(450));
        assert_eq!(result[&1]["total_equity"].to_i128(), Some(950));
        let after = vec![
            balance("cash", 1, 1_300, 0),
            balance("accumulated", 1, 0, 50),
            balance("debt", 1, 0, 300),
            balance("capital", 1, 0, 950),
            balance("revenue", 1, 700, 700),
            balance("expense", 1, 250, 250),
        ];
        let closed = render(Kind::BalanceSheet, &chart(), &after, &[1]).unwrap();
        assert!(closed[&1]["unclosed_earnings"].is_zero());
        assert_eq!(closed[&1]["total_equity"], result[&1]["total_equity"]);
    }

    #[test]
    fn zero_balance_accounts_still_need_exactly_one_mapping() {
        let chart = chart();
        assert!(
            validate_partition(
                Kind::IncomeStatement,
                &chart,
                &[
                    ("revenue", &["revenue"]),
                    ("expense", &["expense", "unused"])
                ]
            )
            .is_ok()
        );
        assert_eq!(
            validate_partition(
                Kind::IncomeStatement,
                &chart,
                &[("revenue", &["revenue"]), ("expense", &["expense"])]
            ),
            Err(Error::MissingMapping("unused".into()))
        );
        assert_eq!(
            validate_partition(
                Kind::IncomeStatement,
                &chart,
                &[
                    ("revenue", &["revenue"]),
                    ("expense", &["expense", "unused"]),
                    ("again", &["unused"])
                ]
            ),
            Err(Error::RepeatedMapping("unused".into()))
        );
    }

    #[test]
    fn units_never_offset_each_others_imbalance() {
        let balances = vec![balance("cash", 1, 10, 0), balance("capital", 2, 0, 10)];
        assert!(matches!(
            render(Kind::BalanceSheet, &chart(), &balances, &[1, 2]),
            Err(Error::Identity { unit: 1, .. })
        ));
        let empty = render(Kind::IncomeStatement, &chart(), &[], &[2, 1]).unwrap();
        assert_eq!(empty.keys().copied().collect::<Vec<_>>(), vec![1, 2]);
        assert!(empty.values().all(|lines| lines["net_income"].is_zero()));
    }

    #[test]
    fn exact_large_amounts_and_cancellation_use_independent_limbs() {
        let large = 9_007_199_254_740_993i128;
        let exact = render(
            Kind::IncomeStatement,
            &chart(),
            &[balance("revenue", 1, 0, large), balance("expense", 1, 3, 0)],
            &[1],
        )
        .unwrap();
        assert_eq!(exact[&1]["net_income"].to_i128(), Some(large - 3));
        let chart = vec![
            account("a", AccountKind::Asset),
            account("b", AccountKind::Asset),
            account("c", AccountKind::Asset),
            account("e", AccountKind::Equity),
        ];
        let cancelled = render(
            Kind::BalanceSheet,
            &chart,
            &[
                balance("a", 1, i128::MAX, 0),
                balance("b", 1, i128::MAX, 0),
                balance("c", 1, 0, i128::MAX),
                balance("e", 1, 0, i128::MAX),
            ],
            &[1],
        )
        .unwrap();
        assert_eq!(cancelled[&1]["assets"].to_i128(), Some(i128::MAX));
        assert!(matches!(
            render(
                Kind::BalanceSheet,
                &chart,
                &[balance("a", 1, i128::MAX, 0), balance("b", 1, 1, 0)],
                &[1]
            ),
            Err(Error::Overflow { .. })
        ));
    }

    fn entry(
        class: &str,
        period: &str,
        account: &str,
        side: Side,
        mantissa: i128,
        reverses: Option<usize>,
    ) -> Entry {
        Entry {
            class: class.into(),
            date: DateDay::parse("2026-12-31").unwrap(),
            period: period.into(),
            legs: vec![Leg {
                side,
                account: account.into(),
                unit: 1,
                entity: None,
                mantissa,
            }],
            key: Vec::new(),
            reverses,
            resolves: None,
            settles: Vec::new(),
            run: None,
        }
    }

    #[test]
    fn income_excludes_closing_and_reversal_lineage_but_keeps_adjustments() {
        let history = vec![
            entry("Original", "P12", "revenue", Side::Credit, 100, None),
            entry("Pending", "P12", "revenue", Side::Credit, 9_999, None),
            entry("Adjusting", "CL", "expense", Side::Debit, 20, None),
            entry("Closing", "CL", "revenue", Side::Debit, 100, None),
            entry("Reversal", "P12", "revenue", Side::Credit, 100, Some(3)),
            entry("Reversal", "P12", "revenue", Side::Debit, 100, Some(4)),
        ];
        for prefix in 3..=history.len() {
            let balances =
                activity_balances(&history, &["P12", "CL", "P12"], &["CL"], prefix).unwrap();
            let income = render(Kind::IncomeStatement, &chart(), &balances, &[1]).unwrap();
            assert_eq!(
                income[&1]["net_income"].to_i128(),
                Some(80),
                "prefix {prefix}"
            );
        }
        let earlier = activity_balances(&history, &["P12"], &["CL"], 1).unwrap();
        assert_eq!(
            render(Kind::IncomeStatement, &chart(), &earlier, &[1]).unwrap()[&1]["net_income"]
                .to_i128(),
            Some(100)
        );
    }

    #[test]
    fn migration_closing_requires_original_classification_and_bad_lineage_refuses() {
        let history = vec![entry("Migration", "CL", "revenue", Side::Debit, 100, None)];
        assert_eq!(
            activity_balances(&history, &["CL"], &["CL"], 1),
            Err(Error::AmbiguousMigrationClosing {
                entry: 0,
                period: "CL".into()
            })
        );
        assert!(
            activity_balances(&history, &["P12"], &["CL"], 1)
                .unwrap()
                .is_empty()
        );
        let cycle = vec![entry(
            "Reversal",
            "P12",
            "revenue",
            Side::Debit,
            100,
            Some(0),
        )];
        assert_eq!(
            activity_balances(&cycle, &["P12"], &[], 1),
            Err(Error::InvalidReversal(0))
        );
    }
}
