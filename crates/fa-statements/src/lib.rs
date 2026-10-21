//! Exact financial-statement arithmetic over explicitly selected journal folds.
//!
//! The caller supplies the complete historical chart, registered native units,
//! and posted balances at one known-at frontier. A balance-sheet column is a
//! stock fold including actual Closing entries; an income column is period
//! activity excluding Closing and its reversal lineage. This crate performs no
//! I/O and cannot establish that source-selection premise itself. The facade
//! binds it to native read evidence and the authenticated journal prefix.
//!
//! Definitions are data: account-type mappings and exact additions/subtractions
//! of earlier lines. Covered leaves partition before any arithmetic, including
//! zero-balance leaves. Each unit remains separate, comparisons share one chart
//! and known-at frontier, reservations never become income or equity, and no
//! rounding residual, FX conversion or synthetic journal entry is introduced.
//! Canonical definition bytes travel in each output so a retained certificate
//! can replay the definition actually used. This is a built-in definition
//! snapshot, not custom-definition activation or a GAAP-conformity claim.

#![forbid(unsafe_code)]
// 128-bit (amount) arithmetic only: clippy.toml exempts the narrower integers.
#![deny(clippy::arithmetic_side_effects, clippy::disallowed_methods)]

mod definition;

/// Direct and indirect cash-flow statements (`CashFlowClassification`, reconciling to cash)
/// and `EquityRollForward` statements (plan §12.1, `fa-i9yn`).
pub mod cash_flow;
/// Concordat: multi-book adjustment layers, book-to-book bridges, intercompany pair matching,
/// deterministic elimination derivation, and consolidated equity reconciliation (plan §12.2, §12.3, FA-INV-13).
pub mod concordat;
/// Custom statement definitions (`AccountSetExpr`), `statement lint`, and presentation rounding
/// with an explicit residual line (plan §12.1, `fa-i9yn`).
pub mod custom;
/// Deterministic Markdown IR for certified financial statements and restatement diffs (fa-9ae, fa-cet).
pub mod markdown;
/// Regulatory schedule definitions (FFIEC 031/041 Call Report Schedules RC/RI, FR Y-9C Schedules HC/HI)
/// and versioned FFIEC validity and quality edits (`regulatory.edits(<form>@<quarter>)`) (plan §12.6, `fa-pbm`).
pub mod regulatory;
/// Deterministic HTML, SVG, PDF, and PDF/A-2b renderers, semantic restatement diffs,
/// and lineage flowcharts over certified `StatementMarkdownIr` (`fa-cet`, `fa-949`).
pub mod render;
/// Exact account lead schedules with classified activity and stock tie-outs.
pub mod roll_forward;

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use fa_model::{AccountType, Id128, Writer};
use fa_money::wide::U256;
use fa_time::DateDay;

pub use definition::{
    BALANCE_SHEET, Basis, INCOME_STATEMENT, LineDefinition, LineSource, MAX_DEFINITION_BYTES, Sign,
    StatementDefinition, StatementKind,
};

pub const OUTPUT_FORMAT: &str = "fa:statement:v1";
const OUTPUT_MAGIC: &[u8; 13] = b"FA-STATEMENT\0";
const MAX_ACCOUNTS: usize = 1_000_000;
const MAX_BALANCES: usize = 2_000_000;
const MAX_COLUMNS: usize = 8;
const MAX_UNITS: usize = 4096;
const MAX_PERIODS: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementError {
    Definition(String),
    Input(String),
    Partition {
        unmapped: Vec<String>,
        multiply_mapped: Vec<(String, Vec<String>)>,
    },
    Overflow {
        line: String,
        column: String,
        unit_id: u32,
    },
    Identity {
        line: String,
        column: String,
        unit_id: u32,
        residual: i128,
    },
    Decode(fa_model::DecodeError),
    Encode(fa_model::EncodeError),
}

impl fmt::Display for StatementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Definition(message) => write!(f, "invalid statement definition: {message}"),
            Self::Input(message) => write!(f, "invalid statement input: {message}"),
            Self::Partition {
                unmapped,
                multiply_mapped,
            } => write!(
                f,
                "statement mappings do not partition covered leaves: unmapped {unmapped:?}; mapped more than once {multiply_mapped:?}"
            ),
            Self::Overflow {
                line,
                column,
                unit_id,
            } => write!(
                f,
                "statement line `{line}` in column `{column}`, unit {unit_id}, exceeds the exact i128 amount range"
            ),
            Self::Identity {
                line,
                column,
                unit_id,
                residual,
            } => write!(
                f,
                "statement identity `{line}` in column `{column}`, unit {unit_id}, is {residual}, not zero; verify the journal fold and definition mappings"
            ),
            Self::Decode(error) => write!(f, "statement decode: {error}"),
            Self::Encode(error) => write!(f, "statement encoding: {error}"),
        }
    }
}

impl core::error::Error for StatementError {}
impl From<fa_model::DecodeError> for StatementError {
    fn from(value: fa_model::DecodeError) -> Self {
        Self::Decode(value)
    }
}
impl From<fa_model::EncodeError> for StatementError {
    fn from(value: fa_model::EncodeError) -> Self {
        Self::Encode(value)
    }
}

/// Historical chart metadata. The source must include zero-valued leaves;
/// deriving this list from only accounts present in a report is insufficient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub id: u128,
    pub code: String,
    pub name: String,
    pub account_type: u8,
    pub is_leaf: bool,
}

/// Posted native-unit columns only. Each account/unit may appear at most once
/// per input column. Pending debits and credits have no representation here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountBalance {
    pub account_id: u128,
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnInput {
    pub label: String,
    pub periods: Vec<String>,
    /// Absent for stock from inception; present for selected-period activity.
    pub effective_from: Option<DateDay>,
    pub effective_through: DateDay,
    pub balances: Vec<AccountBalance>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementInput {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub known_at: u64,
    pub accounts: Vec<Account>,
    /// The source explicitly chooses registered native units. Even an empty
    /// book can request its base unit and receive zero-valued statement lines.
    pub units: Vec<u32>,
    /// Current first, followed by comparatives in the requested order.
    pub columns: Vec<ColumnInput>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    pub label: String,
    pub periods: Vec<String>,
    pub effective_from: Option<DateDay>,
    pub effective_through: DateDay,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementLine {
    pub code: String,
    pub label: String,
    pub unit_id: u32,
    /// Aligned exactly with Statement.columns; every value is an exact native
    /// mantissa in unit_id, never a floating-point presentation amount.
    pub amounts: Vec<i128>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountMapping {
    pub account: Account,
    pub line_code: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub known_at: u64,
    pub definition_name: String,
    pub definition_version: u32,
    pub definition_digest: [u8; 32],
    pub definition_bytes: Vec<u8>,
    pub columns: Vec<Column>,
    /// Definition order, then ascending native unit id.
    pub lines: Vec<StatementLine>,
    /// Account code/id order, including every covered zero-valued leaf.
    pub mappings: Vec<AccountMapping>,
}

impl Statement {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(OUTPUT_MAGIC)
            .u16(1)
            .u16(0)
            .fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u64(self.known_at)
            .str(&self.definition_name)
            .u32(self.definition_version)
            .fixed(&self.definition_digest)
            .bytes(&self.definition_bytes)
            .list(&self.columns, |w, column| {
                w.str(&column.label)
                    .list(&column.periods, |w, period| {
                        w.str(period);
                    })
                    .opt(column.effective_from.as_ref(), |w, day| {
                        w.i32(day.0);
                    })
                    .i32(column.effective_through.0);
            })
            .list(&self.lines, |w, line| {
                w.str(&line.code).str(&line.label).u32(line.unit_id).list(
                    &line.amounts,
                    |w, amount| {
                        w.i128(*amount);
                    },
                );
            })
            .list(&self.mappings, |w, mapping| {
                let account = &mapping.account;
                w.u128(account.id)
                    .str(&account.code)
                    .str(&account.name)
                    .u8(account.account_type)
                    .bool(account.is_leaf)
                    .str(&mapping.line_code);
            });
        w.finish()
    }
}

/// Validate the complete chart before line arithmetic. This is also the
/// source-independent partition lint: zero rows cannot hide an unmapped leaf.
pub fn map_accounts(
    definition: &StatementDefinition,
    accounts: &[Account],
) -> Result<Vec<AccountMapping>, StatementError> {
    if accounts.len() > MAX_ACCOUNTS {
        return Err(input("too many accounts for one statement"));
    }
    let mut ids = BTreeSet::new();
    let mut codes = BTreeSet::new();
    let mut mapped = Vec::new();
    let mut unmapped = Vec::new();
    let mut multiply_mapped = Vec::new();
    for account in accounts {
        if account.code.is_empty()
            || account.code.len() > 64
            || account.name.len() > fa_model::limits::MAX_SCHEMA_CHANGE_BYTES
        {
            return Err(input(
                "account code must be 1..=64 bytes and its name must fit the chart schema body",
            ));
        }
        if !ids.insert(account.id) || !codes.insert(account.code.as_str()) {
            return Err(input(format!(
                "account identity or code `{}` is repeated",
                account.code
            )));
        }
        if !AccountType(account.account_type).is_registered() {
            return Err(input(format!(
                "account `{}` has unknown type {}",
                account.code, account.account_type
            )));
        }
        if !account.is_leaf
            || !definition
                .kind()
                .covered_types()
                .contains(&account.account_type)
        {
            continue;
        }
        let lines: Vec<_> = definition
            .lines()
            .iter()
            .filter_map(|line| match &line.source {
                LineSource::Accounts { account_types, .. }
                    if account_types.contains(&account.account_type) =>
                {
                    Some(line.code.clone())
                }
                _ => None,
            })
            .collect();
        match lines.as_slice() {
            [] => unmapped.push(account.code.clone()),
            [line_code] => mapped.push(AccountMapping {
                account: account.clone(),
                line_code: line_code.clone(),
            }),
            _ => multiply_mapped.push((account.code.clone(), lines)),
        }
    }
    if !unmapped.is_empty() || !multiply_mapped.is_empty() {
        unmapped.sort();
        multiply_mapped.sort_by(|a, b| a.0.cmp(&b.0));
        return Err(StatementError::Partition {
            unmapped,
            multiply_mapped,
        });
    }
    mapped.sort_by(|a, b| {
        a.account
            .code
            .cmp(&b.account.code)
            .then(a.account.id.cmp(&b.account.id))
    });
    Ok(mapped)
}

/// Exact bounded sums using the existing Abacus 256-bit implementation.
/// Positive and negative magnitudes are accumulated separately before the
/// output is narrowed, so a large cancelling intermediate is not a false
/// overflow. At most MAX_BALANCES i128 inputs (<2^149 combined) or 64 formula
/// terms (<2^134) fit comfortably inside this fixed bound.
#[derive(Clone, Copy)]
struct Sum {
    positive: U256,
    negative: U256,
}

impl Sum {
    const ZERO: Self = Self {
        positive: U256::ZERO,
        negative: U256::ZERO,
    };

    fn add(&mut self, amount: i128, subtract: bool) -> Option<()> {
        let negative = (amount < 0) != subtract;
        let part = if negative {
            &mut self.negative
        } else {
            &mut self.positive
        };
        *part = part.checked_add(U256::from_u128(amount.unsigned_abs()))?;
        Some(())
    }

    fn value(self) -> Option<i128> {
        if self.positive >= self.negative {
            i128::try_from(self.positive.checked_sub(self.negative)?.to_u128()?).ok()
        } else {
            let magnitude = self.negative.checked_sub(self.positive)?.to_u128()?;
            if magnitude == i128::MIN.unsigned_abs() {
                Some(i128::MIN)
            } else {
                i128::try_from(magnitude).ok()?.checked_neg()
            }
        }
    }
}

/// Compute all columns with one validated partition and exact native-unit
/// arithmetic. The source fold remains a caller obligation stated above;
/// the facade supplies it through an authenticated, replayable journal read.
pub fn evaluate(
    definition: &StatementDefinition,
    source: &StatementInput,
) -> Result<Statement, StatementError> {
    if source.columns.is_empty() || source.columns.len() > MAX_COLUMNS {
        return Err(input("a statement requires 1..=8 columns"));
    }
    if source.units.is_empty() || source.units.len() > MAX_UNITS {
        return Err(input(
            "a statement requires an explicit nonempty bounded native-unit set",
        ));
    }
    let mut units = source.units.clone();
    units.sort_unstable();
    if units.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(input("the native-unit set contains duplicates"));
    }
    let mappings = map_accounts(definition, &source.accounts)?;
    let accounts: BTreeMap<_, _> = source
        .accounts
        .iter()
        .map(|account| (account.id, account))
        .collect();
    let line_indexes: BTreeMap<_, _> = definition
        .lines()
        .iter()
        .enumerate()
        .map(|(index, line)| (line.code.as_str(), index))
        .collect();
    let account_lines: BTreeMap<_, _> = mappings
        .iter()
        .map(|mapping| (mapping.account.id, line_indexes[mapping.line_code.as_str()]))
        .collect();
    let mut columns = Vec::with_capacity(source.columns.len());
    let mut values = Vec::with_capacity(source.columns.len());
    for column in &source.columns {
        let descriptor = column_descriptor(definition, column)?;
        let mut sums: BTreeMap<_, _> = units
            .iter()
            .map(|unit| (*unit, vec![Sum::ZERO; definition.lines().len()]))
            .collect();
        let mut seen = BTreeSet::new();
        for balance in &column.balances {
            let account = accounts.get(&balance.account_id).ok_or_else(|| {
                input(format!(
                    "balance names unknown account {:032x}",
                    balance.account_id
                ))
            })?;
            if !account.is_leaf {
                return Err(input(format!(
                    "balance names summary account `{}`",
                    account.code
                )));
            }
            if balance.debits < 0 || balance.credits < 0 {
                return Err(input(format!(
                    "negative debit/credit magnitude for account `{}`",
                    account.code
                )));
            }
            if !seen.insert((balance.account_id, balance.unit_id)) {
                return Err(input(format!(
                    "balance repeats account `{}` unit {}",
                    account.code, balance.unit_id
                )));
            }
            let unit_sums = sums.get_mut(&balance.unit_id).ok_or_else(|| {
                input(format!(
                    "balance names undeclared native unit {}",
                    balance.unit_id
                ))
            })?;
            let Some(&index) = account_lines.get(&balance.account_id) else {
                // E.g. cash is an input of the journal's balanced activity
                // fold but is outside the income statement's coverage.
                continue;
            };
            let LineSource::Accounts { sign, .. } = &definition.lines()[index].source else {
                return Err(input("the validated partition names a computed line"));
            };
            let failed = || {
                overflow(
                    &definition.lines()[index].code,
                    &column.label,
                    balance.unit_id,
                )
            };
            unit_sums[index]
                .add(balance.debits, *sign == Sign::Credit)
                .ok_or_else(failed)?;
            unit_sums[index]
                .add(balance.credits, *sign == Sign::Debit)
                .ok_or_else(failed)?;
        }
        let mut column_values = BTreeMap::new();
        for (unit, mut sums) in sums {
            let mut lines: Vec<i128> = Vec::with_capacity(definition.lines().len());
            for (index, line) in definition.lines().iter().enumerate() {
                if let LineSource::Formula { add, subtract } = &line.source {
                    for (operands, subtracting) in [(add, false), (subtract, true)] {
                        for operand in operands {
                            let amount = lines[line_indexes[operand.as_str()]];
                            sums[index]
                                .add(amount, subtracting)
                                .ok_or_else(|| overflow(&line.code, &column.label, unit))?;
                        }
                    }
                }
                let value = sums[index]
                    .value()
                    .ok_or_else(|| overflow(&line.code, &column.label, unit))?;
                if value != 0 && definition.check_lines().contains(&line.code) {
                    return Err(StatementError::Identity {
                        line: line.code.clone(),
                        column: column.label.clone(),
                        unit_id: unit,
                        residual: value,
                    });
                }
                lines.push(value);
            }
            column_values.insert(unit, lines);
        }
        columns.push(descriptor);
        values.push(column_values);
    }
    let mut lines = Vec::with_capacity(definition.lines().len() * units.len());
    for (index, line) in definition.lines().iter().enumerate() {
        for unit in &units {
            lines.push(StatementLine {
                code: line.code.clone(),
                label: line.label.clone(),
                unit_id: *unit,
                amounts: values.iter().map(|column| column[unit][index]).collect(),
            });
        }
    }
    Ok(Statement {
        book_id: source.book_id,
        branch_id: source.branch_id,
        known_at: source.known_at,
        definition_name: definition.name().to_string(),
        definition_version: definition.version(),
        definition_digest: definition.digest()?,
        definition_bytes: definition.canonical_bytes()?,
        columns,
        lines,
        mappings,
    })
}

fn column_descriptor(
    definition: &StatementDefinition,
    column: &ColumnInput,
) -> Result<Column, StatementError> {
    if column.label.trim().is_empty() || column.label.len() > 256 {
        return Err(input("column label is empty or exceeds 256 bytes"));
    }
    if column.balances.len() > MAX_BALANCES || column.periods.len() > MAX_PERIODS {
        return Err(input(
            "column balances or periods exceed the statement bound",
        ));
    }
    let mut periods = column.periods.clone();
    periods.sort();
    if periods
        .iter()
        .any(|period| period.is_empty() || period.len() > 128)
        || periods.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(input(
            "column periods must be bounded, nonempty and distinct",
        ));
    }
    match (definition.basis(), column.effective_from) {
        (Basis::Stock, None) => {}
        (Basis::Activity, Some(from))
            if from <= column.effective_through && !periods.is_empty() => {}
        _ => {
            return Err(input(
                "stock columns start at inception; activity columns need nonempty periods and ordered effective bounds",
            ));
        }
    }
    Ok(Column {
        label: column.label.clone(),
        periods,
        effective_from: column.effective_from,
        effective_through: column.effective_through,
    })
}

fn input(message: impl Into<String>) -> StatementError {
    StatementError::Input(message.into())
}

fn overflow(line: &str, column: &str, unit_id: u32) -> StatementError {
    StatementError::Overflow {
        line: line.to_string(),
        column: column.to_string(),
        unit_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_reference::statements as oracle;

    fn account(id: u128, code: &str, account_type: u8) -> Account {
        Account {
            id,
            code: code.into(),
            name: format!("Account {code}"),
            account_type,
            is_leaf: true,
        }
    }

    fn balance(account_id: u128, unit_id: u32, debits: i128, credits: i128) -> AccountBalance {
        AccountBalance {
            account_id,
            unit_id,
            debits,
            credits,
        }
    }

    fn source(kind: StatementKind) -> StatementInput {
        StatementInput {
            book_id: Id128([0x91; 16]),
            branch_id: Id128::TRUNK,
            known_at: 71,
            accounts: vec![
                account(1, "1000", 1),
                account(2, "2000", 2),
                account(3, "3000", 3),
                account(4, "4000", 4),
                account(5, "5000", 5),
                account(6, "5999", 5),
            ],
            units: vec![1],
            columns: vec![ColumnInput {
                label: "FY2026-P03".into(),
                periods: vec!["FY2026-P03".into()],
                effective_from: (kind == StatementKind::IncomeStatement).then_some(DateDay(10)),
                effective_through: DateDay(40),
                balances: vec![
                    balance(1, 1, 185, 0),
                    balance(2, 1, 0, 50),
                    balance(3, 1, 0, 100),
                    balance(4, 1, 0, 60),
                    balance(5, 1, 25, 0),
                ],
            }],
        }
    }

    fn line<'a>(statement: &'a Statement, code: &str, unit: u32) -> &'a [i128] {
        &statement
            .lines
            .iter()
            .find(|line| line.code == code && line.unit_id == unit)
            .expect("registered line")
            .amounts
    }

    fn oracle_kind(kind: StatementKind) -> oracle::Kind {
        match kind {
            StatementKind::BalanceSheet => oracle::Kind::BalanceSheet,
            StatementKind::IncomeStatement => oracle::Kind::IncomeStatement,
        }
    }

    fn oracle_accounts(accounts: &[Account]) -> Vec<oracle::Account> {
        accounts
            .iter()
            .map(|account| oracle::Account {
                code: account.code.clone(),
                kind: match account.account_type {
                    1 => Some(oracle::AccountKind::Asset),
                    2 => Some(oracle::AccountKind::Liability),
                    3 => Some(oracle::AccountKind::Equity),
                    4 => Some(oracle::AccountKind::Revenue),
                    5 => Some(oracle::AccountKind::Expense),
                    6 => Some(oracle::AccountKind::Memo),
                    7 => Some(oracle::AccountKind::Statistical),
                    8 => Some(oracle::AccountKind::OffBalance),
                    _ => None,
                }
                .expect("registered test type"),
                is_leaf: account.is_leaf,
            })
            .collect()
    }

    fn assert_oracle(definition: &StatementDefinition, source: &StatementInput) {
        let got = evaluate(definition, source).unwrap();
        let accounts = oracle_accounts(&source.accounts);
        let codes: BTreeMap<_, _> = source
            .accounts
            .iter()
            .map(|account| (account.id, account.code.clone()))
            .collect();
        for (index, column) in source.columns.iter().enumerate() {
            let balances: Vec<_> = column
                .balances
                .iter()
                .map(|balance| oracle::Balance {
                    account: codes[&balance.account_id].clone(),
                    unit: balance.unit_id,
                    debits: balance.debits,
                    credits: balance.credits,
                })
                .collect();
            let want = oracle::render(
                oracle_kind(definition.kind()),
                &accounts,
                &balances,
                &source.units,
            )
            .unwrap();
            assert_eq!(
                got.lines.len(),
                want.values().map(BTreeMap::len).sum::<usize>()
            );
            for row in &got.lines {
                assert_eq!(
                    row.amounts[index],
                    want[&row.unit_id][&row.code].to_i128().unwrap(),
                    "column {index}, line {}, unit {}",
                    row.code,
                    row.unit_id
                );
            }
        }
    }

    #[test]
    fn financial_statements_tie_out_and_retain_zero_leaf_mapping() {
        let definition = StatementDefinition::embedded("balance-sheet").unwrap();
        let source = source(definition.kind());
        let statement = evaluate(&definition, &source).unwrap();
        assert_eq!(line(&statement, "assets", 1), [185]);
        assert_eq!(line(&statement, "liabilities", 1), [50]);
        assert_eq!(line(&statement, "equity", 1), [100]);
        assert_eq!(line(&statement, "unclosed_earnings", 1), [35]);
        assert_eq!(line(&statement, "balance_check", 1), [0]);
        assert!(
            statement
                .mappings
                .iter()
                .any(|mapping| mapping.account.code == "5999")
        );
        assert_eq!(
            statement.definition_bytes,
            definition.canonical_bytes().unwrap()
        );
        assert_eq!(statement.definition_digest, definition.digest().unwrap());
        assert_oracle(&definition, &source);

        let income = StatementDefinition::embedded("income-statement").unwrap();
        let source = self::source(income.kind());
        let statement = evaluate(&income, &source).unwrap();
        assert_eq!(line(&statement, "net_income", 1), [35]);
        assert_oracle(&income, &source);
    }

    #[test]
    fn valid_chart_display_metadata_does_not_block_financial_statements() {
        let definition = StatementDefinition::embedded("balance-sheet").unwrap();
        let mut source = source(definition.kind());
        // Chart admission permits blank display names and any nonempty code
        // of at most 64 bytes. Reporting preserves those recorded fields.
        source.accounts[0].name.clear();
        source.accounts[0].code = " 1000 ".into();
        source.accounts[1].name = "Long recorded account name ".repeat(64);
        let statement = evaluate(&definition, &source).unwrap();
        assert_eq!(line(&statement, "balance_check", 1), [0]);
        assert!(statement.mappings.iter().any(|mapping| {
            mapping.account.code == " 1000 " && mapping.account.name.is_empty()
        }));
        assert_oracle(&definition, &source);
    }

    #[test]
    fn missing_and_repeated_mapping_are_refused_even_for_zero_accounts() {
        let text = INCOME_STATEMENT.replacen(
            "account_types = [\"Expense\"]",
            "account_types = [\"Revenue\"]",
            1,
        );
        let definition = StatementDefinition::from_toml(&text).unwrap();
        let source = source(definition.kind());
        let (unmapped, multiply_mapped) = match evaluate(&definition, &source).unwrap_err() {
            StatementError::Partition {
                unmapped,
                multiply_mapped,
            } => Some((unmapped, multiply_mapped)),
            _ => None,
        }
        .expect("partition refusal");
        assert_eq!(unmapped, ["5000", "5999"]);
        assert_eq!(
            multiply_mapped,
            [(
                "4000".to_string(),
                vec!["revenue".to_string(), "expense".to_string()]
            )]
        );

        let accounts = oracle_accounts(&source.accounts);
        assert!(
            matches!(oracle::validate_partition(oracle::Kind::IncomeStatement, &accounts,
            &[("revenue", &["4000"]), ("expense", &["5000"])]),
            Err(oracle::Error::MissingMapping(code)) if code == "5999")
        );
    }

    #[test]
    fn formula_omission_is_an_identity_failure_not_an_inserted_plug() {
        let text = BALANCE_SHEET.replacen("subtract = [\"unclosed_expense\"]", "subtract = []", 1);
        let definition = StatementDefinition::from_toml(&text).unwrap();
        assert!(matches!(
            evaluate(&definition, &source(definition.kind())),
            Err(StatementError::Identity {
                residual: -25,
                unit_id: 1,
                ..
            })
        ));
    }

    #[test]
    fn comparative_columns_share_exact_line_mapping_and_keep_their_own_amounts() {
        let definition = StatementDefinition::embedded("balance-sheet").unwrap();
        let mut source = source(definition.kind());
        source.columns.push(ColumnInput {
            label: "FY2025-P03".into(),
            periods: vec!["FY2025-P03".into()],
            effective_from: None,
            effective_through: DateDay(-325),
            balances: vec![balance(1, 1, 100, 0), balance(3, 1, 0, 100)],
        });
        let statement = evaluate(&definition, &source).unwrap();
        assert_eq!(line(&statement, "assets", 1), [185, 100]);
        assert_eq!(line(&statement, "unclosed_earnings", 1), [35, 0]);
        assert_eq!(statement.columns[1].effective_through, DateDay(-325));
        assert_eq!(statement.known_at, 71);
        assert_oracle(&definition, &source);
    }

    #[test]
    fn account_balance_and_unit_input_order_do_not_change_canonical_output() {
        let definition = StatementDefinition::embedded("balance-sheet").unwrap();
        let mut source = source(definition.kind());
        source.units.push(2);
        source.columns[0]
            .balances
            .extend([balance(1, 2, 19, 0), balance(3, 2, 0, 19)]);
        let first = evaluate(&definition, &source)
            .unwrap()
            .canonical_bytes()
            .unwrap();
        source.accounts.reverse();
        source.units.reverse();
        source.columns[0].balances.reverse();
        let reordered = evaluate(&definition, &source)
            .unwrap()
            .canonical_bytes()
            .unwrap();
        assert_eq!(first, reordered);
        source.known_at += 1;
        assert_ne!(
            first,
            evaluate(&definition, &source)
                .unwrap()
                .canonical_bytes()
                .unwrap()
        );
    }

    #[test]
    fn distinct_native_units_cannot_cancel_a_balance_sheet_residual() {
        let definition = StatementDefinition::embedded("balance-sheet").unwrap();
        let mut source = source(definition.kind());
        source.units.push(2);
        source.columns[0].balances = vec![balance(1, 1, 10, 0), balance(3, 2, 0, 10)];
        assert!(matches!(
            evaluate(&definition, &source),
            Err(StatementError::Identity {
                unit_id: 1,
                residual: 10,
                ..
            })
        ));
    }

    #[test]
    fn empty_books_and_zero_units_have_real_zero_statement_lines() {
        for name in ["balance-sheet", "income-statement"] {
            let definition = StatementDefinition::embedded(name).unwrap();
            let mut source = source(definition.kind());
            source.columns[0].balances.clear();
            source.accounts.clear();
            source.units = vec![7, 1];
            let statement = evaluate(&definition, &source).unwrap();
            assert_eq!(statement.lines.len(), definition.lines().len() * 2);
            assert!(statement.lines.iter().all(|line| line.amounts == [0]));
            assert_oracle(&definition, &source);
        }
    }

    #[test]
    fn exact_wide_sums_accept_cancellation_and_signed_minimum_but_refuse_large_output() {
        let definition = StatementDefinition::embedded("income-statement").unwrap();
        let mut source = source(definition.kind());
        source.accounts = vec![
            account(1, "r1", 4),
            account(2, "r2", 4),
            account(3, "r3", 4),
            account(4, "expense", 5),
        ];
        source.columns[0].balances = vec![
            balance(1, 1, 0, i128::MAX),
            balance(2, 1, 0, i128::MAX),
            balance(3, 1, i128::MAX, 0),
        ];
        assert_eq!(
            line(&evaluate(&definition, &source).unwrap(), "revenue", 1),
            [i128::MAX]
        );
        assert_oracle(&definition, &source);
        source.columns[0].balances = vec![balance(1, 1, i128::MAX, 0), balance(4, 1, 1, 0)];
        assert_eq!(
            line(&evaluate(&definition, &source).unwrap(), "net_income", 1),
            [i128::MIN]
        );
        assert_oracle(&definition, &source);
        source.columns[0].balances = vec![balance(1, 1, 0, i128::MAX), balance(2, 1, 0, 1)];
        assert!(
            matches!(evaluate(&definition, &source), Err(StatementError::Overflow { line, .. }) if line == "revenue")
        );
    }

    #[test]
    fn rejects_malformed_fold_rows_before_a_statement_is_certifiable() {
        let definition = StatementDefinition::embedded("income-statement").unwrap();
        let base = source(definition.kind());
        let mut source = base.clone();
        let duplicate = source.columns[0].balances[0].clone();
        source.columns[0].balances.push(duplicate);
        assert!(matches!(
            evaluate(&definition, &source),
            Err(StatementError::Input(_))
        ));
        source = base.clone();
        source.columns[0].balances[0].account_id = 999;
        assert!(matches!(
            evaluate(&definition, &source),
            Err(StatementError::Input(_))
        ));
        source = base.clone();
        source.accounts[0].is_leaf = false;
        assert!(matches!(
            evaluate(&definition, &source),
            Err(StatementError::Input(_))
        ));
        source = base.clone();
        source.columns[0].balances[0].debits = -1;
        assert!(matches!(
            evaluate(&definition, &source),
            Err(StatementError::Input(_))
        ));
        source = base.clone();
        source.columns[0].balances[0].unit_id = 999;
        assert!(matches!(
            evaluate(&definition, &source),
            Err(StatementError::Input(_))
        ));
        source = base;
        source.columns[0].effective_from = None;
        assert!(matches!(
            evaluate(&definition, &source),
            Err(StatementError::Input(_))
        ));
    }

    #[test]
    fn seeded_statements_match_the_independent_oracle_for_both_kinds_and_units() {
        let mut state = 0x5a73_ae29_31bc_9201_u64;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            i128::from(state >> 16)
        };
        for iteration in 0..64 {
            for name in ["balance-sheet", "income-statement"] {
                let definition = StatementDefinition::embedded(name).unwrap();
                let mut source = source(definition.kind());
                source.units = vec![1, 9];
                source.columns[0].balances.clear();
                for unit in [1, 9] {
                    let equity = next();
                    let debt = next();
                    let revenue = next();
                    let expense = next();
                    let net_cash = equity + debt + revenue - expense;
                    let (debits, credits) = if net_cash >= 0 {
                        (net_cash, 0)
                    } else {
                        (0, -net_cash)
                    };
                    source.columns[0].balances.extend([
                        balance(1, unit, debits, credits),
                        balance(2, unit, 0, debt),
                        balance(3, unit, 0, equity),
                        balance(4, unit, 0, revenue),
                        balance(5, unit, expense, 0),
                    ]);
                }
                source.known_at = iteration;
                assert_oracle(&definition, &source);
            }
        }
    }

    #[test]
    fn memo_off_balance_and_statistical_accounts_are_excluded_from_financial_statements() {
        for name in ["balance-sheet", "income-statement"] {
            let definition = StatementDefinition::embedded(name).unwrap();
            let baseline = evaluate(&definition, &source(definition.kind())).unwrap();

            let mut with_non_monetary = source(definition.kind());
            with_non_monetary.accounts.extend([
                account(60, "8100", 6), // Memo
                account(70, "9100", 7), // Statistical (single-sided allowed)
                account(80, "8510", 8), // OffBalance
                account(81, "8520", 8), // OffBalance counter
            ]);
            with_non_monetary.columns[0].balances.extend([
                balance(60, 1, 50_000, 50_000),
                balance(70, 1, 42, 0),
                balance(80, 1, 250_000, 0),
                balance(81, 1, 0, 250_000),
            ]);

            let statement = evaluate(&definition, &with_non_monetary).unwrap();
            assert_eq!(statement.lines, baseline.lines);
            assert_eq!(statement.mappings, baseline.mappings);
            assert_oracle(&definition, &with_non_monetary);
        }
    }
}
