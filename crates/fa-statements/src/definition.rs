//! Bounded definitions as versioned data, not executable posting rules.

use std::collections::BTreeSet;

use fa_model::{AccountType, EntryClass, Reader, Writer, domain_digest};
use fa_registry::toml::{Table, Value};

use crate::StatementError;

const MAGIC: &[u8; 17] = b"FA-STATEMENT-DEF\0";
const SCHEMA_MAJOR: u16 = 1;
const SCHEMA_MINOR: u16 = 0;
const MAX_LINES: usize = 64;
const MAX_NAME_BYTES: usize = 64;
const MAX_LABEL_BYTES: usize = 256;
/// The entire decoder is bounded before its first allocation.
pub const MAX_DEFINITION_BYTES: usize = 64 * 1024;
pub const BALANCE_SHEET: &str = include_str!("../../../registries/statements/balance-sheet.toml");
pub const INCOME_STATEMENT: &str =
    include_str!("../../../registries/statements/income-statement.toml");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementKind {
    BalanceSheet,
    IncomeStatement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Basis {
    Stock,
    Activity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sign {
    Debit,
    Credit,
}

/// Closed, exact line expressions. A formula may name only earlier lines;
/// there is no dynamic evaluation, multiplication, FX or rounding in v1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LineSource {
    Accounts {
        account_types: Vec<u8>,
        sign: Sign,
    },
    Formula {
        add: Vec<String>,
        subtract: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineDefinition {
    pub code: String,
    pub label: String,
    pub source: LineSource,
}

/// A self-contained definition snapshot. Runtime registry loading and decoding
/// both enforce the same closed vocabulary and canonical collection rules.
/// Retaining these bytes in a certificate preserves the definition actually
/// evaluated; it is not a custom-definition activation or an ObjectId.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementDefinition {
    name: String,
    title: String,
    version: u32,
    kind: StatementKind,
    lines: Vec<LineDefinition>,
    check_lines: Vec<String>,
}

impl StatementKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BalanceSheet => "BalanceSheet",
            Self::IncomeStatement => "IncomeStatement",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::BalanceSheet => 0,
            Self::IncomeStatement => 1,
        }
    }

    #[must_use]
    pub const fn covered_types(self) -> &'static [u8] {
        match self {
            Self::BalanceSheet => &[1, 2, 3, 4, 5],
            Self::IncomeStatement => &[4, 5],
        }
    }

    #[must_use]
    pub const fn basis(self) -> Basis {
        match self {
            Self::BalanceSheet => Basis::Stock,
            Self::IncomeStatement => Basis::Activity,
        }
    }

    #[must_use]
    pub const fn excluded_classes(self) -> &'static [EntryClass] {
        match self {
            Self::BalanceSheet => &[],
            Self::IncomeStatement => &[EntryClass::CLOSING],
        }
    }
}

impl StatementDefinition {
    pub fn embedded(name: &str) -> Result<Self, StatementError> {
        Self::from_toml(match name {
            "balance-sheet" => BALANCE_SHEET,
            "income-statement" => INCOME_STATEMENT,
            _ => {
                return Err(definition(format!(
                    "unknown statement `{name}`; choose balance-sheet or income-statement"
                )));
            }
        })
    }

    pub fn from_toml(text: &str) -> Result<Self, StatementError> {
        if text.len() > MAX_DEFINITION_BYTES {
            return Err(definition("definition exceeds the byte bound"));
        }
        let doc = fa_registry::toml::parse(text).map_err(|error| definition(error.to_string()))?;
        if !doc.tables.is_empty() || doc.arrays.keys().any(|name| name != "line") {
            return Err(definition("only the root and [[line]] tables are admitted"));
        }
        keys(
            &doc.root,
            &[
                "schema_version",
                "name",
                "title",
                "version",
                "kind",
                "basis",
                "covered_types",
                "excluded_classes",
                "check_lines",
            ],
        )?;
        if integer(&doc.root, "schema_version")? != 1 {
            return Err(definition("schema_version must be 1"));
        }
        let kind = match string(&doc.root, "kind")? {
            "BalanceSheet" => StatementKind::BalanceSheet,
            "IncomeStatement" => StatementKind::IncomeStatement,
            other => return Err(definition(format!("unsupported statement kind `{other}`"))),
        };
        let basis = string(&doc.root, "basis")?;
        if basis
            != match kind.basis() {
                Basis::Stock => "stock",
                Basis::Activity => "activity",
            }
        {
            return Err(definition(
                "the statement kind and stock/activity basis disagree",
            ));
        }
        if types(&doc.root, "covered_types")? != kind.covered_types() {
            return Err(definition(
                "covered_types must name exactly the kind's monetary account types",
            ));
        }
        let excluded = strings(&doc.root, "excluded_classes")?;
        let expected: &[&str] = match kind {
            StatementKind::BalanceSheet => &[],
            StatementKind::IncomeStatement => &["Closing"],
        };
        if excluded
            .iter()
            .map(String::as_str)
            .ne(expected.iter().copied())
        {
            return Err(definition(
                "excluded_classes must preserve the kind's registered Closing treatment",
            ));
        }
        let mut lines = Vec::new();
        for row in doc.arrays.get("line").into_iter().flatten() {
            keys(
                row,
                &["code", "label", "account_types", "sign", "add", "subtract"],
            )?;
            let source = if row.contains_key("account_types") {
                if row.contains_key("add") || row.contains_key("subtract") {
                    return Err(definition(
                        "a line cannot both map accounts and compute a formula",
                    ));
                }
                LineSource::Accounts {
                    account_types: types(row, "account_types")?,
                    sign: match string(row, "sign")? {
                        "debit" => Sign::Debit,
                        "credit" => Sign::Credit,
                        other => return Err(definition(format!("unknown sign `{other}`"))),
                    },
                }
            } else {
                if row.contains_key("sign") {
                    return Err(definition("a formula cannot carry an account sign"));
                }
                LineSource::Formula {
                    add: strings(row, "add")?,
                    subtract: strings(row, "subtract")?,
                }
            };
            lines.push(LineDefinition {
                code: string(row, "code")?.to_string(),
                label: string(row, "label")?.to_string(),
                source,
            });
        }
        let value = Self {
            name: string(&doc.root, "name")?.to_string(),
            title: string(&doc.root, "title")?.to_string(),
            version: u32::try_from(integer(&doc.root, "version")?)
                .map_err(|_| definition("version must fit a positive u32"))?,
            kind,
            lines,
            check_lines: strings(&doc.root, "check_lines")?,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), StatementError> {
        identifier(&self.name, "definition name")?;
        label(&self.title, "definition title")?;
        if self.version == 0 || self.lines.is_empty() || self.lines.len() > MAX_LINES {
            return Err(definition(
                "a positive version and 1..=64 lines are required",
            ));
        }
        let mut earlier = BTreeSet::new();
        for line in &self.lines {
            identifier(&line.code, "line code")?;
            label(&line.label, "line label")?;
            if earlier.contains(line.code.as_str()) {
                return Err(definition(format!("line `{}` is defined twice", line.code)));
            }
            match &line.source {
                LineSource::Accounts { account_types, .. } => {
                    if account_types.is_empty()
                        || account_types.windows(2).any(|pair| pair[0] >= pair[1])
                        || account_types
                            .iter()
                            .any(|tag| !self.kind.covered_types().contains(tag))
                    {
                        return Err(definition(format!(
                            "line `{}` must map a sorted nonempty set of covered account types",
                            line.code
                        )));
                    }
                }
                LineSource::Formula { add, subtract } => {
                    if add.is_empty() && subtract.is_empty() {
                        return Err(definition(format!("formula `{}` has no inputs", line.code)));
                    }
                    let mut operands = BTreeSet::new();
                    for operand in add.iter().chain(subtract) {
                        if !earlier.contains(operand.as_str()) {
                            return Err(definition(format!(
                                "formula `{}` names unknown, forward or cyclic input `{operand}`",
                                line.code
                            )));
                        }
                        if !operands.insert(operand) {
                            return Err(definition(format!(
                                "formula `{}` repeats input `{operand}`",
                                line.code
                            )));
                        }
                    }
                    if add.windows(2).any(|pair| pair[0] >= pair[1])
                        || subtract.windows(2).any(|pair| pair[0] >= pair[1])
                    {
                        return Err(definition("formula operands must be sorted and unique"));
                    }
                }
            }
            earlier.insert(line.code.as_str());
        }
        if self.check_lines.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(definition("check_lines must be sorted and unique"));
        }
        if self.kind == StatementKind::BalanceSheet && self.check_lines.is_empty() {
            return Err(definition(
                "a balance sheet must register an exact zero identity",
            ));
        }
        for code in &self.check_lines {
            if !self
                .lines
                .iter()
                .any(|line| line.code == *code && matches!(line.source, LineSource::Formula { .. }))
            {
                return Err(definition(format!(
                    "identity `{code}` must name a computed line"
                )));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }
    #[must_use]
    pub fn kind(&self) -> StatementKind {
        self.kind
    }
    #[must_use]
    pub fn basis(&self) -> Basis {
        self.kind.basis()
    }
    #[must_use]
    pub fn excluded_classes(&self) -> &'static [EntryClass] {
        self.kind.excluded_classes()
    }
    #[must_use]
    pub fn lines(&self) -> &[LineDefinition] {
        &self.lines
    }
    #[must_use]
    pub fn check_lines(&self) -> &[String] {
        &self.check_lines
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(MAGIC)
            .u16(SCHEMA_MAJOR)
            .u16(SCHEMA_MINOR)
            .str(&self.name)
            .str(&self.title)
            .u32(self.version)
            .u8(self.kind.tag())
            .list(&self.lines, |w, line| {
                w.str(&line.code).str(&line.label);
                match &line.source {
                    LineSource::Accounts {
                        account_types,
                        sign,
                    } => {
                        w.u8(0)
                            .list(account_types, |w, tag| {
                                w.u8(*tag);
                            })
                            .u8(match sign {
                                Sign::Debit => 0,
                                Sign::Credit => 1,
                            });
                    }
                    LineSource::Formula { add, subtract } => {
                        w.u8(1)
                            .list(add, |w, name| {
                                w.str(name);
                            })
                            .list(subtract, |w, name| {
                                w.str(name);
                            });
                    }
                }
            })
            .list(&self.check_lines, |w, code| {
                w.str(code);
            });
        w.finish()
    }

    pub fn digest(&self) -> Result<[u8; 32], fa_model::EncodeError> {
        Ok(domain_digest(
            b"fa:statement-definition:v1",
            &[&self.canonical_bytes()?],
        ))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StatementError> {
        if bytes.len() > MAX_DEFINITION_BYTES {
            return Err(definition("definition exceeds the byte bound"));
        }
        let mut r = Reader::new(bytes);
        if r.fixed::<17>("statement definition magic")? != *MAGIC
            || r.u16("definition major")? != SCHEMA_MAJOR
            || r.u16("definition minor")? != SCHEMA_MINOR
        {
            return Err(definition("unknown definition format"));
        }
        let name = r.str(MAX_NAME_BYTES, "definition name")?.to_string();
        let title = r.str(MAX_LABEL_BYTES, "definition title")?.to_string();
        let version = r.u32("definition version")?;
        let kind = match r.u8("statement kind")? {
            0 => StatementKind::BalanceSheet,
            1 => StatementKind::IncomeStatement,
            tag => return Err(r.bad_tag("statement kind", tag).into()),
        };
        let lines = r.list(MAX_LINES, "statement lines", |r| {
            let code = r.str(MAX_NAME_BYTES, "line code")?.to_string();
            let label = r.str(MAX_LABEL_BYTES, "line label")?.to_string();
            let source = match r.u8("line source")? {
                0 => LineSource::Accounts {
                    account_types: r.list(5, "line account types", |r| r.u8("account type"))?,
                    sign: match r.u8("line sign")? {
                        0 => Sign::Debit,
                        1 => Sign::Credit,
                        tag => return Err(r.bad_tag("line sign", tag)),
                    },
                },
                1 => LineSource::Formula {
                    add: r.list(MAX_LINES, "formula add", |r| {
                        Ok(r.str(MAX_NAME_BYTES, "operand")?.to_string())
                    })?,
                    subtract: r.list(MAX_LINES, "formula subtract", |r| {
                        Ok(r.str(MAX_NAME_BYTES, "operand")?.to_string())
                    })?,
                },
                tag => return Err(r.bad_tag("line source", tag)),
            };
            Ok(LineDefinition {
                code,
                label,
                source,
            })
        })?;
        let check_lines = r.list(MAX_LINES, "identity checks", |r| {
            Ok(r.str(MAX_NAME_BYTES, "identity code")?.to_string())
        })?;
        r.finish()?;
        let value = Self {
            name,
            title,
            version,
            kind,
            lines,
            check_lines,
        };
        value.validate()?;
        Ok(value)
    }
}

fn definition(message: impl Into<String>) -> StatementError {
    StatementError::Definition(message.into())
}

fn keys(table: &Table, allowed: &[&str]) -> Result<(), StatementError> {
    if let Some(key) = table.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(definition(format!("unsupported definition field `{key}`")));
    }
    Ok(())
}

fn string<'a>(table: &'a Table, key: &str) -> Result<&'a str, StatementError> {
    table
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| definition(format!("`{key}` must be a string")))
}

fn integer(table: &Table, key: &str) -> Result<i128, StatementError> {
    table
        .get(key)
        .and_then(Value::as_int)
        .ok_or_else(|| definition(format!("`{key}` must be an integer")))
}

fn strings(table: &Table, key: &str) -> Result<Vec<String>, StatementError> {
    let array = table
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| definition(format!("`{key}` must be a string array")))?;
    array
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| definition(format!("`{key}` must contain only strings")))
        })
        .collect()
}

fn types(table: &Table, key: &str) -> Result<Vec<u8>, StatementError> {
    let mut tags = strings(table, key)?
        .iter()
        .map(|name| {
            AccountType::ALL
                .iter()
                .find(|row| row.1 == name.as_str())
                .map(|(tag, ..)| *tag)
                .ok_or_else(|| definition(format!("unknown account type `{name}`")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    tags.sort_unstable();
    if tags.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(definition(format!("`{key}` repeats an account type")));
    }
    Ok(tags)
}

fn identifier(value: &str, field: &str) -> Result<(), StatementError> {
    if value.is_empty()
        || value.len() > MAX_NAME_BYTES
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(definition(format!(
            "{field} must be a nonempty bounded ASCII identifier"
        )));
    }
    Ok(())
}

fn label(value: &str, field: &str) -> Result<(), StatementError> {
    if value.trim().is_empty() || value.len() > MAX_LABEL_BYTES {
        return Err(definition(format!(
            "{field} is empty or exceeds {MAX_LABEL_BYTES} bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_round_trip_exact_definition_bytes_and_preserve_their_basis() {
        for name in ["balance-sheet", "income-statement"] {
            let value = StatementDefinition::embedded(name).unwrap();
            let bytes = value.canonical_bytes().unwrap();
            let decoded = StatementDefinition::decode(&bytes).unwrap();
            assert_eq!(value, decoded);
            assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
            assert_eq!(decoded.digest().unwrap(), value.digest().unwrap());
            assert_eq!(
                value.kind().name(),
                match name {
                    "balance-sheet" => "BalanceSheet",
                    _ => "IncomeStatement",
                }
            );
        }
        let balance = StatementDefinition::embedded("balance-sheet").unwrap();
        assert_eq!(balance.basis(), Basis::Stock);
        assert_eq!(balance.excluded_classes(), []);
        let income = StatementDefinition::embedded("income-statement").unwrap();
        assert_eq!(income.basis(), Basis::Activity);
        assert_eq!(income.excluded_classes(), [EntryClass::CLOSING]);
        assert!(StatementDefinition::embedded("cash-flow").is_err());
    }

    #[test]
    fn definition_codec_rejects_every_truncated_prefix_and_trailing_bytes() {
        let value = StatementDefinition::embedded("balance-sheet").unwrap();
        let bytes = value.canonical_bytes().unwrap();
        for length in 0..bytes.len() {
            assert!(
                StatementDefinition::decode(&bytes[..length]).is_err(),
                "length {length}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(StatementDefinition::decode(&trailing).is_err());
        let mut wrong_version = bytes;
        wrong_version[17] = 2;
        assert!(StatementDefinition::decode(&wrong_version).is_err());
        assert!(StatementDefinition::decode(&vec![0; MAX_DEFINITION_BYTES + 1]).is_err());
    }

    #[test]
    fn typo_basis_future_formula_cycle_and_unsupported_expression_are_refused() {
        for text in [
            INCOME_STATEMENT.replacen("basis = \"activity\"", "basis = \"stock\"", 1),
            INCOME_STATEMENT.replacen(
                "excluded_classes = [\"Closing\"]",
                "excluded_classes = []",
                1,
            ),
            INCOME_STATEMENT.replacen("add = [\"revenue\"]", "add = [\"net_income\"]", 1),
            INCOME_STATEMENT.replacen("add = [\"revenue\"]", "add = [\"absent\"]", 1),
            INCOME_STATEMENT.replacen("add = [\"revenue\"]", "add = [\"revenue\", \"revenue\"]", 1),
            INCOME_STATEMENT.replacen("subtract = [\"expense\"]", "multiply = [\"expense\"]", 1),
            INCOME_STATEMENT.replacen(
                "account_types = [\"Revenue\"]",
                "account_types = [\"Memo\"]",
                1,
            ),
            INCOME_STATEMENT.replacen("version = 1\nkind", "version = 0\nkind", 1),
            INCOME_STATEMENT.replacen(
                "covered_types = [\"Revenue\", \"Expense\"]",
                "covered_types = [\"Revenue\"]",
                1,
            ),
            BALANCE_SHEET.replacen("check_lines = [\"balance_check\"]", "check_lines = []", 1),
        ] {
            assert!(StatementDefinition::from_toml(&text).is_err(), "{text}");
        }
    }

    #[test]
    fn presentation_formula_or_version_changes_alter_the_committed_definition() {
        let original = StatementDefinition::embedded("income-statement")
            .unwrap()
            .digest()
            .unwrap();
        for text in [
            INCOME_STATEMENT.replacen("label = \"Net income\"", "label = \"Period net income\"", 1),
            INCOME_STATEMENT.replacen("subtract = [\"expense\"]", "subtract = []", 1),
            INCOME_STATEMENT.replacen("version = 1\nkind", "version = 2\nkind", 1),
        ] {
            let changed = StatementDefinition::from_toml(&text).unwrap();
            assert_ne!(changed.digest().unwrap(), original);
        }
    }
}
