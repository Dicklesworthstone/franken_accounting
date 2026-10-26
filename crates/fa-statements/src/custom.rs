//! Custom statement definitions with `AccountSetExpr` line mappings, static and
//! chart-partition linting (`statement lint`), and presentation rounding with an
//! explicit residual line (plan §12.1, bead `fa-i9yn`).
//!
//! No floating-point type enters any calculation. Presentation rounding uses the
//! registered `RoundingLaw` rules from `fa-money` over exact power-of-ten divisors
//! (`10^k`) and emits an explicit residual line whenever rounded formula operands
//! differ from the rounded formula total.

mod input;

use std::collections::{BTreeMap, BTreeSet};

use fa_model::{AccountType, DecodeError, EncodeError, Id128, Oid, Reader, Writer, domain_digest};
use fa_money::rounding::RoundingLaw;
use fa_money::wide::U256;

use crate::{
    Account, Column, LineSource, Sign, Statement, StatementDefinition, StatementError,
    StatementInput, StatementKind, StatementLine, Sum, column_descriptor, input, overflow,
};

pub const CUSTOM_STATEMENT_DEF_FORMAT: &[u8] = b"fa:custom-statement-def:v1";
pub const STATEMENT_LINT_REPORT_FORMAT: &[u8] = b"fa:statement-lint:v1";
pub const PRESENTED_STATEMENT_FORMAT: &[u8] = b"fa:presented-statement:v1";
pub const PRESENTATION_ROUNDING_SPEC_FORMAT: &[u8] = b"fa:presentation-rounding-spec:v1";

const MAX_EXPR_DEPTH: usize = 8;
const MAX_EXPR_ITEMS: usize = 1024;
const MAX_CUSTOM_LINES: usize = 128;
/// The largest power of ten an i128 divisor holds (10^38): enough for a unit
/// with an 18-digit scale presented in millions (10^24). The rounding is
/// exact at any divisor (U256 intermediates, checked conversions).
const MAX_SCALE_REDUCTION: u8 = 38;

/// Closed account-set expression for mapping leaf accounts to statement lines (plan §12.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountSetExpr {
    /// Match leaf accounts whose `account_type` is in this sorted, deduplicated set.
    AccountTypes(Vec<u8>),
    /// Match leaf accounts whose `code` is in this sorted, deduplicated set.
    AccountCodes(Vec<String>),
    /// Match leaf accounts whose `code` starts with any prefix in this sorted, deduplicated set.
    AccountCodePrefixes(Vec<String>),
    /// Match leaf accounts matched by any child expression.
    Union(Vec<AccountSetExpr>),
    /// Match leaf accounts matched by `include` and not matched by `exclude`.
    Difference {
        include: Box<AccountSetExpr>,
        exclude: Box<AccountSetExpr>,
    },
}

impl AccountSetExpr {
    /// Evaluate whether `account` matches this expression.
    #[must_use]
    pub fn matches(&self, account: &Account) -> bool {
        match self {
            Self::AccountTypes(types) => types.contains(&account.account_type),
            Self::AccountCodes(codes) => codes.iter().any(|c| c == &account.code),
            Self::AccountCodePrefixes(prefixes) => prefixes
                .iter()
                .any(|p| account.code.starts_with(p.as_str())),
            Self::Union(children) => children.iter().any(|c| c.matches(account)),
            Self::Difference { include, exclude } => {
                include.matches(account) && !exclude.matches(account)
            }
        }
    }

    pub fn validate(&self, covered_types: &[u8], depth: usize) -> Result<(), StatementError> {
        if depth > MAX_EXPR_DEPTH {
            return Err(StatementError::Definition(
                "AccountSetExpr nesting exceeds maximum depth 8".into(),
            ));
        }
        match self {
            Self::AccountTypes(types) => {
                if types.is_empty()
                    || types.len() > 8
                    || types.windows(2).any(|w| w[0] >= w[1])
                    || types.iter().any(|t| !covered_types.contains(t))
                {
                    return Err(StatementError::Definition(
                        "AccountTypes expression requires sorted, unique, covered account types"
                            .into(),
                    ));
                }
            }
            Self::AccountCodes(codes) => {
                if codes.is_empty()
                    || codes.len() > MAX_EXPR_ITEMS
                    || codes.iter().any(|c| c.is_empty() || c.len() > 64)
                    || codes.windows(2).any(|w| w[0] >= w[1])
                {
                    return Err(StatementError::Definition(
                        "AccountCodes expression requires 1..=1024 sorted, unique, bounded codes"
                            .into(),
                    ));
                }
            }
            Self::AccountCodePrefixes(prefixes) => {
                if prefixes.is_empty()
                    || prefixes.len() > MAX_EXPR_ITEMS
                    || prefixes.iter().any(|p| p.is_empty() || p.len() > 64)
                    || prefixes.windows(2).any(|w| w[0] >= w[1])
                {
                    return Err(StatementError::Definition(
                        "AccountCodePrefixes expression requires 1..=1024 sorted, unique prefixes"
                            .into(),
                    ));
                }
            }
            Self::Union(children) => {
                if children.len() < 2 || children.len() > 32 {
                    return Err(StatementError::Definition(
                        "Union expression requires 2..=32 child expressions".into(),
                    ));
                }
                for child in children {
                    child.validate(covered_types, depth + 1)?;
                }
            }
            Self::Difference { include, exclude } => {
                include.validate(covered_types, depth + 1)?;
                exclude.validate(covered_types, depth + 1)?;
            }
        }
        Ok(())
    }

    pub fn collect_explicit_codes<'a>(&'a self, out: &mut BTreeSet<&'a str>) {
        match self {
            Self::AccountTypes(_) | Self::AccountCodePrefixes(_) => {}
            Self::AccountCodes(codes) => {
                for code in codes {
                    out.insert(code.as_str());
                }
            }
            Self::Union(children) => {
                for child in children {
                    child.collect_explicit_codes(out);
                }
            }
            Self::Difference { include, exclude } => {
                include.collect_explicit_codes(out);
                exclude.collect_explicit_codes(out);
            }
        }
    }

    fn encode(&self, w: &mut Writer) {
        match self {
            Self::AccountTypes(types) => {
                w.u8(1).list(types, |w, t| {
                    w.u8(*t);
                });
            }
            Self::AccountCodes(codes) => {
                w.u8(2).list(codes, |w, c| {
                    w.str(c);
                });
            }
            Self::AccountCodePrefixes(prefixes) => {
                w.u8(3).list(prefixes, |w, p| {
                    w.str(p);
                });
            }
            Self::Union(children) => {
                w.u8(4).list(children, |w, child| {
                    child.encode(w);
                });
            }
            Self::Difference { include, exclude } => {
                w.u8(5);
                include.encode(w);
                exclude.encode(w);
            }
        }
    }

    fn decode(r: &mut Reader<'_>, depth: usize) -> Result<Self, DecodeError> {
        if depth > MAX_EXPR_DEPTH {
            return Err(r.invalid("AccountSetExpr depth exceeds bound"));
        }
        match r.u8("account_set_expr.tag")? {
            1 => Ok(Self::AccountTypes(
                r.list(8, "account_types", |r| r.u8("account_type"))?,
            )),
            2 => Ok(Self::AccountCodes(r.list(
                MAX_EXPR_ITEMS,
                "account_codes",
                |r| Ok(r.str(64, "account_code")?.to_string()),
            )?)),
            3 => Ok(Self::AccountCodePrefixes(r.list(
                MAX_EXPR_ITEMS,
                "account_code_prefixes",
                |r| Ok(r.str(64, "prefix")?.to_string()),
            )?)),
            4 => {
                Ok(Self::Union(r.list(32, "union_children", |r| {
                    Self::decode(r, depth + 1)
                })?))
            }
            5 => {
                let include = Box::new(Self::decode(r, depth + 1)?);
                let exclude = Box::new(Self::decode(r, depth + 1)?);
                Ok(Self::Difference { include, exclude })
            }
            tag => Err(r.bad_tag("account_set_expr", tag)),
        }
    }
}

/// Line source in a custom statement definition (`AccountSetExpr` or `Formula`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CustomLineSource {
    AccountSet {
        expr: AccountSetExpr,
        sign: Sign,
    },
    Formula {
        add: Vec<String>,
        subtract: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomLineDefinition {
    pub code: String,
    pub label: String,
    pub source: CustomLineSource,
}

/// Versioned statement definition supporting `AccountSetExpr` line mappings (`fa-i9yn`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomStatementDefinition {
    pub name: String,
    pub title: String,
    pub version: u32,
    pub kind: StatementKind,
    pub lines: Vec<CustomLineDefinition>,
    pub check_lines: Vec<String>,
}

impl CustomStatementDefinition {
    /// Lift a built-in `StatementDefinition` into a `CustomStatementDefinition`.
    #[must_use]
    pub fn from_builtin(def: &StatementDefinition) -> Self {
        let lines = def
            .lines()
            .iter()
            .map(|line| CustomLineDefinition {
                code: line.code.clone(),
                label: line.label.clone(),
                source: match &line.source {
                    LineSource::Accounts {
                        account_types,
                        sign,
                    } => CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountTypes(account_types.clone()),
                        sign: *sign,
                    },
                    LineSource::Formula { add, subtract } => CustomLineSource::Formula {
                        add: add.clone(),
                        subtract: subtract.clone(),
                    },
                },
            })
            .collect();
        Self {
            name: def.name().to_string(),
            title: def.title().to_string(),
            version: def.version(),
            kind: def.kind(),
            lines,
            check_lines: def.check_lines().to_vec(),
        }
    }

    pub fn validate(&self) -> Result<(), StatementError> {
        if self.name.is_empty()
            || self.name.len() > 64
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(StatementError::Definition(
                "definition name must be a non-empty bounded ASCII identifier".into(),
            ));
        }
        if self.title.trim().is_empty() || self.title.len() > 256 {
            return Err(StatementError::Definition(
                "definition title must be non-empty and at most 256 bytes".into(),
            ));
        }
        if self.version == 0 || self.lines.is_empty() || self.lines.len() > MAX_CUSTOM_LINES {
            return Err(StatementError::Definition(
                "custom statement definition requires version > 0 and 1..=128 lines".into(),
            ));
        }
        let covered = self.kind.covered_types();
        let mut earlier = BTreeSet::new();
        for line in &self.lines {
            if line.code.is_empty()
                || line.code.len() > 64
                || !line
                    .code
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(StatementError::Definition(format!(
                    "line code `{}` must be a non-empty bounded ASCII identifier",
                    line.code
                )));
            }
            if line.label.trim().is_empty() || line.label.len() > 256 {
                return Err(StatementError::Definition(format!(
                    "line `{}` label must be non-empty and at most 256 bytes",
                    line.code
                )));
            }
            if !earlier.insert(line.code.as_str()) {
                return Err(StatementError::Definition(format!(
                    "duplicate line code `{}`",
                    line.code
                )));
            }
            match &line.source {
                CustomLineSource::AccountSet { expr, .. } => {
                    expr.validate(covered, 0)?;
                }
                CustomLineSource::Formula { add, subtract } => {
                    if add.is_empty() && subtract.is_empty() {
                        return Err(StatementError::Definition(format!(
                            "formula `{}` has no operands",
                            line.code
                        )));
                    }
                    if add.windows(2).any(|w| w[0] >= w[1])
                        || subtract.windows(2).any(|w| w[0] >= w[1])
                    {
                        return Err(StatementError::Definition(format!(
                            "formula `{}` operands must be sorted and unique",
                            line.code
                        )));
                    }
                    let mut ops = BTreeSet::new();
                    for op in add.iter().chain(subtract) {
                        if op == &line.code || !earlier.contains(op.as_str()) {
                            return Err(StatementError::Definition(format!(
                                "formula `{}` references unknown or forward line `{op}`",
                                line.code
                            )));
                        }
                        if !ops.insert(op.as_str()) {
                            return Err(StatementError::Definition(format!(
                                "formula `{}` repeats operand `{op}`",
                                line.code
                            )));
                        }
                    }
                }
            }
        }
        if self.check_lines.windows(2).any(|w| w[0] >= w[1]) {
            return Err(StatementError::Definition(
                "check_lines must be sorted and unique".into(),
            ));
        }
        if self.kind == StatementKind::BalanceSheet && self.check_lines.is_empty() {
            return Err(StatementError::Definition(
                "a balance sheet must register at least one check_line identity".into(),
            ));
        }
        for check in &self.check_lines {
            if !self
                .lines
                .iter()
                .any(|l| &l.code == check && matches!(l.source, CustomLineSource::Formula { .. }))
            {
                return Err(StatementError::Definition(format!(
                    "check_line `{check}` must name a Formula line"
                )));
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(CUSTOM_STATEMENT_DEF_FORMAT)
            .str(&self.name)
            .str(&self.title)
            .u32(self.version)
            .u8(match self.kind {
                StatementKind::BalanceSheet => 0,
                StatementKind::IncomeStatement => 1,
            })
            .list(&self.lines, |w, line| {
                w.str(&line.code).str(&line.label);
                match &line.source {
                    CustomLineSource::AccountSet { expr, sign } => {
                        w.u8(0);
                        expr.encode(w);
                        w.u8(match sign {
                            Sign::Debit => 0,
                            Sign::Credit => 1,
                        });
                    }
                    CustomLineSource::Formula { add, subtract } => {
                        w.u8(1)
                            .list(add, |w, op| {
                                w.str(op);
                            })
                            .list(subtract, |w, op| {
                                w.str(op);
                            });
                    }
                }
            })
            .list(&self.check_lines, |w, code| {
                w.str(code);
            });
        let bytes = w.finish()?;
        if bytes.len() > crate::MAX_DEFINITION_BYTES {
            return Err(EncodeError::LengthOverflow);
        }
        Ok(bytes)
    }

    pub fn digest(&self) -> Result<Oid, EncodeError> {
        Ok(Oid(domain_digest(
            CUSTOM_STATEMENT_DEF_FORMAT,
            &[&self.canonical_bytes()?],
        )))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StatementError> {
        if bytes.len() > crate::MAX_DEFINITION_BYTES {
            return Err(StatementError::Definition(
                "custom statement definition exceeds the 64 KiB byte bound".into(),
            ));
        }
        let mut r = Reader::new(bytes);
        let magic = r.fixed::<{ CUSTOM_STATEMENT_DEF_FORMAT.len() }>("custom_def.magic")?;
        if magic != CUSTOM_STATEMENT_DEF_FORMAT {
            return Err(StatementError::Definition(
                "unknown custom statement definition header".into(),
            ));
        }
        let name = r.str(64, "name")?.to_string();
        let title = r.str(256, "title")?.to_string();
        let version = r.u32("version")?;
        let kind = match r.u8("kind")? {
            0 => StatementKind::BalanceSheet,
            1 => StatementKind::IncomeStatement,
            tag => return Err(r.bad_tag("custom_def.kind", tag).into()),
        };
        let lines = r.list(MAX_CUSTOM_LINES, "lines", |r| {
            let code = r.str(64, "line.code")?.to_string();
            let label = r.str(256, "line.label")?.to_string();
            let source = match r.u8("line.source")? {
                0 => {
                    let expr = AccountSetExpr::decode(r, 0)?;
                    let sign = match r.u8("line.sign")? {
                        0 => Sign::Debit,
                        1 => Sign::Credit,
                        tag => return Err(r.bad_tag("line.sign", tag)),
                    };
                    CustomLineSource::AccountSet { expr, sign }
                }
                1 => CustomLineSource::Formula {
                    add: r.list(MAX_CUSTOM_LINES, "add", |r| {
                        Ok(r.str(64, "operand")?.to_string())
                    })?,
                    subtract: r.list(MAX_CUSTOM_LINES, "subtract", |r| {
                        Ok(r.str(64, "operand")?.to_string())
                    })?,
                },
                tag => return Err(r.bad_tag("line.source", tag)),
            };
            Ok(CustomLineDefinition {
                code,
                label,
                source,
            })
        })?;
        let check_lines = r.list(MAX_CUSTOM_LINES, "check_lines", |r| {
            Ok(r.str(64, "check_line")?.to_string())
        })?;
        r.finish()?;
        let def = Self {
            name,
            title,
            version,
            kind,
            lines,
            check_lines,
        };
        def.validate()?;
        Ok(def)
    }
}

/// Structured lint diagnostics for `fa statement lint` (`fa-i9yn`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementLintReport {
    pub definition_name: String,
    pub definition_version: u32,
    pub definition_digest: Oid,
    pub covered_leaf_count: u32,
    pub mapped_leaf_count: u32,
    /// Covered leaf account codes that matched zero `AccountSetExpr` lines.
    pub unmapped_leaves: Vec<String>,
    /// Covered leaf account codes that matched two or more `AccountSetExpr` lines.
    pub multiply_mapped_leaves: Vec<(String, Vec<String>)>,
    /// Explicit account codes named in `AccountSetExpr::AccountCodes` that do not exist in the chart.
    pub unknown_referenced_codes: Vec<String>,
    /// Explicit account codes named in `AccountSetExpr::AccountCodes` that are summary (non-leaf) accounts.
    pub summary_referenced_codes: Vec<String>,
    /// Explicit account codes named in `AccountSetExpr::AccountCodes` whose `account_type` is outside coverage.
    pub outside_coverage_codes: Vec<String>,
    /// Account-mapping lines that matched zero leaf accounts in the chart.
    pub empty_account_lines: Vec<String>,
    /// Resolved `(account_code, line_code)` partition mappings in canonical order.
    pub mappings: Vec<(String, String)>,
}

impl StatementLintReport {
    /// True iff the statement definition cleanly partitions all covered leaf accounts
    /// and references no unknown, summary, or out-of-coverage accounts.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.unmapped_leaves.is_empty()
            && self.multiply_mapped_leaves.is_empty()
            && self.unknown_referenced_codes.is_empty()
            && self.summary_referenced_codes.is_empty()
            && self.outside_coverage_codes.is_empty()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(STATEMENT_LINT_REPORT_FORMAT)
            .str(&self.definition_name)
            .u32(self.definition_version)
            .fixed(&self.definition_digest.0)
            .u32(self.covered_leaf_count)
            .u32(self.mapped_leaf_count)
            .list(&self.unmapped_leaves, |w, c| {
                w.str(c);
            })
            .list(&self.multiply_mapped_leaves, |w, (code, lines)| {
                w.str(code).list(lines, |w, l| {
                    w.str(l);
                });
            })
            .list(&self.unknown_referenced_codes, |w, c| {
                w.str(c);
            })
            .list(&self.summary_referenced_codes, |w, c| {
                w.str(c);
            })
            .list(&self.outside_coverage_codes, |w, c| {
                w.str(c);
            })
            .list(&self.empty_account_lines, |w, l| {
                w.str(l);
            })
            .list(&self.mappings, |w, (acct, line)| {
                w.str(acct).str(line);
            });
        w.finish()
    }

    pub fn digest(&self) -> Result<Oid, EncodeError> {
        Ok(Oid(domain_digest(
            STATEMENT_LINT_REPORT_FORMAT,
            &[&self.canonical_bytes()?],
        )))
    }
}

/// Lint a built-in `StatementDefinition` against a chart of accounts (`fa statement lint`).
pub fn lint_statement_definition(
    definition: &StatementDefinition,
    accounts: &[Account],
) -> Result<StatementLintReport, StatementError> {
    let custom = CustomStatementDefinition::from_builtin(definition);
    let mut report = lint_custom_statement_definition(&custom, accounts)?;
    report.definition_digest = Oid(definition.digest()?);
    Ok(report)
}

/// Lint a `CustomStatementDefinition` against a chart of accounts (`fa statement lint`, `fa-i9yn`).
pub fn lint_custom_statement_definition(
    definition: &CustomStatementDefinition,
    accounts: &[Account],
) -> Result<StatementLintReport, StatementError> {
    definition.validate()?;
    let mut ids = BTreeSet::new();
    let mut chart_by_code = BTreeMap::new();
    for account in accounts {
        if account.code.is_empty()
            || account.code.len() > 64
            || account.name.len() > fa_model::limits::MAX_SCHEMA_CHANGE_BYTES
        {
            return Err(input(
                "account code must be 1..=64 bytes and its name must fit the chart schema body",
            ));
        }
        if !ids.insert(account.id)
            || chart_by_code
                .insert(account.code.as_str(), account)
                .is_some()
        {
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
    }

    let covered_types = definition.kind.covered_types();
    let mut explicit_codes = BTreeSet::new();
    let mut line_match_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for line in &definition.lines {
        if let CustomLineSource::AccountSet { expr, .. } = &line.source {
            expr.collect_explicit_codes(&mut explicit_codes);
            line_match_counts.insert(line.code.as_str(), 0);
        }
    }

    let mut unknown_referenced_codes = Vec::new();
    let mut summary_referenced_codes = Vec::new();
    let mut outside_coverage_codes = Vec::new();
    for code in explicit_codes {
        match chart_by_code.get(code) {
            None => unknown_referenced_codes.push(code.to_string()),
            Some(acct) => {
                if !acct.is_leaf {
                    summary_referenced_codes.push(code.to_string());
                } else if !covered_types.contains(&acct.account_type) {
                    outside_coverage_codes.push(code.to_string());
                }
            }
        }
    }

    let mut covered_leaf_count = 0u32;
    let mut mapped_leaf_count = 0u32;
    let mut unmapped_leaves = Vec::new();
    let mut multiply_mapped_leaves = Vec::new();
    let mut mappings = Vec::new();

    for account in chart_by_code.values() {
        if !account.is_leaf || !covered_types.contains(&account.account_type) {
            continue;
        }
        covered_leaf_count += 1;
        let matched_lines: Vec<String> = definition
            .lines
            .iter()
            .filter_map(|line| match &line.source {
                CustomLineSource::AccountSet { expr, .. } if expr.matches(account) => {
                    Some(line.code.clone())
                }
                _ => None,
            })
            .collect();
        for l in &matched_lines {
            if let Some(cnt) = line_match_counts.get_mut(l.as_str()) {
                *cnt += 1;
            }
        }
        match matched_lines.as_slice() {
            [] => unmapped_leaves.push(account.code.clone()),
            [single] => {
                mapped_leaf_count += 1;
                mappings.push((account.code.clone(), single.clone()));
            }
            _ => multiply_mapped_leaves.push((account.code.clone(), matched_lines)),
        }
    }

    let mut empty_account_lines = Vec::new();
    for line in &definition.lines {
        if matches!(line.source, CustomLineSource::AccountSet { .. })
            && line_match_counts
                .get(line.code.as_str())
                .copied()
                .unwrap_or(0)
                == 0
        {
            empty_account_lines.push(line.code.clone());
        }
    }

    Ok(StatementLintReport {
        definition_name: definition.name.clone(),
        definition_version: definition.version,
        definition_digest: definition.digest()?,
        covered_leaf_count,
        mapped_leaf_count,
        unmapped_leaves,
        multiply_mapped_leaves,
        unknown_referenced_codes,
        summary_referenced_codes,
        outside_coverage_codes,
        empty_account_lines,
        mappings,
    })
}

/// Map `accounts` onto `definition`'s lines by code, as [`crate::map_accounts`]
/// maps a registered definition by account type: every covered leaf must
/// match exactly one account line, or the partition is refused naming the
/// unmapped and multiply mapped codes. Codes the definition names that
/// `accounts` lack are not checked here; `lint_custom_statement_definition`
/// reports those against a whole chart.
pub fn map_custom_accounts(
    definition: &CustomStatementDefinition,
    accounts: &[Account],
) -> Result<Vec<crate::AccountMapping>, StatementError> {
    let lint = lint_custom_statement_definition(definition, accounts)?;
    if !lint.unmapped_leaves.is_empty() || !lint.multiply_mapped_leaves.is_empty() {
        return Err(StatementError::Partition {
            unmapped: lint.unmapped_leaves,
            multiply_mapped: lint.multiply_mapped_leaves,
        });
    }
    let by_code: BTreeMap<&str, &Account> = accounts
        .iter()
        .map(|account| (account.code.as_str(), account))
        .collect();
    lint.mappings
        .into_iter()
        .map(|(code, line_code)| {
            let account = by_code
                .get(code.as_str())
                .ok_or_else(|| input(format!("mapped account `{code}` is not in the chart")))?;
            Ok(crate::AccountMapping {
                account: (*account).clone(),
                line_code,
            })
        })
        .collect()
}

/// Evaluate a `CustomStatementDefinition` over a `StatementInput` (`fa-i9yn`).
pub fn evaluate_custom(
    definition: &CustomStatementDefinition,
    source: &StatementInput,
) -> Result<Statement, StatementError> {
    if source.columns.is_empty() || source.columns.len() > 8 {
        return Err(input("a statement requires 1..=8 columns"));
    }
    if source.units.is_empty() || source.units.len() > 4096 {
        return Err(input(
            "a statement requires an explicit nonempty bounded native-unit set",
        ));
    }
    let mut units = source.units.clone();
    units.sort_unstable();
    if units.windows(2).any(|w| w[0] == w[1]) {
        return Err(input("the native-unit set contains duplicates"));
    }

    let lint = lint_custom_statement_definition(definition, &source.accounts)?;
    if !lint.unmapped_leaves.is_empty() || !lint.multiply_mapped_leaves.is_empty() {
        return Err(StatementError::Partition {
            unmapped: lint.unmapped_leaves,
            multiply_mapped: lint.multiply_mapped_leaves,
        });
    }
    if !lint.unknown_referenced_codes.is_empty()
        || !lint.summary_referenced_codes.is_empty()
        || !lint.outside_coverage_codes.is_empty()
    {
        return Err(StatementError::Definition(format!(
            "custom definition references invalid account codes: unknown={:?}, summary={:?}, outside_coverage={:?}",
            lint.unknown_referenced_codes,
            lint.summary_referenced_codes,
            lint.outside_coverage_codes
        )));
    }

    let accounts_by_id: BTreeMap<u128, &Account> =
        source.accounts.iter().map(|a| (a.id, a)).collect();
    let accounts_by_code: BTreeMap<&str, &Account> = source
        .accounts
        .iter()
        .map(|a| (a.code.as_str(), a))
        .collect();
    let line_indexes: BTreeMap<&str, usize> = definition
        .lines
        .iter()
        .enumerate()
        .map(|(idx, line)| (line.code.as_str(), idx))
        .collect();

    let mut mappings = Vec::with_capacity(lint.mappings.len());
    let mut account_lines = BTreeMap::new();
    for (acct_code, line_code) in &lint.mappings {
        let acct = accounts_by_code[acct_code.as_str()];
        account_lines.insert(acct.id, line_indexes[line_code.as_str()]);
        mappings.push(crate::AccountMapping {
            account: (*acct).clone(),
            line_code: line_code.clone(),
        });
    }

    let dummy_builtin = StatementDefinition::embedded(match definition.kind {
        StatementKind::BalanceSheet => "balance-sheet",
        StatementKind::IncomeStatement => "income-statement",
    })?;

    let mut columns = Vec::with_capacity(source.columns.len());
    let mut values = Vec::with_capacity(source.columns.len());
    for column in &source.columns {
        let descriptor = column_descriptor(&dummy_builtin, column)?;
        let mut sums: BTreeMap<u32, Vec<Sum>> = units
            .iter()
            .map(|u| (*u, vec![Sum::ZERO; definition.lines.len()]))
            .collect();
        let mut seen = BTreeSet::new();
        for balance in &column.balances {
            let account = accounts_by_id.get(&balance.account_id).ok_or_else(|| {
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
                continue;
            };
            let CustomLineSource::AccountSet { sign, .. } = &definition.lines[index].source else {
                return Err(input("validated partition names a computed line"));
            };
            let failed = || {
                overflow(
                    &definition.lines[index].code,
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
            let mut lines: Vec<i128> = Vec::with_capacity(definition.lines.len());
            for (index, line) in definition.lines.iter().enumerate() {
                if let CustomLineSource::Formula { add, subtract } = &line.source {
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
                if value != 0 && definition.check_lines.contains(&line.code) {
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

    let mut lines = Vec::with_capacity(definition.lines.len() * units.len());
    for (index, line) in definition.lines.iter().enumerate() {
        for unit in &units {
            lines.push(StatementLine {
                code: line.code.clone(),
                label: line.label.clone(),
                unit_id: *unit,
                amounts: values.iter().map(|col| col[unit][index]).collect(),
            });
        }
    }

    Ok(Statement {
        book_id: source.book_id,
        branch_id: source.branch_id,
        known_at: source.known_at,
        definition_name: definition.name.clone(),
        definition_version: definition.version,
        definition_digest: definition.digest()?.0,
        definition_bytes: definition.canonical_bytes()?,
        columns,
        lines,
        mappings,
    })
}

/// Specification for presentation rounding of a certified statement (plan §12.1, `fa-i9yn`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentationRoundingSpec {
    pub rounding_law: RoundingLaw,
    /// Power-of-ten scale reduction `k` (`0..=38`), dividing exact mantissas by `10^k`.
    pub scale_reduction_digits: u8,
    /// Code prefix/suffix used for explicit presentation-rounding residual lines.
    pub residual_line_code: String,
    pub residual_line_label: String,
}

impl PresentationRoundingSpec {
    /// Validate the bounded report parameter before evaluating or certifying it.
    pub fn validate(&self) -> Result<(), StatementError> {
        if self.scale_reduction_digits > MAX_SCALE_REDUCTION {
            return Err(input(format!(
                "scale_reduction_digits {} exceeds maximum {MAX_SCALE_REDUCTION}",
                self.scale_reduction_digits
            )));
        }
        if self.residual_line_code.is_empty()
            || self.residual_line_code.len() > 64
            || !self
                .residual_line_code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(input(
                "presentation rounding requires a residual_line_code that is a bounded ASCII identifier",
            ));
        }
        if self.residual_line_label.trim().is_empty() || self.residual_line_label.len() > 256 {
            return Err(input(
                "presentation rounding requires a non-empty residual_line_label of at most 256 bytes",
            ));
        }
        Ok(())
    }

    /// Encode the parameter without changing the existing presented-output format.
    /// Call `validate` when accepting a parameter constructed by a caller.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        if self.residual_line_code.len() > 64 || self.residual_line_label.len() > 256 {
            return Err(EncodeError::LengthOverflow);
        }
        let mut w = Writer::new();
        w.fixed(PRESENTATION_ROUNDING_SPEC_FORMAT)
            .u16(self.rounding_law.id())
            .u8(self.scale_reduction_digits)
            .str(&self.residual_line_code)
            .str(&self.residual_line_label);
        w.finish()
    }

    /// Decode one complete, bounded parameter and enforce the same validation.
    pub fn decode(bytes: &[u8]) -> Result<Self, StatementError> {
        const MAX_BYTES: usize = PRESENTATION_ROUNDING_SPEC_FORMAT.len() + 2 + 1 + 4 + 64 + 4 + 256;
        if bytes.len() > MAX_BYTES {
            return Err(input(
                "presentation rounding specification exceeds its byte bound",
            ));
        }
        let mut r = Reader::new(bytes);
        if r.fixed::<{ PRESENTATION_ROUNDING_SPEC_FORMAT.len() }>("presentation.format")?
            != PRESENTATION_ROUNDING_SPEC_FORMAT
        {
            return Err(r
                .invalid("presentation rounding specification format")
                .into());
        }
        let rounding_law = RoundingLaw::from_id(r.u16("presentation.rounding_law")?)
            .ok_or_else(|| r.invalid("registered presentation rounding law"))?;
        let value = Self {
            rounding_law,
            scale_reduction_digits: r.u8("presentation.scale_reduction_digits")?,
            residual_line_code: r.str(64, "presentation.residual_line_code")?.to_string(),
            residual_line_label: r.str(256, "presentation.residual_line_label")?.to_string(),
        };
        r.finish()?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedStatementLine {
    pub code: String,
    pub label: String,
    pub unit_id: u32,
    /// Original exact mantissas prior to presentation rounding (`0` for synthetic residual lines).
    pub exact_amounts: Vec<i128>,
    /// Rounded amounts in presentation units (`10^scale_reduction_digits` native mantissa units).
    pub presented_amounts: Vec<i128>,
    /// Exact native-unit rounding error per column (`presented * 10^k - exact`).
    pub rounding_errors: Vec<i128>,
    /// True when this row is an explicit presentation-rounding residual line.
    pub is_residual_line: bool,
}

/// Statement rendered under a registered presentation-rounding law with explicit
/// residual lines whenever rounded subtotals/totals differ from the sum of rounded inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedStatement {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub known_at: u64,
    pub definition_name: String,
    pub definition_version: u32,
    pub definition_digest: Oid,
    pub rounding_law: RoundingLaw,
    pub scale_reduction_digits: u8,
    pub divisor: i128,
    pub columns: Vec<Column>,
    pub lines: Vec<PresentedStatementLine>,
}

impl PresentedStatement {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(PRESENTED_STATEMENT_FORMAT)
            .fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u64(self.known_at)
            .str(&self.definition_name)
            .u32(self.definition_version)
            .fixed(&self.definition_digest.0)
            .u16(self.rounding_law.id())
            .u8(self.scale_reduction_digits)
            .i128(self.divisor)
            .list(&self.columns, |w, col| {
                w.str(&col.label)
                    .list(&col.periods, |w, p| {
                        w.str(p);
                    })
                    .opt(col.effective_from.as_ref(), |w, d| {
                        w.i32(d.0);
                    })
                    .i32(col.effective_through.0);
            })
            .list(&self.lines, |w, line| {
                w.str(&line.code)
                    .str(&line.label)
                    .u32(line.unit_id)
                    .list(&line.exact_amounts, |w, a| {
                        w.i128(*a);
                    })
                    .list(&line.presented_amounts, |w, a| {
                        w.i128(*a);
                    })
                    .list(&line.rounding_errors, |w, e| {
                        w.i128(*e);
                    })
                    .bool(line.is_residual_line);
            });
        w.finish()
    }

    pub fn digest(&self) -> Result<Oid, EncodeError> {
        Ok(Oid(domain_digest(
            PRESENTED_STATEMENT_FORMAT,
            &[&self.canonical_bytes()?],
        )))
    }
}

fn round_by_power_of_ten(exact: i128, divisor: u128, law: RoundingLaw) -> Option<(i128, i128)> {
    let negative = exact < 0;
    let mag = exact.unsigned_abs();
    let q = mag.checked_div(divisor)?;
    let r = mag.checked_rem(divisor)?;
    let rounded_mag = law.apply_magnitude(q, r, divisor, negative)?;
    let presented = if negative {
        if rounded_mag == 0 {
            0
        } else if rounded_mag == i128::MIN.unsigned_abs() {
            i128::MIN
        } else {
            i128::try_from(rounded_mag).ok()?.checked_neg()?
        }
    } else {
        i128::try_from(rounded_mag).ok()?
    };
    let scaled_back_mag = U256::from_u128(rounded_mag).checked_mul_u128(divisor)?;
    let scaled_back_u128 = scaled_back_mag.to_u128()?;
    let scaled_back = if negative {
        if scaled_back_u128 == 0 {
            0
        } else if scaled_back_u128 == i128::MIN.unsigned_abs() {
            i128::MIN
        } else {
            i128::try_from(scaled_back_u128).ok()?.checked_neg()?
        }
    } else {
        i128::try_from(scaled_back_u128).ok()?
    };
    let error = scaled_back.checked_sub(exact)?;
    // Verify the registered rounding law's exact error bound:
    // - Half-* laws: |error| * 2 <= divisor
    // - Directed/truncation laws: |error| < divisor
    let err_abs = error.unsigned_abs();
    match law {
        RoundingLaw::HalfUp
        | RoundingLaw::HalfDown
        | RoundingLaw::HalfEven
        | RoundingLaw::HalfAwayFromZero
        | RoundingLaw::HalfTowardZero => {
            if err_abs.checked_mul(2)? > divisor {
                return None;
            }
        }
        RoundingLaw::Ceiling
        | RoundingLaw::Floor
        | RoundingLaw::TowardZero
        | RoundingLaw::AwayFromZero => {
            if err_abs >= divisor {
                return None;
            }
        }
    }
    Some((presented, error))
}

/// Apply presentation rounding under a registered `RoundingLaw` to a `Statement`,
/// emitting an explicit residual line whenever rounded formula operands do not sum
/// to the rounded formula line (`fa-i9yn`, never silent).
pub fn apply_presentation_rounding(
    statement: &Statement,
    definition: &CustomStatementDefinition,
    spec: &PresentationRoundingSpec,
) -> Result<PresentedStatement, StatementError> {
    spec.validate()?;
    let divisor_u128 = 10u128.pow(u32::from(spec.scale_reduction_digits));
    let divisor =
        i128::try_from(divisor_u128).map_err(|_| input("presentation divisor overflows i128"))?;

    let mut units: Vec<u32> = statement.lines.iter().map(|l| l.unit_id).collect();
    units.sort_unstable();
    units.dedup();

    let col_count = statement.columns.len();
    let mut out_lines = Vec::new();

    for &unit_id in &units {
        let mut presented_by_code: BTreeMap<&str, Vec<i128>> = BTreeMap::new();
        for def_line in &definition.lines {
            let stmt_line = statement
                .lines
                .iter()
                .find(|l| l.code == def_line.code && l.unit_id == unit_id)
                .ok_or_else(|| {
                    input(format!(
                        "statement missing line `{}` in unit {unit_id}",
                        def_line.code
                    ))
                })?;
            let mut presented_amounts = Vec::with_capacity(col_count);
            let mut rounding_errors = Vec::with_capacity(col_count);
            for (col_idx, &exact) in stmt_line.amounts.iter().enumerate() {
                let (presented, err) =
                    round_by_power_of_ten(exact, divisor_u128, spec.rounding_law).ok_or_else(
                        || overflow(&def_line.code, &statement.columns[col_idx].label, unit_id),
                    )?;
                presented_amounts.push(presented);
                rounding_errors.push(err);
            }

            // If this is a Formula line, check whether the rounded formula total differs from
            // the formula applied to the already-rounded operand lines. When non-zero, emit an
            // explicit residual line right before the formula line so the table foots honestly.
            if let CustomLineSource::Formula { add, subtract } = &def_line.source {
                let mut residual_per_col = Vec::with_capacity(col_count);
                let mut any_non_zero = false;
                for col_idx in 0..col_count {
                    let mut rounded_op_sum = Sum::ZERO;
                    for op in add {
                        let v = presented_by_code[op.as_str()][col_idx];
                        rounded_op_sum.add(v, false).ok_or_else(|| {
                            overflow(&def_line.code, &statement.columns[col_idx].label, unit_id)
                        })?;
                    }
                    for op in subtract {
                        let v = presented_by_code[op.as_str()][col_idx];
                        rounded_op_sum.add(v, true).ok_or_else(|| {
                            overflow(&def_line.code, &statement.columns[col_idx].label, unit_id)
                        })?;
                    }
                    let op_total = rounded_op_sum.value().ok_or_else(|| {
                        overflow(&def_line.code, &statement.columns[col_idx].label, unit_id)
                    })?;
                    let res = presented_amounts[col_idx]
                        .checked_sub(op_total)
                        .ok_or_else(|| {
                            overflow(&def_line.code, &statement.columns[col_idx].label, unit_id)
                        })?;
                    if res != 0 {
                        any_non_zero = true;
                    }
                    residual_per_col.push(res);
                }
                if any_non_zero {
                    let residual_errors: Result<Vec<i128>, StatementError> = residual_per_col
                        .iter()
                        .enumerate()
                        .map(|(col_idx, &r)| {
                            r.checked_mul(divisor).ok_or_else(|| {
                                overflow(
                                    &spec.residual_line_code,
                                    &statement.columns[col_idx].label,
                                    unit_id,
                                )
                            })
                        })
                        .collect();
                    out_lines.push(PresentedStatementLine {
                        code: format!("{}_{}", def_line.code, spec.residual_line_code),
                        label: format!("{} ({})", spec.residual_line_label, def_line.label),
                        unit_id,
                        exact_amounts: vec![0; col_count],
                        presented_amounts: residual_per_col,
                        rounding_errors: residual_errors?,
                        is_residual_line: true,
                    });
                }
            }

            presented_by_code.insert(def_line.code.as_str(), presented_amounts.clone());
            out_lines.push(PresentedStatementLine {
                code: def_line.code.clone(),
                label: def_line.label.clone(),
                unit_id,
                exact_amounts: stmt_line.amounts.clone(),
                presented_amounts,
                rounding_errors,
                is_residual_line: false,
            });
        }
    }

    Ok(PresentedStatement {
        book_id: statement.book_id,
        branch_id: statement.branch_id,
        known_at: statement.known_at,
        definition_name: statement.definition_name.clone(),
        definition_version: statement.definition_version,
        definition_digest: Oid(statement.definition_digest),
        rounding_law: spec.rounding_law,
        scale_reduction_digits: spec.scale_reduction_digits,
        divisor,
        columns: statement.columns.clone(),
        lines: out_lines,
    })
}

pub const STATEMENT_XBRL_MAPPING_FORMAT: &[u8] = b"fa:statement-xbrl-mapping:v1";

/// XBRL 2.1 period type for a monetary taxonomy concept (`instant` or `duration`, plan §12.6, `fa-faim`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum XbrlPeriodType {
    Instant,
    Duration,
}

impl XbrlPeriodType {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Instant => 1,
            Self::Duration => 2,
        }
    }

    pub fn from_tag(tag: u8, r: &Reader<'_>) -> Result<Self, DecodeError> {
        match tag {
            1 => Ok(Self::Instant),
            2 => Ok(Self::Duration),
            _ => Err(r.bad_tag("xbrl_period_type", tag)),
        }
    }
}

/// XBRL 2.1 natural balance attribute (`debit` or `credit`) on a monetary concept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum XbrlBalanceSide {
    Debit,
    Credit,
}

impl XbrlBalanceSide {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Debit => 1,
            Self::Credit => 2,
        }
    }

    pub fn from_tag(tag: u8, r: &Reader<'_>) -> Result<Self, DecodeError> {
        match tag {
            1 => Ok(Self::Debit),
            2 => Ok(Self::Credit),
            _ => Err(r.bad_tag("xbrl_balance_side", tag)),
        }
    }
}

/// Maps one statement definition line (`line_code`) to an XBRL taxonomy concept QName (`us-gaap:...`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XbrlConceptBinding {
    pub line_code: String,
    pub concept: String,
    pub period_type: XbrlPeriodType,
    pub balance_side: Option<XbrlBalanceSide>,
}

/// Content-addressed mapping from a statement definition's line codes to XBRL taxonomy concepts
/// and calculation-linkbase role URI (plan §12.6, §16.3, bead `fa-faim`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementXbrlMapping {
    pub mapping_id: String,
    pub statement_definition_name: String,
    pub taxonomy_namespace: String,
    pub taxonomy_schema_href: String,
    pub role_uri: String,
    pub bindings: Vec<XbrlConceptBinding>,
}

impl StatementXbrlMapping {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(STATEMENT_XBRL_MAPPING_FORMAT)
            .str(&self.mapping_id)
            .str(&self.statement_definition_name)
            .str(&self.taxonomy_namespace)
            .str(&self.taxonomy_schema_href)
            .str(&self.role_uri)
            .list(&self.bindings, |w, b| {
                w.str(&b.line_code)
                    .str(&b.concept)
                    .u8(b.period_type.tag())
                    .opt(b.balance_side.as_ref(), |w, side| {
                        w.u8(side.tag());
                    });
            });
        w.finish()
    }

    pub fn digest(&self) -> Result<Oid, EncodeError> {
        Ok(Oid(domain_digest(
            STATEMENT_XBRL_MAPPING_FORMAT,
            &[&self.canonical_bytes()?],
        )))
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, StatementError> {
        let mut r = Reader::new(bytes);
        let magic = r.fixed::<{ STATEMENT_XBRL_MAPPING_FORMAT.len() }>("xbrl_mapping.magic")?;
        if magic != STATEMENT_XBRL_MAPPING_FORMAT {
            return Err(StatementError::Definition(
                "unknown statement XBRL mapping header".into(),
            ));
        }
        let mapping_id = r.str(256, "mapping_id")?.to_string();
        let statement_definition_name = r.str(256, "statement_definition_name")?.to_string();
        let taxonomy_namespace = r.str(256, "taxonomy_namespace")?.to_string();
        let taxonomy_schema_href = r.str(256, "taxonomy_schema_href")?.to_string();
        let role_uri = r.str(256, "role_uri")?.to_string();
        let bindings = r.list(MAX_CUSTOM_LINES, "bindings", |r| {
            let line_code = r.str(64, "line_code")?.to_string();
            let concept = r.str(256, "concept")?.to_string();
            let period_type_tag = r.u8("period_type")?;
            let period_type = XbrlPeriodType::from_tag(period_type_tag, r)?;
            let balance_side = r.opt("balance_side", |r| {
                let tag = r.u8("balance_side.tag")?;
                XbrlBalanceSide::from_tag(tag, r)
            })?;
            Ok(XbrlConceptBinding {
                line_code,
                concept,
                period_type,
                balance_side,
            })
        })?;
        r.finish()?;
        Ok(Self {
            mapping_id,
            statement_definition_name,
            taxonomy_namespace,
            taxonomy_schema_href,
            role_uri,
            bindings,
        })
    }

    /// Standard US-GAAP concept mapping for FrankenAccounting's built-in type-level Balance Sheet.
    ///
    /// Element names are cited from the published FASB US-GAAP Financial Reporting Taxonomy
    /// (`http://fasb.org/us-gaap/2026`, Statement of Financial Position — Classified `104000`):
    /// - `unclosed_earnings` binds to `us-gaap:RetainedEarningsAccumulatedDeficit`
    ///   (`xbrli:monetaryItemType`, `xbrli:periodType="instant"`, `xbrli:balance="credit"`).
    pub fn us_gaap_type_level_balance_sheet() -> Self {
        let b = |line_code: &str, concept: &str, side: XbrlBalanceSide| XbrlConceptBinding {
            line_code: line_code.into(),
            concept: concept.into(),
            period_type: XbrlPeriodType::Instant,
            balance_side: Some(side),
        };
        Self {
            mapping_id: "fa_xbrl_us_gaap_type_level_balance_sheet_v1".into(),
            statement_definition_name: "balance-sheet".into(),
            taxonomy_namespace: "http://fasb.org/us-gaap/2026".into(),
            taxonomy_schema_href: "us_gaap_2026_small_company.xsd".into(),
            role_uri: "http://frankenaccounting.org/role/TypeLevelStatements".into(),
            bindings: vec![
                b("assets", "us-gaap:Assets", XbrlBalanceSide::Debit),
                b(
                    "liabilities",
                    "us-gaap:Liabilities",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "equity",
                    "us-gaap:StockholdersEquity",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "unclosed_earnings",
                    "us-gaap:RetainedEarningsAccumulatedDeficit",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "total_equity",
                    "us-gaap:StockholdersEquityIncludingPortionAttributableToNoncontrollingInterest",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "liabilities_and_equity",
                    "us-gaap:LiabilitiesAndStockholdersEquity",
                    XbrlBalanceSide::Credit,
                ),
            ],
        }
    }

    /// Standard US-GAAP concept mapping for FrankenAccounting's built-in type-level Income Statement.
    pub fn us_gaap_type_level_income_statement() -> Self {
        let b = |line_code: &str, concept: &str, side: XbrlBalanceSide| XbrlConceptBinding {
            line_code: line_code.into(),
            concept: concept.into(),
            period_type: XbrlPeriodType::Duration,
            balance_side: Some(side),
        };
        Self {
            mapping_id: "fa_xbrl_us_gaap_type_level_income_statement_v1".into(),
            statement_definition_name: "income-statement".into(),
            taxonomy_namespace: "http://fasb.org/us-gaap/2026".into(),
            taxonomy_schema_href: "us_gaap_2026_small_company.xsd".into(),
            role_uri: "http://frankenaccounting.org/role/TypeLevelStatements".into(),
            bindings: vec![
                b("revenue", "us-gaap:Revenues", XbrlBalanceSide::Credit),
                b(
                    "expense",
                    "us-gaap:OperatingExpenses",
                    XbrlBalanceSide::Debit,
                ),
                b(
                    "net_income",
                    "us-gaap:NetIncomeLoss",
                    XbrlBalanceSide::Credit,
                ),
            ],
        }
    }

    /// US-GAAP small-company classified Balance Sheet concept mapping (`StatementOfFinancialPositionClassified`).
    pub fn us_gaap_small_company_balance_sheet() -> Self {
        let b = |line_code: &str, concept: &str, side: XbrlBalanceSide| XbrlConceptBinding {
            line_code: line_code.into(),
            concept: concept.into(),
            period_type: XbrlPeriodType::Instant,
            balance_side: Some(side),
        };
        Self {
            mapping_id: "fa_xbrl_us_gaap_small_company_balance_sheet_v1".into(),
            statement_definition_name: "us_gaap_small_company_balance_sheet".into(),
            taxonomy_namespace: "http://fasb.org/us-gaap/2026".into(),
            taxonomy_schema_href: "us_gaap_2026_small_company.xsd".into(),
            role_uri:
                "http://fasb.org/us-gaap/role/statement/StatementOfFinancialPositionClassified"
                    .into(),
            bindings: vec![
                b(
                    "cash",
                    "us-gaap:CashAndCashEquivalentsAtCarryingValue",
                    XbrlBalanceSide::Debit,
                ),
                b(
                    "accounts_receivable",
                    "us-gaap:AccountsReceivableNetCurrent",
                    XbrlBalanceSide::Debit,
                ),
                b("inventory", "us-gaap:InventoryNet", XbrlBalanceSide::Debit),
                b(
                    "current_assets",
                    "us-gaap:AssetsCurrent",
                    XbrlBalanceSide::Debit,
                ),
                b(
                    "ppe_net",
                    "us-gaap:PropertyPlantAndEquipmentNet",
                    XbrlBalanceSide::Debit,
                ),
                b(
                    "noncurrent_assets",
                    "us-gaap:AssetsNoncurrent",
                    XbrlBalanceSide::Debit,
                ),
                b("total_assets", "us-gaap:Assets", XbrlBalanceSide::Debit),
                b(
                    "accounts_payable",
                    "us-gaap:AccountsPayableCurrent",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "accrued_liabilities",
                    "us-gaap:AccruedLiabilitiesCurrent",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "current_liabilities",
                    "us-gaap:LiabilitiesCurrent",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "long_term_debt",
                    "us-gaap:LongTermDebtNoncurrent",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "noncurrent_liabilities",
                    "us-gaap:LiabilitiesNoncurrent",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "total_liabilities",
                    "us-gaap:Liabilities",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "common_stock",
                    "us-gaap:CommonStockValue",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "retained_earnings",
                    "us-gaap:RetainedEarningsAccumulatedDeficit",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "total_equity",
                    "us-gaap:StockholdersEquity",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "liabilities_and_equity",
                    "us-gaap:LiabilitiesAndStockholdersEquity",
                    XbrlBalanceSide::Credit,
                ),
            ],
        }
    }

    /// US-GAAP small-company multi-step Income Statement concept mapping (`StatementOfIncome`).
    pub fn us_gaap_small_company_income_statement() -> Self {
        let b = |line_code: &str, concept: &str, side: XbrlBalanceSide| XbrlConceptBinding {
            line_code: line_code.into(),
            concept: concept.into(),
            period_type: XbrlPeriodType::Duration,
            balance_side: Some(side),
        };
        Self {
            mapping_id: "fa_xbrl_us_gaap_small_company_income_statement_v1".into(),
            statement_definition_name: "us_gaap_small_company_income_statement".into(),
            taxonomy_namespace: "http://fasb.org/us-gaap/2026".into(),
            taxonomy_schema_href: "us_gaap_2026_small_company.xsd".into(),
            role_uri: "http://fasb.org/us-gaap/role/statement/StatementOfIncome".into(),
            bindings: vec![
                b("revenues", "us-gaap:Revenues", XbrlBalanceSide::Credit),
                b(
                    "cogs",
                    "us-gaap:CostOfGoodsAndServicesSold",
                    XbrlBalanceSide::Debit,
                ),
                b(
                    "gross_profit",
                    "us-gaap:GrossProfit",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "operating_expenses",
                    "us-gaap:OperatingExpenses",
                    XbrlBalanceSide::Debit,
                ),
                b(
                    "operating_income",
                    "us-gaap:OperatingIncomeLoss",
                    XbrlBalanceSide::Credit,
                ),
                b(
                    "income_tax_expense",
                    "us-gaap:IncomeTaxExpenseBenefit",
                    XbrlBalanceSide::Debit,
                ),
                b(
                    "net_income",
                    "us-gaap:NetIncomeLoss",
                    XbrlBalanceSide::Credit,
                ),
            ],
        }
    }
}

impl CustomStatementDefinition {
    /// Standard US-GAAP small-company classified Balance Sheet definition (`fa-faim`):
    /// - `1000..1099`: Cash and Cash Equivalents (`cash`)
    /// - `1100..1199`: Accounts Receivable, Net (`accounts_receivable`)
    /// - `1200..1299`: Inventory, Net (`inventory`)
    /// - `1300..1999`: Property, Plant and Equipment, Net (`ppe_net`, via difference `Asset \ (10..12)`)
    /// - `2000..2099`: Accounts Payable (`accounts_payable`)
    /// - `2100..2199`: Accrued Liabilities (`accrued_liabilities`)
    /// - `2200..2999`: Long-Term Debt (`long_term_debt`, via difference `Liability \ (20..21)`)
    /// - `3000..3099`: Common Stock (`common_stock`)
    /// - Remaining Equity + Revenue + Expense: Retained Earnings & Current Period Earnings (`retained_earnings`)
    pub fn us_gaap_small_company_balance_sheet() -> Self {
        let cash_expr = AccountSetExpr::AccountCodePrefixes(vec!["10".into()]);
        let ar_expr = AccountSetExpr::AccountCodePrefixes(vec!["11".into()]);
        let inv_expr = AccountSetExpr::AccountCodePrefixes(vec!["12".into()]);
        let cur_asset_expr =
            AccountSetExpr::Union(vec![cash_expr.clone(), ar_expr.clone(), inv_expr.clone()]);
        let ppe_expr = AccountSetExpr::Difference {
            include: Box::new(AccountSetExpr::AccountTypes(vec![1])),
            exclude: Box::new(cur_asset_expr),
        };

        let ap_expr = AccountSetExpr::AccountCodePrefixes(vec!["20".into()]);
        let acc_expr = AccountSetExpr::AccountCodePrefixes(vec!["21".into()]);
        let cur_liab_expr = AccountSetExpr::Union(vec![ap_expr.clone(), acc_expr.clone()]);
        let ltd_expr = AccountSetExpr::Difference {
            include: Box::new(AccountSetExpr::AccountTypes(vec![2])),
            exclude: Box::new(cur_liab_expr),
        };

        let cs_expr = AccountSetExpr::AccountCodePrefixes(vec!["30".into()]);
        let re_expr = AccountSetExpr::Union(vec![
            AccountSetExpr::Difference {
                include: Box::new(AccountSetExpr::AccountTypes(vec![3])),
                exclude: Box::new(cs_expr.clone()),
            },
            AccountSetExpr::AccountTypes(vec![4, 5]),
        ]);

        Self {
            name: "us_gaap_small_company_balance_sheet".into(),
            title: "US-GAAP Small-Company Classified Balance Sheet".into(),
            version: 1,
            kind: StatementKind::BalanceSheet,
            lines: vec![
                CustomLineDefinition {
                    code: "cash".into(),
                    label: "Cash and Cash Equivalents".into(),
                    source: CustomLineSource::AccountSet {
                        expr: cash_expr,
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "accounts_receivable".into(),
                    label: "Accounts Receivable, Net".into(),
                    source: CustomLineSource::AccountSet {
                        expr: ar_expr,
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "inventory".into(),
                    label: "Inventory, Net".into(),
                    source: CustomLineSource::AccountSet {
                        expr: inv_expr,
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "current_assets".into(),
                    label: "Total Current Assets".into(),
                    source: CustomLineSource::Formula {
                        add: vec![
                            "accounts_receivable".into(),
                            "cash".into(),
                            "inventory".into(),
                        ],
                        subtract: vec![],
                    },
                },
                CustomLineDefinition {
                    code: "ppe_net".into(),
                    label: "Property, Plant and Equipment, Net".into(),
                    source: CustomLineSource::AccountSet {
                        expr: ppe_expr,
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "noncurrent_assets".into(),
                    label: "Total Noncurrent Assets".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["ppe_net".into()],
                        subtract: vec![],
                    },
                },
                CustomLineDefinition {
                    code: "total_assets".into(),
                    label: "Total Assets".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["current_assets".into(), "noncurrent_assets".into()],
                        subtract: vec![],
                    },
                },
                CustomLineDefinition {
                    code: "accounts_payable".into(),
                    label: "Accounts Payable".into(),
                    source: CustomLineSource::AccountSet {
                        expr: ap_expr,
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "accrued_liabilities".into(),
                    label: "Accrued Liabilities".into(),
                    source: CustomLineSource::AccountSet {
                        expr: acc_expr,
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "current_liabilities".into(),
                    label: "Total Current Liabilities".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["accounts_payable".into(), "accrued_liabilities".into()],
                        subtract: vec![],
                    },
                },
                CustomLineDefinition {
                    code: "long_term_debt".into(),
                    label: "Long-Term Debt".into(),
                    source: CustomLineSource::AccountSet {
                        expr: ltd_expr,
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "noncurrent_liabilities".into(),
                    label: "Total Noncurrent Liabilities".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["long_term_debt".into()],
                        subtract: vec![],
                    },
                },
                CustomLineDefinition {
                    code: "total_liabilities".into(),
                    label: "Total Liabilities".into(),
                    source: CustomLineSource::Formula {
                        add: vec![
                            "current_liabilities".into(),
                            "noncurrent_liabilities".into(),
                        ],
                        subtract: vec![],
                    },
                },
                CustomLineDefinition {
                    code: "common_stock".into(),
                    label: "Common Stock".into(),
                    source: CustomLineSource::AccountSet {
                        expr: cs_expr,
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "retained_earnings".into(),
                    label: "Retained Earnings".into(),
                    source: CustomLineSource::AccountSet {
                        expr: re_expr,
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "total_equity".into(),
                    label: "Total Stockholders' Equity".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["common_stock".into(), "retained_earnings".into()],
                        subtract: vec![],
                    },
                },
                CustomLineDefinition {
                    code: "liabilities_and_equity".into(),
                    label: "Total Liabilities and Stockholders' Equity".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["total_equity".into(), "total_liabilities".into()],
                        subtract: vec![],
                    },
                },
                CustomLineDefinition {
                    code: "accounting_identity_residual".into(),
                    label: "Accounting Identity Residual".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["total_assets".into()],
                        subtract: vec!["liabilities_and_equity".into()],
                    },
                },
            ],
            check_lines: vec!["accounting_identity_residual".into()],
        }
    }

    /// Standard US-GAAP small-company multi-step Income Statement definition (`fa-faim`):
    /// - Type `4` (`Revenue`): Revenues (`revenues`)
    /// - Prefix `50`: Cost of Goods and Services Sold (`cogs`)
    /// - Prefix `69`: Income Tax Expense (`income_tax_expense`)
    /// - Remaining Type `5` (`Expense \ (50 union 69)`): Operating Expenses (`operating_expenses`)
    pub fn us_gaap_small_company_income_statement() -> Self {
        let cogs_expr = AccountSetExpr::AccountCodePrefixes(vec!["50".into()]);
        let tax_expr = AccountSetExpr::AccountCodePrefixes(vec!["69".into()]);
        let opex_expr = AccountSetExpr::Difference {
            include: Box::new(AccountSetExpr::AccountTypes(vec![5])),
            exclude: Box::new(AccountSetExpr::Union(vec![
                cogs_expr.clone(),
                tax_expr.clone(),
            ])),
        };
        Self {
            name: "us_gaap_small_company_income_statement".into(),
            title: "US-GAAP Small-Company Multi-Step Income Statement".into(),
            version: 1,
            kind: StatementKind::IncomeStatement,
            lines: vec![
                CustomLineDefinition {
                    code: "revenues".into(),
                    label: "Revenues".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountTypes(vec![4]),
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "cogs".into(),
                    label: "Cost of Goods and Services Sold".into(),
                    source: CustomLineSource::AccountSet {
                        expr: cogs_expr,
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "gross_profit".into(),
                    label: "Gross Profit".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["revenues".into()],
                        subtract: vec!["cogs".into()],
                    },
                },
                CustomLineDefinition {
                    code: "operating_expenses".into(),
                    label: "Operating Expenses".into(),
                    source: CustomLineSource::AccountSet {
                        expr: opex_expr,
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "operating_income".into(),
                    label: "Operating Income (Loss)".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["gross_profit".into()],
                        subtract: vec!["operating_expenses".into()],
                    },
                },
                CustomLineDefinition {
                    code: "income_tax_expense".into(),
                    label: "Income Tax Expense (Benefit)".into(),
                    source: CustomLineSource::AccountSet {
                        expr: tax_expr,
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "net_income".into(),
                    label: "Net Income (Loss)".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["operating_income".into()],
                        subtract: vec!["income_tax_expense".into()],
                    },
                },
            ],
            check_lines: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountBalance, ColumnInput};
    use fa_time::DateDay;

    fn sample_chart() -> Vec<Account> {
        vec![
            Account {
                id: 1,
                code: "1010".into(),
                name: "Operating Cash".into(),
                account_type: 1,
                is_leaf: true,
            },
            Account {
                id: 2,
                code: "1100".into(),
                name: "Accounts Receivable".into(),
                account_type: 1,
                is_leaf: true,
            },
            Account {
                id: 3,
                code: "2000".into(),
                name: "Accounts Payable".into(),
                account_type: 2,
                is_leaf: true,
            },
            Account {
                id: 4,
                code: "3000".into(),
                name: "Common Stock".into(),
                account_type: 3,
                is_leaf: true,
            },
            Account {
                id: 5,
                code: "4000".into(),
                name: "Product Revenue".into(),
                account_type: 4,
                is_leaf: true,
            },
            Account {
                id: 6,
                code: "5000".into(),
                name: "Operating Expense".into(),
                account_type: 5,
                is_leaf: true,
            },
        ]
    }

    fn custom_balance_sheet_def() -> CustomStatementDefinition {
        CustomStatementDefinition {
            name: "custom-balance-sheet".into(),
            title: "Custom Classified Balance Sheet".into(),
            version: 1,
            kind: StatementKind::BalanceSheet,
            lines: vec![
                CustomLineDefinition {
                    code: "cash_and_equivalents".into(),
                    label: "Cash and cash equivalents".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec!["10".into()]),
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "other_assets".into(),
                    label: "Other assets".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::Difference {
                            include: Box::new(AccountSetExpr::AccountTypes(vec![1])),
                            exclude: Box::new(AccountSetExpr::AccountCodePrefixes(vec![
                                "10".into(),
                            ])),
                        },
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "total_assets".into(),
                    label: "Total assets".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["cash_and_equivalents".into(), "other_assets".into()],
                        subtract: vec![],
                    },
                },
                CustomLineDefinition {
                    code: "liabilities".into(),
                    label: "Total liabilities".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountTypes(vec![2]),
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "contributed_equity".into(),
                    label: "Contributed equity".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodes(vec!["3000".into()]),
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "unclosed_revenue".into(),
                    label: "Unclosed revenue".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountTypes(vec![4]),
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "unclosed_expense".into(),
                    label: "Unclosed expense".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountTypes(vec![5]),
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "total_equity".into(),
                    label: "Total equity".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["contributed_equity".into(), "unclosed_revenue".into()],
                        subtract: vec!["unclosed_expense".into()],
                    },
                },
                CustomLineDefinition {
                    code: "balance_check".into(),
                    label: "Balance check".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["total_assets".into()],
                        subtract: vec!["liabilities".into(), "total_equity".into()],
                    },
                },
            ],
            check_lines: vec!["balance_check".into()],
        }
    }

    /// fa-doa9: certificate status maps a later chart's new leaves alone.
    /// Codes the definition names elsewhere (3000) need not be among them,
    /// but every new covered leaf must match exactly one line.
    #[test]
    fn custom_accounts_map_by_code_or_refuse_the_partition() {
        let definition = custom_balance_sheet_def();
        let leaf = |id: u128, code: &str, account_type: u8| Account {
            id,
            code: code.into(),
            name: format!("Account {code}"),
            account_type,
            is_leaf: true,
        };
        let later = vec![leaf(7, "1020", 1), leaf(8, "1200", 1), leaf(9, "2100", 2)];
        let mapped = map_custom_accounts(&definition, &later).unwrap();
        let lines: Vec<(&str, &str)> = mapped
            .iter()
            .map(|mapping| (mapping.account.code.as_str(), mapping.line_code.as_str()))
            .collect();
        assert_eq!(
            lines,
            [
                ("1020", "cash_and_equivalents"),
                ("1200", "other_assets"),
                ("2100", "liabilities"),
            ]
        );
        assert_eq!(mapped[0].account, later[0]);
        // Planted negative: an equity leaf other than 3000 matches no line.
        let mut unmapped = later.clone();
        unmapped.push(leaf(10, "3100", 3));
        let refused = map_custom_accounts(&definition, &unmapped);
        assert!(
            matches!(
                &refused,
                Err(StatementError::Partition { unmapped, multiply_mapped })
                    if unmapped == &["3100".to_string()] && multiply_mapped.is_empty()
            ),
            "{refused:?}"
        );
    }

    #[test]
    fn custom_account_set_expr_definition_lints_evaluates_and_round_trips() {
        let def = custom_balance_sheet_def();
        let encoded = def.canonical_bytes().unwrap();
        let decoded = CustomStatementDefinition::decode(&encoded).unwrap();
        assert_eq!(def, decoded);

        let chart = sample_chart();
        let lint = lint_custom_statement_definition(&def, &chart).unwrap();
        assert!(lint.is_clean());
        assert_eq!(lint.covered_leaf_count, 6);
        assert_eq!(lint.mapped_leaf_count, 6);

        let input = StatementInput {
            book_id: Id128([0x11; 16]),
            branch_id: Id128::TRUNK,
            known_at: 42,
            accounts: chart.clone(),
            units: vec![1],
            columns: vec![ColumnInput {
                label: "FY2026-P01".into(),
                periods: vec!["FY2026-P01".into()],
                effective_from: None,
                effective_through: DateDay(30),
                balances: vec![
                    AccountBalance {
                        account_id: 1,
                        unit_id: 1,
                        debits: 10040,
                        credits: 0,
                    },
                    AccountBalance {
                        account_id: 2,
                        unit_id: 1,
                        debits: 5040,
                        credits: 0,
                    },
                    AccountBalance {
                        account_id: 3,
                        unit_id: 1,
                        debits: 0,
                        credits: 3020,
                    },
                    AccountBalance {
                        account_id: 4,
                        unit_id: 1,
                        debits: 0,
                        credits: 10000,
                    },
                    AccountBalance {
                        account_id: 5,
                        unit_id: 1,
                        debits: 0,
                        credits: 2560,
                    },
                    AccountBalance {
                        account_id: 6,
                        unit_id: 1,
                        debits: 500,
                        credits: 0,
                    },
                ],
            }],
        };

        let stmt = evaluate_custom(&def, &input).unwrap();
        let get_amt = |code: &str| stmt.lines.iter().find(|l| l.code == code).unwrap().amounts[0];
        assert_eq!(get_amt("cash_and_equivalents"), 10040);
        assert_eq!(get_amt("other_assets"), 5040);
        assert_eq!(get_amt("total_assets"), 15080);
        assert_eq!(get_amt("liabilities"), 3020);
        assert_eq!(get_amt("total_equity"), 12060);
        assert_eq!(get_amt("balance_check"), 0);

        // Presentation rounding at scale_reduction_digits = 2 (dividing cents by 100 -> whole dollars):
        // cash_and_equivalents = 10040 -> 100 (err -40)
        // other_assets         =  5040 ->  50 (err -40)
        // total_assets (exact) = 15080 -> 151 (err +20)
        // Because 100 + 50 = 150 != 151, an explicit residual line `total_assets_rounding_residual = +1` is emitted!
        let rounding_spec = PresentationRoundingSpec {
            rounding_law: RoundingLaw::HalfEven,
            scale_reduction_digits: 2,
            residual_line_code: "rounding_residual".into(),
            residual_line_label: "Presentation rounding residual".into(),
        };
        let presented = apply_presentation_rounding(&stmt, &def, &rounding_spec).unwrap();
        let res_line = presented
            .lines
            .iter()
            .find(|l| l.code == "total_assets_rounding_residual")
            .expect("explicit residual line emitted when rounded sum != rounded total");
        assert!(res_line.is_residual_line);
        assert_eq!(res_line.presented_amounts, vec![1]);
        assert_eq!(res_line.rounding_errors, vec![100]);
        // Every non-residual line has |rounding_error| * 2 <= 100 (HalfEven bound).
        for line in presented.lines.iter().filter(|l| !l.is_residual_line) {
            for &err in &line.rounding_errors {
                assert!(err.unsigned_abs() * 2 <= 100);
            }
        }

        // The widest reduction an i128 divisor holds (10^38; a unit with an
        // 18-digit scale presented in millions needs 10^24) presents every
        // line exactly as zero with its whole amount as the rounding error;
        // one digit more is refused.
        let widest = PresentationRoundingSpec {
            scale_reduction_digits: 38,
            ..rounding_spec.clone()
        };
        let presented = apply_presentation_rounding(&stmt, &def, &widest).unwrap();
        assert_eq!(presented.divisor, 10i128.pow(38));
        for line in &presented.lines {
            assert!(!line.is_residual_line);
            assert_eq!(line.presented_amounts, vec![0]);
            assert_eq!(
                line.rounding_errors,
                line.exact_amounts.iter().map(|e| -e).collect::<Vec<_>>()
            );
        }
        let too_wide = PresentationRoundingSpec {
            scale_reduction_digits: 39,
            ..rounding_spec
        };
        assert!(apply_presentation_rounding(&stmt, &def, &too_wide).is_err());
    }

    #[test]
    fn lint_catches_unmapped_multiply_mapped_and_unknown_accounts() {
        let mut def = custom_balance_sheet_def();
        // Replace contributed_equity with an unknown account code "3999" so "3000" is unmapped
        // and also add "1010" so "1010" is multiply mapped.
        def.lines[4].source = CustomLineSource::AccountSet {
            expr: AccountSetExpr::AccountCodes(vec!["1010".into(), "3999".into()]),
            sign: Sign::Credit,
        };
        let chart = sample_chart();
        let lint = lint_custom_statement_definition(&def, &chart).unwrap();
        assert!(!lint.is_clean());
        assert_eq!(lint.unmapped_leaves, vec!["3000".to_string()]);
        assert_eq!(
            lint.multiply_mapped_leaves,
            vec![(
                "1010".to_string(),
                vec![
                    "cash_and_equivalents".to_string(),
                    "contributed_equity".to_string()
                ]
            )]
        );
        assert_eq!(lint.unknown_referenced_codes, vec!["3999".to_string()]);
    }

    #[test]
    fn us_gaap_small_company_definitions_and_xbrl_mappings_round_trip() {
        for def in [
            CustomStatementDefinition::us_gaap_small_company_balance_sheet(),
            CustomStatementDefinition::us_gaap_small_company_income_statement(),
        ] {
            def.validate().unwrap();
            let bytes = def.canonical_bytes().unwrap();
            assert_eq!(CustomStatementDefinition::decode(&bytes).unwrap(), def);
        }
        for mapping in [
            StatementXbrlMapping::us_gaap_type_level_balance_sheet(),
            StatementXbrlMapping::us_gaap_type_level_income_statement(),
            StatementXbrlMapping::us_gaap_small_company_balance_sheet(),
            StatementXbrlMapping::us_gaap_small_company_income_statement(),
        ] {
            let bytes = mapping.canonical_bytes().unwrap();
            assert_eq!(
                StatementXbrlMapping::decode_canonical(&bytes).unwrap(),
                mapping
            );
        }
    }
}
