//! Deterministic Markdown Intermediate Representation (IR) for certified
//! financial statements and restatement comparisons (plan §12.1, §12.5,
//! beads `fa-9ae` and `fa-cet`).
//!
//! All numeric values are formatted strictly from exact `i128` mantissas and
//! registered unit scales (`0..=38`) using integer division/remainder over
//! `u128` magnitudes — never floating-point arithmetic. Column widths, right
//! alignment, and single/double footing rules are computed deterministically.

use std::collections::BTreeMap;

use fa_model::{DecodeError, EncodeError, Id128, Oid, Reader, Writer, domain_digest};

use crate::{LineSource, Statement, StatementDefinition, StatementError};

pub const MARKDOWN_IR_FORMAT: &[u8] = b"fa:statement-markdown-ir:v1";

const MAX_IR_TABLES: usize = 64;
const MAX_IR_COLS: usize = 16;
const MAX_IR_ROWS: usize = 4096;
const MAX_CELL_BYTES: usize = 512;
const MAX_SCALE: u8 = 38;

/// Registered display metadata for one native unit used in a Markdown IR render.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitFormatSpec {
    pub unit_id: u32,
    pub code: String,
    pub scale: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColumnAlignment {
    Left,
    Right,
}

impl ColumnAlignment {
    const fn tag(self) -> u8 {
        match self {
            Self::Left => 0,
            Self::Right => 1,
        }
    }

    fn from_tag(tag: u8, r: &Reader<'_>) -> Result<Self, DecodeError> {
        match tag {
            0 => Ok(Self::Left),
            1 => Ok(Self::Right),
            _ => Err(r.bad_tag("markdown_ir.alignment", tag)),
        }
    }
}

/// Accounting footing rule on a statement row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FootingRule {
    /// Ordinary account-mapped line.
    None,
    /// Single underline (`---`) for intermediate formula/subtotal lines.
    Single,
    /// Double underline (`===`) for bottom-line totals and identity checks.
    Double,
}

impl FootingRule {
    const fn tag(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Single => 1,
            Self::Double => 2,
        }
    }

    fn from_tag(tag: u8, r: &Reader<'_>) -> Result<Self, DecodeError> {
        match tag {
            0 => Ok(Self::None),
            1 => Ok(Self::Single),
            2 => Ok(Self::Double),
            _ => Err(r.bad_tag("markdown_ir.footing_rule", tag)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkdownRow {
    pub line_code: String,
    pub footing: FootingRule,
    pub cells: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkdownTable {
    pub unit_id: u32,
    pub unit_code: String,
    pub unit_scale: u8,
    pub headers: Vec<String>,
    pub alignments: Vec<ColumnAlignment>,
    pub rows: Vec<MarkdownRow>,
}

/// Certified-ready, deterministic Markdown IR for a financial statement or
/// restatement comparison (`as_originally_reported` vs `as_currently_stated`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementMarkdownIr {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub known_at: u64,
    /// Present when this IR represents a restatement diff (`originally_reported_known_at`).
    pub compared_known_at: Option<u64>,
    pub definition_name: String,
    pub definition_version: u32,
    pub definition_digest: Oid,
    pub tables: Vec<MarkdownTable>,
    pub markdown: String,
}

impl StatementMarkdownIr {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(MARKDOWN_IR_FORMAT)
            .fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u64(self.known_at)
            .opt(self.compared_known_at.as_ref(), |w, seq| {
                w.u64(*seq);
            })
            .str(&self.definition_name)
            .u32(self.definition_version)
            .fixed(&self.definition_digest.0)
            .list(&self.tables, |w, table| {
                w.u32(table.unit_id)
                    .str(&table.unit_code)
                    .u8(table.unit_scale)
                    .list(&table.headers, |w, h| {
                        w.str(h);
                    })
                    .list(&table.alignments, |w, a| {
                        w.u8(a.tag());
                    })
                    .list(&table.rows, |w, row| {
                        w.str(&row.line_code)
                            .u8(row.footing.tag())
                            .list(&row.cells, |w, cell| {
                                w.str(cell);
                            });
                    });
            })
            .str(&self.markdown);
        w.finish()
    }

    pub fn digest(&self) -> Result<Oid, EncodeError> {
        Ok(Oid(domain_digest(
            MARKDOWN_IR_FORMAT,
            &[&self.canonical_bytes()?],
        )))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let magic = r.fixed::<{ MARKDOWN_IR_FORMAT.len() }>("markdown_ir.magic")?;
        if magic != MARKDOWN_IR_FORMAT {
            return Err(r.invalid("statement markdown IR header"));
        }
        let book_id = Id128(r.fixed::<16>("book_id")?);
        let branch_id = Id128(r.fixed::<16>("branch_id")?);
        let known_at = r.u64("known_at")?;
        let compared_known_at =
            r.opt("compared_known_at", |r| r.u64("compared_known_at"))?;
        let definition_name = r.str(64, "definition_name")?.to_string();
        let definition_version = r.u32("definition_version")?;
        let definition_digest = Oid(r.fixed::<32>("definition_digest")?);
        let table_count = r.count(MAX_IR_TABLES, "tables")?;
        let mut tables = Vec::with_capacity(table_count);
        for _ in 0..table_count {
            let unit_id = r.u32("unit_id")?;
            let unit_code = r.str(32, "unit_code")?.to_string();
            let unit_scale = r.u8("unit_scale")?;
            let header_count = r.count(MAX_IR_COLS, "headers")?;
            let mut headers = Vec::with_capacity(header_count);
            for _ in 0..header_count {
                headers.push(r.str(MAX_CELL_BYTES, "header")?.to_string());
            }
            let align_count = r.count(MAX_IR_COLS, "alignments")?;
            let mut alignments = Vec::with_capacity(align_count);
            for _ in 0..align_count {
                let tag = r.u8("alignment")?;
                alignments.push(ColumnAlignment::from_tag(tag, &r)?);
            }
            let row_count = r.count(MAX_IR_ROWS, "rows")?;
            let mut rows = Vec::with_capacity(row_count);
            for _ in 0..row_count {
                let line_code = r.str(64, "line_code")?.to_string();
                let footing_tag = r.u8("footing")?;
                let footing = FootingRule::from_tag(footing_tag, &r)?;
                let cell_count = r.count(MAX_IR_COLS, "cells")?;
                let mut cells = Vec::with_capacity(cell_count);
                for _ in 0..cell_count {
                    cells.push(r.str(MAX_CELL_BYTES, "cell")?.to_string());
                }
                rows.push(MarkdownRow {
                    line_code,
                    footing,
                    cells,
                });
            }
            tables.push(MarkdownTable {
                unit_id,
                unit_code,
                unit_scale,
                headers,
                alignments,
                rows,
            });
        }
        let markdown = r.str(4 * 1024 * 1024, "markdown")?.to_string();
        r.finish()?;
        Ok(Self {
            book_id,
            branch_id,
            known_at,
            compared_known_at,
            definition_name,
            definition_version,
            definition_digest,
            tables,
            markdown,
        })
    }
}

/// Format an exact `i128` mantissa at `scale` decimal places without floats.
pub fn format_scaled_i128(mantissa: i128, scale: u8) -> Result<String, StatementError> {
    if scale > MAX_SCALE {
        return Err(StatementError::Input(format!(
            "unit scale {scale} exceeds maximum supported decimal scale {MAX_SCALE}"
        )));
    }
    let negative = mantissa < 0;
    let abs: u128 = mantissa.unsigned_abs();
    let sign = if negative { "-" } else { "" };
    if scale == 0 {
        return Ok(format!("{sign}{abs}"));
    }
    let divisor = 10u128.pow(u32::from(scale));
    let whole = abs / divisor;
    let frac = abs % divisor;
    let width = usize::from(scale);
    Ok(format!("{sign}{whole}.{frac:0width$}"))
}

fn classify_footing(definition: &StatementDefinition, line_code: &str, source: &LineSource) -> FootingRule {
    if definition.check_lines().contains(&line_code.to_string())
        || matches!(line_code, "total_equity" | "net_income")
    {
        FootingRule::Double
    } else if matches!(source, LineSource::Formula { .. }) {
        FootingRule::Single
    } else {
        FootingRule::None
    }
}

fn render_table_markdown(table: &MarkdownTable) -> String {
    let col_count = table.headers.len();
    let mut widths = vec![3usize; col_count];
    for (idx, h) in table.headers.iter().enumerate() {
        widths[idx] = widths[idx].max(h.chars().count());
    }
    for row in &table.rows {
        for (idx, cell) in row.cells.iter().enumerate() {
            let extra = match (idx >= 2, row.footing) {
                (true, FootingRule::Double) => 4, // `=== ` prefix or suffix marker
                (true, FootingRule::Single) => 2,
                _ => 0,
            };
            widths[idx] = widths[idx].max(cell.chars().count() + extra);
        }
    }

    let mut out = String::new();
    out.push_str(&format!(
        "### Unit: {} (id={}, scale={})\n\n",
        table.unit_code, table.unit_id, table.unit_scale
    ));

    // Header row
    out.push('|');
    for (idx, h) in table.headers.iter().enumerate() {
        let w = widths[idx];
        match table.alignments[idx] {
            ColumnAlignment::Left => out.push_str(&format!(" {h:<w$} |")),
            ColumnAlignment::Right => out.push_str(&format!(" {h:>w$} |")),
        }
    }
    out.push('\n');

    // Alignment rule row
    out.push('|');
    for (idx, align) in table.alignments.iter().enumerate() {
        let w = widths[idx];
        match align {
            ColumnAlignment::Left => {
                out.push(' ');
                out.push(':');
                out.push_str(&"-".repeat(w.saturating_sub(1)));
                out.push_str(" |");
            }
            ColumnAlignment::Right => {
                out.push(' ');
                out.push_str(&"-".repeat(w.saturating_sub(1)));
                out.push(':');
                out.push_str(" |");
            }
        }
    }
    out.push('\n');

    // Data rows with footing indicators
    for row in &table.rows {
        out.push('|');
        for (idx, cell) in row.cells.iter().enumerate() {
            let w = widths[idx];
            let decorated = match (idx >= 2, row.footing) {
                (true, FootingRule::Double) => format!("=={cell}=="),
                (true, FootingRule::Single) => format!("_{cell}_"),
                _ => cell.clone(),
            };
            match table.alignments[idx] {
                ColumnAlignment::Left => out.push_str(&format!(" {decorated:<w$} |")),
                ColumnAlignment::Right => out.push_str(&format!(" {decorated:>w$} |")),
            }
        }
        out.push('\n');
    }
    out
}

fn validate_unit_specs(
    units: &[UnitFormatSpec],
) -> Result<BTreeMap<u32, &UnitFormatSpec>, StatementError> {
    if units.is_empty() {
        return Err(StatementError::Input(
            "Markdown IR requires at least one unit format specification".into(),
        ));
    }
    let mut map = BTreeMap::new();
    for spec in units {
        if spec.code.trim().is_empty() || spec.code.len() > 32 {
            return Err(StatementError::Input(
                "unit format code must be non-empty and at most 32 bytes".into(),
            ));
        }
        if spec.scale > MAX_SCALE {
            return Err(StatementError::Input(format!(
                "unit `{}` scale {} exceeds {MAX_SCALE}",
                spec.code, spec.scale
            )));
        }
        if map.insert(spec.unit_id, spec).is_some() {
            return Err(StatementError::Input(format!(
                "duplicate unit format specification for unit_id {}",
                spec.unit_id
            )));
        }
    }
    Ok(map)
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build the deterministic Markdown IR for a `Statement` (`fa-9ae`, `fa-cet`).
pub fn render_statement_ir(
    statement: &Statement,
    definition: &StatementDefinition,
    units: &[UnitFormatSpec],
) -> Result<StatementMarkdownIr, StatementError> {
    let def_digest = definition.digest()?;
    if statement.definition_digest != def_digest || statement.definition_name != definition.name() {
        return Err(StatementError::Input(
            "statement does not match supplied StatementDefinition".into(),
        ));
    }
    let unit_map = validate_unit_specs(units)?;

    let mut distinct_units: Vec<u32> = statement.lines.iter().map(|l| l.unit_id).collect();
    distinct_units.sort_unstable();
    distinct_units.dedup();

    let mut headers = Vec::with_capacity(2 + statement.columns.len());
    headers.push("Code".to_string());
    headers.push("Line".to_string());
    for col in &statement.columns {
        headers.push(col.label.clone());
    }
    let mut alignments = vec![ColumnAlignment::Left, ColumnAlignment::Left];
    alignments.extend(std::iter::repeat_n(
        ColumnAlignment::Right,
        statement.columns.len(),
    ));

    let mut tables = Vec::with_capacity(distinct_units.len());
    for unit_id in distinct_units {
        let spec = unit_map.get(&unit_id).ok_or_else(|| {
            StatementError::Input(format!(
                "statement uses unit_id {unit_id} missing from UnitFormatSpec list"
            ))
        })?;
        let mut rows = Vec::with_capacity(definition.lines().len());
        for def_line in definition.lines() {
            let stmt_line = statement
                .lines
                .iter()
                .find(|l| l.code == def_line.code && l.unit_id == unit_id)
                .ok_or_else(|| {
                    StatementError::Input(format!(
                        "statement missing line `{}` for unit {unit_id}",
                        def_line.code
                    ))
                })?;
            if stmt_line.amounts.len() != statement.columns.len() {
                return Err(StatementError::Input(
                    "statement line amount count disagrees with column count".into(),
                ));
            }
            let mut cells = Vec::with_capacity(2 + stmt_line.amounts.len());
            cells.push(def_line.code.clone());
            cells.push(def_line.label.clone());
            for &amount in &stmt_line.amounts {
                cells.push(format_scaled_i128(amount, spec.scale)?);
            }
            rows.push(MarkdownRow {
                line_code: def_line.code.clone(),
                footing: classify_footing(definition, &def_line.code, &def_line.source),
                cells,
            });
        }
        tables.push(MarkdownTable {
            unit_id,
            unit_code: spec.code.clone(),
            unit_scale: spec.scale,
            headers: headers.clone(),
            alignments: alignments.clone(),
            rows,
        });
    }

    let mut markdown = format!(
        "# Statement: {} (v{})\n\n- Book: `{}`\n- Branch: `{}`\n- Known-At Sequence: `{}`\n- Definition Digest: `{}`\n\n",
        statement.definition_name,
        statement.definition_version,
        statement.book_id.to_hex(),
        statement.branch_id.to_hex(),
        statement.known_at,
        hex_bytes(&statement.definition_digest),
    );
    for (idx, table) in tables.iter().enumerate() {
        if idx > 0 {
            markdown.push('\n');
        }
        markdown.push_str(&render_table_markdown(table));
    }

    Ok(StatementMarkdownIr {
        book_id: statement.book_id,
        branch_id: statement.branch_id,
        known_at: statement.known_at,
        compared_known_at: None,
        definition_name: statement.definition_name.clone(),
        definition_version: statement.definition_version,
        definition_digest: Oid(statement.definition_digest),
        tables,
        markdown,
    })
}

/// Build a deterministic restatement comparison Markdown IR (`as_originally_reported`
/// vs `as_currently_stated`, plan §12.5, `fa-9ae`, `fa-cet`).
pub fn render_restatement_diff_ir(
    originally_reported: &Statement,
    currently_stated: &Statement,
    definition: &StatementDefinition,
    units: &[UnitFormatSpec],
) -> Result<StatementMarkdownIr, StatementError> {
    if originally_reported.book_id != currently_stated.book_id
        || originally_reported.branch_id != currently_stated.branch_id
    {
        return Err(StatementError::Input(
            "restatement diff requires both statements to belong to the same book and branch"
                .into(),
        ));
    }
    let def_digest = definition.digest()?;
    if originally_reported.definition_digest != def_digest
        || currently_stated.definition_digest != def_digest
    {
        return Err(StatementError::Input(
            "restatement diff requires both statements to share the same StatementDefinition"
                .into(),
        ));
    }
    if originally_reported.known_at > currently_stated.known_at {
        return Err(StatementError::Input(format!(
            "originally_reported known_at ({}) cannot exceed currently_stated known_at ({})",
            originally_reported.known_at, currently_stated.known_at
        )));
    }
    if originally_reported.columns.is_empty() || currently_stated.columns.is_empty() {
        return Err(StatementError::Input(
            "restatement diff requires non-empty primary columns".into(),
        ));
    }
    if originally_reported.columns[0].periods != currently_stated.columns[0].periods {
        return Err(StatementError::Input(
            "restatement diff primary columns must cover the same period set".into(),
        ));
    }

    let unit_map = validate_unit_specs(units)?;
    let mut distinct_units: Vec<u32> = currently_stated.lines.iter().map(|l| l.unit_id).collect();
    distinct_units.sort_unstable();
    distinct_units.dedup();

    let headers = vec![
        "Code".to_string(),
        "Line".to_string(),
        format!("As Originally Reported (seq {})", originally_reported.known_at),
        format!("As Currently Stated (seq {})", currently_stated.known_at),
        "Restatement Delta".to_string(),
    ];
    let alignments = vec![
        ColumnAlignment::Left,
        ColumnAlignment::Left,
        ColumnAlignment::Right,
        ColumnAlignment::Right,
        ColumnAlignment::Right,
    ];

    let mut tables = Vec::with_capacity(distinct_units.len());
    for unit_id in distinct_units {
        let spec = unit_map.get(&unit_id).ok_or_else(|| {
            StatementError::Input(format!(
                "statement uses unit_id {unit_id} missing from UnitFormatSpec list"
            ))
        })?;
        let mut rows = Vec::with_capacity(definition.lines().len());
        for def_line in definition.lines() {
            let orig_amt = originally_reported
                .lines
                .iter()
                .find(|l| l.code == def_line.code && l.unit_id == unit_id)
                .map(|l| l.amounts[0])
                .ok_or_else(|| {
                    StatementError::Input(format!(
                        "originally_reported missing line `{}` in unit {unit_id}",
                        def_line.code
                    ))
                })?;
            let curr_amt = currently_stated
                .lines
                .iter()
                .find(|l| l.code == def_line.code && l.unit_id == unit_id)
                .map(|l| l.amounts[0])
                .ok_or_else(|| {
                    StatementError::Input(format!(
                        "currently_stated missing line `{}` in unit {unit_id}",
                        def_line.code
                    ))
                })?;
            let delta = curr_amt.checked_sub(orig_amt).ok_or(StatementError::Overflow {
                line: def_line.code.clone(),
                column: "Restatement Delta".into(),
                unit_id,
            })?;
            rows.push(MarkdownRow {
                line_code: def_line.code.clone(),
                footing: classify_footing(definition, &def_line.code, &def_line.source),
                cells: vec![
                    def_line.code.clone(),
                    def_line.label.clone(),
                    format_scaled_i128(orig_amt, spec.scale)?,
                    format_scaled_i128(curr_amt, spec.scale)?,
                    format_scaled_i128(delta, spec.scale)?,
                ],
            });
        }
        tables.push(MarkdownTable {
            unit_id,
            unit_code: spec.code.clone(),
            unit_scale: spec.scale,
            headers: headers.clone(),
            alignments: alignments.clone(),
            rows,
        });
    }

    let mut markdown = format!(
        "# Restatement Diff: {} (v{})\n\n- Book: `{}`\n- Branch: `{}`\n- Originally Reported Sequence: `{}`\n- Currently Stated Sequence: `{}`\n- Definition Digest: `{}`\n\n",
        currently_stated.definition_name,
        currently_stated.definition_version,
        currently_stated.book_id.to_hex(),
        currently_stated.branch_id.to_hex(),
        originally_reported.known_at,
        currently_stated.known_at,
        hex_bytes(&currently_stated.definition_digest),
    );
    for (idx, table) in tables.iter().enumerate() {
        if idx > 0 {
            markdown.push('\n');
        }
        markdown.push_str(&render_table_markdown(table));
    }

    Ok(StatementMarkdownIr {
        book_id: currently_stated.book_id,
        branch_id: currently_stated.branch_id,
        known_at: currently_stated.known_at,
        compared_known_at: Some(originally_reported.known_at),
        definition_name: currently_stated.definition_name.clone(),
        definition_version: currently_stated.definition_version,
        definition_digest: Oid(currently_stated.definition_digest),
        tables,
        markdown,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Account, AccountBalance, ColumnInput, StatementInput, evaluate};
    use fa_time::DateDay;

    fn sample_statement(known_at: u64, revenue_cents: i128, expense_cents: i128) -> (StatementDefinition, Statement) {
        let def = StatementDefinition::embedded("balance-sheet").unwrap();
        let net_cash = 100_000 + revenue_cents - expense_cents;
        let input = StatementInput {
            book_id: Id128([0x44; 16]),
            branch_id: Id128::TRUNK,
            known_at,
            accounts: vec![
                Account {
                    id: 1,
                    code: "1000".into(),
                    name: "Cash".into(),
                    account_type: 1,
                    is_leaf: true,
                },
                Account {
                    id: 2,
                    code: "2000".into(),
                    name: "Payables".into(),
                    account_type: 2,
                    is_leaf: true,
                },
                Account {
                    id: 3,
                    code: "3000".into(),
                    name: "Equity".into(),
                    account_type: 3,
                    is_leaf: true,
                },
                Account {
                    id: 4,
                    code: "4000".into(),
                    name: "Revenue".into(),
                    account_type: 4,
                    is_leaf: true,
                },
                Account {
                    id: 5,
                    code: "5000".into(),
                    name: "Expense".into(),
                    account_type: 5,
                    is_leaf: true,
                },
            ],
            units: vec![1],
            columns: vec![ColumnInput {
                label: "FY2026-P03".into(),
                periods: vec!["FY2026-P03".into()],
                effective_from: None,
                effective_through: DateDay(90),
                balances: vec![
                    AccountBalance {
                        account_id: 1,
                        unit_id: 1,
                        debits: net_cash,
                        credits: 0,
                    },
                    AccountBalance {
                        account_id: 3,
                        unit_id: 1,
                        debits: 0,
                        credits: 100_000,
                    },
                    AccountBalance {
                        account_id: 4,
                        unit_id: 1,
                        debits: 0,
                        credits: revenue_cents,
                    },
                    AccountBalance {
                        account_id: 5,
                        unit_id: 1,
                        debits: expense_cents,
                        credits: 0,
                    },
                ],
            }],
        };
        let stmt = evaluate(&def, &input).unwrap();
        (def, stmt)
    }

    #[test]
    fn statement_and_restatement_markdown_ir_are_deterministic_and_round_trip() {
        let (def, orig) = sample_statement(10, 50_025, 12_005);
        let (_, restated) = sample_statement(25, 50_025, 18_505); // +65.00 expense restatement
        let units = vec![UnitFormatSpec {
            unit_id: 1,
            code: "USD".into(),
            scale: 2,
        }];

        let ir = render_statement_ir(&orig, &def, &units).unwrap();
        assert!(ir.markdown.contains("==1380.20=="));
        assert!(ir.markdown.contains("_380.20_"));
        assert_eq!(ir.tables[0].rows[6].footing, FootingRule::Double);
        let encoded = ir.canonical_bytes().unwrap();
        let decoded = StatementMarkdownIr::decode(&encoded).unwrap();
        assert_eq!(ir, decoded);
        assert_eq!(ir.digest().unwrap(), decoded.digest().unwrap());

        let diff_ir = render_restatement_diff_ir(&orig, &restated, &def, &units).unwrap();
        assert_eq!(diff_ir.compared_known_at, Some(10));
        assert_eq!(diff_ir.known_at, 25);
        // Unclosed earnings changed from 380.20 to 315.20 -> delta = -65.00
        let earnings_row = diff_ir.tables[0]
            .rows
            .iter()
            .find(|r| r.line_code == "unclosed_earnings")
            .unwrap();
        assert_eq!(
            earnings_row.cells,
            vec![
                "unclosed_earnings",
                "Unclosed earnings, all years",
                "380.20",
                "315.20",
                "-65.00"
            ]
        );
        let diff_bytes = diff_ir.canonical_bytes().unwrap();
        assert_eq!(StatementMarkdownIr::decode(&diff_bytes).unwrap(), diff_ir);
    }

    #[test]
    fn exact_scaled_formatting_handles_i128_extremes_and_refuses_invalid_scale() {
        assert_eq!(format_scaled_i128(0, 2).unwrap(), "0.00");
        assert_eq!(format_scaled_i128(-5, 2).unwrap(), "-0.05");
        assert_eq!(format_scaled_i128(123_456, 4).unwrap(), "12.3456");
        assert_eq!(
            format_scaled_i128(i128::MIN, 2).unwrap(),
            "-1701411834604692317316873037158841057.28"
        );
        assert!(format_scaled_i128(100, 39).is_err());
    }
}
