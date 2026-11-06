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
    /// Present the already rounded values, including their explicit residuals,
    /// through the same document renderers as the exact statement. Unit scales
    /// remain the registered native scales; each table declares the display
    /// units and law. This display adapter does not certify rounded amounts.
    pub fn with_presentation(
        mut self,
        presentations: &[crate::custom::PresentedStatement],
    ) -> Result<Self, StatementError> {
        if self.compared_known_at.is_some() || presentations.len() != self.tables.len() {
            return Err(StatementError::Input(
                "presentation requires one rounded block per exact statement unit".into(),
            ));
        }
        for (table, presented) in self.tables.iter_mut().zip(presentations) {
            if presented.book_id != self.book_id
                || presented.branch_id != self.branch_id
                || presented.known_at != self.known_at
                || presented.definition_name != self.definition_name
                || presented.definition_version != self.definition_version
                || presented.definition_digest != self.definition_digest
                || presented.columns.len().checked_add(2) != Some(table.headers.len())
                || presented
                    .columns
                    .iter()
                    .zip(table.headers.iter().skip(2))
                    .any(|(column, header)| {
                        column_header(&column.label, &column.periods) != *header
                    })
                || presented
                    .lines
                    .iter()
                    .any(|line| line.unit_id != table.unit_id)
                || presented.divisor
                    != 10_i128
                        .checked_pow(u32::from(presented.scale_reduction_digits))
                        .ok_or_else(|| {
                            StatementError::Input("presentation divisor overflow".into())
                        })?
            {
                return Err(StatementError::Input(
                    "rounded presentation does not match the exact statement IR".into(),
                ));
            }
            let source_rows: BTreeMap<_, _> = table
                .rows
                .iter()
                .map(|row| (row.line_code.as_str(), row))
                .collect();
            if source_rows.len() != table.rows.len() {
                return Err(StatementError::Input(
                    "exact statement IR repeats a row code".into(),
                ));
            }
            let mut rows = Vec::with_capacity(presented.lines.len());
            let mut codes = std::collections::BTreeSet::new();
            for line in &presented.lines {
                if line.presented_amounts.len() != presented.columns.len()
                    || line.exact_amounts.len() != presented.columns.len()
                    || line.rounding_errors.len() != presented.columns.len()
                {
                    return Err(StatementError::Input(
                        "rounded presentation line disagrees with column count".into(),
                    ));
                }
                if !codes.insert(line.code.as_str())
                    || (line.is_residual_line && source_rows.contains_key(line.code.as_str()))
                {
                    return Err(StatementError::Input(
                        "presentation row codes collide".into(),
                    ));
                }
                let footing = if line.is_residual_line {
                    FootingRule::None
                } else {
                    let source = source_rows.get(line.code.as_str()).ok_or_else(|| {
                        StatementError::Input(
                            "rounded line is absent from the exact statement".into(),
                        )
                    })?;
                    let exact = line
                        .exact_amounts
                        .iter()
                        .map(|amount| format_scaled_i128(*amount, table.unit_scale))
                        .collect::<Result<Vec<_>, _>>()?;
                    if source.cells.get(2..) != Some(exact.as_slice()) {
                        return Err(StatementError::Input(
                            "rounded presentation changes or repeats an exact statement line"
                                .into(),
                        ));
                    }
                    source.footing
                };
                let mut cells = vec![line.code.clone(), line.label.clone()];
                cells.extend(line.presented_amounts.iter().map(i128::to_string));
                rows.push(MarkdownRow {
                    line_code: line.code.clone(),
                    footing,
                    cells,
                });
            }
            if presented
                .lines
                .iter()
                .filter(|line| !line.is_residual_line)
                .count()
                != source_rows.len()
            {
                return Err(StatementError::Input(
                    "rounded presentation omits an exact statement line".into(),
                ));
            }
            let extra_digits = presented
                .scale_reduction_digits
                .checked_sub(table.unit_scale)
                .ok_or_else(|| {
                    StatementError::Input(
                        "document presentation must use whole native units or a larger scale"
                            .into(),
                    )
                })?;
            let scale = match extra_digits {
                0 => "units".to_string(),
                3 => "thousands".to_string(),
                6 => "millions".to_string(),
                digits => format!("10^{digits} units"),
            };
            let metadata_code = |prefix: &str| -> Result<String, StatementError> {
                if !codes.contains(prefix) {
                    Ok(prefix.to_string())
                } else {
                    (0..=codes.len())
                        .map(|index| format!("{prefix}_{index}"))
                        .find(|code| !codes.contains(code.as_str()))
                        .ok_or_else(|| {
                            StatementError::Input("no distinct presentation row code".into())
                        })
                }
            };
            for (index, (code, label)) in [
                (
                    metadata_code("presentation")?,
                    format!(
                        "{} {}; {:?}",
                        table.unit_code, scale, presented.rounding_law
                    ),
                ),
                (
                    metadata_code("presentation_scope")?,
                    "Display only; cert exact".to_string(),
                ),
            ]
            .into_iter()
            .enumerate()
            {
                let mut cells = vec![code.clone(), label];
                cells.extend(std::iter::repeat_n(String::new(), presented.columns.len()));
                rows.insert(
                    index,
                    MarkdownRow {
                        line_code: code,
                        footing: FootingRule::None,
                        cells,
                    },
                );
            }
            table.rows = rows;
        }
        self.markdown = format!(
            "# Statement: {} (v{})\n\n- Book: `{}`\n- Branch: `{}`\n- Known-At Sequence: `{}`\n- Definition Digest: `{}`\n- Presentation: rounded display values; accounting certificates bind the exact statement amounts. Each table names the display units and registered rounding law.\n\n",
            self.definition_name,
            self.definition_version,
            self.book_id.to_hex(),
            self.branch_id.to_hex(),
            self.known_at,
            hex_bytes(&self.definition_digest.0),
        );
        for table in &self.tables {
            self.markdown.push_str(&render_table_markdown(table));
            self.markdown.push('\n');
        }
        Ok(self)
    }

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
        let compared_known_at = r.opt("compared_known_at", |r| r.u64("compared_known_at"))?;
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
    let (whole, frac) = abs
        .checked_div(divisor)
        .zip(abs.checked_rem(divisor))
        .ok_or_else(|| StatementError::Input(format!("unit scale {scale} has no divisor")))?;
    let width = usize::from(scale);
    Ok(format!("{sign}{whole}.{frac:0width$}"))
}

fn classify_footing(
    definition: &StatementDefinition,
    line_code: &str,
    source: &LineSource,
) -> FootingRule {
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

/// A cell as table data: an account name may hold `|` or a line break,
/// which would otherwise split the row and shift every later amount under
/// another column's header. A backslash is escaped too, so a name's own
/// `\|` cannot reopen the delimiter.
fn table_cell(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            '\n' | '\r' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

fn render_table_markdown(table: &MarkdownTable) -> String {
    let col_count = table.headers.len();
    let mut widths = vec![3usize; col_count];
    for (idx, h) in table.headers.iter().enumerate() {
        widths[idx] = widths[idx].max(h.chars().count());
    }
    let rows: Vec<Vec<String>> = table
        .rows
        .iter()
        .map(|row| row.cells.iter().map(|cell| table_cell(cell)).collect())
        .collect();
    for (row, cells) in table.rows.iter().zip(&rows) {
        for (idx, cell) in cells.iter().enumerate() {
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
    for (row, cells) in table.rows.iter().zip(&rows) {
        out.push('|');
        for (idx, cell) in cells.iter().enumerate() {
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

/// Generic labels such as `current` must not hide a report's named periods.
/// A caller already using the exact period list as its label keeps its bytes.
fn column_header(label: &str, periods: &[String]) -> String {
    let scope = periods.join(", ");
    if scope.is_empty() || scope == label {
        label.to_string()
    } else {
        format!("{label} ({scope})")
    }
}

/// Build the deterministic Markdown IR for a `Statement` (`fa-9ae`, `fa-cet`).
pub fn render_statement_ir(
    statement: &Statement,
    definition: &StatementDefinition,
    units: &[UnitFormatSpec],
) -> Result<StatementMarkdownIr, StatementError> {
    let def_digest = definition.digest()?;
    if statement.definition_digest != def_digest
        || statement.definition_name != definition.name()
        || statement.definition_version != definition.version()
    {
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
        headers.push(column_header(&col.label, &col.periods));
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
        || originally_reported.definition_name != definition.name()
        || currently_stated.definition_name != definition.name()
        || originally_reported.definition_version != definition.version()
        || currently_stated.definition_version != definition.version()
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
    if originally_reported.columns[0].effective_from != currently_stated.columns[0].effective_from
        || originally_reported.columns[0].effective_through
            != currently_stated.columns[0].effective_through
    {
        return Err(StatementError::Input(
            "restatement diff primary columns must cover the same effective bounds".into(),
        ));
    }

    let unit_map = validate_unit_specs(units)?;
    let mut distinct_units: Vec<u32> = currently_stated.lines.iter().map(|l| l.unit_id).collect();
    distinct_units.sort_unstable();
    distinct_units.dedup();

    let headers = vec![
        "Code".to_string(),
        "Line".to_string(),
        column_header(
            &format!(
                "As Originally Reported (seq {})",
                originally_reported.known_at
            ),
            &originally_reported.columns[0].periods,
        ),
        column_header(
            &format!("As Currently Stated (seq {})", currently_stated.known_at),
            &currently_stated.columns[0].periods,
        ),
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
                .and_then(|line| line.amounts.first().copied())
                .ok_or_else(|| {
                    StatementError::Input(format!(
                        "originally_reported missing primary amount for line `{}` in unit {unit_id}",
                        def_line.code
                    ))
                })?;
            let curr_amt = currently_stated
                .lines
                .iter()
                .find(|l| l.code == def_line.code && l.unit_id == unit_id)
                .and_then(|line| line.amounts.first().copied())
                .ok_or_else(|| {
                    StatementError::Input(format!(
                        "currently_stated missing primary amount for line `{}` in unit {unit_id}",
                        def_line.code
                    ))
                })?;
            let delta = curr_amt
                .checked_sub(orig_amt)
                .ok_or(StatementError::Overflow {
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

/// One account row in a Trial Balance or Period Activity fold (`fa-cet`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrialBalanceIrRow {
    pub account_code: String,
    pub account_name: String,
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
}

/// Input fold for building a deterministic Trial Balance or Period Activity Markdown IR (`fa-cet`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrialBalanceIrInput {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub known_at: u64,
    pub effective_label: String,
    pub activity_only: bool,
    pub rows: Vec<TrialBalanceIrRow>,
}

/// Build a deterministic Markdown IR for a Trial Balance or Period Activity fold (`fa-cet`).
pub fn render_trial_balance_ir(
    input: &TrialBalanceIrInput,
    units: &[UnitFormatSpec],
) -> Result<StatementMarkdownIr, StatementError> {
    let unit_map = validate_unit_specs(units)?;
    let mut distinct_units: Vec<u32> = input.rows.iter().map(|r| r.unit_id).collect();
    distinct_units.sort_unstable();
    distinct_units.dedup();
    if distinct_units.is_empty() {
        let first = units.first().ok_or_else(|| {
            StatementError::Input(
                "a trial balance without rows needs one unit to present its empty table".into(),
            )
        })?;
        distinct_units.push(first.unit_id);
    }

    let definition_name = if input.activity_only {
        "period-activity".to_string()
    } else {
        "trial-balance".to_string()
    };
    let definition_digest = Oid(domain_digest(
        b"fa:markdown-ir-def:v1",
        &[definition_name.as_bytes(), input.effective_label.as_bytes()],
    ));

    let headers = vec![
        "Account".to_string(),
        "Name".to_string(),
        "Debits".to_string(),
        "Credits".to_string(),
        "Net (Dr - Cr)".to_string(),
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
                "trial balance uses unit_id {unit_id} missing from UnitFormatSpec list"
            ))
        })?;
        let mut unit_rows: Vec<&TrialBalanceIrRow> =
            input.rows.iter().filter(|r| r.unit_id == unit_id).collect();
        unit_rows.sort_by(|a, b| a.account_code.cmp(&b.account_code));

        let mut rows = Vec::with_capacity(unit_rows.len() + 1);
        let mut total_debits: i128 = 0;
        let mut total_credits: i128 = 0;

        for r in unit_rows {
            total_debits =
                total_debits
                    .checked_add(r.debits)
                    .ok_or_else(|| StatementError::Overflow {
                        line: r.account_code.clone(),
                        column: "Debits".into(),
                        unit_id,
                    })?;
            total_credits =
                total_credits
                    .checked_add(r.credits)
                    .ok_or_else(|| StatementError::Overflow {
                        line: r.account_code.clone(),
                        column: "Credits".into(),
                        unit_id,
                    })?;
            let net = r
                .debits
                .checked_sub(r.credits)
                .ok_or_else(|| StatementError::Overflow {
                    line: r.account_code.clone(),
                    column: "Net (Dr - Cr)".into(),
                    unit_id,
                })?;
            rows.push(MarkdownRow {
                line_code: r.account_code.clone(),
                footing: FootingRule::None,
                cells: vec![
                    r.account_code.clone(),
                    r.account_name.clone(),
                    format_scaled_i128(r.debits, spec.scale)?,
                    format_scaled_i128(r.credits, spec.scale)?,
                    format_scaled_i128(net, spec.scale)?,
                ],
            });
        }

        let total_net =
            total_debits
                .checked_sub(total_credits)
                .ok_or_else(|| StatementError::Overflow {
                    line: "total_trial_balance".into(),
                    column: "Net (Dr - Cr)".into(),
                    unit_id,
                })?;
        rows.push(MarkdownRow {
            line_code: "total_trial_balance".to_string(),
            footing: FootingRule::Double,
            cells: vec![
                "TOTAL".to_string(),
                "Trial Balance Total".to_string(),
                format_scaled_i128(total_debits, spec.scale)?,
                format_scaled_i128(total_credits, spec.scale)?,
                format_scaled_i128(total_net, spec.scale)?,
            ],
        });

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
        "# Statement: {} (v1)\n\n- Book: `{}`\n- Branch: `{}`\n- Known-At Sequence: `{}`\n- Effective: `{}`\n- Definition Digest: `{}`\n\n",
        definition_name,
        input.book_id.to_hex(),
        input.branch_id.to_hex(),
        input.known_at,
        input.effective_label,
        hex_bytes(&definition_digest.0),
    );
    for (idx, table) in tables.iter().enumerate() {
        if idx > 0 {
            markdown.push('\n');
        }
        markdown.push_str(&render_table_markdown(table));
    }

    Ok(StatementMarkdownIr {
        book_id: input.book_id,
        branch_id: input.branch_id,
        known_at: input.known_at,
        compared_known_at: None,
        definition_name,
        definition_version: 1,
        definition_digest,
        tables,
        markdown,
    })
}

/// One posting leg in an Account Register fold (`fa-cet`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterIrRow {
    pub recorded_at: u64,
    pub effective_date: String,
    pub entry_vid_hex: String,
    pub description: String,
    pub debit: i128,
    pub credit: i128,
}

/// Input fold for building a deterministic Account Register Markdown IR (`fa-cet`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterIrInput {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub known_at: u64,
    pub account_code: String,
    pub account_name: String,
    pub unit_id: u32,
    pub opening_balance: i128,
    pub rows: Vec<RegisterIrRow>,
}

/// Build a deterministic Markdown IR for an Account Register fold (`fa-cet`).
pub fn render_register_ir(
    input: &RegisterIrInput,
    units: &[UnitFormatSpec],
) -> Result<StatementMarkdownIr, StatementError> {
    let unit_map = validate_unit_specs(units)?;
    let spec = unit_map.get(&input.unit_id).ok_or_else(|| {
        StatementError::Input(format!(
            "register uses unit_id {} missing from UnitFormatSpec list",
            input.unit_id
        ))
    })?;

    let definition_name = format!("register:{}", input.account_code);
    let definition_digest = Oid(domain_digest(
        b"fa:markdown-ir-def:v1",
        &[definition_name.as_bytes(), input.account_name.as_bytes()],
    ));

    let headers = vec![
        "Entry / Date".to_string(),
        "Description".to_string(),
        "Debit".to_string(),
        "Credit".to_string(),
        "Running Balance".to_string(),
    ];
    let alignments = vec![
        ColumnAlignment::Left,
        ColumnAlignment::Left,
        ColumnAlignment::Right,
        ColumnAlignment::Right,
        ColumnAlignment::Right,
    ];

    let mut rows = Vec::with_capacity(input.rows.len() + 2);
    let mut running = input.opening_balance;
    rows.push(MarkdownRow {
        line_code: "opening_balance".to_string(),
        footing: FootingRule::Single,
        cells: vec![
            "OPENING".to_string(),
            format!("Opening balance ({})", input.account_name),
            format_scaled_i128(0, spec.scale)?,
            format_scaled_i128(0, spec.scale)?,
            format_scaled_i128(running, spec.scale)?,
        ],
    });

    let mut total_debits: i128 = 0;
    let mut total_credits: i128 = 0;
    for (idx, r) in input.rows.iter().enumerate() {
        total_debits =
            total_debits
                .checked_add(r.debit)
                .ok_or_else(|| StatementError::Overflow {
                    line: format!("row_{idx}"),
                    column: "Debit".into(),
                    unit_id: input.unit_id,
                })?;
        total_credits =
            total_credits
                .checked_add(r.credit)
                .ok_or_else(|| StatementError::Overflow {
                    line: format!("row_{idx}"),
                    column: "Credit".into(),
                    unit_id: input.unit_id,
                })?;
        let delta = r
            .debit
            .checked_sub(r.credit)
            .ok_or_else(|| StatementError::Overflow {
                line: format!("row_{idx}"),
                column: "Running Balance".into(),
                unit_id: input.unit_id,
            })?;
        running = running
            .checked_add(delta)
            .ok_or_else(|| StatementError::Overflow {
                line: format!("row_{idx}"),
                column: "Running Balance".into(),
                unit_id: input.unit_id,
            })?;
        rows.push(MarkdownRow {
            line_code: format!("leg_{}_{}", r.recorded_at, idx),
            footing: FootingRule::None,
            cells: vec![
                format!("{} (seq {})", r.effective_date, r.recorded_at),
                format!("{} [{}]", r.description, r.entry_vid_hex),
                format_scaled_i128(r.debit, spec.scale)?,
                format_scaled_i128(r.credit, spec.scale)?,
                format_scaled_i128(running, spec.scale)?,
            ],
        });
    }

    rows.push(MarkdownRow {
        line_code: "closing_balance".to_string(),
        footing: FootingRule::Double,
        cells: vec![
            "CLOSING".to_string(),
            format!("Closing balance ({})", input.account_name),
            format_scaled_i128(total_debits, spec.scale)?,
            format_scaled_i128(total_credits, spec.scale)?,
            format_scaled_i128(running, spec.scale)?,
        ],
    });

    let table = MarkdownTable {
        unit_id: input.unit_id,
        unit_code: spec.code.clone(),
        unit_scale: spec.scale,
        headers,
        alignments,
        rows,
    };
    let markdown = format!(
        "# Statement: {} (v1)\n\n- Book: `{}`\n- Branch: `{}`\n- Known-At Sequence: `{}`\n- Account: `{} ({})`\n- Definition Digest: `{}`\n\n{}",
        definition_name,
        input.book_id.to_hex(),
        input.branch_id.to_hex(),
        input.known_at,
        input.account_code,
        input.account_name,
        hex_bytes(&definition_digest.0),
        render_table_markdown(&table),
    );

    Ok(StatementMarkdownIr {
        book_id: input.book_id,
        branch_id: input.branch_id,
        known_at: input.known_at,
        compared_known_at: None,
        definition_name,
        definition_version: 1,
        definition_digest,
        tables: vec![table],
        markdown,
    })
}

/// One open item in an Open Items fold (`fa-cet`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenItemIrRow {
    pub item_vid_hex: String,
    pub effective_date: String,
    pub counterparty_or_memo: String,
    pub original_amount: i128,
    pub settled_amount: i128,
    pub open_amount: i128,
}

/// Input fold for building a deterministic Open Items Markdown IR (`fa-cet`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenItemsIrInput {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub known_at: u64,
    pub account_code: String,
    pub account_name: String,
    pub unit_id: u32,
    pub items: Vec<OpenItemIrRow>,
}

/// Build a deterministic Markdown IR for an Open Items fold (`fa-cet`).
pub fn render_open_items_ir(
    input: &OpenItemsIrInput,
    units: &[UnitFormatSpec],
) -> Result<StatementMarkdownIr, StatementError> {
    let unit_map = validate_unit_specs(units)?;
    let spec = unit_map.get(&input.unit_id).ok_or_else(|| {
        StatementError::Input(format!(
            "open items uses unit_id {} missing from UnitFormatSpec list",
            input.unit_id
        ))
    })?;

    let definition_name = format!("open-items:{}", input.account_code);
    let definition_digest = Oid(domain_digest(
        b"fa:markdown-ir-def:v1",
        &[definition_name.as_bytes(), input.account_name.as_bytes()],
    ));

    let headers = vec![
        "Item / Date".to_string(),
        "Counterparty / Memo".to_string(),
        "Original".to_string(),
        "Settled".to_string(),
        "Open Balance".to_string(),
    ];
    let alignments = vec![
        ColumnAlignment::Left,
        ColumnAlignment::Left,
        ColumnAlignment::Right,
        ColumnAlignment::Right,
        ColumnAlignment::Right,
    ];

    let mut rows = Vec::with_capacity(input.items.len() + 1);
    let mut total_orig: i128 = 0;
    let mut total_settled: i128 = 0;
    let mut total_open: i128 = 0;

    for (idx, item) in input.items.iter().enumerate() {
        let expected_open = item
            .original_amount
            .checked_sub(item.settled_amount)
            .ok_or_else(|| StatementError::Overflow {
                line: item.item_vid_hex.clone(),
                column: "Open Balance".into(),
                unit_id: input.unit_id,
            })?;
        if expected_open != item.open_amount {
            return Err(StatementError::Input(format!(
                "open item `{}` open_amount ({}) != original ({}) - settled ({})",
                item.item_vid_hex, item.open_amount, item.original_amount, item.settled_amount
            )));
        }
        total_orig = total_orig
            .checked_add(item.original_amount)
            .ok_or_else(|| StatementError::Overflow {
                line: item.item_vid_hex.clone(),
                column: "Original".into(),
                unit_id: input.unit_id,
            })?;
        total_settled = total_settled
            .checked_add(item.settled_amount)
            .ok_or_else(|| StatementError::Overflow {
                line: item.item_vid_hex.clone(),
                column: "Settled".into(),
                unit_id: input.unit_id,
            })?;
        total_open =
            total_open
                .checked_add(item.open_amount)
                .ok_or_else(|| StatementError::Overflow {
                    line: item.item_vid_hex.clone(),
                    column: "Open Balance".into(),
                    unit_id: input.unit_id,
                })?;
        rows.push(MarkdownRow {
            line_code: format!("item_{idx}_{}", item.item_vid_hex),
            footing: FootingRule::None,
            cells: vec![
                format!("{} ({})", item.effective_date, item.item_vid_hex),
                item.counterparty_or_memo.clone(),
                format_scaled_i128(item.original_amount, spec.scale)?,
                format_scaled_i128(item.settled_amount, spec.scale)?,
                format_scaled_i128(item.open_amount, spec.scale)?,
            ],
        });
    }

    rows.push(MarkdownRow {
        line_code: "total_open_items".to_string(),
        footing: FootingRule::Double,
        cells: vec![
            "TOTAL".to_string(),
            format!("Total Open Items ({})", input.account_code),
            format_scaled_i128(total_orig, spec.scale)?,
            format_scaled_i128(total_settled, spec.scale)?,
            format_scaled_i128(total_open, spec.scale)?,
        ],
    });

    let table = MarkdownTable {
        unit_id: input.unit_id,
        unit_code: spec.code.clone(),
        unit_scale: spec.scale,
        headers,
        alignments,
        rows,
    };
    let markdown = format!(
        "# Statement: {} (v1)\n\n- Book: `{}`\n- Branch: `{}`\n- Known-At Sequence: `{}`\n- Account: `{} ({})`\n- Definition Digest: `{}`\n\n{}",
        definition_name,
        input.book_id.to_hex(),
        input.branch_id.to_hex(),
        input.known_at,
        input.account_code,
        input.account_name,
        hex_bytes(&definition_digest.0),
        render_table_markdown(&table),
    );

    Ok(StatementMarkdownIr {
        book_id: input.book_id,
        branch_id: input.branch_id,
        known_at: input.known_at,
        compared_known_at: None,
        definition_name,
        definition_version: 1,
        definition_digest,
        tables: vec![table],
        markdown,
    })
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)] // fixtures with small literal amounts
mod tests {
    use super::*;
    use crate::{Account, AccountBalance, ColumnInput, StatementInput, evaluate};
    use fa_time::DateDay;

    fn sample_statement(
        known_at: u64,
        revenue_cents: i128,
        expense_cents: i128,
    ) -> (StatementDefinition, Statement) {
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
    fn generic_column_headers_disclose_periods_and_keep_rounded_scope() {
        use crate::custom::{
            CustomStatementDefinition, PresentationRoundingSpec, apply_presentation_rounding,
        };
        use fa_money::RoundingLaw;

        let (definition, mut statement) = sample_statement(10, 19_060, 3_540);
        statement.columns[0].label = "current".into();
        let source_bytes = statement.canonical_bytes().unwrap();
        let units = [UnitFormatSpec {
            unit_id: 1,
            code: "USD".into(),
            scale: 2,
        }];
        let exact = render_statement_ir(&statement, &definition, &units).unwrap();
        assert_eq!(exact.tables[0].headers[2], "current (FY2026-P03)");
        assert!(exact.markdown.contains("current (FY2026-P03)"));
        let mut other = statement.clone();
        other.columns[0].periods = vec!["FY2026-P02".into()];
        let other_ir = render_statement_ir(&other, &definition, &units).unwrap();
        assert_eq!(other_ir.tables[0].headers[2], "current (FY2026-P02)");
        assert_ne!(exact.digest().unwrap(), other_ir.digest().unwrap());
        assert_eq!(exact.tables[0].rows, other_ir.tables[0].rows);

        let presented = apply_presentation_rounding(
            &statement,
            &CustomStatementDefinition::from_builtin(&definition),
            &PresentationRoundingSpec {
                rounding_law: RoundingLaw::HalfEven,
                scale_reduction_digits: 2,
                residual_line_code: "presentation_rounding".into(),
                residual_line_label: "Presentation rounding".into(),
            },
        )
        .unwrap();
        let rounded = exact
            .clone()
            .with_presentation(std::slice::from_ref(&presented))
            .unwrap();
        assert_eq!(rounded.tables[0].headers, exact.tables[0].headers);
        let mut wrong = presented;
        wrong.columns[0].periods = vec!["FY2026-P02".into()];
        assert!(exact.with_presentation(&[wrong]).is_err());
        assert_eq!(statement.canonical_bytes().unwrap(), source_bytes);
    }

    #[test]
    fn statement_ir_refuses_contradictory_definition_identity() {
        let (definition, statement) = sample_statement(10, 19_060, 3_540);
        let units = [UnitFormatSpec {
            unit_id: 1,
            code: "USD".into(),
            scale: 2,
        }];
        let valid = render_statement_ir(&statement, &definition, &units).unwrap();
        assert_eq!(valid.definition_name, definition.name());
        assert_eq!(valid.definition_version, definition.version());
        assert_eq!(valid.definition_digest.0, definition.digest().unwrap());

        for field in ["name", "version", "digest"] {
            let mut changed = statement.clone();
            match field {
                "name" => changed.definition_name = "unrelated-statement".into(),
                "version" => changed.definition_version = 0,
                "digest" => changed.definition_digest = [0; 32],
                _ => unreachable!(),
            }
            let error = render_statement_ir(&changed, &definition, &units).unwrap_err();
            assert!(
                error.to_string().contains("StatementDefinition"),
                "{field}: {error}"
            );
        }
    }

    #[test]
    fn restatement_ir_refuses_contradictory_definition_identity_on_either_side() {
        let (definition, original) = sample_statement(10, 19_060, 3_540);
        let (_, restated) = sample_statement(25, 19_060, 4_000);
        let units = [UnitFormatSpec {
            unit_id: 1,
            code: "USD".into(),
            scale: 2,
        }];
        let valid = render_restatement_diff_ir(&original, &restated, &definition, &units).unwrap();
        assert_eq!(valid.definition_name, definition.name());
        assert_eq!(valid.definition_version, definition.version());
        assert_eq!(valid.definition_digest.0, definition.digest().unwrap());

        for change_original in [false, true] {
            for field in ["name", "version", "digest"] {
                let mut before = original.clone();
                let mut after = restated.clone();
                let changed = if change_original {
                    &mut before
                } else {
                    &mut after
                };
                match field {
                    "name" => changed.definition_name = "unrelated-statement".into(),
                    "version" => changed.definition_version = 0,
                    "digest" => changed.definition_digest = [0; 32],
                    _ => unreachable!(),
                }
                let error =
                    render_restatement_diff_ir(&before, &after, &definition, &units).unwrap_err();
                assert!(
                    error.to_string().contains("StatementDefinition"),
                    "{field}, original={change_original}: {error}"
                );
            }
        }
    }

    #[test]
    fn restatement_diff_refuses_different_effective_bounds() {
        let (definition, original) = sample_statement(10, 19_060, 3_540);
        let (_, restated) = sample_statement(25, 19_060, 4_000);
        let units = [UnitFormatSpec {
            unit_id: 1,
            code: "USD".into(),
            scale: 2,
        }];
        render_restatement_diff_ir(&original, &restated, &definition, &units).unwrap();
        for change_start in [false, true] {
            let mut changed = restated.clone();
            if change_start {
                changed.columns[0].effective_from = Some(DateDay(1));
            } else {
                changed.columns[0].effective_through = DateDay(91);
            }
            let error =
                render_restatement_diff_ir(&original, &changed, &definition, &units).unwrap_err();
            assert!(
                error.to_string().contains("same effective bounds"),
                "{error}"
            );
        }
    }

    #[test]
    fn restatement_diff_refuses_missing_primary_amounts_without_panicking() {
        let (definition, original) = sample_statement(10, 19_060, 3_540);
        let (_, restated) = sample_statement(25, 19_060, 4_000);
        let units = [UnitFormatSpec {
            unit_id: 1,
            code: "USD".into(),
            scale: 2,
        }];
        for clear_original in [false, true] {
            let mut before = original.clone();
            let mut after = restated.clone();
            if clear_original {
                before.lines[0].amounts.clear();
            } else {
                after.lines[0].amounts.clear();
            }
            let error =
                render_restatement_diff_ir(&before, &after, &definition, &units).unwrap_err();
            assert!(
                error.to_string().contains("missing primary amount"),
                "{error}"
            );
        }
    }

    #[test]
    fn rounded_document_ir_preserves_residuals_units_and_exact_source() {
        use crate::custom::{
            CustomStatementDefinition, PresentationRoundingSpec, apply_presentation_rounding,
        };
        use fa_money::RoundingLaw;

        let (definition, statement) = sample_statement(10, 19_060, 3_540);
        let units = [UnitFormatSpec {
            unit_id: 1,
            code: "USD".into(),
            scale: 2,
        }];
        let exact = render_statement_ir(&statement, &definition, &units).unwrap();
        let exact_bytes = exact.canonical_bytes().unwrap();
        let presented = apply_presentation_rounding(
            &statement,
            &CustomStatementDefinition::from_builtin(&definition),
            &PresentationRoundingSpec {
                rounding_law: RoundingLaw::HalfEven,
                scale_reduction_digits: 2,
                residual_line_code: "presentation_rounding".into(),
                residual_line_label: "Presentation rounding".into(),
            },
        )
        .unwrap();
        let ir = exact
            .clone()
            .with_presentation(std::slice::from_ref(&presented))
            .unwrap();
        let table = &ir.tables[0];
        assert_eq!((table.unit_code.as_str(), table.unit_scale), ("USD", 2));
        assert_eq!(table.rows[0].cells[1], "USD units; HalfEven");
        assert_eq!(table.rows[1].cells[1], "Display only; cert exact");
        let at = |code| {
            table
                .rows
                .iter()
                .position(|row| row.line_code == code)
                .unwrap()
        };
        let residual = at("unclosed_earnings_presentation_rounding");
        assert_eq!(residual + 1, at("unclosed_earnings"));
        assert_eq!(table.rows[residual].cells[2], "-1");
        assert_eq!(table.rows[residual].footing, FootingRule::None);
        assert_eq!(table.rows[at("unclosed_revenue")].cells[2], "191");
        assert_eq!(table.rows[at("unclosed_expense")].cells[2], "35");
        assert_eq!(table.rows[at("unclosed_earnings")].cells[2], "155");
        assert!(
            ir.markdown
                .contains("accounting certificates bind the exact statement amounts")
        );
        assert!(ir.markdown.contains("Presentation rounding"));
        assert_eq!(
            StatementMarkdownIr::decode(&ir.canonical_bytes().unwrap()).unwrap(),
            ir
        );
        assert_eq!(exact.canonical_bytes().unwrap(), exact_bytes);
        assert_ne!(ir.digest().unwrap(), exact.digest().unwrap());

        let mut renamed = exact.clone();
        let original_second_code = renamed.tables[0].rows[1].line_code.clone();
        renamed.tables[0].rows[0].line_code = "presentation".into();
        renamed.tables[0].rows[0].cells[0] = "presentation".into();
        renamed.tables[0].rows[1].line_code = "presentation_scope".into();
        renamed.tables[0].rows[1].cells[0] = "presentation_scope".into();
        let mut named = presented.clone();
        named.lines[0].code = "presentation".into();
        named
            .lines
            .iter_mut()
            .find(|line| line.code == original_second_code)
            .unwrap()
            .code = "presentation_scope".into();
        let collision = renamed.with_presentation(&[named]).unwrap();
        assert_ne!(collision.tables[0].rows[0].line_code, "presentation");
        assert_ne!(collision.tables[0].rows[1].line_code, "presentation_scope");
        assert_eq!(
            collision.tables[0]
                .rows
                .iter()
                .filter(|row| row.line_code == "presentation_scope")
                .count(),
            1
        );
        assert_eq!(
            collision.tables[0]
                .rows
                .iter()
                .filter(|row| row.line_code == "presentation")
                .count(),
            1,
            "a valid source code survives without colliding with display metadata"
        );

        let mut wrong = presented.clone();
        wrong.columns[0].label.push_str(" changed");
        assert!(exact.clone().with_presentation(&[wrong]).is_err());
        let mut wrong = presented.clone();
        let source_code = wrong.lines[0].code.clone();
        wrong
            .lines
            .iter_mut()
            .find(|line| line.is_residual_line)
            .unwrap()
            .code = source_code;
        assert!(exact.clone().with_presentation(&[wrong]).is_err());
        let mut wrong = presented.clone();
        wrong.known_at += 1;
        assert!(exact.clone().with_presentation(&[wrong]).is_err());
        let mut wrong = presented.clone();
        wrong.lines[0].exact_amounts[0] += 1;
        assert!(exact.clone().with_presentation(&[wrong]).is_err());
        let mut wrong = presented.clone();
        wrong.lines[0].unit_id = 2;
        assert!(exact.clone().with_presentation(&[wrong]).is_err());
        let mut wrong = presented;
        wrong.lines.pop();
        assert!(exact.with_presentation(&[wrong]).is_err());
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
        assert_eq!(
            diff_ir.tables[0].headers[2],
            "As Originally Reported (seq 10) (FY2026-P03)"
        );
        assert_eq!(
            diff_ir.tables[0].headers[3],
            "As Currently Stated (seq 25) (FY2026-P03)"
        );
        let mut other_original = orig.clone();
        let mut other_restated = restated.clone();
        other_original.columns[0].periods = vec!["FY2026-P02".into()];
        other_restated.columns[0].periods = vec!["FY2026-P02".into()];
        let other_diff =
            render_restatement_diff_ir(&other_original, &other_restated, &def, &units).unwrap();
        assert_eq!(
            other_diff.tables[0].headers[2],
            "As Originally Reported (seq 10) (FY2026-P02)"
        );
        assert_eq!(other_diff.tables[0].rows, diff_ir.tables[0].rows);
        assert_ne!(other_diff.digest().unwrap(), diff_ir.digest().unwrap());
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

    /// An account name is table data. A `|` or a line break in it used to
    /// split its row, so every later amount sat under another column's
    /// header (the Debits column showed part of the name).
    #[test]
    fn account_names_cannot_split_a_markdown_table_row() {
        let row = |code: &str, name: &str, debits: i128, credits: i128| TrialBalanceIrRow {
            account_code: code.into(),
            account_name: name.into(),
            unit_id: 1,
            debits,
            credits,
        };
        let ir = render_trial_balance_ir(
            &TrialBalanceIrInput {
                book_id: Id128([0x44; 16]),
                branch_id: Id128::TRUNK,
                known_at: 25,
                effective_label: "FY2026-P03".into(),
                activity_only: false,
                rows: vec![
                    row("1300", "Due to | affiliates", 10_000, 0),
                    row("1400", "Line\nbreak \\| kept", 0, 10_000),
                ],
            },
            &[UnitFormatSpec {
                unit_id: 1,
                code: "USD".into(),
                scale: 2,
            }],
        )
        .unwrap();
        // A delimiter is a `|` not escaped by a backslash.
        let delimiters = |line: &str| {
            let mut count = 0;
            let mut escaped = false;
            for c in line.chars() {
                match (escaped, c) {
                    (false, '\\') => escaped = true,
                    (false, '|') => count += 1,
                    _ => escaped = false,
                }
            }
            count
        };
        let header = ir.markdown.lines().find(|l| l.starts_with("| ")).unwrap();
        let columns = delimiters(header);
        let rows: Vec<&str> = ir
            .markdown
            .lines()
            .filter(|l| l.contains("1300") || l.contains("1400"))
            .collect();
        assert_eq!(rows.len(), 2, "{}", ir.markdown);
        for line in rows {
            assert_eq!(delimiters(line), columns, "{line}");
        }
        assert!(
            ir.markdown.contains("Due to \\| affiliates"),
            "{}",
            ir.markdown
        );
        assert!(
            ir.markdown.contains("Line break \\\\\\| kept"),
            "{}",
            ir.markdown
        );
    }
}
