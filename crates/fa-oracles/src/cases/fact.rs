//! `facts.toml`: provenance-typed `[[fact]]` rows and their `[[value]]` rows
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §2.1–§2.3, §4.1).
//!
//! Every fact has exactly one provenance: `sourced` (a sentence-aligned
//! excerpt of a source), `interpretation` (a reading of sourced facts by two
//! readers), `derived` (a registered rule over other facts) or `synthetic`
//! (filler or a declared stand-in). A row carrying fields of two kinds is
//! refused, because the typed [`Provenance`] cannot hold it.

use fa_registry::toml::{Document, Table, Value as TomlValue};

use super::error::{LoadError, LoadErrorKind};
use super::fields::{Row, is_date, is_integer, is_sha256_hex};
use super::rows::row_line;
use super::source::{AnchorKind, Assurance, closed, put, put_opt, put_strs};

closed_set! {
    /// The provenance kind (§2.1).
    ProvenanceKind {
        Sourced => "sourced",
        Interpretation => "interpretation",
        Derived => "derived",
        Synthetic => "synthetic",
    }
}

closed_set! {
    /// The granularity a sourced fact is stated at (§2.3).
    Granularity {
        JournalEntry => "journal_entry",
        DatedAggregate => "dated_aggregate",
        PeriodTotal => "period_total",
        StatementLine => "statement_line",
        XbrlFact => "xbrl_fact",
        LedgerRow => "ledger_row",
    }
}

closed_set! {
    /// The literal rule a `[[value]]` is read under (§2.4).
    LiteralRule {
        Scale => "scale",
        DateLiteral => "date_literal",
        DateRangeLiteral => "date_range_literal",
        MonthLiteral => "month_literal",
        NumberWord => "number_word",
        PeriodLiteral => "period_literal",
    }
}

/// The fields of each provenance kind besides `id` and `provenance`.
const SOURCED_FIELDS: [&str; 13] = [
    "source",
    "anchor_kind",
    "anchor",
    "quote_sha256",
    "quote",
    "about_scope",
    "granularity",
    "role",
    "cell",
    "rows_file",
    "complaint",
    "assurance",
    "assurance_fact",
];
const INTERPRETATION_FIELDS: [&str; 4] = ["from", "reader", "second_reader", "rationale"];
const DERIVED_FIELDS: [&str; 3] = ["from", "rule", "params"];
const SYNTHETIC_FIELDS: [&str; 2] = ["reason", "discipline"];

const fn fields_of(kind: ProvenanceKind) -> &'static [&'static str] {
    match kind {
        ProvenanceKind::Sourced => &SOURCED_FIELDS,
        ProvenanceKind::Interpretation => &INTERPRETATION_FIELDS,
        ProvenanceKind::Derived => &DERIVED_FIELDS,
        ProvenanceKind::Synthetic => &SYNTHETIC_FIELDS,
    }
}

/// A sourced fact: an excerpt of one source, located by its anchor and
/// bound by the SHA-256 of its normalized quote (hash-first: the quote
/// text itself is optional until owner decision 2a).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sourced {
    pub source: String,
    pub anchor_kind: AnchorKind,
    pub anchor: String,
    pub quote_sha256: String,
    pub quote: Option<String>,
    pub about_scope: String,
    pub granularity: Granularity,
    /// `oracle_output` marks a figure that is the publisher's own computed
    /// output (§2.1), so a T fed by it is typed C unless named (K-ORACLE).
    pub role: Option<String>,
    /// A vintage-independent cell key `<key>@<date or period>`, which
    /// K-VINTAGE pairs across filings.
    pub cell: Option<String>,
    /// The generated rows file this fact stands for (Exhibit B, a dated
    /// series), and the source whose rows block it holds.
    pub rows_file: Option<String>,
    pub complaint: Option<String>,
    /// Whether `rows_file` is committed (whole tables wait on OD 2b).
    pub rows_committed: bool,
    /// A fact's own assurance, narrowing its filing's (§2.2), with the
    /// sourced fact whose sentence or legend establishes it.
    pub assurance: Option<Assurance>,
    pub assurance_fact: Option<String>,
}

/// A reading of sourced facts that the record implies but does not state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interpretation {
    pub from: Vec<String>,
    pub reader: String,
    pub second_reader: String,
    pub rationale: String,
}

/// A registered rule applied to other facts (§2.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derived {
    pub from: Vec<String>,
    pub rule: String,
    pub params: Option<Vec<TomlValue>>,
}

/// Filler or a declared stand-in, never presented as history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Synthetic {
    pub reason: String,
    pub discipline: String,
}

/// A fact's one provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Provenance {
    Sourced(Sourced),
    Interpretation(Interpretation),
    Derived(Derived),
    Synthetic(Synthetic),
}

impl Provenance {
    #[must_use]
    pub const fn kind(&self) -> ProvenanceKind {
        match self {
            Self::Sourced(_) => ProvenanceKind::Sourced,
            Self::Interpretation(_) => ProvenanceKind::Interpretation,
            Self::Derived(_) => ProvenanceKind::Derived,
            Self::Synthetic(_) => ProvenanceKind::Synthetic,
        }
    }
}

/// One `[[fact]]` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fact {
    pub id: String,
    pub provenance: Provenance,
    pub line: Option<usize>,
}

impl Fact {
    #[must_use]
    pub fn sourced(&self) -> Option<&Sourced> {
        match &self.provenance {
            Provenance::Sourced(s) => Some(s),
            _ => None,
        }
    }
}

/// One `[[value]]` row: a literal of a fact, read under a literal rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Value {
    pub fact: String,
    /// 1-based within the fact.
    pub ordinal: i128,
    pub literal: String,
    pub rule: LiteralRule,
    pub param: Option<i128>,
    /// The canonical result: an integer string at the unit's scale (or in
    /// units of 10^`precision` when unitless), a date, a closed day range,
    /// a month, or a period label.
    pub value: String,
    /// Empty for dates, periods and unitless numbers.
    pub unit: String,
    /// The power of ten of the stated precision; negative only on a
    /// unitless value.
    pub precision: Option<i128>,
    pub line: Option<usize>,
}

pub(crate) fn parse_facts(
    file: &str,
    text: &str,
    rows: &[Table],
    rows_files: &[&str],
    errs: &mut Vec<LoadError>,
) -> Vec<Fact> {
    let mut out = Vec::with_capacity(rows.len());
    for (i, table) in rows.iter().enumerate() {
        let mut r = Row::new(file, row_line(text, "fact", i), table);
        let id = r.req_str("id", errs);
        let kind_raw = r.req_str("provenance", errs);
        let Some(kind) = closed(&r, "provenance", &kind_raw, ProvenanceKind::parse, errs) else {
            continue;
        };
        let foreign: Vec<&str> = ProvenanceKind::ALL
            .iter()
            .filter(|k| **k != kind)
            .flat_map(|k| fields_of(*k).iter().copied())
            .filter(|f| r.has(f) && !fields_of(kind).contains(f))
            .collect();
        if !foreign.is_empty() {
            errs.push(r.err(
                LoadErrorKind::TwoProvenanceKinds,
                format!(
                    "a `{}` fact carries {} of another provenance kind",
                    kind.as_str(),
                    foreign.iter().map(|f| format!("`{f}`")).collect::<Vec<_>>().join(", ")
                ),
            ));
            continue;
        }
        let provenance = match kind {
            ProvenanceKind::Sourced => Provenance::Sourced(parse_sourced(&mut r, rows_files, errs)),
            ProvenanceKind::Interpretation => Provenance::Interpretation(Interpretation {
                from: r.req_strs("from", errs),
                reader: r.req_str("reader", errs),
                second_reader: r.req_str("second_reader", errs),
                rationale: r.req_str("rationale", errs),
            }),
            ProvenanceKind::Derived => Provenance::Derived(Derived {
                from: r.req_strs("from", errs),
                rule: r.req_str("rule", errs),
                params: r.opt_scalars("params", errs),
            }),
            ProvenanceKind::Synthetic => Provenance::Synthetic(Synthetic {
                reason: r.req_str("reason", errs),
                discipline: r.req_str("discipline", errs),
            }),
        };
        r.finish(&[], "", errs);
        out.push(Fact {
            id,
            provenance,
            line: r.line(),
        });
    }
    out
}

fn parse_sourced(r: &mut Row<'_>, rows_files: &[&str], errs: &mut Vec<LoadError>) -> Sourced {
    let source = r.req_str("source", errs);
    let kind_raw = r.req_str("anchor_kind", errs);
    let anchor = r.req_str("anchor", errs);
    let quote_sha256 = r.req_str("quote_sha256", errs);
    let quote = r.opt_str("quote", errs);
    let about_scope = r.req_str("about_scope", errs);
    let granularity_raw = r.req_str("granularity", errs);
    let role = r.opt_str("role", errs);
    let cell = r.opt_str("cell", errs);
    let rows_file = r.opt_str("rows_file", errs);
    let complaint = r.opt_str("complaint", errs);
    let assurance_raw = r.opt_str("assurance", errs);
    let assurance_fact = r.opt_str("assurance_fact", errs);

    let anchor_kind =
        closed(r, "anchor_kind", &kind_raw, AnchorKind::parse, errs).unwrap_or(AnchorKind::Page);
    let granularity = closed(r, "granularity", &granularity_raw, Granularity::parse, errs)
        .unwrap_or(Granularity::JournalEntry);
    if !quote_sha256.is_empty() && !is_sha256_hex(&quote_sha256) {
        errs.push(r.err(
            LoadErrorKind::NotSha256Hex,
            "`quote_sha256` must be 64 lower-case hex characters",
        ));
    }
    if let Err(why) = check_anchor(anchor_kind, &anchor) {
        errs.push(r.err(
            LoadErrorKind::WrongType,
            format!("`anchor = \"{anchor}\"` ({}): {why}", anchor_kind.as_str()),
        ));
    }
    if let Some(role) = &role
        && role != "oracle_output"
    {
        errs.push(r.err(
            LoadErrorKind::UnknownValue,
            format!("`role = \"{role}\"`: the only role is `oracle_output`"),
        ));
    }
    if let Some(c) = &cell {
        if !matches!(
            granularity,
            Granularity::StatementLine | Granularity::XbrlFact | Granularity::PeriodTotal
        ) {
            errs.push(r.err(
                LoadErrorKind::UnknownField,
                format!(
                    "`cell` belongs to statement_line, xbrl_fact and period_total facts, not {}",
                    granularity.as_str()
                ),
            ));
        } else if let Err(why) = check_cell(c) {
            errs.push(r.err(LoadErrorKind::WrongType, format!("`cell = \"{c}\"`: {why}")));
        }
    }
    let table_fact = matches!(
        granularity,
        Granularity::LedgerRow | Granularity::DatedAggregate
    );
    if (rows_file.is_some() || complaint.is_some()) && !table_fact {
        errs.push(r.err(
            LoadErrorKind::UnknownField,
            format!(
                "`rows_file`/`complaint` belong to ledger_row and dated_aggregate facts, not {}",
                granularity.as_str()
            ),
        ));
    } else if rows_file.is_some() != complaint.is_some() {
        errs.push(r.err(
            LoadErrorKind::MissingField,
            "`rows_file` and `complaint` come together",
        ));
    }
    if anchor_kind == AnchorKind::Exhibit && rows_file.is_none() {
        errs.push(r.err(
            LoadErrorKind::WrongType,
            "an `exhibit` anchor needs `rows_file`",
        ));
    }
    if rows_file.is_some() && anchor_kind != AnchorKind::Exhibit {
        errs.push(r.err(
            LoadErrorKind::WrongType,
            format!(
                "a `rows_file` fact is anchored `exhibit`, not `{}`",
                anchor_kind.as_str()
            ),
        ));
    }
    let rows_committed = rows_file
        .as_deref()
        .is_some_and(|f| rows_files.contains(&f));
    let assurance = assurance_raw
        .as_deref()
        .and_then(|a| closed(r, "assurance", a, Assurance::parse, errs));
    if assurance.is_some() && assurance_fact.is_none() {
        errs.push(r.err(
            LoadErrorKind::MissingField,
            "a fact `assurance` needs its `assurance_fact`",
        ));
    }
    if assurance_fact.is_some() && assurance.is_none() {
        errs.push(r.err(
            LoadErrorKind::MissingField,
            "`assurance_fact` without an `assurance`",
        ));
    }
    Sourced {
        source,
        anchor_kind,
        anchor,
        quote_sha256,
        quote,
        about_scope,
        granularity,
        role,
        cell,
        rows_file,
        complaint,
        rows_committed,
        assurance,
        assurance_fact,
    }
}

/// The anchor grammar of each kind (A1a): `page` = `p<page>:l<first>-<last>`;
/// `line` = `l<first>-<last>`; `paragraph` = `para<n>`; `table_cell` =
/// `<table>|<row label>|<column label>`; `xbrl` = `<concept>|<context id>`;
/// `exhibit` = `<label>|p<first page>-<last page>`.
///
/// # Errors
///
/// Names what does not parse.
pub fn check_anchor(kind: AnchorKind, anchor: &str) -> Result<(), String> {
    fn range(s: &str, prefix: char) -> Result<(), String> {
        let body = s
            .strip_prefix(prefix)
            .ok_or_else(|| format!("expected `{prefix}<first>-<last>`"))?;
        let (a, b) = body.split_once('-').ok_or("expected `<first>-<last>`")?;
        let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>()) else {
            return Err("range bounds must be integers".into());
        };
        if a == 0 || a > b {
            return Err("a range runs from 1 upward, first ≤ last".into());
        }
        Ok(())
    }
    fn parts(s: &str, n: usize) -> Result<Vec<&str>, String> {
        let p: Vec<&str> = s.split('|').collect();
        if p.len() != n || p.iter().any(|x| x.trim().is_empty()) {
            return Err(format!("expected {n} non-empty `|`-separated parts"));
        }
        Ok(p)
    }
    match kind {
        AnchorKind::Page => {
            let (page, lines) = anchor
                .split_once(':')
                .ok_or("expected `p<page>:l<first>-<last>`")?;
            let page = page.strip_prefix('p').ok_or("expected `p<page>`")?;
            if page.is_empty() || !page.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err("the printed page is alphanumeric".into());
            }
            range(lines, 'l')
        }
        AnchorKind::Line => range(anchor, 'l'),
        AnchorKind::Paragraph => {
            let n = anchor.strip_prefix("para").ok_or("expected `para<n>`")?;
            match n.parse::<u32>() {
                Ok(n) if n > 0 => Ok(()),
                _ => Err("the paragraph number is a positive integer".into()),
            }
        }
        AnchorKind::TableCell => parts(anchor, 3).map(|_| ()),
        AnchorKind::Xbrl => parts(anchor, 2).map(|_| ()),
        AnchorKind::Exhibit => {
            let p = parts(anchor, 2)?;
            range(p[1], 'p')
        }
    }
}

/// The cell grammar: `<key>@<date or period label>`, where `<key>` is
/// segments of letters, digits, `_` and `-` joined by `.`, optionally
/// followed by `:<member or column>`.
///
/// # Errors
///
/// Names what does not parse.
pub fn check_cell(cell: &str) -> Result<(), String> {
    fn word(s: &str) -> bool {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    }
    let (key, at) = cell
        .split_once('@')
        .ok_or("expected `<key>@<date or period>`")?;
    if !word(at) {
        return Err("the date or period label is letters, digits and `-`".into());
    }
    let (line, member) = match key.split_once(':') {
        Some((l, m)) => (l, Some(m)),
        None => (key, None),
    };
    if !line.split('.').all(word) {
        return Err("the key is `.`-joined segments of letters, digits, `_` and `-`".into());
    }
    if member.is_some_and(|m| !word(m)) {
        return Err("the member is letters, digits, `_` and `-`".into());
    }
    Ok(())
}

pub(crate) fn parse_values(
    file: &str,
    text: &str,
    rows: &[Table],
    unit_codes: &[String],
    errs: &mut Vec<LoadError>,
) -> Vec<Value> {
    let mut out = Vec::with_capacity(rows.len());
    for (i, table) in rows.iter().enumerate() {
        let fact_id = table
            .get("fact")
            .and_then(TomlValue::as_str)
            .map(str::to_string);
        let mut r = Row::new(file, row_line(text, "value", i), table).with_id(fact_id);
        let fact = r.req_str("fact", errs);
        let ordinal = r.req_int("ordinal", errs);
        let literal = r.req_str("literal", errs);
        let rule_raw = r.req_str("rule", errs);
        let param = r.opt_int("param", errs);
        let value = r.req_str("value", errs);
        let unit = r.req_str("unit", errs);
        let precision = r.opt_int("precision", errs);
        r.finish(&[], "", errs);
        let rule =
            closed(&r, "rule", &rule_raw, LiteralRule::parse, errs).unwrap_or(LiteralRule::Scale);
        if ordinal < 1 {
            errs.push(r.err(LoadErrorKind::WrongType, "`ordinal` is 1-based"));
        }
        let numeric = matches!(rule, LiteralRule::Scale | LiteralRule::NumberWord);
        if !unit.is_empty() {
            if !unit_codes.contains(&unit) {
                errs.push(r.err(
                    LoadErrorKind::UnknownValue,
                    format!("`unit = \"{unit}\"` is not a registered unit"),
                ));
            }
            if !numeric {
                errs.push(r.err(
                    LoadErrorKind::WrongType,
                    format!("a `{}` value carries no unit", rule.as_str()),
                ));
            }
            if precision.is_some_and(|p| p < 0) {
                errs.push(r.err(
                    LoadErrorKind::WrongType,
                    "a negative `precision` belongs only to a unitless value",
                ));
            }
        }
        let shape_ok = match rule {
            LiteralRule::Scale | LiteralRule::NumberWord => is_integer(&value),
            LiteralRule::DateLiteral => is_date(&value),
            LiteralRule::DateRangeLiteral => value
                .split_once("..")
                .is_some_and(|(a, b)| is_date(a) && is_date(b) && a <= b),
            LiteralRule::MonthLiteral => is_date(&format!("{value}-01")),
            LiteralRule::PeriodLiteral => !value.is_empty(),
        };
        if !shape_ok {
            errs.push(r.err(
                LoadErrorKind::WrongType,
                format!(
                    "`value = \"{value}\"` is not a canonical `{}` result",
                    rule.as_str()
                ),
            ));
        }
        out.push(Value {
            fact,
            ordinal,
            literal,
            rule,
            param,
            value,
            unit,
            precision,
            line: r.line(),
        });
    }
    out
}

/// The canonical values bytes (A1a), shared with `case_fetch.py`'s writer:
/// `fa:case-values:v1`, `about_scope=<about_scope>`, then one line per
/// value in `ordinal` order with `ordinal`, `literal`, `rule`, `param`,
/// `value`, `unit` and `precision` joined by TAB, every line ending in a
/// newline. `values_sha256` is the lower-case hex SHA-256 of these bytes.
#[must_use]
pub fn values_canonical(about_scope: &str, values: &[&Value]) -> Vec<u8> {
    let mut sorted: Vec<&Value> = values.to_vec();
    sorted.sort_by_key(|v| v.ordinal);
    let mut out = format!("fa:case-values:v1\nabout_scope={about_scope}\n");
    for v in sorted {
        out.push_str(&value_line(v));
        out.push('\n');
    }
    out.into_bytes()
}

/// One value's TAB-joined canonical line (without its newline).
#[must_use]
pub fn value_line(v: &Value) -> String {
    let opt = |o: Option<i128>| o.map(|n| n.to_string()).unwrap_or_default();
    [
        v.ordinal.to_string(),
        v.literal.clone(),
        v.rule.as_str().to_string(),
        opt(v.param),
        v.value.clone(),
        v.unit.clone(),
        opt(v.precision),
    ]
    .join("\t")
}

impl Fact {
    /// The row as the TOML subset's table.
    #[must_use]
    pub fn to_table(&self) -> Table {
        let mut t = Table::new();
        put(&mut t, "id", &self.id);
        put(&mut t, "provenance", self.provenance.kind().as_str());
        match &self.provenance {
            Provenance::Sourced(s) => {
                put(&mut t, "source", &s.source);
                put(&mut t, "anchor_kind", s.anchor_kind.as_str());
                put(&mut t, "anchor", &s.anchor);
                put(&mut t, "quote_sha256", &s.quote_sha256);
                put_opt(&mut t, "quote", s.quote.as_deref());
                put(&mut t, "about_scope", &s.about_scope);
                put(&mut t, "granularity", s.granularity.as_str());
                put_opt(&mut t, "role", s.role.as_deref());
                put_opt(&mut t, "cell", s.cell.as_deref());
                put_opt(&mut t, "rows_file", s.rows_file.as_deref());
                put_opt(&mut t, "complaint", s.complaint.as_deref());
                put_opt(&mut t, "assurance", s.assurance.map(Assurance::as_str));
                put_opt(&mut t, "assurance_fact", s.assurance_fact.as_deref());
            }
            Provenance::Interpretation(x) => {
                put_strs(&mut t, "from", Some(&x.from));
                put(&mut t, "reader", &x.reader);
                put(&mut t, "second_reader", &x.second_reader);
                put(&mut t, "rationale", &x.rationale);
            }
            Provenance::Derived(x) => {
                put_strs(&mut t, "from", Some(&x.from));
                put(&mut t, "rule", &x.rule);
                if let Some(p) = &x.params {
                    t.insert("params".into(), TomlValue::Array(p.clone()));
                }
            }
            Provenance::Synthetic(x) => {
                put(&mut t, "reason", &x.reason);
                put(&mut t, "discipline", &x.discipline);
            }
        }
        t
    }
}

impl Value {
    /// The row as the TOML subset's table.
    #[must_use]
    pub fn to_table(&self) -> Table {
        let mut t = Table::new();
        put(&mut t, "fact", &self.fact);
        t.insert("ordinal".into(), TomlValue::Int(self.ordinal));
        put(&mut t, "literal", &self.literal);
        put(&mut t, "rule", self.rule.as_str());
        if let Some(p) = self.param {
            t.insert("param".into(), TomlValue::Int(p));
        }
        put(&mut t, "value", &self.value);
        put(&mut t, "unit", &self.unit);
        if let Some(p) = self.precision {
            t.insert("precision".into(), TomlValue::Int(p));
        }
        t
    }
}

/// `facts.toml` as a document.
#[must_use]
pub fn to_document(facts: &[Fact], values: &[Value]) -> Document {
    let mut doc = Document::default();
    if !facts.is_empty() {
        doc.arrays
            .insert("fact".into(), facts.iter().map(Fact::to_table).collect());
    }
    if !values.is_empty() {
        doc.arrays
            .insert("value".into(), values.iter().map(Value::to_table).collect());
    }
    doc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchors_parse_per_kind() {
        assert!(check_anchor(AnchorKind::Page, "p111:l12-14").is_ok());
        assert!(check_anchor(AnchorKind::Page, "111").is_err());
        assert!(check_anchor(AnchorKind::Line, "l1-1").is_ok());
        assert!(check_anchor(AnchorKind::Line, "l5-4").is_err());
        assert!(check_anchor(AnchorKind::Paragraph, "para29").is_ok());
        assert!(check_anchor(AnchorKind::TableCell, "Note 3|Total assets|1999").is_ok());
        assert!(check_anchor(AnchorKind::TableCell, "Note 3||1999").is_err());
        assert!(check_anchor(AnchorKind::Xbrl, "us-gaap:NetIncomeLoss|c-443").is_ok());
        assert!(check_anchor(AnchorKind::Exhibit, "Exhibit B-1|p3-41").is_ok());
        assert!(check_anchor(AnchorKind::Exhibit, "Exhibit B-1|3-41").is_err());
    }

    #[test]
    fn cell_with_a_dotted_key_and_a_member_parses() {
        assert!(check_cell("equity.common@1999-12-31").is_ok());
        assert!(check_cell("NetIncomeLoss:RestatementAdjustmentMember@2022Q4").is_ok());
        assert!(check_cell("total_assets@2000-12-31").is_ok());
    }

    #[test]
    fn cell_that_does_not_parse_is_refused() {
        assert!(check_cell("total assets@2000").is_err());
        assert!(check_cell("total_assets").is_err());
        assert!(check_cell("a..b@2000").is_err());
    }
}
