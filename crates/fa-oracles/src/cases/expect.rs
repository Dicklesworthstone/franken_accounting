//! `expectations.toml`: every claim a case makes, as checkable data
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §0.3, §5.1–§5.4; bead fa-yugf.5, A1c).
//!
//! `[[expectation]]` rows declare the claims (D, P, T, C, R, N and their CF
//! rows), `[[target]]` rows the per-entry detail, `[[branch_cell]]` rows the
//! branch tables, and `[[note]]` rows the published observations
//! franken_accounting does not compute (a note has no verdict and is never
//! counted). Every sentence is generated from a [`super::templates`] id.
//!
//! Each row kind has a field table that says which keys are legal for which
//! expectation types. A key no table
//! names is refused as `UnknownField`; a key the verdict projection always
//! excludes as `ExcludedField`; a P row's `exit` as `ExitIsCatalogs` (the
//! exit is the refusal catalog's). Rows keep their schema-checked fields, and
//! [`Expectations::to_document`] writes them back for the canonical round
//! trip.
//!
//! A1c's choices where the plan leaves a spelling open:
//! - a cell's or a CF row's expected verdict is `expect`: `admit` or a
//!   catalogued refusal id on P rows, `finding` or `no_finding` on D rows,
//!   and any of these on N rows;
//! - a D target's components are `cite`, `severity` and `statistic_*`, each
//!   with a `*_status` of `S`, `Sd`, `Si`, `B(<attr>,…)`, `Rel(<covariate>)`
//!   or `X`;
//! - a `rule` T names a rule of A2's derivation table
//!   (`data/case_derivations.toml`, [`super::derive`]).

use std::collections::{BTreeMap, BTreeSet};

use fa_registry::toml::{Document, Table, Value as TomlValue};

use super::book::{BookVariant, BranchAttribute, KnownAt, StepKind};
use super::error::{LoadError, LoadErrorKind};
use super::fact::{Fact, Granularity};
use super::header::{CaseHeader, CaseKind};
use super::rows::row_line;
use super::source::Source;
use super::templates;

closed_set! {
    /// The claim types of plan §0.3.
    ExpectationType {
        D => "D",
        P => "P",
        T => "T",
        C => "C",
        R => "R",
        N => "N",
        Cf => "CF",
    }
}

closed_set! {
    /// `about`: the documented history, or our own reconstruction (§2.7).
    About {
        History => "history",
        Reconstruction => "reconstruction",
    }
}

closed_set! {
    /// `record_label`: a §9.4 record-silent row renders only as counts.
    RecordLabel {
        Characterized => "characterized",
        Silent => "silent",
    }
}

closed_set! {
    /// An N row's kind (§5.2).
    NKind {
        NoRefusal => "no_refusal",
        NoFinding => "no_finding",
        ExactGap => "exact_gap",
    }
}

closed_set! {
    /// An N row's twin (§3.7 item 3).
    TwinKind {
        Mutation => "mutation",
        HarnessObservability => "harness_observability",
        Matcher => "matcher",
    }
}

closed_set! {
    /// A T row's kind (§5.3, plus `rule` and `round_trip`).
    TKind {
        Bridge => "bridge",
        Footing => "footing",
        PerAccount => "per_account",
        Allocation => "allocation",
        Delta => "delta",
        Rule => "rule",
        RoundTrip => "round_trip",
    }
}

closed_set! {
    /// The role of a source in a T's `vintages` (K-VINTAGE, A3b).
    VintageRole {
        A => "A",
        D => "D",
        B => "B",
        Exhibit => "exhibit",
        Source => "source",
    }
}

/// The observed covariates a `Rel(…)` status may name (§2.6 rule 9).
pub const COVARIATES: [&str; 1] = ["account_vid_order"];

/// A component's status (§2.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Sourced.
    S,
    /// Sourced through a declared default.
    Sd,
    /// Sourced through an interpretation.
    Si,
    /// A branch table over these attributes.
    B(Vec<BranchAttribute>),
    /// Relative to an observed covariate.
    Rel(String),
    /// Not asserted.
    X,
}

impl Status {
    /// The status spelled `s`, if it is one.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "S" => return Some(Self::S),
            "Sd" => return Some(Self::Sd),
            "Si" => return Some(Self::Si),
            "X" => return Some(Self::X),
            _ => {}
        }
        if let Some(inner) = s.strip_prefix("B(").and_then(|r| r.strip_suffix(')')) {
            let attrs: Option<Vec<_>> = inner
                .split(',')
                .map(|a| BranchAttribute::parse(a.trim()))
                .collect();
            return attrs.filter(|a| !a.is_empty()).map(Self::B);
        }
        if let Some(inner) = s.strip_prefix("Rel(").and_then(|r| r.strip_suffix(')'))
            && COVARIATES.contains(&inner)
        {
            return Some(Self::Rel(inner.to_string()));
        }
        None
    }
}

/// One component of a D target: its status and expected value, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    pub status: Status,
    pub value: Option<String>,
}

/// The verdict projection of a D target (§5.4): what a run compares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Projection {
    pub procedure: String,
    pub version: i128,
    pub cite: Component,
    pub severity: Component,
    pub statistic_name: Option<String>,
    pub statistic: Component,
    pub statistic_scale: Option<i128>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Str,
    Strs,
    Int,
    Bool,
}

/// A schema-checked field value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Field {
    Str(String),
    Strs(Vec<String>),
    Int(i128),
    Bool(bool),
}

/// One row's schema-checked fields and its line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fields {
    pub map: BTreeMap<String, Field>,
    pub line: Option<usize>,
}

impl Fields {
    #[must_use]
    pub fn str(&self, key: &str) -> Option<&str> {
        match self.map.get(key) {
            Some(Field::Str(s)) => Some(s),
            _ => None,
        }
    }

    #[must_use]
    pub fn strs(&self, key: &str) -> Option<&[String]> {
        match self.map.get(key) {
            Some(Field::Strs(v)) => Some(v),
            _ => None,
        }
    }

    #[must_use]
    pub fn int(&self, key: &str) -> Option<i128> {
        match self.map.get(key) {
            Some(Field::Int(i)) => Some(*i),
            _ => None,
        }
    }

    #[must_use]
    pub fn bool(&self, key: &str) -> Option<bool> {
        match self.map.get(key) {
            Some(Field::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    fn has(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    fn to_table(&self) -> Table {
        self.map
            .iter()
            .map(|(k, v)| {
                let value = match v {
                    Field::Str(s) => TomlValue::Str(s.clone()),
                    Field::Strs(items) => {
                        TomlValue::Array(items.iter().map(|s| TomlValue::Str(s.clone())).collect())
                    }
                    Field::Int(i) => TomlValue::Int(*i),
                    Field::Bool(b) => TomlValue::Bool(*b),
                };
                (k.clone(), value)
            })
            .collect()
    }
}

/// `[[expectation]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expectation {
    pub id: String,
    pub kind: ExpectationType,
    pub fields: Fields,
}

impl Expectation {
    /// The coordinate a D reads at: `known_at`, else `pre_case` (§5.1).
    #[must_use]
    pub fn known_at(&self) -> KnownAt {
        self.fields
            .str("known_at")
            .and_then(KnownAt::parse)
            .unwrap_or(KnownAt::PreCase)
    }

    /// Whether the read fields sit on this row (one read).
    #[must_use]
    pub fn reads_here(&self) -> bool {
        READ_FIELDS.iter().any(|k| self.fields.has(k))
    }
}

/// `[[target]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub expectation: String,
    pub fact: String,
    pub fields: Fields,
}

impl Target {
    /// Whether this target carries its own read (several reads per row).
    #[must_use]
    pub fn reads_here(&self) -> bool {
        READ_FIELDS.iter().any(|k| self.fields.has(k))
    }

    fn component(&self, name: &str, value_key: &str) -> Option<Component> {
        let status = Status::parse(self.fields.str(&format!("{name}_status"))?)?;
        let value = match self.fields.map.get(value_key) {
            Some(Field::Str(s)) => Some(s.clone()),
            Some(Field::Strs(v)) => Some(v.join(",")),
            Some(Field::Int(i)) => Some(i.to_string()),
            _ => None,
        };
        Some(Component { status, value })
    }

    /// The §5.4 projection of a D target.
    #[must_use]
    pub fn projection(&self, expectation: &Expectation) -> Option<Projection> {
        Some(Projection {
            procedure: expectation.fields.str("procedure")?.to_string(),
            version: expectation.fields.int("version")?,
            cite: self.component("cite", "cite")?,
            severity: self.component("severity", "severity")?,
            statistic_name: self.fields.str("statistic_name").map(str::to_string),
            statistic: self.component("statistic", "statistic_value")?,
            statistic_scale: self.fields.int("statistic_scale"),
        })
    }
}

/// `[[branch_cell]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchCell {
    pub expectation: String,
    pub target: String,
    pub cell: Vec<String>,
    pub fields: Fields,
}

impl BranchCell {
    /// The reason the cell waits, when it does (§5.1).
    #[must_use]
    pub fn pending(&self) -> Option<&str> {
        self.fields.str("pending").filter(|p| !p.is_empty())
    }
}

/// `[[note]]`: a published observation with no verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub id: String,
    pub fields: Fields,
}

/// A loaded `expectations.toml`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Expectations {
    pub expectations: Vec<Expectation>,
    pub targets: Vec<Target>,
    pub branch_cells: Vec<BranchCell>,
    pub notes: Vec<Note>,
}

impl Expectations {
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Expectation> {
        self.expectations.iter().find(|e| e.id == id)
    }

    /// The targets of one expectation.
    pub fn targets_of<'a>(&'a self, id: &'a str) -> impl Iterator<Item = &'a Target> + 'a {
        self.targets.iter().filter(move |t| t.expectation == id)
    }

    /// The file as the TOML subset's document (the canonical round trip).
    #[must_use]
    pub fn to_document(&self) -> Document {
        let mut doc = Document::default();
        let mut put = |name: &str, rows: Vec<Table>| {
            if !rows.is_empty() {
                doc.arrays.insert(name.into(), rows);
            }
        };
        put(
            "expectation",
            self.expectations
                .iter()
                .map(|e| e.fields.to_table())
                .collect(),
        );
        put(
            "target",
            self.targets.iter().map(|t| t.fields.to_table()).collect(),
        );
        put(
            "branch_cell",
            self.branch_cells
                .iter()
                .map(|c| c.fields.to_table())
                .collect(),
        );
        put(
            "note",
            self.notes.iter().map(|n| n.fields.to_table()).collect(),
        );
        doc
    }
}

use ExpectationType as E;

const ALL: &[ExpectationType] = &[E::D, E::P, E::T, E::C, E::R, E::N, E::Cf];

/// The read fields a T or R places on itself or on each target, never both.
const READ_FIELDS: [&str; 6] = [
    "read_verb",
    "read_target",
    "read_coordinate",
    "read_selector",
    "published",
    "posted",
];

/// `[[expectation]]`'s field table: (key, kind, the types it is legal on).
const EXP: &[(&str, Kind, &[ExpectationType])] = &[
    ("id", Kind::Str, ALL),
    ("type", Kind::Str, ALL),
    ("book_variant", Kind::Str, ALL),
    ("statement_template", Kind::Str, ALL),
    ("basis", Kind::Strs, ALL),
    ("premises", Kind::Strs, ALL),
    ("granularity", Kind::Str, ALL),
    ("capabilities", Kind::Strs, ALL),
    ("owner_review", Kind::Bool, ALL),
    ("about", Kind::Str, ALL),
    ("record_label", Kind::Str, ALL),
    ("known_at", Kind::Str, ALL),
    ("procedure", Kind::Str, &[E::D, E::N]),
    ("version", Kind::Int, &[E::D, E::N]),
    // A D whose targets are every documented or Δ entry its run's findings
    // cite (A5b): an unexpected cite fails the row.
    ("closed_cites", Kind::Bool, &[E::D]),
    ("population", Kind::Str, &[E::D, E::N]),
    ("population_basis", Kind::Strs, &[E::D, E::N]),
    ("intent", Kind::Str, &[E::P]),
    ("refusal", Kind::Str, &[E::P]),
    ("law_row", Kind::Str, &[E::P]),
    ("attribute", Kind::Str, &[E::P]),
    ("reference_verdict", Kind::Str, &[E::P]),
    ("kind", Kind::Str, &[E::N, E::T]),
    ("target", Kind::Str, &[E::N]),
    ("mechanism", Kind::Str, &[E::N]),
    ("twin_kind", Kind::Str, &[E::N]),
    ("twin_attribute", Kind::Str, &[E::N]),
    ("twin_value", Kind::Str, &[E::N]),
    ("twin_expect", Kind::Str, &[E::N]),
    ("gap_amount", Kind::Str, &[E::N]),
    ("gap_unit", Kind::Str, &[E::N]),
    ("twin_target", Kind::Str, &[E::N]),
    ("parent", Kind::Str, &[E::Cf]),
    ("changed_attribute", Kind::Str, &[E::Cf]),
    ("changed_value", Kind::Str, &[E::Cf]),
    ("expect", Kind::Str, &[E::Cf]),
    ("read_verb", Kind::Str, &[E::T, E::R]),
    ("read_target", Kind::Str, &[E::T, E::R]),
    ("read_coordinate", Kind::Str, &[E::T, E::R]),
    ("read_selector", Kind::Str, &[E::T, E::R]),
    ("published", Kind::Str, &[E::T]),
    ("posted", Kind::Str, &[E::R]),
    ("vintages", Kind::Strs, &[E::T]),
    ("assurance", Kind::Str, &[E::T]),
    ("inputs_named", Kind::Strs, &[E::T]),
    ("rule", Kind::Str, &[E::T]),
    ("display_unit", Kind::Str, &[E::C]),
    ("per_row_test", Kind::Str, &[E::C]),
    ("band", Kind::Str, &[E::C]),
    ("detection_limit", Kind::Str, &[E::C]),
];

const TARGET: &[(&str, Kind, &[ExpectationType])] = &[
    ("expectation", Kind::Str, ALL),
    ("fact", Kind::Str, ALL),
    ("basis", Kind::Strs, ALL),
    ("branch_scope", Kind::Str, ALL),
    ("branch_attrs", Kind::Strs, ALL),
    ("admitted_cell", Kind::Strs, &[E::D]),
    ("cite", Kind::Strs, &[E::D]),
    ("cite_status", Kind::Str, &[E::D]),
    ("severity", Kind::Str, &[E::D]),
    ("severity_status", Kind::Str, &[E::D]),
    // On an exact_gap N's target and twin_target, the sourced value its gap
    // is measured from (A11c).
    ("statistic_name", Kind::Str, &[E::D, E::N]),
    ("statistic_value", Kind::Str, &[E::D, E::N]),
    ("statistic_scale", Kind::Int, &[E::D, E::N]),
    ("statistic_status", Kind::Str, &[E::D]),
    // A5b: the relational rule of a `Rel(…)` component (rel.rs), and R-QUAL's
    // `<interpretive rule>:<fact>` constraints and the sourced facts that
    // document an exception for this target (§2.6 rule 3; K-BRANCH, K-PRED).
    ("rel_rule", Kind::Str, &[E::D]),
    ("constraints", Kind::Strs, &[E::D]),
    ("exceptions", Kind::Strs, &[E::D]),
    ("read_verb", Kind::Str, &[E::T, E::R]),
    ("read_target", Kind::Str, &[E::T, E::R]),
    ("read_coordinate", Kind::Str, &[E::T, E::R]),
    ("read_selector", Kind::Str, &[E::T, E::R]),
    ("published", Kind::Str, &[E::T]),
    ("posted", Kind::Str, &[E::R]),
];

const CELL: &[(&str, Kind, &[ExpectationType])] = &[
    ("expectation", Kind::Str, ALL),
    ("target", Kind::Str, ALL),
    ("cell", Kind::Strs, ALL),
    ("expect", Kind::Str, ALL),
    ("record_consistent", Kind::Bool, ALL),
    ("default", Kind::Bool, ALL),
    ("pending", Kind::Str, ALL),
    ("cite", Kind::Strs, &[E::D]),
    ("severity", Kind::Str, &[E::D]),
    ("statistic_value", Kind::Str, &[E::D]),
];

const NOTE: &[(&str, Kind, &[ExpectationType])] = &[
    ("id", Kind::Str, ALL),
    ("case", Kind::Str, ALL),
    ("basis", Kind::Strs, ALL),
    ("template", Kind::Str, ALL),
];

/// Fields that carry a verdict: a note naming one is refused.
const VERDICT_FIELDS: [&str; 14] = [
    "verdict",
    "expect",
    "refusal",
    "procedure",
    "version",
    "cite",
    "cite_status",
    "severity",
    "severity_status",
    "statistic_name",
    "statistic_value",
    "statistic_scale",
    "statistic_status",
    "kind",
];

/// Whether the projection always excludes `key` (§5.4).
fn excluded(key: &str) -> bool {
    matches!(
        key,
        "statistic_population" | "findings_digest" | "finding_id" | "certificate_id"
    ) || key.ends_with("_vid")
        || key.ends_with("_oid")
        || key.ends_with("_digest")
}

/// Reads one table under a field table, for a row of type `ty` (`None` when
/// the row's type is unknown: then every listed key is accepted).
fn read_fields(
    file: &str,
    line: Option<usize>,
    row: Option<&str>,
    table: &Table,
    spec: &[(&str, Kind, &[ExpectationType])],
    ty: Option<ExpectationType>,
    errs: &mut Vec<LoadError>,
) -> Fields {
    let err = |kind: LoadErrorKind, detail: String| LoadError {
        file: file.to_string(),
        line,
        kind,
        row: row.map(str::to_string),
        detail,
    };
    let mut map = BTreeMap::new();
    for (key, value) in table {
        if key == "exit" {
            errs.push(err(
                LoadErrorKind::ExitIsCatalogs,
                "`exit` is not a field: the expected exit is registries/refusal_catalog.toml's"
                    .into(),
            ));
            continue;
        }
        if excluded(key) {
            errs.push(err(
                LoadErrorKind::ExcludedField,
                format!("`{key}` is a field the verdict projection always excludes (§5.4)"),
            ));
            continue;
        }
        let Some((_, kind, types)) = spec.iter().find(|(k, _, _)| k == key) else {
            errs.push(err(
                LoadErrorKind::UnknownField,
                format!("unknown field `{key}`"),
            ));
            continue;
        };
        if let Some(t) = ty
            && !types.contains(&t)
        {
            errs.push(err(
                LoadErrorKind::UnknownField,
                format!("`{key}` is not a field of a {} row", t.as_str()),
            ));
            continue;
        }
        let parsed = match (kind, value) {
            (Kind::Str, TomlValue::Str(s)) => Some(Field::Str(s.clone())),
            (Kind::Int, TomlValue::Int(i)) => Some(Field::Int(*i)),
            (Kind::Bool, TomlValue::Bool(b)) => Some(Field::Bool(*b)),
            (Kind::Strs, TomlValue::Array(items)) => items
                .iter()
                .map(|v| v.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
                .map(Field::Strs),
            _ => None,
        };
        match parsed {
            Some(f) => {
                map.insert(key.clone(), f);
            }
            None => {
                let want = match kind {
                    Kind::Str => "a string",
                    Kind::Strs => "an array of strings",
                    Kind::Int => "an integer",
                    Kind::Bool => "a boolean",
                };
                errs.push(err(
                    LoadErrorKind::WrongType,
                    format!("`{key}` must be {want}"),
                ));
            }
        }
    }
    Fields { map, line }
}

/// What expectations resolve against.
pub(crate) struct View<'a> {
    pub header: Option<&'a CaseHeader>,
    pub sources: &'a [Source],
    pub facts: &'a [Fact],
    pub books: &'a BTreeMap<String, BookVariant>,
    /// The `books/<stem>.toml` stems among the case's files.
    pub book_files: BTreeSet<String>,
    pub refusals: BTreeSet<String>,
    pub procedures: BTreeMap<String, (u16, Vec<String>)>,
    pub unit_scales: BTreeMap<String, u8>,
    /// The ids of the derivation table (A2).
    pub derivations: BTreeSet<String>,
}

impl View<'_> {
    pub(crate) fn new<'a>(
        header: Option<&'a CaseHeader>,
        sources: &'a [Source],
        facts: &'a [Fact],
        books: &'a BTreeMap<String, BookVariant>,
        paths: &[&str],
        errs: &mut Vec<LoadError>,
    ) -> View<'a> {
        let mut fail = |file: &str, e: &dyn core::fmt::Display| {
            errs.push(LoadError {
                file: format!("registries/{file}"),
                line: None,
                kind: LoadErrorKind::Toml,
                row: None,
                detail: e.to_string(),
            });
        };
        let refusals = match fa_registry::refusal_catalog::RefusalCatalog::embedded() {
            Ok(c) => c.rows.into_iter().map(|r| r.code).collect(),
            Err(e) => {
                fail("refusal_catalog.toml", &e);
                BTreeSet::new()
            }
        };
        let procedures = match fa_registry::procedures::Procedures::embedded() {
            Ok(p) => p
                .rows
                .into_iter()
                .map(|r| {
                    (
                        r.id,
                        (
                            r.version,
                            r.parameters.into_iter().map(|p| p.name).collect(),
                        ),
                    )
                })
                .collect(),
            Err(e) => {
                fail("procedures.toml", &e);
                BTreeMap::new()
            }
        };
        let unit_scales = match fa_registry::units_embedded() {
            Ok(rows) => {
                let mut best: BTreeMap<String, (u16, u8)> = BTreeMap::new();
                for u in rows {
                    let e = best.entry(u.code).or_insert((u.version, u.scale));
                    if u.version >= e.0 {
                        *e = (u.version, u.scale);
                    }
                }
                best.into_iter().map(|(k, (_, s))| (k, s)).collect()
            }
            Err(e) => {
                fail("units.toml", &e);
                BTreeMap::new()
            }
        };
        let derivations = match super::derive::Rules::embedded() {
            Ok(r) => r.rules.into_iter().map(|r| r.id).collect(),
            Err(es) => {
                errs.extend(es);
                BTreeSet::new()
            }
        };
        View {
            derivations,
            header,
            sources,
            facts,
            books,
            book_files: paths
                .iter()
                .filter_map(|p| p.strip_prefix("books/")?.strip_suffix(".toml"))
                .map(str::to_string)
                .collect(),
            refusals,
            procedures,
            unit_scales,
        }
    }

    fn fact(&self, id: &str) -> Option<&Fact> {
        self.facts.iter().find(|f| f.id == id)
    }

    fn is_source(&self, id: &str) -> bool {
        self.sources.iter().any(|s| s.id == id)
    }

    /// A fact id, or an `[[intent]]` id of `variant`.
    fn fact_or_intent(&self, variant: &str, id: &str) -> bool {
        self.fact(id).is_some()
            || self
                .books
                .get(variant)
                .is_some_and(|b| b.intents.iter().any(|i| i.id == id))
    }

    /// The case's id prefix: its letter, or a harness self-test's id.
    fn prefix(&self) -> Option<String> {
        let h = self.header?;
        match (&h.letter, h.kind) {
            (Some(l), _) => Some(l.clone()),
            (None, CaseKind::HarnessSelftest) => Some(h.id.clone()),
            (None, _) => None,
        }
    }
}

/// The step position a D reads at (plan §5.1): `pre_case` is the head just
/// before the variant's first `case_open` step, or, on a variant with no
/// `[[case]]` row, the head at the `finding_record` step itself; `head` is
/// the head at that step. The result counts the steps executed before the
/// read (the runner passes the recorded sequence it observed there as
/// `--known-at`).
#[must_use]
pub fn frontier(book: &BookVariant, known_at: KnownAt, finding_step: usize) -> usize {
    if known_at == KnownAt::Head || book.cases.is_empty() {
        return finding_step;
    }
    book.steps
        .iter()
        .position(|s| s.step_kind() == Some(StepKind::CaseOpen))
        .unwrap_or(finding_step)
}

/// Parses and checks `expectations.toml`, pushing every problem to `errs`.
pub(crate) fn parse(
    view: &View<'_>,
    file: &str,
    text: &str,
    errs: &mut Vec<LoadError>,
) -> Expectations {
    let doc = match fa_registry::toml::parse(text) {
        Ok(doc) => doc,
        Err(e) => {
            errs.push(LoadError {
                file: file.to_string(),
                line: Some(e.line),
                kind: LoadErrorKind::Toml,
                row: None,
                detail: e.message,
            });
            return Expectations::default();
        }
    };
    for key in doc.root.keys() {
        errs.push(LoadError {
            file: file.to_string(),
            line: super::rows::root_key_line(text, key),
            kind: LoadErrorKind::UnknownField,
            row: None,
            detail: format!("unknown root key `{key}`"),
        });
    }
    for name in doc.tables.keys() {
        errs.push(LoadError {
            file: file.to_string(),
            line: None,
            kind: LoadErrorKind::UnknownField,
            row: None,
            detail: format!("unknown table `[{name}]`"),
        });
    }
    for name in doc
        .arrays
        .keys()
        .filter(|n| !["expectation", "target", "branch_cell", "note"].contains(&n.as_str()))
    {
        errs.push(LoadError {
            file: file.to_string(),
            line: row_line(text, name, 0),
            kind: LoadErrorKind::UnknownField,
            row: None,
            detail: format!("unknown array `[[{name}]]`"),
        });
    }
    let rows = |name: &str| doc.arrays.get(name).map(Vec::as_slice).unwrap_or(&[]);
    let mut out = Expectations::default();
    for (i, t) in rows("expectation").iter().enumerate() {
        let line = row_line(text, "expectation", i);
        let id = t
            .get("id")
            .and_then(TomlValue::as_str)
            .unwrap_or("")
            .to_string();
        let ty_raw = t.get("type").and_then(TomlValue::as_str).unwrap_or("");
        let ty = ExpectationType::parse(ty_raw);
        let fields = read_fields(file, line, Some(&id), t, EXP, ty, errs);
        let Some(kind) = ty else {
            errs.push(LoadError {
                file: file.to_string(),
                line,
                kind: if t.contains_key("type") {
                    LoadErrorKind::UnknownValue
                } else {
                    LoadErrorKind::MissingField
                },
                row: Some(id.clone()),
                detail: format!("`type = \"{ty_raw}\"` is D, P, T, C, R, N or CF"),
            });
            continue;
        };
        out.expectations.push(Expectation { id, kind, fields });
    }
    let types: BTreeMap<String, ExpectationType> = out
        .expectations
        .iter()
        .map(|e| (e.id.clone(), e.kind))
        .collect();
    for (i, t) in rows("target").iter().enumerate() {
        let line = row_line(text, "target", i);
        let exp = t
            .get("expectation")
            .and_then(TomlValue::as_str)
            .unwrap_or("")
            .to_string();
        let fact = t
            .get("fact")
            .and_then(TomlValue::as_str)
            .unwrap_or("")
            .to_string();
        let fields = read_fields(
            file,
            line,
            Some(&fact),
            t,
            TARGET,
            types.get(&exp).copied(),
            errs,
        );
        out.targets.push(Target {
            expectation: exp,
            fact,
            fields,
        });
    }
    for (i, t) in rows("branch_cell").iter().enumerate() {
        let line = row_line(text, "branch_cell", i);
        let exp = t
            .get("expectation")
            .and_then(TomlValue::as_str)
            .unwrap_or("")
            .to_string();
        let target = t
            .get("target")
            .and_then(TomlValue::as_str)
            .unwrap_or("")
            .to_string();
        let fields = read_fields(
            file,
            line,
            Some(&target),
            t,
            CELL,
            types.get(&exp).copied(),
            errs,
        );
        let cell = fields
            .strs("cell")
            .map(<[String]>::to_vec)
            .unwrap_or_default();
        out.branch_cells.push(BranchCell {
            expectation: exp,
            target,
            cell,
            fields,
        });
    }
    for (i, t) in rows("note").iter().enumerate() {
        let line = row_line(text, "note", i);
        let id = t
            .get("id")
            .and_then(TomlValue::as_str)
            .unwrap_or("")
            .to_string();
        let verdicts: Vec<&str> = t
            .keys()
            .map(String::as_str)
            .filter(|k| VERDICT_FIELDS.contains(k))
            .collect();
        if !verdicts.is_empty() {
            errs.push(LoadError {
                file: file.to_string(),
                line,
                kind: LoadErrorKind::NoteWithVerdict,
                row: Some(id.clone()),
                detail: format!(
                    "a note has no verdict, yet names {verdicts:?}; a claim that can pass or fail is an [[expectation]]"
                ),
            });
        }
        let mut stripped = t.clone();
        stripped.retain(|k, _| !VERDICT_FIELDS.contains(&k.as_str()));
        let fields = read_fields(file, line, Some(&id), &stripped, NOTE, None, errs);
        out.notes.push(Note { id, fields });
    }
    Check {
        view,
        file,
        set: &out,
        errs,
    }
    .run();
    out
}

struct Check<'a, 'e> {
    view: &'a View<'a>,
    file: &'a str,
    set: &'a Expectations,
    errs: &'e mut Vec<LoadError>,
}

impl<'a> Check<'a, '_> {
    fn push(&mut self, line: Option<usize>, row: &str, kind: LoadErrorKind, detail: String) {
        self.errs.push(LoadError {
            file: self.file.to_string(),
            line,
            kind,
            row: Some(row.to_string()),
            detail,
        });
    }

    fn require(&mut self, e: &Fields, row: &str, keys: &[&str], what: &str) {
        for k in keys {
            if !e.has(k) {
                self.push(
                    e.line,
                    row,
                    LoadErrorKind::MissingField,
                    format!("`{k}` is required on {what}"),
                );
            }
        }
    }

    fn run(mut self) {
        let set = self.set;
        let mut seen = BTreeSet::new();
        for e in &set.expectations {
            if !seen.insert(e.id.as_str()) {
                self.push(
                    e.fields.line,
                    &e.id,
                    LoadErrorKind::DuplicateId,
                    "a second expectation with this id".into(),
                );
            }
            self.expectation(e);
        }
        let mut target_keys = BTreeSet::new();
        for t in &set.targets {
            if !target_keys.insert((t.expectation.as_str(), t.fact.as_str())) {
                self.push(
                    t.fields.line,
                    &t.fact,
                    LoadErrorKind::DuplicateId,
                    format!("a second target `{}` of {}", t.fact, t.expectation),
                );
            }
            self.target(t);
        }
        // An exact_gap N's gap is measured from sourced values: one target
        // row each for its `target` and its `twin_target` (A11c).
        for n in set.expectations.iter().filter(|e| {
            e.kind == E::N && e.fields.str("kind").and_then(NKind::parse) == Some(NKind::ExactGap)
        }) {
            for key in ["target", "twin_target"] {
                let Some(fact) = n.fields.str(key) else {
                    continue;
                };
                if !set
                    .targets_of(&n.id)
                    .any(|t| t.fact == fact && t.fields.has("statistic_value"))
                {
                    self.push(
                        n.fields.line,
                        &n.id,
                        LoadErrorKind::MissingField,
                        format!(
                            "an exact_gap N states its `{key}` {fact}'s sourced value in a [[target]] row (statistic_name, statistic_value)"
                        ),
                    );
                }
            }
        }
        let mut cell_keys = BTreeSet::new();
        let mut defaults: BTreeMap<(&str, &str), usize> = BTreeMap::new();
        for c in &set.branch_cells {
            if !cell_keys.insert((c.expectation.as_str(), c.target.as_str(), c.cell.clone())) {
                self.push(
                    c.fields.line,
                    &c.target,
                    LoadErrorKind::DuplicateId,
                    format!("cell {:?} of {} is declared twice", c.cell, c.target),
                );
            }
            if c.fields.bool("default") == Some(true) {
                *defaults
                    .entry((c.expectation.as_str(), c.target.as_str()))
                    .or_default() += 1;
            }
            self.cell(c);
        }
        for ((exp, target), n) in defaults {
            if n > 1 {
                let line = set
                    .branch_cells
                    .iter()
                    .find(|c| c.expectation == exp && c.target == target)
                    .and_then(|c| c.fields.line);
                self.push(line, target, LoadErrorKind::DuplicateId, format!("{exp}'s target {target} marks {n} cells `default`; a declared default selects one"));
            }
        }
        let mut note_ids = BTreeSet::new();
        for n in &set.notes {
            if !note_ids.insert(n.id.as_str()) {
                self.push(
                    n.fields.line,
                    &n.id,
                    LoadErrorKind::DuplicateId,
                    "a second note with this id".into(),
                );
            }
            self.note(n);
        }
        self.all_x();
        self.claims();
    }

    /// The id grammar (§5.1, §3.2b) and the reserved generated forms.
    fn id(&mut self, e: &Expectation) {
        let Some(prefix) = self.view.prefix() else {
            return;
        };
        let id = e.id.as_str();
        let reserved = id == format!("{prefix}-N-90")
            || id.starts_with(&format!("{prefix}-SELF-"))
            || id.starts_with(&format!("{prefix}-CASE-"));
        if reserved {
            self.push(
                e.fields.line,
                id,
                LoadErrorKind::ReservedId,
                format!(
                    "`{id}` is a generated row (`{prefix}-SELF-<variant>`, `{prefix}-CASE-<case id>`, `{prefix}-N-90`), never authored"
                ),
            );
            return;
        }
        let two_digits = |s: &str| s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit());
        let ok = if e.kind == E::Cf {
            id.rsplit_once("-CF-").is_some_and(|(parent, n)| {
                two_digits(n)
                    && parent.starts_with(&format!("{prefix}-"))
                    && !parent.contains("-CF-")
            })
        } else {
            id.strip_prefix(&format!("{prefix}-"))
                .and_then(|rest| rest.split_once('-'))
                .is_some_and(|(t, n)| t == e.kind.as_str() && two_digits(n))
        };
        if !ok {
            self.push(
                e.fields.line,
                id,
                LoadErrorKind::BadId,
                format!(
                    "a {} row of case `{prefix}` is `{prefix}-{}-NN`{}",
                    e.kind.as_str(),
                    e.kind.as_str(),
                    if e.kind == E::Cf {
                        " (`<parent>-CF-NN`)"
                    } else {
                        ""
                    }
                ),
            );
        }
    }

    fn template(&mut self, e: &Expectation) {
        let Some(t) = e.fields.str("statement_template") else {
            return;
        };
        let want = match e.kind {
            E::T => e.fields.str("kind").map(|k| format!("T.{k}")),
            E::N => e.fields.str("kind").map(|k| format!("N.{k}")),
            _ => None,
        };
        if !templates::TEMPLATE_IDS.contains(&t) {
            self.push(
                e.fields.line,
                &e.id,
                LoadErrorKind::UnknownValue,
                format!("`statement_template = \"{t}\"` is not a template id"),
            );
        } else if !templates::of_type(t, e.kind.as_str()) {
            self.push(
                e.fields.line,
                &e.id,
                LoadErrorKind::UnknownValue,
                format!(
                    "a {} row takes a `{}.` template, not `{t}`",
                    e.kind.as_str(),
                    e.kind.as_str()
                ),
            );
        } else if let Some(w) = want
            && w != t
        {
            self.push(
                e.fields.line,
                &e.id,
                LoadErrorKind::UnknownValue,
                format!("this row's kind renders with `{w}`, not `{t}`"),
            );
        }
    }

    fn expectation(&mut self, e: &Expectation) {
        let f = &e.fields;
        let row = e.id.as_str();
        self.id(e);
        self.require(
            f,
            row,
            &["book_variant", "statement_template", "basis"],
            "every expectation",
        );
        self.template(e);
        let variant = f.str("book_variant").unwrap_or("");
        if !variant.is_empty() && !self.view.book_files.contains(variant) {
            self.push(
                f.line,
                row,
                LoadErrorKind::DanglingKey,
                format!("`book_variant = \"{variant}\"` has no books/{variant}.toml"),
            );
        }
        for b in f.strs("basis").unwrap_or(&[]) {
            if self.view.fact(b).is_none() {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::DanglingKey,
                    format!("basis `{b}` names no fact"),
                );
            }
        }
        // A4's §9.4 marker: a D over a sourced, complete comparison
        // population names the facts that establish its completeness.
        match (f.str("population"), f.strs("population_basis")) {
            (Some(p), _) if p != "sourced_complete" => self.push(
                f.line,
                row,
                LoadErrorKind::UnknownValue,
                format!("`population = \"{p}\"` is \"sourced_complete\" or absent"),
            ),
            (Some(_), None) | (None, Some(_)) => self.push(
                f.line,
                row,
                LoadErrorKind::MissingField,
                "`population` and `population_basis` come together (§9.4)".into(),
            ),
            _ => {}
        }
        for b in f.strs("population_basis").unwrap_or(&[]) {
            if self.view.fact(b).is_none() {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::DanglingKey,
                    format!("population_basis `{b}` names no fact"),
                );
            }
        }
        for (key, parse) in [
            (
                "granularity",
                (|s: &str| Granularity::parse(s).is_some()) as fn(&str) -> bool,
            ),
            ("about", |s| About::parse(s).is_some()),
            ("record_label", |s| RecordLabel::parse(s).is_some()),
            ("known_at", |s| KnownAt::parse(s).is_some()),
        ] {
            if let Some(v) = f.str(key)
                && !parse(v)
            {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::UnknownValue,
                    format!("`{key} = \"{v}\"` is outside its closed set"),
                );
            }
        }
        match e.kind {
            E::D => {
                self.require(f, row, &["procedure", "version"], "a D row");
                self.procedure(f, row);
            }
            E::P => self.p_row(f, row, variant),
            E::N => self.n_row(f, row, variant),
            E::Cf => self.cf_row(e),
            E::T => self.t_row(e, variant),
            E::R => {
                self.reads(e);
                if let Some(p) = f.str("posted")
                    && !self.view.fact_or_intent(variant, p)
                {
                    self.push(
                        f.line,
                        row,
                        LoadErrorKind::DanglingKey,
                        format!(
                            "`posted = \"{p}\"` is neither a fact nor an intent of `{variant}`"
                        ),
                    );
                }
            }
            E::C => {
                self.require(
                    f,
                    row,
                    &["display_unit", "per_row_test", "band", "detection_limit"],
                    "a C row",
                );
                if let Some(d) = f.str("display_unit")
                    && self.view.fact(d).is_none()
                {
                    self.push(f.line, row, LoadErrorKind::DanglingKey, format!("`display_unit = \"{d}\"` names no fact (the fact stating the display unit)"));
                }
            }
        }
    }

    fn procedure(&mut self, f: &Fields, row: &str) {
        let (Some(id), Some(version)) = (f.str("procedure"), f.int("version")) else {
            return;
        };
        let ok = self
            .view
            .procedures
            .get(id)
            .is_some_and(|(v, _)| i128::from(*v) == version);
        if !ok {
            self.push(
                f.line,
                row,
                LoadErrorKind::DanglingKey,
                format!("`{id}@{version}` is not a row of registries/procedures.toml"),
            );
        }
    }

    fn refusal_or(&self, value: &str, also: &[&str]) -> bool {
        also.contains(&value) || self.view.refusals.contains(value)
    }

    fn p_row(&mut self, f: &Fields, row: &str, variant: &str) {
        self.require(
            f,
            row,
            &[
                "intent",
                "refusal",
                "law_row",
                "attribute",
                "reference_verdict",
            ],
            "a P row",
        );
        if let Some(r) = f.str("refusal")
            && !self.view.refusals.contains(r)
        {
            self.push(
                f.line,
                row,
                LoadErrorKind::DanglingKey,
                format!("`refusal = \"{r}\"` is not in registries/refusal_catalog.toml"),
            );
        }
        if let Some(law) = f.str("law_row")
            && !law_row_ok(law)
        {
            self.push(
                f.line,
                row,
                LoadErrorKind::WrongType,
                format!("`law_row = \"{law}\"` is `<registry file>#<row key>` or `plan:§<section>` (no space)"),
            );
        }
        if let Some(a) = f.str("attribute")
            && BranchAttribute::parse(a).is_none()
        {
            self.push(
                f.line,
                row,
                LoadErrorKind::UnknownValue,
                format!("`attribute = \"{a}\"` is outside the §2.6 enum"),
            );
        }
        if let Some(v) = f.str("reference_verdict")
            && !self.refusal_or(v, &["admit", "not_modelled"])
        {
            self.push(
                f.line,
                row,
                LoadErrorKind::UnknownValue,
                format!("`reference_verdict = \"{v}\"` is a refusal id, admit or not_modelled"),
            );
        }
        if let Some(intent) = f.str("intent") {
            let ok = self
                .view
                .books
                .get(variant)
                .is_some_and(|b| b.intents.iter().any(|i| i.fact == intent || i.id == intent));
            if self.view.books.contains_key(variant) && !ok {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::DanglingKey,
                    format!("`intent = \"{intent}\"` has no [[intent]] in `{variant}`"),
                );
            }
        }
    }

    fn n_row(&mut self, f: &Fields, row: &str, variant: &str) {
        self.require(
            f,
            row,
            &["kind", "target", "mechanism", "twin_kind", "twin_expect"],
            "an N row",
        );
        let kind = f.str("kind").and_then(NKind::parse);
        if let Some(k) = f.str("kind")
            && kind.is_none()
        {
            self.push(
                f.line,
                row,
                LoadErrorKind::UnknownValue,
                format!("`kind = \"{k}\"` is no_refusal, no_finding or exact_gap"),
            );
        }
        match kind {
            Some(NKind::NoRefusal) => {
                for k in ["procedure", "version"] {
                    if f.has(k) {
                        self.push(
                            f.line,
                            row,
                            LoadErrorKind::UnknownField,
                            format!(
                                "a no_refusal N observes the kernel's admission; it names no `{k}`"
                            ),
                        );
                    }
                }
            }
            Some(NKind::NoFinding | NKind::ExactGap) => {
                self.require(
                    f,
                    row,
                    &["procedure", "version"],
                    "a no_finding or exact_gap N",
                );
                self.procedure(f, row);
            }
            None => {}
        }
        if kind == Some(NKind::ExactGap) {
            self.require(
                f,
                row,
                &["gap_amount", "gap_unit", "twin_target"],
                "an exact_gap N",
            );
            if let (Some(amount), Some(unit)) = (f.str("gap_amount"), f.str("gap_unit")) {
                match self.view.unit_scales.get(unit) {
                    None => self.push(
                        f.line,
                        row,
                        LoadErrorKind::UnknownValue,
                        format!("`gap_unit = \"{unit}\"` is not a registered unit"),
                    ),
                    Some(scale) => {
                        if let Err(e) = super::amount::parse_amount(amount, *scale) {
                            self.push(
                                f.line,
                                row,
                                LoadErrorKind::WrongType,
                                format!("`gap_amount`: {e}"),
                            );
                        }
                    }
                }
            }
        } else {
            for k in ["gap_amount", "gap_unit", "twin_target"] {
                if f.has(k) {
                    self.push(
                        f.line,
                        row,
                        LoadErrorKind::UnknownField,
                        format!("`{k}` belongs to an exact_gap N"),
                    );
                }
            }
        }
        for key in ["target", "twin_target"] {
            if let Some(t) = f.str(key)
                && !self.view.fact_or_intent(variant, t)
            {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::DanglingKey,
                    format!("`{key} = \"{t}\"` is neither a fact nor an intent of `{variant}`"),
                );
            }
        }
        if let Some(m) = f.str("mechanism") {
            let ok = m.rsplit_once(':').is_some_and(|(path, line)| {
                !path.is_empty() && line.split('-').all(|n| n.parse::<u32>().is_ok())
            });
            if !ok {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::WrongType,
                    format!("`mechanism = \"{m}\"` is `<path>:<line>` at the pinned commit"),
                );
            }
        }
        if let Some(t) = f.str("twin_kind")
            && TwinKind::parse(t).is_none()
        {
            self.push(
                f.line,
                row,
                LoadErrorKind::UnknownValue,
                format!("`twin_kind = \"{t}\"` is mutation, harness_observability or matcher"),
            );
        }
        if let Some(t) = f.str("twin_expect") {
            let ok = t == "reports"
                || t == "gap_zero"
                || t.strip_prefix("refuses ")
                    .is_some_and(|r| self.view.refusals.contains(r));
            if !ok {
                self.push(f.line, row, LoadErrorKind::UnknownValue, format!("`twin_expect = \"{t}\"` is reports, gap_zero or `refuses <a catalogued refusal>`"));
            }
        }
    }

    /// The verdicts an `expect` may state on a row of `ty`.
    fn expect_ok(&self, ty: ExpectationType, value: &str) -> bool {
        match ty {
            E::P => self.refusal_or(value, &["admit"]),
            E::D => matches!(value, "finding" | "no_finding"),
            E::N => self.refusal_or(value, &["admit", "finding", "no_finding"]),
            _ => false,
        }
    }

    fn cf_row(&mut self, e: &Expectation) {
        let f = &e.fields;
        let row = e.id.as_str();
        self.require(
            f,
            row,
            &["parent", "changed_attribute", "changed_value", "expect"],
            "a CF row",
        );
        let parent = f.str("parent").and_then(|p| self.set.get(p));
        match (f.str("parent"), parent) {
            (Some(p), None) => self.push(
                f.line,
                row,
                LoadErrorKind::DanglingKey,
                format!("`parent = \"{p}\"` names no expectation"),
            ),
            (_, Some(p)) if p.kind == E::Cf => self.push(
                f.line,
                row,
                LoadErrorKind::WrongType,
                "a CF's parent is a claim, not another CF".into(),
            ),
            _ => {}
        }
        if let (Some(p), Some(parent)) = (f.str("parent"), parent)
            && !e.id.starts_with(&format!("{p}-CF-"))
        {
            self.push(
                f.line,
                row,
                LoadErrorKind::BadId,
                format!("a CF of `{}` is `{p}-CF-NN`", parent.id),
            );
        }
        if let Some(a) = f.str("changed_attribute")
            && BranchAttribute::parse(a).is_none()
        {
            self.push(
                f.line,
                row,
                LoadErrorKind::UnknownValue,
                format!(
                    "`changed_attribute = \"{a}\"` is one §2.6 attribute (a CF changes exactly one)"
                ),
            );
        }
        if let (Some(v), Some(parent)) = (f.str("expect"), parent)
            && !self.expect_ok(parent.kind, v)
        {
            self.push(
                f.line,
                row,
                LoadErrorKind::UnknownValue,
                format!(
                    "`expect = \"{v}\"` is not a verdict a {} row states",
                    parent.kind.as_str()
                ),
            );
        }
    }

    fn reads(&mut self, e: &Expectation) {
        let targets: Vec<&Target> = self.set.targets_of(&e.id).collect();
        let on_targets = targets.iter().any(|t| t.reads_here());
        let here = e.reads_here();
        let row = e.id.as_str();
        if here && on_targets {
            self.push(
                e.fields.line,
                row,
                LoadErrorKind::ReadFieldsTwice,
                "the read fields sit on the expectation (one read) or on each target (several), never both".into(),
            );
            return;
        }
        let value_key = if e.kind == E::T {
            "published"
        } else {
            "posted"
        };
        let required = ["read_verb", "read_target", "read_coordinate", value_key];
        if here {
            self.require(
                &e.fields,
                row,
                &required,
                &format!("a single-read {} row", e.kind.as_str()),
            );
            self.selector(&e.fields, row, e.fields.str("book_variant").unwrap_or(""));
        } else if on_targets {
            for t in &targets {
                let missing: Vec<&str> = required
                    .iter()
                    .copied()
                    .filter(|k| !t.fields.has(k))
                    .collect();
                if !missing.is_empty() {
                    self.push(
                        t.fields.line,
                        &t.fact,
                        LoadErrorKind::MissingField,
                        format!("a read on a target names {missing:?}"),
                    );
                }
                self.selector(
                    &t.fields,
                    &t.fact,
                    e.fields.str("book_variant").unwrap_or(""),
                );
            }
        } else {
            self.push(e.fields.line, row, LoadErrorKind::MissingField, format!("a {} row names its read (`read_verb`, `read_target`, `read_coordinate`, `{value_key}`)", e.kind.as_str()));
        }
    }

    /// `read_selector`: empty, originally_reported, currently_stated, or
    /// `reported_in:<period label>[#<n>]`, the n-th `issue` step of that
    /// period in step order.
    fn selector(&mut self, f: &Fields, row: &str, variant: &str) {
        let Some(sel) = f.str("read_selector").filter(|s| !s.is_empty()) else {
            return;
        };
        if matches!(sel, "originally_reported" | "currently_stated") {
            return;
        }
        let Some(rest) = sel.strip_prefix("reported_in:") else {
            self.push(f.line, row, LoadErrorKind::UnknownValue, format!("`read_selector = \"{sel}\"` is originally_reported, currently_stated or reported_in:<period>[#<n>]"));
            return;
        };
        let (label, n) = match rest.split_once('#') {
            Some((l, n)) => (l, n.parse::<usize>().ok()),
            None => (rest, Some(1)),
        };
        let Some(n) = n.filter(|n| *n >= 1) else {
            self.push(
                f.line,
                row,
                LoadErrorKind::WrongType,
                format!("`{sel}`: the issuance number is a positive integer"),
            );
            return;
        };
        let Some(book) = self.view.books.get(variant) else {
            return;
        };
        let issues = book
            .steps
            .iter()
            .filter(|s| s.step_kind() == Some(StepKind::Issue) && s.reference == label)
            .count();
        if issues < n {
            self.push(
                f.line,
                row,
                LoadErrorKind::DanglingKey,
                format!("`{sel}` names issuance #{n} of `{label}`; `{variant}` has {issues} issue step(s) for it"),
            );
        }
    }

    fn t_row(&mut self, e: &Expectation, variant: &str) {
        let f = &e.fields;
        let row = e.id.as_str();
        self.require(f, row, &["kind", "vintages"], "a T row");
        let kind = f.str("kind").and_then(TKind::parse);
        if let Some(k) = f.str("kind")
            && kind.is_none()
        {
            self.push(f.line, row, LoadErrorKind::UnknownValue, format!("`kind = \"{k}\"` is bridge, footing, per_account, allocation, delta, rule or round_trip"));
        }
        match (kind, f.str("rule")) {
            (Some(TKind::Rule), None) => self.push(
                f.line,
                row,
                LoadErrorKind::MissingField,
                "a `rule` T names its derivation (`rule`)".into(),
            ),
            (Some(TKind::Rule), Some(r)) if !self.view.derivations.contains(r) => {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::DanglingKey,
                    format!("`rule = \"{r}\"` is not a rule of {}", super::derive::FILE),
                );
            }
            (Some(k), Some(_)) if k != TKind::Rule => {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::UnknownField,
                    "`rule` belongs to a `rule` T".into(),
                );
            }
            _ => {}
        }
        for v in f.strs("vintages").unwrap_or(&[]) {
            let ok = v.split_once(':').is_some_and(|(role, src)| {
                VintageRole::parse(role).is_some() && self.view.is_source(src)
            });
            if !ok {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::DanglingKey,
                    format!("vintage `{v}` is not `<A|D|B|exhibit|source>:<source id>`"),
                );
            }
        }
        for i in f.strs("inputs_named").unwrap_or(&[]) {
            if !self.view.fact_or_intent(variant, i) {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::DanglingKey,
                    format!(
                        "`inputs_named` entry `{i}` is neither a fact nor an intent of `{variant}`"
                    ),
                );
            }
        }
        self.reads(e);
        let mut published: Vec<(&Fields, &str)> = vec![(f, row)];
        published.extend(
            self.set
                .targets_of(&e.id)
                .map(|t| (&t.fields, t.fact.as_str())),
        );
        for (fields, r) in published {
            if let Some(p) = fields.str("published")
                && self.view.fact(p).is_none()
            {
                self.push(
                    fields.line,
                    r,
                    LoadErrorKind::DanglingKey,
                    format!("`published = \"{p}\"` names no fact"),
                );
            }
        }
    }

    fn target(&mut self, t: &Target) {
        let f = &t.fields;
        let row = t.fact.as_str();
        let Some(exp) = self.set.get(&t.expectation) else {
            self.push(
                f.line,
                row,
                LoadErrorKind::DanglingKey,
                format!("`expectation = \"{}\"` names no expectation", t.expectation),
            );
            return;
        };
        let variant = exp.fields.str("book_variant").unwrap_or("");
        if !self.view.fact_or_intent(variant, &t.fact) {
            self.push(
                f.line,
                row,
                LoadErrorKind::DanglingKey,
                format!(
                    "`fact = \"{}\"` is neither a fact nor an intent of `{variant}`",
                    t.fact
                ),
            );
        }
        for b in f.strs("basis").unwrap_or(&[]) {
            if self.view.fact(b).is_none() {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::DanglingKey,
                    format!("basis `{b}` names no fact"),
                );
            }
        }
        for a in f.strs("branch_attrs").unwrap_or(&[]) {
            if BranchAttribute::parse(a).is_none() {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::UnknownValue,
                    format!("branch attribute `{a}` is outside the §2.6 enum"),
                );
            }
        }
        if exp.kind == E::D {
            self.require(
                f,
                row,
                &["cite_status", "severity_status", "statistic_status"],
                "a D target",
            );
            for (name, value_keys) in [
                ("cite", &["cite"][..]),
                ("severity", &["severity"][..]),
                (
                    "statistic",
                    &["statistic_value", "statistic_name", "statistic_scale"][..],
                ),
            ] {
                let Some(raw) = f.str(&format!("{name}_status")) else {
                    continue;
                };
                let Some(status) = Status::parse(raw) else {
                    self.push(f.line, row, LoadErrorKind::UnknownValue, format!("`{name}_status = \"{raw}\"` is S, Sd, Si, B(<attrs>), Rel(account_vid_order) or X"));
                    continue;
                };
                let has_value = f.has(value_keys[0]);
                match status {
                    Status::X if value_keys.iter().any(|k| f.has(k)) => self.push(
                        f.line,
                        row,
                        LoadErrorKind::WrongType,
                        format!("an X {name} is not asserted; it carries no expected value"),
                    ),
                    Status::S | Status::Sd | Status::Si if !has_value => self.push(
                        f.line,
                        row,
                        LoadErrorKind::MissingField,
                        format!(
                            "an asserted {name} ({raw}) states its expected `{}`",
                            value_keys[0]
                        ),
                    ),
                    _ => {}
                }
            }
            self.rel_rule(f, row);
            for c in f.strs("cite").unwrap_or(&[]) {
                let book = self.view.books.get(variant);
                // A leg, an account, the attestation an `assert_balance` step
                // recorded (`attestation:<its ref>`), or a declared period
                // (`period:<code>`): recon.assertion_drift cites all four.
                let ok = if let Some(r) = c.strip_prefix("attestation:") {
                    book.is_some_and(|b| {
                        b.steps.iter().any(|s| {
                            s.step_kind() == Some(super::book::StepKind::AssertBalance)
                                && s.reference == r
                        })
                    })
                } else if let Some(code) = c.strip_prefix("period:") {
                    book.is_some_and(|b| b.periods.iter().any(|p| p.code == code))
                } else {
                    match c.split_once('#') {
                        Some((subject, ordinal)) => {
                            ordinal.parse::<u32>().is_ok()
                                && self.view.fact_or_intent(variant, subject)
                        }
                        None => book.is_some_and(|b| b.accounts.iter().any(|a| a.code == *c)),
                    }
                };
                if !ok {
                    self.push(f.line, row, LoadErrorKind::DanglingKey, format!("cite `{c}` is neither `<fact or intent>#<leg ordinal>`, an account code, `attestation:<assert_balance ref>` nor `period:<code>` of `{variant}`"));
                }
            }
        }
        if exp.kind == E::N {
            self.n_target(exp, t);
        }
    }

    /// A D target with a `Rel(…)` component names the code's selection rule
    /// in `rel_rule`, from the closed list of [`super::rel`]; a target with
    /// no Rel component names none (A5b, §2.6 rule 9). A rule outside the
    /// list, or a role the registry does not list, is refused, so a
    /// misspelled rule never loads as an untested one.
    fn rel_rule(&mut self, f: &Fields, row: &str) {
        let rel = ["cite_status", "severity_status", "statistic_status"]
            .iter()
            .any(|k| matches!(f.str(k).and_then(Status::parse), Some(Status::Rel(_))));
        match (rel, f.str("rel_rule")) {
            (true, None) => self.push(
                f.line,
                row,
                LoadErrorKind::MissingField,
                "a Rel(account_vid_order) component names its `rel_rule`".into(),
            ),
            (false, Some(r)) => self.push(
                f.line,
                row,
                LoadErrorKind::UnknownField,
                format!("`rel_rule = \"{r}\"` on a target with no Rel(…) component"),
            ),
            (true, Some(r)) => {
                let roles = fa_registry::account_roles::AccountRoles::embedded()
                    .map(|r| r.rows.into_iter().map(|row| row.name).collect::<Vec<_>>())
                    .unwrap_or_default();
                let names: Vec<&str> = roles.iter().map(String::as_str).collect();
                if let Err(why) = super::rel::RelRule::parse(r, &names) {
                    self.push(f.line, row, LoadErrorKind::UnknownValue, why);
                }
            }
            (false, None) => {}
        }
    }

    /// An N's `[[target]]` states the sourced value of an exact_gap N's
    /// `target` or `twin_target`, the value its gap is measured from (A11c).
    fn n_target(&mut self, n: &Expectation, t: &Target) {
        let f = &t.fields;
        let row = t.fact.as_str();
        let stat = ["statistic_name", "statistic_value", "statistic_scale"];
        if n.fields.str("kind").and_then(NKind::parse) != Some(NKind::ExactGap) {
            for k in stat.iter().filter(|k| f.has(k)) {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::UnknownField,
                    format!("`{k}` on an N target belongs to an exact_gap N"),
                );
            }
            return;
        }
        if ![n.fields.str("target"), n.fields.str("twin_target")].contains(&Some(row)) {
            self.push(
                f.line,
                row,
                LoadErrorKind::DanglingKey,
                format!(
                    "an exact_gap N's target row is its `target` or `twin_target`, not `{row}`"
                ),
            );
        }
        self.require(f, row, &stat[..2], "an exact_gap N's target row");
        if let Some(v) = f.str("statistic_value")
            && v.parse::<i128>().is_err()
        {
            self.push(
                f.line,
                row,
                LoadErrorKind::WrongType,
                format!(
                    "`statistic_value = \"{v}\"` is the statistic's integer mantissa at its scale"
                ),
            );
        }
    }

    fn cell(&mut self, c: &BranchCell) {
        let f = &c.fields;
        let row = c.target.as_str();
        let Some(exp) = self.set.get(&c.expectation) else {
            self.push(
                f.line,
                row,
                LoadErrorKind::DanglingKey,
                format!("`expectation = \"{}\"` names no expectation", c.expectation),
            );
            return;
        };
        self.require(
            f,
            row,
            &["cell", "expect", "record_consistent"],
            "a branch cell",
        );
        if !matches!(exp.kind, E::D | E::P | E::N) {
            self.push(
                f.line,
                row,
                LoadErrorKind::UnknownValue,
                format!(
                    "branch tables belong to D, P and N rows, not {}",
                    exp.kind.as_str()
                ),
            );
        }
        let Some(target) = self
            .set
            .targets_of(&c.expectation)
            .find(|t| t.fact == c.target)
        else {
            self.push(
                f.line,
                row,
                LoadErrorKind::DanglingKey,
                format!(
                    "`target = \"{}\"` is not a target of {}",
                    c.target, c.expectation
                ),
            );
            return;
        };
        let attrs = target.fields.strs("branch_attrs").unwrap_or(&[]);
        if c.cell.len() != attrs.len() {
            self.push(
                f.line,
                row,
                LoadErrorKind::WrongType,
                format!(
                    "`cell` has {} value(s); the target's branch_attrs {attrs:?} need one each",
                    c.cell.len()
                ),
            );
        }
        if let Some(v) = f.str("expect")
            && !self.expect_ok(exp.kind, v)
        {
            self.push(
                f.line,
                row,
                LoadErrorKind::UnknownValue,
                format!(
                    "`expect = \"{v}\"` is not a verdict a {} row states",
                    exp.kind.as_str()
                ),
            );
        }
        if let Some(p) = f.str("pending").filter(|p| !p.is_empty()) {
            let ok = p
                .split_once(": ")
                .is_some_and(|(item, what)| !item.is_empty() && !what.is_empty());
            if !ok {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::WrongType,
                    format!("`pending = \"{p}\"` is `<item id>: <what it settles>`"),
                );
            }
        }
    }

    fn note(&mut self, n: &Note) {
        let f = &n.fields;
        let row = n.id.as_str();
        self.require(f, row, &["case", "basis", "template"], "a note");
        if let Some(prefix) = self.view.prefix() {
            let ok =
                n.id.strip_prefix(&format!("{prefix}-NOTE-"))
                    .is_some_and(|d| d.len() == 2 && d.bytes().all(|b| b.is_ascii_digit()));
            if !ok {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::BadId,
                    format!("a note of case `{prefix}` is `{prefix}-NOTE-NN`"),
                );
            }
        }
        if let (Some(case), Some(h)) = (f.str("case"), self.view.header)
            && case != h.id
        {
            self.push(
                f.line,
                row,
                LoadErrorKind::DanglingKey,
                format!("`case = \"{case}\"` is not this case (`{}`)", h.id),
            );
        }
        if let Some(t) = f.str("template")
            && t != "NOTE.observation"
        {
            self.push(
                f.line,
                row,
                LoadErrorKind::UnknownValue,
                format!("a note renders with `NOTE.observation`, not `{t}`"),
            );
        }
        for b in f.strs("basis").unwrap_or(&[]) {
            if self.view.fact(b).is_none() {
                self.push(
                    f.line,
                    row,
                    LoadErrorKind::DanglingKey,
                    format!("basis `{b}` names no fact"),
                );
            }
        }
    }

    /// A D row every target of which asserts nothing is a note.
    fn all_x(&mut self) {
        for e in &self.set.expectations {
            if !matches!(e.kind, E::D | E::P) {
                continue;
            }
            let targets: Vec<&Target> = self.set.targets_of(&e.id).collect();
            let statuses = ["cite_status", "severity_status", "statistic_status"];
            let all_x = !targets.is_empty()
                && targets.iter().all(|t| {
                    statuses
                        .iter()
                        .all(|s| t.fields.str(s).and_then(Status::parse) == Some(Status::X))
                });
            if all_x {
                self.push(
                    e.fields.line,
                    &e.id,
                    LoadErrorKind::AllComponentsX,
                    "every component of every target is X: the row can neither pass nor fail, so it is a [[note]]".into(),
                );
            }
        }
    }

    /// `case.toml` `claims`: authored ids, or the runner's generated rows;
    /// a claimed expectation has no pending cell.
    fn claims(&mut self) {
        let Some(h) = self.view.header else {
            return;
        };
        let Some(prefix) = self.view.prefix() else {
            return;
        };
        let generated: BTreeSet<String> = h
            .variants
            .iter()
            .map(|v| format!("{prefix}-SELF-{v}"))
            .chain(
                self.view
                    .books
                    .values()
                    .flat_map(|b| b.cases.iter().map(|c| format!("{prefix}-CASE-{}", c.id))),
            )
            .chain([format!("{prefix}-N-90")])
            .collect();
        for claim in &h.claims {
            if self.set.get(claim).is_none() && !generated.contains(claim) {
                self.errs.push(LoadError {
                    file: super::CASE_FILE.to_string(),
                    line: None,
                    kind: LoadErrorKind::DanglingKey,
                    row: Some(claim.clone()),
                    detail: format!(
                        "claim `{claim}` is neither an expectation nor a generated row of this case"
                    ),
                });
            }
            if let Some(cell) = self
                .set
                .branch_cells
                .iter()
                .find(|c| &c.expectation == claim && c.pending().is_some())
            {
                self.push(
                    cell.fields.line,
                    &cell.target,
                    LoadErrorKind::PendingClaimed,
                    format!(
                        "{claim} is claimed, but its cell {:?} is pending ({}); remove `pending` once its probe settles the cell",
                        cell.cell,
                        cell.pending().unwrap_or_default()
                    ),
                );
            }
        }
    }
}

/// `<registry file>#<row key>` or `plan:§<section>`.
fn law_row_ok(law: &str) -> bool {
    if let Some(section) = law.strip_prefix("plan:§") {
        return !section.is_empty()
            && section
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.');
    }
    law.split_once('#').is_some_and(|(file, key)| {
        file.strip_suffix(".toml").is_some_and(|stem| {
            !stem.is_empty() && stem.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        }) && !key.is_empty()
            && !key.contains(' ')
    })
}

/// The books' refs that name expectations (A1b checks their form; this is
/// the resolution, wired by whichever of A1b and A1c landed second).
pub(crate) fn check_book_refs(
    books: &BTreeMap<String, BookVariant>,
    set: &Expectations,
    errs: &mut Vec<LoadError>,
) {
    for (stem, book) in books {
        let file = format!("books/{stem}.toml");
        let mut recorded: Vec<&str> = Vec::new();
        for s in &book.steps {
            let label = format!("step {}", s.seq);
            let mut push = |kind: LoadErrorKind, detail: String| {
                errs.push(LoadError {
                    file: file.clone(),
                    line: s.line,
                    kind,
                    row: Some(label.clone()),
                    detail,
                });
            };
            match s.step_kind() {
                Some(StepKind::FindingRecord) => recorded.push(s.reference.as_str()),
                Some(StepKind::FindingReview) => {
                    if set.get(&s.reference).is_none() {
                        push(
                            LoadErrorKind::DanglingKey,
                            format!("finding_review names no expectation `{}`", s.reference),
                        );
                    }
                }
                Some(StepKind::AssertBalance) => {
                    let (id, target) = s
                        .reference
                        .split_once('#')
                        .map_or((s.reference.as_str(), None), |(e, t)| (e, Some(t)));
                    match set.get(id) {
                        None => push(
                            LoadErrorKind::DanglingKey,
                            format!("assert_balance names no expectation `{id}`"),
                        ),
                        Some(e) if !matches!(e.kind, E::T | E::R) => push(
                            LoadErrorKind::WrongType,
                            format!(
                                "assert_balance names {id}, a {} row; it asserts a T or R's read",
                                e.kind.as_str()
                            ),
                        ),
                        Some(e) => {
                            let targets: Vec<&Target> = set.targets_of(id).collect();
                            let on_targets = targets.iter().any(|t| t.reads_here());
                            match target {
                                Some(t) if !targets.iter().any(|x| x.fact == t) => {
                                    push(
                                        LoadErrorKind::DanglingKey,
                                        format!("`#{t}` is not a [[target]] of {id}"),
                                    );
                                }
                                None if on_targets && !e.reads_here() => push(
                                    LoadErrorKind::MissingField,
                                    format!(
                                        "{id} reads on its targets; the ref names one (`{id}#<target fact>`)"
                                    ),
                                ),
                                _ => {}
                            }
                        }
                    }
                }
                Some(StepKind::EngagementFile) => {
                    if let Some(id) = s.reference.strip_prefix("finding:") {
                        match set.get(id) {
                            None => push(
                                LoadErrorKind::DanglingKey,
                                format!("`finding:{id}` names no expectation"),
                            ),
                            Some(e) if e.kind != E::D => push(
                                LoadErrorKind::WrongType,
                                format!(
                                    "`finding:{id}` names a {} row; findings come from a D",
                                    e.kind.as_str()
                                ),
                            ),
                            Some(e) => {
                                let pv = format!(
                                    "{}@{}",
                                    e.fields.str("procedure").unwrap_or(""),
                                    e.fields.int("version").unwrap_or_default()
                                );
                                if e.fields.str("book_variant") != Some(stem.as_str()) {
                                    push(
                                        LoadErrorKind::DanglingKey,
                                        format!("{id} runs on another variant, not `{stem}`"),
                                    );
                                } else if !recorded.contains(&pv.as_str()) {
                                    push(
                                        LoadErrorKind::DanglingKey,
                                        format!(
                                            "{id}'s `{pv}` has no earlier finding_record step in `{stem}`"
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
#[path = "expect_tests.rs"]
mod tests;
