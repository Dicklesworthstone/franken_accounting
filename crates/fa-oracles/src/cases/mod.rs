//! The case model (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.2): a case's files
//! loaded into typed, cross-checked rows.
//!
//! [`load`] reads `case.toml`, `sources.toml`, `facts.toml`, `receipts.toml`
//! and `roles.toml` from a [`CaseFiles`] (a committed case through
//! [`embedded`], or an edited copy in a test), refuses every malformed or
//! inconsistent row with a [`LoadError`] naming its file and line, and
//! returns the [`Case`] only when nothing is wrong. Book variants
//! (`books/<stem>.toml`, A1b) load against the case's other files, and the
//! expectations (`expectations.toml`, A1c) against the books too; the keys
//! between books and expectations resolve once both are loaded.
//!
//! The data format is the registries' TOML subset (`fa_registry::toml`):
//! one-line arrays, basic strings, no floats and no dates (amounts are
//! integer strings at the unit's scale, dates `YYYY-MM-DD` strings), and
//! arrays of tables that do not nest, so values are foreign-key rows.

/// A closed set of string values, parsed and rendered from one list.
macro_rules! closed_set {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            /// Every member, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The member's spelling in the case files.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }

            /// The member spelled `s`, if any.
            #[must_use]
            pub fn parse(s: &str) -> Option<Self> {
                match s {
                    $($text => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

pub mod amount;
pub mod book;
pub mod branch;
pub mod check;
pub mod date;
pub mod derive;
pub mod embedded;
pub mod error;
pub mod expect;
pub mod fact;
mod fields;
pub mod filler;
pub mod harness_verbs;
pub mod header;
pub mod intent_json;
pub mod log;
pub mod names;
pub mod normalize;
pub mod observe;
pub mod phrases;
pub mod receipt;
pub mod remedy;
pub mod roles;
pub mod rows;
pub mod scope;
pub mod selfrow;
pub mod sentence;
pub mod source;
pub mod stream;
pub mod stub;
pub mod sweep;
pub mod templates;
#[cfg(test)]
mod tests;
pub mod tiers;
pub mod trace;
pub mod twin;
pub mod verdict;

use std::collections::{BTreeMap, BTreeSet};

use fa_registry::toml::Document;

pub use book::{BookVariant, VariantKind};
pub use error::{LoadError, LoadErrorKind};
pub use expect::{Expectation, ExpectationType, Expectations};
pub use fact::{Fact, Provenance, Value};
pub use header::{CASE_EXTENSIONS, CaseExtension, CaseHeader, CaseKind};
pub use receipt::{Alignment, Receipt};
pub use roles::Roles;
pub use source::{Assurance, Source, SourceStatus};

/// The files A1a's loaders own.
pub const CASE_FILE: &str = "case.toml";
pub const SOURCES_FILE: &str = "sources.toml";
pub const FACTS_FILE: &str = "facts.toml";
pub const RECEIPTS_FILE: &str = "receipts.toml";
pub const ROLES_FILE: &str = "roles.toml";
pub const EXPECTATIONS_FILE: &str = "expectations.toml";

/// A case's files as (relative path, text) pairs, under the id it is loaded
/// as (the directory name for a committed case).
#[derive(Clone, Copy, Debug)]
pub struct CaseFiles<'a> {
    pub id: &'a str,
    pub files: &'a [(&'a str, &'a str)],
}

impl CaseFiles<'_> {
    #[must_use]
    pub fn text(&self, path: &str) -> Option<&str> {
        self.files.iter().find(|(p, _)| *p == path).map(|(_, t)| *t)
    }
}

/// A loaded case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Case {
    pub header: CaseHeader,
    pub sources: Vec<Source>,
    pub facts: Vec<Fact>,
    pub values: Vec<Value>,
    pub receipts: Vec<Receipt>,
    pub roles: Roles,
    /// The book variants, by stem (A1b).
    pub books: BTreeMap<String, BookVariant>,
    /// Every path among the case's files.
    pub files: Vec<String>,
    /// `expectations.toml`, when the case has one (A1c).
    pub expectations: Option<Expectations>,
    /// Each committed rows file a fact names, by path: its exact text, which
    /// K-BIND hashes and K-DERIVE reads (A3a).
    pub rows: BTreeMap<String, String>,
}

/// Loads a case under the committed [`CASE_EXTENSIONS`].
///
/// # Errors
///
/// Every problem found, sorted by (file, line).
pub fn load(files: &CaseFiles<'_>) -> Result<Case, Vec<LoadError>> {
    load_with(files, CASE_EXTENSIONS)
}

/// Loads a case under the given extension rows (a test can admit a key
/// under a test-only row).
///
/// # Errors
///
/// Every problem found, sorted by (file, line).
pub fn load_with(
    files: &CaseFiles<'_>,
    extensions: &[CaseExtension],
) -> Result<Case, Vec<LoadError>> {
    let mut errs = Vec::new();
    let parse = |name: &str, errs: &mut Vec<LoadError>| -> Option<(String, Document)> {
        let text = files.text(name)?;
        match fa_registry::toml::parse(text) {
            Ok(doc) => Some((text.to_string(), doc)),
            Err(e) => {
                errs.push(LoadError {
                    file: name.to_string(),
                    line: Some(e.line),
                    kind: LoadErrorKind::Toml,
                    row: None,
                    detail: e.message,
                });
                None
            }
        }
    };
    let schema_files = [
        CASE_FILE,
        SOURCES_FILE,
        FACTS_FILE,
        RECEIPTS_FILE,
        ROLES_FILE,
        EXPECTATIONS_FILE,
    ];
    let rows_files: Vec<&str> = files
        .files
        .iter()
        .map(|(p, _)| *p)
        .filter(|p| !schema_files.contains(p))
        .collect();
    let unit_codes: Vec<String> = match fa_registry::units_embedded() {
        Ok(units) => units.into_iter().map(|u| u.code).collect(),
        Err(e) => {
            errs.push(LoadError {
                file: "registries/units.toml".into(),
                line: None,
                kind: LoadErrorKind::Toml,
                row: None,
                detail: e.to_string(),
            });
            Vec::new()
        }
    };

    let header = match parse(CASE_FILE, &mut errs) {
        Some((text, doc)) => Some(header::parse(
            CASE_FILE, &text, &doc, files.id, extensions, &mut errs,
        )),
        None => {
            if files.text(CASE_FILE).is_none() {
                errs.push(missing_file(CASE_FILE));
            }
            None
        }
    };
    let sources = parse(SOURCES_FILE, &mut errs)
        .map(|(text, doc)| {
            only(SOURCES_FILE, &text, &doc, &["source"], &[], &mut errs);
            source::parse_rows(SOURCES_FILE, &text, rows_of(&doc, "source"), &mut errs)
        })
        .unwrap_or_default();
    let (facts, values) = parse(FACTS_FILE, &mut errs)
        .map(|(text, doc)| {
            only(FACTS_FILE, &text, &doc, &["fact", "value"], &[], &mut errs);
            let facts = fact::parse_facts(
                FACTS_FILE,
                &text,
                rows_of(&doc, "fact"),
                &rows_files,
                &mut errs,
            );
            let values = fact::parse_values(
                FACTS_FILE,
                &text,
                rows_of(&doc, "value"),
                &unit_codes,
                &mut errs,
            );
            (facts, values)
        })
        .unwrap_or_default();
    let receipts = parse(RECEIPTS_FILE, &mut errs)
        .map(|(text, doc)| {
            only(RECEIPTS_FILE, &text, &doc, &["receipt"], &[], &mut errs);
            receipt::parse_rows(RECEIPTS_FILE, &text, rows_of(&doc, "receipt"), &mut errs)
        })
        .unwrap_or_default();
    let roles = parse(ROLES_FILE, &mut errs)
        .map(|(text, doc)| {
            only(ROLES_FILE, &text, &doc, &["role"], &["deny"], &mut errs);
            roles::parse(ROLES_FILE, &text, &doc, &mut errs)
        })
        .unwrap_or_default();

    cross_check(&sources, &facts, &values, &receipts, &roles, &mut errs);
    let paths: Vec<&str> = files.files.iter().map(|(p, _)| *p).collect();
    let books = load_books(
        files,
        &book::CaseView {
            sources: &sources,
            facts: &facts,
            values: &values,
            roles: &roles,
            variants: header.as_ref().map(|h| h.variants.as_slice()),
            files: &paths,
        },
        &mut errs,
    );
    let expectations = files.text(EXPECTATIONS_FILE).map(|text| {
        let view = expect::View::new(header.as_ref(), &sources, &facts, &books, &paths, &mut errs);
        let set = expect::parse(&view, EXPECTATIONS_FILE, text, &mut errs);
        expect::check_book_refs(&books, &set, &mut errs);
        set
    });

    let rows: BTreeMap<String, String> = facts
        .iter()
        .filter_map(|f| f.sourced()?.rows_file.as_deref())
        .filter_map(|path| Some((path.to_string(), files.text(path)?.to_string())))
        .collect();
    match header {
        Some(header) if errs.is_empty() => Ok(Case {
            header,
            sources,
            facts,
            values,
            receipts,
            roles,
            books,
            files: paths.iter().map(|p| (*p).to_string()).collect(),
            expectations,
            rows,
        }),
        _ => {
            error::sort(&mut errs);
            Err(errs)
        }
    }
}

/// Every `books/*.toml` file, loaded against the case; every variant
/// `case.toml` declares has its file.
fn load_books(
    files: &CaseFiles<'_>,
    view: &book::CaseView<'_>,
    errs: &mut Vec<LoadError>,
) -> BTreeMap<String, BookVariant> {
    let mut books = BTreeMap::new();
    let book_files: Vec<(&str, &str)> = files
        .files
        .iter()
        .copied()
        .filter(|(p, _)| p.starts_with("books/"))
        .collect();
    if !book_files.is_empty() {
        let registries = book::Registries::embedded(errs);
        for (path, text) in &book_files {
            if let Some(b) = book::parse(view, &registries, path, text, errs) {
                books.insert(b.stem.clone(), b);
            }
        }
    }
    for variant in view.variants.unwrap_or(&[]) {
        let path = format!("books/{variant}.toml");
        if !book_files.iter().any(|(p, _)| *p == path) {
            errs.push(LoadError {
                file: CASE_FILE.to_string(),
                line: rows::root_key_line(files.text(CASE_FILE).unwrap_or(""), "variants"),
                kind: LoadErrorKind::MissingField,
                row: None,
                detail: format!("variant `{variant}` has no {path}"),
            });
        }
    }
    books
}

fn missing_file(name: &str) -> LoadError {
    LoadError {
        file: name.to_string(),
        line: None,
        kind: LoadErrorKind::MissingField,
        row: None,
        detail: "the file is required".into(),
    }
}

fn rows_of<'d>(doc: &'d Document, array: &str) -> &'d [fa_registry::toml::Table] {
    doc.arrays.get(array).map(Vec::as_slice).unwrap_or(&[])
}

/// Refuses root keys, tables and arrays a schema file does not declare.
fn only(
    file: &str,
    text: &str,
    doc: &Document,
    arrays: &[&str],
    tables: &[&str],
    errs: &mut Vec<LoadError>,
) {
    for key in doc.root.keys() {
        errs.push(LoadError {
            file: file.to_string(),
            line: rows::root_key_line(text, key),
            kind: LoadErrorKind::UnknownField,
            row: None,
            detail: format!("unknown root key `{key}`"),
        });
    }
    for name in doc.tables.keys().filter(|n| !tables.contains(&n.as_str())) {
        errs.push(LoadError {
            file: file.to_string(),
            line: None,
            kind: LoadErrorKind::UnknownField,
            row: None,
            detail: format!("unknown table `[{name}]`"),
        });
    }
    for name in doc.arrays.keys().filter(|n| !arrays.contains(&n.as_str())) {
        errs.push(LoadError {
            file: file.to_string(),
            line: rows::row_line(text, name, 0),
            kind: LoadErrorKind::UnknownField,
            row: None,
            detail: format!("unknown array `[[{name}]]`"),
        });
    }
}

fn row_err(
    file: &str,
    line: Option<usize>,
    row: &str,
    kind: LoadErrorKind,
    detail: String,
) -> LoadError {
    LoadError {
        file: file.to_string(),
        line,
        kind,
        row: Some(row.to_string()),
        detail,
    }
}

/// Foreign keys and uniqueness across the files.
fn cross_check(
    sources: &[Source],
    facts: &[Fact],
    values: &[Value],
    receipts: &[Receipt],
    roles: &Roles,
    errs: &mut Vec<LoadError>,
) {
    let mut by_source: BTreeMap<&str, &Source> = BTreeMap::new();
    for s in sources {
        if by_source.insert(s.id.as_str(), s).is_some() {
            errs.push(row_err(
                SOURCES_FILE,
                s.line,
                &s.id,
                LoadErrorKind::DuplicateId,
                "duplicate source id".into(),
            ));
        }
    }
    let mut by_fact: BTreeMap<&str, &Fact> = BTreeMap::new();
    for f in facts {
        if by_fact.insert(f.id.as_str(), f).is_some() {
            errs.push(row_err(
                FACTS_FILE,
                f.line,
                &f.id,
                LoadErrorKind::DuplicateId,
                "duplicate fact id".into(),
            ));
        }
    }
    for s in sources {
        for r in s.restates.iter().flatten() {
            if !by_source.contains_key(r.as_str()) {
                errs.push(row_err(
                    SOURCES_FILE,
                    s.line,
                    &s.id,
                    LoadErrorKind::DanglingKey,
                    format!("`restates` names unknown source `{r}`"),
                ));
            }
        }
        if let Some(af) = &s.assurance_fact
            && by_fact
                .get(af.as_str())
                .and_then(|f| f.sourced())
                .is_none_or(|sf| sf.source != s.id)
        {
            errs.push(row_err(
                SOURCES_FILE,
                s.line,
                &s.id,
                LoadErrorKind::DanglingKey,
                format!("`assurance_fact = \"{af}\"` is not a sourced fact of this source"),
            ));
        }
    }
    let mut cells: BTreeSet<(&str, &str)> = BTreeSet::new();
    for f in facts {
        let dangling = |what: &str, key: &str| {
            row_err(
                FACTS_FILE,
                f.line,
                &f.id,
                LoadErrorKind::DanglingKey,
                format!("`{what}` names unknown `{key}`"),
            )
        };
        match &f.provenance {
            Provenance::Sourced(s) => {
                match by_source.get(s.source.as_str()) {
                    None => errs.push(dangling("source", &s.source)),
                    Some(src) => {
                        if src.status != SourceStatus::Ok {
                            errs.push(row_err(
                                FACTS_FILE,
                                f.line,
                                &f.id,
                                LoadErrorKind::UnknownValue,
                                format!("source `{}` is BLOCKED; facts cite only OK rows", src.id),
                            ));
                        }
                        if s.assurance.is_some()
                            && src.assurance.is_none_or(|a| a == Assurance::NotApplicable)
                        {
                            errs.push(row_err(
                                FACTS_FILE,
                                f.line,
                                &f.id,
                                LoadErrorKind::UnknownValue,
                                format!("a fact `assurance` on source `{}`, which is not a filer statement with an assurance", src.id),
                            ));
                        }
                    }
                }
                if let Some(af) = &s.assurance_fact
                    && by_fact
                        .get(af.as_str())
                        .and_then(|x| x.sourced())
                        .is_none_or(|x| x.source != s.source)
                {
                    errs.push(row_err(
                        FACTS_FILE,
                        f.line,
                        &f.id,
                        LoadErrorKind::DanglingKey,
                        format!(
                            "`assurance_fact = \"{af}\"` is not a sourced fact of the same source"
                        ),
                    ));
                }
                if let Some(c) = &s.complaint
                    && !by_source.contains_key(c.as_str())
                {
                    errs.push(dangling("complaint", c));
                }
                if let Some(c) = &s.cell
                    && !cells.insert((s.source.as_str(), c.as_str()))
                {
                    errs.push(row_err(
                        FACTS_FILE,
                        f.line,
                        &f.id,
                        LoadErrorKind::DuplicateId,
                        format!("source `{}` already has a fact for cell `{c}`", s.source),
                    ));
                }
            }
            Provenance::Interpretation(x) => {
                for from in &x.from {
                    if !by_fact.contains_key(from.as_str()) {
                        errs.push(dangling("from", from));
                    }
                }
            }
            Provenance::Derived(x) => {
                for from in &x.from {
                    if !by_fact.contains_key(from.as_str()) {
                        errs.push(dangling("from", from));
                    }
                }
            }
            Provenance::Synthetic(_) => {}
        }
    }
    let mut ordinals: BTreeSet<(&str, i128)> = BTreeSet::new();
    for v in values {
        if !by_fact.contains_key(v.fact.as_str()) {
            errs.push(row_err(
                FACTS_FILE,
                v.line,
                &v.fact,
                LoadErrorKind::DanglingKey,
                format!("`[[value]]` names unknown fact `{}`", v.fact),
            ));
        }
        if !ordinals.insert((v.fact.as_str(), v.ordinal)) {
            errs.push(row_err(
                FACTS_FILE,
                v.line,
                &v.fact,
                LoadErrorKind::DuplicateId,
                format!(
                    "fact `{}` already has a value with ordinal {}",
                    v.fact, v.ordinal
                ),
            ));
        }
    }
    let mut receipt_facts: BTreeSet<&str> = BTreeSet::new();
    for r in receipts {
        let mismatch = |detail: String| {
            row_err(
                RECEIPTS_FILE,
                r.line,
                &r.fact,
                LoadErrorKind::ReceiptMismatch,
                detail,
            )
        };
        if !receipt_facts.insert(r.fact.as_str()) {
            errs.push(row_err(
                RECEIPTS_FILE,
                r.line,
                &r.fact,
                LoadErrorKind::DuplicateId,
                "a second receipt for this fact".into(),
            ));
        }
        let Some(fact) = by_fact.get(r.fact.as_str()) else {
            errs.push(row_err(
                RECEIPTS_FILE,
                r.line,
                &r.fact,
                LoadErrorKind::DanglingKey,
                format!("receipt for unknown fact `{}`", r.fact),
            ));
            continue;
        };
        let Some(sf) = fact.sourced() else {
            errs.push(mismatch(format!(
                "fact `{}` is not sourced; only sourced facts carry receipts",
                r.fact
            )));
            continue;
        };
        if sf.source != r.source {
            errs.push(mismatch(format!(
                "receipt source `{}` differs from the fact's `{}`",
                r.source, sf.source
            )));
        }
        let expected = if sf.anchor_kind.is_prose() {
            Alignment::Sentence
        } else {
            Alignment::Value
        };
        if r.alignment != expected {
            errs.push(mismatch(format!(
                "`alignment = \"{}\"` on a `{}` fact (expected `{}`)",
                r.alignment.as_str(),
                sf.anchor_kind.as_str(),
                expected.as_str()
            )));
        }
        if let Some(src) = by_source.get(r.source.as_str())
            && src.original_hash_compared != r.original_hash_compared
        {
            errs.push(mismatch(format!(
                "`original_hash_compared = {}` differs from source `{}` (`{}`)",
                r.original_hash_compared, src.id, src.original_hash_compared
            )));
        }
    }
    let mut labels: BTreeSet<&str> = BTreeSet::new();
    for role in &roles.roles {
        if !labels.insert(role.label.as_str()) {
            errs.push(row_err(
                ROLES_FILE,
                role.line,
                &role.label,
                LoadErrorKind::DuplicateId,
                "duplicate role label".into(),
            ));
        }
        if let Some(d) = &role.described_by
            && !by_fact.contains_key(d.as_str())
        {
            errs.push(row_err(
                ROLES_FILE,
                role.line,
                &role.label,
                LoadErrorKind::DanglingKey,
                format!("`described_by` names unknown fact `{d}`"),
            ));
        }
    }
}
