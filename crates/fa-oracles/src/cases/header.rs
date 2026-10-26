//! `case.toml`: the case's identity, kind, claims and declared capabilities
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.2, §3.2b), plus the case-local
//! `[[decision]]` rows and the case-specific keys each case item declares in
//! [`CASE_EXTENSIONS`].

use std::collections::BTreeMap;

use fa_registry::toml::{Document, Table, Value as TomlValue};

use super::error::{LoadError, LoadErrorKind};
use super::fields::Row;
use super::rows::{root_key_line, row_line};
use super::source::{closed, put, put_strs};

closed_set! {
    /// What a case is (§3.2): a public-record case, or the harness's own
    /// self-test (exempt from K-BASIS by kind).
    CaseKind {
        Case => "case",
        HarnessSelftest => "harness_selftest",
    }
}

closed_set! {
    /// The kinds of capability token a case declares (`<kind>:<name>[@<version>]`,
    /// read by the coverage gate, A13).
    CapabilityKind {
        Verb => "verb",
        Procedure => "procedure",
        Refusal => "refusal",
        Law => "law",
        Selector => "selector",
        CaseKind => "case_kind",
        Statement => "statement",
        Export => "export",
    }
}

/// The six case letters (§3.2b).
pub const LETTERS: [&str; 6] = ["W", "X", "E", "L", "M", "C"];

/// Keys a case item adds to its own `case.toml` (table `case`) or to its
/// `[[decision]]` rows (table `decision`). A key in neither the header's
/// field list nor its case's row is refused, naming the case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaseExtension {
    pub case: &'static str,
    pub table: &'static str,
    pub keys: &'static [&'static str],
}

/// Every case item that needs its own keys adds a row here (none at A1a).
pub const CASE_EXTENSIONS: &[CaseExtension] = &[];

/// A case-local decision record (E4's vintage decision, E5's outcome, X3's
/// two-book decision).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub id: String,
    pub outcome: String,
    pub facts: Vec<String>,
    pub sources: Vec<String>,
    pub reason: String,
    /// The case's declared extra keys, as authored.
    pub extra: BTreeMap<String, TomlValue>,
    pub line: Option<usize>,
}

/// The parsed `case.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseHeader {
    pub id: String,
    /// The case letter; absent on the harness self-test.
    pub letter: Option<String>,
    pub title: String,
    pub version: i128,
    pub kind: CaseKind,
    pub scope: String,
    /// The expectation ids the case claims complete.
    pub claims: Vec<String>,
    /// Declared capability tokens `<kind>:<name>[@<version>]`.
    pub capabilities: Vec<String>,
    pub pinned_commit: String,
    /// The book-variant stems (`native`, `statement-bridge`, …).
    pub variants: Vec<String>,
    /// Case-specific keys declared in [`CASE_EXTENSIONS`], as authored.
    pub extensions: BTreeMap<String, TomlValue>,
    pub decisions: Vec<Decision>,
}

const DECISION_FIELDS: [&str; 5] = ["id", "outcome", "facts", "sources", "reason"];

fn extension_keys(extensions: &[CaseExtension], case: &str, table: &str) -> Vec<&'static str> {
    extensions
        .iter()
        .filter(|e| e.case == case && e.table == table)
        .flat_map(|e| e.keys.iter().copied())
        .collect()
}

pub(crate) fn parse(
    file: &str,
    text: &str,
    doc: &Document,
    dir_id: &str,
    extensions: &[CaseExtension],
    errs: &mut Vec<LoadError>,
) -> CaseHeader {
    let mut r = Row::new(file, root_key_line(text, "id"), &doc.root);
    let id = r.req_str("id", errs);
    let letter = r.opt_str("letter", errs);
    let title = r.req_str("title", errs);
    let version = r.req_int("version", errs);
    let kind_raw = r.req_str("kind", errs);
    let scope = r.req_str("scope", errs);
    let claims = r.req_strs("claims", errs);
    let capabilities = r.req_strs("capabilities", errs);
    let pinned_commit = r.req_str("pinned_commit", errs);
    let variants = r.req_strs("variants", errs);
    let case_keys = extension_keys(extensions, dir_id, "case");
    r.finish(
        &case_keys,
        &format!(" in case `{dir_id}` (no CASE_EXTENSIONS row declares it)"),
        errs,
    );
    let extensions_found: BTreeMap<String, TomlValue> = doc
        .root
        .iter()
        .filter(|(k, _)| case_keys.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let kind = closed(&r, "kind", &kind_raw, CaseKind::parse, errs).unwrap_or(CaseKind::Case);
    if !id.is_empty() && id != dir_id {
        errs.push(r.err(
            LoadErrorKind::UnknownValue,
            format!("`id = \"{id}\"` differs from the directory it was loaded from (`{dir_id}`)"),
        ));
    }
    match (kind, letter.as_deref()) {
        (CaseKind::Case, None) => {
            errs.push(r.err(LoadErrorKind::MissingField, "a `case` needs its `letter`"))
        }
        (CaseKind::Case, Some(l)) if !LETTERS.contains(&l) => errs.push(r.err(
            LoadErrorKind::UnknownValue,
            format!("`letter = \"{l}\"` is not one of W, X, E, L, M, C"),
        )),
        (CaseKind::HarnessSelftest, Some(_)) => errs.push(r.err(
            LoadErrorKind::UnknownValue,
            "a `harness_selftest` case carries no letter; its id is its prefix",
        )),
        _ => {}
    }
    for token in &capabilities {
        if let Err(why) = check_capability(token) {
            errs.push(r.err(
                LoadErrorKind::WrongType,
                format!("capability `{token}`: {why}"),
            ));
        }
    }
    if !pinned_commit.is_empty()
        && (!(7..=40).contains(&pinned_commit.len())
            || !pinned_commit.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        errs.push(r.err(
            LoadErrorKind::WrongType,
            "`pinned_commit` is a 7–40 character hex commit id",
        ));
    }

    let decision_keys = extension_keys(extensions, dir_id, "decision");
    let mut decisions = Vec::new();
    for (i, table) in doc
        .arrays
        .get("decision")
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .enumerate()
    {
        let mut d = Row::new(file, row_line(text, "decision", i), table);
        let did = d.req_str("id", errs);
        let outcome = d.req_str("outcome", errs);
        let facts = d.req_strs("facts", errs);
        let sources = d.req_strs("sources", errs);
        let reason = d.req_str("reason", errs);
        d.finish(
            &decision_keys,
            &format!(" in case `{dir_id}`'s decision (no CASE_EXTENSIONS row declares it)"),
            errs,
        );
        let extra = table
            .iter()
            .filter(|(k, _)| {
                !DECISION_FIELDS.contains(&k.as_str()) && decision_keys.contains(&k.as_str())
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        decisions.push(Decision {
            id: did,
            outcome,
            facts,
            sources,
            reason,
            extra,
            line: d.line(),
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
    for name in doc.arrays.keys().filter(|n| n.as_str() != "decision") {
        errs.push(LoadError {
            file: file.to_string(),
            line: row_line(text, name, 0),
            kind: LoadErrorKind::UnknownField,
            row: None,
            detail: format!("unknown array `[[{name}]]`"),
        });
    }
    CaseHeader {
        id,
        letter,
        title,
        version,
        kind,
        scope,
        claims,
        capabilities,
        pinned_commit,
        variants,
        extensions: extensions_found,
        decisions,
    }
}

/// The capability token grammar `<kind>:<name>[@<version>]`.
///
/// # Errors
///
/// Names what does not parse.
pub fn check_capability(token: &str) -> Result<(), String> {
    let (kind, rest) = token
        .split_once(':')
        .ok_or("expected `<kind>:<name>[@<version>]`")?;
    if CapabilityKind::parse(kind).is_none() {
        return Err(format!("`{kind}` is not a capability kind"));
    }
    let (name, version) = match rest.split_once('@') {
        Some((n, v)) => (n, Some(v)),
        None => (rest, None),
    };
    if name.is_empty() || name.chars().any(char::is_whitespace) {
        return Err("the name is non-empty, without spaces".into());
    }
    if version.is_some_and(|v| v.parse::<u32>().is_err()) {
        return Err("the version is an integer".into());
    }
    Ok(())
}

impl CaseHeader {
    /// `case.toml` as a document.
    #[must_use]
    pub fn to_document(&self) -> Document {
        let mut doc = Document::default();
        let t = &mut doc.root;
        put(t, "id", &self.id);
        if let Some(l) = &self.letter {
            put(t, "letter", l);
        }
        put(t, "title", &self.title);
        t.insert("version".into(), TomlValue::Int(self.version));
        put(t, "kind", self.kind.as_str());
        put(t, "scope", &self.scope);
        put_strs(t, "claims", Some(&self.claims));
        put_strs(t, "capabilities", Some(&self.capabilities));
        put(t, "pinned_commit", &self.pinned_commit);
        put_strs(t, "variants", Some(&self.variants));
        for (k, v) in &self.extensions {
            t.insert(k.clone(), v.clone());
        }
        if !self.decisions.is_empty() {
            let rows = self
                .decisions
                .iter()
                .map(|d| {
                    let mut r = Table::new();
                    put(&mut r, "id", &d.id);
                    put(&mut r, "outcome", &d.outcome);
                    put_strs(&mut r, "facts", Some(&d.facts));
                    put_strs(&mut r, "sources", Some(&d.sources));
                    put(&mut r, "reason", &d.reason);
                    for (k, v) in &d.extra {
                        r.insert(k.clone(), v.clone());
                    }
                    r
                })
                .collect();
            doc.arrays.insert("decision".into(), rows);
        }
        doc
    }
}
