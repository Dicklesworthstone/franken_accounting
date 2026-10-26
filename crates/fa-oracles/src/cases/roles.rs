//! `roles.toml`: role labels used in place of real names, and the hashed
//! name deny list (docs/FORENSIC_CASE_STUDIES_PLAN.md §2.8). Principals,
//! parties and step actors resolve against these labels (A1b); K-NAMES
//! (A3c) reads the hashes. Names never appear in clear.

use fa_registry::toml::{Document, Table, Value as TomlValue};

use super::error::{LoadError, LoadErrorKind};
use super::fields::{Row, is_sha256_hex};
use super::rows::row_line;
use super::source::{closed, put, put_opt, put_strs};

closed_set! {
    /// A role from the report (a preparer, an approver) or one the harness
    /// itself acts as (a case approver, the second reader).
    RoleKind {
        Report => "report",
        Harness => "harness",
    }
}

/// One `[[role]]` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Role {
    pub label: String,
    pub kind: RoleKind,
    /// The report's role description, or what the harness uses the role for.
    pub description: String,
    /// The sourced fact describing the role, when there is one.
    pub described_by: Option<String>,
    pub line: Option<usize>,
}

/// The parsed `roles.toml`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Roles {
    pub roles: Vec<Role>,
    /// SHA-256 hashes (64-hex) of normalized name tokens; never names.
    pub deny_hashes: Option<Vec<String>>,
}

pub(crate) fn parse(file: &str, text: &str, doc: &Document, errs: &mut Vec<LoadError>) -> Roles {
    let mut roles = Vec::new();
    for (i, table) in doc
        .arrays
        .get("role")
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .enumerate()
    {
        let label_id = table
            .get("label")
            .and_then(TomlValue::as_str)
            .map(str::to_string);
        let mut r = Row::new(file, row_line(text, "role", i), table).with_id(label_id);
        let label = r.req_str("label", errs);
        let kind_raw = r.req_str("kind", errs);
        let description = r.req_str("description", errs);
        let described_by = r.opt_str("described_by", errs);
        r.finish(&[], "", errs);
        let kind = closed(&r, "kind", &kind_raw, RoleKind::parse, errs).unwrap_or(RoleKind::Report);
        roles.push(Role {
            label,
            kind,
            description,
            described_by,
            line: r.line(),
        });
    }
    let mut deny_hashes = None;
    if let Some(deny) = doc.tables.get("deny") {
        let line = text
            .lines()
            .position(|l| l.trim() == "[deny]")
            .map(|n| n + 1);
        let mut r = Row::new(file, line, deny).with_id(Some("deny".into()));
        let hashes = r.req_strs("hashes", errs);
        r.finish(&[], "", errs);
        for h in &hashes {
            if !is_sha256_hex(h) {
                errs.push(r.err(
                    LoadErrorKind::NotSha256Hex,
                    "every deny-list entry is a 64-hex SHA-256 of a normalized name token, never a name",
                ));
            }
        }
        deny_hashes = Some(hashes);
    }
    for name in doc.tables.keys().filter(|n| n.as_str() != "deny") {
        errs.push(LoadError {
            file: file.to_string(),
            line: None,
            kind: LoadErrorKind::UnknownField,
            row: None,
            detail: format!("unknown table `[{name}]`"),
        });
    }
    Roles { roles, deny_hashes }
}

impl Roles {
    /// `roles.toml` as a document.
    #[must_use]
    pub fn to_document(&self) -> Document {
        let mut doc = Document::default();
        if !self.roles.is_empty() {
            let rows = self
                .roles
                .iter()
                .map(|r| {
                    let mut t = Table::new();
                    put(&mut t, "label", &r.label);
                    put(&mut t, "kind", r.kind.as_str());
                    put(&mut t, "description", &r.description);
                    put_opt(&mut t, "described_by", r.described_by.as_deref());
                    t
                })
                .collect();
            doc.arrays.insert("role".into(), rows);
        }
        if let Some(h) = &self.deny_hashes {
            let mut t = Table::new();
            put_strs(&mut t, "hashes", Some(h));
            doc.tables.insert("deny".into(), t);
        }
        doc
    }
}
