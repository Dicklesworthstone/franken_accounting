//! The committed Enron case at load time (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §7.1, §15 E1): the sources ledger and its four assurance facts load and
//! bind offline, and each planted negative edits an in-memory copy of the
//! embedded case text and is refused by the check that owns it. The
//! committed files are never edited. E2a-E2d and E4 add theirs here.

use fa_oracles::cases::check::{Verdict, run_load_checks};
use fa_oracles::cases::embedded::ENRON;
use fa_oracles::cases::error::{LoadError, LoadErrorKind};
use fa_oracles::cases::source::{self, AnchorKind, Assurance, SourceStatus};
use fa_oracles::cases::{Case, CaseFiles, load};

type Files = Vec<(&'static str, String)>;

/// The ledger's six rows, in file order.
const SOURCES: [&str; 6] = [
    "SRC-ENR-001",
    "SRC-ENR-002",
    "SRC-ENR-003",
    "SRC-ENR-005",
    "SRC-ENR-008",
    "SRC-ENR-402",
];

fn enron() -> Files {
    ENRON
        .files
        .iter()
        .map(|(path, text)| (*path, (*text).to_string()))
        .collect()
}

fn text<'a>(files: &'a Files, file: &str) -> &'a str {
    &files
        .iter()
        .find(|(p, _)| *p == file)
        .expect("a case file")
        .1
}

fn text_mut<'a>(files: &'a mut Files, file: &str) -> &'a mut String {
    &mut files
        .iter_mut()
        .find(|(p, _)| *p == file)
        .expect("a case file")
        .1
}

/// The row of `file` that holds `marker` (from its `[[...]]` header to the
/// next one) with `old` replaced by `new`; `marker` occurs once in the file
/// and `old` once in that row, so a stale plant never silently tests nothing.
fn edit_row(files: &mut Files, file: &str, marker: &str, old: &str, new: &str) {
    let t = text_mut(files, file);
    assert_eq!(t.matches(marker).count(), 1, "marker `{marker}` in {file}");
    let at = t.find(marker).expect("the marker");
    let start = t[..at].rfind("[[").expect("a row header");
    let end = t[at..].find("\n[[").map_or(t.len(), |e| at + e);
    let row = &t[start..end];
    assert_eq!(
        row.matches(old).count(),
        1,
        "plant `{old}` in the `{marker}` row"
    );
    let edited = row.replacen(old, new, 1);
    t.replace_range(start..end, &edited);
}

/// The 1-based line of the `[[...]]` header of the row holding `marker`.
fn row_header_line(files: &Files, file: &str, marker: &str) -> usize {
    let t = text(files, file);
    let at = t.find(marker).expect("the marker");
    let start = t[..at].rfind("[[").expect("a row header");
    t[..start].matches('\n').count() + 1
}

fn load_copy(files: &Files) -> Result<Case, Vec<LoadError>> {
    let view: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
    load(&CaseFiles {
        id: ENRON.id,
        files: &view,
    })
}

/// The load is refused with an error of `kind` in `file` on row `row` at
/// `line` whose detail contains every `needle`.
fn refused(
    files: &Files,
    kind: LoadErrorKind,
    file: &str,
    row: &str,
    line: usize,
    needles: &[&str],
) {
    let errs = load_copy(files).err().unwrap_or_default();
    assert!(
        errs.iter().any(|e| e.kind == kind
            && e.file == file
            && e.row.as_deref() == Some(row)
            && e.line == Some(line)
            && needles.iter().all(|n| e.detail.contains(n))),
        "no {kind:?} in {file}:{line} on {row} naming {needles:?}: {errs:#?}"
    );
}

/// The committed case loads, and every load check that has input rows
/// passes: the four assurance facts lead the facts, every sourced fact
/// (E2d's 2000-12-31 balance-sheet cells included) binds offline through
/// its receipt, and each vintage prints 35 lines and 3 totals.
#[test]
fn enron_ledger_binds_offline() {
    let case = load_copy(&enron()).expect("the committed case loads");
    let ids: Vec<&str> = case.facts.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(
        ids[..4],
        [
            "ASSUR-ENR-002",
            "ASSUR-ENR-003",
            "ASSUR-ENR-008",
            "ASSUR-ENR-402"
        ]
    );
    let sourced = case.facts.iter().filter(|f| f.sourced().is_some()).count();
    assert_eq!(case.receipts.len(), sourced);
    for prefix in ["BS10K-", "BS10Q-"] {
        let cells = ids
            .iter()
            .filter(|id| id.starts_with(prefix) && !id.ends_with("-SFC"))
            .count();
        assert_eq!(cells, 38, "{prefix}");
    }
    for report in run_load_checks(&case) {
        assert_ne!(
            report.verdict,
            Verdict::Fail,
            "{}",
            report.render(Some("enron"))
        );
    }
}

#[test]
fn enron_sources_roundtrip() {
    let case = load_copy(&enron()).expect("the committed case loads");
    let parsed = fa_registry::toml::parse(text(&enron(), "sources.toml"))
        .expect("parses")
        .canonical_bytes();
    assert_eq!(source::to_document(&case.sources).canonical_bytes(), parsed);
}

/// Each row is OK and carries every §4.1 field; each filer row names its
/// assurance and the fact establishing it, and each anchor scheme draws on
/// the §4.1 kinds the row's facts use.
#[test]
fn enron_sources_all_ok_rows_have_fields() {
    let case = load_copy(&enron()).expect("the committed case loads");
    let ids: Vec<&str> = case.sources.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, SOURCES);
    for s in &case.sources {
        assert_eq!(s.status, SourceStatus::Ok, "{}", s.id);
        for (field, value) in [
            ("title", Some(s.title.as_str())),
            ("publisher", Some(s.publisher.as_str())),
            ("original_url", Some(s.original_url.as_str())),
            ("retrieved_utc", Some(s.retrieved_utc.as_str())),
            ("sha256", Some(s.sha256.as_str())),
            ("filed_on", s.filed_on.as_deref()),
            ("notes", s.notes.as_deref()),
        ] {
            assert!(value.is_some_and(|v| !v.is_empty()), "{} {field}", s.id);
        }
        assert_eq!(s.extraction.as_ref().map(Vec::len), Some(3), "{}", s.id);
        assert!(!s.anchor_scheme.is_empty(), "{}", s.id);
        let filer = s.assertion_status.is_filer_statement();
        let assured = s.assurance.is_some_and(|a| a != Assurance::NotApplicable);
        assert_eq!(filer, assured, "{}", s.id);
        assert_eq!(filer, s.assurance_fact.is_some(), "{}", s.id);
    }
    let scheme = |id: &str| {
        case.sources
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.anchor_scheme.clone())
            .expect("a row")
    };
    assert_eq!(
        scheme("SRC-ENR-001"),
        [AnchorKind::Paragraph, AnchorKind::Page]
    );
    assert_eq!(scheme("SRC-ENR-005"), [AnchorKind::Page]);
    for id in ["SRC-ENR-002", "SRC-ENR-003", "SRC-ENR-008", "SRC-ENR-402"] {
        assert_eq!(
            scheme(id),
            [AnchorKind::TableCell, AnchorKind::Line],
            "{id}"
        );
    }
}

#[test]
fn enron_fact_citing_blocked_row_refused() {
    let mut files = enron();
    edit_row(
        &mut files,
        "sources.toml",
        "id = \"SRC-ENR-003\"\n",
        "status = \"OK\"",
        "status = \"BLOCKED\"\nstatus_reason = \"test\"",
    );
    let line = row_header_line(&files, "facts.toml", "id = \"ASSUR-ENR-003\"\n");
    refused(
        &files,
        LoadErrorKind::UnknownValue,
        "facts.toml",
        "ASSUR-ENR-003",
        line,
        &["SRC-ENR-003", "BLOCKED"],
    );
}

/// A receipt copies its source row's `original_hash_compared`; it is not a
/// binding boolean, so a receipt that differs is refused.
#[test]
fn enron_receipt_hash_compared_must_match_source() {
    let mut files = enron();
    edit_row(
        &mut files,
        "receipts.toml",
        "fact = \"ASSUR-ENR-008\"\n",
        "original_hash_compared = false",
        "original_hash_compared = true",
    );
    let line = row_header_line(&files, "receipts.toml", "fact = \"ASSUR-ENR-008\"\n");
    refused(
        &files,
        LoadErrorKind::ReceiptMismatch,
        "receipts.toml",
        "ASSUR-ENR-008",
        line,
        &["original_hash_compared = true", "SRC-ENR-008"],
    );
}

/// ASSUR-ENR-003 anchored by a paragraph, a prose kind SRC-ENR-003's
/// scheme does not name, fails K-ANCHOR (its receipt's sentence alignment
/// still matches, so the loader does not stop the copy first).
#[test]
fn enron_anchor_kind_outside_scheme_refused() {
    let mut files = enron();
    edit_row(
        &mut files,
        "facts.toml",
        "id = \"ASSUR-ENR-003\"\n",
        "anchor_kind = \"line\"\nanchor = \"l497-503\"",
        "anchor_kind = \"paragraph\"\nanchor = \"para1\"",
    );
    edit_row(
        &mut files,
        "receipts.toml",
        "fact = \"ASSUR-ENR-003\"\n",
        "anchor = \"l497-503\"",
        "anchor = \"para1\"",
    );
    let case = load_copy(&files).expect("the planted copy loads");
    let report = run_load_checks(&case)
        .into_iter()
        .find(|r| r.check == "K-ANCHOR")
        .expect("K-ANCHOR ran");
    assert_eq!(
        report.verdict,
        Verdict::Fail,
        "{}",
        report.render(Some("enron"))
    );
    assert!(
        report.failures.iter().any(|f| f.row == "ASSUR-ENR-003"
            && f.reason
                .contains("`paragraph` is not in source SRC-ENR-003's anchor_scheme")),
        "{:#?}",
        report.failures
    );
}

/// A prose fact's receipt claiming value alignment is refused by the
/// receipt cross-check, naming the fact, its anchor kind and the field.
#[test]
fn enron_receipt_alignment_wrong_for_anchor_kind_refused() {
    let mut files = enron();
    edit_row(
        &mut files,
        "receipts.toml",
        "fact = \"ASSUR-ENR-008\"\n",
        "alignment = \"sentence\"",
        "alignment = \"value\"",
    );
    let line = row_header_line(&files, "receipts.toml", "fact = \"ASSUR-ENR-008\"\n");
    refused(
        &files,
        LoadErrorKind::ReceiptMismatch,
        "receipts.toml",
        "ASSUR-ENR-008",
        line,
        &[
            "alignment = \"value\"",
            "`line` fact",
            "expected `sentence`",
        ],
    );
}

/// What K-VINTAGE orders by: the 8-K and the later 10-Q each restate the
/// as-filed 10-Ks, the FY2000 10-K restates (reclassifies) the FY1999
/// one, and no other row restates anything.
#[test]
fn enron_sources_vintage_order() {
    let case = load_copy(&enron()).expect("the committed case loads");
    let row = |id: &str| {
        case.sources
            .iter()
            .find(|s| s.id == id)
            .expect("a row")
            .clone()
    };
    let (eight_k, ten_q) = (row("SRC-ENR-002"), row("SRC-ENR-003"));
    let restates = |r: &source::Source| r.restates.clone().unwrap_or_default();
    for r in [&eight_k, &ten_q] {
        assert_eq!(restates(r), ["SRC-ENR-008", "SRC-ENR-402"], "{}", r.id);
    }
    assert_eq!(eight_k.filed_on.as_deref(), Some("2001-11-08"));
    assert_eq!(ten_q.filed_on.as_deref(), Some("2001-11-19"));
    assert!(ten_q.filed_on > eight_k.filed_on);
    assert_eq!(restates(&row("SRC-ENR-008")), ["SRC-ENR-402"]);
    for id in ["SRC-ENR-001", "SRC-ENR-005", "SRC-ENR-402"] {
        assert!(restates(&row(id)).is_empty(), "{id}");
    }
    // A copy whose 10-Q restates a source the ledger lacks is refused,
    // naming the row.
    let mut files = enron();
    edit_row(
        &mut files,
        "sources.toml",
        "id = \"SRC-ENR-003\"\n",
        "restates = [\"SRC-ENR-008\", \"SRC-ENR-402\"]",
        "restates = [\"SRC-ENR-499\"]",
    );
    let line = row_header_line(&files, "sources.toml", "id = \"SRC-ENR-003\"\n");
    refused(
        &files,
        LoadErrorKind::DanglingKey,
        "sources.toml",
        "SRC-ENR-003",
        line,
        &["SRC-ENR-499"],
    );
}
