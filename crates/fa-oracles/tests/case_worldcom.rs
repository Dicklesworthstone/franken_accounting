//! The committed WorldCom case at load time (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §15 W1): the pilot slice binds offline, and each planted negative edits an
//! in-memory copy of the embedded case text and is refused by the check that
//! owns it. The committed files are never edited. W2 and W3 add theirs here.
//!
//! The slice has no F4-p26 fact (its `entry:F4` scope needs A8's F4
//! interpretation), so the negatives the plan states on F4's p.26 rows plant
//! on F9's, the slice's exact-dollar entry.

use fa_oracles::cases::check::{CheckFailure, Verdict, run_load_checks};
use fa_oracles::cases::embedded::WORLDCOM;
use fa_oracles::cases::error::{LoadError, LoadErrorKind};
use fa_oracles::cases::fact::values_canonical;
use fa_oracles::cases::{Case, CaseFiles, load};
use fa_oracles::sha256;

type Files = Vec<(&'static str, String)>;

/// The pilot slice's sourced facts: four entry sentences and four periods.
const SOURCED: usize = 8;

fn worldcom() -> Files {
    WORLDCOM
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
    let at = t.find(marker).unwrap();
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
        id: WORLDCOM.id,
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
    // A copy that loads has no errors, and the assertion below names the plant.
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

/// The copy loads and `check` fails on `row` for a reason containing every
/// `needle`.
fn check_fails(files: &Files, check: &str, row: &str, needles: &[&str]) -> CheckFailure {
    let case = load_copy(files).expect("the planted copy loads");
    let report = run_load_checks(&case)
        .into_iter()
        .find(|r| r.check == check)
        .expect("the check ran");
    assert_eq!(
        report.verdict,
        Verdict::Fail,
        "{}",
        report.render(Some("worldcom"))
    );
    let found = report
        .failures
        .iter()
        .find(|f| f.row == row && needles.iter().all(|n| f.reason.contains(n)))
        .cloned();
    assert!(
        found.is_some(),
        "no {check} failure on {row} naming {needles:?}: {:#?}",
        report.failures
    );
    found.expect("asserted above")
}

#[test]
fn wc_pilot_slice_binds_offline() {
    let case = load_copy(&worldcom()).expect("the committed case loads");
    let reports = run_load_checks(&case);
    for check in ["K-PROV", "K-BIND", "K-SCOPE", "K-ANCHOR"] {
        let r = reports.iter().find(|r| r.check == check).expect(check);
        assert_eq!(r.verdict, Verdict::Pass, "{}", r.render(Some("worldcom")));
        assert_eq!((r.examined, r.inputs), (SOURCED, SOURCED), "{check}");
    }
    // No derived fact until W2/A8: K-DERIVE examined nothing, never PASS.
    let derive = reports.iter().find(|r| r.check == "K-DERIVE").unwrap();
    assert_eq!((derive.verdict, derive.examined), (Verdict::Unrun, 0));
    for r in &reports {
        assert_ne!(r.verdict, Verdict::Fail, "{}", r.render(Some("worldcom")));
    }
    let source = &case.sources[0];
    assert_eq!(
        (
            source.id.as_str(),
            source.original_hash_compared,
            source.filed_on.as_deref()
        ),
        ("SRC-WC-001", false, Some("2003-06-09"))
    );
    assert_eq!(case.receipts.len(), SOURCED);
    assert!(case.receipts.iter().all(|r| !r.original_hash_compared));
}

#[test]
fn wc_fact_citing_blocked_source_is_refused() {
    let mut files = worldcom();
    text_mut(&mut files, "sources.toml").push_str(concat!(
        "\n[[source]]\n",
        "id = \"SRC-WC-ABIDE\"\n",
        "title = \"SEC v. Mark P. Abide, Litigation Release 19776\"\n",
        "publisher = \"U.S. Securities and Exchange Commission\"\n",
        "original_url = \"https://www.sec.gov/litigation/litreleases/2006/lr19776.htm\"\n",
        "retrieval_route = \"archive_capture\"\n",
        "original_hash_compared = false\n",
        "retrieved_utc = \"\"\n",
        "sha256 = \"\"\n",
        "format = \"htm\"\n",
        "redistribution_basis = \"government-work\"\n",
        "assertion_status = \"allegation\"\n",
        "anchor_scheme = [\"paragraph\", \"line\"]\n",
        "status = \"BLOCKED\"\n",
        "status_reason = \"unread candidate\"\n",
        "filed_on = \"2006-07-27\"\n",
        "restates = []\n",
    ));
    edit_row(
        &mut files,
        "facts.toml",
        "id = \"F2\"\n",
        "source = \"SRC-WC-001\"",
        "source = \"SRC-WC-ABIDE\"",
    );
    let line = row_header_line(&files, "facts.toml", "id = \"F2\"\n");
    refused(
        &files,
        LoadErrorKind::UnknownValue,
        "facts.toml",
        "F2",
        line,
        &["SRC-WC-ABIDE", "BLOCKED"],
    );
}

#[test]
fn wc_receipt_flipped_binding_fails() {
    let mut files = worldcom();
    edit_row(
        &mut files,
        "receipts.toml",
        "fact = \"F9\"\n",
        "scope_ok = true",
        "scope_ok = false",
    );
    check_fails(&files, "K-SCOPE", "F9", &["scope_ok = false"]);
}

#[test]
fn wc_receipt_hash_mismatch_fails() {
    let mut files = worldcom();
    let fact = "eddbf0b77b3aef09e93cc6dad482b962e60aa11347a729c11c5b1b9c3056aadf";
    let planted = "fddbf0b77b3aef09e93cc6dad482b962e60aa11347a729c11c5b1b9c3056aadf";
    edit_row(
        &mut files,
        "receipts.toml",
        "fact = \"F9\"\n",
        fact,
        planted,
    );
    check_fails(&files, "K-BIND", "F9", &[fact, planted]);
}

#[test]
fn wc_complaint_fact_with_page_anchor_fails_k_anchor() {
    let mut files = worldcom();
    text_mut(&mut files, "sources.toml").push_str(concat!(
        "\n[[source]]\n",
        "id = \"SRC-WC-002\"\n",
        "title = \"SEC v. Betty L. Vinson and Troy M. Normand, complaint\"\n",
        "publisher = \"U.S. Securities and Exchange Commission\"\n",
        "original_url = \"https://www.sec.gov/litigation/complaints/comp17783.htm\"\n",
        "retrieval_route = \"archive_capture\"\n",
        "original_hash_compared = false\n",
        "retrieved_utc = \"\"\n",
        "sha256 = \"\"\n",
        "format = \"htm\"\n",
        "redistribution_basis = \"government-work\"\n",
        "assertion_status = \"allegation\"\n",
        "anchor_scheme = [\"paragraph\"]\n",
        "status = \"OK\"\n",
        "filed_on = \"\"\n",
        "restates = []\n",
    ));
    let quote = "0000000000000000000000000000000000000000000000000000000000000002";
    let scope = "period:2001Q2";
    text_mut(&mut files, "facts.toml").push_str(&format!(
        "\n[[fact]]\nid = \"W-PLANT-002\"\nprovenance = \"sourced\"\nsource = \"SRC-WC-002\"\n\
         anchor_kind = \"page\"\nanchor = \"p3:l1-2\"\nquote_sha256 = \"{quote}\"\n\
         about_scope = \"{scope}\"\ngranularity = \"journal_entry\"\n"
    ));
    // Only the anchor kind is wrong: the receipt is otherwise consistent.
    let values_sha256 = sha256::hex(&sha256::digest(&values_canonical(scope, &[])));
    text_mut(&mut files, "receipts.toml").push_str(&format!(
        "\n[[receipt]]\nsource = \"SRC-WC-002\"\nfact = \"W-PLANT-002\"\nanchor = \"p3:l1-2\"\n\
         verified_utc = \"2026-10-29T01:59:22Z\"\ntool_version = \"case-fetch-v2\"\n\
         extraction_sha256 = \"{quote}\"\nquote_sha256 = \"{quote}\"\nvalues_sha256 = \"{values_sha256}\"\n\
         alignment = \"sentence\"\nquote_found_once = true\naligned = true\nvalues_in_quote = true\n\
         scope_ok = true\noriginal_hash_compared = false\n"
    ));
    check_fails(
        &files,
        "K-ANCHOR",
        "W-PLANT-002",
        &["`page` is not in source SRC-WC-002's anchor_scheme"],
    );
}

#[test]
fn wc_original_hash_compared_mismatch_fails() {
    let mut files = worldcom();
    edit_row(
        &mut files,
        "receipts.toml",
        "fact = \"F9\"\n",
        "original_hash_compared = false",
        "original_hash_compared = true",
    );
    let line = row_header_line(&files, "receipts.toml", "fact = \"F9\"\n");
    refused(
        &files,
        LoadErrorKind::ReceiptMismatch,
        "receipts.toml",
        "F9",
        line,
        &["original_hash_compared = true", "SRC-WC-001"],
    );
}

#[test]
fn wc_value_edited_after_verify_fails_k_bind() {
    // 742,725,000.00 -> 742,725,000.01 USD, its receipt untouched.
    let mut files = worldcom();
    edit_row(
        &mut files,
        "facts.toml",
        "value = \"74272500000\"",
        "value = \"74272500000\"",
        "value = \"74272500001\"",
    );
    check_fails(
        &files,
        "K-BIND",
        "F9",
        &["values_sha256 mismatch", "edited after verify"],
    );

    let mut files = worldcom();
    edit_row(
        &mut files,
        "facts.toml",
        "id = \"F9\"\n",
        "about_scope = \"entry:F9\"",
        "about_scope = \"entry:F2\"",
    );
    check_fails(&files, "K-BIND", "F9", &["values_sha256 mismatch"]);
}

#[test]
fn wc_receipt_alignment_kind_mismatch_fails() {
    let mut files = worldcom();
    edit_row(
        &mut files,
        "receipts.toml",
        "fact = \"F9\"\n",
        "alignment = \"sentence\"",
        "alignment = \"value\"",
    );
    let line = row_header_line(&files, "receipts.toml", "fact = \"F9\"\n");
    refused(
        &files,
        LoadErrorKind::ReceiptMismatch,
        "receipts.toml",
        "F9",
        line,
        &[
            "alignment = \"value\"",
            "`page` fact",
            "expected `sentence`",
        ],
    );
}

#[test]
fn wc_source_row_without_filed_on_fails() {
    let mut files = worldcom();
    edit_row(
        &mut files,
        "sources.toml",
        "id = \"SRC-WC-001\"\n",
        "filed_on = \"2003-06-09\"\n",
        "",
    );
    let line = row_header_line(&files, "sources.toml", "id = \"SRC-WC-001\"\n");
    refused(
        &files,
        LoadErrorKind::MissingField,
        "sources.toml",
        "SRC-WC-001",
        line,
        &["filed_on"],
    );
}

#[test]
fn wc_restates_naming_an_unknown_source_fails() {
    let mut files = worldcom();
    edit_row(
        &mut files,
        "sources.toml",
        "id = \"SRC-WC-001\"\n",
        "restates = []",
        "restates = [\"SRC-WC-499\"]",
    );
    let line = row_header_line(&files, "sources.toml", "id = \"SRC-WC-001\"\n");
    refused(
        &files,
        LoadErrorKind::DanglingKey,
        "sources.toml",
        "SRC-WC-001",
        line,
        &["SRC-WC-499"],
    );
}
