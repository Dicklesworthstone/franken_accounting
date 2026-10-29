//! The committed WorldCom case at load time (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §15 W1): the sources ledger, the pilot slice and the two assurance facts
//! bind offline, and each planted negative edits an in-memory copy of the
//! embedded case text and is refused by the check that owns it. The committed
//! files are never edited. W2 and W3 add theirs here.
//!
//! The slice has no F4-p26 fact (its `entry:F4` scope needs A8's F4
//! interpretation), so the negatives the plan states on F4's p.26 rows plant
//! on F9's, the slice's exact-dollar entry.

use fa_oracles::cases::check::{CheckFailure, Verdict, run_load_checks};
use fa_oracles::cases::date::Day;
use fa_oracles::cases::embedded::WORLDCOM;
use fa_oracles::cases::error::{LoadError, LoadErrorKind};
use fa_oracles::cases::fact::values_canonical;
use fa_oracles::cases::{Case, CaseFiles, load};
use fa_oracles::sha256;

type Files = Vec<(&'static str, String)>;

/// The sourced facts: the pilot slice's four entry sentences and four
/// periods, the assurance facts of SRC-WC-401 and SRC-WC-406 (W1), p.26's
/// exact amount for F4 (A8), and W2's thirteen sentences of F1, F3 and
/// F6-F11 with the 4Q01 heading.
const SOURCED: usize = 24;

/// W2's booking dates, derived from year-less days and their reporting
/// periods (`day_in_period`) or from an earlier date (`date_offset`), each
/// with the weekday the plan states or the civil calendar gives.
const DATES: [(&str, &str, &str); 9] = [
    ("F1-date", "2001-04-20", "Friday"),
    ("F5-date", "2001-07-17", "Tuesday"),
    ("F6-date", "2001-08-22", "Wednesday"),
    ("F7-date", "2001-08-25", "Saturday"),
    ("F8-date", "2001-09-20", "Thursday"),
    ("F9-date", "2001-10-19", "Friday"),
    ("F11-date", "2002-01-25", "Friday"),
    ("F12-date", "2002-04-12", "Friday"),
    ("F13-date", "2002-04-17", "Wednesday"),
];

/// Every fact: the sourced ones, the interpretations (A8's F4 and F12;
/// W2's F1, F5, F6, F6-approval, F8, F10, F11 and F13) and the dates.
const FACTS: usize = SOURCED + 10 + DATES.len();

/// W1's sources ledger, in file order.
const SOURCES: [&str; 10] = [
    "SRC-WC-001",
    "SRC-WC-002",
    "SRC-WC-003",
    "SRC-WC-004",
    "SRC-WC-401",
    "SRC-WC-406",
    "SRC-WC-EX27-1999",
    "SRC-WC-ABIDE",
    "SRC-WC-8K-20020626",
    "SRC-WC-8K-20020626-EX991",
];

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
    // K-PROV reads every fact; the binding checks read the sourced ones.
    for (check, n) in [
        ("K-PROV", FACTS),
        ("K-BIND", SOURCED),
        ("K-SCOPE", SOURCED),
        ("K-ANCHOR", SOURCED),
    ] {
        let r = reports.iter().find(|r| r.check == check).expect(check);
        assert_eq!(r.verdict, Verdict::Pass, "{}", r.render(Some("worldcom")));
        assert_eq!((r.examined, r.inputs), (n, n), "{check}");
    }
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
    // Every row is OK and archive-captured; the restating filing names the
    // vintages it restates, and each filer row's assurance rests on a fact.
    let ids: Vec<&str> = case.sources.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, SOURCES);
    for s in &case.sources {
        assert_eq!(s.status.as_str(), "OK", "{}", s.id);
        assert_eq!(s.retrieval_route.as_str(), "archive_capture", "{}", s.id);
        assert!(s.sha256.len() == 64 && s.extraction.is_some(), "{}", s.id);
    }
    let row = |id: &str| case.sources.iter().find(|s| s.id == id).unwrap();
    assert_eq!(
        row("SRC-WC-406").restates.as_deref(),
        Some(&["SRC-WC-401".to_string(), "SRC-WC-EX27-1999".to_string()][..])
    );
    for (id, fact) in [
        ("SRC-WC-401", "W-ST-401-opinion"),
        ("SRC-WC-406", "W-ST-406-item6"),
    ] {
        assert_eq!(row(id).assurance_fact.as_deref(), Some(fact));
    }
}

/// W2's booking dates recompute under K-DERIVE (§6.2): a year-less day takes
/// its year from the period the entry adjusts, F1's written "Friday" agrees
/// with 2001-04-20, F7 is three days after F6 (a Saturday) and F11 two days
/// after F10's dated draft entry.
#[test]
fn wc_derived_dates_recompute() {
    let case = load_copy(&worldcom()).expect("the committed case loads");
    let r = run_load_checks(&case)
        .into_iter()
        .find(|r| r.check == "K-DERIVE")
        .expect("K-DERIVE");
    assert_eq!(r.verdict, Verdict::Pass, "{}", r.render(Some("worldcom")));
    for (id, day, weekday) in DATES {
        assert!(r.rows.iter().any(|row| row == id), "{id} is examined");
        let v = case
            .values
            .iter()
            .find(|v| v.fact == id)
            .expect("a derived value");
        assert_eq!(v.value, day, "{id}");
        assert_eq!(
            Day::parse(day).map(Day::weekday),
            Some(weekday),
            "{id} {day}"
        );
    }
}

#[test]
fn wc_f7_date_edited_fails_k_derive() {
    let mut files = worldcom();
    edit_row(
        &mut files,
        "facts.toml",
        "[[value]]\nfact = \"F7-date\"",
        "value = \"2001-08-25\"",
        "value = \"2001-08-24\"",
    );
    check_fails(
        &files,
        "K-DERIVE",
        "F7-date",
        &["expected 2001-08-24, computed 2001-08-25"],
    );
}

/// F1's day read against the wrong quarter: 2002-04-20 is a Saturday, and
/// the sentence writes Friday, so the year is refused, never guessed.
#[test]
fn wc_f1_date_in_the_wrong_year_fails_its_weekday() {
    let mut files = worldcom();
    edit_row(
        &mut files,
        "facts.toml",
        "id = \"F1-date\"\n",
        "from = [\"F2-period\", ",
        "from = [\"F12F13-period\", ",
    );
    check_fails(
        &files,
        "K-DERIVE",
        "F1-date",
        &["2002-04-20 is a Saturday, but the literal writes Friday"],
    );
}

#[test]
fn wc_fact_citing_blocked_source_is_refused() {
    let mut files = worldcom();
    edit_row(
        &mut files,
        "sources.toml",
        "id = \"SRC-WC-ABIDE\"\n",
        "status = \"OK\"",
        "status = \"BLOCKED\"\nstatus_reason = \"unread candidate\"",
    );
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
    // W1 lands no SRC-WC-002 fact (its paragraph facts are W2's), so the copy
    // adds one with a `page` anchor against the complaint's paragraph scheme.
    let mut files = worldcom();
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
        "id = \"SRC-WC-406\"\n",
        "filed_on = \"2004-03-12\"\n",
        "",
    );
    let line = row_header_line(&files, "sources.toml", "id = \"SRC-WC-406\"\n");
    refused(
        &files,
        LoadErrorKind::MissingField,
        "sources.toml",
        "SRC-WC-406",
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
