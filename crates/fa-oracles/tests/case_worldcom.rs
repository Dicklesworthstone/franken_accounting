//! The committed WorldCom case at load time (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §15 W1): the sources ledger, the pilot slice and the two assurance facts
//! bind offline, and each planted negative edits an in-memory copy of the
//! embedded case text and is refused by the check that owns it. The committed
//! files are never edited. W2 and W3 add theirs here.
//!
//! The slice has no F4-p26 fact (its `entry:F4` scope needs A8's F4
//! interpretation), so the negatives the plan states on F4's p.26 rows plant
//! on F9's, the slice's exact-dollar entry.

use std::collections::BTreeMap;

use fa_oracles::cases::check::{CheckFailure, Verdict, run_load_checks};
use fa_oracles::cases::date::Day;
use fa_oracles::cases::embedded::WORLDCOM;
use fa_oracles::cases::error::{LoadError, LoadErrorKind};
use fa_oracles::cases::fact::{Provenance, values_canonical};
use fa_oracles::cases::{Case, CaseFiles, load};
use fa_oracles::sha256;

type Files = Vec<(&'static str, String)>;

/// The sourced facts: the pilot slice's four entry sentences and four
/// periods, the assurance facts of SRC-WC-401 and SRC-WC-406 (W1), p.26's
/// exact amount for F4 (A8), W2's sixteen sentences of F1, F3 and F6-F11
/// with the 4Q01 heading, W2's twenty-five instruction-document, context,
/// second-source and AN-100 sentences, and its eight statement cells.
const SOURCED: usize = 60;

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
/// W2's F1, F5, F6, F6-approval, F8, F10, F11, F13 and F12F13-doc), the
/// booking dates, F2's two booking days, the 1Q01 earnings release's date,
/// and the two statement-level derivations (the EX-27 dollars and the
/// FY2000 reclassification).
const FACTS: usize = SOURCED + 11 + DATES.len() + 4;

/// W1's sources ledger, in file order.
const SOURCES: [&str; 10] = [
    "SRC-WC-001",
    "SRC-WC-002",
    "SRC-WC-003",
    "SRC-WC-004",
    "SRC-WC-401",
    "SRC-WC-406",
    "SRC-WC-EX27-1999",
    "SRC-WC-005",
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
    // F2's "Over the course of April 23 and 24": a branch over two days,
    // Monday and Tuesday.
    assert!(r.rows.iter().any(|row| row == "F2-date"));
    let f2 = case
        .values
        .iter()
        .find(|v| v.fact == "F2-date")
        .expect("F2's days");
    assert_eq!(f2.value, "2001-04-23..2001-04-24");
    assert_eq!(
        ["2001-04-23", "2001-04-24"].map(|d| Day::parse(d).map(Day::weekday)),
        [Some("Monday"), Some("Tuesday")]
    );
}

/// AN-100 (§6.2): ¶34's "in or around February 2002" is a bare month, read
/// as `2002-02` (a branch over its 28 days: 2002 is not a leap year), and no
/// expectation's basis reaches an `AN100-*` fact through any interpretation
/// or derivation, so F10's date rests on the report alone.
#[test]
fn wc_an100_is_a_bare_month_no_expectation_rests_on() {
    let case = load_copy(&worldcom()).expect("the committed case loads");
    for id in ["AN100-1", "AN100-2"] {
        let v = case
            .values
            .iter()
            .find(|v| v.fact == id && v.rule.as_str() == "month_literal")
            .expect("its month");
        assert_eq!(
            (v.literal.as_str(), v.value.as_str()),
            ("February 2002", "2002-02")
        );
    }
    assert!(Day::parse("2002-02-28").is_some() && Day::parse("2002-02-29").is_none());
    let from = |id: &str| -> Vec<String> {
        match case
            .facts
            .iter()
            .find(|f| f.id == id)
            .map(|f| &f.provenance)
        {
            Some(Provenance::Interpretation(i)) => i.from.clone(),
            Some(Provenance::Derived(d)) => d.from.clone(),
            _ => Vec::new(),
        }
    };
    let expectations = case.expectations.as_ref().expect("expectations");
    for e in &expectations.expectations {
        let mut stack: Vec<String> = e.fields.strs("basis").unwrap_or(&[]).to_vec();
        let mut seen = std::collections::BTreeSet::new();
        while let Some(id) = stack.pop() {
            assert!(!id.starts_with("AN100-"), "{} rests on {id}", e.id);
            if seen.insert(id.clone()) {
                stack.extend(from(&id));
            }
        }
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

/// The research's own scope error (§2.1): ¶29 is about the first quarter of
/// 2001, so re-scoping it to F12 (a 1Q02 entry) after `verify` fails
/// offline: its receipt's values_sha256 binds the scope.
#[test]
fn wc_p29_rescoped_to_f12_fails_k_bind_offline() {
    let mut files = worldcom();
    edit_row(
        &mut files,
        "facts.toml",
        "id = \"W-CTX-support-p29\"\n",
        "about_scope = \"period:2001Q1\"",
        "about_scope = \"entry:F12\"",
    );
    check_fails(
        &files,
        "K-BIND",
        "W-CTX-support-p29",
        &["values_sha256 mismatch"],
    );
}

/// p.108 states only "$560 million": rewriting its value as p.26's exact
/// dollars fails offline, which is why F4 is an interpretation of the two.
#[test]
fn wc_f4_p108_exact_dollar_value_fails_k_bind_offline() {
    let mut files = worldcom();
    let marker = "fact = \"F4F5-p108\"\nordinal = 2\n";
    edit_row(
        &mut files,
        "facts.toml",
        marker,
        "literal = \"$560 million\"\nrule = \"scale\"\nparam = 6",
        "literal = \"$560,000,000\"\nrule = \"scale\"\nparam = 0",
    );
    edit_row(
        &mut files,
        "facts.toml",
        marker,
        "precision = 6",
        "precision = 0",
    );
    check_fails(&files, "K-BIND", "F4F5-p108", &["values_sha256 mismatch"]);
}

/// The Post-it reading is an interpretation: no registered rule produces
/// it, so typing it `derived` fails K-DERIVE naming the fact.
#[test]
fn wc_postit_typed_derived_fails_k_derive() {
    let mut files = worldcom();
    let marker = "id = \"F12F13-doc\"\n";
    let rationale = {
        let t = text(&files, "facts.toml");
        let at = t.find(marker).expect("the row") + marker.len();
        let start = at + t[at..].find("rationale = ").expect("its rationale");
        let end = start + t[start..].find('\n').expect("one line") + 1;
        t[start..end].to_string()
    };
    edit_row(&mut files, "facts.toml", marker, &rationale, "");
    edit_row(
        &mut files,
        "facts.toml",
        marker,
        "provenance = \"interpretation\"",
        "provenance = \"derived\"",
    );
    edit_row(
        &mut files,
        "facts.toml",
        marker,
        "reader = \"case-author-1\"\nsecond_reader = \"case-second-reader\"\n",
        "rule = \"postit_is_instruction_document\"\nparams = []\n",
    );
    check_fails(
        &files,
        "K-DERIVE",
        "F12F13-doc",
        &["`postit_is_instruction_document` is not in the derivation table"],
    );
}

/// The exact amounts the T rows rest on, each a checked i128 of cents read
/// from the committed values (no float anywhere): p.26's $560,000,000,
/// F9's $742,725,000, the restating filing's "previously reported" FY2000
/// total and the EX-27's FY1999 total at its multiplier.
#[test]
fn wc_scaled_amounts_are_exact() {
    let case = load_copy(&worldcom()).expect("the committed case loads");
    let cents = |fact: &str, ordinal: i128| -> i128 {
        let v = case
            .values
            .iter()
            .find(|v| v.fact == fact && v.ordinal == ordinal)
            .expect("the value");
        v.value.parse().expect("an integer value")
    };
    assert_eq!(cents("F4-p26", 1), 56_000_000_000);
    assert_eq!(cents("F9", 1), 74_272_500_000);
    assert_eq!(cents("W-ST-ta2000-prev", 1), 9_872_700_000_000);
    assert_eq!(cents("W-ST-ta1999-ex27", 1), 9_107_200_000_000);
    assert_eq!(cents("W-ST-ta2000-reclass", 1), 17_600_000_000);
}

/// W-T-02's A, both deltas and B are four facts with four anchors, so no B
/// value feeds an A or a delta (the K-TAUT precondition W6 relies on). The
/// restated B and the filed figure share the vintage-independent cell key,
/// so K-VINTAGE sees the restating filing supersede the filed one; the
/// restater's "previously reported" A is its own column of that row.
#[test]
fn wc_statement_bridge_inputs_are_three_separate_facts() {
    let case = load_copy(&worldcom()).expect("the committed case loads");
    let ids = [
        "W-ST-ta2000-prev",
        "W-ST-ta2000-adj1",
        "W-ST-ta2000-adj2",
        "W-ST-ta2000-restated",
    ];
    let sourced: Vec<_> = ids
        .iter()
        .map(|id| {
            case.facts
                .iter()
                .find(|f| f.id == *id)
                .and_then(|f| f.sourced())
                .expect("a sourced cell")
        })
        .collect();
    let anchors: std::collections::BTreeSet<&str> =
        sourced.iter().map(|s| s.anchor.as_str()).collect();
    assert_eq!(anchors.len(), 4, "{anchors:?}");
    assert!(sourced.iter().all(|s| s.source == "SRC-WC-406"));
    let cell = |id: &str| {
        case.facts
            .iter()
            .find(|f| f.id == id)
            .and_then(|f| f.sourced())
            .and_then(|s| s.cell.clone())
    };
    for id in ["W-ST-ta2000-restated", "W-ST-ta2000-filed"] {
        assert_eq!(cell(id).as_deref(), Some("total_assets@2000-12-31"), "{id}");
    }
    assert_eq!(
        cell("W-ST-ta2000-prev").as_deref(),
        Some("total_assets:previously_reported@2000-12-31")
    );
}

/// The previously reported FY2000 total rewritten as the filed vintage's
/// 98,903 after `verify` fails offline.
#[test]
fn wc_ta2000_prev_value_edited_fails_k_bind_offline() {
    let mut files = worldcom();
    let marker = "fact = \"W-ST-ta2000-prev\"\n";
    edit_row(
        &mut files,
        "facts.toml",
        marker,
        "literal = \"98,727\"",
        "literal = \"98,903\"",
    );
    edit_row(
        &mut files,
        "facts.toml",
        marker,
        "value = \"9872700000000\"",
        "value = \"9890300000000\"",
    );
    check_fails(
        &files,
        "K-BIND",
        "W-ST-ta2000-prev",
        &["values_sha256 mismatch"],
    );
}

/// The previously reported figure re-pointed at the filed 10-K405: its
/// receipt names the restating filing, so the load refuses the copy.
#[test]
fn wc_ta2000_prev_repointed_to_401_fails_receipt_mismatch() {
    let mut files = worldcom();
    edit_row(
        &mut files,
        "facts.toml",
        "id = \"W-ST-ta2000-prev\"\n",
        "source = \"SRC-WC-406\"",
        "source = \"SRC-WC-401\"",
    );
    let line = row_header_line(&files, "receipts.toml", "fact = \"W-ST-ta2000-prev\"\n");
    refused(
        &files,
        LoadErrorKind::ReceiptMismatch,
        "receipts.toml",
        "W-ST-ta2000-prev",
        line,
        &["receipt source `SRC-WC-406` differs from the fact's `SRC-WC-401`"],
    );
}

/// The EX-27 multiplier read as 1,000 makes the derived FY1999 total a
/// thousand times too small: K-DERIVE names the derived fact.
#[test]
fn wc_ex27_multiplier_edited_fails_k_derive() {
    let mut files = worldcom();
    let marker = "fact = \"W-ST-ex27-1999-mult\"\n";
    edit_row(
        &mut files,
        "facts.toml",
        marker,
        "literal = \"1,000,000\"",
        "literal = \"1,000\"",
    );
    edit_row(
        &mut files,
        "facts.toml",
        marker,
        "value = \"1000000\"",
        "value = \"1000\"",
    );
    check_fails(
        &files,
        "K-DERIVE",
        "W-ST-ta1999-ex27",
        &["expected 9107200000000, computed 9107200000"],
    );
}

/// An EX-27 cell re-anchored as a line (its receipt made consistent, so the
/// load accepts the copy) is refused by K-ANCHOR: the schedule's
/// anchor_scheme is table_cell only.
#[test]
fn wc_ex27_fact_anchored_line_fails_k_anchor() {
    let mut files = worldcom();
    let anchor = "FINANCIAL DATA SCHEDULE DEC. 31, 1999|<TOTAL-ASSETS>|<C>";
    edit_row(
        &mut files,
        "facts.toml",
        "id = \"W-ST-ex27-1999-ta\"\n",
        &format!("anchor_kind = \"table_cell\"\nanchor = \"{anchor}\""),
        "anchor_kind = \"line\"\nanchor = \"l8667-8667\"",
    );
    let receipt = "fact = \"W-ST-ex27-1999-ta\"\n";
    edit_row(
        &mut files,
        "receipts.toml",
        receipt,
        &format!("anchor = \"{anchor}\""),
        "anchor = \"l8667-8667\"",
    );
    edit_row(
        &mut files,
        "receipts.toml",
        receipt,
        "alignment = \"value\"",
        "alignment = \"sentence\"",
    );
    check_fails(
        &files,
        "K-ANCHOR",
        "W-ST-ex27-1999-ta",
        &["`line` is not in source SRC-WC-EX27-1999's anchor_scheme"],
    );
}

#[test]
fn wc_fact_citing_blocked_source_is_refused() {
    let mut files = worldcom();
    edit_row(
        &mut files,
        "sources.toml",
        "id = \"SRC-WC-005\"\n",
        "status = \"OK\"",
        "status = \"BLOCKED\"\nstatus_reason = \"unread candidate\"",
    );
    edit_row(
        &mut files,
        "facts.toml",
        "id = \"F2\"\n",
        "source = \"SRC-WC-001\"",
        "source = \"SRC-WC-005\"",
    );
    let line = row_header_line(&files, "facts.toml", "id = \"F2\"\n");
    refused(
        &files,
        LoadErrorKind::UnknownValue,
        "facts.toml",
        "F2",
        line,
        &["SRC-WC-005", "BLOCKED"],
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
         verified_utc = \"2026-10-29T01:59:22Z\"\ntool_version = \"case-fetch-v3\"\n\
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

/// A value's canonical integer: `<fact>#<n>` names its value of ordinal n,
/// a bare fact its first.
fn value_minor(case: &Case, fact: &str) -> i128 {
    let (fact, ordinal) = fact
        .split_once('#')
        .map_or((fact, 1), |(f, n)| (f, n.parse().expect("an ordinal")));
    case.values
        .iter()
        .find(|v| v.fact == fact && v.ordinal == ordinal)
        .expect("a value of the fact at that ordinal")
        .value
        .parse()
        .expect("an integer value")
}

/// W7 (plan §6.3, §6.4): the native Restatement case R1, recomputed from
/// the book, moves expenses by exactly what W-T-03 publishes and W-R-02
/// reads back. Each Δ negates its target, so it debits the line-cost
/// accounts the target credited, and a quarter's expense delta is the sum
/// of its Δs' Expense debits: 2002Q1 is F12's $718 million plus F13's
/// $100 million, p.116 l.5's "$818 million adjustment"; 2001Q1-Q4 are F1,
/// F4, F9 and F10. Every Δ's quarter is among R1's declared periods, which
/// `fa case rehearse` requires the diff to cover.
#[test]
fn w7_case_deltas_recompute_from_the_book() {
    let case = load_copy(&worldcom()).expect("the committed case loads");
    let book = &case.books["native"];
    let quarter = |day: &str| {
        book.periods
            .iter()
            .find(|p| p.start.as_str() <= day && day <= p.end.as_str())
            .map(|p| p.code.clone())
            .expect("a quarter holding the day")
    };
    let expense: Vec<&str> = book
        .accounts
        .iter()
        .filter(|a| a.account_type == "Expense")
        .map(|a| a.code.as_str())
        .collect();
    let r1 = book.cases.iter().find(|c| c.id == "R1").expect("R1");
    let mut deltas: BTreeMap<String, i128> = BTreeMap::new();
    let restated: Vec<_> = book
        .intents
        .iter()
        .filter(|i| i.scenario.as_deref() == Some("restate"))
        .collect();
    assert_eq!(restated.len(), 6, "a Δ for F1, F4, F9, F10, F12 and F13");
    for delta in restated {
        assert_eq!(delta.fact, "derived:negate", "{}", delta.id);
        let target = delta.target.as_deref().expect("a Δ names its target");
        let q = quarter(&delta.effective_date);
        assert!(
            r1.periods.contains(&q),
            "{} falls in {q}, outside R1's periods {:?}",
            delta.id,
            r1.periods
        );
        assert!(
            book.intents.iter().any(|i| i.id == target),
            "{} names {target}",
            delta.id
        );
        for leg in book
            .legs
            .iter()
            .filter(|l| l.intent == delta.id && expense.contains(&l.account.as_str()))
        {
            let (whole, cents) = leg.amount_literal.split_once('.').expect("cents");
            assert_eq!(cents.len(), 2, "{}", leg.amount_literal);
            let minor: i128 = format!("{whole}{cents}").parse().expect("an amount");
            let signed = if leg.side == "Dr" {
                minor
            } else {
                minor.checked_neg().expect("in range")
            };
            let cell = deltas.entry(q.clone()).or_default();
            *cell = cell.checked_add(signed).expect("in range");
        }
    }
    let set = case.expectations.as_ref().expect("expectations");
    let mut read: BTreeMap<String, i128> = BTreeMap::new();
    for (row, key) in [("W-T-03", "published"), ("W-R-02", "posted")] {
        for t in set.targets_of(row) {
            let coordinate = t.fields.str("read_coordinate").expect("a coordinate");
            let fact = t.fields.str(key).expect("the row's value");
            read.insert(coordinate.to_string(), value_minor(&case, fact));
        }
    }
    assert_eq!(deltas, read);
    assert_eq!(deltas["2002Q1"], 81_800_000_000, "$818 million in cents");
}

/// An R row's `posted = "<fact>#<n>"` names that fact's value of ordinal n
/// (W-R-02's F10 target reads p.114's second value, $941 million). A fact
/// the case does not have, or an ordinal that is not a positive integer,
/// is refused at load, naming the row's value.
#[test]
fn w7_posted_ordinal_names_a_fact_and_a_positive_ordinal() {
    for bad in ["F10-p114#0", "F10-p114#two", "F10-p999#2"] {
        let mut files = worldcom();
        edit_row(
            &mut files,
            "expectations.toml",
            "posted = \"F10-p114#2\"",
            "posted = \"F10-p114#2\"",
            &format!("posted = \"{bad}\""),
        );
        let errors = load_copy(&files).expect_err(bad);
        assert!(
            errors
                .iter()
                .any(|e| e.kind == LoadErrorKind::DanglingKey && e.detail.contains(bad)),
            "{bad}: {errors:#?}"
        );
    }
}
