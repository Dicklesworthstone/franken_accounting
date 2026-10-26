//! The load-time checks over the pilot fixture (`tests/fixtures/pilot/`,
//! with its fixture receipts): the pilot passes every check, and each
//! planted violation fails its check with the `FAIL <K-ID> <file>:<line>
//! <row>: <reason>` line (bead fa-yugf.7, A3a). Plants are either text
//! appended to `facts.toml` (so the line is the loader's) or edits of the
//! loaded [`Case`] (a receipt, a value, an anchor).

use super::super::fact::{
    Derived, Fact, Granularity, Interpretation, Provenance, Sourced, Value, values_canonical,
};
use super::super::normalize::quote_sha256;
use super::super::receipt::{Alignment, Receipt};
use super::super::source::{AnchorKind, SourceFormat};
use super::super::tests::{load_files, pilot};
use super::super::{CASE_EXTENSIONS, Case, FACTS_FILE};
use super::bind::rows_block_sha256;
use super::*;
use crate::sha256;

fn pilot_case() -> Case {
    load_files("worldcom", &pilot(), CASE_EXTENSIONS).expect("the pilot loads")
}

/// The pilot with `extra` appended to `facts.toml`.
fn planted(extra: &str) -> Case {
    let mut files = pilot();
    let facts = files
        .iter_mut()
        .find(|(p, _)| *p == FACTS_FILE)
        .expect("facts.toml");
    facts.1.push_str(extra);
    load_files("worldcom", &files, CASE_EXTENSIONS).expect("the planted pilot loads")
}

/// A sourced `[[fact]]` row carrying its quote.
fn quoted_fact(id: &str, anchor: &str, quote: &str, about: &str, granularity: &str) -> String {
    format!(
        "\n[[fact]]\nid = \"{id}\"\nprovenance = \"sourced\"\nsource = \"SRC-WC-001\"\nanchor_kind = \"page\"\nanchor = \"{anchor}\"\nquote_sha256 = \"{}\"\nquote = \"{quote}\"\nabout_scope = \"{about}\"\ngranularity = \"{granularity}\"\n",
        quote_sha256(quote)
    )
}

fn run_with(cx: &Context<'_>, id: &str) -> CheckReport {
    run_load_checks_with(cx, &[])
        .into_iter()
        .find(|r| r.check == id)
        .expect("the check ran")
}

fn run(case: &Case, id: &str) -> CheckReport {
    run_with(&Context::new(case), id)
}

/// The loader's line for fact `id`, as a FAIL line prints it.
fn line_of(case: &Case, id: &str) -> String {
    case.facts
        .iter()
        .find(|f| f.id == id)
        .and_then(|f| f.line)
        .map_or_else(|| "-".to_string(), |l| l.to_string())
}

/// The report's FAIL line for `row` containing `needle`.
fn fail_line(r: &CheckReport, row: &str, needle: &str) -> String {
    let text = r.render(None);
    let found = text
        .lines()
        .find(|l| {
            l.starts_with(&format!("FAIL {} ", r.check))
                && l.contains(&format!(" {row}: "))
                && l.contains(needle)
        })
        .map(str::to_string);
    assert!(
        found.is_some(),
        "no FAIL line for {row} with `{needle}` in:\n{text}"
    );
    found.unwrap_or_default()
}

fn no_fail_for(r: &CheckReport, row: &str) {
    assert!(
        r.failures.iter().all(|f| f.row != row),
        "unexpected failure for {row}:\n{}",
        r.render(None)
    );
}

fn sourced_mut<'c>(case: &'c mut Case, id: &str) -> &'c mut Sourced {
    case.facts
        .iter_mut()
        .find(|f| f.id == id)
        .and_then(|f| match &mut f.provenance {
            Provenance::Sourced(s) => Some(s),
            _ => None,
        })
        .expect("a sourced fact")
}

fn receipt_mut<'c>(case: &'c mut Case, id: &str) -> &'c mut Receipt {
    case.receipts
        .iter_mut()
        .find(|r| r.fact == id)
        .expect("a receipt")
}

/// A fact's receipt rebuilt over its current values and scope (a fresh
/// `verify`).
fn receipt_for(case: &Case, id: &str, anchor: &str, alignment: Alignment) -> Receipt {
    let s = case
        .facts
        .iter()
        .find(|f| f.id == id)
        .and_then(Fact::sourced)
        .expect("a sourced fact");
    let values: Vec<&Value> = case.values.iter().filter(|v| v.fact == id).collect();
    Receipt {
        source: s.source.clone(),
        fact: id.to_string(),
        anchor: anchor.to_string(),
        verified_utc: "2026-10-24T17:00:00Z".into(),
        tool_version: "fixture".into(),
        extraction_sha256: "b5a0b39702ad5d9d1a59945b2d1574f9ef7325b6a2e13dba8f3a2571f2dfb163"
            .into(),
        quote_sha256: s.quote_sha256.clone(),
        values_sha256: sha256::hex(&sha256::digest(&values_canonical(&s.about_scope, &values))),
        alignment,
        quote_found_once: true,
        aligned: true,
        values_in_quote: true,
        scope_ok: true,
        original_hash_compared: false,
        line: None,
    }
}

const ROWS_FILE: &str = "exhibit_b_rows.toml";

/// A fixture rows file with two complaints' blocks.
const ROWS: &str = "# GENERATED fixture rows (two complaints)\n\n[[row]]\ncomplaint = \"SRC-A\"\naccount = \"1ZA001\"\ndate = \"1995-01-03\"\namount_literal = \"1,000\"\n\n[[row]]\ncomplaint = \"SRC-A\"\naccount = \"1ZA001\"\ndate = \"1995-02-01\"\namount_literal = \"500\"\n\n[[row]]\ncomplaint = \"SRC-B\"\naccount = \"1ZB001\"\ndate = \"1996-01-03\"\namount_literal = \"9,000\"\n";

/// SRC-A's block digest, computed independently (Python's hashlib over the
/// byte slice from its first `[[row]]` through `amount_literal = "500"\n`).
const SRC_A_BLOCK_SHA256: &str = "3a8f2e3d7aafad597115b4b1a72be33effc690f15f9c07b34886de046b069f07";
const SRC_B_BLOCK_SHA256: &str = "bd45cd21b6a1ca3ea9865c733a23975a2f3b83105eb0ee8a2f76f11863a886c4";

/// A whole-exhibit fact for SRC-A's block, with its receipt; the source's
/// scheme admits `exhibit`.
fn with_rows_fact(case: &mut Case, quote_sha256: &str, committed: bool) {
    case.facts.push(Fact {
        id: "EXB".into(),
        provenance: Provenance::Sourced(Sourced {
            source: "SRC-WC-001".into(),
            anchor_kind: AnchorKind::Exhibit,
            anchor: "Exhibit B-1|p3-41".into(),
            quote_sha256: quote_sha256.into(),
            quote: None,
            about_scope: "scheme:exhibit-b".into(),
            granularity: Granularity::LedgerRow,
            role: None,
            cell: None,
            rows_file: Some(ROWS_FILE.into()),
            complaint: Some("SRC-A".into()),
            rows_committed: committed,
            assurance: None,
            assurance_fact: None,
        }),
        line: None,
    });
    let receipt = receipt_for(case, "EXB", "p3-41", Alignment::Value);
    case.receipts.push(receipt);
    if committed {
        case.rows.insert(ROWS_FILE.into(), ROWS.into());
    }
    if let Some(src) = case.sources.iter_mut().find(|s| s.id == "SRC-WC-001") {
        src.anchor_scheme.push(AnchorKind::Exhibit);
    }
}

fn derived_fact(id: &str, from: &[&str], rule: &str) -> Fact {
    Fact {
        id: id.into(),
        provenance: Provenance::Derived(Derived {
            from: from.iter().map(|s| (*s).to_string()).collect(),
            rule: rule.into(),
            params: None,
        }),
        line: None,
    }
}

fn value(fact: &str, value: &str, unit: &str) -> Value {
    Value {
        fact: fact.into(),
        ordinal: 1,
        literal: value.into(),
        rule: super::super::fact::LiteralRule::Scale,
        param: Some(0),
        value: value.into(),
        unit: unit.into(),
        precision: Some(0),
        line: None,
    }
}

const P29: &str = "These entries for the first quarter of 2001 were made without any supporting documentation or proper business rationale.";

// --- positive -------------------------------------------------------------

#[test]
fn pilot_facts_pass_k_prov_bind_scope_anchor_derive() {
    let case = pilot_case();
    let reports = run_load_checks(&case);
    let text: String = reports.iter().map(|r| r.render(None)).collect();
    println!("{text}");
    for (check, counts) in [
        ("K-PROV", "examined=8/8"),
        ("K-BIND", "examined=7/7"),
        ("K-SCOPE", "examined=7/7"),
        ("K-ANCHOR", "examined=7/7"),
        ("K-DERIVE", "examined=14/14"),
    ] {
        assert!(
            text.contains(&format!("CHECK {check} PASS {counts}\n")),
            "{check}:\n{text}"
        );
    }
    assert!(!text.contains("\nFAIL "), "{text}");
    let scope = reports
        .iter()
        .find(|r| r.check == "K-SCOPE")
        .expect("K-SCOPE");
    assert_eq!(scope.rows.len(), 7);
    assert!(scope.rows.contains(&"F12".to_string()), "{:?}", scope.rows);
    let derive = reports
        .iter()
        .find(|r| r.check == "K-DERIVE")
        .expect("K-DERIVE");
    assert!(
        derive.rows.contains(&"native:delta-F4#0".to_string()),
        "{:?}",
        derive.rows
    );
    assert_eq!(
        render_case_line(&reports[0]),
        "CHECK worldcom K-PROV PASS examined=8/8"
    );
}

fn render_case_line(r: &CheckReport) -> String {
    r.render(Some("worldcom"))
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

// --- negatives (§15) ------------------------------------------------------

#[test]
fn sec_p29_quote_bound_to_f12_fails_k_scope() {
    let case = planted(&quoted_fact(
        "F12-P29",
        "p116:l11-12",
        P29,
        "entry:F12",
        "journal_entry",
    ));
    let r = run(&case, "K-SCOPE");
    assert_eq!(r.verdict, Verdict::Fail);
    let line = fail_line(&r, "F12-P29", "names period 2001Q1, entry F12 is 2002Q1");
    assert_eq!(
        line,
        format!(
            "FAIL K-SCOPE facts.toml:{} F12-P29: names period 2001Q1, entry F12 is 2002Q1",
            line_of(&case, "F12-P29")
        )
    );
    // The same quote bound to its own quarter passes the word check.
    let ok = planted(&quoted_fact(
        "P29-1Q01",
        "p116:l11-12",
        P29,
        "period:2001Q1",
        "journal_entry",
    ));
    no_fail_for(&run(&ok, "K-SCOPE"), "P29-1Q01");
}

#[test]
fn entered_and_approved_fragment_fails_k_bind_alignment() {
    // A synthetic carrier sentence with a role label for the name (OD 3).
    let carrier = "The director rarely entered and approved entries himself.";
    let case = planted(&quoted_fact(
        "FRAG",
        "p111:l12-14",
        "entered and approved",
        "period:2001Q3",
        "journal_entry",
    ));
    let extraction = move |_: &str| Some(carrier.to_string());
    let mut cx = Context::new(&case);
    cx.extraction = Some(&extraction);
    let r = run_with(&cx, "K-BIND");
    let line = fail_line(&r, "FRAG", "not sentence-aligned");
    assert!(
        line.starts_with(&format!(
            "FAIL K-BIND facts.toml:{} FRAG: ",
            line_of(&case, "FRAG")
        )),
        "{line}"
    );
    fail_line(&r, "FRAG", "not sentence-aligned in the extraction");
}

#[test]
fn quote_occurring_twice_fails_k_bind() {
    let quote = "The ledger was reviewed.";
    let text = "One sentence. The ledger was reviewed. The ledger was reviewed.";
    assert_eq!(super::super::sentence::occurrences(text, quote), 2);
    let case = planted(&quoted_fact(
        "TWICE",
        "p12:l1-3",
        quote,
        "period:2001Q2",
        "statement_line",
    ));
    let extraction = move |_: &str| Some(text.to_string());
    let mut cx = Context::new(&case);
    cx.extraction = Some(&extraction);
    fail_line(&run_with(&cx, "K-BIND"), "TWICE", "found 2 times");
}

#[test]
fn altered_fips_vector_fails() {
    assert_eq!(sha256::check_vectors(&sha256::FIPS_180_4_VECTORS), Ok(()));
    let mut table = sha256::FIPS_180_4_VECTORS;
    table[1].digest_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ae";
    let err = sha256::check_vectors(&table).expect_err("an altered digit fails");
    assert!(err.contains("abc (one block)"), "{err}");
    // The binding hash is the same SHA-256 over the normalized bytes.
    assert_eq!(
        quote_sha256(" abc\n"),
        sha256::FIPS_180_4_VECTORS[1].digest_hex
    );
}

// --- derived negatives ----------------------------------------------------

#[test]
fn receipt_range_outside_the_fact_anchor_fails_k_anchor() {
    let mut case = pilot_case();
    sourced_mut(&mut case, "F4").anchor = "p111:l12-14".into();
    receipt_mut(&mut case, "F4").anchor = "p112:l3-4".into();
    fail_line(
        &run(&case, "K-ANCHOR"),
        "F4",
        "outside the fact's anchor `p111:l12-14`",
    );
    // Found lines inside the declared lines pass.
    receipt_mut(&mut case, "F4").anchor = "p111:l13-14".into();
    no_fail_for(&run(&case, "K-ANCHOR"), "F4");
}

#[test]
fn anchor_kind_not_in_the_source_scheme_fails_k_anchor() {
    let mut case = pilot_case();
    if let Some(src) = case.sources.iter_mut().find(|s| s.id == "SRC-WC-001") {
        src.format = SourceFormat::Pdf;
    }
    let s = sourced_mut(&mut case, "F9");
    s.anchor_kind = AnchorKind::Xbrl;
    s.anchor = "us-gaap:Assets|c-2001".into();
    let rc = receipt_mut(&mut case, "F9");
    rc.anchor = "us-gaap:Assets|c-2001".into();
    rc.alignment = Alignment::Value;
    let r = run(&case, "K-ANCHOR");
    fail_line(
        &r,
        "F9",
        "`xbrl` is not in source SRC-WC-001's anchor_scheme [\"page\"]",
    );
    fail_line(
        &r,
        "F9",
        "a `xbrl` anchor does not suit source SRC-WC-001's format `pdf`",
    );
}

#[test]
fn quote_less_fact_with_values_not_in_quote_fails_k_bind() {
    let mut case = pilot_case();
    receipt_mut(&mut case, "F2").values_in_quote = false;
    fail_line(&run(&case, "K-BIND"), "F2", "a value not in the quote");
}

#[test]
fn quote_less_fact_with_scope_not_ok_fails_k_scope() {
    let mut case = pilot_case();
    receipt_mut(&mut case, "F9").scope_ok = false;
    fail_line(&run(&case, "K-SCOPE"), "F9", "scope_ok = false");
}

#[test]
fn value_edited_after_verify_fails_k_bind_values_sha256() {
    let mut case = pilot_case();
    let v = case
        .values
        .iter_mut()
        .find(|v| v.fact == "F4" && v.ordinal == 1)
        .expect("F4's value");
    assert_eq!(v.value, "56000000000");
    v.value = "56000000001".into();
    let r = run(&case, "K-BIND");
    fail_line(&r, "F4", "values_sha256 mismatch");
    fail_line(&r, "F4", "under scale is 56000000000, not 56000000001");
}

#[test]
fn scope_edited_after_verify_fails_k_bind() {
    let mut case = pilot_case();
    sourced_mut(&mut case, "F4").about_scope = "period:2001Q3".into();
    fail_line(&run(&case, "K-BIND"), "F4", "values_sha256 mismatch");
}

#[test]
fn receipt_alignment_sentence_on_an_xbrl_fact_fails_k_bind() {
    let mut case = pilot_case();
    let s = sourced_mut(&mut case, "W406-TA-2000");
    s.anchor_kind = AnchorKind::Xbrl;
    s.anchor = "us-gaap:Assets|c-2000".into();
    receipt_mut(&mut case, "W406-TA-2000").alignment = Alignment::Sentence;
    fail_line(
        &run(&case, "K-BIND"),
        "W406-TA-2000",
        "receipt alignment `sentence` on a `xbrl` anchor (expected `value`)",
    );
}

#[test]
fn table_cell_value_that_differs_from_the_cell_fails_k_bind() {
    let mut case = pilot_case();
    let s = sourced_mut(&mut case, "W406-TA-2000");
    s.quote = Some("98,72".into());
    s.quote_sha256 = quote_sha256("98,72");
    receipt_mut(&mut case, "W406-TA-2000").quote_sha256 = quote_sha256("98,72");
    fail_line(
        &run(&case, "K-BIND"),
        "W406-TA-2000",
        "value 1 literal `98,727` is not the whole cell or value `98,72`",
    );
    // The whole cell binds (the pilot's hash-first digest stands in for a
    // quote; with the quote present, the fact and receipt carry its hash).
    let mut ok = pilot_case();
    let s = sourced_mut(&mut ok, "W406-TA-2000");
    s.quote = Some("98,727".into());
    s.quote_sha256 = quote_sha256("98,727");
    receipt_mut(&mut ok, "W406-TA-2000").quote_sha256 = quote_sha256("98,727");
    no_fail_for(&run(&ok, "K-BIND"), "W406-TA-2000");
}

#[test]
fn interpretation_with_one_reader_fails_k_prov() {
    let mut case = pilot_case();
    let f = case
        .facts
        .iter_mut()
        .find(|f| f.id == "F4-amount")
        .expect("F4-amount");
    let reader = match &mut f.provenance {
        Provenance::Interpretation(Interpretation {
            reader,
            second_reader,
            ..
        }) => {
            *second_reader = reader.clone();
            reader.clone()
        }
        _ => String::new(),
    };
    assert_eq!(reader, "case-author-1");
    fail_line(&run(&case, "K-PROV"), "F4-amount", "both `case-author-1`");
}

#[test]
fn derived_fact_with_a_wrong_value_fails_k_derive() {
    let mut case = pilot_case();
    // F4 ($560 million) less F4-p26 ($560,000,000) is exactly 0.
    case.facts
        .push(derived_fact("D-ZERO", &["F4", "F4-p26"], "difference"));
    case.values.push(value("D-ZERO", "0", "USD"));
    let r = run(&case, "K-DERIVE");
    no_fail_for(&r, "D-ZERO");
    assert!(r.rows.contains(&"D-ZERO".to_string()));
    case.values.retain(|v| v.fact != "D-ZERO");
    case.values.push(value("D-ZERO", "1", "USD"));
    fail_line(
        &run(&case, "K-DERIVE"),
        "D-ZERO",
        "difference []: expected 1, computed 0",
    );
}

#[test]
fn leg_amount_differing_from_its_rule_fails_k_derive() {
    let mut case = pilot_case();
    let book = case.books.get_mut("native").expect("native");
    let leg = book
        .legs
        .iter_mut()
        .find(|l| l.amount_rule == "value:F9#1")
        .expect("a value:F9#1 leg");
    leg.amount_literal = "742725000.01".into();
    let row = format!("{}#{}", leg.intent, leg.ordinal);
    let line = leg.line;
    let r = run(&case, "K-DERIVE");
    let fail = fail_line(
        &r,
        &row,
        "is 74272500001 minor units; `value:F9#1` is 74272500000",
    );
    assert!(
        fail.starts_with(&format!(
            "FAIL K-DERIVE books/native.toml:{} {row}: ",
            line.map_or_else(|| "-".to_string(), |l| l.to_string())
        )),
        "{fail}"
    );
    // A Δ leg negating a target leg is checked against that leg.
    let mut case = pilot_case();
    let book = case.books.get_mut("native").expect("native");
    let negate = book
        .legs
        .iter_mut()
        .find(|l| l.amount_rule == "derived:negate")
        .expect("a derived:negate leg");
    negate.amount_literal = "1.00".into();
    let row = format!("{}#{}", negate.intent, negate.ordinal);
    fail_line(&run(&case, "K-DERIVE"), &row, "(negated)");
}

#[test]
fn event_resource_amount_differing_from_its_rule_fails_k_derive() {
    let event = |literal: &str| super::super::book::EventDef {
        id: "EV-F2".into(),
        kind: "transfer".into(),
        occurred_on: "2001-03-31".into(),
        evidence: vec!["DOC-PH-F2".into()],
        participants: None,
        resource_label: Some("line costs".into()),
        resource_amount_literal: Some(literal.into()),
        resource_amount_rule: Some("value:F2#1".into()),
        resource_unit: Some("USD".into()),
        line: None,
    };
    let mut case = pilot_case();
    let book = case.books.get_mut("native").expect("native");
    book.events.push(event("402000000.00"));
    let r = run(&case, "K-DERIVE");
    no_fail_for(&r, "EV-F2");
    assert!(r.rows.contains(&"native:EV-F2".to_string()), "{:?}", r.rows);
    let book = case.books.get_mut("native").expect("native");
    book.events.retain(|e| e.id != "EV-F2");
    book.events.push(event("402000000.01"));
    fail_line(
        &run(&case, "K-DERIVE"),
        "EV-F2",
        "is 40200000001 minor units; `value:F2#1` is 40200000000",
    );
}

#[test]
fn check_examining_zero_rows_never_reports_pass() {
    let mut case = pilot_case();
    case.books.clear();
    let r = run(&case, "K-DERIVE");
    assert_eq!(r.verdict, Verdict::Unrun);
    assert_eq!(r.render(None), "CHECK K-DERIVE UNRUN examined=0/0\n");
}

#[test]
fn quote_naming_a_quarter_outside_the_scheme_range_fails_k_scope() {
    let quote = "Reserves were released between July 17–19, 2000.";
    let case = planted(&quoted_fact(
        "E2A",
        "p20:l1-2",
        quote,
        "scheme:reserve-release-2000Q2",
        "period_total",
    ));
    fail_line(
        &run(&case, "K-SCOPE"),
        "E2A",
        "names 2000-07-17..2000-07-19, outside 2000Q2",
    );
    let ok = planted(&quoted_fact(
        "E2A",
        "p20:l1-2",
        quote,
        "scheme:reserve-release-2000Q2-2000Q3",
        "period_total",
    ));
    no_fail_for(&run(&ok, "K-SCOPE"), "E2A");
}

#[test]
fn inverted_and_unparsable_scheme_ranges_fail_the_k_scope_report() {
    let mut case = pilot_case();
    sourced_mut(&mut case, "F2").about_scope = "scheme:x-2001Q2-2001Q1".into();
    sourced_mut(&mut case, "F2").granularity = Granularity::PeriodTotal;
    sourced_mut(&mut case, "F9").about_scope = "scheme:x-2001Q5".into();
    sourced_mut(&mut case, "F9").granularity = Granularity::PeriodTotal;
    let r = run(&case, "K-SCOPE");
    fail_line(&r, "F2", "its range runs backwards");
    fail_line(
        &r,
        "F9",
        "its range tail parses as no quarter, month or day form",
    );
}

#[test]
fn rangeless_scheme_never_range_checks_and_reports_range_none() {
    let quote = "On July 17, 2000 the partnership was formed.";
    let case = planted(&quoted_fact(
        "LJM1",
        "p20:l3-4",
        quote,
        "scheme:spe-ljm1",
        "period_total",
    ));
    let r = run(&case, "K-SCOPE");
    no_fail_for(&r, "LJM1");
    assert!(
        r.rows.contains(&"LJM1 range=none".to_string()),
        "{:?}",
        r.rows
    );
    assert!(r.render(None).contains("LJM1 range=none"));
}

#[test]
fn a_scheme_scope_backing_a_journal_entry_fails_k_scope() {
    let mut case = pilot_case();
    sourced_mut(&mut case, "F2").about_scope = "scheme:capitalization-2001Q1-2002Q1".into();
    fail_line(
        &run(&case, "K-SCOPE"),
        "F2",
        "backs a journal_entry fact only through an interpretation",
    );
}

#[test]
fn pending_rows_fact_and_its_derived_facts_are_counted_unrun() {
    let mut case = pilot_case();
    with_rows_fact(&mut case, SRC_A_BLOCK_SHA256, false);
    case.facts.push(derived_fact("EXB-SUM", &["EXB"], "sum"));
    case.values.push(value("EXB-SUM", "150000", "USD"));
    assert_eq!(
        pending_facts(&case),
        ["EXB".to_string(), "EXB-SUM".to_string()].into()
    );
    let cx = Context::new(&case);
    let bind = run_with(&cx, "K-BIND");
    assert_eq!(
        bind.render(None).lines().next(),
        Some("CHECK K-BIND PASS examined=7/8 unrun=1 (OD 2b)")
    );
    let derive = run_with(&cx, "K-DERIVE");
    assert_eq!(
        derive.render(None).lines().next(),
        Some("CHECK K-DERIVE PASS examined=14/15 unrun=1 (OD 2b)")
    );
    // A case whose only inputs are pending examines nothing: UNRUN.
    let mut only = case.clone();
    only.books.clear();
    assert_eq!(
        run(&only, "K-DERIVE").render(None),
        "CHECK K-DERIVE UNRUN examined=0/1 unrun=1 (OD 2b)\n"
    );
}

#[test]
fn pending_rows_fact_with_a_mismatched_receipt_fails_k_bind() {
    let mut case = pilot_case();
    with_rows_fact(&mut case, SRC_A_BLOCK_SHA256, false);
    receipt_mut(&mut case, "EXB").quote_sha256 = SRC_B_BLOCK_SHA256.into();
    let r = run(&case, "K-BIND");
    assert_eq!(r.pending, 1);
    fail_line(&r, "EXB", "the receipt's quote_sha256");
    assert!(
        r.render(None)
            .starts_with("CHECK K-BIND FAIL examined=7/8 unrun=1 (OD 2b)\n")
    );
}

#[test]
fn rows_fact_hash_is_the_complaint_block_bytes() {
    assert_eq!(
        rows_block_sha256(ROWS, "SRC-A").as_deref(),
        Ok(SRC_A_BLOCK_SHA256)
    );
    assert_eq!(
        rows_block_sha256(ROWS, "SRC-B").as_deref(),
        Ok(SRC_B_BLOCK_SHA256)
    );
    assert!(rows_block_sha256(ROWS, "SRC-C").is_err());
    // A, A, B, A: SRC-A's rows are not one block.
    let split = format!("{ROWS}\n[[row]]\ncomplaint = \"SRC-A\"\naccount = \"1ZA009\"\n");
    assert!(
        rows_block_sha256(&split, "SRC-A").is_err_and(|e| e.contains("not one contiguous block"))
    );
    // A committed rows fact binds by the block hash; one changed amount fails K-BIND.
    let mut case = pilot_case();
    with_rows_fact(&mut case, SRC_A_BLOCK_SHA256, true);
    no_fail_for(&run(&case, "K-BIND"), "EXB");
    case.rows.insert(
        ROWS_FILE.into(),
        ROWS.replace("amount_literal = \"500\"", "amount_literal = \"501\""),
    );
    fail_line(
        &run(&case, "K-BIND"),
        "EXB",
        "rows block of `SRC-A` in exhibit_b_rows.toml hashes to",
    );
}

#[test]
fn exhibit_anchor_on_a_fact_without_rows_file_fails_k_anchor() {
    let mut case = pilot_case();
    let s = sourced_mut(&mut case, "F2");
    s.anchor_kind = AnchorKind::Exhibit;
    s.anchor = "Exhibit B-1|p3-41".into();
    fail_line(
        &run(&case, "K-ANCHOR"),
        "F2",
        "an `exhibit` anchor belongs only to a `rows_file` fact",
    );
}

#[test]
fn exhibit_receipt_with_sentence_alignment_fails_k_bind() {
    let mut case = pilot_case();
    with_rows_fact(&mut case, SRC_A_BLOCK_SHA256, true);
    no_fail_for(&run(&case, "K-ANCHOR"), "EXB");
    receipt_mut(&mut case, "EXB").alignment = Alignment::Sentence;
    fail_line(
        &run(&case, "K-BIND"),
        "EXB",
        "receipt alignment `sentence` on a `exhibit` anchor (expected `value`)",
    );
    fail_line(
        &run(&case, "K-ANCHOR"),
        "EXB",
        "binds by value, not sentence",
    );
}

#[test]
fn part_of_a_heading_line_fails_k_bind_alignment() {
    let text = "The ledger was reviewed.\n\nSELECTED DATA\n\nIt balanced.";
    let case = planted(&quoted_fact(
        "HEAD",
        "p40:l1-1",
        "SELECTED",
        "period:FY2000",
        "statement_line",
    ));
    let extraction = move |_: &str| Some(text.to_string());
    let mut cx = Context::new(&case);
    cx.extraction = Some(&extraction);
    fail_line(&run_with(&cx, "K-BIND"), "HEAD", "not sentence-aligned");
    // The whole heading line is one sentence.
    let s = super::super::sentence::Sentences::new(text);
    let at = s.norm.find("SELECTED DATA").expect("the heading");
    assert!(s.is_aligned(&(at..at + "SELECTED DATA".len())));
}

#[test]
fn case_scoped_check_runs_only_on_its_case() {
    fn probe(case: &Case) -> CheckReport {
        let mut r = CheckReport::new("probe", case.facts.len());
        for f in &case.facts {
            r.examined(f.id.clone());
        }
        r.finish()
    }
    const PROBE: &[CaseCheck] = &[CaseCheck {
        case: "xbrl",
        name: "probe",
        run: probe,
    }];
    let mut case = pilot_case();
    let ids = |case: &Case| -> Vec<String> {
        run_load_checks_with(&Context::new(case), PROBE)
            .into_iter()
            .map(|r| r.check)
            .collect()
    };
    assert_eq!(
        ids(&case),
        [
            "K-PROV",
            "K-BIND",
            "K-SCOPE",
            "K-ANCHOR",
            "K-DERIVE",
            "K-BASIS",
            "K-TAUT",
            "K-ORACLE",
            "K-VINTAGE",
            "K-TIER"
        ]
    );
    case.header.id = "xbrl".into();
    let reports = run_load_checks_with(&Context::new(&case), PROBE);
    let probe = reports.last().expect("a report");
    assert_eq!(probe.check, "case:xbrl:probe");
    assert_eq!(
        probe.render(None).lines().next(),
        Some("CHECK case:xbrl:probe PASS examined=8/8")
    );
    assert!(CASE_CHECKS.is_empty(), "X5 registers the first");
}

#[test]
fn a_missing_receipt_fails_bind_scope_and_anchor() {
    let mut case = pilot_case();
    case.receipts.retain(|r| r.fact != "F12");
    let cx = Context::new(&case);
    fail_line(&run_with(&cx, "K-BIND"), "F12", "no receipt binds the fact");
    fail_line(&run_with(&cx, "K-SCOPE"), "F12", "no quote and no receipt");
    fail_line(
        &run_with(&cx, "K-ANCHOR"),
        "F12",
        "no receipt witnesses the anchor",
    );
}

#[test]
fn a_present_quote_with_another_hash_fails_k_bind() {
    let mut case = pilot_case();
    sourced_mut(&mut case, "F2").quote = Some("A different sentence.".into());
    fail_line(&run(&case, "K-BIND"), "F2", "is not the quote's");
}
