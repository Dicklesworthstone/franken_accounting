//! K-BASIS, K-TAUT, K-ORACLE and K-VINTAGE over the `t_kinds` fixture
//! (`tests/fixtures/t_kinds/`: one T of each kind, synthetic values) and the
//! T-free pilot (bead fa-yugf.8, A3b). Plants edit the loaded [`Case`]. A
//! re-type is a result, not an `Err`, so each re-type test's name carries a
//! ratchet token and asserts its `RETYPE` line.

use super::super::expect::{ExpectationType, Field};
use super::super::fact::{Derived, Fact, Interpretation, Provenance, Synthetic, Value};
use super::super::tests::{load_files, pilot};
use super::super::{CASE_EXTENSIONS, Case};
use super::*;
use fa_registry::toml::Value as TomlValue;

const T_KINDS: [(&str, &str); 7] = [
    (
        "case.toml",
        include_str!("../../../tests/fixtures/t_kinds/case.toml"),
    ),
    (
        "sources.toml",
        include_str!("../../../tests/fixtures/t_kinds/sources.toml"),
    ),
    (
        "facts.toml",
        include_str!("../../../tests/fixtures/t_kinds/facts.toml"),
    ),
    (
        "receipts.toml",
        include_str!("../../../tests/fixtures/t_kinds/receipts.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../../tests/fixtures/t_kinds/roles.toml"),
    ),
    (
        "books/native.toml",
        include_str!("../../../tests/fixtures/t_kinds/books/native.toml"),
    ),
    (
        "expectations.toml",
        include_str!("../../../tests/fixtures/t_kinds/expectations.toml"),
    ),
];

fn t_kinds() -> Case {
    let files: Vec<(&'static str, String)> = T_KINDS
        .iter()
        .map(|(p, t)| (*p, (*t).to_string()))
        .collect();
    load_files("t_kinds", &files, CASE_EXTENSIONS).expect("the t_kinds fixture loads")
}

fn run(case: &Case, id: &str) -> CheckReport {
    run_load_checks_with(&Context::new(case), &[])
        .into_iter()
        .find(|r| r.check == id)
        .expect("the check ran")
}

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

fn retype_lines(r: &CheckReport) -> Vec<String> {
    r.render(None)
        .lines()
        .filter(|l| l.starts_with("RETYPE "))
        .map(str::to_string)
        .collect()
}

fn set_field(case: &mut Case, expectation: &str, key: &str, value: Field) {
    let e = case
        .expectations
        .as_mut()
        .and_then(|s| s.expectations.iter_mut().find(|e| e.id == expectation))
        .expect("an expectation");
    e.fields.map.insert(key.to_string(), value);
}

fn leg_rule(case: &mut Case, intent: &str, ordinal: i128, rule: &str) {
    let book = case.books.get_mut("native").expect("native");
    let leg = book
        .legs
        .iter_mut()
        .find(|l| l.intent == intent && l.ordinal == ordinal)
        .expect("a leg");
    leg.amount_rule = rule.to_string();
}

fn sourced_role(case: &mut Case, fact: &str, role: &str) {
    let f = case
        .facts
        .iter_mut()
        .find(|f| f.id == fact)
        .expect("a fact");
    if let Provenance::Sourced(s) = &mut f.provenance {
        s.role = Some(role.to_string());
    }
}

fn derived(id: &str, from: &[&str], rule: &str, params: &[&str]) -> Fact {
    Fact {
        id: id.into(),
        provenance: Provenance::Derived(Derived {
            from: from.iter().map(|s| (*s).to_string()).collect(),
            rule: rule.into(),
            params: (!params.is_empty()).then(|| {
                params
                    .iter()
                    .map(|p| TomlValue::Str((*p).to_string()))
                    .collect()
            }),
        }),
        line: None,
    }
}

/// A later source restating `restates`, with a fact on the bridge's B cell
/// carrying another value.
fn with_later_vintage(case: &mut Case, restates: &str) {
    let mut c = case
        .sources
        .iter()
        .find(|s| s.id == "SRC-TK-B")
        .cloned()
        .expect("SRC-TK-B");
    c.id = "SRC-TK-C".into();
    c.filed_on = Some("2022-06-01".into());
    c.restates = Some(vec![restates.to_string()]);
    case.sources.push(c);
    let mut f = case
        .facts
        .iter()
        .find(|f| f.id == "F-B")
        .cloned()
        .expect("F-B");
    f.id = "F-C".into();
    if let Provenance::Sourced(s) = &mut f.provenance {
        s.source = "SRC-TK-C".into();
    }
    case.facts.push(f);
    let mut v: Value = case
        .values
        .iter()
        .find(|v| v.fact == "F-B")
        .cloned()
        .expect("F-B's value");
    v.fact = "F-C".into();
    v.value = "85000".into();
    case.values.push(v);
}

// --- positive -------------------------------------------------------------

#[test]
fn one_t_of_each_kind_passes_basis_taut_oracle_vintage() {
    let case = t_kinds();
    let reports = run_load_checks(&case);
    let text: String = reports.iter().map(|r| r.render(None)).collect();
    println!("{text}");
    for (check, counts) in [
        ("K-BASIS", "examined=7/7"),
        ("K-TAUT", "examined=8/8"),
        ("K-ORACLE", "examined=8/8"),
        ("K-VINTAGE", "examined=8/8"),
    ] {
        assert!(
            text.contains(&format!("CHECK {check} PASS {counts}\n")),
            "{check}:\n{text}"
        );
    }
    assert!(!text.contains("\nFAIL "), "{text}");
    assert!(!text.contains("RETYPE "), "{text}");
    for r in &reports {
        assert_ne!(r.verdict, Verdict::Fail, "{}", r.render(None));
    }
    let taut = reports
        .iter()
        .find(|r| r.check == "K-TAUT")
        .expect("K-TAUT");
    assert!(
        taut.rows.contains(&"X-T-03/F-S2".to_string()),
        "{:?}",
        taut.rows
    );
    assert_eq!(
        case.effective_type("X-T-01", None),
        Some(ExpectationType::T)
    );
}

#[test]
fn reported_in_selector_naming_the_earlier_vintage_passes_k_vintage() {
    let mut case = t_kinds();
    with_later_vintage(&mut case, "SRC-TK-A");
    // Issuance #2 of FY2020 files DOC-B, a stub of SRC-TK-B, the vintage the T reads.
    set_field(
        &mut case,
        "X-T-01",
        "read_selector",
        Field::Str("reported_in:FY2020#2".into()),
    );
    let r = run(&case, "K-VINTAGE");
    assert_eq!(r.verdict, Verdict::Pass, "{}", r.render(None));
}

#[test]
fn pilot_has_no_t_rows_so_taut_oracle_vintage_are_unrun() {
    let mut files = pilot();
    files.push((
        "expectations.toml",
        include_str!("../../../tests/fixtures/pilot/expectations.toml").to_string(),
    ));
    let case = load_files("worldcom", &files, CASE_EXTENSIONS).expect("the pilot loads");
    for check in ["K-TAUT", "K-ORACLE", "K-VINTAGE"] {
        assert_eq!(
            run(&case, check).render(None),
            format!("CHECK {check} UNRUN examined=0/0\n")
        );
    }
    let basis = run(&case, "K-BASIS");
    assert_eq!(basis.verdict, Verdict::Pass, "{}", basis.render(None));
    assert_eq!((basis.examined, basis.inputs), (5, 5));
}

// --- negatives (§15) ------------------------------------------------------

#[test]
fn read_back_t_with_b_posted_never_stays_t() {
    let mut case = t_kinds();
    leg_rule(&mut case, "F-Aa", 0, "value:F-B#1");
    let r = run(&case, "K-TAUT");
    assert_eq!(
        retype_lines(&r),
        ["RETYPE X-T-01 T→R K-TAUT path=[F-B, leg F-Aa#0]"]
    );
    assert_eq!(
        case.effective_type("X-T-01", None),
        Some(ExpectationType::R)
    );
}

#[test]
fn oracle_output_missing_from_inputs_named_is_retyped_c() {
    let mut case = t_kinds();
    sourced_role(&mut case, "F-X1", "oracle_output");
    let r = run(&case, "K-ORACLE");
    assert_eq!(
        retype_lines(&r),
        ["RETYPE X-T-02 T→C K-ORACLE path=[F-X1, leg F-X1a#0]"]
    );
    assert_eq!(
        case.effective_type("X-T-02", None),
        Some(ExpectationType::C)
    );
    // Named, the oracle input feeds the T.
    set_field(
        &mut case,
        "X-T-02",
        "inputs_named",
        Field::Strs(vec!["F-X1".into()]),
    );
    assert!(retype_lines(&run(&case, "K-ORACLE")).is_empty());
    // Naming the intent does not name the fact its legs trace to.
    set_field(
        &mut case,
        "X-T-02",
        "inputs_named",
        Field::Strs(vec!["F-X1a".into()]),
    );
    assert_eq!(retype_lines(&run(&case, "K-ORACLE")).len(), 1);
}

#[test]
fn t_on_a_superseded_vintage_is_refused() {
    let mut case = t_kinds();
    with_later_vintage(&mut case, "SRC-TK-B");
    fail_line(
        &run(&case, "K-VINTAGE"),
        "X-T-01",
        "B source SRC-TK-B is superseded on cell receivables@2020-12-31 by SRC-TK-C",
    );
}

#[test]
fn delta_t_naming_no_delta_accession_is_refused() {
    let mut case = t_kinds();
    set_field(
        &mut case,
        "X-T-05",
        "vintages",
        Field::Strs(vec!["B:SRC-TK-B".into()]),
    );
    let r = run(&case, "K-VINTAGE");
    fail_line(&r, "X-T-05", "delta names no D: accession");
    fail_line(&r, "X-T-05", "no B: accession (E-T-03)");
}

// --- derived negatives ----------------------------------------------------

#[test]
fn basis_without_a_sourced_fact_is_refused() {
    let mut case = t_kinds();
    case.facts.push(Fact {
        id: "I-READING".into(),
        provenance: Provenance::Interpretation(Interpretation {
            from: Vec::new(),
            reader: "tk-preparer-1".into(),
            second_reader: "tk-second-reader".into(),
            rationale: "a reading with nothing under it".into(),
        }),
        line: None,
    });
    set_field(
        &mut case,
        "X-T-07",
        "basis",
        Field::Strs(vec!["I-READING".into()]),
    );
    fail_line(&run(&case, "K-BASIS"), "X-T-07", "has no sourced fact");
}

#[test]
fn basis_reaching_a_synthetic_fact_is_refused() {
    let mut case = t_kinds();
    case.facts.push(Fact {
        id: "SYN".into(),
        provenance: Provenance::Synthetic(Synthetic {
            reason: "filler".into(),
            discipline: "never supports a claim".into(),
        }),
        line: None,
    });
    case.facts
        .push(derived("D-SYN", &["SYN", "F-RT"], "sum", &[]));
    set_field(
        &mut case,
        "X-T-07",
        "basis",
        Field::Strs(vec!["D-SYN".into()]),
    );
    let r = run(&case, "K-BASIS");
    fail_line(&r, "X-T-07", "reaches synthetic fact(s) [\"SYN\"]");
    assert!(
        r.rows.contains(&"X-T-07 premises=D-SYN".to_string()),
        "{:?}",
        r.rows
    );
}

#[test]
fn bridge_whose_a_posting_cites_another_filing_is_refused() {
    let mut case = t_kinds();
    let book = case.books.get_mut("native").expect("native");
    let it = book
        .intents
        .iter_mut()
        .find(|i| i.id == "F-Aa")
        .expect("F-Aa");
    it.evidence = Some("DOC-B".into());
    fail_line(
        &run(&case, "K-VINTAGE"),
        "X-T-01",
        "A intent F-Aa cites a stub of SRC-TK-B, not the A: source",
    );
}

#[test]
fn t_on_a_line_whose_remainder_a_b_value_fed_never_stays_t() {
    let mut case = t_kinds();
    case.facts.push(derived(
        "REM",
        &["F-B"],
        "remainder",
        &["line=1100", "of_total=receivables"],
    ));
    assert_eq!(
        retype_lines(&run(&case, "K-TAUT")),
        ["RETYPE X-T-01 T→R K-TAUT path=[F-B, REM, remainder line=1100]"]
    );
}

#[test]
fn delta_derived_as_b_minus_a_never_stays_t() {
    let mut case = t_kinds();
    case.facts
        .push(derived("D-BA", &["F-B", "F-A"], "difference", &[]));
    leg_rule(&mut case, "delta-F-Aa", 0, "derived:D-BA");
    assert_eq!(
        retype_lines(&run(&case, "K-TAUT")),
        ["RETYPE X-T-01 T→R K-TAUT path=[F-B, D-BA, leg delta-F-Aa#0]"]
    );
}

#[test]
fn t_on_an_earlier_co_restater_without_reported_in_is_refused() {
    let mut case = t_kinds();
    // E4's shape: SRC-TK-B and the later SRC-TK-C both restate SRC-TK-A.
    with_later_vintage(&mut case, "SRC-TK-A");
    fail_line(
        &run(&case, "K-VINTAGE"),
        "X-T-01",
        "superseded on cell receivables@2020-12-31 by SRC-TK-C",
    );
}

#[test]
fn reported_in_naming_an_issuance_of_another_vintage_is_refused() {
    let mut case = t_kinds();
    with_later_vintage(&mut case, "SRC-TK-A");
    // Issuance #1 files DOC-A, a stub of SRC-TK-A, not the B source.
    set_field(
        &mut case,
        "X-T-01",
        "read_selector",
        Field::Str("reported_in:FY2020#1".into()),
    );
    fail_line(
        &run(&case, "K-VINTAGE"),
        "X-T-01",
        "names an issuance that files SRC-TK-A, not SRC-TK-B",
    );
}

#[test]
fn published_fact_from_a_source_its_vintages_do_not_name_is_refused() {
    let mut case = t_kinds();
    set_field(&mut case, "X-T-02", "published", Field::Str("F-SE".into()));
    fail_line(
        &run(&case, "K-VINTAGE"),
        "X-T-02",
        "published fact F-SE comes from SRC-TK-S, which the T's vintages do not name under exhibit:",
    );
}

#[test]
fn oracle_output_missing_from_one_target_inputs_named_retypes_only_that_target() {
    let mut case = t_kinds();
    sourced_role(&mut case, "F-S1", "oracle_output");
    sourced_role(&mut case, "F-S2", "oracle_output");
    set_field(
        &mut case,
        "X-T-03",
        "inputs_named",
        Field::Strs(vec!["F-S1".into()]),
    );
    // X-T-04 and X-T-06 read the same legs and name no inputs, so they
    // are re-typed too; of X-T-03's two targets only F-S2's is.
    let peracct: Vec<String> = retype_lines(&run(&case, "K-ORACLE"))
        .into_iter()
        .filter(|l| l.starts_with("RETYPE X-T-03"))
        .collect();
    assert_eq!(
        peracct,
        ["RETYPE X-T-03/F-S2 T→C K-ORACLE path=[F-S2, leg F-S2a#1]"]
    );
    assert_eq!(
        case.effective_type("X-T-03", Some("F-S2")),
        Some(ExpectationType::C)
    );
    assert_eq!(
        case.effective_type("X-T-03", Some("F-S1")),
        Some(ExpectationType::T)
    );
}

#[test]
fn harness_selftest_basis_is_unrun_with_its_reason() {
    let mut case = t_kinds();
    case.header.kind = super::super::header::CaseKind::HarnessSelftest;
    assert_eq!(
        run(&case, "K-BASIS").render(None),
        "CHECK K-BASIS UNRUN examined=0/0 reason=exempt: harness_selftest\n"
    );
}
