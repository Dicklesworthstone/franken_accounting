use super::*;
use crate::cases::embedded::{WORLDCOM, XBRL};

fn load(case: &crate::cases::embedded::EmbeddedCase) -> Case {
    crate::cases::load(&case.case_files()).expect("the case loads")
}

fn row(
    expectation: &str,
    kind: &str,
    target: Option<&str>,
    verdict: RowVerdict,
    projection: &[(&str, &str)],
    reason: Option<&str>,
) -> VerdictRecord {
    VerdictRecord {
        case: "test".into(),
        expectation: expectation.into(),
        kind: kind.into(),
        book_variant: "native".into(),
        target: target.map(str::to_string),
        cell: "default".into(),
        verdict,
        projection: projection
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        witnesses: Vec::new(),
        reason: reason.map(str::to_string),
    }
}

fn green(verdicts: &[VerdictRecord]) -> RunRecords<'_> {
    RunRecords {
        steps: &[],
        verdicts,
        green: true,
    }
}

#[test]
fn non_green_case_is_not_rendered() {
    let case = load(&WORLDCOM);
    let run = RunRecords {
        steps: &[],
        verdicts: &[],
        green: false,
    };
    assert_eq!(render_readme(&case, &run), Err(RenderError::NotGreen));
}

#[test]
fn render_is_a_pure_function_of_its_inputs() {
    let case = load(&WORLDCOM);
    let rows = [row(
        "W-T-02",
        "T",
        None,
        RowVerdict::Pass,
        &[("kind", "bridge"), ("value", "44188000000.00")],
        None,
    )];
    let a = render_readme(&case, &green(&rows)).expect("renders");
    let b = render_readme(&case, &green(&rows)).expect("renders");
    assert_eq!(a, b);
    assert!(a.starts_with(GENERATED), "{a}");
}

#[test]
fn unrun_row_renders_only_as_not_yet_evaluated() {
    let case = load(&WORLDCOM);
    let rows = [row(
        "W-D-01",
        "D",
        Some("F4"),
        RowVerdict::Unrun,
        &[("finding", "yes"), ("statistic", "56000000000")],
        Some("filler_invariance"),
    )];
    let text = render_readme(&case, &green(&rows)).expect("renders");
    assert!(
        text.contains("Not yet evaluated: filler_invariance. No outcome is stated for this row."),
        "{text}"
    );
    assert!(
        text.contains("not yet evaluated: filler_invariance |"),
        "{text}"
    );
    // The observed outcome of an unevaluated row is logged, never rendered,
    // and its claim sentence is not stated.
    assert!(!text.contains("statistic=56000000000"), "{text}");
    assert!(
        !text.contains("reports a finding citing each of them"),
        "{text}"
    );
    assert!(text.contains("- `W-D-01`: filler_invariance"), "{text}");
}

#[test]
fn unconstrained_cell_is_marked_and_record_cell_is_not() {
    let case = load(&WORLDCOM);
    let rows = [
        row(
            "W-P-02",
            "P",
            Some("F4"),
            RowVerdict::Pass,
            &[("refusal", "FA-REF-080")],
            None,
        ),
        row(
            "W-P-02",
            "P",
            Some("F4"),
            RowVerdict::Pass,
            &[("refusal", "FA-REF-086"), ("record_consistent", "false")],
            None,
        ),
    ];
    let text = render_readme(&case, &green(&rows)).expect("renders");
    let table: Vec<&str> = text.lines().filter(|l| l.contains("FA-REF-08")).collect();
    assert!(
        table
            .iter()
            .any(|l| l.contains("| record-consistent | refusal=FA-REF-080")),
        "{table:?}"
    );
    assert!(
        table
            .iter()
            .any(|l| l.contains("| unconstrained | refusal=FA-REF-086")),
        "{table:?}"
    );
    // The P sentence names the attribute it varies and the authored refusal.
    assert!(
        text.contains("with `evidence_attached` in each cell below"),
        "{text}"
    );
}

#[test]
fn t_sentence_renders_the_phrases_a3c_gives() {
    // X-T-01's quarterly lines narrow the audited 10-K/A to unaudited.
    let case = load(&XBRL);
    let rows = [row(
        "X-T-01",
        "T",
        Some("spwr.NetIncomeLoss.c-443"),
        RowVerdict::Pass,
        &[("kind", "bridge"), ("value", "3425000.00")],
        None,
    )];
    let text = render_readme(&case, &green(&rows)).expect("renders");
    let section: String = text
        .split("### `X-T-01`")
        .nth(1)
        .and_then(|s| s.split("\n### ").next())
        .expect("the X-T-01 section")
        .to_string();
    let e = case
        .expectations
        .as_ref()
        .and_then(|s| s.get("X-T-01"))
        .expect("X-T-01");
    for (source, phrase) in e.phrases(&case) {
        assert!(
            section.contains(&format!("`{source}` ({phrase})")),
            "{section}"
        );
    }
    assert!(section.contains("(reported (unaudited))"), "{section}");
    assert!(!section.contains("(reported (audited))"), "{section}");
}

#[test]
fn retyped_row_says_so() {
    let case = load(&XBRL);
    let rows = [row(
        "X-T-01",
        "R",
        Some("spwr.NetIncomeLoss.c-443"),
        RowVerdict::Pass,
        &[("contrib", "retyped(contribution carries B)")],
        None,
    )];
    let text = render_readme(&case, &green(&rows)).expect("renders");
    assert!(text.contains("| R (re-typed from T) |"), "{text}");
}

#[test]
fn run_variant_token_in_a_row_refuses_the_render() {
    let case = load(&WORLDCOM);
    let rows = [row(
        "W-R-01",
        "R",
        None,
        RowVerdict::Pass,
        &[("entry", "0123456789abcdef0123456789abcdef")],
        None,
    )];
    match render_readme(&case, &green(&rows)) {
        Err(RenderError::Lint(p)) => assert_eq!(
            p,
            ["run-variant token `0123456789abcdef0123456789abcdef`"],
            "{p:?}"
        ),
        other => panic!("expected a lint refusal, got {other:?}"),
    }
}

#[test]
fn deny_listed_name_in_a_source_title_is_withheld() {
    let mut case = load(&WORLDCOM);
    case.roles.deny_hashes = Some(vec![
        names::deny_hash("testname"),
        names::deny_hash("zqxvy"),
    ]);
    case.sources[0].title = "SEC v. Testname Q. Zqxvy, complaint".into();
    let text = render_readme(&case, &green(&[])).expect("renders");
    assert!(
        text.contains("| title withheld: it names a person (plan §2.8) |"),
        "{text}"
    );
    // Withheld whole: neither the denied surname nor the given name beside it.
    assert!(!text.to_lowercase().contains("testname"), "{text}");
    assert!(!text.contains("Q. "), "{text}");
}

#[test]
fn deny_listed_name_anywhere_in_the_output_refuses_the_render() {
    let mut case = load(&WORLDCOM);
    let hash = names::deny_hash("testname");
    case.roles.deny_hashes = Some(vec![hash.clone()]);
    let rows = [row(
        "W-R-01",
        "R",
        None,
        RowVerdict::Pass,
        &[("note", "Testname")],
        None,
    )];
    assert_eq!(
        render_readme(&case, &green(&rows)),
        Err(RenderError::Lint(vec![format!(
            "deny-listed name token {hash}"
        )]))
    );
}

#[test]
fn amounts_are_grouped_by_thousands_without_arithmetic() {
    assert_eq!(grouped("1234567.89"), "1,234,567.89");
    assert_eq!(grouped("-402000000.00"), "-402,000,000.00");
    assert_eq!(grouped("12.00"), "12.00");
    assert_eq!(grouped("123"), "123");
    assert_eq!(grouped("1000"), "1,000");
}
