//! The forensic case runner (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.3; bead
//! fa-yugf.15, A7a), driving the real `fa` binary over every committed case
//! under `crates/fa-oracles/cases/`. Each case's `#[test]` is named after
//! its directory; each case-file negative is a `<dir>_neg_<slug>` test over
//! a planted temp copy, so no committed case file is edited.
//!
//! The runner prints one line per evaluated (expectation, variant, target,
//! cell) row, `REPRODUCE fa …` above a failing step's row, and `LOG <path>`
//! last; the JSONL log carries one step record per `fa` call and one verdict
//! record per row. No row reads PASS until its witnesses exist (A11a–c,
//! A4r); what the self-test proves today is that every implemented stage
//! ran and every evaluated component agreed.

#[path = "cases/budget.rs"]
mod budget;
#[path = "cases/cells.rs"]
mod cells;
#[path = "cases/evaluate.rs"]
mod evaluate;
#[path = "cases/invariance.rs"]
mod invariance;
#[path = "cases/property.rs"]
mod property;
#[path = "cases/reads.rs"]
mod reads;
#[path = "cases/run.rs"]
mod run;

use fa_oracles::cases::harness_verbs::HARNESS_VERBS;
use fa_oracles::json::{self, Json};

use run::{PlantedEdit, RunOutcome, fa, outcome, run_case, run_files, run_planted};

const SELFTEST: &str = "_selftest";

const SELFTEST_D: &str = "UNRUN _selftest-D-01 D native S-1/default procedure=jet.round_amounts@1 entry=S-1 cite=S-1#0,S-1#1 severity=Medium statistic_name=round_legs statistic=2 scale=0 ref=agree reason=filler_invariance";

fn selftest_files() -> fa_oracles::cases::CaseFiles<'static> {
    fa_oracles::cases::embedded::SELFTEST.case_files()
}

/// The harness self-test: every implemented stage over its synthetic book,
/// each row's evaluated components in agreement.
#[test]
fn _selftest() {
    let o = outcome(SELFTEST);
    let text = o.text();
    assert!(o.rows_ok, "{text}");
    assert_eq!(o.row("_selftest-D-01"), Some(SELFTEST_D), "{text}");
    let p = o.row("_selftest-P-01").unwrap_or_default();
    assert!(
        p.starts_with(
            "UNRUN _selftest-P-01 P native -/default law=admissibility.toml#Original/Future refusal=FA-REF-010 exit=7 law_named=ok matrix=ok "
        ) && p.ends_with(" alternatives=ok ref=agree reason=filler_invariance"),
        "{text}"
    );
    assert_eq!(
        o.row("_selftest-SELF-native"),
        Some(
            "UNRUN _selftest-SELF-native D native -/default procedure=jet.self_sourced_evidence@1 entries=S-1 severity=Medium reason=filler_invariance"
        ),
        "{text}"
    );
    assert!(!text.contains("REPRODUCE"), "{text}");
    assert_eq!(
        o.lines.last().map(String::as_str),
        Some(format!("LOG {}", o.log_path.display()).as_str())
    );
}

/// The JSONL log: one step record per `fa` call, one verdict record per
/// printed row, each line a record the log module parses back.
#[test]
fn _selftest_logs_every_step_and_every_row() {
    let o = outcome(SELFTEST);
    let log = std::fs::read_to_string(&o.log_path).expect("the run log");
    let (mut steps, mut verdicts) = (0, 0);
    for line in log.lines() {
        let doc = json::parse(line).expect("a JSON log line");
        let record = doc.get("record").and_then(Json::as_str);
        assert!(
            matches!(record, Some("step" | "verdict")),
            "unknown record: {line}"
        );
        if record == Some("step") {
            fa_oracles::cases::log::StepRecord::parse_line(line).expect("a step record");
            steps += 1;
        } else {
            fa_oracles::cases::log::VerdictRecord::parse_line(line).expect("a verdict record");
            verdicts += 1;
        }
    }
    assert_eq!(steps, o.steps.len());
    let rows = o
        .lines
        .iter()
        .filter(|l| {
            ["PASS ", "FAIL ", "UNRUN "]
                .iter()
                .any(|v| l.starts_with(v))
        })
        .count();
    assert_eq!(verdicts, rows, "{}", o.text());
    assert_eq!(rows, 3, "{}", o.text());
}

/// Every `fa` call the runner makes is a (verb, subcommand) of the table it
/// checks against `verbs.toml` before any book exists, and every
/// run-variant token in a logged argv is a bound placeholder.
#[test]
fn every_logged_verb_is_in_the_harness_verb_table() {
    let o = outcome(SELFTEST);
    assert!(!o.steps.is_empty());
    for s in &o.steps {
        let argv = &s.argv_redacted;
        assert_eq!(
            argv.get(..2),
            Some(&["--book".to_string(), "$BOOK".to_string()][..])
        );
        let verb = argv.get(2).map(String::as_str).unwrap_or_default();
        let sub = argv.get(3).map(String::as_str);
        assert_eq!(s.verb, verb, "{argv:?}");
        assert!(
            HARNESS_VERBS
                .iter()
                .any(|(v, x)| *v == verb && (x.is_none() || *x == sub)),
            "{argv:?} is not in HARNESS_VERBS"
        );
        for a in argv {
            assert!(
                !a.contains(o.books["native"].to_str().unwrap_or("-")),
                "{argv:?}"
            );
            if let Some(p) = a
                .split('$')
                .nth(1)
                .filter(|p| !p.starts_with("BOOK") && !p.starts_with("WORK"))
            {
                let placeholder = format!("${}", p.split('/').next().unwrap_or_default());
                assert!(
                    s.binds.iter().any(|(b, _)| *b == placeholder),
                    "{placeholder} in {argv:?} has no bind: {:?}",
                    s.binds
                );
            }
        }
    }
    let finding = o
        .steps
        .iter()
        .find(|s| s.argv_redacted.get(2..4) == Some(&["finding".into(), "list".into()][..]))
        .expect("a finding list step");
    assert_eq!(
        finding.binds,
        [(
            "$C_FINDINGRUN_jet.round_amounts".to_string(),
            "findings_recorded.certificate of step 4 (jet.round_amounts)".to_string()
        )]
    );
}

/// Exactly one runner-generated SELF row per book variant.
#[test]
fn every_variant_gets_exactly_one_self_row() {
    let o = outcome(SELFTEST);
    for variant in o.books.keys() {
        let id = format!("_selftest-SELF-{variant}");
        let n = o
            .lines
            .iter()
            .filter(|l| l.split(' ').nth(1) == Some(id.as_str()))
            .count();
        assert_eq!(n, 1, "{}", o.text());
    }
}

/// The period label → book code map, matched by dates, is printed once per
/// book; the self-test's two quarters are its custom calendar's P01 and P02.
#[test]
fn period_label_map_is_logged_once_per_book() {
    let o = outcome(SELFTEST);
    let maps: Vec<&String> = o
        .lines
        .iter()
        .filter(|l| l.starts_with("PERIODS "))
        .collect();
    assert_eq!(
        maps,
        ["PERIODS native 2026Q1=FY2026-P01 2026Q2=FY2026-P02"],
        "{}",
        o.text()
    );
}

/// `pre_case` on a variant with no `[[case]]` reads at the head at the
/// `finding_record` step. The self-test's last write before that step is
/// S-1's post (S-2 is refused, `entry show` is a read), so the run's source
/// coordinate is S-1's recorded sequence, and the runner passed exactly it.
#[test]
fn pre_case_on_a_book_without_a_case_is_the_head_at_the_finding_step() {
    let o = outcome(SELFTEST);
    let book = &o.books["native"];
    let runs = fa(book, &["finding".into(), "runs".into(), "--json".into()]);
    assert_eq!(runs.exit, 0, "{}", runs.stdout);
    let rows = runs.array_field("finding_runs", "runs");
    assert_eq!(rows.len(), 1, "{}", runs.stdout);
    let source = rows[0].get("source_known_at").and_then(Json::as_int);
    let cert = rows[0]
        .get("certificate")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let listed = fa(
        book,
        &[
            "finding".into(),
            "list".into(),
            "--certificate".into(),
            format!("C:{cert}"),
            "--json".into(),
        ],
    );
    let findings = listed.array_field("finding_list", "findings");
    let entry = findings
        .first()
        .and_then(|f| f.at(&["finding", "cites"]))
        .and_then(Json::as_array)
        .and_then(|cites| {
            cites
                .iter()
                .find(|c| c.get("kind").and_then(Json::as_str) == Some("entry"))
        })
        .and_then(|c| c.get("entry"))
        .and_then(Json::as_str)
        .expect("the finding cites S-1's entry");
    let shown = fa(
        book,
        &["entry".into(), "show".into(), entry.into(), "--json".into()],
    );
    let posted_at = shown
        .event("entry")
        .and_then(|o| o.field("recorded_at"))
        .and_then(Json::as_int);
    assert!(posted_at.is_some(), "{}", shown.stdout);
    assert_eq!(source, posted_at, "{}\n{}", runs.stdout, shown.stdout);
    let step = o
        .steps
        .iter()
        .find(|s| {
            s.finding_procedure.is_some()
                && s.argv_redacted.get(3).map(String::as_str) == Some("record")
        })
        .expect("the finding record step");
    let at = step
        .argv_redacted
        .iter()
        .position(|a| a == "--known-at")
        .and_then(|i| step.argv_redacted.get(i + 1))
        .and_then(|v| v.parse::<i128>().ok());
    assert_eq!(at, source);
}

/// A renamed verb fails the case before any book is created.
#[test]
fn renamed_verb_fails_before_any_book_is_created() {
    let verbs: Vec<(&str, Option<&str>)> = HARNESS_VERBS
        .iter()
        .map(|(v, s)| {
            if (*v, *s) == ("period", Some("open")) {
                ("periods", Some("open"))
            } else {
                (*v, *s)
            }
        })
        .collect();
    let o = run_case(&selftest_files(), &verbs);
    assert!(!o.ok);
    assert!(o.books.is_empty(), "{}", o.text());
    assert!(o.steps.is_empty(), "{}", o.text());
    assert!(
        o.lines.contains(
            &"FAIL _selftest verbs: the runner invokes periods open that verbs.toml does not register"
                .to_string()
        ),
        "{}",
        o.text()
    );
}

/// A wrong refusal id reports FAIL, and the printed `REPRODUCE` argv
/// reproduces the observed refusal.
#[test]
fn _selftest_neg_wrong_refusal_id() {
    let o = run_planted(
        SELFTEST,
        &[PlantedEdit {
            file: "expectations.toml",
            old: "refusal = \"FA-REF-010\"",
            new: "refusal = \"FA-REF-011\"",
        }],
        HARNESS_VERBS,
    )
    .expect_err("a wrong refusal id fails the case");
    let text = o.text();
    let at = o
        .lines
        .iter()
        .position(|l| l.starts_with("FAIL _selftest-P-01 "))
        .expect("the P row");
    let row = &o.lines[at];
    assert!(
        row.starts_with("FAIL _selftest-P-01 P native -/default law=admissibility.toml#Original/Future refusal=FA-REF-010 exit=7 ")
            && row.ends_with(" reason=expected refusal=FA-REF-011 observed refusal=FA-REF-010"),
        "{text}"
    );
    let argv: Vec<String> = o.lines[at - 1]
        .strip_prefix("REPRODUCE fa ")
        .expect("a REPRODUCE line above the row")
        .split("  # ")
        .next()
        .unwrap_or_default()
        .split(' ')
        .map(str::to_string)
        .collect();
    let book = std::path::PathBuf::from(&argv[1]);
    let again = fa(&book, &argv[2..]);
    assert_eq!(again.exit, 7, "{}", again.stdout);
    assert_eq!(again.refusal_id().as_deref(), Some("FA-REF-010"));
}

/// A cite of the wrong fact reports FAIL on the D row.
#[test]
fn _selftest_neg_cite_of_the_wrong_fact() {
    let o = run_planted(
        SELFTEST,
        &[PlantedEdit {
            file: "expectations.toml",
            old: "cite = [\"S-1#0\", \"S-1#1\"]",
            new: "cite = [\"S-1#0\", \"S-2#1\"]",
        }],
        HARNESS_VERBS,
    )
    .expect_err("a wrong cite fails the case");
    assert_eq!(
        o.row("_selftest-D-01"),
        Some(
            "FAIL _selftest-D-01 D native S-1/default procedure=jet.round_amounts@1 entry=S-1 cite=S-1#0,S-1#1 severity=Medium statistic_name=round_legs statistic=2 scale=0 ref=agree reason=expected cite=S-1#0,S-2#1 observed cite=S-1#0,S-1#1"
        ),
        "{}",
        o.text()
    );
}

/// A planted copy that stops at a load check reports that check on every
/// row and builds no book.
#[test]
fn _selftest_neg_blank_discipline_stops_at_k_prov() {
    let o = run_planted(
        SELFTEST,
        &[PlantedEdit {
            file: "facts.toml",
            old: "discipline = \"never cited by a case; exercises an observed FA-REF-010 refusal\"",
            new: "discipline = \" \"",
        }],
        HARNESS_VERBS,
    )
    .expect_err("a K-PROV failure fails the case");
    assert!(o.books.is_empty() && o.steps.is_empty(), "{}", o.text());
    let rows: Vec<&String> = o
        .lines
        .iter()
        .filter(|l| l.starts_with("FAIL _selftest-"))
        .collect();
    assert_eq!(
        rows,
        [
            "FAIL _selftest-D-01 D native S-1/default reason=expected K-PROV=PASS observed K-PROV=FAIL",
            "FAIL _selftest-P-01 P native -/default reason=expected K-PROV=PASS observed K-PROV=FAIL",
            "FAIL _selftest-SELF-native D native -/default reason=expected K-PROV=PASS observed K-PROV=FAIL",
        ],
        "{}",
        o.text()
    );
}

/// A planted edit whose `old` text is not in the copy is refused, naming
/// the edit.
#[test]
#[should_panic(
    expected = "planted edit `refusal = \"FA-REF-999\"` in expectations.toml must occur exactly once"
)]
fn planted_edit_missing_from_the_copy_is_refused() {
    let _ = run_planted(
        SELFTEST,
        &[PlantedEdit {
            file: "expectations.toml",
            old: "refusal = \"FA-REF-999\"",
            new: "refusal = \"FA-REF-010\"",
        }],
        HARNESS_VERBS,
    );
}

/// The runner fixture (`crates/fa-oracles/tests/fixtures/runner_ext/`):
/// one of each extension step kind on a synthetic book.
const RUNNER_EXT: [(&str, &str); 6] = [
    (
        "case.toml",
        include_str!("../../fa-oracles/tests/fixtures/runner_ext/case.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../fa-oracles/tests/fixtures/runner_ext/roles.toml"),
    ),
    (
        "facts.toml",
        include_str!("../../fa-oracles/tests/fixtures/runner_ext/facts.toml"),
    ),
    (
        "books/native.toml",
        include_str!("../../fa-oracles/tests/fixtures/runner_ext/books/native.toml"),
    ),
    (
        "expectations.toml",
        include_str!("../../fa-oracles/tests/fixtures/runner_ext/expectations.toml"),
    ),
    (
        "rules/cash_sale.rule",
        include_str!("../../fa-oracles/tests/fixtures/runner_ext/rules/cash_sale.rule"),
    ),
];

/// The runner fixture's run, shared by its tests.
fn runner_ext() -> &'static RunOutcome {
    static RUN: std::sync::OnceLock<RunOutcome> = std::sync::OnceLock::new();
    RUN.get_or_init(
        || match run_files("runner_ext", &RUNNER_EXT, &[], HARNESS_VERBS) {
            Ok(o) => o,
            Err(o) => *o,
        },
    )
}

/// The logged step whose argv runs `verb` (and `sub`, when given).
fn steps_of<'o>(
    o: &'o RunOutcome,
    verb: &str,
    sub: Option<&str>,
) -> Vec<&'o fa_oracles::cases::log::StepRecord> {
    o.steps
        .iter()
        .filter(|s| {
            s.argv_redacted.get(2).map(String::as_str) == Some(verb)
                && sub.is_none_or(|x| s.argv_redacted.get(3).map(String::as_str) == Some(x))
        })
        .collect()
}

/// The A1b step kinds beyond the core history run through their registered
/// verbs, each logging its verb and a zero exit: allocate (its rendered
/// `method` the intent's `allocation_law`), a manual-assertion post (attest
/// manual, then commit), batch, event_record, the provenance engagement and
/// a `finding:` filing of the D row's findings, and a period lock planned,
/// approved through approve_as and committed.
#[test]
fn extension_step_kinds_run_through_their_verbs() {
    let o = runner_ext();
    let text = o.text();
    assert!(o.rows_ok, "{text}");
    assert!(!text.contains("REPRODUCE"), "{text}");
    for (verb, sub) in [
        ("party", Some("add")),
        ("allocate", None),
        ("document", Some("attest")),
        ("commit", None),
        ("batch", None),
        ("event", Some("record")),
        ("engagement", Some("open")),
        ("engagement", Some("file")),
        ("approve", None),
        ("period", Some("lock")),
        ("rule", Some("check")),
        ("rule", Some("propose")),
        ("rule", Some("backtest")),
    ] {
        let steps = steps_of(o, verb, sub);
        assert!(!steps.is_empty(), "no `{verb} {sub:?}` step:\n{text}");
        for s in steps {
            assert_eq!(s.exit, 0, "{:?}\n{text}", s.argv_redacted);
        }
    }
    // The allocation's rendered method is its law, never the CLI default.
    let work = o.books["native"].parent().expect("the variant's work dir");
    let alloc =
        std::fs::read_to_string(work.join("S-2.alloc.json")).expect("the rendered allocation");
    let doc = json::parse(&alloc).expect("JSON");
    assert_eq!(
        doc.get("method").and_then(Json::as_str),
        Some("EqualSplitResidualFirst"),
        "{alloc}"
    );
    // The manual assertion's statement is generated from the fact id.
    let attest = steps_of(o, "document", Some("attest"))
        .into_iter()
        .find(|s| s.argv_redacted.get(4).map(String::as_str) == Some("manual"))
        .expect("the attest manual step");
    assert!(
        attest
            .argv_redacted
            .contains(&run::assertion_statement("S-3")),
        "{:?}",
        attest.argv_redacted
    );
    // The finding: filing filed the D row's finding, by its vid.
    assert!(
        steps_of(o, "engagement", Some("file"))
            .iter()
            .any(|s| s.argv_redacted.contains(&"--finding".to_string())),
        "{text}"
    );
    // The backtest's --compare is the digest the propose step reported.
    let backtest = steps_of(o, "rule", Some("backtest"));
    let argv = &backtest[0].argv_redacted;
    let at = argv
        .iter()
        .position(|a| a == "--compare")
        .expect("--compare");
    assert_eq!(
        argv.get(at + 1).map(String::as_str),
        Some("$RULE_13"),
        "{argv:?}"
    );
    assert_eq!(
        backtest[0].binds,
        [(
            "$RULE_13".to_string(),
            "rule_proposed.ir_digest of step 13 (rules/cash_sale.rule)".to_string()
        )]
    );
    // The lock cites the approval approve_as produced.
    let locks = steps_of(o, "period", Some("lock"));
    let commit = locks.last().expect("the lock commit");
    assert!(
        commit.argv_redacted.contains(&"$APPROVAL_1".to_string())
            && commit.binds.iter().any(|(p, _)| p == "$APPROVAL_1"),
        "{:?} {:?}",
        commit.argv_redacted,
        commit.binds
    );
}

#[test]
fn finding_record_step_params_are_passed_as_param_flags() {
    let o = runner_ext();
    let record = steps_of(o, "finding", Some("record"));
    let argv = &record.first().expect("a finding record step").argv_redacted;
    let at = argv.iter().position(|a| a == "--param").expect("--param");
    assert_eq!(
        argv.get(at + 1).map(String::as_str),
        Some("round_power=3"),
        "{argv:?}"
    );
}

/// A planted allocation intent without its law is refused at load, before
/// any `fa` invocation: the runner never lets the CLI choose a default law.
#[test]
fn allocation_intent_without_its_law_is_refused_before_any_fa_invocation() {
    let o = run_files(
        "runner_ext",
        &RUNNER_EXT,
        &[PlantedEdit {
            file: "books/native.toml",
            old: "allocation_law = \"EqualSplitResidualFirst\"\n",
            new: "",
        }],
        HARNESS_VERBS,
    )
    .expect_err("an allocation without its law fails the run");
    assert!(o.steps.is_empty() && o.books.is_empty(), "{}", o.text());
    assert!(
        o.lines
            .iter()
            .any(|l| l.starts_with("FAIL runner_ext load ") && l.contains("allocation_law")),
        "{}",
        o.text()
    );
}

/// The twin fixture (`crates/fa-oracles/tests/fixtures/twins/`): a
/// no_finding N and a no_refusal N on a micro-book (A11c).
const TWINS: [(&str, &str); 5] = [
    (
        "case.toml",
        include_str!("../../fa-oracles/tests/fixtures/twins/case.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../fa-oracles/tests/fixtures/twins/roles.toml"),
    ),
    (
        "facts.toml",
        include_str!("../../fa-oracles/tests/fixtures/twins/facts.toml"),
    ),
    (
        "books/native.toml",
        include_str!("../../fa-oracles/tests/fixtures/twins/books/native.toml"),
    ),
    (
        "expectations.toml",
        include_str!("../../fa-oracles/tests/fixtures/twins/expectations.toml"),
    ),
];

fn twins_run() -> &'static RunOutcome {
    static RUN: std::sync::OnceLock<RunOutcome> = std::sync::OnceLock::new();
    RUN.get_or_init(|| match run_files("twins", &TWINS, &[], HARNESS_VERBS) {
        Ok(o) => o,
        Err(o) => *o,
    })
}

/// jet.round_amounts reports nothing on T-1's 1,234.56 legs, and its
/// mutation twin (1,000.00 legs, on its own book) reports T-1.
#[test]
fn n_with_a_reporting_twin_passes() {
    let o = twins_run();
    let text = o.text();
    assert!(o.rows_ok, "{text}");
    assert_eq!(
        o.row("twins-N-01"),
        Some(
            "UNRUN twins-N-01 N native T-1/default kind=no_finding twin=mutation:reported reason=filler_invariance"
        ),
        "{text}"
    );
    // The twin ran on its own book, logged under `<variant>~twin`.
    assert!(
        o.steps
            .iter()
            .any(|s| s.book_variant == "native~twin" && s.verb == "finding"),
        "{text}"
    );
    assert!(
        o.steps
            .iter()
            .filter(|s| s.book_variant == "native")
            .all(|s| !s.argv_redacted.iter().any(|a| a == "1000.00"))
    );
}

/// The same intent posted into a Closed period is refused FA-REF-010.
#[test]
fn harness_observability_twin_is_refused_fa_ref_010_in_a_closed_period() {
    let o = twins_run();
    assert_eq!(
        o.row("twins-N-02"),
        Some(
            "UNRUN twins-N-02 N native T-2/default kind=no_refusal twin=harness_observability:refused:FA-REF-010 reason=filler_invariance"
        ),
        "{}",
        o.text()
    );
}

/// An N whose target is refused reads FAIL, never PASS, and prints the
/// refused call's argv.
#[test]
fn n_whose_target_run_was_refused_reports_fail() {
    let o = run_files(
        "twins",
        &TWINS,
        &[
            PlantedEdit {
                file: "books/native.toml",
                old: "[[principal]]\nlabel = \"selftest-preparer-1\"",
                new: "[[period]]\ncode = \"2026Q2\"\nstart = \"2026-04-01\"\nend = \"2026-06-30\"\nfiscal_year = 2026\nkind = \"Normal\"\n\n[[principal]]\nlabel = \"selftest-preparer-1\"",
            },
            PlantedEdit {
                file: "books/native.toml",
                old: "effective_date = \"2026-02-20\"",
                new: "effective_date = \"2026-05-20\"",
            },
        ],
        HARNESS_VERBS,
    )
    .expect_err("a refused target fails the N");
    let text = o.text();
    let at = o
        .lines
        .iter()
        .position(|l| l.starts_with("FAIL twins-N-02 "))
        .expect("the N row");
    assert!(
        o.lines[at].ends_with("reason=expected T-2 admitted observed exit=7 refusal=FA-REF-010"),
        "{text}"
    );
    assert!(
        o.lines[at - 1].starts_with("REPRODUCE fa --book "),
        "{text}"
    );
}

/// An N whose target run errors (a parameter the procedure rejects at run
/// time: `fa finding record` exits 2, no refusal) reads FAIL, never PASS,
/// and prints the failed calls' argv. The twin carries the same step, so it
/// errors too.
#[test]
fn n_whose_target_run_errored_reports_fail() {
    let o = run_files(
        "twins",
        &TWINS,
        &[PlantedEdit {
            file: "books/native.toml",
            old: "ref = \"jet.round_amounts@1\"",
            new: "ref = \"jet.round_amounts@1\"\nparams = [\"round_power=31\"]",
        }],
        HARNESS_VERBS,
    )
    .expect_err("an errored target fails the N");
    let text = o.text();
    let at = o
        .lines
        .iter()
        .position(|l| l.starts_with("FAIL twins-N-01 "))
        .expect("the N row");
    assert!(
        o.lines[at].ends_with(
            "twin=mutation:errored reason=expected a recorded run of jet.round_amounts observed exit=2; expected the twin's recorded run of jet.round_amounts observed exit=2"
        ),
        "{text}"
    );
    // Both failed `fa finding record` calls, the target's and the twin's.
    let repro: Vec<&str> = o.lines[at - 1].lines().collect();
    assert_eq!(repro.len(), 2, "{text}");
    for line in &repro {
        assert!(
            line.starts_with("REPRODUCE fa --book ") && line.contains(" finding record "),
            "{text}"
        );
    }
    assert_ne!(repro[0], repro[1], "{text}");
}

/// The twin population fixture
/// (`crates/fa-oracles/tests/fixtures/twins_population/`): a Benford N
/// over 120 legs (A11c).
const TWINS_POPULATION: [(&str, &str); 5] = [
    (
        "case.toml",
        include_str!("../../fa-oracles/tests/fixtures/twins_population/case.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../fa-oracles/tests/fixtures/twins_population/roles.toml"),
    ),
    (
        "facts.toml",
        include_str!("../../fa-oracles/tests/fixtures/twins_population/facts.toml"),
    ),
    (
        "books/native.toml",
        include_str!("../../fa-oracles/tests/fixtures/twins_population/books/native.toml"),
    ),
    (
        "expectations.toml",
        include_str!("../../fa-oracles/tests/fixtures/twins_population/expectations.toml"),
    ),
];

/// Benford below its 500-leg minimum, used as an N: K-TIER admits it under
/// the sourced-and-complete marker, but below `min_population` the finding
/// cites nothing, so its digit-skew twin cannot report and the N fails.
#[test]
fn benford_below_its_minimum_as_an_n_fails_its_twin() {
    let o = run_files("twins_population", &TWINS_POPULATION, &[], HARNESS_VERBS)
        .expect_err("the N fails its twin");
    let text = o.text();
    assert!(
        text.contains("CHECK twins_population K-TIER PASS"),
        "{text}"
    );
    assert_eq!(
        o.row("twins_population-N-01"),
        Some(
            "FAIL twins_population-N-01 N native B-1/default kind=no_finding twin=mutation:did_not_report reason=expected the twin to report observed did_not_report (population 120 < min_population 500)"
        ),
        "{text}"
    );
}

/// The twin gap fixture (`crates/fa-oracles/tests/fixtures/twins_gap/`): an
/// exact_gap N on ponzi.net_investment@4 (A11c; the shape of M-N-01).
const TWINS_GAP: [(&str, &str); 5] = [
    (
        "case.toml",
        include_str!("../../fa-oracles/tests/fixtures/twins_gap/case.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../fa-oracles/tests/fixtures/twins_gap/roles.toml"),
    ),
    (
        "facts.toml",
        include_str!("../../fa-oracles/tests/fixtures/twins_gap/facts.toml"),
    ),
    (
        "books/native.toml",
        include_str!("../../fa-oracles/tests/fixtures/twins_gap/books/native.toml"),
    ),
    (
        "expectations.toml",
        include_str!("../../fa-oracles/tests/fixtures/twins_gap/expectations.toml"),
    ),
];

/// ponzi.net_investment@4 attributes cash-role legs only: A's value
/// (1,000.00) misses the 300.00 of principal B moved to A without cash, so
/// the gap from A's sourced 1,300.00 is exactly 300.00; C, with no
/// transfer, shows gap 0.
#[test]
fn exact_gap_n_passes_when_the_gap_equals_the_mechanism_amount() {
    let o = match run_files("twins_gap", &TWINS_GAP, &[], HARNESS_VERBS) {
        Ok(o) => o,
        Err(o) if o.rows_ok => *o,
        Err(o) => panic!("{}", o.text()),
    };
    assert_eq!(
        o.row("twins_gap-N-01"),
        Some(
            "UNRUN twins_gap-N-01 N native G-A/default kind=exact_gap gap=300.00 twin=mutation:gap:0.00 reason=filler_invariance"
        ),
        "{}",
        o.text()
    );
    // The twin target is read from the target's own book: no twin book.
    assert!(o.steps.iter().all(|s| s.book_variant == "native"));
}

/// A gap other than the declared amount, and a twin target whose gap is not
/// 0, each fail the N.
#[test]
fn exact_gap_n_whose_gaps_disagree_reports_fail() {
    let o = run_files(
        "twins_gap",
        &TWINS_GAP,
        &[
            PlantedEdit {
                file: "expectations.toml",
                old: "gap_amount = \"300.00\"",
                new: "gap_amount = \"250.00\"",
            },
            PlantedEdit {
                file: "expectations.toml",
                old: "statistic_value = \"50000\"",
                new: "statistic_value = \"60000\"",
            },
        ],
        HARNESS_VERBS,
    )
    .expect_err("disagreeing gaps fail the N");
    assert_eq!(
        o.row("twins_gap-N-01"),
        Some(
            "FAIL twins_gap-N-01 N native G-A/default kind=exact_gap gap=300.00 twin=mutation:gap:100.00 reason=expected gap=250.00 observed gap=300.00; expected the twin target G-C gap=0 observed gap=100.00"
        ),
        "{}",
        o.text()
    );
}

/// The pilot (`crates/fa-oracles/tests/fixtures/pilot/`), loaded for its
/// branch tables (A5a).
fn pilot_case() -> fa_oracles::cases::Case {
    const PILOT: [(&str, &str); 7] = [
        (
            "case.toml",
            include_str!("../../fa-oracles/tests/fixtures/pilot/case.toml"),
        ),
        (
            "sources.toml",
            include_str!("../../fa-oracles/tests/fixtures/pilot/sources.toml"),
        ),
        (
            "facts.toml",
            include_str!("../../fa-oracles/tests/fixtures/pilot/facts.toml"),
        ),
        (
            "receipts.toml",
            include_str!("../../fa-oracles/tests/fixtures/pilot/receipts.toml"),
        ),
        (
            "roles.toml",
            include_str!("../../fa-oracles/tests/fixtures/pilot/roles.toml"),
        ),
        (
            "books/native.toml",
            include_str!("../../fa-oracles/tests/fixtures/pilot/books/native.toml"),
        ),
        (
            "expectations.toml",
            include_str!("../../fa-oracles/tests/fixtures/pilot/expectations.toml"),
        ),
    ];
    fa_oracles::cases::load(&fa_oracles::cases::CaseFiles {
        id: "worldcom",
        files: &PILOT,
    })
    .expect("the pilot loads")
}

/// The pilot's W-D-03/F4 table: F4's three credit legs under round_power 3.
fn f4_cells() -> Vec<fa_oracles::cases::branch::Cell> {
    let case = pilot_case();
    let set = case.expectations.as_ref().expect("expectations");
    let e = set.get("W-D-03").expect("W-D-03");
    let t = set
        .targets_of("W-D-03")
        .find(|t| t.fact == "F4")
        .expect("F4");
    fa_oracles::cases::branch::enumerate(&case, e, t)
        .expect("F4's table")
        .cells
}

/// A5a (§2.6 rule 5, §3.7 item 5): 64 seeded witnesses of every class of
/// round_residue_legs (F4's five feasible cells, through jet.round_amounts)
/// and of period_end_window (inside and outside, through
/// jet.period_end_timing) each give the class's verdict on a micro-book.
#[test]
fn branch_class_witnesses_give_the_class_verdict() {
    use fa_oracles::cases::branch::{Cell, CellPart, witnesses};
    use fa_oracles::cases::date::Day;
    let cells = f4_cells();
    assert_eq!(cells.len(), 5);
    let (first, last) = (
        Day::parse("2026-01-01").expect("day"),
        Day::parse("2026-03-31").expect("day"),
    );
    let windows: Vec<Cell> = [("inside_window", true), ("outside_window", false)]
        .into_iter()
        .map(|(key, inside)| Cell {
            key: vec![key.to_string()],
            parts: vec![CellPart::Window {
                inside,
                window_days: 3,
                first,
                last,
            }],
            record_consistent: false,
            default: false,
        })
        .collect();
    // Each class's micro-book is independent: run them side by side.
    let outcomes: Vec<property::ClassOutcome> = std::thread::scope(|s| {
        let residue = cells.iter().map(|cell| {
            s.spawn(move || {
                let w = witnesses("worldcom", "W-D-03", cell, 64);
                property::residue_class("worldcom", "W-D-03", cell, &w, None)
            })
        });
        let window = windows.iter().map(|cell| {
            s.spawn(move || {
                let w = witnesses("property", "period_end_window", cell, 64);
                property::window_class("property", "period_end_window", cell, &w)
            })
        });
        residue
            .collect::<Vec<_>>()
            .into_iter()
            .chain(window.collect::<Vec<_>>())
            .map(|h| h.join().expect("a class run"))
            .collect()
    });
    let text: Vec<String> = outcomes.iter().flat_map(|o| o.lines.clone()).collect();
    let text = text.join("\n");
    assert_eq!(outcomes.len(), 7);
    for o in &outcomes {
        assert_eq!((o.witnesses, o.agree), (64, 64), "{text}");
    }
    assert!(!text.contains("FAIL "), "{text}");
}

/// A planted witness from outside its class (a non-multiple credit in the
/// all-multiples cell) gives another verdict, and the property test fails,
/// naming the rule, the class, the seed and the witness, with its argv.
#[test]
fn out_of_class_witness_fails_the_property_test() {
    use fa_oracles::cases::branch::{WitnessValue, witness_seed, witnesses};
    let cells = f4_cells();
    let mmm = cells.iter().find(|c| c.key == ["mmm"]).expect("mmm");
    let w = witnesses("worldcom", "W-D-03", mmm, 64);
    // Move one minor unit from the first credit to the second: both become
    // non-multiples, the total is unchanged.
    let mut planted: Vec<i128> = w[7]
        .values
        .iter()
        .filter_map(|v| match v {
            WitnessValue::Legs(legs) => Some(legs.iter().map(|(_, a)| *a).collect::<Vec<_>>()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(planted.len(), 3, "a per-leg witness");
    planted[0] -= 1;
    planted[1] += 1;
    let o = property::residue_class("worldcom", "W-D-03", mmm, &w, Some((7, planted)));
    let text = o.lines.join("\n");
    assert_eq!((o.witnesses, o.agree), (64, 63), "{text}");
    let seed: String = witness_seed("worldcom", "W-D-03", mmm)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let at = o
        .lines
        .iter()
        .position(|l| l.starts_with("FAIL property "))
        .expect("the failing witness");
    assert_eq!(
        o.lines[at],
        format!(
            "FAIL property round_residue_legs class=mmm seed={seed} witness=7 expected severity=Medium statistic=4 legs=[W-7#0,W-7#1,W-7#2,W-7#3] observed severity=Low statistic=2 legs=[W-7#0,W-7#3]"
        ),
        "{text}"
    );
    assert!(
        o.lines[at + 1].starts_with("REPRODUCE fa --book "),
        "{text}"
    );
}

/// The sweep fixture (`crates/fa-oracles/tests/fixtures/sweep/`): S-1's
/// entry class × period state table (A7c).
const SWEEP: [(&str, &str); 5] = [
    (
        "case.toml",
        include_str!("../../fa-oracles/tests/fixtures/sweep/case.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../fa-oracles/tests/fixtures/sweep/roles.toml"),
    ),
    (
        "facts.toml",
        include_str!("../../fa-oracles/tests/fixtures/sweep/facts.toml"),
    ),
    (
        "books/native.toml",
        include_str!("../../fa-oracles/tests/fixtures/sweep/books/native.toml"),
    ),
    (
        "expectations.toml",
        include_str!("../../fa-oracles/tests/fixtures/sweep/expectations.toml"),
    ),
];

fn sweep_run() -> &'static RunOutcome {
    static RUN: std::sync::OnceLock<RunOutcome> = std::sync::OnceLock::new();
    RUN.get_or_init(|| match run_files("sweep", &SWEEP, &[], HARNESS_VERBS) {
        Ok(o) => o,
        Err(o) => *o,
    })
}

/// The swept cell lines of sweep-P-01.
fn sweep_cells(o: &RunOutcome) -> Vec<&str> {
    o.lines
        .iter()
        .map(String::as_str)
        .filter(|l| l.contains(" sweep-P-01 P native S-1/"))
        .collect()
}

/// A7c (§3.3): every P cell of S-1 is decided by `fa post --dry-run` on one
/// book, across Future → Open → SoftClosed → Closed → Locked, each under its
/// own key, and each observes its admissibility.toml outcome. The sweep
/// supplies the soft-close the history lacks.
#[test]
fn every_p_cell_of_one_entry_is_decided_by_dry_run_on_one_book() {
    let o = sweep_run();
    let text = o.text();
    let cells = sweep_cells(o);
    assert_eq!(cells.len(), 10, "{text}");
    // Every observed outcome is the authored one, and the reference oracle
    // (A4r) decides each cell the same way, so each reads PASS.
    assert!(
        cells
            .iter()
            .all(|l| l.starts_with("PASS ") && l.ends_with(" ref=agree")),
        "{text}"
    );
    for (cell, outcome) in [
        (
            "Original,period_state_at_commit=Future state=Future",
            "refusal=FA-REF-010 exit=7",
        ),
        (
            "Original,period_state_at_commit=Open state=Open",
            "refusal=admitted exit=0",
        ),
        (
            "Original,period_state_at_commit=SoftClosed state=SoftClosed",
            "refusal=FA-REF-011 exit=7",
        ),
        (
            "Adjusting,period_state_at_commit=SoftClosed state=SoftClosed",
            "refusal=admitted exit=0",
        ),
        (
            "Adjusting,period_state_at_commit=Closed state=Closed",
            "refusal=FA-REF-011 exit=7",
        ),
        (
            "Adjusting,period_state_at_commit=Locked state=Locked",
            "refusal=FA-REF-010 exit=7",
        ),
    ] {
        let prefix = format!("PASS sweep-P-01 P native S-1/entry_class={cell} {outcome}");
        assert!(
            cells.iter().any(|l| l.starts_with(&prefix)),
            "{prefix}\n{text}"
        );
    }
    // One book, one dry run per cell, each under its own `<key>.<12 hex>`.
    let dry: Vec<_> = o
        .steps
        .iter()
        .filter(|s| s.verb == "post" && s.argv_redacted.iter().any(|a| a == "--dry-run"))
        .collect();
    assert_eq!(dry.len(), 10, "{text}");
    let books: std::collections::BTreeSet<_> = dry.iter().map(|s| s.book_id.clone()).collect();
    assert_eq!(books.len(), 1, "{text}");
    // The sweep's own soft-close (the history has none).
    assert!(
        o.steps
            .iter()
            .any(|s| s.verb == "period" && s.argv_redacted.iter().any(|a| a == "soft-close")),
        "{text}"
    );
}

/// One representative per distinct outcome (FA-REF-010, admitted,
/// FA-REF-011) is committed right after its dry run and agrees with it.
#[test]
fn one_committed_representative_per_outcome_agrees_with_its_dry_run() {
    let o = sweep_run();
    let text = o.text();
    let reps: Vec<&str> = sweep_cells(o)
        .into_iter()
        .filter(|l| l.contains(" commit_agrees="))
        .collect();
    assert_eq!(reps.len(), 3, "{text}");
    assert!(
        reps.iter().all(|l| l.contains(" commit_agrees=ok ")),
        "{text}"
    );
    for cell in [
        "Original,period_state_at_commit=Future",
        "Original,period_state_at_commit=Open",
        "Original,period_state_at_commit=SoftClosed",
    ] {
        assert!(
            reps.iter()
                .any(|l| l.contains(&format!("S-1/entry_class={cell} "))),
            "{cell}\n{text}"
        );
    }
    // The admitted representative was committed from its dry run's plan.
    assert!(
        o.steps.iter().any(|s| s.verb == "commit"
            && s.exit == 0
            && s.argv_redacted.iter().any(|a| a == "--plan")),
        "{text}"
    );
}

/// The representative of Original in SoftClosed, committed under a grant
/// its dry run lacked, disagrees with the dry run: FAIL, naming the cell.
#[test]
fn planted_dry_run_commit_divergence_fails_naming_the_cell() {
    let case = fa_oracles::cases::load(&fa_oracles::cases::CaseFiles {
        id: "sweep",
        files: &SWEEP,
    })
    .expect("the sweep fixture loads");
    let groups = run::sweep_groups(&case, "native").expect("a plan");
    assert_eq!(groups.len(), 1);
    let plant = cells::Plant {
        cell: vec!["Original".into(), "SoftClosed".into()],
        commit_args: vec!["--grant".into(), "post_softclosed".into()],
    };
    let swept = cells::sweep(&case, &groups[0], &SWEEP, Some(&plant));
    let lines: Vec<String> = swept.cells.iter().map(|c| c.row.to_string()).collect();
    let text = lines.join("\n");
    let line = lines
        .iter()
        .find(|l| l.contains("S-1/entry_class=Original,period_state_at_commit=SoftClosed "))
        .expect("the planted cell's line");
    // The grant admits the commit its dry run refused.
    assert_eq!(
        line,
        "FAIL sweep-P-01 P native S-1/entry_class=Original,period_state_at_commit=SoftClosed state=SoftClosed refusal=FA-REF-011 exit=7 record_consistent=false commit_agrees=fail reason=expected FA-REF-011 observed admitted",
        "{text}"
    );
    let planted = swept
        .cells
        .iter()
        .find(|c| c.row.to_string() == *line)
        .expect("the cell");
    assert!(
        planted.reproduce.as_deref().is_some_and(
            |r| r.starts_with("REPRODUCE fa --book ") && r.contains("--grant post_softclosed")
        ),
        "{text}"
    );
}

/// A7c (§16): each book logs its invocation count and wall time, and the
/// case its total wall time, the warm cost of one invocation and its budget.
#[test]
fn budget_log_records_invocations_wall_time_and_warm_cost() {
    let o = sweep_run();
    let text = o.text();
    let field = |line: &str, key: &str| -> Option<u64> {
        line.split(' ')
            .find_map(|t| t.strip_prefix(&format!("{key}=")))
            .and_then(|v| v.parse().ok())
    };
    let book = o
        .lines
        .iter()
        .find(|l| l.starts_with("BUDGET sweep native book=1 "))
        .expect("the book's BUDGET line");
    assert!(field(book, "invocations").is_some_and(|n| n > 0), "{text}");
    assert!(field(book, "wall_ms").is_some(), "{text}");
    let case = o
        .lines
        .iter()
        .find(|l| l.starts_with("BUDGET sweep total_ms="))
        .expect("the case's BUDGET line");
    assert!(field(case, "warm_invocation_ms").is_some(), "{text}");
    assert_eq!(field(case, "budget_ms"), Some(60_000), "{text}");
    // The verdict is the measurement's: PASS exactly when the case's total
    // wall time is within its budget, with a FAIL budget line exactly when it
    // is not. (Whether this small case keeps 60 s depends on the worker's
    // load; the verdict's consistency does not.)
    let total = field(case, "total_ms").expect("total_ms");
    let failed = o.lines.iter().any(|l| l.starts_with("FAIL budget sweep "));
    assert_eq!(case.ends_with(" PASS"), total <= 60_000, "{text}");
    assert_eq!(failed, total > 60_000, "{text}");
    assert!(o.rows_ok, "{text}");
}

/// Over budget, the case fails, naming its wall time, budget and
/// invocations; every expectation is still evaluated (nothing is skipped to
/// fit).
#[test]
fn over_budget_case_fails_and_is_not_capped() {
    let full = sweep_run();
    let o = run::run_case_with(
        &fa_oracles::cases::CaseFiles {
            id: "sweep",
            files: &SWEEP,
        },
        HARNESS_VERBS,
        Some(1),
    );
    let text = o.text();
    assert!(!o.ok, "{text}");
    assert!(
        o.lines
            .iter()
            .any(|l| l.starts_with("FAIL budget sweep wall=")
                && l.contains(" budget=1 invocations=")),
        "{text}"
    );
    assert!(
        o.lines
            .iter()
            .any(|l| l.starts_with("BUDGET sweep total_ms=") && l.ends_with(" budget_ms=1 FAIL")),
        "{text}"
    );
    // The same rows as the run within budget.
    let rows = |o: &RunOutcome| -> Vec<String> {
        o.lines
            .iter()
            .filter(|l| l.contains(" sweep-P-01 ") || l.contains(" sweep-SELF-"))
            .cloned()
            .collect()
    };
    assert_eq!(rows(&o), rows(full), "{text}");
}

/// A filler variant above the chunk size posts as several `PostBatch`
/// chunks, each its own logged step under the variant's label. The real
/// limit (8,190) is A6's `extremal_variant_above_8190_entries_is_chunked`;
/// here the chunk size is lowered to 3 so the posting path runs quickly.
#[test]
fn filler_variant_above_the_batch_limit_posts_as_several_chunks() {
    use fa_oracles::cases::filler::{FillerKind, FillerSpec, generate};
    use fa_oracles::cases::tiers::Tier;
    const FILLER: [(&str, &str); 4] = [
        (
            "case.toml",
            include_str!("../../fa-oracles/tests/fixtures/filler/case.toml"),
        ),
        (
            "roles.toml",
            include_str!("../../fa-oracles/tests/fixtures/filler/roles.toml"),
        ),
        (
            "facts.toml",
            include_str!("../../fa-oracles/tests/fixtures/filler/facts.toml"),
        ),
        (
            "books/native.toml",
            include_str!("../../fa-oracles/tests/fixtures/filler/books/native.toml"),
        ),
    ];
    let case = fa_oracles::cases::load(&fa_oracles::cases::CaseFiles {
        id: "filler",
        files: &FILLER,
    })
    .expect("the filler fixture loads");
    let book = &case.books["native"];
    let spec = FillerSpec {
        case: "filler".into(),
        variant: "fv1".into(),
        kind: FillerKind::Seeded(1),
        tier: Tier::L,
    };
    let variant = generate(&case, book, &spec).expect("a seeded variant");
    let members = variant.intents.len();
    assert!(members > 3, "{members} members");
    let mut r = run::BookRun::new(&case, book, run::tmp("filler-chunks"), &FILLER);
    r.filler = Some(variant);
    r.chunk_max = 3;
    r.build();
    r.replay();
    let text = r.lines.join("\n");
    assert_eq!(r.failure, None, "{text}");
    let chunks: Vec<_> = r
        .steps
        .iter()
        .filter(|s| s.verb == "batch" && s.filler_variant.as_deref() == Some("fv1@1"))
        .collect();
    assert_eq!(chunks.len(), members.div_ceil(3), "{text}");
    assert!(chunks.iter().all(|s| s.exit == 0), "{text}");
    // The documented entries still post after the filler.
    assert!(
        r.vids.contains_key("S-1") && r.vids.contains_key("S-2"),
        "{text}"
    );
}

/// The D-cells fixture (`crates/fa-oracles/tests/fixtures/dcells/`): X-1's
/// leg_split table under jet.round_amounts (A7c).
const DCELLS: [(&str, &str); 5] = [
    (
        "case.toml",
        include_str!("../../fa-oracles/tests/fixtures/dcells/case.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../fa-oracles/tests/fixtures/dcells/roles.toml"),
    ),
    (
        "facts.toml",
        include_str!("../../fa-oracles/tests/fixtures/dcells/facts.toml"),
    ),
    (
        "books/native.toml",
        include_str!("../../fa-oracles/tests/fixtures/dcells/books/native.toml"),
    ),
    (
        "expectations.toml",
        include_str!("../../fa-oracles/tests/fixtures/dcells/expectations.toml"),
    ),
];

/// A7c (§3.3): the five feasible leg_split cells of X-1, a tier C reader's
/// table, are copies of X-1 posted beside it on one book, read by one run of
/// jet.round_amounts; each agrees with its authored row (UNRUN: the
/// filler-invariance witness, A11a, is not built).
#[test]
fn co_resident_l_and_c_d_cells_share_one_book() {
    let o = match run_files("dcells", &DCELLS, &[], HARNESS_VERBS) {
        Ok(o) => o,
        Err(o) if o.rows_ok => *o,
        Err(o) => panic!("{}", o.text()),
    };
    let text = o.text();
    let cells: Vec<&str> = o
        .lines
        .iter()
        .map(String::as_str)
        .filter(|l| l.contains(" dcells-D-01 D native X-1/"))
        .collect();
    assert_eq!(cells.len(), 5, "{text}");
    for (cell, tail) in [
        (
            "mmm",
            "cite=X-1#0,X-1#1,X-1#2,X-1#3 severity=Medium statistic=4",
        ),
        ("nnm", "cite=X-1#0,X-1#3 severity=Low statistic=2"),
        ("nmn", "cite=X-1#0,X-1#2 severity=Low statistic=2"),
        ("mnn", "cite=X-1#0,X-1#1 severity=Low statistic=2"),
        ("nnn", "cite=X-1#0 severity=Low statistic=1"),
    ] {
        let line = format!(
            "UNRUN dcells-D-01 D native X-1/leg_split={cell} procedure=jet.round_amounts@1 finding=yes {tail} record_consistent=false reason=filler_invariance"
        );
        assert!(cells.contains(&line.as_str()), "{line}\n{text}");
    }
    // One book holds all five copies, and one run of the procedure read them.
    let copies: Vec<_> = o
        .steps
        .iter()
        .filter(|s| s.verb == "post" && s.reference.starts_with("X-1~c"))
        .collect();
    assert_eq!(copies.len(), 5, "{text}");
    let books: std::collections::BTreeSet<_> = copies.iter().map(|s| s.book_id.clone()).collect();
    assert_eq!(books.len(), 1, "{text}");
    assert_eq!(
        o.steps
            .iter()
            .filter(|s| s.book_id == copies[0].book_id
                && s.verb == "finding"
                && s.finding_procedure.is_some())
            .count(),
        1,
        "{text}"
    );
}

/// A cell whose authored statistic disagrees with the run FAILs, naming the
/// cell.
#[test]
fn d_cell_disagreeing_with_its_authored_row_fails_naming_the_cell() {
    let o = run_files(
        "dcells",
        &DCELLS,
        &[PlantedEdit {
            file: "expectations.toml",
            old: "cell = [\"nnm\"]\nexpect = \"finding\"\ncite = [\"X-1#0\", \"X-1#3\"]\nseverity = \"Low\"\nstatistic_value = \"2\"",
            new: "cell = [\"nnm\"]\nexpect = \"finding\"\ncite = [\"X-1#0\", \"X-1#3\"]\nseverity = \"Low\"\nstatistic_value = \"3\"",
        }],
        HARNESS_VERBS,
    )
    .expect_err("the planted cell fails");
    assert!(
        o.lines.iter().any(|l| l
            == "FAIL dcells-D-01 D native X-1/leg_split=nnm procedure=jet.round_amounts@1 finding=yes cite=X-1#0,X-1#3 severity=Low statistic=2 record_consistent=false reason=expected statistic=3 observed statistic=2"),
        "{}",
        o.text()
    );
}

/// The evidence sweep fixture
/// (`crates/fa-oracles/tests/fixtures/sweep_evidence/`): S-1's
/// evidence_attached table, a ManualAssertion cell included (A7c).
const SWEEP_EVIDENCE: [(&str, &str); 5] = [
    (
        "case.toml",
        include_str!("../../fa-oracles/tests/fixtures/sweep_evidence/case.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../fa-oracles/tests/fixtures/sweep_evidence/roles.toml"),
    ),
    (
        "facts.toml",
        include_str!("../../fa-oracles/tests/fixtures/sweep_evidence/facts.toml"),
    ),
    (
        "books/native.toml",
        include_str!("../../fa-oracles/tests/fixtures/sweep_evidence/books/native.toml"),
    ),
    (
        "expectations.toml",
        include_str!("../../fa-oracles/tests/fixtures/sweep_evidence/expectations.toml"),
    ),
];

/// A7c (§3.3): a ManualAssertion cell is planned by `fa document attest
/// manual --plan-out` (never resealed by a second post) and its
/// representative is committed from that plan; the other evidence cells are
/// dry runs, each its evidence policy's outcome.
#[test]
fn manual_assertion_cell_is_planned_by_attest_manual_and_committed_from_that_plan() {
    let o = match run_files("sweep_evidence", &SWEEP_EVIDENCE, &[], HARNESS_VERBS) {
        Ok(o) => o,
        Err(o) if o.rows_ok => *o,
        Err(o) => panic!("{}", o.text()),
    };
    let text = o.text();
    for (cell, outcome) in [
        (
            "none",
            "refusal=FA-REF-080 exit=3 record_consistent=false commit_agrees=ok",
        ),
        (
            "placeholder_unreviewed",
            "refusal=FA-REF-086 exit=3 record_consistent=false commit_agrees=ok",
        ),
        (
            "placeholder_reviewed",
            "refusal=admitted exit=0 commit_agrees=ok",
        ),
        (
            "manual_assertion(InternalTransfer)",
            "refusal=admitted exit=0 record_consistent=false commit_agrees=ok",
        ),
    ] {
        let line = format!(
            "PASS sweep_evidence-P-01 P native S-1/evidence_attached={cell} state=Open {outcome} ref=agree"
        );
        assert!(o.lines.contains(&line), "{line}\n{text}");
    }
    // The asserted cell: one `attest manual --plan-out`, then a commit of
    // that plan.
    let at = o
        .steps
        .iter()
        .position(|s| {
            s.verb == "document"
                && s.argv_redacted.iter().any(|a| a == "manual")
                && s.argv_redacted.iter().any(|a| a == "--plan-out")
        })
        .expect("the attest step");
    let commit = o.steps[at + 1..]
        .iter()
        .find(|s| s.verb == "commit")
        .expect("its commit");
    assert_eq!(commit.exit, 0, "{text}");
}

/// The invariance fixture (`crates/fa-oracles/tests/fixtures/invariance/`):
/// A6's filler fixture with a D row on jet.round_amounts (A11a).
const INVARIANCE: [(&str, &str); 5] = [
    (
        "case.toml",
        include_str!("../../fa-oracles/tests/fixtures/invariance/case.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../fa-oracles/tests/fixtures/invariance/roles.toml"),
    ),
    (
        "facts.toml",
        include_str!("../../fa-oracles/tests/fixtures/invariance/facts.toml"),
    ),
    (
        "books/native.toml",
        include_str!("../../fa-oracles/tests/fixtures/invariance/books/native.toml"),
    ),
    (
        "expectations.toml",
        include_str!("../../fa-oracles/tests/fixtures/invariance/expectations.toml"),
    ),
];

/// A book with no filler_batch step cannot vary its filler: the row keeps
/// waiting on the witness and never reads PASS.
#[test]
fn expectation_needing_invariance_with_one_book_id_is_unrun() {
    let o = match run_files(
        "invariance",
        &INVARIANCE,
        &[PlantedEdit {
            file: "books/native.toml",
            old: "[[step]]\nseq = 2\nkind = \"filler_batch\"\nref = \"fv1\"\nprincipal = \"selftest-preparer-1\"\n",
            new: "",
        }],
        HARNESS_VERBS,
    ) {
        Ok(o) => o,
        Err(o) if o.rows_ok => *o,
        Err(o) => panic!("{}", o.text()),
    };
    let row = o.row("invariance-D-01").expect("the D row");
    assert!(
        row.starts_with("UNRUN ") && row.ends_with(" reason=filler_invariance"),
        "{}",
        o.text()
    );
}

/// The witness at small volume: the seeded and the empty filler variants,
/// no extremal one. The extremal variants (2,000 entries) run in the
/// ignored tests of `--test cases_invariance` until fa-q7vt.
fn no_extremal(s: &fa_oracles::cases::filler::FillerSpec) -> bool {
    !matches!(s.kind, fa_oracles::cases::filler::FillerKind::Extremal(_))
}

/// A11a: the D row's single components agree on the five seeded variants
/// and the empty one, run on its own book besides the main run: six
/// variants, seven book ids, all through the binary.
#[test]
fn invariance_on_the_seeded_and_empty_variants_agrees_through_the_binary() {
    let tiers = fa_oracles::cases::tiers::tiers().expect("the tier table");
    let w = invariance::witness("invariance", &INVARIANCE, &tiers, &no_extremal);
    let text = w.text();
    let row = w.row("invariance-D-01").expect("the D row");
    assert!(
        row.starts_with(
            "PASS invariance-D-01 D native S-1/default procedure=jet.round_amounts@1 entry=S-1 cite=S-1#0,S-1#1 severity=Medium statistic_name=round_legs statistic=2 scale=0 "
        ),
        "{text}"
    );
    assert!(
        row.ends_with(" invariance=agree(variants=6,book_ids=7)"),
        "{text}"
    );
    assert!(
        w.row("invariance-SELF-native")
            .is_some_and(|l| l.starts_with("PASS ")
                && l.ends_with(" invariance=agree(variants=6,book_ids=7)")),
        "{text}"
    );
}

/// A11a's negative at small volume: under a test tier table declaring
/// numbers.round_amount_density tier L, four filler entries already move the
/// finding from Medium to High (the fixture sits just under High), so the
/// first seeded variant disagrees with the empty one and the row fails,
/// naming the tier row.
#[test]
fn tier_l_row_disagrees_on_a_seeded_variant_naming_the_tier_row() {
    let (tiers, line) = invariance::round_density_tier_l();
    let w = invariance::witness(
        "invariance_negative",
        &invariance::NEGATIVE,
        &tiers,
        &no_extremal,
    );
    let text = w.text();
    let row = w.row("invariance_negative-D-01").expect("the D row");
    assert!(
        row.starts_with("FAIL invariance_negative-D-01 D native N-1/default ")
            && row.contains(" severity=Medium "),
        "{text}"
    );
    assert!(
        row.contains(" invariance=disagree(numbers.round_amount_density@1,severity,fv1@empty/")
            && row.contains(",fv1@1/"),
        "{text}"
    );
    assert!(
        row.ends_with(&format!(
            " reason=tier row case_procedure_tiers.toml:{line} declares L"
        )),
        "{text}"
    );
}

/// The Rel fixture (`crates/fa-oracles/tests/fixtures/rel/`, A5b): one entry
/// debiting two fixed-asset accounts, read by expense.capitalization@2.
const REL: [(&str, &str); 5] = [
    (
        "case.toml",
        include_str!("../../fa-oracles/tests/fixtures/rel/case.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../fa-oracles/tests/fixtures/rel/roles.toml"),
    ),
    (
        "facts.toml",
        include_str!("../../fa-oracles/tests/fixtures/rel/facts.toml"),
    ),
    (
        "books/native.toml",
        include_str!("../../fa-oracles/tests/fixtures/rel/books/native.toml"),
    ),
    (
        "expectations.toml",
        include_str!("../../fa-oracles/tests/fixtures/rel/expectations.toml"),
    ),
];

/// A5b (§2.6 rule 9): a Rel component is judged on the run by its rule,
/// from the account VIds the binary reported. Which account the finding
/// cites follows the random book id, so the test accepts either, but the
/// cite and the capitalized amount must be the rule's selection on this run.
#[test]
fn rel_component_is_judged_by_its_rule_on_the_run() {
    let o = match run_files("rel", &REL, &[], HARNESS_VERBS) {
        Ok(o) => o,
        Err(o) if o.rows_ok => *o,
        Err(o) => panic!("{}", o.text()),
    };
    let row = o.row("rel-D-01").expect("the D row");
    assert!(
        row.starts_with(
            "UNRUN rel-D-01 D native R-1/default procedure=expense.capitalization@2 entry=R-1 "
        ) && row.ends_with(" reason=filler_invariance"),
        "{}",
        o.text()
    );
    let token = |name: &str| {
        row.split(' ')
            .find_map(|t| t.strip_prefix(&format!("{name}=")))
            .unwrap_or_default()
            .to_string()
    };
    let rel = token("rel");
    let (account, magnitude) = rel.split_once('/').expect("rel=<account>/<magnitude>");
    assert!(
        [("1500", "30000"), ("1510", "20000")].contains(&(account, magnitude)),
        "{}",
        o.text()
    );
    assert!(
        token("cite").split(',').any(|c| c == account),
        "{}",
        o.text()
    );
    assert_eq!(token("statistic"), magnitude, "{}", o.text());
}

/// A5b: W4's misreading plant on the runner. A `max_vid_debit_leg` rule
/// selects the other fixed-asset account than expense.capitalization does,
/// so the row fails on every run, naming the rule's components.
#[test]
fn rel_rule_that_misreads_the_code_fails_on_the_run() {
    let o = match run_files(
        "rel",
        &REL,
        &[PlantedEdit {
            file: "expectations.toml",
            old: "rel_rule = \"min_vid_debit_leg{fixed_asset}\"",
            new: "rel_rule = \"max_vid_debit_leg{fixed_asset}\"",
        }],
        HARNESS_VERBS,
    ) {
        Ok(o) => o,
        Err(o) => *o,
    };
    let row = o.row("rel-D-01").expect("the D row");
    assert!(
        row.starts_with("FAIL rel-D-01 D native R-1/default ")
            && row.contains(" reason=expected cite=its relational rule observed cite=")
            && row.contains("; expected statistic=its relational rule observed statistic="),
        "{}",
        o.text()
    );
}

/// A5b + A11a: the Rel row through the invariance witness. The Rel fixture,
/// given filler accounts, a filler document and a filler_batch step, runs
/// on the seeded and empty variants (seven books, seven book ids). Which
/// fixed-asset account each run cites follows that run's book id, so the
/// values may differ across runs; the rule holds on every one, so the row
/// agrees.
#[test]
fn rel_row_agrees_across_book_ids_when_its_rule_holds() {
    let once = |text: &str, old: &str, new: &str| {
        assert_eq!(text.matches(old).count(), 1, "{old}");
        text.replacen(old, new, 1)
    };
    let case = once(
        REL[0].1,
        "capabilities = [\"verb:post\",",
        "capabilities = [\"verb:post\", \"verb:batch\",",
    );
    let mut book = once(
        REL[3].1,
        "[[document]]\nid = \"DOC-PH-R-1\"",
        "[[account]]\ncode = \"9001\"\nname_fact = \"R-1\"\ntype = \"Expense\"\nrole = \"\"\nopened = \"2026-01-01\"\nrole_map_rule = \"role_map\"\n\n[[account]]\ncode = \"9002\"\nname_fact = \"R-1\"\ntype = \"Liability\"\nrole = \"\"\nopened = \"2026-01-01\"\nrole_map_rule = \"role_map\"\n\n[[document]]\nid = \"DOC-FILL\"\nstub_of = \"filler:fv1\"\ngrade = \"AgentUpload\"\nreviewed_by = \"case-second-reader\"\n\n[[document]]\nid = \"DOC-PH-R-1\"",
    );
    book = once(
        &book,
        "seq = 3\nkind = \"finding_record\"",
        "seq = 4\nkind = \"finding_record\"",
    );
    book = once(
        &book,
        "[[step]]\nseq = 2\nkind = \"intent\"",
        "[[step]]\nseq = 2\nkind = \"filler_batch\"\nref = \"fv1\"\nprincipal = \"selftest-preparer-1\"\n\n[[step]]\nseq = 3\nkind = \"intent\"",
    );
    let files: [(&str, &str); 5] = [
        ("case.toml", &case),
        REL[1],
        REL[2],
        ("books/native.toml", &book),
        REL[4],
    ];
    let tiers = fa_oracles::cases::tiers::tiers().expect("the tier table");
    let w = invariance::witness("rel", &files, &tiers, &no_extremal);
    let text = w.text();
    let row = w.row("rel-D-01").expect("the D row");
    assert!(
        row.starts_with(
            "PASS rel-D-01 D native R-1/default procedure=expense.capitalization@2 entry=R-1 "
        ) && row.ends_with(" invariance=agree(variants=6,book_ids=7)"),
        "{text}"
    );
    assert!(row.contains(" rel=15"), "{text}");
}

/// The reads fixture (`crates/fa-oracles/tests/fixtures/reads/`, A7b): a
/// per_account T with its assert_balance step and an R read-back.
const READS: [(&str, &str); 5] = [
    (
        "case.toml",
        include_str!("../../fa-oracles/tests/fixtures/reads/case.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../fa-oracles/tests/fixtures/reads/roles.toml"),
    ),
    (
        "facts.toml",
        include_str!("../../fa-oracles/tests/fixtures/reads/facts.toml"),
    ),
    (
        "books/native.toml",
        include_str!("../../fa-oracles/tests/fixtures/reads/books/native.toml"),
    ),
    (
        "expectations.toml",
        include_str!("../../fa-oracles/tests/fixtures/reads/expectations.toml"),
    ),
];

fn reads_run(edits: &[PlantedEdit]) -> Box<RunOutcome> {
    match run_files("reads", &READS, edits, HARNESS_VERBS) {
        Ok(o) => Box::new(o),
        Err(o) => o,
    }
}

/// A7b (§5.3): the per_account T reads its cell certified, equal to its
/// published 1,000.00; its assert_balance step recorded B and its twin
/// (B plus one minor unit) was refused FA-REF-140; the T then waits on its
/// contributing-entry witness (A11b) and outsider check (A12), never PASS.
/// The R row reads the locked quarter as originally reported: PASS.
#[test]
fn per_account_t_and_its_read_back_are_read_certified() {
    let o = reads_run(&[]);
    let text = o.text();
    assert_eq!(
        o.row("reads-T-01"),
        Some(
            "UNRUN reads-T-01 T native -/default kind=per_account read=balance,1100,2026Q1 value=1000.00 assert=recorded twin=refused:FA-REF-140:exit=3 reason=contributing_entry,outsider"
        ),
        "{text}"
    );
    assert_eq!(
        o.row("reads-R-01"),
        Some(
            "PASS reads-R-01 R native -/default kind=read_back read=balance,1100,2026Q1,originally-reported value=1000.00"
        ),
        "{text}"
    );
}

/// A7b: a published value the book does not reach fails the T row, naming
/// both values, and the kernel refuses its assertion FA-REF-140.
#[test]
fn t_whose_read_differs_from_its_published_value_fails() {
    let o = reads_run(&[PlantedEdit {
        file: "facts.toml",
        old: "fact = \"P-1\"\nordinal = 1\nliteral = \"1,000\"\nrule = \"scale\"\nparam = 0\nvalue = \"100000\"",
        new: "fact = \"P-1\"\nordinal = 1\nliteral = \"999\"\nrule = \"scale\"\nparam = 0\nvalue = \"99900\"",
    }]);
    let text = o.text();
    let row = o.row("reads-T-01").expect("the T row");
    assert!(
        row.starts_with("FAIL reads-T-01 T native -/default kind=per_account read=balance,1100,2026Q1 value=1000.00 assert=refused ")
            && row.contains("reason=expected value=999.00 observed value=1000.00; expected assert-balance 999.00 USD recorded observed exit=3 FA-REF-140"),
        "{text}"
    );
}
