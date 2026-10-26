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

#[path = "cases/cells.rs"]
mod cells;
#[path = "cases/evaluate.rs"]
mod evaluate;
#[path = "cases/property.rs"]
mod property;
#[path = "cases/run.rs"]
mod run;

use fa_oracles::cases::harness_verbs::HARNESS_VERBS;
use fa_oracles::json::{self, Json};

use run::{PlantedEdit, RunOutcome, fa, outcome, run_case, run_files, run_planted};

const SELFTEST: &str = "_selftest";

const SELFTEST_D: &str = "UNRUN _selftest-D-01 D native S-1/default procedure=jet.round_amounts@1 entry=S-1 cite=S-1#0,S-1#1 severity=Medium statistic_name=round_legs statistic=2 scale=0 reason=filler_invariance";

fn selftest_files() -> fa_oracles::cases::CaseFiles<'static> {
    fa_oracles::cases::embedded::SELFTEST.case_files()
}

/// The harness self-test: every implemented stage over its synthetic book,
/// each row's evaluated components in agreement.
#[test]
fn _selftest() {
    let o = outcome(SELFTEST);
    let text = o.text();
    assert!(o.ok, "{text}");
    assert_eq!(o.row("_selftest-D-01"), Some(SELFTEST_D), "{text}");
    let p = o.row("_selftest-P-01").unwrap_or_default();
    assert!(
        p.starts_with(
            "UNRUN _selftest-P-01 P native -/default law=admissibility.toml#Original/Future refusal=FA-REF-010 exit=7 law_named=ok matrix=ok "
        ) && p.ends_with(" alternatives=ok reason=reference"),
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
            "FAIL _selftest-D-01 D native S-1/default procedure=jet.round_amounts@1 entry=S-1 cite=S-1#0,S-1#1 severity=Medium statistic_name=round_legs statistic=2 scale=0 reason=expected cite=S-1#0,S-2#1 observed cite=S-1#0,S-1#1"
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
    assert!(o.ok, "{text}");
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
    assert!(o.ok, "{text}");
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
    // Every observed outcome is the authored one; the reference verdict
    // (A4r) is not built, so none reads PASS.
    assert!(
        cells
            .iter()
            .all(|l| l.starts_with("UNRUN ") && l.ends_with(" reason=reference")),
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
        let prefix = format!("UNRUN sweep-P-01 P native S-1/entry_class={cell} {outcome}");
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
