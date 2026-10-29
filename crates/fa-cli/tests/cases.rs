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
#[path = "cases/lifecycle.rs"]
mod lifecycle;
#[path = "cases/outsider.rs"]
mod outsider;
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

const SELFTEST_D: &str = "UNRUN _selftest-D-01 D native S-1/default procedure=jet.round_amounts@1 entry=S-1 cite=S-1#0,S-1#1 severity=Medium statistic_name=round_legs statistic=2 scale=0 ref=agree outsider=replay:verified reason=filler_invariance";

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
            "UNRUN _selftest-SELF-native D native -/default procedure=jet.self_sourced_evidence@1 entries=A-1,N-1,P-1,S-1,delta-A-1 severity=Medium reason=filler_invariance"
        ),
        "{text}"
    );
    // A8a: P-1's cells by dry run, N-1 and its mutation twin, the bridge T
    // (A, the case's delta, B certified) and its read-back, and the case's
    // generated row. The claimed rows (case.toml) are the ones that PASS.
    for row in [
        "PASS _selftest-P-02 P native P-1/evidence_attached=none state=Open refusal=FA-REF-080 exit=3 record_consistent=false commit_agrees=ok ref=agree",
        "PASS _selftest-P-02 P native P-1/evidence_attached=placeholder_unreviewed state=Open refusal=FA-REF-086 exit=3 record_consistent=false commit_agrees=ok ref=agree",
        "PASS _selftest-P-02 P native P-1/evidence_attached=placeholder_reviewed state=Open refusal=admitted exit=0 commit_agrees=ok ref=agree",
        "PASS _selftest-P-03 P native P-1/period_state_at_commit=Open state=Open refusal=admitted exit=0 ref=agree",
        "PASS _selftest-P-03 P native P-1/period_state_at_commit=Closed state=Closed refusal=FA-REF-010 exit=7 record_consistent=false commit_agrees=ok ref=agree",
        "UNRUN _selftest-N-01 N native N-1/default kind=no_finding twin=mutation:reported reason=filler_invariance",
        "PASS _selftest-R-01 R native -/default kind=read_back read=balance,1100,2026Q1,as-originally-reported value=1000.00 gql=ok",
        "PASS _selftest-CASE-selftest-restatement R native -/default kind=case_show read=case show,selftest-restatement state=Closed case_kind=Restatement determined_on=2026-05-15 authority=DOC-PH-DET disclosure=reviewed twin=refused:FA-REF-179:exit=3 one_approval=refused:FA-REF-012:exit=7:Rehearsed outside_case=refused:FA-REF-178:exit=3",
    ] {
        assert!(o.lines.iter().any(|l| l == row), "{row}\n{text}");
    }
    // The outsider stage: the as-filed checkpoint and the examiner witness's
    // cosignature of it, the closing checkpoint, the balance sheet's report
    // bundle verified in process, its replay byte-identical, the book's
    // integrity green, and the restated book proved to extend the as-filed
    // one (A12).
    assert!(
        o.lines.iter().any(|l| l
            == "OUTSIDER native checkpoint=created witness=cosigned checkpoint=created bundle=verified replay=identical verify_book=green append_only=ok:inclusion=1:rollback=FA-REF-124:foreign=FA-REF-100"),
        "{text}"
    );
    assert!(!text.contains("REPRODUCE"), "{text}");
    assert_eq!(
        o.lines.last().map(String::as_str),
        Some(format!("LOG {}", o.log_path.display()).as_str())
    );
}

/// A8 (§15): the WorldCom pilot on the native book. F2, F4, F9 and F12 post
/// as the record describes them, and the claimed rows (W-D-01 and W-D-03,
/// the detections; W-N-01, the no-finding with its mutation twin; W-P-02
/// and W-P-03, the first refusals) pass through every witness the runner
/// holds them to, against the plan's predicted values.
#[test]
fn worldcom() {
    let o = outcome("worldcom");
    let text = o.text();
    println!("{text}");
    assert!(o.rows_ok, "{text}");
}

/// A12 (§12.1, Appendix Z.7): the first green T. The self-test's bridge T
/// reads its certified B (900.00, A plus the case's delta), holds its
/// contributing-entry witness (A11b), and passes its outsider check: its
/// explain-balance certificate is bundled against a checkpoint, verified by
/// the literal `fa-verify report` argv, whose recomputed cells equal B, and
/// replayed byte for byte (after its GQL second read). The T is claimed,
/// and the case passes.
#[test]
fn selftest_bridge_t_passes_with_the_outsider_check() {
    let o = outcome(SELFTEST);
    let text = o.text();
    assert_eq!(
        o.row("_selftest-T-01"),
        Some(
            "PASS _selftest-T-01 T native -/default kind=bridge read=balance,1100,2026Q1,as-currently-stated value=900.00 gql=ok contrib=holds outsider=report:verified append_only=ok"
        ),
        "{text}"
    );
    let route: Vec<String> = o
        .steps
        .iter()
        .filter(|s| s.reference == "_selftest-T-01/-" && s.verb != "explain")
        .map(|s| {
            format!(
                "{} {} exit={} {}",
                s.verb,
                s.argv_redacted.first().map_or("-", String::as_str),
                s.exit,
                s.certificate_kind.as_deref().unwrap_or("-")
            )
        })
        .collect();
    assert_eq!(
        route,
        [
            "query --book exit=0 Query",
            "bundle --book exit=0 Bundle",
            "fa-verify report exit=0 FaVerifyReport",
            "replay --book exit=0 -",
        ],
        "{text}"
    );
    // The claimed T keeps its claim (its rows; the wall budget depends on
    // the worker's load and has its own test).
    assert!(o.rows_ok, "{text}");
}

/// A12 (§12.7): the append-only witness on the self-test bridge, in every
/// run of its book that reaches the outsider stage (the base run and its
/// invariance runs). The examiner
/// witness cosigned the as-filed checkpoint before the case (step 11);
/// after it, the witness cosigns the restated book with `--previous`, which
/// the book proves extends the as-filed statement, and `fa-verify
/// checkpoint` accepts it at quorum 1. The consistency proof from the
/// as-filed state and the inclusion proof of A-1 (the entry the delta
/// restates) verify offline: an examiner who witnessed the as-filed root can
/// check that the restated book extends it and still includes the as-filed
/// entry. The bridge T carries `append_only=ok`.
#[test]
fn append_only_witness_holds_on_the_selftest_bridge() {
    let o = outcome(SELFTEST);
    let text = o.text();
    let by_run = |keep: &dyn Fn(&fa_oracles::cases::log::StepRecord) -> bool| {
        let mut runs: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for s in o.steps.iter().filter(|s| keep(s)) {
            let what = if s.verb == "fa-verify" {
                format!(
                    "fa-verify {}",
                    s.argv_redacted.first().map_or("-", String::as_str)
                )
            } else {
                words(&s.argv_redacted)
            };
            runs.entry(s.book_id.clone().unwrap_or_default())
                .or_default()
                .push(format!(
                    "{what} exit={} {}",
                    s.exit,
                    s.refusal_id.as_deref().unwrap_or("-")
                ));
        }
        runs
    };
    let cosigned = by_run(&|s| s.step == 11);
    assert!(!cosigned.is_empty(), "{text}");
    for (book, run) in &cosigned {
        assert_eq!(
            run,
            &[
                "checkpoint witness-key exit=0 -",
                "checkpoint witness exit=0 -"
            ],
            "{book}\n{text}"
        );
    }
    // Every run that reaches the outsider stage extends the statement its
    // own step 11 cosigned (twin and cell runs replay without that stage).
    let extended = by_run(&|s| s.reference == "append-only");
    assert!(!extended.is_empty(), "{text}");
    assert!(
        extended.keys().all(|book| cosigned.contains_key(book)),
        "{text}"
    );
    for (book, run) in &extended {
        assert_eq!(
            run,
            &[
                "checkpoint create exit=0 -",
                "checkpoint witness exit=0 -",
                "fa-verify checkpoint exit=0 -",
                "proof signed-checkpoint exit=0 -",
                "proof signed-checkpoint exit=0 -",
                "proof consistency exit=0 -",
                "fa-verify consistency exit=0 -",
                "proof inclusion exit=0 -",
                "fa-verify inclusion exit=0 -",
                "checkpoint witness exit=8 FA-REF-124",
                "checkpoint witness exit=2 FA-REF-100",
            ],
            "{book}\n{text}"
        );
    }
    assert!(
        o.row("_selftest-T-01")
            .is_some_and(|r| r.ends_with(" outsider=report:verified append_only=ok")),
        "{text}"
    );
}

/// The witness's cosignature attempts of every run that `keep` selects:
/// each (exit, refusal).
fn twin_outcomes(o: &RunOutcome, keep: impl Fn(&[String]) -> bool) -> Vec<(i128, Option<String>)> {
    o.steps
        .iter()
        .filter(|s| s.reference == "append-only" && keep(&s.argv_redacted))
        .map(|s| (s.exit, s.refusal_id.clone()))
        .collect()
}

/// A12 (§12.1, D reads): each recorded finding run's canonical workpaper,
/// with its review appendix fixed at the head, is exported (`fa finding
/// export --export-format canonical --include-reviews --known-at <head>`)
/// and replayed recipient-bound (`fa finding replay --certificate C:<run>
/// --known-at <head>`) to the same certified run, in every run of the book;
/// the D row prints `outsider=replay:verified`.
#[test]
fn finding_export_replays_for_d_reads() {
    let o = outcome(SELFTEST);
    let text = o.text();
    let steps: Vec<String> = o
        .steps
        .iter()
        .filter(|s| {
            matches!(
                words(&s.argv_redacted).as_str(),
                "finding export" | "finding replay"
            )
        })
        .map(|s| {
            format!(
                "{} {} exit={}",
                words(&s.argv_redacted),
                s.reference,
                s.exit
            )
        })
        .collect();
    assert!(!steps.is_empty(), "{text}");
    assert!(
        steps.chunks(2).all(|pair| matches!(
            pair,
            [export, replay] if export.starts_with("finding export ")
                && replay.starts_with("finding replay ")
                && export.ends_with(" exit=0")
                && replay.ends_with(" exit=0")
        )),
        "{steps:?}\n{text}"
    );
    assert!(
        o.row("_selftest-D-01")
            .is_some_and(|r| r.contains(" ref=agree outsider=replay:verified ")),
        "{text}"
    );
}

/// A12 (§12.7): the second read path. Each balance read is also read with
/// `fa query --certify` at the sequence its fold path resolved, and nets to
/// the fold value (`gql=ok`): the bridge T as currently stated at the head,
/// and the R as originally reported at the sequence its view resolved (the
/// quarter's lock, before the case), in every run of the book. The view
/// itself is not certified beside a native read; this slice certifies the
/// resolved sequence only (the uncertified view read is later work).
#[test]
fn gql_view_read_is_certified_at_its_resolved_sequence() {
    let o = outcome(SELFTEST);
    let text = o.text();
    let mut runs: std::collections::BTreeMap<String, (Option<i128>, Option<i128>)> =
        std::collections::BTreeMap::new();
    for s in o.steps.iter().filter(|s| s.verb == "query") {
        assert_eq!(s.exit, 0, "{text}");
        assert!(s.argv_redacted.iter().any(|a| a == "--certify"), "{text}");
        assert_eq!(s.certificate_kind.as_deref(), Some("Query"), "{text}");
        let statement = s.argv_redacted.get(3).cloned().unwrap_or_default();
        let seq: i128 = statement
            .rsplit("AS KNOWN AT ")
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("a known-at in {statement}\n{text}"));
        let run = runs
            .entry(s.book_id.clone().unwrap_or_default())
            .or_default();
        match s.reference.as_str() {
            "_selftest-T-01/-" => run.0 = Some(seq),
            "_selftest-R-01/-" => run.1 = Some(seq),
            other => panic!("an unexpected query for {other}\n{text}"),
        }
    }
    assert!(!runs.is_empty(), "{text}");
    for (book, (current, original)) in &runs {
        assert!(
            matches!((current, original), (Some(c), Some(r)) if r < c),
            "{book}: {current:?} {original:?}\n{text}"
        );
    }
    for id in ["_selftest-T-01", "_selftest-R-01"] {
        assert!(
            o.row(id).is_some_and(|r| r.contains(" gql=ok")),
            "{id}\n{text}"
        );
    }
}

/// A12 (§12.7, harness-only twin): a rollback. The restated book's
/// statement as `--previous` for the as-filed state is a history the
/// as-filed state does not extend, so the cosignature is refused FA-REF-124
/// (exit 8) and nothing is signed.
#[test]
fn witness_rollback_to_the_as_filed_state_is_refused_fa_ref_124() {
    let o = outcome(SELFTEST);
    let rollbacks = twin_outcomes(o, |argv| argv.iter().any(|a| a == "$WORK/rollback.witness"));
    assert!(!rollbacks.is_empty(), "{}", o.text());
    for twin in rollbacks {
        assert_eq!(twin, (8, Some("FA-REF-124".to_string())), "{}", o.text());
    }
}

/// A12 (§12.7, harness-only twin): the witness's statement cosigned on
/// another book. The plan expected FA-REF-124 here; the book refuses it
/// earlier, as no history this witness signed on it (FA-REF-100, exit 2,
/// `--previous is a checkpoint of another book`), and signs nothing.
#[test]
fn witness_previous_from_another_book_is_refused_as_not_its_history() {
    let o = outcome(SELFTEST);
    let foreign = twin_outcomes(o, |argv| {
        argv.windows(2)
            .any(|w| w[0] == "--previous" && w[1] == "$WORK/other-book.witness")
    });
    assert!(!foreign.is_empty(), "{}", o.text());
    for twin in foreign {
        assert_eq!(twin, (2, Some("FA-REF-100".to_string())), "{}", o.text());
    }
}

/// A8a (§3.7 item 3): an N twin that keeps the target's 1,234.56 legs is
/// not a mutation, so the procedure does not report it and the row fails.
#[test]
fn _selftest_neg_n_twin_that_keeps_the_legs_fails() {
    let o = run_planted(
        SELFTEST,
        &[PlantedEdit {
            file: "expectations.toml",
            old: "twin_value = \"1000.00\"",
            new: "twin_value = \"1234.56\"",
        }],
        HARNESS_VERBS,
    )
    .expect_err("a twin that does not report fails the case");
    let row = o.row("_selftest-N-01").unwrap_or_default();
    assert!(
        row.starts_with(
            "FAIL _selftest-N-01 N native N-1/default kind=no_finding twin=mutation:did_not_report "
        ),
        "{}",
        o.text()
    );
}

/// §5.3: a T passes on exact equality at its published value's declared
/// precision. A planted copy states the self-test's B to the hundred dollars
/// (precision 2); the certified 900.00 equals it to the cent, so it equals it
/// at that precision too and the T passes without a rounding rule.
#[test]
fn bridge_t_equal_to_a_coarsely_stated_b_passes() {
    let o = match run_planted(
        SELFTEST,
        &[PlantedEdit {
            file: "facts.toml",
            old: "value = \"90000\"\nunit = \"USD\"\nprecision = 0",
            new: "value = \"90000\"\nunit = \"USD\"\nprecision = 2",
        }],
        HARNESS_VERBS,
    ) {
        Ok(o) => o,
        Err(o) => *o,
    };
    let row = o.row("_selftest-T-01").unwrap_or_default();
    assert!(
        row.starts_with("PASS _selftest-T-01 T ") && row.contains(" value=900.00 "),
        "{}",
        o.text()
    );
}

/// A11b (§3.7 item 2): the bridge's contributions on 1100 are exactly A's
/// and the delta's entries (its named inputs: the basis intents other than
/// the published B, and their delta) and re-add to the certified 900.00.
#[test]
fn selftest_bridge_contributions_are_exactly_a_and_delta() {
    let o = outcome(SELFTEST);
    let row = o.row("_selftest-T-01").unwrap_or_default();
    assert!(row.contains(" contrib=holds "), "{}", o.text());
    let record = o
        .verdicts
        .iter()
        .find(|v| v.expectation == "_selftest-T-01")
        .expect("the T's verdict record");
    assert!(
        record
            .witnesses
            .contains(&("named_inputs".to_string(), "A-1,delta-A-1".to_string())),
        "{:?}",
        record.witnesses
    );
}

/// A11b: a T whose published value is a posted amount (A, read back as
/// originally reported) is a read-back, never a T: the witness finds the
/// contribution carrying B and the row prints as R. The T is claimed (A12),
/// so the re-typed row fails the case.
#[test]
fn _selftest_neg_read_back_t_never_passes_as_t() {
    let o = run_planted(
        SELFTEST,
        &[PlantedEdit {
            file: "expectations.toml",
            old: "read_selector = \"currently_stated\"\npublished = \"B-1\"",
            new: "read_selector = \"originally_reported\"\npublished = \"A-1\"",
        }],
        HARNESS_VERBS,
    )
    .expect_err("a claimed T re-typed R fails the case");
    let row = o.row("_selftest-T-01").unwrap_or_default();
    assert!(
        !row.starts_with("PASS _selftest-T-01 T ")
            && row.starts_with("PASS _selftest-T-01 R ")
            && row.contains(" contrib=retyped(contribution carries B)"),
        "{}",
        o.text()
    );
}

/// A7b and A11b (§3.3 step 7): a stock T is explained in every period up
/// to its own. A planted copy reads the bridge T on 1100 (an Asset) at
/// 2026Q2: the runner explains 1100 certified in 2026Q1 and then 2026Q2,
/// and the union of both still holds and re-adds to B, since nothing posts
/// to 1100 in Q2.
#[test]
fn stock_t_is_explained_in_every_period_up_to_its_own() {
    let o = match run_planted(
        SELFTEST,
        &[PlantedEdit {
            file: "expectations.toml",
            old: "read_coordinate = \"2026Q1\"\nread_selector = \"currently_stated\"\npublished = \"B-1\"",
            new: "read_coordinate = \"2026Q2\"\nread_selector = \"currently_stated\"\npublished = \"B-1\"",
        }],
        HARNESS_VERBS,
    ) {
        Ok(o) => o,
        Err(o) => *o,
    };
    let text = o.text();
    let periods: Vec<String> = o
        .steps
        .iter()
        .filter(|s| {
            s.reference == "_selftest-T-01/-" && words(&s.argv_redacted) == "explain balance"
        })
        .map(|s| {
            let at = s.argv_redacted.iter().position(|a| a == "--period");
            let code = at.and_then(|i| s.argv_redacted.get(i + 1));
            assert!(s.argv_redacted.iter().any(|a| a == "--certify"), "{text}");
            format!("{} exit={}", code.map_or("-", String::as_str), s.exit)
        })
        .collect();
    assert_eq!(
        periods,
        ["FY2026-P01 exit=0", "FY2026-P02 exit=0"],
        "{text}"
    );
    assert_eq!(
        o.row("_selftest-T-01"),
        Some(
            "PASS _selftest-T-01 T native -/default kind=bridge read=balance,1100,2026Q2,as-currently-stated value=900.00 gql=ok contrib=holds outsider=report:verified append_only=ok"
        ),
        "{text}"
    );
}

/// A11b: an extra posting on 1100 in the T's quarter (P-1 moved onto it,
/// and B raised by its 75.00 so the read still equals B) is a contribution
/// the predicate does not name: the row is re-typed R, which fails the case
/// that claims the T (A12).
#[test]
fn _selftest_neg_unnamed_contribution_never_passes_as_t() {
    let o = run_planted(
        SELFTEST,
        &[
            PlantedEdit {
                file: "books/native.toml",
                old: "intent = \"P-1\"\nordinal = 0\naccount = \"6000\"",
                new: "intent = \"P-1\"\nordinal = 0\naccount = \"1100\"",
            },
            PlantedEdit {
                file: "facts.toml",
                old: "fact = \"B-1\"\nordinal = 1\nliteral = \"900\"\nrule = \"scale\"\nparam = 0\nvalue = \"90000\"",
                new: "fact = \"B-1\"\nordinal = 1\nliteral = \"975\"\nrule = \"scale\"\nparam = 0\nvalue = \"97500\"",
            },
        ],
        HARNESS_VERBS,
    )
    .expect_err("a claimed T re-typed R fails the case");
    let row = o.row("_selftest-T-01").unwrap_or_default();
    assert!(
        row.starts_with("PASS _selftest-T-01 R ")
            && row.contains(" value=975.00 ")
            && row.contains(" contrib=retyped(extra contribution P-1)"),
        "{}",
        o.text()
    );
}

/// A12 (§12.1): a published B one minor unit above the book's 900.00 fails
/// the T twice over: its certified read differs, and so does fa-verify's
/// offline recomputation of the bundled certificate, which the row prints
/// as `outsider=report:failed`.
#[test]
fn _selftest_neg_report_recomputation_differing_from_b_fails() {
    let o = run_planted(
        SELFTEST,
        &[PlantedEdit {
            file: "facts.toml",
            old: "fact = \"B-1\"\nordinal = 1\nliteral = \"900\"\nrule = \"scale\"\nparam = 0\nvalue = \"90000\"",
            new: "fact = \"B-1\"\nordinal = 1\nliteral = \"900.01\"\nrule = \"scale\"\nparam = 0\nvalue = \"90001\"",
        }],
        HARNESS_VERBS,
    )
    .expect_err("a T whose recomputation differs from B fails the case");
    let row = o.row("_selftest-T-01").unwrap_or_default();
    assert!(
        row.starts_with(
            "FAIL _selftest-T-01 T native -/default kind=bridge read=balance,1100,2026Q1,as-currently-stated value=900.00 gql=ok outsider=report:failed append_only=ok reason="
        ) && row.contains("outsider report: expected the recomputed 900.01 observed 900.00"),
        "{}",
        o.text()
    );
}

/// A11b: an as-originally-reported read on a line no delta moves does not
/// exercise its selector. In a planted copy of the self-test the delta's
/// 1100 leg moves to 1000, so 1100 reads 1,000.00 both as originally
/// reported and as currently stated. R-01 still passes, flagged
/// `selector=not_exercised`. In the self-test itself the delta moves 1100
/// to 900.00, and R-01 carries no flag.
#[test]
fn as_originally_reported_on_a_zero_delta_line_is_flagged_selector_not_exercised() {
    const R_01: &str = "PASS _selftest-R-01 R native -/default kind=read_back read=balance,1100,2026Q1,as-originally-reported value=1000.00";
    let o = match run_planted(
        SELFTEST,
        &[PlantedEdit {
            file: "books/native.toml",
            old: "intent = \"delta-A-1\"\nordinal = 1\naccount = \"1100\"",
            new: "intent = \"delta-A-1\"\nordinal = 1\naccount = \"1000\"",
        }],
        HARNESS_VERBS,
    ) {
        Ok(o) => o,
        Err(o) => *o,
    };
    assert_eq!(
        o.row("_selftest-R-01"),
        Some(format!("{R_01} selector=not_exercised gql=ok").as_str()),
        "{}",
        o.text()
    );
    let base = outcome(SELFTEST);
    assert_eq!(
        base.row("_selftest-R-01"),
        Some(format!("{R_01} gql=ok").as_str()),
        "{}",
        base.text()
    );
}

/// The self-test's claimed rows, which the outsider negatives keep PASS.
const SELFTEST_CLAIMS: [&str; 5] = [
    "_selftest-P-02",
    "_selftest-P-03",
    "_selftest-T-01",
    "_selftest-R-01",
    "_selftest-CASE-selftest-restatement",
];

/// A8a (§12.1): one flipped byte in the produced bundle makes the
/// in-process `fa_verify::verify_bundle` refuse it, and the case fails even
/// though every claimed row still reads PASS.
#[test]
fn bundle_byte_flip_fails_the_case_whatever_its_expectations_say() {
    outsider::FLIP_BUNDLE_BYTE.with(|f| f.set(true));
    let o = run_case(&selftest_files(), HARNESS_VERBS);
    outsider::FLIP_BUNDLE_BYTE.with(|f| f.set(false));
    let text = o.text();
    for id in SELFTEST_CLAIMS {
        assert!(
            o.row(id).is_some_and(|r| r.starts_with("PASS ")),
            "{id}\n{text}"
        );
    }
    let line = o
        .lines
        .iter()
        .find(|l| l.starts_with("OUTSIDER native "))
        .expect("the outsider line");
    assert!(
        line.starts_with(
            "OUTSIDER native checkpoint=created witness=cosigned checkpoint=created bundle=fail(the report bundle did not verify"
        ) && line.ends_with(" replay=identical verify_book=green append_only=ok:inclusion=1:rollback=FA-REF-124:foreign=FA-REF-100"),
        "{text}"
    );
    assert!(!o.rows_ok && !o.ok, "{text}");
}

/// A8a (§12.7): `fa verify book` exiting 8 fails the case, whatever its
/// rows say. The binary offers no way to corrupt a book from the CLI, so
/// the exit is injected into the runner's observation of the call.
#[test]
fn verify_book_exit_8_fails_the_case() {
    outsider::FORCE_VERIFY_BOOK_EXIT.with(|f| f.set(Some(8)));
    let o = run_case(&selftest_files(), HARNESS_VERBS);
    outsider::FORCE_VERIFY_BOOK_EXIT.with(|f| f.set(None));
    let text = o.text();
    for id in SELFTEST_CLAIMS {
        assert!(
            o.row(id).is_some_and(|r| r.starts_with("PASS ")),
            "{id}\n{text}"
        );
    }
    assert!(
        o.lines.iter().any(|l| l
            == "OUTSIDER native checkpoint=created witness=cosigned checkpoint=created bundle=verified replay=identical verify_book=fail(expected fa verify book exit=0 green observed exit=8 green=true) append_only=ok:inclusion=1:rollback=FA-REF-124:foreign=FA-REF-100"),
        "{text}"
    );
    assert!(!o.rows_ok && !o.ok, "{text}");
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
    // A budget line (`FAIL budget ...`, on a contended worker) is the
    // case's wall-clock verdict, not a row: it has no verdict record.
    let rows = o
        .lines
        .iter()
        .filter(|l| {
            ["PASS ", "FAIL ", "UNRUN "]
                .iter()
                .any(|v| l.starts_with(v))
                && !l.starts_with("FAIL budget ")
        })
        .count();
    assert_eq!(verdicts, rows, "{}", o.text());
    assert_eq!(rows, 12, "{}", o.text());
}

/// Every `fa` call the runner makes is a (verb, subcommand) of the table it
/// checks against `verbs.toml` before any book exists, and every
/// run-variant token in a logged argv is a bound placeholder. The
/// `fa-verify` steps run in process (A12): each is a literal `fa-verify
/// report|checkpoint|consistency|inclusion` argv over the runner's work
/// files, never the book directory.
#[test]
fn every_logged_verb_is_in_the_harness_verb_table() {
    let o = outcome(SELFTEST);
    assert!(!o.steps.is_empty());
    let book = o.books["native"].to_str().unwrap_or("-");
    let verified: Vec<&Vec<String>> = o
        .steps
        .iter()
        .filter(|s| s.verb == "fa-verify")
        .map(|s| &s.argv_redacted)
        .collect();
    assert!(!verified.is_empty(), "{}", o.text());
    for argv in verified {
        assert!(
            argv.first().is_some_and(|c| {
                ["report", "checkpoint", "consistency", "inclusion"].contains(&c.as_str())
            }),
            "{argv:?}"
        );
        assert!(argv.iter().all(|a| !a.contains(book)), "{argv:?}");
    }
    for s in o.steps.iter().filter(|s| s.verb != "fa-verify") {
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
            "findings_recorded.certificate of step 5 (jet.round_amounts)".to_string()
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

/// A `finding_record` step before the book's case opens reads at the head
/// at that step. The self-test's last write before it is S-1's post (N-1
/// posts first, S-2 is refused, `entry show` is a read), so the run's source
/// coordinate is S-1's recorded sequence, and the runner passed exactly it.
#[test]
fn finding_record_before_the_case_reads_the_head_at_its_step() {
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
            old: "intent = \"S-2\"\nrefusal = \"FA-REF-010\"",
            new: "intent = \"S-2\"\nrefusal = \"FA-REF-011\"",
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
            "FAIL _selftest-D-01 D native S-1/default procedure=jet.round_amounts@1 entry=S-1 cite=S-1#0,S-1#1 severity=Medium statistic_name=round_legs statistic=2 scale=0 ref=agree outsider=replay:verified reason=expected cite=S-1#0,S-2#1 observed cite=S-1#0,S-1#1"
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
            "FAIL _selftest-P-02 P native P-1/default reason=expected K-PROV=PASS observed K-PROV=FAIL",
            "FAIL _selftest-P-03 P native P-1/default reason=expected K-PROV=PASS observed K-PROV=FAIL",
            "FAIL _selftest-N-01 N native -/default reason=expected K-PROV=PASS observed K-PROV=FAIL",
            "FAIL _selftest-T-01 T native -/default reason=expected K-PROV=PASS observed K-PROV=FAIL",
            "FAIL _selftest-R-01 R native -/default reason=expected K-PROV=PASS observed K-PROV=FAIL",
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
/// per_account T with its assert_balance step, a quarter issued twice, and
/// read-backs through each selector.
const CONSOLIDATION: [(&str, &str); 6] = [
    (
        "case.toml",
        include_str!("../../fa-oracles/tests/fixtures/consolidation_min/case.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../fa-oracles/tests/fixtures/consolidation_min/roles.toml"),
    ),
    (
        "sources.toml",
        include_str!("../../fa-oracles/tests/fixtures/consolidation_min/sources.toml"),
    ),
    (
        "facts.toml",
        include_str!("../../fa-oracles/tests/fixtures/consolidation_min/facts.toml"),
    ),
    (
        "books/native.toml",
        include_str!("../../fa-oracles/tests/fixtures/consolidation_min/books/native.toml"),
    ),
    (
        "expectations.toml",
        include_str!("../../fa-oracles/tests/fixtures/consolidation_min/expectations.toml"),
    ),
];

/// A7b and A12 (§12.1, the replay route): a two-entity micro-book, the
/// parent owning all of its subsidiary, read through `fa consolidate
/// --period 2026Q1 --certify`. The consolidated balance sheet's assets line
/// is 5,000.00 (the investment eliminated against the subsidiary's capital),
/// and the consolidation certificate replays byte for byte (`fa replay`), its
/// output hashing to the digest it recorded: `outsider=replay:verified`, a
/// replay in the book (fa-verify has no consolidation recomputation). A
/// consolidated line has no contributing-entry witness yet, so the T waits
/// on it.
#[test]
fn consolidation_certificate_replays_byte_identically() {
    let o = match run_files("consolidation_min", &CONSOLIDATION, &[], HARNESS_VERBS) {
        Ok(o) => o,
        Err(o) => *o,
    };
    let text = o.text();
    assert_eq!(
        o.row("consolidation_min-T-01"),
        Some(
            "UNRUN consolidation_min-T-01 T native -/default kind=footing read=consolidate,assets,2026Q1 value=5000.00 contrib=unrun(needs:A11b consolidate lines) outsider=replay:verified reason=contributing_entry"
        ),
        "{text}"
    );
    let route: Vec<String> = o
        .steps
        .iter()
        .filter(|s| s.reference == "consolidation_min-T-01/-")
        .map(|s| format!("{} exit={}", words(&s.argv_redacted), s.exit))
        .collect();
    assert_eq!(route.len(), 2, "{text}");
    assert!(
        route[0].starts_with("consolidate --period exit=0"),
        "{text}"
    );
    assert!(
        route[1].starts_with("replay C:") && route[1].ends_with(" exit=0"),
        "{text}"
    );
    assert!(
        o.lines
            .iter()
            .any(|l| l == "OUTSIDER native verify_book=green"),
        "{text}"
    );
}

const READS: [(&str, &str); 6] = [
    (
        "case.toml",
        include_str!("../../fa-oracles/tests/fixtures/reads/case.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../fa-oracles/tests/fixtures/reads/roles.toml"),
    ),
    (
        "sources.toml",
        include_str!("../../fa-oracles/tests/fixtures/reads/sources.toml"),
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

/// The reads fixture's unedited run, shared by its tests.
fn reads() -> &'static RunOutcome {
    static RUN: std::sync::OnceLock<RunOutcome> = std::sync::OnceLock::new();
    RUN.get_or_init(|| *reads_run(&[]))
}

/// A7b (§5.3, §3.3 step 7): the per_account T reads its cell certified,
/// equal to its published 1,250.00; its assert_balance step recorded B and
/// both twins (B plus and minus one minor unit) were refused FA-REF-140; the
/// T passes with its contributing-entry witness (A11b) and outsider check
/// (A12). As originally reported reads the quarter's first issuance
/// (1,000.00, before R-2), and as currently stated the head.
#[test]
fn per_account_t_and_its_read_back_are_read_certified() {
    let o = reads();
    let text = o.text();
    assert_eq!(
        o.row("reads-T-01"),
        Some(
            "PASS reads-T-01 T native -/default kind=per_account read=balance,1100,2026Q1 value=1250.00 gql=ok assert=recorded twin=refused:FA-REF-140:exit=3 contrib=holds outsider=report:verified"
        ),
        "{text}"
    );
    assert_eq!(
        o.row("reads-R-01"),
        Some(
            "PASS reads-R-01 R native -/default kind=read_back read=balance,1100,2026Q1,as-originally-reported value=1000.00 gql=ok"
        ),
        "{text}"
    );
    assert_eq!(
        o.row("reads-R-04"),
        Some(
            "PASS reads-R-04 R native -/default kind=read_back read=balance,1100,2026Q1,as-currently-stated value=1250.00 gql=ok"
        ),
        "{text}"
    );
    assert!(o.rows_ok, "{text}");
}

/// A7b (§5.3): an assertion at the fold is recorded as a RegisterEquals
/// attestation that holds. The per_account T's `assert=recorded` token
/// requires all three (admitted, claim RegisterEquals, holds = true), and
/// its two twins at B plus and minus one minor unit are the only refused
/// assert-balance calls.
#[test]
fn assert_balance_at_the_fold_records_register_equals() {
    let o = reads();
    let text = o.text();
    let row = o.row("reads-T-01").unwrap_or_default();
    assert!(
        row.contains(" assert=recorded twin=refused:FA-REF-140:exit=3 "),
        "{text}"
    );
    let asserts: Vec<_> = o
        .steps
        .iter()
        .filter(|s| words(&s.argv_redacted).starts_with("assert-balance "))
        .map(|s| (s.exit, s.refusal_id.as_deref().unwrap_or("-")))
        .collect();
    assert_eq!(
        asserts,
        [(0, "-"), (3, "FA-REF-140"), (3, "FA-REF-140")],
        "{text}"
    );
}

/// A12 (§12.7, step 5): book integrity runs on every book variant, not only
/// on books with a checkpoint step. The reads fixture has none: its book's
/// registers are advanced and `fa verify book` reports it green, and only
/// that check runs.
#[test]
fn verify_book_runs_on_every_book_variant() {
    let o = reads();
    let text = o.text();
    let outsider: Vec<&String> = o
        .lines
        .iter()
        .filter(|l| l.starts_with("OUTSIDER native "))
        .collect();
    assert!(!outsider.is_empty(), "{text}");
    for line in outsider {
        assert_eq!(line, "OUTSIDER native verify_book=green", "{text}");
    }
    assert!(
        o.steps
            .iter()
            .any(|s| words(&s.argv_redacted) == "verify book" && s.exit == 0),
        "{text}"
    );
}

/// A11b (§3.7 item 2): a statement line T read at the head is also traced
/// publication by publication over the history (`fa statement trace
/// --certify`), and the trace agrees with the line's explained balances, so
/// the witness holds on contributions both certified reads attribute.
#[test]
fn statement_line_t_is_traced_and_agrees_with_its_explained_balances() {
    let o = reads();
    let text = o.text();
    let traced: Vec<_> = o
        .steps
        .iter()
        .filter(|s| words(&s.argv_redacted) == "statement trace")
        .map(|s| {
            assert!(s.argv_redacted.iter().any(|a| a == "--certify"), "{text}");
            (s.reference.as_str(), s.exit, s.certificate_kind.as_deref())
        })
        .collect();
    assert_eq!(
        traced,
        [
            ("reads-T-02/-", 0, Some("StatementTrace")),
            ("reads-T-03/-", 0, Some("StatementTrace"))
        ],
        "{text}"
    );
    for id in ["reads-T-02", "reads-T-03"] {
        assert!(
            o.row(id)
                .is_some_and(|r| r.ends_with(" contrib=holds outsider=report:verified")),
            "{id}\n{text}"
        );
    }
}

/// A11b (§3.7 item 2): a trace that disagrees with a line's explained
/// balances re-types the T as R, `contrib=disagree(trace,explained)`, with
/// the first difference a verdict witness and the trace's argv printed to
/// reproduce. The binary's two reads agree, so the runner drops the last
/// publication that moves each line.
#[test]
fn statement_line_trace_disagreeing_with_its_explained_balances_retypes_r() {
    reads::DROP_LAST_PUBLICATION.with(|f| f.set(true));
    let o = reads_run(&[]);
    reads::DROP_LAST_PUBLICATION.with(|f| f.set(false));
    let text = o.text();
    for (id, read) in [
        ("reads-T-02", "balance-sheet,assets"),
        ("reads-T-03", "income-statement,revenue"),
    ] {
        assert_eq!(
            o.row(id),
            Some(
                format!(
                    "PASS {id} R native -/default kind=footing read={read},2026Q1 value=1250.00 contrib=disagree(trace,explained) outsider=report:verified"
                )
                .as_str()
            ),
            "{text}"
        );
        let record = o
            .verdicts
            .iter()
            .find(|v| v.expectation == id)
            .expect("the verdict record");
        let detail = record
            .witnesses
            .iter()
            .find(|(k, _)| k == "disagreement")
            .map_or("", |(_, v)| v.as_str());
        assert!(
            detail.starts_with("explained entry ") && detail.ends_with(" is in no publication"),
            "{detail}\n{text}"
        );
    }
    let reproduced = o
        .lines
        .iter()
        .filter(|l| l.starts_with("REPRODUCE fa ") && l.contains(" statement trace "))
        .count();
    assert_eq!(reproduced, 2, "{text}");
}

/// A7b (§3.3 step 4): each `issue` step certifies the balance sheet, plans
/// its issuance, has another hand approve it and commits it. The quarter's
/// first issuance binds `$C_ISSUE_2026Q1` and its second
/// `$C_ISSUE_2026Q1_2`, and `reported_in:2026Q1#<n>` reads as reported in
/// the n-th: 1,000.00, then 1,250.00.
#[test]
fn second_issuance_of_a_period_binds_its_own_placeholder() {
    let o = reads();
    let text = o.text();
    assert_eq!(
        o.row("reads-R-02"),
        Some(
            "PASS reads-R-02 R native -/default kind=read_back read=balance,1100,2026Q1,as-reported-in=$C_ISSUE_2026Q1 value=1000.00 gql=ok"
        ),
        "{text}"
    );
    assert_eq!(
        o.row("reads-R-03"),
        Some(
            "PASS reads-R-03 R native -/default kind=read_back read=balance,1100,2026Q1,as-reported-in=$C_ISSUE_2026Q1_2 value=1250.00 gql=ok"
        ),
        "{text}"
    );
    for (seq, placeholder) in [(3, "$C_ISSUE_2026Q1"), (6, "$C_ISSUE_2026Q1_2")] {
        let steps: Vec<_> = o
            .steps
            .iter()
            .filter(|s| s.step == seq && (s.verb == "statement" || s.verb == "approve"))
            .collect();
        let verbs: Vec<String> = steps
            .iter()
            .map(|s| {
                format!(
                    "{} exit={} cert={}",
                    // After `--book $BOOK`.
                    s.argv_redacted.get(2..4).unwrap_or_default().join(" "),
                    s.exit,
                    s.certificate_kind.as_deref().unwrap_or("-")
                )
            })
            .collect();
        assert_eq!(
            verbs,
            [
                "statement balance-sheet exit=0 cert=BalanceSheet",
                "statement issue exit=0 cert=-",
                "approve --proposal exit=0 cert=-",
                "statement issue exit=0 cert=StatementIssuance",
            ],
            "{text}"
        );
        let planned = steps.get(1).expect("the plan");
        assert!(
            planned.argv_redacted.contains(&format!("C:{placeholder}"))
                && planned.binds.iter().any(|(p, _)| p == placeholder),
            "{:?}",
            planned.argv_redacted
        );
    }
}

/// A7b (§3.3 step 7): the same quarter read off the certified statements
/// and trial balance: the balance sheet's assets line as currently stated
/// (1,250.00), the income statement's revenue line as originally reported
/// (1,000.00, the first issuance's) and the trial balance's 1100 row
/// (1,250.00).
#[test]
fn statement_and_trial_balance_reads_return_their_lines() {
    let o = reads();
    let text = o.text();
    for (id, row) in [
        (
            "reads-R-05",
            "PASS reads-R-05 R native -/default kind=read_back read=balance-sheet,assets,2026Q1,as-currently-stated value=1250.00",
        ),
        (
            "reads-R-06",
            "PASS reads-R-06 R native -/default kind=read_back read=income-statement,revenue,2026Q1,as-originally-reported value=1000.00",
        ),
        (
            "reads-R-07",
            "PASS reads-R-07 R native -/default kind=read_back read=tb,1100,2026Q1 value=1250.00",
        ),
    ] {
        assert_eq!(o.row(id), Some(row), "{text}");
    }
}

/// A11b: a statement line's contributions are every account its registered
/// definition maps to it, explained over the definition's basis and signed
/// as the line signs them: the assets line folds R-1's and R-2's debits on
/// 1100, the revenue line their credits on 4000 (credit-signed), and both
/// hold to the published 1,250.00.
#[test]
fn statement_line_t_holds_on_the_accounts_its_definition_maps() {
    let o = reads();
    let text = o.text();
    for row in [
        "PASS reads-T-02 T native -/default kind=footing read=balance-sheet,assets,2026Q1 value=1250.00 contrib=holds outsider=report:verified",
        "PASS reads-T-03 T native -/default kind=footing read=income-statement,revenue,2026Q1 value=1250.00 contrib=holds outsider=report:verified",
    ] {
        assert!(o.lines.iter().any(|l| l == row), "{row}\n{text}");
    }
}

/// A7b: a statement read names a line the definition has not: no read, so
/// the row fails naming the line, never reading zero.
#[test]
fn statement_read_of_an_unknown_line_fails() {
    let o = reads_run(&[PlantedEdit {
        file: "expectations.toml",
        old: "read_target = \"assets\"\nread_coordinate = \"2026Q1\"\nread_selector",
        new: "read_target = \"assetz\"\nread_coordinate = \"2026Q1\"\nread_selector",
    }]);
    let text = o.text();
    assert!(
        o.row("reads-R-05")
            .is_some_and(|r| r.starts_with("FAIL reads-R-05 ")
                && r.contains("reason=expected a balance-sheet line assetz in USD observed none")),
        "{text}"
    );
}

/// A7b: a published value the book does not reach fails the T row, naming
/// both values, and the kernel refuses its assertion FA-REF-140; the
/// read-backs of the same value fail too.
#[test]
fn t_whose_read_differs_from_its_published_value_fails() {
    let o = reads_run(&[PlantedEdit {
        file: "facts.toml",
        old: "fact = \"P-1\"\nordinal = 1\nliteral = \"1,250\"\nrule = \"scale\"\nparam = 0\nvalue = \"125000\"",
        new: "fact = \"P-1\"\nordinal = 1\nliteral = \"999\"\nrule = \"scale\"\nparam = 0\nvalue = \"99900\"",
    }]);
    let text = o.text();
    let row = o.row("reads-T-01").expect("the T row");
    assert!(
        row.starts_with("FAIL reads-T-01 T native -/default kind=per_account read=balance,1100,2026Q1 value=1250.00 gql=ok assert=refused twin=refused:FA-REF-140:exit=3 ")
            && row.contains("reason=expected value=999.00 observed value=1250.00; expected assert-balance 999.00 USD recorded observed exit=3 FA-REF-140"),
        "{text}"
    );
    for id in ["reads-R-03", "reads-R-04"] {
        assert!(
            o.row(id)
                .is_some_and(|r| r.starts_with(&format!("FAIL {id} "))
                    && r.contains("expected value=999.00 observed value=1250.00")),
            "{text}"
        );
    }
    assert!(!o.rows_ok, "{text}");
}

/// A7b (§3.3 step 4, §7.4): a period never issued nor locked has no
/// original report. With the history's `issue` and `period_lock` steps
/// removed (and the reported_in reads turned into originally-reported
/// ones), `explain balance --as-originally-reported` is refused FA-REF-161
/// and each such read-back fails naming it; as currently stated still reads
/// the head.
#[test]
fn as_originally_reported_without_issuance_or_lock_is_refused_fa_ref_161() {
    let edits = [
        PlantedEdit {
            file: "books/native.toml",
            old: "[[step]]\nseq = 3\nkind = \"issue\"\nref = \"2026Q1\"\nprincipal = \"case-closer-1\"\napprovers = [\"case-second-reader\"]\ndocument = \"DOC-RD-1\"\n\n",
            new: "",
        },
        PlantedEdit {
            file: "books/native.toml",
            old: "[[step]]\nseq = 6\nkind = \"issue\"\nref = \"2026Q1\"\nprincipal = \"case-closer-1\"\napprovers = [\"case-second-reader\"]\ndocument = \"DOC-RD-1\"\n\n",
            new: "",
        },
        PlantedEdit {
            file: "books/native.toml",
            old: "[[step]]\nseq = 8\nkind = \"period_lock\"\nref = \"2026Q1\"\nprincipal = \"case-closer-1\"\napprovers = [\"case-second-reader\"]\n\n",
            new: "",
        },
        PlantedEdit {
            file: "expectations.toml",
            old: "read_selector = \"reported_in:2026Q1\"\n",
            new: "read_selector = \"originally_reported\"\n",
        },
        PlantedEdit {
            file: "expectations.toml",
            old: "read_selector = \"reported_in:2026Q1#2\"\n",
            new: "read_selector = \"originally_reported\"\n",
        },
    ];
    let o = reads_run(&edits);
    let text = o.text();
    for id in ["reads-R-01", "reads-R-02", "reads-R-03"] {
        assert_eq!(
            o.row(id),
            Some(
                format!(
                    "FAIL {id} R native -/default kind=read_back read=balance,1100,2026Q1,as-originally-reported reason=expected exit=0 from explain balance of 2026Q1 observed exit=3 FA-REF-161"
                )
                .as_str()
            ),
            "{text}"
        );
    }
    assert_eq!(
        o.row("reads-R-04"),
        Some(
            "PASS reads-R-04 R native -/default kind=read_back read=balance,1100,2026Q1,as-currently-stated value=1250.00 gql=ok"
        ),
        "{text}"
    );
    assert_eq!(
        o.row("reads-R-06"),
        Some(
            "FAIL reads-R-06 R native -/default kind=read_back read=income-statement,revenue,2026Q1,as-originally-reported reason=expected exit=0 from statement income-statement observed exit=3 FA-REF-161"
        ),
        "{text}"
    );
    assert!(!o.rows_ok, "{text}");
}

/// The lifecycle fixture (`crates/fa-oracles/tests/fixtures/lifecycle_min/`,
/// A7b): an issued and locked quarter restated by a full case.
const LIFECYCLE: [(&str, &str); 6] = [
    (
        "case.toml",
        include_str!("../../fa-oracles/tests/fixtures/lifecycle_min/case.toml"),
    ),
    (
        "roles.toml",
        include_str!("../../fa-oracles/tests/fixtures/lifecycle_min/roles.toml"),
    ),
    (
        "sources.toml",
        include_str!("../../fa-oracles/tests/fixtures/lifecycle_min/sources.toml"),
    ),
    (
        "facts.toml",
        include_str!("../../fa-oracles/tests/fixtures/lifecycle_min/facts.toml"),
    ),
    (
        "books/native.toml",
        include_str!("../../fa-oracles/tests/fixtures/lifecycle_min/books/native.toml"),
    ),
    (
        "expectations.toml",
        include_str!("../../fa-oracles/tests/fixtures/lifecycle_min/expectations.toml"),
    ),
];

fn lifecycle_run(edits: &[PlantedEdit]) -> Box<RunOutcome> {
    match run_files("lifecycle", &LIFECYCLE, edits, HARNESS_VERBS) {
        Ok(o) => Box::new(o),
        Err(o) => o,
    }
}

/// The lifecycle fixture's unedited run, shared by its tests.
fn lifecycle() -> &'static RunOutcome {
    static RUN: std::sync::OnceLock<RunOutcome> = std::sync::OnceLock::new();
    RUN.get_or_init(|| *lifecycle_run(&[]))
}

/// The logged calls of `o` that exited non-zero, as the two argv words
/// after `--book $BOOK` and the refusal id.
fn refused_calls(o: &RunOutcome) -> Vec<String> {
    o.steps
        .iter()
        .filter(|s| s.exit != 0)
        .map(|s| {
            format!(
                "{} {}",
                words(&s.argv_redacted),
                s.refusal_id.as_deref().unwrap_or("-")
            )
        })
        .collect()
}

/// The fixture's `case_disclose` step, which a planted edit removes.
const DISCLOSE_STEP: &str =
    "[[step]]\nseq = 17\nkind = \"case_disclose\"\nref = \"rc\"\nprincipal = \"case-poster-1\"\n\n";

/// A7b (§3.3 steps 4 and 5): the quarter is issued and locked, then case rc
/// runs its whole life cycle: open (determined on the restating filing's
/// date, the declared default), scenario fork/run/diff, rehearse, two
/// approvals, post by a non-approver, statement diff, disclose and close.
/// The case's number is logged once, every case and scenario call
/// succeeds but its three twins (one approval, FA-REF-012; the delta
/// posted outside the case, FA-REF-178; the unreviewed disclosure,
/// FA-REF-179), and the generated row reads the case Closed with its kind,
/// day, authority and reviewed disclosure (the target's lineage names
/// Restates). The quarter reads 1,000.00 as originally reported and as
/// reported in its issuance, and 1,200.00 as currently stated.
#[test]
fn issue_lock_and_full_restatement_lifecycle_run() {
    let o = lifecycle();
    let text = o.text();
    let cases: Vec<&String> = o.lines.iter().filter(|l| l.starts_with("CASES ")).collect();
    assert_eq!(cases, ["CASES native rc=1"], "{text}");
    assert_eq!(
        o.row("lifecycle-CASE-rc"),
        Some(
            "PASS lifecycle-CASE-rc R native -/default kind=case_show read=case show,rc state=Closed case_kind=Restatement determined_on=2026-05-15 authority=DOC-LC-1 disclosure=reviewed twin=refused:FA-REF-179:exit=3 one_approval=refused:FA-REF-012:exit=7:Rehearsed outside_case=refused:FA-REF-178:exit=3 superseded=2026Q1:SupersededBy:later_entries=1"
        ),
        "{text}"
    );
    // The as-filed assertion's two twins (A +/- 1 minor unit), the case's
    // three twins and the restated assertion's two twins (B +/- 1) are the
    // only refused calls.
    assert_eq!(
        refused_calls(o),
        [
            "assert-balance --account FA-REF-140",
            "assert-balance --account FA-REF-140",
            "case approve FA-REF-012",
            "post --intent FA-REF-178",
            "case disclose FA-REF-179",
            "assert-balance --account FA-REF-140",
            "assert-balance --account FA-REF-140"
        ],
        "{text}"
    );
    for (id, row) in [
        (
            "lifecycle-R-01",
            "PASS lifecycle-R-01 R native -/default kind=read_back read=balance,6100,2026Q1,as-originally-reported value=1000.00 gql=ok",
        ),
        (
            "lifecycle-R-02",
            "PASS lifecycle-R-02 R native -/default kind=read_back read=balance,6100,2026Q1,as-reported-in=$C_ISSUE_2026Q1 value=1000.00 gql=ok",
        ),
        (
            "lifecycle-R-03",
            "PASS lifecycle-R-03 R native -/default kind=read_back read=balance,6100,2026Q1,as-currently-stated value=1200.00 gql=ok",
        ),
    ] {
        assert_eq!(o.row(id), Some(row), "{text}");
    }
    assert!(o.rows_ok, "{text}");
}

/// A7b (§5.3): A is asserted as filed (1,000.00 on 6100) before the case;
/// after the case restates A, `recon.assertion_drift` reports exactly that
/// attestation, Critical, citing the attestation, the account, the quarter
/// and the delta recorded after it, with the drift's magnitude |sum of
/// deltas|. The sign is the fold's, never the statistic's: restated up by
/// 200.00 the quarter reads 1,200.00 and the drift 200.00; restated down by
/// 100.00 (a planted copy: the delta's legs reversed, D-1 = 100 and P-1 =
/// 900) it reads 900.00, below A, and the drift is 100.00, still positive.
#[test]
fn assertion_drift_reports_the_magnitude_of_the_summed_deltas() {
    let drift = |o: &RunOutcome, statistic: &str| {
        let row = o.row("lifecycle-D-01").unwrap_or_default();
        !row.starts_with("FAIL ")
            && row.contains(" procedure=recon.assertion_drift@1 ")
            && row.contains(" entry=delta-A-1 ")
            && row.contains(" cite=6100,attestation:lifecycle-R-01,period:2026Q1 ")
            && row.contains(" severity=Critical ")
            && row.contains(&format!(
                " statistic_name=assertion_drift statistic={statistic} scale=2 "
            ))
    };
    let up = lifecycle();
    assert!(drift(up, "20000"), "{}", up.text());
    let edit = |file, old, new| PlantedEdit { file, old, new };
    let down = lifecycle_run(&[
        edit(
            "facts.toml",
            "literal = \"200\"\nrule = \"scale\"\nparam = 0\nvalue = \"20000\"",
            "literal = \"100\"\nrule = \"scale\"\nparam = 0\nvalue = \"10000\"",
        ),
        edit(
            "facts.toml",
            "literal = \"1,200\"\nrule = \"scale\"\nparam = 0\nvalue = \"120000\"",
            "literal = \"900\"\nrule = \"scale\"\nparam = 0\nvalue = \"90000\"",
        ),
        edit(
            "books/native.toml",
            "account = \"6100\"\nside = \"Dr\"\namount_literal = \"200.00\"",
            "account = \"6100\"\nside = \"Cr\"\namount_literal = \"100.00\"",
        ),
        edit(
            "books/native.toml",
            "account = \"1000\"\nside = \"Cr\"\namount_literal = \"200.00\"",
            "account = \"1000\"\nside = \"Dr\"\namount_literal = \"100.00\"",
        ),
        edit(
            "expectations.toml",
            "statistic_value = \"20000\"",
            "statistic_value = \"10000\"",
        ),
    ]);
    let text = down.text();
    assert!(drift(&down, "10000"), "{text}");
    for (id, value) in [("lifecycle-R-01", "1000.00"), ("lifecycle-R-03", "900.00")] {
        assert!(
            down.row(id).is_some_and(
                |r| r.starts_with("PASS ") && r.ends_with(&format!(" value={value} gql=ok"))
            ),
            "{id}: {text}"
        );
    }
    assert!(down.rows_ok, "{text}");
}

/// A7b (§5.3): each assert_balance step asserts its fact and cites its own
/// filing stub. Step 6 names its fact (`asserts = "A-1"`): A as filed,
/// 1,000.00, citing the as-filed stub before the case. Step 20 asserts its
/// R's published value by default: B as restated, 1,200.00, citing the
/// restating filing's stub after it. Both are admitted; their twins are the
/// refused calls `issue_lock_and_full_restatement_lifecycle_run` lists.
#[test]
fn assert_balance_step_asserts_its_named_fact_and_cites_its_evidence_stub() {
    let o = lifecycle();
    let text = o.text();
    let after = |argv: &[String], name: &str| {
        argv.iter()
            .position(|a| a == name)
            .and_then(|i| argv.get(i + 1))
            .cloned()
            .unwrap_or_default()
    };
    let asserted: Vec<_> = o
        .steps
        .iter()
        .filter(|s| s.exit == 0 && words(&s.argv_redacted).starts_with("assert-balance "))
        .map(|s| {
            (
                s.step,
                s.reference.as_str(),
                after(&s.argv_redacted, "--balance"),
                after(&s.argv_redacted, "--evidence"),
            )
        })
        .collect();
    let want = |step, reference, balance: &str, evidence: &str| {
        (step, reference, balance.to_string(), evidence.to_string())
    };
    assert_eq!(
        asserted,
        [
            want(6, "lifecycle-R-01", "1000.00 USD", "$DOC_DOC-LC-0"),
            want(20, "lifecycle-R-03", "1200.00 USD", "$DOC_DOC-LC-1"),
        ],
        "{text}"
    );
}

/// A7b (§3.3 step 5): one approval is not dual control. `fa case approve`
/// citing the first approver's approval alone is refused FA-REF-012 (exit
/// 7), `fa case show` then reads the case still Rehearsed, and the same
/// approval with the second approver's is admitted.
#[test]
fn case_with_one_approval_is_refused_fa_ref_012_and_stays_rehearsed() {
    let o = lifecycle();
    let text = o.text();
    let approves: Vec<_> = o
        .steps
        .iter()
        .filter(|s| words(&s.argv_redacted) == "case approve")
        .filter(|s| !s.argv_redacted.iter().any(|a| a == "--dry-run"))
        .map(|s| {
            let n = s
                .argv_redacted
                .iter()
                .filter(|a| *a == "--approval")
                .count();
            (n, s.exit, s.refusal_id.as_deref().unwrap_or("-"))
        })
        .collect();
    assert_eq!(approves, [(1, 7, "FA-REF-012"), (2, 0, "-")], "{text}");
    let row = o.row("lifecycle-CASE-rc").unwrap_or_default();
    assert!(
        row.starts_with("PASS ")
            && row.contains(" one_approval=refused:FA-REF-012:exit=7:Rehearsed "),
        "{text}"
    );
}

/// A7b (§3.3 step 5, FA-REF-178): a case-bound entry posts only through its
/// case. The rehearsed delta's intent file, posted on its own while the
/// case is Approved (confirmed and with restate), is refused FA-REF-178
/// (exit 3) before `fa case post`, and the quarter as currently stated
/// moves by the delta once, not twice.
#[test]
fn restatement_intent_outside_its_case_is_refused_fa_ref_178() {
    let o = lifecycle();
    let text = o.text();
    let posts: Vec<_> = o
        .steps
        .iter()
        .filter(|s| s.argv_redacted.get(2).is_some_and(|w| w == "post"))
        .map(|s| {
            (
                s.reference.as_str(),
                s.exit,
                s.refusal_id.as_deref().unwrap_or("-"),
            )
        })
        .collect();
    assert!(posts.contains(&("delta-A-1", 3, "FA-REF-178")), "{text}");
    let at = |sub: &str| {
        o.steps
            .iter()
            .position(|s| words(&s.argv_redacted) == format!("case {sub}"))
    };
    let outside = o
        .steps
        .iter()
        .position(|s| s.reference == "delta-A-1" && s.refusal_id.as_deref() == Some("FA-REF-178"));
    assert!(outside.is_some() && outside < at("post"), "{text}");
    let row = o.row("lifecycle-CASE-rc").unwrap_or_default();
    assert!(
        row.starts_with("PASS ") && row.contains(" outside_case=refused:FA-REF-178:exit=3 "),
        "{text}"
    );
    assert!(
        o.row("lifecycle-R-03")
            .is_some_and(|r| r.starts_with("PASS ") && r.ends_with(" value=1200.00 gql=ok")),
        "{text}"
    );
}

/// The two argv words after `--book $BOOK`.
fn words(argv: &[String]) -> String {
    argv.get(2..4).unwrap_or_default().join(" ")
}

/// A12 (§12.7): after the case posts, `fa certificate status` of 2026Q1's
/// first issuance (its as-filed statement certificate) reports it
/// SupersededBy exactly the entry the case posted: an independent second
/// half of the contributing-entry witness.
#[test]
fn as_filed_certificate_is_superseded_by_exactly_the_cases_entries() {
    let o = lifecycle();
    let text = o.text();
    let statuses: Vec<(i128, String)> = o
        .steps
        .iter()
        .filter(|s| s.reference == "rc" && words(&s.argv_redacted) == "certificate status")
        .map(|s| (s.exit, s.argv_redacted.get(4).cloned().unwrap_or_default()))
        .collect();
    assert_eq!(statuses, [(0, "C:$C_ISSUE_2026Q1".to_string())], "{text}");
    assert!(
        o.row("lifecycle-CASE-rc")
            .is_some_and(|r| r.ends_with(" superseded=2026Q1:SupersededBy:later_entries=1")),
        "{text}"
    );
}

/// A12 (§12.7): a certificate status whose later entries miss one the case
/// posted fails the case row. The binary reports the entry, so the
/// evaluator drops it from the observation.
#[test]
fn certificate_status_later_entries_missing_a_delta_fails() {
    evaluate::DROP_LATER_ENTRY.with(|f| f.set(true));
    let o = lifecycle_run(&[]);
    evaluate::DROP_LATER_ENTRY.with(|f| f.set(false));
    let row = o.row("lifecycle-CASE-rc").unwrap_or_default();
    assert!(
        row.starts_with("FAIL lifecycle-CASE-rc R ")
            && row.contains(" superseded=2026Q1:SupersededBy:later_entries=0 ")
            && row.contains(
                "expected the as-filed certificate of 2026Q1 SupersededBy the case's 1 posted entries observed SupersededBy with 0 later entries (0 of them posted by the case)"
            ),
        "{}",
        o.text()
    );
}

/// A7b (§3.3 step 5): a history that ends before its `case_close` step
/// (X3's walking skeleton ends at `case_post`) leaves the case's row UNRUN,
/// never PASS.
#[test]
fn case_row_is_unrun_never_pass_without_a_case_close_step() {
    let o = lifecycle_run(&[
        PlantedEdit {
            file: "books/native.toml",
            old: DISCLOSE_STEP,
            new: "",
        },
        PlantedEdit {
            file: "books/native.toml",
            old: "[[step]]\nseq = 18\nkind = \"case_close\"\nref = \"rc\"\nprincipal = \"case-poster-1\"\n\n",
            new: "",
        },
    ]);
    let text = o.text();
    assert_eq!(
        o.row("lifecycle-CASE-rc"),
        Some(
            "UNRUN lifecycle-CASE-rc R native -/default kind=case_show read=case show,rc reason=needs:case_close step"
        ),
        "{text}"
    );
}

/// A7b (§3.3 step 5): without its `case_disclose` step, `fa case close` is
/// refused (it moves only Disclosed to Closed), the case stays Posted, and
/// the generated row fails naming the state it observed.
#[test]
fn case_show_without_disclosure_fails() {
    let o = lifecycle_run(&[PlantedEdit {
        file: "books/native.toml",
        old: DISCLOSE_STEP,
        new: "",
    }]);
    let text = o.text();
    let row = o.row("lifecycle-CASE-rc").expect("the case row");
    assert!(
        row.starts_with(
            "FAIL lifecycle-CASE-rc R native -/default kind=case_show read=case show,rc state=Posted case_kind=Restatement "
        ) && row.contains("reason=expected Closed observed Posted"),
        "{text}"
    );
    assert!(!o.rows_ok, "{text}");
}
