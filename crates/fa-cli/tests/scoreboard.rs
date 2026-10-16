//! Executable Vision & Convergence Gate Scoreboard (`beads fa-e9z, fa-7s6d`).
//!
//! Runs every workflow step (`README.md §Quick example` + plan §15.6) and every
//! convergence gate criterion (plan §19 `G0`, `Genesis`, `G1`–`G4`) declared in
//! `registries/scoreboard.toml` against the real `fa` surface and registry
//! checks, and verifies that:
//!   1. Every step's actual `(exit, event, refusal_id)` matches its declared
//!      expectation (`works` | `refused` | `absent`) in BOTH directions:
//!      - a `works` step that fails is a regression (FAIL);
//!      - an `absent` or `refused` step that now succeeds is unrecorded
//!        progress (FAIL: update `registries/scoreboard.toml` and regenerate
//!        `docs/VISION_AND_GATE_SCOREBOARD.md`).
//!   2. `docs/VISION_AND_GATE_SCOREBOARD.md` equals
//!      `Scoreboard::embedded().render_markdown()` byte-for-byte.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};
use fa_registry::admissibility_plan::PlanAdmissibility;
use fa_registry::invariants::Invariants;
use fa_registry::refusal_catalog::RefusalCatalog;
use fa_registry::scoreboard::{ProbeKind, Scoreboard, StepExpectation};
use fa_registry::threat_model::ThreatModel;
use fa_registry::{Admissibility, EntryClasses, ExitCodes};

const SCOREBOARD_DOC: &str = include_str!("../../../docs/VISION_AND_GATE_SCOREBOARD.md");

fn tmp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("fa-scoreboard-{}-{tag}-{n}", std::process::id()));
        if std::fs::create_dir(&dir).is_ok() {
            return dir;
        }
    }
}

fn write_file(dir: &Path, name: &str, content: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, content.as_bytes()).expect("write fixture file");
    path.display().to_string()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProbeOutcome {
    exit: u8,
    event: String,
    refusal_id: Option<String>,
    raw_stdout: String,
    raw_stderr: String,
}

fn run_cli_probe(argv: &[String]) -> ProbeOutcome {
    let (exit, captured) = fa_cli::entry::fa(argv, true);
    let primary_line = if exit == 0 {
        captured.stdout.lines().next()
    } else {
        captured.stdout.lines().last()
    }
    .unwrap_or("");
    let parsed = json::parse(primary_line).unwrap_or(Json::Null);
    let event = parsed
        .get("event")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_string();
    let refusal_id = parsed
        .get("data")
        .and_then(|d| d.get("refusal_id"))
        .and_then(Json::as_str)
        .map(str::to_string);
    ProbeOutcome {
        exit,
        event,
        refusal_id,
        raw_stdout: captured.stdout,
        raw_stderr: captured.stderr,
    }
}

fn run_registry_probe(probe_name: &str) -> ProbeOutcome {
    match probe_name {
        "invariants_spine" => match Invariants::embedded() {
            Ok(inv) if inv.invariants.len() == 16 && inv.clauses.iter().any(|c| c.is_live()) => {
                ProbeOutcome {
                    exit: 0,
                    event: "registry_ok".into(),
                    refusal_id: None,
                    raw_stdout: String::new(),
                    raw_stderr: String::new(),
                }
            }
            other => ProbeOutcome {
                exit: 2,
                event: "error".into(),
                refusal_id: None,
                raw_stdout: String::new(),
                raw_stderr: format!("{other:?}"),
            },
        },
        "threat_model" => match ThreatModel::embedded() {
            Ok(tm)
                if tm.threats.len() == 8
                    && tm.trust_boundaries.len() == 5
                    && tm.tamper_vectors.len() == 10 =>
            {
                ProbeOutcome {
                    exit: 0,
                    event: "registry_ok".into(),
                    refusal_id: None,
                    raw_stdout: String::new(),
                    raw_stderr: String::new(),
                }
            }
            other => ProbeOutcome {
                exit: 2,
                event: "error".into(),
                refusal_id: None,
                raw_stdout: String::new(),
                raw_stderr: format!("{other:?}"),
            },
        },
        "admissibility_four_way" => {
            use fa_registry::ALL_STATES;
            use fa_registry::admissibility_plan::{ALL_KINDS, DispositionFamily};
            let classes = EntryClasses::embedded().expect("entry_classes.toml");
            let reg = Admissibility::embedded(&classes).expect("admissibility.toml");
            let plan = PlanAdmissibility::parse(include_str!(
                "../../../COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md"
            ))
            .expect("plan Appendix C");
            let mut matches = plan.cells.len() == 225;
            for class in classes.posting() {
                let name = class.name.as_str();
                for state in ALL_STATES {
                    for family in DispositionFamily::ALL {
                        for kind in ALL_KINDS {
                            for pre_opening in [false, true] {
                                let p_dec =
                                    plan.decide_cell(name, state, family, kind, pre_opening);
                                let t_dec = reg.decide_cell(name, state, family, kind, pre_opening);
                                if p_dec != t_dec {
                                    matches = false;
                                }
                            }
                        }
                    }
                }
            }
            if matches {
                ProbeOutcome {
                    exit: 0,
                    event: "registry_ok".into(),
                    refusal_id: None,
                    raw_stdout: String::new(),
                    raw_stderr: String::new(),
                }
            } else {
                ProbeOutcome {
                    exit: 2,
                    event: "error".into(),
                    refusal_id: None,
                    raw_stdout: String::new(),
                    raw_stderr: format!("admissibility mismatch: {}", plan.cells.len()),
                }
            }
        }
        "g1_genesis_clauses_live" => {
            let inv = Invariants::embedded().expect("invariants.toml");
            let g1_all_live = inv
                .clauses
                .iter()
                .filter(|c| c.first_gate == "G1")
                .all(|c| c.is_live());
            if g1_all_live {
                ProbeOutcome {
                    exit: 0,
                    event: "registry_ok".into(),
                    refusal_id: None,
                    raw_stdout: String::new(),
                    raw_stderr: String::new(),
                }
            } else {
                ProbeOutcome {
                    exit: 2,
                    event: "error".into(),
                    refusal_id: None,
                    raw_stdout: String::new(),
                    raw_stderr: "not all G1 clauses are live".into(),
                }
            }
        }
        "g4_all_clauses_live" => {
            let inv = Invariants::embedded().expect("invariants.toml");
            let all_live = inv.clauses.iter().all(|c| c.is_live());
            if all_live {
                ProbeOutcome {
                    exit: 0,
                    event: "registry_ok".into(),
                    refusal_id: None,
                    raw_stdout: String::new(),
                    raw_stderr: String::new(),
                }
            } else {
                ProbeOutcome {
                    exit: 2,
                    event: "error".into(),
                    refusal_id: None,
                    raw_stdout: String::new(),
                    raw_stderr: "dormant clauses remain before G4".into(),
                }
            }
        }
        other => ProbeOutcome {
            exit: 2,
            event: "error".into(),
            refusal_id: None,
            raw_stdout: String::new(),
            raw_stderr: format!("unknown registry probe `{other}`"),
        },
    }
}

fn check_expectation(
    id: &str,
    expected: &StepExpectation,
    expected_exit: u8,
    expected_event: &str,
    outcome: &ProbeOutcome,
) -> Result<(), String> {
    match expected {
        StepExpectation::Works => {
            if outcome.exit != 0 || outcome.event != expected_event {
                return Err(format!(
                    "{id}: REGRESSION — declared `works` (exit 0, event `{expected_event}`), got exit {} event `{}`\nstdout: {}\nstderr: {}",
                    outcome.exit, outcome.event, outcome.raw_stdout, outcome.raw_stderr
                ));
            }
        }
        StepExpectation::Refused { refusal_id, bead } => {
            if outcome.exit == 0 {
                return Err(format!(
                    "{id}: UNRECORDED CHANGE — declared `refused` ({refusal_id}, bead {bead}), but command succeeded with event `{}`! Update registries/scoreboard.toml.",
                    outcome.event
                ));
            }
            if outcome.exit != expected_exit
                || outcome.event != expected_event
                || outcome.refusal_id.as_deref() != Some(refusal_id.as_str())
            {
                return Err(format!(
                    "{id}: DRIFT — declared `refused` (exit {expected_exit}, event `{expected_event}`, refusal `{refusal_id}`), got exit {} event `{}` refusal {:?}\nstdout: {}\nstderr: {}",
                    outcome.exit,
                    outcome.event,
                    outcome.refusal_id,
                    outcome.raw_stdout,
                    outcome.raw_stderr
                ));
            }
        }
        StepExpectation::Absent { bead } => {
            if outcome.exit == 0 {
                return Err(format!(
                    "{id}: UNRECORDED PROGRESS — declared `absent` (bead {bead}), but command now succeeds with event `{}`! Update registries/scoreboard.toml and docs/VISION_AND_GATE_SCOREBOARD.md.",
                    outcome.event
                ));
            }
            if outcome.exit != expected_exit || outcome.event != expected_event {
                return Err(format!(
                    "{id}: DRIFT — declared `absent` (exit {expected_exit}, event `{expected_event}`, bead {bead}), got exit {} event `{}`\nstdout: {}\nstderr: {}",
                    outcome.exit, outcome.event, outcome.raw_stdout, outcome.raw_stderr
                ));
            }
        }
    }
    Ok(())
}

fn setup_fixture_book(dir: &Path) -> BTreeMap<String, String> {
    let book = dir.join("acme");
    let book_str = book.display().to_string();
    let run_ok = |args: &[&str]| -> Json {
        let mut full: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        full.push("--book".into());
        full.push(book_str.clone());
        full.push("--json".into());
        let out = run_cli_probe(&full);
        assert_eq!(
            out.exit, 0,
            "fixture setup failed for {args:?}:\nstdout={}\nstderr={}",
            out.raw_stdout, out.raw_stderr
        );
        let last = out.raw_stdout.lines().last().unwrap_or("{}");
        json::parse(last).expect("valid robot json")
    };

    run_ok(&[
        "book",
        "create",
        "--name",
        "Acme Scoreboard Co",
        "--base-unit",
        "USD",
    ]);
    run_ok(&["chart", "import", "--template", "us-gaap-smb"]);
    run_ok(&["period", "create", "--fiscal-year", "2025"]);
    run_ok(&["period", "create", "--fiscal-year", "2026"]);
    run_ok(&["period", "open", "FY2025-P12"]);
    run_ok(&["period", "open", "FY2026-P01"]);
    run_ok(&[
        "period",
        "soft-close",
        "FY2026-P01",
        "--as",
        "controller",
        "--yes",
    ]);
    run_ok(&[
        "period",
        "close",
        "FY2026-P01",
        "--as",
        "controller",
        "--yes",
    ]);
    run_ok(&["period", "open", "FY2026-P03"]);
    run_ok(&["period", "open", "FY2026-P04"]);

    let invoice_path = write_file(
        dir,
        "invoice.txt",
        "Invoice 10442 to ACME-CUST-17: 10 widgets at 125.00 USD, total 1,250.00 USD.\n",
    );
    let doc_line = run_ok(&[
        "document",
        "add",
        &invoice_path,
        "--kind",
        "Invoice",
        "--grade",
        "HumanUpload",
    ]);
    let doc_oid = doc_line
        .get("data")
        .and_then(|d| d.get("oid"))
        .and_then(Json::as_str)
        .expect("doc oid")
        .to_string();

    let sale_1 = write_file(
        dir,
        "sale1.json",
        r#"{"effective_date":"2026-03-14","idempotency_key":"inv-10442","legs":[{"side":"debit","account":"1200","amount":"1250.00 USD"},{"side":"credit","account":"4000","amount":"1250.00 USD"}]}"#,
    );
    let posted_1 = run_ok(&["post", "--intent", &sale_1, "--evidence", &doc_oid]);
    let entry_vid = posted_1
        .get("data")
        .and_then(|d| d.get("vid"))
        .and_then(Json::as_str)
        .expect("entry vid")
        .to_string();
    let post_seq = posted_1
        .get("data")
        .and_then(|d| d.get("recorded_at"))
        .and_then(|v| match v {
            Json::Int(n) => Some(*n),
            _ => None,
        })
        .expect("recorded_at")
        .to_string();

    let rev_intent = write_file(
        dir,
        "rev_target.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"rev-target-1","legs":[{"side":"debit","account":"1200","amount":"100.00 USD"},{"side":"credit","account":"4000","amount":"100.00 USD"}]}"#,
    );
    let posted_rev = run_ok(&["post", "--intent", &rev_intent, "--evidence", &doc_oid]);
    let rev_target_vid = posted_rev
        .get("data")
        .and_then(|d| d.get("vid"))
        .and_then(Json::as_str)
        .expect("rev_target vid")
        .to_string();

    let sale_2 = write_file(
        dir,
        "sale2.json",
        r#"{"effective_date":"2026-03-16","idempotency_key":"inv-10443","legs":[{"side":"debit","account":"1200","amount":"200.00 USD"},{"side":"credit","account":"4000","amount":"200.00 USD"}]}"#,
    );
    let plan_file_2 = dir.join("sale2.plan").display().to_string();

    let unbalanced_intent = write_file(
        dir,
        "unbalanced.json",
        r#"{"effective_date":"2026-03-17","idempotency_key":"unbal-1","legs":[{"side":"debit","account":"1200","amount":"100.00 USD"},{"side":"credit","account":"4000","amount":"90.00 USD"}]}"#,
    );
    let closed_period_intent = write_file(
        dir,
        "closed_period.json",
        r#"{"effective_date":"2026-01-15","idempotency_key":"closed-p01-1","legs":[{"side":"debit","account":"1200","amount":"50.00 USD"},{"side":"credit","account":"4000","amount":"50.00 USD"}]}"#,
    );

    let cert_file = dir.join("march.cert").display().to_string();
    run_ok(&[
        "tb",
        "--period",
        "FY2026-P03",
        "--certificate-out",
        &cert_file,
    ]);
    run_ok(&["registers", "advance", "--period", "FY2026-P03"]);
    run_ok(&["checkpoint", "create", "--grant", "witness"]);

    let mut vars = BTreeMap::new();
    vars.insert("{book}".into(), book_str);
    vars.insert(
        "{demo_book}".into(),
        dir.join("retail-demo").display().to_string(),
    );
    vars.insert("{doc_oid}".into(), doc_oid);
    vars.insert("{entry_vid}".into(), entry_vid);
    vars.insert("{post_seq}".into(), post_seq);
    vars.insert("{rev_target_vid}".into(), rev_target_vid);
    vars.insert("{sale_intent_2}".into(), sale_2);
    vars.insert("{plan_file_2}".into(), plan_file_2);
    vars.insert("{cert_file}".into(), cert_file);
    vars.insert("{unbalanced_intent}".into(), unbalanced_intent);
    vars.insert("{closed_period_intent}".into(), closed_period_intent);
    vars
}

fn substitute(argv: &[String], vars: &BTreeMap<String, String>) -> Vec<String> {
    argv.iter()
        .map(|arg| {
            let mut s = arg.clone();
            for (k, v) in vars {
                if s.contains(k) {
                    s = s.replace(k, v);
                }
            }
            s
        })
        .collect()
}

#[test]
fn vision_workflows_and_gate_criteria_match_declared_scoreboard_in_both_directions() {
    let sb = Scoreboard::embedded().expect("scoreboard.toml is valid");
    let dir = tmp_dir("live-wf");
    let vars = setup_fixture_book(&dir);

    for step in &sb.steps {
        let argv = substitute(&step.argv, &vars);
        let outcome = run_cli_probe(&argv);
        check_expectation(
            &step.id,
            &step.expected,
            step.expected_exit,
            &step.expected_event,
            &outcome,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    }

    let gate_dir = tmp_dir("live-gate");
    let gate_vars = setup_fixture_book(&gate_dir);
    for crit in &sb.gate_criteria {
        let argv = substitute(&crit.argv, &gate_vars);
        let outcome = match crit.probe_kind {
            ProbeKind::Cli => run_cli_probe(&argv),
            ProbeKind::Registry => run_registry_probe(&argv[0]),
        };
        check_expectation(
            &crit.id,
            &crit.expected,
            crit.expected_exit,
            &crit.expected_event,
            &outcome,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    }

    let rendered = sb.render_markdown();
    assert_eq!(
        SCOREBOARD_DOC, rendered,
        "docs/VISION_AND_GATE_SCOREBOARD.md is out of sync with registries/scoreboard.toml; regenerate with `cargo run -p xtask -- scoreboard > docs/VISION_AND_GATE_SCOREBOARD.md`"
    );
}

#[test]
fn planted_scoreboard_drift_fails_in_both_directions() {
    let exits = ExitCodes::embedded().expect("exit_codes.toml");
    let refusals = RefusalCatalog::embedded().expect("refusal_catalog.toml");
    let _ = (exits, refusals);

    // 1. Declaring an absent command as `works` must fail with REGRESSION.
    let absent_outcome = ProbeOutcome {
        exit: 2,
        event: "error".into(),
        refusal_id: None,
        raw_stdout: String::new(),
        raw_stderr: "unknown verb".into(),
    };
    let err = check_expectation(
        "WF-PLANTED-1",
        &StepExpectation::Works,
        0,
        "posted",
        &absent_outcome,
    )
    .expect_err("declaring a failing step as works must fail");
    assert!(err.contains("REGRESSION"), "{err}");

    // 2. Landing a feature while leaving its step declared `absent` must fail with UNRECORDED PROGRESS.
    let working_outcome = ProbeOutcome {
        exit: 0,
        event: "posted".into(),
        refusal_id: None,
        raw_stdout: String::new(),
        raw_stderr: String::new(),
    };
    let err = check_expectation(
        "WF-PLANTED-2",
        &StepExpectation::Absent {
            bead: "fa-8q2".into(),
        },
        2,
        "error",
        &working_outcome,
    )
    .expect_err("an absent step that now succeeds must fail to force a scoreboard update");
    assert!(err.contains("UNRECORDED PROGRESS"), "{err}");
}
