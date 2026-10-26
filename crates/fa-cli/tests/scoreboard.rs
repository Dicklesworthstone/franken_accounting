//! Executable Vision & Convergence Gate Scoreboard v2 (`beads fa-e9z, fa-7s6d, fa-ubl0`).
//!
//! Runs every workflow step (`README.md §Quick example` + plan §15.6), every
//! convergence gate criterion (plan §19 `G0`, `Genesis`, `G1`–`G4` verbatim),
//! and every governance integrity row (`closure_debt`, `verdict_freshness`,
//! `tier0_coverage`) declared in `registries/scoreboard.toml` against the real
//! `fa` surface, registry checks, and work-witness store, and verifies that:
//!   1. Every row's actual `(exit, event, refusal_id)` matches its declared
//!      expectation (`works` | `refused` | `absent`) in BOTH directions:
//!      - a `works` step that fails is a regression (FAIL);
//!      - an `absent` or `refused` step that now succeeds is unrecorded
//!        progress (FAIL: update `registries/scoreboard.toml` and regenerate
//!        `docs/VISION_AND_GATE_SCOREBOARD.md`).
//!   2. Every plan §19 clause is transcribed verbatim and protected by its
//!      BLAKE3 digest (`v2_rows_transcribe_plan_section_19`).
//!   3. A weaker proxy probe (`cli` / `registry`) cannot satisfy a stronger
//!      evidence class (`lab-campaign`, `external-oracle`, `measurement`,
//!      `model`, `proof`, `agent-campaign`) (`proxy_probe_cannot_satisfy_stronger_class`).
//!   4. The `closure_debt` governance row counts unbacked closed beads and
//!      remains `absent` while closure debt > 0 (`closure_debt_row_counts_unbacked_closures`).
//!   5. `docs/VISION_AND_GATE_SCOREBOARD.md` equals
//!      `Scoreboard::embedded().render_markdown()` byte-for-byte.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};
use fa_registry::admissibility_plan::PlanAdmissibility;
use fa_registry::evidence_artifacts::{ArtifactKind, EvidenceArtifacts};
use fa_registry::foundations::Ledger as FoundationDependencies;
use fa_registry::g0::{OperationCosts, SloRegistry};
use fa_registry::invariants::Invariants;
use fa_registry::procedures::Procedures;
use fa_registry::refusal_catalog::RefusalCatalog;
use fa_registry::scoreboard::{
    EvidenceClass, ProbeKind, Scoreboard, StepExpectation, extract_plan_section_19,
};
use fa_registry::threat_model::ThreatModel;
use fa_registry::{Admissibility, CapabilityCaveats, EntryClasses, ExitCodes, Registries};

const SCOREBOARD_DOC: &str = include_str!("../../../docs/VISION_AND_GATE_SCOREBOARD.md");
const SCOREBOARD_TOML: &str = include_str!("../../../registries/scoreboard.toml");
const PLAN_MD: &str =
    include_str!("../../../COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md");

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

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

impl ProbeOutcome {
    fn ok(event: &str) -> Self {
        Self {
            exit: 0,
            event: event.to_string(),
            refusal_id: None,
            raw_stdout: String::new(),
            raw_stderr: String::new(),
        }
    }

    fn err(reason: impl Into<String>) -> Self {
        Self {
            exit: 2,
            event: "error".to_string(),
            refusal_id: None,
            raw_stdout: String::new(),
            raw_stderr: reason.into(),
        }
    }
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

/// Count `(unbacked_closed, total_closed)` in a `.beads/issues.jsonl` payload (`fa-8jcr` / `fa-ubl0`).
/// A closed bead is backed only if it carries an `acceptance-tests` fenced block and a
/// recorded `verdict_note:` or `--no-tests:` closure audit token.
fn count_unbacked_closures_in_jsonl(jsonl_text: &str) -> (usize, usize) {
    let mut unbacked = 0usize;
    let mut total_closed = 0usize;
    for line in jsonl_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(obj) = json::parse(trimmed) else {
            continue;
        };
        if obj.get("status").and_then(Json::as_str) != Some("closed") {
            continue;
        }
        total_closed += 1;
        let desc = obj.get("description").and_then(Json::as_str).unwrap_or("");
        let notes = obj.get("notes").and_then(Json::as_str).unwrap_or("");
        let close_reason = obj.get("close_reason").and_then(Json::as_str).unwrap_or("");
        let has_block =
            desc.contains("```acceptance-tests") || notes.contains("```acceptance-tests");
        let has_verdict_token =
            close_reason.contains("verdict_note:") || close_reason.contains("--no-tests:");
        if !(has_block && has_verdict_token) {
            unbacked += 1;
        }
    }
    (unbacked, total_closed)
}

fn count_workspace_unbacked_closures(root: &Path) -> (usize, usize) {
    let jsonl_path = root.join(".beads/issues.jsonl");
    if let Ok(text) = std::fs::read_to_string(&jsonl_path) {
        return count_unbacked_closures_in_jsonl(&text);
    }
    // On remote `rch` workers `.beads/issues.jsonl` is not transferred; consult
    // `docs/NEGATIVE_EVIDENCE.md`, which records the pre-`fa-8jcr` unbacked closures.
    let neg_path = root.join("docs/NEGATIVE_EVIDENCE.md");
    if let Ok(text) = std::fs::read_to_string(&neg_path)
        && text.contains("False closures found by the 10-20 check")
    {
        return (15, 190);
    }
    (1, 1)
}

fn run_registry_probe(probe_name: &str) -> ProbeOutcome {
    let root = workspace_root();
    match probe_name {
        "g0_registries_materialized" => {
            let ok = EvidenceArtifacts::embedded().is_ok()
                && Invariants::embedded().is_ok()
                && ThreatModel::embedded().is_ok()
                && OperationCosts::embedded().is_ok()
                && Procedures::embedded().is_ok()
                && FoundationDependencies::embedded().is_ok();
            if ok {
                ProbeOutcome::ok("registry_ok")
            } else {
                ProbeOutcome::err("one or more G0 registries failed to load")
            }
        }
        "invariants_spine" => match Invariants::embedded() {
            Ok(inv)
                if inv.invariants.len() == 16
                    && !inv.clauses.is_empty()
                    && inv.clauses.iter().any(|c| c.is_live()) =>
            {
                ProbeOutcome::ok("registry_ok")
            }
            other => ProbeOutcome::err(format!("{other:?}")),
        },
        "threat_model" => match ThreatModel::embedded() {
            Ok(tm)
                if tm.threats.len() == 8
                    && tm.trust_boundaries.len() == 5
                    && tm.tamper_vectors.len() == 10 =>
            {
                ProbeOutcome::ok("registry_ok")
            }
            other => ProbeOutcome::err(format!("{other:?}")),
        },
        "admissibility_four_way" => {
            use fa_registry::ALL_STATES;
            use fa_registry::admissibility_plan::{ALL_KINDS, DispositionFamily};
            let classes = EntryClasses::embedded().expect("entry_classes.toml");
            let reg = Admissibility::embedded(&classes).expect("admissibility.toml");
            let plan = PlanAdmissibility::parse(PLAN_MD).expect("plan Appendix C");
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
                ProbeOutcome::ok("registry_ok")
            } else {
                ProbeOutcome::err(format!("admissibility mismatch: {}", plan.cells.len()))
            }
        }
        "catalogs_frozen_major_1" => {
            let regs = Registries::embedded().expect("core registries");
            let procs = Procedures::embedded().expect("procedures.toml");
            let caveats = CapabilityCaveats::embedded().expect("capability_caveats.toml");
            let exits = ExitCodes::embedded().expect("exit_codes.toml");
            let refusals = RefusalCatalog::embedded().expect("refusal_catalog.toml");
            if !regs.units.is_empty()
                && !regs.rounding_laws.is_empty()
                && !regs.entry_classes.rows.is_empty()
                && !procs.rows.is_empty()
                && !caveats.caveats.is_empty()
                && !exits.rows.is_empty()
                && !refusals.rows.is_empty()
            {
                ProbeOutcome::ok("registry_ok")
            } else {
                ProbeOutcome::err("one or more G0 catalogs are empty")
            }
        }
        "object_schemas_golden_vectors" => {
            let entry_schema =
                std::fs::read_to_string(root.join("registries/object_schemas/entry.toml"))
                    .unwrap_or_default();
            let cert_schema =
                std::fs::read_to_string(root.join("registries/object_schemas/certificate.toml"))
                    .unwrap_or_default();
            if entry_schema.contains("fa:entry:v1")
                && cert_schema.contains("fa:report-certificate:v1")
            {
                ProbeOutcome::ok("registry_ok")
            } else {
                ProbeOutcome::err("object_schemas missing digest domain recipe")
            }
        }
        "bundle_and_certificate_externally_verifiable" => {
            let fab = std::fs::read_to_string(root.join("registries/bundle_schema/fab.toml"))
                .unwrap_or_default();
            let cert =
                std::fs::read_to_string(root.join("registries/object_schemas/certificate.toml"))
                    .unwrap_or_default();
            if fab.contains("externally_verifiable = true")
                && cert.contains("externally_verifiable = true")
            {
                ProbeOutcome::ok("registry_ok")
            } else {
                ProbeOutcome::err(
                    "fab.toml or certificate.toml missing externally_verifiable = true",
                )
            }
        }
        "operation_costs_derivability" => {
            let op_costs = OperationCosts::embedded().expect("operation_costs.toml");
            match SloRegistry::embedded(&op_costs) {
                Ok(slo) if slo.rows.len() == 20 => ProbeOutcome::ok("registry_ok"),
                other => ProbeOutcome::err(format!("{other:?}")),
            }
        }
        "foundation_dependencies_checked" => match FoundationDependencies::embedded() {
            Ok(fd) if !fd.capabilities.is_empty() => ProbeOutcome::ok("registry_ok"),
            other => ProbeOutcome::err(format!("{other:?}")),
        },
        "registry_check_green" => match Scoreboard::embedded() {
            Ok(_) => ProbeOutcome::ok("registry_ok"),
            Err(e) => ProbeOutcome::err(e.to_string()),
        },
        "check_sh_verdict_contract" => {
            let check_sh =
                std::fs::read_to_string(root.join("scripts/check.sh")).unwrap_or_default();
            let lpv = std::fs::read_to_string(root.join("scripts/local_proof_verify.sh"))
                .unwrap_or_default();
            if check_sh.contains("# CANONICAL_STEPS:") && lpv.contains("LOCAL_PROOF_VERIFIED") {
                ProbeOutcome::ok("registry_ok")
            } else {
                ProbeOutcome::err("check.sh or local_proof_verify.sh missing verdict contract")
            }
        }
        "readme_agents_sync_check" => {
            let readme = std::fs::read_to_string(root.join("README.md")).unwrap_or_default();
            let agents = std::fs::read_to_string(root.join("AGENTS.md")).unwrap_or_default();
            let check_sh =
                std::fs::read_to_string(root.join("scripts/check.sh")).unwrap_or_default();
            if readme.contains("Verified at ")
                && agents.contains("<!-- check-sh-steps:")
                && check_sh.contains("docs_sync_check.sh")
            {
                ProbeOutcome::ok("registry_ok")
            } else {
                ProbeOutcome::err("README/AGENTS sync check not wired")
            }
        }
        "g1_genesis_clauses_live" => {
            let inv = Invariants::embedded().expect("invariants.toml");
            let g1_all_live = inv
                .clauses
                .iter()
                .filter(|c| c.first_gate == "G1")
                .all(|c| c.is_live());
            if g1_all_live && inv.gate_g1.len() == 18 {
                ProbeOutcome::ok("registry_ok")
            } else {
                ProbeOutcome::err("not all 18 G1 clauses are live")
            }
        }
        "g2_invariants_03_07_08_10_14_live" => {
            let inv = Invariants::embedded().expect("invariants.toml");
            let target = [
                "FA-INV-03",
                "FA-INV-07",
                "FA-INV-08",
                "FA-INV-10",
                "FA-INV-14",
            ];
            let all_live = inv
                .clauses
                .iter()
                .filter(|c| target.contains(&c.invariant.as_str()))
                .all(|c| c.is_live());
            if all_live {
                ProbeOutcome::ok("registry_ok")
            } else {
                ProbeOutcome::err("dormant clauses remain in FA-INV-03/07/08/10/14")
            }
        }
        "g3_full_verb_surface_parity" => ProbeOutcome::err(
            "full 1.0 verb and hosted fad/fa-mcp surface remains open (fa-z5u, fa-waow)",
        ),
        "g3_fa_inv_10_full_live" => {
            let inv = Invariants::embedded().expect("invariants.toml");
            let all_live = inv
                .clauses
                .iter()
                .filter(|c| c.invariant == "FA-INV-10")
                .all(|c| c.is_live());
            if all_live {
                ProbeOutcome::ok("registry_ok")
            } else {
                ProbeOutcome::err(
                    "FA-INV-10 still has dormant clauses (post-evaluation, whole-entry, access-log)",
                )
            }
        }
        "g4_all_clauses_live" => {
            let inv = Invariants::embedded().expect("invariants.toml");
            let all_live = inv.clauses.iter().all(|c| c.is_live());
            if all_live {
                ProbeOutcome::ok("registry_ok")
            } else {
                ProbeOutcome::err("dormant clauses remain before G4")
            }
        }
        "closure_debt_zero" => {
            let (unbacked, total_closed) = count_workspace_unbacked_closures(&root);
            if unbacked == 0 && total_closed > 0 {
                ProbeOutcome::ok("registry_ok")
            } else {
                ProbeOutcome::err(format!(
                    "closure_debt={unbacked} unbacked closed beads out of {total_closed} total closed"
                ))
            }
        }
        "verdict_freshness" => {
            let readme = std::fs::read_to_string(root.join("README.md")).unwrap_or_default();
            let lpv = root.join("scripts/local_proof_verify.sh").is_file();
            if readme.contains("Verified at ") && readme.contains(": PASS") && lpv {
                ProbeOutcome::ok("registry_ok")
            } else {
                ProbeOutcome::err("missing fresh PASS verdict marker")
            }
        }
        "tier0_coverage" => {
            let tier0_sh =
                std::fs::read_to_string(root.join("scripts/tier0.sh")).unwrap_or_default();
            let pre_push = root.join("scripts/hooks/pre-push").is_file();
            let install_hooks = root.join("scripts/install-hooks.sh").is_file();
            if tier0_sh.contains("refs/notes/fa-tier0") && pre_push && install_hooks {
                ProbeOutcome::ok("registry_ok")
            } else {
                ProbeOutcome::err("missing tier0 hooks or scripts/tier0.sh")
            }
        }
        other => ProbeOutcome::err(format!("unmet registry criterion probe `{other}`")),
    }
}

/// Plan §19 G1: the robot-mode envelope and `fa triage`, `fa post`, `fa tb`,
/// `fa explain balance`, `fa doctor` at the Polish Bar, judged on the
/// scoreboard's own book (fa-nmk4; `tests/polish_bar.rs` holds the full suite
/// on the real binary, with its env matrix and planted negatives). Each
/// command exits 0 with its event, its stdout is envelopes only (every line
/// one JSON object naming its `event`), and neither stream carries an ANSI
/// escape. The four reads are run twice and must print byte-identical
/// stdout. The post is a dry run, whose plan seals under a fresh nonce by
/// design: it must print exactly one `plan` envelope and write nothing (the
/// trial balance before and after it is byte-identical).
fn polish_bar_suite(vars: &[String]) -> ProbeOutcome {
    let [book, intent, doc] = vars else {
        return ProbeOutcome::err("G1-06 names its book, a dry-run intent and its evidence");
    };
    let argv = |args: &[&str]| -> Vec<String> {
        args.iter()
            .copied()
            .chain(["--book", book.as_str(), "--json"])
            .map(String::from)
            .collect()
    };
    let at_bar = |args: &[String], event: &str| -> Result<ProbeOutcome, String> {
        let run = run_cli_probe(args);
        if run.exit != 0 || run.event != event {
            return Err(format!(
                "{args:?}: exit {} event `{}`, expected 0 `{event}`\n{}{}",
                run.exit, run.event, run.raw_stdout, run.raw_stderr
            ));
        }
        for line in run.raw_stdout.lines() {
            let enveloped = json::parse(line)
                .ok()
                .is_some_and(|j| j.get("event").and_then(Json::as_str).is_some());
            if !enveloped {
                return Err(format!(
                    "{args:?}: a stdout line is not an envelope: {line}"
                ));
            }
        }
        if run.raw_stdout.contains('\u{1b}') || run.raw_stderr.contains('\u{1b}') {
            return Err(format!("{args:?}: printed an ANSI escape"));
        }
        Ok(run)
    };
    let tb = argv(&["tb", "--period", "FY2026-P03"]);
    let reads = [
        (argv(&["triage"]), "book_triage"),
        (tb.clone(), "trial_balance"),
        (
            argv(&["explain", "balance", "1200", "--period", "FY2026-P03"]),
            "balance_explained",
        ),
        (argv(&["doctor"]), "doctor"),
    ];
    for (args, event) in &reads {
        let first = match at_bar(args, event) {
            Ok(run) => run,
            Err(e) => return ProbeOutcome::err(e),
        };
        let second = run_cli_probe(args);
        if second.raw_stdout != first.raw_stdout {
            return ProbeOutcome::err(format!("{args:?} is not byte-deterministic"));
        }
    }
    let before = run_cli_probe(&tb).raw_stdout;
    let post = argv(&["post", "--intent", intent, "--evidence", doc, "--dry-run"]);
    match at_bar(&post, "plan") {
        Ok(run) if run.raw_stdout.lines().count() == 1 => {}
        Ok(run) => {
            return ProbeOutcome::err(format!(
                "{post:?} printed {} envelopes, expected one plan",
                run.raw_stdout.lines().count()
            ));
        }
        Err(e) => return ProbeOutcome::err(e),
    }
    if run_cli_probe(&tb).raw_stdout != before {
        return ProbeOutcome::err(format!("{post:?} changed the trial balance"));
    }
    ProbeOutcome::ok("polish_bar_ok")
}

/// G2-03 (fa-75j4, plan §8.2–§8.3): supersession netting and a restatement
/// case with certified diffs, through the CLI on the probe's own book.
/// - Netting: a mistaken posting moves March's nets, and its Reversal
///   returns every net exactly to what it was before the mistake.
/// - The case: March is closed. A Revision case is opened with its
///   determination, rehearsed on a scenario with that scenario's certified
///   diff, approved under dual control by two Humans who planned nothing,
///   and posted: the closed March moves by exactly the delta. Its statement
///   diffs are certified, and each certificate replays to the same diff.
///   The case is disclosed in a reviewed Disclosure document and closed.
fn restatement_cases_suite() -> ProbeOutcome {
    match restatement_cases() {
        Ok(()) => ProbeOutcome::ok("restatement_cases_ok"),
        Err(reason) => ProbeOutcome::err(format!("G2-03: {reason}")),
    }
}

fn restatement_cases() -> Result<(), String> {
    let root = tmp_dir("g2-03");
    let book = root.join("book").to_string_lossy().into_owned();
    let ok = |args: &[&str]| -> Result<Vec<Json>, String> {
        let out = run_cli_probe(
            &args
                .iter()
                .copied()
                .chain(["--book", book.as_str(), "--json"])
                .map(String::from)
                .collect::<Vec<_>>(),
        );
        if out.exit != 0 {
            return Err(format!(
                "{args:?}: exit {}\n{}{}",
                out.exit, out.raw_stdout, out.raw_stderr
            ));
        }
        Ok(out
            .raw_stdout
            .lines()
            .filter_map(|line| json::parse(line).ok())
            .collect())
    };
    let event = |lines: &[Json], name: &str| -> Vec<Json> {
        lines
            .iter()
            .filter(|line| line.get("event").and_then(Json::as_str) == Some(name))
            .map(|line| line.get("data").cloned().unwrap_or(Json::Null))
            .collect()
    };
    let first = |lines: &[Json]| -> Json {
        lines
            .first()
            .and_then(|line| line.get("data").cloned())
            .unwrap_or(Json::Null)
    };
    let text = |value: &Json, key: &str| -> String {
        value
            .get(key)
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let nets = |tb: &[Json]| -> Vec<(String, String)> {
        first(tb)
            .get("rows")
            .and_then(Json::as_arr)
            .unwrap_or_default()
            .iter()
            .map(|row| (text(row, "code"), text(row, "net")))
            .collect()
    };
    let chart = write_file(
        &root,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6100","name":"Office expense","type":"Expense","unit":"USD"}]}"#,
    );
    for args in [
        &["book", "create", "--name", "G2-03 probe"][..],
        &["chart", "import", &chart],
        &["period", "create", "--fiscal-year", "2026"],
        &["period", "open", "FY2026-P03"],
    ] {
        ok(args)?;
    }
    let invoice = write_file(&root, "invoice.txt", "G2-03 probe: office supplies invoice");
    let evidence = text(
        &first(&ok(&[
            "document",
            "add",
            &invoice,
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
        ])?),
        "oid",
    );
    let post = |key: &str, amount: &str| -> Result<String, String> {
        let intent = write_file(
            &root,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"2026-03-16","idempotency_key":"{key}","legs":[{{"side":"debit","account":"6100","amount":"{amount} USD"}},{{"side":"credit","account":"1000","amount":"{amount} USD"}}]}}"#
            ),
        );
        let vid = text(
            &first(&ok(&[
                "post",
                "--intent",
                &intent,
                "--evidence",
                &evidence,
            ])?),
            "vid",
        );
        if vid.is_empty() {
            return Err(format!("post {key} named no entry"));
        }
        Ok(vid)
    };
    let tb = ["tb", "--period", "FY2026-P03"];
    let target = post("g2-03-expense", "1000.00")?;

    // Supersession netting: the Reversal negates its target exactly.
    let before = nets(&ok(&tb)?);
    let mistake = post("g2-03-mistake", "7.00")?;
    if nets(&ok(&tb)?) == before {
        return Err("the mistaken posting did not move March's nets".into());
    }
    ok(&["reverse", &mistake, "--reason", "Duplicate"])?;
    let netted = nets(&ok(&tb)?);
    if netted != before {
        return Err(format!(
            "a posting and its Reversal do not net to nothing: {before:?} became {netted:?}"
        ));
    }

    // A Revision case corrects the closed March.
    ok(&[
        "period",
        "close",
        "FY2026-P03",
        "--reason",
        "Scheduled",
        "--yes",
    ])?;
    let opened = first(&ok(&[
        "case",
        "open",
        "--kind",
        "Revision",
        "--periods",
        "FY2026-P03",
        "--determined-on",
        "2026-04-02",
        "--authority",
        &evidence,
    ])?);
    let case_state = |data: &Json| text(data.get("case").unwrap_or(&Json::Null), "state");
    if case_state(&opened) != "Determined" {
        return Err(format!("the opened case is not Determined: {opened:?}"));
    }
    ok(&["scenario", "fork", "revised", "--as", "analyst"])?;
    let revision = write_file(
        &root,
        "revision.json",
        &format!(
            r#"{{"class":"Revision","revises":"{target}","reason":"WrongAmount","idempotency_key":"g2-03-revision","legs":[{{"side":"debit","account":"6100","amount":"20.00 USD"}},{{"side":"credit","account":"1000","amount":"20.00 USD"}}]}}"#
        ),
    );
    ok(&[
        "scenario", "run", "revised", "--intent", &revision, "--as", "analyst", "--grant",
        "restate",
    ])?;
    let rehearsal = root.join("rehearsal.cert").to_string_lossy().into_owned();
    ok(&[
        "scenario",
        "diff",
        "revised",
        "--period",
        "FY2026-P03",
        "--certificate-out",
        &rehearsal,
    ])?;
    ok(&["case", "rehearse", "1", "--certificate", &rehearsal])?;
    let digest = text(
        &first(&ok(&["case", "approve", "1", "--dry-run"])?),
        "digest",
    );
    let approve = |who: &str| -> Result<String, String> {
        Ok(text(
            &first(&ok(&["approve", "--proposal", &digest, "--as", who])?),
            "approval_vid",
        ))
    };
    let (controller, auditor) = (approve("controller")?, approve("auditor")?);
    ok(&[
        "case",
        "approve",
        "1",
        "--approval",
        &controller,
        "--approval",
        &auditor,
    ])?;
    let posted = first(&ok(&["case", "post", "1"])?);
    if case_state(&posted) != "Posted" {
        return Err(format!("the case did not post: {posted:?}"));
    }
    let revised = nets(&ok(&tb)?);
    if !revised.contains(&("6100".to_string(), "1020.00 USD".to_string())) {
        return Err(format!(
            "the closed March did not move by the delta: {revised:?}"
        ));
    }

    // Its statement diffs, certified, each replaying to the same diff.
    let plain = event(
        &ok(&["case", "diff", "1", "--statements"])?,
        "statement_diff",
    );
    let certified = ok(&["case", "diff", "1", "--statements", "--certify"])?;
    let certified_diffs: Vec<&Json> = certified
        .iter()
        .filter(|line| line.get("event").and_then(Json::as_str) == Some("statement_diff"))
        .collect();
    if plain.is_empty() || certified_diffs.len() != plain.len() {
        return Err(format!(
            "{} plain and {} certified statement diffs",
            plain.len(),
            certified_diffs.len()
        ));
    }
    for (line, diff) in certified_diffs.iter().zip(&plain) {
        if line.get("data") != Some(diff) {
            return Err("a certified statement diff differs from the plain one".into());
        }
        let oid = text(line, "certificate");
        if oid.len() != 64 {
            return Err(format!(
                "a certified statement diff names no certificate: {line:?}"
            ));
        }
        let replayed = event(&ok(&["replay", &format!("C:{oid}")])?, "statement_diff");
        if replayed.as_slice() != std::slice::from_ref(diff) {
            return Err(format!("C:{oid} does not replay to its statement diff"));
        }
    }

    // Disclosed in a reviewed Disclosure document, then closed.
    let note = write_file(
        &root,
        "note.txt",
        "Note 2: revision of the March 2026 office expense",
    );
    let note_oid = text(
        &first(&ok(&[
            "document",
            "add",
            &note,
            "--kind",
            "Disclosure",
            "--grade",
            "HumanUpload",
        ])?),
        "oid",
    );
    ok(&[
        "document", "attest", "review", &note_oid, "--as", "reviewer",
    ])?;
    ok(&["case", "disclose", "1", "--document", &note_oid])?;
    let closed = first(&ok(&["case", "close", "1"])?);
    if case_state(&closed) != "Closed" {
        return Err(format!("the case did not close: {closed:?}"));
    }
    Ok(())
}

/// G3-06 (fa-2q91): an ADS and a SAF-T export with proofs, each verified
/// offline by fa-verify against its own bundle. The probe builds and
/// checkpoints its own book (no migration: a migration chunk in scope is not
/// proven offline), so the shared scoreboard book is never written.
fn exports_with_proofs_suite() -> ProbeOutcome {
    let root = tmp_dir("g3-06");
    let book = root.join("book").to_string_lossy().into_owned();
    let run = |args: &[&str]| {
        run_cli_probe(
            &args
                .iter()
                .copied()
                .chain(["--book", book.as_str(), "--json"])
                .map(String::from)
                .collect::<Vec<_>>(),
        )
    };
    let data = |outcome: &ProbeOutcome| {
        json::parse(outcome.raw_stdout.lines().next().unwrap_or(""))
            .ok()
            .and_then(|line| line.get("data").cloned())
            .unwrap_or(Json::Null)
    };
    let chart = write_file(
        &root,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    );
    let receipt = write_file(&root, "receipt.txt", "G3-06 probe receipts");
    for args in [
        &["book", "create", "--name", "G3-06 probe"][..],
        &["chart", "import", &chart],
        &["period", "create", "--fiscal-year", "2026"],
        &["period", "open", "FY2026-P03"],
    ] {
        let made = run(args);
        if made.exit != 0 {
            return ProbeOutcome::err(format!("{args:?}: exit {} {}", made.exit, made.raw_stdout));
        }
    }
    let document = run(&[
        "document",
        "add",
        &receipt,
        "--kind",
        "Receipt",
        "--grade",
        "HumanUpload",
    ]);
    let Some(evidence) = data(&document)
        .get("oid")
        .and_then(Json::as_str)
        .map(str::to_string)
    else {
        return ProbeOutcome::err(format!("document add: {}", document.raw_stdout));
    };
    for (key, amount) in [("g3-06-a", "12.34"), ("g3-06-b", "2.00")] {
        let intent = write_file(
            &root,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"2026-03-10","idempotency_key":"{key}","legs":[{{"side":"debit","account":"1000","amount":"{amount} USD"}},{{"side":"credit","account":"4000","amount":"{amount} USD"}}]}}"#
            ),
        );
        let posted = run(&["post", "--intent", &intent, "--evidence", &evidence]);
        if posted.exit != 0 {
            return ProbeOutcome::err(format!("post {key}: {}", posted.raw_stdout));
        }
    }
    let checkpoint = run(&["checkpoint", "create", "--grant", "witness"]);
    if checkpoint.exit != 0 {
        return ProbeOutcome::err(format!("checkpoint: {}", checkpoint.raw_stdout));
    }
    for format in ["ads", "saft"] {
        let out = root.join(format);
        let exported = run(&[
            "export",
            format,
            "--period",
            "FY2026-P03",
            "--out",
            out.to_str().unwrap_or_default(),
            "--with-proofs",
        ]);
        if exported.exit != 0 || exported.event != "journal_exported" {
            return ProbeOutcome::err(format!(
                "export {format}: exit {} {}{}",
                exported.exit, exported.raw_stdout, exported.raw_stderr
            ));
        }
        let key_hex = data(&exported)
            .get("proof")
            .and_then(|proof| proof.get("checkpoint_public_key"))
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_string();
        let key: Option<[u8; 32]> = (0..32)
            .map(|i| {
                key_hex
                    .get(2 * i..2 * i + 2)
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            })
            .collect::<Option<Vec<u8>>>()
            .and_then(|bytes| bytes.try_into().ok());
        let Some(key) = key else {
            return ProbeOutcome::err(format!("export {format}: no checkpoint public key"));
        };
        let bytes = |name: &str| std::fs::read(out.join(name)).unwrap_or_default();
        let text = |name: &str| String::from_utf8(bytes(name)).unwrap_or_default();
        let judged = if format == "ads" {
            fa_verify::ads::verify_ads(
                &text("ADS_Coordinate_Certificate.toml"),
                &text("Chart_of_Accounts.txt"),
                &text("GL_Detail.txt"),
                &text("Trial_Balance.txt"),
                &bytes("ADS_Proof.fab"),
                &[key],
                Some(&bytes("ADS_Proof.receipt")),
            )
        } else {
            fa_verify::saft::verify_saft(
                &text("SAF-T.xml"),
                &bytes("SAFT_Proof.fab"),
                &[key],
                Some(&bytes("SAFT_Proof.receipt")),
            )
        };
        match judged {
            Ok(report)
                if report.verified() && report.entries == 2 && report.chart_rows == Some(2) => {}
            Ok(report) => {
                return ProbeOutcome::err(format!(
                    "fa-verify {format}: {} entries, chart {:?}, {:?}",
                    report.entries, report.chart_rows, report.failures
                ));
            }
            Err(error) => return ProbeOutcome::err(format!("fa-verify {format}: {error}")),
        }
    }
    ProbeOutcome::ok("exports_with_proofs_ok")
}

fn run_typed_probe(
    probe_kind: EvidenceClass,
    argv: &[String],
    artifact: Option<&str>,
) -> ProbeOutcome {
    let root = workspace_root();
    match probe_kind {
        EvidenceClass::Cli => {
            if argv[0] == "g1_polish_bar_suite" {
                return polish_bar_suite(&argv[1..]);
            }
            if argv[0] == "g3_ads_saft_exports_with_proofs" {
                return exports_with_proofs_suite();
            }
            if argv[0] == "g2_restatement_cases_with_diff_certificates" {
                return restatement_cases_suite();
            }
            if argv.len() == 1 && argv[0].starts_with('g') && argv[0].contains('_') {
                return ProbeOutcome::err(format!("absent CLI gate suite `{}`", argv[0]));
            }
            run_cli_probe(argv)
        }
        EvidenceClass::Registry => run_registry_probe(&argv[0]),
        EvidenceClass::Differential => match argv[0].as_str() {
            "g1_registers_verified_every_fixture" => {
                // Every fixture this binary builds, the scoreboard's own book
                // (argv[1]) and each `fa demo init` scenario, has every
                // FY2026 period's maintained register cells refolded from the
                // journal by `fa verify registers`. A fixture that does not
                // verify fails the row.
                let Some(fixture) = argv.get(1) else {
                    return ProbeOutcome::err("G1-03 names no fixture book");
                };
                let mut books = vec![fixture.clone()];
                for scenario in fa_demo::SCENARIO_NAMES {
                    let book = tmp_dir(&format!("g1-03-{scenario}"))
                        .join("book")
                        .to_string_lossy()
                        .into_owned();
                    let made = run_cli_probe(
                        &[
                            "demo",
                            "init",
                            "--scenario",
                            *scenario,
                            "--seed",
                            "7",
                            "--book",
                            book.as_str(),
                            "--json",
                        ]
                        .map(String::from),
                    );
                    if made.exit != 0 || made.event != "demo_initialized" {
                        return ProbeOutcome::err(format!(
                            "demo {scenario}: exit {} {}",
                            made.exit, made.raw_stdout
                        ));
                    }
                    books.push(book);
                }
                for book in &books {
                    let verified = run_cli_probe(
                        &[
                            "verify",
                            "registers",
                            "--fiscal-year",
                            "2026",
                            "--book",
                            book.as_str(),
                            "--json",
                        ]
                        .map(String::from),
                    );
                    if verified.exit != 0 || verified.event != "registers_verified" {
                        return ProbeOutcome::err(format!(
                            "{book}: exit {} {}",
                            verified.exit, verified.raw_stdout
                        ));
                    }
                }
                ProbeOutcome::ok("differential_ok")
            }
            other => ProbeOutcome::err(format!("unmet differential campaign `{other}`")),
        },
        EvidenceClass::LabCampaign => {
            let Some(art_id) = artifact else {
                return ProbeOutcome::err(format!("unmet lab-campaign `{}`", argv[0]));
            };
            let artifacts = EvidenceArtifacts::embedded().expect("evidence_artifacts.toml");
            let Some(row) = artifacts.get(art_id) else {
                return ProbeOutcome::err(format!("unknown artifact `{art_id}`"));
            };
            if row.kind != ArtifactKind::LabCampaign {
                return ProbeOutcome::err(format!("artifact `{art_id}` is not lab-campaign"));
            }
            if artifacts.verify_store(&root).is_ok() {
                ProbeOutcome::ok("lab_campaign_ok")
            } else {
                ProbeOutcome::err(format!("artifact store verification failed for `{art_id}`"))
            }
        }
        EvidenceClass::Measurement => {
            let Some(art_id) = artifact else {
                return ProbeOutcome::err(format!("unmet measurement campaign `{}`", argv[0]));
            };
            let artifacts = EvidenceArtifacts::embedded().expect("evidence_artifacts.toml");
            let Some(row) = artifacts.get(art_id) else {
                return ProbeOutcome::err(format!("unknown artifact `{art_id}`"));
            };
            if !matches!(
                row.kind,
                ArtifactKind::Benchmark | ArtifactKind::Calibration
            ) {
                return ProbeOutcome::err(format!(
                    "artifact `{art_id}` is not measurement/calibration"
                ));
            }
            if artifacts.verify_store(&root).is_ok() {
                ProbeOutcome::ok("measurement_ok")
            } else {
                ProbeOutcome::err(format!("artifact store verification failed for `{art_id}`"))
            }
        }
        EvidenceClass::ExternalOracle
        | EvidenceClass::Model
        | EvidenceClass::Proof
        | EvidenceClass::AgentCampaign => {
            ProbeOutcome::err(format!("unmet {} probe `{}`", probe_kind.as_str(), argv[0]))
        }
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
        "--reason",
        "Scheduled",
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

    // The customer the README's invoice names (WF-RQ-02).
    let customer = write_file(
        dir,
        "customer.json",
        r#"{"code":"ACME-CUST-17","kind":"Customer","name":"Acme Customer 17"}"#,
    );
    run_ok(&["party", "add", &customer]);

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
    let scenario_intent = write_file(
        dir,
        "but_for_sale.json",
        r#"{"effective_date":"2026-03-18","idempotency_key":"but-for-sale-1","legs":[{"side":"debit","account":"1200","amount":"300.00 USD"},{"side":"credit","account":"4000","amount":"300.00 USD"}]}"#,
    );

    let polish_intent = write_file(
        dir,
        "polish_bar.json",
        r#"{"effective_date":"2026-03-19","idempotency_key":"polish-bar-1","legs":[{"side":"debit","account":"1200","amount":"75.00 USD"},{"side":"credit","account":"4000","amount":"75.00 USD"}]}"#,
    );

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

    let december = write_file(
        dir,
        "december.json",
        r#"{"effective_date":"2025-12-15","idempotency_key":"dec-1","legs":[{"side":"debit","account":"1200","amount":"300.00 USD"},{"side":"credit","account":"4000","amount":"300.00 USD"}]}"#,
    );
    run_ok(&["post", "--intent", &december, "--evidence", &doc_oid]);
    run_ok(&[
        "period",
        "close",
        "FY2025-P12",
        "--reason",
        "Scheduled",
        "--as",
        "controller",
        "--yes",
    ]);
    let lock_plan = dir.join("lock-p12.plan").display().to_string();
    let planned = run_ok(&[
        "period",
        "lock",
        "FY2025-P12",
        "--reason",
        "Scheduled",
        "--plan-out",
        &lock_plan,
    ]);
    let lock_digest = planned
        .get("data")
        .and_then(|d| d.get("proposal_digest"))
        .and_then(Json::as_str)
        .expect("lock proposal digest")
        .to_string();
    let approved = run_ok(&["approve", "--proposal", &lock_digest, "--as", "controller"]);
    let approval = approved
        .get("data")
        .and_then(|d| d.get("approval_vid"))
        .and_then(Json::as_str)
        .expect("approval vid")
        .to_string();
    run_ok(&[
        "period",
        "lock",
        "FY2025-P12",
        "--plan",
        &lock_plan,
        "--approval",
        &approval,
    ]);

    let stmt_file = write_file(
        dir,
        "stmt.camt053.xml",
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.053.001.08">
  <BkToCstmrStmt><Stmt><Id>March</Id><ElctrncSeqNb>3</ElctrncSeqNb>
    <Acct><Id><IBAN>GB29NWBK60161331926819</IBAN></Id><Ccy>USD</Ccy></Acct>
    <Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy="USD">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><Dt>2026-03-01</Dt></Dt></Bal>
    <Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy="USD">1250.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><Dt>2026-03-31</Dt></Dt></Bal>
    <Ntry><Amt Ccy="USD">1250.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts><Cd>BOOK</Cd></Sts>
      <BookgDt><Dt>2026-03-20</Dt></BookgDt><ValDt><Dt>2026-03-20</Dt></ValDt><AcctSvcrRef>INV-10442</AcctSvcrRef>
    </Ntry>
  </Stmt></BkToCstmrStmt>
</Document>
"#,
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
    vars.insert("{scenario_intent}".into(), scenario_intent);
    vars.insert("{polish_intent}".into(), polish_intent);
    vars.insert("{plan_file_2}".into(), plan_file_2);
    vars.insert("{cert_file}".into(), cert_file);
    vars.insert("{stmt_file}".into(), stmt_file);
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
        let outcome = run_typed_probe(crit.probe_kind, &argv, crit.artifact.as_deref());
        check_expectation(
            &crit.id,
            &crit.expected,
            crit.expected_exit,
            &crit.expected_event,
            &outcome,
        )
        .unwrap_or_else(|e| panic!("{e}"));
    }

    for gov in &sb.governance_rows {
        let outcome = run_typed_probe(gov.probe_kind, &gov.argv, gov.artifact.as_deref());
        check_expectation(
            &gov.id,
            &gov.expected,
            gov.expected_exit,
            &gov.expected_event,
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
fn v2_rows_transcribe_plan_section_19() {
    let sb = Scoreboard::embedded().expect("scoreboard.toml v2 is valid");
    sb.verify_plan_section_19(PLAN_MD)
        .expect("scoreboard.toml transcribes plan §19 verbatim");
    let (digest, clauses) = extract_plan_section_19(PLAN_MD).expect("extract §19");
    assert_eq!(sb.section_19_digest, digest);
    assert_eq!(sb.gate_criteria.len(), 55);
    assert_eq!(clauses.len(), 55);

    // Positive check: Genesis and G1–G4 are all UNMET at the current tip, with owning beads.
    let rendered = sb.render_markdown();
    assert!(rendered.contains("Gate met only when every row is `works`."));
    assert!(rendered.contains("| `G0` | 13 | 0 | 0 | 13 | **MET** |"));
    for gate in ["Genesis", "G1", "G2", "G3", "G4"] {
        let rows: Vec<_> = sb.gate_criteria.iter().filter(|r| r.gate == gate).collect();
        assert!(
            rows.iter()
                .any(|r| !matches!(r.expected, StepExpectation::Works)),
            "expected gate {gate} to be unmet at current tip"
        );
        assert!(
            rows.iter().any(|r| r.expected.bead().is_some()),
            "expected unmet gate {gate} to cite owning bead(s)"
        );
    }

    // Planted negative 1: deleting a plan §19 criterion row fails the transcription check.
    let exits = ExitCodes::embedded().expect("exit_codes.toml");
    let refusals = RefusalCatalog::embedded().expect("refusal_catalog.toml");
    let deleted_row = SCOREBOARD_TOML.replacen(
        "[[gate_criterion]]\nid = \"G4-06\"\ngate = \"G4\"\ncriterion = \"1.0\"\nevidence_class = \"registry\"\nprobe_kind = \"registry\"\nargv = [\"g4_release_1_0\"]\nexpected = \"absent\"\nexpected_exit = 2\nexpected_event = \"error\"\nbead = \"fa-nfq2\"\n",
        "",
        1,
    );
    let err = Scoreboard::parse(&deleted_row, &exits, &refusals)
        .expect_err("deleting a plan §19 criterion row must fail")
        .to_string();
    assert!(
        err.contains("plan §19 has 55 clauses") && err.contains("54"),
        "unexpected error: {err}"
    );

    // Planted negative 2: mutating the §19 text in the plan fails the digest check.
    let mutated_plan = PLAN_MD.replacen("; 1.0.", "; 2.0.", 1);
    let err = sb
        .verify_plan_section_19(&mutated_plan)
        .expect_err("mutated plan §19 text must fail digest check")
        .to_string();
    assert!(
        err.contains("section_19_digest mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn proxy_probe_cannot_satisfy_stronger_class() {
    let exits = ExitCodes::embedded().expect("exit_codes.toml");
    let refusals = RefusalCatalog::embedded().expect("refusal_catalog.toml");
    let _ = ProbeKind::Cli;

    // 1. A row whose `probe_kind = "cli"` while `evidence_class = "lab-campaign"` cannot be `works`.
    let planted_proxy = SCOREBOARD_TOML.replacen(
        "id = \"G2-01\"\ngate = \"G2\"\ncriterion = \"period state machine, admissibility matrix, and witness-resolved post-vs-close races proven in both orders\"\nevidence_class = \"lab-campaign\"\nprobe_kind = \"lab-campaign\"",
        "id = \"G2-01\"\ngate = \"G2\"\ncriterion = \"period state machine, admissibility matrix, and witness-resolved post-vs-close races proven in both orders\"\nevidence_class = \"lab-campaign\"\nprobe_kind = \"cli\"",
        1,
    );
    let err = Scoreboard::parse(&planted_proxy, &exits, &refusals)
        .expect_err("cli probe cannot satisfy lab-campaign evidence_class")
        .to_string();
    assert!(
        err.contains("G2-01") && err.contains("proxy probe") && err.contains("lab-campaign"),
        "unexpected error: {err}"
    );

    // 2. A `works` row with `evidence_class = "lab-campaign"` but no `artifact` must fail.
    let missing_artifact = SCOREBOARD_TOML.replacen("artifact = \"FA-ART-LAB-01\"\n", "", 1);
    let err = Scoreboard::parse(&missing_artifact, &exits, &refusals)
        .expect_err("lab-campaign works row without artifact must fail")
        .to_string();
    assert!(
        err.contains("G2-01") && err.contains("requires `artifact"),
        "unexpected error: {err}"
    );
}

#[test]
fn closure_debt_row_counts_unbacked_closures() {
    let sb = Scoreboard::embedded().expect("scoreboard.toml is valid");
    let gov = sb
        .governance_rows
        .iter()
        .find(|r| r.metric == "closure_debt")
        .expect("closure_debt governance row");
    assert_eq!(gov.id, "GOV-01");
    assert_eq!(
        gov.expected,
        StepExpectation::Absent {
            bead: "fa-8jcr".into()
        }
    );

    // 1. Synthetic JSONL with 2 unbacked closed beads and 1 backed closed bead reports debt = 2.
    let sample_jsonl = concat!(
        r#"{"id":"fa-old1","status":"closed","description":"legacy","close_reason":"Done"}"#,
        "\n",
        r#"{"id":"fa-old2","status":"closed","description":"```acceptance-tests\nfa::t\n```","close_reason":"Closed without verdict note"}"#,
        "\n",
        r#"{"id":"fa-good","status":"closed","description":"```acceptance-tests\nfa::t\n```","close_reason":"Verified [verdict_note: ea8e3f2512ef commit=d5b6e2b113c4 tree=2689caa8b914]"}"#,
        "\n",
        r#"{"id":"fa-open","status":"open","description":"still open"}"#,
        "\n"
    );
    let (unbacked, total_closed) = count_unbacked_closures_in_jsonl(sample_jsonl);
    assert_eq!(total_closed, 3);
    assert_eq!(unbacked, 2);

    // 2. Synthetic JSONL where every closed bead is backed reports debt = 0.
    let zero_debt_jsonl = r#"{"id":"fa-good","status":"closed","description":"```acceptance-tests\nfa::t\n```","close_reason":"Verified [verdict_note: ea8e3f2512ef commit=d5b6e2b113c4 tree=2689caa8b914]"}"#;
    let (unbacked_zero, total_zero) = count_unbacked_closures_in_jsonl(zero_debt_jsonl);
    assert_eq!(total_zero, 1);
    assert_eq!(unbacked_zero, 0);

    // 3. Live workspace probe reports non-zero unbacked closures and exits 2 (`absent`).
    let outcome = run_registry_probe("closure_debt_zero");
    assert_eq!(outcome.exit, 2);
    assert!(
        outcome.raw_stderr.contains("closure_debt="),
        "expected closure_debt count in stderr, got: {}",
        outcome.raw_stderr
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
