//! `xtask` — deterministic registry/topology inspection and developer helper binary
//! (plan §18.1–§18.2, beads `fa-ad8d`, `fa-9km9`).

#![forbid(unsafe_code)]

mod reachability;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fa_registry::foundations::Ledger;
use fa_registry::invariants::Invariants;
use fa_registry::mutants::{MutantLedger, MutationManifest, TestOutcome};
use fa_registry::procedures::Procedures;
use fa_registry::refusal_catalog::RefusalCatalog;
use fa_registry::scoreboard::Scoreboard;
use fa_registry::topology::Topology;
use fa_registry::unwired_modules::UnwiredModules;
use fa_registry::{EntryClasses, ExitCodes, rounding_laws_embedded, units_embedded};

fn default_workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

pub fn render_summary(json: bool) -> Result<String, String> {
    let topo = Topology::embedded().map_err(|e| e.to_string())?;
    let inv = Invariants::embedded().map_err(|e| e.to_string())?;
    let refusals = RefusalCatalog::embedded().map_err(|e| e.to_string())?;
    let classes = EntryClasses::embedded().map_err(|e| e.to_string())?;
    let exits = ExitCodes::embedded().map_err(|e| e.to_string())?;
    let units = units_embedded().map_err(|e| e.to_string())?;
    let rounding = rounding_laws_embedded().map_err(|e| e.to_string())?;
    let procedures = Procedures::embedded().map_err(|e| e.to_string())?;
    let foundations = Ledger::embedded().map_err(|e| e.to_string())?;
    let scoreboard = Scoreboard::embedded().map_err(|e| e.to_string())?;
    let mutants = MutantLedger::embedded().map_err(|e| e.to_string())?;

    let live_crates = topo.crates.iter().filter(|c| !c.planned).count();
    let planned_crates = topo.crates.iter().filter(|c| c.planned).count();
    let live_clauses = inv.clauses.iter().filter(|c| c.is_live()).count();
    let g1_live = inv
        .clauses
        .iter()
        .filter(|c| c.first_gate == "G1" && c.is_live())
        .count();

    if json {
        Ok(format!(
            "{{\"crates_total\":{},\"crates_live\":{},\"crates_planned\":{},\"invariants\":{},\"clauses_total\":{},\"clauses_live\":{},\"gate_g1_live\":{},\"gate_g1_total\":{},\"refusals\":{},\"entry_classes\":{},\"exit_codes\":{},\"units\":{},\"rounding_laws\":{},\"procedures\":{},\"foundations\":{},\"workflow_steps\":{},\"gate_criteria\":{},\"mutants\":{}}}",
            topo.crates.len(),
            live_crates,
            planned_crates,
            inv.invariants.len(),
            inv.clauses.len(),
            live_clauses,
            g1_live,
            inv.gate_g1.len(),
            refusals.rows.len(),
            classes.rows.len(),
            exits.rows.len(),
            units.len(),
            rounding.len(),
            procedures.rows.len(),
            foundations.capabilities.len(),
            scoreboard.steps.len(),
            scoreboard.gate_criteria.len(),
            mutants.mutants.len(),
        ))
    } else {
        Ok(format!(
            "FrankenAccounting Workspace Registry Summary\n  crates:       {} total ({} live, {} planned across {} layers)\n  invariants:   {} invariants, {}/{} clauses live (Gate G1: {}/{})\n  refusals:     {} active ({} reserved)\n  entry_classes: {}\n  exit_codes:   {}\n  units:        {}\n  rounding_laws: {}\n  procedures:   {}\n  foundations:  {}\n  scoreboard:   {} workflow steps, {} gate criteria\n  mutants:      {} named kernel-law mutations",
            topo.crates.len(),
            live_crates,
            planned_crates,
            topo.layers.len(),
            inv.invariants.len(),
            live_clauses,
            inv.clauses.len(),
            g1_live,
            inv.gate_g1.len(),
            refusals.rows.len(),
            refusals.reserved.len(),
            classes.rows.len(),
            exits.rows.len(),
            units.len(),
            rounding.len(),
            procedures.rows.len(),
            foundations.capabilities.len(),
            scoreboard.steps.len(),
            scoreboard.gate_criteria.len(),
            mutants.mutants.len(),
        ))
    }
}

/// Anchor the ledger without executing it: every `find` occurs exactly once
/// in its file. Returns the number of mutants anchored.
pub fn anchor_workspace_mutants(root: &Path) -> Result<usize, String> {
    let ledger = MutantLedger::embedded().map_err(|e| e.to_string())?;
    ledger.verify_against_workspace(|rel| fs::read_to_string(root.join(rel)).ok())?;
    Ok(ledger.mutants.len())
}

/// The mutation lane judged from an execution record: `results` maps each
/// mutant id to the verdict `scripts/mutants_execute.sh --results` recorded.
/// Only a recorded `KILLED` kills; a `SURVIVED`, `UNRUN` or missing record
/// survives, so the lane never credits a kill nobody ran.
pub fn evaluate_workspace_mutants(
    root: &Path,
    results: &BTreeMap<String, String>,
) -> Result<MutationManifest, String> {
    let ledger = MutantLedger::embedded().map_err(|e| e.to_string())?;
    ledger.verify_against_workspace(|rel| fs::read_to_string(root.join(rel)).ok())?;
    ledger.enforce_lane(
        |mutant, _checker| match results.get(&mutant.id).map(String::as_str) {
            Some("KILLED") => TestOutcome::Killed,
            _ => TestOutcome::Survived,
        },
    )
}

/// Parse an execution record: one `<MUT-id> KILLED|SURVIVED|UNRUN` per line.
fn parse_mutant_results(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut results = BTreeMap::new();
    for (n, line) in text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
    {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [id, verdict] = fields[..] else {
            return Err(format!("xtask: results line {}: `{line}`", n + 1));
        };
        if !matches!(verdict, "KILLED" | "SURVIVED" | "UNRUN") {
            return Err(format!(
                "xtask: results line {}: verdict `{verdict}`",
                n + 1
            ));
        }
        if results
            .insert(id.to_string(), verdict.to_string())
            .is_some()
        {
            return Err(format!(
                "xtask: results line {}: `{id}` recorded twice",
                n + 1
            ));
        }
    }
    Ok(results)
}

fn run() -> Result<(), String> {
    let mut json = false;
    let mut mode = "summary";
    let mut manifest_path: Option<PathBuf> = None;
    let mut results_path: Option<PathBuf> = None;
    let mut today: Option<String> = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "summary" | "status" => mode = "summary",
            "scoreboard" => mode = "scoreboard",
            "mutants" => mode = "mutants",
            "reachability" => mode = "reachability",
            "--today" => {
                let d = args
                    .next()
                    .ok_or_else(|| "xtask: --today requires a YYYY-MM-DD date".to_string())?;
                if fa_registry::unwired_modules::parse_date(&d).is_none() {
                    return Err(format!("xtask: --today `{d}` is not a YYYY-MM-DD date"));
                }
                today = Some(d);
            }
            "--manifest" => {
                let p = args
                    .next()
                    .ok_or_else(|| "xtask: --manifest requires a file path".to_string())?;
                manifest_path = Some(PathBuf::from(p));
            }
            "--results" => {
                let p = args
                    .next()
                    .ok_or_else(|| "xtask: --results requires a file path".to_string())?;
                results_path = Some(PathBuf::from(p));
            }
            "--json" => json = true,
            "-h" | "--help" => {
                println!(
                    "Usage: xtask [summary|scoreboard|mutants|reachability] [--manifest <path>] [--results <path>] [--today YYYY-MM-DD] [--json]"
                );
                return Ok(());
            }
            other => return Err(format!("xtask: unknown argument `{other}`")),
        }
    }
    if mode == "scoreboard" {
        let sb = Scoreboard::embedded().map_err(|e| e.to_string())?;
        print!("{}", sb.render_markdown());
        return Ok(());
    }
    if mode == "reachability" {
        return run_reachability(today.unwrap_or_else(reachability::utc_today));
    }
    if mode == "mutants" {
        let root = default_workspace_root();
        let Some(results_path) = results_path else {
            let anchored = anchor_workspace_mutants(&root)?;
            println!(
                "xtask mutants: {anchored} mutants anchored (each `find` occurs once in its file); none executed: `scripts/mutants_execute.sh --results <file>` executes them, then `xtask mutants --results <file>` judges the record"
            );
            return Ok(());
        };
        let record = fs::read_to_string(&results_path)
            .map_err(|e| format!("{}: {e}", results_path.display()))?;
        let manifest = evaluate_workspace_mutants(&root, &parse_mutant_results(&record)?)?;
        let payload = manifest.to_json();
        if let Some(path) = manifest_path {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
            }
            fs::write(&path, format!("{payload}\n"))
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
        if json {
            println!("{payload}");
        } else {
            println!(
                "xtask mutants: ok ({}/{} killed by execution, 0 survivors)",
                manifest.killed, manifest.total
            );
        }
        return Ok(());
    }
    let out = render_summary(json)?;
    println!("{out}");
    Ok(())
}

/// `xtask reachability`: the report on stdout; every failure, the expiry
/// check against `today` included, as a `FAIL ` line and exit 2 (fa-2ioe).
fn run_reachability(today: String) -> Result<(), String> {
    let root = default_workspace_root();
    let crates = reachability::workspace_crates()?;
    let read = |p: &str| fs::read_to_string(root.join(p)).ok();
    let modules = reachability::analyze(&crates, &read);
    let registry = UnwiredModules::embedded().map_err(|e| e.to_string())?;
    print!("{}", reachability::render(&modules, &registry));
    let fails = reachability::check(&modules, &registry, &read, Some(today.as_str()));
    if fails.is_empty() {
        println!("xtask reachability: ok (as of {today})");
        Ok(())
    } else {
        Err(fails
            .iter()
            .map(|f| format!("FAIL {f}"))
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_is_deterministic_in_text_and_json() {
        let a = render_summary(false).expect("text summary");
        let b = render_summary(false).expect("text summary");
        assert_eq!(a, b);
        assert!(a.contains("Gate G1: 18/18"));
        assert!(a.contains("named kernel-law mutations"));

        let j = render_summary(true).expect("json summary");
        assert!(j.contains("\"gate_g1_live\":18,\"gate_g1_total\":18"));
        assert!(j.contains("\"mutants\":38"));
    }

    #[test]
    fn workspace_mutants_manifest_is_green_and_deterministic() {
        let root = default_workspace_root();
        assert_eq!(anchor_workspace_mutants(&root).expect("anchored"), 38);
        let ids = MutantLedger::embedded().expect("ledger").mutants;
        let all_killed: BTreeMap<String, String> = ids
            .iter()
            .map(|m| (m.id.clone(), "KILLED".to_string()))
            .collect();
        let m1 = evaluate_workspace_mutants(&root, &all_killed).expect("mutants lane");
        let m2 = evaluate_workspace_mutants(&root, &all_killed).expect("mutants lane");
        assert_eq!(m1, m2);
        assert!(m1.is_green());
        assert_eq!(m1.total, 38);
        assert_eq!(m1.killed, 38);
        assert!(m1.survivors.is_empty());
        assert_eq!(m1.to_json(), m2.to_json());
    }

    /// Only a recorded kill kills: a survivor, an unrun mutant and a mutant
    /// with no record each fail the lane by name.
    #[test]
    fn an_execution_record_decides_each_kill() {
        let root = default_workspace_root();
        let ids: Vec<String> = MutantLedger::embedded()
            .expect("ledger")
            .mutants
            .into_iter()
            .map(|m| m.id)
            .collect();
        let record: String = ids.iter().map(|id| format!("{id} KILLED\n")).collect();
        let killed = parse_mutant_results(&record).expect("record");
        assert!(evaluate_workspace_mutants(&root, &killed).is_ok());
        for verdict in ["SURVIVED", "UNRUN", "missing"] {
            let mut results = killed.clone();
            if verdict == "missing" {
                results.remove(&ids[3]);
            } else {
                results.insert(ids[3].clone(), verdict.to_string());
            }
            let err = evaluate_workspace_mutants(&root, &results).expect_err(verdict);
            assert!(err.contains(&ids[3]), "{verdict}: {err}");
        }
        for bad in [
            "MUT-001",
            "MUT-001 KILLED extra",
            "MUT-001 DEAD",
            "MUT-001 KILLED\nMUT-001 KILLED",
        ] {
            assert!(parse_mutant_results(bad).is_err(), "{bad:?}");
        }
    }
}
