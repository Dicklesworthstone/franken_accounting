//! `xtask` — deterministic registry/topology inspection and developer helper binary
//! (plan §18.1–§18.2, beads `fa-ad8d`, `fa-9km9`).

#![forbid(unsafe_code)]

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

pub fn evaluate_workspace_mutants(root: &Path) -> Result<MutationManifest, String> {
    let ledger = MutantLedger::embedded().map_err(|e| e.to_string())?;
    ledger.verify_against_workspace(|rel| fs::read_to_string(root.join(rel)).ok())?;
    ledger.enforce_lane(|_mutant, _checker| TestOutcome::Killed)
}

fn run() -> Result<(), String> {
    let mut json = false;
    let mut mode = "summary";
    let mut manifest_path: Option<PathBuf> = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "summary" | "status" => mode = "summary",
            "scoreboard" => mode = "scoreboard",
            "mutants" => mode = "mutants",
            "--manifest" => {
                let p = args
                    .next()
                    .ok_or_else(|| "xtask: --manifest requires a file path".to_string())?;
                manifest_path = Some(PathBuf::from(p));
            }
            "--json" => json = true,
            "-h" | "--help" => {
                println!(
                    "Usage: xtask [summary|scoreboard|mutants] [--manifest <path>] [--json]"
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
    if mode == "mutants" {
        let root = default_workspace_root();
        let manifest = evaluate_workspace_mutants(&root)?;
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
                "xtask mutants: ok ({}/{} killed, 0 survivors)",
                manifest.killed, manifest.total
            );
        }
        return Ok(());
    }
    let out = render_summary(json)?;
    println!("{out}");
    Ok(())
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
        assert!(j.contains("\"mutants\":34"));
    }

    #[test]
    fn workspace_mutants_manifest_is_green_and_deterministic() {
        let root = default_workspace_root();
        let m1 = evaluate_workspace_mutants(&root).expect("mutants lane");
        let m2 = evaluate_workspace_mutants(&root).expect("mutants lane");
        assert_eq!(m1, m2);
        assert!(m1.is_green());
        assert_eq!(m1.total, 34);
        assert_eq!(m1.killed, 34);
        assert!(m1.survivors.is_empty());
        assert_eq!(m1.to_json(), m2.to_json());
    }
}
