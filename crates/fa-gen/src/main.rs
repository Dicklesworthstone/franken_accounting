//! Test-only `fa-gen` CLI over the deterministic scenario generators (plan §15.3, bead `fa-8mae`).
//!
//! Subcommands:
//! - `fa-gen scenarios [--json]`
//! - `fa-gen book --scenario <name> [--seed <u64>] [--scale <usize>] [--out <dir>] [--json]`

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use fa_gen::{GenConfig, ScenarioKind, generate};

fn usage(msg: &str) -> ExitCode {
    eprintln!("fa-gen error: {msg}");
    eprintln!(
        "usage: fa-gen scenarios [--json] | fa-gen book --scenario <name> [--seed <u64>] [--scale <usize>] [--out <dir>] [--json]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        return usage("missing subcommand (`scenarios` or `book`)");
    }
    let json = args.iter().any(|a| a == "--json");
    match args[0].as_str() {
        "scenarios" => {
            if json {
                print!("{{\"event\":\"scenarios\",\"scenarios\":[");
                for (i, s) in ScenarioKind::ALL.iter().enumerate() {
                    if i > 0 {
                        print!(",");
                    }
                    print!(
                        "{{\"slug\":\"{}\",\"alias\":\"{}\",\"title\":\"{}\"}}",
                        s.slug(),
                        s.short_alias(),
                        s.title()
                    );
                }
                println!("]}}");
            } else {
                for s in ScenarioKind::ALL {
                    println!(
                        "{:<24} (alias: {:<13}) — {}",
                        s.slug(),
                        s.short_alias(),
                        s.title()
                    );
                }
            }
            ExitCode::SUCCESS
        }
        "book" => {
            let mut scenario_name: Option<String> = None;
            let mut seed: u64 = 7;
            let mut scale: usize = 1;
            let mut out_dir: Option<PathBuf> = None;
            let mut i = 1usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--json" => {
                        i += 1;
                    }
                    "--scenario" => {
                        let Some(val) = args.get(i + 1) else {
                            return usage("--scenario requires a scenario name");
                        };
                        scenario_name = Some(val.clone());
                        i += 2;
                    }
                    "--seed" => {
                        let Some(val) = args.get(i + 1) else {
                            return usage("--seed requires an integer");
                        };
                        let Ok(parsed) = val.parse::<u64>() else {
                            return usage("--seed must be an unsigned 64-bit integer");
                        };
                        seed = parsed;
                        i += 2;
                    }
                    "--scale" => {
                        let Some(val) = args.get(i + 1) else {
                            return usage("--scale requires a positive integer");
                        };
                        let Ok(parsed) = val.parse::<usize>() else {
                            return usage("--scale must be a positive integer");
                        };
                        if parsed == 0 {
                            return usage("--scale must be >= 1");
                        }
                        scale = parsed;
                        i += 2;
                    }
                    "--out" => {
                        let Some(val) = args.get(i + 1) else {
                            return usage("--out requires a directory path");
                        };
                        out_dir = Some(PathBuf::from(val));
                        i += 2;
                    }
                    other => {
                        return usage(&format!("unknown flag `{other}`"));
                    }
                }
            }
            let Some(name) = scenario_name else {
                return usage("--scenario <name> is required");
            };
            let Some(scenario) = ScenarioKind::from_name(&name) else {
                let valid: Vec<&str> = ScenarioKind::ALL.iter().map(|s| s.slug()).collect();
                return usage(&format!(
                    "unknown scenario `{name}`; valid scenarios: {}",
                    valid.join(", ")
                ));
            };
            let corpus = generate(GenConfig::new(scenario, seed).with_scale(scale));
            if let Some(dir) = &out_dir {
                if let Err(e) = fs::create_dir_all(dir) {
                    eprintln!("fa-gen error: cannot create {}: {e}", dir.display());
                    return ExitCode::from(4);
                }
                let labels_path = dir.join("labels.json");
                let readme_path = dir.join("README.md");
                if let Err(e) = fs::write(&labels_path, corpus.render_labels_json()) {
                    eprintln!("fa-gen error: cannot write {}: {e}", labels_path.display());
                    return ExitCode::from(4);
                }
                if let Err(e) = fs::write(&readme_path, corpus.render_readme()) {
                    eprintln!("fa-gen error: cannot write {}: {e}", readme_path.display());
                    return ExitCode::from(4);
                }
            }
            if json {
                print!("{}", corpus.render_labels_json());
            } else {
                print!("{}", corpus.render_readme());
            }
            ExitCode::SUCCESS
        }
        other => usage(&format!("unknown subcommand `{other}`")),
    }
}
