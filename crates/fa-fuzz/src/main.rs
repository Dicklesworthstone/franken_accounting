#![forbid(unsafe_code)]
//! CLI smoke runner for `fa-fuzz` (`cargo run -p fa-fuzz` or `cargo test -p fa-fuzz`).

use fa_fuzz::{DORMANT_TARGETS, LIVE_TARGETS, run_all_smoke, run_target_smoke};

fn main() {
    let mut args = std::env::args().skip(1);
    let mut mutations_per_seed = 64usize;
    let mut selected_target: Option<String> = None;
    let mut json = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--mutations" => {
                let raw = args.next().unwrap_or_else(|| {
                    eprintln!("--mutations requires a count");
                    std::process::exit(2);
                });
                mutations_per_seed = raw.parse().unwrap_or_else(|_| {
                    eprintln!("--mutations must be a positive integer");
                    std::process::exit(2);
                });
            }
            "--target" => {
                selected_target = Some(args.next().unwrap_or_else(|| {
                    eprintln!("--target requires a target name");
                    std::process::exit(2);
                }));
            }
            "--list" => {
                for t in LIVE_TARGETS {
                    println!("live\t{}\t{}", t.name, t.description);
                }
                for d in DORMANT_TARGETS {
                    println!(
                        "dormant\t{}\t(activates on {})\t{}",
                        d.name, d.activating_bead, d.description
                    );
                }
                return;
            }
            other => {
                eprintln!(
                    "unknown argument `{other}`; use --target <name>, --mutations <n>, --json, or --list"
                );
                std::process::exit(2);
            }
        }
    }

    if let Some(name) = selected_target {
        let Some(target) = LIVE_TARGETS.iter().find(|t| t.name == name) else {
            eprintln!("unknown live fuzz target `{name}`");
            std::process::exit(2);
        };
        let (seeds, mutated) = run_target_smoke(target, mutations_per_seed);
        if json {
            println!(
                "{{\"event\":\"fuzz_smoke\",\"status\":\"ok\",\"target\":\"{}\",\"seeds\":{},\"mutated\":{}}}",
                target.name, seeds, mutated
            );
        } else {
            println!(
                "fa-fuzz-smoke: target={} seeds={} mutated={} status=ok",
                target.name, seeds, mutated
            );
        }
    } else {
        let summary = run_all_smoke(mutations_per_seed);
        if json {
            println!(
                "{{\"event\":\"fuzz_smoke\",\"status\":\"ok\",\"targets\":{},\"seeds\":{},\"mutated\":{},\"dormant\":{}}}",
                summary.targets_run,
                summary.corpus_inputs,
                summary.mutated_inputs,
                DORMANT_TARGETS.len()
            );
        } else {
            println!(
                "fa-fuzz-smoke: targets={} seeds={} mutated={} dormant={} status=ok",
                summary.targets_run,
                summary.corpus_inputs,
                summary.mutated_inputs,
                DORMANT_TARGETS.len()
            );
        }
    }
}
