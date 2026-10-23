#![forbid(unsafe_code)]
//! CLI smoke runner for `fa-fuzz` (`cargo run -p fa-fuzz` or `cargo test -p fa-fuzz`).
//! With `--crash-dir <dir>` each target runs as a catching campaign: the first
//! panic is minimized and written there with its replay command;
//! `--target <name> --replay <file>` reruns one input.

use fa_fuzz::{
    DORMANT_TARGETS, FuzzTarget, LIVE_TARGETS, run_all_smoke, run_target_campaign, run_target_smoke,
};

/// Ddmin's budget of target runs per crash.
const MINIMIZE_BUDGET: usize = 4096;

/// Run `targets` as catching campaigns. On the first crash, write the input
/// and its minimized reproducer into `dir` and exit 1 with the replay
/// command.
fn campaign(targets: &[&FuzzTarget], mutations_per_seed: usize, dir: &str, json: bool) {
    let (mut seeds, mut mutated) = (0usize, 0usize);
    for target in targets {
        match run_target_campaign(target, mutations_per_seed, MINIMIZE_BUDGET) {
            Ok((s, m)) => {
                seeds += s;
                mutated += m;
            }
            Err(crash) => {
                let write = |name: String, bytes: &[u8]| {
                    let path = std::path::Path::new(dir).join(name);
                    std::fs::create_dir_all(dir)
                        .and_then(|()| std::fs::write(&path, bytes))
                        .unwrap_or_else(|e| {
                            eprintln!("cannot write {}: {e}", path.display());
                            std::process::exit(2);
                        });
                    path.display().to_string()
                };
                let input = write(format!("{}-input.bin", crash.target), &crash.input);
                let minimized = write(format!("{}-min.bin", crash.target), &crash.minimized);
                let replay = format!(
                    "fa_fuzz_smoke --target {} --replay {minimized}",
                    crash.target
                );
                if json {
                    println!(
                        "{{\"event\":\"fuzz_crash\",\"target\":\"{}\",\"input_len\":{},\"minimized_len\":{},\"input\":\"{input}\",\"minimized\":\"{minimized}\",\"replay\":\"{replay}\"}}",
                        crash.target,
                        crash.input.len(),
                        crash.minimized.len()
                    );
                } else {
                    println!(
                        "fa-fuzz-smoke: CRASH target={} input={input} ({} bytes) minimized={minimized} ({} bytes); replay: {replay}",
                        crash.target,
                        crash.input.len(),
                        crash.minimized.len()
                    );
                }
                std::process::exit(1);
            }
        }
    }
    if json {
        println!(
            "{{\"event\":\"fuzz_smoke\",\"status\":\"ok\",\"targets\":{},\"seeds\":{seeds},\"mutated\":{mutated}}}",
            targets.len()
        );
    } else {
        println!(
            "fa-fuzz-smoke: targets={} seeds={seeds} mutated={mutated} status=ok",
            targets.len()
        );
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut mutations_per_seed = 64usize;
    let mut selected_target: Option<String> = None;
    let mut json = false;
    let mut crash_dir: Option<String> = None;
    let mut replay: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--crash-dir" => {
                crash_dir = Some(args.next().unwrap_or_else(|| {
                    eprintln!("--crash-dir requires a directory");
                    std::process::exit(2);
                }));
            }
            "--replay" => {
                replay = Some(args.next().unwrap_or_else(|| {
                    eprintln!("--replay requires an input file");
                    std::process::exit(2);
                }));
            }
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
                    "unknown argument `{other}`; use --target <name>, --mutations <n>, --crash-dir <dir>, --replay <file>, --json, or --list"
                );
                std::process::exit(2);
            }
        }
    }

    let live = |name: &str| {
        LIVE_TARGETS
            .iter()
            .find(|t| t.name == name)
            .unwrap_or_else(|| {
                eprintln!("unknown live fuzz target `{name}`");
                std::process::exit(2);
            })
    };
    if let Some(file) = replay {
        let Some(name) = selected_target.as_deref() else {
            eprintln!("--replay needs --target <name>");
            std::process::exit(2);
        };
        let target = live(name);
        let bytes = std::fs::read(&file).unwrap_or_else(|e| {
            eprintln!("cannot read {file}: {e}");
            std::process::exit(2);
        });
        // A panic here is the reproduced crash: it exits non-zero with its message.
        (target.run)(&bytes);
        println!(
            "fa-fuzz-smoke: target={} replay={file} ({} bytes) status=ok",
            target.name,
            bytes.len()
        );
        return;
    }
    if let Some(dir) = crash_dir {
        let targets: Vec<&FuzzTarget> = match selected_target.as_deref() {
            Some(name) => vec![live(name)],
            None => LIVE_TARGETS.iter().collect(),
        };
        campaign(&targets, mutations_per_seed, &dir, json);
        return;
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
