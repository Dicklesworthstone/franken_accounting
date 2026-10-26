//! `fa-bench` CLI: verifies §17 manifests (`bench/manifests/*.toml`) and the
//! counted kernel operation witnesses against `registries/operation_costs.toml`
//! (beads `fa-tu58`, `fa-i5s`), and reports each §17 benchmark as measured or
//! unmeasured. No §17 benchmark is reported measured yet (fa-e75k, fa-ykbp):
//! `fa-bench sample register_rebuild` times the first real workload's raw
//! samples, with no incumbent and so no §17 verdict.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use fa_bench::driver::{Drive, drive};
use fa_bench::{
    BenchOutcome, load_embedded_manifests, run_all_benchmarks, run_benchmark,
    verify_all_kernel_op_witnesses,
};

fn usage() {
    eprintln!(
        "usage: fa-bench [--smoke] [--bench <name>] [--verify-manifests] [--verify-op-costs] [--json]\n       fa-bench --bench <name> --incumbent <previous fa-bench> [--worker-class <class>] [--legs <n>] [--rounds <n>] [--json]\n       fa-bench sample register_rebuild --legs <even count> [--rounds <n>] [--seed <n>]"
    );
}

/// `fa-bench sample register_rebuild --legs N [--rounds R] [--seed S]`: post
/// a book of N legs, then time R full register rebuilds, each digest-equal
/// to the maintained registers. One JSON line carries the raw samples and
/// the engine's legs-folded witness (fa-ykbp); no §17 verdict is drawn here.
fn sample(args: &[String]) -> ExitCode {
    let flag = |name: &str, default: Option<u64>| -> Result<u64, String> {
        match args.iter().position(|a| a == name) {
            Some(i) => args
                .get(i + 1)
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| format!("{name} takes a non-negative integer")),
            None => default.ok_or_else(|| format!("{name} is required")),
        }
    };
    if args.first().map(String::as_str) != Some("register_rebuild") {
        eprintln!("fa-bench: sample runs one workload: register_rebuild");
        usage();
        return ExitCode::from(2);
    }
    let known = ["--legs", "--rounds", "--seed"];
    if let Some(odd) = args[1..]
        .iter()
        .step_by(2)
        .find(|a| !known.contains(&a.as_str()))
    {
        eprintln!(
            "fa-bench: sample register_rebuild takes --legs, --rounds and --seed, not `{odd}`"
        );
        return ExitCode::from(2);
    }
    let (legs, rounds, seed) = match (
        flag("--legs", None),
        flag("--rounds", Some(10)),
        flag("--seed", Some(42)),
    ) {
        (Ok(legs), Ok(rounds), Ok(seed)) if rounds > 0 => (legs, rounds, seed),
        (Err(why), ..) | (_, Err(why), _) | (.., Err(why)) => {
            eprintln!("fa-bench: {why}");
            return ExitCode::from(2);
        }
        _ => {
            eprintln!("fa-bench: --rounds must be at least 1");
            return ExitCode::from(2);
        }
    };
    let mut book = match fa_bench::rebuild::build(legs, seed) {
        Ok(book) => book,
        Err(e) => {
            eprintln!("fa-bench: {e}");
            return ExitCode::from(3);
        }
    };
    let mut samples = Vec::new();
    let mut counted = 0;
    for _ in 0..rounds {
        match book.rebuild() {
            Ok(run) if run.legs_folded == book.legs_posted => {
                counted = run.legs_folded;
                samples.push(run.elapsed_us);
            }
            Ok(run) => {
                eprintln!(
                    "fa-bench: a rebuild folded {} legs of the {} posted; no sample is drawn from it",
                    run.legs_folded, book.legs_posted
                );
                return ExitCode::from(3);
            }
            Err(e) => {
                eprintln!("fa-bench: {e}");
                return ExitCode::from(3);
            }
        }
    }
    let list: Vec<String> = samples.iter().map(u64::to_string).collect();
    println!(
        "{{\"event\":\"bench_samples\",\"workload\":\"register_rebuild\",\"seed\":{seed},\"legs_posted\":{},\"witness\":{{\"counter\":\"legs_folded\",\"counted\":{}}},\"samples_us\":[{}]}}",
        book.legs_posted,
        counted,
        list.join(",")
    );
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("sample") {
        return sample(&argv[1..]);
    }
    let mut smoke = false;
    let mut json = false;
    let mut verify_manifests_only = false;
    let mut verify_op_costs_only = false;
    let mut target_bench: Option<String> = None;
    let mut incumbent: Option<String> = None;
    let mut worker_class: Option<String> = None;
    let mut scale: Option<u64> = None;
    let mut rounds: u64 = 10;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--smoke" => smoke = true,
            "--json" => json = true,
            "--verify-manifests" => verify_manifests_only = true,
            "--verify-op-costs" => verify_op_costs_only = true,
            "--bench" | "--incumbent" | "--worker-class" | "--legs" | "--rounds" => {
                let Some(val) = args.next() else {
                    eprintln!("fa-bench: {arg} requires a value");
                    usage();
                    return ExitCode::from(2);
                };
                let number = || {
                    val.parse::<u64>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or_else(|| format!("{arg} takes a positive integer, not `{val}`"))
                };
                match arg.as_str() {
                    "--bench" => target_bench = Some(val.clone()),
                    "--incumbent" => incumbent = Some(val.clone()),
                    "--worker-class" => worker_class = Some(val.clone()),
                    "--legs" => match number() {
                        Ok(n) => scale = Some(n),
                        Err(why) => {
                            eprintln!("fa-bench: {why}");
                            return ExitCode::from(2);
                        }
                    },
                    _ => match number() {
                        Ok(n) => rounds = n,
                        Err(why) => {
                            eprintln!("fa-bench: {why}");
                            return ExitCode::from(2);
                        }
                    },
                }
            }
            "-h" | "--help" => {
                usage();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("fa-bench: unknown argument `{other}`");
                usage();
                return ExitCode::from(2);
            }
        }
    }

    let manifests = match load_embedded_manifests() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("fa-bench: manifest verification failed: {e}");
            return ExitCode::from(3);
        }
    };

    // A driven run judges one bench against its incumbent; it does not
    // re-verify the operation-cost witnesses, and its summary says 0.
    let driving = incumbent.is_some() || worker_class.is_some() || scale.is_some();
    if driving && (verify_manifests_only || verify_op_costs_only) {
        eprintln!("fa-bench: --verify-manifests and --verify-op-costs do not drive a bench");
        return ExitCode::from(2);
    }
    let witnesses = if driving {
        Vec::new()
    } else {
        match verify_all_kernel_op_witnesses() {
            Ok(w) => w,
            Err(e) => {
                eprintln!("fa-bench: operation-cost witness verification failed: {e}");
                return ExitCode::from(3);
            }
        }
    };

    if verify_manifests_only {
        if json {
            println!(
                "{{\"event\":\"manifests_verified\",\"count\":{}}}",
                manifests.len()
            );
        } else {
            println!(
                "fa-bench: verified {} §17 baseline manifests",
                manifests.len()
            );
        }
        return ExitCode::SUCCESS;
    }

    if verify_op_costs_only {
        if json {
            println!(
                "{{\"event\":\"op_costs_verified\",\"count\":{}}}",
                witnesses.len()
            );
        } else {
            println!(
                "fa-bench: verified {} kernel operation witnesses",
                witnesses.len()
            );
        }
        return ExitCode::SUCCESS;
    }

    let outcomes = match target_bench {
        // A driven run (fa-ykbp): this binary and the incumbent, judged.
        Some(ref name) if driving => {
            let candidate = match std::env::current_exe() {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("fa-bench: cannot locate this binary: {e}");
                    return ExitCode::from(4);
                }
            };
            let class = worker_class
                .or_else(|| std::env::var("FA_BENCH_WORKER_CLASS").ok())
                .unwrap_or_else(|| "dev".to_string());
            match drive(&Drive {
                bench: name,
                candidate: &candidate,
                incumbent: incumbent.as_deref().map(std::path::Path::new),
                worker_class: &class,
                scale,
                rounds,
            }) {
                Ok(o) => vec![o],
                Err(e) => {
                    eprintln!("fa-bench: {e}");
                    return ExitCode::from(3);
                }
            }
        }
        None if driving => {
            eprintln!(
                "fa-bench: --incumbent, --worker-class and --legs drive one bench; name it with --bench"
            );
            return ExitCode::from(2);
        }
        Some(ref name) => match run_benchmark(name, smoke) {
            Ok(o) => vec![o],
            Err(e) => {
                eprintln!("fa-bench: {e}");
                return ExitCode::from(3);
            }
        },
        None => match run_all_benchmarks(smoke) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("fa-bench: {e}");
                return ExitCode::from(3);
            }
        },
    };
    let measured = outcomes
        .iter()
        .filter(|o| matches!(o, BenchOutcome::Measured(_)))
        .count();
    let unmeasured = outcomes.len() - measured;

    if json {
        for o in &outcomes {
            println!("{}", o.to_json_line());
        }
        println!(
            "{{\"event\":\"bench_summary\",\"measured\":{measured},\"unmeasured\":{unmeasured},\"witnesses_verified\":{},\"manifests_verified\":{},\"smoke\":{smoke}}}",
            witnesses.len(),
            manifests.len(),
        );
    } else {
        for o in &outcomes {
            match o {
                BenchOutcome::Measured(r) => println!(
                    "{:<12} {:<30} p50={}us p95={}us p99={}us",
                    r.manifest.slo_id,
                    r.manifest.bench_name,
                    r.candidate.p50_us,
                    r.candidate.p95_us,
                    r.candidate.p99_us
                ),
                BenchOutcome::Unmeasured {
                    slo_id,
                    bench_name,
                    reason,
                } => println!("{slo_id:<12} {bench_name:<30} UNMEASURED: {reason}"),
            }
        }
        println!(
            "fa-bench: {measured} measured, {unmeasured} unmeasured §17 benchmarks; {} manifests and {} kernel op witnesses verified",
            manifests.len(),
            witnesses.len()
        );
    }

    ExitCode::SUCCESS
}
