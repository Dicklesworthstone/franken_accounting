//! `fa-bench` CLI: runs §17 benchmark distributions, verifies baseline manifests
//! (`bench/manifests/*.toml`), and checks counted kernel operation witnesses
//! against `registries/operation_costs.toml` (beads `fa-tu58`, `fa-i5s`).

#![forbid(unsafe_code)]

use std::process::ExitCode;

use fa_bench::{
    load_embedded_manifests, run_all_benchmarks, run_benchmark, verify_all_kernel_op_witnesses,
};

fn usage() {
    eprintln!(
        "usage: fa-bench [--smoke] [--bench <name>] [--verify-manifests] [--verify-op-costs] [--json]"
    );
}

fn main() -> ExitCode {
    let mut smoke = false;
    let mut json = false;
    let mut verify_manifests_only = false;
    let mut verify_op_costs_only = false;
    let mut target_bench: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--smoke" => smoke = true,
            "--json" => json = true,
            "--verify-manifests" => verify_manifests_only = true,
            "--verify-op-costs" => verify_op_costs_only = true,
            "--bench" => {
                let Some(val) = args.next() else {
                    eprintln!("fa-bench: --bench requires a benchmark name or SLO ID");
                    usage();
                    return ExitCode::from(2);
                };
                target_bench = Some(val);
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

    let witnesses = match verify_all_kernel_op_witnesses() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("fa-bench: operation-cost witness verification failed: {e}");
            return ExitCode::from(3);
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

    let reports = match target_bench {
        Some(ref name) => match run_benchmark(name, smoke) {
            Ok(r) => vec![r],
            Err(e) => {
                eprintln!("fa-bench: {e}");
                return ExitCode::from(3);
            }
        },
        None => match run_all_benchmarks(smoke) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("fa-bench: {e}");
                return ExitCode::from(3);
            }
        },
    };

    if json {
        for r in &reports {
            println!("{}", r.to_json_line());
        }
        println!(
            "{{\"event\":\"bench_summary\",\"benchmarks\":{},\"witnesses_verified\":{},\"manifests_verified\":{},\"smoke\":{}}}",
            reports.len(),
            witnesses.len(),
            manifests.len(),
            smoke
        );
    } else {
        println!(
            "{:<12} {:<30} {:>10} {:>10} {:>10} {:>10} {:>12}",
            "SLO_ID", "BENCHMARK", "INC_P50_US", "P50_US", "P95_US", "P99_US", "BASE_P50_US"
        );
        for r in &reports {
            let extra = match (r.watermark_disclosure, r.memory_breakdown) {
                (Some(w), _) => format!(" [{} tail={}]", w.served_mode.as_str(), w.tail_length),
                (_, Some(m)) => format!(" [{} B/leg]", m.total_bytes_per_leg),
                (None, None) => String::new(),
            };
            println!(
                "{:<12} {:<30} {:>10} {:>10} {:>10} {:>10} {:>12}{}",
                r.manifest.slo_id,
                r.manifest.bench_name,
                r.incumbent.p50_us,
                r.candidate.p50_us,
                r.candidate.p95_us,
                r.candidate.p99_us,
                r.manifest.baseline.p50_us,
                extra
            );
        }
        println!(
            "fa-bench: {} benchmarks passed ({} manifests, {} kernel op witnesses verified)",
            reports.len(),
            manifests.len(),
            witnesses.len()
        );
    }

    ExitCode::SUCCESS
}
