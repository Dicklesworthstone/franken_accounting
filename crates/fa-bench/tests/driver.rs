//! fa-ykbp: the §17 incumbent driver through the real `fa-bench` binary.
//!
//! The binary stands in for its own incumbent here only to run the
//! pipeline end to end at a small scale; every run below is judged
//! unmeasured, each for the reason it names.

use std::process::Command;

use fa_bench::driver::parse_samples_line;

const REFERENCE: &str = "apple-silicon-nvme-m4";

fn fa_bench(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_fa-bench"))
        .args(args)
        .env_remove("FA_BENCH_WORKER_CLASS")
        .output()
        .expect("fa-bench runs");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8(output.stdout).expect("utf-8 stdout"),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The one `bench_unmeasured` reason of a driven run.
fn unmeasured_reason(args: &[&str]) -> String {
    let (code, stdout, stderr) = fa_bench(args);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("\"event\":\"bench_summary\",\"measured\":0,\"unmeasured\":1"),
        "{stdout}"
    );
    let line = stdout
        .lines()
        .find(|l| l.contains("\"event\":\"bench_unmeasured\""))
        .unwrap_or_else(|| panic!("no bench_unmeasured line: {stdout}"));
    assert!(line.contains("\"slo_id\":\"FA-BENCH-06\""), "{line}");
    assert!(!line.contains("\"p50_us\":"), "{line}");
    line.to_string()
}

#[test]
fn sample_prints_raw_samples_and_the_engine_witness() {
    let (code, stdout, stderr) = fa_bench(&[
        "sample",
        "register_rebuild",
        "--legs",
        "48",
        "--rounds",
        "2",
    ]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let run = parse_samples_line(stdout.trim()).expect("bench_samples line");
    assert_eq!(run.counted, 48);
    assert_eq!(run.samples_us.len(), 2);
    // An odd leg count is refused before anything is posted.
    let (code, _, stderr) = fa_bench(&["sample", "register_rebuild", "--legs", "601"]);
    assert_eq!(code, 3, "{stderr}");
    assert!(stderr.contains("not a positive even count"), "{stderr}");
}

#[test]
fn a_driven_run_names_why_it_is_unmeasured() {
    let me = env!("CARGO_BIN_EXE_fa-bench");
    // One round suffices: a below-scale run is judged before any comparison.
    let small = [
        "--bench",
        "register_rebuild_10m",
        "--json",
        "--legs",
        "48",
        "--rounds",
        "1",
    ];
    let with = |extra: &[&str]| -> Vec<String> {
        small
            .iter()
            .chain(extra)
            .map(|s| (*s).to_string())
            .collect()
    };
    let run = |extra: &[&str]| {
        let args = with(extra);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        unmeasured_reason(&refs)
    };

    let none = run(&["--worker-class", REFERENCE]);
    assert!(none.contains("no incumbent"), "{none}");

    let missing = run(&[
        "--worker-class",
        REFERENCE,
        "--incumbent",
        "/nonexistent/fa-bench",
    ]);
    assert!(missing.contains("the incumbent did not run"), "{missing}");

    let not_bench = run(&["--worker-class", REFERENCE, "--incumbent", "/bin/sh"]);
    assert!(
        not_bench.contains("is not an fa-bench binary"),
        "{not_bench}"
    );

    let dev = run(&["--worker-class", "dev", "--incumbent", me]);
    assert!(
        dev.contains("refused cross-worker comparison") && dev.contains(REFERENCE),
        "{dev}"
    );

    // Both binaries run 48 legs; the engine counted 48, and the bench
    // states 10M: a below-scale run is no measurement.
    let small_run = run(&["--worker-class", REFERENCE, "--incumbent", me]);
    assert!(
        small_run.contains("the engine counted 48 legs_folded where the bench states 10000000"),
        "{small_run}"
    );

    // Run alone, the bench says a real workload exists and what it needs.
    let (code, stdout, _) = fa_bench(&["--bench", "FA-BENCH-06", "--json"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("needs the previous release"), "{stdout}");
}
