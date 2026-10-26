//! fa-ykbp: the §17 incumbent driver through the real `fa-bench` binary.
//!
//! The binary stands in for its own incumbent here only to run the
//! pipeline end to end at a small scale. Each unmeasured run is judged so
//! for the reason it names; the one measured run proves the artifact's
//! shape, not any number (a binary compared with itself).

use std::path::PathBuf;
use std::process::Command;

use fa_bench::driver::parse_samples_line;

const REFERENCE: &str = "apple-silicon-nvme-m4";

/// A directory path that does not exist yet.
fn fresh(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "fa-bench-driver-{name}-{}-{nanos}",
        std::process::id()
    ))
}

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

/// The one `bench_unmeasured` reason of a driven run of `slo`.
fn unmeasured_reason(slo: &str, args: &[&str]) -> String {
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
    assert!(line.contains(&format!("\"slo_id\":\"{slo}\"")), "{line}");
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
        unmeasured_reason("FA-BENCH-06", &refs)
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

#[test]
fn the_write_path_samples_and_a_driven_run_measure_end_to_end() {
    let me = env!("CARGO_BIN_EXE_fa-bench");
    // Three single posts on a new directory book: three entries committed.
    let dir = fresh("single");
    let (code, stdout, stderr) = fa_bench(&[
        "sample",
        "single_entry_post",
        "--dir",
        dir.to_str().expect("utf-8 path"),
        "--rounds",
        "3",
    ]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let run = parse_samples_line(stdout.trim()).expect("bench_samples line");
    assert_eq!((run.counted, run.samples_us.len()), (3, 3));
    assert!(stdout.contains("\"stated\":3,\"witness\":{\"counter\":\"entries_committed\""));
    // The same directory again is refused: the book exists.
    let (code, _, stderr) = fa_bench(&[
        "sample",
        "single_entry_post",
        "--dir",
        dir.to_str().expect("utf-8 path"),
    ]);
    assert_eq!(code, 3, "{stderr}");
    assert!(stderr.contains("exists"), "{stderr}");

    // Two batches of 100.
    let dir = fresh("batched");
    let (code, stdout, stderr) = fa_bench(&[
        "sample",
        "batched_post",
        "--dir",
        dir.to_str().expect("utf-8 path"),
        "--rounds",
        "2",
    ]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let run = parse_samples_line(stdout.trim()).expect("bench_samples line");
    assert_eq!((run.counted, run.samples_us.len()), (200, 2));

    // A disk bench without --dir is unmeasured, naming the flag.
    let no_dir = unmeasured_reason(
        "FA-BENCH-01",
        &[
            "--bench",
            "single_entry_post",
            "--json",
            "--worker-class",
            REFERENCE,
            "--incumbent",
            me,
        ],
    );
    assert!(no_dir.contains("--dir"), "{no_dir}");

    // Ten posts on each binary: the engine counted the 10 entries the bench
    // states, so the run is judged and the artifact carries the witness and
    // the incumbent binary's digest.
    let base = fresh("driven");
    let (code, stdout, stderr) = fa_bench(&[
        "--bench",
        "FA-BENCH-01",
        "--json",
        "--worker-class",
        REFERENCE,
        "--incumbent",
        me,
        "--dir",
        base.to_str().expect("utf-8 path"),
        "--rounds",
        "10",
    ]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("\"event\":\"bench_summary\",\"measured\":1,\"unmeasured\":0"),
        "{stdout}"
    );
    let line = stdout
        .lines()
        .find(|l| l.contains("\"event\":\"bench_result\""))
        .expect("bench_result line");
    assert!(
        line.contains(
            "\"witness\":{\"counter\":\"entries_committed\",\"stated\":10,\"counted\":10}"
        ),
        "{line}"
    );
    assert!(line.contains("\"incumbent_binary_blake3\":\""), "{line}");
    assert!(line.contains("\"verdict\":\""), "{line}");
    assert!(base.join("candidate").join("store").exists());
    assert!(base.join("incumbent").join("store").exists());
}

#[test]
fn a_bundle_sample_counts_what_fa_verify_verified() {
    let (code, stdout, stderr) = fa_bench(&[
        "sample",
        "bundle_production_and_verify",
        "--entries",
        "50",
        "--rounds",
        "2",
    ]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let run = parse_samples_line(stdout.trim()).expect("bench_samples line");
    // The 50 posted entries and the book's control entries before them.
    assert!(run.counted > 50, "{stdout}");
    assert_eq!(run.samples_us.len(), 2);
    assert!(stdout.contains("\"stated\":50,\"witness\":{\"counter\":\"entries_verified\""));
}
