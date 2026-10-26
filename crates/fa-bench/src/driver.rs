//! The §17 incumbent driver (plan §17, AGENTS.md, fa-ykbp): a bench is
//! measured only with the incumbent live in the same invocation. The driver
//! runs `fa-bench sample <workload>` on the candidate binary and on the
//! incumbent binary (the previous release), at the bench's stated scale and
//! seed, and judges the two sample sets with [`crate::judge_run`].
//!
//! It refuses to measure, saying why, when there is no incumbent, when the
//! host is not the manifest's worker class (the baseline is pinned to it),
//! when the incumbent cannot run the workload, or when the two binaries did
//! not count the same work. A failure of the candidate itself is an error.

use std::path::Path;
use std::process::Command;

use crate::{BenchError, BenchOutcome, WorkWitness, judge_run, load_embedded_manifests};

/// A §17 bench `fa-bench sample` runs: its workload, the engine counter that
/// witnesses it, and the scale the bench states.
pub struct Sampled {
    pub bench_name: &'static str,
    pub workload: &'static str,
    pub counter: &'static str,
    pub stated: u64,
}

/// Every §17 bench with a real workload.
pub const SAMPLED: &[Sampled] = &[Sampled {
    bench_name: "register_rebuild_10m",
    workload: "register_rebuild",
    counter: "legs_folded",
    stated: 10_000_000,
}];

/// The sampled workload behind `bench` (a bench name or SLO id).
#[must_use]
pub fn sampled(bench: &str) -> Option<&'static Sampled> {
    let manifests = load_embedded_manifests().ok()?;
    let name = manifests
        .iter()
        .find(|m| m.bench_name == bench || m.slo_id == bench)
        .map(|m| m.bench_name.clone())?;
    SAMPLED.iter().find(|s| s.bench_name == name)
}

/// One `bench_samples` line: the engine's witness count and raw samples.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SampleRun {
    pub counted: u64,
    pub samples_us: Vec<u64>,
}

fn after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.find(key).map(|at| &line[at + key.len()..])
}

/// Read `fa-bench sample`'s own `bench_samples` line.
pub fn parse_samples_line(line: &str) -> Result<SampleRun, String> {
    if !line.contains("\"event\":\"bench_samples\"") {
        return Err("not a bench_samples line".into());
    }
    let counted = after(line, "\"counted\":")
        .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|digits| digits.parse().ok())
        .ok_or("the line carries no witness count")?;
    let list = after(line, "\"samples_us\":[")
        .and_then(|rest| rest.split(']').next())
        .ok_or("the line carries no samples")?;
    let samples_us = if list.is_empty() {
        Vec::new()
    } else {
        list.split(',')
            .map(|v| {
                v.parse()
                    .map_err(|_| format!("sample `{v}` is not an integer"))
            })
            .collect::<Result<_, _>>()?
    };
    Ok(SampleRun {
        counted,
        samples_us,
    })
}

/// The binary the driver may run: an existing file named `fa-bench`, by its
/// canonical path. Nothing else is executed, and no shell is involved.
fn fa_bench_binary(binary: &Path) -> Result<std::path::PathBuf, String> {
    let path = binary
        .canonicalize()
        .map_err(|e| format!("{}: {e}", binary.display()))?;
    let named = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "fa-bench" || n == "fa-bench.exe");
    if !named || !path.is_file() {
        return Err(format!("{} is not an fa-bench binary", path.display()));
    }
    Ok(path)
}

/// Run `binary sample <workload> --legs <scale> --rounds <rounds> --seed <seed>`.
fn sample(
    binary: &Path,
    workload: &str,
    scale: u64,
    rounds: u64,
    seed: u64,
) -> Result<SampleRun, String> {
    let binary = fa_bench_binary(binary)?;
    let binary = binary.as_path();
    let output = Command::new(binary)
        .args(["sample", workload, "--legs"])
        .arg(scale.to_string())
        .arg("--rounds")
        .arg(rounds.to_string())
        .arg("--seed")
        .arg(seed.to_string())
        .output()
        .map_err(|e| format!("could not start {}: {e}", binary.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "{} exited {:?}: {}",
            binary.display(),
            output.status.code(),
            stderr.lines().next().unwrap_or("")
        ));
    }
    let line = stdout
        .lines()
        .find(|l| l.contains("\"event\":\"bench_samples\""))
        .ok_or_else(|| format!("{} printed no bench_samples line", binary.display()))?;
    parse_samples_line(line)
}

/// What a driven run asks for.
pub struct Drive<'a> {
    /// The §17 bench, by name or SLO id.
    pub bench: &'a str,
    /// This build's `fa-bench`.
    pub candidate: &'a Path,
    /// The previous release's `fa-bench`.
    pub incumbent: Option<&'a Path>,
    /// The worker class of this host.
    pub worker_class: &'a str,
    /// The scale to post; the bench's stated scale when absent. A smaller
    /// one exercises the pipeline and is judged unmeasured.
    pub scale: Option<u64>,
    pub rounds: u64,
}

/// Drive one §17 bench: both binaries, then [`judge_run`].
pub fn drive(request: &Drive<'_>) -> Result<BenchOutcome, BenchError> {
    let manifest = load_embedded_manifests()?
        .into_iter()
        .find(|m| m.bench_name == request.bench || m.slo_id == request.bench)
        .ok_or_else(|| BenchError::UnknownBenchmark(request.bench.to_string()))?;
    let unmeasured = |reason: String| BenchOutcome::Unmeasured {
        slo_id: manifest.slo_id.clone(),
        bench_name: manifest.bench_name.clone(),
        reason,
    };
    let Some(workload) = SAMPLED.iter().find(|s| s.bench_name == manifest.bench_name) else {
        return Ok(unmeasured(crate::UNMEASURED_REASON.to_string()));
    };
    let Some(incumbent) = request.incumbent else {
        return Ok(unmeasured(
            "no incumbent: a §17 number needs the previous release's fa-bench run in the same invocation (--incumbent <binary>); tracked by fa-ykbp".into(),
        ));
    };
    if let Err(why) = manifest.validate_comparison(request.worker_class, true) {
        return Ok(unmeasured(format!(
            "{why}; run `fa-bench sample {}` for development numbers",
            workload.workload
        )));
    }
    let scale = request.scale.unwrap_or(workload.stated);
    let seed = manifest.fixture_seed;
    let candidate = sample(
        request.candidate,
        workload.workload,
        scale,
        request.rounds,
        seed,
    )
    .map_err(BenchError::Execution)?;
    let incumbent_run = match sample(incumbent, workload.workload, scale, request.rounds, seed) {
        Ok(run) => run,
        Err(why) => {
            return Ok(unmeasured(format!(
                "the incumbent did not run `sample {}`: {why}",
                workload.workload
            )));
        }
    };
    if incumbent_run.counted != candidate.counted {
        return Ok(unmeasured(format!(
            "the incumbent counted {} {} and the candidate {}: they did not do the same work",
            incumbent_run.counted, workload.counter, candidate.counted
        )));
    }
    let digest = std::fs::read(incumbent)
        .map(|bytes| fgdb_crypto::hash(&bytes).0)
        .map_err(|e| BenchError::Execution(format!("read {}: {e}", incumbent.display())))?;
    let mut outcome = judge_run(
        manifest.clone(),
        &incumbent_run.samples_us,
        &candidate.samples_us,
        WorkWitness {
            counter: workload.counter.to_string(),
            stated: workload.stated,
            counted: candidate.counted,
        },
    )?;
    if let BenchOutcome::Measured(report) = &mut outcome {
        report.incumbent_binary_blake3 = Some(digest);
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_samples_line_parses_and_a_foreign_line_does_not() {
        let line = "{\"event\":\"bench_samples\",\"workload\":\"register_rebuild\",\"seed\":42,\"legs_posted\":600,\"witness\":{\"counter\":\"legs_folded\",\"counted\":600},\"samples_us\":[910,875,1002]}";
        assert_eq!(
            parse_samples_line(line),
            Ok(SampleRun {
                counted: 600,
                samples_us: vec![910, 875, 1002],
            })
        );
        assert!(parse_samples_line("{\"event\":\"bench_result\"}").is_err());
        assert!(
            parse_samples_line(&line.replace("[910,875,1002]", "[910,x]"))
                .unwrap_err()
                .contains("`x`")
        );
    }

    #[test]
    fn only_the_rebuild_bench_has_a_workload() {
        assert_eq!(
            sampled("FA-BENCH-06").map(|s| s.workload),
            Some("register_rebuild")
        );
        assert!(sampled("single_entry_post").is_none());
        assert!(sampled("no_such_bench").is_none());
    }
}
