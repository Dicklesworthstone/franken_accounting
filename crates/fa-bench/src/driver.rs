//! The §17 incumbent driver (plan §17, AGENTS.md, fa-ykbp): a bench is
//! measured only with the incumbent live in the same invocation. The driver
//! runs `fa-bench sample <workload>` on the candidate binary and on the
//! incumbent binary (the previous release), at the bench's stated scale and
//! seed, and judges the two sample sets with [`crate::judge_run`].
//!
//! It refuses to measure, saying why, when there is no incumbent, when the
//! host is not the manifest's worker class (the baseline is pinned to it),
//! when a disk workload has no directory to write on, when the incumbent
//! cannot run the workload, or when the two binaries did not count the same
//! work. A failure of the candidate itself is an error.

use std::path::Path;
use std::process::Command;

use crate::{BenchError, BenchOutcome, WorkWitness, judge_run, load_embedded_manifests};

/// The work a sampled bench states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scale {
    /// A fixed amount for the whole run, e.g. 10M legs in the book.
    Fixed(u64),
    /// An amount every round must do, e.g. one entry per single post.
    PerRound(u64),
}

/// A §17 bench `fa-bench sample` runs: its workload, the counter that
/// witnesses it, the work it states, and the flag that sets a fixed scale
/// (a per-round bench writes a directory book named by `--dir` instead).
pub struct Sampled {
    pub bench_name: &'static str,
    pub workload: &'static str,
    pub counter: &'static str,
    pub scale: Scale,
    pub scale_flag: Option<&'static str>,
}

/// Every §17 bench with a real workload.
pub const SAMPLED: &[Sampled] = &[
    Sampled {
        bench_name: "single_entry_post",
        workload: "single_entry_post",
        counter: "entries_committed",
        scale: Scale::PerRound(1),
        scale_flag: None,
    },
    Sampled {
        bench_name: "batched_post",
        workload: "batched_post",
        counter: "entries_committed",
        scale: Scale::PerRound(crate::post::BATCH_ENTRIES),
        scale_flag: None,
    },
    Sampled {
        bench_name: "register_rebuild_10m",
        workload: "register_rebuild",
        counter: "legs_folded",
        scale: Scale::Fixed(10_000_000),
        scale_flag: Some("--legs"),
    },
    Sampled {
        bench_name: "bundle_production_and_verify",
        workload: "bundle_production_and_verify",
        counter: "entries_verified",
        scale: Scale::Fixed(10_000),
        scale_flag: Some("--entries"),
    },
];

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

/// What `fa-bench sample <workload>` was asked to do.
pub struct SampleArgs<'a> {
    /// A fixed-scale workload's scale: legs in the book for
    /// register_rebuild (`--legs`), posted entries for
    /// bundle_production_and_verify (`--entries`).
    pub scale: Option<u64>,
    /// The new directory a disk workload creates its book in.
    pub dir: Option<&'a Path>,
    pub rounds: u64,
    pub seed: u64,
}

/// Run `workload` in this process: every round must do exactly the work it
/// states, or no sample is drawn. Returns the run, the work stated, and the
/// counter that witnesses it.
pub fn run_sample(
    workload: &str,
    args: &SampleArgs<'_>,
) -> Result<(SampleRun, u64, &'static str), String> {
    let Some(sampled) = SAMPLED.iter().find(|s| s.workload == workload) else {
        let names: Vec<&str> = SAMPLED.iter().map(|s| s.workload).collect();
        return Err(format!(
            "no workload `{workload}`; sample runs {}",
            names.join(", ")
        ));
    };
    if args.rounds == 0 {
        return Err("--rounds must be at least 1".into());
    }
    let mut samples_us = Vec::new();
    let mut counted = 0u64;
    let stated = match sampled.scale {
        Scale::Fixed(_) if workload == "bundle_production_and_verify" => {
            let entries = args
                .scale
                .ok_or("bundle_production_and_verify needs --entries <count>")?;
            let mut book = crate::bundle::build(entries, args.seed).map_err(|e| e.to_string())?;
            for _ in 0..args.rounds {
                let run = book.produce_and_verify().map_err(|e| e.to_string())?;
                if run.entries_verified < entries {
                    return Err(format!(
                        "a verified bundle carried {} entries of the {entries} posted; no sample is drawn from it",
                        run.entries_verified
                    ));
                }
                counted = run.entries_verified;
                samples_us.push(run.elapsed_us);
            }
            entries
        }
        Scale::Fixed(_) => {
            let legs = args
                .scale
                .ok_or("register_rebuild needs --legs <even count>")?;
            let mut book = crate::rebuild::build(legs, args.seed).map_err(|e| e.to_string())?;
            for _ in 0..args.rounds {
                let run = book.rebuild().map_err(|e| e.to_string())?;
                if run.legs_folded != legs {
                    return Err(format!(
                        "a rebuild folded {} legs of the {legs} posted; no sample is drawn from it",
                        run.legs_folded
                    ));
                }
                counted = run.legs_folded;
                samples_us.push(run.elapsed_us);
            }
            legs
        }
        Scale::PerRound(per_round) => {
            let dir = args.dir.ok_or_else(|| {
                format!("{workload} writes a directory book: --dir <new directory>")
            })?;
            let mut book = crate::post::build(dir, args.seed).map_err(|e| e.to_string())?;
            for _ in 0..args.rounds {
                let written = if workload == "batched_post" {
                    book.post_batch()
                } else {
                    book.post_one()
                }
                .map_err(|e| e.to_string())?;
                if written.committed != per_round {
                    return Err(format!(
                        "a write committed {} entries where it states {per_round}; no sample is drawn from it",
                        written.committed
                    ));
                }
                counted += written.committed;
                samples_us.push(written.elapsed_us);
            }
            per_round * args.rounds
        }
    };
    Ok((
        SampleRun {
            counted,
            samples_us,
        },
        stated,
        sampled.counter,
    ))
}

/// `fa-bench sample`'s one output line.
#[must_use]
pub fn samples_line(
    workload: &str,
    seed: u64,
    stated: u64,
    counter: &str,
    run: &SampleRun,
) -> String {
    let list: Vec<String> = run.samples_us.iter().map(u64::to_string).collect();
    format!(
        "{{\"event\":\"bench_samples\",\"workload\":\"{workload}\",\"seed\":{seed},\"stated\":{stated},\"witness\":{{\"counter\":\"{counter}\",\"counted\":{}}},\"samples_us\":[{}]}}",
        run.counted,
        list.join(",")
    )
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

/// Run `binary sample <workload> <args...>` and read its samples line.
fn sample(binary: &Path, workload: &str, args: &[String]) -> Result<SampleRun, String> {
    let binary = fa_bench_binary(binary)?;
    let binary = binary.as_path();
    // ubs:ignore — fa_bench_binary admits only an existing file named fa-bench.
    let output = Command::new(binary)
        .args(["sample", workload])
        .args(args)
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
    /// The scale to post for a fixed-scale bench; its stated scale when
    /// absent. A smaller one exercises the pipeline and is judged
    /// unmeasured.
    pub scale: Option<u64>,
    /// Where a disk workload's books are created: `<dir>/candidate` and
    /// `<dir>/incumbent`, which must not exist yet.
    pub dir: Option<&'a Path>,
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
    let seed = manifest.fixture_seed;
    let common = |extra: Vec<String>| -> Vec<String> {
        let mut args = extra;
        args.extend([
            "--rounds".to_string(),
            request.rounds.to_string(),
            "--seed".to_string(),
            seed.to_string(),
        ]);
        args
    };
    let (candidate_args, incumbent_args, stated) = match workload.scale {
        Scale::Fixed(stated) => {
            let scale = vec![
                workload.scale_flag.unwrap_or("--legs").to_string(),
                request.scale.unwrap_or(stated).to_string(),
            ];
            (common(scale.clone()), common(scale), stated)
        }
        Scale::PerRound(per_round) => {
            let Some(dir) = request.dir else {
                return Ok(unmeasured(format!(
                    "{} writes a directory book on the target filesystem: name a new directory with --dir",
                    manifest.bench_name
                )));
            };
            let at = |side: &str| vec!["--dir".to_string(), dir.join(side).display().to_string()];
            (
                common(at("candidate")),
                common(at("incumbent")),
                per_round * request.rounds,
            )
        }
    };
    let candidate = sample(request.candidate, workload.workload, &candidate_args)
        .map_err(BenchError::Execution)?;
    let incumbent_run = match sample(incumbent, workload.workload, &incumbent_args) {
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
            stated,
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
        let run = SampleRun {
            counted: 600,
            samples_us: vec![910, 875, 1002],
        };
        let line = samples_line("register_rebuild", 42, 600, "legs_folded", &run);
        assert_eq!(parse_samples_line(&line), Ok(run));
        assert!(parse_samples_line("{\"event\":\"bench_result\"}").is_err());
        assert!(
            parse_samples_line(&line.replace("[910,875,1002]", "[910,x]"))
                .unwrap_err()
                .contains("`x`")
        );
    }

    #[test]
    fn the_sampled_benches_are_the_write_path_the_rebuild_and_bundles() {
        assert_eq!(
            sampled("FA-BENCH-06").map(|s| s.workload),
            Some("register_rebuild")
        );
        assert_eq!(
            sampled("FA-BENCH-11").map(|s| (s.scale, s.scale_flag)),
            Some((Scale::Fixed(10_000), Some("--entries")))
        );
        assert_eq!(
            sampled("FA-BENCH-01").map(|s| (s.workload, s.scale)),
            Some(("single_entry_post", Scale::PerRound(1)))
        );
        assert_eq!(
            sampled("batched_post").map(|s| s.scale),
            Some(Scale::PerRound(100))
        );
        assert!(sampled("trial_balance_100k").is_none());
        assert!(sampled("no_such_bench").is_none());
        // Every sampled bench has a manifest.
        let names: Vec<String> = load_embedded_manifests()
            .expect("manifests")
            .into_iter()
            .map(|m| m.bench_name)
            .collect();
        for s in SAMPLED {
            assert!(names.iter().any(|n| n == s.bench_name), "{}", s.bench_name);
        }
    }

    #[test]
    fn a_sample_refuses_what_it_cannot_run() {
        let args = |scale, dir| SampleArgs {
            scale,
            dir,
            rounds: 1,
            seed: 1,
        };
        assert!(
            run_sample("no_such", &args(None, None))
                .unwrap_err()
                .contains("no workload")
        );
        assert!(
            run_sample("register_rebuild", &args(None, None))
                .unwrap_err()
                .contains("--legs")
        );
        assert!(
            run_sample("single_entry_post", &args(None, None))
                .unwrap_err()
                .contains("--dir")
        );
        assert!(
            run_sample("bundle_production_and_verify", &args(None, None))
                .unwrap_err()
                .contains("--entries")
        );
    }
}
