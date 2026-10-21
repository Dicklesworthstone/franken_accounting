//! Actual-binary coverage over independently signed nonempty index fixtures.

#[path = "support/incremental_index_vectors.rs"]
mod vector;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const SECRET: &str = "INCREMENTAL_PRIVATE_PAYLOAD";

fn decode(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-incremental-index-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained test fixture: {error}"),
        }
    }
}

fn args() -> (Vec<OsString>, PathBuf) {
    let dir = directory();
    for (name, value) in [
        ("old", vector::OLD),
        ("candidate", vector::CANDIDATE),
        ("baseline", vector::BASELINE),
        ("consistency", vector::CONSISTENCY),
        ("delta1", vector::DELTA_1),
        ("delta2", vector::DELTA_2),
        ("range", vector::RANGE),
    ] {
        std::fs::write(dir.join(name), decode(value)).unwrap();
    }
    let mut args: Vec<OsString> = ["witness", "index"].map(OsString::from).into();
    for (flag, name) in [
        ("--previous", "old"),
        ("--checkpoint", "candidate"),
        ("--consistency", "consistency"),
        ("--baseline-prefix", "baseline"),
        ("--delta-record", "delta1"),
        ("--delta-record", "delta2"),
    ] {
        args.extend([flag.into(), dir.join(name).into_os_string()]);
    }
    for (flag, value) in [
        ("--expect-book", "42".repeat(16)),
        ("--expect-branch", "00".repeat(16)),
        ("--expect-policy", "55".repeat(32)),
        ("--expect-previous-body", vector::OLD_BODY.into()),
        ("--publisher-key", vector::PUBLISHER.into()),
        ("--witness-key", vector::WITNESS_A.into()),
        ("--witness-key", vector::WITNESS_B.into()),
        ("--quorum", "2".into()),
    ] {
        args.extend([flag.into(), value.into()]);
    }
    args.push("--json".into());
    (args, dir)
}

fn run(args: &[OsString]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .args(args)
        .output()
        .expect("execute offline verifier")
}

fn set(args: &mut [OsString], flag: &str, value: impl Into<OsString>) {
    let at = args.iter().position(|arg| arg == flag).unwrap();
    args[at + 1] = value.into();
}

fn remove(args: &mut Vec<OsString>, flag: &str) {
    let at = args.iter().position(|arg| arg == flag).unwrap();
    drop(args.drain(at..at + 2));
}

fn result(output: Output, exit: i32) -> String {
    let text = String::from_utf8(output.stdout).unwrap();
    let error = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(exit), "{text}\n{error}");
    assert_eq!(text.lines().count(), 1);
    for stream in [&text[..], &error[..]] {
        assert!(!stream.contains(SECRET));
        assert!(!stream.contains(&fa_verify::blake3::hex(SECRET.as_bytes())));
    }
    if exit == 0 {
        assert!(error.is_empty());
        assert!(text.contains("\"proof_kind\":\"witnessed_index_advance\""));
        assert!(text.contains("\"scope_index_derivation\":\"payload_recomputed\""));
        assert!(text.contains("\"recorded_boundary\":\"verified\""));
        assert!(text.contains("\"pin_written\":false"));
    } else {
        assert!(text.contains("\"verified\":false"));
        assert!(!text.contains("proof_verified"));
        assert!(!text.contains("payload_recomputed"));
    }
    text
}

#[test]
fn nonempty_incremental_index_and_requested_range_verify_without_resending_old_payloads() {
    let (mut input, dir) = args();
    let json = result(run(&input), 0);
    assert!(json.contains("\"tuple_count\":6"));
    assert!(json.contains("\"appended_records\":\"2\""));
    assert!(json.contains(vector::INDEX_ROOT));
    assert!(json.contains("\"range\":null"));
    input.extend([
        "--scope-proof".into(),
        dir.join("range").into_os_string(),
        "--expect-account".into(),
        format!("{:032x}", 10).into(),
        "--expect-days".into(),
        "-20:100".into(),
    ]);
    let json = result(run(&input), 0);
    assert!(json.contains("scope_index_complete"));
    for i in [0, 2] {
        assert!(json.contains(&format!("\"leaf_index\":\"{i}\"")));
    }
    assert!(!json.contains("\"leaf_index\":\"1\""));
    assert_eq!(result(run(&input), 0), json);
    for (name, value) in [
        ("old", vector::OLD),
        ("candidate", vector::CANDIDATE),
        ("baseline", vector::BASELINE),
        ("delta1", vector::DELTA_1),
        ("delta2", vector::DELTA_2),
    ] {
        assert_eq!(std::fs::read(dir.join(name)).unwrap(), decode(value));
    }
    set(&mut input, "--expect-account", format!("{:032x}", 20));
    result(run(&input), 8); // a genuinely valid proof for the wrong recipient question
    set(&mut input, "--expect-account", format!("{:032x}", 99));
    std::fs::write(dir.join("range"), decode(vector::EMPTY_RANGE)).unwrap();
    assert!(result(run(&input), 0).contains("\"leaves\":[]"));
}

#[test]
fn omitted_reordered_duplicated_and_envelope_only_suffixes_cannot_downgrade() {
    let (input, dir) = args();
    result(run(&input), 0);
    let mut omitted = input.clone();
    remove(&mut omitted, "--delta-record");
    result(run(&omitted), 8);
    remove(&mut omitted, "--delta-record");
    result(run(&omitted), 8);
    let mut duplicate = input.clone();
    set(
        &mut duplicate,
        "--delta-record",
        dir.join("delta2").into_os_string(),
    );
    result(run(&duplicate), 8);
    std::fs::write(dir.join("delta1"), decode(vector::DELTA_2)).unwrap();
    std::fs::write(dir.join("delta2"), decode(vector::DELTA_1)).unwrap();
    result(run(&input), 8);
    std::fs::write(dir.join("delta1"), decode(vector::BARE_1)).unwrap();
    std::fs::write(dir.join("delta2"), decode(vector::DELTA_2)).unwrap();
    result(run(&input), 8);
}

#[test]
fn genuine_signatures_do_not_excuse_wrong_index_roots_old_recorded_sequences_or_missing_quorum() {
    let (input, dir) = args();
    result(run(&input), 0);
    for candidate in [vector::BAD_INDEX, vector::WEAK] {
        std::fs::write(dir.join("candidate"), decode(candidate)).unwrap();
        result(run(&input), 8);
    }
    std::fs::write(dir.join("candidate"), decode(vector::BACKFILL)).unwrap();
    std::fs::write(
        dir.join("consistency"),
        decode(vector::BACKFILL_CONSISTENCY),
    )
    .unwrap();
    std::fs::write(dir.join("delta2"), decode(vector::BACKFILL_RECORD)).unwrap();
    let mut backfill = input;
    remove(&mut backfill, "--delta-record");
    let error = result(run(&backfill), 8);
    assert!(error.contains("retained frontier"));
}

#[test]
fn pin_binding_and_baseline_integrity_are_checked_before_candidate_file_access() {
    let (mut input, dir) = args();
    set(
        &mut input,
        "--checkpoint",
        dir.join("missing-candidate").into_os_string(),
    );
    set(&mut input, "--expect-previous-body", "00".repeat(32));
    assert!(result(run(&input), 8).contains("retained body digest"));
    set(&mut input, "--expect-previous-body", vector::OLD_BODY);
    let baseline = decode(vector::BASELINE);
    let mut corrupt = baseline.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    for bytes in [
        decode(vector::LEGACY),
        baseline[..baseline.len() - 1].to_vec(),
        corrupt,
    ] {
        std::fs::write(dir.join("baseline"), bytes).unwrap();
        result(run(&input), 8); // not the missing-candidate I/O error
    }
    std::fs::write(dir.join("baseline"), baseline).unwrap();
    result(run(&input), 5);
}

#[test]
fn all_scope_and_delta_syntax_is_validated_before_io() {
    let (mut base, dir) = args();
    set(
        &mut base,
        "--previous",
        dir.join("missing-old").into_os_string(),
    );
    for extra in [
        vec!["--baseline-prefix", "other"],
        vec!["--json"],
        vec!["--delta-record"],
        vec!["--scope-proof", "range"],
        vec!["--expect-account", "aa"],
        vec![
            "--scope-proof",
            "range",
            "--expect-account",
            "aa",
            "--expect-days",
            "0:1",
        ],
        vec!["--recorded-prefix", "candidate-prefix"],
    ] {
        let mut bad = base.clone();
        bad.extend(extra.into_iter().map(OsString::from));
        result(run(&bad), 2);
    }
    for flag in [
        "--baseline-prefix",
        "--previous",
        "--expect-previous-body",
        "--consistency",
    ] {
        let mut bad = base.clone();
        remove(&mut bad, flag);
        result(run(&bad), 2);
    }
    let mut too_many = base.clone();
    for _ in 0..4095 {
        too_many.extend(["--delta-record".into(), "absent".into()]);
    }
    result(run(&too_many), 2);
    result(run(&base), 5);
}

#[test]
fn all_files_share_one_budget_and_corrupt_last_proofs_never_emit_partial_success() {
    let (input, dir) = args();
    let good = decode(vector::DELTA_2);
    for n in [0, 1, good.len() - 1] {
        std::fs::write(dir.join("delta2"), &good[..n]).unwrap();
        result(run(&input), 8);
    }
    let mut bad = good;
    bad.push(0);
    std::fs::write(dir.join("delta2"), bad).unwrap();
    result(run(&input), 8);
    for name in ["delta1", "delta2"] {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join(name))
            .unwrap();
        file.set_len(32 * 1024 * 1024 + 1).unwrap();
    }
    assert!(result(run(&input), 8).contains("byte bound"));
}

#[test]
fn empty_delta_still_requires_continuity_and_the_candidate_index_root() {
    let (mut input, dir) = args();
    remove(&mut input, "--delta-record");
    remove(&mut input, "--delta-record");
    std::fs::write(dir.join("candidate"), decode(vector::OLD)).unwrap();
    std::fs::write(dir.join("consistency"), decode(vector::NOOP)).unwrap();
    let json = result(run(&input), 0);
    assert!(json.contains("\"continuity\":\"unchanged\""));
    assert!(json.contains("\"appended_records\":\"0\""));
    std::fs::write(dir.join("candidate"), decode(vector::SAME_TREE)).unwrap();
    std::fs::write(dir.join("consistency"), decode(vector::SAME_CONSISTENCY)).unwrap();
    assert!(result(run(&input), 0).contains("\"continuity\":\"advanced\""));
    std::fs::write(dir.join("consistency"), b"").unwrap();
    result(run(&input), 8);
}

#[test]
fn help_and_human_output_describe_limits_without_leaking_payloads() {
    for words in [
        vec!["witness", "--help"],
        vec!["witness", "index", "--help"],
    ] {
        let output = run(&words.into_iter().map(OsString::from).collect::<Vec<_>>());
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        assert!(String::from_utf8(output.stdout).unwrap().contains("index"));
    }
    let (mut input, _) = args();
    input.retain(|arg| arg != "--json");
    let output = run(&input);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("2 appended records"));
    assert!(text.contains("Recorded boundary verified"));
    assert!(text.contains("No pin or payload bytes were written"));
    assert!(!text.contains(SECRET));
}

// Non-UTF-8 component names are not representable on macOS APFS; match the
// existing verifier path-test boundary rather than pretending this is portable.
#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn non_utf8_paths_work_while_non_ascii_query_scalars_refuse() {
    use std::os::unix::ffi::OsStringExt;
    let (mut input, dir) = args();
    for (flag, name) in [
        ("--baseline-prefix", "baseline"),
        ("--delta-record", "delta1"),
    ] {
        let path = dir.join(OsString::from_vec(
            format!("{name}-").bytes().chain([255]).collect(),
        ));
        std::fs::copy(dir.join(name), &path).unwrap();
        set(&mut input, flag, path.into_os_string());
    }
    result(run(&input), 0);
    input.extend([
        "--scope-proof".into(),
        dir.join("range").into_os_string(),
        "--expect-account".into(),
        OsString::from_vec(vec![255]),
        "--expect-days".into(),
        "-20:100".into(),
    ]);
    result(run(&input), 2);
}

#[test]
fn ordinary_witness_continuity_retains_its_tree_only_boundary() {
    let (mut input, _) = args();
    input.remove(1); // remove only the index subcommand
    remove(&mut input, "--baseline-prefix");
    remove(&mut input, "--delta-record");
    remove(&mut input, "--delta-record");
    let output = run(&input);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains("\"proof_kind\":\"witnessed_checkpoint\""));
    assert!(json.contains("\"continuity\":\"advanced\""));
    assert!(!json.contains("payload_recomputed"));
    assert!(json.contains("not_checked"));
}
