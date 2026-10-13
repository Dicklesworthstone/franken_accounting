//! The `fa-verify` binary itself, in a separate process on raw-byte files
//! written from the pinned vectors. Both anchors are exercised: a signed
//! `TransparencyCheckpoint` judged against `--key`, and a raw 80-byte
//! checkpoint the operator trusts independently (`--unsigned-checkpoint`).
//! The trusted checkpoint is always a separate file, never chosen from the
//! proof by the executable. Temporary inputs are retained on failure.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::{Checkpoint, verify_state};

const ACCUMULATOR: &str = include_str!("fixtures/accumulator_v1.txt");
const CHECKPOINT: &str = include_str!("fixtures/checkpoint_v1.txt");

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn vector(name: &str) -> Vec<u8> {
    ACCUMULATOR
        .lines()
        .chain(CHECKPOINT.lines())
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
        .map(unhex)
        .expect("pinned vector")
}

fn directory(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fa-verify-{}-{name}-{index}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) => assert_eq!(
                error.kind(),
                std::io::ErrorKind::AlreadyExists,
                "create {}: {error}",
                path.display()
            ),
        }
    }
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).expect("write retained input fixture");
    path
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .args(args)
        .output()
        .expect("run fa-verify binary")
}

fn text(output: &Output) -> (i32, String, String) {
    (
        output.status.code().expect("exit code"),
        String::from_utf8(output.stdout.clone()).expect("UTF-8 stdout"),
        String::from_utf8(output.stderr.clone()).expect("UTF-8 stderr"),
    )
}

/// A raw-checkpoint proof run in robot mode: the trusted checkpoint is
/// `anchor`; for consistency `next` is the producer's claimed extension.
fn run_proof(kind: &str, proof: &Path, anchor: &Path, next: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fa-verify"));
    command
        .arg(kind)
        .arg("--proof")
        .arg(proof)
        .arg("--checkpoint")
        .arg(anchor)
        .arg("--unsigned-checkpoint")
        .arg("--json");
    if let Some(next) = next {
        command.arg("--next-checkpoint").arg(next);
    }
    command.output().expect("run fa-verify binary")
}

fn success(output: &Output) -> String {
    let (code, stdout, stderr) = text(output);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stderr.is_empty(), "robot mode keeps stderr empty: {stderr}");
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(stdout.contains("\"verdict\":\"verified\""), "{stdout}");
    assert!(
        stdout.contains("\"scope\":\"operator_trusted\""),
        "{stdout}"
    );
    assert!(stdout.contains("\"format\":\"unsigned_raw_checkpoint\""));
    assert!(stdout.contains("\"signature_verification\":\"not_performed\""));
    stdout
}

fn failure(output: &Output, code: i32, verdict: &str) -> String {
    let (exit, stdout, stderr) = text(output);
    assert_eq!(exit, code, "{stdout}\n{stderr}");
    assert!(!stderr.is_empty(), "a failure includes a diagnostic");
    assert_eq!(stdout.lines().count(), 1, "one structured report: {stdout}");
    assert!(
        stdout.contains(&format!("\"verdict\":\"{verdict}\"")),
        "{stdout}"
    );
    assert!(!stdout.contains("\"verdict\":\"verified\""), "{stdout}");
    stdout
}

/// The frozen states' checkpoints, written as the operator's independently
/// pinned raw anchors. No producer crate is linked into this test.
fn checkpoints(dir: &Path) -> (PathBuf, PathBuf) {
    let old = verify_state(&vector("old_state")).unwrap().checkpoint;
    let current = verify_state(&vector("state")).unwrap().checkpoint;
    (
        write(dir, "old.checkpoint", &old.encode()),
        write(dir, "current.checkpoint", &current.encode()),
    )
}

fn u32_at(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
}

#[test]
fn the_binary_verifies_signed_checkpoints_refuses_and_explains() {
    let d = directory("signed");
    for name in ["checkpoint", "prefix", "scope", "balance", "state"] {
        write(&d, name, &vector(name));
    }
    let mut tampered = vector("checkpoint");
    tampered[100] ^= 0x01;
    write(&d, "checkpoint-tampered", &tampered);
    let p = |name: &str| d.join(name).to_string_lossy().into_owned();
    let key = vector("public_key")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    let (code, out, err) = text(&run(&[]));
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("usage: fa-verify"));

    let (code, out, err) = text(&run(&[
        "scope",
        &p("scope"),
        "--checkpoint",
        &p("checkpoint"),
        "--key",
        &key,
        "--account",
        "0x10",
        "--from",
        "20527",
        "--to",
        "20527",
        "--prefix",
        &p("prefix"),
        "--json",
    ]));
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("\"verdict\":\"verified\""), "{out}");
    assert!(out.contains("\"scope\":\"scope_index_complete\""));
    assert!(err.is_empty(), "robot mode keeps stderr empty: {err}");

    let (code, out, _) = text(&run(&[
        "balance",
        &p("balance"),
        "--checkpoint",
        &p("checkpoint"),
        "--key",
        &key,
    ]));
    assert_eq!(code, 0, "{out}");
    assert!(out.starts_with("fa-verify balance: VERIFIED"), "{out}");

    let out = run(&[
        "prefix",
        &p("prefix"),
        "--checkpoint",
        &p("checkpoint-tampered"),
        "--key",
        &key,
        "--json",
    ]);
    failure(&out, 8, "failed");

    let (code, out, err) = text(&run(&[
        "prefix",
        &p("prefix"),
        "--checkpoint",
        &p("checkpoint"),
    ]));
    assert_eq!(code, 2, "{out}");
    assert!(err.contains("--key"), "{err}");
    assert!(err.contains("--unsigned-checkpoint"), "{err}");

    let (code, _, err) = text(&run(&["stat", &p("state")]));
    assert_eq!(code, 2);
    assert!(err.contains("did you mean `state`?"), "{err}");

    // The two anchors are exclusive, and a scope proof needs the signed one.
    let out = run(&[
        "prefix",
        &p("prefix"),
        "--checkpoint",
        &p("checkpoint"),
        "--key",
        &key,
        "--unsigned-checkpoint",
        "--json",
    ]);
    failure(&out, 2, "usage");
    let out = run(&[
        "scope",
        &p("scope"),
        "--checkpoint",
        &p("checkpoint"),
        "--unsigned-checkpoint",
        "--account",
        "0x10",
        "--from",
        "20527",
        "--to",
        "20527",
        "--json",
    ]);
    let stdout = failure(&out, 2, "usage");
    assert!(stdout.contains("signed checkpoint"), "{stdout}");
}

#[test]
fn every_raw_proof_verifies_against_an_operator_trusted_checkpoint() {
    let dir = directory("goldens");
    let (old, current) = checkpoints(&dir);
    for (kind, scope) in [
        ("inclusion", "inclusion"),
        ("consistency", "consistency"),
        ("prefix", "seq_range_complete"),
        ("balance", "recomputation"),
    ] {
        let proof = write(&dir, &format!("{kind}.proof"), &vector(kind));
        let (anchor, next) = if kind == "consistency" {
            (&old, Some(current.as_path()))
        } else {
            (&current, None)
        };
        let stdout = success(&run_proof(kind, &proof, anchor, next));
        assert!(stdout.contains(&format!("\"command\":\"{kind}\"")));
        assert!(
            stdout.contains(&format!("\"scope\":\"{scope}\"")),
            "{stdout}"
        );
        assert!(stdout.contains(&format!("\"book_id\":\"{}\"", "5a".repeat(16))));
        match kind {
            "inclusion" => {
                assert!(stdout.contains("\"record\":\"recomputed\""), "{stdout}");
                assert!(stdout.contains("\"leaf_index\":3"), "{stdout}");
                assert!(stdout.contains("\"commit_seq\":5"), "{stdout}");
            }
            "consistency" => {
                assert!(stdout.contains("\"scope\":\"producer_claim\""), "{stdout}");
                assert!(
                    stdout
                        .contains("\"claimed_sequence_boundary\":\"not_verified_by_consistency\""),
                    "{stdout}"
                );
                assert!(stdout.contains("\"check\":\"consistency\""));
            }
            "prefix" => {
                assert!(stdout.contains("\"leaves\":4"), "{stdout}");
            }
            other => {
                assert_eq!(other, "balance");
                assert!(stdout.contains("\"account\":\"0x00000000000000000000000000000030\""));
                assert!(stdout.contains("\"unit\":1"));
                assert!(stdout.contains("\"debits\":\"0\""));
                assert!(stdout.contains("\"credits\":\"120550\""));
                assert!(stdout.contains("\"effective_through\":null"));
                let contributing = stdout
                    .split_once("\"contributing\":[")
                    .and_then(|(_, rest)| rest.split_once(']'))
                    .map(|(list, _)| list.split(',').count())
                    .expect("contributing leaves listed");
                assert_eq!(contributing, 2, "{stdout}");
            }
        }
    }
}

#[test]
fn inclusion_without_a_record_does_not_claim_payload_recomputation() {
    let dir = directory("envelope-only");
    let (_, current) = checkpoints(&dir);
    let original = vector("inclusion");
    let envelope_length_at = 4 + u32_at(&original, 0) + Checkpoint::ENCODED_LEN + 8;
    let record_at = envelope_length_at + 4 + u32_at(&original, envelope_length_at);
    assert_eq!(
        original[record_at], 1,
        "frozen inclusion embeds its payload"
    );
    let record_length_at = record_at + 1 + 4;
    let path_at = record_length_at + 4 + u32_at(&original, record_length_at);
    let mut envelope_only = original[..record_at].to_vec();
    envelope_only.push(0);
    envelope_only.extend_from_slice(&original[path_at..]);
    let proof = write(&dir, "envelope-only.proof", &envelope_only);
    let stdout = success(&run_proof("inclusion", &proof, &current, None));
    assert!(stdout.contains("\"scope\":\"inclusion\""));
    assert!(stdout.contains("\"record\":\"not_supplied\""), "{stdout}");
    assert!(!stdout.contains("recomputed"), "{stdout}");
}

#[test]
fn tampered_truncated_and_wrong_anchor_proofs_fail_closed() {
    let dir = directory("tampering");
    let (old, current) = checkpoints(&dir);
    for kind in ["inclusion", "consistency", "prefix", "balance"] {
        let original = vector(kind);
        let (anchor, next) = if kind == "consistency" {
            (&old, Some(current.as_path()))
        } else {
            (&current, None)
        };
        let mut flipped = original.clone();
        let middle = flipped.len() / 2;
        flipped[middle] ^= 1;
        let mut trailing = original.clone();
        trailing.push(0);
        for (name, bytes) in [
            ("flipped", flipped),
            ("trailing", trailing),
            ("truncated", original[..original.len() - 1].to_vec()),
            ("empty", Vec::new()),
        ] {
            let proof = write(&dir, &format!("{kind}-{name}.proof"), &bytes);
            failure(&run_proof(kind, &proof, anchor, next), 8, "failed");
        }
        let proof = write(&dir, &format!("{kind}.proof"), &original);
        let mut changed_anchor = fs::read(anchor).unwrap();
        changed_anchor[Checkpoint::ENCODED_LEN - 1] ^= 1;
        let changed = write(&dir, &format!("{kind}-wrong.checkpoint"), &changed_anchor);
        let stdout = failure(&run_proof(kind, &proof, &changed, next), 8, "failed");
        assert!(stdout.contains("checkpoint you did not trust"), "{stdout}");
    }
}

#[test]
fn completeness_refuses_an_omitted_envelope_and_consistency_refuses_a_substituted_claim() {
    let dir = directory("scope");
    let (old, current) = checkpoints(&dir);
    let original = vector("prefix");
    let count_at = 4 + u32_at(&original, 0) + Checkpoint::ENCODED_LEN;
    assert_eq!(u32_at(&original, count_at), 4);
    let mut cursor = count_at + 4;
    for _ in 0..3 {
        cursor += 4 + u32_at(&original, cursor);
    }
    let mut omitted = original[..cursor].to_vec();
    omitted[count_at..count_at + 4].copy_from_slice(&3_u32.to_le_bytes());
    let proof = write(&dir, "omitted.proof", &omitted);
    let stdout = failure(&run_proof("prefix", &proof, &current, None), 8, "failed");
    assert!(stdout.contains('3') && stdout.contains('4'), "{stdout}");

    let consistency = write(&dir, "consistency.proof", &vector("consistency"));
    let stdout = failure(
        &run_proof("consistency", &consistency, &old, Some(&old)),
        8,
        "failed",
    );
    assert!(stdout.contains("other than the one claimed"), "{stdout}");
}

#[test]
fn raw_checkpoint_files_must_have_exactly_the_canonical_eighty_bytes() {
    let dir = directory("anchor-codec");
    let (_, current) = checkpoints(&dir);
    let original = fs::read(current).unwrap();
    let proof = write(&dir, "prefix.proof", &vector("prefix"));
    for (name, bytes) in [
        ("short", original[..79].to_vec()),
        ("empty", Vec::new()),
        ("long", [original.as_slice(), &[0]].concat()),
        ("hex", fa_verify::blake3::hex(&original).into_bytes()),
    ] {
        let anchor = write(&dir, name, &bytes);
        failure(&run_proof("prefix", &proof, &anchor, None), 8, "failed");
    }
}

#[test]
fn ambiguous_and_inapplicable_flags_refuse_before_file_io() {
    // Every path is deliberately absent. An invocation that slips through
    // parsing would fail as I/O (5), so exit 2 also tests the admission order.
    let dir = directory("argv");
    let missing = dir.join("absent");
    let file = missing.to_str().unwrap();
    let u = "--unsigned-checkpoint";
    for args in [
        vec!["prefix", "--proof", file, u, "--json"],
        vec!["prefix", "--checkpoint", file, u, "--json"],
        vec![
            "prefix",
            "--proof",
            file,
            "--checkpoint",
            file,
            "--proof",
            file,
            u,
            "--json",
        ],
        vec![
            "prefix",
            "--proof",
            file,
            "--checkpoint",
            file,
            "--checkpoint",
            file,
            u,
            "--json",
        ],
        vec![
            "prefix",
            "--proof",
            file,
            "--checkpoint",
            file,
            u,
            "--json",
            "--json",
        ],
        vec![
            "prefix",
            "--proof",
            file,
            "--checkpoint",
            file,
            "--next-checkpoint",
            file,
            u,
            "--json",
        ],
        vec![
            "consistency",
            "--proof",
            file,
            "--checkpoint",
            file,
            u,
            "--json",
        ],
        vec![
            "consistency",
            "--proof",
            file,
            "--checkpoint",
            file,
            "--next-checkpoint",
            file,
            "--next-checkpoint",
            file,
            u,
            "--json",
        ],
        vec![
            "consistency",
            "--proof",
            file,
            "--checkpoint",
            file,
            "--trusted",
            file,
            "--next-checkpoint",
            file,
            u,
            "--json",
        ],
        vec![
            "inclusion",
            "--proof",
            file,
            "--checkpoint",
            file,
            "--record",
            file,
            u,
            "--json",
        ],
        vec![
            "balance",
            "--proof",
            file,
            "--checkpoint",
            file,
            "extra",
            u,
            "--json",
        ],
        vec!["balance", "--proof", "--json"],
        vec!["prefix", "--proof", "", "--checkpoint", file, u, "--json"],
        vec!["prefix", "--proof", file, "--checkpoint", file, "--json"],
        vec!["state", file, u, "--json"],
        vec!["other", "--proof", file, "--checkpoint", file, u, "--json"],
    ] {
        failure(&run(&args), 2, "usage");
    }
}

#[test]
fn io_failures_are_distinct_from_oversized_or_invalid_proofs() {
    let dir = directory("io");
    let (_, current) = checkpoints(&dir);
    let missing = dir.join("missing-\"quoted\"\nfile");
    let stdout = failure(
        &run_proof("prefix", &missing, &current, None),
        5,
        "io_error",
    );
    assert!(stdout.contains("\\\"quoted\\\"\\nfile"), "{stdout}");

    // A sparse oversized file tests the size check without allocating or
    // copying 64 MiB in this test or in the verifier process.
    let oversized = dir.join("oversized.proof");
    File::create(&oversized)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    let stdout = failure(
        &run_proof("prefix", &oversized, &current, None),
        8,
        "failed",
    );
    assert!(stdout.contains("67108864-byte bound"), "{stdout}");
}

#[cfg(unix)]
#[test]
fn a_file_name_that_is_not_utf8_stays_usable() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = directory("non-utf8");
    let (_, current) = checkpoints(&dir);
    let name = OsStr::from_bytes(b"prefix-\xff.proof");
    let proof = dir.join(name);
    fs::write(&proof, vector("prefix")).expect("write non-UTF-8 named proof");
    let stdout = success(&run_proof("prefix", &proof, &current, None));
    assert!(
        stdout.contains("\"scope\":\"seq_range_complete\""),
        "{stdout}"
    );
}

#[test]
fn help_and_human_output_explain_the_trust_boundary_and_json_is_deterministic() {
    let (code, help, err) = text(&run(&["--help"]));
    assert_eq!(code, 0);
    assert!(err.is_empty());
    assert!(help.contains("trust independently"), "{help}");
    assert!(help.contains("not a trusted anchor"), "{help}");
    assert!(help.contains("5 file I/O"), "{help}");

    let dir = directory("presentation");
    let (_, current) = checkpoints(&dir);
    let proof = write(&dir, "balance.proof", &vector("balance"));
    let (code, plain, err) = text(&run(&[
        "balance",
        "--proof",
        proof.to_str().unwrap(),
        "--checkpoint",
        current.to_str().unwrap(),
        "--unsigned-checkpoint",
    ]));
    assert_eq!(code, 0, "{plain}{err}");
    assert!(err.is_empty());
    assert!(plain.starts_with("fa-verify balance: VERIFIED"), "{plain}");
    assert!(
        plain.contains("PASS checkpoint (operator_trusted)"),
        "{plain}"
    );
    assert!(plain.contains("signature_verification: not_performed"));
    assert!(plain.contains("PASS balance (recomputation)"), "{plain}");
    assert!(plain.contains("credits: 120550"), "{plain}");

    let mut outputs = Vec::new();
    for epoch in ["0", "1900000000"] {
        let output = Command::new(env!("CARGO_BIN_EXE_fa-verify"))
            .arg("balance")
            .arg("--proof")
            .arg(&proof)
            .arg("--checkpoint")
            .arg(&current)
            .arg("--unsigned-checkpoint")
            .arg("--json")
            .env("SOURCE_DATE_EPOCH", epoch)
            .output()
            .unwrap();
        outputs.push(success(&output));
    }
    assert_eq!(outputs[0], outputs[1]);
}
