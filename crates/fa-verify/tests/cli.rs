//! The standalone process verifies frozen producer vectors using std alone.
//! Its trusted checkpoint is always a separate fixture, never chosen from
//! the proof by the executable. Temporary inputs are retained on failure.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::{Checkpoint, verify_state};

const FIXTURE: &str = include_str!("fixtures/accumulator_v1.txt");

fn vector(name: &str) -> Vec<u8> {
    let text = FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
        .expect("named frozen vector");
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
        .collect()
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

fn run_proof(kind: &str, proof: &Path, anchor: &Path, next: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fa-verify"));
    command
        .arg(kind)
        .arg("--proof")
        .arg(proof)
        .arg("--checkpoint")
        .arg(anchor)
        .arg("--json");
    if let Some(next) = next {
        command.arg("--next-checkpoint").arg(next);
    }
    command.output().expect("run fa-verify binary")
}

fn success(output: &Output) -> String {
    let stdout = String::from_utf8(output.stdout.clone()).expect("UTF-8 stdout");
    let stderr = String::from_utf8(output.stderr.clone()).expect("UTF-8 stderr");
    assert_eq!(output.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(stdout.contains("\"event\":\"proof_verified\""), "{stdout}");
    assert!(stdout.contains("\"verified\":true"), "{stdout}");
    assert!(stdout.contains("\"source\":\"operator_trusted_checkpoint\""));
    assert!(stdout.contains("\"format\":\"unsigned_raw_checkpoint\""));
    assert!(stdout.contains("\"signature_verification\":\"not_performed\""));
    stdout
}

fn failure(output: &Output, code: i32, class: &str) -> String {
    let stdout = String::from_utf8(output.stdout.clone()).expect("UTF-8 stdout");
    let stderr = String::from_utf8(output.stderr.clone()).expect("UTF-8 stderr");
    assert_eq!(output.status.code(), Some(code), "{stdout}\n{stderr}");
    assert!(!stderr.is_empty(), "a failure includes diagnostics");
    assert_eq!(
        stdout.lines().count(),
        1,
        "one structured failure: {stdout}"
    );
    assert!(stdout.contains("\"event\":\"error\""), "{stdout}");
    assert!(stdout.contains(&format!("\"exit\":{code}")), "{stdout}");
    assert!(
        stdout.contains(&format!("\"class\":\"{class}\"")),
        "{stdout}"
    );
    assert!(stdout.contains("\"verified\":false"), "{stdout}");
    assert!(!stdout.contains("proof_verified"), "{stdout}");
    stdout
}

fn checkpoints(dir: &Path) -> (PathBuf, PathBuf) {
    // These pre-existing frozen states are the test operator's independently
    // pinned anchors. No producer crate or generated accounting fixture is
    // linked into this process-level test.
    let old = verify_state(&vector("old_state")).unwrap().checkpoint;
    let current = verify_state(&vector("state")).unwrap().checkpoint;
    (
        write(dir, "old.checkpoint", &old.encode()),
        write(dir, "current.checkpoint", &current.encode()),
    )
}

#[test]
fn every_supported_proof_verifies_in_a_separate_process() {
    let dir = directory("goldens");
    let (old, current) = checkpoints(&dir);
    for (kind, scope) in [
        ("inclusion", "inclusion"),
        ("consistency", "consistency"),
        ("prefix", "seq_range_complete"),
        // The frozen v1 balance omits the two control payloads. Its selected
        // arithmetic still verifies, but not the omitted records' selectors.
        ("balance", "membership_only"),
    ] {
        let proof = write(&dir, &format!("{kind}.proof"), &vector(kind));
        let (anchor, next) = if kind == "consistency" {
            (&old, Some(current.as_path()))
        } else {
            (&current, None)
        };
        let stdout = success(&run_proof(kind, &proof, anchor, next));
        assert!(stdout.contains(&format!("\"proof_kind\":\"{kind}\"")));
        assert!(stdout.contains(&format!("\"scope\":\"{scope}\"")));
        assert!(stdout.contains(&format!("\"book_id\":\"{}\"", "5a".repeat(16))));
        match kind {
            "inclusion" => {
                assert!(stdout.contains("\"record_check\":\"recomputed\""));
                assert!(stdout.contains("\"leaf_index\":3"));
                assert!(stdout.contains("\"recorded_at\":5"));
            }
            "consistency" => {
                assert!(stdout.contains("\"claimed_checkpoint\":"));
                assert!(
                    stdout
                        .contains("\"claimed_sequence_boundary\":\"not_verified_by_consistency\"")
                );
                assert!(stdout.contains("\"name\":\"tree_extension\""));
            }
            "prefix" => {
                assert!(stdout.contains("\"envelopes\":4"));
                assert!(stdout.contains("\"record_check\":\"not_supplied\""));
            }
            other => {
                assert_eq!(other, "balance");
                assert!(stdout.contains("\"account\":\"00000000000000000000000000000030\""));
                assert!(stdout.contains("\"unit\":1"));
                assert!(stdout.contains("\"debits_mantissa\":\"0\""));
                assert!(stdout.contains("\"credits_mantissa\":\"120550\""));
                assert!(stdout.contains("\"effective_through_day\":null"));
                assert!(stdout.contains("\"contributing_leaves\":2"));
                assert!(stdout.contains("\"balance_complete\":false"));
                assert!(!stdout.contains("posted_balance_recomputation"));
            }
        }
    }
}

fn u32_at(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
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
    assert!(stdout.contains("\"record_check\":\"not_supplied\""));
    assert!(!stdout.contains("record_recomputation"), "{stdout}");
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
            failure(&run_proof(kind, &proof, anchor, next), 8, "verification");
        }
        let proof = write(&dir, &format!("{kind}.proof"), &original);
        let mut changed_anchor = fs::read(anchor).unwrap();
        changed_anchor[Checkpoint::ENCODED_LEN - 1] ^= 1;
        let changed = write(&dir, &format!("{kind}-wrong.checkpoint"), &changed_anchor);
        let stdout = failure(&run_proof(kind, &proof, &changed, next), 8, "verification");
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
    let stdout = failure(
        &run_proof("prefix", &proof, &current, None),
        8,
        "verification",
    );
    assert!(stdout.contains("3") && stdout.contains("4"), "{stdout}");

    let consistency = write(&dir, "consistency.proof", &vector("consistency"));
    let stdout = failure(
        &run_proof("consistency", &consistency, &old, Some(&old)),
        8,
        "verification",
    );
    assert!(stdout.contains("other than the one claimed"), "{stdout}");
}

#[test]
fn checkpoint_files_must_have_exactly_the_canonical_eighty_bytes() {
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
        failure(
            &run_proof("prefix", &proof, &anchor, None),
            8,
            "verification",
        );
    }
}

#[test]
fn ambiguous_and_inapplicable_flags_refuse_before_file_io() {
    // Every path is deliberately absent. An invocation that slips through
    // parsing would fail as I/O (5), so exit 2 also tests the admission order.
    let dir = directory("argv");
    let missing = dir.join("absent");
    let file = missing.to_str().unwrap();
    for args in [
        vec!["prefix", "--proof", file, "--json"],
        vec!["prefix", "--checkpoint", file, "--json"],
        vec![
            "prefix",
            "--proof",
            file,
            "--checkpoint",
            file,
            "--proof",
            file,
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
            "--json",
        ],
        vec![
            "prefix",
            "--proof",
            file,
            "--checkpoint",
            file,
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
            "--json",
        ],
        vec![
            "consistency",
            "--proof",
            file,
            "--checkpoint",
            file,
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
            "--json",
        ],
        vec![
            "balance",
            "--proof",
            file,
            "--checkpoint",
            file,
            "extra",
            "--json",
        ],
        vec!["balance", "--proof", "--json"],
        vec!["prefix", "--proof", "", "--checkpoint", file, "--json"],
        vec!["other", "--proof", file, "--checkpoint", file, "--json"],
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
        "foundation",
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
        "verification",
    );
    assert!(stdout.contains("67108864-byte bound"), "{stdout}");
}

#[test]
fn help_and_human_output_explain_the_trust_boundary_and_json_is_deterministic() {
    let help = run(&["--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(help.stderr.is_empty());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("trust --checkpoint independently"));
    assert!(text.contains("not a trusted anchor"));

    let dir = directory("presentation");
    let (_, current) = checkpoints(&dir);
    let proof = write(&dir, "balance.proof", &vector("balance"));
    let plain = run(&[
        "balance",
        "--proof",
        proof.to_str().unwrap(),
        "--checkpoint",
        current.to_str().unwrap(),
    ]);
    assert_eq!(plain.status.code(), Some(0));
    assert!(plain.stderr.is_empty());
    let text = String::from_utf8(plain.stdout).unwrap();
    assert!(text.contains("scope: membership_only"));
    assert!(text.contains("completeness NOT proven"));
    assert!(text.contains("credits 120550 (exact mantissas)"));
    assert!(text.contains("operator-trusted unsigned checkpoint"));

    let mut outputs = Vec::new();
    for epoch in ["0", "1900000000"] {
        let output = Command::new(env!("CARGO_BIN_EXE_fa-verify"))
            .arg("balance")
            .arg("--proof")
            .arg(&proof)
            .arg("--checkpoint")
            .arg(&current)
            .arg("--json")
            .env("SOURCE_DATE_EPOCH", epoch)
            .output()
            .unwrap();
        outputs.push(success(&output));
    }
    assert_eq!(outputs[0], outputs[1]);
}
