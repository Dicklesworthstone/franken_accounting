//! The standalone process verifies frozen producer vectors using std alone.
//! Its trusted checkpoint is always a separate fixture, never chosen from
//! the proof by the executable. Temporary inputs are retained on failure.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::{Checkpoint, verify_state};

const CHECKPOINT: &str = include_str!("fixtures/checkpoint_v1.txt");
const BUNDLE: &str = include_str!("fixtures/bundle_v1.txt");

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
        ("balance", "recomputation"),
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
    assert!(text.contains("scope: recomputation"));
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

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// A pinned vector from the accumulator fixture, then the signed-checkpoint
/// fixture (the bundle-limit test needs the book key and signed checkpoint).
fn pinned(name: &str) -> Vec<u8> {
    FIXTURE
        .lines()
        .chain(CHECKPOINT.lines())
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
        .map(unhex)
        .expect("pinned vector")
}

/// Run the binary: exit code, stdout, stderr.
fn fa_verify(args: &[&str]) -> (i32, String, String) {
    let output = run(args);
    (
        output.status.code().expect("exit code"),
        String::from_utf8(output.stdout).expect("UTF-8 stdout"),
        String::from_utf8(output.stderr).expect("UTF-8 stderr"),
    )
}

fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(
        &u32::try_from(value.len())
            .expect("bounded fixture")
            .to_le_bytes(),
    );
    out.extend_from_slice(value);
}

/// Hand-encode the published bundle 1.0 prefix layout using existing
/// checkpoint/proof vectors. The synthetic bodies below test decoding;
/// they make no claim of semantic validity.
fn bundle_header() -> Vec<u8> {
    let key: [u8; 32] = pinned("public_key").try_into().expect("public key");
    let checkpoint = pinned("checkpoint");
    let signed = fa_verify::verify_checkpoint(&checkpoint, &[key]).expect("pinned checkpoint");
    let cp = signed.checkpoint;
    let mut out = Vec::new();
    bytes(&mut out, b"fa:bundle:v1");
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&cp.book_id);
    out.extend_from_slice(&cp.branch_id);
    out.extend_from_slice(&cp.through_seq.to_le_bytes());
    out.extend_from_slice(&cp.leaf_count.to_le_bytes());
    out.extend_from_slice(&signed.oid);
    out.push(1); // Prefix scope.
    out.push(1); // SeqRangeComplete.
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&cp.leaf_count.to_le_bytes());
    bytes(&mut out, &checkpoint);
    bytes(&mut out, &pinned("prefix"));
    out
}

#[test]
fn the_binary_rejects_oversized_inline_bytes_and_balance_counts_at_the_named_field() {
    use fa_verify::codec::Reason;
    use fa_verify::{BundleError, DecodeError};

    // Separate files keep this independent of the original CLI test.
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fa-verify-cli-bundle-limits");
    std::fs::create_dir_all(&dir).expect("bundle-limit directory");
    let key_bytes: [u8; 32] = pinned("public_key").try_into().expect("public key");
    let key = key_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    // This same executable must first accept an existing valid bundle.
    let pinned = BUNDLE
        .lines()
        .find_map(|line| line.strip_prefix("bundle_prefix "))
        .map(unhex)
        .expect("pinned bundle");
    let pinned_key = BUNDLE
        .lines()
        .find_map(|line| line.strip_prefix("public_key "))
        .expect("pinned bundle key");
    let control = dir.join("pinned.fab");
    std::fs::write(&control, pinned).expect("write pinned bundle");
    let (code, out, err) = fa_verify(&[
        "bundle",
        control.to_str().expect("path"),
        "--key",
        pinned_key,
        "--json",
    ]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("\"verdict\":\"verified\""), "{out}");
    assert!(err.is_empty(), "{err}");

    const INLINE_MAX: usize = 16 * 1024 * 1024;
    let mut inline = bundle_header();
    inline.extend_from_slice(&1u32.to_le_bytes()); // One entry.
    inline.extend_from_slice(&0u64.to_le_bytes()); // Leaf index.
    inline.extend_from_slice(&0u32.to_le_bytes()); // Proposal length.
    bytes(&mut inline, &[]); // Record semantics follow decoding.
    inline.extend_from_slice(&1u32.to_le_bytes()); // One stub.
    inline.extend_from_slice(&[0x41; 32]);
    inline.push(1); // Document kind.
    inline.extend_from_slice(&((INLINE_MAX + 1) as u64).to_le_bytes());
    inline.extend_from_slice(&[0x42; 32]); // Chunk root.
    inline.push(1); // Inline document present.
    inline.extend_from_slice(&((INLINE_MAX + 1) as u32).to_le_bytes());
    let inline_offset = inline.len();
    inline.resize(inline_offset + INLINE_MAX + 1, b'x');
    inline.extend_from_slice(&0u32.to_le_bytes()); // No balances.
    bytes(&mut inline, &[]);

    const BALANCE_MAX: usize = 4096;
    let mut balances = bundle_header();
    balances.extend_from_slice(&0u32.to_le_bytes()); // No entries.
    balances.extend_from_slice(&((BALANCE_MAX + 1) as u32).to_le_bytes());
    let balances_offset = balances.len();
    for _ in 0..=BALANCE_MAX {
        bytes(&mut balances, b"fa:register-fold:v2");
        balances.extend_from_slice(&2u16.to_le_bytes());
        bytes(&mut balances, &[]); // Proof semantics follow count admission.
    }
    bytes(&mut balances, &[]);

    for (name, wire, field, offset, max) in [
        (
            "inline-too-large.fab",
            inline,
            "stub.document",
            inline_offset,
            INLINE_MAX,
        ),
        (
            "too-many-balances.fab",
            balances,
            "bundle.balances",
            balances_offset,
            BALANCE_MAX,
        ),
    ] {
        let expected = BundleError::Decode(DecodeError {
            offset,
            what: field,
            reason: Reason::TooLong {
                max,
                actual: max + 1,
            },
        });
        assert_eq!(
            fa_verify::verify_bundle(&wire, &[key_bytes], None).expect_err("wire limit"),
            expected
        );
        let path = dir.join(name);
        std::fs::write(&path, wire).expect("write generated over-limit bundle");
        let (code, out, err) = fa_verify(&[
            "bundle",
            path.to_str().expect("path"),
            "--key",
            &key,
            "--json",
        ]);
        assert_eq!(code, 8, "{name}: {out}\n{err}");
        let reason = format!(
            "decode `{field}` at byte {offset}: length {} exceeds bound {max}",
            max + 1
        );
        assert_eq!(
            out,
            format!(
                "{{\"v\":1,\"tool\":\"fa-verify\",\"command\":\"bundle\",\"verdict\":\"failed\",\"checks\":[{{\"check\":\"bundle\",\"scope\":\"format\",\"result\":\"fail\",\"detail\":{{}},\"reason\":\"{reason}\"}}],\"error\":null}}\n"
            ),
            "{name}"
        );
        assert!(err.is_empty(), "robot failure stays on stdout: {err}");
    }
}
