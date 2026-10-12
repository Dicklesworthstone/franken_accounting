//! The `fa-verify` binary itself, on raw-byte files written from the pinned
//! vectors: it verifies them (exit 0), refuses a tampered one (exit 8),
//! refuses bad usage (exit 2), and prints help on a bare invocation.

use std::path::PathBuf;
use std::process::Command;

const ACCUMULATOR: &str = include_str!("fixtures/accumulator_v1.txt");
const CHECKPOINT: &str = include_str!("fixtures/checkpoint_v1.txt");
const BUNDLE: &str = include_str!("fixtures/bundle_v1.txt");

fn unhex(s: &str) -> Vec<u8> {
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

/// The vectors as raw files in a directory of this test's own.
fn dir() -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fa-verify-cli");
    std::fs::create_dir_all(&d).expect("tmp dir");
    for name in ["checkpoint", "prefix", "scope", "balance", "state"] {
        std::fs::write(d.join(name), vector(name)).expect("write vector");
    }
    let mut tampered = vector("checkpoint");
    tampered[100] ^= 0x01;
    std::fs::write(d.join("checkpoint-tampered"), tampered).expect("write tampered");
    d
}

fn fa_verify(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .args(args)
        .output()
        .expect("run fa-verify");
    (
        out.status.code().expect("exit code"),
        String::from_utf8(out.stdout).expect("utf-8 stdout"),
        String::from_utf8(out.stderr).expect("utf-8 stderr"),
    )
}

#[test]
fn the_binary_verifies_refuses_and_explains() {
    let d = dir();
    let p = |name: &str| d.join(name).to_string_lossy().into_owned();
    let key = vector("public_key")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    let (code, out, err) = fa_verify(&[]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("usage: fa-verify"));

    let (code, out, err) = fa_verify(&[
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
    ]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("\"verdict\":\"verified\""), "{out}");
    assert!(out.contains("\"scope\":\"scope_index_complete\""));
    assert!(err.is_empty(), "robot mode keeps stderr empty: {err}");

    let (code, out, _) = fa_verify(&[
        "balance",
        &p("balance"),
        "--checkpoint",
        &p("checkpoint"),
        "--key",
        &key,
    ]);
    assert_eq!(code, 0, "{out}");
    assert!(out.starts_with("fa-verify balance: VERIFIED"), "{out}");

    let (code, out, _) = fa_verify(&[
        "prefix",
        &p("prefix"),
        "--checkpoint",
        &p("checkpoint-tampered"),
        "--key",
        &key,
        "--json",
    ]);
    assert_eq!(code, 8, "{out}");
    assert!(out.contains("\"verdict\":\"failed\""));

    let (code, out, err) = fa_verify(&["prefix", &p("prefix"), "--checkpoint", &p("checkpoint")]);
    assert_eq!(code, 2, "{out}");
    assert!(err.contains("--key"), "{err}");

    let (code, _, err) = fa_verify(&["stat", &p("state")]);
    assert_eq!(code, 2);
    assert!(err.contains("did you mean `state`?"), "{err}");
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
    let key: [u8; 32] = vector("public_key").try_into().expect("public key");
    let checkpoint = vector("checkpoint");
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
    bytes(&mut out, &vector("prefix"));
    out
}

#[test]
fn the_binary_rejects_oversized_inline_bytes_and_balance_counts_at_the_named_field() {
    use fa_verify::codec::Reason;
    use fa_verify::{BundleError, DecodeError};

    // Separate files keep this independent of the original CLI test.
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("fa-verify-cli-bundle-limits");
    std::fs::create_dir_all(&dir).expect("bundle-limit directory");
    let key_bytes: [u8; 32] = vector("public_key").try_into().expect("public key");
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
