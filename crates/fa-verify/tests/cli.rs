//! The `fa-verify` binary itself, on raw-byte files written from the pinned
//! vectors: it verifies them (exit 0), refuses a tampered one (exit 8),
//! refuses bad usage (exit 2), and prints help on a bare invocation.

use std::path::PathBuf;
use std::process::Command;

const ACCUMULATOR: &str = include_str!("fixtures/accumulator_v1.txt");
const CHECKPOINT: &str = include_str!("fixtures/checkpoint_v1.txt");

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
