//! Exercise the Cargo-built offline command with the existing fixed signatures.
//! The fixtures are synthetic trees, not claims of accounting correctness.

#[path = "witness_cli/advance.rs"]
mod advance;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::blake3::hex;
use fa_verify::checkpoint::signer_key_id;
use fa_verify::checkpoint::witness::MAX_WITNESSED_CHECKPOINT_BYTES;

fn decode(text: &str, name: &str) -> Vec<u8> {
    let hex = text
        .lines()
        .find_map(|line| {
            line.strip_prefix(name)
                .and_then(|tail| tail.strip_prefix(' '))
        })
        .expect("named fixed vector");
    let (pairs, tail) = hex.as_bytes().as_chunks::<2>();
    assert!(tail.is_empty());
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn fixture(name: &str) -> Vec<u8> {
    decode(include_str!("fixtures/checkpoint_witness_v1.txt"), name)
}

fn key(name: &str) -> [u8; 32] {
    fixture(name).try_into().unwrap()
}

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-witness-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture: {error}"),
        }
    }
}

fn args(bytes: &[u8]) -> (Vec<OsString>, PathBuf) {
    let dir = directory();
    let path = dir.join("candidate");
    std::fs::write(&path, bytes).unwrap();
    let mut args = vec![
        "witness".into(),
        "--checkpoint".into(),
        path.into_os_string(),
        "--expect-book".into(),
        "11".repeat(16).into(),
        "--expect-branch".into(),
        "00".repeat(16).into(),
        "--expect-policy".into(),
        "55".repeat(32).into(),
        "--publisher-key".into(),
        hex(&key("publisher")).into(),
        "--quorum".into(),
        "2".into(),
        "--json".into(),
    ];
    for name in ["witness_a", "witness_b", "witness_c"] {
        args.extend(["--witness-key".into(), hex(&key(name)).into()]);
    }
    (args, dir)
}

fn run(args: &[OsString]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .args(args)
        .output()
        .expect("run offline binary")
}

fn result(output: Output, exit: i32) -> String {
    let text = String::from_utf8(output.stdout).unwrap();
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(exit), "{text}\n{err}");
    assert_eq!(text.lines().count(), 1, "one buffered JSON result: {text}");
    if exit == 0 {
        assert!(err.is_empty(), "{err}");
        assert!(text.contains("\"proof_kind\":\"witnessed_checkpoint\""));
        assert!(text.contains("\"verified\":true"));
        assert!(text.contains("\"pin_written\":false"));
    } else {
        assert!(text.contains("\"verified\":false"));
        assert!(text.contains("\"event\":\"error\""));
        assert!(!text.contains("proof_verified"));
        assert!(
            !text.contains("\"witnesses\":["),
            "no partial quorum report"
        );
    }
    assert!(!text.contains(&hex(&fixture("initial"))));
    text
}

fn set(args: &mut [OsString], flag: &str, value: impl Into<OsString>) {
    let index = args.iter().position(|arg| arg == flag).unwrap();
    args[index + 1] = value.into();
}

// Signature rows are outside the signed body. Removing one never re-signs it.
fn retain(bytes: &[u8], names: &[&str]) -> Vec<u8> {
    let ids: Vec<_> = names.iter().map(|name| signer_key_id(&key(name))).collect();
    let (rows, tail) = bytes[218..].as_chunks::<102>();
    assert!(tail.is_empty());
    let rows: Vec<_> = rows
        .iter()
        .filter(|row| ids.iter().any(|id| row[..32] == *id))
        .collect();
    let mut out = bytes[..214].to_vec();
    out.extend_from_slice(&u32::try_from(rows.len()).unwrap().to_le_bytes());
    for row in rows {
        out.extend_from_slice(row);
    }
    out
}

#[test]
fn actual_binary_verifies_distinct_quorums_and_marks_continuity_unchecked() {
    let bytes = fixture("initial");
    let (input, dir) = args(&bytes);
    let text = result(run(&input), 0);
    for value in [
        "\"through_seq\":\"7\"",
        "\"leaf_count\":\"1\"",
        "\"configured_witnesses\":3",
        "\"required_witnesses\":2",
        "\"continuity\":\"not_checked\"",
        "policy_registration",
        "global_freshness",
    ] {
        assert!(text.contains(value), "{value}: {text}");
    }
    for name in ["witness_a", "witness_b", "witness_c", "outsider"] {
        assert!(text.contains(&hex(&signer_key_id(&key(name)))));
    }
    assert_eq!(std::fs::read(dir.join("candidate")).unwrap(), bytes);
    assert_eq!(result(run(&input), 0), text);
    let subset = retain(&bytes, &["publisher", "witness_a", "witness_b"]);
    result(run(&args(&subset).0), 0);
}

#[test]
fn publisher_and_unknown_signers_cannot_replace_missing_witness_votes() {
    let initial = fixture("initial");
    result(run(&args(&initial).0), 0);
    for names in [
        vec!["publisher"],
        vec!["publisher", "outsider"],
        vec!["publisher", "witness_a", "outsider"],
        vec!["witness_a", "witness_b", "witness_c"],
    ] {
        let bytes = retain(&initial, &names);
        result(run(&args(&bytes).0), 8);
    }
    let mut bad = initial;
    let id = signer_key_id(&key("witness_c"));
    let row = bad[218..]
        .as_chunks_mut::<102>()
        .0
        .iter_mut()
        .find(|row| row[..32] == id)
        .unwrap();
    row[101] ^= 1;
    let (mut input, _) = args(&bad);
    set(&mut input, "--quorum", "1");
    result(run(&input), 8); // enough good signatures do not excuse a bad configured signature
}

#[test]
fn genuine_signatures_for_another_book_branch_or_policy_do_not_match() {
    for name in [
        "foreign_book",
        "foreign_branch",
        "other_policy",
        "missing_policy",
    ] {
        let bytes = fixture(name);
        assert!(fa_verify::verify_checkpoint(&bytes, &[key("publisher")]).is_ok());
        result(run(&args(&bytes).0), 8);
    }
}

#[test]
fn malformed_and_duplicate_requests_are_rejected_before_missing_input_files() {
    let (mut base, dir) = args(&fixture("initial"));
    set(
        &mut base,
        "--checkpoint",
        dir.join("missing").into_os_string(),
    );
    for flag in [
        "--checkpoint",
        "--expect-book",
        "--expect-branch",
        "--expect-policy",
        "--publisher-key",
        "--quorum",
    ] {
        let index = base.iter().position(|arg| arg == flag).unwrap();
        let mut missing = base.clone();
        drop(missing.drain(index..index + 2));
        result(run(&missing), 2);
        let mut repeated = base.clone();
        repeated.extend_from_slice(&base[index..index + 2]);
        result(run(&repeated), 2);
    }
    for (flag, value) in [
        ("--expect-book", "g".repeat(32)),
        ("--expect-policy", "00".repeat(31)),
        ("--publisher-key", "é".repeat(32)),
        ("--quorum", "0".into()),
        ("--quorum", "4".into()),
        ("--quorum", "+1".into()),
        ("--quorum", "1.0".into()),
        ("--publisher-key", hex(&key("witness_a"))),
        ("--witness-key", format!("01{}", "00".repeat(31))),
    ] {
        let mut invalid = base.clone();
        set(&mut invalid, flag, value);
        result(run(&invalid), 2);
    }
    for extra in [
        vec!["--json".into()],
        vec!["--unsigned-checkpoint".into()],
        vec!["--key".into(), hex(&key("publisher"))],
        vec!["--hex".into()],
        vec![
            "--witness-key".into(),
            hex(&key("witness_a")).to_uppercase(),
        ],
    ] {
        let mut invalid = base.clone();
        invalid.extend(extra.into_iter().map(OsString::from));
        result(run(&invalid), 2);
    }
    let mut excessive = base.clone();
    for _ in 0..61 {
        excessive.extend(["--witness-key".into(), hex(&key("outsider")).into()]);
    }
    result(run(&excessive), 2);
    result(run(&base), 5);
}

#[test]
fn malformed_raw_unsigned_and_oversized_checkpoints_never_fall_back() {
    let good = fixture("initial");
    let (input, dir) = args(&good);
    for end in [0, 3, 83, 213, 217, good.len() - 1] {
        std::fs::write(dir.join("candidate"), &good[..end]).unwrap();
        result(run(&input), 8);
    }
    let mut trailing = good.clone();
    trailing.push(0);
    std::fs::write(dir.join("candidate"), trailing).unwrap();
    result(run(&input), 8);
    std::fs::write(dir.join("candidate"), &good[4..84]).unwrap();
    result(run(&input), 8);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("candidate"))
        .unwrap();
    file.set_len(MAX_WITNESSED_CHECKPOINT_BYTES as u64 + 1)
        .unwrap();
    result(run(&input), 8);
}

#[test]
fn human_help_and_existing_any_signer_command_remain_available() {
    for words in [
        vec![],
        vec!["--help"],
        vec!["witness", "--help"],
        vec!["witness", "-h"],
    ] {
        let output = run(&words.into_iter().map(OsString::from).collect::<Vec<_>>());
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("fa-verify witness")
        );
    }
    let (mut input, dir) = args(&fixture("initial"));
    input.retain(|arg| arg != "--json");
    let output = run(&input);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Continuity and freshness were not checked"));
    assert!(text.contains("No pin was written"));
    let legacy: Vec<OsString> = vec![
        "checkpoint".into(),
        dir.join("candidate").into_os_string(),
        "--key".into(),
        hex(&key("publisher")).into(),
        "--json".into(),
    ];
    assert_eq!(run(&legacy).status.code(), Some(0));
}

#[cfg(unix)]
#[test]
fn non_utf8_paths_work_but_scalar_expectations_are_not_lossy() {
    use std::os::unix::ffi::OsStringExt;
    let (mut input, dir) = args(&fixture("initial"));
    let path = dir.join(OsString::from_vec(b"candidate-\xff".to_vec()));
    std::fs::copy(dir.join("candidate"), &path).unwrap();
    set(&mut input, "--checkpoint", path.into_os_string());
    result(run(&input), 0);
    for flag in [
        "--expect-policy",
        "--publisher-key",
        "--witness-key",
        "--quorum",
    ] {
        let mut invalid = input.clone();
        set(&mut invalid, flag, OsString::from_vec(vec![255]));
        result(run(&invalid), 2);
    }
}
