//! Process-level request binding: a valid proof is not necessarily the
//! answer the recipient asked for. Inputs and failures are retained.

#[path = "fixtures/complete_balance.rs"]
mod complete_balance;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::codec::Writer;
use fa_verify::{Checkpoint, verify_state};

const SCOPE: [&str; 6] = [
    "--expect-account",
    "00000000000000000000000000000030",
    "--expect-unit",
    "1",
    "--expect-through",
    "none",
];
const AMOUNTS: [&str; 4] = ["--expect-debits", "0", "--expect-credits", "120550"];

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-verify-expectations-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
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

fn vector(name: &str) -> Vec<u8> {
    let text = include_str!("fixtures/accumulator_v1.txt")
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
        .expect("frozen vector");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

fn inputs(dir: &Path, proof: &[u8], checkpoint: &Checkpoint) -> (PathBuf, PathBuf) {
    let proof_path = dir.join("balance.proof");
    let checkpoint_path = dir.join("trusted.checkpoint");
    fs::write(&proof_path, proof).unwrap();
    fs::write(&checkpoint_path, checkpoint.encode()).unwrap();
    (proof_path, checkpoint_path)
}

fn run(kind: &str, proof: &Path, checkpoint: &Path, flags: &[&str], json: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fa-verify"));
    command
        .arg(kind)
        .arg("--proof")
        .arg(proof)
        .arg("--checkpoint")
        .arg(checkpoint)
        .args(flags);
    if json {
        command.arg("--json");
    }
    command.output().unwrap()
}

fn result(output: Output, exit: i32) -> String {
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(exit), "{stdout}\n{stderr}");
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    if exit == 0 {
        assert!(stderr.is_empty(), "{stderr}");
        assert!(stdout.contains("\"verified\":true"));
        assert!(stdout.contains("\"signature_verification\":\"not_performed\""));
    } else {
        assert!(!stderr.is_empty());
        assert!(stdout.contains("\"verified\":false"));
        assert!(!stdout.contains("proof_verified"));
        let class = match exit {
            2 => "usage",
            5 => "foundation",
            _ => "verification",
        };
        assert!(stdout.contains(&format!("\"class\":\"{class}\"")));
    }
    stdout
}

#[test]
fn complete_balance_requires_the_requested_scope_and_gross_amounts() {
    let dir = directory();
    let (bytes, checkpoint) = complete_balance::fixture();
    let (proof, anchor) = inputs(&dir, &bytes, &checkpoint);
    let mut flags = SCOPE.to_vec();
    flags.extend(AMOUNTS);
    let stdout = result(run("balance", &proof, &anchor, &flags, true), 0);
    assert!(stdout.contains("\"name\":\"requested_balance_scope\""));
    assert!(stdout.contains("\"name\":\"requested_balance_amounts\""));
    assert!(stdout.contains("\"scope\":\"recomputation\""));
    assert!(stdout.contains("\"balance_complete\":true"));
    assert!(stdout.contains("\"scope_derivation\":\"all_prefix_payloads_checked\""));
    assert!(stdout.contains("\"name\":\"posted_balance_recomputation\""));
    let scope_only = result(run("balance", &proof, &anchor, &SCOPE, true), 0);
    assert!(scope_only.contains("requested_balance_scope"));
    assert!(!scope_only.contains("requested_balance_amounts"));
    let inspection = result(run("balance", &proof, &anchor, &[], true), 0);
    assert!(!inspection.contains("requested_balance_"));

    for (position, other) in [
        (1, "00000000000000000000000000000031"),
        (3, "2"),
        (5, "0"),
        (7, "1"),
        (9, "120551"),
    ] {
        let mut wrong = flags.clone();
        wrong[position] = other;
        let stdout = result(run("balance", &proof, &anchor, &wrong, true), 8);
        assert!(stdout.contains(if position < 6 {
            "balance scope mismatch"
        } else {
            "balance amounts mismatch"
        }));
    }
    // Same net credit as 0 / 120550, but neither gross column matches.
    flags[7] = "1";
    flags[9] = "120551";
    let stdout = result(run("balance", &proof, &anchor, &flags, true), 8);
    assert!(stdout.contains("balance amounts mismatch"));
}

#[test]
fn frozen_legacy_membership_never_satisfies_a_complete_balance_request() {
    // Preserve the v1 golden bytes. They carry four envelopes but only the
    // two selected entry payloads; the omitted controls' indexing is unproven.
    let bytes = vector("balance");
    let checkpoint = verify_state(&vector("state")).unwrap().checkpoint;
    let (proof, anchor) = inputs(&directory(), &bytes, &checkpoint);
    let inspected = result(run("balance", &proof, &anchor, &[], true), 0);
    assert!(inspected.contains("\"scope\":\"membership_only\""));
    assert!(inspected.contains("\"balance_complete\":false"));
    assert!(inspected.contains("\"scope_derivation\":\"not_verified\""));
    assert!(inspected.contains("selected_amount_recomputation"));
    assert!(!inspected.contains("posted_balance_recomputation"));
    assert!(!inspected.contains("exact_contributing_record_set"));
    let mut exact = SCOPE.to_vec();
    exact.extend(AMOUNTS);
    for flags in [&SCOPE[..], exact.as_slice()] {
        let rejected = result(run("balance", &proof, &anchor, flags, true), 8);
        assert!(rejected.contains("balance completeness is not independently verified"));
    }
    let human = run("balance", &proof, &anchor, &[], false);
    assert!(human.status.success());
    assert!(
        String::from_utf8(human.stdout)
            .unwrap()
            .contains("completeness NOT proven")
    );
    assert_eq!(fs::read(&proof).unwrap(), bytes);
}

#[test]
fn migration_and_complete_dispatch_bind_explicit_cutoffs_in_the_standalone_process() {
    let checkpoint = Checkpoint {
        book_id: [1; 16],
        branch_id: [0; 16],
        through_seq: 0,
        leaf_count: 0,
        root: fa_verify::tree::empty_root(),
    };
    for format in [
        fa_verify::migration_balance::BALANCE_FORMAT_V2,
        fa_verify::migration_balance::BALANCE_FORMAT_V3,
    ] {
        for through in [None, Some(i32::MIN), Some(0), Some(i32::MAX)] {
            let mut writer = Writer::default();
            writer
                .bytes(format)
                .fixed(&checkpoint.encode())
                .u128(0x30)
                .u32(1);
            match through {
                Some(day) => {
                    writer.u8(1).i32(day);
                }
                None => {
                    writer.u8(0);
                }
            }
            writer.i128(0).i128(0).count(0).count(0).count(0);
            let dir = directory();
            let (proof, anchor) = inputs(&dir, &writer.buf, &checkpoint);
            let cutoff = through.map_or_else(|| "none".to_string(), |day| day.to_string());
            let mut flags = SCOPE.to_vec();
            flags[5] = &cutoff;
            flags.extend(["--expect-debits", "0", "--expect-credits", "0"]);
            result(run("balance", &proof, &anchor, &flags, true), 0);
            flags[5] = if through.is_some() { "none" } else { "0" };
            assert!(
                result(run("balance", &proof, &anchor, &flags, true), 8)
                    .contains("balance scope mismatch")
            );
        }
    }
}

#[test]
fn request_matching_never_masks_a_wrong_anchor_or_corrupt_proof() {
    let dir = directory();
    let mut checkpoint = verify_state(&vector("state")).unwrap().checkpoint;
    checkpoint.book_id[0] ^= 1;
    let (proof, anchor) = inputs(&dir, &vector("balance"), &checkpoint);
    let stdout = result(run("balance", &proof, &anchor, &SCOPE, true), 8);
    assert!(!stdout.contains("balance scope mismatch"));
    let checkpoint = verify_state(&vector("state")).unwrap().checkpoint;
    let (proof, anchor) = inputs(&directory(), &[0, 1, 2], &checkpoint);
    let stdout = result(run("balance", &proof, &anchor, &SCOPE, true), 8);
    assert!(!stdout.contains("balance scope mismatch"));
}

#[test]
fn all_request_options_are_validated_before_any_input_is_opened() {
    let dir = directory();
    let missing = dir.join("does-not-exist");
    for flags in [
        vec!["--expect-unit", "1"],
        vec!["--expect-through", "none"],
        vec!["--expect-account", "30"],
        vec!["--expect-unit", "4294967296"],
        vec!["--expect-through", "2147483648"],
        vec!["--expect-debits", "1e6"],
        vec!["--expect-credits", "-1"],
        vec!["--expect-through"],
    ] {
        result(run("balance", &missing, &missing, &flags, true), 2);
    }
    for extra in [
        vec!["--expect-debits", "0"],
        vec!["--expect-through", "none"],
    ] {
        let mut flags = SCOPE.to_vec();
        flags.extend(extra);
        result(run("balance", &missing, &missing, &flags, true), 2);
    }
    for kind in ["inclusion", "prefix", "consistency"] {
        let mut flags = SCOPE.to_vec();
        if kind == "consistency" {
            flags.extend(["--next-checkpoint", "missing-next"]);
        }
        let stdout = result(run(kind, &missing, &missing, &flags, true), 2);
        assert!(stdout.contains("admitted only for balance"));
    }
}

#[test]
fn human_mode_distinguishes_requested_verification_from_claim_inspection() {
    let (bytes, checkpoint) = complete_balance::fixture();
    let (proof, anchor) = inputs(&directory(), &bytes, &checkpoint);
    let output = run("balance", &proof, &anchor, &SCOPE, false);
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("recipient scope matched")
    );
    let output = run("balance", &proof, &anchor, &[], false);
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("no independently specified balance request was checked")
    );
    let mut flags = SCOPE.to_vec();
    flags[3] = "2";
    let output = run("balance", &proof, &anchor, &flags, false);
    assert_eq!(output.status.code(), Some(8));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("balance scope mismatch")
    );
}

#[cfg(unix)]
#[test]
fn request_flags_preserve_non_utf8_input_paths() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let dir = directory();
    let proof = dir.join(OsString::from_vec(b"proof-\xff".to_vec()));
    let anchor = dir.join(OsString::from_vec(b"anchor-\xfe".to_vec()));
    let (bytes, checkpoint) = complete_balance::fixture();
    match fs::write(&proof, bytes) {
        Ok(()) => {
            fs::write(&anchor, checkpoint.encode()).unwrap();
            result(run("balance", &proof, &anchor, &SCOPE, true), 0);
        }
        Err(e) if e.raw_os_error() == Some(92) => {
            result(run("balance", &proof, &anchor, &SCOPE, true), 5);
        }
        Err(e) => panic!("unexpected write error: {e:?}"),
    }
}
