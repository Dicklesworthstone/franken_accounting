//! Native prefix v1/v2 assurance through the real standalone dispatcher.
//! Fixtures own their trusted checkpoints; this does not authenticate a signer
//! or assert kernel admission of the synthetic journal entries.

#[path = "fixtures/complete_balance.rs"]
mod balance_fixture;
#[path = "support/production.rs"]
mod fixture;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::proof::production::MAX_PRODUCTION_LEAVES;
use fa_verify::proof::production::derivation::{
    MAX_PREFIX_PROOF_BYTES, PREFIX_FORMAT_V2, verify_prefix_with_status,
};
use fa_verify::proof::{PREFIX_FORMAT, RecordCheck};
use fa_verify::{Checkpoint, VerifyError};
use fixture::{Fixture, SECRET, Wire, borrowed, record};

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-native-prefix-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        match fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
}

fn inputs(bytes: &[u8], checkpoint: &Checkpoint) -> (PathBuf, PathBuf) {
    let dir = directory();
    let proof = dir.join("journal.prefix");
    let anchor = dir.join("operator.checkpoint");
    fs::write(&proof, bytes).unwrap();
    fs::write(&anchor, checkpoint.encode()).unwrap();
    (proof, anchor)
}

fn run(proof: &Path, checkpoint: &Path, json: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fa-verify"));
    command
        .arg("prefix")
        .arg("--proof")
        .arg(proof)
        .arg("--checkpoint")
        .arg(checkpoint);
    if json {
        command.arg("--json");
    }
    command.output().expect("run offline prefix verification")
}

fn no_payload(text: &str) {
    assert!(!text.contains(std::str::from_utf8(SECRET).unwrap()));
    assert!(!text.contains(&fa_verify::blake3::hex(SECRET)));
}

fn json_result(output: Output, exit: i32) -> String {
    let out = String::from_utf8(output.stdout).unwrap();
    let err = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(exit), "{out}\n{err}");
    assert_eq!(out.lines().count(), 1, "one buffered result: {out}");
    no_payload(&out);
    no_payload(&err);
    if exit == 0 {
        assert!(err.is_empty(), "{err}");
        assert!(out.contains("\"verified\":true"));
        assert!(out.contains("\"proof_kind\":\"prefix\""));
        assert!(out.contains("\"scope\":\"seq_range_complete\""));
        assert!(out.contains("\"signature_verification\":\"not_performed\""));
    } else {
        assert!(out.contains("\"verified\":false"));
        assert!(out.contains("\"event\":\"error\""));
        assert!(!out.contains("proof_verified"));
        assert!(!out.contains("\"checks\":["));
        assert!(!err.is_empty());
    }
    out
}

fn legacy(f: &Fixture) -> Vec<u8> {
    let mut w = Wire::default();
    w.bytes(PREFIX_FORMAT)
        .fixed(&f.checkpoint.encode())
        .u32(f.records.len() as u32);
    for record in &f.records {
        w.bytes(&record.envelope.encode());
    }
    w.0
}

fn with_indexes(f: &Fixture, indexes: &[usize]) -> Vec<u8> {
    let mut w = Wire::default();
    w.bytes(PREFIX_FORMAT_V2)
        .fixed(&f.checkpoint.encode())
        .u32(f.records.len() as u32);
    for record in &f.records {
        w.bytes(&record.envelope.encode());
    }
    w.u32(indexes.len() as u32);
    for index in indexes {
        let record = &f.records[*index];
        w.u64(*index as u64)
            .u32(record.split as u32)
            .bytes(&record.payload);
    }
    w.0
}

#[test]
fn native_v2_and_legacy_v1_keep_different_assurance_for_the_same_checkpoint() {
    for f in [
        Fixture::new(vec![], 0),
        Fixture::new(vec![record(1, 0, 19, 0, None)], 1),
        Fixture::mixed(),
    ] {
        let complete = f.prefix();
        let old = legacy(&f);
        let native = verify_prefix_with_status(&complete, &f.checkpoint).unwrap();
        let membership = verify_prefix_with_status(&old, &f.checkpoint).unwrap();
        assert_eq!(native.record_check, RecordCheck::Recomputed);
        assert_eq!(membership.record_check, RecordCheck::NotSupplied);
        assert_eq!(native.prefix, membership.prefix);
        assert_eq!(complete, f.prefix());
        for (bytes, full) in [(&complete, true), (&old, false)] {
            let (proof, anchor) = inputs(bytes, &f.checkpoint);
            let out = json_result(run(&proof, &anchor, true), 0);
            assert!(out.contains(if full {
                "\"record_check\":\"recomputed\""
            } else {
                "\"record_check\":\"not_supplied\""
            }));
            assert!(out.contains(if full {
                "\"scope_derivation\":\"all_prefix_payloads_checked\""
            } else {
                "\"scope_derivation\":\"not_verified\""
            }));
            assert_eq!(out.contains("\"name\":\"record_recomputation\""), full);
            assert!(!out.contains("posted_balance_recomputation"));
            assert_eq!(fs::read(&proof).unwrap(), *bytes);
        }
    }
}

#[test]
fn library_cli_and_explicit_anchor_dispatch_preserve_native_prefix_assurance() {
    let f = Fixture::mixed();
    for (bytes, full) in [(f.prefix(), true), (legacy(&f), false)] {
        let verified = verify_prefix_with_status(&bytes, &f.checkpoint).unwrap();
        assert_eq!(
            verified.record_check,
            if full {
                RecordCheck::Recomputed
            } else {
                RecordCheck::NotSupplied
            }
        );
        let (proof, anchor) = inputs(&bytes, &f.checkpoint);
        for named_proof in [false, true] {
            let mut args = vec!["prefix".to_string()];
            if named_proof {
                args.push("--proof".into());
            }
            args.extend([
                proof.to_str().unwrap().into(),
                "--checkpoint".into(),
                anchor.to_str().unwrap().into(),
                "--unsigned-checkpoint".into(),
                "--json".into(),
            ]);
            let library = fa_verify::cli::run(&args, &|path| fs::read(path));
            assert_eq!(library.exit, 0, "{}\n{}", library.stdout, library.stderr);
            assert!(library.stderr.is_empty());
            assert!(library.stdout.contains("\"verdict\":\"verified\""));
            assert!(library.stdout.contains("\"scope\":\"seq_range_complete\""));
            assert!(library.stdout.contains(if full {
                "\"record_check\":\"recomputed\""
            } else {
                "\"record_check\":\"not_supplied\""
            }));
            assert!(library.stdout.contains(if full {
                "\"scope_derivation\":\"all_prefix_payloads_checked\""
            } else {
                "\"scope_derivation\":\"not_verified\""
            }));
            no_payload(&library.stdout);
            no_payload(&library.stderr);
            let binary = Command::new(env!("CARGO_BIN_EXE_fa-verify"))
                .args(&args)
                .output()
                .unwrap();
            assert_eq!(binary.status.code(), Some(0));
            assert_eq!(binary.stdout, library.stdout.as_bytes());
            assert_eq!(binary.stderr, library.stderr.as_bytes());
            assert_eq!(fs::read(&proof).unwrap(), bytes);
        }
    }

    let mut invalid = Vec::new();
    for indexes in [vec![], vec![0, 1, 2, 3, 4, 5], vec![0, 1, 2, 3, 4, 5, 5]] {
        invalid.push((with_indexes(&f, &indexes), f.checkpoint));
    }
    // The final byte is inside the final record payload. A same-length
    // change must fail recomputation against the unchanged trusted root.
    let mut changed = f.prefix();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    invalid.push((changed, f.checkpoint));
    let mut selector = record(1, 0, 1, 10, Some(10));
    selector.envelope.account_vids.clear();
    let selector = Fixture::new(vec![selector], 1);
    invalid.push((selector.prefix(), selector.checkpoint));
    let mut wrong = f.checkpoint;
    wrong.root[0] ^= 1;
    invalid.push((f.prefix(), wrong));
    let complete = f.prefix();
    invalid.push((complete[..complete.len() - 1].to_vec(), f.checkpoint));
    for (bytes, checkpoint) in invalid {
        let (proof, anchor) = inputs(&bytes, &checkpoint);
        let args = [
            "prefix",
            proof.to_str().unwrap(),
            "--checkpoint",
            anchor.to_str().unwrap(),
            "--unsigned-checkpoint",
            "--json",
        ]
        .map(str::to_string);
        let library = fa_verify::cli::run(&args, &|path| fs::read(path));
        assert_eq!(library.exit, 8, "{}\n{}", library.stdout, library.stderr);
        assert!(library.stdout.contains("\"verdict\":\"failed\""));
        assert!(!library.stdout.contains("\"record_check\":\"recomputed\""));
        no_payload(&library.stdout);
        no_payload(&library.stderr);
        let binary = Command::new(env!("CARGO_BIN_EXE_fa-verify"))
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(binary.status.code(), Some(8));
        assert_eq!(binary.stdout, library.stdout.as_bytes());
        assert_eq!(binary.stderr, library.stderr.as_bytes());
        assert_eq!(fs::read(&proof).unwrap(), bytes);
    }
}

#[test]
fn missing_duplicate_and_out_of_order_payloads_never_publish_partial_success() {
    let f = Fixture::mixed();
    for indexes in [
        vec![],
        vec![0, 1, 2, 3, 4, 5],
        vec![0, 1, 2, 3, 4, 5, 5],
        vec![0, 1, 2, 3, 4, 6, 5],
    ] {
        let (proof, anchor) = inputs(&with_indexes(&f, &indexes), &f.checkpoint);
        json_result(run(&proof, &anchor, true), 8);
    }
    let complete = f.prefix();
    for end in [0, 4, complete.len() / 2, complete.len() - 1] {
        let (proof, anchor) = inputs(&complete[..end], &f.checkpoint);
        json_result(run(&proof, &anchor, true), 8);
    }
    let mut trailing = complete;
    trailing.push(0);
    let (proof, anchor) = inputs(&trailing, &f.checkpoint);
    json_result(run(&proof, &anchor, true), 8);
    let mut relabeled = legacy(&f);
    // Equal-length version tags; retagging cannot supply the missing payloads.
    relabeled[4..4 + PREFIX_FORMAT_V2.len()].copy_from_slice(PREFIX_FORMAT_V2);
    let (proof, anchor) = inputs(&relabeled, &f.checkpoint);
    json_result(run(&proof, &anchor, true), 8);
}

#[test]
fn every_payload_is_required_even_when_a_later_production_would_exclude_it() {
    let f = Fixture::mixed();
    let selected = f.inclusions(&[0, 2, 3]);
    let requested = fa_verify::proof::production::ProductionScope {
        first_seq: 0,
        known_at: 5,
        account: Some(10),
        effective_days: Some((10, 20)),
    };
    assert!(
        fa_verify::proof::production::verify_production_for(
            &f.prefix(),
            &borrowed(&selected),
            &f.checkpoint,
            &requested,
        )
        .is_ok()
    );
    for index in 0..f.records.len() {
        let mut changed = Fixture::mixed();
        let offset = changed.records[index]
            .payload
            .windows(SECRET.len())
            .position(|bytes| bytes == SECRET)
            .unwrap();
        changed.records[index].payload[offset] ^= 1;
        let (proof, anchor) = inputs(&changed.prefix(), &changed.checkpoint);
        json_result(run(&proof, &anchor, true), 8);
    }
    // Deliberately commit an inconsistent selector and trust that exact root.
    // This reaches payload derivation, not a trivial stale-root failure.
    let mut entry = record(1, 0, 1, 10, Some(10));
    entry.envelope.account_vids.clear();
    let inconsistent = Fixture::new(vec![entry], 1);
    assert!(matches!(
        verify_prefix_with_status(&inconsistent.prefix(), &inconsistent.checkpoint),
        Err(VerifyError::Record(fa_verify::RecordError::Envelope))
    ));
    let (proof, anchor) = inputs(&inconsistent.prefix(), &inconsistent.checkpoint);
    json_result(run(&proof, &anchor, true), 8);
}

#[test]
fn native_prefix_dispatch_does_not_reinterpret_another_proof_kind_or_trust_its_anchor() {
    let f = Fixture::mixed();
    let mut wrong = f.checkpoint;
    wrong.root[0] ^= 1;
    let (proof, anchor) = inputs(&f.prefix(), &wrong);
    json_result(run(&proof, &anchor, true), 8);
    let (balance, trusted) = balance_fixture::fixture();
    assert!(fa_verify::verify_balance(&balance, &trusted).is_ok());
    assert!(matches!(
        verify_prefix_with_status(&balance, &trusted),
        Err(VerifyError::Format { .. })
    ));
    let (proof, anchor) = inputs(&balance, &trusted);
    json_result(run(&proof, &anchor, true), 8);
    let inclusion = f.inclusion(0, true);
    let (proof, anchor) = inputs(&inclusion, &f.checkpoint);
    json_result(run(&proof, &anchor, true), 8);
}

#[test]
fn encoded_byte_and_declared_leaf_budgets_are_checked_before_allocating_payloads() {
    let f = Fixture::new(vec![], 0);
    let (proof, anchor) = inputs(&f.prefix(), &f.checkpoint);
    fs::OpenOptions::new()
        .write(true)
        .open(&proof)
        .unwrap()
        .set_len(MAX_PREFIX_PROOF_BYTES as u64 + 1)
        .unwrap();
    json_result(run(&proof, &anchor, true), 8);
    let mut oversized = Wire::default();
    oversized
        .bytes(PREFIX_FORMAT_V2)
        .fixed(&f.checkpoint.encode())
        .u32(MAX_PRODUCTION_LEAVES as u32 + 1);
    assert!(matches!(
        verify_prefix_with_status(&oversized.0, &f.checkpoint),
        Err(VerifyError::Decode(_))
    ));
    let (proof, anchor) = inputs(&oversized.0, &f.checkpoint);
    json_result(run(&proof, &anchor, true), 8);
}

#[test]
fn human_reports_and_help_explain_payload_scope_without_echoing_entry_bytes() {
    let f = Fixture::mixed();
    for (bytes, full) in [(f.prefix(), true), (legacy(&f), false)] {
        let (proof, anchor) = inputs(&bytes, &f.checkpoint);
        let output = run(&proof, &anchor, false);
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        no_payload(&text);
        assert!(text.contains(if full {
            "every entry payload and scope selector was recomputed"
        } else {
            "payloads were not recomputed"
        }));
        assert!(text.contains("signatures and origin authenticity were not checked"));
    }
    let help = Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("fa proof prefix --with-record"));
    assert!(help.contains("Prefix v1 checks envelope membership only"));
}
