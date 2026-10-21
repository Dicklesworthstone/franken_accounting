//! Actual executable coverage using existing fixed signed checkpoint vectors.
//! This file never signs, regenerates fixtures, or requires a book/network.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::blake3::hex;
use fa_verify::bundle::{BUNDLE_FORMAT, BundleScope, Completeness, Manifest, Summary, manifest_md};
use fa_verify::checkpoint::{signer_key_id, verify_checkpoint};
use fa_verify::checkpoint::witness::bundle::{MAX_WITNESSED_BUNDLE_BYTES, MAX_WITNESSED_RECEIPT_BYTES};

fn fixture(name: &str) -> Vec<u8> {
    let initial = include_str!("fixtures/checkpoint_witness_v1.txt");
    let advance = include_str!("fixtures/checkpoint_witness_advance_v1.txt");
    let text = initial.lines().chain(advance.lines())
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' ')).unwrap();
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn key(name: &str) -> [u8; 32] { fixture(name).try_into().unwrap() }

fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
    out.extend_from_slice(value);
}

fn bundle(checkpoint: &[u8]) -> Vec<u8> {
    let signed = verify_checkpoint(checkpoint, &[key("publisher")]).unwrap();
    let cp = signed.checkpoint;
    let m = Manifest { book_id: cp.book_id, branch_id: cp.branch_id, through_seq: cp.through_seq,
        leaf_count: cp.leaf_count, checkpoint_oid: signed.oid,
        scope: BundleScope::Entries(vec![]), completeness: Completeness::FilterAttested };
    let summary = Summary { format: (1, 0), entries: 0, documents: 0, inline: 0, balances: vec![] };
    let mut out = Vec::new();
    bytes(&mut out, BUNDLE_FORMAT);
    out.extend_from_slice(&1u16.to_le_bytes()); out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&cp.book_id); out.extend_from_slice(&cp.branch_id);
    out.extend_from_slice(&cp.through_seq.to_le_bytes()); out.extend_from_slice(&cp.leaf_count.to_le_bytes());
    out.extend_from_slice(&signed.oid); out.push(3); out.extend_from_slice(&0u32.to_le_bytes()); out.push(3);
    bytes(&mut out, checkpoint);
    for _ in 0..3 { out.extend_from_slice(&0u32.to_le_bytes()); } // members, entries, balances
    bytes(&mut out, manifest_md(&m, &summary).as_bytes());
    out
}

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!("fa-witness-bundle-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture: {error}"),
        }
    }
}

fn args() -> (Vec<OsString>, PathBuf) {
    let dir = directory();
    std::fs::write(dir.join("checkpoint"), fixture("initial")).unwrap();
    std::fs::write(dir.join("bundle"), bundle(&fixture("initial"))).unwrap();
    let mut result: Vec<OsString> = ["witness", "bundle", "--checkpoint"].map(OsString::from).into();
    result.push(dir.join("checkpoint").into_os_string());
    for (flag, value) in [
        ("--expect-book", "11".repeat(16)), ("--expect-branch", "00".repeat(16)),
        ("--expect-policy", "55".repeat(32)), ("--publisher-key", hex(&key("publisher"))),
        ("--witness-key", hex(&key("witness_a"))), ("--witness-key", hex(&key("witness_b"))),
        ("--quorum", "2".into()), ("--expect-scope", "entries".into()),
        ("--expect-leaves", "none".into()), ("--expect-documents", "inline".into()),
        ("--expect-receipt", "optional".into()),
    ] { result.extend([flag.into(), value.into()]); }
    result.extend(["--bundle".into(), dir.join("bundle").into_os_string(), "--json".into()]);
    (result, dir)
}

fn set(args: &mut [OsString], flag: &str, value: impl Into<OsString>) {
    let index = args.iter().position(|arg| arg == flag).unwrap();
    args[index + 1] = value.into();
}

fn remove(args: &mut Vec<OsString>, flag: &str) {
    let index = args.iter().position(|arg| arg == flag).unwrap();
    drop(args.drain(index..index + 2));
}

fn run(args: &[OsString]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fa-verify")).args(args).output().expect("run actual binary")
}

fn result(output: Output, exit: i32) -> String {
    let out = String::from_utf8(output.stdout).unwrap();
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(exit), "{out}\n{err}");
    assert_eq!(out.lines().count(), 1, "one JSON report, not a partial result");
    if exit == 0 {
        assert!(err.is_empty());
        assert!(out.contains("\"verified\":true"));
        assert!(out.contains("\"proof_kind\":\"witnessed_bundle\""));
        assert!(out.contains("\"pin_written\":false"));
    } else {
        assert!(out.contains("\"verified\":false"));
        assert!(!out.contains("proof_verified"));
    }
    out
}

#[test]
fn matching_bundle_reports_per_predicate_assurance_and_preserves_inputs() {
    let (input, dir) = args();
    let expected = std::fs::read(dir.join("bundle")).unwrap();
    let output = result(run(&input), 0);
    for text in ["witnessed_checkpoint_binding", "requested_bundle_scope", "requested_document_disclosure",
        "requested_publisher_receipt", "\"completeness\":\"membership_only\"",
        "\"continuity\":\"not_checked\"", "\"through_seq\":\"7\""]
    { assert!(output.contains(text)); }
    assert_eq!(std::fs::read(dir.join("bundle")).unwrap(), expected);
    assert_eq!(std::fs::read(dir.join("checkpoint")).unwrap(), fixture("initial"));
    assert_eq!(result(run(&input), 0), output);
}

#[test]
fn different_genuine_checkpoints_and_stripped_signatures_do_not_borrow_a_quorum() {
    let (input, dir) = args();
    let full = fixture("initial");
    let id = signer_key_id(&key("publisher"));
    let row = full[218..].as_chunks::<102>().0.iter().find(|row| row[..32] == id).unwrap();
    let mut stripped = full[..214].to_vec();
    stripped.extend_from_slice(&1u32.to_le_bytes()); stripped.extend_from_slice(row);
    for cp in [fixture("extended"), fixture("foreign_book"), stripped] {
        std::fs::write(dir.join("bundle"), bundle(&cp)).unwrap();
        let output = result(run(&input), 8);
        assert!(output.contains("witnessed_checkpoint_binding"));
        assert!(output.contains("\"status\":\"fail\""));
        assert!(output.contains("\"status\":\"unrun\""));
    }
}

#[test]
fn recipient_scope_and_receipt_requirements_are_load_bearing() {
    let (input, dir) = args();
    let mut changed = input.clone();
    set(&mut changed, "--expect-leaves", "0");
    assert!(result(run(&changed), 8).contains("bundle scope differs"));
    let mut changed = input.clone();
    set(&mut changed, "--expect-scope", "prefix"); remove(&mut changed, "--expect-leaves");
    assert!(result(run(&changed), 8).contains("requested_bundle_scope"));
    let mut changed = input.clone();
    set(&mut changed, "--expect-receipt", "publisher");
    assert!(result(run(&changed), 8).contains("receipt is absent or invalid"));
    std::fs::write(dir.join("receipt"), b"NEVER_ECHO_RECEIPT_SOURCE_BYTES").unwrap();
    changed.extend(["--receipt".into(), dir.join("receipt").into_os_string()]);
    let out = result(run(&changed), 8);
    assert!(!out.contains("NEVER_ECHO_RECEIPT_SOURCE_BYTES"));
}

#[test]
fn complete_syntax_and_policy_validation_precede_all_file_reads() {
    let (mut base, dir) = args();
    set(&mut base, "--checkpoint", dir.join("absent").into_os_string());
    for flag in ["--bundle", "--expect-scope", "--expect-leaves", "--expect-documents", "--expect-receipt"] {
        let mut bad = base.clone(); remove(&mut bad, flag); result(run(&bad), 2);
        let mut bad = base.clone();
        let pos = base.iter().position(|arg| arg == flag).unwrap();
        bad.extend_from_slice(&base[pos..pos + 2]); result(run(&bad), 2);
    }
    for (flag, value) in [("--expect-leaves", "0,0"), ("--expect-leaves", "1,0"),
        ("--expect-leaves", "+1"), ("--expect-leaves", "18446744073709551616"),
        ("--expect-documents", "all"), ("--expect-receipt", "any-key"), ("--quorum", "0")]
    {
        let mut bad = base.clone(); set(&mut bad, flag, value); result(run(&bad), 2);
    }
    let mut bad = base.clone();
    bad.extend(["--expect-account".into(), "00".repeat(16).into()]); result(run(&bad), 2);
    let mut bad = base.clone(); bad.push("--json".into()); result(run(&bad), 2);
    let mut bad = base.clone();
    set(&mut bad, "--expect-scope", "account"); remove(&mut bad, "--expect-leaves");
    bad.extend(["--expect-account".into(), "00".repeat(16).into(), "--expect-days".into(), "2:1".into()]);
    result(run(&bad), 2);
    result(run(&base), 5);
}

#[test]
fn continuity_and_retained_body_binding_run_before_bundle_verification() {
    let (mut input, dir) = args();
    let previous = fixture("initial");
    let body = verify_checkpoint(&previous, &[key("publisher")]).unwrap().body_digest;
    std::fs::write(dir.join("previous"), &previous).unwrap();
    std::fs::write(dir.join("checkpoint"), fixture("extended")).unwrap();
    std::fs::write(dir.join("proof"), fixture("extend_proof")).unwrap();
    std::fs::write(dir.join("bundle"), bundle(&fixture("extended"))).unwrap();
    input.extend(["--previous".into(), dir.join("previous").into_os_string(),
        "--expect-previous-body".into(), hex(&body).into(),
        "--consistency".into(), dir.join("proof").into_os_string()]);
    let out = result(run(&input), 0);
    assert!(out.contains("\"continuity\":\"advanced\""));
    assert!(out.contains("\"through_seq\":\"9\""));
    let old_bundle = bundle(&previous);
    std::fs::write(dir.join("bundle"), old_bundle).unwrap(); result(run(&input), 8);
    std::fs::write(dir.join("previous"), fixture("empty")).unwrap();
    set(&mut input, "--bundle", dir.join("absent").into_os_string());
    assert!(result(run(&input), 8).contains("independently retained body digest"));
    remove(&mut input, "--consistency"); result(run(&input), 2);
}

#[test]
fn failed_quorum_and_oversized_or_malformed_artifacts_never_emit_success() {
    let (input, dir) = args();
    let mut bad_policy = input.clone(); set(&mut bad_policy, "--expect-policy", "aa".repeat(32));
    set(&mut bad_policy, "--bundle", dir.join("absent").into_os_string());
    result(run(&bad_policy), 8);
    let good = std::fs::read(dir.join("bundle")).unwrap();
    for end in [0, 1, good.len() - 1] {
        std::fs::write(dir.join("bundle"), &good[..end]).unwrap(); result(run(&input), 8);
    }
    let mut trailing = good.clone(); trailing.push(0);
    std::fs::write(dir.join("bundle"), trailing).unwrap(); result(run(&input), 8);
    let file = std::fs::OpenOptions::new().write(true).open(dir.join("bundle")).unwrap();
    file.set_len(MAX_WITNESSED_BUNDLE_BYTES as u64 + 1).unwrap(); result(run(&input), 8);
    std::fs::write(dir.join("bundle"), good).unwrap();
    std::fs::write(dir.join("receipt"), vec![0; MAX_WITNESSED_RECEIPT_BYTES + 1]).unwrap();
    let mut input = input; input.extend(["--receipt".into(), dir.join("receipt").into_os_string()]);
    result(run(&input), 8);
}

#[test]
fn human_reports_help_and_legacy_witness_mode_keep_their_boundaries() {
    for words in [vec!["witness", "--help"], vec!["witness", "bundle", "--help"]] {
        let out = run(&words.into_iter().map(OsString::from).collect::<Vec<_>>());
        assert_eq!(out.status.code(), Some(0)); assert!(out.stderr.is_empty());
        assert!(String::from_utf8(out.stdout).unwrap().contains("bundle"));
    }
    let (mut input, _) = args(); input.retain(|arg| arg != "--json");
    let out = run(&input); assert_eq!(out.status.code(), Some(0)); assert!(out.stderr.is_empty());
    let out = String::from_utf8(out.stdout).unwrap();
    assert!(out.contains("every required predicate passed")); assert!(out.contains("membership_only"));
    assert!(out.contains("not independently recomputed"));
    set(&mut input, "--expect-leaves", "0");
    let out = run(&input); assert_eq!(out.status.code(), Some(8));
    assert!(String::from_utf8(out.stdout).unwrap().contains("verification failed"));
    let (mut old, _) = args(); old.remove(1);
    for flag in ["--bundle", "--expect-scope", "--expect-leaves", "--expect-documents", "--expect-receipt"] { remove(&mut old, flag); }
    let out = run(&old); assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8(out.stdout).unwrap().contains("\"proof_kind\":\"witnessed_checkpoint\""));
}

#[cfg(unix)]
#[test]
fn raw_paths_remain_usable_and_non_ascii_selectors_are_refused() {
    use std::os::unix::ffi::OsStringExt;
    let (mut input, dir) = args();
    let path = dir.join(OsString::from_vec(b"bundle-\xff".to_vec()));
    std::fs::copy(dir.join("bundle"), &path).unwrap();
    set(&mut input, "--bundle", path.into_os_string()); result(run(&input), 0);
    set(&mut input, "--expect-leaves", OsString::from_vec(vec![255])); result(run(&input), 2);
}
