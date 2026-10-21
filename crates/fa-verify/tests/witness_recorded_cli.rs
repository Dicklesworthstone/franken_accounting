//! Execute the real offline binary with independently signed recorded-history
//! fixtures. Input files are retained for diagnosis; payloads must never print.

#[path = "support/recorded_vectors.rs"]
mod vectors;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::blake3::{hash_parts, hex};
use fa_verify::bundle::{BUNDLE_FORMAT, BundleScope, Completeness, Manifest, Summary, manifest_md};
use fa_verify::checkpoint::verify_checkpoint;
use fa_verify::checkpoint::witness::recorded::MAX_RECORDED_ADVANCE_BYTES;
use fa_verify::envelope::{ENTRY_DIGEST_DOMAIN, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry};
use fa_verify::proof::production::derivation::PREFIX_FORMAT_V2;
use fa_verify::proof::{CONSISTENCY_FORMAT, PREFIX_FORMAT};
use fa_verify::tree::{leaf_hash, root_of};
use fa_verify::{Checkpoint, SignedCheckpoint};

const SECRET: &[u8] = b"RECORDED_PAYLOAD_NOT_FOR_STDOUT";

fn decode(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len()).step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

#[derive(Default)]
struct Wire(Vec<u8>);

impl Wire {
    fn fixed(&mut self, bytes: &[u8]) -> &mut Self { self.0.extend_from_slice(bytes); self }
    fn u8(&mut self, n: u8) -> &mut Self { self.fixed(&[n]) }
    fn u16(&mut self, n: u16) -> &mut Self { self.fixed(&n.to_le_bytes()) }
    fn u32(&mut self, n: u32) -> &mut Self { self.fixed(&n.to_le_bytes()) }
    fn u64(&mut self, n: u64) -> &mut Self { self.fixed(&n.to_le_bytes()) }
    fn u128(&mut self, n: u128) -> &mut Self { self.fixed(&n.to_le_bytes()) }
    fn i128(&mut self, n: i128) -> &mut Self { self.fixed(&n.to_le_bytes()) }
    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.u32(u32::try_from(b.len()).unwrap()).fixed(b)
    }
}

fn record(index: usize, sequence: u64, day: i32) -> (Vec<u8>, Vec<u8>, usize) {
    let mut p = Wire::default();
    p.u16(1).u16(1).fixed(&[0x42; 16]).fixed(&[0; 16]).u16(1)
        .fixed(&day.to_le_bytes()).u8(0)
        .fixed(&[0; 32]).u8(0).fixed(&[0; 24]).bytes(SECRET).u8(0).u32(2);
    for (side, account) in [(0, 10), (1, 20)] {
        p.u8(side).u128(account).u32(1).i128(123).u8(0).u32(0).u8(0).u32(0);
    }
    p.u8(0).u32(1).u32(1).i128(123).i128(123).u8(0)
        .bytes(format!("record-{index}").as_bytes()).u8(0).fixed(&[9; 32]).u16(1)
        .u128(7).u8(0).u32(0).u32(0).u8(0).u32(0).u32(0).u32(0);
    let split = p.0.len();
    let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&p.0]);
    let entry_digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &[0; 5]]);
    p.fixed(&[0; 5]).fixed(&proposal_digest).fixed(&entry_digest);
    let envelope = envelope_of_entry(&p.0, split, sequence, 0).unwrap().encode();
    (envelope, p.0, split)
}

struct Artifact {
    bytes: Vec<u8>,
    signed: SignedCheckpoint,
    envelopes: Vec<Vec<u8>>,
    prefix: Vec<u8>,
}

fn artifact(signed_hex: &str, rows: &[(u64, i32)]) -> Artifact {
    let bytes = decode(signed_hex);
    let keys = [vectors::PUBLISHER, vectors::WITNESS_A, vectors::WITNESS_B]
        .map(|key| decode(key).try_into().unwrap());
    let signed = verify_checkpoint(&bytes, &keys).unwrap();
    let records: Vec<_> = rows.iter().enumerate()
        .map(|(index, (sequence, day))| record(index, *sequence, *day)).collect();
    let envelopes: Vec<_> = records.iter().map(|(env, _, _)| env.clone()).collect();
    assert_eq!(signed.checkpoint.leaf_count, rows.len() as u64);
    assert_eq!(signed.checkpoint.root, root_of(&envelopes.iter().map(|e| leaf_hash(e)).collect::<Vec<_>>()));
    let mut prefix = prefix(&signed.checkpoint, &envelopes, PREFIX_FORMAT_V2);
    prefix.u32(u32::try_from(records.len()).unwrap());
    for (index, (_, payload, split)) in records.iter().enumerate() {
        prefix.u64(index as u64).u32(u32::try_from(*split).unwrap()).bytes(payload);
    }
    Artifact { bytes, signed, envelopes, prefix: prefix.0 }
}

fn prefix(cp: &Checkpoint, envelopes: &[Vec<u8>], format: &[u8]) -> Wire {
    let mut out = Wire::default();
    out.bytes(format).fixed(&cp.encode()).u32(u32::try_from(envelopes.len()).unwrap());
    for envelope in envelopes { out.bytes(envelope); }
    out
}

fn consistency(old: &Artifact, new: &Artifact) -> Vec<u8> {
    let mut w = Wire::default();
    w.bytes(CONSISTENCY_FORMAT).fixed(&old.signed.checkpoint.encode())
        .fixed(&new.signed.checkpoint.encode());
    if old.envelopes.len() == 1 && new.envelopes.len() == 2 {
        assert_eq!(old.envelopes[0], new.envelopes[0]);
        w.u32(1).fixed(&leaf_hash(&new.envelopes[1]));
    } else {
        assert_eq!(old.envelopes, new.envelopes);
        w.u32(0);
    }
    w.0
}

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let dir = std::env::temp_dir().join(format!("fa-recorded-cli-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        match std::fs::create_dir(&dir) {
            Ok(()) => return dir,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => panic!("create retained fixture: {e}"),
        }
    }
}

fn invocation(old: &Artifact, new: &Artifact) -> (Vec<OsString>, PathBuf) {
    let dir = directory();
    for (name, bytes) in [("old", &old.bytes), ("new", &new.bytes), ("prefix", &new.prefix)] {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
    std::fs::write(dir.join("consistency"), consistency(old, new)).unwrap();
    let args = vec![
        "witness".into(), "--checkpoint".into(), dir.join("new").into_os_string(),
        "--expect-book".into(), hex(&[0x42; 16]).into(),
        "--expect-branch".into(), hex(&[0; 16]).into(),
        "--expect-policy".into(), hex(&[0x55; 32]).into(),
        "--publisher-key".into(), vectors::PUBLISHER.into(),
        "--witness-key".into(), vectors::WITNESS_A.into(),
        "--witness-key".into(), vectors::WITNESS_B.into(),
        "--quorum".into(), "2".into(), "--previous".into(), dir.join("old").into_os_string(),
        "--expect-previous-body".into(), hex(&old.signed.body_digest).into(),
        "--consistency".into(), dir.join("consistency").into_os_string(),
        "--recorded-prefix".into(), dir.join("prefix").into_os_string(), "--json".into(),
    ];
    (args, dir)
}

fn set(args: &mut [OsString], flag: &str, value: impl Into<OsString>) {
    let at = args.iter().position(|arg| arg == flag).unwrap();
    args[at + 1] = value.into();
}

fn remove(args: &mut Vec<OsString>, flag: &str) {
    let at = args.iter().position(|arg| arg == flag).unwrap();
    drop(args.drain(at..at + 2));
}

fn run(args: &[OsString]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fa-verify")).args(args).output().expect("execute offline binary")
}

fn result(output: Output, exit: i32) -> String {
    let out = String::from_utf8(output.stdout).unwrap();
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(exit), "{out}\n{err}");
    assert_eq!(out.lines().count(), 1, "one buffered JSON result");
    for text in [&out[..], &err[..]] {
        assert!(!text.contains(std::str::from_utf8(SECRET).unwrap()));
        assert!(!text.contains(&hex(SECRET)));
    }
    if exit == 0 {
        assert!(err.is_empty());
        assert!(out.contains("\"verified\":true"));
        assert!(out.contains("\"pin_written\":false"));
    } else {
        assert!(out.contains("\"verified\":false"));
        assert!(!out.contains("proof_verified"));
        assert!(!out.contains("\"recorded_boundary\":{"), "no partial success report");
    }
    out
}

#[test]
fn valid_later_recording_with_earlier_effective_day_has_explicit_recorded_assurance() {
    let old = artifact(vectors::OLD, &[(7, 100)]);
    let new = artifact(vectors::GOOD, &[(7, 100), (11, -100)]);
    let (args, dir) = invocation(&old, &new);
    let json = result(run(&args), 0);
    assert!(json.contains("\"recorded_boundary\":{\"status\":\"verified\""));
    assert!(json.contains("\"appended_records\":\"1\""));
    assert!(json.contains("complete_candidate_payloads"));
    assert!(json.contains("retained_recorded_boundary"));
    assert!(json.contains("\"continuity\":\"advanced\""));
    assert_eq!(std::fs::read(dir.join("old")).unwrap(), old.bytes);
    assert_eq!(std::fs::read(dir.join("new")).unwrap(), new.bytes);
    assert_eq!(std::fs::read(dir.join("prefix")).unwrap(), new.prefix);
    assert_eq!(result(run(&args), 0), json);
}

#[test]
fn signed_tree_extensions_that_backfill_the_retained_frontier_fail_only_the_stronger_mode() {
    let old = artifact(vectors::OLD, &[(7, 100)]);
    for (bytes, sequence) in [(vectors::BACKFILL, 8), (vectors::BOUNDARY, 10)] {
        let new = artifact(bytes, &[(7, 100), (sequence, -100)]);
        let (mut args, _) = invocation(&old, &new);
        let denied = result(run(&args), 8);
        assert!(denied.contains("retained checkpoint commits 1 records"));
        remove(&mut args, "--recorded-prefix");
        let tree_only = result(run(&args), 0);
        assert!(tree_only.contains("\"recorded_boundary\":{\"status\":\"not_checked\""));
        assert!(!tree_only.contains("complete_candidate_payloads"));
    }
}

#[test]
fn empty_and_unchanged_candidates_still_require_the_complete_prefix() {
    for (old, new, status) in [
        (artifact(vectors::OLD, &[(7, 100)]), artifact(vectors::OLD, &[(7, 100)]), "unchanged"),
        (artifact(vectors::EMPTY_OLD, &[]), artifact(vectors::EMPTY_NEW, &[]), "advanced"),
    ] {
        let (args, dir) = invocation(&old, &new);
        let verified = result(run(&args), 0);
        assert!(verified.contains(&format!("\"continuity\":\"{status}\"")));
        assert!(verified.contains("\"appended_records\":\"0\""));
        std::fs::write(dir.join("prefix"), []).unwrap();
        result(run(&args), 8);
    }
}

#[test]
fn malformed_foreign_or_envelope_only_witnesses_never_fall_back_to_signature_checks() {
    let old = artifact(vectors::OLD, &[(7, 100)]);
    let new = artifact(vectors::GOOD, &[(7, 100), (11, -100)]);
    let other = artifact(vectors::BACKFILL, &[(7, 100), (8, -100)]);
    let (args, dir) = invocation(&old, &new);
    result(run(&args), 0);
    let mut corrupt = new.prefix.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let mut trailing = new.prefix.clone();
    trailing.push(0);
    for invalid in [
        prefix(&new.signed.checkpoint, &new.envelopes, PREFIX_FORMAT).0,
        corrupt, trailing, other.prefix, new.prefix[..new.prefix.len() - 1].to_vec(),
    ] {
        std::fs::write(dir.join("prefix"), invalid).unwrap();
        result(run(&args), 8);
    }
    std::fs::write(dir.join("prefix"), &new.prefix).unwrap();
    let mut bad_signature = new.bytes.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    std::fs::write(dir.join("new"), bad_signature).unwrap();
    result(run(&args), 8);
}

#[test]
fn the_retained_body_pin_is_checked_before_candidate_or_prefix_files_are_opened() {
    let old = artifact(vectors::OLD, &[(7, 100)]);
    let new = artifact(vectors::GOOD, &[(7, 100), (11, -100)]);
    let (mut args, dir) = invocation(&old, &new);
    set(&mut args, "--expect-previous-body", "ff".repeat(32));
    for flag in ["--checkpoint", "--consistency", "--recorded-prefix"] {
        set(&mut args, flag, dir.join("absent").into_os_string());
    }
    assert!(result(run(&args), 8).contains("independently retained body digest"));
}

#[test]
fn recorded_prefix_requires_complete_pin_arguments_and_unique_options_before_io() {
    let old = artifact(vectors::OLD, &[(7, 100)]);
    let new = artifact(vectors::GOOD, &[(7, 100), (11, -100)]);
    let (mut base, dir) = invocation(&old, &new);
    set(&mut base, "--previous", dir.join("absent").into_os_string());
    for flag in ["--previous", "--expect-previous-body", "--consistency"] {
        let mut invalid = base.clone();
        remove(&mut invalid, flag);
        result(run(&invalid), 2);
    }
    let mut no_pin = base.clone();
    for flag in ["--previous", "--expect-previous-body", "--consistency"] { remove(&mut no_pin, flag); }
    result(run(&no_pin), 2);
    for suffix in [vec!["--recorded-prefix", "another"], vec!["--recorded-prefix"], vec!["--json"]] {
        let mut invalid = base.clone();
        invalid.extend(suffix.into_iter().map(OsString::from));
        result(run(&invalid), 2);
    }
    set(&mut base, "--recorded-prefix", "--checkpoint");
    result(run(&base), 2);
}

fn empty_bundle(new: &Artifact) -> Vec<u8> {
    let cp = new.signed.checkpoint;
    assert_eq!(cp.leaf_count, 0);
    let manifest = Manifest {
        book_id: cp.book_id, branch_id: cp.branch_id, through_seq: cp.through_seq,
        leaf_count: 0, checkpoint_oid: new.signed.oid, scope: BundleScope::Prefix,
        completeness: Completeness::SeqRangeComplete { from: 0, to: 0 },
    };
    let summary = Summary { format: (1, 0), entries: 0, documents: 0, inline: 0, balances: vec![] };
    let mut w = Wire::default();
    w.bytes(BUNDLE_FORMAT).u16(1).u16(0).fixed(&cp.book_id).fixed(&cp.branch_id)
        .u64(cp.through_seq).u64(cp.leaf_count).fixed(&new.signed.oid)
        .u8(1).u8(1).u64(0).u64(0).bytes(&new.bytes)
        .bytes(&prefix(&cp, &[], PREFIX_FORMAT).0).u32(0).u32(0)
        .bytes(manifest_md(&manifest, &summary).as_bytes());
    w.0
}

fn bundled(mut args: Vec<OsString>, path: PathBuf) -> Vec<OsString> {
    args.insert(1, "bundle".into());
    args.extend(["--bundle".into(), path.into_os_string(), "--expect-scope".into(), "prefix".into(),
        "--expect-documents".into(), "inline".into(), "--expect-receipt".into(), "optional".into(),
        "--expect-no-balances".into()]);
    args
}

#[test]
fn bundles_share_the_recorded_check_and_refuse_backfills_before_opening_accounting_artifacts() {
    let old = artifact(vectors::EMPTY_OLD, &[]);
    let new = artifact(vectors::EMPTY_NEW, &[]);
    let (args, dir) = invocation(&old, &new);
    std::fs::write(dir.join("bundle"), empty_bundle(&new)).unwrap();
    let args = bundled(args, dir.join("bundle"));
    let report = result(run(&args), 0);
    assert!(report.contains("\"proof_kind\":\"witnessed_bundle\""));
    assert!(report.contains("\"recorded_boundary\":{\"status\":\"verified\""));
    assert!(report.contains("requested_balance_set"));
    let old = artifact(vectors::OLD, &[(7, 100)]);
    for (hexed, sequence, exit) in [(vectors::GOOD, 11, 5), (vectors::BACKFILL, 8, 8)] {
        let new = artifact(hexed, &[(7, 100), (sequence, -100)]);
        let (args, dir) = invocation(&old, &new);
        let args = bundled(args, dir.join("absent-bundle"));
        let report = result(run(&args), exit);
        if exit == 8 { assert!(report.contains("retained checkpoint commits 1 records")); }
    }
}

#[test]
fn prefix_and_bundle_reads_use_the_remaining_total_budget_not_individual_file_allowances() {
    let old = artifact(vectors::EMPTY_OLD, &[]);
    let new = artifact(vectors::EMPTY_NEW, &[]);
    let (args, dir) = invocation(&old, &new);
    let f = std::fs::OpenOptions::new().write(true).open(dir.join("prefix")).unwrap();
    f.set_len(MAX_RECORDED_ADVANCE_BYTES as u64).unwrap();
    assert!(result(run(&args), 8).contains("input exceeds"));
    std::fs::write(dir.join("prefix"), &new.prefix).unwrap();
    std::fs::write(dir.join("bundle"), empty_bundle(&new)).unwrap();
    let f = std::fs::OpenOptions::new().write(true).open(dir.join("bundle")).unwrap();
    f.set_len(MAX_RECORDED_ADVANCE_BYTES as u64).unwrap();
    let args = bundled(args, dir.join("bundle"));
    assert!(result(run(&args), 8).contains("input exceeds"));
}

#[test]
fn human_reports_and_help_explain_recorded_time_without_claiming_freshness_or_disclosure_authority() {
    for args in [vec!["witness", "--help"], vec!["witness", "bundle", "--help"]] {
        let output = run(&args.into_iter().map(OsString::from).collect::<Vec<_>>());
        assert_eq!(output.status.code(), Some(0));
        assert!(String::from_utf8(output.stdout).unwrap().contains("--recorded-prefix"));
    }
    let old = artifact(vectors::OLD, &[(7, 100)]);
    let new = artifact(vectors::GOOD, &[(7, 100), (11, -100)]);
    let (mut args, _) = invocation(&old, &new);
    args.retain(|arg| arg != "--json");
    let output = run(&args);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("Recorded-time boundary verified"));
    assert!(text.contains("Global freshness was not checked"));
    assert!(!text.contains(std::str::from_utf8(SECRET).unwrap()));
    assert!(!text.contains(&hex(SECRET)));
}

#[cfg(unix)]
#[cfg_attr(target_os = "macos", ignore = "APFS rejects filenames containing non-UTF-8 bytes (EILSEQ)")]
#[test]
fn recorded_witness_paths_remain_os_strings() {
    use std::os::unix::ffi::OsStringExt;
    let old = artifact(vectors::OLD, &[(7, 100)]);
    let new = artifact(vectors::GOOD, &[(7, 100), (11, -100)]);
    let (mut args, dir) = invocation(&old, &new);
    let path = dir.join(OsString::from_vec(b"prefix-\xff".to_vec()));
    std::fs::copy(dir.join("prefix"), &path).unwrap();
    set(&mut args, "--recorded-prefix", path.into_os_string());
    result(run(&args), 0);
}
