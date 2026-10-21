//! Actual executable coverage with independently generated signed empty-index
//! vectors. Nonempty producer/selector counterexamples live in fa-notary.

#[path = "support/scope_index_vector.rs"]
mod vector;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

fn decode(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-witness-index-{}-{}",
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

fn args() -> (Vec<OsString>, PathBuf) {
    let dir = directory();
    for (name, bytes) in [
        ("checkpoint", vector::CHECKPOINT),
        ("bundle", vector::BUNDLE),
        ("index", vector::PREFIX),
        ("consistency", vector::CONSISTENCY),
    ] {
        std::fs::write(dir.join(name), decode(bytes)).unwrap();
    }
    let mut args: Vec<OsString> = ["witness", "bundle", "--checkpoint"]
        .map(OsString::from)
        .into();
    args.push(dir.join("checkpoint").into_os_string());
    for (name, value) in [
        ("--expect-book", "42".repeat(16)),
        ("--expect-branch", "00".repeat(16)),
        ("--expect-policy", "55".repeat(32)),
        ("--publisher-key", vector::PUBLISHER.into()),
        ("--witness-key", vector::WITNESS_A.into()),
        ("--witness-key", vector::WITNESS_B.into()),
        ("--quorum", "2".into()),
        ("--expect-scope", "account".into()),
        ("--expect-account", format!("{:032x}", 99)),
        ("--expect-days", "0:1".into()),
        ("--expect-documents", "inline".into()),
        ("--expect-receipt", "optional".into()),
    ] {
        args.extend([name.into(), value.into()]);
    }
    args.extend([
        "--bundle".into(),
        dir.join("bundle").into_os_string(),
        "--index-prefix".into(),
        dir.join("index").into_os_string(),
        "--json".into(),
    ]);
    (args, dir)
}

fn run(args: &[OsString]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .args(args)
        .output()
        .expect("execute verifier")
}

fn set(args: &mut [OsString], flag: &str, value: impl Into<OsString>) {
    let at = args.iter().position(|arg| arg == flag).unwrap();
    args[at + 1] = value.into();
}

fn remove(args: &mut Vec<OsString>, flag: &str) {
    let at = args.iter().position(|arg| arg == flag).unwrap();
    drop(args.drain(at..at + 2));
}

fn result(output: Output, exit: i32) -> String {
    let text = String::from_utf8(output.stdout).unwrap();
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(exit), "{text}\n{err}");
    assert_eq!(text.lines().count(), 1);
    if exit == 0 {
        assert!(err.is_empty());
        assert!(text.contains("\"verified\":true"));
    } else {
        assert!(text.contains("\"verified\":false"));
        assert!(!text.contains("\"scope_index_derivation\":\"payload_recomputed\""));
    }
    assert!(!text.contains("NEVER_ECHO_PREFIX_BYTES"));
    assert!(!err.contains("NEVER_ECHO_PREFIX_BYTES"));
    text
}

#[test]
fn full_payload_index_is_explicit_and_legacy_signed_mode_remains_available() {
    let (mut input, dir) = args();
    let signed = fa_verify::verify_checkpoint(
        &decode(vector::CHECKPOINT),
        &[decode(vector::PUBLISHER).try_into().unwrap()],
    )
    .unwrap();
    let index =
        fa_verify::scope::payloads::verify_payload_index(&decode(vector::PREFIX), &signed).unwrap();
    assert_eq!(index.root().as_slice(), decode(vector::INDEX_ROOT));
    let text = result(run(&input), 0);
    assert!(text.contains("\"scope_index_derivation\":\"payload_recomputed\""));
    assert!(text.contains("payload_scope_index_derivation"));
    assert!(text.contains("\"completeness\":\"scope_index_complete\""));
    assert_eq!(text, result(run(&input), 0));
    for (name, expected) in [
        ("index", vector::PREFIX),
        ("bundle", vector::BUNDLE),
        ("checkpoint", vector::CHECKPOINT),
    ] {
        assert_eq!(std::fs::read(dir.join(name)).unwrap(), decode(expected));
    }
    input.push("--expect-no-balances".into());
    assert!(result(run(&input), 0).contains("requested_balance_set"));
    remove(&mut input, "--index-prefix");
    let old = result(run(&input), 0);
    assert!(old.contains("\"scope_index_derivation\":\"signed\""));
    assert!(!old.contains("payload_scope_index_derivation"));
}

#[test]
fn legacy_truncated_corrupt_and_wrong_coordinate_prefixes_cannot_downgrade_the_request() {
    let (input, dir) = args();
    result(run(&input), 0);
    let prefix = decode(vector::PREFIX);
    let mut wrong = prefix.clone();
    let book_offset = 4 + fa_verify::proof::production::derivation::PREFIX_FORMAT_V2.len();
    wrong[book_offset] ^= 1;
    let mut trailing = prefix.clone();
    trailing.extend_from_slice(b"NEVER_ECHO_PREFIX_BYTES");
    for bytes in [
        decode(vector::LEGACY),
        vec![],
        prefix[..prefix.len() - 1].to_vec(),
        wrong,
        trailing,
    ] {
        std::fs::write(dir.join("index"), bytes).unwrap();
        result(run(&input), 8);
    }
}

#[test]
fn index_arguments_are_validated_before_any_checkpoint_or_witness_file_is_opened() {
    let (mut base, dir) = args();
    set(
        &mut base,
        "--checkpoint",
        dir.join("missing-checkpoint").into_os_string(),
    );
    for extra in [
        vec!["--index-prefix", "duplicate"],
        vec!["--index-prefix"],
        vec!["--json"],
    ] {
        let mut bad = base.clone();
        bad.extend(extra.into_iter().map(OsString::from));
        result(run(&bad), 2);
    }
    let mut wrong_scope = base.clone();
    set(&mut wrong_scope, "--expect-scope", "prefix");
    remove(&mut wrong_scope, "--expect-account");
    remove(&mut wrong_scope, "--expect-days");
    result(run(&wrong_scope), 2);
    for bad_value in ["", "--json"] {
        let mut bad = base.clone();
        set(&mut bad, "--index-prefix", bad_value);
        result(run(&bad), 2);
    }
    result(run(&base), 5); // valid syntax still reports genuine missing I/O
}

#[test]
fn correct_index_cannot_rescue_wrong_bundle_questions_or_waive_shared_byte_limits() {
    let (base, dir) = args();
    result(run(&base), 0);
    for (flag, value) in [
        ("--expect-account", format!("{:032x}", 100)),
        ("--expect-days", "0:2".into()),
        ("--expect-receipt", "publisher".into()),
    ] {
        let mut bad = base.clone();
        set(&mut bad, flag, value);
        result(run(&bad), 8);
    }
    let mut missing_balance = base.clone();
    missing_balance.extend([
        "--expect-balance".into(),
        format!("{:032x}:1:none", 99).into(),
    ]);
    result(run(&missing_balance), 8);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("bundle"))
        .unwrap();
    file.set_len(fa_verify::checkpoint::witness::bundle::MAX_WITNESSED_BUNDLE_BYTES as u64)
        .unwrap();
    let error = result(run(&base), 8);
    assert!(error.contains("byte bound")); // prefix consumed part of the shared budget
}

#[test]
fn retained_pin_binding_still_precedes_candidate_and_index_evidence_reads() {
    let (mut input, dir) = args();
    input.extend([
        "--previous".into(),
        dir.join("checkpoint").into_os_string(),
        "--expect-previous-body".into(),
        vector::BODY.into(),
        "--consistency".into(),
        dir.join("consistency").into_os_string(),
    ]);
    assert!(result(run(&input), 0).contains("\"continuity\":\"unchanged\""));
    set(&mut input, "--expect-previous-body", "ff".repeat(32));
    set(
        &mut input,
        "--index-prefix",
        dir.join("absent-index").into_os_string(),
    );
    let error = result(run(&input), 8);
    assert!(error.contains("retained body digest"));
}

#[test]
fn help_and_human_output_describe_payload_derivation_and_whole_prefix_disclosure() {
    let output = run(&["witness", "bundle", "--help"].map(OsString::from));
    assert_eq!(output.status.code(), Some(0));
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--index-prefix"));
    assert!(help.contains("excluded records"));
    let (mut input, _) = args();
    input.retain(|arg| arg != "--json");
    let output = run(&input);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("every prefix selector were independently recomputed"));
    assert!(!text.contains("A signed account index is not independently recomputed"));
    assert!(text.contains("No pin or payload bytes were written"));
}

#[cfg(unix)]
#[cfg_attr(
    target_os = "macos",
    ignore = "APFS rejects the non-UTF-8 fixture filename (EILSEQ)"
)]
#[test]
fn non_utf8_index_filenames_are_not_lossily_rewritten() {
    use std::os::unix::ffi::OsStringExt;
    let (mut input, dir) = args();
    let path = dir.join(OsString::from_vec(b"index-\xff".to_vec()));
    std::fs::copy(dir.join("index"), &path).unwrap();
    set(&mut input, "--index-prefix", path.into_os_string());
    result(run(&input), 0);
}
