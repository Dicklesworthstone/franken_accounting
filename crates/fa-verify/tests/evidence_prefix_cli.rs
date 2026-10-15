//! Real offline dispatcher coverage for both single-prefix production modes.
//! Fixtures are independently encoded; no book, producer or network is used.

#[path = "support/evidence_inventory.rs"]
mod fixture;
#[path = "support/evidence_production.rs"]
mod production_fixture;

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::blake3::hex;
use fa_verify::document::doc_commit;
use fa_verify::proof::PREFIX_FORMAT;
use fa_verify::proof::production::MAX_PRODUCTION_BYTES;
use production_fixture::{Journal, entry, journal};

const DOCUMENT: &[u8] = b"DO_NOT_PRINT_ORIGINAL_DOCUMENT_CONTENT";

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-evidence-prefix-cli-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        match fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
}

fn files(j: &Journal) -> PathBuf {
    let dir = directory();
    fs::write(dir.join("prefix.bin"), &j.prefix).unwrap();
    fs::write(dir.join("trusted.bin"), j.checkpoint.encode()).unwrap();
    dir
}

fn args(dir: &Path, documents: bool, known: u64) -> Vec<OsString> {
    let mut args: Vec<OsString> = ["evidence", "production"].map(OsString::from).into();
    if documents { args.push("documents".into()); }
    args.extend([
        "--prefix".into(), dir.join("prefix.bin").into_os_string(),
        "--checkpoint".into(), dir.join("trusted.bin").into_os_string(),
        "--expect-first-seq".into(), "0".into(),
        "--expect-known-at".into(), known.to_string().into(),
        "--expect-account".into(), "all".into(),
        "--expect-days".into(), "all".into(), "--json".into(),
    ]);
    args
}

fn document_args(args: &mut Vec<OsString>, oid: &[u8; 32], kind: u8, path: &Path) {
    args.extend(["--document".into(), hex(oid).into(), kind.to_string().into(), path.as_os_str().to_owned()]);
}

fn change(args: &mut [OsString], option: &str, value: impl Into<OsString>) {
    let index = args.iter().position(|arg| arg == option).expect("existing option");
    args[index + 1] = value.into();
}

fn no_payload(text: &str) {
    for secret in [fixture::SECRET, DOCUMENT] {
        assert!(!text.contains(std::str::from_utf8(secret).unwrap()));
        assert!(!text.contains(&hex(secret)));
    }
}

fn invoke(args: &[OsString], exit: i32) -> String {
    let Output { status, stdout, stderr } = Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .args(args).output().expect("run fa-verify");
    let out = String::from_utf8(stdout).unwrap();
    let err = String::from_utf8(stderr).unwrap();
    assert_eq!(status.code(), Some(exit), "args={args:?}\n{out}\n{err}");
    no_payload(&out);
    no_payload(&err);
    if args.iter().any(|arg| arg == "--json") {
        assert_eq!(out.lines().count(), 1, "one buffered report: {out}");
        if exit == 0 {
            assert!(out.contains("\"verified\":true"));
            assert!(out.contains("\"event\":\"proof_verified\""));
            assert!(out.contains("\"signature_verification\":\"not_performed\""));
        } else {
            assert!(out.contains("\"verified\":false"));
            assert!(out.contains("\"event\":\"error\""));
            assert!(!out.contains("proof_verified"));
        }
    }
    if exit == 0 { assert!(err.is_empty(), "{err}"); }
    out
}

#[test]
fn single_prefix_inventory_and_historical_empty_selection_need_no_inclusion_files() {
    let citations = fixture::citations();
    let j = journal(&[entry(&citations[..1], 7, 10), entry(&citations[1..], 11, 20)]);
    let dir = files(&j);
    let mut direct = args(&dir, false, 11);
    direct.push("--from-prefix".into());
    let out = invoke(&direct, 0);
    assert!(out.contains("\"entry_count\":2"));
    assert!(out.contains("\"citation_count\":3"));
    assert!(out.contains("\"record_source\":\"complete_native_prefix\""));
    assert!(out.contains("\"separate_record_set_checked\":false"));
    assert!(out.contains("complete_prefix_record_selection"));
    assert!(!out.contains("\"name\":\"exact_record_set\""));
    let human: Vec<_> = direct.iter().filter(|arg| *arg != "--json").cloned().collect();
    assert!(invoke(&human, 0).contains("no separate record set was supplied or checked"));

    change(&mut direct, "--expect-known-at", "7");
    assert!(invoke(&direct, 0).contains("\"citation_count\":1"));
    change(&mut direct, "--expect-first-seq", "1");
    change(&mut direct, "--expect-account", format!("{:032x}", 99));
    assert!(invoke(&direct, 0).contains("\"entry_count\":0"));
    change(&mut direct, "--expect-known-at", "12");
    invoke(&direct, 8);
    assert_eq!(fs::read(dir.join("prefix.bin")).unwrap(), j.prefix);
}

#[test]
fn from_prefix_and_document_declarations_are_independent_tokens_in_any_valid_order() {
    let citation = fixture::citation(doc_commit(1, DOCUMENT), 3);
    let j = journal(&[entry(&[citation], 7, 10)]);
    let dir = files(&j);
    let document = dir.join("original.bin");
    fs::write(&document, DOCUMENT).unwrap();
    for placement in 0..3 {
        let mut argv = args(&dir, true, 7);
        if placement == 0 { argv.insert(3, "--from-prefix".into()); }
        if placement == 1 { argv.push("--from-prefix".into()); }
        document_args(&mut argv, &citation.document_oid, 1, &document);
        if placement == 2 { argv.push("--from-prefix".into()); }
        let out = invoke(&argv, 0);
        assert!(out.contains("\"proof_kind\":\"evidence_document_production\""));
        assert!(out.contains("\"document_count\":1"));
        assert!(out.contains("\"document_scope\":\"recomputation\""));
        assert!(out.contains("\"record_source\":\"complete_native_prefix\""));
        assert!(out.contains("\"separate_record_set_checked\":false"));
    }
}

#[test]
fn a_missing_or_corrupt_full_document_never_returns_a_successful_partial_inventory() {
    let citation = fixture::citation(doc_commit(1, DOCUMENT), 3);
    let j = journal(&[entry(&[citation], 7, 10)]);
    let dir = files(&j);
    let document = dir.join("original.bin");
    fs::write(&document, DOCUMENT).unwrap();
    let mut argv = args(&dir, true, 7);
    argv.push("--from-prefix".into());
    invoke(&argv, 8);
    document_args(&mut argv, &citation.document_oid, 1, &document);
    invoke(&argv, 0);
    let mut damaged = DOCUMENT.to_vec();
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&document, damaged).unwrap();
    invoke(&argv, 8);
    fs::write(&document, DOCUMENT).unwrap();
    let document_option = argv.iter().position(|arg| arg == "--document").unwrap();
    argv[document_option + 2] = "2".into();
    invoke(&argv, 8);
}

#[test]
fn ambiguous_duplicate_and_incomplete_modes_are_usage_errors_before_file_access() {
    let missing = directory().join("not-created");
    for documents in [false, true] {
        let mut valid = args(&missing, documents, 7);
        valid.push("--from-prefix".into());
        for extra in [vec!["--from-prefix"], vec!["--record", "not-opened"], vec!["--from-prefix=true"], vec!["--json"]] {
            let mut bad = valid.clone();
            bad.extend(extra.into_iter().map(OsString::from));
            invoke(&bad, 2);
        }
        for required in ["--expect-first-seq", "--expect-known-at", "--expect-account", "--expect-days"] {
            let mut bad = valid.clone();
            let index = bad.iter().position(|arg| arg == required).unwrap();
            bad.drain(index..index + 2);
            invoke(&bad, 2);
        }
        // A boolean must not be consumed as a path or silently become a mode
        // when it occupies another option's required value position.
        let mut bad = valid.clone();
        change(&mut bad, "--prefix", "--from-prefix");
        invoke(&bad, 2);
    }
    assert!(!missing.exists());
}

#[test]
fn default_multi_proof_mode_still_checks_separately_supplied_records() {
    let citation = fixture::citation(doc_commit(1, DOCUMENT), 3);
    let j = journal(&[entry(&[citation], 7, 10)]);
    let dir = files(&j);
    let record = dir.join("record.bin");
    let document = dir.join("original.bin");
    fs::write(&record, &j.records[0]).unwrap();
    fs::write(&document, DOCUMENT).unwrap();
    for documents in [false, true] {
        let mut argv = args(&dir, documents, 7);
        if documents { document_args(&mut argv, &citation.document_oid, 1, &document); }
        invoke(&argv, 8);
        argv.extend(["--record".into(), record.as_os_str().to_owned()]);
        let out = invoke(&argv, 0);
        assert!(out.contains("\"record_source\":\"individual_inclusions\""));
        assert!(out.contains("\"separate_record_set_checked\":true"));
    }
}

#[test]
fn native_mode_refuses_legacy_and_corrupt_prefixes_even_for_empty_citation_sets() {
    let j = journal(&[]);
    let dir = files(&j);
    let mut legacy = fixture::Wire::default();
    legacy.bytes(PREFIX_FORMAT).fixed(&j.checkpoint.encode()).u32(0);
    let mut trailing = j.prefix.clone();
    trailing.push(0);
    for bytes in [&legacy.0[..], &j.prefix[..j.prefix.len() - 1], &trailing] {
        fs::write(dir.join("prefix.bin"), bytes).unwrap();
        for documents in [false, true] {
            let mut argv = args(&dir, documents, 0);
            argv.push("--from-prefix".into());
            invoke(&argv, 8);
        }
    }
}

#[test]
fn full_document_file_reads_share_the_prefix_transport_budget() {
    let citation = fixture::citation(doc_commit(1, DOCUMENT), 3);
    let j = journal(&[entry(&[citation], 7, 10)]);
    let dir = files(&j);
    let oversized = dir.join("oversized.sparse");
    fs::File::create(&oversized).unwrap().set_len(MAX_PRODUCTION_BYTES as u64).unwrap();
    let mut argv = args(&dir, true, 7);
    argv.push("--from-prefix".into());
    document_args(&mut argv, &citation.document_oid, 1, &oversized);
    let out = invoke(&argv, 8);
    assert!(out.contains("input exceeds"), "remaining budget must refuse before content hashing: {out}");
}

#[cfg(unix)]
#[test]
fn non_utf8_prefix_checkpoint_and_document_paths_remain_usable() {
    use std::os::unix::ffi::OsStringExt;
    let citation = fixture::citation(doc_commit(1, DOCUMENT), 3);
    let j = journal(&[entry(&[citation], 7, 10)]);
    let dir = directory();
    let prefix = dir.join(OsString::from_vec(b"prefix-\xff.bin".to_vec()));
    let checkpoint = dir.join(OsString::from_vec(b"checkpoint-\xfe.bin".to_vec()));
    let document = dir.join(OsString::from_vec(b"document-\xfd.bin".to_vec()));
    fs::write(&prefix, &j.prefix).unwrap();
    fs::write(&checkpoint, j.checkpoint.encode()).unwrap();
    fs::write(&document, DOCUMENT).unwrap();
    let mut argv = args(&dir, true, 7);
    change(&mut argv, "--prefix", prefix.into_os_string());
    change(&mut argv, "--checkpoint", checkpoint.into_os_string());
    argv.push("--from-prefix".into());
    document_args(&mut argv, &citation.document_oid, 1, &document);
    invoke(&argv, 0);
}
