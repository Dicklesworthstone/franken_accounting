//! Actual-binary regressions; temporary fixtures are retained for diagnosis.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::blake3::hex;
use fa_verify::evidence::inventory::production::documents::DocumentContent;
use fa_verify::proof::production::MAX_PRODUCTION_BYTES;

use super::{DOCUMENT_SECRET, citations, document, fixture, production_fixture};
use production_fixture::{Journal, entry, journal};

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let dir = std::env::temp_dir().join(format!(
            "fa-evidence-documents-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let result = std::fs::create_dir(&dir);
        if matches!(&result, Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists) {
            continue;
        }
        result.expect("create retained fixture");
        return dir;
    }
}

fn args(j: &Journal, indexes: &[usize], docs: &[DocumentContent<'_>]) -> (Vec<OsString>, PathBuf) {
    let dir = directory();
    std::fs::write(dir.join("prefix"), &j.prefix).unwrap();
    std::fs::write(dir.join("checkpoint"), j.checkpoint.encode()).unwrap();
    let mut args = vec![
        "evidence".into(),
        "production".into(),
        "documents".into(),
        "--prefix".into(),
        dir.join("prefix").into_os_string(),
        "--checkpoint".into(),
        dir.join("checkpoint").into_os_string(),
        "--expect-first-seq".into(),
        "0".into(),
        "--expect-known-at".into(),
        j.checkpoint.through_seq.to_string().into(),
        "--expect-account".into(),
        "all".into(),
        "--expect-days".into(),
        "all".into(),
        "--json".into(),
    ];
    for (index, record) in j.records.iter().enumerate() {
        std::fs::write(dir.join(format!("record-{index}")), record).unwrap();
    }
    for index in indexes {
        args.extend([
            "--record".into(),
            dir.join(format!("record-{index}")).into_os_string(),
        ]);
    }
    for (index, doc) in docs.iter().enumerate() {
        let path = dir.join(format!("document-{index}"));
        std::fs::write(&path, doc.bytes).unwrap();
        args.extend([
            "--document".into(),
            hex(&doc.document_oid).into(),
            doc.kind.to_string().into(),
            path.into_os_string(),
        ]);
    }
    (args, dir)
}

fn set(args: &mut [OsString], flag: &str, offset: usize, value: impl Into<OsString>) {
    let position = args.iter().position(|argument| argument == flag).unwrap();
    args[position + offset] = value.into();
}

fn run(args: &[OsString]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .args(args)
        .output()
        .expect("execute offline verifier")
}

fn result(output: Output, exit: i32) -> String {
    let out = String::from_utf8(output.stdout).unwrap();
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(exit), "{out}\n{err}");
    assert_eq!(out.lines().count(), 1, "one buffered JSON result: {out}");
    for text in [&out[..], &err[..]] {
        for secret in [fixture::SECRET, DOCUMENT_SECRET] {
            assert!(!text.contains(std::str::from_utf8(secret).unwrap()));
            assert!(!text.contains(&hex(secret)));
        }
    }
    if exit == 0 {
        assert!(err.is_empty(), "{err}");
        for field in [
            "\"verified\":true",
            "\"proof_kind\":\"evidence_document_production\"",
            "\"scope\":\"seq_range_complete\"",
            "\"document_scope\":\"recomputation\"",
            "\"original_cited_document_bytes\":\"complete_and_recomputed\"",
            "\"full_provenance_closure\":\"not_verified\"",
            "\"supplemental_evidence\":\"not_verified\"",
            "\"signature_verification\":\"not_performed\"",
        ] {
            assert!(out.contains(field), "missing {field}: {out}");
        }
    } else {
        assert!(out.contains("\"verified\":false"));
        assert!(out.contains("\"event\":\"error\""));
        for partial in [
            "proof_verified",
            "\"entries\":[",
            "\"citations\":[",
            "\"documents\":[",
        ] {
            assert!(!out.contains(partial), "partial verification report: {out}");
        }
    }
    out
}

#[test]
fn full_bytes_binary_reports_all_associations_and_exact_coordinates_without_payloads() {
    let mut docs = [document(1, DOCUMENT_SECRET), document(255, &[])];
    docs.sort_by_key(|doc| doc.document_oid);
    let mut refs = citations(&docs, 3);
    refs.extend(citations(&docs[..1], 4));
    refs.sort();
    let j = journal(&[
        entry(&refs, 7, i32::MIN),
        entry(&[], 11, 10),
        entry(&refs, u64::MAX, i32::MAX),
    ]);
    let (mut input, dir) = args(&j, &[0, 1, 2], &docs);
    set(&mut input, "--expect-days", 1, "-2147483648:2147483647");
    let json = result(run(&input), 0);
    for field in [
        "\"entry_count\":3",
        "\"citation_count\":6",
        "\"document_count\":2",
        "\"citations\":[]",
        "\"byte_length\":\"0\"",
        "\"first\":\"-2147483648\"",
        "\"last\":\"2147483647\"",
    ] {
        assert!(json.contains(field));
    }
    for field in ["through_seq", "known_at", "recorded_at"] {
        assert!(json.contains(&format!("\"{field}\":\"18446744073709551615\"")));
    }
    assert_eq!(std::fs::read(dir.join("prefix")).unwrap(), j.prefix);
    assert_eq!(
        std::fs::read(dir.join("checkpoint")).unwrap(),
        j.checkpoint.encode()
    );
    for (index, doc) in docs.iter().enumerate() {
        assert_eq!(
            std::fs::read(dir.join(format!("document-{index}")))
                .unwrap()
                .as_slice(),
            doc.bytes
        );
    }
    assert_eq!(
        result(run(&input), 0),
        json,
        "deterministic metadata report"
    );
}

#[test]
fn document_omissions_extras_duplicate_locators_and_wrong_bytes_fail_without_partial_output() {
    let mut docs = [
        document(1, b"one"),
        document(2, b"two"),
        document(3, b"extra"),
    ];
    docs.sort_by_key(|doc| doc.document_oid);
    let j = journal(&[entry(&citations(&docs[..2], 3), 7, 10)]);
    for supplied in [vec![], vec![docs[0]], docs.to_vec(), vec![docs[0], docs[2]]] {
        result(run(&args(&j, &[0], &supplied).0), 8);
    }
    for supplied in [[docs[0], docs[0]], [docs[1], docs[0]]] {
        result(run(&args(&j, &[0], &supplied).0), 2);
    }
    let (input, dir) = args(&j, &[0], &docs[..2]);
    std::fs::write(dir.join("document-1"), b"substituted last file").unwrap();
    result(run(&input), 8);
    let (mut input, dir) = args(&j, &[0], &docs[..2]);
    set(&mut input, "--document", 2, "254");
    result(run(&input), 8);
    set(&mut input, "--document", 2, docs[0].kind.to_string());
    set(
        &mut input,
        "--document",
        3,
        dir.join("absent-file").into_os_string(),
    );
    result(run(&input), 5);
}

#[test]
fn complete_argument_validation_precedes_even_the_checkpoint_open() {
    let base: Vec<OsString> = [
        "evidence",
        "production",
        "documents",
        "--prefix",
        "absent-prefix",
        "--checkpoint",
        "absent-checkpoint",
        "--expect-first-seq",
        "0",
        "--expect-known-at",
        "0",
        "--expect-account",
        "all",
        "--expect-days",
        "all",
        "--json",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let zero = "0".repeat(64);
    let extra = vec![
        vec!["--document".into()],
        vec!["--document".into(), zero.clone(), "1".into()],
        vec![
            "--document".into(),
            "g".repeat(64),
            "1".into(),
            "file".into(),
        ],
        vec![
            "--document".into(),
            "0".repeat(63),
            "1".into(),
            "file".into(),
        ],
        vec![
            "--document".into(),
            zero.clone(),
            "256".into(),
            "file".into(),
        ],
        vec![
            "--document".into(),
            zero.clone(),
            "+1".into(),
            "file".into(),
        ],
        vec![
            "--document".into(),
            zero.clone(),
            "1".into(),
            "--record".into(),
        ],
        vec!["--document".into(), zero.clone(), "1".into(), "".into()],
        vec!["--json".into()],
        vec!["--expect-known-at".into(), "0".into()],
        vec!["--unknown".into(), "value".into()],
        vec![
            "--document".into(),
            zero.clone(),
            "1".into(),
            "file".into(),
            "--document".into(),
            zero,
            "2".into(),
            "other".into(),
        ],
    ];
    for suffix in extra {
        let mut bad = base.clone();
        bad.extend(suffix.into_iter().map(OsString::from));
        result(run(&bad), 2); // not the I/O error the absent files would cause
    }
    let mut bad = base;
    set(&mut bad, "--expect-first-seq", 1, "1");
    result(run(&bad), 2);
}

#[test]
fn one_total_byte_budget_applies_before_loading_the_second_large_document() {
    let mut docs = [document(1, b"one"), document(2, b"two")];
    docs.sort_by_key(|doc| doc.document_oid);
    let j = journal(&[entry(&citations(&docs, 3), 7, 10)]);
    let (input, dir) = args(&j, &[0], &docs);
    for index in 0..2 {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join(format!("document-{index}")))
            .unwrap();
        file.set_len((MAX_PRODUCTION_BYTES / 2 + 1) as u64).unwrap();
    }
    let error = result(run(&input), 8);
    assert!(error.contains("byte bound")); // not just a later commitment mismatch
}

#[test]
fn historical_and_empty_scopes_determine_documents_not_the_supplied_file_list() {
    let one = document(1, b"old");
    let two = document(2, b"late effective");
    let j = journal(&[
        entry(&citations(&[one], 3), 7, 10),
        entry(&citations(&[two], 3), 30, 10),
    ]);
    let (mut input, _) = args(&j, &[0], &[one]);
    set(&mut input, "--expect-known-at", 1, "7");
    assert!(result(run(&input), 0).contains("\"document_count\":1"));
    set(&mut input, "--expect-known-at", 1, "30");
    result(run(&input), 8); // late-effective entry omitted
    let (mut empty, _) = args(&j, &[], &[]);
    set(
        &mut empty,
        "--expect-account",
        1,
        format!("{:032x}", u128::MAX),
    );
    assert!(result(run(&empty), 0).contains("\"document_count\":0"));
    let j = journal(&[entry(&[], 7, 10)]);
    let (input, _) = args(&j, &[0], &[]);
    let json = result(run(&input), 0);
    assert!(json.contains("\"entry_count\":1"));
    assert!(json.contains("\"document_count\":0"));
}

#[test]
fn wrong_anchors_and_truncated_proofs_refuse_and_inventory_only_mode_is_unchanged() {
    let doc = document(1, DOCUMENT_SECRET);
    let j = journal(&[entry(&citations(&[doc], 3), 7, 10)]);
    let (input, dir) = args(&j, &[0], &[doc]);
    for end in [0, 1, j.prefix.len() - 1] {
        std::fs::write(dir.join("prefix"), &j.prefix[..end]).unwrap();
        result(run(&input), 8);
    }
    std::fs::write(dir.join("prefix"), &j.prefix).unwrap();
    let mut wrong = j.checkpoint;
    wrong.root[0] ^= 1;
    std::fs::write(dir.join("checkpoint"), wrong.encode()).unwrap();
    result(run(&input), 8);
    std::fs::write(dir.join("checkpoint"), j.checkpoint.encode()).unwrap();
    let (mut old_mode, _) = args(&j, &[0], &[]);
    old_mode.remove(2); // only remove the documents subcommand, not any file
    let output = run(&old_mode);
    assert_eq!(output.status.code(), Some(0));
    let json = String::from_utf8(output.stdout).unwrap();
    assert!(json.contains("\"proof_kind\":\"evidence_production\""));
    assert!(json.contains("\"document_bytes\":\"not_verified\""));
}

#[test]
fn help_and_human_reports_separate_original_bytes_from_unverified_provenance() {
    for words in [
        vec!["evidence", "production", "--help"],
        vec!["evidence", "production", "documents", "--help"],
    ] {
        let output = run(&words.into_iter().map(OsString::from).collect::<Vec<_>>());
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("documents")
        );
    }
    let doc = document(1, DOCUMENT_SECRET);
    let j = journal(&[entry(&citations(&[doc], 3), 7, 10), entry(&[], 11, 10)]);
    let (mut input, _) = args(&j, &[0, 1], &[doc]);
    input.retain(|arg| arg != "--json");
    let output = run(&input);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "bytes recomputed",
        "0 citations",
        "not full provenance",
        "signatures",
    ] {
        assert!(text.contains(expected));
    }
    for secret in [fixture::SECRET, DOCUMENT_SECRET] {
        assert!(!text.contains(std::str::from_utf8(secret).unwrap()));
        assert!(!text.contains(&hex(secret)));
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_document_paths_are_supported_but_document_selectors_are_not_lossy() {
    use std::os::unix::ffi::OsStringExt;
    let doc = document(1, DOCUMENT_SECRET);
    let j = journal(&[entry(&citations(&[doc], 3), 7, 10)]);
    let (mut input, dir) = args(&j, &[0], &[doc]);
    let path = dir.join(OsString::from_vec(b"document-\xff".to_vec()));
    std::fs::copy(dir.join("document-0"), &path).unwrap();
    set(&mut input, "--document", 3, path.into_os_string());
    result(run(&input), 0);
    let valid = input.clone();
    for offset in [1, 2] {
        let mut bad = valid.clone();
        set(
            &mut bad,
            "--document",
            offset,
            OsString::from_vec(vec![255]),
        );
        result(run(&bad), 2);
    }
}
