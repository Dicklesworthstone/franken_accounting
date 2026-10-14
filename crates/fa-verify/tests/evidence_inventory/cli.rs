//! Actual-binary coverage for the evidence inventory command.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::blake3::hex;
use fa_verify::evidence::{EvidenceCitation, MAX_PROOF_BYTES};

use super::fixture;

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-evidence-inventory-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let result = std::fs::create_dir(&path);
        if matches!(&result, Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists) {
            continue;
        }
        result.expect("create retained fixture");
        return path;
    }
}

fn args(f: &fixture::Fixture) -> (Vec<OsString>, PathBuf) {
    let dir = directory();
    std::fs::write(dir.join("proof"), &f.proof).unwrap();
    std::fs::write(dir.join("checkpoint"), f.checkpoint.encode()).unwrap();
    (
        vec![
            "evidence".into(),
            "--proof".into(),
            dir.join("proof").into_os_string(),
            "--checkpoint".into(),
            dir.join("checkpoint").into_os_string(),
            "--expect-entry".into(),
            hex(&f.entry_digest).into(),
            "--json".into(),
        ],
        dir,
    )
}

fn encoded(citation: &EvidenceCitation) -> OsString {
    format!(
        "{}:{}:{}",
        hex(&citation.document_oid),
        hex(&citation.doc_commit),
        citation.role
    )
    .into()
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
    assert_eq!(out.lines().count(), 1, "one atomic JSON result: {out}");
    for text in [&out[..], &err[..]] {
        assert!(!text.contains(std::str::from_utf8(fixture::SECRET).unwrap()));
        assert!(!text.contains(&hex(fixture::SECRET)));
    }
    if exit == 0 {
        assert!(err.is_empty(), "{err}");
        assert!(out.contains("\"event\":\"proof_verified\""));
        assert!(out.contains("\"proof_kind\":\"evidence_inventory\""));
        assert!(out.contains("\"scope\":\"inclusion\""));
        assert!(out.contains("\"citations\":\"complete_for_requested_entry\""));
        assert!(out.contains("\"document_bytes\":\"not_verified\""));
    } else {
        assert!(out.contains("\"event\":\"error\""));
        assert!(out.contains("\"verified\":false"));
        assert!(!out.contains("proof_verified"));
        assert!(
            !out.contains("\"citations\":["),
            "partial inventory emitted"
        );
    }
    out
}

#[test]
fn binary_inventory_and_exact_matching_retain_all_rows_and_exact_u64_coordinates() {
    let citations = fixture::citations();
    let f = fixture::proof(&fixture::proposal(&citations).bytes, true, u64::MAX);
    let (mut args, dir) = args(&f);
    let inventory = result(run(&args), 0);
    assert!(inventory.contains("\"request_check\":\"entry_only\""));
    assert!(inventory.contains("\"recorded_at\":\"18446744073709551615\""));
    assert!(inventory.contains("\"through_seq\":\"18446744073709551615\""));
    assert!(inventory.contains("\"citation_count\":3"));
    for citation in &citations {
        args.extend(["--expect-citation".into(), encoded(citation)]);
        assert!(inventory.contains(&hex(&citation.document_oid)));
    }
    let exact = result(run(&args), 0);
    assert!(exact.contains("exact_requested_citation_set"));
    assert!(exact.contains("entry_and_exact_citations"));
    assert_eq!(std::fs::read(dir.join("proof")).unwrap(), f.proof);
    assert_eq!(
        std::fs::read(dir.join("checkpoint")).unwrap(),
        f.checkpoint.encode()
    );
    args.truncate(args.len() - 2);
    result(run(&args), 8); // a genuine subset cannot be passed off as exact
}

#[test]
fn binary_empty_is_an_explicit_recipient_expectation_not_a_missing_flag() {
    for citations in [Vec::new(), fixture::citations()] {
        let f = fixture::proof(&fixture::proposal(&citations).bytes, true, 7);
        let (mut args, _) = args(&f);
        result(run(&args), 0);
        args.push("--expect-empty".into());
        result(run(&args), if citations.is_empty() { 0 } else { 8 });
    }
}

#[test]
fn binary_syntax_errors_precede_missing_files_and_never_normalize_requests() {
    let citations = fixture::citations();
    let f = fixture::proof(&fixture::proposal(&citations).bytes, true, 7);
    let (mut base, dir) = args(&f);
    base[2] = dir.join("missing-proof").into_os_string();
    base[4] = dir.join("missing-checkpoint").into_os_string();
    let row = encoded(&citations[0]);
    let mut cases = vec![
        vec![
            "--expect-empty".into(),
            "--expect-citation".into(),
            row.clone(),
        ],
        vec![
            "--expect-citation".into(),
            row.clone(),
            "--expect-citation".into(),
            row,
        ],
        vec![
            "--expect-citation".into(),
            encoded(&citations[1]),
            "--expect-citation".into(),
            encoded(&citations[0]),
        ],
        vec!["--expect-empty".into(), "--expect-empty".into()],
        vec!["--json".into()],
        vec!["--view".into(), "missing".into()],
        vec!["--expect-citation".into()],
    ];
    for value in [
        "",
        "aa:bb:3",
        &format!("{}:{}:256", "aa".repeat(32), "bb".repeat(32)),
        &format!("{}:{}:+1", "aa".repeat(32), "bb".repeat(32)),
        &format!("{}:{}:１", "aa".repeat(32), "bb".repeat(32)),
    ] {
        cases.push(vec!["--expect-citation".into(), value.into()]);
    }
    for extra in cases {
        let mut invalid = base.clone();
        invalid.extend(extra);
        result(run(&invalid), 2);
    }
    for index in [1, 3, 5] {
        let mut missing = base.clone();
        drop(missing.drain(index..index + 2));
        result(run(&missing), 2);
        let mut duplicate = base.clone();
        duplicate.extend_from_slice(&base[index..index + 2]);
        result(run(&duplicate), 2);
    }
    for value in ["aa", &"g".repeat(64), &"é".repeat(32)] {
        let mut invalid = base.clone();
        invalid[6] = value.into();
        result(run(&invalid), 2);
    }
    result(run(&base), 5);
}

#[test]
fn binary_refuses_wrong_entry_tampered_truncated_and_oversized_inputs_atomically() {
    let f = fixture::proof(&fixture::proposal(&fixture::citations()).bytes, true, 7);
    let (args, dir) = args(&f);
    result(run(&args), 0);
    let mut wrong = args.clone();
    wrong[6] = "ff".repeat(32).into();
    result(run(&wrong), 8);
    for end in [0, 1, f.proof.len() / 2, f.proof.len() - 1] {
        std::fs::write(dir.join("proof"), &f.proof[..end]).unwrap();
        result(run(&args), 8);
    }
    let mut trailing = f.proof.clone();
    trailing.push(0);
    std::fs::write(dir.join("proof"), trailing).unwrap();
    result(run(&args), 8);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("proof"))
        .unwrap();
    file.set_len(MAX_PROOF_BYTES as u64 + 1).unwrap();
    result(run(&args), 8);
    std::fs::write(dir.join("proof"), &f.proof).unwrap();
    let mut checkpoint = f.checkpoint.encode();
    checkpoint[0] ^= 1;
    std::fs::write(dir.join("checkpoint"), checkpoint).unwrap();
    result(run(&args), 8);
}

#[test]
fn binary_human_reports_and_help_state_the_single_entry_boundary() {
    for flags in [
        vec!["--help"],
        vec!["evidence", "--help"],
        vec!["evidence", "-h"],
    ] {
        let output = run(&flags.into_iter().map(OsString::from).collect::<Vec<_>>());
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("evidence")
        );
    }
    let f = fixture::proof(&fixture::proposal(&fixture::citations()).bytes, true, 7);
    let (mut args, _) = args(&f);
    args.pop();
    let output = run(&args);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("complete citation list for this entry only"));
    assert!(text.contains("production completeness were not checked"));
    assert!(!text.contains(std::str::from_utf8(fixture::SECRET).unwrap()));
    assert!(!text.contains(&hex(fixture::SECRET)));
}

#[cfg(unix)]
#[test]
fn binary_paths_can_be_non_utf8_but_expected_citations_cannot() {
    use std::os::unix::ffi::OsStringExt;
    let f = fixture::proof(&fixture::proposal(&fixture::citations()).bytes, true, 7);
    let (mut args, dir) = args(&f);
    for (index, name) in [(2, "proof"), (4, "checkpoint")] {
        let path = dir.join(OsString::from_vec(
            format!("{name}-").bytes().chain([255]).collect(),
        ));
        std::fs::copy(dir.join(name), &path).unwrap();
        args[index] = path.into_os_string();
    }
    result(run(&args), 0);
    args.extend(["--expect-citation".into(), OsString::from_vec(vec![255])]);
    result(run(&args), 2);
}
