//! Process-level regressions through the shipped command dispatcher.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::blake3::hex;
use fa_verify::proof::production::{MAX_PRODUCTION_BYTES, MAX_PRODUCTION_RECORDS};

use super::{fixture, production_fixture};
use production_fixture::{Journal, entry, journal};

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-evidence-production-{}-{}",
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

fn args(j: &Journal, indexes: &[usize]) -> (Vec<OsString>, PathBuf) {
    let dir = directory();
    std::fs::write(dir.join("prefix"), &j.prefix).unwrap();
    std::fs::write(dir.join("checkpoint"), j.checkpoint.encode()).unwrap();
    for (index, bytes) in j.records.iter().enumerate() {
        std::fs::write(dir.join(format!("record-{index}")), bytes).unwrap();
    }
    let mut args = vec![
        "evidence".into(),
        "production".into(),
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
    for index in indexes {
        args.extend([
            "--record".into(),
            dir.join(format!("record-{index}")).into_os_string(),
        ]);
    }
    (args, dir)
}

fn set(args: &mut [OsString], flag: &str, value: impl Into<OsString>) {
    let position = args.iter().position(|argument| argument == flag).unwrap();
    args[position + 1] = value.into();
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
        assert!(!text.contains(std::str::from_utf8(fixture::SECRET).unwrap()));
        assert!(!text.contains(&hex(fixture::SECRET)));
    }
    if exit == 0 {
        assert!(err.is_empty(), "{err}");
        for field in [
            "\"verified\":true",
            "\"proof_kind\":\"evidence_production\"",
            "\"scope\":\"seq_range_complete\"",
            "complete_for_requested_scope",
            "complete_for_selected_entries",
            "\"document_bytes\":\"not_verified\"",
            "\"supplemental_evidence\":\"not_verified\"",
            "\"request_check\":\"recipient_scope\"",
        ] {
            assert!(out.contains(field), "missing {field}: {out}");
        }
    } else {
        assert!(out.contains("\"verified\":false"));
        assert!(out.contains("\"event\":\"error\""));
        assert!(!out.contains("proof_verified"));
        assert!(!out.contains("\"entries\":["), "partial production emitted");
        assert!(
            !out.contains("\"citations\":["),
            "partial citations emitted"
        );
    }
    out
}

#[test]
fn complete_scope_binary_reports_all_rows_with_exact_coordinates_and_no_payloads() {
    let citations = fixture::citations();
    let j = journal(&[
        entry(&citations, 7, 10),
        entry(&[], 11, 10),
        entry(&citations, u64::MAX, 10),
    ]);
    let (args, dir) = args(&j, &[0, 1, 2]);
    let json = result(run(&args), 0);
    assert!(json.contains("\"entry_count\":3"));
    assert!(json.contains("\"citation_count\":6"));
    assert!(json.contains("\"citations\":[]"));
    for field in ["through_seq", "known_at", "recorded_at"] {
        assert!(json.contains(&format!("\"{field}\":\"18446744073709551615\"")));
    }
    assert_eq!(std::fs::read(dir.join("prefix")).unwrap(), j.prefix);
    assert_eq!(
        std::fs::read(dir.join("checkpoint")).unwrap(),
        j.checkpoint.encode()
    );
    for (index, bytes) in j.records.iter().enumerate() {
        assert_eq!(
            std::fs::read(dir.join(format!("record-{index}"))).unwrap(),
            *bytes
        );
    }
}

#[test]
fn omission_duplicate_reordering_extra_records_and_false_last_citations_are_atomic_failures() {
    let citations = fixture::citations();
    let j = journal(&[
        entry(&citations, 7, 10),
        entry(&[], 11, 10),
        entry(&citations, 30, 10),
    ]);
    for indexes in [vec![0, 2], vec![0, 0, 2], vec![2, 1, 0], vec![0, 1, 2, 2]] {
        result(run(&args(&j, &indexes).0), 8);
    }
    let mut bad = entry(&citations, 11, 10);
    bad.proposal.push(0); // genuine rehashed inclusion, invalid proposal tail
    let j = journal(&[entry(&citations, 7, 10), bad]);
    result(run(&args(&j, &[0, 1]).0), 8);
}

#[test]
fn exact_scope_filters_historical_entries_and_proves_empty_results() {
    let citations = fixture::citations();
    let j = journal(&[
        entry(&citations, 7, 10),
        entry(&[], 11, 20),
        entry(&citations, 30, 10),
    ]);
    let (mut selected, _) = args(&j, &[0, 2]);
    set(&mut selected, "--expect-account", format!("{:032x}", 10));
    set(&mut selected, "--expect-days", "10:10");
    assert!(result(run(&selected), 0).contains("\"entry_count\":2"));
    set(&mut selected, "--expect-known-at", "11");
    result(run(&selected), 8); // later entry is extra, even with an older civil day
    selected.truncate(selected.len() - 2);
    assert!(result(run(&selected), 0).contains("\"entry_count\":1"));
    set(&mut selected, "--expect-known-at", "31");
    result(run(&selected), 8); // beyond trusted frontier
    let (mut empty, _) = args(&j, &[]);
    result(run(&empty), 8); // no files is not a complete unfiltered extract
    set(&mut empty, "--expect-account", format!("{:032x}", 99));
    assert!(result(run(&empty), 0).contains("\"entry_count\":0"));
    result(run(&args(&journal(&[]), &[]).0), 0);
}

#[test]
fn complete_request_validation_precedes_missing_files_and_never_infers_selector_defaults() {
    let j = journal(&[entry(&fixture::citations(), 7, 10)]);
    let (mut base, dir) = args(&j, &[]);
    set(
        &mut base,
        "--prefix",
        dir.join("absent-prefix").into_os_string(),
    );
    set(
        &mut base,
        "--checkpoint",
        dir.join("absent-checkpoint").into_os_string(),
    );
    for flag in [
        "--prefix",
        "--checkpoint",
        "--expect-first-seq",
        "--expect-known-at",
        "--expect-account",
        "--expect-days",
    ] {
        let at = base.iter().position(|argument| argument == flag).unwrap();
        let mut missing = base.clone();
        drop(missing.drain(at..at + 2));
        result(run(&missing), 2);
        let mut duplicate = base.clone();
        duplicate.extend_from_slice(&base[at..at + 2]);
        result(run(&duplicate), 2);
    }
    for (flag, value) in [
        ("--expect-first-seq", "8"),
        ("--expect-first-seq", "-1"),
        ("--expect-known-at", "18446744073709551616"),
        ("--expect-known-at", "+7"),
        ("--expect-known-at", "７"),
        ("--expect-account", "10"),
        ("--expect-account", "ALL"),
        ("--expect-days", "20:10"),
        ("--expect-days", "0:2147483648"),
        ("--expect-days", "-2147483649:0"),
        ("--expect-days", "0:1:2"),
        ("--expect-days", "0: 1"),
        ("--expect-days", "+0:1"),
    ] {
        let mut invalid = base.clone();
        set(&mut invalid, flag, value);
        result(run(&invalid), 2);
    }
    for extra in [
        vec!["--json"],
        vec!["--record"],
        vec!["--expect-entry", "aa"],
        vec!["--help"],
    ] {
        let mut invalid = base.clone();
        invalid.extend(extra.into_iter().map(OsString::from));
        result(run(&invalid), 2);
    }
    let mut too_many = base.clone();
    for _ in 0..=MAX_PRODUCTION_RECORDS {
        too_many.extend(["--record".into(), "missing".into()]);
    }
    result(run(&too_many), 2);
    result(run(&base), 5); // only a fully valid invocation reaches file I/O
}

#[test]
fn corruption_truncation_missing_payloads_and_aggregate_file_budget_refuse() {
    let citations = fixture::citations();
    let j = journal(&[entry(&citations, 7, 10)]);
    let (args, dir) = args(&j, &[0]);
    for end in [0, 1, j.prefix.len() - 1] {
        std::fs::write(dir.join("prefix"), &j.prefix[..end]).unwrap();
        result(run(&args), 8);
    }
    std::fs::write(dir.join("prefix"), &j.prefix).unwrap();
    let mut wrong = j.checkpoint.encode();
    wrong[0] ^= 1;
    std::fs::write(dir.join("checkpoint"), wrong).unwrap();
    result(run(&args), 8);
    std::fs::write(dir.join("checkpoint"), j.checkpoint.encode()).unwrap();
    let mut missing = entry(&citations, 7, 10);
    missing.include_record = false;
    let no_record = journal(&[missing]);
    std::fs::write(dir.join("record-0"), &no_record.records[0]).unwrap();
    result(run(&args), 8);
    let mut aggregate = args.clone();
    aggregate.extend(["--record".into(), dir.join("record-0").into_os_string()]);
    // Each file individually is below 64 MiB. The second occurrence exceeds
    // the remaining budget and must be refused before both are loaded.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("record-0"))
        .unwrap();
    file.set_len((MAX_PRODUCTION_BYTES / 2 + 1) as u64).unwrap();
    let error = result(run(&aggregate), 8);
    assert!(error.contains("byte bound"));
}

#[test]
fn human_output_and_help_make_the_scope_and_unverified_document_boundary_explicit() {
    for words in [
        vec!["evidence", "--help"],
        vec!["evidence", "production", "--help"],
        vec!["evidence", "production", "-h"],
    ] {
        let output = run(&words.into_iter().map(OsString::from).collect::<Vec<_>>());
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("production")
        );
    }
    let j = journal(&[entry(&fixture::citations(), 7, 10), entry(&[], 11, 20)]);
    let (mut args, _) = args(&j, &[0, 1]);
    args.retain(|arg| arg != "--json");
    let output = run(&args);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let out = String::from_utf8(output.stdout).unwrap();
    assert!(out.contains("original citation lists"));
    assert!(out.contains("0 citations"));
    assert!(out.contains("Document bytes, supplemental evidence"));
    assert!(!out.contains(std::str::from_utf8(fixture::SECRET).unwrap()));
    assert!(!out.contains(&hex(fixture::SECRET)));
}

#[cfg(unix)]
#[test]
fn non_utf8_paths_work_without_admitting_non_utf8_selector_values() {
    use std::os::unix::ffi::OsStringExt;
    let j = journal(&[entry(&fixture::citations(), 7, 10)]);
    let (mut args, dir) = args(&j, &[0]);
    for (flag, name) in [
        ("--prefix", "prefix"),
        ("--checkpoint", "checkpoint"),
        ("--record", "record-0"),
    ] {
        let path = dir.join(OsString::from_vec(
            format!("{name}-").bytes().chain([255]).collect(),
        ));
        std::fs::copy(dir.join(name), &path).unwrap();
        set(&mut args, flag, path.into_os_string());
    }
    result(run(&args), 0);
    set(&mut args, "--expect-days", OsString::from_vec(vec![255]));
    result(run(&args), 2);
}

#[test]
fn signed_day_extrema_and_maximum_recipient_coordinates_round_trip_exactly() {
    let j = journal(&[
        entry(&fixture::citations(), 7, i32::MIN),
        entry(&fixture::citations(), u64::MAX, i32::MAX),
    ]);
    let (mut all, _) = args(&j, &[0, 1]);
    set(&mut all, "--expect-days", "-2147483648:2147483647");
    let out = result(run(&all), 0);
    assert!(out.contains("\"first\":\"-2147483648\""));
    assert!(out.contains("\"last\":\"2147483647\""));
    let (mut last, _) = args(&j, &[1]);
    set(&mut last, "--expect-first-seq", u64::MAX.to_string());
    assert!(result(run(&last), 0).contains("\"entry_count\":1"));
    let (mut empty, _) = args(&j, &[]);
    set(
        &mut empty,
        "--expect-account",
        format!("{:032x}", u128::MAX),
    );
    let out = result(run(&empty), 0);
    assert!(out.contains("\"account\":\"ffffffffffffffffffffffffffffffff\""));
    assert!(out.contains("\"entry_count\":0"));
}
