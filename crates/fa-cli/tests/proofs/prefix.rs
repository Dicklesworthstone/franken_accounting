//! Complete native prefixes through real persisted-book and bound-host paths.

use super::*;
use fa_verify::proof::production::derivation::verify_prefix_with_records;
use fa_verify::proof::production::{ProductionScope, verify_production_for};

fn full(f: &Fixture, state: &str) -> Json {
    exported(&f.book, &["prefix", "--with-record", "--state", state])
}

fn checkpoint(f: &Fixture, state: &str) -> Checkpoint {
    // Separate fixture-owned checkpoint input, not taken from the untrusted
    // prefix being checked. This is a test trust premise, not a signature.
    Checkpoint::decode(&bytes(&exported(
        &f.book,
        &["checkpoint", "--state", state],
    )))
    .unwrap()
}

#[test]
fn native_prefixes_work_before_the_chart_and_preserve_historical_payload_coverage() {
    let f = Fixture::new();
    let empty_state = f.checkpoint();
    let empty_oid = text(&empty_state, "oid");
    let empty = bytes(&full(&f, empty_oid));
    assert!(
        verify_prefix_with_records(&empty, &checkpoint(&f, empty_oid))
            .unwrap()
            .envelopes
            .is_empty()
    );

    let evidence = f.chart_and_evidence();
    let controls = f.checkpoint();
    let controls_oid = text(&controls, "oid");
    let control_prefix = bytes(&full(&f, controls_oid));
    let checked =
        verify_prefix_with_records(&control_prefix, &checkpoint(&f, controls_oid)).unwrap();
    assert!(!checked.envelopes.is_empty());
    // The chart, fiscal-year and period controls, and the evidence document's
    // import receipt: an evidence leaf (kind 3) since fa-va02.
    assert!(
        checked
            .envelopes
            .iter()
            .filter(|leaf| leaf.kind == 1)
            .all(|entry| entry.class >= 16)
    );
    assert_eq!(
        checked
            .envelopes
            .iter()
            .filter(|leaf| leaf.kind != 1)
            .map(|leaf| leaf.kind)
            .collect::<Vec<_>>(),
        vec![3]
    );

    let posted = f.post("native-prefix-sale", "2026-03-10", "12.34", &evidence);
    let state = f.checkpoint();
    let oid = text(&state, "oid");
    let trusted = checkpoint(&f, oid);
    let native = full(&f, oid);
    assert_eq!(get(get(&native, "claim"), "with_record"), &Json::Bool(true));
    assert_eq!(
        text(get(&native, "claim"), "payload_coverage"),
        "all_checkpoint_entries"
    );
    let native_bytes = bytes(&native);
    let prefix = verify_prefix_with_records(&native_bytes, &trusted).unwrap();
    let legacy = bytes(&exported(&f.book, &["prefix", "--state", oid]));
    assert_eq!(
        fa_verify::verify_prefix(&legacy, &trusted)
            .unwrap()
            .envelopes,
        prefix.envelopes
    );

    let included = exported(
        &f.book,
        &[
            "inclusion",
            "--with-record",
            "--entry",
            text(&posted, "vid"),
            "--state",
            oid,
        ],
    );
    let included_bytes = bytes(&included);
    let request = ProductionScope {
        first_seq: 0,
        known_at: trusted.through_seq,
        account: Some(account_vid(BOOK_ID, "1000").0),
        effective_days: Some((
            fa_time::DateDay::parse("2026-03-10").unwrap().0,
            fa_time::DateDay::parse("2026-03-10").unwrap().0,
        )),
    };
    let production =
        verify_production_for(&native_bytes, &[&included_bytes], &trusted, &request).unwrap();
    assert_eq!(production.entries.len(), 1);
    let inventory = fa_verify::evidence::inventory::production::verify_evidence_production_for(
        &native_bytes,
        &[&included_bytes],
        &trusted,
        &request,
    )
    .unwrap();
    assert_eq!(inventory.entries.len(), 1);
    assert!(inventory.citation_count > 0);
    assert!(verify_production_for(&native_bytes, &[], &trusted, &request).is_err());

    f.post("after-native-checkpoint", "2026-03-20", "2.00", &evidence);
    f.checkpoint();
    let before = f.head();
    assert_eq!(bytes(&full(&f, oid)), native_bytes);
    assert_eq!(bytes(&full(&f, empty_oid)), empty);
    assert_eq!(
        bytes(&exported(&f.book, &["prefix", "--state", oid])),
        legacy
    );
    assert_eq!(
        f.head(),
        before,
        "neither prefix mode writes or advances a checkpoint"
    );
}

#[test]
fn native_prefix_file_output_is_private_complete_and_never_overwrites() {
    let f = Fixture::new();
    f.chart_and_evidence();
    let state = f.checkpoint();
    let oid = text(&state, "oid");
    let expected = bytes(&full(&f, oid));
    let before = f.head();
    let path = f.dir.join("complete-prefix.proof");
    let args = [
        "prefix",
        "--with-record",
        "--state",
        oid,
        "--out",
        path.to_str().unwrap(),
    ];
    let result = exported(&f.book, &args);
    assert_eq!(get(&result, "bytes"), &Json::Null);
    assert_eq!(std::fs::read(&path).unwrap(), expected);
    verify_prefix_with_records(&expected, &checkpoint(&f, oid)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let mut repeat = vec!["proof"];
    repeat.extend(args);
    let (code, _) = run(&f.book, &repeat);
    assert_eq!(code, 5);
    assert_eq!(std::fs::read(&path).unwrap(), expected);
    assert_eq!(f.head(), before);
}

#[test]
fn native_prefixes_keep_admission_before_io_and_cannot_expand_bound_host_authority() {
    let dir = temp_dir();
    let missing = dir.join("absent");
    for grants in [&["read"][..], &["produce"][..], &[][..]] {
        let authority = LaunchAuthority::new(
            missing.clone(),
            None,
            "prefix-agent",
            LaunchProfile::Agent,
            grants,
        )
        .unwrap();
        let (code, _) = bound(&authority, &["proof", "prefix", "--with-record"]);
        assert_eq!(code, 7);
    }
    assert!(!missing.exists());
    let f = Fixture::new();
    f.checkpoint();
    let authority = LaunchAuthority::new(
        f.book.clone(),
        None,
        "prefix-agent",
        LaunchProfile::Agent,
        &["read", "produce"],
    )
    .unwrap();
    let (code, proof) = bound(&authority, &["proof", "prefix", "--with-record"]);
    assert_eq!(code, 0, "{}", proof.render());
    let (code, anchor) = bound(&authority, &["proof", "checkpoint"]);
    assert_eq!(code, 0);
    verify_prefix_with_records(
        &bytes(&proof),
        &Checkpoint::decode(&bytes(&anchor)).unwrap(),
    )
    .unwrap();
    let forbidden = f.dir.join("host-file.proof");
    let (code, _) = bound(
        &authority,
        &[
            "proof",
            "prefix",
            "--with-record",
            "--out",
            forbidden.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 2);
    assert!(!forbidden.exists());

    let book = f.open();
    let before = book.head().unwrap();
    let holder = principal_vid("prefix-auditor");
    let capability = Capability::embedded(holder, &["read", "produce"]).unwrap();
    let request = fa::ProofRequest {
        state: Some(Oid([0xff; 32])),
        kind: fa::ProofKind::PrefixWithRecords,
    };
    let expired = capability.clone().expiring_at(before);
    assert_eq!(
        book.export_proof(holder, &expired, request)
            .unwrap()
            .unwrap_err()
            .code,
        fa_policy::denial::code::EXPIRED
    );
    assert_eq!(
        book.export_proof(principal_vid("someone-else"), &capability, request)
            .unwrap()
            .unwrap_err()
            .code,
        fa_policy::denial::code::CAPABILITY
    );
    assert_eq!(book.head().unwrap(), before);
}

#[test]
fn portable_access_log_export_verifies_offline_and_preserves_its_retained_checkpoint() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    let auditor = LaunchAuthority::new(
        f.book.clone(),
        None,
        "portable-access-auditor",
        LaunchProfile::Preparer,
        &["read"],
    )
    .unwrap();
    let other = LaunchAuthority::new(
        f.book.clone(),
        None,
        "portable-access-other",
        LaunchProfile::Preparer,
        &["read"],
    )
    .unwrap();
    let after = f.head();
    for authority in [&auditor, &other] {
        let (code, log) = bound(authority, &["access", "log"]);
        assert_eq!(code, 0, "{}", log.render());
    }
    let events = f.open().access_log(fgdb_types::CommitSeq(after)).unwrap();
    assert_eq!(events.len(), 2);
    let created = f.checkpoint();
    let oid = text(&created, "oid");
    let expected = fa_verify::AccessLogExpectation {
        book_id: BOOK_ID.0,
        branch_id: Id128::TRUNK.0,
        checkpoint_oid: Some(unhex(text(&created, "checkpoint_oid")).try_into().unwrap()),
    };
    // The fixture independently retains its key and identities before asking
    // the exporter for an artifact; no trust key is taken from that artifact.
    let key = f.open().checkpoint_public_key();
    let request = fa_verify::AccessLogRequest {
        after_seq: after,
        through_seq: u64::try_from(integer(&created, "through_seq")).unwrap(),
        principal: Some(principal_vid("portable-access-auditor").0),
    };
    let proof = exported(&f.book, &["access-log", "--state", oid]);
    assert_eq!(text(&proof, "scope"), "seq_range_complete");
    assert_eq!(
        text(get(&proof, "claim"), "payload_coverage"),
        "all_checkpoint_records"
    );
    assert_eq!(
        text(get(&proof, "claim"), "meaning"),
        "recorded_pre_disclosure_attempts"
    );
    let retained = bytes(&proof);
    let verified = fa_verify::verify_access_log_proof(&retained, &[key], &request, &expected)
        .expect("native producer bytes pass the independent verifier");
    let selected = events
        .iter()
        .find(|event| Some(event.record.principal.0) == request.principal)
        .unwrap();
    assert_eq!(verified.events.len(), 1);
    assert_eq!(verified.events[0].recorded_at, selected.recorded_at.0);
    assert_eq!(verified.events[0].principal, selected.record.principal.0);
    assert_eq!(verified.events[0].command, selected.record.command);
    assert_eq!(
        verified.events[0].request_digest,
        selected.record.request_digest
    );
    assert!(verified.checked_records > events.len());
    assert!(
        fa_verify::verify_access_log_proof(
            &retained,
            &[key],
            &fa_verify::AccessLogRequest {
                principal: Some(u128::MAX),
                ..request
            },
            &expected,
        )
        .unwrap()
        .events
        .is_empty()
    );
    assert_eq!(
        fa_verify::verify_access_log_proof(
            &retained,
            &[key],
            &request,
            &fa_verify::AccessLogExpectation {
                book_id: [0xfe; 16],
                ..expected
            },
        )
        .unwrap_err()
        .predicate,
        "access.identity"
    );

    let (code, later_read) = bound(&auditor, &["access", "log"]);
    assert_eq!(code, 0, "{}", later_read.render());
    f.post("after-access-proof", "2026-03-20", "2.00", &evidence);
    f.checkpoint();
    let before = f.head();
    assert_eq!(
        bytes(&exported(&f.book, &["access-log", "--state", oid])),
        retained
    );
    let latest = bytes(&exported(&f.book, &["access-log"]));
    assert_eq!(
        fa_verify::verify_access_log_proof(&latest, &[key], &request, &expected)
            .unwrap_err()
            .predicate,
        "access.checkpoint_pin",
        "a newer legitimate checkpoint cannot replace an exact retained pin"
    );
    let path = f.dir.join("access-log.proof");
    let file = exported(
        &f.book,
        &[
            "access-log",
            "--state",
            oid,
            "--out",
            path.to_str().unwrap(),
        ],
    );
    assert_eq!(get(&file, "bytes"), &Json::Null);
    assert_eq!(std::fs::read(&path).unwrap(), retained);
    assert_eq!(f.head(), before, "proof export publishes no checkpoint");

    // Leave the original source path unavailable. The independent CLI can
    // read exactly one proof file; it cannot open the preserved source book.
    std::fs::rename(&f.book, f.dir.join("retained-source-book")).unwrap();
    assert!(!f.book.exists());
    let args = [
        "access-log",
        path.to_str().unwrap(),
        "--book",
        &fa_verify::blake3::hex(&expected.book_id),
        "--branch",
        &fa_verify::blake3::hex(&expected.branch_id),
        "--expect-checkpoint",
        &fa_verify::blake3::hex(&expected.checkpoint_oid.unwrap()),
        "--key",
        &fa_verify::blake3::hex(&key),
        "--after-seq",
        &request.after_seq.to_string(),
        "--through-seq",
        &request.through_seq.to_string(),
        "--reader",
        &format!("{:032x}", request.principal.unwrap()),
        "--json",
    ]
    .map(str::to_string);
    let read = |requested: &str| {
        if requested == path.to_str().unwrap() {
            std::fs::read(&path)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "offline verifier may read only the retained proof",
            ))
        }
    };
    let output = fa_verify::cli::run(&args, &read);
    assert_eq!(output.exit, 0, "{}\n{}", output.stdout, output.stderr);
    let result = json::parse(output.stdout.trim()).unwrap();
    let check = &get(&result, "checks").as_arr().unwrap()[0];
    assert_eq!(text(check, "scope"), "access_log_complete");
    let detail = get(check, "detail");
    assert_eq!(text(detail, "source_selection"), "recipient_bound");
    assert_eq!(integer(detail, "count"), 1);
}

#[test]
fn portable_access_log_export_requires_current_whole_book_read_and_produce() {
    let missing = temp_dir().join("absent-access-source");
    for grants in [&["read"][..], &["produce"][..], &[][..]] {
        let authority = LaunchAuthority::new(
            missing.clone(),
            None,
            "access-proof-agent",
            LaunchProfile::Agent,
            grants,
        )
        .unwrap();
        let (code, _) = bound(&authority, &["proof", "access-log"]);
        assert_eq!(code, 7);
    }
    assert!(!missing.exists(), "operation denial precedes source I/O");
    let f = Fixture::new();
    f.checkpoint();
    let book = f.open();
    let before = book.head().unwrap();
    let holder = principal_vid("access-proof-auditor");
    let capability = Capability::embedded(holder, &["read", "produce"]).unwrap();
    let unknown = fa::ProofRequest {
        state: Some(Oid([0xff; 32])),
        kind: fa::ProofKind::AccessLog,
    };
    for restricted in [
        capability.clone().expiring_at(before),
        capability.clone().for_accounts(&["1000"]).unwrap(),
        capability.clone().for_periods(&["FY2026-P03"]).unwrap(),
        capability
            .clone()
            .for_classes(&[fa_model::EntryClass::PERIOD_CONTROL])
            .unwrap(),
    ] {
        assert_eq!(
            book.export_proof(holder, &restricted, unknown)
                .unwrap()
                .unwrap_err()
                .exit,
            7,
            "authority is checked before resolving the deliberately unknown state"
        );
    }
    assert_eq!(book.head().unwrap(), before);
}
