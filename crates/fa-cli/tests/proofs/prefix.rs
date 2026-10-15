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
    assert!(checked.envelopes.iter().all(|entry| entry.class >= 16));

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
