//! Large accounting entries retain one identity through native storage,
//! historical certification, reopen, and independent portable verification.

use super::*;

fn reseal_trial_balance(certificate: &mut ReportCertificate) {
    let bytes = certificate.canonical_bytes().unwrap();
    let mut hash = fgdb_crypto::Hasher::new();
    hash.update(b"fa:report-certificate:v1");
    hash.update(&bytes[..bytes.len() - 32]);
    certificate.digest = hash.finalize().0;
}

fn verify_bundle(book: &mut Book, certificate: &ReportCertificate) {
    let produced = super::report_bundle::produce(book, certificate);
    let key = book.checkpoint_public_key();
    let anchor = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&anchor.checkpoint),
        Some(&produced.receipt),
        Some(&certificate.digest),
    )
    .expect("independent verifier must reproduce the large Entry's canonical accounting bytes");
    assert_eq!(verified.output, certificate.output);
    assert_eq!(verified.known_at, certificate.known_at.0);
    assert_eq!(verified.certificate_digest, certificate.digest);
    assert_eq!(verified.scope, "recomputation");
}

#[test]
fn large_entry_certificates_bind_fragments_and_replay_offline_after_reopen() {
    let seed = 0x98;
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fa-entry-certificate-storage-{}-{suffix}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let mut fixture = Fixture::at(seed, Some(&directory));
    let maintain = Capability::embedded(PRINCIPAL, &["read", "verify", "maintain"]).unwrap();
    fixture
        .book
        .advance_registers(PRINCIPAL, &maintain, JANUARY)
        .unwrap()
        .unwrap();
    let selector = fa::TrialBalanceSelection::Periods(vec![JANUARY.into()]);
    let original = fixture
        .book
        .certify_trial_balance(selector.clone(), None)
        .unwrap()
        .unwrap();
    let before = fixture.book.head().unwrap();
    assert!(
        original
            .certificate
            .inputs
            .iter()
            .all(|input| !input.statement.contains("EntryFragment"))
    );

    let mut legs = Vec::new();
    for amount in 1..=256 {
        legs.extend(fixture.legs(fixture.usd, ("1000", "4000"), amount));
    }
    let proposal = fixture.proposal(
        day(2026, 1, 15),
        b"complete-512-leg-entry",
        EntryClass::ORIGINAL,
        legs,
    );
    let canonical = proposal
        .clone()
        .seal(Vec::new(), None)
        .unwrap()
        .encode()
        .unwrap();
    assert!(
        CanonicalScalar::bytes(canonical)
            .unwrap()
            .encode()
            .unwrap()
            .len()
            > 16 * 1024
    );
    let posted = fixture.commit(proposal.clone());
    assert_eq!(
        posted.recorded_at().0,
        before.0 + 1,
        "one accounting publication"
    );
    let (entry, recorded_at) = fixture
        .book
        .read_entry(posted.entry_ref().vid)
        .unwrap()
        .unwrap();
    assert_eq!(
        entry.proposal.legs, proposal.legs,
        "every original leg is retained in order"
    );
    assert_eq!(entry.proposal.legs.len(), 512);
    assert_eq!(entry.entry_digest, posted.entry_ref().entry_digest);
    assert_eq!(recorded_at, posted.recorded_at());
    let canonical = entry.encode().unwrap();
    let retry_at = fixture.book.head().unwrap();
    assert!(matches!(
        fixture.commit(proposal.clone()),
        Posted::AlreadyRecorded { .. }
    ));
    assert_eq!(fixture.book.head().unwrap(), retry_at);

    let certified = fixture
        .book
        .certify_trial_balance(selector, Some(recorded_at))
        .unwrap()
        .unwrap();
    assert_eq!(
        certified.report.unit_totals[&fixture.usd.0],
        (32_896, 32_896)
    );
    assert_eq!(
        certified.certificate.journal_leaves,
        original.certificate.journal_leaves + 1
    );
    assert_eq!(
        certified.certificate.inputs.len(),
        original.certificate.inputs.len() + 1
    );
    assert!(
        certified
            .certificate
            .inputs
            .last()
            .unwrap()
            .statement
            .starts_with("MATCH (n:EntryFragment) ")
    );
    assert_eq!(
        fixture
            .book
            .replay_report(&original.certificate)
            .unwrap()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        original.certificate.output
    );
    assert_eq!(
        fixture
            .book
            .replay_report(&certified.certificate)
            .unwrap()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        certified.certificate.output
    );

    // Recompute the certificate digest so refusal proves that replay requires
    // the actual fragment closure, rather than merely spotting a stale hash.
    let mut omitted = certified.certificate.clone();
    omitted.inputs.pop();
    reseal_trial_balance(&mut omitted);
    let omitted = ReportCertificate::decode(&omitted.canonical_bytes().unwrap()).unwrap();
    assert!(fixture.book.replay_report(&omitted).unwrap().is_err());
    let mut reordered = certified.certificate.clone();
    let last = reordered.inputs.len() - 1;
    reordered.inputs.swap(0, last);
    reseal_trial_balance(&mut reordered);
    assert!(ReportCertificate::decode(&reordered.canonical_bytes().unwrap()).is_err());

    let literal = fixture.book.fold_period(JANUARY).unwrap();
    let maintained = fixture
        .book
        .advance_registers(PRINCIPAL, &maintain, JANUARY)
        .unwrap()
        .unwrap();
    assert!(!maintained.rebuilt);
    assert_eq!(maintained.fold, literal);
    let rebuilt = fixture
        .book
        .rebuild_registers(PRINCIPAL, &maintain, JANUARY)
        .unwrap()
        .unwrap();
    assert_eq!(rebuilt.fold, literal);
    assert!(fixture.book.verify_registers(JANUARY).unwrap().is_green());
    let projections = fixture.book.verify_projections(None).unwrap();
    assert!(projections.is_green());
    assert_eq!(projections.legs_checked, 512);

    let retained = fixture
        .book
        .retain_certificate(
            PRINCIPAL,
            &Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap(),
            &certified.certificate,
        )
        .unwrap()
        .unwrap();
    fixture.transfer(
        day(2026, 1, 20),
        b"later-small-entry",
        fixture.usd,
        ("1000", "4000"),
        7,
    );
    verify_bundle(&mut fixture.book, &original.certificate);
    verify_bundle(&mut fixture.book, &certified.certificate);
    drop(fixture);

    let mut book = Book::open_dir(
        &directory,
        BookKeys::for_development(seed),
        Entropy::deterministic(u64::from(seed)),
    )
    .unwrap();
    let (reopened, at) = book.read_entry(posted.entry_ref().vid).unwrap().unwrap();
    assert_eq!(at, recorded_at);
    assert_eq!(reopened.encode().unwrap(), canonical);
    let loaded = book.read_certificate(&retained.digest).unwrap().unwrap();
    assert_eq!(loaded, certified.certificate);
    for certificate in [&original.certificate, &loaded] {
        assert_eq!(
            book.replay_report(certificate)
                .unwrap()
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            certificate.output
        );
        verify_bundle(&mut book, certificate);
    }
    let retry_at = book.head().unwrap();
    let retry = book
        .post(PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        })
        .unwrap()
        .unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(book.head().unwrap(), retry_at);
}
