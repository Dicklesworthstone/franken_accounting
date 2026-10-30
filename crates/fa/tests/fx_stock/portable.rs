//! The exported bytes must reproduce exact historical carrying values in the
//! standalone verifier, without access to the source book or its arithmetic.

use super::*;
use fa::{ReportCertificate, TrialBalanceSelection};

fn producer() -> Capability {
    cap(&["read", "produce"])
}

fn checkpoint(book: &mut Book) -> Oid {
    book.checkpoint(PRINCIPAL, &cap(&["read", "produce", "witness"]))
        .unwrap()
        .unwrap()
        .checkpoint
        .checkpoint
        .body
        .state_oid
}

fn certify(fixture: &mut Fixture, selection: TrialBalanceSelection) -> ReportCertificate {
    fixture
        .book
        .certify_functional_trial_balance(&producer(), selection, None)
        .unwrap()
        .unwrap()
        .certificate
}

fn produce(
    fixture: &mut Fixture,
    state: Oid,
    certificate: &ReportCertificate,
) -> fa::ProducedBundle {
    fixture
        .book
        .produce_report_bundle(PRINCIPAL, &producer(), Some(state), certificate)
        .unwrap()
        .unwrap()
        .unwrap()
}

fn verify(
    fixture: &Fixture,
    produced: &fa::ProducedBundle,
    certificate: &ReportCertificate,
) -> fa_verify::report::VerifiedReport {
    fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[fixture.book.checkpoint_public_key()],
        None,
        Some(&produced.receipt),
        Some(&certificate.digest),
    )
    .unwrap()
}

fn average_post(fixture: &mut Fixture) {
    let rate = FxRateDocument::new(
        FxRateTerms {
            base_unit: fixture.usd,
            quote_unit: fixture.eur,
            rate_num: 6,
            rate_den: 5,
            rounding: RoundingLaw::HalfEven,
        },
        day(2, 28),
        1_767_571_200_000_000_000,
        FxRatePurpose::PeriodAverage,
        "Original February average",
    )
    .unwrap();
    let oid = fixture
        .book
        .upload_fx_rate(&cap(&["post"]), &rate)
        .unwrap()
        .unwrap()
        .oid;
    let proposal = fixture.proposal(b"portable-average", day(2, 5), 5_000);
    let valued = fixture
        .book
        .value_fx_proposal(
            &cap(&["read", "post"]),
            proposal,
            FxLawId::PeriodAverage,
            &[oid],
        )
        .unwrap()
        .unwrap();
    fixture.book.post(request(valued)).unwrap().unwrap();
}

#[test]
fn functional_exports_recompute_stock_activity_rates_and_the_original_known_prefix() {
    let mut fixture = Fixture::new();
    fixture.post(b"portable-spot", day(1, 5), 10_000, 11);
    average_post(&mut fixture);
    let certificates: Vec<_> = [
        TrialBalanceSelection::AsOf(day(2, 28)),
        TrialBalanceSelection::Periods(vec!["FY2026-P02".into()]),
        TrialBalanceSelection::Activity(vec!["FY2026-P02".into()]),
    ]
    .into_iter()
    .map(|selection| certify(&mut fixture, selection))
    .collect();
    fixture.rate(
        day(1, 5),
        99,
        "Later unused quote cannot replace the original",
    );
    fixture.post(b"portable-late-backdate", day(1, 20), 2_000, 13);
    let state = checkpoint(&mut fixture.book);
    let before = fixture.book.head().unwrap();
    for certificate in &certificates {
        let produced = produce(&mut fixture, state, certificate);
        let again = produce(&mut fixture, state, certificate);
        assert_eq!(produced.bundle.bytes, again.bundle.bytes);
        assert_eq!(produced.receipt, again.receipt);
        assert_eq!(
            produced.documents.len(),
            2,
            "even activity retains the complete valuation prefix"
        );
        let verified = verify(&fixture, &produced, certificate);
        assert_eq!(verified.output, certificate.output);
        assert_eq!(verified.known_at, certificate.known_at.0);
        assert_eq!(verified.certificate_digest, certificate.digest);
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
        assert!(verified.functional_trial_balance.is_some());
        assert!(verified.statement.is_none());
        assert!(verified.rows.is_empty());
        assert!(
            fa_verify::report::verify_report_expected(
                &produced.bundle.bytes,
                &[fixture.book.checkpoint_public_key()],
                None,
                Some(&produced.receipt),
                Some(&[0; 32]),
            )
            .is_err(),
            "a different reporting question cannot pin the source"
        );
    }
    assert_eq!(
        fixture.book.head().unwrap(),
        before,
        "proof production publishes no accounting or metadata changes"
    );
}

/// Locate the transport's final exact Rate closure, leaving the original
/// certificate, checkpoint, prefix and six registries untouched.
fn rates_offset(bytes: &[u8]) -> usize {
    let mut reader = fa_model::Reader::new(bytes);
    let bound = fa_notary::report::MAX_REPORT_BUNDLE_BYTES;
    assert_eq!(
        reader.bytes(64, "format").unwrap(),
        fa_notary::report::REPORT_BUNDLE_FORMAT
    );
    assert_eq!(reader.u16("major").unwrap(), 3);
    assert_eq!(reader.u16("minor").unwrap(), 0);
    for field in ["certificate", "checkpoint", "prefix"] {
        reader.bytes(bound, field).unwrap();
    }
    for _ in 0..reader.u32("records").unwrap() {
        reader.u32("proposal length").unwrap();
        reader.bytes(bound, "record").unwrap();
    }
    for _ in 0..reader.u32("migrations").unwrap() {
        reader.u64("open index").unwrap();
        reader.bytes(bound, "migration").unwrap();
    }
    assert_eq!(reader.u32("registries").unwrap(), 6);
    for _ in 0..6 {
        reader.str(128, "registry name").unwrap();
        reader.bytes(1024 * 1024, "registry").unwrap();
    }
    reader.bytes(1024 * 1024, "BookSpec").unwrap();
    // The canonical reader deliberately exposes no cursor; the final closure
    // can be measured exactly from its bounded decoded frames.
    let count = reader.u32("rate count").unwrap();
    let mut closure_len = 4;
    for _ in 0..count {
        reader.fixed::<32>("Rate OID").unwrap();
        closure_len += 36 + reader.bytes(4096, "Rate payload").unwrap().len();
    }
    reader.finish().unwrap();
    bytes.len() - closure_len
}

/// Rebuild the authenticated source from a real export so both producer and
/// independent consumer are tested against the same hostile wrapper. The Rate
/// content commitment alone does not authenticate who originally imported it.
fn forged_rate_receiver(
    fixture: &Fixture,
    produced: &fa::ProducedBundle,
    certificate: &ReportCertificate,
) -> Vec<u8> {
    let mut reader = fa_model::Reader::new(&produced.bundle.bytes);
    let bound = fa_notary::report::MAX_REPORT_BUNDLE_BYTES;
    reader.bytes(64, "format").unwrap();
    assert_eq!(reader.u16("major").unwrap(), 3);
    assert_eq!(reader.u16("minor").unwrap(), 0);
    let certificate_bytes = reader.bytes(bound, "certificate").unwrap();
    let signed = fa_verify::verify_checkpoint(
        reader.bytes(bound, "checkpoint").unwrap(),
        &[fixture.book.checkpoint_public_key()],
    )
    .unwrap();
    let prefix =
        fa_verify::verify_prefix(reader.bytes(bound, "prefix").unwrap(), &signed.checkpoint)
            .unwrap();
    assert_eq!(
        reader.u32("records").unwrap() as usize,
        prefix.envelopes.len()
    );
    let mut records = Vec::new();
    for (index, envelope) in prefix.envelopes.iter().enumerate() {
        reader.u32("proposal length").unwrap();
        let record =
            fa_notary::Record::decode(envelope.kind, reader.bytes(bound, "record").unwrap())
                .unwrap();
        // Vertex ids determine ordering, but are not fields of an accumulated
        // envelope. Preserve the proven ordinal order with ascending ids.
        records.push((
            VId(index as u128 + 1),
            record,
            CommitSeq(envelope.commit_seq),
        ));
    }
    let journal = fa_notary::Journal::from_records_with_evidence(
        Id128(signed.checkpoint.book_id),
        CommitSeq(signed.checkpoint.through_seq),
        Some(CommitSeq(0)),
        records,
    )
    .unwrap();
    assert_eq!(
        journal.statement(),
        produced.checkpoint.checkpoint.body.statement
    );
    assert_eq!(reader.u32("migrations").unwrap(), 0);
    assert_eq!(reader.u32("registries").unwrap(), 6);
    let mut registries = Vec::new();
    for _ in 0..6 {
        registries.push((
            reader.str(128, "registry name").unwrap().to_owned(),
            reader.bytes(1024 * 1024, "registry").unwrap().to_vec(),
        ));
    }
    let book_spec = reader.bytes(1024 * 1024, "BookSpec").unwrap();
    assert_eq!(reader.u32("rate count").unwrap(), 1);
    let oid = Oid(reader.fixed::<32>("Rate OID").unwrap());
    let payload = reader.bytes(4096, "Rate payload").unwrap().to_vec();
    reader.finish().unwrap();
    let mut rates = vec![(oid, payload)];
    let assemble = |rates: &[(Oid, Vec<u8>)]| {
        fa_notary::report::assemble_functional_with_registries(
            &journal,
            &produced.checkpoint,
            certificate_bytes,
            certificate.known_at,
            &std::collections::BTreeMap::new(),
            &registries,
            book_spec,
            rates,
        )
    };
    assert_eq!(
        assemble(&rates).unwrap().unwrap().bytes,
        produced.bundle.bytes,
        "the authenticated original closure reproduces the complete export"
    );
    let mut document = fa_journal::evidence::Document::decode(&rates[0].1).unwrap();
    let commitment = document.doc_commit();
    document.retrieved_by = VId(document.retrieved_by.0 ^ 2);
    assert_eq!(document.oid(), oid);
    assert_eq!(document.doc_commit(), commitment);
    rates[0].1 = document.canonical_bytes().unwrap();
    assert!(
        assemble(&rates).unwrap().is_err(),
        "producer must bind the wrapper receiver to its authenticated import receipt"
    );
    let offset = rates_offset(&produced.bundle.bytes);
    let mut forged = produced.bundle.bytes[..offset].to_vec();
    forged.extend_from_slice(&1u32.to_le_bytes());
    forged.extend_from_slice(&oid.0);
    forged.extend_from_slice(&(rates[0].1.len() as u32).to_le_bytes());
    forged.extend_from_slice(&rates[0].1);
    forged
}

#[test]
fn independent_verifier_rejects_missing_duplicate_and_substituted_rate_bodies() {
    let mut fixture = Fixture::new();
    fixture.post(b"portable-rate-attack", day(1, 5), 10_000, 11);
    let certificate = certify(&mut fixture, TrialBalanceSelection::AsOf(day(1, 31)));
    let state = checkpoint(&mut fixture.book);
    let produced = produce(&mut fixture, state, &certificate);
    verify(&fixture, &produced, &certificate);
    let offset = rates_offset(&produced.bundle.bytes);
    let original = &produced.bundle.bytes;
    assert_eq!(&original[offset..offset + 4], &1u32.to_le_bytes());

    let mut missing = original[..offset].to_vec();
    missing.extend_from_slice(&0u32.to_le_bytes());
    let mut duplicate = original[..offset].to_vec();
    duplicate.extend_from_slice(&2u32.to_le_bytes());
    duplicate.extend_from_slice(&original[offset + 4..]);
    duplicate.extend_from_slice(&original[offset + 4..]);
    let mut substitute = original.clone();
    substitute[offset + 4] ^= 1;
    let mut changed_body = original.clone();
    *changed_body.last_mut().unwrap() ^= 1;
    let changed_receiver = forged_rate_receiver(&fixture, &produced, &certificate);
    for attack in [
        missing,
        duplicate,
        substitute,
        changed_body,
        changed_receiver,
    ] {
        // Omit the detached receipt so rejection must come from the pinned
        // report's authenticated source closure, not a stale bundle signature.
        assert!(
            fa_verify::report::verify_report_expected(
                &attack,
                &[fixture.book.checkpoint_public_key()],
                None,
                None,
                Some(&certificate.digest),
            )
            .is_err()
        );
    }
    assert!(
        fa_verify::report::verify_report_expected(
            original,
            &[fixture.book.checkpoint_public_key()],
            None,
            None,
            None,
        )
        .is_err(),
        "a checkpoint alone cannot approve report parameters"
    );
}

#[test]
fn functional_export_keeps_exact_residual_and_refuses_a_pinned_producer() {
    let mut fixture = Fixture::new();
    let rate = fixture.rate(day(1, 5), 15, "Half-even residual source");
    let mut proposal = fixture.proposal(b"portable-residual", day(1, 5), 2);
    proposal.legs[0].amount.mantissa = 1;
    proposal.legs.insert(1, proposal.legs[0].clone());
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    let valued = fixture
        .book
        .value_fx_proposal(
            &cap(&["read", "post"]),
            proposal,
            FxLawId::SpotClose,
            &[rate],
        )
        .unwrap()
        .unwrap();
    assert!(valued.base_totals.as_ref().unwrap().residual.is_some());
    fixture.book.post(request(valued)).unwrap().unwrap();
    let certificate = certify(&mut fixture, TrialBalanceSelection::AsOf(day(1, 31)));
    let state = checkpoint(&mut fixture.book);
    let pin = fixture.book.head().unwrap();
    fixture.post(b"later-than-producer-pin", day(2, 5), 100, 12);
    let before = fixture.book.head().unwrap();
    // Bundle integrity reads reach HEAD, so a producer pinned below it is
    // refused even for a checkpoint inside its pin (fa-0x0, f68db34f6).
    // The selected historical certificate does not bound export's current
    // journal/checkpoint integrity reads. A pinned token cannot authorize them.
    let pinned = fixture
        .book
        .produce_report_bundle(
            PRINCIPAL,
            &producer().known_at_most(pin),
            Some(state),
            &certificate,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!((pinned.code, pinned.exit), ("FA-REF-011", 7));
    assert!(pinned.message.contains("`known_at`"), "{}", pinned.message);
    assert_eq!(fixture.book.head().unwrap(), before);
    let produced = produce(&mut fixture, state, &certificate);
    let verified = verify(&fixture, &produced, &certificate);
    assert_eq!(verified.output, certificate.output);
    let denied = fixture
        .book
        .produce_report_bundle(PRINCIPAL, &cap(&["read"]), Some(state), &certificate)
        .unwrap()
        .unwrap_err();
    assert!(denied.message.contains("produce"));
    assert_eq!(fixture.book.head().unwrap(), before);
}

#[path = "portable/transitions.rs"]
mod transitions;

#[path = "portable/statements.rs"]
mod statements;

#[test]
fn functional_export_refuses_unvalued_foreign_history_even_outside_selected_dates() {
    let mut fixture = Fixture::new();
    fixture.post(b"portable-valued-original", day(1, 5), 10_000, 11);
    let original = certify(&mut fixture, TrialBalanceSelection::AsOf(day(1, 31)));
    let unvalued = fixture.proposal(b"portable-unvalued-later-period", day(2, 5), 5_000);
    fixture.book.post(request(unvalued)).unwrap().unwrap();
    // A native January fold is still valid: the unvalued posting is effective
    // in February. The portable profile nevertheless checks every valuation
    // within its recorded prefix, including out-of-period entries.
    let current = certify(&mut fixture, TrialBalanceSelection::AsOf(day(1, 31)));
    let state = checkpoint(&mut fixture.book);
    let before = fixture.book.head().unwrap();
    let historical = produce(&mut fixture, state, &original);
    assert_eq!(
        verify(&fixture, &historical, &original).output,
        original.output
    );
    let refusal = fixture
        .book
        .produce_report_bundle(PRINCIPAL, &producer(), Some(state), &current)
        .unwrap()
        .unwrap_err();
    assert!(
        refusal.message.contains("unvalued foreign entry"),
        "{refusal:?}"
    );
    assert_eq!(fixture.book.head().unwrap(), before);
}

#[path = "portable/settlements.rs"]
mod settlements;

#[path = "portable/migration.rs"]
mod migration;
