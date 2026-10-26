//! Both sides of an aging/control comparison cross one authenticated prefix.
//! The independent verifier receives the original outer certificate and sources.

use super::*;

fn collect(
    fixture: &mut Fixture,
    date: DateDay,
    key: &[u8],
    amount: i128,
    applications: &[(fa_model::EntryRef, i128)],
) -> Posted {
    let mut legs = fixture.legs(fixture.usd, ("2000", "1000"), amount);
    legs[1].settles = applications
        .iter()
        .map(|(target, amount)| fa_model::Settlement {
            target: *target,
            ordinal: 0,
            amount: Amount::new(fixture.usd, *amount),
        })
        .collect();
    fixture.commit(fixture.proposal(date, key, EntryClass::ORIGINAL, legs))
}

fn reverse(fixture: &mut Fixture, target: fa_model::EntryRef) {
    let (source, _) = fixture.book.read_entry(target.vid).unwrap().unwrap();
    let mut legs = source.proposal.legs.clone();
    for leg in &mut legs {
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
        leg.settles.clear();
    }
    let mut proposal = fixture.proposal(
        day(2026, 2, 15),
        b"reconciliation-undo-receipt",
        EntryClass::REVERSAL,
        legs,
    );
    proposal.supersession = vec![fa_model::Supersession {
        target,
        kind: fa_model::SupersessionKind::Reverses,
        reason_code: 1,
    }];
    fixture.commit(proposal);
}

fn request(book: &Book, code: &str, cutoff: DateDay) -> fa::AgingReconciliationRequest {
    fa::AgingReconciliationRequest {
        account: account_vid(book.context().book_id, code),
        effective_through: cutoff,
        known_at: Some(book.head().unwrap()),
        buckets: fa::AgingBuckets::thirty_day(),
    }
}

fn certify(
    book: &Book,
    expected: &fa::AgingReconciliationRequest,
) -> fa::CertifiedAgingReconciliation {
    book.certify_effective_date_aging_reconciliation(
        PRINCIPAL,
        &Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap(),
        expected,
    )
    .unwrap()
    .unwrap()
}

fn produce(
    book: &mut Book,
    certificate: &fa::AgingReconciliationCertificate,
    expected: &fa::AgingReconciliationRequest,
) -> fa::ProducedBundle {
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap();
    let checkpoint = book.checkpoint(PRINCIPAL, &capability).unwrap().unwrap();
    let state = checkpoint.checkpoint.checkpoint.body.state_oid;
    let before = book.head().unwrap();
    let produced = book
        .produce_aging_reconciliation_bundle(
            PRINCIPAL,
            &capability,
            Some(state),
            certificate,
            expected,
        )
        .unwrap()
        .unwrap()
        .unwrap();
    let repeated = book
        .produce_aging_reconciliation_bundle(
            PRINCIPAL,
            &capability,
            Some(state),
            certificate,
            expected,
        )
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(produced.bundle.bytes, repeated.bundle.bytes);
    assert_eq!(produced.receipt, repeated.receipt);
    assert_eq!(book.head().unwrap(), before, "reconciliation export is a read");
    let mut reader = fa_model::Reader::new(&produced.bundle.bytes);
    assert_eq!(
        reader.bytes(64, "bundle format").unwrap(),
        b"fa:report-bundle:v1"
    );
    assert_eq!(reader.u16("bundle major").unwrap(), 2);
    assert_eq!(reader.u16("bundle minor").unwrap(), 0);
    assert_eq!(
        reader
            .bytes(fa_notary::report::MAX_REPORT_BUNDLE_BYTES, "certificate")
            .unwrap(),
        certificate.canonical_bytes().unwrap()
    );
    produced
}

fn verify(
    book: &Book,
    certified: &fa::CertifiedAgingReconciliation,
    produced: &fa::ProducedBundle,
) -> fa_verify::report::VerifiedReport {
    let certificate = &certified.certificate;
    let native = &certified.report;
    let key = book.checkpoint_public_key();
    let anchor = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&anchor.checkpoint),
        Some(&produced.receipt),
        Some(certificate.digest()),
    )
    .expect("both original sources independently reproduce their reconciliation");
    assert_eq!(verified.output, certificate.output());
    assert_eq!(verified.certificate_digest, *certificate.digest());
    assert_eq!(verified.known_at, native.known_at().0);
    assert_eq!(verified.effective_through, Some(native.effective_through().0));
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    assert!(verified.receipt.is_some());
    assert!(verified.rows.is_empty());
    assert!(verified.statement.is_none());
    assert!(verified.open_items.is_none());
    assert!(verified.aging.is_none());
    assert!(verified.time_selection.is_none());
    let reconciliation = verified
        .aging_reconciliation
        .as_ref()
        .expect("aging/control comparison");
    assert_eq!(reconciliation.book_id, native.aging().book_id.0);
    assert_eq!(reconciliation.known_at, native.known_at().0);
    assert_eq!(
        reconciliation.effective_through,
        native.effective_through().0
    );
    assert_eq!(reconciliation.account.account, native.account().vid.0);
    assert_eq!(reconciliation.account.code, native.account().code);
    assert_eq!(reconciliation.account.name, native.account().name);
    assert_eq!(
        reconciliation.account.account_type,
        native.account().account_type
    );
    assert_eq!(
        reconciliation.account.normal_balance,
        native.account().normal_balance
    );
    assert_eq!(reconciliation.account.is_leaf, native.account().is_leaf);
    assert_eq!(
        reconciliation.account.created_at,
        native.account().created_at.0
    );
    assert_eq!(
        reconciliation.aging_certificate_digest,
        *certificate.aging_source().digest()
    );
    assert_eq!(
        reconciliation.control_certificate_digest,
        certificate.control_source().digest
    );
    assert_eq!(
        reconciliation.aging.source_certificate_digest,
        certificate.aging_source().source().digest
    );
    assert_eq!(
        reconciliation.aging.account_filter,
        Some(native.account().vid.0)
    );
    assert_eq!(reconciliation.is_reconciled(), native.is_reconciled());
    assert_eq!(reconciliation.rows.len(), native.rows().len());
    for (actual, expected) in reconciliation.rows.iter().zip(native.rows()) {
        assert_eq!(
            (
                actual.unit_id,
                actual.posted_debits,
                actual.posted_credits,
                actual.pending_debits,
                actual.pending_credits,
                actual.open_debits,
                actual.open_credits,
                actual.open_item_count,
                actual.posted_net,
                actual.open_net,
                actual.difference,
            ),
            (
                expected.unit_id,
                expected.posted_debits,
                expected.posted_credits,
                expected.pending_debits,
                expected.pending_credits,
                expected.open_debits,
                expected.open_credits,
                expected.open_item_count,
                expected.posted_net,
                expected.open_net,
                expected.difference,
            ),
        );
    }
    assert_eq!(reconciliation.control_rows.len(), native.control_rows().len());
    for (actual, expected) in reconciliation.control_rows.iter().zip(native.control_rows()) {
        assert_eq!(actual.account, expected.account.0);
        assert_eq!(actual.code, expected.code);
        assert_eq!(actual.name, expected.name);
        assert_eq!(actual.account_type, expected.account_type.0);
        assert_eq!(
            (
                actual.unit,
                actual.debits,
                actual.credits,
                actual.debits_pending,
                actual.credits_pending,
            ),
            (
                expected.unit_id,
                expected.debits,
                expected.credits,
                expected.debits_pending,
                expected.credits_pending,
            ),
        );
    }
    verified
}

#[test]
fn reconciliation_bundle_recomputes_turnover_residuals_pending_and_native_units() {
    let mut fixture = Fixture::new(0x88);
    let (usd, jpy) = (fixture.usd, fixture.jpy);
    let first = fixture
        .transfer(day(2026, 1, 1), b"reconcile-first", usd, ("1000", "4000"), 10_000)
        .entry_ref();
    let second = fixture
        .transfer(day(2026, 1, 2), b"reconcile-second", usd, ("1000", "4000"), 6_000)
        .entry_ref();
    let receipt = collect(
        &mut fixture,
        day(2026, 2, 5),
        b"reconcile-partial",
        4_500,
        &[(first, 4_000)],
    );
    collect(
        &mut fixture,
        day(2026, 2, 9),
        b"reconcile-full",
        6_000,
        &[(second, 6_000)],
    );
    // Recorded in this prefix, but outside both the aging and control cutoff.
    collect(
        &mut fixture,
        day(2026, 3, 15),
        b"reconcile-future-payment",
        1_000,
        &[(first, 1_000)],
    );
    let mut pending = fixture.proposal(
        day(2026, 2, 10),
        b"reconcile-pending",
        EntryClass::PENDING,
        fixture.legs(usd, ("1000", "2000"), 700),
    );
    pending.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    fixture.commit(pending);
    fixture.transfer(day(2026, 1, 3), b"reconcile-jpy", jpy, ("1000", "4000"), 1_200);
    // The complete control source also includes accounts outside the comparison.
    fixture.transfer(day(2026, 2, 1), b"reconcile-other", usd, ("6000", "2000"), 123);
    let expected = request(&fixture.book, "1000", day(2026, 2, 28));
    let certified = certify(&fixture.book, &expected);
    let produced = produce(&mut fixture.book, &certified.certificate, &expected);
    let verified = verify(&fixture.book, &certified, &produced);
    let report = verified.aging_reconciliation.unwrap();
    assert!(report.is_reconciled());
    assert_eq!(report.rows.len(), 2);
    let usd_row = report.rows.iter().find(|row| row.unit_id == usd.0).unwrap();
    assert_eq!((usd_row.posted_debits, usd_row.posted_credits), (16_000, 10_500));
    assert_eq!((usd_row.pending_debits, usd_row.pending_credits), (700, 0));
    assert_eq!((usd_row.open_debits, usd_row.open_credits), (6_000, 500));
    assert_eq!((usd_row.posted_net, usd_row.open_net, usd_row.difference), (5_500, 5_500, 0));
    assert_eq!(usd_row.open_item_count, 2);
    let jpy_row = report.rows.iter().find(|row| row.unit_id == jpy.0).unwrap();
    assert_eq!((jpy_row.posted_net, jpy_row.open_net, jpy_row.difference), (1_200, 1_200, 0));
    assert!(!report.aging.items.iter().any(|row| row.item.entry == second.vid.0));
    let partial = report.aging.items.iter().find(|row| row.item.entry == first.vid.0).unwrap();
    assert_eq!(partial.item.applications.len(), 1);
    assert_eq!(partial.item.applications[0].entry, receipt.entry_ref().vid.0);
    assert_eq!(partial.item.applications[0].amount, 4_000);
    assert!(partial.item.applications[0].live);
}

#[test]
fn reconciliation_bundle_replays_original_sources_after_backdating_reversal_and_reopen() {
    let seed = 0x89;
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "fa-aging-control-bundle-{}-{suffix}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let mut fixture = Fixture::at(seed, Some(&directory));
    let usd = fixture.usd;
    let first = fixture
        .transfer(day(2026, 1, 1), b"reconcile-history", usd, ("1000", "4000"), 10_000)
        .entry_ref();
    let receipt = collect(
        &mut fixture,
        day(2026, 2, 5),
        b"reconcile-history-payment",
        4_500,
        &[(first, 4_000)],
    );
    let expected = request(&fixture.book, "1000", day(2026, 2, 10));
    let certified = certify(&fixture.book, &expected);
    let canonical = certified.certificate.canonical_bytes().unwrap();
    reverse(&mut fixture, receipt.entry_ref());
    let later = fixture.transfer(
        day(2026, 1, 2),
        b"reconcile-late-backdated",
        usd,
        ("1000", "4000"),
        900,
    );
    let produced = produce(&mut fixture.book, &certified.certificate, &expected);
    let verified = verify(&fixture.book, &certified, &produced);
    let report = verified.aging_reconciliation.unwrap();
    assert!(!report.aging.items.iter().any(|row| row.item.entry == later.entry_ref().vid.0));
    assert_eq!(report.rows[0].posted_net, 5_500);
    assert_eq!(report.rows[0].open_net, 5_500);
    let invoice = report
        .aging
        .items
        .iter()
        .find(|row| row.item.entry == first.vid.0)
        .unwrap();
    assert!(invoice.item.applications[0].live);
    let state = produced.checkpoint.checkpoint.body.state_oid;
    let head = fixture.book.head().unwrap();
    drop(fixture);
    let mut book = Book::open_dir(
        &directory,
        BookKeys::for_development(seed),
        Entropy::deterministic(u64::from(seed)),
    )
    .unwrap();
    let decoded = fa::AgingReconciliationCertificate::decode(&canonical).unwrap();
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap();
    let reopened = book
        .produce_aging_reconciliation_bundle(
            PRINCIPAL,
            &capability,
            Some(state),
            &decoded,
            &expected,
        )
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(reopened.bundle.bytes, produced.bundle.bytes);
    assert_eq!(reopened.receipt, produced.receipt);
    verify(&book, &certified, &reopened);
    assert_eq!(book.head().unwrap(), head, "reopened export hydrates history without writing");
}

#[test]
fn reconciliation_bundle_keeps_empty_account_metadata_and_pending_only_units() {
    let mut fixture = Fixture::new(0x8a);
    let jpy = fixture.jpy;
    let expected = request(&fixture.book, "6100", day(2026, 2, 28));
    let empty = certify(&fixture.book, &expected);
    let produced = produce(&mut fixture.book, &empty.certificate, &expected);
    let verified = verify(&fixture.book, &empty, &produced);
    let report = verified.aging_reconciliation.unwrap();
    assert_eq!(report.account.code, "6100");
    assert_eq!(report.account.name, "Unused expense");
    assert!(report.rows.is_empty());
    assert!(report.control_rows.is_empty());
    assert!(report.aging.items.is_empty());
    assert!(report.is_reconciled());

    // The chart predates the first declared period. A civil-date stock
    // comparison is valid there without inventing a calendar period.
    let before_periods = fa::AgingReconciliationRequest {
        known_at: Some(empty.report.account().created_at),
        ..expected.clone()
    };
    let historical_empty = certify(&fixture.book, &before_periods);
    let produced = produce(
        &mut fixture.book,
        &historical_empty.certificate,
        &before_periods,
    );
    let verified = verify(&fixture.book, &historical_empty, &produced);
    assert!(verified.periods.is_empty());
    assert!(verified.aging_reconciliation.unwrap().rows.is_empty());

    let mut pending = fixture.proposal(
        day(2026, 2, 10),
        b"reconcile-pending-only",
        EntryClass::PENDING,
        fixture.legs(jpy, ("6100", "2000"), 700),
    );
    pending.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    fixture.commit(pending);
    let expected = request(&fixture.book, "6100", day(2026, 2, 28));
    let held = certify(&fixture.book, &expected);
    let produced = produce(&mut fixture.book, &held.certificate, &expected);
    let verified = verify(&fixture.book, &held, &produced);
    let report = verified.aging_reconciliation.unwrap();
    assert_eq!(report.rows.len(), 1);
    assert_eq!(report.rows[0].unit_id, jpy.0);
    assert_eq!(report.rows[0].pending_debits, 700);
    assert_eq!(report.rows[0].pending_credits, 0);
    assert_eq!(report.rows[0].posted_debits, 0);
    assert_eq!(report.rows[0].posted_credits, 0);
    assert_eq!(report.rows[0].open_item_count, 0);
    assert_eq!(report.rows[0].difference, 0);
    assert!(report.aging.items.is_empty());
    assert!(report.is_reconciled());
}

fn repaired_false_comparison(
    certificate: &fa::AgingReconciliationCertificate,
) -> fa::AgingReconciliationCertificate {
    let mut output = certificate.output().to_vec();
    let reconciled = output.last_mut().unwrap();
    assert_eq!(*reconciled, 1);
    *reconciled = 0;
    let mut writer = fa_model::Writer::new();
    writer
        .bytes(b"fa:aging-reconciliation-certificate:v1")
        .u128(certificate.producer().0)
        .fixed(certificate.capability_commitment())
        .bytes(&certificate.aging_source().canonical_bytes().unwrap())
        .bytes(&certificate.control_source().canonical_bytes().unwrap())
        .bytes(&output);
    let mut bytes = writer.finish().unwrap();
    let digest = fa_model::domain_digest(b"fa:aging-reconciliation-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&digest);
    fa::AgingReconciliationCertificate::decode(&bytes).unwrap()
}

#[test]
fn reconciliation_export_requires_current_authority_exact_question_and_replayed_output() {
    let mut fixture = Fixture::new(0x8b);
    let usd = fixture.usd;
    fixture.transfer(day(2026, 1, 1), b"reconcile-admission", usd, ("1000", "4000"), 100);
    let expected = request(&fixture.book, "1000", day(2026, 1, 31));
    let certified = certify(&fixture.book, &expected);
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    let before = fixture.book.head().unwrap();
    assert!(
        fixture.book.produce_aging_reconciliation_bundle(
            PRINCIPAL, &capability, None, &certified.certificate, &expected,
        ).unwrap().unwrap().is_none(),
        "a valid report without a recorded checkpoint has no portable bundle"
    );
    assert_eq!(fixture.book.head().unwrap(), before);
    let produced = produce(&mut fixture.book, &certified.certificate, &expected);
    verify(&fixture.book, &certified, &produced);
    let before = fixture.book.head().unwrap();
    for denied in [
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["produce"]).unwrap(),
        capability.clone().for_accounts(&["1000"]).unwrap(),
        capability.clone().for_periods(&[JANUARY]).unwrap(),
        capability.clone().for_books(&[Id128([0xff; 16])]).unwrap(),
        capability.clone().expiring_at(before),
    ] {
        assert!(
            fixture.book.produce_aging_reconciliation_bundle(
                PRINCIPAL, &denied, None, &certified.certificate, &expected,
            ).unwrap().is_err()
        );
        assert_eq!(fixture.book.head().unwrap(), before);
    }
    assert!(
        fixture.book.produce_aging_reconciliation_bundle(
            VId(99), &capability, None, &certified.certificate, &expected,
        ).unwrap().is_err()
    );
    for changed in [
        fa::AgingReconciliationRequest {
            account: account_vid(fixture.book.context().book_id, "2000"),
            ..expected.clone()
        },
        fa::AgingReconciliationRequest {
            effective_through: day(2026, 1, 30),
            ..expected.clone()
        },
        fa::AgingReconciliationRequest {
            known_at: Some(before),
            ..expected.clone()
        },
        fa::AgingReconciliationRequest {
            known_at: None,
            ..expected.clone()
        },
        fa::AgingReconciliationRequest {
            buckets: fa::AgingBuckets::new(vec![0, 30]).unwrap(),
            ..expected.clone()
        },
    ] {
        assert!(
            fixture.book.produce_aging_reconciliation_bundle(
                PRINCIPAL, &capability, None, &certified.certificate, &changed,
            ).unwrap().is_err()
        );
        assert_eq!(fixture.book.head().unwrap(), before);
    }
    let forged = repaired_false_comparison(&certified.certificate);
    assert!(
        fixture.book.produce_aging_reconciliation_bundle(
            PRINCIPAL, &capability, None, &forged, &expected,
        ).unwrap().is_err(),
        "a repaired outer digest does not establish the comparison"
    );
    for wrong_pin in [
        certified.certificate.aging_source().digest(),
        &certified.certificate.control_source().digest,
        &certified.certificate.aging_source().source().digest,
    ] {
        assert!(
            fa_verify::report::verify_report_expected(
                &produced.bundle.bytes,
                &[fixture.book.checkpoint_public_key()],
                None,
                Some(&produced.receipt),
                Some(wrong_pin),
            ).is_err(),
            "neither native source identifies the outer comparison"
        );
    }
    assert_eq!(fixture.book.head().unwrap(), before);
}
