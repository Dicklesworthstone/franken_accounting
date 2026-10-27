//! Effective-date aging crosses the real producer and the independent verifier.
//! Later-effective applications must be excluded before settlement netting.

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

fn reverse(fixture: &mut Fixture, target: fa_model::EntryRef, date: DateDay, key: &[u8]) -> Posted {
    let (source, _) = fixture.book.read_entry(target.vid).unwrap().unwrap();
    let mut legs = source.proposal.legs.clone();
    for leg in &mut legs {
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
        leg.settles.clear();
    }
    let mut proposal = fixture.proposal(date, key, EntryClass::REVERSAL, legs);
    proposal.supersession = vec![fa_model::Supersession {
        target,
        kind: fa_model::SupersessionKind::Reverses,
        reason_code: 1,
    }];
    fixture.commit(proposal)
}

fn produce(book: &mut Book, certificate: &fa::AgingCertificate) -> fa::ProducedBundle {
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap();
    let checkpoint = book.checkpoint(PRINCIPAL, &capability).unwrap().unwrap();
    let state = checkpoint.checkpoint.checkpoint.body.state_oid;
    let before = book.head().unwrap();
    let produced = book
        .produce_aging_bundle(PRINCIPAL, &capability, Some(state), certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    let repeated = book
        .produce_aging_bundle(PRINCIPAL, &capability, Some(state), certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(produced.bundle.bytes, repeated.bundle.bytes);
    assert_eq!(produced.receipt, repeated.receipt);
    assert_eq!(book.head().unwrap(), before, "aging export is a read");
    produced
}

fn verify(
    book: &Book,
    certificate: &fa::AgingCertificate,
    produced: &fa::ProducedBundle,
) -> fa_verify::report::VerifiedReport {
    let key = book.checkpoint_public_key();
    let anchor = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&anchor.checkpoint),
        Some(&produced.receipt),
        Some(certificate.digest()),
    )
    .expect("the complete signed prefix independently reproduces aging");
    assert_eq!(verified.output, certificate.output());
    assert_eq!(verified.certificate_digest, *certificate.digest());
    assert_eq!(verified.known_at, certificate.source().known_at.0);
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    assert!(verified.receipt.is_some());
    assert!(verified.rows.is_empty());
    assert!(verified.statement.is_none());
    assert!(verified.open_items.is_none());
    assert!(verified.time_selection.is_none());
    let aging = verified.aging.as_ref().expect("aging result");
    assert_eq!(aging.source_certificate_digest, certificate.source().digest);
    assert_eq!(
        aging.effective_through,
        certificate.request().unwrap().effective_through.0
    );
    assert_eq!(
        verified.effective_through,
        Some(certificate.request().unwrap().effective_through.0)
    );
    verified
}

#[test]
fn native_aging_bundles_refold_effective_settlements_and_reversals_at_historical_prefixes() {
    let mut fixture = Fixture::new(0x85);
    let usd = fixture.usd;
    let cash = account_vid(fixture.book.context().book_id, "1000");
    let first = fixture
        .transfer(
            day(2026, 1, 1),
            b"aging-first",
            usd,
            ("1000", "4000"),
            10_000,
        )
        .entry_ref();
    let second = fixture
        .transfer(
            day(2026, 1, 2),
            b"aging-second",
            usd,
            ("1000", "4000"),
            6_000,
        )
        .entry_ref();
    let before_payments = fixture.book.head().unwrap();
    let receipt = collect(
        &mut fixture,
        day(2026, 2, 5),
        b"aging-first-payment",
        4_500,
        &[(first, 4_000)],
    );
    let full = collect(
        &mut fixture,
        day(2026, 2, 9),
        b"aging-full-payment",
        6_000,
        &[(second, 6_000)],
    );
    let reversed = reverse(
        &mut fixture,
        receipt.entry_ref(),
        day(2026, 2, 15),
        b"aging-undo-first-payment",
    );
    let later = fixture.transfer(
        day(2026, 1, 2),
        b"aging-later-backdated",
        usd,
        ("1000", "4000"),
        900,
    );
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    for (at, cutoff, expected_open, applications, live, second_visible, remainder) in [
        (
            before_payments,
            day(2026, 2, 20),
            10_000,
            0,
            false,
            true,
            false,
        ),
        (
            full.recorded_at(),
            day(2026, 2, 1),
            10_000,
            0,
            false,
            true,
            false,
        ),
        (
            full.recorded_at(),
            day(2026, 2, 10),
            6_000,
            1,
            true,
            false,
            true,
        ),
        (
            reversed.recorded_at(),
            day(2026, 2, 10),
            6_000,
            1,
            true,
            false,
            true,
        ),
        (
            reversed.recorded_at(),
            day(2026, 2, 20),
            10_000,
            1,
            false,
            false,
            false,
        ),
    ] {
        let certified = fixture
            .book
            .certify_effective_date_aging(
                PRINCIPAL,
                &capability,
                &fa::AgingRequest {
                    account: Some(cash),
                    effective_through: cutoff,
                    known_at: Some(at),
                    buckets: fa::AgingBuckets::thirty_day(),
                },
            )
            .unwrap()
            .unwrap();
        let produced = produce(&mut fixture.book, &certified.certificate);
        let verified = verify(&fixture.book, &certified.certificate, &produced);
        let aging = verified.aging.unwrap();
        assert_eq!(aging.account_filter, Some(cash.0));
        assert!(aging.items.iter().all(|row| row.item.account == cash.0));
        assert!(
            !aging
                .items
                .iter()
                .any(|row| row.item.entry == later.entry_ref().vid.0)
        );
        let item = &aging
            .items
            .iter()
            .find(|row| row.item.entry == first.vid.0)
            .unwrap()
            .item;
        assert_eq!(item.open, expected_open);
        assert_eq!(item.applied, 10_000 - expected_open);
        assert_eq!(item.applications.len(), applications);
        if applications != 0 {
            assert_eq!(item.applications[0].entry, receipt.entry_ref().vid.0);
            assert_eq!(item.applications[0].live, live);
        }
        assert_eq!(
            aging.items.iter().any(|row| row.item.entry == second.vid.0),
            second_visible,
            "fully applied items are omitted only inside the selected cutoff"
        );
        let unapplied = aging
            .items
            .iter()
            .find(|row| row.item.entry == receipt.entry_ref().vid.0);
        assert_eq!(unapplied.is_some(), remainder);
        if let Some(unapplied) = unapplied {
            assert_eq!(unapplied.item.open, 500);
            assert_eq!(unapplied.item.applied_out, 4_000);
        }
        // A pin for the nested all-time source cannot authenticate a different
        // question: the delivered certificate also binds cutoff and age bands.
        assert!(
            fa_verify::report::verify_report_expected(
                &produced.bundle.bytes,
                &[fixture.book.checkpoint_public_key()],
                None,
                None,
                Some(&certified.certificate.source().digest),
            )
            .is_err()
        );
    }
}

#[test]
fn native_aging_bundles_preserve_bucket_edges_gross_sides_units_and_empty_filters() {
    let mut fixture = Fixture::new(0x86);
    let usd = fixture.usd;
    let jpy = fixture.jpy;
    let cash = account_vid(fixture.book.context().book_id, "1000");
    let unused = account_vid(fixture.book.context().book_id, "6100");
    let over_edge = fixture.transfer(day(2026, 1, 1), b"aging-age-31", usd, ("1000", "4000"), 100);
    let edge = fixture.transfer(day(2026, 1, 2), b"aging-age-30", usd, ("1000", "4000"), 200);
    let today = fixture.transfer(day(2026, 2, 1), b"aging-age-0", usd, ("1000", "4000"), 300);
    fixture.transfer(
        day(2026, 1, 31),
        b"aging-credit",
        usd,
        ("2000", "1000"),
        200,
    );
    fixture.transfer(
        day(2026, 1, 2),
        b"aging-other-unit",
        jpy,
        ("1000", "4000"),
        700,
    );
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    let at = fixture.book.head().unwrap();
    for account in [Some(cash), Some(unused), None] {
        let certified = fixture
            .book
            .certify_effective_date_aging(
                PRINCIPAL,
                &capability,
                &fa::AgingRequest {
                    account,
                    effective_through: day(2026, 2, 1),
                    known_at: Some(at),
                    buckets: fa::AgingBuckets::new(vec![0, 30]).unwrap(),
                },
            )
            .unwrap()
            .unwrap();
        let produced = produce(&mut fixture.book, &certified.certificate);
        let verified = verify(&fixture.book, &certified.certificate, &produced);
        let aging = verified.aging.unwrap();
        assert_eq!(aging.account_filter, account.map(|value| value.0));
        assert_eq!(aging.bands.len(), 3);
        assert_eq!(aging.bands[0].upper_inclusive, Some(0));
        assert_eq!(aging.bands[1].lower_inclusive, 1);
        assert_eq!(aging.bands[1].upper_inclusive, Some(30));
        assert_eq!(aging.bands[2].lower_inclusive, 31);
        assert_eq!(aging.bands[2].upper_inclusive, None);
        if account == Some(unused) {
            assert!(aging.items.is_empty());
            assert!(aging.cells.is_empty());
            assert!(aging.totals.is_empty());
            continue;
        }
        for (entry, age, bucket) in [
            (today.entry_ref().vid, 0, 0),
            (edge.entry_ref().vid, 30, 1),
            (over_edge.entry_ref().vid, 31, 2),
        ] {
            let item = aging
                .items
                .iter()
                .find(|row| row.item.entry == entry.0 && row.item.account == cash.0)
                .unwrap();
            assert_eq!(item.age_days, age);
            assert_eq!(item.bucket, bucket);
        }
        let usd_total = aging
            .totals
            .iter()
            .find(|row| row.account == cash.0 && row.unit_id == usd.0)
            .unwrap();
        assert_eq!(usd_total.amounts.debits, 600);
        assert_eq!(usd_total.amounts.credits, 200);
        assert_eq!(usd_total.amounts.item_count, 4);
        let jpy_total = aging
            .totals
            .iter()
            .find(|row| row.account == cash.0 && row.unit_id == jpy.0)
            .unwrap();
        assert_eq!(jpy_total.amounts.debits, 700);
        assert_eq!(jpy_total.amounts.credits, 0);
        assert_eq!(jpy_total.amounts.item_count, 1);
    }
}

#[test]
fn aging_bundle_production_checks_current_whole_book_authority_before_exporting_history() {
    let mut fixture = Fixture::new(0x87);
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    let certificate = fixture
        .book
        .certify_effective_date_aging(
            PRINCIPAL,
            &capability,
            &fa::AgingRequest {
                account: Some(account_vid(fixture.book.context().book_id, "1000")),
                effective_through: day(2026, 1, 31),
                known_at: None,
                buckets: fa::AgingBuckets::thirty_day(),
            },
        )
        .unwrap()
        .unwrap()
        .certificate;
    let produced = produce(&mut fixture.book, &certificate);
    verify(&fixture.book, &certificate, &produced);
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
            fixture
                .book
                .produce_aging_bundle(PRINCIPAL, &denied, None, &certificate)
                .unwrap()
                .is_err()
        );
        assert_eq!(fixture.book.head().unwrap(), before);
    }
    assert!(
        fixture
            .book
            .produce_aging_bundle(VId(99), &capability, None, &certificate)
            .unwrap()
            .is_err()
    );
    assert_eq!(fixture.book.head().unwrap(), before);
}

fn obligation(
    fixture: &mut Fixture,
    key: &[u8],
    amount: i128,
    terms: Option<(fa_model::obligation::ObligationStatus, Vec<(DateDay, i128)>)>,
) -> Posted {
    use fa_model::obligation::{InlineObligationTerms, ObligationInstallment};
    let mut proposal = fixture.proposal(
        day(2026, 1, 1),
        key,
        EntryClass::ORIGINAL,
        fixture.legs(fixture.usd, ("6000", "2000"), amount),
    );
    if let Some((status, installments)) = terms {
        proposal.extensions.push(
            InlineObligationTerms::to_extension(&[InlineObligationTerms {
                ordinal: 1,
                status,
                installments: installments
                    .into_iter()
                    .map(|(due_date, amount)| ObligationInstallment { due_date, amount })
                    .collect(),
            }])
            .unwrap(),
        );
    }
    fixture.commit(proposal)
}

fn due_date_certificate(fixture: &Fixture, cutoff: DateDay) -> fa::CertifiedDueDateAging {
    fixture
        .book
        .certify_due_date_aging(
            PRINCIPAL,
            &Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap(),
            &fa::AgingRequest {
                account: Some(account_vid(fixture.book.context().book_id, "2000")),
                effective_through: cutoff,
                known_at: None,
                buckets: fa::AgingBuckets::thirty_day(),
            },
        )
        .unwrap()
        .unwrap()
}

fn produce_due_date(
    book: &mut Book,
    certificate: &fa::DueDateAgingCertificate,
) -> fa::ProducedBundle {
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce", "witness"]).unwrap();
    let checkpoint = book.checkpoint(PRINCIPAL, &capability).unwrap().unwrap();
    let state = checkpoint.checkpoint.checkpoint.body.state_oid;
    let before = book.head().unwrap();
    let produced = book
        .produce_due_date_aging_bundle(PRINCIPAL, &capability, Some(state), certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    let repeated = book
        .produce_due_date_aging_bundle(PRINCIPAL, &capability, Some(state), certificate)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(produced.bundle.bytes, repeated.bundle.bytes);
    assert_eq!(produced.receipt, repeated.receipt);
    assert_eq!(book.head().unwrap(), before, "due-date export is a read");
    produced
}

fn verify_due_date(
    book: &Book,
    certificate: &fa::DueDateAgingCertificate,
    produced: &fa::ProducedBundle,
) -> fa_verify::report::VerifiedReport {
    let key = book.checkpoint_public_key();
    let checkpoint = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&checkpoint.checkpoint),
        Some(&produced.receipt),
        Some(certificate.digest()),
    )
    .expect("the independent verifier derives maturity from the signed journal prefix");
    assert_eq!(verified.output, certificate.output());
    assert_eq!(verified.certificate_digest, *certificate.digest());
    assert_eq!(verified.known_at, certificate.source().known_at.0);
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    assert!(verified.aging.is_none());
    assert!(verified.open_items.is_none());
    assert!(verified.receipt.is_some());
    let aging = verified.due_date_aging.as_ref().unwrap();
    assert_eq!(aging.source_certificate_digest, certificate.source().digest);
    assert_eq!(
        aging.effective_through,
        certificate.request().unwrap().effective_through.0,
    );
    verified
}

#[test]
fn due_date_aging_bundles_recompute_installments_partial_settlements_and_unscheduled_terms() {
    use fa_model::obligation::ObligationStatus;
    use fa_verify::report::VerifiedUnscheduled;
    let mut fixture = Fixture::new(0x88);
    let invoice = obligation(
        &mut fixture,
        b"due-installments",
        1_000,
        Some((
            ObligationStatus::Contractual,
            vec![(day(2026, 1, 31), 600), (day(2026, 2, 28), 400)],
        )),
    );
    let plain = obligation(&mut fixture, b"due-no-terms", 50, None);
    let missing = obligation(
        &mut fixture,
        b"due-missing",
        70,
        Some((ObligationStatus::MissingMaturity, Vec::new())),
    );
    let disputed = obligation(
        &mut fixture,
        b"due-disputed",
        90,
        Some((
            ObligationStatus::Disputed { reason_code: 19 },
            vec![(day(2026, 1, 15), 90)],
        )),
    );
    let mut legs = fixture.legs(fixture.usd, ("2000", "1000"), 700);
    legs[0].settles.push(fa_model::Settlement {
        target: invoice.entry_ref(),
        ordinal: 1,
        amount: Amount::new(fixture.usd, 700),
    });
    fixture.commit(fixture.proposal(
        day(2026, 2, 15),
        b"due-partial-payment",
        EntryClass::ORIGINAL,
        legs,
    ));
    let before_effective_payment = due_date_certificate(&fixture, day(2026, 2, 1));
    let after_payment = due_date_certificate(&fixture, day(2026, 3, 1));
    let original_source = after_payment
        .certificate
        .source()
        .canonical_bytes()
        .unwrap();
    let later = obligation(
        &mut fixture,
        b"due-later-backdated-terms",
        999,
        Some((ObligationStatus::Contractual, vec![(day(2026, 1, 2), 999)])),
    );
    for (certified, expected_open, expected_parts) in [
        (&before_effective_payment, 1_000, 2),
        (&after_payment, 300, 1),
    ] {
        let produced = produce_due_date(&mut fixture.book, &certified.certificate);
        let verified = verify_due_date(&fixture.book, &certified.certificate, &produced);
        let aging = verified.due_date_aging.unwrap();
        assert_eq!(aging.items.len(), expected_parts);
        assert!(
            aging
                .items
                .iter()
                .all(|part| part.item.entry == invoice.entry_ref().vid.0)
        );
        assert!(
            aging
                .items
                .iter()
                .all(|part| part.item.entry != later.entry_ref().vid.0)
        );
        assert_eq!(aging.totals[0].amounts.credits, expected_open);
        assert_eq!(aging.totals[0].amounts.debits, 0);
        assert_eq!(aging.unscheduled.len(), 3);
        assert_eq!(aging.unscheduled_totals[0].amounts.credits, 210);
        for (entry, reason) in [
            (plain.entry_ref().vid.0, VerifiedUnscheduled::NoTerms),
            (
                missing.entry_ref().vid.0,
                VerifiedUnscheduled::MissingMaturity,
            ),
            (
                disputed.entry_ref().vid.0,
                VerifiedUnscheduled::Disputed { reason_code: 19 },
            ),
        ] {
            assert_eq!(
                aging
                    .unscheduled
                    .iter()
                    .find(|row| row.item.entry == entry)
                    .unwrap()
                    .reason,
                reason
            );
        }
        if expected_parts == 1 {
            let part = &aging.items[0];
            assert_eq!(
                (part.open, part.item.applied, part.days_past_due),
                (300, 700, 1)
            );
            assert_eq!(part.due_date, day(2026, 2, 28).0);
        } else {
            let part = aging
                .items
                .iter()
                .find(|part| part.due_date == day(2026, 1, 31).0)
                .unwrap();
            assert_eq!(
                (part.open, part.item.applied, part.days_past_due),
                (600, 0, 1)
            );
        }
        assert!(
            fa_verify::report::verify_report_expected(
                &produced.bundle.bytes,
                &[fixture.book.checkpoint_public_key()],
                None,
                None,
                Some(&certified.certificate.source().digest),
            )
            .is_err(),
            "a pin for the all-time source cannot authorize a due-date report"
        );
    }
    let from_source = fixture
        .book
        .certify_due_date_aging_from_source(
            PRINCIPAL,
            &Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap(),
            after_payment.certificate.source(),
            day(2026, 3, 1),
            &fa::AgingBuckets::thirty_day(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(from_source.certificate, after_payment.certificate);
    assert_eq!(
        from_source.certificate.source().canonical_bytes().unwrap(),
        original_source
    );
}

fn reseal_due_date_output(
    certificate: &fa::DueDateAgingCertificate,
    output: &[u8],
) -> fa::DueDateAgingCertificate {
    let request = certificate.request().unwrap();
    let mut writer = fa_model::Writer::new();
    writer
        .bytes(fa::DUE_DATE_AGING_CERTIFICATE_FORMAT)
        .u128(certificate.producer().0)
        .fixed(certificate.capability_commitment())
        .bytes(&certificate.source().canonical_bytes().unwrap())
        .i32(request.effective_through.0)
        .list(request.buckets.upper_bounds(), |writer, bound| {
            writer.u32(*bound);
        })
        .bytes(output);
    let mut bytes = writer.finish().unwrap();
    let digest = fa_model::domain_digest(b"fa:due-date-aging-certificate-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&digest);
    fa::DueDateAgingCertificate::decode(&bytes).unwrap()
}

fn replace_due_date_outer(bundle: &[u8], outer: &[u8]) -> Vec<u8> {
    let at = 4 + fa_notary::report::REPORT_BUNDLE_FORMAT.len() + 4;
    let old_len = u32::from_le_bytes(bundle[at..at + 4].try_into().unwrap()) as usize;
    let mut bytes = bundle[..at].to_vec();
    bytes.extend_from_slice(&u32::try_from(outer.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(outer);
    bytes.extend_from_slice(&bundle[at + 4 + old_len..]);
    bytes
}

#[test]
fn due_date_aging_bundles_reject_resealed_reported_due_dates() {
    use fa_model::obligation::ObligationStatus;
    let mut fixture = Fixture::new(0x89);
    obligation(
        &mut fixture,
        b"due-forgery",
        1_000,
        Some((
            ObligationStatus::Contractual,
            vec![(day(2026, 1, 31), 1_000)],
        )),
    );
    let certified = due_date_certificate(&fixture, day(2026, 2, 1));
    let produced = produce_due_date(&mut fixture.book, &certified.certificate);
    verify_due_date(&fixture.book, &certified.certificate, &produced);
    // Change the reported maturity, preserving the native source and fixing
    // the public outer checksum. The verifier must derive the real date.
    let mut output = certified.certificate.output().to_vec();
    let mut reader = fa_model::Reader::new(&output);
    assert_eq!(
        reader.bytes(64, "format").unwrap(),
        fa::DUE_DATE_AGING_OUTPUT_FORMAT
    );
    reader.fixed::<16>("book").unwrap();
    reader.u64("known-at").unwrap();
    reader.i32("cutoff").unwrap();
    reader.opt("account", |r| r.u128("account")).unwrap();
    for _ in 0..reader.count(129, "bands").unwrap() {
        reader.u64("lower").unwrap();
        reader.opt("upper", |r| r.u64("upper")).unwrap();
    }
    assert_eq!(reader.count(1, "scheduled items").unwrap(), 1);
    reader.fixed::<115>("open-item fields").unwrap();
    for _ in 0..reader.count(10, "applications").unwrap() {
        reader.fixed::<43>("application").unwrap();
    }
    let offset = reader.offset();
    output[offset..offset + 4].copy_from_slice(&day(2026, 1, 30).0.to_le_bytes());
    let fake = reseal_due_date_output(&certified.certificate, &output);
    let capability = Capability::embedded(PRINCIPAL, &["read", "produce"]).unwrap();
    assert!(
        fixture
            .book
            .produce_due_date_aging_bundle(PRINCIPAL, &capability, None, &fake)
            .unwrap()
            .is_err()
    );
    let bundle = replace_due_date_outer(&produced.bundle.bytes, &fake.canonical_bytes().unwrap());
    let error = fa_verify::report::verify_report_expected(
        &bundle,
        &[fixture.book.checkpoint_public_key()],
        None,
        None,
        Some(fake.digest()),
    )
    .unwrap_err();
    assert_eq!(error.predicate, "report_recomputation");
}

/// Replace one admitted entry with a well-formed, resealed alternate record.
/// The original checkpoint remains the trust anchor, so repaired public hashes
/// cannot remove or change a term that its authenticated prefix committed.
fn alter_maturity_record(bundle: &[u8], remove: bool) -> Vec<u8> {
    use fa_model::obligation::InlineObligationTerms;
    let bound = fa_notary::report::MAX_REPORT_BUNDLE_BYTES;
    let mut reader = fa_model::Reader::new(bundle);
    assert_eq!(
        reader.bytes(64, "format").unwrap(),
        fa_notary::report::REPORT_BUNDLE_FORMAT
    );
    assert_eq!(reader.u16("major").unwrap(), 2);
    reader.u16("minor").unwrap();
    reader.bytes(bound, "certificate").unwrap();
    reader.bytes(bound, "checkpoint").unwrap();
    reader.bytes(bound, "prefix").unwrap();
    for _ in 0..reader.count(1_000, "records").unwrap() {
        let start = reader.offset();
        reader.u32("proposal length").unwrap();
        let payload = reader.bytes(bound, "payload").unwrap();
        let Ok(mut entry) = fa_model::Entry::decode(payload) else {
            continue;
        };
        let Some(index) = entry
            .proposal
            .extensions
            .iter()
            .position(|(tag, _)| *tag == fa_model::entry::OBLIGATION_MATURITY_EXTENSION)
        else {
            continue;
        };
        if remove {
            entry.proposal.extensions.remove(index);
        } else {
            let mut terms =
                InlineObligationTerms::decode_list(&entry.proposal.extensions[index].1).unwrap();
            terms[0].installments[0].due_date = day(2026, 1, 30);
            entry.proposal.extensions[index] = InlineObligationTerms::to_extension(&terms).unwrap();
        }
        let proposal_len = entry.proposal.canonical_bytes().unwrap().len();
        let changed = entry
            .proposal
            .seal(entry.approvals, entry.plan_certificate)
            .unwrap()
            .encode()
            .unwrap();
        let mut writer = fa_model::Writer::new();
        writer
            .u32(u32::try_from(proposal_len).unwrap())
            .bytes(&changed);
        let mut bytes = bundle[..start].to_vec();
        bytes.extend_from_slice(&writer.finish().unwrap());
        bytes.extend_from_slice(&bundle[reader.offset()..]);
        return bytes;
    }
    panic!("fixture must contain a journaled maturity record");
}

#[test]
fn due_date_aging_bundles_authenticate_changed_or_missing_maturity_terms() {
    use fa_model::obligation::ObligationStatus;
    let mut fixture = Fixture::new(0x8a);
    obligation(
        &mut fixture,
        b"due-retained-terms",
        1_000,
        Some((
            ObligationStatus::Contractual,
            vec![(day(2026, 1, 31), 1_000)],
        )),
    );
    let certified = due_date_certificate(&fixture, day(2026, 2, 1));
    let produced = produce_due_date(&mut fixture.book, &certified.certificate);
    verify_due_date(&fixture.book, &certified.certificate, &produced);
    for remove in [false, true] {
        let changed = alter_maturity_record(&produced.bundle.bytes, remove);
        let error = fa_verify::report::verify_report_expected(
            &changed,
            &[fixture.book.checkpoint_public_key()],
            None,
            None,
            Some(certified.certificate.digest()),
        )
        .unwrap_err();
        assert_eq!(
            error.predicate, "record_derivation",
            "remove={remove}: {error:?}"
        );
    }
}
