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
