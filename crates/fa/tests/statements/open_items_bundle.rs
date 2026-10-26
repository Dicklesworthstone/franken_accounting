//! Independently replay the real kernel's application graph from portable bytes.

use super::report_bundle::{produce, replace_certificate, reseal, tick};
use super::*;

fn collect(
    fixture: &mut Fixture,
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
    fixture.commit(fixture.proposal(day(2026, 1, 20), key, EntryClass::ORIGINAL, legs))
}

fn reverse(fixture: &mut Fixture, target: fa_model::EntryRef, key: &[u8]) -> Posted {
    let (source, _) = fixture.book.read_entry(target.vid).unwrap().unwrap();
    let mut legs = source.proposal.legs.clone();
    for leg in &mut legs {
        leg.side = if leg.side == Side::Debit {
            Side::Credit
        } else {
            Side::Debit
        };
        leg.settles.clear();
    }
    let mut proposal = fixture.proposal(
        source.proposal.effective_date,
        key,
        EntryClass::REVERSAL,
        legs,
    );
    proposal.effective_period = source.proposal.effective_period.clone();
    proposal.supersession = vec![fa_model::Supersession {
        target,
        kind: fa_model::SupersessionKind::Reverses,
        reason_code: 1,
    }];
    fixture.commit(proposal)
}

fn verify(
    book: &Book,
    produced: &fa::ProducedBundle,
    certificate: &ReportCertificate,
) -> fa_verify::report::VerifiedReport {
    let key = book.checkpoint_public_key();
    let checkpoint = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&checkpoint.checkpoint),
        Some(&produced.receipt),
        Some(&certificate.digest),
    )
    .expect("authenticated journal history must reproduce every open-item byte");
    assert_eq!(verified.output, certificate.output);
    assert_eq!(verified.known_at, certificate.known_at.0);
    assert_eq!(verified.certificate_digest, certificate.digest);
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.unit_universe_source, "authenticated-registry");
    assert!(verified.open_items.is_some());
    assert!(verified.statement.is_none());
    assert!(verified.rows.is_empty());
    verified
}

#[test]
fn native_open_item_bundles_recompute_applications_and_reversal_parity_at_each_frontier() {
    let mut fixture = Fixture::new(0x81);
    let usd = fixture.usd;
    let cash = account_vid(fixture.book.context().book_id, "1000");
    let unused = account_vid(fixture.book.context().book_id, "6100");
    let first = fixture
        .transfer(
            day(2026, 1, 10),
            b"open-first",
            usd,
            ("1000", "4000"),
            10_000,
        )
        .entry_ref();
    let second = fixture
        .transfer(
            day(2026, 1, 11),
            b"open-second",
            usd,
            ("1000", "4000"),
            5_000,
        )
        .entry_ref();
    let mut frontiers = vec![(fixture.book.head().unwrap(), Some(10_000), None)];
    let receipt = collect(
        &mut fixture,
        b"open-collection",
        4_500,
        &[(first, 3_000), (second, 1_000)],
    );
    frontiers.push((receipt.recorded_at(), Some(7_000), Some(true)));
    let reversed = reverse(&mut fixture, receipt.entry_ref(), b"undo-open-collection");
    frontiers.push((reversed.recorded_at(), Some(10_000), Some(false)));
    // The kernel refuses revival of a settlement-bearing payment by reversing
    // its reversal. Restore the settlement-free invoice instead, after the
    // payment is undone, and retain that undone application in its history.
    let reversed_invoice = reverse(&mut fixture, first, b"undo-open-invoice");
    frontiers.push((reversed_invoice.recorded_at(), None, Some(false)));
    let restored = reverse(
        &mut fixture,
        reversed_invoice.entry_ref(),
        b"restore-open-invoice",
    );
    frontiers.push((restored.recorded_at(), Some(10_000), Some(false)));
    let later = fixture.transfer(
        day(2026, 1, 1),
        b"later-backdated-open-item",
        usd,
        ("1000", "4000"),
        900,
    );
    for (at, first_open, application_live) in frontiers {
        for account in [None, Some(cash), Some(unused)] {
            let certified = fixture
                .book
                .certify_report(fa::ReportSelection::OpenItems { account }, Some(at))
                .unwrap()
                .unwrap();
            fixture
                .book
                .retain_certificate(&certified.certificate)
                .unwrap()
                .unwrap();
            let produced = produce(&mut fixture.book, &certified.certificate);
            let verified = verify(&fixture.book, &produced, &certified.certificate);
            let report = verified.open_items.unwrap();
            assert_eq!(report.account_filter, account.map(|vid| vid.0));
            assert!(
                !report
                    .items
                    .iter()
                    .any(|item| item.entry == later.entry_ref().vid.0)
            );
            if account == Some(unused) {
                assert!(report.items.is_empty());
                assert_eq!(report.accounts.len(), 1);
                assert!(report.accounts.contains_key(&unused.0));
                continue;
            }
            let item = report
                .items
                .iter()
                .find(|item| item.entry == first.vid.0 && item.ordinal == 0);
            if let Some(first_open) = first_open {
                let item = item.expect("a live invoice remains visible, even when fully settled");
                assert_eq!(item.open, first_open);
                assert_eq!(item.applied, 10_000 - first_open);
                assert_eq!(item.applied_out, 0);
                match application_live {
                    None => assert!(item.applications.is_empty()),
                    Some(live) => {
                        assert_eq!(item.applications.len(), 1);
                        assert_eq!(item.applications[0].entry, receipt.entry_ref().vid.0);
                        assert_eq!(item.applications[0].amount, 3_000);
                        assert_eq!(item.applications[0].live, live);
                    }
                }
            } else {
                assert!(
                    item.is_none(),
                    "a reversed invoice is absent from live items"
                );
            }
            if account == Some(cash) {
                assert!(report.items.iter().all(|item| item.account == cash.0));
                assert_eq!(report.accounts.len(), 1);
            }
            if application_live == Some(true) {
                let remainder = report
                    .items
                    .iter()
                    .find(|item| item.entry == receipt.entry_ref().vid.0 && item.ordinal == 1)
                    .unwrap();
                assert_eq!(remainder.original, 4_500);
                assert_eq!(remainder.applied_out, 4_000);
                assert_eq!(remainder.open, 500);
            } else {
                assert!(
                    !report
                        .items
                        .iter()
                        .any(|item| item.entry == receipt.entry_ref().vid.0)
                );
            }
        }
    }
}

#[test]
fn instant_open_item_bundles_keep_the_original_authenticated_time_bucket() {
    let mut fixture = Fixture::new(0x82);
    let instant = fa_time::UtcInstant::parse("2026-01-15T00:00:00Z")
        .unwrap()
        .unix_ns();
    let usd = fixture.usd;
    tick(&mut fixture.book, instant + 100, false);
    let invoice = fixture
        .transfer(
            day(2026, 1, 10),
            b"instant-open-invoice",
            usd,
            ("1000", "4000"),
            10_000,
        )
        .entry_ref();
    collect(
        &mut fixture,
        b"instant-open-first-payment",
        3_000,
        &[(invoice, 3_000)],
    );
    let selection = fa::ReportSelection::OpenItems {
        account: Some(account_vid(fixture.book.context().book_id, "1000")),
    };
    let original = fixture
        .book
        .certify_report_at_instant(selection.clone(), instant + 105)
        .unwrap()
        .unwrap()
        .certificate;
    tick(&mut fixture.book, instant + 110, true);
    collect(
        &mut fixture,
        b"instant-open-later-payment",
        2_000,
        &[(invoice, 2_000)],
    );
    tick(&mut fixture.book, instant + 120, true);
    let bounded = fixture
        .book
        .certify_report_at_instant(selection, instant + 105)
        .unwrap()
        .unwrap()
        .certificate;
    assert_eq!(original.output, bounded.output);
    for certificate in [original, bounded] {
        let produced = produce(&mut fixture.book, &certificate);
        let verified = verify(&fixture.book, &produced, &certificate);
        let item = verified
            .open_items
            .unwrap()
            .items
            .into_iter()
            .find(|item| item.entry == invoice.vid.0 && item.ordinal == 0)
            .unwrap();
        assert_eq!(item.open, 7_000);
        let actual = verified.time_selection.unwrap();
        let expected = certificate.time_selection.unwrap();
        assert_eq!(actual.frontier, expected.resolution.frontier);
        assert_eq!(actual.lower_entry, expected.lower_entry.0);
        assert_eq!(
            actual.upper_entry,
            expected.upper_entry.map(|entry| entry.0)
        );
    }
}

#[test]
fn resealed_open_item_amount_history_and_account_forgeries_are_refused() {
    let mut fixture = Fixture::new(0x83);
    let usd = fixture.usd;
    let cash = account_vid(fixture.book.context().book_id, "1000");
    let invoice = fixture
        .transfer(
            day(2026, 1, 10),
            b"forgery-open-invoice",
            usd,
            ("1000", "4000"),
            5_000,
        )
        .entry_ref();
    collect(
        &mut fixture,
        b"forgery-open-payment",
        2_000,
        &[(invoice, 2_000)],
    );
    let certified = fixture
        .book
        .certify_report(
            fa::ReportSelection::OpenItems {
                account: Some(cash),
            },
            None,
        )
        .unwrap()
        .unwrap();
    let produced = produce(&mut fixture.book, &certified.certificate);
    verify(&fixture.book, &produced, &certified.certificate);
    let ReportOutput::OpenItems(original) = certified.report else {
        unreachable!()
    };
    for change in ["amount", "history", "metadata"] {
        let mut report = original.clone();
        let item = report
            .items
            .iter_mut()
            .find(|item| item.entry == invoice.vid)
            .unwrap();
        match change {
            "amount" => {
                item.open += 1;
                item.applied -= 1;
            }
            "history" => {
                item.applications[0].live = false;
                item.applied = 0;
                item.open = item.original;
            }
            "metadata" => {
                report.accounts.get_mut(&cash).unwrap().name = "Fabricated account name".into();
            }
            _ => unreachable!(),
        }
        let mut certificate = certified.certificate.clone();
        certificate.output = report.canonical_bytes().unwrap();
        reseal(&mut certificate);
        let forged = replace_certificate(&produced.bundle.bytes, &certificate);
        // Accept the changed certificate digest deliberately: the independent
        // fold, not an old receipt/digest, must reject the altered output.
        let error = fa_verify::report::verify_report_expected(
            &forged,
            &[fixture.book.checkpoint_public_key()],
            None,
            None,
            Some(&certificate.digest),
        )
        .unwrap_err();
        assert_eq!(error.predicate, "report_recomputation", "{change}: {error}");
    }
}

#[test]
fn open_item_bundle_production_requires_current_read_and_produce_authority() {
    let mut fixture = Fixture::new(0x84);
    let certificate = fixture
        .book
        .certify_report(fa::ReportSelection::OpenItems { account: None }, None)
        .unwrap()
        .unwrap()
        .certificate;
    for operations in [&["read"][..], &["produce"][..]] {
        let capability = Capability::embedded(PRINCIPAL, operations).unwrap();
        let before = fixture.book.head().unwrap();
        assert!(
            fixture
                .book
                .produce_report_bundle(PRINCIPAL, &capability, None, &certificate)
                .unwrap()
                .is_err()
        );
        assert_eq!(fixture.book.head().unwrap(), before);
    }
}
