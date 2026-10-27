//! Real journal transitions must agree with the independent portable fold,
//! including the original valuation evidence when the reporting date changes.

use super::*;
use fa_model::{ControlPayload, Disposition, Pending, Residual, Supersession, SupersessionKind};

fn verified_transition(
    fixture: &mut Fixture,
    state: Oid,
    certificate: &ReportCertificate,
    rate: Oid,
) -> fa_verify::report::VerifiedFunctionalTrialBalance {
    let replayed = fixture.book.replay_report(certificate).unwrap().unwrap();
    assert_eq!(replayed.canonical_bytes().unwrap(), certificate.output);
    let produced = produce(fixture, state, certificate);
    assert_eq!(produced.documents, [rate]);
    let verified = verify(fixture, &produced, certificate);
    assert_eq!(verified.output, certificate.output);
    assert_eq!(verified.known_at, certificate.known_at.0);
    verified.functional_trial_balance.unwrap()
}

#[test]
fn valued_pending_exports_keep_old_holds_and_release_them_across_periods() {
    let mut fixture = Fixture::new();
    let rate = fixture.rate(day(1, 5), 15, "Original January reservation valuation");
    let mut pending = fixture.proposal(b"portable-valued-hold", day(1, 5), 2_000);
    pending.class = EntryClass::PENDING;
    pending.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let pending = fixture
        .book
        .value_fx_proposal(
            &cap(&["read", "post"]),
            pending,
            FxLawId::SpotClose,
            &[rate],
        )
        .unwrap()
        .unwrap();
    let held = fixture.book.post(request(pending)).unwrap().unwrap();
    let held_at = held.recorded_at();
    let selectors = [
        TrialBalanceSelection::AsOf(day(1, 31)),
        TrialBalanceSelection::Periods(vec!["FY2026-P01".into()]),
        TrialBalanceSelection::Activity(vec!["FY2026-P01".into()]),
    ];
    let original: Vec<_> = selectors
        .iter()
        .cloned()
        .map(|selection| certify(&mut fixture, selection))
        .collect();

    // The February release changes January's outstanding reservation at a
    // later recorded frontier, even though its effective date is outside
    // every selected report. It contributes no posted legs or new valuation.
    let mut release = fixture.proposal(b"portable-valued-release", day(2, 5), 1);
    release.class = EntryClass::RESOLUTION;
    release.legs.clear();
    release.unit_totals.clear();
    release.control = Some(ControlPayload::ReservationRelease);
    release.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: Some(held.entry_ref()),
        disposition: Some(Disposition::Voids),
    });
    let released = fixture.book.post(request(release)).unwrap().unwrap();
    let released_at = released.recorded_at();
    let current: Vec<_> = selectors
        .into_iter()
        .map(|selection| certify(&mut fixture, selection))
        .collect();
    let state = checkpoint(&mut fixture.book);
    let head = fixture.book.head().unwrap();

    for (original, current) in original.iter().zip(&current) {
        assert_eq!(original.known_at, held_at);
        assert_eq!(current.known_at, released_at);
        let held = verified_transition(&mut fixture, state, original, rate);
        let released = verified_transition(&mut fixture, state, current, rate);
        assert!(held.cells.is_empty());
        assert_eq!(held.pending.len(), 2);
        assert_eq!(
            held.pending.iter().map(|cell| cell.debits).sum::<i128>(),
            3_000
        );
        assert_eq!(
            held.pending.iter().map(|cell| cell.credits).sum::<i128>(),
            3_000
        );
        assert!(held.pending.iter().all(|cell| cell.entry_count == 1));
        assert_eq!(held.watermark, Some(held_at.0));
        assert!(released.cells.is_empty());
        assert!(released.pending.is_empty());
        assert_eq!(released.watermark, Some(released_at.0));
        assert_ne!(held.fold_digest, released.fold_digest);
    }
    assert_eq!(fixture.book.head().unwrap(), head);
}

fn reverse_valued(
    fixture: &mut Fixture,
    target: EntryRef,
    key: &[u8],
    effective: DateDay,
) -> EntryRef {
    let (original, _) = fixture.book.read_entry(target.vid).unwrap().unwrap();
    let mut reversal = original.proposal.clone();
    reversal.class = EntryClass::REVERSAL;
    reversal.idempotency_key = key.to_vec();
    reversal.effective_date = effective;
    reversal.description = fixture
        .book
        .seal_text("Exact inherited valuation reversal")
        .unwrap();
    reversal.supersession = vec![Supersession {
        target,
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    }];
    for leg in &mut reversal.legs {
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
    }
    reversal.unit_totals = EntryPayload::fold_unit_totals(&reversal.legs).unwrap();
    let reversed = fixture
        .book
        .post(request(reversal))
        .unwrap()
        .unwrap()
        .entry_ref();
    let (recorded, _) = fixture.book.read_entry(reversed.vid).unwrap().unwrap();
    assert_eq!(recorded.proposal.base_totals, original.proposal.base_totals);
    assert_eq!(recorded.proposal.evidence, original.proposal.evidence);
    for (before, after) in original.proposal.legs.iter().zip(&recorded.proposal.legs) {
        assert_eq!(before.amount, after.amount);
        assert_eq!(before.base_amount, after.base_amount);
        assert_ne!(before.side, after.side);
    }
    reversed
}

#[test]
fn inherited_reversal_exports_keep_original_rate_and_residual_through_a_chain() {
    let mut fixture = Fixture::new();
    let rate = FxRateDocument::new(
        FxRateTerms {
            base_unit: fixture.usd,
            quote_unit: fixture.eur,
            rate_num: 1,
            rate_den: 3,
            rounding: RoundingLaw::HalfEven,
        },
        day(1, 5),
        1_767_571_200_000_000_000,
        FxRatePurpose::SpotClose,
        "Original one-third spot with a split credit residual",
    )
    .unwrap();
    let rate = fixture
        .book
        .upload_fx_rate(&cap(&["post"]), &rate)
        .unwrap()
        .unwrap()
        .oid;
    let mut original = fixture.proposal(b"portable-residual-original", day(1, 5), 8);
    original.legs[1].amount.mantissa = 4;
    original.legs.push(original.legs[1].clone());
    original.unit_totals = EntryPayload::fold_unit_totals(&original.legs).unwrap();
    let original = fixture
        .book
        .value_fx_proposal(
            &cap(&["read", "post"]),
            original,
            FxLawId::SpotClose,
            &[rate],
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        original
            .legs
            .iter()
            .map(|leg| leg.base_amount)
            .collect::<Vec<_>>(),
        [
            Some(Amount::new(fixture.usd, 3)),
            Some(Amount::new(fixture.usd, 2)),
            Some(Amount::new(fixture.usd, 1))
        ],
    );
    assert_eq!(
        original.base_totals.as_ref().unwrap().residual,
        Some(Residual {
            leg_ordinal: 1,
            amount: Amount::new(fixture.usd, 1)
        }),
    );
    let original = fixture
        .book
        .post(request(original))
        .unwrap()
        .unwrap()
        .entry_ref();
    let initial = certify(&mut fixture, TrialBalanceSelection::AsOf(day(2, 28)));

    // No February Rate exists. A legitimate reversal retains the January
    // quote and the positive residual on its original ordinal, with the leg
    // side swapped; it cannot silently obtain a current-date valuation.
    let reversed = reverse_valued(
        &mut fixture,
        original,
        b"portable-residual-reversed",
        day(2, 5),
    );
    let offset = certify(&mut fixture, TrialBalanceSelection::AsOf(day(2, 28)));
    let february = certify(
        &mut fixture,
        TrialBalanceSelection::Activity(vec!["FY2026-P02".into()]),
    );
    reverse_valued(
        &mut fixture,
        reversed,
        b"portable-residual-restored",
        day(2, 10),
    );
    let restored = certify(&mut fixture, TrialBalanceSelection::AsOf(day(2, 28)));
    let state = checkpoint(&mut fixture.book);
    let head = fixture.book.head().unwrap();
    let receivable = account_vid(fixture.book.context().book_id, "1200").0;
    let revenue = account_vid(fixture.book.context().book_id, "4000").0;

    for (certificate, gross, entries, asset_net) in [
        (&initial, 3, 1, 3),
        (&offset, 6, 2, 0),
        (&restored, 9, 3, 3),
    ] {
        let result = verified_transition(&mut fixture, state, certificate, rate);
        assert_eq!(
            result.cells.iter().map(|cell| cell.debits).sum::<i128>(),
            gross
        );
        assert_eq!(
            result.cells.iter().map(|cell| cell.credits).sum::<i128>(),
            gross
        );
        assert_eq!(result.entries, entries);
        assert!(result.pending.is_empty());
        let asset = result
            .cells
            .iter()
            .find(|cell| cell.account == receivable)
            .unwrap();
        let income = result
            .cells
            .iter()
            .find(|cell| cell.account == revenue)
            .unwrap();
        assert_eq!(asset.debits.checked_sub(asset.credits), Some(asset_net));
        assert_eq!(income.credits.checked_sub(income.debits), Some(asset_net));
        assert_eq!(asset.entry_count, entries);
        assert_eq!(
            income.entry_count, entries,
            "split legs count once per contributing entry"
        );
    }
    let activity = verified_transition(&mut fixture, state, &february, rate);
    assert!(activity.activity);
    assert_eq!(activity.entries, 1);
    let asset = activity
        .cells
        .iter()
        .find(|cell| cell.account == receivable)
        .unwrap();
    let income = activity
        .cells
        .iter()
        .find(|cell| cell.account == revenue)
        .unwrap();
    assert_eq!((asset.debits, asset.credits), (0, 3));
    assert_eq!((income.debits, income.credits), (3, 0));
    assert_eq!(fixture.book.head().unwrap(), head);
}
