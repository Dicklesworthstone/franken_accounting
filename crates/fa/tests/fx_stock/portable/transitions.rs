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
fn scheduled_foreign_accrual_exports_replay_original_carrying_after_later_quotes_and_posts() {
    let mut fixture = Fixture::with_time_zone(Some(fa_journal::TimeZonePolicy::Utc));
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
        "January accrual, before the automatic February reversal",
    )
    .unwrap();
    let rate = fixture
        .book
        .upload_fx_rate(&cap(&["post"]), &rate)
        .unwrap()
        .unwrap()
        .oid;
    let mut proposal = fixture.proposal(b"portable-scheduled-accrual", day(1, 5), 8);
    proposal.class = EntryClass::ADJUSTING;
    proposal.legs[1].amount.mantissa = 4;
    proposal.legs.push(proposal.legs[1].clone());
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    let proposal = fa_journal::with_auto_reverse(proposal, day(2, 1));
    let proposal = fixture
        .book
        .value_fx_proposal(
            &cap(&["read", "post"]),
            proposal,
            FxLawId::SpotClose,
            &[rate],
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        proposal.base_totals.as_ref().unwrap().residual,
        Some(Residual {
            leg_ordinal: 1,
            amount: Amount::new(fixture.usd, 1),
        })
    );
    let target = fixture
        .book
        .post(request(proposal))
        .unwrap()
        .unwrap()
        .entry_ref();
    let initial = certify(&mut fixture, TrialBalanceSelection::AsOf(day(2, 28)));

    // No February quote exists. The scheduled effect must use the original
    // January carrying values and original residual ordinal, just as an
    // exact manual reversal does.
    let runtime = asupersync::runtime::RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let instant = u64::try_from(day(2, 1).0).unwrap() * 86_400_000_000_000;
    runtime
        .block_on(
            fixture
                .book
                .record_tick(&root, instant, true, &cap(&["witness"])),
        )
        .unwrap()
        .unwrap();
    let system = fa_journal::rows::system_principal(fixture.book.context().book_id);
    let executor = Capability::new(
        system,
        fa_policy::Profile::System,
        &[fa_policy::Op::Post],
        PRINCIPAL,
    )
    .unwrap();
    let swept = fixture.book.sweep_now(&executor, 16).unwrap().unwrap();
    let minted = swept
        .reversals
        .iter()
        .flat_map(|batch| batch.minted.iter())
        .collect::<Vec<_>>();
    assert_eq!(minted.len(), 1);
    assert_eq!(minted[0].0, target);
    assert!(swept.reversals.iter().all(|batch| batch.blocked.is_empty()));
    let (original, _) = fixture.book.read_entry(target.vid).unwrap().unwrap();
    let (reversal, _) = fixture.book.read_entry(minted[0].1.vid).unwrap().unwrap();
    assert_eq!(reversal.proposal.base_totals, original.proposal.base_totals);
    assert!(matches!(
        reversal.proposal.origin,
        EntryOrigin::Schedule { .. }
    ));
    assert!(fixture.book.verify_schedules().unwrap().is_green());
    assert!(fixture.book.verify_fx_conversions(None).unwrap().is_green());
    let offset = certify(&mut fixture, TrialBalanceSelection::AsOf(day(2, 28)));
    let february = certify(
        &mut fixture,
        TrialBalanceSelection::Activity(vec!["FY2026-P02".into()]),
    );

    fixture.rate(
        day(1, 5),
        99,
        "A later quote cannot reprice the saved automatic reversal",
    );
    fixture.post(b"after-scheduled-proof", day(1, 20), 20, 13);
    let state = checkpoint(&mut fixture.book);
    let head = fixture.book.head().unwrap();
    let account = account_vid(fixture.book.context().book_id, "1200").0;
    for (certificate, entries, gross, net) in [(&initial, 1, 3, 3), (&offset, 2, 6, 0)] {
        let verified = verified_transition(&mut fixture, state, certificate, rate);
        assert_eq!(verified.entries, entries);
        assert_eq!(
            verified.cells.iter().map(|cell| cell.debits).sum::<i128>(),
            gross
        );
        assert_eq!(
            verified.cells.iter().map(|cell| cell.credits).sum::<i128>(),
            gross
        );
        let cell = verified
            .cells
            .iter()
            .find(|cell| cell.account == account)
            .unwrap();
        assert_eq!(cell.debits.checked_sub(cell.credits), Some(net));
    }
    let activity = verified_transition(&mut fixture, state, &february, rate);
    assert!(activity.activity);
    assert_eq!(activity.entries, 1);
    let cell = activity
        .cells
        .iter()
        .find(|cell| cell.account == account)
        .unwrap();
    assert_eq!((cell.debits, cell.credits), (0, 3));
    assert_eq!(fixture.book.head().unwrap(), head);
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
