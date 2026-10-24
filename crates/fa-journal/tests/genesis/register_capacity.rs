use super::*;

#[test]
fn functional_capacity_refuses_while_native_cells_still_fit() {
    use fa_journal::fx::{FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms, value_proposal};
    use fa_money::rate::{ArithmeticBudget, BudgetLimits};
    let mut h = harness();
    let eur = h.book.units.lookup("EUR").unwrap();
    let accounts: Vec<_> = [("1288", 1, 0), ("4088", 4, 1)]
        .into_iter()
        .map(|(code, account_type, normal_balance)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type,
            normal_balance,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(eur),
            parent_code: None,
            limit: None,
        })
        .collect();
    let ctx = h.ctx();
    let description = h
        .proposal(vec![], b"foreign-chart", EntryClass::ORIGINAL)
        .description;
    let day = h.day();
    h.runtime
        .block_on(install_chart(
            &mut h.db,
            &ctx,
            &h.book,
            &accounts,
            PRINCIPAL,
            day,
            b"foreign-chart",
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let rate = FxRateDocument::new(
        FxRateTerms {
            base_unit: h.usd,
            quote_unit: eur,
            rate_num: i128::MAX as u128,
            rate_den: 1,
            rounding: fa_money::RoundingLaw::HalfEven,
        },
        day,
        1,
        FxRatePurpose::SpotClose,
        "Capacity boundary retained rate",
    )
    .unwrap();
    h.add_document(
        &rate
            .document(h.book.book_id, PRINCIPAL, HUMAN_UPLOAD)
            .unwrap(),
    )
    .unwrap();
    for (index, key) in [
        b"functional-at-cap".as_slice(),
        b"functional-over-cap".as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(h.book.book_id, "1288"),
                Amount::new(eur, 1),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(h.book.book_id, "4088"),
                Amount::new(eur, 1),
            ),
        ];
        let arithmetic = h.root.restrict::<asupersync::cx::cap::None>();
        let mut budget =
            ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(100_000, 0), 4096);
        let proposal = value_proposal(
            &mut budget,
            h.proposal(legs, key, EntryClass::ORIGINAL),
            &fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap(),
            &h.book.units,
            FxLawId::SpotClose,
            std::slice::from_ref(&rate),
        )
        .unwrap();
        assert_eq!(proposal.legs[0].base_amount.unwrap().mantissa, i128::MAX);
        let head = h.db.frontier().unwrap();
        let result = h.post(h.request(proposal, &["post"]));
        if index == 0 {
            result.expect("first functional gross column fits");
        } else {
            let refusal = result.unwrap_err();
            assert_eq!(refusal.code, "FA-REF-198", "{refusal}");
            assert!(refusal.message.contains("functional"), "{refusal}");
            assert_eq!(h.db.frontier().unwrap(), head);
        }
    }
    assert_leg_projections(&h);
}

fn oracle(h: &Harness) -> fa_reference::Oracle {
    let mut oracle = fa_reference::Oracle::new(h.book.calendar.clone());
    oracle.create_periods(2026);
    oracle.transition(&h.march, PeriodTransition::Open).unwrap();
    for code in ["1000", "6000"] {
        oracle.add_account(fa_reference::Account {
            code: code.into(),
            is_leaf: true,
            unit: Some(h.usd.0),
        });
    }
    oracle
}

fn intent(h: &Harness, amount: i128, key: &[u8]) -> fa_reference::Intent {
    fa_reference::Intent {
        class: "Original".into(),
        date: h.day(),
        discriminator: None,
        legs: vec![
            fa_reference::Leg {
                side: fa_reference::Side::Debit,
                account: "6000".into(),
                unit: h.usd.0,
                entity: None,
                mantissa: amount,
            },
            fa_reference::Leg {
                side: fa_reference::Side::Credit,
                account: "1000".into(),
                unit: h.usd.0,
                entity: None,
                mantissa: amount,
            },
        ],
        key: key.to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 0,
        resolves: None,
        settles: vec![],
    }
}

#[test]
fn cumulative_gross_capacity_is_admitted_before_publication() {
    let mut h = harness();
    let mut reference = oracle(&h);
    for (amount, key) in [
        (i128::MAX - 1, b"cap-minus-one".as_slice()),
        (1, b"at-cap".as_slice()),
    ] {
        h.post(h.request(
            h.proposal(h.rent_legs(amount), key, EntryClass::ORIGINAL),
            &["post"],
        ))
        .expect("representable gross cell");
        assert!(matches!(
            reference.post(&intent(&h, amount, key)),
            fa_reference::Verdict::Posted { .. }
        ));
    }
    let head = h.db.frontier().unwrap();
    let proposal = h.proposal(h.rent_legs(1), b"correctable", EntryClass::ORIGINAL);
    let refusal = h.post(h.request(proposal, &["post"])).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-198", 3), "{refusal}");
    assert!(refusal.message.contains("posted"), "{refusal}");
    assert_eq!(
        h.db.frontier().unwrap(),
        head,
        "no entry or outcome was published"
    );
    assert_eq!(
        reference.post(&intent(&h, 1, b"correctable")),
        fa_reference::Verdict::Refused { code: "FA-REF-198" }
    );
    assert_leg_projections(&h);

    // A refused key remains free. Opposite gross columns still have room.
    let mut corrected = h.proposal(h.rent_legs(1), b"correctable", EntryClass::ORIGINAL);
    for leg in &mut corrected.legs {
        leg.side = leg.side.flipped();
    }
    corrected.unit_totals = EntryPayload::fold_unit_totals(&corrected.legs).unwrap();
    h.post(h.request(corrected, &["post"]))
        .expect("same key with corrected admissible effects");
    assert_leg_projections(&h);
}

#[test]
fn prepared_writers_cannot_jointly_exceed_capacity() {
    for first in [0, 1] {
        let mut h = harness();
        h.post(h.request(
            h.proposal(h.rent_legs(i128::MAX - 1), b"basis", EntryClass::ORIGINAL),
            &["post"],
        ))
        .unwrap();
        let mut prepared = Vec::new();
        for key in [b"writer-a".as_slice(), b"writer-b".as_slice()] {
            let request = h.request(
                h.proposal(h.rent_legs(1), key, EntryClass::ORIGINAL),
                &["post"],
            );
            let ctx = h.ctx();
            let PostPreparation::Ready(p) = prepare_post(&mut h.db, &ctx, &h.book, request)
                .unwrap()
                .unwrap()
            else {
                panic!("fresh writer");
            };
            prepared.push(Some(p));
        }
        let ctx = h.ctx();
        let winner = prepared[first].take().unwrap();
        h.runtime
            .block_on(winner.commit(&mut h.db, &ctx))
            .unwrap()
            .unwrap();
        let head = h.db.frontier().unwrap();
        let loser = prepared[1 - first].take().unwrap();
        let refusal = h
            .runtime
            .block_on(loser.commit(&mut h.db, &ctx))
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refusal.exit, 6,
            "native prefix witness must conflict: {refusal}"
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_leg_projections(&h);
    }
}

#[test]
fn fitting_net_does_not_authorize_overflowing_gross_columns() {
    let mut h = harness();
    let posted = h
        .post(h.request(
            h.proposal(h.rent_legs(i128::MAX), b"maximum", EntryClass::ORIGINAL),
            &["post"],
        ))
        .unwrap();
    let target = committed(&posted).unwrap().0;
    h.post(h.request(h.reversal_of(target, i128::MAX, b"reverse"), &["post"]))
        .unwrap();
    let head = h.db.frontier().unwrap();
    let refusal = h
        .post(h.request(
            h.proposal(h.rent_legs(1), b"net-fits", EntryClass::ORIGINAL),
            &["post"],
        ))
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-198");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_leg_projections(&h);
}

#[test]
fn pending_release_is_judged_in_the_final_atomic_state_across_periods() {
    let mut h = harness();
    let mut reference = oracle(&h);
    let mut old = intent(&h, i128::MAX, b"old-hold");
    old.class = "Pending".into();
    let fa_reference::Verdict::Posted {
        index: old_index, ..
    } = reference.post(&old)
    else {
        panic!("oracle hold fits");
    };
    let hold = h
        .post(h.request(h.pending(h.rent_legs(i128::MAX), b"old-hold"), &["post"]))
        .unwrap();
    let target = committed(&hold).unwrap().0;
    h.transition(
        &h.april.clone(),
        PeriodTransition::Open,
        b"open-april-capacity",
    )
    .unwrap();
    let mut next = h.pending(h.rent_legs(1), b"next-hold");
    next.effective_date = DateDay::from_ymd(2026, 4, 1).unwrap();
    let mut release = h.resolution_voids(target, b"release-old");
    release.effective_date = next.effective_date;
    let batch = h.batch(b"replace-hold", vec![next, release]);
    h.post_batch(batch)
        .expect("released old hold is absent from final pending sum");
    reference
        .transition(&h.april, PeriodTransition::Open)
        .unwrap();
    let mut next = intent(&h, 1, b"next-hold");
    next.class = "Pending".into();
    next.date = DateDay::from_ymd(2026, 4, 1).unwrap();
    let mut release = next.clone();
    release.class = "Resolution".into();
    release.key = b"release-old".to_vec();
    release.legs.clear();
    release.resolves = Some(fa_reference::Resolve {
        target: old_index,
        posts: None,
    });
    assert!(matches!(
        reference.post_batch(b"replace-hold", &[next, release]),
        fa_reference::BatchVerdict::Posted { .. }
    ));
    assert_leg_projections(&h);
    let head = h.db.frontier().unwrap();
    let mut too_large = h.pending(h.rent_legs(i128::MAX), b"pending-over-cap");
    too_large.effective_date = DateDay::from_ymd(2026, 4, 1).unwrap();
    let refusal = h.post(h.request(too_large, &["post"])).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-198");
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn atomic_batch_capacity_refusal_publishes_neither_members_nor_outcome() {
    let mut h = harness();
    let before = h.db.frontier().unwrap();
    let batch = h.batch(
        b"capacity-batch",
        vec![
            h.proposal(h.rent_legs(i128::MAX), b"batch-max", EntryClass::ORIGINAL),
            h.proposal(h.rent_legs(1), b"batch-one", EntryClass::ORIGINAL),
        ],
    );
    let refusal = h.post_batch(batch).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-198");
    assert_eq!(h.db.frontier().unwrap(), before);
    let corrected = h.batch(
        b"capacity-batch",
        vec![
            h.proposal(h.rent_legs(1), b"batch-max", EntryClass::ORIGINAL),
            h.proposal(h.rent_legs(1), b"batch-one", EntryClass::ORIGINAL),
        ],
    );
    h.post_batch(corrected)
        .expect("refused batch and member keys stay free");
    assert_leg_projections(&h);
}
