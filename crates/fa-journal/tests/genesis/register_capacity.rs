use super::*;

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
    assert_leg_projections(&h);
    let head = h.db.frontier().unwrap();
    let mut too_large = h.pending(h.rent_legs(i128::MAX), b"pending-over-cap");
    too_large.effective_date = DateDay::from_ymd(2026, 4, 1).unwrap();
    let refusal = h.post(h.request(too_large, &["post"])).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-198");
    assert_eq!(h.db.frontier().unwrap(), head);
}
