use super::*;

fn invoice(h: &Harness, count: u16, key: &[u8]) -> EntryPayload {
    let mut legs = vec![
        LegPayload::simple(Side::Debit, h.receivable, Amount::new(h.usd, 100));
        usize::from(count)
    ];
    legs.push(LegPayload::simple(
        Side::Credit,
        h.revenue,
        Amount::new(h.usd, i128::from(count) * 100),
    ));
    h.proposal(legs, key, EntryClass::ORIGINAL)
}

fn receipt(h: &Harness, target: EntryRef, count: u16, each: i128, key: &[u8]) -> EntryPayload {
    let mut legs = vec![LegPayload::simple(
        Side::Debit,
        h.cash,
        Amount::new(h.usd, i128::from(count) * each),
    )];
    for ordinal in 0..count {
        let mut applying = LegPayload::simple(Side::Credit, h.receivable, Amount::new(h.usd, each));
        applying.settles = vec![settle(target, ordinal, h.usd, each)];
        legs.push(applying);
    }
    h.proposal(legs, key, EntryClass::ORIGINAL)
}

fn prepare(h: &mut Harness, proposal: EntryPayload) -> Box<PreparedPost> {
    let request = h.request(proposal, &["post"]);
    let ctx = h.ctx();
    match prepare_post(&mut h.db, &ctx, &h.book, request)
        .expect("prepare kernel")
        .expect("settlement admitted")
    {
        PostPreparation::Ready(prepared) => prepared,
        PostPreparation::AlreadyRecorded(_) => panic!("distinct settlement must be fresh"),
    }
}

fn commit(h: &mut Harness, prepared: Box<PreparedPost>) -> Result<Posted, Refusal> {
    let ctx = h.ctx();
    let db = &mut h.db;
    h.runtime
        .block_on(async move { prepared.commit(db, &ctx).await })
        .expect("commit kernel")
}

#[test]
fn a_shared_settlement_target_checks_its_complete_payload_and_mirrors_once() {
    // The actual checked-entry reader counts every mirror lookup, including
    // the absent final leg. Increasing both the invoice and its applications
    // must grow that work linearly, while every applied balance is still exact.
    for count in [16, 128, 1_024] {
        let mut h = harness();
        let proposal = invoice(&h, count, b"many-line-invoice");
        let target = h
            .post(h.request(proposal, &["post"]))
            .expect("invoice committed")
            .entry_ref();
        let proposal = receipt(&h, target, count, 40, b"many-line-receipt");
        let expected = proposal.clone();
        let prepared = prepare(&mut h, proposal);
        let work = prepared.settlement_work();
        assert_eq!(work.target_entries_checked, 1, "count={count}");
        assert_eq!(work.peak_cached_target_entries, 1, "count={count}");
        assert_eq!(
            work.target_leg_mirrors_checked,
            usize::from(count) + 2,
            "count={count}"
        );
        assert_eq!(work.reversal_points_checked, 1, "count={count}");
        assert_eq!(work.target_settlement_links_checked, 0, "count={count}");
        let posted = commit(&mut h, prepared).expect("receipt committed");
        let (recorded, _) = read_entry(&h.db, posted.entry_ref().vid)
            .unwrap()
            .expect("receipt retained");
        assert_eq!(recorded.proposal, expected);
        for ordinal in 0..count {
            assert_eq!(h.applied_to(target.vid, ordinal), 40, "ordinal={ordinal}");
        }
        assert_eq!(
            h.applied_to(target.vid, count),
            0,
            "revenue stays unapplied"
        );
    }
}

#[test]
fn settlement_target_payloads_live_only_until_their_last_application() {
    let mut h = harness();
    let invoices: Vec<_> = (0u16..32)
        .map(|i| invoice(&h, 2, &i.to_le_bytes()))
        .collect();
    let targets: Vec<_> = invoices.iter().map(|entry| h.member_ref(entry)).collect();
    let batch = h.batch(b"retention-invoices", invoices);
    h.post_batch(batch).expect("target invoices committed");
    let single: Vec<_> = targets
        .iter()
        .map(|target| settle(*target, 0, h.usd, 1))
        .collect();
    let interleaved = vec![
        settle(targets[0], 0, h.usd, 1),
        settle(targets[1], 0, h.usd, 1),
        settle(targets[0], 1, h.usd, 1),
        settle(targets[2], 0, h.usd, 1),
        settle(targets[1], 1, h.usd, 1),
    ];
    for (key, settlements, targets_checked, peak) in [
        (b"retention-single".as_slice(), single, 32, 1),
        (b"retention-interleaved".as_slice(), interleaved, 3, 2),
    ] {
        let expected: Vec<_> = settlements
            .iter()
            .map(|s| {
                (
                    s.target.vid,
                    s.ordinal,
                    h.applied_to(s.target.vid, s.ordinal) + 1,
                )
            })
            .collect();
        let proposal = h.receipt(i128::try_from(settlements.len()).unwrap(), settlements, key);
        let prepared = prepare(&mut h, proposal);
        let work = prepared.settlement_work();
        assert_eq!(work.target_entries_checked, targets_checked);
        assert_eq!(work.peak_cached_target_entries, peak);
        assert_eq!(work.target_leg_mirrors_checked, targets_checked * 4);
        assert_eq!(work.reversal_points_checked, targets_checked);
        commit(&mut h, prepared).expect("receipt committed");
        for (target, ordinal, applied) in expected {
            assert_eq!(h.applied_to(target, ordinal), applied);
        }
    }
}

#[test]
fn repeated_applications_fold_a_target_legs_outgoing_settlements_once() {
    for count in [16, 128, 1_024] {
        let mut h = harness();
        let invoice = h
            .post(h.request(invoice(&h, count, b"capacity-invoice"), &["post"]))
            .expect("invoice committed")
            .entry_ref();
        // One credit leg applies one unit to each invoice leg and retains the
        // other half of its amount as an open overpayment. Its own application
        // history must be subtracted once when many later legs settle it.
        let mut credit = LegPayload::simple(
            Side::Credit,
            h.receivable,
            Amount::new(h.usd, i128::from(count) * 2),
        );
        credit.settles = (0..count)
            .map(|ordinal| settle(invoice, ordinal, h.usd, 1))
            .collect();
        let prepaid = h.proposal(
            vec![
                LegPayload::simple(
                    Side::Debit,
                    h.cash,
                    Amount::new(h.usd, i128::from(count) * 2),
                ),
                credit,
            ],
            b"capacity-prepayment",
            EntryClass::ORIGINAL,
        );
        let target = h
            .post(h.request(prepaid, &["post"]))
            .expect("prepayment committed")
            .entry_ref();
        let mut legs = vec![LegPayload::simple(
            Side::Credit,
            h.cash,
            Amount::new(h.usd, i128::from(count)),
        )];
        for _ in 0..count {
            let mut debit = LegPayload::simple(Side::Debit, h.receivable, Amount::new(h.usd, 1));
            debit.settles.push(settle(target, 1, h.usd, 1));
            legs.push(debit);
        }
        let proposal = h.proposal(legs, b"capacity-refund", EntryClass::ORIGINAL);
        let expected = proposal.clone();
        let prepared = prepare(&mut h, proposal);
        let work = prepared.settlement_work();
        assert_eq!(work.target_entries_checked, 1, "count={count}");
        assert_eq!(work.target_leg_mirrors_checked, 3, "count={count}");
        assert_eq!(work.reversal_points_checked, 1, "count={count}");
        assert_eq!(
            work.target_settlement_links_checked,
            usize::from(count),
            "count={count}"
        );
        let posted = commit(&mut h, prepared).expect("refund committed");
        let (recorded, _) = read_entry(&h.db, posted.entry_ref().vid)
            .unwrap()
            .expect("refund retained");
        assert_eq!(recorded.proposal, expected);
        assert_eq!(h.applied_to(target.vid, 1), i128::from(count));
        for ordinal in 0..count {
            assert_eq!(h.applied_to(invoice.vid, ordinal), 1, "ordinal={ordinal}");
        }
        let mut extra = LegPayload::simple(Side::Debit, h.receivable, Amount::new(h.usd, 1));
        extra.settles.push(settle(target, 1, h.usd, 1));
        let proposal = h.proposal(
            vec![
                LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 1)),
                extra,
            ],
            b"capacity-exhausted",
            EntryClass::ORIGINAL,
        );
        let refusal = h.post(h.request(proposal, &["post"])).unwrap_err();
        assert_eq!(refusal.code, "FA-REF-072", "{refusal}");
        assert_eq!(h.db.frontier().unwrap(), posted.recorded_at());
        assert_eq!(h.applied_to(target.vid, 1), i128::from(count));
    }
}

#[test]
fn a_cached_target_still_checks_every_handle_and_each_leg_capacity() {
    let mut h = harness();
    let target = h
        .post(h.request(invoice(&h, 4, b"shared-target"), &["post"]))
        .unwrap()
        .entry_ref();
    let before = h.db.frontier().unwrap();
    let mut wrong_handle = receipt(&h, target, 4, 40, b"shared-bad-handle");
    wrong_handle.legs[2].settles[0].target.entry_digest[0] ^= 1;
    let refusal = h.post(h.request(wrong_handle, &["post"])).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-070");
    assert!(refusal.message.contains("leg 2"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), before);

    // Each application is individually within the target's amount, but three
    // applications to its first leg jointly exceed it. Memoizing the target
    // must never memoize its growing in-transaction applied delta.
    let mut overdraw = receipt(&h, target, 4, 40, b"shared-overdraw");
    for leg in &mut overdraw.legs[1..] {
        leg.settles[0].ordinal = 0;
    }
    let refusal = h.post(h.request(overdraw, &["post"])).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-072", "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), before);
    for ordinal in 0..4 {
        assert_eq!(h.applied_to(target.vid, ordinal), 0);
    }
}

#[test]
fn cached_settlement_lineage_keeps_the_absent_successor_conflict_witness() {
    let mut h = harness();
    let target = h
        .post(h.request(invoice(&h, 8, b"lineage-target"), &["post"]))
        .unwrap()
        .entry_ref();
    let proposal = receipt(&h, target, 8, 40, b"lineage-receipt");
    let prepared = prepare(&mut h, proposal);
    assert_eq!(prepared.settlement_work().target_entries_checked, 1);
    assert_eq!(prepared.settlement_work().reversal_points_checked, 1);
    let reversal = h.reversal_of_entry(target, b"lineage-race-reversal");
    h.post(h.request(reversal, &["post"]))
        .expect("reversal wins");
    let after_reversal = h.db.frontier().unwrap();
    let refusal = commit(&mut h, prepared).expect_err("cached lineage still conflicts");
    assert_eq!(refusal.exit, exit::CONFLICT, "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), after_reversal);
    for ordinal in 0..8 {
        assert_eq!(h.applied_to(target.vid, ordinal), 0);
    }
}

#[test]
fn settlement_target_reuse_stays_inside_one_ordered_batch_member() {
    let mut h = harness();
    let invoice = invoice(&h, 32, b"batch-shared-target");
    let target = h.member_ref(&invoice);
    let first = receipt(&h, target, 32, 40, b"batch-shared-first");
    let second = receipt(&h, target, 32, 60, b"batch-shared-second");
    let before = h.db.frontier().unwrap();
    let batch = h.batch(b"batch-shared", vec![invoice, first, second]);
    let posted = h
        .post_batch(batch)
        .expect("later members see earlier applications");
    assert_eq!(posted.recorded_at.0, before.0 + 1);
    for ordinal in 0..32 {
        assert_eq!(h.applied_to(target.vid, ordinal), 100);
    }
    let refusal = h
        .post(h.request(receipt(&h, target, 32, 1, b"batch-shared-full"), &["post"]))
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-072", "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), posted.recorded_at);
}
