//! Native atomic intercompany pairs on the actual posting transaction.
use super::*;

fn entities() -> Vec<LegalEntitySpec> {
    ["A", "B"]
        .into_iter()
        .map(|code| LegalEntitySpec {
            code: code.into(),
            name: code.into(),
            functional_unit: UnitId(0),
        })
        .collect()
}

fn paired(h: &Harness, key: &[u8], pair_key: &str) -> EntryPayload {
    let mut legs = vec![
        LegPayload::simple(Side::Debit, h.receivable, Amount::new(h.usd, 100)),
        LegPayload::simple(Side::Credit, h.revenue, Amount::new(h.usd, 100)),
        LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, 100)),
        LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 100)),
    ];
    for (leg, entity) in legs.iter_mut().zip(["A", "A", "B", "B"]) {
        leg.dimension_set = vec![(
            fa_model::LEGAL_ENTITY_DIMENSION,
            fa_model::entity_value_vid(h.book.book_id, entity),
        )];
    }
    let mut proposal = h.proposal(legs, key, EntryClass::ORIGINAL);
    proposal
        .set_intercompany_pairs(&fa_model::IntercompanyPairs {
            pairs: vec![fa_model::IntercompanyPair {
                pair_key: pair_key.into(),
                left_leg: 1,
                right_leg: 2,
            }],
        })
        .unwrap();
    proposal
}

fn pairs(h: &Harness) -> Vec<fgdb_types::EId> {
    h.db.edges_at(h.db.frontier().unwrap())
        .unwrap()
        .iter()
        .filter(|edge| edge.entry.relation == relation::INTERCOMPANY_WITH)
        .map(|edge| edge.entry.eid)
        .collect()
}

fn reverse_pair(h: &Harness, target: EntryRef, key: &[u8]) -> EntryPayload {
    let (entry, _) = read_entry(&h.db, target.vid).unwrap().unwrap();
    let mut legs = entry.proposal.legs.clone();
    for leg in &mut legs {
        leg.side = leg.side.flipped();
        leg.settles.clear();
    }
    let mut reversal = h.proposal(legs, key, EntryClass::REVERSAL);
    reversal.supersession = vec![Supersession {
        target,
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    }];
    reversal
        .set_intercompany_pairs(&entry.proposal.intercompany_pairs().unwrap().unwrap())
        .unwrap();
    reversal
}

#[test]
fn atomic_pair_posts_once_and_binds_key_and_members_before_approval() {
    let mut h = harness_with_entities(entities());
    let proposal = paired(&h, b"sale", "sale-A-B");
    let digest = proposal.proposal_digest().unwrap();
    let mut changed = proposal.clone();
    let mut declaration = changed.intercompany_pairs().unwrap().unwrap();
    declaration.pairs[0].pair_key = "different-sale".into();
    changed.set_intercompany_pairs(&declaration).unwrap();
    assert_ne!(changed.proposal_digest().unwrap(), digest);
    assert_ne!(
        changed.semantic_digest(&h.book.seal_key).unwrap(),
        proposal.semantic_digest(&h.book.seal_key).unwrap()
    );
    declaration.pairs[0].left_leg = 0;
    declaration.pairs[0].right_leg = 3;
    changed.set_intercompany_pairs(&declaration).unwrap();
    assert_ne!(changed.proposal_digest().unwrap(), digest);

    let before = h.db.frontier().unwrap();
    let posted = h.post(h.request(proposal.clone(), &["post"])).unwrap();
    assert_eq!(posted.recorded_at().0, before.0 + 1);
    let ids = pairs(&h);
    assert_eq!(ids.len(), 1);
    let edge = h.db.edge(ids[0]).unwrap().unwrap();
    assert_eq!(edge.entry.created_at, posted.recorded_at());
    assert_eq!(edge.entry.src, leg_vid(posted.entry_ref().vid, 1));
    assert_eq!(edge.entry.dst, leg_vid(posted.entry_ref().vid, 2));
    assert_eq!(
        edge.props,
        vec![(property::CODE, CanonicalScalar::ucs_basic_text("sale-A-B").unwrap())]
    );
    let report = verify_projections(&h.db, &h.book, None).unwrap();
    assert!(report.is_green(), "{report:?}");
    assert!(matches!(
        h.post(h.request(proposal, &["post"])).unwrap(),
        Posted::AlreadyRecorded { .. }
    ));
    assert_eq!(h.db.frontier().unwrap(), posted.recorded_at());
    assert_eq!(pairs(&h), ids);
    assert_eq!(
        h.post(h.request(changed, &["post"])).unwrap_err().exit,
        exit::CONFLICT
    );
    let reused = paired(&h, b"new-entry-key", "sale-A-B");
    let refusal = h.post(h.request(reused, &["post"])).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), posted.recorded_at());
}

#[test]
fn mismatched_pairs_and_cross_entity_netting_refuse_without_any_write() {
    let mut h = harness_with_entities(entities());
    let base = paired(&h, b"bad-pair", "sale-A-B");
    let frontier = h.db.frontier().unwrap();
    for plant in 0..5 {
        let mut proposal = base.clone();
        match plant {
            // Each entity still balances; only the declared pair differs.
            0 => {
                proposal.legs[2].amount.mantissa = 200;
                proposal.legs[3].amount.mantissa = 200;
            }
            1 => {
                for leg in &mut proposal.legs {
                    leg.dimension_set[0].1 = fa_model::entity_value_vid(h.book.book_id, "A");
                }
            }
            // Global totals still balance, but entities may not net each other.
            2 => {
                proposal.legs[0].dimension_set[0].1 =
                    fa_model::entity_value_vid(h.book.book_id, "B");
                proposal.legs[3].dimension_set[0].1 =
                    fa_model::entity_value_vid(h.book.book_id, "A");
            }
            3 => {
                proposal
                    .set_intercompany_pairs(&fa_model::IntercompanyPairs {
                        pairs: vec![fa_model::IntercompanyPair {
                            pair_key: "same-side".into(),
                            left_leg: 0,
                            right_leg: 2,
                        }],
                    })
                    .unwrap();
            }
            _ => {
                let eur = h.book.units.lookup("EUR").unwrap();
                for leg in &mut proposal.legs {
                    leg.amount.unit = eur;
                }
            }
        }
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        let refusal = h.post(h.request(proposal, &["post"])).unwrap_err();
        assert_eq!(refusal.exit, exit::REFUSAL, "plant {plant}: {refusal}");
        if plant == 2 {
            assert_eq!(refusal.code, "FA-REF-001", "{refusal}");
        }
        if plant == 4 {
            assert_eq!(refusal.code, "FA-REF-102", "{refusal}");
        }
        assert_eq!(h.db.frontier().unwrap(), frontier, "plant {plant}");
        assert!(pairs(&h).is_empty());
    }
    // Refusal did not consume either the post key or the pair key.
    h.post(h.request(base, &["post"])).unwrap();
}

#[test]
fn approvals_bind_intercompany_keys_and_reciprocal_member_selection() {
    let mut h = harness_with_entities(entities());
    let march = h.march.clone();
    h.transition(&march, PeriodTransition::Close, b"close-for-pair")
        .unwrap();
    let mut proposal = paired(&h, b"approved-pair", "approved-sale");
    proposal.class = EntryClass::ADJUSTING;
    let approval = h.approve_transition(proposal.proposal_digest().unwrap());
    let before = h.db.frontier().unwrap();
    for change_key in [true, false] {
        let mut changed = proposal.clone();
        let mut declaration = changed.intercompany_pairs().unwrap().unwrap();
        if change_key {
            declaration.pairs[0].pair_key = "unapproved-sale".into();
        } else {
            declaration.pairs[0].left_leg = 0;
            declaration.pairs[0].right_leg = 3;
        }
        changed.set_intercompany_pairs(&declaration).unwrap();
        let mut request = h.request(changed, &["post", "post_closed"]);
        request.approvals = vec![approval];
        let refusal = h.post(request).unwrap_err();
        assert_eq!(refusal.code, "FA-REF-012", "{refusal}");
        assert_eq!(h.db.frontier().unwrap(), before);
    }
    let mut request = h.request(proposal, &["post", "post_closed"]);
    request.approvals = vec![approval];
    h.post(request).unwrap();
}

#[test]
fn reversals_preserve_pairs_without_releasing_keys_and_projection_tamper_is_visible() {
    let mut h = harness_with_entities(entities());
    let original = h
        .post(h.request(paired(&h, b"original", "pair-for-life"), &["post"]))
        .unwrap();
    let original_edge = pairs(&h)[0];
    let mut tip = original.entry_ref();
    for index in 0..3 {
        let proposal = reverse_pair(&h, tip, format!("reverse-{index}").as_bytes());
        for plant in 0..3 {
            let mut altered = proposal.clone();
            if plant == 0 {
                altered
                    .extensions
                    .retain(|(tag, _)| *tag != fa_model::entry::INTERCOMPANY_PAIRS_EXTENSION);
            } else {
                let mut terms = altered.intercompany_pairs().unwrap().unwrap();
                if plant == 1 {
                    terms.pairs[0].pair_key = "reversal-cannot-rebind-key".into();
                } else {
                    terms.pairs[0].left_leg = 0;
                    terms.pairs[0].right_leg = 3;
                }
                altered.set_intercompany_pairs(&terms).unwrap();
            }
            let before = h.db.frontier().unwrap();
            let refusal = h.post(h.request(altered, &["post"])).unwrap_err();
            assert_eq!(refusal.code, "FA-REF-051", "{refusal}");
            assert_eq!(h.db.frontier().unwrap(), before);
        }
        tip = h.post(h.request(proposal, &["post"])).unwrap().entry_ref();
        assert!(h.db.edge(original_edge).unwrap().is_some());
        assert_eq!(pairs(&h).len(), index + 2);
        let refusal = h
            .post(h.request(paired(&h, b"another", "pair-for-life"), &["post"]))
            .unwrap_err();
        assert_eq!(refusal.exit, exit::CONFLICT);
        let report = verify_projections(&h.db, &h.book, None).unwrap();
        assert!(report.is_green(), "{report:?}");
    }
    let intact = h.db.frontier().unwrap();
    let mut corrupt = fgdb::WriteBatch::new(relation::INTERCOMPANY_WITH);
    corrupt.delete_edge(original_edge);
    h.write_raw(corrupt);
    let report = verify_projections(&h.db, &h.book, None).unwrap();
    assert!(!report.is_green());
    assert!(report.drift.iter().any(|row| row.contains("missing INTERCOMPANY_WITH")));
    assert!(
        verify_projections(&h.db, &h.book, Some(intact))
            .unwrap()
            .is_green()
    );
}

#[test]
fn duplicate_pair_in_atomic_batch_rolls_back_all_members_and_claims() {
    for reverse_order in [false, true] {
        let mut h = harness_with_entities(entities());
        let first = paired(&h, b"batch-first", "same-pair");
        let second = paired(&h, b"batch-second", "same-pair");
        let before = h.db.frontier().unwrap();
        let mut members = vec![first.clone(), second];
        if reverse_order {
            members.reverse();
        }
        let batch = h.batch(b"two-claims", members);
        let refusal = h.post_batch(batch).unwrap_err();
        assert_eq!(refusal.exit, exit::CONFLICT, "{refusal}");
        assert_eq!(h.db.frontier().unwrap(), before);
        assert!(pairs(&h).is_empty());
        let vid = h.member_ref(&first).vid;
        assert!(read_entry(&h.db, vid).unwrap().is_none());
        for ordinal in 0..4 {
            assert!(h.db.vertex(leg_vid(vid, ordinal)).unwrap().is_none());
        }
        let second = paired(&h, b"batch-second", "different-pair");
        h.post_batch(h.batch(b"two-claims", vec![first, second]))
            .unwrap();
        assert_eq!(pairs(&h).len(), 2);
        assert!(verify_projections(&h.db, &h.book, None).unwrap().is_green());
    }
}

#[test]
fn competing_pair_claims_have_one_winner_in_both_commit_orders() {
    for reverse_order in [false, true] {
        let mut h = harness_with_entities(entities());
        let mut prepare = |key: &[u8]| {
            let proposal = paired(&h, key, "raced-pair");
            let request = h.request(proposal, &["post"]);
            let ctx = h.ctx();
            match prepare_post(&mut h.db, &ctx, &h.book, request).unwrap().unwrap() {
                PostPreparation::Ready(prepared) => prepared,
                PostPreparation::AlreadyRecorded(_) => panic!("distinct entry must be fresh"),
            }
        };
        let first = prepare(b"race-a");
        let second = prepare(b"race-b");
        let (winner, loser) = if reverse_order { (second, first) } else { (first, second) };
        let ctx = h.ctx();
        let posted = h
            .runtime
            .block_on(winner.commit(&mut h.db, &ctx))
            .unwrap()
            .unwrap();
        let refusal = h
            .runtime
            .block_on(loser.commit(&mut h.db, &ctx))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, exit::CONFLICT, "{refusal}");
        assert_eq!(h.db.frontier().unwrap(), posted.recorded_at());
        assert_eq!(pairs(&h).len(), 1);
        assert!(verify_projections(&h.db, &h.book, None).unwrap().is_green());
    }
}

#[test]
fn scoped_fresh_claims_refuse_before_global_key_lookup_but_exact_retries_work() {
    let mut h = harness_with_entities(entities());
    let original = paired(&h, b"namespace-owner", "claimed-key");
    h.post(h.request(original.clone(), &["post"])).unwrap();
    let before = h.db.frontier().unwrap();
    let before_pairs = pairs(&h);
    for (key, pair_key) in [
        (b"scoped-new".as_slice(), "unused-key"),
        (b"scoped-taken".as_slice(), "claimed-key"),
    ] {
        let proposal = paired(&h, key, pair_key);
        let mut request = h.request(proposal, &["post"]);
        request.capability = request
            .capability
            .for_periods(&[h.march.as_str()])
            .unwrap();
        let refusal = h.post(request).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-011", exit::SAFETY));
        assert!(refusal.message.contains("unscoped capability"), "{refusal}");
        assert_eq!(h.db.frontier().unwrap(), before);
        assert_eq!(pairs(&h), before_pairs);
    }
    let mut retry = h.request(original, &["post"]);
    retry.capability = retry.capability.for_periods(&[h.march.as_str()]).unwrap();
    assert!(matches!(h.post(retry).unwrap(), Posted::AlreadyRecorded { .. }));
    assert_eq!(h.db.frontier().unwrap(), before);
}
