//! The scoped key is shared by successful posting families, independently
//! of the target-derived Entry identity. Refusals must leave the whole native
//! publication untouched, including the earlier member of a correction pair.

use super::*;

/// The original dedicated control writer, before common outcome claims.
/// Preserve its original bytes and projections rather than deleting a claim
/// from a modern publication to manufacture a legacy fixture.
pub(super) fn write_legacy_transition(
    h: &mut Harness,
    code: &str,
    transition: PeriodTransition,
    key: &[u8],
) -> VId {
    let period = fa_journal::policy::calendar_period(&h.book, code).unwrap();
    let pvid = period_vid(&h.book.calendar.id, code);
    let from = PeriodRow::decode(&h.db.vertex(pvid).unwrap().unwrap())
        .unwrap()
        .state;
    let to = fa_time::period::transition(from, transition).unwrap();
    let proposal = transition_proposal(
        &h.book,
        &period,
        from,
        to,
        PRINCIPAL,
        1,
        key,
        Erasable::seal(
            &"period".to_string(),
            None,
            &h.book.seal_key,
            [3; 32],
            [4; 24],
        ),
    );
    let entry = proposal.seal(Vec::new(), None).unwrap();
    let vid = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key);
    let mut batch = fgdb::WriteBatch::new(relation::IN_PERIOD);
    batch.create_vertex(
        vid,
        vec![fa_model::symbols::label::ENTRY],
        fa_model::entry_mirrors(&entry).unwrap(),
    );
    batch.compare_and_set_vertex_property(
        pvid,
        property::STATE,
        Some(CanonicalScalar::Int(i64::from(from.tag()))),
        CanonicalScalar::Int(i64::from(to.tag())),
        fgdb::WriteMismatchPolicy::AbortWrite,
    );
    batch.add_edge(edge_id(relation::IN_PERIOD, vid, pvid), vid, pvid, vec![]);
    let cx = h.ctx();
    let mut txn = h.db.begin(&cx.txn()).unwrap();
    txn.write_ordered(&mut h.db, vec![batch]).unwrap();
    h.runtime
        .block_on(txn.commit(&mut h.db, &cx.commit()))
        .unwrap();
    vid
}

fn outcome_id(h: &Harness, proposal: &EntryPayload) -> VId {
    fa_model::intent_outcome_vid(
        h.book.book_id,
        &proposal.principal_ref.0.to_le_bytes(),
        &proposal.idempotency_key,
    )
}

fn assert_claim(h: &Harness, proposal: &EntryPayload, posted: &Posted) {
    let entry = h.db.vertex(posted.entry_ref().vid).unwrap().unwrap();
    let claim = h.db.vertex(outcome_id(h, proposal)).unwrap().unwrap();
    assert_eq!(
        claim.labels.as_slice(),
        [fa_model::symbols::label::INTENT_OUTCOME]
    );
    assert_eq!(
        claim.created_at, entry.created_at,
        "the key and entry publish together"
    );
    assert_eq!(
        fa_journal::rows::prop(&claim, property::TARGET_REF),
        Some(&CanonicalScalar::bytes(posted.entry_ref().vid.0.to_le_bytes().to_vec()).unwrap())
    );
}

fn refused_without_publication(h: &mut Harness, proposal: EntryPayload) {
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refusal = h.post(h.request(proposal, &["post"])).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(
        h.db.vertices().unwrap(),
        vertices,
        "no partial key or accounting state"
    );
}

#[test]
fn each_posting_family_retains_an_atomic_claim_and_exact_retries_consume_no_sequence() {
    let mut h = harness();
    let original = h.proposal(h.rent_legs(100), b"claim-original", EntryClass::ORIGINAL);
    let posted = h.post(h.request(original.clone(), &["post"])).unwrap();
    assert_claim(&h, &original, &posted);
    let reversal = h.reversal_of_entry(posted.entry_ref(), b"claim-reversal");
    let reversed = h.post(h.request(reversal.clone(), &["post"])).unwrap();
    assert_claim(&h, &reversal, &reversed);
    let pending = h.pending(h.rent_legs(200), b"claim-pending");
    let held = h.post(h.request(pending.clone(), &["post"])).unwrap();
    assert_claim(&h, &pending, &held);
    let resolution = h.resolution_posts(
        held.entry_ref(),
        h.rent_legs(150),
        vec![0, 1],
        b"claim-resolution",
    );
    let resolved = h.post(h.request(resolution.clone(), &["post"])).unwrap();
    assert_claim(&h, &resolution, &resolved);
    let head = h.db.frontier().unwrap();
    for (proposal, first) in [
        (original, posted),
        (reversal, reversed),
        (pending, held),
        (resolution, resolved),
    ] {
        let retry = h.post(h.request(proposal, &["post"])).unwrap();
        assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
        assert_eq!(retry.entry_ref(), first.entry_ref());
        assert_eq!(h.db.frontier().unwrap(), head);
    }
}

#[test]
fn an_ordinary_key_blocks_reversal_resolution_and_batch_but_not_another_principal() {
    let mut h = harness();
    let occupied = h.proposal(h.rent_legs(100), b"shared-key", EntryClass::ORIGINAL);
    let target = h
        .post(h.request(occupied.clone(), &["post"]))
        .unwrap()
        .entry_ref();
    let pending = h.pending(h.rent_legs(200), b"unresolved-hold");
    let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();

    let reversal = h.reversal_of_entry(target, b"shared-key");
    refused_without_publication(&mut h, reversal);
    let resolution = h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], b"shared-key");
    refused_without_publication(&mut h, resolution);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    assert!(h.db.vertex(resolution_vid(hold.vid)).unwrap().is_none());

    let member = h.proposal(
        h.rent_legs(300),
        b"uncommitted-member",
        EntryClass::ORIGINAL,
    );
    let member_vid = h.member_ref(&member).vid;
    let batch = h.batch(b"shared-key", vec![member]);
    let before = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refusal = h.post_batch(batch).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert!(h.db.vertex(member_vid).unwrap().is_none());

    let mut independent = occupied;
    independent.principal_ref = VId(99);
    let other = h.post(h.request(independent.clone(), &["post"])).unwrap();
    assert_ne!(other.entry_ref().vid, target.vid);
    assert_claim(&h, &independent, &other);
}

#[test]
fn target_derived_reversal_and_resolution_keys_cannot_be_reused_as_ordinary_keys() {
    let mut h = harness();
    let original = h.proposal(h.rent_legs(100), b"reverse-source", EntryClass::ORIGINAL);
    let target = h.post(h.request(original, &["post"])).unwrap().entry_ref();
    let reversal = h.reversal_of_entry(target, b"reversal-owned-key");
    h.post(h.request(reversal, &["post"])).unwrap();
    let pending = h.pending(h.rent_legs(200), b"resolution-source");
    let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
    let resolution =
        h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], b"resolution-owned-key");
    h.post(h.request(resolution, &["post"])).unwrap();

    for key in [
        b"reversal-owned-key".as_slice(),
        b"resolution-owned-key".as_slice(),
    ] {
        let ordinary = h.proposal(h.rent_legs(100), key, EntryClass::ORIGINAL);
        refused_without_publication(&mut h, ordinary);
        assert!(
            h.db.vertex(entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key))
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn batch_and_member_keys_share_the_namespace_and_an_inner_outer_collision_is_atomic() {
    let mut h = harness();
    let member = h.proposal(h.rent_legs(100), b"member-owned-key", EntryClass::ORIGINAL);
    let batch = h.batch(b"batch-owned-key", vec![member.clone()]);
    let committed = h.post_batch(batch.clone()).unwrap();
    let head = h.db.frontier().unwrap();
    let retry = h.post_batch(batch).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, committed.entries);
    assert_eq!(h.db.frontier().unwrap(), head);
    let ordinary = h.proposal(h.rent_legs(300), b"batch-owned-key", EntryClass::ORIGINAL);
    refused_without_publication(&mut h, ordinary);

    for (batch_key, member_key) in [
        (b"member-owned-key".as_slice(), b"new-member".as_slice()),
        (
            b"same-inner-outer-key".as_slice(),
            b"same-inner-outer-key".as_slice(),
        ),
    ] {
        let next = h.proposal(h.rent_legs(200), member_key, EntryClass::ORIGINAL);
        let next_vid = h.member_ref(&next).vid;
        let attempt = h.batch(batch_key, vec![next]);
        let vertices = h.db.vertices().unwrap();
        let refusal = h.post_batch(attempt).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
        assert!(h.db.vertex(next_vid).unwrap().is_none());
    }
    let again = h.post(h.request(member, &["post"])).unwrap();
    assert!(matches!(again, Posted::AlreadyRecorded { .. }));
    assert_eq!(again.entry_ref(), committed.entries[0]);
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn replacement_pair_key_collisions_publish_neither_member_and_a_valid_pair_still_commits() {
    let mut h = harness();
    let original = h.proposal(h.rent_legs(100), b"pair-key-source", EntryClass::ORIGINAL);
    let target = h.post(h.request(original, &["post"])).unwrap().entry_ref();
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    for replacement_key in [b"pair-shared".as_slice(), b"pair-key-source".as_slice()] {
        let reversal = h.request(h.reversal_of_entry(target, b"pair-shared"), &["post"]);
        let replacement = h.request(
            replacement_proposal(
                target,
                h.proposal(h.rent_legs(125), replacement_key, EntryClass::REPLACEMENT),
            ),
            &["post"],
        );
        let refusal = h.post_pair(reversal, replacement).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
        assert!(
            h.db.vertex(fa_journal::rows::replacement_vid(target.vid))
                .unwrap()
                .is_none()
        );
    }
    let reversal = h.reversal_of_entry(target, b"pair-valid-reversal");
    let replacement = replacement_proposal(
        target,
        h.proposal(
            h.rent_legs(125),
            b"pair-valid-replacement",
            EntryClass::REPLACEMENT,
        ),
    );
    let (first, second) = h
        .post_pair(
            h.request(reversal.clone(), &["post"]),
            h.request(replacement.clone(), &["post"]),
        )
        .unwrap();
    assert_eq!(h.db.frontier().unwrap().0, head.0 + 1);
    assert_claim(&h, &reversal, &first);
    assert_claim(&h, &replacement, &second);
}

#[test]
fn recorded_key_binds_ordered_approvals_without_changing_fresh_seal_retry_semantics() {
    let mut h = harness();
    let proposal = h.proposal(h.rent_legs(100), b"approved-key", EntryClass::ORIGINAL);
    let approval = h.approve_transition(proposal.proposal_digest().unwrap());
    let ctx = h.ctx();
    let second_approval = h
        .runtime
        .block_on(record_approval(
            &mut h.db,
            &ctx,
            &h.book,
            ApprovalRequest {
                capability: Capability::embedded(VId(71), &["approve"]).unwrap(),
                approved_proposal_digest: proposal.proposal_digest().unwrap(),
                role: 0,
            },
        ))
        .unwrap()
        .unwrap()
        .approval();
    let mut request = h.request(proposal.clone(), &["post"]);
    request.approvals.push(approval);
    request.approvals.push(second_approval);
    let posted = h.post(request.clone()).unwrap();
    assert_claim(&h, &proposal, &posted);
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let mut stripped = request.clone();
    stripped.approvals.clear();
    let refusal = h.post(stripped).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);

    let mut reordered = request.clone();
    reordered.approvals.reverse();
    let refusal = h.post(reordered).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);

    request.proposal.description = Erasable::seal(
        &"March rent".to_string(),
        None,
        &h.book.seal_key,
        [90; 32],
        [91; 24],
    );
    assert_ne!(
        request.proposal.proposal_digest().unwrap(),
        proposal.proposal_digest().unwrap()
    );
    let retry = h.post(request).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn period_transitions_cannot_reuse_target_derived_or_outer_batch_keys() {
    let mut h = harness();
    let source = h.proposal(
        h.rent_legs(100),
        b"period-reversal-source",
        EntryClass::ORIGINAL,
    );
    let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
    let reversal = h.reversal_of_entry(target, b"period-reversal-key");
    h.post(h.request(reversal, &["post"])).unwrap();
    let pending = h.pending(h.rent_legs(200), b"period-resolution-source");
    let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
    let resolution =
        h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], b"period-resolution-key");
    h.post(h.request(resolution, &["post"])).unwrap();
    let member = h.proposal(
        h.rent_legs(300),
        b"period-batch-member",
        EntryClass::ORIGINAL,
    );
    h.post_batch(h.batch(b"period-batch-key", vec![member]))
        .unwrap();

    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let april = h.april.clone();
    for key in [
        b"period-reversal-key".as_slice(),
        b"period-resolution-key".as_slice(),
        b"period-batch-key".as_slice(),
    ] {
        let refused = h
            .transition(&april, PeriodTransition::Open, key)
            .unwrap_err();
        assert_eq!((refused.code, refused.exit), ("FA-REF-032", exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(
            h.db.vertices().unwrap(),
            vertices,
            "the period and prior outcome are unchanged"
        );
    }

    let opened = h
        .transition(&april, PeriodTransition::Open, b"period-fresh-key")
        .unwrap();
    let row = h.db.vertex(opened.control_entry).unwrap().unwrap();
    let entry = read_entry(&h.db, opened.control_entry).unwrap().unwrap().0;
    let claim =
        h.db.vertex(outcome_id(&h, &entry.proposal))
            .unwrap()
            .unwrap();
    assert_eq!(claim.created_at, row.created_at);
    let head = h.db.frontier().unwrap();
    let retry = h
        .transition(&april, PeriodTransition::Open, b"period-fresh-key")
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.control_entry, opened.control_entry);
    assert_eq!(retry.recorded_at, opened.recorded_at);
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn a_period_control_key_blocks_postings_target_effects_and_batches() {
    let mut h = harness();
    let april = h.april.clone();
    h.transition(&april, PeriodTransition::Open, b"control-owned-key")
        .unwrap();
    let source = h.proposal(
        h.rent_legs(100),
        b"control-reversal-source",
        EntryClass::ORIGINAL,
    );
    let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
    let pending = h.pending(h.rent_legs(200), b"control-resolution-source");
    let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
    let original = h.proposal(h.rent_legs(300), b"control-owned-key", EntryClass::ORIGINAL);
    let reversal = h.reversal_of_entry(target, b"control-owned-key");
    let resolution = h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], b"control-owned-key");
    for proposal in [original, reversal, resolution] {
        refused_without_publication(&mut h, proposal);
    }
    let member = h.proposal(
        h.rent_legs(300),
        b"control-new-batch-member",
        EntryClass::ORIGINAL,
    );
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refused = h
        .post_batch(h.batch(b"control-owned-key", vec![member]))
        .unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}

#[test]
fn prepared_period_and_reversal_key_races_publish_one_outcome_in_both_orders() {
    for period_first in [false, true] {
        let mut h = harness();
        let source = h.proposal(
            h.rent_legs(100),
            b"period-race-source",
            EntryClass::ORIGINAL,
        );
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let key = b"period-race-key";
        let reversal = h.reversal_of_entry(target, key);
        let request = h.request(reversal, &["post"]);
        let cx = h.ctx();
        let PostPreparation::Ready(post) = prepare_post(&mut h.db, &cx, &h.book, request)
            .unwrap()
            .unwrap()
        else {
            panic!("fresh reversal must be prepared")
        };
        let period = fa_journal::period::prepare_transition(
            &mut h.db,
            &cx,
            &h.book,
            &h.april,
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            key,
            Erasable::seal(
                &"period".to_string(),
                None,
                &h.book.seal_key,
                [3; 32],
                [4; 24],
            ),
            &Capability::embedded(PRINCIPAL, &["close", "post"]).unwrap(),
            &[],
        )
        .unwrap()
        .unwrap();
        let basis = h.db.frontier().unwrap();
        assert_eq!(post.basis(), basis);
        assert_eq!(period.basis(), basis);
        if period_first {
            h.runtime
                .block_on(period.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap();
            let winner = h.db.vertices().unwrap();
            let refused = h
                .runtime
                .block_on(post.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap_err();
            assert_eq!(refused.exit, exit::CONFLICT);
            assert_eq!(h.db.vertices().unwrap(), winner);
            assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
        } else {
            h.runtime
                .block_on(post.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap();
            let winner = h.db.vertices().unwrap();
            let refused = h
                .runtime
                .block_on(period.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap_err();
            assert_eq!(refused.exit, exit::CONFLICT);
            assert_eq!(h.db.vertices().unwrap(), winner);
            assert_eq!(
                PeriodRow::decode(&h.db.vertex(period_vid("cal", &h.april)).unwrap().unwrap())
                    .unwrap()
                    .state,
                PeriodState::Future,
            );
        }
        assert_eq!(h.db.frontier().unwrap().0, basis.0 + 1);
    }
}

#[test]
fn legacy_period_retries_remain_readable_but_fresh_controls_require_key_recovery() {
    let mut h = harness_legacy();
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let march = h.march.clone();
    let retry = h
        .transition(&march, PeriodTransition::Open, b"open-march")
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    let april = h.april.clone();
    let refused = h
        .transition(&april, PeriodTransition::Open, b"legacy-new-control")
        .unwrap_err();
    assert_eq!(refused.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert!(refused.fix.contains("fa recover outcomes"));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}

#[test]
fn period_control_claims_survive_accounting_replay_with_compressed_sequences() {
    let mut h = harness();
    let cx = h.ctx();
    let mut maintenance = fgdb::WriteBatch::new(relation::IN_BOOK);
    maintenance.create_vertex(
        VId(0xfeed_1278),
        vec![fa_model::symbols::label::REGISTER],
        Vec::new(),
    );
    h.runtime
        .block_on(h.db.write(&cx.commit(), maintenance))
        .unwrap();
    let april = h.april.clone();
    let key = b"replayed-period-key";
    let opened = h.transition(&april, PeriodTransition::Open, key).unwrap();
    let source_head = h.db.frontier().unwrap();
    let entry = read_entry(&h.db, opened.control_entry).unwrap().unwrap().0;
    let claim_vid = outcome_id(&h, &entry.proposal);
    let claim_bytes = h.db.vertex(claim_vid).unwrap().unwrap().props;
    let keys = DatabaseKeys::new([71; 32], DatabaseSecurityNamespaceId([72; 32]), [73; 32]);
    let mut scratch = h
        .runtime
        .block_on(Database::open_memory(&cx.commit(), keys))
        .unwrap();
    let mapping = h
        .runtime
        .block_on(fa_journal::scratch::replay_into(
            &mut h.db,
            &mut scratch,
            &cx,
            &h.book,
            None,
        ))
        .unwrap()
        .unwrap();
    let expected_at = mapping.translate(opened.recorded_at).unwrap();
    assert!(
        expected_at < opened.recorded_at,
        "maintenance consumes no scratch sequence"
    );
    let claim = scratch.vertex(claim_vid).unwrap().unwrap();
    assert_eq!(claim.props, claim_bytes);
    assert_eq!(claim.created_at, expected_at);
    assert_eq!(
        scratch
            .vertex(opened.control_entry)
            .unwrap()
            .unwrap()
            .created_at,
        expected_at
    );
    let scratch_head = scratch.frontier().unwrap();
    let retry = h
        .runtime
        .block_on(transition_period(
            &mut scratch,
            &cx,
            &h.book,
            &april,
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            key,
            Erasable::seal(
                &"period".to_string(),
                None,
                &h.book.seal_key,
                [3; 32],
                [4; 24],
            ),
            &Capability::embedded(PRINCIPAL, &["close", "post"]).unwrap(),
            &[],
        ))
        .unwrap()
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.control_entry, opened.control_entry);
    assert_eq!(retry.recorded_at, expected_at);
    assert_eq!(scratch.frontier().unwrap(), scratch_head);
    assert_eq!(h.db.frontier().unwrap(), source_head);
}

#[test]
fn recovered_legacy_keys_protect_period_controls_after_durable_reopen() {
    let mut h = harness_legacy();
    let original = h.proposal(
        h.rent_legs(100),
        b"legacy-period-source",
        EntryClass::ORIGINAL,
    );
    let target = outcome_recovery_tests::write_legacy(&mut h, original);
    let reversal = h.reversal_of_entry(target, b"legacy-period-occupied");
    outcome_recovery_tests::write_legacy(&mut h, reversal);
    let cx = h.ctx();
    let cap = Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap();
    let prepared = h
        .runtime
        .block_on(prepare_outcome_rebuild(&mut h.db, &cx, &h.book, cap))
        .unwrap()
        .unwrap();
    h.runtime
        .block_on(publish_outcome_rebuild(&mut h.db, &cx, &h.book, prepared))
        .unwrap()
        .unwrap();

    let (vfs, keys) = h.legacy_storage.clone().unwrap();
    let empty = h
        .runtime
        .block_on(Database::open_memory(&cx.commit(), keys.clone()))
        .unwrap();
    drop(std::mem::replace(&mut h.db, empty));
    h.db = h
        .runtime
        .block_on(Database::open_with_vfs(
            &cx.commit(),
            vfs.clone(),
            vfs.database_dir(),
            keys,
        ))
        .unwrap();
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let march = h.march.clone();
    let original_retry = h
        .transition(&march, PeriodTransition::Open, b"open-march")
        .unwrap();
    assert!(original_retry.already_recorded);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    let refused = h
        .transition(
            &march,
            PeriodTransition::SoftClose,
            b"legacy-period-occupied",
        )
        .unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    let closed = h
        .transition(
            &march,
            PeriodTransition::SoftClose,
            b"recovered-fresh-control",
        )
        .unwrap();
    assert!(!closed.already_recorded);
    assert_eq!(closed.from, PeriodState::Open);
    assert_eq!(closed.to, PeriodState::SoftClosed);
    assert_eq!(h.db.frontier().unwrap().0, head.0 + 1);
}

#[test]
fn period_retry_binds_ordered_approvals_and_description_after_the_state_moves() {
    let mut h = harness();
    let april = h.april.clone();
    let key = b"period-approved-key";
    let period = fa_journal::policy::calendar_period(&h.book, &april).unwrap();
    let description = Erasable::seal(
        &"approved period opening".to_string(),
        None,
        &h.book.seal_key,
        [13; 32],
        [14; 24],
    );
    let proposal = transition_proposal(
        &h.book,
        &period,
        PeriodState::Future,
        PeriodState::Open,
        PRINCIPAL,
        1,
        key,
        description.clone(),
    );
    let digest = proposal.proposal_digest().unwrap();
    let first = h.approve_transition(digest);
    let cx = h.ctx();
    let second = h
        .runtime
        .block_on(record_approval(
            &mut h.db,
            &cx,
            &h.book,
            ApprovalRequest {
                capability: Capability::embedded(VId(71), &["approve"]).unwrap(),
                approved_proposal_digest: digest,
                role: 0,
            },
        ))
        .unwrap()
        .unwrap()
        .approval();
    let approvals = vec![first, second];
    let cap = Capability::embedded(PRINCIPAL, &["close", "post"]).unwrap();
    let opened = h
        .runtime
        .block_on(transition_period(
            &mut h.db,
            &cx,
            &h.book,
            &april,
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            key,
            description.clone(),
            &cap,
            &approvals,
        ))
        .unwrap()
        .unwrap();
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    for candidate_approvals in [Vec::new(), vec![second, first]] {
        let refused = h
            .runtime
            .block_on(transition_period(
                &mut h.db,
                &cx,
                &h.book,
                &april,
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                key,
                description.clone(),
                &cap,
                &candidate_approvals,
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!((refused.code, refused.exit), ("FA-REF-032", exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }
    let changed_description = Erasable::seal(
        &"a different request".to_string(),
        None,
        &h.book.seal_key,
        [23; 32],
        [24; 24],
    );
    let refused = h
        .runtime
        .block_on(transition_period(
            &mut h.db,
            &cx,
            &h.book,
            &april,
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            key,
            changed_description,
            &cap,
            &approvals,
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);

    let fresh_seal = Erasable::seal(
        &"approved period opening".to_string(),
        None,
        &h.book.seal_key,
        [33; 32],
        [34; 24],
    );
    let retry = h
        .runtime
        .block_on(transition_period(
            &mut h.db,
            &cx,
            &h.book,
            &april,
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            key,
            fresh_seal,
            &cap,
            &approvals,
        ))
        .unwrap()
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.control_entry, opened.control_entry);
    assert_eq!(retry.recorded_at, opened.recorded_at);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}

#[test]
fn scoped_period_retry_checks_existing_reach_before_claim_or_entry_payloads() {
    let mut h = harness();
    let march = h.march.clone();
    let april = h.april.clone();
    let key = b"scoped-invalid-period-key";
    let evid = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key);
    let outcome = fa_model::intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key);
    // Both payloads are armed negatives: decoding either is an error.
    // Metadata alone places the occupied key outside an April capability.
    let mut planted = fgdb::WriteBatch::new(relation::IN_PERIOD);
    planted.create_vertex(
        evid,
        vec![fa_model::symbols::label::ENTRY],
        vec![
            (
                property::FA_EFFECTIVE_DAY,
                CanonicalScalar::Int(i64::from(h.day().0)),
            ),
            (
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(vec![0xff; 8]).unwrap(),
            ),
        ],
    );
    planted.create_vertex(
        outcome,
        vec![fa_model::symbols::label::INTENT_OUTCOME],
        vec![
            (
                property::TARGET_REF,
                CanonicalScalar::bytes(evid.0.to_le_bytes().to_vec()).unwrap(),
            ),
            (
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(b"FA-ENTRY-OUTCOME\0".to_vec()).unwrap(),
            ),
        ],
    );
    h.write_raw(planted);
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let cx = h.ctx();
    let capability = Capability::embedded(PRINCIPAL, &["close", "post"])
        .unwrap()
        .for_periods(&[april.as_str()])
        .unwrap();
    let description = Erasable::seal(
        &"period".to_string(),
        None,
        &h.book.seal_key,
        [43; 32],
        [44; 24],
    );
    for candidate in [b"open-march".as_slice(), key.as_slice()] {
        let refused = h
            .runtime
            .block_on(transition_period(
                &mut h.db,
                &cx,
                &h.book,
                &april,
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                candidate,
                description.clone(),
                &capability,
                &[],
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!((refused.code, refused.exit), ("FA-REF-032", exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }

    let march_capability = Capability::embedded(PRINCIPAL, &["close", "post"])
        .unwrap()
        .for_periods(&[march.as_str()])
        .unwrap();
    let retry = h
        .runtime
        .block_on(transition_period(
            &mut h.db,
            &cx,
            &h.book,
            &march,
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            b"open-march",
            description.clone(),
            &march_capability,
            &[],
        ))
        .unwrap()
        .unwrap();
    assert!(retry.already_recorded);

    // Prove the malformed claim was actually armed: an unscoped caller
    // reaches its decoder and receives the native corruption error.
    let unscoped = Capability::embedded(PRINCIPAL, &["close", "post"]).unwrap();
    assert!(
        h.runtime
            .block_on(transition_period(
                &mut h.db,
                &cx,
                &h.book,
                &april,
                PeriodTransition::Open,
                PRINCIPAL,
                1,
                key,
                description,
                &unscoped,
                &[],
            ))
            .is_err()
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}

#[test]
fn deleting_a_modern_period_claim_cannot_create_a_legacy_retry() {
    let mut h = harness();
    let april = h.april.clone();
    let key = b"deleted-period-outcome";
    let opened = h.transition(&april, PeriodTransition::Open, key).unwrap();
    let outcome = fa_model::intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key);
    assert!(
        h.db.vertex_at(outcome, opened.recorded_at)
            .unwrap()
            .is_some()
    );
    let mut damage = fgdb::WriteBatch::new(relation::IN_PERIOD);
    damage.delete_vertex(outcome);
    h.write_raw(damage);
    assert!(h.db.vertex(outcome).unwrap().is_none());
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refused = h
        .transition(&april, PeriodTransition::Open, key)
        .unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}

fn hold_authority(h: &mut Harness) -> Oid {
    let order = h.document(INVOICE, HUMAN_UPLOAD, b"PRESERVATION ORDER: outcome keys");
    h.add_document(&order).unwrap();
    order.oid()
}

fn assert_hold_claim(h: &Harness, key: &[u8], control: VId) {
    let outcome = fa_model::intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key);
    let claim = h.db.vertex(outcome).unwrap().expect("atomic key claim");
    let entry = h.db.vertex(control).unwrap().expect("hold control");
    assert_eq!(claim.labels, [fa_model::symbols::label::INTENT_OUTCOME]);
    assert_eq!(claim.created_at, entry.created_at);
    assert_eq!(
        fa_journal::rows::prop(&claim, property::TARGET_REF),
        Some(&CanonicalScalar::bytes(control.0.to_le_bytes().to_vec()).unwrap())
    );
}

#[test]
fn legal_hold_lifecycle_keys_are_atomic_and_retries_keep_the_original_outcome() {
    for whole_book in [false, true] {
        let mut h = harness();
        let authority = hold_authority(&mut h);
        let counsel = Capability::embedded(PRINCIPAL, &["hold"]).unwrap();
        let reach = if whole_book {
            HoldReach::ThroughHead
        } else {
            HoldReach::Subjects(vec![document_vid(&authority)])
        };
        let place_basis = h.db.frontier().unwrap();
        let place_rows = h.db.vertices().unwrap().len();
        let place_edges = h.db.edges_at(place_basis).unwrap().len();
        let placed = h
            .place_reach(&counsel, reach.clone(), authority, b"hold-outcome-place")
            .unwrap();
        assert_eq!(placed.recorded_at.0, place_basis.0 + 1);
        assert_eq!(h.db.vertices().unwrap().len(), place_rows + 3);
        assert_eq!(
            h.db.edges_at(placed.recorded_at).unwrap().len(),
            place_edges + 1
        );
        assert_hold_claim(&h, b"hold-outcome-place", placed.hold);
        let plan = h
            .plan_hold_release(placed.hold, b"hold-outcome-release")
            .unwrap();
        let approval = h
            .approve_digest(RELEASE_APPROVER, plan.proposal_digest(&h.book).unwrap())
            .unwrap();
        let release_basis = h.db.frontier().unwrap();
        let release_rows = h.db.vertices().unwrap().len();
        let released = h.release_hold(&plan, &[approval]).unwrap();
        assert_eq!(released.recorded_at.0, release_basis.0 + 1);
        assert_eq!(h.db.vertices().unwrap().len(), release_rows + 2);
        assert_eq!(
            h.db.edges_at(released.recorded_at).unwrap().len(),
            place_edges + 1
        );
        assert_hold_claim(&h, b"hold-outcome-release", released.release);

        // Lost acknowledgments and later head movement never execute again,
        // change a ThroughHead hold's original scope, or re-open its cells.
        h.post(h.request(
            h.proposal(h.rent_legs(17), b"hold-later-post", EntryClass::ORIGINAL),
            &["post"],
        ))
        .unwrap();
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        assert_eq!(
            h.place_reach(&counsel, reach, authority, b"hold-outcome-place")
                .unwrap(),
            LegalHoldPlaced {
                already_recorded: true,
                ..placed
            }
        );
        let expected = LegalHoldReleased {
            already_recorded: true,
            ..released
        };
        assert_eq!(h.release_hold(&plan, &[approval]).unwrap(), expected);
        let resealed = ReleasePlan {
            description: h.statement("hold release", 63),
            ..plan.clone()
        };
        assert_eq!(h.release_hold(&resealed, &[approval]).unwrap(), expected);
        let refusal = h.release_hold(&plan, &[]).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert!(h.holds_on(document_vid(&authority)).is_empty());
    }
}

#[test]
fn posting_and_batch_keys_cannot_place_or_release_legal_holds() {
    let mut h = harness();
    let authority = hold_authority(&mut h);
    let counsel = Capability::embedded(PRINCIPAL, &["hold"]).unwrap();
    let subject = document_vid(&authority);
    let placed = h
        .place_hold(&counsel, vec![subject], authority, b"hold-collision-source")
        .unwrap();
    let original = h.proposal(h.rent_legs(100), b"hold-post-key", EntryClass::ORIGINAL);
    let target = h.post(h.request(original, &["post"])).unwrap().entry_ref();
    let reversal = h.reversal_of_entry(target, b"hold-reverse-key");
    h.post(h.request(reversal, &["post"])).unwrap();
    let pending = h.pending(h.rent_legs(200), b"hold-pending-key");
    let pending = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
    let resolution = h.resolution_posts(pending, h.rent_legs(150), vec![0, 1], b"hold-resolve-key");
    h.post(h.request(resolution, &["post"])).unwrap();
    let member = h.proposal(h.rent_legs(300), b"hold-batch-member", EntryClass::ORIGINAL);
    h.post_batch(h.batch(b"hold-batch-key", vec![member]))
        .unwrap();
    for key in [
        b"hold-post-key".as_slice(),
        b"hold-reverse-key",
        b"hold-resolve-key",
        b"hold-batch-key",
    ] {
        let plan = h.plan_hold_release(placed.hold, key).unwrap();
        let approval = h
            .approve_digest(RELEASE_APPROVER, plan.proposal_digest(&h.book).unwrap())
            .unwrap();
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let edges = h.db.edges_at(head).unwrap();
        for reach in [HoldReach::Subjects(vec![subject]), HoldReach::ThroughHead] {
            let refusal = h.place_reach(&counsel, reach, authority, key).unwrap_err();
            assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
        }
        let refusal = h.release_hold(&plan, &[approval]).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(h.db.edges_at(head).unwrap(), edges);
        assert_eq!(h.holds_on(subject), vec![placed.hold]);
    }
}

#[test]
fn a_legal_hold_release_key_cannot_release_another_hold_or_post_a_batch() {
    let mut h = harness();
    let authority = hold_authority(&mut h);
    let counsel = Capability::embedded(PRINCIPAL, &["hold"]).unwrap();
    let subject = document_vid(&authority);
    let first = h
        .place_hold(&counsel, vec![subject], authority, b"hold-first")
        .unwrap();
    let second = h
        .place_hold(&counsel, vec![subject], authority, b"hold-second")
        .unwrap();
    let key = b"hold-shared-release";
    let plan = h.plan_hold_release(first.hold, key).unwrap();
    let second_plan = h.plan_hold_release(second.hold, key).unwrap();
    let approval = h
        .approve_digest(RELEASE_APPROVER, plan.proposal_digest(&h.book).unwrap())
        .unwrap();
    let second_approval = h
        .approve_digest(
            RELEASE_APPROVER,
            second_plan.proposal_digest(&h.book).unwrap(),
        )
        .unwrap();
    h.release_hold(&plan, &[approval]).unwrap();
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let refusal = h
        .release_hold(&second_plan, &[second_approval])
        .unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
    assert_eq!(h.holds_on(subject), vec![second.hold]);
    for occupied in [key.as_slice(), b"hold-first", b"hold-second"] {
        let posting = h.proposal(h.rent_legs(10), occupied, EntryClass::ORIGINAL);
        refused_without_publication(&mut h, posting);
        let member = h.proposal(
            h.rent_legs(11),
            b"hold-forbidden-member",
            EntryClass::ORIGINAL,
        );
        let refusal = h.post_batch(h.batch(occupied, vec![member])).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
    }
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
    assert!(
        h.db.vertex(fa_journal::legal_hold::release_vid(
            h.book.book_id,
            second.hold
        ))
        .unwrap()
        .is_none()
    );
}

#[test]
fn legal_hold_retries_reject_missing_or_republished_claims_and_controls() {
    for release in [false, true] {
        for attack in 0..4 {
            let mut h = harness();
            let authority = hold_authority(&mut h);
            let counsel = Capability::embedded(PRINCIPAL, &["hold"]).unwrap();
            let placed = h
                .place_hold(
                    &counsel,
                    vec![document_vid(&authority)],
                    authority,
                    b"hold-damage",
                )
                .unwrap();
            let plan = h
                .plan_hold_release(placed.hold, b"hold-damage-release")
                .unwrap();
            let approval = h
                .approve_digest(RELEASE_APPROVER, plan.proposal_digest(&h.book).unwrap())
                .unwrap();
            let (key, control) = if release {
                let released = h.release_hold(&plan, &[approval]).unwrap();
                (b"hold-damage-release".as_slice(), released.release)
            } else {
                (b"hold-damage".as_slice(), placed.hold)
            };
            let claim =
                fa_model::intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key);
            let damaged = if attack == 3 { control } else { claim };
            let original = h.db.vertex(damaged).unwrap().unwrap();
            let mut change = fgdb::WriteBatch::new(relation::HOLDS);
            match attack {
                0 => {
                    change.delete_vertex(damaged);
                }
                2 => {
                    change.set_vertex_property(
                        damaged,
                        property::TARGET_REF,
                        Some(CanonicalScalar::bytes(VId(0xdead).0.to_le_bytes().to_vec()).unwrap()),
                    );
                }
                _ => {
                    change.set_vertex_property(
                        damaged,
                        property::FA_PAYLOAD,
                        Some(
                            CanonicalScalar::bytes(b"altered immutable control".to_vec()).unwrap(),
                        ),
                    );
                }
            }
            h.write_raw(change);
            if attack == 1 || attack == 3 {
                let mut restore = fgdb::WriteBatch::new(relation::HOLDS);
                restore.set_vertex_property(
                    damaged,
                    property::FA_PAYLOAD,
                    Some(
                        fa_journal::rows::prop(&original, property::FA_PAYLOAD)
                            .unwrap()
                            .clone(),
                    ),
                );
                h.write_raw(restore);
            }
            let head = h.db.frontier().unwrap();
            let rows = h.db.vertices().unwrap();
            let refusal = if release {
                h.release_hold(&plan, &[approval]).unwrap_err()
            } else {
                h.place_hold(&counsel, vec![document_vid(&authority)], authority, key)
                    .unwrap_err()
            };
            assert_eq!(
                (refusal.code, refusal.exit),
                ("FA-REF-032", exit::CONFLICT),
                "release={release} attack={attack}"
            );
            if !release {
                // A valid release approval cannot legitimize a placement
                // whose original control or atomic claim was altered.
                let refusal = h.release_hold(&plan, &[approval]).unwrap_err();
                assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
            }
            assert_eq!(h.db.frontier().unwrap(), head);
            assert_eq!(h.db.vertices().unwrap(), rows);
        }
    }
}

fn reopen_hold_store(h: &mut Harness) {
    let ctx = h.ctx();
    let (vfs, keys) = h.legacy_storage.clone().expect("durable hold fixture");
    let empty = h
        .runtime
        .block_on(Database::open_memory(&ctx.commit(), keys.clone()))
        .unwrap();
    drop(std::mem::replace(&mut h.db, empty));
    h.db = h
        .runtime
        .block_on(Database::open_with_vfs(
            &ctx.commit(),
            vfs.clone(),
            vfs.database_dir(),
            keys,
        ))
        .unwrap();
}

fn hold_cell_scalar(holds: &[VId]) -> CanonicalScalar {
    let mut writer = fa_model::Writer::new();
    writer.list(holds, |writer, hold| writer.u128(hold.0));
    CanonicalScalar::bytes(writer.finish().unwrap()).unwrap()
}

#[test]
fn claim_free_legacy_hold_controls_remain_original_retry_anchors_after_reopen() {
    for whole_book in [false, true] {
        let mut h = harness_legacy();
        let authority = hold_authority(&mut h);
        let subject = document_vid(&authority);
        let counsel = Capability::embedded(PRINCIPAL, &["hold"]).unwrap();
        let scope = if whole_book {
            fa_journal::legal_hold::Scope::Book(h.db.frontier().unwrap())
        } else {
            fa_journal::legal_hold::Scope::Place(vec![subject])
        };
        let scope_digest = scope.digest().unwrap();
        let place_key = b"legacy-hold-original-place";
        let hold = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), place_key);
        let (cell, target, reach, subjects, through) = match &scope {
            fa_journal::legal_hold::Scope::Book(through) => (
                fa_journal::legal_hold::book_hold_cell_vid(h.book.book_id),
                book_root(),
                HoldReach::ThroughHead,
                vec![],
                Some(*through),
            ),
            _ => (
                fa_journal::legal_hold::legal_hold_cell_vid(h.book.book_id, subject),
                subject,
                HoldReach::Subjects(vec![subject]),
                vec![subject],
                None,
            ),
        };
        let mut proposal = h.proposal(Vec::new(), place_key, EntryClass::HOLD_CONTROL);
        proposal.schema_minor = fa_model::entry::EXTENSIONS_MINOR;
        proposal.effective_date = DateDay::from_ymd(2026, 3, 20).unwrap();
        proposal.description = h.statement("legal hold", 61);
        proposal.control = Some(ControlPayload::HoldEvent {
            scope_digest,
            authority_oid: authority,
            kind: fa_journal::legal_hold::PLACE,
        });
        proposal.origin = EntryOrigin::Control {
            control_kind: fa_model::ControlKind::LEGAL_HOLD,
            spec_body_digest: scope_digest,
        };
        proposal.evidence.clear();
        proposal.extensions = vec![(
            fa_model::entry::LEGAL_HOLD_SCOPE_EXTENSION,
            scope.canonical_bytes().unwrap(),
        )];
        let entry = proposal.seal(Vec::new(), None).unwrap();
        // Publish the original pre-claim writer's complete native outcome.
        // A modern claim is never created and then deleted to fake history.
        let mut place = fgdb::WriteBatch::new(relation::HOLDS);
        place.create_vertex(
            hold,
            vec![fa_model::symbols::label::ENTRY],
            fa_model::entry_mirrors(&entry).unwrap(),
        );
        place.create_vertex(
            cell,
            vec![fa_model::symbols::label::LEGAL_HOLD_CELL],
            vec![(property::LEGAL_HOLDS, hold_cell_scalar(&[hold]))],
        );
        place.add_edge(edge_id(relation::HOLDS, hold, target), hold, target, vec![]);
        h.write_raw(place);
        let placed = LegalHoldPlaced {
            hold,
            subjects,
            through,
            recorded_at: h.db.frontier().unwrap(),
            already_recorded: true,
        };
        let release_key = b"legacy-hold-original-release";
        let plan = h.plan_hold_release(hold, release_key).unwrap();
        let approval = h
            .approve_digest(RELEASE_APPROVER, plan.proposal_digest(&h.book).unwrap())
            .unwrap();
        let entry = plan
            .proposal(&h.book)
            .unwrap()
            .seal(vec![approval], None)
            .unwrap();
        let release = fa_journal::legal_hold::release_vid(h.book.book_id, hold);
        let mut release_batch = fgdb::WriteBatch::new(relation::HOLDS);
        release_batch.create_vertex(
            release,
            vec![fa_model::symbols::label::ENTRY],
            fa_model::entry_mirrors(&entry).unwrap(),
        );
        release_batch.compare_and_set_vertex_property(
            cell,
            property::LEGAL_HOLDS,
            Some(hold_cell_scalar(&[hold])),
            hold_cell_scalar(&[]),
            fgdb::WriteMismatchPolicy::AbortWrite,
        );
        h.write_raw(release_batch);
        let released = LegalHoldReleased {
            release,
            hold,
            recorded_at: h.db.frontier().unwrap(),
            already_recorded: true,
        };

        reopen_hold_store(&mut h);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        assert_eq!(
            h.place_reach(&counsel, reach, authority, place_key)
                .unwrap(),
            placed
        );
        assert_eq!(h.release_hold(&plan, &[approval]).unwrap(), released);
        assert!(h.holds_on(subject).is_empty());
        for key in [place_key.as_slice(), release_key] {
            let outcome =
                fa_model::intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key);
            assert!(h.db.vertex(outcome).unwrap().is_none());
            assert!(
                h.db.vertex_at(outcome, released.recorded_at)
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn legal_hold_outcomes_survive_durable_reopen_without_another_publication() {
    let mut h = harness_legacy();
    let ctx = h.ctx();
    let prepared = h
        .runtime
        .block_on(prepare_outcome_rebuild(
            &mut h.db,
            &ctx,
            &h.book,
            Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    h.runtime
        .block_on(publish_outcome_rebuild(&mut h.db, &ctx, &h.book, prepared))
        .unwrap()
        .unwrap();
    let authority = hold_authority(&mut h);
    let counsel = Capability::embedded(PRINCIPAL, &["hold"]).unwrap();
    let key = b"durable-hold-place";
    let placed = h
        .place_reach(&counsel, HoldReach::ThroughHead, authority, key)
        .unwrap();
    let plan = h
        .plan_hold_release(placed.hold, b"durable-hold-release")
        .unwrap();
    let approval = h
        .approve_digest(RELEASE_APPROVER, plan.proposal_digest(&h.book).unwrap())
        .unwrap();
    reopen_hold_store(&mut h);
    // Releasing a reopened placement authenticates its original claim and
    // publication before it changes the persisted active-hold cell.
    let released = h.release_hold(&plan, &[approval]).unwrap();
    reopen_hold_store(&mut h);
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    assert_eq!(
        h.place_reach(&counsel, HoldReach::ThroughHead, authority, key)
            .unwrap(),
        LegalHoldPlaced {
            already_recorded: true,
            ..placed
        }
    );
    assert_eq!(
        h.release_hold(&plan, &[approval]).unwrap(),
        LegalHoldReleased {
            already_recorded: true,
            ..released
        }
    );
    assert_hold_claim(&h, key, placed.hold);
    assert_hold_claim(&h, b"durable-hold-release", released.release);
    let posting = h.proposal(
        h.rent_legs(20),
        b"durable-hold-release",
        EntryClass::ORIGINAL,
    );
    refused_without_publication(&mut h, posting);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

mod statement_issuance_keys {
    use super::*;
    use fa_model::ApprovalRef;
    use fa_model::symbols::label;

    fn plan(h: &mut Harness, key: &[u8]) -> IssuancePlan {
        let certificate = [0x69; 32];
        let vid = fa_model::report_certificate_vid(h.book.book_id, &certificate);
        if h.db.vertex(vid).unwrap().is_none() {
            // The kernel witnesses retention. The facade separately validates
            // the statement certificate's full definition and coordinate.
            let mut retained = fgdb::WriteBatch::new(relation::IN_BOOK);
            retained.create_vertex(vid, vec![label::CERTIFICATE], vec![]);
            h.write_raw(retained);
        }
        plan_issuance(
            &h.db,
            &h.book,
            &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
            StatementIssuance {
                book_id: h.book.book_id,
                period: h.march.clone(),
                ordinal: 1,
                definition_digest: [0x6a; 32],
                definition_name: "income-statement".into(),
                definition_version: 1,
                certificate,
                certified_at: h.db.frontier().unwrap(),
                issued_to: IssuedTo::Auditor,
                document: None,
            },
            h.day(),
            key,
            h.statement("issued financial statements", 105),
        )
        .unwrap()
        .unwrap()
    }

    fn execute(
        h: &mut Harness,
        plan: &IssuancePlan,
        approvals: &[ApprovalRef],
        capability: &Capability,
    ) -> Result<Result<StatementsIssued, Refusal>, KernelError> {
        let ctx = h.ctx();
        h.runtime.block_on(issue_statements(
            &mut h.db,
            &ctx,
            &h.book,
            capability,
            plan.clone(),
            approvals.to_vec(),
        ))
    }

    fn issue(
        h: &mut Harness,
        plan: &IssuancePlan,
        approvals: &[ApprovalRef],
    ) -> Result<Result<StatementsIssued, Refusal>, KernelError> {
        execute(
            h,
            plan,
            approvals,
            &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
        )
    }

    fn refused_unchanged(h: &mut Harness, plan: &IssuancePlan, approvals: &[ApprovalRef]) {
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let refusal = issue(h, plan, approvals).unwrap().unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }

    #[test]
    fn issuance_claim_is_atomic_and_retries_preserve_the_complete_approval_transcript() {
        let mut h = harness();
        let plan = plan(&mut h, b"issuance-atomic");
        let digest = plan.proposal_digest(&h.book).unwrap();
        let first = h.approve_digest(VId(70), digest).unwrap();
        let second = h.approve_digest(VId(71), digest).unwrap();
        let approvals = [first, second];
        let proposal = plan.proposal(&h.book).unwrap();
        let basis = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap().len();
        let edges = h.db.edges_at(basis).unwrap().len();
        let issued = issue(&mut h, &plan, &approvals).unwrap().unwrap();
        assert!(!issued.already_recorded);
        assert_eq!(issued.record.recorded_at.0, basis.0 + 1);
        assert_eq!(h.db.vertices().unwrap().len(), vertices + 3);
        assert_eq!(
            h.db.edges_at(issued.record.recorded_at).unwrap().len(),
            edges + 1
        );
        assert_hold_claim(&h, &proposal.idempotency_key, issued.record.control_entry);
        let body = h.db.vertex(issued.record.vid).unwrap().unwrap();
        assert_eq!(body.created_at, issued.record.recorded_at);
        assert_eq!(
            issuances(&h.db, &h.book, &h.march).unwrap(),
            vec![issued.record.clone()]
        );
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        assert_eq!(
            issue(&mut h, &plan, &approvals).unwrap().unwrap(),
            StatementsIssued {
                already_recorded: true,
                ..issued
            }
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        for changed in [vec![], vec![first], vec![second, first]] {
            refused_unchanged(&mut h, &plan, &changed);
        }
        let mut changed = plan.clone();
        changed.issuance.issued_to = IssuedTo::Lender;
        refused_unchanged(&mut h, &changed, &approvals);
        let refusal = execute(
            &mut h,
            &plan,
            &approvals,
            &Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        )
        .unwrap()
        .unwrap_err();
        assert_eq!(refusal.code, code::CAPABILITY);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }

    #[test]
    fn issuance_record_keys_cannot_cross_posting_or_batch_outcomes_in_either_order() {
        for occupant in ["ordinary", "reversal", "batch"] {
            let mut h = harness();
            let plan = plan(&mut h, b"issuance-reserved-key");
            let key = plan.proposal(&h.book).unwrap().idempotency_key;
            let approval = h.approve_transition(plan.proposal_digest(&h.book).unwrap());
            let original = h.proposal(h.rent_legs(100), b"issuance-source", EntryClass::ORIGINAL);
            let posted = h.post(h.request(original, &["post"])).unwrap();
            match occupant {
                "ordinary" => {
                    let ordinary = h.proposal(h.rent_legs(20), &key, EntryClass::ORIGINAL);
                    h.post(h.request(ordinary, &["post"])).unwrap();
                }
                "reversal" => {
                    let reversal = h.reversal_of_entry(posted.entry_ref(), &key);
                    h.post(h.request(reversal, &["post"])).unwrap();
                }
                _ => {
                    let member =
                        h.proposal(h.rent_legs(20), b"issuance-member", EntryClass::ORIGINAL);
                    h.post_batch(h.batch(&key, vec![member])).unwrap();
                }
            }
            refused_unchanged(&mut h, &plan, &[approval]);
            assert!(h.db.vertex(plan.issuance.vid()).unwrap().is_none());
        }

        let mut h = harness();
        let plan = plan(&mut h, b"issuance-first");
        let key = plan.proposal(&h.book).unwrap().idempotency_key;
        let approval = h.approve_transition(plan.proposal_digest(&h.book).unwrap());
        issue(&mut h, &plan, &[approval]).unwrap().unwrap();
        let original = h.proposal(h.rent_legs(100), b"issued-source", EntryClass::ORIGINAL);
        let posted = h.post(h.request(original, &["post"])).unwrap();
        let reversal = h.reversal_of_entry(posted.entry_ref(), &key);
        refused_without_publication(&mut h, reversal);
        let member = h.proposal(h.rent_legs(20), b"issued-member", EntryClass::ORIGINAL);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let refusal = h.post_batch(h.batch(&key, vec![member])).unwrap_err();
        assert_eq!(refusal.code, code::IDEMPOTENCY_CONFLICT);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }

    #[test]
    fn issuance_retries_and_reported_views_reject_damaged_or_restored_sources() {
        for attack in 0..6 {
            let mut h = harness();
            let plan = plan(&mut h, b"issuance-integrity");
            let approval = h.approve_transition(plan.proposal_digest(&h.book).unwrap());
            let issued = issue(&mut h, &plan, &[approval]).unwrap().unwrap();
            let proposal = plan.proposal(&h.book).unwrap();
            let claim = outcome_id(&h, &proposal);
            let damaged = match attack {
                2 => issued.record.control_entry,
                3 | 4 => issued.record.vid,
                _ => claim,
            };
            let original = h.db.vertex(damaged).unwrap().unwrap();
            let property = match attack {
                4 => property::FA_DIGEST,
                5 => property::TARGET_REF,
                _ => property::FA_PAYLOAD,
            };
            let mut change = fgdb::WriteBatch::new(relation::IN_CASE);
            if attack == 0 {
                change.delete_vertex(damaged);
            } else {
                change.set_vertex_property(
                    damaged,
                    property,
                    Some(CanonicalScalar::bytes(vec![0x56; 32]).unwrap()),
                );
            }
            h.write_raw(change);
            if (1..=3).contains(&attack) {
                let mut restore = fgdb::WriteBatch::new(relation::IN_CASE);
                restore.set_vertex_property(
                    damaged,
                    property,
                    Some(fa_journal::rows::prop(&original, property).unwrap().clone()),
                );
                h.write_raw(restore);
            }
            let head = h.db.frontier().unwrap();
            let rows = h.db.vertices().unwrap();
            assert!(
                issuances(&h.db, &h.book, &h.march).is_err(),
                "attack {attack}"
            );
            match issue(&mut h, &plan, &[approval]) {
                Ok(Err(refusal)) => assert_eq!(refusal.code, code::IDEMPOTENCY_CONFLICT),
                Err(KernelError::Corrupt(_)) => {}
                other => panic!("damaged issuance {attack} was accepted: {other:?}"),
            }
            assert_eq!(h.db.frontier().unwrap(), head);
            assert_eq!(h.db.vertices().unwrap(), rows);
        }
    }

    fn write_legacy_issuance(
        h: &mut Harness,
        plan: &IssuancePlan,
        approvals: &[ApprovalRef],
        separate_publications: bool,
    ) {
        let issuance = &plan.issuance;
        let proposal = plan.proposal(&h.book).unwrap();
        let control = entry_vid(
            h.book.book_id,
            &PRINCIPAL.0.to_le_bytes(),
            &proposal.idempotency_key,
        );
        let entry = proposal.seal(approvals.to_vec(), None).unwrap();
        let body = issuance.vid();
        let mut props = vec![
            (
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(issuance.canonical_bytes().unwrap()).unwrap(),
            ),
            (
                property::FA_DIGEST,
                CanonicalScalar::bytes(issuance.digest().unwrap().to_vec()).unwrap(),
            ),
            (
                property::BOOK_ID,
                CanonicalScalar::bytes(h.book.book_id.0.to_vec()).unwrap(),
            ),
            (
                property::CODE,
                fa_journal::rows::scalar_text("issuance.code", &issuance.period).unwrap(),
            ),
        ];
        props.sort_by_key(|(key, _)| key.0);
        let mut batch = fgdb::WriteBatch::new(relation::IN_CASE);
        batch.create_vertex(body, vec![label::STATEMENT_ISSUANCE], props);
        if separate_publications {
            h.write_raw(batch);
            batch = fgdb::WriteBatch::new(relation::IN_CASE);
        }
        batch.create_vertex(
            control,
            vec![label::ENTRY],
            fa_model::entry_mirrors(&entry).unwrap(),
        );
        batch.add_edge(
            edge_id(relation::IN_CASE, control, body),
            control,
            body,
            vec![],
        );
        h.write_raw(batch);
    }

    #[test]
    fn legacy_issuance_retry_requires_original_atomic_sources_and_survives_reopen() {
        for separate_publications in [false, true] {
            let mut h = harness_legacy();
            let plan = plan(&mut h, b"legacy-issuance");
            let approval = h.approve_transition(plan.proposal_digest(&h.book).unwrap());
            write_legacy_issuance(&mut h, &plan, &[approval], separate_publications);
            reopen_hold_store(&mut h);
            let head = h.db.frontier().unwrap();
            let rows = h.db.vertices().unwrap();
            if separate_publications {
                assert!(matches!(
                    issue(&mut h, &plan, &[approval]),
                    Err(KernelError::Corrupt(_))
                ));
            } else {
                let recorded = issue(&mut h, &plan, &[approval]).unwrap().unwrap();
                assert!(recorded.already_recorded);
                assert_eq!(recorded.record.recorded_at, head);
                assert_eq!(
                    first_issuance(&h.db, &h.book, &h.march).unwrap(),
                    Some(recorded.record)
                );
                refused_unchanged(&mut h, &plan, &[]);
                assert!(
                    h.db.vertex(outcome_id(&h, &plan.proposal(&h.book).unwrap()))
                        .unwrap()
                        .is_none()
                );
            }
            assert_eq!(h.db.frontier().unwrap(), head);
            assert_eq!(h.db.vertices().unwrap(), rows);
        }
    }

    #[test]
    fn durable_issuance_retry_is_read_only_and_rechecks_current_authority() {
        let mut h = harness_legacy();
        let ctx = h.ctx();
        let prepared = h
            .runtime
            .block_on(prepare_outcome_rebuild(
                &mut h.db,
                &ctx,
                &h.book,
                Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        h.runtime
            .block_on(publish_outcome_rebuild(&mut h.db, &ctx, &h.book, prepared))
            .unwrap()
            .unwrap();
        let plan = plan(&mut h, b"durable-issuance");
        let approval = h.approve_transition(plan.proposal_digest(&h.book).unwrap());
        let controller = Capability::embedded(PRINCIPAL, &["close"]).unwrap();
        let issued = execute(&mut h, &plan, &[approval], &controller)
            .unwrap()
            .unwrap();
        reopen_hold_store(&mut h);
        assert_eq!(
            first_issuance(&h.db, &h.book, &h.march).unwrap(),
            Some(issued.record.clone())
        );
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        assert_eq!(
            execute(&mut h, &plan, &[approval], &controller)
                .unwrap()
                .unwrap(),
            StatementsIssued {
                already_recorded: true,
                ..issued
            }
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        h.revoke(&controller, 106);
        reopen_hold_store(&mut h);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let refusal = execute(&mut h, &plan, &[approval], &controller)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_policy::denial::code::REVOKED);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

mod case_lifecycle_outcomes {
    use super::*;
    use fa_journal::case::{CaseBody, CaseRequest, open_case, read_case};
    use fa_journal::refusal::{Outcome, code};
    use fa_model::symbols::label;

    fn request(h: &Harness, key: &[u8]) -> (CaseBody, CaseRequest) {
        (
            CaseBody {
                book_id: h.book.book_id,
                ordinal: 1,
                kind: CaseKind::Restatement,
                periods: vec![h.march.clone()],
                narrative: None,
                determination: None,
            },
            CaseRequest {
                capability: Capability::embedded(PRINCIPAL, &["restate"]).unwrap(),
                effective_date: h.day(),
                description: h.statement("case outcome", 181),
                idempotency_key: key.to_vec(),
            },
        )
    }

    fn record_key(request: &CaseRequest) -> Vec<u8> {
        fa_model::domain_digest(
            b"fa:case-record-key:v1",
            &[&[0], &[0; 16], &request.idempotency_key],
        )
        .to_vec()
    }

    fn outcome(h: &Harness, request: &CaseRequest) -> VId {
        fa_model::intent_outcome_vid(
            h.book.book_id,
            &request.capability.holder().0.to_le_bytes(),
            &record_key(request),
        )
    }

    fn execute(h: &mut Harness, body: &CaseBody, request: &CaseRequest) -> Outcome<CaseRecorded> {
        let ctx = h.ctx();
        h.runtime.block_on(open_case(
            &mut h.db,
            &ctx,
            &h.book,
            body.clone(),
            request.clone(),
        ))
    }

    fn assert_open_conflict(h: &mut Harness, body: &CaseBody, request: &CaseRequest) {
        let head = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        let edges = h.db.edges_at(head).unwrap();
        let refused = execute(h, body, request).unwrap().unwrap_err();
        assert_eq!(
            (refused.code, refused.exit),
            (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT)
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
        assert_eq!(h.db.edges_at(head).unwrap(), edges);
    }

    fn assert_control_claim(h: &Harness, recorded: &CaseRecorded) {
        let row = h.db.vertex(recorded.control_entry).unwrap().unwrap();
        let (entry, _) = read_entry(&h.db, row.vid).unwrap().unwrap();
        let claim = h
            .db
            .vertex(outcome_id(h, &entry.proposal))
            .unwrap()
            .unwrap();
        assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
        assert_eq!(
            (row.created_at, claim.created_at),
            (recorded.recorded_at, recorded.recorded_at)
        );
        assert_eq!(
            fa_journal::rows::prop(&claim, property::TARGET_REF),
            Some(&CanonicalScalar::bytes(row.vid.0.to_le_bytes().to_vec()).unwrap())
        );
    }

    fn compact_and_reopen(h: &mut Harness) {
        let ctx = h.ctx();
        h.runtime.block_on(h.db.compact(&ctx.commit())).unwrap();
        let (vfs, keys) = h.legacy_storage.clone().unwrap();
        let empty = h.runtime.block_on(Database::open_memory(&ctx.commit(), keys.clone())).unwrap();
        drop(std::mem::replace(&mut h.db, empty));
        h.db = h
            .runtime
            .block_on(Database::open_with_vfs(
                &ctx.commit(),
                vfs.clone(),
                vfs.database_dir(),
                keys,
            ))
            .unwrap();
        assert!(matches!(
            h.db.delta_since(fgdb_types::CommitSeq(0)),
            Err(fgdb::ReadError::DeltaCursorRetired { .. })
        ));
    }

    #[test]
    fn case_controls_claim_their_canonical_key_and_bind_the_complete_retry() {
        let mut h = harness();
        let (body, original) = request(&h, b"case-original");
        let first = execute(&mut h, &body, &original).unwrap().unwrap();
        assert_control_claim(&h, &first);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        for description in [
            original.description.clone(),
            h.statement("case outcome", 182),
        ] {
            let mut retry = original.clone();
            retry.description = description;
            assert_eq!(
                execute(&mut h, &body, &retry).unwrap().unwrap(),
                CaseRecorded {
                    already_recorded: true,
                    ..first.clone()
                }
            );
            assert_eq!(h.db.frontier().unwrap(), head);
            assert_eq!(h.db.vertices().unwrap(), rows);
        }
        let mut changed_body = body.clone();
        changed_body.kind = CaseKind::Revision;
        assert_open_conflict(&mut h, &changed_body, &original);
        let mut changed = original.clone();
        changed.description = h.statement("another case outcome", 183);
        assert_open_conflict(&mut h, &body, &changed);
        changed = original.clone();
        changed.effective_date = DateDay::from_ymd(2026, 3, 16).unwrap();
        assert_open_conflict(&mut h, &body, &changed);

        let authority = h.document(INVOICE, HUMAN_UPLOAD, b"case determination authority");
        h.add_document(&authority).unwrap();
        let determination = Determination {
            day: h.day(),
            authority: authority.oid(),
        };
        let (_, determine) = request(&h, b"case-determine");
        let ctx = h.ctx();
        let determined = h
            .runtime
            .block_on(fa_journal::case::determine_case(
                &mut h.db,
                &ctx,
                &h.book,
                1,
                determination,
                determine,
            ))
            .unwrap()
            .unwrap();
        assert_control_claim(&h, &determined);
        let head = h.db.frontier().unwrap();
        let late_retry = execute(&mut h, &body, &original).unwrap().unwrap();
        assert!(late_retry.already_recorded);
        assert_eq!(late_retry.recorded_at, first.recorded_at);
        assert_eq!(late_retry.control_entry, first.control_entry);
        assert_eq!(late_retry.case.state, CaseState::Determined);
        assert_eq!(h.db.frontier().unwrap(), head);
    }

    #[test]
    fn posting_families_cannot_reuse_a_case_record_key() {
        for family in ["original", "reversal", "replacement", "pending", "resolution", "batch"] {
            let mut h = harness();
            let (body, request) = request(&h, b"case-collision");
            let key = record_key(&request);
            let source = h.proposal(h.rent_legs(100), b"case-source", EntryClass::ORIGINAL);
            let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
            let occupied = match family {
                "original" | "batch" => h.proposal(h.rent_legs(200), &key, EntryClass::ORIGINAL),
                "reversal" => h.reversal_of_entry(target, &key),
                "replacement" => replacement_proposal(
                    target,
                    h.proposal(h.rent_legs(125), &key, EntryClass::REPLACEMENT),
                ),
                "pending" => h.pending(h.rent_legs(200), &key),
                "resolution" => {
                    let pending = h.pending(h.rent_legs(200), b"case-held-source");
                    let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
                    h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], &key)
                }
                _ => unreachable!(),
            };
            if family == "replacement" {
                h.post_pair(
                    h.request(h.reversal_of_entry(target, b"case-pair-reversal"), &["post"]),
                    h.request(occupied, &["post"]),
                )
                .unwrap();
            } else if family == "batch" {
                let mut member = occupied;
                member.idempotency_key = b"case-batch-member".to_vec();
                h.post_batch(h.batch(&key, vec![member])).unwrap();
            } else {
                h.post(h.request(occupied, &["post"])).unwrap();
            }
            assert_open_conflict(&mut h, &body, &request);
            assert!(read_case(&h.db, &h.book, 1).unwrap().is_none());
        }
    }

    #[test]
    fn a_case_claim_blocks_postings_and_batches_without_partial_effects() {
        let mut h = harness();
        let source = h.proposal(h.rent_legs(100), b"case-blocked-source", EntryClass::ORIGINAL);
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let pending = h.pending(h.rent_legs(200), b"case-blocked-hold");
        let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
        let (body, request) = request(&h, b"case-owned");
        execute(&mut h, &body, &request).unwrap().unwrap();
        let key = record_key(&request);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let edges = h.db.edges_at(head).unwrap();
        let original = h.proposal(h.rent_legs(300), &key, EntryClass::ORIGINAL);
        let reversal = h.reversal_of_entry(target, &key);
        let pending = h.pending(h.rent_legs(300), &key);
        let resolution = h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], &key);
        for proposal in [original, reversal, pending, resolution] {
            let refused = h.post(h.request(proposal, &["post"])).unwrap_err();
            assert_eq!(
                (refused.code, refused.exit),
                (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT)
            );
        }
        let reversal = h.request(
            h.reversal_of_entry(target, b"case-unpublished-reversal"),
            &["post"],
        );
        let replacement = h.request(
            replacement_proposal(
                target,
                h.proposal(h.rent_legs(125), &key, EntryClass::REPLACEMENT),
            ),
            &["post"],
        );
        assert_eq!(
            h.post_pair(reversal, replacement).unwrap_err().code,
            code::IDEMPOTENCY_CONFLICT
        );
        let member = h.proposal(h.rent_legs(300), b"case-unpublished-member", EntryClass::ORIGINAL);
        assert_eq!(
            h.post_batch(h.batch(&key, vec![member])).unwrap_err().code,
            code::IDEMPOTENCY_CONFLICT
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(h.db.edges_at(head).unwrap(), edges);
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
        assert!(h.db.vertex(resolution_vid(hold.vid)).unwrap().is_none());
    }

    #[test]
    fn a_prepared_reversal_loses_to_the_case_claim_without_changing_the_winner() {
        let mut h = harness();
        let source = h.proposal(h.rent_legs(100), b"case-race-source", EntryClass::ORIGINAL);
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let (body, request) = request(&h, b"case-race");
        let reversal = h.request(h.reversal_of_entry(target, &record_key(&request)), &["post"]);
        let ctx = h.ctx();
        let PostPreparation::Ready(prepared) = prepare_post(&mut h.db, &ctx, &h.book, reversal)
            .unwrap()
            .unwrap()
        else {
            panic!("fresh reversal");
        };
        let epoch = security_policy_epoch(&h.db).unwrap();
        execute(&mut h, &body, &request).unwrap().unwrap();
        assert_eq!(security_policy_epoch(&h.db).unwrap(), epoch);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let refusal = h
            .runtime
            .block_on(prepared.commit(&mut h.db, &ctx))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, exit::CONFLICT);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    }

    #[test]
    fn authentic_legacy_case_retries_survive_durable_reopen_and_recovery() {
        let mut producer = harness();
        let (body, original) = request(&producer, b"legacy-case");
        let first = execute(&mut producer, &body, &original).unwrap().unwrap();
        let claim = outcome(&producer, &original);
        let mut publication = fgdb::WriteBatch::new(relation::IN_CASE);
        let mut created = std::collections::BTreeSet::new();
        // Retain the original pre-protocol publication in a separate store.
        // No modern claim is ever published there and then deleted.
        for row in producer.db.vertices_at(first.recorded_at).unwrap() {
            if row.created_at != first.recorded_at || row.vid == claim {
                continue;
            }
            assert!(row.labels.iter().all(|kind| matches!(*kind, label::ENTRY | label::RESTATEMENT_CASE)));
            assert!(created.insert(row.vid));
            publication.create_vertex(row.vid, row.labels, row.props);
        }
        assert_eq!(created.len(), 2);
        for edge in producer.db.edges_at(first.recorded_at).unwrap() {
            if created.contains(&edge.entry.src) {
                assert_eq!(edge.entry.relation, relation::IN_CASE);
                publication.add_edge(edge.entry.eid, edge.entry.src, edge.entry.dst, edge.props);
            }
        }
        let mut h = harness_legacy();
        h.write_raw(publication);
        let original_sequence = h.db.frontier().unwrap();
        let original_row = h.db.vertex(first.control_entry).unwrap().unwrap();
        let ctx = h.ctx();
        compact_and_reopen(&mut h);
        let head = h.db.frontier().unwrap();
        let retry = execute(&mut h, &body, &original).unwrap().unwrap();
        assert!(retry.already_recorded);
        assert_eq!(retry.control_entry, first.control_entry);
        assert_eq!(retry.recorded_at, original_sequence);
        assert_eq!(h.db.vertex(first.control_entry).unwrap().unwrap(), original_row);
        assert!(h.db.vertex(claim).unwrap().is_none());
        assert_eq!(h.db.frontier().unwrap(), head);
        let (_, fresh) = request(&h, b"fresh-after-legacy-case");
        assert_eq!(
            execute(&mut h, &body, &fresh).unwrap().unwrap_err().code,
            code::PLAN_INVALIDATED
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        let prepared = h
            .runtime
            .block_on(prepare_outcome_rebuild(
                &mut h.db,
                &ctx,
                &h.book,
                Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        h.runtime
            .block_on(publish_outcome_rebuild(&mut h.db, &ctx, &h.book, prepared))
            .unwrap()
            .unwrap();
        compact_and_reopen(&mut h);
        let head = h.db.frontier().unwrap();
        let retry = execute(&mut h, &body, &original).unwrap().unwrap();
        assert_eq!(retry.recorded_at, original_sequence);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert!(h.db.vertex(claim).unwrap().is_none());
        assert!(matches!(
            h.db.delta_since(fgdb_types::CommitSeq(0)),
            Err(fgdb::ReadError::DeltaCursorRetired { .. })
        ), "an authentic exact retry does not need capsule history");
        let next = execute(&mut h, &body, &fresh).unwrap().unwrap();
        assert_eq!(next.case.body.ordinal, 2);
        assert_control_claim(&h, &next);
    }

    #[test]
    fn changed_control_rows_and_deleted_or_retargeted_claims_cannot_become_legacy() {
        for variant in ["mirror", "deleted claim", "retargeted claim"] {
            let mut h = harness();
            let (body, request) = request(&h, b"damaged-case-outcome");
            let recorded = execute(&mut h, &body, &request).unwrap().unwrap();
            let mut write = fgdb::WriteBatch::new(relation::IN_CASE);
            match variant {
                "mirror" => write.set_vertex_property(
                    recorded.control_entry,
                    property::FA_EFFECTIVE_DAY,
                    Some(CanonicalScalar::Int(1)),
                ),
                "deleted claim" => write.delete_vertex(outcome(&h, &request)),
                "retargeted claim" => write.set_vertex_property(
                    outcome(&h, &request),
                    property::TARGET_REF,
                    Some(CanonicalScalar::bytes(VId(188).0.to_le_bytes().to_vec()).unwrap()),
                ),
                _ => unreachable!(),
            };
            h.write_raw(write);
            let head = h.db.frontier().unwrap();
            let rows = h.db.vertices().unwrap();
            assert!(read_case(&h.db, &h.book, 1).is_err(), "{variant}");
            assert!(!matches!(execute(&mut h, &body, &request), Ok(Ok(_))), "{variant}");
            assert_eq!(h.db.frontier().unwrap(), head, "{variant}");
            assert_eq!(h.db.vertices().unwrap(), rows, "{variant}");
        }
    }

    #[test]
    fn case_authority_precedes_malformed_outcome_observation() {
        let mut h = harness();
        let (body, original) = request(&h, b"unauthorized-case-outcome");
        let mut write = fgdb::WriteBatch::new(relation::IN_CASE);
        write.create_vertex(
            outcome(&h, &original),
            vec![label::INTENT_OUTCOME],
            vec![(property::FA_PAYLOAD, CanonicalScalar::bytes(vec![0]).unwrap())],
        );
        h.write_raw(write);
        let head = h.db.frontier().unwrap();
        for capability in [
            Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
            Capability::embedded(PRINCIPAL, &["restate"])
                .unwrap()
                .for_classes(&[EntryClass::ORIGINAL])
                .unwrap(),
            Capability::embedded(PRINCIPAL, &["restate"]).unwrap().with_requires_dry_run(),
        ] {
            let mut unauthorized = original.clone();
            unauthorized.capability = capability;
            let refused = execute(&mut h, &body, &unauthorized).unwrap().unwrap_err();
            assert_eq!(refused.code, code::CAPABILITY);
            assert_eq!(h.db.frontier().unwrap(), head);
        }
    }
}
