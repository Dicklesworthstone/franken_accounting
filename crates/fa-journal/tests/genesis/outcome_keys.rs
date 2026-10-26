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
