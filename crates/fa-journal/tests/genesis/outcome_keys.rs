//! The scoped key is shared by successful posting families, independently
//! of the target-derived Entry identity. Refusals must leave the whole native
//! publication untouched, including the earlier member of a correction pair.

use super::*;

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
