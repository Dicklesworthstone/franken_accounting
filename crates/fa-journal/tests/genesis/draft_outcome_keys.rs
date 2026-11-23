//! Draft lifecycle and compound planning records retain their public keys
//! while sharing successful-intent ownership with monetary publication.

use super::*;
use fa_intents::PostIntent;
use fa_journal::refusal::{Outcome, code};
use fa_model::symbols::label;
use fgdb_types::CommitSeq;

const NAME: &str = "outcome-draft";
const INTENT_KEY: &[u8] = b"draft-member";
const BATCH_KEY: &[u8] = b"draft-member-batch";
const REVERSAL_KEY: &[u8] = b"draft-pair-reversal";

fn principal(kind: u8) -> VId {
    if kind == 2 { APPROVER } else { PRINCIPAL }
}

fn request(h: &Harness, kind: u8) -> DraftRequest {
    let capability = if kind == 2 {
        h.approver_capability()
    } else {
        Capability::embedded(PRINCIPAL, &["post", "read"]).unwrap()
    };
    h.draft_request(capability)
}

fn key(h: &Harness, kind: u8) -> Vec<u8> {
    let discriminator = match kind {
        1 => INTENT_KEY,
        4 => BATCH_KEY,
        5 => REVERSAL_KEY,
        _ => &[],
    };
    fa_model::domain_digest(
        b"fa:draft-record-key:v1",
        &[
            &[kind],
            &fa_model::draft_vid(h.book.book_id, NAME).0.to_le_bytes(),
            discriminator,
        ],
    )
    .to_vec()
}

fn outcome(h: &Harness, kind: u8) -> VId {
    fa_model::intent_outcome_vid(
        h.book.book_id,
        &principal(kind).0.to_le_bytes(),
        &key(h, kind),
    )
}

fn execute(
    h: &mut Harness,
    kind: u8,
    correction_target: EntryRef,
    request: &DraftRequest,
) -> Outcome<DraftRecorded> {
    let ctx = h.ctx();
    match kind {
        0 => h
            .runtime
            .block_on(open_draft(&mut h.db, &ctx, &h.book, NAME, request.clone())),
        1 => {
            let intent = PostIntent::new(
                h.proposal(h.rent_legs(100), INTENT_KEY, EntryClass::ORIGINAL),
                Vec::new(),
            )
            .unwrap();
            h.runtime
                .block_on(plan_into_draft(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    NAME,
                    intent,
                    request.clone(),
                ))
                .map(|result| result.map(|planned| planned.recorded))
        }
        2 => h
            .runtime
            .block_on(promote_draft(
                &mut h.db,
                &ctx,
                &h.book,
                NAME,
                request.clone(),
            ))
            .map(|result| {
                result.map(|promoted| DraftRecorded {
                    draft: promoted.draft,
                    control_entry: promoted.control_entry,
                    recorded_at: promoted.recorded_at,
                    already_recorded: promoted.already_recorded,
                })
            }),
        3 => h.runtime.block_on(discard_draft(
            &mut h.db,
            &ctx,
            &h.book,
            NAME,
            request.clone(),
        )),
        4 => {
            let batch = h.batch(
                BATCH_KEY,
                vec![
                    h.proposal(h.rent_legs(100), INTENT_KEY, EntryClass::ORIGINAL),
                    h.proposal(h.rent_legs(50), b"draft-member-2", EntryClass::ORIGINAL),
                ],
            );
            h.runtime
                .block_on(plan_batch_into_draft(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    NAME,
                    batch,
                    request.clone(),
                ))
                .map(|result| result.map(|planned| planned.recorded))
        }
        5 => {
            let reversal = PostIntent::new(
                h.reversal_of_entry(correction_target, REVERSAL_KEY),
                Vec::new(),
            )
            .unwrap();
            let replacement = PostIntent::new(
                replacement_proposal(
                    correction_target,
                    h.proposal(
                        h.rent_legs(125),
                        b"draft-pair-replacement",
                        EntryClass::REPLACEMENT,
                    ),
                ),
                Vec::new(),
            )
            .unwrap();
            h.runtime
                .block_on(plan_correction_into_draft(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    NAME,
                    reversal,
                    replacement,
                    request.clone(),
                ))
                .map(|result| result.map(|planned| planned.recorded))
        }
        _ => unreachable!(),
    }
}

fn prepare(h: &mut Harness, kind: u8) -> EntryRef {
    let source = h.proposal(
        h.rent_legs(100),
        b"draft-correction-source",
        EntryClass::ORIGINAL,
    );
    let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
    let owner = request(h, 0);
    if kind != 0 {
        execute(h, 0, target, &owner).unwrap().unwrap();
    }
    if kind == 2 {
        execute(h, 1, target, &owner).unwrap().unwrap();
    }
    target
}

fn assert_claim(h: &Harness, recorded: &DraftRecorded) {
    let (entry, sequence) = read_entry(&h.db, recorded.control_entry).unwrap().unwrap();
    let claim =
        h.db.vertex(fa_model::intent_outcome_vid(
            h.book.book_id,
            &entry.proposal.principal_ref.0.to_le_bytes(),
            &entry.proposal.idempotency_key,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
    assert_eq!(
        (sequence, claim.created_at),
        (recorded.recorded_at, recorded.recorded_at)
    );
    assert_eq!(
        fa_journal::rows::prop(&claim, property::TARGET_REF),
        Some(&CanonicalScalar::bytes(recorded.control_entry.0.to_le_bytes().to_vec()).unwrap())
    );
}

#[test]
fn postings_and_outer_batches_reserve_every_draft_record_key() {
    for kind in 0..=5 {
        for family in ["original", "reversal", "batch"] {
            let mut h = harness();
            let correction_target = prepare(&mut h, kind);
            let request = request(&h, kind);
            let source = h.proposal(h.rent_legs(200), b"collision-source", EntryClass::ORIGINAL);
            let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
            let key = key(&h, kind);
            let mut occupied = if family == "reversal" {
                h.reversal_of_entry(target, &key)
            } else {
                h.proposal(h.rent_legs(200), &key, EntryClass::ORIGINAL)
            };
            occupied.principal_ref = principal(kind);
            if family == "batch" {
                occupied.idempotency_key = b"collision-batch-member".to_vec();
                h.post_batch(h.batch(&key, vec![occupied])).unwrap();
            } else {
                h.post(h.request(occupied, &["post"])).unwrap();
            }
            let head = h.db.frontier().unwrap();
            let rows = h.db.vertices().unwrap();
            let edges = h.db.edges_at(head).unwrap();
            let refusal = execute(&mut h, kind, correction_target, &request)
                .unwrap()
                .unwrap_err();
            assert_eq!(
                (refusal.code, refusal.exit),
                (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT),
                "record kind {kind}, {family}"
            );
            assert_eq!(h.db.frontier().unwrap(), head);
            assert_eq!(h.db.vertices().unwrap(), rows);
            assert_eq!(h.db.edges_at(head).unwrap(), edges);
            let draft = read_draft(&h.db, &h.ctx().query(), &h.book, NAME).unwrap();
            if kind == 0 {
                assert!(draft.is_none());
            } else {
                let draft = draft.unwrap();
                assert_eq!(draft.state, DraftState::Open);
                assert!(draft.closed.is_none());
                assert_eq!(draft.intents.len(), if kind == 2 { 1 } else { 0 });
            }
        }
    }
}

#[test]
fn every_draft_record_claim_blocks_postings_and_outer_batches() {
    for kind in 0..=5 {
        let mut h = harness();
        let correction_target = prepare(&mut h, kind);
        let request = request(&h, kind);
        let source = h.proposal(h.rent_legs(200), b"blocked-source", EntryClass::ORIGINAL);
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let recorded = execute(&mut h, kind, correction_target, &request)
            .unwrap()
            .unwrap();
        assert_claim(&h, &recorded);
        let key = key(&h, kind);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let edges = h.db.edges_at(head).unwrap();
        for family in ["original", "reversal", "batch"] {
            let mut proposal = if family == "reversal" {
                h.reversal_of_entry(target, &key)
            } else {
                h.proposal(h.rent_legs(200), &key, EntryClass::ORIGINAL)
            };
            proposal.principal_ref = principal(kind);
            let refusal = if family == "batch" {
                proposal.idempotency_key = b"unpublished-draft-member".to_vec();
                h.post_batch(h.batch(&key, vec![proposal])).unwrap_err()
            } else {
                h.post(h.request(proposal, &["post"])).unwrap_err()
            };
            assert_eq!(
                (refusal.code, refusal.exit),
                (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT),
                "record kind {kind}, {family}"
            );
        }
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(h.db.edges_at(head).unwrap(), edges);
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    }
}

#[test]
fn single_batch_and_correction_plans_promote_claims_and_members_atomically() {
    for kind in [1, 4, 5] {
        let mut h = harness();
        let correction_target = prepare(&mut h, kind);
        let owner = request(&h, kind);
        let planned = execute(&mut h, kind, correction_target, &owner)
            .unwrap()
            .unwrap();
        assert_claim(&h, &planned);
        for member in h.draft(NAME).intents {
            let proposal = member.intent.proposal();
            assert!(
                h.db.vertex(fa_model::intent_outcome_vid(
                    h.book.book_id,
                    &proposal.principal_ref.0.to_le_bytes(),
                    &proposal.idempotency_key,
                ))
                .unwrap()
                .is_none()
            );
        }
        let promoted = h.promote(h.approver_capability(), NAME).unwrap();
        assert_eq!(promoted.entries.len(), if kind == 1 { 1 } else { 2 });
        let record = DraftRecorded {
            draft: promoted.draft,
            control_entry: promoted.control_entry,
            recorded_at: promoted.recorded_at,
            already_recorded: false,
        };
        assert_claim(&h, &record);
        assert_eq!(
            h.db.vertex(promoted.outcome).unwrap().unwrap().created_at,
            promoted.recorded_at
        );
        for member in &promoted.entries {
            assert_eq!(
                read_entry(&h.db, member.vid).unwrap().unwrap().1,
                promoted.recorded_at
            );
        }
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let retry = execute(&mut h, kind, correction_target, &owner)
            .unwrap()
            .unwrap();
        assert!(retry.already_recorded);
        assert_eq!(
            (retry.control_entry, retry.recorded_at),
            (planned.control_entry, planned.recorded_at)
        );
        let retry = h.promote(h.approver_capability(), NAME).unwrap();
        assert!(retry.already_recorded);
        assert_eq!(retry.entries, promoted.entries);
        assert_eq!(retry.recorded_at, promoted.recorded_at);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn authority_precedes_malformed_draft_outcome_observation() {
    for kind in 0..=5 {
        let mut h = harness();
        let target = prepare(&mut h, kind);
        let original = request(&h, kind);
        let mut write = fgdb::WriteBatch::new(relation::IN_CASE);
        write.create_vertex(
            outcome(&h, kind),
            vec![label::INTENT_OUTCOME],
            vec![(
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(vec![0]).unwrap(),
            )],
        );
        h.write_raw(write);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        for capability in [
            Capability::embedded(principal(kind), &["read"]).unwrap(),
            original.capability.clone().with_requires_dry_run(),
        ] {
            let mut denied = original.clone();
            denied.capability = capability;
            let refused = execute(&mut h, kind, target, &denied).unwrap().unwrap_err();
            assert_eq!(refused.code, code::CAPABILITY, "record kind {kind}");
        }
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn damaged_draft_controls_and_claims_never_become_legacy_retry_anchors() {
    for kind in 0..=5 {
        for variant in ["mirror", "deleted claim", "retargeted claim"] {
            let mut h = harness();
            let target = prepare(&mut h, kind);
            let request = request(&h, kind);
            let recorded = execute(&mut h, kind, target, &request).unwrap().unwrap();
            let mut write = fgdb::WriteBatch::new(relation::IN_CASE);
            match variant {
                "mirror" => write.set_vertex_property(
                    recorded.control_entry,
                    property::FA_EFFECTIVE_DAY,
                    Some(CanonicalScalar::Int(1)),
                ),
                "deleted claim" => write.delete_vertex(outcome(&h, kind)),
                "retargeted claim" => write.set_vertex_property(
                    outcome(&h, kind),
                    property::TARGET_REF,
                    Some(CanonicalScalar::bytes(VId(219).0.to_le_bytes().to_vec()).unwrap()),
                ),
                _ => unreachable!(),
            };
            h.write_raw(write);
            let head = h.db.frontier().unwrap();
            let rows = h.db.vertices().unwrap();
            assert!(
                read_draft(&h.db, &h.ctx().query(), &h.book, NAME).is_err(),
                "record kind {kind}, {variant}"
            );
            assert!(
                !matches!(execute(&mut h, kind, target, &request), Ok(Ok(_))),
                "record kind {kind}, {variant}"
            );
            assert_eq!(h.db.frontier().unwrap(), head);
            assert_eq!(h.db.vertices().unwrap(), rows);
        }
    }
}

#[test]
fn an_authentic_claim_free_draft_retries_after_compaction_and_durable_reopen() {
    let mut producer = harness();
    let original_request = request(&producer, 0);
    let first = producer
        .open_draft(original_request.capability.clone(), NAME)
        .unwrap();
    let claim = outcome(&producer, 0);
    let mut original = fgdb::WriteBatch::new(relation::IN_CASE);
    let mut created = std::collections::BTreeSet::new();
    for row in producer.db.vertices_at(first.recorded_at).unwrap() {
        if row.created_at == first.recorded_at && row.vid != claim {
            assert!(created.insert(row.vid));
            original.create_vertex(row.vid, row.labels, row.props);
        }
    }
    assert_eq!(created.len(), 2);
    for edge in producer.db.edges_at(first.recorded_at).unwrap() {
        if created.contains(&edge.entry.src) {
            assert_eq!(edge.entry.relation, relation::IN_CASE);
            original.add_edge(edge.entry.eid, edge.entry.src, edge.entry.dst, edge.props);
        }
    }
    let mut h = harness_legacy();
    h.write_raw(original);
    let sequence = h.db.frontier().unwrap();
    let original_row = h.db.vertex(first.control_entry).unwrap().unwrap();
    let ctx = h.ctx();
    h.runtime.block_on(h.db.compact(&ctx.commit())).unwrap();
    let (vfs, keys) = h.legacy_storage.clone().unwrap();
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
    let head = h.db.frontier().unwrap();
    let retry = h.open_draft(original_request.capability, NAME).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(
        (retry.control_entry, retry.recorded_at),
        (first.control_entry, sequence)
    );
    assert_eq!(
        h.db.vertex(first.control_entry).unwrap().unwrap(),
        original_row
    );
    assert!(h.db.vertex(claim).unwrap().is_none());
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(matches!(
        h.db.delta_since(CommitSeq(0)),
        Err(fgdb::ReadError::DeltaCursorRetired { .. })
    ));
}
