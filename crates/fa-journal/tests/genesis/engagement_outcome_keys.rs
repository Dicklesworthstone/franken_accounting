//! Engagement lifecycle records share the successful-intent namespace with
//! postings, while retaining their historical derived identities.

use super::*;
use fa_journal::engagement::{
    EngagementKind, EngagementOpened, EngagementProfile, EngagementRequest, Materiality,
};
use fa_journal::refusal::{Outcome, code};
use fa_model::symbols::label;
use fgdb_types::CommitSeq;

fn request(h: &Harness, name: &str, key: &[u8]) -> (EngagementProfile, EngagementRequest) {
    let capability = Capability::embedded(PRINCIPAL, &["produce", "read"]).unwrap();
    (
        EngagementProfile {
            book_id: h.book.book_id,
            engagement: name.into(),
            kind: EngagementKind::Audit,
            firm_principal: PRINCIPAL,
            scope_periods: vec![h.march.clone()],
            unit: h.usd,
            materiality: Materiality {
                overall: 10_000,
                performance: 7_500,
                clearly_trivial: 100,
            },
            report_release_day: Some(h.day()),
            capability_commitment: capability.commitment().unwrap(),
        },
        EngagementRequest {
            capability,
            effective_date: h.day(),
            description: h.statement("engagement outcome", 191),
            idempotency_key: key.to_vec(),
        },
    )
}

fn key(profile: &EngagementProfile, request: &EngagementRequest) -> Vec<u8> {
    fa_model::domain_digest(
        b"fa:engagement-record-key:v1",
        &[&[0], &profile.vid().0.to_le_bytes(), &request.idempotency_key],
    )
    .to_vec()
}

fn outcome(h: &Harness, profile: &EngagementProfile, request: &EngagementRequest) -> VId {
    fa_model::intent_outcome_vid(
        h.book.book_id,
        &request.capability.holder().0.to_le_bytes(),
        &key(profile, request),
    )
}

fn execute(h: &mut Harness, profile: &EngagementProfile, request: &EngagementRequest) -> Outcome<EngagementOpened> {
    let ctx = h.ctx();
    h.runtime.block_on(fa_journal::engagement::open_engagement(
        &mut h.db, &ctx, &h.book, profile.clone(), request.clone(),
    ))
}

fn assert_claim(h: &Harness, vid: VId, sequence: CommitSeq) {
    let (entry, recorded_at) = read_entry(&h.db, vid).unwrap().unwrap();
    let claim = h.db.vertex(fa_model::intent_outcome_vid(
        h.book.book_id,
        &entry.proposal.principal_ref.0.to_le_bytes(),
        &entry.proposal.idempotency_key,
    )).unwrap().unwrap();
    assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
    assert_eq!((recorded_at, claim.created_at), (sequence, sequence));
    assert_eq!(
        fa_journal::rows::prop(&claim, property::TARGET_REF),
        Some(&CanonicalScalar::bytes(vid.0.to_le_bytes().to_vec()).unwrap())
    );
}

#[test]
fn all_posting_families_reserve_keys_against_engagement_creation() {
    for family in ["original", "reversal", "replacement", "pending", "resolution", "batch"] {
        let mut h = harness();
        let (profile, request) = request(&h, "audit", b"shared");
        let key = key(&profile, &request);
        let source = h.proposal(h.rent_legs(100), b"engagement-source", EntryClass::ORIGINAL);
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
                let pending = h.pending(h.rent_legs(200), b"engagement-hold");
                let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
                h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], &key)
            }
            _ => unreachable!(),
        };
        if family == "replacement" {
            h.post_pair(
                h.request(h.reversal_of_entry(target, b"engagement-pair"), &["post"]),
                h.request(occupied, &["post"]),
            ).unwrap();
        } else if family == "batch" {
            let mut member = occupied;
            member.idempotency_key = b"engagement-member".to_vec();
            h.post_batch(h.batch(&key, vec![member])).unwrap();
        } else {
            h.post(h.request(occupied, &["post"])).unwrap();
        }
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let edges = h.db.edges_at(head).unwrap();
        let refused = execute(&mut h, &profile, &request).unwrap().unwrap_err();
        assert_eq!((refused.code, refused.exit), (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT), "{family}");
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(h.db.edges_at(head).unwrap(), edges);
        assert!(h.db.vertex(profile.vid()).unwrap().is_none());
    }
}

#[test]
fn an_engagement_claim_blocks_postings_pairs_and_outer_batches_atomically() {
    let mut h = harness();
    let source = h.proposal(h.rent_legs(100), b"blocked-source", EntryClass::ORIGINAL);
    let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
    let pending = h.pending(h.rent_legs(200), b"blocked-hold");
    let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
    let (profile, request) = request(&h, "audit", b"owned");
    execute(&mut h, &profile, &request).unwrap().unwrap();
    let key = key(&profile, &request);
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let edges = h.db.edges_at(head).unwrap();
    let original = h.proposal(h.rent_legs(300), &key, EntryClass::ORIGINAL);
    let reversal = h.reversal_of_entry(target, &key);
    let pending = h.pending(h.rent_legs(300), &key);
    let resolution = h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], &key);
    for proposal in [original, reversal, pending, resolution] {
        let refused = h.post(h.request(proposal, &["post"])).unwrap_err();
        assert_eq!((refused.code, refused.exit), (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT));
    }
    let reversal = h.request(h.reversal_of_entry(target, b"unpublished-reversal"), &["post"]);
    let replacement = h.request(
        replacement_proposal(target, h.proposal(h.rent_legs(125), &key, EntryClass::REPLACEMENT)),
        &["post"],
    );
    assert_eq!(h.post_pair(reversal, replacement).unwrap_err().code, code::IDEMPOTENCY_CONFLICT);
    let member = h.proposal(h.rent_legs(300), b"unpublished-member", EntryClass::ORIGINAL);
    assert_eq!(h.post_batch(h.batch(&key, vec![member])).unwrap_err().code, code::IDEMPOTENCY_CONFLICT);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
    assert_eq!(h.db.edges_at(head).unwrap(), edges);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    assert!(h.db.vertex(resolution_vid(hold.vid)).unwrap().is_none());
}

#[test]
fn exact_retries_bind_profile_date_and_text_without_consuming_a_sequence() {
    let mut h = harness();
    let (profile, original) = request(&h, "audit", b"retry");
    let first = execute(&mut h, &profile, &original).unwrap().unwrap();
    assert_claim(&h, first.control_entry, first.recorded_at);
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    for description in [original.description.clone(), h.statement("engagement outcome", 192)] {
        let mut retry = original.clone();
        retry.description = description;
        let again = execute(&mut h, &profile, &retry).unwrap().unwrap();
        assert!(again.already_recorded);
        assert_eq!((again.control_entry, again.recorded_at), (first.control_entry, first.recorded_at));
    }
    let mut changed_profile = profile.clone();
    changed_profile.materiality.overall += 1;
    assert_eq!(execute(&mut h, &changed_profile, &original).unwrap().unwrap_err().code, code::IDEMPOTENCY_CONFLICT);
    let mut changed = original.clone();
    changed.effective_date = DateDay::from_ymd(2026, 3, 16).unwrap();
    assert_eq!(execute(&mut h, &profile, &changed).unwrap().unwrap_err().code, code::IDEMPOTENCY_CONFLICT);
    changed = original.clone();
    changed.description = h.statement("different engagement outcome", 193);
    assert_eq!(execute(&mut h, &profile, &changed).unwrap().unwrap_err().code, code::IDEMPOTENCY_CONFLICT);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn proposed_passed_completed_and_filed_records_keep_claims_and_original_retry_states() {
    use fa_journal::engagement::{AdjustmentDecision, ProposalLeg};
    let mut h = harness();
    let (profile, open) = request(&h, "audit", b"open");
    execute(&mut h, &profile, &open).unwrap().unwrap();
    let (_, proposed_request) = request(&h, "audit", b"propose");
    let legs = vec![
        ProposalLeg { side: Side::Debit, account: h.rent, amount: Amount::new(h.usd, 100) },
        ProposalLeg { side: Side::Credit, account: h.cash, amount: Amount::new(h.usd, 100) },
    ];
    let date = h.day();
    let ctx = h.ctx();
    let proposed = h.runtime.block_on(fa_journal::engagement::propose_adjustment(
        &mut h.db, &ctx, &h.book, "audit", date, legs.clone(), proposed_request.clone(),
    )).unwrap().unwrap();
    assert_claim(&h, proposed.control_entry, proposed.recorded_at);
    let (_, pass) = request(&h, "audit", b"pass");
    let passed = h.runtime.block_on(fa_journal::engagement::decide_adjustment(
        &mut h.db, &ctx, &h.book, "audit", 1,
        AdjustmentDecision::Pass { reason_code: 1 }, pass.clone(),
    )).unwrap().unwrap();
    assert_claim(&h, passed.control_entry, passed.recorded_at);
    let doc = h.document(INVOICE, HUMAN_UPLOAD, b"engagement workpaper");
    h.add_document(&doc).unwrap();
    let (_, file) = request(&h, "audit", b"file");
    let filed = h.runtime.block_on(fa_journal::engagement::file_workpaper(
        &mut h.db, &ctx, &h.book, "audit", doc.oid(), file.clone(),
    )).unwrap().unwrap();
    assert_claim(&h, filed.control_entry, filed.recorded_at);
    assert!(!filed.added_after_completion);
    let (_, complete) = request(&h, "audit", b"complete");
    let completed = h.runtime.block_on(fa_journal::engagement::complete_documentation(
        &mut h.db, &ctx, &h.book, "audit", None, date, complete,
    )).unwrap().unwrap();
    assert_claim(&h, completed.control_entry, completed.recorded_at);
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let retried = h.runtime.block_on(fa_journal::engagement::propose_adjustment(
        &mut h.db, &ctx, &h.book, "audit", date, legs, proposed_request,
    )).unwrap().unwrap();
    assert!(retried.already_recorded);
    assert_eq!((retried.control_entry, retried.recorded_at), (proposed.control_entry, proposed.recorded_at));
    let filed_again = h.runtime.block_on(fa_journal::engagement::file_workpaper(
        &mut h.db, &ctx, &h.book, "audit", doc.oid(), file,
    )).unwrap().unwrap();
    assert!(filed_again.already_recorded);
    assert!(!filed_again.added_after_completion);
    let changed = h.runtime.block_on(fa_journal::engagement::decide_adjustment(
        &mut h.db, &ctx, &h.book, "audit", 1,
        AdjustmentDecision::Pass { reason_code: 2 }, pass,
    )).unwrap().unwrap_err();
    assert_eq!(changed.code, code::IDEMPOTENCY_CONFLICT);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn a_prepared_reversal_loses_to_an_engagement_claim() {
    let mut h = harness();
    let source = h.proposal(h.rent_legs(100), b"race-source", EntryClass::ORIGINAL);
    let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
    let (profile, request) = request(&h, "audit", b"race");
    let reversal = h.request(h.reversal_of_entry(target, &key(&profile, &request)), &["post"]);
    let ctx = h.ctx();
    let PostPreparation::Ready(prepared) = prepare_post(&mut h.db, &ctx, &h.book, reversal).unwrap().unwrap() else {
        panic!("fresh reversal");
    };
    execute(&mut h, &profile, &request).unwrap().unwrap();
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let refused = h.runtime.block_on(prepared.commit(&mut h.db, &ctx)).unwrap().unwrap_err();
    assert_eq!(refused.exit, exit::CONFLICT);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
}

#[test]
fn authority_precedes_malformed_claim_observation() {
    let mut h = harness();
    let (profile, original) = request(&h, "audit", b"denied");
    let mut write = fgdb::WriteBatch::new(relation::IN_CASE);
    write.create_vertex(outcome(&h, &profile, &original), vec![label::INTENT_OUTCOME], vec![
        (property::FA_PAYLOAD, CanonicalScalar::bytes(vec![0]).unwrap()),
    ]);
    h.write_raw(write);
    let head = h.db.frontier().unwrap();
    for capability in [
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["produce"]).unwrap().for_classes(&[EntryClass::ORIGINAL]).unwrap(),
        Capability::embedded(PRINCIPAL, &["produce"]).unwrap().with_requires_dry_run(),
    ] {
        let mut denied_profile = profile.clone();
        denied_profile.capability_commitment = capability.commitment().unwrap();
        let mut denied = original.clone();
        denied.capability = capability;
        let refused = execute(&mut h, &denied_profile, &denied).unwrap().unwrap_err();
        assert_eq!(refused.code, code::CAPABILITY);
        assert_eq!(h.db.frontier().unwrap(), head);
    }
}

#[test]
fn rewritten_records_and_missing_or_retargeted_modern_claims_never_retry_as_legacy() {
    for variant in ["mirror", "deleted claim", "retargeted claim"] {
        let mut h = harness();
        let (profile, request) = request(&h, "audit", b"damaged");
        let recorded = execute(&mut h, &profile, &request).unwrap().unwrap();
        let mut write = fgdb::WriteBatch::new(relation::IN_CASE);
        match variant {
            "mirror" => write.set_vertex_property(recorded.control_entry, property::FA_EFFECTIVE_DAY, Some(CanonicalScalar::Int(1))),
            "deleted claim" => write.delete_vertex(outcome(&h, &profile, &request)),
            "retargeted claim" => write.set_vertex_property(
                outcome(&h, &profile, &request), property::TARGET_REF,
                Some(CanonicalScalar::bytes(VId(199).0.to_le_bytes().to_vec()).unwrap()),
            ),
            _ => unreachable!(),
        };
        h.write_raw(write);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        assert!(fa_journal::engagement::read_engagement(&h.db, &h.book, "audit").is_err(), "{variant}");
        assert!(!matches!(execute(&mut h, &profile, &request), Ok(Ok(_))), "{variant}");
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn an_authentic_claim_free_engagement_survives_compaction_and_durable_reopen() {
    let mut producer = harness();
    let (profile, request) = request(&producer, "legacy-audit", b"legacy");
    let first = execute(&mut producer, &profile, &request).unwrap().unwrap();
    let claim = outcome(&producer, &profile, &request);
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
    let empty = h.runtime.block_on(Database::open_memory(&ctx.commit(), keys.clone())).unwrap();
    drop(std::mem::replace(&mut h.db, empty));
    h.db = h.runtime.block_on(Database::open_with_vfs(
        &ctx.commit(), vfs.clone(), vfs.database_dir(), keys,
    )).unwrap();
    let head = h.db.frontier().unwrap();
    let retry = execute(&mut h, &profile, &request).unwrap().unwrap();
    assert!(retry.already_recorded);
    assert_eq!((retry.control_entry, retry.recorded_at), (first.control_entry, sequence));
    assert_eq!(h.db.vertex(first.control_entry).unwrap().unwrap(), original_row);
    assert!(h.db.vertex(claim).unwrap().is_none());
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(matches!(h.db.delta_since(CommitSeq(0)), Err(fgdb::ReadError::DeltaCursorRetired { .. })));
}
