use super::*;
use fa_journal::period_creation::{PeriodCreation, creation_vid};
use fa_journal::refusal::{Outcome, code};
use fa_model::ApprovalRef;
use fa_model::symbols::label;
use fa_time::PeriodDef;
use fgdb::{VertexRow, WriteBatch};
use fgdb_types::CommitSeq;

#[derive(Clone)]
struct CreationRequest {
    year: i32,
    principal: VId,
    description: Erasable<String>,
}

fn request(h: &Harness, year: i32, principal: VId) -> CreationRequest {
    CreationRequest {
        year,
        principal,
        description: h.statement("period creation outcome", 151),
    }
}

fn execute(
    h: &mut Harness,
    request: &CreationRequest,
    capability: &Capability,
) -> Outcome<(CommitSeq, Vec<PeriodDef>)> {
    let ctx = h.ctx();
    h.runtime.block_on(create_periods(
        &mut h.db,
        &ctx,
        &h.book,
        request.year,
        request.principal,
        request.description.clone(),
        capability,
    ))
}

fn record(
    h: &mut Harness,
    request: &CreationRequest,
) -> Result<(CommitSeq, Vec<PeriodDef>), Refusal> {
    execute(
        h,
        request,
        &Capability::embedded(request.principal, &["schema_change"]).unwrap(),
    )
    .expect("period creation kernel")
}

fn outcome(h: &Harness, request: &CreationRequest) -> VId {
    fa_model::intent_outcome_vid(
        h.book.book_id,
        &request.principal.0.to_le_bytes(),
        &request.year.to_le_bytes(),
    )
}

fn refused_without_publication(h: &mut Harness, request: &CreationRequest, expected: &str) {
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let edges = h.db.edges_at(head).unwrap();
    let refusal = record(h, request).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), (expected, exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert_eq!(h.db.edges_at(head).unwrap(), edges);
}

/// Reproduce the old writer's original native publication, excluding its
/// modern claim before anything is committed to the legacy store. The source
/// prefix preserves closed birth states even when its current periods opened.
fn legacy_batches(
    producer: &Harness,
    year: i32,
    approvals: Vec<ApprovalRef>,
    plan: Option<Oid>,
) -> (Vec<WriteBatch>, Vec<PeriodDef>) {
    let target = creation_vid(&producer.book, year);
    let (entry, sequence) = read_entry(&producer.db, target).unwrap().unwrap();
    let claim = fa_model::intent_outcome_vid(
        producer.book.book_id,
        &entry.proposal.principal_ref.0.to_le_bytes(),
        &year.to_le_bytes(),
    );
    let Some(ControlPayload::SchemaChange {
        kind: 13,
        canonical_bytes,
    }) = &entry.proposal.control
    else {
        panic!("period birth control");
    };
    let periods = PeriodCreation::decode(canonical_bytes)
        .unwrap()
        .definitions();
    let entry = entry.proposal.seal(approvals, plan).unwrap();
    let mut vertices = WriteBatch::new(relation::IN_BOOK);
    let mut created = std::collections::BTreeSet::new();
    for row in producer.db.vertices_at(sequence).unwrap() {
        if row.created_at != sequence || row.vid == claim {
            continue;
        }
        assert!(
            row.labels
                .iter()
                .all(|kind| matches!(*kind, label::ENTRY | label::PERIOD | label::LIMIT_CELL))
        );
        assert!(created.insert(row.vid));
        let props = if row.vid == target {
            fa_model::entry_mirrors(&entry).unwrap()
        } else {
            row.props
        };
        vertices.create_vertex(row.vid, row.labels, props);
    }
    assert!(created.contains(&target));
    let mut edges = WriteBatch::new(relation::IN_BOOK);
    let mut edge_count = 0;
    for edge in producer.db.edges_at(sequence).unwrap() {
        if created.contains(&edge.entry.src) {
            assert_eq!(edge.entry.relation, relation::IN_BOOK);
            assert_eq!(edge.entry.dst, book_root());
            edges.add_edge(edge.entry.eid, edge.entry.src, edge.entry.dst, edge.props);
            edge_count += 1;
        }
    }
    assert_eq!(edge_count, periods.len() + 1);
    (vec![vertices, edges], periods)
}

fn publish_legacy(
    runtime: &Runtime,
    db: &mut Database<MemVfs>,
    ctx: &PurposeContexts,
    batches: Vec<WriteBatch>,
) -> CommitSeq {
    let mut txn = db.begin(&ctx.txn()).unwrap();
    txn.write_ordered(db, batches).unwrap();
    runtime.block_on(txn.commit(db, &ctx.commit())).unwrap()
}

pub(super) fn write_legacy_bootstrap(
    runtime: &Runtime,
    db: &mut Database<MemVfs>,
    ctx: &PurposeContexts,
    book: &BookContext,
) -> (CommitSeq, Vec<PeriodDef>) {
    let producer = harness();
    assert_eq!(producer.book.book_id, book.book_id);
    assert_eq!(producer.book.calendar, book.calendar);
    let (batches, periods) = legacy_batches(&producer, 2026, Vec::new(), None);
    let sequence = publish_legacy(runtime, db, ctx, batches);
    assert!(
        db.vertex(fa_model::intent_outcome_vid(
            book.book_id,
            &PRINCIPAL.0.to_le_bytes(),
            &2026_i32.to_le_bytes(),
        ))
        .unwrap()
        .is_none()
    );
    (sequence, periods)
}

fn write_legacy(
    h: &mut Harness,
    request: &CreationRequest,
    approvals: Vec<ApprovalRef>,
    plan: Option<Oid>,
) -> (CommitSeq, Vec<PeriodDef>) {
    let mut producer = harness();
    record(&mut producer, request).unwrap();
    let (batches, periods) = legacy_batches(&producer, request.year, approvals, plan);
    let ctx = h.ctx();
    let sequence = publish_legacy(&h.runtime, &mut h.db, &ctx, batches);
    assert!(h.db.vertex(outcome(h, request)).unwrap().is_none());
    (sequence, periods)
}

#[test]
fn posting_keys_cannot_create_periods_or_observe_another_creators_target() {
    for existing_target in [false, true] {
        for family in [
            "original",
            "reversal",
            "replacement",
            "pending",
            "resolution",
            "batch",
        ] {
            let mut h = harness();
            let principal = if existing_target { VId(71) } else { PRINCIPAL };
            let year = if existing_target { 2026_i32 } else { 2027_i32 };
            let key = year.to_le_bytes();
            let source = h.proposal(h.rent_legs(100), b"period-key-source", EntryClass::ORIGINAL);
            let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
            let mut occupied = match family {
                "original" | "batch" => h.proposal(h.rent_legs(200), &key, EntryClass::ORIGINAL),
                "reversal" => h.reversal_of_entry(target, &key),
                "replacement" => replacement_proposal(
                    target,
                    h.proposal(h.rent_legs(125), &key, EntryClass::REPLACEMENT),
                ),
                "pending" => h.pending(h.rent_legs(200), &key),
                "resolution" => {
                    let pending = h.pending(h.rent_legs(200), b"period-key-hold");
                    let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
                    h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], &key)
                }
                _ => unreachable!(),
            };
            occupied.principal_ref = principal;
            if family == "replacement" {
                let mut reversal = h.reversal_of_entry(target, b"period-key-pair");
                reversal.principal_ref = principal;
                h.post_pair(
                    h.request(reversal, &["post"]),
                    h.request(occupied, &["post"]),
                )
                .unwrap();
            } else if family == "batch" {
                occupied.idempotency_key = b"period-key-member".to_vec();
                h.post_batch(h.batch(&key, vec![occupied])).unwrap();
            } else {
                h.post(h.request(occupied, &["post"])).unwrap();
            }
            let creation = request(&h, year, principal);
            refused_without_publication(&mut h, &creation, code::IDEMPOTENCY_CONFLICT);
        }
    }
}

#[test]
fn period_creation_claims_publish_with_every_birth_and_block_posting_families() {
    let mut h = harness();
    let source = h.proposal(h.rent_legs(100), b"period-source", EntryClass::ORIGINAL);
    let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
    let pending = h.pending(h.rent_legs(200), b"period-hold");
    let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
    let creation = request(&h, 2027, PRINCIPAL);
    let key = creation.year.to_le_bytes();
    let before = h.db.frontier().unwrap();
    let vertices_before = h.db.vertices().unwrap().len();
    let edges_before = h.db.edges_at(before).unwrap().len();
    let first = record(&mut h, &creation).unwrap();
    assert_eq!(first.0.0, before.0 + 1);
    assert_eq!(
        h.db.vertices().unwrap().len() - vertices_before,
        first.1.len() + 2
    );
    assert_eq!(
        h.db.edges_at(first.0).unwrap().len() - edges_before,
        first.1.len() + 1
    );
    let control =
        h.db.vertex(creation_vid(&h.book, creation.year))
            .unwrap()
            .unwrap();
    let claim = h.db.vertex(outcome(&h, &creation)).unwrap().unwrap();
    assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
    assert_eq!((control.created_at, claim.created_at), (first.0, first.0));
    assert_eq!(
        fa_journal::rows::prop(&claim, property::TARGET_REF),
        Some(&CanonicalScalar::bytes(control.vid.0.to_le_bytes().to_vec()).unwrap()),
    );
    for period in &first.1 {
        assert_eq!(
            h.db.vertex(period_vid(&h.book.calendar.id, &period.code))
                .unwrap()
                .unwrap()
                .created_at,
            first.0,
        );
    }
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let original = h.proposal(h.rent_legs(300), &key, EntryClass::ORIGINAL);
    let reversal = h.reversal_of_entry(target, &key);
    let pending = h.pending(h.rent_legs(300), &key);
    let resolution = h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], &key);
    for proposal in [original, reversal, pending, resolution] {
        let refusal = h.post(h.request(proposal, &["post"])).unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT)
        );
    }
    let reversal = h.request(
        h.reversal_of_entry(target, b"period-unpublished-reversal"),
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
    let member = h.proposal(
        h.rent_legs(300),
        b"period-unpublished-member",
        EntryClass::ORIGINAL,
    );
    assert_eq!(
        h.post_batch(h.batch(&key, vec![member])).unwrap_err().code,
        code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    assert!(h.db.vertex(resolution_vid(hold.vid)).unwrap().is_none());
}

#[test]
fn period_creation_retries_preserve_original_result_and_creator_after_transitions() {
    let mut h = harness();
    let original = request(&h, 2027, PRINCIPAL);
    let first = record(&mut h, &original).unwrap();
    let period = first
        .1
        .iter()
        .find(|period| period.kind == PeriodKind::Normal)
        .unwrap();
    h.transition(&period.code, PeriodTransition::Open, b"period-retry-open")
        .unwrap();
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    assert_eq!(record(&mut h, &original).unwrap(), first);
    let mut resealed = original.clone();
    resealed.description = h.statement("period creation outcome", 152);
    assert_eq!(record(&mut h, &resealed).unwrap(), first);
    let mut changed = original.clone();
    changed.description = h.statement("different period creation", 153);
    refused_without_publication(&mut h, &changed, code::IDEMPOTENCY_CONFLICT);
    let another = request(&h, 2027, VId(72));
    assert_eq!(record(&mut h, &another).unwrap(), first);
    assert!(h.db.vertex(outcome(&h, &another)).unwrap().is_none());
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
    let (entry, _) = read_entry(&h.db, creation_vid(&h.book, 2027))
        .unwrap()
        .unwrap();
    assert_eq!(entry.proposal.principal_ref, PRINCIPAL);
    let mut wrong_calendar = h.book.clone();
    wrong_calendar.calendar = FiscalCalendar::monthly("other-calendar", 1, 1).unwrap();
    let ctx = h.ctx();
    assert!(
        h.runtime
            .block_on(create_periods(
                &mut h.db,
                &ctx,
                &wrong_calendar,
                original.year,
                original.principal,
                original.description.clone(),
                &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            ))
            .is_err()
    );
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn a_prepared_reversal_loses_to_period_creation_at_the_same_scoped_key() {
    let mut h = harness();
    let source = h.proposal(
        h.rent_legs(100),
        b"period-race-source",
        EntryClass::ORIGINAL,
    );
    let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
    let creation = request(&h, 2027, PRINCIPAL);
    let reversal = h.request(
        h.reversal_of_entry(target, &creation.year.to_le_bytes()),
        &["post"],
    );
    let ctx = h.ctx();
    let PostPreparation::Ready(prepared) = prepare_post(&mut h.db, &ctx, &h.book, reversal)
        .unwrap()
        .unwrap()
    else {
        panic!("fresh reversal");
    };
    let epoch = security_policy_epoch(&h.db).unwrap();
    record(&mut h, &creation).unwrap();
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
fn legacy_period_creation_retries_survive_recovery_and_durable_reopen() {
    let mut h = harness_legacy();
    let original = request(&h, 2027, PRINCIPAL);
    let first = write_legacy(&mut h, &original, Vec::new(), None);
    let target = creation_vid(&h.book, original.year);
    let original_row = h.db.vertex(target).unwrap().unwrap();
    let head = h.db.frontier().unwrap();
    assert_eq!(record(&mut h, &original).unwrap(), first);
    assert_eq!(h.db.frontier().unwrap(), head);
    let another = request(&h, 2027, VId(73));
    refused_without_publication(&mut h, &another, code::PLAN_INVALIDATED);
    let fresh = request(&h, 2028, PRINCIPAL);
    refused_without_publication(&mut h, &fresh, code::PLAN_INVALIDATED);
    let source = h.proposal(
        h.rent_legs(100),
        b"legacy-period-source",
        EntryClass::ORIGINAL,
    );
    let source_ref = outcome_recovery_tests::write_legacy(&mut h, source);
    let mut reversal = h.reversal_of_entry(source_ref, &2027_i32.to_le_bytes());
    reversal.principal_ref = another.principal;
    outcome_recovery_tests::write_legacy(&mut h, reversal);
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
    assert_eq!(record(&mut h, &original).unwrap(), first);
    assert_eq!(h.db.vertex(target).unwrap().unwrap(), original_row);
    assert_eq!(h.db.frontier().unwrap(), head);
    refused_without_publication(&mut h, &another, code::IDEMPOTENCY_CONFLICT);
    let unused = request(&h, 2027, VId(74));
    assert_eq!(record(&mut h, &unused).unwrap(), first);
    assert_eq!(h.db.frontier().unwrap(), head);
    let second = record(&mut h, &fresh).unwrap();
    assert_eq!(
        h.db.vertex(outcome(&h, &fresh))
            .unwrap()
            .unwrap()
            .created_at,
        second.0
    );
}

fn replace_row(h: &mut Harness, row: &VertexRow, entry: &fa_model::Entry) {
    let mut write = WriteBatch::new(relation::IN_BOOK);
    for (key, value) in fa_model::entry_mirrors(entry).unwrap() {
        write.set_vertex_property(row.vid, key, Some(value));
    }
    h.write_raw(write);
}

#[test]
fn altered_period_control_envelopes_and_deleted_or_retargeted_claims_never_retry() {
    for variant in [
        "approvals",
        "plan",
        "mirror",
        "deleted claim",
        "retargeted claim",
    ] {
        let mut h = harness();
        let original = request(&h, 2027, PRINCIPAL);
        record(&mut h, &original).unwrap();
        let target = creation_vid(&h.book, 2027);
        let row = h.db.vertex(target).unwrap().unwrap();
        let (entry, _) = read_entry(&h.db, target).unwrap().unwrap();
        match variant {
            "approvals" => {
                let approval = h.approve_digest(VId(75), entry.proposal_digest).unwrap();
                replace_row(
                    &mut h,
                    &row,
                    &entry.proposal.seal(vec![approval], None).unwrap(),
                );
            }
            "plan" => replace_row(
                &mut h,
                &row,
                &entry
                    .proposal
                    .seal(Vec::new(), Some(Oid([77; 32])))
                    .unwrap(),
            ),
            "mirror" => {
                let mut write = WriteBatch::new(relation::IN_BOOK);
                write.set_vertex_property(
                    target,
                    property::FA_EFFECTIVE_DAY,
                    Some(CanonicalScalar::Int(1)),
                );
                h.write_raw(write);
            }
            "deleted claim" => {
                let mut write = WriteBatch::new(relation::IN_BOOK);
                write.delete_vertex(outcome(&h, &original));
                h.write_raw(write);
            }
            "retargeted claim" => {
                let mut write = WriteBatch::new(relation::IN_BOOK);
                write.set_vertex_property(
                    outcome(&h, &original),
                    property::TARGET_REF,
                    Some(CanonicalScalar::bytes(VId(78).0.to_le_bytes().to_vec()).unwrap()),
                );
                h.write_raw(write);
            }
            _ => unreachable!(),
        }
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        assert!(
            !matches!(
                execute(
                    &mut h,
                    &original,
                    &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap()
                ),
                Ok(Ok(_))
            ),
            "{variant}"
        );
        assert_eq!(h.db.frontier().unwrap(), head, "{variant}");
        assert_eq!(h.db.vertices().unwrap(), rows, "{variant}");
    }
    for plan in [None, Some(Oid([77; 32]))] {
        let mut h = harness_legacy();
        let original = request(&h, 2027, PRINCIPAL);
        let approvals = if plan.is_none() {
            vec![h.approve_digest(VId(75), [11; 32]).unwrap()]
        } else {
            Vec::new()
        };
        write_legacy(&mut h, &original, approvals, plan);
        refused_without_publication(&mut h, &original, code::IDEMPOTENCY_CONFLICT);
    }
}

#[test]
fn period_creation_authority_precedes_malformed_claim_observation() {
    let mut h = harness();
    let original = request(&h, 2027, PRINCIPAL);
    let mut write = WriteBatch::new(relation::IN_BOOK);
    write.create_vertex(
        outcome(&h, &original),
        vec![label::INTENT_OUTCOME],
        vec![(
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(vec![0]).unwrap(),
        )],
    );
    h.write_raw(write);
    let head = h.db.frontier().unwrap();
    for capability in [
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(VId(79), &["schema_change"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["schema_change"])
            .unwrap()
            .for_classes(&[EntryClass::ORIGINAL])
            .unwrap(),
        Capability::embedded(PRINCIPAL, &["schema_change"])
            .unwrap()
            .with_requires_dry_run(),
    ] {
        let refused = execute(&mut h, &original, &capability)
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, code::CAPABILITY);
        assert_eq!(h.db.frontier().unwrap(), head);
    }
}
