//! Real legacy births, explicit recovery, durable reopen, and scratch replay.

use super::*;
use fa_journal::refusal::code;
use fa_model::symbols::label;
use fgdb::WriteBatch;
use fgdb_types::CommitSeq;

/// The earlier native writer's original Entry/projections, with no common
/// claim. This is used only in a separately constructed legacy genesis.
pub(super) fn write_legacy(h: &mut Harness, proposal: EntryPayload) -> EntryRef {
    let vid = match proposal.class {
        EntryClass::REVERSAL => reversal_vid(proposal.supersession[0].target.vid),
        _ => entry_vid(
            h.book.book_id,
            &proposal.principal_ref.0.to_le_bytes(),
            &proposal.idempotency_key,
        ),
    };
    let entry = proposal.seal(Vec::new(), None).unwrap();
    let mut rows = WriteBatch::new(relation::HAS_LEG);
    rows.create_vertex(
        vid,
        vec![label::ENTRY],
        fa_model::entry_mirrors(&entry).unwrap(),
    );
    let mut accounts = WriteBatch::new(relation::POSTS_TO);
    let mut units = WriteBatch::new(relation::IN_UNIT);
    for (index, leg) in entry.proposal.legs.iter().enumerate() {
        assert!(leg.dimension_set.is_empty());
        let ordinal = u16::try_from(index).unwrap();
        let lvid = leg_vid(vid, ordinal);
        let mut props =
            fa_model::leg_mirrors(leg, ordinal, entry.proposal.effective_date, &h.book.units)
                .unwrap();
        props.push((
            property::APPLIED,
            fa_journal::rows::mantissa_scalar("legacy applied", 0).unwrap(),
        ));
        rows.create_vertex(lvid, vec![label::LEG], props);
        rows.add_edge(
            edge_id(relation::HAS_LEG, vid, lvid),
            vid,
            lvid,
            vec![(property::ORDINAL, CanonicalScalar::Int(i64::from(ordinal)))],
        );
        accounts.add_edge(
            edge_id(relation::POSTS_TO, lvid, leg.account_ref),
            lvid,
            leg.account_ref,
            vec![],
        );
        let unit = h.book.units.get(leg.amount.unit).unwrap();
        let uvid = fa_model::unit_vid(h.book.book_id, &format!("{}@v{}", unit.code, unit.version));
        units.add_edge(edge_id(relation::IN_UNIT, lvid, uvid), lvid, uvid, vec![]);
    }
    let mut periods = WriteBatch::new(relation::IN_PERIOD);
    let pvid = period_vid(&h.book.calendar.id, &h.march);
    periods.add_edge(edge_id(relation::IN_PERIOD, vid, pvid), vid, pvid, vec![]);
    let mut evidence = WriteBatch::new(relation::EVIDENCED_BY);
    for source in &entry.proposal.evidence {
        let doc = document_vid(&source.document_oid);
        evidence.add_edge(edge_id(relation::EVIDENCED_BY, vid, doc), vid, doc, vec![]);
    }
    let mut supersedes = WriteBatch::new(relation::SUPERSEDES);
    for target in &entry.proposal.supersession {
        supersedes.add_edge(
            edge_id(relation::SUPERSEDES, vid, target.target.vid),
            vid,
            target.target.vid,
            vec![],
        );
    }
    // fgdb refuses an empty batch: an entry without evidence or
    // supersession writes neither relation.
    let mut batches = vec![rows, accounts, units, periods];
    if !entry.proposal.evidence.is_empty() {
        batches.push(evidence);
    }
    if !entry.proposal.supersession.is_empty() {
        batches.push(supersedes);
    }
    let cx = h.ctx();
    let mut txn = h.db.begin(&cx.txn()).unwrap();
    txn.write_ordered(&mut h.db, batches).unwrap();
    h.runtime
        .block_on(txn.commit(&mut h.db, &cx.commit()))
        .unwrap();
    entry.entry_ref(vid)
}

fn legacy_pair() -> (Harness, EntryPayload, EntryPayload) {
    let mut h = harness_legacy();
    let original = h.proposal(h.rent_legs(100), b"old-original", EntryClass::ORIGINAL);
    let target = write_legacy(&mut h, original.clone());
    let reversal = h.reversal_of_entry(target, b"old-reversal");
    write_legacy(&mut h, reversal.clone());
    (h, original, reversal)
}

fn rebuild(h: &mut Harness) -> OutcomeRebuild {
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
        .unwrap()
}

fn reopen(h: &mut Harness) {
    let cx = h.ctx();
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
    assert!(matches!(
        h.db.delta_since(CommitSeq(0)),
        Err(fgdb::ReadError::DeltaCursorRetired { .. })
    ));
}

#[test]
fn explicit_legacy_recovery_is_atomic_durable_and_unblocks_only_unused_keys() {
    let (mut h, original, reversal) = legacy_pair();
    let old_head = h.db.frontier().unwrap();
    // Existing semantic retries stay readable, even before upgrading.
    for proposal in [&original, &reversal] {
        assert!(matches!(
            h.post(h.request(proposal.clone(), &["post"])).unwrap(),
            Posted::AlreadyRecorded { .. }
        ));
    }
    assert_eq!(h.db.frontier().unwrap(), old_head);
    let fresh = h.proposal(h.rent_legs(25), b"after-upgrade", EntryClass::ORIGINAL);
    let refusal = h.post(h.request(fresh.clone(), &["post"])).unwrap_err();
    assert_eq!(refusal.code, code::PLAN_INVALIDATED);
    assert!(refusal.fix.contains("recover outcomes"));
    assert_eq!(h.db.frontier().unwrap(), old_head);

    let cx = h.ctx();
    let cap = Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap();
    let preview = h
        .runtime
        .block_on(prepare_outcome_rebuild(&mut h.db, &cx, &h.book, cap))
        .unwrap()
        .unwrap();
    assert_eq!(preview.preview().basis, old_head);
    assert_eq!(preview.preview().outcomes_created, 2);
    assert!(preview.preview().entries_checked >= 2);
    assert!(!preview.preview().already_covered);
    assert_eq!(h.db.frontier().unwrap(), old_head);
    preview.abort();
    assert!(
        h.db.vertex(fa_journal::outcome::coverage_vid(h.book.book_id))
            .unwrap()
            .is_none()
    );

    let result = rebuild(&mut h);
    assert!(result.wrote);
    assert_eq!(result.outcomes_created, 2);
    assert_eq!(result.recorded_at, CommitSeq(old_head.0 + 1));
    for proposal in [&original, &reversal] {
        let claim =
            h.db.vertex(fa_model::intent_outcome_vid(
                h.book.book_id,
                &proposal.principal_ref.0.to_le_bytes(),
                &proposal.idempotency_key,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(claim.created_at, result.recorded_at);
    }
    reopen(&mut h);
    let no_op = rebuild(&mut h);
    assert!(!no_op.wrote);
    assert_eq!(no_op.recorded_at, result.recorded_at);
    assert_eq!(h.db.frontier().unwrap(), result.recorded_at);
    assert!(matches!(
        h.post(h.request(reversal.clone(), &["post"])).unwrap(),
        Posted::AlreadyRecorded { .. }
    ));
    let reused = h.proposal(
        h.rent_legs(50),
        &reversal.idempotency_key,
        EntryClass::ORIGINAL,
    );
    assert_eq!(
        h.post(h.request(reused, &["post"])).unwrap_err().code,
        code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(h.db.frontier().unwrap(), result.recorded_at);
    assert!(matches!(
        h.post(h.request(fresh, &["post"])).unwrap(),
        Posted::Committed { .. }
    ));
}

#[test]
fn ambiguous_legacy_keys_refuse_recovery_without_any_partial_claims() {
    let mut h = harness_legacy();
    let original = h.proposal(h.rent_legs(100), b"legacy-reused", EntryClass::ORIGINAL);
    let target = write_legacy(&mut h, original.clone());
    let reversal = h.reversal_of_entry(target, &original.idempotency_key);
    write_legacy(&mut h, reversal);
    let before = h.db.vertices().unwrap();
    let head = h.db.frontier().unwrap();
    let cx = h.ctx();
    let cap = Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap();
    let refusal = h
        .runtime
        .block_on(prepare_outcome_rebuild(&mut h.db, &cx, &h.book, cap))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, code::IDEMPOTENCY_CONFLICT);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), before);
    assert!(
        h.db.vertex(fa_journal::outcome::coverage_vid(h.book.book_id))
            .unwrap()
            .is_none()
    );
}

#[test]
fn recovered_coverage_survives_maintenance_and_nested_scratch_replay_without_rewriting_it() {
    let (mut h, _, reversal) = legacy_pair();
    let cx = h.ctx();
    // A real native maintenance-only publication: its object is omitted by
    // accounting replay, but its source sequence must remain represented.
    let maintenance_vid = VId(0xface_7788);
    let mut maintenance = WriteBatch::new(relation::IN_BOOK);
    maintenance.create_vertex(maintenance_vid, vec![label::REGISTER], Vec::new());
    h.runtime
        .block_on(h.db.write(&cx.commit(), maintenance))
        .unwrap();
    rebuild(&mut h);
    let prefix = h.db.frontier().unwrap();
    let coverage_vid = fa_journal::outcome::coverage_vid(h.book.book_id);
    let retained = h.db.vertex(coverage_vid).unwrap().unwrap().props;
    let keys = DatabaseKeys::new([71; 32], DatabaseSecurityNamespaceId([72; 32]), [73; 32]);
    let mut scratch = h
        .runtime
        .block_on(Database::open_memory(&cx.commit(), keys.clone()))
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
    assert_eq!(scratch.frontier().unwrap(), prefix);
    assert_eq!(mapping.translate(prefix), Some(prefix));
    assert!(scratch.vertex(maintenance_vid).unwrap().is_none());
    assert_eq!(
        scratch.vertex(coverage_vid).unwrap().unwrap().props,
        retained
    );
    let request = h.request(reversal, &["post"]);
    assert!(matches!(
        h.runtime
            .block_on(fa_journal::post::post(&mut scratch, &cx, &h.book, request))
            .unwrap()
            .unwrap(),
        Posted::AlreadyRecorded { .. }
    ));
    let fresh = h.request(
        h.proposal(h.rent_legs(25), b"scratch-new-key", EntryClass::ORIGINAL),
        &["post"],
    );
    h.runtime
        .block_on(fa_journal::post::post(&mut scratch, &cx, &h.book, fresh))
        .unwrap()
        .unwrap();

    let mut nested = h
        .runtime
        .block_on(Database::open_memory(&cx.commit(), keys))
        .unwrap();
    h.runtime
        .block_on(fa_journal::scratch::replay_into(
            &mut scratch,
            &mut nested,
            &cx,
            &h.book,
            None,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        nested.vertex(coverage_vid).unwrap().unwrap().props,
        retained
    );
    let next = h.request(
        h.proposal(h.rent_legs(30), b"nested-new-key", EntryClass::ORIGINAL),
        &["post"],
    );
    h.runtime
        .block_on(fa_journal::post::post(&mut nested, &cx, &h.book, next))
        .unwrap()
        .unwrap();
}
