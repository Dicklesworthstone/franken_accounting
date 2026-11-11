//! FX configuration participates in the same successful-intent namespace as
//! monetary posts and batches, including retained retries and legacy births.

#[path = "outcome_keys/closing.rs"]
mod closing;

use super::*;
use fa_model::symbols::label;
use fa_model::{EntryRef, Supersession, SupersessionKind, entry_vid, intent_outcome_vid};

fn outcome(h: &Harness, key: &[u8]) -> VId {
    intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key)
}

fn posting(h: &Harness, key: &[u8]) -> EntryPayload {
    let legs = vec![
        LegPayload::simple(Side::Debit, h.account("1000"), Amount::new(h.usd, 100)),
        LegPayload::simple(Side::Credit, h.account("3000"), Amount::new(h.usd, 100)),
    ];
    EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: h.book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: day(1, 5),
        document_date: None,
        description: h.seal("Cash contribution"),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: key.to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([220; 32]),
            intent_kind: 1,
        },
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: vec![h.evidence],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    }
}

fn post_request(proposal: EntryPayload) -> PostRequest {
    PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: cap(&["post"]),
    }
}

fn post_entry(h: &mut Harness, proposal: EntryPayload) -> Result<Posted, Refusal> {
    let cx = h.cx();
    h.runtime
        .block_on(post(&mut h.db, &cx, &h.book, post_request(proposal)))
        .unwrap()
}

fn reversal(h: &Harness, target: EntryRef, key: &[u8]) -> EntryPayload {
    let mut proposal = posting(h, key);
    proposal.class = EntryClass::REVERSAL;
    proposal.legs[0].side = Side::Credit;
    proposal.legs[1].side = Side::Debit;
    proposal.supersession = vec![Supersession {
        target,
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    }];
    proposal
}

fn batch(h: &mut Harness, key: &[u8]) -> Result<fa_journal::BatchPosted, Refusal> {
    let member = fa_intents::PostIntent::new(posting(h, b"batch-member"), Vec::new()).unwrap();
    let batch = fa_intents::PostBatch::new(key.to_vec(), vec![member]).unwrap();
    let cx = h.cx();
    h.runtime
        .block_on(fa_journal::post_batch(
            &mut h.db,
            &cx,
            &h.book,
            cap(&["post"]),
            batch,
        ))
        .unwrap()
}

fn write(h: &mut Harness, batch: WriteBatch) -> CommitSeq {
    let cx = h.cx();
    h.runtime.block_on(h.db.write(&cx.commit(), batch)).unwrap()
}

fn reopen(h: &mut Harness) {
    let cx = h.cx();
    let (vfs, keys) = h.storage.clone();
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
}

fn refused(h: &mut Harness, request: FxRevaluationRoutesRequest) {
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refusal = h.set(&authority(), request).unwrap().unwrap_err();
    assert_eq!(
        (refusal.code, refusal.exit),
        (code::IDEMPOTENCY_CONFLICT, 6)
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}

#[test]
fn fx_route_and_posting_family_keys_conflict_in_both_orders() {
    for family in ["original", "reversal", "batch"] {
        for route_first in [false, true] {
            let mut h = Harness::new();
            let source = posting(&h, b"reversal-source");
            let target = post_entry(&mut h, source).unwrap().entry_ref();
            let key = b"shared-fx-key";
            let route = h.request(&[("1200", "1290", "4000")], day(1, 1), key);
            if route_first {
                h.set(&authority(), route.clone()).unwrap().unwrap();
            }
            let head = h.db.frontier().unwrap();
            let vertices = h.db.vertices().unwrap();
            let result = match family {
                "original" => {
                    let proposal = posting(&h, key);
                    post_entry(&mut h, proposal).map(|_| ())
                }
                "reversal" => {
                    let proposal = reversal(&h, target, key);
                    post_entry(&mut h, proposal).map(|_| ())
                }
                "batch" => batch(&mut h, key).map(|_| ()),
                _ => unreachable!(),
            };
            if route_first {
                let refusal = result.unwrap_err();
                assert_eq!(
                    (refusal.code, refusal.exit),
                    (code::IDEMPOTENCY_CONFLICT, 6),
                    "{family} after FX route"
                );
                assert_eq!(h.db.frontier().unwrap(), head);
                assert_eq!(h.db.vertices().unwrap(), vertices);
            } else {
                result.unwrap();
                refused(&mut h, route);
            }
        }
    }
}

#[test]
fn route_claims_publish_atomically_and_retries_survive_durable_reopen() {
    let mut h = Harness::new();
    let request = h.request(&[("1200", "1290", "4000")], day(1, 1), b"durable-fx-key");
    let before = h.db.frontier().unwrap();
    let vertex_count = h.db.vertices().unwrap().len();
    let edge_count = h.db.edges_at(before).unwrap().len();
    let recorded = h.set(&authority(), request.clone()).unwrap().unwrap();
    assert_eq!(recorded.recorded_at.0, before.0 + 1);
    assert_eq!(h.db.vertices().unwrap().len(), vertex_count + 2);
    assert_eq!(
        h.db.edges_at(recorded.recorded_at).unwrap().len(),
        edge_count
    );
    let entry = h.db.vertex(recorded.control_entry).unwrap().unwrap();
    let claim =
        h.db.vertex(outcome(&h, &request.idempotency_key))
            .unwrap()
            .unwrap();
    assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
    assert_eq!(claim.created_at, entry.created_at);
    assert_eq!(
        fa_journal::rows::prop(&claim, property::TARGET_REF),
        Some(&CanonicalScalar::bytes(recorded.control_entry.0.to_le_bytes().to_vec()).unwrap())
    );
    let expanded = h.request(
        &[("1200", "1290", "4000"), ("2200", "2290", "6000")],
        day(3, 1),
        b"later-fx-key",
    );
    h.set(&authority(), expanded).unwrap().unwrap();
    reopen(&mut h);
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let expected = FxRevaluationRoutesRecorded {
        already_recorded: true,
        ..recorded
    };
    assert_eq!(
        h.set(&authority(), request.clone()).unwrap().unwrap(),
        expected
    );
    let mut resealed = request.clone();
    resealed.description = Erasable::seal(
        &"Reviewed monetary exposure assignment".to_owned(),
        None,
        &h.book.seal_key,
        [221; 32],
        [222; 24],
    );
    assert_eq!(h.set(&authority(), resealed).unwrap().unwrap(), expected);
    for changed in [
        FxRevaluationRoutesRequest {
            effective_from: day(2, 1),
            ..request.clone()
        },
        FxRevaluationRoutesRequest {
            routes: h.routes(&[("1200", "1291", "4000")]),
            ..request.clone()
        },
        FxRevaluationRoutesRequest {
            description: h.seal("A different reviewed assignment"),
            ..request
        },
    ] {
        refused(&mut h, changed);
    }
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert_eq!(h.db.vertex(expected.control_entry).unwrap().unwrap(), entry);
    assert_eq!(h.db.vertex(claim.vid).unwrap().unwrap(), claim);
}

/// Reproduce the pre-claim FX writer in a separate publication: the original
/// canonical Entry is unchanged, and no modern claim is deleted to imitate it.
fn legacy_route(h: &mut Harness, request: &FxRevaluationRoutesRequest, plan: Option<Oid>) {
    let mut producer = Harness::new();
    let recorded = producer
        .set(&authority(), request.clone())
        .unwrap()
        .unwrap();
    let (entry, _) = read_entry(&producer.db, recorded.control_entry)
        .unwrap()
        .unwrap();
    let entry = entry.proposal.seal(Vec::new(), plan).unwrap();
    let mut batch = WriteBatch::new(relation::CHILD_OF);
    batch.create_vertex(
        recorded.control_entry,
        vec![label::ENTRY],
        fa_model::entry_mirrors(&entry).unwrap(),
    );
    write(h, batch);
}

#[test]
fn original_legacy_routes_remain_read_only_retry_anchors_after_reopen() {
    let mut h = Harness::new();
    let request = h.request(&[("1200", "1290", "4000")], day(1, 1), b"legacy-fx-key");
    legacy_route(&mut h, &request, None);
    let vid = entry_vid(
        h.book.book_id,
        &PRINCIPAL.0.to_le_bytes(),
        &request.idempotency_key,
    );
    let original = h.db.vertex(vid).unwrap().unwrap();
    assert!(
        h.db.vertex(outcome(&h, &request.idempotency_key))
            .unwrap()
            .is_none()
    );
    let first = h.set(&authority(), request.clone()).unwrap().unwrap();
    assert!(first.already_recorded);
    assert_eq!(first.recorded_at, original.created_at);
    let next = h.request(
        &[("1200", "1290", "4000"), ("2200", "2290", "6000")],
        day(3, 1),
        b"first-modern-fx-key",
    );
    h.set(&authority(), next).unwrap().unwrap();
    reopen(&mut h);
    let head = h.db.frontier().unwrap();
    assert_eq!(
        h.set(&authority(), request.clone()).unwrap().unwrap(),
        first
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertex(vid).unwrap().unwrap(), original);
    assert!(
        h.db.vertex(outcome(&h, &request.idempotency_key))
            .unwrap()
            .is_none()
    );

    let mut damaged = Harness::new();
    legacy_route(&mut damaged, &request, Some(Oid([223; 32])));
    refused(&mut damaged, request);
}

#[test]
fn deleted_or_retargeted_route_claims_never_become_legacy_retries() {
    for deleted in [true, false] {
        let mut h = Harness::new();
        let request = h.request(&[("1200", "1290", "4000")], day(1, 1), b"damaged-fx-key");
        let recorded = h.set(&authority(), request.clone()).unwrap().unwrap();
        let claim = outcome(&h, &request.idempotency_key);
        assert!(
            h.db.vertex_at(claim, recorded.recorded_at)
                .unwrap()
                .is_some()
        );
        let mut damage = WriteBatch::new(relation::IN_BOOK);
        if deleted {
            damage.delete_vertex(claim);
        } else {
            damage.set_vertex_property(
                claim,
                property::TARGET_REF,
                Some(CanonicalScalar::bytes(VId(999).0.to_le_bytes().to_vec()).unwrap()),
            );
        }
        write(&mut h, damage);
        reopen(&mut h);
        refused(&mut h, request);
    }
}

#[test]
fn a_prepared_reversal_cannot_take_a_newly_recorded_route_key() {
    let mut h = Harness::new();
    let source = posting(&h, b"race-source");
    let target = post_entry(&mut h, source).unwrap().entry_ref();
    let key = b"race-fx-key";
    let proposal = reversal(&h, target, key);
    let cx = h.cx();
    let fa_journal::PostPreparation::Ready(prepared) =
        fa_journal::prepare_post(&mut h.db, &cx, &h.book, post_request(proposal))
            .unwrap()
            .unwrap()
    else {
        panic!("fresh reversal");
    };
    let request = h.request(&[("1200", "1290", "4000")], day(1, 1), key);
    h.set(&authority(), request).unwrap().unwrap();
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refusal = h
        .runtime
        .block_on(prepared.commit(&mut h.db, &cx))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.exit, 6);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert!(
        h.db.vertex(fa_model::reversal_vid(target.vid))
            .unwrap()
            .is_none()
    );
}

#[test]
fn route_claims_and_original_results_survive_compressed_accounting_replay() {
    let mut h = Harness::new();
    let mut maintenance = WriteBatch::new(relation::IN_BOOK);
    maintenance.create_vertex(VId(0xfeed_221), vec![label::REGISTER], Vec::new());
    write(&mut h, maintenance);
    let request = h.request(&[("1200", "1290", "4000")], day(1, 1), b"replayed-fx-key");
    let recorded = h.set(&authority(), request.clone()).unwrap().unwrap();
    let claim =
        h.db.vertex(outcome(&h, &request.idempotency_key))
            .unwrap()
            .unwrap();
    let cx = h.cx();
    let mut scratch = h
        .runtime
        .block_on(Database::open_memory(&cx.commit(), h.storage.1.clone()))
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
    let expected_at = mapping.translate(recorded.recorded_at).unwrap();
    assert!(expected_at < recorded.recorded_at);
    let copied = scratch.vertex(claim.vid).unwrap().unwrap();
    assert_eq!(copied.props, claim.props);
    assert_eq!(copied.created_at, expected_at);
    let head = scratch.frontier().unwrap();
    let retry = h
        .runtime
        .block_on(set_fx_revaluation_routes(
            &mut scratch,
            &cx,
            &h.book,
            &authority(),
            request,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        retry,
        FxRevaluationRoutesRecorded {
            recorded_at: expected_at,
            already_recorded: true,
            ..recorded
        }
    );
    assert_eq!(scratch.frontier().unwrap(), head);
}
