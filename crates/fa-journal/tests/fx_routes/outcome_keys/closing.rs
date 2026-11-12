//! The closing-route family shares the routing fixture's real posting and
//! durable-storage paths, while retaining SchemaChange-only write authority.

use super::*;
use fa_journal::chart::{
    ClosingRoutesRecorded, ClosingRoutesRequest, closing_routes_at, set_closing_routes,
};

fn request(h: &Harness, key: &[u8]) -> ClosingRoutesRequest {
    ClosingRoutesRequest {
        principal: PRINCIPAL,
        effective_from: day(1, 1),
        routes: BTreeMap::from([(h.account("4000"), h.account("3000"))]),
        idempotency_key: key.to_vec(),
        description: h.seal("Reviewed year-end closing destinations"),
    }
}

fn set(h: &mut Harness, request: ClosingRoutesRequest) -> Result<ClosingRoutesRecorded, Refusal> {
    let cx = h.cx();
    h.runtime
        .block_on(set_closing_routes(
            &mut h.db,
            &cx,
            &h.book,
            &cap(&["schema_change"]),
            request,
        ))
        .unwrap()
}

fn refused(h: &mut Harness, request: ClosingRoutesRequest) {
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refusal = set(h, request).unwrap_err();
    assert_eq!(
        (refusal.code, refusal.exit),
        (code::IDEMPOTENCY_CONFLICT, 6)
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}

#[test]
fn closing_route_and_posting_family_keys_conflict_in_both_orders() {
    for family in ["original", "reversal", "batch", "fx-route"] {
        for route_first in [false, true] {
            let mut h = Harness::new();
            let source = posting(&h, b"closing-reversal-source");
            let target = post_entry(&mut h, source).unwrap().entry_ref();
            let key = b"shared-closing-key";
            let route = request(&h, key);
            if route_first {
                set(&mut h, route.clone()).unwrap();
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
                "fx-route" => {
                    let proposal = h.request(&[("1200", "1290", "4000")], day(1, 1), key);
                    h.set(&authority(), proposal).unwrap().map(|_| ())
                }
                _ => unreachable!(),
            };
            if route_first {
                let refusal = result.unwrap_err();
                assert_eq!(
                    (refusal.code, refusal.exit),
                    (code::IDEMPOTENCY_CONFLICT, 6),
                    "{family} after closing route"
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
fn closing_route_claims_publish_atomically_and_retries_survive_durable_reopen() {
    let mut h = Harness::new();
    let original = request(&h, b"durable-closing-key");
    let before = h.db.frontier().unwrap();
    let vertex_count = h.db.vertices().unwrap().len();
    let edge_count = h.db.edges_at(before).unwrap().len();
    let recorded = set(&mut h, original.clone()).unwrap();
    assert_eq!(recorded.recorded_at.0, before.0 + 1);
    assert_eq!(h.db.vertices().unwrap().len(), vertex_count + 2);
    assert_eq!(
        h.db.edges_at(recorded.recorded_at).unwrap().len(),
        edge_count
    );
    let entry = h.db.vertex(recorded.control_entry).unwrap().unwrap();
    let claim =
        h.db.vertex(outcome(&h, &original.idempotency_key))
            .unwrap()
            .unwrap();
    assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
    assert_eq!(claim.created_at, entry.created_at);
    assert_eq!(
        fa_journal::rows::prop(&claim, property::TARGET_REF),
        Some(&CanonicalScalar::bytes(recorded.control_entry.0.to_le_bytes().to_vec()).unwrap())
    );
    let mut replacement = request(&h, b"later-closing-key");
    replacement.effective_from = day(3, 1);
    replacement.routes = BTreeMap::from([(h.account("6000"), h.account("3000"))]);
    set(&mut h, replacement.clone()).unwrap();
    reopen(&mut h);
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let expected = ClosingRoutesRecorded {
        already_recorded: true,
        ..recorded
    };
    assert_eq!(set(&mut h, original.clone()).unwrap(), expected);
    let mut resealed = original.clone();
    resealed.description = Erasable::seal(
        &"Reviewed year-end closing destinations".to_owned(),
        None,
        &h.book.seal_key,
        [224; 32],
        [225; 24],
    );
    assert_eq!(set(&mut h, resealed).unwrap(), expected);
    for changed in [
        ClosingRoutesRequest {
            effective_from: day(2, 1),
            ..original.clone()
        },
        ClosingRoutesRequest {
            routes: replacement.routes.clone(),
            ..original.clone()
        },
        ClosingRoutesRequest {
            description: h.seal("Different closing destinations"),
            ..original
        },
    ] {
        refused(&mut h, changed);
    }
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert_eq!(h.db.vertex(expected.control_entry).unwrap().unwrap(), entry);
    assert_eq!(h.db.vertex(claim.vid).unwrap().unwrap(), claim);
    assert_eq!(
        closing_routes_at(&h.db, &h.book, day(3, 31), head)
            .unwrap()
            .unwrap()
            .routes,
        replacement.routes,
        "an original retry does not reinstate a superseded closing map"
    );
}

/// Preserve an actual pre-claim Entry birth; never delete a modern claim to
/// manufacture old history. The old writer had no separate object effects.
fn legacy(h: &mut Harness, request: &ClosingRoutesRequest, plan: Option<Oid>) {
    let mut producer = Harness::new();
    let recorded = set(&mut producer, request.clone()).unwrap();
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
fn original_legacy_closing_routes_remain_read_only_retry_anchors_after_reopen() {
    let mut h = Harness::new();
    let original = request(&h, b"legacy-closing-key");
    legacy(&mut h, &original, None);
    let vid = entry_vid(
        h.book.book_id,
        &PRINCIPAL.0.to_le_bytes(),
        &original.idempotency_key,
    );
    let entry = h.db.vertex(vid).unwrap().unwrap();
    assert!(
        h.db.vertex(outcome(&h, &original.idempotency_key))
            .unwrap()
            .is_none()
    );
    let first = set(&mut h, original.clone()).unwrap();
    assert!(first.already_recorded);
    assert_eq!(first.recorded_at, entry.created_at);
    let next = request(&h, b"modern-closing-key");
    set(&mut h, next).unwrap();
    reopen(&mut h);
    let head = h.db.frontier().unwrap();
    assert_eq!(set(&mut h, original.clone()).unwrap(), first);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertex(vid).unwrap().unwrap(), entry);
    assert!(
        h.db.vertex(outcome(&h, &original.idempotency_key))
            .unwrap()
            .is_none()
    );

    let mut altered = Harness::new();
    legacy(&mut altered, &original, Some(Oid([226; 32])));
    refused(&mut altered, original);
}

#[test]
fn deleted_retargeted_or_restored_closing_claims_never_become_legacy_retries() {
    for mode in ["deleted", "retargeted", "restored"] {
        let mut h = Harness::new();
        let original = request(&h, b"damaged-closing-key");
        let recorded = set(&mut h, original.clone()).unwrap();
        let claim = outcome(&h, &original.idempotency_key);
        assert!(
            h.db.vertex_at(claim, recorded.recorded_at)
                .unwrap()
                .is_some()
        );
        let mut damage = WriteBatch::new(relation::IN_BOOK);
        if mode == "deleted" {
            damage.delete_vertex(claim);
        } else {
            damage.set_vertex_property(
                claim,
                property::TARGET_REF,
                Some(CanonicalScalar::bytes(VId(999).0.to_le_bytes().to_vec()).unwrap()),
            );
        }
        write(&mut h, damage);
        if mode == "restored" {
            let mut restore = WriteBatch::new(relation::IN_BOOK);
            restore.set_vertex_property(
                claim,
                property::TARGET_REF,
                Some(
                    CanonicalScalar::bytes(recorded.control_entry.0.to_le_bytes().to_vec())
                        .unwrap(),
                ),
            );
            write(&mut h, restore);
        }
        reopen(&mut h);
        refused(&mut h, original);
    }
}

#[test]
fn current_schema_authority_precedes_closing_claim_observation() {
    let mut h = Harness::new();
    let original = request(&h, b"guarded-closing-key");
    set(&mut h, original.clone()).unwrap();
    let schema = cap(&["schema_change"]);
    let revocation = RevocationRequest {
        capability: cap(&["issue_capability"]),
        revoked: schema.commitment().unwrap(),
        effective_date: day(1, 5),
        idempotency_key: b"revoke-closing-authority".to_vec(),
        description: h.seal("Withdraw closing-route authority"),
    };
    let cx = h.cx();
    h.runtime
        .block_on(revoke_capability(&mut h.db, &cx, &h.book, revocation))
        .unwrap()
        .unwrap();
    let mut damage = WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        outcome(&h, &original.idempotency_key),
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(b"FA-ENTRY-OUTCOME\0".to_vec()).unwrap()),
    );
    write(&mut h, damage);
    let head = h.db.frontier().unwrap();
    for denied in [
        cap(&["read"]),
        schema.clone().for_accounts(&["4000", "3000"]).unwrap(),
        schema,
    ] {
        let refusal = h
            .runtime
            .block_on(set_closing_routes(
                &mut h.db,
                &cx,
                &h.book,
                &denied,
                original.clone(),
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, 7);
        assert_eq!(h.db.frontier().unwrap(), head);
    }
    assert!(
        h.runtime
            .block_on(set_closing_routes(
                &mut h.db,
                &cx,
                &h.book,
                &cap(&["schema_change", "read"]),
                original,
            ))
            .is_err(),
        "a currently authorized observer reaches the malformed claim"
    );
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn a_prepared_reversal_cannot_take_a_newly_recorded_closing_route_key() {
    let mut h = Harness::new();
    let source = posting(&h, b"closing-race-source");
    let target = post_entry(&mut h, source).unwrap().entry_ref();
    let key = b"closing-race-key";
    let proposal = reversal(&h, target, key);
    let cx = h.cx();
    let fa_journal::PostPreparation::Ready(prepared) =
        fa_journal::prepare_post(&mut h.db, &cx, &h.book, post_request(proposal))
            .unwrap()
            .unwrap()
    else {
        panic!("fresh reversal");
    };
    let original = request(&h, key);
    set(&mut h, original).unwrap();
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
        h.db.vertex(fa_journal::rows::reversal_vid(target.vid))
            .unwrap()
            .is_none()
    );
}

#[test]
fn closing_route_claims_survive_compressed_accounting_replay() {
    let mut h = Harness::new();
    let mut maintenance = WriteBatch::new(relation::IN_BOOK);
    maintenance.create_vertex(VId(0x0fee_d227), vec![label::REGISTER], Vec::new());
    write(&mut h, maintenance);
    let original = request(&h, b"replayed-closing-key");
    let recorded = set(&mut h, original.clone()).unwrap();
    let claim =
        h.db.vertex(outcome(&h, &original.idempotency_key))
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
        .block_on(set_closing_routes(
            &mut scratch,
            &cx,
            &h.book,
            &cap(&["schema_change"]),
            original,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        retry,
        ClosingRoutesRecorded {
            recorded_at: expected_at,
            already_recorded: true,
            ..recorded
        }
    );
    assert_eq!(scratch.frontier().unwrap(), head);
}
