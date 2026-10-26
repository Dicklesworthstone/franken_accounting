//! Dimension and native subledger registrations reserve the shared intent key.

use super::*;
use fa_journal::dimension::{DimensionValueSpec, create_dimension_value};
use fa_model::ApprovalRef;
use fa_model::symbols::label;
use fgdb_types::CommitSeq;

#[derive(Clone, Copy, Debug)]
enum Kind {
    Dimension,
    Subledger,
}

#[derive(Clone)]
struct Request {
    kind: Kind,
    code: String,
    name: String,
    account: VId,
    key: Vec<u8>,
    description: Erasable<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Recorded {
    control_entry: VId,
    object: VId,
    recorded_at: CommitSeq,
    already_recorded: bool,
}

fn request(h: &Harness, kind: Kind, key: &[u8]) -> Request {
    Request {
        kind,
        code: "OPERATIONS".into(),
        name: "Operations".into(),
        account: h.receivable,
        key: key.to_vec(),
        description: h.statement("registration", 121),
    }
}

fn execute(
    h: &mut Harness,
    request: &Request,
    capability: &Capability,
) -> Result<Result<Recorded, Refusal>, KernelError> {
    let ctx = h.ctx();
    match request.kind {
        Kind::Dimension => {
            let spec = DimensionValueSpec {
                dimension: "cost_center".into(),
                code: request.code.clone(),
                name: request.name.clone(),
                parent: None,
                valid_from: Some(h.day()),
                valid_to: None,
            };
            Ok(h.runtime
                .block_on(create_dimension_value(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    &spec,
                    PRINCIPAL,
                    &request.key,
                    request.description.clone(),
                    capability,
                ))?
                .map(|recorded| Recorded {
                    control_entry: recorded.control_entry,
                    object: recorded.value.vid,
                    recorded_at: recorded.value.created_at,
                    already_recorded: recorded.already_recorded,
                }))
        }
        Kind::Subledger => {
            let spec = NativeSubledgerSpec {
                code: request.code.clone(),
                name: request.name.clone(),
                kind: NativeSubledgerKind::Receivables,
                control_account: request.account,
            };
            let day = h.day();
            Ok(h.runtime
                .block_on(create_native_subledger(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    &spec,
                    PRINCIPAL,
                    day,
                    &request.key,
                    request.description.clone(),
                    capability,
                ))?
                .map(|recorded| Recorded {
                    control_entry: recorded.subledger.entry.vid,
                    object: recorded.subledger.vid,
                    recorded_at: recorded.subledger.recorded_at,
                    already_recorded: recorded.already_recorded,
                }))
        }
    }
}

fn register(h: &mut Harness, request: &Request) -> Result<Recorded, Refusal> {
    execute(
        h,
        request,
        &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
    )
    .expect("kernel")
}

fn outcome(h: &Harness, request: &Request) -> VId {
    fa_model::intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), &request.key)
}

fn refused_without_publication(h: &mut Harness, request: &Request, code: &str) {
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refusal = register(h, request).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), (code, exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}

#[test]
fn posting_family_keys_cannot_create_dimensions_or_register_native_subledgers() {
    let mut h = harness();
    let source = h.proposal(
        h.rent_legs(100),
        b"registration-source",
        EntryClass::ORIGINAL,
    );
    let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
    let reversal = h.reversal_of_entry(target, b"registration-reversal");
    h.post(h.request(reversal, &["post"])).unwrap();
    let pending = h.pending(h.rent_legs(200), b"registration-hold");
    let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
    let resolution = h.resolution_posts(
        hold,
        h.rent_legs(150),
        vec![0, 1],
        b"registration-resolution",
    );
    h.post(h.request(resolution, &["post"])).unwrap();
    let member = h.proposal(
        h.rent_legs(300),
        b"registration-batch-member",
        EntryClass::ORIGINAL,
    );
    h.post_batch(h.batch(b"registration-batch", vec![member]))
        .unwrap();
    for kind in [Kind::Dimension, Kind::Subledger] {
        for key in [
            b"registration-source".as_slice(),
            b"registration-reversal".as_slice(),
            b"registration-resolution".as_slice(),
            b"registration-batch".as_slice(),
        ] {
            let request = request(&h, kind, key);
            refused_without_publication(&mut h, &request, "FA-REF-032");
        }
    }
}

#[test]
fn registration_claims_publish_atomically_and_block_other_posting_families() {
    for kind in [Kind::Dimension, Kind::Subledger] {
        let mut h = harness();
        let source = h.proposal(
            h.rent_legs(100),
            b"registration-source",
            EntryClass::ORIGINAL,
        );
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let key = b"registration-owned-key";
        let request = request(&h, kind, key);
        let before = h.db.frontier().unwrap();
        let vertex_count = h.db.vertices().unwrap().len();
        let edge_count = h.db.edges_at(before).unwrap().len();
        let new_dimension = matches!(kind, Kind::Dimension)
            && h.db
                .vertex(fa_model::dimension_vid(h.book.book_id, "cost_center"))
                .unwrap()
                .is_none();
        let first = register(&mut h, &request).unwrap();
        assert!(!first.already_recorded);
        assert_eq!(first.recorded_at.0, before.0 + 1);
        assert_eq!(
            h.db.vertices().unwrap().len() - vertex_count,
            3 + usize::from(new_dimension),
            "one Entry, one common claim, one object, and a dimension root only when absent"
        );
        assert_eq!(
            h.db.edges_at(first.recorded_at).unwrap().len() - edge_count,
            match kind {
                Kind::Dimension => 1 + usize::from(new_dimension),
                Kind::Subledger => 2,
            },
        );
        let entry = h.db.vertex(first.control_entry).unwrap().unwrap();
        let claim = h.db.vertex(outcome(&h, &request)).unwrap().unwrap();
        let object = h.db.vertex(first.object).unwrap().unwrap();
        assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
        assert_eq!(claim.created_at, entry.created_at);
        assert_eq!(object.created_at, entry.created_at);
        assert_eq!(
            fa_journal::rows::prop(&claim, property::TARGET_REF),
            Some(&CanonicalScalar::bytes(first.control_entry.0.to_le_bytes().to_vec()).unwrap()),
        );
        match kind {
            Kind::Dimension => {
                let values =
                    fa_journal::dimension::dimension_values_at(&h.db, first.recorded_at).unwrap();
                assert!(values.iter().any(|value| value.vid == first.object));
            }
            Kind::Subledger => {
                let definitions = native_subledgers_at(&h.db, &h.book, first.recorded_at).unwrap();
                assert_eq!(definitions.len(), 1);
                assert_eq!(definitions[0].vid, first.object);
            }
        }
        let head = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        let original = h.proposal(h.rent_legs(300), key, EntryClass::ORIGINAL);
        let reversal = h.reversal_of_entry(target, key);
        for proposal in [original, reversal] {
            let refusal = h.post(h.request(proposal, &["post"])).unwrap_err();
            assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
        }
        let member = h.proposal(
            h.rent_legs(300),
            b"registration-unpublished-member",
            EntryClass::ORIGINAL,
        );
        let refusal = h.post_batch(h.batch(key, vec![member])).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
        let other = Request {
            kind: match kind {
                Kind::Dimension => Kind::Subledger,
                Kind::Subledger => Kind::Dimension,
            },
            ..request
        };
        refused_without_publication(&mut h, &other, "FA-REF-032");
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }
}

#[test]
fn registration_retries_preserve_original_results_and_semantic_request_bytes() {
    for kind in [Kind::Dimension, Kind::Subledger] {
        let mut h = harness();
        let original = request(&h, kind, b"registration-retry");
        let first = register(&mut h, &original).unwrap();
        let expected = Recorded {
            already_recorded: true,
            ..first
        };
        let head = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        assert_eq!(register(&mut h, &original).unwrap(), expected);
        let mut changed = original.clone();
        changed.description = h.statement("different registration", 122);
        refused_without_publication(&mut h, &changed, "FA-REF-032");
        let mut changed = original.clone();
        changed.name = "Different name".into();
        refused_without_publication(&mut h, &changed, "FA-REF-032");
        let mut changed = original.clone();
        changed.code = "OTHER".into();
        refused_without_publication(&mut h, &changed, "FA-REF-032");
        let mut resealed = original;
        resealed.description = h.statement("registration", 123);
        assert_eq!(register(&mut h, &resealed).unwrap(), expected);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }
}

#[test]
fn a_prepared_reversal_loses_to_a_registration_with_the_same_key() {
    for kind in [Kind::Dimension, Kind::Subledger] {
        let mut h = harness();
        let source = h.proposal(
            h.rent_legs(100),
            b"registration-race-source",
            EntryClass::ORIGINAL,
        );
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let key = b"registration-race-key";
        let request = request(&h, kind, key);
        let reversal = h.request(h.reversal_of_entry(target, key), &["post"]);
        let ctx = h.ctx();
        let PostPreparation::Ready(prepared) = prepare_post(&mut h.db, &ctx, &h.book, reversal)
            .unwrap()
            .unwrap()
        else {
            panic!("fresh reversal")
        };
        let epoch = security_policy_epoch(&h.db).unwrap();
        register(&mut h, &request).unwrap();
        assert_eq!(security_policy_epoch(&h.db).unwrap(), epoch);
        let head = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        let refusal = h
            .runtime
            .block_on(prepared.commit(&mut h.db, &ctx))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, exit::CONFLICT);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    }
}

/// Reproduce the old registration writer's unchanged Entry and projections in
/// one native publication. Copy only its known object effects from an independent
/// producer; never delete a modern claim to manufacture historical absence.
fn write_legacy(
    h: &mut Harness,
    request: &Request,
    approvals: Vec<ApprovalRef>,
    plan_certificate: Option<Oid>,
) -> Recorded {
    let mut producer = harness();
    let before = producer.db.frontier().unwrap();
    let old_rows: std::collections::BTreeMap<_, _> = producer
        .db
        .vertices()
        .unwrap()
        .into_iter()
        .map(|row| (row.vid, row))
        .collect();
    let old_edges: std::collections::BTreeSet<_> = producer
        .db
        .edges_at(before)
        .unwrap()
        .into_iter()
        .map(|edge| edge.entry.eid)
        .collect();
    let recorded = register(&mut producer, request).unwrap();
    let (entry, _) = read_entry(&producer.db, recorded.control_entry)
        .unwrap()
        .unwrap();
    let entry = entry.proposal.seal(approvals, plan_certificate).unwrap();
    let mut vertices = fgdb::WriteBatch::new(relation::IN_BOOK);
    for row in producer.db.vertices().unwrap() {
        if row.vid == outcome(&producer, request) {
            continue;
        }
        match old_rows.get(&row.vid) {
            None => {
                assert!(row.labels.iter().all(|label| matches!(
                    *label,
                    label::ENTRY | label::DIMENSION | label::DIMENSION_VALUE | label::SUBLEDGER
                )));
                let props = if row.vid == recorded.control_entry {
                    fa_model::entry_mirrors(&entry).unwrap()
                } else {
                    row.props
                };
                vertices.create_vertex(row.vid, row.labels, props);
            }
            Some(old) if old != &row => {
                assert_eq!(row.vid, request.account);
                let previous = fa_journal::rows::prop(old, property::TARGET_REF).cloned();
                let new = fa_journal::rows::prop(&row, property::TARGET_REF)
                    .cloned()
                    .unwrap();
                vertices.compare_and_set_vertex_property(
                    row.vid,
                    property::TARGET_REF,
                    previous,
                    new,
                    fgdb::WriteMismatchPolicy::AbortWrite,
                );
            }
            Some(_) => {}
        }
    }
    let mut relations = std::collections::BTreeMap::new();
    for edge in producer.db.edges_at(recorded.recorded_at).unwrap() {
        if old_edges.contains(&edge.entry.eid) {
            continue;
        }
        assert!(matches!(
            edge.entry.relation,
            relation::IN_BOOK | relation::CONTROLS
        ));
        relations
            .entry(edge.entry.relation)
            .or_insert_with(|| fgdb::WriteBatch::new(edge.entry.relation))
            .add_edge(edge.entry.eid, edge.entry.src, edge.entry.dst, edge.props);
    }
    let ctx = h.ctx();
    let mut txn = h.db.begin(&ctx.txn()).unwrap();
    let mut batches = vec![vertices];
    batches.extend(relations.into_values());
    txn.write_ordered(&mut h.db, batches).unwrap();
    let recorded_at = h
        .runtime
        .block_on(txn.commit(&mut h.db, &ctx.commit()))
        .unwrap();
    Recorded {
        recorded_at,
        ..recorded
    }
}

#[test]
fn legacy_registration_retries_survive_outcome_recovery_and_durable_reopen() {
    for kind in [Kind::Dimension, Kind::Subledger] {
        let mut h = harness_legacy();
        let mut legs = h.rent_legs(100);
        legs[1].account_ref = h.revenue;
        let source = h.proposal(legs, b"old-registration-source", EntryClass::ORIGINAL);
        let target = outcome_recovery_tests::write_legacy(&mut h, source);
        let reversal = h.reversal_of_entry(target, b"old-registration-reversal");
        outcome_recovery_tests::write_legacy(&mut h, reversal);
        let old = request(&h, kind, b"old-registration");
        let recorded = write_legacy(&mut h, &old, Vec::new(), None);
        let original_row = h.db.vertex(recorded.control_entry).unwrap().unwrap();
        let expected = Recorded {
            already_recorded: true,
            ..recorded
        };
        assert_eq!(register(&mut h, &old).unwrap(), expected);
        assert!(h.db.vertex(outcome(&h, &old)).unwrap().is_none());
        let mut fresh = request(&h, kind, b"new-registration");
        fresh.code = "FRESH".into();
        fresh.account = h.cash;
        refused_without_publication(&mut h, &fresh, fa_journal::refusal::code::PLAN_INVALIDATED);

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
        assert_eq!(register(&mut h, &old).unwrap(), expected);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(
            h.db.vertex(expected.control_entry).unwrap().unwrap(),
            original_row
        );
        assert!(h.db.vertex(outcome(&h, &old)).unwrap().is_none());
        let occupied = request(&h, kind, b"old-registration-reversal");
        refused_without_publication(&mut h, &occupied, "FA-REF-032");
        assert!(!register(&mut h, &fresh).unwrap().already_recorded);
    }
}

#[test]
fn registration_retries_reject_nonempty_approval_or_plan_envelopes() {
    for kind in [Kind::Dimension, Kind::Subledger] {
        for plan in [None, Some(Oid([124; 32]))] {
            let mut h = harness_legacy();
            let request = request(&h, kind, b"registration-altered-envelope");
            let approvals = if plan.is_none() {
                vec![h.approve_digest(VId(70), [11; 32]).unwrap()]
            } else {
                Vec::new()
            };
            write_legacy(&mut h, &request, approvals, plan);
            refused_without_publication(&mut h, &request, "FA-REF-032");
        }
    }
}

#[test]
fn scoped_and_revoked_schema_authority_cannot_observe_registration_claims() {
    for kind in [Kind::Dimension, Kind::Subledger] {
        let mut h = harness();
        let request = request(&h, kind, b"unread-registration-key");
        let evid = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), &request.key);
        let mut planted = fgdb::WriteBatch::new(relation::IN_BOOK);
        planted.create_vertex(
            evid,
            vec![label::ENTRY],
            vec![(
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(vec![0xff; 8]).unwrap(),
            )],
        );
        let mut props = vec![
            (
                property::TARGET_REF,
                CanonicalScalar::bytes(evid.0.to_le_bytes().to_vec()).unwrap(),
            ),
            (
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(b"FA-ENTRY-OUTCOME\0".to_vec()).unwrap(),
            ),
        ];
        props.sort_by_key(|(key, _)| key.0);
        planted.create_vertex(outcome(&h, &request), vec![label::INTENT_OUTCOME], props);
        h.write_raw(planted);
        let capability = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
        h.revoke(&capability, 125);
        let head = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        let scoped = capability.clone().for_periods(&[h.march.as_str()]).unwrap();
        for (capability, code) in [(scoped, "FA-REF-011"), (capability, "FA-REF-023")] {
            let refusal = execute(&mut h, &request, &capability).unwrap().unwrap_err();
            assert_eq!((refusal.code, refusal.exit), (code, exit::SAFETY));
        }
        assert!(
            execute(
                &mut h,
                &request,
                &Capability::embedded(PRINCIPAL, &["schema_change", "read"]).unwrap(),
            )
            .is_err(),
            "the malformed claim is armed for an authorized observer"
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }
}

#[test]
fn a_deleted_registration_claim_cannot_be_treated_as_a_legacy_request() {
    for kind in [Kind::Dimension, Kind::Subledger] {
        let mut h = harness();
        let request = request(&h, kind, b"registration-deleted-claim");
        let recorded = register(&mut h, &request).unwrap();
        let claim = outcome(&h, &request);
        assert!(
            h.db.vertex_at(claim, recorded.recorded_at)
                .unwrap()
                .is_some()
        );
        let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
        damage.delete_vertex(claim);
        h.write_raw(damage);
        refused_without_publication(&mut h, &request, "FA-REF-032");
    }
}
