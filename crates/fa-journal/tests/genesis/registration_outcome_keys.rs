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

mod dimension_lifecycle {
    use super::*;
    use fa_journal::dimension::{
        DimensionCloseSpec, DimensionRequirementRecorded, DimensionRequirementSpec,
        DimensionValueRecorded, close_dimension_value, record_dimension_requirement,
    };

    #[derive(Clone, Copy, Debug)]
    enum Change {
        Requirement,
        Close,
    }

    #[derive(Clone)]
    struct ChangeRequest {
        change: Change,
        key: Vec<u8>,
        description: Erasable<String>,
        required: bool,
        closed_on: DateDay,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Changed {
        Requirement(DimensionRequirementRecorded),
        Close(DimensionValueRecorded),
    }

    impl Changed {
        fn control_entry(&self) -> VId {
            match self {
                Self::Requirement(value) => value.control_entry.expect("a published change"),
                Self::Close(value) => value.control_entry,
            }
        }

        fn already_recorded(&self) -> bool {
            match self {
                Self::Requirement(value) => value.already_recorded,
                Self::Close(value) => value.already_recorded,
            }
        }

        fn into_retry(mut self) -> Self {
            match &mut self {
                Self::Requirement(value) => value.already_recorded = true,
                Self::Close(value) => value.already_recorded = true,
            }
            self
        }
    }

    fn setup(h: &mut Harness, legacy: bool) {
        let request = super::request(h, Kind::Dimension, b"dimension-lifecycle-value");
        if legacy {
            super::write_legacy(h, &request, Vec::new(), None);
        } else {
            register(h, &request).unwrap();
        }
    }

    fn request(h: &Harness, change: Change, key: &[u8]) -> ChangeRequest {
        ChangeRequest {
            change,
            key: key.to_vec(),
            description: h.statement("dimension lifecycle", 130),
            required: true,
            closed_on: h.day().add_days(10).unwrap(),
        }
    }

    fn execute(
        h: &mut Harness,
        request: &ChangeRequest,
        capability: &Capability,
    ) -> Result<Result<Changed, Refusal>, KernelError> {
        let ctx = h.ctx();
        match request.change {
            Change::Requirement => {
                let spec = DimensionRequirementSpec {
                    dimension: "cost_center".into(),
                    account: h.receivable,
                    required: request.required,
                };
                Ok(h.runtime
                    .block_on(record_dimension_requirement(
                        &mut h.db,
                        &ctx,
                        &h.book,
                        &spec,
                        PRINCIPAL,
                        &request.key,
                        request.description.clone(),
                        capability,
                    ))?
                    .map(Changed::Requirement))
            }
            Change::Close => {
                let spec = DimensionCloseSpec {
                    dimension: "cost_center".into(),
                    code: "OPERATIONS".into(),
                    closed_on: request.closed_on,
                };
                Ok(h.runtime
                    .block_on(close_dimension_value(
                        &mut h.db,
                        &ctx,
                        &h.book,
                        &spec,
                        PRINCIPAL,
                        &request.key,
                        request.description.clone(),
                        capability,
                    ))?
                    .map(Changed::Close))
            }
        }
    }

    fn change(h: &mut Harness, request: &ChangeRequest) -> Result<Changed, Refusal> {
        execute(
            h,
            request,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        )
        .expect("kernel")
    }

    fn outcome(h: &Harness, request: &ChangeRequest) -> VId {
        fa_model::intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), &request.key)
    }

    fn projection(h: &Harness, change: Change) -> VId {
        match change {
            Change::Requirement => fa_model::dimension_vid(h.book.book_id, "cost_center"),
            Change::Close => {
                fa_model::dimension_value_vid(h.book.book_id, "cost_center", "OPERATIONS")
            }
        }
    }

    fn refused_without_publication(h: &mut Harness, request: &ChangeRequest, code: &str) {
        let head = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        let refusal = change(h, request).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), (code, exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }

    #[test]
    fn posting_keys_cannot_change_dimension_requirements_or_close_values_even_when_noop() {
        let mut h = harness();
        setup(&mut h, false);
        let source = h.proposal(h.rent_legs(100), b"dimension-source", EntryClass::ORIGINAL);
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let reversal = h.reversal_of_entry(target, b"dimension-reversal");
        h.post(h.request(reversal, &["post"])).unwrap();
        let pending = h.pending(h.rent_legs(200), b"dimension-pending");
        let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
        let resolution =
            h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], b"dimension-resolution");
        h.post(h.request(resolution, &["post"])).unwrap();
        let member = h.proposal(
            h.rent_legs(300),
            b"dimension-batch-member",
            EntryClass::ORIGINAL,
        );
        h.post_batch(h.batch(b"dimension-batch", vec![member]))
            .unwrap();
        for kind in [Change::Requirement, Change::Close] {
            for noop in [false, true] {
                if noop {
                    let own_key = match kind {
                        Change::Requirement => b"dimension-require-own".as_slice(),
                        Change::Close => b"dimension-close-own".as_slice(),
                    };
                    let own = request(&h, kind, own_key);
                    assert!(!change(&mut h, &own).unwrap().already_recorded());
                }
                for key in [
                    b"dimension-source".as_slice(),
                    b"dimension-reversal".as_slice(),
                    b"dimension-resolution".as_slice(),
                    b"dimension-batch".as_slice(),
                ] {
                    let request = request(&h, kind, key);
                    refused_without_publication(&mut h, &request, "FA-REF-032");
                }
            }
        }
    }

    #[test]
    fn dimension_lifecycle_claims_publish_with_their_effects_and_block_posting_keys() {
        for kind in [Change::Requirement, Change::Close] {
            let mut h = harness();
            setup(&mut h, false);
            let source = h.proposal(h.rent_legs(100), b"dimension-source", EntryClass::ORIGINAL);
            let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
            let key = b"dimension-owned-key";
            let request = request(&h, kind, key);
            let before = h.db.frontier().unwrap();
            let count = h.db.vertices().unwrap().len();
            let recorded = change(&mut h, &request).unwrap();
            assert!(!recorded.already_recorded());
            assert_eq!(h.db.frontier().unwrap().0, before.0 + 1);
            assert_eq!(h.db.vertices().unwrap().len(), count + 2);
            let entry = h.db.vertex(recorded.control_entry()).unwrap().unwrap();
            let claim = h.db.vertex(outcome(&h, &request)).unwrap().unwrap();
            let state = h.db.vertex(projection(&h, kind)).unwrap().unwrap();
            assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
            assert_eq!(claim.created_at, entry.created_at);
            assert_eq!(state.created_at, entry.created_at);
            assert_eq!(
                fa_journal::rows::prop(&claim, property::TARGET_REF),
                Some(
                    &CanonicalScalar::bytes(recorded.control_entry().0.to_le_bytes().to_vec())
                        .unwrap()
                )
            );
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
                b"dimension-unpublished-member",
                EntryClass::ORIGINAL,
            );
            let refusal = h.post_batch(h.batch(key, vec![member])).unwrap_err();
            assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
            assert_eq!(h.db.frontier().unwrap(), head);
            assert_eq!(h.db.vertices().unwrap(), vertices);
        }
    }

    #[test]
    fn dimension_lifecycle_retries_return_original_results_after_later_changes() {
        for kind in [Change::Requirement, Change::Close] {
            let mut h = harness();
            setup(&mut h, false);
            let original = request(&h, kind, b"dimension-retry");
            let expected = change(&mut h, &original).unwrap().into_retry();
            if matches!(kind, Change::Close) {
                let mut intermediate = request(&h, kind, b"dimension-intermediate");
                intermediate.closed_on = h.day().add_days(7).unwrap();
                change(&mut h, &intermediate).unwrap();
            }
            let mut subsequent = request(&h, kind, b"dimension-subsequent");
            subsequent.required = false;
            subsequent.closed_on = h.day().add_days(5).unwrap();
            change(&mut h, &subsequent).unwrap();
            let head = h.db.frontier().unwrap();
            let vertices = h.db.vertices().unwrap();
            assert_eq!(change(&mut h, &original).unwrap(), expected);
            let mut resealed = original.clone();
            resealed.description = h.statement("dimension lifecycle", 131);
            assert_eq!(change(&mut h, &resealed).unwrap(), expected);
            let mut changed = original.clone();
            changed.description = h.statement("different dimension lifecycle", 132);
            refused_without_publication(&mut h, &changed, "FA-REF-032");
            let mut changed = original;
            changed.required = false;
            changed.closed_on = h.day().add_days(4).unwrap();
            refused_without_publication(&mut h, &changed, "FA-REF-032");
            assert_eq!(h.db.frontier().unwrap(), head);
            assert_eq!(h.db.vertices().unwrap(), vertices);
        }
    }

    #[test]
    fn a_prepared_reversal_loses_to_a_dimension_lifecycle_change_with_the_same_key() {
        for kind in [Change::Requirement, Change::Close] {
            let mut h = harness();
            setup(&mut h, false);
            let source = h.proposal(
                h.rent_legs(100),
                b"dimension-race-source",
                EntryClass::ORIGINAL,
            );
            let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
            let key = b"dimension-race-key";
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
            change(&mut h, &request).unwrap();
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

    /// Copy the old writer's Entry and sole projection update from a separately
    /// executed control, omitting its modern claim at birth, never deleting one.
    fn write_legacy_change(
        h: &mut Harness,
        request: &ChangeRequest,
        approvals: Vec<ApprovalRef>,
        plan_certificate: Option<Oid>,
    ) -> VId {
        let mut producer = harness();
        setup(&mut producer, false);
        let projected = projection(&producer, request.change);
        let old = producer.db.vertex(projected).unwrap().unwrap();
        let recorded = change(&mut producer, request).unwrap();
        let (entry, _) = read_entry(&producer.db, recorded.control_entry())
            .unwrap()
            .unwrap();
        let entry = entry.proposal.seal(approvals, plan_certificate).unwrap();
        let new = producer.db.vertex(projected).unwrap().unwrap();
        let mut batch = fgdb::WriteBatch::new(relation::IN_BOOK);
        batch.create_vertex(
            recorded.control_entry(),
            vec![label::ENTRY],
            fa_model::entry_mirrors(&entry).unwrap(),
        );
        batch.compare_and_set_vertex_property(
            projected,
            property::FA_PAYLOAD,
            fa_journal::rows::prop(&old, property::FA_PAYLOAD).cloned(),
            fa_journal::rows::prop(&new, property::FA_PAYLOAD)
                .cloned()
                .expect("dimension projection payload"),
            fgdb::WriteMismatchPolicy::AbortWrite,
        );
        h.write_raw(batch);
        assert!(h.db.vertex(outcome(h, request)).unwrap().is_none());
        recorded.control_entry()
    }

    #[test]
    fn legacy_dimension_lifecycle_retries_survive_recovery_and_durable_reopen() {
        for kind in [Change::Requirement, Change::Close] {
            let mut h = harness_legacy();
            setup(&mut h, true);
            let source = h.proposal(
                h.rent_legs(100),
                b"legacy-dimension-source",
                EntryClass::ORIGINAL,
            );
            let target = outcome_recovery_tests::write_legacy(&mut h, source);
            let reversal = h.reversal_of_entry(target, b"legacy-dimension-reversal");
            outcome_recovery_tests::write_legacy(&mut h, reversal);
            let original = request(&h, kind, b"legacy-dimension-change");
            let evid = write_legacy_change(&mut h, &original, Vec::new(), None);
            let original_row = h.db.vertex(evid).unwrap().unwrap();
            let expected = change(&mut h, &original).unwrap();
            assert!(expected.already_recorded());
            let fresh = request(&h, kind, b"fresh-dimension-change");
            refused_without_publication(
                &mut h,
                &fresh,
                fa_journal::refusal::code::PLAN_INVALIDATED,
            );
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
            assert_eq!(change(&mut h, &original).unwrap(), expected);
            assert_eq!(h.db.frontier().unwrap(), head);
            assert_eq!(h.db.vertex(evid).unwrap().unwrap(), original_row);
            assert!(h.db.vertex(outcome(&h, &original)).unwrap().is_none());
            let occupied = request(&h, kind, b"legacy-dimension-reversal");
            refused_without_publication(&mut h, &occupied, "FA-REF-032");
            let mut fresh = fresh;
            fresh.required = false;
            fresh.closed_on = h.day().add_days(5).unwrap();
            assert!(!change(&mut h, &fresh).unwrap().already_recorded());
        }
    }

    #[test]
    fn dimension_lifecycle_retries_refuse_altered_envelopes_and_deleted_claims() {
        for kind in [Change::Requirement, Change::Close] {
            for plan in [None, Some(Oid([133; 32]))] {
                let mut h = harness_legacy();
                setup(&mut h, true);
                let request = request(&h, kind, b"dimension-altered-envelope");
                let approvals = if plan.is_none() {
                    vec![h.approve_digest(VId(70), [11; 32]).unwrap()]
                } else {
                    Vec::new()
                };
                write_legacy_change(&mut h, &request, approvals, plan);
                refused_without_publication(&mut h, &request, "FA-REF-032");
            }
            let mut h = harness();
            setup(&mut h, false);
            let request = request(&h, kind, b"dimension-deleted-claim");
            let recorded = change(&mut h, &request).unwrap();
            let created_at =
                h.db.vertex(recorded.control_entry())
                    .unwrap()
                    .unwrap()
                    .created_at;
            let claim = outcome(&h, &request);
            assert!(h.db.vertex_at(claim, created_at).unwrap().is_some());
            let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
            damage.delete_vertex(claim);
            h.write_raw(damage);
            refused_without_publication(&mut h, &request, "FA-REF-032");
        }
    }

    #[test]
    fn dimension_lifecycle_authority_is_checked_before_outcome_observation() {
        for kind in [Change::Requirement, Change::Close] {
            let mut h = harness();
            setup(&mut h, false);
            let request = request(&h, kind, b"unread-dimension-lifecycle");
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
            h.revoke(&capability, 134);
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
}
