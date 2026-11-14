//! Every REA schema control shares the successful-intent namespace with
//! monetary postings, target-derived corrections and ordered batches.

use super::*;
use fa_journal::refusal::{Outcome, code, exit};
use fa_model::symbols::label;
use fa_model::{
    DepositCapacity, DepositParticipant, DepositProduct, DepositProfileSpec, DepositRole,
    EventKind, EventSpec, ExternalId, ExternalIdBinding, InstrumentKind, InstrumentSpec,
    LegalEntityFullSpec, PartyIdentifierUpdate, PartyKind, PartySpec, ReaControlOp,
    RelationshipKind, RelationshipSpec, instrument_vid, party_vid,
};

#[derive(Clone)]
struct Request {
    operation: ReaControlOp,
    key: Vec<u8>,
    description: Erasable<String>,
}

fn party(h: &Harness, code: &str) -> PartySpec {
    PartySpec {
        code: code.into(),
        kind: PartyKind::Customer,
        name: h.statement("REA customer", 140),
        identifiers: Vec::new(),
        external_ids: Vec::new(),
    }
}

fn request(h: &Harness, kind: u8, key: &[u8]) -> Request {
    let customer = party_vid(h.book.book_id, "REA-CUSTOMER");
    let other = party_vid(h.book.book_id, "REA-OTHER");
    let operation = match kind {
        0 => ReaControlOp::CreateParty(party(h, "REA-NEW")),
        1 => ReaControlOp::CreateInstrument(InstrumentSpec {
            code: "REA-NEW-INSTRUMENT".into(),
            name: "Operating account".into(),
            kind: InstrumentKind::BankAccount,
            unit: h.usd,
            held_at_party: customer,
            mirrors_account: h.cash,
            external_ids: Vec::new(),
        }),
        2 => ReaControlOp::CreateLegalEntity(LegalEntityFullSpec {
            code: "REA-ENTITY".into(),
            name: "REA entity".into(),
            jurisdiction: "US".into(),
            functional_unit: h.usd,
            formed: Some(h.day()),
            dissolved: None,
            external_ids: Vec::new(),
        }),
        3 => ReaControlOp::BindExternalId(ExternalIdBinding {
            target_vid: customer,
            external_id: ExternalId {
                system: "REA-source".into(),
                id: h.statement("customer-0001", 141),
            },
        }),
        4 => ReaControlOp::RecordRelationship(RelationshipSpec {
            from: customer,
            to: other,
            kind: RelationshipKind::RelatedTo,
            basis: "common_control".into(),
            valid_from: h.day(),
            valid_to: None,
        }),
        5 => ReaControlOp::UpdatePartyIdentifiers(PartyIdentifierUpdate {
            party_vid: customer,
            identifiers: vec![("customer_number".into(), h.statement("0001", 142))],
        }),
        6 => ReaControlOp::RecordEvent(EventSpec {
            code: "REA-EVENT".into(),
            kind: EventKind::Receipt,
            occurred_on: h.day(),
            description: h.statement("Receipt event", 143),
            participants: vec![customer],
            resources: Vec::new(),
            evidence: h.evidence.clone(),
            external_ids: Vec::new(),
        }),
        7 => ReaControlOp::RecordDepositProfile(DepositProfileSpec {
            instrument: instrument_vid(h.book.book_id, "REA-DEPOSIT"),
            product: DepositProduct::Demand,
            capacity: DepositCapacity::Single,
            primary_party: customer,
            interest_account: None,
            participants: vec![DepositParticipant {
                party: customer,
                role: DepositRole::Owner,
                ownership_bps: 10_000,
                beneficiary_count: 0,
            }],
            valid_from: h.day(),
        }),
        _ => unreachable!("eight registered REA control kinds"),
    };
    Request {
        operation,
        key: key.to_vec(),
        description: h.statement("REA operation", 144),
    }
}

fn execute(
    h: &mut Harness,
    request: &Request,
    capability: &Capability,
) -> Outcome<ReaControlRecorded> {
    let ctx = h.ctx();
    let day = h.day();
    macro_rules! run {
        ($writer:ident, $spec:expr) => {
            h.runtime.block_on($writer(
                &mut h.db,
                &ctx,
                &h.book,
                $spec,
                PRINCIPAL,
                day,
                &request.key,
                request.description.clone(),
                capability,
            ))
        };
    }
    match &request.operation {
        ReaControlOp::CreateParty(spec) => run!(create_party, spec),
        ReaControlOp::CreateInstrument(spec) => run!(create_instrument, spec),
        ReaControlOp::CreateLegalEntity(spec) => run!(create_legal_entity, spec),
        ReaControlOp::BindExternalId(spec) => run!(bind_external_id, spec),
        ReaControlOp::RecordRelationship(spec) => run!(record_relationship, spec),
        ReaControlOp::UpdatePartyIdentifiers(spec) => run!(update_party_identifiers, spec),
        ReaControlOp::RecordEvent(spec) => run!(record_event, spec),
        ReaControlOp::RecordDepositProfile(spec) => run!(record_deposit_profile, spec),
    }
}

fn record(h: &mut Harness, request: &Request) -> Result<ReaControlRecorded, Refusal> {
    execute(
        h,
        request,
        &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
    )
    .expect("REA kernel")
}

fn setup(h: &mut Harness) {
    for code in ["REA-CUSTOMER", "REA-OTHER"] {
        let mut req = request(h, 0, code.as_bytes());
        req.operation = ReaControlOp::CreateParty(party(h, code));
        record(h, &req).unwrap();
    }
    let ctx = h.ctx();
    let day = h.day();
    let account = AccountSpec {
        code: "REA-DEPOSITS".into(),
        name: "Customer deposits".into(),
        account_type: fa_model::AccountType::LIABILITY.0,
        normal_balance: 1,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(h.usd),
        parent_code: None,
        limit: None,
    };
    let description = h.statement("Deposit account", 145);
    h.runtime
        .block_on(open_account(
            &mut h.db,
            &ctx,
            &h.book,
            &account,
            day,
            None,
            PRINCIPAL,
            day,
            b"REA-deposits-account",
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let mut req = request(h, 1, b"REA-deposit-instrument");
    let ReaControlOp::CreateInstrument(spec) = &mut req.operation else {
        unreachable!()
    };
    spec.code = "REA-DEPOSIT".into();
    spec.kind = InstrumentKind::Deposit;
    spec.mirrors_account = account_vid(h.book.book_id, &account.code);
    record(h, &req).unwrap();
}

fn outcome(h: &Harness, request: &Request) -> VId {
    fa_model::intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), &request.key)
}

fn refused_without_publication(h: &mut Harness, request: &Request, expected: &str) {
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let edges = h.db.edges_at(head).unwrap();
    let refusal = record(h, request).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), (expected, exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
    assert_eq!(h.db.edges_at(head).unwrap(), edges);
}

#[test]
fn posting_family_keys_cannot_publish_any_rea_schema_control() {
    let mut h = harness();
    setup(&mut h);
    let original = h.proposal(h.rent_legs(100), b"REA-original", EntryClass::ORIGINAL);
    let target = h.post(h.request(original, &["post"])).unwrap().entry_ref();
    let reversal = h.reversal_of_entry(target, b"REA-reversal");
    h.post(h.request(reversal, &["post"])).unwrap();
    let pending = h.pending(h.rent_legs(200), b"REA-pending");
    let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
    let resolution = h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], b"REA-resolution");
    h.post(h.request(resolution, &["post"])).unwrap();
    let member = h.proposal(h.rent_legs(300), b"REA-member", EntryClass::ORIGINAL);
    h.post_batch(h.batch(b"REA-batch", vec![member])).unwrap();
    for kind in 0..8 {
        for key in [
            b"REA-original".as_slice(),
            b"REA-reversal",
            b"REA-resolution",
            b"REA-batch",
        ] {
            let req = request(&h, kind, key);
            refused_without_publication(&mut h, &req, code::IDEMPOTENCY_CONFLICT);
        }
    }
}

#[test]
fn every_rea_control_atomically_reserves_its_key_against_other_families() {
    for kind in 0..8 {
        let mut h = harness();
        setup(&mut h);
        let source = h.proposal(h.rent_legs(100), b"REA-source", EntryClass::ORIGINAL);
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let pending = h.pending(h.rent_legs(200), b"REA-hold");
        let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
        let req = request(&h, kind, b"REA-shared-key");
        let before = h.db.frontier().unwrap();
        let first = record(&mut h, &req).unwrap();
        assert_eq!(first.recorded_at.0, before.0 + 1);
        let entry = h.db.vertex(first.control_entry).unwrap().unwrap();
        let claim = h.db.vertex(outcome(&h, &req)).unwrap().unwrap();
        assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
        assert_eq!(claim.created_at, entry.created_at);
        assert_eq!(
            fa_journal::rows::prop(&claim, property::TARGET_REF),
            Some(&CanonicalScalar::bytes(first.control_entry.0.to_le_bytes().to_vec()).unwrap()),
        );
        read_rea_at(&h.db, &h.book, first.recorded_at).unwrap();
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let postings = [
            h.proposal(h.rent_legs(300), &req.key, EntryClass::ORIGINAL),
            h.reversal_of_entry(target, &req.key),
            h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], &req.key),
        ];
        for proposal in postings {
            let refusal = h.post(h.request(proposal, &["post"])).unwrap_err();
            assert_eq!(
                (refusal.code, refusal.exit),
                (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT)
            );
        }
        let member = h.proposal(
            h.rent_legs(300),
            b"REA-refused-member",
            EntryClass::ORIGINAL,
        );
        let refusal = h.post_batch(h.batch(&req.key, vec![member])).unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT)
        );
        let other = request(&h, (kind + 1) % 8, &req.key);
        refused_without_publication(&mut h, &other, code::IDEMPOTENCY_CONFLICT);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

fn recover(h: &mut Harness) {
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
}

fn reopen(h: &mut Harness) {
    let ctx = h.ctx();
    let (vfs, keys) = h.legacy_storage.clone().expect("durable test storage");
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
}

#[test]
fn rea_control_retries_survive_reopen_and_bind_semantic_request_bytes() {
    for kind in 0..8 {
        let mut h = harness_legacy();
        recover(&mut h);
        setup(&mut h);
        let req = request(&h, kind, b"REA-durable-request");
        let first = record(&mut h, &req).unwrap();
        reopen(&mut h);
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let expected = ReaControlRecorded {
            already_recorded: true,
            ..first
        };
        assert_eq!(record(&mut h, &req).unwrap(), expected);
        let mut resealed = req.clone();
        resealed.description = h.statement("REA operation", 146);
        assert_eq!(record(&mut h, &resealed).unwrap(), expected);
        let mut changed = req;
        changed.description = h.statement("Changed REA operation", 147);
        refused_without_publication(&mut h, &changed, code::IDEMPOTENCY_CONFLICT);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn rea_retries_reject_missing_or_republished_modern_claims() {
    for kind in 0..8 {
        for missing in [false, true] {
            let mut h = harness();
            setup(&mut h);
            let req = request(&h, kind, b"REA-damaged-claim");
            record(&mut h, &req).unwrap();
            let claim = h.db.vertex(outcome(&h, &req)).unwrap().unwrap();
            let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
            if missing {
                damage.delete_vertex(claim.vid);
            } else {
                damage.set_vertex_property(
                    claim.vid,
                    property::FA_PAYLOAD,
                    Some(CanonicalScalar::bytes(b"altered claim".to_vec()).unwrap()),
                );
            }
            h.write_raw(damage);
            if !missing {
                // Restoring the exact bytes does not restore the original
                // atomic publication of an immutable outcome.
                let mut restore = fgdb::WriteBatch::new(relation::IN_BOOK);
                restore.set_vertex_property(
                    claim.vid,
                    property::FA_PAYLOAD,
                    Some(
                        fa_journal::rows::prop(&claim, property::FA_PAYLOAD)
                            .unwrap()
                            .clone(),
                    ),
                );
                h.write_raw(restore);
            }
            refused_without_publication(&mut h, &req, code::IDEMPOTENCY_CONFLICT);
        }
    }
}

#[test]
fn copied_rea_claim_cannot_reserve_another_requests_key() {
    for kind in 0..8 {
        let mut h = harness();
        setup(&mut h);
        let original = request(&h, kind, b"REA-authentic-claim");
        record(&mut h, &original).unwrap();
        let claim = h.db.vertex(outcome(&h, &original)).unwrap().unwrap();
        let copied = request(&h, kind, b"REA-copied-claim");
        let mut copy = fgdb::WriteBatch::new(relation::IN_BOOK);
        copy.create_vertex(outcome(&h, &copied), claim.labels, claim.props);
        h.write_raw(copy);
        refused_without_publication(&mut h, &copied, code::IDEMPOTENCY_CONFLICT);
    }
}

#[test]
fn rea_authorization_precedes_outcome_and_entry_decoding() {
    for kind in 0..8 {
        let mut h = harness();
        let req = request(&h, kind, b"REA-malformed-outcome");
        let evid = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), &req.key);
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
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(b"FA-ENTRY-OUTCOME\0".to_vec()).unwrap(),
            ),
            (
                property::TARGET_REF,
                CanonicalScalar::bytes(evid.0.to_le_bytes().to_vec()).unwrap(),
            ),
        ];
        props.sort_by_key(|(key, _)| key.0);
        planted.create_vertex(outcome(&h, &req), vec![label::INTENT_OUTCOME], props);
        h.write_raw(planted);
        let cap = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
        h.revoke(&cap, 148);
        let scoped = cap.clone().for_periods(&[h.march.as_str()]).unwrap();
        let before = h.db.frontier().unwrap();
        for capability in [scoped, cap] {
            let refusal = execute(&mut h, &req, &capability).unwrap().unwrap_err();
            assert_eq!(refusal.exit, exit::SAFETY);
        }
        assert!(
            execute(
                &mut h,
                &req,
                &Capability::embedded(PRINCIPAL, &["schema_change", "read"]).unwrap()
            )
            .is_err(),
            "authorized observation must reach the planted malformed claim"
        );
        assert_eq!(h.db.frontier().unwrap(), before);
    }
}

#[test]
fn prepared_reversal_loses_to_each_rea_control_claim() {
    for kind in 0..8 {
        let mut h = harness();
        setup(&mut h);
        let source = h.proposal(h.rent_legs(100), b"REA-race-source", EntryClass::ORIGINAL);
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let req = request(&h, kind, b"REA-race-key");
        let reversal = h.reversal_of_entry(target, &req.key);
        let ctx = h.ctx();
        let request = h.request(reversal, &["post"]);
        let PostPreparation::Ready(prepared) = prepare_post(&mut h.db, &ctx, &h.book, request)
            .unwrap()
            .unwrap()
        else {
            panic!("fresh reversal")
        };
        record(&mut h, &req).unwrap();
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
}

/// Reproduce a pre-protocol Party publication in a distinct legacy book.
/// The control and its declared projections are unchanged; no modern claim
/// is removed, and the original modern producer is retained intact.
fn legacy_party(
    h: &mut Harness,
    request: &Request,
    approvals: Vec<fa_model::ApprovalRef>,
    plan: Option<Oid>,
) -> ReaControlRecorded {
    assert!(matches!(request.operation, ReaControlOp::CreateParty(_)));
    let mut producer = harness();
    let before = producer.db.frontier().unwrap();
    let edges: std::collections::BTreeSet<_> = producer
        .db
        .edges_at(before)
        .unwrap()
        .into_iter()
        .map(|edge| edge.entry.eid)
        .collect();
    let recorded = record(&mut producer, request).unwrap();
    let (entry, _) = read_entry(&producer.db, recorded.control_entry)
        .unwrap()
        .unwrap();
    let entry = entry.proposal.seal(approvals, plan).unwrap();
    let mut vertices = fgdb::WriteBatch::new(relation::IN_BOOK);
    for row in producer.db.vertices().unwrap() {
        if row.created_at != recorded.recorded_at || row.vid == outcome(&producer, request) {
            continue;
        }
        assert!(row.labels.iter().all(|label| matches!(
            *label,
            label::ENTRY | label::PARTY | label::DIMENSION | label::DIMENSION_VALUE
        )));
        let props = if row.vid == recorded.control_entry {
            fa_model::entry_mirrors(&entry).unwrap()
        } else {
            row.props
        };
        vertices.create_vertex(row.vid, row.labels, props);
    }
    let mut relations = std::collections::BTreeMap::new();
    for edge in producer.db.edges_at(recorded.recorded_at).unwrap() {
        if edges.contains(&edge.entry.eid) {
            continue;
        }
        assert!(matches!(
            edge.entry.relation,
            relation::IN_BOOK | relation::REPRESENTS
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
    ReaControlRecorded {
        recorded_at,
        ..recorded
    }
}

#[test]
fn legacy_rea_retries_survive_recovery_without_rewriting_their_birth() {
    let mut h = harness_legacy();
    let req = request(&h, 0, b"REA-legacy-party");
    let first = legacy_party(&mut h, &req, Vec::new(), None);
    let birth = h.db.vertex(first.control_entry).unwrap().unwrap();
    let expected = ReaControlRecorded {
        already_recorded: true,
        ..first
    };
    assert_eq!(record(&mut h, &req).unwrap(), expected);
    assert!(h.db.vertex(outcome(&h, &req)).unwrap().is_none());
    let fresh = request(&h, 0, b"REA-fresh-party");
    refused_without_publication(&mut h, &fresh, code::PLAN_INVALIDATED);
    recover(&mut h);
    reopen(&mut h);
    let head = h.db.frontier().unwrap();
    assert_eq!(record(&mut h, &req).unwrap(), expected);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertex(expected.control_entry).unwrap().unwrap(), birth);
    assert!(h.db.vertex(outcome(&h, &req)).unwrap().is_none());
}

#[test]
fn recovered_legacy_reversal_key_refuses_every_rea_control_after_reopen() {
    let mut h = harness_legacy();
    let original = h.proposal(
        h.rent_legs(100),
        b"REA-legacy-source",
        EntryClass::ORIGINAL,
    );
    let target = outcome_recovery_tests::write_legacy(&mut h, original);
    let key = b"REA-legacy-reversal-key";
    let reversal = h.reversal_of_entry(target, key);
    outcome_recovery_tests::write_legacy(&mut h, reversal);
    recover(&mut h);
    setup(&mut h);
    reopen(&mut h);
    let common_key = fa_model::intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key);
    let normal_entry = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key);
    assert!(h.db.vertex(common_key).unwrap().is_none());
    assert!(h.db.vertex(normal_entry).unwrap().is_none());
    for kind in 0..8 {
        let req = request(&h, kind, key);
        refused_without_publication(&mut h, &req, code::IDEMPOTENCY_CONFLICT);
    }
}

#[test]
fn legacy_rea_retries_refuse_unrecognized_approval_and_plan_envelopes() {
    for plan in [false, true] {
        let mut h = harness_legacy();
        let req = request(&h, 0, b"REA-legacy-envelope");
        let approvals = if plan {
            Vec::new()
        } else {
            vec![h.approve_digest(VId(70), [149; 32]).unwrap()]
        };
        legacy_party(&mut h, &req, approvals, plan.then_some(Oid([150; 32])));
        refused_without_publication(&mut h, &req, code::IDEMPOTENCY_CONFLICT);
    }
}
