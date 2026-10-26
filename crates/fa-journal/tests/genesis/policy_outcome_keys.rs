//! Security and retention activations reserve the shared key atomically.

use super::*;
use fa_model::ApprovalRef;
use fa_model::symbols::label;
use fgdb_types::CommitSeq;

#[derive(Clone, Copy, Debug)]
enum Kind {
    Security,
    Retention,
}

#[derive(Clone)]
struct Request {
    proposal: EntryPayload,
    retention: Option<RetentionPolicy>,
    approvals: Vec<ApprovalRef>,
}

#[derive(Debug, PartialEq, Eq)]
struct Recorded {
    entry: VId,
    at: CommitSeq,
    epoch: u64,
    already_recorded: bool,
}

fn request(h: &Harness, kind: Kind, key: &[u8]) -> Request {
    let description = h.statement("activate policy", 61);
    let (proposal, retention) = match kind {
        Kind::Security => (
            activation_proposal(
                &h.book,
                PRINCIPAL,
                fa_journal::policy::steward().unwrap().policy_oid,
                h.day(),
                key,
                description,
            ),
            None,
        ),
        Kind::Retention => {
            let policy = RetentionPolicy::new(
                h.book.book_id,
                RetentionScope::Book,
                RetentionFloor::Days(365),
                h.evidence[0].document_oid,
                h.day(),
            );
            let proposal =
                retention_activation_proposal(&h.book, PRINCIPAL, &policy, key, description)
                    .unwrap();
            (proposal, Some(policy))
        }
    };
    Request {
        proposal,
        retention,
        approvals: Vec::new(),
    }
}

fn approve(h: &mut Harness, request: &mut Request) {
    let digest = request.proposal.proposal_digest().unwrap();
    request.approvals = vec![
        h.approve_digest(VId(70), digest).unwrap(),
        h.approve_digest(VId(71), digest).unwrap(),
    ];
}

fn execute(
    h: &mut Harness,
    request: &Request,
    capability: Capability,
) -> Result<Result<Recorded, Refusal>, KernelError> {
    let cx = h.ctx();
    match &request.retention {
        None => h
            .runtime
            .block_on(activate_policy(
                &mut h.db,
                &cx,
                &h.book,
                ActivationRequest {
                    proposal: request.proposal.clone(),
                    capability,
                    approvals: request.approvals.clone(),
                },
            ))
            .map(|outcome| {
                outcome.map(|record| Recorded {
                    entry: record.control_entry,
                    at: record.recorded_at,
                    epoch: record.to_epoch,
                    already_recorded: record.already_recorded,
                })
            }),
        Some(policy) => h
            .runtime
            .block_on(activate_retention_policy(
                &mut h.db,
                &cx,
                &h.book,
                RetentionActivationRequest {
                    policy: policy.clone(),
                    proposal: request.proposal.clone(),
                    capability,
                    approvals: request.approvals.clone(),
                },
            ))
            .map(|outcome| {
                outcome.map(|record| Recorded {
                    entry: record.control_entry,
                    at: record.recorded_at,
                    epoch: record.security_policy_epoch,
                    already_recorded: record.already_recorded,
                })
            }),
    }
}

fn activate(h: &mut Harness, request: &Request) -> Result<Recorded, Refusal> {
    execute(
        h,
        request,
        Capability::embedded(PRINCIPAL, &["rule_change"]).unwrap(),
    )
    .expect("kernel")
}

fn outcome(h: &Harness, request: &Request) -> VId {
    fa_model::intent_outcome_vid(
        h.book.book_id,
        &PRINCIPAL.0.to_le_bytes(),
        &request.proposal.idempotency_key,
    )
}

fn refused_without_publication(h: &mut Harness, request: &Request, code: &str) {
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refused = activate(h, request).unwrap_err();
    assert_eq!(refused.code, code, "{refused:?}");
    assert_eq!(refused.exit, exit::CONFLICT);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}

#[test]
fn posting_family_keys_cannot_activate_security_or_retention_policy() {
    let mut h = harness();
    let original = h.proposal(h.rent_legs(100), b"policy-source", EntryClass::ORIGINAL);
    let target = h.post(h.request(original, &["post"])).unwrap().entry_ref();
    let reversed = h.reversal_of_entry(target, b"policy-reversed-key");
    h.post(h.request(reversed, &["post"])).unwrap();
    let pending = h.pending(h.rent_legs(200), b"policy-pending-source");
    let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
    let resolution = h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], b"policy-resolved-key");
    h.post(h.request(resolution, &["post"])).unwrap();
    let member = h.proposal(
        h.rent_legs(300),
        b"policy-batch-member",
        EntryClass::ORIGINAL,
    );
    h.post_batch(h.batch(b"policy-batch-key", vec![member]))
        .unwrap();

    for kind in [Kind::Security, Kind::Retention] {
        for key in [
            b"policy-reversed-key".as_slice(),
            b"policy-resolved-key".as_slice(),
            b"policy-batch-key".as_slice(),
        ] {
            let request = request(&h, kind, key);
            refused_without_publication(&mut h, &request, "FA-REF-032");
        }
    }
    assert_eq!(security_policy_epoch(&h.db).unwrap(), 0);
    assert!(
        active_retention_policies(&h.db, h.book.book_id)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn activation_claims_publish_atomically_and_block_other_posting_families() {
    for kind in [Kind::Security, Kind::Retention] {
        let mut h = harness();
        let source = h.proposal(h.rent_legs(100), b"activation-source", EntryClass::ORIGINAL);
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let key = b"activation-owned-key";
        let mut request = request(&h, kind, key);
        approve(&mut h, &mut request);
        let head = h.db.frontier().unwrap();
        let vertices_before = h.db.vertices().unwrap().len();
        let recorded = activate(&mut h, &request).unwrap();
        assert!(!recorded.already_recorded);
        assert_eq!(recorded.at.0, head.0 + 1);
        assert_eq!(
            h.db.vertices().unwrap().len() - vertices_before,
            match kind {
                Kind::Security => 2,
                Kind::Retention => 4,
            },
            "the fixed publication census includes the common claim"
        );
        let entry = h.db.vertex(recorded.entry).unwrap().unwrap();
        let claim = h.db.vertex(outcome(&h, &request)).unwrap().unwrap();
        assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
        assert_eq!(claim.created_at, entry.created_at);
        assert_eq!(
            fa_journal::rows::prop(&claim, property::TARGET_REF),
            Some(&CanonicalScalar::bytes(recorded.entry.0.to_le_bytes().to_vec()).unwrap())
        );
        let head = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        let original = h.proposal(h.rent_legs(300), key, EntryClass::ORIGINAL);
        let reversal = h.reversal_of_entry(target, key);
        for proposal in [original, reversal] {
            let refused = h.post(h.request(proposal, &["post"])).unwrap_err();
            assert_eq!((refused.code, refused.exit), ("FA-REF-032", exit::CONFLICT));
        }
        let member = h.proposal(
            h.rent_legs(300),
            b"activation-unpublished-member",
            EntryClass::ORIGINAL,
        );
        let refused = h.post_batch(h.batch(key, vec![member])).unwrap_err();
        assert_eq!((refused.code, refused.exit), ("FA-REF-032", exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }
}

#[test]
fn activation_retries_bind_approvals_and_description_and_keep_the_original_epoch() {
    for kind in [Kind::Security, Kind::Retention] {
        let mut h = harness();
        let mut original = request(&h, kind, b"activation-retry");
        approve(&mut h, &mut original);
        let first = activate(&mut h, &original).unwrap();
        let mut later = request(&h, Kind::Security, b"later-security-epoch");
        approve(&mut h, &mut later);
        activate(&mut h, &later).unwrap();
        assert_eq!(security_policy_epoch(&h.db).unwrap(), first.epoch + 1);
        let head = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        let expected = Recorded {
            already_recorded: true,
            ..first
        };
        assert_eq!(activate(&mut h, &original).unwrap(), expected);

        for approvals in [
            Vec::new(),
            original.approvals.iter().rev().copied().collect(),
        ] {
            let mut changed = original.clone();
            changed.approvals = approvals;
            refused_without_publication(&mut h, &changed, "FA-REF-032");
        }
        let mut changed = original.clone();
        changed.proposal.description = h.statement("different activation", 62);
        refused_without_publication(&mut h, &changed, "FA-REF-032");
        let mut resealed = original;
        resealed.proposal.description = h.statement("activate policy", 63);
        assert_eq!(activate(&mut h, &resealed).unwrap(), expected);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }
}

#[test]
fn prepared_reversal_loses_to_retention_activation_with_the_same_key() {
    let mut h = harness();
    let source = h.proposal(
        h.rent_legs(100),
        b"retention-race-source",
        EntryClass::ORIGINAL,
    );
    let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
    let key = b"retention-race-key";
    let mut activation = request(&h, Kind::Retention, key);
    approve(&mut h, &mut activation);
    let reversal = h.request(h.reversal_of_entry(target, key), &["post"]);
    let cx = h.ctx();
    let PostPreparation::Ready(prepared) = prepare_post(&mut h.db, &cx, &h.book, reversal)
        .unwrap()
        .unwrap()
    else {
        panic!("fresh reversal")
    };
    let epoch = security_policy_epoch(&h.db).unwrap();
    activate(&mut h, &activation).unwrap();
    assert_eq!(
        security_policy_epoch(&h.db).unwrap(),
        epoch,
        "the retention winner does not move the security epoch"
    );
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refused = h
        .runtime
        .block_on(prepared.commit(&mut h.db, &cx))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.exit, exit::CONFLICT);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
}

/// Reproduce the original dedicated writer's Entry and state in one native
/// publication. No modern claim is created and then deleted for this fixture.
fn write_legacy(h: &mut Harness, request: &Request) -> Recorded {
    let entry = request
        .proposal
        .clone()
        .seal(request.approvals.clone(), None)
        .unwrap();
    let vid = entry_vid(
        h.book.book_id,
        &PRINCIPAL.0.to_le_bytes(),
        &request.proposal.idempotency_key,
    );
    let mut batch = fgdb::WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(
        vid,
        vec![label::ENTRY],
        fa_model::entry_mirrors(&entry).unwrap(),
    );
    let mut epoch = security_policy_epoch(&h.db).unwrap();
    match &request.retention {
        None => {
            let root = h.db.vertex(book_root()).unwrap().unwrap();
            let before = fa_journal::rows::prop(&root, property::SECURITY_POLICY_EPOCH).cloned();
            epoch += 1;
            batch.compare_and_set_vertex_property(
                book_root(),
                property::SECURITY_POLICY_EPOCH,
                before,
                CanonicalScalar::Int(i64::try_from(epoch).unwrap()),
                fgdb::WriteMismatchPolicy::AbortWrite,
            );
        }
        Some(policy) => {
            let oid = policy.policy_oid().unwrap();
            let mut props = vec![
                (
                    property::FA_PAYLOAD,
                    CanonicalScalar::bytes(policy.canonical_bytes().unwrap()).unwrap(),
                ),
                (
                    property::FA_DIGEST,
                    CanonicalScalar::bytes(oid.0.to_vec()).unwrap(),
                ),
            ];
            props.sort_by_key(|(key, _)| key.0);
            batch.create_vertex(
                retention_policy_vid(h.book.book_id, &oid),
                vec![label::LEGAL_HOLD_CELL],
                props,
            );
            let mut cell = fa_model::Writer::new();
            cell.list(&[(vid, oid)], |writer, (vid, oid)| {
                writer.u128(vid.0).fixed(&oid.0);
            });
            batch.create_vertex(
                retention_cell_vid(h.book.book_id),
                vec![label::LEGAL_HOLD_CELL],
                vec![(
                    property::FA_PAYLOAD,
                    CanonicalScalar::bytes(cell.finish().unwrap()).unwrap(),
                )],
            );
        }
    }
    h.write_raw(batch);
    Recorded {
        entry: vid,
        at: h.db.frontier().unwrap(),
        epoch,
        already_recorded: false,
    }
}

#[test]
fn legacy_activation_retries_survive_recovery_and_reopen_without_claim_rewrites() {
    for kind in [Kind::Security, Kind::Retention] {
        let mut h = harness_legacy();
        let source = h.proposal(
            h.rent_legs(100),
            b"activation-old-source",
            EntryClass::ORIGINAL,
        );
        let target = outcome_recovery_tests::write_legacy(&mut h, source);
        let reversal = h.reversal_of_entry(target, b"activation-old-reversal");
        outcome_recovery_tests::write_legacy(&mut h, reversal);
        let mut old = request(&h, kind, b"legacy-activation");
        approve(&mut h, &mut old);
        let recorded = write_legacy(&mut h, &old);
        let entry_before = h.db.vertex(recorded.entry).unwrap().unwrap();
        let expected = Recorded {
            already_recorded: true,
            ..recorded
        };
        assert_eq!(activate(&mut h, &old).unwrap(), expected);
        assert!(h.db.vertex(outcome(&h, &old)).unwrap().is_none());
        for next in [Kind::Security, Kind::Retention] {
            let fresh = request(&h, next, b"unrecovered-policy-key");
            refused_without_publication(
                &mut h,
                &fresh,
                fa_journal::refusal::code::PLAN_INVALIDATED,
            );
        }

        let cx = h.ctx();
        let prepared = h
            .runtime
            .block_on(prepare_outcome_rebuild(
                &mut h.db,
                &cx,
                &h.book,
                Capability::embedded(PRINCIPAL, &["read", "schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        h.runtime
            .block_on(publish_outcome_rebuild(&mut h.db, &cx, &h.book, prepared))
            .unwrap()
            .unwrap();
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
        let head = h.db.frontier().unwrap();
        assert_eq!(activate(&mut h, &old).unwrap(), expected);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertex(expected.entry).unwrap().unwrap(), entry_before);
        assert!(h.db.vertex(outcome(&h, &old)).unwrap().is_none());
        for next in [Kind::Security, Kind::Retention] {
            let occupied = request(&h, next, b"activation-old-reversal");
            refused_without_publication(&mut h, &occupied, "FA-REF-032");
        }
        let mut fresh = request(&h, kind, b"recovered-policy-key");
        approve(&mut h, &mut fresh);
        assert!(!activate(&mut h, &fresh).unwrap().already_recorded);
    }
}

#[test]
fn scoped_activation_authority_never_reads_an_occupied_outcome_payload() {
    for kind in [Kind::Security, Kind::Retention] {
        let mut h = harness();
        let request = request(&h, kind, b"outside-policy-authority");
        let evid = entry_vid(
            h.book.book_id,
            &PRINCIPAL.0.to_le_bytes(),
            &request.proposal.idempotency_key,
        );
        let mut planted = fgdb::WriteBatch::new(relation::IN_BOOK);
        planted.create_vertex(
            evid,
            vec![label::ENTRY],
            vec![(
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(vec![0xff; 8]).unwrap(),
            )],
        );
        planted.create_vertex(
            outcome(&h, &request),
            vec![label::INTENT_OUTCOME],
            vec![
                (
                    property::TARGET_REF,
                    CanonicalScalar::bytes(evid.0.to_le_bytes().to_vec()).unwrap(),
                ),
                (
                    property::FA_PAYLOAD,
                    CanonicalScalar::bytes(b"FA-ENTRY-OUTCOME\0".to_vec()).unwrap(),
                ),
            ],
        );
        h.write_raw(planted);
        let head = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        let scoped = Capability::embedded(PRINCIPAL, &["rule_change"])
            .unwrap()
            .for_periods(&[h.march.as_str()])
            .unwrap();
        let refused = execute(&mut h, &request, scoped).unwrap().unwrap_err();
        assert_eq!((refused.code, refused.exit), ("FA-REF-011", exit::SAFETY));
        assert!(
            execute(
                &mut h,
                &request,
                Capability::embedded(PRINCIPAL, &["rule_change"]).unwrap()
            )
            .is_err(),
            "the malformed common claim must be armed for an admitted observer"
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }
}

#[test]
fn a_deleted_activation_claim_cannot_masquerade_as_a_legacy_publication() {
    for kind in [Kind::Security, Kind::Retention] {
        let mut h = harness();
        let mut request = request(&h, kind, b"activation-deleted-claim");
        approve(&mut h, &mut request);
        let recorded = activate(&mut h, &request).unwrap();
        let claim = outcome(&h, &request);
        assert!(h.db.vertex_at(claim, recorded.at).unwrap().is_some());
        let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
        damage.delete_vertex(claim);
        h.write_raw(damage);
        refused_without_publication(&mut h, &request, "FA-REF-032");
    }
}
