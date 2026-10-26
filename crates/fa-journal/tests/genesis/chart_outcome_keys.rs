//! Account lifecycle controls share one key reservation with posting families.

use super::*;
use fa_model::ApprovalRef;
use fa_model::symbols::label;

#[derive(Clone, Copy, Debug)]
enum Kind {
    Open,
    Close,
    Promote,
}

#[derive(Clone)]
struct Request {
    kind: Kind,
    code: String,
    day: DateDay,
    key: Vec<u8>,
    description: Erasable<String>,
}

fn request(h: &Harness, kind: Kind, key: &[u8]) -> Request {
    Request {
        kind,
        code: if matches!(kind, Kind::Open) {
            "6100"
        } else {
            "1200"
        }
        .into(),
        day: h.day(),
        key: key.to_vec(),
        description: h.statement("account lifecycle", 101),
    }
}

fn execute(
    h: &mut Harness,
    request: &Request,
    capability: &Capability,
) -> Result<Result<AccountLifecycleRecorded, Refusal>, KernelError> {
    let ctx = h.ctx();
    match request.kind {
        Kind::Open => {
            let spec = AccountSpec {
                code: request.code.clone(),
                name: "New expense".into(),
                account_type: 5,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(h.usd),
                parent_code: None,
                limit: None,
            };
            h.runtime.block_on(open_account(
                &mut h.db,
                &ctx,
                &h.book,
                &spec,
                request.day,
                None,
                PRINCIPAL,
                request.day,
                &request.key,
                request.description.clone(),
                capability,
            ))
        }
        Kind::Close => h.runtime.block_on(close_account(
            &mut h.db,
            &ctx,
            &h.book,
            &request.code,
            request.day,
            PRINCIPAL,
            request.day,
            &request.key,
            request.description.clone(),
            capability,
        )),
        Kind::Promote => h.runtime.block_on(promote_to_summary(
            &mut h.db,
            &ctx,
            &h.book,
            &request.code,
            request.day,
            PRINCIPAL,
            request.day,
            &request.key,
            request.description.clone(),
            capability,
        )),
    }
}

fn mutate(h: &mut Harness, request: &Request) -> Result<AccountLifecycleRecorded, Refusal> {
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
    let refusal = mutate(h, request).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), (code, exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}

#[test]
fn posting_family_keys_cannot_open_close_or_promote_accounts() {
    let mut h = harness();
    let source = h.proposal(h.rent_legs(100), b"chart-source", EntryClass::ORIGINAL);
    let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
    let reversal = h.reversal_of_entry(target, b"chart-reversal-key");
    h.post(h.request(reversal, &["post"])).unwrap();
    let pending = h.pending(h.rent_legs(200), b"chart-pending-source");
    let target = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
    let resolution = h.resolution_posts(
        target,
        h.rent_legs(150),
        vec![0, 1],
        b"chart-resolution-key",
    );
    h.post(h.request(resolution, &["post"])).unwrap();
    let member = h.proposal(
        h.rent_legs(300),
        b"chart-batch-member",
        EntryClass::ORIGINAL,
    );
    h.post_batch(h.batch(b"chart-batch-key", vec![member]))
        .unwrap();

    for kind in [Kind::Open, Kind::Close, Kind::Promote] {
        for key in [
            b"chart-source".as_slice(),
            b"chart-reversal-key".as_slice(),
            b"chart-resolution-key".as_slice(),
            b"chart-batch-key".as_slice(),
        ] {
            let request = request(&h, kind, key);
            refused_without_publication(&mut h, &request, "FA-REF-032");
        }
    }
}

#[test]
fn lifecycle_claims_publish_atomically_with_state_and_block_posting_keys() {
    for kind in [Kind::Open, Kind::Close, Kind::Promote] {
        let mut h = harness();
        let source = h.proposal(h.rent_legs(100), b"lifecycle-source", EntryClass::ORIGINAL);
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let key = b"lifecycle-owned-key";
        let request = request(&h, kind, key);
        let before = h.db.frontier().unwrap();
        let count = h.db.vertices().unwrap().len();
        let recorded = mutate(&mut h, &request).unwrap();
        assert_eq!(recorded.recorded_at.0, before.0 + 1);
        assert!(!recorded.already_recorded);
        assert_eq!(
            h.db.vertices().unwrap().len() - count,
            if matches!(kind, Kind::Open) { 3 } else { 2 },
            "one control, one common claim, and the new account only when opening"
        );
        let entry = h.db.vertex(recorded.control_entry).unwrap().unwrap();
        let claim = h.db.vertex(outcome(&h, &request)).unwrap().unwrap();
        assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
        assert_eq!(claim.created_at, entry.created_at);
        assert_eq!(
            fa_journal::rows::prop(&claim, property::TARGET_REF),
            Some(&CanonicalScalar::bytes(recorded.control_entry.0.to_le_bytes().to_vec()).unwrap())
        );
        let account = h.db.vertex(recorded.account_vid).unwrap().unwrap();
        let effectivity = AccountEffectivity::decode_from_row(&account).unwrap();
        match kind {
            Kind::Open => assert_eq!(effectivity.opened, Some(request.day)),
            Kind::Close => assert_eq!(effectivity.closed, Some(request.day)),
            Kind::Promote => {
                assert_eq!(effectivity.promoted_on, Some(request.day));
                assert_eq!(
                    fa_journal::rows::prop(&account, property::POSTING),
                    Some(&CanonicalScalar::Int(0))
                );
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
            b"lifecycle-unpublished-member",
            EntryClass::ORIGINAL,
        );
        let refusal = h.post_batch(h.batch(key, vec![member])).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-032", exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }
}

#[test]
fn lifecycle_retries_return_original_outcomes_and_bind_semantic_content() {
    for kind in [Kind::Open, Kind::Close, Kind::Promote] {
        let mut h = harness();
        let original = request(&h, kind, b"lifecycle-retry");
        let first = mutate(&mut h, &original).unwrap();
        let expected = AccountLifecycleRecorded {
            already_recorded: true,
            ..first
        };
        let head = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        assert_eq!(mutate(&mut h, &original).unwrap(), expected);
        let mut changed = original.clone();
        changed.description = h.statement("another lifecycle request", 102);
        refused_without_publication(&mut h, &changed, "FA-REF-032");
        let mut changed = original.clone();
        changed.day = DateDay::from_ymd(2026, 3, 16).unwrap();
        refused_without_publication(&mut h, &changed, "FA-REF-032");
        let mut changed = original.clone();
        changed.code = "6200".into();
        refused_without_publication(&mut h, &changed, "FA-REF-032");
        let mut resealed = original;
        resealed.description = h.statement("account lifecycle", 103);
        assert_eq!(mutate(&mut h, &resealed).unwrap(), expected);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }
}

#[test]
fn prepared_reversal_loses_to_a_lifecycle_control_with_the_same_key() {
    for kind in [Kind::Open, Kind::Close, Kind::Promote] {
        let mut h = harness();
        let source = h.proposal(h.rent_legs(100), b"chart-race-source", EntryClass::ORIGINAL);
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let key = b"chart-race-key";
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
        mutate(&mut h, &request).unwrap();
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

/// Reproduce the earlier writer's canonical Entry and account effects in one
/// native publication. The independent modern fixture supplies those unchanged
/// bytes; its claim is never copied, and no published claim is deleted.
fn write_legacy(
    h: &mut Harness,
    request: &Request,
    approvals: Vec<ApprovalRef>,
    plan_certificate: Option<Oid>,
) -> AccountLifecycleRecorded {
    let mut producer = harness();
    let produced = mutate(&mut producer, request).unwrap();
    let (entry, _) = read_entry(&producer.db, produced.control_entry)
        .unwrap()
        .unwrap();
    let entry = entry.proposal.seal(approvals, plan_certificate).unwrap();
    let account = producer.db.vertex(produced.account_vid).unwrap().unwrap();
    let mut batch = fgdb::WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(
        produced.control_entry,
        vec![label::ENTRY],
        fa_model::entry_mirrors(&entry).unwrap(),
    );
    match request.kind {
        Kind::Open => {
            batch.create_vertex(account.vid, account.labels, account.props);
            let root = book_root();
            batch.add_edge(
                edge_id(relation::IN_BOOK, account.vid, root),
                account.vid,
                root,
                vec![],
            );
        }
        Kind::Close | Kind::Promote => {
            let before = h.db.vertex(account.vid).unwrap().unwrap();
            for key in [property::FA_PAYLOAD, property::POSTING] {
                let old = fa_journal::rows::prop(&before, key).cloned();
                let new = fa_journal::rows::prop(&account, key).cloned();
                if old != new {
                    batch.compare_and_set_vertex_property(
                        account.vid,
                        key,
                        old,
                        new.unwrap(),
                        fgdb::WriteMismatchPolicy::AbortWrite,
                    );
                }
            }
        }
    }
    h.write_raw(batch);
    AccountLifecycleRecorded {
        recorded_at: h.db.frontier().unwrap(),
        ..produced
    }
}

#[test]
fn legacy_lifecycle_retries_survive_recovery_and_reopen_without_claim_rewrites() {
    for kind in [Kind::Open, Kind::Close, Kind::Promote] {
        let mut h = harness_legacy();
        let source = h.proposal(h.rent_legs(100), b"chart-old-source", EntryClass::ORIGINAL);
        let target = outcome_recovery_tests::write_legacy(&mut h, source);
        let reversal = h.reversal_of_entry(target, b"chart-old-reversal");
        outcome_recovery_tests::write_legacy(&mut h, reversal);
        let old = request(&h, kind, b"legacy-lifecycle");
        let recorded = write_legacy(&mut h, &old, Vec::new(), None);
        let original_row = h.db.vertex(recorded.control_entry).unwrap().unwrap();
        let expected = AccountLifecycleRecorded {
            already_recorded: true,
            ..recorded
        };
        assert_eq!(mutate(&mut h, &old).unwrap(), expected);
        assert!(h.db.vertex(outcome(&h, &old)).unwrap().is_none());
        let mut fresh = request(&h, kind, b"new-lifecycle-key");
        fresh.code = if matches!(kind, Kind::Open) {
            "6110"
        } else {
            "4000"
        }
        .into();
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
        assert_eq!(mutate(&mut h, &old).unwrap(), expected);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(
            h.db.vertex(expected.control_entry).unwrap().unwrap(),
            original_row
        );
        assert!(h.db.vertex(outcome(&h, &old)).unwrap().is_none());
        for next in [Kind::Open, Kind::Close, Kind::Promote] {
            let occupied = request(&h, next, b"chart-old-reversal");
            refused_without_publication(&mut h, &occupied, "FA-REF-032");
        }
        assert!(!mutate(&mut h, &fresh).unwrap().already_recorded);
    }
}

#[test]
fn lifecycle_retries_cannot_discard_a_recorded_approval_or_plan_transcript() {
    for kind in [Kind::Open, Kind::Close, Kind::Promote] {
        for plan in [None, Some(Oid([105; 32]))] {
            let mut h = harness_legacy();
            let request = request(&h, kind, b"lifecycle-altered-envelope");
            let approvals = if plan.is_none() {
                vec![
                    h.approve_digest(VId(70), [11; 32]).unwrap(),
                    h.approve_digest(VId(71), [11; 32]).unwrap(),
                ]
            } else {
                Vec::new()
            };
            write_legacy(&mut h, &request, approvals, plan);
            refused_without_publication(&mut h, &request, "FA-REF-032");
        }
    }
}

#[test]
fn scoped_and_revoked_chart_authority_cannot_read_an_occupied_claim() {
    for kind in [Kind::Open, Kind::Close, Kind::Promote] {
        let mut h = harness();
        let request = request(&h, kind, b"unread-chart-key");
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
        h.revoke(&capability, 104);
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
            "the malformed claim must be armed for an admitted observer"
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }
}

#[test]
fn a_deleted_lifecycle_claim_cannot_masquerade_as_a_legacy_control() {
    for kind in [Kind::Open, Kind::Close, Kind::Promote] {
        let mut h = harness();
        let request = request(&h, kind, b"chart-deleted-claim");
        let recorded = mutate(&mut h, &request).unwrap();
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
