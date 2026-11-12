use std::collections::BTreeSet;

use super::*;
use fa_journal::refusal::code;

fn role(
    h: &mut Harness,
    account: VId,
    role: &str,
    assigned: bool,
    key: &[u8],
    salt: u8,
    ops: &[&str],
) -> Result<AccountRoleRecorded, Refusal> {
    let cx = h.ctx();
    let description = Erasable::seal(
        &"account role".to_string(),
        None,
        &h.book.seal_key,
        [salt; 32],
        [salt; 24],
    );
    let spec = AccountRoleSpec {
        account,
        role: role.into(),
        assigned,
    };
    h.runtime
        .block_on(record_account_role(
            &mut h.db,
            &cx,
            &h.book,
            &spec,
            PRINCIPAL,
            key,
            description,
            &Capability::embedded(PRINCIPAL, ops).unwrap(),
        ))
        .unwrap()
}

const SCHEMA: &[&str] = &["schema_change"];

/// A role is one immutable control; the roles at a prefix are the fold of
/// the controls recorded by then, the latest per (account, role) deciding.
#[test]
fn a_role_is_journaled_folded_at_its_prefix_and_retried_exactly() {
    let mut h = harness();
    let before = h.db.frontier().unwrap();
    let cash = h.cash;
    let first = role(&mut h, cash, "suspense", true, b"role-1", 1, SCHEMA).unwrap();
    assert!(!first.already_recorded);
    let at = first.control.recorded_at;
    assert!(
        !account_roles_at(&h.db, &h.book, before)
            .unwrap()
            .holds(cash, "suspense")
    );
    let roles = account_roles_at(&h.db, &h.book, at).unwrap();
    assert!(roles.holds(cash, "suspense"));
    assert_eq!(roles.accounts_with("suspense"), BTreeSet::from([cash]));
    assert!(roles.accounts_with("intercompany").is_empty());
    assert_eq!(roles.controls(cash, "suspense"), 1);
    assert!(fa_journal::chart::read_at(&h.db, &h.book, at).is_ok());

    // An exact retry, its description sealed afresh, is the recorded control.
    let retry = role(&mut h, cash, "suspense", true, b"role-1", 2, SCHEMA).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.control, first.control);
    // The same state under another key writes nothing either.
    let again = role(&mut h, cash, "suspense", true, b"role-2", 3, SCHEMA).unwrap();
    assert!(again.already_recorded);
    assert_eq!(again.control, first.control);
    assert_eq!(h.db.frontier().unwrap(), at);
    // The same key with other content is a conflict.
    let receivable = h.receivable;
    let conflict = role(&mut h, receivable, "suspense", true, b"role-1", 4, SCHEMA).unwrap_err();
    assert_eq!(
        (conflict.code, conflict.exit),
        (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT)
    );

    // Removal, then assignment again: the latest control decides, and the
    // earlier prefix still reads the role as it stood then.
    let removed = role(&mut h, cash, "suspense", false, b"role-3", 5, SCHEMA).unwrap();
    assert!(!removed.already_recorded);
    let roles = account_roles_at(&h.db, &h.book, removed.control.recorded_at).unwrap();
    assert!(!roles.holds(cash, "suspense"));
    assert_eq!(roles.controls(cash, "suspense"), 2);
    assert!(
        account_roles_at(&h.db, &h.book, at)
            .unwrap()
            .holds(cash, "suspense")
    );
    let back = role(&mut h, cash, "suspense", true, b"role-4", 6, SCHEMA).unwrap();
    let roles = account_roles_at(&h.db, &h.book, back.control.recorded_at).unwrap();
    assert!(roles.holds(cash, "suspense"));
    assert_eq!(roles.controls(cash, "suspense"), 3);
    assert_eq!(roles.assigned().count(), 1);
    assert!(fa_journal::chart::read_at(&h.db, &h.book, back.control.recorded_at).is_ok());
}

/// Planted: an unregistered role, a type the role does not admit, a summary,
/// an absent account, removing a role not held, and a capability without
/// schema_change are each refused, and nothing is written.
#[test]
fn a_role_the_registry_or_the_account_does_not_admit_is_refused_and_writes_nothing() {
    let mut h = harness();
    let head = h.db.frontier().unwrap();
    let missing = account_vid(h.book.book_id, "9999");
    let cases = [
        (
            h.cash,
            "revenue",
            true,
            SCHEMA,
            "is not a registered account role",
        ),
        (
            h.rent,
            "suspense",
            true,
            SCHEMA,
            "admits Asset or Liability",
        ),
        (h.revenue, "intercompany", true, SCHEMA, "is Revenue"),
        (h.assets, "suspense", true, SCHEMA, "is a summary"),
        (missing, "suspense", true, SCHEMA, "does not exist"),
        (h.cash, "suspense", false, SCHEMA, "nothing to remove"),
    ];
    for (salt, (account, name, assigned, ops, expected)) in (10u8..).zip(cases) {
        let refusal = role(&mut h, account, name, assigned, b"planted", salt, ops).unwrap_err();
        assert!(
            refusal.message.contains(expected),
            "{expected}: {refusal:?}"
        );
        assert_eq!(h.db.frontier().unwrap(), head, "{expected}");
    }
    let cash = h.cash;
    let unauthorized = role(&mut h, cash, "suspense", true, b"read-only", 9, &["read"]);
    assert!(unauthorized.is_err(), "{unauthorized:?}");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(
        account_roles_at(&h.db, &h.book, head)
            .unwrap()
            .assigned()
            .next()
            .is_none()
    );
}

mod outcome_keys {
    use super::*;
    use fa_model::ApprovalRef;
    use fa_model::symbols::label;

    #[derive(Clone)]
    struct RoleRequest {
        spec: AccountRoleSpec,
        key: Vec<u8>,
        description: Erasable<String>,
    }

    fn request(h: &Harness, key: &[u8], assigned: bool) -> RoleRequest {
        RoleRequest {
            spec: AccountRoleSpec {
                account: h.cash,
                role: "suspense".into(),
                assigned,
            },
            key: key.to_vec(),
            description: h.statement("account role outcome", 141),
        }
    }

    fn execute(
        h: &mut Harness,
        request: &RoleRequest,
        capability: &Capability,
    ) -> Result<Result<AccountRoleRecorded, Refusal>, KernelError> {
        let ctx = h.ctx();
        h.runtime.block_on(record_account_role(
            &mut h.db,
            &ctx,
            &h.book,
            &request.spec,
            PRINCIPAL,
            &request.key,
            request.description.clone(),
            capability,
        ))
    }

    fn record(h: &mut Harness, request: &RoleRequest) -> Result<AccountRoleRecorded, Refusal> {
        execute(
            h,
            request,
            &Capability::embedded(PRINCIPAL, SCHEMA).unwrap(),
        )
        .expect("role kernel")
    }

    fn outcome(h: &Harness, request: &RoleRequest) -> VId {
        fa_model::intent_outcome_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), &request.key)
    }

    fn refused_without_publication(h: &mut Harness, request: &RoleRequest, expected: &str) {
        let head = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        let refusal = record(h, request).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), (expected, exit::CONFLICT));
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }

    #[test]
    fn posting_keys_cannot_assign_or_remove_account_roles_even_when_noop() {
        let mut h = harness();
        let source = h.proposal(h.rent_legs(100), b"role-source", EntryClass::ORIGINAL);
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let reversal = h.request(h.reversal_of_entry(target, b"role-reversal"), &["post"]);
        let replacement = h.request(
            replacement_proposal(
                target,
                h.proposal(
                    h.rent_legs(125),
                    b"role-replacement",
                    EntryClass::REPLACEMENT,
                ),
            ),
            &["post"],
        );
        h.post_pair(reversal, replacement).unwrap();
        let pending = h.pending(h.rent_legs(200), b"role-pending");
        let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
        let resolution = h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], b"role-resolution");
        h.post(h.request(resolution, &["post"])).unwrap();
        let member = h.proposal(h.rent_legs(300), b"role-batch-member", EntryClass::ORIGINAL);
        h.post_batch(h.batch(b"role-batch", vec![member])).unwrap();

        for assigned in [true, false] {
            for noop in [false, true] {
                if noop {
                    let key = if assigned {
                        b"role-own-assignment".as_slice()
                    } else {
                        b"role-own-removal".as_slice()
                    };
                    let own = request(&h, key, assigned);
                    assert!(!record(&mut h, &own).unwrap().already_recorded);
                }
                for key in [
                    b"role-source".as_slice(),
                    b"role-reversal".as_slice(),
                    b"role-replacement".as_slice(),
                    b"role-pending".as_slice(),
                    b"role-resolution".as_slice(),
                    b"role-batch".as_slice(),
                ] {
                    let collision = request(&h, key, assigned);
                    refused_without_publication(&mut h, &collision, code::IDEMPOTENCY_CONFLICT);
                }
            }
        }
    }

    #[test]
    fn account_role_claims_publish_atomically_and_block_posting_families() {
        for assigned in [true, false] {
            let mut h = harness();
            if !assigned {
                let initial = request(&h, b"role-initial", true);
                record(&mut h, &initial).unwrap();
            }
            let source = h.proposal(h.rent_legs(100), b"role-source", EntryClass::ORIGINAL);
            let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
            let pending = h.pending(h.rent_legs(200), b"role-pending");
            let hold = h.post(h.request(pending, &["post"])).unwrap().entry_ref();
            let key = b"role-owned-key";
            let change = request(&h, key, assigned);
            let before = h.db.frontier().unwrap();
            let vertex_count = h.db.vertices().unwrap().len();
            let edges = h.db.edges_at(before).unwrap();
            let first = record(&mut h, &change).unwrap();
            assert!(!first.already_recorded);
            assert_eq!(first.control.recorded_at.0, before.0 + 1);
            assert_eq!(h.db.vertices().unwrap().len() - vertex_count, 2);
            assert_eq!(h.db.edges_at(first.control.recorded_at).unwrap(), edges);
            let entry = h.db.vertex(first.control.entry.vid).unwrap().unwrap();
            let claim = h.db.vertex(outcome(&h, &change)).unwrap().unwrap();
            assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
            assert_eq!(claim.created_at, first.control.recorded_at);
            assert_eq!(claim.created_at, entry.created_at);
            assert_eq!(
                fa_journal::rows::prop(&claim, property::TARGET_REF),
                Some(
                    &CanonicalScalar::bytes(first.control.entry.vid.0.to_le_bytes().to_vec())
                        .unwrap()
                ),
            );
            assert_eq!(
                account_roles_at(&h.db, &h.book, first.control.recorded_at)
                    .unwrap()
                    .holds(h.cash, "suspense"),
                assigned,
            );
            let head = h.db.frontier().unwrap();
            let vertices = h.db.vertices().unwrap();
            let original = h.proposal(h.rent_legs(300), key, EntryClass::ORIGINAL);
            let reversal = h.reversal_of_entry(target, key);
            let resolution = h.resolution_posts(hold, h.rent_legs(150), vec![0, 1], key);
            for proposal in [original, reversal, resolution] {
                let refusal = h.post(h.request(proposal, &["post"])).unwrap_err();
                assert_eq!(
                    (refusal.code, refusal.exit),
                    (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT)
                );
            }
            let reversal = h.request(
                h.reversal_of_entry(target, b"role-unpublished-reversal"),
                &["post"],
            );
            let replacement = h.request(
                replacement_proposal(
                    target,
                    h.proposal(h.rent_legs(125), key, EntryClass::REPLACEMENT),
                ),
                &["post"],
            );
            let refusal = h.post_pair(reversal, replacement).unwrap_err();
            assert_eq!(
                (refusal.code, refusal.exit),
                (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT)
            );
            let member = h.proposal(
                h.rent_legs(300),
                b"role-unpublished-member",
                EntryClass::ORIGINAL,
            );
            let refusal = h.post_batch(h.batch(key, vec![member])).unwrap_err();
            assert_eq!(
                (refusal.code, refusal.exit),
                (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT)
            );
            assert_eq!(h.db.frontier().unwrap(), head);
            assert_eq!(h.db.vertices().unwrap(), vertices);
            assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
            assert!(h.db.vertex(resolution_vid(hold.vid)).unwrap().is_none());
            assert!(
                h.db.vertex(fa_journal::rows::replacement_vid(target.vid))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn account_role_retries_preserve_the_original_control_after_later_changes() {
        let mut h = harness();
        let original = request(&h, b"role-retry", true);
        let first = record(&mut h, &original).unwrap();
        let expected = AccountRoleRecorded {
            already_recorded: true,
            ..first
        };
        let subsequent = request(&h, b"role-subsequent", false);
        record(&mut h, &subsequent).unwrap();
        let head = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        assert_eq!(record(&mut h, &original).unwrap(), expected);
        let mut resealed = original.clone();
        resealed.description = h.statement("account role outcome", 142);
        assert_eq!(record(&mut h, &resealed).unwrap(), expected);
        for altered in 0..4 {
            let mut changed = original.clone();
            match altered {
                0 => changed.description = h.statement("different account role", 143),
                1 => changed.spec.account = h.receivable,
                2 => changed.spec.role = "intercompany".into(),
                3 => changed.spec.assigned = false,
                _ => unreachable!(),
            }
            refused_without_publication(&mut h, &changed, code::IDEMPOTENCY_CONFLICT);
        }
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
        assert!(
            !account_roles_at(&h.db, &h.book, head)
                .unwrap()
                .holds(h.cash, "suspense")
        );
    }

    #[test]
    fn a_prepared_reversal_loses_to_an_account_role_change_with_the_same_key() {
        let mut h = harness();
        let source = h.proposal(h.rent_legs(100), b"role-race-source", EntryClass::ORIGINAL);
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let key = b"role-race-key";
        let change = request(&h, key, true);
        let reversal = h.request(h.reversal_of_entry(target, key), &["post"]);
        let ctx = h.ctx();
        let PostPreparation::Ready(prepared) = prepare_post(&mut h.db, &ctx, &h.book, reversal)
            .unwrap()
            .unwrap()
        else {
            panic!("fresh reversal")
        };
        let epoch = security_policy_epoch(&h.db).unwrap();
        record(&mut h, &change).unwrap();
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

    /// The old role writer emitted only its sealed control. Construct that
    /// original publication directly, never by deleting a modern claim.
    fn write_legacy_role(
        h: &mut Harness,
        request: &RoleRequest,
        approvals: Vec<ApprovalRef>,
        plan_certificate: Option<Oid>,
    ) -> AccountRoleRecorded {
        let (proposal, _) = role_control(
            &h.book,
            &request.spec,
            PRINCIPAL,
            &request.key,
            request.description.clone(),
        )
        .unwrap();
        let entry = proposal.seal(approvals, plan_certificate).unwrap();
        let vid = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), &request.key);
        let mut batch = fgdb::WriteBatch::new(relation::IN_BOOK);
        batch.create_vertex(
            vid,
            vec![label::ENTRY],
            fa_model::entry_mirrors(&entry).unwrap(),
        );
        h.write_raw(batch);
        assert!(h.db.vertex(outcome(h, request)).unwrap().is_none());
        AccountRoleRecorded {
            control: AccountRoleControl {
                spec: request.spec.clone(),
                entry: entry.entry_ref(vid),
                recorded_at: h.db.frontier().unwrap(),
            },
            already_recorded: false,
        }
    }

    #[test]
    fn legacy_account_role_retries_survive_recovery_and_durable_reopen() {
        let mut h = harness_legacy();
        let source = h.proposal(
            h.rent_legs(100),
            b"legacy-role-source",
            EntryClass::ORIGINAL,
        );
        let target = outcome_recovery_tests::write_legacy(&mut h, source);
        let reversal = h.reversal_of_entry(target, b"legacy-role-reversal");
        outcome_recovery_tests::write_legacy(&mut h, reversal);
        let original = request(&h, b"legacy-role-change", true);
        let recorded = write_legacy_role(&mut h, &original, Vec::new(), None);
        let original_row = h.db.vertex(recorded.control.entry.vid).unwrap().unwrap();
        let expected = AccountRoleRecorded {
            already_recorded: true,
            ..recorded
        };
        assert_eq!(record(&mut h, &original).unwrap(), expected);
        let fresh = request(&h, b"fresh-role-change", true);
        refused_without_publication(&mut h, &fresh, code::PLAN_INVALIDATED);
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
        assert_eq!(record(&mut h, &original).unwrap(), expected);
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(
            h.db.vertex(expected.control.entry.vid).unwrap().unwrap(),
            original_row
        );
        assert!(h.db.vertex(outcome(&h, &original)).unwrap().is_none());
        let occupied = request(&h, b"legacy-role-reversal", true);
        refused_without_publication(&mut h, &occupied, code::IDEMPOTENCY_CONFLICT);
        let mut fresh = fresh;
        fresh.spec.assigned = false;
        assert!(!record(&mut h, &fresh).unwrap().already_recorded);
    }

    #[test]
    fn account_role_retries_reject_altered_envelopes_mirrors_and_deleted_claims() {
        for plan in [None, Some(Oid([144; 32]))] {
            let mut h = harness_legacy();
            let request = request(&h, b"role-altered-envelope", true);
            let approvals = if plan.is_none() {
                vec![h.approve_digest(VId(70), [11; 32]).unwrap()]
            } else {
                Vec::new()
            };
            write_legacy_role(&mut h, &request, approvals, plan);
            refused_without_publication(&mut h, &request, code::IDEMPOTENCY_CONFLICT);
        }
        for delete_claim in [true, false] {
            let mut h = harness();
            let request = request(&h, b"role-damaged-publication", true);
            let recorded = record(&mut h, &request).unwrap();
            let claim = outcome(&h, &request);
            assert!(
                h.db.vertex_at(claim, recorded.control.recorded_at)
                    .unwrap()
                    .is_some()
            );
            let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
            if delete_claim {
                damage.delete_vertex(claim);
            } else {
                damage.set_vertex_property(
                    recorded.control.entry.vid,
                    property::FA_EFFECTIVE_DAY,
                    Some(CanonicalScalar::Int(1)),
                );
            }
            h.write_raw(damage);
            refused_without_publication(&mut h, &request, code::IDEMPOTENCY_CONFLICT);
        }
    }

    #[test]
    fn account_role_authority_is_checked_before_outcome_observation() {
        let mut h = harness();
        let request = request(&h, b"unread-account-role", true);
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
        let capability = Capability::embedded(PRINCIPAL, SCHEMA).unwrap();
        h.revoke(&capability, 145);
        let head = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        let scoped = capability.clone().for_periods(&[h.march.as_str()]).unwrap();
        for (capability, expected) in [(scoped, "FA-REF-011"), (capability, "FA-REF-023")] {
            let refusal = execute(&mut h, &request, &capability).unwrap().unwrap_err();
            assert_eq!((refusal.code, refusal.exit), (expected, exit::SAFETY));
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
