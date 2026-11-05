//! Lifecycle retries require current authority before they observe retained
//! draft data, even when they publish nothing and never open a transaction.

use super::*;
use fa_policy::{Op, Profile, possession_digest};
use fgdb::WriteBatch;

fn issued(h: &mut Harness, holder: VId, profile: Profile, ops: &[Op], salt: u8) -> Capability {
    let capability = Capability::new(holder, profile, ops, PRINCIPAL)
        .unwrap()
        .holder_bound(possession_digest(&[salt; 32]));
    let request = fa_journal::policy::IssuanceRequest {
        capability: Capability::embedded(
            PRINCIPAL,
            &["read", "post", "approve", "issue_capability"],
        )
        .unwrap(),
        issued: capability.clone(),
        effective_date: h.day(),
        idempotency_key: vec![b'i', salt],
        description: h.statement("issued draft authority", salt),
    };
    let ctx = h.ctx();
    h.runtime
        .block_on(fa_journal::policy::issue_capability(
            &mut h.db, &ctx, &h.book, request,
        ))
        .unwrap()
        .unwrap();
    capability
}

#[test]
fn draft_authority_rechecks_promoters_before_acknowledging_recorded_promotion() {
    let mut h = harness();
    let agent = h.agent_capability();
    h.open_draft(agent.clone(), "promoted").unwrap();
    h.plan_draft(agent, "promoted", h.agent_rent(100, b"promoted-member"))
        .unwrap();
    let promoter = issued(
        &mut h,
        APPROVER,
        Profile::Human,
        &[Op::Read, Op::Approve],
        81,
    );
    let first = h.promote(promoter.clone(), "promoted").unwrap();
    let retry = h.promote(promoter.clone(), "promoted").unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, first.entries);
    assert_eq!(retry.recorded_at, first.recorded_at);

    let unissued = promoter.clone().holder_bound(possession_digest(&[82; 32]));
    h.revoke(&promoter, 83);
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    for (capability, expected) in [(promoter, "FA-REF-023"), (unissued, "FA-REF-156")] {
        let refusal = h.promote(capability, "promoted").unwrap_err();
        assert_eq!((refusal.code, refusal.exit), (expected, exit::SAFETY));
    }
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn draft_authority_rechecks_owners_before_acknowledging_recorded_plan_or_discard() {
    let mut h = harness();
    let owner = issued(&mut h, AGENT, Profile::Agent, &[Op::Read, Op::Post], 84);
    h.open_draft(owner.clone(), "discarded").unwrap();
    let proposal = h.agent_rent(100, b"discarded-member");
    let planned = h
        .plan_draft(owner.clone(), "discarded", proposal.clone())
        .unwrap();
    let discarded = h.discard(owner.clone(), "discarded").unwrap();
    let plan_retry = h
        .plan_draft(owner.clone(), "discarded", proposal.clone())
        .unwrap();
    assert!(plan_retry.recorded.already_recorded);
    assert_eq!(
        plan_retry.recorded.control_entry,
        planned.recorded.control_entry
    );
    let discard_retry = h.discard(owner.clone(), "discarded").unwrap();
    assert!(discard_retry.already_recorded);
    assert_eq!(discard_retry.control_entry, discarded.control_entry);

    let unissued = owner.clone().holder_bound(possession_digest(&[85; 32]));
    h.revoke(&owner, 86);
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    for (capability, expected) in [(owner, "FA-REF-023"), (unissued, "FA-REF-156")] {
        let planned = h
            .plan_draft(capability.clone(), "discarded", proposal.clone())
            .unwrap_err();
        let discarded = h.discard(capability, "discarded").unwrap_err();
        assert_eq!((planned.code, planned.exit), (expected, exit::SAFETY));
        assert_eq!(discarded, planned);
    }
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn draft_authority_refuses_before_decoding_corrupt_or_absent_lifecycle_targets() {
    for revoke in [false, true] {
        let mut h = harness();
        let owner = Capability::embedded(PRINCIPAL, &["post", "approve"]).unwrap();
        let opened = h.open_draft(owner, "planted").unwrap();
        let capability = if revoke {
            let issued = issued(
                &mut h,
                PRINCIPAL,
                Profile::Human,
                &[Op::Post, Op::Approve],
                87,
            );
            h.revoke(&issued, 88);
            issued
        } else {
            Capability::new(
                PRINCIPAL,
                Profile::Human,
                &[Op::Post, Op::Approve],
                PRINCIPAL,
            )
            .unwrap()
            .holder_bound(possession_digest(&[89; 32]))
        };
        let ctx = h.ctx();
        let mut batch = WriteBatch::new(relation::IN_CASE);
        batch.set_vertex_property(
            opened.draft,
            property::FA_PAYLOAD,
            Some(fa_journal::rows::scalar_bytes("corrupt draft", vec![0xff; 8]).unwrap()),
        );
        h.runtime
            .block_on(h.db.write(&ctx.commit(), batch))
            .unwrap();
        assert!(
            read_draft(&h.db, &ctx.query(), &h.book, "planted").is_err(),
            "the target trap is live for a reader that reaches its payload",
        );
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let mut expected = None;
        for name in ["absent", "planted"] {
            let proposal = h.proposal(h.rent_legs(100), b"unadmitted-plan", EntryClass::ORIGINAL);
            let refusals = [
                h.plan_draft(capability.clone(), name, proposal)
                    .unwrap_err(),
                h.discard(capability.clone(), name).unwrap_err(),
                h.promote(capability.clone(), name).unwrap_err(),
            ];
            for refusal in refusals {
                assert_eq!(
                    (refusal.code, refusal.exit),
                    (
                        if revoke { "FA-REF-023" } else { "FA-REF-156" },
                        exit::SAFETY
                    ),
                );
                if let Some(expected) = &expected {
                    assert_eq!(&refusal, expected, "no target contents are observed");
                } else {
                    expected = Some(refusal);
                }
            }
        }
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

fn post_only_draft_capability(h: &Harness, name: &str) -> Capability {
    Capability::new(AGENT, Profile::Agent, &[Op::Post], PRINCIPAL)
        .unwrap()
        .on_branch(fa_model::draft_branch(h.book.book_id, name))
        .unwrap()
}

#[test]
fn a_post_only_branch_capability_plans_only_its_named_draft_and_preserves_promotion() {
    let mut h = harness();
    let name = "confined-agent";
    let capability = post_only_draft_capability(&h, name);
    let branch = fa_model::draft_branch(h.book.book_id, name);
    let opened = h.open_draft(capability.clone(), name).unwrap();
    assert_eq!(branch.to_hex(), format!("{:032x}", opened.draft.0));
    assert_ne!(branch, Id128::TRUNK);
    assert_ne!(branch, fa_model::draft_branch(h.book.book_id, "another"));

    let proposal = h.agent_rent(123, b"confined-member");
    let expected = h.member_ref(&proposal);
    let planned = h
        .plan_draft(capability.clone(), name, proposal.clone())
        .unwrap();
    assert_eq!(
        planned.plan.unwrap().members()[0]
            .entry
            .entry_ref(expected.vid),
        expected
    );
    assert!(h.db.vertex(expected.vid).unwrap().is_none());
    let before = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();

    let retry = h
        .plan_draft(capability.clone(), name, proposal.clone())
        .unwrap();
    assert!(retry.recorded.already_recorded);
    for other in ["another", "does-not-exist"] {
        let denied = h.open_draft(capability.clone(), other).unwrap_err();
        assert!(denied.message.contains("branch"), "{denied}");
        let denied = h
            .plan_draft(capability.clone(), other, proposal.clone())
            .unwrap_err();
        assert!(denied.message.contains("branch"), "{denied}");
        let denied = h.discard(capability.clone(), other).unwrap_err();
        assert!(denied.message.contains("branch"), "{denied}");
    }
    let mut direct = h.request(proposal.clone(), &["post"]);
    direct.capability = capability.clone();
    assert!(
        h.post(direct.clone()).is_err(),
        "no direct Agent trunk publication"
    );
    let denied = h.post_plan(direct).unwrap_err();
    assert!(
        denied.message.contains("branch"),
        "no portable trunk plan: {denied}"
    );
    assert!(fa_policy::admit_read(&capability, AGENT, h.book.book_id).is_err());
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), rows);

    let promoted = h.promote(h.approver_capability(), name).unwrap();
    assert_eq!(promoted.entries, vec![expected]);
    let (posted, at) = read_entry(&h.db, expected.vid).unwrap().unwrap();
    assert_eq!(posted.proposal, proposal);
    assert_eq!(at, promoted.recorded_at);
    assert_eq!(posted.proposal.branch_id, Id128::TRUNK);
    assert_eq!(posted.proposal.principal_ref, AGENT);
    assert!(
        h.plan_draft(capability, name, proposal)
            .unwrap()
            .recorded
            .already_recorded
    );
}

#[test]
fn draft_branch_confinement_keeps_ceiling_revocation_and_required_rehearsal_checks() {
    let mut h = harness();
    let name = "confined-laws";
    let capability = post_only_draft_capability(&h, name)
        .with_ceiling(h.usd, 200)
        .unwrap();
    h.open_draft(capability.clone(), name).unwrap();
    let before = h.db.frontier().unwrap();
    let denied = h
        .plan_draft(capability.clone(), name, h.agent_rent(201, b"too-much"))
        .unwrap_err();
    assert!(denied.message.contains("ceiling"), "{denied}");
    assert_eq!(h.db.frontier().unwrap(), before);
    h.plan_draft(capability.clone(), name, h.agent_rent(200, b"admitted"))
        .unwrap();
    h.revoke(&capability, 91);
    let before = h.db.frontier().unwrap();
    let denied = h.promote(h.approver_capability(), name).unwrap_err();
    assert_eq!(denied.code, "FA-REF-023", "{denied}");
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.draft(name).state, DraftState::Open);

    // Tag 12 is explicit on a non-Agent base profile. Agent-profile tokens
    // already require posting rehearsal, and their canonical constructor
    // deliberately does not add this separate control-write caveat.
    let required = Capability::new(AGENT, Profile::Human, &[Op::Post], PRINCIPAL)
        .unwrap()
        .with_operator_kind(fa_policy::OperatorKind::Agent)
        .unwrap()
        .on_branch(fa_model::draft_branch(
            h.book.book_id,
            "unrehearsed-control",
        ))
        .unwrap()
        .with_requires_dry_run();
    assert!(required.has_requires_dry_run_caveat());
    let before = h.db.frontier().unwrap();
    let denied = h.open_draft(required, "unrehearsed-control").unwrap_err();
    assert!(denied.message.contains("requires_dry_run"), "{denied}");
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn a_draft_branch_cannot_be_rebound_by_replacing_the_retained_body() {
    let mut h = harness();
    let name = "confined-original";
    let owner = post_only_draft_capability(&h, name);
    let opened = h.open_draft(owner.clone(), name).unwrap();
    let other = "confined-rebound";
    let other_owner = post_only_draft_capability(&h, other);
    h.open_draft(other_owner.clone(), other).unwrap();
    let other_body = h.draft(other).body;
    let mut damage = WriteBatch::new(relation::IN_CASE);
    for (key, value) in [
        (
            property::FA_PAYLOAD,
            fa_journal::rows::scalar_bytes("draft body", other_body.canonical_bytes().unwrap())
                .unwrap(),
        ),
        (
            property::FA_DIGEST,
            fa_journal::rows::scalar_bytes("draft digest", other_body.digest().unwrap().to_vec())
                .unwrap(),
        ),
        (
            property::CODE,
            fa_journal::rows::scalar_text("draft name", other).unwrap(),
        ),
    ] {
        damage.set_vertex_property(opened.draft, key, Some(value));
    }
    let cx = h.ctx();
    h.runtime
        .block_on(h.db.write(&cx.commit(), damage))
        .unwrap();
    let before = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();

    // A caller confined elsewhere is refused before the corrupted root is
    // decoded, while its actual owner must not mint a token for the new name.
    let denied = h
        .plan_draft(other_owner, name, h.agent_rent(100, b"wrong-branch"))
        .unwrap_err();
    assert!(denied.message.contains("branch"), "{denied}");
    let request = h.draft_request(owner);
    let intent =
        fa_intents::PostIntent::new(h.agent_rent(100, b"rebound-body"), Vec::new()).unwrap();
    let error = h
        .runtime
        .block_on(plan_into_draft(
            &mut h.db, &cx, &h.book, name, intent, request,
        ))
        .unwrap_err();
    assert!(error.to_string().contains("identity or mirrors"), "{error}");
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(h.db.vertices().unwrap(), rows);
}
