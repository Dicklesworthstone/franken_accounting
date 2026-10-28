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
