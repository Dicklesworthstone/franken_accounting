//! Native drafts retain the reviewed foreign relief and promote independent
//! existing items through the same guarded atomic carrying-value batch law.

use super::*;

fn agent_proposal(prepared: PreparedFxSettlement) -> EntryPayload {
    let mut proposal = prepared.into_proposal();
    proposal.principal_ref = AGENT;
    proposal
}

fn planned_pair(f: &mut Fixture, name: &str, second_amount: i128) -> (EntryRef, Vec<EntryRef>) {
    let second = f.another_target();
    let agent = f.h.agent_capability();
    f.h.open_draft(agent.clone(), name).unwrap();
    let first = agent_proposal(f.prepare(1, b"draft-fx-first"));
    let later = agent_proposal(f.prepare_for(second, second_amount, b"draft-fx-second"));
    f.h.plan_draft(agent.clone(), name, first).unwrap();
    let planned = f.h.plan_draft(agent, name, later).unwrap();
    let entries = planned
        .plan
        .unwrap()
        .members()
        .iter()
        .map(|member| {
            member.entry.entry_ref(entry_vid(
                f.h.book.book_id,
                &AGENT.0.to_le_bytes(),
                &member.entry.proposal.idempotency_key,
            ))
        })
        .collect();
    (second, entries)
}

fn assert_unpublished(f: &Fixture, name: &str, entries: &[EntryRef]) {
    assert_eq!(f.h.draft(name).state, DraftState::Open);
    for entry in entries {
        assert!(read_entry(&f.h.db, entry.vid).unwrap().is_none());
    }
}

#[test]
fn an_agent_drafts_foreign_relief_and_an_independent_human_promotes_exactly_once() {
    for (base, second_amount, expected) in [(10, 3, [(2, 7), (0, 0)]), (1, 1, [(2, 1), (2, 1)])] {
        let mut f = fixture(3, base);
        let name = "foreign-collections";
        let (second, entries) = planned_pair(&mut f, name, second_amount);
        assert_unpublished(&f, name, &entries);
        for target in [f.target, second] {
            let item = f.carrying_for(target);
            assert_eq!(
                (item.open_native.mantissa, item.open_base.mantissa),
                (3, base)
            );
        }

        // Planning does not give the Agent a direct trunk capability, and
        // the owner cannot impersonate an independent promoter.
        let before = f.h.db.frontier().unwrap();
        let mut direct = request(agent_proposal(f.prepare(1, b"agent-cannot-publish")));
        direct.capability = f.h.agent_capability();
        assert_eq!(f.h.post(direct).unwrap_err().exit, exit::SAFETY);
        let owner = Capability::embedded(AGENT, &["read", "approve"]).unwrap();
        let refusal = f.h.promote(owner, name).unwrap_err();
        assert_eq!((refusal.code, refusal.exit), ("FA-REF-008", exit::SAFETY));
        assert_eq!(f.h.db.frontier().unwrap(), before);

        let promoted = f.h.promote(f.h.approver_capability(), name).unwrap();
        assert_eq!(promoted.recorded_at.0, before.0 + 1);
        assert_eq!(promoted.entries, entries);
        assert!(!promoted.already_recorded);
        for target in &promoted.entries {
            let (entry, recorded_at) = read_entry(&f.h.db, target.vid).unwrap().unwrap();
            assert_eq!(entry.entry_digest, target.entry_digest);
            assert_eq!(recorded_at, promoted.recorded_at);
            assert_eq!(entry.proposal.principal_ref, AGENT);
        }
        for (target, expected) in [f.target, second].into_iter().zip(expected) {
            let item = f.carrying_for(target);
            assert_eq!(
                (item.open_native.mantissa, item.open_base.mantissa),
                expected
            );
        }
        assert_eq!(f.h.draft(name).state, DraftState::Promoted);
        f.verify();
        let rows = f.h.db.vertices().unwrap();
        let retry = f.h.promote(f.h.approver_capability(), name).unwrap();
        assert!(retry.already_recorded);
        assert_eq!(retry.entries, promoted.entries);
        assert_eq!(retry.recorded_at, promoted.recorded_at);
        assert_eq!(f.h.db.frontier().unwrap(), promoted.recorded_at);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn changed_later_foreign_relief_refuses_the_entire_draft_without_repricing_it() {
    let mut f = fixture(3, 10);
    let name = "foreign-carrying-drift";
    let (second, entries) = planned_pair(&mut f, name, 1);
    // Both reviewed applications relieved 3. A competing application to
    // the later target leaves 2 native / 7 base, whose next 1 relieves 4.
    let competing = f
        .prepare_for(second, 1, b"competing-foreign-receipt")
        .into_proposal();
    f.h.post(request(competing)).unwrap();
    let before = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let refusal = f.h.promote(f.h.approver_capability(), name).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-071", "{refusal}");
    assert!(refusal.message.contains("batch member 1"), "{refusal}");
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    assert_unpublished(&f, name, &entries);
    let first = f.carrying();
    let later = f.carrying_for(second);
    assert_eq!(
        (first.open_native.mantissa, first.open_base.mantissa),
        (3, 10)
    );
    assert_eq!(
        (later.open_native.mantissa, later.open_base.mantissa),
        (2, 7)
    );
    f.verify();
}

#[test]
fn revoked_foreign_draft_planner_cannot_be_replaced_by_the_promoters_authority() {
    let mut f = fixture(3, 10);
    let name = "revoked-foreign-planner";
    let (second, entries) = planned_pair(&mut f, name, 1);
    let agent = f.h.agent_capability();
    f.h.revoke(&agent, 181);
    let before = f.h.db.frontier().unwrap();
    let rows = f.h.db.vertices().unwrap();
    let refusal = f.h.promote(f.h.approver_capability(), name).unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-023", exit::SAFETY));
    assert_eq!(f.h.db.frontier().unwrap(), before);
    assert_eq!(f.h.db.vertices().unwrap(), rows);
    assert_unpublished(&f, name, &entries);
    for target in [f.target, second] {
        let item = f.carrying_for(target);
        assert_eq!(
            (item.open_native.mantissa, item.open_base.mantissa),
            (3, 10)
        );
    }
}

#[test]
fn foreign_drafts_still_refuse_overlapping_sources_mixed_members_and_groups() {
    for variant in ["overlap", "forged-overlap", "mixed", "group"] {
        let mut f = fixture(3, 10);
        let second = f.another_target();
        let agent = f.h.agent_capability();
        f.h.open_draft(agent.clone(), variant).unwrap();
        let first = agent_proposal(f.prepare(1, b"first-foreign-member"));
        f.h.plan_draft(agent.clone(), variant, first).unwrap();
        let mut later = match variant {
            "mixed" => f.h.agent_rent(1, b"unrelated-native-member"),
            "group" => {
                let mut proposal = f
                    .prepare_group(
                        &[f.fx_request(f.target, 1), f.fx_request(second, 1)],
                        b"multiple-targets-in-one-member",
                    )
                    .unwrap()
                    .into_proposal();
                proposal.principal_ref = AGENT;
                proposal
            }
            _ => agent_proposal(f.prepare(1, b"same-foreign-source")),
        };
        if variant == "forged-overlap" {
            let applying = later
                .legs
                .iter_mut()
                .find(|leg| !leg.settles.is_empty())
                .unwrap();
            applying.settles[0].target.entry_digest[0] ^= 1;
        }
        let before = f.h.db.frontier().unwrap();
        let rows = f.h.db.vertices().unwrap();
        let planned = f.h.draft(variant);
        let refusal = f.h.plan_draft(agent, variant, later).unwrap_err();
        let expected = if variant == "mixed" {
            "FA-REF-102"
        } else {
            "FA-REF-071"
        };
        assert_eq!(refusal.code, expected, "{variant}: {refusal}");
        assert_eq!(f.h.db.frontier().unwrap(), before);
        assert_eq!(f.h.db.vertices().unwrap(), rows);
        assert_eq!(f.h.draft(variant), planned);
    }
}
