//! A closing draft delegates only Close to its independent promoter. The
//! retained planner, complete intrinsic source and approval law stay intact.

use super::*;
use fa_journal::closing::{YearEndCloseRequest, prepare_year_end_close_for_draft};

fn request() -> YearEndCloseRequest {
    YearEndCloseRequest {
        fiscal_year: 2026,
        closing_period: "FY2026-CLOSE".into(),
    }
}

fn reviewed(h: &Harness, capability: &Capability, key: &[u8]) -> EntryPayload {
    let prepared =
        prepare_year_end_close_for_draft(&h.db, &h.ctx(), &h.book, capability, &request())
            .unwrap()
            .unwrap();
    let mut proposal = year_end_close_proposal(h, &prepared, key);
    proposal.principal_ref = capability.holder();
    proposal
}

fn closer() -> Capability {
    Capability::embedded(APPROVER, &["read", "approve", "close"]).unwrap()
}

fn plan_approved(
    h: &mut Harness,
    capability: Capability,
    name: &str,
    proposal: EntryPayload,
    approvals: Vec<fa_model::ApprovalRef>,
) -> Result<DraftPlanned, Refusal> {
    let intent = fa_intents::PostIntent::new(proposal, approvals).unwrap();
    let req = h.draft_request(capability);
    let ctx = h.ctx();
    h.runtime
        .block_on(plan_into_draft(&mut h.db, &ctx, &h.book, name, intent, req))
        .unwrap()
}

fn fixture() -> (Harness, Capability) {
    let (mut h, _) = year_end_close_fixture();
    h.post(h.request(h.invoice(20_000, b"closing-draft-source"), &["post"]))
        .unwrap();
    let agent = h.agent_capability();
    (h, agent)
}

#[test]
fn closing_draft_preserves_review_and_requires_an_independent_current_closer() {
    let (mut h, agent) = fixture();
    assert!(!agent.holds(fa_policy::Op::Close));
    let before = h.db.frontier().unwrap();
    let proposal = reviewed(&h, &agent, b"governed-close");
    assert_eq!(h.db.frontier().unwrap(), before);
    assert!(
        fa_journal::closing::prepare_year_end_close(&h.db, &h.ctx(), &h.book, &agent, &request(),)
            .unwrap()
            .is_err()
    );
    let direct = PostRequest {
        proposal: proposal.clone(),
        approvals: Vec::new(),
        capability: agent.clone(),
        plan_certificate: None,
    };
    assert!(h.post_plan(direct.clone()).is_err());
    assert!(h.post(direct).is_err());
    assert_eq!(h.db.frontier().unwrap(), before);

    h.open_draft(agent.clone(), "year-close").unwrap();
    let approval = h.approve_transition(proposal.proposal_digest().unwrap());
    let planned = plan_approved(
        &mut h,
        agent.clone(),
        "year-close",
        proposal.clone(),
        vec![approval],
    )
    .unwrap();
    let expected = planned.plan.unwrap().members()[0].entry.entry_digest;
    h.open_draft(agent.clone(), "unrelated-control").unwrap();
    let before = h.db.frontier().unwrap();
    let view = h.draft("year-close");
    assert_eq!(view.intents.len(), 1);
    assert_eq!(view.intents[0].capability, agent);
    assert_eq!(view.intents[0].intent.proposal(), &proposal);
    assert_eq!(view.intents[0].intent.approvals(), &[approval]);
    assert_eq!(year_end_close_net(&h, h.revenue, before), -20_000);
    let missing_close = h
        .promote(h.approver_capability(), "year-close")
        .unwrap_err();
    assert!(missing_close.message.contains("close"), "{missing_close}");
    assert!(h.promote(agent, "year-close").is_err());
    let self_approval = Capability::embedded(AGENT, &["read", "approve", "close"]).unwrap();
    assert_eq!(
        h.promote(self_approval, "year-close").unwrap_err().code,
        "FA-REF-008"
    );
    assert_eq!(h.db.frontier().unwrap(), before);

    let ctx = h.ctx();
    let target = h
        .runtime
        .block_on(Database::open_memory(
            &ctx.commit(),
            DatabaseKeys::new([221; 32], DatabaseSecurityNamespaceId([222; 32]), [223; 32]),
        ))
        .unwrap();
    let (scratch, rehearsal) = h
        .runtime
        .block_on(rehearse_draft_into(
            &mut h.db,
            target,
            &ctx,
            &h.book,
            &closer(),
            DraftRehearsalRequest {
                name: "year-close".into(),
                known_at: before,
            },
        ))
        .unwrap()
        .unwrap();
    assert_eq!(scratch.frontier().unwrap().0, before.0 + 1);
    assert_eq!(h.db.frontier().unwrap(), before);
    assert_eq!(rehearsal.batch.entries.len(), 1);
    assert_eq!(rehearsal.batch.entries[0].entry_digest, expected);
    let verification =
        fa_journal::closing::verify_year_end_close(&scratch, &ctx, &h.book, &closer(), 2026, None)
            .unwrap()
            .unwrap();
    assert!(verification.is_green());
    assert!(!verification.needs_reclose);

    let promoted = h.promote(closer(), "year-close").unwrap();
    assert_eq!(promoted.recorded_at.0, before.0 + 1);
    assert_eq!(promoted.entries.len(), 1);
    assert_eq!(promoted.entries[0].entry_digest, expected);
    assert_eq!(year_end_close_net(&h, h.revenue, promoted.recorded_at), 0);
    let (entry, _) = read_entry(&h.db, promoted.entries[0].vid).unwrap().unwrap();
    assert_eq!(entry.proposal, proposal);
    assert_eq!(h.draft("year-close").state, DraftState::Promoted);
    let retry = h.promote(closer(), "year-close").unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, promoted.entries);
    assert_eq!(h.db.frontier().unwrap(), promoted.recorded_at);
}

#[test]
fn closing_draft_closed_period_still_requires_the_exact_proposal_approval() {
    let (mut h, agent) = fixture();
    h.transition("FY2026-CLOSE", PeriodTransition::SoftClose, b"closing-soft")
        .unwrap();
    h.transition("FY2026-CLOSE", PeriodTransition::Close, b"closing-closed")
        .unwrap();
    let proposal = reviewed(&h, &agent, b"approved-closing-draft");
    h.open_draft(agent.clone(), "closed-year").unwrap();
    let before = h.db.frontier().unwrap();
    assert!(
        h.plan_draft(agent.clone(), "closed-year", proposal.clone())
            .is_err()
    );
    assert_eq!(h.db.frontier().unwrap(), before);
    assert!(h.draft("closed-year").intents.is_empty());
    let approval = h.approve_transition(proposal.proposal_digest().unwrap());
    plan_approved(&mut h, agent, "closed-year", proposal, vec![approval]).unwrap();
    h.promote(closer(), "closed-year").unwrap();
    let verified = year_end_close_verify(&h, None);
    assert!(verified.is_green());
    assert!(!verified.needs_reclose);
}

#[test]
fn closing_draft_refuses_mixed_members_in_both_orders_without_partial_records() {
    for close_first in [true, false] {
        let (mut h, agent) = fixture();
        h.open_draft(agent.clone(), "singleton").unwrap();
        let close = reviewed(&h, &agent, b"singleton-close");
        let ordinary = h.agent_rent(100, b"singleton-ordinary");
        let (first, second) = if close_first {
            (close, ordinary)
        } else {
            (ordinary, close)
        };
        h.plan_draft(agent.clone(), "singleton", first).unwrap();
        let before = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let refusal = h.plan_draft(agent, "singleton", second).unwrap_err();
        assert_eq!(refusal.code, code::CLASS_NOT_IMPLEMENTED);
        assert_eq!(h.db.frontier().unwrap(), before);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(h.draft("singleton").intents.len(), 1);
    }
}

#[test]
fn closing_draft_rejects_changed_then_reversed_sources_at_append_and_promotion() {
    for already_planned in [false, true] {
        let (mut h, agent) = fixture();
        h.open_draft(agent.clone(), "stale-close").unwrap();
        let proposal = reviewed(&h, &agent, b"stale-close-intent");
        if already_planned {
            h.plan_draft(agent.clone(), "stale-close", proposal.clone())
                .unwrap();
        }
        let added = h
            .post(h.request(h.invoice(50, b"late-source"), &["post"]))
            .unwrap()
            .entry_ref();
        h.post(h.request(h.reversal_of_entry(added, b"undo-late-source"), &["post"]))
            .unwrap();
        let before = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        assert_eq!(year_end_close_net(&h, h.revenue, before), -20_000);
        let refusal = if already_planned {
            h.promote(closer(), "stale-close").unwrap_err()
        } else {
            h.plan_draft(agent, "stale-close", proposal).unwrap_err()
        };
        assert_eq!(refusal.code, code::PLAN_INVALIDATED, "{refusal}");
        assert_eq!(h.db.frontier().unwrap(), before);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(h.draft("stale-close").state, DraftState::Open);
    }
}

#[test]
fn closing_draft_rechecks_routes_period_and_both_current_capabilities() {
    for change in ["routes", "period", "planner-revoked", "promoter-revoked"] {
        let (mut h, agent) = fixture();
        h.open_draft(agent.clone(), "changed-close").unwrap();
        let proposal = reviewed(&h, &agent, b"changed-close-intent");
        h.plan_draft(agent.clone(), "changed-close", proposal)
            .unwrap();
        match change {
            "routes" => {
                let equity = account_vid(h.book.book_id, "3000");
                let routes = [(h.rent, equity), (h.revenue, equity)].into();
                year_end_close_routes(&mut h, routes, b"new-route-record");
            }
            "period" => {
                h.transition(
                    "FY2026-CLOSE",
                    PeriodTransition::SoftClose,
                    b"new-close-state",
                )
                .unwrap();
            }
            "planner-revoked" => h.revoke(&agent, 224),
            "promoter-revoked" => h.revoke(&closer(), 225),
            _ => unreachable!(),
        }
        let before = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let refusal = h.promote(closer(), "changed-close").unwrap_err();
        let expected = if change.ends_with("revoked") {
            "FA-REF-023"
        } else {
            code::PLAN_INVALIDATED
        };
        assert_eq!(refusal.code, expected, "{change}: {refusal}");
        assert_eq!(h.db.frontier().unwrap(), before);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(h.draft("changed-close").state, DraftState::Open);
    }
}
