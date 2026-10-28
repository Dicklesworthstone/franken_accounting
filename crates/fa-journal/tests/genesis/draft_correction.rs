//! Reviewed correction pairs retain the native pair law across planning,
//! scratch review, independent promotion, and retries of closed drafts.

use super::*;
use fa_intents::{PostBatch, PostIntent};
use fa_journal::refusal::code;
use fa_model::symbols::label;
use fgdb_types::CommitSeq;

impl Harness {
    fn plan_correction(
        &mut self,
        capability: Capability,
        name: &str,
        pair: &(PostIntent, PostIntent),
    ) -> Result<DraftPlanned, Refusal> {
        let request = self.draft_request(capability);
        let cx = self.ctx();
        self.runtime
            .block_on(plan_correction_into_draft(
                &mut self.db,
                &cx,
                &self.book,
                name,
                pair.0.clone(),
                pair.1.clone(),
                request,
            ))
            .unwrap()
    }

    fn correction_pair(
        &self,
        target: EntryRef,
        replacement: EntryPayload,
    ) -> (PostIntent, PostIntent) {
        let mut reversal = self.reversal_of_entry(target, b"draft-correction-reverse");
        reversal.principal_ref = AGENT;
        let mut replacement = replacement_proposal(target, replacement);
        replacement.principal_ref = AGENT;
        (
            PostIntent::new(reversal, Vec::new()).unwrap(),
            PostIntent::new(replacement, Vec::new()).unwrap(),
        )
    }
}

fn rent_target(h: &mut Harness) -> EntryRef {
    h.post(h.request(
        h.proposal(
            h.rent_legs(1_000),
            b"correction-target",
            EntryClass::ORIGINAL,
        ),
        &["post"],
    ))
    .unwrap()
    .entry_ref()
}

fn expected_refs(target: EntryRef, preview: &DraftPreview) -> Vec<EntryRef> {
    [
        reversal_vid(target.vid),
        fa_journal::rows::replacement_vid(target.vid),
    ]
    .into_iter()
    .zip(preview.members())
    .map(|(vid, member)| member.entry.entry_ref(vid))
    .collect()
}

fn cash_net(db: &Database<MemVfs>, cash: VId) -> i128 {
    db.vertices()
        .unwrap()
        .iter()
        .filter(|row| row.labels.contains(&label::ENTRY))
        .map(|row| read_entry(db, row.vid).unwrap().unwrap().0)
        .flat_map(|entry| entry.proposal.legs)
        .filter(|leg| leg.account_ref == cash)
        .map(|leg| {
            if leg.side == Side::Debit {
                leg.amount.mantissa
            } else {
                -leg.amount.mantissa
            }
        })
        .sum()
}

#[test]
fn correction_draft_agent_reviews_exact_pair_then_independent_promoter_publishes_once() {
    let mut h = harness();
    let target = rent_target(&mut h);
    let agent = h.agent_capability();
    h.open_draft(agent.clone(), "correct-rent").unwrap();
    let pair = h.correction_pair(target, h.agent_rent(1_250, b"corrected-rent"));
    let before_plan = h.db.frontier().unwrap();
    let planned = h
        .plan_correction(agent.clone(), "correct-rent", &pair)
        .unwrap();
    assert_eq!(planned.recorded.recorded_at, CommitSeq(before_plan.0 + 1));
    let preview = planned.plan.unwrap();
    let expected = expected_refs(target, &preview);
    let view = h.draft("correct-rent");
    assert_eq!(view.intents.len(), 2);
    assert!(view.intents.iter().all(|member| {
        member.record == planned.recorded.control_entry
            && member.capability == agent
            && member.recorded_at == planned.recorded.recorded_at
    }));
    let (record, _) = read_entry(&h.db, planned.recorded.control_entry)
        .unwrap()
        .unwrap();
    let extension = record
        .proposal
        .extensions
        .iter()
        .find(|(kind, _)| *kind == fa_model::entry::DRAFT_INTENT_EXTENSION)
        .unwrap();
    assert_eq!(extension.1[..2], 5_u16.to_le_bytes());
    for entry in &expected {
        assert!(read_entry(&h.db, entry.vid).unwrap().is_none());
    }
    assert_eq!(cash_net(&h.db, h.cash), -1_000);

    let cx = h.ctx();
    let second_preview = h
        .runtime
        .block_on(preview_draft(
            &mut h.db,
            &cx,
            &h.book,
            &agent,
            "correct-rent",
        ))
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(expected_refs(target, &second_preview), expected);
    let source_head = h.db.frontier().unwrap();
    let source_rows = h.db.vertices().unwrap();
    let scratch = h
        .runtime
        .block_on(Database::open_memory(
            &cx.commit(),
            DatabaseKeys::new([201; 32], DatabaseSecurityNamespaceId([202; 32]), [203; 32]),
        ))
        .unwrap();
    let reader = Capability::embedded(VId(93), &["read"]).unwrap();
    let (scratch, rehearsal) = h
        .runtime
        .block_on(rehearse_draft_into(
            &mut h.db,
            scratch,
            &cx,
            &h.book,
            &reader,
            DraftRehearsalRequest {
                name: "correct-rent".into(),
                known_at: source_head,
            },
        ))
        .unwrap()
        .unwrap();
    assert_eq!(rehearsal.source.plans.len(), 1);
    assert_eq!(rehearsal.batch.entries, expected);
    assert_eq!(rehearsal.batch.recorded_at, CommitSeq(source_head.0 + 1));
    assert_eq!(cash_net(&scratch, h.cash), -1_250);
    assert_eq!(h.db.frontier().unwrap(), source_head);
    assert_eq!(h.db.vertices().unwrap(), source_rows);
    assert_eq!(h.draft("correct-rent").state, DraftState::Open);

    let denied = h.promote(agent.clone(), "correct-rent").unwrap_err();
    assert_eq!(denied.code, code::CAPABILITY);
    let owner_approval = Capability::embedded(AGENT, &["approve", "read"]).unwrap();
    let denied = h.promote(owner_approval, "correct-rent").unwrap_err();
    assert_eq!(denied.code, fa_policy::denial::code::SOD);
    assert_eq!(h.db.frontier().unwrap(), source_head);

    let promoted = h.promote(h.approver_capability(), "correct-rent").unwrap();
    assert_eq!(promoted.recorded_at, CommitSeq(source_head.0 + 1));
    assert_eq!(promoted.entries, expected);
    assert_eq!(cash_net(&h.db, h.cash), -1_250);
    for (entry_ref, member) in promoted.entries.iter().zip(preview.members()) {
        let (entry, at) = read_entry(&h.db, entry_ref.vid).unwrap().unwrap();
        assert_eq!(at, promoted.recorded_at);
        assert_eq!(entry, member.entry);
        assert_eq!(entry.proposal.principal_ref, AGENT);
        for (relation, target) in [
            (relation::IN_CASE, promoted.draft),
            (relation::IN_BATCH, promoted.outcome),
        ] {
            assert!(
                h.db.edge(edge_id(relation, entry_ref.vid, target))
                    .unwrap()
                    .is_some()
            );
        }
    }
    assert_eq!(
        read_entry(&h.db, promoted.control_entry)
            .unwrap()
            .unwrap()
            .1,
        promoted.recorded_at
    );
    let (outcome, at) = fa_journal::batch::read_outcome(&h.db, &cx.query(), promoted.outcome)
        .unwrap()
        .unwrap();
    assert_eq!(at, promoted.recorded_at);
    assert_eq!(outcome.entries, expected);
    assert_eq!(h.draft("correct-rent").state, DraftState::Promoted);
    let retry = h.plan_correction(agent, "correct-rent", &pair).unwrap();
    assert!(retry.recorded.already_recorded && retry.plan.is_none());
    assert_eq!(retry.recorded.control_entry, planned.recorded.control_entry);
    let retry = h.promote(h.approver_capability(), "correct-rent").unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, expected);
    assert_eq!(h.db.frontier().unwrap(), promoted.recorded_at);
}

#[test]
fn correction_draft_replacement_redeclares_settlements_after_atomic_application_undo() {
    let mut h = harness();
    let invoice = h
        .post(h.request(h.invoice(10_000, b"draft-invoice"), &["post"]))
        .unwrap()
        .entry_ref();
    let receipt = h
        .post(h.request(
            h.receipt(
                8_000,
                vec![settle(invoice, 0, h.usd, 8_000)],
                b"draft-old-receipt",
            ),
            &["post"],
        ))
        .unwrap()
        .entry_ref();
    let corrected = h.receipt(
        6_000,
        vec![settle(invoice, 0, h.usd, 6_000)],
        b"draft-new-receipt",
    );
    let pair = h.correction_pair(receipt, corrected);
    let agent = h.agent_capability();
    h.open_draft(agent.clone(), "correct-receipt").unwrap();
    let planned = h.plan_correction(agent, "correct-receipt", &pair).unwrap();
    assert_eq!(h.applied_to(invoice.vid, 0), 8_000);
    let expected = expected_refs(receipt, planned.plan.as_ref().unwrap());
    let promoted = h
        .promote(h.approver_capability(), "correct-receipt")
        .unwrap();
    assert_eq!(promoted.entries, expected);
    assert_eq!(h.applied_to(invoice.vid, 0), 6_000);
    let invoice_leg = leg_vid(invoice.vid, 0);
    for (relation, member) in [
        (relation::UNSETTLES, expected[0]),
        (relation::SETTLES, expected[1]),
    ] {
        let source = leg_vid(member.vid, 1);
        assert!(
            h.db.edge(edge_id(relation, source, invoice_leg))
                .unwrap()
                .is_some()
        );
    }
    h.post(h.request(
        h.receipt(
            4_000,
            vec![settle(invoice, 0, h.usd, 4_000)],
            b"draft-final-receipt",
        ),
        &["post"],
    ))
    .unwrap();
    assert_eq!(h.applied_to(invoice.vid, 0), 10_000);
}

#[test]
fn correction_draft_retry_after_discard_binds_both_members_and_current_planner() {
    let mut h = harness();
    let target = rent_target(&mut h);
    let agent = h.agent_capability();
    h.open_draft(agent.clone(), "discard-correction").unwrap();
    let pair = h.correction_pair(target, h.agent_rent(1_250, b"corrected-rent"));
    let planned = h
        .plan_correction(agent.clone(), "discard-correction", &pair)
        .unwrap();
    h.discard(agent.clone(), "discard-correction").unwrap();
    let head = h.db.frontier().unwrap();
    let retry = h
        .plan_correction(agent.clone(), "discard-correction", &pair)
        .unwrap();
    assert!(retry.recorded.already_recorded && retry.plan.is_none());
    assert_eq!(
        retry.recorded,
        DraftRecorded {
            already_recorded: true,
            ..planned.recorded
        }
    );
    let changed = h.correction_pair(target, h.agent_rent(1_500, b"corrected-rent"));
    let refused = h
        .plan_correction(agent.clone(), "discard-correction", &changed)
        .unwrap_err();
    assert_eq!(refused.code, code::IDEMPOTENCY_CONFLICT);
    let changed_key = h.correction_pair(target, h.agent_rent(1_250, b"new-replacement-key"));
    let refused = h
        .plan_correction(agent.clone(), "discard-correction", &changed_key)
        .unwrap_err();
    assert_eq!(refused.code, code::IDEMPOTENCY_CONFLICT);
    assert_eq!(h.db.frontier().unwrap(), head);
    h.revoke(&agent, 97);
    let head = h.db.frontier().unwrap();
    let refused = h
        .plan_correction(agent, "discard-correction", &pair)
        .unwrap_err();
    assert_eq!(refused.code, fa_policy::denial::code::REVOKED);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(cash_net(&h.db, h.cash), -1_000);
}

#[test]
fn correction_draft_requires_dedicated_operation_without_broadening_batch_or_replacement_admission()
{
    let mut h = harness();
    let target = rent_target(&mut h);
    let agent = h.agent_capability();
    let pair = h.correction_pair(target, h.agent_rent(1_250, b"corrected-rent"));
    h.open_draft(agent.clone(), "ordinary").unwrap();
    h.plan_draft(agent.clone(), "ordinary", h.agent_rent(100, b"other-rent"))
        .unwrap();
    let head = h.db.frontier().unwrap();
    assert!(h.plan_correction(agent.clone(), "ordinary", &pair).is_err());
    assert_eq!(h.draft("ordinary").intents.len(), 1);
    assert_eq!(h.db.frontier().unwrap(), head);
    h.open_draft(agent.clone(), "pair-only").unwrap();
    h.plan_correction(agent.clone(), "pair-only", &pair)
        .unwrap();
    let head = h.db.frontier().unwrap();
    assert!(
        h.plan_draft(agent.clone(), "pair-only", h.agent_rent(100, b"other-rent"))
            .is_err()
    );
    let batch = PostBatch::new(
        b"extra-members".to_vec(),
        vec![PostIntent::new(h.agent_rent(100, b"other-rent"), Vec::new()).unwrap()],
    )
    .unwrap();
    let req = h.draft_request(agent.clone());
    let cx = h.ctx();
    assert!(
        h.runtime
            .block_on(plan_batch_into_draft(
                &mut h.db,
                &cx,
                &h.book,
                "pair-only",
                batch,
                req
            ))
            .unwrap()
            .is_err()
    );
    let mut another_reversal = pair.0.proposal().clone();
    another_reversal.idempotency_key = b"second-pair-reversal".to_vec();
    let another = (
        PostIntent::new(another_reversal, Vec::new()).unwrap(),
        pair.1.clone(),
    );
    assert!(
        h.plan_correction(agent.clone(), "pair-only", &another)
            .is_err()
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.draft("pair-only").intents.len(), 2);

    // Even a Human cannot publish the retained Replacement without its pair.
    let mut standalone = pair.1.proposal().clone();
    standalone.principal_ref = PRINCIPAL;
    let refused = h.post(h.request(standalone, &["post"])).unwrap_err();
    assert_eq!(refused.code, code::REPLACEMENT_UNPAIRED);
    let ordinary_batch = PostBatch::new(
        b"not-a-pair-protocol".to_vec(),
        vec![pair.0.clone(), pair.1.clone()],
    )
    .unwrap();
    let req = h.draft_request(agent);
    assert!(
        h.runtime
            .block_on(plan_batch_into_draft(
                &mut h.db,
                &cx,
                &h.book,
                "pair-only",
                ordinary_batch,
                req
            ))
            .unwrap()
            .is_err()
    );
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn correction_draft_promotion_revalidates_current_planner_and_period_without_partial_publication() {
    for revoked in [false, true] {
        let mut h = harness();
        let target = rent_target(&mut h);
        let agent = h.agent_capability();
        h.open_draft(agent.clone(), "current-law").unwrap();
        let pair = h.correction_pair(target, h.agent_rent(1_250, b"corrected-rent"));
        let planned = h
            .plan_correction(agent.clone(), "current-law", &pair)
            .unwrap();
        let expected = expected_refs(target, planned.plan.as_ref().unwrap());
        if revoked {
            h.revoke(&agent, 98);
        } else {
            h.transition(
                &h.march.clone(),
                PeriodTransition::Close,
                b"close-correction-period",
            )
            .unwrap();
        }
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let refused = h
            .promote(h.approver_capability(), "current-law")
            .unwrap_err();
        if revoked {
            assert_eq!(refused.code, fa_policy::denial::code::REVOKED);
        }
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
        assert_eq!(h.draft("current-law").state, DraftState::Open);
        for entry in &expected {
            assert!(read_entry(&h.db, entry.vid).unwrap().is_none());
        }
        assert_eq!(cash_net(&h.db, h.cash), -1_000);
    }
}

#[test]
fn correction_draft_never_adopts_a_pair_posted_elsewhere_after_review() {
    let mut h = harness();
    let target = rent_target(&mut h);
    let planner = Capability::embedded(AGENT, &["read", "post"]).unwrap();
    h.open_draft(planner.clone(), "external-correction")
        .unwrap();
    let pair = h.correction_pair(target, h.agent_rent(1_250, b"corrected-rent"));
    h.plan_correction(planner.clone(), "external-correction", &pair)
        .unwrap();
    let request = |intent: &PostIntent| PostRequest {
        proposal: intent.proposal().clone(),
        approvals: Vec::new(),
        plan_certificate: None,
        capability: planner.clone(),
    };
    h.post_pair(request(&pair.0), request(&pair.1)).unwrap();
    let head = h.db.frontier().unwrap();
    let refused = h
        .promote(h.approver_capability(), "external-correction")
        .unwrap_err();
    assert_eq!(refused.code, code::IDEMPOTENCY_CONFLICT);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.draft("external-correction").state, DraftState::Open);
}
