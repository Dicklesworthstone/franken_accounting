//! Explicitly selected Canon derivations retain their typed request and
//! planner authority through ordered rehearsal and independent promotion.

use super::*;

fn draft_request(
    proposal: &fa_model::EntryPayload,
    capability: fa_policy::Capability,
) -> fa_journal::DraftRequest {
    fa_journal::DraftRequest {
        capability,
        effective_date: proposal.effective_date,
        description: proposal.description.clone(),
    }
}

#[test]
fn agent_mixed_rule_drafts_preserve_reviewed_effects_and_promote_atomically() {
    for atomic_append in [false, true] {
        let mut h = harness();
        let rule = automatic_rule(&mut h, "explicit_draft_sale", "6000");
        let source = event(&mut h, "EXPLICIT-DRAFT", 4_000);
        let mut derived = proposal(&h, &rule, &source, b"draft-rule");
        derived.principal_ref = AGENT;
        let rule_intent =
            fa_intents::PostIntent::rule_derived(derived.clone(), Vec::new()).unwrap();
        let mut ordinary = derived.clone();
        ordinary.origin = fa_model::EntryOrigin::Intent {
            intent_oid: fa_model::Oid([81; 32]),
            intent_kind: 1,
        };
        ordinary.idempotency_key = b"draft-ordinary".to_vec();
        ordinary.extensions.clear();
        let ordinary_intent = fa_intents::PostIntent::new(ordinary.clone(), Vec::new()).unwrap();
        let expected = [ordinary_intent.clone(), rule_intent.clone()];
        let capability = fa_policy::Capability::new(
            AGENT,
            fa_policy::Profile::Agent,
            &[fa_policy::Op::Read, fa_policy::Op::Post],
            PREPARER,
        )
        .unwrap();
        let name = "explicit-rules";
        let ctx = h.ctx();
        h.runtime
            .block_on(fa_journal::open_draft(
                &mut h.db,
                &ctx,
                &h.book,
                name,
                draft_request(&derived, capability.clone()),
            ))
            .unwrap()
            .unwrap();

        let planned = if atomic_append {
            let batch =
                fa_intents::PostBatch::for_draft(b"mixed-draft-append".to_vec(), expected.to_vec())
                    .unwrap();
            h.runtime
                .block_on(fa_journal::plan_batch_into_draft(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    name,
                    batch,
                    draft_request(&derived, capability.clone()),
                ))
                .unwrap()
                .unwrap()
        } else {
            h.runtime
                .block_on(fa_journal::plan_into_draft(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    name,
                    ordinary_intent,
                    draft_request(&derived, capability.clone()),
                ))
                .unwrap()
                .unwrap();
            h.runtime
                .block_on(fa_journal::plan_into_draft(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    name,
                    rule_intent,
                    draft_request(&derived, capability.clone()),
                ))
                .unwrap()
                .unwrap()
        };
        let preview = planned.plan.unwrap();
        assert_eq!(preview.members().len(), expected.len());
        let view = fa_journal::read_draft(&h.db, &ctx.query(), &h.book, name)
            .unwrap()
            .unwrap();
        assert_eq!(view.body.owner, AGENT);
        assert_eq!(view.intents.len(), expected.len());
        for ((retained, requested), reviewed) in
            view.intents.iter().zip(&expected).zip(preview.members())
        {
            assert_eq!(
                retained.intent.canonical_bytes().unwrap(),
                requested.canonical_bytes().unwrap()
            );
            assert_eq!(retained.capability, capability);
            assert_eq!(
                retained.resolved_entry_digest,
                Some(reviewed.entry.entry_digest)
            );
            let p = requested.proposal();
            let vid = fa_model::entry_vid(
                h.book.book_id,
                &p.principal_ref.0.to_le_bytes(),
                &p.idempotency_key,
            );
            assert!(
                h.db.vertex(vid).unwrap().is_none(),
                "draft preparation never posts its accounting effects"
            );
        }

        // Another Agent may not append to the owner's retained draft.
        let other = fgdb_types::VId(78);
        let other_capability = fa_policy::Capability::new(
            other,
            fa_policy::Profile::Agent,
            &[fa_policy::Op::Read, fa_policy::Op::Post],
            PREPARER,
        )
        .unwrap();
        let mut other_proposal = derived.clone();
        other_proposal.principal_ref = other;
        other_proposal.idempotency_key = b"foreign-draft-member".to_vec();
        let head = h.db.frontier().unwrap();
        let refused = h
            .runtime
            .block_on(fa_journal::plan_into_draft(
                &mut h.db,
                &ctx,
                &h.book,
                name,
                fa_intents::PostIntent::rule_derived(other_proposal, Vec::new()).unwrap(),
                draft_request(&derived, other_capability),
            ))
            .unwrap();
        assert!(refused.is_err());
        assert_eq!(h.db.frontier().unwrap(), head);

        let promoter = fa_policy::Capability::embedded(PREPARER, &["approve", "read"]).unwrap();
        let promoted = h
            .runtime
            .block_on(fa_journal::promote_draft(
                &mut h.db,
                &ctx,
                &h.book,
                name,
                draft_request(&derived, promoter.clone()),
            ))
            .unwrap()
            .unwrap();
        assert_eq!(promoted.entries.len(), expected.len());
        for (entry_ref, reviewed) in promoted.entries.iter().zip(preview.members()) {
            let (entry, recorded_at) = fa_journal::post::read_entry(&h.db, entry_ref.vid)
                .unwrap()
                .unwrap();
            assert_eq!(recorded_at, promoted.recorded_at);
            assert_eq!(entry, reviewed.entry);
            assert_eq!(entry_ref.entry_digest, reviewed.entry.entry_digest);
        }
        let head = h.db.frontier().unwrap();
        let retry = h
            .runtime
            .block_on(fa_journal::promote_draft(
                &mut h.db,
                &ctx,
                &h.book,
                name,
                draft_request(&derived, promoter),
            ))
            .unwrap()
            .unwrap();
        assert!(retry.already_recorded);
        assert_eq!(retry.entries, promoted.entries);
        assert_eq!(retry.recorded_at, promoted.recorded_at);
        assert_eq!(h.db.frontier().unwrap(), head);
    }
}

#[test]
fn draft_rule_preparation_reproduces_effects_and_rejects_balanced_forgery() {
    let mut h = harness();
    let rule = automatic_rule(&mut h, "forged_draft_sale", "6000");
    let source = event(&mut h, "FORGED-DRAFT", 4_000);
    let mut derived = proposal(&h, &rule, &source, b"forged-draft-rule");
    derived.principal_ref = AGENT;
    let capability = fa_policy::Capability::new(
        AGENT,
        fa_policy::Profile::Agent,
        &[fa_policy::Op::Read, fa_policy::Op::Post],
        PREPARER,
    )
    .unwrap();
    let request = draft_request(&derived, capability);
    let ctx = h.ctx();
    h.runtime
        .block_on(fa_journal::open_draft(
            &mut h.db,
            &ctx,
            &h.book,
            "forged-rule",
            request.clone(),
        ))
        .unwrap()
        .unwrap();
    for leg in &mut derived.legs {
        leg.amount.mantissa -= 1;
    }
    derived.unit_totals = fa_model::EntryPayload::fold_unit_totals(&derived.legs).unwrap();
    let intent = fa_intents::PostIntent::rule_derived(derived, Vec::new()).unwrap();
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refusal = h
        .runtime
        .block_on(fa_journal::plan_into_draft(
            &mut h.db,
            &ctx,
            &h.book,
            "forged-rule",
            intent,
            request,
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-196", "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert!(
        fa_journal::read_draft(&h.db, &ctx.query(), &h.book, "forged-rule")
            .unwrap()
            .unwrap()
            .intents
            .is_empty()
    );
}
