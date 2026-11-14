//! Rule activation reserves its canonical key and authenticates the original
//! successful publication before returning a retry, independently of later rules.

use super::*;
use fa_journal::rule::{RuleActivated, RuleActivationPlan};

fn planned(h: &mut Harness, ceiling: &str, key: &[u8], month: u8) -> RuleActivationPlan {
    let rule = propose(h, ceiling, format!("propose-{ceiling}").as_bytes());
    plan_rule_activation(
        &h.db,
        &h.book,
        &controller(),
        &rule.ir_digest(),
        DateDay::from_ymd(2026, month, 1).unwrap(),
        key,
        h.period_description(),
    )
    .unwrap()
    .unwrap()
}

fn approvals(h: &mut Harness, plan: &RuleActivationPlan) -> Vec<ApprovalRef> {
    let digest = plan.proposal_digest(&h.book).unwrap();
    vec![
        h.approve(ALICE, digest).unwrap().approval(),
        h.approve(BOB, digest).unwrap().approval(),
    ]
}

fn activate(
    h: &mut Harness,
    plan: RuleActivationPlan,
    approvals: Vec<ApprovalRef>,
) -> Result<RuleActivated, Refusal> {
    let ctx = h.ctx();
    h.runtime
        .block_on(activate_rule_version(
            &mut h.db,
            &ctx,
            &h.book,
            &controller(),
            plan,
            approvals,
        ))
        .expect("activation kernel")
}

fn outcome(h: &Harness, plan: &RuleActivationPlan) -> VId {
    fa_model::intent_outcome_vid(
        h.book.book_id,
        &PREPARER.0.to_le_bytes(),
        &plan.proposal(&h.book).idempotency_key,
    )
}

fn write_raw(h: &mut Harness, batch: WriteBatch) -> CommitSeq {
    let ctx = h.ctx();
    let mut txn = h.db.begin(&ctx.txn()).unwrap();
    txn.write(&h.db, batch).unwrap();
    h.runtime.block_on(txn.commit(&mut h.db, &ctx.commit())).unwrap()
}

#[test]
fn rule_activation_and_post_batch_share_the_canonical_intent_key() {
    for activation_first in [false, true] {
        let mut h = harness();
        let plan = planned(&mut h, "40.00", b"shared-activation-key", 3);
        let approvals = approvals(&mut h, &plan);
        // RuleActivationPlan has always domain-separated its caller's key.
        // The stored canonical key is the shared successful-intent identity.
        let batch = PostBatch::new(
            plan.proposal(&h.book).idempotency_key,
            vec![
                PostIntent::new(
                    h.proposal(PREPARER, 500, b"batch-member", EntryClass::ORIGINAL),
                    Vec::new(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let ctx = h.ctx();
        if activation_first {
            activate(&mut h, plan.clone(), approvals).unwrap();
        } else {
            h.runtime
                .block_on(post_batch(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    controller(),
                    batch.clone(),
                ))
                .unwrap()
                .unwrap();
        }
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let refusal = if activation_first {
            h.runtime
                .block_on(post_batch(&mut h.db, &ctx, &h.book, controller(), batch))
                .unwrap()
                .unwrap_err()
        } else {
            // The collision must be found before approval or rule observation.
            activate(&mut h, plan, Vec::new()).unwrap_err()
        };
        assert_eq!(refusal.code, code::IDEMPOTENCY_CONFLICT, "{refusal:?}");
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn rule_activation_claim_is_atomic_and_retry_survives_a_later_activation() {
    let mut h = harness();
    let plan = planned(&mut h, "40.00", b"first-activation", 3);
    let cited = approvals(&mut h, &plan);
    let first = activate(&mut h, plan.clone(), cited).unwrap();
    let claim = h.db.vertex(outcome(&h, &plan)).unwrap().unwrap();
    assert_eq!(claim.labels, vec![label::INTENT_OUTCOME]);
    assert_eq!(claim.created_at, first.recorded_at);
    assert_eq!(
        h.db.vertex(first.control_entry).unwrap().unwrap().created_at,
        claim.created_at
    );
    assert_eq!(first.approvals, 2);
    assert!(!first.already_recorded);

    let later = planned(&mut h, "50.00", b"later-activation", 4);
    let cited = approvals(&mut h, &later);
    activate(&mut h, later, cited).unwrap();
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let retry = activate(&mut h, plan, Vec::new()).unwrap();
    assert_eq!(retry.control_entry, first.control_entry);
    assert_eq!(retry.recorded_at, first.recorded_at);
    assert_eq!(retry.binding, first.binding);
    assert_eq!(retry.approvals, first.approvals);
    assert!(retry.already_recorded);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn rule_activation_retry_authenticates_the_name_in_its_immutable_version() {
    let mut h = harness();
    let plan = planned(&mut h, "40.00", b"name-bound-activation", 3);
    let cited = approvals(&mut h, &plan);
    let first = activate(&mut h, plan.clone(), cited).unwrap();
    let later = planned(&mut h, "50.00", b"name-bound-later-activation", 4);
    let cited = approvals(&mut h, &later);
    activate(&mut h, later, cited).unwrap();
    let mut renamed = plan.clone();
    renamed.rule_name = "a_rule_that_was_never_activated".into();
    assert_eq!(
        renamed.proposal_digest(&h.book).unwrap(),
        plan.proposal_digest(&h.book).unwrap(),
        "the IR digest binds the canonical name; the plan's name is redundant"
    );
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let refusal = activate(&mut h, renamed, Vec::new()).unwrap_err();
    assert_eq!(refusal.code, code::IDEMPOTENCY_CONFLICT, "{refusal:?}");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
    let retry = activate(&mut h, plan, Vec::new()).unwrap();
    assert_eq!(
        retry,
        RuleActivated {
            already_recorded: true,
            ..first
        }
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn rule_activation_refusal_leaves_the_key_available_for_an_approved_retry() {
    let mut h = harness();
    let plan = planned(&mut h, "40.00", b"approval-retry", 3);
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let refusal = activate(&mut h, plan.clone(), Vec::new()).unwrap_err();
    assert_ne!(refusal.code, code::IDEMPOTENCY_CONFLICT);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
    assert!(h.db.vertex(outcome(&h, &plan)).unwrap().is_none());
    let cited = approvals(&mut h, &plan);
    activate(&mut h, plan, cited).unwrap();
}

#[test]
fn rule_activation_retry_rejects_a_deleted_or_republished_claim() {
    for missing in [false, true] {
        let mut h = harness();
        let plan = planned(&mut h, "40.00", b"damaged-activation", 3);
        let cited = approvals(&mut h, &plan);
        activate(&mut h, plan.clone(), cited).unwrap();
        let claim = h.db.vertex(outcome(&h, &plan)).unwrap().unwrap();
        let mut damage = WriteBatch::new(relation::IN_BOOK);
        if missing {
            damage.delete_vertex(claim.vid);
        } else {
            damage.set_vertex_property(
                claim.vid,
                property::FA_PAYLOAD,
                Some(CanonicalScalar::bytes(b"altered claim".to_vec()).unwrap()),
            );
        }
        write_raw(&mut h, damage);
        if !missing {
            let mut restore = WriteBatch::new(relation::IN_BOOK);
            restore.set_vertex_property(
                claim.vid,
                property::FA_PAYLOAD,
                Some(fa_journal::rows::prop(&claim, property::FA_PAYLOAD).unwrap().clone()),
            );
            write_raw(&mut h, restore);
        }
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        let refusal = activate(&mut h, plan, Vec::new()).unwrap_err();
        assert_eq!(refusal.code, code::IDEMPOTENCY_CONFLICT, "{refusal:?}");
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn legacy_rule_activation_retries_remain_read_only() {
    let mut h = harness();
    let plan = planned(&mut h, "40.00", b"legacy-activation", 3);
    let cited = approvals(&mut h, &plan);
    let proposal = plan.proposal(&h.book);
    let evid = fa_model::entry_vid(
        h.book.book_id,
        &PREPARER.0.to_le_bytes(),
        &proposal.idempotency_key,
    );
    let entry = proposal.seal(cited, None).unwrap();
    let mut legacy = WriteBatch::new(relation::IN_BOOK);
    legacy.create_vertex(evid, vec![label::ENTRY], fa_model::entry_mirrors(&entry).unwrap());
    let at = write_raw(&mut h, legacy);
    assert!(h.db.vertex(outcome(&h, &plan)).unwrap().is_none());
    let rows = h.db.vertices().unwrap();
    let retry = activate(&mut h, plan, Vec::new()).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.control_entry, evid);
    assert_eq!(retry.recorded_at, at);
    assert_eq!(retry.approvals, 2);
    assert_eq!(h.db.frontier().unwrap(), at);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn rule_activation_outcome_rejects_unrelated_lifecycle_controls() {
    let mut h = harness();
    let plan = planned(&mut h, "40.00", b"precise-activation-shape", 3);
    let proposal = plan.proposal(&h.book);
    let entry = proposal.clone().seal(Vec::new(), None).unwrap();
    assert!(fa_journal::outcome::is_rule_activation(&entry));
    for mutation in 0..4 {
        let mut forged = entry.clone();
        let Some(ControlPayload::LifecycleTransition {
            object_ref, from, proof_refs, reason_code, ..
        }) = &mut forged.proposal.control else {
            unreachable!("rule activation lifecycle");
        };
        match mutation {
            0 => *object_ref = VId(99),
            1 => *from = 2,
            2 => proof_refs.push(fa_model::TypedRef::Object(Oid([5; 32]))),
            3 => *reason_code = fa_journal::outcome::STATEMENT_ACTIVATION_REASON,
            _ => unreachable!(),
        }
        assert!(!fa_journal::outcome::is_rule_activation(&forged));
        let evid = fa_model::entry_vid(
            h.book.book_id,
            &PREPARER.0.to_le_bytes(),
            &forged.proposal.idempotency_key,
        );
        assert!(fa_journal::outcome::stage_control(
            &mut WriteBatch::new(relation::IN_BOOK), &forged, evid,
        ).is_err());
    }
}
