use super::*;

fn approver() -> Capability { Capability::embedded(VId(8), &["read", "approve"]).unwrap() }

#[test]
fn distinct_read_and_approve_authority_can_complete_the_review_workflow_without_post() {
    let (mut h, review) = fixture();
    let cx = h.cx();
    let digest = review.digest().unwrap();
    let at = h.head();
    let approval = h.runtime.block_on(h.book.approve_settlement_review(&cx, &review, digest, &approver()))
        .unwrap().unwrap();
    assert!(approval.recorded_at() > at);
    assert_eq!(approval.approval().approved_digest, review.proposal().proposal_digest().unwrap());
    assert_ne!(approval.approval().approved_digest, digest);
    let approved_at = h.head();
    let retry = h.runtime.block_on(h.book.approve_settlement_review(&cx, &review, digest, &approver()))
        .unwrap().unwrap();
    assert!(matches!(retry, fa_journal::Approved::AlreadyRecorded { .. }));
    assert_eq!(retry.approval(), approval.approval());
    assert_eq!(retry.recorded_at(), approval.recorded_at());
    assert_eq!(h.head(), approved_at);
    let plan = h.book.plan_settlement_review(&cx, &review, vec![approval.approval()], &cap())
        .unwrap().unwrap();
    assert_eq!(plan.post_plan().proposal(), review.proposal());
    assert_eq!(h.head(), approved_at);
    h.runtime.block_on(h.book.commit_settlement_plan(&cx, plan, &cap())).unwrap().unwrap();
    assert!(h.book.verify_open_items(&cx).unwrap().is_green());
}

#[test]
fn approving_a_saved_review_requires_its_independently_retained_digest_and_current_authority() {
    let (mut h, review) = fixture();
    let cx = h.cx();
    let at = h.head();
    let digest = review.digest().unwrap();
    let mut wrong = digest;
    wrong[0] ^= 1;
    let refusal = h.runtime.block_on(h.book.approve_settlement_review(&cx, &review, wrong, &approver()))
        .unwrap().unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    let denied = [
        Capability::embedded(PRINCIPAL, &["read", "approve"]).unwrap(),
        Capability::embedded(VId(8), &["approve"]).unwrap(),
        Capability::embedded(VId(8), &["read", "post"]).unwrap(),
        approver().expiring_at(at),
        approver().for_books(&[Id128([0x99; 16])]).unwrap(),
        approver().with_ceiling(h.usd, 129).unwrap(),
    ];
    for authority in &denied {
        assert!(h.runtime.block_on(h.book.approve_settlement_review(&cx, &review, digest, authority))
            .unwrap().is_err());
        assert_eq!(h.head(), at, "no approval may be recorded on refusal");
    }
}

#[test]
fn stale_capacity_cannot_be_approved_even_when_the_reviewed_payment_still_fits() {
    let mut h = Harness::new();
    let invoice = h.invoice("invoice", "2026-03-10", 1000);
    let review = h.prepare("reviewed", 60, &[invoice]).export_review().unwrap();
    let other = h.prepare("other", 10, &[invoice]);
    let cx = h.cx();
    let plan = h.book.plan_prepared_settlement(&cx, other, Vec::new(), &cap()).unwrap().unwrap();
    h.runtime.block_on(h.book.commit_settlement_plan(&cx, plan, &cap())).unwrap().unwrap();
    let at = h.head();
    let refusal = h.runtime.block_on(h.book.approve_settlement_review(
        &cx, &review, review.digest().unwrap(), &approver(),
    )).unwrap().unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert_eq!(h.head(), at);
    assert_eq!(h.open(invoice), 990);
}

#[test]
fn internally_valid_but_false_target_handles_and_dimensions_do_not_receive_approvals() {
    let (mut h, review) = fixture();
    let mut cases = Vec::new();
    let mut changed = review.clone();
    let mut proposal = review.proposal().clone();
    proposal.legs[1].settles[0].target.entry_digest[0] ^= 1;
    changed.intent = PostIntent::new(proposal, Vec::new()).unwrap();
    cases.push(changed);
    let mut changed = review.clone();
    let mut proposal = review.proposal().clone();
    proposal.legs[1].dimension_set = vec![(1, VId(99))];
    changed.intent = PostIntent::new(proposal, Vec::new()).unwrap();
    cases.push(changed);
    let cx = h.cx();
    let at = h.head();
    for changed in cases {
        let decoded = SettlementReview::decode(&changed.canonical_bytes().unwrap()).unwrap();
        // Even a caller who intentionally names the changed artifact must not
        // get an approval for false current target observations.
        assert!(h.runtime.block_on(h.book.approve_settlement_review(
            &cx, &decoded, decoded.digest().unwrap(), &approver(),
        )).unwrap().is_err());
        assert_eq!(h.head(), at);
    }
}
