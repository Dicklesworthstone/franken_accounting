use super::*;

fn approve(h: &mut Harness, digest: [u8; 32]) -> ApprovalRef {
    let cx = h.cx();
    h.runtime
        .block_on(h.book.approve(
            &cx,
            Capability::embedded(VId(8), &["approve"]).unwrap(),
            digest,
        ))
        .unwrap()
        .unwrap()
        .approval()
}

#[test]
fn complete_proposal_approval_refresh_reopen_and_exact_commit_retry() {
    let (mut h, invoice, bill, request) = fixture();
    let reviewed = h.prepare(request);
    let approval = approve(&mut h, reviewed.proposal().proposal_digest().unwrap());
    let at = h.head();
    let cx = h.cx();
    assert!(at > reviewed.known_at());
    let stale = h
        .book
        .plan_prepared_settlement_group(&cx, reviewed.clone(), vec![approval], &cap())
        .unwrap()
        .unwrap_err();
    assert_eq!(stale.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert_eq!(h.head(), at);
    // A held in-memory review can be used with a reopened instance. No portable
    // group-review format is implied; only the resulting PostPlan is portable.
    let mut h = h.reopen();
    let cx = h.cx();
    let fresh = h
        .book
        .refresh_settlement_group(&cx, &reviewed, &cap())
        .unwrap()
        .unwrap();
    assert_eq!(fresh.known_at(), at);
    assert_eq!(fresh.proposal(), reviewed.proposal());
    assert_eq!(fresh.request(), reviewed.request());
    for (a, b) in fresh.allocations().iter().zip(reviewed.allocations()) {
        assert_eq!(a.allocation.allocations, b.allocation.allocations);
        assert_eq!(a.allocation.unapplied, b.allocation.unapplied);
    }
    let plan = h
        .book
        .plan_reviewed_settlement_group(&cx, &reviewed, vec![approval], &cap())
        .unwrap()
        .unwrap();
    assert_eq!(plan.post_plan().intent().proposal(), reviewed.proposal());
    assert_eq!(h.head(), at);
    let bytes = plan.post_plan().canonical_bytes().unwrap();
    let posted = h.commit(plan);
    let committed_at = h.head();
    assert_eq!(h.open(invoice, 0), 0);
    assert_eq!(h.open(bill, 1), 10);
    assert!(
        h.book
            .refresh_settlement_group(&cx, &reviewed, &cap())
            .unwrap()
            .is_err()
    );
    let retry = h
        .runtime
        .block_on(
            h.book
                .commit_plan(&cx, PostPlan::decode(&bytes).unwrap(), &cap()),
        )
        .unwrap()
        .unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(h.head(), committed_at);
}

#[test]
fn equal_proposal_after_a_competing_payment_is_not_equal_reviewed_observations() {
    let (mut h, invoice, bill, mut request) = fixture();
    for leg in &mut request.proposal.legs[..2] {
        leg.amount.mantissa = 50;
    }
    request.proposal.unit_totals = EntryPayload::fold_unit_totals(&request.proposal.legs).unwrap();
    let reviewed = h.prepare(request.clone());
    assert_eq!(
        reviewed.allocations()[0].allocation.allocations[0].open_before,
        100
    );
    h.consume(invoice, 10);
    let fresh = h.prepare(request);
    assert_eq!(
        fresh.proposal(),
        reviewed.proposal(),
        "the same application still fits"
    );
    assert_eq!(
        fresh.allocations()[0].allocation.allocations[0].open_before,
        90
    );
    let at = h.head();
    let cx = h.cx();
    let refusal = h
        .book
        .refresh_settlement_group(&cx, &reviewed, &cap())
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert!(
        h.book
            .plan_reviewed_settlement_group(&cx, &reviewed, Vec::new(), &cap())
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), at);
    assert_eq!(h.open(invoice, 0), 90);
    assert_eq!(h.open(bill, 1), 70);
}

#[test]
fn approving_only_one_intermediate_selection_cannot_authorize_the_combined_entry() {
    let (mut h, invoice, _, request) = fixture();
    let cx = h.cx();
    let partial = h
        .book
        .prepare_settlement(
            &cx,
            SettlementPostRequest {
                proposal: request.proposal.clone(),
                payment_leg: 1,
                targets: vec![(invoice.vid, 0)],
            },
            &cap(),
        )
        .unwrap()
        .unwrap();
    let reviewed = h.prepare(request);
    assert_ne!(
        partial.proposal().proposal_digest().unwrap(),
        reviewed.proposal().proposal_digest().unwrap()
    );
    let wrong = approve(&mut h, partial.proposal().proposal_digest().unwrap());
    let at = h.head();
    assert!(
        h.book
            .plan_reviewed_settlement_group(&cx, &reviewed, vec![wrong], &cap())
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), at);
    let correct = approve(&mut h, reviewed.proposal().proposal_digest().unwrap());
    let plan = h
        .book
        .plan_reviewed_settlement_group(&cx, &reviewed, vec![correct], &cap())
        .unwrap()
        .unwrap();
    assert_eq!(plan.post_plan().intent().proposal(), reviewed.proposal());
}

#[test]
fn refresh_accepts_unrelated_publications_but_never_old_authority() {
    let (mut h, _, _, request) = fixture();
    let reviewed = h.prepare(request);
    let expires = cap().expiring_at(CommitSeq(reviewed.known_at().0 + 1));
    h.invoice("unrelated-to-reviewed-targets", 9);
    let at = h.head();
    let cx = h.cx();
    let fresh = h
        .book
        .refresh_settlement_group(&cx, &reviewed, &cap())
        .unwrap()
        .unwrap();
    assert_eq!(fresh.proposal(), reviewed.proposal());
    assert_eq!(fresh.known_at(), at);
    for capability in [
        expires,
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        Capability::embedded(VId(8), &["read", "post"]).unwrap(),
        cap().for_books(&[Id128([0x77; 16])]).unwrap(),
    ] {
        assert!(
            h.book
                .refresh_settlement_group(&cx, &reviewed, &capability)
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), at);
    }
}
