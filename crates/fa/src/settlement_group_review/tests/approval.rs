//! Independent-approver acceptance and refusal without partial approvals.

use super::*;

fn approver() -> Capability {
    Capability::embedded(VId(8), &["read", "approve"]).unwrap()
}

#[test]
fn reopened_workflows_refuse_current_authority_before_loading_source_history() {
    let Fixture { mut h, review, .. } = fixture();
    let revoked_post = cap().expiring_at(CommitSeq(u64::MAX));
    let revoked_approver = approver().expiring_at(CommitSeq(u64::MAX));
    let cx = h.cx();
    for (authority, key) in [
        (&revoked_post, b"revoke-source-poster".as_slice()),
        (&revoked_approver, b"revoke-source-approver".as_slice()),
    ] {
        h.runtime
            .block_on(h.book.revoke_capability(
                &cx,
                Capability::embedded(PRINCIPAL, &["issue_capability"]).unwrap(),
                authority.commitment().unwrap(),
                day("2026-03-20"),
                key,
                "Revoke a saved workflow capability",
            ))
            .unwrap()
            .unwrap();
    }
    let mut h = h.reopen();
    let cx = h.cx();
    let head = h.head();
    let assert_cold = |h: &Harness| {
        assert!(matches!(
            h.book.db.delta_since(CommitSeq(0)),
            Err(fgdb::ReadError::DeltaCursorRetired {
                asked: CommitSeq(0),
                ..
            })
        ));
    };
    assert_cold(&h);
    for denied in [
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
        cap().expiring_at(head),
        cap().known_at_most(review.known_at()),
        cap().for_accounts(&["receivable"]).unwrap(),
        cap().for_periods(&["FY2026-P03"]).unwrap(),
        revoked_post,
    ] {
        assert!(
            h.runtime
                .block_on(
                    h.book
                        .plan_settlement_group_review(&cx, &review, Vec::new(), &denied)
                )
                .unwrap()
                .is_err()
        );
        assert_cold(&h);
        assert_eq!(h.head(), head);
    }
    let digest = review.digest().unwrap();
    for denied in [
        Capability::embedded(VId(8), &["read"]).unwrap(),
        Capability::embedded(VId(8), &["approve"]).unwrap(),
        approver().expiring_at(head),
        approver().known_at_most(review.known_at()),
        approver().for_accounts(&["receivable"]).unwrap(),
        approver().for_periods(&["FY2026-P03"]).unwrap(),
        revoked_approver,
    ] {
        assert!(
            h.runtime
                .block_on(
                    h.book
                        .approve_settlement_group_review(&cx, &review, digest, &denied)
                )
                .unwrap()
                .is_err()
        );
        assert_cold(&h);
        assert_eq!(h.head(), head);
    }
    let fresh = h
        .runtime
        .block_on(h.book.refresh_settlement_group_review(&cx, &review, &cap()))
        .unwrap()
        .unwrap();
    assert_eq!(fresh.proposal(), review.proposal());
    assert_eq!(fresh.known_at(), head);
    assert!(h.book.db.delta_since(CommitSeq(0)).is_ok());
    assert_eq!(h.head(), head, "source hydration publishes nothing");

    // An independent approver must also hydrate a cold book using only Read
    // and Approve. The retained sealed proposal is neither refreshed nor resealed.
    let mut h = h.reopen();
    assert_cold(&h);
    let cx = h.cx();
    let approved = h
        .runtime
        .block_on(
            h.book
                .approve_settlement_group_review(&cx, &review, digest, &approver()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        approved.approval().approved_digest,
        review.proposal().proposal_digest().unwrap()
    );
    assert_eq!(h.head(), CommitSeq(head.0 + 1));
    assert!(h.book.db.delta_since(CommitSeq(0)).is_ok());
}

#[test]
fn independent_approver_without_post_authority_records_one_full_proposal_approval() {
    let Fixture {
        mut h,
        invoice,
        bill,
        review,
        ..
    } = fixture();
    let bytes = review.canonical_bytes().unwrap();
    let saved_digest = review.digest().unwrap();
    h.invoice("unrelated", 7);
    let mut h = h.reopen();
    let cx = h.cx();
    let head = h.head();
    let review = SettlementGroupReview::decode(&bytes).unwrap();
    let approved = h
        .runtime
        .block_on(
            h.book
                .approve_settlement_group_review(&cx, &review, saved_digest, &approver()),
        )
        .unwrap()
        .unwrap()
        .approval();
    assert_eq!(
        h.head(),
        CommitSeq(head.0 + 1),
        "one approval for the entire group, not per leg"
    );
    assert_eq!(
        approved.approved_digest,
        review.proposal().proposal_digest().unwrap()
    );
    assert_ne!(approved.approved_digest, saved_digest);
    assert_eq!(
        (h.open(invoice, 0), h.open(bill, 1)),
        (100, 70),
        "approval is not a payment"
    );
    let head = h.head();
    // Removing the only foreign application invalidates the named carrying
    // law before approval binding is reached. Preserve that exact refusal.
    let mut partial = review.proposal().clone();
    partial.legs[2].settles.clear();
    let denied = h
        .book
        .plan(
            &cx,
            PostIntent::new(partial, vec![approved]).unwrap(),
            &cap(),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, fa_journal::refusal::code::SETTLE_SHAPE);
    assert_eq!(h.head(), head);
    // Removing only the native application still satisfies the FX law,
    // but the whole-proposal approval must not authorize that substitution.
    let mut partial = review.proposal().clone();
    partial.legs[1].settles.clear();
    let denied = h
        .book
        .plan(
            &cx,
            PostIntent::new(partial, vec![approved]).unwrap(),
            &cap(),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, fa_policy::denial::code::APPROVAL_BINDING);
    assert_eq!(h.head(), head);
    let plan = h
        .runtime
        .block_on(
            h.book
                .plan_settlement_group_review(&cx, &review, vec![approved], &cap()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(plan.post_plan().intent().proposal(), review.proposal());
    h.runtime
        .block_on(h.book.commit_settlement_group_plan(&cx, plan, &cap()))
        .unwrap()
        .unwrap();
    assert_eq!((h.open(invoice, 0), h.open(bill, 1)), (40, 0));
    assert!(h.book.verify_open_items(&cx).unwrap().is_green());
}

#[test]
fn authority_scope_amount_expiry_and_separation_fail_without_any_approval_publication() {
    let Fixture { mut h, review, .. } = fixture();
    let head = h.head();
    let cx = h.cx();
    let digest = review.digest().unwrap();
    let denied = [
        Capability::embedded(PRINCIPAL, &["read", "approve"]).unwrap(),
        Capability::embedded(VId(8), &["read"]).unwrap(),
        Capability::embedded(VId(8), &["approve"]).unwrap(),
        Capability::embedded(VId(8), &["read", "post"]).unwrap(),
        approver().expiring_at(head),
        approver().for_books(&[Id128([0x55; 16])]).unwrap(),
        // EUR allocation is only 70, but the complete payable/cash legs are 80.
        // Approving allocations rather than full entry legs would miss this.
        approver().with_ceiling(h.eur, 75).unwrap(),
    ];
    for capability in denied {
        assert!(
            h.runtime
                .block_on(
                    h.book
                        .approve_settlement_group_review(&cx, &review, digest, &capability,)
                )
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), head);
    }
}

#[test]
fn a_valid_but_substituted_review_fails_the_independently_retained_digest() {
    let Fixture { mut h, review, .. } = fixture();
    let head = h.head();
    let cx = h.cx();
    let original_digest = review.digest().unwrap();
    // A distinct, structurally valid reviewed description is not the review
    // the recipient approved merely because its own checksum is consistent.
    let mut substituted = review.clone();
    let mut proposal = substituted.proposal().clone();
    proposal.description = h
        .book
        .seal_text(&cx, "different reviewed instructions")
        .unwrap();
    substituted.intent = PostIntent::new(proposal, Vec::new()).unwrap();
    let substituted =
        SettlementGroupReview::decode(&substituted.canonical_bytes().unwrap()).unwrap();
    assert_ne!(substituted.digest().unwrap(), original_digest);
    let refusal = h
        .runtime
        .block_on(h.book.approve_settlement_group_review(
            &cx,
            &substituted,
            original_digest,
            &approver(),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert_eq!(h.head(), head);
}

#[test]
fn changed_first_or_later_allocation_never_publishes_a_partial_group_approval() {
    for change_later_leg in [false, true] {
        let Fixture {
            mut h,
            invoice,
            bill,
            review,
            ..
        } = fixture();
        let cx = h.cx();
        if change_later_leg {
            let proposal = h.proposal(
                "competing-eur",
                vec![
                    leg(Side::Debit, "payable", h.eur, 5),
                    leg(Side::Credit, "cash", h.eur, 5),
                ],
            );
            let proposal = h.value(proposal, FxLawId::SettlementSpotCarrying);
            let request = SettlementPostRequest {
                proposal,
                payment_leg: 0,
                targets: vec![(bill.vid, 1)],
            };
            let plan = h
                .runtime
                .block_on(h.book.plan_settlement(&cx, request, Vec::new(), &cap()))
                .unwrap()
                .unwrap();
            h.runtime
                .block_on(h.book.commit_settlement_plan(&cx, plan, &cap()))
                .unwrap()
                .unwrap();
        } else {
            h.consume(invoice, 10);
        }
        let head = h.head();
        let refusal = h
            .runtime
            .block_on(h.book.approve_settlement_group_review(
                &cx,
                &review,
                review.digest().unwrap(),
                &approver(),
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
        assert_eq!(h.head(), head);
        assert_eq!(h.open(invoice, 0), if change_later_leg { 100 } else { 90 });
        assert_eq!(h.open(bill, 1), if change_later_leg { 65 } else { 70 });
    }
}

#[test]
fn full_handles_false_witnesses_unused_targets_and_foreign_books_are_rechecked() {
    let Fixture {
        mut h,
        bill,
        review,
        ..
    } = fixture();
    let head = h.head();
    let cx = h.cx();
    let mut cases = Vec::new();
    let mut changed = review.clone();
    changed.allocations[0].allocation.allocations[0].open_before += 1;
    changed.allocations[0].allocation.allocations[0].open_after += 1;
    cases.push(changed);
    let mut changed = review.clone();
    let mut proposal = changed.proposal().clone();
    proposal.legs[2].settles[0].target.entry_digest[0] ^= 1;
    changed.intent = PostIntent::new(proposal, Vec::new()).unwrap();
    cases.push(changed);
    let mut changed = review.clone();
    changed.allocations[0]
        .allocation
        .request
        .targets
        .push((bill.vid, 0));
    changed.allocations[0]
        .allocation
        .request
        .targets
        .sort_unstable();
    cases.push(changed);
    let mut changed = review.clone();
    let mut proposal = changed.proposal().clone();
    proposal.legs[2].dimension_set = vec![(1, VId(99))];
    changed.intent = PostIntent::new(proposal, Vec::new()).unwrap();
    cases.push(changed);
    let mut changed = review;
    let mut proposal = changed.proposal().clone();
    proposal.book_id = Id128([0x55; 16]);
    changed.intent = PostIntent::new(proposal, Vec::new()).unwrap();
    cases.push(changed);
    for changed in cases {
        let decoded = SettlementGroupReview::decode(&changed.canonical_bytes().unwrap()).unwrap();
        let refusal = h
            .runtime
            .block_on(h.book.approve_settlement_group_review(
                &cx,
                &decoded,
                decoded.digest().unwrap(),
                &approver(),
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
        assert_eq!(h.head(), head);
    }
}

#[test]
fn approval_never_skips_the_production_kernels_accounting_laws() {
    let Fixture {
        mut h,
        invoice,
        bill,
        mut review,
        ..
    } = fixture();
    let cx = h.cx();
    let mut proposal = review.proposal().clone();
    proposal.legs[0].amount.mantissa = 59;
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    review.intent = PostIntent::new(proposal, Vec::new()).unwrap();
    let approval = h
        .runtime
        .block_on(h.book.approve_settlement_group_review(
            &cx,
            &review,
            review.digest().unwrap(),
            &approver(),
        ))
        .unwrap()
        .unwrap()
        .approval();
    let head = h.head();
    let refusal = h
        .runtime
        .block_on(
            h.book
                .plan_settlement_group_review(&cx, &review, vec![approval], &cap()),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::UNBALANCED);
    assert_eq!(h.head(), head);
    assert_eq!((h.open(invoice, 0), h.open(bill, 1)), (100, 70));
}
