use super::*;

#[test]
fn approver_only_authority_records_the_proposal_digest_and_retries_idempotently() {
    let mut h = Harness::new();
    let review = h.review("approval-handoff");
    let cx = h.cx();
    let digest = review.digest().unwrap();
    let at = h.head();
    assert!(!approver().holds(fa::Op::Post));
    assert!(!approver().holds(fa::Op::Read));
    let approval = h
        .runtime
        .block_on(
            h.book
                .approve_allocation_review(&cx, &review, digest, &approver()),
        )
        .unwrap()
        .unwrap();
    assert!(approval.recorded_at() > at);
    assert_eq!(
        approval.approval().approved_digest,
        review.proposal_digest().unwrap()
    );
    assert_ne!(approval.approval().approved_digest, digest);
    assert_eq!(
        h.book.fold_period(&cx, "FY2026-P03").unwrap().entries,
        0,
        "approval is not a posting"
    );
    let at = h.head();
    let retry = h
        .runtime
        .block_on(
            h.book
                .approve_allocation_review(&cx, &review, digest, &approver()),
        )
        .unwrap()
        .unwrap();
    assert!(matches!(
        retry,
        fa_journal::Approved::AlreadyRecorded { .. }
    ));
    assert_eq!(retry.approval(), approval.approval());
    assert_eq!(retry.recorded_at(), approval.recorded_at());
    assert_eq!(h.head(), at);
    let plan = h
        .book
        .plan_allocation_review(&cx, &review, digest, vec![approval.approval()], &author())
        .unwrap()
        .unwrap();
    h.runtime
        .block_on(h.book.commit_plan(&cx, plan, &author()))
        .unwrap()
        .unwrap();
    assert_eq!(h.book.fold_period(&cx, "FY2026-P03").unwrap().entries, 1);
}

#[test]
fn self_approval_wrong_digest_expiry_scope_profile_and_ceilings_refuse_without_writes() {
    let mut h = Harness::new();
    let review = h.review("approval-denial");
    let cx = h.cx();
    let at = h.head();
    let digest = review.digest().unwrap();
    let mut wrong = digest;
    wrong[0] ^= 1;
    let refusal = h
        .runtime
        .block_on(
            h.book
                .approve_allocation_review(&cx, &review, wrong, &approver()),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, code::PLAN_INVALIDATED);
    assert!(Capability::new(VId(8), fa::Profile::Agent, &[fa::Op::Approve], VId(1)).is_err());
    for denied in [
        Capability::embedded(AUTHOR, &["approve"]).unwrap(),
        Capability::embedded(VId(8), &["read", "post"]).unwrap(),
        approver().expiring_at(at),
        approver().for_books(&[Id128([9; 16])]).unwrap(),
        approver().with_ceiling(h.usd, 9999).unwrap(),
        Capability::new(
            VId(8),
            fa::Profile::Agent,
            &[fa::Op::Read, fa::Op::Post],
            VId(1),
        )
        .unwrap(),
    ] {
        assert!(
            h.runtime
                .block_on(
                    h.book
                        .approve_allocation_review(&cx, &review, digest, &denied)
                )
                .unwrap()
                .is_err()
        );
        assert_eq!(h.head(), at);
    }
}

#[test]
fn same_result_substitution_and_foreign_book_reviews_never_receive_this_approval() {
    let mut h = Harness::new();
    let original = h.review("review-identity");
    let mut basis = original.posting().clone();
    for target in &mut basis.request.targets {
        target.basis *= 2;
    }
    let template = h.template(&basis, "review-identity");
    let changed = AllocationReview::new(basis.clone(), template).unwrap();
    assert_eq!(
        changed.outcome().unwrap().shares(),
        original.outcome().unwrap().shares()
    );
    let cx = h.cx();
    let at = h.head();
    let refused = h
        .runtime
        .block_on(h.book.approve_allocation_review(
            &cx,
            &changed,
            original.digest().unwrap(),
            &approver(),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::PLAN_INVALIDATED);
    let foreign = Id128([9; 16]);
    let mut template = h.template(&basis, "foreign-review");
    template.book_id = foreign;
    template.evidence = vec![basis.driver_evidence(foreign).unwrap()];
    let foreign = AllocationReview::new(basis, template).unwrap();
    let refused = h
        .runtime
        .block_on(h.book.approve_allocation_review(
            &cx,
            &foreign,
            foreign.digest().unwrap(),
            &approver(),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::COORDINATE);
    assert_eq!(h.head(), at);
}

#[test]
fn closed_period_requires_real_proposal_approval_and_separate_post_closed_authority() {
    let mut h = Harness::new();
    let review = h.review("closed-allocation");
    let cx = h.cx();
    let digest = review.digest().unwrap();
    h.runtime
        .block_on(h.book.transition_period(
            &cx,
            "FY2026-P03",
            PeriodTransition::Close,
            AUTHOR,
            1,
            day("2026-03-31"),
            b"close-march",
            &Capability::embedded(AUTHOR, &["close"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let post_closed = Capability::embedded(AUTHOR, &["post", "post_closed"]).unwrap();
    let at = h.head();
    assert!(
        h.book
            .plan_allocation_review(&cx, &review, digest, Vec::new(), &post_closed)
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), at);
    // Approving the container digest through the generic API does NOT approve
    // its proposal. The posting kernel must reject that otherwise genuine ref.
    let wrong = h
        .runtime
        .block_on(h.book.approve(&cx, approver(), digest))
        .unwrap()
        .unwrap();
    let at = h.head();
    assert!(
        h.book
            .plan_allocation_review(&cx, &review, digest, vec![wrong.approval()], &post_closed)
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), at);
    let right = h
        .runtime
        .block_on(
            h.book
                .approve_allocation_review(&cx, &review, digest, &approver()),
        )
        .unwrap()
        .unwrap();
    let at = h.head();
    assert!(
        h.book
            .plan_allocation_review(&cx, &review, digest, vec![right.approval()], &author())
            .unwrap()
            .is_err(),
        "approval cannot grant post_closed"
    );
    assert_eq!(h.head(), at);
    let plan = h
        .book
        .plan_allocation_review(&cx, &review, digest, vec![right.approval()], &post_closed)
        .unwrap()
        .unwrap();
    assert_eq!(plan.proposal(), review.proposal());
    assert_eq!(plan.certificate().snapshot_seq, at);
    h.runtime
        .block_on(h.book.commit_plan(&cx, plan, &post_closed))
        .unwrap()
        .unwrap();
    assert_eq!(h.book.fold_period(&cx, "FY2026-P03").unwrap().entries, 1);
}

#[test]
fn an_instruction_approval_neither_imports_a_driver_nor_attests_agent_evidence() {
    for grade in [None, Some(4)] {
        let mut h = Harness::new();
        let basis = h.basis(&[("a", 1), ("b", 1)]);
        let cx = h.cx();
        if let Some(grade) = grade {
            let document = Document {
                book_id: BOOK,
                kind: 21,
                mime: "application/octet-stream".into(),
                grade,
                retrieved_by: AUTHOR,
                bytes: basis.basis_bytes().unwrap(),
            };
            h.runtime
                .block_on(h.book.add_document(&cx, &document))
                .unwrap()
                .unwrap();
        }
        let template = h.template(&basis, "unadmitted-instruction");
        let review = AllocationReview::new(basis, template).unwrap();
        let digest = review.digest().unwrap();
        let approved = h
            .runtime
            .block_on(
                h.book
                    .approve_allocation_review(&cx, &review, digest, &approver()),
            )
            .unwrap()
            .unwrap();
        let at = h.head();
        let refusal = h
            .book
            .plan_allocation_review(&cx, &review, digest, vec![approved.approval()], &author())
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refusal.code,
            if grade.is_some() {
                code::SELF_SOURCED
            } else {
                code::EVIDENCE_UNKNOWN
            }
        );
        assert_eq!(h.head(), at);
        assert_eq!(h.book.fold_period(&cx, "FY2026-P03").unwrap().entries, 0);
    }
}

#[test]
fn approval_after_restart_uses_original_ciphertext_and_current_authority() {
    let mut h = Harness::new();
    let review = h.review("restart-approval");
    let bytes = review.canonical_bytes().unwrap();
    let digest = review.digest().unwrap();
    let Harness {
        runtime,
        root,
        book,
        vfs,
        ..
    } = h;
    drop(book);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let mut book = runtime
        .block_on(AsyncBook::open_with_vfs(
            &cx,
            vfs,
            Path::new("allocation-review-book"),
            BookKeys::for_development(180),
            Entropy::deterministic(182),
        ))
        .unwrap();
    let restored = AllocationReview::decode(&bytes).unwrap();
    let approval = runtime
        .block_on(book.approve_allocation_review(&cx, &restored, digest, &approver()))
        .unwrap()
        .unwrap();
    assert_eq!(
        approval.approval().approved_digest,
        review.proposal_digest().unwrap()
    );
    let plan = book
        .plan_allocation_review(&cx, &restored, digest, vec![approval.approval()], &author())
        .unwrap()
        .unwrap();
    assert_eq!(plan.proposal(), review.proposal());
    runtime
        .block_on(book.commit_plan(&cx, plan, &author()))
        .unwrap()
        .unwrap();
    assert!(book.verify_projections(&cx, None).unwrap().is_green());
}

#[test]
fn approval_refs_cannot_be_smuggled_inside_unsigned_review_transport() {
    let mut h = Harness::new();
    let review = h.review("approval-free-container");
    let cx = h.cx();
    let approved = h
        .runtime
        .block_on(h.book.approve_allocation_review(
            &cx,
            &review,
            review.digest().unwrap(),
            &approver(),
        ))
        .unwrap()
        .unwrap();
    let intent = fa::PostIntent::new(review.proposal().clone(), vec![approved.approval()])
        .unwrap()
        .canonical_bytes()
        .unwrap();
    let mut bytes = review.canonical_bytes().unwrap();
    // Fixture has no dimensions. Preserve the complete header/instruction,
    // then replace only the length-prefixed PostIntent with an approved one.
    assert!(review.posting().dimensions.is_empty());
    let intent_offset = 45 + review.posting().request.canonical_bytes().unwrap().len();
    bytes.truncate(intent_offset);
    bytes.extend_from_slice(&u32::try_from(intent.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&intent);
    assert!(AllocationReview::decode(&bytes).is_err());
}

#[test]
fn approval_ceilings_apply_to_residual_legs_not_just_the_source_total() {
    let mut h = Harness::new();
    let mut basis = h.basis(&[("a", 0), ("b", 1), ("c", 1), ("additional-target", 1)]);
    basis.request.total.mantissa = 1;
    basis.request.method = AllocationMethod::ProRataResidualToNamed {
        rounding: fa_money::RoundingLaw::Ceiling,
        recipient: account("a").0,
    };
    let template = h.template(&basis, "residual-ceiling");
    let review = AllocationReview::new(basis, template).unwrap();
    // This is a supplied instruction, not a claim of imported evidence or
    // account admission. Its explicit residual leg still requires authority.
    assert_eq!(review.proposal().legs[0].amount.mantissa, 1);
    assert_eq!(review.proposal().legs[1].amount.mantissa, 2);
    assert_eq!(review.proposal().legs[1].side, Side::Credit);
    let cx = h.cx();
    let at = h.head();
    let cap = approver().with_ceiling(h.usd, 1).unwrap();
    assert!(
        h.runtime
            .block_on(h.book.approve_allocation_review(
                &cx,
                &review,
                review.digest().unwrap(),
                &cap,
            ))
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), at);
}

#[test]
fn synchronous_book_completes_the_same_review_approval_and_native_plan_workflow() {
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let mut book = fa::Book::create_memory(
        BookKeys::for_development(183),
        BookSpec {
            book_id: BOOK,
            name: "Synchronous allocation review".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(183),
    )
    .unwrap();
    let chart = ["source", "a", "b"]
        .into_iter()
        .map(|name| AccountSpec {
            code: name.into(),
            name: name.into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        })
        .collect::<Vec<_>>();
    book.install_chart(&chart, AUTHOR, day("2026-03-01"), b"chart")
        .unwrap()
        .unwrap();
    book.create_periods(2026).unwrap();
    book.transition_period(
        "FY2026-P03",
        PeriodTransition::Open,
        AUTHOR,
        1,
        day("2026-03-01"),
        b"open",
        &Capability::embedded(AUTHOR, &["close"]).unwrap(),
    )
    .unwrap()
    .unwrap();
    let basis = AllocationPosting {
        source: account("source"),
        source_side: Side::Credit,
        dimensions: Vec::new(),
        request: AllocationRequest {
            total: Amount::new(usd, 7),
            method: AllocationMethod::LargestRemainder,
            targets: ["a", "b"]
                .into_iter()
                .map(|name| AllocationTarget {
                    id: account(name).0,
                    basis: 1,
                })
                .collect(),
        },
    };
    book.add_document(&Document {
        book_id: BOOK,
        kind: 21,
        mime: "application/octet-stream".into(),
        grade: 3,
        retrieved_by: AUTHOR,
        bytes: basis.basis_bytes().unwrap(),
    })
    .unwrap()
    .unwrap();
    let template = EntryPayload {
        schema_minor: 1,
        book_id: BOOK,
        branch_id: Id128::TRUNK,
        class: EntryClass::ALLOCATION,
        effective_date: day("2026-03-15"),
        document_date: None,
        description: book.seal_text("sync review").unwrap(),
        effective_period: None,
        unit_totals: Vec::new(),
        legs: Vec::new(),
        control: None,
        base_totals: None,
        idempotency_key: b"sync-allocation".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([1; 32]),
            intent_kind: 1,
        },
        principal_ref: AUTHOR,
        session_ref: None,
        evidence: vec![basis.driver_evidence(BOOK).unwrap()],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let review = AllocationReview::new(basis, template).unwrap();
    let digest = review.digest().unwrap();
    let at = book.head().unwrap();
    assert!(
        book.approve_allocation_review(&review, [0; 32], &approver())
            .unwrap()
            .is_err()
    );
    assert!(
        book.plan_allocation_review(&review, [0; 32], Vec::new(), &author())
            .unwrap()
            .is_err()
    );
    assert_eq!(book.head().unwrap(), at);
    let approval = book
        .approve_allocation_review(&review, digest, &approver())
        .unwrap()
        .unwrap();
    let at = book.head().unwrap();
    let plan = book
        .plan_allocation_review(&review, digest, vec![approval.approval()], &author())
        .unwrap()
        .unwrap();
    assert_eq!(plan.proposal(), review.proposal());
    assert_eq!(book.head().unwrap(), at);
    let bytes = plan.canonical_bytes().unwrap();
    let posted = book.commit_plan(plan, &author()).unwrap().unwrap();
    let at = book.head().unwrap();
    let retry = book
        .commit_plan(PostPlan::decode(&bytes).unwrap(), &author())
        .unwrap()
        .unwrap();
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(book.head().unwrap(), at);
    let fold = book.fold_period("FY2026-P03").unwrap();
    assert_eq!(fold.entries, 1);
    assert_eq!(
        fold.cells
            .iter()
            .find(|cell| cell.key.account == account("a"))
            .unwrap()
            .net(),
        4
    );
    assert_eq!(
        fold.cells
            .iter()
            .find(|cell| cell.key.account == account("b"))
            .unwrap()
            .net(),
        3
    );
}
