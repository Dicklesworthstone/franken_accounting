//! A combined review checks the hypothetical Closing before any real task,
//! survives metadata-only prefix translation, and binds the entire fiscal year.

use super::*;
use fa::CloseTaskRehearsalOutcome;

const CLOSING_PERIOD: &str = "FY2026-CLOSE";

fn closing_draft(f: &mut Fixture) -> ReviewedCloseAction {
    f.review("source-expense", PLANNER, 1_000);
    f.book
        .promote_draft(closer(), "source-expense", day(), "Posted source expense")
        .unwrap()
        .unwrap();
    let schema = cap(ADMIN, &["read", "schema_change"]);
    f.book
        .open_account(
            &AccountSpec {
                code: "3000".into(),
                name: "Retained earnings".into(),
                account_type: AccountType::EQUITY.0,
                normal_balance: 1,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(f.usd),
                parent_code: None,
                limit: None,
            },
            day(),
            None,
            ADMIN,
            day(),
            b"checkpoint-equity",
            &schema,
        )
        .unwrap()
        .unwrap();
    let book_id = f.book.context().book_id;
    let description = f.book.seal_text("Reviewed year-end route").unwrap();
    f.book
        .set_closing_routes(
            fa::ClosingRoutesRequest {
                principal: ADMIN,
                effective_from: day(),
                routes: [(account_vid(book_id, "6000"), account_vid(book_id, "3000"))].into(),
                idempotency_key: b"checkpoint-route".to_vec(),
                description,
            },
            &schema,
        )
        .unwrap()
        .unwrap();
    f.book
        .transition_period(
            CLOSING_PERIOD,
            PeriodTransition::Open,
            ADMIN,
            1,
            b"checkpoint-open-closing",
            &cap(ADMIN, &["close"]),
        )
        .unwrap()
        .unwrap();
    let workpaper = Document {
        book_id,
        kind: 21,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: ADMIN,
        bytes: b"Reviewed exact year-end closing computation".to_vec(),
    };
    f.book.add_document(&workpaper).unwrap().unwrap();
    let prepared = f
        .book
        .prepare_year_end_close_for_draft(
            &fa::YearEndCloseRequest {
                fiscal_year: 2026,
                closing_period: CLOSING_PERIOD.into(),
            },
            &planner(PLANNER),
        )
        .unwrap()
        .unwrap();
    let template = EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::CLOSING,
        effective_date: prepared.closing_date(),
        document_date: None,
        description: f
            .book
            .seal_text("Reviewed intrinsic year-end close")
            .unwrap(),
        effective_period: Some(fa_model::PeriodRef {
            calendar: f.book.context().calendar.id.clone(),
            code: CLOSING_PERIOD.into(),
        }),
        legs: Vec::new(),
        control: None,
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: b"checkpoint-year-end-close".to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: workpaper.oid(),
            intent_kind: 1,
        },
        principal_ref: PLANNER,
        session_ref: None,
        evidence: vec![workpaper.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    f.book
        .open_draft(
            planner(PLANNER),
            "year-end-draft",
            day(),
            "Reviewed fiscal-year close",
        )
        .unwrap()
        .unwrap();
    f.book
        .plan_into_draft(
            planner(PLANNER),
            "year-end-draft",
            PostIntent::new(prepared.proposal(template).unwrap(), Vec::new()).unwrap(),
        )
        .unwrap()
        .unwrap();
    let producer = cap(CLOSER, &["read", "produce"]);
    let review = f
        .book
        .certify_draft_diff(CLOSER, &producer, "year-end-draft", CLOSING_PERIOD)
        .unwrap()
        .unwrap();
    f.book
        .retain_draft_diff(CLOSER, &producer, &review.certificate)
        .unwrap()
        .unwrap();
    ReviewedCloseAction::DraftCertificate(*review.certificate.digest())
}

fn year_end_tasks(draft: ReviewedCloseAction) -> Vec<ReviewedCloseTask> {
    vec![
        task("post-closing", &[], draft),
        task(
            "verify",
            &["post-closing"],
            ReviewedCloseAction::VerifyYearEndClose { fiscal_year: 2026 },
        ),
        task(
            "finish",
            &["verify"],
            ReviewedCloseAction::PeriodTransition(PeriodTransition::Close),
        ),
    ]
}

#[test]
fn closing_checkpoint_combined_review_survives_retention_and_replays_the_original_scratch() {
    let mut f = Fixture::new(216);
    let draft = closing_draft(&mut f);
    f.book
        .start_close_run(
            closer(),
            "year-end",
            CLOSING_PERIOD,
            year_end_tasks(draft),
            "Post, verify, then close the year",
        )
        .unwrap()
        .unwrap();
    let producer = cap(CLOSER, &["read", "produce"]);
    let before = f.book.head().unwrap();
    assert!(
        f.book
            .execute_close_task(
                "year-end",
                "verify",
                closer(),
                "Too early",
                None,
                Vec::new()
            )
            .unwrap()
            .is_err()
    );
    assert_eq!(f.book.head().unwrap(), before);
    let original = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "year-end")
        .unwrap()
        .unwrap();
    assert_eq!(f.book.head().unwrap(), before, "rehearsal is read-only");
    let verification = &original.report.tasks[1].outcome;
    let CloseTaskRehearsalOutcome::VerifiedYearEndClose {
        source_digest: original_exact,
        review_basis: original_stable,
        verified_at: original_at,
        ..
    } = verification
    else {
        panic!("year-end verification follows the hypothetical Closing");
    };
    f.book
        .retain_close_run_rehearsal(CLOSER, &producer, &original.certificate)
        .unwrap()
        .unwrap();
    let after_retention = f
        .book
        .close_run_rehearsal(CLOSER, &producer, "year-end")
        .unwrap()
        .unwrap();
    let CloseTaskRehearsalOutcome::VerifiedYearEndClose {
        source_digest: current_exact,
        review_basis: current_stable,
        verified_at: current_at,
        ..
    } = &after_retention.tasks[1].outcome
    else {
        panic!("current year-end verification");
    };
    assert!(current_at > original_at);
    assert_ne!(
        current_exact, original_exact,
        "hypothetical publication sequences translated"
    );
    assert_eq!(
        current_stable, original_stable,
        "all authenticated accounting content is unchanged"
    );
    let execution = f
        .book
        .execute_reviewed_close_run(
            "year-end",
            closer(),
            "Execute reviewed fiscal-year close",
            &original.certificate,
            Some(CloseRunTransition::Review {
                task: "finish".into(),
                reason_code: 1,
                idempotency_key: b"checkpoint-period-close".to_vec(),
            }),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        execution
            .completed
            .iter()
            .map(|task| task.task.as_str())
            .collect::<Vec<_>>(),
        ["post-closing", "verify"]
    );
    let Some(CloseRunStop::TransitionReview { plan, .. }) = execution.stop else {
        panic!("the terminal transition still needs its reviewed native plan");
    };
    let current = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "year-end")
        .unwrap()
        .unwrap();
    f.book
        .retain_close_run_rehearsal(CLOSER, &producer, &current.certificate)
        .unwrap()
        .unwrap();
    let finished = f
        .book
        .execute_reviewed_close_run(
            "year-end",
            closer(),
            "Finish reviewed close",
            &current.certificate,
            Some(CloseRunTransition::Reviewed {
                task: "finish".into(),
                plan,
                approvals: Vec::new(),
            }),
        )
        .unwrap()
        .unwrap();
    assert!(finished.run.complete);
    assert_eq!(finished.completed.len(), 1);
    assert_eq!(
        f.book
            .replay_close_run_rehearsal(CLOSER, &producer, &original.certificate)
            .unwrap()
            .unwrap(),
        original.report
    );
}

#[test]
fn closing_checkpoint_preflight_refuses_unclosed_draft_before_any_live_promotion() {
    let mut f = Fixture::new(217);
    closing_draft(&mut f);
    f.book
        .promote_draft(closer(), "year-end-draft", day(), "Original valid closing")
        .unwrap()
        .unwrap();
    let late = f.review("late-expense", PLANNER, 250);
    f.start(
        "late",
        vec![
            task("post", &[], late),
            task(
                "verify",
                &["post"],
                ReviewedCloseAction::VerifyYearEndClose { fiscal_year: 2026 },
            ),
        ],
    );
    let before = f.book.head().unwrap();
    let refusal = f
        .book
        .close_run_rehearsal(CLOSER, &closer(), "late")
        .unwrap()
        .unwrap_err();
    assert!(refusal.message.contains("verify"));
    let refused = f
        .book
        .execute_close_run("late", closer(), "Check all work first", None)
        .unwrap()
        .unwrap();
    assert!(
        matches!(refused.stop, Some(CloseRunStop::Refused { ref task, .. }) if task == "verify")
    );
    assert!(refused.completed.is_empty());
    assert_eq!(f.book.head().unwrap(), before);
    assert!(
        refused
            .run
            .tasks
            .iter()
            .all(|task| task.completion.is_none())
    );
    assert_eq!(
        f.book.draft("late-expense").unwrap().unwrap().state,
        fa_journal::DraftState::Open
    );
}

#[test]
fn closing_checkpoint_review_binds_offsetting_activity_outside_the_selected_run_period() {
    let mut f = Fixture::new(218);
    closing_draft(&mut f);
    f.book
        .promote_draft(closer(), "year-end-draft", day(), "Original valid closing")
        .unwrap()
        .unwrap();
    f.book
        .start_close_run(
            closer(),
            "fresh-check",
            CLOSING_PERIOD,
            vec![task(
                "verify",
                &[],
                ReviewedCloseAction::VerifyYearEndClose { fiscal_year: 2026 },
            )],
            "Verify all fiscal-year sources",
        )
        .unwrap()
        .unwrap();
    let producer = cap(CLOSER, &["read", "produce"]);
    let original = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "fresh-check")
        .unwrap()
        .unwrap();
    f.book
        .retain_close_run_rehearsal(CLOSER, &producer, &original.certificate)
        .unwrap()
        .unwrap();
    let book_id = f.book.context().book_id;
    for (key, debit, credit) in [
        (b"late-debit".as_slice(), "6000", "1000"),
        (b"late-credit".as_slice(), "1000", "6000"),
    ] {
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, debit),
                Amount::new(f.usd, 123),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, credit),
                Amount::new(f.usd, 123),
            ),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(),
            document_date: None,
            description: f.book.seal_text("Later offsetting January source").unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: f.evidence.document_oid,
                intent_kind: 1,
            },
            principal_ref: ADMIN,
            session_ref: None,
            evidence: vec![f.evidence],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        f.book
            .post(fa_journal::PostRequest {
                proposal,
                approvals: Vec::new(),
                capability: cap(ADMIN, &["post"]),
                plan_certificate: None,
            })
            .unwrap()
            .unwrap();
    }
    let current = f
        .book
        .verify_year_end_close(2026, None, &producer)
        .unwrap()
        .unwrap();
    assert!(
        current.is_green() && !current.needs_reclose,
        "net nominal amounts still close"
    );
    let before = f.book.head().unwrap();
    assert_eq!(
        f.book
            .execute_reviewed_close_run(
                "fresh-check",
                closer(),
                "Reject stale FY review",
                &original.certificate,
                None
            )
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::PLAN_INVALIDATED
    );
    assert_eq!(f.book.head().unwrap(), before);
    assert_eq!(
        f.book
            .replay_close_run_rehearsal(CLOSER, &producer, &original.certificate)
            .unwrap()
            .unwrap(),
        original.report,
        "historical review still replays exactly"
    );
}
