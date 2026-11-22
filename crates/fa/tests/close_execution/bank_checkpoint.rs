//! A close checks real retained bank evidence at the final monetary prefix.

use super::*;
use fa::CloseTaskRehearsalOutcome;
use fa::bank::{
    BankDecisionRef, BankFormat, BankImportRequest, BankReconciliationRequest, BankStatusRequest,
};

#[path = "bank_checkpoint/coverage.rs"]
mod coverage;

fn bank_closer() -> Capability {
    cap(CLOSER, &["read", "close", "approve", "reconcile"])
}

fn bank_producer() -> Capability {
    cap(CLOSER, &["read", "produce", "reconcile"])
}

fn empty_statement(f: &mut Fixture, end: &str) -> Oid {
    let account = account_vid(f.book.context().book_id, "1000");
    f.book
        .import_bank_statement(
            &cap(ADMIN, &["read", "post", "reconcile"]),
            BankImportRequest {
                account,
                format: BankFormat::Mt940,
                bytes: format!(
                    ":20:CLOSE-STATEMENT\n:25:OPERATING-ACCOUNT\n:28C:1\n:60F:C260101USD0,\n:62F:C{end}USD0,\n"
                )
                .into_bytes(),
                previous_manifest: None,
            },
        )
        .unwrap()
        .unwrap()
        .manifest_oid
}

fn reconcile(f: &mut Fixture, manifest_oid: Oid) -> fa::bank::BankReconciliationRecorded {
    let evaluated_known_at = f.book.head().unwrap();
    f.book
        .reconcile_bank_statement(
            &bank_closer(),
            BankReconciliationRequest {
                manifest_oid,
                evaluated_known_at,
            },
        )
        .unwrap()
        .unwrap()
}

fn tasks(manifest_oid: Oid) -> Vec<ReviewedCloseTask> {
    vec![
        task(
            "verify-bank",
            &[],
            ReviewedCloseAction::VerifyBankReconciliation { manifest_oid },
        ),
        task(
            "finish",
            &["verify-bank"],
            ReviewedCloseAction::PeriodTransition(PeriodTransition::SoftClose),
        ),
    ]
}

fn start(f: &mut Fixture, name: &str, tasks: Vec<ReviewedCloseTask>) {
    f.book
        .start_close_run(bank_closer(), name, PERIOD, tasks, "Reconcile before close")
        .unwrap()
        .unwrap();
}

fn proposal(f: &mut Fixture, key: &str, principal: VId, debit: &str, credit: &str) -> EntryPayload {
    let book_id = f.book.context().book_id;
    let legs = vec![
        LegPayload::simple(
            Side::Debit,
            account_vid(book_id, debit),
            Amount::new(f.usd, 125),
        ),
        LegPayload::simple(
            Side::Credit,
            account_vid(book_id, credit),
            Amount::new(f.usd, 125),
        ),
    ];
    EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: day(),
        document_date: None,
        description: f.book.seal_text("January cash contribution").unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: key.as_bytes().to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: f.evidence.document_oid,
            intent_kind: 1,
        },
        principal_ref: principal,
        session_ref: None,
        evidence: vec![f.evidence],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    }
}

#[test]
fn bank_checkpoint_review_survives_retention_and_finishes_the_native_close() {
    let mut f = Fixture::new(219);
    let manifest_oid = empty_statement(&mut f, "260131");
    let reconciled = reconcile(&mut f, manifest_oid);
    start(&mut f, "bank-close", tasks(manifest_oid));
    let producer = bank_producer();
    let before = f.book.head().unwrap();
    let original = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "bank-close")
        .unwrap()
        .unwrap();
    assert_eq!(f.book.head().unwrap(), before, "rehearsal is read-only");
    let CloseTaskRehearsalOutcome::VerifiedBankReconciliation {
        manifest_oid: checked_manifest,
        verified_at,
        attestation,
        statement_date,
        account,
        unit,
        source_digest,
    } = &original.report.tasks[0].outcome
    else {
        panic!("the combined review must bind the native bank checkpoint");
    };
    assert_eq!(*checked_manifest, manifest_oid);
    assert_eq!(*verified_at, before);
    assert_eq!(
        *attestation,
        BankDecisionRef {
            vid: reconciled.attestation_vid,
            digest: reconciled.attestation_digest,
        }
    );
    assert_eq!(*statement_date, DateDay::from_ymd(2026, 1, 31).unwrap());
    assert_eq!(*account, account_vid(f.book.context().book_id, "1000"));
    assert_eq!(*unit, f.usd);
    f.book
        .retain_close_run_rehearsal(CLOSER, &producer, &original.certificate)
        .unwrap()
        .unwrap();
    let current = f
        .book
        .close_run_rehearsal(CLOSER, &producer, "bank-close")
        .unwrap()
        .unwrap();
    let CloseTaskRehearsalOutcome::VerifiedBankReconciliation {
        verified_at: current_at,
        attestation: current_attestation,
        source_digest: current_digest,
        ..
    } = &current.tasks[0].outcome
    else {
        panic!("metadata retention preserves the checked bank basis");
    };
    assert!(current_at > verified_at);
    assert_eq!(current_attestation, attestation);
    assert_eq!(current_digest, source_digest);

    let execution = f
        .book
        .execute_reviewed_close_run(
            "bank-close",
            bank_closer(),
            "Execute exact bank checkpoint",
            &original.certificate,
            Some(CloseRunTransition::Review {
                task: "finish".into(),
                reason_code: 1,
                idempotency_key: b"bank-checkpoint-close".to_vec(),
            }),
        )
        .unwrap()
        .unwrap();
    assert_eq!(execution.completed.len(), 1);
    assert_eq!(execution.completed[0].task, "verify-bank");
    let Some(CloseRunStop::TransitionReview { plan, .. }) = execution.stop else {
        panic!("the terminal transition still needs separate native review");
    };
    let completion = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "bank-close")
        .unwrap()
        .unwrap();
    f.book
        .retain_close_run_rehearsal(CLOSER, &producer, &completion.certificate)
        .unwrap()
        .unwrap();
    let finished = f
        .book
        .execute_reviewed_close_run(
            "bank-close",
            bank_closer(),
            "Finish independently reviewed close",
            &completion.certificate,
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
    let after = f.book.head().unwrap();
    let retry = f
        .book
        .execute_close_run("bank-close", bank_closer(), "Exact completed retry", None)
        .unwrap()
        .unwrap();
    assert!(retry.completed.is_empty());
    assert_eq!(f.book.head().unwrap(), after);
    let bank = f
        .book
        .bank_reconciliation_status(
            &bank_closer(),
            BankStatusRequest {
                manifest_oid,
                known_at: None,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        bank.reconciliations.len(),
        1,
        "verification cannot invent an attestation"
    );
    assert_eq!(bank.reconciliations[0].recorded, reconciled);
    assert_eq!(
        f.book
            .replay_close_run_rehearsal(CLOSER, &producer, &original.certificate)
            .unwrap()
            .unwrap(),
        original.report
    );
}

#[test]
fn bank_checkpoint_requires_reconcile_before_observing_the_selected_statement() {
    let mut f = Fixture::new(220);
    let manifest_oid = empty_statement(&mut f, "260131");
    reconcile(&mut f, manifest_oid);
    let before = f.book.head().unwrap();
    let denied = f
        .book
        .verify_bank_reconciliation_checkpoint(manifest_oid, PERIOD, None, &closer())
        .unwrap()
        .unwrap_err();
    let unknown = f
        .book
        .verify_bank_reconciliation_checkpoint(Oid([0xf1; 32]), "absent", None, &closer())
        .unwrap()
        .unwrap_err();
    assert_eq!(
        denied, unknown,
        "missing authority cannot disclose source existence"
    );
    assert_eq!(denied.code, fa_journal::refusal::code::CAPABILITY);
    assert!(
        f.book
            .start_close_run(
                closer(),
                "denied",
                PERIOD,
                tasks(manifest_oid),
                "Missing bank grant"
            )
            .unwrap()
            .is_err()
    );
    assert_eq!(f.book.head().unwrap(), before);
    start(&mut f, "authorized", tasks(manifest_oid));
    let before = f.book.head().unwrap();
    assert!(
        f.book
            .close_run_status("authorized", &cap(CLOSER, &["read"]))
            .unwrap()
            .unwrap()
            .is_some(),
        "reading the declared graph needs no fresh bank verification grant"
    );
    assert_eq!(
        f.book
            .execute_close_task(
                "authorized",
                "verify-bank",
                closer(),
                "Missing bank grant",
                None,
                Vec::new(),
            )
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::CAPABILITY,
    );
    assert_eq!(
        f.book
            .plan_close_task_transition(
                "authorized",
                "finish",
                &closer(),
                1,
                b"missing-bank-grant",
                "Missing bank grant",
            )
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::CAPABILITY,
    );
    assert_eq!(
        f.book
            .execute_close_run("authorized", closer(), "Missing bank grant", None)
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::CAPABILITY,
    );
    assert!(
        f.book
            .close_run_rehearsal(CLOSER, &closer(), "authorized")
            .unwrap()
            .is_err()
    );
    assert_eq!(f.book.head().unwrap(), before);
}

#[test]
fn bank_checkpoint_review_binds_the_exact_attestation_even_when_cash_is_unchanged() {
    let mut f = Fixture::new(225);
    let manifest_oid = empty_statement(&mut f, "260131");
    let first = reconcile(&mut f, manifest_oid);
    start(&mut f, "replacement-check", tasks(manifest_oid));
    let producer = bank_producer();
    let original = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "replacement-check")
        .unwrap()
        .unwrap();
    f.book
        .retain_close_run_rehearsal(CLOSER, &producer, &original.certificate)
        .unwrap()
        .unwrap();
    let replacement = reconcile(&mut f, manifest_oid);
    assert_ne!(replacement.attestation_vid, first.attestation_vid);
    let checked = f
        .book
        .verify_bank_reconciliation_checkpoint(manifest_oid, PERIOD, None, &bank_closer())
        .unwrap()
        .unwrap();
    assert_eq!(checked.attestation().vid, replacement.attestation_vid);
    let before = f.book.head().unwrap();
    assert_eq!(
        f.book
            .execute_reviewed_close_run(
                "replacement-check",
                bank_closer(),
                "Do not substitute the reviewed attestation",
                &original.certificate,
                None,
            )
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::PLAN_INVALIDATED,
    );
    assert_eq!(f.book.head().unwrap(), before);
    assert_eq!(
        f.book
            .replay_close_run_rehearsal(CLOSER, &producer, &original.certificate)
            .unwrap()
            .unwrap(),
        original.report,
    );
}

#[test]
fn bank_checkpoint_refuses_missing_attestation_and_partial_period_coverage() {
    for (seed, end, should_reconcile) in [(221, "260131", false), (222, "260130", true)] {
        let mut f = Fixture::new(seed);
        let manifest_oid = empty_statement(&mut f, end);
        if should_reconcile {
            reconcile(&mut f, manifest_oid);
        }
        // Declaring the task does not make an accounting assertion.
        start(&mut f, "incomplete-bank", tasks(manifest_oid));
        let before = f.book.head().unwrap();
        let refusal = f
            .book
            .close_run_rehearsal(CLOSER, &bank_closer(), "incomplete-bank")
            .unwrap()
            .unwrap_err();
        assert!(refusal.message.contains("verify-bank"));
        let execution = f
            .book
            .execute_close_run(
                "incomplete-bank",
                bank_closer(),
                "Require complete evidence",
                None,
            )
            .unwrap()
            .unwrap();
        assert!(execution.completed.is_empty());
        assert!(matches!(
            execution.stop,
            Some(CloseRunStop::Refused { ref task, .. }) if task == "verify-bank"
        ));
        assert_eq!(f.book.head().unwrap(), before);
    }
}

#[test]
fn bank_checkpoint_preflight_checks_the_final_scratch_before_any_live_cash_posting() {
    let mut f = Fixture::new(223);
    let manifest_oid = empty_statement(&mut f, "260131");
    reconcile(&mut f, manifest_oid);
    let planning = Capability::new(
        PLANNER,
        Profile::Agent,
        &[Op::Read, Op::Post, Op::Reconcile],
        ADMIN,
    )
    .unwrap();
    f.book
        .open_draft(
            planning.clone(),
            "late-cash",
            day(),
            "Authorized later cash",
        )
        .unwrap()
        .unwrap();
    let proposal = proposal(&mut f, "late-cash", PLANNER, "6000", "1000");
    f.book
        .plan_into_draft(
            planning,
            "late-cash",
            PostIntent::new(proposal, Vec::new()).unwrap(),
        )
        .unwrap()
        .unwrap();
    let producer = bank_producer();
    let draft = f
        .book
        .certify_draft_diff(CLOSER, &producer, "late-cash", PERIOD)
        .unwrap()
        .unwrap();
    f.book
        .retain_draft_diff(CLOSER, &producer, &draft.certificate)
        .unwrap()
        .unwrap();
    start(
        &mut f,
        "hypothetical-drift",
        vec![
            task(
                "post-cash",
                &[],
                ReviewedCloseAction::DraftCertificate(*draft.certificate.digest()),
            ),
            task(
                "verify-bank",
                &["post-cash"],
                ReviewedCloseAction::VerifyBankReconciliation { manifest_oid },
            ),
        ],
    );
    let before = f.book.head().unwrap();
    let execution = f
        .book
        .execute_close_run(
            "hypothetical-drift",
            bank_closer(),
            "Check the combined result",
            None,
        )
        .unwrap()
        .unwrap();
    assert!(execution.completed.is_empty());
    assert!(matches!(
        execution.stop,
        Some(CloseRunStop::Refused { ref task, .. }) if task == "verify-bank"
    ));
    assert_eq!(f.book.head().unwrap(), before);
    assert_eq!(
        f.book.draft("late-cash").unwrap().unwrap().state,
        fa_journal::DraftState::Open
    );
    assert!(
        execution
            .run
            .tasks
            .iter()
            .all(|task| task.completion.is_none())
    );
}

#[test]
fn bank_checkpoint_terminal_check_detects_offsetting_cash_after_completion() {
    let mut f = Fixture::new(224);
    let manifest_oid = empty_statement(&mut f, "260131");
    reconcile(&mut f, manifest_oid);
    start(&mut f, "later-drift", tasks(manifest_oid));
    let producer = bank_producer();
    let original = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "later-drift")
        .unwrap()
        .unwrap();
    f.book
        .retain_close_run_rehearsal(CLOSER, &producer, &original.certificate)
        .unwrap()
        .unwrap();
    f.book
        .execute_reviewed_close_task(
            "later-drift",
            "verify-bank",
            bank_closer(),
            "Complete the current checkpoint",
            &original.certificate,
            None,
            Vec::new(),
        )
        .unwrap()
        .unwrap();
    for (key, debit, credit) in [
        ("cash-debit", "1000", "6000"),
        ("cash-credit", "6000", "1000"),
    ] {
        let proposal = proposal(&mut f, key, ADMIN, debit, credit);
        f.book
            .post(fa_journal::PostRequest {
                proposal,
                approvals: Vec::new(),
                capability: cap(ADMIN, &["post", "reconcile"]),
                plan_certificate: None,
            })
            .unwrap()
            .unwrap();
    }
    let bank = f
        .book
        .bank_reconciliation_status(
            &bank_closer(),
            BankStatusRequest {
                manifest_oid,
                known_at: None,
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(bank.reconciliations[0].cash_balance, 0);
    assert!(!bank.reconciliations[0].balance_drift);
    assert!(
        bank.reconciliations[0].cash_drift,
        "unchanged net cash is insufficient"
    );
    let before = f.book.head().unwrap();
    assert!(
        f.book
            .plan_close_task_transition(
                "later-drift",
                "finish",
                &bank_closer(),
                1,
                b"after-cash-drift",
                "A new plan must recheck completed bank prerequisites",
            )
            .unwrap()
            .is_err()
    );
    assert!(
        f.book
            .close_run_rehearsal(CLOSER, &producer, "later-drift")
            .unwrap()
            .is_err()
    );
    assert_eq!(f.book.head().unwrap(), before);
    assert_eq!(
        f.book
            .replay_close_run_rehearsal(CLOSER, &producer, &original.certificate)
            .unwrap()
            .unwrap(),
        original.report,
        "later drift must preserve the authentic historical review"
    );
}
