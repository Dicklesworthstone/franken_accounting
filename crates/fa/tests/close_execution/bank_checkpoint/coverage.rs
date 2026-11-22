//! Combined reviewed closes prove a complete registered-bank portfolio.

use super::*;
use fa_model::{InstrumentKind, InstrumentSpec, PartyKind, PartySpec};

fn register_bank(f: &mut Fixture, code: &str, account: &str) -> VId {
    let schema = cap(ADMIN, &["schema_change"]);
    let party = PartySpec {
        code: format!("BANK-{code}"),
        kind: PartyKind::Bank,
        name: f.book.seal_text("Bank counterparty").unwrap(),
        identifiers: Vec::new(),
        external_ids: Vec::new(),
    };
    let bank = f
        .book
        .create_party(&party, ADMIN, day(), party.code.as_bytes(), &schema)
        .unwrap()
        .unwrap()
        .target_vid;
    let spec = InstrumentSpec {
        code: code.into(),
        name: format!("Registered {code} cash account"),
        kind: InstrumentKind::BankAccount,
        unit: f.usd,
        held_at_party: bank,
        mirrors_account: account_vid(f.book.context().book_id, account),
        external_ids: Vec::new(),
    };
    f.book
        .create_instrument(&spec, ADMIN, day(), code.as_bytes(), &schema)
        .unwrap()
        .unwrap()
        .target_vid
}

fn second_account(f: &mut Fixture) {
    f.book
        .install_chart(
            &[AccountSpec {
                code: "1001".into(),
                name: "Payroll bank cash".into(),
                account_type: AccountType::ASSET.0,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(f.usd),
                parent_code: None,
                limit: None,
            }],
            ADMIN,
            day(),
            b"payroll-chart",
            &cap(ADMIN, &["schema_change"]),
        )
        .unwrap()
        .unwrap();
}

fn statement(f: &mut Fixture, account: &str) -> Oid {
    f.book
        .import_bank_statement(
            &cap(ADMIN, &["read", "post", "reconcile"]),
            BankImportRequest {
                account: account_vid(f.book.context().book_id, account),
                format: BankFormat::Mt940,
                bytes: format!(
                    ":20:COVERAGE-{account}\n:25:BANK-{account}\n:28C:1\n:60F:C260101USD0,\n:62F:C260131USD0,\n"
                )
                .into_bytes(),
                previous_manifest: None,
            },
        )
        .unwrap()
        .unwrap()
        .manifest_oid
}

fn coverage_tasks(manifest_oids: Vec<Oid>) -> Vec<ReviewedCloseTask> {
    vec![
        task(
            "verify-all-banks",
            &[],
            ReviewedCloseAction::VerifyBankInstrumentCoverage { manifest_oids },
        ),
        task(
            "finish",
            &["verify-all-banks"],
            ReviewedCloseAction::PeriodTransition(PeriodTransition::SoftClose),
        ),
    ]
}

#[test]
fn complete_registered_bank_inventory_survives_retention_and_finishes_reviewed_close() {
    let mut f = Fixture::new(231);
    second_account(&mut f);
    let operating = register_bank(&mut f, "OPERATING", "1000");
    let payroll = register_bank(&mut f, "PAYROLL", "1001");
    let a = statement(&mut f, "1000");
    let b = statement(&mut f, "1001");
    let a_reconciled = reconcile(&mut f, a);
    let b_reconciled = reconcile(&mut f, b);
    start(&mut f, "portfolio", coverage_tasks(vec![b, a]));
    let producer = bank_producer();
    let before = f.book.head().unwrap();
    let original = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "portfolio")
        .unwrap()
        .unwrap();
    assert_eq!(
        f.book.head().unwrap(),
        before,
        "complete coverage rehearsal is read-only"
    );
    let CloseTaskRehearsalOutcome::VerifiedBankInstrumentCoverage {
        verified_at,
        inventory_digest,
        source_digest,
        instruments,
    } = &original.report.tasks[0].outcome
    else {
        panic!("the combined review must retain its complete native bank inventory");
    };
    assert_eq!(*verified_at, before);
    assert_eq!(instruments.len(), 2);
    for (instrument, manifest, attestation) in [
        (operating, a, a_reconciled.attestation_vid),
        (payroll, b, b_reconciled.attestation_vid),
    ] {
        let row = instruments
            .iter()
            .find(|row| row.instrument == instrument)
            .unwrap();
        assert_eq!(row.manifest_oid, manifest);
        assert_eq!(row.attestation.vid, attestation);
    }
    f.book
        .retain_close_run_rehearsal(CLOSER, &producer, &original.certificate)
        .unwrap()
        .unwrap();
    let current = f
        .book
        .close_run_rehearsal(CLOSER, &producer, "portfolio")
        .unwrap()
        .unwrap();
    let CloseTaskRehearsalOutcome::VerifiedBankInstrumentCoverage {
        verified_at: current_at,
        inventory_digest: current_inventory,
        source_digest: current_source,
        instruments: current_instruments,
    } = &current.tasks[0].outcome
    else {
        panic!("retention preserves complete coverage");
    };
    assert!(*current_at > *verified_at);
    assert_eq!(current_inventory, inventory_digest);
    assert_eq!(current_source, source_digest);
    assert_eq!(current_instruments, instruments);

    let execution = f
        .book
        .execute_reviewed_close_run(
            "portfolio",
            bank_closer(),
            "Execute reviewed full bank coverage",
            &original.certificate,
            Some(CloseRunTransition::Review {
                task: "finish".into(),
                reason_code: 1,
                idempotency_key: b"portfolio-soft-close".to_vec(),
            }),
        )
        .unwrap()
        .unwrap();
    assert_eq!(execution.completed.len(), 1);
    assert_eq!(execution.completed[0].task, "verify-all-banks");
    assert_eq!(
        execution.completed[0].receipt.effect,
        fa_journal::rows::book_root()
    );
    let Some(CloseRunStop::TransitionReview { plan, .. }) = execution.stop else {
        panic!("period transition still requires independent review");
    };
    let completion = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "portfolio")
        .unwrap()
        .unwrap();
    f.book
        .retain_close_run_rehearsal(CLOSER, &producer, &completion.certificate)
        .unwrap()
        .unwrap();
    let finished = f
        .book
        .execute_reviewed_close_run(
            "portfolio",
            bank_closer(),
            "Finish reviewed complete-bank close",
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
    assert_eq!(
        f.book
            .replay_close_run_rehearsal(CLOSER, &producer, &original.certificate)
            .unwrap()
            .unwrap(),
        original.report
    );
}

#[test]
fn omitted_registered_bank_refuses_before_any_receipt_and_requires_bank_authority() {
    let mut f = Fixture::new(232);
    second_account(&mut f);
    register_bank(&mut f, "OPERATING", "1000");
    register_bank(&mut f, "PAYROLL", "1001");
    let a = statement(&mut f, "1000");
    reconcile(&mut f, a);
    start(&mut f, "incomplete-portfolio", coverage_tasks(vec![a]));
    let before = f.book.head().unwrap();
    let execution = f
        .book
        .execute_close_run(
            "incomplete-portfolio",
            bank_closer(),
            "Require all registered banks",
            None,
        )
        .unwrap()
        .unwrap();
    assert!(execution.completed.is_empty());
    assert!(
        matches!(execution.stop, Some(CloseRunStop::Refused { ref task, .. }) if task == "verify-all-banks")
    );
    assert!(
        f.book
            .close_run_rehearsal(CLOSER, &bank_producer(), "incomplete-portfolio")
            .unwrap()
            .is_err()
    );
    let denied = f
        .book
        .verify_bank_instrument_coverage_checkpoint(&[a], PERIOD, None, &closer())
        .unwrap()
        .unwrap_err();
    let unknown = f
        .book
        .verify_bank_instrument_coverage_checkpoint(&[Oid([99; 32])], "absent", None, &closer())
        .unwrap()
        .unwrap_err();
    assert_eq!(denied, unknown);
    assert_eq!(denied.code, fa_journal::refusal::code::CAPABILITY);
    assert_eq!(
        f.book
            .execute_close_task(
                "incomplete-portfolio",
                "verify-all-banks",
                closer(),
                "Denied source replay",
                None,
                Vec::new(),
            )
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::CAPABILITY
    );
    assert_eq!(f.book.head().unwrap(), before);
}

#[test]
fn new_bank_registration_invalidates_current_review_but_preserves_original_replay() {
    let mut f = Fixture::new(233);
    second_account(&mut f);
    register_bank(&mut f, "OPERATING", "1000");
    let a = statement(&mut f, "1000");
    reconcile(&mut f, a);
    start(&mut f, "inventory-drift", coverage_tasks(vec![a]));
    let producer = bank_producer();
    let original = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "inventory-drift")
        .unwrap()
        .unwrap();
    f.book
        .retain_close_run_rehearsal(CLOSER, &producer, &original.certificate)
        .unwrap()
        .unwrap();
    register_bank(&mut f, "PAYROLL", "1001");
    let before = f.book.head().unwrap();
    assert_eq!(
        f.book
            .execute_reviewed_close_run(
                "inventory-drift",
                bank_closer(),
                "Do not omit the new bank",
                &original.certificate,
                None,
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
        original.report
    );
}

#[test]
fn portfolio_preflight_checks_cash_drift_in_combined_scratch_before_posting() {
    let mut f = Fixture::new(234);
    register_bank(&mut f, "OPERATING", "1000");
    let a = statement(&mut f, "1000");
    reconcile(&mut f, a);
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
            "cash-adjustment",
            day(),
            "Authorized cash adjustment",
        )
        .unwrap()
        .unwrap();
    let proposal = proposal(&mut f, "cash-adjustment", PLANNER, "6000", "1000");
    f.book
        .plan_into_draft(
            planning,
            "cash-adjustment",
            PostIntent::new(proposal, Vec::new()).unwrap(),
        )
        .unwrap()
        .unwrap();
    let producer = bank_producer();
    let draft = f
        .book
        .certify_draft_diff(CLOSER, &producer, "cash-adjustment", PERIOD)
        .unwrap()
        .unwrap();
    f.book
        .retain_draft_diff(CLOSER, &producer, &draft.certificate)
        .unwrap()
        .unwrap();
    start(
        &mut f,
        "combined-portfolio",
        vec![
            task(
                "post-cash",
                &[],
                ReviewedCloseAction::DraftCertificate(*draft.certificate.digest()),
            ),
            task(
                "verify-all-banks",
                &["post-cash"],
                ReviewedCloseAction::VerifyBankInstrumentCoverage {
                    manifest_oids: vec![a],
                },
            ),
        ],
    );
    let before = f.book.head().unwrap();
    let execution = f
        .book
        .execute_close_run(
            "combined-portfolio",
            bank_closer(),
            "Check all cash after every draft",
            None,
        )
        .unwrap()
        .unwrap();
    assert!(execution.completed.is_empty());
    assert!(
        matches!(execution.stop, Some(CloseRunStop::Refused { ref task, .. }) if task == "verify-all-banks")
    );
    assert_eq!(f.book.head().unwrap(), before);
    assert_eq!(
        f.book.draft("cash-adjustment").unwrap().unwrap().state,
        fa_journal::DraftState::Open
    );
}
