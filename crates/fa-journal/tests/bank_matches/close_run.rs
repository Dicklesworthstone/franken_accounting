//! Close prerequisites use real native imports, matches and reconciliations.

use super::*;
use fa_journal::bank::{
    BankReconciliationRecorded, BankReconciliationRequest, reconcile_bank_statement,
};
use fa_journal::close_run::{
    BankReconciliationCheckpoint, CloseRunDefinition, CloseTaskAction, CloseTaskDefinition,
    CloseTaskRecorded, CloseTaskRequest, close_run_status, create_close_run, execute_close_task,
    plan_close_task_transition, verify_bank_reconciliation_checkpoint,
    verify_close_run_checkpoints,
};
use fa_journal::period::TransitionPlan;

#[path = "close_run/coverage.rs"]
mod coverage;

fn closer() -> Capability {
    Capability::embedded(CONFIRMER, &["read", "close", "reconcile"]).unwrap()
}

fn period(h: &Harness) -> String {
    h.book
        .calendar
        .periods_for_year(2026)
        .unwrap()
        .into_iter()
        .find(|period| period.kind == PeriodKind::Normal && period.contains(day()))
        .unwrap()
        .code
}

fn fixture(
    h: &mut Harness,
    closing: DateDay,
) -> (
    BankImportWitness,
    BankMatchRecorded,
    BankReconciliationRecorded,
) {
    let entry = h.entry(&[10_000], "WIRE", b"cash");
    let (import, mut lines) = super::reconciliation_tests::statement(
        h,
        "WIRE",
        &[10_000],
        day(),
        closing,
        0,
        b"close-bank-statement",
    );
    let request = h.request(import.clone(), lines.remove(0), entry, 0);
    let matched = h.confirm(&cap(CONFIRMER), request).unwrap();
    let request = BankReconciliationRequest {
        import: import.clone(),
        predecessors: Vec::new(),
        evaluated_known_at: h.head(),
    };
    let cx = h.cx();
    let reconciled = h
        .runtime
        .block_on(reconcile_bank_statement(
            &mut h.db,
            &cx,
            &h.book,
            &cap(CONFIRMER),
            None,
            request,
        ))
        .unwrap()
        .unwrap();
    (import, matched, reconciled)
}

fn checkpoint(
    h: &Harness,
    manifest: Oid,
    at: Option<CommitSeq>,
) -> Result<BankReconciliationCheckpoint, Refusal> {
    verify_bank_reconciliation_checkpoint(
        &h.db,
        &h.cx(),
        &h.book,
        &metadata_cap(OWNER),
        manifest,
        &period(h),
        at,
    )
    .unwrap()
}

fn start(h: &mut Harness, manifest: Oid) {
    let definition = CloseRunDefinition {
        name: "bank-close".into(),
        period: period(h),
        tasks: vec![
            CloseTaskDefinition {
                id: "bank".into(),
                depends_on: Vec::new(),
                action: CloseTaskAction::VerifyBankReconciliation {
                    manifest_oid: manifest,
                },
            },
            CloseTaskDefinition {
                id: "final".into(),
                depends_on: vec!["bank".into()],
                action: CloseTaskAction::PeriodTransition(PeriodTransition::Close),
            },
        ],
    };
    let cx = h.cx();
    let description = seal(&h.book, "close bank prerequisite");
    h.runtime
        .block_on(create_close_run(
            &mut h.db,
            &cx,
            &h.book,
            &definition,
            &closer(),
            description,
        ))
        .unwrap()
        .unwrap();
}

fn step(
    h: &mut Harness,
    task: &str,
    plan: Option<TransitionPlan>,
    approvals: Vec<ApprovalRef>,
) -> Result<CloseTaskRecorded, Refusal> {
    let request = CloseTaskRequest {
        capability: closer(),
        description: seal(&h.book, "execute bank close task"),
        transition_plan: plan,
        approvals,
        review: None,
    };
    let cx = h.cx();
    h.runtime
        .block_on(execute_close_task(
            &mut h.db,
            &cx,
            &h.book,
            "bank-close",
            task,
            request,
        ))
        .unwrap()
}

fn final_plan(h: &Harness) -> Result<TransitionPlan, Refusal> {
    plan_close_task_transition(
        &h.db,
        &h.cx(),
        &h.book,
        "bank-close",
        "final",
        &closer(),
        1,
        b"close-march-after-bank",
        seal(&h.book, "close March after bank verification"),
    )
    .unwrap()
}

#[test]
fn checkpoint_requires_current_whole_book_authority_and_exact_period_end() {
    let mut h = Harness::new();
    let end = DateDay::from_ymd(2026, 3, 31).unwrap();
    let (import, _, reconciled) = fixture(&mut h, end);
    let at = h.head();
    let verified = checkpoint(&h, import.manifest_oid(), None).unwrap();
    assert_eq!(verified.known_at(), at);
    assert_eq!(verified.manifest_oid(), import.manifest_oid());
    assert_eq!(verified.period(), period(&h));
    assert_eq!(verified.statement_date(), end);
    assert_eq!(verified.account(), account_vid(h.book.book_id, "1000"));
    assert_eq!(verified.unit(), h.usd);
    assert_eq!(verified.attestation().vid, reconciled.attestation_vid);
    assert_eq!(verified.attestation().digest, reconciled.attestation_digest);
    assert!(checkpoint(&h, import.manifest_oid(), Some(CommitSeq(at.0 - 1))).is_err());

    for denied in [
        Capability::embedded(OWNER, &["read"]).unwrap(),
        metadata_cap(OWNER).for_accounts(&["1000"]).unwrap(),
    ] {
        let check = |manifest| {
            verify_bank_reconciliation_checkpoint(
                &h.db,
                &h.cx(),
                &h.book,
                &denied,
                manifest,
                &period(&h),
                None,
            )
            .unwrap()
            .unwrap_err()
        };
        assert_eq!(check(import.manifest_oid()), check(Oid([99; 32])));
    }
    assert_eq!(h.head(), at, "verification never publishes a receipt");

    // A legitimate unrelated publication advances the observation prefix,
    // while the exact accounting prerequisite retains its source identity.
    let document = Document {
        bytes: b"unrelated close workpaper".to_vec(),
        ..h.evidence.clone()
    };
    let cx = h.cx();
    h.runtime
        .block_on(add_document(&mut h.db, &cx, &h.book, &document))
        .unwrap()
        .unwrap();
    let current = checkpoint(&h, import.manifest_oid(), None).unwrap();
    assert!(current.known_at() > verified.known_at());
    assert_eq!(current.source_digest(), verified.source_digest());

    let mut partial = Harness::new();
    let (import, _, _) = fixture(&mut partial, DateDay::from_ymd(2026, 3, 30).unwrap());
    start(&mut partial, import.manifest_oid());
    let before = partial.head();
    assert_eq!(
        step(&mut partial, "bank", None, Vec::new())
            .unwrap_err()
            .code,
        refusal::code::PLAN_INVALIDATED
    );
    assert_eq!(partial.head(), before);
}

#[test]
fn match_correction_preserves_receipt_but_blocks_even_a_prepared_terminal_plan() {
    let mut h = Harness::new();
    let (import, matched, reconciled) = fixture(&mut h, DateDay::from_ymd(2026, 3, 31).unwrap());
    start(&mut h, import.manifest_oid());
    let before = h.head();
    let completed = step(&mut h, "bank", None, Vec::new()).unwrap();
    assert_eq!(
        h.head().0,
        before.0 + 1,
        "receipt is one native publication"
    );
    assert_eq!(completed.receipt.effect, reconciled.attestation_vid);
    let plan = final_plan(&h).unwrap();
    h.unmatch(&metadata_cap(CONFIRMER), decision_ref(&matched))
        .unwrap();
    let after_correction = h.head();

    // Historical task integrity uses its original prefix, without requiring
    // the bank decision or its original authority to remain currently active.
    let view = close_run_status(
        &h.db,
        &h.cx(),
        &h.book,
        "bank-close",
        &Capability::embedded(OWNER, &["read"]).unwrap(),
    )
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(view.tasks[0].completion.as_ref(), Some(&completed.receipt));
    let retry = step(&mut h, "bank", None, Vec::new()).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.receipt, completed.receipt);
    let request = CloseTaskRequest {
        capability: Capability::embedded(OWNER, &["read", "close"]).unwrap(),
        description: seal(&h.book, "observe the original bank close receipt"),
        transition_plan: None,
        approvals: Vec::new(),
        review: None,
    };
    let cx = h.cx();
    let retry_without_reconcile = h
        .runtime
        .block_on(execute_close_task(
            &mut h.db,
            &cx,
            &h.book,
            "bank-close",
            "bank",
            request,
        ))
        .unwrap()
        .unwrap();
    assert!(retry_without_reconcile.already_recorded);
    assert_eq!(retry_without_reconcile.receipt, completed.receipt);
    assert_eq!(h.head(), after_correction);
    assert_eq!(
        final_plan(&h).unwrap_err().code,
        refusal::code::PLAN_INVALIDATED
    );
    assert_eq!(
        verify_close_run_checkpoints(
            &h.db,
            &h.cx(),
            &h.book,
            "bank-close",
            &closer(),
            after_correction,
        )
        .unwrap()
        .unwrap_err()
        .code,
        refusal::code::PLAN_INVALIDATED
    );
    assert_eq!(
        step(&mut h, "final", Some(plan), Vec::new())
            .unwrap_err()
            .code,
        refusal::code::PLAN_INVALIDATED,
        "a precomputed transition plan cannot bypass the atomic bank gate"
    );
    assert_eq!(
        h.head(),
        after_correction,
        "refused transition and receipt both stay absent"
    );
}

#[test]
fn equal_bank_balance_cannot_hide_later_net_zero_cash_contributions() {
    let mut h = Harness::new();
    let (import, _, _) = fixture(&mut h, DateDay::from_ymd(2026, 3, 31).unwrap());
    start(&mut h, import.manifest_oid());
    step(&mut h, "bank", None, Vec::new()).unwrap();
    let original_at = h.head();
    let original = checkpoint(&h, import.manifest_oid(), None).unwrap();
    h.entry(&[25], "LATE RECEIPT", b"late-cash-debit");
    let mut proposal = h.entry_payload(&[25], "LATE DISBURSEMENT", b"late-cash-credit");
    for leg in &mut proposal.legs {
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    let cx = h.cx();
    h.runtime
        .block_on(post(
            &mut h.db,
            &cx,
            &h.book,
            PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(OWNER),
            },
        ))
        .unwrap()
        .unwrap();
    let at = h.head();
    let states = fa_journal::bank::read_bank_reconciliation_states(
        &h.db,
        &h.cx(),
        &h.book,
        &metadata_cap(OWNER),
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(states.len(), 1);
    assert!(!states[0].balance_drift);
    assert!(!states[0].match_drift);
    assert!(states[0].cash_drift);
    assert_eq!(states[0].changed_entries.len(), 2);
    assert_eq!(
        checkpoint(&h, import.manifest_oid(), Some(original_at))
            .unwrap()
            .source_digest(),
        original.source_digest(),
        "the historical verification remains exactly reproducible"
    );
    assert_eq!(
        checkpoint(&h, import.manifest_oid(), None)
            .unwrap_err()
            .code,
        refusal::code::PLAN_INVALIDATED
    );
    assert_eq!(
        final_plan(&h).unwrap_err().code,
        refusal::code::PLAN_INVALIDATED
    );
    assert_eq!(h.head(), at);
}

#[test]
fn a_missing_statement_can_be_declared_but_cannot_complete_a_bank_task() {
    let mut h = Harness::new();
    start(&mut h, Oid([91; 32]));
    let before = h.head();
    assert_eq!(
        step(&mut h, "bank", None, Vec::new()).unwrap_err().code,
        refusal::code::PLAN_INVALIDATED
    );
    assert!(
        final_plan(&h).is_err(),
        "the terminal task is still blocked"
    );
    assert_eq!(h.head(), before);
}

#[test]
fn forged_period_end_cannot_make_partial_bank_coverage_complete() {
    let mut h = Harness::new();
    let (import, _, _) = fixture(&mut h, DateDay::from_ymd(2026, 3, 30).unwrap());
    assert!(checkpoint(&h, import.manifest_oid(), None).is_err());
    let mut damage = WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        fa_model::period_vid(&h.book.calendar.id, &period(&h)),
        property::PERIOD_END,
        Some(CanonicalScalar::Int(i64::from(
            DateDay::from_ymd(2026, 3, 31).unwrap().0,
        ))),
    );
    h.write(damage);
    let before = h.head();
    let error = verify_bank_reconciliation_checkpoint(
        &h.db,
        &h.cx(),
        &h.book,
        &metadata_cap(OWNER),
        import.manifest_oid(),
        &period(&h),
        None,
    )
    .unwrap_err();
    assert!(
        matches!(error, KernelError::Corrupt(ref message) if message.contains("canonical birth definition"))
    );
    assert_eq!(h.head(), before);
}
