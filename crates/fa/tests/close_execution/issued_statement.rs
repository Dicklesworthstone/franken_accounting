//! Real report replay, source freshness and historical close receipts through
//! the public facade. Every issuance and monetary contribution is admitted by
//! the native kernel; no synthetic report certificate enters these tests.

use super::*;
use fa::{
    CloseRunRehearsalCertificate, CloseTaskRehearsalOutcome, ReportCertificate, ReportOutput,
    Statement, StatementDefinition, StatementSelection,
};
use fa_journal::issuance::IssuanceRecord;
use fa_journal::refusal::code;
use fa_journal::{IssuedTo, PostRequest};

fn post(f: &mut Fixture, key: &[u8], debit: &str, credit: &str, amount: i128) {
    let book_id = f.book.context().book_id;
    let legs = vec![
        LegPayload::simple(
            Side::Debit,
            account_vid(book_id, debit),
            Amount::new(f.usd, amount),
        ),
        LegPayload::simple(
            Side::Credit,
            account_vid(book_id, credit),
            Amount::new(f.usd, amount),
        ),
    ];
    let proposal = EntryPayload {
        schema_minor: 0,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: day(),
        document_date: None,
        description: f
            .book
            .seal_text("Issued statement source contribution")
            .unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: key.to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([231; 32]),
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
        .post(PostRequest {
            proposal,
            approvals: Vec::new(),
            capability: cap(ADMIN, &["read", "post"]),
            plan_certificate: None,
        })
        .unwrap()
        .unwrap();
}

fn issue(f: &mut Fixture) -> (IssuanceRecord, ReportCertificate, Statement) {
    let certified = f
        .book
        .certify_statement(
            StatementSelection {
                definition: StatementDefinition::embedded("income-statement").unwrap(),
                periods: vec![PERIOD.into()],
                comparative: Vec::new(),
            },
            Some(f.book.head().unwrap()),
        )
        .unwrap()
        .unwrap();
    let retained = f
        .book
        .retain_certificate(
            ADMIN,
            &cap(ADMIN, &["read", "produce"]),
            &certified.certificate,
        )
        .unwrap()
        .unwrap();
    let controller = cap(ADMIN, &["read", "close"]);
    let plan = f
        .book
        .plan_statement_issuance(
            &controller,
            &retained.digest,
            None,
            IssuedTo::Auditor,
            None,
            day(),
            b"issued-statement-auditor",
        )
        .unwrap()
        .unwrap();
    let digest = plan.proposal_digest(f.book.context()).unwrap();
    let approval = f
        .book
        .approve(cap(CLOSER, &["approve"]), digest)
        .unwrap()
        .unwrap()
        .approval();
    let record = f
        .book
        .issue_statements(&controller, plan, vec![approval])
        .unwrap()
        .unwrap()
        .record;
    (record, certified.certificate, certified.statement)
}

fn tasks(terminal: bool) -> Vec<ReviewedCloseTask> {
    let mut tasks = vec![task(
        "statement",
        &[],
        ReviewedCloseAction::RequireCurrentStatementIssuance { ordinal: 1 },
    )];
    if terminal {
        tasks.push(task(
            "finish",
            &["statement"],
            ReviewedCloseAction::PeriodTransition(PeriodTransition::Close),
        ));
    }
    tasks
}

fn cash_net(book: &Book) -> i128 {
    book.trial_balance(&[PERIOD.into()])
        .unwrap()
        .rows
        .iter()
        .filter(|row| row.code == "1000")
        .map(|row| row.debits - row.credits)
        .sum()
}

#[test]
fn issued_statement_close_requires_retained_review_and_resumes_after_reopen() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("fa-close-issued-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let seed = 231;
    let mut f = Fixture::at(seed, Some(&directory));
    post(&mut f, b"statement-source", "6000", "1000", 1_000);
    let (issuance, report_certificate, statement) = issue(&mut f);
    f.start("issued", tasks(true));
    let producer = cap(CLOSER, &["read", "produce"]);
    let basis = f
        .book
        .verify_statement_issuance_checkpoint(PERIOD, 1, None, &closer())
        .unwrap()
        .unwrap();
    assert_eq!(basis.issuance(), &issuance);
    let before = f.book.head().unwrap();
    assert_eq!(
        f.book
            .execute_close_task(
                "issued",
                "statement",
                closer(),
                "A real issuance alone is not a combined review",
                None,
                Vec::new(),
            )
            .unwrap()
            .unwrap_err()
            .code,
        code::PLAN_INVALIDATED
    );
    assert_eq!(f.book.head().unwrap(), before);

    let original = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "issued")
        .unwrap()
        .unwrap();
    assert_eq!(
        f.book.head().unwrap(),
        before,
        "rehearsal must publish nothing"
    );
    let checked = original
        .report
        .tasks
        .iter()
        .find(|task| task.id == "statement")
        .unwrap();
    let CloseTaskRehearsalOutcome::CurrentStatementIssuance {
        ordinal,
        checked_at,
        issuance: recorded_issuance,
        certificate_digest,
        certified_at,
        source_digest,
    } = &checked.outcome
    else {
        panic!("real retained statement prerequisite");
    };
    assert_eq!(*ordinal, 1);
    assert_eq!(*checked_at, basis.known_at());
    assert_eq!(*recorded_issuance, issuance.vid);
    assert_eq!(*certificate_digest, issuance.issuance.certificate);
    assert_eq!(*certified_at, issuance.issuance.certified_at);
    assert_eq!(source_digest, basis.source_digest());
    assert_eq!(
        CloseRunRehearsalCertificate::decode(&original.certificate.canonical_bytes().unwrap())
            .unwrap(),
        original.certificate,
    );
    assert_eq!(
        f.book
            .execute_reviewed_close_task(
                "issued",
                "statement",
                closer(),
                "Unretained review",
                &original.certificate,
                None,
                Vec::new(),
            )
            .unwrap()
            .unwrap_err()
            .code,
        code::PLAN_INVALIDATED
    );
    assert_eq!(f.book.head().unwrap(), before);

    f.book
        .retain_close_run_rehearsal(CLOSER, &producer, &original.certificate)
        .unwrap()
        .unwrap();
    let retained_at = f.book.head().unwrap();
    let completed = f
        .book
        .execute_reviewed_close_task(
            "issued",
            "statement",
            closer(),
            "Authenticate the issued statement",
            &original.certificate,
            None,
            Vec::new(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(f.book.head().unwrap().0, retained_at.0 + 1);
    assert_eq!(completed.receipt.effect, issuance.control_entry);
    assert!(!completed.run.complete);
    let plan = f
        .book
        .plan_close_task_transition(
            "issued",
            "finish",
            &closer(),
            1,
            b"issued-final-close",
            "Close after issued statement",
        )
        .unwrap()
        .unwrap();
    let current = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "issued")
        .unwrap()
        .unwrap();
    f.book
        .retain_close_run_rehearsal(CLOSER, &producer, &current.certificate)
        .unwrap()
        .unwrap();
    let reopen_at = f.book.head().unwrap();
    drop(f);

    let mut book = Book::open_dir(
        &directory,
        BookKeys::for_development(seed),
        Entropy::deterministic(232),
    )
    .unwrap();
    assert_eq!(book.head().unwrap(), reopen_at);
    let status = book
        .close_run_status("issued", &closer())
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        status
            .tasks
            .iter()
            .find(|task| task.id == "statement")
            .unwrap()
            .completion
            .as_ref(),
        Some(&completed.receipt),
    );
    let finished = book
        .execute_reviewed_close_run(
            "issued",
            closer(),
            "Finish the reviewed issued-statement close",
            &current.certificate,
            Some(CloseRunTransition::Reviewed {
                task: "finish".into(),
                plan: Box::new(plan),
                approvals: Vec::new(),
            }),
        )
        .unwrap()
        .unwrap();
    assert!(finished.run.complete);
    assert!(finished.stop.is_none());
    assert_eq!(finished.completed.len(), 1);
    assert_eq!(finished.completed[0].task, "finish");
    assert_eq!(
        book.verify_statement_issuance_checkpoint(PERIOD, 1, Some(basis.known_at()), &closer())
            .unwrap()
            .unwrap(),
        basis,
    );
    assert_eq!(
        book.replay_report(&report_certificate).unwrap().unwrap(),
        ReportOutput::Statement(Box::new(statement)),
    );
    assert_eq!(
        book.replay_close_run_rehearsal(CLOSER, &producer, &original.certificate)
            .unwrap()
            .unwrap(),
        original.report,
    );
    let complete_at = book.head().unwrap();
    let retry = book
        .execute_close_run("issued", closer(), "Already complete", None)
        .unwrap()
        .unwrap();
    assert!(retry.run.complete);
    assert!(retry.completed.is_empty());
    assert_eq!(book.head().unwrap(), complete_at);
}

#[test]
fn zero_net_activity_invalidates_issued_statement_and_a_prepared_terminal_transition() {
    let mut f = Fixture::new(233);
    post(&mut f, b"statement-source", "6000", "1000", 1_000);
    issue(&mut f);
    f.start("issued", tasks(true));
    let producer = cap(CLOSER, &["read", "produce"]);
    let original = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "issued")
        .unwrap()
        .unwrap();
    f.book
        .retain_close_run_rehearsal(CLOSER, &producer, &original.certificate)
        .unwrap()
        .unwrap();
    let completed = f
        .book
        .execute_reviewed_close_task(
            "issued",
            "statement",
            closer(),
            "Original current issuance",
            &original.certificate,
            None,
            Vec::new(),
        )
        .unwrap()
        .unwrap();
    let plan = f
        .book
        .plan_close_task_transition(
            "issued",
            "finish",
            &closer(),
            1,
            b"before-zero-net",
            "Close original source",
        )
        .unwrap()
        .unwrap();
    let current = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "issued")
        .unwrap()
        .unwrap();
    f.book
        .retain_close_run_rehearsal(CLOSER, &producer, &current.certificate)
        .unwrap()
        .unwrap();
    let basis = f
        .book
        .verify_statement_issuance_checkpoint(PERIOD, 1, None, &closer())
        .unwrap()
        .unwrap();
    let net = cash_net(&f.book);
    post(&mut f, b"zero-net-new-contribution", "1000", "1000", 100);
    assert_eq!(
        cash_net(&f.book),
        net,
        "the monetary source changed even though the balance did not"
    );
    let before = f.book.head().unwrap();

    assert_eq!(
        f.book
            .verify_statement_issuance_checkpoint(PERIOD, 1, None, &closer())
            .unwrap()
            .unwrap_err()
            .code,
        code::PLAN_INVALIDATED
    );
    assert_eq!(
        f.book
            .verify_statement_issuance_checkpoint(PERIOD, 1, Some(basis.known_at()), &closer())
            .unwrap()
            .unwrap(),
        basis,
    );
    assert!(
        f.book
            .certify_close_run_rehearsal(CLOSER, &producer, "issued")
            .unwrap()
            .is_err()
    );
    assert_eq!(
        f.book
            .execute_reviewed_close_task(
                "issued",
                "finish",
                closer(),
                "Cannot close changed source",
                &current.certificate,
                Some(plan),
                Vec::new(),
            )
            .unwrap()
            .unwrap_err()
            .code,
        code::PLAN_INVALIDATED
    );
    let status = f
        .book
        .close_run_status("issued", &closer())
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!status.complete);
    assert_eq!(
        status
            .tasks
            .iter()
            .find(|task| task.id == "statement")
            .unwrap()
            .completion
            .as_ref(),
        Some(&completed.receipt),
    );
    assert!(
        status
            .tasks
            .iter()
            .find(|task| task.id == "finish")
            .unwrap()
            .completion
            .is_none()
    );
    assert_eq!(
        f.book
            .replay_close_run_rehearsal(CLOSER, &producer, &original.certificate)
            .unwrap()
            .unwrap(),
        original.report,
    );
    assert_eq!(
        f.book.head().unwrap(),
        before,
        "no refusal or historical replay may publish"
    );
}

#[test]
fn fully_completed_issuance_task_remains_rehearsable_after_later_monetary_activity() {
    let mut f = Fixture::new(234);
    post(&mut f, b"statement-source", "6000", "1000", 1_000);
    let (issuance, certificate, statement) = issue(&mut f);
    f.start("receipt", tasks(false));
    let producer = cap(CLOSER, &["read", "produce"]);
    let original = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "receipt")
        .unwrap()
        .unwrap();
    f.book
        .retain_close_run_rehearsal(CLOSER, &producer, &original.certificate)
        .unwrap()
        .unwrap();
    let completed = f
        .book
        .execute_reviewed_close_task(
            "receipt",
            "statement",
            closer(),
            "Record the original issuance prerequisite",
            &original.certificate,
            None,
            Vec::new(),
        )
        .unwrap()
        .unwrap();
    assert!(completed.run.complete);
    assert_eq!(completed.receipt.effect, issuance.control_entry);
    post(&mut f, b"later-expense", "6000", "1000", 250);
    let before = f.book.head().unwrap();
    assert_eq!(
        f.book
            .verify_statement_issuance_checkpoint(PERIOD, 1, None, &closer())
            .unwrap()
            .unwrap_err()
            .code,
        code::PLAN_INVALIDATED
    );

    let now = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "receipt")
        .unwrap()
        .unwrap();
    assert!(now.report.complete_on_trunk);
    assert_eq!(now.report.tasks.len(), 1);
    assert!(now.report.tasks.iter().all(|task| matches!(
        &task.outcome,
        CloseTaskRehearsalOutcome::AlreadyCompleted(receipt) if receipt == &completed.receipt
    )));
    assert_eq!(
        f.book
            .replay_close_run_rehearsal(CLOSER, &producer, &original.certificate)
            .unwrap()
            .unwrap(),
        original.report,
    );
    assert_eq!(
        f.book
            .replay_close_run_rehearsal(CLOSER, &producer, &now.certificate)
            .unwrap()
            .unwrap(),
        now.report,
    );
    assert_eq!(
        f.book.replay_report(&certificate).unwrap().unwrap(),
        ReportOutput::Statement(Box::new(statement)),
    );
    let retry = f
        .book
        .execute_reviewed_close_task(
            "receipt",
            "statement",
            closer(),
            "Retry authentic original completion",
            &original.certificate,
            None,
            Vec::new(),
        )
        .unwrap()
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.receipt, completed.receipt);
    assert_eq!(f.book.head().unwrap(), before);
}

#[test]
fn combined_rehearsal_rejects_an_issuance_invalidated_by_a_hypothetical_draft() {
    let mut f = Fixture::new(235);
    post(&mut f, b"statement-source", "6000", "1000", 1_000);
    let draft = f.review("unposted-expense", PLANNER, 250);
    issue(&mut f);
    f.start(
        "combined",
        vec![
            task("post", &[], draft),
            task(
                "statement",
                &["post"],
                ReviewedCloseAction::RequireCurrentStatementIssuance { ordinal: 1 },
            ),
            task(
                "finish",
                &["statement"],
                ReviewedCloseAction::PeriodTransition(PeriodTransition::Close),
            ),
        ],
    );
    f.book
        .verify_statement_issuance_checkpoint(PERIOD, 1, None, &closer())
        .unwrap()
        .unwrap();
    let before = f.book.head().unwrap();
    let balance = f.book.trial_balance(&[PERIOD.into()]).unwrap();
    let producer = cap(CLOSER, &["read", "produce"]);
    let refusal = f
        .book
        .certify_close_run_rehearsal(CLOSER, &producer, "combined")
        .unwrap()
        .unwrap_err();
    assert!(refusal.message.contains("statement"), "{refusal:?}");
    assert_eq!(f.book.head().unwrap(), before);
    assert_eq!(f.book.trial_balance(&[PERIOD.into()]).unwrap(), balance);
    let status = f
        .book
        .close_run_status("combined", &closer())
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(status.tasks.iter().all(|task| task.completion.is_none()));
    assert!(status.reviews.is_empty());
    assert_eq!(
        f.book.draft("unposted-expense").unwrap().unwrap().state,
        fa_journal::DraftState::Open
    );
}
