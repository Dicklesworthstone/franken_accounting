//! Resumable close runs use real retained reviews and native atomic receipts.

#![forbid(unsafe_code)]

use std::path::Path;

use fa::close_run::{CloseRunStop, CloseRunTransition};
use fa::{Book, BookKeys, Entropy, ReviewedCloseAction, ReviewedCloseTask};
use fa_intents::PostIntent;
use fa_journal::{AccountSpec, BookSpec, Document, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128, LegPayload, Oid,
    account_vid,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_policy::{Capability, Op, Profile};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::VId;

const ADMIN: VId = VId(201);
const PLANNER: VId = VId(202);
const OTHER_PLANNER: VId = VId(203);
const CLOSER: VId = VId(204);
const PERIOD: &str = "FY2026-P01";

fn day() -> DateDay {
    DateDay::from_ymd(2026, 1, 15).unwrap()
}

fn cap(principal: VId, ops: &[&str]) -> Capability {
    Capability::embedded(principal, ops).unwrap()
}

fn planner(principal: VId) -> Capability {
    Capability::new(principal, Profile::Agent, &[Op::Read, Op::Post], ADMIN).unwrap()
}

fn closer() -> Capability {
    cap(CLOSER, &["read", "close", "approve"])
}

fn task(id: &str, depends_on: &[&str], action: ReviewedCloseAction) -> ReviewedCloseTask {
    ReviewedCloseTask {
        id: id.into(),
        depends_on: depends_on.iter().map(|id| (*id).into()).collect(),
        action,
    }
}

struct Fixture {
    book: Book,
    usd: UnitId,
    evidence: EvidenceRef,
}

impl Fixture {
    fn new(seed: u8) -> Self {
        Self::at(seed, None)
    }

    fn at(seed: u8, directory: Option<&Path>) -> Self {
        let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
        let book_id = Id128([seed; 16]);
        let spec = BookSpec {
            book_id,
            name: "Resumable close".into(),
            base_unit: usd,
            calendar: FiscalCalendar::monthly("close-execution", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let keys = BookKeys::for_development(seed);
        let entropy = Entropy::deterministic(u64::from(seed));
        let mut book = match directory {
            Some(directory) => Book::create_dir(directory, keys, spec, entropy),
            None => Book::create_memory(keys, spec, entropy),
        }
        .unwrap();
        let account = |code: &str, kind: AccountType| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: kind.0,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        };
        let schema = cap(ADMIN, &["schema_change"]);
        book.install_chart(
            &[
                account("1000", AccountType::ASSET),
                account("6000", AccountType::EXPENSE),
            ],
            ADMIN,
            day(),
            b"chart",
            &schema,
        )
        .unwrap()
        .unwrap();
        book.create_periods(2026, ADMIN, &schema).unwrap().unwrap();
        book.transition_period(
            PERIOD,
            PeriodTransition::Open,
            ADMIN,
            1,
            b"open",
            &cap(ADMIN, &["close"]),
        )
        .unwrap()
        .unwrap();
        let document = Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: ADMIN,
            bytes: b"January invoices for reviewed close tasks".to_vec(),
        };
        book.add_document(&document).unwrap().unwrap();
        Self {
            book,
            usd,
            evidence: document.evidence_ref(1),
        }
    }

    fn review(&mut self, name: &str, principal: VId, amount: i128) -> ReviewedCloseAction {
        self.book
            .open_draft(planner(principal), name, day(), "January close task")
            .unwrap()
            .unwrap();
        let book_id = self.book.context().book_id;
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, "6000"),
                Amount::new(self.usd, amount),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, "1000"),
                Amount::new(self.usd, amount),
            ),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day(),
            document_date: None,
            description: self.book.seal_text("Reviewed January expense").unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: name.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([201; 32]),
                intent_kind: 1,
            },
            principal_ref: principal,
            session_ref: None,
            evidence: vec![self.evidence],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        self.book
            .plan_into_draft(
                planner(principal),
                name,
                PostIntent::new(proposal, Vec::new()).unwrap(),
            )
            .unwrap()
            .unwrap();
        let producer = cap(CLOSER, &["read", "produce"]);
        let review = self
            .book
            .certify_draft_diff(CLOSER, &producer, name, PERIOD)
            .unwrap()
            .unwrap();
        self.book
            .retain_draft_diff(CLOSER, &producer, &review.certificate)
            .unwrap()
            .unwrap();
        ReviewedCloseAction::DraftCertificate(*review.certificate.digest())
    }

    fn start(&mut self, name: &str, tasks: Vec<ReviewedCloseTask>) {
        self.book
            .start_close_run(closer(), name, PERIOD, tasks, "Reviewed January close")
            .unwrap()
            .unwrap();
    }
}

#[test]
fn close_run_resumes_after_directory_reopen_without_duplicate_effects() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("fa-close-execution-{}-{nonce}", std::process::id()));
    // Exclusive creation avoids reusing a prior run; retain it for diagnosis.
    std::fs::create_dir(&directory).unwrap();
    let seed = 201;
    let mut fixture = Fixture::at(seed, Some(&directory));
    let first = fixture.review("first-expense", PLANNER, 100);
    let second = fixture.review("second-expense", PLANNER, 250);
    fixture.start(
        "january",
        vec![
            task("second", &["first"], second),
            task("first", &[], first),
        ],
    );
    let first = fixture
        .book
        .execute_close_task("january", "first", closer(), "First task", None, Vec::new())
        .unwrap()
        .unwrap();
    let after_first = fixture.book.head().unwrap();
    drop(fixture);

    let mut book = Book::open_dir(
        &directory,
        BookKeys::for_development(seed),
        Entropy::deterministic(220),
    )
    .unwrap();
    let resumed = book
        .execute_close_run("january", closer(), "Resume reviewed close", None)
        .unwrap()
        .unwrap();
    assert!(resumed.run.complete);
    assert!(resumed.stop.is_none());
    assert_eq!(resumed.completed.len(), 1);
    assert_eq!(resumed.completed[0].task, "second");
    assert!(resumed.completed[0].receipt.recorded_at > after_first);
    assert_eq!(
        resumed.run.tasks[0].completion.as_ref(),
        Some(&first.receipt),
    );
    let after_resume = book.head().unwrap();
    let again = book
        .execute_close_run(
            "january",
            cap(CLOSER, &["read", "close"]),
            "Already complete",
            None,
        )
        .unwrap()
        .unwrap();
    assert!(again.completed.is_empty());
    assert_eq!(again.run, resumed.run);
    assert_eq!(book.head().unwrap(), after_resume);
    let balance = book.trial_balance_at(&[PERIOD.to_string()], None).unwrap();
    let expense = balance.rows.iter().find(|row| row.code == "6000").unwrap();
    assert_eq!((expense.debits, expense.credits), (350, 0));
    assert!(
        book.execute_close_run("january", cap(CLOSER, &["read"]), "Missing close", None)
            .unwrap()
            .is_err()
    );
    assert_eq!(book.head().unwrap(), after_resume);
}

#[test]
fn close_run_stops_at_revoked_second_planner_and_retains_first_receipt() {
    let mut fixture = Fixture::new(202);
    let first = fixture.review("allowed-expense", PLANNER, 100);
    let second = fixture.review("revoked-expense", OTHER_PLANNER, 250);
    // Both tasks are ready initially: lexical IDs, not declaration order,
    // select the authorized first task before the refused second one.
    fixture.start(
        "partial",
        vec![task("b-refused", &[], second), task("a-posted", &[], first)],
    );
    fixture
        .book
        .revoke_capability(
            cap(ADMIN, &["issue_capability"]),
            planner(OTHER_PLANNER).commitment().unwrap(),
            day(),
            b"revoke-second-planner",
            "Second planner no longer authorized",
        )
        .unwrap()
        .unwrap();
    let result = fixture
        .book
        .execute_close_run("partial", closer(), "Execute available tasks", None)
        .unwrap()
        .unwrap();
    assert_eq!(result.completed.len(), 1);
    assert_eq!(result.completed[0].task, "a-posted");
    assert!(!result.run.complete);
    let Some(CloseRunStop::Refused { task, refusal }) = &result.stop else {
        panic!("a revoked planner must stop native promotion");
    };
    assert_eq!(task, "b-refused");
    assert_eq!(refusal.code, "FA-REF-023");
    assert!(result.run.tasks[0].completion.is_some());
    assert!(result.run.tasks[1].completion.is_none());
    let head = fixture.book.head().unwrap();
    let retry = fixture
        .book
        .execute_close_run("partial", closer(), "Retry without new authority", None)
        .unwrap()
        .unwrap();
    assert!(retry.completed.is_empty());
    assert_eq!(retry.run, result.run);
    assert_eq!(retry.stop, result.stop);
    assert_eq!(fixture.book.head().unwrap(), head);
}

#[test]
fn close_run_preflights_transition_inputs_then_returns_a_fresh_unexecuted_plan() {
    let mut fixture = Fixture::new(203);
    let posting = fixture.review("before-transition", PLANNER, 125);
    fixture.start(
        "review",
        vec![
            task("expenses", &[], posting),
            task(
                "soft-close",
                &["expenses"],
                ReviewedCloseAction::PeriodTransition(PeriodTransition::SoftClose),
            ),
        ],
    );
    let before = fixture.book.head().unwrap();
    for (task, reason_code, key) in [
        ("missing", 1, b"close-review".to_vec()),
        ("expenses", 1, b"close-review".to_vec()),
        ("soft-close", 0, b"close-review".to_vec()),
        ("soft-close", 1, Vec::new()),
    ] {
        assert!(
            fixture
                .book
                .execute_close_run(
                    "review",
                    closer(),
                    "Prepare exact transition",
                    Some(CloseRunTransition::Review {
                        task: task.into(),
                        reason_code,
                        idempotency_key: key,
                    }),
                )
                .unwrap()
                .is_err()
        );
        assert_eq!(fixture.book.head().unwrap(), before);
    }
    for (task, principal) in [("expenses", CLOSER), ("soft-close", OTHER_PLANNER)] {
        let plan = fixture
            .book
            .plan_transition(
                PERIOD,
                PeriodTransition::SoftClose,
                principal,
                1,
                b"wrong-task-or-executor",
            )
            .unwrap()
            .unwrap();
        assert!(
            fixture
                .book
                .execute_close_run(
                    "review",
                    closer(),
                    "Wrong task or executor",
                    Some(CloseRunTransition::Reviewed {
                        task: task.into(),
                        plan,
                        approvals: Vec::new(),
                    }),
                )
                .unwrap()
                .is_err()
        );
        assert_eq!(fixture.book.head().unwrap(), before);
    }
    let prepared = fixture
        .book
        .execute_close_run(
            "review",
            closer(),
            "Scheduled January soft close",
            Some(CloseRunTransition::Review {
                task: "soft-close".into(),
                reason_code: 1,
                idempotency_key: b"close-review".to_vec(),
            }),
        )
        .unwrap()
        .unwrap();
    assert_eq!(prepared.completed.len(), 1);
    assert_eq!(prepared.completed[0].task, "expenses");
    let Some(CloseRunStop::TransitionReview {
        task,
        plan,
        proposal_digest,
    }) = prepared.stop
    else {
        panic!("the transition must wait for review even without an approval requirement");
    };
    assert_eq!(task, "soft-close");
    assert!(!prepared.run.complete);
    assert_eq!(plan.snapshot_seq, fixture.book.head().unwrap());
    assert_eq!(plan.snapshot_seq, prepared.completed[0].receipt.recorded_at);
    assert!(plan.snapshot_seq > before);
    assert_eq!(
        fixture.book.plan_digest(&plan).unwrap().unwrap(),
        proposal_digest,
    );
    let completed = fixture
        .book
        .execute_close_run(
            "review",
            closer(),
            "Execute separately reviewed soft close",
            Some(CloseRunTransition::Reviewed {
                task,
                plan,
                approvals: Vec::new(),
            }),
        )
        .unwrap()
        .unwrap();
    assert!(completed.run.complete);
    assert_eq!(completed.completed.len(), 1);
    assert_eq!(completed.completed[0].task, "soft-close");
}

#[test]
fn close_run_lock_requires_an_independent_approval_and_exact_retry_artifacts() {
    let mut fixture = Fixture::new(204);
    fixture
        .book
        .transition_period(
            PERIOD,
            PeriodTransition::Close,
            ADMIN,
            1,
            b"close-before-lock",
            &cap(ADMIN, &["close"]),
        )
        .unwrap()
        .unwrap();
    fixture.start(
        "lock",
        vec![task(
            "lock",
            &[],
            ReviewedCloseAction::PeriodTransition(PeriodTransition::Lock),
        )],
    );
    let no_input = fixture
        .book
        .execute_close_run("lock", closer(), "Lock when reviewed", None)
        .unwrap()
        .unwrap();
    assert!(matches!(
        no_input.stop,
        Some(CloseRunStop::TransitionRequired {
            to: PeriodTransition::Lock,
            ..
        })
    ));
    let prepared = fixture
        .book
        .execute_close_run(
            "lock",
            closer(),
            "Audit complete",
            Some(CloseRunTransition::Review {
                task: "lock".into(),
                reason_code: 3,
                idempotency_key: b"reviewed-lock".to_vec(),
            }),
        )
        .unwrap()
        .unwrap();
    let Some(CloseRunStop::TransitionReview {
        plan,
        proposal_digest,
        ..
    }) = prepared.stop
    else {
        panic!("native lock proposal");
    };
    let mut input = CloseRunTransition::Reviewed {
        task: "lock".into(),
        plan,
        approvals: Vec::new(),
    };
    let before = fixture.book.head().unwrap();
    let refused = fixture
        .book
        .execute_close_run(
            "lock",
            closer(),
            "No approval supplied",
            Some(input.clone()),
        )
        .unwrap()
        .unwrap();
    assert!(matches!(refused.stop, Some(CloseRunStop::Refused { .. })));
    assert!(refused.completed.is_empty());
    assert_eq!(fixture.book.head().unwrap(), before);
    let approval = fixture
        .book
        .approve(cap(ADMIN, &["approve"]), proposal_digest)
        .unwrap()
        .unwrap()
        .approval();
    let CloseRunTransition::Reviewed { approvals, .. } = &mut input else {
        unreachable!();
    };
    approvals.push(approval);
    let completed = fixture
        .book
        .execute_close_run(
            "lock",
            closer(),
            "Independently approved",
            Some(input.clone()),
        )
        .unwrap()
        .unwrap();
    assert!(completed.run.complete);
    assert_eq!(completed.completed.len(), 1);
    let after = fixture.book.head().unwrap();
    let retry = fixture
        .book
        .execute_close_run(
            "lock",
            closer(),
            "Exact retained retry",
            Some(input.clone()),
        )
        .unwrap()
        .unwrap();
    assert!(retry.completed.is_empty());
    assert_eq!(retry.run, completed.run);
    assert_eq!(fixture.book.head().unwrap(), after);
    let CloseRunTransition::Reviewed { plan, .. } = &mut input else {
        unreachable!();
    };
    plan.reason_code = 1;
    assert!(
        fixture
            .book
            .execute_close_run("lock", closer(), "Changed old review", Some(input))
            .unwrap()
            .is_err()
    );
    assert_eq!(fixture.book.head().unwrap(), after);
    fixture
        .book
        .revoke_capability(
            cap(ADMIN, &["issue_capability"]),
            closer().commitment().unwrap(),
            day(),
            b"revoke-complete-run-executor",
            "Completed runs still need current authority",
        )
        .unwrap()
        .unwrap();
    let refusal = fixture
        .book
        .execute_close_run("lock", closer(), "Revoked retry", None)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-023");
}
