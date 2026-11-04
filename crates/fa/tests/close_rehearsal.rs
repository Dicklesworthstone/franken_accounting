//! Combined close review uses native batches and detects interactions between
//! independently reviewed drafts without publishing any hypothetical effect.

#![forbid(unsafe_code)]

use fa::{
    Book, BookKeys, CLOSE_RUN_REHEARSAL_CERTIFICATE_FORMAT, CloseRunRehearsalCertificate,
    CloseTaskRehearsalOutcome, Entropy, MAX_CLOSE_RUN_REHEARSAL_CERTIFICATE_BYTES,
    ReviewedCloseAction, ReviewedCloseTask,
};
use fa_intents::PostIntent;
use fa_journal::{
    AccountSpec, BalanceLimit, BookSpec, Document, DraftState, LimitScope, UnitPolicy,
};
use fa_model::{
    AccountType, CloseRunBody, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128,
    LegPayload, Oid, Reader, Writer, account_vid, domain_digest,
};
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_policy::{Capability, Op, Profile, possession_digest};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::{CommitSeq, VId};

const ADMIN: VId = VId(211);
const PLANNER: VId = VId(212);
const REVIEWER: VId = VId(213);
const PERIOD: &str = "FY2026-P01";
const RUN: &str = "january-close";
const FIRST: &str = "january-rent";
const SECOND: &str = "january-fees";

fn day() -> DateDay {
    DateDay::from_ymd(2026, 1, 15).unwrap()
}

fn cap(principal: VId, ops: &[&str]) -> Capability {
    Capability::embedded(principal, ops).unwrap()
}

fn planner() -> Capability {
    Capability::new(PLANNER, Profile::Agent, &[Op::Read, Op::Post], ADMIN).unwrap()
}

fn producer() -> Capability {
    cap(REVIEWER, &["read", "produce"])
}

fn executor() -> Capability {
    cap(REVIEWER, &["read", "close", "approve"])
}

struct Fixture {
    book: Book,
    usd: UnitId,
    evidence: EvidenceRef,
}

impl Fixture {
    fn new(limit: Option<i128>) -> Self {
        let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
        let book_id = Id128([211; 16]);
        let mut book = Book::create_memory(
            BookKeys::for_development(211),
            BookSpec {
                book_id,
                name: "Combined close rehearsal".into(),
                base_unit: usd,
                calendar: FiscalCalendar::monthly("combined-close", 1, 1).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(211),
        )
        .unwrap();
        let schema = cap(ADMIN, &["schema_change"]);
        let chart = [
            AccountSpec {
                code: "1000".into(),
                name: "Cash".into(),
                account_type: AccountType::ASSET.0,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: limit.map(|lower| BalanceLimit {
                    lower: Some(lower),
                    upper: None,
                    scope: LimitScope::Lifetime,
                }),
            },
            AccountSpec {
                code: "6000".into(),
                name: "Expenses".into(),
                account_type: AccountType::EXPENSE.0,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            },
        ];
        book.install_chart(&chart, ADMIN, day(), b"chart", &schema)
            .unwrap()
            .unwrap();
        book.create_periods(2026, ADMIN, &schema).unwrap().unwrap();
        book.transition_period(
            PERIOD,
            PeriodTransition::Open,
            ADMIN,
            1,
            b"open-period",
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
            bytes: b"Independent January invoice evidence for the complete close".to_vec(),
        };
        book.add_document(&document).unwrap().unwrap();
        Self {
            book,
            usd,
            evidence: document.evidence_ref(1),
        }
    }

    fn plan(&mut self, name: &str, amount: i128, key: &[u8]) {
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
            description: self.book.seal_text("Reviewed close expense").unwrap(),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([211; 32]),
                intent_kind: 1,
            },
            principal_ref: PLANNER,
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
                planner(),
                name,
                PostIntent::new(proposal, Vec::new()).unwrap(),
            )
            .unwrap()
            .unwrap();
    }

    fn review(&mut self, name: &str, amount: i128, key: &[u8]) -> [u8; 32] {
        self.book
            .open_draft(planner(), name, day(), "January close task")
            .unwrap()
            .unwrap();
        self.plan(name, amount, key);
        let review = self
            .book
            .certify_draft_diff(REVIEWER, &producer(), name, PERIOD)
            .unwrap()
            .unwrap();
        self.book
            .retain_draft_diff(REVIEWER, &producer(), &review.certificate)
            .unwrap()
            .unwrap();
        *review.certificate.digest()
    }

    fn start(&mut self, first: i128, second: i128, terminal: bool) {
        let first = self.review(FIRST, first, b"rent");
        let second = self.review(SECOND, second, b"fees");
        let mut tasks = vec![
            ReviewedCloseTask {
                id: "a-second".into(),
                depends_on: vec!["z-first".into()],
                action: ReviewedCloseAction::DraftCertificate(second),
            },
            ReviewedCloseTask {
                id: "z-first".into(),
                depends_on: Vec::new(),
                action: ReviewedCloseAction::DraftCertificate(first),
            },
        ];
        if terminal {
            tasks.push(ReviewedCloseTask {
                id: "period".into(),
                depends_on: vec!["a-second".into(), "z-first".into()],
                action: ReviewedCloseAction::PeriodTransition(PeriodTransition::SoftClose),
            });
        }
        self.book
            .start_close_run(
                executor(),
                RUN,
                PERIOD,
                tasks,
                "Review the complete January close",
            )
            .unwrap()
            .unwrap();
        // Retention and maintenance are genuine publications, but neither
        // becomes a forged source Certificate in any scratch database.
        self.book
            .advance_registers(ADMIN, &cap(ADMIN, &["read", "verify", "maintain"]), PERIOD)
            .unwrap()
            .unwrap();
    }

    fn execute(&mut self, task: &str) {
        self.book
            .execute_close_task(
                RUN,
                task,
                executor(),
                "Execute the reviewed close task",
                None,
                Vec::new(),
            )
            .unwrap()
            .unwrap();
    }

    fn later_entry(&mut self, key: &[u8], opposite: bool, pending: bool) {
        let mut proposal = self
            .book
            .draft_entries(&planner(), FIRST)
            .unwrap()
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .proposal;
        proposal.principal_ref = ADMIN;
        proposal.idempotency_key = key.to_vec();
        if opposite {
            for leg in &mut proposal.legs {
                leg.side = match leg.side {
                    Side::Debit => Side::Credit,
                    Side::Credit => Side::Debit,
                };
            }
        }
        if pending {
            proposal.class = EntryClass::PENDING;
            proposal.pending = Some(fa_model::Pending {
                timeout_ns: None,
                resolution_of: None,
                disposition: None,
            });
        }
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        self.book
            .post(fa_journal::PostRequest {
                proposal,
                approvals: Vec::new(),
                capability: cap(ADMIN, &["post"]),
                plan_certificate: None,
            })
            .unwrap()
            .unwrap();
    }
}

#[test]
fn complete_graph_rehearses_dependencies_and_cumulative_balances_without_trunk_writes() {
    let mut f = Fixture::new(None);
    f.start(1_000, 250, true);
    let head = f.book.head().unwrap();
    let first = f.book.draft(FIRST).unwrap().unwrap();
    let second = f.book.draft(SECOND).unwrap().unwrap();
    let state = f
        .book
        .periods()
        .unwrap()
        .into_iter()
        .find(|period| period.code == PERIOD)
        .unwrap()
        .state;
    let baseline = f.book.trial_balance(&[PERIOD.into()]).unwrap();
    let certified = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap();
    let report = &certified.report;
    assert_eq!(
        report
            .tasks
            .iter()
            .map(|task| task.id.as_str())
            .collect::<Vec<_>>(),
        ["z-first", "a-second", "period"]
    );
    assert_eq!(report.source_known_at, head);
    assert_eq!(report.rehearsal_known_at, CommitSeq(head.0 + 2));
    assert!(report.seq_map_digest.is_some());
    assert!(!report.complete_on_trunk);
    assert!(
        matches!(&report.tasks[0].outcome, CloseTaskRehearsalOutcome::Rehearsed { recorded_at, entries, .. } if *recorded_at == CommitSeq(head.0 + 1) && entries.len() == 1)
    );
    assert!(
        matches!(&report.tasks[1].outcome, CloseTaskRehearsalOutcome::Rehearsed { recorded_at, entries, .. } if *recorded_at == CommitSeq(head.0 + 2) && entries.len() == 1)
    );
    assert!(matches!(
        report.tasks[2].outcome,
        CloseTaskRehearsalOutcome::AwaitingNativeTransitionReview { to: 2 }
    ));
    assert_eq!(
        report
            .rows
            .iter()
            .map(|row| (row.code.as_str(), row.delta, row.pending_delta))
            .collect::<Vec<_>>(),
        [("1000", -1_250, 0), ("6000", 1_250, 0)]
    );
    assert_eq!(f.book.head().unwrap(), head);
    assert_eq!(f.book.draft(FIRST).unwrap().unwrap(), first);
    assert_eq!(f.book.draft(SECOND).unwrap().unwrap(), second);
    assert_eq!(
        f.book
            .periods()
            .unwrap()
            .into_iter()
            .find(|period| period.code == PERIOD)
            .unwrap()
            .state,
        state
    );
    assert_eq!(f.book.trial_balance(&[PERIOD.into()]).unwrap(), baseline);
    let bytes = certified.certificate.canonical_bytes().unwrap();
    let decoded = CloseRunRehearsalCertificate::decode(&bytes).unwrap();
    assert_eq!(decoded, certified.certificate);
    assert_eq!(decoded.output(), report.canonical_bytes().unwrap());
    assert_eq!(
        f.book
            .replay_close_run_rehearsal(REVIEWER, &cap(REVIEWER, &["read"]), &decoded)
            .unwrap()
            .unwrap(),
        *report
    );
    assert_eq!(f.book.head().unwrap(), head);
}

#[test]
fn independent_reviews_that_overspend_together_refuse_without_partial_effects() {
    let mut f = Fixture::new(Some(-1_000));
    // Each original review can lawfully spend 600; the combined close cannot
    // spend 1,200. Only a sequential native rehearsal detects that interaction.
    f.start(600, 600, true);
    let head = f.book.head().unwrap();
    let before = f.book.trial_balance(&[PERIOD.into()]).unwrap();
    let refusal = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap_err();
    assert_eq!(
        refusal.code,
        fa_journal::refusal::code::AVAILABILITY_LOWER,
        "{refusal}"
    );
    assert!(refusal.message.contains("a-second"), "{refusal}");
    assert_eq!(f.book.head().unwrap(), head);
    assert_eq!(f.book.trial_balance(&[PERIOD.into()]).unwrap(), before);
    for draft in [FIRST, SECOND] {
        assert_eq!(
            f.book.draft(draft).unwrap().unwrap().state,
            DraftState::Open
        );
    }
    let run = f
        .book
        .close_run_status(RUN, &cap(REVIEWER, &["read"]))
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!run.complete);
    assert!(run.tasks.iter().all(|task| task.completion.is_none()));
}

#[test]
fn close_execution_refuses_combined_overspend_before_any_task_publishes() {
    let mut f = Fixture::new(Some(-1_000));
    f.start(600, 600, true);
    let head = f.book.head().unwrap();
    let baseline = f.book.trial_balance(&[PERIOD.into()]).unwrap();
    let first = f.book.draft(FIRST).unwrap().unwrap();
    let second = f.book.draft(SECOND).unwrap().unwrap();
    for _ in 0..2 {
        let execution = f
            .book
            .execute_close_run(RUN, executor(), "Execute the complete close", None)
            .unwrap()
            .unwrap();
        assert!(execution.completed.is_empty());
        assert!(!execution.run.complete);
        assert!(
            execution
                .run
                .tasks
                .iter()
                .all(|task| task.completion.is_none())
        );
        let Some(fa::CloseRunStop::Refused { task, refusal }) = execution.stop else {
            panic!("the combined limit violation must stop the entire invocation");
        };
        assert_eq!(task, "a-second");
        assert_eq!(refusal.code, fa_journal::refusal::code::AVAILABILITY_LOWER);
        assert_eq!(f.book.head().unwrap(), head);
        assert_eq!(f.book.trial_balance(&[PERIOD.into()]).unwrap(), baseline);
        assert_eq!(f.book.draft(FIRST).unwrap().unwrap(), first);
        assert_eq!(f.book.draft(SECOND).unwrap().unwrap(), second);
    }
}

#[test]
fn close_execution_rehearses_remaining_tasks_at_the_exact_limit_without_reapplying_receipts() {
    let mut f = Fixture::new(Some(-1_000));
    f.start(600, 400, false);
    f.execute("z-first");
    let before = f.book.head().unwrap();
    let execution = f
        .book
        .execute_close_run(RUN, executor(), "Resume the close at its exact limit", None)
        .unwrap()
        .unwrap();
    assert!(execution.run.complete);
    assert!(execution.stop.is_none());
    assert_eq!(execution.completed.len(), 1);
    assert_eq!(execution.completed[0].task, "a-second");
    assert_eq!(f.book.head().unwrap(), CommitSeq(before.0 + 1));
    let balance = f.book.trial_balance(&[PERIOD.into()]).unwrap();
    let cash = balance.rows.iter().find(|row| row.code == "1000").unwrap();
    assert_eq!((cash.debits, cash.credits), (0, 1_000));
    assert_eq!((cash.debits_pending, cash.credits_pending), (0, 0));
    let report = f
        .book
        .close_run_rehearsal(REVIEWER, &cap(REVIEWER, &["read"]), RUN)
        .unwrap()
        .unwrap();
    assert!(report.complete_on_trunk);
    assert!(report.rows.is_empty());
    let retry = f
        .book
        .execute_close_run(RUN, executor(), "Retry the completed close", None)
        .unwrap()
        .unwrap();
    assert_eq!(retry.run, execution.run);
    assert!(retry.completed.is_empty());
    assert_eq!(f.book.head().unwrap(), CommitSeq(before.0 + 1));
}

#[test]
fn partial_run_rehearses_only_remaining_work_and_replays_after_real_completion() {
    let mut f = Fixture::new(None);
    f.start(1_000, 250, false);
    f.execute("z-first");
    let certified = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap();
    let report = &certified.report;
    assert!(matches!(
        report.tasks[0].outcome,
        CloseTaskRehearsalOutcome::AlreadyCompleted(_)
    ));
    assert!(matches!(
        report.tasks[1].outcome,
        CloseTaskRehearsalOutcome::Rehearsed { .. }
    ));
    assert_eq!(
        report.rehearsal_known_at,
        CommitSeq(report.source_known_at.0 + 1)
    );
    let cash = report.rows.iter().find(|row| row.code == "1000").unwrap();
    assert_eq!(
        (cash.trunk_credits, cash.draft_credits, cash.delta),
        (1_000, 1_250, -250)
    );
    assert!(!report.complete_on_trunk);
    let invented_receipt = rehashed(&certified.certificate, "receipt");
    let refusal = f
        .book
        .replay_close_run_rehearsal(REVIEWER, &cap(REVIEWER, &["read"]), &invented_receipt)
        .unwrap()
        .unwrap_err();
    assert_eq!(
        refusal.code,
        fa::certificate::code::CERTIFICATE_INVALID,
        "{refusal}"
    );
    f.execute("a-second");
    let executed_at = f.book.head().unwrap();
    assert_eq!(
        f.book
            .replay_close_run_rehearsal(REVIEWER, &cap(REVIEWER, &["read"]), &certified.certificate)
            .unwrap()
            .unwrap(),
        *report
    );
    assert_eq!(f.book.head().unwrap(), executed_at);
    let complete = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap();
    assert!(complete.report.complete_on_trunk);
    assert!(complete.report.rows.is_empty());
    assert!(complete.report.seq_map_digest.is_none());
    assert_eq!(
        complete.report.source_known_at,
        complete.report.rehearsal_known_at
    );
    assert!(
        complete
            .report
            .tasks
            .iter()
            .all(|task| matches!(task.outcome, CloseTaskRehearsalOutcome::AlreadyCompleted(_)))
    );
}

#[test]
fn already_completed_dependencies_are_satisfied_before_selecting_the_next_task() {
    let mut f = Fixture::new(Some(-1_000));
    let done = f.review(FIRST, 100, b"done");
    let next = f.review(SECOND, 400, b"next");
    let independent = f.review("january-other", 200, b"independent");
    f.book
        .start_close_run(
            executor(),
            RUN,
            PERIOD,
            vec![
                ReviewedCloseTask {
                    id: "a-next".into(),
                    depends_on: vec!["z-done".into()],
                    action: ReviewedCloseAction::DraftCertificate(next),
                },
                ReviewedCloseTask {
                    id: "b-independent".into(),
                    depends_on: Vec::new(),
                    action: ReviewedCloseAction::DraftCertificate(independent),
                },
                ReviewedCloseTask {
                    id: "z-done".into(),
                    depends_on: Vec::new(),
                    action: ReviewedCloseAction::DraftCertificate(done),
                },
            ],
            "Continue a partially completed native close",
        )
        .unwrap()
        .unwrap();
    f.execute("z-done");
    let report = f
        .book
        .close_run_rehearsal(REVIEWER, &cap(REVIEWER, &["read"]), RUN)
        .unwrap()
        .unwrap();
    assert_eq!(
        report
            .tasks
            .iter()
            .map(|task| task.id.as_str())
            .collect::<Vec<_>>(),
        ["z-done", "a-next", "b-independent"]
    );
    assert!(matches!(
        report.tasks[0].outcome,
        CloseTaskRehearsalOutcome::AlreadyCompleted(_)
    ));
    assert!(
        matches!(&report.tasks[1].outcome, CloseTaskRehearsalOutcome::Rehearsed { recorded_at, .. } if *recorded_at == CommitSeq(report.source_known_at.0 + 1))
    );
    assert!(
        matches!(&report.tasks[2].outcome, CloseTaskRehearsalOutcome::Rehearsed { recorded_at, .. } if *recorded_at == CommitSeq(report.source_known_at.0 + 2))
    );
    let cash = report.rows.iter().find(|row| row.code == "1000").unwrap();
    assert_eq!(
        (cash.trunk_credits, cash.draft_credits, cash.delta),
        (100, 700, -600)
    );
    assert_eq!(f.book.head().unwrap(), report.source_known_at);
}

#[test]
fn changed_draft_membership_refuses_current_rehearsal_but_preserves_original_replay() {
    let mut f = Fixture::new(None);
    f.start(1_000, 250, false);
    let certified = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap();
    f.plan(FIRST, 70, b"later-unreviewed-member");
    let head = f.book.head().unwrap();
    let refusal = f
        .book
        .close_run_rehearsal(REVIEWER, &cap(REVIEWER, &["read"]), RUN)
        .unwrap()
        .unwrap_err();
    assert!(
        refusal.message.contains("membership") || refusal.message.contains("reviewed effects"),
        "{refusal}"
    );
    assert_eq!(
        f.book
            .replay_close_run_rehearsal(REVIEWER, &cap(REVIEWER, &["read"]), &certified.certificate)
            .unwrap()
            .unwrap(),
        certified.report
    );
    assert_eq!(f.book.head().unwrap(), head);
}

/// Alter a valid container and recompute its public digest. A hash check alone
/// cannot detect this; source graph validation and full replay must refuse it.
fn rehashed(
    certificate: &CloseRunRehearsalCertificate,
    change: &str,
) -> CloseRunRehearsalCertificate {
    let bytes = certificate.canonical_bytes().unwrap();
    let mut r = Reader::new(&bytes);
    assert_eq!(
        r.bytes(64, "format").unwrap(),
        CLOSE_RUN_REHEARSAL_CERTIFICATE_FORMAT
    );
    let trunk = r
        .bytes(MAX_CLOSE_RUN_REHEARSAL_CERTIFICATE_BYTES, "trunk")
        .unwrap();
    let mut body = CloseRunBody::decode(
        r.bytes(fa_model::limits::MAX_CLOSE_RUN_BYTES, "graph")
            .unwrap(),
    )
    .unwrap();
    let opened_at = r.u64("opened at").unwrap();
    let reviews = r
        .list(fa_model::limits::MAX_CLOSE_RUN_TASKS, "reviews", |r| {
            r.bytes(MAX_CLOSE_RUN_REHEARSAL_CERTIFICATE_BYTES, "review")
        })
        .unwrap();
    let producer = r.u128("producer").unwrap();
    let authority: [u8; 32] = r.fixed("capability").unwrap();
    let mut output = r
        .bytes(MAX_CLOSE_RUN_REHEARSAL_CERTIFICATE_BYTES, "output")
        .unwrap()
        .to_vec();
    let _: [u8; 32] = r.fixed("digest").unwrap();
    r.finish().unwrap();
    match change {
        "output" => *output.last_mut().unwrap() ^= 1,
        "graph" => body
            .tasks
            .iter_mut()
            .find(|task| task.id == "a-second")
            .unwrap()
            .depends_on
            .clear(),
        "map" => {
            let mut q = Reader::new(&output);
            q.str(64, "format").unwrap();
            q.str(128, "name").unwrap();
            q.u128("run").unwrap();
            let _: [u8; 32] = q.fixed("graph").unwrap();
            q.str(128, "period").unwrap();
            q.u64("opened at").unwrap();
            q.u64("source at").unwrap();
            assert_eq!(q.u8("has map").unwrap(), 1);
            let offset = q.offset();
            output[offset] ^= 1;
        }
        "receipt" => {
            let mut q = Reader::new(&output);
            q.str(64, "format").unwrap();
            q.str(128, "name").unwrap();
            q.u128("run").unwrap();
            let _: [u8; 32] = q.fixed("graph").unwrap();
            q.str(128, "period").unwrap();
            q.u64("opened at").unwrap();
            q.u64("source at").unwrap();
            let _: Option<[u8; 32]> = q.opt("map", |q| q.fixed("map")).unwrap();
            q.u64("scratch head").unwrap();
            q.bool("complete").unwrap();
            assert!(q.u32("tasks").unwrap() > 0);
            q.str(128, "task").unwrap();
            assert_eq!(q.u8("outcome").unwrap(), 0);
            let offset = q.offset();
            output[offset] ^= 1;
        }
        _ => unreachable!(),
    }
    let mut w = Writer::new();
    w.bytes(CLOSE_RUN_REHEARSAL_CERTIFICATE_FORMAT)
        .bytes(trunk)
        .bytes(&body.canonical_bytes().unwrap())
        .u64(opened_at)
        .list(&reviews, |w, review| {
            w.bytes(review);
        })
        .u128(producer)
        .fixed(&authority)
        .bytes(&output);
    let mut changed = w.finish().unwrap();
    let digest = domain_digest(b"fa:close-run-rehearsal-certificate-digest:v1", &[&changed]);
    changed.extend_from_slice(&digest);
    CloseRunRehearsalCertificate::decode(&changed).unwrap()
}

#[test]
fn current_holder_bound_reader_issued_after_the_source_can_replay_every_scratch_task() {
    let mut f = Fixture::new(None);
    f.start(1_000, 250, false);
    let certified = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap();
    let auditor = VId(214);
    let reader = Capability::new(auditor, Profile::Human, &[Op::Read], ADMIN)
        .unwrap()
        .holder_bound(possession_digest(&[214; 32]));
    f.book
        .issue_capability(
            cap(ADMIN, &["read", "issue_capability"]),
            reader.clone(),
            day(),
            b"new-reviewer",
            "A current reader admitted after the historical close prefix",
        )
        .unwrap()
        .unwrap();
    let head = f.book.head().unwrap();
    assert!(head > certified.certificate.known_at());
    assert_eq!(
        f.book
            .replay_close_run_rehearsal(auditor, &reader, &certified.certificate)
            .unwrap()
            .unwrap(),
        certified.report
    );
    assert_eq!(f.book.head().unwrap(), head);
    f.book
        .revoke_capability(
            cap(ADMIN, &["issue_capability"]),
            reader.commitment().unwrap(),
            day(),
            b"revoke-new-reviewer",
            "The historical report cannot resurrect current authority",
        )
        .unwrap()
        .unwrap();
    let revoked_at = f.book.head().unwrap();
    let refusal = f
        .book
        .replay_close_run_rehearsal(auditor, &reader, &certified.certificate)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-023", "{refusal}");
    assert_eq!(f.book.head().unwrap(), revoked_at);
}

#[test]
fn rehashed_graph_source_map_and_amount_substitutions_fail_historical_replay() {
    let mut f = Fixture::new(None);
    f.start(1_000, 250, true);
    let certified = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap();
    let head = f.book.head().unwrap();
    for change in ["graph", "map", "output"] {
        let forged = rehashed(&certified.certificate, change);
        assert_ne!(forged.digest(), certified.certificate.digest());
        let refusal = f
            .book
            .replay_close_run_rehearsal(REVIEWER, &cap(REVIEWER, &["read"]), &forged)
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refusal.code,
            fa::certificate::code::CERTIFICATE_INVALID,
            "{change}: {refusal}"
        );
        assert_eq!(f.book.head().unwrap(), head, "{change}");
    }
}

#[test]
fn terminal_only_review_preserves_pending_transition_and_never_claims_completion() {
    let mut f = Fixture::new(None);
    f.book
        .start_close_run(
            executor(),
            RUN,
            PERIOD,
            vec![ReviewedCloseTask {
                id: "period".into(),
                depends_on: Vec::new(),
                action: ReviewedCloseAction::PeriodTransition(PeriodTransition::SoftClose),
            }],
            "The only remaining work requires its native transition review",
        )
        .unwrap()
        .unwrap();
    let certified = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap();
    assert!(!certified.report.complete_on_trunk);
    assert!(certified.report.rows.is_empty());
    assert!(certified.report.seq_map_digest.is_none());
    assert_eq!(
        certified.report.rehearsal_known_at,
        certified.report.source_known_at
    );
    assert!(matches!(
        certified.report.tasks[0].outcome,
        CloseTaskRehearsalOutcome::AwaitingNativeTransitionReview { to: 2 }
    ));
    let plan = f
        .book
        .plan_close_task_transition(
            RUN,
            "period",
            &executor(),
            1,
            b"soft-close",
            "Review the native final transition",
        )
        .unwrap()
        .unwrap();
    f.book
        .execute_close_task(
            RUN,
            "period",
            executor(),
            "Execute the final native transition",
            Some(plan),
            Vec::new(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        f.book
            .replay_close_run_rehearsal(REVIEWER, &cap(REVIEWER, &["read"]), &certified.certificate)
            .unwrap()
            .unwrap(),
        certified.report
    );
    assert!(
        f.book
            .close_run_rehearsal(REVIEWER, &cap(REVIEWER, &["read"]), RUN)
            .unwrap()
            .unwrap()
            .complete_on_trunk
    );
}

#[test]
fn certificate_provenance_does_not_replace_current_read_or_produce_authority() {
    let mut f = Fixture::new(None);
    f.start(1_000, 250, false);
    let certified = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap();
    let refusal = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &cap(REVIEWER, &["read"]), RUN)
        .unwrap()
        .unwrap_err();
    assert!(refusal.message.contains("produce"), "{refusal}");
    let reader = cap(REVIEWER, &["read"]);
    f.book
        .revoke_capability(
            cap(ADMIN, &["issue_capability"]),
            reader.commitment().unwrap(),
            day(),
            b"revoke-close-reader",
            "Revoke current close reader",
        )
        .unwrap()
        .unwrap();
    let head = f.book.head().unwrap();
    let refusal = f
        .book
        .replay_close_run_rehearsal(REVIEWER, &reader, &certified.certificate)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-023", "{refusal}");
    assert_eq!(f.book.head().unwrap(), head);
}

#[test]
fn malformed_or_unknown_close_rehearsal_containers_are_refused() {
    assert!(CloseRunRehearsalCertificate::decode(&[]).is_err());
    let mut w = Writer::new();
    w.bytes(b"fa:close-run-rehearsal-certificate:v2");
    assert!(CloseRunRehearsalCertificate::decode(&w.finish().unwrap()).is_err());
    let mut w = Writer::new();
    w.bytes(CLOSE_RUN_REHEARSAL_CERTIFICATE_FORMAT)
        .bytes(b"not a native certificate");
    assert!(CloseRunRehearsalCertificate::decode(&w.finish().unwrap()).is_err());
}

#[test]
fn reviewed_close_execution_accepts_retention_and_an_independent_certificate_producer() {
    let mut f = Fixture::new(None);
    f.start(1_000, 250, true);
    let reviewer = cap(ADMIN, &["read", "produce"]);
    let certified = f
        .book
        .certify_close_run_rehearsal(ADMIN, &reviewer, RUN)
        .unwrap()
        .unwrap();
    assert_ne!(certified.certificate.producer(), executor().holder());
    f.book
        .retain_close_run_rehearsal(ADMIN, &reviewer, &certified.certificate)
        .unwrap()
        .unwrap();
    let retained_at = f.book.head().unwrap();
    assert!(retained_at > certified.certificate.known_at());
    let execution = f
        .book
        .execute_reviewed_close_run(
            RUN,
            executor(),
            "Execute the selected complete review",
            &certified.certificate,
            None,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        execution
            .completed
            .iter()
            .map(|task| task.task.as_str())
            .collect::<Vec<_>>(),
        ["z-first", "a-second"]
    );
    assert!(matches!(
        execution.stop,
        Some(fa::CloseRunStop::TransitionRequired { task, .. }) if task == "period"
    ));
    assert!(!execution.run.complete);
    assert_eq!(f.book.head().unwrap(), CommitSeq(retained_at.0 + 2));
    let balance = f.book.trial_balance(&[PERIOD.into()]).unwrap();
    let cash = balance.rows.iter().find(|row| row.code == "1000").unwrap();
    assert_eq!((cash.debits, cash.credits), (0, 1_250));
    assert_eq!((cash.debits_pending, cash.credits_pending), (0, 0));
}

#[test]
fn reviewed_close_execution_rejects_offsetting_posted_and_pending_baseline_changes() {
    for pending in [false, true] {
        let mut f = Fixture::new(None);
        f.start(1_000, 250, false);
        let certified = f
            .book
            .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
            .unwrap()
            .unwrap();
        f.later_entry(b"later-outflow", false, pending);
        f.later_entry(b"later-inflow", true, pending);
        let head = f.book.head().unwrap();
        let baseline = f.book.trial_balance(&[PERIOD.into()]).unwrap();
        let cash = baseline.rows.iter().find(|row| row.code == "1000").unwrap();
        assert_eq!(cash.debits, cash.credits, "posted net is unchanged");
        assert_eq!(
            cash.debits_pending, cash.credits_pending,
            "pending net is unchanged"
        );
        let first = f.book.draft(FIRST).unwrap().unwrap();
        let second = f.book.draft(SECOND).unwrap().unwrap();
        let refusal = f
            .book
            .execute_reviewed_close_run(
                RUN,
                executor(),
                "An old net balance is insufficient",
                &certified.certificate,
                None,
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            (
                fa_journal::refusal::code::PLAN_INVALIDATED,
                fa_journal::exit::CONFLICT,
            ),
            "{refusal}"
        );
        assert!(refusal.fix.contains("close dry-run"));
        assert_eq!(f.book.head().unwrap(), head);
        assert_eq!(f.book.trial_balance(&[PERIOD.into()]).unwrap(), baseline);
        assert_eq!(f.book.draft(FIRST).unwrap().unwrap(), first);
        assert_eq!(f.book.draft(SECOND).unwrap().unwrap(), second);
        assert_eq!(
            f.book
                .replay_close_run_rehearsal(REVIEWER, &producer(), &certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report,
            "a stale execution review remains valid historical evidence"
        );
        let current = f
            .book
            .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
            .unwrap()
            .unwrap();
        let execution = f
            .book
            .execute_reviewed_close_run(
                RUN,
                executor(),
                "Execute the newly reviewed baseline",
                &current.certificate,
                None,
            )
            .unwrap()
            .unwrap();
        assert!(execution.run.complete);
        assert_eq!(execution.completed.len(), 2);
    }
}

#[test]
fn reviewed_close_execution_requires_new_reviews_after_partial_and_complete_progress() {
    let mut f = Fixture::new(Some(-1_000));
    f.start(600, 400, false);
    let original = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap();
    f.execute("z-first");
    let partial_at = f.book.head().unwrap();
    let refusal = f
        .book
        .execute_reviewed_close_run(
            RUN,
            executor(),
            "The original review predates a completion",
            &original.certificate,
            None,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert_eq!(f.book.head().unwrap(), partial_at);

    let partial = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap();
    assert!(matches!(
        partial.report.tasks[0].outcome,
        CloseTaskRehearsalOutcome::AlreadyCompleted(_)
    ));
    let execution = f
        .book
        .execute_reviewed_close_run(
            RUN,
            executor(),
            "Resume the reviewed remaining work",
            &partial.certificate,
            None,
        )
        .unwrap()
        .unwrap();
    assert!(execution.run.complete);
    assert_eq!(execution.completed.len(), 1);
    assert_eq!(execution.completed[0].task, "a-second");
    assert_eq!(f.book.head().unwrap(), CommitSeq(partial_at.0 + 1));
    let complete_at = f.book.head().unwrap();
    let refusal = f
        .book
        .execute_reviewed_close_run(
            RUN,
            executor(),
            "Completion cannot bypass the selected review",
            &partial.certificate,
            None,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert_eq!(f.book.head().unwrap(), complete_at);

    let complete = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap();
    assert!(complete.report.complete_on_trunk);
    let retry = f
        .book
        .execute_reviewed_close_run(
            RUN,
            executor(),
            "A current completed review returns the durable result",
            &complete.certificate,
            None,
        )
        .unwrap()
        .unwrap();
    assert_eq!(retry.run, execution.run);
    assert!(retry.completed.is_empty());
    assert!(retry.stop.is_none());
    assert_eq!(f.book.head().unwrap(), complete_at);
}

#[test]
fn reviewed_close_execution_preserves_native_approvals_and_receipt_only_freshness() {
    let mut f = Fixture::new(None);
    f.book
        .transition_period(
            PERIOD,
            PeriodTransition::Close,
            ADMIN,
            1,
            b"close-before-reviewed-lock",
            &cap(ADMIN, &["close"]),
        )
        .unwrap()
        .unwrap();
    f.book
        .start_close_run(
            executor(),
            RUN,
            PERIOD,
            vec![ReviewedCloseTask {
                id: "period".into(),
                depends_on: Vec::new(),
                action: ReviewedCloseAction::PeriodTransition(PeriodTransition::Lock),
            }],
            "Review the terminal lock",
        )
        .unwrap()
        .unwrap();
    let certified = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap();
    let plan = f
        .book
        .plan_close_task_transition(
            RUN,
            "period",
            &executor(),
            3,
            b"reviewed-lock",
            "Audit complete",
        )
        .unwrap()
        .unwrap();
    let digest = f.book.plan_digest(&plan).unwrap().unwrap();
    // Retention after native planning must not invalidate either review.
    f.book
        .retain_close_run_rehearsal(REVIEWER, &producer(), &certified.certificate)
        .unwrap()
        .unwrap();
    let mut input = fa::CloseRunTransition::Reviewed {
        task: "period".into(),
        plan: Box::new(plan),
        approvals: Vec::new(),
    };
    let before = f.book.head().unwrap();
    let missing = f
        .book
        .execute_reviewed_close_run(
            RUN,
            executor(),
            "A combined certificate supplies no approval",
            &certified.certificate,
            Some(input.clone()),
        )
        .unwrap()
        .unwrap();
    assert!(matches!(
        missing.stop,
        Some(fa::CloseRunStop::Refused { .. })
    ));
    assert!(missing.completed.is_empty());
    assert_eq!(f.book.head().unwrap(), before);
    let approval = f
        .book
        .approve(cap(ADMIN, &["approve"]), digest)
        .unwrap()
        .unwrap()
        .approval();
    let fa::CloseRunTransition::Reviewed { approvals, .. } = &mut input else {
        unreachable!();
    };
    approvals.push(approval);
    let execution = f
        .book
        .execute_reviewed_close_run(
            RUN,
            executor(),
            "The same monetary review survives an independent approval",
            &certified.certificate,
            Some(input.clone()),
        )
        .unwrap()
        .unwrap();
    assert!(execution.run.complete);
    assert_eq!(execution.completed.len(), 1);
    let completed_at = f.book.head().unwrap();
    assert!(matches!(
        f.book
            .certificate_status(certified.certificate.trunk())
            .unwrap()
            .unwrap(),
        fa::CertificateStatus::Current { .. }
    ));
    let refusal = f
        .book
        .execute_reviewed_close_run(
            RUN,
            executor(),
            "An unchanged trial balance cannot hide a changed receipt",
            &certified.certificate,
            Some(input.clone()),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
    assert_eq!(f.book.head().unwrap(), completed_at);
    let current = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap();
    let retry = f
        .book
        .execute_reviewed_close_run(
            RUN,
            executor(),
            "Authenticate the exact original transition retry",
            &current.certificate,
            Some(input.clone()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(retry.run, execution.run);
    assert!(retry.completed.is_empty());
    assert_eq!(f.book.head().unwrap(), completed_at);
    let fa::CloseRunTransition::Reviewed { plan, .. } = &mut input else {
        unreachable!();
    };
    plan.reason_code = 1;
    assert!(
        f.book
            .execute_reviewed_close_run(
                RUN,
                executor(),
                "A completed review cannot ignore a changed native plan",
                &current.certificate,
                Some(input),
            )
            .unwrap()
            .is_err()
    );
    assert_eq!(f.book.head().unwrap(), completed_at);
}

#[test]
fn reviewed_close_execution_replays_every_certificate_binding_before_publication() {
    let mut f = Fixture::new(None);
    f.start(1_000, 250, true);
    let certified = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap();
    let head = f.book.head().unwrap();
    for change in ["graph", "map", "output"] {
        let forged = rehashed(&certified.certificate, change);
        let refusal = f
            .book
            .execute_reviewed_close_run(
                RUN,
                executor(),
                "A valid container digest is not a reviewed close",
                &forged,
                None,
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa::certificate::code::CERTIFICATE_INVALID);
        assert_eq!(f.book.head().unwrap(), head);
    }
    let forged = rehashed(&certified.certificate, "output");
    let denied = f
        .book
        .execute_reviewed_close_run(
            "unobserved-run",
            cap(REVIEWER, &["read"]),
            "Check authority before observing run or certificate",
            &forged,
            None,
        )
        .unwrap()
        .unwrap_err();
    assert!(denied.message.contains("close"), "{denied}");
    assert_eq!(f.book.head().unwrap(), head);

    f.book
        .start_close_run(
            executor(),
            "different-close",
            PERIOD,
            vec![ReviewedCloseTask {
                id: "period".into(),
                depends_on: Vec::new(),
                action: ReviewedCloseAction::PeriodTransition(PeriodTransition::SoftClose),
            }],
            "A distinct graph cannot consume the first graph's certificate",
        )
        .unwrap()
        .unwrap();
    let before_wrong_run = f.book.head().unwrap();
    let refusal = f
        .book
        .execute_reviewed_close_run(
            "different-close",
            executor(),
            "The explicit run must match the selected review",
            &certified.certificate,
            None,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::STRUCTURE);
    assert_eq!(f.book.head().unwrap(), before_wrong_run);
}

#[test]
fn reviewed_close_execution_rechecks_current_draft_membership_and_executor_authority() {
    let mut f = Fixture::new(None);
    f.start(1_000, 250, false);
    let certified = f
        .book
        .certify_close_run_rehearsal(REVIEWER, &producer(), RUN)
        .unwrap()
        .unwrap();
    f.plan(SECOND, 25, b"added-after-combined-review");
    let changed_at = f.book.head().unwrap();
    assert!(
        f.book
            .execute_reviewed_close_run(
                RUN,
                executor(),
                "A historical replay cannot admit changed current membership",
                &certified.certificate,
                None,
            )
            .unwrap()
            .is_err()
    );
    assert_eq!(f.book.head().unwrap(), changed_at);
    assert!(
        f.book
            .close_run_status(RUN, &executor())
            .unwrap()
            .unwrap()
            .unwrap()
            .tasks
            .iter()
            .all(|task| task.completion.is_none())
    );
    f.book
        .revoke_capability(
            cap(ADMIN, &["issue_capability"]),
            executor().commitment().unwrap(),
            day(),
            b"revoke-reviewed-close-executor",
            "The selected certificate cannot restore live authority",
        )
        .unwrap()
        .unwrap();
    let revoked_at = f.book.head().unwrap();
    let refusal = f
        .book
        .execute_reviewed_close_run(
            RUN,
            executor(),
            "Revocation precedes historical and current review checks",
            &certified.certificate,
            None,
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-023");
    assert_eq!(f.book.head().unwrap(), revoked_at);
}
