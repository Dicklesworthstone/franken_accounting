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
