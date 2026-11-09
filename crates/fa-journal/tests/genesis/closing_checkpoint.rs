//! A verified fiscal-year checkpoint is a native close task, not a mutable
//! green label. Terminal publication consumes the same authenticated basis.

use super::*;
use fa_journal::close_run::{
    CloseRunDefinition, CloseRunView, CloseTaskAction, CloseTaskDefinition, CloseTaskRecorded,
    CloseTaskRequest, close_run_status, create_close_run, execute_close_task,
    plan_close_task_transition,
};
use fgdb_types::CommitSeq;

fn authority() -> Capability {
    Capability::embedded(PRINCIPAL, &["read", "close"]).unwrap()
}

fn declaration(h: &Harness, name: &str) -> CloseRunDefinition {
    CloseRunDefinition {
        name: name.into(),
        period: h.march.clone(),
        tasks: vec![
            CloseTaskDefinition {
                id: "verify".into(),
                depends_on: Vec::new(),
                action: CloseTaskAction::VerifyYearEndClose { fiscal_year: 2026 },
            },
            CloseTaskDefinition {
                id: "finish".into(),
                depends_on: vec!["verify".into()],
                action: CloseTaskAction::PeriodTransition(PeriodTransition::Close),
            },
        ],
    }
}

fn start(h: &mut Harness, definition: &CloseRunDefinition) -> Result<CloseRunView, Refusal> {
    let ctx = h.ctx();
    let description = h.statement("Verified fiscal-year close graph", 131);
    h.runtime
        .block_on(create_close_run(
            &mut h.db,
            &ctx,
            &h.book,
            definition,
            &authority(),
            description,
        ))
        .unwrap()
}

fn task_request(h: &Harness) -> CloseTaskRequest {
    CloseTaskRequest {
        capability: authority(),
        description: h.statement("Execute verified close task", 132),
        transition_plan: None,
        approvals: Vec::new(),
        review: None,
    }
}

fn step(
    h: &mut Harness,
    name: &str,
    task: &str,
    request: CloseTaskRequest,
) -> Result<CloseTaskRecorded, Refusal> {
    let ctx = h.ctx();
    h.runtime
        .block_on(execute_close_task(
            &mut h.db, &ctx, &h.book, name, task, request,
        ))
        .unwrap()
}

fn status(h: &Harness, name: &str) -> CloseRunView {
    close_run_status(&h.db, &h.ctx(), &h.book, name, &authority())
        .unwrap()
        .unwrap()
        .unwrap()
}

fn plan(h: &Harness, name: &str) -> Result<TransitionPlan, Refusal> {
    plan_close_task_transition(
        &h.db,
        &h.ctx(),
        &h.book,
        name,
        "finish",
        &authority(),
        1,
        name.as_bytes(),
        h.statement("Reviewed terminal transition", 133),
    )
    .unwrap()
}

fn close(h: &mut Harness, key: &[u8]) -> EntryRef {
    let prepared = year_end_close_prepare(h);
    let proposal = year_end_close_proposal(h, &prepared, key);
    h.post(h.request(proposal, &["read", "post", "close"]))
        .unwrap()
        .entry_ref()
}

fn closed_fixture() -> Harness {
    let (mut h, _) = year_end_close_fixture();
    h.post(h.request(h.invoice(20_000, b"checkpoint-source"), &["post"]))
        .unwrap();
    close(&mut h, b"checkpoint-closing");
    h
}

#[test]
fn closing_checkpoint_requires_a_real_current_close_and_publishes_atomically() {
    let (mut h, _) = year_end_close_fixture();
    let definition = declaration(&h, "year-end");
    start(&mut h, &definition).unwrap();
    let before = h.db.frontier().unwrap();
    let request = task_request(&h);
    assert!(step(&mut h, "year-end", "verify", request).is_err());
    assert_eq!(h.db.frontier().unwrap(), before);
    assert!(
        status(&h, "year-end")
            .tasks
            .iter()
            .all(|task| task.completion.is_none())
    );

    h.post(h.request(h.invoice(20_000, b"checkpoint-source"), &["post"]))
        .unwrap();
    let closing = close(&mut h, b"checkpoint-closing");
    let before = h.db.frontier().unwrap();
    let verified = fa_journal::closing::verify_year_end_close_checkpoint(
        &h.db,
        &h.ctx(),
        &h.book,
        &authority(),
        2026,
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(verified.latest_close().entry_ref, closing);
    assert!(
        !year_end_close_verify(&h, None).residuals.is_empty(),
        "valid zero-valued cells remain useful public report rows"
    );
    let request = task_request(&h);
    let completed = step(&mut h, "year-end", "verify", request).unwrap();
    assert_eq!(completed.receipt.recorded_at, CommitSeq(before.0 + 1));
    assert_eq!(completed.receipt.effect, closing.vid);
    let (receipt, seq) = read_entry(&h.db, completed.receipt.record)
        .unwrap()
        .unwrap();
    assert_eq!(seq, completed.receipt.recorded_at);
    let Some(ControlPayload::LifecycleTransition { proof_refs, .. }) = receipt.proposal.control
    else {
        panic!("native completion lifecycle");
    };
    assert_eq!(
        proof_refs,
        vec![
            fa_model::TypedRef::Vertex(closing.vid),
            fa_model::TypedRef::Object(Oid(*verified.source_digest())),
        ]
    );
    let request = task_request(&h);
    assert_eq!(
        step(&mut h, "year-end", "verify", request).unwrap().receipt,
        completed.receipt
    );
    assert_eq!(h.db.frontier().unwrap(), completed.receipt.recorded_at);

    // Unrelated approval metadata advances history without changing the
    // fiscal-year basis. The terminal transaction still admits this receipt.
    h.approve_transition([135; 32]);
    let terminal = plan(&h, "year-end").unwrap();
    let mut request = task_request(&h);
    request.transition_plan = Some(terminal);
    let finished = step(&mut h, "year-end", "finish", request).unwrap();
    assert!(finished.run.complete);
    assert_eq!(
        PeriodRow::decode(
            &h.db
                .vertex(period_vid(&h.book.calendar.id, &h.march))
                .unwrap()
                .unwrap()
        )
        .unwrap()
        .state,
        PeriodState::Closed
    );

    // Later activity elsewhere in the same year does not erase the original
    // completed run or turn its authenticated verification receipt corrupt.
    let april = h.april.clone();
    h.transition(&april, PeriodTransition::Open, b"checkpoint-open-april")
        .unwrap();
    let mut late = h.invoice(500, b"checkpoint-later-april");
    late.effective_date = DateDay::from_ymd(2026, 4, 15).unwrap();
    h.post(h.request(late, &["post"])).unwrap();
    assert!(year_end_close_verify(&h, None).needs_reclose);
    assert!(status(&h, "year-end").complete);
    let before = h.db.frontier().unwrap();
    let request = task_request(&h);
    assert_eq!(
        step(&mut h, "year-end", "verify", request).unwrap().receipt,
        completed.receipt
    );
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn closing_checkpoint_blocks_terminal_planning_and_publication_after_offsetting_sources() {
    for offset in [false, true] {
        let mut h = closed_fixture();
        let definition = declaration(&h, "stale");
        start(&mut h, &definition).unwrap();
        let request = task_request(&h);
        let original = step(&mut h, "stale", "verify", request).unwrap();
        let late = h
            .post(h.request(h.invoice(123, b"checkpoint-late"), &["post"]))
            .unwrap();
        if offset {
            h.post(h.request(
                h.reversal_of_entry(late.entry_ref(), b"checkpoint-offset"),
                &["post"],
            ))
            .unwrap();
        }
        let verification = year_end_close_verify(&h, None);
        assert!(verification.is_green(), "the original close remains valid");
        assert_eq!(verification.needs_reclose, !offset);
        let before = h.db.frontier().unwrap();
        assert_eq!(
            plan(&h, "stale").unwrap_err().code,
            fa_journal::refusal::code::PLAN_INVALIDATED
        );

        // A newly prepared ordinary native period plan is valid on this
        // changed source, but cannot bypass the close task's atomic check.
        let native_plan = fa_journal::period::plan_transition(
            &h.db,
            &h.book,
            &h.march,
            PeriodTransition::Close,
            PRINCIPAL,
            1,
            b"ordinary-native-close",
            h.statement("Current native period plan", 134),
        )
        .unwrap()
        .unwrap();
        let mut request = task_request(&h);
        request.transition_plan = Some(native_plan);
        let refusal = step(&mut h, "stale", "finish", request).unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::PLAN_INVALIDATED);
        assert!(refusal.message.contains("stale completion"));
        assert_eq!(h.db.frontier().unwrap(), before);
        let view = status(&h, "stale");
        assert!(!view.complete);
        assert_eq!(
            view.tasks
                .iter()
                .find(|task| task.id == "verify")
                .unwrap()
                .completion
                .as_ref(),
            Some(&original.receipt)
        );
        assert!(
            view.tasks
                .iter()
                .find(|task| task.id == "finish")
                .unwrap()
                .completion
                .is_none()
        );
        assert_eq!(
            PeriodRow::decode(
                &h.db
                    .vertex(period_vid(&h.book.calendar.id, &h.march))
                    .unwrap()
                    .unwrap()
            )
            .unwrap()
            .state,
            PeriodState::Open
        );

        // Offset activity needs a fresh source check even when no delta
        // reclose is necessary; a nonzero delta first needs its native close.
        if !offset {
            let definition = declaration(&h, "unclosed");
            start(&mut h, &definition).unwrap();
            let request = task_request(&h);
            let at = h.db.frontier().unwrap();
            assert!(step(&mut h, "unclosed", "verify", request).is_err());
            assert_eq!(h.db.frontier().unwrap(), at);
            close(&mut h, b"checkpoint-delta-close");
        }
        let definition = declaration(&h, "fresh");
        start(&mut h, &definition).unwrap();
        let request = task_request(&h);
        step(&mut h, "fresh", "verify", request).unwrap();
        let mut request = task_request(&h);
        request.transition_plan = Some(plan(&h, "fresh").unwrap());
        assert!(
            step(&mut h, "fresh", "finish", request)
                .unwrap()
                .run
                .complete
        );
        assert!(
            !status(&h, "stale").complete,
            "original graph and receipt remain immutable"
        );
    }
}

#[test]
fn closing_checkpoint_rejects_wrong_year_authority_and_tampered_evidence() {
    let mut h = closed_fixture();
    let mut wrong = declaration(&h, "wrong-year");
    wrong.tasks[0].action = CloseTaskAction::VerifyYearEndClose { fiscal_year: 2027 };
    let before = h.db.frontier().unwrap();
    assert!(start(&mut h, &wrong).is_err());
    assert_eq!(h.db.frontier().unwrap(), before);
    let definition = declaration(&h, "tamper");
    start(&mut h, &definition).unwrap();
    let before = h.db.frontier().unwrap();
    let mut request = task_request(&h);
    request.capability = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    assert!(step(&mut h, "tamper", "verify", request).is_err());
    assert_eq!(h.db.frontier().unwrap(), before);
    let request = task_request(&h);
    let completed = step(&mut h, "tamper", "verify", request).unwrap();
    let row = h.db.vertex(completed.receipt.record).unwrap().unwrap();
    let payload = fa_journal::rows::prop(&row, property::FA_PAYLOAD)
        .unwrap()
        .clone();
    let mut corruption = fgdb::WriteBatch::new(relation::IN_CASE);
    corruption.set_vertex_property(
        completed.receipt.record,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(vec![0]).unwrap()),
    );
    h.write_raw(corruption);
    assert!(close_run_status(&h.db, &h.ctx(), &h.book, "tamper", &authority()).is_err());
    let mut restoration = fgdb::WriteBatch::new(relation::IN_CASE);
    restoration.set_vertex_property(
        completed.receipt.record,
        property::FA_PAYLOAD,
        Some(payload),
    );
    h.write_raw(restoration);
    assert!(close_run_status(&h.db, &h.ctx(), &h.book, "tamper", &authority()).is_err());
}
