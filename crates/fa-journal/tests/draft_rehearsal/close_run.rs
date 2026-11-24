//! The kernel's native atomic boundary; facade/CLI tests separately replay
//! real retained DraftDiff certificates before invoking this lower-level API.

use super::*;

#[path = "close_run/issued_statement.rs"]
mod issued_statement;

fn closer() -> Capability {
    Capability::embedded(APPROVER, &["read", "close", "approve"]).unwrap()
}

fn description(h: &Harness) -> Erasable<String> {
    Erasable::seal(
        &"reviewed close".to_string(),
        None,
        &h.book.seal_key,
        [201; 32],
        [202; 24],
    )
}

fn request(h: &Harness, capability: Capability) -> CloseTaskRequest {
    CloseTaskRequest {
        capability,
        description: description(h),
        transition_plan: None,
        approvals: Vec::new(),
        review: None,
    }
}

fn review(h: &mut Harness, name: &str, amount: i128, ordinal: u8) -> CloseTaskAction {
    review_at(h, name, amount, ordinal, None)
}

fn review_at(
    h: &mut Harness,
    name: &str,
    amount: i128,
    ordinal: u8,
    effective_date: Option<DateDay>,
) -> CloseTaskAction {
    h.open(name, agent());
    let mut proposal = h.proposal(amount, &[ordinal], EntryClass::ORIGINAL, AGENT);
    if let Some(day) = effective_date {
        proposal.effective_date = day;
    }
    h.plan(
        name,
        agent(),
        PostIntent::new(proposal, Vec::new()).unwrap(),
    );
    let (target, _) = h.target();
    let at = h.head();
    let (_, reviewed) = h.rehearse(target, &reader(), name, at).unwrap().unwrap();
    let certificate_digest =
        fa_model::domain_digest(b"fa:close-kernel-retention-fixture:v1", &[&[ordinal]]);
    // At this crate boundary report-family semantics belong to the facade.
    // The real native rehearsal supplies the source and exact entry effects;
    // this root exercises the journal's retained-artifact identity contract.
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(reviewed.source.canonical_bytes().unwrap()).unwrap(),
        ),
        (
            property::FA_DIGEST,
            CanonicalScalar::bytes(certificate_digest.to_vec()).unwrap(),
        ),
        (
            property::BOOK_ID,
            CanonicalScalar::bytes(h.book.book_id.0.to_vec()).unwrap(),
        ),
    ];
    props.sort_by_key(|(key, _)| key.0);
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(
        fa_model::report_certificate_vid(h.book.book_id, &certificate_digest),
        vec![label::CERTIFICATE],
        props,
    );
    h.write(batch);
    CloseTaskAction::PromoteDraft {
        source: reviewed.source,
        certificate_digest,
        expected_entries: reviewed.batch.entries,
    }
}

#[test]
fn close_run_cannot_relabel_normal_period_postings_as_an_overlapping_special_period() {
    let mut h = Harness::new(None);
    let day = DateDay::from_ymd(2026, 12, 31).unwrap();
    let periods = h.book.calendar.periods_for_year(2026).unwrap();
    let normal = periods
        .iter()
        .find(|p| p.kind == PeriodKind::Normal && p.contains(day))
        .unwrap()
        .code
        .clone();
    let adjustment = periods
        .iter()
        .find(|p| p.kind == PeriodKind::Adjustment && p.contains(day))
        .unwrap()
        .code
        .clone();
    let cx = h.ctx();
    let description = description(&h);
    h.runtime
        .block_on(transition_period(
            &mut h.db,
            &cx,
            &h.book,
            &normal,
            PeriodTransition::Open,
            OWNER,
            1,
            b"december-open",
            description,
            &Capability::embedded(OWNER, &["close"]).unwrap(),
            &[],
        ))
        .unwrap()
        .unwrap();
    let action = review_at(&mut h, "december-normal", 10, 221, Some(day));
    let mut declaration = definition(&h, "wrong-special", vec![task("post", &[], action)]);
    declaration.period = adjustment;
    let before = h.head();
    assert!(
        start(&mut h, &declaration)
            .unwrap_err()
            .message
            .contains("selected period")
    );
    assert_eq!(h.head(), before);
    declaration.name = "normal".into();
    declaration.period = normal;
    start(&mut h, &declaration).unwrap();
    let req = request(&h, closer());
    assert!(step(&mut h, "normal", "post", req).unwrap().run.complete);
}

fn task(id: &str, depends_on: &[&str], action: CloseTaskAction) -> CloseTaskDefinition {
    CloseTaskDefinition {
        id: id.into(),
        depends_on: depends_on.iter().map(|id| (*id).into()).collect(),
        action,
    }
}

fn definition(h: &Harness, name: &str, tasks: Vec<CloseTaskDefinition>) -> CloseRunDefinition {
    CloseRunDefinition {
        name: name.into(),
        period: h.period.clone(),
        tasks,
    }
}

fn start(h: &mut Harness, definition: &CloseRunDefinition) -> Result<CloseRunView, Refusal> {
    let cx = h.ctx();
    let description = description(h);
    h.runtime
        .block_on(create_close_run(
            &mut h.db,
            &cx,
            &h.book,
            definition,
            &closer(),
            description,
        ))
        .unwrap()
}

fn step(
    h: &mut Harness,
    run: &str,
    task: &str,
    request: CloseTaskRequest,
) -> Result<CloseTaskRecorded, Refusal> {
    let cx = h.ctx();
    h.runtime
        .block_on(execute_close_task(
            &mut h.db, &cx, &h.book, run, task, request,
        ))
        .unwrap()
}

fn status(h: &Harness, name: &str) -> CloseRunView {
    close_run_status(&h.db, &h.ctx(), &h.book, name, &reader())
        .unwrap()
        .unwrap()
        .unwrap()
}

fn plan(h: &Harness, run: &str, task: &str, key: &[u8]) -> Result<TransitionPlan, Refusal> {
    plan_close_task_transition(
        &h.db,
        &h.ctx(),
        &h.book,
        run,
        task,
        &closer(),
        1,
        key,
        description(h),
    )
    .unwrap()
}

// This is deliberately an identity-only kernel fixture. Real complete report
// frames and their mathematical replay are exercised by fa's close_execution
// and close_rehearsal tests; the kernel does not claim to verify those frames.
fn combined_review_bytes(view: &CloseRunView, marker: u8) -> Vec<u8> {
    let mut w = fa_model::Writer::new();
    w.bytes(b"fa:close-run-rehearsal-certificate:v1")
        .bytes(b"native baseline checked by facade")
        .bytes(&view.body.canonical_bytes().unwrap())
        .u64(view.opened_at.0);
    let count = view
        .body
        .tasks
        .iter()
        .filter(|task| {
            matches!(
                task.action,
                fa_model::CloseTaskBodyAction::PromoteDraft { .. },
            )
        })
        .count();
    w.u32(count as u32);
    for _ in 0..count {
        w.bytes(b"draft review checked by facade");
    }
    w.u128(APPROVER.0).fixed(&[0; 32]).bytes(&[marker]);
    let mut bytes = w.finish().unwrap();
    let digest =
        fa_model::domain_digest(b"fa:close-run-rehearsal-certificate-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&digest);
    bytes
}

fn retain_combined_review(
    h: &mut Harness,
    bytes: Vec<u8>,
) -> (fa_journal::close_run::CloseTaskReview, [u8; 32]) {
    let digest: [u8; 32] = bytes[bytes.len() - 32..].try_into().unwrap();
    let mut props = vec![
        (
            property::BOOK_ID,
            CanonicalScalar::bytes(h.book.book_id.0.to_vec()).unwrap(),
        ),
        (
            property::FA_DIGEST,
            CanonicalScalar::bytes(digest.to_vec()).unwrap(),
        ),
        (
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(bytes.clone()).unwrap(),
        ),
    ];
    props.sort_by_key(|(key, _)| key.0);
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(
        fa_model::report_certificate_vid(h.book.book_id, &digest),
        vec![label::CERTIFICATE],
        props,
    );
    h.write(batch);
    (
        fa_journal::close_run::CloseTaskReview::from_certificate(&bytes, h.head()).unwrap(),
        digest,
    )
}

#[test]
fn close_review_identity_frontier_and_atomic_history_are_enforced_by_the_kernel() {
    use fa_journal::close_run::CloseTaskReview;
    let mut h = Harness::new(None);
    let first = review(&mut h, "first-bound", 100, 201);
    let second = review(&mut h, "second-bound", 40, 202);
    let declaration = definition(
        &h,
        "bound",
        vec![
            task("first", &[], first),
            task("second", &["first"], second),
        ],
    );
    let initial = start(&mut h, &declaration).unwrap();
    let bytes = combined_review_bytes(&initial, 1);
    let stale = CloseTaskReview::from_certificate(&bytes, h.head()).unwrap();
    let mut req = request(&h, closer());
    req.review = Some(stale.clone());
    let before = h.head();
    assert_eq!(
        step(&mut h, "bound", "first", req).unwrap_err().code,
        code::PLAN_INVALIDATED
    );
    assert_eq!(h.head(), before, "a review must already be retained");
    let (selected, digest) = retain_combined_review(&mut h, bytes.clone());
    let mut req = request(&h, closer());
    req.review = Some(stale);
    let before = h.head();
    assert_eq!(
        step(&mut h, "bound", "first", req).unwrap_err().code,
        code::PLAN_INVALIDATED
    );
    assert_eq!(
        h.head(),
        before,
        "the checked native frontier must be exact"
    );

    let mut req = request(
        &h,
        Capability::embedded(AGENT, &["read", "close", "approve"]).unwrap(),
    );
    req.review = Some(selected.clone());
    assert!(step(&mut h, "bound", "first", req).is_err());
    assert_eq!(h.head(), before);
    assert!(
        status(&h, "bound").reviews.is_empty(),
        "failed native approval cannot attach a review"
    );
    let mut req = request(&h, closer());
    req.review = Some(selected.clone());
    let first = step(&mut h, "bound", "first", req).unwrap();
    assert_eq!(h.head().0, before.0 + 1);
    assert_eq!(first.run.reviews.len(), 1);
    assert_eq!(first.run.reviews[0].certificate, digest);
    assert_eq!(first.run.reviews[0].recorded_at, first.receipt.recorded_at);
    assert_eq!(first.run.tasks[0].rehearsal, Some(digest));
    let before = h.head();
    let req = request(&h, closer());
    assert_eq!(
        step(&mut h, "bound", "second", req).unwrap_err().code,
        code::PLAN_INVALIDATED
    );
    let mut req = request(&h, closer());
    req.review = Some(selected.at_frontier(h.head()));
    let retry = step(&mut h, "bound", "first", req).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.receipt, first.receipt);
    assert_eq!(h.head(), before);

    let fresh_bytes = combined_review_bytes(&first.run, 2);
    let (fresh, fresh_digest) = retain_combined_review(&mut h, fresh_bytes);
    let mut req = request(&h, closer());
    req.review = Some(fresh.clone());
    let before = h.head();
    assert_eq!(
        step(&mut h, "bound", "first", req).unwrap_err().code,
        code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(h.head(), before);
    let mut req = request(&h, closer());
    req.review = Some(fresh);
    let completed = step(&mut h, "bound", "second", req).unwrap();
    assert!(completed.run.complete);
    assert_eq!(
        completed
            .run
            .reviews
            .iter()
            .map(|review| review.certificate)
            .collect::<Vec<_>>(),
        [digest, fresh_digest]
    );
    assert_eq!(completed.run.reviews[0], first.run.reviews[0]);
    assert_eq!(
        completed.run.tasks[0].completion.as_ref(),
        Some(&first.receipt)
    );
    assert_eq!(completed.run.tasks[1].rehearsal, Some(fresh_digest));
    assert_eq!(
        completed.run.reviews[1].recorded_at,
        completed.receipt.recorded_at
    );
    assert_eq!(status(&h, "bound"), completed.run);

    let mut malformed = bytes;
    malformed[4] ^= 1;
    assert!(CloseTaskReview::from_certificate(&malformed, h.head()).is_err());
    malformed = combined_review_bytes(&initial, 3);
    let last = malformed.len() - 1;
    malformed[last] ^= 1;
    assert!(CloseTaskReview::from_certificate(&malformed, h.head()).is_err());
}

#[test]
fn close_review_cannot_bind_a_different_book_run_body_or_creation_sequence() {
    let mut h = Harness::new(None);
    let action = review(&mut h, "identity", 100, 203);
    let declaration = definition(&h, "identity", vec![task("post", &[], action)]);
    let initial = start(&mut h, &declaration).unwrap();
    for change in 0..4 {
        let mut other = initial.clone();
        match change {
            0 => other.body.book_id = Id128([252; 16]),
            1 => other.body.name = "another-run".into(),
            2 => other.body.owner = VId(999),
            _ => other.opened_at = CommitSeq(initial.opened_at.0 - 1),
        }
        let bytes = combined_review_bytes(&other, 4 + change);
        let (selected, _) = retain_combined_review(&mut h, bytes);
        let mut req = request(&h, closer());
        req.review = Some(selected);
        let before = h.head();
        let refusal = step(&mut h, "identity", "post", req).unwrap_err();
        assert_eq!(refusal.code, code::PLAN_INVALIDATED);
        assert_eq!(h.head(), before);
        assert_eq!(status(&h, "identity"), initial);
    }
}

#[test]
fn close_run_executes_reviewed_dependencies_and_final_period_atomically_with_durable_retries() {
    let mut h = Harness::new(None);
    let a = review(&mut h, "accrual", 100, 211);
    let b = review(&mut h, "adjustment", 40, 212);
    let definition = definition(
        &h,
        "march",
        vec![
            task(
                "final",
                &["second"],
                CloseTaskAction::PeriodTransition(PeriodTransition::Close),
            ),
            task("second", &["first"], b),
            task("first", &[], a),
        ],
    );
    let opened = start(&mut h, &definition).unwrap();
    assert_eq!(
        opened
            .tasks
            .iter()
            .filter(|task| task.ready)
            .map(|task| task.id.as_str())
            .collect::<Vec<_>>(),
        ["first"]
    );
    assert_eq!(cash_balance(&h.db, h.cash), 0);
    let head = h.head();
    let req = request(&h, closer());
    assert!(
        step(&mut h, "march", "second", req)
            .unwrap_err()
            .message
            .contains("prerequisites")
    );
    assert!(plan(&h, "march", "final", b"close-march").is_err());
    assert_eq!(h.head(), head);
    let req = request(&h, closer());
    let first = step(&mut h, "march", "first", req).unwrap();
    assert_eq!(first.receipt.recorded_at, CommitSeq(head.0 + 1));
    assert_eq!(
        read_entry(&h.db, first.receipt.effect).unwrap().unwrap().1,
        first.receipt.recorded_at
    );
    assert_eq!(
        read_entry(&h.db, first.receipt.record).unwrap().unwrap().1,
        first.receipt.recorded_at
    );
    assert_eq!(cash_balance(&h.db, h.cash), -100);
    let req = request(&h, closer());
    let retry = step(&mut h, "march", "first", req).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.receipt, first.receipt);
    assert_eq!(h.head(), first.receipt.recorded_at);
    let req = request(&h, closer());
    step(&mut h, "march", "second", req).unwrap();
    assert_eq!(cash_balance(&h.db, h.cash), -140);
    let reviewed = plan(&h, "march", "final", b"close-march").unwrap();
    let mut req = request(&h, closer());
    req.transition_plan = Some(reviewed.clone());
    let before_final = h.head();
    let final_task = step(&mut h, "march", "final", req.clone()).unwrap();
    assert!(final_task.run.complete);
    assert_eq!(h.head(), CommitSeq(before_final.0 + 1));
    assert_eq!(
        read_entry(&h.db, final_task.receipt.effect)
            .unwrap()
            .unwrap()
            .1,
        final_task.receipt.recorded_at
    );
    let after = h.head();
    assert_eq!(start(&mut h, &definition).unwrap(), final_task.run);
    assert_eq!(
        step(&mut h, "march", "final", req).unwrap().receipt,
        final_task.receipt
    );
    assert_eq!(h.head(), after);
    assert!(status(&h, "march").complete);
    let period = fa_journal::rows::PeriodRow::decode(
        &h.db
            .vertex(fa_model::period_vid(&h.book.calendar.id, &h.period))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(period.state, fa_time::PeriodState::Closed);
}

#[test]
fn close_run_refuses_cycles_unknown_dependencies_duplicates_and_unsupported_work_without_writes() {
    let mut h = Harness::new(None);
    let a = review(&mut h, "cycle-a", 10, 213);
    let b = review(&mut h, "cycle-b", 20, 214);
    let bad_graphs = [
        vec![task("a", &["b"], a.clone()), task("b", &["a"], b.clone())],
        vec![task("a", &["absent"], a.clone())],
        vec![task("a", &[], a.clone()), task("a", &[], b.clone())],
        vec![task("a", &["b", "b"], a.clone()), task("b", &[], b)],
        vec![task(
            "a",
            &[],
            CloseTaskAction::Unsupported("generate-statement".into()),
        )],
        vec![
            task("a", &[], a),
            task(
                "final",
                &[],
                CloseTaskAction::PeriodTransition(PeriodTransition::Close),
            ),
        ],
    ];
    let before = h.head();
    let rows = h.db.vertices().unwrap();
    for tasks in bad_graphs {
        let definition = definition(&h, "invalid", tasks);
        assert!(start(&mut h, &definition).is_err());
    }
    assert_eq!(h.head(), before);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn close_run_refuses_reviewed_effect_mismatch_and_new_draft_members_without_partial_publication() {
    let mut h = Harness::new(None);
    let mut wrong = review(&mut h, "wrong-effect", 60, 215);
    if let CloseTaskAction::PromoteDraft {
        expected_entries, ..
    } = &mut wrong
    {
        expected_entries[0].entry_digest[0] ^= 1;
    }
    let declaration = definition(&h, "wrong", vec![task("post", &[], wrong)]);
    start(&mut h, &declaration).unwrap();
    let before = h.head();
    let rows = h.db.vertices().unwrap();
    let req = request(&h, closer());
    assert!(
        step(&mut h, "wrong", "post", req)
            .unwrap_err()
            .message
            .contains("reviewed close effects")
    );
    assert_eq!(h.head(), before);
    assert_eq!(h.db.vertices().unwrap(), rows);
    assert_eq!(cash_balance(&h.db, h.cash), 0);
    assert!(status(&h, "wrong").tasks[0].ready);

    let action = review(&mut h, "membership", 50, 216);
    let declaration = definition(&h, "membership", vec![task("post", &[], action)]);
    start(&mut h, &declaration).unwrap();
    h.plan(
        "membership",
        agent(),
        PostIntent::new(
            h.proposal(1, b"unreviewed-tail", EntryClass::ORIGINAL, AGENT),
            Vec::new(),
        )
        .unwrap(),
    );
    let before = h.head();
    let req = request(&h, closer());
    assert!(
        step(&mut h, "membership", "post", req)
            .unwrap_err()
            .message
            .contains("membership changed")
    );
    assert_eq!(h.head(), before);
    assert_eq!(cash_balance(&h.db, h.cash), 0);
}

#[test]
fn close_run_requires_retained_review_and_refuses_retroactive_completion() {
    let mut h = Harness::new(None);
    let mut missing = review(&mut h, "unretained", 15, 217);
    if let CloseTaskAction::PromoteDraft {
        certificate_digest, ..
    } = &mut missing
    {
        certificate_digest[0] ^= 1;
    }
    let declaration = definition(&h, "missing-review", vec![task("post", &[], missing)]);
    let before = h.head();
    assert!(
        start(&mut h, &declaration)
            .unwrap_err()
            .message
            .contains("not retained")
    );
    assert_eq!(h.head(), before);

    let action = review(&mut h, "external-promotion", 15, 218);
    let declaration = definition(&h, "external", vec![task("post", &[], action)]);
    start(&mut h, &declaration).unwrap();
    h.promote("external-promotion");
    let before = h.head();
    let req = request(&h, closer());
    assert!(step(&mut h, "external", "post", req).is_err());
    assert_eq!(h.head(), before);
    assert!(status(&h, "external").tasks[0].completion.is_none());
}

#[test]
fn close_run_retries_recheck_native_authority_and_refuse_ignored_arguments() {
    let mut h = Harness::new(None);
    let action = review(&mut h, "authority", 20, 219);
    let declaration = definition(&h, "authority", vec![task("post", &[], action)]);
    start(&mut h, &declaration).unwrap();
    let req = request(&h, closer());
    step(&mut h, "authority", "post", req).unwrap();
    let before = h.head();
    for cap in [
        Capability::embedded(APPROVER, &["read", "close"]).unwrap(),
        Capability::embedded(AGENT, &["read", "close", "approve"]).unwrap(),
        Capability::embedded(APPROVER, &["close", "approve"]).unwrap(),
    ] {
        let req = request(&h, cap);
        assert!(step(&mut h, "authority", "post", req).is_err());
    }
    let mut req = request(&h, closer());
    req.approvals.push(ApprovalRef {
        approval_vid: VId(999),
        approved_digest: [1; 32],
    });
    assert!(step(&mut h, "authority", "post", req).is_err());
    h.revoke(&closer(), b"revoke-close");
    let after_revoke = h.head();
    let req = request(&h, closer());
    assert!(step(&mut h, "authority", "post", req).is_err());
    assert_eq!(after_revoke, CommitSeq(before.0 + 1));
    assert_eq!(h.head(), after_revoke);
}

#[test]
fn close_run_final_lock_uses_exact_native_plan_and_independent_approval() {
    let mut h = Harness::new(None);
    h.transition(PeriodTransition::Close, b"close-before-lock");
    let declaration = definition(
        &h,
        "lock",
        vec![task(
            "lock",
            &[],
            CloseTaskAction::PeriodTransition(PeriodTransition::Lock),
        )],
    );
    start(&mut h, &declaration).unwrap();
    let reviewed = plan(&h, "lock", "lock", b"lock-march").unwrap();
    let mut req = request(&h, closer());
    req.transition_plan = Some(reviewed.clone());
    let before = h.head();
    assert!(step(&mut h, "lock", "lock", req.clone()).is_err());
    assert_eq!(h.head(), before);
    assert!(!status(&h, "lock").complete);
    let approval = h.approve(&reviewed.proposal(&h.book).unwrap(), OWNER);
    req.approvals.push(approval);
    let result = step(&mut h, "lock", "lock", req.clone()).unwrap();
    assert!(result.run.complete);
    let after = h.head();
    assert_eq!(
        step(&mut h, "lock", "lock", req.clone()).unwrap().receipt,
        result.receipt
    );
    req.transition_plan.as_mut().unwrap().reason_code += 1;
    assert!(step(&mut h, "lock", "lock", req).is_err());
    assert_eq!(h.head(), after);
}

#[test]
fn close_run_cannot_attach_a_period_receipt_to_an_earlier_native_publication() {
    let mut h = Harness::new(None);
    let declaration = definition(
        &h,
        "external-period",
        vec![task(
            "close",
            &[],
            CloseTaskAction::PeriodTransition(PeriodTransition::Close),
        )],
    );
    start(&mut h, &declaration).unwrap();
    let reviewed = plan(&h, "external-period", "close", b"external-period-close").unwrap();
    let cx = h.ctx();
    let native = h
        .runtime
        .block_on(transition_planned(
            &mut h.db,
            &cx,
            &h.book,
            &reviewed,
            PeriodTransition::Close,
            &closer(),
            &[],
        ))
        .unwrap()
        .unwrap();
    let before = h.head();
    let mut req = request(&h, closer());
    req.transition_plan = Some(reviewed);
    assert!(step(&mut h, "external-period", "close", req).is_err());
    assert_eq!(h.head(), before);
    assert_eq!(before, native.recorded_at);
    let view = status(&h, "external-period");
    assert!(!view.complete);
    assert!(view.tasks[0].completion.is_none());
}

#[test]
fn close_run_status_refuses_state_and_immutable_definition_tampering() {
    let mut h = Harness::new(None);
    let action = review(&mut h, "tamper", 20, 220);
    let declaration = definition(&h, "tamper", vec![task("post", &[], action)]);
    let run = start(&mut h, &declaration).unwrap();
    let mut batch = WriteBatch::new(relation::IN_CASE);
    batch.set_vertex_property(
        run.tasks[0].vid,
        property::STATE,
        Some(CanonicalScalar::Int(1)),
    );
    h.write(batch);
    assert!(close_run_status(&h.db, &h.ctx(), &h.book, "tamper", &reader()).is_err());
    let mut restore = WriteBatch::new(relation::IN_CASE);
    restore.set_vertex_property(
        run.tasks[0].vid,
        property::STATE,
        Some(CanonicalScalar::Int(0)),
    );
    h.write(restore);
    assert!(
        close_run_status(&h.db, &h.ctx(), &h.book, "tamper", &reader()).is_err(),
        "restoring a mirror does not erase its unauthorized history"
    );
}

#[test]
fn close_run_status_binds_the_original_native_outcome_not_a_rewritten_entry_list() {
    let mut h = Harness::new(None);
    let action = review(&mut h, "outcome-history", 20, 222);
    let declaration = definition(&h, "outcome-history", vec![task("post", &[], action)]);
    start(&mut h, &declaration).unwrap();
    let req = request(&h, closer());
    step(&mut h, "outcome-history", "post", req).unwrap();
    let outcome = h
        .draft("outcome-history")
        .closed
        .unwrap()
        .promoted
        .unwrap()
        .0;
    let (original, _) = read_outcome(&h.db, &h.ctx().query(), outcome)
        .unwrap()
        .unwrap();
    let mut changed = original.clone();
    changed.request_digest[0] ^= 1;
    for body in [changed, original] {
        let mut batch = WriteBatch::new(relation::IN_CASE);
        batch.set_vertex_property(
            outcome,
            property::FA_PAYLOAD,
            Some(CanonicalScalar::bytes(body.canonical_bytes().unwrap()).unwrap()),
        );
        h.write(batch);
        assert!(close_run_status(&h.db, &h.ctx(), &h.book, "outcome-history", &reader()).is_err());
    }
}

fn lifecycle_key(kind: u8, object: VId) -> Vec<u8> {
    fa_model::domain_digest(
        b"fa:close-record-key:v1",
        &[&[kind], &object.0.to_le_bytes()],
    )
    .to_vec()
}

fn shared_key_batch(h: &mut Harness, key: &[u8], principal: VId) -> Result<BatchPosted, Refusal> {
    let member = PostIntent::new(
        h.proposal(
            321,
            b"close-key-batch-member",
            EntryClass::ORIGINAL,
            principal,
        ),
        Vec::new(),
    )
    .unwrap();
    let batch = PostBatch::new(key.to_vec(), vec![member]).unwrap();
    let cx = h.ctx();
    h.runtime
        .block_on(post_batch(
            &mut h.db,
            &cx,
            &h.book,
            Capability::embedded(principal, &["post"]).unwrap(),
            batch,
        ))
        .unwrap()
}

#[test]
fn close_lifecycle_and_batches_reserve_the_same_principal_key_in_both_orders() {
    for kind in ["open", "task", "review", "complete"] {
        for batch_first in [false, true] {
            let mut h = Harness::new(None);
            let action = review(&mut h, "shared-close-key", 20, 230);
            let declaration = definition(&h, "shared-close-key", vec![task("post", &[], action)]);
            let run = fa_model::close_run_vid(h.book.book_id, &declaration.name);
            let task_vid = fa_model::close_task_vid(h.book.book_id, &declaration.name, "post");
            let mut selected = None;
            let key = match kind {
                "open" => lifecycle_key(0, run),
                _ => {
                    let opened = start(&mut h, &declaration).unwrap();
                    match kind {
                        "task" => lifecycle_key(1, task_vid),
                        "complete" => lifecycle_key(2, run),
                        "review" => {
                            let (review, certificate) =
                                retain_combined_review(&mut h, combined_review_bytes(&opened, 1));
                            selected = Some(review);
                            fa_model::domain_digest(
                                b"fa:close-review-key:v1",
                                &[&run.0.to_le_bytes(), &certificate],
                            )
                            .to_vec()
                        }
                        _ => unreachable!(),
                    }
                }
            };
            if batch_first {
                shared_key_batch(&mut h, &key, APPROVER).unwrap();
                let before = h.head();
                let rows = h.db.vertices().unwrap();
                let refusal = if kind == "open" {
                    start(&mut h, &declaration).unwrap_err()
                } else {
                    let mut req = request(&h, closer());
                    req.review = selected.as_ref().map(|review| review.at_frontier(before));
                    step(&mut h, &declaration.name, "post", req).unwrap_err()
                };
                assert_eq!(
                    refusal.code,
                    code::IDEMPOTENCY_CONFLICT,
                    "{kind}: {refusal}"
                );
                assert_eq!(h.head(), before, "{kind}");
                assert_eq!(h.db.vertices().unwrap(), rows, "{kind}");
                assert_eq!(cash_balance(&h.db, h.cash), -321, "{kind}");
                assert!(h.draft("shared-close-key").closed.is_none(), "{kind}");
                if kind == "open" {
                    assert!(h.db.vertex(run).unwrap().is_none());
                } else {
                    let view = status(&h, &declaration.name);
                    assert!(view.tasks[0].completion.is_none(), "{kind}");
                    assert!(view.reviews.is_empty(), "{kind}");
                    assert!(!view.complete, "{kind}");
                }
            } else {
                if kind == "open" {
                    start(&mut h, &declaration).unwrap();
                } else {
                    let mut req = request(&h, closer());
                    req.review = selected;
                    assert!(
                        step(&mut h, &declaration.name, "post", req)
                            .unwrap()
                            .run
                            .complete
                    );
                }
                let before = h.head();
                let rows = h.db.vertices().unwrap();
                assert_eq!(
                    shared_key_batch(&mut h, &key, APPROVER).unwrap_err().code,
                    code::IDEMPOTENCY_CONFLICT,
                    "{kind}"
                );
                assert_eq!(h.head(), before, "{kind}");
                assert_eq!(h.db.vertices().unwrap(), rows, "{kind}");
                let entry = entry_vid(h.book.book_id, &APPROVER.0.to_le_bytes(), &key);
                let claim =
                    h.db.vertex(fa_model::intent_outcome_vid(
                        h.book.book_id,
                        &APPROVER.0.to_le_bytes(),
                        &key,
                    ))
                    .unwrap()
                    .unwrap();
                assert_eq!(claim.labels, vec![label::INTENT_OUTCOME], "{kind}");
                assert_eq!(
                    claim.created_at,
                    h.db.vertex(entry).unwrap().unwrap().created_at,
                    "{kind}"
                );
                assert_eq!(
                    prop(&claim, property::TARGET_REF),
                    Some(&CanonicalScalar::bytes(entry.0.to_le_bytes().to_vec()).unwrap()),
                    "{kind}"
                );
                shared_key_batch(&mut h, &key, OWNER).unwrap();
            }
        }
    }
}

#[test]
fn close_control_claims_publish_with_their_native_effect_and_authenticate_every_retry() {
    for kind in ["open", "task", "review", "complete"] {
        for attack in ["deleted", "rewritten-and-restored"] {
            let mut h = Harness::new(None);
            let action = review(&mut h, "claim-history", 20, 231);
            let declaration = definition(&h, "claim-history", vec![task("post", &[], action)]);
            let opened = start(&mut h, &declaration).unwrap();
            let (selected, certificate) =
                retain_combined_review(&mut h, combined_review_bytes(&opened, 2));
            let mut req = request(&h, closer());
            req.review = Some(selected);
            let completed = step(&mut h, &declaration.name, "post", req).unwrap();
            let key = match kind {
                "open" => lifecycle_key(0, opened.vid),
                "task" => lifecycle_key(1, opened.tasks[0].vid),
                "complete" => lifecycle_key(2, opened.vid),
                "review" => fa_model::domain_digest(
                    b"fa:close-review-key:v1",
                    &[&opened.vid.0.to_le_bytes(), &certificate],
                )
                .to_vec(),
                _ => unreachable!(),
            };
            let outcome =
                fa_model::intent_outcome_vid(h.book.book_id, &APPROVER.0.to_le_bytes(), &key);
            let original = h.db.vertex(outcome).unwrap().unwrap();
            assert_eq!(
                original.created_at,
                if kind == "open" {
                    opened.opened_at
                } else {
                    completed.receipt.recorded_at
                }
            );
            assert_eq!(
                h.db.vertex(completed.receipt.effect)
                    .unwrap()
                    .unwrap()
                    .created_at,
                completed.receipt.recorded_at
            );
            let mut change = WriteBatch::new(relation::IN_CASE);
            if attack == "deleted" {
                change.delete_vertex(outcome);
                h.write(change);
            } else {
                change.set_vertex_property(
                    outcome,
                    property::FA_PAYLOAD,
                    Some(CanonicalScalar::Int(0)),
                );
                h.write(change);
                let mut restore = WriteBatch::new(relation::IN_CASE);
                restore.set_vertex_property(
                    outcome,
                    property::FA_PAYLOAD,
                    Some(prop(&original, property::FA_PAYLOAD).unwrap().clone()),
                );
                h.write(restore);
                assert_eq!(h.db.vertex(outcome).unwrap().unwrap().props, original.props);
            }
            let before = h.head();
            let rows = h.db.vertices().unwrap();
            assert!(
                close_run_status(&h.db, &h.ctx(), &h.book, &declaration.name, &reader()).is_err(),
                "{kind}: {attack}"
            );
            let cx = h.ctx();
            let text = description(&h);
            assert!(
                !matches!(
                    h.runtime.block_on(create_close_run(
                        &mut h.db,
                        &cx,
                        &h.book,
                        &declaration,
                        &closer(),
                        text,
                    )),
                    Ok(Ok(_))
                ),
                "{kind}: {attack}"
            );
            let req = request(&h, closer());
            assert!(
                !matches!(
                    h.runtime.block_on(execute_close_task(
                        &mut h.db,
                        &cx,
                        &h.book,
                        &declaration.name,
                        "post",
                        req,
                    )),
                    Ok(Ok(_))
                ),
                "{kind}: {attack}"
            );
            // Admission must precede reading even the corrupted claim.
            let denied = request(&h, Capability::embedded(APPROVER, &["close"]).unwrap());
            let refusal = h
                .runtime
                .block_on(execute_close_task(
                    &mut h.db,
                    &cx,
                    &h.book,
                    &declaration.name,
                    "post",
                    denied,
                ))
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.code, code::CAPABILITY, "{kind}: {attack}");
            assert_eq!(h.head(), before, "{kind}: {attack}");
            assert_eq!(h.db.vertices().unwrap(), rows, "{kind}: {attack}");
        }
    }
}

#[test]
fn close_open_retry_binds_its_semantic_description_and_accepts_equivalent_resealing() {
    let mut h = Harness::new(None);
    let declaration = definition(
        &h,
        "semantic-open",
        vec![task(
            "close",
            &[],
            CloseTaskAction::PeriodTransition(PeriodTransition::Close),
        )],
    );
    let initial = start(&mut h, &declaration).unwrap();
    let before = h.head();
    let rows = h.db.vertices().unwrap();
    for text in ["different reviewed work", "reviewed close"] {
        let description = Erasable::seal(
            &text.to_string(),
            None,
            &h.book.seal_key,
            [232; 32],
            [233; 24],
        );
        let cx = h.ctx();
        let result = h
            .runtime
            .block_on(create_close_run(
                &mut h.db,
                &cx,
                &h.book,
                &declaration,
                &closer(),
                description,
            ))
            .unwrap();
        if text == "reviewed close" {
            assert_eq!(result.unwrap(), initial);
        } else {
            assert_eq!(result.unwrap_err().code, code::IDEMPOTENCY_CONFLICT);
        }
        assert_eq!(h.head(), before);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn a_current_authorized_controller_can_resume_another_controllers_completed_task() {
    let mut h = Harness::new(None);
    let first = review(&mut h, "controller-first", 20, 234);
    let second = review(&mut h, "controller-second", 30, 235);
    let declaration = definition(
        &h,
        "controllers",
        vec![
            task("first", &[], first),
            task("second", &["first"], second),
        ],
    );
    start(&mut h, &declaration).unwrap();
    let req = request(&h, closer());
    let first = step(&mut h, "controllers", "first", req).unwrap();
    let before = h.head();
    let other = Capability::embedded(OWNER, &["read", "close", "approve"]).unwrap();
    let mut req = request(&h, other.clone());
    req.description = Erasable::seal(
        &"continuing the existing close".to_string(),
        None,
        &h.book.seal_key,
        [236; 32],
        [237; 24],
    );
    let retry = step(&mut h, "controllers", "first", req).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.receipt, first.receipt);
    assert_eq!(retry.receipt.principal, APPROVER);
    assert_eq!(h.head(), before);
    let task = fa_model::close_task_vid(h.book.book_id, "controllers", "first");
    assert!(
        h.db.vertex(fa_model::intent_outcome_vid(
            h.book.book_id,
            &OWNER.0.to_le_bytes(),
            &lifecycle_key(1, task),
        ))
        .unwrap()
        .is_none(),
        "observing another controller's completed task does not acquire its key"
    );
    let req = request(&h, other);
    let second = step(&mut h, "controllers", "second", req).unwrap();
    assert!(second.run.complete);
    assert_eq!(second.receipt.principal, OWNER);
    assert_eq!(cash_balance(&h.db, h.cash), -50);
    assert_eq!(status(&h, "controllers"), second.run);
}

#[test]
fn a_genuine_legacy_close_open_remains_a_read_only_retry_anchor() {
    let mut h = Harness::new(None);
    let declaration = definition(
        &h,
        "legacy-close",
        vec![task(
            "close",
            &[],
            CloseTaskAction::PeriodTransition(PeriodTransition::Close),
        )],
    );
    let body = fa_model::CloseRunBody {
        book_id: h.book.book_id,
        name: declaration.name.clone(),
        period: declaration.period.clone(),
        owner: APPROVER,
        tasks: vec![fa_model::CloseTaskBody {
            id: "close".into(),
            depends_on: Vec::new(),
            action: fa_model::CloseTaskBodyAction::PeriodTransition { to: 3 },
        }],
    };
    let run = fa_model::close_run_vid(h.book.book_id, &body.name);
    let task = fa_model::close_task_vid(h.book.book_id, &body.name, "close");
    let key = lifecycle_key(0, run);
    let entry_id = entry_vid(h.book.book_id, &APPROVER.0.to_le_bytes(), &key);
    let claim = fa_model::intent_outcome_vid(h.book.book_id, &APPROVER.0.to_le_bytes(), &key);
    let opening = EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: h.book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::CLOSE_CONTROL,
        effective_date: DateDay(0),
        document_date: None,
        description: description(&h),
        effective_period: None,
        legs: Vec::new(),
        control: Some(fa_model::ControlPayload::LifecycleTransition {
            object_ref: run,
            from: 0,
            to: 1,
            proof_refs: Vec::new(),
            reason_code: 0,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: key,
        origin: EntryOrigin::Control {
            control_kind: fa_model::ControlKind::CLOSE_TRANSITION,
            spec_body_digest: body.digest().unwrap(),
        },
        principal_ref: APPROVER,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: vec![(
            fa_model::entry::CLOSE_RUN_EXTENSION,
            body.canonical_bytes().unwrap(),
        )],
        tags: Vec::new(),
    }
    .seal(Vec::new(), None)
    .unwrap();
    let object_props = |code: &str, payload: Vec<u8>, digest: [u8; 32], state: i64| {
        let mut props = vec![
            (
                property::FA_PAYLOAD,
                CanonicalScalar::bytes(payload).unwrap(),
            ),
            (
                property::FA_DIGEST,
                CanonicalScalar::bytes(digest.to_vec()).unwrap(),
            ),
            (
                property::BOOK_ID,
                CanonicalScalar::bytes(h.book.book_id.0.to_vec()).unwrap(),
            ),
            (
                property::CODE,
                CanonicalScalar::ucs_basic_text(code).unwrap(),
            ),
            (property::STATE, CanonicalScalar::Int(state)),
        ];
        props.sort_by_key(|(key, _)| key.0);
        props
    };
    // Reproduce an old writer's publication, with no claim at its original
    // coordinate. Deleting a modern claim would not be a legacy fixture.
    let mut batch = WriteBatch::new(relation::IN_CASE);
    batch.create_vertex(
        run,
        vec![label::CLOSE_RUN],
        object_props(
            &body.name,
            body.canonical_bytes().unwrap(),
            body.digest().unwrap(),
            1,
        ),
    );
    batch.create_vertex(
        task,
        vec![label::CLOSE_TASK],
        object_props(
            "close",
            body.tasks[0].canonical_bytes().unwrap(),
            body.tasks[0].digest().unwrap(),
            0,
        ),
    );
    batch.create_vertex(
        entry_id,
        vec![label::ENTRY],
        fa_model::entry_mirrors(&opening).unwrap(),
    );
    batch.add_edge(
        edge_id(relation::IN_CASE, entry_id, run),
        entry_id,
        run,
        vec![],
    );
    batch.add_edge(edge_id(relation::IN_CASE, task, run), task, run, vec![]);
    h.write(batch);
    let original = status(&h, &declaration.name);
    let before = h.head();
    let rows = h.db.vertices().unwrap();
    assert_eq!(start(&mut h, &declaration).unwrap(), original);
    assert_eq!(h.head(), before);
    assert_eq!(h.db.vertices().unwrap(), rows);
    assert!(h.db.vertex(claim).unwrap().is_none());
    assert!(h.db.vertex_at(claim, original.opened_at).unwrap().is_none());

    let reviewed = plan(&h, &declaration.name, "close", b"legacy-final-close").unwrap();
    let mut req = request(&h, closer());
    req.transition_plan = Some(reviewed);
    let complete = step(&mut h, &declaration.name, "close", req).unwrap();
    assert!(complete.run.complete);
    assert!(h.db.vertex(claim).unwrap().is_none());
    for key in [lifecycle_key(1, task), lifecycle_key(2, run)] {
        let claim =
            h.db.vertex(fa_model::intent_outcome_vid(
                h.book.book_id,
                &APPROVER.0.to_le_bytes(),
                &key,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(claim.created_at, complete.receipt.recorded_at);
    }
    let before = h.head();
    assert_eq!(start(&mut h, &declaration).unwrap(), complete.run);
    assert_eq!(status(&h, &declaration.name), complete.run);
    assert_eq!(h.head(), before);
}
