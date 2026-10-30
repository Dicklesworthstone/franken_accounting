use super::*;
use fa_journal::recurring::*;
use fa_time::MonthEndPolicy;

fn capability() -> Capability {
    Capability::embedded(PRINCIPAL, &["post", "read"]).unwrap()
}

fn spec(h: &Harness, name: &str, anchor: &str, end: &str) -> RecurringSpec {
    let mut template = h.proposal(
        h.rent_legs(12_345),
        b"recurring-template",
        EntryClass::ORIGINAL,
    );
    template.effective_date = DateDay::parse(anchor).unwrap();
    RecurringSpec {
        name: name.into(),
        template,
        every_months: 1,
        month_end: MonthEndPolicy::ClampToMonthEnd,
        end: Some(DateDay::parse(end).unwrap()),
    }
}

fn plan(h: &Harness, spec: RecurringSpec, cap: &Capability) -> RecurringPlan {
    plan_recurring(&h.db, &h.ctx(), &h.book, cap, spec)
        .unwrap()
        .unwrap()
}

fn create(
    h: &mut Harness,
    plan: RecurringPlan,
    cap: &Capability,
    approvals: Vec<fa_model::ApprovalRef>,
) -> Result<RecurringRecorded, Refusal> {
    let ctx = h.ctx();
    h.runtime
        .block_on(create_recurring(
            &mut h.db, &ctx, &h.book, cap, plan, approvals,
        ))
        .unwrap()
}

fn approved(h: &mut Harness, spec: RecurringSpec, cap: &Capability) -> RecurringRecorded {
    let plan = plan(h, spec, cap);
    let approval = h.approve_transition(plan.proposal_digest().unwrap());
    create(h, plan, cap, vec![approval]).unwrap()
}

fn sweep(h: &mut Harness, max_batch: usize) -> Option<RecurringBatch> {
    let system = fa_journal::rows::system_principal(h.book.book_id);
    let req = SweepRequest {
        principal_ref: system,
        capability: Capability::new(system, Profile::System, &[Op::Post], system).unwrap(),
        max_batch,
    };
    let ctx = h.ctx();
    h.runtime
        .block_on(sweep_recurring_batch(&mut h.db, &ctx, &h.book, &req))
        .unwrap()
        .unwrap()
}

fn sweep_with_history(
    h: &mut Harness,
    max_batch: usize,
    history: &mut Option<RecurringHistory>,
) -> fa_journal::refusal::Outcome<Option<RecurringBatch>> {
    let system = fa_journal::rows::system_principal(h.book.book_id);
    let req = SweepRequest {
        principal_ref: system,
        capability: Capability::new(system, Profile::System, &[Op::Post], system).unwrap(),
        max_batch,
    };
    let ctx = h.ctx();
    h.runtime.block_on(sweep_recurring_batch_with_history(
        &mut h.db, &ctx, &h.book, &req, history,
    ))
}

fn tick_on(h: &mut Harness, date: &str) {
    let day = DateDay::parse(date).unwrap();
    let ns = u64::try_from(day.0)
        .unwrap()
        .checked_mul(86_400_000_000_000)
        .unwrap();
    h.tick(ns, date.as_bytes(), 91);
}

fn cancel(h: &mut Harness, name: &str) -> RecurringRecorded {
    let ctx = h.ctx();
    let description = h.statement("stop future rent", 93);
    h.runtime
        .block_on(cancel_recurring(
            &mut h.db,
            &ctx,
            &h.book,
            &capability(),
            name,
            description,
        ))
        .unwrap()
        .unwrap()
}

#[test]
fn monthly_rent_mints_twelve_exact_occurrences_with_bounded_restart_and_no_duplicates() {
    let mut h = harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None);
    for period in h.book.calendar.periods_for_year(2026).unwrap() {
        if period.kind == PeriodKind::Normal && h.period_state(&period.code) == PeriodState::Future
        {
            h.transition(
                &period.code,
                PeriodTransition::Open,
                format!("open-{}", period.code).as_bytes(),
            )
            .unwrap();
        }
    }
    let definition = spec(&h, "monthly-rent", "2026-01-31", "2026-12-31");
    let created = approved(&mut h, definition, &capability());
    tick_on(&mut h, "2026-12-31");
    let mut posted = Vec::new();
    while let Some(batch) = sweep(&mut h, 2) {
        assert!(batch.blocked.is_empty(), "{:?}", batch.blocked);
        assert!(batch.posted.len() <= 2);
        let more = batch.more;
        posted.extend(batch.posted);
        if !more {
            break;
        }
    }
    let expected = [
        "2026-01-31",
        "2026-02-28",
        "2026-03-31",
        "2026-04-30",
        "2026-05-31",
        "2026-06-30",
        "2026-07-31",
        "2026-08-31",
        "2026-09-30",
        "2026-10-31",
        "2026-11-30",
        "2026-12-31",
    ];
    assert_eq!(posted.len(), expected.len());
    for (index, (entry_ref, date)) in posted.iter().zip(expected).enumerate() {
        assert_eq!(
            entry_ref.vid,
            recurring_occurrence_vid(created.schedule, index as u64)
        );
        let (entry, _) = read_entry(&h.db, entry_ref.vid).unwrap().unwrap();
        assert_eq!(entry.proposal.effective_date.render(), date);
        assert_eq!(entry.proposal.legs, h.rent_legs(12_345));
        assert_eq!(entry.proposal.principal_ref, PRINCIPAL);
    }
    let before_retry = h.db.frontier().unwrap();
    assert_eq!(sweep(&mut h, 2), None);
    assert_eq!(h.db.frontier().unwrap(), before_retry);
    let view = recurring_schedules(&h.db, &h.ctx(), &h.book, &capability())
        .unwrap()
        .unwrap();
    assert_eq!(view.len(), 1);
    assert_eq!(view[0].next_index, 12);
    assert_eq!(view[0].next_date, None);
    assert!(
        verify_recurring(&h.db, &h.ctx(), &h.book)
            .unwrap()
            .is_green()
    );
}

#[test]
fn recurring_creation_requires_an_independent_approval_and_binds_all_effects() {
    let mut h = harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None);
    let planned = plan(
        &h,
        spec(&h, "rent", "2026-03-15", "2026-03-15"),
        &capability(),
    );
    let head = h.db.frontier().unwrap();
    assert!(create(&mut h, planned.clone(), &capability(), vec![]).is_err());
    assert_eq!(h.db.frontier().unwrap(), head);
    let self_approval = h
        .approve_digest(PRINCIPAL, planned.proposal_digest().unwrap())
        .unwrap();
    let head = h.db.frontier().unwrap();
    assert!(create(&mut h, planned.clone(), &capability(), vec![self_approval]).is_err());
    assert_eq!(h.db.frontier().unwrap(), head);
    let approval = h.approve_transition(planned.proposal_digest().unwrap());
    let mut changed = planned.spec().clone();
    changed.template.legs = h.rent_legs(50_000);
    changed.template.unit_totals = EntryPayload::fold_unit_totals(&changed.template.legs).unwrap();
    let changed = plan(&h, changed, &capability());
    let head = h.db.frontier().unwrap();
    assert!(create(&mut h, changed, &capability(), vec![approval]).is_err());
    assert_eq!(h.db.frontier().unwrap(), head);
    let encoded = planned.encode().unwrap();
    assert_eq!(RecurringPlan::decode(&encoded).unwrap(), planned);
    let recorded = create(&mut h, planned.clone(), &capability(), vec![approval]).unwrap();
    assert!(!recorded.already_recorded);
    assert!(
        create(&mut h, planned, &capability(), vec![approval])
            .unwrap()
            .already_recorded
    );
    let agent = Capability::new(PRINCIPAL, Profile::Agent, &[Op::Post, Op::Read], VId(1)).unwrap();
    assert!(
        plan_recurring(
            &h.db,
            &h.ctx(),
            &h.book,
            &agent,
            spec(&h, "agent-rent", "2026-03-15", "2026-03-15")
        )
        .unwrap()
        .is_err()
    );
}

#[test]
fn cancellation_stops_unminted_backlog_and_is_a_journaled_idempotent_lineage() {
    let mut h = harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None);
    h.transition(&h.april.clone(), PeriodTransition::Open, b"recurring-april")
        .unwrap();
    let definition = spec(&h, "rent", "2026-03-31", "2026-04-30");
    let created = approved(&mut h, definition, &capability());
    tick_on(&mut h, "2026-04-30");
    let first = sweep(&mut h, 1).unwrap();
    assert_eq!(first.posted.len(), 1);
    assert!(first.more);
    let stopped = cancel(&mut h, "rent");
    assert!(!stopped.already_recorded);
    let (entry, _) = read_entry(&h.db, stopped.control_entry.vid)
        .unwrap()
        .unwrap();
    assert_eq!(
        entry.proposal.control,
        Some(ControlPayload::ScheduleCancelled {
            schedule_ref: created.schedule,
            cause_ref: created.control_entry.vid
        })
    );
    let head = h.db.frontier().unwrap();
    assert!(cancel(&mut h, "rent").already_recorded);
    assert_eq!(sweep(&mut h, 1), None);
    assert_eq!(h.db.frontier().unwrap(), head);
    let view = recurring_schedules(&h.db, &h.ctx(), &h.book, &capability())
        .unwrap()
        .unwrap();
    assert_eq!(view[0].next_index, 1);
    assert!(view[0].cancelled_at.is_some());
    assert!(
        verify_recurring(&h.db, &h.ctx(), &h.book)
            .unwrap()
            .is_green()
    );
    assert!(verify_schedules(&h.db, &h.book).unwrap().is_green());
}

#[test]
fn closed_due_schedule_remains_blocked_without_starving_an_open_schedule() {
    let mut h = harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None);
    h.transition(&h.april.clone(), PeriodTransition::Open, b"recurring-april")
        .unwrap();
    let open_name = "open-rent";
    let open_id = recurring_schedule_vid(h.book.book_id, open_name);
    let blocked_name = (0..1000)
        .map(|n| format!("closed-rent-{n}"))
        .find(|n| recurring_schedule_vid(h.book.book_id, n) < open_id)
        .unwrap();
    let blocked = spec(&h, &blocked_name, "2026-03-15", "2026-03-15");
    approved(&mut h, blocked, &capability());
    let open = spec(&h, open_name, "2026-04-15", "2026-04-15");
    approved(&mut h, open, &capability());
    h.transition(
        &h.march.clone(),
        PeriodTransition::SoftClose,
        b"recurring-soft-close",
    )
    .unwrap();
    h.transition(
        &h.march.clone(),
        PeriodTransition::Close,
        b"recurring-close",
    )
    .unwrap();
    tick_on(&mut h, "2026-04-30");
    let result = sweep(&mut h, 1).unwrap();
    assert_eq!(result.posted.len(), 1);
    assert_eq!(result.blocked.len(), 1);
    assert_eq!(result.blocked[0].name, blocked_name);
    assert!(!result.more);
    let head = h.db.frontier().unwrap();
    let retry = sweep(&mut h, 1).unwrap();
    assert!(retry.posted.is_empty());
    assert_eq!(retry.blocked.len(), 1);
    assert!(!retry.more);
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn current_creator_revocation_stops_approved_effects_and_public_post_cannot_forge_occurrences() {
    let mut h = harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None);
    let cap = capability();
    let definition = spec(&h, "rent", "2026-03-15", "2026-03-15");
    approved(&mut h, definition, &cap);
    tick_on(&mut h, "2026-03-31");
    let posted = sweep(&mut h, 1).unwrap().posted[0];
    let (entry, _) = read_entry(&h.db, posted.vid).unwrap().unwrap();
    let head = h.db.frontier().unwrap();
    assert!(
        h.post(h.request(entry.proposal, &["post", "read"]))
            .is_err()
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    let mut fake_control = h.proposal(h.rent_legs(12_345), b"fake-schedule", EntryClass::ORIGINAL);
    fake_control.schema_minor = fa_model::entry::SCHEMA_MINOR;
    fake_control.extensions = vec![(fa_model::entry::RECURRING_SCHEDULE_EXTENSION, vec![1])];
    assert!(h.post(h.request(fake_control, &["post", "read"])).is_err());
    assert_eq!(h.db.frontier().unwrap(), head);
    let second = spec(&h, "revoked-rent", "2026-03-15", "2026-03-15");
    approved(&mut h, second, &cap);
    h.revoke(&cap, 99);
    let head = h.db.frontier().unwrap();
    let blocked = sweep(&mut h, 1).unwrap();
    assert!(blocked.posted.is_empty());
    assert_eq!(blocked.blocked.len(), 1);
    assert!(blocked.blocked[0].refusal.message.contains("revoked"));
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn preserve_day_refuses_a_short_month_without_skipping_its_occurrence_index() {
    let mut h = harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None);
    for period in h.book.calendar.periods_for_year(2026).unwrap() {
        if period.kind == PeriodKind::Normal && h.period_state(&period.code) == PeriodState::Future
        {
            h.transition(
                &period.code,
                PeriodTransition::Open,
                format!("preserve-{}", period.code).as_bytes(),
            )
            .unwrap();
        }
    }
    let mut definition = spec(&h, "day-31", "2026-01-31", "2026-03-31");
    definition.month_end = MonthEndPolicy::PreserveDay;
    approved(&mut h, definition, &capability());
    tick_on(&mut h, "2026-03-31");
    let batch = sweep(&mut h, 10).unwrap();
    assert_eq!(batch.posted.len(), 1);
    assert_eq!(batch.blocked.len(), 1);
    assert_eq!(batch.blocked[0].index, 1);
    let view = recurring_schedules(&h.db, &h.ctx(), &h.book, &capability())
        .unwrap()
        .unwrap();
    assert_eq!(view[0].next_index, 1);
    assert!(view[0].blocked.is_some());
}

#[test]
fn completed_finite_schedule_does_not_evaluate_an_invalid_or_unrepresentable_later_month() {
    for (anchor, interval) in [("2026-03-31", 1), ("2026-03-15", u32::MAX)] {
        let mut h = harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None);
        let mut definition = spec(&h, "bounded-rent", anchor, anchor);
        definition.month_end = MonthEndPolicy::PreserveDay;
        definition.every_months = interval;
        approved(&mut h, definition, &capability());
        tick_on(&mut h, "2026-03-31");
        let batch = sweep(&mut h, 2).unwrap();
        assert_eq!(batch.posted.len(), 1);
        assert!(batch.blocked.is_empty(), "{:?}", batch.blocked);
        assert!(!batch.more);
        assert_eq!(sweep(&mut h, 2), None);
        let view = recurring_schedules(&h.db, &h.ctx(), &h.book, &capability())
            .unwrap()
            .unwrap();
        assert_eq!(view[0].next_index, 1);
        assert_eq!(view[0].next_date, None);
        assert_eq!(view[0].blocked, None);
    }
}

#[test]
fn recurring_history_carries_ordinary_posts_and_ticks_without_scanning_the_prior_book() {
    let mut tail_work = Vec::new();
    for prior_posts in [1, 33] {
        let mut h = harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None);
        for index in 0..prior_posts {
            let proposal = h.proposal(
                h.rent_legs(100),
                format!("prior-{index}").as_bytes(),
                EntryClass::ORIGINAL,
            );
            h.post(h.request(proposal, &["post"])).unwrap();
        }
        tick_on(&mut h, "2026-03-15");
        let mut history = None;
        assert_eq!(
            sweep_with_history(&mut h, 1, &mut history)
                .unwrap()
                .unwrap(),
            None
        );
        let cold = history.as_ref().unwrap().read_work();
        assert_eq!(cold.snapshot_scans, 1);
        assert!(cold.entries_decoded >= prior_posts);
        let head = h.db.frontier().unwrap();
        assert_eq!(
            sweep_with_history(&mut h, 1, &mut history)
                .unwrap()
                .unwrap(),
            None
        );
        assert_eq!(
            history.as_ref().unwrap().read_work(),
            RecurringReadWork::default()
        );
        assert_eq!(history.as_ref().unwrap().verified_at(), head);
        let proposal = h.proposal(h.rent_legs(200), b"new-ordinary", EntryClass::ORIGINAL);
        h.post(h.request(proposal, &["post"])).unwrap();
        tick_on(&mut h, "2026-03-16");
        let head = h.db.frontier().unwrap();
        assert_eq!(
            sweep_with_history(&mut h, 1, &mut history)
                .unwrap()
                .unwrap(),
            None
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(history.as_ref().unwrap().verified_at(), head);
        let carried = history.as_ref().unwrap().read_work();
        assert_eq!((carried.snapshot_scans, carried.snapshot_rows), (0, 0));
        assert_eq!(carried.entries_decoded, 2);
        assert!(carried.delta_rows > 0);
        tail_work.push(carried);
        // Dropping process state requires a fresh authoritative reconstruction.
        history = None;
        assert_eq!(
            sweep_with_history(&mut h, 1, &mut history)
                .unwrap()
                .unwrap(),
            None
        );
        assert_eq!(history.as_ref().unwrap().read_work().snapshot_scans, 1);
    }
    assert_eq!(
        tail_work[0], tail_work[1],
        "the same tail is independent of prior book size"
    );
}

#[test]
fn recurring_history_refolds_creation_occurrence_and_cancellation() {
    let mut h = harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None);
    h.transition(
        &h.april.clone(),
        PeriodTransition::Open,
        b"recurring-history-april",
    )
    .unwrap();
    tick_on(&mut h, "2026-03-14");
    let mut history = None;
    assert_eq!(
        sweep_with_history(&mut h, 1, &mut history)
            .unwrap()
            .unwrap(),
        None
    );
    let definition = spec(&h, "cached-rent", "2026-03-15", "2026-04-15");
    let created = approved(&mut h, definition, &capability());
    tick_on(&mut h, "2026-03-15");
    let due = sweep_with_history(&mut h, 1, &mut history)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(due.posted.len(), 1);
    assert_eq!(
        due.posted[0].vid,
        recurring_occurrence_vid(created.schedule, 0)
    );
    assert_eq!(history.as_ref().unwrap().read_work().snapshot_scans, 1);
    assert_eq!(
        sweep_with_history(&mut h, 1, &mut history)
            .unwrap()
            .unwrap(),
        None
    );
    assert_eq!(history.as_ref().unwrap().read_work().snapshot_scans, 1);
    // Once the occurrence is verified, another idle cycle carries the prefix.
    assert_eq!(
        sweep_with_history(&mut h, 1, &mut history)
            .unwrap()
            .unwrap(),
        None
    );
    assert_eq!(history.as_ref().unwrap().read_work().snapshot_scans, 0);
    cancel(&mut h, "cached-rent");
    tick_on(&mut h, "2026-04-15");
    let head = h.db.frontier().unwrap();
    assert_eq!(
        sweep_with_history(&mut h, 1, &mut history)
            .unwrap()
            .unwrap(),
        None
    );
    assert_eq!(history.as_ref().unwrap().read_work().snapshot_scans, 1);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(
        h.db.vertex(recurring_occurrence_vid(created.schedule, 1))
            .unwrap()
            .is_none()
    );
    assert!(
        verify_recurring(&h.db, &h.ctx(), &h.book)
            .unwrap()
            .is_green()
    );
}

#[test]
fn recurring_history_cannot_carry_authority_past_creator_revocation() {
    let mut h = harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None);
    let cap = capability();
    let definition = spec(&h, "revoked-cache", "2026-03-31", "2026-03-31");
    approved(&mut h, definition, &cap);
    tick_on(&mut h, "2026-03-15");
    let mut history = None;
    assert_eq!(
        sweep_with_history(&mut h, 1, &mut history)
            .unwrap()
            .unwrap(),
        None
    );
    h.revoke(&cap, 99);
    tick_on(&mut h, "2026-03-31");
    let head = h.db.frontier().unwrap();
    let batch = sweep_with_history(&mut h, 1, &mut history)
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(batch.posted.is_empty());
    assert_eq!(batch.blocked.len(), 1);
    assert!(batch.blocked[0].refusal.message.contains("revoked"));
    assert_eq!(history.as_ref().unwrap().read_work().snapshot_scans, 0);
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn recurring_history_keeps_the_literal_fold_verdict_after_projection_or_prior_entry_damage() {
    for damage_schedule in [true, false] {
        let mut h = harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None);
        let proposal = h.proposal(h.rent_legs(200), b"prior-entry", EntryClass::ORIGINAL);
        let prior = h.post(h.request(proposal, &["post"])).unwrap().entry_ref();
        let definition = spec(&h, "damage-cache", "2026-03-31", "2026-03-31");
        let created = approved(&mut h, definition, &capability());
        tick_on(&mut h, "2026-03-15");
        let mut history = None;
        assert_eq!(
            sweep_with_history(&mut h, 1, &mut history)
                .unwrap()
                .unwrap(),
            None
        );
        let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
        if damage_schedule {
            damage.set_vertex_property(
                created.schedule,
                property::ORDINAL,
                Some(CanonicalScalar::Int(1)),
            );
        } else {
            damage.set_vertex_property(
                prior.vid,
                property::FA_PAYLOAD,
                Some(CanonicalScalar::Int(0)),
            );
        }
        h.write_raw(damage);
        let head = h.db.frontier().unwrap();
        let carried_error = sweep_with_history(&mut h, 1, &mut history).unwrap_err();
        let literal_error = sweep_with_history(&mut h, 1, &mut None).unwrap_err();
        assert_eq!(carried_error.to_string(), literal_error.to_string());
        assert!(
            history.is_none(),
            "failed reconstruction cannot leave a reusable prefix"
        );
        assert_eq!(h.db.frontier().unwrap(), head);
    }
}

#[test]
fn recurring_history_from_a_different_native_prefix_is_rebuilt() {
    let mut producer = harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None);
    let definition = spec(&producer, "first-book", "2026-03-31", "2026-03-31");
    approved(&mut producer, definition, &capability());
    tick_on(&mut producer, "2026-03-15");
    let mut history = None;
    assert_eq!(
        sweep_with_history(&mut producer, 1, &mut history)
            .unwrap()
            .unwrap(),
        None
    );

    // Same book id and same commit count, but a different schedule history.
    let mut consumer = harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None);
    let definition = spec(&consumer, "second-book", "2026-03-31", "2026-03-31");
    let created = approved(&mut consumer, definition, &capability());
    tick_on(&mut consumer, "2026-03-15");
    assert_eq!(consumer.book.book_id, producer.book.book_id);
    assert_eq!(
        consumer.db.frontier().unwrap(),
        history.as_ref().unwrap().verified_at()
    );
    assert_eq!(
        sweep_with_history(&mut consumer, 1, &mut history)
            .unwrap()
            .unwrap(),
        None
    );
    assert_eq!(history.as_ref().unwrap().read_work().snapshot_scans, 1);
    tick_on(&mut consumer, "2026-03-31");
    let due = sweep_with_history(&mut consumer, 1, &mut history)
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(due.posted.len(), 1);
    assert_eq!(
        due.posted[0].vid,
        recurring_occurrence_vid(created.schedule, 0)
    );
}
