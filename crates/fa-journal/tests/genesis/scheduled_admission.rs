//! Automatic accrual reversals obey native posting laws at execution.
use super::*;
use fa_journal::refusal::code;
use fa_journal::schedule::{ReversalBatch, ReversalStatus};
use fa_journal::usage::{UsageCell, UsageKey, verify_usage};
use fa_model::symbols::label;
use fgdb_types::CommitSeq;

fn april() -> DateDay {
    DateDay::from_ymd(2026, 4, 1).unwrap()
}

fn fixture() -> Harness {
    harness_configured(Vec::new(), Some(TimeZonePolicy::Utc), None)
}

fn accrue(h: &mut Harness, amount: i128, key: &[u8]) -> EntryRef {
    let proposal = with_auto_reverse(
        h.proposal(h.rent_legs(amount), key, EntryClass::ADJUSTING),
        april(),
    );
    h.post(h.request(proposal, &["post"])).unwrap().entry_ref()
}

fn zero_rent(h: &mut Harness, target: EntryRef) {
    // A separate original, not a cancellation: the schedule remains live.
    let mut offset = h.reversal_of_entry(target, b"offset-before-retirement");
    offset.class = EntryClass::ORIGINAL;
    offset.supersession.clear();
    h.post(h.request(offset, &["post"])).unwrap();
}

fn close_rent(h: &mut Harness, closed_on: DateDay) {
    let ctx = h.ctx();
    let description = h.statement("retire zero-balance rent", 115);
    let day = h.day();
    h.runtime
        .block_on(close_account(
            &mut h.db,
            &ctx,
            &h.book,
            "6000",
            closed_on,
            PRINCIPAL,
            day,
            b"retire-rent-before-reversal",
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
}

fn tick(h: &mut Harness, day: DateDay, nonce: u8) {
    let ns = u64::try_from(day.0).unwrap() * 86_400_000_000_000 + u64::from(nonce);
    h.tick(ns, &[b'a', nonce], nonce);
}

fn executor(h: &Harness) -> Capability {
    let system = fa_journal::rows::system_principal(h.book.book_id);
    Capability::new(system, Profile::System, &[Op::Post], PRINCIPAL).unwrap()
}

fn sweep(h: &mut Harness, capability: Capability) -> Result<Option<ReversalBatch>, Refusal> {
    let ctx = h.ctx();
    let req = SweepRequest {
        principal_ref: capability.holder(),
        capability,
        max_batch: 16,
    };
    let book = &h.book;
    let mut describe = |text: &str| {
        Ok(Erasable::seal(
            &text.to_string(),
            None,
            &book.seal_key,
            [117; 32],
            [118; 24],
        ))
    };
    h.runtime
        .block_on(fa_journal::schedule::sweep_reversals_batch(
            &mut h.db,
            &ctx,
            book,
            &req,
            &mut describe,
        ))
        .unwrap()
}

fn open(h: &mut Harness, capability: &Capability, key: &[u8]) -> Result<Transitioned, Refusal> {
    let ctx = h.ctx();
    let description = h.statement("open with governed reversals", 119);
    h.runtime
        .block_on(transition_period(
            &mut h.db,
            &ctx,
            &h.book,
            &h.april,
            PeriodTransition::Open,
            capability.holder(),
            1,
            key,
            description,
            capability,
            &[],
        ))
        .unwrap()
}

fn closer() -> Capability {
    Capability::embedded(PRINCIPAL, &["close", "post"]).unwrap()
}

fn issue_quota(h: &mut Harness, capability: Capability, limit: i128) -> Capability {
    let capability = capability
        .holder_bound(fa_policy::possession_digest(&[120; 32]))
        .with_daily_total(h.usd, limit)
        .unwrap();
    let ctx = h.ctx();
    let request = fa_journal::policy::IssuanceRequest {
        capability: Capability::embedded(PRINCIPAL, &["issue_capability", "post", "close"])
            .unwrap(),
        issued: capability.clone(),
        effective_date: h.day(),
        idempotency_key: format!("schedule-quota-{limit}-{:032x}", capability.holder().0)
            .into_bytes(),
        description: h.statement("issue scheduled execution quota", 120),
    };
    h.runtime
        .block_on(fa_journal::policy::issue_capability(
            &mut h.db, &ctx, &h.book, request,
        ))
        .unwrap()
        .unwrap();
    capability
}

fn usage_key(h: &Harness, capability: &Capability, day: DateDay) -> UsageKey {
    UsageKey {
        book_id: h.book.book_id,
        root_issuance: capability.commitment().unwrap(),
        day,
        unit: h.usd,
    }
}

#[test]
fn retired_account_blocks_both_execution_paths_and_open_retry_preserves_its_reason() {
    for via_open in [false, true] {
        let mut h = fixture();
        let target = accrue(&mut h, 100, b"retiring-accrual");
        zero_rent(&mut h, target);
        if !via_open {
            open(&mut h, &closer(), b"open-before-due").unwrap();
        }
        close_rent(&mut h, april());
        tick(&mut h, april(), 121);
        let reason = if via_open {
            let result = open(&mut h, &closer(), b"open-retired").unwrap();
            assert!(result.minted.is_empty());
            assert_eq!(result.blocked.len(), 1);
            assert_eq!(result.blocked[0].0, target);
            // Advance history. A retry must retain the original block even
            // after its tick and the surrounding history have moved.
            tick(&mut h, DateDay(april().0 + 1), 122);
            let head = h.db.frontier().unwrap();
            let retry = open(
                &mut h,
                &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
                b"open-retired",
            )
            .unwrap();
            assert!(retry.already_recorded);
            assert_eq!(retry.blocked, result.blocked);
            assert_eq!(retry.minted, result.minted);
            assert_eq!(h.db.frontier().unwrap(), head);
            result.blocked[0].1.clone()
        } else {
            let due = due_reversals(&h.db, &h.book).unwrap();
            assert!(matches!(&due[0].status, ReversalStatus::Blocked { row, .. }
                if row.contains("outside its effective interval")));
            let cap = executor(&h);
            let result = sweep(&mut h, cap).unwrap().unwrap();
            assert!(result.minted.is_empty());
            assert_eq!(result.blocked.len(), 1);
            result.blocked[0].1.clone()
        };
        assert!(reason.contains(code::NOT_A_LEAF), "{reason}");
        assert!(
            reason.contains("outside its effective interval"),
            "{reason}"
        );
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
        assert!(verify_schedules(&h.db, &h.book).unwrap().is_green());
    }
}

#[test]
fn account_effectivity_is_judged_at_reversal_date_and_close_races_conflict() {
    let mut h = fixture();
    let target = accrue(&mut h, 100, b"pre-close-reversal");
    zero_rent(&mut h, target);
    close_rent(&mut h, DateDay(april().0 + 1));
    tick(&mut h, april(), 123);
    let result = open(&mut h, &closer(), b"open-valid-historical-account").unwrap();
    assert_eq!(result.minted.len(), 1);
    assert_eq!(result.minted[0].0, target);
    assert!(result.blocked.is_empty());
    assert!(verify_schedules(&h.db, &h.book).unwrap().is_green());

    let mut h = fixture();
    let target = accrue(&mut h, 100, b"racing-account-close");
    zero_rent(&mut h, target);
    tick(&mut h, april(), 124);
    let ctx = h.ctx();
    let description = h.statement("prepared Open", 125);
    let prepared = fa_journal::period::prepare_transition(
        &mut h.db,
        &ctx,
        &h.book,
        &h.april,
        PeriodTransition::Open,
        PRINCIPAL,
        1,
        b"race-open",
        description,
        &closer(),
        &[],
    )
    .unwrap()
    .unwrap();
    close_rent(&mut h, april());
    let head = h.db.frontier().unwrap();
    let refusal = h
        .runtime
        .block_on(prepared.commit(&mut h.db, &ctx))
        .unwrap()
        .unwrap_err();
    assert_eq!(
        (refusal.code, refusal.exit),
        (code::CONFLICT, exit::CONFLICT)
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.period_state(&h.april), PeriodState::Future);
    assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
}

#[test]
fn automatic_effects_enforce_post_ceiling_class_scope_dry_run_and_revocation() {
    let mut h = fixture();
    let target = accrue(&mut h, 100, b"governed-accrual");
    tick(&mut h, april(), 126);
    let head = h.db.frontier().unwrap();
    let denied = [
        Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
        closer().with_ceiling(h.usd, 99).unwrap(),
        closer().for_classes(&[EntryClass::ORIGINAL]).unwrap(),
        closer().for_accounts(&["6000"]).unwrap(),
        closer().for_periods(&[h.april.as_str()]).unwrap(),
        closer().effective_through(DateDay(april().0 - 1)),
        closer().with_requires_dry_run(),
    ];
    for (n, cap) in denied.iter().enumerate() {
        assert!(open(&mut h, cap, format!("denied-open-{n}").as_bytes()).is_err());
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.period_state(&h.april), PeriodState::Future);
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    }
    // No due effects are hidden by moving the period first: use a separate
    // fixture whose period was opened before the committed tick.
    let mut h = fixture();
    let target = accrue(&mut h, 100, b"bounded-sweep-accrual");
    open(&mut h, &closer(), b"sweep-period").unwrap();
    for (nonce, cap) in [
        (127, executor(&h).with_ceiling(h.usd, 99).unwrap()),
        (
            128,
            executor(&h).for_classes(&[EntryClass::ORIGINAL]).unwrap(),
        ),
        (129, executor(&h).with_requires_dry_run()),
    ] {
        tick(&mut h, april(), nonce);
        let result = sweep(&mut h, cap).unwrap().unwrap();
        assert!(result.minted.is_empty());
        assert_eq!(result.blocked.len(), 1);
        assert_eq!(result.blocked[0].0, target);
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    }
    let cap = executor(&h);
    h.revoke(&cap, 130);
    tick(&mut h, april(), 131);
    let head = h.db.frontier().unwrap();
    assert!(sweep(&mut h, cap).is_err());
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn one_sweep_shares_daily_budget_across_reversals_and_keeps_processing_after_a_block() {
    let mut h = fixture();
    let first = accrue(&mut h, 60, b"quota-first");
    let second = accrue(&mut h, 60, b"quota-second");
    let third = accrue(&mut h, 30, b"quota-third");
    open(&mut h, &closer(), b"open-before-budget-tick").unwrap();
    let cap = executor(&h);
    let cap = issue_quota(&mut h, cap, 100);
    tick(&mut h, april(), 132);
    let result = sweep(&mut h, cap.clone()).unwrap().unwrap();
    assert_eq!(
        result.minted.iter().map(|p| p.0).collect::<Vec<_>>(),
        [first, third]
    );
    assert_eq!(result.blocked.len(), 1);
    assert_eq!(result.blocked[0].0, second);
    assert!(result.blocked[0].1.contains(code::DAILY_CEILING));
    let key = usage_key(&h, &cap, april());
    let cell = UsageCell::from_row(&h.db.vertex(key.cell_vid()).unwrap().unwrap(), key).unwrap();
    assert_eq!((cell.gross_debits, cell.generation), (90, 2));
    let head = h.db.frontier().unwrap();
    assert_eq!(sweep(&mut h, cap.clone()).unwrap(), None);
    assert_eq!(h.db.frontier().unwrap(), head);
    // A newly committed day permits the outstanding exact reversal without
    // refunding or rewriting any previous usage.
    tick(&mut h, DateDay(april().0 + 1), 133);
    let next = sweep(&mut h, cap.clone()).unwrap().unwrap();
    assert_eq!(next.minted.len(), 1);
    assert_eq!(next.minted[0].0, second);
    assert!(next.blocked.is_empty());
    let report = verify_usage(&h.db, &h.ctx(), &h.book, None).unwrap();
    assert!(report.is_green(), "{:?}", report.drift);
    assert_eq!((report.charges_checked, report.cells_checked), (3, 2));
}

#[test]
fn opening_with_insufficient_daily_budget_rolls_back_all_effects_and_usage() {
    let mut h = fixture();
    let first = accrue(&mut h, 60, b"open-quota-first");
    let second = accrue(&mut h, 60, b"open-quota-second");
    let too_small = issue_quota(&mut h, closer(), 100);
    tick(&mut h, april(), 134);
    let head = h.db.frontier().unwrap();
    let refusal = open(&mut h, &too_small, b"open-budget-atomic").unwrap_err();
    assert_eq!(refusal.code, code::DAILY_CEILING);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.period_state(&h.april), PeriodState::Future);
    assert!(
        h.db.vertex(usage_key(&h, &too_small, april()).cell_vid())
            .unwrap()
            .is_none()
    );
    for target in [first, second] {
        assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
    }
    assert!(
        !h.db
            .vertices()
            .unwrap()
            .iter()
            .any(|r| r.labels.contains(&label::USAGE_DEBIT))
    );
    // The explicitly issued larger authorization makes the same requested
    // atomic Open possible; its System entries charge the real Human actor.
    let cap = issue_quota(&mut h, closer(), 150);
    let result = open(&mut h, &cap, b"open-budget-atomic").unwrap();
    assert_eq!(result.minted.len(), 2);
    assert!(result.blocked.is_empty());
    let key = usage_key(&h, &cap, april());
    let cell = UsageCell::from_row(&h.db.vertex(key.cell_vid()).unwrap().unwrap(), key).unwrap();
    assert_eq!((cell.gross_debits, cell.generation), (120, 2));
    let report = verify_usage(&h.db, &h.ctx(), &h.book, None).unwrap();
    assert!(report.is_green(), "{:?}", report.drift);
    assert_eq!(report.charges_checked, 2);
    let head = h.db.frontier().unwrap();
    let retry = open(
        &mut h,
        &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
        b"open-budget-atomic",
    )
    .unwrap();
    assert_eq!(retry.minted, result.minted);
    assert!(retry.already_recorded);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(
        verify_usage(&h.db, &h.ctx(), &h.book, Some(CommitSeq(head.0)))
            .unwrap()
            .charges_checked,
        2
    );
}
