use super::*;
use fa_journal::limit::{LimitCell, LimitScope, cell_vid};
use fa_journal::migration::{self, RunBody, RunControlRequest, RunControlled, RunMode, RunState};

fn limited(scope: LimitScope) -> Harness {
    let mut h = harness_configured(
        Vec::new(),
        None,
        Some(BalanceLimit {
            lower: Some(0),
            upper: Some(1_000),
            scope,
        }),
    );
    // This fixture has no opening_date, so its Opening period is born
    // Future. Migration requires the real, dual-controlled Locked state.
    let period = opening(&h);
    for (i, transition) in [
        PeriodTransition::Open,
        PeriodTransition::SoftClose,
        PeriodTransition::Close,
        PeriodTransition::Lock,
    ]
    .into_iter()
    .enumerate()
    {
        h.transition(
            &period,
            transition,
            format!("migration-opening-{i}").as_bytes(),
        )
        .expect("the opening period is locked through journaled transitions");
    }
    h
}

fn cell(h: &Harness, period: Option<&str>) -> LimitCell {
    LimitCell::decode_bound(
        &h.db.vertex(cell_vid(h.cash, period)).unwrap().unwrap(),
        h.cash,
        period,
    )
    .unwrap()
}

fn opening(h: &Harness) -> String {
    h.book
        .calendar
        .periods_for_year(2026)
        .unwrap()
        .into_iter()
        .find(|p| p.kind == PeriodKind::Opening)
        .unwrap()
        .code
}

fn cash_legs(h: &Harness, delta: i128) -> Vec<LegPayload> {
    let (cash_side, revenue_side) = if delta > 0 {
        (Side::Debit, Side::Credit)
    } else {
        (Side::Credit, Side::Debit)
    };
    vec![
        LegPayload::simple(cash_side, h.cash, Amount::new(h.usd, delta.abs())),
        LegPayload::simple(revenue_side, h.revenue, Amount::new(h.usd, delta.abs())),
    ]
}

fn open(h: &mut Harness, key: &str, lines: &[(&str, i128)]) -> VId {
    let body = RunBody {
        book_id: h.book.book_id,
        run_key: key.into(),
        source_system: "legacy-limits".into(),
        mode: RunMode::OpeningOnly,
        trial_balance: h.evidence[0].document_oid,
        opening_date: DateDay::from_ymd(2026, 1, 1).unwrap(),
        lines: lines
            .iter()
            .map(|(account, mantissa)| migration::TrialBalanceLine {
                account_code: (*account).into(),
                unit: h.usd,
                mantissa: *mantissa,
            })
            .collect(),
        periods: Vec::new(),
        detail_base: Vec::new(),
        sole_opening_source: false,
    };
    let proposal = migration::open_proposal(
        &h.book,
        PRINCIPAL,
        &body,
        h.evidence.clone(),
        format!("open-{key}").as_bytes(),
        h.statement("open legacy limits", 41),
    )
    .unwrap();
    let request = RunControlRequest {
        proposal,
        capability: Capability::embedded(PRINCIPAL, &["migrate"]).unwrap(),
        approvals: Vec::new(),
    };
    let ctx = h.ctx();
    h.runtime
        .block_on(migration::open_run(
            &mut h.db, &ctx, &h.book, &body, request,
        ))
        .unwrap()
        .unwrap()
        .run
}

fn chunk(h: &Harness, run: VId, legs: Vec<LegPayload>, key: &[u8]) -> EntryPayload {
    let mut proposal = h.proposal(legs, key, EntryClass::MIGRATION);
    proposal.effective_date = DateDay::from_ymd(2026, 1, 1).unwrap();
    proposal.effective_period = Some(fa_model::PeriodRef {
        calendar: h.book.calendar.id.clone(),
        code: opening(h),
    });
    proposal.origin = EntryOrigin::Migration {
        run_ref: run,
        source_system: "legacy-limits".into(),
        source_id: h.statement(&String::from_utf8_lossy(key), 42),
        source_recorded_at_ns: None,
        source_entered_by: None,
        source_approved_by: None,
        batch_oid: h.evidence[0].document_oid,
    };
    proposal
}

fn approvals(h: &mut Harness, proposal: &EntryPayload) -> Vec<fa_model::ApprovalRef> {
    let digest = proposal.proposal_digest().unwrap();
    [VId(70), VId(71)]
        .into_iter()
        .map(|who| h.approve_digest(who, digest).unwrap())
        .collect()
}

fn stage(h: &mut Harness, proposal: EntryPayload) -> Result<Posted, Refusal> {
    let approvals = approvals(h, &proposal);
    let mut request = h.request(proposal, &["post", "migrate"]);
    request.approvals = approvals;
    h.post(request)
}

fn control(h: &mut Harness, run: VId, kind: u8, key: &[u8]) -> RunControlRequest {
    let proposal = migration::plan_run_transition(
        &h.db,
        &h.book,
        run,
        kind,
        PRINCIPAL,
        key,
        h.statement("activate legacy limits", 43),
    )
    .unwrap()
    .unwrap();
    let approvals = if kind == migration::kind::FINALIZE {
        approvals(h, &proposal)
    } else {
        Vec::new()
    };
    RunControlRequest {
        proposal,
        capability: Capability::embedded(PRINCIPAL, &["post", "migrate"]).unwrap(),
        approvals,
    }
}

fn transition(h: &mut Harness, request: RunControlRequest) -> Result<RunControlled, Refusal> {
    let ctx = h.ctx();
    h.runtime
        .block_on(migration::transition_run(&mut h.db, &ctx, &h.book, request))
        .expect("migration kernel")
}

#[test]
fn activation_aggregates_staged_chunks_and_preserves_live_reservations() {
    let mut h = limited(LimitScope::Lifetime);
    let deposit = h.proposal(cash_legs(&h, 500), b"live-deposit", EntryClass::ORIGINAL);
    h.post(h.request(deposit, &["post"])).unwrap();
    let held = h.pending(h.rent_legs(150), b"live-reservation");
    h.post(h.request(held, &["post"])).unwrap();
    let before = cell(&h, None);
    let before_seq = h.db.frontier().unwrap();
    let run = open(&mut h, "aggregate", &[("1000", 200), ("4000", -200)]);
    // Each staging prefix would violate a bound if judged as live money.
    let outflow = chunk(&h, run, cash_legs(&h, -700), b"chunk-out");
    let first = stage(&mut h, outflow.clone()).unwrap();
    assert_eq!(cell(&h, None), before);
    assert_eq!(
        stage(&mut h, outflow).unwrap().entry_ref(),
        first.entry_ref()
    );
    let inflow = chunk(&h, run, cash_legs(&h, 900), b"chunk-in");
    stage(&mut h, inflow).unwrap();
    assert_eq!(cell(&h, None), before, "staging does not reserve or post");

    let finalize = control(
        &mut h,
        run,
        migration::kind::FINALIZE,
        b"finalize-aggregate",
    );
    let committed = transition(&mut h, finalize.clone()).unwrap();
    let after = cell(&h, None);
    assert_eq!((after.debits_posted, after.credits_posted), (1_400, 700));
    assert_eq!((after.debits_pending, after.credits_pending), (0, 150));
    assert_eq!(after.generation, before.generation + 1);
    assert_eq!(committed.to, RunState::Finalized);
    assert_eq!(
        LimitCell::decode_bound(
            &h.db
                .vertex_at(cell_vid(h.cash, None), before_seq)
                .unwrap()
                .unwrap(),
            h.cash,
            None,
        )
        .unwrap(),
        before,
        "activation never rewrites historical availability"
    );
    let frontier = h.db.frontier().unwrap();
    assert!(transition(&mut h, finalize).unwrap().already_recorded);
    assert_eq!(h.db.frontier().unwrap(), frontier);
    assert_eq!(
        cell(&h, None),
        after,
        "Finalize retry has no monetary effect"
    );
}

#[test]
fn activation_checks_pending_inflows_and_can_retry_after_the_hold_is_released() {
    let mut h = limited(LimitScope::Lifetime);
    let deposit = h.proposal(cash_legs(&h, 200), b"existing-cash", EntryClass::ORIGINAL);
    h.post(h.request(deposit, &["post"])).unwrap();
    let held = h.pending(cash_legs(&h, 200), b"pending-cash");
    let hold = h.post(h.request(held, &["post"])).unwrap().entry_ref();
    let run = open(&mut h, "upper", &[("1000", 700), ("4000", -700)]);
    let staged = chunk(&h, run, cash_legs(&h, 700), b"upper-chunk");
    stage(&mut h, staged).unwrap();
    let finalize = control(&mut h, run, migration::kind::FINALIZE, b"finalize-upper");
    let before = cell(&h, None);
    let frontier = h.db.frontier().unwrap();
    let refused = transition(&mut h, finalize.clone()).unwrap_err();
    assert_eq!(refused.code, "FA-REF-091", "{refused}");
    assert_eq!(h.db.frontier().unwrap(), frontier);
    assert_eq!(cell(&h, None), before);
    assert_eq!(
        migration::read_run(&h.db, run, None)
            .unwrap()
            .unwrap()
            .state,
        RunState::Open
    );
    let control_vid = entry_vid(
        h.book.book_id,
        &PRINCIPAL.0.to_le_bytes(),
        b"finalize-upper",
    );
    assert!(read_entry(&h.db, control_vid).unwrap().is_none());

    let release = h.resolution_voids(hold, b"release-cash");
    h.post(h.request(release, &["post"])).unwrap();
    transition(&mut h, finalize).unwrap();
    let after = cell(&h, None);
    assert_eq!((after.debits_posted, after.debits_pending), (900, 0));
    assert_eq!(after.generation, before.generation + 2);
}

#[test]
fn activation_lower_bound_refusal_and_abandon_leave_cells_unchanged() {
    let mut h = limited(LimitScope::Lifetime);
    let deposit = h.proposal(cash_legs(&h, 500), b"lower-cash", EntryClass::ORIGINAL);
    h.post(h.request(deposit, &["post"])).unwrap();
    let held = h.pending(h.rent_legs(200), b"lower-reservation");
    h.post(h.request(held, &["post"])).unwrap();
    let run = open(&mut h, "lower", &[("1000", -400), ("4000", 400)]);
    let staged = chunk(&h, run, cash_legs(&h, -400), b"lower-chunk");
    stage(&mut h, staged).unwrap();
    let before = cell(&h, None);
    let finalize = control(&mut h, run, migration::kind::FINALIZE, b"finalize-lower");
    assert_eq!(transition(&mut h, finalize).unwrap_err().code, "FA-REF-090");
    assert_eq!(cell(&h, None), before);
    let abandon = control(&mut h, run, migration::kind::ABANDON, b"abandon-lower");
    assert_eq!(
        transition(&mut h, abandon.clone()).unwrap().to,
        RunState::Abandoned
    );
    assert!(transition(&mut h, abandon).unwrap().already_recorded);
    assert_eq!(cell(&h, None), before);
    let late = chunk(&h, run, cash_legs(&h, 1), b"abandoned-chunk");
    assert_eq!(stage(&mut h, late).unwrap_err().code, "FA-REF-130");
}

#[test]
fn activation_uses_each_chunks_period_cell_and_the_existing_opening_balance() {
    let mut h = limited(LimitScope::Period);
    let opening = opening(&h);
    let march = h.march.clone();
    let current = h.proposal(cash_legs(&h, 900), b"march-cash", EntryClass::ORIGINAL);
    h.post(h.request(current, &["post"])).unwrap();
    let march_before = cell(&h, Some(&march));
    let run = open(&mut h, "period-a", &[("1000", 600), ("4000", -600)]);
    let staged = chunk(&h, run, cash_legs(&h, 600), b"period-chunk-a");
    stage(&mut h, staged).unwrap();
    assert_eq!(cell(&h, Some(&opening)), LimitCell::default());
    let finalize = control(&mut h, run, migration::kind::FINALIZE, b"finalize-period-a");
    transition(&mut h, finalize).unwrap();
    assert_eq!(cell(&h, Some(&march)), march_before);
    let opening_before = cell(&h, Some(&opening));
    assert_eq!(
        (opening_before.debits_posted, opening_before.generation),
        (600, 1)
    );

    let other = open(&mut h, "period-b", &[("1000", 500), ("4000", -500)]);
    let staged = chunk(&h, other, cash_legs(&h, 500), b"period-chunk-b");
    stage(&mut h, staged).unwrap();
    let finalize = control(
        &mut h,
        other,
        migration::kind::FINALIZE,
        b"finalize-period-b",
    );
    let refused = transition(&mut h, finalize).unwrap_err();
    assert_eq!(refused.code, "FA-REF-091");
    assert!(refused.message.contains(&opening), "{refused}");
    assert_eq!(cell(&h, Some(&opening)), opening_before);
    assert_eq!(cell(&h, Some(&march)), march_before);
}

#[test]
fn zero_net_activation_moves_gross_totals_and_invalidates_a_prepared_cell_witness() {
    let mut h = limited(LimitScope::Lifetime);
    let deposit = h.proposal(cash_legs(&h, 500), b"race-cash", EntryClass::ORIGINAL);
    h.post(h.request(deposit, &["post"])).unwrap();
    let run = open(&mut h, "zero-net", &[("1200", 10), ("4000", -10)]);
    for (key, amount) in [(b"zero-in".as_slice(), 100), (b"zero-out".as_slice(), -100)] {
        let staged = chunk(&h, run, cash_legs(&h, amount), key);
        stage(&mut h, staged).unwrap();
    }
    let invoice = chunk(
        &h,
        run,
        h.invoice(10, b"zero-invoice").legs,
        b"zero-invoice",
    );
    stage(&mut h, invoice).unwrap();
    let finalize = control(&mut h, run, migration::kind::FINALIZE, b"finalize-zero");
    let spend = h.proposal(h.rent_legs(100), b"stale-spend", EntryClass::ORIGINAL);
    let request = h.request(spend, &["post"]);
    let ctx = h.ctx();
    let PostPreparation::Ready(prepared) = prepare_post(&mut h.db, &ctx, &h.book, request)
        .unwrap()
        .unwrap()
    else {
        panic!("the distinct spend must be a fresh preparation");
    };
    let before = cell(&h, None);
    transition(&mut h, finalize).unwrap();
    let after = cell(&h, None);
    assert_eq!((after.debits_posted, after.credits_posted), (600, 100));
    assert_eq!(after.generation, before.generation + 1);
    let frontier = h.db.frontier().unwrap();
    let refused = h
        .runtime
        .block_on(prepared.commit(&mut h.db, &ctx))
        .unwrap()
        .unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-030", exit::CONFLICT));
    assert_eq!(h.db.frontier().unwrap(), frontier);
    assert_eq!(cell(&h, None), after);
    let spend_vid = entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), b"stale-spend");
    assert!(read_entry(&h.db, spend_vid).unwrap().is_none());
}

#[test]
fn activation_refuses_a_gross_ceiling_even_when_every_chunk_and_the_net_tie_out_fit() {
    let mut h = limited(LimitScope::Lifetime);
    let run = open(&mut h, "gross-ceiling", &[("1200", 1), ("4000", -1)]);
    let amount = i128::MAX / 2 + 1;
    for key in [b"gross-a".as_slice(), b"gross-b".as_slice()] {
        let legs = vec![
            LegPayload::simple(Side::Debit, h.cash, Amount::new(h.usd, amount)),
            LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, amount)),
        ];
        let staged = chunk(&h, run, legs, key);
        stage(&mut h, staged).unwrap();
    }
    let invoice = chunk(
        &h,
        run,
        h.invoice(1, b"gross-invoice").legs,
        b"gross-invoice",
    );
    stage(&mut h, invoice).unwrap();
    let finalize = control(&mut h, run, migration::kind::FINALIZE, b"finalize-gross");
    let frontier = h.db.frontier().unwrap();
    let refused = transition(&mut h, finalize).unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-092", exit::REFUSAL));
    assert_eq!(h.db.frontier().unwrap(), frontier);
    assert_eq!(cell(&h, None), LimitCell::default());
    assert_eq!(
        migration::read_run(&h.db, run, None)
            .unwrap()
            .unwrap()
            .state,
        RunState::Open
    );
}
