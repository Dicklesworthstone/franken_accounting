//! fa-1tvm: a procedure runs under its meter, which refuses the charge past
//! the run's budget and observes the caller's cancellation inside the run.
//! A stopped run returns no finding, even when the procedure discards the
//! refused charge.

use std::cell::Cell;

use super::*;
use fa_lantern::{CANCELLATION_INTERVAL, Cancellation, run_over_metered};

/// Charges one comparison per step for up to `steps` steps, counting the
/// steps it took; `cancel_after` raises `cancel` once that many steps ran
/// (the caller's cancellation arriving mid-run). With `discard`, a refused
/// charge is ignored and the procedure keeps going, then reports a finding.
struct Loop<'a> {
    params: Params,
    steps: u64,
    taken: &'a Cell<u64>,
    cancel_after: Option<(u64, &'a Cell<bool>)>,
    /// Test injection of the caller's real runtime cancellation during a run.
    context_cancel_after: Option<(u64, &'a Cx)>,
    discard: bool,
}

impl<'a> Loop<'a> {
    fn new(steps: u64, taken: &'a Cell<u64>) -> Self {
        Self {
            params: Params::defaults("jet.weekend").unwrap(),
            steps,
            taken,
            cancel_after: None,
            context_cancel_after: None,
            discard: false,
        }
    }
}

impl Procedure for Loop<'_> {
    fn id(&self) -> &'static str {
        "jet.weekend"
    }
    fn version(&self) -> u16 {
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        _book: &BookContext,
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        for step in 0..self.steps {
            if let Some((after, cancel)) = self.cancel_after
                && step == after
            {
                cancel.set(true);
            }
            if let Some((after, root)) = self.context_cancel_after
                && step == after
            {
                root.set_cancel_requested(true);
            }
            self.taken.set(self.taken.get() + 1);
            if self.discard {
                let _ = work.compare(1);
            } else {
                work.compare(1)?;
            }
        }
        let first = snapshot
            .entries
            .iter()
            .find(|e| e.posts())
            .expect("a posting");
        Ok(vec![Finding {
            procedure: "jet.weekend".into(),
            version: 1,
            severity: Severity::Low,
            statistic: Statistic::count("steps", self.steps, self.steps.max(1)),
            cites: vec![Cite::Entry(first.vid)],
            narrative: "ran every step".into(),
        }])
    }
}

/// The caller's context as the meter sees it.
struct Flag<'a>(&'a Cell<bool>);

impl Cancellation for Flag<'_> {
    fn cancelled(&self) -> bool {
        self.0.get()
    }
}

#[test]
fn snapshot_cancellation_precedes_selection_and_returns_no_snapshot() {
    let (h, _) = posted_corpus();
    let before = h.db.frontier().unwrap();
    let future = CommitSeq(before.0.checked_add(1).unwrap());
    let cx = h.ctx().query();
    assert!(matches!(
        Snapshot::read(&h.db, &cx, &h.book, Some(future), None),
        Err(LanternError::Register(
            fa_registers::RegisterError::InvalidSelection(_)
        ))
    ));

    h.root.set_cancel_requested(true);
    for selection in [None, Some(future)] {
        let error = Snapshot::read(&h.db, &cx, &h.book, selection, None)
            .expect_err("cancelled acquisition must stop before selecting a storage prefix");
        assert!(
            matches!(
                error,
                LanternError::Kernel(KernelError::Txn(fgdb::WriteTxnError::Interrupted(_)))
            ),
            "{error:?}"
        );
    }
    assert_eq!(h.db.frontier().unwrap(), before);

    h.root.set_cancel_requested(false);
    let snapshot = Snapshot::read(&h.db, &cx, &h.book, None, None).unwrap();
    assert_eq!(snapshot.coordinate.known_at, before);
    assert!(snapshot.entries.iter().any(|entry| entry.posts()));
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn direct_library_run_carries_context_cancellation_into_the_procedure() {
    let (h, _) = posted_corpus();
    let before = h.db.frontier().unwrap();
    let cx = h.ctx().query();
    let taken = Cell::new(0);
    let mut procedure = Loop::new(20, &taken);
    procedure.context_cancel_after = Some((5, &h.root));
    let error = run(&h.db, &cx, &h.book, None, None, &procedure)
        .expect_err("the direct read-and-run API must retain the caller's cancellation source");
    assert!(
        matches!(error, LanternError::Cancelled { used: 20, .. }),
        "{error:?}"
    );
    assert_eq!(taken.get(), 20);
    assert_eq!(h.db.frontier().unwrap(), before);

    h.root.set_cancel_requested(false);
    procedure.context_cancel_after = None;
    taken.set(0);
    let complete = run(&h.db, &cx, &h.book, None, None, &procedure).unwrap();
    assert_eq!(taken.get(), 20);
    let snapshot = Snapshot::read(&h.db, &cx, &h.book, None, None).unwrap();
    let unmetered = run_over(&snapshot, &h.book, &procedure).unwrap();
    assert_eq!(complete.findings_digest, unmetered.findings_digest);
    assert_eq!(complete.work, unmetered.work);
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn budget_exhaustion_refuses_mid_run() {
    let (h, _) = posted_corpus();
    let snapshot = h.snapshot();
    let taken = Cell::new(0);
    let err = run_over_metered(
        &snapshot,
        &h.book,
        &Loop::new(1_000_000, &taken),
        Some(100),
        None,
    )
    .expect_err("a run past its budget is refused");
    assert!(
        matches!(&err, LanternError::BudgetExhausted { procedure, used: 101, budget: 100, .. }
            if procedure == "jet.weekend"),
        "{err:?}"
    );
    // It stopped at the charge past the budget, not after a million steps.
    assert_eq!(taken.get(), 101);
    assert!(err.fix_hint().is_some_and(|f| f.contains("work budget")));

    // Within its budget the same run completes with its finding.
    let taken = Cell::new(0);
    let run = run_over_metered(&snapshot, &h.book, &Loop::new(100, &taken), Some(100), None)
        .expect("a run within its budget completes");
    assert_eq!(run.findings.len(), 1);
    assert_eq!(run.work.comparisons, 100);
}

/// Planted: a procedure that discards a refused charge and reports a
/// finding anyway is still refused, and its finding never escapes.
#[test]
fn a_discarded_refused_charge_still_refuses_the_run() {
    let (h, _) = posted_corpus();
    let snapshot = h.snapshot();
    let taken = Cell::new(0);
    let mut procedure = Loop::new(1_000, &taken);
    procedure.discard = true;
    let err = run_over_metered(&snapshot, &h.book, &procedure, Some(10), None)
        .expect_err("the discarded refusal still refuses the run");
    assert!(
        matches!(
            err,
            LanternError::BudgetExhausted {
                used: 11,
                budget: 10,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(taken.get(), 1_000, "the procedure ignored the refusal");
}

#[test]
fn cancellation_is_observed_inside_run() {
    let (h, _) = posted_corpus();
    let snapshot = h.snapshot();

    // Cancelled before the run: refuse before entering the procedure.
    let cancel = Cell::new(true);
    let taken = Cell::new(0);
    let err = run_over_metered(
        &snapshot,
        &h.book,
        &Loop::new(1_000_000, &taken),
        None,
        Some(&Flag(&cancel)),
    )
    .expect_err("a cancelled caller stops the run");
    assert!(
        matches!(&err, LanternError::Cancelled { procedure, used: 0 } if procedure == "jet.weekend"),
        "{err:?}"
    );
    assert_eq!(taken.get(), 0);

    // Cancelled mid-run: observed within one checkpoint interval.
    let cancel = Cell::new(false);
    let taken = Cell::new(0);
    let mut procedure = Loop::new(1_000_000, &taken);
    procedure.cancel_after = Some((5_000, &cancel));
    let err = run_over_metered(&snapshot, &h.book, &procedure, None, Some(&Flag(&cancel)))
        .expect_err("cancellation arriving mid-run stops it");
    let LanternError::Cancelled { used, .. } = err else {
        panic!("{err:?}");
    };
    assert!(
        used > 5_000 && used <= 5_000 + CANCELLATION_INTERVAL,
        "observed at {used}"
    );
    assert_eq!(taken.get(), used);

    // Never cancelled: the run completes.
    let cancel = Cell::new(false);
    let taken = Cell::new(0);
    let run = run_over_metered(
        &snapshot,
        &h.book,
        &Loop::new(10_000, &taken),
        None,
        Some(&Flag(&cancel)),
    )
    .expect("an uncancelled run completes");
    assert_eq!(run.findings.len(), 1);
}

#[test]
fn cancellation_refuses_an_empty_native_procedure_without_a_work_charge() {
    let h = harness();
    let before = h.db.frontier().unwrap();
    let snapshot = h.snapshot();
    assert!(!snapshot.entries.iter().any(|entry| entry.posts()));
    let procedure = Weekend::new().unwrap();
    let cancelled = Cell::new(true);
    let error = run_over_metered(
        &snapshot,
        &h.book,
        &procedure,
        None,
        Some(&Flag(&cancelled)),
    )
    .expect_err("an empty procedure must still observe its cancelled caller");
    assert!(
        matches!(error, LanternError::Cancelled { used: 0, .. }),
        "{error:?}"
    );
    assert_eq!(h.db.frontier().unwrap(), before);

    cancelled.set(false);
    let complete = run_over_metered(
        &snapshot,
        &h.book,
        &procedure,
        None,
        Some(&Flag(&cancelled)),
    )
    .unwrap();
    assert!(complete.findings.is_empty());
    assert_eq!(complete.work, fa_lantern::Work::default());
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn cancellation_after_the_last_interval_withholds_findings_and_preserves_first_refusal() {
    let (h, _) = posted_corpus();
    let snapshot = h.snapshot();
    let cancel = Cell::new(false);
    let taken = Cell::new(0);
    let mut procedure = Loop::new(20, &taken);
    procedure.cancel_after = Some((5, &cancel));
    let error = run_over_metered(&snapshot, &h.book, &procedure, None, Some(&Flag(&cancel)))
        .expect_err("cancellation after the last periodic check withholds the result");
    assert!(
        matches!(error, LanternError::Cancelled { used: 20, .. }),
        "{error:?}"
    );
    assert_eq!(taken.get(), 20);

    // A swallowed budget refusal precedes cancellation. The final checkpoint
    // must retain that original cause and count, rather than overwrite it.
    cancel.set(false);
    taken.set(0);
    procedure.discard = true;
    let error = run_over_metered(
        &snapshot,
        &h.book,
        &procedure,
        Some(3),
        Some(&Flag(&cancel)),
    )
    .expect_err("the original stopped charge remains the run's refusal");
    assert!(
        matches!(
            error,
            LanternError::BudgetExhausted {
                used: 4,
                budget: 3,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(cancel.get());
    assert_eq!(taken.get(), 20);
}

#[test]
fn round_trip_search_obeys_the_runtime_budget_before_finishing_its_search() {
    let mut h = harness();
    h.post(&Spec::simple(day(2026, 1, 5), "1010", "1000", 100));
    h.post(&Spec::simple(day(2026, 1, 6), "1020", "1010", 100));
    h.post(&Spec::simple(day(2026, 1, 7), "1000", "1020", 100));
    let before = h.db.frontier().unwrap();
    let snapshot = h.snapshot();
    let procedure = RoundTrips::with(
        Params::defaults(RoundTrips::ID)
            .unwrap()
            .set("max_hops", 3)
            .unwrap(),
    );
    let complete = run_over_metered(&snapshot, &h.book, &procedure, None, None).unwrap();
    assert_eq!(complete.findings.len(), 1);
    assert_eq!(complete.work.legs, 3);
    assert!(complete.work.total() > 8);

    // Three flow legs and the three-unit sort estimate consume six units;
    // the first root consumes seven. The recursive continuation's eighth
    // charge must refuse immediately. Charging the complete search afterward
    // reports a larger count and fails this assertion.
    let error = run_over_metered(&snapshot, &h.book, &procedure, Some(7), None)
        .expect_err("the caller's budget interrupts the native corpus search");
    assert!(
        matches!(
            error,
            LanternError::BudgetExhausted {
                used: 8,
                budget: 7,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(
        h.db.frontier().unwrap(),
        before,
        "no partial finding is journaled"
    );

    let bounded = run_over_metered(
        &snapshot,
        &h.book,
        &procedure,
        Some(complete.work.total()),
        None,
    )
    .unwrap();
    assert_eq!(bounded.findings_digest, complete.findings_digest);
    assert_eq!(bounded.work, complete.work);
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn subsequent_events_default_budget_covers_long_period_history_and_explicit_budget_still_refuses() {
    use fa_lantern::cutoff::SubsequentEvents;
    use fa_lantern::{Transition, default_budget};

    let mut h = harness();
    let mut snapshot = h.snapshot();
    let january = h.period_code(day(2026, 1, 15));
    let february = h.period_code(day(2026, 2, 1));
    let usd = h.usd;
    let mut closed_periods = 0_u64;
    // Sixteen complete fiscal years plus January: each posting must pass 192
    // old, out-of-window boundaries before finding the final eligible period.
    // A budget based only on posting legs/log legs cannot pay for this scan.
    for year in 2010..=2026 {
        for period in h.book.calendar.periods_for_year(year).unwrap() {
            if period.kind != PeriodKind::Normal || period.end > day(2026, 2, 1) {
                continue;
            }
            closed_periods += 1;
            snapshot.periods.insert(
                period.code.clone(),
                fa_journal::rows::PeriodRow {
                    vid: fa_model::period_vid(&h.book.calendar.id, &period.code),
                    calendar_id: h.book.calendar.id.clone(),
                    code: period.code.clone(),
                    fiscal_year: period.fiscal_year,
                    ordinal: period.ordinal,
                    kind: period.kind,
                    start: period.start,
                    end: period.end,
                    state: PeriodState::Closed,
                    created_at: CommitSeq(1),
                },
            );
            snapshot.transitions.insert(
                period.code,
                vec![Transition {
                    recorded_at: snapshot.coordinate.known_at,
                    from: PeriodState::SoftClosed,
                    to: PeriodState::Closed,
                }],
            );
        }
    }
    assert_eq!(closed_periods, 193);
    for index in 0_u64..128 {
        snapshot.entries.push(make_snapshot_entry(
            &mut h,
            VId(300_000 + u128::from(index)),
            snapshot.coordinate.known_at,
            day(2026, 2, 1),
            &february,
            EntryClass::ADJUSTING,
            vec![
                ("6000", Side::Debit, usd, 500_000),
                ("1000", Side::Credit, usd, 500_000),
            ],
            Vec::new(),
            None,
            None,
            None,
            Vec::new(),
        ));
    }
    let procedure = SubsequentEvents::new().unwrap();
    let budget = default_budget(SubsequentEvents::ID, &snapshot).unwrap();
    let complete = run_over_metered(&snapshot, &h.book, &procedure, Some(budget), None)
        .expect("the registered budget must include the book's closed-period history");
    assert_eq!(complete.findings.len(), 128);
    assert_eq!(complete.work.entries, 128);
    assert_eq!(complete.work.legs, 256);
    assert_eq!(complete.work.comparisons, 128 * closed_periods);
    for finding in &complete.findings {
        assert!(finding.cites.contains(&Cite::Period(january.clone())));
        assert!(
            finding
                .narrative
                .contains(&format!("(1 day(s) after prior period {january})"))
        );
    }
    let row = fa_lantern::bind(SubsequentEvents::ID).unwrap();
    assert!(
        complete
            .work
            .within_registered_bound(&row.complexity, &snapshot)
    );
    let reversed = run_over_metered(
        &snapshot.with_entries_reversed(),
        &h.book,
        &procedure,
        Some(budget),
        None,
    )
    .unwrap();
    assert_eq!(reversed.findings, complete.findings);
    assert_eq!(reversed.findings_digest, complete.findings_digest);
    assert_eq!(reversed.work, complete.work);

    // The larger derived default never overrides an explicitly smaller
    // caller budget. This refuses while scanning the first posting's periods,
    // before returning any findings from the otherwise valid full run.
    let error = run_over_metered(&snapshot, &h.book, &procedure, Some(50), None)
        .expect_err("the caller's budget must still interrupt the nested scan");
    assert!(
        matches!(&error, LanternError::BudgetExhausted { procedure, used: 51, budget: 50, .. }
            if procedure == SubsequentEvents::ID),
        "{error:?}"
    );
    assert!(error.fix_hint().unwrap().contains("work budget"));
}
