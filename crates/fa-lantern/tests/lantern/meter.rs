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
    discard: bool,
}

impl<'a> Loop<'a> {
    fn new(steps: u64, taken: &'a Cell<u64>) -> Self {
        Self {
            params: Params::defaults("jet.weekend").unwrap(),
            steps,
            taken,
            cancel_after: None,
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

    // Cancelled before the run: the first charge observes it.
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
        matches!(&err, LanternError::Cancelled { procedure, used: 1 } if procedure == "jet.weekend"),
        "{err:?}"
    );
    assert_eq!(taken.get(), 1);

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
