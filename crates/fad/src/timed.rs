//! The daemon's owned timed-work driver (fa-ffo; plan §5.4, §7.1a, §7.6).
//!
//! Launch explicitly opts into a trusted-local book-key bootstrap. This is
//! not authenticated Steward issuance, and holding the writer lease alone
//! never grants System authority. Requests cannot configure or mint it.
//!
//! Each cycle journals one clock observation, then performs at most one
//! expiry transaction and one reversal transaction under the latest
//! corroborated tick. `sweep_batch` bounds committed effects, not input
//! discovery: the current kernel still scans candidate rows eagerly.

use core::fmt;

use asupersync::Cx;
use asupersync::fs::Vfs;
use asupersync::types::Time;
use fa::{AsyncBook, Book, BookError, Capability, Op, Outcome, Profile};
use fa_cli::json::{Json, s};
use fa_cli::verbs::Daemon;
use fa_journal::{Refusal, ReversalBatch, SweepBatch, Tick, Ticked};
use fa_model::Id128;
use fgdb_types::context::PurposeContexts;

use crate::clock::{self, ClockError, Judge, Observation, SystemClock};

/// Registry-selected policy; no client request can change it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub tick_ns: u64,
    pub sweep_batch: usize,
    pub clock_drift_ns: u64,
}

impl Policy {
    pub fn from_registry(d: &Daemon) -> Result<Self, ClockError> {
        let policy = Self {
            tick_ns: d.tick_ns,
            sweep_batch: d.sweep_batch,
            clock_drift_ns: d.clock_drift_ns,
        };
        policy.validate()?;
        Ok(policy)
    }

    fn validate(self) -> Result<(), ClockError> {
        if self.tick_ns == 0 {
            return Err(ClockError::InvalidPolicy("tick_ns must be positive".into()));
        }
        if !(1..=fa_model::limits::MAX_BATCH_ENTRIES).contains(&self.sweep_batch) {
            return Err(ClockError::InvalidPolicy(format!(
                "sweep_batch must be in 1..={}",
                fa_model::limits::MAX_BATCH_ENTRIES
            )));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum TimedError {
    Clock(ClockError),
    Book(BookError),
    Refused(Refusal),
    Authority(String),
    StaleTick,
}

impl fmt::Display for TimedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clock(e) => e.fmt(f),
            Self::Book(e) => e.fmt(f),
            Self::Refused(e) => write!(f, "{}: {}", e.code, e.message),
            Self::Authority(why) => write!(f, "daemon System bootstrap refused: {why}"),
            Self::StaleTick => {
                f.write_str("the returned tick is not the book's latest tick; no sweep ran")
            }
        }
    }
}

impl core::error::Error for TimedError {}

impl From<ClockError> for TimedError {
    fn from(e: ClockError) -> Self {
        Self::Clock(e)
    }
}

impl From<BookError> for TimedError {
    fn from(e: BookError) -> Self {
        Self::Book(e)
    }
}

fn admitted<T>(outcome: Outcome<T>) -> Result<T, TimedError> {
    outcome
        .map_err(TimedError::Book)?
        .map_err(TimedError::Refused)
}

/// Only the existing timing adapters vary between the synchronous facade
/// and a caller-owned lab book. Both execute the same cycle below; the lab
/// adapter never constructs a production Runtime.
pub(crate) trait TimedBook {
    fn latest_tick(&self, cx: &Cx) -> Result<Option<Tick>, BookError>;
    async fn record_tick(
        &mut self,
        cx: &Cx,
        ns: u64,
        ok: bool,
        cap: &Capability,
    ) -> Outcome<Ticked>;
    async fn sweep_expiry(
        &mut self,
        cx: &Cx,
        cap: &Capability,
        max: usize,
    ) -> Outcome<Option<SweepBatch>>;
    async fn sweep_reversals(
        &mut self,
        cx: &Cx,
        cap: &Capability,
        max: usize,
    ) -> Outcome<Option<ReversalBatch>>;
}

impl TimedBook for Book {
    fn latest_tick(&self, _cx: &Cx) -> Result<Option<Tick>, BookError> {
        Book::latest_tick(self)
    }

    async fn record_tick(
        &mut self,
        cx: &Cx,
        ns: u64,
        ok: bool,
        cap: &Capability,
    ) -> Outcome<Ticked> {
        Book::record_tick(self, cx, ns, ok, cap).await
    }

    async fn sweep_expiry(
        &mut self,
        cx: &Cx,
        cap: &Capability,
        max: usize,
    ) -> Outcome<Option<SweepBatch>> {
        Book::sweep_expiry(self, cx, cap, max).await
    }

    async fn sweep_reversals(
        &mut self,
        cx: &Cx,
        cap: &Capability,
        max: usize,
    ) -> Outcome<Option<ReversalBatch>> {
        Book::sweep_reversals(self, cx, cap, max).await
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> TimedBook for AsyncBook<V, B> {
    fn latest_tick(&self, cx: &Cx) -> Result<Option<Tick>, BookError> {
        AsyncBook::latest_tick(self, &PurposeContexts::narrow_runtime_root(cx))
    }

    async fn record_tick(
        &mut self,
        cx: &Cx,
        ns: u64,
        ok: bool,
        cap: &Capability,
    ) -> Outcome<Ticked> {
        AsyncBook::record_tick(self, &PurposeContexts::narrow_runtime_root(cx), ns, ok, cap).await
    }

    async fn sweep_expiry(
        &mut self,
        cx: &Cx,
        cap: &Capability,
        max: usize,
    ) -> Outcome<Option<SweepBatch>> {
        AsyncBook::sweep_expiry(self, &PurposeContexts::narrow_runtime_root(cx), cap, max).await
    }

    async fn sweep_reversals(
        &mut self,
        cx: &Cx,
        cap: &Capability,
        max: usize,
    ) -> Outcome<Option<ReversalBatch>> {
        AsyncBook::sweep_reversals(self, &PurposeContexts::narrow_runtime_root(cx), cap, max).await
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Cycle {
    pub corroborated: bool,
    pub expired: usize,
    pub reversed: usize,
    pub blocked_reversals: usize,
}

/// Timed work owned by the daemon's serving region. Dropping the server
/// drops this state; no worker, thread, or background task outlives it.
pub struct TimedWork {
    policy: Policy,
    capability: Capability,
    judge: Judge,
    next: Option<Time>,
    cycles: u64,
    last_tick_utc_ns: Option<u64>,
    last_tick_monotonic_ok: Option<bool>,
    error: Option<String>,
}

impl TimedWork {
    /// Call only after an explicit `serve --bootstrap-system` launch and
    /// successful opening with the supplied book keys. This grants the
    /// intrinsic actor exactly witness/post on this book in the trusted
    /// local posture. It does not authenticate a remote caller or journal
    /// an issuance, and the lease is not an input to this constructor.
    pub fn bootstrap(cx: &Cx, book: &Book, policy: Policy) -> Result<Self, TimedError> {
        Self::bootstrap_for_book(cx, book.context().book_id, policy)
    }

    pub(crate) fn bootstrap_for_book(
        cx: &Cx,
        book: Id128,
        policy: Policy,
    ) -> Result<Self, TimedError> {
        policy.validate()?;
        let now = clock::timer(cx)?.now();
        clock::deadline_after(now, policy.tick_ns)?;
        let system = fa_journal::rows::system_principal(book);
        let capability = Capability::new(system, Profile::System, &[Op::Witness, Op::Post], system)
            .and_then(|cap| cap.for_books(&[book]))
            .map_err(|e| TimedError::Authority(e.to_string()))?;
        Ok(Self {
            policy,
            capability,
            judge: Judge::new(policy.clock_drift_ns),
            next: Some(now),
            cycles: 0,
            last_tick_utc_ns: None,
            last_tick_monotonic_ok: None,
            error: None,
        })
    }

    pub(crate) fn deadline(&self) -> Option<Time> {
        self.next
    }

    pub(crate) async fn run_due(&mut self, cx: &Cx, book: &mut Book) {
        let sample = SystemClock.observe(cx);
        let _ = self.run_observation(cx, book, sample).await;
    }

    /// The production sampler and the actual virtual-time lab feed the
    /// same admission path. Each call is one cycle, never a catch-up drain.
    pub(crate) async fn run_observation<B: TimedBook>(
        &mut self,
        cx: &Cx,
        book: &mut B,
        sample: Result<Observation, ClockError>,
    ) -> Result<Cycle, TimedError> {
        self.cycles = self.cycles.saturating_add(1);
        let result = match sample {
            Ok(sample) => self.cycle(cx, book, sample).await,
            Err(error) => Err(error.into()),
        };
        self.error = result.as_ref().err().map(ToString::to_string);
        // Delay from completion. Missed intervals never become an
        // unbounded burst; the next read/accept always has a chance to run.
        match clock::timer(cx)
            .and_then(|driver| clock::deadline_after(driver.now(), self.policy.tick_ns))
        {
            Ok(next) => self.next = Some(next),
            Err(error) => {
                self.next = None;
                self.error = Some(error.to_string());
                return Err(error.into());
            }
        }
        result
    }

    async fn cycle<B: TimedBook>(
        &mut self,
        cx: &Cx,
        book: &mut B,
        sample: Observation,
    ) -> Result<Cycle, TimedError> {
        clock::timer(cx)?;
        let corroborated = self.judge.observe(sample)?;
        let ticked = admitted(
            book.record_tick(cx, sample.utc_ns, corroborated, &self.capability)
                .await,
        )?;
        // An idempotent retry may return an old tick. It is not current
        // clock evidence, even if that old tick was corroborated.
        if book.latest_tick(cx)? != Some(ticked.tick) {
            return Err(TimedError::StaleTick);
        }
        self.last_tick_utc_ns = Some(ticked.tick.observed_utc_ns);
        self.last_tick_monotonic_ok = Some(corroborated);
        let mut cycle = Cycle {
            corroborated,
            ..Cycle::default()
        };
        if !corroborated {
            return Ok(cycle);
        }
        // Both kernel paths also witness current tick corroboration and
        // current capability policy inside their own transactions.
        cx.checkpoint().map_err(|_| ClockError::Cancelled)?;
        if let Some(batch) = admitted(
            book.sweep_expiry(cx, &self.capability, self.policy.sweep_batch)
                .await,
        )? {
            cycle.expired = batch.expired.len();
        }
        cx.checkpoint().map_err(|_| ClockError::Cancelled)?;
        if let Some(batch) = admitted(
            book.sweep_reversals(cx, &self.capability, self.policy.sweep_batch)
                .await,
        )? {
            cycle.reversed = batch.minted.len();
            cycle.blocked_reversals = batch.blocked.len();
        }
        Ok(cycle)
    }
}

/// Fixed-shape status fields, including for an unconfigured/stopped daemon.
#[must_use]
pub fn status_fields(work: Option<&TimedWork>) -> Vec<(&'static str, Json)> {
    let number = |n: Option<u64>| n.map_or(Json::Null, |n| Json::Int(i128::from(n)));
    vec![
        ("timed_work_enabled", Json::Bool(work.is_some())),
        (
            "timed_authority",
            work.map_or(Json::Null, |_| s("trusted-local-book-keys")),
        ),
        ("tick_ns", number(work.map(|w| w.policy.tick_ns))),
        (
            "sweep_batch",
            work.map_or(Json::Null, |w| Json::Int(w.policy.sweep_batch as i128)),
        ),
        (
            "clock_drift_ns",
            number(work.map(|w| w.policy.clock_drift_ns)),
        ),
        (
            "timed_cycles",
            Json::Int(i128::from(work.map_or(0, |w| w.cycles))),
        ),
        (
            "last_tick_utc_ns",
            number(work.and_then(|w| w.last_tick_utc_ns)),
        ),
        (
            "last_tick_monotonic_ok",
            work.and_then(|w| w.last_tick_monotonic_ok)
                .map_or(Json::Null, Json::Bool),
        ),
        (
            "timed_work_error",
            work.and_then(|w| w.error.as_deref()).map_or(Json::Null, s),
        ),
    ]
}

/// Human status carries the authority posture and failures too.
#[must_use]
pub fn status_text(work: Option<&TimedWork>) -> String {
    let Some(work) = work else {
        return "timed work disabled".into();
    };
    let grade = match work.last_tick_monotonic_ok {
        None => "awaiting first observation",
        Some(false) => "last tick uncorroborated; no automatic effects",
        Some(true) => "last tick corroborated by the local monotonic clock",
    };
    let mut text = format!(
        "timed work uses trusted-local book-key System bootstrap; interval {} ns, at most {} expiry and {} reversal effects per cycle; {grade}",
        work.policy.tick_ns, work.policy.sweep_batch, work.policy.sweep_batch,
    );
    if let Some(error) = &work.error {
        text.push_str(&format!("; last cycle refused: {error}"));
    }
    text
}

#[cfg(test)]
mod tests;
