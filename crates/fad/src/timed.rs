//! The daemon's owned timed-work driver (fa-ffo; plan §5.4, §7.1a, §7.6).
//!
//! Launch explicitly opts into a trusted-local book-key bootstrap. This is
//! not authenticated Steward issuance, and holding the writer lease alone
//! never grants System authority. Requests cannot configure or mint it.
//!
//! Each cycle journals one clock observation, then performs at most one
//! expiry transaction, one reversal transaction, and a bounded batch of
//! approved recurring posts under the latest corroborated tick. `sweep_batch` bounds committed effects, not input
//! discovery: the current kernel still scans candidate rows eagerly.

pub mod registers;

use core::fmt;

use asupersync::Cx;
use asupersync::fs::Vfs;
use asupersync::types::Time;
use fa::{AsyncBook, Book, BookError, Capability, Op, Outcome, Profile};
use fa_cli::json::{Json, s};
use fa_cli::verbs::Daemon;
use fa_journal::{Refusal, ReversalBatch, SweepBatch, Tick, Ticked};
use fa_model::Id128;
use fgdb_types::CommitSeq;
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
            Self::StaleTick => f.write_str(
                "the returned tick is not a fresh latest observation; no requested effect ran",
            ),
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
    fn corroborated_tick_at(&self, cx: &Cx, at: CommitSeq) -> Result<Option<Tick>, BookError>;
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
    async fn sweep_recurring(
        &mut self,
        cx: &Cx,
        cap: &Capability,
        max: usize,
    ) -> Outcome<Option<fa_journal::recurring::RecurringBatch>>;
    async fn advance_sweep_index(
        &mut self,
        cx: &Cx,
    ) -> Result<fa_journal::SweepIndexState, BookError>;
}

impl TimedBook for Book {
    fn latest_tick(&self, _cx: &Cx) -> Result<Option<Tick>, BookError> {
        Book::latest_tick(self)
    }

    fn corroborated_tick_at(&self, _cx: &Cx, at: CommitSeq) -> Result<Option<Tick>, BookError> {
        Book::corroborated_tick_at(self, at)
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

    async fn sweep_recurring(
        &mut self,
        cx: &Cx,
        cap: &Capability,
        max: usize,
    ) -> Outcome<Option<fa_journal::recurring::RecurringBatch>> {
        Book::sweep_recurring(self, cx, cap, max).await
    }

    async fn advance_sweep_index(
        &mut self,
        cx: &Cx,
    ) -> Result<fa_journal::SweepIndexState, BookError> {
        Book::advance_sweep_index_with(self, cx).await
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> TimedBook for AsyncBook<V, B> {
    fn latest_tick(&self, cx: &Cx) -> Result<Option<Tick>, BookError> {
        AsyncBook::latest_tick(self, &PurposeContexts::narrow_runtime_root(cx))
    }

    fn corroborated_tick_at(&self, cx: &Cx, at: CommitSeq) -> Result<Option<Tick>, BookError> {
        AsyncBook::corroborated_tick_at(self, &PurposeContexts::narrow_runtime_root(cx), at)
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

    async fn sweep_recurring(
        &mut self,
        cx: &Cx,
        cap: &Capability,
        max: usize,
    ) -> Outcome<Option<fa_journal::recurring::RecurringBatch>> {
        AsyncBook::sweep_recurring(self, &PurposeContexts::narrow_runtime_root(cx), cap, max).await
    }

    async fn advance_sweep_index(
        &mut self,
        cx: &Cx,
    ) -> Result<fa_journal::SweepIndexState, BookError> {
        AsyncBook::advance_sweep_index(self, &PurposeContexts::narrow_runtime_root(cx)).await
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Cycle {
    pub corroborated: bool,
    pub expired: usize,
    pub reversed: usize,
    pub blocked_reversals: usize,
    pub recurring: usize,
    pub blocked_recurring: usize,
    /// Whether the paged sweep index reached the cycle's final head.
    pub sweep_index_current: bool,
}

/// Timed work owned by the daemon's serving region. Dropping the server
/// drops this state; no worker, thread, or background task outlives it.
pub struct TimedWork {
    policy: Policy,
    // System authority exists only after explicit --bootstrap-system.
    capability: Option<Capability>,
    judge: Judge,
    next: Option<Time>,
    cycles: u64,
    last_tick_utc_ns: Option<u64>,
    last_tick_monotonic_ok: Option<bool>,
    error: Option<String>,
    registers: Option<registers::RegisterWork>,
    register_wake: bool,
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
            capability: Some(capability),
            judge: Judge::new(policy.clock_drift_ns),
            next: Some(now),
            cycles: 0,
            last_tick_utc_ns: None,
            last_tick_monotonic_ok: None,
            error: None,
            registers: None,
            register_wake: false,
        })
    }

    /// Run derived-cache maintenance without granting System authority or
    /// enabling TimeEvidence, expiries, or reversals.
    pub fn maintenance_only(
        cx: &Cx,
        policy: Policy,
        periods: Vec<String>,
    ) -> Result<Self, registers::ConfigurationError> {
        policy
            .validate()
            .map_err(|_| registers::ConfigurationError("invalid daemon maintenance policy"))?;
        let now = clock::timer(cx)
            .map_err(|_| {
                registers::ConfigurationError("register maintenance requires a timer capability")
            })?
            .now();
        let next = clock::deadline_after(now, policy.tick_ns)
            .map_err(|_| registers::ConfigurationError("register maintenance deadline overflow"))?;
        Ok(Self {
            policy,
            capability: None,
            judge: Judge::new(policy.clock_drift_ns),
            next: Some(next),
            cycles: 0,
            last_tick_utc_ns: None,
            last_tick_monotonic_ok: None,
            error: None,
            registers: Some(registers::RegisterWork::new(periods)?),
            register_wake: false,
        })
    }

    #[must_use]
    pub fn timing_enabled(&self) -> bool {
        self.capability.is_some()
    }

    /// Explicit local-launch selection of derived period maintenance. No
    /// wire request can reach this builder or broaden these exact codes.
    /// Existing launchers remain timing-only until they call this method.
    pub fn with_register_maintenance(
        mut self,
        periods: Vec<String>,
    ) -> Result<Self, registers::ConfigurationError> {
        if self.registers.is_some() {
            return Err(registers::ConfigurationError(
                "register maintenance is already configured",
            ));
        }
        self.registers = Some(registers::RegisterWork::new(periods)?);
        Ok(self)
    }

    #[must_use]
    pub fn register_maintenance(&self) -> Option<&registers::RegisterWork> {
        self.registers.as_ref()
    }

    pub(crate) fn deadline(&self) -> Option<Time> {
        self.next.map(|next| {
            if self.register_wake {
                Time::from_nanos(0)
            } else {
                next
            }
        })
    }

    /// The serving region observed a request advance the committed frontier.
    /// Coalesce notifications; a cache publication never notifies itself.
    /// Only periods explicitly selected at launch can be advanced.
    pub(crate) fn notify_commit(&mut self) {
        if self.registers.is_some() && self.next.is_some() {
            self.register_wake = true;
        }
    }

    /// An early commit wake runs one cache attempt without sampling UTC,
    /// sweeping, or postponing the regular timer. If that timer is already
    /// due, the normal cycle below consumes the notification and does both.
    pub(crate) async fn run_register_wake<B: registers::RegisterBook>(
        &mut self,
        cx: &Cx,
        book: &mut B,
    ) -> bool {
        if !core::mem::take(&mut self.register_wake) {
            return false;
        }
        if cx.checkpoint().is_err() {
            self.next = None;
            return true;
        }
        let Some(next) = self.next else {
            return false;
        };
        let Ok(timer) = clock::timer(cx) else {
            return false;
        };
        if timer.now() >= next {
            return false;
        }
        if let Some(registers) = self.registers.as_mut() {
            registers.run_cycle(cx, book).await;
        }
        true
    }

    pub(crate) async fn run_due(&mut self, cx: &Cx, book: &mut Book) {
        if self.run_register_wake(cx, book).await {
            return;
        }
        if self.capability.is_some() {
            let sample = SystemClock.observe(cx);
            let _ = self.run_maintained_observation(cx, book, sample).await;
            return;
        }
        if cx.checkpoint().is_err() {
            self.next = None;
            return;
        }
        if let Some(registers) = self.registers.as_mut() {
            registers.run_cycle(cx, book).await;
        }
        let _ = self.schedule_next(cx);
    }

    /// Journal a fresh, locally corroborated observation for an already
    /// admitted critical command. This does not sweep, advance registers, or
    /// postpone the periodic deadline: only the requested command may follow.
    pub(crate) async fn before_command(
        &mut self,
        cx: &Cx,
        book: &mut Book,
    ) -> Result<Ticked, TimedError> {
        let sample = SystemClock.observe(cx);
        self.command_observation(cx, book, sample).await
    }

    pub(crate) async fn command_observation<B: TimedBook>(
        &mut self,
        cx: &Cx,
        book: &mut B,
        sample: Result<Observation, ClockError>,
    ) -> Result<Ticked, TimedError> {
        let result = match sample {
            Ok(sample) => self.record_observation(cx, book, sample).await,
            Err(error) => Err(error.into()),
        };
        let recorded = result
            .as_ref()
            .is_ok_and(|(ticked, _)| !ticked.already_recorded);
        let result = result.and_then(|(ticked, corroborated)| {
            if ticked.already_recorded {
                return Err(TimedError::StaleTick);
            }
            // A startup sample or a clock jump is recorded honestly, but cannot
            // supply corroborated time for a critical publication. Retrying
            // waits for the real clock to corroborate; no synthetic increment.
            if corroborated {
                Ok(ticked)
            } else {
                Err(TimedError::Refused(Refusal::new(
                    fa_journal::refusal::code::TICK_UNCORROBORATED,
                    fa_journal::exit::REFUSAL,
                    "the fresh daemon TimeEvidence tick is not corroborated; the requested operation was not run",
                    "plan §7.1a; fa-7uhr (fresh time evidence before critical publication)",
                    "wait for the daemon's next locally corroborated clock observation, then retry the same command; inspect fad status for timed_work_error",
                )))
            }
        });
        self.error = result.as_ref().err().map(ToString::to_string);
        // Even an uncorroborated tick is a committed observation. Its consumer
        // still performs current-authority admission at the new frontier.
        if recorded {
            self.notify_commit();
        }
        result
    }

    /// One shared production/lab path. Cache maintenance is independent of
    /// UTC corroboration: it consumes committed facts, never authorizes an
    /// expiry or reversal. Preserve timing errors and per-period errors
    /// separately, and never attempt maintenance after cancellation.
    pub(crate) async fn run_maintained_observation<B: TimedBook + registers::RegisterBook>(
        &mut self,
        cx: &Cx,
        book: &mut B,
        sample: Result<Observation, ClockError>,
    ) -> Result<Cycle, TimedError> {
        let result = self.run_observation(cx, book, sample).await;
        if self.next.is_some()
            && let Some(registers) = self.registers.as_mut()
        {
            registers.run_cycle(cx, book).await;
            // A fold may exceed the tick interval. Rearm AFTER it,
            // otherwise continuously-due maintenance can starve I/O.
            self.schedule_next(cx)?;
        }
        result
    }

    fn schedule_next(&mut self, cx: &Cx) -> Result<(), TimedError> {
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
        Ok(())
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
        self.schedule_next(cx)?;
        result
    }

    async fn cycle<B: TimedBook>(
        &mut self,
        cx: &Cx,
        book: &mut B,
        sample: Observation,
    ) -> Result<Cycle, TimedError> {
        let (_ticked, corroborated) = self.record_observation(cx, book, sample).await?;
        let mut cycle = Cycle {
            corroborated,
            ..Cycle::default()
        };
        if !corroborated {
            return Ok(cycle);
        }
        let capability = self
            .capability
            .as_ref()
            .ok_or_else(|| TimedError::Authority("timed accounting effects are disabled".into()))?;
        // Both kernel paths also witness current tick corroboration and
        // current capability policy inside their own transactions.
        cx.checkpoint().map_err(|_| ClockError::Cancelled)?;
        // The disposable paged index turns candidate discovery into a read of
        // the committed delta instead of a whole-book scan (fa-gpd4,
        // fa-0hs4.11). It is derived state: when it cannot advance, discovery
        // falls back to the exact scan and the cycle still runs.
        cycle.sweep_index_current = book.advance_sweep_index(cx).await.is_ok();
        if let Some(batch) = admitted(
            book.sweep_expiry(cx, capability, self.policy.sweep_batch)
                .await,
        )? {
            cycle.expired = batch.expired.len();
        }
        cx.checkpoint().map_err(|_| ClockError::Cancelled)?;
        if let Some(batch) = admitted(
            book.sweep_reversals(cx, capability, self.policy.sweep_batch)
                .await,
        )? {
            cycle.reversed = batch.minted.len();
            cycle.blocked_reversals = batch.blocked.len();
        }
        cx.checkpoint().map_err(|_| ClockError::Cancelled)?;
        if let Some(batch) = admitted(
            book.sweep_recurring(cx, capability, self.policy.sweep_batch)
                .await,
        )? {
            cycle.recurring = batch.posted.len();
            cycle.blocked_recurring = batch.blocked.len();
        }
        // Carry the index over this cycle's own effects, so the next cycle
        // reads only what commits in between.
        if cycle.expired + cycle.reversed + cycle.recurring > 0 {
            cycle.sweep_index_current = book.advance_sweep_index(cx).await.is_ok();
        }
        Ok(cycle)
    }

    async fn record_observation<B: TimedBook>(
        &mut self,
        cx: &Cx,
        book: &mut B,
        sample: Observation,
    ) -> Result<(Ticked, bool), TimedError> {
        clock::timer(cx)?;
        let capability = self
            .capability
            .as_ref()
            .ok_or_else(|| TimedError::Authority("timed accounting effects are disabled".into()))?;
        let corroborated = self.judge.observe(sample)?;
        let ticked = admitted(
            book.record_tick(cx, sample.utc_ns, corroborated, capability)
                .await,
        )?;
        // An idempotent retry may return an old tick. It is not current
        // clock evidence, even if that old tick was corroborated.
        if book.latest_tick(cx)? != Some(ticked.tick) {
            return Err(TimedError::StaleTick);
        }
        // The kernel can downgrade an observation under its retained clock
        // skew law. Judge the committed evidence, not only the caller's flag.
        let corroborated =
            corroborated && book.corroborated_tick_at(cx, ticked.recorded_at)? == Some(ticked.tick);
        self.last_tick_utc_ns = Some(ticked.tick.observed_utc_ns);
        self.last_tick_monotonic_ok = Some(corroborated);
        Ok((ticked, corroborated))
    }
}

/// Fixed-shape status fields, including for an unconfigured/stopped daemon.
#[must_use]
pub fn status_fields(work: Option<&TimedWork>) -> Vec<(&'static str, Json)> {
    let number = |n: Option<u64>| n.map_or(Json::Null, |n| Json::Int(i128::from(n)));
    vec![
        (
            "timed_work_enabled",
            Json::Bool(work.is_some_and(TimedWork::timing_enabled)),
        ),
        (
            "timed_authority",
            work.filter(|w| w.timing_enabled())
                .map_or(Json::Null, |_| s("trusted-local-book-keys")),
        ),
        (
            "tick_ns",
            number(
                work.filter(|w| w.timing_enabled())
                    .map(|w| w.policy.tick_ns),
            ),
        ),
        (
            "sweep_batch",
            work.filter(|w| w.timing_enabled())
                .map_or(Json::Null, |w| Json::Int(w.policy.sweep_batch as i128)),
        ),
        (
            "clock_drift_ns",
            number(
                work.filter(|w| w.timing_enabled())
                    .map(|w| w.policy.clock_drift_ns),
            ),
        ),
        (
            "timed_cycles",
            Json::Int(i128::from(
                work.filter(|w| w.timing_enabled()).map_or(0, |w| w.cycles),
            )),
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
        (
            "register_maintenance",
            work.and_then(|w| w.registers.as_ref())
                .map_or(Json::Null, registers::RegisterWork::status),
        ),
    ]
}

/// Human status carries the authority posture and failures too.
#[must_use]
pub fn status_text(work: Option<&TimedWork>) -> String {
    let Some(work) = work else {
        return "timed work disabled".into();
    };
    let mut text = if work.timing_enabled() {
        let grade = match work.last_tick_monotonic_ok {
            None => "awaiting first observation",
            Some(false) => "last tick uncorroborated; no automatic expiry or reversal effects",
            Some(true) => "last tick corroborated by the local monotonic clock",
        };
        format!(
            "timed work uses trusted-local book-key System bootstrap; interval {} ns, at most {} expiry and {} reversal effects per cycle; {grade}",
            work.policy.tick_ns, work.policy.sweep_batch, work.policy.sweep_batch,
        )
    } else {
        "timed accounting effects disabled; no System authority was bootstrapped".into()
    };
    if let Some(error) = &work.error {
        text.push_str(&format!("; last cycle refused: {error}"));
    }
    if let Some(registers) = &work.registers {
        text.push_str(&format!("; {}", registers.status_text()));
    } else {
        text.push_str("; register maintenance disabled");
    }
    text
}

#[cfg(test)]
mod tests;
