//! The daemon's clock boundary (plan §7.1a).
//!
//! UTC is sampled between two reads of the caller's monotonic timer. The
//! pure judge compares elapsed UTC with that sampling bracket at process
//! startup; a rejected jump never becomes a new trusted baseline. This is
//! local clock corroboration, not authentication of physical UTC.

use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use asupersync::Cx;
use asupersync::time::{TimerDriverHandle, TimerHandle};
use asupersync::types::Time;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClockError {
    MissingTimeCapability,
    Cancelled,
    BeforeUnixEpoch,
    UtcOverflow,
    MonotonicRollback,
    DeadlineOverflow,
    InvalidPolicy(String),
}

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTimeCapability => {
                f.write_str("the daemon requires an explicit Cx time capability and timer driver")
            }
            Self::Cancelled => f.write_str("daemon timed work was cancelled"),
            Self::BeforeUnixEpoch => f.write_str("the UTC observation precedes the Unix epoch"),
            Self::UtcOverflow => f.write_str("the UTC observation exceeds u64 nanoseconds"),
            Self::MonotonicRollback => f.write_str("the monotonic clock moved backwards"),
            Self::DeadlineOverflow => {
                f.write_str("the next daemon deadline exceeds u64 nanoseconds")
            }
            Self::InvalidPolicy(why) => write!(f, "invalid daemon time policy: {why}"),
        }
    }
}

impl core::error::Error for ClockError {}

pub(crate) fn timer(cx: &Cx) -> Result<TimerDriverHandle, ClockError> {
    cx.checkpoint().map_err(|_| ClockError::Cancelled)?;
    cx.timer_driver().ok_or(ClockError::MissingTimeCapability)
}

pub(crate) fn deadline_after(now: Time, nanos: u64) -> Result<Time, ClockError> {
    now.as_nanos()
        .checked_add(nanos)
        .map(Time::from_nanos)
        .ok_or(ClockError::DeadlineOverflow)
}

/// The UTC sample was taken between these two monotonic readings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Observation {
    pub utc_ns: u64,
    pub before_ns: u64,
    pub after_ns: u64,
}

/// The only production UTC reader in the daemon. A timer-less or stripped
/// context is refused before reading SystemTime; no ambient fallback.
#[derive(Debug, Default)]
pub struct SystemClock;

impl SystemClock {
    pub(crate) fn observe(&mut self, cx: &Cx) -> Result<Observation, ClockError> {
        let driver = timer(cx)?;
        let before_ns = driver.now().as_nanos();
        let utc = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockError::BeforeUnixEpoch)?;
        let after_ns = driver.now().as_nanos();
        let utc_ns = u64::try_from(utc.as_nanos()).map_err(|_| ClockError::UtcOverflow)?;
        Ok(Observation {
            utc_ns,
            before_ns,
            after_ns,
        })
    }
}

#[derive(Debug)]
pub(crate) struct Judge {
    baseline: Option<Observation>,
    last_monotonic_ns: Option<u64>,
    drift_ns: u64,
}

impl Judge {
    pub(crate) fn new(drift_ns: u64) -> Self {
        Self {
            baseline: None,
            last_monotonic_ns: None,
            drift_ns,
        }
    }

    /// The first observation supplies a baseline but is uncorroborated.
    /// Later UTC elapsed time must fall inside the elapsed monotonic
    /// sampling bracket, expanded by the configured drift bound. i128
    /// subtraction preserves both signs across the entire u64 input range.
    pub(crate) fn observe(&mut self, sample: Observation) -> Result<bool, ClockError> {
        if sample.after_ns < sample.before_ns
            || self
                .last_monotonic_ns
                .is_some_and(|last| sample.before_ns < last)
        {
            return Err(ClockError::MonotonicRollback);
        }
        self.last_monotonic_ns = Some(sample.after_ns);
        let Some(baseline) = self.baseline else {
            self.baseline = Some(sample);
            return Ok(false);
        };
        let elapsed = i128::from(sample.utc_ns) - i128::from(baseline.utc_ns);
        let lower = i128::from(sample.before_ns)
            - i128::from(baseline.after_ns)
            - i128::from(self.drift_ns);
        let upper = i128::from(sample.after_ns) - i128::from(baseline.before_ns)
            + i128::from(self.drift_ns);
        Ok(elapsed > 0 && lower <= elapsed && elapsed <= upper)
    }
}

/// A timer explicitly bound to the supplied Cx driver. Dropping it cancels
/// its registration. It never uses Sleep's ambient/global fallback and
/// rechecks the true deadline when a timer-wheel horizon wakes it early.
pub(crate) struct Deadline<'a> {
    cx: &'a Cx,
    driver: TimerDriverHandle,
    at: Time,
    handle: Option<TimerHandle>,
}

impl<'a> Deadline<'a> {
    pub(crate) fn new(cx: &'a Cx, at: Time) -> Result<Self, ClockError> {
        Ok(Self {
            cx,
            driver: timer(cx)?,
            at,
            handle: None,
        })
    }
}

impl Future for Deadline<'_> {
    type Output = Result<(), ClockError>;

    fn poll(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cx.checkpoint().is_err() {
            return Poll::Ready(Err(ClockError::Cancelled));
        }
        if self.driver.now() >= self.at {
            if let Some(handle) = self.handle.take() {
                let _ = self.driver.cancel(&handle);
            }
            return Poll::Ready(Ok(()));
        }
        // update() deliberately returns an already-spent handle unchanged.
        // A horizon wake may have spent our registration before the true
        // deadline, so always register a new one after cancelling the old.
        if let Some(handle) = self.handle.take() {
            let _ = self.driver.cancel(&handle);
        }
        self.handle = Some(self.driver.register(self.at, task.waker().clone()));
        Poll::Pending
    }
}

impl Drop for Deadline<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = self.driver.cancel(&handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(utc_ns: u64, monotonic_ns: u64) -> Observation {
        Observation {
            utc_ns,
            before_ns: monotonic_ns,
            after_ns: monotonic_ns,
        }
    }

    #[test]
    fn startup_and_restart_are_uncorroborated_and_jumps_do_not_reset_the_baseline() {
        let mut judge = Judge::new(5);
        assert_eq!(judge.observe(sample(1_000, 0)), Ok(false));
        assert_eq!(judge.observe(sample(1_100, 100)), Ok(true));
        assert_eq!(judge.observe(sample(2_000, 200)), Ok(false));
        assert_eq!(judge.observe(sample(2_100, 300)), Ok(false));
        assert_eq!(judge.observe(sample(1_400, 400)), Ok(true));
        assert_eq!(Judge::new(5).observe(sample(1_400, 400)), Ok(false));
        assert_eq!(judge.observe(sample(900, 500)), Ok(false));
        assert_eq!(
            judge.observe(sample(1_600, 499)),
            Err(ClockError::MonotonicRollback)
        );
    }

    #[test]
    fn sampling_uncertainty_drift_edges_and_wide_signed_deltas_are_exact() {
        let mut judge = Judge::new(5);
        assert_eq!(
            judge.observe(Observation {
                utc_ns: 1_000,
                before_ns: 10,
                after_ns: 20
            }),
            Ok(false)
        );
        // Elapsed bracket [90, 110], expanded to [85, 115].
        assert_eq!(
            judge.observe(Observation {
                utc_ns: 1_115,
                before_ns: 110,
                after_ns: 120
            }),
            Ok(true)
        );
        assert_eq!(judge.observe(sample(1_126, 130)), Ok(false));
        let mut wide = Judge::new(0);
        assert_eq!(wide.observe(sample(u64::MAX, 0)), Ok(false));
        assert_eq!(wide.observe(sample(0, u64::MAX)), Ok(false));
        assert_eq!(
            deadline_after(Time::from_nanos(u64::MAX - 2), 3),
            Err(ClockError::DeadlineOverflow)
        );
        assert_eq!(
            deadline_after(Time::from_nanos(u64::MAX - 2), 2),
            Ok(Time::from_nanos(u64::MAX))
        );
    }
}
