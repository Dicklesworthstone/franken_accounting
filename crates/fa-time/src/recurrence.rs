//! Pure monthly occurrence arithmetic (plan §7.6–§7.7, fa-0bi).
//!
//! Every occurrence is computed from the original anchor, never from the
//! preceding clamped date. January 31, February 28, March 31 therefore stays
//! a day-31 schedule. The occurrence index is stable across batch boundaries
//! and can be included in a journaled schedule's identity.
//!
//! This module neither reads a clock nor posts entries. Authority, committed
//! TimeEvidence, cancellation, period law, and exactly-once publication still
//! belong to the journaled recurring-schedule workflow. An occurrence is a
//! date calculation, not permission to post.

use core::fmt;
use core::iter::FusedIterator;

use crate::{DateDay, DateError, MonthEndPolicy};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecurrenceError {
    ZeroInterval,
    Date(DateError),
}

impl fmt::Display for RecurrenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroInterval => {
                f.write_str("a monthly recurrence needs a positive month interval")
            }
            Self::Date(error) => write!(f, "recurring date: {error}"),
        }
    }
}

impl core::error::Error for RecurrenceError {}

impl From<DateError> for RecurrenceError {
    fn from(error: DateError) -> Self {
        Self::Date(error)
    }
}

/// An anchor and an explicit month-end law. Fields are private so an invalid
/// zero interval cannot enter through a struct literal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonthlyRecurrence {
    anchor: DateDay,
    every_months: u32,
    month_end: MonthEndPolicy,
}

/// Zero-based identity within a schedule and its unadjusted civil date.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonthlyOccurrence {
    pub index: u64,
    pub date: DateDay,
}

impl MonthlyRecurrence {
    pub fn new(
        anchor: DateDay,
        every_months: u32,
        month_end: MonthEndPolicy,
    ) -> Result<Self, RecurrenceError> {
        if every_months == 0 {
            return Err(RecurrenceError::ZeroInterval);
        }
        Ok(Self {
            anchor,
            every_months,
            month_end,
        })
    }

    #[must_use]
    pub fn anchor(&self) -> DateDay {
        self.anchor
    }

    #[must_use]
    pub fn every_months(&self) -> u32 {
        self.every_months
    }

    #[must_use]
    pub fn month_end_policy(&self) -> MonthEndPolicy {
        self.month_end
    }

    /// Calculate one occurrence directly, independent of prior calls.
    /// `PreserveDay` refuses a nonexistent day; no occurrence is silently
    /// skipped, clamped, or moved into the following month.
    pub fn occurrence(&self, index: u64) -> Result<MonthlyOccurrence, RecurrenceError> {
        let months = index
            .checked_mul(u64::from(self.every_months))
            .and_then(|n| i32::try_from(n).ok())
            .ok_or(DateError::OutOfRange)?;
        Ok(MonthlyOccurrence {
            index,
            date: self.anchor.add_months(months, self.month_end)?,
        })
    }

    /// Locate an occurrence without replaying all preceding months. An
    /// invalid `PreserveDay` occurrence in the searched month is a refusal,
    /// not an implicit decision to skip it.
    pub fn first_on_or_after(&self, date: DateDay) -> Result<MonthlyOccurrence, RecurrenceError> {
        if date <= self.anchor {
            return self.occurrence(0);
        }
        let (ay, am, _) = self.anchor.ymd();
        let (y, m, _) = date.ymd();
        let elapsed = (i64::from(y) - i64::from(ay)) * 12 + i64::from(m) - i64::from(am);
        let index = u64::try_from(elapsed).map_err(|_| DateError::OutOfRange)?
            / u64::from(self.every_months);
        let candidate = self.occurrence(index)?;
        if candidate.date >= date {
            Ok(candidate)
        } else {
            self.occurrence(index.checked_add(1).ok_or(DateError::OutOfRange)?)
        }
    }

    /// A lazy stream for caller-bounded consumption, such as `.take(12)`.
    /// Resuming at an index produces exactly the same dates as uninterrupted
    /// consumption. The first invalid/unrepresentable date is returned as an
    /// error and terminates the stream; errors are never hidden by skipping.
    #[must_use]
    pub fn iter_from(&self, first_index: u64) -> MonthlyOccurrences {
        MonthlyOccurrences {
            recurrence: *self,
            next_index: Some(first_index),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MonthlyOccurrences {
    recurrence: MonthlyRecurrence,
    next_index: Option<u64>,
}

impl Iterator for MonthlyOccurrences {
    type Item = Result<MonthlyOccurrence, RecurrenceError>;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.next_index?;
        let result = self.recurrence.occurrence(index);
        self.next_index = if result.is_ok() {
            index.checked_add(1)
        } else {
            None
        };
        Some(result)
    }
}

impl FusedIterator for MonthlyOccurrences {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::date::days_in_month;

    fn recurrence(anchor: &str, step: u32, policy: MonthEndPolicy) -> MonthlyRecurrence {
        MonthlyRecurrence::new(DateDay::parse(anchor).unwrap(), step, policy).unwrap()
    }

    #[test]
    fn clamp_preserves_the_original_anchor_across_short_months() {
        let schedule = recurrence("2026-01-31", 1, MonthEndPolicy::ClampToMonthEnd);
        let dates: Vec<String> = schedule
            .iter_from(0)
            .take(4)
            .map(|o| o.unwrap().date.render())
            .collect();
        assert_eq!(
            dates,
            ["2026-01-31", "2026-02-28", "2026-03-31", "2026-04-30"]
        );
        let joined: Vec<_> = schedule
            .iter_from(0)
            .take(2)
            .chain(schedule.iter_from(2).take(10))
            .collect();
        assert_eq!(joined, schedule.iter_from(0).take(12).collect::<Vec<_>>());
    }

    #[test]
    fn last_day_policy_uses_the_anchor_not_an_intermediate_clamp() {
        let schedule = recurrence("2026-01-30", 1, MonthEndPolicy::LastDayStaysLast);
        assert_eq!(schedule.occurrence(1).unwrap().date.render(), "2026-02-28");
        assert_eq!(schedule.occurrence(2).unwrap().date.render(), "2026-03-30");
        let end = recurrence("2026-02-28", 1, MonthEndPolicy::LastDayStaysLast);
        assert_eq!(end.occurrence(1).unwrap().date.render(), "2026-03-31");
        assert_eq!(end.occurrence(2).unwrap().date.render(), "2026-04-30");
    }

    #[test]
    fn preserve_day_reports_the_missing_occurrence_and_stops() {
        let schedule = recurrence("2026-01-31", 1, MonthEndPolicy::PreserveDay);
        let mut dates = schedule.iter_from(0);
        assert_eq!(dates.next().unwrap().unwrap().index, 0);
        assert!(matches!(
            dates.next().unwrap(),
            Err(RecurrenceError::Date(DateError::InvalidYmd { .. }))
        ));
        assert_eq!(dates.next(), None);
        assert_eq!(dates.next(), None);
        // Explicit random access does not silently renumber March to index 1.
        assert_eq!(schedule.occurrence(2).unwrap().date.render(), "2026-03-31");
    }

    #[test]
    fn seek_respects_the_due_day_and_the_interval() {
        let schedule = recurrence("2024-02-29", 12, MonthEndPolicy::ClampToMonthEnd);
        for (query, index, expected) in [
            ("2020-01-01", 0, "2024-02-29"),
            ("2025-02-28", 1, "2025-02-28"),
            ("2025-03-01", 2, "2026-02-28"),
            ("2028-02-28", 4, "2028-02-29"),
            ("2028-03-01", 5, "2029-02-28"),
        ] {
            let found = schedule
                .first_on_or_after(DateDay::parse(query).unwrap())
                .unwrap();
            assert_eq!(
                (found.index, found.date.render()),
                (index, expected.to_string())
            );
        }
    }

    #[test]
    fn anchored_months_match_a_calendar_counter_for_a_gregorian_cycle() {
        for day in [28, 29, 30, 31] {
            let schedule = MonthlyRecurrence::new(
                DateDay::from_ymd(1800, 1, day).unwrap(),
                1,
                MonthEndPolicy::ClampToMonthEnd,
            )
            .unwrap();
            let (mut year, mut month) = (1800, 1);
            for occurrence in schedule.iter_from(0).take(400 * 12) {
                let occurrence = occurrence.unwrap();
                assert_eq!(
                    occurrence.date.ymd(),
                    (year, month, day.min(days_in_month(year, month)))
                );
                month += 1;
                if month == 13 {
                    year += 1;
                    month = 1;
                }
            }
        }
    }

    #[test]
    fn invalid_intervals_and_unrepresentable_occurrences_are_refused() {
        assert_eq!(
            MonthlyRecurrence::new(DateDay::EPOCH, 0, MonthEndPolicy::PreserveDay),
            Err(RecurrenceError::ZeroInterval)
        );
        let schedule = recurrence("2026-01-01", 1, MonthEndPolicy::PreserveDay);
        assert_eq!(
            schedule.occurrence(u64::MAX),
            Err(RecurrenceError::Date(DateError::OutOfRange))
        );
        let mut dates = schedule.iter_from(u64::MAX);
        assert!(dates.next().unwrap().is_err());
        assert_eq!(dates.next(), None);
        let huge = recurrence("2026-01-01", u32::MAX, MonthEndPolicy::PreserveDay);
        assert_eq!(huge.occurrence(0).unwrap().date.render(), "2026-01-01");
        assert_eq!(
            huge.occurrence(1),
            Err(RecurrenceError::Date(DateError::OutOfRange))
        );
    }
}
