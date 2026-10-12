//! Explicit business-day calendars (plan §7.2 and §7.7).
//!
//! Working weekdays and holiday dates are input data, not host locale or an
//! inferred jurisdiction. No holiday observance rule is silently applied.
//! Calendar owners must retain and bind that data when certifying a result;
//! this pure value does not authenticate a holiday table or read a clock.
//!
//! Counts use whole weeks and binary searches over sorted holiday dates.
//! Offsets select a business-day ordinal with at most 32 date bisections,
//! rather than walking a potentially multi-million-year date interval.

use core::fmt;

use crate::recurrence::MonthlyOccurrence;
use crate::{DateDay, Weekday};

const FIRST_DAY: i64 = i32::MIN as i64;
const AFTER_LAST_DAY: i64 = i32::MAX as i64 + 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BusinessDayError {
    NoWorkingWeekday,
    OutOfRange,
    NoBusinessDayInMonth { year: i32, month: u8 },
}

impl fmt::Display for BusinessDayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoWorkingWeekday => f.write_str("a business calendar needs a working weekday"),
            Self::OutOfRange => f.write_str("business-day result outside the civil-date range"),
            Self::NoBusinessDayInMonth { year, month } => {
                write!(
                    f,
                    "the supplied calendar has no business day in {year:04}-{month:02}"
                )
            }
        }
    }
}

impl core::error::Error for BusinessDayError {}

/// An explicit adjustment, separate from the unadjusted contractual date.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusinessDayConvention {
    Unadjusted,
    Following,
    Preceding,
    /// Following unless it changes month, then preceding within the month.
    ModifiedFollowing,
    /// Preceding unless it changes month, then following within the month.
    ModifiedPreceding,
}

/// Immutable calendar data. Duplicate holidays and weekdays have set
/// semantics. Holidays on non-working weekdays never subtract a second day.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusinessCalendar {
    working_week: u8,
    holidays: Vec<DateDay>,
    // Derived index; the complete declared holiday table remains above.
    weekday_holidays: Vec<DateDay>,
}

impl BusinessCalendar {
    pub fn new(
        working_days: &[Weekday],
        mut holidays: Vec<DateDay>,
    ) -> Result<Self, BusinessDayError> {
        let working_week = working_days
            .iter()
            .fold(0u8, |mask, day| mask | (1u8 << (day.iso() - 1)));
        if working_week == 0 {
            return Err(BusinessDayError::NoWorkingWeekday);
        }
        holidays.sort_unstable();
        holidays.dedup();
        let weekday_holidays = holidays
            .iter()
            .copied()
            .filter(|day| working_week & (1u8 << (day.weekday().iso() - 1)) != 0)
            .collect();
        Ok(Self {
            working_week,
            holidays,
            weekday_holidays,
        })
    }

    /// Monday is bit 0 and Sunday is bit 6. At least one bit is set.
    #[must_use]
    pub fn working_week_mask(&self) -> u8 {
        self.working_week
    }

    /// The complete supplied holiday set, in ascending civil-date order.
    #[must_use]
    pub fn holidays(&self) -> &[DateDay] {
        &self.holidays
    }

    #[must_use]
    pub fn is_business_day(&self, date: DateDay) -> bool {
        self.weekday_is_open(i64::from(date.0))
            && self.weekday_holidays.binary_search(&date).is_err()
    }

    /// Business days in `[start, end)`. Reversed endpoints negate the same
    /// interval's count. `i64` covers the entire `DateDay` domain exactly.
    #[must_use]
    pub fn business_days_between(&self, start: DateDay, end: DateDay) -> i64 {
        if start <= end {
            self.count(i64::from(start.0), i64::from(end.0))
        } else {
            -self.count(i64::from(end.0), i64::from(start.0))
        }
    }

    /// Move by business days, excluding `date` for a nonzero offset.
    /// Zero returns the original date, even on a holiday: rolling an anchor
    /// is a separate, explicit [`Self::adjust`] operation. No offset wraps.
    pub fn add_business_days(
        &self,
        date: DateDay,
        offset: i64,
    ) -> Result<DateDay, BusinessDayError> {
        if offset == 0 {
            return Ok(date);
        }
        let raw = i64::from(date.0);
        let ordinal = if offset > 0 {
            self.count(FIRST_DAY, raw + 1).checked_add(offset)
        } else {
            self.count(FIRST_DAY, raw)
                .checked_add(offset)
                .and_then(|n| n.checked_add(1))
        }
        .ok_or(BusinessDayError::OutOfRange)?;
        let total = self.count(FIRST_DAY, AFTER_LAST_DAY);
        if ordinal < 1 || ordinal > total {
            return Err(BusinessDayError::OutOfRange);
        }
        let mut low = FIRST_DAY;
        let mut high = AFTER_LAST_DAY - 1;
        while low < high {
            let middle = low + (high - low) / 2;
            if self.count(FIRST_DAY, middle + 1) < ordinal {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        // The binary-search interval is exactly the representable domain.
        Ok(DateDay(low as i32))
    }

    /// Apply the named convention without changing an already-working day.
    /// Modified conventions refuse a wholly closed month rather than
    /// silently returning a date from an adjacent accounting period.
    pub fn adjust(
        &self,
        date: DateDay,
        convention: BusinessDayConvention,
    ) -> Result<DateDay, BusinessDayError> {
        use BusinessDayConvention::{
            Following, ModifiedFollowing, ModifiedPreceding, Preceding, Unadjusted,
        };
        if convention == Unadjusted || self.is_business_day(date) {
            return Ok(date);
        }
        match convention {
            Unadjusted => Ok(date),
            Following => self.add_business_days(date, 1),
            Preceding => self.add_business_days(date, -1),
            ModifiedFollowing | ModifiedPreceding => {
                let direction = if convention == ModifiedFollowing {
                    1
                } else {
                    -1
                };
                let (year, month, _) = date.ymd();
                let same_month = |candidate: DateDay| {
                    let (y, m, _) = candidate.ymd();
                    (y, m) == (year, month)
                };
                // At a domain boundary the preferred direction can fail
                // while the opposite direction still exists in this month.
                if let Ok(candidate) = self.add_business_days(date, direction)
                    && same_month(candidate)
                {
                    return Ok(candidate);
                }
                let candidate = self.add_business_days(date, -direction)?;
                if same_month(candidate) {
                    Ok(candidate)
                } else {
                    Err(BusinessDayError::NoBusinessDayInMonth { year, month })
                }
            }
        }
    }

    fn weekday_is_open(&self, raw: i64) -> bool {
        let weekday = (raw + 3).rem_euclid(7) as u32;
        self.working_week & (1u8 << weekday) != 0
    }

    /// Internal half-open interval, including the widened sentinel one day
    /// after `i32::MAX`. Callers supply ordered endpoints within the domain.
    fn count(&self, start: i64, end: i64) -> i64 {
        let days = end - start;
        let mut count = (days / 7) * i64::from(self.working_week.count_ones());
        for offset in 0..days % 7 {
            if self.weekday_is_open(start + offset) {
                count += 1;
            }
        }
        let left = self
            .weekday_holidays
            .partition_point(|d| i64::from(d.0) < start);
        let right = self
            .weekday_holidays
            .partition_point(|d| i64::from(d.0) < end);
        // Deduplicated DateDay values: at most 2^32, so the cast fits i64.
        count - (right - left) as i64
    }
}

/// Preserve both the contractual occurrence and its calendar adjustment.
/// Several indices may adjust to the same date; their identities stay
/// distinct. No posting, deduplication, or schedule authority is implied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdjustedOccurrence {
    pub index: u64,
    pub unadjusted: DateDay,
    pub adjusted: DateDay,
    pub convention: BusinessDayConvention,
}

impl MonthlyOccurrence {
    pub fn adjust(
        self,
        calendar: &BusinessCalendar,
        convention: BusinessDayConvention,
    ) -> Result<AdjustedOccurrence, BusinessDayError> {
        Ok(AdjustedOccurrence {
            index: self.index,
            unadjusted: self.date,
            adjusted: calendar.adjust(self.date, convention)?,
            convention,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MonthEndPolicy, MonthlyRecurrence};

    const WEEK: [Weekday; 7] = [
        Weekday::Monday,
        Weekday::Tuesday,
        Weekday::Wednesday,
        Weekday::Thursday,
        Weekday::Friday,
        Weekday::Saturday,
        Weekday::Sunday,
    ];

    fn date(text: &str) -> DateDay {
        DateDay::parse(text).unwrap()
    }

    fn weekdays(holidays: &[&str]) -> BusinessCalendar {
        BusinessCalendar::new(&WEEK[..5], holidays.iter().map(|h| date(h)).collect()).unwrap()
    }

    #[test]
    fn calendar_data_is_explicit_sorted_and_set_valued() {
        assert_eq!(
            BusinessCalendar::new(&[], Vec::new()),
            Err(BusinessDayError::NoWorkingWeekday)
        );
        let calendar = weekdays(&["2026-01-03", "2026-01-02", "2026-01-02"]);
        assert_eq!(calendar.working_week_mask(), 0b0001_1111);
        assert_eq!(
            calendar.holidays(),
            &[date("2026-01-02"), date("2026-01-03")]
        );
        assert_eq!(
            calendar.business_days_between(date("2026-01-01"), date("2026-01-08")),
            4
        );
        assert!(!calendar.is_business_day(date("2026-01-02")));
        assert!(!calendar.is_business_day(date("2026-01-03")));
        assert!(calendar.is_business_day(date("2026-01-05")));
        let repeated =
            BusinessCalendar::new(&[Weekday::Monday, Weekday::Monday], Vec::new()).unwrap();
        assert_eq!(repeated.working_week_mask(), 1);
    }

    #[test]
    fn explicit_conventions_respect_month_boundaries() {
        use BusinessDayConvention::*;
        let calendar = weekdays(&[]);
        for (input, convention, expected) in [
            ("2026-01-31", Unadjusted, "2026-01-31"),
            ("2026-01-31", Following, "2026-02-02"),
            ("2026-01-31", Preceding, "2026-01-30"),
            ("2026-01-31", ModifiedFollowing, "2026-01-30"),
            ("2026-02-01", ModifiedPreceding, "2026-02-02"),
            ("2026-02-02", ModifiedFollowing, "2026-02-02"),
        ] {
            assert_eq!(calendar.adjust(date(input), convention), Ok(date(expected)));
        }
        let holiday = weekdays(&["2026-01-30"]);
        assert_eq!(
            holiday.adjust(date("2026-01-31"), ModifiedFollowing),
            Ok(date("2026-01-29"))
        );
    }

    #[test]
    fn a_wholly_closed_month_is_not_silently_shifted() {
        let holidays = (1..=28)
            .map(|d| DateDay::from_ymd(2026, 2, d).unwrap())
            .collect();
        let calendar = BusinessCalendar::new(&WEEK[..5], holidays).unwrap();
        for convention in [
            BusinessDayConvention::ModifiedFollowing,
            BusinessDayConvention::ModifiedPreceding,
        ] {
            assert_eq!(
                calendar.adjust(date("2026-02-15"), convention),
                Err(BusinessDayError::NoBusinessDayInMonth {
                    year: 2026,
                    month: 2,
                })
            );
        }
        assert_eq!(
            calendar.adjust(date("2026-02-15"), BusinessDayConvention::Following),
            Ok(date("2026-03-02"))
        );
        assert_eq!(
            calendar.business_days_between(date("2026-02-01"), date("2026-03-01")),
            0
        );
    }

    #[test]
    fn offsets_exclude_the_anchor_and_never_implicitly_roll_zero() {
        let calendar = weekdays(&["2026-02-02"]);
        for (input, offset, expected) in [
            ("2026-01-30", 1, "2026-02-03"),
            ("2026-01-30", 2, "2026-02-04"),
            ("2026-02-04", -2, "2026-01-30"),
            ("2026-02-01", 1, "2026-02-03"),
            ("2026-02-01", -1, "2026-01-30"),
            ("2026-02-01", 0, "2026-02-01"),
            ("2026-02-02", 0, "2026-02-02"),
        ] {
            assert_eq!(
                calendar.add_business_days(date(input), offset),
                Ok(date(expected))
            );
        }
    }

    #[test]
    fn nonstandard_working_weeks_are_not_replaced_by_weekends() {
        let calendar =
            BusinessCalendar::new(&[Weekday::Sunday, Weekday::Thursday], Vec::new()).unwrap();
        assert_eq!(
            calendar.add_business_days(date("2026-01-01"), 1),
            Ok(date("2026-01-04"))
        );
        assert_eq!(
            calendar.add_business_days(date("2026-01-04"), 1),
            Ok(date("2026-01-08"))
        );
        assert_eq!(
            calendar.business_days_between(date("2026-01-01"), date("2026-01-15")),
            4
        );
    }

    #[test]
    fn counts_and_offsets_match_naive_walks_for_every_nonempty_workweek() {
        let holidays: Vec<_> = (-80..=80).filter(|d| d % 11 == 0).map(DateDay).collect();
        for mask in 1u8..=127 {
            let working: Vec<_> = WEEK
                .iter()
                .copied()
                .filter(|d| mask & (1u8 << (d.iso() - 1)) != 0)
                .collect();
            let calendar = BusinessCalendar::new(&working, holidays.clone()).unwrap();
            let open = |d: DateDay| working.contains(&d.weekday()) && !holidays.contains(&d);
            for raw in (-60..=60).step_by(10) {
                let start = DateDay(raw);
                for offset in [-20i32, -1, 0, 1, 20] {
                    let end = DateDay(raw + offset);
                    let (a, b) = if start <= end {
                        (start, end)
                    } else {
                        (end, start)
                    };
                    let count = (a.0..b.0).filter(|d| open(DateDay(*d))).count() as i64;
                    let expected = if start <= end { count } else { -count };
                    assert_eq!(calendar.business_days_between(start, end), expected);
                    assert_eq!(calendar.business_days_between(end, start), -expected);
                    let mut expected = start;
                    let mut remaining = offset.unsigned_abs();
                    while remaining > 0 {
                        expected = expected.add_days(offset.signum()).unwrap();
                        if open(expected) {
                            remaining -= 1;
                        }
                    }
                    let actual = calendar
                        .add_business_days(start, i64::from(offset))
                        .unwrap();
                    assert_eq!(
                        actual, expected,
                        "mask {mask}, start {start}, offset {offset}"
                    );
                    if open(start) {
                        assert_eq!(
                            calendar.add_business_days(actual, -i64::from(offset)),
                            Ok(start)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn full_domain_offsets_are_bounded_and_checked() {
        let calendar = BusinessCalendar::new(&WEEK, Vec::new()).unwrap();
        let first = DateDay(i32::MIN);
        let last = DateDay(i32::MAX);
        let distance = i64::from(i32::MAX) - i64::from(i32::MIN);
        assert_eq!(calendar.business_days_between(first, last), distance);
        assert_eq!(calendar.add_business_days(first, distance), Ok(last));
        assert_eq!(calendar.add_business_days(last, -distance), Ok(first));
        for (start, offset) in [
            (last, 1),
            (first, -1),
            (DateDay::EPOCH, i64::MIN),
            (DateDay::EPOCH, i64::MAX),
        ] {
            assert_eq!(
                calendar.add_business_days(start, offset),
                Err(BusinessDayError::OutOfRange)
            );
        }
    }

    #[test]
    fn holidays_and_modified_adjustments_work_at_domain_boundaries() {
        let first = DateDay(i32::MIN);
        let last = DateDay(i32::MAX);
        let calendar = BusinessCalendar::new(&WEEK, vec![last, first, last]).unwrap();
        assert_eq!(
            calendar.add_business_days(first, 1),
            Ok(first.succ().unwrap())
        );
        assert_eq!(
            calendar.add_business_days(last, -1),
            Ok(last.pred().unwrap())
        );
        assert_eq!(
            calendar.adjust(last, BusinessDayConvention::Following),
            Err(BusinessDayError::OutOfRange)
        );
        assert_eq!(
            calendar.adjust(last, BusinessDayConvention::ModifiedFollowing),
            Ok(last.pred().unwrap())
        );
        assert_eq!(
            calendar.adjust(first, BusinessDayConvention::ModifiedPreceding),
            Ok(first.succ().unwrap())
        );
        assert_eq!(calendar.business_days_between(first, last), 4_294_967_294);
    }

    #[test]
    fn adjusted_occurrences_retain_distinct_indices_and_original_dates() {
        let first = date("2026-01-31");
        let next = date("2026-02-28");
        let holidays = (first.0..next.0).map(DateDay).collect();
        let calendar = BusinessCalendar::new(&WEEK, holidays).unwrap();
        let recurrence = MonthlyRecurrence::new(first, 1, MonthEndPolicy::ClampToMonthEnd).unwrap();
        let a = recurrence
            .occurrence(0)
            .unwrap()
            .adjust(&calendar, BusinessDayConvention::Following)
            .unwrap();
        let b = recurrence
            .occurrence(1)
            .unwrap()
            .adjust(&calendar, BusinessDayConvention::Following)
            .unwrap();
        assert_eq!((a.unadjusted, b.unadjusted), (first, next));
        assert_eq!((a.adjusted, b.adjusted), (next, next));
        assert_eq!((a.index, b.index), (0, 1));
        assert_ne!(a, b, "same adjusted date must not merge occurrences");
    }
}
