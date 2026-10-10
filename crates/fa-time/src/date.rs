//! Civil dates: proleptic Gregorian, exact integer arithmetic, no time zone
//! (an effective date is a civil date in the book's calendar; plan §4.7).

use core::fmt;

/// Days since 1970-01-01 (which is day 0, a Thursday).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DateDay(pub i32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

impl Weekday {
    /// ISO numbering: Monday = 1 … Sunday = 7.
    pub fn iso(self) -> u8 {
        match self {
            Self::Monday => 1,
            Self::Tuesday => 2,
            Self::Wednesday => 3,
            Self::Thursday => 4,
            Self::Friday => 5,
            Self::Saturday => 6,
            Self::Sunday => 7,
        }
    }

    pub fn from_iso(n: u8) -> Option<Self> {
        Some(match n {
            1 => Self::Monday,
            2 => Self::Tuesday,
            3 => Self::Wednesday,
            4 => Self::Thursday,
            5 => Self::Friday,
            6 => Self::Saturday,
            7 => Self::Sunday,
            _ => return None,
        })
    }
}

/// What to do when adding months lands on a day the target month lacks
/// (Jan 31 + 1 month).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MonthEndPolicy {
    /// Clamp to the last day of the target month (Jan 31 → Feb 28/29).
    ClampToMonthEnd,
    /// If the source day was the last day of its month, the result is the
    /// last day of the target month even when the day number exists
    /// (Feb 28 → Mar 31); otherwise clamp.
    LastDayStaysLast,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DateError {
    InvalidYmd { year: i32, month: u8, day: u8 },
    Malformed(String),
    OutOfRange,
}

impl fmt::Display for DateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidYmd { year, month, day } => {
                write!(f, "invalid civil date {year:04}-{month:02}-{day:02}")
            }
            Self::Malformed(s) => write!(f, "malformed date `{s}`; expected YYYY-MM-DD"),
            Self::OutOfRange => f.write_str("date out of representable range"),
        }
    }
}

impl core::error::Error for DateError {}

pub fn is_leap_year(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

pub fn days_in_month(y: i32, m: u8) -> u8 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

impl DateDay {
    pub const EPOCH: DateDay = DateDay(0);

    /// Construct from a civil date, validating the day of month.
    pub fn from_ymd(year: i32, month: u8, day: u8) -> Result<Self, DateError> {
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
            return Err(DateError::InvalidYmd { year, month, day });
        }
        Ok(Self(days_from_civil(year, month, day)))
    }

    /// `(year, month, day)`.
    pub fn ymd(self) -> (i32, u8, u8) {
        civil_from_days(self.0)
    }

    pub fn year(self) -> i32 {
        self.ymd().0
    }

    pub fn month(self) -> u8 {
        self.ymd().1
    }

    pub fn day(self) -> u8 {
        self.ymd().2
    }

    pub fn weekday(self) -> Weekday {
        // 1970-01-01 is a Thursday (ISO 4).
        let iso = ((self.0 + 3).rem_euclid(7) + 1) as u8;
        Weekday::from_iso(iso).expect("1..=7")
    }

    pub fn add_days(self, n: i32) -> Result<Self, DateError> {
        self.0
            .checked_add(n)
            .map(DateDay)
            .ok_or(DateError::OutOfRange)
    }

    /// Exclusive-end successor: the next civil day.
    pub fn succ(self) -> Result<Self, DateError> {
        self.add_days(1)
    }

    pub fn pred(self) -> Result<Self, DateError> {
        self.add_days(-1)
    }

    pub fn is_month_end(self) -> bool {
        let (y, m, d) = self.ymd();
        d == days_in_month(y, m)
    }

    pub fn month_end(self) -> Self {
        let (y, m, _) = self.ymd();
        Self(days_from_civil(y, m, days_in_month(y, m)))
    }

    pub fn month_start(self) -> Self {
        let (y, m, _) = self.ymd();
        Self(days_from_civil(y, m, 1))
    }

    /// Add `n` months (may be negative) under an explicit end-of-month policy.
    pub fn add_months(self, n: i32, policy: MonthEndPolicy) -> Result<Self, DateError> {
        let (y, m, d) = self.ymd();
        let total = i64::from(y) * 12 + i64::from(m) - 1 + i64::from(n);
        let ny = i32::try_from(total.div_euclid(12)).map_err(|_| DateError::OutOfRange)?;
        let nm = (total.rem_euclid(12) + 1) as u8;
        let last = days_in_month(ny, nm);
        let nd = match policy {
            MonthEndPolicy::ClampToMonthEnd => d.min(last),
            MonthEndPolicy::LastDayStaysLast => {
                if self.is_month_end() {
                    last
                } else {
                    d.min(last)
                }
            }
        };
        Self::from_ymd(ny, nm, nd)
    }

    /// The last `weekday` on or before `self`.
    pub fn last_weekday_on_or_before(self, weekday: Weekday) -> Self {
        let delta = (i32::from(self.weekday().iso()) - i32::from(weekday.iso())).rem_euclid(7);
        DateDay(self.0 - delta)
    }

    /// The `weekday` nearest to `self` (ties resolve to the earlier one).
    pub fn nearest_weekday(self, weekday: Weekday) -> Self {
        let before = self.last_weekday_on_or_before(weekday);
        let after = DateDay(before.0 + 7);
        if (self.0 - before.0) <= (after.0 - self.0) {
            before
        } else {
            after
        }
    }

    /// Parse `YYYY-MM-DD` (years 0001–9999, optionally a leading `-` for
    /// proleptic years is not accepted: accounting dates are modern).
    pub fn parse(text: &str) -> Result<Self, DateError> {
        let t = text.trim();
        let parts: Vec<&str> = t.split('-').collect();
        if parts.len() != 3 || parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
            return Err(DateError::Malformed(text.into()));
        }
        let num = |s: &str| {
            s.parse::<i32>()
                .map_err(|_| DateError::Malformed(text.into()))
        };
        let (y, m, d) = (num(parts[0])?, num(parts[1])?, num(parts[2])?);
        let (m, d) = (
            u8::try_from(m).map_err(|_| DateError::Malformed(text.into()))?,
            u8::try_from(d).map_err(|_| DateError::Malformed(text.into()))?,
        );
        Self::from_ymd(y, m, d)
    }

    pub fn render(self) -> String {
        let (y, m, d) = self.ymd();
        format!("{y:04}-{m:02}-{d:02}")
    }
}

impl fmt::Display for DateDay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// Howard Hinnant's `days_from_civil`: exact for every proleptic Gregorian date.
fn days_from_civil(y: i32, m: u8, d: u8) -> i32 {
    let y = i64::from(y) - i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    (era * 146_097 + doe - 719_468) as i32
}

/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i32) -> (i32, u8, u8) {
    let z = i64::from(z) + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8; // [1, 12]
    ((y + i64::from(m <= 2)) as i32, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Brute-force reference: walk every day from 1900-01-01 to 2100-12-31
    /// with a naive day/month/year counter and compare to the closed form.
    #[test]
    fn closed_form_matches_a_day_walk_1900_to_2100() {
        let mut day = DateDay::from_ymd(1900, 1, 1).unwrap().0;
        let (mut y, mut m, mut d) = (1900, 1u8, 1u8);
        while y <= 2100 {
            let got = civil_from_days(day);
            assert_eq!(got, (y, m, d), "day {day}");
            assert_eq!(days_from_civil(y, m, d), day);
            // advance the naive counter
            d += 1;
            if d > days_in_month(y, m) {
                d = 1;
                m += 1;
                if m > 12 {
                    m = 1;
                    y += 1;
                }
            }
            day += 1;
        }
    }

    #[test]
    fn weekdays_and_anchors() {
        assert_eq!(DateDay::EPOCH.weekday(), Weekday::Thursday);
        assert_eq!(
            DateDay::from_ymd(2026, 10, 10).unwrap().weekday(),
            Weekday::Saturday
        );
        assert_eq!(
            DateDay::from_ymd(2000, 2, 29).unwrap().weekday(),
            Weekday::Tuesday
        );
        assert!(DateDay::from_ymd(1900, 2, 29).is_err());
        assert!(DateDay::from_ymd(2024, 2, 29).is_ok());
        assert_eq!(DateDay::parse("2026-03-31").unwrap().render(), "2026-03-31");
        assert!(DateDay::parse("2026-3-31").is_err());
        assert!(
            DateDay::parse("2026-03-31T00:00:00Z").is_err(),
            "an instant is not a civil date"
        );
    }

    #[test]
    fn month_arithmetic_policies() {
        let jan31 = DateDay::from_ymd(2026, 1, 31).unwrap();
        assert_eq!(
            jan31
                .add_months(1, MonthEndPolicy::ClampToMonthEnd)
                .unwrap()
                .render(),
            "2026-02-28"
        );
        let feb28 = DateDay::from_ymd(2026, 2, 28).unwrap();
        assert_eq!(
            feb28
                .add_months(1, MonthEndPolicy::ClampToMonthEnd)
                .unwrap()
                .render(),
            "2026-03-28"
        );
        assert_eq!(
            feb28
                .add_months(1, MonthEndPolicy::LastDayStaysLast)
                .unwrap()
                .render(),
            "2026-03-31"
        );
        assert_eq!(
            jan31
                .add_months(-1, MonthEndPolicy::ClampToMonthEnd)
                .unwrap()
                .render(),
            "2025-12-31"
        );
        assert_eq!(
            jan31
                .add_months(13, MonthEndPolicy::ClampToMonthEnd)
                .unwrap()
                .render(),
            "2027-02-28"
        );
    }

    #[test]
    fn weekday_searches() {
        let dec31 = DateDay::from_ymd(2026, 12, 31).unwrap(); // Thursday
        assert_eq!(
            dec31.last_weekday_on_or_before(Weekday::Saturday).render(),
            "2026-12-26"
        );
        assert_eq!(
            dec31.nearest_weekday(Weekday::Saturday).render(),
            "2027-01-02"
        );
        let dec31_2025 = DateDay::from_ymd(2025, 12, 31).unwrap(); // Wednesday
        assert_eq!(
            dec31_2025.nearest_weekday(Weekday::Saturday).render(),
            "2026-01-03"
        );
        assert_eq!(
            dec31_2025.last_weekday_on_or_before(Weekday::Wednesday),
            dec31_2025
        );
    }
}
