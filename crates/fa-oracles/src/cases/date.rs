//! Civil-date arithmetic on `YYYY-MM-DD` strings, std-only
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §2.4; bead fa-yugf.6, A2).
//!
//! The derivations (a `date_offset`, the weekday `jet.weekend`'s model reads)
//! use this independent implementation, not fa-time's, so a shared date bug
//! cannot make a derived date agree with the engine. Days are counted from
//! 1970-01-01 in the proleptic Gregorian calendar (Hinnant's
//! days-from-civil).

/// A calendar day.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Day {
    pub year: i64,
    pub month: u32,
    pub day: u32,
}

/// The weekday names, Monday first.
pub const WEEKDAYS: [&str; 7] = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
];

#[must_use]
pub const fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[must_use]
pub const fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

impl Day {
    /// The day `s` names, if it is a valid `YYYY-MM-DD` date.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
            return None;
        }
        let num = |r: core::ops::Range<usize>| -> Option<u32> {
            let part = s.get(r)?;
            part.bytes()
                .all(|c| c.is_ascii_digit())
                .then(|| part.parse().ok())
                .flatten()
        };
        let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
        let year = i64::from(year);
        ((1..=12).contains(&month) && day >= 1 && day <= days_in_month(year, month))
            .then_some(Self { year, month, day })
    }

    /// Days since 1970-01-01.
    #[must_use]
    pub const fn to_days(self) -> i64 {
        let y = if self.month <= 2 {
            self.year - 1
        } else {
            self.year
        };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let m = self.month as i64;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + self.day as i64 - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    /// The day `days` after 1970-01-01.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub const fn from_days(days: i64) -> Self {
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
        Self { year, month, day }
    }

    /// This day plus `days` (negative goes back).
    #[must_use]
    pub const fn add_days(self, days: i64) -> Self {
        Self::from_days(self.to_days() + days)
    }

    /// The weekday, 0 = Monday … 6 = Sunday.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub const fn weekday_index(self) -> usize {
        // 1970-01-01 was a Thursday (index 3).
        (self.to_days() + 3).rem_euclid(7) as usize
    }

    #[must_use]
    pub const fn weekday(self) -> &'static str {
        WEEKDAYS[self.weekday_index()]
    }
}

impl core::fmt::Display for Day {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_match_known_weekdays() {
        for (date, weekday) in [
            ("2001-08-22", "Wednesday"),
            ("2001-08-25", "Saturday"),
            ("2001-07-17", "Tuesday"),
            ("2000-02-29", "Tuesday"),
            ("2002-01-23", "Wednesday"),
            ("1970-01-01", "Thursday"),
            ("1969-12-31", "Wednesday"),
        ] {
            let d = Day::parse(date).expect(date);
            assert_eq!(d.weekday(), weekday, "{date}");
            assert_eq!(d.to_string(), date);
            assert_eq!(Day::from_days(d.to_days()), d, "{date} round-trips");
        }
    }

    #[test]
    fn invalid_dates_do_not_parse() {
        for bad in [
            "2001-02-29",
            "1900-02-29",
            "2001-13-01",
            "2001-00-10",
            "2001-1-01",
            "20010101",
        ] {
            assert_eq!(Day::parse(bad), None, "{bad}");
        }
        assert!(Day::parse("2000-02-29").is_some(), "2000 is a leap year");
    }

    #[test]
    fn day_arithmetic_crosses_months_years_and_leap_days() {
        let d = Day::parse("2001-08-22").expect("day");
        assert_eq!(d.add_days(3).to_string(), "2001-08-25");
        assert_eq!(
            Day::parse("2000-02-28")
                .expect("day")
                .add_days(1)
                .to_string(),
            "2000-02-29"
        );
        assert_eq!(
            Day::parse("2001-12-31")
                .expect("day")
                .add_days(1)
                .to_string(),
            "2002-01-01"
        );
        assert_eq!(
            Day::parse("2002-01-01")
                .expect("day")
                .add_days(-1)
                .to_string(),
            "2001-12-31"
        );
        // Every day of 1999-2002 round-trips and advances by exactly one.
        let start = Day::parse("1999-01-01").expect("day").to_days();
        let end = Day::parse("2002-12-31").expect("day").to_days();
        for n in start..end {
            assert_eq!(Day::from_days(n).to_days(), n);
            assert_eq!(
                Day::from_days(n + 1).weekday_index(),
                (Day::from_days(n).weekday_index() + 1) % 7
            );
        }
    }
}
