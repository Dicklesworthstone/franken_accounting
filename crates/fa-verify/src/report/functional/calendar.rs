//! Fiscal-year boundaries derived from the retained BookSpec, independently
//! of the producer's calendar implementation and period projections.
use super::super::{ReportError, failed};
use crate::codec::Reader;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub(super) enum Calendar {
    Monthly(u8),
    Weekly { rule: u8, weekday: u8, month: u8 },
    Custom(BTreeMap<i32, (i32, i32)>),
}

fn invalid(detail: &str) -> ReportError {
    failed("functional_calendar", detail)
}

fn month(value: u8) -> Result<u8, ReportError> {
    if (1..=12).contains(&value) {
        Ok(value)
    } else {
        Err(invalid("fiscal calendar month is outside 1..=12"))
    }
}

impl Calendar {
    pub(super) fn read(r: &mut Reader<'_>) -> Result<Self, ReportError> {
        if r.u8("calendar.adjustment_periods")? > 4 {
            return Err(invalid("more than four adjustment periods are unsupported"));
        }
        Ok(match r.u8("calendar.kind")? {
            0 => Self::Monthly(month(r.u8("calendar.year_start_month")?)?),
            kind @ (1 | 2) => {
                if kind == 1 && r.u8("calendar.pattern")? > 2 {
                    return Err(invalid("unknown weekly period pattern"));
                }
                let rule = r.u8("calendar.rule")?;
                let weekday = r.u8("calendar.weekday")?;
                let month = month(r.u8("calendar.month")?)?;
                if rule > 1 || weekday > 6 {
                    return Err(invalid("unknown fiscal year-end rule or weekday"));
                }
                Self::Weekly {
                    rule,
                    weekday,
                    month,
                }
            }
            3 => {
                let count = r.count(200, 8, "calendar.years")?;
                if count == 0 {
                    return Err(invalid("custom calendar declares no fiscal year"));
                }
                let mut years = BTreeMap::new();
                let mut previous: Option<(i32, i32)> = None;
                for _ in 0..count {
                    let year = r.i32("calendar.year")?;
                    let count = r.count(54, 4, "calendar.bounds")?;
                    if count < 2 {
                        return Err(invalid("custom fiscal year has no period"));
                    }
                    let start = r.i32("calendar.bound")?;
                    if previous.is_some_and(|(prior_year, after)| {
                        prior_year.checked_add(1) != Some(year) || after != start
                    }) {
                        return Err(invalid(
                            "custom fiscal years must be consecutive and contiguous",
                        ));
                    }
                    let mut after = start;
                    for _ in 1..count {
                        let next = r.i32("calendar.bound")?;
                        if next <= after {
                            return Err(invalid("custom period boundaries must strictly increase"));
                        }
                        after = next;
                    }
                    let end = after
                        .checked_sub(1)
                        .ok_or_else(|| invalid("custom fiscal year ends outside DateDay"))?;
                    years.insert(year, (start, end));
                    previous = Some((year, after));
                }
                Self::Custom(years)
            }
            _ => return Err(invalid("unknown fiscal calendar kind")),
        })
    }

    /// Inclusive fiscal-year limits. Monthly years use their ending year;
    /// weekly years use the declared last/nearest weekday of the ending month.
    pub(super) fn year_bounds(&self, fiscal_year: i32) -> Result<(i32, i32), ReportError> {
        match self {
            Self::Custom(years) => years
                .get(&fiscal_year)
                .copied()
                .ok_or_else(|| invalid("custom calendar does not declare this fiscal year")),
            Self::Monthly(month) => {
                let year = i64::from(fiscal_year) - i64::from(*month != 1);
                let start = civil_day(year, *month, 1)?;
                let after = civil_day(year + 1, *month, 1)?;
                let end = after
                    .checked_sub(1)
                    .ok_or_else(|| invalid("monthly fiscal year ends outside DateDay"))?;
                Ok((start, end))
            }
            Self::Weekly {
                rule,
                weekday,
                month,
            } => {
                let year = i64::from(fiscal_year);
                let end = week_end(year, *month, *weekday, *rule)?;
                let start = week_end(year - 1, *month, *weekday, *rule)?
                    .checked_add(1)
                    .ok_or_else(|| invalid("weekly fiscal year starts outside DateDay"))?;
                Ok((start, end))
            }
        }
    }
}

// Count complete civil years from 0000-01-01, then add complete months.
// All intermediates are i64; decoded years are i32, so these products remain
// far below i64 bounds. Conversion to the persisted i32 day is checked.
fn civil_day(year: i64, month: u8, day: u8) -> Result<i32, ReportError> {
    const BEFORE: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let previous = year - 1;
    let leap_days =
        previous.div_euclid(4) - previous.div_euclid(100) + previous.div_euclid(400) + 1;
    let leap = year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0);
    let days = year * 365
        + leap_days
        + BEFORE[usize::from(month - 1)]
        + i64::from(month > 2 && leap)
        + i64::from(day)
        - 1
        - 719_528;
    i32::try_from(days).map_err(|_| invalid("fiscal calendar date exceeds DateDay"))
}

fn week_end(year: i64, month: u8, weekday: u8, rule: u8) -> Result<i32, ReportError> {
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    let last = civil_day(next_year, next_month, 1)?
        .checked_sub(1)
        .ok_or_else(|| invalid("fiscal month end exceeds DateDay"))?;
    let actual = (i64::from(last) + 3).rem_euclid(7); // 1970-01-01 was Thursday.
    let back = (actual - i64::from(weekday)).rem_euclid(7);
    let offset = if rule == 1 && back > 3 {
        7 - back
    } else {
        -back
    };
    i32::try_from(i64::from(last) + offset)
        .map_err(|_| invalid("fiscal weekday adjustment exceeds DateDay"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Writer;

    fn decode(bytes: &[u8]) -> Result<Calendar, ReportError> {
        let mut r = Reader::new(bytes);
        let value = Calendar::read(&mut r)?;
        r.finish("calendar")?;
        Ok(value)
    }

    #[test]
    fn fiscal_boundaries_match_independent_civil_date_vectors() {
        for (month, year, expected) in [
            (1, 1970, (0, 364)),
            (1, 1969, (-365, -1)),
            (1, 2000, (10_957, 11_322)),
            (10, 2026, (20_362, 20_726)),
        ] {
            assert_eq!(
                decode(&[0, 0, month]).unwrap().year_bounds(year).unwrap(),
                expected
            );
        }
        // Last Saturday in December: 2026-12-26; nearest Saturday:
        // 2027-01-02. Both 4/4/5 and 13-period profiles use these year limits.
        for kind in [1, 2] {
            for (rule, expected) in [(0, (20_450, 20_813)), (1, (20_457, 20_820))] {
                let mut bytes = vec![0, kind];
                if kind == 1 {
                    bytes.push(0);
                }
                bytes.extend([rule, 5, 12]);
                assert_eq!(decode(&bytes).unwrap().year_bounds(2026).unwrap(), expected);
            }
        }
        assert!(decode(&[0, 0, 1]).unwrap().year_bounds(i32::MAX).is_err());
    }

    #[test]
    fn custom_years_are_explicit_and_cannot_hide_gaps_or_duplicate_years() {
        let mut w = Writer::default();
        w.u8(0)
            .u8(3)
            .count(2)
            .i32(2025)
            .count(3)
            .i32(0)
            .i32(10)
            .i32(30)
            .i32(2026)
            .count(2)
            .i32(30)
            .i32(61);
        let calendar = decode(&w.buf).unwrap();
        assert_eq!(calendar.year_bounds(2025).unwrap(), (0, 29));
        assert_eq!(calendar.year_bounds(2026).unwrap(), (30, 60));
        assert!(calendar.year_bounds(2027).is_err());
        let mut gap = w.buf.clone();
        gap[34..38].copy_from_slice(&31i32.to_le_bytes());
        assert!(decode(&gap).is_err());
        let mut duplicate = w.buf;
        duplicate[26..30].copy_from_slice(&2025i32.to_le_bytes());
        assert!(decode(&duplicate).is_err());
        for bad in [
            &[5, 0, 1][..],
            &[0, 0, 0],
            &[0, 2, 2, 0, 1],
            &[0, 2, 0, 7, 1],
        ] {
            assert!(decode(bad).is_err());
        }
    }
}
