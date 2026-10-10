//! Fiscal calendars generate period definitions deterministically (plan §7.2).

use crate::date::{DateDay, DateError, MonthEndPolicy, Weekday, days_in_month};
use crate::period::{PeriodDef, PeriodKind};

/// Week grouping per quarter for week-based calendars.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WeekPattern {
    W445,
    W454,
    W544,
}

impl WeekPattern {
    fn weeks(self) -> [u32; 3] {
        match self {
            Self::W445 => [4, 4, 5],
            Self::W454 => [4, 5, 4],
            Self::W544 => [5, 4, 4],
        }
    }
}

/// How a week-based fiscal year finds its last day.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum YearEndRule {
    /// The last `weekday` of `month` (e.g. the last Saturday of December).
    LastWeekdayOfMonth { weekday: Weekday, month: u8 },
    /// The `weekday` nearest to the last day of `month` (the common 52/53
    /// retail rule; may fall in the next calendar year).
    WeekdayNearestEnd { weekday: Weekday, month: u8 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CalendarKind {
    /// Twelve calendar months, the fiscal year starting in `year_start_month`.
    /// Fiscal year numbering follows the calendar year in which the fiscal
    /// year *ends* (a year starting 2025-10 is FY2026).
    Monthly12 { year_start_month: u8 },
    /// Twelve periods of 4/4/5-pattern weeks per quarter, 52 or 53 weeks per
    /// year; the 53rd week joins the last period.
    Weeks {
        pattern: WeekPattern,
        end_rule: YearEndRule,
    },
    /// Thirteen four-week periods, 52 or 53 weeks; the 53rd week joins the
    /// last period.
    Week5253 { end_rule: YearEndRule },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FiscalCalendar {
    pub id: String,
    pub kind: CalendarKind,
    /// Number of adjustment periods appended to each fiscal year (0..=4),
    /// all sharing the last civil day of the year.
    pub adjustment_periods: u8,
}

impl FiscalCalendar {
    pub fn monthly(
        id: &str,
        year_start_month: u8,
        adjustment_periods: u8,
    ) -> Result<Self, DateError> {
        if !(1..=12).contains(&year_start_month) {
            return Err(DateError::InvalidYmd {
                year: 0,
                month: year_start_month,
                day: 1,
            });
        }
        Ok(Self {
            id: id.into(),
            kind: CalendarKind::Monthly12 { year_start_month },
            adjustment_periods: adjustment_periods.min(4),
        })
    }

    /// First and last civil day (inclusive) of fiscal year `fy`.
    pub fn year_bounds(&self, fy: i32) -> Result<(DateDay, DateDay), DateError> {
        match &self.kind {
            CalendarKind::Monthly12 { year_start_month } => {
                let m = *year_start_month;
                let start = if m == 1 {
                    DateDay::from_ymd(fy, 1, 1)?
                } else {
                    DateDay::from_ymd(fy - 1, m, 1)?
                };
                let end = start
                    .add_months(12, MonthEndPolicy::ClampToMonthEnd)?
                    .pred()?;
                Ok((start, end))
            }
            CalendarKind::Weeks { end_rule, .. } | CalendarKind::Week5253 { end_rule } => {
                let end = year_end(*end_rule, fy)?;
                let prev_end = year_end(*end_rule, fy - 1)?;
                Ok((prev_end.succ()?, end))
            }
        }
    }

    /// Every period of fiscal year `fy`: normal periods first (ordinal 1..),
    /// then `Opening` (shares the first day), the adjustment periods and the
    /// `Closing` period (all sharing the last day). Special periods carry
    /// codes `FYxxxx-OPEN`, `FYxxxx-A1`…, `FYxxxx-CLOSE`.
    pub fn periods_for_year(&self, fy: i32) -> Result<Vec<PeriodDef>, DateError> {
        let (start, end) = self.year_bounds(fy)?;
        let mut out = Vec::new();
        match &self.kind {
            CalendarKind::Monthly12 { .. } => {
                let mut cursor = start;
                for ordinal in 1..=12u16 {
                    let next = cursor
                        .add_months(1, MonthEndPolicy::ClampToMonthEnd)?
                        .month_start();
                    out.push(PeriodDef {
                        code: format!("FY{fy}-P{ordinal:02}"),
                        fiscal_year: fy,
                        ordinal,
                        kind: PeriodKind::Normal,
                        start: cursor,
                        end: next,
                    });
                    cursor = next;
                }
                debug_assert_eq!(cursor, end.succ()?);
            }
            CalendarKind::Weeks { pattern, .. } => {
                let total_weeks = ((end.0 - start.0 + 1) / 7) as u32;
                debug_assert!(
                    total_weeks == 52 || total_weeks == 53,
                    "{total_weeks} weeks"
                );
                let mut cursor = start;
                let mut ordinal = 1u16;
                for q in 0..4 {
                    for (i, w) in pattern.weeks().iter().enumerate() {
                        let mut weeks = *w;
                        if q == 3 && i == 2 && total_weeks == 53 {
                            weeks += 1;
                        }
                        let next = cursor.add_days((weeks * 7) as i32)?;
                        out.push(PeriodDef {
                            code: format!("FY{fy}-P{ordinal:02}"),
                            fiscal_year: fy,
                            ordinal,
                            kind: PeriodKind::Normal,
                            start: cursor,
                            end: next,
                        });
                        cursor = next;
                        ordinal += 1;
                    }
                }
                debug_assert_eq!(cursor, end.succ()?);
            }
            CalendarKind::Week5253 { .. } => {
                let total_weeks = ((end.0 - start.0 + 1) / 7) as u32;
                let mut cursor = start;
                for ordinal in 1..=13u16 {
                    let weeks = if ordinal == 13 && total_weeks == 53 {
                        5
                    } else {
                        4
                    };
                    let next = cursor.add_days(weeks * 7)?;
                    out.push(PeriodDef {
                        code: format!("FY{fy}-P{ordinal:02}"),
                        fiscal_year: fy,
                        ordinal,
                        kind: PeriodKind::Normal,
                        start: cursor,
                        end: next,
                    });
                    cursor = next;
                }
                debug_assert_eq!(cursor, end.succ()?);
            }
        }
        let normal_count = out.len() as u16;
        out.push(PeriodDef {
            code: format!("FY{fy}-OPEN"),
            fiscal_year: fy,
            ordinal: normal_count + 1,
            kind: PeriodKind::Opening,
            start,
            end: start.succ()?,
        });
        for a in 1..=self.adjustment_periods {
            out.push(PeriodDef {
                code: format!("FY{fy}-A{a}"),
                fiscal_year: fy,
                ordinal: normal_count + 1 + u16::from(a),
                kind: PeriodKind::Adjustment,
                start: end,
                end: end.succ()?,
            });
        }
        out.push(PeriodDef {
            code: format!("FY{fy}-CLOSE"),
            fiscal_year: fy,
            ordinal: normal_count + 2 + u16::from(self.adjustment_periods),
            kind: PeriodKind::Closing,
            start: end,
            end: end.succ()?,
        });
        Ok(out)
    }

    /// The fiscal year containing `day`.
    pub fn fiscal_year_of(&self, day: DateDay) -> Result<i32, DateError> {
        let (y, m, _) = day.ymd();
        let guess = match &self.kind {
            CalendarKind::Monthly12 { year_start_month } => {
                if *year_start_month == 1 || m < *year_start_month {
                    y
                } else {
                    y + 1
                }
            }
            _ => y,
        };
        // Week-based years can end up to ±6 days from the calendar boundary.
        for fy in [guess - 1, guess, guess + 1] {
            let (s, e) = self.year_bounds(fy)?;
            if day >= s && day <= e {
                return Ok(fy);
            }
        }
        Err(DateError::OutOfRange)
    }
}

fn year_end(rule: YearEndRule, fy: i32) -> Result<DateDay, DateError> {
    match rule {
        YearEndRule::LastWeekdayOfMonth { weekday, month } => {
            let last = DateDay::from_ymd(fy, month, days_in_month(fy, month))?;
            Ok(last.last_weekday_on_or_before(weekday))
        }
        YearEndRule::WeekdayNearestEnd { weekday, month } => {
            let last = DateDay::from_ymd(fy, month, days_in_month(fy, month))?;
            Ok(last.nearest_weekday(weekday))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_contiguous(periods: &[PeriodDef], start: DateDay, end: DateDay) {
        let normals: Vec<&PeriodDef> = periods
            .iter()
            .filter(|p| p.kind == PeriodKind::Normal)
            .collect();
        assert_eq!(normals[0].start, start);
        for w in normals.windows(2) {
            assert_eq!(
                w[0].end, w[1].start,
                "periods must be contiguous: {} / {}",
                w[0].code, w[1].code
            );
            assert!(w[0].start < w[0].end);
        }
        assert_eq!(normals.last().unwrap().end, end.succ().unwrap());
    }

    #[test]
    fn monthly_calendar_with_october_start() {
        let cal = FiscalCalendar::monthly("usgov", 10, 1).unwrap();
        let (s, e) = cal.year_bounds(2026).unwrap();
        assert_eq!(
            (s.render(), e.render()),
            ("2025-10-01".into(), "2026-09-30".into())
        );
        let ps = cal.periods_for_year(2026).unwrap();
        check_contiguous(&ps, s, e);
        assert_eq!(
            ps.iter().filter(|p| p.kind == PeriodKind::Normal).count(),
            12
        );
        assert_eq!(ps[0].code, "FY2026-P01");
        assert_eq!(ps[11].end.render(), "2026-10-01");
        assert_eq!(
            cal.fiscal_year_of(DateDay::parse("2026-09-30").unwrap())
                .unwrap(),
            2026
        );
        assert_eq!(
            cal.fiscal_year_of(DateDay::parse("2026-10-01").unwrap())
                .unwrap(),
            2027
        );
        // Special periods share civil dates with normal ones.
        let open = ps.iter().find(|p| p.kind == PeriodKind::Opening).unwrap();
        let adj = ps
            .iter()
            .find(|p| p.kind == PeriodKind::Adjustment)
            .unwrap();
        let close = ps.iter().find(|p| p.kind == PeriodKind::Closing).unwrap();
        assert_eq!(open.start, s);
        assert_eq!(adj.start, e);
        assert_eq!(close.start, e);
        assert_eq!(adj.code, "FY2026-A1");
    }

    #[test]
    fn calendar_year_monthly() {
        let cal = FiscalCalendar::monthly("cy", 1, 0).unwrap();
        let (s, e) = cal.year_bounds(2024).unwrap();
        assert_eq!(
            (s.render(), e.render()),
            ("2024-01-01".into(), "2024-12-31".into())
        );
        let ps = cal.periods_for_year(2024).unwrap();
        check_contiguous(&ps, s, e);
        assert_eq!(ps[1].end.render(), "2024-03-01", "leap February");
        assert_eq!(
            cal.fiscal_year_of(DateDay::parse("2024-12-31").unwrap())
                .unwrap(),
            2024
        );
    }

    #[test]
    fn week_based_calendars_have_52_or_53_weeks_and_are_contiguous() {
        let rule = YearEndRule::WeekdayNearestEnd {
            weekday: Weekday::Saturday,
            month: 12,
        };
        let cal = FiscalCalendar {
            id: "retail".into(),
            kind: CalendarKind::Weeks {
                pattern: WeekPattern::W445,
                end_rule: rule,
            },
            adjustment_periods: 0,
        };
        let mut fifty_three = 0;
        for fy in 1990..=2100 {
            let (s, e) = cal.year_bounds(fy).unwrap();
            let weeks = (e.0 - s.0 + 1) / 7;
            assert!(
                (e.0 - s.0 + 1) % 7 == 0,
                "fy{fy} is not a whole number of weeks"
            );
            assert!(weeks == 52 || weeks == 53, "fy{fy} has {weeks} weeks");
            if weeks == 53 {
                fifty_three += 1;
            }
            assert_eq!(e.weekday(), Weekday::Saturday);
            let ps = cal.periods_for_year(fy).unwrap();
            check_contiguous(&ps, s, e);
            assert_eq!(
                ps.iter().filter(|p| p.kind == PeriodKind::Normal).count(),
                12
            );
            // 4-4-5: periods 3, 6, 9 have 35 days; 12 has 35 or 42.
            assert_eq!(ps[2].end.0 - ps[2].start.0, 35);
            assert!(matches!(ps[11].end.0 - ps[11].start.0, 35 | 42));
            assert_eq!(cal.fiscal_year_of(s).unwrap(), fy);
            assert_eq!(cal.fiscal_year_of(e).unwrap(), fy);
        }
        // 53-week years occur roughly every 5–6 years.
        assert!(
            (15..=25).contains(&fifty_three),
            "{fifty_three} fifty-three-week years in 111"
        );
        // Known anchor: FY2023 under this rule ended 2023-12-30; FY2024 ended 2024-12-28; FY2025 ends 2026-01-03 (53 weeks).
        assert_eq!(cal.year_bounds(2023).unwrap().1.render(), "2023-12-30");
        assert_eq!(cal.year_bounds(2024).unwrap().1.render(), "2024-12-28");
        assert_eq!(cal.year_bounds(2025).unwrap().1.render(), "2026-01-03");
        let (s25, e25) = cal.year_bounds(2025).unwrap();
        assert_eq!((e25.0 - s25.0 + 1) / 7, 53);
    }

    #[test]
    fn thirteen_period_calendar() {
        let rule = YearEndRule::LastWeekdayOfMonth {
            weekday: Weekday::Sunday,
            month: 1,
        };
        let cal = FiscalCalendar {
            id: "13p".into(),
            kind: CalendarKind::Week5253 { end_rule: rule },
            adjustment_periods: 2,
        };
        for fy in 2020..=2035 {
            let (s, e) = cal.year_bounds(fy).unwrap();
            let ps = cal.periods_for_year(fy).unwrap();
            check_contiguous(&ps, s, e);
            assert_eq!(
                ps.iter().filter(|p| p.kind == PeriodKind::Normal).count(),
                13
            );
            assert_eq!(
                ps.iter()
                    .filter(|p| p.kind == PeriodKind::Adjustment)
                    .count(),
                2
            );
            assert_eq!(e.weekday(), Weekday::Sunday);
        }
    }
}
