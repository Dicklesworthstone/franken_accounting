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
    /// An explicit period list (plan §7.2 `Custom`): consecutive declared
    /// fiscal years, each with its normal periods' boundaries. Only declared
    /// years exist.
    Custom { years: Vec<CustomYear> },
}

/// The most fiscal years a custom calendar declares.
pub const MAX_CUSTOM_YEARS: usize = 200;
/// The most normal periods one custom fiscal year holds.
pub const MAX_CUSTOM_PERIODS: usize = 53;

/// One declared fiscal year of a custom calendar. Normal period `i`
/// (1-based) is `[bounds[i - 1], bounds[i])`, so the periods are contiguous
/// and cannot overlap; the year runs from `bounds[0]` through the day before
/// its last bound.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CustomYear {
    pub fiscal_year: i32,
    pub bounds: Vec<DateDay>,
}

impl CustomYear {
    /// The year from inclusive `(start, end)` periods, each starting the day
    /// after the previous one ends.
    pub fn from_periods(
        fiscal_year: i32,
        periods: &[(DateDay, DateDay)],
    ) -> Result<Self, DateError> {
        let mut bounds: Vec<DateDay> = Vec::with_capacity(periods.len() + 1);
        for (i, (start, end)) in periods.iter().enumerate() {
            if let Some(last) = bounds.last()
                && last != start
            {
                return Err(DateError::InvalidCalendar(format!(
                    "fiscal year {fiscal_year} period {} starts {}, but the period before it ends {}: periods are contiguous and in order",
                    i + 1,
                    start.render(),
                    last.pred()?.render()
                )));
            }
            if end < start {
                return Err(DateError::InvalidCalendar(format!(
                    "fiscal year {fiscal_year} period {} ends {} before it starts {}",
                    i + 1,
                    end.render(),
                    start.render()
                )));
            }
            if bounds.is_empty() {
                bounds.push(*start);
            }
            bounds.push(end.succ()?);
        }
        let year = Self {
            fiscal_year,
            bounds,
        };
        year.validate()?;
        Ok(year)
    }

    fn validate(&self) -> Result<(), DateError> {
        let periods = self.bounds.len().saturating_sub(1);
        if !(1..=MAX_CUSTOM_PERIODS).contains(&periods) {
            return Err(DateError::InvalidCalendar(format!(
                "fiscal year {} declares {periods} periods; a custom year holds 1..={MAX_CUSTOM_PERIODS}",
                self.fiscal_year
            )));
        }
        if !self.bounds.windows(2).all(|w| w[0] < w[1]) {
            return Err(DateError::InvalidCalendar(format!(
                "fiscal year {}'s period boundaries are not strictly ascending: every period is at least one day, in order",
                self.fiscal_year
            )));
        }
        Ok(())
    }

    /// First and last civil day (inclusive).
    fn span(&self) -> Result<(DateDay, DateDay), DateError> {
        match (self.bounds.first(), self.bounds.last()) {
            (Some(first), Some(after)) => Ok((*first, after.pred()?)),
            _ => Err(DateError::InvalidCalendar(format!(
                "fiscal year {} declares no periods",
                self.fiscal_year
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FiscalCalendar {
    pub id: String,
    pub kind: CalendarKind,
    /// Number of adjustment periods appended to each fiscal year (0..=4),
    /// all sharing the last civil day of the year.
    pub adjustment_periods: u8,
}

pub const MAX_ADJUSTMENT_PERIODS: u8 = 4;

impl FiscalCalendar {
    pub fn validate(&self) -> Result<(), DateError> {
        if self.id.is_empty() {
            return Err(DateError::InvalidCalendar(
                "calendar id must not be empty".into(),
            ));
        }
        if self.adjustment_periods > MAX_ADJUSTMENT_PERIODS {
            return Err(DateError::InvalidCalendar(format!(
                "adjustment_periods {} exceeds the maximum of {MAX_ADJUSTMENT_PERIODS}",
                self.adjustment_periods
            )));
        }
        let month = match &self.kind {
            CalendarKind::Monthly12 { year_start_month } => *year_start_month,
            CalendarKind::Weeks { end_rule, .. } | CalendarKind::Week5253 { end_rule } => {
                match end_rule {
                    YearEndRule::LastWeekdayOfMonth { month, .. }
                    | YearEndRule::WeekdayNearestEnd { month, .. } => *month,
                }
            }
            CalendarKind::Custom { years } => return validate_custom(years),
        };
        if !(1..=12).contains(&month) {
            return Err(DateError::InvalidYmd {
                year: 0,
                month,
                day: 1,
            });
        }
        Ok(())
    }

    pub fn monthly(
        id: &str,
        year_start_month: u8,
        adjustment_periods: u8,
    ) -> Result<Self, DateError> {
        let cal = Self {
            id: id.into(),
            kind: CalendarKind::Monthly12 { year_start_month },
            adjustment_periods,
        };
        cal.validate()?;
        Ok(cal)
    }

    pub fn weeks(
        id: &str,
        pattern: WeekPattern,
        end_rule: YearEndRule,
        adjustment_periods: u8,
    ) -> Result<Self, DateError> {
        let cal = Self {
            id: id.into(),
            kind: CalendarKind::Weeks { pattern, end_rule },
            adjustment_periods,
        };
        cal.validate()?;
        Ok(cal)
    }

    pub fn week_52_53(
        id: &str,
        end_rule: YearEndRule,
        adjustment_periods: u8,
    ) -> Result<Self, DateError> {
        let cal = Self {
            id: id.into(),
            kind: CalendarKind::Week5253 { end_rule },
            adjustment_periods,
        };
        cal.validate()?;
        Ok(cal)
    }

    /// A custom calendar over explicitly declared fiscal years (plan §7.2).
    pub fn custom(
        id: &str,
        years: Vec<CustomYear>,
        adjustment_periods: u8,
    ) -> Result<Self, DateError> {
        let cal = Self {
            id: id.into(),
            kind: CalendarKind::Custom { years },
            adjustment_periods,
        };
        cal.validate()?;
        Ok(cal)
    }

    /// First and last civil day (inclusive) of fiscal year `fy`.
    pub fn year_bounds(&self, fy: i32) -> Result<(DateDay, DateDay), DateError> {
        self.validate()?;
        match &self.kind {
            CalendarKind::Custom { years } => custom_year(years, fy)?.span(),
            CalendarKind::Monthly12 { year_start_month } => {
                let m = *year_start_month;
                let start = if m == 1 {
                    DateDay::from_ymd(fy, 1, 1)?
                } else {
                    let prev_fy = fy.checked_sub(1).ok_or(DateError::OutOfRange)?;
                    DateDay::from_ymd(prev_fy, m, 1)?
                };
                let end = start
                    .add_months(12, MonthEndPolicy::ClampToMonthEnd)?
                    .pred()?;
                Ok((start, end))
            }
            CalendarKind::Weeks { end_rule, .. } | CalendarKind::Week5253 { end_rule } => {
                let prev_fy = fy.checked_sub(1).ok_or(DateError::OutOfRange)?;
                let end = year_end(*end_rule, fy)?;
                let prev_end = year_end(*end_rule, prev_fy)?;
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
                        .try_month_start()?;
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
            CalendarKind::Custom { years } => {
                let year = custom_year(years, fy)?;
                for (i, w) in year.bounds.windows(2).enumerate() {
                    let ordinal = u16::try_from(i + 1).map_err(|_| DateError::OutOfRange)?;
                    out.push(PeriodDef {
                        code: format!("FY{fy}-P{ordinal:02}"),
                        fiscal_year: fy,
                        ordinal,
                        kind: PeriodKind::Normal,
                        start: w[0],
                        end: w[1],
                    });
                }
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
        self.validate()?;
        if let CalendarKind::Custom { years } = &self.kind {
            return years
                .iter()
                .find(|y| {
                    y.bounds.first().is_some_and(|f| *f <= day)
                        && y.bounds.last().is_some_and(|l| day < *l)
                })
                .map(|y| y.fiscal_year)
                .ok_or(DateError::OutOfRange);
        }
        let (y, m, _) = day.ymd();
        let guess = match &self.kind {
            CalendarKind::Monthly12 { year_start_month } => {
                if *year_start_month == 1 || m < *year_start_month {
                    y
                } else {
                    y.checked_add(1).ok_or(DateError::OutOfRange)?
                }
            }
            _ => y,
        };
        // Week-based years can end up to ±6 days from the calendar boundary.
        for fy in [guess.checked_sub(1), Some(guess), guess.checked_add(1)]
            .into_iter()
            .flatten()
        {
            if let Ok((s, e)) = self.year_bounds(fy)
                && day >= s
                && day <= e
            {
                return Ok(fy);
            }
        }
        Err(DateError::OutOfRange)
    }
}

/// A custom calendar's declared years: `1..=MAX_CUSTOM_YEARS`, each valid,
/// numbered consecutively, and each starting the day after the one before
/// it ends.
fn validate_custom(years: &[CustomYear]) -> Result<(), DateError> {
    if !(1..=MAX_CUSTOM_YEARS).contains(&years.len()) {
        return Err(DateError::InvalidCalendar(format!(
            "a custom calendar declares 1..={MAX_CUSTOM_YEARS} fiscal years, not {}",
            years.len()
        )));
    }
    for year in years {
        year.validate()?;
    }
    for w in years.windows(2) {
        if w[0].fiscal_year.checked_add(1) != Some(w[1].fiscal_year) {
            return Err(DateError::InvalidCalendar(format!(
                "custom fiscal years are consecutive: {} is followed by {}",
                w[0].fiscal_year, w[1].fiscal_year
            )));
        }
        if w[0].bounds.last() != w[1].bounds.first() {
            return Err(DateError::InvalidCalendar(format!(
                "fiscal year {} starts {}, not the day after fiscal year {} ends ({}): custom years are contiguous",
                w[1].fiscal_year,
                w[1].bounds.first().map_or_else(String::new, |d| d.render()),
                w[0].fiscal_year,
                w[0].span()?.1.render()
            )));
        }
    }
    Ok(())
}

/// The declared custom year `fy`; refused, naming the declared range, when
/// the calendar does not declare it.
fn custom_year(years: &[CustomYear], fy: i32) -> Result<&CustomYear, DateError> {
    years.iter().find(|y| y.fiscal_year == fy).ok_or_else(|| {
        DateError::InvalidCalendar(format!(
            "this custom calendar declares fiscal years {}..={}, not {fy}",
            years.first().map_or(0, |y| y.fiscal_year),
            years.last().map_or(0, |y| y.fiscal_year)
        ))
    })
}

fn year_end(rule: YearEndRule, fy: i32) -> Result<DateDay, DateError> {
    match rule {
        YearEndRule::LastWeekdayOfMonth { weekday, month } => {
            let last = DateDay::from_ymd(fy, month, days_in_month(fy, month))?;
            last.try_last_weekday_on_or_before(weekday)
        }
        YearEndRule::WeekdayNearestEnd { weekday, month } => {
            let last = DateDay::from_ymd(fy, month, days_in_month(fy, month))?;
            last.try_nearest_weekday(weekday)
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

    #[test]
    fn adjustment_periods_above_max_are_refused_never_clamped() {
        for adj in 0..=MAX_ADJUSTMENT_PERIODS {
            assert_eq!(
                FiscalCalendar::monthly("cy", 1, adj)
                    .unwrap()
                    .adjustment_periods,
                adj
            );
        }
        let rule = YearEndRule::WeekdayNearestEnd {
            weekday: Weekday::Saturday,
            month: 12,
        };
        for adj in 5..=10 {
            assert!(matches!(
                FiscalCalendar::monthly("cy", 1, adj),
                Err(DateError::InvalidCalendar(_))
            ));
            assert!(matches!(
                FiscalCalendar::weeks("retail", WeekPattern::W445, rule, adj),
                Err(DateError::InvalidCalendar(_))
            ));
            assert!(matches!(
                FiscalCalendar::week_52_53("13p", rule, adj),
                Err(DateError::InvalidCalendar(_))
            ));
        }
    }

    #[test]
    fn all_calendar_kinds_enumerate_1900_through_2100_and_refuse_out_of_range_years() {
        let nearest_sat = YearEndRule::WeekdayNearestEnd {
            weekday: Weekday::Saturday,
            month: 1,
        };
        let last_sun = YearEndRule::LastWeekdayOfMonth {
            weekday: Weekday::Sunday,
            month: 12,
        };
        let calendars = [
            FiscalCalendar::monthly("m12", 4, 1).unwrap(),
            FiscalCalendar::weeks("w445", WeekPattern::W445, nearest_sat, 1).unwrap(),
            FiscalCalendar::weeks("w454", WeekPattern::W454, last_sun, 1).unwrap(),
            FiscalCalendar::weeks("w544", WeekPattern::W544, nearest_sat, 1).unwrap(),
            FiscalCalendar::week_52_53("w5253", last_sun, 1).unwrap(),
        ];
        for cal in &calendars {
            for fy in 1900..=2100 {
                let (s, e) = cal.year_bounds(fy).unwrap();
                let ps = cal.periods_for_year(fy).unwrap();
                check_contiguous(&ps, s, e);
                assert_eq!(cal.fiscal_year_of(s).unwrap(), fy);
                assert_eq!(cal.fiscal_year_of(e).unwrap(), fy);
            }
            for bad_fy in [i32::MIN, i32::MAX] {
                assert_eq!(cal.year_bounds(bad_fy), Err(DateError::OutOfRange));
                assert_eq!(cal.periods_for_year(bad_fy), Err(DateError::OutOfRange));
            }
        }
    }

    /// A short first year, then a thirteen-period year of four-week periods.
    fn custom_years() -> Vec<CustomYear> {
        let day = |y, m, d| DateDay::from_ymd(y, m, d).unwrap();
        let stub = CustomYear::from_periods(
            2025,
            &[
                (day(2025, 11, 1), day(2025, 11, 30)),
                (day(2025, 12, 1), day(2026, 1, 3)),
            ],
        )
        .unwrap();
        let mut periods = Vec::new();
        let mut start = day(2026, 1, 4);
        for _ in 0..13 {
            let end = start.add_days(27).unwrap();
            periods.push((start, end));
            start = end.succ().unwrap();
        }
        let thirteen = CustomYear::from_periods(2026, &periods).unwrap();
        vec![stub, thirteen]
    }

    #[test]
    fn custom_calendar_validates_and_generates() {
        let day = |y, m, d| DateDay::from_ymd(y, m, d).unwrap();
        let cal = FiscalCalendar::custom("retail13", custom_years(), 1).unwrap();
        assert_eq!(
            cal.year_bounds(2025).unwrap(),
            (day(2025, 11, 1), day(2026, 1, 3))
        );
        let (s, e) = cal.year_bounds(2026).unwrap();
        assert_eq!((s, e), (day(2026, 1, 4), day(2027, 1, 2)));
        let ps = cal.periods_for_year(2026).unwrap();
        check_contiguous(&ps, s, e);
        let normal: Vec<&PeriodDef> = ps.iter().filter(|p| p.kind == PeriodKind::Normal).collect();
        assert_eq!(normal.len(), 13);
        assert_eq!(normal[12].code, "FY2026-P13");
        assert!(normal.iter().all(|p| p.end.0 - p.start.0 == 28));
        let codes: Vec<&str> = ps[13..].iter().map(|p| p.code.as_str()).collect();
        assert_eq!(codes, ["FY2026-OPEN", "FY2026-A1", "FY2026-CLOSE"]);
        for (d, fy) in [
            (day(2025, 11, 1), 2025),
            (day(2026, 1, 3), 2025),
            (day(2026, 1, 4), 2026),
            (day(2027, 1, 2), 2026),
        ] {
            assert_eq!(cal.fiscal_year_of(d).unwrap(), fy, "{}", d.render());
        }
        assert_eq!(
            cal.fiscal_year_of(day(2027, 1, 3)),
            Err(DateError::OutOfRange)
        );
        assert_eq!(
            cal.fiscal_year_of(day(2025, 10, 31)),
            Err(DateError::OutOfRange)
        );
        let undeclared = cal.year_bounds(2027).unwrap_err().to_string();
        assert!(undeclared.contains("2025..=2026"), "{undeclared}");
        assert!(cal.periods_for_year(2024).is_err());

        // Planted negatives: overlapping, gapped and reversed periods; years
        // out of order, not consecutive, or not contiguous; too many periods.
        let a = day(2026, 1, 1);
        for (what, periods) in [
            (
                "overlap",
                vec![(a, day(2026, 1, 10)), (day(2026, 1, 10), day(2026, 1, 20))],
            ),
            (
                "gap",
                vec![(a, day(2026, 1, 10)), (day(2026, 1, 12), day(2026, 1, 20))],
            ),
            ("reversed", vec![(day(2026, 1, 10), a)]),
            ("empty", vec![]),
        ] {
            assert!(CustomYear::from_periods(2026, &periods).is_err(), "{what}");
        }
        let many: Vec<(DateDay, DateDay)> = (0..=MAX_CUSTOM_PERIODS as i32)
            .map(|i| (a.add_days(i).unwrap(), a.add_days(i).unwrap()))
            .collect();
        assert!(CustomYear::from_periods(2026, &many).is_err(), "54 periods");
        let [stub, thirteen] = <[CustomYear; 2]>::try_from(custom_years()).unwrap();
        let skipped = CustomYear {
            fiscal_year: 2027,
            ..thirteen.clone()
        };
        let shifted = CustomYear {
            bounds: thirteen.bounds.iter().map(|d| d.succ().unwrap()).collect(),
            ..thirteen.clone()
        };
        for (what, years) in [
            ("out of order", vec![thirteen.clone(), stub.clone()]),
            ("not consecutive", vec![stub.clone(), skipped]),
            ("not contiguous", vec![stub.clone(), shifted]),
            ("no years", vec![]),
        ] {
            let refused = FiscalCalendar::custom("bad", years, 1);
            assert!(refused.is_err(), "{what}");
        }
    }
}
