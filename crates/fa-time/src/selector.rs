//! Effective-time selectors (plan §4.8, §7.4). Omitted effective means `All`,
//! never a wall clock.

use crate::calendar::FiscalCalendar;
use crate::date::{DateDay, DateError};
use crate::period::PeriodDef;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectiveSelector {
    All,
    /// One period by code (the discriminator-aware code, e.g. `FY2026-P03`).
    Period(String),
    /// Half-open `[start, end)`.
    Range {
        start: DateDay,
        end: DateDay,
    },
    /// Everything effective on or before `day` (stock positions).
    AsOf(DateDay),
    /// From the fiscal year's first day through `day` inclusive.
    YearToDate(DateDay),
    /// From the book's opening date through `day` inclusive (fund/grant/project).
    InceptionToDate(DateDay),
}

/// Why a selector could not be resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectorError {
    /// `Period(code)` names a period the book does not have. Never `All`.
    UnknownPeriod(String),
    Date(DateError),
}

impl core::fmt::Display for SelectorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownPeriod(c) => write!(f, "unknown period `{c}`"),
            Self::Date(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for SelectorError {}

impl From<DateError> for SelectorError {
    fn from(e: DateError) -> Self {
        Self::Date(e)
    }
}

impl EffectiveSelector {
    /// Resolve to a concrete half-open day interval, given the calendar, the
    /// known period definitions, and the book's opening date. `None` means
    /// unbounded (`All`); an unknown period is a typed error, never `All`.
    pub fn interval(
        &self,
        calendar: &FiscalCalendar,
        periods: &[PeriodDef],
        opening_date: DateDay,
    ) -> Result<Option<(DateDay, DateDay)>, SelectorError> {
        Ok(match self {
            Self::All => None,
            Self::Period(code) => periods
                .iter()
                .find(|p| &p.code == code)
                .map(|p| Some((p.start, p.end)))
                .ok_or_else(|| SelectorError::UnknownPeriod(code.clone()))?,
            Self::Range { start, end } => Some((*start, *end)),
            Self::AsOf(day) => Some((DateDay(i32::MIN), day.succ()?)),
            Self::YearToDate(day) => {
                let fy = calendar.fiscal_year_of(*day)?;
                let (start, _) = calendar.year_bounds(fy)?;
                Some((start, day.succ()?))
            }
            Self::InceptionToDate(day) => Some((opening_date, day.succ()?)),
        })
    }

    /// Does `day` fall inside the selector?
    pub fn contains(
        &self,
        day: DateDay,
        calendar: &FiscalCalendar,
        periods: &[PeriodDef],
        opening_date: DateDay,
    ) -> Result<bool, SelectorError> {
        Ok(match self.interval(calendar, periods, opening_date)? {
            None => true,
            Some((s, e)) => day >= s && day < e,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_resolve_against_the_calendar() {
        let cal = FiscalCalendar::monthly("usgov", 10, 0).unwrap();
        let ps = cal.periods_for_year(2026).unwrap();
        let opening = DateDay::parse("2020-10-01").unwrap();
        let d = |s: &str| DateDay::parse(s).unwrap();
        let c =
            |sel: &EffectiveSelector, day: &str| sel.contains(d(day), &cal, &ps, opening).unwrap();
        assert!(c(&EffectiveSelector::All, "1999-01-01"));
        let p3 = EffectiveSelector::Period("FY2026-P03".into()); // Dec 2025
        assert!(c(&p3, "2025-12-15"));
        assert!(!c(&p3, "2026-01-01"));
        let ytd = EffectiveSelector::YearToDate(d("2026-03-15"));
        assert!(c(&ytd, "2025-10-01"));
        assert!(c(&ytd, "2026-03-15"));
        assert!(!c(&ytd, "2026-03-16"));
        assert!(!c(&ytd, "2025-09-30"));
        let itd = EffectiveSelector::InceptionToDate(d("2026-03-15"));
        assert!(c(&itd, "2020-10-01"));
        assert!(!c(&itd, "2020-09-30"));
        let asof = EffectiveSelector::AsOf(d("2026-03-15"));
        assert!(c(&asof, "1980-01-01"));
        assert!(!c(&asof, "2026-03-16"));
        let unknown = EffectiveSelector::Period("FY2026-P99".into());
        assert_eq!(
            unknown.interval(&cal, &ps, opening),
            Err(SelectorError::UnknownPeriod("FY2026-P99".into()))
        );
        assert!(
            unknown
                .contains(d("2026-01-01"), &cal, &ps, opening)
                .is_err(),
            "an unknown period is never All"
        );
    }
}
