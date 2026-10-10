//! Periods: definitions, the discriminator rule, and the state machine
//! (plan §7.3). Transitions are control entries in the journal; this module
//! only decides which transitions are legal.

use core::fmt;

use crate::date::DateDay;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PeriodKind {
    Normal,
    Adjustment,
    Opening,
    Closing,
    /// Precedes the book's opening date; born `Locked`; admits `Migration` only.
    Historical,
}

/// A period definition: half-open civil interval `[start, end)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodDef {
    pub code: String,
    pub fiscal_year: i32,
    pub ordinal: u16,
    pub kind: PeriodKind,
    pub start: DateDay,
    pub end: DateDay,
}

impl PeriodDef {
    pub fn contains(&self, day: DateDay) -> bool {
        day >= self.start && day < self.end
    }

    /// Last civil day (inclusive).
    pub fn last_day(&self) -> DateDay {
        DateDay(self.end.0 - 1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PeriodState {
    Future,
    Open,
    SoftClosed,
    Closed,
    Locked,
}

impl PeriodState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Future => "Future",
            Self::Open => "Open",
            Self::SoftClosed => "SoftClosed",
            Self::Closed => "Closed",
            Self::Locked => "Locked",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "Future" => Self::Future,
            "Open" => Self::Open,
            "SoftClosed" => Self::SoftClosed,
            "Closed" => Self::Closed,
            "Locked" => Self::Locked,
            _ => return None,
        })
    }

    /// Registry tag (stable).
    pub fn tag(self) -> u8 {
        match self {
            Self::Future => 0,
            Self::Open => 1,
            Self::SoftClosed => 2,
            Self::Closed => 3,
            Self::Locked => 4,
        }
    }

    pub fn from_tag(t: u8) -> Option<Self> {
        [
            Self::Future,
            Self::Open,
            Self::SoftClosed,
            Self::Closed,
            Self::Locked,
        ]
        .into_iter()
        .find(|s| s.tag() == t)
    }
}

/// The control-entry kinds that move a period.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PeriodTransition {
    Open,
    SoftClose,
    Close,
    Lock,
    /// Reopen to `Open` or `SoftClosed`; requires a case per the matrix.
    Reopen {
        to: PeriodState,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionError {
    Illegal {
        from: PeriodState,
        transition: PeriodTransition,
    },
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Illegal { from, transition } => write!(
                f,
                "period transition {transition:?} is illegal from {from:?}"
            ),
        }
    }
}

impl core::error::Error for TransitionError {}

/// Apply a transition; the matrix of plan Appendix C's `PeriodControl` row.
pub fn transition(from: PeriodState, t: PeriodTransition) -> Result<PeriodState, TransitionError> {
    use PeriodState::*;
    let to = match (from, t) {
        (Future, PeriodTransition::Open) => Open,
        (Open, PeriodTransition::SoftClose) => SoftClosed,
        (Open, PeriodTransition::Close) | (SoftClosed, PeriodTransition::Close) => Closed,
        (Closed, PeriodTransition::Lock) => Locked,
        (SoftClosed, PeriodTransition::Reopen { to: Open }) => Open,
        (
            Closed,
            PeriodTransition::Reopen {
                to: to @ (Open | SoftClosed),
            },
        ) => to,
        (
            Locked,
            PeriodTransition::Reopen {
                to: to @ (Open | SoftClosed),
            },
        ) => to,
        _ => {
            return Err(TransitionError::Illegal {
                from,
                transition: t,
            });
        }
    };
    Ok(to)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// No period of the calendar contains the date.
    NoPeriod { day: DateDay },
    /// The named discriminator is not a period containing the date.
    BadDiscriminator {
        day: DateDay,
        named: String,
        candidates: Vec<String>,
    },
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPeriod { day } => write!(f, "no period contains {day}"),
            Self::BadDiscriminator {
                day,
                named,
                candidates,
            } => {
                write!(
                    f,
                    "`{named}` is not a period containing {day}; candidates: {}",
                    candidates.join(", ")
                )
            }
        }
    }
}

impl core::error::Error for ResolveError {}

/// Resolve an effective date to exactly one period (plan §7.3): the `Normal`
/// period by default; a special period only when named by the discriminator.
pub fn resolve_period<'a>(
    periods: &'a [PeriodDef],
    day: DateDay,
    discriminator: Option<&str>,
) -> Result<&'a PeriodDef, ResolveError> {
    let containing: Vec<&PeriodDef> = periods.iter().filter(|p| p.contains(day)).collect();
    match discriminator {
        None => containing
            .iter()
            .copied()
            .find(|p| p.kind == PeriodKind::Normal || p.kind == PeriodKind::Historical)
            .ok_or(ResolveError::NoPeriod { day }),
        Some(code) => containing
            .iter()
            .copied()
            .find(|p| p.code == code)
            .ok_or_else(|| ResolveError::BadDiscriminator {
                day,
                named: code.into(),
                candidates: containing.iter().map(|p| p.code.clone()).collect(),
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calendar::FiscalCalendar;

    /// fa-xwv's example: December 31 belongs to normal P12 by default, and to
    /// adjustment period A1 or the closing period only when named.
    #[test]
    fn december_31_resolves_by_discriminator() {
        let cal = FiscalCalendar::monthly("cy", 1, 1).unwrap();
        let ps = cal.periods_for_year(2026).unwrap();
        let dec31 = DateDay::parse("2026-12-31").unwrap();
        assert_eq!(resolve_period(&ps, dec31, None).unwrap().code, "FY2026-P12");
        assert_eq!(
            resolve_period(&ps, dec31, Some("FY2026-A1")).unwrap().kind,
            PeriodKind::Adjustment
        );
        assert_eq!(
            resolve_period(&ps, dec31, Some("FY2026-CLOSE"))
                .unwrap()
                .kind,
            PeriodKind::Closing
        );
        let err = resolve_period(&ps, dec31, Some("FY2026-P11")).unwrap_err();
        assert!(
            matches!(err, ResolveError::BadDiscriminator { ref candidates, .. } if candidates.len() == 3),
            "{err:?}"
        );
        let jan1 = DateDay::parse("2026-01-01").unwrap();
        assert_eq!(resolve_period(&ps, jan1, None).unwrap().code, "FY2026-P01");
        assert_eq!(
            resolve_period(&ps, jan1, Some("FY2026-OPEN")).unwrap().kind,
            PeriodKind::Opening
        );
        let mid = DateDay::parse("2026-06-15").unwrap();
        assert_eq!(resolve_period(&ps, mid, None).unwrap().code, "FY2026-P06");
        assert!(resolve_period(&ps, DateDay::parse("2027-01-01").unwrap(), None).is_err());
    }

    #[test]
    fn state_machine_matches_the_matrix() {
        use PeriodState::*;
        assert_eq!(transition(Future, PeriodTransition::Open), Ok(Open));
        assert_eq!(
            transition(Open, PeriodTransition::SoftClose),
            Ok(SoftClosed)
        );
        assert_eq!(transition(SoftClosed, PeriodTransition::Close), Ok(Closed));
        assert_eq!(transition(Open, PeriodTransition::Close), Ok(Closed));
        assert_eq!(transition(Closed, PeriodTransition::Lock), Ok(Locked));
        assert_eq!(
            transition(Locked, PeriodTransition::Reopen { to: Open }),
            Ok(Open)
        );
        assert_eq!(
            transition(Closed, PeriodTransition::Reopen { to: SoftClosed }),
            Ok(SoftClosed)
        );
        assert!(transition(Future, PeriodTransition::Close).is_err());
        assert!(
            transition(Open, PeriodTransition::Lock).is_err(),
            "lock requires Closed"
        );
        assert!(transition(Locked, PeriodTransition::Open).is_err());
        assert!(transition(Open, PeriodTransition::Reopen { to: Open }).is_err());
        assert!(transition(Closed, PeriodTransition::Reopen { to: Locked }).is_err());
        for s in [Future, Open, SoftClosed, Closed, Locked] {
            assert_eq!(PeriodState::from_tag(s.tag()), Some(s));
            assert_eq!(PeriodState::from_name(s.name()), Some(s));
        }
    }
}
