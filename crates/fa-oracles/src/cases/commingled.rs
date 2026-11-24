//! Date and movement reader for `commingled_fifo_v1` transcripts. The case
//! binds raw bytes before parsing. An observation bounds imprecise dates and
//! each `MM/DD/YY` label uses the layout's 2000–2099 date domain.

use std::collections::BTreeMap;

use super::date::Day;

closed_set! {
    /// The economic direction and stated source class of a row.
    MovementKind {
        Opening => "opening",
        Other => "other",
        Social => "social",
        Debit => "debit",
        ScheduleDebit => "schedule-debit",
        TrusteeDebit => "trustee-debit",
    }
}

impl MovementKind {
    #[must_use]
    pub const fn is_debit(self) -> bool {
        matches!(self, Self::Debit | Self::ScheduleDebit | Self::TrusteeDebit)
    }
}

/// Selects one of the two alternative withdrawals at the petition boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Schedule,
    Trustee,
}

impl Endpoint {
    const fn kind(self) -> MovementKind {
        match self {
            Self::Schedule => MovementKind::ScheduleDebit,
            Self::Trustee => MovementKind::TrusteeDebit,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.kind().as_str()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Movement<'a> {
    pub line: usize,
    pub observed: Day,
    pub printed: &'a str,
    pub exact_day: Option<Day>,
    pub earliest: Day,
    pub latest: Day,
    pub kind: MovementKind,
    pub cents: i128,
}

impl Movement<'_> {
    /// A representative effective day for this reconstruction. An exact
    /// printed day is retained. For an imprecise date, choose the last day
    /// within its allowed range, which can precede the statement close.
    #[must_use]
    pub const fn reconstruction_day(&self) -> Day {
        self.latest
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct FundingBound {
    pub minimum_cents: i128,
    pub minimum_day: Day,
    pub ending_cents: i128,
    pub withdrawals_cents: i128,
}

#[derive(Debug)]
pub struct Transcript<'a> {
    rows: Vec<Movement<'a>>,
}

impl<'a> Transcript<'a> {
    /// Parses the authenticated text in statement order. A precise date
    /// can precede the previous statement observation when printed that way.
    ///
    /// # Errors
    /// A row or date is malformed, the opening is ambiguous, or the two
    /// endpoint alternatives are missing, repeated, or lie outside the final
    /// observation.
    pub fn parse(text: &'a str) -> Result<Self, String> {
        let mut rows = Vec::new();
        let mut previous = None;
        let mut current = None;
        for (index, line) in text.lines().enumerate() {
            if line.starts_with('#') {
                continue;
            }
            let number = index + 1;
            let problem = |why| format!("movement line {number}: {why}");
            let mut fields = line.split('\t');
            let (Some(observed), Some(printed), Some(kind), Some(cents), None) = (
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
            ) else {
                return Err(problem("expected four tab-separated fields"));
            };
            let observed =
                Day::parse(observed).ok_or_else(|| problem("invalid observation date"))?;
            if current != Some(observed) {
                if current.is_some_and(|day| observed < day) {
                    return Err(problem("observations run backwards"));
                }
                previous = current;
                current = Some(observed);
            }
            let kind =
                MovementKind::parse(kind).ok_or_else(|| problem("unregistered movement kind"))?;
            let cents = cents
                .parse::<i128>()
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| problem("expected positive integer cents"))?;
            let (earliest, latest, exact_day) = match printed {
                "unknown" | "unknown, before petition" => (
                    previous.ok_or_else(|| problem("unknown date needs a prior observation"))?,
                    observed,
                    None,
                ),
                value => match value.split_once('–') {
                    Some((first, last)) => (
                        printed_day(first).ok_or_else(|| problem("invalid interval start"))?,
                        printed_day(last).ok_or_else(|| problem("invalid interval end"))?,
                        None,
                    ),
                    None => {
                        let day =
                            printed_day(value).ok_or_else(|| problem("invalid printed date"))?;
                        (day, day, Some(day))
                    }
                },
            };
            if earliest > latest || latest > observed {
                return Err(problem(
                    "printed bounds are reversed or extend past the observation",
                ));
            }
            rows.push(Movement {
                line: number,
                observed,
                printed,
                exact_day,
                earliest,
                latest,
                kind,
                cents,
            });
        }
        let Some((opening, tail)) = rows.split_first() else {
            return Err("movement transcript is empty".into());
        };
        if opening.kind != MovementKind::Opening
            || opening.exact_day != Some(opening.observed)
            || tail
                .iter()
                .any(|r| r.kind == MovementKind::Opening || r.earliest < opening.observed)
        {
            return Err("expected a single dated opening before all other movements".into());
        }
        for endpoint in [Endpoint::Schedule, Endpoint::Trustee] {
            let mut alternatives = rows.iter().filter(|row| row.kind == endpoint.kind());
            if !alternatives
                .next()
                .is_some_and(|row| Some(row.observed) == current)
                || alternatives.next().is_some()
            {
                return Err(format!(
                    "expected exactly one {} at the final observation",
                    endpoint.as_str()
                ));
            }
        }
        Ok(Self { rows })
    }

    /// The selected movement stream, in source-line order.
    pub fn movements(&self, endpoint: Endpoint) -> impl Iterator<Item = &Movement<'a>> {
        self.rows.iter().filter(move |row| {
            !matches!(
                row.kind,
                MovementKind::ScheduleDebit | MovementKind::TrusteeDebit
            ) || row.kind == endpoint.kind()
        })
    }

    /// A conservative cash-balance bound. Every debit may occur on its
    /// earliest possible day, before all same-day credits. Every credit is
    /// delayed to its latest possible day. Opening cash precedes either.
    ///
    /// # Errors
    /// Arithmetic exceeds the exact `i128` cents domain.
    pub fn funding_bound(&self, endpoint: Endpoint) -> Result<FundingBound, &'static str> {
        let opening = &self.rows[0];
        let mut totals = BTreeMap::<Day, (i128, i128)>::new();
        let mut withdrawals = 0_i128;
        let overflow = "movement totals exceed exact cents";
        for row in self.movements(endpoint).skip(1) {
            if row.kind.is_debit() {
                let debits = &mut totals.entry(row.earliest).or_default().0;
                *debits = debits.checked_add(row.cents).ok_or(overflow)?;
                withdrawals = withdrawals.checked_add(row.cents).ok_or(overflow)?;
            } else {
                let credits = &mut totals.entry(row.latest).or_default().1;
                *credits = credits.checked_add(row.cents).ok_or(overflow)?;
            }
        }
        let mut balance = opening.cents;
        let mut minimum = (balance, opening.observed);
        for (day, (debits, credits)) in totals {
            balance = balance.checked_sub(debits).ok_or(overflow)?;
            minimum = minimum.min((balance, day));
            balance = balance.checked_add(credits).ok_or(overflow)?;
        }
        Ok(FundingBound {
            minimum_cents: minimum.0,
            minimum_day: minimum.1,
            ending_cents: balance,
            withdrawals_cents: withdrawals,
        })
    }
}

fn printed_day(s: &str) -> Option<Day> {
    let mut parts = s.split('/');
    let (Some(month), Some(day), Some(year), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    (month.len() == 2 && day.len() == 2 && year.len() == 2)
        .then(|| Day::parse(&format!("20{year}-{month}-{day}")))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINC: &str = include_str!("../../cases/minc/fifo-movements.tsv");
    const SMALL: &str = "2024-01-01\t01/01/24\topening\t20\n\
        2024-01-31\tunknown\tother\t10\n\
        2024-01-31\tunknown, before petition\tschedule-debit\t25\n\
        2024-01-31\tunknown, before petition\ttrustee-debit\t18\n";

    #[test]
    fn sourced_minc_rows_preserve_dates_and_both_funding_bounds() {
        let transcript = Transcript::parse(MINC).unwrap();
        assert_eq!(transcript.rows.len(), 71);
        for (endpoint, ending, withdrawals) in [
            (Endpoint::Schedule, 3_778_946, 3_945_394),
            (Endpoint::Trustee, 3_753_741, 3_970_599),
        ] {
            assert_eq!(transcript.movements(endpoint).count(), 70);
            let bound = transcript.funding_bound(endpoint).unwrap();
            assert_eq!(bound.ending_cents, ending);
            assert_eq!(bound.withdrawals_cents, withdrawals);
            assert_eq!(bound.minimum_cents, 2_287_531);
            assert_eq!(bound.minimum_day, Day::parse("2023-05-23").unwrap());
        }
        let older_printed_credit = transcript
            .rows
            .iter()
            .find(|row| {
                row.printed == "12/13/23" && row.observed == Day::parse("2024-01-25").unwrap()
            })
            .unwrap();
        assert_eq!(older_printed_credit.exact_day, Day::parse("2023-12-13"));
        assert_eq!(
            Some(older_printed_credit.reconstruction_day()),
            older_printed_credit.exact_day
        );
        let first_interval = &transcript.rows[1];
        assert_eq!(first_interval.exact_day, None);
        assert_eq!(first_interval.earliest, Day::parse("2023-03-24").unwrap());
        assert_eq!(first_interval.latest, Day::parse("2023-03-28").unwrap());
        assert_eq!(
            Some(first_interval.reconstruction_day()),
            Day::parse("2023-03-28")
        );
        assert!(first_interval.reconstruction_day() < first_interval.observed);
        let unknown = transcript
            .rows
            .iter()
            .find(|row| row.printed == "unknown")
            .unwrap();
        assert_eq!(unknown.exact_day, None);
        assert_eq!(unknown.reconstruction_day(), unknown.observed);
    }

    #[test]
    fn positive_final_cash_can_still_admit_an_overdraft_within_date_bounds() {
        let transcript = Transcript::parse(SMALL).unwrap();
        let schedule = transcript.funding_bound(Endpoint::Schedule).unwrap();
        assert_eq!((schedule.ending_cents, schedule.minimum_cents), (5, -5));
        let trustee = transcript.funding_bound(Endpoint::Trustee).unwrap();
        assert_eq!((trustee.ending_cents, trustee.minimum_cents), (12, 2));
    }

    #[test]
    fn malformed_dates_rows_and_endpoint_alternatives_refuse() {
        for (from, to, why) in [
            ("01/01/24", "02/30/24", "invalid printed date"),
            (
                "unknown\tother",
                "02/01/24\tother",
                "extend past the observation",
            ),
            (
                "unknown\tother",
                "01/12/24–01/05/24\tother",
                "bounds are reversed",
            ),
            ("other\t10", "other\t0", "positive integer cents"),
            ("trustee-debit", "debit", "exactly one trustee-debit"),
        ] {
            let changed = SMALL.replacen(from, to, 1);
            let error = Transcript::parse(&changed).unwrap_err();
            assert!(error.contains(why), "{error}");
        }
    }
}
