//! Read reach under a capability's scope caveats (plan §14.2, doctrine 8):
//! the literal model of which reads the `periods`, `effective` and
//! `known_at` caveats admit, decided from the request alone before anything
//! is read.
//!
//! A read reaches a recorded frontier, a set of periods (`None`: every
//! period) and the last effective day it runs through (`None`: unbounded,
//! or not known before the read). Each caveat the scope carries must cover
//! its dimension, judged in the kernel's order (the known-at pin, then
//! periods, then effective), and the first that does not names the refusal.
//! What a report reaches follows from what it folds:
//! - a stock balance (a trial balance, a stock statement column) runs from
//!   inception through the latest selected period's last day, so it reaches
//!   every period;
//! - activity (a period's activity, an activity statement column, one
//!   account's explanation) reaches exactly its periods, through the latest
//!   of their last days;
//! - a stock as of a civil day reaches every period, through that day;
//! - open items, an entry, its lineage or its evidence reach the whole book.
//!
//! A period code the calendar does not have bounds nothing, so an
//! `effective` caveat refuses it; a `periods` caveat refuses it unless it
//! names it.

use std::collections::BTreeSet;

use fa_time::DateDay;

/// A capability's read-scope caveats in plain values; `None` is no caveat.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scope {
    pub periods: Option<BTreeSet<String>>,
    pub effective_through: Option<DateDay>,
    pub known_at_most: Option<u64>,
}

/// What a read folds, by period code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read {
    /// A stock balance through the latest of these periods.
    Stock(Vec<String>),
    /// The activity of exactly these periods.
    Activity(Vec<String>),
    /// A stock balance as of a civil day.
    AsOf(DateDay),
    /// Every period and effective date.
    WholeBook,
}

/// Whether `scope` admits `read` at recorded frontier `at`; `last_day`
/// names each period's last civil day (`None`: not a period of the
/// calendar). A refusal names the caveat that does not cover the read.
pub fn judge(
    scope: &Scope,
    read: &Read,
    at: u64,
    last_day: impl Fn(&str) -> Option<DateDay>,
) -> Result<(), &'static str> {
    if scope.known_at_most.is_some_and(|pin| at > pin) {
        return Err("known_at");
    }
    let latest = |codes: &[String]| -> Option<DateDay> {
        let mut through: Option<DateDay> = None;
        for code in codes {
            let day = last_day(code)?;
            through = Some(through.map_or(day, |seen| seen.max(day)));
        }
        through
    };
    let (periods, through) = match read {
        Read::Stock(codes) => (None, latest(codes)),
        Read::Activity(codes) => (Some(codes.as_slice()), latest(codes)),
        Read::AsOf(day) => (None, Some(*day)),
        Read::WholeBook => (None, None),
    };
    if let Some(held) = &scope.periods {
        let Some(codes) = periods else {
            return Err("periods");
        };
        if codes.iter().any(|code| !held.contains(code)) {
            return Err("periods");
        }
    }
    if let Some(bound) = scope.effective_through {
        match through {
            Some(day) if day <= bound => {}
            _ => return Err("effective"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(list: &[&str]) -> Vec<String> {
        list.iter().map(|c| (*c).to_string()).collect()
    }

    /// March and April of 2026, by their last days.
    fn last_day(code: &str) -> Option<DateDay> {
        match code {
            "P03" => DateDay::parse("2026-03-31").ok(),
            "P04" => DateDay::parse("2026-04-30").ok(),
            _ => None,
        }
    }

    #[test]
    fn each_caveat_refuses_what_it_does_not_cover_and_admits_the_rest() {
        let march = Scope {
            periods: Some(["P03".to_string()].into_iter().collect()),
            ..Scope::default()
        };
        let through = Scope {
            effective_through: DateDay::parse("2026-03-31").ok(),
            ..Scope::default()
        };
        let pinned = Scope {
            known_at_most: Some(5),
            ..Scope::default()
        };
        let march_day = DateDay::parse("2026-03-20").unwrap();
        for (scope, read, at, verdict) in [
            (&march, Read::Activity(codes(&["P03"])), 9, Ok(())),
            (
                &march,
                Read::Activity(codes(&["P03", "P04"])),
                9,
                Err("periods"),
            ),
            (&march, Read::Stock(codes(&["P03"])), 9, Err("periods")),
            (&march, Read::AsOf(march_day), 9, Err("periods")),
            (&march, Read::WholeBook, 9, Err("periods")),
            (&through, Read::Stock(codes(&["P03"])), 9, Ok(())),
            (&through, Read::Stock(codes(&["P04"])), 9, Err("effective")),
            (
                &through,
                Read::Activity(codes(&["P99"])),
                9,
                Err("effective"),
            ),
            (&through, Read::AsOf(march_day), 9, Ok(())),
            (&through, Read::WholeBook, 9, Err("effective")),
            (&pinned, Read::WholeBook, 5, Ok(())),
            (&pinned, Read::Stock(codes(&["P04"])), 6, Err("known_at")),
            (&Scope::default(), Read::WholeBook, 9, Ok(())),
        ] {
            assert_eq!(
                judge(scope, &read, at, last_day),
                verdict,
                "{scope:?} {read:?}"
            );
        }
    }
}
