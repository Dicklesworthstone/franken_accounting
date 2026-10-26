//! The K-SCOPE word rule, `case-fetch-scope-v2` (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §2.1; bead fa-yugf.7, A3a). `tools/case-fetch/case_fetch.py`'s `scope_ok`
//! implements the same rule word for word, and both are tested on the
//! `[[scope]]` rows of `data/binding_fixtures.toml`, verdicts and messages.
//!
//! An `about_scope` is one of:
//! - `entry:<fact>`: the period of that fact's entry, its first
//!   `period_literal` value, else its own `period:` scope;
//! - `period:<label>`: a quarter `YYYYQn`, a calendar fiscal year `FYyyyy`
//!   or a month `YYYY-MM`;
//! - `scheme:<slug>`, whose range is read from the slug's tail: two quarters
//!   `<P1>-<P2>`, two months `<YYYY-MM>-<YYYY-MM>`, one day `<YYYY-MM-DD>`,
//!   one month `<YYYY-MM>` or one quarter `<P>`. A tail with a component
//!   that starts with four digits but parses as none of these, or a range
//!   that runs backwards, is refused; a slug with no dated tail bounds no
//!   period (`range=none`);
//! - `account:<id>`, an id being 4–12 upper-case letters and digits with at
//!   least one digit.
//!
//! The quote's words are scanned once, left to right, trying at each word in
//! this order: a two-date range (`July 17, 2001 through July 19, 2001`), a
//! same-month range (`July 17 and 19, 2000`, `July 17–19, 2000`), a date
//! (`July 17, 2001`, `17 July 2001`), a month (`September 2001`), a quarter
//! phrase (`the first quarter of 2001`, `first-quarter 2001`), a quarter
//! label (`Q1 2001`, `2001 Q1`, `1Q01`, `2001Q1`), a fiscal year (`fiscal
//! 2001`, `fiscal year 2001`, `FY 2001`, `FY2001`), an account word
//! (`account 1ZR010`, `account No. 1ZR010`, `account number 1ZR010`,
//! `account #1ZR010`, `account:1ZR010`), and a bare id the case's
//! `account:` scopes name.
//!
//! The verdict: a named quarter or fiscal year must equal a `period:` or
//! `entry:` scope's label, or lie inside a scheme's range (all its days); a
//! named date, day range or month must lie inside a scheme's range, and is
//! not compared with a `period:` or `entry:` scope, because an entry's quote
//! names the day it was made beside the period it was booked to (WorldCom's
//! July 17, 2001 entry for the second quarter); a named account must equal
//! an `account:` scope's id; a `scheme:` scope never backs a
//! `journal_entry` fact (§2.1: only through an interpretation).

use core::fmt;
use std::collections::BTreeSet;

use super::date::{Day, days_in_month};
use super::normalize::normalize_str;

/// The rule's version, as A9's receipts and the check report name it.
pub const SCOPE_VERSION: &str = "case-fetch-scope-v2";

/// A closed span of days.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub first: Day,
    pub last: Day,
}

impl Span {
    fn contains(self, other: Self) -> bool {
        self.first <= other.first && other.last <= self.last
    }
}

/// Something the quote names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Named {
    /// A quarter or fiscal year: its label and its days.
    Period(String, Span),
    /// A date, a day range or a month: its text and its days.
    Days(String, Span),
    Account(String),
}

impl fmt::Display for Named {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Period(l, _) => write!(f, "period {l}"),
            Self::Days(t, _) => f.write_str(t),
            Self::Account(a) => write!(f, "account {a}"),
        }
    }
}

const MONTHS: [&str; 12] = [
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
];

/// A month name, its three-letter abbreviation or `Sept`, any case, with
/// an optional trailing `.`.
fn month_of(word: &str) -> Option<u32> {
    let w = word.strip_suffix('.').unwrap_or(word).to_ascii_lowercase();
    let i = MONTHS.iter().position(|m| {
        *m == w || (w.len() == 3 && m.starts_with(w.as_str())) || (w == "sept" && *m == "september")
    })?;
    u32::try_from(i + 1).ok()
}

fn digits(word: &str, n: usize) -> bool {
    word.len() == n && word.bytes().all(|b| b.is_ascii_digit())
}

fn year_of(word: &str) -> Option<i64> {
    digits(word, 4).then(|| word.parse().ok()).flatten()
}

fn day_of(word: &str) -> Option<u32> {
    (digits(word, 1) || digits(word, 2))
        .then(|| word.parse().ok())
        .flatten()
}

fn ordinal_of(word: &str) -> Option<u32> {
    match word.to_ascii_lowercase().as_str() {
        "first" => Some(1),
        "second" => Some(2),
        "third" => Some(3),
        "fourth" => Some(4),
        _ => None,
    }
}

fn joiner(word: &str) -> bool {
    matches!(word, "and" | "through" | "to" | "-" | "\u{2013}")
}

/// A word without the punctuation around it.
fn clean(word: &str) -> &str {
    word.trim_start_matches(['(', '[', '"', '\u{201c}'])
        .trim_end_matches([',', '.', ';', ':', ')', ']', '"', '\u{201d}'])
}

fn day(year: i64, month: u32, day: u32) -> Option<Day> {
    ((1..=12).contains(&month) && day >= 1 && day <= days_in_month(year, month)).then_some(Day {
        year,
        month,
        day,
    })
}

fn quarter(year: i64, q: u32) -> Option<Span> {
    if !(1..=4).contains(&q) {
        return None;
    }
    let m = 3 * q - 2;
    Some(Span {
        first: day(year, m, 1)?,
        last: day(year, m + 2, days_in_month(year, m + 2))?,
    })
}

fn month_span(year: i64, month: u32) -> Option<Span> {
    Some(Span {
        first: day(year, month, 1)?,
        last: day(year, month, days_in_month(year, month))?,
    })
}

/// A quarter label's year and quarter (`2001Q2`).
fn quarter_label(label: &str) -> Option<(i64, u32)> {
    let b = label.as_bytes();
    if b.len() != 6 || b[4] != b'Q' || !(b'1'..=b'4').contains(&b[5]) {
        return None;
    }
    Some((year_of(&label[..4])?, u32::from(b[5] - b'0')))
}

/// A `YYYY-MM` month's year and month.
fn month_label(label: &str) -> Option<(i64, u32)> {
    let (y, m) = label.split_once('-')?;
    let m: u32 = digits(m, 2).then(|| m.parse().ok()).flatten()?;
    (1..=12).contains(&m).then_some((year_of(y)?, m))
}

/// The days of a period label: `YYYYQn`, `FYyyyy` or `YYYY-MM`.
#[must_use]
pub fn period_span(label: &str) -> Option<Span> {
    if let Some(y) = label.strip_prefix("FY").and_then(year_of) {
        return Some(Span {
            first: day(y, 1, 1)?,
            last: day(y, 12, 31)?,
        });
    }
    if let Some((y, q)) = quarter_label(label) {
        return quarter(y, q);
    }
    let (y, m) = month_label(label)?;
    month_span(y, m)
}

/// A one-word quarter or fiscal-year label: `1Q01`, `2001Q1`, `FY2001`.
fn label_word(word: &str) -> Option<String> {
    let b = word.as_bytes();
    if b.len() == 4 && (b'1'..=b'4').contains(&b[0]) && b[1] == b'Q' && digits(&word[2..], 2) {
        let yy: i64 = word[2..].parse().ok()?;
        let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
        return Some(format!("{year}Q{}", b[0] - b'0'));
    }
    if quarter_label(word).is_some() {
        return Some(word.to_string());
    }
    word.strip_prefix("FY")
        .and_then(year_of)
        .map(|y| format!("FY{y}"))
}

/// Whether `id` has the account-id shape.
#[must_use]
pub fn account_id(id: &str) -> bool {
    (4..=12).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        && id.bytes().any(|b| b.is_ascii_digit())
}

/// Everything a quote names, in order. `accounts` are the ids the case's
/// `account:` scopes name, recognized as bare words too.
#[must_use]
pub fn named(quote: &str, accounts: &BTreeSet<String>) -> Vec<Named> {
    let norm = normalize_str(quote);
    let words: Vec<&str> = norm
        .split(' ')
        .filter(|w| !w.is_empty())
        .map(clean)
        .collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < words.len() {
        match scan(&words, i, accounts) {
            Some((n, next)) => {
                out.push(n);
                i = next;
            }
            None => i += 1,
        }
    }
    out
}

fn days_named(text: String, first: Day, last: Day) -> Named {
    Named::Days(text, Span { first, last })
}

fn period_named(label: String) -> Option<Named> {
    let span = period_span(&label)?;
    Some(Named::Period(label, span))
}

/// What the words from `i` name, and the index after them.
fn scan(words: &[&str], i: usize, accounts: &BTreeSet<String>) -> Option<(Named, usize)> {
    let at = |k: usize| words.get(k).copied().unwrap_or("");
    if let Some(m1) = month_of(at(i)) {
        // Month D, YYYY (joiner) Month D, YYYY.
        if let (Some(d1), Some(y1)) = (day_of(at(i + 1)), year_of(at(i + 2)))
            && joiner(at(i + 3))
            && let (Some(m2), Some(d2), Some(y2)) =
                (month_of(at(i + 4)), day_of(at(i + 5)), year_of(at(i + 6)))
            && let (Some(a), Some(b)) = (day(y1, m1, d1), day(y2, m2, d2))
            && a <= b
        {
            return Some((days_named(format!("{a}..{b}"), a, b), i + 7));
        }
        // Month D1–D2, YYYY and Month D1 (joiner) D2, YYYY.
        let joined = at(i + 1)
            .split_once(['-', '\u{2013}'])
            .and_then(|(a, b)| Some(((day_of(a)?, day_of(b)?), i + 2)));
        let spaced = match (day_of(at(i + 1)), joiner(at(i + 2)), day_of(at(i + 3))) {
            (Some(a), true, Some(b)) => Some(((a, b), i + 4)),
            _ => None,
        };
        if let Some(((d1, d2), year_at)) = joined.or(spaced)
            && let Some(y) = year_of(at(year_at))
            && let (Some(a), Some(b)) = (day(y, m1, d1), day(y, m1, d2))
            && a <= b
        {
            return Some((days_named(format!("{a}..{b}"), a, b), year_at + 1));
        }
        // Month D, YYYY.
        if let (Some(d), Some(y)) = (day_of(at(i + 1)), year_of(at(i + 2)))
            && let Some(a) = day(y, m1, d)
        {
            return Some((days_named(a.to_string(), a, a), i + 3));
        }
        // Month YYYY.
        if let Some(y) = year_of(at(i + 1))
            && let Some(s) = month_span(y, m1)
        {
            return Some((Named::Days(format!("{y:04}-{m1:02}"), s), i + 2));
        }
    }
    // D Month YYYY.
    if let (Some(d), Some(m), Some(y)) = (day_of(at(i)), month_of(at(i + 1)), year_of(at(i + 2)))
        && let Some(a) = day(y, m, d)
    {
        return Some((days_named(a.to_string(), a, a), i + 3));
    }
    // first quarter [of] YYYY; first-quarter [of] YYYY.
    let ord = match at(i).split_once('-') {
        Some((o, q)) if q.eq_ignore_ascii_case("quarter") => ordinal_of(o).map(|n| (n, i + 1)),
        _ if at(i + 1).eq_ignore_ascii_case("quarter") => ordinal_of(at(i)).map(|n| (n, i + 2)),
        _ => None,
    };
    if let Some((q, after)) = ord {
        let year_at = if at(after).eq_ignore_ascii_case("of") {
            after + 1
        } else {
            after
        };
        if let Some(y) = year_of(at(year_at)) {
            return Some((period_named(format!("{y}Q{q}"))?, year_at + 1));
        }
    }
    // Q1 YYYY; YYYY Q1.
    let q_word = |w: &str| {
        w.strip_prefix('Q')
            .filter(|q| digits(q, 1))
            .map(str::to_string)
    };
    if let (Some(q), Some(y)) = (q_word(at(i)), year_of(at(i + 1)))
        && let Some(n) = period_named(format!("{y}Q{q}"))
    {
        return Some((n, i + 2));
    }
    if let (Some(y), Some(q)) = (year_of(at(i)), q_word(at(i + 1)))
        && let Some(n) = period_named(format!("{y}Q{q}"))
    {
        return Some((n, i + 2));
    }
    if let Some(n) = label_word(at(i)).and_then(period_named) {
        return Some((n, i + 1));
    }
    // fiscal YYYY; fiscal year YYYY; FY YYYY.
    let fiscal = at(i).eq_ignore_ascii_case("fiscal");
    if fiscal || at(i) == "FY" {
        let year_at = if fiscal && at(i + 1).eq_ignore_ascii_case("year") {
            i + 2
        } else {
            i + 1
        };
        if let Some(y) = year_of(at(year_at)) {
            return Some((period_named(format!("FY{y}"))?, year_at + 1));
        }
    }
    // account:<id>; account <id>, account No. <id>, account number <id>, account #<id>.
    let w = at(i);
    if let Some(id) = w.strip_prefix("account:").filter(|id| account_id(id)) {
        return Some((Named::Account(id.to_string()), i + 1));
    }
    if w.eq_ignore_ascii_case("account") || w.eq_ignore_ascii_case("accounts") {
        let j = if at(i + 1).eq_ignore_ascii_case("no") || at(i + 1).eq_ignore_ascii_case("number")
        {
            i + 2
        } else {
            i + 1
        };
        let id = at(j).strip_prefix('#').unwrap_or(at(j));
        if account_id(id) {
            return Some((Named::Account(id.to_string()), j + 1));
        }
    }
    accounts
        .contains(w)
        .then(|| (Named::Account(w.to_string()), i + 1))
}

/// A parsed `about_scope`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    Entry(String),
    Period(String, Span),
    /// The slug, and its range's tail text and days.
    Scheme(String, Option<(String, Span)>),
    Account(String),
}

/// Parses an `about_scope`.
///
/// # Errors
///
/// Why it is none of the four forms, or why its scheme range is refused.
pub fn parse_scope(about: &str) -> Result<Scope, String> {
    if let Some(fact) = about.strip_prefix("entry:").filter(|f| !f.is_empty()) {
        return Ok(Scope::Entry(fact.to_string()));
    }
    if let Some(label) = about.strip_prefix("period:") {
        let span = period_span(label)
            .ok_or_else(|| format!("`{about}`: a period is YYYYQn, FYyyyy or YYYY-MM"))?;
        return Ok(Scope::Period(label.to_string(), span));
    }
    if let Some(id) = about.strip_prefix("account:") {
        return if account_id(id) {
            Ok(Scope::Account(id.to_string()))
        } else {
            Err(format!(
                "`{about}`: an account id is 4-12 upper-case letters and digits with a digit"
            ))
        };
    }
    if let Some(slug) = about.strip_prefix("scheme:").filter(|s| !s.is_empty()) {
        return Ok(Scope::Scheme(slug.to_string(), scheme_range(slug)?));
    }
    Err(format!(
        "`{about}` is not entry:<fact>, period:<label>, scheme:<slug> or account:<id>"
    ))
}

/// The range in a scheme slug's tail, if it has one.
fn scheme_range(slug: &str) -> Result<Option<(String, Span)>, String> {
    let parts: Vec<&str> = slug.split('-').collect();
    let n = parts.len();
    // The tail's k last components, when a name component precedes them.
    let tail = |k: usize| (n > k).then(|| &parts[n - k..]);
    let quarter_of = |w: &str| quarter_label(w).and_then(|(y, q)| quarter(y, q));
    let month_of_pair = |y: &str, m: &str| {
        year_of(y)?;
        month_label(&format!("{y}-{m}")).and_then(|(y, m)| month_span(y, m))
    };
    let ranged = |t: &[&str], a: Span, b: Span| {
        if a.first <= b.last {
            Ok(Some((
                t.join("-"),
                Span {
                    first: a.first,
                    last: b.last,
                },
            )))
        } else {
            Err(format!("scheme `{slug}`: its range runs backwards"))
        }
    };
    if let Some(t @ [p1, p2]) = tail(2)
        && let (Some(a), Some(b)) = (quarter_of(p1), quarter_of(p2))
    {
        return ranged(t, a, b);
    }
    if let Some(t @ [y1, m1, y2, m2]) = tail(4)
        && let (Some(a), Some(b)) = (month_of_pair(y1, m1), month_of_pair(y2, m2))
    {
        return ranged(t, a, b);
    }
    if let Some(t @ [y, m, d]) = tail(3)
        && digits(d, 2)
        && let Some(s) = month_of_pair(y, m)
        && let Some(one) = d
            .parse()
            .ok()
            .and_then(|d| day(s.first.year, s.first.month, d))
    {
        return Ok(Some((
            t.join("-"),
            Span {
                first: one,
                last: one,
            },
        )));
    }
    if let Some(t @ [y, m]) = tail(2)
        && let Some(s) = month_of_pair(y, m)
    {
        return Ok(Some((t.join("-"), s)));
    }
    if let Some(t @ [p]) = tail(1)
        && let Some(s) = quarter_of(p)
    {
        return Ok(Some((t.join("-"), s)));
    }
    let dated = parts
        .iter()
        .skip(1)
        .skip(n.saturating_sub(4))
        .any(|w| w.len() >= 4 && w.bytes().take(4).all(|b| b.is_ascii_digit()));
    if dated {
        return Err(format!(
            "scheme `{slug}`: its range tail parses as no quarter, month or day form"
        ));
    }
    Ok(None)
}

/// Resolves an `entry:` scope's fact to its period label: `Ok(None)` when
/// the fact has none, `Err` when there is no such fact.
pub type EntryPeriod<'a> = &'a dyn Fn(&str) -> Result<Option<String>, String>;

/// The scope's own refusals, which need no quote: its form, its scheme
/// range, and a scheme scope on a `journal_entry` fact.
///
/// # Errors
///
/// The refusal, in words.
pub fn check_scope(about: &str, granularity: &str) -> Result<Scope, String> {
    let scope = parse_scope(about)?;
    if matches!(scope, Scope::Scheme(..)) && granularity == "journal_entry" {
        return Err(format!(
            "`{about}` is scheme-level; it backs a journal_entry fact only through an interpretation"
        ));
    }
    Ok(scope)
}

/// The K-SCOPE verdict for one quote: `Ok(Some("range=none"))` for a
/// rangeless scheme, `Ok(None)` otherwise, or the conflict.
///
/// # Errors
///
/// The scope's refusal or the conflict, in words.
pub fn check(
    quote: &str,
    about: &str,
    granularity: &str,
    entry_period: EntryPeriod<'_>,
    accounts: &BTreeSet<String>,
) -> Result<Option<&'static str>, String> {
    let scope = check_scope(about, granularity)?;
    let names = named(quote, accounts);
    // A period or entry scope's label, or a scheme's range and its text.
    let (label, range, against) = match &scope {
        Scope::Period(label, _) => (Some(label.clone()), None, format!("scope period {label}")),
        Scope::Entry(fact) => match entry_period(fact)? {
            Some(label) => {
                if period_span(&label).is_none() {
                    return Err(format!(
                        "entry {fact}'s period `{label}` is not YYYYQn, FYyyyy or YYYY-MM"
                    ));
                }
                let against = format!("entry {fact} is {label}");
                (Some(label), None, against)
            }
            None => {
                if let Some(n) = names.iter().find(|n| matches!(n, Named::Period(..))) {
                    return Err(format!("names {n}, and entry {fact} has no period"));
                }
                (None, None, String::new())
            }
        },
        Scope::Scheme(_, Some((text, span))) => (None, Some(*span), format!("outside {text}")),
        Scope::Scheme(_, None) | Scope::Account(_) => (None, None, String::new()),
    };
    for n in &names {
        let ok = match n {
            Named::Period(l, s) => match (&label, range) {
                (Some(want), _) => l == want,
                (None, Some(range)) => range.contains(*s),
                (None, None) => true,
            },
            Named::Days(_, s) => range.is_none_or(|range| range.contains(*s)),
            Named::Account(a) => match &scope {
                Scope::Account(want) => a == want,
                _ => true,
            },
        };
        if !ok {
            return Err(match (n, &scope) {
                (Named::Account(a), Scope::Account(want)) => {
                    format!("names account {a}, scope account {want}")
                }
                _ => format!("names {n}, {against}"),
            });
        }
    }
    Ok(matches!(scope, Scope::Scheme(_, None)).then_some("range=none"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: &str = include_str!("../../data/binding_fixtures.toml");

    fn no_entry(_: &str) -> Result<Option<String>, String> {
        Ok(None)
    }

    #[test]
    fn scope_matches_the_shared_fixtures() {
        let doc = fa_registry::toml::parse(BINDING).expect("binding_fixtures.toml");
        let rows = doc.arrays.get("scope").expect("[[scope]] rows");
        assert!(rows.len() >= 20, "{} rows", rows.len());
        for row in rows {
            let s = |k: &str| {
                row.get(k)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            let id = s("id");
            let entry = s("entry_period");
            let lookup = move |_: &str| Ok((!entry.is_empty()).then(|| entry.clone()));
            let accounts: BTreeSet<String> = row
                .get("case_accounts")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let got = check(
                &s("quote"),
                &s("about_scope"),
                &s("granularity"),
                &lookup,
                &accounts,
            );
            let want = row
                .get("scope_ok")
                .and_then(|v| v.as_bool())
                .expect("scope_ok");
            assert_eq!(got.is_ok(), want, "row {id}: {got:?}");
            let text = match &got {
                Ok(note) => note.unwrap_or_default().to_string(),
                Err(e) => e.clone(),
            };
            assert_eq!(text, s("reason"), "row {id}");
        }
    }

    fn range(about: &str) -> Option<String> {
        let parsed = parse_scope(about);
        assert!(
            matches!(parsed, Ok(Scope::Scheme(..))),
            "{about}: {parsed:?}"
        );
        match parsed {
            Ok(Scope::Scheme(_, range)) => {
                range.map(|(t, s)| format!("{t}={}..{}", s.first, s.last))
            }
            _ => None,
        }
    }

    #[test]
    fn scheme_range_forms_parse() {
        assert_eq!(
            range("scheme:capitalization-2001Q1-2002Q1").as_deref(),
            Some("2001Q1-2002Q1=2001-01-01..2002-03-31")
        );
        assert_eq!(
            range("scheme:reserve-release-2000Q2-2000Q3").as_deref(),
            Some("2000Q2-2000Q3=2000-04-01..2000-09-30")
        );
        assert_eq!(
            range("scheme:linkedin-ppa-2016-12-08").as_deref(),
            Some("2016-12-08=2016-12-08..2016-12-08")
        );
        assert_eq!(
            range("scheme:notes-for-stock-2001-03").as_deref(),
            Some("2001-03=2001-03-01..2001-03-31")
        );
        assert_eq!(
            range("scheme:x-2001-03-2001-05").as_deref(),
            Some("2001-03-2001-05=2001-03-01..2001-05-31")
        );
        assert_eq!(
            range("scheme:reserve-release-2000Q2").as_deref(),
            Some("2000Q2=2000-04-01..2000-06-30")
        );
        assert_eq!(range("scheme:spe-ljm1"), None);
        assert_eq!(range("scheme:notes-for-stock"), None);
        let quote = "Reserves were released between July 17–19, 2000.";
        let accounts = BTreeSet::new();
        assert_eq!(
            check(
                quote,
                "scheme:reserve-release-2000Q2",
                "period_total",
                &no_entry,
                &accounts
            ),
            Err("names 2000-07-17..2000-07-19, outside 2000Q2".into())
        );
        assert_eq!(
            check(
                quote,
                "scheme:reserve-release-2000Q2-2000Q3",
                "period_total",
                &no_entry,
                &accounts
            ),
            Ok(None)
        );
    }

    #[test]
    fn inverted_scheme_range_fails_k_scope() {
        assert_eq!(
            parse_scope("scheme:x-2001Q2-2001Q1"),
            Err("scheme `x-2001Q2-2001Q1`: its range runs backwards".into())
        );
    }

    #[test]
    fn scheme_range_tail_that_does_not_parse_fails_k_scope() {
        for slug in [
            "scheme:x-2001Q5",
            "scheme:x-2001-13",
            "scheme:x-2001-02-30",
            "scheme:x-2001",
        ] {
            assert!(
                parse_scope(slug).is_err_and(|e| e.contains("parses as no")),
                "{slug}"
            );
        }
    }

    #[test]
    fn the_quote_scanner_names_periods_dates_ranges_months_and_accounts() {
        let accounts: BTreeSet<String> = ["1FN025".to_string()].into();
        let names: Vec<String> = named(
            "In the first quarter of 2001 and 2Q01, on July 17, 2001, between July 17–19, 2000, in September 2001, fiscal year 2002, account No. 1ZR176 and 1FN025.",
            &accounts,
        )
        .iter()
        .map(ToString::to_string)
        .collect();
        assert_eq!(
            names,
            [
                "period 2001Q1",
                "period 2001Q2",
                "2001-07-17",
                "2000-07-17..2000-07-19",
                "2001-09",
                "period FY2002",
                "account 1ZR176",
                "account 1FN025",
            ]
        );
    }

    #[test]
    fn an_unstructured_scope_is_refused() {
        assert!(
            check_scope("the 2Q01 line-cost transfer to CIP", "journal_entry")
                .is_err_and(|e| e.contains("is not entry:<fact>"))
        );
    }
}
