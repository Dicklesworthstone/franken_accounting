//! K-SCOPE (§2.1, §3.6): a quote's own period, date and account words do
//! not conflict with the fact's `about_scope`, under `case-fetch-scope-v2`
//! ([`crate::cases::scope`], the rule A9's `verify` runs word for word). The
//! scope's own refusals (its form, a scheme range that does not parse or runs
//! backwards, a scheme scope on a `journal_entry` fact, an `entry:` naming
//! no fact) need no quote; the word check runs on a present quote, and a
//! quote-less fact rests on its receipt's `scope_ok`. A fact under a
//! rangeless scheme is listed `range=none`: its dates were not range-checked.

use std::collections::BTreeSet;

use super::super::Case;
use super::super::fact::LiteralRule;
use super::super::scope::{self as words, Scope};
use super::{CheckReport, Context, FACTS};

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    let case = cx.case;
    let sourced: Vec<_> = case
        .facts
        .iter()
        .filter_map(|f| Some((f, f.sourced()?)))
        .collect();
    let accounts = case_accounts(case);
    let entry_period = |fact: &str| entry_period(case, fact);
    let mut r = CheckReport::new("K-SCOPE", sourced.len());
    for (f, s) in sourced {
        let mut problems = Vec::new();
        let mut note = None;
        match words::check_scope(&s.about_scope, s.granularity.as_str()) {
            Err(e) => problems.push(e),
            Ok(scope) => {
                if let Scope::Entry(fact) = &scope
                    && let Err(e) = entry_period(fact)
                {
                    problems.push(e);
                }
                if matches!(scope, Scope::Scheme(_, None)) {
                    note = Some("range=none");
                }
                match &s.quote {
                    Some(quote) => {
                        if let Err(e) = words::check(
                            quote,
                            &s.about_scope,
                            s.granularity.as_str(),
                            &entry_period,
                            &accounts,
                        ) && !problems.contains(&e)
                        {
                            problems.push(e);
                        }
                    }
                    None => match cx.receipt(&f.id) {
                        None => problems.push(
                            "no quote and no receipt carries the scope check (run `case_fetch.py verify`)"
                                .into(),
                        ),
                        Some(rc) if !rc.scope_ok => problems
                            .push("the receipt records the quote's words conflicting with about_scope (scope_ok = false)".into()),
                        Some(_) => {}
                    },
                }
            }
        }
        r.examined(match note {
            Some(n) => format!("{} {n}", f.id),
            None => f.id.clone(),
        });
        for p in problems {
            r.fail(FACTS, f.line, &f.id, p);
        }
    }
    r.finish()
}

/// The ids the case's `account:` scopes name.
#[must_use]
pub fn case_accounts(case: &Case) -> BTreeSet<String> {
    case.facts
        .iter()
        .filter_map(|f| f.sourced()?.about_scope.strip_prefix("account:"))
        .map(str::to_string)
        .collect()
}

/// An `entry:` scope's period: the fact's first `period_literal` value, else
/// its own `period:` scope's label.
///
/// # Errors
///
/// When the case has no such fact.
pub fn entry_period(case: &Case, fact: &str) -> Result<Option<String>, String> {
    let f = case
        .facts
        .iter()
        .find(|f| f.id == fact)
        .ok_or_else(|| format!("entry:{fact} names no fact of this case"))?;
    let mut values: Vec<_> = case.values.iter().filter(|v| v.fact == fact).collect();
    values.sort_by_key(|v| v.ordinal);
    if let Some(v) = values.iter().find(|v| v.rule == LiteralRule::PeriodLiteral) {
        return Ok(Some(v.value.clone()));
    }
    Ok(f.sourced()
        .and_then(|s| s.about_scope.strip_prefix("period:"))
        .map(str::to_string))
}
