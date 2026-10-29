//! K-DERIVE (§2.4, §3.6): every derived fact recomputes exactly under its
//! rule with A2's engine ([`Rules::evaluate`](super::super::derive::Rules::evaluate)),
//! and every book leg whose `amount_rule` names a fact (`value:<fact>#<n>`,
//! `derived:<fact>`) or its Δ target (`derived:negate`), and every L3
//! event whose `resource_amount_rule` names a fact, carries that amount.
//!
//! A derived fact's inputs are its `from` facts in order, less those a
//! `<name>=from:<fact>[#<n>]` parameter reads: a rows fact's input is its
//! committed rows file, any other fact's its first `[[value]]`. Its result
//! is compared with its own first `[[value]]`. A pending fact (owner
//! decision 2b) or a leg naming one is counted, never recomputed.

use super::super::amount::parse_amount;
use super::super::book::{EventDef, LegDef};
use super::super::fact::{Derived, Provenance, Value};
use super::{CheckReport, Context, FACTS};

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    let case = cx.case;
    let derived: Vec<_> = case
        .facts
        .iter()
        .filter_map(|f| match &f.provenance {
            Provenance::Derived(d) => Some((f, d)),
            _ => None,
        })
        .collect();
    let legs: Vec<(&str, &LegDef)> = case
        .books
        .values()
        .flat_map(|b| b.legs.iter().map(move |l| (b.stem.as_str(), l)))
        .filter(|(_, l)| names_an_amount(&l.amount_rule))
        .collect();
    let events: Vec<(&str, &EventDef)> = case
        .books
        .values()
        .flat_map(|b| b.events.iter().map(move |e| (b.stem.as_str(), e)))
        .filter(|(_, e)| {
            e.resource_amount_rule
                .as_deref()
                .is_some_and(names_an_amount)
        })
        .collect();
    let mut r = CheckReport::new("K-DERIVE", derived.len() + legs.len() + events.len());
    let rules = match &cx.rules {
        Ok(rules) => rules,
        Err(e) => {
            r.fail(
                super::super::derive::FILE,
                None,
                "-",
                format!("the derivation table does not load: {e}"),
            );
            return r.finish();
        }
    };
    for (f, d) in derived {
        if cx.pending.contains(&f.id) {
            r.pending += 1;
            continue;
        }
        r.examined(f.id.clone());
        if let Err(e) = recompute(cx, rules, &f.id, d) {
            r.fail(FACTS, f.line, &f.id, e);
        }
    }
    for (stem, leg) in legs {
        let row = format!("{}#{}", leg.intent, leg.ordinal);
        let file = format!("books/{stem}.toml");
        if names_fact(&leg.amount_rule).is_some_and(|n| cx.pending.contains(n)) {
            r.pending += 1;
            continue;
        }
        r.examined(format!("{stem}:{row}"));
        if let Err(e) = leg_amount(cx, stem, leg) {
            r.fail(&file, leg.line, &row, e);
        }
    }
    for (stem, e) in events {
        let rule = e.resource_amount_rule.as_deref().unwrap_or_default();
        if names_fact(rule).is_some_and(|n| cx.pending.contains(n)) {
            r.pending += 1;
            continue;
        }
        r.examined(format!("{stem}:{}", e.id));
        if let Err(err) = event_amount(cx, e) {
            r.fail(&format!("books/{stem}.toml"), e.line, &e.id, err);
        }
    }
    r.finish()
}

/// The fact a `value:<fact>#<n>` or `derived:<fact>` rule names.
fn names_fact(rule: &str) -> Option<&str> {
    rule.strip_prefix("value:")
        .and_then(|v| v.split_once('#').map(|(f, _)| f))
        .or_else(|| rule.strip_prefix("derived:").filter(|n| *n != "negate"))
}

fn names_an_amount(rule: &str) -> bool {
    rule.starts_with("value:") || rule.starts_with("derived:")
}

fn first_value<'c>(values: &'c [Value], fact: &str) -> Option<&'c Value> {
    values
        .iter()
        .filter(|v| v.fact == fact)
        .min_by_key(|v| v.ordinal)
}

/// Recomputes one derived fact.
fn recompute(
    cx: &Context<'_>,
    rules: &super::super::derive::Rules,
    id: &str,
    d: &Derived,
) -> Result<(), String> {
    let case = cx.case;
    let rule = rules
        .get(&d.rule)
        .ok_or_else(|| format!("rule `{}` is not in the derivation table", d.rule))?;
    let params = rules
        .params_of(d, &case.values)
        .map_err(|e| e.to_string())?;
    let read_by_param: Vec<&str> = d
        .params
        .iter()
        .flatten()
        .filter_map(|p| p.as_str()?.split_once("=from:").map(|(_, f)| f))
        .map(|f| f.split_once('#').map_or(f, |(f, _)| f))
        .collect();
    let mut inputs = Vec::new();
    for from in d
        .from
        .iter()
        .filter(|f| !read_by_param.contains(&f.as_str()))
    {
        let rows = case
            .facts
            .iter()
            .find(|f| f.id == *from)
            .and_then(|f| f.sourced())
            .and_then(|s| s.rows_file.as_ref());
        match rows {
            Some(file) => inputs.push(
                case.rows
                    .get(file)
                    .cloned()
                    .ok_or_else(|| format!("input `{from}`'s rows file `{file}` is not loaded"))?,
            ),
            None => inputs.push(
                first_value(&case.values, from)
                    .map(|v| v.value.clone())
                    .ok_or_else(|| format!("input `{from}` has no [[value]]"))?,
            ),
        }
    }
    let expected = first_value(&case.values, id)
        .ok_or_else(|| format!("derived fact `{id}` has no [[value]] to compare"))?;
    let computed = rules
        .evaluate(&d.rule, &params, &inputs)
        .map_err(|e| e.to_string())?;
    let tokens: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
    super::super::derive::compare(rule, &tokens, &expected.value, &computed)
        .map_err(|e| e.to_string())
}

/// The minor units `literal` reads at `unit`'s scale.
fn minor_units(cx: &Context<'_>, literal: &str, unit: &str) -> Result<i128, String> {
    let scale = *cx
        .scales
        .get(unit)
        .ok_or_else(|| format!("unit `{unit}` is not registered"))?;
    parse_amount(literal, scale).map_err(|e| format!("amount `{literal}`: {e}"))
}

/// The amount a `value:<fact>#<n>` or `derived:<fact>` rule names, in
/// `unit`'s minor units.
fn named_amount(cx: &Context<'_>, rule: &str, unit: &str) -> Result<i128, String> {
    let values = &cx.case.values;
    let (fact, ordinal) = match rule.strip_prefix("value:") {
        Some(v) => {
            let (f, n) = v
                .split_once('#')
                .ok_or_else(|| format!("`{rule}` is value:<fact>#<n>"))?;
            let n = n
                .parse::<i128>()
                .map_err(|_| format!("`{rule}`: the ordinal is an integer"))?;
            (f, n)
        }
        None => {
            let f = rule.strip_prefix("derived:").unwrap_or(rule);
            let first = first_value(values, f)
                .ok_or_else(|| format!("`{rule}`: fact `{f}` has no [[value]]"))?;
            (f, first.ordinal)
        }
    };
    let v = values
        .iter()
        .find(|v| v.fact == fact && v.ordinal == ordinal)
        .ok_or_else(|| format!("`{rule}` names no [[value]]"))?;
    if !v.unit.is_empty() && v.unit != unit {
        return Err(format!("`{rule}` is in {}, the amount in {unit}", v.unit));
    }
    v.value
        .parse()
        .map_err(|_| format!("`{rule}`'s value `{}` is not an integer", v.value))
}

fn compare_amounts(
    literal: &str,
    unit: &str,
    amount: i128,
    want: i128,
    what: &str,
) -> Result<(), String> {
    if amount == want {
        Ok(())
    } else {
        Err(format!(
            "amount {literal} {unit} is {amount} minor units; {what} is {want}"
        ))
    }
}

/// One leg's amount equals the amount its rule names.
fn leg_amount(cx: &Context<'_>, stem: &str, leg: &LegDef) -> Result<(), String> {
    let amount = minor_units(cx, &leg.amount_literal, &leg.unit)?;
    let rule = leg.amount_rule.as_str();
    if rule != "derived:negate" {
        // A leg carries a magnitude and its side the direction, so a figure the source prints
        // negative (a parenthesized decrease) binds a leg by its magnitude.
        let want = named_amount(cx, rule, &leg.unit)?
            .checked_abs()
            .ok_or_else(|| format!("`{rule}` has no magnitude in i128"))?;
        return compare_amounts(
            &leg.amount_literal,
            &leg.unit,
            amount,
            want,
            &format!("`{rule}`"),
        );
    }
    let book = &cx.case.books[stem];
    let target = book
        .intents
        .iter()
        .find(|i| i.id == leg.intent)
        .and_then(|i| i.target.clone())
        .ok_or_else(|| {
            format!(
                "derived:negate on intent `{}`, which has no target",
                leg.intent
            )
        })?;
    let mirror = book
        .legs
        .iter()
        .find(|l| l.intent == target && l.ordinal == leg.ordinal)
        .ok_or_else(|| format!("derived:negate: {target} has no leg {}", leg.ordinal))?;
    let want = minor_units(cx, &mirror.amount_literal, &mirror.unit)
        .map_err(|e| format!("{target}'s leg {}: {e}", leg.ordinal))?;
    compare_amounts(
        &leg.amount_literal,
        &leg.unit,
        amount,
        want,
        &format!("{target}'s leg {} (negated)", leg.ordinal),
    )
}

/// An event's resource amount equals the amount its rule names (L3).
fn event_amount(cx: &Context<'_>, e: &EventDef) -> Result<(), String> {
    let (Some(literal), Some(rule), Some(unit)) = (
        e.resource_amount_literal.as_deref(),
        e.resource_amount_rule.as_deref(),
        e.resource_unit.as_deref(),
    ) else {
        return Err("an event's resource names its amount literal, rule and unit together".into());
    };
    if rule == "derived:negate" {
        return Err("derived:negate belongs to a case Δ leg, not an event's resource".into());
    }
    let amount = minor_units(cx, literal, unit)?;
    let want = named_amount(cx, rule, unit)?;
    compare_amounts(literal, unit, amount, want, &format!("`{rule}`"))
}
