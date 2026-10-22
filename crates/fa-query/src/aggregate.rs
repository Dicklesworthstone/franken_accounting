//! Amount aggregates the profile computes itself. The native read sums only
//! integers and floats, and an amount mirror is an exact decimal, so a final
//! `RETURN` that aggregates an amount is compiled into a native `RETURN` of
//! its group keys and raw arguments. The caller groups those rows and
//! aggregates them exactly (plan §15.5: a profile procedure runs "over the
//! certified native result"); nothing is rounded and no null is skipped.
//!
//! This build compiles one shape: the statement's only `RETURN`, whose items
//! are group keys (any expression without an aggregate) and `COUNT(*)`,
//! `COUNT`, `SUM`, `MIN`, `MAX` or `AVG` of one binding or property,
//! optionally followed by `ORDER BY` output columns, `SKIP` and `LIMIT`.
//! Anything else beside an amount aggregate is refused.

use crate::lex::{Kind, Lexed};
use crate::{Law, Refusal, clause_word, law, squeezed};

/// How the caller turns the native rows into the statement's result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Aggregation {
    /// The output columns, in `RETURN` order.
    pub columns: Vec<Column>,
    /// `ORDER BY`: output column index and descending. Empty: by the group
    /// keys, ascending.
    pub order: Vec<(usize, bool)>,
    pub skip: u64,
    pub limit: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub value: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Function {
    Count,
    Sum,
    Min,
    Max,
    Avg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    /// A group key: this native column.
    Key(usize),
    /// An aggregate of this native column (`None`: `COUNT(*)`). `amount`:
    /// the argument is an amount mirror, so a null is refused, never skipped.
    Aggregate {
        function: Function,
        native: Option<usize>,
        amount: bool,
    },
}

fn refused(lexed: &Lexed<'_>, i: usize, message: &str, fix: &str) -> Refusal {
    let at = lexed.tokens.get(i).map_or(lexed.text.len(), |t| t.start);
    Refusal::new(Law::Profile, at, message, fix)
}

const FIX: &str = "aggregate amounts in the statement's one final RETURN: RETURN u.code AS unit, SUM(l.amount) AS total [ORDER BY unit] [LIMIT n]";

fn function(lexed: &Lexed<'_>, i: usize) -> Option<Function> {
    [
        ("COUNT", Function::Count),
        ("SUM", Function::Sum),
        ("MIN", Function::Min),
        ("MAX", Function::Max),
        ("AVG", Function::Avg),
    ]
    .into_iter()
    .find(|(name, _)| lexed.word(i, name))
    .map(|(_, f)| f)
}

fn any_aggregate(lexed: &Lexed<'_>, from: usize, to: usize) -> bool {
    (from..to).any(|k| {
        [
            "COUNT", "SUM", "SUM_INT", "AVG", "AVG_INT", "MIN", "MAX", "COLLECT",
        ]
        .iter()
        .any(|w| lexed.word(k, w))
            && lexed.punct(k + 1, '(')
    })
}

/// Plan the aggregation of a statement whose amounts are aggregated: the
/// byte offset its native text keeps up to (the final `RETURN`), the
/// native `RETURN` that replaces the rest, and the plan.
pub(crate) fn plan(
    lexed: &Lexed<'_>,
    spans: &[(usize, usize)],
) -> Result<(usize, String, Aggregation), Refusal> {
    let returns: Vec<usize> = (0..lexed.tokens.len())
        .filter(|&i| lexed.root(i) && lexed.word(i, "RETURN"))
        .collect();
    let [r] = returns.as_slice() else {
        return Err(refused(
            lexed,
            returns.get(1).copied().unwrap_or(0),
            "an amount aggregate is computed in the statement's one RETURN; a UNION is not compiled beside it",
            FIX,
        ));
    };
    let r = *r;
    for k in 0..lexed.tokens.len() {
        let amount = lexed.kind(k) == Some(Kind::Word)
            && lexed.punct(k + 1, '.')
            && law::AMOUNTS.contains(&lexed.str(k + 2));
        if amount && k < r && law::aggregated(lexed, k) {
            return Err(refused(
                lexed,
                k,
                "an amount aggregate before the final RETURN (in a WITH) is not compiled in this build",
                FIX,
            ));
        }
    }
    let clauses: Vec<usize> = (r + 1..lexed.tokens.len())
        .filter(|&i| clause_word(lexed, i))
        .collect();
    let end = clauses.first().copied().unwrap_or(lexed.tokens.len());
    if lexed.word(r + 1, "DISTINCT") {
        return Err(refused(
            lexed,
            r + 1,
            "RETURN DISTINCT is not compiled beside an amount aggregate",
            FIX,
        ));
    }
    let text = |from: usize, to: usize| -> String {
        if from >= to {
            return String::new();
        }
        squeezed(
            lexed.text,
            lexed.tokens[from].start,
            lexed.tokens[to - 1].end,
            spans,
        )
        .trim()
        .to_string()
    };
    let mut items = Vec::new();
    let mut from = r + 1;
    for k in r + 1..end {
        if lexed.root(k) && lexed.punct(k, ',') {
            items.push(from..k);
            from = k + 1;
        }
    }
    items.push(from..end);
    let mut native = Vec::new();
    let mut columns = Vec::new();
    for item in items {
        if item.is_empty() {
            return Err(refused(lexed, item.start, "an empty RETURN item", FIX));
        }
        let (expr, alias) = if item.len() >= 3
            && lexed.word(item.end - 2, "AS")
            && lexed.kind(item.end - 1) == Some(Kind::Word)
        {
            (
                item.start..item.end - 2,
                Some(lexed.str(item.end - 1).to_string()),
            )
        } else {
            (item.start..item.end, None)
        };
        let name = alias.unwrap_or_else(|| text(expr.start, expr.end));
        let open = expr.start + 1;
        let closes = expr.len() >= 3
            && lexed.punct(open, '(')
            && lexed.punct(expr.end - 1, ')')
            && (open + 1..expr.end - 1).all(|k| lexed.tokens[k].depth > lexed.tokens[open].depth);
        let value = match function(lexed, expr.start).filter(|_| closes) {
            Some(f) => {
                let args = open + 1..expr.end - 1;
                let arg = text(args.start, args.end);
                let shape = args.len() == 1 && lexed.kind(args.start) == Some(Kind::Word)
                    || args.len() == 3
                        && lexed.kind(args.start) == Some(Kind::Word)
                        && lexed.punct(args.start + 1, '.')
                        && lexed.kind(args.start + 2) == Some(Kind::Word);
                if f == Function::Count && args.len() == 1 && lexed.punct(args.start, '*') {
                    Value::Aggregate {
                        function: f,
                        native: None,
                        amount: false,
                    }
                } else if shape {
                    native.push(arg);
                    Value::Aggregate {
                        function: f,
                        native: Some(native.len() - 1),
                        amount: args.len() == 3
                            && law::AMOUNTS.contains(&lexed.str(args.start + 2)),
                    }
                } else {
                    return Err(refused(
                        lexed,
                        expr.start,
                        &format!(
                            "`{}`: beside an amount aggregate, an aggregate takes one binding or property",
                            text(expr.start, expr.end)
                        ),
                        FIX,
                    ));
                }
            }
            None if any_aggregate(lexed, expr.start, expr.end) => {
                return Err(refused(
                    lexed,
                    expr.start,
                    &format!(
                        "`{}`: an aggregate inside an expression is not compiled beside an amount aggregate",
                        text(expr.start, expr.end)
                    ),
                    FIX,
                ));
            }
            None => {
                native.push(text(expr.start, expr.end));
                Value::Key(native.len() - 1)
            }
        };
        if columns.iter().any(|c: &Column| c.name == name) {
            return Err(refused(
                lexed,
                item.start,
                &format!("two RETURN items are named `{name}`"),
                "give each item its own AS name",
            ));
        }
        columns.push(Column { name, value });
    }
    let mut order = Vec::new();
    let mut skip = 0;
    let mut limit = None;
    for (n, &c) in clauses.iter().enumerate() {
        let stop = clauses.get(n + 1).copied().unwrap_or(lexed.tokens.len());
        let number = || -> Result<u64, Refusal> {
            if stop == c + 2 && lexed.kind(c + 1) == Some(Kind::Digits) {
                lexed
                    .str(c + 1)
                    .parse()
                    .map_err(|_| refused(lexed, c + 1, "out of range", FIX))
            } else {
                Err(refused(lexed, c, "SKIP and LIMIT take one integer", FIX))
            }
        };
        if lexed.word(c, "ORDER") && order.is_empty() && lexed.word(c + 1, "BY") {
            let mut from = c + 2;
            let mut keys = Vec::new();
            for k in c + 2..stop {
                if lexed.root(k) && lexed.punct(k, ',') {
                    keys.push(from..k);
                    from = k + 1;
                }
            }
            keys.push(from..stop);
            for key in keys {
                let (named, descending) = match key.end.checked_sub(1) {
                    Some(last)
                        if key.len() >= 2
                            && (lexed.word(last, "DESC") || lexed.word(last, "DESCENDING")) =>
                    {
                        (key.start..last, true)
                    }
                    Some(last)
                        if key.len() >= 2
                            && (lexed.word(last, "ASC") || lexed.word(last, "ASCENDING")) =>
                    {
                        (key.start..last, false)
                    }
                    _ => (key.clone(), false),
                };
                let wanted = text(named.start, named.end);
                let index = columns
                    .iter()
                    .position(|c| c.name == wanted)
                    .ok_or_else(|| {
                        refused(
                            lexed,
                            key.start,
                            &format!("ORDER BY `{wanted}` names no RETURN column"),
                            "order by a RETURN item's name: ORDER BY unit DESC",
                        )
                    })?;
                if matches!(
                    columns[index].value,
                    Value::Aggregate {
                        function: Function::Avg,
                        ..
                    }
                ) {
                    return Err(refused(
                        lexed,
                        key.start,
                        &format!(
                            "ORDER BY `{wanted}`: ordering by an exact average is not compiled in this build"
                        ),
                        "order by a key, a SUM, a COUNT, a MIN or a MAX column instead",
                    ));
                }
                order.push((index, descending));
            }
        } else if lexed.word(c, "SKIP") && skip == 0 {
            skip = number()?;
        } else if lexed.word(c, "LIMIT") && limit.is_none() {
            limit = Some(number()?);
        } else {
            return Err(refused(
                lexed,
                c,
                &format!(
                    "`{}` after an amount aggregate's RETURN is not compiled in this build",
                    lexed.str(c)
                ),
                FIX,
            ));
        }
    }
    let returned = native
        .iter()
        .enumerate()
        .map(|(i, expr)| format!("{expr} AS __fa_c{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    Ok((
        lexed.tokens[r].start,
        format!("RETURN {returned}"),
        Aggregation {
            columns,
            order,
            skip,
            limit,
        },
    ))
}
