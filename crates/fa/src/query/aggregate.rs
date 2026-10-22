//! The exact aggregation of an amount aggregate over its native rows (see
//! `fa_query::Aggregation`): rows are grouped by the key columns and every
//! aggregate is computed in checked i128 arithmetic over the canonical
//! decimal coefficients. A null amount mirror is refused, never skipped, and
//! an overflow is refused, never wrapped (FA-INV-06).

use std::cmp::Ordering;
use std::collections::BTreeMap;

use fa_journal::refusal::{Refusal, exit};
use fa_query::{Aggregation, Function, Value};
use fgdb::QueryValue;
use fgdb_gql::GraphAggregateValue;
use fgdb_gql::algebra::GraphValue;
use fgdb_types::{CanonicalDecimal, CanonicalScalar};

use super::{AMOUNT_CITE, CITE, MAX_QUERY_ROWS, QueryCell, code, decimal};

/// An exact number: an integer, or a decimal as its coefficient at the
/// canonical scale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Number {
    Int(i128),
    Decimal(i128),
}

impl Number {
    fn of(value: &QueryValue) -> Result<Option<Self>, ()> {
        match value {
            GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Null)) => Ok(None),
            GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Int(n))) => {
                Ok(Some(Self::Int(i128::from(*n))))
            }
            GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Decimal(d))) => {
                Ok(Some(Self::Decimal(d.coefficient())))
            }
            GraphAggregateValue::Integer(n) => Ok(Some(Self::Int(*n))),
            GraphAggregateValue::Count(n) => Ok(Some(Self::Int(i128::from(*n)))),
            _ => Err(()),
        }
    }

    fn cell(self) -> QueryCell {
        match self {
            Self::Int(n) => QueryCell::Int(n),
            Self::Decimal(coefficient) => QueryCell::Decimal(decimal_text(coefficient)),
        }
    }
}

fn decimal_text(coefficient: i128) -> String {
    let unit = 10_u128.pow(CanonicalDecimal::scale());
    let magnitude = coefficient.unsigned_abs();
    let sign = if coefficient < 0 { "-" } else { "" };
    decimal(&format!(
        "{sign}{}.{:0width$}",
        magnitude / unit,
        magnitude % unit,
        width = CanonicalDecimal::scale() as usize
    ))
}

fn refusal(name: &str, message: String, amount_law: bool) -> Refusal {
    if amount_law {
        Refusal::new(
            code::QUERY_AMOUNT_LAW,
            exit::REFUSAL,
            message,
            AMOUNT_CITE,
            "read the exact fold: CALL fa.trial_balance FOR PERIOD '<code>' (or fa tb); leaving such legs out is an explicit WHERE l.amount IS NOT NULL",
        )
    } else {
        Refusal::new(
            code::QUERY_PROFILE,
            exit::REFUSAL,
            message,
            CITE,
            "aggregate one numeric binding or property per column: SUM(l.amount), COUNT(e)",
        )
    }
    .at("column", name.to_string())
}

#[derive(Clone, Debug)]
enum Acc {
    Count(u64),
    Sum(Option<Number>),
    Min(Option<Number>),
    Max(Option<Number>),
    Avg(Option<Number>, u64),
}

fn add(a: Number, b: Number, name: &str) -> Result<Number, Refusal> {
    match (a, b) {
        (Number::Int(x), Number::Int(y)) => x.checked_add(y).map(Number::Int),
        (Number::Decimal(x), Number::Decimal(y)) => x.checked_add(y).map(Number::Decimal),
        _ => {
            return Err(refusal(
                name,
                format!("`{name}` mixes integers and decimals"),
                false,
            ));
        }
    }
    .ok_or_else(|| {
        refusal(
            name,
            format!("`{name}` exceeds the exact 128-bit range"),
            true,
        )
    })
}

fn compare(a: Number, b: Number, name: &str) -> Result<Ordering, Refusal> {
    match (a, b) {
        (Number::Int(x), Number::Int(y)) | (Number::Decimal(x), Number::Decimal(y)) => {
            Ok(x.cmp(&y))
        }
        _ => Err(refusal(
            name,
            format!("`{name}` mixes integers and decimals"),
            false,
        )),
    }
}

fn fold(
    acc: &mut Acc,
    value: Option<&QueryValue>,
    amount: bool,
    name: &str,
) -> Result<(), Refusal> {
    if let Acc::Count(n) = acc {
        let counted = value.is_none_or(|v| {
            !matches!(
                v,
                GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Null))
            )
        });
        if counted {
            *n = n
                .checked_add(1)
                .ok_or_else(|| refusal(name, format!("`{name}` overflows"), false))?;
        }
        return Ok(());
    }
    let Some(value) = value else {
        return Err(refusal(name, format!("`{name}` has no argument"), false));
    };
    let x = match Number::of(value) {
        Ok(Some(x)) => x,
        Ok(None) if amount => {
            return Err(refusal(
                name,
                format!(
                    "`{name}` meets a leg whose amount is wider than its decimal mirror (null); an aggregate never skips it"
                ),
                true,
            ));
        }
        Ok(None) => return Ok(()),
        Err(()) => {
            return Err(refusal(
                name,
                format!("`{name}` aggregates a value that is not a number"),
                false,
            ));
        }
    };
    match acc {
        Acc::Count(_) => {}
        Acc::Sum(total) => *total = Some(total.map_or(Ok(x), |t| add(t, x, name))?),
        Acc::Min(least) => {
            if least.map_or(Ok(true), |l| compare(x, l, name).map(Ordering::is_lt))? {
                *least = Some(x);
            }
        }
        Acc::Max(most) => {
            if most.map_or(Ok(true), |m| compare(x, m, name).map(Ordering::is_gt))? {
                *most = Some(x);
            }
        }
        Acc::Avg(total, n) => {
            *total = Some(total.map_or(Ok(x), |t| add(t, x, name))?);
            *n = n
                .checked_add(1)
                .ok_or_else(|| refusal(name, format!("`{name}` overflows"), false))?;
        }
    }
    Ok(())
}

fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// An exact average: a number when it divides evenly, else the reduced
/// fraction of base units.
fn average(total: Number, n: u64, name: &str) -> Result<QueryCell, Refusal> {
    let count = i128::from(n);
    match total {
        Number::Int(v) if v % count == 0 => return Ok(QueryCell::Int(v / count)),
        Number::Decimal(c) if c % count == 0 => {
            return Ok(QueryCell::Decimal(decimal_text(c / count)));
        }
        _ => {}
    }
    let (numerator, scale) = match total {
        Number::Int(v) => (v, 1_u128),
        Number::Decimal(c) => (c, 10_u128.pow(CanonicalDecimal::scale())),
    };
    let overflow = || {
        refusal(
            name,
            format!("`{name}` has no exact 128-bit fraction"),
            true,
        )
    };
    let denominator = u128::from(n).checked_mul(scale).ok_or_else(overflow)?;
    let g = gcd(numerator.unsigned_abs(), denominator);
    let g_signed = i128::try_from(g).map_err(|_| overflow())?;
    Ok(QueryCell::Fraction {
        numerator: numerator / g_signed,
        denominator: u64::try_from(denominator / g).map_err(|_| overflow())?,
    })
}

/// One output value while the rows are ordered.
#[derive(Clone, Debug)]
enum Out {
    Cell(QueryCell),
    Number(Option<Number>),
    Count(u64),
}

/// Group, aggregate, order and page the native rows under `plan`.
pub(super) fn aggregate(
    plan: &Aggregation,
    rows: &[Vec<QueryValue>],
) -> Result<Vec<Vec<QueryCell>>, Refusal> {
    let keys: Vec<usize> = plan
        .columns
        .iter()
        .filter_map(|c| match c.value {
            Value::Key(native) => Some(native),
            Value::Aggregate { .. } => None,
        })
        .collect();
    let fresh = || -> Vec<Acc> {
        plan.columns
            .iter()
            .filter_map(|c| match c.value {
                Value::Key(_) => None,
                Value::Aggregate { function, .. } => Some(match function {
                    Function::Count => Acc::Count(0),
                    Function::Sum => Acc::Sum(None),
                    Function::Min => Acc::Min(None),
                    Function::Max => Acc::Max(None),
                    Function::Avg => Acc::Avg(None, 0),
                }),
            })
            .collect()
    };
    let mut groups: BTreeMap<Vec<QueryCell>, Vec<Acc>> = BTreeMap::new();
    if keys.is_empty() {
        groups.insert(Vec::new(), fresh());
    }
    for row in rows {
        let key: Vec<QueryCell> = keys.iter().map(|&n| QueryCell::of(&row[n])).collect();
        let accs = groups.entry(key).or_insert_with(fresh);
        let mut a = 0;
        for column in &plan.columns {
            let Value::Aggregate { native, amount, .. } = column.value else {
                continue;
            };
            fold(&mut accs[a], native.map(|n| &row[n]), amount, &column.name)?;
            a += 1;
        }
    }
    if groups.len() as u64 > MAX_QUERY_ROWS {
        return Err(Refusal::new(
            code::QUERY_PROFILE,
            exit::REFUSAL,
            format!(
                "the aggregate has {} groups; a result is at most {MAX_QUERY_ROWS} rows",
                groups.len()
            ),
            CITE,
            "group more coarsely or narrow the pattern",
        ));
    }
    let mut out: Vec<Vec<Out>> = Vec::with_capacity(groups.len());
    for (key, accs) in groups {
        let mut keyed = key.into_iter();
        let mut accs = accs.into_iter();
        let mut row = Vec::with_capacity(plan.columns.len());
        for column in &plan.columns {
            row.push(match column.value {
                Value::Key(_) => Out::Cell(keyed.next().unwrap_or(QueryCell::Null)),
                Value::Aggregate { amount, .. } => match accs.next() {
                    Some(Acc::Count(n)) => Out::Count(n),
                    Some(Acc::Sum(total)) => Out::Cell(total.map_or_else(
                        || {
                            if amount {
                                QueryCell::Decimal("0".to_string())
                            } else {
                                QueryCell::Int(0)
                            }
                        },
                        Number::cell,
                    )),
                    Some(Acc::Min(n) | Acc::Max(n)) => Out::Number(n),
                    Some(Acc::Avg(total, n)) => Out::Cell(match total {
                        Some(total) => average(total, n, &column.name)?,
                        None => QueryCell::Null,
                    }),
                    None => Out::Cell(QueryCell::Null),
                },
            });
        }
        out.push(row);
    }
    if !plan.order.is_empty() {
        let mut failure = None;
        out.sort_by(|a, b| {
            for &(index, descending) in &plan.order {
                let ordering = match (&a[index], &b[index]) {
                    (Out::Count(x), Out::Count(y)) => x.cmp(y),
                    (Out::Number(x), Out::Number(y)) => match (x, y) {
                        (None, None) => Ordering::Equal,
                        (None, Some(_)) => Ordering::Less,
                        (Some(_), None) => Ordering::Greater,
                        (Some(x), Some(y)) => compare(*x, *y, &plan.columns[index].name)
                            .unwrap_or_else(|r| {
                                failure.get_or_insert(r);
                                Ordering::Equal
                            }),
                    },
                    (Out::Cell(QueryCell::Decimal(x)), Out::Cell(QueryCell::Decimal(y))) => {
                        exact_order(x, y)
                    }
                    (Out::Cell(x), Out::Cell(y)) => x.cmp(y),
                    _ => Ordering::Equal,
                };
                let ordering = if descending {
                    ordering.reverse()
                } else {
                    ordering
                };
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            Ordering::Equal
        });
        if let Some(refusal) = failure {
            return Err(refusal);
        }
    }
    let skip = usize::try_from(plan.skip).unwrap_or(usize::MAX);
    let limit = plan
        .limit
        .map_or(usize::MAX, |n| usize::try_from(n).unwrap_or(usize::MAX));
    Ok(out
        .into_iter()
        .skip(skip)
        .take(limit)
        .map(|row| {
            row.into_iter()
                .map(|value| match value {
                    Out::Cell(cell) => cell,
                    Out::Count(n) => QueryCell::Int(i128::from(n)),
                    Out::Number(n) => n.map_or(QueryCell::Null, Number::cell),
                })
                .collect()
        })
        .collect())
}

/// Two decimal texts (an exact sum) in numeric order.
fn exact_order(x: &str, y: &str) -> Ordering {
    let parse = |text: &str| -> Option<i128> {
        let negative = text.starts_with('-');
        let digits = text.trim_start_matches('-');
        let (whole, fraction) = digits.split_once('.').unwrap_or((digits, ""));
        let scale = CanonicalDecimal::scale() as usize;
        let padded = format!("{fraction:0<scale$}");
        let magnitude: i128 = format!("{whole}{padded}").parse().ok()?;
        Some(if negative { -magnitude } else { magnitude })
    };
    match (parse(x), parse(y)) {
        (Some(a), Some(b)) => a.cmp(&b),
        _ => x.cmp(y),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decimal(units: i128) -> QueryValue {
        GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Decimal(
            CanonicalDecimal::from_scaled_half_even(units, 2).unwrap(),
        )))
    }

    fn text(value: &str) -> QueryValue {
        GraphAggregateValue::Value(GraphValue::Scalar(
            CanonicalScalar::ucs_basic_text(value).unwrap(),
        ))
    }

    fn plan(columns: Vec<(&str, Value)>, order: Vec<(usize, bool)>) -> Aggregation {
        Aggregation {
            columns: columns
                .into_iter()
                .map(|(name, value)| fa_query::Column {
                    name: name.to_string(),
                    value,
                })
                .collect(),
            order,
            skip: 0,
            limit: None,
        }
    }

    fn sum(native: usize) -> Value {
        Value::Aggregate {
            function: Function::Sum,
            native: Some(native),
            amount: true,
        }
    }

    #[test]
    fn sums_are_exact_per_group_and_ordered_numerically() {
        let rows = vec![
            vec![text("USD"), decimal(1000)],
            vec![text("EUR"), decimal(5)],
            vec![text("USD"), decimal(25)],
            vec![text("EUR"), decimal(250)],
        ];
        let by_unit = plan(vec![("unit", Value::Key(0)), ("total", sum(1))], vec![]);
        assert_eq!(
            aggregate(&by_unit, &rows).unwrap(),
            vec![
                vec![
                    QueryCell::Text("EUR".into()),
                    QueryCell::Decimal("2.55".into())
                ],
                vec![
                    QueryCell::Text("USD".into()),
                    QueryCell::Decimal("10.25".into())
                ],
            ]
        );
        // 10.25 > 2.55 numerically, though "10.25" < "2.55" as text.
        let largest = plan(
            vec![("unit", Value::Key(0)), ("total", sum(1))],
            vec![(1, true)],
        );
        assert_eq!(
            aggregate(&largest, &rows).unwrap()[0][0],
            QueryCell::Text("USD".into())
        );
        let mut paged = largest.clone();
        paged.skip = 1;
        paged.limit = Some(1);
        assert_eq!(
            aggregate(&paged, &rows).unwrap(),
            vec![vec![
                QueryCell::Text("EUR".into()),
                QueryCell::Decimal("2.55".into())
            ]]
        );
    }

    #[test]
    fn a_null_amount_and_an_overflow_are_refused_and_averages_are_exact() {
        let null = GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Null));
        let total = plan(vec![("total", sum(0))], vec![]);
        let refused = aggregate(&total, &[vec![decimal(1)], vec![null.clone()]]).unwrap_err();
        assert_eq!(refused.code, code::QUERY_AMOUNT_LAW, "{refused:?}");
        // No rows and no keys: one row, the sum of nothing.
        assert_eq!(
            aggregate(&total, &[]).unwrap(),
            vec![vec![QueryCell::Decimal("0".into())]]
        );
        let big = GraphAggregateValue::Integer(i128::MAX);
        let ints = plan(
            vec![(
                "n",
                Value::Aggregate {
                    function: Function::Sum,
                    native: Some(0),
                    amount: false,
                },
            )],
            vec![],
        );
        let refused = aggregate(&ints, &[vec![big.clone()], vec![big]]).unwrap_err();
        assert_eq!(refused.code, code::QUERY_AMOUNT_LAW, "{refused:?}");
        let mean = plan(
            vec![(
                "mean",
                Value::Aggregate {
                    function: Function::Avg,
                    native: Some(0),
                    amount: true,
                },
            )],
            vec![],
        );
        // (1.00 + 2.00 + 2.00) / 3 = 5/3, exactly.
        let rows = vec![vec![decimal(100)], vec![decimal(200)], vec![decimal(200)]];
        assert_eq!(
            aggregate(&mean, &rows).unwrap(),
            vec![vec![QueryCell::Fraction {
                numerator: 5,
                denominator: 3
            }]]
        );
        let rows = vec![vec![decimal(100)], vec![decimal(200)]];
        assert_eq!(
            aggregate(&mean, &rows).unwrap(),
            vec![vec![QueryCell::Decimal("1.5".into())]]
        );
        // COUNT(*) beside them counts rows; COUNT(x) skips nulls.
        let counts = plan(
            vec![
                (
                    "rows",
                    Value::Aggregate {
                        function: Function::Count,
                        native: None,
                        amount: false,
                    },
                ),
                (
                    "mirrored",
                    Value::Aggregate {
                        function: Function::Count,
                        native: Some(0),
                        amount: true,
                    },
                ),
            ],
            vec![],
        );
        assert_eq!(
            aggregate(&counts, &[vec![decimal(1)], vec![null]]).unwrap(),
            vec![vec![QueryCell::Int(2), QueryCell::Int(1)]]
        );
    }
}
