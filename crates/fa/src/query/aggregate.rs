//! The exact aggregation of an amount aggregate over its native rows (see
//! `fa_query::Aggregation`): rows are grouped by the key columns and every
//! aggregate is computed in checked i128 arithmetic over the canonical
//! decimal coefficients. Distinct leg counts recover exact mantissas from
//! the decimal or byte representation at the registered unit scale. A
//! missing amount is refused, never skipped, and an overflow is refused,
//! never wrapped (FA-INV-06).

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use fa_journal::refusal::{Refusal, exit};
use fa_money::{UnitId, UnitRegistry};
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
    Distinct(BTreeSet<QueryValue>, u64),
    DistinctAmounts(BTreeSet<i128>, Option<UnitId>, u64),
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
    if let Acc::Distinct(seen, n) = acc {
        let Some(value) = value else {
            return Err(refusal(name, format!("`{name}` has no argument"), false));
        };
        if value.is_null() {
            return if amount {
                Err(refusal(
                    name,
                    format!("`{name}` has no exact amount; distinct counting never skips it"),
                    true,
                ))
            } else {
                Ok(())
            };
        }
        if seen.insert(value.clone()) {
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
        Acc::Count(_) | Acc::Distinct(_, _) | Acc::DistinctAmounts(_, _, _) => {}
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

/// Recover the logical mantissa, independent of which exact storage
/// representation supplied it. Decimal coefficients are at scale 18;
/// `amount_bytes` is an i128 little-endian mantissa at the unit's scale.
/// No float, rounding, or representability-dependent omission is involved.
fn distinct_amount(
    acc: &mut Acc,
    row: &[QueryValue],
    columns: (usize, usize, usize),
    units: &UnitRegistry,
    name: &str,
) -> Result<(), Refusal> {
    let bad = |message: &str| {
        refusal(
            name,
            format!("`{name}` {message}; exact distinct counting cannot omit this amount"),
            true,
        )
    };
    let (amount_column, bytes_column, unit_column) = columns;
    let Some(GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Int(id)))) =
        row.get(unit_column)
    else {
        return Err(bad("has no exact unit identity"));
    };
    let unit_id = u32::try_from(*id)
        .map(UnitId)
        .map_err(|_| bad("has an invalid unit identity"))?;
    let unit = units
        .get(unit_id)
        .ok_or_else(|| bad("names an unknown unit"))?;
    let (Some(amount), Some(bytes)) = (row.get(amount_column), row.get(bytes_column)) else {
        return Err(bad("is missing a certified amount column"));
    };
    let mantissa = match (amount, bytes) {
        (
            GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Decimal(value))),
            GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Null)),
        ) => {
            let exponent = CanonicalDecimal::scale()
                .checked_sub(u32::from(unit.scale))
                .ok_or_else(|| {
                    bad("has a decimal representation incompatible with its unit scale")
                })?;
            let factor = 10_i128
                .checked_pow(exponent)
                .ok_or_else(|| bad("has an unrepresentable unit scale"))?;
            if value.coefficient() % factor != 0 {
                return Err(bad(
                    "has a decimal value outside the registered unit precision",
                ));
            }
            value.coefficient() / factor
        }
        (
            GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Null)),
            GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Bytes(value))),
        ) => {
            let encoded: [u8; 16] = value
                .as_slice()
                .try_into()
                .map_err(|_| bad("has a malformed i128 amount fallback"))?;
            i128::from_le_bytes(encoded)
        }
        (
            GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Null)),
            GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Null)),
        ) => return Err(bad("has neither an amount nor its byte fallback")),
        _ => return Err(bad("has ambiguous or invalid amount representations")),
    };
    let Acc::DistinctAmounts(seen, group_unit, n) = acc else {
        return Err(bad("has an invalid distinct aggregation plan"));
    };
    if group_unit.is_some_and(|previous| previous != unit_id) {
        return Err(bad("compares amounts of different units in one group"));
    }
    *group_unit = Some(unit_id);
    if seen.insert(mantissa) {
        *n = n
            .checked_add(1)
            .ok_or_else(|| refusal(name, format!("`{name}` overflows"), false))?;
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
    units: &UnitRegistry,
) -> Result<Vec<Vec<QueryCell>>, Refusal> {
    let keys: Vec<usize> = plan
        .columns
        .iter()
        .filter_map(|c| match c.value {
            Value::Key(native) => Some(native),
            Value::Aggregate { .. } | Value::DistinctAmountCount { .. } => None,
        })
        .collect();
    let fresh = || -> Vec<Acc> {
        plan.columns
            .iter()
            .filter_map(|c| match c.value {
                Value::Key(_) => None,
                Value::DistinctAmountCount { .. } => {
                    Some(Acc::DistinctAmounts(BTreeSet::new(), None, 0))
                }
                Value::Aggregate { function, .. } => Some(match function {
                    Function::Count => Acc::Count(0),
                    Function::CountDistinct => Acc::Distinct(BTreeSet::new(), 0),
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
            match column.value {
                Value::Key(_) => continue,
                Value::Aggregate { native, amount, .. } => {
                    fold(&mut accs[a], native.map(|n| &row[n]), amount, &column.name)?;
                }
                Value::DistinctAmountCount {
                    amount,
                    bytes,
                    unit,
                } => distinct_amount(
                    &mut accs[a],
                    row,
                    (amount, bytes, unit),
                    units,
                    &column.name,
                )?,
            }
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
                Value::Aggregate { .. } | Value::DistinctAmountCount { .. } => match accs.next() {
                    Some(Acc::Count(n) | Acc::Distinct(_, n) | Acc::DistinctAmounts(_, _, n)) => {
                        Out::Count(n)
                    }
                    Some(Acc::Sum(total)) => Out::Cell(total.map_or_else(
                        || {
                            if matches!(column.value, Value::Aggregate { amount: true, .. }) {
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

    fn aggregate(
        plan: &Aggregation,
        rows: &[Vec<QueryValue>],
    ) -> Result<Vec<Vec<QueryCell>>, Refusal> {
        super::aggregate(plan, rows, &UnitRegistry::embedded().unwrap())
    }

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

    fn null() -> QueryValue {
        GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Null))
    }

    fn bytes(mantissa: i128) -> QueryValue {
        GraphAggregateValue::Value(GraphValue::Scalar(
            CanonicalScalar::bytes(mantissa.to_le_bytes().to_vec()).unwrap(),
        ))
    }

    fn unit(id: UnitId) -> QueryValue {
        GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Int(i64::from(id.0))))
    }

    fn distinct_count(amount: usize) -> Value {
        Value::DistinctAmountCount {
            amount,
            bytes: amount + 1,
            unit: amount + 2,
        }
    }

    #[test]
    fn distinct_amounts_deduplicate_logical_mantissas_including_byte_fallbacks() {
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let p = plan(
            vec![
                ("distinct", distinct_count(0)),
                (
                    "mirrored",
                    Value::Aggregate {
                        function: Function::Count,
                        native: Some(0),
                        amount: true,
                    },
                ),
                (
                    "rows",
                    Value::Aggregate {
                        function: Function::Count,
                        native: None,
                        amount: false,
                    },
                ),
            ],
            vec![],
        );
        let rows = vec![
            vec![decimal(123), null(), unit(usd)],
            // Different representations of one logical value must not
            // increase cardinality, even when replay supplies both forms.
            vec![null(), bytes(123), unit(usd)],
            vec![decimal(250), null(), unit(usd)],
            vec![null(), bytes(10_i128.pow(35)), unit(usd)],
            vec![null(), bytes(10_i128.pow(35)), unit(usd)],
            vec![null(), bytes(i128::MAX), unit(usd)],
            vec![null(), bytes(i128::MIN), unit(usd)],
        ];
        assert_eq!(
            aggregate(&p, &rows).unwrap(),
            [vec![
                QueryCell::Int(5),
                QueryCell::Int(2),
                QueryCell::Int(7)
            ]]
        );
        assert_eq!(
            aggregate(&p, &[]).unwrap(),
            [vec![
                QueryCell::Int(0),
                QueryCell::Int(0),
                QueryCell::Int(0)
            ]]
        );
        // Unit precision beyond the native decimal scale still has the
        // complete exact i128 domain through the byte representation.
        let mut units = units;
        let mut precise = units.get(usd).unwrap().clone();
        precise.code = "PRECISE".to_string();
        precise.scale = 38;
        let precise = units.register(precise).unwrap();
        let rows = vec![
            vec![null(), bytes(1), unit(precise)],
            vec![null(), bytes(i128::MAX), unit(precise)],
        ];
        assert_eq!(
            super::aggregate(&p, &rows, &units).unwrap(),
            [vec![
                QueryCell::Int(2),
                QueryCell::Int(0),
                QueryCell::Int(2)
            ]]
        );
    }

    #[test]
    fn distinct_amount_groups_order_and_page_counts_without_cross_unit_comparison() {
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let mut p = plan(
            vec![("unit", Value::Key(0)), ("distinct", distinct_count(1))],
            vec![(1, true)],
        );
        let rows = vec![
            vec![text("EUR"), decimal(123), null(), unit(eur)],
            vec![text("USD"), decimal(123), null(), unit(usd)],
            vec![text("EUR"), null(), bytes(123), unit(eur)],
            vec![text("USD"), null(), bytes(i128::MAX), unit(usd)],
        ];
        assert_eq!(
            aggregate(&p, &rows).unwrap(),
            [
                vec![QueryCell::Text("USD".into()), QueryCell::Int(2)],
                vec![QueryCell::Text("EUR".into()), QueryCell::Int(1)],
            ]
        );
        p.skip = 1;
        p.limit = Some(1);
        assert_eq!(
            aggregate(&p, &rows).unwrap(),
            [vec![QueryCell::Text("EUR".into()), QueryCell::Int(1)]]
        );
        assert!(aggregate(&p, &[]).unwrap().is_empty());
    }

    #[test]
    fn distinct_amounts_refuse_missing_malformed_ambiguous_or_cross_unit_inputs() {
        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eur = units.lookup("EUR").unwrap();
        let p = plan(vec![("distinct", distinct_count(0))], vec![]);
        let finer = GraphAggregateValue::Value(GraphValue::Scalar(CanonicalScalar::Decimal(
            CanonicalDecimal::from_scaled_half_even(1, 3).unwrap(),
        )));
        let malformed = GraphAggregateValue::Value(GraphValue::Scalar(
            CanonicalScalar::bytes(vec![0; 15]).unwrap(),
        ));
        for row in [
            vec![null(), null(), unit(usd)],
            vec![decimal(123), bytes(123), unit(usd)],
            vec![finer, null(), unit(usd)],
            vec![null(), malformed, unit(usd)],
            vec![null(), text("123"), unit(usd)],
            vec![GraphAggregateValue::Integer(123), null(), unit(usd)],
            vec![decimal(123), null(), null()],
            vec![decimal(123), null(), unit(UnitId(u32::MAX))],
            vec![decimal(123), null()],
        ] {
            let refusal = aggregate(&p, &[row]).unwrap_err();
            assert_eq!(refusal.code, code::QUERY_AMOUNT_LAW, "{refusal:?}");
        }
        let refusal = aggregate(
            &p,
            &[
                vec![decimal(123), null(), unit(usd)],
                vec![decimal(123), null(), unit(eur)],
            ],
        )
        .unwrap_err();
        assert_eq!(refusal.code, code::QUERY_AMOUNT_LAW);
        assert!(refusal.message.contains("different units"));
        // Even a row outside the result's page must be validated.
        let mut paged = p;
        paged.limit = Some(0);
        assert!(aggregate(&paged, &[vec![null(), null(), unit(usd)]]).is_err());
    }

    #[test]
    fn distinct_nonamount_values_keep_native_null_semantics_and_counts_never_wrap() {
        let p = plan(
            vec![(
                "distinct",
                Value::Aggregate {
                    function: Function::CountDistinct,
                    native: Some(0),
                    amount: false,
                },
            )],
            vec![],
        );
        assert_eq!(
            aggregate(
                &p,
                &[
                    vec![text("same")],
                    vec![text("same")],
                    vec![null()],
                    vec![text("other")],
                ]
            )
            .unwrap(),
            [vec![QueryCell::Int(2)]]
        );
        let mut acc = Acc::Distinct(BTreeSet::from([text("same")]), u64::MAX);
        fold(&mut acc, Some(&text("same")), false, "distinct").unwrap();
        assert!(fold(&mut acc, Some(&text("other")), false, "distinct").is_err());

        let units = UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let mut acc = Acc::DistinctAmounts(BTreeSet::from([123]), Some(usd), u64::MAX);
        distinct_amount(
            &mut acc,
            &[null(), bytes(123), unit(usd)],
            (0, 1, 2),
            &units,
            "distinct",
        )
        .unwrap();
        assert!(
            distinct_amount(
                &mut acc,
                &[decimal(124), null(), unit(usd)],
                (0, 1, 2),
                &units,
                "distinct",
            )
            .is_err()
        );
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
