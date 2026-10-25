//! Profile queries over the book's graph (plan §15.5, bead fa-5c1): a
//! statement [`fa_query`] compiled is run as one native read at one
//! recorded sequence through the substrate's certified execution, so the
//! same statement at the same sequence returns the same rows and the same
//! result digest.
//!
//! The rows are the graph as recorded at that sequence: every committed
//! vertex and edge, pending holds and staged migration chunks included. A
//! balance is a fold, read with `CALL fa.trial_balance` or the report
//! verbs, never a sum of these rows presented as one. Authorization is the
//! caller's, before this runs: a query is a whole-book read.

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Refusal, exit};
use fa_model::{EncodeError, Writer};
use fa_query::{Law, Native};
use fa_time::DateDay;
use fgdb::{Database, NativeResultCertificate, QueryError, QueryResult, QueryValue};
use fgdb_gql::algebra::GraphValue;
use fgdb_gql::{GqlParameters, GqlQueryPolicy, GraphAggregateValue};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, EId, QueryCx, VId};

use crate::{AsyncBook, BookError};

mod aggregate;
mod certificate;

pub use certificate::{
    CertifiedQuery, QUERY_CERTIFICATE_FORMAT, QueryCertificate, QueryCertificateStatus,
};

/// The canonical bytes of a query's result begin with this tag.
pub const QUERY_OUTPUT_FORMAT: &[u8] = b"fa:query-result:v1";

pub mod code {
    /// A clause outside the profile, a malformed selector, an unsupported
    /// construct or a native refusal (parse, budget) of the compiled
    /// statement.
    pub const QUERY_PROFILE: &str = "FA-REF-188";
    /// An amount aggregated, compared or ordered across units, compared with
    /// a literal, or aggregated over a leg whose decimal mirror is null.
    pub const QUERY_AMOUNT_LAW: &str = "FA-REF-189";
}

/// The most rows a query returns; a larger result is refused, never cut.
pub const MAX_QUERY_ROWS: u64 = 10_000;

/// The most native rows an amount aggregate folds.
pub const MAX_AGGREGATED_ROWS: u64 = 1_000_000;

const CITE: &str = "plan §15.5 (the profile is a rewriter onto native reads)";
const AMOUNT_CITE: &str = "plan §15.5 (sum, avg and comparison over amounts of different units are refused at rewrite time) · doctrine 4";

/// One value of a result row, exactly as the native read returned it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueryCell {
    Null,
    Bool(bool),
    /// An integer property, a count or an exact integer aggregate.
    Int(i128),
    /// An exact decimal without trailing zeros (`150`, `0.5`): an amount
    /// mirror, or an exact sum of them.
    Decimal(String),
    /// An exact average, never rounded.
    Fraction {
        numerator: i128,
        denominator: u64,
    },
    /// A float a native function produced; no FA property holds one.
    Float(String),
    Text(String),
    /// A timestamp as UTC nanoseconds.
    Timestamp(i128),
    Bytes(Vec<u8>),
    Vertex(VId),
    Edge(EId),
    Path {
        start: VId,
        steps: Vec<(EId, VId)>,
    },
    List(Vec<QueryCell>),
    Map(Vec<(String, QueryCell)>),
}

impl QueryCell {
    fn of(value: &QueryValue) -> Self {
        match value {
            GraphAggregateValue::Count(n) => Self::Int(i128::from(*n)),
            GraphAggregateValue::Integer(n) => Self::Int(*n),
            GraphAggregateValue::Average(average) => Self::Fraction {
                numerator: average.numerator(),
                denominator: average.denominator(),
            },
            GraphAggregateValue::Value(value) => Self::graph(value),
        }
    }

    fn graph(value: &GraphValue) -> Self {
        match value {
            GraphValue::Scalar(scalar) => match scalar {
                CanonicalScalar::Null => Self::Null,
                CanonicalScalar::Bool(b) => Self::Bool(*b),
                CanonicalScalar::Int(n) => Self::Int(i128::from(*n)),
                CanonicalScalar::Decimal(d) => Self::Decimal(decimal(&d.to_string())),
                CanonicalScalar::Float(f) => Self::Float(f.get().to_string()),
                CanonicalScalar::Text(text) => Self::Text(text.as_str().to_string()),
                CanonicalScalar::Timestamp(ts) => Self::Timestamp(ts.instant_utc_nanos()),
                CanonicalScalar::Bytes(bytes) => Self::Bytes(bytes.as_slice().to_vec()),
            },
            GraphValue::Vertex(vid) => Self::Vertex(*vid),
            GraphValue::Edge(eid) => Self::Edge(*eid),
            GraphValue::Path(path) => Self::Path {
                start: path.start(),
                steps: path.steps().to_vec(),
            },
            GraphValue::Vertices(vids) => {
                Self::List(vids.iter().map(|v| Self::Vertex(*v)).collect())
            }
            GraphValue::Edges(eids) => Self::List(eids.iter().map(|e| Self::Edge(*e)).collect()),
            GraphValue::List(values) => Self::List(values.iter().map(Self::graph).collect()),
            GraphValue::Map { keys, values } => Self::Map(
                keys.iter()
                    .zip(values.iter())
                    .map(|(k, v)| (k.to_string(), Self::graph(v)))
                    .collect(),
            ),
        }
    }
}

/// The canonical decimal text (always 18 fraction digits) without its
/// trailing zeros: the same exact value, as an amount is usually written.
fn decimal(canonical: &str) -> String {
    match canonical.split_once('.') {
        Some((whole, fraction)) => {
            let fraction = fraction.trim_end_matches('0');
            if fraction.is_empty() {
                whole.to_string()
            } else {
                format!("{whole}.{fraction}")
            }
        }
        None => canonical.to_string(),
    }
}

/// One query's result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryRows {
    /// The native statement that ran.
    pub statement: String,
    pub known_at: CommitSeq,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<QueryCell>>,
    /// The substrate's digest of the ordered result under its plan.
    pub result_digest: [u8; 32],
}

impl QueryRows {
    /// The result's canonical bytes: the native statement, its sequence,
    /// the columns, every cell and the substrate's result digest. A query
    /// certificate binds exactly these bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.bytes(QUERY_OUTPUT_FORMAT)
            .str(&self.statement)
            .u64(self.known_at.0)
            .list(&self.columns, |w, column| {
                w.str(column);
            })
            .list(&self.rows, |w, row| {
                w.list(row, write_cell);
            })
            .fixed(&self.result_digest);
        w.finish()
    }
}

fn write_cell(w: &mut Writer, cell: &QueryCell) {
    match cell {
        QueryCell::Null => {
            w.u8(0);
        }
        QueryCell::Bool(b) => {
            w.u8(1).bool(*b);
        }
        QueryCell::Int(n) => {
            w.u8(2).i128(*n);
        }
        QueryCell::Decimal(text) => {
            w.u8(3).str(text);
        }
        QueryCell::Fraction {
            numerator,
            denominator,
        } => {
            w.u8(4).i128(*numerator).u64(*denominator);
        }
        QueryCell::Float(text) => {
            w.u8(5).str(text);
        }
        QueryCell::Text(text) => {
            w.u8(6).str(text);
        }
        QueryCell::Timestamp(ns) => {
            w.u8(7).i128(*ns);
        }
        QueryCell::Bytes(bytes) => {
            w.u8(8).bytes(bytes);
        }
        QueryCell::Vertex(vid) => {
            w.u8(9).u128(vid.0);
        }
        QueryCell::Edge(eid) => {
            w.u8(10).u128(eid.0);
        }
        QueryCell::Path { start, steps } => {
            w.u8(11).u128(start.0).list(steps, |w, (eid, vid)| {
                w.u128(eid.0).u128(vid.0);
            });
        }
        QueryCell::List(cells) => {
            w.u8(12).list(cells, write_cell);
        }
        QueryCell::Map(entries) => {
            w.u8(13).list(entries, |w, (key, value)| {
                w.str(key);
                write_cell(w, value);
            });
        }
    }
}

/// A profile refusal as the catalog's typed refusal.
#[must_use]
pub fn profile_refusal(refusal: &fa_query::Refusal) -> Refusal {
    let typed = match refusal.law {
        Law::Profile => Refusal::new(
            code::QUERY_PROFILE,
            exit::REFUSAL,
            refusal.message.clone(),
            CITE,
            refusal.fix.clone(),
        ),
        Law::Amount => Refusal::new(
            code::QUERY_AMOUNT_LAW,
            exit::REFUSAL,
            refusal.message.clone(),
            AMOUNT_CITE,
            refusal.fix.clone(),
        ),
    };
    typed.at("statement offset", refusal.at.to_string())
}

fn policy(rows: u64) -> GqlQueryPolicy {
    // Bounded native execution: exceeding a budget is a typed refusal,
    // never a truncated result.
    GqlQueryPolicy::new(10_000_000, rows, 256 * 1024 * 1024, 256 * 1024 * 1024)
}

fn native_refusal(statement: &str, error: &QueryError) -> Refusal {
    Refusal::new(
        code::QUERY_PROFILE,
        exit::REFUSAL,
        format!("the native read refused the compiled statement: {error}"),
        CITE,
        format!(
            "correct the statement; the profile ran exactly `{statement}`. A result is at most {MAX_QUERY_ROWS} rows: narrow the pattern or add LIMIT"
        ),
    )
}

/// The period `code` names at `seq`, or the refusal for one the book does
/// not hold.
fn period_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    code: &str,
    seq: CommitSeq,
) -> Result<Result<fa_journal::PeriodRow, Refusal>, BookError> {
    let row = db
        .vertex_at(fa_model::period_vid(&book.calendar.id, code), seq)
        .map_err(fa_journal::KernelError::from)?
        .filter(|row| row.labels.contains(&fa_model::symbols::label::PERIOD));
    Ok(match row {
        Some(row) => Ok(fa_journal::PeriodRow::decode(&row)?),
        None => Err(Refusal::new(
            code::QUERY_PROFILE,
            exit::REFUSAL,
            format!("period `{code}` does not exist at {}", seq.0),
            CITE,
            "name a period the book holds: fa period list --json",
        )
        .at("period", code.to_string())),
    })
}

/// The days a `FOR PERIOD` selects at `seq`: its period's (or a range's
/// first period's) start and its (or the last period's) exclusive end. A
/// code the book does not hold, at either end, and a range that ends before
/// it starts are refused.
fn period_bounds<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    code: &str,
    seq: CommitSeq,
) -> Result<Result<(DateDay, DateDay), Refusal>, BookError> {
    let (from, through) = code.split_once("..").unwrap_or((code, code));
    let first = match period_at(db, book, from, seq)? {
        Ok(period) => period,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let last = if through == from {
        first.clone()
    } else {
        match period_at(db, book, through, seq)? {
            Ok(period) => period,
            Err(refusal) => return Ok(Err(refusal)),
        }
    };
    if last.start < first.start {
        return Ok(Err(Refusal::new(
            code::QUERY_PROFILE,
            exit::REFUSAL,
            format!(
                "the period range `{code}` ends before it starts: {through} starts {}, before {from}'s {}",
                last.start.render(),
                first.start.render()
            ),
            CITE,
            format!("name the earlier period first: FOR PERIOD '{through}'..'{from}'"),
        )
        .at("period", code.to_string())));
    }
    Ok(Ok((first.start, last.end)))
}

/// The native rows a statement may read: an amount aggregate folds more
/// rows than it returns.
fn budget(native: &Native) -> GqlQueryPolicy {
    policy(
        native
            .aggregation()
            .map_or(MAX_QUERY_ROWS, |_| MAX_AGGREGATED_ROWS),
    )
}

/// The statement's result from its native rows: the native columns and
/// values, or the exact aggregation its plan names.
fn result_of(
    native: &Native,
    seq: CommitSeq,
    result: QueryResult,
    certificate: &NativeResultCertificate,
) -> Result<QueryRows, Refusal> {
    let QueryResult::Rows { columns, rows } = result else {
        return Err(Refusal::new(
            code::QUERY_PROFILE,
            exit::REFUSAL,
            "the compiled statement is not a read",
            CITE,
            "fa query only reads; the journal changes through its intents",
        ));
    };
    let (columns, rows) = match native.aggregation() {
        Some(plan) => (
            plan.columns.iter().map(|c| c.name.clone()).collect(),
            aggregate::aggregate(plan, &rows)?,
        ),
        None => (
            columns,
            rows.iter()
                .map(|row| row.iter().map(QueryCell::of).collect())
                .collect(),
        ),
    };
    Ok(QueryRows {
        statement: native.statement(seq.0),
        known_at: seq,
        columns,
        rows,
        result_digest: certificate.result_digest.0,
    })
}

/// One certified native read of `native` at `seq` (at most the head).
fn execute<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    native: &Native,
    seq: CommitSeq,
    period: Option<&str>,
) -> Result<Result<(QueryRows, NativeResultCertificate), Refusal>, BookError> {
    // A period range's filter waits for its days, resolved at `seq`.
    let bound;
    let native = match period {
        Some(code) => match period_bounds(db, book, code, seq)? {
            Err(refusal) => return Ok(Err(refusal)),
            Ok((start, end)) if native.period_range() => {
                bound = native.bind_period_range(start.0, end.0);
                &bound
            }
            Ok(_) => native,
        },
        None => native,
    };
    let statement = native.statement(seq.0);
    let (result, certificate) = match db.execute_certified(
        cx,
        &statement,
        &GqlParameters::new(),
        book.symbols.clone(),
        budget(native),
    ) {
        Ok(executed) => executed,
        Err(QueryError::Read(error)) => {
            return Err(BookError::CertifiedRead(QueryError::Read(error)));
        }
        Err(error) => return Ok(Err(native_refusal(&statement, &error))),
    };
    Ok(result_of(native, seq, result, &certificate).map(|rows| (rows, certificate)))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Run `native` at `known_at` (at most the head). With `period`, the
    /// period must exist at that sequence.
    pub fn query_native(
        &self,
        cx: &PurposeContexts,
        native: &Native,
        known_at: CommitSeq,
        period: Option<&str>,
    ) -> Result<Result<QueryRows, Refusal>, BookError> {
        self.query(cx, |db, book| {
            let seq = fa_registers::resolve_known_at(db, Some(known_at))?;
            Ok(execute(db, &cx.query(), book, native, seq, period)?.map(|(rows, _)| rows))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::decimal;

    #[test]
    fn a_decimal_keeps_its_exact_value_without_trailing_zeros() {
        assert_eq!(decimal("1000.000000000000000000"), "1000");
        assert_eq!(decimal("-0.500000000000000000"), "-0.5");
        assert_eq!(decimal("12.340000000000000001"), "12.340000000000000001");
        assert_eq!(decimal("7"), "7");
    }
}
