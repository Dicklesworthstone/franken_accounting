//! Per-row open amounts over a certified native source, then an ordinary
//! native row continuation. No GQL predicate or projection is evaluated here.
//! A v2 query certificate retains both native reads and commits to the
//! complete derived parameter transcript. Replay regenerates that transcript
//! from the first read and the historical journal fold, never supplied values.

use std::collections::BTreeMap;

use fa_model::domain_digest;
use fa_money::UnitId;
use fa_query::OpenAmount;
use fgdb_types::CanonicalDecimal;

use super::*;

/// One native list parameter is bounded by the pinned foundation to 64 KiB.
/// We refuse a larger source rather than truncate it or execute batches with
/// different grouping, ordering or pagination semantics.
const MAX_PARAMETER_BYTES: usize = 64 * 1024;
const PARAMETER_DOMAIN: &[u8] = b"fa:query-open-amount-parameters:v1";

/// The first native read and every named, typed value passed to the second.
/// The continuation's own native certificate independently binds these values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Evidence {
    pub source: NativeResultCertificate,
    pub parameters_digest: [u8; 32],
}

fn parameters_digest(parameters: &GqlParameters) -> [u8; 32] {
    domain_digest(PARAMETER_DOMAIN, &[&parameters.canonical_bytes()])
}

fn invalid(why: impl Into<String>) -> Refusal {
    Refusal::new(
        code::QUERY_PROFILE,
        exit::REFUSAL,
        why,
        CITE,
        "narrow the MATCH or its pre-CALL WHERE; open_amount accepts at most 10,000 source rows and one 64 KiB native parameter",
    )
}

fn amount_refusal(why: impl Into<String>) -> Refusal {
    Refusal::new(
        code::QUERY_AMOUNT_LAW,
        exit::REFUSAL,
        why,
        AMOUNT_CITE,
        "use the historical open-items or aging report for exact mantissas outside the native decimal range",
    )
}

fn parameters(
    book: &BookContext,
    procedure: &OpenAmount,
    rows: Vec<Vec<QueryValue>>,
    items: &[fa_registers::open_items::OpenItem],
) -> Result<GqlParameters, Refusal> {
    let items = items
        .iter()
        .map(|item| (fa_journal::rows::leg_vid(item.entry, item.ordinal), item))
        .collect::<BTreeMap<_, _>>();
    let mut values = Vec::with_capacity(rows.len());
    // A conservative framing charge; the foundation checks exact canonical
    // framing again when admitting the complete immutable list parameter.
    let mut parameter_bytes = 16_usize;
    for row in rows {
        if row.len() != procedure.input_columns() {
            return Err(invalid(
                "the native source returned an unexpected column count",
            ));
        }
        let Some(GraphAggregateValue::Value(GraphValue::Vertex(leg))) = row.first() else {
            return Err(invalid("open_amount's source is not a Leg vertex"));
        };
        let (open, age_days) = match items.get(leg) {
            Some(item) => {
                let unit = book.units.get(UnitId(item.unit_id)).ok_or_else(|| {
                    amount_refusal("the historical open item names an unknown unit")
                })?;
                if unit.scale > 18 {
                    return Err(amount_refusal(format!(
                        "unit {} has scale {}; a native decimal carries at most 18 exact places",
                        unit.code, unit.scale
                    )));
                }
                let amount =
                    CanonicalDecimal::from_scaled_half_even(item.open, u32::from(unit.scale))
                        .map_err(|_| {
                            amount_refusal("the open amount exceeds the exact native decimal range")
                        })?;
                let age = i64::from(procedure.effective_through().0)
                    .checked_sub(i64::from(item.effective_date.0))
                    .filter(|age| *age >= 0)
                    .ok_or_else(|| {
                        invalid("the historical fold returned an item after its effective cutoff")
                    })?;
                (CanonicalScalar::Decimal(amount), CanonicalScalar::Int(age))
            }
            // A raw graph query also sees holds, reversals and staged
            // migrations. They have no live posted open item at this prefix.
            // Preserve the row and its inapplicability, not an invented zero.
            None => (CanonicalScalar::Null, CanonicalScalar::Null),
        };
        let mut fields = Vec::with_capacity(row.len() + 2);
        for (i, value) in row.into_iter().enumerate() {
            let GraphAggregateValue::Value(value) = value else {
                return Err(invalid(
                    "the open_amount source unexpectedly aggregated a carried value",
                ));
            };
            fields.push((format!("c{i}").into_boxed_str(), value));
        }
        fields.push(("open".into(), GraphValue::Scalar(open)));
        fields.push(("age_days".into(), GraphValue::Scalar(age_days)));
        let row = GraphValue::map(fields).ok_or_else(|| invalid("duplicate carried row fields"))?;
        let bytes = row
            .canonical_bytes()
            .map_err(|_| invalid("a carried row exceeds native value bounds"))?;
        parameter_bytes = parameter_bytes
            .checked_add(bytes.len())
            .filter(|bytes| *bytes <= MAX_PARAMETER_BYTES)
            .ok_or_else(|| {
                invalid("the open_amount continuation exceeds its 64 KiB parameter bound")
            })?;
        values.push(row);
    }
    let parameters = GqlParameters::new()
        .with_list(procedure.parameter(), values)
        .map_err(|error| {
            invalid(format!(
                "the native continuation refused its bounded parameter: {error}"
            ))
        })?;
    // Include parameter names, type tags and list/map framing in the bound,
    // not just the sum of the carried values' encodings.
    if parameters.canonical_bytes().len() > MAX_PARAMETER_BYTES {
        return Err(invalid(
            "the open_amount continuation exceeds its 64 KiB parameter bound",
        ));
    }
    Ok(parameters)
}

pub(super) fn execute<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    native: &Native,
    procedure: &OpenAmount,
    seq: CommitSeq,
) -> Result<Result<ExecutedQuery, Refusal>, BookError> {
    let source = native.statement(seq.0);
    let (result, source_certificate) = match db.execute_certified(
        cx,
        &source,
        &GqlParameters::new(),
        book.symbols.clone(),
        policy(MAX_QUERY_ROWS),
    ) {
        Ok(executed) => executed,
        Err(QueryError::Read(error)) => {
            return Err(BookError::CertifiedRead(QueryError::Read(error)));
        }
        Err(error) => return Ok(Err(native_refusal(&source, &error))),
    };
    let QueryResult::Rows { rows, .. } = result else {
        return Ok(Err(invalid("the open_amount source is not a native read")));
    };
    let snapshot = fa_registers::open_items::history::open_items_as_of(
        db,
        book,
        None,
        procedure.effective_through(),
        Some(seq),
    )?;
    let parameters = match parameters(book, procedure, rows, &snapshot.items) {
        Ok(parameters) => parameters,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let statement = procedure.statement(seq.0);
    let (result, certificate) = match db.execute_certified(
        cx,
        &statement,
        &parameters,
        book.symbols.clone(),
        budget(native),
    ) {
        Ok(executed) => executed,
        Err(QueryError::Read(error)) => {
            return Err(BookError::CertifiedRead(QueryError::Read(error)));
        }
        Err(error) => return Ok(Err(native_refusal(&statement, &error))),
    };
    Ok(
        finish(native, procedure, seq, result, &certificate).map(|rows| ExecutedQuery {
            rows,
            native: certificate,
            pipeline: Some(Evidence {
                source: source_certificate,
                parameters_digest: parameters_digest(&parameters),
            }),
        }),
    )
}

/// Replay both native stages with freshly derived values at the certified
/// recorded/effective coordinate. The caller first replays the whole-prefix
/// ReportCertificate and validates the statements and stage coordinates.
pub(super) fn replay<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    native: &Native,
    seq: CommitSeq,
    evidence: &Evidence,
    continuation: &NativeResultCertificate,
) -> Result<Result<QueryRows, Refusal>, BookError> {
    let Some(procedure) = native.open_amount() else {
        return Ok(Err(invalid(
            "pipeline evidence needs an open_amount statement",
        )));
    };
    let result = match db.replay(
        cx,
        &evidence.source,
        &GqlParameters::new(),
        book.symbols.clone(),
        policy(MAX_QUERY_ROWS),
    ) {
        Ok(result) => result,
        Err(error) => {
            return Ok(Err(invalid(format!(
                "the pipeline source read does not replay: {error}"
            ))));
        }
    };
    let QueryResult::Rows { rows, .. } = result else {
        return Ok(Err(invalid(
            "the replayed pipeline source is not a native read",
        )));
    };
    let snapshot = fa_registers::open_items::history::open_items_as_of(
        db,
        book,
        None,
        procedure.effective_through(),
        Some(seq),
    )?;
    let parameters = match parameters(book, procedure, rows, &snapshot.items) {
        Ok(parameters) => parameters,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if parameters_digest(&parameters) != evidence.parameters_digest {
        return Ok(Err(invalid(
            "the regenerated open_amount parameters differ from their certified commitment",
        )));
    }
    let result = match db.replay(
        cx,
        continuation,
        &parameters,
        book.symbols.clone(),
        budget(native),
    ) {
        Ok(result) => result,
        Err(error) => {
            return Ok(Err(invalid(format!(
                "the pipeline continuation does not replay: {error}"
            ))));
        }
    };
    Ok(finish(native, procedure, seq, result, continuation))
}

fn finish(
    native: &Native,
    procedure: &OpenAmount,
    seq: CommitSeq,
    result: QueryResult,
    certificate: &NativeResultCertificate,
) -> Result<QueryRows, Refusal> {
    let mut rows = result_of(native, seq, result, certificate)?;
    if native.aggregation().is_none() {
        if rows.columns.len() != procedure.columns().len() {
            return Err(invalid(
                "the native continuation returned an unexpected column count",
            ));
        }
        rows.columns = procedure.columns().to_vec();
    }
    rows.statement = format!(
        "{}; {}",
        native.statement(seq.0),
        procedure.statement(seq.0)
    );
    Ok(rows)
}

#[cfg(test)]
pub(super) mod tests;

#[cfg(test)]
mod bounds_tests;
