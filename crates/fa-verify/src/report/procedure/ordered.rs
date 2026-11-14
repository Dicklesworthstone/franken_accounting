//! Independent one-account FIFO and LIFO tracing from authenticated movements.
//!
//! There is only one tainted deposit. All held money is therefore expressible
//! as three amounts: clean money older than that deposit, the deposit's
//! remainder, and newer clean money. Consuming these amounts in the chosen
//! order reproduces the law without the producer's per-deposit layer queue.
//! Negative account balances remain signed; a deposit first repays overdraft
//! and can contribute only the positive amount the account actually holds.

use std::collections::BTreeSet;

use super::{
    Entry, MAX_CITES, Reader, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureParameters, VerifiedProcedureStatistic, failed, libr, text,
};

pub(super) const DEFAULTS: [(&str, u32); 1] = [("intraday_order", 0)];

fn profile(message: &str) -> ReportError {
    failed("procedure_profile", message)
}

fn arithmetic() -> ReportError {
    failed(
        "procedure_arithmetic",
        "ordered tracing movement or balance exceeds exact i128 arithmetic",
    )
}

pub(super) fn decode(
    reader: &mut Reader<'_>,
    lifo: bool,
) -> Result<VerifiedProcedureParameters, ReportError> {
    if reader.count(1, 20, "procedure.parameters")? != 1
        || text(reader, 64, "procedure.parameter")? != "intraday_order"
    {
        return Err(profile(
            "FIFO and LIFO require only the explicit intraday_order parameter",
        ));
    }
    let intraday_order = u32::try_from(reader.i128("procedure.parameter_value")?)
        .map_err(|_| profile("tracing order is outside its unsigned range"))?;
    if !matches!(intraday_order, 0 | 2 | 3) {
        return Err(profile("tracing supports intraday_order 0, 2 or 3"));
    }
    let [account, source] = libr::decode_inputs(reader)?;
    Ok(if lifo {
        VerifiedProcedureParameters::TraceLifo {
            intraday_order,
            account,
            source,
        }
    } else {
        VerifiedProcedureParameters::TraceFifo {
            intraday_order,
            account,
            source,
        }
    })
}

fn consume(pool: &mut i128, remaining: &mut i128) -> Result<i128, ReportError> {
    let amount = (*pool).min(*remaining);
    *pool = pool.checked_sub(amount).ok_or_else(arithmetic)?;
    *remaining = remaining.checked_sub(amount).ok_or_else(arithmetic)?;
    Ok(amount)
}

pub(super) fn replay(
    selection: VerifiedProcedureParameters,
    claim: Option<i32>,
    live: &[&Entry],
    registry: &Registry,
) -> Result<(VerifiedProcedureFinding, u64, u64), ReportError> {
    let (lifo, intraday_order, account, source) = match selection {
        VerifiedProcedureParameters::TraceFifo {
            intraday_order,
            account,
            source,
        } => (false, intraday_order, account, source),
        VerifiedProcedureParameters::TraceLifo {
            intraday_order,
            account,
            source,
        } => (true, intraday_order, account, source),
        _ => return Err(profile("expected the FIFO or LIFO tracing profile")),
    };
    let claim = claim.ok_or_else(|| profile("tracing requires an effective claim date"))?;
    let stream = libr::stream(account, source, claim, intraday_order, live, registry)?;
    let mut opening = 0i128;
    for movement in &stream.movements[..stream.source_at] {
        opening = if movement.inflow {
            opening.checked_add(movement.magnitude)
        } else {
            opening.checked_sub(movement.magnitude)
        }
        .ok_or_else(arithmetic)?;
    }
    let deposit = stream.movements[stream.source_at].magnitude;
    let mut balance = opening.checked_add(deposit).ok_or_else(arithmetic)?;
    let mut older = opening.max(0);
    let mut traced = deposit.min(balance.max(0));
    let mut newer = 0i128;
    let mut lowest = balance;
    let mut lowest_entry = None;
    let mut carriers = BTreeSet::new();
    let mut carried = 0i128;
    for movement in &stream.movements[stream.source_at + 1..] {
        if movement.inflow {
            let before = balance.max(0);
            balance = balance
                .checked_add(movement.magnitude)
                .ok_or_else(arithmetic)?;
            let held = balance.max(0).checked_sub(before).ok_or_else(arithmetic)?;
            newer = newer.checked_add(held).ok_or_else(arithmetic)?;
            continue;
        }
        balance = balance
            .checked_sub(movement.magnitude)
            .ok_or_else(arithmetic)?;
        if balance < lowest {
            lowest = balance;
            lowest_entry = Some(movement.identity);
        }
        let mut withdrawal = movement.magnitude;
        let (first, last) = if lifo {
            (&mut newer, &mut older)
        } else {
            (&mut older, &mut newer)
        };
        consume(first, &mut withdrawal)?;
        let tainted = consume(&mut traced, &mut withdrawal)?;
        consume(last, &mut withdrawal)?;
        // Any remaining withdrawal is debt already recorded by `balance`,
        // never negative held money and never a source for later tracing.
        if tainted > 0 {
            carriers.insert(movement.identity);
            carried = carried.checked_add(tainted).ok_or_else(arithmetic)?;
        }
    }
    let carrier_count = carriers.len();
    if let Some(identity) = lowest_entry {
        carriers.insert(identity);
    }
    let mut citations = vec![source];
    citations.extend(
        carriers
            .into_iter()
            .filter(|id| *id != source)
            .take(MAX_CITES - 2),
    );
    let scale = registry
        .unit_scales
        .get(&stream.unit)
        .copied()
        .ok_or_else(|| failed("procedure_units", "the traced source unit is unregistered"))?;
    let count = stream.movements.len() as u64;
    let source_date = crate::bundle::civil(stream.movements[stream.source_at].day);
    let claim_date = crate::bundle::civil(claim);
    let entity_text = stream.entity.map_or_else(
        || "implicit book entity".to_string(),
        |entity| format!("entity {entity:032x}"),
    );
    let law = if lifo { "LIFO" } else { "FIFO (Clayton)" };
    let finding = VerifiedProcedureFinding {
        entry: None,
        severity: 0,
        statistic: VerifiedProcedureStatistic::TracedAmount {
            account,
            unit: stream.unit,
            mantissa: traced,
            scale,
            entries: citations,
        },
        population: count,
        narrative: format!(
            "{law}: {deposit} (mantissa) deposited {source_date}; {} later movement(s) through {claim_date}; lowest balance after the deposit {lowest}; {carrier_count} withdrawal(s) carried {carried} tainted; traced {traced}; {entity_text}",
            count - stream.source_at as u64 - 1,
        ),
    };
    Ok((finding, count - 1, stream.comparisons))
}

#[cfg(test)]
mod tests;
