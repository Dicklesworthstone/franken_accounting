//! Effective-date aging reconstructed from independently verified open items.
//!
//! The complete source is checked before applying the civil-date cutoff. Its
//! application/reversal fold supplies the residuals; the producer's bucket
//! amounts, citations and native read witnesses supply no arithmetic here.

use std::collections::BTreeMap;

use super::{
    MAX_CITES, MAX_FINDINGS, Reader, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureParameters, VerifiedProcedureStatistic, failed, text,
};

pub(super) const DEFAULTS: [(&str, u32); 3] =
    [("bucket_1", 30), ("bucket_2", 60), ("bucket_3", 90)];

pub(super) fn decode(reader: &mut Reader<'_>) -> Result<VerifiedProcedureParameters, ReportError> {
    if reader.count(DEFAULTS.len(), 20, "procedure.parameters")? != DEFAULTS.len() {
        return Err(failed(
            "procedure_profile",
            "open-item aging requires all three explicit bucket edges",
        ));
    }
    let mut edges = [0; 3];
    for (index, (name, _)) in DEFAULTS.iter().enumerate() {
        if text(reader, 64, "procedure.parameter")? != *name {
            return Err(failed(
                "procedure_profile",
                "aging bucket names must be complete, unique and lexically ordered",
            ));
        }
        edges[index] = u32::try_from(reader.i128("procedure.parameter_value")?).map_err(|_| {
            failed(
                "procedure_profile",
                "aging bucket edges must be unsigned 32-bit integers",
            )
        })?;
    }
    validate_edges(edges)?;
    Ok(VerifiedProcedureParameters::OpenItemsAging { edges })
}

fn validate_edges(edges: [u32; 3]) -> Result<(), ReportError> {
    if edges[0] >= edges[1] || edges[1] >= edges[2] {
        return Err(failed(
            "procedure_profile",
            "aging bucket edges must be strictly ascending",
        ));
    }
    Ok(())
}

fn arithmetic() -> ReportError {
    failed(
        "procedure_arithmetic",
        "open-item aging exceeds its exact arithmetic bounds",
    )
}

#[derive(Default)]
struct Column {
    totals: [i128; 4],
    items: u64,
    oldest: Vec<(u128, u16)>,
}

pub(super) fn replay(
    profile: VerifiedProcedureParameters,
    effective_through: Option<i32>,
    registry: &Registry,
) -> Result<(Vec<VerifiedProcedureFinding>, u64), ReportError> {
    let VerifiedProcedureParameters::OpenItemsAging { edges } = profile else {
        return Err(failed("procedure_profile", "expected open-item aging"));
    };
    validate_edges(edges)?;
    let cutoff = effective_through.ok_or_else(|| {
        failed(
            "procedure_selection",
            "open-item aging requires an explicit inclusive effective cutoff",
        )
    })?;
    let items = registry.open_items.as_ref().ok_or_else(|| {
        failed(
            "procedure_inputs",
            "open-item aging requires an independently reconstructed historical fold",
        )
    })?;
    let mut aged = Vec::new();
    for item in items {
        let expected = item
            .original
            .checked_sub(item.applied_out)
            .and_then(|amount| amount.checked_sub(item.applied))
            .ok_or_else(arithmetic)?;
        if item.original < 0
            || item.applied < 0
            || item.applied_out < 0
            || item.open < 0
            || item.open != expected
            || item.effective_date > cutoff
        {
            return Err(failed(
                "procedure_inputs",
                "historical open-item residual or effective date is inconsistent",
            ));
        }
        if item.open == 0 {
            continue;
        }
        let age = u64::try_from(i64::from(cutoff) - i64::from(item.effective_date))
            .map_err(|_| arithmetic())?;
        let bucket = edges.partition_point(|edge| u64::from(*edge) < age);
        aged.push((item, bucket));
    }
    // Native aging caps only the oldest-band citations. Preserve which first
    // chronological items are cited before sorting those citations by identity.
    aged.sort_unstable_by_key(|(item, bucket)| {
        (
            item.account,
            item.unit_id,
            *bucket,
            item.effective_date,
            item.recorded_at,
            item.entry,
            item.ordinal,
        )
    });
    let population = u64::try_from(aged.len()).map_err(|_| arithmetic())?;
    let mut columns: BTreeMap<(u128, u32, bool), Column> = BTreeMap::new();
    for (item, bucket) in aged {
        let column = columns
            .entry((item.account, item.unit_id, !item.debit))
            .or_default();
        column.totals[bucket] = column.totals[bucket]
            .checked_add(item.open)
            .ok_or_else(arithmetic)?;
        column.items = column.items.checked_add(1).ok_or_else(arithmetic)?;
        if bucket == 3 && column.oldest.len() < MAX_CITES - 1 {
            column.oldest.push((item.entry, item.ordinal));
        }
    }
    if columns.len() > MAX_FINDINGS {
        return Err(failed(
            "bounded_input",
            "open-item aging findings exceed the certificate bound",
        ));
    }
    let mut findings = Vec::with_capacity(columns.len());
    for ((account, unit, credit), mut column) in columns {
        let total = column
            .totals
            .iter()
            .try_fold(0i128, |sum, amount| sum.checked_add(*amount))
            .ok_or_else(arithmetic)?;
        let past = column.totals[3];
        let severity = if past == 0 {
            0
        } else if past.unsigned_abs() >= total.unsigned_abs().div_ceil(2) {
            3
        } else {
            2
        };
        let scale = *registry.unit_scales.get(&unit).ok_or_else(|| {
            failed(
                "procedure_units",
                "open-item aging uses an unregistered unit",
            )
        })?;
        column.oldest.sort_unstable();
        let side = if credit { "credit" } else { "debit" };
        findings.push(VerifiedProcedureFinding {
            entry: None,
            severity,
            population,
            narrative: format!(
                "unit {unit} {side}: {} open item(s); buckets 0..={}: {}, ..={}: {}, ..={}: {}, older: {} (mantissas, never netted)",
                column.items,
                edges[0], column.totals[0],
                edges[1], column.totals[1],
                edges[2], column.totals[2], past,
            ),
            statistic: VerifiedProcedureStatistic::AgedOpenAmount {
                name: format!("open_past_{}_days", edges[2]),
                account,
                unit,
                debit: !credit,
                totals: column.totals,
                items: column.items,
                scale,
                legs: column.oldest,
            },
        });
    }
    Ok((findings, population))
}

#[cfg(test)]
mod tests;
