//! Due-date aging over the complete authenticated OpenItems prefix. Maturity
//! comes only from immutable extension 33; no producer-supplied schedule or
//! effective-date fallback can supply a missing contractual due date.

use std::collections::BTreeMap;

use super::{
    MAX_REPORT_BUNDLE_BYTES, ReportError, VerifiedAgingAmounts, VerifiedAgingBand,
    VerifiedAgingCell, VerifiedAgingTotal, VerifiedOpenItem, VerifiedOpenItems, failed, hash_parts,
    metadata,
};
use crate::codec::{Reader, Writer};
use crate::envelope::Leg;

pub(super) const CERTIFICATE_FORMAT: &[u8] = b"fa:due-date-aging-certificate:v1";
const OUTPUT_FORMAT: &[u8] = b"fa:due-date-aging:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:due-date-aging-certificate-digest:v1";
const MAX_BOUNDS: usize = 128;
const MAX_TERMS: usize = 256;
const MAX_INSTALLMENTS: usize = 256;

pub(super) struct Certificate<'a> {
    pub source: &'a [u8],
    pub effective_through: i32,
    pub upper_bounds: Vec<u32>,
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDueDateAgedItem {
    pub item: VerifiedOpenItem,
    pub due_date: i32,
    /// Open amount of this installment, not the whole original leg.
    pub open: i128,
    pub days_past_due: u64,
    pub bucket: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifiedUnscheduled {
    NoTerms,
    MissingMaturity,
    Disputed { reason_code: u16 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedUnscheduledItem {
    pub item: VerifiedOpenItem,
    pub reason: VerifiedUnscheduled,
}

/// Contractual installments and explicitly unscheduled open items together
/// cover the historical open-item fold. Scheduled item counts count remaining
/// installment parts; unscheduled counts count original open items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDueDateAging {
    pub book_id: [u8; 16],
    pub known_at: u64,
    pub effective_through: i32,
    pub account_filter: Option<u128>,
    pub source_certificate_digest: [u8; 32],
    pub bands: Vec<VerifiedAgingBand>,
    pub items: Vec<VerifiedDueDateAgedItem>,
    pub cells: Vec<VerifiedAgingCell>,
    pub totals: Vec<VerifiedAgingTotal>,
    pub unscheduled: Vec<VerifiedUnscheduledItem>,
    pub unscheduled_totals: Vec<VerifiedAgingTotal>,
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    bytes.starts_with(&(CERTIFICATE_FORMAT.len() as u32).to_le_bytes())
        && bytes.get(4..4 + CERTIFICATE_FORMAT.len()) == Some(CERTIFICATE_FORMAT)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "due-date certificate exceeds 64 MiB",
        ));
    }
    let mut r = Reader::new(bytes);
    if r.bytes(64, "due_date.format")? != CERTIFICATE_FORMAT {
        return Err(failed(
            "supported_report",
            "unsupported due-date certificate",
        ));
    }
    r.u128("due_date.producer")?;
    r.fixed::<32>("due_date.capability_commitment")?;
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "due_date.source")?;
    let effective_through = r.i32("due_date.effective_through")?;
    let count = r.count(MAX_BOUNDS, 4, "due_date.bucket_bounds")?;
    let mut upper_bounds = Vec::with_capacity(count);
    for _ in 0..count {
        upper_bounds.push(r.u32("due_date.bucket_bound")?);
    }
    if !upper_bounds.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(failed(
            "aging_buckets",
            "bucket bounds must strictly increase",
        ));
    }
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "due_date.output")?;
    let digest = r.fixed("due_date.digest")?;
    r.finish("due-date certificate")?;
    let body = &bytes[..bytes.len() - 32];
    if hash_parts(DIGEST_DOMAIN, &[&(body.len() as u32).to_le_bytes(), body]) != digest {
        return Err(failed(
            "certificate_digest",
            "due-date certificate digest differs",
        ));
    }
    Ok(Certificate {
        source,
        effective_through,
        upper_bounds,
        output,
        digest,
    })
}

#[derive(Clone, Debug)]
struct Terms {
    unscheduled: Option<VerifiedUnscheduled>,
    installments: Vec<(i32, i128)>,
}

fn decode_terms(bytes: &[u8], legs: &[Leg]) -> Result<Vec<(u16, Terms)>, ReportError> {
    let mut r = Reader::new(bytes);
    if r.u16("maturity.version")? != 1 {
        return Err(failed(
            "obligation_terms",
            "unsupported maturity term version",
        ));
    }
    let count = r.count(MAX_TERMS, 7, "maturity.terms")?;
    if count == 0 {
        return Err(failed("obligation_terms", "empty maturity extension"));
    }
    let mut terms = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let ordinal = r.u16("maturity.ordinal")?;
        if previous.is_some_and(|previous| previous >= ordinal) {
            return Err(failed(
                "obligation_terms",
                "term ordinals are not strictly ordered",
            ));
        }
        previous = Some(ordinal);
        let leg = legs
            .get(usize::from(ordinal))
            .ok_or_else(|| failed("obligation_terms", "maturity terms name an absent leg"))?;
        if leg.debit || leg.mantissa <= 0 {
            return Err(failed(
                "obligation_terms",
                "maturity requires a positive credit leg",
            ));
        }
        let unscheduled = match r.u8("maturity.status")? {
            1 => None,
            2 => Some(VerifiedUnscheduled::Disputed {
                reason_code: r.u16("maturity.reason")?,
            }),
            3 => Some(VerifiedUnscheduled::MissingMaturity),
            _ => return Err(failed("obligation_terms", "unknown maturity status")),
        };
        let count = r.count(MAX_INSTALLMENTS, 20, "maturity.installments")?;
        if (unscheduled.is_none() && count == 0)
            || (unscheduled == Some(VerifiedUnscheduled::MissingMaturity) && count != 0)
        {
            return Err(failed(
                "obligation_terms",
                "maturity status and installments disagree",
            ));
        }
        let mut installments = Vec::with_capacity(count);
        let mut total = 0_i128;
        let mut previous_due = None;
        for _ in 0..count {
            let due = r.i32("maturity.due_date")?;
            let amount = r.i128("maturity.amount")?;
            if amount <= 0 || previous_due.is_some_and(|previous| previous >= due) {
                return Err(failed(
                    "obligation_terms",
                    "installments must be positive and date-ordered",
                ));
            }
            previous_due = Some(due);
            total = total.checked_add(amount).ok_or_else(|| {
                failed("exact_arithmetic", "maturity schedule total overflows i128")
            })?;
            installments.push((due, amount));
        }
        if !installments.is_empty() && total != leg.mantissa {
            return Err(failed(
                "obligation_terms",
                "installments do not cover the original leg exactly",
            ));
        }
        terms.push((
            ordinal,
            Terms {
                unscheduled,
                installments,
            },
        ));
    }
    r.finish("obligation maturity terms")?;
    Ok(terms)
}

fn add_amount(
    amounts: &mut VerifiedAgingAmounts,
    debit: bool,
    amount: i128,
) -> Result<(), ReportError> {
    let column = if debit {
        &mut amounts.debits
    } else {
        &mut amounts.credits
    };
    *column = column.checked_add(amount).ok_or_else(|| {
        failed(
            "exact_arithmetic",
            "due-date aging total exceeds signed 128-bit bounds",
        )
    })?;
    amounts.item_count = amounts
        .item_count
        .checked_add(1)
        .ok_or_else(|| failed("exact_arithmetic", "due-date aging item count overflow"))?;
    Ok(())
}

fn item_size(item: &VerifiedOpenItem) -> Result<usize, ReportError> {
    item.applications
        .len()
        .checked_mul(43)
        .and_then(|n| n.checked_add(16 + 2 + 16 + 4 + 1 + 4 + 8 + 64 + 4))
        .ok_or_else(|| failed("bounded_input", "due-date item history size overflow"))
}

fn charge(size: &mut usize, amount: usize) -> Result<(), ReportError> {
    *size = size
        .checked_add(amount)
        .filter(|size| *size <= MAX_REPORT_BUNDLE_BYTES)
        .ok_or_else(|| failed("bounded_input", "expanded due-date output exceeds 64 MiB"))?;
    Ok(())
}

pub(super) fn replay(
    certificate: &Certificate<'_>,
    book_id: [u8; 16],
    known_at: u64,
    source_certificate_digest: [u8; 32],
    snapshot: VerifiedOpenItems,
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    legs: &[Vec<Leg>],
) -> Result<(VerifiedDueDateAging, Vec<u8>), ReportError> {
    let mut terms = BTreeMap::new();
    for (&index, info) in infos {
        if let Some(bytes) = info.obligation_maturity {
            for (ordinal, term) in decode_terms(bytes, &legs[index])? {
                if terms.insert((info.identity, ordinal), term).is_some() {
                    return Err(failed("obligation_terms", "duplicate obligation identity"));
                }
            }
        }
    }
    let mut lower = 0;
    let mut bands = Vec::with_capacity(certificate.upper_bounds.len() + 1);
    for &upper in &certificate.upper_bounds {
        bands.push(VerifiedAgingBand {
            lower_inclusive: lower,
            upper_inclusive: Some(u64::from(upper)),
        });
        lower = u64::from(upper) + 1;
    }
    bands.push(VerifiedAgingBand {
        lower_inclusive: lower,
        upper_inclusive: None,
    });
    let mut items = Vec::new();
    let mut unscheduled = Vec::new();
    let mut cells: BTreeMap<(u128, u32, usize), VerifiedAgingAmounts> = BTreeMap::new();
    let mut totals: BTreeMap<(u128, u32), VerifiedAgingAmounts> = BTreeMap::new();
    let mut unscheduled_totals: BTreeMap<(u128, u32), VerifiedAgingAmounts> = BTreeMap::new();
    // Charge repeated histories before cloning them for installment rows.
    let mut projected_bytes = 0;
    for item in snapshot.items {
        let expected_open = item
            .original
            .checked_sub(item.applied_out)
            .and_then(|n| n.checked_sub(item.applied))
            .ok_or_else(|| failed("exact_arithmetic", "historical open amount overflow"))?;
        if item.original < 0
            || item.applied < 0
            || item.applied_out < 0
            || item.open < 0
            || item.open != expected_open
        {
            return Err(failed(
                "aging_open_amount",
                "historical applications exceed the open item",
            ));
        }
        if item.effective_date > certificate.effective_through {
            return Err(failed(
                "aging_effective_selection",
                "due-date aging includes a future-effective item",
            ));
        }
        if item.open == 0 {
            continue;
        }
        let term = terms.get(&(item.entry, item.ordinal));
        let reason = term.map_or(Some(VerifiedUnscheduled::NoTerms), |term| term.unscheduled);
        if let Some(reason) = reason {
            charge(&mut projected_bytes, item_size(&item)?)?;
            charge(
                &mut projected_bytes,
                1 + usize::from(matches!(reason, VerifiedUnscheduled::Disputed { .. })) * 4,
            )?;
            add_amount(
                unscheduled_totals
                    .entry((item.account, item.unit_id))
                    .or_default(),
                item.debit,
                item.open,
            )?;
            unscheduled.push(VerifiedUnscheduledItem { item, reason });
            continue;
        }
        let term =
            term.ok_or_else(|| failed("obligation_terms", "contractual terms are absent"))?;
        let mut relief = item
            .original
            .checked_sub(item.open)
            .ok_or_else(|| failed("exact_arithmetic", "installment relief overflow"))?;
        for &(due_date, amount) in &term.installments {
            let relieved = relief.min(amount);
            relief = relief
                .checked_sub(relieved)
                .ok_or_else(|| failed("exact_arithmetic", "installment relief underflow"))?;
            let open = amount
                .checked_sub(relieved)
                .ok_or_else(|| failed("exact_arithmetic", "installment open underflow"))?;
            if open == 0 {
                continue;
            }
            let days_past_due =
                u64::try_from(i64::from(certificate.effective_through) - i64::from(due_date))
                    .unwrap_or(0);
            let bucket = certificate
                .upper_bounds
                .partition_point(|upper| u64::from(*upper) < days_past_due);
            charge(&mut projected_bytes, item_size(&item)?)?;
            charge(&mut projected_bytes, 4 + 16 + 8 + 4)?;
            add_amount(
                cells
                    .entry((item.account, item.unit_id, bucket))
                    .or_default(),
                item.debit,
                open,
            )?;
            add_amount(
                totals.entry((item.account, item.unit_id)).or_default(),
                item.debit,
                open,
            )?;
            items.push(VerifiedDueDateAgedItem {
                item: item.clone(),
                due_date,
                open,
                days_past_due,
                bucket,
            });
        }
        if relief != 0 {
            return Err(failed(
                "obligation_terms",
                "applications exceed the contractual schedule",
            ));
        }
    }
    items.sort_by_key(|row| {
        (
            row.item.account,
            row.item.unit_id,
            row.bucket,
            row.due_date,
            row.item.effective_date,
            row.item.recorded_at,
            row.item.entry,
            row.item.ordinal,
        )
    });
    unscheduled.sort_by_key(|row| {
        (
            row.item.account,
            row.item.unit_id,
            row.item.effective_date,
            row.item.recorded_at,
            row.item.entry,
            row.item.ordinal,
        )
    });
    let totals_of = |totals: BTreeMap<(u128, u32), VerifiedAgingAmounts>| {
        totals
            .into_iter()
            .map(|((account, unit_id), amounts)| VerifiedAgingTotal {
                account,
                unit_id,
                amounts,
            })
            .collect()
    };
    let report = VerifiedDueDateAging {
        book_id,
        known_at,
        effective_through: certificate.effective_through,
        account_filter: snapshot.account_filter,
        source_certificate_digest,
        bands,
        items,
        cells: cells
            .into_iter()
            .map(|((account, unit_id, bucket), amounts)| VerifiedAgingCell {
                account,
                unit_id,
                bucket,
                amounts,
            })
            .collect(),
        totals: totals_of(totals),
        unscheduled,
        unscheduled_totals: totals_of(unscheduled_totals),
    };
    let output = encode(&report)?;
    if output != certificate.output {
        return Err(failed(
            "report_recomputation",
            "due dates, installment relief, unscheduled items, histories, bands or totals differ from independent replay",
        ));
    }
    Ok((report, output))
}

fn write_item(w: &mut Writer, item: &VerifiedOpenItem) {
    w.u128(item.entry)
        .u16(item.ordinal)
        .u128(item.account)
        .u32(item.unit_id)
        .u8(u8::from(!item.debit))
        .i32(item.effective_date)
        .u64(item.recorded_at)
        .i128(item.original)
        .i128(item.applied)
        .i128(item.applied_out)
        .i128(item.open)
        .count(item.applications.len());
    for application in &item.applications {
        w.u128(application.entry)
            .u16(application.ordinal)
            .i128(application.amount)
            .u64(application.recorded_at)
            .u8(u8::from(application.live));
    }
}

fn write_totals(w: &mut Writer, totals: &[VerifiedAgingTotal]) {
    w.count(totals.len());
    for total in totals {
        w.u128(total.account)
            .u32(total.unit_id)
            .i128(total.amounts.debits)
            .i128(total.amounts.credits)
            .u64(total.amounts.item_count);
    }
}

fn encode(report: &VerifiedDueDateAging) -> Result<Vec<u8>, ReportError> {
    let mut size = 4
        + OUTPUT_FORMAT.len()
        + 16
        + 8
        + 4
        + 1
        + usize::from(report.account_filter.is_some()) * 16
        + 6 * 4;
    for band in &report.bands {
        charge(
            &mut size,
            8 + 1 + usize::from(band.upper_inclusive.is_some()) * 8,
        )?;
    }
    for row in &report.items {
        charge(&mut size, item_size(&row.item)?)?;
        charge(&mut size, 4 + 16 + 8 + 4)?;
    }
    for row in &report.unscheduled {
        charge(&mut size, item_size(&row.item)?)?;
        charge(
            &mut size,
            1 + usize::from(matches!(row.reason, VerifiedUnscheduled::Disputed { .. })) * 4,
        )?;
    }
    for (count, width) in [
        (report.cells.len(), 64),
        (report.totals.len(), 60),
        (report.unscheduled_totals.len(), 60),
    ] {
        charge(
            &mut size,
            count
                .checked_mul(width)
                .ok_or_else(|| failed("bounded_input", "due-date output size overflow"))?,
        )?;
    }
    let mut w = Writer {
        buf: Vec::with_capacity(size),
    };
    w.bytes(OUTPUT_FORMAT)
        .fixed(&report.book_id)
        .u64(report.known_at)
        .i32(report.effective_through)
        .u8(u8::from(report.account_filter.is_some()));
    if let Some(account) = report.account_filter {
        w.u128(account);
    }
    w.count(report.bands.len());
    for band in &report.bands {
        w.u64(band.lower_inclusive)
            .u8(u8::from(band.upper_inclusive.is_some()));
        if let Some(upper) = band.upper_inclusive {
            w.u64(upper);
        }
    }
    w.count(report.items.len());
    for row in &report.items {
        write_item(&mut w, &row.item);
        w.i32(row.due_date)
            .i128(row.open)
            .u64(row.days_past_due)
            .u32(row.bucket as u32);
    }
    w.count(report.cells.len());
    for cell in &report.cells {
        w.u128(cell.account)
            .u32(cell.unit_id)
            .u32(cell.bucket as u32)
            .i128(cell.amounts.debits)
            .i128(cell.amounts.credits)
            .u64(cell.amounts.item_count);
    }
    write_totals(&mut w, &report.totals);
    w.count(report.unscheduled.len());
    for row in &report.unscheduled {
        write_item(&mut w, &row.item);
        match row.reason {
            VerifiedUnscheduled::NoTerms => {
                w.u8(0);
            }
            VerifiedUnscheduled::MissingMaturity => {
                w.u8(1);
            }
            VerifiedUnscheduled::Disputed { reason_code } => {
                w.u8(2).u32(u32::from(reason_code));
            }
        }
    }
    write_totals(&mut w, &report.unscheduled_totals);
    if w.buf.len() != size {
        return Err(failed(
            "canonical_encoding",
            "due-date output size differs from canonical fields",
        ));
    }
    Ok(w.buf)
}
