//! Effective-date aging derived from a fully authenticated OpenItems source.
//!
//! The all-effective source is verified first. Its entries are then selected
//! by the inclusive effective cutoff BEFORE reversal and settlement netting.
//! The cutoff and age bands belong to the outer certificate and require its
//! recipient pin or the signed bundle receipt. Ages are not contractual due
//! dates, and the saved producer/capability bytes do not grant current authority.

use super::{
    MAX_REPORT_BUNDLE_BYTES, ReportError, VerifiedOpenItem, VerifiedOpenItems, failed, hash_parts,
};
use crate::codec::{Reader, Writer};
use std::collections::BTreeMap;

pub(super) const CERTIFICATE_FORMAT: &[u8] = b"fa:aging-certificate:v1";
pub(super) const OUTPUT_FORMAT: &[u8] = b"fa:effective-date-aging:v1";
pub(super) const DIGEST_DOMAIN: &[u8] = b"fa:aging-certificate-digest:v1";
const MAX_BOUNDS: usize = 128;

pub(super) struct Certificate<'a> {
    pub source: &'a [u8],
    pub effective_through: i32,
    pub upper_bounds: Vec<u32>,
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAgingBand {
    pub lower_inclusive: u64,
    pub upper_inclusive: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifiedAgingAmounts {
    pub debits: i128,
    pub credits: i128,
    pub item_count: u64,
}

impl VerifiedAgingAmounts {
    fn add(&mut self, item: &VerifiedOpenItem) -> Result<(), ReportError> {
        let column = if item.debit {
            &mut self.debits
        } else {
            &mut self.credits
        };
        *column = column.checked_add(item.open).ok_or_else(|| {
            failed(
                "exact_arithmetic",
                "aging amount sum exceeds signed 128-bit bounds",
            )
        })?;
        self.item_count = self
            .item_count
            .checked_add(1)
            .ok_or_else(|| failed("exact_arithmetic", "aging item count overflow"))?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAgedOpenItem {
    pub item: VerifiedOpenItem,
    pub age_days: u64,
    pub bucket: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAgingCell {
    pub account: u128,
    pub unit_id: u32,
    pub bucket: usize,
    pub amounts: VerifiedAgingAmounts,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAgingTotal {
    pub account: u128,
    pub unit_id: u32,
    pub amounts: VerifiedAgingAmounts,
}

/// Exact age bands, item histories and separate native debit/credit totals.
/// No contractual due date or assertion that an item is overdue is inferred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAging {
    pub book_id: [u8; 16],
    pub known_at: u64,
    pub effective_through: i32,
    pub account_filter: Option<u128>,
    pub source_certificate_digest: [u8; 32],
    pub bands: Vec<VerifiedAgingBand>,
    pub items: Vec<VerifiedAgedOpenItem>,
    pub cells: Vec<VerifiedAgingCell>,
    pub totals: Vec<VerifiedAgingTotal>,
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    bytes.starts_with(&(CERTIFICATE_FORMAT.len() as u32).to_le_bytes())
        && bytes.get(4..4 + CERTIFICATE_FORMAT.len()) == Some(CERTIFICATE_FORMAT)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed("bounded_input", "aging certificate exceeds 64 MiB"));
    }
    let mut r = Reader::new(bytes);
    if r.bytes(64, "aging.format")? != CERTIFICATE_FORMAT {
        return Err(failed(
            "supported_report",
            "unsupported aging certificate format",
        ));
    }
    r.u128("aging.producer")?;
    r.fixed::<32>("aging.capability_commitment")?;
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "aging.source")?;
    let effective_through = r.i32("aging.effective_through")?;
    let count = r.count(MAX_BOUNDS, 4, "aging.bucket_bounds")?;
    let mut upper_bounds = Vec::with_capacity(count);
    for _ in 0..count {
        upper_bounds.push(r.u32("aging.bucket_bound")?);
    }
    if !upper_bounds.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(failed(
            "aging_buckets",
            "finite bucket bounds must be strictly increasing",
        ));
    }
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "aging.output")?;
    let digest = r.fixed("aging.digest")?;
    r.finish("aging certificate")?;
    let body = &bytes[..bytes.len() - 32];
    let body_len = (body.len() as u32).to_le_bytes();
    if hash_parts(DIGEST_DOMAIN, &[&body_len, body]) != digest {
        return Err(failed(
            "certificate_digest",
            "aging certificate bytes differ from their commitment",
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

pub(super) fn replay(
    certificate: &Certificate<'_>,
    book_id: [u8; 16],
    known_at: u64,
    source_certificate_digest: [u8; 32],
    snapshot: VerifiedOpenItems,
) -> Result<(VerifiedAging, Vec<u8>), ReportError> {
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
    let mut cells: BTreeMap<(u128, u32, usize), VerifiedAgingAmounts> = BTreeMap::new();
    let mut totals: BTreeMap<(u128, u32), VerifiedAgingAmounts> = BTreeMap::new();
    let mut items = Vec::new();
    for item in snapshot.items {
        let expected_open = item
            .original
            .checked_sub(item.applied_out)
            .and_then(|amount| amount.checked_sub(item.applied))
            .ok_or_else(|| failed("exact_arithmetic", "historical aging open amount overflow"))?;
        if item.original < 0
            || item.applied < 0
            || item.applied_out < 0
            || item.open < 0
            || item.open != expected_open
        {
            return Err(failed(
                "aging_open_amount",
                "historical selected applications exceed the item's open amount",
            ));
        }
        let age = i64::from(certificate.effective_through) - i64::from(item.effective_date);
        let age_days = u64::try_from(age).map_err(|_| {
            failed(
                "aging_effective_selection",
                "aging includes a future-effective item",
            )
        })?;
        if item.open == 0 {
            continue;
        }
        let bucket = certificate
            .upper_bounds
            .partition_point(|upper| u64::from(*upper) < age_days);
        cells
            .entry((item.account, item.unit_id, bucket))
            .or_default()
            .add(&item)?;
        totals
            .entry((item.account, item.unit_id))
            .or_default()
            .add(&item)?;
        items.push(VerifiedAgedOpenItem {
            item,
            age_days,
            bucket,
        });
    }
    items.sort_by_key(|row| {
        (
            row.item.account,
            row.item.unit_id,
            row.bucket,
            row.item.effective_date,
            row.item.recorded_at,
            row.item.entry,
            row.item.ordinal,
        )
    });
    let report = VerifiedAging {
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
        totals: totals
            .into_iter()
            .map(|((account, unit_id), amounts)| VerifiedAgingTotal {
                account,
                unit_id,
                amounts,
            })
            .collect(),
    };
    let output = encode(&report)?;
    if output != certificate.output {
        return Err(failed(
            "report_recomputation",
            "aging cutoff, bands, item/application histories, cells, totals or canonical bytes differ from independent replay",
        ));
    }
    Ok((report, output))
}

fn encode(report: &VerifiedAging) -> Result<Vec<u8>, ReportError> {
    // Account for the entire expanded projection before allocating its bytes.
    // A short source can expand into many history rows; no truncated schedule
    // or partially encoded output is a successful verification result.
    let mut size = 4
        + OUTPUT_FORMAT.len()
        + 16
        + 8
        + 4
        + 1
        + usize::from(report.account_filter.is_some()) * 16
        + 4 * 4;
    let mut add = |bytes: usize| -> Result<(), ReportError> {
        size = size
            .checked_add(bytes)
            .filter(|size| *size <= MAX_REPORT_BUNDLE_BYTES)
            .ok_or_else(|| failed("bounded_input", "expanded aging output exceeds 64 MiB"))?;
        Ok(())
    };
    for band in &report.bands {
        add(8 + 1 + usize::from(band.upper_inclusive.is_some()) * 8)?;
    }
    for aged in &report.items {
        add(16 + 2 + 16 + 4 + 1 + 4 + 8 + 64 + 4 + 8 + 4)?;
        add(aged
            .item
            .applications
            .len()
            .checked_mul(43)
            .ok_or_else(|| failed("bounded_input", "aging application count overflow"))?)?;
    }
    add(report
        .cells
        .len()
        .checked_mul(64)
        .ok_or_else(|| failed("bounded_input", "aging cell count overflow"))?)?;
    add(report
        .totals
        .len()
        .checked_mul(60)
        .ok_or_else(|| failed("bounded_input", "aging total count overflow"))?)?;
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
    for aged in &report.items {
        let item = &aged.item;
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
        w.u64(aged.age_days).u32(aged.bucket as u32);
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
    w.count(report.totals.len());
    for total in &report.totals {
        w.u128(total.account)
            .u32(total.unit_id)
            .i128(total.amounts.debits)
            .i128(total.amounts.credits)
            .u64(total.amounts.item_count);
    }
    if w.buf.len() != size {
        return Err(failed(
            "canonical_encoding",
            "aging output size differs from its canonical fields",
        ));
    }
    Ok(w.buf)
}
