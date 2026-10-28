//! Independent native lead schedules over a complete authenticated prefix.
//! Opening and closing are checked gross stock folds. Every posted movement
//! remains visible, including reversing and offsetting legs. Bucket labels
//! preserve recorded class, numeric reasons and Rule-origin version identity;
//! they do not assert an economic classification or successful rule execution.

use super::metadata::{EntryInfo, Schema};
use super::statement::Sum;
use super::{MAX_REPORT_BUNDLE_BYTES, ReportError, ReportRow, failed, hash_parts, text};
use crate::codec::{Reader, Writer};
use crate::envelope::{LeafEnvelope, Leg};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const CERTIFICATE_FORMAT: &[u8] = b"fa:roll-forward-certificate:v1";
pub(super) const DIGEST_DOMAIN: &[u8] = b"fa:roll-forward-certificate-digest:v1";
const OUTPUT_MAGIC: &[u8; 16] = b"FA-ROLL-FORWARD\0";
const MAX_SCOPE: usize = 4096;
const MAX_BUCKETS: usize = 256;
const MAX_VALUES: usize = 2_000_000;

pub(super) struct Certificate<'a> {
    pub source: &'a [u8],
    pub accounts: Vec<u128>,
    pub units: Vec<u32>,
    pub label: &'a str,
    pub effective_from: i32,
    pub effective_through: i32,
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollForwardAccount {
    pub id: u128,
    pub code: String,
    pub name: String,
    pub account_type: u8,
    pub is_leaf: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RollForwardBucket {
    pub class: u16,
    pub reason_code: String,
    pub rule_digest: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollForwardRow {
    pub account_id: u128,
    pub unit_id: u32,
    pub opening: i128,
    pub activity: Vec<i128>,
    pub net_change: i128,
    pub closing: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollForwardMovement {
    pub entry_digest: [u8; 32],
    pub leg_index: u32,
    pub recorded_seq: u64,
    pub effective_day: i32,
    pub account_id: u128,
    pub unit_id: u32,
    pub bucket: RollForwardBucket,
    pub debits: i128,
    pub credits: i128,
}

/// Complete native-unit lead schedule. Rows include every selected account
/// and unit, even when zero; movement citations include offsetting activity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRollForward {
    pub book_id: [u8; 16],
    pub known_at: u64,
    pub label: String,
    pub effective_from: i32,
    pub effective_through: i32,
    pub source_certificate_digest: [u8; 32],
    pub accounts: Vec<RollForwardAccount>,
    pub units: Vec<u32>,
    pub buckets: Vec<RollForwardBucket>,
    pub rows: Vec<RollForwardRow>,
    pub movements: Vec<RollForwardMovement>,
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    bytes.starts_with(&(CERTIFICATE_FORMAT.len() as u32).to_le_bytes())
        && bytes.get(4..4 + CERTIFICATE_FORMAT.len()) == Some(CERTIFICATE_FORMAT)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "roll-forward certificate exceeds 64 MiB",
        ));
    }
    let mut r = Reader::new(bytes);
    if r.bytes(64, "roll_forward.format")? != CERTIFICATE_FORMAT {
        return Err(failed(
            "supported_report",
            "unsupported roll-forward certificate format",
        ));
    }
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "roll_forward.source")?;
    let count = r.count(MAX_SCOPE, 16, "roll_forward.accounts")?;
    let mut accounts = Vec::with_capacity(count);
    for _ in 0..count {
        accounts.push(r.u128("roll_forward.account")?);
    }
    let count = r.count(MAX_SCOPE, 4, "roll_forward.units")?;
    let mut units = Vec::with_capacity(count);
    for _ in 0..count {
        units.push(r.u32("roll_forward.unit")?);
    }
    let label = text(&mut r, 256, "roll_forward.label")?;
    let effective_from = r.i32("roll_forward.effective_from")?;
    let effective_through = r.i32("roll_forward.effective_through")?;
    if accounts.is_empty()
        || units.is_empty()
        || !accounts.windows(2).all(|pair| pair[0] < pair[1])
        || !units.windows(2).all(|pair| pair[0] < pair[1])
        || label.trim().is_empty()
        || effective_from > effective_through
        || accounts
            .len()
            .checked_mul(units.len())
            .is_none_or(|n| n > 666_666)
    {
        return Err(failed(
            "roll_forward_selection",
            "roll-forward scope, label or dates are not canonical",
        ));
    }
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "roll_forward.output")?;
    let digest = r.fixed("roll_forward.digest")?;
    r.finish("roll-forward certificate")?;
    let body = &bytes[..bytes.len() - 32];
    if hash_parts(DIGEST_DOMAIN, &[&(body.len() as u32).to_le_bytes(), body]) != digest {
        return Err(failed(
            "certificate_digest",
            "roll-forward certificate bytes differ from their commitment",
        ));
    }
    Ok(Certificate {
        source,
        accounts,
        units,
        label,
        effective_from,
        effective_through,
        output,
        digest,
    })
}

fn overflow() -> ReportError {
    failed(
        "exact_arithmetic",
        "roll-forward amount exceeds its exact registered range",
    )
}

fn bucket(class: u16, info: &EntryInfo<'_>) -> Result<RollForwardBucket, ReportError> {
    let reasons: BTreeSet<_> = info.supersession_reasons.iter().copied().collect();
    let reason_code = if reasons.is_empty() {
        String::new()
    } else {
        format!(
            "supersession:{}",
            reasons
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    if reason_code.len() > 256 {
        return Err(failed(
            "bounded_output",
            "roll-forward reason set exceeds 256 bytes",
        ));
    }
    Ok(RollForwardBucket {
        class,
        reason_code,
        rule_digest: info.rule_version_oid,
    })
}

fn bucket_size(bucket: &RollForwardBucket) -> usize {
    7 + bucket.reason_code.len() + if bucket.rule_digest.is_some() { 32 } else { 0 }
}

fn charge(size: &mut usize, count: usize, width: usize, limit: usize) -> Result<(), ReportError> {
    *size = count
        .checked_mul(width)
        .and_then(|part| size.checked_add(part))
        .filter(|total| *total <= limit)
        .ok_or_else(|| {
            failed(
                "bounded_output",
                "complete roll-forward output exceeds its declared byte bound",
            )
        })?;
    Ok(())
}

/// The native as-of source has already been completely recomputed. Its
/// authenticated records and chart, not its claimed schedule, drive this fold.
#[allow(clippy::too_many_arguments)]
pub(super) fn replay(
    certificate: &Certificate<'_>,
    book_id: [u8; 16],
    known_at: u64,
    source_certificate_digest: [u8; 32],
    registered_units: &[u32],
    schema: &Schema,
    envelopes: &[LeafEnvelope],
    infos: &BTreeMap<usize, EntryInfo<'_>>,
    legs: &[Vec<Leg>],
    visible_migrations: &BTreeSet<u64>,
    source_rows: &[ReportRow],
) -> Result<(VerifiedRollForward, Vec<u8>), ReportError> {
    let (report, output) = recompute(
        certificate,
        book_id,
        known_at,
        source_certificate_digest,
        registered_units,
        schema,
        envelopes,
        infos,
        legs,
        visible_migrations,
        source_rows,
        certificate.output.len().min(MAX_REPORT_BUNDLE_BYTES),
    )?;
    if output != certificate.output {
        return Err(failed(
            "report_recomputation",
            "roll-forward scope, historical metadata, opening, classified movements, closing or exact citations differ from independent replay",
        ));
    }
    Ok((report, output))
}

/// Pure fold over an already authenticated native source. Indirect reports use
/// it to reconstruct their complete historical non-cash account population;
/// that scope comes from the authenticated chart, not delivered output bytes.
#[allow(clippy::too_many_arguments)]
pub(super) fn recompute(
    certificate: &Certificate<'_>,
    book_id: [u8; 16],
    known_at: u64,
    source_certificate_digest: [u8; 32],
    registered_units: &[u32],
    schema: &Schema,
    envelopes: &[LeafEnvelope],
    infos: &BTreeMap<usize, EntryInfo<'_>>,
    legs: &[Vec<Leg>],
    visible_migrations: &BTreeSet<u64>,
    source_rows: &[ReportRow],
    maximum_output: usize,
) -> Result<(VerifiedRollForward, Vec<u8>), ReportError> {
    if certificate
        .units
        .iter()
        .any(|unit| registered_units.binary_search(unit).is_err())
    {
        return Err(failed(
            "registry_closure",
            "roll-forward selects an unregistered native unit",
        ));
    }
    let mut size = 92 + certificate.label.len();
    let limit = maximum_output.min(MAX_REPORT_BUNDLE_BYTES);
    let mut accounts = Vec::with_capacity(certificate.accounts.len());
    for &id in &certificate.accounts {
        let account = schema.accounts.get(&id).ok_or_else(|| {
            failed(
                "account_metadata",
                "roll-forward account is absent at its recorded prefix",
            )
        })?;
        if !account.is_leaf || !(1..=5).contains(&account.account_type) {
            return Err(failed(
                "roll_forward_selection",
                "roll-forward requires monetary posting leaves",
            ));
        }
        charge(
            &mut size,
            1,
            26 + account.code.len() + account.name.len(),
            limit,
        )?;
        accounts.push(RollForwardAccount {
            id,
            code: account.code.clone(),
            name: account.name.clone(),
            account_type: account.account_type,
            is_leaf: account.is_leaf,
        });
    }
    charge(&mut size, certificate.units.len(), 4, limit)?;
    accounts.sort_by(|a, b| a.code.cmp(&b.code).then(a.id.cmp(&b.id)));
    let mut stocks: BTreeMap<(u128, u32), [i128; 4]> = BTreeMap::new();
    let mut movements = Vec::new();
    let mut buckets = BTreeSet::new();
    for (&index, info) in infos {
        let entry = &envelopes[index];
        if entry.class == 2
            || legs[index].is_empty()
            || (entry.class == 12 && !visible_migrations.contains(&(index as u64)))
        {
            continue;
        }
        let effective_day = entry
            .effective_day
            .ok_or_else(|| failed("report_selector", "posted movement has no effective date"))?;
        if effective_day > certificate.effective_through {
            continue;
        }
        let selected = effective_day >= certificate.effective_from;
        let mut classification = None;
        for (ordinal, leg) in legs[index].iter().enumerate() {
            if certificate.accounts.binary_search(&leg.account).is_err()
                || certificate.units.binary_search(&leg.unit).is_err()
            {
                continue;
            }
            if leg.mantissa < 0 {
                return Err(failed(
                    "exact_arithmetic",
                    "roll-forward leg has a negative mantissa",
                ));
            }
            let cell = stocks.entry((leg.account, leg.unit)).or_insert([0; 4]);
            let side = usize::from(!leg.debit);
            cell[side + 2] = cell[side + 2]
                .checked_add(leg.mantissa)
                .ok_or_else(overflow)?;
            if !selected {
                cell[side] = cell[side].checked_add(leg.mantissa).ok_or_else(overflow)?;
                continue;
            }
            if leg.mantissa == 0 {
                continue;
            }
            if classification.is_none() {
                classification = Some(bucket(entry.class, info)?);
            }
            let bucket = classification
                .as_ref()
                .expect("selected movement has a bucket");
            charge(&mut size, 1, 100 + bucket_size(bucket), limit)?;
            buckets.insert(bucket.clone());
            if buckets.len() > MAX_BUCKETS || movements.len() == MAX_VALUES {
                return Err(failed(
                    "bounded_output",
                    "roll-forward movement or classification bound exceeded",
                ));
            }
            movements.push(RollForwardMovement {
                entry_digest: entry.record_digest,
                leg_index: u32::try_from(ordinal)
                    .map_err(|_| failed("bounded_output", "movement ordinal overflow"))?,
                recorded_seq: entry.commit_seq,
                effective_day,
                account_id: leg.account,
                unit_id: leg.unit,
                bucket: bucket.clone(),
                debits: if leg.debit { leg.mantissa } else { 0 },
                credits: if leg.debit { 0 } else { leg.mantissa },
            });
        }
    }
    accounts
        .len()
        .checked_mul(certificate.units.len())
        .and_then(|cells| cells.checked_mul(buckets.len() + 3))
        .filter(|values| *values <= MAX_VALUES)
        .ok_or_else(|| {
            failed(
                "bounded_output",
                "roll-forward expanded scope exceeds two million amounts",
            )
        })?;
    let buckets: Vec<_> = buckets.into_iter().collect();
    for bucket in &buckets {
        charge(&mut size, 1, bucket_size(bucket), limit)?;
    }
    let cells = accounts.len() * certificate.units.len();
    charge(&mut size, cells, 72 + buckets.len() * 16, limit)?;
    let indexes: BTreeMap<_, _> = buckets
        .iter()
        .enumerate()
        .map(|(i, bucket)| (bucket, i))
        .collect();
    let mut activity: BTreeMap<(u128, u32), Vec<Sum>> = BTreeMap::new();
    for movement in &movements {
        let sums = activity
            .entry((movement.account_id, movement.unit_id))
            .or_insert_with(|| vec![Sum::default(); buckets.len()]);
        let sum = &mut sums[indexes[&movement.bucket]];
        sum.add(movement.debits, false).ok_or_else(overflow)?;
        sum.add(movement.credits, true).ok_or_else(overflow)?;
    }
    let closing: BTreeMap<_, _> = source_rows
        .iter()
        .map(|row| ((row.account, row.unit), (row.debits, row.credits)))
        .collect();
    let mut rows = Vec::with_capacity(cells);
    for account in &accounts {
        for &unit in &certificate.units {
            let key = (account.id, unit);
            let stock = stocks.get(&key).copied().unwrap_or([0; 4]);
            if closing.get(&key).copied().unwrap_or((0, 0)) != (stock[2], stock[3]) {
                return Err(failed(
                    "roll_forward_source",
                    "closing gross stock differs from the verified native source",
                ));
            }
            let opening = stock[0].checked_sub(stock[1]).ok_or_else(overflow)?;
            let closing = stock[2].checked_sub(stock[3]).ok_or_else(overflow)?;
            let amounts = (0..buckets.len())
                .map(|index| {
                    activity
                        .get(&key)
                        .map_or(Some(0), |sums| sums[index].value())
                        .ok_or_else(overflow)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut net = Sum::default();
            for &amount in &amounts {
                net.add(amount, false).ok_or_else(overflow)?;
            }
            let net_change = net.value().ok_or_else(overflow)?;
            net.add(opening, false).ok_or_else(overflow)?;
            net.add(closing, true).ok_or_else(overflow)?;
            if net.value().ok_or_else(overflow)? != 0 {
                return Err(failed(
                    "roll_forward_identity",
                    "opening plus complete classified movement does not equal closing",
                ));
            }
            rows.push(RollForwardRow {
                account_id: account.id,
                unit_id: unit,
                opening,
                activity: amounts,
                net_change,
                closing,
            });
        }
    }
    movements.sort_by_key(|movement| {
        (
            movement.recorded_seq,
            movement.entry_digest,
            movement.leg_index,
        )
    });
    let report = VerifiedRollForward {
        book_id,
        known_at,
        label: certificate.label.to_string(),
        effective_from: certificate.effective_from,
        effective_through: certificate.effective_through,
        source_certificate_digest,
        accounts,
        units: certificate.units.clone(),
        buckets,
        rows,
        movements,
    };
    let output = encode(&report, size);
    Ok((report, output))
}

fn write_bucket(w: &mut Writer, bucket: &RollForwardBucket) {
    w.u16(bucket.class)
        .bytes(bucket.reason_code.as_bytes())
        .u8(u8::from(bucket.rule_digest.is_some()));
    if let Some(digest) = bucket.rule_digest {
        w.fixed(&digest);
    }
}

fn encode(report: &VerifiedRollForward, size: usize) -> Vec<u8> {
    let mut w = Writer {
        buf: Vec::with_capacity(size),
    };
    w.fixed(OUTPUT_MAGIC)
        .u16(1)
        .u16(0)
        .fixed(&report.book_id)
        .fixed(&[0; 16])
        .u64(report.known_at)
        .bytes(report.label.as_bytes())
        .i32(report.effective_from)
        .i32(report.effective_through)
        .count(report.accounts.len());
    for account in &report.accounts {
        w.u128(account.id)
            .bytes(account.code.as_bytes())
            .bytes(account.name.as_bytes())
            .u8(account.account_type)
            .u8(u8::from(account.is_leaf));
    }
    w.count(report.units.len());
    for &unit in &report.units {
        w.u32(unit);
    }
    w.count(report.buckets.len());
    for bucket in &report.buckets {
        write_bucket(&mut w, bucket);
    }
    w.count(report.rows.len());
    for row in &report.rows {
        w.u128(row.account_id)
            .u32(row.unit_id)
            .i128(row.opening)
            .count(row.activity.len());
        for &amount in &row.activity {
            w.i128(amount);
        }
        w.i128(row.net_change).i128(row.closing);
    }
    w.count(report.movements.len());
    for movement in &report.movements {
        w.fixed(&movement.entry_digest)
            .u32(movement.leg_index)
            .u64(movement.recorded_seq)
            .i32(movement.effective_day)
            .u128(movement.account_id)
            .u32(movement.unit_id);
        write_bucket(&mut w, &movement.bucket);
        w.i128(movement.debits).i128(movement.credits);
    }
    debug_assert_eq!(w.buf.len(), size);
    w.buf
}
