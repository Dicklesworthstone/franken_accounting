//! Independent recomputation of native trial-balance certificates (plan §13.3).
//!
//! Report bundles disclose the complete signed checkpoint prefix, including
//! every payload that derives its selectors. The verifier reconstructs the
//! certificate's older entries-only prefix, journaled chart and fiscal periods,
//! migration visibility, and pending resolutions before comparing every output
//! byte. Native database read attestations are retained, but are not an outsider
//! proof and never supply the arithmetic or metadata used here.
//!
//! Version 1 supports sequence-selected native trial balances (as-of, stock by
//! period, and period activity). Instant selections and statement certificates
//! are refused. It proves accounting recomputation, not economic truth, unit
//! display labels, source-document authenticity, or database read attestations.

mod metadata;
#[cfg(test)]
mod tests;

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use crate::blake3::hash_parts;
use crate::bundle::ReceiptFacts;
use crate::checkpoint::{SignedCheckpoint, verify_checkpoint};
use crate::codec::{DecodeError, Reader, Writer};
use crate::envelope::{KIND_ENTRY, MAX_RECORD_BYTES, check_record};
use crate::proof::{Checkpoint, VerifyError, verify_prefix};
use crate::tree::{leaf_hash, root_of};

pub const REPORT_BUNDLE_FORMAT: &[u8] = b"fa:report-bundle:v1";
pub const MAX_REPORT_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
const CERTIFICATE_FORMAT: &[u8; 24] = b"fa:report-certificate:v1";
const OUTPUT_FORMAT: &[u8; 19] = b"fa:trial-balance:v1";
const MAX_ROWS: usize = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportError {
    /// The failed predicate, suitable for machine-readable verification output.
    pub predicate: &'static str,
    pub detail: String,
}
impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.predicate, self.detail)
    }
}
impl core::error::Error for ReportError {}
impl From<DecodeError> for ReportError {
    fn from(error: DecodeError) -> Self {
        failed("canonical_encoding", error.to_string())
    }
}
impl From<VerifyError> for ReportError {
    fn from(error: VerifyError) -> Self {
        failed("authenticated_prefix", error.to_string())
    }
}
fn failed(predicate: &'static str, detail: impl Into<String>) -> ReportError {
    ReportError {
        predicate,
        detail: detail.into(),
    }
}

/// Each row is independently reconstructed from authenticated entry payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportRow {
    pub account: u128,
    pub code: String,
    pub name: String,
    pub account_type: u8,
    pub unit: u32,
    pub debits: i128,
    pub credits: i128,
    pub debits_pending: i128,
    pub credits_pending: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReport {
    pub scope: &'static str,
    pub bundle_digest: [u8; 32],
    pub certificate_digest: [u8; 32],
    pub output_digest: [u8; 32],
    pub checkpoint: SignedCheckpoint,
    pub known_at: u64,
    pub effective_through: Option<i32>,
    pub activity: bool,
    pub periods: Vec<String>,
    pub rows: Vec<ReportRow>,
    /// Exact canonical report bytes, independently reconstructed.
    pub output: Vec<u8>,
    pub checked_records: usize,
    pub receipt: Option<ReceiptFacts>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Selection {
    Periods(Vec<String>),
    AsOf(i32),
    Activity(Vec<String>),
}
struct Certificate<'a> {
    book: [u8; 16],
    branch: [u8; 16],
    known_at: u64,
    selection: Selection,
    journal_root: [u8; 32],
    leaves: u64,
    output: &'a [u8],
    output_digest: [u8; 32],
    digest: [u8; 32],
}
fn text<'a>(r: &mut Reader<'a>, max: usize, field: &'static str) -> Result<&'a str, ReportError> {
    std::str::from_utf8(r.bytes(max, field)?)
        .map_err(|_| failed("canonical_encoding", format!("{field} is not UTF-8")))
}
fn strings(r: &mut Reader<'_>, field: &'static str) -> Result<Vec<String>, ReportError> {
    let n = r.count(65_536, 4, field)?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(text(r, 128, field)?.to_string());
    }
    if out.iter().any(String::is_empty) || !out.windows(2).all(|p| p[0] < p[1]) {
        return Err(failed(
            "canonical_encoding",
            "period codes must be nonempty and strictly ordered",
        ));
    }
    Ok(out)
}
fn certificate(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    let mut r = Reader::new(bytes);
    if &r.fixed::<24>("certificate.format")? != CERTIFICATE_FORMAT {
        return Err(failed(
            "supported_report",
            "expected a sequence-selected v1 native trial-balance certificate",
        ));
    }
    for (field, expected) in [
        ("certificate.scope", "fa-fold-over-prefix"),
        ("certificate.authority", "embedded-owner"),
        ("certificate.output_format", "fa:trial-balance:v1"),
    ] {
        if text(&mut r, 64, field)? != expected {
            return Err(failed("supported_report", field));
        }
    }
    let book = r.fixed("certificate.book")?;
    let branch = r.fixed("certificate.branch")?;
    let known_at = r.u64("certificate.known_at")?;
    let selection = match r.u8("certificate.selector")? {
        0 => Selection::Periods(strings(&mut r, "certificate.periods")?),
        1 => Selection::AsOf(r.i32("certificate.as_of")?),
        2 => Selection::Activity(strings(&mut r, "certificate.periods")?),
        _ => return Err(failed("supported_report", "unknown trial-balance selector")),
    };
    if matches!(&selection, Selection::Periods(p) | Selection::Activity(p) if p.is_empty()) {
        return Err(failed("report_selector", "period selection is empty"));
    }
    r.fixed::<32>("certificate.registry_digest")?;
    let journal_root = r.fixed("certificate.journal_root")?;
    let leaves = r.u64("certificate.leaves")?;
    let inputs = r.count(7, 4, "certificate.native_inputs")?;
    if inputs != 7 {
        return Err(failed(
            "certificate_closure",
            "certificate must retain all seven native input attestations",
        ));
    }
    for _ in 0..inputs {
        r.bytes(1024 * 1024, "certificate.native_input")?;
    }
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "certificate.output")?;
    let output_digest = r.fixed("certificate.output_digest")?;
    let digest = r.fixed("certificate.digest")?;
    r.finish("report certificate")?;
    if hash_parts(b"fa:report-output:v1", &[output]) != output_digest {
        return Err(failed(
            "output_digest",
            "certificate output differs from its commitment",
        ));
    }
    if hash_parts(CERTIFICATE_FORMAT, &[&bytes[..bytes.len() - 32]]) != digest {
        return Err(failed(
            "certificate_digest",
            "certificate bytes differ from their commitment",
        ));
    }
    Ok(Certificate {
        book,
        branch,
        known_at,
        selection,
        journal_root,
        leaves,
        output,
        output_digest,
        digest,
    })
}

/// Verify an offline report against recipient-owned keys and, when supplied,
/// an exact independently selected checkpoint. An optional detached receipt is
/// verified over this report bundle's digest using those same trusted keys.
/// An embedded checkpoint is never a trust anchor merely because it is present.
pub fn verify_report(
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    expected_checkpoint: Option<&Checkpoint>,
    receipt: Option<&[u8]>,
) -> Result<VerifiedReport, ReportError> {
    verify_report_with(
        bundle,
        trusted_keys,
        expected_checkpoint,
        receipt,
        verify_checkpoint,
    )
}

fn verify_report_with(
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    expected_checkpoint: Option<&Checkpoint>,
    receipt: Option<&[u8]>,
    authenticate: impl FnOnce(&[u8], &[[u8; 32]]) -> Result<SignedCheckpoint, VerifyError>,
) -> Result<VerifiedReport, ReportError> {
    if bundle.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed("bounded_input", "report bundle exceeds 64 MiB"));
    }
    let mut r = Reader::new(bundle);
    if r.bytes(64, "report_bundle.format")? != REPORT_BUNDLE_FORMAT
        || r.u16("report_bundle.major")? != 1
        || r.u16("report_bundle.minor")? != 0
    {
        return Err(failed(
            "supported_report",
            "unsupported report bundle format",
        ));
    }
    let cert = certificate(r.bytes(MAX_REPORT_BUNDLE_BYTES, "report_bundle.certificate")?)?;
    let signed_bytes = r.bytes(1024 * 1024, "report_bundle.checkpoint")?;
    let signed = authenticate(signed_bytes, trusted_keys)
        .map_err(|e| failed("checkpoint_signature", e.to_string()))?;
    if expected_checkpoint.is_some_and(|expected| *expected != signed.checkpoint) {
        return Err(failed(
            "recipient_checkpoint",
            "bundle uses another checkpoint than the recipient requested",
        ));
    }
    let anchor = &signed.checkpoint;
    if cert.branch != [0; 16]
        || (cert.book, cert.branch) != (anchor.book_id, anchor.branch_id)
        || cert.known_at > anchor.through_seq
    {
        return Err(failed(
            "report_coordinate",
            "report coordinate is outside the authenticated checkpoint prefix",
        ));
    }
    let prefix = verify_prefix(
        r.bytes(MAX_REPORT_BUNDLE_BYTES, "report_bundle.prefix")?,
        anchor,
    )?;
    let n = r.count(MAX_ROWS, 8, "report_bundle.records")?;
    if n != prefix.envelopes.len() {
        return Err(failed(
            "record_completeness",
            "every checkpoint leaf must have exactly one payload",
        ));
    }
    let mut records = Vec::with_capacity(n);
    let mut legs = Vec::with_capacity(n);
    for envelope in &prefix.envelopes {
        let len = r.u32("record.proposal_len")? as usize;
        let payload = r.bytes(MAX_RECORD_BYTES, "record.payload")?;
        legs.push(
            check_record(envelope, payload, len)
                .map_err(|e| failed("record_derivation", format!("{e:?}")))?,
        );
        records.push((len, payload));
    }
    let n = r.count(records.len(), 12, "report_bundle.migrations")?;
    let mut bodies = Vec::with_capacity(n);
    for _ in 0..n {
        bodies.push((
            r.u64("migration.open_index")?,
            r.bytes(MAX_RECORD_BYTES, "migration.body")?,
        ));
    }
    r.finish("report bundle")?;
    let digest = hash_parts(REPORT_BUNDLE_FORMAT, &[bundle]);
    let receipt = receipt
        .map(|raw| {
            crate::bundle::receipt_grade(raw, &digest, trusted_keys)
                .map_err(|e| failed("production_receipt", e))
        })
        .transpose()?;
    let envelopes = &prefix.envelopes;
    let mut hashes = Vec::new();
    let mut last_seq = None;
    let mut ordinal = 0u32;
    for e in envelopes
        .iter()
        .filter(|e| e.kind == KIND_ENTRY && e.commit_seq <= cert.known_at)
    {
        if last_seq != Some(e.commit_seq) {
            ordinal = 0;
            last_seq = Some(e.commit_seq);
        }
        let mut historical = e.clone();
        historical.within_commit_ordinal = ordinal;
        ordinal = ordinal
            .checked_add(1)
            .ok_or_else(|| failed("historical_prefix", "entry ordinal overflow"))?;
        hashes.push(leaf_hash(&historical.encode()));
    }
    if hashes.len() as u64 != cert.leaves || root_of(&hashes) != cert.journal_root {
        return Err(failed(
            "historical_prefix",
            "the authenticated entries at known-at do not reproduce the certificate's journal root",
        ));
    }
    let visible_migrations =
        crate::migration_balance::report_visibility(envelopes, &records, &bodies, cert.known_at)
            .map_err(|e| failed("migration_visibility", e.to_string()))?;
    let mut schema = metadata::Schema::default();
    let mut infos = BTreeMap::new();
    let mut by_digest = BTreeMap::new();
    for (index, (envelope, (len, payload))) in envelopes.iter().zip(&records).enumerate() {
        if envelope.kind != KIND_ENTRY || envelope.commit_seq > cert.known_at {
            continue;
        }
        let info = metadata::entry_info(&payload[..*len], envelope)?;
        if let Some((kind, body)) = info.schema {
            schema.apply(kind, body, &cert.book)?;
        }
        if by_digest.insert(envelope.record_digest, index).is_some() {
            return Err(failed(
                "entry_identity",
                "duplicate entry digest in the prefix",
            ));
        }
        infos.insert(index, info);
    }
    let (periods, through, activity) = schema.selection(&cert.selection)?;
    let mut resolved = BTreeSet::new();
    for (index, info) in &infos {
        let e = &envelopes[*index];
        if e.class != 3 {
            continue;
        }
        let target = info
            .resolution
            .ok_or_else(|| failed("pending_resolution", "resolution lacks a pending target"))?;
        let target_index = *by_digest
            .get(&target.1)
            .ok_or_else(|| failed("pending_resolution", "pending target is missing"))?;
        let original = &envelopes[target_index];
        if original.class != 2
            || original.commit_seq >= e.commit_seq
            || infos[&target_index].identity != target.0
            || !resolved.insert(target_index)
        {
            return Err(failed(
                "pending_resolution",
                "invalid or duplicate pending resolution",
            ));
        }
    }
    let mut sums: BTreeMap<(u128, u32), [i128; 4]> = BTreeMap::new();
    for (index, info) in &infos {
        let e = &envelopes[*index];
        if legs[*index].is_empty()
            || (e.class == 2 && resolved.contains(index))
            || (e.class == 12 && !visible_migrations.contains(&(*index as u64)))
        {
            continue;
        }
        let effective = e
            .effective_day
            .ok_or_else(|| failed("report_selector", "monetary entry has no effective date"))?;
        let selected = match through {
            Some(cutoff) => effective <= cutoff,
            None => periods
                .binary_search(&schema.entry_period(info, effective)?)
                .is_ok(),
        };
        if !selected {
            continue;
        }
        for leg in &legs[*index] {
            if leg.mantissa < 0 {
                return Err(failed("exact_arithmetic", "a leg has a negative mantissa"));
            }
            let columns = sums.entry((leg.account, leg.unit)).or_insert([0; 4]);
            let column = usize::from(!leg.debit) + if e.class == 2 { 2 } else { 0 };
            columns[column] = columns[column]
                .checked_add(leg.mantissa)
                .ok_or_else(|| failed("exact_arithmetic", "trial balance column overflow"))?;
        }
    }
    let mut rows = Vec::with_capacity(sums.len());
    let mut totals: BTreeMap<u32, [i128; 4]> = BTreeMap::new();
    for ((account, unit), values) in sums {
        let a = schema.accounts.get(&account).ok_or_else(|| {
            failed(
                "account_metadata",
                format!("account {account:032x} has no authenticated chart declaration"),
            )
        })?;
        if a.account_type <= 5 {
            let t = totals.entry(unit).or_insert([0; 4]);
            for i in 0..4 {
                t[i] = t[i]
                    .checked_add(values[i])
                    .ok_or_else(|| failed("exact_arithmetic", "unit total overflow"))?;
            }
        }
        rows.push(ReportRow {
            account,
            code: a.code.clone(),
            name: a.name.clone(),
            account_type: a.account_type,
            unit,
            debits: values[0],
            credits: values[1],
            debits_pending: values[2],
            credits_pending: values[3],
        });
    }
    rows.sort_by(|a, b| a.code.cmp(&b.code).then(a.unit.cmp(&b.unit)));
    if totals.values().any(|t| t[0] != t[1] || t[2] != t[3]) {
        return Err(failed(
            "monetary_footing",
            "posted or pending monetary totals do not balance",
        ));
    }
    let output = output(&periods, cert.known_at, through, activity, &rows, &totals);
    if output != cert.output {
        return Err(failed(
            "report_recomputation",
            mismatch(&rows, cert.output)?,
        ));
    }
    Ok(VerifiedReport {
        scope: "recomputation",
        bundle_digest: digest,
        certificate_digest: cert.digest,
        output_digest: cert.output_digest,
        checkpoint: signed,
        known_at: cert.known_at,
        effective_through: through,
        activity,
        periods,
        rows,
        output,
        checked_records: records.len(),
        receipt,
    })
}

fn output(
    periods: &[String],
    known_at: u64,
    through: Option<i32>,
    activity: bool,
    rows: &[ReportRow],
    totals: &BTreeMap<u32, [i128; 4]>,
) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(OUTPUT_FORMAT).count(periods.len());
    for p in periods {
        w.bytes(p.as_bytes());
    }
    w.u64(known_at).u8(u8::from(through.is_some()));
    if let Some(day) = through {
        w.i32(day);
    }
    w.u8(u8::from(activity)).count(rows.len());
    for row in rows {
        w.u128(row.account)
            .bytes(row.code.as_bytes())
            .bytes(row.name.as_bytes())
            .u8(row.account_type)
            .u32(row.unit)
            .i128(row.debits)
            .i128(row.credits)
            .i128(row.debits_pending)
            .i128(row.credits_pending);
    }
    for start in [0, 2] {
        w.count(totals.len());
        for (unit, values) in totals {
            w.u32(*unit).i128(values[start]).i128(values[start + 1]);
        }
    }
    w.buf
}

fn mismatch(rows: &[ReportRow], expected: &[u8]) -> Result<String, ReportError> {
    let mut r = Reader::new(expected);
    if &r.fixed::<19>("output.format")? != OUTPUT_FORMAT {
        return Ok("unknown trial balance output format".into());
    }
    strings(&mut r, "output.periods")?;
    r.u64("output.known_at")?;
    if r.present("output.through")? {
        r.i32("output.through")?;
    }
    r.present("output.activity")?;
    let n = r.count(MAX_ROWS, 16 + 4 + 4 + 1 + 4 + 64, "output.rows")?;
    if n != rows.len() {
        return Ok(format!(
            "expected {} complete rows, certificate contains {n}",
            rows.len()
        ));
    }
    for row in rows {
        let claimed = ReportRow {
            account: r.u128("row.account")?,
            code: text(&mut r, 64, "row.code")?.into(),
            name: text(&mut r, MAX_RECORD_BYTES, "row.name")?.into(),
            account_type: r.u8("row.type")?,
            unit: r.u32("row.unit")?,
            debits: r.i128("row.debits")?,
            credits: r.i128("row.credits")?,
            debits_pending: r.i128("row.debits_pending")?,
            credits_pending: r.i128("row.credits_pending")?,
        };
        if claimed != *row {
            return Ok(format!(
                "account {} unit {} differs: independently computed posted ({}, {}), pending ({}, {}) with authenticated labels",
                row.code,
                row.unit,
                row.debits,
                row.credits,
                row.debits_pending,
                row.credits_pending
            ));
        }
    }
    Ok(
        "report coordinate, unit totals, or canonical bytes differ from the independent fold"
            .into(),
    )
}
