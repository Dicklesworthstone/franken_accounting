//! Independent external-feed reconciliation over the complete journal prefix.
//!
//! Retained detail is authenticated through its original summary entry and
//! Workpaper commitment. Import/review records bind the cited identities and
//! chronology. Native graph mirrors, security admission, actual reviewer
//! independence and completeness of the external source system are unjudged.

mod population;
mod source;

pub use population::ExternalFeedManifest;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use super::{
    MAX_REPORT_BUNDLE_BYTES, ReportError, ReportRow, Selection, failed, hash_parts, metadata, text,
};
use crate::codec::{Reader, Writer};
use crate::envelope::{LeafEnvelope, Leg, LegDetails, proposal_leg_details};

const CERTIFICATE_FORMAT: &[u8] = b"fa:external-feed-certificate:v1";
const CERTIFICATE_DIGEST: &[u8] = b"fa:external-feed-certificate-digest:v1";
const OUTPUT_FORMAT: &[u8] = b"fa:external-feed-reconciliation:v1";
const MAX_REPORT_LEGS: usize = 100_000;

/// The recipient's independently selected question, including a fixed prefix.
/// Never construct this by copying fields from the certificate being checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalFeedRequest {
    pub feed: String,
    pub control_account: u128,
    pub effective_through: i32,
    pub known_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedExternalFeedSummaryLeg {
    pub account: u128,
    pub unit: u32,
    pub credit: bool,
    pub amount: i128,
    pub dimension_set: Vec<(u32, u128)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedExternalFeedBatch {
    pub entry: u128,
    pub entry_digest: [u8; 32],
    pub recorded_at: u64,
    pub feed: String,
    pub batch_key: String,
    pub effective_date: i32,
    pub document_oid: [u8; 32],
    pub doc_commit: [u8; 32],
    pub evidence_role: u8,
    pub review_attestation: u128,
    pub reviewer: u128,
    pub detail_rows: usize,
    pub summary_legs: Vec<VerifiedExternalFeedSummaryLeg>,
    pub reconciled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedExternalFeedContribution {
    pub entry: u128,
    pub entry_digest: [u8; 32],
    pub source: u128,
    pub source_digest: [u8; 32],
    pub recorded_at: u64,
    pub effective_date: i32,
    pub reversed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedExternalFeedLeg {
    pub entry: u128,
    pub entry_digest: [u8; 32],
    pub ordinal: u32,
    pub unit: u32,
    pub credit: bool,
    pub amount: i128,
    pub dimension_set: Vec<(u32, u128)>,
    pub pending: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedExternalFeedRow {
    pub unit_id: u32,
    pub dimension_set: Vec<(u32, u128)>,
    pub detail_debits: i128,
    pub detail_credits: i128,
    pub control_debits: i128,
    pub control_credits: i128,
    pub pending_debits: i128,
    pub pending_credits: i128,
}

impl VerifiedExternalFeedRow {
    fn columns(&self) -> [i128; 6] {
        [
            self.detail_debits,
            self.detail_credits,
            self.control_debits,
            self.control_credits,
            self.pending_debits,
            self.pending_credits,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedExternalFeedTotal {
    pub unit_id: u32,
    pub detail_debits: i128,
    pub detail_credits: i128,
    pub control_debits: i128,
    pub control_credits: i128,
    pub pending_debits: i128,
    pub pending_credits: i128,
    pub register_debits: i128,
    pub register_credits: i128,
    pub register_debits_pending: i128,
    pub register_credits_pending: i128,
}

/// Exact gross source/control reconciliation; an unreconciled report is a
/// valid verified result when it faithfully exposes uncovered or pending legs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedExternalFeed {
    pub book_id: [u8; 16],
    pub known_at: u64,
    pub effective_through: i32,
    pub source_certificate_digest: [u8; 32],
    pub feed: String,
    pub control_account: u128,
    pub batches: Vec<VerifiedExternalFeedBatch>,
    pub contributions: Vec<VerifiedExternalFeedContribution>,
    pub unattributed: Vec<VerifiedExternalFeedLeg>,
    pub rows: Vec<VerifiedExternalFeedRow>,
    pub totals: Vec<VerifiedExternalFeedTotal>,
    pub reconciled: bool,
}

pub(super) struct Certificate<'a> {
    pub source: &'a [u8],
    pub request: ExternalFeedRequest,
    pub registry_digest: [u8; 32],
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

fn invalid(detail: impl Into<String>) -> ReportError {
    failed("external_feed_source", detail)
}

fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
}

fn framed_digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut w = Writer::default();
    for part in parts {
        w.bytes(part);
    }
    hash_parts(domain, &[&w.buf])
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    bytes.starts_with(&(CERTIFICATE_FORMAT.len() as u32).to_le_bytes())
        && bytes.get(4..4 + CERTIFICATE_FORMAT.len()) == Some(CERTIFICATE_FORMAT)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "external-feed certificate exceeds 64 MiB",
        ));
    }
    let mut r = Reader::new(bytes);
    if r.bytes(64, "external_feed.format")? != CERTIFICATE_FORMAT {
        return Err(failed(
            "supported_report",
            "unsupported external-feed certificate",
        ));
    }
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "external_feed.source")?;
    if r.count(4, 4, "external_feed.native_inputs")? != 4 {
        return Err(invalid(
            "external-feed certificate requires its four retained native inputs",
        ));
    }
    for _ in 0..4 {
        // Retain and commit native query attestations without treating their
        // graph results as independent evidence of detail or review admission.
        if r.bytes(1024 * 1024, "external_feed.native_input")?
            .is_empty()
        {
            return Err(invalid("empty external-feed native input"));
        }
    }
    let request = ExternalFeedRequest {
        feed: text(&mut r, 64, "external_feed.feed")?.into(),
        control_account: r.u128("external_feed.control")?,
        effective_through: r.i32("external_feed.cutoff")?,
        known_at: r.u64("external_feed.known_at")?,
    };
    if !identifier(&request.feed, 64) {
        return Err(invalid("invalid external feed identifier"));
    }
    let registry_digest = r.fixed("external_feed.registry")?;
    r.u128("external_feed.producer")?;
    r.fixed::<32>("external_feed.capability")?;
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "external_feed.output")?;
    let mut output_reader = Reader::new(output);
    if output_reader.bytes(64, "external_feed.output.format")? != OUTPUT_FORMAT {
        return Err(failed(
            "supported_report",
            "unsupported external-feed output",
        ));
    }
    let digest = r.fixed("external_feed.digest")?;
    r.finish("external-feed certificate")?;
    if framed_digest(CERTIFICATE_DIGEST, &[&bytes[..bytes.len() - 32]]) != digest {
        return Err(failed(
            "certificate_digest",
            "external-feed certificate commitment differs",
        ));
    }
    Ok(Certificate {
        source,
        request,
        registry_digest,
        output,
        digest,
    })
}

pub(super) fn bind_request(
    certificate: &Certificate<'_>,
    expected: &ExternalFeedRequest,
) -> Result<(), ReportError> {
    if !identifier(&expected.feed, 64) || &certificate.request != expected {
        return Err(failed(
            "external_feed_request",
            "external-feed certificate differs from the recipient's fixed feed, control account, cutoff or known-at",
        ));
    }
    Ok(())
}

pub(super) fn bind_source(
    certificate: &Certificate<'_>,
    source: &super::Certificate<'_>,
) -> Result<(), ReportError> {
    if !certificate.source.starts_with(super::CERTIFICATE_FORMAT)
        || source.known_at == 0
        || source.known_at != certificate.request.known_at
        || source.selection != Selection::AsOf(certificate.request.effective_through)
        || source.branch != [0; 16]
        || source.time_selection.is_some()
        || source.dimension.is_some()
        || source.functional
    {
        return Err(failed(
            "external_feed_request",
            "external feed requires its complete sequence-selected trunk native v1 stock trial balance at the same cutoff and known-at",
        ));
    }
    Ok(())
}

fn add(columns: &mut [i128; 6], index: usize, amount: i128) -> Result<(), ReportError> {
    if amount < 0 {
        return Err(failed("exact_arithmetic", "external-feed leg is negative"));
    }
    columns[index] = columns[index]
        .checked_add(amount)
        .ok_or_else(|| failed("exact_arithmetic", "external-feed gross column overflow"))?;
    Ok(())
}

/// Resolve every ancestry hop by immutable identity, digest, publication and
/// exact gross sides/dimensions. Memo and settlement policy are not a native
/// side-swap predicate and supply no control amounts here.
#[allow(clippy::too_many_arguments)]
fn source_of(
    start: usize,
    feed: &str,
    by_id: &BTreeMap<u128, usize>,
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    envelopes: &[LeafEnvelope],
    legs: &[Vec<Leg>],
    details: &BTreeMap<usize, Vec<LegDetails>>,
    sources: &BTreeMap<usize, source::Batch>,
    cache: &mut BTreeMap<usize, Option<(usize, bool)>>,
) -> Result<Option<(usize, bool)>, ReportError> {
    let mut current = start;
    let mut path = Vec::new();
    let mut seen = BTreeSet::new();
    let mut result;
    loop {
        if !seen.insert(current) {
            return Err(invalid("cycle in external source reversal ancestry"));
        }
        if let Some(cached) = cache.get(&current) {
            result = *cached;
            break;
        }
        if let Some(batch) = sources.get(&current) {
            result = (batch.feed == feed).then_some((current, false));
            cache.insert(current, result);
            break;
        }
        if envelopes[current].class != 4 {
            result = None;
            cache.insert(current, None);
            break;
        }
        let [(target, digest, 1)] = infos[&current].supersession.as_slice() else {
            return Err(invalid(
                "external source reversal requires exactly one Reverses target",
            ));
        };
        let prior = *by_id
            .get(target)
            .ok_or_else(|| invalid("external source reversal target is absent at known-at"))?;
        let before = &legs[prior];
        let after = &legs[current];
        if envelopes[prior].record_digest != *digest
            // Publication is atomic; within-commit ordinals order immutable
            // identities, not the execution order of original and reversal.
            || envelopes[prior].commit_seq > envelopes[current].commit_seq
            || before.is_empty()
            || before.len() != after.len()
            || !before.iter().zip(after).all(|(a, b)| {
                a.account == b.account
                    && a.unit == b.unit
                    && a.mantissa == b.mantissa
                    && a.debit != b.debit
            })
            || !details[&prior]
                .iter()
                .zip(&details[&current])
                .all(|(a, b)| a.dimensions == b.dimensions)
        {
            return Err(invalid(
                "reversal differs from its target's immutable exact gross effects",
            ));
        }
        path.push(current);
        current = prior;
    }
    for index in path.into_iter().rev() {
        result = result.map(|(original, reversed)| (original, !reversed));
        cache.insert(index, result);
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn replay(
    certificate: &Certificate<'_>,
    source_certificate: &super::Certificate<'_>,
    units: &[u32],
    schema: &metadata::Schema,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    legs: &[Vec<Leg>],
    visible_migrations: &BTreeSet<u64>,
    resolved: &BTreeSet<usize>,
    control_rows: &[ReportRow],
) -> Result<(VerifiedExternalFeed, Vec<u8>), ReportError> {
    bind_source(certificate, source_certificate)?;
    let request = &certificate.request;
    let control = schema
        .accounts
        .get(&request.control_account)
        .ok_or_else(|| invalid("external-feed control account is absent at known-at"))?;
    if !control.is_leaf {
        return Err(invalid(
            "external-feed control must be an authenticated posting leaf",
        ));
    }
    let mut by_id = BTreeMap::new();
    let mut ordered = BTreeMap::new();
    let mut details = BTreeMap::new();
    let mut sources = BTreeMap::new();
    for (&index, info) in infos {
        if envelopes[index].class == 12 && !visible_migrations.contains(&(index as u64)) {
            continue;
        }
        for identity in info.identities() {
            if by_id.insert(identity, index).is_some() {
                return Err(invalid("duplicate external-feed journal entry identity"));
            }
        }
        ordered.insert(info.identity, index);
        let (len, payload) = records[index];
        let decoded = proposal_leg_details(&payload[..len])?;
        if decoded.len() != legs[index].len() {
            return Err(invalid(
                "external-feed dimension and monetary leg counts differ",
            ));
        }
        details.insert(index, decoded);
        if let Some((body, valid_shape)) = info.external_subledger {
            let batch = source::batch(
                body,
                valid_shape,
                &envelopes[index],
                info,
                &payload[..len],
                units,
            )?;
            sources.insert(index, batch);
        }
    }
    let evidence = source::Evidence::read(
        envelopes,
        records,
        &source_certificate.book,
        request.known_at,
    )?;
    let mut columns = BTreeMap::<(u32, Vec<(u32, u128)>), [i128; 6]>::new();
    let mut batches = BTreeMap::new();
    let mut batch_identities = BTreeSet::new();
    let mut contributions = Vec::new();
    let mut unattributed = Vec::new();
    let mut cache = BTreeMap::new();
    let mut selected_legs = 0usize;
    for (entry, index) in ordered {
        let envelope = &envelopes[index];
        let Some(effective_date) = envelope.effective_day else {
            continue;
        };
        if effective_date > request.effective_through
            || envelope.class == 2 && resolved.contains(&index)
        {
            continue;
        }
        let original = source_of(
            index,
            &request.feed,
            &by_id,
            infos,
            envelopes,
            legs,
            &details,
            &sources,
            &mut cache,
        )?;
        if let Some((original, reversed)) = original {
            let batch = &sources[&original];
            let source_id = infos[&original].identity;
            if let std::collections::btree_map::Entry::Vacant(slot) = batches.entry(source_id) {
                if !batch_identities.insert((batch.feed.clone(), batch.batch_key.clone())) {
                    return Err(invalid(
                        "two summaries consume the same external feed and batch key",
                    ));
                }
                slot.insert(evidence.bind(batch, source_id, &envelopes[original])?);
            }
            contributions.push(VerifiedExternalFeedContribution {
                entry,
                entry_digest: envelope.record_digest,
                source: source_id,
                source_digest: envelopes[original].record_digest,
                recorded_at: envelope.commit_seq,
                effective_date,
                reversed,
            });
            if contributions.len() > MAX_REPORT_LEGS {
                return Err(failed(
                    "bounded_input",
                    "external feed exceeds 100000 contributing entries",
                ));
            }
            for row in &batch.rows {
                if row.account == request.control_account {
                    let c = columns
                        .entry((row.unit, row.dimension_set.clone()))
                        .or_default();
                    add(c, usize::from(row.credit != reversed), row.amount)?;
                }
            }
        }
        for (ordinal, (leg, detail)) in legs[index].iter().zip(&details[&index]).enumerate() {
            if leg.account != request.control_account {
                continue;
            }
            selected_legs = selected_legs
                .checked_add(1)
                .ok_or_else(|| failed("bounded_input", "external-feed leg count overflow"))?;
            if selected_legs > MAX_REPORT_LEGS {
                return Err(failed(
                    "bounded_input",
                    "external control exceeds 100000 legs",
                ));
            }
            if units.binary_search(&leg.unit).is_err() {
                return Err(failed(
                    "registry_closure",
                    "external-feed control leg names an unregistered unit",
                ));
            }
            let pending = envelope.class == 2;
            let c = columns
                .entry((leg.unit, detail.dimensions.clone()))
                .or_default();
            add(
                c,
                if pending { 4 } else { 2 } + usize::from(!leg.debit),
                leg.mantissa,
            )?;
            if original.is_none() {
                unattributed.push(VerifiedExternalFeedLeg {
                    entry,
                    entry_digest: envelope.record_digest,
                    ordinal: ordinal as u32,
                    unit: leg.unit,
                    credit: !leg.debit,
                    amount: leg.mantissa,
                    dimension_set: detail.dimensions.clone(),
                    pending,
                });
            }
        }
    }
    let mut sums = BTreeMap::<u32, [i128; 6]>::new();
    let mut rows = Vec::with_capacity(columns.len());
    for ((unit_id, dimension_set), c) in columns {
        for (index, amount) in c.into_iter().enumerate() {
            add(sums.entry(unit_id).or_default(), index, amount)?;
        }
        rows.push(VerifiedExternalFeedRow {
            unit_id,
            dimension_set,
            detail_debits: c[0],
            detail_credits: c[1],
            control_debits: c[2],
            control_credits: c[3],
            pending_debits: c[4],
            pending_credits: c[5],
        });
    }
    let registers: BTreeMap<_, _> = control_rows
        .iter()
        .filter(|row| row.account == request.control_account)
        .map(|row| {
            (
                row.unit,
                [
                    row.debits,
                    row.credits,
                    row.debits_pending,
                    row.credits_pending,
                ],
            )
        })
        .collect();
    let selected_units: BTreeSet<_> = sums.keys().chain(registers.keys()).copied().collect();
    let mut totals = Vec::with_capacity(selected_units.len());
    for unit_id in selected_units {
        if units.binary_search(&unit_id).is_err() {
            return Err(failed(
                "registry_closure",
                "external-feed register names an unregistered unit",
            ));
        }
        let c = sums.get(&unit_id).copied().unwrap_or([0; 6]);
        let r = registers.get(&unit_id).copied().unwrap_or([0; 4]);
        totals.push(VerifiedExternalFeedTotal {
            unit_id,
            detail_debits: c[0],
            detail_credits: c[1],
            control_debits: c[2],
            control_credits: c[3],
            pending_debits: c[4],
            pending_credits: c[5],
            register_debits: r[0],
            register_credits: r[1],
            register_debits_pending: r[2],
            register_credits_pending: r[3],
        });
    }
    let reconciled = unattributed.is_empty()
        && rows.iter().all(|r| {
            r.detail_debits == r.control_debits
                && r.detail_credits == r.control_credits
                && r.pending_debits == 0
                && r.pending_credits == 0
        })
        && totals.iter().all(|r| {
            r.detail_debits == r.control_debits
                && r.detail_credits == r.control_credits
                && r.pending_debits == 0
                && r.pending_credits == 0
                && r.control_debits == r.register_debits
                && r.control_credits == r.register_credits
                && r.pending_debits == r.register_debits_pending
                && r.pending_credits == r.register_credits_pending
        });
    let report = VerifiedExternalFeed {
        book_id: source_certificate.book,
        known_at: request.known_at,
        effective_through: request.effective_through,
        source_certificate_digest: source_certificate.digest,
        feed: request.feed.clone(),
        control_account: request.control_account,
        batches: batches.into_values().collect(),
        contributions,
        unattributed,
        rows,
        totals,
        reconciled,
    };
    let output = encode(&report)?;
    if output != certificate.output {
        return Err(failed(
            "report_recomputation",
            "external-feed detail, sources, gross control population or reconciliation output differs",
        ));
    }
    Ok((report, output))
}

fn dimensions(w: &mut Writer, values: &[(u32, u128)]) {
    w.count(values.len());
    for (kind, value) in values {
        w.u32(*kind).u128(*value);
    }
}

fn encode(report: &VerifiedExternalFeed) -> Result<Vec<u8>, ReportError> {
    let mut w = Writer::default();
    w.bytes(OUTPUT_FORMAT)
        .fixed(&report.book_id)
        .u64(report.known_at)
        .bytes(report.feed.as_bytes())
        .u128(report.control_account)
        .i32(report.effective_through)
        .count(report.batches.len());
    for batch in &report.batches {
        w.u128(batch.entry)
            .fixed(&batch.entry_digest)
            .u64(batch.recorded_at)
            .bytes(batch.feed.as_bytes())
            .bytes(batch.batch_key.as_bytes())
            .i32(batch.effective_date)
            .fixed(&batch.document_oid)
            .fixed(&batch.doc_commit)
            .u8(batch.evidence_role)
            .u128(batch.review_attestation)
            .u128(batch.reviewer)
            .u64(batch.detail_rows as u64)
            .u8(u8::from(batch.reconciled))
            .count(batch.summary_legs.len());
        for leg in &batch.summary_legs {
            w.u128(leg.account)
                .u32(leg.unit)
                .u8(u8::from(leg.credit))
                .i128(leg.amount);
            dimensions(&mut w, &leg.dimension_set);
        }
    }
    w.count(report.contributions.len());
    for row in &report.contributions {
        w.u128(row.entry)
            .fixed(&row.entry_digest)
            .u128(row.source)
            .fixed(&row.source_digest)
            .u64(row.recorded_at)
            .i32(row.effective_date)
            .u8(u8::from(row.reversed));
    }
    w.count(report.unattributed.len());
    for row in &report.unattributed {
        w.u128(row.entry)
            .fixed(&row.entry_digest)
            .u32(row.ordinal)
            .u32(row.unit)
            .u8(u8::from(row.credit))
            .i128(row.amount)
            .u8(u8::from(row.pending));
        dimensions(&mut w, &row.dimension_set);
    }
    w.count(report.rows.len());
    for row in &report.rows {
        w.u32(row.unit_id);
        dimensions(&mut w, &row.dimension_set);
        for amount in row.columns() {
            w.i128(amount);
        }
    }
    w.count(report.totals.len());
    for row in &report.totals {
        w.u32(row.unit_id);
        for amount in [
            row.detail_debits,
            row.detail_credits,
            row.control_debits,
            row.control_credits,
            row.pending_debits,
            row.pending_credits,
            row.register_debits,
            row.register_credits,
            row.register_debits_pending,
            row.register_credits_pending,
        ] {
            w.i128(amount);
        }
    }
    w.u8(u8::from(report.reconciled));
    if w.buf.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "external-feed output exceeds 64 MiB",
        ));
    }
    Ok(w.buf)
}
