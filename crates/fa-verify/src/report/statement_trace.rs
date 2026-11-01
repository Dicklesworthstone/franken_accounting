//! Independent attribution of every publication in a native statement interval.
//! The complete authenticated checkpoint prefix supplies all historical inputs;
//! no intermediate statement or entry link is accepted from the claimed output.

use std::collections::BTreeMap;

use super::{
    Certificate as NativeCertificate, MAX_REPORT_BUNDLE_BYTES, ReportError, Selection,
    StatementLineChange, StatementMappingChange, VerifiedStatement, VerifiedStatementDiff, failed,
    metadata, statement_diff,
};
use crate::blake3::hash_parts;
use crate::codec::{Reader, Writer};
use crate::envelope::{KIND_ENTRY, LeafEnvelope, Leg, proposal_leg_details};

const FORMAT: &[u8] = b"fa:statement-trace-certificate:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:statement-trace-certificate-digest:v1";
const SOURCE_DOMAIN: &[u8] = b"fa:statement-trace-source:v1";
const OUTPUT_FORMAT: &[u8] = b"fa:statement-trace:v1";
const MAX_SOURCES: usize = 257;
const MAX_LINKS: usize = 65_536;
const MAX_REFERENCES: usize = 4096;

/// One recorded entry, reconstructed from its authenticated canonical payload.
/// Its references identify lineage and settlement targets, not economic causes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedStatementEntryLink {
    pub entry: u128,
    pub digest: [u8; 32],
    pub class: u16,
    pub recorded_at: u64,
    pub posting_date: Option<i32>,
    pub principal: u128,
    pub references: Vec<(u128, [u8; 32])>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedStatementPublication {
    pub recorded_at: u64,
    pub before_source_digest: [u8; 32],
    pub after_source_digest: [u8; 32],
    pub entries: Vec<VerifiedStatementEntryLink>,
    pub changes: Vec<StatementLineChange>,
    pub mapping_changes: Vec<StatementMappingChange>,
}

/// Every consecutive publication, including those without entries or changes.
/// The summary contains every line, including zero lines, at both endpoints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedStatementTrace {
    pub summary: VerifiedStatementDiff,
    pub publications: Vec<VerifiedStatementPublication>,
}

pub(super) struct Certificate<'a> {
    pub sources: Vec<&'a [u8]>,
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    Reader::new(bytes)
        .bytes(64, "statement_trace.format")
        .is_ok_and(|format| format == FORMAT)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed("bounded_input", "statement trace exceeds 64 MiB"));
    }
    let mut r = Reader::new(bytes);
    if r.bytes(64, "statement_trace.format")? != FORMAT {
        return Err(failed(
            "supported_report",
            "unsupported statement trace format",
        ));
    }
    // Historical producer provenance is never a current authority grant.
    r.u128("statement_trace.producer")?;
    r.fixed::<32>("statement_trace.capability")?;
    let n = r.count(MAX_SOURCES, 4, "statement_trace.sources")?;
    if n == 0 {
        return Err(failed(
            "statement_trace_sources",
            "trace has no initial source",
        ));
    }
    let mut sources = Vec::with_capacity(n);
    for _ in 0..n {
        let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "statement_trace.source")?;
        if !source.starts_with(super::STATEMENT_CERTIFICATE_FORMAT) {
            return Err(failed(
                "supported_report",
                "trace sources require native v4 financial statements",
            ));
        }
        sources.push(source);
    }
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "statement_trace.output")?;
    if Reader::new(output).bytes(64, "statement_trace.output_format")? != OUTPUT_FORMAT {
        return Err(failed(
            "supported_report",
            "unrelated statement trace output",
        ));
    }
    let body_len = bytes.len() - r.remaining();
    let digest = r.fixed::<32>("statement_trace.digest")?;
    r.finish("statement trace certificate")?;
    if hash_parts(
        DIGEST_DOMAIN,
        &[&(body_len as u32).to_le_bytes(), &bytes[..body_len]],
    ) != digest
    {
        return Err(failed(
            "certificate_digest",
            "statement trace body digest differs",
        ));
    }
    let first = super::certificate(sources[0])?;
    for (offset, source) in sources.iter().enumerate() {
        let next = super::certificate(source)?;
        statement_diff::bind(&first, &next)?;
        if first.known_at.checked_add(offset as u64) != Some(next.known_at) || next.functional {
            return Err(failed(
                "statement_trace_sources",
                "trace must retain every consecutive native statement at the same selection and registry epoch",
            ));
        }
    }
    Ok(Certificate {
        sources,
        output,
        digest,
    })
}

#[allow(clippy::too_many_arguments)]
fn source(
    certificate: &NativeCertificate<'_>,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    bodies: &[(u64, &[u8])],
    legs: &[Vec<Leg>],
    units: &[u32],
) -> Result<(VerifiedStatement, Vec<u8>), ReportError> {
    let Selection::Statement(selection) = &certificate.selection else {
        return Err(failed(
            "supported_report",
            "trace source is not a statement",
        ));
    };
    let source_bodies = crate::migration_balance::report_bodies_at(
        envelopes,
        records,
        bodies,
        certificate.known_at,
    )
    .map_err(|error| failed("migration_visibility", error.to_string()))?;
    let inputs = super::historical_inputs(certificate, envelopes, records, &source_bodies)?;
    let (statement, output) = super::statement::replay(
        selection,
        &certificate.book,
        &certificate.branch,
        certificate.known_at,
        units,
        &inputs.schema,
        envelopes,
        &inputs.infos,
        legs,
        &inputs.visible_migrations,
        &inputs.resolved,
    )?;
    if output != certificate.output {
        return Err(failed(
            "report_recomputation",
            "an intermediate trace statement differs from its independently reconstructed historical source",
        ));
    }
    Ok((statement, output))
}

fn links(
    at: u64,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    legs: &[Vec<Leg>],
) -> Result<Vec<VerifiedStatementEntryLink>, ReportError> {
    let mut links = BTreeMap::new();
    for (index, envelope) in envelopes.iter().enumerate() {
        if envelope.kind != KIND_ENTRY || envelope.commit_seq != at {
            continue;
        }
        // Migration visibility events and historical replacement row aliases
        // require additional authenticated identity semantics. Never guess them.
        if matches!(envelope.class, 5 | 12 | 22) {
            return Err(failed(
                "supported_report",
                "portable trace attribution does not yet support migration publications or ambiguous legacy replacement identities",
            ));
        }
        let (len, payload) = records[index];
        let proposal = &payload[..len];
        let info = metadata::entry_info(proposal, envelope)?;
        let mut references = BTreeMap::new();
        let mut insert = |id, digest| -> Result<(), ReportError> {
            if references
                .insert(id, digest)
                .is_some_and(|old| old != digest)
            {
                return Err(failed(
                    "entry_lineage",
                    "trace target has conflicting digests",
                ));
            }
            if references.len() > MAX_REFERENCES {
                return Err(failed(
                    "bounded_input",
                    "trace entry exceeds 4096 references",
                ));
            }
            Ok(())
        };
        for (id, digest, _) in &info.supersession {
            insert(*id, *digest)?;
        }
        if let Some((id, digest)) = info.resolution {
            insert(id, digest)?;
        }
        for leg in proposal_leg_details(proposal)? {
            for settlement in leg.settlements {
                insert(settlement.target, settlement.digest)?;
            }
        }
        let link = VerifiedStatementEntryLink {
            entry: info.identity,
            digest: envelope.record_digest,
            class: envelope.class,
            recorded_at: at,
            posting_date: if legs[index].is_empty() {
                None
            } else {
                envelope.effective_day
            },
            principal: info.principal,
            references: references.into_iter().collect(),
        };
        if links.insert(link.entry, link).is_some() {
            return Err(failed(
                "entry_identity",
                "trace contains duplicate derived entry identities",
            ));
        }
        if links.len() > MAX_LINKS {
            return Err(failed("bounded_input", "trace exceeds 65536 entry links"));
        }
    }
    Ok(links.into_values().collect())
}

fn mapping(w: &mut Writer, mapping: &super::StatementMapping) {
    w.u128(mapping.account)
        .bytes(mapping.code.as_bytes())
        .bytes(mapping.name.as_bytes())
        .u8(mapping.account_type)
        .u8(u8::from(mapping.is_leaf))
        .bytes(mapping.line_code.as_bytes());
}

fn encode_publication(
    step: &VerifiedStatementPublication,
    budget: usize,
) -> Result<Vec<u8>, ReportError> {
    // Price every output frame before allocating, including sparse line vectors.
    let mut size = 84usize;
    let mut charge = |n: usize| -> Result<(), ReportError> {
        size = size
            .checked_add(n)
            .filter(|n| *n <= budget)
            .ok_or_else(|| {
                failed(
                    "bounded_input",
                    "reconstructed trace exceeds its bounded output",
                )
            })?;
        Ok(())
    };
    for entry in &step.entries {
        charge(81 + usize::from(entry.posting_date.is_some()) * 4 + entry.references.len() * 48)?;
    }
    for line in &step.changes {
        charge(
            24 + line.code.len()
                + line.label.len()
                + (line.before.len() + line.after.len() + line.delta.len()) * 16,
        )?;
    }
    for change in &step.mapping_changes {
        charge(18)?;
        for m in [change.before.as_ref(), change.after.as_ref()]
            .into_iter()
            .flatten()
        {
            charge(30 + m.code.len() + m.name.len() + m.line_code.len())?;
        }
    }
    if size > budget {
        return Err(failed(
            "bounded_input",
            "trace publication exceeds output budget",
        ));
    }
    let mut w = Writer::default();
    w.u64(step.recorded_at)
        .fixed(&step.before_source_digest)
        .fixed(&step.after_source_digest)
        .count(step.entries.len());
    for entry in &step.entries {
        w.u8(0)
            .u64(entry.recorded_at)
            .u128(entry.entry)
            .fixed(&entry.digest)
            .u16(entry.class)
            .u8(u8::from(entry.posting_date.is_some()));
        if let Some(day) = entry.posting_date {
            w.i32(day);
        }
        w.u128(entry.principal).count(entry.references.len());
        for (id, digest) in &entry.references {
            w.u128(*id).fixed(digest);
        }
        w.u8(0); // No migration run in this admitted native attribution profile.
    }
    w.count(step.changes.len());
    for line in &step.changes {
        w.bytes(line.code.as_bytes())
            .bytes(line.label.as_bytes())
            .u32(line.unit);
        for amounts in [&line.before, &line.after, &line.delta] {
            w.count(amounts.len());
            for amount in amounts {
                w.i128(*amount);
            }
        }
    }
    w.count(step.mapping_changes.len());
    for change in &step.mapping_changes {
        w.u128(change.account);
        for item in [&change.before, &change.after] {
            w.u8(u8::from(item.is_some()));
            if let Some(item) = item {
                mapping(&mut w, item);
            }
        }
    }
    if w.buf.len() != size {
        return Err(failed(
            "canonical_encoding",
            "trace publication framing length differs",
        ));
    }
    Ok(w.buf)
}

pub(super) fn replay(
    request: &Certificate<'_>,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    bodies: &[(u64, &[u8])],
    legs: &[Vec<Leg>],
    units: &[u32],
) -> Result<(VerifiedStatementTrace, Vec<u8>), ReportError> {
    let first_certificate = super::certificate(request.sources[0])?;
    let (first, first_bytes) = source(&first_certificate, envelopes, records, bodies, legs, units)?;
    let mut previous_certificate = super::certificate(request.sources[0])?;
    let mut previous = first.clone();
    let mut previous_bytes = first_bytes.clone();
    let mut publications = Vec::with_capacity(request.sources.len() - 1);
    let mut encoded_steps = Vec::new();
    let mut link_count = 0usize;
    for raw in request.sources.iter().skip(1) {
        let next_certificate = super::certificate(raw)?;
        let (next, next_bytes) =
            source(&next_certificate, envelopes, records, bodies, legs, units)?;
        let (diff, _) = statement_diff::derive(
            false,
            &previous_certificate,
            &next_certificate,
            previous,
            &previous_bytes,
            next.clone(),
            &next_bytes,
        )?;
        let entries = links(next_certificate.known_at, envelopes, records, legs)?;
        link_count = link_count
            .checked_add(entries.len())
            .filter(|n| *n <= MAX_LINKS)
            .ok_or_else(|| failed("bounded_input", "trace exceeds 65536 total entry links"))?;
        let publication = VerifiedStatementPublication {
            recorded_at: next_certificate.known_at,
            before_source_digest: hash_parts(
                SOURCE_DOMAIN,
                &[
                    &(previous_bytes.len() as u32).to_le_bytes(),
                    &previous_bytes,
                ],
            ),
            after_source_digest: hash_parts(
                SOURCE_DOMAIN,
                &[&(next_bytes.len() as u32).to_le_bytes(), &next_bytes],
            ),
            entries,
            changes: diff
                .lines
                .into_iter()
                .filter(|line| line.delta.iter().any(|value| *value != 0))
                .collect(),
            mapping_changes: diff.mapping_changes,
        };
        let budget = request
            .output
            .len()
            .checked_sub(encoded_steps.len())
            .ok_or_else(|| failed("bounded_input", "trace output budget exhausted"))?;
        encoded_steps.extend_from_slice(&encode_publication(&publication, budget)?);
        publications.push(publication);
        previous_certificate = next_certificate;
        previous = next;
        previous_bytes = next_bytes;
    }
    let (summary, summary_bytes) = statement_diff::derive(
        false,
        &first_certificate,
        &previous_certificate,
        first,
        &first_bytes,
        previous,
        &previous_bytes,
    )?;
    let length = 12usize
        .checked_add(OUTPUT_FORMAT.len())
        .and_then(|n| n.checked_add(summary_bytes.len()))
        .and_then(|n| n.checked_add(encoded_steps.len()))
        .filter(|n| *n == request.output.len())
        .ok_or_else(|| {
            failed(
                "statement_trace_recomputation",
                "trace output has a missing or extra frame",
            )
        })?;
    let mut w = Writer::default();
    w.bytes(OUTPUT_FORMAT)
        .bytes(&summary_bytes)
        .count(publications.len())
        .fixed(&encoded_steps);
    if w.buf.len() != length || w.buf != request.output {
        return Err(failed(
            "statement_trace_recomputation",
            "trace summary, intermediate publications, source commitments, entry lineage or exact canonical bytes differ from independent replay",
        ));
    }
    Ok((
        VerifiedStatementTrace {
            summary,
            publications,
        },
        w.buf,
    ))
}
