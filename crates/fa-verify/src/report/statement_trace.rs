//! Independent attribution of every publication in a statement interval.
//! The complete authenticated checkpoint prefix supplies all historical inputs;
//! no intermediate statement or entry link is accepted from the claimed output.

use std::collections::BTreeMap;

use super::{
    Certificate as NativeCertificate, MAX_REPORT_BUNDLE_BYTES, ReportError, Selection,
    StatementLineChange, StatementMappingChange, VerifiedCustomStatement, VerifiedStatement,
    VerifiedStatementDiff, custom_statement, failed, functional, metadata, registry,
    statement_diff,
};
use crate::blake3::hash_parts;
use crate::codec::{Reader, Writer};
use crate::envelope::{KIND_ENTRY, LeafEnvelope, Leg, proposal_leg_details};

const FORMAT: &[u8] = b"fa:statement-trace-certificate:v1";
const FUNCTIONAL_FORMAT: &[u8] = b"fa:functional-statement-trace-certificate:v1";
const CUSTOM_FORMAT: &[u8] = b"fa:custom-statement-trace-certificate:v1";
const FUNCTIONAL_CUSTOM_FORMAT: &[u8] = b"fa:functional-custom-statement-trace-certificate:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:statement-trace-certificate-digest:v1";
const FUNCTIONAL_DIGEST_DOMAIN: &[u8] = b"fa:functional-statement-trace-certificate-digest:v1";
const CUSTOM_DIGEST_DOMAIN: &[u8] = b"fa:custom-statement-trace-certificate-digest:v1";
const FUNCTIONAL_CUSTOM_DIGEST_DOMAIN: &[u8] =
    b"fa:functional-custom-statement-trace-certificate-digest:v1";
const SOURCE_DOMAIN: &[u8] = b"fa:statement-trace-source:v1";
const FUNCTIONAL_SOURCE_DOMAIN: &[u8] = b"fa:functional-statement-trace-source:v1";
const CUSTOM_SOURCE_DOMAIN: &[u8] = b"fa:custom-statement-trace-source:v1";
const FUNCTIONAL_CUSTOM_SOURCE_DOMAIN: &[u8] = b"fa:functional-custom-statement-trace-source:v1";
const OUTPUT_FORMAT: &[u8] = b"fa:statement-trace:v1";
const FUNCTIONAL_OUTPUT_FORMAT: &[u8] = b"fa:functional-statement-trace:v1";
const CUSTOM_OUTPUT_FORMAT: &[u8] = b"fa:custom-statement-trace:v1";
const FUNCTIONAL_CUSTOM_OUTPUT_FORMAT: &[u8] = b"fa:functional-custom-statement-trace:v1";
const MAX_SOURCES: usize = 257;
const MAX_LINKS: usize = 65_536;
const MAX_REFERENCES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifiedStatementEntryEvent {
    Recorded,
    /// Finalize made an earlier recorded migration chunk count at this step.
    BecameVisible,
}

/// One recorded or newly visible entry, reconstructed from its authenticated payload.
/// Its references identify lineage and settlement targets, not economic causes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedStatementEntryLink {
    pub event: VerifiedStatementEntryEvent,
    pub entry: u128,
    pub digest: [u8; 32],
    pub class: u16,
    pub recorded_at: u64,
    pub posting_date: Option<i32>,
    pub principal: u128,
    pub references: Vec<(u128, [u8; 32])>,
    pub migration_run: Option<u128>,
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
    pub functional: bool,
    pub custom: bool,
    pub sources: Vec<&'a [u8]>,
    pub output: &'a [u8],
    pub digest: [u8; 32],
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    Reader::new(bytes)
        .bytes(64, "statement_trace.format")
        .is_ok_and(|format| {
            matches!(
                format,
                FORMAT | FUNCTIONAL_FORMAT | CUSTOM_FORMAT | FUNCTIONAL_CUSTOM_FORMAT
            )
        })
}

fn output_format(custom: bool, functional: bool) -> &'static [u8] {
    match (custom, functional) {
        (false, false) => OUTPUT_FORMAT,
        (false, true) => FUNCTIONAL_OUTPUT_FORMAT,
        (true, false) => CUSTOM_OUTPUT_FORMAT,
        (true, true) => FUNCTIONAL_CUSTOM_OUTPUT_FORMAT,
    }
}

pub(super) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Err(failed("bounded_input", "statement trace exceeds 64 MiB"));
    }
    let mut r = Reader::new(bytes);
    let (custom, functional) = match r.bytes(64, "statement_trace.format")? {
        FORMAT => (false, false),
        FUNCTIONAL_FORMAT => (false, true),
        CUSTOM_FORMAT => (true, false),
        FUNCTIONAL_CUSTOM_FORMAT => (true, true),
        _ => {
            return Err(failed(
                "supported_report",
                "unsupported statement trace format",
            ));
        }
    };
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
        let source_format = match (custom, functional) {
            (false, false) => super::STATEMENT_CERTIFICATE_FORMAT,
            (false, true) => super::FUNCTIONAL_STATEMENT_CERTIFICATE_FORMAT,
            (true, false) => custom_statement::NATIVE_FORMAT,
            (true, true) => custom_statement::FUNCTIONAL_FORMAT,
        };
        if !source.starts_with(source_format) {
            return Err(failed(
                "supported_report",
                "trace sources must preserve the outer family's built-in v4/v5 or custom v11/v12 statement measure",
            ));
        }
        sources.push(source);
    }
    let output = r.bytes(MAX_REPORT_BUNDLE_BYTES, "statement_trace.output")?;
    let output_format = output_format(custom, functional);
    if Reader::new(output).bytes(64, "statement_trace.output_format")? != output_format {
        return Err(failed(
            "supported_report",
            "unrelated statement trace output",
        ));
    }
    let body_len = bytes.len() - r.remaining();
    let digest = r.fixed::<32>("statement_trace.digest")?;
    r.finish("statement trace certificate")?;
    if hash_parts(
        match (custom, functional) {
            (false, false) => DIGEST_DOMAIN,
            (false, true) => FUNCTIONAL_DIGEST_DOMAIN,
            (true, false) => CUSTOM_DIGEST_DOMAIN,
            (true, true) => FUNCTIONAL_CUSTOM_DIGEST_DOMAIN,
        },
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
        if first.known_at.checked_add(offset as u64) != Some(next.known_at)
            || next.functional != functional
        {
            return Err(failed(
                "statement_trace_sources",
                "trace must retain every consecutive statement at the same selection, valuation measure and registry epoch",
            ));
        }
    }
    Ok(Certificate {
        functional,
        custom,
        sources,
        output,
        digest,
    })
}

/// The final statement has already independently checked this exact complete
/// Rate closure. Each earlier source derives its required subset from its own
/// authenticated prefix and checks original custody and first-use visibility.
pub(super) struct FunctionalInputs<'a> {
    pub registry: &'a registry::FunctionalRegistry,
    pub book: &'a [u8],
    pub rates: &'a [([u8; 32], &'a [u8])],
}

#[derive(Clone)]
enum ReplayedStatement {
    BuiltIn(VerifiedStatement),
    Custom(VerifiedCustomStatement),
}

#[allow(clippy::too_many_arguments)]
fn compare(
    functional: bool,
    before_certificate: &NativeCertificate<'_>,
    after_certificate: &NativeCertificate<'_>,
    before: ReplayedStatement,
    before_bytes: &[u8],
    after: ReplayedStatement,
    after_bytes: &[u8],
) -> Result<(VerifiedStatementDiff, Vec<u8>), ReportError> {
    match (before, after) {
        (ReplayedStatement::BuiltIn(before), ReplayedStatement::BuiltIn(after)) => {
            statement_diff::derive(
                functional,
                before_certificate,
                after_certificate,
                before,
                before_bytes,
                after,
                after_bytes,
            )
        }
        (ReplayedStatement::Custom(before), ReplayedStatement::Custom(after)) => {
            statement_diff::derive_custom(
                functional,
                before_certificate,
                after_certificate,
                before,
                before_bytes,
                after,
                after_bytes,
            )
        }
        _ => Err(failed(
            "statement_trace_sources",
            "trace changes its custom or built-in definition family",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn source(
    certificate: &NativeCertificate<'_>,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    bodies: &[(u64, &[u8])],
    legs: &[Vec<Leg>],
    units: &[u32],
    functional_inputs: Option<&FunctionalInputs<'_>>,
) -> Result<ReplayedSource, ReportError> {
    let source_bodies = crate::migration_balance::report_bodies_at(
        envelopes,
        records,
        bodies,
        certificate.known_at,
    )
    .map_err(|error| failed("migration_visibility", error.to_string()))?;
    let inputs = super::historical_inputs(certificate, envelopes, records, &source_bodies)?;
    if let Selection::CustomStatement(selection) = &certificate.selection {
        let valued = if let Some(valuation) = functional_inputs {
            let rates = functional::historical_rates(valuation.rates, records, &inputs.infos)?;
            Some(functional::statement_legs(
                certificate,
                valuation.registry,
                valuation.book,
                &rates,
                &inputs.schema,
                envelopes,
                records,
                legs,
                &inputs.infos,
                &inputs.migration_activations,
            )?)
        } else {
            None
        };
        let (units, legs) = match &valued {
            Some((base, values)) => (std::slice::from_ref(base), values.as_slice()),
            None => (units, legs),
        };
        let (statement, output) = custom_statement::replay(
            selection,
            &certificate.book,
            &certificate.branch,
            certificate.known_at,
            units,
            &inputs.schema,
            envelopes,
            records,
            &inputs.infos,
            legs,
            &inputs.visible_migrations,
            &inputs.resolved,
        )?;
        if output != certificate.output {
            return Err(failed(
                "custom_statement_recomputation",
                "an intermediate custom trace source differs in its historical activation, exact statement, mappings or independently rounded presentation",
            ));
        }
        return Ok(ReplayedSource {
            statement: ReplayedStatement::Custom(statement),
            output,
            migration_activations: inputs.migration_activations,
        });
    }
    let Selection::Statement(selection) = &certificate.selection else {
        return Err(failed(
            "supported_report",
            "trace source is not a statement",
        ));
    };
    let (statement, output) = if let Some(valuation) = functional_inputs {
        let rates = functional::historical_rates(valuation.rates, records, &inputs.infos)?;
        let (report, output) = functional::replay_statement(
            certificate,
            selection,
            valuation.registry,
            valuation.book,
            &rates,
            &inputs.schema,
            envelopes,
            records,
            legs,
            &inputs.infos,
            &inputs.resolved,
            &inputs.visible_migrations,
            &inputs.migration_activations,
        )?;
        (report.statement, output)
    } else {
        super::statement::replay(
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
        )?
    };
    if output != certificate.output {
        return Err(failed(
            "report_recomputation",
            "an intermediate trace statement differs from its independently reconstructed historical source",
        ));
    }
    Ok(ReplayedSource {
        statement: ReplayedStatement::BuiltIn(statement),
        output,
        migration_activations: inputs.migration_activations,
    })
}

struct ReplayedSource {
    statement: ReplayedStatement,
    output: Vec<u8>,
    /// Counting chunks mapped to the sequence of their authenticated Finalize.
    migration_activations: BTreeMap<u64, u64>,
}

fn source_digest(custom: bool, functional: bool, output: &[u8]) -> Result<[u8; 32], ReportError> {
    let domain = match (custom, functional) {
        (false, false) => SOURCE_DOMAIN,
        (false, true) => FUNCTIONAL_SOURCE_DOMAIN,
        (true, false) => CUSTOM_SOURCE_DOMAIN,
        (true, true) => FUNCTIONAL_CUSTOM_SOURCE_DOMAIN,
    };
    let bytes = if custom {
        custom_statement::statement_bytes(output)?
    } else if functional {
        functional::statement_bytes(output)?
    } else {
        output
    };
    Ok(hash_parts(
        domain,
        &[&(bytes.len() as u32).to_le_bytes(), bytes],
    ))
}

fn links(
    at: u64,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    legs: &[Vec<Leg>],
    migration_activations: &BTreeMap<u64, u64>,
) -> Result<Vec<VerifiedStatementEntryLink>, ReportError> {
    let mut links = BTreeMap::new();
    for (index, envelope) in envelopes.iter().enumerate() {
        if envelope.kind != KIND_ENTRY || envelope.commit_seq > at {
            continue;
        }
        let event = if envelope.commit_seq == at {
            VerifiedStatementEntryEvent::Recorded
        } else if envelope.class == 12 && migration_activations.get(&(index as u64)) == Some(&at) {
            // The lifecycle proof has already checked the run body, counting
            // policy and unique terminal publication. Preserve the chunk's
            // actual recording sequence rather than assigning Finalize to it.
            VerifiedStatementEntryEvent::BecameVisible
        } else {
            continue;
        };
        // The original replacement format does not distinguish its historical
        // row alias. Never guess that identity from an untrusted output link.
        if envelope.class == 5 {
            return Err(failed(
                "supported_report",
                "portable trace attribution does not yet support ambiguous legacy replacement identities",
            ));
        }
        let (len, payload) = records[index];
        let proposal = &payload[..len];
        let info = metadata::entry_info(proposal, envelope)?;
        let migration_run =
            crate::migration_balance::report_run_for_entry(envelope, proposal, index as u64)
                .map_err(|error| failed("migration_visibility", error.to_string()))?;
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
            event,
            entry: info.identity,
            digest: envelope.record_digest,
            class: envelope.class,
            recorded_at: envelope.commit_seq,
            posting_date: if legs[index].is_empty() {
                None
            } else {
                envelope.effective_day
            },
            principal: info.principal,
            references: references.into_iter().collect(),
            migration_run,
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
        charge(
            81 + usize::from(entry.posting_date.is_some()) * 4
                + entry.references.len() * 48
                + usize::from(entry.migration_run.is_some()) * 16,
        )?;
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
        w.u8(match entry.event {
            VerifiedStatementEntryEvent::Recorded => 0,
            VerifiedStatementEntryEvent::BecameVisible => 1,
        })
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
        w.u8(u8::from(entry.migration_run.is_some()));
        if let Some(run) = entry.migration_run {
            w.u128(run);
        }
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
    functional_inputs: Option<FunctionalInputs<'_>>,
) -> Result<(VerifiedStatementTrace, Vec<u8>), ReportError> {
    if request.functional != functional_inputs.is_some() {
        return Err(failed(
            "supported_report",
            "trace valuation profile requires matching independently checked source inputs",
        ));
    }
    let functional_inputs = functional_inputs.as_ref();
    let first_certificate = super::certificate(request.sources[0])?;
    let ReplayedSource {
        statement: first,
        output: first_bytes,
        ..
    } = source(
        &first_certificate,
        envelopes,
        records,
        bodies,
        legs,
        units,
        functional_inputs,
    )?;
    let mut previous_certificate = super::certificate(request.sources[0])?;
    let mut previous = first.clone();
    let mut previous_bytes = first_bytes.clone();
    let mut publications = Vec::with_capacity(request.sources.len() - 1);
    let mut encoded_steps = Vec::new();
    let mut link_count = 0usize;
    for raw in request.sources.iter().skip(1) {
        let next_certificate = super::certificate(raw)?;
        let ReplayedSource {
            statement: next,
            output: next_bytes,
            migration_activations,
        } = source(
            &next_certificate,
            envelopes,
            records,
            bodies,
            legs,
            units,
            functional_inputs,
        )?;
        let (diff, _) = compare(
            request.functional,
            &previous_certificate,
            &next_certificate,
            previous,
            &previous_bytes,
            next.clone(),
            &next_bytes,
        )?;
        let entries = links(
            next_certificate.known_at,
            envelopes,
            records,
            legs,
            &migration_activations,
        )?;
        link_count = link_count
            .checked_add(entries.len())
            .filter(|n| *n <= MAX_LINKS)
            .ok_or_else(|| failed("bounded_input", "trace exceeds 65536 total entry links"))?;
        let publication = VerifiedStatementPublication {
            recorded_at: next_certificate.known_at,
            before_source_digest: source_digest(
                request.custom,
                request.functional,
                &previous_bytes,
            )?,
            after_source_digest: source_digest(request.custom, request.functional, &next_bytes)?,
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
    let (summary, summary_bytes) = compare(
        request.functional,
        &first_certificate,
        &previous_certificate,
        first,
        &first_bytes,
        previous,
        &previous_bytes,
    )?;
    let output_format = output_format(request.custom, request.functional);
    let length = 12usize
        .checked_add(output_format.len())
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
    w.bytes(output_format)
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
