//! Portable certificates for registered Lantern computations (plan §11.1/13.6).
//!
//! A native report certificate binds the complete journal/chart/calendar/unit
//! closure; a supplementary native Approval read binds the inputs used by JET.
//! V2 also binds REA populations and independently immutable attestations.
//! The outer certificate fixes the exact procedure, parameters, handles, recorded
//! frontier, effective cutoff, decision card and ordered findings. Decoding is an
//! integrity check, NOT a replay, signature, or independent completeness proof.
//! Current whole-book read/produce authority admits creation; current whole-book
//! read authority admits replay. Saved principal/commitment fields grant nothing.

mod extended;
pub use extended::EXTENDED_CERTIFIABLE_PROCEDURES;

use crate::{AsyncBook, BookError, Outcome, ReportCertificate, ReportSelection};
use asupersync::fs::Vfs;
use fa_journal::{KernelError, Refusal, exit};
use fa_lantern::{
    Cite, Coordinate, Finding, Params, ProcedureRun, Severity, Snapshot, Statistic, Work, catalog,
};
use fa_model::symbols::{label, property};
use fa_model::{DecodeError, Id128, Reader, Writer, domain_digest};
use fa_policy::{Capability, Op};
use fa_registry::procedures::Claim;
use fa_time::DateDay;
use fgdb::{Database, NativeResultCertificate};
use fgdb_crypto::Hasher;
use fgdb_gql::{GqlParameters, GqlQueryPolicy};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};
use std::collections::BTreeSet;

pub const PROCEDURE_CERTIFICATE_FORMAT: &[u8] = b"fa:procedure-certificate:v1";
pub const EXTENDED_PROCEDURE_CERTIFICATE_FORMAT: &[u8] = extended::FORMAT;
pub const PROCEDURE_OUTPUT_FORMAT: &[u8] = b"fa:procedure-output:v1";
pub const MAX_PROCEDURE_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_OUTPUT: usize = 32 * 1024 * 1024;
const MAX_NATIVE: usize = 1024 * 1024;
const MAX_FINDINGS: usize = 100_000;
const CERTIFICATE_DOMAIN: &[u8] = b"fa:procedure-certificate-digest:v1";

/// Output-input closures audited for this certificate format. New catalog
/// procedures or semantic versions need their additional native inputs covered
/// before they can be certified here. This does not restrict ordinary runs.
pub const CERTIFIABLE_PROCEDURES: &[(&str, u16)] = &[
    ("jet.round_amounts", 1),
    ("jet.period_end_timing", 1),
    ("jet.post_closing", 1),
    ("jet.weekend", 1),
    ("jet.self_approved", 1),
    ("jet.thin_descriptions", 1),
    ("duplicates.same_same_same", 1),
    ("duplicates.same_same_different", 1),
    ("numbers.sequence_gaps", 1),
    ("benford.first_digit", 1),
    ("cutoff.period_boundary", 1),
    ("aging.open_items", 1),
    ("graph.round_trips", 2),
    ("graph.structuring", 2),
    ("trace.libr", 2),
    ("trace.fifo", 2),
    ("trace.lifo", 2),
    ("trace.pro_rata", 2),
    ("trace.network_fifo", 1),
    ("trace.network_lifo", 1),
    ("trace.network_libr", 1),
    ("trace.network_pro_rata", 1),
];

fn supported(id: &str, version: u16) -> bool {
    CERTIFIABLE_PROCEDURES.contains(&(id, version))
}

/// Registered defaults are explicit data, not reselected when a certificate is
/// replayed. Callers can narrow/replace `parameters` with Params::set before use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcedureRequest {
    pub procedure: String,
    pub parameters: Params,
    pub inputs: catalog::Inputs,
    pub known_at: Option<CommitSeq>,
    pub effective_through: Option<DateDay>,
}

impl ProcedureRequest {
    pub fn new(procedure: &str, inputs: catalog::Inputs) -> Result<Self, fa_lantern::LanternError> {
        Ok(Self {
            procedure: procedure.into(),
            parameters: Params::defaults(procedure)?,
            inputs,
            known_at: None,
            effective_through: None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcedureCertificate {
    source: ReportCertificate,
    approvals: NativeResultCertificate,
    extended_inputs: Vec<NativeResultCertificate>,
    registry: [u8; 32],
    producer: VId,
    capability_commitment: [u8; 32],
    report: ProcedureRun,
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedProcedure {
    pub report: ProcedureRun,
    pub certificate: ProcedureCertificate,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §11.1/13.6; FA-INV-11 (native analytic inputs and exact output must replay)",
        "retain the complete procedure certificate and original book; replay with its registry/foundation versions and current whole-book read authority",
    )
}
fn encode_error(e: fa_model::EncodeError) -> Refusal {
    invalid(format!("procedure encoding: {e}"))
}
fn decode_error(e: DecodeError) -> Refusal {
    invalid(format!("procedure decoding: {e}"))
}
fn lantern_error(e: fa_lantern::LanternError) -> Refusal {
    invalid(format!("procedure: {e}"))
}

/// The registries a procedure certificate binds, in commitment order.
const PROCEDURE_REGISTRIES: &[(&str, &str)] = &[
    (
        "procedures",
        include_str!("../../../registries/procedures.toml"),
    ),
    ("foundations", include_str!("../../../franken-stack.lock")),
];

/// The v2 closure over each registry's canonical content, so a comment or
/// layout edit never refuses a retained procedure certificate (bead fa-t8gk).
fn registry_digest() -> Result<[u8; 32], Refusal> {
    crate::certificate::canonical_closure(b"fa:procedure-registry:v2", PROCEDURE_REGISTRIES)
}

/// The v1 raw-text closure, accepted only from certificates retained before
/// fa-t8gk; new certificates never carry it.
fn legacy_registry_digest() -> [u8; 32] {
    let sources: Vec<&[u8]> = PROCEDURE_REGISTRIES
        .iter()
        .map(|(_, text)| text.as_bytes())
        .collect();
    domain_digest(b"fa:procedure-registry:v1", &sources)
}
fn approval_statement(at: CommitSeq) -> String {
    format!(
        "MATCH (n:Approval) FOR SYSTEM_TIME AS OF SEQ {} RETURN n,n._fa_payload,n._fa_digest ORDER BY n",
        at.0
    )
}
fn policy() -> GqlQueryPolicy {
    GqlQueryPolicy::new(10_000_000, 1_000_000, 256 * 1024 * 1024, 256 * 1024 * 1024)
}
fn raw_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().0
}

fn check_run(run: &ProcedureRun) -> Result<(), Refusal> {
    if run.procedure.is_empty()
        || run.procedure.len() > 128
        || run.version == 0
        || run.evidence.len() > 128
        || run.parameters.len() > 128
        || run.inputs.len() > 16
        || run.findings.len() > MAX_FINDINGS
    {
        return Err(invalid("procedure record exceeds its field bounds"));
    }
    for values in [
        run.parameters
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>(),
        run.inputs.iter().map(|(k, _)| k.as_str()).collect(),
    ] {
        if values.iter().any(|k| k.is_empty() || k.len() > 128)
            || values.windows(2).any(|p| p[0] >= p[1])
        {
            return Err(invalid(
                "procedure parameter/input names must be unique and ordered",
            ));
        }
    }
    if run.inputs.iter().any(|(_, v)| v.len() > 256) {
        return Err(invalid("oversized procedure handle"));
    }
    let mut w = Writer::new();
    w.str(&run.procedure).u16(run.version);
    w.list(&run.parameters, |w, (k, v)| {
        w.str(k).i128(*v);
    });
    w.list(&run.inputs, |w, (k, v)| {
        w.str(k).str(v);
    });
    if raw_digest(
        fa_lantern::PARAMETERS_DIGEST_DOMAIN,
        &w.finish().map_err(encode_error)?,
    ) != run.parameters_digest
    {
        return Err(invalid(
            "procedure parameters/handles do not match their digest",
        ));
    }
    let mut previous: Option<(Severity, i128, Vec<Vec<u8>>, &str)> = None;
    let mut finding_bytes = 0usize;
    for finding in &run.findings {
        if finding.procedure != run.procedure
            || finding.version != run.version
            || finding.cites.len() > fa_lantern::MAX_CITES
            || finding.narrative.len() > fa_lantern::MAX_NARRATIVE_BYTES
            || finding.statistic.name.len() > 128
        {
            return Err(invalid(
                "finding identity or field bounds disagree with the run",
            ));
        }
        // Check aggregate size before encoding all findings into a single buffer.
        let bytes = finding.canonical_bytes().map_err(encode_error)?;
        finding_bytes = finding_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| invalid("finding size overflow"))?;
        if finding_bytes > MAX_OUTPUT {
            return Err(invalid("procedure findings exceed the output bound"));
        }
        let cites = finding
            .cites
            .iter()
            .map(Cite::canonical_bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(encode_error)?;
        let current = (
            finding.severity,
            finding.statistic.value,
            cites,
            finding.narrative.as_str(),
        );
        if let Some(prior) = &previous {
            let order = current
                .0
                .cmp(&prior.0)
                .then(current.1.cmp(&prior.1))
                .then_with(|| prior.2.cmp(&current.2))
                .then_with(|| prior.3.cmp(current.3));
            if order.is_gt() {
                return Err(invalid("findings are not in canonical ranking order"));
            }
        }
        previous = Some(current);
    }
    let mut w = Writer::new();
    w.str(&run.procedure)
        .u16(run.version)
        .fixed(&run.parameters_digest)
        .fixed(&run.inputs_digest);
    run.coordinate.encode(&mut w);
    w.list(&run.findings, |w, f| f.encode(w));
    if raw_digest(
        fa_lantern::FINDINGS_DIGEST_DOMAIN,
        &w.finish().map_err(encode_error)?,
    ) != run.findings_digest
    {
        return Err(invalid("procedure findings do not match their digest"));
    }
    if run.decision_card.digest().map_err(encode_error)? != run.decision_card_digest {
        return Err(invalid("procedure decision card digest differs"));
    }
    Ok(())
}

fn encode_run(run: &ProcedureRun) -> Result<Vec<u8>, Refusal> {
    check_run(run)?;
    let mut w = Writer::new();
    w.bytes(PROCEDURE_OUTPUT_FORMAT)
        .str(&run.procedure)
        .u16(run.version)
        .u8(match run.claim {
            Claim::Statistical => 0,
            Claim::Invariant => 1,
        })
        .str(&run.evidence);
    run.coordinate.encode(&mut w);
    w.list(&run.parameters, |w, (k, v)| {
        w.str(k).i128(*v);
    });
    w.list(&run.inputs, |w, (k, v)| {
        w.str(k).str(v);
    });
    w.fixed(&run.parameters_digest)
        .fixed(&run.inputs_digest)
        .u64(run.population)
        .u64(run.work.entries)
        .u64(run.work.legs)
        .u64(run.work.comparisons);
    w.list(&run.findings, |w, f| f.encode(w));
    w.fixed(&run.findings_digest)
        .bytes(&run.decision_card.canonical_bytes().map_err(encode_error)?)
        .fixed(&run.decision_card_digest);
    let bytes = w.finish().map_err(encode_error)?;
    if bytes.len() > MAX_OUTPUT {
        return Err(invalid("procedure output exceeds 32 MiB"));
    }
    Ok(bytes)
}

fn decode_run(bytes: &[u8]) -> Result<ProcedureRun, Refusal> {
    if bytes.len() > MAX_OUTPUT {
        return Err(invalid("procedure output exceeds 32 MiB"));
    }
    let read = || -> Result<ProcedureRun, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.bytes(64, "procedure output format")? != PROCEDURE_OUTPUT_FORMAT {
            return Err(r.invalid("procedure output format"));
        }
        let procedure = r.str(128, "procedure")?.to_string();
        let version = r.u16("procedure version")?;
        let claim = match r.u8("claim")? {
            0 => Claim::Statistical,
            1 => Claim::Invariant,
            t => return Err(r.bad_tag("claim", t)),
        };
        let evidence = r.str(128, "evidence")?.to_string();
        let coordinate = Coordinate {
            book_id: Id128(r.fixed("book")?),
            known_at: CommitSeq(r.u64("known-at")?),
            effective_through: r.opt("effective cutoff", |r| Ok(DateDay(r.i32("day")?)))?,
        };
        let parameters = r.list(128, "parameters", |r| {
            Ok((r.str(128, "parameter")?.to_string(), r.i128("value")?))
        })?;
        let inputs = r.list(16, "inputs", |r| {
            Ok((
                r.str(128, "input")?.to_string(),
                r.str(256, "handle")?.to_string(),
            ))
        })?;
        let parameters_digest = r.fixed("parameter digest")?;
        let inputs_digest = r.fixed("inputs digest")?;
        let population = r.u64("population")?;
        let work = Work {
            entries: r.u64("work entries")?,
            legs: r.u64("work legs")?,
            comparisons: r.u64("work comparisons")?,
        };
        let findings = r.list(MAX_FINDINGS, "findings", |r| {
            let procedure = r.str(128, "finding procedure")?.to_string();
            let version = r.u16("finding version")?;
            let tag = r.u8("severity")?;
            let severity = Severity::from_tag(tag).ok_or_else(|| r.bad_tag("severity", tag))?;
            let statistic = Statistic {
                name: r.str(128, "statistic name")?.to_string(),
                value: r.i128("statistic value")?,
                scale: r.u8("scale")?,
                population: r.u64("statistic population")?,
            };
            let cites = r.list(fa_lantern::MAX_CITES, "citations", Cite::decode)?;
            let narrative = r
                .str(fa_lantern::MAX_NARRATIVE_BYTES, "narrative")?
                .to_string();
            Ok(Finding {
                procedure,
                version,
                severity,
                statistic,
                cites,
                narrative,
            })
        })?;
        let findings_digest = r.fixed("findings digest")?;
        let decision_card = fa_policy::DecisionCard::decode(r.bytes(MAX_NATIVE, "decision card")?)?;
        let decision_card_digest = r.fixed("decision digest")?;
        r.finish()?;
        Ok(ProcedureRun {
            procedure,
            version,
            claim,
            evidence,
            coordinate,
            parameters,
            inputs,
            parameters_digest,
            inputs_digest,
            population,
            work,
            findings,
            findings_digest,
            decision_card,
            decision_card_digest,
        })
    };
    let run = read().map_err(decode_error)?;
    if encode_run(&run)?.as_slice() != bytes {
        return Err(invalid("noncanonical procedure output"));
    }
    Ok(run)
}

impl ProcedureCertificate {
    #[must_use]
    pub fn source_certificate(&self) -> &ReportCertificate {
        &self.source
    }
    #[must_use]
    pub fn report(&self) -> &ProcedureRun {
        &self.report
    }
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    #[must_use]
    pub fn producer(&self) -> VId {
        self.producer
    }
    #[must_use]
    pub fn capability_commitment(&self) -> &[u8; 32] {
        &self.capability_commitment
    }
    /// Original procedures use v1. Extended procedures carry six additional
    /// native population witnesses and use v2; neither format is auto-upgraded.
    #[must_use]
    pub fn format(&self) -> &'static [u8] {
        if self.extended_inputs.is_empty() {
            PROCEDURE_CERTIFICATE_FORMAT
        } else {
            extended::FORMAT
        }
    }
    #[must_use]
    pub fn supplemental_inputs(&self) -> &[NativeResultCertificate] {
        &self.extended_inputs
    }
    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.source.known_at
    }
    #[must_use]
    pub fn book_id(&self) -> Id128 {
        self.source.book_id
    }

    fn body(&self) -> Result<Vec<u8>, Refusal> {
        if self.source.branch_id != Id128::TRUNK
            || self.source.time_selection.is_some()
            || self.source.selection != (ReportSelection::OpenItems { account: None })
            || self.report.coordinate.book_id != self.source.book_id
            || self.report.coordinate.known_at != self.source.known_at
        {
            return Err(invalid(
                "procedure and complete native source coordinates disagree",
            ));
        }
        extended::validate(self)?;
        let source = self.source.canonical_bytes().map_err(encode_error)?;
        ReportCertificate::decode(&source)?;
        let native = self.approvals.canonical_bytes();
        let basis = self
            .source
            .inputs
            .first()
            .ok_or_else(|| invalid("missing native source"))?;
        if native.len() > MAX_NATIVE
            || self.approvals.statement != approval_statement(self.known_at())
            || self.approvals.plan.snapshot_seq != self.known_at()
            || self.approvals.snapshot_identity != basis.snapshot_identity
            || self.approvals.database_identity != basis.database_identity
        {
            return Err(invalid(
                "approval read is not the same certified native snapshot",
            ));
        }
        if encode_run(&self.report)? != self.output {
            return Err(invalid("procedure output record differs"));
        }
        let supplementary = if self.extended_inputs.is_empty() {
            0
        } else {
            4 + self
                .extended_inputs
                .iter()
                .map(|input| 4 + input.canonical_bytes().len())
                .sum::<usize>()
        };
        let total = source
            .len()
            .checked_add(native.len())
            .and_then(|n| n.checked_add(self.output.len()))
            .and_then(|n| {
                n.checked_add(4 + self.format().len() + 4 * 3 + 32 * 3 + 16 + supplementary)
            })
            .ok_or_else(|| invalid("procedure certificate length overflow"))?;
        if total > MAX_PROCEDURE_CERTIFICATE_BYTES {
            return Err(invalid("procedure certificate exceeds 64 MiB"));
        }
        let mut w = Writer::with_capacity(total);
        w.bytes(self.format()).bytes(&source).bytes(&native);
        if !self.extended_inputs.is_empty() {
            w.list(&self.extended_inputs, |w, input| {
                w.bytes(&input.canonical_bytes());
            });
        }
        w.fixed(&self.registry)
            .u128(self.producer.0)
            .fixed(&self.capability_commitment)
            .bytes(&self.output);
        w.finish().map_err(encode_error)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut bytes = self.body()?;
        if domain_digest(CERTIFICATE_DOMAIN, &[&bytes]) != self.digest {
            return Err(invalid("procedure certificate digest differs"));
        }
        bytes.extend_from_slice(&self.digest);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_PROCEDURE_CERTIFICATE_BYTES {
            return Err(invalid("procedure certificate exceeds 64 MiB"));
        }
        let mut r = Reader::new(bytes);
        let format = r
            .bytes(64, "procedure certificate format")
            .map_err(decode_error)?;
        if format != PROCEDURE_CERTIFICATE_FORMAT && format != extended::FORMAT {
            return Err(invalid("unsupported procedure certificate version"));
        }
        let source = ReportCertificate::decode(
            r.bytes(MAX_PROCEDURE_CERTIFICATE_BYTES, "native source")
                .map_err(decode_error)?,
        )?;
        let approvals = NativeResultCertificate::decode(
            r.bytes(MAX_NATIVE, "approval source")
                .map_err(decode_error)?,
        )
        .map_err(|_| invalid("malformed native approval source"))?;
        let mut extended_inputs = Vec::new();
        if format == extended::FORMAT {
            let count = r
                .count(extended::COUNT, "extended native inputs")
                .map_err(decode_error)?;
            if count != extended::COUNT {
                return Err(invalid("incomplete extended native input closure"));
            }
            for _ in 0..count {
                extended_inputs.push(
                    NativeResultCertificate::decode(
                        r.bytes(MAX_NATIVE, "extended native source")
                            .map_err(decode_error)?,
                    )
                    .map_err(|_| invalid("malformed extended native input"))?,
                );
            }
        }
        let registry = r.fixed("registry").map_err(decode_error)?;
        let producer = VId(r.u128("producer").map_err(decode_error)?);
        let capability_commitment = r.fixed("capability commitment").map_err(decode_error)?;
        let output = r
            .bytes(MAX_OUTPUT, "procedure output")
            .map_err(decode_error)?
            .to_vec();
        let report = decode_run(&output)?;
        let digest = r.fixed("certificate digest").map_err(decode_error)?;
        r.finish().map_err(decode_error)?;
        let certificate = Self {
            source,
            approvals,
            extended_inputs,
            registry,
            producer,
            capability_commitment,
            report,
            output,
            digest,
        };
        if certificate.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical procedure certificate"));
        }
        Ok(certificate)
    }
    fn request(&self) -> Result<ProcedureRequest, Refusal> {
        if !supported(&self.report.procedure, self.report.version)
            && !extended::supported(&self.report.procedure, self.report.version)
        {
            return Err(invalid(
                "this procedure version has no complete registered native certificate closure",
            ));
        }
        let current = registry_digest()?;
        if self.registry != current && self.registry != legacy_registry_digest() {
            return Err(crate::certificate::registry_unavailable(
                "procedure certificate",
                &self.registry,
                &current,
                PROCEDURE_REGISTRIES,
            ));
        }
        let mut request = ProcedureRequest::new(&self.report.procedure, catalog::Inputs::default())
            .map_err(lantern_error)?;
        let row = fa_lantern::bind(&self.report.procedure).map_err(lantern_error)?;
        if row.version != self.report.version
            || row.claim != self.report.claim
            || row.evidence != self.report.evidence
            || request
                .parameters
                .values()
                .iter()
                .map(|(k, _)| k)
                .collect::<Vec<_>>()
                != self
                    .report
                    .parameters
                    .iter()
                    .map(|(k, _)| k)
                    .collect::<Vec<_>>()
        {
            return Err(invalid(
                "procedure identity, claim, evidence or full parameter set has changed",
            ));
        }
        for (name, value) in &self.report.parameters {
            request.parameters = request
                .parameters
                .set(name, *value)
                .map_err(lantern_error)?;
        }
        for (name, value) in &self.report.inputs {
            if value.len() != 32
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid("noncanonical procedure handle"));
            }
            let id = VId(u128::from_str_radix(value, 16).map_err(|_| invalid("procedure handle"))?);
            match name.as_str() {
                "account" => request.inputs.account = Some(id),
                "source" => request.inputs.source = Some(id),
                _ => return Err(invalid("unsupported procedure input")),
            }
        }
        let built = catalog::build(
            &request.procedure,
            request.parameters.clone(),
            request.inputs,
        )
        .map_err(lantern_error)?;
        if built.inputs() != self.report.inputs {
            return Err(invalid("procedure declared handles differ"));
        }
        request.known_at = Some(self.known_at());
        request.effective_through = self.report.coordinate.effective_through;
        Ok(request)
    }
}

fn authorize<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    produce: bool,
) -> Outcome<()> {
    if let Err(denial) = fa_policy::admit_read(capability, principal, book.context().book_id)
        .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
        .and_then(|()| {
            if produce {
                fa_policy::require(capability, Op::Produce, "certifying a procedure")
            } else {
                Ok(())
            }
        })
    {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    book.query(cx, |db, context| {
        let head = db.frontier().map_err(KernelError::from)?;
        if let Err(denial) = fa_policy::current(capability, head) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        Ok(fa_journal::policy::capability_admitted(
            db, context, capability,
        )?)
    })
}

/// Approval objects are immutable, outside the posting Entry accumulator.
/// Their historical payload is also required to remain unchanged at HEAD.
fn unchanged_approvals<V: Vfs + Clone>(db: &Database<V>, snapshot: &Snapshot) -> Outcome<()> {
    use fa_journal::rows::bytes;
    let head = db.frontier().map_err(KernelError::from)?;
    let mut seen = BTreeSet::new();
    for entry in &snapshot.entries {
        for cited in &entry.entry.approvals {
            if !seen.insert(cited.approval_vid) {
                continue;
            }
            let Some(old) = db
                .vertex_at(cited.approval_vid, snapshot.coordinate.known_at)
                .map_err(KernelError::from)?
            else {
                return Ok(Err(invalid("historical procedure approval is missing")));
            };
            let Some(now) = db
                .vertex_at(cited.approval_vid, head)
                .map_err(KernelError::from)?
            else {
                return Ok(Err(invalid("procedure approval was retired")));
            };
            let old_payload = bytes(&old, property::FA_PAYLOAD, "approval payload")?;
            let old_digest = bytes(&old, property::FA_DIGEST, "approval digest")?;
            let approval = fa_policy::Approval::decode(&old_payload)
                .map_err(|e| BookError::Kernel(KernelError::Model(e.into())))?;
            let digest = approval
                .digest()
                .map_err(|e| BookError::Kernel(KernelError::Model(e.into())))?;
            if !old.labels.contains(&label::APPROVAL)
                || now.labels != old.labels
                || now.created_at != old.created_at
                || approval.book_id != snapshot.coordinate.book_id
                || old_digest.as_slice() != digest
                || approval.approved_proposal_digest != cited.approved_digest
                || fa_journal::policy::approval_vid(
                    approval.book_id,
                    approval.principal,
                    &approval.approved_proposal_digest,
                    approval.security_policy_epoch,
                ) != cited.approval_vid
                || bytes(&now, property::FA_PAYLOAD, "current approval payload")? != old_payload
                || bytes(&now, property::FA_DIGEST, "current approval digest")? != old_digest
            {
                return Ok(Err(invalid(
                    "a procedure approval was rebound or rewritten",
                )));
            }
        }
    }
    Ok(Ok(()))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Compute and certify a catalog procedure without publishing any record.
    /// Canonical bytes can be saved by the host and replayed after restarting.
    pub fn certify_procedure(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &ProcedureRequest,
    ) -> Outcome<CertifiedProcedure> {
        if let Err(r) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(r));
        }
        let built = match catalog::build(
            &request.procedure,
            request.parameters.clone(),
            request.inputs,
        ) {
            Ok(p) => p,
            Err(e) => return Ok(Err(lantern_error(e))),
        };
        let row = fa_lantern::bind(built.id())?;
        if !supported(&row.id, row.version) && !extended::supported(&row.id, row.version) {
            return Ok(Err(invalid(
                "this procedure version has no complete registered native certificate closure; ordinary procedure execution is unchanged",
            )));
        }
        for (name, present) in [
            ("account", request.inputs.account.is_some()),
            ("source", request.inputs.source.is_some()),
        ] {
            if present != row.inputs.iter().any(|i| i.name == name) {
                return Ok(Err(invalid(
                    "procedure handles must exactly match its declared inputs",
                )));
            }
        }
        let result = self.query(cx, |db, book| {
            let source = match crate::certificate::certify_report(
                db,
                &cx.query(),
                book,
                ReportSelection::OpenItems { account: None },
                request.known_at,
            )? {
                Ok(s) => s.certificate,
                Err(r) => return Ok(Err(r)),
            };
            let (_, approvals) = db
                .execute_certified(
                    &cx.query(),
                    &approval_statement(source.known_at),
                    &GqlParameters::new(),
                    book.symbols.clone(),
                    policy(),
                )
                .map_err(BookError::CertifiedRead)?;
            let extended_inputs = if extended::supported(&row.id, row.version) {
                extended::capture(db, cx, book, source.known_at)?
            } else {
                Vec::new()
            };
            let snapshot =
                Snapshot::read(db, book, Some(source.known_at), request.effective_through)?;
            if !extended_inputs.is_empty()
                && let Err(r) = extended::unchanged_attestations(db, cx, &snapshot)?
            {
                return Ok(Err(r));
            }
            if let Err(r) = unchanged_approvals(db, &snapshot)? {
                return Ok(Err(r));
            }
            let report = fa_lantern::run_over(&snapshot, book, built.as_ref())?;
            let output = match encode_run(&report) {
                Ok(b) => b,
                Err(r) => return Ok(Err(r)),
            };
            let registry = match registry_digest() {
                Ok(closure) => closure,
                Err(r) => return Ok(Err(r)),
            };
            let mut certificate = ProcedureCertificate {
                source,
                approvals,
                extended_inputs,
                registry,
                producer: principal,
                capability_commitment: capability
                    .commitment()
                    .map_err(|e| BookError::Kernel(KernelError::Corrupt(e.to_string())))?,
                report: report.clone(),
                output,
                digest: [0; 32],
            };
            let body = match certificate.body() {
                Ok(b) => b,
                Err(r) => return Ok(Err(r)),
            };
            certificate.digest = domain_digest(CERTIFICATE_DOMAIN, &[&body]);
            Ok(Ok(CertifiedProcedure {
                report,
                certificate,
            }))
        })?;
        if let Err(r) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(r));
        }
        Ok(result)
    }

    /// Replay the fixed native inputs, the extra approval closure and the exact
    /// algorithm/output. A later legitimate post cannot move the saved basis.
    pub fn replay_procedure(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &ProcedureCertificate,
    ) -> Outcome<ProcedureRun> {
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        if certificate.book_id() != self.context().book_id {
            return Ok(Err(invalid(
                "procedure certificate belongs to another book",
            )));
        }
        if let Err(r) = certificate.canonical_bytes() {
            return Ok(Err(r));
        }
        let request = match certificate.request() {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        let built = catalog::build(&request.procedure, request.parameters, request.inputs)?;
        let result = self.query(cx, |db, book| {
            if let Err(r) =
                crate::certificate::replay_report(db, &cx.query(), book, &certificate.source)?
            {
                return Ok(Err(r));
            }
            if let Err(e) = db.replay(
                &cx.query(),
                &certificate.approvals,
                &GqlParameters::new(),
                book.symbols.clone(),
                policy(),
            ) {
                return Ok(Err(invalid(format!(
                    "native approval read does not replay: {e}"
                ))));
            }
            if let Err(r) = extended::replay(db, cx, book, certificate)? {
                return Ok(Err(r));
            }
            let snapshot = Snapshot::read(
                db,
                book,
                Some(certificate.known_at()),
                request.effective_through,
            )?;
            if !certificate.extended_inputs.is_empty()
                && let Err(r) = extended::unchanged_attestations(db, cx, &snapshot)?
            {
                return Ok(Err(r));
            }
            if let Err(r) = unchanged_approvals(db, &snapshot)? {
                return Ok(Err(r));
            }
            let report = fa_lantern::run_over(&snapshot, book, built.as_ref())?;
            let actual = match encode_run(&report) {
                Ok(b) => b,
                Err(r) => return Ok(Err(r)),
            };
            if actual != certificate.output {
                return Ok(Err(invalid(
                    "procedure output, decision card or work transcript does not replay exactly",
                )));
            }
            Ok(Ok(report))
        })?;
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
