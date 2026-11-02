//! Retain and replay every snapshot behind a publication trace.
//!
//! Endpoint-only certificates cannot authenticate intermediate history. This
//! container therefore retains a ReportCertificate for EVERY sequence, including
//! the initial frontier and zero-effect publications. Replay verifies them all,
//! refolds their statements, reconstructs historical entry links and compares
//! every output byte. The unsigned producer fields never confer authority.

use asupersync::fs::Vfs;
use fa_journal::{Refusal, exit};
use fa_model::{DecodeError, Id128, Reader, Writer, domain_digest};
use fa_policy::Capability;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use super::{
    Builder, CustomStatementTraceRequest, MAX_STATEMENT_TRACE_PUBLICATIONS, SourceRequest,
    StatementTrace, StatementTraceRequest, authorize, publication_entries, resolve_interval,
    resolved,
};
use crate::{
    AsyncBook, BookError, CertifiedStatement, Outcome, ReportCertificate, ReportOutput,
    ReportSelection, Statement, StatementDiffCertificate, StatementDiffRequest,
};

pub const CERTIFICATE_FORMAT: &[u8] = b"fa:statement-trace-certificate:v1";
pub const FUNCTIONAL_CERTIFICATE_FORMAT: &[u8] = b"fa:functional-statement-trace-certificate:v1";
pub const CUSTOM_CERTIFICATE_FORMAT: &[u8] = b"fa:custom-statement-trace-certificate:v1";
pub const FUNCTIONAL_CUSTOM_CERTIFICATE_FORMAT: &[u8] =
    b"fa:functional-custom-statement-trace-certificate:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:statement-trace-certificate-digest:v1";
const FUNCTIONAL_DIGEST_DOMAIN: &[u8] = b"fa:functional-statement-trace-certificate-digest:v1";
const CUSTOM_DIGEST_DOMAIN: &[u8] = b"fa:custom-statement-trace-certificate-digest:v1";
const FUNCTIONAL_CUSTOM_DIGEST_DOMAIN: &[u8] =
    b"fa:functional-custom-statement-trace-certificate-digest:v1";
pub const MAX_STATEMENT_TRACE_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_SOURCES: usize = MAX_STATEMENT_TRACE_PUBLICATIONS + 1;

#[path = "export.rs"]
mod export;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementTraceCertificate {
    sources: Vec<ReportCertificate>,
    producer: VId,
    capability_commitment: [u8; 32],
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedStatementTrace {
    pub report: StatementTrace,
    pub certificate: StatementTraceCertificate,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §8.3 / §12.5 / §13.6 (all intermediate statement sources and attribution must replay)",
        "retain the complete original source chain and book history; replay all publications, not just the net comparison or the outer digest",
    )
}

fn total(parts: impl IntoIterator<Item = usize>) -> Result<usize, Refusal> {
    let size = parts
        .into_iter()
        .try_fold(0usize, |sum, part| sum.checked_add(part))
        .ok_or_else(|| invalid("statement trace certificate length overflow"))?;
    if size > MAX_STATEMENT_TRACE_CERTIFICATE_BYTES {
        return Err(invalid(
            "statement trace certificate exceeds its aggregate 64 MiB bound",
        ));
    }
    Ok(size)
}

fn family(sources: &[ReportCertificate]) -> Result<(), Refusal> {
    let Some(first) = sources.first() else {
        return Err(invalid("a trace must retain its initial source"));
    };
    if sources.len() > MAX_SOURCES
        || !matches!(
            &first.selection,
            ReportSelection::Statement(_)
                | ReportSelection::FunctionalStatement(_)
                | ReportSelection::CustomStatement(_)
        )
    {
        return Err(invalid("a trace needs 1..=257 financial statement sources"));
    }
    for (index, source) in sources.iter().enumerate() {
        if source.book_id != first.book_id
            || source.branch_id != Id128::TRUNK
            || source.time_selection.is_some()
            || source.selection != first.selection
            || first.known_at.0.checked_add(index as u64) != Some(source.known_at.0)
        {
            return Err(invalid(
                "trace sources must be the same trunk statement and valuation basis at every consecutive sequence",
            ));
        }
    }
    Ok(())
}

fn statement(output: ReportOutput) -> Result<Statement, Refusal> {
    match output {
        ReportOutput::Statement(statement) | ReportOutput::FunctionalStatement(statement) => {
            Ok(*statement)
        }
        // Source replay verifies the complete presentation. Attribution is
        // always over the exact underlying statement, never rounded amounts.
        ReportOutput::CustomStatement(report) => Ok(report.statement),
        _ => Err(invalid(
            "a trace source replay did not produce a financial statement",
        )),
    }
}

impl StatementTraceCertificate {
    #[must_use]
    pub fn is_custom(&self) -> bool {
        self.sources
            .first()
            .is_some_and(|source| matches!(&source.selection, ReportSelection::CustomStatement(_)))
    }

    #[must_use]
    pub fn uses_functional_valuations(&self) -> bool {
        self.sources
            .iter()
            .any(|source| source.selection.uses_functional_valuations())
    }

    #[must_use]
    pub fn format(&self) -> &'static [u8] {
        match (self.is_custom(), self.uses_functional_valuations()) {
            (false, false) => CERTIFICATE_FORMAT,
            (false, true) => FUNCTIONAL_CERTIFICATE_FORMAT,
            (true, false) => CUSTOM_CERTIFICATE_FORMAT,
            (true, true) => FUNCTIONAL_CUSTOM_CERTIFICATE_FORMAT,
        }
    }

    #[must_use]
    pub fn output_format(&self) -> &'static [u8] {
        match (self.is_custom(), self.uses_functional_valuations()) {
            (false, false) => super::OUTPUT_FORMAT,
            (false, true) => super::FUNCTIONAL_OUTPUT_FORMAT,
            (true, false) => super::CUSTOM_OUTPUT_FORMAT,
            (true, true) => super::FUNCTIONAL_CUSTOM_OUTPUT_FORMAT,
        }
    }

    fn digest_domain(&self) -> &'static [u8] {
        match (self.is_custom(), self.uses_functional_valuations()) {
            (false, false) => DIGEST_DOMAIN,
            (false, true) => FUNCTIONAL_DIGEST_DOMAIN,
            (true, false) => CUSTOM_DIGEST_DOMAIN,
            (true, true) => FUNCTIONAL_CUSTOM_DIGEST_DOMAIN,
        }
    }

    #[must_use]
    pub fn sources(&self) -> &[ReportCertificate] {
        &self.sources
    }
    #[must_use]
    pub fn producer(&self) -> VId {
        self.producer
    }
    #[must_use]
    pub fn capability_commitment(&self) -> &[u8; 32] {
        &self.capability_commitment
    }
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The complete, identical question retained by every source certificate.
    pub fn report_selection(&self) -> Result<ReportSelection, Refusal> {
        family(&self.sources)?;
        Ok(self.sources[0].selection.clone())
    }

    pub fn request(&self) -> Result<StatementTraceRequest, Refusal> {
        family(&self.sources)?;
        let first = &self.sources[0];
        let last = &self.sources[self.sources.len() - 1];
        let selection = match &first.selection {
            ReportSelection::Statement(selection)
            | ReportSelection::FunctionalStatement(selection) => selection,
            _ => {
                return Err(invalid(
                    "custom trace sources require the complete report_selection",
                ));
            }
        };
        Ok(StatementTraceRequest {
            comparison: StatementDiffRequest {
                selection: (**selection).clone(),
                before: first.known_at,
                after: Some(last.known_at),
            },
            // The generation limit is a work admission parameter, not a claim
            // about accounting. The retained complete interval fixes replay work.
            max_publications: MAX_STATEMENT_TRACE_PUBLICATIONS,
        })
    }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        family(&self.sources)?;
        total([self.output.len()])?;
        let mut r = Reader::new(&self.output);
        if r.bytes(64, "trace output format")
            .map_err(|e| invalid(e.to_string()))?
            != self.output_format()
        {
            return Err(invalid("unsupported statement trace output format"));
        }
        // Includes the final digest, which is appended only after hashing body.
        let mut length = total([92, self.format().len(), self.output.len()])?;
        let mut sources = Vec::with_capacity(self.sources.len());
        for source in &self.sources {
            let bytes = source
                .canonical_bytes()
                .map_err(|e| invalid(e.to_string()))?;
            length = total([length, 4, bytes.len()])?;
            // Public ReportCertificate fields are not trusted merely because
            // they can be encoded. Preserve their own bounded decoder checks.
            ReportCertificate::decode(&bytes)?;
            sources.push(bytes);
        }
        let mut w = Writer::with_capacity(length);
        w.bytes(self.format())
            .u128(self.producer.0)
            .fixed(&self.capability_commitment)
            .list(&sources, |w, source| {
                w.bytes(source);
            })
            .bytes(&self.output);
        let body = w.finish().map_err(|e| invalid(e.to_string()))?;
        if body.len().checked_add(32) != Some(length) {
            return Err(invalid("trace certificate framing length mismatch"));
        }
        Ok(body)
    }

    fn seal(
        sources: Vec<ReportCertificate>,
        producer: VId,
        capability_commitment: [u8; 32],
        output: Vec<u8>,
    ) -> Result<Self, Refusal> {
        let mut certificate = Self {
            sources,
            producer,
            capability_commitment,
            output,
            digest: [0; 32],
        };
        certificate.digest =
            domain_digest(certificate.digest_domain(), &[&certificate.body_bytes()?]);
        Ok(certificate)
    }

    /// Canonical outer framing and source containers, not historical validity.
    /// The bounded output is an opaque claim until complete semantic replay.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut bytes = self.body_bytes()?;
        if domain_digest(self.digest_domain(), &[&bytes]) != self.digest {
            return Err(invalid("statement trace certificate digest mismatch"));
        }
        bytes.extend_from_slice(&self.digest);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        total([bytes.len()])?;
        let malformed =
            |e: DecodeError| invalid(format!("malformed statement trace certificate: {e}"));
        let mut r = Reader::new(bytes);
        let format = r.bytes(64, "trace certificate format").map_err(malformed)?;
        if ![
            CERTIFICATE_FORMAT,
            FUNCTIONAL_CERTIFICATE_FORMAT,
            CUSTOM_CERTIFICATE_FORMAT,
            FUNCTIONAL_CUSTOM_CERTIFICATE_FORMAT,
        ]
        .contains(&format)
        {
            return Err(invalid("unsupported statement trace certificate format"));
        }
        let producer = VId(r.u128("trace producer").map_err(malformed)?);
        let capability_commitment = r
            .fixed::<32>("trace producer capability commitment")
            .map_err(malformed)?;
        let count = r.count(MAX_SOURCES, "trace sources").map_err(malformed)?;
        if count == 0 || count > r.remaining() / 4 {
            return Err(invalid("empty or truncated trace source chain"));
        }
        let mut sources = Vec::with_capacity(count);
        for _ in 0..count {
            sources.push(ReportCertificate::decode(
                r.bytes(MAX_STATEMENT_TRACE_CERTIFICATE_BYTES, "trace source")
                    .map_err(malformed)?,
            )?);
        }
        let output = r
            .bytes(MAX_STATEMENT_TRACE_CERTIFICATE_BYTES, "trace output")
            .map_err(malformed)?
            .to_vec();
        let digest = r.fixed::<32>("trace digest").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let certificate = Self {
            sources,
            producer,
            capability_commitment,
            output,
            digest,
        };
        if certificate.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical statement trace certificate"));
        }
        Ok(certificate)
    }
}

fn source_at<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    request: &SourceRequest,
    at: CommitSeq,
    endpoints: Option<(&ReportCertificate, &ReportCertificate)>,
) -> Outcome<CertifiedStatement> {
    let pinned = endpoints.and_then(|(before, after)| {
        if at == before.known_at {
            Some(before)
        } else if at == after.known_at {
            Some(after)
        } else {
            None
        }
    });
    if let Some(source) = pinned {
        return Ok(book
            .replay_report(cx, source)?
            .and_then(statement)
            .map(|statement| CertifiedStatement {
                statement,
                certificate: source.clone(),
            }));
    }
    // The caller has admitted authority and, for functional selections,
    // prepared complete retained Entry/Rate history before this source walk.
    // Reusing the exact full selection also retains the custom activation and
    // presentation at intermediate frontiers; no latest-layout lookup occurs.
    Ok(book
        .certify_report(cx, request.selection.clone(), Some(at))?
        .and_then(|source| {
            statement(source.report).map(|statement| CertifiedStatement {
                statement,
                certificate: source.certificate,
            })
        }))
}

fn source_frame_size(source: &ReportCertificate) -> Result<usize, Refusal> {
    let bytes = source
        .canonical_bytes()
        .map_err(|e| invalid(e.to_string()))?;
    total([4, bytes.len()])
}

/// Caller has already admitted current read+produce authority and resolved the
/// bounded interval. Saved endpoint certificates, when supplied, are reused
/// byte-for-byte and replayed; no fresh source silently replaces either one.
fn build<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    request: &SourceRequest,
    endpoints: Option<(&ReportCertificate, &ReportCertificate)>,
) -> Outcome<CertifiedStatementTrace> {
    let after = request.after;
    let functional = request.selection.uses_functional_valuations();
    let first = match source_at(book, cx, request, request.before, endpoints)? {
        Ok(s) => s,
        Err(r) => return Ok(Err(r)),
    };
    let mut source_bytes = match source_frame_size(&first.certificate) {
        Ok(n) => n,
        Err(r) => return Ok(Err(r)),
    };
    let mut builder = match Builder::with_basis(first.statement, after, functional) {
        Ok(b) => b,
        Err(r) => return Ok(Err(r)),
    };
    let mut sources = vec![first.certificate];
    let format = match (
        matches!(&request.selection, ReportSelection::CustomStatement(_)),
        functional,
    ) {
        (false, false) => CERTIFICATE_FORMAT,
        (false, true) => FUNCTIONAL_CERTIFICATE_FORMAT,
        (true, false) => CUSTOM_CERTIFICATE_FORMAT,
        (true, true) => FUNCTIONAL_CUSTOM_CERTIFICATE_FORMAT,
    };
    for offset in 1..=after.0 - request.before.0 {
        let at = CommitSeq(request.before.0 + offset);
        cx.query().checkpoint().map_err(BookError::Context)?;
        let next = match source_at(book, cx, request, at, endpoints)? {
            Ok(s) => s,
            Err(r) => return Ok(Err(r)),
        };
        source_bytes =
            match source_frame_size(&next.certificate).and_then(|n| total([source_bytes, n])) {
                Ok(n) => n,
                Err(r) => return Ok(Err(r)),
            };
        let entries = match publication_entries(book, cx, at)? {
            Ok(e) => e,
            Err(r) => return Ok(Err(r)),
        };
        if let Err(r) = builder.push(next.statement, entries) {
            return Ok(Err(r));
        }
        if let Err(r) = total([92, format.len(), source_bytes, builder.step_bytes]) {
            return Ok(Err(r));
        }
        sources.push(next.certificate);
    }
    let report = match builder.finish() {
        Ok(report) => report,
        Err(r) => return Ok(Err(r)),
    };
    let length = match report.encoded_len() {
        Ok(n) => n,
        Err(r) => return Ok(Err(r)),
    };
    if let Err(r) = total([92, format.len(), source_bytes, length]) {
        return Ok(Err(r));
    }
    let output = match report.canonical_bytes() {
        Ok(b) => b,
        Err(r) => return Ok(Err(r)),
    };
    let commitment = match capability.commitment() {
        Ok(d) => d,
        Err(e) => return Ok(Err(invalid(e.to_string()))),
    };
    cx.query().checkpoint().map_err(BookError::Context)?;
    Ok(
        StatementTraceCertificate::seal(sources, principal, commitment, output).map(
            |certificate| CertifiedStatementTrace {
                report,
                certificate,
            },
        ),
    )
}

fn request_from_diff(
    comparison: &StatementDiffCertificate,
    max_publications: usize,
    head: CommitSeq,
) -> Result<SourceRequest, Refusal> {
    let selection = comparison.report_selection()?;
    let (first, last) = comparison.sources();
    let after = resolve_interval(first.known_at, Some(last.known_at), max_publications, head)?;
    Ok(SourceRequest {
        selection,
        before: first.known_at,
        after,
    })
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Retain every historical native custom statement, including its exact
    /// reviewed activation and independently recomputed presentation.
    pub fn certify_custom_statement_trace(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &CustomStatementTraceRequest,
    ) -> Outcome<CertifiedStatementTrace> {
        let head = match authorize(self, cx, principal, capability, true)? {
            Ok(head) => head,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let request = match SourceRequest::custom(request, head, false) {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        build(self, cx, principal, capability, &request, None)
    }

    /// Retain every functional custom source under one complete approved
    /// selector. Historical Rate evidence is prepared before source evaluation.
    pub async fn certify_functional_custom_statement_trace(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &CustomStatementTraceRequest,
    ) -> Outcome<CertifiedStatementTrace> {
        let head = match self.admit_functional_report(cx, principal, capability, None, true)? {
            Ok(head) => head,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let request = match SourceRequest::custom(request, head, true) {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = self
            .prepare_functional_report(cx, principal, capability, Some(request.after), true)
            .await?
        {
            return Ok(Err(refusal));
        }
        let result = build(self, cx, principal, capability, &request, None)?;
        if let Err(refusal) =
            self.admit_functional_report(cx, principal, capability, Some(request.after), true)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Retain a source certificate for every adjacent frontier, not just the
    /// endpoints. Current read+produce authority precedes all observations.
    pub fn certify_statement_trace(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &StatementTraceRequest,
    ) -> Outcome<CertifiedStatementTrace> {
        let head = match authorize(self, cx, principal, capability, true)? {
            Ok(h) => h,
            Err(r) => return Ok(Err(r)),
        };
        let request = match resolved(request, head).and_then(|r| SourceRequest::builtin(r, false)) {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        build(self, cx, principal, capability, &request, None)
    }

    /// Certify every functional statement prefix, retaining the original
    /// valuation laws and Rate evidence at each frontier. The complete source
    /// chain is domain-separated from native-unit attribution.
    pub async fn certify_functional_statement_trace(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &StatementTraceRequest,
    ) -> Outcome<CertifiedStatementTrace> {
        let head = match self.admit_functional_report(cx, principal, capability, None, true)? {
            Ok(head) => head,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let request = match resolved(request, head).and_then(|r| SourceRequest::builtin(r, true)) {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = self
            .prepare_functional_report(cx, principal, capability, Some(request.after), true)
            .await?
        {
            return Ok(Err(refusal));
        }
        let result = build(self, cx, principal, capability, &request, None)?;
        if let Err(refusal) =
            self.admit_functional_report(cx, principal, capability, Some(request.after), true)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Add publication attribution to an EXISTING saved comparison. Replay the
    /// original bridge first, preserve both original endpoint certificates and
    /// certify every missing intermediate source. Later HEAD is never selected.
    pub fn certify_statement_trace_from_diff(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        comparison: &StatementDiffCertificate,
        max_publications: usize,
    ) -> Outcome<CertifiedStatementTrace> {
        let head = match authorize(self, cx, principal, capability, true)? {
            Ok(h) => h,
            Err(r) => return Ok(Err(r)),
        };
        if comparison.uses_functional_valuations() {
            return Ok(Err(invalid(
                "functional statement comparisons require certify_functional_statement_trace_from_diff to prepare their retained valuation history",
            )));
        }
        let request = match request_from_diff(comparison, max_publications, head) {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        let endpoints = comparison.sources();
        if endpoints.0.known_at == endpoints.1.known_at && endpoints.0 != endpoints.1 {
            return Ok(Err(invalid(
                "a zero-length trace cannot collapse distinct endpoint certificates",
            )));
        }
        let original = match self.replay_statement_diff(cx, principal, capability, comparison)? {
            Ok(report) => report,
            Err(r) => return Ok(Err(r)),
        };
        let certified = match build(self, cx, principal, capability, &request, Some(endpoints))? {
            Ok(value) => value,
            Err(r) => return Ok(Err(r)),
        };
        if certified.report.summary() != &original {
            return Ok(Err(invalid(
                "trace no longer reproduces the saved comparison",
            )));
        }
        Ok(Ok(certified))
    }

    /// Add complete publication attribution to an existing functional bridge.
    /// Both saved endpoint certificates are replayed and retained byte-for-byte;
    /// later postings and later Rate documents never replace either endpoint.
    pub async fn certify_functional_statement_trace_from_diff(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        comparison: &StatementDiffCertificate,
        max_publications: usize,
    ) -> Outcome<CertifiedStatementTrace> {
        let head = match self.admit_functional_report(cx, principal, capability, None, true)? {
            Ok(head) => head,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if !comparison.uses_functional_valuations() {
            return Ok(Err(invalid(
                "a functional publication trace requires a functional comparison; use certify_statement_trace_from_diff for native sources",
            )));
        }
        let request = match request_from_diff(comparison, max_publications, head) {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let endpoints = comparison.sources();
        if endpoints.0.known_at == endpoints.1.known_at && endpoints.0 != endpoints.1 {
            return Ok(Err(invalid(
                "a zero-length trace cannot collapse distinct endpoint certificates",
            )));
        }
        if let Err(refusal) = self
            .prepare_functional_report(cx, principal, capability, Some(request.after), true)
            .await?
        {
            return Ok(Err(refusal));
        }
        let original = match self.replay_statement_diff(cx, principal, capability, comparison)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let certified = match build(self, cx, principal, capability, &request, Some(endpoints))? {
            Ok(certified) => certified,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if certified.report.summary() != &original {
            return Ok(Err(invalid(
                "functional trace no longer reproduces the saved comparison",
            )));
        }
        if let Err(refusal) =
            self.admit_functional_report(cx, principal, capability, Some(request.after), true)?
        {
            return Ok(Err(refusal));
        }
        Ok(Ok(certified))
    }

    /// Verify EVERY original source, refold each historical statement,
    /// rebuild all publication metadata and compare the complete trace output.
    /// Neither a matching digest nor unchanged endpoint totals is sufficient.
    /// Functional sources require complete prepared history; cold callers use
    /// `replay_report_artifact_for_with_history` to hydrate it under authority.
    pub fn replay_statement_trace(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &StatementTraceCertificate,
    ) -> Outcome<StatementTrace> {
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        if certificate
            .sources
            .first()
            .is_none_or(|source| source.book_id != self.context().book_id)
        {
            return Ok(Err(invalid("statement trace has no source in this book")));
        }
        if let Err(r) = certificate.canonical_bytes() {
            return Ok(Err(r));
        }
        let first = match self
            .replay_report(cx, &certificate.sources[0])?
            .and_then(statement)
        {
            Ok(s) => s,
            Err(r) => return Ok(Err(r)),
        };
        let after = certificate.sources[certificate.sources.len() - 1].known_at;
        let mut builder =
            match Builder::with_basis(first, after, certificate.uses_functional_valuations()) {
                Ok(b) => b,
                Err(r) => return Ok(Err(invalid(r.message))),
            };
        for source in certificate.sources.iter().skip(1) {
            cx.query().checkpoint().map_err(BookError::Context)?;
            let next = match self.replay_report(cx, source)?.and_then(statement) {
                Ok(s) => s,
                Err(r) => return Ok(Err(r)),
            };
            let entries = match publication_entries(self, cx, source.known_at)? {
                Ok(e) => e,
                Err(r) => return Ok(Err(r)),
            };
            if let Err(r) = builder.push(next, entries) {
                return Ok(Err(invalid(r.message)));
            }
        }
        let report = match builder.finish() {
            Ok(r) => r,
            Err(r) => return Ok(Err(invalid(r.message))),
        };
        let output = match report.canonical_bytes() {
            Ok(b) => b,
            Err(r) => return Ok(Err(invalid(r.message))),
        };
        if output != certificate.output {
            return Ok(Err(invalid(
                "source chain replayed but publication attribution differs from the saved trace",
            )));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }
}

#[cfg(test)]
#[path = "certificate_tests.rs"]
mod tests;
