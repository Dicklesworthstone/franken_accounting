//! Two independently replayed statement sources plus their exact bridge.
//!
//! Decoding validates the bounded container and both source certificates, not
//! the historical claim. Replay must succeed for BOTH sources and reproduce
//! the complete bridge. The producer/capability fields are unsigned provenance,
//! never authority to read a book. This format makes no case-approval, issuance,
//! signature, outsider-completeness or economic-truth claim.

use asupersync::fs::Vfs;
use fa_journal::{KernelError, Refusal, exit};
use fa_model::{DecodeError, Id128, Reader, Writer, domain_digest};
use fa_policy::{Capability, Op};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use super::{StatementDiff, StatementDiffRequest};
use crate::{
    AsyncBook, BookError, Outcome, ReportCertificate, ReportOutput, ReportSelection, Statement,
};

pub const CERTIFICATE_FORMAT: &[u8] = b"fa:statement-diff-certificate:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:statement-diff-certificate-digest:v1";
pub const MAX_STATEMENT_DIFF_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementDiffCertificate {
    before: ReportCertificate,
    after: ReportCertificate,
    producer: VId,
    capability_commitment: [u8; 32],
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedStatementDiff {
    pub report: StatementDiff,
    pub certificate: StatementDiffCertificate,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §8.3 / §12.5 / §13.6 (both historical statements and the complete bridge must replay)",
        "retain both source certificates and their original book history; replay the complete comparison, not only its deltas or one source",
    )
}

fn sources(before: &ReportCertificate, after: &ReportCertificate) -> Result<(), Refusal> {
    if before.book_id != after.book_id
        || before.branch_id != Id128::TRUNK
        || after.branch_id != Id128::TRUNK
        || before.known_at > after.known_at
        || before.time_selection.is_some()
        || after.time_selection.is_some()
        || before.selection != after.selection
        || !matches!(&before.selection, ReportSelection::Statement(_))
    {
        return Err(invalid(
            "comparison sources must be the same sequence-selected trunk statement at ordered frontiers",
        ));
    }
    Ok(())
}

fn statement(output: ReportOutput) -> Result<Statement, Refusal> {
    match output {
        ReportOutput::Statement(statement) => Ok(*statement),
        _ => Err(invalid(
            "comparison source replay did not produce a financial statement",
        )),
    }
}

fn total(parts: impl IntoIterator<Item = usize>) -> Result<usize, Refusal> {
    let size = parts
        .into_iter()
        .try_fold(0usize, |sum, part| sum.checked_add(part))
        .ok_or_else(|| invalid("statement comparison length overflow"))?;
    if size > MAX_STATEMENT_DIFF_CERTIFICATE_BYTES {
        return Err(invalid(
            "statement comparison exceeds the 64 MiB portable format bound",
        ));
    }
    Ok(size)
}

fn output_bytes(report: &StatementDiff) -> Result<Vec<u8>, Refusal> {
    // Price the exact output before serializing. It contains three amount
    // vectors per line; limiting either source alone would not bound the bridge.
    let mut size = total([
        4,
        super::OUTPUT_FORMAT.len(),
        16,
        16,
        8,
        8,
        32,
        32,
        32,
        4,
        4,
        4,
    ])?;
    for c in &report.before().columns {
        size = total([
            size,
            4,
            c.label.len(),
            4,
            1,
            usize::from(c.effective_from.is_some()) * 4,
            4,
        ])?;
        for period in &c.periods {
            size = total([size, 4, period.len()])?;
        }
    }
    for l in report.lines() {
        size = total([size, 24, l.code.len(), l.label.len(), l.before.len() * 48])?;
    }
    for c in report.mapping_changes() {
        size = total([size, 16, 1, 1])?;
        for m in [c.before.as_ref(), c.after.as_ref()].into_iter().flatten() {
            size = total([
                size,
                30,
                m.account.code.len(),
                m.account.name.len(),
                m.line_code.len(),
            ])?;
        }
    }
    let bytes = report
        .canonical_bytes()
        .map_err(|e| invalid(e.to_string()))?;
    if bytes.len() != size {
        return Err(invalid(
            "statement comparison output length does not match its encoding",
        ));
    }
    Ok(bytes)
}

impl StatementDiffCertificate {
    #[must_use]
    pub fn sources(&self) -> (&ReportCertificate, &ReportCertificate) {
        (&self.before, &self.after)
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
    #[must_use]
    pub fn book_id(&self) -> Id128 {
        self.before.book_id
    }

    pub fn request(&self) -> Result<StatementDiffRequest, Refusal> {
        sources(&self.before, &self.after)?;
        let ReportSelection::Statement(selection) = &self.before.selection else {
            return Err(invalid("comparison sources are not financial statements"));
        };
        Ok(StatementDiffRequest {
            selection: (**selection).clone(),
            before: self.before.known_at,
            after: Some(self.after.known_at),
        })
    }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        sources(&self.before, &self.after)?;
        if self.output.len() > MAX_STATEMENT_DIFF_CERTIFICATE_BYTES {
            return Err(invalid("oversized comparison output"));
        }
        let mut r = Reader::new(&self.output);
        if r.bytes(64, "statement comparison output format")
            .map_err(|e| invalid(e.to_string()))?
            != super::OUTPUT_FORMAT
        {
            return Err(invalid("unsupported comparison output format"));
        }
        let before = self
            .before
            .canonical_bytes()
            .map_err(|e| invalid(e.to_string()))?;
        let after = self
            .after
            .canonical_bytes()
            .map_err(|e| invalid(e.to_string()))?;
        let size = total([
            4,
            CERTIFICATE_FORMAT.len(),
            16,
            32,
            4,
            before.len(),
            4,
            after.len(),
            4,
            self.output.len(),
            32,
        ])?;
        // Their public fields can be changed by an embedding: encoding is not
        // validation. Retain the source decoders' own closure/digest checks.
        ReportCertificate::decode(&before)?;
        ReportCertificate::decode(&after)?;
        let mut w = Writer::with_capacity(size);
        w.bytes(CERTIFICATE_FORMAT)
            .u128(self.producer.0)
            .fixed(&self.capability_commitment)
            .bytes(&before)
            .bytes(&after)
            .bytes(&self.output);
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    fn seal(
        before: ReportCertificate,
        after: ReportCertificate,
        producer: VId,
        capability_commitment: [u8; 32],
        output: Vec<u8>,
    ) -> Result<Self, Refusal> {
        let mut value = Self {
            before,
            after,
            producer,
            capability_commitment,
            output,
            digest: [0; 32],
        };
        value.digest = domain_digest(DIGEST_DOMAIN, &[&value.body_bytes()?]);
        Ok(value)
    }

    /// Canonical bounded container. Source membership and the bridge's meaning
    /// are established by replay, never by this unsigned content digest alone.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut bytes = self.body_bytes()?;
        if domain_digest(DIGEST_DOMAIN, &[&bytes]) != self.digest {
            return Err(invalid("statement comparison certificate digest mismatch"));
        }
        bytes.extend_from_slice(&self.digest);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        total([bytes.len()])?;
        let malformed =
            |e: DecodeError| invalid(format!("malformed statement comparison certificate: {e}"));
        let mut r = Reader::new(bytes);
        if r.bytes(64, "comparison certificate format")
            .map_err(malformed)?
            != CERTIFICATE_FORMAT
        {
            return Err(invalid(
                "unsupported statement comparison certificate format",
            ));
        }
        let producer = VId(r.u128("comparison producer").map_err(malformed)?);
        let capability_commitment = r
            .fixed::<32>("comparison capability commitment")
            .map_err(malformed)?;
        let before = ReportCertificate::decode(
            r.bytes(MAX_STATEMENT_DIFF_CERTIFICATE_BYTES, "before source")
                .map_err(malformed)?,
        )?;
        let after = ReportCertificate::decode(
            r.bytes(MAX_STATEMENT_DIFF_CERTIFICATE_BYTES, "after source")
                .map_err(malformed)?,
        )?;
        let output = r
            .bytes(MAX_STATEMENT_DIFF_CERTIFICATE_BYTES, "comparison output")
            .map_err(malformed)?
            .to_vec();
        let digest = r.fixed::<32>("comparison digest").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let value = Self {
            before,
            after,
            producer,
            capability_commitment,
            output,
            digest,
        };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical statement comparison certificate"));
        }
        Ok(value)
    }
}

fn authorize<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    produce: bool,
) -> Outcome<CommitSeq> {
    let context = book.context();
    let admitted = fa_policy::admit_read(capability, principal, context.book_id).and_then(|()| {
        if produce {
            fa_policy::require(capability, Op::Produce, "certifying statement comparisons")
        } else {
            Ok(())
        }
    });
    if let Err(denial) = admitted {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    let query = cx.query();
    query.checkpoint().map_err(BookError::Context)?;
    query.with_restriction(|| {
        let head = book.db.frontier().map_err(KernelError::from)?;
        if let Err(denial) = fa_policy::current(capability, head) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if let Err(refusal) =
            fa_journal::policy::capability_admitted(&book.db, context, capability)?
        {
            return Ok(Err(refusal));
        }
        Ok(Ok(head))
    })
}

fn resolved(
    request: &StatementDiffRequest,
    head: CommitSeq,
) -> Result<StatementDiffRequest, Refusal> {
    let after = request.after.unwrap_or(head);
    if request.before > after || after > head {
        return Err(super::invalid(
            "comparison needs before <= after <= observed book head",
        ));
    }
    let selection = request.selection.clone().normalize();
    if !selection.is_canonical() {
        return Err(super::invalid(
            "comparison needs a nonempty canonical statement selection",
        ));
    }
    Ok(StatementDiffRequest {
        selection,
        before: request.before,
        after: Some(after),
    })
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Read the same stock/activity statement at two fixed recorded frontiers.
    /// No write, implicit issue date, current-time substitute or rounding occurs.
    pub fn statement_diff(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &StatementDiffRequest,
    ) -> Outcome<StatementDiff> {
        let head = match authorize(self, cx, principal, capability, false)? {
            Ok(head) => head,
            Err(r) => return Ok(Err(r)),
        };
        let request = match resolved(request, head) {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        let before = match self.statement(cx, request.selection.clone(), Some(request.before))? {
            Ok(s) => s,
            Err(r) => return Ok(Err(r)),
        };
        let after = match self.statement(cx, request.selection, request.after)? {
            Ok(s) => s,
            Err(r) => return Ok(Err(r)),
        };
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(StatementDiff::between(before, after))
    }

    /// Produce both complete native source certificates and the exact bridge.
    /// The current caller must hold read+produce before ANY book observation.
    pub fn certify_statement_diff(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &StatementDiffRequest,
    ) -> Outcome<CertifiedStatementDiff> {
        let head = match authorize(self, cx, principal, capability, true)? {
            Ok(head) => head,
            Err(r) => return Ok(Err(r)),
        };
        let request = match resolved(request, head) {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        let before =
            match self.certify_statement(cx, request.selection.clone(), Some(request.before))? {
                Ok(s) => s,
                Err(r) => return Ok(Err(r)),
            };
        let after = match self.certify_statement(cx, request.selection, request.after)? {
            Ok(s) => s,
            Err(r) => return Ok(Err(r)),
        };
        let report = match StatementDiff::between(before.statement, after.statement) {
            Ok(report) => report,
            Err(r) => return Ok(Err(r)),
        };
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(package(
            report,
            before.certificate,
            after.certificate,
            principal,
            capability,
        ))
    }

    /// Replay both retained sources in full and bridge them. Neither frontier
    /// nor definition is replaced with HEAD. The caller has admitted authority.
    fn retained_statement_diff(
        &self,
        cx: &PurposeContexts,
        before: &ReportCertificate,
        after: &ReportCertificate,
    ) -> Outcome<StatementDiff> {
        if let Err(r) = sources(before, after) {
            return Ok(Err(r));
        }
        let old = match self.replay_report(cx, before)?.and_then(statement) {
            Ok(s) => s,
            Err(r) => return Ok(Err(r)),
        };
        let new = match self.replay_report(cx, after)?.and_then(statement) {
            Ok(s) => s,
            Err(r) => return Ok(Err(r)),
        };
        let report = match StatementDiff::between(old, new) {
            Ok(d) => d,
            Err(r) => return Ok(Err(r)),
        };
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }

    /// Read the bridge between previously retained statements under current
    /// read authority. Both source claims are replayed in full first; nothing
    /// is certified or written.
    pub fn diff_statement_certificates(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        before: &ReportCertificate,
        after: &ReportCertificate,
    ) -> Outcome<StatementDiff> {
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        self.retained_statement_diff(cx, before, after)
    }

    /// Compare previously retained statements without replacing their frontiers
    /// or definitions with HEAD. Both source claims are replayed in full first.
    pub fn compare_statement_certificates(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        before: &ReportCertificate,
        after: &ReportCertificate,
    ) -> Outcome<CertifiedStatementDiff> {
        if let Err(r) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(r));
        }
        let report = match self.retained_statement_diff(cx, before, after)? {
            Ok(d) => d,
            Err(r) => return Ok(Err(r)),
        };
        Ok(package(
            report,
            before.clone(),
            after.clone(),
            principal,
            capability,
        ))
    }

    /// Verify both source closures, refold both statements and reconstruct all
    /// rows and mapping changes. Certificate provenance NEVER grants authority.
    pub fn replay_statement_diff(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &StatementDiffCertificate,
    ) -> Outcome<StatementDiff> {
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        if certificate.book_id() != self.context().book_id {
            return Ok(Err(invalid("comparison belongs to another book")));
        }
        if let Err(r) = certificate.canonical_bytes() {
            return Ok(Err(r));
        }
        let before = match self
            .replay_report(cx, &certificate.before)?
            .and_then(statement)
        {
            Ok(s) => s,
            Err(r) => return Ok(Err(r)),
        };
        let after = match self
            .replay_report(cx, &certificate.after)?
            .and_then(statement)
        {
            Ok(s) => s,
            Err(r) => return Ok(Err(r)),
        };
        let report = match StatementDiff::between(before, after) {
            Ok(d) => d,
            Err(r) => return Ok(Err(invalid(r.message))),
        };
        let output = match output_bytes(&report) {
            Ok(bytes) => bytes,
            Err(r) => return Ok(Err(r)),
        };
        if output != certificate.output {
            return Ok(Err(invalid(
                "both sources replayed but the statement comparison output differs",
            )));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }
}

fn package(
    report: StatementDiff,
    before: ReportCertificate,
    after: ReportCertificate,
    principal: VId,
    capability: &Capability,
) -> Result<CertifiedStatementDiff, Refusal> {
    let commitment = capability
        .commitment()
        .map_err(|e| invalid(e.to_string()))?;
    let output = output_bytes(&report)?;
    let certificate = StatementDiffCertificate::seal(before, after, principal, commitment, output)?;
    Ok(CertifiedStatementDiff {
        report,
        certificate,
    })
}

#[cfg(test)]
#[path = "certificate_tests.rs"]
mod tests;
