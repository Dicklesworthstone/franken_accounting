//! Retained-history certificates for summary-account trial balances.
//!
//! The source is an existing `ReportCertificate`, including its native chart,
//! journal, period, migration and unit read closure. The outer certificate
//! binds the summary root selector and exact summary bytes. Replay first
//! verifies that source against the retained book, then rebuilds the historical
//! forest and every summary group. A digest alone is never a successful replay.
//!
//! This is local retained-history recomputation, not an independently trusted
//! checkpoint, a signature, or an outsider completeness proof. Producing an
//! artifact requires current whole-book read and produce authority; replay
//! requires current whole-book read authority. Neither operation writes.

use asupersync::fs::Vfs;
use fa_journal::{KernelError, Refusal, exit};
use fa_model::{DecodeError, EncodeError, Id128, Reader, Writer, domain_digest};
use fa_policy::{Capability, Op};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{
    AsyncBook, BookError, Outcome, ReportCertificate, ReportSelection, SummaryRequest,
    SummaryScope, SummaryTrialBalance, TrialBalanceSelection,
};

pub const CERTIFICATE_FORMAT: &[u8] = b"fa:summary-certificate:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:summary-certificate-digest:v1";
pub const MAX_SUMMARY_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_ROOTS: usize = 65_536;

/// A composed certificate. The complete source certificate remains available
/// for inspection, but no caller can mutate it through this object's API.
/// Decoding checks canonical structure and digests, NOT historical validity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryCertificate {
    source: ReportCertificate,
    scope: SummaryScope,
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedSummaryTrialBalance {
    pub report: SummaryTrialBalance,
    pub certificate: SummaryCertificate,
}

fn invalid(why: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        why,
        "plan §4.3 / §5.6 / §13.6 (summary membership and exact output must replay)",
        "recreate the summary certificate from the original book and selector; preserve its historical chart, journal and source certificate",
    )
}

fn encoding(error: EncodeError) -> BookError {
    KernelError::Model(error.into()).into()
}

fn canonical_scope(scope: &SummaryScope) -> Result<SummaryScope, Refusal> {
    match scope {
        SummaryScope::AllRoots => Ok(SummaryScope::AllRoots),
        SummaryScope::Selected(roots) => {
            if roots.len() > MAX_ROOTS {
                return Err(invalid("summary root selection exceeds the format limit"));
            }
            let mut roots = roots.clone();
            roots.sort_unstable();
            if roots.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(invalid("summary root selection contains a duplicate"));
            }
            Ok(SummaryScope::Selected(roots))
        }
    }
}

fn write_scope(w: &mut Writer, scope: &SummaryScope) {
    match scope {
        SummaryScope::AllRoots => {
            w.u8(0);
        }
        SummaryScope::Selected(roots) => {
            w.u8(1).list(roots, |w, root| {
                w.u128(root.0);
            });
        }
    }
}

fn read_scope(r: &mut Reader<'_>) -> Result<SummaryScope, DecodeError> {
    match r.u8("summary scope")? {
        0 => Ok(SummaryScope::AllRoots),
        1 => {
            let count = r.count(MAX_ROOTS, "summary roots")?;
            if count > r.remaining() / 16 {
                return Err(r.invalid("truncated summary root list"));
            }
            let mut roots = Vec::with_capacity(count);
            for _ in 0..count {
                roots.push(VId(r.u128("summary root")?));
            }
            if roots.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(r.invalid("summary roots must be strictly increasing"));
            }
            Ok(SummaryScope::Selected(roots))
        }
        tag => Err(r.bad_tag("summary scope", tag)),
    }
}

impl SummaryCertificate {
    #[must_use]
    pub fn source_certificate(&self) -> &ReportCertificate {
        &self.source
    }

    #[must_use]
    pub fn scope(&self) -> &SummaryScope {
        &self.scope
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
    pub fn known_at(&self) -> CommitSeq {
        self.source.known_at
    }

    #[must_use]
    pub fn book_id(&self) -> Id128 {
        self.source.book_id
    }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        if self.output.len() > MAX_SUMMARY_CERTIFICATE_BYTES
            || !self.output.starts_with(crate::summary::OUTPUT_FORMAT)
        {
            return Err(invalid("unsupported or oversized summary output"));
        }
        if self.source.branch_id != Id128::TRUNK
            || self.source.time_selection.is_some()
            || !matches!(&self.source.selection, ReportSelection::TrialBalance(_))
        {
            return Err(invalid("a v1 summary needs a sequence-selected trunk trial-balance source"));
        }
        if canonical_scope(&self.scope)? != self.scope {
            return Err(invalid("noncanonical summary root order"));
        }
        let source = self.source.canonical_bytes().map_err(|e| invalid(e.to_string()))?;
        // A ReportCertificate's public fields can be changed by an embedding.
        // Its encoder is not validation. Use the existing bounded decoder to
        // check its own complete closure, selector and both stored digests.
        ReportCertificate::decode(&source)?;
        let scope_bytes = match &self.scope {
            SummaryScope::AllRoots => 1,
            SummaryScope::Selected(roots) => roots.len().checked_mul(16)
                .and_then(|length| length.checked_add(5))
                .ok_or_else(|| invalid("summary selector length overflow"))?,
        };
        let size = [4, CERTIFICATE_FORMAT.len(), 4, source.len(), scope_bytes,
            4, self.output.len(), 32]
            .into_iter()
            .try_fold(0usize, |total, part| total.checked_add(part))
            .ok_or_else(|| invalid("summary certificate length overflow"))?;
        if size > MAX_SUMMARY_CERTIFICATE_BYTES {
            return Err(invalid("summary certificate exceeds the 64 MiB total format limit"));
        }
        let mut w = Writer::with_capacity(size);
        w.bytes(CERTIFICATE_FORMAT).bytes(&source);
        write_scope(&mut w, &self.scope);
        w.bytes(&self.output);
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    fn seal(source: ReportCertificate, scope: SummaryScope, output: Vec<u8>) -> Result<Self, Refusal> {
        let mut value = Self {
            source,
            scope: canonical_scope(&scope)?,
            output,
            digest: [0; 32],
        };
        value.digest = domain_digest(DIGEST_DOMAIN, &[&value.body_bytes()?]);
        Ok(value)
    }

    /// Canonical, bounded portable bytes. This checks framing and content
    /// integrity; only replay checks the retained source and summary meaning.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut body = self.body_bytes()?;
        if domain_digest(DIGEST_DOMAIN, &[&body]) != self.digest {
            return Err(invalid("summary certificate content digest does not match"));
        }
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_SUMMARY_CERTIFICATE_BYTES {
            return Err(invalid("summary certificate exceeds the 64 MiB total format limit"));
        }
        let read = || -> Result<Self, Refusal> {
            let malformed = |error: DecodeError| invalid(format!("malformed summary certificate: {error}"));
            let mut r = Reader::new(bytes);
            if r.bytes(64, "summary certificate format").map_err(malformed)? != CERTIFICATE_FORMAT {
                return Err(invalid("unsupported summary certificate format"));
            }
            let source_bytes = r.bytes(MAX_SUMMARY_CERTIFICATE_BYTES, "source certificate")
                .map_err(malformed)?;
            let source = ReportCertificate::decode(source_bytes)?;
            let scope = read_scope(&mut r).map_err(malformed)?;
            let output = r.bytes(MAX_SUMMARY_CERTIFICATE_BYTES, "summary output")
                .map_err(malformed)?.to_vec();
            let digest = r.fixed("summary certificate digest").map_err(malformed)?;
            r.finish().map_err(malformed)?;
            Ok(Self { source, scope, output, digest })
        };
        let value = read()?;
        // In addition to checking the digest, reject any alternate encoding.
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical summary certificate encoding"));
        }
        Ok(value)
    }

    fn request(&self) -> Result<SummaryRequest, Refusal> {
        let ReportSelection::TrialBalance(selection) = &self.source.selection else {
            return Err(invalid("summary source is not a trial balance"));
        };
        Ok(SummaryRequest {
            selection: selection.clone(),
            scope: self.scope.clone(),
            known_at: Some(self.known_at()),
        })
    }
}

fn authorize<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    produce: bool,
) -> Outcome<()> {
    let context = book.context();
    let admitted = fa_policy::admit_read(capability, principal, context.book_id)
        .and_then(|()| {
            if produce {
                fa_policy::require(capability, Op::Produce, "certifying summary reports")
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
        Ok(fa_journal::policy::capability_admitted(&book.db, context, capability)?)
    })
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Certify exactly the summary returned at one recorded frontier. The
    /// source certificate binds the complete native input closure, including
    /// immutable chart declarations, rather than only the aggregate amounts.
    /// Empty period selectors are resolved before retaining the source.
    pub fn certify_summary_trial_balance(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &SummaryRequest,
    ) -> Outcome<CertifiedSummaryTrialBalance> {
        if let Err(refusal) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(refusal));
        }
        let scope = match canonical_scope(&request.scope) {
            Ok(scope) => scope,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let report = match self.summary_trial_balance(cx, principal, capability, request)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let selection = match &request.selection {
            TrialBalanceSelection::Periods(_) => TrialBalanceSelection::Periods(report.source.periods.clone()),
            TrialBalanceSelection::Activity(_) => TrialBalanceSelection::Activity(report.source.periods.clone()),
            TrialBalanceSelection::AsOf(day) => TrialBalanceSelection::AsOf(*day),
        };
        let certified = match self.certify_trial_balance(cx, selection, Some(report.source.known_at))? {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if certified.report != report.source {
            return Ok(Err(invalid("summary and certified source do not reproduce the same leaf fold")));
        }
        let output = report.canonical_bytes().map_err(encoding)?;
        let certificate = match SummaryCertificate::seal(certified.certificate, scope, output) {
            Ok(certificate) => certificate,
            Err(refusal) => return Ok(Err(refusal)),
        };
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(CertifiedSummaryTrialBalance { report, certificate }))
    }

    /// Check the source's retained historical reads and exact leaf fold,
    /// then independently rebuild group membership and summary amounts at
    /// that same known-at. Current capabilities cannot be taken from the
    /// artifact. A later posting or chart installation never moves its basis.
    pub fn replay_summary_trial_balance(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &SummaryCertificate,
    ) -> Outcome<SummaryTrialBalance> {
        if let Err(refusal) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(refusal));
        }
        if certificate.book_id() != self.context().book_id {
            return Ok(Err(invalid("summary certificate belongs to another book")));
        }
        if let Err(refusal) = certificate.canonical_bytes() {
            return Ok(Err(refusal));
        }
        let source = match self.replay_trial_balance(cx, certificate.source_certificate())? {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let request = match certificate.request() {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let report = match self.summary_trial_balance(cx, principal, capability, &request)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if report.source != source || report.canonical_bytes().map_err(encoding)? != certificate.output {
            return Ok(Err(invalid("summary membership or exact output differs from the certificate")));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_scope_has_one_encoding_and_distinguishes_empty_from_all() {
        let all = SummaryScope::AllRoots;
        let empty = SummaryScope::Selected(Vec::new());
        let sorted = canonical_scope(&SummaryScope::Selected(vec![VId(9), VId(1)])).unwrap();
        assert_eq!(sorted, SummaryScope::Selected(vec![VId(1), VId(9)]));
        let mut encodings = Vec::new();
        for scope in [all, empty, sorted] {
            let mut w = Writer::new();
            write_scope(&mut w, &scope);
            let bytes = w.finish().unwrap();
            let mut r = Reader::new(&bytes);
            assert_eq!(read_scope(&mut r).unwrap(), scope);
            r.finish().unwrap();
            encodings.push(bytes);
        }
        assert_ne!(encodings[0], encodings[1]);
        assert!(canonical_scope(&SummaryScope::Selected(vec![VId(1), VId(1)])).is_err());
        for roots in [vec![VId(9), VId(1)], vec![VId(1), VId(1)]] {
            let mut w = Writer::new();
            write_scope(&mut w, &SummaryScope::Selected(roots));
            assert!(read_scope(&mut Reader::new(&w.finish().unwrap())).is_err());
        }
    }

    #[test]
    fn malformed_frames_and_hostile_root_counts_are_refused() {
        for bytes in [vec![], vec![0], vec![255; 32]] {
            assert!(SummaryCertificate::decode(&bytes).is_err());
        }
        let mut w = Writer::new();
        w.u8(1).u32(u32::MAX);
        assert!(read_scope(&mut Reader::new(&w.finish().unwrap())).is_err());
        let mut w = Writer::new();
        w.u8(1).u32(2).u128(1);
        assert!(read_scope(&mut Reader::new(&w.finish().unwrap())).is_err());
        assert!(read_scope(&mut Reader::new(&[2])).is_err());
    }
}
