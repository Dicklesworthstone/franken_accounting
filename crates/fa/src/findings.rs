//! Immutable, replay-backed Finding vertices (plan §11.8).
//!
//! The complete procedure certificate must already be retained. One native
//! transaction publishes a run index, its findings and every CITES edge. Small
//! locator records refer to the original certificate rather than truncating or
//! copying its findings into another storage format. An empty run has an index
//! too. Exact retries verify the entire publication and return its original
//! sequence; missing or rewritten records are never repaired.
//!
//! These records preserve observations, not accusations or review decisions.
//! Ordered, repeated citations (including tracing paths) remain in the original
//! certificate; graph CITES edges are the distinct-target membership projection.

pub mod review;
pub mod lookup;
pub use lookup::RecordedFinding;
pub mod workpaper;
pub use workpaper::{FindingWorkpaper, FINDING_WORKPAPER_FORMAT, MAX_FINDING_WORKPAPER_BYTES};

use std::collections::BTreeSet;

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_journal::rows::{edge_id, leg_vid, prop, scalar_bytes};
use fa_journal::{KernelError, Refusal, exit};
use fa_lantern::{Cite, ProcedureRun};
use fa_model::symbols::{label, property, relation};
use fa_model::{Id128, Writer, domain_digest};
use fa_policy::{Capability, Op};
use fgdb::{Database, WriteBatch, WriteError, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::{AsyncBook, BookError, Outcome, ProcedureCertificate, ReportArtifactFamily};

pub const FINDING_RUN_FORMAT: &[u8] = b"fa:finding-run:v1";
pub const FINDING_RECORD_FORMAT: &[u8] = b"fa:finding-record:v1";
pub const MAX_RECORDED_FINDINGS: usize = 4096;
pub const MAX_RECORDED_CITATIONS: usize = 65536;

/// One complete, checked publication. The report is always recomputed from its
/// retained native certificate before being returned. Public fields are output
/// only: none of the recording or exporting APIs accept this as authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedFindings {
    pub run_vid: VId,
    pub certificate_digest: [u8; 32],
    pub recorded_at: CommitSeq,
    pub producer: VId,
    /// Same order as report.findings, including separate identical observations.
    pub finding_ids: Vec<VId>,
    pub report: ProcedureRun,
}

pub(crate) fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID, exit::VERIFICATION, message,
        "plan §11.8; FA-INV-02/10/11 (immutable finding publication and native replay)",
        "retain and replay the original complete procedure certificate with current whole-book authority; preserve damaged records instead of repairing them",
    )
}

fn vid(domain: &[u8], book: Id128, digest: &[u8; 32], suffix: &[u8]) -> VId {
    let hash = domain_digest(domain, &[&book.0, digest, suffix]);
    let mut low = [0; 16];
    low.copy_from_slice(&hash[..16]);
    VId(u128::from_le_bytes(low))
}

/// Stable run identity for an exact certificate, not for a mutable procedure id.
#[must_use]
pub fn finding_run_vid(book: Id128, certificate: &[u8; 32]) -> VId {
    vid(b"fa:vid:finding-run:v1", book, certificate, &[])
}

/// Stable zero-based occurrence identity in the certificate's ordered findings.
#[must_use]
pub fn finding_vid(book: Id128, certificate: &[u8; 32], ordinal: u32) -> VId {
    vid(b"fa:vid:finding:v1", book, certificate, &ordinal.to_le_bytes())
}

pub(crate) fn authorize<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>, cx: &PurposeContexts, principal: VId,
    capability: &Capability, produce: bool,
) -> Outcome<()> {
    if let Err(denial) = fa_policy::admit_read(capability, principal, book.context().book_id)
        .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
        .and_then(|()| if produce {
            fa_policy::require(capability, Op::Produce, "publishing or exporting findings")
        } else { Ok(()) })
    {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    book.query(cx, |db, context| {
        let head = db.frontier().map_err(KernelError::from)?;
        if let Err(denial) = fa_policy::current(capability, head) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        Ok(fa_journal::policy::capability_admitted(db, context, capability)?)
    })
}

struct Record {
    vid: VId,
    digest: [u8; 32],
    payload: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Link {
    cite: bool,
    from: VId,
    to: VId,
}

struct Prepared {
    records: Vec<Record>,
    links: BTreeSet<Link>,
    certificate_vid: VId,
    certificate: ProcedureCertificate,
}

fn encoded(writer: Writer) -> Result<Vec<u8>, Refusal> {
    writer.finish().map_err(|e| invalid(format!("finding record encoding: {e}")))
}

fn target(cite: &Cite, book: &BookContext) -> VId {
    match cite {
        Cite::Entry(v) | Cite::Account(v) | Cite::Principal(v) | Cite::Approval(v) => *v,
        Cite::Leg { entry, ordinal } => leg_vid(*entry, *ordinal),
        Cite::Document(oid) => fa_journal::evidence::document_vid(oid),
        Cite::Period(code) => fa_model::period_vid(&book.calendar.id, code),
    }
}

impl Prepared {
    fn new(certificate: ProcedureCertificate, book: &BookContext) -> Result<Self, Refusal> {
        let report = certificate.report();
        if report.findings.len() > MAX_RECORDED_FINDINGS {
            return Err(invalid("the complete run exceeds MAX_RECORDED_FINDINGS; no partial publication"));
        }
        let citations = report.findings.iter().try_fold(0usize, |n, f| n.checked_add(f.cites.len()));
        if citations.is_none_or(|n| n > MAX_RECORDED_CITATIONS) {
            return Err(invalid("the complete run exceeds MAX_RECORDED_CITATIONS; no partial publication"));
        }
        let digest = certificate.digest();
        let run = finding_run_vid(book.book_id, digest);
        let cvid = crate::certificate_store::certificate_vid(book.book_id, digest);
        let mut w = Writer::new();
        w.fixed(FINDING_RUN_FORMAT).fixed(&book.book_id.0).fixed(digest)
            .u32(report.findings.len() as u32).fixed(&report.findings_digest);
        let payload = encoded(w)?;
        let mut records = vec![Record {
            vid: run, digest: domain_digest(b"fa:finding-record-digest:v1", &[&payload]), payload,
        }];
        let mut links = BTreeSet::from([Link { cite: false, from: run, to: cvid }]);
        let mut identities = BTreeSet::from([run, cvid]);
        for (ordinal, finding) in report.findings.iter().enumerate() {
            let fvid = finding_vid(book.book_id, digest, ordinal as u32);
            if !identities.insert(fvid) { return Err(invalid("finding identity collision")); }
            let bytes = finding.canonical_bytes().map_err(|e| invalid(format!("finding: {e}")))?;
            let value_digest = domain_digest(b"fa:finding-value:v1", &[&bytes]);
            let mut w = Writer::new();
            w.fixed(FINDING_RECORD_FORMAT).fixed(&book.book_id.0).fixed(digest)
                .u32(ordinal as u32).fixed(&value_digest);
            let payload = encoded(w)?;
            records.push(Record {
                vid: fvid, digest: domain_digest(b"fa:finding-record-digest:v1", &[&payload]), payload,
            });
            links.insert(Link { cite: false, from: fvid, to: run });
            for cite in &finding.cites {
                links.insert(Link { cite: true, from: fvid, to: target(cite, book) });
            }
        }
        Ok(Self { records, links, certificate_vid: cvid, certificate })
    }

    fn result(&self, recorded_at: CommitSeq) -> RecordedFindings {
        RecordedFindings {
            run_vid: self.records[0].vid,
            certificate_digest: *self.certificate.digest(), recorded_at,
            producer: self.certificate.producer(),
            finding_ids: self.records[1..].iter().map(|r| r.vid).collect(),
            report: self.certificate.report().clone(),
        }
    }

    /// Compare against the certified output, not just against untrusted mirrors.
    /// A version's predecessor distinguishes first birth from byte restoration.
    fn verify<V: Vfs + Clone>(
        &self, db: &Database<V>, cx: &PurposeContexts, book: &BookContext, at: CommitSeq,
    ) -> Outcome<RecordedFindings> {
        let Some(root) = db.vertex_at(self.records[0].vid, at).map_err(KernelError::from)? else {
            return Ok(Err(invalid("finding run is not recorded or has been retired")));
        };
        let birth = root.created_at;
        let Some(before) = birth.0.checked_sub(1).map(CommitSeq) else {
            return Ok(Err(invalid("finding run has no original birth")));
        };
        let Some(source) = db.vertex_at(self.certificate_vid, before).map_err(KernelError::from)? else {
            return Ok(Err(invalid("the full certificate must be retained before its findings")));
        };
        if !source.labels.contains(&label::CERTIFICATE) || birth <= self.certificate.known_at() {
            return Ok(Err(invalid("finding publication precedes its certified source")));
        }
        for record in &self.records {
            cx.query().checkpoint().map_err(BookError::Context)?;
            let Some(row) = db.vertex_at(record.vid, at).map_err(KernelError::from)? else {
                return Ok(Err(invalid("incomplete finding run: a finding is missing or retired")));
            };
            if row.created_at != birth || row.retired_at.is_some()
                || row.labels.as_slice() != [label::FINDING] || row.props.len() != 3
                || !matches!(prop(&row, property::BOOK_ID), Some(CanonicalScalar::Bytes(b)) if b.as_slice() == book.book_id.0)
                || !matches!(prop(&row, property::FA_DIGEST), Some(CanonicalScalar::Bytes(b)) if b.as_slice() == record.digest)
                || !matches!(prop(&row, property::FA_PAYLOAD), Some(CanonicalScalar::Bytes(b)) if b.as_slice() == record.payload)
                || db.vertex_at(record.vid, before).map_err(KernelError::from)?.is_some()
                || db.vertex_at(record.vid, birth).map_err(KernelError::from)?.as_ref() != Some(&row)
            {
                return Ok(Err(invalid("finding record was rewritten, rebound, or separately published")));
            }
        }
        for link in &self.links {
            cx.query().checkpoint().map_err(BookError::Context)?;
            let rel = if link.cite { relation::CITES } else { relation::DERIVED_FROM };
            let id = edge_id(rel, link.from, link.to);
            let Some(edge) = db.edge_at(id, at).map_err(KernelError::from)? else {
                return Ok(Err(invalid("a required finding citation or lineage edge is missing")));
            };
            if edge.entry.src != link.from || edge.entry.dst != link.to
                || edge.entry.relation != rel || edge.entry.created_at != birth
                || edge.entry.retired_at.is_some() || !edge.props.is_empty()
                || db.edge_at(id, before).map_err(KernelError::from)?.is_some()
                || db.edge_at(id, birth).map_err(KernelError::from)?.as_ref() != Some(&edge)
            {
                return Ok(Err(invalid("finding citation was rewritten, rebound, or separately published")));
            }
        }
        Ok(Ok(self.result(birth)))
    }
}

fn refused_write<T>(error: WriteTxnError) -> Outcome<T> {
    match error {
        WriteTxnError::Write(WriteError::AlreadyLive { .. } | WriteError::IdentitySpent { .. }) =>
            Ok(Err(invalid("a finding or citation identity is already used; no overwrite or repair"))),
        WriteTxnError::Write(WriteError::FirstCommitterWins { detail, .. }) =>
            Ok(Err(Refusal::new(fa_journal::refusal::code::CONFLICT, exit::CONFLICT,
                format!("finding publication witness changed: {detail}"), "FG-LAW-FCW-01",
                "retry the complete run with its same retained certificate"))),
        other => Err(KernelError::from(other).into()),
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    async fn prepared_findings(
        &self, cx: &PurposeContexts, principal: VId, capability: &Capability, digest: &[u8; 32],
    ) -> Outcome<Prepared> {
        let artifact = match self.read_report_artifact(cx, principal, capability, digest).await? {
            Ok(a) => a, Err(r) => return Ok(Err(r)),
        };
        if artifact.family() != ReportArtifactFamily::Procedure {
            return Ok(Err(invalid("findings require a complete retained procedure certificate")));
        }
        let bytes = match artifact.canonical_bytes() { Ok(b) => b, Err(r) => return Ok(Err(r)) };
        let certificate = match ProcedureCertificate::decode(&bytes) { Ok(c) => c, Err(r) => return Ok(Err(r)) };
        let prepared = match Prepared::new(certificate, self.context()) { Ok(p) => p, Err(r) => return Ok(Err(r)) };
        if let Err(r) = self.replay_procedure(cx, principal, capability, &prepared.certificate)? { return Ok(Err(r)); }
        let report = prepared.certificate.report();
        let valid = self.query(cx, |db, book| {
            for finding in &report.findings {
                for cite in &finding.cites {
                    cx.query().checkpoint().map_err(BookError::Context)?;
                    if !cite.resolves(db, book, report.coordinate.known_at)? {
                        return Ok(Err(invalid("a certified finding citation does not resolve at its source coordinate")));
                    }
                }
            }
            Ok(Ok(()))
        })?;
        if let Err(r) = valid { return Ok(Err(r)); }
        Ok(Ok(prepared))
    }

    /// Atomically record every finding and its graph citations. The certificate
    /// must first be retained through retain_report_artifact. This operation does
    /// not post an accounting Entry, mutate the certificate, or mark anything reviewed.
    pub async fn record_findings(
        &mut self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        certificate_digest: &[u8; 32],
    ) -> Outcome<RecordedFindings> {
        if let Err(r) = authorize(self, cx, principal, capability, true)? { return Ok(Err(r)); }
        let at = self.head(cx)?;
        let prepared = match self.prepared_findings(cx, principal, capability, certificate_digest).await? {
            Ok(p) => p, Err(r) => return Ok(Err(r)),
        };
        let mut txn = self.db.begin(&cx.txn()).map_err(KernelError::from)?;
        if txn.basis() != at {
            txn.abort();
            return Ok(Err(Refusal::new(fa_journal::refusal::code::CONFLICT, exit::CONFLICT,
                "book changed after finding replay", "FA-INV-10/11", "retry the same complete run")));
        }
        if let Err(d) = fa_policy::current(capability, txn.basis()) {
            txn.abort(); return Ok(Err(fa_journal::policy::refusal(&d)));
        }
        if let Err(r) = fa_journal::policy::capability_witness(&txn, &self.db, self.context(), capability)? {
            txn.abort(); return Ok(Err(r));
        }
        fa_journal::policy::epoch_witness(&txn, &self.db)?;
        if txn.vertex(&self.db, prepared.records[0].vid).map_err(KernelError::from)?.is_some() {
            txn.abort();
            return self.query(cx, |db, book| prepared.verify(db, cx, book, at));
        }
        let mut derived = WriteBatch::new(relation::DERIVED_FROM);
        let mut citations = WriteBatch::new(relation::CITES);
        for record in &prepared.records {
            cx.query().checkpoint().map_err(BookError::Context)?;
            if txn.vertex(&self.db, record.vid).map_err(KernelError::from)?.is_some() {
                txn.abort(); return Ok(Err(invalid("orphan finding record; refusing partial-run repair")));
            }
            let mut props = vec![
                (property::FA_PAYLOAD, scalar_bytes("finding payload", record.payload.clone())?),
                (property::FA_DIGEST, scalar_bytes("finding digest", record.digest.to_vec())?),
                (property::BOOK_ID, scalar_bytes("finding book", self.context().book_id.0.to_vec())?),
            ];
            props.sort_by_key(|(key, _)| key.0);
            derived.create_vertex(record.vid, vec![label::FINDING], props);
        }
        for link in &prepared.links {
            cx.query().checkpoint().map_err(BookError::Context)?;
            if (link.cite || link.to == prepared.certificate_vid)
                && txn.vertex(&self.db, link.to).map_err(KernelError::from)?.is_none()
            {
                txn.abort(); return Ok(Err(invalid("finding citation target is no longer live")));
            }
            let (rel, batch) = if link.cite { (relation::CITES, &mut citations) }
                else { (relation::DERIVED_FROM, &mut derived) };
            batch.add_edge(edge_id(rel, link.from, link.to), link.from, link.to, vec![]);
        }
        // CITES depends on the vertices created by DERIVED_FROM's batch.
        // The substrate's ordinary write() deliberately rejects introducing a
        // second relation; ordered staging preserves one atomic publication.
        let batches = if prepared.links.iter().any(|link| link.cite) {
            vec![derived, citations]
        } else {
            vec![derived]
        };
        if let Err(e) = txn.write_ordered(&mut self.db, batches) {
            txn.abort();
            return refused_write(e);
        }
        cx.commit().checkpoint().map_err(BookError::Context)?;
        match txn.commit(&mut self.db, &cx.commit()).await {
            Ok(seq) => Ok(Ok(prepared.result(seq))), Err(e) => refused_write(e),
        }
    }

    /// Read the entire run by full certificate digest, under current authority.
    /// Verifies original record births and every required graph edge, then returns
    /// the exact certificate-replayed observations; never a mutable graph cache.
    pub async fn read_findings(
        &self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        certificate_digest: &[u8; 32],
    ) -> Outcome<RecordedFindings> {
        if let Err(r) = authorize(self, cx, principal, capability, false)? { return Ok(Err(r)); }
        let prepared = match self.prepared_findings(cx, principal, capability, certificate_digest).await? {
            Ok(p) => p, Err(r) => return Ok(Err(r)),
        };
        let result = self.query(cx, |db, book| {
            prepared.verify(db, cx, book, db.frontier().map_err(KernelError::from)?)
        })?;
        if let Err(r) = authorize(self, cx, principal, capability, false)? { return Ok(Err(r)); }
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
