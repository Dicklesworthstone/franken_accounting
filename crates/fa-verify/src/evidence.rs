//! Journal-authenticated document disclosures (plan §9.6, §13.1–§13.3).
//!
//! An independently trusted checkpoint authenticates the requested entry;
//! that entry's evidence list, not the view's header, supplies the document
//! commitment. The recipient chooses the entry digest, document locator,
//! evidence role and exact chunk set independently of both artifacts.
//!
//! This composes existing inclusion proofs with either RedactedView v1 or
//! compact document-disclosure v1 exports. It
//! does not invent a bundle, accept an envelope-only citation, or upgrade
//! chunk membership to production completeness. The authenticated proposal
//! has its evidence list and remaining wire framing checked. Fields outside
//! the citation are not interpreted as accounting facts: full entry semantics,
//! accounting law, evidence minima, provenance and authorization are not checked.

use core::fmt;

use crate::blake3::hash_parts;
use crate::codec::{DecodeError, Reader, Reason};
use crate::disclosure::{self, DisclosureProofError, VerifiedDisclosure};
use crate::envelope::{
    MAX_ENVELOPE_LIST, MAX_RECORD_BYTES, RecordError, proposal_after_legs, skip_erasable,
};
use crate::proof::{Checkpoint, INCLUSION_FORMAT, Inclusion, RecordCheck, VerifyError};
use crate::redaction::{
    DisclosedChunk, MAX_VIEW_BYTES, MAX_VIEW_CHUNKS, ViewError, verify_view_for,
};

/// The same outer allocation/input policy as the standalone proof verifier.
pub const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
/// Appendix A / max_evidence_per_entry. Independent of producer code.
pub const MAX_EVIDENCE_PER_ENTRY: usize = 1024;
const DOCUMENT_OID_DOMAIN: &[u8] = b"fa:oid:document:v1";

pub mod inventory;

/// Recipient-owned question, never learned from the untrusted artifacts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceExpectation {
    pub entry_digest: [u8; 32],
    pub document_oid: [u8; 32],
    /// The exact evidence-role tag the entry must use for this document.
    /// Verifying the tag does not establish the truth of that role.
    pub role: u8,
}

/// A citation authenticated by the included entry's record digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceCitation {
    pub document_oid: [u8; 32],
    pub doc_commit: [u8; 32],
    pub role: u8,
}

/// All components succeeded before this report was returned. In particular,
/// neither a genuine but unrelated entry nor a genuine but uncited document
/// can be combined into a successful report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEvidenceView<'a> {
    /// Scope `inclusion`, with the entry payload recomputed.
    pub inclusion: Inclusion,
    pub citation: EvidenceCitation,
    /// Still `membership_only`, not complete production or evidence closure.
    pub disclosure_scope: &'static str,
    pub kind: u8,
    pub size: u64,
    /// Kernel-compatible artifact identity, computed rather than signed.
    pub view_commit: [u8; 32],
    pub disclosed: Vec<DisclosedChunk<'a>>,
    pub withheld_chunks: u64,
    /// A citation authenticates neither the redaction contract nor permission
    /// to disclose. Unlike this field, the view's original locator is bound
    /// to the authenticated citation and the book-scoped document identity.
    pub unverified_contract: u16,
}

/// A compact export authenticated through its entry citation. The compact
/// format carries no locator or contract metadata to mistake for authority.
/// Its report contains chunk metadata only, never document payload bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEvidenceDisclosure {
    pub inclusion: Inclusion,
    pub citation: EvidenceCitation,
    /// Scope remains `membership_only`, not completeness or provenance.
    pub disclosure: VerifiedDisclosure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    Proof(VerifyError),
    Decode(DecodeError),
    View(ViewError),
    Disclosure(DisclosureProofError),
    Request(&'static str),
    InputLimit,
    RecordRequired,
    EntryMismatch,
    CitationMissing,
    CitationAmbiguous,
    DocumentIdentity,
    ViewLocator,
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proof(error) => write!(f, "{error}"),
            Self::Decode(error) => write!(f, "{error}"),
            Self::View(error) => write!(f, "{error}"),
            Self::Disclosure(error) => write!(f, "{error}"),
            Self::Request(why) => write!(f, "invalid evidence disclosure request: {why}"),
            Self::InputLimit => write!(f, "inclusion proof exceeds the 64 MiB input bound"),
            Self::RecordRequired => write!(
                f,
                "evidence verification requires the entry payload inside the inclusion proof"
            ),
            Self::EntryMismatch => write!(
                f,
                "the included entry is not the recipient's requested entry digest"
            ),
            Self::CitationMissing => write!(
                f,
                "the included entry does not cite the requested document with that role"
            ),
            Self::CitationAmbiguous => write!(
                f,
                "the entry assigns multiple commitments to the requested document and role"
            ),
            Self::DocumentIdentity => write!(
                f,
                "the citation's commitment does not derive its locator in the checkpoint's book"
            ),
            Self::ViewLocator => write!(
                f,
                "the view names a different original locator than the authenticated citation"
            ),
        }
    }
}

impl core::error::Error for EvidenceError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Proof(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::View(error) => Some(error),
            Self::Disclosure(error) => Some(error),
            _ => None,
        }
    }
}

impl From<VerifyError> for EvidenceError {
    fn from(error: VerifyError) -> Self {
        Self::Proof(error)
    }
}

impl From<DecodeError> for EvidenceError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

impl From<ViewError> for EvidenceError {
    fn from(error: ViewError) -> Self {
        Self::View(error)
    }
}

impl From<DisclosureProofError> for EvidenceError {
    fn from(error: DisclosureProofError) -> Self {
        Self::Disclosure(error)
    }
}

/// Validate a recipient-owned kernel-view chunk set before reading artifacts.
/// It is not sorted, deduplicated, widened or derived from a view.
pub fn validate_request(requested: &[u64]) -> Result<(), EvidenceError> {
    if requested.is_empty() || requested.len() > MAX_VIEW_CHUNKS {
        return Err(EvidenceError::Request(
            "require one to MAX_VIEW_CHUNKS indices",
        ));
    }
    if requested.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(EvidenceError::Request("indices must be strictly ascending"));
    }
    if requested
        .last()
        .is_some_and(|index| *index >= MAX_VIEW_CHUNKS as u64)
    {
        return Err(EvidenceError::Request(
            "an index exceeds the document size bound",
        ));
    }
    Ok(())
}

/// Verify checkpoint → entry → evidence citation → requested view chunks.
///
/// The inclusion proof must carry its entry payload, in the existing v1
/// optional-record field. An envelope alone authenticates a record digest,
/// not its evidence list. Both artifacts are untrusted; only `checkpoint`
/// and the independently chosen `expected` / `requested` inputs are anchors.
/// Nothing here verifies checkpoint signatures or permission to export.
pub fn verify_evidence_view_for<'a>(
    proof: &[u8],
    view: &'a [u8],
    checkpoint: &Checkpoint,
    expected: &EvidenceExpectation,
    requested: &[u64],
) -> Result<VerifiedEvidenceView<'a>, EvidenceError> {
    validate_request(requested)?;
    if view.len() > MAX_VIEW_BYTES {
        return Err(ViewError::Bound("encoded bytes").into());
    }
    let (inclusion, citation) = authenticated_citation(proof, checkpoint, expected)?;
    let verified = verify_view_for(view, &citation.doc_commit, requested)?;
    if verified.unverified_metadata.original != citation.document_oid {
        return Err(EvidenceError::ViewLocator);
    }
    Ok(VerifiedEvidenceView {
        inclusion,
        citation,
        disclosure_scope: verified.scope,
        kind: verified.kind,
        size: verified.size,
        view_commit: verified.view_commit,
        disclosed: verified.disclosed,
        withheld_chunks: verified.withheld_chunks,
        unverified_contract: verified.unverified_metadata.contract,
    })
}

/// Verify the compact bytes produced by the authorized document exporter
/// through the same independently trusted entry citation as a kernel view.
/// Only the exact requested subset is needed; other readable chunks need
/// not be exported. Neither input format contains a replacement trust anchor.
///
/// Compact proofs retain their own bounded count/byte/path policy and u64
/// document indexes. Do not accidentally impose the full kernel-view size
/// ceiling on a sparse membership proof. Signatures, authorization, contract
/// compliance and complete evidence production remain outside this check.
pub fn verify_evidence_disclosure_for(
    proof: &[u8],
    disclosure_bytes: &[u8],
    checkpoint: &Checkpoint,
    expected: &EvidenceExpectation,
    requested: &[u64],
) -> Result<VerifiedEvidenceDisclosure, EvidenceError> {
    disclosure::validate_request(requested)?;
    if disclosure_bytes.len() > disclosure::MAX_PROOF_BYTES {
        return Err(DisclosureProofError::InputLimit {
            maximum: disclosure::MAX_PROOF_BYTES,
            actual: disclosure_bytes.len(),
        }
        .into());
    }
    let (inclusion, citation) = authenticated_citation(proof, checkpoint, expected)?;
    let disclosure = disclosure::verify(disclosure_bytes, requested, &citation.doc_commit)?;
    Ok(VerifiedEvidenceDisclosure {
        inclusion,
        citation,
        disclosure,
    })
}

fn authenticated_citation(
    proof: &[u8],
    checkpoint: &Checkpoint,
    expected: &EvidenceExpectation,
) -> Result<(Inclusion, EvidenceCitation), EvidenceError> {
    let (inclusion, proposal) = authenticated_entry(proof, checkpoint, &expected.entry_digest)?;
    let citation = read_citation(proposal, expected)?;
    if document_oid(&checkpoint.book_id, &citation.doc_commit) != citation.document_oid {
        return Err(EvidenceError::DocumentIdentity);
    }
    Ok((inclusion, citation))
}

/// One authenticated immutable proposal, shared by selected disclosures and
/// complete citation inventories. A digest alone cannot reveal its citations.
fn authenticated_entry<'a>(
    proof: &'a [u8],
    checkpoint: &Checkpoint,
    expected_entry_digest: &[u8; 32],
) -> Result<(Inclusion, &'a [u8]), EvidenceError> {
    if proof.len() > MAX_PROOF_BYTES {
        return Err(EvidenceError::InputLimit);
    }
    let inclusion = crate::verify_inclusion(proof, checkpoint)?;
    if inclusion.envelope.record_digest != *expected_entry_digest {
        return Err(EvidenceError::EntryMismatch);
    }
    if inclusion.record != RecordCheck::Recomputed {
        return Err(EvidenceError::RecordRequired);
    }
    // The shared verifier has authenticated this exact immutable byte slice
    // and checked its entire frame, path, payload and split hint. Re-reading
    // the fixed v1 header below only borrows the already checked proposal;
    // it neither accepts a second payload nor repeats the cryptographic work.
    let proposal = included_proposal(proof)?;
    Ok((inclusion, proposal))
}

fn document_oid(book: &[u8; 16], commitment: &[u8; 32]) -> [u8; 32] {
    // fa_model::domain_digest length-frames EACH part, including fixed IDs.
    hash_parts(
        DOCUMENT_OID_DOMAIN,
        &[&16u32.to_le_bytes(), book, &32u32.to_le_bytes(), commitment],
    )
}

/// Only called after successful verify_inclusion on this exact proof.
fn included_proposal(proof: &[u8]) -> Result<&[u8], EvidenceError> {
    let mut r = crate::proof::open(proof, INCLUSION_FORMAT)?;
    Checkpoint::read(&mut r)?;
    r.u64("proof.leaf_index")?;
    // The shared inclusion decoder already enforced its narrower envelope
    // bound. This second, larger bound never expands what it accepts.
    r.bytes(MAX_RECORD_BYTES, "proof.envelope")?;
    if !r.present("proof.record")? {
        return Err(EvidenceError::RecordRequired);
    }
    let length = usize::try_from(r.u32("proof.record.proposal_len")?)
        .map_err(|_| EvidenceError::Proof(VerifyError::Record(RecordError::Split)))?;
    let payload = r.bytes(MAX_RECORD_BYTES, "proof.record")?;
    let split_error = || EvidenceError::Proof(VerifyError::Record(RecordError::Split));
    let end = payload.len().checked_sub(64).ok_or_else(split_error)?;
    let envelope = payload.get(length..end).ok_or_else(split_error)?;
    let mut envelope = Reader::new(envelope);
    if envelope.present("entry.plan_certificate")? {
        envelope.fixed::<32>("entry.plan_certificate")?;
    }
    let count = envelope.count(256, 48, "entry.approvals")?;
    for _ in 0..count {
        envelope.fixed::<48>("entry.approval")?;
    }
    envelope.finish("entry envelope")?;
    payload.get(..length).ok_or_else(split_error)
}

fn optional_vid(r: &mut Reader<'_>, field: &'static str) -> Result<(), DecodeError> {
    if r.present(field)? {
        r.u128(field)?;
    }
    Ok(())
}

/// Exact current ControlBody framing. Unknown tags refuse rather than
/// guessing where the evidence list begins. No control law is evaluated.
fn skip_control(r: &mut Reader<'_>) -> Result<(), DecodeError> {
    if !r.present("entry.control")? {
        return Ok(());
    }
    match r.u8("control.tag")? {
        0 => {
            r.bytes(32, "control.period.calendar")?;
            r.bytes(32, "control.period.code")?;
            r.fixed::<4>("control.transition")?; // from, to, u16 reason
            optional_vid(r, "control.case_ref")?;
        }
        1 => {
            r.u16("control.kind")?;
            r.bytes(1024 * 1024, "control.canonical_bytes")?;
        }
        2 => {
            r.fixed::<40>("control.policy_activation")?;
        }
        3 => {
            r.fixed::<18>("control.lifecycle")?; // object, from, to
            let count = r.count(256, 17, "control.proof_refs")?;
            for _ in 0..count {
                match r.u8("control.proof_ref.tag")? {
                    0 => {
                        r.u128("control.proof_ref.vertex")?;
                    }
                    1 => {
                        r.fixed::<32>("control.proof_ref.object")?;
                    }
                    tag => return Err(r.error("control.proof_ref.tag", Reason::BadTag(tag))),
                }
            }
            r.u16("control.reason")?;
        }
        4 => {
            r.u64("control.observed_utc_ns")?;
            r.u8("control.source")?;
            r.present("control.monotonic_ok")?;
        }
        5 => {
            r.fixed::<33>("control.sweep_cursor")?;
        }
        6 => {
            r.fixed::<32>("control.schedule_cancelled")?;
        }
        7 => {
            r.fixed::<65>("control.capability_event")?;
        }
        8 => {
            r.fixed::<65>("control.hold_event")?;
        }
        9 => {
            r.u128("control.subject_ref")?;
            let count = r.count(4096, 32, "control.field_digests")?;
            for _ in 0..count {
                r.fixed::<32>("control.field_digest")?;
            }
        }
        10 => {
            r.fixed::<49>("control.migration")?;
        }
        11 => {}
        13 => {
            match r.u8("control.intake_source")? {
                0 => {
                    r.u128("control.upload_principal")?;
                }
                1 => {
                    r.bytes(256, "control.connector_name")?;
                    r.bytes(256, "control.connector_version")?;
                }
                2 | 3 => {
                    r.bytes(256, "control.intake_text")?;
                }
                tag => return Err(r.error("control.intake_source", Reason::BadTag(tag))),
            }
            r.fixed::<76>("control.import_run")?; // u32 count, u64 bytes, two hashes
        }
        tag => return Err(r.error("control.tag", Reason::BadTag(tag))),
    }
    Ok(())
}

fn skip_origin(r: &mut Reader<'_>) -> Result<(), DecodeError> {
    match r.u8("entry.origin")? {
        0 => {
            r.fixed::<34>("origin.intent")?;
        }
        1 => {
            r.fixed::<80>("origin.rule")?;
        }
        2 => {
            r.u128("origin.run_ref")?;
            r.bytes(64, "origin.source_system")?;
            skip_erasable(r, "origin.source_id")?;
            if r.present("origin.source_recorded_at")? {
                r.u64("origin.source_recorded_at")?;
            }
            for field in ["origin.source_entered_by", "origin.source_approved_by"] {
                if r.present(field)? {
                    skip_erasable(r, field)?;
                }
            }
            r.fixed::<32>("origin.batch_oid")?;
        }
        3 => {
            r.fixed::<34>("origin.control")?;
        }
        4 => {
            r.fixed::<33>("origin.sweep")?;
        }
        5 => {
            r.u128("origin.schedule_ref")?;
            match r.u8("origin.trigger")? {
                0 | 1 => {
                    r.u128("origin.trigger_ref")?;
                }
                tag => return Err(r.error("origin.trigger", Reason::BadTag(tag))),
            }
        }
        tag => return Err(r.error("entry.origin", Reason::BadTag(tag))),
    }
    Ok(())
}

fn read_citation(
    proposal: &[u8],
    expected: &EvidenceExpectation,
) -> Result<EvidenceCitation, EvidenceError> {
    let mut found = None;
    visit_citations(proposal, |citation| {
        if citation.document_oid == expected.document_oid
            && citation.role == expected.role
            && found.replace(citation).is_some()
        {
            return Err(EvidenceError::CitationAmbiguous);
        }
        Ok(())
    })?;
    found.ok_or(EvidenceError::CitationMissing)
}

/// Walk the complete canonical evidence list, then validate the remaining
/// proposal frame. Callers must not publish visitor results before success.
fn visit_citations(
    proposal: &[u8],
    mut visit: impl FnMut(EvidenceCitation) -> Result<(), EvidenceError>,
) -> Result<(), EvidenceError> {
    let mut schema = Reader::new(proposal);
    schema.u16("entry.schema_major")?;
    let minor = schema.u16("entry.schema_minor")?;
    let mut r = proposal_after_legs(proposal)?;
    skip_control(&mut r)?;
    let count = r.count(MAX_ENVELOPE_LIST, 36, "entry.unit_totals")?;
    for _ in 0..count {
        r.fixed::<36>("entry.unit_total")?;
    }
    if r.present("entry.base_totals")? {
        r.fixed::<68>("entry.base_totals.fields")?;
        let count = r.count(64, 32, "entry.base_totals.rate_doc_oids")?;
        for _ in 0..count {
            r.fixed::<32>("entry.base_totals.rate_doc_oid")?;
        }
        if r.present("entry.base_totals.residual")? {
            r.fixed::<22>("entry.base_totals.residual")?;
        }
    }
    r.bytes(64, "entry.idempotency_key")?;
    skip_origin(&mut r)?;
    r.u128("entry.principal_ref")?;
    optional_vid(&mut r, "entry.session_ref")?;
    let count = r.count(MAX_EVIDENCE_PER_ENTRY, 65, "entry.evidence")?;
    let mut previous = None;
    for _ in 0..count {
        let citation = EvidenceCitation {
            document_oid: r.fixed("evidence.document_oid")?,
            doc_commit: r.fixed("evidence.doc_commit")?,
            role: r.u8("evidence.role")?,
        };
        // Canonical order is (document_oid, doc_commit, role), not just oid:
        // one document can legitimately be cited with several distinct roles.
        if previous.is_some_and(|prior| prior >= citation) {
            return Err(r.error("entry.evidence", Reason::Unsorted).into());
        }
        previous = Some(citation);
        visit(citation)?;
    }
    // Do not return on the first match: a later malformed citation invalidates
    // the list. Validate the remaining frame too, without claiming its semantic
    // content has been checked. Additive minor versions only append extensions.
    skip_proposal_tail(&mut r, minor)?;
    r.finish("entry proposal")?;
    Ok(())
}

fn skip_proposal_tail(r: &mut Reader<'_>, minor: u16) -> Result<(), DecodeError> {
    let count = r.count(1024, 51, "entry.supersession")?;
    for _ in 0..count {
        r.fixed::<48>("supersession.target")?;
        match r.u8("supersession.kind")? {
            1..=6 => {}
            tag => return Err(r.error("supersession.kind", Reason::BadTag(tag))),
        }
        r.u16("supersession.reason_code")?;
    }
    if r.present("entry.pending")? {
        if r.present("pending.timeout")? {
            r.u64("pending.timeout")?;
        }
        if r.present("pending.resolution_of")? {
            r.fixed::<48>("pending.resolution_of")?;
        }
        if r.present("pending.disposition")? {
            match r.u8("disposition.tag")? {
                1 => {}
                2 => {
                    r.u64("disposition.at_tick")?;
                }
                3 => {
                    let count = r.count(MAX_ENVELOPE_LIST, 2, "disposition.ordinals")?;
                    let mut previous = None;
                    for _ in 0..count {
                        let ordinal = r.u16("disposition.ordinal")?;
                        if previous.is_some_and(|prior| prior >= ordinal) {
                            return Err(r.error("disposition.ordinals", Reason::Unsorted));
                        }
                        previous = Some(ordinal);
                    }
                }
                tag => return Err(r.error("disposition.tag", Reason::BadTag(tag))),
            }
        }
    }
    let count = r.count(256, 65, "entry.external_ids")?;
    for _ in 0..count {
        r.bytes(64, "external_id.system")?;
        skip_erasable(r, "external_id.value")?;
    }
    let count = r.count(32, 65, "entry.tags")?;
    for _ in 0..count {
        r.bytes(64, "tag.key")?;
        skip_erasable(r, "tag.value")?;
    }
    if minor >= 1 {
        let count = r.count(64, 6, "entry.extensions")?;
        let mut previous = None;
        for _ in 0..count {
            let tag = r.u16("extension.tag")?;
            if previous.is_some_and(|prior| prior >= tag) {
                return Err(r.error("entry.extensions", Reason::Unsorted));
            }
            previous = Some(tag);
            r.bytes(64 * 1024, "extension.bytes")?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Writer;
    use crate::document::{DOC_CHUNK_BYTES, DOC_LEAF_DOMAIN, doc_commit};
    use crate::envelope::{ENTRY_DIGEST_DOMAIN, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry};
    use crate::tree::{leaf_hash, root_of};

    const BOOK: [u8; 16] = [0x42; 16];

    fn citation(doc: &[u8]) -> EvidenceCitation {
        let commitment = doc_commit(1, doc);
        EvidenceCitation {
            document_oid: document_oid(&BOOK, &commitment),
            doc_commit: commitment,
            role: 3,
        }
    }

    fn erasable(w: &mut Writer) {
        w.fixed(&[0; 32]).u8(0).fixed(&[0; 24]).bytes(&[]);
    }

    fn origin() -> Vec<u8> {
        let mut w = Writer::default();
        w.u8(0).fixed(&[9; 32]).u16(1);
        w.buf
    }

    // Complete wire fixture, not an assertion of kernel authorization.
    fn proposal(citations: &[EvidenceCitation], control: &[u8], origin: &[u8]) -> Vec<u8> {
        let mut w = Writer::default();
        w.u16(1)
            .u16(1)
            .fixed(&BOOK)
            .fixed(&[0; 16])
            .u16(1)
            .i32(20_527)
            .u8(0);
        erasable(&mut w);
        w.u8(0).count(2);
        for (side, account) in [(0, 10), (1, 20)] {
            w.u8(side)
                .u128(account)
                .u32(1)
                .i128(123)
                .u8(0)
                .count(0)
                .u8(0)
                .count(0);
        }
        w.fixed(control)
            .count(1)
            .u32(1)
            .i128(123)
            .i128(123)
            .u8(0)
            .bytes(b"evidence-test")
            .fixed(origin)
            .u128(7)
            .u8(0)
            .count(citations.len());
        for citation in citations {
            w.fixed(&citation.document_oid)
                .fixed(&citation.doc_commit)
                .u8(citation.role);
        }
        w.count(0).u8(0).count(0).count(0).count(0);
        w.buf
    }

    fn proof(
        proposal: &[u8],
        entry_envelope: &[u8],
        include_record: bool,
    ) -> (Vec<u8>, Checkpoint, [u8; 32]) {
        let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[proposal]);
        let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, entry_envelope]);
        let mut payload = proposal.to_vec();
        payload.extend_from_slice(entry_envelope);
        payload.extend_from_slice(&proposal_digest);
        payload.extend_from_slice(&digest);
        let envelope = envelope_of_entry(&payload, proposal.len(), 7, 0)
            .unwrap()
            .encode();
        let checkpoint = Checkpoint {
            book_id: BOOK,
            branch_id: [0; 16],
            through_seq: 9,
            leaf_count: 1,
            root: root_of(&[leaf_hash(&envelope)]),
        };
        let mut w = Writer::default();
        w.bytes(INCLUSION_FORMAT)
            .fixed(&checkpoint.encode())
            .u64(0)
            .bytes(&envelope)
            .u8(u8::from(include_record));
        if include_record {
            w.u32(u32::try_from(proposal.len()).unwrap())
                .bytes(&payload);
        }
        w.count(0);
        (w.buf, checkpoint, digest)
    }

    fn view(doc: &[u8], shown: &[u64]) -> Vec<u8> {
        let citation = citation(doc);
        let chunks: Vec<&[u8]> = if doc.is_empty() {
            vec![&[]]
        } else {
            doc.chunks(DOC_CHUNK_BYTES).collect()
        };
        let mut w = Writer::default();
        w.u16(1)
            .fixed(&citation.document_oid)
            .u16(7)
            .u8(1)
            .u64(doc.len() as u64)
            .fixed(&citation.doc_commit)
            .count(chunks.len());
        for (index, chunk) in chunks.into_iter().enumerate() {
            let index = index as u64;
            if shown.contains(&index) {
                w.u8(0).bytes(chunk);
            } else {
                w.u8(1).fixed(&hash_parts(
                    DOC_LEAF_DOMAIN,
                    &[
                        &index.to_le_bytes(),
                        &(chunk.len() as u64).to_le_bytes(),
                        chunk,
                    ],
                ));
            }
        }
        w.buf
    }

    fn request(digest: [u8; 32], citation: EvidenceCitation) -> EvidenceExpectation {
        EvidenceExpectation {
            entry_digest: digest,
            document_oid: citation.document_oid,
            role: citation.role,
        }
    }

    fn compact(chunk: &[u8], size: u64, index: u64, siblings: &[[u8; 32]]) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(disclosure::FORMAT)
            .u8(1)
            .u64(size)
            .count(1)
            .u64(index)
            .bytes(chunk)
            .count(siblings.len());
        for sibling in siblings {
            w.fixed(sibling);
        }
        w.buf
    }

    #[test]
    fn compact_exports_take_their_anchor_from_the_included_citation() {
        for doc in [Vec::new(), b"cited document".to_vec()] {
            let citation = citation(&doc);
            let proposal = proposal(&[citation], &[0], &origin());
            let (proof, checkpoint, digest) = proof(&proposal, &[0; 5], true);
            let expected = request(digest, citation);
            let bytes = compact(&doc, doc.len() as u64, 0, &[]);
            let verified =
                verify_evidence_disclosure_for(&proof, &bytes, &checkpoint, &expected, &[0])
                    .unwrap();
            assert_eq!(verified.inclusion.scope, "inclusion");
            assert_eq!(verified.inclusion.record, RecordCheck::Recomputed);
            assert_eq!(verified.citation, citation);
            assert_eq!(verified.disclosure.scope, "membership_only");
            assert_eq!(verified.disclosure.chunks[0].byte_length, doc.len());
            let unrelated = compact(b"other", 5, 0, &[]);
            assert!(
                verify_evidence_disclosure_for(&proof, &unrelated, &checkpoint, &expected, &[0],)
                    .is_err()
            );
            let mut wrong = expected;
            wrong.entry_digest[0] ^= 1;
            assert_eq!(
                verify_evidence_disclosure_for(&proof, &bytes, &checkpoint, &wrong, &[0],),
                Err(EvidenceError::EntryMismatch)
            );
        }
    }

    #[test]
    fn compact_framing_and_exact_request_checks_cannot_return_partial_success() {
        let doc = b"cited document";
        let citation = citation(doc);
        let proposal = proposal(&[citation], &[0], &origin());
        let (proof, checkpoint, digest) = proof(&proposal, &[0; 5], true);
        let expected = request(digest, citation);
        let bytes = compact(doc, doc.len() as u64, 0, &[]);
        for end in 0..bytes.len() {
            assert!(verify_evidence_disclosure_for(
                &proof, &bytes[..end], &checkpoint, &expected, &[0],
            ).is_err(), "compact prefix {end}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(
            verify_evidence_disclosure_for(&proof, &trailing, &checkpoint, &expected, &[0],)
                .is_err()
        );
        assert!(
            verify_evidence_disclosure_for(&proof, &view(doc, &[0]), &checkpoint, &expected, &[0],)
                .is_err()
        );
        for requested in [vec![], vec![0, 0], vec![1, 0], vec![0, 1], vec![1]] {
            assert!(
                verify_evidence_disclosure_for(&proof, &bytes, &checkpoint, &expected, &requested,)
                    .is_err()
            );
        }
    }

    #[test]
    fn sparse_compact_proofs_keep_their_own_index_and_sibling_policy() {
        use crate::document::{DOC_DOMAIN, DOC_NODE_DOMAIN};

        // The compact verifier admits u64 indexes without allocating a full
        // document. A promoted final leaf at 16384 needs only one sibling.
        let index = MAX_VIEW_CHUNKS as u64;
        let size = (index + 1) * DOC_CHUNK_BYTES as u64;
        let chunk = vec![42; DOC_CHUNK_BYTES];
        let sibling = [7; 32];
        let leaf = hash_parts(
            DOC_LEAF_DOMAIN,
            &[
                &index.to_le_bytes(),
                &(chunk.len() as u64).to_le_bytes(),
                &chunk,
            ],
        );
        let root = hash_parts(DOC_NODE_DOMAIN, &[&sibling, &leaf]);
        let doc_commit = hash_parts(DOC_DOMAIN, &[&[1], &size.to_le_bytes(), &root]);
        let citation = EvidenceCitation {
            document_oid: document_oid(&BOOK, &doc_commit),
            doc_commit,
            role: 3,
        };
        // Independently calculated with the session's Python BLAKE3 model,
        // checked against 31 reference vectors; these are not producer output.
        assert_eq!(
            crate::blake3::hex(&citation.doc_commit),
            "5f120b0c4da0fc5463ba30e795aecae7c5c01905ad59a63369bc0fe15cbbb312"
        );
        assert_eq!(
            crate::blake3::hex(&citation.document_oid),
            "00c6f3858a9acfe43935d6837690669088813736a290888ff540265bbf07c535"
        );
        let proposal = proposal(&[citation], &[0], &origin());
        let (proof, checkpoint, digest) = proof(&proposal, &[0; 5], true);
        let expected = request(digest, citation);
        let bytes = compact(&chunk, size, index, &[sibling]);
        assert!(validate_request(&[index]).is_err()); // Full kernel-view policy.
        let verified =
            verify_evidence_disclosure_for(&proof, &bytes, &checkpoint, &expected, &[index])
                .unwrap();
        assert_eq!(verified.disclosure.document_length, size);
        assert_eq!(verified.disclosure.chunks[0].index, index);
        let mut corrupt = bytes;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(
            verify_evidence_disclosure_for(&proof, &corrupt, &checkpoint, &expected, &[index],)
                .is_err()
        );
    }

    #[test]
    fn checkpoint_entry_citation_and_exact_chunks_form_one_verified_chain() {
        for length in [0usize, 1, 4095, 4096, 4097, 8193, 5 * 4096 + 3] {
            let doc: Vec<u8> = (0..length).map(|i| (i % 251) as u8).collect();
            let citation = citation(&doc);
            let count = length.div_ceil(DOC_CHUNK_BYTES).max(1);
            let shown: Vec<u64> = (0..count).step_by(2).map(|i| i as u64).collect();
            let proposal = proposal(&[citation], &[0], &origin());
            let (proof, checkpoint, digest) = proof(&proposal, &[0; 5], true);
            let bytes = view(&doc, &shown);
            let expected = request(digest, citation);
            let verified =
                verify_evidence_view_for(&proof, &bytes, &checkpoint, &expected, &shown).unwrap();
            assert_eq!(verified.inclusion.record, RecordCheck::Recomputed);
            assert_eq!(verified.inclusion.scope, "inclusion");
            assert_eq!(verified.disclosure_scope, "membership_only");
            assert_eq!(verified.citation, citation);
            assert_eq!(verified.size, length as u64);
            assert_eq!(verified.unverified_contract, 7);
            for chunk in verified.disclosed {
                let start = chunk.index as usize * DOC_CHUNK_BYTES;
                assert_eq!(
                    chunk.bytes,
                    &doc[start..(start + DOC_CHUNK_BYTES).min(length)]
                );
            }
        }
    }

    #[test]
    fn genuine_unrelated_artifacts_and_producer_chosen_questions_do_not_compose() {
        let doc = b"requested evidence";
        let citation = citation(doc);
        let proposal = proposal(&[citation], &[0], &origin());
        let (proof, checkpoint, digest) = proof(&proposal, &[0; 5], true);
        let expected = request(digest, citation);
        let bytes = view(doc, &[0]);
        let unrelated = view(b"different valid document", &[0]);
        assert!(
            verify_evidence_view_for(&proof, &unrelated, &checkpoint, &expected, &[0]).is_err()
        );
        let mut wrong = expected;
        wrong.entry_digest[0] ^= 1;
        assert_eq!(
            verify_evidence_view_for(&proof, &bytes, &checkpoint, &wrong, &[0]),
            Err(EvidenceError::EntryMismatch)
        );
        wrong = expected;
        wrong.document_oid[0] ^= 1;
        assert_eq!(
            verify_evidence_view_for(&proof, &bytes, &checkpoint, &wrong, &[0]),
            Err(EvidenceError::CitationMissing)
        );
        wrong = expected;
        wrong.role ^= 1;
        assert_eq!(
            verify_evidence_view_for(&proof, &bytes, &checkpoint, &wrong, &[0]),
            Err(EvidenceError::CitationMissing)
        );
        let mut wrong_checkpoint = checkpoint;
        wrong_checkpoint.root[0] ^= 1;
        assert!(
            verify_evidence_view_for(&proof, &bytes, &wrong_checkpoint, &expected, &[0]).is_err()
        );
        assert!(verify_evidence_view_for(&proof, &bytes, &checkpoint, &expected, &[1]).is_err());
    }

    #[test]
    fn envelope_only_inclusion_cannot_authenticate_an_evidence_list() {
        let citation = citation(b"doc");
        let proposal = proposal(&[citation], &[0], &origin());
        let (proof, checkpoint, digest) = proof(&proposal, &[0; 5], false);
        assert_eq!(
            crate::verify_inclusion(&proof, &checkpoint).unwrap().record,
            RecordCheck::NotSupplied
        );
        assert_eq!(
            verify_evidence_view_for(
                &proof,
                &view(b"doc", &[0]),
                &checkpoint,
                &request(digest, citation),
                &[0]
            ),
            Err(EvidenceError::RecordRequired)
        );
    }

    #[test]
    fn locator_is_authenticated_but_the_contract_is_not() {
        let doc = b"evidence";
        let citation = citation(doc);
        let proposal = proposal(&[citation], &[0], &origin());
        let (proof, checkpoint, digest) = proof(&proposal, &[0; 5], true);
        let expected = request(digest, citation);
        let mut bytes = view(doc, &[0]);
        bytes[2] ^= 1;
        assert_eq!(
            verify_evidence_view_for(&proof, &bytes, &checkpoint, &expected, &[0]),
            Err(EvidenceError::ViewLocator)
        );
        bytes[2] ^= 1;
        bytes[34..36].copy_from_slice(&999u16.to_le_bytes());
        let verified =
            verify_evidence_view_for(&proof, &bytes, &checkpoint, &expected, &[0]).unwrap();
        assert_eq!(verified.unverified_contract, 999);
        assert_eq!(verified.disclosure_scope, "membership_only");
    }

    #[test]
    fn even_authenticated_citations_must_bind_the_book_scoped_identity() {
        let doc = b"evidence";
        let mut citation = citation(doc);
        citation.document_oid = document_oid(&[0x43; 16], &citation.doc_commit);
        let proposal = proposal(&[citation], &[0], &origin());
        let (proof, checkpoint, digest) = proof(&proposal, &[0; 5], true);
        assert_eq!(
            verify_evidence_view_for(
                &proof,
                &view(doc, &[0]),
                &checkpoint,
                &request(digest, citation),
                &[0]
            ),
            Err(EvidenceError::DocumentIdentity)
        );
    }

    #[test]
    fn all_citations_and_the_remaining_proposal_frame_are_checked() {
        let citation = citation(b"doc");
        let expected = request([0; 32], citation);
        let mut other_role = citation;
        other_role.role += 1;
        let valid = proposal(&[citation, other_role], &[0], &origin());
        assert_eq!(read_citation(&valid, &expected).unwrap(), citation);
        for citations in [vec![citation, citation], vec![other_role, citation]] {
            assert!(read_citation(&proposal(&citations, &[0], &origin()), &expected).is_err());
        }
        let mut conflicting = citation;
        conflicting.doc_commit[0] ^= 1;
        let mut ambiguous = [citation, conflicting];
        ambiguous.sort_unstable();
        assert_eq!(
            read_citation(&proposal(&ambiguous, &[0], &origin()), &expected),
            Err(EvidenceError::CitationAmbiguous)
        );
        for end in 0..valid.len() {
            assert!(
                read_citation(&valid[..end], &expected).is_err(),
                "prefix {end}"
            );
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        // Re-hashing malformed bytes into a valid included record is not enough.
        let (proof, checkpoint, digest) = proof(&trailing, &[0; 5], true);
        assert!(crate::verify_inclusion(&proof, &checkpoint).is_ok());
        assert!(
            verify_evidence_view_for(
                &proof,
                &view(b"doc", &[0]),
                &checkpoint,
                &request(digest, citation),
                &[0]
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_entry_envelopes_and_later_view_chunks_never_return_success() {
        let doc = vec![42; 8193];
        let citation = citation(&doc);
        let proposal = proposal(&[citation], &[0], &origin());
        let bytes = view(&doc, &[0, 2]);
        for envelope in [&[][..], &[0], &[2, 0, 0, 0, 0], &[0, 0, 0, 0, 0, 0]] {
            let (proof, checkpoint, digest) = proof(&proposal, envelope, true);
            assert!(crate::verify_inclusion(&proof, &checkpoint).is_ok());
            assert!(
                verify_evidence_view_for(
                    &proof,
                    &bytes,
                    &checkpoint,
                    &request(digest, citation),
                    &[0, 2]
                )
                .is_err()
            );
        }
        let (proof, checkpoint, digest) = proof(&proposal, &[0; 5], true);
        let expected = request(digest, citation);
        for mut corrupt in [bytes[..bytes.len() - 1].to_vec(), bytes.clone()] {
            if corrupt.len() == bytes.len() {
                *corrupt.last_mut().unwrap() ^= 1;
            }
            assert!(
                verify_evidence_view_for(&proof, &corrupt, &checkpoint, &expected, &[0, 2])
                    .is_err()
            );
        }
    }

    #[test]
    fn requests_are_bounded_and_unknown_tags_fail_closed() {
        for requested in [vec![], vec![0, 0], vec![2, 1], vec![16384], vec![u64::MAX]] {
            assert!(matches!(
                verify_evidence_view_for(
                    &[],
                    &[],
                    &Checkpoint {
                        book_id: BOOK,
                        branch_id: [0; 16],
                        through_seq: 0,
                        leaf_count: 0,
                        root: [0; 32],
                    },
                    &request([0; 32], citation(b"doc")),
                    &requested
                ),
                Err(EvidenceError::Request(_))
            ));
        }
        let citation = citation(b"doc");
        let expected = request([0; 32], citation);
        for control in [&[1, 12][..], &[1, 255], &[2]] {
            assert!(read_citation(&proposal(&[citation], control, &origin()), &expected).is_err());
        }
        assert!(read_citation(&proposal(&[citation], &[0], &[255]), &expected).is_err());
    }

    #[test]
    fn current_control_and_origin_frames_cannot_shift_the_citation_offset() {
        let fixed_control = |tag, length| {
            let mut bytes = vec![1, tag];
            bytes.extend(vec![0; length]);
            bytes
        };
        let mut controls = vec![
            vec![0],
            fixed_control(2, 40),
            fixed_control(4, 10),
            fixed_control(5, 33),
            fixed_control(6, 32),
            fixed_control(7, 65),
            fixed_control(8, 65),
            fixed_control(10, 49),
            fixed_control(11, 0),
        ];
        let mut w = Writer::default();
        w.u8(1)
            .u8(0)
            .bytes(b"cal")
            .bytes(b"period")
            .u8(0)
            .u8(1)
            .u16(2)
            .u8(1)
            .u128(3);
        controls.push(w.buf);
        let mut w = Writer::default();
        w.u8(1).u8(1).u16(1).bytes(b"schema");
        controls.push(w.buf);
        let mut w = Writer::default();
        w.u8(1)
            .u8(3)
            .u128(1)
            .u8(0)
            .u8(1)
            .count(2)
            .u8(0)
            .u128(2)
            .u8(1)
            .fixed(&[3; 32])
            .u16(4);
        controls.push(w.buf);
        let mut w = Writer::default();
        w.u8(1)
            .u8(9)
            .u128(1)
            .count(2)
            .fixed(&[2; 32])
            .fixed(&[3; 32]);
        controls.push(w.buf);
        for source in 0..=3 {
            let mut w = Writer::default();
            w.u8(1).u8(13).u8(source);
            match source {
                0 => {
                    w.u128(7);
                }
                1 => {
                    w.bytes(b"connector").bytes(b"v1");
                }
                _ => {
                    w.bytes(b"source");
                }
            }
            w.u32(1).u64(10).fixed(&[2; 32]).fixed(&[3; 32]);
            controls.push(w.buf);
        }
        let mut origins = vec![origin()];
        for (tag, length) in [(1, 80), (3, 34), (4, 33)] {
            let mut bytes = vec![tag];
            bytes.extend(vec![0; length]);
            origins.push(bytes);
        }
        let mut w = Writer::default();
        w.u8(2).u128(1).bytes(b"legacy");
        erasable(&mut w);
        w.u8(1).u64(u64::MAX);
        for _ in 0..2 {
            w.u8(1);
            erasable(&mut w);
        }
        w.fixed(&[2; 32]);
        origins.push(w.buf);
        for trigger in 0..=1 {
            let mut w = Writer::default();
            w.u8(5).u128(1).u8(trigger).u128(2);
            origins.push(w.buf);
        }
        let citation = citation(b"doc");
        let expected = request([0; 32], citation);
        for control in &controls {
            for origin in &origins {
                assert_eq!(
                    read_citation(&proposal(&[citation], control, origin), &expected).unwrap(),
                    citation
                );
            }
        }
    }
}
