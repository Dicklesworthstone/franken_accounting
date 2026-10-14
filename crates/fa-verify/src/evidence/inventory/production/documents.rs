//! Complete bytes for every document originally cited by a scoped extract.
//!
//! The trusted prefix and recipient scope, not a producer manifest, determine
//! which entries and citations are required. Their authenticated commitments
//! then determine the exact distinct document set. This is an original-only
//! evidence production, not the full provenance closure of plan §9.2: events,
//! rules, approvals, custody, supplemental evidence and signatures are NOT
//! checked. Redacted/sparse disclosures cannot satisfy a full-byte request.

use core::fmt;

use super::{
    EvidenceProductionError, MAX_PRODUCTION_CITATIONS, VerifiedEvidenceProduction,
    verify_evidence_production_for,
};
use crate::document::doc_commit;
use crate::proof::Checkpoint;
use crate::proof::production::{
    MAX_PRODUCTION_BYTES, MAX_PRODUCTION_RECORDS, ProductionError, ProductionScope,
};

/// Every distinct document requires at least one authenticated citation.
pub const MAX_PRODUCTION_DOCUMENTS: usize = MAX_PRODUCTION_CITATIONS;

/// Untrusted full document bytes, not a new durable format. The locator and
/// kind are checked against commitments obtained from authenticated entries.
/// Inputs must be strictly increasing by document_oid; one copy per document.
#[derive(Clone, Copy)]
pub struct DocumentContent<'a> {
    pub document_oid: [u8; 32],
    pub kind: u8,
    pub bytes: &'a [u8],
}

// Deliberately no Debug: a failed test/log must not dump protected bytes.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDocumentContent {
    pub document_oid: [u8; 32],
    pub doc_commit: [u8; 32],
    pub kind: u8,
    pub byte_length: u64,
    /// All entry/role associations; the corresponding rows remain in inventory.
    pub citation_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDocumentProduction {
    /// Complete matching entries and their original citation lists.
    pub inventory: VerifiedEvidenceProduction,
    /// `recomputation` of FULL bytes against every distinct cited commitment.
    /// This scope does not assert provenance, authority or economic truth.
    pub document_scope: &'static str,
    /// Canonical locator order. No payload bytes or filesystem paths escape.
    pub documents: Vec<VerifiedDocumentContent>,
    /// Distinct document bytes, not multiplied by the number of citations.
    pub document_byte_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DocumentProductionError {
    Evidence(EvidenceProductionError),
    Limit(&'static str),
    Order { position: usize },
    ConflictingCitation,
    DocumentCount { expected: usize, actual: usize },
    DocumentIdentity { position: usize },
    Commitment { position: usize },
}

impl fmt::Display for DocumentProductionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evidence(error) => write!(f, "{error}"),
            Self::Limit(what) => write!(f, "document production exceeds the {what} bound"),
            Self::Order { position } => write!(f,
                "document {position} is not strictly after its predecessor by locator"),
            Self::ConflictingCitation => write!(f,
                "authenticated entries assign different commitments to one document locator"),
            Self::DocumentCount { expected, actual } => write!(f,
                "original citations require {expected} distinct documents; supplied {actual}"),
            Self::DocumentIdentity { position } => write!(f,
                "document {position} is not the next locator required by the original citations"),
            Self::Commitment { position } => write!(f,
                "document {position} kind, length or bytes do not match its authenticated commitment"),
        }
    }
}

impl core::error::Error for DocumentProductionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Evidence(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EvidenceProductionError> for DocumentProductionError {
    fn from(error: EvidenceProductionError) -> Self {
        Self::Evidence(error)
    }
}

/// Authenticate checkpoint -> exact selected entries -> all original citations
/// -> exactly every distinct document's complete bytes (plan §9.1, §13.1).
///
/// The scope and checkpoint must be chosen independently of the artifacts.
/// A document's expected commitment is NEVER taken from its supplied metadata.
/// Shared documents are hashed once, with every citation association retained.
/// Empty documents are real documents: their kind and empty bytes are hashed;
/// they cannot be omitted. An empty document set is accepted only when every
/// selected entry has no original citations (or the authenticated scope is empty).
///
/// There is one 64 MiB budget for prefix, all record proofs and all document
/// bytes, plus bounded metadata counts. Inputs are borrowed, not recopied.
/// Every proof and citation is verified before any document is hashed. No
/// partial report is returned on a missing, extra, substituted or corrupt file.
/// No filesystem, network, book, signature or new dependency is involved.
pub fn verify_document_production_for(
    prefix: &[u8],
    records: &[&[u8]],
    documents: &[DocumentContent<'_>],
    checkpoint: &Checkpoint,
    expected: &ProductionScope,
) -> Result<VerifiedDocumentProduction, DocumentProductionError> {
    expected.validate().map_err(EvidenceProductionError::from)?;
    if expected.known_at > checkpoint.through_seq {
        return Err(EvidenceProductionError::from(ProductionError::Request(
            "known_at is later than the trusted checkpoint",
        )).into());
    }
    if records.len() > MAX_PRODUCTION_RECORDS {
        return Err(DocumentProductionError::Limit("record count"));
    }
    if documents.len() > MAX_PRODUCTION_DOCUMENTS {
        return Err(DocumentProductionError::Limit("document count"));
    }
    let mut total = prefix.len();
    for length in records.iter().map(|record| record.len())
        .chain(documents.iter().map(|document| document.bytes.len()))
    {
        total = total.checked_add(length)
            .ok_or(DocumentProductionError::Limit("aggregate input bytes"))?;
    }
    if total > MAX_PRODUCTION_BYTES {
        return Err(DocumentProductionError::Limit("aggregate input bytes"));
    }
    for (position, pair) in documents.windows(2).enumerate() {
        if pair[0].document_oid >= pair[1].document_oid {
            return Err(DocumentProductionError::Order { position: position + 1 });
        }
    }
    let inventory = verify_evidence_production_for(prefix, records, checkpoint, expected)?;
    // Sort only authenticated metadata. Neither entries nor supplied documents
    // are reordered or silently deduplicated to repair a malformed production.
    let mut required = Vec::new();
    required.try_reserve_exact(inventory.citation_count)
        .map_err(|_| DocumentProductionError::Limit("citation allocation"))?;
    for entry in &inventory.entries {
        required.extend(entry.citations.iter().map(|citation| {
            (citation.document_oid, citation.doc_commit)
        }));
    }
    required.sort_unstable();
    let mut distinct = usize::from(!required.is_empty());
    for pair in required.windows(2) {
        if pair[0].0 != pair[1].0 {
            distinct += 1; // bounded by MAX_PRODUCTION_CITATIONS
        } else if pair[0].1 != pair[1].1 {
            return Err(DocumentProductionError::ConflictingCitation);
        }
    }
    if distinct != documents.len() {
        return Err(DocumentProductionError::DocumentCount {
            expected: distinct, actual: documents.len(),
        });
    }
    let mut verified = Vec::new();
    verified.try_reserve_exact(distinct)
        .map_err(|_| DocumentProductionError::Limit("document allocation"))?;
    let mut cursor = 0;
    let mut document_byte_count = 0u64;
    for (position, document) in documents.iter().enumerate() {
        let (oid, commitment) = required[cursor];
        if document.document_oid != oid {
            return Err(DocumentProductionError::DocumentIdentity { position });
        }
        let mut end = cursor + 1;
        while end < required.len() && required[end].0 == oid { end += 1; }
        if doc_commit(document.kind, document.bytes) != commitment {
            return Err(DocumentProductionError::Commitment { position });
        }
        // The aggregate byte policy above is <= 64 MiB on every admitted host.
        let byte_length = document.bytes.len() as u64;
        document_byte_count += byte_length;
        verified.push(VerifiedDocumentContent {
            document_oid: oid, doc_commit: commitment, kind: document.kind,
            byte_length, citation_count: end - cursor,
        });
        cursor = end;
    }
    Ok(VerifiedDocumentProduction {
        inventory, document_scope: "recomputation", documents: verified, document_byte_count,
    })
}
