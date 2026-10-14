//! Complete citation inventories for one independently requested entry.
//!
//! This is a projection of an authenticated entry payload, not a new wire
//! format or a proof that the book contains all real-world evidence. An
//! inventory lists every citation in that entry, including multiple roles
//! for one document. It does not verify or disclose document bytes.

pub mod allocation;
pub mod production;

use core::fmt;

use super::{
    EvidenceCitation, EvidenceError, MAX_EVIDENCE_PER_ENTRY, authenticated_entry, document_oid,
    visit_citations,
};
use crate::{Checkpoint, Inclusion};

/// A complete, canonically ordered inventory from the requested entry.
///
/// `inclusion.scope` remains `inclusion`. Completeness is confined to the
/// citation list inside that authenticated record; it is not a completeness
/// claim over journal entries, production, custody, or document contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEvidenceInventory {
    pub inclusion: Inclusion,
    pub citations: Vec<EvidenceCitation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InventoryError {
    Evidence(EvidenceError),
    Request(&'static str),
    /// Zero-based ordinal of the first missing, extra, or changed citation.
    /// No payload bytes or unverified metadata are retained in diagnostics.
    CitationSetMismatch {
        ordinal: usize,
    },
}

impl fmt::Display for InventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evidence(error) => write!(f, "{error}"),
            Self::Request(why) => write!(f, "invalid evidence inventory request: {why}"),
            Self::CitationSetMismatch { ordinal } => write!(
                f,
                "the entry's complete citation set differs from the recipient's request at ordinal {ordinal}"
            ),
        }
    }
}

impl core::error::Error for InventoryError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Evidence(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EvidenceError> for InventoryError {
    fn from(error: EvidenceError) -> Self {
        Self::Evidence(error)
    }
}

/// Check recipient inputs without observing any artifact. Empty means an
/// explicitly expected empty inventory. Never sort or deduplicate a request.
pub fn validate_citation_request(expected: &[EvidenceCitation]) -> Result<(), InventoryError> {
    if expected.len() > MAX_EVIDENCE_PER_ENTRY {
        return Err(InventoryError::Request("too many expected citations"));
    }
    if expected.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(InventoryError::Request(
            "citations must be strictly ascending by (document_oid, doc_commit, role)",
        ));
    }
    Ok(())
}

/// Authenticate the requested entry and return its entire evidence list.
///
/// The checkpoint and entry digest must be obtained independently of the
/// proof. A genuine proof for a different entry and an envelope-only proof
/// both refuse. Every citation's book-scoped document identity is checked,
/// not only a selected document. The full remaining proposal frame must also
/// pass before any inventory is returned. The existing 64 MiB proof and
/// 1,024-citation bounds apply, with no producer or substrate dependency.
pub fn verify_evidence_inventory_for(
    proof: &[u8],
    checkpoint: &Checkpoint,
    expected_entry_digest: &[u8; 32],
) -> Result<VerifiedEvidenceInventory, InventoryError> {
    let (inclusion, proposal) = authenticated_entry(proof, checkpoint, expected_entry_digest)?;
    let citations = citations_from_proposal(proposal, &checkpoint.book_id)?;
    Ok(VerifiedEvidenceInventory {
        inclusion,
        citations,
    })
}

// This only reads framing and citation identities. Callers must authenticate
// the exact immutable proposal first; it is deliberately not a public API.
fn citations_from_proposal(
    proposal: &[u8],
    book: &[u8; 16],
) -> Result<Vec<EvidenceCitation>, EvidenceError> {
    let mut citations = Vec::new();
    visit_citations(proposal, |citation| {
        if document_oid(book, &citation.doc_commit) != citation.document_oid {
            return Err(EvidenceError::DocumentIdentity);
        }
        citations.push(citation);
        Ok(())
    })?;
    Ok(citations)
}

/// Additionally require exactly the recipient-owned citation inventory.
///
/// Missing, extra, changed-commitment, and changed-role citations all fail.
/// `expected` may be empty but must otherwise be in canonical strict order.
/// It is never learned from the untrusted proof or silently normalized.
pub fn verify_evidence_inventory_exact(
    proof: &[u8],
    checkpoint: &Checkpoint,
    expected_entry_digest: &[u8; 32],
    expected: &[EvidenceCitation],
) -> Result<VerifiedEvidenceInventory, InventoryError> {
    validate_citation_request(expected)?;
    let inventory = verify_evidence_inventory_for(proof, checkpoint, expected_entry_digest)?;
    let actual = &inventory.citations;
    let ordinal = expected
        .iter()
        .zip(actual)
        .position(|(left, right)| left != right);
    if let Some(ordinal) = ordinal {
        return Err(InventoryError::CitationSetMismatch { ordinal });
    }
    if expected.len() != actual.len() {
        return Err(InventoryError::CitationSetMismatch {
            ordinal: expected.len().min(actual.len()),
        });
    }
    Ok(inventory)
}
