//! Complete original and later-attached citations within a trusted prefix.
//!
//! The recipient selects entries, then obtains every supplement to those exact
//! entries recorded through `known_at`. A supplement has no effective date or
//! account selectors of its own: filtering that envelope would silently omit
//! evidence. The target join uses BOTH the immutable entry digest and its
//! independently derived native identity, never a producer-supplied edge.
//!
//! Completeness is within the independently trusted accumulated prefix. This
//! does not extend its coverage to evidence predating a legacy accumulator's
//! upgrade, nor verify provenance, custody, signatures, authority, policy or
//! economic truth. Whole-prefix disclosure is required and is not authorized
//! by this API. Existing original-only production APIs retain their scope.

mod identity;

use std::collections::{BTreeMap, BTreeSet};

use super::documents::{
    DocumentContent, DocumentProductionError, VerifiedDocumentContent, validate_inputs,
    verify_cited_documents,
};
use super::prefix::{authenticated_records, inventory_from_records};
use super::{EvidenceProductionError, MAX_PRODUCTION_CITATIONS, VerifiedEvidenceProduction};
use crate::codec::{Reader, Reason};
use crate::envelope::{KIND_ENTRY, KIND_SUPPLEMENTAL_EVIDENCE};
use crate::evidence::{EvidenceCitation, EvidenceError, document_oid};
use crate::proof::Checkpoint;
use crate::proof::production::ProductionScope;
use crate::proof::production::derivation::LeafRecord;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProducedSupplement {
    pub leaf_index: u64,
    pub recorded_at: u64,
    pub record_digest: [u8; 32],
    pub entry_vid: u128,
    pub entry_digest: [u8; 32],
    pub attached_by: u128,
    /// Entire canonical list, including distinct roles for the same document.
    pub citations: Vec<EvidenceCitation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSupplementedEvidenceProduction {
    /// Matching entries and their original citations, unchanged in meaning.
    pub inventory: VerifiedEvidenceProduction,
    /// Matching attachments in journal order, through the requested known-at.
    pub supplements: Vec<ProducedSupplement>,
    /// Original plus supplemental association rows, not distinct documents.
    pub citation_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSupplementedDocumentProduction {
    pub inventory: VerifiedSupplementedEvidenceProduction,
    /// `recomputation` of every distinct document's complete bytes.
    pub document_scope: &'static str,
    /// Canonical locator order; no payload bytes or filesystem paths escape.
    pub documents: Vec<VerifiedDocumentContent>,
    /// Shared document bytes are counted once, regardless of associations.
    pub document_byte_count: u64,
}

fn invalid(leaf_index: u64, problem: &'static str) -> EvidenceProductionError {
    EvidenceProductionError::Supplement {
        leaf_index,
        problem,
    }
}

/// Authenticate a native payload-complete v2 prefix once, then independently
/// derive the requested original-plus-supplements citation inventory.
///
/// The checkpoint and complete `ProductionScope` are recipient-owned. The
/// recorded range, account and effective-day selectors choose TARGET entries;
/// attachments are joined to those entries through `known_at`, even when the
/// attachment's sequence is outside the target range. Every known-at supplement
/// is validated against the complete entry population before scope filtering,
/// so orphan targets, changed digests and false identities cannot disappear in
/// an empty selection. Targets must have committed strictly before attachment.
///
/// Target identities are independently reconstructed for supported monetary
/// entry families, including reversals, resolutions, migration and recurring
/// occurrences. Ambiguous legacy Replacement identities and control-entry
/// targets refuse explicitly; unrelated records of those families may remain
/// in the prefix. No accounting, approval or actor-authority replay is claimed.
///
/// All prefix payloads, including records after `known_at`, are authenticated.
/// Later attachments do not enter the historical inventory. The existing 64
/// MiB input, 65,536 prefix leaves and 65,536 combined citation bounds apply.
/// No partial metadata is returned if any check fails.
pub fn verify_supplemented_evidence_prefix_for(
    prefix: &[u8],
    checkpoint: &Checkpoint,
    expected: &ProductionScope,
) -> Result<VerifiedSupplementedEvidenceProduction, EvidenceProductionError> {
    let records = authenticated_records(prefix, checkpoint, expected)?;
    let inventory = inventory_from_records(&records, checkpoint, expected)?;

    // Index authenticated digests, not claimed supplemental identities. An
    // identical digest at two positions cannot identify one original record.
    let mut targets = BTreeMap::new();
    for (position, record) in records.iter().enumerate() {
        if record.envelope.kind == KIND_ENTRY && record.envelope.commit_seq <= expected.known_at {
            targets
                .entry(record.envelope.record_digest)
                .and_modify(|position| *position = None)
                .or_insert(Some(position));
        }
    }
    let mut identities = BTreeMap::new();
    let mut seen_supplements = BTreeSet::new();
    let mut supplements = Vec::new();
    let mut citation_count = inventory.citation_count;
    for (position, record) in records.iter().enumerate() {
        if record.envelope.kind != KIND_SUPPLEMENTAL_EVIDENCE
            || record.envelope.commit_seq > expected.known_at
        {
            continue;
        }
        let leaf_index = position as u64; // complete_records bounds the prefix.
        if !seen_supplements.insert(record.envelope.record_digest) {
            return Err(invalid(leaf_index, "duplicate supplemental record"));
        }
        let supplement = read_supplement(record, leaf_index, &checkpoint.book_id)?;
        let target_position = targets
            .get(&supplement.entry_digest)
            .ok_or_else(|| {
                invalid(
                    leaf_index,
                    "target digest is absent at the requested known-at",
                )
            })?
            .ok_or_else(|| invalid(leaf_index, "target digest names multiple entry records"))?;
        let target = &records[target_position];
        if target.envelope.commit_seq >= supplement.recorded_at {
            return Err(invalid(
                leaf_index,
                "target did not commit before attachment",
            ));
        }
        let target_identity = match identities.get(&target_position) {
            Some(identity) => *identity,
            None => {
                let identity = identity::entry_identity(target, target_position as u64)?;
                identities.insert(target_position, identity);
                identity
            }
        };
        if supplement.entry_vid != target_identity {
            return Err(invalid(
                leaf_index,
                "target identity does not match its immutable payload",
            ));
        }
        if expected.selects(&target.envelope) {
            citation_count = citation_count
                .checked_add(supplement.citations.len())
                .filter(|count| *count <= MAX_PRODUCTION_CITATIONS)
                .ok_or(EvidenceProductionError::Limit("aggregate citation count"))?;
            supplements
                .try_reserve(1)
                .map_err(|_| EvidenceProductionError::Limit("supplement allocation"))?;
            supplements.push(supplement);
        }
    }
    Ok(VerifiedSupplementedEvidenceProduction {
        inventory,
        supplements,
        citation_count,
    })
}

/// Verify the exact distinct union of full document bytes required by the
/// original and supplemental inventory. A shared file is hashed once; every
/// entry/attachment/role association remains in the inventory and its count.
/// Missing, extra, duplicate, reordered or corrupt files refuse atomically.
///
/// One 64 MiB budget covers the full prefix plus all supplied document bytes,
/// before authentication or document hashing. Documents must be strictly
/// ordered by locator. Expected commitments come only from the authenticated
/// inventory. This proves byte recomputation, not provenance or permission.
pub fn verify_supplemented_document_prefix_for(
    prefix: &[u8],
    documents: &[DocumentContent<'_>],
    checkpoint: &Checkpoint,
    expected: &ProductionScope,
) -> Result<VerifiedSupplementedDocumentProduction, DocumentProductionError> {
    validate_inputs(prefix, &[], documents, checkpoint, expected)?;
    let inventory = verify_supplemented_evidence_prefix_for(prefix, checkpoint, expected)?;
    let citations = inventory
        .inventory
        .entries
        .iter()
        .flat_map(|entry| &entry.citations)
        .chain(
            inventory
                .supplements
                .iter()
                .flat_map(|entry| &entry.citations),
        );
    let (documents, document_byte_count) =
        verify_cited_documents(inventory.citation_count, citations, documents)?;
    Ok(VerifiedSupplementedDocumentProduction {
        inventory,
        document_scope: "recomputation",
        documents,
        document_byte_count,
    })
}

fn read_supplement(
    record: &LeafRecord<'_>,
    leaf_index: u64,
    book: &[u8; 16],
) -> Result<ProducedSupplement, EvidenceProductionError> {
    let at_leaf = |error| EvidenceProductionError::Evidence { leaf_index, error };
    // Authentication already checked the split, body digest, book and list
    // framing. Borrow the exact body and enforce the document identity law.
    let mut r = Reader::new(&record.payload[..record.split]);
    let read = (|| -> Result<ProducedSupplement, EvidenceError> {
        if r.u16("supplement.version")? != 1 {
            return Err(EvidenceError::Request("unsupported supplemental version"));
        }
        if &r.fixed::<16>("supplement.book_id")? != book {
            return Err(EvidenceError::Request("supplement names another book"));
        }
        let entry_vid = r.u128("supplement.entry_vid")?;
        let entry_digest = r.fixed("supplement.entry_digest")?;
        let count = r.count(1024, 65, "supplement.documents")?;
        if count == 0 {
            return Err(r.error("supplement.documents", Reason::BadTag(0)).into());
        }
        let mut citations = Vec::new();
        citations
            .try_reserve_exact(count)
            .map_err(|_| EvidenceError::InputLimit)?;
        let mut previous = None;
        for _ in 0..count {
            let citation = EvidenceCitation {
                document_oid: r.fixed("supplement.document_oid")?,
                doc_commit: r.fixed("supplement.doc_commit")?,
                role: r.u8("supplement.role")?,
            };
            if previous.is_some_and(|prior| prior >= citation) {
                return Err(r.error("supplement.documents", Reason::Unsorted).into());
            }
            if citation.document_oid != document_oid(book, &citation.doc_commit) {
                return Err(EvidenceError::DocumentIdentity);
            }
            previous = Some(citation);
            citations.push(citation);
        }
        let attached_by = r.u128("supplement.attached_by")?;
        r.finish("supplement.body")?;
        Ok(ProducedSupplement {
            leaf_index,
            recorded_at: record.envelope.commit_seq,
            record_digest: record.envelope.record_digest,
            entry_vid,
            entry_digest,
            attached_by,
            citations,
        })
    })();
    read.map_err(at_leaf)
}
