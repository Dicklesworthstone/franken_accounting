//! Original citation inventories directly from a native payload-complete prefix.
//!
//! `fa proof prefix --with-record` already discloses every entry payload.
//! Requiring a second copy of each selected payload inside an inclusion proof
//! is unnecessary here: authenticate the whole prefix, select locally, then
//! inventory the selected records in that same immutable witness. This does
//! not verify a separate producer-supplied extract or a provenance closure.

use crate::codec::Reader;
use crate::envelope::RecordError;
use crate::evidence::EvidenceError;
use crate::proof::production::derivation::{LeafRecord, complete_records};
use crate::proof::production::{
    MAX_PRODUCTION_BYTES, MAX_PRODUCTION_RECORDS, ProducedEntry, ProductionError, ProductionScope,
};
use crate::proof::{Checkpoint, SCOPE_SEQ_RANGE_COMPLETE, VerifyError};

use super::super::citations_from_proposal;
use super::{
    EvidenceProductionError, MAX_PRODUCTION_CITATIONS, ProducedEvidence, VerifiedEvidenceProduction,
};

/// The entry's digests and split were already checked. As in the existing
/// inclusion inventory, also check plan-certificate/approval framing before
/// interpreting its original citations. Hashing bytes alone is not this check.
pub(super) fn framed_proposal(payload: &[u8], split: usize) -> Result<&[u8], EvidenceError> {
    let split_error = || EvidenceError::Proof(VerifyError::Record(RecordError::Split));
    let end = payload.len().checked_sub(64).ok_or_else(split_error)?;
    let mut envelope = Reader::new(payload.get(split..end).ok_or_else(split_error)?);
    if envelope.present("entry.plan_certificate")? {
        envelope.fixed::<32>("entry.plan_certificate")?;
    }
    let approvals = envelope.count(256, 48, "entry.approvals")?;
    for _ in 0..approvals {
        envelope.fixed::<48>("entry.approval")?;
    }
    envelope.finish("entry envelope")?;
    payload.get(..split).ok_or_else(split_error)
}

/// Derive the complete original citation inventory for an independent scope
/// from one native v2 prefix. No individual inclusion proofs are necessary.
///
/// The trusted checkpoint and ALL selectors are caller-owned inputs. Every
/// prefix payload, including excluded and later-effective records, is checked
/// before selection. Selected entries then undergo full citation-list and
/// entry-frame checks. No metadata escapes until the entire operation passes.
///
/// This deliberately accepts only the native v2 prefix, not legacy envelopes
/// or a balance proof. The existing multi-proof production API retains those
/// formats under its original rules. Whole-prefix disclosure is required;
/// neither this API nor its output grants authority to disclose the witness.
pub fn verify_evidence_prefix_for(
    bytes: &[u8],
    checkpoint: &Checkpoint,
    expected: &ProductionScope,
) -> Result<VerifiedEvidenceProduction, EvidenceProductionError> {
    let records = authenticated_records(bytes, checkpoint, expected)?;
    inventory_from_records(&records, checkpoint, expected)
}

/// Authenticate once and retain borrowed payloads for the original inventory
/// and any independently requested supplemental target joins.
pub(super) fn authenticated_records<'a>(
    bytes: &'a [u8],
    checkpoint: &Checkpoint,
    expected: &ProductionScope,
) -> Result<Vec<LeafRecord<'a>>, EvidenceProductionError> {
    expected.validate()?;
    if expected.known_at > checkpoint.through_seq {
        return Err(
            ProductionError::Request("known_at is later than the trusted checkpoint").into(),
        );
    }
    if bytes.len() > MAX_PRODUCTION_BYTES {
        return Err(ProductionError::Limit("aggregate encoded bytes").into());
    }
    complete_records(bytes, checkpoint)
        .map_err(ProductionError::Prefix)
        .map_err(EvidenceProductionError::from)
}

pub(super) fn inventory_from_records(
    records: &[LeafRecord<'_>],
    checkpoint: &Checkpoint,
    expected: &ProductionScope,
) -> Result<VerifiedEvidenceProduction, EvidenceProductionError> {
    let count = records
        .iter()
        .filter(|record| expected.selects(&record.envelope))
        .count();
    if count > MAX_PRODUCTION_RECORDS {
        return Err(ProductionError::Limit("selected record count").into());
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| EvidenceProductionError::Limit("entry allocation"))?;
    let mut citation_count = 0usize;
    for (position, record) in records.iter().enumerate() {
        if !expected.selects(&record.envelope) {
            continue;
        }
        let leaf_index = position as u64; // bounded by MAX_PRODUCTION_LEAVES
        let at_leaf = |error| EvidenceProductionError::Evidence { leaf_index, error };
        let proposal = framed_proposal(record.payload, record.split).map_err(at_leaf)?;
        let citations = citations_from_proposal(proposal, &checkpoint.book_id).map_err(at_leaf)?;
        citation_count = citation_count
            .checked_add(citations.len())
            .filter(|count| *count <= MAX_PRODUCTION_CITATIONS)
            .ok_or(EvidenceProductionError::Limit("aggregate citation count"))?;
        entries.push(ProducedEvidence {
            entry: ProducedEntry {
                leaf_index,
                envelope: record.envelope.clone(),
            },
            citations,
        });
    }
    Ok(VerifiedEvidenceProduction {
        scope: SCOPE_SEQ_RANGE_COMPLETE,
        checkpoint: *checkpoint,
        requested: *expected,
        entries,
        citation_count,
    })
}
