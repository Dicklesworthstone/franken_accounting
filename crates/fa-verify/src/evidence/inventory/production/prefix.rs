//! Original citation inventories directly from a native payload-complete prefix.
//!
//! `fa proof prefix --with-record` already discloses every entry payload.
//! Requiring a second copy of each selected payload inside an inclusion proof
//! is unnecessary here: authenticate the whole prefix, select locally, then
//! inventory the selected records in that same immutable witness. This does
//! not verify a separate producer-supplied extract or a provenance closure.

use crate::codec::Reader;
use crate::envelope::{MAX_RECORD_BYTES, RecordError};
use crate::evidence::EvidenceError;
use crate::proof::production::derivation::{PREFIX_FORMAT_V2, verify_prefix_with_records};
use crate::proof::production::{
    MAX_PRODUCTION_BYTES, MAX_PRODUCTION_LEAVES, MAX_PRODUCTION_RECORDS,
    ProducedEntry, ProductionError, ProductionScope,
};
use crate::proof::{Checkpoint, VerifyError, open};

use super::super::citations_from_proposal;
use super::{
    EvidenceProductionError, MAX_PRODUCTION_CITATIONS, ProducedEvidence,
    VerifiedEvidenceProduction,
};

/// Borrow the record list only after the entire native v2 witness has passed
/// authentication. All fields are bounded again, but hashes are not repeated.
fn records_reader(bytes: &[u8], expected: usize) -> Result<Reader<'_>, VerifyError> {
    let mut reader = open(bytes, PREFIX_FORMAT_V2)?;
    Checkpoint::read(&mut reader)?;
    let count = reader.count(MAX_PRODUCTION_LEAVES, 4, "prefix.envelopes")?;
    for _ in 0..count {
        reader.bytes(MAX_RECORD_BYTES, "prefix.envelope")?;
    }
    let count = reader.count(MAX_PRODUCTION_LEAVES, 16, "prefix.records")?;
    if count != expected {
        return Err(VerifyError::RecordSet { index: count as u64 });
    }
    Ok(reader)
}

fn record<'a>(reader: &mut Reader<'a>, position: usize) -> Result<(&'a [u8], usize), VerifyError> {
    let index = reader.u64("prefix.record.leaf_index")?;
    if index != position as u64 {
        return Err(VerifyError::RecordSet { index });
    }
    let split = usize::try_from(reader.u32("prefix.record.proposal_len")?)
        .map_err(|_| VerifyError::Record(RecordError::Split))?;
    Ok((reader.bytes(MAX_RECORD_BYTES, "prefix.record.payload")?, split))
}

/// The entry's digests and split were already checked. As in the existing
/// inclusion inventory, also check plan-certificate/approval framing before
/// interpreting its original citations. Hashing bytes alone is not this check.
fn framed_proposal(payload: &[u8], split: usize) -> Result<&[u8], EvidenceError> {
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
    expected.validate()?;
    if expected.known_at > checkpoint.through_seq {
        return Err(ProductionError::Request("known_at is later than the trusted checkpoint").into());
    }
    if bytes.len() > MAX_PRODUCTION_BYTES {
        return Err(ProductionError::Limit("aggregate encoded bytes").into());
    }
    // Reject proof-kind confusion before any crypto work. The broader shared
    // prefix verifier also accepts v3 balances; this borrowing decoder does not.
    open(bytes, PREFIX_FORMAT_V2).map_err(ProductionError::Prefix)?;
    let prefix = verify_prefix_with_records(bytes, checkpoint).map_err(ProductionError::Prefix)?;
    let count = prefix.envelopes.iter().filter(|entry| expected.selects(entry)).count();
    if count > MAX_PRODUCTION_RECORDS {
        return Err(ProductionError::Limit("selected record count").into());
    }
    let mut reader = records_reader(bytes, prefix.envelopes.len()).map_err(ProductionError::Prefix)?;
    let mut entries = Vec::new();
    entries.try_reserve_exact(count)
        .map_err(|_| EvidenceProductionError::Limit("entry allocation"))?;
    let mut citation_count = 0usize;
    for (position, envelope) in prefix.envelopes.into_iter().enumerate() {
        let (payload, split) = record(&mut reader, position).map_err(ProductionError::Prefix)?;
        if !expected.selects(&envelope) {
            continue;
        }
        let leaf_index = position as u64; // bounded by MAX_PRODUCTION_LEAVES
        let at_leaf = |error| EvidenceProductionError::Evidence { leaf_index, error };
        let proposal = framed_proposal(payload, split).map_err(at_leaf)?;
        let citations = citations_from_proposal(proposal, &checkpoint.book_id).map_err(at_leaf)?;
        citation_count = citation_count.checked_add(citations.len())
            .filter(|count| *count <= MAX_PRODUCTION_CITATIONS)
            .ok_or(EvidenceProductionError::Limit("aggregate citation count"))?;
        entries.push(ProducedEvidence {
            entry: ProducedEntry { leaf_index, envelope },
            citations,
        });
    }
    reader.finish("complete prefix proof")
        .map_err(VerifyError::from).map_err(ProductionError::Prefix)?;
    Ok(VerifiedEvidenceProduction {
        scope: prefix.scope,
        checkpoint: prefix.checkpoint,
        requested: *expected,
        entries,
        citation_count,
    })
}
