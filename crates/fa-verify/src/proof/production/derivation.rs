//! Complete-prefix evidence for scoped productions (fa-n6fh).
//!
//! V2 prefix: `bytes(format) || Checkpoint || list(bytes(LeafEnvelope)) ||
//! list(leaf_index u64 || proposal_len u32 || bytes(entry_payload))`.
//!
//! Native v3 balance exports also carry every prefix payload. They can be
//! reused directly as prefix witnesses, even for a different recipient scope.
//! Their balance claim and migration witnesses are fully verified first.
//! Both forms disclose all prefix entry payloads, not a private scope index.

use crate::codec::{DecodeError, Reader, Reason};
use crate::envelope::{LeafEnvelope, MAX_RECORD_BYTES, check_record};
use crate::migration_balance::BALANCE_FORMAT_V3;
use crate::proof::{
    Checkpoint, PREFIX_FORMAT, Prefix, SCOPE_SEQ_RANGE_COMPLETE, VerifyError,
    complete_prefix, open, read_envelopes, trusted,
};

pub const PREFIX_FORMAT_V2: &[u8] = b"fa:acc-prefix-proof:v2";
pub const MAX_PREFIX_PROOF_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PrefixKind { Legacy, Complete, Balance }

/// Position a bounded reader at the envelope list of a registered format.
/// This validates only the header, not the prefix or the balance claim.
pub(super) fn read_header<'a>(
    proof: &'a [u8], anchor: &Checkpoint,
) -> Result<(Reader<'a>, PrefixKind), VerifyError> {
    let tag = Reader::new(proof).bytes(64, "proof.format")?;
    let (format, kind) = if tag == PREFIX_FORMAT_V2 {
        (PREFIX_FORMAT_V2, PrefixKind::Complete)
    } else if tag == BALANCE_FORMAT_V3 {
        (BALANCE_FORMAT_V3, PrefixKind::Balance)
    } else {
        (PREFIX_FORMAT, PrefixKind::Legacy)
    };
    let mut r = open(proof, format)?;
    trusted(Checkpoint::read(&mut r)?, anchor)?;
    if kind == PrefixKind::Balance {
        r.u128("balance.account")?;
        r.u32("balance.unit")?;
        if r.present("balance.effective_through")? { r.i32("balance.effective_through")?; }
        r.i128("balance.debits")?;
        r.i128("balance.credits")?;
    }
    Ok((r, kind))
}

/// Verify every payload-to-selector derivation against an independent anchor.
/// Accepts v2 prefixes or existing native v3 balance exports; legacy prefixes
/// alone cannot prove exclusions. This grants no disclosure authority.
pub fn verify_prefix_with_records(
    proof: &[u8], anchor: &Checkpoint,
) -> Result<Prefix, VerifyError> {
    if proof.len() > MAX_PREFIX_PROOF_BYTES {
        return Err(VerifyError::Decode(DecodeError {
            offset: 0, what: "complete prefix bytes",
            reason: Reason::TooLong { max: MAX_PREFIX_PROOF_BYTES, actual: proof.len() },
        }));
    }
    let (mut preflight, kind) = read_header(proof, anchor)?;
    if kind == PrefixKind::Legacy {
        return Err(VerifyError::Format { expected: PREFIX_FORMAT_V2 });
    }
    preflight.count(super::MAX_PRODUCTION_LEAVES, 4, "production.prefix.envelopes")?;
    if kind == PrefixKind::Balance {
        // Do not treat a parseable header as a verified balance certificate.
        // Existing v3 verifies all records, lifecycle bodies and exact sums.
        let balance = crate::verify_balance(proof, anchor)?;
        let (mut r, _) = read_header(proof, anchor)?;
        let raw = read_envelopes(&mut r)?;
        // Membership, order and every selector were checked by v3 above.
        // Decode the same immutable bytes without hashing the prefix twice.
        let envelopes = raw.into_iter().map(LeafEnvelope::decode)
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(Prefix { scope: SCOPE_SEQ_RANGE_COMPLETE,
            checkpoint: balance.checkpoint, envelopes });
    }
    let (mut r, _) = read_header(proof, anchor)?;
    let raw = read_envelopes(&mut r)?;
    let envelopes = complete_prefix(&raw, anchor)?;
    let count = r.count(envelopes.len(), 16, "prefix.records")?;
    if count != envelopes.len() {
        return Err(VerifyError::RecordSet { index: count as u64 });
    }
    for (position, envelope) in envelopes.iter().enumerate() {
        let index = r.u64("prefix.record.leaf_index")?;
        let expected = position as u64; // bounded by MAX_PRODUCTION_LEAVES
        if index != expected {
            return Err(VerifyError::RecordSet { index: index.min(expected) });
        }
        let split = usize::try_from(r.u32("prefix.record.proposal_len")?).unwrap_or(usize::MAX);
        let payload = r.bytes(MAX_RECORD_BYTES, "prefix.record.payload")?;
        check_record(envelope, payload, split).map_err(VerifyError::Record)?;
    }
    r.finish("complete prefix proof")?;
    Ok(Prefix { scope: SCOPE_SEQ_RANGE_COMPLETE, checkpoint: *anchor, envelopes })
}
