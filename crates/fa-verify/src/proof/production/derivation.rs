//! Payload-complete prefix witnesses for scoped productions (fa-n6fh).
//!
//! `bytes(format) || Checkpoint || list(bytes(LeafEnvelope)) ||
//! list(leaf_index u64 || proposal_len u32 || bytes(entry_payload))`.
//!
//! Every selector is rebuilt, including excluded records. The checkpoint
//! authenticates bytes, not correct indexing. This format discloses the full
//! prefix's entry payloads and is not a privacy-preserving scope index.

use crate::codec::{DecodeError, Reason};
use crate::envelope::{MAX_RECORD_BYTES, check_record};
use crate::proof::{
    Checkpoint, Prefix, SCOPE_SEQ_RANGE_COMPLETE, VerifyError, complete_prefix,
    open, read_envelopes, trusted,
};

pub const PREFIX_FORMAT_V2: &[u8] = b"fa:acc-prefix-proof:v2";
pub const MAX_PREFIX_PROOF_BYTES: usize = 64 * 1024 * 1024;

/// Verify complete prefix membership AND payload-to-selector derivation.
/// Unlike the legacy `crate::verify_prefix`, this requires every payload.
/// No accounting admission, signature or migration-visibility claim is made.
pub fn verify_prefix_with_records(
    proof: &[u8],
    anchor: &Checkpoint,
) -> Result<Prefix, VerifyError> {
    if proof.len() > MAX_PREFIX_PROOF_BYTES {
        return Err(VerifyError::Decode(DecodeError {
            offset: 0,
            what: "complete prefix bytes",
            reason: Reason::TooLong {
                max: MAX_PREFIX_PROOF_BYTES,
                actual: proof.len(),
            },
        }));
    }
    let mut r = open(proof, PREFIX_FORMAT_V2)?;
    let checkpoint = trusted(Checkpoint::read(&mut r)?, anchor)?;
    let raw = read_envelopes(&mut r)?;
    let envelopes = complete_prefix(&raw, &checkpoint)?;
    let count = r.count(envelopes.len(), 16, "prefix.records")?;
    if count != envelopes.len() {
        return Err(VerifyError::RecordSet {
            index: u64::try_from(count).unwrap_or(u64::MAX),
        });
    }
    for (position, envelope) in envelopes.iter().enumerate() {
        let index = r.u64("prefix.record.leaf_index")?;
        let expected = u64::try_from(position).unwrap_or(u64::MAX);
        if index != expected {
            return Err(VerifyError::RecordSet { index: index.min(expected) });
        }
        let split = usize::try_from(r.u32("prefix.record.proposal_len")?)
            .unwrap_or(usize::MAX);
        let payload = r.bytes(MAX_RECORD_BYTES, "prefix.record.payload")?;
        check_record(envelope, payload, split).map_err(VerifyError::Record)?;
    }
    r.finish("complete prefix proof")?;
    Ok(Prefix { scope: SCOPE_SEQ_RANGE_COMPLETE, checkpoint, envelopes })
}
