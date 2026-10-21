//! Exact record-bearing suffixes for an independently retained journal prefix.
//!
//! The recipient's retained statement, not an account/date filter or a list of
//! vertex IDs, fixes the boundary. Every new leaf is exported in journal order,
//! including undated controls and evidence records. Wire formats are unchanged:
//! one existing consistency proof plus existing v1 inclusion proofs.

use core::fmt;

use fa_journal::refusal::{Outcome, Refusal, exit};
use fa_model::Writer;

use super::{
    MAX_ENVELOPE_BYTES, MAX_PREFIX_LEAVES, MAX_PREFIX_PROOF_BYTES, MAX_RECORD_BYTES, MAX_SELECTORS,
    drift,
};
use crate::journal::INCLUSION_FORMAT;
use crate::tree::{Tree, leaf_hash};
use crate::{Journal, Statement};

/// Match the independent incremental verifier's per-advance record limit.
pub const MAX_SUFFIX_RECORDS: usize = 4096;

/// A transport of existing proof bytes, not a signature or authorization.
/// The caller must obtain a signed candidate checkpoint separately, and the
/// recipient must verify it under its own retained policy before accepting it.
/// Private fields and getters avoid accidental modification during assembly;
/// this producer result is NOT a substitute for independent verification.
pub struct RecordSuffix {
    previous: Statement,
    checkpoint: Statement,
    consistency: Vec<u8>,
    records: Vec<Vec<u8>>,
    encoded_bytes: usize,
}

// Never dump protected record payloads through debug logs or failed assertions.
impl fmt::Debug for RecordSuffix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordSuffix")
            .field("first_leaf", &self.previous.leaf_count)
            .field("record_count", &self.records.len())
            .field("encoded_bytes", &self.encoded_bytes)
            .finish_non_exhaustive()
    }
}

impl RecordSuffix {
    #[must_use]
    pub fn previous(&self) -> &Statement {
        &self.previous
    }

    #[must_use]
    pub fn checkpoint(&self) -> &Statement {
        &self.checkpoint
    }

    #[must_use]
    pub fn consistency_proof(&self) -> &[u8] {
        &self.consistency
    }

    /// Exactly [previous.leaf_count, checkpoint.leaf_count), in leaf order.
    #[must_use]
    pub fn records(&self) -> &[Vec<u8>] {
        &self.records
    }

    /// Sum of the consistency and inclusion frames, not the signed checkpoint
    /// or the recipient's retained evidence. Charge those separately.
    #[must_use]
    pub fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }
}

fn limit(what: &'static str) -> Refusal {
    Refusal::new(
        "FA-REF-127",
        exit::USAGE,
        format!("record-complete suffix exceeds its {what} limit"),
        "plan §13.2 (a verified delta contains every appended journal record)",
        "choose a nearer checkpoint or a larger admitted remaining budget; never omit suffix records",
    )
}

fn charge(total: &mut usize, amount: usize, budget: usize) -> Result<(), Refusal> {
    *total = total
        .checked_add(amount)
        .filter(|n| *n <= budget)
        .ok_or_else(|| limit("remaining encoded-byte"))?;
    Ok(())
}

fn inclusion_size(envelope: usize, payload: usize, path: usize) -> usize {
    // All three lengths are bounded before this arithmetic. On every admitted
    // host this is <= 8 MiB + MAX_ENVELOPE_BYTES + 64 digests + fixed framing.
    4 + INCLUSION_FORMAT.len() + 80 + 8 + 4 + envelope + 1 + 4 + 4 + payload + 4 + 32 * path
}

impl Journal {
    /// Export the complete suffix after an independently chosen old statement.
    ///
    /// `remaining_bytes` is the caller's REMAINING transport budget, at most
    /// 64 MiB. The retained baseline and signed checkpoint may consume part of
    /// a recipient's cumulative budget; this method cannot infer those costs.
    /// Every inclusion frame is sized before output allocation, with a 4,096
    /// appended-record and 65,536 total-leaf bound. Nothing is returned if any
    /// leaf fails. Both empty histories and unchanged trees still produce an
    /// explicit consistency proof.
    ///
    /// All envelopes and cached hashes are checked against the current tree
    /// and retained root. Only appended payloads are decoded or exported: the
    /// recipient has already verified its retained records. This does not audit
    /// old payload availability, source retention or database immutability.
    /// It is a pure encoder, not a capability-admitting export endpoint. The
    /// embedding must authorize ALL suffix records, including evidence leaves.
    pub fn suffix_proofs_with_records(
        &self,
        previous: &Statement,
        remaining_bytes: usize,
    ) -> Outcome<RecordSuffix> {
        if remaining_bytes > MAX_PREFIX_PROOF_BYTES {
            return Ok(Err(limit("64 MiB transport")));
        }
        if self.leaves.len() > MAX_PREFIX_LEAVES {
            return Ok(Err(limit("65,536-leaf")));
        }
        if previous.book_id != self.book_id
            || previous.branch_id != self.branch_id
            || previous.through_seq > self.through_seq
            || previous.leaf_count > self.len()
        {
            return Ok(Err(drift(
                "the retained statement is not an earlier coordinate of this journal",
            )));
        }
        // The previous count is now bounded by this host's actual vector size.
        let first = previous.leaf_count as usize;
        if self.leaves.len() - first > MAX_SUFFIX_RECORDS {
            return Ok(Err(limit("4,096-record")));
        }
        let consistency = match self.consistency_proof(previous)? {
            Some(bytes) => bytes,
            None => {
                return Ok(Err(drift(
                    "the retained journal root is not a prefix of this history",
                )));
            }
        };
        let mut size = 0;
        if let Err(refusal) = charge(&mut size, consistency.len(), remaining_bytes) {
            return Ok(Err(refusal));
        }
        let mut rebuilt = Tree::new();
        let mut before = None;
        for (index, leaf) in self.leaves.iter().enumerate() {
            let envelope = &leaf.envelope;
            if envelope.account_vids.len() > MAX_SELECTORS
                || envelope.unit_ids.len() > MAX_SELECTORS
                || leaf.envelope_bytes.len() > MAX_ENVELOPE_BYTES
            {
                return Ok(Err(limit("envelope-selector")));
            }
            let position = (envelope.commit_seq, envelope.within_commit_ordinal);
            if envelope.book_id != self.book_id
                || envelope.branch_id != self.branch_id
                || envelope.commit_seq > self.through_seq
                || before.is_some_and(|prior| prior >= position)
                || ((index < first) != (envelope.commit_seq <= previous.through_seq))
            {
                return Ok(Err(drift(format!(
                    "leaf {index} contradicts journal order or the retained recorded boundary"
                ))));
            }
            before = Some(position);
            if envelope
                .canonical_bytes()
                .map_err(fa_model::EntryError::Encode)?
                != leaf.envelope_bytes
            {
                return Ok(Err(drift(format!(
                    "leaf {index} disagrees with its canonical envelope"
                ))));
            }
            let hash = leaf_hash(&leaf.envelope_bytes);
            if hash != leaf.hash {
                return Ok(Err(drift(format!(
                    "leaf {index} has an inconsistent cached hash"
                ))));
            }
            rebuilt.push(hash);
            if index < first {
                continue;
            }
            if leaf.payload.len() > MAX_RECORD_BYTES || leaf.proposal_len > u32::MAX as usize {
                return Ok(Err(limit("8 MiB record-payload or u32 split")));
            }
            if leaf.authenticated_record()?.is_none() {
                return Ok(Err(drift(format!(
                    "appended leaf {index} disagrees with its record payload"
                ))));
            }
            let Some(path) = self.leaf_path(index) else {
                return Ok(Err(drift("an appended leaf has no accumulator path")));
            };
            if path.len() > 64 {
                return Ok(Err(limit("inclusion-path")));
            }
            if let Err(refusal) = charge(
                &mut size,
                inclusion_size(leaf.envelope_bytes.len(), leaf.payload.len(), path.len()),
                remaining_bytes,
            ) {
                return Ok(Err(refusal));
            }
        }
        if rebuilt.root() != self.root() || rebuilt.root_at(first) != Some(previous.root) {
            return Ok(Err(drift(
                "the current envelopes do not reproduce the retained and candidate roots",
            )));
        }
        let checkpoint = self.statement();
        let mut records = Vec::new();
        if records
            .try_reserve_exact(self.leaves.len() - first)
            .is_err()
        {
            return Ok(Err(limit("record allocation")));
        }
        for index in first..self.leaves.len() {
            let leaf = &self.leaves[index];
            let Some(path) = self.leaf_path(index) else {
                return Ok(Err(drift("an appended leaf has no accumulator path")));
            };
            let length = inclusion_size(leaf.envelope_bytes.len(), leaf.payload.len(), path.len());
            let mut w = Writer::with_capacity(length);
            w.bytes(INCLUSION_FORMAT);
            checkpoint.encode(&mut w);
            w.u64(index as u64)
                .bytes(&leaf.envelope_bytes)
                .u8(1)
                .u32(leaf.proposal_len as u32)
                .bytes(&leaf.payload);
            w.list(&path, |w, digest| {
                w.fixed(digest);
            });
            let bytes = w.finish().map_err(fa_model::EntryError::Encode)?;
            if bytes.len() != length {
                return Ok(Err(drift(
                    "suffix serialization disagrees with its framed size",
                )));
            }
            records.push(bytes);
        }
        Ok(Ok(RecordSuffix {
            previous: *previous,
            checkpoint,
            consistency,
            records,
            encoded_bytes: size,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_transport_budget_is_exact_and_never_wraps() {
        let mut n = MAX_PREFIX_PROOF_BYTES - 1;
        charge(&mut n, 1, MAX_PREFIX_PROOF_BYTES).unwrap();
        assert!(charge(&mut n, 1, MAX_PREFIX_PROOF_BYTES).is_err());
        let mut n = usize::MAX;
        assert!(charge(&mut n, 1, MAX_PREFIX_PROOF_BYTES).is_err());
        assert!(charge(&mut 0, 1, 0).is_err());
    }
}
