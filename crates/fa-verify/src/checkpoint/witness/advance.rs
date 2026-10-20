//! Monotonic acceptance relative to a retained, quorum-verified checkpoint.
//!
//! This never persists a pin and cannot prove the candidate is the latest head.
//! The embedding must retain the last accepted checkpoint and its independently
//! configured policy outside the producer's rollback domain. Bootstrap and key
//! rotation are separate trust decisions; a candidate cannot replace the policy.

use std::fmt;

use super::{WitnessError, WitnessedCheckpoint, verify_witnessed_checkpoint};
use crate::proof::{CONSISTENCY_FORMAT, Checkpoint, VerifyError, verify_consistency};

/// V1 length-framed format, two checkpoint statements, count and at most 64
/// sibling digests. Checked before signature work; the decoder checks shape.
pub const MAX_WITNESS_CONSISTENCY_BYTES: usize =
    4 + CONSISTENCY_FORMAT.len() + 2 * Checkpoint::ENCODED_LEN + 4 + 64 * 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvanceStatus {
    /// The signed BODY is identical; a different signature set is not a fork.
    Unchanged,
    /// The recorded sequence increased and the tree extends the retained tree.
    Advanced,
}

/// Both candidate quorum and tree continuity passed. Private fields keep the
/// verified next pin distinct from caller-constructed reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointAdvance {
    checkpoint: WitnessedCheckpoint,
    status: AdvanceStatus,
}

impl CheckpointAdvance {
    #[must_use]
    pub fn checkpoint(&self) -> &WitnessedCheckpoint {
        &self.checkpoint
    }

    #[must_use]
    pub fn status(&self) -> AdvanceStatus {
        self.status
    }

    /// Install only after the embedding's own durable, atomic pin update.
    #[must_use]
    pub fn into_checkpoint(self) -> WitnessedCheckpoint {
        self.checkpoint
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdvanceError {
    Witness(WitnessError),
    Consistency(VerifyError),
    ProofLimit,
    Regression,
    /// A different signed body claims the very same recorded sequence.
    /// Includes state, index, chain and policy/time metadata, not only the tree.
    Equivocation,
}

impl fmt::Display for AdvanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Witness(error) => write!(f, "{error}"),
            Self::Consistency(error) => write!(f, "{error}"),
            Self::ProofLimit => write!(f, "witness consistency proof exceeds its v1 byte bound"),
            Self::Regression => write!(f, "checkpoint regresses the retained sequence or leaf count"),
            Self::Equivocation => write!(f, "different signed checkpoint bodies claim the same sequence"),
        }
    }
}

impl std::error::Error for AdvanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Witness(error) => Some(error),
            Self::Consistency(error) => Some(error),
            _ => None,
        }
    }
}

/// Accept a checkpoint only under the retained pin's unchanged recipient policy
/// AND an exact append-only consistency proof from that pin. There is no optional
/// proof or fallback to signature-only verification, even for an unchanged tree.
///
/// A quorum signature does not excuse a rollback, a different history, or a new
/// signed body at the same sequence. Re-signing the SAME body with a sufficient
/// different witness subset is permitted; artifact OIDs include signatures and
/// are therefore not the identity used to detect equivocation.
///
/// This borrows the previous pin and never mutates it on failure or success.
/// Persisting the returned pin, protecting it from rollback, authenticating
/// policy/rotation and collecting witnesses are the embedding's responsibility.
/// The result checks tree consistency, NOT appended record semantics, scope-index
/// derivation, wall-clock freshness or the absence of colluding/quorum forks.
pub fn verify_checkpoint_advance(
    previous: &WitnessedCheckpoint,
    candidate_bytes: &[u8],
    consistency_proof: &[u8],
) -> Result<CheckpointAdvance, AdvanceError> {
    if consistency_proof.len() > MAX_WITNESS_CONSISTENCY_BYTES {
        return Err(AdvanceError::ProofLimit);
    }
    // The next artifact supplies no replacement keys, quorum, book or policy ID.
    let candidate = verify_witnessed_checkpoint(candidate_bytes, &previous.policy)
        .map_err(AdvanceError::Witness)?;
    let old = &previous.signed.checkpoint;
    let new = &candidate.signed.checkpoint;
    if new.through_seq < old.through_seq || new.leaf_count < old.leaf_count {
        return Err(AdvanceError::Regression);
    }
    let status = if new.through_seq == old.through_seq {
        if candidate.signed.body_digest != previous.signed.body_digest {
            return Err(AdvanceError::Equivocation);
        }
        AdvanceStatus::Unchanged
    } else {
        AdvanceStatus::Advanced
    };
    verify_consistency(consistency_proof, old, new).map_err(AdvanceError::Consistency)?;
    Ok(CheckpointAdvance { checkpoint: candidate, status })
}
