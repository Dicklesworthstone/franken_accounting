//! Recipient-owned witness quorums for existing signed checkpoints (fa-qtfd).
//!
//! This is an in-memory trust decision, NOT a new serialized WitnessPolicy or
//! TrustAnchorSet. The caller obtains the publisher key, witness keys, quorum,
//! book, branch and policy-object ID independently. The checkpoint must bind
//! that ID, but this module does not fetch or interpret a policy document.
//!
//! A quorum counts distinct admitted keys, never signature rows, the publisher,
//! or unknown signers. Different keys do not establish organizational independence.
//! [`verify_checkpoint_advance`] additionally checks continuity from a retained
//! verified pin while keeping its policy unchanged. It does not persist that pin.
//! [`recorded::verify_recorded_checkpoint_advance`] additionally checks that
//! a complete candidate prefix preserves the retained recorded-time boundary.
//! Key validity intervals, rotation, witness capabilities, external collection,
//! durable pin storage, freshness and ledger/index correctness are not checked.

mod advance;
pub mod bundle;
pub mod recorded;

pub use advance::{
    AdvanceError, AdvanceStatus, CheckpointAdvance, MAX_WITNESS_CONSISTENCY_BYTES,
    verify_checkpoint_advance,
};

use std::collections::BTreeSet;
use std::fmt;

use super::{CheckpointError, SignedCheckpoint, signer_key_id, verify_checkpoint};
use crate::ed25519;
use crate::proof::{Checkpoint, VerifyError};
use crate::tree::Digest;

/// The canonical v1 decoder's maximum frame, including unknown signatures.
/// Enforce it before any key or signature work on an incoming checkpoint.
pub const MAX_WITNESSED_CHECKPOINT_BYTES: usize = 4
    + Checkpoint::ENCODED_LEN
    + 3 * 32
    + 2 * 33
    + 4
    + super::MAX_SIGNATURES * (32 + 2 + 4 + super::MAX_SIGNATURE_BYTES);

/// A validated recipient policy. Private fields prevent replacing keys or the
/// quorum after admission. The publisher must NOT appear in the witness list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientWitnessPolicy {
    book_id: [u8; 16],
    branch_id: [u8; 16],
    policy_oid: Digest,
    publisher_id: Digest,
    witness_ids: BTreeSet<Digest>,
    trusted_keys: Vec<[u8; 32]>,
    quorum: usize,
}

impl RecipientWitnessPolicy {
    /// Require a publisher AND a nonzero quorum of distinct witness keys.
    /// Duplicate keys and publisher/witness overlap are errors, not silently
    /// deduplicated votes. Unknown checkpoint signers never extend this policy.
    pub fn new(
        book_id: [u8; 16],
        branch_id: [u8; 16],
        policy_oid: Digest,
        publisher_key: [u8; 32],
        witness_keys: &[[u8; 32]],
        quorum: usize,
    ) -> Result<Self, WitnessError> {
        if witness_keys.is_empty() || witness_keys.len() >= super::MAX_SIGNATURES {
            return Err(WitnessError::Policy(
                "require between one and 63 witness keys",
            ));
        }
        if quorum == 0 || quorum > witness_keys.len() {
            return Err(WitnessError::Policy(
                "quorum must be between one and the witness count",
            ));
        }
        let publisher_id = signer_key_id(&publisher_key);
        let mut witness_ids = BTreeSet::new();
        for key in witness_keys {
            let id = signer_key_id(key);
            if id == publisher_id || !witness_ids.insert(id) {
                return Err(WitnessError::Policy(
                    "publisher and witness keys must all be distinct",
                ));
            }
        }
        let mut trusted_keys = Vec::with_capacity(witness_keys.len() + 1);
        trusted_keys.push(publisher_key);
        trusted_keys.extend_from_slice(witness_keys);
        for key in &trusted_keys {
            ed25519::check_public_key(key).map_err(|reason| {
                WitnessError::Verification(VerifyError::Checkpoint(CheckpointError::TrustedKey {
                    signer_key_id: signer_key_id(key),
                    reason,
                }))
            })?;
        }
        Ok(Self {
            book_id,
            branch_id,
            policy_oid,
            publisher_id,
            witness_ids,
            trusted_keys,
            quorum,
        })
    }

    #[must_use]
    pub fn required_witnesses(&self) -> usize {
        self.quorum
    }
}

/// A signature-verified checkpoint that additionally satisfied the recipient's
/// complete policy. This cannot be constructed from a caller-forged
/// `SignedCheckpoint` report: only raw bytes accepted by the verifier create it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessedCheckpoint {
    signed: SignedCheckpoint,
    policy: RecipientWitnessPolicy,
    witnesses: Vec<Digest>,
}

impl WitnessedCheckpoint {
    #[must_use]
    pub fn signed_checkpoint(&self) -> &SignedCheckpoint {
        &self.signed
    }

    /// Exactly the admitted witness keys whose signatures passed, sorted by ID.
    #[must_use]
    pub fn witnesses(&self) -> &[Digest] {
        &self.witnesses
    }

    #[must_use]
    pub fn required_witnesses(&self) -> usize {
        self.policy.quorum
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessError {
    Policy(&'static str),
    InputLimit(&'static str),
    Verification(VerifyError),
    Coordinate,
    PolicyIdentity,
    PublisherMissing,
    Quorum { required: usize, verified: usize },
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(why) => write!(f, "invalid recipient witness policy: {why}"),
            Self::InputLimit(what) => {
                write!(f, "witness verification input exceeds the {what} bound")
            }
            Self::Verification(error) => write!(f, "{error}"),
            Self::Coordinate => write!(f, "checkpoint is for a different expected book or branch"),
            Self::PolicyIdentity => {
                write!(f, "checkpoint does not bind the expected witness policy ID")
            }
            Self::PublisherMissing => {
                write!(f, "checkpoint lacks the required publisher signature")
            }
            Self::Quorum { required, verified } => write!(
                f,
                "checkpoint requires {required} distinct witness signatures; {verified} verified"
            ),
        }
    }
}

impl std::error::Error for WitnessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Verification(error) => Some(error),
            _ => None,
        }
    }
}

impl From<VerifyError> for WitnessError {
    fn from(error: VerifyError) -> Self {
        Self::Verification(error)
    }
}

/// Verify the publisher and witness quorum against recipient-owned expectations.
/// Every supplied signature by ANY configured key must verify, even after the
/// quorum has been reached. Unconfigured signatures are reported as not judged,
/// never counted. This function alone does NOT establish freshness or continuity.
/// Existing `verify_checkpoint` behavior and checkpoint wire bytes are unchanged.
pub fn verify_witnessed_checkpoint(
    bytes: &[u8],
    policy: &RecipientWitnessPolicy,
) -> Result<WitnessedCheckpoint, WitnessError> {
    if bytes.len() > MAX_WITNESSED_CHECKPOINT_BYTES {
        return Err(WitnessError::InputLimit("signed checkpoint"));
    }
    let signed = verify_checkpoint(bytes, &policy.trusted_keys)?;
    if signed.checkpoint.book_id != policy.book_id
        || signed.checkpoint.branch_id != policy.branch_id
    {
        return Err(WitnessError::Coordinate);
    }
    if signed.witness_policy_oid != Some(policy.policy_oid) {
        return Err(WitnessError::PolicyIdentity);
    }
    if !signed.signed_by.contains(&policy.publisher_id) {
        return Err(WitnessError::PublisherMissing);
    }
    // Use a set even though canonical Ed25519 signature rows are already unique:
    // quorum semantics must never become signature-count semantics.
    let witnesses: BTreeSet<_> = signed
        .signed_by
        .iter()
        .copied()
        .filter(|id| policy.witness_ids.contains(id))
        .collect();
    if witnesses.len() < policy.quorum {
        return Err(WitnessError::Quorum {
            required: policy.quorum,
            verified: witnesses.len(),
        });
    }
    Ok(WitnessedCheckpoint {
        signed,
        policy: policy.clone(),
        witnesses: witnesses.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests;
