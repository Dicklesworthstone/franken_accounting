//! Scope-index derivation with EVERY prefix payload, not only signed selectors.
//!
//! Native v2 prefixes and v3 balance exports already carry the required
//! records. Reuse that verifier before deriving the existing scope-index
//! transcript. A legacy envelope-only prefix cannot establish this stronger
//! premise, including for an empty account interval. This is an opt-in API;
//! existing signed-index and envelope-index APIs retain their behavior.

pub mod bundle;

use core::fmt;

use super::{IndexDerivation, ScopeClaim, ScopeReport, scope_node, scope_root, tuple_leaf};
use crate::checkpoint::SignedCheckpoint;
use crate::proof::production::derivation::verify_prefix_with_records;
use crate::proof::{Checkpoint, VerifyError};
use crate::tree::{Digest, root_of_with};

/// Bound account expansion separately from the prefix's byte and leaf limits.
/// At most 1,048,576 account/day/leaf tuples are retained during reconstruction.
pub const MAX_PAYLOAD_INDEX_TUPLES: usize = 1 << 20;

/// A reusable, immutable derivation result. Public report structs are not
/// accepted in its place: only successful record and root verification builds
/// this value. It retains no record bytes, selectors, or disclosed documents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadIndex {
    checkpoint: Checkpoint,
    root: Digest,
    tuples: usize,
    encoded_bytes: usize,
}

impl PayloadIndex {
    #[must_use]
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    #[must_use]
    pub fn root(&self) -> &Digest {
        &self.root
    }

    #[must_use]
    pub fn tuple_count(&self) -> usize {
        self.tuples
    }

    /// The verified witness size, retained for composed aggregate input limits.
    #[must_use]
    pub fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }

    /// Bind reuse to the exact journal coordinate AND scope-index root. Other
    /// signed metadata/signature sets do not change this derivation; callers
    /// still verify their own checkpoint signatures and artifact requirements.
    #[must_use]
    pub fn matches(&self, signed: &SignedCheckpoint) -> bool {
        self.checkpoint == signed.checkpoint && self.root == signed.scope_index_root
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadIndexError {
    Proof(VerifyError),
    Limit(&'static str),
    Root,
    Anchor,
}

impl fmt::Display for PayloadIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proof(error) => write!(f, "scope-index payload witness: {error}"),
            Self::Limit(what) => write!(f, "scope-index reconstruction exceeds the {what} bound"),
            Self::Root => write!(
                f,
                "the signed scope index differs from the complete payload-derived index"
            ),
            Self::Anchor => write!(
                f,
                "the payload-derived index belongs to another checkpoint or index root"
            ),
        }
    }
}

impl core::error::Error for PayloadIndexError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Proof(error) => Some(error),
            _ => None,
        }
    }
}

impl From<VerifyError> for PayloadIndexError {
    fn from(error: VerifyError) -> Self {
        Self::Proof(error)
    }
}

/// Derive all tuples from independently checked payload selectors and require
/// the existing signed root to match. The caller obtains/trusts `signed`
/// independently (or takes it from a sealed witnessed checkpoint).
///
/// Every payload is verified, even for accounts/days outside a later query.
/// V3 balance inputs additionally undergo their existing fold and migration
/// checks; a readable header is never accepted as a prefix certificate.
/// Empty and undated records retain their actual journal positions. No claim
/// of authorization, private disclosure, accounting truth or freshness is made.
pub fn verify_payload_index(
    complete_prefix: &[u8],
    signed: &SignedCheckpoint,
) -> Result<PayloadIndex, PayloadIndexError> {
    let prefix = verify_prefix_with_records(complete_prefix, &signed.checkpoint)?;
    let count = prefix
        .envelopes
        .iter()
        .try_fold(0usize, |count, envelope| {
            count
                .checked_add(if envelope.effective_day.is_some() {
                    envelope.account_vids.len()
                } else {
                    0
                })
                .filter(|count| *count <= MAX_PAYLOAD_INDEX_TUPLES)
                .ok_or(PayloadIndexError::Limit("expanded tuple count"))
        })?;
    let mut tuples = Vec::new();
    tuples
        .try_reserve_exact(count)
        .map_err(|_| PayloadIndexError::Limit("tuple allocation"))?;
    for (index, envelope) in prefix.envelopes.iter().enumerate() {
        if let Some(day) = envelope.effective_day {
            tuples.extend(
                envelope
                    .account_vids
                    .iter()
                    .map(|account| (*account, day, index as u64)),
            );
        }
    }
    tuples.sort_unstable();
    let mut leaves = Vec::new();
    leaves
        .try_reserve_exact(count)
        .map_err(|_| PayloadIndexError::Limit("hash allocation"))?;
    leaves.extend(
        tuples
            .iter()
            .map(|(account, day, index)| tuple_leaf(&signed.checkpoint, *account, *day, *index)),
    );
    // Reuse the parent module's exact transcript and tree law; this does not
    // introduce a new index domain, encoding, or alternate producer algorithm.
    let root = scope_root(count as u64, &root_of_with(scope_node, &leaves));
    if root != signed.scope_index_root {
        return Err(PayloadIndexError::Root);
    }
    Ok(PayloadIndex {
        checkpoint: prefix.checkpoint,
        root,
        tuples: count,
        encoded_bytes: complete_prefix.len(),
    })
}

/// Reuse a checked derivation across range proofs at the SAME checkpoint.
/// Range membership, exact recipient scope, empty-interval boundaries and
/// neighbours are still verified by the existing scope verifier each time.
pub fn verify_scope_with_payload_index(
    proof: &[u8],
    signed: &SignedCheckpoint,
    claim: &ScopeClaim,
    index: &PayloadIndex,
) -> Result<ScopeReport, PayloadIndexError> {
    if !index.matches(signed) {
        return Err(PayloadIndexError::Anchor);
    }
    let mut report = super::verify_scope(proof, signed, claim, None)?;
    report.index_derivation = IndexDerivation::Recomputed;
    Ok(report)
}
