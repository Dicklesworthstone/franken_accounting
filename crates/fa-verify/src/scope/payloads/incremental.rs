//! Advance a payload-derived scope index from a complete authenticated suffix.
//!
//! Plan §13.2 permits extending previously verified state instead of sending
//! the entire history again. A signed/consistent root alone is insufficient:
//! EVERY appended leaf needs its record, and every appended recorded sequence
//! must be later than the retained frontier. Backdated effective days are fine.
//! No new durable proof format, trust policy, clock, filesystem or network.

use core::fmt;

use super::{
    IndexTuple, MAX_PAYLOAD_INDEX_TUPLES, PayloadIndex, PayloadIndexError, derive_with_tuples,
    root_from_tuples,
};
use crate::checkpoint::SignedCheckpoint;
use crate::checkpoint::witness::{AdvanceError, WitnessedCheckpoint, verify_checkpoint_advance};
use crate::proof::production::{
    MAX_PRODUCTION_BYTES, MAX_PRODUCTION_LEAVES, MAX_PRODUCTION_RECORDS,
};
use crate::proof::{RecordCheck, VerifyError, verify_inclusion};

/// An in-memory recipient state, created only from a verified full baseline.
/// Private fields prevent importing an unverified index or replacing its trust
/// policy. Unlike PayloadIndex this retains sorted account/day/leaf tuples,
/// but never entry payloads. It has deliberately no serialization or mutation
/// API: durable rollback protection remains the embedding's responsibility.
#[derive(PartialEq, Eq)]
pub struct IncrementalPayloadIndex {
    checkpoint: WitnessedCheckpoint,
    index: PayloadIndex,
    tuples: Vec<IndexTuple>,
}

// Do not accidentally disclose account/day tuples through logging or asserts.
impl fmt::Debug for IncrementalPayloadIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncrementalPayloadIndex")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexAdvanceError {
    Continuity(AdvanceError),
    Derivation(PayloadIndexError),
    Limit(&'static str),
    RecordCount { expected: u64, actual: usize },
    Record { leaf_index: u64, error: VerifyError },
    Position { expected: u64, actual: u64 },
    PayloadRequired { leaf_index: u64 },
    RecordedOrder { leaf_index: u64 },
}

impl fmt::Display for IndexAdvanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continuity(error) => write!(f, "{error}"),
            Self::Derivation(error) => write!(f, "{error}"),
            Self::Limit(what) => write!(f, "incremental index exceeds the {what} bound"),
            Self::RecordCount { expected, actual } => write!(
                f,
                "the checkpoint appends {expected} leaves; supplied {actual} records"
            ),
            Self::Record { leaf_index, error } => write!(f, "appended leaf {leaf_index}: {error}"),
            Self::Position { expected, actual } => {
                write!(f, "the next appended leaf must be {expected}, not {actual}")
            }
            Self::PayloadRequired { leaf_index } => write!(
                f,
                "appended leaf {leaf_index} requires its payload, not just membership"
            ),
            Self::RecordedOrder { leaf_index } => write!(
                f,
                "appended leaf {leaf_index} is not in journal order after the retained frontier"
            ),
        }
    }
}

impl core::error::Error for IndexAdvanceError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Continuity(error) => Some(error),
            Self::Derivation(error) => Some(error),
            Self::Record { error, .. } => Some(error),
            _ => None,
        }
    }
}

impl From<PayloadIndexError> for IndexAdvanceError {
    fn from(error: PayloadIndexError) -> Self {
        Self::Derivation(error)
    }
}

impl IncrementalPayloadIndex {
    /// Bootstrap from an existing native v2 prefix or v3 balance export and
    /// an independently verified publisher/witness checkpoint. Every baseline
    /// payload and the signed index root are checked by the existing verifier.
    pub fn verify(
        complete_prefix: &[u8],
        checkpoint: &WitnessedCheckpoint,
    ) -> Result<Self, PayloadIndexError> {
        let (index, tuples) = derive_with_tuples(complete_prefix, checkpoint.signed_checkpoint())?;
        Ok(Self {
            checkpoint: checkpoint.clone(),
            index,
            tuples,
        })
    }

    #[must_use]
    pub fn checkpoint(&self) -> &WitnessedCheckpoint {
        &self.checkpoint
    }

    /// Reuse this sealed result with the existing scope/bundle APIs. Its
    /// encoded_bytes conservatively counts the initial prefix plus EVERY
    /// accepted delta's checkpoint, consistency and inclusion bytes. Thus an
    /// incremental chain cannot bypass a composed verifier's total byte limit.
    #[must_use]
    pub fn index(&self) -> &PayloadIndex {
        &self.index
    }

    /// Return a new state only after quorum, append-only continuity, exact
    /// suffix coverage, every payload selector and the new index root pass.
    /// The old state remains usable on both success and failure. The candidate
    /// cannot supply a different publisher, witness policy or weaker quorum.
    ///
    /// `records` are the existing record-bearing v1 inclusion proofs at the
    /// NEW checkpoint, in leaf order, for precisely [old_count, new_count).
    /// Undated controls and non-entry evidence leaves must be present too;
    /// a zero-tuple record still occupies a journal position. An empty suffix
    /// is accepted only when the tree size is unchanged and its index matches.
    ///
    /// Limits remain explicit: 4096 records per advance, 65536 retained leaves,
    /// 1048576 expanded tuples and 64 MiB cumulative witness bytes. Prior record
    /// payloads need not be resent or rehashed. Tuple merging and root hashing
    /// still visit the complete metadata index; no logarithmic-time claim is
    /// made. Disclosure authority, economic truth and latest-head freshness are
    /// NOT established; no persistent checkpoint or file is updated here.
    pub fn advance(
        &self,
        candidate: &[u8],
        consistency: &[u8],
        records: &[&[u8]],
    ) -> Result<Self, IndexAdvanceError> {
        let encoded_bytes = witness_budget(
            self.index.encoded_bytes,
            candidate.len(),
            consistency.len(),
            records,
        )?;
        let advance = verify_checkpoint_advance(&self.checkpoint, candidate, consistency)
            .map_err(IndexAdvanceError::Continuity)?;
        let checkpoint = advance.into_checkpoint();
        let (index, tuples) = extend(
            &self.index,
            &self.tuples,
            checkpoint.signed_checkpoint(),
            records,
            encoded_bytes,
        )?;
        Ok(Self {
            checkpoint,
            index,
            tuples,
        })
    }
}

fn witness_budget(
    previous: usize,
    candidate: usize,
    consistency: usize,
    records: &[&[u8]],
) -> Result<usize, IndexAdvanceError> {
    if records.len() > MAX_PRODUCTION_RECORDS {
        return Err(IndexAdvanceError::Limit("delta record count"));
    }
    [candidate, consistency]
        .into_iter()
        .chain(records.iter().map(|bytes| bytes.len()))
        .try_fold(previous, |total, size| {
            total
                .checked_add(size)
                .filter(|sum| *sum <= MAX_PRODUCTION_BYTES)
                .ok_or(IndexAdvanceError::Limit("cumulative witness bytes"))
        })
}

// Only the public advance method can publish this result. It has first proved
// continuity under the retained policy. Keep record/index work separate so
// unsigned synthetic vectors can exercise it without claiming signature tests.
fn extend(
    old: &PayloadIndex,
    retained: &[IndexTuple],
    next: &SignedCheckpoint,
    records: &[&[u8]],
    encoded_bytes: usize,
) -> Result<(PayloadIndex, Vec<IndexTuple>), IndexAdvanceError> {
    let cp = &next.checkpoint;
    if cp.leaf_count > MAX_PRODUCTION_LEAVES as u64 {
        return Err(IndexAdvanceError::Limit("retained leaf count"));
    }
    let count = cp
        .leaf_count
        .checked_sub(old.checkpoint.leaf_count)
        .ok_or(PayloadIndexError::Anchor)?;
    if count != records.len() as u64 {
        return Err(IndexAdvanceError::RecordCount {
            expected: count,
            actual: records.len(),
        });
    }
    let mut appended = Vec::new();
    let mut previous_position = None;
    for (position, proof) in records.iter().enumerate() {
        // The bounded new checkpoint and exact count above make this exact.
        let leaf_index = old.checkpoint.leaf_count + position as u64;
        let record = verify_inclusion(proof, cp)
            .map_err(|error| IndexAdvanceError::Record { leaf_index, error })?;
        if record.leaf_index != leaf_index {
            return Err(IndexAdvanceError::Position {
                expected: leaf_index,
                actual: record.leaf_index,
            });
        }
        if record.record != RecordCheck::Recomputed {
            return Err(IndexAdvanceError::PayloadRequired { leaf_index });
        }
        let envelope = record.envelope;
        if envelope.commit_seq <= old.checkpoint.through_seq
            || previous_position.is_some_and(|prior| prior >= envelope.position())
        {
            return Err(IndexAdvanceError::RecordedOrder { leaf_index });
        }
        previous_position = Some(envelope.position());
        if let Some(day) = envelope.effective_day {
            let length = retained
                .len()
                .checked_add(appended.len())
                .and_then(|n| n.checked_add(envelope.account_vids.len()));
            if length.is_none_or(|n| n > MAX_PAYLOAD_INDEX_TUPLES) {
                return Err(IndexAdvanceError::Limit("expanded tuple count"));
            }
            appended
                .try_reserve(envelope.account_vids.len())
                .map_err(|_| IndexAdvanceError::Limit("delta tuple allocation"))?;
            appended.extend(
                envelope
                    .account_vids
                    .iter()
                    .map(|account| (*account, day, leaf_index)),
            );
        }
    }
    appended.sort_unstable();
    let mut tuples = Vec::new();
    tuples
        .try_reserve_exact(retained.len() + appended.len())
        .map_err(|_| IndexAdvanceError::Limit("merged tuple allocation"))?;
    // Late-effective tuples may precede old tuples; append-only journal order
    // is NOT append-only account/day order. Merge without re-sorting history.
    let (mut old_at, mut new_at) = (0, 0);
    while old_at < retained.len() && new_at < appended.len() {
        if retained[old_at] < appended[new_at] {
            tuples.push(retained[old_at]);
            old_at += 1;
        } else {
            tuples.push(appended[new_at]);
            new_at += 1;
        }
    }
    tuples.extend_from_slice(&retained[old_at..]);
    tuples.extend_from_slice(&appended[new_at..]);
    let root = root_from_tuples(&tuples, cp)?;
    if root != next.scope_index_root {
        return Err(PayloadIndexError::Root.into());
    }
    Ok((
        PayloadIndex {
            checkpoint: *cp,
            root,
            tuples: tuples.len(),
            encoded_bytes,
        },
        tuples,
    ))
}

#[cfg(test)]
mod tests;
