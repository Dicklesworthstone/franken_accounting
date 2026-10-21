//! Recorded-sequence continuity, in addition to append-only tree consistency.
//!
//! A tree may extend a retained root while a new leaf claims a sequence at or
//! before that retained checkpoint's known-at boundary. Hash consistency alone
//! cannot detect this: it does not disclose the appended envelopes. This opt-in
//! verifier checks a complete, payload-derived candidate prefix as well.
//!
//! Full-prefix disclosure requires independent authorization. The result does
//! not establish freshness, economic truth, scope-index derivation, custody,
//! key rotation, or completeness against an undisclosed second journal.

use std::fmt;

use super::{
    AdvanceError, AdvanceStatus, CheckpointAdvance, WitnessedCheckpoint,
    verify_checkpoint_advance,
};
use crate::envelope::LeafEnvelope;
use crate::proof::production::derivation::verify_prefix_with_records;
use crate::proof::{Checkpoint, VerifyError};

/// Candidate checkpoint, consistency proof and complete prefix share one
/// budget. Each underlying verifier retains its narrower count/format limits.
pub const MAX_RECORDED_ADVANCE_BYTES: usize = 64 * 1024 * 1024;

/// A candidate quorum, append-only extension and recorded-sequence boundary
/// that all verified. Private fields prevent constructing this from reports.
/// No entry payloads or envelope selectors are retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedCheckpointAdvance {
    advance: CheckpointAdvance,
    previous: Checkpoint,
    appended_records: u64,
}

impl RecordedCheckpointAdvance {
    #[must_use]
    pub fn checkpoint(&self) -> &WitnessedCheckpoint {
        self.advance.checkpoint()
    }

    #[must_use]
    pub fn status(&self) -> AdvanceStatus {
        self.advance.status()
    }

    /// Exactly the independently retained statement checked by this operation.
    #[must_use]
    pub fn previous(&self) -> &Checkpoint {
        &self.previous
    }

    /// Includes every record kind, not only entries or balance contributors.
    #[must_use]
    pub fn appended_records(&self) -> u64 {
        self.appended_records
    }

    /// Transfer the verified pin to the caller. This does NOT persist it,
    /// protect its storage from rollback, or retain this result's extra grade.
    #[must_use]
    pub fn into_checkpoint(self) -> WitnessedCheckpoint {
        self.advance.into_checkpoint()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordedAdvanceError {
    Advance(AdvanceError),
    Prefix(VerifyError),
    InputLimit,
    /// The candidate's complete prefix places a different number of records
    /// at/before the retained known-at than the old checkpoint committed.
    RecordedBoundary {
        retained_leaf_count: u64,
        reconstructed_leaf_count: u64,
    },
}

impl fmt::Display for RecordedAdvanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Advance(error) => write!(f, "{error}"),
            Self::Prefix(error) => write!(f, "recorded-continuity prefix: {error}"),
            Self::InputLimit => write!(
                f,
                "recorded checkpoint advancement exceeds the shared 64 MiB input bound"
            ),
            Self::RecordedBoundary {
                retained_leaf_count,
                reconstructed_leaf_count,
            } => write!(
                f,
                "retained checkpoint commits {retained_leaf_count} records through its sequence; \
                 the complete candidate prefix places {reconstructed_leaf_count} there"
            ),
        }
    }
}

impl std::error::Error for RecordedAdvanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Advance(error) => Some(error),
            Self::Prefix(error) => Some(error),
            Self::InputLimit | Self::RecordedBoundary { .. } => None,
        }
    }
}

/// Verify quorum/policy continuity AND preserve the retained recorded boundary.
///
/// Reuses `verify_checkpoint_advance` unchanged: publisher and witness quorum,
/// book/branch/policy, same-sequence body identity, exact consistency endpoints
/// and append-only extension must all pass. It then requires EVERY candidate
/// prefix payload to authenticate its envelope, including excluded/control/
/// evidence records, before checking the retained sequence boundary.
///
/// `complete_prefix` accepts existing native v2 prefixes or native v3 balance
/// exports. V3 also undergoes its own arithmetic and migration verification.
/// V1 envelope-only prefixes refuse; there is no fallback to a weaker result.
///
/// In the authenticated, ordered candidate prefix, exactly old.leaf_count
/// records must have commit_seq <= old.through_seq. Together with the verified
/// root extension this proves that newly appended records are strictly later
/// in recorded time, including when the old tree was empty. Effective dates
/// may legitimately be earlier; no effective-date restriction is introduced.
/// It also detects a retained statement whose existing leaves were recorded
/// after that statement's own sequence.
///
/// Even an unchanged candidate requires the complete witness. No previous pin
/// is mutated and no partial result escapes a later prefix/boundary failure.
pub fn verify_recorded_checkpoint_advance(
    previous: &WitnessedCheckpoint,
    candidate_bytes: &[u8],
    consistency_proof: &[u8],
    complete_prefix: &[u8],
) -> Result<RecordedCheckpointAdvance, RecordedAdvanceError> {
    check_input_size(
        candidate_bytes.len(),
        consistency_proof.len(),
        complete_prefix.len(),
    )?;
    let advance = verify_checkpoint_advance(previous, candidate_bytes, consistency_proof)
        .map_err(RecordedAdvanceError::Advance)?;
    let candidate = &advance.checkpoint().signed_checkpoint().checkpoint;
    let prefix = verify_prefix_with_records(complete_prefix, candidate)
        .map_err(RecordedAdvanceError::Prefix)?;
    let old = &previous.signed_checkpoint().checkpoint;
    check_recorded_boundary(&prefix.envelopes, old)?;
    // Monotonic sizes were checked by the shared advance verifier. This
    // subtraction cannot underflow, and no allocation depends on the result.
    let appended_records = candidate.leaf_count - old.leaf_count;
    Ok(RecordedCheckpointAdvance {
        advance,
        previous: *old,
        appended_records,
    })
}

fn check_input_size(
    candidate: usize,
    consistency: usize,
    prefix: usize,
) -> Result<(), RecordedAdvanceError> {
    let total = candidate
        .checked_add(consistency)
        .and_then(|value| value.checked_add(prefix));
    if total.is_none_or(|value| value > MAX_RECORDED_ADVANCE_BYTES) {
        Err(RecordedAdvanceError::InputLimit)
    } else {
        Ok(())
    }
}

/// Only called with the complete ordered prefix returned by the existing
/// verifier. All record kinds count, independently of account/day selectors.
fn check_recorded_boundary(
    envelopes: &[LeafEnvelope],
    old: &Checkpoint,
) -> Result<(), RecordedAdvanceError> {
    let boundary = envelopes.partition_point(|entry| entry.commit_seq <= old.through_seq);
    // The upstream complete-prefix decoder admits at most 65,536 records.
    let reconstructed = u64::try_from(boundary).unwrap_or(u64::MAX);
    if reconstructed != old.leaf_count {
        return Err(RecordedAdvanceError::RecordedBoundary {
            retained_leaf_count: old.leaf_count,
            reconstructed_leaf_count: reconstructed,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(sequence: u64, ordinal: u32, effective_day: Option<i32>) -> LeafEnvelope {
        LeafEnvelope {
            kind: crate::envelope::KIND_ENTRY,
            book_id: [1; 16],
            branch_id: [0; 16],
            commit_seq: sequence,
            within_commit_ordinal: ordinal,
            record_digest: [3; 32],
            class: 1,
            effective_day,
            account_vids: vec![10],
            unit_ids: vec![1],
        }
    }

    fn old(sequence: u64, count: u64) -> Checkpoint {
        Checkpoint {
            book_id: [1; 16],
            branch_id: [0; 16],
            through_seq: sequence,
            leaf_count: count,
            root: [4; 32],
        }
    }

    #[test]
    fn later_recorded_entries_may_have_earlier_effective_dates() {
        let prefix = [
            envelope(7, 0, Some(100)),
            envelope(11, 0, Some(i32::MIN)),
            envelope(11, 1, None),
        ];
        assert_eq!(check_recorded_boundary(&prefix, &old(10, 1)), Ok(()));
    }

    #[test]
    fn records_cannot_be_added_inside_a_retained_sequence_including_its_last_commit() {
        for sequence in [7, 9, 10] {
            let prefix = [
                envelope(7, 0, Some(100)),
                envelope(sequence, 1, Some(200)),
            ];
            assert_eq!(
                check_recorded_boundary(&prefix, &old(10, 1)),
                Err(RecordedAdvanceError::RecordedBoundary {
                    retained_leaf_count: 1,
                    reconstructed_leaf_count: 2,
                })
            );
        }
    }

    #[test]
    fn empty_pins_and_empty_advancements_still_have_recorded_boundaries() {
        assert_eq!(check_recorded_boundary(&[], &old(10, 0)), Ok(()));
        assert_eq!(
            check_recorded_boundary(&[envelope(11, 0, None)], &old(10, 0)),
            Ok(())
        );
        assert_eq!(
            check_recorded_boundary(&[envelope(10, 0, None)], &old(10, 0)),
            Err(RecordedAdvanceError::RecordedBoundary {
                retained_leaf_count: 0,
                reconstructed_leaf_count: 1,
            })
        );
    }

    #[test]
    fn retained_future_record_and_u64_extrema_are_not_normalized() {
        assert_eq!(
            check_recorded_boundary(&[envelope(11, 0, None)], &old(10, 1)),
            Err(RecordedAdvanceError::RecordedBoundary {
                retained_leaf_count: 1,
                reconstructed_leaf_count: 0,
            })
        );
        let prefix = [envelope(0, 0, None), envelope(u64::MAX, 0, None)];
        assert_eq!(check_recorded_boundary(&prefix, &old(0, 1)), Ok(()));
        assert_eq!(check_recorded_boundary(&prefix, &old(u64::MAX, 2)), Ok(()));
        assert!(check_recorded_boundary(&prefix, &old(u64::MAX, 1)).is_err());
    }

    #[test]
    fn aggregate_input_arithmetic_is_bounded_before_verification_or_allocation() {
        assert_eq!(check_input_size(100, 200, MAX_RECORDED_ADVANCE_BYTES - 300), Ok(()));
        assert_eq!(
            check_input_size(100, 200, MAX_RECORDED_ADVANCE_BYTES - 299),
            Err(RecordedAdvanceError::InputLimit)
        );
        for sizes in [(usize::MAX, 1, 0), (0, usize::MAX, 1), (1, 0, usize::MAX)] {
            assert_eq!(
                check_input_size(sizes.0, sizes.1, sizes.2),
                Err(RecordedAdvanceError::InputLimit)
            );
        }
    }
}
