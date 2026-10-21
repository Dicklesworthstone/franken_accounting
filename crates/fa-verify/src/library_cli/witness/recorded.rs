//! Shared recorded-time continuity for checkpoint-only and bundle commands.
//! The retained body pin is checked by the caller before this opens a witness.

use std::path::Path;

use fa_verify::checkpoint::witness::WitnessedCheckpoint;
use fa_verify::checkpoint::witness::recorded::{
    MAX_RECORDED_ADVANCE_BYTES, RecordedCheckpointAdvance, verify_recorded_checkpoint_advance,
};

use crate::{Failure, object, quote, read_bounded};

pub(super) struct Facts {
    appended_records: u64,
    /// Include both checkpoint files, the proof and witness in composed budgets.
    pub(super) input_bytes: usize,
}

fn remaining(previous: usize, candidate: usize, proof: usize) -> Result<usize, Failure> {
    previous
        .checked_add(candidate)
        .and_then(|n| n.checked_add(proof))
        .and_then(|used| MAX_RECORDED_ADVANCE_BYTES.checked_sub(used))
        .ok_or_else(|| {
            Failure::verification("recorded-continuity inputs exceed the shared 64 MiB budget")
        })
}

pub(super) fn authenticate(
    previous: &WitnessedCheckpoint,
    candidate: &[u8],
    proof: &[u8],
    path: &Path,
    previous_bytes: usize,
) -> Result<(RecordedCheckpointAdvance, Facts), Failure> {
    let available = remaining(previous_bytes, candidate.len(), proof.len())?;
    let prefix = read_bounded(path, available)?;
    let verified = verify_recorded_checkpoint_advance(previous, candidate, proof, &prefix)
        .map_err(|error| Failure::verification(error.to_string()))?;
    let facts = Facts {
        appended_records: verified.appended_records(),
        input_bytes: MAX_RECORDED_ADVANCE_BYTES - available + prefix.len(),
    };
    // Only sealed checkpoint metadata and counts escape; drop all prefix bytes.
    Ok((verified, facts))
}

pub(super) fn human(facts: Option<&Facts>) -> String {
    match facts {
        None => "Recorded-time boundary was not checked.".into(),
        Some(facts) => format!(
            "Recorded-time boundary verified against every candidate payload; {} appended records. Effective dates may be earlier.",
            facts.appended_records,
        ),
    }
}

pub(super) fn json(facts: Option<&Facts>) -> String {
    object([
        (
            "status",
            quote(if facts.is_some() {
                "verified"
            } else {
                "not_checked"
            }),
        ),
        (
            "scope",
            facts.map_or_else(|| "null".into(), |_| quote("recomputation")),
        ),
        (
            "appended_records",
            facts.map_or_else(
                || "null".into(),
                |facts| quote(&facts.appended_records.to_string()),
            ),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_checkpoint_and_consistency_bytes_consume_the_same_input_budget() {
        assert_eq!(
            remaining(10, 20, 30).ok(),
            Some(MAX_RECORDED_ADVANCE_BYTES - 60)
        );
        assert_eq!(
            remaining(MAX_RECORDED_ADVANCE_BYTES - 30, 20, 10).ok(),
            Some(0)
        );
        for sizes in [
            (MAX_RECORDED_ADVANCE_BYTES, 1, 0),
            (usize::MAX, 1, 0),
            (1, usize::MAX, 1),
        ] {
            let error = remaining(sizes.0, sizes.1, sizes.2).expect_err("budget refusal");
            assert_eq!(error.exit, 8);
        }
    }

    #[test]
    fn reports_distinguish_no_check_from_verified_zero_and_keep_u64_exact() {
        assert!(json(None).contains("\"status\":\"not_checked\""));
        assert!(json(None).contains("\"scope\":null"));
        for count in [0, u64::MAX] {
            let facts = Facts {
                appended_records: count,
                input_bytes: 100,
            };
            let report = json(Some(&facts));
            assert!(report.contains("\"status\":\"verified\""));
            assert!(report.contains(&format!("\"appended_records\":\"{count}\"")));
            assert!(human(Some(&facts)).contains("Effective dates may be earlier"));
        }
    }
}
