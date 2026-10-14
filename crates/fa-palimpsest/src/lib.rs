#![forbid(unsafe_code)]
//! Palimpsest — supersession lineage (`Reverse`, `Replace`, `Reclass`,
//! `Restate`), restatement case lifecycle, migration run state/modes, and
//! counterfactual scratch-book commit-sequence translation (plan §8, §15.2).

use std::collections::{BTreeMap, BTreeSet};

use fa_model::{EncodeError, EntryClass, Id128, Oid, Writer, domain_digest};
use fa_money::UnitId;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

/// `H(domain ‖ canonical SeqMap)`.
pub const SEQ_MAP_DOMAIN: &[u8] = b"fa:seq-map:v1";
pub const SEQ_MAP_VERSION: u16 = 1;
/// The scope a scratch book replays: accounting objects only (§15.2).
pub const SCOPE_ACCOUNTING_OBJECTS_ONLY: u8 = 1;

/// One replayed source commit and the scratch commit that reproduces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeqPair {
    pub source_seq: CommitSeq,
    /// The source commit's marker object id (its place in the source chain).
    pub source_marker: [u8; 32],
    pub scratch_seq: CommitSeq,
}

/// Encode canonical `SeqMap` bytes.
pub fn encode_seq_map(
    source_book: Id128,
    source_prefix: CommitSeq,
    pairs: &[SeqPair],
) -> Result<Vec<u8>, EncodeError> {
    let mut w = Writer::new();
    w.u16(SEQ_MAP_VERSION)
        .fixed(&source_book.0)
        .u64(source_prefix.0)
        .u8(SCOPE_ACCOUNTING_OBJECTS_ONLY)
        .list(pairs, |w, p| {
            w.u64(p.source_seq.0)
                .fixed(&p.source_marker)
                .u64(p.scratch_seq.0);
        });
    w.finish()
}

/// Compute the domain-separated `SeqMap` digest.
pub fn seq_map_digest(
    source_book: Id128,
    source_prefix: CommitSeq,
    pairs: &[SeqPair],
) -> Result<[u8; 32], EncodeError> {
    Ok(domain_digest(
        SEQ_MAP_DOMAIN,
        &[&encode_seq_map(source_book, source_prefix, pairs)?],
    ))
}

/// Check that a sequence of `SeqPair`s is strictly increasing on both sides.
#[must_use]
pub fn seq_pairs_are_monotone(pairs: &[SeqPair]) -> bool {
    pairs
        .windows(2)
        .all(|w| w[0].source_seq < w[1].source_seq && w[0].scratch_seq < w[1].scratch_seq)
}

/// Translate `source_known_at` through `pairs` within `[0, source_prefix]`.
#[must_use]
pub fn translate_seq(
    source_prefix: CommitSeq,
    pairs: &[SeqPair],
    source_known_at: CommitSeq,
) -> Option<CommitSeq> {
    if source_known_at > source_prefix {
        return None;
    }
    pairs
        .iter()
        .take_while(|p| p.source_seq <= source_known_at)
        .last()
        .map(|p| p.scratch_seq)
}

/// The migration run's declared mode (plan §8.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode {
    OpeningOnly,
    PeriodBalances,
    FullDetail,
}

impl RunMode {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::OpeningOnly => 0,
            Self::PeriodBalances => 1,
            Self::FullDetail => 2,
        }
    }
}

/// The `state` projection of a migration run vertex (lifecycle-by-transition).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunState {
    Open,
    Finalized,
    Abandoned,
}

impl RunState {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Finalized => 1,
            Self::Abandoned => 2,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Finalized => "Finalized",
            Self::Abandoned => "Abandoned",
        }
    }

    #[must_use]
    pub fn from_scalar(v: Option<&CanonicalScalar>) -> Option<Self> {
        match v {
            Some(CanonicalScalar::Int(0)) => Some(Self::Open),
            Some(CanonicalScalar::Int(1)) => Some(Self::Finalized),
            Some(CanonicalScalar::Int(2)) => Some(Self::Abandoned),
            _ => None,
        }
    }

    #[must_use]
    pub fn scalar(self) -> CanonicalScalar {
        CanonicalScalar::Int(i64::from(self.tag()))
    }
}

/// One declared line of the legacy trial balance: the account's net in
/// debit sign (`debits − credits`), never zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrialBalanceLine {
    pub account_code: String,
    pub unit: UnitId,
    pub mantissa: i128,
}

/// One elapsed period of a `PeriodBalances` run (plan §8.6): the legacy
/// trial balance as of the period's end — cumulative from the run's opening
/// date — and the document that states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodBalance {
    pub period_code: String,
    pub trial_balance: Oid,
    /// Strictly ascending by `(account_code, unit)`, never zero.
    pub lines: Vec<TrialBalanceLine>,
}

/// One node in the journal's `SUPERSEDES` lineage graph (plan §8.1–§8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupersessionNode {
    pub vid: VId,
    pub class: EntryClass,
    pub supersedes: Option<VId>,
}

/// Validate that `target` has an unreversed ancestry chain in `nodes` before
/// admitting a new `Reversal` (plan §8.1, bead `fa-wck`):
/// returns `Err(ancestor_vid)` if `target` or any `SUPERSEDES` ancestor has
/// already been reversed by a committed `Reversal` entry.
pub fn validate_unreversed_ancestry(
    nodes: &BTreeMap<VId, SupersessionNode>,
    reversed_targets: &BTreeSet<VId>,
    target: VId,
) -> Result<(), VId> {
    let mut cursor = Some(target);
    let mut visited = BTreeSet::new();
    while let Some(v) = cursor {
        if !visited.insert(v) {
            break;
        }
        if reversed_targets.contains(&v) {
            return Err(v);
        }
        cursor = nodes.get(&v).and_then(|n| n.supersedes);
    }
    Ok(())
}

/// Lifecycle state of a restatement case (`RestatementCase`, plan §8.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestatementCaseState {
    Open,
    Approved,
    Applied,
    Closed,
}

impl RestatementCaseState {
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Open, Self::Approved)
                | (Self::Approved, Self::Applied)
                | (Self::Applied, Self::Closed)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn palimpsest_seq_map_monotonicity_and_translation() {
        let pairs = vec![
            SeqPair {
                source_seq: CommitSeq(2),
                source_marker: [0x11; 32],
                scratch_seq: CommitSeq(1),
            },
            SeqPair {
                source_seq: CommitSeq(5),
                source_marker: [0x22; 32],
                scratch_seq: CommitSeq(2),
            },
        ];
        assert!(seq_pairs_are_monotone(&pairs));
        assert_eq!(translate_seq(CommitSeq(6), &pairs, CommitSeq(1)), None);
        assert_eq!(
            translate_seq(CommitSeq(6), &pairs, CommitSeq(2)),
            Some(CommitSeq(1))
        );
        assert_eq!(
            translate_seq(CommitSeq(6), &pairs, CommitSeq(4)),
            Some(CommitSeq(1))
        );
        assert_eq!(
            translate_seq(CommitSeq(6), &pairs, CommitSeq(5)),
            Some(CommitSeq(2))
        );
        assert_eq!(translate_seq(CommitSeq(6), &pairs, CommitSeq(7)), None);
    }

    #[test]
    fn palimpsest_reversal_ancestry_detects_reversed_ancestor() {
        let e1 = VId(1);
        let e2 = VId(2);
        let mut nodes = BTreeMap::new();
        nodes.insert(
            e1,
            SupersessionNode {
                vid: e1,
                class: EntryClass::ORIGINAL,
                supersedes: None,
            },
        );
        nodes.insert(
            e2,
            SupersessionNode {
                vid: e2,
                class: EntryClass::RECLASSIFICATION,
                supersedes: Some(e1),
            },
        );
        let mut reversed = BTreeSet::new();
        assert_eq!(validate_unreversed_ancestry(&nodes, &reversed, e2), Ok(()));
        reversed.insert(e1);
        assert_eq!(validate_unreversed_ancestry(&nodes, &reversed, e2), Err(e1));
    }

    #[test]
    fn palimpsest_restatement_case_state_transitions_are_monotone() {
        assert!(RestatementCaseState::Open.can_transition_to(RestatementCaseState::Approved));
        assert!(RestatementCaseState::Approved.can_transition_to(RestatementCaseState::Applied));
        assert!(RestatementCaseState::Applied.can_transition_to(RestatementCaseState::Closed));
        assert!(!RestatementCaseState::Closed.can_transition_to(RestatementCaseState::Open));
    }
}
