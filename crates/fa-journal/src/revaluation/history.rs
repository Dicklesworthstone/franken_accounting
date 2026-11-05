//! A call-local, authenticated immutable entry index for historical audit.
//!
//! This is not a cache of observations. Every historical call still verifies
//! its own period, chart, migration, route and rate evidence and hashes its own
//! selected source stream. Only immutable entry payloads and their structural
//! indexes are shared; carrying liveness and guards belong to each cutoff.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;

use super::*;
use crate::carrying::CarryingIndex;

#[cfg(test)]
mod tests;

/// Work performed by the historical audit after the initial selected-prefix
/// observation. The initial observation is excluded from these counters.
/// Each historical observation still runs its original metadata verifiers;
/// source-contribution hashing remains proportional to its selected stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RevaluationHistoryWork {
    pub historical_observations: usize,
    pub entry_history_proofs_reused: usize,
    pub shared_history_scans: usize,
    pub shared_entries_decoded: usize,
    pub shared_applications_indexed: usize,
    pub source_legs_indexed: usize,
    pub source_entry_candidates: usize,
    pub source_contributions_hashed: usize,
    pub historical_route_reads: usize,
    pub historical_route_reuses: usize,
    /// Remaining cutoff-specific item work, including visible-prefix source
    /// guards, liveness, release validation and actual effect visits. Shared
    /// decode/index construction is counted separately above.
    pub historical_carrying: crate::carrying::CarryingPopulationWork,
}

/// Constructible only by the actual complete-prefix immutability verifier.
/// A successful larger prefix proves all earlier Entry payloads unchanged,
/// including mutations that were later restored. It says nothing about the
/// historical chart, period, migration or document projections.
pub(super) struct VerifiedEntryPrefix {
    book_id: Id128,
    at: CommitSeq,
}

pub(super) fn verify_prefix<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    at: CommitSeq,
) -> Result<VerifiedEntryPrefix, KernelError> {
    crate::entry_history::verify_entry_history(db, cx, book, Some(at))?;
    Ok(VerifiedEntryPrefix {
        book_id: book.book_id,
        at,
    })
}

pub(super) struct AuthenticatedHistory {
    proof: VerifiedEntryPrefix,
    index: Rc<CarryingIndex>,
    by_account: BTreeMap<VId, Vec<usize>>,
    reversal_related: Vec<(CommitSeq, usize)>,
    work: Cell<RevaluationHistoryWork>,
}

impl AuthenticatedHistory {
    /// The caller supplies the proof returned by its successful initial
    /// observation, preserving that observation's refusal precedence.
    pub(super) fn read_verified<V: Vfs + Clone>(
        db: &Database<V>,
        cx: &PurposeContexts,
        book: &BookContext,
        proof: VerifiedEntryPrefix,
    ) -> Result<Self, KernelError> {
        if proof.book_id != book.book_id {
            return Err(KernelError::Corrupt(
                "revaluation entry proof belongs to another book".into(),
            ));
        }
        let index = Rc::new(CarryingIndex::read_at(db, cx, book, proof.at)?);
        let index_work = index.build_work();
        let mut work = RevaluationHistoryWork {
            shared_history_scans: index_work.history_scans,
            shared_entries_decoded: index_work.entries_decoded,
            shared_applications_indexed: index_work.applications_indexed,
            ..RevaluationHistoryWork::default()
        };
        let mut by_account: BTreeMap<VId, Vec<usize>> = BTreeMap::new();
        let mut reversal_related = Vec::new();
        for (position, (seq, _, entry)) in index.entries().iter().enumerate() {
            cx.query()
                .checkpoint()
                .map_err(fgdb::WriteTxnError::Interrupted)?;
            let mut accounts = BTreeSet::new();
            for leg in &entry.proposal.legs {
                work.source_legs_indexed += 1;
                accounts.insert(leg.account_ref);
            }
            for account in accounts {
                by_account.entry(account).or_default().push(position);
            }
            // Population validation intentionally checks every effective,
            // visible reversal, including unrelated accounts. Retain those
            // rows and all of their targets so pruning cannot hide a refusal.
            if entry.proposal.class == EntryClass::REVERSAL {
                reversal_related.push((*seq, position));
                for link in &entry.proposal.supersession {
                    if let Some(target) = index.position(link.target.vid) {
                        reversal_related.push((*seq, target));
                    }
                }
            }
        }
        reversal_related.sort_unstable();
        reversal_related.dedup();
        Ok(Self {
            proof,
            index,
            by_account,
            reversal_related,
            work: Cell::new(work),
        })
    }

    pub(super) fn reuse_proof(
        &self,
        book: &BookContext,
        at: CommitSeq,
    ) -> Result<VerifiedEntryPrefix, KernelError> {
        if book.book_id != self.proof.book_id || at > self.proof.at {
            return Err(KernelError::Corrupt(
                "historical revaluation exceeds its authenticated entry prefix".into(),
            ));
        }
        let mut work = self.work.get();
        work.historical_observations += 1;
        work.entry_history_proofs_reused += 1;
        self.work.set(work);
        Ok(VerifiedEntryPrefix {
            book_id: book.book_id,
            at,
        })
    }

    pub(super) fn index(&self) -> &Rc<CarryingIndex> {
        &self.index
    }

    /// Native vertices are ordered by identity. Authenticated immutable Entry
    /// roots have one version, so restricting this order to an earlier birth
    /// prefix is exactly that prefix's native validation order.
    fn select(
        &self,
        cx: &PurposeContexts,
        accounts: &[VId],
        at: CommitSeq,
        include_reversals: bool,
    ) -> Result<Vec<&(CommitSeq, VId, Entry)>, KernelError> {
        let entries = self.index.entries();
        let end = entries.partition_point(|(seq, _, _)| *seq <= at);
        let mut positions = BTreeSet::new();
        for account in accounts {
            if let Some(indices) = self.by_account.get(account) {
                for &index in &indices[..indices.partition_point(|index| *index < end)] {
                    cx.query()
                        .checkpoint()
                        .map_err(fgdb::WriteTxnError::Interrupted)?;
                    positions.insert((entries[index].1, index));
                }
            }
        }
        if include_reversals {
            for &(_, index) in &self.reversal_related
                [..self.reversal_related.partition_point(|(seq, _)| *seq <= at)]
            {
                cx.query()
                    .checkpoint()
                    .map_err(fgdb::WriteTxnError::Interrupted)?;
                if index < end {
                    positions.insert((entries[index].1, index));
                }
            }
        }
        positions
            .into_iter()
            .map(|(_, index)| {
                cx.query()
                    .checkpoint()
                    .map_err(fgdb::WriteTxnError::Interrupted)?;
                Ok(&entries[index])
            })
            .collect()
    }

    pub(super) fn adjustments(
        &self,
        cx: &PurposeContexts,
        valuation: VId,
        at: CommitSeq,
    ) -> Result<Vec<&(CommitSeq, VId, Entry)>, KernelError> {
        self.select(cx, &[valuation], at, false)
    }

    pub(super) fn source_entries(
        &self,
        cx: &PurposeContexts,
        source: VId,
        valuation: VId,
        at: CommitSeq,
        allocated: bool,
    ) -> Result<Vec<&(CommitSeq, VId, Entry)>, KernelError> {
        let selected = self.select(cx, &[source, valuation], at, allocated)?;
        let mut work = self.work.get();
        work.source_entry_candidates += selected.len();
        self.work.set(work);
        Ok(selected)
    }

    pub(super) fn contribution_hashed(&self) {
        let mut work = self.work.get();
        work.source_contributions_hashed += 1;
        self.work.set(work);
    }

    pub(super) fn carrying_work(&self, carrying: crate::carrying::CarryingPopulationWork) {
        let mut work = self.work.get();
        work.historical_carrying.accumulate(carrying);
        self.work.set(work);
    }

    pub(super) fn routes_at<V: Vfs + Clone>(
        &self,
        db: &Database<V>,
        book: &BookContext,
        date: DateDay,
        at: CommitSeq,
    ) -> Result<Option<Rc<crate::chart::FxRevaluationRoutes>>, KernelError> {
        self.index.routes_at(db, book, date, at)
    }

    pub(super) fn work(&self) -> RevaluationHistoryWork {
        let mut work = self.work.get();
        (work.historical_route_reads, work.historical_route_reuses) = self.index.route_work();
        work
    }
}
