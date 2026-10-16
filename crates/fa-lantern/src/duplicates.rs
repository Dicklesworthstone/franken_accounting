//! Duplicate detection (plan §11.3): entries with the same leg multiset
//! (account, side, unit, magnitude) on the same date, or on different dates
//! inside a window. The counterparty is the account set until Party edges
//! exist; `duplicates.near` (amount tolerance plus description similarity)
//! is a later slice.

use std::collections::BTreeMap;

use fa_journal::genesis::BookContext;
use fa_money::Side;
use fgdb_types::VId;

use crate::jet::{finding, procedure_boilerplate};
use crate::{
    Cite, Finding, LanternError, MAX_CITES, Params, Procedure, Severity, Snapshot, SnapshotEntry,
    Statistic, Work,
};

type Signature = Vec<(u128, u8, u32, i128)>;

fn signature(e: &SnapshotEntry, work: &mut Work) -> Signature {
    let mut s: Signature = e
        .entry
        .proposal
        .legs
        .iter()
        .map(|l| {
            work.leg();
            (
                l.account_ref.0,
                match l.side {
                    Side::Debit => 0,
                    Side::Credit => 1,
                },
                l.amount.unit.0,
                l.amount.mantissa,
            )
        })
        .collect();
    s.sort_unstable();
    s
}

/// `duplicates.same_same_same`: same legs, same effective date.
pub struct SameSameSame {
    params: Params,
}
procedure_boilerplate!(SameSameSame, "duplicates.same_same_same");

impl Procedure for SameSameSame {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        _book: &BookContext,
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let mut groups: BTreeMap<(Signature, i32), Vec<VId>> = BTreeMap::new();
        let mut population = 0u64;
        for e in snapshot.live_postings()? {
            work.entry();
            population += 1;
            let list = groups
                .entry((signature(e, work), e.entry.proposal.effective_date.0))
                .or_default();
            if list
                .iter()
                .all(|&other| !snapshot.shares_supersession_lineage(other, e.vid))
            {
                list.push(e.vid);
            }
        }
        work.compare(population.saturating_mul(population.max(1).ilog2().into()));
        Ok(groups
            .into_values()
            .filter(|g| g.len() >= 2)
            .map(|mut g| {
                g.sort_unstable();
                let n = g.len() as u64;
                // A finding cites at most MAX_CITES handles; a larger group is
                // still one finding, its full size in the statistic.
                let cited = if g.len() > MAX_CITES {
                    format!(" (the first {MAX_CITES} by entry id cited)")
                } else {
                    String::new()
                };
                g.truncate(MAX_CITES);
                finding(
                    Self::ID,
                    Severity::Medium,
                    Statistic::count("entries", n, population),
                    g.into_iter().map(Cite::Entry).collect(),
                    format!("{n} entries share the same legs and effective date{cited}"),
                )
            })
            .collect())
    }
}

/// `duplicates.same_same_different`: same legs, different effective dates at
/// most `window_days` apart. Each entry is paired with the next occurrence of
/// its legs on a later date (the first recorded entry on that date), so a
/// group of k identical entries yields at most k pairs: a retail book with
/// identical daily sales reports a chain, not every pair of days.
pub struct SameSameDifferent {
    params: Params,
}
procedure_boilerplate!(SameSameDifferent, "duplicates.same_same_different");

impl Procedure for SameSameDifferent {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        _book: &BookContext,
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let window = i32::try_from(self.params.get_u32("window_days")?)
            .map_err(|_| LanternError::Overflow("window_days"))?;
        // `(effective day, recorded sequence, entry)` per signature.
        let mut groups: BTreeMap<Signature, Vec<(i32, u64, VId)>> = BTreeMap::new();
        let mut population = 0u64;
        for e in snapshot.live_postings()? {
            work.entry();
            population += 1;
            groups.entry(signature(e, work)).or_default().push((
                e.entry.proposal.effective_date.0,
                e.recorded_at.0,
                e.vid,
            ));
        }
        let mut out = Vec::new();
        for list in groups.values_mut() {
            list.sort_unstable();
            // `next` is the first index on a later date than `list[i]`; it
            // only moves forward, so the scan is linear after the sort.
            let mut next = 0usize;
            for i in 0..list.len() {
                next = next.max(i + 1);
                while next < list.len() && list[next].0 == list[i].0 {
                    work.compare(1);
                    next += 1;
                }
                let mut cand = next;
                while cand < list.len()
                    && snapshot.shares_supersession_lineage(list[i].2, list[cand].2)
                {
                    work.compare(1);
                    cand += 1;
                }
                let Some(&(day, _, later)) = list.get(cand) else {
                    continue;
                };
                work.compare(1);
                let apart = day - list[i].0;
                if apart > window {
                    continue;
                }
                // Earlier then later, in (date, recorded) order: the
                // chronology a reader checks, never the hashed vid order.
                let pair = [list[i].2, later];
                out.push(finding(
                    Self::ID,
                    Severity::Low,
                    Statistic::count("days_apart", apart as u64, population),
                    pair.into_iter().map(Cite::Entry).collect(),
                    format!(
                        "two entries share the same legs {apart} day(s) apart (window {window})"
                    ),
                ));
            }
        }
        Ok(out)
    }
}
