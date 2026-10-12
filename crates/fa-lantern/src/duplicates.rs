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
    Cite, Finding, LanternError, Params, Procedure, Severity, Snapshot, SnapshotEntry, Statistic,
    Work,
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
        for e in snapshot.entries.iter().filter(|e| e.posts()) {
            work.entry();
            population += 1;
            groups
                .entry((signature(e, work), e.entry.proposal.effective_date.0))
                .or_default()
                .push(e.vid);
        }
        work.compare(population.saturating_mul(population.max(1).ilog2().into()));
        Ok(groups
            .into_values()
            .filter(|g| g.len() >= 2)
            .map(|mut g| {
                g.sort_unstable();
                let n = g.len() as u64;
                finding(
                    Self::ID,
                    Severity::Medium,
                    Statistic::count("entries", n, population),
                    g.into_iter().map(Cite::Entry).collect(),
                    format!("{n} entries share the same legs and effective date"),
                )
            })
            .collect())
    }
}

/// `duplicates.same_same_different`: same legs, different effective dates at
/// most `window_days` apart.
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
        let mut groups: BTreeMap<Signature, Vec<(i32, VId)>> = BTreeMap::new();
        let mut population = 0u64;
        for e in snapshot.entries.iter().filter(|e| e.posts()) {
            work.entry();
            population += 1;
            groups
                .entry(signature(e, work))
                .or_default()
                .push((e.entry.proposal.effective_date.0, e.vid));
        }
        let mut out = Vec::new();
        for list in groups.values_mut() {
            list.sort_unstable();
            for i in 0..list.len() {
                for j in (i + 1)..list.len() {
                    work.compare(1);
                    let apart = list[j].0 - list[i].0;
                    if apart > window {
                        break;
                    }
                    if apart >= 1 {
                        let mut pair = [list[i].1, list[j].1];
                        pair.sort_unstable();
                        out.push(finding(
                            Self::ID,
                            Severity::Low,
                            Statistic::count("days_apart", apart as u64, population),
                            pair.into_iter().map(Cite::Entry).collect(),
                            format!("two entries share the same legs {apart} day(s) apart (window {window})"),
                        ));
                    }
                }
            }
        }
        Ok(out)
    }
}
