//! Open items (plan §5.7): the application fold over immutable payloads.
//!
//! An open item is a leg of a live posted entry; its open amount is the
//! leg's amount minus the applications of live entries against it. "Live"
//! is a lineage predicate — an entry is live unless a live `Reversal`
//! targets it — so reversing a receipt reopens the invoice and reversing
//! that reversal closes it again, with nothing re-entered. The kernel keeps
//! an `applied` mirror on every Leg vertex as its concurrency witness; this
//! module is the fold that mirror must agree with (`verify_open_items`),
//! never a second source of truth.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::genesis::BookContext;
use fa_journal::rows::{applied, leg_vid};
use fa_model::{Entry, EntryClass, SupersessionKind};
use fa_money::Side;
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::{CommitSeq, VId};

use crate::{KernelError, RegisterError, entries_at, resolve_known_at};

/// One application against an open item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Application {
    pub entry: VId,
    pub ordinal: u16,
    pub amount: i128,
    pub recorded_at: CommitSeq,
    /// `false` when the applying entry is reversed: the application is
    /// undone and does not count against the item.
    pub live: bool,
}

/// A leg of a live posted entry with its application history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenItem {
    pub entry: VId,
    pub ordinal: u16,
    pub account: VId,
    pub unit_id: u32,
    pub side: Side,
    pub effective_date: DateDay,
    pub recorded_at: CommitSeq,
    pub original: i128,
    /// Sum of live applications against this leg.
    pub applied: i128,
    /// What this leg itself applied to other items (its own `settles`).
    pub applied_out: i128,
    /// `original − applied_out − applied`.
    pub open: i128,
    /// Every application ever made, live or undone, in commit order.
    pub applications: Vec<Application>,
}

/// One leg whose stored `applied` mirror disagrees with the fold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedDrift {
    pub entry: VId,
    pub ordinal: u16,
    pub stored: Option<i128>,
    pub refolded: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenItemVerification {
    pub known_at: CommitSeq,
    pub legs_checked: usize,
    pub drift: Vec<AppliedDrift>,
}

impl OpenItemVerification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.drift.is_empty()
    }
}

/// Whether an entry carries open-item legs: posted classes only (a hold
/// reserves, a release posts nothing, a reversal's legs negate).
fn carries_open_items(entry: &Entry) -> bool {
    matches!(
        entry.proposal.class,
        EntryClass::ORIGINAL | EntryClass::ADJUSTING
    ) || (entry.proposal.class == EntryClass::RESOLUTION && !entry.proposal.legs.is_empty())
}

/// The lineage predicate: `reversed_by[e]` is the reversal targeting `e`,
/// and `e` is live iff it has no live reversal. Chains are short (a
/// reversal of a reversal), so a direct recursion with a cycle guard is the
/// obvious implementation.
fn is_live(
    vid: VId,
    reversed_by: &BTreeMap<VId, VId>,
    depth: usize,
) -> Result<bool, RegisterError> {
    if depth > 64 {
        return Err(KernelError::Corrupt("reversal lineage deeper than 64".into()).into());
    }
    match reversed_by.get(&vid) {
        None => Ok(true),
        Some(reversal) => Ok(!is_live(*reversal, reversed_by, depth + 1)?),
    }
}

/// The open items of the book (optionally one account) as known at `known_at`.
pub fn open_items<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    account: Option<VId>,
    known_at: Option<CommitSeq>,
) -> Result<Vec<OpenItem>, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    let entries = entries_at(db, book, seq)?;
    let mut reversed_by: BTreeMap<VId, VId> = BTreeMap::new();
    for (vid, entry, _) in &entries {
        if entry.proposal.class != EntryClass::REVERSAL {
            continue;
        }
        if let [s] = entry.proposal.supersession.as_slice()
            && s.kind == SupersessionKind::Reverses
            && reversed_by.insert(s.target.vid, *vid).is_some()
        {
            return Err(KernelError::Corrupt("an entry is reversed twice".into()).into());
        }
    }
    let mut live: BTreeSet<VId> = BTreeSet::new();
    for (vid, _, _) in &entries {
        if is_live(*vid, &reversed_by, 0)? {
            live.insert(*vid);
        }
    }
    // Every application ever made, keyed by its target leg, in commit order.
    let mut applications: BTreeMap<(VId, u16), Vec<Application>> = BTreeMap::new();
    for (vid, entry, recorded_at) in &entries {
        if !carries_open_items(entry) {
            continue;
        }
        for (i, leg) in entry.proposal.legs.iter().enumerate() {
            let ordinal =
                u16::try_from(i).map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
            for s in &leg.settles {
                applications
                    .entry((s.target.vid, s.ordinal))
                    .or_default()
                    .push(Application {
                        entry: *vid,
                        ordinal,
                        amount: s.amount.mantissa,
                        recorded_at: *recorded_at,
                        live: live.contains(vid),
                    });
            }
        }
    }
    let mut items = Vec::new();
    for (vid, entry, recorded_at) in &entries {
        if !carries_open_items(entry) || !live.contains(vid) {
            continue;
        }
        for (i, leg) in entry.proposal.legs.iter().enumerate() {
            if account.is_some_and(|a| a != leg.account_ref) {
                continue;
            }
            let ordinal =
                u16::try_from(i).map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
            let mut history = applications.remove(&(*vid, ordinal)).unwrap_or_default();
            history.sort_by_key(|a| (a.recorded_at, a.entry, a.ordinal));
            let mut applied_sum: i128 = 0;
            for a in history.iter().filter(|a| a.live) {
                applied_sum = applied_sum
                    .checked_add(a.amount)
                    .ok_or(RegisterError::Overflow)?;
            }
            let mut applied_out: i128 = 0;
            for s in &leg.settles {
                applied_out = applied_out
                    .checked_add(s.amount.mantissa)
                    .ok_or(RegisterError::Overflow)?;
            }
            let open = leg
                .amount
                .mantissa
                .checked_sub(applied_out)
                .and_then(|o| o.checked_sub(applied_sum))
                .ok_or(RegisterError::Overflow)?;
            items.push(OpenItem {
                entry: *vid,
                ordinal,
                account: leg.account_ref,
                unit_id: leg.amount.unit.0,
                side: leg.side,
                effective_date: entry.proposal.effective_date,
                recorded_at: *recorded_at,
                original: leg.amount.mantissa,
                applied: applied_sum,
                applied_out,
                open,
                applications: history,
            });
        }
    }
    items.sort_by_key(|i| (i.account, i.recorded_at, i.entry, i.ordinal));
    Ok(items)
}

/// Compare every posted leg's stored `applied` mirror with the fold. A
/// reversed entry's legs must read zero (the kernel refuses to reverse an
/// item with live applications); a live leg must read the fold's sum; a
/// missing mirror is drift.
pub fn verify_open_items<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    known_at: Option<CommitSeq>,
) -> Result<OpenItemVerification, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    let items = open_items(db, book, None, Some(seq))?;
    let expected: BTreeMap<(VId, u16), i128> = items
        .iter()
        .map(|i| ((i.entry, i.ordinal), i.applied))
        .collect();
    let mut drift = Vec::new();
    let mut legs_checked = 0usize;
    for (vid, entry, _) in entries_at(db, book, seq)? {
        if !carries_open_items(&entry) {
            continue;
        }
        for i in 0..entry.proposal.legs.len() {
            let ordinal =
                u16::try_from(i).map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
            let refolded = expected.get(&(vid, ordinal)).copied().unwrap_or(0);
            let row = db.vertex_at(leg_vid(vid, ordinal), seq)?.ok_or_else(|| {
                KernelError::Corrupt(format!("leg {ordinal} of entry {:032x} missing", vid.0))
            })?;
            let stored = applied(&row)?;
            legs_checked += 1;
            // A missing mirror is drift even when the fold says zero: the
            // kernel refuses to apply to such a leg until it is rebuilt.
            if stored != Some(refolded) {
                drift.push(AppliedDrift {
                    entry: vid,
                    ordinal,
                    stored,
                    refolded,
                });
            }
        }
    }
    Ok(OpenItemVerification {
        known_at: seq,
        legs_checked,
        drift,
    })
}
