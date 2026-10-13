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

pub mod aging;
pub mod history;
pub mod settlement;

pub use settlement::{SettlementAllocation, SettlementPlan, SettlementRequest, plan_settlement};

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::genesis::BookContext;
use fa_journal::rows::{AccountRow, applied, leg_vid};
use fa_model::symbols::label;
use fa_model::{EncodeError, Entry, EntryClass, SupersessionKind, Writer};
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

/// Exact literal output format for an open-item report.
pub const OUTPUT_FORMAT: &[u8] = b"fa:open-items:v1";

/// Open items and the account metadata used to render them, all from one
/// historical snapshot. Only displayed accounts and the explicit filter are
/// retained; unrelated chart rows do not change the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenItemsReport {
    pub known_at: CommitSeq,
    pub account_filter: Option<VId>,
    pub accounts: BTreeMap<VId, AccountRow>,
    pub items: Vec<OpenItem>,
}

impl OpenItemsReport {
    /// Bind exact mantissas, the complete application history and historical
    /// account metadata. Reversed applications remain visible with live=false.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(OUTPUT_FORMAT)
            .u64(self.known_at.0)
            .opt(self.account_filter.as_ref(), |w, account| {
                w.u128(account.0);
            });
        let accounts: Vec<_> = self.accounts.iter().collect();
        w.list(&accounts, |w, (vid, account)| {
            w.u128(vid.0);
            crate::report::account(w, account);
        })
        .list(&self.items, |w, item| {
            w.u128(item.entry.0)
                .u16(item.ordinal)
                .u128(item.account.0)
                .u32(item.unit_id)
                .u8(crate::report::side(item.side))
                .i32(item.effective_date.0)
                .u64(item.recorded_at.0)
                .i128(item.original)
                .i128(item.applied)
                .i128(item.applied_out)
                .i128(item.open)
                .list(&item.applications, |w, application| {
                    w.u128(application.entry.0)
                        .u16(application.ordinal)
                        .i128(application.amount)
                        .u64(application.recorded_at.0)
                        .bool(application.live);
                });
        });
        w.finish()
    }
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
/// reserves, a release posts nothing, a reversal's legs negate). A
/// `Migration` chunk reaches here only when the migration predicate selects
/// it (its run Finalized, the chunk counting), so its legs are open items
/// exactly then (ruling 3733 C1).
#[must_use]
pub fn carries_open_items(entry: &Entry) -> bool {
    matches!(
        entry.proposal.class,
        EntryClass::ORIGINAL | EntryClass::ADJUSTING | EntryClass::MIGRATION
    ) || (entry.proposal.class == EntryClass::RESOLUTION && !entry.proposal.legs.is_empty())
}

/// The lineage predicate: `reversed_by[e]` is the reversal targeting `e`,
/// and `e` is live iff it has no live reversal. A chain of any length is
/// legal (every reversal of a reversal is an explicit entry), so this is an
/// iterative parity walk; the only failure is a cycle, which honest
/// identities cannot form and which therefore means corruption.
pub fn is_live(vid: VId, reversed_by: &BTreeMap<VId, VId>) -> Result<bool, RegisterError> {
    let mut live = true;
    let mut current = vid;
    let mut seen: BTreeSet<VId> = BTreeSet::new();
    while let Some(reversal) = reversed_by.get(&current) {
        if !seen.insert(current) {
            return Err(
                KernelError::Corrupt(format!("reversal lineage of {:032x} cycles", vid.0)).into(),
            );
        }
        live = !live;
        current = *reversal;
    }
    Ok(live)
}

/// The open items of the book (optionally one account) as known at `known_at`.
pub fn open_items<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    account: Option<VId>,
    known_at: Option<CommitSeq>,
) -> Result<Vec<OpenItem>, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    if let Some(account) = account {
        account_at(db, account, seq)?;
    }
    let entries = entries_at(db, book, seq)?;
    fold_open_items(&entries, account)
}

fn account_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    account: VId,
    seq: CommitSeq,
) -> Result<AccountRow, RegisterError> {
    let row = db
        .vertex_at(account, seq)?
        .filter(|row| row.labels.contains(&label::ACCOUNT))
        .ok_or_else(|| {
            RegisterError::InvalidSelection(format!(
                "unknown account {:032x} at sequence {}",
                account.0, seq.0
            ))
        })?;
    Ok(AccountRow::decode(&row)?)
}

/// Retain the literal fold and its account display metadata at the same
/// known-at coordinate. An unknown historical account is a selection error.
pub fn open_items_report<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    account: Option<VId>,
    known_at: Option<CommitSeq>,
) -> Result<OpenItemsReport, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    let items = open_items(db, book, account, Some(seq))?;
    let accounts = items
        .iter()
        .map(|item| item.account)
        .chain(account)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|vid| account_at(db, vid, seq).map(|row| (vid, row)))
        .collect::<Result<_, _>>()?;
    Ok(OpenItemsReport {
        known_at: seq,
        account_filter: account,
        accounts,
        items,
    })
}

// One payload fold shared by known-at-only and effective-cutoff readers.
fn fold_open_items(
    entries: &[(VId, Entry, CommitSeq)],
    account: Option<VId>,
) -> Result<Vec<OpenItem>, RegisterError> {
    let mut reversed_by: BTreeMap<VId, VId> = BTreeMap::new();
    for (vid, entry, _) in entries {
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
    for (vid, _, _) in entries {
        if is_live(*vid, &reversed_by)? {
            live.insert(*vid);
        }
    }
    // Every application ever made, keyed by its target leg, in commit order.
    let mut applications: BTreeMap<(VId, u16), Vec<Application>> = BTreeMap::new();
    for (vid, entry, recorded_at) in entries {
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
    for (vid, entry, recorded_at) in entries {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_output_distinguishes_application_history_even_when_open_amount_is_equal() {
        let account = AccountRow {
            vid: VId(9),
            code: "AR".into(),
            name: "Receivables at the selected snapshot".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: fa_journal::UnitPolicy::Single(fa_money::UnitId(1)),
            limit: None,
            created_at: CommitSeq(2),
        };
        let mut report = OpenItemsReport {
            known_at: CommitSeq(8),
            account_filter: Some(account.vid),
            accounts: BTreeMap::from([(account.vid, account)]),
            items: vec![OpenItem {
                entry: VId(10),
                ordinal: 0,
                account: VId(9),
                unit_id: 1,
                side: Side::Debit,
                effective_date: DateDay(20_000),
                recorded_at: CommitSeq(3),
                original: 9_007_199_254_740_993,
                applied: 0,
                applied_out: 0,
                open: 9_007_199_254_740_993,
                applications: vec![Application {
                    entry: VId(11),
                    ordinal: 1,
                    amount: 9_007_199_254_740_993,
                    recorded_at: CommitSeq(5),
                    live: false,
                }],
            }],
        };
        let original = report.canonical_bytes().unwrap();
        assert!(original.starts_with(OUTPUT_FORMAT));
        assert!(original.windows(16).any(|bytes| {
            bytes == 9_007_199_254_740_993i128.to_le_bytes().as_slice()
        }));

        // Public settlement advice consumes the same exact, reversal-aware
        // snapshot as the certified report, without changing its output bytes.
        let request = SettlementRequest {
            account: VId(9),
            unit_id: 1,
            side: Side::Credit,
            amount: 9_007_199_254_740_993,
            effective_date: DateDay(20_000),
            targets: vec![(VId(10), 0)],
        };
        let plan = report.plan_settlement(&request).unwrap();
        assert_eq!(plan.known_at, report.known_at);
        assert_eq!(plan.unapplied, 0);
        assert_eq!(plan.allocations.len(), 1);
        assert_eq!(plan.allocations[0].amount, request.amount);
        assert_eq!(plan.allocations[0].open_before, request.amount);
        assert_eq!(plan.allocations[0].open_after, 0);
        plan.validate_against(&report).unwrap();
        assert_eq!(report.canonical_bytes().unwrap(), original);
        let mut newer = report.clone();
        newer.known_at = CommitSeq(9);
        assert!(plan.validate_against(&newer).is_err());

        // An undone application remains part of the certified history even
        // though it contributes zero to the current applied/open amounts.
        let history = report.items[0].applications.pop().unwrap();
        assert_ne!(report.canonical_bytes().unwrap(), original);
        report.items[0].applications.push(history);
        assert_eq!(report.canonical_bytes().unwrap(), original);
        report.items[0].applications[0].recorded_at = CommitSeq(6);
        assert_ne!(report.canonical_bytes().unwrap(), original);
        report.items[0].applications[0].recorded_at = CommitSeq(5);
        report.accounts.get_mut(&VId(9)).unwrap().name = "Later account name".into();
        assert_ne!(report.canonical_bytes().unwrap(), original);
        report.accounts.get_mut(&VId(9)).unwrap().name =
            "Receivables at the selected snapshot".into();
        report.account_filter = None;
        assert_ne!(report.canonical_bytes().unwrap(), original);
    }

    /// Parity over a chain of any length: 65 links reverse the original,
    /// 66 revive it; a cycle is corruption, never a stack overflow or a
    /// false "corrupt" on a long honest history.
    #[test]
    fn liveness_is_parity_over_arbitrarily_long_chains_and_cycles_are_corruption() {
        for n in [0usize, 1, 2, 63, 64, 65, 66, 200] {
            let mut reversed_by = BTreeMap::new();
            for i in 0..n {
                reversed_by.insert(VId(i as u128), VId(i as u128 + 1));
            }
            assert_eq!(
                is_live(VId(0), &reversed_by).unwrap(),
                n % 2 == 0,
                "chain {n}"
            );
            assert!(is_live(VId(n as u128), &reversed_by).unwrap(), "tip {n}");
        }
        let mut cyclic = BTreeMap::new();
        cyclic.insert(VId(1), VId(2));
        cyclic.insert(VId(2), VId(3));
        cyclic.insert(VId(3), VId(1));
        assert!(matches!(
            is_live(VId(1), &cyclic),
            Err(RegisterError::Kernel(KernelError::Corrupt(_)))
        ));
    }
}
