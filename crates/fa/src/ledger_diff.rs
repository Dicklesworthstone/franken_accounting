//! Trunk ledger diffs between two recorded frontiers (plan §15.3, `fa diff
//! --from … --to …`): one trial-balance question asked at two known-at
//! sequences, every (account, unit) whose balance changed between them, and
//! every entry recorded after the first and through the second, whatever
//! date it carries. Only recorded time differs, so an entry dated into an
//! earlier period shows in the window it was recorded in: what changed in
//! the books since a report was run.
//!
//! Both trial balances and the entry list are read in one query, so they
//! describe the same journal. Amounts are exact; a change outside the i128
//! range is a fold defect, refused and never wrapped.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_model::{EntryClass, Supersession};
use fa_registers::{RegisterError, TrialBalance};
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError, TrialBalanceSelection};

/// One (account, unit) whose debits or credits differ between two trial
/// balances, posted and pending (reserved, unposted) amounts apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrialBalanceChange {
    pub account: VId,
    pub code: String,
    pub name: String,
    pub unit_id: u32,
    pub before_debits: i128,
    pub before_credits: i128,
    pub after_debits: i128,
    pub after_credits: i128,
    /// `(after debits − credits) − (before debits − credits)`.
    pub delta: i128,
    pub before_debits_pending: i128,
    pub before_credits_pending: i128,
    pub after_debits_pending: i128,
    pub after_credits_pending: i128,
    /// The same signed change over the pending columns.
    pub pending_delta: i128,
}

/// One entry recorded in a diff's window, as its proposal states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedEntry {
    pub vid: VId,
    pub recorded_at: CommitSeq,
    pub class: EntryClass,
    pub effective_date: DateDay,
    /// The period its effective date resolves to, as the folds resolve it;
    /// `None` for an entry no period contains (a book-scoped control).
    pub period: Option<String>,
    /// What it reverses, replaces, reclassifies or resolves, with the
    /// recorded reason.
    pub supersedes: Vec<Supersession>,
}

/// A trial-balance selection at two recorded frontiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerDiff {
    pub from: CommitSeq,
    pub to: CommitSeq,
    /// The selection's periods (empty for an as-of date).
    pub periods: Vec<String>,
    pub effective_through: Option<DateDay>,
    pub activity: bool,
    /// Only the changed rows, by account code then unit.
    pub changes: Vec<TrialBalanceChange>,
    /// Every entry recorded after `from` and through `to`, in recorded order.
    pub entries: Vec<RecordedEntry>,
}

fn overflow(what: &str) -> BookError {
    BookError::Kernel(fa_journal::KernelError::Corrupt(format!(
        "trial-balance {what} exceeds the exact i128 range"
    )))
}

/// Every (account, unit) whose debits or credits differ from `before` to
/// `after`, by account code then unit, with the exact change in its net
/// balance; a row only one side has counts as zero on the other.
pub fn trial_balance_changes(
    before: &TrialBalance,
    after: &TrialBalance,
) -> Result<Vec<TrialBalanceChange>, BookError> {
    let mut cells: BTreeMap<(String, u32, u128), TrialBalanceChange> = BTreeMap::new();
    for (is_after, tb) in [(false, before), (true, after)] {
        for row in &tb.rows {
            let cell = cells
                .entry((row.code.clone(), row.unit_id, row.account.0))
                .or_insert_with(|| TrialBalanceChange {
                    account: row.account,
                    code: row.code.clone(),
                    name: row.name.clone(),
                    unit_id: row.unit_id,
                    before_debits: 0,
                    before_credits: 0,
                    after_debits: 0,
                    after_credits: 0,
                    delta: 0,
                    before_debits_pending: 0,
                    before_credits_pending: 0,
                    after_debits_pending: 0,
                    after_credits_pending: 0,
                    pending_delta: 0,
                });
            if is_after {
                cell.after_debits = row.debits;
                cell.after_credits = row.credits;
                cell.after_debits_pending = row.debits_pending;
                cell.after_credits_pending = row.credits_pending;
            } else {
                cell.before_debits = row.debits;
                cell.before_credits = row.credits;
                cell.before_debits_pending = row.debits_pending;
                cell.before_credits_pending = row.credits_pending;
            }
        }
    }
    let change = |after: (i128, i128), before: (i128, i128), what: &str| {
        let after_net = after.0.checked_sub(after.1);
        let before_net = before.0.checked_sub(before.1);
        after_net
            .zip(before_net)
            .and_then(|(a, b)| a.checked_sub(b))
            .ok_or_else(|| overflow(what))
    };
    let mut rows = Vec::new();
    for mut cell in cells.into_values() {
        let posted = (
            (cell.after_debits, cell.after_credits),
            (cell.before_debits, cell.before_credits),
        );
        let pending = (
            (cell.after_debits_pending, cell.after_credits_pending),
            (cell.before_debits_pending, cell.before_credits_pending),
        );
        if posted.0 == posted.1 && pending.0 == pending.1 {
            continue;
        }
        cell.delta = change(posted.0, posted.1, "delta")?;
        cell.pending_delta = change(pending.0, pending.1, "pending delta")?;
        rows.push(cell);
    }
    Ok(rows)
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// `selection` at `from` and at `to` (the head when `None`), what
    /// changed between them, and every entry recorded after `from` through
    /// `to`. `from` after `to` is an invalid selection.
    pub fn ledger_diff(
        &self,
        cx: &PurposeContexts,
        selection: &TrialBalanceSelection,
        from: CommitSeq,
        to: Option<CommitSeq>,
    ) -> Result<LedgerDiff, BookError> {
        self.query(cx, |db, book| {
            let to = fa_registers::resolve_known_at(db, to)?;
            let from = fa_registers::resolve_known_at(db, Some(from))?;
            if from > to {
                return Err(BookError::Registers(RegisterError::InvalidSelection(
                    format!(
                        "--from {} is after --to {}: a diff runs forward in recorded time",
                        from.0, to.0
                    ),
                )));
            }
            let before = selection.report(db, book, from)?;
            let after = selection.report(db, book, to)?;
            let changes = trial_balance_changes(&before, &after)?;
            let mut entries: Vec<RecordedEntry> = fa_registers::entries_at(db, book, to)?
                .into_iter()
                .filter(|(_, _, recorded_at)| *recorded_at > from)
                .map(|(vid, entry, recorded_at)| {
                    // A book-scoped control is dated in no period; it has none.
                    let period = fa_registers::entry_period(book, &entry).ok();
                    let proposal = entry.proposal;
                    RecordedEntry {
                        vid,
                        recorded_at,
                        class: proposal.class,
                        effective_date: proposal.effective_date,
                        period,
                        supersedes: proposal.supersession,
                    }
                })
                .collect();
            entries.sort_by_key(|entry| (entry.recorded_at, entry.vid));
            Ok(LedgerDiff {
                from,
                to,
                periods: after.periods,
                effective_through: after.effective_through,
                activity: after.activity,
                changes,
                entries,
            })
        })
    }
}
