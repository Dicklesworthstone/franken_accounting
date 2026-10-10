//! Reserved availability (plan §5.4, §5.5): the refold every `LimitCell`
//! must agree with.
//!
//! The kernel keeps limit cells as its concurrency witnesses (the interim
//! posture of Appendix H R-ESC): one per lifetime-limited account, and one
//! per period for a budget cap (a period-scoped limit). This module
//! recomputes every expected cell from the immutable payloads alone —
//! posted legs of posting classes, reserved legs of unresolved holds, the
//! full original legs of a resolved hold released — keyed the way the kernel
//! keys them (posted and reserved legs in the entry's period, released legs
//! in the hold's period), compares it with the stored cell, generation
//! included, and checks that the stored cell is bound to its account (its
//! `account_ref`) and, for a period cell, to its period. A cell is a
//! witness, never truth: drift is a finding for `fa verify availability`
//! (exit 8), never a correction applied to the journal.
//!
//! **Scope.** Verification covers the expected cells: the vertex at
//! `limit_cell_vid(account)` for a lifetime limit, and at
//! `period_cell_vid(account, period)` for every period of the book for a
//! budget cap. `LimitCell` vertices that no limited account's identity
//! references are outside this check and are not reported; a green result
//! does not claim every stored `LimitCell` vertex was examined.

use std::collections::BTreeMap;

use fa_journal::genesis::BookContext;
use fa_journal::limit::{
    BalanceLimit, LimitCell, LimitScope, Movement, cell_account, cell_period, cell_vid,
};
use fa_journal::rows::{AccountRow, PeriodRow};
use fa_model::symbols::label;
use fa_model::{Entry, EntryClass};
use fa_money::Side;
use fgdb::Database;
use fgdb_types::{CommitSeq, VId};

use crate::{KernelError, RegisterError, entries_at, entry_period, resolve_known_at};

/// One expected cell as the refold sees it, in its account's normal-balance
/// sign: a limited account's lifetime cell (`period: None`), or one period
/// cell of a budget-capped account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountAvailability {
    pub account: VId,
    pub code: String,
    pub period: Option<String>,
    pub normal: Side,
    pub limit: BalanceLimit,
    /// The refolded cell (the truth the stored cell must equal).
    pub cell: LimitCell,
    pub net: i128,
    pub pending_out: i128,
    pub pending_in: i128,
}

/// One expected cell whose stored state disagrees with the refold; `stored`
/// is `None` when the cell is missing or malformed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailabilityDrift {
    pub account: VId,
    pub code: String,
    /// The period of a budget cap's cell; `None` for a lifetime cell.
    pub period: Option<String>,
    pub stored: Option<LimitCell>,
    pub refolded: LimitCell,
    /// The account the stored cell claims (`account_ref`); `None` when the
    /// cell is missing or its reference is absent or malformed. Anything but
    /// `Some(account)` is drift even when the sums agree.
    pub stored_account: Option<VId>,
    /// That account's code, when it names an account of this book.
    pub stored_account_code: Option<String>,
    /// The period the stored cell claims (`effective_period`); for a period
    /// cell anything but `Some(period)` is drift.
    pub stored_period: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailabilityVerification {
    pub known_at: CommitSeq,
    /// Limited accounts (lifetime or budget-capped).
    pub accounts_checked: usize,
    /// Expected cells examined (one per lifetime limit, one per period per
    /// budget cap).
    pub cells_checked: usize,
    pub accounts: Vec<AccountAvailability>,
    pub drift: Vec<AvailabilityDrift>,
}

impl AvailabilityVerification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.drift.is_empty()
    }
}

/// `(account, cell period)`: `None` for a lifetime cell.
type CellKey = (VId, Option<String>);

fn add(slot: &mut i128, m: i128) -> Result<(), RegisterError> {
    *slot = slot.checked_add(m).ok_or(RegisterError::Overflow)?;
    Ok(())
}

/// Fold one entry's movement into `cells`, keyed as the kernel keys it:
/// posted and reserved legs in the entry's period, released legs in the
/// hold's period (lifetime cells ignore the period); each cell an entry
/// touches advances its generation once.
fn fold_entry(
    cells: &mut BTreeMap<CellKey, LimitCell>,
    scopes: &BTreeMap<VId, LimitScope>,
    book: &BookContext,
    entry: &Entry,
    by_id: &BTreeMap<VId, &Entry>,
) -> Result<(), RegisterError> {
    let p = &entry.proposal;
    let mut moves: BTreeMap<CellKey, Movement> = BTreeMap::new();
    let key = |account: VId, of: &Entry| -> Result<Option<CellKey>, RegisterError> {
        Ok(match scopes.get(&account) {
            None => None,
            Some(LimitScope::Lifetime) => Some((account, None)),
            Some(LimitScope::Period) => Some((account, Some(entry_period(book, of)?))),
        })
    };
    match p.class {
        EntryClass::ORIGINAL | EntryClass::ADJUSTING | EntryClass::REVERSAL => {
            for leg in &p.legs {
                if let Some(k) = key(leg.account_ref, entry)? {
                    moves
                        .entry(k)
                        .or_default()
                        .post(leg.side, leg.amount.mantissa)?;
                }
            }
        }
        EntryClass::PENDING => {
            for leg in &p.legs {
                if let Some(k) = key(leg.account_ref, entry)? {
                    moves
                        .entry(k)
                        .or_default()
                        .reserve(leg.side, leg.amount.mantissa)?;
                }
            }
        }
        EntryClass::RESOLUTION => {
            let target = p
                .pending
                .as_ref()
                .and_then(|x| x.resolution_of)
                .ok_or_else(|| KernelError::Corrupt("resolution has no pending target".into()))?;
            let hold = by_id
                .get(&target.vid)
                .ok_or_else(|| KernelError::Corrupt("resolution target is missing".into()))?;
            for leg in &hold.proposal.legs {
                if let Some(k) = key(leg.account_ref, hold)? {
                    moves
                        .entry(k)
                        .or_default()
                        .release(leg.side, leg.amount.mantissa)?;
                }
            }
            for leg in &p.legs {
                if let Some(k) = key(leg.account_ref, entry)? {
                    moves
                        .entry(k)
                        .or_default()
                        .post(leg.side, leg.amount.mantissa)?;
                }
            }
        }
        // Control entries carry no legs; classes the kernel does not admit
        // carry none on a limited account.
        _ => {}
    }
    for (k, m) in moves {
        let cell = cells.get_mut(&k).ok_or_else(|| {
            KernelError::Corrupt(format!(
                "account {:032x} moved in period {:?}, which has no expected cell",
                k.0.0, k.1
            ))
        })?;
        add(&mut cell.debits_posted, m.posted_debits)?;
        add(&mut cell.credits_posted, m.posted_credits)?;
        add(&mut cell.debits_pending, m.reserved_debits)?;
        add(&mut cell.credits_pending, m.reserved_credits)?;
        add(
            &mut cell.debits_pending,
            m.released_debits
                .checked_neg()
                .ok_or(RegisterError::Overflow)?,
        )?;
        add(
            &mut cell.credits_pending,
            m.released_credits
                .checked_neg()
                .ok_or(RegisterError::Overflow)?,
        )?;
        if cell.debits_pending < 0 || cell.credits_pending < 0 {
            return Err(KernelError::Corrupt(format!(
                "account {:032x}: a resolution releases more than its hold reserved",
                k.0.0
            ))
            .into());
        }
        cell.generation = cell
            .generation
            .checked_add(1)
            .ok_or(RegisterError::Overflow)?;
    }
    Ok(())
}

/// Refold every expected limit cell at `known_at` (head when `None`) and
/// compare it with the stored `LimitCell` at the derived identity: sums,
/// generation, and the `account_ref` (and, for a period cell, the
/// `effective_period`) binding. Only those expected cells are examined (see
/// the module's scope note).
pub fn verify_availability<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    known_at: Option<CommitSeq>,
) -> Result<AvailabilityVerification, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    let mut limited: BTreeMap<VId, (AccountRow, BalanceLimit)> = BTreeMap::new();
    let mut codes: BTreeMap<VId, String> = BTreeMap::new();
    let mut periods: Vec<String> = Vec::new();
    for row in db.vertices_at(seq)? {
        if row.labels.contains(&label::PERIOD) {
            periods.push(PeriodRow::decode(&row)?.code);
            continue;
        }
        if !row.labels.contains(&label::ACCOUNT) {
            continue;
        }
        let account = AccountRow::decode(&row)?;
        codes.insert(row.vid, account.code.clone());
        if let Some(limit) = BalanceLimit::decode(&row)? {
            limited.insert(row.vid, (account, limit));
        }
    }
    periods.sort();
    let scopes: BTreeMap<VId, LimitScope> =
        limited.iter().map(|(v, (_, l))| (*v, l.scope)).collect();
    let mut cells: BTreeMap<CellKey, LimitCell> = BTreeMap::new();
    for (vid, (_, limit)) in &limited {
        match limit.scope {
            LimitScope::Lifetime => {
                cells.insert((*vid, None), LimitCell::default());
            }
            LimitScope::Period => {
                for p in &periods {
                    cells.insert((*vid, Some(p.clone())), LimitCell::default());
                }
            }
        }
    }
    let entries = entries_at(db, book, seq)?;
    let by_id: BTreeMap<VId, &Entry> = entries.iter().map(|(v, e, _)| (*v, e)).collect();
    let mut ordered: Vec<&(VId, Entry, CommitSeq)> = entries.iter().collect();
    ordered.sort_by_key(|(v, _, seq)| (*seq, *v));
    for (_, entry, _) in ordered {
        fold_entry(&mut cells, &scopes, book, entry, &by_id)?;
    }
    let mut accounts = Vec::with_capacity(cells.len());
    let mut drift = Vec::new();
    for ((vid, period), refolded) in &cells {
        let (account, limit) = limited
            .get(vid)
            .ok_or_else(|| KernelError::Corrupt("refold lost an account".into()))?;
        let normal = if account.normal_balance == 0 {
            Side::Debit
        } else {
            Side::Credit
        };
        let row = db
            .vertex_at(cell_vid(*vid, period.as_deref()), seq)?
            .filter(|row| row.labels.contains(&label::LIMIT_CELL));
        let stored = row.as_ref().and_then(|r| LimitCell::decode(r).ok());
        let stored_account = row.as_ref().and_then(|r| cell_account(r).ok().flatten());
        let stored_period = row.as_ref().and_then(|r| cell_period(r).ok().flatten());
        let period_bound = period.is_none() || stored_period == *period;
        if stored != Some(*refolded) || stored_account != Some(*vid) || !period_bound {
            drift.push(AvailabilityDrift {
                account: *vid,
                code: account.code.clone(),
                period: period.clone(),
                stored,
                refolded: *refolded,
                stored_account,
                stored_account_code: stored_account.and_then(|a| codes.get(&a).cloned()),
                stored_period,
            });
        }
        let (net, pending_out, pending_in) = refolded.availability(normal)?;
        accounts.push(AccountAvailability {
            account: *vid,
            code: account.code.clone(),
            period: period.clone(),
            normal,
            limit: *limit,
            cell: *refolded,
            net,
            pending_out,
            pending_in,
        });
    }
    accounts.sort_by(|a, b| (&a.code, &a.period).cmp(&(&b.code, &b.period)));
    drift.sort_by(|a, b| (&a.code, &a.period).cmp(&(&b.code, &b.period)));
    Ok(AvailabilityVerification {
        known_at: seq,
        accounts_checked: limited.len(),
        cells_checked: cells.len(),
        accounts,
        drift,
    })
}
