//! Reserved availability (plan §5.4, §5.5): the refold every `LimitCell`
//! must agree with.
//!
//! The kernel keeps one `LimitCell` per limited account as its concurrency
//! witness (the interim posture of Appendix H R-ESC). This module recomputes
//! the cell from the immutable payloads alone — posted legs of posting
//! classes, reserved legs of unresolved holds, the full original legs of a
//! resolved hold released — and compares it with the stored cell, generation
//! included. A cell is a witness, never truth: drift is a finding for `fa
//! verify availability` (exit 8), never a correction applied to the journal.

use std::collections::BTreeMap;

use fa_journal::genesis::BookContext;
use fa_journal::limit::{BalanceLimit, LimitCell, Movement, limit_cell_vid};
use fa_journal::rows::AccountRow;
use fa_model::symbols::label;
use fa_model::{Entry, EntryClass};
use fa_money::Side;
use fgdb::Database;
use fgdb_types::{CommitSeq, VId};

use crate::{KernelError, RegisterError, entries_at, resolve_known_at};

/// One limited account as the refold sees it, in its normal-balance sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountAvailability {
    pub account: VId,
    pub code: String,
    pub normal: Side,
    pub limit: BalanceLimit,
    /// The refolded cell (the truth the stored cell must equal).
    pub cell: LimitCell,
    pub net: i128,
    pub pending_out: i128,
    pub pending_in: i128,
}

/// One limited account whose stored cell disagrees with the refold; `stored`
/// is `None` when the cell is missing or malformed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailabilityDrift {
    pub account: VId,
    pub code: String,
    pub stored: Option<LimitCell>,
    pub refolded: LimitCell,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailabilityVerification {
    pub known_at: CommitSeq,
    pub accounts_checked: usize,
    pub accounts: Vec<AccountAvailability>,
    pub drift: Vec<AvailabilityDrift>,
}

impl AvailabilityVerification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.drift.is_empty()
    }
}

fn add(slot: &mut i128, m: i128) -> Result<(), RegisterError> {
    *slot = slot.checked_add(m).ok_or(RegisterError::Overflow)?;
    Ok(())
}

/// Fold one entry's movement into `cells` for the limited accounts it
/// touches; each touched cell's generation advances once.
fn fold_entry(
    cells: &mut BTreeMap<VId, LimitCell>,
    entry: &Entry,
    by_id: &BTreeMap<VId, &Entry>,
) -> Result<(), RegisterError> {
    let mut moves: BTreeMap<VId, Movement> = BTreeMap::new();
    let p = &entry.proposal;
    match p.class {
        EntryClass::ORIGINAL | EntryClass::ADJUSTING | EntryClass::REVERSAL => {
            for leg in &p.legs {
                if cells.contains_key(&leg.account_ref) {
                    moves
                        .entry(leg.account_ref)
                        .or_default()
                        .post(leg.side, leg.amount.mantissa)?;
                }
            }
        }
        EntryClass::PENDING => {
            for leg in &p.legs {
                if cells.contains_key(&leg.account_ref) {
                    moves
                        .entry(leg.account_ref)
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
                if cells.contains_key(&leg.account_ref) {
                    moves
                        .entry(leg.account_ref)
                        .or_default()
                        .release(leg.side, leg.amount.mantissa)?;
                }
            }
            for leg in &p.legs {
                if cells.contains_key(&leg.account_ref) {
                    moves
                        .entry(leg.account_ref)
                        .or_default()
                        .post(leg.side, leg.amount.mantissa)?;
                }
            }
        }
        // Control entries carry no legs; classes the kernel does not admit
        // carry none on a limited account.
        _ => {}
    }
    for (account, m) in moves {
        let cell = cells
            .get_mut(&account)
            .ok_or_else(|| KernelError::Corrupt("limited account vanished".into()))?;
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
                account.0
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

/// Refold every limited account's cell at `known_at` (head when `None`) and
/// compare it with the stored `LimitCell`.
pub fn verify_availability<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    known_at: Option<CommitSeq>,
) -> Result<AvailabilityVerification, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    let mut limited: BTreeMap<VId, (AccountRow, BalanceLimit)> = BTreeMap::new();
    for row in db.vertices_at(seq)? {
        if !row.labels.contains(&label::ACCOUNT) {
            continue;
        }
        if let Some(limit) = BalanceLimit::decode(&row)? {
            limited.insert(row.vid, (AccountRow::decode(&row)?, limit));
        }
    }
    let mut cells: BTreeMap<VId, LimitCell> =
        limited.keys().map(|a| (*a, LimitCell::default())).collect();
    let entries = entries_at(db, book, seq)?;
    let by_id: BTreeMap<VId, &Entry> = entries.iter().map(|(v, e, _)| (*v, e)).collect();
    let mut ordered: Vec<&(VId, Entry, CommitSeq)> = entries.iter().collect();
    ordered.sort_by_key(|(v, _, seq)| (*seq, *v));
    for (_, entry, _) in ordered {
        fold_entry(&mut cells, entry, &by_id)?;
    }
    let mut accounts = Vec::with_capacity(limited.len());
    let mut drift = Vec::new();
    for (vid, (account, limit)) in &limited {
        let refolded = cells
            .get(vid)
            .copied()
            .ok_or_else(|| KernelError::Corrupt("refold lost a cell".into()))?;
        let normal = if account.normal_balance == 0 {
            Side::Debit
        } else {
            Side::Credit
        };
        let stored = db
            .vertex_at(limit_cell_vid(*vid), seq)?
            .filter(|row| row.labels.contains(&label::LIMIT_CELL))
            .and_then(|row| LimitCell::decode(&row).ok());
        if stored != Some(refolded) {
            drift.push(AvailabilityDrift {
                account: *vid,
                code: account.code.clone(),
                stored,
                refolded,
            });
        }
        let (net, pending_out, pending_in) = refolded.availability(normal)?;
        accounts.push(AccountAvailability {
            account: *vid,
            code: account.code.clone(),
            normal,
            limit: *limit,
            cell: refolded,
            net,
            pending_out,
            pending_in,
        });
    }
    accounts.sort_by(|a, b| a.code.cmp(&b.code));
    drift.sort_by(|a, b| a.code.cmp(&b.code));
    Ok(AvailabilityVerification {
        known_at: seq,
        accounts_checked: accounts.len(),
        accounts,
        drift,
    })
}
