//! Explain a balance (plan §15.3 `fa explain balance`): the register cells of
//! one account in one period at a known-at frontier, the fold they belong to,
//! every leg that contributes to them with its entry and recorded sequence,
//! and the cell's known-at history (when it last changed, and by what).
//!
//! A certified-read precursor, not a certificate: the explanation reads the
//! same immutable payloads at the same snapshot as [`fold_period_at`], applies
//! the fold's own selection (legless entries and other periods contribute
//! nothing; a released reservation is in neither column), and must re-add to
//! the fold's cells exactly. A disagreement is corruption, never an
//! explanation — the journal is the truth and the explanation is a view of it.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::KernelError;
use fa_journal::genesis::BookContext;
use fa_journal::rows::AccountRow;
use fa_model::symbols::label;
use fa_model::{EntryClass, EvidenceRef, Supersession};
use fa_money::Side;
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::{CommitSeq, VId};

use crate::{
    Cell, RegisterError, contribution_seq, entries_at, entry_period, fold_period_at,
    migration_activations, resolutions, resolve_known_at,
};

/// Which column of the register a contributing leg lands in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Column {
    /// A posting entry's leg: the posted debits and credits.
    Posted,
    /// An outstanding reservation's leg: the pending debits and credits.
    Pending,
    /// A reservation a Resolution released at `released_at`: in neither
    /// column at this frontier, listed because it was pending here once.
    Released,
}

impl Column {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Pending => "pending",
            Self::Released => "released",
        }
    }
}

/// One leg of one entry that bears on the account's cells in the period.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contribution {
    pub entry: VId,
    pub entry_digest: [u8; 32],
    pub class: EntryClass,
    pub effective_date: DateDay,
    /// The entry's recorded sequence (its creating commit), never user-supplied.
    pub recorded_at: CommitSeq,
    /// The first sequence at which this leg contributes: its creating
    /// commit, or the later Finalize that activates a migration chunk.
    pub visible_at: CommitSeq,
    pub ordinal: u16,
    pub side: Side,
    pub unit_id: u32,
    pub mantissa: i128,
    pub column: Column,
    /// For `Released`: the recorded sequence of the releasing Resolution.
    pub released_at: Option<CommitSeq>,
    /// For a Resolution: the hold it resolves.
    pub resolves: Option<VId>,
    /// The entry's lineage (what it reverses, replaces, …).
    pub supersedes: Vec<Supersession>,
    /// The entry's evidence heads, as committed.
    pub evidence: Vec<EvidenceRef>,
}

/// The account's cell in one unit as known after `recorded_at`: one point of
/// the known-at history, emitted at every sequence that touched the cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellChange {
    pub recorded_at: CommitSeq,
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
    pub debits_pending: i128,
    pub credits_pending: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceExplanation {
    pub account: VId,
    /// The account as it stood at `known_at` (never a later chart's metadata).
    pub account_row: AccountRow,
    pub period: String,
    /// The fixed snapshot read, including when the caller asked for HEAD.
    pub known_at: CommitSeq,
    /// The whole period's fold at `known_at`: these cells are part of the
    /// projection this digest and watermark name (what `fa verify registers`
    /// compares a materialized register against).
    pub fold_digest: [u8; 32],
    pub watermark: Option<CommitSeq>,
    /// The account's posted cells in that fold, one per unit, by unit.
    pub cells: Vec<Cell>,
    /// The account's pending cells in that fold, one per unit, by unit.
    pub pending: Vec<Cell>,
    /// Every contributing leg, by (recorded_at, entry, ordinal).
    pub contributions: Vec<Contribution>,
    /// The cell's known-at history, by (recorded_at, unit).
    pub history: Vec<CellChange>,
}

impl BalanceExplanation {
    /// The last recorded sequence that touched the account's cells here.
    #[must_use]
    pub fn last_changed_at(&self) -> Option<CommitSeq> {
        self.history.iter().map(|c| c.recorded_at).max()
    }
}

/// Explain `account`'s cells in `period_code` as known at `known_at` (`None`
/// is the current head; the result records the resolved sequence).
pub fn explain_balance<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    account: VId,
    period_code: &str,
    known_at: Option<CommitSeq>,
) -> Result<BalanceExplanation, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    // The projection first; it also refuses a period unknown at `seq`.
    let fold = fold_period_at(db, book, period_code, Some(seq))?;
    // The account is resolved at the same coordinate: one created later is
    // refused like a period created later, never described with its
    // present-day metadata.
    let account_row = db
        .vertex_at(account, seq)?
        .filter(|r| r.labels.contains(&label::ACCOUNT))
        .map(|r| AccountRow::decode(&r))
        .transpose()?
        .ok_or_else(|| {
            RegisterError::InvalidSelection(format!(
                "unknown account {:032x} at sequence {}",
                account.0, seq.0
            ))
        })?;
    let entries = entries_at(db, book, seq)?;
    let resolved = resolutions(&entries)?;
    let activated = migration_activations(&entries)?;
    let mut contributions = Vec::new();
    for (vid, entry, recorded_at) in &entries {
        if entry.proposal.legs.is_empty() || entry_period(book, entry)? != period_code {
            continue;
        }
        let (column, released_at) = if entry.proposal.class == EntryClass::PENDING {
            match resolved.get(vid) {
                Some(release) => (Column::Released, Some(*release)),
                None => (Column::Pending, None),
            }
        } else {
            (Column::Posted, None)
        };
        for (ordinal, leg) in entry.proposal.legs.iter().enumerate() {
            if leg.account_ref != account {
                continue;
            }
            contributions.push(Contribution {
                entry: *vid,
                entry_digest: entry.entry_digest,
                class: entry.proposal.class,
                effective_date: entry.proposal.effective_date,
                recorded_at: *recorded_at,
                visible_at: contribution_seq(entry, *recorded_at, &activated)?,
                ordinal: u16::try_from(ordinal)
                    .map_err(|_| KernelError::Corrupt("leg ordinal exceeds u16".into()))?,
                side: leg.side,
                unit_id: leg.amount.unit.0,
                mantissa: leg.amount.mantissa,
                column,
                released_at,
                resolves: entry
                    .proposal
                    .pending
                    .as_ref()
                    .and_then(|p| p.resolution_of)
                    .map(|r| r.vid),
                supersedes: entry.proposal.supersession.clone(),
                evidence: entry.proposal.evidence.clone(),
            });
        }
    }
    contributions.sort_by_key(|c| (c.recorded_at, c.entry, c.ordinal));
    let cells: Vec<Cell> = fold
        .cells
        .iter()
        .filter(|c| c.key.account == account)
        .cloned()
        .collect();
    let pending: Vec<Cell> = fold
        .pending
        .iter()
        .filter(|c| c.key.account == account)
        .cloned()
        .collect();
    reconcile(&cells, &contributions, Column::Posted)?;
    reconcile(&pending, &contributions, Column::Pending)?;
    let history = history(&contributions)?;
    Ok(BalanceExplanation {
        account,
        account_row,
        period: period_code.to_string(),
        known_at: seq,
        fold_digest: fold.fold_digest,
        watermark: fold.watermark,
        cells,
        pending,
        contributions,
        history,
    })
}

type Sums = (i128, i128, BTreeSet<VId>);

/// The explanation's proof obligation: the listed legs of `column` re-add,
/// unit by unit, to exactly the fold's cells (sums and entry counts).
fn reconcile(
    cells: &[Cell],
    contributions: &[Contribution],
    column: Column,
) -> Result<(), RegisterError> {
    let mut sums: BTreeMap<u32, Sums> = BTreeMap::new();
    for c in contributions.iter().filter(|c| c.column == column) {
        let s = sums
            .entry(c.unit_id)
            .or_insert_with(|| (0, 0, BTreeSet::new()));
        let slot = match c.side {
            Side::Debit => &mut s.0,
            Side::Credit => &mut s.1,
        };
        *slot = slot
            .checked_add(c.mantissa)
            .ok_or(RegisterError::Overflow)?;
        s.2.insert(c.entry);
    }
    let mut readded = Vec::with_capacity(sums.len());
    for (unit, (debits, credits, entries)) in sums {
        let count = u64::try_from(entries.len()).map_err(|_| RegisterError::Overflow)?;
        readded.push((unit, debits, credits, count));
    }
    let folded: Vec<(u32, i128, i128, u64)> = cells
        .iter()
        .map(|c| (c.key.unit_id, c.debits, c.credits, c.entry_count))
        .collect();
    if readded != folded {
        return Err(KernelError::Corrupt(format!(
            "the {} legs of the explanation do not re-add to the fold's cells: legs {readded:?}, fold {folded:?}",
            column.name()
        ))
        .into());
    }
    Ok(())
}

fn bump(
    deltas: &mut BTreeMap<(CommitSeq, u32), [i128; 4]>,
    at: CommitSeq,
    unit: u32,
    slot: usize,
    amount: i128,
) -> Result<(), RegisterError> {
    let d = deltas.entry((at, unit)).or_insert([0; 4]);
    d[slot] = d[slot].checked_add(amount).ok_or(RegisterError::Overflow)?;
    Ok(())
}

/// Running cell values at every sequence that touched them. A posted leg
/// enters the posted column when visible (a migration chunk only at its
/// Finalize); a reservation enters the pending column when recorded and
/// leaves it when its Resolution is recorded.
fn history(contributions: &[Contribution]) -> Result<Vec<CellChange>, RegisterError> {
    let mut deltas: BTreeMap<(CommitSeq, u32), [i128; 4]> = BTreeMap::new();
    for c in contributions {
        let side = match c.side {
            Side::Debit => 0,
            Side::Credit => 1,
        };
        match c.column {
            Column::Posted => bump(&mut deltas, c.visible_at, c.unit_id, side, c.mantissa)?,
            Column::Pending => bump(&mut deltas, c.recorded_at, c.unit_id, side + 2, c.mantissa)?,
            Column::Released => {
                let at = c.released_at.ok_or_else(|| {
                    KernelError::Corrupt("released reservation without a release".into())
                })?;
                let undo = c.mantissa.checked_neg().ok_or(RegisterError::Overflow)?;
                bump(&mut deltas, c.recorded_at, c.unit_id, side + 2, c.mantissa)?;
                bump(&mut deltas, at, c.unit_id, side + 2, undo)?;
            }
        }
    }
    let mut running: BTreeMap<u32, [i128; 4]> = BTreeMap::new();
    let mut out = Vec::with_capacity(deltas.len());
    for ((at, unit), d) in deltas {
        let r = running.entry(unit).or_insert([0; 4]);
        for (value, delta) in r.iter_mut().zip(d) {
            *value = value.checked_add(delta).ok_or(RegisterError::Overflow)?;
        }
        out.push(CellChange {
            recorded_at: at,
            unit_id: unit,
            debits: r[0],
            credits: r[1],
            debits_pending: r[2],
            credits_pending: r[3],
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CellKey;

    fn leg(entry: u128, at: u64, side: Side, mantissa: i128, column: Column) -> Contribution {
        Contribution {
            entry: VId(entry),
            entry_digest: [0; 32],
            class: if column == Column::Posted {
                EntryClass::ORIGINAL
            } else {
                EntryClass::PENDING
            },
            effective_date: DateDay(0),
            recorded_at: CommitSeq(at),
            visible_at: CommitSeq(at),
            ordinal: 0,
            side,
            unit_id: 1,
            mantissa,
            column,
            released_at: None,
            resolves: None,
            supersedes: Vec::new(),
            evidence: Vec::new(),
        }
    }

    fn cell(debits: i128, credits: i128, entry_count: u64) -> Cell {
        Cell {
            key: CellKey {
                account: VId(9),
                unit_id: 1,
                period: "P".into(),
            },
            debits,
            credits,
            entry_count,
        }
    }

    #[test]
    fn contributions_must_re_add_to_the_fold() {
        let legs = vec![
            leg(1, 5, Side::Debit, 100, Column::Posted),
            leg(2, 6, Side::Credit, 30, Column::Posted),
            leg(3, 7, Side::Debit, 40, Column::Pending),
        ];
        reconcile(&[cell(100, 30, 2)], &legs, Column::Posted).expect("re-adds");
        reconcile(&[cell(40, 0, 1)], &legs, Column::Pending).expect("re-adds");
        // A missing leg, an extra cent, a wrong entry count, and a cell the
        // legs do not explain are each corruption.
        for wrong in [
            vec![cell(100, 0, 1)],
            vec![cell(100, 31, 2)],
            vec![cell(100, 30, 3)],
            Vec::new(),
        ] {
            assert!(
                matches!(
                    reconcile(&wrong, &legs, Column::Posted),
                    Err(RegisterError::Kernel(KernelError::Corrupt(_)))
                ),
                "{wrong:?}"
            );
        }
    }

    #[test]
    fn history_runs_both_columns_and_releases_at_the_resolution() {
        let mut hold = leg(3, 7, Side::Debit, 40, Column::Released);
        hold.released_at = Some(CommitSeq(9));
        let legs = vec![
            leg(1, 5, Side::Debit, 100, Column::Posted),
            leg(2, 6, Side::Credit, 30, Column::Posted),
            hold,
        ];
        let h = history(&legs).unwrap();
        let points: Vec<(u64, i128, i128, i128)> = h
            .iter()
            .map(|c| (c.recorded_at.0, c.debits, c.credits, c.debits_pending))
            .collect();
        assert_eq!(
            points,
            vec![
                (5, 100, 0, 0),
                (6, 100, 30, 0),
                (7, 100, 30, 40),
                (9, 100, 30, 0)
            ]
        );
        let mut orphan = leg(4, 8, Side::Credit, 1, Column::Released);
        orphan.released_at = None;
        assert!(history(&[orphan]).is_err(), "a release needs its sequence");
    }
}
