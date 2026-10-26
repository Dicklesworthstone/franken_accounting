//! Literal functional-currency trial balances with replayable display metadata.
//!
//! The fold uses the book's committed base valuations and preserves its entity
//! coordinates, pending column, exact gross amounts, source digest and watermark.
//! Certification additionally replays the original Rate evidence and FX laws;
//! reading an uncertified result retains the existing functional-read contract.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Refusal, code, exit};
use fa_journal::rows::{AccountRow, PeriodRow};
use fa_journal::{LimitScope, UnitPolicy};
use fa_model::symbols::label;
use fa_model::{Writer, period_vid};
use fa_money::UnitId;
use fa_registers::{FunctionalCell, FunctionalStockCell, RegisterError};
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::{CommitSeq, VId};

use crate::{BookError, Outcome, TrialBalanceSelection};

/// One exact functional cell, preserving the legal entity discriminator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionalTrialBalanceCell {
    pub account: VId,
    pub unit_id: u32,
    pub entity: Option<String>,
    pub debits: i128,
    pub credits: i128,
    pub entry_count: u64,
}

impl FunctionalTrialBalanceCell {
    #[must_use]
    pub fn net(&self) -> Option<i128> {
        self.debits.checked_sub(self.credits)
    }
}

impl From<FunctionalCell> for FunctionalTrialBalanceCell {
    fn from(cell: FunctionalCell) -> Self {
        Self {
            account: cell.key.account,
            unit_id: cell.key.unit_id,
            entity: cell.key.entity,
            debits: cell.debits,
            credits: cell.credits,
            entry_count: cell.entry_count,
        }
    }
}

impl From<FunctionalStockCell> for FunctionalTrialBalanceCell {
    fn from(cell: FunctionalStockCell) -> Self {
        Self {
            account: cell.key.account,
            unit_id: cell.key.unit_id,
            entity: cell.key.entity,
            debits: cell.debits,
            credits: cell.credits,
            entry_count: cell.entry_count,
        }
    }
}

/// Functional stock through one period or date, or one period's activity.
/// All account metadata comes from the selected prefix; replay needs no current
/// chart lookup to recover the original display. Empty reports remain explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionalTrialBalance {
    pub selection: TrialBalanceSelection,
    /// Inclusive stock cutoff. Activity has no stock cutoff.
    pub effective_through: Option<DateDay>,
    pub base_unit: UnitId,
    pub known_at: CommitSeq,
    pub cells: Vec<FunctionalTrialBalanceCell>,
    pub pending: Vec<FunctionalTrialBalanceCell>,
    pub watermark: Option<CommitSeq>,
    pub entries: u64,
    pub fold_digest: [u8; 32],
    /// Exactly the accounts named by posted or pending cells, keyed by identity.
    pub accounts: BTreeMap<VId, AccountRow>,
}

impl FunctionalTrialBalance {
    pub fn total_debits(&self) -> Result<i128, RegisterError> {
        self.cells.iter().try_fold(0i128, |sum, cell| {
            sum.checked_add(cell.debits).ok_or(RegisterError::Overflow)
        })
    }

    pub fn total_credits(&self) -> Result<i128, RegisterError> {
        self.cells.iter().try_fold(0i128, |sum, cell| {
            sum.checked_add(cell.credits).ok_or(RegisterError::Overflow)
        })
    }

    /// Dedicated v1 output: original selector, resolved stock cutoff, exact
    /// fold coordinates and every displayed cell and historical account field.
    /// Native-unit trial balance and functional statement bytes stay unchanged.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(crate::FUNCTIONAL_TRIAL_BALANCE_OUTPUT_FORMAT.as_bytes())
            .str("retained-base-amounts");
        self.selection.write(&mut w);
        w.opt(self.effective_through.as_ref(), |w, day| {
            w.i32(day.0);
        })
        .u32(self.base_unit.0)
        .u64(self.known_at.0)
        .opt(self.watermark.as_ref(), |w, at| {
            w.u64(at.0);
        })
        .u64(self.entries)
        .fixed(&self.fold_digest);
        for column in [&self.cells, &self.pending] {
            w.list(column, |w, cell| {
                w.u128(cell.account.0)
                    .u32(cell.unit_id)
                    .opt(cell.entity.as_ref(), |w, entity| {
                        w.str(entity);
                    })
                    .i128(cell.debits)
                    .i128(cell.credits)
                    .u64(cell.entry_count);
            });
        }
        let accounts: Vec<_> = self.accounts.iter().collect();
        w.list(&accounts, |w, (vid, row)| {
            w.u128(vid.0)
                .u128(row.vid.0)
                .str(&row.code)
                .str(&row.name)
                .u8(row.account_type)
                .u8(row.normal_balance)
                .bool(row.is_leaf);
            match row.unit_policy {
                UnitPolicy::Single(unit) => {
                    w.u8(0).u32(unit.0);
                }
                UnitPolicy::AnyCurrency => {
                    w.u8(1);
                }
                UnitPolicy::AnyUnit => {
                    w.u8(2);
                }
            }
            w.opt(row.limit.as_ref(), |w, limit| {
                w.opt(limit.lower.as_ref(), |w, amount| {
                    w.i128(*amount);
                })
                .opt(limit.upper.as_ref(), |w, amount| {
                    w.i128(*amount);
                })
                .u8(match limit.scope {
                    LimitScope::Lifetime => 0,
                    LimitScope::Period => 1,
                });
            })
            .u64(row.created_at.0);
        });
        w.finish()
    }
}

pub(crate) fn supported_selection(selection: &TrialBalanceSelection) -> bool {
    match selection {
        TrialBalanceSelection::Periods(periods) | TrialBalanceSelection::Activity(periods) => {
            periods.len() == 1 && !periods[0].is_empty() && periods[0].len() <= 128
        }
        TrialBalanceSelection::AsOf(_) => true,
    }
}

pub(crate) fn invalid_selection() -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        "functional trial balance selects one period for stock or activity, or one stock date",
        "plan §5.3 / §13.6 (one fixed functional report scope)",
        "select one --period, one --as-of date, or --activity with one --period",
    )
}

pub(crate) fn report_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    selection: &TrialBalanceSelection,
    at: CommitSeq,
) -> Outcome<FunctionalTrialBalance> {
    if !supported_selection(selection) {
        return Ok(Err(invalid_selection()));
    }
    // Preserve the public functional read's checked chart contract: journaled
    // declarations and lifecycle controls authenticate every historical mirror.
    // A forged display name, code or account type must never become certified
    // merely because the entry-derived functional amounts still balance.
    let chart = fa_journal::chart::read_at(db, book, at)?;
    let mut report = match selection {
        TrialBalanceSelection::Activity(periods) => {
            let fold = fa_registers::fold_period_functional(db, book, &periods[0], Some(at))?;
            FunctionalTrialBalance {
                selection: selection.clone(),
                effective_through: None,
                base_unit: fold.base_unit,
                known_at: fold.known_at,
                cells: fold.cells.into_iter().map(Into::into).collect(),
                pending: fold.pending.into_iter().map(Into::into).collect(),
                watermark: fold.watermark,
                entries: fold.entries,
                fold_digest: fold.fold_digest,
                accounts: BTreeMap::new(),
            }
        }
        TrialBalanceSelection::AsOf(_) | TrialBalanceSelection::Periods(_) => {
            let through = match selection {
                TrialBalanceSelection::AsOf(day) => *day,
                TrialBalanceSelection::Periods(periods) => {
                    // A period's mirrored end date cannot choose the accounting
                    // cutoff until its journaled historical definition verifies.
                    let verified = fa_journal::period::verify_periods(db, book, Some(at))?;
                    if !verified.is_green() {
                        return Ok(Err(Refusal::new(
                            crate::certificate::code::CERTIFICATE_INVALID,
                            exit::VERIFICATION,
                            format!(
                                "functional stock period history has drifted: {}",
                                verified.drift.join("; ")
                            ),
                            "FA-INV-02 (period dates and state derive from the journal)",
                            "inspect fa verify periods at the same known-at prefix; preserve native history",
                        )));
                    }
                    let code = &periods[0];
                    let row = db
                        .vertex_at(period_vid(&book.calendar.id, code), at)
                        .map_err(fa_journal::KernelError::from)?
                        .filter(|row| row.labels.contains(&label::PERIOD))
                        .ok_or_else(|| {
                            RegisterError::InvalidSelection(format!(
                                "unknown period {code} at sequence {}",
                                at.0
                            ))
                        })?;
                    let period = PeriodRow::decode(&row)?;
                    if period.calendar_id != book.calendar.id || period.end <= period.start {
                        return Err(fa_journal::KernelError::Corrupt(
                            "functional stock period has a different calendar or invalid bounds"
                                .into(),
                        )
                        .into());
                    }
                    period.end.pred().map_err(fa_journal::KernelError::from)?
                }
                TrialBalanceSelection::Activity(_) => unreachable!("activity handled above"),
            };
            let fold = fa_registers::fold_functional_stock(db, book, through, Some(at))?;
            FunctionalTrialBalance {
                selection: selection.clone(),
                effective_through: Some(through),
                base_unit: fold.base_unit,
                known_at: fold.known_at,
                cells: fold.cells.into_iter().map(Into::into).collect(),
                pending: fold.pending.into_iter().map(Into::into).collect(),
                watermark: fold.watermark,
                entries: fold.entries,
                fold_digest: fold.fold_digest,
                accounts: BTreeMap::new(),
            }
        }
    };
    for cell in report.cells.iter().chain(&report.pending) {
        if report.accounts.contains_key(&cell.account) {
            continue;
        }
        let account = chart.accounts().get(&cell.account).ok_or_else(|| {
            RegisterError::ProjectionDrift(format!(
                "functional trial-balance account {:032x} is absent at {}",
                cell.account.0, at.0
            ))
        })?;
        report.accounts.insert(cell.account, account.clone());
    }
    Ok(Ok(report))
}
