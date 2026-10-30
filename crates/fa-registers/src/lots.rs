//! Cost-basis lots and relief planning over the open-item fold (plan §6.5, `fa-2ly`).
//!
//! A `Lot` is not a second vertex label or a separate mutable subledger table:
//! it is an open-item pair `(quantity leg, cost leg)` on an `AnyUnit` account
//! (such as `1400 Inventory` or `1200 Securities`), where the acquiring entry
//! posts the non-base quantity in `U != book.base_unit` and the acquisition cost
//! in `book.base_unit` on the same side.
//!
//! Disposals relieve both the quantity leg and the cost leg via `leg.settles`,
//! which produces `RELIEVES {quantity, cost}` edges in the lot projection and
//! moves both `Leg.applied` mirrors atomically under the kernel's CAS check
//! (`fa-omi`). Reversing a disposal entry emits `UNSETTLES` (`live = false` on
//! the application) and restores both `open_quantity` and `open_cost`.

use std::collections::{BTreeMap, VecDeque};

use fa_journal::UnitPolicy;
use fa_journal::genesis::BookContext;
use fa_journal::rows::AccountRow;
use fa_model::symbols::label;
use fa_model::{EntryRef, Id128, Settlement};
use fa_money::{
    AccountingRegime, Amount, LotCandidate, LotError, LotLaw, RoundingLaw, Side, UnitId,
    relieve_lots,
};
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::{CommitSeq, VId};

use crate::open_items::OpenItem;
use crate::open_items::history::open_items_as_of;
use crate::{RegisterError, entries_at, open_items, resolve_known_at};

/// One disposal application against a lot (`RELIEVES {quantity, cost}`).
/// When `live` is `false`, a reversal (`UNSETTLES`) undid this relief and
/// restored the lot's open quantity and open cost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotReliefEdge {
    pub disposal_entry: VId,
    /// Applying quantity leg, absent for a weighted-average cost-only slice.
    pub qty_ordinal: Option<u16>,
    pub cost_ordinal: Option<u16>,
    pub quantity: Amount,
    pub cost: Amount,
    pub recorded_at: CommitSeq,
    pub live: bool,
}

/// One cost-basis lot on an `AnyUnit` account, folded from the open-item history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotItem {
    pub entry: VId,
    pub entry_digest: [u8; 32],
    pub qty_ordinal: u16,
    pub cost_ordinal: u16,
    pub account: VId,
    pub side: Side,
    pub effective_date: DateDay,
    pub recorded_at: CommitSeq,
    pub original_quantity: Amount,
    pub relieved_quantity: Amount,
    pub open_quantity: Amount,
    pub original_cost: Amount,
    pub relieved_cost: Amount,
    pub open_cost: Amount,
    pub relieves: Vec<LotReliefEdge>,
}

/// Complete lot schedule for an `AnyUnit` account at `(known_at, effective_through)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotsReport {
    pub book_id: Id128,
    pub known_at: CommitSeq,
    pub effective_through: Option<DateDay>,
    pub account: VId,
    pub account_code: String,
    pub account_name: String,
    pub base_unit: UnitId,
    pub lots: Vec<LotItem>,
}

/// Request to plan a lot disposal under a registered `LotLaw`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotDisposalRequest {
    pub quantity: Amount,
    pub law: LotLaw,
    pub regime: AccountingRegime,
    pub rounding_law: RoundingLaw,
    pub targets: Vec<(VId, u16)>,
}

/// One lot slice relieved by a planned disposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotDisposalSlice {
    pub entry: VId,
    pub entry_digest: [u8; 32],
    pub qty_ordinal: u16,
    pub cost_ordinal: u16,
    pub effective_date: DateDay,
    pub recorded_at: CommitSeq,
    pub quantity_relieved: Amount,
    pub cost_relieved: Amount,
    pub open_quantity_before: Amount,
    pub open_quantity_after: Amount,
    pub open_cost_before: Amount,
    pub open_cost_after: Amount,
}

/// Deterministic dry-run lot relief plan with ready-to-post `Settlement` vectors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotDisposalPlan {
    pub known_at: CommitSeq,
    pub effective_through: Option<DateDay>,
    pub account: VId,
    pub law: LotLaw,
    pub regime: AccountingRegime,
    pub rounding_law: RoundingLaw,
    pub total_quantity: Amount,
    pub total_cost: Amount,
    pub wac_residual_numerator: i128,
    pub slices: Vec<LotDisposalSlice>,
}

impl LotDisposalPlan {
    /// `Settlement` targets for the disposal entry's quantity leg on `account`.
    #[must_use]
    pub fn quantity_settlements(&self) -> Vec<Settlement> {
        self.slices
            .iter()
            .filter(|s| s.quantity_relieved.mantissa > 0)
            .map(|s| Settlement {
                target: EntryRef {
                    vid: s.entry,
                    entry_digest: s.entry_digest,
                },
                ordinal: s.qty_ordinal,
                amount: s.quantity_relieved,
            })
            .collect()
    }

    /// `Settlement` targets for the disposal entry's cost leg on `account`.
    #[must_use]
    pub fn cost_settlements(&self) -> Vec<Settlement> {
        self.slices
            .iter()
            .filter(|s| s.cost_relieved.mantissa > 0)
            .map(|s| Settlement {
                target: EntryRef {
                    vid: s.entry,
                    entry_digest: s.entry_digest,
                },
                ordinal: s.cost_ordinal,
                amount: s.cost_relieved,
            })
            .collect()
    }
}

impl LotsReport {
    /// Open lots (`open_quantity > 0`) in `unit`, ordered by `(effective_date, recorded_at, entry, qty_ordinal)`.
    #[must_use]
    pub fn open_lots(&self, unit: UnitId) -> Vec<&LotItem> {
        self.lots
            .iter()
            .filter(|lot| lot.original_quantity.unit == unit && lot.open_quantity.mantissa > 0)
            .collect()
    }

    /// Plan a disposal of `request.quantity` against the open lots of this report.
    pub fn plan_disposal(&self, request: &LotDisposalRequest) -> Result<LotDisposalPlan, LotError> {
        let qty_unit = request.quantity.unit;
        let candidates: Vec<LotCandidate> = self
            .lots
            .iter()
            .filter(|lot| {
                lot.original_quantity.unit == qty_unit
                    && (lot.open_quantity.mantissa > 0 || lot.open_cost.mantissa > 0)
            })
            .map(|lot| LotCandidate {
                entry_id: lot.entry.0,
                qty_ordinal: lot.qty_ordinal,
                cost_ordinal: lot.cost_ordinal,
                effective_day: lot.effective_date.0,
                recorded_seq: lot.recorded_at.0,
                open_quantity: lot.open_quantity.mantissa,
                open_cost: lot.open_cost.mantissa,
            })
            .collect();
        let target_ids: Vec<(u128, u16)> = request
            .targets
            .iter()
            .map(|(vid, ord)| (vid.0, *ord))
            .collect();
        let explicit_targets = if target_ids.is_empty() {
            None
        } else {
            Some(target_ids.as_slice())
        };
        let outcome = relieve_lots(
            &candidates,
            request.quantity.mantissa,
            request.law,
            request.regime,
            request.rounding_law,
            explicit_targets,
        )?;
        let by_id: BTreeMap<(u128, u16), &LotItem> = self
            .lots
            .iter()
            .map(|lot| ((lot.entry.0, lot.qty_ordinal), lot))
            .collect();
        let mut slices = Vec::with_capacity(outcome.slices.len());
        for slice in outcome.slices {
            let lot = by_id
                .get(&(slice.entry_id, slice.qty_ordinal))
                .copied()
                .ok_or(LotError::UnknownTarget {
                    entry_id: slice.entry_id,
                    qty_ordinal: slice.qty_ordinal,
                })?;
            slices.push(LotDisposalSlice {
                entry: lot.entry,
                entry_digest: lot.entry_digest,
                qty_ordinal: lot.qty_ordinal,
                cost_ordinal: lot.cost_ordinal,
                effective_date: lot.effective_date,
                recorded_at: lot.recorded_at,
                quantity_relieved: Amount::new(qty_unit, slice.relieved_quantity),
                cost_relieved: Amount::new(self.base_unit, slice.relieved_cost),
                open_quantity_before: Amount::new(qty_unit, slice.open_quantity_before),
                open_quantity_after: Amount::new(qty_unit, slice.open_quantity_after),
                open_cost_before: Amount::new(self.base_unit, slice.open_cost_before),
                open_cost_after: Amount::new(self.base_unit, slice.open_cost_after),
            });
        }
        Ok(LotDisposalPlan {
            known_at: self.known_at,
            effective_through: self.effective_through,
            account: self.account,
            law: outcome.law,
            regime: outcome.regime,
            rounding_law: outcome.rounding_law,
            total_quantity: Amount::new(qty_unit, outcome.requested_quantity),
            total_cost: Amount::new(self.base_unit, outcome.total_relieved_cost),
            wac_residual_numerator: outcome.wac_residual_numerator,
            slices,
        })
    }
}

/// Fold the cost-basis lots and `RELIEVES {quantity, cost}` edges for `account`.
pub fn lots<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    account: VId,
    effective_through: Option<DateDay>,
    known_at: Option<CommitSeq>,
) -> Result<LotsReport, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    let row = db
        .vertex_at(account, seq)?
        .filter(|r| r.labels.contains(&label::ACCOUNT))
        .ok_or_else(|| {
            RegisterError::InvalidSelection(format!(
                "unknown account {:032x} at sequence {}",
                account.0, seq.0
            ))
        })?;
    let account_row = AccountRow::decode(&row)?;
    if account_row.unit_policy != UnitPolicy::AnyUnit {
        return Err(RegisterError::InvalidSelection(format!(
            "account `{}` ({}) is not an AnyUnit lot account",
            account_row.code, account_row.name
        )));
    }
    let base_unit = fa_journal::genesis::read_book_spec(db)?
        .ok_or_else(|| fa_journal::KernelError::Corrupt("missing book root".into()))?
        .base_unit;
    let items = match effective_through {
        Some(day) => open_items_as_of(db, book, Some(account), day, Some(seq))?.items,
        None => open_items(db, book, Some(account), Some(seq))?,
    };
    let entries = entries_at(db, book, seq)?;
    let digests: BTreeMap<VId, [u8; 32]> = entries
        .into_iter()
        .map(|(vid, entry, _)| (vid, entry.entry_digest))
        .collect();
    let lots = fold_lots_from_open_items(&items, &digests, base_unit)?;
    Ok(LotsReport {
        book_id: book.book_id,
        known_at: seq,
        effective_through,
        account,
        account_code: account_row.code,
        account_name: account_row.name,
        base_unit,
        lots,
    })
}

/// Pure fold of `LotItem`s from open-item legs on an `AnyUnit` account.
pub fn fold_lots_from_open_items(
    items: &[OpenItem],
    entry_digests: &BTreeMap<VId, [u8; 32]>,
    base_unit: UnitId,
) -> Result<Vec<LotItem>, RegisterError> {
    let mut by_entry: BTreeMap<VId, Vec<&OpenItem>> = BTreeMap::new();
    for item in items {
        // Acquiring legs do not settle prior legs (`applied_out == 0`).
        if item.applied_out == 0 {
            by_entry.entry(item.entry).or_default().push(item);
        }
    }

    let mut lots = Vec::new();
    for (entry_vid, mut legs) in by_entry {
        legs.sort_by_key(|l| l.ordinal);
        let qty_legs: Vec<&OpenItem> = legs
            .iter()
            .copied()
            .filter(|l| l.unit_id != base_unit.0)
            .collect();
        if qty_legs.is_empty() {
            continue;
        }
        let cost_legs: Vec<&OpenItem> = legs
            .iter()
            .copied()
            .filter(|l| l.unit_id == base_unit.0)
            .collect();
        if qty_legs.len() != cost_legs.len() {
            return Err(RegisterError::InvalidSelection(format!(
                "entry {:032x} has {} non-base quantity leg(s) and {} base-unit cost leg(s) on the lot account; each acquiring quantity leg requires a paired base-unit cost leg",
                entry_vid.0,
                qty_legs.len(),
                cost_legs.len()
            )));
        }
        let entry_digest = entry_digests.get(&entry_vid).copied().unwrap_or([0u8; 32]);
        for (qty_leg, cost_leg) in qty_legs.into_iter().zip(cost_legs) {
            if qty_leg.side != cost_leg.side {
                return Err(RegisterError::InvalidSelection(format!(
                    "entry {:032x} quantity leg {} ({:?}) and cost leg {} ({:?}) have opposite sides",
                    entry_vid.0, qty_leg.ordinal, qty_leg.side, cost_leg.ordinal, cost_leg.side
                )));
            }
            let qty_unit = UnitId(qty_leg.unit_id);
            let mut cost_apps_by_entry: BTreeMap<(VId, CommitSeq, bool), VecDeque<(u16, i128)>> =
                BTreeMap::new();
            for app in &cost_leg.applications {
                cost_apps_by_entry
                    .entry((app.entry, app.recorded_at, app.live))
                    .or_default()
                    .push_back((app.ordinal, app.amount));
            }
            let mut relieves = Vec::with_capacity(qty_leg.applications.len());
            for app in &qty_leg.applications {
                let cost_match = cost_apps_by_entry
                    .get_mut(&(app.entry, app.recorded_at, app.live))
                    .and_then(VecDeque::pop_front);
                let (cost_ordinal, cost_mantissa) = match cost_match {
                    Some((ord, amt)) => (Some(ord), amt),
                    None => (None, 0),
                };
                relieves.push(LotReliefEdge {
                    disposal_entry: app.entry,
                    qty_ordinal: Some(app.ordinal),
                    cost_ordinal,
                    quantity: Amount::new(qty_unit, app.amount),
                    cost: Amount::new(base_unit, cost_mantissa),
                    recorded_at: app.recorded_at,
                    live: app.live,
                });
            }
            // A pooled-cost relief can consume cost from a different layer
            // than the quantity, including one whose quantity is exhausted.
            // Preserve those applications in the lot's provenance instead of
            // silently dropping them because no quantity application matches.
            for ((disposal_entry, recorded_at, live), cost_apps) in cost_apps_by_entry {
                for (cost_ordinal, cost_mantissa) in cost_apps {
                    relieves.push(LotReliefEdge {
                        disposal_entry,
                        qty_ordinal: None,
                        cost_ordinal: Some(cost_ordinal),
                        quantity: Amount::new(qty_unit, 0),
                        cost: Amount::new(base_unit, cost_mantissa),
                        recorded_at,
                        live,
                    });
                }
            }
            relieves.sort_by_key(|relief| {
                (
                    relief.recorded_at,
                    relief.disposal_entry,
                    relief.qty_ordinal,
                    relief.cost_ordinal,
                )
            });
            lots.push(LotItem {
                entry: entry_vid,
                entry_digest,
                qty_ordinal: qty_leg.ordinal,
                cost_ordinal: cost_leg.ordinal,
                account: qty_leg.account,
                side: qty_leg.side,
                effective_date: qty_leg.effective_date,
                recorded_at: qty_leg.recorded_at,
                original_quantity: Amount::new(qty_unit, qty_leg.original),
                relieved_quantity: Amount::new(qty_unit, qty_leg.applied),
                open_quantity: Amount::new(qty_unit, qty_leg.open),
                original_cost: Amount::new(base_unit, cost_leg.original),
                relieved_cost: Amount::new(base_unit, cost_leg.applied),
                open_cost: Amount::new(base_unit, cost_leg.open),
                relieves,
            });
        }
    }
    lots.sort_by_key(|lot| {
        (
            lot.effective_date.0,
            lot.recorded_at,
            lot.entry,
            lot.qty_ordinal,
        )
    });
    Ok(lots)
}

#[cfg(test)]
mod tests;
