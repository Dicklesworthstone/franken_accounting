//! Prepublication representability, independent of derived registers.
//!
//! The interim implementation folds the final transaction overlay. Its full
//! vertex scan retains the substrate's insertion/read witnesses, so a prepared
//! writer cannot publish against a changed prefix. No balance is persisted.
//! Each account/unit stock gross column bounds its period, entity and dimension
//! subsets because monetary legs are nonnegative. Cross-account report totals
//! are not registered cells and are deliberately outside this admission law.

use std::collections::{BTreeMap, BTreeSet};

use fa_model::symbols::{label, property};
use fa_model::{Entry, EntryClass, EntryPayload, Id128};
use fa_money::{Side, UnitId};
use fgdb::{Database, WriteTxn, WriteTxnError};
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;

use crate::refusal::{KernelError, Outcome, Refusal, code, exit};

pub(crate) fn accounts<'a>(proposals: impl IntoIterator<Item = &'a EntryPayload>) -> BTreeSet<VId> {
    proposals
        .into_iter()
        .flat_map(|p| p.legs.iter().map(|l| l.account_ref))
        .collect()
}

/// Called only after payload scope/authority admission. Restrict financial
/// evaluation and diagnostics to accounts in the authorized proposed effects;
/// the wider native scan is a conservative internal conflict witness.
pub(crate) fn admit<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    ctx: &PurposeContexts,
    book_id: Id128,
    accounts: &BTreeSet<VId>,
) -> Outcome<()> {
    admit_including(txn, db, ctx, book_id, accounts, None)
}

/// Automatic effects need a verdict before staging, so a blocked schedule
/// can be skipped without leaving any of its financial effects in the batch.
pub(crate) fn admit_addition<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    ctx: &PurposeContexts,
    vid: VId,
    entry: &Entry,
) -> Outcome<()> {
    let accounts = accounts([&entry.proposal]);
    admit_including(
        txn,
        db,
        ctx,
        entry.proposal.book_id,
        &accounts,
        Some((vid, entry)),
    )
}

fn admit_including<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    ctx: &PurposeContexts,
    book_id: Id128,
    accounts: &BTreeSet<VId>,
    extra: Option<(VId, &Entry)>,
) -> Outcome<()> {
    if accounts.is_empty() {
        return Ok(Ok(()));
    }
    let maximum = fa_registry::register_capacity_embedded()
        .map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let base = crate::genesis::read_book_spec_at(db, txn.basis())?
        .ok_or_else(|| KernelError::Corrupt("register capacity requires a book".into()))?
        .base_unit;
    let mut entries = Vec::new();
    let mut resolved = BTreeSet::new();
    let mut runs = BTreeMap::new();
    for row in txn.vertices(db)? {
        ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&crate::rows::bytes(
            &row,
            property::FA_PAYLOAD,
            "entry._fa_payload",
        )?)?;
        if entry.proposal.book_id != book_id || entry.proposal.branch_id != Id128::TRUNK {
            continue;
        }
        if !crate::migration::visible_in(txn, db, &entry, &mut runs)? {
            continue;
        }
        if entry.proposal.class == EntryClass::RESOLUTION {
            let target = entry
                .proposal
                .pending
                .as_ref()
                .and_then(|p| p.resolution_of)
                .ok_or_else(|| KernelError::Corrupt("resolution has no pending target".into()))?;
            resolved.insert(target.vid);
        }
        entries.push((row.vid, entry));
    }
    if let Some((vid, entry)) = extra {
        entries.push((vid, entry.clone()));
    }
    // Resolve first: an old hold may have exceeded a prospective sum yet be
    // released in this same atomic publication, including across periods.
    let mut cells: BTreeMap<(VId, UnitId, bool), [i128; 4]> = BTreeMap::new();
    for (vid, entry) in entries {
        ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
        let pending = entry.proposal.class == EntryClass::PENDING;
        if pending && resolved.contains(&vid) {
            continue;
        }
        for leg in &entry.proposal.legs {
            if !accounts.contains(&leg.account_ref) {
                continue;
            }
            let column = usize::from(pending) * 2 + usize::from(leg.side == Side::Credit);
            let functional = match leg.base_amount {
                Some(amount) if amount.unit == base && amount.mantissa >= 0 => {
                    if leg.amount.unit == base && amount != leg.amount {
                        return Err(KernelError::Corrupt(
                            "base-unit leg has inconsistent functional valuation".into(),
                        ));
                    }
                    Some(amount.mantissa)
                }
                Some(_) => return Err(KernelError::Corrupt("invalid functional valuation".into())),
                None if leg.amount.unit == base => Some(leg.amount.mantissa),
                // Native-only interim paths have no functional projection;
                // absence is not a fabricated zero valuation.
                None => None,
            };
            for (unit, functional, mantissa) in
                std::iter::once((leg.amount.unit, false, leg.amount.mantissa))
                    .chain(functional.map(|m| (base, true, m)))
            {
                let cell = cells
                    .entry((leg.account_ref, unit, functional))
                    .or_default();
                let next = cell[column].checked_add(mantissa);
                if mantissa < 0 {
                    return Err(KernelError::Corrupt("negative register leg".into()));
                }
                let Some(next) = next.filter(|v| *v <= maximum) else {
                    return Ok(Err(Refusal::new(
                        code::REGISTER_CAPACITY,
                        exit::REFUSAL,
                        format!(
                            "account {:032x}, unit {}, {} stock {} exceeds max_register_mantissa {} at transaction prefix {}; nothing was published",
                            leg.account_ref.0,
                            unit.0,
                            if functional { "functional" } else { "native" },
                            [
                                "posted debit",
                                "posted credit",
                                "pending debit",
                                "pending credit"
                            ][column],
                            maximum,
                            txn.basis().0
                        ),
                        "plan §5.2; limits.toml register_capacity",
                        "reduce the proposed gross activity; a reversal increases gross activity, so preserve any historical over-cap prefix for diagnosis rather than attempting a corrective reversal",
                    )));
                };
                cell[column] = next;
            }
        }
    }
    Ok(Ok(()))
}
