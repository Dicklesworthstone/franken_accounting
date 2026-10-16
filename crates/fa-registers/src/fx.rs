//! Functional-currency register fold (plan §5.2, §5.3; bead `fa-s3c`;
//! `FA-INV-04.functional-fold`).
//!
//! A functional-value register cell `(account, base_unit, period, legal_entity)`
//! is a deterministic fold over the committed entry payloads of a period in
//! the book's `base_unit`. Every leg in `base_unit` contributes its native
//! amount at par (`1:1`), and every foreign-currency leg contributes its
//! verified `leg.base_amount` computed under the entry's registered FX law.
//! An unvalued foreign-currency leg in a functional fold is refused as
//! projection drift.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::KernelError;
use fa_journal::entity::leg_entity;
use fa_journal::genesis::{BookContext, BookSpec, read_book_spec};
use fa_model::{Entry, EntryClass, LegPayload, Writer};
use fa_money::{Side, UnitId};
use fgdb::Database;
use fgdb_crypto::Hasher;
use fgdb_types::{CommitSeq, VId};

use crate::{
    RegisterError, contribution_seq, entries_at, entry_period, migration_activations, period_at,
    resolutions, resolve_known_at,
};

/// Domain separator for functional-value register fold digests (`FA-INV-04.functional-fold`).
pub const FUNCTIONAL_FOLD_DIGEST_DOMAIN: &[u8] = b"fa:register-functional-fold:v1";

/// Key of a functional-currency register cell: `(account, base_unit, period, entity)`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FunctionalCellKey {
    pub account: VId,
    pub unit_id: u32,
    pub period: String,
    pub entity: Option<String>,
}

/// One functional-currency register cell in the book's `base_unit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionalCell {
    pub key: FunctionalCellKey,
    pub debits: i128,
    pub credits: i128,
    pub entry_count: u64,
}

impl FunctionalCell {
    /// Checked debits minus credits in `base_unit`.
    #[must_use]
    pub fn net(&self) -> Option<i128> {
        self.debits.checked_sub(self.credits)
    }
}

/// Deterministic functional-currency fold of one period at `known_at`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionalFold {
    pub period: String,
    pub base_unit: UnitId,
    pub known_at: CommitSeq,
    pub cells: Vec<FunctionalCell>,
    pub pending: Vec<FunctionalCell>,
    pub watermark: Option<CommitSeq>,
    pub entries: u64,
    pub fold_digest: [u8; 32],
}

impl FunctionalFold {
    /// Look up the posted functional cell at `key`.
    #[must_use]
    pub fn cell(&self, key: &FunctionalCellKey) -> Option<&FunctionalCell> {
        self.cells.iter().find(|c| c.key == *key)
    }

    /// Total functional debits across all posted cells in this period.
    pub fn total_debits(&self) -> Result<i128, RegisterError> {
        let mut sum = 0i128;
        for cell in &self.cells {
            sum = sum
                .checked_add(cell.debits)
                .ok_or(RegisterError::Overflow)?;
        }
        Ok(sum)
    }

    /// Total functional credits across all posted cells in this period.
    pub fn total_credits(&self) -> Result<i128, RegisterError> {
        let mut sum = 0i128;
        for cell in &self.cells {
            sum = sum
                .checked_add(cell.credits)
                .ok_or(RegisterError::Overflow)?;
        }
        Ok(sum)
    }
}

fn entity_of(spec: &BookSpec, leg: &LegPayload) -> Option<String> {
    leg_entity(spec, leg).or_else(|| match spec.entities.as_slice() {
        [only] => Some(only.code.clone()),
        _ => None,
    })
}

fn functional_mantissa(
    spec: &BookSpec,
    entry_vid: VId,
    ordinal: usize,
    leg: &LegPayload,
) -> Result<i128, RegisterError> {
    match leg.base_amount {
        Some(base) => {
            if base.unit != spec.base_unit || base.mantissa <= 0 {
                return Err(RegisterError::ProjectionDrift(format!(
                    "entry {:032x} leg {ordinal} has base_amount in unit {} (mantissa {}), expected positive base_unit {}",
                    entry_vid.0, base.unit.0, base.mantissa, spec.base_unit.0
                )));
            }
            if leg.amount.unit == spec.base_unit && base != leg.amount {
                return Err(RegisterError::ProjectionDrift(format!(
                    "entry {:032x} leg {ordinal} is in base_unit {} but base_amount {} != native amount {}",
                    entry_vid.0, spec.base_unit.0, base.mantissa, leg.amount.mantissa
                )));
            }
            Ok(base.mantissa)
        }
        None => {
            if leg.amount.unit == spec.base_unit {
                Ok(leg.amount.mantissa)
            } else {
                Err(RegisterError::ProjectionDrift(format!(
                    "entry {:032x} leg {ordinal} is in foreign unit {} without a functional base_amount",
                    entry_vid.0, leg.amount.unit.0
                )))
            }
        }
    }
}

fn add_functional_entry(
    cells: &mut BTreeMap<FunctionalCellKey, FunctionalCell>,
    spec: &BookSpec,
    entry_vid: VId,
    entry: &Entry,
    period: &str,
) -> Result<(), RegisterError> {
    let mut touched = BTreeSet::new();
    let mut by_entity: BTreeMap<Option<String>, (i128, i128)> = BTreeMap::new();
    for (ordinal, leg) in entry.proposal.legs.iter().enumerate() {
        let mantissa = functional_mantissa(spec, entry_vid, ordinal, leg)?;
        let entity = entity_of(spec, leg);
        let key = FunctionalCellKey {
            account: leg.account_ref,
            unit_id: spec.base_unit.0,
            period: period.into(),
            entity: entity.clone(),
        };
        let cell = cells.entry(key.clone()).or_insert_with(|| FunctionalCell {
            key: key.clone(),
            debits: 0,
            credits: 0,
            entry_count: 0,
        });
        let entity_slot = by_entity.entry(entity).or_insert((0, 0));
        match leg.side {
            Side::Debit => {
                cell.debits = cell
                    .debits
                    .checked_add(mantissa)
                    .ok_or(RegisterError::Overflow)?;
                entity_slot.0 = entity_slot
                    .0
                    .checked_add(mantissa)
                    .ok_or(RegisterError::Overflow)?;
            }
            Side::Credit => {
                cell.credits = cell
                    .credits
                    .checked_add(mantissa)
                    .ok_or(RegisterError::Overflow)?;
                entity_slot.1 = entity_slot
                    .1
                    .checked_add(mantissa)
                    .ok_or(RegisterError::Overflow)?;
            }
        }
        touched.insert(key);
    }
    for (entity, (debits, credits)) in by_entity {
        if debits != credits {
            let label = entity.as_deref().unwrap_or("<default>");
            return Err(RegisterError::ProjectionDrift(format!(
                "entry {:032x} functional base amounts do not balance in entity `{label}`: debits {debits} != credits {credits}",
                entry_vid.0
            )));
        }
    }
    for key in touched {
        let cell = cells
            .get_mut(&key)
            .ok_or_else(|| KernelError::Corrupt("missing functional fold cell".into()))?;
        cell.entry_count = cell
            .entry_count
            .checked_add(1)
            .ok_or(RegisterError::Overflow)?;
    }
    Ok(())
}

fn fold_functional_leg_contribution(
    prev: [u8; 32],
    (commit_seq, entry, ordinal): (CommitSeq, VId, u16),
    account: VId,
    base_unit_id: u32,
    entity: Option<&String>,
    side: Side,
    base_mantissa: i128,
) -> Result<[u8; 32], RegisterError> {
    let mut w = Writer::new();
    w.fixed(&prev)
        .u64(commit_seq.0)
        .u128(entry.0)
        .u16(ordinal)
        .u128(account.0)
        .u32(base_unit_id)
        .opt(entity, |w, e| {
            w.str(e);
        })
        .u8(match side {
            Side::Debit => 0,
            Side::Credit => 1,
        })
        .i128(base_mantissa);
    let mut h = Hasher::new();
    h.update(b"fa:register-functional-leg-contribution:v1");
    h.update(&w.finish().map_err(RegisterError::Encoding)?);
    Ok(h.finalize().0)
}

fn fold_functional_entry_contributions(
    mut acc: [u8; 32],
    spec: &BookSpec,
    commit_seq: CommitSeq,
    entry_vid: VId,
    entry: &Entry,
) -> Result<[u8; 32], RegisterError> {
    for (ordinal, leg) in entry.proposal.legs.iter().enumerate() {
        let ord_u16 = u16::try_from(ordinal)
            .map_err(|_| KernelError::Corrupt("leg ordinal exceeds u16".into()))?;
        let mantissa = functional_mantissa(spec, entry_vid, ordinal, leg)?;
        let entity = entity_of(spec, leg);
        acc = fold_functional_leg_contribution(
            acc,
            (commit_seq, entry_vid, ord_u16),
            leg.account_ref,
            spec.base_unit.0,
            entity.as_ref(),
            leg.side,
            mantissa,
        )?;
    }
    Ok(acc)
}

fn digest_of(
    period: &str,
    base_unit: UnitId,
    cells: &[FunctionalCell],
    pending: &[FunctionalCell],
    watermark: Option<CommitSeq>,
    posted_legs_digest: [u8; 32],
    pending_holds: &BTreeMap<(CommitSeq, VId), [u8; 32]>,
) -> Result<[u8; 32], RegisterError> {
    let mut w = Writer::new();
    w.str(period)
        .u32(base_unit.0)
        .opt(watermark.as_ref(), |w, s| {
            w.u64(s.0);
        })
        .fixed(&posted_legs_digest);
    let holds: Vec<_> = pending_holds.iter().collect();
    w.list(&holds, |w, ((seq, vid), digest)| {
        w.u64(seq.0).u128(vid.0).fixed(*digest);
    });
    for column in [cells, pending] {
        w.list(column, |w, c| {
            w.u128(c.key.account.0)
                .u32(c.key.unit_id)
                .str(&c.key.period)
                .opt(c.key.entity.as_ref(), |w, e| {
                    w.str(e);
                })
                .i128(c.debits)
                .i128(c.credits)
                .u64(c.entry_count);
        });
    }
    let mut h = Hasher::new();
    h.update(FUNCTIONAL_FOLD_DIGEST_DOMAIN);
    h.update(&w.finish().map_err(RegisterError::Encoding)?);
    Ok(h.finalize().0)
}

/// Fold functional-currency (`base_unit`) register cells for `period_code` at
/// `known_at` (head when `None`) (`FA-INV-04.functional-fold`).
pub fn fold_period_functional<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
    known_at: Option<CommitSeq>,
) -> Result<FunctionalFold, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    period_at(db, book, period_code, seq)?;
    let spec = read_book_spec(db)?
        .ok_or_else(|| KernelError::Corrupt("no book spec on the root".into()))?;
    let mut cells: BTreeMap<FunctionalCellKey, FunctionalCell> = BTreeMap::new();
    let mut pending: BTreeMap<FunctionalCellKey, FunctionalCell> = BTreeMap::new();
    let mut watermark: Option<CommitSeq> = None;
    let mut entries_count: u64 = 0;
    let mut posted_legs_digest = [0u8; 32];
    let mut pending_holds = BTreeMap::new();

    let entries = entries_at(db, book, seq)?;
    let resolved = resolutions(&entries)?;
    let activated = migration_activations(&entries)?;

    for (vid, entry, created_at) in &entries {
        if entry.proposal.legs.is_empty() || entry_period(book, entry)? != period_code {
            continue;
        }
        let contribution = contribution_seq(entry, *created_at, &activated)?;
        watermark = Some(watermark.map_or(contribution, |w| w.max(contribution)));
        if entry.proposal.class == EntryClass::PENDING {
            if let Some(release) = resolved.get(vid) {
                watermark = Some(watermark.map_or(*release, |w| w.max(*release)));
            } else {
                add_functional_entry(&mut pending, &spec, *vid, entry, period_code)?;
                let hold_digest = fold_functional_entry_contributions(
                    [0u8; 32],
                    &spec,
                    *created_at,
                    *vid,
                    entry,
                )?;
                pending_holds.insert((*created_at, *vid), hold_digest);
            }
        } else {
            add_functional_entry(&mut cells, &spec, *vid, entry, period_code)?;
            posted_legs_digest = fold_functional_entry_contributions(
                posted_legs_digest,
                &spec,
                *created_at,
                *vid,
                entry,
            )?;
            entries_count = entries_count
                .checked_add(1)
                .ok_or(RegisterError::Overflow)?;
        }
    }

    let cells: Vec<FunctionalCell> = cells.into_values().collect();
    let pending: Vec<FunctionalCell> = pending.into_values().collect();
    let fold_digest = digest_of(
        period_code,
        spec.base_unit,
        &cells,
        &pending,
        watermark,
        posted_legs_digest,
        &pending_holds,
    )?;

    Ok(FunctionalFold {
        period: period_code.into(),
        base_unit: spec.base_unit,
        known_at: seq,
        cells,
        pending,
        watermark,
        entries: entries_count,
        fold_digest,
    })
}

/// Verify a claimed [`FunctionalFold`] by refolding the journal at
/// `claimed.known_at` and checking exact cell, watermark, and `fold_digest`
/// equality (`FA-INV-04.functional-fold`).
pub fn verify_functional_fold<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
    claimed: &FunctionalFold,
) -> Result<(), RegisterError> {
    let refolded = fold_period_functional(db, book, period_code, Some(claimed.known_at))?;
    if refolded != *claimed {
        return Err(RegisterError::ProjectionDrift(format!(
            "functional fold drift on period `{period_code}` at seq {}: expected digest {:02x?}, got {:02x?}",
            claimed.known_at.0, refolded.fold_digest, claimed.fold_digest
        )));
    }
    Ok(())
}
