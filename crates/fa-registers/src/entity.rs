//! Registers by legal entity (plan §5.3 over §4.1's `Book.entities`;
//! FA-INV-01 `per-entity`; §9.4 `RegisterEquals`).
//!
//! A cell `(account, unit, period, legal_entity)` is the same deterministic
//! fold over committed payloads as the plain register, keyed one dimension
//! finer: each leg's entity is the legal-entity value of its
//! `dimension_set` (the book's single entity when it names none, `None` in a
//! book that declares none). Cash by legal entity is this fold restricted
//! to the cash accounts. [`verify_entities`] refolds it and proves it
//! against the journal: per (account, unit) the entity cells sum to the
//! plain fold's cell, every committed entry of the period balances per
//! `(unit, entity)`, and in a multi-entity book every leg names a declared
//! entity. A [`RegisterEquals`] claim binds a cell's key and value to the
//! fold digest at the sequence it was evaluated at, so the claim itself can
//! never become false; [`check_register_equals`] refolds at that sequence.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::KernelError;
use fa_journal::entity::leg_entity;
use fa_journal::genesis::{BookContext, BookSpec, read_book_spec};
use fa_model::{Entry, EntryClass, LegPayload, Writer};
use fa_money::{Amount, Side, UnitId};
use fa_time::DateDay;
use fgdb::Database;
use fgdb_crypto::Hasher;
use fgdb_types::{CommitSeq, VId};

use crate::{
    RegisterError, contribution_seq, entries_at, entry_period, fold_period_at,
    migration_activations, period_at, resolutions, resolve_known_at,
};

pub const ENTITY_FOLD_DIGEST_DOMAIN: &[u8] = b"fa:register-entity-fold:v1";

/// A register cell one dimension finer than [`crate::CellKey`]: the legal
/// entity the legs belong to (`None` in a book that declares none).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityCellKey {
    pub account: VId,
    pub unit_id: u32,
    pub period: String,
    pub entity: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntityCell {
    pub key: EntityCellKey,
    pub debits: i128,
    pub credits: i128,
    pub entry_count: u64,
}

/// The per-entity fold of one period at `known_at`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntityFold {
    pub period: String,
    pub known_at: CommitSeq,
    pub cells: Vec<EntityCell>,
    pub pending: Vec<EntityCell>,
    pub watermark: Option<CommitSeq>,
    pub fold_digest: [u8; 32],
}

impl EntityFold {
    /// The posted cell at `key`, if any leg touched it.
    #[must_use]
    pub fn cell(&self, key: &EntityCellKey) -> Option<&EntityCell> {
        self.cells.iter().find(|c| c.key == *key)
    }
}

/// The entity a committed leg belongs to: its declared value's code, the
/// single entity when it names none, `None` when the book declares none.
fn entity_of(spec: &BookSpec, leg: &LegPayload) -> Option<String> {
    leg_entity(spec, leg).or_else(|| match spec.entities.as_slice() {
        [only] => Some(only.code.clone()),
        _ => None,
    })
}

fn add_entry(
    cells: &mut BTreeMap<EntityCellKey, EntityCell>,
    spec: &BookSpec,
    entry: &Entry,
    period: &str,
) -> Result<(), RegisterError> {
    let mut touched = BTreeSet::new();
    for leg in &entry.proposal.legs {
        let key = EntityCellKey {
            account: leg.account_ref,
            unit_id: leg.amount.unit.0,
            period: period.into(),
            entity: entity_of(spec, leg),
        };
        let cell = cells.entry(key.clone()).or_insert_with(|| EntityCell {
            key: key.clone(),
            debits: 0,
            credits: 0,
            entry_count: 0,
        });
        let slot = match leg.side {
            Side::Debit => &mut cell.debits,
            Side::Credit => &mut cell.credits,
        };
        *slot = slot
            .checked_add(leg.amount.mantissa)
            .ok_or(RegisterError::Overflow)?;
        touched.insert(key);
    }
    for key in touched {
        let cell = cells
            .get_mut(&key)
            .ok_or_else(|| KernelError::Corrupt("missing entity fold cell".into()))?;
        cell.entry_count = cell
            .entry_count
            .checked_add(1)
            .ok_or(RegisterError::Overflow)?;
    }
    Ok(())
}

fn digest_of(
    cells: &[EntityCell],
    pending: &[EntityCell],
    watermark: Option<CommitSeq>,
) -> Result<[u8; 32], RegisterError> {
    let mut w = Writer::new();
    w.opt(watermark.as_ref(), |w, s| {
        w.u64(s.0);
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
    h.update(ENTITY_FOLD_DIGEST_DOMAIN);
    h.update(&w.finish().map_err(RegisterError::Encoding)?);
    Ok(h.finalize().0)
}

fn book_spec<V: asupersync::fs::Vfs + Clone>(db: &Database<V>) -> Result<BookSpec, RegisterError> {
    Ok(read_book_spec(db)?
        .ok_or_else(|| KernelError::Corrupt("no book spec on the root".into()))?)
}

/// The per-entity fold of `period_code` at `known_at` (head when `None`):
/// posted legs and unresolved holds, keyed `(account, unit, period,
/// entity)`, with the same watermark rule as the plain fold.
pub fn fold_period_by_entity<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
    known_at: Option<CommitSeq>,
) -> Result<EntityFold, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    period_at(db, book, period_code, seq)?;
    let spec = book_spec(db)?;
    let mut cells: BTreeMap<EntityCellKey, EntityCell> = BTreeMap::new();
    let mut pending: BTreeMap<EntityCellKey, EntityCell> = BTreeMap::new();
    let mut watermark: Option<CommitSeq> = None;
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
                add_entry(&mut pending, &spec, entry, period_code)?;
            }
        } else {
            add_entry(&mut cells, &spec, entry, period_code)?;
        }
    }
    let cells: Vec<EntityCell> = cells.into_values().collect();
    let pending: Vec<EntityCell> = pending.into_values().collect();
    let fold_digest = digest_of(&cells, &pending, watermark)?;
    Ok(EntityFold {
        period: period_code.to_string(),
        known_at: seq,
        cells,
        pending,
        watermark,
        fold_digest,
    })
}

/// `(account, unit) → (debits, credits)`.
type AccountSums = BTreeMap<(VId, u32), (i128, i128)>;

/// What `verify_entities` found for one period.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntityVerification {
    pub period: String,
    pub known_at: CommitSeq,
    pub cells_checked: usize,
    pub entries_checked: usize,
    pub fold_digest: [u8; 32],
    pub findings: Vec<String>,
}

impl EntityVerification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.findings.is_empty()
    }
}

/// Refold the per-entity register of `period_code` and prove it against
/// the journal (FA-INV-01 `per-entity`, FA-INV-04): per (account, unit) the
/// entity cells sum exactly to the plain fold's cell (posted and pending);
/// every committed entry of the period balances per `(unit, entity)`; in a
/// multi-entity book every leg names a declared entity. Findings are drift,
/// never corrections.
pub fn verify_entities<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
    known_at: Option<CommitSeq>,
) -> Result<EntityVerification, RegisterError> {
    let by_entity = fold_period_by_entity(db, book, period_code, known_at)?;
    let plain = fold_period_at(db, book, period_code, Some(by_entity.known_at))?;
    let spec = book_spec(db)?;
    let mut findings = Vec::new();
    let sum = |column: &[EntityCell]| -> Result<AccountSums, RegisterError> {
        let mut out = AccountSums::new();
        for c in column {
            let slot = out.entry((c.key.account, c.key.unit_id)).or_insert((0, 0));
            slot.0 = slot
                .0
                .checked_add(c.debits)
                .ok_or(RegisterError::Overflow)?;
            slot.1 = slot
                .1
                .checked_add(c.credits)
                .ok_or(RegisterError::Overflow)?;
        }
        Ok(out)
    };
    for (name, entity_cells, plain_cells) in [
        ("posted", &by_entity.cells, &plain.cells),
        ("pending", &by_entity.pending, &plain.pending),
    ] {
        let summed = sum(entity_cells)?;
        let expected: AccountSums = plain_cells
            .iter()
            .map(|c| ((c.key.account, c.key.unit_id), (c.debits, c.credits)))
            .collect();
        if summed != expected {
            findings.push(format!(
                "{name} entity cells of `{period_code}` do not sum to the plain register"
            ));
        }
    }
    let entries = entries_at(db, book, by_entity.known_at)?;
    let mut entries_checked = 0usize;
    for (vid, entry, _) in &entries {
        if entry.proposal.legs.is_empty() || entry_period(book, entry)? != period_code {
            continue;
        }
        entries_checked += 1;
        let mut totals: BTreeMap<(u32, Option<String>), (i128, i128)> = BTreeMap::new();
        for leg in &entry.proposal.legs {
            if spec.entities.len() > 1 && leg_entity(&spec, leg).is_none() {
                findings.push(format!(
                    "entry {:032x} has a leg naming no declared legal entity",
                    vid.0
                ));
            }
            let slot = totals
                .entry((leg.amount.unit.0, entity_of(&spec, leg)))
                .or_insert((0, 0));
            let side = match leg.side {
                Side::Debit => &mut slot.0,
                Side::Credit => &mut slot.1,
            };
            *side = side
                .checked_add(leg.amount.mantissa)
                .ok_or(RegisterError::Overflow)?;
        }
        for ((unit, entity), (d, c)) in totals {
            if d != c {
                findings.push(format!(
                    "entry {:032x} is unbalanced for entity {:?} in unit {unit}",
                    vid.0, entity
                ));
            }
        }
    }
    Ok(EntityVerification {
        period: period_code.to_string(),
        known_at: by_entity.known_at,
        cells_checked: by_entity.cells.len() + by_entity.pending.len(),
        entries_checked,
        fold_digest: by_entity.fold_digest,
        findings,
    })
}

/// A balance assertion (plan §9.4 `RegisterEquals`): the posted net of one
/// per-entity cell, in debit sign, bound to the fold digest at the sequence
/// it was evaluated at — immutable, so it can never become false; drift is
/// a separate head-following comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisterEquals {
    pub cell_key: EntityCellKey,
    pub amount: Amount,
    /// The last day of the cell's period.
    pub as_of_effective: DateDay,
    pub evaluated_known_at: CommitSeq,
    pub fold_digest: [u8; 32],
}

/// The cell's posted net in debit sign (`0` for an untouched cell).
fn net_of(fold: &EntityFold, key: &EntityCellKey) -> Result<i128, RegisterError> {
    match fold.cell(key) {
        Some(c) => c
            .debits
            .checked_sub(c.credits)
            .ok_or(RegisterError::Overflow),
        None => Ok(0),
    }
}

/// Evaluate a `RegisterEquals` claim for `key` at `known_at` (head when
/// `None`): its value and the fold digest it is bound to.
pub fn register_equals<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    key: &EntityCellKey,
    known_at: Option<CommitSeq>,
) -> Result<RegisterEquals, RegisterError> {
    let fold = fold_period_by_entity(db, book, &key.period, known_at)?;
    let period = period_at(db, book, &key.period, fold.known_at)?;
    Ok(RegisterEquals {
        cell_key: key.clone(),
        amount: Amount::new(UnitId(key.unit_id), net_of(&fold, key)?),
        as_of_effective: period
            .end
            .0
            .checked_sub(1)
            .map(DateDay)
            .ok_or(RegisterError::Overflow)?,
        evaluated_known_at: fold.known_at,
        fold_digest: fold.fold_digest,
    })
}

/// Recheck a claim at its own sequence: true iff refolding there yields the
/// same value and the same fold digest the claim binds.
pub fn check_register_equals<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    claim: &RegisterEquals,
) -> Result<bool, RegisterError> {
    let fold = fold_period_by_entity(
        db,
        book,
        &claim.cell_key.period,
        Some(claim.evaluated_known_at),
    )?;
    Ok(fold.fold_digest == claim.fold_digest
        && net_of(&fold, &claim.cell_key)? == claim.amount.mantissa
        && claim.amount.unit == UnitId(claim.cell_key.unit_id))
}
