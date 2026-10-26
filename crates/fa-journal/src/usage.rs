//! Shared daily gross-debit limits (plan §14.2, FA-INV-10.ceiling).
//!
//! An issued root and all its attenuated descendants consume the same cell
//! for each declared book-calendar day and native unit. Posting stages the
//! cell CAS and immutable admission receipts with its unchanged Entry. The
//! receipts retain the capability and committed time evidence needed to
//! rebuild the projection; no host clock or effective posting date selects
//! the spending day. Pending and posted positive debit legs both consume
//! budget. Nothing refunds usage, including reversals and reservation voids.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property, relation};
use fa_model::{ControlPayload, Entry, EntryClass, EntryPayload, EntryRef, Id128};
use fa_money::{Side, UnitId};
use fa_policy::Capability;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn};
use fgdb_crypto::Hasher;
use fgdb_delta_types::DeltaRow;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::{BookContext, BookSpec};
use crate::policy;
use crate::refusal::{Outcome, code, exit};
use crate::rows::{book_root, edge_id};
use crate::{KernelError, Refusal};

mod codec;
mod verify;
/// Frozen canonical storage and caveat contract for native daily usage.
pub const SCHEMA_REGISTRY: &str =
    include_str!("../../../registries/object_schemas/daily_usage.toml");
use codec::corrupt;
pub use codec::{UsageCell, UsageDebit, UsageKey};
pub use verify::{UsageVerification, verify_usage};

pub(crate) fn mismatch(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::USAGE_MISMATCH,
        exit::VERIFICATION,
        message,
        "plan §14.2 / FA-INV-04 / FA-INV-10.ceiling (usage is a projection of immutable admission facts)",
        "retain the original book history and run fa verify registers for the affected period; do not reset a usage cell or mint a replacement quota to bypass the discrepancy",
    )
}

pub(crate) fn not_issued(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::CAPABILITY_NOT_ISSUED,
        exit::SAFETY,
        message,
        "plan §14.2 (a daily limit is rooted in an immutable journaled issuance)",
        "present a holder-bound capability issued in this book with its original daily-limit root",
    )
}

/// Decode the actual retained issuance and bind every digest and identity.
pub(crate) fn issued_capability(
    row: &VertexRow,
    book: Id128,
    commitment: &[u8; 32],
) -> Result<(Capability, EntryRef), KernelError> {
    let (entry, _) = crate::post::entry_of(row)?;
    let body = entry
        .proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == fa_model::entry::CAPABILITY_BODY_EXTENSION)
        .map(|(_, body)| body.as_slice())
        .ok_or_else(|| corrupt("issuance omits its capability body"))?;
    let capability = Capability::decode(body).map_err(|e| corrupt(e.to_string()))?;
    let expected = capability
        .commitment()
        .map_err(|e| corrupt(e.to_string()))?;
    if expected != *commitment
        || row.vid != policy::issuance_vid(book, commitment)
        || entry.proposal.book_id != book
        || entry.proposal.branch_id != Id128::TRUNK
        || entry.proposal.class != EntryClass::POLICY_CONTROL
        || !matches!(entry.proposal.control.as_ref(),
            Some(ControlPayload::CapabilityEvent { commitment: actual, kind: policy::CAPABILITY_EVENT_ISSUE, caveats_digest })
            if *actual == *commitment && *caveats_digest == fa_model::domain_digest(b"fa:capability-body:v1", &[body]))
        || capability.possession().is_none()
    {
        return Err(corrupt(
            "issuance identity, body or control digest disagrees",
        ));
    }
    Ok((capability, entry.entry_ref(row.vid)))
}

pub(crate) fn gross_debits(proposal: &EntryPayload) -> Result<BTreeMap<UnitId, i128>, KernelError> {
    let mut gross = BTreeMap::<UnitId, i128>::new();
    for leg in &proposal.legs {
        if leg.amount.mantissa <= 0 {
            return Err(corrupt("a monetary leg has a nonpositive magnitude"));
        }
        if leg.side == Side::Debit {
            let value = gross.entry(leg.amount.unit).or_default();
            *value = value
                .checked_add(leg.amount.mantissa)
                .ok_or_else(|| corrupt("gross debit sum exceeds i128"))?;
        }
    }
    Ok(gross)
}

struct CellMove {
    before: Option<UsageCell>,
    after: UsageCell,
    debit: UsageDebit,
}

pub(crate) struct Judged {
    moves: Vec<CellMove>,
}

/// Called only after current admission, identity retry resolution, all
/// posting laws, and balancing-leg resolution, under the posting transaction.
pub(crate) fn judge<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    contexts: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    entry: &Entry,
    entry_vid: VId,
) -> Outcome<Option<Judged>> {
    if capability.daily_totals().is_empty() {
        return Ok(Ok(None));
    }
    let gross = gross_debits(&entry.proposal)?;
    if gross.is_empty() {
        return Ok(Ok(None));
    }
    let commitment = capability
        .commitment()
        .map_err(|e| corrupt(e.to_string()))?;
    let root = capability.daily_root().unwrap_or(commitment);
    let Some(issuance) = txn.vertex(db, policy::issuance_vid(book.book_id, &commitment))? else {
        return Ok(Err(not_issued(
            "daily spending requires a retained issued capability",
        )));
    };
    let (issued, _) = issued_capability(&issuance, book.book_id, &commitment)?;
    if &issued != capability {
        return Ok(Err(mismatch(
            "presented daily limit differs from its retained issuance",
        )));
    }
    let Some(root_row) = txn.vertex(db, policy::issuance_vid(book.book_id, &root))? else {
        return Ok(Err(not_issued(
            "the daily spending root issuance is missing",
        )));
    };
    let (root_capability, _) = issued_capability(&root_row, book.book_id, &root)?;
    if root_capability.daily_root().is_some() || root_capability.daily_totals().is_empty() {
        return Ok(Err(mismatch(
            "daily spending root is not an original quota issuance",
        )));
    }
    let spec = txn.vertex_property(db, book_root(), property::FA_PAYLOAD)?;
    let Some(CanonicalScalar::Bytes(spec)) = spec else {
        return Err(corrupt("book genesis payload is missing"));
    };
    let Some(time_zone) = BookSpec::decode(spec.as_slice())?.time_zone_policy else {
        return Ok(Err(Refusal::new(
            code::CLASS_NOT_IMPLEMENTED,
            exit::REFUSAL,
            "daily spending requires an explicit book time_zone_policy",
            "plan §14.2 / §7.7 (budget day comes from the declared book calendar)",
            "use a book created with --time-zone UTC; the posting effective date cannot select the budget day",
        )));
    };
    let (_, tick) = crate::sweep::tick_witness(txn, db)?;
    let Some(tick) = tick else {
        return Ok(Err(Refusal::new(
            code::TICK_MISSING,
            exit::REFUSAL,
            "daily spending requires a previously committed TimeEvidence tick",
            "plan §14.2 / §7.1a (the day boundary comes from retained time evidence)",
            "have the book's authorized clock holder journal a TimeEvidence tick, then retry",
        )));
    };
    let tick_row = txn
        .vertex(db, tick.entry)?
        .ok_or_else(|| corrupt("latest tick entry is missing"))?;
    let (tick_entry, tick_at) = crate::post::entry_of(&tick_row)?;
    if tick_at.0 == 0
        || tick_at > txn.basis()
        || tick_entry.proposal.book_id != book.book_id
        || tick_entry.proposal.branch_id != Id128::TRUNK
        || !matches!(tick_entry.proposal.control.as_ref(), Some(ControlPayload::TimeTick { observed_utc_ns, .. }) if *observed_utc_ns == tick.observed_utc_ns)
    {
        return Ok(Err(mismatch(
            "budget tick is not the retained, strictly preceding observation",
        )));
    }
    if !crate::sweep::tick_corroborated(&tick_row)? {
        return Ok(Err(crate::sweep::uncorroborated(tick)));
    }
    let day = time_zone.civil_date(tick.observed_utc_ns);
    let mut moves = Vec::with_capacity(gross.len());
    for (unit, delta) in gross {
        let Some(&limit) = capability.daily_totals().get(&unit) else {
            return Ok(Err(Refusal::new(
                code::DAILY_CEILING,
                exit::SAFETY,
                format!(
                    "daily-limit capability does not authorize native unit {}",
                    unit.0
                ),
                "plan §14.2 (a bounded capability admits only its bounded units)",
                "use an issued daily limit covering every native unit in the complete entry",
            )));
        };
        if root_capability
            .daily_totals()
            .get(&unit)
            .is_none_or(|bound| limit > *bound)
        {
            return Ok(Err(mismatch(
                "a descendant daily limit widens its retained root",
            )));
        }
        let key = UsageKey {
            book_id: book.book_id,
            root_issuance: root,
            day,
            unit,
        };
        let row = txn.vertex(db, key.cell_vid())?;
        let before = match row
            .as_ref()
            .map(|row| UsageCell::from_row(row, key))
            .transpose()
        {
            Ok(value) => value,
            Err(error) => return Ok(Err(mismatch(error.to_string()))),
        };
        if let Some(cell) = before {
            let Some(last) = txn.vertex(db, key.debit_vid(cell.generation))? else {
                return Ok(Err(mismatch(
                    "usage cell has no matching immutable last receipt",
                )));
            };
            let last_row = last;
            let last = match UsageDebit::from_row(&last_row) {
                Ok(last) => last,
                Err(error) => return Ok(Err(mismatch(error.to_string()))),
            };
            if last.key != key
                || last.generation != cell.generation
                || last.total_gross_debits != cell.gross_debits
            {
                return Ok(Err(mismatch(
                    "usage cell disagrees with its immutable last receipt",
                )));
            }
            let Some(source) = txn.vertex(db, last.entry.vid)? else {
                return Ok(Err(mismatch(
                    "the last usage receipt's source entry is missing",
                )));
            };
            let (source_entry, source_at) = crate::post::entry_of(&source)?;
            if source_entry.entry_ref(source.vid) != last.entry
                || source_at != last_row.created_at
                || gross_debits(&source_entry.proposal)?.get(&unit) != Some(&last.gross_debits)
            {
                return Ok(Err(mismatch(
                    "the last usage receipt is not an unchanged debit of its same-commit source entry",
                )));
            }
            // A current row's created_at is its content-version start, not
            // necessarily its birth. Prove both native creations before
            // trusting that shared coordinate or its historical snapshot.
            let last_committed = db.vertex_at(last_row.vid, txn.basis())?.is_some();
            if last_committed {
                if let Err(refusal) =
                    same_publication_births(db, contexts, source_at, &last_row, &source)?
                {
                    return Ok(Err(refusal));
                }
                let Some(original) = db.vertex_at(last_row.vid, source_at)? else {
                    return Ok(Err(mismatch(
                        "the last usage receipt's creating snapshot is unavailable",
                    )));
                };
                if original.props != last_row.props
                    || original.labels != last_row.labels
                    || original.birth_ordinal != last_row.birth_ordinal
                {
                    return Ok(Err(mismatch(
                        "the last usage receipt differs from its immutable creating row",
                    )));
                }
            }
            if last.generation > 1 {
                let Some(previous) = txn.vertex(db, key.debit_vid(last.generation - 1))? else {
                    return Ok(Err(mismatch(
                        "the last usage receipt has no retained predecessor generation",
                    )));
                };
                let predecessor = match UsageDebit::from_row(&previous) {
                    Ok(value) => value,
                    Err(error) => return Ok(Err(mismatch(error.to_string()))),
                };
                if predecessor.key != key
                    || predecessor.generation != last.generation - 1
                    || predecessor.total_gross_debits != last.previous_gross_debits
                    || (last_committed && previous.created_at > last_row.created_at)
                {
                    return Ok(Err(mismatch(
                        "the last usage receipt breaks its immutable predecessor's cumulative total",
                    )));
                }
            }
        } else if txn.vertex(db, key.debit_vid(1))?.is_some() {
            return Ok(Err(mismatch(
                "a missing usage cell is not a fresh budget: its first receipt is retained",
            )));
        }
        let previous = before.map_or(0, |cell| cell.gross_debits);
        let Some(total) = previous.checked_add(delta) else {
            return Ok(Err(Refusal::new(
                code::DAILY_CEILING,
                exit::SAFETY,
                "daily gross debit accumulation exceeds i128",
                "plan §14.2 / §6.1 (checked exact daily spending)",
                "use a smaller authorized entry; no usage was consumed",
            )));
        };
        if total > limit {
            return Ok(Err(Refusal::new(
                code::DAILY_CEILING,
                exit::SAFETY,
                format!(
                    "daily gross debit limit exceeded for unit {} on {}: used {previous} + requested {delta} > limit {limit}; all descendants share this root's usage",
                    unit.0,
                    day.render()
                ),
                "plan §14.2 (gross debits per root issuance, day and native unit)",
                "reduce the complete entry or wait for a corroborated tick in the next book-calendar day; splitting calls or attenuating the token does not reset usage",
            )));
        }
        let Some(generation) = before.map_or(0, |cell| cell.generation).checked_add(1) else {
            return Ok(Err(mismatch("usage generation exceeds i64")));
        };
        if txn.vertex(db, key.debit_vid(generation))?.is_some() {
            return Ok(Err(mismatch(
                "the next immutable usage generation already exists; an older cell cannot restore spent capacity",
            )));
        }
        moves.push(CellMove {
            before,
            after: UsageCell {
                key,
                gross_debits: total,
                generation,
            },
            debit: UsageDebit {
                key,
                generation,
                entry: entry.entry_ref(entry_vid),
                capability: commitment,
                tick: tick_entry.entry_ref(tick.entry),
                time_zone_policy: time_zone.tag(),
                gross_debits: delta,
                previous_gross_debits: previous,
                total_gross_debits: total,
            },
        });
    }
    let fresh: BTreeSet<_> = moves
        .iter()
        .filter(|movement| movement.before.is_none())
        .flat_map(|movement| {
            [
                movement.after.key.cell_vid(),
                movement.after.key.debit_vid(1),
            ]
        })
        .collect();
    if !fresh.is_empty()
        && let Err(refusal) = never_created(db, contexts, txn.basis(), &fresh)?
    {
        return Ok(Err(refusal));
    }
    Ok(Ok(Some(Judged { moves })))
}

/// Only native CreateVertex rows establish a receipt's and source's original
/// publication. The pinned substrate permanently spends deleted identities,
/// so a creation at this coordinate cannot be a later resurrection. Inspect
/// this one retained commit; no full-prefix refold is needed for an existing
/// cell. Earlier members of the same uncommitted batch bypass this check.
fn same_publication_births<V: Vfs + Clone>(
    db: &Database<V>,
    contexts: &PurposeContexts,
    at: CommitSeq,
    receipt: &VertexRow,
    source: &VertexRow,
) -> Outcome<()> {
    let cx = contexts.txn();
    cx.checkpoint().map_err(fgdb::WriteTxnError::Interrupted)?;
    let Some(before) = at.0.checked_sub(1) else {
        return Ok(Err(mismatch(
            "a committed usage receipt cannot precede native history",
        )));
    };
    let Some(batch) = db.delta_since(CommitSeq(before))?.next() else {
        return Ok(Err(mismatch(
            "the last usage receipt's native creating commit is unavailable",
        )));
    };
    if batch.commit_seq() != at {
        return Ok(Err(mismatch(
            "the last usage receipt's native creating commit is unavailable",
        )));
    }
    let mut receipt_born = false;
    let mut source_born = false;
    let invalid_birth = || {
        mismatch(
            "the last usage receipt and source are not their unchanged same-publication native births; a joint rewrite cannot restore spent capacity",
        )
    };
    for coordinate in batch.coordinate_entries() {
        for row in &coordinate.rows {
            cx.checkpoint().map_err(fgdb::WriteTxnError::Interrupted)?;
            if let DeltaRow::CreateVertex {
                vid,
                birth_ordinal,
                labels,
                props,
                ..
            } = row
            {
                if *vid == receipt.vid {
                    if receipt_born
                        || *birth_ordinal != receipt.birth_ordinal
                        || labels.as_slice() != [label::USAGE_DEBIT]
                        || labels != &receipt.labels
                        || props != &receipt.props
                    {
                        return Ok(Err(invalid_birth()));
                    }
                    receipt_born = true;
                }
                if *vid == source.vid {
                    if source_born
                        || *birth_ordinal != source.birth_ordinal
                        || labels.as_slice() != [label::ENTRY]
                        || labels != &source.labels
                        || props != &source.props
                    {
                        return Ok(Err(invalid_birth()));
                    }
                    source_born = true;
                }
            }
        }
    }
    if !receipt_born || !source_born {
        return Ok(Err(invalid_birth()));
    }
    Ok(Ok(()))
}

/// An absent derived cell does not prove a quota is fresh. Only the complete
/// authenticated creation prefix can establish that both its identity and
/// first immutable receipt have never been used. Existing cells use point
/// witnesses and one retained birth commit; this full-prefix read is needed
/// only to establish a new day.
fn never_created<V: Vfs + Clone>(
    db: &Database<V>,
    contexts: &PurposeContexts,
    at: CommitSeq,
    identities: &BTreeSet<VId>,
) -> Outcome<()> {
    let cx = contexts.txn();
    let mut through = 0_u64;
    for batch in db.delta_since(CommitSeq(0))? {
        let seq = batch.commit_seq();
        if seq > at {
            break;
        }
        cx.checkpoint().map_err(fgdb::WriteTxnError::Interrupted)?;
        if through.checked_add(1) != Some(seq.0) {
            return Ok(Err(mismatch(
                "first daily spending requires complete retained creation history; load history before preparing this quota",
            )));
        }
        for coordinate in batch.coordinate_entries() {
            for row in &coordinate.rows {
                cx.checkpoint().map_err(fgdb::WriteTxnError::Interrupted)?;
                if let DeltaRow::CreateVertex { vid, .. } = row
                    && identities.contains(vid)
                {
                    return Ok(Err(mismatch(
                        "an absent usage cell or first receipt has a retained creation; deleting both cannot reset spent capacity",
                    )));
                }
            }
        }
        through = seq.0;
    }
    if through != at.0 {
        return Ok(Err(mismatch(
            "first daily spending requires the complete native prefix; load history before preparing this quota",
        )));
    }
    Ok(Ok(()))
}

pub(super) fn cite_targets(debit: &UsageDebit) -> BTreeSet<VId> {
    BTreeSet::from([
        debit.entry.vid,
        debit.tick.vid,
        policy::issuance_vid(debit.key.book_id, &debit.capability),
        policy::issuance_vid(debit.key.book_id, &debit.key.root_issuance),
    ])
}

impl Judged {
    pub(crate) fn stage(&self, batch: &mut WriteBatch) -> Result<Vec<WriteBatch>, KernelError> {
        let mut cites = WriteBatch::new(relation::CITES);
        let mut in_book = WriteBatch::new(relation::IN_BOOK);
        for movement in &self.moves {
            let cell = movement.after.key.cell_vid();
            if let Some(before) = movement.before {
                batch.compare_and_set_vertex_property(
                    cell,
                    property::GENERATION,
                    Some(CanonicalScalar::Int(before.generation)),
                    CanonicalScalar::Int(movement.after.generation),
                    WriteMismatchPolicy::AbortWrite,
                );
                for (key, value) in movement.after.properties()? {
                    if key != property::GENERATION {
                        batch.set_vertex_property(cell, key, Some(value));
                    }
                }
            } else {
                batch.create_vertex(cell, vec![label::USAGE_CELL], movement.after.properties()?);
            }
            let id = movement.debit.vid();
            batch.create_vertex(id, vec![label::USAGE_DEBIT], movement.debit.properties()?);
            for target in cite_targets(&movement.debit) {
                cites.add_edge(edge_id(relation::CITES, id, target), id, target, vec![]);
            }
            in_book.add_edge(
                edge_id(relation::IN_BOOK, id, book_root()),
                id,
                book_root(),
                vec![],
            );
        }
        Ok(vec![cites, in_book])
    }

    pub(crate) fn record_template_bytes(
        &self,
        tracker: &mut crate::batch::TemplateByteTracker,
    ) -> Result<(), KernelError> {
        for movement in &self.moves {
            let cell = movement.after.key.cell_vid();
            let after_props = movement.after.properties()?;
            if let Some(before) = movement.before {
                let before_props = before.properties()?;
                for ((key, before_val), (_, after_val)) in before_props.into_iter().zip(after_props)
                {
                    tracker.set_vertex_property(
                        relation::HAS_LEG,
                        cell,
                        key,
                        Some(before_val),
                        Some(after_val),
                    );
                }
            } else {
                tracker.create_vertex(relation::HAS_LEG, cell, 1, &after_props);
            }
            let id = movement.debit.vid();
            tracker.create_vertex(relation::HAS_LEG, id, 1, &movement.debit.properties()?);
            for _ in cite_targets(&movement.debit) {
                tracker.add_edge(relation::CITES, &[]);
            }
            tracker.add_edge(relation::IN_BOOK, &[]);
        }
        Ok(())
    }

    /// Only daily-limited plans append this domain; old plans keep their bytes.
    pub(crate) fn bind_effects(&self, hasher: &mut Hasher) -> Result<(), KernelError> {
        hasher.update(b"fa:post-daily-usage:v1");
        hasher.update(&(self.moves.len() as u64).to_le_bytes());
        for movement in &self.moves {
            let receipt = movement.debit.canonical_bytes()?;
            hasher.update(&(receipt.len() as u64).to_le_bytes());
            hasher.update(&receipt);
            hasher.update(&movement.after.key.cell_vid().0.to_le_bytes());
        }
        Ok(())
    }
}
