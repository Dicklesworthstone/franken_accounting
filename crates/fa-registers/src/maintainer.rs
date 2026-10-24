//! Native posted/pending period registers over the committed delta stream.
//!
//! Cells and the consumed frontier are one atomic publication. A prepared
//! advance owns no transaction and can be dropped; publication rejects a
//! changed basis. Only new Entry payloads are decoded during advancement,
//! plus the original Pending payload for each release. Leg mirrors are not
//! inputs. Retired cursors rebuild from the authoritative journal.
//!
//! RegisterState is mutable, disposable maintenance metadata, not a certified
//! RegisterCheckpoint. This module does not yet maintain entity, open-item or
//! availability projections. Reports still use the independent literal fold.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::KernelError;
use fa_journal::genesis::{BookContext, UnitPolicy};
use fa_journal::rows::{AccountRow, bytes, prop, scalar_bytes, scalar_text};
use fa_model::symbols::{label, property};
use fa_model::{ControlPayload, Entry, EntryClass, Id128, Reader, Writer};
use fa_money::Side;
use fgdb::{Database, WriteMismatchPolicy};
use fgdb_crypto::Hasher;
use fgdb_delta_types::{DeltaRow, ElementId, IndexError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::{Cell, CellKey, Fold, RegisterError};

/// What one publication consumed. `through` is the input frontier, not the
/// register write's own sequence or the last monetary contribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advance {
    pub period: String,
    pub from: CommitSeq,
    pub through: CommitSeq,
    pub published_at: CommitSeq,
    pub entries_decoded: usize,
    pub rebuilt: bool,
    pub wrote: bool,
    pub fold: Fold,
    pub decision_card: fa_policy::DecisionCard,
    pub decision_card_digest: [u8; 32],
}

/// A computed advance with a private basis and immutable result. Computing
/// one changes no cells. Publication after *any* intervening commit refuses.
#[derive(Debug)]
pub struct PreparedAdvance {
    book_id: Id128,
    basis: CommitSeq,
    basis_root: fgdb_types::ObjectId,
    expected_state: Option<CanonicalScalar>,
    result: Advance,
}

impl PreparedAdvance {
    #[must_use]
    pub fn result(&self) -> &Advance {
        &self.result
    }
}

/// Deterministic identity of disposable metadata for this register family.
#[must_use]
pub fn state_vid(book: Id128, period: &str) -> VId {
    let mut h = Hasher::new();
    h.update(b"fa:register-state:native-period:v1");
    h.update(&book.0);
    h.update(&(period.len() as u64).to_le_bytes());
    h.update(period.as_bytes());
    let mut lo = [0; 16];
    lo.copy_from_slice(&h.finalize().0[..16]);
    VId(u128::from_le_bytes(lo))
}

fn drift(what: impl Into<String>) -> RegisterError {
    RegisterError::ProjectionDrift(what.into())
}

fn state_digest(book: Id128, period: &str, payload: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"fa:register-state-payload:v1");
    h.update(&book.0);
    h.update(&(period.len() as u64).to_le_bytes());
    h.update(period.as_bytes());
    h.update(payload);
    h.finalize().0
}

const STATE_VERSION: u16 = 2;

fn empty(period: &str) -> Result<Fold, RegisterError> {
    let pending_holds = BTreeMap::new();
    Ok(Fold {
        period: period.into(),
        cells: Vec::new(),
        pending: Vec::new(),
        watermark: None,
        entries: 0,
        fold_digest: crate::digest_of(period, &[], &[], None, [0u8; 32], &pending_holds)?,
        posted_legs_digest: [0u8; 32],
        pending_holds,
    })
}

fn encode(through: CommitSeq, fold: &Fold) -> Result<Vec<u8>, RegisterError> {
    let mut w = Writer::new();
    w.fixed(b"FARS").u16(STATE_VERSION).u64(through.0);
    w.opt(fold.watermark.as_ref(), |w, seq| {
        w.u64(seq.0);
    });
    w.u64(fold.entries)
        .fixed(&fold.fold_digest)
        .fixed(&fold.posted_legs_digest);
    let holds: Vec<_> = fold.pending_holds.iter().collect();
    w.list(&holds, |w, ((seq, vid), digest)| {
        w.u64(seq.0).u128(vid.0).fixed(*digest);
    });
    w.finish().map_err(RegisterError::Encoding)
}

fn decode(payload: &[u8], period: &str) -> Result<(CommitSeq, Fold), RegisterError> {
    let read = || -> Result<_, fa_model::DecodeError> {
        let mut r = Reader::new(payload);
        if r.fixed::<4>("register-state.magic")? != *b"FARS"
            || r.u16("register-state.version")? != STATE_VERSION
        {
            return Err(r.invalid("register-state.format"));
        }
        let through = CommitSeq(r.u64("register-state.through")?);
        let watermark = r.opt("register-state.watermark", |r| {
            Ok(CommitSeq(r.u64("register-state.watermark")?))
        })?;
        let entries = r.u64("register-state.entries")?;
        let fold_digest = r.fixed::<32>("register-state.digest")?;
        let posted_legs_digest = r.fixed::<32>("register-state.posted_legs_digest")?;
        let holds = r.list(
            fa_model::limits::MAX_BATCH_ENTRIES,
            "register-state.pending_holds",
            |r| {
                let seq = CommitSeq(r.u64("register-state.hold_seq")?);
                let vid = VId(r.u128("register-state.hold_vid")?);
                let digest = r.fixed::<32>("register-state.hold_digest")?;
                Ok(((seq, vid), digest))
            },
        )?;
        let mut pending_holds = BTreeMap::new();
        for (key, digest) in holds {
            if key.0 > through
                || pending_holds
                    .last_key_value()
                    .is_some_and(|(prev, _)| *prev >= key)
            {
                return Err(r.invalid("register-state.pending_holds"));
            }
            pending_holds.insert(key, digest);
        }
        r.finish()?;
        Ok((
            through,
            watermark,
            entries,
            fold_digest,
            posted_legs_digest,
            pending_holds,
        ))
    };
    let (through, watermark, entries, fold_digest, posted_legs_digest, pending_holds) =
        read().map_err(|e| drift(e.to_string()))?;
    if watermark.is_some_and(|w| w > through) {
        return Err(drift("contribution watermark exceeds consumed frontier"));
    }
    Ok((
        through,
        Fold {
            period: period.into(),
            cells: Vec::new(),
            pending: Vec::new(),
            watermark,
            entries,
            fold_digest,
            posted_legs_digest,
            pending_holds,
        },
    ))
}

/// Load cells only after their identities, both amount columns, metadata and
/// digest agree. This is cache-integrity checking; verify_period independently
/// proves equality with the journal, including coherently forged cache data.
fn load<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
) -> Result<Option<(CommitSeq, Fold, CanonicalScalar)>, RegisterError> {
    let Some(state) = db.vertex(state_vid(book.book_id, period))? else {
        return Ok(None);
    };
    if state.labels != vec![label::REGISTER_STATE]
        || bytes(&state, property::BOOK_ID, "register-state.book")? != book.book_id.0
        || crate::text(&state, property::EFFECTIVE_PERIOD, "register-state.period")? != period
    {
        return Err(drift("maintenance state identity or coordinate"));
    }
    let payload = bytes(&state, property::FA_PAYLOAD, "register-state.payload")?;
    if bytes(&state, property::FA_DIGEST, "register-state.digest")?
        != state_digest(book.book_id, period, &payload)
    {
        return Err(drift("maintenance state checksum"));
    }
    let (through, mut fold) = decode(&payload, period)?;
    if through > db.frontier()? {
        return Err(drift("maintenance cursor exceeds book frontier"));
    }
    match crate::period_at(db, book, period, through) {
        Ok(_) => {}
        Err(RegisterError::InvalidSelection(_)) => {
            return Err(drift("maintenance cursor predates its period"));
        }
        Err(error) => return Err(error),
    }
    for row in crate::stored_registers(db, book, &fold)?.values() {
        let account: [u8; 16] = bytes(row, property::ACCOUNT_REF, "register.account")?
            .try_into()
            .map_err(|_| drift("register account identity"))?;
        let unit_id = u32::try_from(crate::int(row, property::UNIT_ID, "register.unit")?)
            .map_err(|_| drift("register unit identity"))?;
        let key = CellKey {
            account: VId(u128::from_le_bytes(account)),
            unit_id,
            period: period.into(),
        };
        for (pending, column) in [(false, &mut fold.cells), (true, &mut fold.pending)] {
            let (debits, credits, entry_count) = crate::stored_values(row, pending)?
                .ok_or_else(|| drift("missing or malformed register column"))?;
            if debits < 0 || credits < 0 || (entry_count == 0 && (debits != 0 || credits != 0)) {
                return Err(drift("invalid register sums/count"));
            }
            if entry_count != 0 {
                column.push(Cell {
                    key: key.clone(),
                    debits,
                    credits,
                    entry_count,
                });
            }
        }
    }
    fold.cells.sort_by(|a, b| a.key.cmp(&b.key));
    fold.pending.sort_by(|a, b| a.key.cmp(&b.key));
    if crate::digest_of(
        period,
        &fold.cells,
        &fold.pending,
        fold.watermark,
        fold.posted_legs_digest,
        &fold.pending_holds,
    )? != fold.fold_digest
        || !crate::verify_projection(db, book, &fold)?.is_green()
    {
        return Err(drift(
            "stored cells disagree with maintenance digest or metadata",
        ));
    }
    Ok(Some((
        through,
        fold,
        scalar_bytes("register-state.payload", payload)?,
    )))
}

/// Independent verification includes the state header, not merely its checksum.
/// A coherently forged cursor or entry count cannot pass a journal refold.
pub(crate) fn verify_state<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
) -> Result<(Option<CommitSeq>, Option<String>), RegisterError> {
    match load(db, book, period) {
        Ok(None) => Ok((None, None)),
        Ok(Some((through, fold, _))) => {
            let truth = crate::fold_period_at(db, book, period, Some(through))?;
            Ok((
                Some(through),
                (fold != truth)
                    .then(|| "maintenance state disagrees with its journal prefix".into()),
            ))
        }
        Err(RegisterError::ProjectionDrift(what))
        | Err(RegisterError::Kernel(KernelError::Corrupt(what))) => Ok((None, Some(what))),
        Err(error) => Err(error),
    }
}

/// What folding the committed suffix after a cursor did.
enum Tail {
    /// Every new entry was folded; this many payloads were decoded.
    Applied(usize),
    /// Only a literal fold is exact: a migration run was finalized (its
    /// chunks may precede the cursor), or a pending column overflowed before
    /// the releases later in the suffix.
    Rebuild,
}

/// Fold the committed suffix after `from` into `fold` as of `basis`,
/// decoding only the new Entry payloads (plan §5.3). Maintenance and the
/// head read share it, so both apply one law.
fn apply_tail<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
    basis: CommitSeq,
    from: CommitSeq,
    fold: &mut Fold,
) -> Result<Tail, RegisterError> {
    let mut cells: BTreeMap<_, _> = fold
        .cells
        .iter()
        .cloned()
        .map(|c| (c.key.clone(), c))
        .collect();
    let mut pending: BTreeMap<_, _> = fold
        .pending
        .iter()
        .cloned()
        .map(|c| (c.key.clone(), c))
        .collect();
    let mut entries_decoded = 0usize;
    let mut migration_runs = BTreeMap::new();
    for batch in db.delta_since(from)? {
        let seq = batch.commit_seq();
        let mut batch_entries = Vec::new();
        for coordinate in batch.coordinate_entries() {
            for row in &coordinate.rows {
                match row {
                    DeltaRow::CreateVertex {
                        vid, labels, props, ..
                    } if labels.contains(&label::ENTRY) => {
                        let payload = props
                            .iter()
                            .find_map(|(key, value)| {
                                if *key == property::FA_PAYLOAD
                                    && let CanonicalScalar::Bytes(b) = value
                                {
                                    return Some(b.as_slice());
                                }
                                None
                            })
                            .ok_or_else(|| {
                                KernelError::Corrupt("delta Entry lacks canonical payload".into())
                            })?;
                        let entry = Entry::decode(payload).map_err(KernelError::from)?;
                        if entry.proposal.book_id != book.book_id
                            || entry.proposal.branch_id != Id128::TRUNK
                        {
                            return Err(KernelError::Corrupt(
                                "delta Entry coordinate is not this trunk book".into(),
                            )
                            .into());
                        }
                        entries_decoded = entries_decoded
                            .checked_add(1)
                            .ok_or(RegisterError::Overflow)?;
                        batch_entries.push((*vid, entry));
                    }
                    DeltaRow::Property {
                        elem: ElementId::Vertex(vid),
                        property: key,
                        ..
                    } if *key == property::FA_PAYLOAD => reject_entry_mutation(db, *vid, seq)?,
                    DeltaRow::DeleteVertex { vid, .. } => reject_entry_mutation(db, *vid, seq)?,
                    DeltaRow::LabelMembership { label: l, .. } if *l == label::ENTRY => {
                        return Err(KernelError::Corrupt(
                            "delta changed immutable Entry membership".into(),
                        )
                        .into());
                    }
                    _ => {}
                }
            }
        }
        batch_entries.sort_by_key(|(vid, _)| vid.0);
        for (vid, entry) in batch_entries {
            if matches!(
                entry.proposal.control,
                Some(ControlPayload::MigrationControl {
                    kind: fa_journal::migration::kind::FINALIZE,
                    ..
                })
            ) {
                // Finalization activates chunks whose creation may
                // precede our cursor. Rebuild at this basis rather
                // than omit those newly visible old contributions.
                return Ok(Tail::Rebuild);
            }
            if !fa_journal::migration::visible_at(db, &entry, basis, &mut migration_runs)? {
                continue;
            }
            if entry.proposal.class == EntryClass::RESOLUTION {
                release(db, book, vid, &entry, seq, fold, &mut pending)?;
            }
            if entry.proposal.legs.is_empty() || crate::entry_period(book, &entry)? != period {
                continue;
            }
            fold.watermark = Some(fold.watermark.map_or(seq, |w| w.max(seq)));
            if entry.proposal.class == EntryClass::PENDING {
                match crate::add_entry(&mut pending, &entry, period, (vid, seq), basis) {
                    Ok(()) => {}
                    // Later resolutions in this same suffix may
                    // release an otherwise overflowing hold. The
                    // literal fold selects unresolved holds at
                    // the target frontier before adding them. A
                    // truly oversized final column still fails.
                    Err(RegisterError::Overflow | RegisterError::Capacity(_)) => {
                        return Ok(Tail::Rebuild);
                    }
                    Err(error) => return Err(error),
                }
                let hold_digest = crate::fold_entry_contributions([0u8; 32], seq, vid, &entry)?;
                if fold.pending_holds.insert((seq, vid), hold_digest).is_some() {
                    return Err(
                        KernelError::Corrupt("duplicate pending hold identity".into()).into(),
                    );
                }
            } else {
                fold.entries = fold.entries.checked_add(1).ok_or(RegisterError::Overflow)?;
                crate::add_entry(&mut cells, &entry, period, (vid, seq), basis)?;
                fold.posted_legs_digest =
                    crate::fold_entry_contributions(fold.posted_legs_digest, seq, vid, &entry)?;
            }
        }
    }
    fold.cells = cells.into_values().collect();
    fold.pending = pending.into_values().collect();
    fold.fold_digest = crate::digest_of(
        period,
        &fold.cells,
        &fold.pending,
        fold.watermark,
        fold.posted_legs_digest,
        &fold.pending_holds,
    )?;
    Ok(Tail::Applied(entries_decoded))
}

/// Compute a new projection without writing it. Rehydrate checkpoint-opened
/// delta history explicitly; an actually retired cursor triggers a full fold.
pub async fn prepare_advance<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    period: &str,
) -> Result<PreparedAdvance, RegisterError> {
    let basis = db.frontier()?;
    crate::period_at(db, book, period, basis)?;
    let (from, mut fold, expected_state) = match load(db, book, period)? {
        Some((through, fold, payload)) => (through, fold, Some(payload)),
        None => (CommitSeq::ORIGIN, empty(period)?, None),
    };
    if let Err(error) = db.ensure_delta_window(&ctx.commit(), from).await {
        return match error {
            fgdb::RebuildError::Index {
                error: IndexError::CursorRetired { .. },
                ..
            } => prepare_rebuild(db, book, period),
            other => Err(fgdb::WriteError::from(other).into()),
        };
    }
    let entries_decoded = match apply_tail(db, book, period, basis, from, &mut fold)? {
        Tail::Applied(decoded) => decoded,
        Tail::Rebuild => return prepare_rebuild(db, book, period),
    };
    // Repeated calls after our own maintenance write must not manufacture
    // an endless stream of empty maintenance commits.
    let wrote = expected_state.is_none() || entries_decoded != 0;
    let through = if wrote { basis } else { from };
    let policy_oid = fa_policy::Steward::embedded()
        .map_err(|e| KernelError::Corrupt(e.to_string()))?
        .policy_oid;
    let decision_card = fa_policy::decide_register_checkpoint_cadence(
        Some(policy_oid),
        policy_oid,
        period,
        from.0,
        through.0,
        entries_decoded as u64,
        fold.entries,
    );
    let decision_card_digest = decision_card.digest().map_err(RegisterError::Encoding)?;
    Ok(PreparedAdvance {
        book_id: book.book_id,
        basis,
        basis_root: db.partition_root()?.0,
        expected_state,
        result: Advance {
            period: period.into(),
            from,
            through,
            published_at: basis,
            entries_decoded,
            rebuilt: false,
            wrote,
            fold,
            decision_card,
            decision_card_digest,
        },
    })
}

fn reject_entry_mutation<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    vid: VId,
    seq: CommitSeq,
) -> Result<(), RegisterError> {
    if let Some(before) = seq.0.checked_sub(1)
        && db
            .vertex_at(vid, CommitSeq(before))?
            .is_some_and(|r| r.labels.contains(&label::ENTRY))
    {
        return Err(KernelError::Corrupt("delta changed an immutable Entry".into()).into());
    }
    Ok(())
}

fn release<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    vid: VId,
    entry: &Entry,
    seq: CommitSeq,
    fold: &mut Fold,
    pending: &mut BTreeMap<CellKey, Cell>,
) -> Result<(), RegisterError> {
    let target = entry
        .proposal
        .pending
        .as_ref()
        .and_then(|p| p.resolution_of)
        .ok_or_else(|| KernelError::Corrupt("delta resolution has no target".into()))?;
    let (hold, hold_seq) = fa_journal::post::read_entry(db, target.vid)?
        .ok_or_else(|| KernelError::Corrupt("delta resolution target missing".into()))?;
    if hold.proposal.class != EntryClass::PENDING
        || hold.entry_digest != target.entry_digest
        || hold_seq >= seq
        || vid != fa_journal::rows::resolution_vid(target.vid)
        || hold.proposal.book_id != book.book_id
        || hold.proposal.branch_id != Id128::TRUNK
    {
        return Err(
            KernelError::Corrupt("invalid delta resolution target or identity".into()).into(),
        );
    }
    if crate::entry_period(book, &hold)? != fold.period {
        return Ok(());
    }
    let mut touched = BTreeSet::new();
    for leg in &hold.proposal.legs {
        let key = CellKey {
            account: leg.account_ref,
            unit_id: leg.amount.unit.0,
            period: fold.period.clone(),
        };
        let cell = pending
            .get_mut(&key)
            .ok_or_else(|| drift("released hold is missing from pending cells"))?;
        let value = match leg.side {
            Side::Debit => &mut cell.debits,
            Side::Credit => &mut cell.credits,
        };
        *value = value
            .checked_sub(leg.amount.mantissa)
            .filter(|n| *n >= 0)
            .ok_or_else(|| drift("pending release underflow"))?;
        touched.insert(key);
    }
    for key in touched {
        let cell = pending
            .get_mut(&key)
            .ok_or_else(|| drift("released pending cell missing"))?;
        cell.entry_count = cell
            .entry_count
            .checked_sub(1)
            .ok_or_else(|| drift("pending count underflow"))?;
        if cell.entry_count == 0 {
            if cell.debits != 0 || cell.credits != 0 {
                return Err(drift("released cell has residual amount"));
            }
            pending.remove(&key);
        }
    }
    if !hold.proposal.legs.is_empty() {
        let expected_hold_digest =
            crate::fold_entry_contributions([0u8; 32], hold_seq, target.vid, &hold)?;
        if fold.pending_holds.remove(&(hold_seq, target.vid)) != Some(expected_hold_digest) {
            return Err(drift("released hold is missing from pending digest state"));
        }
        fold.watermark = Some(fold.watermark.map_or(seq, |w| w.max(seq)));
    }
    Ok(())
}

/// The period's maintenance state when it can serve a read at `basis`: its
/// identity, checksum and format agree and its cursor does not pass the
/// frontier. The cells are not read here. `None` otherwise; reads never
/// repair state.
fn servable_state<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
    basis: CommitSeq,
) -> Result<Option<(CommitSeq, Fold)>, RegisterError> {
    let Some(state) = db.vertex(state_vid(book.book_id, period))? else {
        return Ok(None);
    };
    let payload = match (
        prop(&state, property::BOOK_ID),
        prop(&state, property::EFFECTIVE_PERIOD),
        prop(&state, property::FA_PAYLOAD),
        prop(&state, property::FA_DIGEST),
    ) {
        (
            Some(CanonicalScalar::Bytes(owner)),
            Some(CanonicalScalar::Text(code)),
            Some(CanonicalScalar::Bytes(payload)),
            Some(CanonicalScalar::Bytes(digest)),
        ) if state.labels == vec![label::REGISTER_STATE]
            && owner.as_slice() == &book.book_id.0[..]
            && code.as_str() == period
            && digest.as_slice() == &state_digest(book.book_id, period, payload.as_slice())[..] =>
        {
            payload.as_slice().to_vec()
        }
        _ => return Ok(None),
    };
    let Ok((through, fold)) = decode(&payload, period) else {
        return Ok(None);
    };
    Ok((through <= basis).then_some((through, fold)))
}

/// The maintenance cursor of `period` when its state could serve a read at
/// the frontier (fa-715); a caller loads the delta window back to it.
pub fn cursor<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
) -> Result<Option<CommitSeq>, RegisterError> {
    Ok(servable_state(db, book, period, db.frontier()?)?.map(|(through, _)| through))
}

/// A period's fold at the frontier, served from its maintained cells and the
/// exact tail after their cursor, without writing (plan §5.3, fa-715).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadFold {
    pub fold: Fold,
    /// The maintenance cursor the cells were read at.
    pub served_at: CommitSeq,
    /// Entry payloads decoded for the tail after `served_at`.
    pub tail_entries: usize,
}

/// Read `period`'s fold at the frontier from its maintained cells plus the
/// exact tail since their cursor. The cells are point reads of the
/// registers of `accounts` in every unit their policies admit, so the cost
/// follows the chart and the tail, not the journal's history; the assembled
/// cells must reproduce the state's fold digest.
///
/// `None` whenever this cannot be served exactly (no or damaged state,
/// drifted cells, a delta window that no longer reaches the cursor, a tail
/// that needs a rebuild); the caller then folds the journal literally. A
/// maintained read never serves a partial answer, and it never repairs: a
/// damaged cache is reported by `verify registers`, not here.
pub fn head_fold<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
    accounts: &[AccountRow],
) -> Result<Option<HeadFold>, RegisterError> {
    let basis = db.frontier()?;
    let Some((through, mut fold)) = servable_state(db, book, period, basis)? else {
        return Ok(None);
    };
    for account in accounts {
        let units: Vec<u32> = match account.unit_policy {
            UnitPolicy::Single(unit) => vec![unit.0],
            UnitPolicy::AnyCurrency | UnitPolicy::AnyUnit => {
                book.units.iter().map(|(id, _)| id.0).collect()
            }
        };
        for unit_id in units {
            let key = CellKey {
                account: account.vid,
                unit_id,
                period: period.into(),
            };
            let Some(row) = db.vertex(crate::register_vid(book.book_id, &key))? else {
                continue;
            };
            // A retired cell keeps its identity for reuse and holds nothing;
            // a live cell missing here fails the digest below.
            if !row.labels.contains(&label::REGISTER) {
                continue;
            }
            let identity = row.labels == vec![label::REGISTER]
                && matches!(prop(&row, property::BOOK_ID), Some(CanonicalScalar::Bytes(b)) if b.as_slice() == &book.book_id.0[..])
                && matches!(prop(&row, property::ACCOUNT_REF), Some(CanonicalScalar::Bytes(b)) if b.as_slice() == &account.vid.0.to_le_bytes()[..])
                && matches!(prop(&row, property::UNIT_ID), Some(CanonicalScalar::Int(u)) if *u == i64::from(unit_id))
                && matches!(prop(&row, property::EFFECTIVE_PERIOD), Some(CanonicalScalar::Text(p)) if p.as_str() == period)
                && matches!(prop(&row, property::WATERMARK), Some(CanonicalScalar::Int(w)) if u64::try_from(*w).ok() == Some(fold.watermark.map_or(0, |s| s.0)));
            if !identity {
                return Ok(None);
            }
            for (pending, column) in [(false, &mut fold.cells), (true, &mut fold.pending)] {
                let Ok(Some((debits, credits, entry_count))) = crate::stored_values(&row, pending)
                else {
                    return Ok(None);
                };
                if debits < 0 || credits < 0 || (entry_count == 0 && (debits != 0 || credits != 0))
                {
                    return Ok(None);
                }
                if entry_count != 0 {
                    column.push(Cell {
                        key: key.clone(),
                        debits,
                        credits,
                        entry_count,
                    });
                }
            }
        }
    }
    fold.cells.sort_by(|a, b| a.key.cmp(&b.key));
    fold.pending.sort_by(|a, b| a.key.cmp(&b.key));
    if crate::digest_of(
        period,
        &fold.cells,
        &fold.pending,
        fold.watermark,
        fold.posted_legs_digest,
        &fold.pending_holds,
    )? != fold.fold_digest
    {
        return Ok(None);
    }
    match db.delta_since(through) {
        Ok(_) => {}
        Err(fgdb::ReadError::DeltaCursorRetired { .. }) => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let tail_entries = match apply_tail(db, book, period, basis, through, &mut fold)? {
        Tail::Applied(decoded) => decoded,
        Tail::Rebuild => return Ok(None),
    };
    Ok(Some(HeadFold {
        fold,
        served_at: through,
        tail_entries,
    }))
}

fn prepare_rebuild<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
) -> Result<PreparedAdvance, RegisterError> {
    let fold = crate::fold_period_at(db, book, period, None)?;
    prepare_fold(db, book, fold)
}

/// Used only with a freshly computed or independently validated literal fold.
pub(crate) fn prepare_fold<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    fold: Fold,
) -> Result<PreparedAdvance, RegisterError> {
    let basis = db.frontier()?;
    let state = db.vertex(state_vid(book.book_id, &fold.period))?;
    if state
        .as_ref()
        .is_some_and(|row| row.labels.iter().any(|l| *l != label::REGISTER_STATE))
    {
        return Err(drift(
            "maintenance identity belongs to an authoritative object",
        ));
    }
    let expected_state = state
        .as_ref()
        .and_then(|row| prop(row, property::FA_PAYLOAD).cloned());
    let policy_oid = fa_policy::Steward::embedded()
        .map_err(|e| KernelError::Corrupt(e.to_string()))?
        .policy_oid;
    let decision_card = fa_policy::decide_register_checkpoint_cadence(
        Some(policy_oid),
        policy_oid,
        &fold.period,
        CommitSeq::ORIGIN.0,
        basis.0,
        0,
        fold.entries,
    );
    let decision_card_digest = decision_card.digest().map_err(RegisterError::Encoding)?;
    Ok(PreparedAdvance {
        book_id: book.book_id,
        basis,
        basis_root: db.partition_root()?.0,
        expected_state,
        result: Advance {
            period: fold.period.clone(),
            from: CommitSeq::ORIGIN,
            through: basis,
            published_at: basis,
            entries_decoded: 0,
            rebuilt: true,
            wrote: true,
            fold,
            decision_card,
            decision_card_digest,
        },
    })
}

/// Publish cells and their cursor in one substrate write. The private basis
/// check rejects a moving journal; the CAS rejects a changed maintenance state.
pub async fn publish_advance<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    prepared: PreparedAdvance,
) -> Result<Advance, RegisterError> {
    if prepared.book_id != book.book_id
        || prepared.basis != db.frontier()?
        || prepared.basis_root != db.partition_root()?.0
    {
        return Err(RegisterError::StaleFold);
    }
    let mut result = prepared.result;
    if !result.wrote {
        return Ok(result);
    }
    let mut batch = crate::materialize_batch(db, book, &result.fold)?;
    let state = state_vid(book.book_id, &result.period);
    batch.ensure_vertex(state, vec![label::REGISTER_STATE], Vec::new());
    batch.set_vertex_label(state, label::REGISTER_STATE, true);
    batch.set_vertex_property(
        state,
        property::BOOK_ID,
        Some(scalar_bytes("book", book.book_id.0.to_vec())?),
    );
    batch.set_vertex_property(
        state,
        property::EFFECTIVE_PERIOD,
        Some(scalar_text("period", &result.period)?),
    );
    let payload = encode(result.through, &result.fold)?;
    batch.set_vertex_property(
        state,
        property::FA_DIGEST,
        Some(scalar_bytes(
            "register-state.digest",
            state_digest(book.book_id, &result.period, &payload).to_vec(),
        )?),
    );
    batch.compare_and_set_vertex_property(
        state,
        property::FA_PAYLOAD,
        prepared.expected_state,
        scalar_bytes("register-state", payload)?,
        WriteMismatchPolicy::AbortWrite,
    );
    result.published_at = db.write(&ctx.commit(), batch).await?;
    Ok(result)
}

/// Consume the new entry suffix, then atomically publish native period cells.
pub async fn advance<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    period: &str,
) -> Result<Advance, RegisterError> {
    let prepared = prepare_advance(db, ctx, book, period).await?;
    publish_advance(db, ctx, book, prepared).await
}

/// Discard the cached values and atomically replace them by a literal fold.
/// No journal object is changed or removed. A damaged cache is not an input.
pub async fn rebuild<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    period: &str,
) -> Result<Advance, RegisterError> {
    let prepared = prepare_rebuild(db, book, period)?;
    publish_advance(db, ctx, book, prepared).await
}
