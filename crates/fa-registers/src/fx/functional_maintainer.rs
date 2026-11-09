//! Maintained, unfiltered functional period activity (plan §5.3).
//!
//! A complete immutable snapshot contains both amount columns, legal-entity
//! keys and the contribution state needed to continue the literal fold. The
//! snapshot and its discovery pointer publish atomically, off the posting
//! path. The native register and every report/certificate encoding stay
//! unchanged. Stock, dimension and class-excluded folds remain literal.
//!
//! This is a disposable projection, not a proof of the journal. A read checks
//! cache integrity and an exact retained suffix; `verify` independently folds
//! the claimed prefix. Missing, damaged or unservable caches yield `None` so
//! callers retain the authoritative literal fallback. Certification must use
//! that independent fold, not accept a cache checksum as source evidence.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::KernelError;
use fa_journal::genesis::{BookContext, BookSpec};
use fa_journal::object::{self, ObjectKind};
use fa_journal::rows::{book_root, bytes, prop, scalar_bytes, scalar_text};
use fa_model::limits::{
    MAX_BATCH_ENTRIES, MAX_PERIOD_REF_BYTES, MAX_REGISTER_CHECKPOINT_BYTES,
    MAX_REGISTER_CHECKPOINT_CELLS,
};
use fa_model::symbols::{label, property, relation};
use fa_model::{ControlPayload, Entry, EntryClass, Id128, Reader, Writer, domain_digest};
use fa_money::UnitId;
use fgdb::{Database, WriteBatch, WriteMismatchPolicy};
use fgdb_delta_types::{DeltaRow, ElementId, IndexError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, ObjectId, QueryCx, VId};

use super::{
    FunctionalCell, FunctionalCellKey, FunctionalFold, FunctionalFoldWork, FunctionalState,
    add_functional_entry, digest_of, fold_functional_entry_contributions,
    literal_period_functional_state,
};
use crate::RegisterError;

const FORMAT: &[u8] = b"fa:register-functional-period-checkpoint:v1";
const POINTER_FORMAT: &[u8] = b"fa:register-functional-period-pointer:v1";
// The BookSpec codec admits entity codes of at most 32 bytes.
const MAX_ENTITY_CODE_BYTES: usize = 32;
const MIN_CELL_BYTES: usize = 16 + 1 + 16 + 16 + 8;
const HOLD_BYTES: usize = 8 + 16 + 32;

/// Content-addressed complete functional state at an input frontier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointRef {
    pub through: CommitSeq,
    pub body_digest: [u8; 32],
}

/// Work performed by one explicit off-path maintenance publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advance {
    pub period: String,
    pub from: CommitSeq,
    pub through: CommitSeq,
    pub published_at: CommitSeq,
    /// Entry payloads decoded by the selected successful continuation or
    /// rebuild, including controls and unrelated periods. A rebuild counts
    /// its full selected prefix. Discarded tail attempts and pending target
    /// point reads are additional work, outside this counter.
    pub entries_decoded: usize,
    /// Selected legs added by that successful continuation or rebuild;
    /// discarded tail attempts are additional work, as above.
    pub legs_folded: u64,
    pub rebuilt: bool,
    pub wrote: bool,
    /// A complete immutable snapshot accompanies every substantive advance.
    pub checkpoint: Option<CheckpointRef>,
    pub fold: FunctionalFold,
}

/// A read-only preparation is bound to the entire committed basis. Dropping
/// it changes nothing; any intervening write makes publication stale.
#[derive(Debug)]
pub struct PreparedAdvance {
    book: Id128,
    basis: CommitSeq,
    basis_root: ObjectId,
    expected_pointer: Option<CanonicalScalar>,
    snapshot: Snapshot,
    result: Advance,
}

/// A checked projection plus the exact retained tail at a selected snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadFold {
    pub fold: FunctionalFold,
    pub served_at: CommitSeq,
    pub tail_entries: usize,
    pub checkpoint: CheckpointRef,
}

/// An absent cache is not corruption, and does not prove a processed prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verification {
    pub available: bool,
    pub through: Option<CommitSeq>,
    pub drift: Vec<String>,
}

impl Verification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.drift.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    book: Id128,
    through: CommitSeq,
    spec_digest: [u8; 32],
    previous: Option<CheckpointRef>,
    state: FunctionalState,
}

fn drift(message: impl Into<String>) -> RegisterError {
    RegisterError::ProjectionDrift(format!("functional register: {}", message.into()))
}

fn context(cx: &QueryCx) -> Result<(), RegisterError> {
    cx.checkpoint()
        .map_err(fgdb::WriteTxnError::Interrupted)
        .map_err(KernelError::from)?;
    Ok(())
}

fn cache_error(error: KernelError) -> RegisterError {
    match error {
        KernelError::Corrupt(message) => drift(message),
        other => other.into(),
    }
}

fn low_vid(digest: [u8; 32]) -> VId {
    let mut low = [0; 16];
    low.copy_from_slice(&digest[..16]);
    VId(u128::from_le_bytes(low))
}

/// The functional namespace cannot alias native cells or checkpoint heads.
#[must_use]
pub fn head_vid(book: Id128, period: &str) -> VId {
    low_vid(domain_digest(
        b"fa:vid:register-functional-period-head:v1",
        &[&book.0, period.as_bytes()],
    ))
}

#[must_use]
pub fn checkpoint_vid(book: Id128, period: &str, reference: CheckpointRef) -> VId {
    low_vid(domain_digest(
        b"fa:vid:register-functional-period-checkpoint:v1",
        &[
            &book.0,
            period.as_bytes(),
            &reference.through.0.to_le_bytes(),
            &reference.body_digest,
        ],
    ))
}

fn write_reference(writer: &mut Writer, reference: &CheckpointRef) {
    writer
        .u64(reference.through.0)
        .fixed(&reference.body_digest);
}

fn read_reference(reader: &mut Reader<'_>) -> Result<CheckpointRef, fa_model::DecodeError> {
    Ok(CheckpointRef {
        through: CommitSeq(reader.u64("functional checkpoint through")?),
        body_digest: reader.fixed("functional checkpoint digest")?,
    })
}

fn pointer_bytes(reference: CheckpointRef) -> Result<Vec<u8>, RegisterError> {
    let mut writer = Writer::new();
    writer.fixed(POINTER_FORMAT);
    write_reference(&mut writer, &reference);
    writer.finish().map_err(RegisterError::Encoding)
}

fn read_pointer(encoded: &[u8]) -> Result<CheckpointRef, RegisterError> {
    let read = || -> Result<_, fa_model::DecodeError> {
        let mut reader = Reader::new(encoded);
        if reader.fixed::<{ POINTER_FORMAT.len() }>("functional pointer format")? != POINTER_FORMAT
        {
            return Err(reader.invalid("functional pointer format"));
        }
        let reference = read_reference(&mut reader)?;
        reader.finish()?;
        Ok(reference)
    };
    read().map_err(|error| drift(error.to_string()))
}

fn spec_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    at: CommitSeq,
) -> Result<(BookSpec, [u8; 32]), RegisterError> {
    let root = db
        .vertex_at(book_root(), at)?
        .filter(|row| row.labels.contains(&label::BOOK))
        .ok_or_else(|| {
            RegisterError::InvalidSelection(format!("the book does not exist at sequence {}", at.0))
        })?;
    let encoded = bytes(&root, property::FA_PAYLOAD, "functional book payload")?;
    let spec = BookSpec::decode(&encoded)?;
    if spec.book_id != book.book_id || spec.calendar != book.calendar {
        return Err(KernelError::Corrupt(
            "functional fold context differs from the book at its selected sequence".into(),
        )
        .into());
    }
    Ok((
        spec,
        domain_digest(b"fa:register-functional-period-book:v1", &[&encoded]),
    ))
}

fn refresh(state: &mut FunctionalState) -> Result<(), RegisterError> {
    let fold = &mut state.fold;
    fold.fold_digest = digest_of(
        &fold.period,
        fold.base_unit,
        &fold.cells,
        &fold.pending,
        fold.watermark,
        state.posted_legs_digest,
        &state.pending_holds,
    )?;
    Ok(())
}

fn validate(snapshot: &Snapshot) -> Result<(), RegisterError> {
    let state = &snapshot.state;
    let fold = &state.fold;
    if fold.period.is_empty()
        || fold.period.len() > MAX_PERIOD_REF_BYTES
        || fold.known_at != snapshot.through
        || snapshot
            .previous
            .is_some_and(|previous| previous.through >= snapshot.through)
        || state.pending_holds.len() > MAX_BATCH_ENTRIES
        || fold.watermark.is_some_and(|at| at > snapshot.through)
        || state.pending_holds.keys().any(|(at, _)| {
            *at > snapshot.through || fold.watermark.is_none_or(|watermark| *at > watermark)
        })
        || (fold.entries == 0 && state.posted_legs_digest != [0; 32])
    {
        return Err(drift("invalid definition, frontier or contribution state"));
    }
    let held = u64::try_from(state.pending_holds.len()).map_err(|_| RegisterError::Overflow)?;
    for (cells, entries) in [(&fold.cells, fold.entries), (&fold.pending, held)] {
        if cells.len() > MAX_REGISTER_CHECKPOINT_CELLS
            || !cells.windows(2).all(|pair| pair[0].key < pair[1].key)
            || cells.is_empty() != (entries == 0)
            || cells.iter().any(|cell| {
                cell.key.period != fold.period
                    || cell.key.unit_id != fold.base_unit.0
                    || cell.key.entity.as_ref().is_some_and(|entity| {
                        entity.is_empty() || entity.len() > MAX_ENTITY_CODE_BYTES
                    })
                    || cell.debits < 0
                    || cell.credits < 0
                    || cell.entry_count == 0
                    || cell.entry_count > entries
            })
        {
            return Err(drift(
                "invalid cell order, coordinate, amounts or entry counts",
            ));
        }
    }
    if ((!fold.cells.is_empty() || !fold.pending.is_empty()) && fold.watermark.is_none())
        || fold
            .cells
            .iter()
            .chain(&fold.pending)
            .map(|cell| &cell.key)
            .collect::<BTreeSet<_>>()
            .len()
            > MAX_REGISTER_CHECKPOINT_CELLS
    {
        return Err(drift(
            "cell population disagrees with its bound or watermark",
        ));
    }
    let mut checked = state.clone();
    refresh(&mut checked)?;
    if checked.fold.fold_digest != fold.fold_digest {
        return Err(drift(
            "complete state does not reproduce its functional fold digest",
        ));
    }
    Ok(())
}

fn write_cells(writer: &mut Writer, cells: &[FunctionalCell]) {
    writer.list(cells, |writer, cell| {
        writer
            .u128(cell.key.account.0)
            .opt(cell.key.entity.as_ref(), |writer, entity| {
                writer.str(entity);
            })
            .i128(cell.debits)
            .i128(cell.credits)
            .u64(cell.entry_count);
    });
}

fn read_cells(
    reader: &mut Reader<'_>,
    period: &str,
    base: UnitId,
) -> Result<Vec<FunctionalCell>, fa_model::DecodeError> {
    let count = reader.count(MAX_REGISTER_CHECKPOINT_CELLS, "functional checkpoint cells")?;
    if count > reader.remaining() / MIN_CELL_BYTES {
        return Err(reader.invalid("functional checkpoint cell bytes"));
    }
    let mut cells = Vec::with_capacity(count);
    for _ in 0..count {
        cells.push(FunctionalCell {
            key: FunctionalCellKey {
                account: VId(reader.u128("functional checkpoint account")?),
                unit_id: base.0,
                period: period.into(),
                entity: reader.opt("functional checkpoint entity", |reader| {
                    Ok(reader
                        .str(MAX_ENTITY_CODE_BYTES, "functional checkpoint entity")?
                        .into())
                })?,
            },
            debits: reader.i128("functional checkpoint debits")?,
            credits: reader.i128("functional checkpoint credits")?,
            entry_count: reader.u64("functional checkpoint entry count")?,
        });
    }
    Ok(cells)
}

impl Snapshot {
    fn encode(&self) -> Result<Vec<u8>, RegisterError> {
        validate(self)?;
        let state = &self.state;
        let fold = &state.fold;
        let mut writer = Writer::new();
        writer
            .fixed(FORMAT)
            .fixed(&self.book.0)
            .fixed(&Id128::TRUNK.0)
            .str(&fold.period)
            .u32(fold.base_unit.0)
            .fixed(&self.spec_digest)
            .u64(self.through.0)
            .opt(self.previous.as_ref(), write_reference)
            .opt(fold.watermark.as_ref(), |writer, at| {
                writer.u64(at.0);
            })
            .u64(fold.entries)
            .fixed(&fold.fold_digest)
            .fixed(&state.posted_legs_digest);
        let holds: Vec<_> = state.pending_holds.iter().collect();
        writer.list(&holds, |writer, ((at, entry), digest)| {
            writer.u64(at.0).u128(entry.0).fixed(*digest);
        });
        writer.u8(0);
        write_cells(&mut writer, &fold.cells);
        writer.u8(1);
        write_cells(&mut writer, &fold.pending);
        let encoded = writer.finish().map_err(RegisterError::Encoding)?;
        if encoded.len() > MAX_REGISTER_CHECKPOINT_BYTES {
            return Err(drift("complete snapshot exceeds the registered byte bound"));
        }
        Ok(encoded)
    }

    fn decode(encoded: &[u8], book: Id128, period: &str) -> Result<Self, RegisterError> {
        if encoded.len() > MAX_REGISTER_CHECKPOINT_BYTES {
            return Err(drift("complete snapshot exceeds the registered byte bound"));
        }
        let read = || -> Result<_, fa_model::DecodeError> {
            let mut reader = Reader::new(encoded);
            if reader.fixed::<{ FORMAT.len() }>("functional checkpoint format")? != FORMAT
                || reader.fixed::<16>("functional checkpoint book")? != book.0
                || reader.fixed::<16>("functional checkpoint branch")? != Id128::TRUNK.0
                || reader.str(MAX_PERIOD_REF_BYTES, "functional checkpoint period")? != period
            {
                return Err(reader.invalid("functional checkpoint definition"));
            }
            let base_unit = UnitId(reader.u32("functional checkpoint base unit")?);
            let spec_digest = reader.fixed("functional checkpoint book digest")?;
            let through = CommitSeq(reader.u64("functional checkpoint through")?);
            let previous = reader.opt("functional checkpoint predecessor", read_reference)?;
            let watermark = reader.opt("functional checkpoint watermark", |reader| {
                Ok(CommitSeq(reader.u64("functional checkpoint watermark")?))
            })?;
            let entries = reader.u64("functional checkpoint entries")?;
            let fold_digest = reader.fixed("functional checkpoint fold digest")?;
            let posted_legs_digest = reader.fixed("functional checkpoint contribution digest")?;
            let count = reader.count(MAX_BATCH_ENTRIES, "functional checkpoint pending holds")?;
            if count > reader.remaining() / HOLD_BYTES {
                return Err(reader.invalid("functional checkpoint pending hold bytes"));
            }
            let mut pending_holds = BTreeMap::new();
            let mut previous_hold = None;
            for _ in 0..count {
                let key = (
                    CommitSeq(reader.u64("functional hold sequence")?),
                    VId(reader.u128("functional hold identity")?),
                );
                let digest = reader.fixed("functional hold contribution")?;
                if previous_hold.is_some_and(|previous| previous >= key) {
                    return Err(reader.unsorted("functional pending holds"));
                }
                previous_hold = Some(key);
                pending_holds.insert(key, digest);
            }
            if reader.u8("functional posted column")? != 0 {
                return Err(reader.invalid("functional posted column"));
            }
            let cells = read_cells(&mut reader, period, base_unit)?;
            if reader.u8("functional pending column")? != 1 {
                return Err(reader.invalid("functional pending column"));
            }
            let pending = read_cells(&mut reader, period, base_unit)?;
            reader.finish()?;
            Ok(Self {
                book,
                through,
                spec_digest,
                previous,
                state: FunctionalState {
                    fold: FunctionalFold {
                        period: period.into(),
                        base_unit,
                        known_at: through,
                        cells,
                        pending,
                        watermark,
                        entries,
                        fold_digest,
                    },
                    posted_legs_digest,
                    pending_holds,
                },
            })
        };
        let snapshot = read().map_err(|error| drift(error.to_string()))?;
        validate(&snapshot)?;
        Ok(snapshot)
    }
}

fn body_digest(encoded: &[u8]) -> [u8; 32] {
    domain_digest(b"fa:register-functional-period-body:v1", &[encoded])
}

fn read_head<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
    at: CommitSeq,
) -> Result<Option<(CheckpointRef, CommitSeq)>, RegisterError> {
    let Some(row) = db.vertex_at(head_vid(book.book_id, period), at)? else {
        return Ok(None);
    };
    if row.labels.as_slice() != [label::REGISTER_STATE]
        || !matches!(prop(&row, property::BOOK_ID), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == book.book_id.0)
        || !matches!(prop(&row, property::EFFECTIVE_PERIOD), Some(CanonicalScalar::Text(value)) if value.as_str() == period)
    {
        return Err(drift(
            "discovery pointer has a different identity or coordinate",
        ));
    }
    let encoded = bytes(&row, property::TARGET_REF, "functional register pointer")?;
    let reference = read_pointer(&encoded)?;
    if reference.through >= row.created_at {
        return Err(drift("pointer frontier does not precede publication"));
    }
    Ok(Some((reference, row.created_at)))
}

fn load<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    period: &str,
    reference: CheckpointRef,
    at: CommitSeq,
) -> Result<(Snapshot, CommitSeq), RegisterError> {
    context(cx)?;
    let root = checkpoint_vid(book.book_id, period, reference);
    let row = db
        .vertex_at(root, at)?
        .ok_or_else(|| drift("referenced complete snapshot is absent"))?;
    let before = row
        .created_at
        .0
        .checked_sub(1)
        .map(CommitSeq)
        .ok_or_else(|| drift("snapshot has no immutable creation"))?;
    if row.labels.as_slice() != [label::REGISTER_CHECKPOINT]
        || row.props.len() != 3
        || row.retired_at.is_some()
        || reference.through >= row.created_at
        || !matches!(prop(&row, property::BOOK_ID), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == book.book_id.0)
        || !matches!(prop(&row, property::FA_DIGEST), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == reference.body_digest)
        || db.vertex_at(root, before)?.is_some()
        || db.vertex_at(root, row.created_at)?.as_ref() != Some(&row)
    {
        return Err(drift(
            "snapshot identity, coordinate or immutable creation differs",
        ));
    }
    let encoded = object::read(
        db,
        cx,
        book.book_id,
        &row,
        label::REGISTER_CHECKPOINT,
        ObjectKind::RegisterCheckpoint,
        at,
        MAX_REGISTER_CHECKPOINT_BYTES,
    )
    .map_err(cache_error)?;
    let snapshot = Snapshot::decode(&encoded, book.book_id, period)?;
    let (spec, spec_digest) =
        spec_at(db, book, reference.through).map_err(|error| match error {
            RegisterError::InvalidSelection(message) => drift(message),
            error => error,
        })?;
    if snapshot.through != reference.through
        || body_digest(&encoded) != reference.body_digest
        || snapshot.spec_digest != spec_digest
        || snapshot.state.fold.base_unit != spec.base_unit
        || book.units.get(spec.base_unit).is_none()
        || snapshot
            .state
            .fold
            .cells
            .iter()
            .chain(&snapshot.state.fold.pending)
            .any(|cell| {
                cell.key.entity.as_ref().is_some_and(|entity| {
                    !spec
                        .entities
                        .iter()
                        .any(|declared| declared.code == *entity)
                })
            })
    {
        return Err(drift(
            "snapshot differs from its reference or historical book definition",
        ));
    }
    crate::period_at(db, book, period, reference.through).map_err(|error| match error {
        RegisterError::InvalidSelection(message) => drift(message),
        error => error,
    })?;
    Ok((snapshot, row.created_at))
}

fn load_latest<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    period: &str,
    at: CommitSeq,
) -> Result<Option<(Snapshot, CheckpointRef)>, RegisterError> {
    let Some((reference, pointer_at)) = read_head(db, book, period, at)? else {
        return Ok(None);
    };
    let (snapshot, born) = load(db, cx, book, period, reference, at)?;
    if born > pointer_at {
        return Err(drift("discovery pointer predates its complete snapshot"));
    }
    Ok(Some((snapshot, reference)))
}

/// The bounded cursor can hydrate a retained suffix without decoding cells.
pub fn cursor<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
    at: CommitSeq,
) -> Result<Option<CommitSeq>, RegisterError> {
    crate::resolve_known_at(db, Some(at))?;
    Ok(read_head(db, book, period, at)?.map(|(reference, _)| reference.through))
}

enum Tail {
    Applied { entries: usize, legs: u64 },
    Rebuild,
}

fn reject_entry_mutation<V: Vfs + Clone>(
    db: &Database<V>,
    vid: VId,
    at: CommitSeq,
) -> Result<(), RegisterError> {
    if let Some(before) = at.0.checked_sub(1)
        && db.vertex_at(vid, CommitSeq(before))?.is_some_and(|row| {
            row.labels.contains(&label::ENTRY) || row.labels.contains(&label::ENTRY_FRAGMENT)
        })
    {
        return Err(KernelError::Corrupt("delta changed an immutable Entry".into()).into());
    }
    Ok(())
}

fn release<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    spec: &BookSpec,
    (vid, entry, at): (VId, &Entry, CommitSeq),
    state: &mut FunctionalState,
    pending: &mut BTreeMap<FunctionalCellKey, FunctionalCell>,
) -> Result<(), RegisterError> {
    let target = entry
        .proposal
        .pending
        .as_ref()
        .and_then(|pending| pending.resolution_of)
        .ok_or_else(|| KernelError::Corrupt("delta resolution has no pending target".into()))?;
    let (hold, held_at) = fa_journal::post::read_entry_at(db, target.vid, at)?
        .ok_or_else(|| KernelError::Corrupt("delta resolution target is absent".into()))?;
    if hold.proposal.class != EntryClass::PENDING
        || hold.entry_digest != target.entry_digest
        || held_at > at
        || vid != fa_journal::rows::resolution_vid(target.vid)
        || hold.proposal.book_id != book.book_id
        || hold.proposal.branch_id != Id128::TRUNK
    {
        return Err(
            KernelError::Corrupt("invalid delta resolution target or identity".into()).into(),
        );
    }
    let period = &state.fold.period;
    if crate::entry_period(book, &hold)? != *period || hold.proposal.legs.is_empty() {
        return Ok(());
    }
    // Derive the release from the immutable original amount/entity payload.
    // One temporary entry fold also reuses the source entity-balance law.
    let mut released = BTreeMap::new();
    add_functional_entry(
        &mut released,
        spec,
        target.vid,
        &hold,
        period,
        (held_at, at),
        None,
    )?;
    let expected =
        fold_functional_entry_contributions([0; 32], spec, held_at, target.vid, &hold, None)?;
    if state.pending_holds.remove(&(held_at, target.vid)) != Some(expected) {
        return Err(drift(
            "released hold differs from the complete pending contribution state",
        ));
    }
    for (key, released) in released {
        let cell = pending
            .get_mut(&key)
            .ok_or_else(|| drift("released hold is missing from functional pending cells"))?;
        cell.debits = cell
            .debits
            .checked_sub(released.debits)
            .filter(|value| *value >= 0)
            .ok_or_else(|| drift("functional pending debit release underflow"))?;
        cell.credits = cell
            .credits
            .checked_sub(released.credits)
            .filter(|value| *value >= 0)
            .ok_or_else(|| drift("functional pending credit release underflow"))?;
        cell.entry_count = cell
            .entry_count
            .checked_sub(released.entry_count)
            .ok_or_else(|| drift("functional pending entry count underflow"))?;
        if cell.entry_count == 0 {
            if cell.debits != 0 || cell.credits != 0 {
                return Err(drift("released functional cell retains an amount"));
            }
            pending.remove(&key);
        }
    }
    state.fold.watermark = Some(state.fold.watermark.map_or(at, |prior| prior.max(at)));
    Ok(())
}

fn apply_tail<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    spec: &BookSpec,
    from: CommitSeq,
    through: CommitSeq,
    state: &mut FunctionalState,
) -> Result<Tail, RegisterError> {
    let mut cells: BTreeMap<_, _> = state
        .fold
        .cells
        .iter()
        .cloned()
        .map(|cell| (cell.key.clone(), cell))
        .collect();
    let mut pending: BTreeMap<_, _> = state
        .fold
        .pending
        .iter()
        .cloned()
        .map(|cell| (cell.key.clone(), cell))
        .collect();
    let mut entries = 0usize;
    let mut legs = 0u64;
    let mut runs = BTreeMap::new();
    for batch in db
        .delta_since(from)?
        .take_while(|batch| batch.commit_seq() <= through)
    {
        context(cx)?;
        let at = batch.commit_seq();
        let mut members = Vec::new();
        for coordinate in batch.coordinate_entries() {
            for row in &coordinate.rows {
                match row {
                    DeltaRow::CreateVertex {
                        vid, labels, props, ..
                    } if labels.contains(&label::ENTRY) => {
                        let root = db.vertex_at(*vid, at)?.ok_or_else(|| {
                            KernelError::Corrupt("delta Entry lacks its creating row".into())
                        })?;
                        if root.created_at != at || root.labels != *labels || root.props != *props {
                            return Err(KernelError::Corrupt(
                                "delta Entry differs from its immutable creating row".into(),
                            )
                            .into());
                        }
                        let entry = fa_journal::entry_storage::decode_at(db, &root, through)?;
                        if entry.proposal.book_id != book.book_id
                            || entry.proposal.branch_id != Id128::TRUNK
                        {
                            return Err(KernelError::Corrupt(
                                "delta Entry coordinate is not this trunk book".into(),
                            )
                            .into());
                        }
                        entries = entries.checked_add(1).ok_or(RegisterError::Overflow)?;
                        members.push((*vid, entry));
                    }
                    DeltaRow::Property {
                        elem: ElementId::Vertex(vid),
                        ..
                    }
                    | DeltaRow::DeleteVertex { vid, .. } => {
                        reject_entry_mutation(db, *vid, at)?;
                    }
                    DeltaRow::LabelMembership { label: changed, .. }
                        if *changed == label::ENTRY || *changed == label::ENTRY_FRAGMENT =>
                    {
                        return Err(KernelError::Corrupt(
                            "delta changed immutable Entry membership".into(),
                        )
                        .into());
                    }
                    _ => {}
                }
            }
        }
        // A publication can create and resolve a hold in either VId order.
        // Install its holds first, then preserve VId order for posted hashes.
        members.sort_by_key(|(vid, entry)| (entry.proposal.class != EntryClass::PENDING, vid.0));
        for (vid, entry) in members {
            context(cx)?;
            if matches!(
                entry.proposal.control,
                Some(ControlPayload::MigrationControl {
                    kind: fa_journal::migration::kind::FINALIZE,
                    ..
                })
            ) {
                // Finalization makes older chunks visible. They cannot be
                // reconstructed from a suffix beginning after those chunks.
                return Ok(Tail::Rebuild);
            }
            if !fa_journal::migration::visible_at(db, &entry, through, &mut runs)? {
                continue;
            }
            if entry.proposal.class == EntryClass::RESOLUTION {
                match release(db, book, spec, (vid, &entry, at), state, &mut pending) {
                    Ok(()) => {}
                    Err(RegisterError::ProjectionDrift(_)) => return Ok(Tail::Rebuild),
                    Err(error) => return Err(error),
                }
            }
            if entry.proposal.legs.is_empty()
                || crate::entry_period(book, &entry)? != state.fold.period
            {
                continue;
            }
            state.fold.watermark = Some(state.fold.watermark.map_or(at, |prior| prior.max(at)));
            if entry.proposal.class == EntryClass::PENDING {
                match add_functional_entry(
                    &mut pending,
                    spec,
                    vid,
                    &entry,
                    &state.fold.period,
                    (at, through),
                    None,
                ) {
                    Ok(()) => {}
                    // The literal law removes every resolved hold before
                    // adding amounts. A later release can remove a temporary
                    // overflow, or an unvalued hold, in this suffix.
                    Err(
                        RegisterError::Overflow
                        | RegisterError::Capacity(_)
                        | RegisterError::ProjectionDrift(_),
                    ) => return Ok(Tail::Rebuild),
                    Err(error) => return Err(error),
                }
                let digest =
                    fold_functional_entry_contributions([0; 32], spec, at, vid, &entry, None)?;
                if state.pending_holds.insert((at, vid), digest).is_some() {
                    return Err(
                        KernelError::Corrupt("duplicate pending hold identity".into()).into(),
                    );
                }
            } else {
                add_functional_entry(
                    &mut cells,
                    spec,
                    vid,
                    &entry,
                    &state.fold.period,
                    (at, through),
                    None,
                )?;
                state.posted_legs_digest = fold_functional_entry_contributions(
                    state.posted_legs_digest,
                    spec,
                    at,
                    vid,
                    &entry,
                    None,
                )?;
                state.fold.entries = state
                    .fold
                    .entries
                    .checked_add(1)
                    .ok_or(RegisterError::Overflow)?;
            }
            legs = legs
                .checked_add(entry.proposal.legs.len() as u64)
                .ok_or(RegisterError::Overflow)?;
        }
    }
    state.fold.known_at = through;
    state.fold.cells = cells.into_values().collect();
    state.fold.pending = pending.into_values().collect();
    refresh(state)?;
    Ok(Tail::Applied { entries, legs })
}

fn rebuilt<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
    at: CommitSeq,
) -> Result<(FunctionalState, FunctionalFoldWork), RegisterError> {
    let mut work = FunctionalFoldWork::default();
    let state = literal_period_functional_state(db, book, period, Some(at), &[], None, &mut work)?;
    Ok((state, work))
}

/// Prepare exact functional activity from complete state and a retained tail.
/// A retired suffix or activation of older migration chunks refolds literally.
/// Corrupt stored state is reported; explicit `rebuild` performs recovery.
pub async fn prepare_advance<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    period: &str,
) -> Result<PreparedAdvance, RegisterError> {
    prepare(db, cx, book, period, false).await
}

async fn prepare<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    period: &str,
    force_rebuild: bool,
) -> Result<PreparedAdvance, RegisterError> {
    context(&cx.query())?;
    let basis = db.frontier()?;
    crate::period_at(db, book, period, basis)?;
    let (spec, spec_digest) = spec_at(db, book, basis)?;
    let head = db.vertex(head_vid(book.book_id, period))?;
    if head.as_ref().is_some_and(|row| {
        row.labels
            .iter()
            .any(|value| *value != label::REGISTER_STATE)
    }) {
        return Err(drift(
            "discovery identity belongs to an authoritative object",
        ));
    }
    let expected_pointer = head
        .as_ref()
        .and_then(|row| prop(row, property::TARGET_REF).cloned());
    let previous = if force_rebuild {
        None
    } else {
        load_latest(db, &cx.query(), book, period, basis)?
    };
    let from = previous
        .as_ref()
        .map_or(CommitSeq::ORIGIN, |(_, reference)| reference.through);
    let mut rebuild = force_rebuild || previous.is_none();
    let mut entries_decoded = 0;
    let mut legs_folded = 0;
    let mut state = match previous.as_ref() {
        Some((snapshot, _)) if snapshot.spec_digest == spec_digest => Some(snapshot.state.clone()),
        _ => {
            rebuild = true;
            None
        }
    };
    if !rebuild {
        match db.ensure_delta_window(&cx.commit(), from).await {
            Ok(()) => {}
            Err(fgdb::RebuildError::Index {
                error: IndexError::CursorRetired { .. },
                ..
            }) => rebuild = true,
            Err(error) => return Err(fgdb::WriteError::from(error).into()),
        }
    }
    if !rebuild {
        let current = state
            .as_mut()
            .ok_or_else(|| drift("continuation state is absent"))?;
        match apply_tail(db, &cx.query(), book, &spec, from, basis, current)? {
            Tail::Applied { entries, legs } => {
                entries_decoded = entries;
                legs_folded = legs;
            }
            Tail::Rebuild => rebuild = true,
        }
    }
    if rebuild {
        let (fresh, work) = rebuilt(db, book, period, basis)?;
        entries_decoded = work.entries_decoded;
        legs_folded = work.legs_folded;
        state = Some(fresh);
    }
    let state = state.ok_or_else(|| drift("functional preparation has no state"))?;
    let wrote = rebuild || entries_decoded != 0;
    let snapshot = Snapshot {
        book: book.book_id,
        through: basis,
        spec_digest,
        previous: if force_rebuild {
            None
        } else {
            previous.map(|(_, reference)| reference)
        },
        state,
    };
    let result = Advance {
        period: period.into(),
        from,
        through: if wrote { basis } else { from },
        published_at: basis,
        entries_decoded,
        legs_folded,
        rebuilt: rebuild,
        wrote,
        checkpoint: None,
        fold: snapshot.state.fold.clone(),
    };
    Ok(PreparedAdvance {
        book: book.book_id,
        basis,
        basis_root: db.partition_root()?.0,
        expected_pointer,
        snapshot,
        result,
    })
}

/// Publish the complete immutable object and its bounded pointer together.
/// A moving basis or changed pointer cannot expose a partly advanced cache.
pub async fn publish_advance<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    prepared: PreparedAdvance,
) -> Result<Advance, RegisterError> {
    context(&cx.query())?;
    if prepared.book != book.book_id
        || prepared.basis != db.frontier()?
        || prepared.basis_root != db.partition_root()?.0
    {
        return Err(RegisterError::StaleFold);
    }
    let mut result = prepared.result;
    if !result.wrote {
        return Ok(result);
    }
    let encoded = prepared.snapshot.encode()?;
    let reference = CheckpointRef {
        through: prepared.basis,
        body_digest: body_digest(&encoded),
    };
    let root = checkpoint_vid(book.book_id, &result.period, reference);
    let mut batch = WriteBatch::new(relation::IN_PERIOD);
    if db.vertex(root)?.is_some() {
        if load(
            db,
            &cx.query(),
            book,
            &result.period,
            reference,
            prepared.basis,
        )?
        .0 != prepared.snapshot
        {
            return Err(drift("existing immutable snapshot differs"));
        }
    } else {
        object::stage(
            &cx.query(),
            &mut batch,
            book.book_id,
            root,
            label::REGISTER_CHECKPOINT,
            ObjectKind::RegisterCheckpoint,
            &encoded,
        )?;
        batch.create_vertex(
            root,
            vec![label::REGISTER_CHECKPOINT],
            vec![
                (
                    property::BOOK_ID,
                    scalar_bytes("functional checkpoint book", book.book_id.0.to_vec())?,
                ),
                (
                    property::FA_PAYLOAD,
                    scalar_bytes(
                        "functional checkpoint body",
                        object::payload(ObjectKind::RegisterCheckpoint, &encoded)?,
                    )?,
                ),
                (
                    property::FA_DIGEST,
                    scalar_bytes(
                        "functional checkpoint digest",
                        reference.body_digest.to_vec(),
                    )?,
                ),
            ],
        );
    }
    let head = head_vid(book.book_id, &result.period);
    batch.ensure_vertex(head, vec![label::REGISTER_STATE], Vec::new());
    batch.set_vertex_label(head, label::REGISTER_STATE, true);
    batch.set_vertex_property(
        head,
        property::BOOK_ID,
        Some(scalar_bytes(
            "functional register book",
            book.book_id.0.to_vec(),
        )?),
    );
    batch.set_vertex_property(
        head,
        property::EFFECTIVE_PERIOD,
        Some(scalar_text("functional register period", &result.period)?),
    );
    batch.compare_and_set_vertex_property(
        head,
        property::TARGET_REF,
        prepared.expected_pointer,
        scalar_bytes("functional register pointer", pointer_bytes(reference)?)?,
        WriteMismatchPolicy::AbortWrite,
    );
    result.published_at = db.write(&cx.commit(), batch).await?;
    result.checkpoint = Some(reference);
    Ok(result)
}

/// Explicit off-path functional activity maintenance. Native registers are
/// unaffected, including books whose foreign entries have no base amounts.
pub async fn advance<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    period: &str,
) -> Result<Advance, RegisterError> {
    let prepared = prepare_advance(db, cx, book, period).await?;
    publish_advance(db, cx, book, prepared).await
}

/// Recover a disposable functional cache from the independent literal fold.
/// The replacement starts a new snapshot chain; historical MVCC pointers
/// still resolve their original snapshots at their observation coordinates.
pub async fn rebuild<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    period: &str,
) -> Result<Advance, RegisterError> {
    let prepared = prepare(db, cx, book, period, true).await?;
    publish_advance(db, cx, book, prepared).await
}

/// Read maintained activity at one recorded prefix. Every object and head
/// is selected at that prefix; later maintenance never supplies older facts.
/// No cache is repaired and no journal/source error is hidden by a warm read.
pub fn fold_at_with_context<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    period: &str,
    known_at: CommitSeq,
) -> Result<Option<HeadFold>, RegisterError> {
    context(cx)?;
    let basis = crate::resolve_known_at(db, Some(known_at))?;
    crate::period_at(db, book, period, basis)?;
    let (spec, spec_digest) = spec_at(db, book, basis)?;
    let (mut snapshot, reference) = match load_latest(db, cx, book, period, basis) {
        Ok(Some(value)) => value,
        Ok(None)
        | Err(
            RegisterError::ProjectionDrift(_)
            | RegisterError::InvalidSelection(_)
            | RegisterError::Kernel(KernelError::Corrupt(_)),
        ) => return Ok(None),
        Err(error) => return Err(error),
    };
    if snapshot.spec_digest != spec_digest {
        return Ok(None);
    }
    match db.delta_since(reference.through) {
        Ok(_) => {}
        Err(fgdb::ReadError::DeltaCursorRetired { .. }) => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let tail_entries = match apply_tail(
        db,
        cx,
        book,
        &spec,
        reference.through,
        basis,
        &mut snapshot.state,
    ) {
        Ok(Tail::Applied { entries, .. }) => entries,
        Ok(Tail::Rebuild) | Err(RegisterError::Overflow | RegisterError::Capacity(_)) => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    Ok(Some(HeadFold {
        fold: snapshot.state.fold,
        served_at: reference.through,
        tail_entries,
        checkpoint: reference,
    }))
}

/// Independently compare complete cached state to its literal journal prefix.
/// Coherently resealed invented cells/counts are findings, not valid evidence.
pub fn verify<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    period: &str,
    known_at: Option<CommitSeq>,
) -> Result<Verification, RegisterError> {
    context(cx)?;
    let at = crate::resolve_known_at(db, known_at)?;
    crate::period_at(db, book, period, at)?;
    let loaded = match load_latest(db, cx, book, period, at) {
        Ok(loaded) => loaded,
        Err(RegisterError::ProjectionDrift(message))
        | Err(RegisterError::Kernel(KernelError::Corrupt(message))) => {
            return Ok(Verification {
                available: true,
                through: None,
                drift: vec![message],
            });
        }
        Err(error) => return Err(error),
    };
    let Some((snapshot, reference)) = loaded else {
        return Ok(Verification {
            available: false,
            through: None,
            drift: Vec::new(),
        });
    };
    let (literal, _) = rebuilt(db, book, period, reference.through)?;
    Ok(Verification {
        available: true,
        through: Some(reference.through),
        drift: if snapshot.state == literal {
            Vec::new()
        } else {
            vec!["complete functional state disagrees with its literal journal prefix".into()]
        },
    })
}

#[cfg(test)]
#[path = "functional_maintainer_tests.rs"]
mod tests;
