//! Immutable, complete native-period register snapshots (plan §5.3, fa-9xf9).
//!
//! A checkpoint contains both amount columns and the contribution state needed
//! to continue their exact fold. It is a disposable cache, not independent
//! evidence of a balance: verification refolds the journal at `through`.
//! Roots, fragments and the latest pointer join the caller's existing atomic
//! register publication. Nothing here writes on the posting path or commits.
//! Historical lookup follows point-addressed predecessor references; it never
//! searches the book's vertices. A checkpoint does not restore a retired delta
//! suffix, and consumers must retain their literal fallback for that case.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::KernelError;
use fa_journal::genesis::BookContext;
use fa_journal::object::{self, ObjectKind};
use fa_journal::rows::{prop, scalar_bytes};
use fa_model::limits::{
    MAX_BATCH_ENTRIES, MAX_PERIOD_REF_BYTES, MAX_REGISTER_CHECKPOINT_BYTES,
    MAX_REGISTER_CHECKPOINT_CELLS,
};
use fa_model::symbols::{label, property};
use fa_model::{Id128, Reader, Writer, domain_digest};
use fa_money::UnitId;
use fgdb::{Database, WriteBatch, WriteTxnError};
use fgdb_types::{CanonicalScalar, CommitSeq, QueryCx, VId};

use crate::{Cell, CellKey, Fold, RegisterError};

const FORMAT: &[u8] = b"fa:register-checkpoint:v1";
const DEFINITION_FORMAT: &[u8] = b"fa:register-definition:native-period:v1";
const POINTER_FORMAT: &[u8] = b"fa:register-checkpoint-ref:v1";
const CELL_BYTES: usize = 16 + 4 + 16 + 16 + 8;
const HOLD_BYTES: usize = 8 + 16 + 32;
const MAX_DEFINITION_BYTES: usize = DEFINITION_FORMAT.len()
    + 16
    + 16
    + 4
    + MAX_PERIOD_REF_BYTES
    + 4
    + crate::FOLD_DIGEST_DOMAIN.len();

/// A content-bound locator within one book and native-period definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointRef {
    pub through: CommitSeq,
    pub body_digest: [u8; 32],
}

/// Complete state, rather than a reference to mutable Register vertices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub through: CommitSeq,
    pub definition_oid: [u8; 32],
    pub cells_root: [u8; 32],
    /// Distinct keys across posted and pending columns, not column rows.
    pub cell_count: u64,
    pub body_digest: [u8; 32],
    pub previous: Option<CheckpointRef>,
    pub fold: Fold,
    book_id: Id128,
}

fn drift(message: impl Into<String>) -> RegisterError {
    RegisterError::ProjectionDrift(format!("register checkpoint: {}", message.into()))
}

fn context(cx: &QueryCx) -> Result<(), RegisterError> {
    cx.checkpoint()
        .map_err(WriteTxnError::Interrupted)
        .map_err(KernelError::from)?;
    Ok(())
}

fn cache_error(error: KernelError) -> RegisterError {
    match error {
        KernelError::Corrupt(message) => drift(message),
        other => other.into(),
    }
}

fn definition_bytes(book: Id128, period: &str) -> Result<Vec<u8>, RegisterError> {
    if period.is_empty() || period.len() > MAX_PERIOD_REF_BYTES {
        return Err(drift("native-period definition has an invalid period code"));
    }
    let mut writer = Writer::new();
    writer
        .fixed(DEFINITION_FORMAT)
        .fixed(&book.0)
        .fixed(&Id128::TRUNK.0)
        .str(period)
        .bytes(crate::FOLD_DIGEST_DOMAIN);
    writer.finish().map_err(RegisterError::Encoding)
}

/// Identity of the journaled definition bytes embedded in every snapshot.
/// This definition covers native posted/pending period cells only.
pub fn definition_oid(book: Id128, period: &str) -> Result<[u8; 32], RegisterError> {
    Ok(domain_digest(
        b"fa:register-definition:v1",
        &[&definition_bytes(book, period)?],
    ))
}

/// Point-addressable immutable root; the content reference is part of its id.
#[must_use]
pub fn vid(book: Id128, period: &str, reference: CheckpointRef) -> VId {
    let digest = domain_digest(
        b"fa:vid:register-checkpoint:v1",
        &[
            &book.0,
            &(period.len() as u64).to_le_bytes(),
            period.as_bytes(),
            &reference.through.0.to_le_bytes(),
            &reference.body_digest,
        ],
    );
    let mut low = [0; 16];
    low.copy_from_slice(&digest[..16]);
    VId(u128::from_le_bytes(low))
}

/// The disposable discovery row is independent of the mutable register
/// header/cells, so their absence does not erase the retained snapshots.
#[must_use]
pub fn head_vid(book: Id128, period: &str) -> VId {
    let digest = domain_digest(
        b"fa:vid:register-checkpoint-head:v1",
        &[
            &book.0,
            &(period.len() as u64).to_le_bytes(),
            period.as_bytes(),
        ],
    );
    let mut low = [0; 16];
    low.copy_from_slice(&digest[..16]);
    VId(u128::from_le_bytes(low))
}

fn write_reference(writer: &mut Writer, reference: &CheckpointRef) {
    writer
        .u64(reference.through.0)
        .fixed(&reference.body_digest);
}

fn read_reference(reader: &mut Reader<'_>) -> Result<CheckpointRef, fa_model::DecodeError> {
    Ok(CheckpointRef {
        through: CommitSeq(reader.u64("checkpoint reference through")?),
        body_digest: reader.fixed("checkpoint reference digest")?,
    })
}

fn pointer_bytes(reference: CheckpointRef) -> Result<Vec<u8>, RegisterError> {
    let mut writer = Writer::new();
    writer.fixed(POINTER_FORMAT);
    write_reference(&mut writer, &reference);
    writer.finish().map_err(RegisterError::Encoding)
}

fn read_pointer(bytes: &[u8]) -> Result<CheckpointRef, RegisterError> {
    let read = || -> Result<_, fa_model::DecodeError> {
        let mut reader = Reader::new(bytes);
        if reader.fixed::<{ POINTER_FORMAT.len() }>("checkpoint pointer format")? != POINTER_FORMAT
        {
            return Err(reader.invalid("checkpoint pointer format"));
        }
        let reference = read_reference(&mut reader)?;
        reader.finish()?;
        Ok(reference)
    };
    read().map_err(|error| drift(error.to_string()))
}

fn write_cells(writer: &mut Writer, cells: &[Cell]) {
    writer.list(cells, |writer, cell| {
        writer
            .u128(cell.key.account.0)
            .u32(cell.key.unit_id)
            .i128(cell.debits)
            .i128(cell.credits)
            .u64(cell.entry_count);
    });
}

fn columns(fold: &Fold) -> Result<Vec<u8>, RegisterError> {
    let mut writer = Writer::new();
    writer.u8(0);
    write_cells(&mut writer, &fold.cells);
    writer.u8(1);
    write_cells(&mut writer, &fold.pending);
    writer.finish().map_err(RegisterError::Encoding)
}

fn read_cells(reader: &mut Reader<'_>, period: &str) -> Result<Vec<Cell>, fa_model::DecodeError> {
    let count = reader.count(MAX_REGISTER_CHECKPOINT_CELLS, "checkpoint cells")?;
    if count > reader.remaining() / CELL_BYTES {
        return Err(reader.invalid("checkpoint cell bytes"));
    }
    let mut cells = Vec::with_capacity(count);
    for _ in 0..count {
        let cell = Cell {
            key: CellKey {
                account: VId(reader.u128("checkpoint account")?),
                unit_id: reader.u32("checkpoint unit")?,
                period: period.into(),
            },
            debits: reader.i128("checkpoint debits")?,
            credits: reader.i128("checkpoint credits")?,
            entry_count: reader.u64("checkpoint entry count")?,
        };
        if cells
            .last()
            .is_some_and(|previous: &Cell| previous.key >= cell.key)
        {
            return Err(reader.unsorted("checkpoint cell keys"));
        }
        cells.push(cell);
    }
    Ok(cells)
}

fn validate_fold(through: CommitSeq, fold: &Fold) -> Result<u64, RegisterError> {
    if fold.cells.len() > MAX_REGISTER_CHECKPOINT_CELLS
        || fold.pending.len() > MAX_REGISTER_CHECKPOINT_CELLS
        || fold.pending_holds.len() > MAX_BATCH_ENTRIES
    {
        return Err(drift("complete state exceeds its registered count bounds"));
    }
    let holds = u64::try_from(fold.pending_holds.len()).map_err(|_| RegisterError::Overflow)?;
    for (cells, entries) in [(&fold.cells, fold.entries), (&fold.pending, holds)] {
        if !cells.windows(2).all(|pair| pair[0].key < pair[1].key)
            || cells.iter().any(|cell| {
                cell.key.period != fold.period
                    || cell.debits < 0
                    || cell.credits < 0
                    || cell.entry_count == 0
                    || cell.entry_count > entries
            })
        {
            return Err(drift("cell order, period, amounts or entry count differs"));
        }
        if cells.is_empty() != (entries == 0) {
            return Err(drift("cell columns and their entry counts disagree"));
        }
    }
    if fold.watermark.is_some_and(|watermark| watermark > through)
        || ((!fold.cells.is_empty() || !fold.pending.is_empty()) && fold.watermark.is_none())
        || fold.pending_holds.keys().any(|(seq, _)| {
            *seq > through || fold.watermark.is_none_or(|watermark| *seq > watermark)
        })
        || (fold.entries == 0 && fold.posted_legs_digest != [0; 32])
    {
        return Err(drift(
            "contribution state exceeds or disagrees with its frontier",
        ));
    }
    let count = fold
        .cells
        .iter()
        .chain(&fold.pending)
        .map(|cell| &cell.key)
        .collect::<BTreeSet<_>>()
        .len();
    if count > MAX_REGISTER_CHECKPOINT_CELLS {
        return Err(drift("distinct cell count exceeds its registered bound"));
    }
    if crate::digest_of(
        &fold.period,
        &fold.cells,
        &fold.pending,
        fold.watermark,
        fold.posted_legs_digest,
        &fold.pending_holds,
    )? != fold.fold_digest
    {
        return Err(drift("complete state does not reproduce its fold digest"));
    }
    u64::try_from(count).map_err(|_| RegisterError::Overflow)
}

impl Checkpoint {
    #[must_use]
    pub fn reference(&self) -> CheckpointRef {
        CheckpointRef {
            through: self.through,
            body_digest: self.body_digest,
        }
    }

    fn build(
        book: Id128,
        through: CommitSeq,
        fold: &Fold,
        previous: Option<CheckpointRef>,
    ) -> Result<Self, RegisterError> {
        if previous.is_some_and(|reference| reference.through >= through) {
            return Err(drift("predecessor does not precede the checkpoint"));
        }
        let cell_count = validate_fold(through, fold)?;
        let definition_oid = definition_oid(book, &fold.period)?;
        let cells_root = domain_digest(
            b"fa:register-checkpoint-cells:v1",
            &[&definition_oid, &columns(fold)?],
        );
        let mut checkpoint = Self {
            through,
            definition_oid,
            cells_root,
            cell_count,
            body_digest: [0; 32],
            previous,
            fold: fold.clone(),
            book_id: book,
        };
        let body = checkpoint.body_bytes()?;
        checkpoint.body_digest = domain_digest(b"fa:register-checkpoint-body:v1", &[&body]);
        if body.len().saturating_add(32) > MAX_REGISTER_CHECKPOINT_BYTES {
            return Err(drift("complete snapshot exceeds its registered byte bound"));
        }
        Ok(checkpoint)
    }

    fn body_bytes(&self) -> Result<Vec<u8>, RegisterError> {
        let mut writer = Writer::new();
        writer
            .fixed(FORMAT)
            .bytes(&definition_bytes(self.book_id, &self.fold.period)?)
            .fixed(&self.definition_oid)
            .u64(self.through.0)
            .opt(self.previous.as_ref(), write_reference)
            .u64(self.cell_count)
            .fixed(&self.cells_root)
            .opt(self.fold.watermark.as_ref(), |writer, watermark| {
                writer.u64(watermark.0);
            })
            .u64(self.fold.entries)
            .fixed(&self.fold.fold_digest)
            .fixed(&self.fold.posted_legs_digest);
        let holds: Vec<_> = self.fold.pending_holds.iter().collect();
        writer.list(&holds, |writer, ((seq, entry), digest)| {
            writer.u64(seq.0).u128(entry.0).fixed(*digest);
        });
        writer.fixed(&columns(&self.fold)?);
        writer.finish().map_err(RegisterError::Encoding)
    }

    fn encode(&self) -> Result<Vec<u8>, RegisterError> {
        let mut bytes = self.body_bytes()?;
        bytes.extend_from_slice(&self.body_digest);
        if bytes.len() > MAX_REGISTER_CHECKPOINT_BYTES {
            return Err(drift("complete snapshot exceeds its registered byte bound"));
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8], book: Id128, period: &str) -> Result<Self, RegisterError> {
        if bytes.len() > MAX_REGISTER_CHECKPOINT_BYTES {
            return Err(drift("snapshot exceeds its registered byte bound"));
        }
        let definition = definition_bytes(book, period)?;
        let read = || -> Result<_, fa_model::DecodeError> {
            let mut reader = Reader::new(bytes);
            if reader.fixed::<{ FORMAT.len() }>("checkpoint format")? != FORMAT
                || reader.bytes(MAX_DEFINITION_BYTES, "checkpoint definition")? != definition
            {
                return Err(reader.invalid("checkpoint format or native-period definition"));
            }
            let definition_oid = reader.fixed("checkpoint definition oid")?;
            let through = CommitSeq(reader.u64("checkpoint through")?);
            let previous = reader.opt("checkpoint predecessor", read_reference)?;
            let cell_count = reader.u64("checkpoint cell count")?;
            let cells_root = reader.fixed("checkpoint cells root")?;
            let watermark = reader.opt("checkpoint watermark", |reader| {
                Ok(CommitSeq(reader.u64("checkpoint watermark")?))
            })?;
            let entries = reader.u64("checkpoint contributing entries")?;
            let fold_digest = reader.fixed("checkpoint fold digest")?;
            let posted_legs_digest = reader.fixed("checkpoint posted contribution digest")?;
            let count = reader.count(MAX_BATCH_ENTRIES, "checkpoint pending holds")?;
            if count > reader.remaining() / HOLD_BYTES {
                return Err(reader.invalid("checkpoint pending hold bytes"));
            }
            let mut pending_holds = BTreeMap::new();
            for _ in 0..count {
                let seq = CommitSeq(reader.u64("checkpoint pending sequence")?);
                let entry = VId(reader.u128("checkpoint pending entry")?);
                let digest = reader.fixed("checkpoint pending contribution digest")?;
                let key = (seq, entry);
                if pending_holds
                    .last_key_value()
                    .is_some_and(|(previous, _)| *previous >= key)
                {
                    return Err(reader.unsorted("checkpoint pending holds"));
                }
                pending_holds.insert(key, digest);
            }
            if reader.u8("checkpoint posted column")? != 0 {
                return Err(reader.invalid("checkpoint posted column"));
            }
            let cells = read_cells(&mut reader, period)?;
            if reader.u8("checkpoint pending column")? != 1 {
                return Err(reader.invalid("checkpoint pending column"));
            }
            let pending = read_cells(&mut reader, period)?;
            let body_digest = reader.fixed("checkpoint body digest")?;
            reader.finish()?;
            Ok(Self {
                through,
                definition_oid,
                cells_root,
                cell_count,
                body_digest,
                previous,
                fold: Fold {
                    period: period.into(),
                    cells,
                    pending,
                    watermark,
                    entries,
                    fold_digest,
                    posted_legs_digest,
                    pending_holds,
                },
                book_id: book,
            })
        };
        let decoded = read().map_err(|error| drift(error.to_string()))?;
        let expected = Self::build(book, decoded.through, &decoded.fold, decoded.previous)?;
        if decoded != expected || decoded.encode()? != bytes {
            return Err(drift("canonical snapshot commitments differ"));
        }
        Ok(decoded)
    }
}

fn load_with_birth<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    period: &str,
    reference: CheckpointRef,
    at: CommitSeq,
) -> Result<(Checkpoint, CommitSeq), RegisterError> {
    context(cx)?;
    crate::resolve_known_at(db, Some(at))?;
    let root = vid(book.book_id, period, reference);
    let row = db
        .vertex_at(root, at)?
        .ok_or_else(|| drift("referenced immutable root is absent"))?;
    let before = row
        .created_at
        .0
        .checked_sub(1)
        .map(CommitSeq)
        .ok_or_else(|| drift("root has no original creating commit"))?;
    if row.labels.as_slice() != [label::REGISTER_CHECKPOINT]
        || row.props.len() != 3
        || row.retired_at.is_some()
        || reference.through >= row.created_at
        || !matches!(prop(&row, property::BOOK_ID), Some(CanonicalScalar::Bytes(bytes)) if bytes.as_slice() == book.book_id.0)
        || !matches!(prop(&row, property::FA_DIGEST), Some(CanonicalScalar::Bytes(bytes)) if bytes.as_slice() == reference.body_digest)
        || db.vertex_at(root, before)?.is_some()
        || db.vertex_at(root, row.created_at)?.as_ref() != Some(&row)
    {
        return Err(drift(
            "root identity, coordinate or immutable birth differs",
        ));
    }
    let bytes = object::read(
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
    let checkpoint = Checkpoint::decode(&bytes, book.book_id, period)?;
    if checkpoint.reference() != reference
        || checkpoint
            .fold
            .cells
            .iter()
            .chain(&checkpoint.fold.pending)
            .any(|cell| book.units.get(UnitId(cell.key.unit_id)).is_none())
    {
        return Err(drift("reference or native unit definition differs"));
    }
    Ok((checkpoint, row.created_at))
}

/// Load one immutable root and all its chunks at the same storage snapshot.
/// This establishes cache integrity; it does not refold the journal.
pub fn load<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    period: &str,
    reference: CheckpointRef,
    at: CommitSeq,
) -> Result<Checkpoint, RegisterError> {
    load_with_birth(db, cx, book, period, reference, at).map(|(checkpoint, _)| checkpoint)
}

fn read_head<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    period: &str,
    at: CommitSeq,
) -> Result<Option<(CheckpointRef, CommitSeq)>, RegisterError> {
    context(cx)?;
    crate::resolve_known_at(db, Some(at))?;
    let Some(state) = db.vertex_at(head_vid(book.book_id, period), at)? else {
        return Ok(None);
    };
    if state.labels.as_slice() != [label::REGISTER_STATE]
        || !matches!(prop(&state, property::BOOK_ID), Some(CanonicalScalar::Bytes(bytes)) if bytes.as_slice() == book.book_id.0)
        || !matches!(prop(&state, property::EFFECTIVE_PERIOD), Some(CanonicalScalar::Text(code)) if code.as_str() == period)
    {
        return Err(drift("latest pointer's maintenance coordinate differs"));
    }
    let encoded = prop(&state, property::TARGET_REF)
        .ok_or_else(|| drift("checkpoint head has no latest pointer"))?;
    let CanonicalScalar::Bytes(encoded) = encoded else {
        return Err(drift("latest pointer is not canonical bytes"));
    };
    let reference = read_pointer(encoded.as_slice())?;
    if reference.through >= state.created_at {
        return Err(drift(
            "latest pointer's frontier does not precede publication",
        ));
    }
    Ok(Some((reference, state.created_at)))
}

/// Read only the bounded latest pointer, for preparing an unloaded delta
/// window. This does not load or validate the full checkpoint: a consumer must
/// still use `load` before accepting any cached accounting state.
pub fn latest_ref<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    period: &str,
    at: CommitSeq,
) -> Result<Option<CheckpointRef>, RegisterError> {
    read_head(db, cx, book, period, at).map(|head| head.map(|(reference, _)| reference))
}

/// Read the pointer on the dedicated checkpoint-head maintenance row. Its
/// absence returns `None`; existing FARSv2 register headers are unchanged.
pub fn load_latest<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    period: &str,
    at: CommitSeq,
) -> Result<Option<Checkpoint>, RegisterError> {
    let Some((reference, pointer_at)) = read_head(db, cx, book, period, at)? else {
        return Ok(None);
    };
    let (checkpoint, born) = load_with_birth(db, cx, book, period, reference, at)?;
    if born > pointer_at {
        return Err(drift("latest pointer predates its checkpoint publication"));
    }
    Ok(Some(checkpoint))
}

/// Find the nearest complete snapshot through `target`, observing storage at
/// `at`. A checkpoint may be published after its input frontier. Its storage
/// visibility and the report's known-at are therefore distinct coordinates.
/// Lookup work is proportional to predecessor checkpoints visited, with a
/// cancellation checkpoint per hop; journal history is never scanned here.
pub fn latest_before<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    period: &str,
    at: CommitSeq,
    target: CommitSeq,
) -> Result<Option<Checkpoint>, RegisterError> {
    if target > at {
        return Err(RegisterError::InvalidSelection(
            "checkpoint target exceeds its storage snapshot".into(),
        ));
    }
    let Some(mut checkpoint) = load_latest(db, cx, book, period, at)? else {
        return Ok(None);
    };
    while checkpoint.through > target {
        let Some(previous) = checkpoint.previous else {
            return Ok(None);
        };
        // decode/build already enforce strict decrease, so this walk cannot
        // cycle or skip a malformed link under a later valid checkpoint.
        checkpoint = load(db, cx, book, period, previous, at)?;
    }
    Ok(Some(checkpoint))
}

/// Stage an immutable snapshot, its fragments and the latest pointer in the
/// caller's existing register publication. The caller owns authority, an
/// independently validated fold, the unchanged journal basis and publication
/// of the matching cells/FARS header in this same batch.
///
/// `reset_chain` is for an explicit literal repair: it starts a new chain
/// without trusting the old pointer or predecessor. Old immutable objects are
/// preserved. Ordinary advances refuse a malformed predecessor.
#[allow(clippy::too_many_arguments)]
pub fn stage<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    batch: &mut WriteBatch,
    through: CommitSeq,
    fold: &Fold,
    reset_chain: bool,
) -> Result<Checkpoint, RegisterError> {
    context(cx)?;
    let at = db.frontier()?;
    if through > at {
        return Err(RegisterError::StaleFold);
    }
    crate::period_at(db, book, &fold.period, through)?;
    if fold
        .cells
        .iter()
        .chain(&fold.pending)
        .any(|cell| book.units.get(UnitId(cell.key.unit_id)).is_none())
    {
        return Err(drift("snapshot uses an unregistered native unit"));
    }
    let head = head_vid(book.book_id, &fold.period);
    if db.vertex(head)?.is_some_and(|row| {
        row.labels
            .iter()
            .any(|label| *label != label::REGISTER_STATE)
    }) {
        return Err(drift(
            "checkpoint head also belongs to an authoritative object",
        ));
    }
    let previous = if reset_chain {
        None
    } else {
        load_latest(db, cx, book, &fold.period, at)?.map(|checkpoint| checkpoint.reference())
    };
    let checkpoint = Checkpoint::build(book.book_id, through, fold, previous)?;
    let root = vid(book.book_id, &fold.period, checkpoint.reference());
    if db.vertex(root)?.is_some() {
        if load(db, cx, book, &fold.period, checkpoint.reference(), at)? != checkpoint {
            return Err(drift("existing immutable root differs"));
        }
    } else {
        let bytes = checkpoint.encode()?;
        object::stage(
            cx,
            batch,
            book.book_id,
            root,
            label::REGISTER_CHECKPOINT,
            ObjectKind::RegisterCheckpoint,
            &bytes,
        )
        .map_err(cache_error)?;
        batch.create_vertex(
            root,
            vec![label::REGISTER_CHECKPOINT],
            vec![
                (
                    property::BOOK_ID,
                    scalar_bytes("checkpoint book", book.book_id.0.to_vec())?,
                ),
                (
                    property::FA_PAYLOAD,
                    scalar_bytes(
                        "checkpoint body",
                        object::payload(ObjectKind::RegisterCheckpoint, &bytes)?,
                    )?,
                ),
                (
                    property::FA_DIGEST,
                    scalar_bytes("checkpoint digest", checkpoint.body_digest.to_vec())?,
                ),
            ],
        );
    }
    batch.ensure_vertex(head, vec![label::REGISTER_STATE], Vec::new());
    batch.set_vertex_label(head, label::REGISTER_STATE, true);
    batch.set_vertex_property(
        head,
        property::BOOK_ID,
        Some(scalar_bytes(
            "checkpoint head book",
            book.book_id.0.to_vec(),
        )?),
    );
    batch.set_vertex_property(
        head,
        property::EFFECTIVE_PERIOD,
        Some(fa_journal::rows::scalar_text(
            "checkpoint head period",
            &fold.period,
        )?),
    );
    batch.set_vertex_property(
        head,
        property::TARGET_REF,
        Some(scalar_bytes(
            "latest register checkpoint",
            pointer_bytes(checkpoint.reference())?,
        )?),
    );
    Ok(checkpoint)
}

#[cfg(test)]
#[path = "checkpoint/tests.rs"]
mod tests;
