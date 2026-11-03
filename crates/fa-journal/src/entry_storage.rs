//! Immutable storage fragments for canonical Entries (fa-fdt).
//!
//! An Entry remains one accounting object and one publication. Its codec and
//! digests do not depend on storage: only the root's payload property uses the
//! existing bounded object manifest when the canonical bytes exceed 4 KiB.
//! Fragments have their own label, so they can never appear as journal Entries.
//! Callers authorize the root and selector before invoking these readers.

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property};
use fa_model::{Entry, Id128, entry_mirrors};
use fgdb::{Database, VertexRow, WriteBatch, WriteTxn};
use fgdb_delta_types::PropertyKeyId;
use fgdb_types::{CanonicalScalar, CommitSeq, QueryCx, VId};

use crate::object::{self, ObjectKind};
use crate::refusal::KernelError;
use crate::rows::{bytes, prop, scalar_bytes};

/// An Entry manifest remains identifiable if a corrupt writer removes the
/// Entry label. Recognition is not authentication of its body or authority.
pub fn is_stored_entry_payload(encoded: &[u8]) -> bool {
    object::is_payload_for(ObjectKind::Entry, encoded)
}

/// A control retry may share its ordinary key namespace with a monetary
/// Entry. Reject another class from selection mirrors before observing any
/// fragments under authority that admitted only the requested control.
pub(crate) fn has_class_mirror(row: &VertexRow, class: fa_model::EntryClass) -> bool {
    row.labels.as_slice() == [label::ENTRY]
        && prop(row, property::CLASS) == Some(&CanonicalScalar::Int(i64::from(class.0)))
}

fn book_id(row: &VertexRow) -> Result<Id128, KernelError> {
    if row.labels.as_slice() != [label::ENTRY] {
        return Err(KernelError::Corrupt(
            "entry storage root has another label".into(),
        ));
    }
    let book: [u8; 16] = bytes(row, property::BOOK_ID, "entry storage book")?
        .try_into()
        .map_err(|_| KernelError::Corrupt("entry storage book has the wrong length".into()))?;
    Ok(Id128(book))
}

/// Canonical bytes at an already authorized, pinned coordinate. Historical
/// inline payloads remain accepted; manifests resolve only immutable fragments
/// born in the root's publication and matching all stored content commitments.
pub fn payload_at<V: Vfs + Clone>(
    db: &Database<V>,
    row: &VertexRow,
    at: CommitSeq,
) -> Result<Vec<u8>, KernelError> {
    if row.created_at > at || row.retired_at.is_some_and(|retired| retired <= at) {
        return Err(KernelError::Corrupt(
            "entry storage root is outside its selected prefix".into(),
        ));
    }
    object::read_bounded(
        db,
        book_id(row)?,
        row,
        label::ENTRY_FRAGMENT,
        ObjectKind::Entry,
        at,
        fa_model::limits::MAX_ENTRY_BYTES,
    )
}

/// Canonical bytes visible to a posting transaction, including earlier staged
/// atomic-batch members. This never falls back to a different committed root.
pub fn payload_staged<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    row: &VertexRow,
) -> Result<Vec<u8>, KernelError> {
    object::read_staged_bounded(
        txn,
        db,
        book_id(row)?,
        row,
        label::ENTRY_FRAGMENT,
        ObjectKind::Entry,
        fa_model::limits::MAX_ENTRY_BYTES,
    )
}

fn decoded(row: &VertexRow, payload: &[u8]) -> Result<Entry, KernelError> {
    let entry = Entry::decode(payload)?;
    if entry.proposal.book_id != book_id(row)? {
        return Err(KernelError::Corrupt(
            "entry storage book differs from canonical bytes".into(),
        ));
    }
    Ok(entry)
}

pub fn decode_at<V: Vfs + Clone>(
    db: &Database<V>,
    row: &VertexRow,
    at: CommitSeq,
) -> Result<Entry, KernelError> {
    decoded(row, &payload_at(db, row, at)?)
}

pub fn decode_staged<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    row: &VertexRow,
) -> Result<Entry, KernelError> {
    decoded(row, &payload_staged(txn, db, row)?)
}

/// Current storage representation; callers still publish the root and
/// `stage` fragments together in their original transaction.
pub fn stored_mirrors(entry: &Entry) -> Result<Vec<(PropertyKeyId, CanonicalScalar)>, KernelError> {
    let mut mirrors = entry_mirrors(entry)?;
    let stored = object::payload(ObjectKind::Entry, &entry.encode()?)?;
    for (key, value) in &mut mirrors {
        if *key == property::FA_PAYLOAD {
            *value = scalar_bytes("entry storage payload", stored)?;
            break;
        }
    }
    Ok(mirrors)
}

/// The immutable mirrors must describe this Entry exactly. Retained inline
/// entries predate fragmentation and need not be rewritten to remain valid.
pub fn mirrors_match(row: &VertexRow, entry: &Entry) -> Result<bool, KernelError> {
    let canonical = entry_mirrors(entry)?;
    if row.props == canonical {
        return Ok(true);
    }
    Ok(row.props == stored_mirrors(entry)?)
}

/// Match the payload property without rejecting additional index mirrors.
pub fn payload_mirror_matches(row: &VertexRow, entry: &Entry) -> Result<bool, KernelError> {
    let raw = entry.encode()?;
    let stored = object::payload(ObjectKind::Entry, &raw)?;
    Ok(
        matches!(prop(row, property::FA_PAYLOAD), Some(CanonicalScalar::Bytes(value))
        if value.as_slice() == raw || value.as_slice() == stored),
    )
}

pub fn stage(
    cx: &QueryCx,
    batch: &mut WriteBatch,
    entry: &Entry,
    vid: VId,
) -> Result<(), KernelError> {
    object::stage(
        cx,
        batch,
        entry.proposal.book_id,
        vid,
        label::ENTRY_FRAGMENT,
        ObjectKind::Entry,
        &entry.encode()?,
    )
}
