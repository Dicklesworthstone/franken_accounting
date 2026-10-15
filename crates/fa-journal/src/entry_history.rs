//! Entry immutability against the complete native creation history (FA-INV-02).
//!
//! A live-label scan cannot prove that an Entry was not retired or relabeled.
//! A self-consistent replacement payload cannot prove that it is the original.
//! Enumerate Entry births from every native commit through the requested
//! prefix, then bind each current row to its creating version and canonical
//! mirrors. A rewrite followed by exact restoration is still a rewrite.
//!
//! This is an in-database integrity check, not an offline proof or an assertion
//! that the entries were economically valid. The native database supplies the
//! authenticated delta history and snapshots. A missing history window is an
//! error, never a partial success. Unrelated typed objects may legitimately
//! contain bytes that happen to decode as an Entry; they are not journal entries.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property};
use fa_model::{Entry, Id128, entry_mirrors};
use fgdb::{Database, WriteTxnError};
use fgdb_delta_types::{DeltaRow, ElementId};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, QueryCx, VId};

use crate::genesis::BookContext;
use crate::refusal::KernelError;
use crate::rows::{bytes, prop};

/// Every native commit through known_at was examined, including maintenance.
/// Every Entry birth in that prefix has its original live canonical row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryHistoryVerification {
    pub known_at: CommitSeq,
    pub commits_checked: u64,
    pub entries_checked: usize,
}

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(message.into())
}

fn checkpoint(cx: &QueryCx) -> Result<(), KernelError> {
    cx.checkpoint().map_err(WriteTxnError::Interrupted)?;
    Ok(())
}

/// Verify a complete retained prefix without modifying the database. History
/// must be loaded from sequence zero; `scratch::ensure_history` is the existing
/// async loader when an opened checkpoint has only a shorter resident window.
/// Current and historical checks use the same law and never inspect later rows
/// to decide what was intact at an earlier coordinate.
pub fn verify_entry_history<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    known_at: Option<CommitSeq>,
) -> Result<EntryHistoryVerification, KernelError> {
    let query = cx.query();
    checkpoint(&query)?;
    query.with_restriction(|| verify(db, &query, book, known_at))
}

fn verify<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    known_at: Option<CommitSeq>,
) -> Result<EntryHistoryVerification, KernelError> {
    let known_at = known_at.unwrap_or(db.frontier()?);
    let rows = db.vertices_at(known_at)?;
    let current: BTreeMap<_, _> = rows.iter().map(|row| (row.vid, row)).collect();
    let mut births: BTreeMap<VId, (CommitSeq, u64)> = BTreeMap::new();
    let mut through = 0_u64;
    for batch in db.delta_since(CommitSeq(0))? {
        let sequence = batch.commit_seq();
        if sequence > known_at {
            break;
        }
        checkpoint(cx)?;
        let expected = through
            .checked_add(1)
            .ok_or_else(|| corrupt("entry history sequence overflow"))?;
        if sequence.0 != expected {
            return Err(corrupt(format!(
                "entry integrity requires complete native history: expected sequence {expected}, found {}",
                sequence.0,
            )));
        }
        // Coordinates sort canonically, not causally. Collect all births in
        // this commit before considering its label-membership rows.
        for coordinate in batch.coordinate_entries() {
            for row in &coordinate.rows {
                checkpoint(cx)?;
                if let DeltaRow::CreateVertex {
                    vid,
                    labels,
                    birth_ordinal,
                    ..
                } = row
                    && labels.contains(&label::ENTRY)
                    && births.insert(*vid, (sequence, *birth_ordinal)).is_some()
                {
                    return Err(corrupt(
                        "a journal Entry identity was created more than once",
                    ));
                }
            }
        }
        for coordinate in batch.coordinate_entries() {
            for row in &coordinate.rows {
                checkpoint(cx)?;
                if let DeltaRow::LabelMembership {
                    vid,
                    label: changed,
                    after: true,
                    ..
                } = row
                    && *changed == label::ENTRY
                    && !births.contains_key(vid)
                {
                    return Err(corrupt(format!(
                        "Entry label on {:032x} has no native Entry creation; labels cannot manufacture journal history",
                        vid.0,
                    )));
                }
                let touched = match row {
                    DeltaRow::Property {
                        elem: ElementId::Vertex(vid),
                        ..
                    }
                    | DeltaRow::LabelMembership { vid, .. }
                    | DeltaRow::DeleteVertex { vid, .. } => Some(vid),
                    _ => None,
                };
                if let Some(vid) = touched
                    && let Some((created, _)) = births.get(vid)
                    && *created < sequence
                {
                    return Err(corrupt(format!(
                        "journal Entry {:032x} was modified at {} after creation at {}; a later restoration cannot erase this history",
                        vid.0, sequence.0, created.0,
                    )));
                }
            }
        }
        through = sequence.0;
    }
    if through != known_at.0 {
        return Err(corrupt(format!(
            "entry integrity history ends at {through}, before requested prefix {}; load the complete retained native history",
            known_at.0,
        )));
    }
    for row in &rows {
        checkpoint(cx)?;
        if row.labels.contains(&label::ENTRY) && !births.contains_key(&row.vid) {
            return Err(corrupt(
                "a visible Entry has no creation in the complete native prefix",
            ));
        }
    }
    for (vid, (created_at, birth_ordinal)) in &births {
        checkpoint(cx)?;
        let row = current.get(vid).ok_or_else(|| corrupt(format!(
            "journal Entry {:032x} was created at {} but is absent at {}; retirement cannot remove an Entry from verification",
            vid.0, created_at.0, known_at.0,
        )))?;
        if row.labels.as_slice() != [label::ENTRY] || row.retired_at.is_some() {
            return Err(corrupt(format!(
                "journal Entry {:032x} was relabeled or retired",
                vid.0
            )));
        }
        if row.created_at != *created_at || row.birth_ordinal != *birth_ordinal {
            return Err(corrupt(format!(
                "journal Entry {:032x} was rewritten after creation at {}; exact restoration does not restore immutability",
                vid.0, created_at.0,
            )));
        }
        let original = db
            .vertex_at(*vid, *created_at)?
            .ok_or_else(|| corrupt("an Entry's native creating snapshot is unavailable"))?;
        if original.created_at != *created_at
            || original.birth_ordinal != *birth_ordinal
            || original.labels != row.labels
            || original.props != row.props
        {
            return Err(corrupt(
                "a journal Entry differs from its native creating row",
            ));
        }
        let entry = Entry::decode(&bytes(
            row,
            property::FA_PAYLOAD,
            "entry integrity payload",
        )?)?;
        if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
            return Err(corrupt(
                "a journal Entry's canonical coordinate differs from this trunk book",
            ));
        }
        // This includes the payload, full digest and every declared index
        // mirror. A valid payload with dishonest selection mirrors is not green.
        for (key, value) in entry_mirrors(&entry)? {
            if prop(row, key) != Some(&value) {
                return Err(corrupt(format!(
                    "journal Entry {:032x} mirror {} disagrees with its canonical payload",
                    vid.0, key.0,
                )));
            }
        }
    }
    checkpoint(cx)?;
    Ok(EntryHistoryVerification {
        known_at,
        commits_checked: through,
        entries_checked: births.len(),
    })
}
