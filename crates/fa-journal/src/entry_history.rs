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

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property};
use fa_model::{Id128, entry_mirrors};
use fgdb::{Database, VertexRow, WriteTxnError};
use fgdb_delta_types::{DeltaRow, ElementId};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, MarkerRef, QueryCx, VId};

use crate::genesis::BookContext;
use crate::refusal::KernelError;
use crate::rows::prop;

/// Every native commit through known_at was examined, including maintenance.
/// Every Entry birth in that prefix has its original live canonical row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryHistoryVerification {
    pub known_at: CommitSeq,
    pub commits_checked: u64,
    pub entries_checked: usize,
}

/// Work performed by one successful carried verification. These are actual
/// verifier visits, not the size of the authenticated prefix. Marker lookups
/// and the substrate's own work are not included in these counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EntryHistoryWork {
    /// Delta rows examined, including both passes over a commit's births and
    /// changes and any unsuccessful fast-path attempt before a literal fold.
    pub delta_rows: u64,
    pub snapshot_scans: u64,
    pub snapshot_rows: u64,
    pub entries_decoded: usize,
    /// The literal complete-prefix verifier was used during this call.
    pub rebuilt: bool,
}

#[derive(Debug)]
struct VerifiedPrefix {
    book: Id128,
    verification: EntryHistoryVerification,
    marker: Option<MarkerRef>,
    entries: BTreeSet<VId>,
    fragments: BTreeSet<VId>,
}

/// Disposable, handle-owned evidence of a completely verified native prefix.
///
/// Private fields prevent a caller from inventing a verified frontier. Every
/// use authenticates the carried Chronicle marker, whose predecessor chain
/// binds the complete prefix. Only contiguous native suffixes containing new
/// immutable Entries and unrelated changes can extend it. A changed Entry or
/// fragment, unfamiliar row family, historical query or different prefix runs
/// the original complete verifier. This never replaces explicit book audits,
/// certificates, current capability admission, or retained history loading.
#[derive(Debug, Default)]
pub struct EntryHistoryMemo {
    prefix: Option<VerifiedPrefix>,
    work: EntryHistoryWork,
}

impl EntryHistoryMemo {
    /// Actual work of the most recent successful call; an error never installs
    /// a partial prefix or replaces this successful-call diagnostic.
    #[must_use]
    pub fn read_work(&self) -> EntryHistoryWork {
        self.work
    }

    #[must_use]
    pub fn verified_at(&self) -> Option<CommitSeq> {
        self.prefix
            .as_ref()
            .map(|prefix| prefix.verification.known_at)
    }
}

struct Extension {
    verification: EntryHistoryVerification,
    marker: Option<MarkerRef>,
    entries: BTreeSet<VId>,
    fragments: BTreeSet<VId>,
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
    query.with_restriction(|| {
        Ok(verify(db, &query, book, known_at, &mut EntryHistoryWork::default())?.verification)
    })
}

/// Verify with a previously authenticated prefix, preserving the literal
/// verifier's verdict. Callers must authorize the requested observation and
/// hydrate its retained native history before this function, just as for
/// [`verify_entry_history`]. No mutation of the book is performed.
pub fn verify_entry_history_carried<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    known_at: Option<CommitSeq>,
    memo: &mut EntryHistoryMemo,
) -> Result<EntryHistoryVerification, KernelError> {
    let query = cx.query();
    checkpoint(&query)?;
    query.with_restriction(|| {
        let at = known_at.unwrap_or(db.frontier()?);
        let mut work = EntryHistoryWork::default();
        let compatible = match &memo.prefix {
            Some(prefix)
                if prefix.book == book.book_id
                    && prefix.verification.known_at <= at
                    && prefix.marker.is_some() =>
            {
                crate::rows::marker_at(db, prefix.verification.known_at)? == prefix.marker
            }
            _ => false,
        };
        if compatible
            && let Some(prefix) = &memo.prefix
            && let Some(extension) = extend(db, &query, book, prefix, at, &mut work)?
        {
            checkpoint(&query)?;
            let verification = extension.verification.clone();
            // Extend only after every native suffix row and new Entry has
            // passed. Never clone the complete identity set on a warm read.
            let Some(prefix) = memo.prefix.as_mut() else {
                return Err(corrupt(
                    "verified entry prefix disappeared during its extension",
                ));
            };
            prefix.verification = extension.verification;
            prefix.marker = extension.marker;
            prefix.entries.extend(extension.entries);
            prefix.fragments.extend(extension.fragments);
            memo.work = work;
            return Ok(verification);
        }
        let prefix = verify(db, &query, book, Some(at), &mut work)?;
        checkpoint(&query)?;
        let verification = prefix.verification.clone();
        // A historical query must not evict this handle's newer verified
        // frontier. Its marker is rechecked on the next forward read anyway.
        if !memo.prefix.as_ref().is_some_and(|previous| {
            previous.book == book.book_id && previous.verification.known_at > at
        }) {
            memo.prefix = Some(prefix);
        }
        memo.work = work;
        Ok(verification)
    })
}

fn extend<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    prefix: &VerifiedPrefix,
    at: CommitSeq,
    work: &mut EntryHistoryWork,
) -> Result<Option<Extension>, KernelError> {
    let mut births = BTreeMap::new();
    let mut fragments = BTreeMap::new();
    let mut through = prefix.verification.known_at;
    for batch in db.delta_since(through)? {
        let sequence = batch.commit_seq();
        if sequence > at {
            break;
        }
        checkpoint(cx)?;
        if through.0.checked_add(1) != Some(sequence.0) {
            return Ok(None);
        }
        // Native coordinate order is not causal. Observe the entire birth
        // cohort before interpreting a property or label in the same commit.
        for coordinate in batch.coordinate_entries() {
            for row in &coordinate.rows {
                checkpoint(cx)?;
                work.delta_rows = work.delta_rows.saturating_add(1);
                if let DeltaRow::CreateVertex {
                    vid,
                    labels,
                    birth_ordinal,
                    ..
                } = row
                {
                    if prefix.entries.contains(vid)
                        || prefix.fragments.contains(vid)
                        || births.contains_key(vid)
                        || fragments.contains_key(vid)
                    {
                        return Ok(None);
                    }
                    if labels.contains(&label::ENTRY)
                        && births.insert(*vid, (sequence, *birth_ordinal)).is_some()
                    {
                        return Ok(None);
                    }
                    if labels.contains(&label::ENTRY_FRAGMENT)
                        && fragments.insert(*vid, sequence).is_some()
                    {
                        return Ok(None);
                    }
                }
            }
        }
        for coordinate in batch.coordinate_entries() {
            for row in &coordinate.rows {
                checkpoint(cx)?;
                work.delta_rows = work.delta_rows.saturating_add(1);
                if let DeltaRow::LabelMembership {
                    vid,
                    label: changed,
                    after: true,
                    ..
                } = row
                    && *changed == label::ENTRY
                    && !prefix.entries.contains(vid)
                    && !births.contains_key(vid)
                {
                    return Ok(None);
                }
                match row {
                    DeltaRow::CreateVertex { .. }
                    | DeltaRow::CreateEdge { .. }
                    | DeltaRow::DeleteEdge { .. }
                    | DeltaRow::Property {
                        elem: ElementId::Edge(_),
                        ..
                    } => {}
                    DeltaRow::Property {
                        elem: ElementId::Vertex(vid),
                        ..
                    }
                    | DeltaRow::LabelMembership { vid, .. }
                    | DeltaRow::DeleteVertex { vid, .. } => {
                        if prefix.entries.contains(vid)
                            || prefix.fragments.contains(vid)
                            || births
                                .get(vid)
                                .is_some_and(|(created, _)| *created < sequence)
                            || fragments
                                .get(vid)
                                .is_some_and(|created| *created < sequence)
                        {
                            // Includes restoration, retirement, and fragment
                            // changes. The literal verifier decides whether a
                            // changed fragment is actually part of an Entry;
                            // an unrelated orphan is not journal corruption.
                            return Ok(None);
                        }
                    }
                    // Counter, valid-time, escrow, schema and future row
                    // families receive the complete original observation.
                    _ => return Ok(None),
                }
            }
        }
        through = sequence;
    }
    if through != at {
        return Ok(None);
    }
    for (vid, (created, ordinal)) in &births {
        checkpoint(cx)?;
        let row = db.vertex_at(*vid, at)?.ok_or_else(|| {
            corrupt("a new journal Entry is absent at the verified suffix frontier")
        })?;
        verify_entry(db, book, &row, *created, *ordinal, at, work)?;
    }
    let entries_checked = prefix
        .verification
        .entries_checked
        .checked_add(births.len())
        .ok_or_else(|| corrupt("entry history count overflow"))?;
    Ok(Some(Extension {
        verification: EntryHistoryVerification {
            known_at: at,
            commits_checked: at.0,
            entries_checked,
        },
        marker: crate::rows::marker_at(db, at)?,
        entries: births.into_keys().collect(),
        fragments: fragments.into_keys().collect(),
    }))
}

fn verify<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    known_at: Option<CommitSeq>,
    work: &mut EntryHistoryWork,
) -> Result<VerifiedPrefix, KernelError> {
    let known_at = known_at.unwrap_or(db.frontier()?);
    work.rebuilt = true;
    work.snapshot_scans = work.snapshot_scans.saturating_add(1);
    let rows = db.vertices_at(known_at)?;
    work.snapshot_rows = work.snapshot_rows.saturating_add(rows.len() as u64);
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
                work.delta_rows = work.delta_rows.saturating_add(1);
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
                work.delta_rows = work.delta_rows.saturating_add(1);
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
        verify_entry(db, book, row, *created_at, *birth_ordinal, known_at, work)?;
    }
    checkpoint(cx)?;
    Ok(VerifiedPrefix {
        book: book.book_id,
        verification: EntryHistoryVerification {
            known_at,
            commits_checked: through,
            entries_checked: births.len(),
        },
        marker: crate::rows::marker_at(db, known_at)?,
        entries: births.into_keys().collect(),
        fragments: rows
            .iter()
            .filter(|row| row.labels.contains(&label::ENTRY_FRAGMENT))
            .map(|row| row.vid)
            .collect(),
    })
}

fn verify_entry<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    row: &VertexRow,
    created_at: CommitSeq,
    birth_ordinal: u64,
    known_at: CommitSeq,
    work: &mut EntryHistoryWork,
) -> Result<(), KernelError> {
    let vid = row.vid;
    if row.labels.as_slice() != [label::ENTRY]
        || row.retired_at.is_some_and(|retired| retired <= known_at)
    {
        return Err(corrupt(format!(
            "journal Entry {:032x} was relabeled or retired",
            vid.0
        )));
    }
    if row.created_at != created_at || row.birth_ordinal != birth_ordinal {
        return Err(corrupt(format!(
            "journal Entry {:032x} was rewritten after creation at {}; exact restoration does not restore immutability",
            vid.0, created_at.0,
        )));
    }
    let original = db
        .vertex_at(vid, created_at)?
        .ok_or_else(|| corrupt("an Entry's native creating snapshot is unavailable"))?;
    if original.created_at != created_at
        || original.birth_ordinal != birth_ordinal
        || original.labels != row.labels
        || original.props != row.props
    {
        return Err(corrupt(
            "a journal Entry differs from its native creating row",
        ));
    }
    let entry = crate::entry_storage::decode_at(db, row, known_at)?;
    work.entries_decoded = work.entries_decoded.saturating_add(1);
    if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
        return Err(corrupt(
            "a journal Entry's canonical coordinate differs from this trunk book",
        ));
    }
    // This includes the payload, full digest and every declared index
    // mirror. A valid payload with dishonest selection mirrors is not green.
    for (key, value) in entry_mirrors(&entry)? {
        if key == property::FA_PAYLOAD {
            if !crate::entry_storage::payload_mirror_matches(row, &entry)? {
                return Err(corrupt(
                    "entry storage payload differs from canonical Entry",
                ));
            }
            continue;
        }
        if prop(row, key) != Some(&value) {
            return Err(corrupt(format!(
                "journal Entry {:032x} mirror {} disagrees with its canonical payload",
                vid.0, key.0,
            )));
        }
    }
    Ok(())
}
