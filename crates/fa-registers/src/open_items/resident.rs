//! Disposable open-item folds over authenticated native prefixes.
//!
//! The first read selects canonical Entry payloads independently of derived
//! membership edges. A resident read authenticates that prefix's Chronicle
//! marker, consumes a complete contiguous suffix, and changes only new items
//! and application targets. Reversals, migration visibility changes, changed
//! source rows and unfamiliar native operations use the literal fold again.
//! No persisted applied mirror or register supplies an amount.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_model::symbols::label;
use fa_model::{ControlPayload, Entry, EntryClass, EntryOrigin, Id128};
use fa_time::FiscalCalendar;
use fgdb::{Database, VertexRow};
use fgdb_delta_types::{DeltaRow, ElementId};
use fgdb_types::{CommitSeq, MarkerRef, QueryCx, VId};

use super::{
    Application, OpenItem, OpenItemsReport, account_at, carries_open_items, fold_open_items,
};
use crate::{
    EntryReadCount, RegisterError, entries_at_counted, entry_from_row, report_checkpoint,
    resolve_known_at,
};

/// Actual visits by the resident source reader and incremental item fold.
/// Fragment authentication, migration-run lookup and native index internals
/// are outside these counts; these are not whole-request storage operations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpenItemReadWork {
    pub snapshot_reads: usize,
    pub snapshot_rows: usize,
    pub delta_rows: usize,
    pub vertex_reads: usize,
    pub marker_reads: usize,
    pub entries_decoded: usize,
    pub literal_folds: usize,
    pub item_updates: usize,
    pub applications_appended: usize,
    pub returned_items: usize,
}

/// An owned, disposable fold, never an externally supplied balance authority.
/// Historical requests do not evict a newer resident coordinate. Missing
/// retained history, a different database prefix, or an unsupported change
/// disables reuse; the existing literal reader decides the answer or error.
#[derive(Debug, Default)]
pub struct OpenItemMemo {
    prefix: Option<Prefix>,
    work: OpenItemReadWork,
}

type ItemKey = (VId, CommitSeq, VId, u16);
type LegKey = (VId, u16);
type Record = (VId, Entry, CommitSeq);

#[derive(Debug)]
struct Prefix {
    book: Id128,
    calendar: FiscalCalendar,
    at: CommitSeq,
    marker: Option<MarkerRef>,
    items: BTreeMap<ItemKey, OpenItem>,
    by_leg: BTreeMap<LegKey, ItemKey>,
}

fn item_key(item: &OpenItem) -> ItemKey {
    (item.account, item.recorded_at, item.entry, item.ordinal)
}

impl OpenItemMemo {
    #[must_use]
    pub fn known_at(&self) -> Option<CommitSeq> {
        self.prefix.as_ref().map(|prefix| prefix.at)
    }

    /// Work of the latest read, including an unsuccessful suffix attempt
    /// before a literal fallback. Neither a hit nor a fallback writes the book.
    #[must_use]
    pub fn read_work(&self) -> OpenItemReadWork {
        self.work
    }

    fn read<V: Vfs + Clone>(
        &mut self,
        db: &Database<V>,
        cx: &QueryCx,
        book: &BookContext,
        account: Option<VId>,
        at: CommitSeq,
    ) -> Result<Vec<OpenItem>, RegisterError> {
        let extension = match &self.prefix {
            Some(prefix) if prefix.book == book.book_id && prefix.calendar == book.calendar => {
                extend(db, cx, book, prefix, at, &mut self.work)
            }
            _ => None,
        };
        if let Some(extension) = extension {
            report_checkpoint(Some(cx))?;
            if let Some(prefix) = self.prefix.as_mut() {
                for item in extension.changed.into_values() {
                    let key = item_key(&item);
                    prefix.by_leg.insert((item.entry, item.ordinal), key);
                    prefix.items.insert(key, item);
                }
                prefix.at = at;
                prefix.marker = extension.marker;
                return select(prefix, cx, account, &mut self.work);
            }
        }

        report_checkpoint(Some(cx))?;
        self.work.snapshot_reads = self.work.snapshot_reads.saturating_add(1);
        let mut counted = EntryReadCount::default();
        let entries = entries_at_counted(db, book, at, &mut counted);
        self.work.snapshot_rows = self
            .work
            .snapshot_rows
            .saturating_add(counted.vertices_read);
        self.work.entries_decoded = self
            .work
            .entries_decoded
            .saturating_add(counted.entries_decoded);
        let entries = entries?;
        report_checkpoint(Some(cx))?;
        self.work.literal_folds = self.work.literal_folds.saturating_add(1);
        let items = match fold_open_items(&entries, None) {
            Ok(items) => items,
            Err(_) if account.is_some() => {
                // A malformed unrelated account must not change the existing
                // account-filtered reader's diagnostic or make it fail. Such a
                // snapshot cannot populate a whole-book optimization.
                self.work.literal_folds = self.work.literal_folds.saturating_add(1);
                let selected = fold_open_items(&entries, account)?;
                report_checkpoint(Some(cx))?;
                self.work.returned_items = selected.len();
                return Ok(selected);
            }
            Err(error) => return Err(error),
        };
        // The literal reader historically tolerates an application to a
        // missing target. Do not reuse that malformed prefix: a later entry
        // with the named identity would otherwise acquire an old application
        // that is absent from this memo. Honest kernel histories are closed.
        let identities: BTreeSet<_> = entries.iter().map(|(vid, _, _)| *vid).collect();
        let closed = entries.iter().all(|(_, entry, _)| {
            entry.proposal.legs.iter().all(|leg| {
                leg.settles
                    .iter()
                    .all(|settlement| identities.contains(&settlement.target.vid))
            }) && entry
                .proposal
                .supersession
                .iter()
                .all(|supersession| identities.contains(&supersession.target.vid))
        });
        let fresh = Prefix {
            book: book.book_id,
            calendar: book.calendar.clone(),
            at,
            marker: closed
                .then(|| retained_marker(db, at, &mut self.work))
                .flatten(),
            by_leg: items
                .iter()
                .map(|item| ((item.entry, item.ordinal), item_key(item)))
                .collect(),
            items: items
                .into_iter()
                .map(|item| (item_key(&item), item))
                .collect(),
        };
        report_checkpoint(Some(cx))?;
        let result = select(&fresh, cx, account, &mut self.work)?;
        if !self.prefix.as_ref().is_some_and(|previous| {
            previous.book == book.book_id && previous.calendar == book.calendar && previous.at > at
        }) {
            self.prefix = Some(fresh);
        }
        Ok(result)
    }
}

fn select(
    prefix: &Prefix,
    cx: &QueryCx,
    account: Option<VId>,
    work: &mut OpenItemReadWork,
) -> Result<Vec<OpenItem>, RegisterError> {
    let mut output = Vec::new();
    let mut append = |item: &OpenItem| -> Result<(), RegisterError> {
        report_checkpoint(Some(cx))?;
        work.returned_items = work.returned_items.saturating_add(1);
        output.push(item.clone());
        Ok(())
    };
    if let Some(account) = account {
        let first = (account, CommitSeq(0), VId(0), 0);
        let last = (account, CommitSeq(u64::MAX), VId(u128::MAX), u16::MAX);
        for (_, item) in prefix.items.range(first..=last) {
            append(item)?;
        }
    } else {
        for item in prefix.items.values() {
            append(item)?;
        }
    }
    Ok(output)
}

/// The literal open-item result with a reusable, authenticated native prefix.
/// The caller must admit this observation before invoking the reader, exactly
/// as for [`super::open_items`]. A cache cannot grant read authority.
pub fn open_items_carried<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    account: Option<VId>,
    known_at: Option<CommitSeq>,
    memo: &mut OpenItemMemo,
) -> Result<Vec<OpenItem>, RegisterError> {
    report_checkpoint(Some(cx))?;
    memo.work = OpenItemReadWork::default();
    let at = resolve_known_at(db, known_at)?;
    if let Some(account) = account {
        memo.work.vertex_reads = memo.work.vertex_reads.saturating_add(1);
        account_at(db, account, at)?;
    }
    memo.read(db, cx, book, account, at)
}

/// Open items and display metadata from the same resolved native coordinate.
/// Metadata stays a point read at that coordinate, so a later account rename
/// never alters a historical report or requires guessing cache invalidation.
pub fn open_items_report_carried<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    account: Option<VId>,
    known_at: Option<CommitSeq>,
    memo: &mut OpenItemMemo,
) -> Result<OpenItemsReport, RegisterError> {
    report_checkpoint(Some(cx))?;
    let at = resolve_known_at(db, known_at)?;
    let items = open_items_carried(db, cx, book, account, Some(at), memo)?;
    let accounts = items
        .iter()
        .map(|item| item.account)
        .chain(account)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|vid| {
            report_checkpoint(Some(cx))?;
            memo.work.vertex_reads = memo.work.vertex_reads.saturating_add(1);
            account_at(db, vid, at).map(|row| (vid, row))
        })
        .collect::<Result<_, _>>()?;
    Ok(OpenItemsReport {
        known_at: at,
        account_filter: account,
        accounts,
        items,
    })
}

fn retained_marker<V: Vfs + Clone>(
    db: &Database<V>,
    at: CommitSeq,
    work: &mut OpenItemReadWork,
) -> Option<MarkerRef> {
    let before = at.0.checked_sub(1)?;
    work.marker_reads = work.marker_reads.saturating_add(1);
    db.delta_since(CommitSeq(before))
        .ok()?
        .next()
        .filter(|batch| batch.commit_seq() == at)
        .map(|batch| batch.commit_marker_identity())
}

fn migration_row(row: &VertexRow) -> bool {
    row.labels.iter().any(|kind| {
        matches!(
            *kind,
            label::MIGRATION_RUN
                | label::MIGRATION_RUN_FRAGMENT
                | label::MIGRATION_SOURCE
                | label::MIGRATION_SOURCE_FRAGMENT
        )
    })
}

fn source_row(row: &VertexRow) -> bool {
    migration_row(row)
        || row.labels.iter().any(|kind| {
            matches!(
                *kind,
                label::ENTRY | label::ENTRY_FRAGMENT | label::ACCOUNT | label::PERIOD
            )
        })
}

struct Extension {
    marker: Option<MarkerRef>,
    changed: BTreeMap<LegKey, OpenItem>,
}

/// An unsuccessful shortcut decides no error and changes no cached state.
/// The literal read supplies the same verdict, including corruption and
/// arithmetic diagnostic ordering, as the context-free public reader.
fn extend<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    prefix: &Prefix,
    at: CommitSeq,
    work: &mut OpenItemReadWork,
) -> Option<Extension> {
    if prefix.at > at
        || prefix.marker.is_none()
        || retained_marker(db, prefix.at, work) != prefix.marker
    {
        return None;
    }
    let mut through = prefix.at;
    let mut marker = prefix.marker;
    let mut touched = BTreeSet::new();
    let mut born = BTreeMap::new();
    for batch in db.delta_since(prefix.at).ok()? {
        let seq = batch.commit_seq();
        if seq > at {
            break;
        }
        if through.0.checked_add(1) != Some(seq.0) {
            return None;
        }
        for coordinate in batch.coordinate_entries() {
            for row in &coordinate.rows {
                report_checkpoint(Some(cx)).ok()?;
                work.delta_rows = work.delta_rows.saturating_add(1);
                match row {
                    DeltaRow::CreateVertex {
                        vid, valid_time, ..
                    } => {
                        if valid_time.is_some() || born.insert(*vid, seq).is_some() {
                            return None;
                        }
                        touched.insert(*vid);
                    }
                    DeltaRow::Property {
                        elem: ElementId::Vertex(vid),
                        ..
                    } => {
                        touched.insert(*vid);
                    }
                    // Canonical entries and migration visibility do not use
                    // these derived edges. They cannot hide a source posting.
                    DeltaRow::CreateEdge { .. }
                    | DeltaRow::DeleteEdge { .. }
                    | DeltaRow::Property {
                        elem: ElementId::Edge(_),
                        ..
                    } => {}
                    // Relabeling, deletion, valid-time changes and unfamiliar
                    // row families require complete independent reconstruction.
                    _ => return None,
                }
            }
        }
        through = seq;
        marker = Some(batch.commit_marker_identity());
    }
    if through != at {
        return None;
    }

    let mut appended = Vec::new();
    for vid in touched {
        report_checkpoint(Some(cx)).ok()?;
        work.vertex_reads = work.vertex_reads.saturating_add(1);
        let before = db.vertex_at(vid, prefix.at).ok()?;
        if before.as_ref().is_some_and(source_row) {
            return None;
        }
        work.vertex_reads = work.vertex_reads.saturating_add(1);
        let row = db.vertex_at(vid, at).ok()??;
        if migration_row(&row)
            || (source_row(&row) && (before.is_some() || born.get(&vid) != Some(&row.created_at)))
        {
            return None;
        }
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        work.entries_decoded = work.entries_decoded.saturating_add(1);
        let entry = entry_from_row(db, &row, book, at).ok()??;
        if entry.proposal.class == EntryClass::REVERSAL
            || matches!(entry.proposal.origin, EntryOrigin::Migration { .. })
            || matches!(
                entry.proposal.control,
                Some(ControlPayload::MigrationControl { .. })
            )
        {
            return None;
        }
        appended.push((vid, entry, row.created_at));
    }
    appended.sort_by_key(|(vid, _, seq)| (*seq, *vid));
    let changed = append_items(prefix, cx, &appended, work)?;
    report_checkpoint(Some(cx)).ok()?;
    Some(Extension { marker, changed })
}

fn append_items(
    prefix: &Prefix,
    cx: &QueryCx,
    appended: &[Record],
    work: &mut OpenItemReadWork,
) -> Option<BTreeMap<LegKey, OpenItem>> {
    let mut changed = BTreeMap::new();
    // Populate all new items first: same-commit references follow execution
    // order, which need not be the Entry vid order used by report rendering.
    for (vid, entry, seq) in appended {
        if !carries_open_items(entry) {
            continue;
        }
        for (index, leg) in entry.proposal.legs.iter().enumerate() {
            report_checkpoint(Some(cx)).ok()?;
            let ordinal = u16::try_from(index).ok()?;
            let applied_out = leg.settles.iter().try_fold(0_i128, |sum, settlement| {
                sum.checked_add(settlement.amount.mantissa)
            })?;
            let item = OpenItem {
                entry: *vid,
                ordinal,
                account: leg.account_ref,
                unit_id: leg.amount.unit.0,
                side: leg.side,
                effective_date: entry.proposal.effective_date,
                recorded_at: *seq,
                original: leg.amount.mantissa,
                applied: 0,
                applied_out,
                open: leg.amount.mantissa.checked_sub(applied_out)?,
                applications: Vec::new(),
            };
            if prefix.by_leg.contains_key(&(*vid, ordinal))
                || changed.insert((*vid, ordinal), item).is_some()
            {
                return None;
            }
            work.item_updates = work.item_updates.saturating_add(1);
        }
    }
    for (vid, entry, seq) in appended {
        if !carries_open_items(entry) {
            continue;
        }
        for (index, leg) in entry.proposal.legs.iter().enumerate() {
            let ordinal = u16::try_from(index).ok()?;
            for settlement in &leg.settles {
                report_checkpoint(Some(cx)).ok()?;
                let key = (settlement.target.vid, settlement.ordinal);
                if let std::collections::btree_map::Entry::Vacant(slot) = changed.entry(key) {
                    let existing = prefix.items.get(prefix.by_leg.get(&key)?)?;
                    slot.insert(existing.clone());
                }
                let target = changed.get_mut(&key)?;
                target.applied = target.applied.checked_add(settlement.amount.mantissa)?;
                target.open = target
                    .original
                    .checked_sub(target.applied_out)?
                    .checked_sub(target.applied)?;
                target.applications.push(Application {
                    entry: *vid,
                    ordinal,
                    amount: settlement.amount.mantissa,
                    recorded_at: *seq,
                    live: true,
                });
                work.item_updates = work.item_updates.saturating_add(1);
                work.applications_appended = work.applications_appended.saturating_add(1);
            }
        }
    }
    for item in changed.values_mut() {
        report_checkpoint(Some(cx)).ok()?;
        item.applications.sort_by_key(|application| {
            (
                application.recorded_at,
                application.entry,
                application.ordinal,
            )
        });
    }
    Some(changed)
}
