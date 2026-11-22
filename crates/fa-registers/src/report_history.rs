//! Disposable source metadata for repeated resident TB and activity reads.
//!
//! The first read enumerates the selected native snapshot, independently of
//! derived membership edges. A carried read authenticates that prefix's
//! Chronicle marker and examines a contiguous suffix. Only new immutable
//! source rows extend it; edits, migration visibility changes and unfamiliar
//! native rows fall back to the same literal snapshot. This memo contains no
//! amounts and never replaces maintained-cell or tail verification.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_journal::rows::{AccountRow, PeriodRow};
use fa_model::Id128;
use fa_model::symbols::label;
use fa_time::FiscalCalendar;
use fgdb::{Database, VertexRow};
use fgdb_delta_types::{DeltaRow, ElementId};
use fgdb_types::{CommitSeq, MarkerRef, QueryCx, VId};

use crate::{PeriodOf, RegisterError, entry_from_row, report_checkpoint};

/// Actual visits by the source metadata and empty-period population reader.
/// These counts exclude native marker/index work, fragment and migration-run
/// lookups inside entry decoding, maintained cells, monetary tails and a
/// report's subsequent literal fallback. They are not whole-request counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReportHistoryWork {
    pub metadata_scans: usize,
    pub population_scans: usize,
    pub snapshot_rows: usize,
    pub delta_rows: usize,
    pub vertex_reads: usize,
    pub entries_decoded: usize,
}

/// Handle-owned evidence of independently enumerated report source rows.
/// Private state cannot be supplied as authoritative metadata by a caller.
/// Reusing it across another book, another native prefix, retired history or
/// a historical coordinate performs a fresh literal read. Historical reads
/// do not evict a newer compatible coordinate held by the resident handle.
#[derive(Debug, Default)]
pub struct ReportHistoryMemo {
    prefix: Option<Prefix>,
    work: ReportHistoryWork,
}

impl ReportHistoryMemo {
    /// Work of the latest metadata/population read, including an unsuccessful
    /// suffix attempt before the literal fallback. No book mutation occurs.
    #[must_use]
    pub fn read_work(&self) -> ReportHistoryWork {
        self.work
    }

    #[must_use]
    pub fn known_at(&self) -> Option<CommitSeq> {
        self.prefix.as_ref().map(|prefix| prefix.at)
    }

    pub(crate) fn read<V: Vfs + Clone>(
        &mut self,
        db: &Database<V>,
        cx: Option<&QueryCx>,
        book: &BookContext,
        at: CommitSeq,
    ) -> Result<Read<'_>, RegisterError> {
        report_checkpoint(cx)?;
        self.work = ReportHistoryWork::default();
        let extension = match &self.prefix {
            Some(prefix) if prefix.book == book.book_id && prefix.calendar == book.calendar => {
                extend(db, cx, book, prefix, at, &mut self.work)
            }
            _ => None,
        };
        if let Some(extension) = extension {
            // No state advances until the complete suffix has been checked.
            if let Some(prefix) = self.prefix.as_mut() {
                prefix.at = at;
                prefix.marker = extension.marker;
                prefix.accounts.extend(extension.accounts);
                prefix.periods.extend(extension.periods);
                if let Some(populated) = prefix.populated.as_mut() {
                    populated.extend(extension.populated);
                }
            }
        } else {
            let fresh = metadata(db, cx, book, at, &mut self.work)?;
            if self.prefix.as_ref().is_some_and(|prefix| {
                prefix.book == book.book_id && prefix.calendar == book.calendar && prefix.at > at
            }) {
                return Ok(Read {
                    prefix: Selected::Historical(Box::new(fresh)),
                    work: &mut self.work,
                });
            }
            self.prefix = Some(fresh);
        }
        let prefix = self.prefix.as_mut().ok_or_else(|| {
            fa_journal::KernelError::Corrupt("report source prefix was not read".into())
        })?;
        Ok(Read {
            prefix: Selected::Resident(prefix),
            work: &mut self.work,
        })
    }
}

#[derive(Debug)]
struct Prefix {
    book: Id128,
    calendar: FiscalCalendar,
    at: CommitSeq,
    marker: Option<MarkerRef>,
    accounts: BTreeMap<VId, AccountRow>,
    periods: BTreeMap<VId, PeriodRow>,
    /// Loaded only when the report needs to prove an unservable period empty.
    populated: Option<BTreeSet<String>>,
}

enum Selected<'a> {
    Resident(&'a mut Prefix),
    Historical(Box<Prefix>),
}

impl Selected<'_> {
    fn prefix(&self) -> &Prefix {
        match self {
            Self::Resident(prefix) => prefix,
            Self::Historical(prefix) => prefix,
        }
    }

    fn prefix_mut(&mut self) -> &mut Prefix {
        match self {
            Self::Resident(prefix) => prefix,
            Self::Historical(prefix) => prefix,
        }
    }
}

pub(crate) struct Read<'a> {
    prefix: Selected<'a>,
    work: &'a mut ReportHistoryWork,
}

impl Read<'_> {
    pub(crate) fn metadata(&self) -> (Vec<AccountRow>, Vec<PeriodRow>) {
        let prefix = self.prefix.prefix();
        let mut accounts: Vec<_> = prefix.accounts.values().cloned().collect();
        let mut periods: Vec<_> = prefix.periods.values().cloned().collect();
        accounts.sort_by(|a, b| a.code.cmp(&b.code));
        periods.sort_by(|a, b| {
            (a.fiscal_year, a.ordinal, &a.code).cmp(&(b.fiscal_year, b.ordinal, &b.code))
        });
        (accounts, periods)
    }

    pub(crate) fn period_has_postings<V: Vfs + Clone>(
        &mut self,
        db: &Database<V>,
        cx: Option<&QueryCx>,
        book: &BookContext,
        period: &str,
    ) -> Result<bool, RegisterError> {
        report_checkpoint(cx)?;
        let prefix = self.prefix.prefix_mut();
        if let Some(populated) = &prefix.populated {
            return Ok(populated.contains(period));
        }
        let rows = fa_journal::op_witness::vertices_at(db, prefix.at)?;
        self.work.population_scans = self.work.population_scans.saturating_add(1);
        self.work.snapshot_rows = self.work.snapshot_rows.saturating_add(rows.len());
        let mut populated = BTreeSet::new();
        let mut resolver = PeriodOf::new(book);
        let mut runs = BTreeMap::new();
        for row in rows {
            report_checkpoint(cx)?;
            if row.labels.contains(&label::ENTRY) {
                self.work.entries_decoded = self.work.entries_decoded.saturating_add(1);
            }
            let Some(entry) = entry_from_row(db, &row, book, prefix.at)? else {
                continue;
            };
            if fa_journal::migration::visible_at(db, &entry, prefix.at, &mut runs)?
                && !entry.proposal.legs.is_empty()
            {
                populated.insert(resolver.period(&entry)?.to_string());
            }
        }
        report_checkpoint(cx)?;
        let present = populated.contains(period);
        prefix.populated = Some(populated);
        Ok(present)
    }
}

/// Same independent metadata inputs as the literal reader in lib.rs. No
/// IN_BOOK or IN_PERIOD projection can remove an account or period here.
fn metadata<V: Vfs + Clone>(
    db: &Database<V>,
    cx: Option<&QueryCx>,
    book: &BookContext,
    at: CommitSeq,
    work: &mut ReportHistoryWork,
) -> Result<Prefix, RegisterError> {
    report_checkpoint(cx)?;
    let rows = fa_journal::op_witness::vertices_at(db, at)?;
    work.metadata_scans = work.metadata_scans.saturating_add(1);
    work.snapshot_rows = work.snapshot_rows.saturating_add(rows.len());
    let mut accounts = BTreeMap::new();
    let mut periods = BTreeMap::new();
    for row in rows {
        report_checkpoint(cx)?;
        if row.labels.contains(&label::ACCOUNT) {
            accounts.insert(row.vid, AccountRow::decode(&row)?);
        }
        if row.labels.contains(&label::PERIOD) {
            let period = PeriodRow::decode(&row)?;
            if period.calendar_id == book.calendar.id {
                periods.insert(row.vid, period);
            }
        }
    }
    report_checkpoint(cx)?;
    Ok(Prefix {
        book: book.book_id,
        calendar: book.calendar.clone(),
        at,
        marker: retained_marker(db, at),
        accounts,
        periods,
        populated: None,
    })
}

fn retained_marker<V: Vfs + Clone>(db: &Database<V>, at: CommitSeq) -> Option<MarkerRef> {
    let before = at.0.checked_sub(1)?;
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
                label::ACCOUNT | label::PERIOD | label::ENTRY | label::ENTRY_FRAGMENT
            )
        })
}

struct Extension {
    marker: Option<MarkerRef>,
    accounts: BTreeMap<VId, AccountRow>,
    periods: BTreeMap<VId, PeriodRow>,
    populated: BTreeSet<String>,
}

/// Only a completely checked append suffix earns reuse. A failed attempt
/// decides no error: the original full snapshot preserves its refusal and
/// diagnostic order, even when this particular report never needs population.
fn extend<V: Vfs + Clone>(
    db: &Database<V>,
    cx: Option<&QueryCx>,
    book: &BookContext,
    prefix: &Prefix,
    at: CommitSeq,
    work: &mut ReportHistoryWork,
) -> Option<Extension> {
    if prefix.at > at || prefix.marker.is_none() || retained_marker(db, prefix.at) != prefix.marker
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
                report_checkpoint(cx).ok()?;
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
                    DeltaRow::LabelMembership { .. } => return None,
                    // These source selections depend on canonical vertex
                    // bodies and migration visibility, never derived edges.
                    DeltaRow::CreateEdge { .. }
                    | DeltaRow::DeleteEdge { .. }
                    | DeltaRow::Property {
                        elem: ElementId::Edge(_),
                        ..
                    } => {}
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
    let mut extension = Extension {
        marker,
        accounts: BTreeMap::new(),
        periods: BTreeMap::new(),
        populated: BTreeSet::new(),
    };
    let mut resolver = PeriodOf::new(book);
    let mut runs = BTreeMap::new();
    for vid in touched {
        report_checkpoint(cx).ok()?;
        work.vertex_reads = work.vertex_reads.saturating_add(1);
        let before = db.vertex_at(vid, prefix.at).ok()?;
        if before.as_ref().is_some_and(source_row) {
            return None;
        }
        work.vertex_reads = work.vertex_reads.saturating_add(1);
        let row = db.vertex_at(vid, at).ok()??;
        if migration_row(&row) {
            return None;
        }
        if source_row(&row) && (before.is_some() || born.get(&vid) != Some(&row.created_at)) {
            return None;
        }
        if row.labels.contains(&label::ACCOUNT) {
            extension
                .accounts
                .insert(vid, AccountRow::decode(&row).ok()?);
        }
        if row.labels.contains(&label::PERIOD) {
            let period = PeriodRow::decode(&row).ok()?;
            if period.calendar_id == book.calendar.id {
                extension.periods.insert(vid, period);
            }
        }
        if prefix.populated.is_some() && row.labels.contains(&label::ENTRY) {
            work.entries_decoded = work.entries_decoded.saturating_add(1);
            let entry = entry_from_row(db, &row, book, at).ok()??;
            if fa_journal::migration::visible_at(db, &entry, at, &mut runs).ok()?
                && !entry.proposal.legs.is_empty()
            {
                extension
                    .populated
                    .insert(resolver.period(&entry).ok()?.to_string());
            }
        }
    }
    report_checkpoint(cx).ok()?;
    Some(extension)
}
