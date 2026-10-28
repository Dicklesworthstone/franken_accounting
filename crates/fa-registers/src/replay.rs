//! Verifying a scratch-book replay (plan §15.2, bead fa-xo0 part 2).
//!
//! A scratch book is evidentiary only if its [`SeqMap`] is exactly the map
//! of the replay it describes. [`verify_replay`] re-derives that from the
//! source and refolds both sides:
//!
//! - the map names this book, and is strictly increasing on both sides;
//! - its prefix is not past the source's frontier, nor before the book's
//!   genesis;
//! - its pairs are exactly the source's commits through the prefix that
//!   carry accounting objects (no gap, no extra), each with that commit's
//!   marker;
//! - at every pair, the entries selected at the source sequence and at the
//!   scratch sequence are the same objects (vid and entry digest, under the
//!   same migration predicate), and every period they post into folds to the
//!   same cells on both sides.
//!
//! Any departure is FA-REF-135: a SeqMap is never edited, only re-made by a
//! fresh replay.
//!
//! Entry selection carries a previously read prefix over the complete native
//! delta stream, rereading every changed vertex at the next mapped sequence
//! (fa-vr7q). Migration visibility changes, unmodeled rows, a missing delta or
//! a different retained marker fall back to the literal selector. The folds
//! carry the already checked cells over native posting and reservation-release
//! suffixes. Each new entry identity and each changed cell is compared on both
//! sides. Releases subtract the complete original hold in its original period;
//! only a resolution's posted subvector enters its own period. A migration
//! activation, changed historical entry or failed fast-path check uses the
//! complete literal folds at that pair. No persisted register is an input, and
//! an error is always decided by the literal path.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Refusal, exit};
use fa_journal::scratch::{Maintenance, SeqMap, replayable, source_genesis};
use fa_model::symbols::label;
use fa_model::{ControlPayload, Entry, EntryClass, EntryOrigin};
use fgdb::Database;
use fgdb_delta_types::{DeltaRow, ElementId};
use fgdb_types::{CommitSeq, MarkerRef, VId};

use crate::{
    Cell, CellKey, EntryReadCount, Fold, PeriodOf, RegisterError, add_entry, entries_at_counted,
    entry_from_row, folds_at, period_at, resolve_known_at, take_fold,
};

/// Refusal codes this module issues.
pub mod code {
    /// A SeqMap that does not describe the replay: wrong book, not monotone,
    /// a prefix past the source frontier or before its genesis, a gap or an
    /// extra pair, a wrong marker, or a pair at which the two books' entries
    /// or folds differ.
    pub const SEQ_MAP_INVALID: &str = "FA-REF-135";
}

/// What a verification checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayVerification {
    pub seq_map_digest: [u8; 32],
    pub pairs_checked: usize,
    pub entries_checked: usize,
    pub folds_checked: usize,
}

/// Actual work performed by one side's entry selector, including failed
/// carry attempts before a literal fallback. These are not total verifier
/// work counts: source-map validation, migration run lookups, marker reads,
/// and folding are outside their scope.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayReadWork {
    /// Complete `vertices_at` selections.
    pub full_reads: usize,
    /// Rows visited in complete selections, plus changed-vertex point reads
    /// (including a point read that finds a deleted vertex).
    pub vertices_read: usize,
    /// Entry payload decodes attempted, including invisible migration chunks.
    pub entries_decoded: usize,
    /// Delta rows examined when advancing an already selected prefix.
    pub delta_rows: usize,
}

/// Entry-selection work for [`verify_replay_counted`], kept outside the
/// existing verdict and robot envelope.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayWork {
    pub source: ReplayReadWork,
    pub scratch: ReplayReadWork,
    /// Entry identities actually compared, counting both books. An unchanged,
    /// previously equal prefix needs no second identity comparison.
    pub identities_compared: usize,
    /// Entries submitted to the incremental fold, counting both books and any
    /// failed attempt before a literal fallback. Includes empty controls.
    pub appended_entries: usize,
    /// Legs submitted to checked addition on the incremental path, on both books.
    /// A failed addition can stop before all the submitted legs are visited.
    pub appended_legs: usize,
    /// Reservation targets checked on the incremental path, on both books.
    /// Includes holds created and resolved in one mapped commit.
    pub resolved_holds: usize,
    /// Original pending legs submitted to checked subtraction, on both books.
    /// A hold created and resolved in one mapped commit is never added and
    /// needs no subtraction. Failed attempts before a fallback are included.
    pub released_legs: usize,
    /// Pairs evaluated by the original full-prefix fold path. Its internal
    /// error fallbacks and hashing work are not measured by the other fields.
    pub full_fold_pairs: usize,
    /// Cell comparisons on the incremental path, including pending cells.
    pub cells_compared: usize,
}

/// Only a retained marker at the exact prefix can justify carrying a read.
/// Failure to obtain it disables the shortcut; the literal selector still
/// determines the result, just as it did before this optimization.
fn retained_marker<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    at: CommitSeq,
) -> Option<MarkerRef> {
    let before = at.0.checked_sub(1)?;
    db.delta_since(CommitSeq(before))
        .ok()?
        .next()
        .filter(|batch| batch.commit_seq() == at)
        .map(|batch| batch.commit_marker_identity())
}

/// A literal entry selection extended only when every way its inputs can
/// change is modeled. It is local to one verification, never persisted or
/// accepted as authoritative state from a caller.
#[derive(Default)]
struct EntrySelection {
    through: Option<CommitSeq>,
    marker: Option<MarkerRef>,
    /// The same order as the literal selector. Normal append-only history
    /// extends this vector without cloning old payloads or re-sorting them.
    entries: Vec<(VId, Entry, CommitSeq)>,
    by_vid: BTreeMap<VId, usize>,
    /// The previous selection is an unchanged prefix of this selection.
    /// `None` after a literal read or any change to an existing entry.
    append_from: Option<usize>,
}

impl EntrySelection {
    fn read<V: asupersync::fs::Vfs + Clone>(
        &mut self,
        db: &Database<V>,
        book: &BookContext,
        at: CommitSeq,
        work: &mut ReplayReadWork,
    ) -> Result<&[(VId, Entry, CommitSeq)], RegisterError> {
        if self.carry(db, book, at, work) {
            return Ok(&self.entries);
        }

        work.full_reads = work.full_reads.saturating_add(1);
        let mut counted = EntryReadCount::default();
        let read = entries_at_counted(db, book, at, &mut counted);
        work.vertices_read = work.vertices_read.saturating_add(counted.vertices_read);
        work.entries_decoded = work.entries_decoded.saturating_add(counted.entries_decoded);
        let entries = read?;
        self.entries = entries;
        self.index();
        self.through = Some(at);
        self.marker = retained_marker(db, at);
        self.append_from = None;
        Ok(&self.entries)
    }

    fn index(&mut self) {
        self.by_vid = self
            .entries
            .iter()
            .enumerate()
            .map(|(index, (vid, _, _))| (*vid, index))
            .collect();
    }

    /// A failed shortcut does not decide an error. The literal read at the
    /// same pair preserves its exact first error and diagnostic order.
    fn carry<V: asupersync::fs::Vfs + Clone>(
        &mut self,
        db: &Database<V>,
        book: &BookContext,
        at: CommitSeq,
        work: &mut ReplayReadWork,
    ) -> bool {
        let Some(from) = self.through else {
            return false;
        };
        if from > at || self.marker.is_none() || retained_marker(db, from) != self.marker {
            return false;
        }
        let Ok(batches) = db.delta_since(from) else {
            return false;
        };
        let mut through = from;
        let mut marker = self.marker;
        let mut touched = BTreeSet::new();
        for batch in batches {
            let seq = batch.commit_seq();
            if seq > at {
                break;
            }
            if through.0.checked_add(1) != Some(seq.0) {
                return false;
            }
            for coordinate in batch.coordinate_entries() {
                for row in &coordinate.rows {
                    work.delta_rows = work.delta_rows.saturating_add(1);
                    match row {
                        DeltaRow::CreateVertex {
                            vid,
                            labels,
                            valid_time,
                            ..
                        } => {
                            if valid_time.is_some() || labels.contains(&label::MIGRATION_RUN) {
                                return false;
                            }
                            touched.insert(*vid);
                        }
                        DeltaRow::Property {
                            elem: ElementId::Vertex(vid),
                            ..
                        } => {
                            touched.insert(*vid);
                        }
                        DeltaRow::LabelMembership {
                            vid,
                            label: changed,
                            ..
                        } => {
                            if *changed == label::ENTRY || *changed == label::MIGRATION_RUN {
                                return false;
                            }
                            touched.insert(*vid);
                        }
                        // Neither the literal entry selector nor migration
                        // visibility reads edges. Their projections cannot
                        // hide or manufacture an authoritative entry.
                        DeltaRow::CreateEdge { .. }
                        | DeltaRow::DeleteEdge { .. }
                        | DeltaRow::Property {
                            elem: ElementId::Edge(_),
                            ..
                        } => {}
                        // Includes vertex deletion, valid-time and every
                        // unmodeled family. A full read decides their effect.
                        _ => return false,
                    }
                }
            }
            through = seq;
            marker = Some(batch.commit_marker_identity());
        }
        if through != at {
            return false;
        }

        // Accumulate the suffix before changing the selected prefix. An
        // unmodeled row or a decode error must leave the old state intact
        // until the complete literal replacement succeeds.
        let mut changed = Vec::new();
        for vid in touched {
            work.vertices_read = work.vertices_read.saturating_add(1);
            let Ok(row) = db.vertex_at(vid, at) else {
                return false;
            };
            let Some(row) = row else {
                if self.by_vid.contains_key(&vid) {
                    return false;
                }
                continue;
            };
            // A run's state or immutable body can change the visibility of
            // chunks not present in the previous selected set. Re-read the
            // complete snapshot rather than assuming those chunks absent.
            if row.labels.contains(&label::MIGRATION_RUN) {
                return false;
            }
            if row.labels.contains(&label::ENTRY) {
                work.entries_decoded = work.entries_decoded.saturating_add(1);
            }
            match entry_from_row(&row, book) {
                Ok(Some(entry)) => {
                    if matches!(entry.proposal.origin, EntryOrigin::Migration { .. }) {
                        return false;
                    }
                    // `created_at` is the snapshot's version sequence. Even
                    // a rewrite followed by restoration must not keep the
                    // old version's contribution position.
                    changed.push((vid, entry, row.created_at));
                }
                Ok(None) => {
                    if self.by_vid.contains_key(&vid) {
                        return false;
                    }
                }
                Err(_) => return false,
            }
        }
        let previous_len = self.entries.len();
        let mut appended = true;
        let mut sorted = true;
        for (vid, entry, seq) in changed {
            if let Some(index) = self.by_vid.get(&vid).copied() {
                appended = false;
                sorted &= self.entries[index].2 == seq;
                self.entries[index] = (vid, entry, seq);
            } else {
                sorted &= self
                    .entries
                    .last()
                    .is_none_or(|(last_vid, _, last_seq)| (*last_seq, *last_vid) <= (seq, vid));
                self.by_vid.insert(vid, self.entries.len());
                self.entries.push((vid, entry, seq));
            }
        }
        if !sorted {
            self.entries.sort_by_key(|(vid, _, seq)| (*seq, vid.0));
            self.index();
        }
        self.through = Some(at);
        self.marker = marker;
        self.append_from = (appended && sorted).then_some(previous_len);
        true
    }
}

/// Only the values the replay contract compares. These are private,
/// short-lived folds of authenticated payloads, never cached book registers
/// or report certificates. Sequence-dependent fold digests intentionally are
/// not compared: source and scratch have different commit sequences.
#[derive(Default)]
struct CheckedPeriod {
    cells: BTreeMap<CellKey, Cell>,
    pending: BTreeMap<CellKey, Cell>,
    entries: u64,
    legs: u64,
    holds: usize,
}

impl CheckedPeriod {
    fn from_fold(fold: Fold, legs: u64) -> Self {
        Self {
            cells: fold
                .cells
                .into_iter()
                .map(|cell| (cell.key.clone(), cell))
                .collect(),
            pending: fold
                .pending
                .into_iter()
                .map(|cell| (cell.key.clone(), cell))
                .collect(),
            entries: fold.entries,
            legs,
            holds: fold.pending_holds.len(),
        }
    }
}

#[derive(Default)]
struct ChangedCells {
    periods: BTreeSet<String>,
    posted: BTreeSet<CellKey>,
    pending: BTreeSet<CellKey>,
}

#[derive(Default)]
struct CheckedFolds {
    periods: BTreeMap<String, CheckedPeriod>,
    /// A literal fallback can accept an empty set of periods without exposing
    /// an invalid resolution's fold error. Such a prefix cannot seed the
    /// shortcut: retain `None` and let the literal path decide later pairs too.
    resolved: Option<BTreeSet<VId>>,
}

/// Migration changes visibility of old contributions and requires the literal
/// selector. Native resolutions have a bounded inverse: remove the complete
/// original hold, then add the posted subvector (if any) in its own period.
fn incremental(entries: &[(VId, Entry, CommitSeq)]) -> bool {
    entries.iter().all(|(_, entry, _)| {
        !matches!(entry.proposal.origin, EntryOrigin::Migration { .. })
            && !matches!(
                entry.proposal.control,
                Some(ControlPayload::MigrationControl {
                    kind: fa_journal::migration::kind::FINALIZE,
                    ..
                })
            )
    })
}

fn append_folds(
    folds: &mut CheckedFolds,
    selection: &EntrySelection,
    from: usize,
    period_of: &mut PeriodOf<'_>,
    at: CommitSeq,
    work: &mut ReplayWork,
) -> Result<ChangedCells, RegisterError> {
    let mut changed = ChangedCells::default();
    let resolved = folds.resolved.as_mut().ok_or(RegisterError::Overflow)?;
    let entries = &selection.entries[from..];

    // Resolve first, as the literal fold does. A batch may release an old MAX
    // hold while creating a new one, or create and resolve a hold at one seq.
    // VId order is not staging order; neither case may transiently overflow.
    for (vid, entry, recorded_at) in entries {
        if entry.proposal.class != EntryClass::RESOLUTION {
            continue;
        }
        let target = entry
            .proposal
            .pending
            .as_ref()
            .and_then(|pending| pending.resolution_of)
            .ok_or(RegisterError::Overflow)?;
        let original_index = *selection
            .by_vid
            .get(&target.vid)
            .ok_or(RegisterError::Overflow)?;
        let (_, original, original_seq) = &selection.entries[original_index];
        // These are the literal `resolutions` predicate over the complete
        // carried selection, including same-commit targets. A failed check
        // only disables the shortcut; the literal path supplies the error.
        if original.proposal.class != EntryClass::PENDING
            || original.entry_digest != target.entry_digest
            || original_seq > recorded_at
            || *vid != fa_journal::rows::resolution_vid(target.vid)
            || !resolved.insert(target.vid)
        {
            return Err(RegisterError::Overflow);
        }
        work.resolved_holds = work.resolved_holds.saturating_add(1);
        if original_index >= from || original.proposal.legs.is_empty() {
            // The addition pass skips holds already resolved at this pair.
            continue;
        }
        let period = period_of.period(original)?;
        let fold = folds
            .periods
            .get_mut(period)
            .ok_or(RegisterError::Overflow)?;
        release_hold(fold, original, period, &mut changed, work)?;
    }

    for (vid, entry, recorded_at) in entries {
        work.appended_entries = work.appended_entries.saturating_add(1);
        if entry.proposal.legs.is_empty() {
            continue;
        }
        let period = period_of.period(entry)?;
        let fold = folds.periods.entry(period.to_string()).or_default();
        changed.periods.insert(period.to_string());
        let pending = entry.proposal.class == EntryClass::PENDING;
        if pending && resolved.contains(vid) {
            continue;
        }
        let (cells, keys) = if pending {
            fold.holds = fold.holds.checked_add(1).ok_or(RegisterError::Overflow)?;
            (&mut fold.pending, &mut changed.pending)
        } else {
            fold.entries = fold.entries.checked_add(1).ok_or(RegisterError::Overflow)?;
            (&mut fold.cells, &mut changed.posted)
        };
        work.appended_legs = work.appended_legs.saturating_add(entry.proposal.legs.len());
        add_entry(cells, entry, period, (*vid, *recorded_at), at)?;
        fold.legs = fold
            .legs
            .checked_add(entry.proposal.legs.len() as u64)
            .ok_or(RegisterError::Overflow)?;
        // The literal fold also encodes its cell/hold counts as u32 and
        // contribution ordinals as u16. Preserve those representability
        // checks without re-encoding unchanged cells at every pair.
        if u32::try_from(cells.len()).is_err()
            || u32::try_from(fold.holds).is_err()
            || u16::try_from(entry.proposal.legs.len() - 1).is_err()
        {
            return Err(RegisterError::Encoding(
                fa_model::EncodeError::LengthOverflow,
            ));
        }
        for leg in &entry.proposal.legs {
            keys.insert(CellKey {
                account: leg.account_ref,
                unit_id: leg.amount.unit.0,
                period: period.to_string(),
            });
        }
    }
    Ok(changed)
}

/// Remove a previously counted hold, including its one-per-cell entry count.
/// Zero-count rows disappear exactly as in a literal fold that never added the
/// resolved hold. All arithmetic is checked; malformed negative amounts or a
/// state inconsistency fall back instead of changing the verifier's verdict.
fn release_hold(
    fold: &mut CheckedPeriod,
    original: &Entry,
    period: &str,
    changed: &mut ChangedCells,
    work: &mut ReplayWork,
) -> Result<(), RegisterError> {
    let mut touched = BTreeSet::new();
    work.released_legs = work
        .released_legs
        .saturating_add(original.proposal.legs.len());
    for leg in &original.proposal.legs {
        if leg.amount.mantissa < 0 {
            return Err(RegisterError::Overflow);
        }
        let key = CellKey {
            account: leg.account_ref,
            unit_id: leg.amount.unit.0,
            period: period.to_string(),
        };
        let cell = fold.pending.get_mut(&key).ok_or(RegisterError::Overflow)?;
        let slot = match leg.side {
            fa_money::Side::Debit => &mut cell.debits,
            fa_money::Side::Credit => &mut cell.credits,
        };
        *slot = slot
            .checked_sub(leg.amount.mantissa)
            .filter(|amount| *amount >= 0)
            .ok_or(RegisterError::Overflow)?;
        touched.insert(key);
    }
    for key in touched {
        let cell = fold.pending.get_mut(&key).ok_or(RegisterError::Overflow)?;
        cell.entry_count = cell
            .entry_count
            .checked_sub(1)
            .ok_or(RegisterError::Overflow)?;
        if cell.entry_count == 0 {
            if cell.debits != 0 || cell.credits != 0 {
                return Err(RegisterError::Overflow);
            }
            fold.pending.remove(&key);
        }
        changed.pending.insert(key);
    }
    fold.holds = fold.holds.checked_sub(1).ok_or(RegisterError::Overflow)?;
    fold.legs = fold
        .legs
        .checked_sub(original.proposal.legs.len() as u64)
        .ok_or(RegisterError::Overflow)?;
    changed.periods.insert(period.to_string());
    Ok(())
}

/// A successful previous pair proved every unchanged value equal. Compare
/// the union of changed keys, retaining the first period's diagnostic order.
fn different_period(
    source: &CheckedFolds,
    scratch: &CheckedFolds,
    a: ChangedCells,
    b: ChangedCells,
    work: &mut ReplayWork,
) -> Option<String> {
    let mut different = BTreeSet::new();
    for period in a.periods.union(&b.periods) {
        if source.periods.get(period).map(|fold| fold.entries)
            != scratch.periods.get(period).map(|fold| fold.entries)
        {
            different.insert(period.clone());
        }
    }
    for (pending, left, right) in [(false, a.posted, b.posted), (true, a.pending, b.pending)] {
        for key in left.union(&right) {
            work.cells_compared = work.cells_compared.saturating_add(1);
            if checked_cell(source, key, pending) != checked_cell(scratch, key, pending) {
                different.insert(key.period.clone());
            }
        }
    }
    different.into_iter().next()
}

fn checked_cell<'a>(folds: &'a CheckedFolds, key: &CellKey, pending: bool) -> Option<&'a Cell> {
    folds.periods.get(&key.period).and_then(|fold| {
        if pending {
            fold.pending.get(key)
        } else {
            fold.cells.get(key)
        }
    })
}

fn invalid(why: String) -> Refusal {
    Refusal::new(
        code::SEQ_MAP_INVALID,
        exit::VERIFICATION,
        why,
        "plan §15.2 (a scratch book's certificate carries its SeqMap; replay equals the source at every mapped sequence)",
        "replay again with fa_journal::scratch::replay_into and verify the fresh map; a SeqMap is never edited",
    )
}

/// Verify `map` as the replay of `source`'s accounting history into
/// `scratch` (see the module docs).
pub fn verify_replay<V, W>(
    source: &Database<V>,
    scratch: &Database<W>,
    book: &BookContext,
    map: &SeqMap,
) -> Result<Result<ReplayVerification, Refusal>, RegisterError>
where
    V: asupersync::fs::Vfs + Clone,
    W: asupersync::fs::Vfs + Clone,
{
    verify_replay_counted(source, scratch, book, map).map(|(verdict, _)| verdict)
}

/// The same verdict as [`verify_replay`], with transparent work counters.
/// Native histories decode and add each new posting once per side; resolutions
/// additionally visit only their original pending vector. Migration and changed
/// historical entries retain the literal fallback. Source-map validation and
/// scratch-book construction are unchanged and are outside these counters.
pub fn verify_replay_counted<V, W>(
    source: &Database<V>,
    scratch: &Database<W>,
    book: &BookContext,
    map: &SeqMap,
) -> Result<(Result<ReplayVerification, Refusal>, ReplayWork), RegisterError>
where
    V: asupersync::fs::Vfs + Clone,
    W: asupersync::fs::Vfs + Clone,
{
    let mut work = ReplayWork::default();
    let verdict = verify_replay_with_work(source, scratch, book, map, &mut work)?;
    Ok((verdict, work))
}

fn verify_replay_with_work<V, W>(
    source: &Database<V>,
    scratch: &Database<W>,
    book: &BookContext,
    map: &SeqMap,
    work: &mut ReplayWork,
) -> Result<Result<ReplayVerification, Refusal>, RegisterError>
where
    V: asupersync::fs::Vfs + Clone,
    W: asupersync::fs::Vfs + Clone,
{
    if map.source_book != book.book_id {
        return Ok(Err(invalid(format!(
            "the map names book {}, not {}",
            map.source_book.to_hex(),
            book.book_id.to_hex()
        ))));
    }
    if !map.is_monotone() {
        return Ok(Err(invalid(
            "the map's pairs are not strictly increasing on both sides".into(),
        )));
    }
    // The verifier is the outsider's check: a prefix past the source's
    // frontier names history the source does not hold, refused here even
    // though `source_batches` refuses it when a replay is made.
    let frontier = source.frontier()?;
    if map.source_prefix > frontier {
        return Ok(Err(invalid(format!(
            "the map's source prefix {} is past the source frontier {}",
            map.source_prefix.0, frontier.0
        ))));
    }
    // Nor before the book's genesis: an empty map over an empty database is
    // not a scratch book.
    // Maintenance advances the root's content version. Only its original
    // CreateVertex in the authenticated history defines the book's genesis.
    let genesis = source_genesis(source)?;
    if genesis.is_none_or(|g| map.source_prefix < g) {
        return Ok(Err(invalid(format!(
            "the map's source prefix {} precedes the source book's genesis ({})",
            map.source_prefix.0,
            genesis.map_or_else(|| "no book".to_string(), |g| g.0.to_string())
        ))));
    }
    // The source commits a replay through the prefix must reproduce.
    let mut maintenance = Maintenance::default();
    let mut expected: Vec<(CommitSeq, [u8; 32])> = Vec::new();
    for batch in source
        .delta_since(CommitSeq(0))?
        .filter(|b| b.commit_seq() <= map.source_prefix)
    {
        match replayable(batch, &mut maintenance) {
            Ok(writes) if !writes.is_empty() => {
                expected.push((
                    batch.commit_seq(),
                    batch.commit_marker_identity().marker_oid.0,
                ));
            }
            Ok(_) => {}
            Err(r) => return Ok(Err(r)),
        }
    }
    let named: Vec<(CommitSeq, [u8; 32])> = map
        .pairs
        .iter()
        .map(|p| (p.source_seq, p.source_marker))
        .collect();
    if named != expected {
        let first = expected
            .iter()
            .zip(&named)
            .position(|(a, b)| a != b)
            .unwrap_or(expected.len().min(named.len()));
        return Ok(Err(invalid(format!(
            "the map does not name exactly the source's accounting commits through {}: {} expected, {} named, first difference at pair {first}",
            map.source_prefix.0,
            expected.len(),
            named.len()
        ))));
    }
    let digest = map.digest()?;
    let mut entries_checked = 0;
    let mut folds_checked = 0;
    let mut period_of = PeriodOf::new(book);
    let mut source_selection = EntrySelection::default();
    let mut scratch_selection = EntrySelection::default();
    let mut checked_source = CheckedFolds::default();
    let mut checked_scratch = CheckedFolds::default();
    for pair in &map.pairs {
        source_selection.read(source, book, pair.source_seq, &mut work.source)?;
        scratch_selection.read(scratch, book, pair.scratch_seq, &mut work.scratch)?;
        let src_entries = &source_selection.entries;
        let scr_entries = &scratch_selection.entries;
        let appended = source_selection
            .append_from
            .zip(scratch_selection.append_from);
        let (src_changed, scr_changed) = match appended {
            Some((a, b)) => (&src_entries[a..], &scr_entries[b..]),
            None => (src_entries.as_slice(), scr_entries.as_slice()),
        };
        let digests = |entries: &[(VId, fa_model::Entry, CommitSeq)]| {
            entries
                .iter()
                .map(|(v, e, _)| (*v, e.entry_digest))
                .collect::<BTreeMap<_, _>>()
        };
        work.identities_compared = work
            .identities_compared
            .saturating_add(src_changed.len())
            .saturating_add(scr_changed.len());
        let (src, scr) = (digests(src_changed), digests(scr_changed));
        if src != scr {
            return Ok(Err(invalid(format!(
                "at source {} / scratch {} the books select different entries ({} vs {})",
                pair.source_seq.0,
                pair.scratch_seq.0,
                src_entries.len(),
                scr_entries.len()
            ))));
        }
        entries_checked += src_entries.len();
        if let Some((source_from, scratch_from)) = appended
            && checked_source.resolved.is_some()
            && checked_scratch.resolved.is_some()
            && incremental(src_changed)
            && incremental(scr_changed)
        {
            let attempt = (|| -> Result<Option<String>, RegisterError> {
                let a = append_folds(
                    &mut checked_source,
                    &source_selection,
                    source_from,
                    &mut period_of,
                    pair.source_seq,
                    work,
                )?;
                let b = append_folds(
                    &mut checked_scratch,
                    &scratch_selection,
                    scratch_from,
                    &mut period_of,
                    pair.scratch_seq,
                    work,
                )?;
                // Period definitions are snapshot inputs too. Even a pair
                // with no new posting must still observe damaged/deleted
                // period metadata at its exact source and scratch prefixes.
                resolve_known_at(source, Some(pair.source_seq))?;
                resolve_known_at(scratch, Some(pair.scratch_seq))?;
                for period in checked_source.periods.keys() {
                    period_at(source, book, period, pair.source_seq)?;
                    period_at(scratch, book, period, pair.scratch_seq)?;
                }
                Ok(different_period(
                    &checked_source,
                    &checked_scratch,
                    a,
                    b,
                    work,
                ))
            })();
            if let Ok(different) = attempt {
                if let Some(period) = different {
                    return Ok(Err(invalid(format!(
                        "at source {} / scratch {} period `{period}` folds differently",
                        pair.source_seq.0, pair.scratch_seq.0,
                    ))));
                }
                folds_checked += checked_source.periods.len();
                continue;
            }
            // A partial attempted addition is not a verdict. Replace both
            // states with the literal folds below, which also preserve the
            // original first-error order and capacity diagnosis.
        }
        work.full_fold_pairs = work.full_fold_pairs.saturating_add(1);
        let mut periods = BTreeSet::new();
        for (_, e, _) in src_entries {
            if !e.proposal.legs.is_empty() {
                periods.insert(period_of.period(e)?.to_string());
            }
        }
        // Every period from the entry lists just read, not a fresh read and
        // decode of the prefix per period and side (fa-rbs3).
        // Each fold is the one fold_period_at returns, error included.
        let periods: BTreeSet<&str> = periods.iter().map(String::as_str).collect();
        let mut source_folds = folds_at(source, book, &periods, pair.source_seq, Some(src_entries));
        let mut scratch_folds =
            folds_at(scratch, book, &periods, pair.scratch_seq, Some(scr_entries));
        checked_source = CheckedFolds::default();
        checked_scratch = CheckedFolds::default();
        for period in periods {
            let (a, a_legs) = take_fold(&mut source_folds, period)?;
            let (b, b_legs) = take_fold(&mut scratch_folds, period)?;
            if a.cells != b.cells || a.pending != b.pending || a.entries != b.entries {
                return Ok(Err(invalid(format!(
                    "at source {} / scratch {} period `{period}` folds differently",
                    pair.source_seq.0, pair.scratch_seq.0
                ))));
            }
            checked_source
                .periods
                .insert(period.to_string(), CheckedPeriod::from_fold(a, a_legs));
            checked_scratch
                .periods
                .insert(period.to_string(), CheckedPeriod::from_fold(b, b_legs));
            folds_checked += 1;
        }
        checked_source.resolved = crate::resolutions(src_entries)
            .ok()
            .map(|resolved| resolved.into_keys().collect());
        checked_scratch.resolved = crate::resolutions(scr_entries)
            .ok()
            .map(|resolved| resolved.into_keys().collect());
    }
    Ok(Ok(ReplayVerification {
        seq_map_digest: digest,
        pairs_checked: map.pairs.len(),
        entries_checked,
        folds_checked,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::Budget;
    use asupersync::runtime::{Runtime, RuntimeBuilder};
    use fa_journal::rows::scalar_bytes;
    use fa_model::symbols::{property, relation};
    use fa_model::{
        EntryClass, EntryPayload, Erasable, Id128, LegPayload, Oid, SealKey, SymbolTable,
    };
    use fa_money::{Amount, Side, UnitRegistry};
    use fa_time::{DateDay, FiscalCalendar};
    use fgdb::{DatabaseKeys, MemVfs, WriteBatch};
    use fgdb_types::context::PurposeContexts;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    // These raw substrate fixtures isolate selection and cache mechanics.
    // Posting admission and replay-map acceptance use the real-kernel
    // integration fixtures in tests/migration.rs.
    struct Fixture {
        runtime: Runtime,
        cx: PurposeContexts,
        db: Database<MemVfs>,
        book: BookContext,
        vfs: MemVfs,
        keys: DatabaseKeys,
    }

    impl Fixture {
        fn new() -> Self {
            let runtime = RuntimeBuilder::new().build().unwrap();
            let root = runtime.request_cx_with_budget(Budget::INFINITE);
            let cx = PurposeContexts::narrow_runtime_root(&root);
            let vfs = MemVfs::new().unwrap();
            let keys = DatabaseKeys::new(
                [0x71; 32],
                DatabaseSecurityNamespaceId([0x72; 32]),
                [0x73; 32],
            );
            let db = runtime
                .block_on(Database::create_with_vfs(
                    &cx.commit(),
                    vfs.clone(),
                    vfs.database_dir(),
                    keys.clone(),
                ))
                .unwrap();
            Self {
                runtime,
                cx,
                db,
                book: BookContext {
                    book_id: Id128([0x74; 16]),
                    calendar: FiscalCalendar::monthly("replay-selection", 1, 1).unwrap(),
                    units: UnitRegistry::with_defaults(),
                    seal_key: SealKey([0x75; 32]),
                    symbols: SymbolTable::compiled(),
                },
                vfs,
                keys,
            }
        }

        fn entry(&self, key: &str) -> Entry {
            let unit = self.book.units.lookup("USD").unwrap();
            let legs = vec![
                LegPayload::simple(Side::Debit, VId(100), Amount::new(unit, 500)),
                LegPayload::simple(Side::Credit, VId(200), Amount::new(unit, 500)),
            ];
            EntryPayload {
                schema_minor: fa_model::entry::SCHEMA_MINOR,
                book_id: self.book.book_id,
                branch_id: Id128::TRUNK,
                class: EntryClass::ORIGINAL,
                effective_date: DateDay(20_000),
                document_date: None,
                description: Erasable::seal(
                    &key.to_string(),
                    None,
                    &self.book.seal_key,
                    [0x76; 32],
                    [0x77; 24],
                ),
                effective_period: None,
                unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
                legs,
                control: None,
                base_totals: None,
                idempotency_key: key.as_bytes().to_vec(),
                origin: EntryOrigin::Intent {
                    intent_oid: Oid([0x78; 32]),
                    intent_kind: 1,
                },
                principal_ref: VId(300),
                session_ref: None,
                evidence: Vec::new(),
                supersession: Vec::new(),
                pending: None,
                external_ids: Vec::new(),
                tags: Vec::new(),
                extensions: Vec::new(),
            }
            .seal(Vec::new(), None)
            .unwrap()
        }

        fn write(&mut self, batch: WriteBatch) -> CommitSeq {
            self.runtime
                .block_on(self.db.write(&self.cx.commit(), batch))
                .unwrap();
            self.db.frontier().unwrap()
        }

        fn add(&mut self, vid: VId, entry: &Entry) -> CommitSeq {
            let mut batch = WriteBatch::new(relation::IN_BOOK);
            batch.create_vertex(
                vid,
                vec![label::ENTRY],
                vec![(
                    property::FA_PAYLOAD,
                    scalar_bytes("entry.payload", entry.encode().unwrap()).unwrap(),
                )],
            );
            self.write(batch)
        }
    }

    #[test]
    fn carried_selection_rereads_restored_versions_in_snapshot_order() {
        let mut f = Fixture::new();
        let first = f.entry("first");
        f.add(VId(1), &first);
        let second = f.entry("second");
        let before = f.add(VId(2), &second);
        let rewritten = f.entry("rewritten");
        for entry in [&rewritten, &first] {
            let mut change = WriteBatch::new(relation::IN_BOOK);
            change.set_vertex_property(
                VId(1),
                property::FA_PAYLOAD,
                Some(scalar_bytes("entry.payload", entry.encode().unwrap()).unwrap()),
            );
            f.write(change);
        }
        let restored = f.db.frontier().unwrap();
        let mut selection = EntrySelection::default();
        let mut work = ReplayReadWork::default();
        let initial = selection.read(&f.db, &f.book, before, &mut work).unwrap();
        assert_eq!(
            initial.iter().map(|(vid, _, _)| *vid).collect::<Vec<_>>(),
            vec![VId(1), VId(2)]
        );
        let actual = selection.read(&f.db, &f.book, restored, &mut work).unwrap();
        let expected = crate::entries_at(&f.db, &f.book, restored).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual[1], (VId(1), first, restored));
        assert_eq!(work.full_reads, 1);
        assert_eq!(
            work.entries_decoded, 3,
            "only the changed historical entry was decoded again"
        );
    }

    #[test]
    fn carried_selection_never_reuses_a_different_database_prefix() {
        let mut a = Fixture::new();
        let first = a.entry("source");
        let at = a.add(VId(1), &first);
        let mut b = Fixture::new();
        let other = b.entry("other");
        assert_eq!(b.add(VId(2), &other), at);
        assert_ne!(retained_marker(&a.db, at), retained_marker(&b.db, at));
        let mut selection = EntrySelection::default();
        let mut work = ReplayReadWork::default();
        selection.read(&a.db, &a.book, at, &mut work).unwrap();
        let actual = selection.read(&b.db, &b.book, at, &mut work).unwrap();
        assert_eq!(actual, crate::entries_at(&b.db, &b.book, at).unwrap());
        assert_eq!(actual[0].0, VId(2));
        assert_eq!(
            work.full_reads, 2,
            "a shared sequence number is not prefix identity"
        );
    }

    #[test]
    fn an_unloaded_delta_window_falls_back_to_each_literal_snapshot() {
        let mut f = Fixture::new();
        let first = f.entry("first");
        let before = f.add(VId(1), &first);
        let second = f.entry("second");
        let after = f.add(VId(2), &second);
        drop(f.db);
        let db = f
            .runtime
            .block_on(Database::open_with_vfs(
                &f.cx.commit(),
                f.vfs.clone(),
                f.vfs.database_dir(),
                f.keys.clone(),
            ))
            .unwrap();
        assert!(
            db.delta_since(CommitSeq(0)).is_err(),
            "the reopened prefix is not yet loaded"
        );
        let mut selection = EntrySelection::default();
        let mut work = ReplayReadWork::default();
        for at in [before, after] {
            assert_eq!(
                selection.read(&db, &f.book, at, &mut work).unwrap(),
                crate::entries_at(&db, &f.book, at).unwrap()
            );
        }
        assert_eq!(work.full_reads, 2);
        assert_eq!(work.entries_decoded, 3);
        assert_eq!(work.delta_rows, 0, "no unretained suffix was inferred");
    }

    #[test]
    fn a_failed_carried_and_literal_read_preserves_the_previous_selection() {
        let mut f = Fixture::new();
        let first = f.entry("first");
        let before = f.add(VId(1), &first);
        let changed = f.entry("changed");
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        batch.set_vertex_property(
            VId(1),
            property::FA_PAYLOAD,
            Some(scalar_bytes("entry.payload", changed.encode().unwrap()).unwrap()),
        );
        batch.create_vertex(
            VId(2),
            vec![label::ENTRY],
            vec![(
                property::FA_PAYLOAD,
                scalar_bytes("entry.payload", vec![0xff]).unwrap(),
            )],
        );
        let invalid = f.write(batch);
        let mut selection = EntrySelection::default();
        let mut work = ReplayReadWork::default();
        let initial = selection
            .read(&f.db, &f.book, before, &mut work)
            .unwrap()
            .to_vec();
        let expected = crate::entries_at(&f.db, &f.book, invalid)
            .unwrap_err()
            .to_string();
        assert_eq!(
            selection
                .read(&f.db, &f.book, invalid, &mut work)
                .unwrap_err()
                .to_string(),
            expected
        );
        assert_eq!(selection.entries, initial);
        assert_eq!(selection.through, Some(before));
        assert_eq!(selection.by_vid, BTreeMap::from([(VId(1), 0)]));
        assert_eq!(work.full_reads, 2, "the literal read decides the error");
    }
}
