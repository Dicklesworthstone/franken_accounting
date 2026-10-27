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
//! themselves are still recomputed at every pair; this removes repeated entry
//! decoding, not the remaining quadratic fold work.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Refusal, exit};
use fa_journal::scratch::{Maintenance, SeqMap, replayable, source_genesis};
use fa_model::symbols::label;
use fa_model::{Entry, EntryOrigin};
use fgdb::Database;
use fgdb_delta_types::{DeltaRow, ElementId};
use fgdb_types::{CommitSeq, MarkerRef, VId};

use crate::{
    EntryReadCount, PeriodOf, RegisterError, entries_at_counted, entry_from_row, folds_at,
    take_fold,
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
/// and the unchanged per-pair folds are outside their scope.
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
        let mut sorted = true;
        for (vid, entry, seq) in changed {
            if let Some(index) = self.by_vid.get(&vid).copied() {
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
        true
    }
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

/// The same verdict as [`verify_replay`], with a transparent witness of the
/// entry-selection work. Normal native histories decode each newly touched
/// entry once per side instead of decoding every old entry at every pair.
/// Folds, source-map validation and scratch-book construction are unchanged.
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
    for pair in &map.pairs {
        let src_entries = source_selection.read(source, book, pair.source_seq, &mut work.source)?;
        let scr_entries =
            scratch_selection.read(scratch, book, pair.scratch_seq, &mut work.scratch)?;
        let digests = |entries: &[(VId, fa_model::Entry, CommitSeq)]| {
            entries
                .iter()
                .map(|(v, e, _)| (*v, e.entry_digest))
                .collect::<BTreeMap<_, _>>()
        };
        let (src, scr) = (digests(src_entries), digests(scr_entries));
        if src != scr {
            return Ok(Err(invalid(format!(
                "at source {} / scratch {} the books select different entries ({} vs {})",
                pair.source_seq.0,
                pair.scratch_seq.0,
                src.len(),
                scr.len()
            ))));
        }
        entries_checked += src.len();
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
        for period in periods {
            let (a, _) = take_fold(&mut source_folds, period)?;
            let (b, _) = take_fold(&mut scratch_folds, period)?;
            if a.cells != b.cells || a.pending != b.pending || a.entries != b.entries {
                return Ok(Err(invalid(format!(
                    "at source {} / scratch {} period `{period}` folds differently",
                    pair.source_seq.0, pair.scratch_seq.0
                ))));
            }
            folds_checked += 1;
        }
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
