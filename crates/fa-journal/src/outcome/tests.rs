//! Native tamper regressions for coverage's authenticated point proofs.

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_model::symbols::relation;
use fa_model::{SealKey, SymbolTable};
use fa_money::UnitRegistry;
use fa_time::FiscalCalendar;
use fgdb::{DatabaseKeys, MemVfs};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;

use super::*;

struct Harness {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
}

impl Harness {
    fn empty() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let db = runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([111; 32], DatabaseSecurityNamespaceId([112; 32]), [113; 32]),
            ))
            .unwrap();
        Self {
            runtime,
            root,
            db,
            book: BookContext {
                book_id: Id128([114; 16]),
                calendar: FiscalCalendar::monthly("coverage-test", 1, 1).unwrap(),
                units: UnitRegistry::with_defaults(),
                seal_key: SealKey([115; 32]),
                symbols: SymbolTable::compiled(),
            },
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn write(&mut self, batch: WriteBatch) -> CommitSeq {
        let cx = self.cx();
        self.runtime
            .block_on(self.db.write(&cx.commit(), batch))
            .unwrap()
    }

    // The private coverage-proof tests need a real, distinct native prefix;
    // populated legacy rebuilds exercise the public producer separately.
    fn source(name: &str) -> Self {
        let mut h = Self::empty();
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        batch.create_vertex(
            book_root(),
            vec![label::BOOK],
            vec![
                (
                    property::BOOK_ID,
                    scalar_bytes("book", h.book.book_id.0.to_vec()).unwrap(),
                ),
                (
                    property::NAME,
                    crate::rows::scalar_text("name", name).unwrap(),
                ),
            ],
        );
        h.write(batch);
        h
    }

    fn coverage(&self, keys_digest: [u8; 32], count: u64) -> Coverage {
        let basis = self.db.frontier().unwrap();
        let mut coverage = Coverage {
            book: self.book.book_id,
            basis,
            source_marker: marker_at(&self.db, basis).unwrap(),
            operator: VId(116),
            epoch: 0,
            entries: count,
            claims_digest: domain_digest(b"fa:test:omitted-outcome-claims:v1", &[]),
            keys_digest,
            authentication: [0; 32],
        };
        coverage.authentication = coverage.authenticate(&self.book).unwrap();
        coverage
    }
}

#[test]
fn authenticated_legacy_keys_remain_reserved_when_claim_roots_were_omitted() {
    let mut h = Harness::source("complete source prefix");
    let occupied = [VId(10_001), VId(10_003), VId(10_005)];
    let mut publication = WriteBatch::new(relation::IN_BOOK);
    let root = keys::stage(&mut publication, h.book.book_id, &occupied).unwrap();
    let coverage = h.coverage(root, occupied.len() as u64);
    stage_coverage(&mut publication, &coverage).unwrap();
    h.write(publication);
    let before = h.db.vertices().unwrap();
    let head = h.db.frontier().unwrap();

    for key in occupied {
        assert!(h.db.vertex(key).unwrap().is_none(), "the claim was omitted");
        let txn = h.db.begin(&h.cx().txn()).unwrap();
        let refusal = require_unused_legacy_key(&txn, &h.db, &h.book, key)
            .unwrap()
            .unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT)
        );
        txn.abort();
    }
    let txn = h.db.begin(&h.cx().txn()).unwrap();
    require_unused_legacy_key(&txn, &h.db, &h.book, VId(10_002))
        .unwrap()
        .unwrap();
    txn.abort();
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), before);
}

#[test]
fn missing_authenticated_key_nodes_refuse_without_publication() {
    let mut h = Harness::source("source with a reserved key");
    let mut omitted_nodes = WriteBatch::new(relation::IN_BOOK);
    let root = keys::stage(&mut omitted_nodes, h.book.book_id, &[VId(20_001)]).unwrap();
    let coverage = h.coverage(root, 1);
    // The authentic commitment survives, but its point-proof rows do not.
    // Neither membership nor nonmembership may be inferred from absence.
    let mut publication = WriteBatch::new(relation::IN_BOOK);
    stage_coverage(&mut publication, &coverage).unwrap();
    h.write(publication);
    let before = h.db.vertices().unwrap();
    let head = h.db.frontier().unwrap();
    for key in [VId(20_001), VId(20_002)] {
        let txn = h.db.begin(&h.cx().txn()).unwrap();
        let error = require_unused_legacy_key(&txn, &h.db, &h.book, key).unwrap_err();
        assert!(
            matches!(error, KernelError::Corrupt(ref why) if why.contains("missing a node")),
            "{error}"
        );
        txn.abort();
    }
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), before);
}

#[test]
fn authentic_coverage_cannot_move_to_a_divergent_native_prefix() {
    let mut source = Harness::source("source A");
    let mut target = Harness::source("divergent source B");
    let basis = source.db.frontier().unwrap();
    assert_eq!(target.db.frontier().unwrap(), basis);
    assert_eq!(source.book.book_id, target.book.book_id);
    assert_ne!(
        marker_at(&source.db, basis).unwrap(),
        marker_at(&target.db, basis).unwrap()
    );

    let coverage = source.coverage(keys::empty_digest(), 0);
    for h in [&mut source, &mut target] {
        let mut publication = WriteBatch::new(relation::IN_BOOK);
        stage_coverage(&mut publication, &coverage).unwrap();
        h.write(publication);
    }
    let vid = coverage_vid(source.book.book_id);
    let original_row = source.db.vertex(vid).unwrap().unwrap();
    let transplanted = target.db.vertex(vid).unwrap().unwrap();
    assert_eq!(
        original_row.props, transplanted.props,
        "the signature is authentic"
    );
    assert_eq!(
        coverage_of(&source.db, &source.book, &original_row).unwrap(),
        coverage
    );
    assert!(
        original(&target.db, &transplanted).unwrap(),
        "native birth alone is insufficient"
    );
    let head = target.db.frontier().unwrap();
    let before = target.db.vertices().unwrap();
    let txn = target.db.begin(&target.cx().txn()).unwrap();
    let error = require_unused_legacy_key(&txn, &target.db, &target.book, VId(30_001)).unwrap_err();
    assert!(
        matches!(error, KernelError::Corrupt(ref why) if why.contains("source prefix")),
        "{error}"
    );
    txn.abort();
    assert_eq!(target.db.frontier().unwrap(), head);
    assert_eq!(target.db.vertices().unwrap(), before);
}

#[test]
fn genesis_coverage_cannot_share_its_birth_with_a_journal_entry() {
    let mut source = Harness::empty();
    let spec = crate::genesis::BookSpec {
        book_id: source.book.book_id,
        name: "Real genesis".into(),
        base_unit: source.book.units.lookup("USD").unwrap(),
        calendar: source.book.calendar.clone(),
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    };
    let cx = source.cx();
    source
        .runtime
        .block_on(crate::genesis::create_book(
            &mut source.db,
            &cx,
            &spec,
            &source.book.units,
            &source.book.symbols,
        ))
        .unwrap();
    let vid = coverage_vid(source.book.book_id);
    let row = source.db.vertex(vid).unwrap().unwrap();
    assert!(coverage_of(&source.db, &source.book, &row).is_ok());

    let mut target = Harness::empty();
    let mut planted = WriteBatch::new(relation::IN_BOOK);
    let mut rows = source.db.vertices().unwrap();
    rows.sort_by_key(|row| row.birth_ordinal);
    for row in rows {
        planted.create_vertex(row.vid, row.labels, row.props);
    }
    for edge in source.db.edges_at(source.db.frontier().unwrap()).unwrap() {
        assert_eq!(edge.entry.relation, relation::IN_BOOK);
        planted.add_edge(edge.entry.eid, edge.entry.src, edge.entry.dst, edge.props);
    }
    planted.create_vertex(VId(40_001), vec![label::ENTRY], Vec::new());
    target.write(planted);
    let transplanted = target.db.vertex(vid).unwrap().unwrap();
    assert!(original(&target.db, &transplanted).unwrap());
    // A faithful transplant: its root is the first birth, as the genuine
    // root is, so only the planted Entry can make it refuse.
    let first_birth =
        |db: &fgdb::Database<MemVfs>| db.vertex(book_root()).unwrap().unwrap().birth_ordinal;
    assert_eq!(first_birth(&target.db), first_birth(&source.db));
    let head = target.db.frontier().unwrap();
    let before = target.db.vertices().unwrap();
    let error = coverage_of(&target.db, &target.book, &transplanted).unwrap_err();
    assert!(matches!(error, KernelError::Corrupt(_)), "{error}");
    assert_eq!(target.db.frontier().unwrap(), head);
    assert_eq!(target.db.vertices().unwrap(), before);
}

/// A reopened on-disk book retains no delta batch before its frontier, so
/// its genesis frame is unloaded: coverage is then authenticated from the
/// genesis snapshot. A genuine genesis still verifies; a frame that also
/// births an Entry still refuses.
#[test]
fn genesis_coverage_verifies_after_reopen_when_its_frame_is_unloaded() {
    let h = Harness::empty();
    let cx = h.cx();
    let keys = DatabaseKeys::new([116; 32], DatabaseSecurityNamespaceId([117; 32]), [118; 32]);
    let spec = crate::genesis::BookSpec {
        book_id: h.book.book_id,
        name: "Reopened genesis".into(),
        base_unit: h.book.units.lookup("USD").unwrap(),
        calendar: h.book.calendar.clone(),
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    };
    let reopened = |plant: bool| {
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let path = vfs.database_dir();
        let mut db = h
            .runtime
            .block_on(Database::create_with_vfs(
                &cx.commit(),
                vfs.clone(),
                &path,
                keys.clone(),
            ))
            .unwrap();
        if plant {
            // The genuine genesis rows, transplanted with an extra Entry.
            let mut source = Harness::empty();
            let source_cx = source.cx();
            source
                .runtime
                .block_on(crate::genesis::create_book(
                    &mut source.db,
                    &source_cx,
                    &spec,
                    &source.book.units,
                    &source.book.symbols,
                ))
                .unwrap();
            let mut planted = WriteBatch::new(relation::IN_BOOK);
            let mut rows = source.db.vertices().unwrap();
            rows.sort_by_key(|row| row.birth_ordinal);
            for row in rows {
                planted.create_vertex(row.vid, row.labels, row.props);
            }
            for edge in source.db.edges_at(source.db.frontier().unwrap()).unwrap() {
                planted.add_edge(edge.entry.eid, edge.entry.src, edge.entry.dst, edge.props);
            }
            planted.create_vertex(VId(40_002), vec![label::ENTRY], Vec::new());
            h.runtime.block_on(db.write(&cx.commit(), planted)).unwrap();
        } else {
            h.runtime
                .block_on(crate::genesis::create_book(
                    &mut db,
                    &cx,
                    &spec,
                    &h.book.units,
                    &h.book.symbols,
                ))
                .unwrap();
        }
        drop(db);
        let db = h
            .runtime
            .block_on(Database::open_with_vfs(
                &cx.commit(),
                vfs,
                &path,
                keys.clone(),
            ))
            .unwrap();
        assert!(
            db.delta_index().unwrap().get(CommitSeq(1)).is_none(),
            "the reopened database must not retain the genesis frame"
        );
        db
    };

    let genuine = reopened(false);
    let row = genuine
        .vertex(coverage_vid(h.book.book_id))
        .unwrap()
        .unwrap();
    assert!(coverage_of(&genuine, &h.book, &row).is_ok());

    let planted = reopened(true);
    let row = planted
        .vertex(coverage_vid(h.book.book_id))
        .unwrap()
        .unwrap();
    let error = coverage_of(&planted, &h.book, &row).unwrap_err();
    assert!(matches!(error, KernelError::Corrupt(_)), "{error}");
}
