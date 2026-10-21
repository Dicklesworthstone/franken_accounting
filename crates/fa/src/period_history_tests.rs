//! Complete period verification through the public asynchronous facade.
//! Raw mutations below are deliberate corruption, never repair behavior.

use std::path::Path;

use asupersync::fs::UnixVfs;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::period_creation::{PeriodCreation, creation_vid};
use fa_journal::rows::{book_root, bytes, edge_id, scalar_bytes, scalar_text};
use fa_journal::{BookSpec, KernelError, PeriodHistoryVerification};
use fa_model::symbols::{label, property, relation};
use fa_model::{Id128, period_vid};
use fa_money::UnitRegistry;
use fa_policy::{Capability, Op, Profile};
use fa_time::{DateDay, FiscalCalendar, PeriodDef, PeriodKind, PeriodState, PeriodTransition};
use fgdb::{Database, MemVfs, ReadError, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::{AsyncBook, BookError, BookKeys, Entropy, Outcome};

const PRINCIPAL: VId = VId(47);

fn spec() -> BookSpec {
    BookSpec {
        book_id: Id128([147; 16]),
        name: "Complete period history".into(),
        base_unit: UnitRegistry::embedded().unwrap().lookup("USD").unwrap(),
        calendar: FiscalCalendar::monthly("period-history", 1, 1).unwrap(),
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    }
}

fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

fn verifier() -> Capability {
    cap(&["read", "verify"])
}

struct Harness {
    runtime: Runtime,
    root: Cx,
    book: AsyncBook<MemVfs>,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs,
                Path::new("complete-period-history"),
                BookKeys::for_development(147),
                spec(),
                Entropy::deterministic(147),
            ))
            .unwrap();
        Self {
            runtime,
            root,
            book,
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn head(&self) -> CommitSeq {
        self.book.head(&self.cx()).unwrap()
    }

    fn create(&mut self, year: i32) -> (CommitSeq, Vec<PeriodDef>) {
        let cx = self.cx();
        self.runtime
            .block_on(
                self.book
                    .create_periods(&cx, year, PRINCIPAL, &cap(&["schema_change"])),
            )
            .unwrap()
            .unwrap()
    }

    fn verify(
        &mut self,
        capability: &Capability,
        known_at: Option<CommitSeq>,
    ) -> Outcome<PeriodHistoryVerification> {
        let cx = self.cx();
        self.runtime.block_on(
            self.book
                .verify_periods_with_history(&cx, PRINCIPAL, capability, known_at),
        )
    }

    fn mutate(&mut self, batch: WriteBatch) -> CommitSeq {
        let cx = self.cx();
        self.runtime
            .block_on(self.book.db.write(&cx.commit(), batch))
            .unwrap()
    }

    fn retire(&mut self, year: i32, periods: bool) {
        let control = creation_vid(self.book.context(), year);
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        batch.delete_edge(edge_id(relation::IN_BOOK, control, book_root()));
        batch.delete_vertex(control);
        if periods {
            for definition in spec().calendar.periods_for_year(year).unwrap() {
                let vid = period_vid(&spec().calendar.id, &definition.code);
                batch.delete_edge(edge_id(relation::IN_BOOK, vid, book_root()));
                batch.delete_vertex(vid);
            }
        }
        self.mutate(batch);
    }

    /// Build a separate native database with version-1 bytes at the Book's
    /// original birth, then write a projection-only fiscal year. No Entry is
    /// ever created or deleted to manufacture this legacy history.
    fn legacy_year(&mut self, year: i32) -> (CommitSeq, Vec<PeriodDef>) {
        let cx = self.cx();
        let coverage_vid = fa_journal::outcome::coverage_vid(spec().book_id);
        let (coverage, rows): (Vec<_>, Vec<_>) = self
            .book
            .db
            .vertices_at(self.head())
            .unwrap()
            .into_iter()
            .partition(|row| row.vid == coverage_vid);
        // A modern genesis includes its common-idempotency coverage. This
        // separate v1 fixture reconstructs the original Book/Unit genesis;
        // no committed coverage root is retired or rewritten to do so.
        assert_eq!(coverage.len(), 1);
        assert_eq!(coverage[0].labels.as_slice(), [label::INTENT_OUTCOME]);
        let edges = self.book.db.edges_at(self.head()).unwrap();
        assert!(rows.iter().all(|row| {
            row.labels.as_slice() == [label::BOOK] || row.labels.as_slice() == [label::UNIT]
        }));
        let mut genesis = WriteBatch::new(relation::IN_BOOK);
        for mut row in rows {
            if row.vid == book_root() {
                let mut payload = bytes(&row, property::FA_PAYLOAD, "book fixture").unwrap();
                payload[..2].copy_from_slice(&1_u16.to_le_bytes());
                BookSpec::decode(&payload).unwrap();
                let value = row
                    .props
                    .iter_mut()
                    .find(|(key, _)| *key == property::FA_PAYLOAD)
                    .unwrap();
                value.1 = scalar_bytes("legacy book", payload).unwrap();
            }
            genesis.create_vertex(row.vid, row.labels, row.props);
        }
        for edge in edges {
            assert_eq!(edge.entry.relation, relation::IN_BOOK);
            genesis.add_edge(edge.entry.eid, edge.entry.src, edge.entry.dst, edge.props);
        }
        let mut legacy = self
            .runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                BookKeys::for_development(147).inner,
            ))
            .unwrap();
        self.runtime
            .block_on(legacy.write(&cx.commit(), genesis))
            .unwrap();
        self.book.db = legacy;
        self.projection_only_year(year)
    }

    fn projection_only_year(&mut self, year: i32) -> (CommitSeq, Vec<PeriodDef>) {
        let declaration = PeriodCreation::from_spec(&spec(), year).unwrap();
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        for (period, state) in &declaration.periods {
            let kind = match period.kind {
                PeriodKind::Normal => 0,
                PeriodKind::Adjustment => 1,
                PeriodKind::Opening => 2,
                PeriodKind::Closing => 3,
                PeriodKind::Historical => 4,
            };
            let mut props = vec![
                (
                    property::BOOK_ID,
                    scalar_bytes("book_id", spec().book_id.0.to_vec()).unwrap(),
                ),
                (
                    property::CALENDAR_ID,
                    scalar_text("calendar_id", &spec().calendar.id).unwrap(),
                ),
                (property::CODE, scalar_text("code", &period.code).unwrap()),
                (
                    property::FISCAL_YEAR,
                    CanonicalScalar::Int(i64::from(period.fiscal_year)),
                ),
                (
                    property::ORDINAL,
                    CanonicalScalar::Int(i64::from(period.ordinal)),
                ),
                (property::PERIOD_KIND, CanonicalScalar::Int(kind)),
                (
                    property::PERIOD_START,
                    CanonicalScalar::Int(i64::from(period.start.0)),
                ),
                (
                    property::PERIOD_END,
                    CanonicalScalar::Int(i64::from(period.end.0)),
                ),
                (
                    property::STATE,
                    CanonicalScalar::Int(i64::from(state.tag())),
                ),
            ];
            props.sort_by_key(|(key, _)| key.0);
            let vid = period_vid(&spec().calendar.id, &period.code);
            batch.create_vertex(vid, vec![label::PERIOD], props);
            batch.add_edge(
                edge_id(relation::IN_BOOK, vid, book_root()),
                vid,
                book_root(),
                vec![],
            );
        }
        let sequence = self.mutate(batch);
        (sequence, declaration.definitions())
    }
}

#[test]
fn complete_period_history_counts_one_prefix_and_admits_read_only_agents() {
    let mut h = Harness::new();
    let (birth, periods) = h.create(2026);
    let cx = h.cx();
    h.runtime
        .block_on(h.book.transition_period(
            &cx,
            &periods[0].code,
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            b"history-open",
            &cap(&["close"]),
        ))
        .unwrap()
        .unwrap();
    let head = h.head();
    let before_root = h.book.db.partition_root().unwrap();
    let agent =
        Capability::new(PRINCIPAL, Profile::Agent, &[Op::Read, Op::Verify], VId(99)).unwrap();
    let current = h.verify(&agent, None).unwrap().unwrap();
    assert!(current.is_green(), "{:?}", current.periods.drift);
    assert_eq!(current.history.known_at, head);
    assert_eq!(current.periods.known_at, head);
    assert_eq!(current.history.commits_checked, head.0);
    assert_eq!(current.history.entries_checked, 2);
    assert_eq!(current.periods.periods_checked, 15);
    assert_eq!(current.periods.transitions_checked, 1);
    let original = h.verify(&agent, Some(birth)).unwrap().unwrap();
    assert!(original.is_green());
    assert_eq!(original.history.known_at, birth);
    assert_eq!(original.periods.known_at, birth);
    assert_eq!(original.history.entries_checked, 1);
    assert_eq!(original.periods.transitions_checked, 0);
    assert_eq!(h.head(), head);
    assert_eq!(h.book.db.partition_root().unwrap(), before_root);
}

#[test]
fn retired_year_and_birth_control_fail_complete_history_but_old_prefix_stays_valid() {
    let mut h = Harness::new();
    let (birth, _) = h.create(2026);
    let original = h.verify(&verifier(), Some(birth)).unwrap().unwrap();
    h.retire(2026, true);
    let head = h.head();
    let root = h.book.db.partition_root().unwrap();
    assert!(h.book.verify_periods(&h.cx(), None).unwrap().is_green());
    assert!(matches!(
        h.verify(&verifier(), None),
        Err(BookError::Kernel(KernelError::Corrupt(_)))
    ));
    assert_eq!(
        h.verify(&verifier(), Some(birth)).unwrap().unwrap(),
        original
    );
    assert_eq!(h.head(), head);
    assert_eq!(h.book.db.partition_root().unwrap(), root);
}

#[test]
fn genuine_legacy_baseline_is_valid_but_losing_its_sole_cutover_control_is_not() {
    for retire_periods in [false, true] {
        let mut h = Harness::new();
        let (legacy_at, _) = h.legacy_year(2025);
        let legacy = h.verify(&verifier(), None).unwrap().unwrap();
        assert!(legacy.is_green(), "{:?}", legacy.periods.drift);
        assert_eq!(legacy.history.entries_checked, 0);
        assert_eq!(legacy.periods.legacy_periods, 15);
        let (cutover, _) = h.create(2026);
        let mixed = h.verify(&verifier(), Some(cutover)).unwrap().unwrap();
        assert!(mixed.is_green(), "{:?}", mixed.periods.drift);
        assert_eq!(mixed.history.entries_checked, 1);
        assert_eq!(mixed.periods.legacy_periods, 15);
        h.retire(2026, retire_periods);
        assert!(h.book.verify_periods(&h.cx(), None).unwrap().is_green());
        assert!(matches!(
            h.verify(&verifier(), None),
            Err(BookError::Kernel(KernelError::Corrupt(_)))
        ));
        assert_eq!(
            h.verify(&verifier(), Some(cutover)).unwrap().unwrap(),
            mixed
        );
        assert_eq!(
            h.verify(&verifier(), Some(legacy_at)).unwrap().unwrap(),
            legacy
        );
    }
}

#[test]
fn complete_history_does_not_hide_projection_findings() {
    let mut h = Harness::new();
    let (_, periods) = h.create(2026);
    let mut damage = WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        period_vid(&spec().calendar.id, &periods[0].code),
        property::STATE,
        Some(CanonicalScalar::Int(i64::from(PeriodState::Open.tag()))),
    );
    let damaged_at = h.mutate(damage);
    let result = h.verify(&verifier(), None).unwrap().unwrap();
    assert_eq!(result.history.entries_checked, 1);
    assert_eq!(result.history.known_at, damaged_at);
    assert_eq!(result.periods.known_at, damaged_at);
    assert!(!result.is_green());
    assert!(!result.periods.drift.is_empty());
}

#[test]
fn historical_verification_requires_current_unrevoked_authority() {
    let mut h = Harness::new();
    let (birth, _) = h.create(2026);
    let capability = verifier();
    let cx = h.cx();
    h.runtime
        .block_on(h.book.revoke_capability(
            &cx,
            Capability::embedded(VId(21), &["issue_capability"]).unwrap(),
            capability.commitment().unwrap(),
            DateDay::from_ymd(2026, 1, 1).unwrap(),
            b"revoke-period-verifier",
            "Revoke verification authority",
        ))
        .unwrap()
        .unwrap();
    let head = h.head();
    let refusal = h.verify(&capability, Some(birth)).unwrap().unwrap_err();
    assert_eq!(refusal.code, "FA-REF-023");
    assert_eq!(h.head(), head);
}

#[test]
fn period_history_prefixes_outside_the_book_refuse_without_publication() {
    let mut h = Harness::new();
    h.create(2026);
    let head = h.head();
    for prefix in [CommitSeq(0), CommitSeq(head.0 + 1)] {
        let refusal = h.verify(&verifier(), Some(prefix)).unwrap().unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::STRUCTURE);
        assert_eq!(refusal.exit, fa_journal::exit::USAGE);
        assert_eq!(h.head(), head);
    }
}

#[test]
fn disk_checkpoint_reopen_loads_history_only_after_current_whole_book_admission() {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let directory = std::env::temp_dir().join(format!(
        "fa-period-history-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    ));
    let keys = BookKeys::for_development(148);
    let mut book = runtime
        .block_on(AsyncBook::create_with_vfs(
            &cx,
            UnixVfs,
            &directory,
            keys.clone(),
            spec(),
            Entropy::deterministic(148),
        ))
        .unwrap();
    let (birth, _) = runtime
        .block_on(book.create_periods(&cx, 2026, PRINCIPAL, &cap(&["schema_change"])))
        .unwrap()
        .unwrap();
    runtime.block_on(book.db.compact(&cx.commit())).unwrap();
    drop(book);
    let mut book = runtime
        .block_on(AsyncBook::open_with_vfs(
            &cx,
            UnixVfs,
            &directory,
            keys,
            Entropy::deterministic(149),
        ))
        .unwrap();
    assert!(matches!(
        book.db.delta_since(CommitSeq(0)),
        Err(ReadError::DeltaCursorRetired { retained_after, .. }) if retained_after == birth
    ));
    let root_before = book.db.partition_root().unwrap();
    for denied in [
        cap(&[]),
        cap(&["read"]),
        cap(&["verify"]),
        Capability::embedded(VId(48), &["read", "verify"]).unwrap(),
        verifier().for_books(&[Id128([255; 16])]).unwrap(),
        verifier().for_accounts(&["1000"]).unwrap(),
        verifier().for_periods(&["FY2026-P01"]).unwrap(),
        verifier().expiring_at(birth),
    ] {
        let refusal = runtime
            .block_on(book.verify_periods_with_history(&cx, PRINCIPAL, &denied, Some(birth)))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, fa_journal::exit::SAFETY);
        assert!(
            matches!(
                book.db.delta_since(CommitSeq(0)),
                Err(ReadError::DeltaCursorRetired { retained_after, .. }) if retained_after == birth
            ),
            "denied authority must not load native history"
        );
    }
    let verified = runtime
        .block_on(book.verify_periods_with_history(&cx, PRINCIPAL, &verifier(), Some(birth)))
        .unwrap()
        .unwrap();
    assert!(verified.is_green(), "{:?}", verified.periods.drift);
    assert_eq!(verified.history.known_at, birth);
    assert_eq!(verified.periods.known_at, birth);
    assert_eq!(verified.history.commits_checked, birth.0);
    assert_eq!(verified.history.entries_checked, 1);
    assert!(book.db.delta_since(CommitSeq(0)).is_ok());
    assert_eq!(book.head(&cx).unwrap(), birth);
    assert_eq!(book.db.partition_root().unwrap(), root_before);
}

#[test]
fn rewritten_v2_book_header_cannot_manufacture_legacy_period_eligibility() {
    let mut h = Harness::new();
    let clean = h.head();
    let original = h.verify(&verifier(), Some(clean)).unwrap().unwrap();
    let root = h.book.db.vertex_at(book_root(), clean).unwrap().unwrap();
    let mut payload = bytes(&root, property::FA_PAYLOAD, "book fixture").unwrap();
    assert!(payload.starts_with(&2_u16.to_le_bytes()));
    payload[..2].copy_from_slice(&1_u16.to_le_bytes());
    let mut damage = WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        book_root(),
        property::FA_PAYLOAD,
        Some(scalar_bytes("rewritten book", payload).unwrap()),
    );
    h.mutate(damage);
    h.projection_only_year(2026);
    let retained = h.book.verify_periods(&h.cx(), None).unwrap();
    assert!(retained.is_green(), "{:?}", retained.drift);
    assert_eq!(retained.legacy_periods, 15);
    let damaged_at = h.head();
    let damaged_root = h.book.db.partition_root().unwrap();
    assert!(matches!(
        h.verify(&verifier(), None),
        Err(BookError::Kernel(KernelError::Corrupt(_)))
    ));
    assert_eq!(
        h.verify(&verifier(), Some(clean)).unwrap().unwrap(),
        original
    );
    assert_eq!(h.head(), damaged_at);
    assert_eq!(h.book.db.partition_root().unwrap(), damaged_root);
}
