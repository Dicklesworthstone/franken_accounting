//! Real-storage regressions for journaled litigation productions (fa-6l9):
//! Bates ranges assigned once per matter, continuing numbers, multi-matter
//! ranges, exact retries, and a refusal for every planted negative.
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::refusal::code;
use fa_journal::upload::{UploadRequest, upload_document};
use fa_journal::{
    BookContext, BookSpec, Produced, ProducedDocument, ProductionOpened, ProductionProfile,
    ProductionRequest, Refusal, create_book, document_ranges, list_productions, open_production,
    produce, read_production,
};
use fa_model::symbols::{property, relation};
use fa_model::{Erasable, Id128, Oid, SealKey, SymbolTable, production_profile_vid};
use fa_money::UnitRegistry;
use fa_policy::{Capability, Op, Profile};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::{DateDay, FiscalCalendar};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, VId};

const BOOK: Id128 = Id128([51; 16]);

struct Harness {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([52; 32], DatabaseSecurityNamespaceId([53; 32]), [54; 32]),
            ))
            .unwrap();
        let units = UnitRegistry::with_defaults();
        let calendar = FiscalCalendar::monthly("production-calendar", 1, 1).unwrap();
        let symbols = SymbolTable::compiled();
        let book = BookContext {
            book_id: BOOK,
            calendar: calendar.clone(),
            units: units.clone(),
            seal_key: SealKey([55; 32]),
            symbols: symbols.clone(),
        };
        let spec = BookSpec {
            book_id: BOOK,
            name: "Production test".into(),
            base_unit: units.lookup("USD").unwrap(),
            calendar,
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        runtime
            .block_on(create_book(&mut db, &cx, &spec, &units, &symbols))
            .unwrap();
        Self {
            runtime,
            root,
            db,
            book,
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn document(&mut self, text: &str) -> Oid {
        let req = UploadRequest {
            kind: EvidencePolicy::embedded()
                .unwrap()
                .kind_by_name("Invoice")
                .unwrap()
                .tag,
            mime: "text/plain".into(),
            bytes: text.as_bytes().to_vec(),
            asserted_grade: None,
        };
        let cx = self.cx();
        let uploader = Capability::new(VId(9), Profile::Human, &[Op::Post], VId(1)).unwrap();
        self.runtime
            .block_on(upload_document(
                &mut self.db,
                &cx,
                &self.book,
                &uploader,
                req,
            ))
            .unwrap()
            .expect("the document is recorded")
            .oid
    }

    fn open(
        &mut self,
        cap: &Capability,
        profile: ProductionProfile,
        key: &str,
    ) -> Result<ProductionOpened, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(open_production(
                &mut self.db,
                &cx,
                &self.book,
                profile,
                request(cap, key),
            ))
            .unwrap()
    }

    fn produce(
        &mut self,
        cap: &Capability,
        matter: &str,
        documents: Vec<ProducedDocument>,
        key: &str,
    ) -> Result<Produced, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(produce(
                &mut self.db,
                &cx,
                &self.book,
                matter,
                documents,
                request(cap, key),
            ))
            .unwrap()
    }

    fn head(&self) -> fgdb_types::CommitSeq {
        self.db.frontier().unwrap()
    }
}

fn request(cap: &Capability, key: &str) -> ProductionRequest {
    ProductionRequest {
        capability: cap.clone(),
        effective_date: DateDay::from_ymd(2026, 3, 9).unwrap(),
        description: Erasable::seal(
            &"production record".to_string(),
            None,
            &SealKey([55; 32]),
            [1; 32],
            [2; 24],
        ),
        idempotency_key: key.as_bytes().to_vec(),
    }
}

fn counsel() -> Capability {
    Capability::new(VId(21), Profile::Human, &[Op::Produce], VId(1)).unwrap()
}

fn profile(matter: &str, prefix: &str, first: u64) -> ProductionProfile {
    ProductionProfile {
        book_id: BOOK,
        matter: matter.into(),
        bates_prefix: prefix.into(),
        first_bates: first,
        load_file_format: 1,
        protective_order: None,
    }
}

fn doc(oid: Oid, pages: Option<u64>, designation: Option<u8>) -> ProducedDocument {
    ProducedDocument {
        document: oid,
        pages,
        designation,
    }
}

/// `(start, end, assigned)` per requested document.
fn spans(produced: &Produced) -> Vec<(u64, u64, bool)> {
    produced
        .ranges
        .iter()
        .map(|r| (r.range.start, r.range.end, r.assigned))
        .collect()
}

#[test]
fn bates_numbers_continue_per_matter_and_a_produced_document_keeps_its_range() {
    let mut h = Harness::new();
    let (a, b, c) = (h.document("A"), h.document("B"), h.document("C"));
    let order = h.document("protective order");
    let counsel = counsel();
    let opened = h
        .open(
            &counsel,
            ProductionProfile {
                protective_order: Some(order),
                ..profile("SEC v. Acme", "ACME-SEC", 1)
            },
            "open-sec",
        )
        .unwrap();
    assert!(!opened.already_recorded);
    assert_eq!(opened.profile, production_profile_vid(BOOK, "SEC v. Acme"));

    let first = h
        .produce(
            &counsel,
            "SEC v. Acme",
            vec![doc(a, Some(3), Some(1)), doc(b, None, None)],
            "vol-1",
        )
        .unwrap();
    assert_eq!(spans(&first), vec![(1, 3, true), (4, 4, true)]);
    assert_eq!(first.next_bates, 5);
    assert_eq!(first.ranges[0].range.designation, 1);
    let (record, recorded_at) = first.record.expect("a record assigned two ranges");

    // The same documents again burn no number and write nothing.
    let head = h.head();
    let again = h
        .produce(
            &counsel,
            "SEC v. Acme",
            vec![doc(b, None, None), doc(a, None, None)],
            "vol-1b",
        )
        .unwrap();
    assert_eq!(spans(&again), vec![(4, 4, false), (1, 3, false)]);
    assert_eq!(again.record, None);
    assert_eq!(h.head(), head);

    // A new document continues the numbering; the produced one keeps its range.
    let second = h
        .produce(
            &counsel,
            "SEC v. Acme",
            vec![doc(a, Some(3), Some(1)), doc(c, Some(2), None)],
            "vol-2",
        )
        .unwrap();
    assert_eq!(spans(&second), vec![(1, 3, false), (5, 6, true)]);
    assert_eq!(second.next_bates, 7);

    // Another matter numbers the same document from its own start.
    h.open(&counsel, profile("Doe v. Acme", "DOE", 1000), "open-doe")
        .unwrap();
    let doe = h
        .produce(
            &counsel,
            "Doe v. Acme",
            vec![doc(a, Some(1), Some(2))],
            "doe-1",
        )
        .unwrap();
    assert_eq!(spans(&doe), vec![(1000, 1000, true)]);

    let view = read_production(&h.db, &h.book, "SEC v. Acme")
        .unwrap()
        .expect("the matter has a profile");
    assert_eq!(view.next_bates, 7);
    assert_eq!(view.profile.protective_order, Some(order));
    assert_eq!(view.opened_by, VId(21));
    let listed: Vec<(u64, u64)> = view
        .ranges
        .iter()
        .map(|r| (r.range.start, r.range.end))
        .collect();
    assert_eq!(listed, vec![(1, 3), (4, 4), (5, 6)]);
    assert_eq!(view.ranges[0].record, record);
    assert_eq!(view.ranges[0].recorded_at, recorded_at);

    let matters: Vec<String> = list_productions(&h.db, &h.book)
        .unwrap()
        .into_iter()
        .map(|v| v.profile.matter)
        .collect();
    assert_eq!(
        matters,
        vec!["SEC v. Acme".to_string(), "Doe v. Acme".to_string()]
    );

    // The document lists both matters' ranges; its commitment is unchanged.
    let ranges = document_ranges(&h.db, &h.book, &a).unwrap();
    let labels: Vec<String> = ranges
        .iter()
        .map(|(p, r)| format!("{}..={}", p.label(r.range.start), p.label(r.range.end)))
        .collect();
    assert_eq!(
        labels,
        vec![
            "DOE-00001000..=DOE-00001000",
            "ACME-SEC-00000001..=ACME-SEC-00000003"
        ]
    );
    assert_eq!(ranges[0].1.range.doc_commit, ranges[1].1.range.doc_commit);
    assert!(document_ranges(&h.db, &h.book, &order).unwrap().is_empty());
}

#[test]
fn exact_retries_return_the_record_and_a_reused_key_or_changed_range_is_refused() {
    let mut h = Harness::new();
    let (a, b) = (h.document("A"), h.document("B"));
    let counsel = counsel();
    let opened = h.open(&counsel, profile("M-1", "M1", 1), "open").unwrap();
    let retried = h.open(&counsel, profile("M-1", "M1", 1), "open").unwrap();
    assert!(retried.already_recorded);
    assert_eq!(retried.control_entry, opened.control_entry);

    let request = vec![doc(a, Some(2), None)];
    let first = h.produce(&counsel, "M-1", request.clone(), "k").unwrap();
    let head = h.head();
    let retry = h.produce(&counsel, "M-1", request, "k").unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.record, first.record);
    assert_eq!(spans(&retry), vec![(1, 2, true)]);
    assert_eq!(h.head(), head);

    let reused = h
        .produce(&counsel, "M-1", vec![doc(b, None, None)], "k")
        .unwrap_err();
    assert_eq!(
        (reused.code, reused.exit),
        (code::IDEMPOTENCY_CONFLICT, 6),
        "{reused}"
    );

    for (pages, designation, what) in [
        (Some(5), None, "page count"),
        (None, Some(3), "designation"),
    ] {
        let fixed = h
            .produce(&counsel, "M-1", vec![doc(a, pages, designation)], "fix")
            .unwrap_err();
        assert_eq!(
            (fixed.code, fixed.exit),
            (code::BATES_RANGE_FIXED, 3),
            "{fixed}"
        );
        assert!(fixed.message.contains(what), "{fixed}");
        assert!(
            fixed.message.contains("M1-00000001..=M1-00000002"),
            "{fixed}"
        );
    }

    // Another principal cannot restart the matter's numbering.
    let other = Capability::new(VId(22), Profile::Human, &[Op::Produce], VId(1)).unwrap();
    let reopened = h.open(&other, profile("M-1", "M1", 1), "open").unwrap_err();
    assert_eq!(
        (reopened.code, reopened.exit),
        (code::IDEMPOTENCY_CONFLICT, 6),
        "{reopened}"
    );
    assert!(
        reopened
            .message
            .contains("already has a production profile"),
        "{reopened}"
    );
    assert_eq!(h.head(), head);
}

#[test]
fn authority_structure_and_unknown_subjects_refuse_without_writing() {
    let mut h = Harness::new();
    let a = h.document("A");
    let counsel = counsel();
    h.open(&counsel, profile("M-1", "M1", 1), "open").unwrap();
    let head = h.head();
    let missing = Oid([77; 32]);

    let poster = Capability::new(VId(23), Profile::Human, &[Op::Post], VId(1)).unwrap();
    let agent = Capability::new(VId(24), Profile::Agent, &[Op::Produce], VId(1)).unwrap();
    let cases: Vec<(&str, Refusal, &str, u8)> = vec![
        (
            "no produce op",
            h.produce(&poster, "M-1", vec![doc(a, None, None)], "x")
                .unwrap_err(),
            "FA-REF-011",
            7,
        ),
        (
            "agent on trunk",
            h.produce(&agent, "M-1", vec![doc(a, None, None)], "x")
                .unwrap_err(),
            "FA-REF-013",
            7,
        ),
        (
            "agent opening",
            h.open(&agent, profile("M-2", "M2", 1), "x").unwrap_err(),
            "FA-REF-013",
            7,
        ),
        (
            "unknown matter",
            h.produce(&counsel, "M-9", vec![doc(a, None, None)], "x")
                .unwrap_err(),
            code::PRODUCTION_UNKNOWN,
            3,
        ),
        (
            "unknown document",
            h.produce(
                &counsel,
                "M-1",
                vec![doc(a, None, None), doc(missing, None, None)],
                "x",
            )
            .unwrap_err(),
            code::EVIDENCE_UNKNOWN,
            3,
        ),
        (
            "unknown protective order",
            h.open(
                &counsel,
                ProductionProfile {
                    protective_order: Some(missing),
                    ..profile("M-3", "M3", 1)
                },
                "x",
            )
            .unwrap_err(),
            code::EVIDENCE_UNKNOWN,
            3,
        ),
        (
            "duplicate document",
            h.produce(
                &counsel,
                "M-1",
                vec![doc(a, None, None), doc(a, None, None)],
                "x",
            )
            .unwrap_err(),
            code::STRUCTURE,
            2,
        ),
        (
            "no document",
            h.produce(&counsel, "M-1", Vec::new(), "x").unwrap_err(),
            code::STRUCTURE,
            2,
        ),
        (
            "zero pages",
            h.produce(&counsel, "M-1", vec![doc(a, Some(0), None)], "x")
                .unwrap_err(),
            code::STRUCTURE,
            2,
        ),
        (
            "unregistered designation",
            h.produce(&counsel, "M-1", vec![doc(a, None, Some(4))], "x")
                .unwrap_err(),
            code::STRUCTURE,
            2,
        ),
        (
            "prefix with a space",
            h.open(&counsel, profile("M-4", "M 4", 1), "x").unwrap_err(),
            code::STRUCTURE,
            2,
        ),
        (
            "first number zero",
            h.open(&counsel, profile("M-5", "M5", 0), "x").unwrap_err(),
            code::STRUCTURE,
            2,
        ),
        (
            "unregistered load-file format",
            h.open(
                &counsel,
                ProductionProfile {
                    load_file_format: 9,
                    ..profile("M-6", "M6", 1)
                },
                "x",
            )
            .unwrap_err(),
            code::STRUCTURE,
            2,
        ),
    ];
    for (case, refusal, expected, exit) in cases {
        assert_eq!(
            (refusal.code, refusal.exit),
            (expected, exit),
            "{case}: {refusal}"
        );
    }
    assert_eq!(h.head(), head, "no refusal wrote");
    let view = read_production(&h.db, &h.book, "M-1").unwrap().unwrap();
    assert!(view.ranges.is_empty());
    assert_eq!(view.next_bates, 1);
}

#[test]
fn a_matter_numbered_past_the_last_bates_number_is_refused() {
    let mut h = Harness::new();
    let a = h.document("A");
    let counsel = counsel();
    let last = fa_journal::production::MAX_BATES - 1;
    h.open(&counsel, profile("M-1", "M1", last), "open")
        .unwrap();
    let head = h.head();
    let refused = h
        .produce(&counsel, "M-1", vec![doc(a, Some(2), None)], "x")
        .unwrap_err();
    assert_eq!(
        (refused.code, refused.exit),
        (code::STRUCTURE, 2),
        "{refused}"
    );
    assert_eq!(h.head(), head);
    let one = h
        .produce(&counsel, "M-1", vec![doc(a, Some(1), None)], "y")
        .unwrap();
    assert_eq!(spans(&one), vec![(last, last, true)]);
}

#[test]
fn a_moved_next_bates_projection_is_found_by_the_view() {
    let mut h = Harness::new();
    let a = h.document("A");
    let counsel = counsel();
    h.open(&counsel, profile("M-1", "M1", 1), "open").unwrap();
    h.produce(&counsel, "M-1", vec![doc(a, Some(2), None)], "x")
        .unwrap();
    // A planted mutation of the projection alone: the records still say 3.
    let mut batch = WriteBatch::new(relation::IN_CASE);
    batch.set_vertex_property(
        production_profile_vid(BOOK, "M-1"),
        property::NEXT_BATES,
        Some(CanonicalScalar::Int(2)),
    );
    let cx = h.cx();
    h.runtime.block_on(h.db.write(&cx.commit(), batch)).unwrap();
    let err = read_production(&h.db, &h.book, "M-1").unwrap_err();
    assert!(err.to_string().contains("not contiguous"), "{err}");
}
