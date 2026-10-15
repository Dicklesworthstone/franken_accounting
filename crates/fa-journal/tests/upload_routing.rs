//! Physical inline limits must agree across owner, session and batch intake.
//! Exercise the real database and blob store without relaxing registry limits.
#![forbid(unsafe_code)]

use std::path::Path;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::blob::{BlobStore, DurableDirectory, locator_of};
use fa_journal::evidence::{
    Document, MAX_INLINE_DOCUMENT_BYTES, Storage, document_record, document_vid,
    fetch_document, inline_document_bound,
};
use fa_journal::upload::{UploadRequest, upload_document, upload_document_in_store};
use fa_journal::{BookContext, BookSpec, DocumentAdded, Refusal, create_book};
use fa_model::{Erasable, Id128, IntakeSource, Oid, SealKey, SymbolTable};
use fa_money::UnitRegistry;
use fa_policy::{Capability, Op, Profile};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::{DateDay, FiscalCalendar};
use fgdb::{Database, DatabaseKeys, MemVfs};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::VId;

struct Harness {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    store: BlobStore<MemVfs>,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime.block_on(Database::open_memory(
            &cx.commit(),
            DatabaseKeys::new([81; 32], DatabaseSecurityNamespaceId([82; 32]), [83; 32]),
        )).unwrap();
        let units = UnitRegistry::with_defaults();
        let calendar = FiscalCalendar::monthly("inline-routing", 1, 1).unwrap();
        let symbols = SymbolTable::compiled();
        let book = BookContext {
            book_id: Id128([85; 16]),
            calendar: calendar.clone(),
            units: units.clone(),
            seal_key: SealKey([84; 32]),
            symbols: symbols.clone(),
        };
        let spec = BookSpec {
            book_id: book.book_id,
            name: "Inline boundary test".into(),
            base_unit: units.lookup("USD").unwrap(),
            calendar,
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        runtime.block_on(create_book(&mut db, &cx, &spec, &units, &symbols)).unwrap();
        let blob_vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let directory = runtime.block_on(DurableDirectory::create(
            &cx.commit(), blob_vfs, Path::new("blobs"),
        )).unwrap();
        let store = BlobStore::open(1, directory).unwrap();
        Self { runtime, root, db, book, store }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn route(&mut self, cap: &Capability, req: UploadRequest) -> Result<DocumentAdded, Refusal> {
        let cx = self.cx();
        self.runtime.block_on(upload_document_in_store(
            &mut self.db, &cx, &self.book, cap, &self.store, req,
        )).unwrap()
    }

    fn read(&self, oid: &Oid) -> Document {
        self.runtime.block_on(fetch_document(
            &self.db, &self.cx(), &self.store, oid,
        )).unwrap().unwrap().unwrap()
    }

    fn no_document_or_receipt(&self, oid: &Oid) {
        assert!(self.db.vertex(document_vid(oid)).unwrap().is_none());
        let receipt = fa_journal::custody::custody_vid(self.book.book_id, oid, 0);
        assert!(self.db.vertex(receipt).unwrap().is_none());
    }

    fn document(&self, req: &UploadRequest, cap: &Capability) -> Document {
        Document {
            book_id: self.book.book_id,
            kind: req.kind,
            mime: req.mime.clone(),
            grade: fa_journal::upload::upload_grade(
                &EvidencePolicy::embedded().unwrap(), cap.profile(),
            ).unwrap(),
            retrieved_by: cap.holder(),
            bytes: req.bytes.clone(),
        }
    }
}

fn capability(profile: Profile, holder: u128) -> Capability {
    Capability::new(VId(holder), profile, &[Op::Post], VId(1)).unwrap()
}

fn request(size: usize) -> UploadRequest {
    let policy = EvidencePolicy::embedded().unwrap();
    UploadRequest {
        kind: policy.kind_by_name("Invoice").unwrap().tag,
        // The payload must fit even with the longest admitted MIME string.
        mime: "m".repeat(policy.max_mime_bytes),
        bytes: vec![0x71; size],
        asserted_grade: None,
    }
}

fn bound() -> usize {
    usize::try_from(inline_document_bound(&EvidencePolicy::embedded().unwrap())).unwrap()
}

#[test]
fn inline_bound_caps_storage_without_raising_a_stricter_policy_limit() {
    let mut policy = EvidencePolicy::embedded().unwrap();
    assert!(policy.max_document_bytes > MAX_INLINE_DOCUMENT_BYTES);
    assert_eq!(inline_document_bound(&policy), MAX_INLINE_DOCUMENT_BYTES);
    policy.max_document_bytes = 17;
    assert_eq!(inline_document_bound(&policy), 17);
}

#[test]
fn raw_inline_intake_fits_the_boundary_and_refuses_one_extra_byte_without_writes() {
    let mut h = Harness::new();
    let cap = capability(Profile::Human, 91);
    let doc = h.document(&request(bound()), &cap);
    let cx = h.cx();
    let added = h.runtime.block_on(fa_journal::add_document(
        &mut h.db, &cx, &h.book, &doc,
    )).unwrap().unwrap();
    assert!(matches!(document_record(&h.db, &added.oid).unwrap().unwrap().storage, Storage::Inline(_)));
    assert_eq!(h.read(&added.oid), doc);

    let head = h.db.frontier().unwrap();
    let oversized = h.document(&request(bound() + 1), &cap);
    let refusal = h.runtime.block_on(fa_journal::add_document(
        &mut h.db, &cx, &h.book, &oversized,
    )).unwrap().unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-083", 2));
    assert!(refusal.fix.contains("blob store"));
    assert_eq!(h.db.frontier().unwrap(), head);
    h.no_document_or_receipt(&oversized.oid());
}

#[test]
fn inline_session_intake_refuses_before_staging_an_oversized_row() {
    let mut h = Harness::new();
    let cap = capability(Profile::Agent, 92);
    let req = request(bound() + 1);
    let doc = h.document(&req, &cap);
    let head = h.db.frontier().unwrap();
    let cx = h.cx();
    let refusal = h.runtime.block_on(upload_document(
        &mut h.db, &cx, &h.book, &cap, req,
    )).unwrap().unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-083", 2));
    assert!(refusal.fix.contains("blob store"));
    assert_eq!(h.db.frontier().unwrap(), head);
    h.no_document_or_receipt(&doc.oid());
}

#[test]
fn router_crosses_the_physical_boundary_without_changing_identity_or_custody() {
    let mut h = Harness::new();
    let cap = capability(Profile::Agent, 93);
    for size in [bound() - 1, bound(), bound() + 1, 16 * 1024] {
        let req = request(size);
        let expected = h.document(&req, &cap);
        let head = h.db.frontier().unwrap();
        let added = h.route(&cap, req.clone()).unwrap();
        assert_eq!(added.oid, expected.oid());
        assert_eq!(added.doc_commit, expected.doc_commit());
        assert_eq!(added.size, u64::try_from(size).unwrap());
        assert_eq!(added.recorded_at.0, head.0 + 1);
        let record = document_record(&h.db, &added.oid).unwrap().unwrap();
        if size <= bound() {
            assert!(matches!(record.storage, Storage::Inline(_)));
        } else {
            assert!(matches!(record.storage, Storage::External { store: 1, .. }));
        }
        assert_eq!(h.read(&added.oid), expected);
        let custody = fa_journal::custody_chain(&h.db, &added.oid).unwrap();
        assert_eq!(custody.len(), 1);
        assert_eq!(custody[0].1, added.recorded_at);

        let recorded_head = h.db.frontier().unwrap();
        let retry = h.route(&capability(Profile::Human, 94), req).unwrap();
        assert!(retry.already_recorded);
        assert_eq!((retry.oid, retry.grade, retry.recorded_at), (added.oid, added.grade, added.recorded_at));
        assert_eq!(h.db.frontier().unwrap(), recorded_head);
        assert_eq!(h.read(&added.oid), expected);
        assert_eq!(fa_journal::custody_chain(&h.db, &added.oid).unwrap().len(), 1);
    }
}

#[test]
fn router_denies_authority_before_either_storage_path_has_effects() {
    let mut h = Harness::new();
    let reader = Capability::new(VId(95), Profile::Human, &[Op::Read], VId(1)).unwrap();
    for size in [bound(), bound() + 1, 16 * 1024] {
        let req = request(size);
        let doc = h.document(&req, &reader);
        let head = h.db.frontier().unwrap();
        assert_eq!(h.route(&reader, req).unwrap_err().code, "FA-REF-011");
        assert_eq!(h.db.frontier().unwrap(), head);
        h.no_document_or_receipt(&doc.oid());
        let locator = locator_of(&doc.doc_commit());
        assert!(h.runtime.block_on(h.store.get(
            &h.cx().query(), &locator, u64::try_from(size).unwrap(),
        )).unwrap().is_none());
    }
}

#[test]
fn one_oversized_document_refuses_the_whole_inline_import_before_writes() {
    let mut h = Harness::new();
    let cap = capability(Profile::Human, 96);
    let small = h.document(&request(20), &cap);
    let large = h.document(&request(bound() + 1), &cap);
    let documents = vec![small.clone(), large.clone()];
    let req = fa_journal::ImportRequest {
        principal: cap.holder(),
        source: IntakeSource::Upload { principal: cap.holder() },
        idempotency_key: b"inline-batch-limit".to_vec(),
        effective_date: DateDay::from_ymd(2026, 1, 1).unwrap(),
        description: Erasable::seal(
            &"inline boundary import".to_string(), None, &h.book.seal_key, [17; 32], [18; 24],
        ),
        documents,
    };
    let run = fa_model::entry_vid(h.book.book_id, &cap.holder().0.to_le_bytes(), &req.idempotency_key);
    let head = h.db.frontier().unwrap();
    let cx = h.cx();
    let refusal = h.runtime.block_on(fa_journal::import_run(
        &mut h.db, &cx, &h.book, &cap, req,
    )).unwrap().unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-083", 2));
    assert!(refusal.message.contains("documents[1]"));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(h.db.vertex(run).unwrap().is_none());
    h.no_document_or_receipt(&small.oid());
    h.no_document_or_receipt(&large.oid());
}
