//! Real-storage regressions for session-bound document intake (fa-vwf).
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::evidence::{document_vid, read_document};
use fa_journal::upload::{PreparedUpload, UploadPreparation, UploadRequest, prepare_upload, upload_document};
use fa_journal::{BookContext, BookSpec, Refusal, create_book};
use fa_model::symbols::{property, relation};
use fa_model::{Id128, SealKey, SymbolTable};
use fa_money::UnitRegistry;
use fa_policy::{Capability, Op, Profile};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::FiscalCalendar;
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

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
        let mut db = runtime.block_on(Database::open_memory(
            &cx.commit(),
            DatabaseKeys::new([31; 32], DatabaseSecurityNamespaceId([32; 32]), [33; 32]),
        )).unwrap();
        let units = UnitRegistry::with_defaults();
        let calendar = FiscalCalendar::monthly("upload-calendar", 1, 1).unwrap();
        let symbols = SymbolTable::compiled();
        let book = BookContext {
            book_id: Id128([44; 16]),
            calendar: calendar.clone(),
            units: units.clone(),
            seal_key: SealKey([34; 32]),
            symbols: symbols.clone(),
        };
        let spec = BookSpec {
            book_id: book.book_id,
            name: "Upload test".into(),
            base_unit: units.lookup("USD").unwrap(),
            calendar,
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        runtime.block_on(create_book(&mut db, &cx, &spec, &units, &symbols)).unwrap();
        Self { runtime, root, db, book }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn upload(&mut self, cap: &Capability, req: UploadRequest) -> Result<fa_journal::DocumentAdded, Refusal> {
        let cx = self.cx();
        self.runtime.block_on(upload_document(&mut self.db, &cx, &self.book, cap, req)).unwrap()
    }

    fn prepare(&mut self, cap: &Capability, req: UploadRequest) -> Box<PreparedUpload> {
        let cx = self.cx();
        match prepare_upload(&mut self.db, &cx, &self.book, cap, req).unwrap().unwrap() {
            UploadPreparation::Ready(prepared) => prepared,
            other => panic!("expected new upload: {other:?}"),
        }
    }

    fn commit(&mut self, prepared: Box<PreparedUpload>) -> Result<fa_journal::DocumentAdded, Refusal> {
        let cx = self.cx();
        self.runtime.block_on(prepared.commit(&mut self.db, &cx)).unwrap()
    }
}

fn cap(profile: Profile, holder: u128) -> Capability {
    Capability::new(VId(holder), profile, &[Op::Post], VId(1)).unwrap()
}

fn grade(name: &str) -> u8 {
    EvidencePolicy::embedded().unwrap().grade_by_name(name).unwrap().tag
}

fn request(bytes: &[u8]) -> UploadRequest {
    UploadRequest {
        kind: EvidencePolicy::embedded().unwrap().kind_by_name("Invoice").unwrap().tag,
        mime: "text/plain".into(),
        bytes: bytes.to_vec(),
        asserted_grade: None,
    }
}

#[test]
fn uploader_and_grade_come_from_the_session_and_receipt_is_atomic() {
    let mut h = Harness::new();
    for (profile, holder, name) in [
        (Profile::Human, 11, "HumanUpload"),
        (Profile::Agent, 12, "AgentUpload"),
        (Profile::System, 13, "AgentUpload"),
    ] {
        let capability = cap(profile, holder);
        let bytes = format!("invoice for {holder}");
        let head = h.db.frontier().unwrap();
        let added = h.upload(&capability, request(bytes.as_bytes())).unwrap();
        let stored = read_document(&h.db, &added.oid).unwrap().unwrap().unwrap();
        assert_eq!(stored.retrieved_by, VId(holder));
        assert_eq!(stored.grade, grade(name));
        assert_eq!(stored.bytes, bytes.as_bytes());
        assert_eq!(added.grade, grade(name));
        assert!(!added.already_recorded);
        assert_eq!(added.recorded_at.0, head.0 + 1);
        let chain = fa_journal::custody_chain(&h.db, &added.oid).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].1, added.recorded_at, "receipt and bytes have one publication");
    }
}

#[test]
fn forged_grade_assertions_refuse_before_any_write_including_on_retry() {
    let mut h = Harness::new();
    let agent = cap(Profile::Agent, 20);
    let added = h.upload(&agent, request(b"self sourced")).unwrap();
    for claimed in ["HumanUpload", "Connector", "ThirdPartySigned", "Generated"] {
        let head = h.db.frontier().unwrap();
        let mut req = request(b"self sourced");
        req.asserted_grade = Some(grade(claimed));
        let refusal = h.upload(&agent, req).unwrap_err();
        assert_eq!(refusal.code, "FA-REF-084", "{claimed}: {refusal}");
        assert_eq!(h.db.frontier().unwrap(), head);
    }
    let mut req = request(b"self sourced");
    req.asserted_grade = Some(grade("AgentUpload"));
    let retry = h.upload(&agent, req).unwrap();
    assert!(retry.already_recorded);
    assert_eq!((retry.oid, retry.recorded_at), (added.oid, added.recorded_at));
}

#[test]
fn human_reupload_cannot_launder_an_existing_agent_receipt() {
    let mut h = Harness::new();
    let first = h.upload(&cap(Profile::Agent, 30), request(b"shared bytes")).unwrap();
    let before = h.db.frontier().unwrap();
    let retry = h.upload(&cap(Profile::Human, 31), request(b"shared bytes")).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.grade, grade("AgentUpload"));
    assert_eq!((retry.oid, retry.recorded_at), (first.oid, first.recorded_at));
    assert_eq!(h.db.frontier().unwrap(), before);
    let stored = read_document(&h.db, &first.oid).unwrap().unwrap().unwrap();
    assert_eq!(stored.retrieved_by, VId(30));
    assert_eq!(fa_journal::custody_chain(&h.db, &first.oid).unwrap().len(), 1);
}

#[test]
fn missing_authority_excluded_books_and_expiry_refuse_without_writes() {
    let mut h = Harness::new();
    let head = h.db.frontier().unwrap();
    let reader = Capability::new(VId(40), Profile::Human, &[Op::Read], VId(1)).unwrap();
    // Missing authority takes precedence even over malformed input.
    assert_eq!(h.upload(&reader, request(b"")).unwrap_err().code, "FA-REF-011");
    let excluded = cap(Profile::Human, 40).for_books(&[Id128([99; 16])]).unwrap();
    assert_eq!(h.upload(&excluded, request(b"off book")).unwrap_err().exit, 7);
    let expired = cap(Profile::Human, 40).expiring_at(head);
    let denial = h.upload(&expired, request(b"expired")).unwrap_err();
    assert!(denial.message.contains("expir"), "{denial}");
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn abort_and_drop_publish_neither_document_nor_receipt() {
    let mut h = Harness::new();
    let capability = cap(Profile::Human, 50);
    let head = h.db.frontier().unwrap();
    let first = h.prepare(&capability, request(b"aborted"));
    let first_oid = first.document_oid();
    assert_eq!(first.basis(), head);
    first.abort();
    let second = h.prepare(&capability, request(b"dropped"));
    let second_oid = second.document_oid();
    drop(second);
    for oid in [first_oid, second_oid] {
        assert!(h.db.vertex(document_vid(&oid)).unwrap().is_none());
        let receipt = fa_journal::custody::custody_vid(h.book.book_id, &oid, 0);
        assert!(h.db.vertex(receipt).unwrap().is_none());
    }
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn prepared_duplicate_has_one_winner_and_retry_is_read_only() {
    let mut h = Harness::new();
    let capability = cap(Profile::Agent, 60);
    let first = h.prepare(&capability, request(b"one document"));
    let second = h.prepare(&capability, request(b"one document"));
    let added = h.commit(first).unwrap();
    let head = h.db.frontier().unwrap();
    assert_eq!(h.commit(second).unwrap_err().exit, 6);
    let retry = h.upload(&capability, request(b"one document")).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.oid, added.oid);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(fa_journal::custody_chain(&h.db, &added.oid).unwrap().len(), 1);
}

#[test]
fn expiry_is_checked_again_at_publication() {
    let mut h = Harness::new();
    let expires = CommitSeq(h.db.frontier().unwrap().0 + 1);
    let capability = cap(Profile::Human, 70).expiring_at(expires);
    let prepared = h.prepare(&capability, request(b"too late"));
    let oid = prepared.document_oid();
    h.upload(&cap(Profile::Human, 71), request(b"advance frontier")).unwrap();
    let head = h.db.frontier().unwrap();
    let refusal = h.commit(prepared).unwrap_err();
    assert!(refusal.message.contains("expir"), "{refusal}");
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(h.db.vertex(document_vid(&oid)).unwrap().is_none());
}

#[test]
fn policy_epoch_is_an_original_witness_not_refreshed_at_publication() {
    let mut h = Harness::new();
    let prepared = h.prepare(&cap(Profile::Human, 80), request(b"old policy"));
    let oid = prepared.document_oid();
    // A planted mutation isolates the exact property a lawful policy activation moves.
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.set_vertex_property(
        fa_journal::rows::book_root(), property::SECURITY_POLICY_EPOCH,
        Some(CanonicalScalar::Int(1)),
    );
    let cx = h.cx();
    h.runtime.block_on(h.db.write(&cx.commit(), batch)).unwrap();
    let head = h.db.frontier().unwrap();
    assert_eq!(h.commit(prepared).unwrap_err().exit, 6);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(h.db.vertex(document_vid(&oid)).unwrap().is_none());
}
