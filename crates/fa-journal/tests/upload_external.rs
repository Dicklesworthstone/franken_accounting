//! External evidence uses the real database, BlobStore and custody verifier.
//! None of these tests relaxes the document limits or authorization policy.
#![forbid(unsafe_code)]
use std::path::{Path, PathBuf};

use asupersync::fs::{OpenOptions, Vfs};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::blob::{BlobStore, DurableDirectory, locator_of};
use fa_journal::evidence::{Document, Storage, document_record, document_vid, fetch_document};
use fa_journal::upload::{
    PreparedUpload, UploadPreparation, UploadRequest, prepare_external_upload, upload_document,
    upload_document_in_store, upload_external_document,
};
use fa_journal::{BookContext, BookSpec, DocumentAdded, Refusal, create_book};
use fa_model::symbols::{property, relation};
use fa_model::{Erasable, Id128, Oid, SealKey, SymbolTable};
use fa_money::UnitRegistry;
use fa_policy::{Capability, Op, Profile};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::{DateDay, FiscalCalendar};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

struct Harness {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
    book: BookContext,
    store: BlobStore<MemVfs>,
    blob_vfs: MemVfs,
    blob_root: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([61; 32], DatabaseSecurityNamespaceId([62; 32]), [63; 32]),
            ))
            .unwrap();
        let units = UnitRegistry::with_defaults();
        let calendar = FiscalCalendar::monthly("external-upload", 1, 1).unwrap();
        let symbols = SymbolTable::compiled();
        let book = BookContext {
            book_id: Id128([65; 16]),
            calendar: calendar.clone(),
            units: units.clone(),
            seal_key: SealKey([64; 32]),
            symbols: symbols.clone(),
        };
        let spec = BookSpec {
            book_id: book.book_id,
            name: "External upload test".into(),
            base_unit: units.lookup("USD").unwrap(),
            calendar,
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        runtime
            .block_on(create_book(&mut db, &cx, &spec, &units, &symbols))
            .unwrap();
        let blob_vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let directory = runtime
            .block_on(DurableDirectory::create(
                &cx.commit(),
                blob_vfs.clone(),
                Path::new("blobs"),
            ))
            .unwrap();
        let blob_root = directory.path().to_path_buf();
        let store = BlobStore::open(1, directory).unwrap();
        Self {
            runtime,
            root,
            db,
            book,
            store,
            blob_vfs,
            blob_root,
        }
    }

    fn cx(&self) -> PurposeContexts {
        PurposeContexts::narrow_runtime_root(&self.root)
    }

    fn upload(&mut self, cap: &Capability, req: UploadRequest) -> Result<DocumentAdded, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(upload_external_document(
                &mut self.db,
                &cx,
                &self.book,
                cap,
                &self.store,
                req,
            ))
            .unwrap()
    }

    fn prepare(&mut self, cap: &Capability, req: UploadRequest) -> Box<PreparedUpload> {
        let cx = self.cx();
        match self
            .runtime
            .block_on(prepare_external_upload(
                &mut self.db,
                &cx,
                &self.book,
                cap,
                &self.store,
                req,
            ))
            .unwrap()
            .unwrap()
        {
            UploadPreparation::Ready(prepared) => prepared,
            other => panic!("expected a new document: {other:?}"),
        }
    }

    fn commit(&mut self, prepared: Box<PreparedUpload>) -> Result<DocumentAdded, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(prepared.commit(&mut self.db, &cx))
            .unwrap()
    }

    fn read(&self, oid: &Oid) -> Document {
        self.runtime
            .block_on(fetch_document(&self.db, &self.cx(), &self.store, oid))
            .unwrap()
            .unwrap()
            .unwrap()
    }

    fn no_graph_record(&self, oid: &Oid) {
        assert!(self.db.vertex(document_vid(oid)).unwrap().is_none());
        let receipt = fa_journal::custody::custody_vid(self.book.book_id, oid, 0);
        assert!(self.db.vertex(receipt).unwrap().is_none());
    }
}

fn capability(profile: Profile, holder: u128) -> Capability {
    Capability::new(VId(holder), profile, &[Op::Post], VId(1)).unwrap()
}

fn request(bytes: Vec<u8>) -> UploadRequest {
    UploadRequest {
        kind: EvidencePolicy::embedded()
            .unwrap()
            .kind_by_name("Invoice")
            .unwrap()
            .tag,
        mime: "application/octet-stream".into(),
        bytes,
        asserted_grade: None,
    }
}

fn identity(h: &Harness, req: &UploadRequest) -> (Oid, String) {
    let commit = fa_journal::evidence::doc_commit(req.kind, &req.bytes);
    (
        fa_journal::evidence::document_oid(h.book.book_id, &commit),
        locator_of(&commit),
    )
}

#[test]
fn large_machine_document_routes_to_external_bytes_with_one_atomic_receipt() {
    let mut h = Harness::new();
    let inline = EvidencePolicy::embedded().unwrap().max_document_bytes;
    let size = usize::try_from(inline.checked_add(1).unwrap()).unwrap();
    assert!(u64::try_from(size).unwrap() <= h.store.max_document_bytes());
    let req = request(vec![0x71; size]);
    let expected = req.bytes.clone();
    let head = h.db.frontier().unwrap();
    let cap = capability(Profile::Agent, 11);
    let cx = h.cx();
    let added = h
        .runtime
        .block_on(upload_document_in_store(
            &mut h.db, &cx, &h.book, &cap, &h.store, req,
        ))
        .unwrap()
        .unwrap();
    let record = document_record(&h.db, &added.oid).unwrap().unwrap();
    assert!(matches!(record.storage, Storage::External { store: 1, .. }));
    assert_eq!(added.recorded_at.0, head.0 + 1);
    assert_eq!(added.size, u64::try_from(size).unwrap());
    let doc = h.read(&added.oid);
    assert_eq!(doc.bytes, expected);
    assert_eq!(doc.retrieved_by, cap.holder());
    assert_eq!(
        doc.grade,
        EvidencePolicy::embedded()
            .unwrap()
            .grade_by_name("AgentUpload")
            .unwrap()
            .tag
    );
    let custody = fa_journal::custody_chain(&h.db, &added.oid).unwrap();
    assert_eq!(custody.len(), 1);
    assert_eq!(custody[0].1, added.recorded_at);
}

#[test]
fn small_uploads_still_route_inline_and_external_retry_preserves_first_intake() {
    let mut h = Harness::new();
    let req = request(b"small agent evidence".to_vec());
    let (_, locator) = identity(&h, &req);
    let cx = h.cx();
    let first = h
        .runtime
        .block_on(upload_document_in_store(
            &mut h.db,
            &cx,
            &h.book,
            &capability(Profile::Agent, 12),
            &h.store,
            req.clone(),
        ))
        .unwrap()
        .unwrap();
    let before = h.db.frontier().unwrap();
    let retry = h.upload(&capability(Profile::Human, 13), req).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(
        (retry.oid, retry.grade, retry.recorded_at),
        (first.oid, first.grade, first.recorded_at)
    );
    assert_eq!(h.db.frontier().unwrap(), before);
    let record = document_record(&h.db, &first.oid).unwrap().unwrap();
    assert!(matches!(record.storage, Storage::Inline(_)));
    assert!(
        h.runtime
            .block_on(h.store.get(&cx.query(), &locator, 100))
            .unwrap()
            .is_none()
    );
    assert_eq!(h.read(&first.oid).retrieved_by, VId(12));
}

#[test]
fn external_then_inline_retry_keeps_external_layout_and_original_provenance() {
    let mut h = Harness::new();
    let req = request(b"same bytes across stores".to_vec());
    let first = h
        .upload(&capability(Profile::Agent, 20), req.clone())
        .unwrap();
    let before = h.db.frontier().unwrap();
    let cx = h.cx();
    let retry = h
        .runtime
        .block_on(upload_document(
            &mut h.db,
            &cx,
            &h.book,
            &capability(Profile::Human, 21),
            req,
        ))
        .unwrap()
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(
        (retry.oid, retry.grade, retry.recorded_at),
        (first.oid, first.grade, first.recorded_at)
    );
    assert_eq!(h.db.frontier().unwrap(), before);
    assert!(matches!(
        document_record(&h.db, &first.oid).unwrap().unwrap().storage,
        Storage::External { .. }
    ));
    assert_eq!(h.read(&first.oid).retrieved_by, VId(20));
}

#[test]
fn denied_uploads_do_not_touch_blobs_or_reveal_existing_metadata() {
    let mut h = Harness::new();
    let req = request(b"no blob on refusal".to_vec());
    let (oid, locator) = identity(&h, &req);
    let head = h.db.frontier().unwrap();
    let reader = Capability::new(VId(30), Profile::Human, &[Op::Read], VId(1)).unwrap();
    assert_eq!(
        h.upload(&reader, req.clone()).unwrap_err().code,
        "FA-REF-011"
    );
    let excluded = capability(Profile::Human, 30)
        .for_books(&[Id128([99; 16])])
        .unwrap();
    assert_eq!(h.upload(&excluded, req.clone()).unwrap_err().exit, 7);
    let expired = capability(Profile::Agent, 31).expiring_at(head);
    assert_eq!(h.upload(&expired, req.clone()).unwrap_err().exit, 7);
    let mut forged = req.clone();
    forged.asserted_grade = Some(
        EvidencePolicy::embedded()
            .unwrap()
            .grade_by_name("HumanUpload")
            .unwrap()
            .tag,
    );
    assert_eq!(
        h.upload(&capability(Profile::Agent, 31), forged)
            .unwrap_err()
            .code,
        "FA-REF-084"
    );
    h.no_graph_record(&oid);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(
        h.runtime
            .block_on(h.store.get(&h.cx().query(), &locator, 100))
            .unwrap()
            .is_none()
    );
    h.upload(&capability(Profile::Human, 32), req.clone())
        .unwrap();
    assert_eq!(h.upload(&reader, req).unwrap_err().code, "FA-REF-011");
}

#[test]
fn failed_blob_publication_never_publishes_document_or_receipt() {
    let mut h = Harness::new();
    let req = request(b"blocked shard".to_vec());
    let (oid, locator) = identity(&h, &req);
    let cx = h.cx();
    let blocker = h.blob_root.join(&locator[..2]);
    h.runtime
        .block_on(cx.commit().with_restriction_async(async {
            // A file where the content-addressed shard directory must be.
            let file = h
                .blob_vfs
                .open(&blocker, &OpenOptions::new().write(true).create_new(true))
                .await
                .unwrap();
            drop(file);
        }));
    let head = h.db.frontier().unwrap();
    assert_eq!(
        h.upload(&capability(Profile::Agent, 40), req)
            .unwrap_err()
            .code,
        "FA-REF-116"
    );
    h.no_graph_record(&oid);
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn aborted_and_dropped_external_preparations_leave_only_reusable_orphan_bytes() {
    let mut h = Harness::new();
    let cap = capability(Profile::Agent, 50);
    for abort in [true, false] {
        let req = request(if abort {
            b"abort external".to_vec()
        } else {
            b"drop external".to_vec()
        });
        let (oid, locator) = identity(&h, &req);
        let head = h.db.frontier().unwrap();
        let prepared = h.prepare(&cap, req.clone());
        assert_eq!(prepared.basis(), head);
        assert_eq!(prepared.document_oid(), oid);
        assert_eq!(
            h.runtime
                .block_on(h.store.get(&h.cx().query(), &locator, 100))
                .unwrap(),
            Some(req.bytes.clone())
        );
        if abort {
            prepared.abort();
        } else {
            drop(prepared);
        }
        h.no_graph_record(&oid);
        assert_eq!(h.db.frontier().unwrap(), head);
        let added = h.upload(&cap, req.clone()).unwrap();
        assert!(!added.already_recorded);
        assert_eq!(h.read(&oid).bytes, req.bytes);
        assert_eq!(fa_journal::custody_chain(&h.db, &oid).unwrap().len(), 1);
    }
}

#[test]
fn external_preparations_keep_original_expiry_and_policy_witnesses() {
    let mut h = Harness::new();
    let expires = CommitSeq(h.db.frontier().unwrap().0 + 1);
    let expired = h.prepare(
        &capability(Profile::Agent, 60).expiring_at(expires),
        request(b"expires".to_vec()),
    );
    let expired_oid = expired.document_oid();
    let policy = h.prepare(
        &capability(Profile::Agent, 61),
        request(b"policy changes".to_vec()),
    );
    let policy_oid = policy.document_oid();
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.set_vertex_property(
        fa_journal::rows::book_root(),
        property::SECURITY_POLICY_EPOCH,
        Some(CanonicalScalar::Int(1)),
    );
    let cx = h.cx();
    h.runtime.block_on(h.db.write(&cx.commit(), batch)).unwrap();
    let head = h.db.frontier().unwrap();
    assert_eq!(h.commit(expired).unwrap_err().exit, 7);
    assert_eq!(h.commit(policy).unwrap_err().exit, 6);
    h.no_graph_record(&expired_oid);
    h.no_graph_record(&policy_oid);
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn journaled_revocation_blocks_prepared_and_fresh_external_uploads() {
    let mut h = Harness::new();
    let cap = capability(Profile::Agent, 70);
    let req = request(b"revoked after blob durability".to_vec());
    let prepared = h.prepare(&cap, req.clone());
    let oid = prepared.document_oid();
    let cx = h.cx();
    let revoke = fa_journal::RevocationRequest {
        capability: Capability::embedded(VId(71), &["issue_capability"]).unwrap(),
        revoked: cap.commitment().unwrap(),
        effective_date: DateDay::from_ymd(2026, 3, 1).unwrap(),
        idempotency_key: b"external-revoke".to_vec(),
        description: Erasable::seal(
            &"revoke upload authority".to_string(),
            None,
            &h.book.seal_key,
            [11; 32],
            [12; 24],
        ),
    };
    h.runtime
        .block_on(fa_journal::revoke_capability(
            &mut h.db, &cx, &h.book, revoke,
        ))
        .unwrap()
        .unwrap();
    let head = h.db.frontier().unwrap();
    assert_eq!(h.commit(prepared).unwrap_err().exit, 6);
    assert_eq!(h.upload(&cap, req).unwrap_err().exit, 7);
    h.no_graph_record(&oid);
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn competing_external_preparations_publish_exactly_one_receipt() {
    let mut h = Harness::new();
    let cap = capability(Profile::Agent, 80);
    let req = request(b"same external identity".to_vec());
    let first = h.prepare(&cap, req.clone());
    let second = h.prepare(&cap, req.clone());
    let added = h.commit(first).unwrap();
    let head = h.db.frontier().unwrap();
    assert_eq!(h.commit(second).unwrap_err().exit, 6);
    let retry = h.upload(&capability(Profile::Human, 81), req).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(
        (retry.oid, retry.grade, retry.recorded_at),
        (added.oid, added.grade, added.recorded_at)
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(
        fa_journal::custody_chain(&h.db, &added.oid).unwrap().len(),
        1
    );
}
