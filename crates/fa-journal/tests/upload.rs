//! Real-storage regressions for session-bound document intake (fa-vwf).
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::evidence::{document_vid, read_document};
use fa_journal::upload::{
    PreparedUpload, UploadPreparation, UploadRequest, prepare_upload, upload_document,
};
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
        let mut db = runtime
            .block_on(Database::open_memory(
                &cx.commit(),
                DatabaseKeys::new([31; 32], DatabaseSecurityNamespaceId([32; 32]), [33; 32]),
            ))
            .unwrap();
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

    fn upload(
        &mut self,
        cap: &Capability,
        req: UploadRequest,
    ) -> Result<fa_journal::DocumentAdded, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(upload_document(&mut self.db, &cx, &self.book, cap, req))
            .unwrap()
    }

    fn prepare(&mut self, cap: &Capability, req: UploadRequest) -> Box<PreparedUpload> {
        let cx = self.cx();
        match prepare_upload(&mut self.db, &cx, &self.book, cap, req)
            .unwrap()
            .unwrap()
        {
            UploadPreparation::Ready(prepared) => prepared,
            other => panic!("expected new upload: {other:?}"),
        }
    }

    fn commit(
        &mut self,
        prepared: Box<PreparedUpload>,
    ) -> Result<fa_journal::DocumentAdded, Refusal> {
        let cx = self.cx();
        self.runtime
            .block_on(prepared.commit(&mut self.db, &cx))
            .unwrap()
    }
}

fn cap(profile: Profile, holder: u128) -> Capability {
    Capability::new(VId(holder), profile, &[Op::Post], VId(1)).unwrap()
}

fn grade(name: &str) -> u8 {
    EvidencePolicy::embedded()
        .unwrap()
        .grade_by_name(name)
        .unwrap()
        .tag
}

fn request(bytes: &[u8]) -> UploadRequest {
    UploadRequest {
        kind: EvidencePolicy::embedded()
            .unwrap()
            .kind_by_name("Invoice")
            .unwrap()
            .tag,
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
        assert_eq!(
            chain[0].1, added.recorded_at,
            "receipt and bytes have one publication"
        );
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
    assert_eq!(
        (retry.oid, retry.recorded_at),
        (added.oid, added.recorded_at)
    );
}

#[test]
fn human_reupload_cannot_launder_an_existing_agent_receipt() {
    let mut h = Harness::new();
    let first = h
        .upload(&cap(Profile::Agent, 30), request(b"shared bytes"))
        .unwrap();
    let before = h.db.frontier().unwrap();
    let retry = h
        .upload(&cap(Profile::Human, 31), request(b"shared bytes"))
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.grade, grade("AgentUpload"));
    assert_eq!(
        (retry.oid, retry.recorded_at),
        (first.oid, first.recorded_at)
    );
    assert_eq!(h.db.frontier().unwrap(), before);
    let stored = read_document(&h.db, &first.oid).unwrap().unwrap().unwrap();
    assert_eq!(stored.retrieved_by, VId(30));
    assert_eq!(
        fa_journal::custody_chain(&h.db, &first.oid).unwrap().len(),
        1
    );
}

#[test]
fn missing_authority_excluded_books_and_expiry_refuse_without_writes() {
    let mut h = Harness::new();
    let head = h.db.frontier().unwrap();
    let reader = Capability::new(VId(40), Profile::Human, &[Op::Read], VId(1)).unwrap();
    // Missing authority takes precedence even over malformed input.
    assert_eq!(
        h.upload(&reader, request(b"")).unwrap_err().code,
        "FA-REF-011"
    );
    let excluded = cap(Profile::Human, 40)
        .for_books(&[Id128([99; 16])])
        .unwrap();
    assert_eq!(
        h.upload(&excluded, request(b"off book")).unwrap_err().exit,
        7
    );
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
    assert_eq!(
        fa_journal::custody_chain(&h.db, &added.oid).unwrap().len(),
        1
    );
}

#[test]
fn expiry_is_checked_again_at_publication() {
    let mut h = Harness::new();
    let expires = CommitSeq(h.db.frontier().unwrap().0 + 1);
    let capability = cap(Profile::Human, 70).expiring_at(expires);
    let prepared = h.prepare(&capability, request(b"too late"));
    let oid = prepared.document_oid();
    h.upload(&cap(Profile::Human, 71), request(b"advance frontier"))
        .unwrap();
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
        fa_journal::rows::book_root(),
        property::SECURITY_POLICY_EPOCH,
        Some(CanonicalScalar::Int(1)),
    );
    let cx = h.cx();
    h.runtime.block_on(h.db.write(&cx.commit(), batch)).unwrap();
    let head = h.db.frontier().unwrap();
    assert_eq!(h.commit(prepared).unwrap_err().exit, 6);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert!(h.db.vertex(document_vid(&oid)).unwrap().is_none());
}

fn import_cap(profile: Profile, holder: u128) -> Capability {
    let key = fa_policy::sod::control_key("ImportControl", None, "Import");
    let op = fa_journal::policy::steward()
        .unwrap()
        .preparer_op(&key)
        .unwrap();
    Capability::new(VId(holder), profile, &[op], VId(1)).unwrap()
}

fn import_document(
    h: &Harness,
    capability: &Capability,
    bytes: &[u8],
    name: &str,
) -> fa_journal::Document {
    let req = request(bytes);
    fa_journal::Document {
        book_id: h.book.book_id,
        kind: req.kind,
        mime: req.mime,
        grade: grade(name),
        retrieved_by: capability.holder(),
        bytes: req.bytes,
    }
}

fn import_request(
    h: &Harness,
    capability: &Capability,
    key: &[u8],
    documents: Vec<fa_journal::Document>,
) -> fa_journal::ImportRequest {
    fa_journal::ImportRequest {
        principal: capability.holder(),
        source: fa_model::IntakeSource::Upload {
            principal: capability.holder(),
        },
        idempotency_key: key.to_vec(),
        effective_date: fa_time::DateDay::EPOCH,
        // A constant plaintext for these deterministic test-only sealing inputs.
        description: fa_model::Erasable::seal(
            &"authorized import".to_string(),
            None,
            &h.book.seal_key,
            [51; 32],
            [52; 24],
        ),
        documents,
    }
}

fn run_import(
    h: &mut Harness,
    capability: &Capability,
    request: fa_journal::ImportRequest,
) -> Result<fa_journal::ImportRecorded, Refusal> {
    let cx = h.cx();
    h.runtime
        .block_on(fa_journal::import_run(
            &mut h.db, &cx, &h.book, capability, request,
        ))
        .unwrap()
}

#[test]
fn a_forged_document_uploader_refuses_the_whole_import_before_any_staging() {
    let mut h = Harness::new();
    let capability = import_cap(Profile::Human, 90);
    let docs = vec![
        import_document(&h, &capability, b"first batch invoice", "HumanUpload"),
        import_document(&h, &capability, b"second batch invoice", "HumanUpload"),
    ];
    let valid = import_request(&h, &capability, b"bound-batch", docs);
    let mut forged = valid.clone();
    forged.documents[1].retrieved_by = VId(999);
    let before = h.db.frontier().unwrap();
    let denied = run_import(&mut h, &capability, forged).unwrap_err();
    assert_eq!(denied.exit, 7, "{denied}");
    assert!(
        denied.message.contains("documents[1].retrieved_by"),
        "{denied}"
    );
    assert_eq!(h.db.frontier().unwrap(), before);
    for doc in &valid.documents {
        assert!(h.db.vertex(document_vid(&doc.oid())).unwrap().is_none());
        let receipt = fa_journal::custody::custody_vid(h.book.book_id, &doc.oid(), 0);
        assert!(h.db.vertex(receipt).unwrap().is_none());
    }
    let run_id = fa_model::entry_vid(
        h.book.book_id,
        &capability.holder().0.to_le_bytes(),
        &valid.idempotency_key,
    );
    assert!(h.db.vertex(run_id).unwrap().is_none());
    let mut oids: Vec<_> = valid.documents.iter().map(|doc| doc.oid()).collect();
    oids.sort();
    let imported = run_import(&mut h, &capability, valid).unwrap();
    assert_eq!(imported.recorded, oids);
    assert_eq!(imported.receipt.recorded_at.0, before.0 + 1);
    fa_journal::verify_receipt_in(&h.db, h.book.book_id, &imported.receipt, &oids)
        .unwrap()
        .unwrap();
    for oid in oids {
        let chain = fa_journal::custody_chain(&h.db, &oid).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].1, imported.receipt.recorded_at);
    }
}

#[test]
fn an_import_source_cannot_claim_another_uploading_principal() {
    let mut h = Harness::new();
    let capability = import_cap(Profile::Human, 100);
    let doc = import_document(&h, &capability, b"source binding", "HumanUpload");
    let mut req = import_request(&h, &capability, b"source-bound", vec![doc]);
    req.source = fa_model::IntakeSource::Upload {
        principal: VId(101),
    };
    let before = h.db.frontier().unwrap();
    let denied = run_import(&mut h, &capability, req).unwrap_err();
    assert_eq!(denied.exit, 7, "{denied}");
    assert!(denied.message.contains("source uploader"), "{denied}");
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn registered_connector_names_do_not_let_machine_imports_claim_human_provenance() {
    let mut h = Harness::new();
    let machine = import_cap(Profile::System, 110);
    let doc = import_document(&h, &machine, b"automated invoice", "HumanUpload");
    let mut req = import_request(&h, &machine, b"machine-import", vec![doc]);
    let sources = [
        fa_model::IntakeSource::Upload {
            principal: machine.holder(),
        },
        fa_model::IntakeSource::Connector {
            name: "fa-import".into(),
            version: "1".into(),
        },
        fa_model::IntakeSource::Email {
            message_id: "declared-message-id".into(),
        },
    ];
    let before = h.db.frontier().unwrap();
    for source in sources {
        req.source = source;
        let denied = run_import(&mut h, &machine, req.clone()).unwrap_err();
        assert_eq!(denied.code, "FA-REF-084", "{denied}");
        assert!(denied.message.contains("documents[0]"), "{denied}");
        assert_eq!(h.db.frontier().unwrap(), before);
    }
    req.source = fa_model::IntakeSource::Upload {
        principal: machine.holder(),
    };
    req.documents[0].grade = grade("AgentUpload");
    let expected = req.documents[0].oid();
    let imported = run_import(&mut h, &machine, req).unwrap();
    assert_eq!(imported.recorded, vec![expected]);
    let stored = read_document(&h.db, &expected).unwrap().unwrap().unwrap();
    assert_eq!(stored.retrieved_by, machine.holder());
    assert_eq!(stored.grade, grade("AgentUpload"));
}

#[test]
fn human_imports_preserve_conservative_grades_and_existing_custody() {
    let mut h = Harness::new();
    let first_cap = import_cap(Profile::Human, 120);
    let doc = import_document(&h, &first_cap, b"conservative batch", "AgentUpload");
    let oid = doc.oid();
    let req = import_request(&h, &first_cap, b"conservative-first", vec![doc]);
    let first = run_import(&mut h, &first_cap, req).unwrap();
    let second_cap = import_cap(Profile::Human, 121);
    let reupload = import_document(&h, &second_cap, b"conservative batch", "HumanUpload");
    let req = import_request(&h, &second_cap, b"conservative-repeat", vec![reupload]);
    let second = run_import(&mut h, &second_cap, req).unwrap();
    assert!(second.recorded.is_empty());
    assert_eq!(second.already_held, vec![oid]);
    let stored = read_document(&h.db, &oid).unwrap().unwrap().unwrap();
    assert_eq!(stored.grade, grade("AgentUpload"));
    assert_eq!(stored.retrieved_by, first_cap.holder());
    let chain = fa_journal::custody_chain(&h.db, &oid).unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].1, first.receipt.recorded_at);
    fa_journal::verify_receipt_in(&h.db, h.book.book_id, &second.receipt, &[oid])
        .unwrap()
        .unwrap();
}

#[test]
fn recorded_import_retries_do_not_bypass_current_provenance_admission() {
    let mut h = Harness::new();
    let capability = import_cap(Profile::Human, 130);
    let doc = import_document(&h, &capability, b"idempotent import", "HumanUpload");
    let req = import_request(&h, &capability, b"repeated-import", vec![doc]);
    let original = run_import(&mut h, &capability, req.clone()).unwrap();
    let before = h.db.frontier().unwrap();
    let retry = run_import(&mut h, &capability, req.clone()).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.receipt, original.receipt);
    let mut wrong_doc = req.clone();
    wrong_doc.documents[0].retrieved_by = VId(131);
    assert_eq!(
        run_import(&mut h, &capability, wrong_doc).unwrap_err().exit,
        7
    );
    let mut wrong_source = req;
    wrong_source.source = fa_model::IntakeSource::Upload {
        principal: VId(131),
    };
    assert_eq!(
        run_import(&mut h, &capability, wrong_source)
            .unwrap_err()
            .exit,
        7
    );
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn import_authority_precedes_document_processing_and_agent_trunk_policy_stays_intact() {
    let mut h = Harness::new();
    let reader = Capability::new(VId(140), Profile::Human, &[], VId(1)).unwrap();
    let malformed = import_request(&h, &reader, b"no-authority", Vec::new());
    let before = h.db.frontier().unwrap();
    assert_eq!(
        run_import(&mut h, &reader, malformed).unwrap_err().code,
        "FA-REF-011"
    );
    // Supplying an evidence object is not permission to append ImportControl.
    let agent = import_cap(Profile::Agent, 141);
    let doc = import_document(&h, &agent, b"agent bulk attempt", "AgentUpload");
    let req = import_request(&h, &agent, b"no-trunk", vec![doc]);
    assert_eq!(
        run_import(&mut h, &agent, req).unwrap_err().code,
        "FA-REF-013"
    );
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn a_real_revocation_invalidates_prepared_uploads_and_blocks_recorded_retries() {
    let mut h = Harness::new();
    let capability = cap(Profile::Agent, 150);
    let prior = h
        .upload(&capability, request(b"uploaded before revocation"))
        .unwrap();
    let prepared = h.prepare(&capability, request(b"prepared before revocation"));
    let oid = prepared.document_oid();
    let revoker = Capability::new(VId(1), Profile::Human, &[Op::IssueCapability], VId(1)).unwrap();
    let req = fa_journal::RevocationRequest {
        capability: revoker,
        revoked: capability.commitment().unwrap(),
        effective_date: fa_time::DateDay::EPOCH,
        idempotency_key: b"revoke-uploader".to_vec(),
        description: fa_model::Erasable::seal(
            &"revoke upload authority".to_string(),
            None,
            &h.book.seal_key,
            [61; 32],
            [62; 24],
        ),
    };
    let cx = h.cx();
    let revoked = h
        .runtime
        .block_on(fa_journal::revoke_capability(&mut h.db, &cx, &h.book, req))
        .unwrap()
        .unwrap();
    let before = h.db.frontier().unwrap();
    assert_eq!(before, revoked.recorded_at);
    assert_eq!(h.commit(prepared).unwrap_err().exit, 6);
    for bytes in [
        b"uploaded before revocation".as_slice(),
        b"prepared before revocation".as_slice(),
    ] {
        let denied = h.upload(&capability, request(bytes)).unwrap_err();
        assert_eq!(denied.exit, 7, "{denied}");
        assert!(denied.message.contains("revok"), "{denied}");
    }
    assert_eq!(h.db.frontier().unwrap(), before);
    assert!(h.db.vertex(document_vid(&oid)).unwrap().is_none());
    let receipt = fa_journal::custody::custody_vid(h.book.book_id, &oid, 0);
    assert!(h.db.vertex(receipt).unwrap().is_none());
    let kept = read_document(&h.db, &prior.oid).unwrap().unwrap().unwrap();
    assert_eq!(kept.bytes, b"uploaded before revocation");
}

fn derived_from(db: &Database<MemVfs>) -> Vec<(VId, VId)> {
    db.edges_at(db.frontier().unwrap())
        .unwrap()
        .into_iter()
        .filter(|edge| edge.entry.relation == relation::DERIVED_FROM)
        .map(|edge| (edge.entry.src, edge.entry.dst))
        .collect()
}

fn extraction(source: fa_model::Oid, text: &str) -> Vec<u8> {
    fa_journal::encode_extraction_derivation(
        &[source],
        &fa_journal::DerivedExtractionMetadata {
            method: fa_journal::ExtractionMethod::PdfTextLayer,
            tool_name: "fa-docket/pdf-text-layer".into(),
            tool_version: "0.0.1".into(),
            model_artifact_hash: None,
            command_line: Vec::new(),
            replayable: true,
            extracted_text: text.into(),
            raw_tool_output: Vec::new(),
        },
    )
    .unwrap()
}

/// fa-lzrn: an uploaded derivation records its `DERIVED_FROM` lineage in
/// the upload's own commit, as `add_document` does. Derived text is governed
/// as its source is (plan §9.6): deriving from a document a redaction
/// contract governs, under a kind that contract does not govern, is refused
/// (FA-REF-083) with nothing written; under the source's kind it records.
#[test]
fn uploaded_derivations_record_lineage_and_keep_their_sources_redaction_contract() {
    let mut h = Harness::new();
    let human = cap(Profile::Human, 21);
    let kind = |name: &str| {
        EvidencePolicy::embedded()
            .unwrap()
            .kind_by_name(name)
            .unwrap()
            .tag
    };
    let typed = |name: &str, bytes: Vec<u8>| UploadRequest {
        kind: kind(name),
        mime: "text/plain".into(),
        bytes,
        asserted_grade: None,
    };
    let invoice = h
        .upload(&human, typed("Invoice", b"INVOICE 1001".to_vec()))
        .unwrap();
    let statement = h
        .upload(&human, typed("BankStatement", b"STATEMENT 12345".to_vec()))
        .unwrap();

    let derived = h
        .upload(
            &human,
            typed("Invoice", extraction(invoice.oid, "INVOICE 1001")),
        )
        .unwrap();
    assert!(
        derived_from(&h.db).contains(&(document_vid(&derived.oid), document_vid(&invoice.oid))),
        "the upload's commit carries its lineage"
    );

    let head = h.db.frontier().unwrap();
    let refused = h
        .upload(&human, typed("Invoice", extraction(statement.oid, "12345")))
        .unwrap_err();
    assert_eq!(refused.code, "FA-REF-083", "{refused:?}");
    assert_eq!(h.db.frontier().unwrap(), head, "a refusal writes nothing");

    let kept = h
        .upload(
            &human,
            typed("BankStatement", extraction(statement.oid, "12345")),
        )
        .unwrap();
    assert!(derived_from(&h.db).contains(&(document_vid(&kept.oid), document_vid(&statement.oid))));
}
