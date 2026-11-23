//! Imports share successful-intent ownership with monetary publication,
//! including their prepared, external-store and authentic legacy paths.

use super::*;
use fa_journal::import::{ImportPreparation, PreparedImport, prepare_import, read_run};
use fa_journal::refusal::{Outcome, code};
use fa_model::IntakeSource;
use fa_model::symbols::label;
use fgdb_types::CommitSeq;

fn request(h: &Harness, key: &[u8], bytes: &[u8]) -> ImportRequest {
    ImportRequest {
        principal: PRINCIPAL,
        source: IntakeSource::Upload {
            principal: PRINCIPAL,
        },
        idempotency_key: key.to_vec(),
        effective_date: h.day(),
        description: h.statement("import key ownership", 137),
        documents: vec![h.document(INVOICE, HUMAN_UPLOAD, bytes)],
    }
}

fn execute(
    h: &mut Harness,
    req: &ImportRequest,
    capability: &Capability,
) -> Outcome<ImportRecorded> {
    let cx = h.ctx();
    h.runtime
        .block_on(import_run(&mut h.db, &cx, &h.book, capability, req.clone()))
}

fn import(h: &mut Harness, req: &ImportRequest) -> Result<ImportRecorded, Refusal> {
    execute(
        h,
        req,
        &Capability::embedded(req.principal, &["post"]).unwrap(),
    )
    .unwrap()
}

fn prepare(h: &mut Harness, req: &ImportRequest) -> Box<PreparedImport> {
    let cx = h.ctx();
    match prepare_import(
        &mut h.db,
        &cx,
        &h.book,
        &Capability::embedded(req.principal, &["post"]).unwrap(),
        req.clone(),
    )
    .unwrap()
    .unwrap()
    {
        ImportPreparation::Ready(prepared) => prepared,
        ImportPreparation::AlreadyRecorded(_) => panic!("fresh import was already recorded"),
    }
}

fn claim(h: &Harness, req: &ImportRequest) -> VId {
    fa_model::intent_outcome_vid(
        h.book.book_id,
        &req.principal.0.to_le_bytes(),
        &req.idempotency_key,
    )
}

#[test]
fn target_and_batch_keys_refuse_imports_before_document_or_external_blob_writes() {
    use fa_journal::blob::{BlobStore, DurableDirectory, locator_of};
    let mut h = harness();
    let source = h.proposal(h.rent_legs(100), b"import-source", EntryClass::ORIGINAL);
    let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
    let reversal = h.reversal_of(target, 100, b"import-spent-reversal");
    h.post(h.request(reversal, &["post"])).unwrap();
    let member = h.proposal(
        h.rent_legs(200),
        b"import-batch-member",
        EntryClass::ORIGINAL,
    );
    h.post_batch(h.batch(b"import-spent-batch", vec![member]))
        .unwrap();
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let edges = h.db.edges_at(head).unwrap();
    for key in [
        b"import-spent-reversal".as_slice(),
        b"import-spent-batch".as_slice(),
    ] {
        let req = request(&h, key, b"this invoice must never be imported");
        let refused = import(&mut h, &req).unwrap_err();
        assert_eq!(
            (refused.code, refused.exit),
            (code::IDEMPOTENCY_CONFLICT, exit::CONFLICT)
        );
    }

    let cx = h.ctx();
    let blob_vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
    let directory = h
        .runtime
        .block_on(DurableDirectory::create(
            &cx.commit(),
            blob_vfs,
            std::path::Path::new("import-outcome-blobs"),
        ))
        .unwrap();
    let store = BlobStore::open(1, directory).unwrap();
    let policy = fa_registry::evidence_policy::EvidencePolicy::embedded().unwrap();
    let size = usize::try_from(fa_journal::evidence::inline_document_bound(&policy)).unwrap() + 1;
    let req = request(&h, b"import-spent-batch", &vec![b'x'; size]);
    let document = &req.documents[0];
    let locator = locator_of(&document.doc_commit());
    let refused = h
        .runtime
        .block_on(fa_journal::import::prepare_import_in_store(
            &mut h.db,
            &cx,
            &h.book,
            &Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
            &store,
            req.clone(),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.code, code::IDEMPOTENCY_CONFLICT);
    assert!(
        h.runtime
            .block_on(store.get(&cx.query(), &locator, size as u64))
            .unwrap()
            .is_none()
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert_eq!(h.db.edges_at(head).unwrap(), edges);
}

#[test]
fn imports_atomically_claim_keys_and_preserve_exact_semantic_retries() {
    let mut h = harness();
    let source = h.proposal(
        h.rent_legs(100),
        b"import-owned-source",
        EntryClass::ORIGINAL,
    );
    let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
    let key = b"import-owned-key";
    let req = request(&h, key, b"an imported invoice");
    let before = h.db.frontier().unwrap();
    let first = import(&mut h, &req).unwrap();
    assert!(!first.already_recorded);
    assert_eq!(first.receipt.recorded_at.0, before.0 + 1);
    let entry = h.db.vertex(first.receipt.run).unwrap().unwrap();
    let outcome = h.db.vertex(claim(&h, &req)).unwrap().unwrap();
    assert_eq!(outcome.labels, vec![label::INTENT_OUTCOME]);
    assert_eq!(outcome.created_at, entry.created_at);
    assert_eq!(
        fa_journal::rows::prop(&outcome, property::TARGET_REF),
        Some(&CanonicalScalar::bytes(first.receipt.run.0.to_le_bytes().to_vec()).unwrap())
    );
    assert_eq!(
        h.db.vertex(document_vid(&req.documents[0].oid()))
            .unwrap()
            .unwrap()
            .created_at,
        entry.created_at
    );
    assert_eq!(
        read_run(&h.db, first.receipt.run).unwrap(),
        Some(first.receipt.clone())
    );
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let edges = h.db.edges_at(head).unwrap();
    let mut resealed = req.clone();
    resealed.description = h.statement("import key ownership", 138);
    let retry = import(&mut h, &resealed).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.receipt, first.receipt);
    let mut changed_description = req.clone();
    changed_description.description = h.statement("a different import request", 139);
    let changed_documents = request(&h, key, b"a different invoice");
    for changed in [changed_description, changed_documents] {
        assert_eq!(
            import(&mut h, &changed).unwrap_err().code,
            code::IDEMPOTENCY_CONFLICT
        );
    }
    let reversal = h.reversal_of(target, 100, key);
    assert_eq!(
        h.post(h.request(reversal, &["post"])).unwrap_err().code,
        code::IDEMPOTENCY_CONFLICT
    );
    let member = h.proposal(
        h.rent_legs(200),
        b"import-blocked-member",
        EntryClass::ORIGINAL,
    );
    assert_eq!(
        h.post_batch(h.batch(key, vec![member])).unwrap_err().code,
        code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert_eq!(h.db.edges_at(head).unwrap(), edges);

    let mut other = request(&h, key, b"a second principal's invoice");
    other.principal = VId(218);
    other.source = IntakeSource::Upload {
        principal: other.principal,
    };
    other.documents[0].retrieved_by = other.principal;
    let recorded = import(&mut h, &other).unwrap();
    assert_ne!(recorded.receipt.run, first.receipt.run);
    assert_ne!(claim(&h, &other), outcome.vid);
}

#[test]
fn prepared_import_and_target_publication_conflict_in_both_commit_orders() {
    for import_first in [false, true] {
        let mut h = harness();
        let source = h.proposal(
            h.rent_legs(100),
            b"import-race-source",
            EntryClass::ORIGINAL,
        );
        let target = h.post(h.request(source, &["post"])).unwrap().entry_ref();
        let key = b"import-race-key";
        let req = request(&h, key, b"prepared import invoice");
        let prepared_import = prepare(&mut h, &req);
        let reversal = h.reversal_of(target, 100, key);
        let post_request = h.request(reversal.clone(), &["post"]);
        let cx = h.ctx();
        let PostPreparation::Ready(prepared_post) =
            prepare_post(&mut h.db, &cx, &h.book, post_request)
                .unwrap()
                .unwrap()
        else {
            panic!("fresh reversal must be prepared")
        };
        let basis = h.db.frontier().unwrap();
        assert_eq!(prepared_import.basis(), basis);
        assert_eq!(prepared_post.basis(), basis);
        if import_first {
            let winner = h
                .runtime
                .block_on(prepared_import.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap();
            let vertices = h.db.vertices().unwrap();
            let edges = h.db.edges_at(winner.receipt.recorded_at).unwrap();
            let refused = h
                .runtime
                .block_on(prepared_post.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap_err();
            assert_eq!(refused.exit, exit::CONFLICT);
            assert_eq!(h.db.vertices().unwrap(), vertices);
            assert_eq!(h.db.edges_at(h.db.frontier().unwrap()).unwrap(), edges);
            assert!(h.db.vertex(reversal_vid(target.vid)).unwrap().is_none());
            let retry = import(&mut h, &req).unwrap();
            assert!(retry.already_recorded);
            assert_eq!(retry.receipt, winner.receipt);
        } else {
            let winner = h
                .runtime
                .block_on(prepared_post.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap();
            let vertices = h.db.vertices().unwrap();
            let edges = h.db.edges_at(winner.recorded_at()).unwrap();
            let refused = h
                .runtime
                .block_on(prepared_import.commit(&mut h.db, &cx))
                .unwrap()
                .unwrap_err();
            assert_eq!(refused.exit, exit::CONFLICT);
            assert_eq!(h.db.vertices().unwrap(), vertices);
            assert_eq!(h.db.edges_at(h.db.frontier().unwrap()).unwrap(), edges);
            assert!(
                h.db.vertex(document_vid(&req.documents[0].oid()))
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                import(&mut h, &req).unwrap_err().code,
                code::IDEMPOTENCY_CONFLICT
            );
            let retry = h.post(h.request(reversal, &["post"])).unwrap();
            assert_eq!(retry.entry_ref(), winner.entry_ref());
        }
        assert_eq!(h.db.frontier().unwrap().0, basis.0 + 1);
    }
}

#[test]
fn a_prepared_import_loses_to_a_later_outer_batch_claim() {
    let mut h = harness();
    let key = b"import-batch-race";
    let req = request(&h, key, b"a staged but unpublished invoice");
    let prepared = prepare(&mut h, &req);
    let member = h.proposal(
        h.rent_legs(100),
        b"import-batch-race-member",
        EntryClass::ORIGINAL,
    );
    let batch = h.batch(key, vec![member]);
    let winner = h.post_batch(batch.clone()).unwrap();
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let edges = h.db.edges_at(head).unwrap();
    let cx = h.ctx();
    let refused = h
        .runtime
        .block_on(prepared.commit(&mut h.db, &cx))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.exit, exit::CONFLICT);
    assert_eq!(
        import(&mut h, &req).unwrap_err().code,
        code::IDEMPOTENCY_CONFLICT
    );
    let retry = h.post_batch(batch).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, winner.entries);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert_eq!(h.db.edges_at(head).unwrap(), edges);
}

#[test]
fn import_authority_precedes_shared_key_observation() {
    let mut h = harness();
    let req = request(&h, b"import-denied", b"invoice");
    let mut write = fgdb::WriteBatch::new(relation::CUSTODY_OF);
    write.create_vertex(
        claim(&h, &req),
        vec![label::INTENT_OUTCOME],
        vec![(
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(vec![0]).unwrap(),
        )],
    );
    h.write_raw(write);
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let refused = execute(
        &mut h,
        &req,
        &Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
    )
    .unwrap()
    .unwrap_err();
    assert_eq!(
        (refused.code, refused.exit),
        (code::CAPABILITY, exit::SAFETY)
    );
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
}

#[test]
fn deleted_or_rewritten_import_claims_cannot_supply_receipts_or_legacy_retries() {
    for damage in ["deleted", "retargeted", "rewritten and restored"] {
        let mut h = harness();
        let req = request(&h, b"damaged-import", b"original invoice");
        let first = import(&mut h, &req).unwrap();
        let original_claim = h.db.vertex(claim(&h, &req)).unwrap().unwrap();
        let mut write = fgdb::WriteBatch::new(relation::CUSTODY_OF);
        match damage {
            "deleted" => write.delete_vertex(original_claim.vid),
            "retargeted" => write.set_vertex_property(
                original_claim.vid,
                property::TARGET_REF,
                Some(CanonicalScalar::bytes(VId(219).0.to_le_bytes().to_vec()).unwrap()),
            ),
            _ => write.set_vertex_property(
                original_claim.vid,
                property::FA_PAYLOAD,
                Some(CanonicalScalar::bytes(vec![0]).unwrap()),
            ),
        }
        h.write_raw(write);
        if damage == "rewritten and restored" {
            let mut restore = fgdb::WriteBatch::new(relation::CUSTODY_OF);
            restore.set_vertex_property(
                original_claim.vid,
                property::FA_PAYLOAD,
                fa_journal::rows::prop(&original_claim, property::FA_PAYLOAD).cloned(),
            );
            h.write_raw(restore);
        }
        let head = h.db.frontier().unwrap();
        let vertices = h.db.vertices().unwrap();
        assert!(read_run(&h.db, first.receipt.run).is_err(), "{damage}");
        assert!(
            !matches!(
                execute(
                    &mut h,
                    &req,
                    &Capability::embedded(PRINCIPAL, &["post"]).unwrap()
                ),
                Ok(Ok(_))
            ),
            "{damage}"
        );
        assert!(
            !matches!(
                verify_receipt_in(
                    &h.db,
                    h.book.book_id,
                    &first.receipt,
                    &[req.documents[0].oid()]
                ),
                Ok(Ok(()))
            ),
            "{damage}"
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), vertices);
    }
}

#[test]
fn authentic_claim_free_imports_retry_after_reopen_but_fresh_legacy_keys_require_coverage() {
    let mut producer = harness();
    let req = request(&producer, b"legacy-import", b"original legacy invoice");
    let first = import(&mut producer, &req).unwrap();
    let outcome = claim(&producer, &req);
    // Replay the original pre-claim publication into a separate legacy book;
    // never erase a modern claim to manufacture the compatibility fixture.
    let mut custody = fgdb::WriteBatch::new(relation::CUSTODY_OF);
    let mut imported = fgdb::WriteBatch::new(relation::IMPORTED_BY);
    let mut created = std::collections::BTreeSet::new();
    for row in producer.db.vertices_at(first.receipt.recorded_at).unwrap() {
        if row.created_at == first.receipt.recorded_at && row.vid != outcome {
            created.insert(row.vid);
            custody.create_vertex(row.vid, row.labels, row.props);
        }
    }
    assert_eq!(
        created.len(),
        3,
        "one import entry, document and custody receipt"
    );
    for edge in producer.db.edges_at(first.receipt.recorded_at).unwrap() {
        if created.contains(&edge.entry.src) {
            let batch = if edge.entry.relation == relation::CUSTODY_OF {
                &mut custody
            } else {
                assert_eq!(edge.entry.relation, relation::IMPORTED_BY);
                &mut imported
            };
            batch.add_edge(edge.entry.eid, edge.entry.src, edge.entry.dst, edge.props);
        }
    }
    let mut h = harness_legacy();
    let cx = h.ctx();
    let mut txn = h.db.begin(&cx.txn()).unwrap();
    txn.write_ordered(&mut h.db, vec![custody, imported])
        .unwrap();
    let recorded_at = h
        .runtime
        .block_on(txn.commit(&mut h.db, &cx.commit()))
        .unwrap();
    h.runtime.block_on(h.db.compact(&cx.commit())).unwrap();
    let (vfs, keys) = h.legacy_storage.clone().unwrap();
    let empty = h
        .runtime
        .block_on(Database::open_memory(&cx.commit(), keys.clone()))
        .unwrap();
    drop(std::mem::replace(&mut h.db, empty));
    h.db = h
        .runtime
        .block_on(Database::open_with_vfs(
            &cx.commit(),
            vfs.clone(),
            vfs.database_dir(),
            keys,
        ))
        .unwrap();
    let head = h.db.frontier().unwrap();
    let vertices = h.db.vertices().unwrap();
    let expected = RunReceipt {
        recorded_at,
        ..first.receipt
    };
    assert_eq!(
        read_run(&h.db, expected.run).unwrap(),
        Some(expected.clone())
    );
    let retry = import(&mut h, &req).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.receipt, expected);
    assert!(h.db.vertex(outcome).unwrap().is_none());
    let fresh = request(&h, b"uncovered-new-import", b"new invoice");
    let refused = import(&mut h, &fresh).unwrap_err();
    assert_eq!(refused.code, code::PLAN_INVALIDATED);
    assert!(refused.fix.contains("fa recover outcomes"));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), vertices);
    assert!(matches!(
        h.db.delta_since(CommitSeq(0)),
        Err(fgdb::ReadError::DeltaCursorRetired { .. })
    ));
}
