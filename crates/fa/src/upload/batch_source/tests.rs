use super::*;

use std::path::Path;

use asupersync::io::AsyncWriteExt;
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fa_journal::{BookSpec, DocumentRead, UploadRequest};
use fa_model::Id128;
use fa_money::UnitRegistry;
use fa_policy::{Op, Profile};
use fa_time::FiscalCalendar;
use fgdb::MemVfs;
use fgdb_types::VId;

use crate::{BookKeys, Entropy};

fn runtime() -> (Runtime, Cx) {
    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    (runtime, root)
}

async fn create(cx: &PurposeContexts, seed: u8) -> (AsyncBook<MemVfs>, MemVfs, MemVfs) {
    let destination = cx.commit().with_restriction(MemVfs::new).unwrap();
    let source = cx.commit().with_restriction(MemVfs::new).unwrap();
    let book = AsyncBook::create_with_vfs(
        cx,
        destination.clone(),
        Path::new("book"),
        BookKeys::for_development(seed),
        BookSpec {
            book_id: Id128([seed; 16]),
            name: "Atomic source import".into(),
            base_unit: UnitRegistry::with_defaults().lookup("USD").unwrap(),
            calendar: FiscalCalendar::monthly("source-import", 1, 0).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(u64::from(seed)),
    )
    .await
    .unwrap();
    (book, destination, source)
}

fn human() -> Capability {
    Capability::embedded(VId(401), &["post"]).unwrap()
}

fn request(names: &[&str], total: u64) -> SourceImportRequest {
    SourceImportRequest {
        idempotency_key: b"atomic-source-import".to_vec(),
        effective_date: DateDay::from_ymd(2026, 1, 1).unwrap(),
        description: "uploaded evidence batch".into(),
        documents: names
            .iter()
            .map(|name| SourceDocument {
                path: PathBuf::from(name),
                upload: SourceUploadRequest {
                    kind: 1,
                    mime: "application/octet-stream".into(),
                    asserted_grade: None,
                    max_bytes: total.max(1),
                },
            })
            .collect(),
        max_total_bytes: total,
    }
}

async fn write(cx: &PurposeContexts, source: &MemVfs, path: &str, bytes: &[u8]) {
    cx.commit()
        .with_restriction_async(async {
            let mut file = source
                .open(
                    Path::new(path),
                    &OpenOptions::new().write(true).create(true).truncate(true),
                )
                .await
                .unwrap();
            file.write_all(bytes).await.unwrap();
        })
        .await;
}

#[test]
fn authority_count_budgets_and_all_metadata_are_checked_before_any_open() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let (mut book, _, source) = create(&cx, 231).await;
        let before = book.head(&cx).unwrap();
        let agent = Capability::new(VId(402), Profile::Agent, &[Op::Post], VId(1)).unwrap();
        let denied = book
            .import_uploads_from_vfs(&cx, &agent, &source, request(&["missing"], 64))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(denied.code, "FA-REF-013");
        let mut too_many = request(&["missing"], 64);
        too_many.documents =
            vec![too_many.documents[0].clone(); fa_model::limits::MAX_IMPORT_DOCUMENTS + 1];
        let mut bad_later = request(&["first-missing", "second-missing"], 64);
        bad_later.documents[1].upload.asserted_grade = Some(
            EvidencePolicy::embedded()
                .unwrap()
                .grade_by_name("AgentUpload")
                .unwrap()
                .tag,
        );
        for req in [
            request(&[], 64),
            request(&["same", "same"], 64),
            request(&["missing"], 0),
            request(&["missing"], u64::MAX),
            too_many,
            bad_later,
        ] {
            assert!(
                book.import_uploads_from_vfs(&cx, &human(), &source, req)
                    .await
                    .unwrap()
                    .is_err()
            );
        }
        assert_eq!(book.head(&cx).unwrap(), before);
    });
}

#[test]
fn combined_and_per_document_limits_refuse_whole_run_then_exact_budget_succeeds() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let (mut book, _, source) = create(&cx, 232).await;
        write(&cx, &source, "a", b"abcd").await;
        write(&cx, &source, "b", b"efgh").await;
        let before = book.head(&cx).unwrap();
        assert!(
            book.import_uploads_from_vfs(&cx, &human(), &source, request(&["a", "b"], 7))
                .await
                .unwrap()
                .is_err()
        );
        let mut individual = request(&["a", "b"], 8);
        individual.documents[1].upload.max_bytes = 3;
        assert!(
            book.import_uploads_from_vfs(&cx, &human(), &source, individual)
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(book.head(&cx).unwrap(), before);
        let imported = book
            .import_uploads_from_vfs(&cx, &human(), &source, request(&["a", "b"], 8))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(imported.recorded.len(), 2);
        assert_eq!(imported.receipt.document_count, 2);
        assert_eq!(imported.receipt.byte_count, 8);
        assert_eq!(imported.receipt.recorded_at.0, before.0 + 1);
        assert_eq!(book.head(&cx).unwrap(), imported.receipt.recorded_at);
    });
}

#[test]
fn a_late_missing_or_empty_source_never_publishes_earlier_documents() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let (mut book, _, source) = create(&cx, 233).await;
        write(&cx, &source, "a", b"first document").await;
        write(&cx, &source, "empty", b"").await;
        let before = book.head(&cx).unwrap();
        assert!(matches!(
            book.import_uploads_from_vfs(&cx, &human(), &source, request(&["a", "missing"], 64),)
                .await,
            Err(BookError::Io(_, _))
        ));
        assert!(
            book.import_uploads_from_vfs(&cx, &human(), &source, request(&["a", "empty"], 64))
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(book.head(&cx).unwrap(), before);
        let document = Document {
            book_id: book.context().book_id,
            kind: 1,
            mime: "application/octet-stream".into(),
            grade: 1,
            retrieved_by: human().holder(),
            bytes: b"first document".to_vec(),
        };
        assert!(
            book.document_commitment(&cx, &document.oid())
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn duplicate_content_under_different_paths_is_refused_atomically() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let (mut book, _, source) = create(&cx, 234).await;
        write(&cx, &source, "a", b"same").await;
        write(&cx, &source, "b", b"same").await;
        let before = book.head(&cx).unwrap();
        assert!(
            book.import_uploads_from_vfs(&cx, &human(), &source, request(&["a", "b"], 8))
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(book.head(&cx).unwrap(), before);
    });
}

#[test]
fn reordered_retry_keeps_receipt_and_changed_content_conflicts() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let (mut book, _, source) = create(&cx, 235).await;
        write(&cx, &source, "a", b"abcd").await;
        write(&cx, &source, "b", b"efgh").await;
        let first = book
            .import_uploads_from_vfs(&cx, &human(), &source, request(&["a", "b"], 8))
            .await
            .unwrap()
            .unwrap();
        let before = book.head(&cx).unwrap();
        let retry = book
            .import_uploads_from_vfs(&cx, &human(), &source, request(&["b", "a"], 8))
            .await
            .unwrap()
            .unwrap();
        assert!(retry.already_recorded);
        assert_eq!(retry.receipt, first.receipt);
        assert_eq!(book.head(&cx).unwrap(), before);
        write(&cx, &source, "b", b"efg!").await;
        let conflict = book
            .import_uploads_from_vfs(&cx, &human(), &source, request(&["a", "b"], 8))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(conflict.exit, 6);
        assert_eq!(book.head(&cx).unwrap(), before);
    });
}

#[test]
fn an_import_counts_held_evidence_without_regrading_or_replacing_custody() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let (mut book, _, source) = create(&cx, 236).await;
        write(&cx, &source, "a", b"agent document").await;
        write(&cx, &source, "b", b"human document").await;
        let agent = Capability::new(VId(403), Profile::Agent, &[Op::Post], VId(1)).unwrap();
        let held = book
            .upload_document(
                &cx,
                &agent,
                UploadRequest {
                    kind: 1,
                    mime: "application/octet-stream".into(),
                    asserted_grade: None,
                    bytes: b"agent document".to_vec(),
                },
            )
            .await
            .unwrap()
            .unwrap();
        let custody = book.custody_chain(&cx, &held.oid).unwrap();
        let imported = book
            .import_uploads_from_vfs(&cx, &human(), &source, request(&["a", "b"], 64))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(imported.recorded.len(), 1);
        assert_eq!(imported.already_held, vec![held.oid]);
        assert_eq!(imported.receipt.document_count, 2);
        assert_eq!(
            imported.receipt.source,
            IntakeSource::Upload {
                principal: human().holder()
            }
        );
        assert_eq!(book.custody_chain(&cx, &held.oid).unwrap(), custody);
        let reader = Capability::embedded(VId(404), &["read", "privileged"]).unwrap();
        let DocumentRead::Full(document) = book
            .read_document_for(&cx, &reader, &held.oid)
            .await
            .unwrap()
            .unwrap()
        else {
            panic!("expected full evidence")
        };
        assert_eq!(document.grade, held.grade);
        assert_eq!(document.retrieved_by, agent.holder());
    });
}

#[test]
fn mixed_inline_and_external_source_import_reopens_with_every_byte() {
    let (runtime, root) = runtime();
    let cx = PurposeContexts::narrow_runtime_root(&root);
    runtime.block_on(async {
        let (mut book, destination, source) = create(&cx, 237).await;
        let size = EvidencePolicy::embedded().unwrap().max_document_bytes + 1;
        let large = vec![0xa9; usize::try_from(size).unwrap()];
        write(&cx, &source, "small", b"tiny").await;
        write(&cx, &source, "large", &large).await;
        let before = book.head(&cx).unwrap();
        let imported = book
            .import_uploads_from_vfs(
                &cx,
                &human(),
                &source,
                request(&["small", "large"], size + 4),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(imported.receipt.recorded_at.0, before.0 + 1);
        assert_eq!(imported.receipt.byte_count, size + 4);
        drop(book);
        let mut book = AsyncBook::open_with_vfs(
            &cx,
            destination,
            Path::new("book"),
            BookKeys::for_development(237),
            Entropy::deterministic(238),
        )
        .await
        .unwrap();
        let read = Capability::embedded(VId(405), &["read", "privileged"]).unwrap();
        for oid in &imported.recorded {
            let DocumentRead::Full(document) = book
                .read_document_for(&cx, &read, oid)
                .await
                .unwrap()
                .unwrap()
            else {
                panic!("expected full evidence")
            };
            if document.bytes.len() == 4 {
                assert_eq!(document.bytes, b"tiny");
            } else {
                assert_eq!(document.bytes, large);
            }
            assert_eq!(book.custody_chain(&cx, oid).unwrap().len(), 1);
        }
        assert_eq!(
            book.read_run(&cx, imported.receipt.run).unwrap(),
            Some(imported.receipt)
        );
    });
}
