use super::*;

use std::pin::Pin;
use std::task::{Context, Poll};

use asupersync::fs::OpenOptions;
use asupersync::io::{AsyncWriteExt, ReadBuf};
use fa_journal::{BookSpec, DocumentRead};
use fa_model::Id128;
use fa_money::UnitRegistry;
use fa_policy::{Op, Profile};
use fa_time::{DateDay, FiscalCalendar};
use fgdb::MemVfs;
use fgdb_types::VId;

use crate::upload::SourceDocument;
use crate::{BookError, BookKeys, Entropy};

struct Untouched;

impl AsyncRead for Untouched {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        panic!("refused input must not be polled");
    }
}

fn create(seed: u8) -> Book {
    Book::create_memory(
        BookKeys::for_development(seed),
        BookSpec {
            book_id: Id128([seed; 16]),
            name: "Blocking source intake".into(),
            base_unit: UnitRegistry::with_defaults().lookup("USD").unwrap(),
            calendar: FiscalCalendar::monthly("blocking-intake", 1, 0).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(u64::from(seed)),
    )
    .unwrap()
}

fn human() -> Capability {
    Capability::embedded(VId(451), &["post"]).unwrap()
}

fn agent() -> Capability {
    Capability::new(VId(452), Profile::Agent, &[Op::Post], VId(1)).unwrap()
}

fn upload(limit: u64) -> SourceUploadRequest {
    SourceUploadRequest {
        kind: 1,
        mime: "application/octet-stream".into(),
        asserted_grade: None,
        max_bytes: limit,
    }
}

fn batch(paths: &[&str], limit: u64) -> SourceImportRequest {
    SourceImportRequest {
        idempotency_key: b"blocking-source-import".to_vec(),
        effective_date: DateDay::from_ymd(2026, 1, 1).unwrap(),
        description: "source import".into(),
        documents: paths
            .iter()
            .map(|path| SourceDocument {
                path: (*path).into(),
                upload: upload(limit.max(1)),
            })
            .collect(),
        max_total_bytes: limit,
    }
}

fn source(book: &Book) -> MemVfs {
    book.purposes()
        .commit()
        .with_restriction(MemVfs::new)
        .unwrap()
}

fn write(book: &Book, source: &MemVfs, path: &str, bytes: &[u8]) {
    let purposes = book.purposes();
    book.runtime
        .block_on(purposes.commit().with_restriction_async(async {
            let mut file = source
                .open(
                    Path::new(path),
                    &OpenOptions::new().write(true).create(true).truncate(true),
                )
                .await
                .unwrap();
            file.write_all(bytes).await.unwrap();
        }));
}

#[test]
fn preflight_distinguishes_upload_from_trunk_import_without_advancing_head() {
    let book = create(241);
    let before = book.head().unwrap();
    assert!(
        book.preflight_intake(&agent(), IntakeAction::Upload)
            .unwrap()
            .is_ok()
    );
    let denied = book
        .preflight_intake(&agent(), IntakeAction::ImportRun)
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.code, "FA-REF-013");
    assert!(
        book.preflight_intake(&human(), IntakeAction::ImportRun)
            .unwrap()
            .is_ok()
    );
    assert_eq!(book.head().unwrap(), before);
}

#[test]
fn rejected_authority_and_metadata_never_poll_the_reader() {
    let mut book = create(242);
    let before = book.head().unwrap();
    let read_only = Capability::embedded(VId(453), &["read"]).unwrap();
    assert!(
        book.upload_document_from_reader(&read_only, &mut Untouched, upload(16))
            .unwrap()
            .is_err()
    );
    assert!(
        book.upload_document_from_reader(&human(), &mut Untouched, upload(0))
            .unwrap()
            .is_err()
    );
    let mut invalid = upload(16);
    invalid.kind = 0;
    assert!(
        book.upload_document_from_reader(&human(), &mut Untouched, invalid)
            .unwrap()
            .is_err()
    );
    assert_eq!(book.head().unwrap(), before);
}

#[test]
fn exact_reader_budget_succeeds_overflow_refuses_and_retry_preserves_custody() {
    let mut book = create(243);
    let before = book.head().unwrap();
    let mut bytes = &b"abcd"[..];
    assert!(
        book.upload_document_from_reader(&human(), &mut bytes, upload(3))
            .unwrap()
            .is_err()
    );
    assert_eq!(book.head().unwrap(), before);
    let mut bytes = &b"abcd"[..];
    let added = book
        .upload_document_from_reader(&agent(), &mut bytes, upload(4))
        .unwrap()
        .unwrap();
    let custody = book.custody_chain(&added.oid).unwrap();
    let before_retry = book.head().unwrap();
    let mut bytes = &b"abcd"[..];
    let retry = book
        .upload_document_from_reader(&human(), &mut bytes, upload(4))
        .unwrap()
        .unwrap();
    assert_eq!(retry.oid, added.oid);
    assert_eq!(retry.grade, added.grade);
    assert_eq!(book.head().unwrap(), before_retry);
    assert_eq!(book.custody_chain(&added.oid).unwrap(), custody);
    let reader = Capability::embedded(VId(454), &["read", "privileged"]).unwrap();
    let DocumentRead::Full(document) = book
        .read_document_for(&reader, &added.oid)
        .unwrap()
        .unwrap()
    else {
        panic!("expected full evidence")
    };
    assert_eq!(document.bytes, b"abcd");
    assert_eq!(document.retrieved_by, agent().holder());
}

#[test]
fn supplied_vfs_and_local_paths_are_not_opened_when_authority_is_refused() {
    let mut book = create(244);
    let source = source(&book);
    let read_only = Capability::embedded(VId(455), &["read"]).unwrap();
    let before = book.head().unwrap();
    let missing = Path::new("blocking-intake-missing-source");
    assert!(
        book.upload_document_from_vfs(&read_only, &source, missing, upload(16))
            .unwrap()
            .is_err()
    );
    assert!(
        book.upload_document_from_path(&read_only, missing, upload(16))
            .unwrap()
            .is_err()
    );
    assert!(
        book.import_uploads_from_paths(&agent(), batch(&["missing"], 16))
            .unwrap()
            .is_err()
    );
    assert!(matches!(
        book.upload_document_from_vfs(&human(), &source, missing, upload(16)),
        Err(BookError::Io(_, _))
    ));
    assert_eq!(book.head().unwrap(), before);
}

#[test]
fn mixed_source_batch_is_atomic_and_retry_uses_the_original_run() {
    let mut book = create(245);
    let source = source(&book);
    write(&book, &source, "a", b"abcd");
    write(&book, &source, "b", b"efgh");
    let before = book.head().unwrap();
    assert!(
        book.import_uploads_from_vfs(&human(), &source, batch(&["a", "b"], 7))
            .unwrap()
            .is_err()
    );
    assert!(matches!(
        book.import_uploads_from_vfs(&human(), &source, batch(&["a", "missing"], 16)),
        Err(BookError::Io(_, _))
    ));
    assert_eq!(book.head().unwrap(), before);
    let imported = book
        .import_uploads_from_vfs(&human(), &source, batch(&["a", "b"], 8))
        .unwrap()
        .unwrap();
    assert_eq!(imported.receipt.recorded_at.0, before.0 + 1);
    assert_eq!(imported.recorded.len(), 2);
    assert_eq!(imported.receipt.byte_count, 8);
    let retry = book
        .import_uploads_from_vfs(&human(), &source, batch(&["b", "a"], 8))
        .unwrap()
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.receipt, imported.receipt);
    assert_eq!(book.head().unwrap(), imported.receipt.recorded_at);
    assert_eq!(
        book.read_run(imported.receipt.run).unwrap(),
        Some(imported.receipt)
    );
}

#[test]
fn external_evidence_uses_the_destination_store_not_the_source_vfs() {
    let mut book = create(246);
    let source = source(&book);
    let size = fa_registry::evidence_policy::EvidencePolicy::embedded()
        .unwrap()
        .max_document_bytes
        + 1;
    let bytes = vec![0x91; usize::try_from(size).unwrap()];
    write(&book, &source, "large", &bytes);
    let added = book
        .upload_document_from_vfs(&human(), &source, Path::new("large"), upload(size))
        .unwrap()
        .unwrap();
    // Changing the original source cannot change committed evidence.
    write(&book, &source, "large", b"changed");
    let reader = Capability::embedded(VId(456), &["read", "privileged"]).unwrap();
    let DocumentRead::Full(document) = book
        .read_document_for(&reader, &added.oid)
        .unwrap()
        .unwrap()
    else {
        panic!("expected full evidence")
    };
    assert_eq!(document.bytes, bytes);
    assert_eq!(book.custody_chain(&added.oid).unwrap().len(), 1);
}
