//! Mixed-size import integration through the existing public Book API.
//! Directory reopen and scratch isolation use real book storage.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fa::{Book, BookKeys, Entropy};
use fa_journal::{BookSpec, Document, DocumentRead, ImportRecorded};
use fa_model::{Id128, IntakeSource, Oid};
use fa_money::UnitRegistry;
use fa_policy::{Capability, Op, Profile};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::{DateDay, FiscalCalendar};
use fgdb_types::VId;

const BOOK_ID: Id128 = Id128([0x63; 16]);
const IMPORTER: u128 = 210;

fn spec() -> BookSpec {
    let units = UnitRegistry::embedded().unwrap();
    BookSpec {
        book_id: BOOK_ID,
        name: "Mixed-size import facade".into(),
        base_unit: units.lookup("USD").unwrap(),
        calendar: FiscalCalendar::monthly("import-facade", 1, 1).unwrap(),
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    }
}

fn importer() -> Capability {
    Capability::new(VId(IMPORTER), Profile::Human, &[Op::Post], VId(1)).unwrap()
}

fn reader() -> Capability {
    Capability::new(
        VId(211),
        Profile::Human,
        &[Op::Read, Op::Privileged],
        VId(1),
    )
    .unwrap()
}

fn documents() -> Vec<Document> {
    let policy = EvidencePolicy::embedded().unwrap();
    let inline = usize::try_from(fa_journal::evidence::inline_document_bound(&policy)).unwrap();
    [inline, inline + 1, 128 * 1024]
        .into_iter()
        .enumerate()
        .map(|(index, size)| Document {
            book_id: BOOK_ID,
            kind: policy.kind_by_name("Invoice").unwrap().tag,
            mime: "application/octet-stream".into(),
            grade: policy.grade_by_name("HumanUpload").unwrap().tag,
            retrieved_by: VId(IMPORTER),
            bytes: vec![u8::try_from(index + 1).unwrap(); size],
        })
        .collect()
}

fn import(book: &mut Book, docs: Vec<Document>, key: &[u8]) -> ImportRecorded {
    book.import_run(
        &importer(),
        IntakeSource::Upload {
            principal: VId(IMPORTER),
        },
        key,
        DateDay::from_ymd(2026, 3, 1).unwrap(),
        "retained import evidence",
        docs,
    )
    .unwrap()
    .unwrap()
}

fn expected_oids(docs: &[Document]) -> Vec<Oid> {
    let mut oids: Vec<_> = docs.iter().map(Document::oid).collect();
    oids.sort();
    oids
}

fn read_back(book: &mut Book, docs: &[Document], result: &ImportRecorded) {
    assert_eq!(
        book.read_run(result.receipt.run).unwrap(),
        Some(result.receipt.clone())
    );
    fa_journal::import::verify_receipt(&result.receipt, BOOK_ID, &expected_oids(docs)).unwrap();
    assert_eq!(
        result.receipt.byte_count,
        docs.iter().map(|doc| doc.bytes.len() as u64).sum::<u64>()
    );
    for doc in docs {
        let DocumentRead::Full(actual) = book
            .read_document_for(&reader(), &doc.oid())
            .unwrap()
            .unwrap()
        else {
            panic!("the privileged reader must receive full verified evidence");
        };
        assert_eq!(actual, *doc);
        assert_eq!(
            book.document_commitment(&doc.oid()).unwrap(),
            Some(doc.doc_commit())
        );
        let custody = book.custody_chain(&doc.oid()).unwrap();
        assert_eq!(custody.len(), 1);
        assert_eq!(custody[0].1, result.receipt.recorded_at);
    }
}

fn temporary_directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("fa-import-store-{}-{n}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
}

#[test]
fn memory_book_imports_inline_and_large_evidence_in_one_publication() {
    let mut book = Book::create_memory(
        BookKeys::for_development(0x63),
        spec(),
        Entropy::deterministic(630),
    )
    .unwrap();
    let docs = documents();
    let before = book.head().unwrap();
    let result = import(&mut book, docs.clone(), b"memory-batch");
    assert_eq!(result.recorded, expected_oids(&docs));
    assert!(result.already_held.is_empty());
    assert_eq!(result.receipt.document_count, 3);
    assert_eq!(result.receipt.recorded_at.0, before.0 + 1);
    read_back(&mut book, &docs, &result);
    assert_eq!(book.head().unwrap(), result.receipt.recorded_at);
}

#[test]
fn directory_imports_reopen_with_their_original_receipt_and_retry_without_writes() {
    let dir = temporary_directory().join("book");
    let keys = BookKeys::for_development(0x64);
    let docs = documents();
    let mut book =
        Book::create_dir(&dir, keys.clone(), spec(), Entropy::deterministic(640)).unwrap();
    let before = book.head().unwrap();
    let result = import(&mut book, docs.clone(), b"directory-batch");
    assert_eq!(result.receipt.recorded_at.0, before.0 + 1);
    for doc in &docs[1..] {
        let locator = fa_journal::blob::locator_of(&doc.doc_commit());
        let bytes = std::fs::read(dir.join("blobs").join(&locator[..2]).join(&locator)).unwrap();
        assert_eq!(bytes, doc.bytes);
    }
    drop(book);
    let mut book = Book::open_dir(&dir, keys, Entropy::deterministic(641)).unwrap();
    read_back(&mut book, &docs, &result);
    let head = book.head().unwrap();
    let mut reversed = docs.clone();
    reversed.reverse();
    // A new sealing entropy stream and supplied ordering cannot manufacture
    // a second economic operation or a new first-intake custody receipt.
    let retry = import(&mut book, reversed, b"directory-batch");
    assert!(retry.already_recorded);
    assert_eq!(retry.receipt, result.receipt);
    assert_eq!(book.head().unwrap(), head);
    read_back(&mut book, &docs, &result);
}

#[test]
fn scratch_imports_share_blob_storage_but_never_publish_into_the_source_journal() {
    let dir = temporary_directory().join("book");
    let mut source = Book::create_dir(
        &dir,
        BookKeys::for_development(0x65),
        spec(),
        Entropy::deterministic(650),
    )
    .unwrap();
    let before = source.head().unwrap();
    let (mut scratch, map) = source
        .replay_into_scratch(
            None,
            BookKeys::for_development(0x66),
            Entropy::deterministic(660),
        )
        .unwrap()
        .unwrap();
    source.verify_replay(&scratch, &map).unwrap().unwrap();
    let docs = documents();
    let result = import(&mut scratch, docs.clone(), b"scratch-batch");
    read_back(&mut scratch, &docs, &result);
    assert!(source.read_run(result.receipt.run).unwrap().is_none());
    for doc in &docs {
        assert_eq!(source.document_commitment(&doc.oid()).unwrap(), None);
        assert!(source.custody_chain(&doc.oid()).unwrap().is_empty());
    }
    assert_eq!(source.head().unwrap(), before);
    // An explicit source import is a distinct publication. Existing blob
    // bytes do not cause it to mistake absent document rows for an old run.
    let recorded = import(&mut source, docs.clone(), b"source-batch");
    assert!(!recorded.already_recorded);
    assert_eq!(recorded.recorded, expected_oids(&docs));
    read_back(&mut source, &docs, &recorded);
}
