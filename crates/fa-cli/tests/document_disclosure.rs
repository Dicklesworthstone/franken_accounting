//! Public Book/AsyncBook export to the independent verifier. These are library
//! integration tests hosted here because fa-cli already depends on both sides.
//! No new production or test dependency is needed to cross the trust boundary.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::Budget;
use asupersync::runtime::RuntimeBuilder;
use fa::{AsyncBook, Book, BookKeys, Capability, DisclosureAccess, Entropy, Op, Profile};
use fa_journal::{BookSpec, Document};
use fa_model::{Id128, Oid};
use fa_money::UnitRegistry;
use fa_time::FiscalCalendar;
use fa_verify::disclosure::verify;
use fgdb::MemVfs;
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;

const BOOK: Id128 = Id128([73; 16]);
const PRINCIPAL: VId = VId(7);
fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}
fn spec() -> BookSpec {
    BookSpec {
        book_id: BOOK,
        name: "Disclosure integration".into(),
        base_unit: UnitRegistry::embedded().unwrap().lookup("USD").unwrap(),
        calendar: FiscalCalendar::monthly("disclosures", 1, 1).unwrap(),
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    }
}
fn document(kind: u8, size: usize) -> Document {
    Document {
        book_id: BOOK,
        kind,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: (0..size).map(|i| b'A' + (i / 4096 % 26) as u8).collect(),
    }
}
fn temp() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("fa-disclosure-{}-{n}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create disclosure fixture: {e}"),
        }
    }
}
fn memory() -> Book {
    Book::create_memory(
        BookKeys::for_development(73),
        spec(),
        Entropy::deterministic(73),
    )
    .unwrap()
}
fn assert_verified(proof: &fa::DocumentDisclosureArtifact, doc: &Document, indexes: &[u64]) {
    // Trust comes from the independently known original, not artifact metadata.
    let report = verify(&proof.bytes, indexes, &doc.doc_commit()).unwrap();
    assert_eq!(report.scope, "membership_only");
    assert_eq!(report.kind, doc.kind);
    assert_eq!(report.document_length, doc.bytes.len() as u64);
    assert_eq!(
        report.chunks.iter().map(|c| c.index).collect::<Vec<_>>(),
        indexes
    );
    assert_eq!(proof.doc_commit, doc.doc_commit());
    assert_eq!(proof.document, doc.oid());
    assert_eq!(proof.requested_chunks, indexes);
}

#[test]
fn persisted_book_exports_exact_public_chunks_and_reopens_without_a_checkpoint_or_write() {
    let directory = temp();
    let keys = BookKeys::for_development(73);
    let mut book =
        Book::create_dir(&directory, keys.clone(), spec(), Entropy::deterministic(73)).unwrap();
    let doc = document(1, 4096 * 4 + 7);
    book.add_document(&doc).unwrap().unwrap();
    let head = book.head().unwrap();
    let proof = book
        .export_document_disclosure(&cap(&["read", "produce"]), &doc.oid(), &[1, 4])
        .unwrap()
        .unwrap();
    assert_verified(&proof, &doc, &[1, 4]);
    assert_eq!(proof.access, DisclosureAccess::Full);
    assert!(!proof.bytes.windows(128).any(|s| s == [b'A'; 128]));
    assert!(!proof.bytes.windows(128).any(|s| s == [b'C'; 128]));
    let debug = format!("{proof:?}");
    assert!(!debug.contains(&"B".repeat(128)));
    assert!(!debug.contains("[66, 66, 66"));
    assert!(debug.contains("proof_byte_length"));
    assert_eq!(book.head().unwrap(), head);
    drop(book);
    let mut reopened = Book::open_dir(&directory, keys, Entropy::deterministic(74)).unwrap();
    let repeated = reopened
        .export_document_disclosure(&cap(&["read", "produce"]), &doc.oid(), &[1, 4])
        .unwrap()
        .unwrap();
    assert_eq!(repeated, proof);
    assert_eq!(reopened.head().unwrap(), head);
    assert!(verify(&proof.bytes, &[1], &doc.doc_commit()).is_err());
    assert!(verify(&proof.bytes, &[1, 3], &doc.doc_commit()).is_err());
    let wrong_document = document(2, doc.bytes.len());
    assert!(verify(&proof.bytes, &[1, 4], &wrong_document.doc_commit()).is_err());
}

#[test]
fn agent_exports_only_the_governed_view_and_produce_never_grants_privileged_bytes() {
    let mut book = memory();
    let doc = document(5, 4096 * 4 + 7);
    book.add_document(&doc).unwrap().unwrap();
    let agent = Capability::new(VId(31), Profile::Agent, &[Op::Read, Op::Produce], VId(1))
        .unwrap()
        .for_books(&[BOOK])
        .unwrap();
    let head = book.head().unwrap();
    let missing = book
        .export_document_disclosure(&agent, &doc.oid(), &[1])
        .unwrap()
        .unwrap_err();
    assert_eq!(
        missing.code,
        fa_journal::refusal::code::REDACTED_VIEW_ABSENT
    );
    assert_eq!(
        book.head().unwrap(),
        head,
        "export does not derive a missing view"
    );
    book.derive_redacted_view(&cap(&["privileged"]), &doc.oid())
        .unwrap()
        .unwrap();
    let head = book.head().unwrap();
    let allowed = book
        .export_document_disclosure(&agent, &doc.oid(), &[1, 4])
        .unwrap()
        .unwrap();
    assert_verified(&allowed, &doc, &[1, 4]);
    assert_eq!(allowed.access, DisclosureAccess::Redacted { contract: 1 });
    for requested in [&[0][..], &[0, 1][..]] {
        let refusal = book
            .export_document_disclosure(&agent, &doc.oid(), requested)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::CAPABILITY);
        assert_eq!(refusal.exit, fa_journal::exit::SAFETY);
        assert!(refusal.message.contains("withheld"));
    }
    let privileged = book
        .export_document_disclosure(&cap(&["read", "produce", "privileged"]), &doc.oid(), &[0])
        .unwrap()
        .unwrap();
    assert_verified(&privileged, &doc, &[0]);
    assert_eq!(privileged.access, DisclosureAccess::Full);
    let full_subset = book
        .export_document_disclosure(
            &cap(&["read", "produce", "privileged"]),
            &doc.oid(),
            &[1, 4],
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        full_subset.bytes, allowed.bytes,
        "access metadata is not forged into a proof grade"
    );
    assert_eq!(book.head().unwrap(), head);
}

#[test]
fn request_and_authority_refusals_never_disclose_document_existence_or_publish() {
    let mut book = memory();
    let doc = document(1, 1);
    book.add_document(&doc).unwrap().unwrap();
    let head = book.head().unwrap();
    let missing = Oid([255; 32]);
    for denied in [
        cap(&["read"]),
        cap(&["produce"]),
        cap(&["read", "produce"])
            .for_books(&[Id128([74; 16])])
            .unwrap(),
    ] {
        let exists = book
            .export_document_disclosure(&denied, &doc.oid(), &[0])
            .unwrap()
            .unwrap_err();
        let absent = book
            .export_document_disclosure(&denied, &missing, &[])
            .unwrap()
            .unwrap_err();
        assert_eq!(exists, absent, "admission precedes even malformed requests");
        assert_eq!(exists.code, fa_journal::refusal::code::CAPABILITY);
    }
    let expired = cap(&["read", "produce"]).expiring_at(head);
    assert_eq!(
        book.export_document_disclosure(&expired, &doc.oid(), &[0])
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-014"
    );
    for indexes in [vec![], vec![0, 0], vec![1, 0], vec![1], vec![u64::MAX]] {
        let error = book
            .export_document_disclosure(&cap(&["read", "produce"]), &doc.oid(), &indexes)
            .unwrap()
            .unwrap_err();
        assert_eq!(error.exit, fa_journal::exit::USAGE);
    }
    assert_eq!(
        book.export_document_disclosure(&cap(&["read", "produce"]), &missing, &[0])
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::EVIDENCE_UNKNOWN
    );
    assert_eq!(book.head().unwrap(), head);
}

#[test]
fn async_and_synchronous_exports_share_identical_wire_bytes_and_read_policies() {
    let doc = document(5, 8193);
    let capability = cap(&["read", "produce"]);
    let mut book = memory();
    book.add_document(&doc).unwrap().unwrap();
    book.derive_redacted_view(&cap(&["privileged"]), &doc.oid())
        .unwrap()
        .unwrap();
    let expected = book
        .export_document_disclosure(&capability, &doc.oid(), &[1, 2])
        .unwrap()
        .unwrap();
    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
    let mut asynchronous = runtime
        .block_on(AsyncBook::create_with_vfs(
            &cx,
            vfs,
            std::path::Path::new("async-disclosure"),
            BookKeys::for_development(75),
            spec(),
            Entropy::deterministic(75),
        ))
        .unwrap();
    runtime
        .block_on(asynchronous.add_document(&cx, &doc))
        .unwrap()
        .unwrap();
    runtime
        .block_on(asynchronous.derive_redacted_view(&cx, &cap(&["privileged"]), &doc.oid()))
        .unwrap()
        .unwrap();
    let head = asynchronous.head(&cx).unwrap();
    let actual = runtime
        .block_on(asynchronous.export_document_disclosure(&cx, &capability, &doc.oid(), &[1, 2]))
        .unwrap()
        .unwrap();
    assert_eq!(actual, expected);
    assert_verified(&actual, &doc, &[1, 2]);
    assert_eq!(
        runtime
            .block_on(asynchronous.export_document_disclosure(&cx, &capability, &doc.oid(), &[0]))
            .unwrap()
            .unwrap_err()
            .code,
        fa_journal::refusal::code::CAPABILITY
    );
    assert_eq!(asynchronous.head(&cx).unwrap(), head);
}

#[test]
fn external_document_storage_and_empty_documents_use_the_same_public_export() {
    let directory = temp();
    let keys = BookKeys::for_development(76);
    let mut book =
        Book::create_dir(&directory, keys.clone(), spec(), Entropy::deterministic(76)).unwrap();
    // One byte beyond the current 16 MiB inline policy uses the configured
    // blob store. The public API accepts no caller-selected storage path.
    let large = document(1, 16 * 1024 * 1024 + 17);
    book.add_document(&large).unwrap().unwrap();
    let empty = document(1, 0);
    book.add_document(&empty).unwrap().unwrap();
    let head = book.head().unwrap();
    drop(book);
    let mut reopened = Book::open_dir(&directory, keys, Entropy::deterministic(77)).unwrap();
    let last = (large.bytes.len() - 1) as u64 / 4096;
    let large_proof = reopened
        .export_document_disclosure(&cap(&["read", "produce"]), &large.oid(), &[0, last])
        .unwrap()
        .unwrap();
    assert_verified(&large_proof, &large, &[0, last]);
    assert!(large_proof.bytes.len() < 8192);
    let empty_proof = reopened
        .export_document_disclosure(&cap(&["read", "produce"]), &empty.oid(), &[0])
        .unwrap()
        .unwrap();
    assert_verified(&empty_proof, &empty, &[0]);
    assert_eq!(reopened.head().unwrap(), head);
}
