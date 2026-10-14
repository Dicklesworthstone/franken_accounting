//! Synchronous Book integration for capability-bound evidence intake (fa-vwf).
//! These tests exercise real book storage and the shared posting kernel.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fa::{Book, BookKeys, Entropy};
use fa_journal::{BookSpec, DocumentRead, UploadRequest};
use fa_model::Id128;
use fa_money::UnitRegistry;
use fa_policy::{Capability, Op, Profile};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::FiscalCalendar;
use fgdb_types::VId;

fn spec() -> BookSpec {
    let units = UnitRegistry::embedded().unwrap();
    BookSpec {
        book_id: Id128([0x72; 16]),
        name: "Authorized upload facade".into(),
        base_unit: units.lookup("USD").unwrap(),
        calendar: FiscalCalendar::monthly("upload-facade", 1, 1).unwrap(),
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    }
}

fn book() -> Book {
    Book::create_memory(
        BookKeys::for_development(0x5a),
        spec(),
        Entropy::deterministic(72),
    )
    .unwrap()
}

fn capability(holder: u128, profile: Profile, ops: &[Op]) -> Capability {
    Capability::new(VId(holder), profile, ops, VId(1)).unwrap()
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

fn temporary_directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fa-authorized-upload-{}-{n}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
}

#[test]
fn synchronous_upload_derives_identity_and_publishes_one_custody_receipt() {
    let mut book = book();
    let reader = capability(99, Profile::Human, &[Op::Read, Op::Privileged]);
    for (holder, profile, expected) in [
        (20, Profile::Agent, "AgentUpload"),
        (21, Profile::Human, "HumanUpload"),
        (22, Profile::System, "AgentUpload"),
    ] {
        let cap = capability(holder, profile, &[Op::Post]);
        let bytes = format!("distinct document for holder {holder}");
        let before = book.head().unwrap();
        let added = book
            .upload_document(&cap, request(bytes.as_bytes()))
            .unwrap()
            .unwrap();
        assert_eq!(added.grade, grade(expected));
        assert!(!added.already_recorded);
        assert_eq!(added.recorded_at.0, before.0 + 1);
        assert_eq!(book.head().unwrap(), added.recorded_at);
        let custody = book.custody_chain(&added.oid).unwrap();
        assert_eq!(custody.len(), 1);
        assert_eq!(custody[0].1, added.recorded_at);
        assert_eq!(
            book.document_commitment(&added.oid).unwrap(),
            Some(added.doc_commit)
        );
        let DocumentRead::Full(document) = book
            .read_document_for(&reader, &added.oid)
            .unwrap()
            .unwrap()
        else {
            panic!("privileged read must return verified full bytes");
        };
        assert_eq!(document.retrieved_by, cap.holder());
        assert_eq!(document.grade, grade(expected));
        assert_eq!(document.bytes, bytes.as_bytes());
        assert_eq!(book.head().unwrap(), added.recorded_at);
    }
}

#[test]
fn a_human_reupload_does_not_upgrade_existing_machine_evidence() {
    let mut book = book();
    let agent = capability(20, Profile::Agent, &[Op::Post]);
    let human = capability(21, Profile::Human, &[Op::Post]);
    let original = book
        .upload_document(&agent, request(b"same evidence"))
        .unwrap()
        .unwrap();
    let before = book.head().unwrap();
    let chain = book.custody_chain(&original.oid).unwrap();
    let mut retry = request(b"same evidence");
    retry.asserted_grade = Some(grade("HumanUpload"));
    let repeated = book.upload_document(&human, retry).unwrap().unwrap();
    assert!(repeated.already_recorded);
    assert_eq!(repeated.grade, grade("AgentUpload"));
    assert_eq!(repeated.oid, original.oid);
    assert_eq!(repeated.recorded_at, original.recorded_at);
    assert_eq!(book.head().unwrap(), before);
    assert_eq!(book.custody_chain(&original.oid).unwrap(), chain);
}

#[test]
fn forged_grade_and_unauthorized_retries_never_publish() {
    let mut book = book();
    let agent = capability(20, Profile::Agent, &[Op::Post]);
    book.upload_document(&agent, request(b"held evidence"))
        .unwrap()
        .unwrap();
    for bytes in [b"held evidence".as_slice(), b"new evidence".as_slice()] {
        let before = book.head().unwrap();
        let mut forged = request(bytes);
        forged.asserted_grade = Some(grade("HumanUpload"));
        let denied = book.upload_document(&agent, forged).unwrap().unwrap_err();
        assert_eq!((denied.code, denied.exit), ("FA-REF-084", 3));
        assert_eq!(book.head().unwrap(), before);
        let reader = capability(20, Profile::Agent, &[Op::Read]);
        let denied = book
            .upload_document(&reader, request(bytes))
            .unwrap()
            .unwrap_err();
        assert_eq!((denied.code, denied.exit), ("FA-REF-011", 7));
        assert_eq!(book.head().unwrap(), before);
    }
}

#[test]
fn scoped_and_expired_authority_cannot_be_self_issued_away() {
    let mut book = book();
    let before = book.head().unwrap();
    let cap = capability(20, Profile::Agent, &[Op::Post]);
    for (cap, code) in [
        (
            cap.clone().for_books(&[Id128([0x73; 16])]).unwrap(),
            "FA-REF-011",
        ),
        (cap.clone().expiring_at(before), "FA-REF-014"),
    ] {
        let denied = book
            .upload_document(&cap, request(b"excluded evidence"))
            .unwrap()
            .unwrap_err();
        assert_eq!((denied.code, denied.exit), (code, 7));
        assert_eq!(book.head().unwrap(), before);
    }
    let admitted = book
        .upload_document(&cap, request(b"excluded evidence"))
        .unwrap()
        .unwrap();
    assert_eq!(admitted.recorded_at.0, before.0 + 1);
}

#[test]
fn large_session_uploads_use_the_book_store_and_keep_authority_after_reopen() {
    let dir = temporary_directory().join("book");
    let keys = BookKeys::for_development(0x75);
    let mut book =
        Book::create_dir(&dir, keys.clone(), spec(), Entropy::deterministic(75)).unwrap();
    let agent = capability(30, Profile::Agent, &[Op::Post]);
    let limit = usize::try_from(EvidencePolicy::embedded().unwrap().max_document_bytes).unwrap();
    let mut large = request(b"");
    large.bytes = vec![0x75; limit.checked_add(1).unwrap()];
    let before = book.head().unwrap();
    let reader = capability(31, Profile::Human, &[Op::Read, Op::Privileged]);
    let denied = book
        .upload_document(&reader, large.clone())
        .unwrap()
        .unwrap_err();
    assert_eq!((denied.code, denied.exit), ("FA-REF-011", 7));
    let mut forged = large.clone();
    forged.asserted_grade = Some(grade("HumanUpload"));
    let denied = book.upload_document(&agent, forged).unwrap().unwrap_err();
    assert_eq!((denied.code, denied.exit), ("FA-REF-084", 3));
    assert_eq!(book.head().unwrap(), before);
    let added = book
        .upload_document(&agent, large.clone())
        .unwrap()
        .unwrap();
    assert_eq!(added.grade, grade("AgentUpload"));
    assert_eq!(added.recorded_at.0, before.0 + 1);
    let locator = fa_journal::blob::locator_of(&added.doc_commit);
    assert_eq!(
        std::fs::read(dir.join("blobs").join(&locator[..2]).join(&locator)).unwrap(),
        large.bytes
    );
    drop(book);
    let mut book = Book::open_dir(&dir, keys, Entropy::deterministic(76)).unwrap();
    let DocumentRead::Full(document) = book
        .read_document_for(&reader, &added.oid)
        .unwrap()
        .unwrap()
    else {
        panic!("large upload must remain readable after reopen");
    };
    assert_eq!(document.bytes, large.bytes);
    assert_eq!(document.retrieved_by, agent.holder());
    assert_eq!(document.grade, grade("AgentUpload"));
    let human = capability(32, Profile::Human, &[Op::Post]);
    large.asserted_grade = Some(grade("HumanUpload"));
    let repeated = book.upload_document(&human, large).unwrap().unwrap();
    assert!(repeated.already_recorded);
    assert_eq!(
        (repeated.oid, repeated.recorded_at, repeated.grade),
        (added.oid, added.recorded_at, added.grade)
    );
    assert_eq!(book.custody_chain(&added.oid).unwrap().len(), 1);
    assert_eq!(book.head().unwrap(), added.recorded_at);
}

#[test]
fn scratch_directory_dispatch_keeps_new_evidence_out_of_the_source_journal() {
    let dir = temporary_directory().join("book");
    let mut source = Book::create_dir(
        &dir,
        BookKeys::for_development(0x76),
        spec(),
        Entropy::deterministic(76),
    )
    .unwrap();
    let agent = capability(40, Profile::Agent, &[Op::Post]);
    let initial = source
        .upload_document(&agent, request(b"source evidence"))
        .unwrap()
        .unwrap();
    let before = source.head().unwrap();
    let (mut scratch, map) = source
        .replay_into_scratch(
            None,
            BookKeys::for_development(0x77),
            Entropy::deterministic(77),
        )
        .unwrap()
        .unwrap();
    source.verify_replay(&scratch, &map).unwrap().unwrap();
    let repeated = scratch
        .upload_document(&agent, request(b"source evidence"))
        .unwrap()
        .unwrap();
    assert!(repeated.already_recorded);
    assert_eq!(repeated.oid, initial.oid);
    let added = scratch
        .upload_document(&agent, request(b"scratch-only evidence"))
        .unwrap()
        .unwrap();
    assert!(!added.already_recorded);
    assert_eq!(added.grade, grade("AgentUpload"));
    assert_eq!(source.document_commitment(&added.oid).unwrap(), None);
    assert!(source.custody_chain(&added.oid).unwrap().is_empty());
    assert_eq!(source.head().unwrap(), before);
    assert_eq!(scratch.custody_chain(&added.oid).unwrap().len(), 1);
}
