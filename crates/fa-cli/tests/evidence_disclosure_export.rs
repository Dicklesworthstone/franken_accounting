//! Real persisted books and committed postings, checked by the independent
//! verifier. This target uses fa-cli's existing fa-verify development dependency;
//! the producer never depends on its verifier or a second wire implementation.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa::{Book, BookKeys, Capability, DisclosureAccess, Entropy, EvidenceDisclosureRequest};
use fa_cli::json::{self, Json};
use fa_journal::{BookSpec, Document};
use fa_model::{Id128, Oid};
use fa_money::UnitRegistry;
use fa_time::FiscalCalendar;
use fa_verify::evidence::{EvidenceExpectation, verify_evidence_disclosure_for};
use fa_verify::{Checkpoint, RecordCheck};
use fgdb_types::VId;

const PRINCIPAL: VId = VId(7);
const CHUNK: usize = 4096;
const KEY_SEED: u8 = 94;

fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64);
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap();
    }
    bytes
}

fn data_text<'a>(event: &'a Json, name: &str) -> &'a str {
    event
        .get("data")
        .unwrap()
        .get(name)
        .unwrap()
        .as_str()
        .unwrap()
}

fn temporary() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-cited-evidence-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
}

fn cli(book: &Path, arguments: &[&str]) -> Json {
    let result = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(["--via", "direct", "--json", "--no-color"])
        .args(arguments)
        .env_remove("FA_BOOK")
        .output()
        .unwrap();
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(
        result.status.success(),
        "{arguments:?}: {stdout}\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stderr.is_empty());
    assert_eq!(stdout.lines().count(), 1);
    fa_cli::verbs::registry()
        .unwrap()
        .check_line(stdout.trim())
        .unwrap();
    json::parse(stdout.trim()).unwrap()
}

struct Fixture {
    root: PathBuf,
    book: PathBuf,
    document: Document,
    uncited: Document,
    request: EvidenceDisclosureRequest,
    anchor: Checkpoint,
}

impl Fixture {
    fn new(kind: u8, derive: bool) -> Self {
        let root = temporary();
        let path = root.join("book");
        let keys = BookKeys::for_development(KEY_SEED);
        let mut book = Book::create_dir(
            &path,
            keys.clone(),
            BookSpec {
                book_id: Id128([KEY_SEED; 16]),
                name: "Journal-authenticated evidence".into(),
                base_unit: UnitRegistry::embedded().unwrap().lookup("USD").unwrap(),
                calendar: FiscalCalendar::monthly("evidence", 1, 1).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(u64::from(KEY_SEED)),
        )
        .unwrap();
        keys.save(&path.join("book.keys")).unwrap();
        let document = Document {
            book_id: book.context().book_id,
            kind,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: PRINCIPAL,
            bytes: (0..CHUNK * 3 + 11)
                .map(|index| b'A' + (index / CHUNK) as u8)
                .collect(),
        };
        let uncited = Document {
            bytes: b"a different document which this entry does not cite".to_vec(),
            ..document.clone()
        };
        book.add_document(&document).unwrap().unwrap();
        book.add_document(&uncited).unwrap().unwrap();
        if derive {
            book.derive_redacted_view(&cap(&["privileged"]), &document.oid())
                .unwrap()
                .unwrap();
        }
        drop(book);
        let chart = root.join("chart.json");
        std::fs::write(&chart, r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#).unwrap();
        cli(&path, &["chart", "import", chart.to_str().unwrap()]);
        cli(&path, &["period", "create", "--fiscal-year", "2026"]);
        cli(&path, &["period", "open", "FY2026-P03"]);
        let source_role = fa_registry::evidence_policy::EvidencePolicy::embedded()
            .unwrap()
            .role_by_name("Source")
            .unwrap()
            .tag;
        let (entry, expected_entry_digest) = Self::post_at(&root, &path, &document, "first");
        let checkpoint = cli(&path, &["checkpoint", "create", "--grant", "witness"]);
        let state = Oid(digest(data_text(&checkpoint, "oid")));
        let request = EvidenceDisclosureRequest {
            state: Some(state),
            entry,
            expected_entry_digest,
            document: document.oid(),
            role: source_role,
        };
        // Establish fixture trust separately, before invoking the composite
        // exporter; never derive an expected anchor from its returned proof.
        let handle = Book::open_dir(&path, keys, Entropy::deterministic(95)).unwrap();
        let exported = handle
            .export_proof(
                PRINCIPAL,
                &cap(&["read", "produce"]),
                fa::ProofRequest {
                    state: Some(state),
                    kind: fa::ProofKind::Checkpoint,
                },
            )
            .unwrap()
            .unwrap();
        let anchor = Checkpoint::decode(&exported.bytes).unwrap();
        drop(handle);
        Self {
            root,
            book: path,
            document,
            uncited,
            request,
            anchor,
        }
    }

    fn open(&self) -> Book {
        Book::open_dir(
            &self.book,
            BookKeys::for_development(KEY_SEED),
            Entropy::deterministic(95),
        )
        .unwrap()
    }

    fn post(&self, key: &str) -> (VId, [u8; 32]) {
        Self::post_at(&self.root, &self.book, &self.document, key)
    }

    fn post_at(root: &Path, book: &Path, document: &Document, key: &str) -> (VId, [u8; 32]) {
        let path = root.join(format!("{key}.json"));
        std::fs::write(&path, format!(r#"{{"effective_date":"2026-03-15","idempotency_key":"{key}","legs":[{{"side":"debit","account":"1000","amount":"12.34 USD"}},{{"side":"credit","account":"4000","amount":"12.34 USD"}}]}}"#)).unwrap();
        let entry = cli(
            book,
            &[
                "post",
                "--intent",
                path.to_str().unwrap(),
                "--evidence",
                &hex(&document.oid().0),
            ],
        );
        (
            VId(u128::from_str_radix(data_text(&entry, "vid"), 16).unwrap()),
            digest(data_text(&entry, "entry_digest")),
        )
    }

    fn expected(&self) -> EvidenceExpectation {
        EvidenceExpectation {
            entry_digest: self.request.expected_entry_digest,
            document_oid: self.request.document.0,
            role: self.request.role,
        }
    }
}

#[test]
fn committed_entry_and_exact_chunks_verify_independently_after_reopen() {
    let fixture = Fixture::new(1, false);
    let mut book = fixture.open();
    let before = book.head().unwrap();
    let artifact = book
        .export_evidence_disclosure(&cap(&["read", "produce"]), fixture.request, &[0, 3])
        .unwrap()
        .unwrap();
    let report = verify_evidence_disclosure_for(
        &artifact.inclusion.bytes,
        &artifact.disclosure.bytes,
        &fixture.anchor,
        &fixture.expected(),
        &[0, 3],
    )
    .unwrap();
    assert_eq!(report.inclusion.record, RecordCheck::Recomputed);
    assert_eq!(report.disclosure.scope, "membership_only");
    assert_eq!(report.citation.doc_commit, fixture.document.doc_commit());
    assert_eq!(artifact.citation.document_oid, fixture.document.oid());
    assert_eq!(artifact.entry_digest, fixture.request.expected_entry_digest);
    assert_eq!(artifact.disclosure.requested_chunks, vec![0, 3]);
    assert_eq!(book.head().unwrap(), before);
    let debug = format!("{artifact:?}");
    assert!(!debug.contains(&"A".repeat(100)));
    assert!(!debug.contains(&hex(&artifact.disclosure.bytes)));
    assert!(!debug.contains(&format!("{:?}", artifact.inclusion.bytes)));
    let mut damaged = artifact.disclosure.bytes.clone();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(
        verify_evidence_disclosure_for(
            &artifact.inclusion.bytes,
            &damaged,
            &fixture.anchor,
            &fixture.expected(),
            &[0, 3]
        )
        .is_err()
    );
    assert!(
        verify_evidence_disclosure_for(
            &artifact.inclusion.bytes,
            &artifact.disclosure.bytes,
            &fixture.anchor,
            &fixture.expected(),
            &[0]
        )
        .is_err()
    );
    drop(book);
    let repeated = fixture
        .open()
        .export_evidence_disclosure(&cap(&["read", "produce"]), fixture.request, &[0, 3])
        .unwrap()
        .unwrap();
    assert_eq!(artifact, repeated);
}

#[test]
fn wrong_entry_digest_uncited_document_and_wrong_role_never_produce_an_artifact() {
    let fixture = Fixture::new(1, false);
    let mut book = fixture.open();
    let before = book.head().unwrap();
    let mut changed_digest = fixture.request;
    changed_digest.expected_entry_digest[0] ^= 1;
    let mut changed_document = fixture.request;
    changed_document.document = fixture.uncited.oid();
    let mut changed_role = fixture.request;
    changed_role.role = 255;
    for request in [changed_digest, changed_document, changed_role] {
        let refusal = book
            .export_evidence_disclosure(&cap(&["read", "produce"]), request, &[0])
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::STRUCTURE);
    }
    for requested in [&[][..], &[1, 1], &[2, 1], &[u64::MAX]] {
        assert!(
            book.export_evidence_disclosure(&cap(&["read", "produce"]), fixture.request, requested)
                .unwrap()
                .is_err()
        );
    }
    assert_eq!(book.head().unwrap(), before);
}

#[test]
fn governed_disclosure_preserves_redaction_and_requires_an_existing_view() {
    for derive in [false, true] {
        let fixture = Fixture::new(5, derive);
        let mut book = fixture.open();
        let before = book.head().unwrap();
        let reader = cap(&["read", "produce"]);
        assert!(
            book.export_evidence_disclosure(&reader, fixture.request, &[0])
                .unwrap()
                .is_err()
        );
        let permitted = book
            .export_evidence_disclosure(&reader, fixture.request, &[1, 3])
            .unwrap();
        if derive {
            let artifact = permitted.unwrap();
            assert_eq!(
                artifact.disclosure.access,
                DisclosureAccess::Redacted { contract: 1 }
            );
            verify_evidence_disclosure_for(
                &artifact.inclusion.bytes,
                &artifact.disclosure.bytes,
                &fixture.anchor,
                &fixture.expected(),
                &[1, 3],
            )
            .unwrap();
            assert!(
                !artifact
                    .disclosure
                    .bytes
                    .windows(100)
                    .any(|bytes| bytes == [b'A'; 100])
            );
        } else {
            assert!(permitted.is_err(), "export never derives a missing view");
        }
        let privileged = book
            .export_evidence_disclosure(
                &cap(&["read", "produce", "privileged"]),
                fixture.request,
                &[0],
            )
            .unwrap()
            .unwrap();
        assert_eq!(privileged.disclosure.access, DisclosureAccess::Full);
        verify_evidence_disclosure_for(
            &privileged.inclusion.bytes,
            &privileged.disclosure.bytes,
            &fixture.anchor,
            &fixture.expected(),
            &[0],
        )
        .unwrap();
        assert_eq!(book.head().unwrap(), before);
    }
}

#[test]
fn current_authority_and_the_selected_checkpoint_cannot_be_replaced_by_a_later_entry() {
    let fixture = Fixture::new(1, false);
    let mut book = fixture.open();
    let before = book.head().unwrap();
    for capability in [
        cap(&["read"]),
        cap(&["produce"]),
        cap(&["privileged", "produce"]),
    ] {
        let refusal = book
            .export_evidence_disclosure(&capability, fixture.request, &[])
            .unwrap()
            .unwrap_err();
        assert_eq!(
            refusal.code,
            fa_journal::refusal::code::CAPABILITY,
            "authority precedes malformed request"
        );
    }
    let expired = cap(&["read", "produce"]).expiring_at(before);
    assert_eq!(
        book.export_evidence_disclosure(&expired, fixture.request, &[0])
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-014"
    );
    assert_eq!(book.head().unwrap(), before);
    drop(book);
    let (entry, expected_entry_digest) = fixture.post("after-checkpoint");
    let mut request = fixture.request;
    request.entry = entry;
    request.expected_entry_digest = expected_entry_digest;
    let mut book = fixture.open();
    let before = book.head().unwrap();
    assert!(
        book.export_evidence_disclosure(&cap(&["read", "produce"]), request, &[0])
            .unwrap()
            .is_err()
    );
    assert_eq!(
        book.head().unwrap(),
        before,
        "no checkpoint is created to make a request pass"
    );
}
