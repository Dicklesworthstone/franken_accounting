//! Session-bound intake through the real CLI dispatcher and journal.
//! No fake book, transport authorization bypass or alternate publication path.

use std::path::PathBuf;

use fa::{Book, BookKeys, Entropy};
use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::{Books, Captured, Files, Stdin, run, run_with_authority};
use fa_cli::json::{Json, parse};
use fa_journal::{BookSpec, Capability, Document, DocumentRead};
use fa_model::{Id128, IntakeSource, Oid};
use fa_money::UnitRegistry;
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::FiscalCalendar;
use fgdb_types::VId;

fn book(seed: u8) -> Book {
    Book::create_memory(
        BookKeys::for_development(seed),
        BookSpec {
            book_id: Id128([seed; 16]),
            name: "Session intake".into(),
            base_unit: UnitRegistry::with_defaults().lookup("USD").unwrap(),
            calendar: FiscalCalendar::monthly("session-intake", 1, 0).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(u64::from(seed)),
    )
    .unwrap()
}

fn authority(name: &str, profile: LaunchProfile) -> LaunchAuthority {
    LaunchAuthority::new(
        PathBuf::from("session-intake-book"), None, name, profile, &["post"],
    )
    .unwrap()
}

fn event(status: u8, captured: Captured, expected: u8) -> Json {
    assert_eq!(status, expected, "{}\n{}", captured.stdout, captured.stderr);
    let lines: Vec<&str> = captured.stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{}\n{}", captured.stdout, captured.stderr);
    fa_cli::verbs::registry().unwrap().check_line(lines[0]).unwrap();
    parse(lines[0]).unwrap()
}

fn invoke(
    book: &mut Book, authority: &LaunchAuthority, args: &[&str], stdin: Stdin, expected: u8,
) -> Json {
    let argv: Vec<String> = args.iter().map(|s| (*s).into()).collect();
    let (status, captured) = run_with_authority(
        &argv,
        Books::Held { book, dir: authority.book().to_path_buf() },
        Files { cwd: None, stdin },
        authority,
        true,
    );
    event(status, captured, expected)
}

fn data(event: &Json) -> &Json {
    event.get("data").unwrap()
}

fn string<'a>(json: &'a Json, key: &str) -> &'a str {
    json.get(key).and_then(Json::as_str).unwrap()
}

fn run_vid(event: &Json) -> VId {
    VId(u128::from_str_radix(string(data(event), "run_vid"), 16).unwrap())
}

fn identity(book: &Book, bytes: &[u8]) -> Oid {
    Document {
        book_id: book.context().book_id,
        kind: EvidencePolicy::embedded().unwrap().kind_by_name("Invoice").unwrap().tag,
        mime: "application/octet-stream".into(),
        grade: 0, // Neither the grade nor uploader participates in this identity.
        retrieved_by: VId(0),
        bytes: bytes.to_vec(),
    }.oid()
}

fn read(book: &mut Book, oid: &Oid) -> Document {
    let capability = Capability::embedded(VId(900), &["read", "privileged"]).unwrap();
    match book.read_document_for(&capability, oid).unwrap().unwrap() {
        DocumentRead::Full(document) => document,
        _ => panic!("privileged reader must receive complete evidence"),
    }
}

const IMPORT: &[&str] = &["document", "import", "run", "--file", "-", "--kind", "Invoice", "--json"];

#[test]
fn post_only_preparer_imports_with_session_grade_source_and_receipt() {
    let mut book = book(161);
    let authority = authority("alice", LaunchProfile::Preparer);
    let bytes = b"human invoice";
    let oid = identity(&book, bytes);
    let before = book.head().unwrap();
    let imported = invoke(&mut book, &authority, IMPORT, Stdin::Forwarded(bytes.to_vec()), 0);
    assert_eq!(string(data(&imported), "source_kind"), "Upload");
    let receipt = book.read_run(run_vid(&imported)).unwrap().unwrap();
    assert_eq!(receipt.source, IntakeSource::Upload { principal: authority.principal_vid() });
    assert_eq!(receipt.document_count, 1);
    assert_eq!(receipt.byte_count, u64::try_from(bytes.len()).unwrap());
    assert_eq!(receipt.recorded_at.0, before.0 + 1);
    let document = read(&mut book, &oid);
    assert_eq!(document.retrieved_by, authority.principal_vid());
    assert_eq!(document.grade, EvidencePolicy::embedded().unwrap().grade_by_name("HumanUpload").unwrap().tag);
    assert_eq!(document.bytes, bytes);
    let chain = book.custody_chain(&oid).unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].0.holder(), authority.principal_vid());
}

#[test]
fn human_import_and_exact_retry_never_relabel_an_earlier_agent_upload() {
    let mut book = book(162);
    let agent = authority("agent", LaunchProfile::Agent);
    let human = authority("alice", LaunchProfile::Preparer);
    let bytes = b"agent invoice";
    let oid = identity(&book, bytes);
    invoke(&mut book, &agent, &["document", "add", "-", "--kind", "Invoice", "--json"],
        Stdin::Forwarded(bytes.to_vec()), 0);
    let original = read(&mut book, &oid);
    let custody = book.custody_chain(&oid).unwrap();
    let imported = invoke(&mut book, &human, IMPORT, Stdin::Forwarded(bytes.to_vec()), 0);
    assert_eq!(data(&imported).get("recorded").and_then(Json::as_arr).unwrap().len(), 0);
    assert_eq!(data(&imported).get("already_held").and_then(Json::as_arr).unwrap().len(), 1);
    let before = book.head().unwrap();
    let retry = invoke(&mut book, &human, IMPORT, Stdin::Forwarded(bytes.to_vec()), 0);
    assert_eq!(data(&retry).get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(data(&retry).get("receipt_hash"), data(&imported).get("receipt_hash"));
    assert_eq!(run_vid(&retry), run_vid(&imported));
    assert_eq!(book.head().unwrap(), before);
    let retained = read(&mut book, &oid);
    assert_eq!(retained.grade, original.grade);
    assert_eq!(retained.retrieved_by, agent.principal_vid());
    assert_eq!(retained.bytes, original.bytes);
    assert_eq!(book.custody_chain(&oid).unwrap(), custody);
}

#[test]
fn forged_source_and_grade_refuse_before_missing_input_is_consumed() {
    let mut book = book(163);
    let authority = authority("alice", LaunchProfile::Preparer);
    let before = book.head().unwrap();
    for source in ["Connector", "Connector:fa-import:1", "Email:message", "Scan:scanner"] {
        let mut args = IMPORT.to_vec();
        args.extend(["--source", source]);
        let refused = invoke(&mut book, &authority, &args, Stdin::Missing, 2);
        assert!(string(data(&refused), "message").contains("cannot assert"));
    }
    for grade in ["AgentUpload", "Generated", "ThirdPartySigned"] {
        let mut args = IMPORT.to_vec();
        args.extend(["--grade", grade]);
        let refused = invoke(&mut book, &authority, &args, Stdin::Missing, 3);
        assert_eq!(string(data(&refused), "refusal_id"), fa_journal::refusal::code::GRADE_UNVERIFIED);
    }
    assert_eq!(book.head().unwrap(), before);
}

#[test]
fn metadata_errors_are_reported_before_any_input_consumption() {
    let mut book = book(164);
    let authority = authority("alice", LaunchProfile::Preparer);
    let before = book.head().unwrap();
    let mime = "m".repeat(EvidencePolicy::embedded().unwrap().max_mime_bytes + 1);
    let key = "k".repeat(fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES + 1);
    let description = "d".repeat(fa_model::limits::MAX_DESCRIPTION_BYTES + 1);
    for (flag, value) in [("--mime", ""), ("--mime", mime.as_str()),
        ("--key", ""), ("--key", key.as_str()), ("--description", description.as_str())]
    {
        let mut args = IMPORT.to_vec();
        args.extend([flag, value]);
        let refused = invoke(&mut book, &authority, &args, Stdin::Missing, 2);
        assert_eq!(string(data(&refused), "refusal_id"), fa_journal::refusal::code::DOCUMENT_INTAKE);
    }
    let refused = invoke(&mut book, &authority,
        &["document", "add", "-", "--mime", &mime, "--json"], Stdin::Missing, 2);
    assert_eq!(string(data(&refused), "refusal_id"), fa_journal::refusal::code::DOCUMENT_INTAKE);
    assert_eq!(book.head().unwrap(), before);
}

#[test]
fn matching_assertions_work_but_agent_import_is_still_a_trunk_refusal() {
    let mut book = book(165);
    let human = authority("alice", LaunchProfile::Preparer);
    let agent = authority("agent", LaunchProfile::Agent);
    let mut args = IMPORT.to_vec();
    args.extend(["--source", "Upload", "--grade", "HumanUpload"]);
    invoke(&mut book, &human, &args, Stdin::Forwarded(b"verified input boundary".to_vec()), 0);
    let before = book.head().unwrap();
    let refused = invoke(&mut book, &agent, IMPORT, Stdin::Missing, 7);
    assert_eq!(string(data(&refused), "refusal_id"), "FA-REF-013");
    assert_eq!(book.head().unwrap(), before);
}

#[test]
fn embedded_owner_import_retains_its_explicit_legacy_posture() {
    let mut book = book(166);
    let bytes = b"owner source assertion";
    let oid = identity(&book, bytes);
    let mut argv = IMPORT.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
    let dir = PathBuf::from("session-intake-owner");
    argv.extend(["--book".into(), dir.to_str().unwrap().into()]);
    let (status, captured) = run(&argv,
        Books::Held { book: &mut book, dir },
        Files { cwd: None, stdin: Stdin::Forwarded(bytes.to_vec()) }, true);
    let imported = event(status, captured, 0);
    assert_eq!(string(data(&imported), "source_kind"), "Connector");
    let document = read(&mut book, &oid);
    assert_eq!(document.grade, EvidencePolicy::embedded().unwrap().grade_by_name("AgentUpload").unwrap().tag);
    assert_eq!(document.retrieved_by, fa_model::principal_vid("operator"));
}
