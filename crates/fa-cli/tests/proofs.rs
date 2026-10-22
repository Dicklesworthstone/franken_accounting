//! Persisted producer artifacts checked by the independent outsider verifier.
//! Every CLI invocation opens the book anew; proof export must remain a read.

#![forbid(unsafe_code)]

#[path = "proofs/prefix.rs"]
mod prefix;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa::book::{Book, BookKeys, Entropy};
use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::{Files, Stdin};
use fa_cli::entry::fa_with_authority;
use fa_cli::json::{self, Json};
use fa_journal::BookSpec;
use fa_model::{Id128, Oid, account_vid, principal_vid};
use fa_policy::Capability;
use fa_verify::{Checkpoint, RecordCheck};

const BOOK_ID: Id128 = Id128([0x51; 16]);
const KEY_SEED: u8 = 53;
const UNKNOWN_STATE: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const UNKNOWN_ENTRY: &str = "ffffffffffffffffffffffffffffffff";

fn get<'a>(value: &'a Json, key: &str) -> &'a Json {
    value
        .get("data")
        .and_then(|data| data.get(key))
        .or_else(|| value.get(key))
        .expect(key)
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    get(value, key).as_str().expect(key)
}

fn integer(value: &Json, key: &str) -> i128 {
    match get(value, key) {
        Json::Int(value) => *value,
        value => panic!("{key} must be an integer: {value:?}"),
    }
}

fn parse_line(stdout: &str, stderr: &str) -> Json {
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{stdout}\n{stderr}");
    fa_cli::verbs::registry()
        .expect("registry")
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("{error}\n{stdout}\n{stderr}"));
    json::parse(lines[0]).expect("one robot object")
}

fn run(book: &Path, args: &[&str]) -> (i32, Json) {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .output()
        .expect("run fa");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let line = parse_line(&stdout, &stderr);
    assert_eq!(text(&line, "event") == "error", code != 0, "{line:?}");
    (code, line)
}

fn ok(book: &Path, args: &[&str]) -> Json {
    let (code, line) = run(book, args);
    assert_eq!(code, 0, "args={args:?}: {}", line.render());
    line
}

fn exported(book: &Path, args: &[&str]) -> Json {
    let mut argv = vec!["proof"];
    argv.extend_from_slice(args);
    let line = ok(book, &argv);
    assert_eq!(text(&line, "event"), "proof_exported");
    assert_eq!(text(&line, "kind"), args[0]);
    if args[0] == "signed-checkpoint" {
        assert_eq!(text(&line, "signatures"), "ed25519");
        assert_eq!(text(&line, "trust"), "checkpoint_public_key");
    } else {
        assert_eq!(text(&line, "signatures"), "unsigned");
        assert_eq!(text(&line, "trust"), "external_checkpoint_required");
    }
    assert_eq!(
        unhex(text(&line, "checkpoint_public_key")).len(),
        32,
        "every export names the book's checkpoint public key"
    );
    assert_eq!(
        integer(get(&line, "coordinate"), "known_at"),
        integer(&line, "through_seq")
    );
    let checkpoint = Checkpoint::decode(&unhex(text(&line, "checkpoint_bytes")))
        .expect("every export names the exact independent checkpoint format");
    assert_eq!(
        fa_verify::blake3::hex(&checkpoint.root),
        text(&line, "root")
    );
    assert_eq!(checkpoint.leaf_count, integer(&line, "leaf_count") as u64);
    if let Some(raw) = get(&line, "bytes").as_str() {
        assert_eq!(unhex(raw).len() as i128, integer(&line, "byte_len"));
    }
    line
}

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "even hex length");
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16).expect("hex byte")
        })
        .collect()
}

fn bytes(value: &Json) -> Vec<u8> {
    unhex(text(value, "bytes"))
}

fn temp_dir() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("fa-proofs-cli-{}-{id}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
}

fn write(dir: &Path, name: &str, contents: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write retained fixture");
    path.display().to_string()
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = temp_dir();
        let book = dir.join("book");
        let units = fa_money::UnitRegistry::embedded().expect("units");
        let keys = BookKeys::for_development(KEY_SEED);
        let handle = Book::create_dir(
            &book,
            keys.clone(),
            BookSpec {
                book_id: BOOK_ID,
                name: "Portable proof fixture".into(),
                base_unit: units.lookup("USD").expect("USD"),
                calendar: fa_time::FiscalCalendar::monthly("fiscal", 1, 1).expect("calendar"),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(u64::from(KEY_SEED)),
        )
        .expect("create persisted book");
        keys.save(&book.join("book.keys")).expect("save keys");
        drop(handle);
        Self { dir, book }
    }

    fn open(&self) -> Book {
        Book::open_dir(
            &self.book,
            BookKeys::load(&self.book.join("book.keys")).expect("load fixture keys"),
            Entropy::deterministic(97),
        )
        .expect("reopen persisted book")
    }

    fn head(&self) -> u64 {
        self.open().head().expect("book frontier").0
    }

    fn checkpoint(&self) -> Json {
        ok(&self.book, &["checkpoint", "create", "--grant", "witness"])
    }

    fn chart_and_evidence(&self) -> String {
        let chart = write(
            &self.dir,
            "chart.json",
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
        );
        ok(&self.book, &["chart", "import", &chart]);
        ok(&self.book, &["period", "create", "--fiscal-year", "2026"]);
        ok(&self.book, &["period", "open", "FY2026-P03"]);
        let source = write(&self.dir, "receipt.txt", "Retained proof fixture receipts.");
        let document = ok(
            &self.book,
            &[
                "document",
                "add",
                &source,
                "--kind",
                "Receipt",
                "--grade",
                "HumanUpload",
            ],
        );
        text(&document, "oid").to_string()
    }

    fn post(&self, key: &str, date: &str, amount: &str, evidence: &str) -> Json {
        let intent = write(
            &self.dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":[{{"side":"debit","account":"1000","amount":"{amount} USD"}},{{"side":"credit","account":"4000","amount":"{amount} USD"}}]}}"#
            ),
        );
        ok(
            &self.book,
            &["post", "--intent", &intent, "--evidence", evidence],
        )
    }
}

/// The signed anchor end to end through the CLI: `fa proof signed-checkpoint`
/// exports the journaled TransparencyCheckpoint, the independent verifier
/// checks its signature against the public key every export names, and a
/// prefix proof is judged against the checkpoint that signature covers. A
/// flipped byte or another key is refused.
#[test]
fn a_signed_checkpoint_export_verifies_against_the_named_public_key() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    f.post("signed-sale", "2026-03-10", "5.00", &evidence);
    let created = f.checkpoint();
    assert_eq!(text(&created, "signatures"), "ed25519");
    let signed = exported(&f.book, &["signed-checkpoint"]);
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .expect("32-byte key");
    assert_eq!(
        text(&created, "public_key"),
        text(&signed, "checkpoint_public_key")
    );
    let verified = fa_verify::verify_checkpoint(&bytes(&signed), &[key])
        .expect("the book's own key verifies its checkpoint");
    let raw = Checkpoint::decode(&unhex(text(&signed, "checkpoint_bytes")))
        .expect("the raw statement of the same state");
    assert_eq!(
        verified.checkpoint, raw,
        "the signature covers this statement"
    );
    assert_eq!(
        fa_verify::blake3::hex(&verified.oid),
        text(&created, "checkpoint_oid")
    );
    let prefix = exported(&f.book, &["prefix"]);
    let complete = fa_verify::verify_prefix(&bytes(&prefix), &verified.checkpoint)
        .expect("the prefix proof verifies against the signed anchor");
    assert_eq!(
        complete.envelopes.len() as u64,
        verified.checkpoint.leaf_count
    );

    let mut flipped = bytes(&signed);
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert!(fa_verify::verify_checkpoint(&flipped, &[key]).is_err());
    let mut stranger = key;
    stranger[0] ^= 0x80;
    assert!(
        fa_verify::verify_checkpoint(&bytes(&signed), &[stranger]).is_err(),
        "another key never verifies it"
    );
}

/// `fa bundle produce` end to end: a prefix bundle and an account-interval
/// bundle with a recomputed balance, written to new files and checked by the
/// independent verifier with the key the event names; inline output equals
/// the files; usage mistakes refuse before the book is read.
#[test]
fn bundles_produced_by_the_cli_verify_offline_with_their_receipts() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    let (code, refusal) = run(&f.book, &["bundle", "produce"]);
    assert_eq!(code, 2, "{}", refusal.render());
    assert_eq!(
        text(&refusal, "refusal_id"),
        "FA-REF-145",
        "no checkpoint yet"
    );
    f.post("bundle-sale-1", "2026-03-10", "12.34", &evidence);
    f.post("bundle-sale-2", "2026-03-20", "2.00", &evidence);
    f.checkpoint();

    let fab = f.dir.join("prefix.fab");
    let receipt = f.dir.join("prefix.receipt");
    let line = ok(
        &f.book,
        &[
            "bundle",
            "produce",
            "--out",
            fab.to_str().unwrap(),
            "--receipt-out",
            receipt.to_str().unwrap(),
        ],
    );
    assert_eq!(text(&line, "event"), "bundle_produced");
    assert_eq!(text(&line, "scope"), "prefix");
    assert_eq!(get(&line, "bytes"), &Json::Null);
    let key: [u8; 32] = unhex(text(&line, "checkpoint_public_key"))
        .try_into()
        .expect("32-byte key");
    assert!(text(&line, "verify").starts_with("fa-verify bundle "));
    let bundle_bytes = std::fs::read(&fab).expect("bundle file");
    let receipt_bytes = std::fs::read(&receipt).expect("receipt file");
    assert_eq!(bundle_bytes.len() as i128, integer(&line, "byte_len"));
    let report = fa_verify::verify_bundle(&bundle_bytes, &[key], Some(&receipt_bytes))
        .expect("a well-formed bundle");
    assert!(report.verified(), "{:#?}", report.checks);
    assert_eq!(
        fa_verify::blake3::hex(&report.digest),
        text(&line, "digest")
    );
    assert!(report.receipt.is_some(), "the receipt verified");

    // Inline output carries the same deterministic body.
    let inline = ok(&f.book, &["bundle", "produce"]);
    assert_eq!(unhex(text(&inline, "bytes")), bundle_bytes);

    // One account's interval with a recomputed balance.
    let line = ok(
        &f.book,
        &[
            "bundle",
            "produce",
            "--account",
            "1000",
            "--from",
            "2026-03-01",
            "--to",
            "2026-03-31",
            "--balance",
            "1000:USD:2026-03-31",
        ],
    );
    assert_eq!(text(&line, "scope"), "account");
    assert_eq!(integer(&line, "balances"), 1);
    let report = fa_verify::verify_bundle(
        &unhex(text(&line, "bytes")),
        &[key],
        Some(&unhex(text(&line, "receipt"))),
    )
    .expect("a well-formed account bundle");
    assert!(report.verified(), "{:#?}", report.checks);
    assert_eq!(report.summary.balances.len(), 1);

    // Tampering is caught; usage mistakes exit 2 before any read.
    let mut flipped = bundle_bytes.clone();
    let middle = flipped.len() / 2;
    flipped[middle] ^= 1;
    assert!(
        fa_verify::verify_bundle(&flipped, &[key], Some(&receipt_bytes))
            .map_or(true, |report| !report.verified())
    );
    for args in [
        vec!["bundle", "produce", "--account", "1000", "--entry", "E:00"],
        vec!["bundle", "produce", "--from", "2026-03-01"],
        vec!["bundle", "produce", "--out", "x.fab"],
        vec!["bundle", "produce", "--balance", "1000"],
        vec!["bundle", "export"],
    ] {
        let (code, refusal) = run(&f.book, &args);
        assert_eq!(code, 2, "{args:?}: {}", refusal.render());
    }
}

#[test]
fn all_five_exports_verify_independently_at_recorded_checkpoints_after_reopen() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    let first = f.post("first-sale", "2026-03-10", "12.34", &evidence);
    let old_state = f.checkpoint();
    let second = f.post("second-sale", "2026-03-20", "2.00", &evidence);
    let new_state = f.checkpoint();
    let later = f.post("later-sale", "2026-03-21", "9.00", &evidence);
    let before = f.head();

    let old_export = exported(&f.book, &["checkpoint", "--state", text(&old_state, "oid")]);
    let old = Checkpoint::decode(&bytes(&old_export)).expect("independent old checkpoint decode");
    assert_eq!(bytes(&old_export).len(), Checkpoint::ENCODED_LEN);
    assert_eq!(
        text(&old_export, "bytes"),
        text(&old_export, "checkpoint_bytes")
    );
    assert_eq!(text(&old_export, "state_oid"), text(&old_state, "oid"));
    assert_eq!(old.through_seq, integer(&old_state, "through_seq") as u64);
    // Chart, fiscal-year birth, period opening, the evidence document's
    // import receipt (fa-va02), and the first posting.
    assert_eq!(old.leaf_count, 5);

    let new_export = exported(&f.book, &["checkpoint"]);
    let new = Checkpoint::decode(&bytes(&new_export)).expect("independent new checkpoint decode");
    assert_eq!(text(&new_export, "state_oid"), text(&new_state, "oid"));
    assert_eq!(new.through_seq, integer(&new_state, "through_seq") as u64);
    assert_eq!(new.book_id, BOOK_ID.0);
    assert_eq!(new.branch_id, Id128::TRUNK.0);
    assert_eq!(new.leaf_count, 6);
    assert!(new.through_seq < integer(&later, "recorded_at") as u64);
    assert_eq!(
        bytes(&exported(&f.book, &["checkpoint", "--state", "latest"])),
        bytes(&new_export)
    );

    let inclusion = exported(&f.book, &["inclusion", "--entry", text(&first, "vid")]);
    let included = fa_verify::verify_inclusion(&bytes(&inclusion), &new)
        .expect("producer inclusion verifies independently");
    assert_eq!(included.record, RecordCheck::NotSupplied);
    assert_eq!(
        included.envelope.commit_seq,
        integer(&first, "recorded_at") as u64
    );
    assert_eq!(
        fa_verify::blake3::hex(&included.envelope.record_digest),
        text(&first, "entry_digest")
    );
    let typed_entry = format!("E:{}", text(&first, "vid"));
    let disclosed = exported(
        &f.book,
        &["inclusion", "--entry", &typed_entry, "--with-record"],
    );
    let checked_record = fa_verify::verify_inclusion(&bytes(&disclosed), &new)
        .expect("producer record is independently recomputed");
    assert_eq!(checked_record.envelope, included.envelope);

    let consistency = exported(
        &f.book,
        &[
            "consistency",
            "--state",
            text(&old_state, "oid"),
            "--next-state",
            text(&new_state, "oid"),
        ],
    );
    let extended = fa_verify::verify_consistency(&bytes(&consistency), &old, &new)
        .expect("new recorded root extends the trusted old root");
    assert_eq!(extended.trusted, old);
    assert_eq!(extended.extended, new);
    assert_eq!(
        text(&consistency, "next_state_oid"),
        text(&new_state, "oid")
    );
    assert_eq!(
        Checkpoint::decode(&unhex(text(&consistency, "next_checkpoint_bytes")))
            .expect("claimed next checkpoint"),
        new
    );

    let prefix = exported(&f.book, &["prefix"]);
    let complete = fa_verify::verify_prefix(&bytes(&prefix), &new)
        .expect("complete prefix independently reconstructs the root");
    assert_eq!(complete.envelopes.len() as u64, new.leaf_count);
    for posted in [&first, &second] {
        assert!(complete.envelopes.iter().any(|envelope| {
            fa_verify::blake3::hex(&envelope.record_digest) == text(posted, "entry_digest")
        }));
    }
    assert!(!complete.envelopes.iter().any(|envelope| {
        fa_verify::blake3::hex(&envelope.record_digest) == text(&later, "entry_digest")
    }));

    let filtered = exported(
        &f.book,
        &[
            "balance",
            "--account",
            "1000",
            "--unit",
            "USD",
            "--as-of",
            "2026-03-15",
        ],
    );
    let balance = fa_verify::verify_balance(&bytes(&filtered), &new)
        .expect("independent exact balance recomputation");
    assert_eq!(balance.claim.account, account_vid(BOOK_ID, "1000").0);
    assert_eq!(
        balance.claim.unit,
        fa_money::UnitRegistry::embedded()
            .unwrap()
            .lookup("USD")
            .unwrap()
            .0
    );
    assert_eq!(
        balance.claim.effective_through,
        Some(fa_time::DateDay::parse("2026-03-15").unwrap().0)
    );
    assert_eq!((balance.claim.debits, balance.claim.credits), (1234, 0));
    assert_eq!(balance.contributing.len(), 1);
    let all_days = exported(&f.book, &["balance", "--account", "1000", "--unit", "USD"]);
    let all_days = fa_verify::verify_balance(&bytes(&all_days), &new).expect("all effective days");
    assert_eq!(all_days.claim.effective_through, None);
    assert_eq!((all_days.claim.debits, all_days.claim.credits), (1434, 0));
    assert_eq!(all_days.contributing.len(), 2);

    assert!(
        fa_verify::verify_prefix(&bytes(&prefix), &old).is_err(),
        "another recorded root is not silently trusted"
    );
    let mut damaged = bytes(&disclosed);
    *damaged.last_mut().expect("nonempty inclusion") ^= 1;
    assert!(fa_verify::verify_inclusion(&damaged, &new).is_err());
    assert_eq!(
        f.head(),
        before,
        "export creates no checkpoint, journal entry, or other write"
    );
}

#[test]
fn missing_unknown_and_empty_checkpoints_have_distinct_read_only_outcomes() {
    let f = Fixture::new();
    let before = f.head();
    let absent_output = f.dir.join("absent-checkpoint.bin");
    let (code, missing) = run(
        &f.book,
        &[
            "proof",
            "checkpoint",
            "--out",
            absent_output.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 2, "{}", missing.render());
    assert_eq!(
        text(&missing, "refusal_id"),
        fa::proof::code::PROOF_STATE_UNKNOWN
    );
    assert!(!absent_output.exists());
    assert_eq!(f.head(), before);

    let recorded = f.checkpoint();
    let before = f.head();
    let empty = exported(&f.book, &["checkpoint"]);
    let checkpoint = Checkpoint::decode(&bytes(&empty)).expect("empty checkpoint");
    assert_eq!(checkpoint.leaf_count, 0);
    assert_eq!(text(&empty, "state_oid"), text(&recorded, "oid"));
    let prefix = exported(&f.book, &["prefix"]);
    assert!(
        fa_verify::verify_prefix(&bytes(&prefix), &checkpoint)
            .expect("empty complete prefix")
            .envelopes
            .is_empty()
    );

    for args in [
        vec!["proof", "checkpoint", "--state", UNKNOWN_STATE],
        vec!["proof", "consistency", "--next-state", UNKNOWN_STATE],
    ] {
        let (code, refusal) = run(&f.book, &args);
        assert_eq!(code, 2, "args={args:?}: {}", refusal.render());
        assert_eq!(
            text(&refusal, "refusal_id"),
            fa::proof::code::PROOF_STATE_UNKNOWN
        );
    }
    let (code, refusal) = run(&f.book, &["proof", "inclusion", "--entry", UNKNOWN_ENTRY]);
    assert_eq!(code, 3, "{}", refusal.render());
    assert_eq!(text(&refusal, "refusal_id"), fa_notary::code::NOT_IN_PREFIX);
    assert_eq!(f.head(), before);
}

#[test]
fn malformed_duplicate_and_inapplicable_proof_flags_refuse_before_book_open() {
    let dir = temp_dir();
    let missing_book = dir.join("not-created");
    let destination = dir.join("must-not-exist.bin");
    let output = destination.to_str().unwrap();
    for args in [
        vec!["proof", "unknown"],
        vec!["proof", "checkpoint", "unexpected"],
        vec!["proof", "checkpoint", "--state", "not-an-oid"],
        vec![
            "proof",
            "checkpoint",
            "--state",
            UNKNOWN_STATE,
            "--state",
            "latest",
        ],
        vec!["proof", "checkpoint", "--entry", UNKNOWN_ENTRY],
        vec!["proof", "checkpoint", "--out", output, "--out", output],
        vec!["proof", "inclusion"],
        vec!["proof", "inclusion", "--entry", "E:short"],
        vec![
            "proof",
            "inclusion",
            "--entry",
            UNKNOWN_ENTRY,
            "--entry",
            UNKNOWN_ENTRY,
        ],
        vec![
            "proof",
            "inclusion",
            "--entry",
            UNKNOWN_ENTRY,
            "--with-record",
            "--with-record",
        ],
        vec![
            "proof",
            "inclusion",
            "--entry",
            UNKNOWN_ENTRY,
            "--account",
            "1000",
        ],
        vec!["proof", "consistency"],
        vec!["proof", "consistency", "--next-state", "latest"],
        vec!["proof", "prefix", "--with-record", "--with-record"],
        vec!["proof", "prefix", "--as-of", "2026-03-15"],
        vec!["proof", "balance", "--account", "1000"],
        vec!["proof", "balance", "--unit", "USD"],
        vec![
            "proof",
            "balance",
            "--account",
            "1000",
            "--unit",
            "USD",
            "--as-of",
            "2026-02-30",
        ],
        vec![
            "proof",
            "balance",
            "--account",
            "1000",
            "--unit",
            "USD",
            "--next-state",
            UNKNOWN_STATE,
        ],
    ] {
        let (code, refusal) = run(&missing_book, &args);
        assert_eq!(code, 2, "args={args:?}: {}", refusal.render());
        assert_eq!(text(&refusal, "class"), "usage");
        assert!(!text(&refusal, "fix").is_empty());
    }
    assert!(!missing_book.exists());
    assert!(!destination.exists());
}

#[test]
fn raw_file_export_is_private_verifiable_and_never_overwrites() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    let posted = f.post("file-sale", "2026-03-10", "12.34", &evidence);
    f.checkpoint();
    let before = f.head();
    let checkpoint_line = exported(&f.book, &["checkpoint"]);
    let checkpoint = Checkpoint::decode(&bytes(&checkpoint_line)).expect("checkpoint");
    let path = f.dir.join("inclusion.proof");
    let args = [
        "inclusion",
        "--entry",
        text(&posted, "vid"),
        "--with-record",
        "--out",
        path.to_str().unwrap(),
    ];
    let exported_line = exported(&f.book, &args);
    assert_eq!(get(&exported_line, "bytes"), &Json::Null);
    assert_eq!(text(&exported_line, "file"), path.to_str().unwrap());
    let raw = std::fs::read(&path).expect("raw exported bytes");
    assert_eq!(raw.len() as i128, integer(&exported_line, "byte_len"));
    assert_eq!(
        fa_verify::verify_inclusion(&raw, &checkpoint)
            .expect("file verifies independently")
            .record,
        RecordCheck::Recomputed
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let mut repeated = vec!["proof"];
    repeated.extend_from_slice(&args);
    let (code, failure) = run(&f.book, &repeated);
    assert_eq!(code, 5, "{}", failure.render());
    assert_eq!(std::fs::read(&path).expect("original retained"), raw);
    assert_eq!(f.head(), before);
}

#[test]
fn false_or_malformed_checkpoint_chains_refuse_export_without_touching_destination() {
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fa_journal::rows::book_root;
    use fa_model::symbols::{label, property, relation};
    use fgdb::{Database, DatabaseKeys, WriteBatch};
    use fgdb_types::CanonicalScalar;
    use fgdb_types::context::PurposeContexts;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    for corrupt_head in [false, true] {
        let f = Fixture::new();
        f.checkpoint();
        let runtime = RuntimeBuilder::new().build().expect("runtime");
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let keys = DatabaseKeys::new(
            [KEY_SEED; 32],
            DatabaseSecurityNamespaceId([KEY_SEED + 1; 32]),
            [KEY_SEED + 2; 32],
        );
        let store = f.book.join("store");
        let mut db = runtime
            .block_on(async { Database::open(&cx.commit(), &store, keys).await })
            .expect("open substrate");
        let prior = fa_notary::latest(&db, None)
            .expect("read prior")
            .expect("checkpoint");
        let mut false_state = prior.state;
        false_state.prev_state_oid = Some(prior.oid);
        false_state.through_seq = db.frontier().expect("frontier");
        false_state.root[0] ^= 1;
        let payload = false_state
            .canonical_bytes()
            .expect("canonical false state");
        let oid = fa_notary::state_oid(&payload);
        let scalar = |bytes| CanonicalScalar::bytes(bytes).expect("bounded scalar");
        let mut props = vec![
            (property::FA_PAYLOAD, scalar(payload)),
            (property::FA_DIGEST, scalar(oid.0.to_vec())),
            (property::BOOK_ID, scalar(BOOK_ID.0.to_vec())),
        ];
        props.sort_by_key(|(key, _)| key.0);
        let mut batch = WriteBatch::new(relation::DERIVED_FROM);
        if !corrupt_head {
            batch.create_vertex(
                fa_notary::state_vid(&oid),
                vec![label::ACCUMULATOR_STATE],
                props,
            );
        }
        batch.set_vertex_property(
            book_root(),
            property::ACCUMULATOR_HEAD,
            Some(scalar(if corrupt_head {
                vec![0xff]
            } else {
                oid.0.to_vec()
            })),
        );
        runtime
            .block_on(async { db.write(&cx.commit(), batch).await })
            .expect("plant tampering");
        drop(db);
        drop(runtime);
        let before = f.head();
        let path = f.dir.join("must-not-export.proof");
        for kind in ["checkpoint", "prefix"] {
            let (code, failure) = run(&f.book, &["proof", kind, "--out", path.to_str().unwrap()]);
            assert_eq!(code, 8, "{}", failure.render());
            assert_eq!(
                text(&failure, "refusal_id"),
                fa_notary::code::ACCUMULATOR_DRIFT
            );
            assert_eq!(text(&failure, "class"), "verification");
            assert!(!path.exists());
        }
        assert_eq!(f.head(), before);
    }
}

fn bound(authority: &LaunchAuthority, args: &[&str]) -> (u8, Json) {
    let argv: Vec<_> = args
        .iter()
        .copied()
        .chain(["--json"])
        .map(str::to_string)
        .collect();
    let (code, out) = fa_with_authority(
        &argv,
        Files {
            cwd: None,
            stdin: Stdin::Forwarded(Vec::new()),
        },
        authority,
        true,
    );
    let line = parse_line(&out.stdout, &out.stderr);
    assert_eq!(line.get("authority"), Some(&authority.envelope_json()));
    (code, line)
}

#[test]
fn a_bound_agent_needs_explicit_read_and_produce_and_cannot_select_a_host_file() {
    let dir = temp_dir();
    let missing_book = dir.join("not-created");
    for grants in [&["read"][..], &["produce"][..], &[][..]] {
        let authority = LaunchAuthority::new(
            missing_book.clone(),
            None,
            "proof-agent",
            LaunchProfile::Agent,
            grants,
        )
        .expect("bounded launch");
        let (code, denial) = bound(&authority, &["proof", "prefix"]);
        assert_eq!(code, 7, "{}", denial.render());
        assert_eq!(
            text(&denial, "refusal_id"),
            fa_policy::denial::code::CAPABILITY
        );
    }
    assert!(
        !missing_book.exists(),
        "authority refusal precedes opening the book"
    );

    let f = Fixture::new();
    f.checkpoint();
    let authority = LaunchAuthority::new(
        f.book.clone(),
        None,
        "proof-agent",
        LaunchProfile::Agent,
        &["read", "produce"],
    )
    .expect("explicit producer authority");
    let before = f.head();
    let (code, checkpoint_line) = bound(&authority, &["proof", "checkpoint"]);
    assert_eq!(code, 0, "{}", checkpoint_line.render());
    let checkpoint = Checkpoint::decode(&bytes(&checkpoint_line)).expect("bound checkpoint");
    let (code, prefix) = bound(&authority, &["proof", "prefix"]);
    assert_eq!(code, 0, "{}", prefix.render());
    fa_verify::verify_prefix(&bytes(&prefix), &checkpoint)
        .expect("agent read and produce is lawful on trunk");
    let destination = f.dir.join("forbidden-host-path.proof");
    let (code, refusal) = bound(
        &authority,
        &["proof", "prefix", "--out", destination.to_str().unwrap()],
    );
    assert_eq!(code, 2, "{}", refusal.render());
    assert_eq!(text(&refusal, "class"), "usage");
    assert!(!destination.exists());
    assert_eq!(f.head(), before);
}

#[test]
fn facade_expiry_and_revocation_refuse_before_observing_requested_checkpoint() {
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fgdb::{Database, DatabaseKeys};
    use fgdb_types::context::PurposeContexts;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    let f = Fixture::new();
    f.checkpoint();
    let holder = principal_vid("outside-auditor");
    let capability = Capability::embedded(holder, &["read", "produce"]).expect("producer");
    let unknown = fa::ProofRequest {
        state: Some(Oid([0xff; 32])),
        kind: fa::ProofKind::Prefix,
    };
    let book = f.open();
    let before = book.head().expect("head");
    let expired = capability.clone().expiring_at(before);
    let refusal = book
        .export_proof(holder, &expired, unknown)
        .expect("read result")
        .expect_err("expired");
    assert_eq!(refusal.code, fa_policy::denial::code::EXPIRED);
    assert_eq!(refusal.exit, 7);
    let wrong_holder = book
        .export_proof(principal_vid("another-principal"), &capability, unknown)
        .expect("read result")
        .expect_err("holder mismatch");
    assert_eq!(wrong_holder.code, fa_policy::denial::code::CAPABILITY);
    let context = book.context().clone();
    let description = book
        .seal_text("Withdraw proof export authority.")
        .expect("sealed reason");
    assert_eq!(book.head().unwrap(), before);
    drop(book);

    let runtime = RuntimeBuilder::new().build().expect("runtime");
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let keys = DatabaseKeys::new(
        [KEY_SEED; 32],
        DatabaseSecurityNamespaceId([KEY_SEED + 1; 32]),
        [KEY_SEED + 2; 32],
    );
    let store = f.book.join("store");
    let mut db = runtime
        .block_on(async { Database::open(&cx.commit(), &store, keys).await })
        .expect("open substrate");
    let revoker = principal_vid("owner");
    runtime
        .block_on(fa_journal::policy::revoke_capability(
            &mut db,
            &cx,
            &context,
            fa_journal::policy::RevocationRequest {
                capability: Capability::embedded(revoker, &["issue_capability"]).expect("revoker"),
                revoked: capability.commitment().expect("commitment"),
                effective_date: fa_time::DateDay::parse("2026-03-22").expect("date"),
                idempotency_key: b"revoke-proof-auditor".to_vec(),
                description,
            },
        ))
        .expect("journal write")
        .expect("revocation admitted");
    drop(db);
    drop(runtime);

    let book = f.open();
    let after_revocation = book.head().expect("revocation frontier");
    let refusal = book
        .export_proof(holder, &capability, unknown)
        .expect("read result")
        .expect_err("revoked");
    assert_eq!(refusal.code, fa_policy::denial::code::REVOKED);
    assert_eq!(refusal.exit, 7);
    assert_eq!(book.head().unwrap(), after_revocation);
}

/// Plan §13.1 (fa-2q91): `fa export ads --with-proofs` writes the auditor's
/// extract at exactly a recorded state's sequence, beside that state's
/// complete-prefix bundle and receipt. `fa_verify::ads` proves offline that
/// GL_Detail is exactly the proven entries the export selects; an entry
/// taken out, an amount altered or a row added fails.
#[test]
fn an_ads_extract_with_proofs_is_exactly_its_proven_selection_offline() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    let export = |name: &str| -> (PathBuf, Vec<String>) {
        let dir = f.dir.join(name);
        let args = [
            "export",
            "ads",
            "--period",
            "FY2026-P03",
            "--out",
            dir.to_str().unwrap(),
            "--with-proofs",
        ]
        .map(str::to_string)
        .to_vec();
        (dir, args)
    };
    fn strs(args: &[String]) -> Vec<&str> {
        args.iter().map(String::as_str).collect()
    }
    let (_, early) = export("early");
    let (code, refusal) = run(&f.book, &strs(&early));
    assert_eq!(code, 2, "{}", refusal.render());
    assert_eq!(text(&refusal, "refusal_id"), "FA-REF-145", "no state yet");
    // --with-proofs proves an ADS package written to a directory, at the
    // state's own sequence.
    let (code, _) = run(
        &f.book,
        &["export", "saft", "--period", "FY2026-P03", "--with-proofs"],
    );
    assert_eq!(code, 2);

    f.post("ads-1", "2026-03-10", "12.34", &evidence);
    f.post("ads-2", "2026-03-20", "2.00", &evidence);
    f.checkpoint();
    // Recorded after the state: not in the extract.
    f.post("ads-3", "2026-03-25", "5.00", &evidence);
    let (dir, args) = export("ads");
    let line = ok(&f.book, &strs(&args));
    let proof = get(&line, "proof");
    assert_eq!(integer(&line, "known_at"), integer(proof, "through_seq"));
    assert_eq!(
        integer(&line, "entries"),
        2,
        "the later posting is not in it"
    );
    assert_eq!(text(proof, "completeness"), "seq_range_complete");
    let key: [u8; 32] = unhex(text(proof, "checkpoint_public_key"))
        .try_into()
        .expect("32-byte key");
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).expect(name);
    let certificate = read("ADS_Coordinate_Certificate.toml");
    let bundle = std::fs::read(dir.join("ADS_Proof.fab")).expect("bundle");
    let receipt = std::fs::read(dir.join("ADS_Proof.receipt")).expect("receipt");
    let tb = read("Trial_Balance.txt");
    let verify_with = |gl: &str, tb: &str| {
        fa_verify::ads::verify_ads(&certificate, gl, tb, &bundle, &[key], Some(&receipt))
            .expect("a well-formed bundle")
    };
    let verify = |gl: &str| verify_with(gl, &tb);
    let gl = read("GL_Detail.txt");
    let report = verify(&gl);
    assert!(report.verified(), "{:?}", report.failures);
    assert_eq!((report.entries, report.rows), (2, 4));
    // The trial balance is the refold of the two proven entries, and so is
    // proven too; an altered balance is not.
    assert_eq!(report.tb_rows, 2);
    assert!(tb.contains("1000|2026-03-31|D|14.34|USD|2\n"), "{tb}");
    assert!(tb.contains("4000|2026-03-31|C|14.34|USD|2\n"), "{tb}");
    let altered = verify_with(&gl, &tb.replace("C|14.34", "C|14.35"));
    assert!(!altered.verified());
    assert!(
        altered
            .failures
            .iter()
            .any(|f| f.contains("is not the refold")),
        "{:?}",
        altered.failures
    );
    let usd = fa_money::UnitRegistry::embedded()
        .unwrap()
        .lookup("USD")
        .unwrap();
    assert_eq!(report.units, vec![("USD".to_string(), usd.0)]);
    // The verifier derives account vids exactly as the book does.
    assert_eq!(
        fa_verify::ads::account_vid(&BOOK_ID.0, "1000"),
        account_vid(BOOK_ID, "1000").0
    );

    // Planted: the first entry's rows taken out; an amount altered; a row
    // added under another Journal_ID.
    let rows: Vec<&str> = gl.lines().collect();
    let first = rows[1].split('|').next().unwrap();
    let without: String = rows
        .iter()
        .filter(|row| !row.starts_with(&format!("{first}|")))
        .map(|row| format!("{row}\n"))
        .collect();
    let missing = verify(&without);
    assert!(!missing.verified());
    assert!(
        missing
            .failures
            .iter()
            .any(|f| f.contains("missing from GL_Detail")),
        "{:?}",
        missing.failures
    );
    // One row deleted: its entry keeps line 1 only, which no proven entry is.
    assert!(rows[2].starts_with(&format!("{first}|2|")), "{gl}");
    let one_row_less: String = rows
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, row)| format!("{row}\n"))
        .collect();
    let short = verify(&one_row_less);
    assert!(!short.verified());
    assert!(
        short
            .failures
            .iter()
            .any(|f| f.contains("missing from GL_Detail")),
        "{:?}",
        short.failures
    );
    assert!(!verify(&gl.replacen("12.34", "12.35", 1)).verified());
    let extra = format!(
        "{gl}{}\n",
        rows[1].replacen(first, "00000000000000000000000000000000", 1)
    );
    let added = verify(&extra);
    assert!(!added.verified());
    assert!(
        added
            .failures
            .iter()
            .any(|f| f.contains("is no proven entry")),
        "{:?}",
        added.failures
    );

    // `fa-verify ads <dir>` reads the package by its names: exit 0 on the
    // export as written, 8 when GL_Detail is altered, 2 with no key.
    let cli = |gl_detail: &str, with_key: bool| {
        let mut args = vec![
            "ads".to_string(),
            dir.to_str().unwrap().to_string(),
            "--json".to_string(),
        ];
        if with_key {
            args.extend([
                "--key".to_string(),
                text(proof, "checkpoint_public_key").to_string(),
            ]);
        }
        let read = |path: &str| {
            if path.ends_with("/GL_Detail.txt") {
                Ok(gl_detail.as_bytes().to_vec())
            } else {
                std::fs::read(path)
            }
        };
        fa_verify::cli::run(&args, &read)
    };
    let verified = cli(&gl, true);
    assert_eq!(verified.exit, 0, "{}{}", verified.stdout, verified.stderr);
    let report = json::parse(verified.stdout.trim()).expect("one JSON report");
    assert_eq!(text(&report, "verdict"), "verified");
    let Json::Arr(checks) = get(&report, "checks") else {
        panic!("checks: {}", verified.stdout);
    };
    let extract = checks
        .iter()
        .find(|check| text(check, "check") == "ads_extract")
        .expect("the extract is a named check");
    assert_eq!(text(extract, "result"), "pass");
    assert_eq!(integer(get(extract, "detail"), "entries"), 2);
    assert_eq!(cli(&without, true).exit, 8);
    assert_eq!(cli(&gl, false).exit, 2);
}
