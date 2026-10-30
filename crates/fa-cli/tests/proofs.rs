//! Persisted producer artifacts checked by the independent outsider verifier.
//! Every CLI invocation opens the book anew. Bound proof exports publish only
//! their AccessEvents; the retained proof and ledger remain unchanged.

#![forbid(unsafe_code)]

#[path = "proofs/aging.rs"]
mod aging;
#[path = "proofs/cash_flow.rs"]
mod cash_flow;
#[path = "proofs/dimension_report.rs"]
mod dimension_report;
#[path = "proofs/explanation_report.rs"]
mod explanation_report;
#[path = "proofs/indirect_cash_flow_basis.rs"]
mod indirect_cash_flow_basis;
#[path = "proofs/prefix.rs"]
mod prefix;
#[path = "proofs/report.rs"]
mod report;
#[path = "proofs/roll_forward.rs"]
mod roll_forward;
#[path = "proofs/statement_diff.rs"]
mod statement_diff;
#[path = "proofs/summary.rs"]
mod summary;

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

    fn assert_proof_accesses_since(&self, before: u64, principal: &str, count: usize) {
        let book = self.open();
        let events = book.access_log(fgdb_types::CommitSeq(before)).unwrap();
        assert_eq!(events.len(), count, "one receipt per bound export");
        for (index, event) in events.iter().enumerate() {
            let observed = before + u64::try_from(index).unwrap();
            assert_eq!(event.record.principal_name, principal);
            assert_eq!(event.record.command, "bundle produce");
            assert_eq!(event.observed_at.0, observed);
            assert_eq!(event.recorded_at.0, observed + 1);
        }
        assert_eq!(
            book.head().unwrap().0,
            before + u64::try_from(count).unwrap(),
            "proof export publishes only its audit receipt, no accounting or certificate changes"
        );
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

/// Recompute a cross-year PPA from a retained report bundle without opening
/// the book, then refuse the same signed bundle when its PPA payload is absent.
#[test]
fn equity_roll_forward_prior_period_line_verifies_offline() {
    let fixture = Fixture::new();
    let invoke = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fa"))
            .arg("--book")
            .arg(&fixture.book)
            .args(args)
            .arg("--json")
            .env_remove("FA_BOOK")
            .output()
            .expect("run the retained PPA proof workflow");
        let exit = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!(
            "PPA proof argv=fa --book {:?} {args:?} --json exit={exit}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            fixture.book,
        );
        assert_eq!(exit, 0, "PPA proof step: {args:?}");
        let registry = fa_cli::verbs::registry().unwrap();
        stdout
            .lines()
            .map(|line| {
                registry.check_line(line).unwrap();
                json::parse(line).unwrap()
            })
            .collect::<Vec<_>>()
    };
    let chart = write(
        &fixture.dir,
        "ppa-chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"3000","name":"Retained earnings","type":"Equity","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    );
    invoke(&["chart", "import", &chart]);
    invoke(&["chart", "role", "3000", "retained_earnings"]);
    for year in ["2025", "2026"] {
        invoke(&["period", "create", "--fiscal-year", year]);
    }
    for period in ["FY2025-P12", "FY2026-P01"] {
        invoke(&["period", "open", period]);
    }
    let source = write(
        &fixture.dir,
        "ppa-source.txt",
        "Fixture bank advice: a December 2025 receipt was omitted.",
    );
    let document = invoke(&[
        "document",
        "add",
        &source,
        "--kind",
        "Receipt",
        "--grade",
        "HumanUpload",
    ]);
    let evidence = text(&document[0], "oid");
    let opening = write(
        &fixture.dir,
        "ppa-opening.json",
        r#"{"idempotency_key":"2025-capital","effective_date":"2025-12-01","legs":[{"side":"debit","account":"1000","amount":"100.00 USD"},{"side":"credit","account":"3000","amount":"100.00 USD"}]}"#,
    );
    invoke(&["post", "--intent", &opening, "--evidence", evidence]);
    invoke(&["period", "soft-close", "FY2025-P12"]);
    invoke(&[
        "period",
        "close",
        "FY2025-P12",
        "--reason",
        "Scheduled",
        "--yes",
    ]);
    invoke(&[
        "case",
        "open",
        "--kind",
        "PriorPeriodAdjustment",
        "--periods",
        "FY2025-P12",
        "--determined-on",
        "2026-01-02",
        "--authority",
        evidence,
    ]);
    invoke(&["scenario", "fork", "adjusted", "--as", "analyst"]);
    let intent = write(
        &fixture.dir,
        "ppa-adjustment.json",
        &format!(
            r#"{{"idempotency_key":"cross-year-ppa","effective_date":"2026-01-02","relates_to":"FY2025-P12","evidence":["{evidence}"],"legs":[{{"side":"debit","account":"1000","amount":"50.00 USD"}},{{"side":"credit","account":"3000","amount":"50.00 USD"}}]}}"#
        ),
    );
    invoke(&[
        "scenario", "run", "adjusted", "--intent", &intent, "--as", "analyst",
    ]);
    let diff = fixture.dir.join("ppa.diff");
    invoke(&[
        "scenario",
        "diff",
        "adjusted",
        "--period",
        "FY2025-P12",
        "--period",
        "FY2026-P01",
        "--certificate-out",
        diff.to_str().unwrap(),
    ]);
    invoke(&[
        "case",
        "rehearse",
        "1",
        "--certificate",
        diff.to_str().unwrap(),
    ]);
    let plan = invoke(&["case", "approve", "1", "--dry-run"]);
    let digest = text(&plan[0], "digest");
    let mut approvals = Vec::new();
    for principal in ["controller", "auditor"] {
        let approved = invoke(&["approve", "--proposal", digest, "--as", principal]);
        approvals.push(text(&approved[0], "approval_vid").to_string());
    }
    invoke(&[
        "case",
        "approve",
        "1",
        "--approval",
        &approvals[0],
        "--approval",
        &approvals[1],
    ]);
    let posted = invoke(&["case", "post", "1", "--yes"]);
    let posted_entries = get(get(&posted[0], "case"), "posted").as_arr().unwrap();
    assert_eq!(posted_entries.len(), 1);
    let adjustment_digest: [u8; 32] = unhex(text(&posted_entries[0], "entry_digest"))
        .try_into()
        .unwrap();

    let certificate_path = fixture.dir.join("ppa-equity.cert");
    let certified = invoke(&[
        "statement",
        "equity-roll-forward",
        "--from",
        "2026-01-01",
        "--to",
        "2026-12-31",
        "--unit",
        "USD",
        "--label",
        "FY2026 correction",
        "--certificate-out",
        certificate_path.to_str().unwrap(),
    ]);
    let metadata = certified
        .iter()
        .find(|event| text(event, "event") == "report_certificate")
        .unwrap();
    let encoded = bytes(metadata);
    assert_eq!(std::fs::read(&certificate_path).unwrap(), encoded);
    let artifact = fa::ReportArtifact::decode(&encoded).unwrap();
    let state = fixture.checkpoint();
    let produced = invoke(&[
        "bundle",
        "produce",
        "--certificate",
        certificate_path.to_str().unwrap(),
        "--state",
        text(&state, "oid"),
    ]);
    let bundle = bytes(&produced[0]);
    let receipt = unhex(text(&produced[0], "receipt"));
    let key = fixture.open().checkpoint_public_key();
    let verified = fa_verify::report::verify_report_expected(
        &bundle,
        &[key],
        None,
        Some(&receipt),
        Some(artifact.digest()),
    )
    .expect("the independent verifier recomputes the cross-year PPA");
    assert_eq!(verified.output, artifact.output());
    let equity = verified.equity_roll_forward.unwrap();
    assert_eq!(equity.units.len(), 1);
    let unit = &equity.units[0];
    assert_eq!(unit.opening_total_equity, 10_000);
    assert_eq!(unit.prior_period_adjustments, 5_000);
    assert_eq!(unit.opening_equity_as_adjusted, 15_000);
    assert_eq!(unit.closing_total_equity, 15_000);
    assert_eq!(unit.net_income, 0);
    assert_eq!(equity.movements.len(), 1);
    assert_eq!(equity.movements[0].case_ordinal, Some(1));
    assert_eq!(
        equity.movements[0].relates_to.as_ref().unwrap().1,
        "FY2025-P12"
    );

    // The same independently selected certificate authenticates inputs even
    // without a receipt. The negative below therefore tests omitted payloads,
    // not an intentionally mismatched detached receipt.
    fa_verify::report::verify_report_expected(&bundle, &[key], None, None, Some(artifact.digest()))
        .expect("positive control under the negative's exact recipient authority");
    let mut reader = fa_model::Reader::new(&bundle);
    reader.bytes(64, "report format").unwrap();
    assert_eq!(reader.u16("major").unwrap(), 2);
    assert_eq!(reader.u16("minor").unwrap(), 0);
    for field in ["certificate", "signed checkpoint", "prefix proof"] {
        reader.bytes(64 * 1024 * 1024, field).unwrap();
    }
    let count_at = reader.offset();
    let count = reader.u32("record count").unwrap();
    let mut omitted = None;
    for _ in 0..count {
        let start = reader.offset();
        reader.u32("proposal length").unwrap();
        let payload = reader.bytes(64 * 1024 * 1024, "record").unwrap();
        if let Ok(entry) = fa_model::Entry::decode(payload)
            && entry.entry_digest == adjustment_digest
        {
            assert_eq!(
                entry.proposal.class,
                fa_model::EntryClass::PRIOR_PERIOD_ADJUSTMENT
            );
            assert_eq!(
                entry.proposal.effective_date,
                fa_time::DateDay::parse("2026-01-02").unwrap()
            );
            assert_eq!(entry.proposal.legs.len(), 2);
            assert!(
                entry
                    .proposal
                    .legs
                    .iter()
                    .all(|leg| leg.amount.mantissa == 5_000)
            );
            assert!(omitted.replace((start, reader.offset())).is_none());
        }
    }
    let (start, end) = omitted.expect("locate the actual PPA entry, not a reference to it");
    let mut missing = bundle[..start].to_vec();
    missing.extend_from_slice(&bundle[end..]);
    missing[count_at..count_at + 4].copy_from_slice(&(count - 1).to_le_bytes());
    let refusal = fa_verify::report::verify_report_expected(
        &missing,
        &[key],
        None,
        None,
        Some(artifact.digest()),
    )
    .unwrap_err();
    assert_eq!(refusal.predicate, "record_completeness");

    let expected = fa_verify::blake3::hex(artifact.digest());
    let public_key = fa_verify::blake3::hex(&key);
    for (input, bytes, expected_exit) in [("ppa.fab", &bundle, 0), ("omitted-ppa.fab", &missing, 8)]
    {
        let args = [
            "report",
            input,
            "--key",
            &public_key,
            "--expect",
            &expected,
            "--json",
        ]
        .map(str::to_string);
        let read = |name: &str| {
            assert_eq!(name, input, "verification has no path to the live book");
            Ok(bytes.clone())
        };
        let result = fa_verify::cli::run(&args, &read);
        eprintln!(
            "PPA offline argv={args:?} exit={}\nstdout:\n{}\nstderr:\n{}",
            result.exit, result.stdout, result.stderr
        );
        assert_eq!(
            result.exit, expected_exit,
            "{}{}",
            result.stdout, result.stderr
        );
        if expected_exit == 8 {
            assert!(
                result.stdout.contains("record_completeness"),
                "{}",
                result.stdout
            );
        }
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
    // fa-7dw: each bound proof read records its access receipt before it
    // observes; the host path is refused before the book is opened, so the
    // receipts are the only publication.
    let book = f.open();
    let events = book.access_log(fgdb_types::CommitSeq(before)).unwrap();
    let commands: Vec<&str> = events
        .iter()
        .map(|event| {
            assert_eq!(event.record.principal_name, "proof-agent");
            event.record.command.as_str()
        })
        .collect();
    assert_eq!(commands, ["proof checkpoint", "proof prefix"]);
    assert_eq!(book.head().unwrap().0, before + 2);
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
    let chart = read("Chart_of_Accounts.txt");
    let verify_package = |chart: &str, gl: &str, tb: &str| {
        fa_verify::ads::verify_ads(&certificate, chart, gl, tb, &bundle, &[key], Some(&receipt))
            .expect("a well-formed bundle")
    };
    let verify_with = |gl: &str, tb: &str| verify_package(&chart, gl, tb);
    let verify = |gl: &str| verify_with(gl, &tb);
    let gl = read("GL_Detail.txt");
    let report = verify(&gl);
    assert!(report.verified(), "{:?}", report.failures);
    assert_eq!((report.entries, report.rows), (2, 4));
    // The chart is exactly the one the proven entries declare: the code,
    // name, type and normal balance of each account.
    assert_eq!(report.chart_rows, Some(2), "{chart}");
    assert!(chart.contains("1000|Cash|Asset|D\n"), "{chart}");
    for bad in [
        chart.replace("|Cash|", "|Petty cash|"),
        chart.replace("Cash|Asset", "Cash|Expense"),
        format!("{chart}9999|Suspense|Asset|D\n"),
    ] {
        let judged = verify_package(&bad, &gl, &tb);
        assert!(!judged.verified(), "{bad}");
        assert!(
            judged
                .failures
                .iter()
                .any(|f| f.contains("Chart_of_Accounts")),
            "{:?}",
            judged.failures
        );
    }
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

/// Plan §13.1 (fa-2q91): one account's month, `fa export ads --account 1000
/// --period FY2026-P03 --with-proofs`, is proven by that account's scope
/// index (ScopeIndexComplete) over every effective day through the cutoff.
/// GL_Detail is exactly the proven entries with a Cash leg, each whole;
/// Trial_Balance is Cash's own refold. An entry without a Cash leg, a
/// missing entry, an altered balance, a stripped scope or another
/// account's scope fails offline.
#[test]
fn an_account_month_ads_extract_is_proven_by_its_scope_index_offline() {
    let f = Fixture::new();
    let chart = write(
        &f.dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"2000","name":"Payables","type":"Liability","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},{"code":"6000","name":"Expense","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&f.book, &["chart", "import", &chart]);
    ok(&f.book, &["period", "create", "--fiscal-year", "2026"]);
    ok(&f.book, &["period", "open", "FY2026-P03"]);
    let source = write(
        &f.dir,
        "receipt.txt",
        "Account-month proof fixture receipts.",
    );
    let evidence = text(
        &ok(
            &f.book,
            &[
                "document",
                "add",
                &source,
                "--kind",
                "Receipt",
                "--grade",
                "HumanUpload",
            ],
        ),
        "oid",
    )
    .to_string();
    let post = |key: &str, date: &str, debit: &str, credit: &str, amount: &str| {
        let intent = write(
            &f.dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount} USD"}},{{"side":"credit","account":"{credit}","amount":"{amount} USD"}}]}}"#
            ),
        );
        ok(
            &f.book,
            &["post", "--intent", &intent, "--evidence", &evidence],
        );
    };
    post("sale-1", "2026-03-05", "1000", "4000", "12.34");
    // No Cash leg: outside the account's extract.
    post("bill-1", "2026-03-08", "6000", "2000", "3.00");
    post("pay-1", "2026-03-12", "2000", "1000", "3.00");
    f.checkpoint();
    // Recorded after the state: in neither extract.
    post("sale-2", "2026-03-20", "1000", "4000", "5.00");

    let export = |name: &str, account: Option<&str>| -> (PathBuf, Json) {
        let dir = f.dir.join(name);
        let mut args = vec!["export", "ads"];
        if let Some(code) = account {
            args.extend(["--account", code]);
        }
        args.extend([
            "--period",
            "FY2026-P03",
            "--out",
            dir.to_str().unwrap(),
            "--with-proofs",
        ]);
        let line = ok(&f.book, &args);
        (dir, line)
    };
    let (dir, line) = export("cash", Some("1000"));
    let (whole, whole_line) = export("whole", None);
    assert_eq!(text(&line, "account_scope"), "1000");
    assert_eq!(get(&whole_line, "account_scope"), &Json::Null);
    let proof = get(&line, "proof");
    assert_eq!(text(proof, "completeness"), "scope_index_complete");
    assert_eq!(integer(&line, "known_at"), integer(proof, "through_seq"));
    assert_eq!(integer(&line, "entries"), 2, "sale-1 and pay-1");
    assert_eq!(integer(&whole_line, "entries"), 3);
    let key: [u8; 32] = unhex(text(proof, "checkpoint_public_key"))
        .try_into()
        .expect("32-byte key");
    let read = |dir: &Path, name: &str| std::fs::read_to_string(dir.join(name)).expect(name);
    let certificate = read(&dir, "ADS_Coordinate_Certificate.toml");
    assert!(
        certificate.ends_with("account_scope = \"1000\"\n"),
        "{certificate}"
    );
    let bundle = std::fs::read(dir.join("ADS_Proof.fab")).expect("bundle");
    let receipt = std::fs::read(dir.join("ADS_Proof.receipt")).expect("receipt");
    let gl = read(&dir, "GL_Detail.txt");
    let tb = read(&dir, "Trial_Balance.txt");
    let chart = read(&dir, "Chart_of_Accounts.txt");
    let verify_as = |certificate: &str, gl: &str, tb: &str| {
        fa_verify::ads::verify_ads(certificate, &chart, gl, tb, &bundle, &[key], Some(&receipt))
            .expect("a well-formed bundle")
    };
    let verify_with = |gl: &str, tb: &str| verify_as(&certificate, gl, tb);
    let report = verify_with(&gl, &tb);
    assert!(report.verified(), "{:?}", report.failures);
    assert_eq!(report.account_scope.as_deref(), Some("1000"));
    assert_eq!((report.entries, report.rows), (2, 4));
    // One account's run carries no chart declaration: its chart is not
    // judged, and the report says so rather than passing it.
    assert_eq!(report.chart_rows, None);
    assert_eq!(
        chart
            .lines()
            .skip(1)
            .map(|row| &row[..4])
            .collect::<Vec<_>>(),
        ["1000", "2000", "4000"],
        "the accounts Cash's entries name: {chart}"
    );
    assert!(!gl.contains("|6000|"), "{gl}");
    // Cash's own balance only: 12.34 in, 3.00 out.
    assert_eq!(report.tb_rows, 1);
    assert_eq!(
        tb.lines().skip(1).collect::<Vec<_>>(),
        ["1000|2026-03-31|D|9.34|USD|2"],
        "{tb}"
    );

    // Planted: bill-1's rows, copied from the whole-chart extract.
    let whole_gl = read(&whole, "GL_Detail.txt");
    let bill: String = whole_gl
        .lines()
        .filter(|row| row.contains("|6000|"))
        .flat_map(|row| {
            let id = row.split('|').next().unwrap();
            whole_gl
                .lines()
                .filter(move |other| other.starts_with(&format!("{id}|")))
        })
        .take(2)
        .map(|row| format!("{row}\n"))
        .collect();
    assert_eq!(bill.lines().count(), 2, "{whole_gl}");
    let smuggled = verify_with(&format!("{gl}{bill}"), &tb);
    assert!(!smuggled.verified());
    assert!(
        smuggled
            .failures
            .iter()
            .any(|f| f.contains("is no proven entry")),
        "{:?}",
        smuggled.failures
    );
    // Planted: pay-1's rows taken out.
    let rows: Vec<&str> = gl.lines().collect();
    let last = rows.last().unwrap().split('|').next().unwrap();
    let without: String = rows
        .iter()
        .filter(|row| !row.starts_with(&format!("{last}|")))
        .map(|row| format!("{row}\n"))
        .collect();
    let missing = verify_with(&without, &tb);
    assert!(
        missing
            .failures
            .iter()
            .any(|f| f.contains("missing from GL_Detail")),
        "{:?}",
        missing.failures
    );
    // Planted: Cash's balance altered.
    let altered = verify_with(&gl, &tb.replace("D|9.34", "D|9.35"));
    assert!(
        altered
            .failures
            .iter()
            .any(|f| f.contains("is not the refold")),
        "{:?}",
        altered.failures
    );
    // Planted: the scope stripped (a whole chart claimed over one
    // account's bundle), and another account's scope.
    let stripped = verify_as(
        &certificate.replace("account_scope = \"1000\"\n", ""),
        &gl,
        &tb,
    );
    assert!(
        stripped
            .failures
            .iter()
            .any(|f| f
                .contains("a whole-chart ADS extract is judged against a complete-prefix bundle")),
        "{:?}",
        stripped.failures
    );
    let other = verify_as(
        &certificate.replace("account_scope = \"1000\"", "account_scope = \"4000\""),
        &gl,
        &tb,
    );
    assert!(
        other
            .failures
            .iter()
            .any(|f| f.contains("account 4000's entries")),
        "{:?}",
        other.failures
    );

    // `fa-verify ads <dir>` names the scope; --account is ADS-only and
    // names a chart account.
    let cli = fa_verify::cli::run(
        &[
            "ads".to_string(),
            dir.to_str().unwrap().to_string(),
            "--json".to_string(),
            "--key".to_string(),
            text(proof, "checkpoint_public_key").to_string(),
        ],
        &|path: &str| std::fs::read(path),
    );
    assert_eq!(cli.exit, 0, "{}{}", cli.stdout, cli.stderr);
    let parsed = json::parse(cli.stdout.trim()).expect("one JSON report");
    let Json::Arr(checks) = get(&parsed, "checks") else {
        panic!("checks: {}", cli.stdout);
    };
    let extract = checks
        .iter()
        .find(|check| text(check, "check") == "ads_extract")
        .expect("the extract is a named check");
    assert_eq!(text(get(extract, "detail"), "account_scope"), "1000");
    let (code, _) = run(
        &f.book,
        &[
            "export",
            "saft",
            "--account",
            "1000",
            "--period",
            "FY2026-P03",
        ],
    );
    assert_eq!(code, 2);
    let unknown = f.dir.join("unknown");
    let (code, refused) = run(
        &f.book,
        &[
            "export",
            "ads",
            "--account",
            "9999",
            "--period",
            "FY2026-P03",
            "--out",
            unknown.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 2, "{}", refused.render());
    assert!(
        !unknown.exists(),
        "nothing is written for an unknown account"
    );
}

/// Plan §13.1 (fa-2q91, scoreboard G3-06): `fa export saft --with-proofs`
/// writes the SAF-T 2.00 extract at exactly a recorded state's sequence,
/// beside that state's complete-prefix bundle and receipt, in a new
/// directory. `fa_verify::saft` reads it without fa-formats and judges it
/// as `fa-verify ads` does: its transactions are exactly the proven entries
/// the export selects, its balance assertions their refold, and its
/// accounts the proven chart. An altered amount, a dropped transaction, an
/// altered assertion, a renamed account or a moved coordinate fails.
#[test]
fn a_saft_extract_with_proofs_is_exactly_its_proven_selection_offline() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    f.post("saft-1", "2026-03-10", "12.34", &evidence);
    f.post("saft-2", "2026-03-20", "2.00", &evidence);
    f.checkpoint();
    // Recorded after the state: not in the extract.
    f.post("saft-3", "2026-03-25", "5.00", &evidence);
    let dir = f.dir.join("saft");
    let line = ok(
        &f.book,
        &[
            "export",
            "saft",
            "--period",
            "FY2026-P03",
            "--out",
            dir.to_str().unwrap(),
            "--with-proofs",
        ],
    );
    let proof = get(&line, "proof");
    assert_eq!(text(proof, "completeness"), "seq_range_complete");
    assert_eq!(text(proof, "bundle"), "SAFT_Proof.fab");
    assert_eq!(integer(&line, "known_at"), integer(proof, "through_seq"));
    assert_eq!(integer(&line, "entries"), 2);
    let key: [u8; 32] = unhex(text(proof, "checkpoint_public_key"))
        .try_into()
        .expect("32-byte key");
    let xml = std::fs::read_to_string(dir.join("SAF-T.xml")).expect("SAF-T.xml");
    let bundle = std::fs::read(dir.join("SAFT_Proof.fab")).expect("bundle");
    let receipt = std::fs::read(dir.join("SAFT_Proof.receipt")).expect("receipt");
    let verify = |xml: &str| {
        fa_verify::saft::verify_saft(xml, &bundle, &[key], Some(&receipt))
            .expect("a well-formed bundle")
    };
    let report = verify(&xml);
    assert!(report.verified(), "{:?}", report.failures);
    assert_eq!((report.entries, report.rows), (2, 4));
    assert_eq!(report.tb_rows, 2);
    assert_eq!(report.chart_rows, Some(2));
    assert_eq!(report.effective_through, "2026-03-31");

    let fails_on = |bad: &str, part: &str| {
        assert_ne!(bad, xml, "the planted edit changed nothing");
        let judged = verify(bad);
        assert!(!judged.verified(), "{bad}");
        assert!(
            judged.failures.iter().any(|f| f.contains(part)),
            "{part}: {:?}",
            judged.failures
        );
    };
    // An amount in the transactions, the first entry's debit.
    fails_on(
        &xml.replacen(
            "<DebitAmount>12.34</DebitAmount>",
            "<DebitAmount>12.35</DebitAmount>",
            1,
        ),
        "is no proven entry",
    );
    // A whole transaction dropped.
    let start = xml.find("    <Transaction>").unwrap();
    let end =
        xml[start..].find("    </Transaction>\n").unwrap() + start + "    </Transaction>\n".len();
    let dropped = format!("{}{}", &xml[..start], &xml[end..]);
    fails_on(&dropped, "missing from GeneralLedgerEntries");
    // A balance assertion.
    fails_on(
        &xml.replacen("<Amount>14.34</Amount>", "<Amount>14.35</Amount>", 1),
        "is not the refold",
    );
    // An account renamed in the master files.
    fails_on(
        &xml.replace(
            "<AccountDescription>Cash</AccountDescription>",
            "<AccountDescription>Petty cash</AccountDescription>",
        ),
        "GeneralLedgerAccounts row",
    );
    // The coordinate moved.
    let seq = integer(proof, "through_seq");
    fails_on(
        &xml.replace(
            &format!("<KnownAtSeq>{seq}</KnownAtSeq>"),
            &format!("<KnownAtSeq>{}</KnownAtSeq>", seq + 1),
        ),
        "known_at_seq",
    );

    // `fa-verify saft <dir>` reads the package by its names: exit 0 as
    // written, 8 when a transaction is dropped, 2 with no key.
    let cli = |xml_text: &str, with_key: bool| {
        let mut args = vec![
            "saft".to_string(),
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
            if path.ends_with("/SAF-T.xml") {
                Ok(xml_text.as_bytes().to_vec())
            } else {
                std::fs::read(path)
            }
        };
        fa_verify::cli::run(&args, &read)
    };
    let verified = cli(&xml, true);
    assert_eq!(verified.exit, 0, "{}{}", verified.stdout, verified.stderr);
    let parsed = json::parse(verified.stdout.trim()).expect("one JSON report");
    let Json::Arr(checks) = get(&parsed, "checks") else {
        panic!("checks: {}", verified.stdout);
    };
    let extract = checks
        .iter()
        .find(|check| text(check, "check") == "saft_extract")
        .expect("the extract is a named check");
    assert_eq!(text(extract, "result"), "pass");
    assert_eq!(cli(&dropped, true).exit, 8);
    assert_eq!(cli(&xml, false).exit, 2);
}

/// fa-mv0f: a migrated book's extracts verify offline. Every demo book holds
/// a finalized MigrationRun. A proved whole-chart extract's bundle carries a
/// migration-aware balance over every chart cell, whose run bodies let
/// fa-verify decide each chunk's visibility. The migration entries are in
/// GL_Detail and proven, in ADS and SAF-T alike. One taken out fails, and
/// the same extract judged against the state's plain prefix bundle (no
/// balances) is refused, naming the visibility it cannot prove.
#[test]
fn a_migrated_books_extracts_verify_offline() {
    let dir = temp_dir();
    let book = dir.join("book");
    let (code, made) = run(
        &book,
        &["demo", "init", "--scenario", "retail", "--seed", "7"],
    );
    assert_eq!(code, 0, "{}", made.render());
    ok(&book, &["checkpoint", "create", "--grant", "witness"]);
    let export = |format: &str| {
        let out = dir.join(format);
        let line = ok(
            &book,
            &[
                "export",
                format,
                "--as-of",
                "2026-12-31",
                "--out",
                out.to_str().unwrap(),
                "--with-proofs",
            ],
        );
        (out, line)
    };
    let (ads, line) = export("ads");
    let proof = get(&line, "proof");
    let key: [u8; 32] = unhex(text(proof, "checkpoint_public_key"))
        .try_into()
        .expect("32-byte key");
    let read = |name: &str| std::fs::read_to_string(ads.join(name)).expect(name);
    let (certificate, chart, gl, tb) = (
        read("ADS_Coordinate_Certificate.toml"),
        read("Chart_of_Accounts.txt"),
        read("GL_Detail.txt"),
        read("Trial_Balance.txt"),
    );
    let receipt = std::fs::read(ads.join("ADS_Proof.receipt")).expect("receipt");
    let verify = |gl: &str, bundle: &[u8], receipt: &[u8]| {
        fa_verify::ads::verify_ads(&certificate, &chart, gl, &tb, bundle, &[key], Some(receipt))
            .expect("a well-formed bundle")
    };
    let bundle = std::fs::read(ads.join("ADS_Proof.fab")).expect("bundle");
    let report = verify(&gl, &bundle, &receipt);
    assert!(report.verified(), "{:?}", report.failures);
    assert!(report.chart_rows.is_some(), "{report:?}");
    // The migration entries (Entry_Class 12) are in the extract, proven.
    let migrated: Vec<&str> = gl
        .lines()
        .skip(1)
        .filter(|row| row.split('|').nth(4) == Some("12"))
        .collect();
    assert!(!migrated.is_empty(), "{gl}");
    let id = migrated[0].split('|').next().unwrap();
    let without: String = gl
        .lines()
        .filter(|row| !row.starts_with(&format!("{id}|")))
        .map(|row| format!("{row}\n"))
        .collect();
    let missing = verify(&without, &bundle, &receipt);
    assert!(
        missing
            .failures
            .iter()
            .any(|f| f.contains("missing from GL_Detail")),
        "{:?}",
        missing.failures
    );
    // The same extract against the state's plain prefix bundle: nothing
    // decides the chunks' visibility, so they are refused, not guessed.
    let plain = dir.join("plain.fab");
    let plain_receipt = dir.join("plain.receipt");
    ok(
        &book,
        &[
            "bundle",
            "produce",
            "--state",
            text(proof, "state"),
            "--out",
            plain.to_str().unwrap(),
            "--receipt-out",
            plain_receipt.to_str().unwrap(),
        ],
    );
    let unproven = verify(
        &gl,
        &std::fs::read(&plain).expect("plain bundle"),
        &std::fs::read(&plain_receipt).expect("plain receipt"),
    );
    assert!(!unproven.verified());
    assert!(
        unproven
            .failures
            .iter()
            .any(|f| f.contains("proves whether its run makes it visible")),
        "{:?}",
        unproven.failures
    );

    // SAF-T of the same book verifies the same way.
    let (saft, saft_line) = export("saft");
    let saft_proof = get(&saft_line, "proof");
    let saft_key: [u8; 32] = unhex(text(saft_proof, "checkpoint_public_key"))
        .try_into()
        .expect("32-byte key");
    let judged = fa_verify::saft::verify_saft(
        &std::fs::read_to_string(saft.join("SAF-T.xml")).expect("SAF-T.xml"),
        &std::fs::read(saft.join("SAFT_Proof.fab")).expect("bundle"),
        &[saft_key],
        Some(&std::fs::read(saft.join("SAFT_Proof.receipt")).expect("receipt")),
    )
    .expect("a well-formed bundle");
    assert!(judged.verified(), "{:?}", judged.failures);
    assert_eq!(judged.entries, report.entries);
}

#[test]
fn ads_text_survives_real_post_export_reimport_and_offline_verification() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    let description = "line one\nline two\rpipe | slash \\ tab\t café";
    let memo = "memo | with\nnew line and literal \\n";
    let intent = format!(
        "{{\"effective_date\":\"2026-03-10\",\"description\":{},\"idempotency_key\":\"ads-text\",\"legs\":[{{\"side\":\"debit\",\"account\":\"1000\",\"amount\":\"12.34 USD\",\"memo\":{}}},{{\"side\":\"credit\",\"account\":\"4000\",\"amount\":\"12.34 USD\"}}]}}",
        Json::Str(description.into()).render(),
        Json::Str(memo.into()).render(),
    );
    let path = write(&f.dir, "ads-text.json", &intent);
    ok(
        &f.book,
        &["post", "--intent", &path, "--evidence", &evidence],
    );
    f.checkpoint();
    let dir = f.dir.join("escaped-ads");
    let export = ok(
        &f.book,
        &[
            "export",
            "ads",
            "--period",
            "FY2026-P03",
            "--out",
            dir.to_str().unwrap(),
            "--with-proofs",
        ],
    );
    let key = text(get(&export, "proof"), "checkpoint_public_key");
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();
    let package = fa_formats::ads::AdsPackage {
        chart_of_accounts: read("Chart_of_Accounts.txt"),
        gl_detail: read("GL_Detail.txt"),
        trial_balance: read("Trial_Balance.txt"),
        certificate_toml: read("ADS_Coordinate_Certificate.toml"),
    };
    assert!(package.certificate_toml.contains("aicpa_ads_gl_v3"));
    assert_eq!(
        package.gl_detail.lines().count(),
        3,
        "two legs, no split text rows"
    );
    let restored =
        fa_formats::ads::read_ads_package(&package, &fa_formats::UnitCatalog::embedded().unwrap())
            .unwrap();
    assert_eq!(restored.entries[0].description, description);
    assert_eq!(restored.entries[0].legs[0].memo.as_deref(), Some(memo));
    assert_eq!(
        fa_formats::hex_encode(&restored.coordinate.content_digest),
        text(&export, "content_digest")
    );
    let args = vec![
        "ads".into(),
        dir.to_str().unwrap().into(),
        "--key".into(),
        key.into(),
        "--json".into(),
    ];
    let verified = fa_verify::cli::run(&args, &|path| std::fs::read(path));
    assert_eq!(verified.exit, 0, "{}{}", verified.stdout, verified.stderr);
    // A bad escape is a format failure even in an unauthenticated text field.
    let corrupt = package.gl_detail.replacen("\\p", "\\q", 1);
    let rejected = fa_verify::cli::run(&args, &|path| {
        if Path::new(path)
            .file_name()
            .is_some_and(|name| name == "GL_Detail.txt")
        {
            Ok(corrupt.as_bytes().to_vec())
        } else {
            std::fs::read(path)
        }
    });
    assert_eq!(rejected.exit, 8, "{}{}", rejected.stdout, rejected.stderr);
}

/// fa-qtfd (plan §13.5): a witness cosigns a recorded checkpoint with its
/// own key, a second witness adds its signature onto the first's, and
/// fa-verify meets a quorum of two named witnesses but not three. A witness
/// extends only the history it signed: the next state is cosigned with
/// --previous, while a rollback, another key's previous file, a key file
/// readable by others and a rewritten history under the same book key (a
/// second book with the same identity whose posting differs) are refused
/// and write nothing.
#[test]
fn witnesses_cosign_an_extending_history_and_refuse_a_rewritten_one() {
    use std::os::unix::fs::PermissionsExt;

    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    f.post("w-1", "2026-03-10", "5.00", &evidence);
    let created = f.checkpoint();
    let book_key = text(&created, "public_key").to_string();
    let path = |name: &str| f.dir.join(name).display().to_string();
    let witness_key = |name: &str| {
        let made = ok(
            &f.book,
            &["checkpoint", "witness-key", "--out", &path(name)],
        );
        let mode = std::fs::metadata(path(name)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a witness key is a 0600 file");
        (path(name), text(&made, "public_key").to_string())
    };
    let (alice, alice_pk) = witness_key("alice.key");
    let (bob, bob_pk) = witness_key("bob.key");
    let (_, carol_pk) = witness_key("carol.key");
    let witness = |book: &Path, args: &[&str]| {
        run(
            book,
            &[&["checkpoint", "witness", "--grant", "witness"][..], args].concat(),
        )
    };
    let (code, first) = witness(&f.book, &["--key", &alice, "--out", &path("a1.cp")]);
    assert_eq!(code, 0, "{}", first.render());
    assert_eq!(text(&first, "claim"), "witnessed_detection");
    assert_eq!(text(&first, "state_oid"), text(&created, "oid"));
    assert_eq!(get(&first, "extends"), &Json::Null);
    assert_eq!(text(&first, "book_public_key"), book_key);
    let (code, both) = witness(
        &f.book,
        &[
            "--key",
            &bob,
            "--onto",
            &path("a1.cp"),
            "--out",
            &path("ab.cp"),
        ],
    );
    assert_eq!(code, 0, "{}", both.render());
    assert_ne!(
        text(&both, "checkpoint_oid"),
        text(&first, "checkpoint_oid")
    );

    let verify = |file: &str, extra: &[&str]| {
        let mut args: Vec<String> = ["checkpoint", file, "--key", book_key.as_str(), "--json"]
            .map(str::to_string)
            .to_vec();
        args.extend(extra.iter().map(|a| (*a).to_string()));
        let read = |p: &str| std::fs::read(p);
        let out = fa_verify::cli::run(&args, &read);
        (
            out.exit,
            json::parse(out.stdout.trim()).expect("one JSON report"),
        )
    };
    let (code, report) = verify(
        &path("ab.cp"),
        &["--witness", &alice_pk, "--witness", &bob_pk],
    );
    assert_eq!(code, 0, "{}", report.render());
    let (code, report) = verify(
        &path("ab.cp"),
        &[
            "--witness",
            &alice_pk,
            "--witness",
            &bob_pk,
            "--witness",
            &carol_pk,
            "--quorum",
            "3",
        ],
    );
    assert_eq!(code, 8, "carol never signed: {}", report.render());
    assert!(
        report
            .render()
            .contains("2 of the 3 named witnesses signed")
    );
    let (code, _) = verify(
        &path("a1.cp"),
        &["--witness", &alice_pk, "--witness", &bob_pk],
    );
    assert_eq!(code, 8, "only alice signed a1");
    let (code, _) = verify(&path("ab.cp"), &["--witness", &book_key]);
    assert_eq!(code, 2, "the book's own key is no witness");
    // The book's signature comes from the book, never from the --onto file:
    // a copy with it stripped, or altered, still yields one that verifies.
    let a1 =
        fa_notary::TransparencyCheckpoint::decode(&std::fs::read(path("a1.cp")).unwrap()).unwrap();
    let book_key_bytes: [u8; 32] = unhex(&book_key).try_into().unwrap();
    let book_id = fa_notary::checkpoint::signer_key_id(&book_key_bytes);
    let mut stripped = a1.clone();
    stripped.signatures.retain(|s| s.signer_key_id != book_id);
    assert_eq!(stripped.signatures.len(), 1, "only alice's is left");
    let mut altered = a1.clone();
    for s in &mut altered.signatures {
        if s.signer_key_id == book_id {
            s.bytes[0] ^= 1;
        }
    }
    for (name, copy) in [("stripped", stripped), ("altered", altered)] {
        let file = path(&format!("{name}.cp"));
        std::fs::write(&file, copy.canonical_bytes().unwrap()).unwrap();
        let out = path(&format!("{name}-b.cp"));
        let (code, line) = witness(&f.book, &["--key", &bob, "--onto", &file, "--out", &out]);
        assert_eq!(code, 0, "{name}: {}", line.render());
        let (code, report) = verify(&out, &["--witness", &alice_pk, "--witness", &bob_pk]);
        assert_eq!(code, 0, "{name}: {}", report.render());
    }

    // The next state extends the one alice signed: cosigned with --previous.
    f.post("w-2", "2026-03-11", "6.00", &evidence);
    let next = f.checkpoint();
    let (code, second) = witness(
        &f.book,
        &[
            "--key",
            &alice,
            "--previous",
            &path("a1.cp"),
            "--out",
            &path("a2.cp"),
        ],
    );
    assert_eq!(code, 0, "{}", second.render());
    assert_eq!(text(&second, "state_oid"), text(&next, "oid"));
    assert_eq!(
        integer(get(&second, "extends"), "leaf_count"),
        integer(&created, "leaf_count")
    );
    // Refused, nothing written: another key's previous file; a rollback to
    // the earlier state; a key file others can read.
    let (code, refused) = witness(
        &f.book,
        &[
            "--key",
            &bob,
            "--previous",
            &path("a1.cp"),
            "--out",
            &path("x1.cp"),
        ],
    );
    assert_eq!(code, 2, "{}", refused.render());
    assert!(text(&refused, "message").contains("no signature by this witness key"));
    let (code, refused) = witness(
        &f.book,
        &[
            "--key",
            &alice,
            "--previous",
            &path("a2.cp"),
            "--state",
            text(&created, "oid"),
            "--out",
            &path("x2.cp"),
        ],
    );
    assert_eq!(code, 8, "{}", refused.render());
    assert_eq!(text(&refused, "refusal_id"), "FA-REF-124");
    std::fs::set_permissions(&alice, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (code, refused) = witness(&f.book, &["--key", &alice, "--out", &path("x3.cp")]);
    assert_eq!(code, 4, "{}", refused.render());
    assert_eq!(text(&refused, "refusal_id"), "FA-REF-155");
    std::fs::set_permissions(&alice, std::fs::Permissions::from_mode(0o600)).unwrap();
    for name in ["x1.cp", "x2.cp", "x3.cp"] {
        assert!(!f.dir.join(name).exists(), "{name}");
    }

    // A rewritten history under the same book key: the same identity and
    // signing key, a different first posting. Its checkpoint verifies under
    // the book key, but it does not extend what alice signed.
    let g = Fixture::new();
    let g_evidence = g.chart_and_evidence();
    g.post("w-1", "2026-03-10", "50.00", &g_evidence);
    g.post("w-2", "2026-03-11", "6.00", &g_evidence);
    let rewritten = g.checkpoint();
    assert_eq!(
        text(&rewritten, "public_key"),
        book_key,
        "the same signing key"
    );
    let (code, refused) = witness(
        &g.book,
        &[
            "--key",
            &alice,
            "--previous",
            &path("a2.cp"),
            "--out",
            &path("x4.cp"),
        ],
    );
    assert_eq!(code, 8, "{}", refused.render());
    assert_eq!(text(&refused, "refusal_id"), "FA-REF-124");
    assert!(
        text(&refused, "message")
            .contains("does not extend the checkpoint this witness signed last"),
        "{}",
        refused.render()
    );
    assert!(!f.dir.join("x4.cp").exists());
}

/// FA-INV-14.witnessed, the negative (planted): a witness that signed a
/// later state refuses to cosign a rolled-back one, and refuses a forked
/// history under the same book key, with FA-REF-124 each time. Nothing is
/// signed: no output file appears, and the witness's own last checkpoint is
/// byte-identical afterwards.
#[test]
fn a_witness_refuses_to_cosign_a_rolled_back_or_forked_history() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    f.post("r-1", "2026-03-10", "5.00", &evidence);
    let earlier = f.checkpoint();
    let path = |name: &str| f.dir.join(name).display().to_string();
    ok(
        &f.book,
        &["checkpoint", "witness-key", "--out", &path("w.key")],
    );
    let witness = |book: &Path, args: &[&str]| {
        run(
            book,
            &[&["checkpoint", "witness", "--grant", "witness"][..], args].concat(),
        )
    };
    let (code, line) = witness(&f.book, &["--key", &path("w.key"), "--out", &path("w1.cp")]);
    assert_eq!(code, 0, "{}", line.render());
    f.post("r-2", "2026-03-11", "6.00", &evidence);
    f.checkpoint();
    let (code, line) = witness(
        &f.book,
        &[
            "--key",
            &path("w.key"),
            "--previous",
            &path("w1.cp"),
            "--out",
            &path("w2.cp"),
        ],
    );
    assert_eq!(code, 0, "{}", line.render());
    let signed_last = std::fs::read(path("w2.cp")).unwrap();

    // Rollback: asked to cosign the earlier state after signing the later.
    let (code, refused) = witness(
        &f.book,
        &[
            "--key",
            &path("w.key"),
            "--previous",
            &path("w2.cp"),
            "--state",
            text(&earlier, "oid"),
            "--out",
            &path("rolled-back.cp"),
        ],
    );
    assert_eq!(code, 8, "{}", refused.render());
    assert_eq!(text(&refused, "refusal_id"), "FA-REF-124");

    // Fork: the same identity and book key, a different first posting.
    let g = Fixture::new();
    let g_evidence = g.chart_and_evidence();
    g.post("r-1", "2026-03-10", "50.00", &g_evidence);
    g.post("r-2", "2026-03-11", "6.00", &g_evidence);
    let forked = g.checkpoint();
    assert_eq!(
        text(&forked, "public_key"),
        text(&earlier, "public_key"),
        "the fork is signed by the same book key"
    );
    let (code, refused) = witness(
        &g.book,
        &[
            "--key",
            &path("w.key"),
            "--previous",
            &path("w2.cp"),
            "--out",
            &path("forked.cp"),
        ],
    );
    assert_eq!(code, 8, "{}", refused.render());
    assert_eq!(text(&refused, "refusal_id"), "FA-REF-124");

    for name in ["rolled-back.cp", "forked.cp"] {
        assert!(!f.dir.join(name).exists(), "{name} was signed");
    }
    assert_eq!(
        std::fs::read(path("w2.cp")).unwrap(),
        signed_last,
        "the witness's last checkpoint is unchanged"
    );
}

/// `fa proof suffix` (plan §13.2): a recipient that kept an old state gets
/// everything appended since in one export, including a document's import
/// receipt, which no entry vid names (so `proof inclusion` cannot cut it),
/// and checks it offline. The consistency proof extends the old checkpoint
/// to the new one, and each record is a recomputed inclusion at the new
/// checkpoint, at consecutive leaves from the old leaf count. Written to a
/// new directory, the files carry the same bytes. A missing --state, an
/// existing directory and a reversed pair are refused, writing nothing.
#[test]
fn a_suffix_carries_every_appended_leaf_and_verifies_against_both_checkpoints() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    f.post("s-1", "2026-03-10", "5.00", &evidence);
    let old_state = f.checkpoint();
    let posted = f.post("s-2", "2026-03-11", "6.00", &evidence);
    let memo = write(&f.dir, "memo.txt", "A later supporting memo.");
    ok(
        &f.book,
        &[
            "document",
            "add",
            &memo,
            "--kind",
            "Receipt",
            "--grade",
            "HumanUpload",
        ],
    );
    let new_state = f.checkpoint();
    let (old_oid, new_oid) = (text(&old_state, "oid"), text(&new_state, "oid"));
    let checkpoint = |oid: &str| {
        Checkpoint::decode(&bytes(&exported(&f.book, &["checkpoint", "--state", oid])))
            .expect("a checkpoint statement")
    };
    let (old, new) = (checkpoint(old_oid), checkpoint(new_oid));

    let line = ok(
        &f.book,
        &[
            "proof",
            "suffix",
            "--state",
            old_oid,
            "--next-state",
            new_oid,
        ],
    );
    assert_eq!(text(&line, "event"), "proof_suffix_exported");
    assert_eq!(integer(&line, "from_leaf") as u64, old.leaf_count);
    assert_eq!(integer(&line, "to_leaf") as u64, new.leaf_count);
    let records: Vec<Vec<u8>> = get(&line, "records")
        .as_arr()
        .expect("inline records")
        .iter()
        .map(|r| unhex(r.as_str().expect("hex")))
        .collect();
    assert_eq!(
        records.len(),
        2,
        "the posting and the memo's import receipt"
    );
    assert_eq!(records.len() as u64, new.leaf_count - old.leaf_count);
    let consistency = unhex(text(&line, "consistency"));
    let extended = fa_verify::verify_consistency(&consistency, &old, &new)
        .expect("the suffix extends the retained root");
    assert_eq!((extended.trusted, extended.extended), (old, new));
    let mut kinds = Vec::new();
    for (leaf, record) in (old.leaf_count..).zip(&records) {
        let included = fa_verify::verify_inclusion(record, &new)
            .expect("each record verifies at the new root");
        assert_eq!(included.leaf_index, leaf);
        assert_eq!(included.record, RecordCheck::Recomputed);
        kinds.push(included.envelope.kind);
    }
    assert!(
        kinds.contains(&1) && kinds.iter().any(|k| *k != 1),
        "an entry and an evidence record: {kinds:?}"
    );
    // The posting's record is exactly what `proof inclusion --with-record` cuts.
    let single = exported(
        &f.book,
        &[
            "inclusion",
            "--entry",
            text(&posted, "vid"),
            "--with-record",
            "--state",
            new_oid,
        ],
    );
    assert!(records.contains(&bytes(&single)));
    // The latest state is the default end.
    let latest = ok(&f.book, &["proof", "suffix", "--state", old_oid]);
    assert_eq!(text(&latest, "next_state_oid"), new_oid);

    // To a new directory: the same bytes, record files in leaf order.
    let out = f.dir.join("suffix").display().to_string();
    let written = ok(
        &f.book,
        &["proof", "suffix", "--state", old_oid, "--out", &out],
    );
    assert_eq!(get(&written, "records"), &Json::Null);
    let files: Vec<String> = get(&written, "files")
        .as_arr()
        .expect("files")
        .iter()
        .map(|p| p.as_str().expect("a path").to_string())
        .collect();
    assert_eq!(files.len(), 3, "{}", written.render());
    assert_eq!(std::fs::read(&files[0]).unwrap(), consistency);
    for (file, record) in files[1..].iter().zip(&records) {
        assert_eq!(&std::fs::read(file).unwrap(), record);
    }
    let mut sorted = files[1..].to_vec();
    sorted.sort();
    assert_eq!(sorted, files[1..], "name order is leaf order");

    // Refused, nothing written.
    let (code, refused) = run(&f.book, &["proof", "suffix"]);
    assert_eq!(code, 2, "{}", refused.render());
    let (code, refused) = run(
        &f.book,
        &["proof", "suffix", "--state", old_oid, "--out", &out],
    );
    assert_ne!(code, 0, "an existing directory: {}", refused.render());
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 3);
    let reversed = f.dir.join("reversed").display().to_string();
    let (code, refused) = run(
        &f.book,
        &[
            "proof",
            "suffix",
            "--state",
            new_oid,
            "--next-state",
            old_oid,
            "--out",
            &reversed,
        ],
    );
    assert_ne!(code, 0, "a suffix runs forward: {}", refused.render());
    assert!(!f.dir.join("reversed").exists());
}
