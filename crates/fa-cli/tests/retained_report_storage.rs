//! Large report retention through the actual fa binary and the same held-book
//! dispatcher used by fad. No fake report, storage engine or injected output.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa::{Book, BookKeys, Entropy, ReportCertificate};
use fa_cli::cli::{self, Books, Files, Stdin};
use fa_cli::json::{self, Json};
use fa_journal::{AccountSpec, BookSpec, Capability, Document, PostRequest, UnitPolicy};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload, Oid, account_vid,
};
use fa_money::{Amount, Side, UnitRegistry};
use fa_time::{DateDay, FiscalCalendar, PeriodTransition};
use fgdb_types::{CommitSeq, VId};

const BOOK_ID: Id128 = Id128([0xd1; 16]);
const PRINCIPAL: VId = VId(1);
const PERIOD: &str = "FY2026-P01";
const INLINE_BYTES: usize = 12 * 1024;

struct Fixture {
    dir: PathBuf,
    keys: BookKeys,
    source_head: CommitSeq,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = loop {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "fa-retained-report-storage-{}-{n}",
                std::process::id(),
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create retained fixture {}: {error}", path.display()),
            }
        };
        let dir = parent.join("book");
        let keys = BookKeys::for_development(0xd1);
        let units = UnitRegistry::embedded().unwrap();
        let mut book = Book::create_dir(
            &dir,
            keys.clone(),
            BookSpec {
                book_id: BOOK_ID,
                name: "Large report CLI".into(),
                base_unit: units.lookup("USD").unwrap(),
                calendar: FiscalCalendar::monthly("report-cli", 1, 1).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(209),
        )
        .unwrap();
        keys.save(&dir.join("book.keys")).unwrap();
        let accounts: Vec<_> = [
            ("1000", AccountType::ASSET, 0),
            ("4000", AccountType::REVENUE, 1),
        ]
        .into_iter()
        .map(|(code, kind, normal_balance)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: kind.0,
            normal_balance,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            parent_code: None,
            limit: None,
        })
        .collect();
        book.install_chart(&accounts, PRINCIPAL, day(), b"chart")
            .unwrap()
            .unwrap();
        book.create_periods(2026).unwrap();
        book.transition_period(
            PERIOD,
            PeriodTransition::Open,
            PRINCIPAL,
            1,
            day(),
            b"open",
            &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
        )
        .unwrap()
        .unwrap();
        for n in 0..64 {
            post(&mut book, n);
        }
        let source_head = book.head().unwrap();
        drop(book);
        Self {
            dir,
            keys,
            source_head,
        }
    }

    fn open(&self) -> Book {
        Book::open_dir(&self.dir, self.keys.clone(), Entropy::deterministic(210)).unwrap()
    }

    fn head(&self) -> CommitSeq {
        self.open().head().unwrap()
    }

    fn run(&self, args: &[&str]) -> (i32, Vec<Json>) {
        let output = Command::new(env!("CARGO_BIN_EXE_fa"))
            .args(args)
            .arg("--book")
            .arg(&self.dir)
            .args(["--via", "direct", "--json", "--no-color"])
            .env_remove("FA_BOOK")
            .env_remove("FA_KEYS")
            .output()
            .unwrap();
        let code = output.status.code().expect("fa exited normally");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let events = parse_events(&stdout);
        if code != 0 {
            assert!(
                events.iter().any(|row| text(row, "event") == "error"),
                "args={args:?}, code={code}, stdout={stdout}, stderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        (code, events)
    }

    fn ok(&self, args: &[&str]) -> Vec<Json> {
        let (code, events) = self.run(args);
        assert_eq!(code, 0, "args={args:?}; events={events:?}");
        events
    }
}

fn day() -> DateDay {
    DateDay::from_ymd(2026, 1, 1).unwrap()
}

fn post(book: &mut Book, n: u32) {
    let document = Document {
        book_id: BOOK_ID,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"source for report CLI postings".to_vec(),
    };
    book.add_document(&document).unwrap().unwrap();
    let usd = book.context().units.lookup("USD").unwrap();
    let legs = vec![
        LegPayload::simple(
            Side::Debit,
            account_vid(BOOK_ID, "1000"),
            Amount::new(usd, 100),
        ),
        LegPayload::simple(
            Side::Credit,
            account_vid(BOOK_ID, "4000"),
            Amount::new(usd, 100),
        ),
    ];
    let proposal = EntryPayload {
        schema_minor: 0,
        book_id: BOOK_ID,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: day(),
        document_date: None,
        description: book.seal_text("report CLI posting").unwrap(),
        effective_period: None,
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: format!("post-{n}").into_bytes(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid([0xd2; 32]),
            intent_kind: 1,
        },
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: vec![document.evidence_ref(1)],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    book.post(PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
    })
    .unwrap()
    .unwrap();
}

fn parse_events(stdout: &str) -> Vec<Json> {
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| json::parse(line).expect("stdout is NDJSON"))
        .collect()
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("missing {key}: {value:?}"))
}

fn event<'a>(events: &'a [Json], name: &str) -> &'a Json {
    events
        .iter()
        .find(|row| text(row, "event") == name)
        .unwrap_or_else(|| panic!("missing event {name}: {events:?}"))
}

fn data<'a>(events: &'a [Json], name: &str) -> &'a Json {
    event(events, name).get("data").unwrap()
}

fn unhex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn held(book: &mut Book, dir: &std::path::Path, args: &[&str], stdin: Stdin) -> Vec<Json> {
    let mut argv: Vec<String> = args.iter().map(|s| (*s).into()).collect();
    argv.extend([
        "--book".into(),
        dir.to_str().unwrap().into(),
        "--json".into(),
    ]);
    let (code, captured) = cli::run(
        &argv,
        Books::Held {
            book,
            dir: dir.into(),
        },
        Files { cwd: None, stdin },
        true,
    );
    assert_eq!(
        code, 0,
        "{args:?}: {}\n{}",
        captured.stdout, captured.stderr
    );
    parse_events(&captured.stdout)
}

#[test]
fn large_cli_reports_replay_from_digest_and_file_after_reopen_and_backdated_posting() {
    let f = Fixture::new();
    let at = f.source_head.0.to_string();
    let path = f.dir.join("explanation.cert");
    let args = [
        "explain",
        "balance",
        "1000",
        "--period",
        PERIOD,
        "--as-known-at",
        &at,
        "--certificate-out",
        path.to_str().unwrap(),
    ];
    let events = f.ok(&args);
    let metadata = data(&events, "report_certificate");
    let expected = unhex(text(metadata, "bytes"));
    let certificate = ReportCertificate::decode(&expected).unwrap();
    assert!(certificate.output.len() > INLINE_BYTES);
    assert_eq!(std::fs::read(&path).unwrap(), expected);
    assert_eq!(certificate.known_at, f.source_head);
    assert_eq!(
        f.head().0,
        f.source_head.0 + 1,
        "one retention publication, not one per fragment"
    );
    let locator = format!("C:{}", text(metadata, "oid"));
    let mut book = f.open();
    assert_eq!(
        book.read_certificate(&certificate.digest).unwrap().unwrap(),
        certificate
    );
    post(&mut book, 64);
    let later = book.head().unwrap();
    drop(book);
    for input in [locator.as_str(), path.to_str().unwrap()] {
        let replayed = f.ok(&["replay", input]);
        assert_eq!(
            data(&replayed, "balance_explained"),
            data(&events, "balance_explained")
        );
        assert_eq!(
            text(event(&replayed, "balance_explained"), "certificate"),
            text(metadata, "oid")
        );
        let status = f.ok(&["certificate", "status", input]);
        assert_eq!(
            text(data(&status, "certificate_status"), "status"),
            "SupersededBy"
        );
    }
    assert_eq!(f.head(), later);
    let (code, _) = f.run(&args);
    assert_ne!(
        code, 0,
        "an existing external artifact must never be replaced"
    );
    assert_eq!(std::fs::read(&path).unwrap(), expected);
    assert_eq!(f.head(), later);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn daemon_held_book_dispatch_reuses_the_same_large_certificate_and_forwarded_binary_bytes() {
    let f = Fixture::new();
    let at = f.source_head.0.to_string();
    let args = [
        "explain",
        "balance",
        "1000",
        "--period",
        PERIOD,
        "--as-known-at",
        &at,
        "--certify",
    ];
    let direct = f.ok(&args);
    let metadata = data(&direct, "report_certificate");
    let bytes = unhex(text(metadata, "bytes"));
    assert!(ReportCertificate::decode(&bytes).unwrap().output.len() > INLINE_BYTES);
    let locator = format!("C:{}", text(metadata, "oid"));
    let mut book = f.open();
    let before = book.head().unwrap();
    let repeated = held(&mut book, &f.dir, &args, Stdin::Missing);
    assert_eq!(data(&repeated, "report_certificate"), metadata);
    assert_eq!(book.head().unwrap(), before);
    let by_digest = held(&mut book, &f.dir, &["replay", &locator], Stdin::Missing);
    let by_stdin = held(&mut book, &f.dir, &["replay", "-"], Stdin::Forwarded(bytes));
    assert_eq!(
        data(&by_digest, "balance_explained"),
        data(&by_stdin, "balance_explained")
    );
    assert_eq!(
        data(&by_digest, "balance_explained"),
        data(&direct, "balance_explained")
    );
    assert_eq!(book.head().unwrap(), before);
}

#[test]
fn compact_legacy_trial_balance_certificates_still_round_trip_through_the_cli() {
    let f = Fixture::new();
    let at = f.source_head.0.to_string();
    let events = f.ok(&["tb", "--period", PERIOD, "--as-known-at", &at, "--certify"]);
    let metadata = data(&events, "report_certificate");
    let bytes = unhex(text(metadata, "bytes"));
    assert!(
        bytes.len() <= INLINE_BYTES,
        "fixture must cover the original inline format"
    );
    assert!(bytes.starts_with(fa::certificate::CERTIFICATE_FORMAT));
    let certificate = ReportCertificate::decode(&bytes).unwrap();
    let book = f.open();
    assert_eq!(
        book.read_certificate(&certificate.digest)
            .unwrap()
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        bytes
    );
    let before = book.head().unwrap();
    drop(book);
    let locator = format!("C:{}", text(metadata, "oid"));
    let replayed = f.ok(&["replay", &locator]);
    assert_eq!(
        data(&replayed, "trial_balance"),
        data(&events, "trial_balance")
    );
    assert_eq!(f.head(), before);
}
