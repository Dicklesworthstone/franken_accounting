//! Large report retention through the actual fa binary and the same held-book
//! dispatcher used by fad. No fake report, storage engine or injected output.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa::{Book, BookKeys, Entropy, ReportCertificate};
use fa_cli::cli::{self, Books, Files, Stdin};
use fa_cli::json::{self, Json, obj, s};
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
        Self::with_additional_cash_accounts(0)
    }

    fn with_additional_cash_accounts(additional_accounts: u16) -> Self {
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
        let mut accounts: Vec<_> = [
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
        accounts.extend((0..additional_accounts).map(|index| {
            let code = (2000 + u32::from(index)).to_string();
            AccountSpec {
                name: format!("Operating cash account {code}"),
                code,
                account_type: AccountType::ASSET.0,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            }
        }));
        book.install_chart(
            &accounts,
            PRINCIPAL,
            day(),
            b"chart",
            &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        )
        .unwrap()
        .unwrap();
        book.create_periods(
            2026,
            PRINCIPAL,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        )
        .unwrap()
        .unwrap();
        book.transition_period(
            PERIOD,
            PeriodTransition::Open,
            PRINCIPAL,
            1,
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
    post_cash_movement(book, n, "USD", 100, Side::Debit);
}

fn post_cash_movement(book: &mut Book, n: u32, unit: &str, amount: i128, side: Side) {
    let document = Document {
        book_id: BOOK_ID,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"source for report CLI postings".to_vec(),
    };
    book.add_document(&document).unwrap().unwrap();
    let unit = book.context().units.lookup(unit).unwrap();
    let counterpart = match side {
        Side::Debit => Side::Credit,
        Side::Credit => Side::Debit,
    };
    let legs = vec![
        LegPayload::simple(
            side,
            account_vid(BOOK_ID, "1000"),
            Amount::new(unit, amount),
        ),
        LegPayload::simple(
            counterpart,
            account_vid(BOOK_ID, "4000"),
            Amount::new(unit, amount),
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
fn summary_aging_and_roll_forward_certify_retain_and_replay_the_original_report() {
    // A summary collapses the 64 postings into two balance rows. Retaining
    // the real membership of 130 chart roots makes its output large enough
    // to exercise fragments, including zero-activity leaves without padding.
    // Other fixtures retain the compact two-account chart for inline coverage.
    const ADDITIONAL_ACCOUNTS: u16 = 128;
    let f = Fixture::with_additional_cash_accounts(ADDITIONAL_ACCOUNTS);
    let at = f.source_head.0.to_string();
    // The roll-forward covers the same 129 cash accounts, so its retained
    // artifact is large enough to exercise fragments too.
    let cash_accounts = std::iter::once("1000".to_string())
        .chain((0..ADDITIONAL_ACCOUNTS).map(|index| (2000 + u32::from(index)).to_string()))
        .collect::<Vec<_>>()
        .join(",");
    let cases = [
        (
            "summary",
            "summary_trial_balance",
            vec!["tb", "--period", PERIOD, "--summary"],
        ),
        (
            "roll-forward",
            "roll_forward",
            vec![
                "gl",
                "roll-forward",
                "--account",
                cash_accounts.as_str(),
                "--from",
                "2026-01-01",
                "--to",
                "2026-01-31",
            ],
        ),
        (
            "effective-date-aging",
            "aging",
            vec![
                "gl",
                "aging",
                "--account",
                "1000",
                "--as-of",
                "2026-01-31",
                "--bucket",
                "0,30,60",
            ],
        ),
    ];
    let mut originals = Vec::new();
    for (family, event_name, mut args) in cases {
        args.extend(["--as-known-at", &at]);
        let before = f.head();
        let plain = f.ok(&args);
        assert_eq!(f.head(), before, "{family}: ordinary report is read-only");
        if family == "summary" {
            let summary = data(&plain, event_name);
            assert_eq!(
                summary.get("groups").and_then(Json::as_arr).unwrap().len(),
                usize::from(ADDITIONAL_ACCOUNTS) + 2,
            );
            assert_eq!(summary.get("complete"), Some(&Json::Bool(true)));
        }
        let file = f.dir.join(format!("{family}.cert"));
        let mut certify_args = args.clone();
        certify_args.extend(["--certificate-out", file.to_str().unwrap()]);
        let events = f.ok(&certify_args);
        assert_eq!(events.len(), 2, "{family}: report and complete certificate");
        assert_eq!(data(&events, event_name), data(&plain, event_name));
        let metadata = data(&events, "report_certificate");
        let bytes = unhex(text(metadata, "bytes"));
        let artifact = fa::ReportArtifact::decode(&bytes).unwrap();
        assert_eq!(artifact.family().name(), family);
        assert_eq!(artifact.known_at(), f.source_head);
        assert!(
            bytes.len() > 16 * 1024,
            "{family}: exercise chunked retention"
        );
        assert_eq!(std::fs::read(&file).unwrap(), bytes);
        assert_eq!(
            f.head().0,
            before.0 + 1,
            "{family}: one metadata publication"
        );
        let digest = text(metadata, "oid");
        assert_eq!(unhex(digest).as_slice(), artifact.digest().as_slice());
        assert_eq!(text(event(&events, event_name), "certificate"), digest);
        assert_eq!(
            text(event(&events, "report_certificate"), "certificate"),
            digest
        );
        let locator = format!("C:{digest}");
        let retained_at = f.head();
        args.push("--certify");
        let repeated = f.ok(&args);
        assert_eq!(data(&repeated, event_name), data(&events, event_name));
        assert_eq!(text(data(&repeated, "report_certificate"), "oid"), digest);
        assert_eq!(
            f.head(),
            retained_at,
            "{family}: exact retry reuses its retention"
        );
        // A summary has its own relevance law (the report reproduces at
        // HEAD) and a roll-forward its selected-schedule law; effective-date
        // aging still refuses selector status.
        let (exit, status) = f.run(&["certificate", "status", &locator]);
        if family == "effective-date-aging" {
            assert_eq!(exit, 8, "{family}: {status:?}");
        } else {
            assert_eq!(exit, 0, "{family}: {status:?}");
            let status = data(&status, "certificate_status");
            assert_eq!(text(status, "status"), "Current", "{family}");
            assert_eq!(status.get("later_entries"), Some(&Json::Arr(Vec::new())));
        }
        assert_eq!(f.head(), retained_at, "{family}: status is a read");
        originals.push((event_name, events, bytes, locator, file));
    }
    let mut book = f.open();
    post(&mut book, 64);
    let later = book.head().unwrap();
    drop(book);
    for (event_name, original, bytes, locator, file) in originals {
        if event_name == "summary_trial_balance" {
            let status = f.ok(&["certificate", "status", &locator]);
            let status = data(&status, "certificate_status");
            assert_eq!(text(status, "status"), "Changed", "64 later postings");
            assert_eq!(
                status.get("checked_at"),
                Some(&Json::Int(i128::from(later.0)))
            );
            assert_eq!(status.get("later_entries"), Some(&Json::Arr(Vec::new())));
            let (exit, refused) = f.run(&["certificate", "status", &locator, "--expect", "{}"]);
            assert_eq!(
                exit, 2,
                "a summary status takes no expectation: {refused:?}"
            );
            assert!(
                text(data(&refused, "error"), "message").contains("summary status compares"),
                "{refused:?}"
            );
        }
        let artifact = fa::ReportArtifact::decode(&bytes).unwrap();
        for input in [locator.as_str(), file.to_str().unwrap()] {
            let replayed = f.ok(&["replay", input]);
            assert_eq!(data(&replayed, event_name), data(&original, event_name));
            assert_eq!(
                event(&replayed, event_name).get("coordinate"),
                event(&original, event_name).get("coordinate"),
                "replay preserves the report's historical selector",
            );
            assert_eq!(
                event(&replayed, event_name).get("certificate"),
                event(&original, event_name).get("certificate"),
            );
            assert_eq!(
                text(data(&replayed, "report_replayed"), "family"),
                artifact.family().name()
            );
        }
        let output = f.dir.join(format!("{event_name}.output"));
        let replayed = f.ok(&["replay", &locator, "--output", output.to_str().unwrap()]);
        assert_eq!(std::fs::read(&output).unwrap(), artifact.output());
        assert_eq!(
            data(&replayed, "report_replayed").get("output_digest"),
            data(&original, "report_certificate").get("output_digest"),
        );
        let mut book = f.open();
        let held_replay = held(&mut book, &f.dir, &["replay", "-"], Stdin::Forwarded(bytes));
        assert_eq!(data(&held_replay, event_name), data(&original, event_name));
        assert_eq!(book.head().unwrap(), later, "replay never publishes");
    }
    assert_eq!(f.head(), later);
}

#[test]
fn derived_report_certificates_refuse_tampering_and_existing_outputs_without_success() {
    let f = Fixture::new();
    let events = f.ok(&["gl", "aging", "--as-of", "2026-01-31", "--certify"]);
    let metadata = data(&events, "report_certificate");
    let original = unhex(text(metadata, "bytes"));
    let mut damaged = original.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    let file = f.dir.join("tampered-aging.cert");
    std::fs::write(&file, damaged).unwrap();
    let output = f.dir.join("must-not-write-aging.output");
    let before = f.head();
    let (exit, errors) = f.run(&[
        "replay",
        file.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(exit, 8, "{errors:?}");
    assert_eq!(errors.len(), 1, "no report can escape after replay fails");
    assert_eq!(text(&errors[0], "event"), "error");
    assert!(!output.exists());
    assert_eq!(f.head(), before);
    let occupied = f.dir.join("occupied.cert");
    std::fs::write(&occupied, b"preserved recipient evidence").unwrap();
    let (exit, errors) = f.run(&[
        "gl",
        "roll-forward",
        "--account",
        "1000",
        "--from",
        "2026-01-01",
        "--to",
        "2026-01-31",
        "--certificate-out",
        occupied.to_str().unwrap(),
    ]);
    assert_ne!(exit, 0);
    assert_eq!(errors.len(), 1);
    assert_eq!(text(&errors[0], "event"), "error");
    assert_eq!(
        std::fs::read(occupied).unwrap(),
        b"preserved recipient evidence"
    );
    assert_eq!(f.head(), before, "output refusal must precede retention");
    for args in [
        vec![
            "gl",
            "aging",
            "--as-of",
            "2026-01-31",
            "--reconcile",
            "--certify",
        ],
        vec!["gl", "cash-flow", "--certify"],
        vec!["gl", "lots", "--certify"],
    ] {
        let (exit, errors) = f.run(&args);
        assert_eq!(exit, 2, "{args:?}: {errors:?}");
        assert_eq!(errors.len(), 1);
        assert_eq!(text(&errors[0], "event"), "error");
        assert_eq!(f.head(), before);
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

#[test]
fn gl_families_certify_retain_and_replay_their_complete_original_artifacts() {
    let f = Fixture::new();
    let at = f.source_head.0.to_string();
    let baseline = f.ok(&[
        "gl",
        "detail",
        "--account",
        "1000",
        "--from",
        "2026-01-01",
        "--to",
        "2026-01-31",
        "--as-known-at",
        &at,
    ]);
    let assignments: Vec<Json> = data(&baseline, "general_ledger")
        .get("lines")
        .and_then(Json::as_arr)
        .unwrap()
        .iter()
        .map(|line| {
            obj(vec![
                ("entry_digest", line.get("entry_digest").unwrap().clone()),
                ("leg_index", line.get("leg_index").unwrap().clone()),
                ("activity", s("operating")),
            ])
        })
        .collect();
    assert_eq!(assignments.len(), 64);
    let direct_policy = obj(vec![
        ("name", s("cash-policy")),
        ("cash_accounts", Json::Arr(vec![s("1000")])),
        ("assignments", Json::Arr(assignments.clone())),
    ]);
    let indirect_policy = obj(vec![
        ("name", s("indirect-policy")),
        ("cash_policy", s("cash-policy")),
        ("cash_accounts", Json::Arr(vec![s("1000")])),
        ("assignments", Json::Arr(assignments)),
        ("adjustments", Json::Arr(Vec::new())),
    ]);
    let direct_path = f.dir.join("direct-policy.json");
    let indirect_path = f.dir.join("indirect-policy.json");
    std::fs::write(&direct_path, direct_policy.render()).unwrap();
    std::fs::write(&indirect_path, indirect_policy.render()).unwrap();
    let cash_expectation = |kind: &str, label: &str, policy: &Json| {
        let mut fields = vec![
            ("kind", s(kind)),
            ("accounts", Json::Arr(vec![s("1000")])),
            ("units", Json::Arr(vec![s("USD")])),
            ("from", s("2026-01-01")),
            ("through", s("2026-01-31")),
            ("label", s(label)),
            ("known_at", Json::Int(i128::from(f.source_head.0))),
            ("policy", policy.clone()),
        ];
        if kind == "indirect-cash-flow" {
            fields.push((
                "income_periods",
                Json::Arr(vec![s("FY2026-OPEN"), s(PERIOD)]),
            ));
        }
        obj(fields)
    };
    let reconcile_expected = obj(vec![
        ("kind", s("aging-reconciliation")),
        ("account", s("1000")),
        ("through", s("2026-01-31")),
        ("known_at", Json::Int(i128::from(f.source_head.0))),
        (
            "buckets",
            Json::Arr([0, 30, 60, 90].into_iter().map(Json::Int).collect()),
        ),
    ]);
    let mut retained = Vec::new();
    for (name, report_event, family, expected) in [
        ("detail", "general_ledger", "roll-forward", None),
        ("roll-forward", "roll_forward", "roll-forward", None),
        ("aging", "aging", "effective-date-aging", None),
        (
            "reconcile",
            "aging_reconciled",
            "aging-reconciliation",
            Some(reconcile_expected),
        ),
        (
            "cash",
            "cash_flow",
            "cash-flow",
            Some(cash_expectation("cash-flow", "cash", &direct_policy)),
        ),
        (
            "indirect",
            "indirect_cash_flow",
            "indirect-cash-flow",
            Some(cash_expectation(
                "indirect-cash-flow",
                "indirect",
                &indirect_policy,
            )),
        ),
    ] {
        let subcommand = match name {
            "reconcile" => "aging",
            "cash" | "indirect" => "cash-flow",
            other => other,
        };
        let mut args = vec!["gl", subcommand, "--account", "1000", "--as-known-at", &at];
        if subcommand == "aging" {
            args.extend(["--as-of", "2026-01-31", "--bucket", "0,30,60,90"]);
            if name == "reconcile" {
                args.push("--reconcile");
            }
        } else {
            args.extend([
                "--from",
                "2026-01-01",
                "--to",
                "2026-01-31",
                "--label",
                name,
            ]);
        }
        if name == "cash" {
            args.extend(["--policy", direct_path.to_str().unwrap()]);
        }
        if name == "indirect" {
            args.extend([
                "--policy",
                indirect_path.to_str().unwrap(),
                "--indirect",
                "--income-period",
                "FY2026-OPEN,FY2026-P01",
            ]);
        }
        let cert_path = f.dir.join(format!("{name}.cert"));
        let mut save_args = args.clone();
        save_args.extend(["--certificate-out", cert_path.to_str().unwrap()]);
        let events = f.ok(&save_args);
        assert_eq!(events.len(), 2, "{name}: {events:?}");
        let metadata = data(&events, "report_certificate");
        let bytes = unhex(text(metadata, "bytes"));
        assert_eq!(std::fs::read(&cert_path).unwrap(), bytes);
        let artifact = fa::ReportArtifact::decode(&bytes).unwrap();
        assert_eq!(artifact.family().name(), family);
        assert_eq!(artifact.known_at(), f.source_head);
        assert_eq!(
            text(event(&events, report_event), "certificate"),
            text(metadata, "oid")
        );
        assert_eq!(
            data(&events, report_event).get("known_at"),
            Some(&Json::Int(i128::from(f.source_head.0)))
        );
        let locator = format!("C:{}", text(metadata, "oid"));
        let before_retry = f.head();
        args.push("--certify");
        let retry = f.ok(&args);
        assert_eq!(
            text(data(&retry, "report_certificate"), "oid"),
            text(metadata, "oid")
        );
        assert_eq!(
            data(&retry, "report_certificate").get("recorded_at"),
            metadata.get("recorded_at")
        );
        assert_eq!(
            f.head(),
            before_retry,
            "exact certification retry must not publish"
        );
        let expectation = expected.as_ref().map(Json::render);
        let supports_status = matches!(family, "roll-forward" | "cash-flow");
        if supports_status {
            let mut status_args = vec!["certificate", "status", &locator];
            if let Some(expected) = &expectation {
                status_args.extend(["--expect", expected]);
            }
            let status = f.ok(&status_args);
            let receipt = data(&status, "certificate_status");
            assert_eq!(text(receipt, "status"), "Current");
            assert_eq!(text(receipt, "oid"), text(metadata, "oid"));
            assert_eq!(keys(receipt), pinned_fields("events", "certificate_status"));
            assert_eq!(f.head(), before_retry, "freshness never publishes");
        }
        for (index, input) in [locator.as_str(), cert_path.to_str().unwrap()]
            .into_iter()
            .enumerate()
        {
            let output = f.dir.join(format!("{name}-{index}.report"));
            let mut replay_args = vec!["replay", input, "--output", output.to_str().unwrap()];
            if let Some(expected) = &expectation {
                replay_args.extend(["--expect", expected]);
            }
            let replayed = f.ok(&replay_args);
            assert_eq!(text(data(&replayed, "report_replayed"), "family"), family);
            assert_eq!(std::fs::read(output).unwrap(), artifact.output());
            assert_eq!(f.head(), before_retry);
        }
        // The generated command carries a fixed request the producer can
        // retain separately before delivering a certificate to another party.
        if expectation.is_some() {
            let command = text(metadata, "replay_command");
            let generated = command
                .split_once(" --expect '")
                .unwrap()
                .1
                .split_once("' --book")
                .unwrap()
                .0;
            let replayed = f.ok(&["replay", &locator, "--expect", generated]);
            assert_eq!(text(data(&replayed, "report_replayed"), "family"), family);
            let absent_output = f.dir.join(format!("{name}-refused.report"));
            let (code, errors) = f.run(&[
                "replay",
                &locator,
                "--output",
                absent_output.to_str().unwrap(),
            ]);
            assert_eq!(
                code, 8,
                "recipient-dependent family needs its expected scope: {errors:?}"
            );
            assert_eq!(errors.len(), 1);
            let refusal = data(&errors, "error");
            assert!(
                text(refusal, "message")
                    .contains(&format!("{family} report certificates replay only")),
                "{refusal:?}"
            );
            assert!(
                text(refusal, "fix").contains("--expect"),
                "an omitted expectation must name --expect, not a damaged certificate: {refusal:?}"
            );
            assert!(!absent_output.exists());
            let mut wrong = expected.clone().unwrap();
            let Json::Obj(fields) = &mut wrong else {
                panic!("expected object");
            };
            for (field, value) in fields {
                if field == "through" {
                    *value = s("2026-01-30");
                }
            }
            let wrong_json = wrong.render();
            if supports_status {
                for additional in [Vec::new(), vec!["--expect", wrong_json.as_str()]] {
                    let mut status_args = vec!["certificate", "status", &locator];
                    status_args.extend(additional);
                    let (code, errors) = f.run(&status_args);
                    assert_eq!(code, 8, "freshness needs the original request: {errors:?}");
                    assert_eq!(errors.len(), 1, "no freshness verdict may escape");
                }
            }
            let (code, errors) = f.run(&[
                "replay",
                &locator,
                "--expect",
                &wrong_json,
                "--output",
                absent_output.to_str().unwrap(),
            ]);
            assert_eq!(
                code, 8,
                "changing the expected cutoff must fail even when balances match: {errors:?}"
            );
            assert_eq!(errors.len(), 1);
            assert!(!absent_output.exists());
            let mut floating_prefix = expected.clone().unwrap();
            let Json::Obj(fields) = &mut floating_prefix else {
                panic!("expected object");
            };
            for (field, value) in fields {
                if field == "known_at" {
                    *value = s("HEAD");
                }
            }
            let (code, errors) =
                f.run(&["replay", &locator, "--expect", &floating_prefix.render()]);
            assert_eq!(
                code, 2,
                "HEAD must never replace the fixed expected prefix: {errors:?}"
            );
            if let Some(policy) = expected.as_ref().and_then(|doc| doc.get("policy")) {
                let mut unknown_policy = expected.clone().unwrap();
                let Json::Obj(fields) = &mut unknown_policy else {
                    panic!("expected object");
                };
                let Json::Obj(mut policy_fields) = policy.clone() else {
                    panic!("expected policy object");
                };
                policy_fields.push(("unrecognized_classification".into(), Json::Bool(true)));
                for (field, value) in fields {
                    if field == "policy" {
                        *value = Json::Obj(policy_fields.clone());
                    }
                }
                let (code, errors) =
                    f.run(&["replay", &locator, "--expect", &unknown_policy.render()]);
                assert_eq!(
                    code, 2,
                    "unknown policy inputs must not be silently discarded: {errors:?}"
                );
            }
        }
        retained.push((
            locator,
            bytes,
            artifact.output().to_vec(),
            expectation,
            supports_status,
        ));
    }
    let mut book = f.open();
    post(&mut book, 64);
    let later_head = book.head().unwrap();
    for (locator, bytes, expected_output, expectation, supports_status) in retained {
        let output = f.dir.join(format!("held-{}.report", &locator[2..]));
        let mut args = vec!["replay", "-", "--output", output.to_str().unwrap()];
        if let Some(expected) = &expectation {
            args.extend(["--expect", expected]);
        }
        let replayed = held(&mut book, &f.dir, &args, Stdin::Forwarded(bytes));
        assert_eq!(
            text(event(&replayed, "report_replayed"), "certificate"),
            &locator[2..]
        );
        assert_eq!(std::fs::read(output).unwrap(), expected_output);
        if supports_status {
            let mut args = vec!["certificate", "status", &locator];
            if let Some(expected) = &expectation {
                args.extend(["--expect", expected]);
            }
            let status = held(&mut book, &f.dir, &args, Stdin::Missing);
            let receipt = data(&status, "certificate_status");
            assert_eq!(text(receipt, "status"), "SupersededBy");
            assert_eq!(
                receipt
                    .get("later_entries")
                    .and_then(Json::as_arr)
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                receipt.get("checked_at"),
                Some(&Json::Int(i128::from(later_head.0)))
            );
        }
        assert_eq!(book.head().unwrap(), later_head);
    }
}

#[test]
fn gl_certification_refuses_missing_produce_authority_and_unsupported_lot_certification() {
    let f = Fixture::new();
    let before = f.head();
    let authority = fa_cli::authority::LaunchAuthority::new(
        f.dir.clone(),
        None,
        "gl-reader",
        fa_cli::authority::LaunchProfile::Agent,
        &["read"],
    )
    .unwrap();
    let args = [
        "gl",
        "detail",
        "--account",
        "1000",
        "--from",
        "2026-01-01",
        "--to",
        "2026-01-31",
        "--certify",
        "--json",
    ]
    .map(String::from);
    let (code, captured) =
        fa_cli::entry::fa_with_authority(&args, Files::default(), &authority, true);
    assert_eq!(code, 7, "{}{}", captured.stdout, captured.stderr);
    let errors = parse_events(&captured.stdout);
    assert_eq!(errors.len(), 1);
    assert_eq!(text(&errors[0], "event"), "error");
    assert!(captured.stdout.contains("produce"));
    let (code, errors) = f.run(&["gl", "lots", "--certify"]);
    assert_eq!(code, 2, "{errors:?}");
    assert_eq!(errors.len(), 1);
    // Held dispatch avoids the operating system's argv limit. The transport
    // bound must fail before reading even a nonexistent certificate file.
    {
        let mut book = f.open();
        let output = f.dir.join("oversized-expectation.report");
        let argv = vec![
            "replay".into(),
            "missing.certificate".into(),
            "--expect".into(),
            " ".repeat(1024 * 1024 + 1),
            "--output".into(),
            output.to_str().unwrap().into(),
            "--book".into(),
            f.dir.to_str().unwrap().into(),
            "--json".into(),
        ];
        let (code, captured) = cli::run(
            &argv,
            Books::Held {
                book: &mut book,
                dir: f.dir.clone(),
            },
            Files {
                cwd: None,
                stdin: Stdin::Forwarded(Vec::new()),
            },
            true,
        );
        assert_eq!(code, 2, "{}{}", captured.stdout, captured.stderr);
        assert!(captured.stdout.contains("1 MiB"), "{}", captured.stdout);
        assert_eq!(parse_events(&captured.stdout).len(), 1);
        assert!(!output.exists());
        assert_eq!(book.head().unwrap(), before);
    }
    assert_eq!(f.head(), before);
}

#[test]
fn cash_flow_policy_typos_refuse_before_retention_and_optional_defaults_still_work() {
    let f = Fixture::new();
    let at = f.source_head.0.to_string();
    let baseline = f.ok(&[
        "gl",
        "detail",
        "--account",
        "1000,4000",
        "--from",
        "2026-01-01",
        "--to",
        "2026-01-31",
        "--as-known-at",
        &at,
    ]);
    let lines = data(&baseline, "general_ledger")
        .get("lines")
        .and_then(Json::as_arr)
        .unwrap();
    let assignments: Vec<Json> = lines
        .iter()
        .filter(|line| text(line, "account") == "1000")
        .map(|line| {
            obj(vec![
                ("entry_digest", line.get("entry_digest").unwrap().clone()),
                ("leg_index", line.get("leg_index").unwrap().clone()),
                ("activity", s("operating")),
            ])
        })
        .collect();
    assert_eq!(assignments.len(), 64);
    // The two distinct, equal revenue legs have opposite adjustment signs.
    // Their cited contributions cancel exactly; this is a valid indirect
    // control case without changing the earnings-to-cash reconciliation.
    let adjustments: Vec<Json> = lines
        .iter()
        .filter(|line| text(line, "account") == "4000")
        .take(2)
        .enumerate()
        .map(|(index, line)| {
            obj(vec![
                ("entry_digest", line.get("entry_digest").unwrap().clone()),
                ("leg_index", line.get("leg_index").unwrap().clone()),
                ("category", s("non_operating")),
                (
                    "sign",
                    s(if index == 0 {
                        "debit_minus_credit"
                    } else {
                        "credit_minus_debit"
                    }),
                ),
                ("reason", s("offsetting classification control")),
            ])
        })
        .collect();
    assert_eq!(adjustments.len(), 2);
    let direct = obj(vec![("assignments", Json::Arr(assignments.clone()))]);
    let indirect = obj(vec![
        ("assignments", Json::Arr(assignments.clone())),
        ("adjustments", Json::Arr(adjustments.clone())),
    ]);
    let policy_path = f.dir.join("checked-policy.json");
    let run_args = |indirect: bool, empty_period: bool| {
        let mut args = vec![
            "gl",
            "cash-flow",
            "--account",
            "1000",
            "--from",
            if empty_period {
                "2026-02-01"
            } else {
                "2026-01-01"
            },
            "--to",
            if empty_period {
                "2026-02-28"
            } else {
                "2026-01-31"
            },
            "--as-known-at",
            at.as_str(),
            "--policy",
            policy_path.to_str().unwrap(),
        ];
        if indirect {
            args.extend([
                "--indirect",
                "--income-period",
                if empty_period {
                    "FY2026-P02"
                } else {
                    "FY2026-OPEN,FY2026-P01"
                },
            ]);
        }
        args
    };
    // Names, cash_accounts, assignments, cash_policy, and adjustments retain
    // their existing optional defaults when the period has no cash movement.
    for indirect_mode in [false, true] {
        std::fs::write(&policy_path, "{}").unwrap();
        let events = f.ok(&run_args(indirect_mode, true));
        let name = if indirect_mode {
            "indirect_cash_flow"
        } else {
            "cash_flow"
        };
        assert_eq!(
            text(data(&events, name), "policy"),
            if indirect_mode {
                "indirect-cash-flow"
            } else {
                "cash-flow"
            },
        );
    }
    // Both complete control policies also work with their optional names
    // and cash account lists omitted.
    for (indirect_mode, policy) in [(false, &direct), (true, &indirect)] {
        std::fs::write(&policy_path, policy.render()).unwrap();
        f.ok(&run_args(indirect_mode, false));
    }
    let before = f.head();
    assert_eq!(before, f.source_head);
    let add_field = |doc: &Json, key: &str, value: Json| {
        let Json::Obj(mut fields) = doc.clone() else {
            panic!("object");
        };
        fields.push((key.into(), value));
        Json::Obj(fields)
    };
    let direct_only_violation = add_field(&direct, "cash_policy", s("indirect-only"));
    let indirect_typo = add_field(&indirect, "classification_override", Json::Bool(true));
    let mut mistyped_assignments = assignments;
    mistyped_assignments[0] = add_field(
        &mistyped_assignments[0],
        "activity_override",
        s("investing"),
    );
    let assignment_typo = obj(vec![("assignments", Json::Arr(mistyped_assignments))]);
    let mut mistyped_adjustments = adjustments;
    mistyped_adjustments[0] = add_field(
        &mistyped_adjustments[0],
        "sign_override",
        s("credit_minus_debit"),
    );
    let Json::Obj(mut indirect_fields) = indirect else {
        panic!("indirect policy object");
    };
    for (name, value) in &mut indirect_fields {
        if name == "adjustments" {
            *value = Json::Arr(mistyped_adjustments.clone());
        }
    }
    let adjustment_typo = Json::Obj(indirect_fields);
    for (indirect_mode, bad_field, policy) in [
        (false, "cash_policy", direct_only_violation),
        (true, "classification_override", indirect_typo),
        (false, "activity_override", assignment_typo),
        (true, "sign_override", adjustment_typo),
    ] {
        std::fs::write(&policy_path, policy.render()).unwrap();
        let output = f.dir.join(format!("{bad_field}.certificate"));
        let mut args = run_args(indirect_mode, false);
        args.extend(["--certificate-out", output.to_str().unwrap()]);
        let (code, errors) = f.run(&args);
        assert_eq!(code, 2, "{bad_field}: {errors:?}");
        assert_eq!(errors.len(), 1, "{bad_field}: {errors:?}");
        let error = errors[0].render();
        assert!(
            error.contains("unknown") && error.contains(bad_field),
            "{error}"
        );
        assert!(
            !output.exists(),
            "{bad_field}: no external certificate may be created"
        );
        assert_eq!(f.head(), before, "{bad_field}: no artifact may be retained");
    }
}

/// Field names the pinned robot schema declares for one event or shape.
fn pinned_fields(kind: &str, name: &str) -> Vec<String> {
    let row = json::parse(include_str!("../../../registries/robot_schema/1.jsonl").trim_end())
        .expect("the pin is one JSON line");
    let entry = row
        .get("data")
        .and_then(|data| data.get(kind))
        .and_then(Json::as_arr)
        .expect("pinned list")
        .iter()
        .find(|entry| text(entry, "name") == name)
        .unwrap_or_else(|| panic!("{name} is not a pinned {kind} entry"));
    let mut names: Vec<String> = entry
        .get("fields")
        .and_then(Json::as_arr)
        .expect("pinned fields")
        .iter()
        .map(|field| text(field, "name").to_string())
        .collect();
    names.sort();
    names
}

fn keys(value: &Json) -> Vec<String> {
    let Json::Obj(fields) = value else {
        panic!("expected an object: {value:?}");
    };
    let mut names: Vec<String> = fields.iter().map(|(name, _)| name.clone()).collect();
    names.sort();
    names
}

fn account_codes(value: &Json, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Json::as_arr)
        .unwrap_or_else(|| panic!("missing {key}: {value:?}"))
        .iter()
        .map(|account| text(account, "account").to_string())
        .collect()
}

fn portfolio_args<'a>(at: &'a str, selection: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "gl",
        "aging",
        "--as-of",
        "2026-01-31",
        "--as-known-at",
        at,
        "--reconcile",
    ];
    args.extend_from_slice(selection);
    args
}

#[test]
fn aging_portfolio_equals_each_single_leaf_reconciliation_and_replays_only_against_its_request() {
    // 1000 and 4000 carry 64 postings; 2000 and 2001 are zero-activity leaves.
    let f = Fixture::with_additional_cash_accounts(2);
    let at = f.source_head.0.to_string();
    let before = f.head();

    let whole_events = f.ok(&portfolio_args(&at, &["--all-posting"]));
    let whole = data(&whole_events, "aging_portfolio_reconciled");
    assert_eq!(
        keys(whole),
        pinned_fields("events", "aging_portfolio_reconciled")
    );
    assert_eq!(text(whole, "scope"), "all-posting");
    assert_eq!(
        whole.get("known_at"),
        Some(&Json::Int(i128::from(f.source_head.0)))
    );
    assert_eq!(text(whole, "effective_through"), "2026-01-31");
    assert_eq!(
        account_codes(whole, "accounts"),
        ["1000", "2000", "2001", "4000"],
        "every posting leaf in code order, zero-activity leaves included"
    );
    assert!(account_codes(whole, "uncovered").is_empty());
    assert_eq!(whole.get("complete"), Some(&Json::Bool(true)));
    let accounts = whole.get("accounts").and_then(Json::as_arr).unwrap();
    let cash_rows = accounts[0].get("rows").and_then(Json::as_arr).unwrap();
    assert_eq!(cash_rows.len(), 1, "{cash_rows:?}");
    assert_eq!(text(&cash_rows[0], "posted_net"), "64.00 USD");

    // Differential: each portfolio account is exactly the single-leaf
    // reconciliation of that account at the same coordinate.
    let mut every_reconciled = true;
    for account in accounts {
        assert_eq!(
            keys(account),
            pinned_fields("shapes", "aging_portfolio_account")
        );
        let code = text(account, "account");
        let single_events = f.ok(&portfolio_args(&at, &["--account", code]));
        assert!(
            single_events
                .iter()
                .all(|row| text(row, "event") != "aging_portfolio_reconciled"),
            "one code keeps the single-leaf report"
        );
        let single = data(&single_events, "aging_reconciled");
        for field in ["account_vid", "name", "reconciled", "rows", "item_count"] {
            assert_eq!(
                account.get(field),
                single.get(field),
                "{code}.{field} differs from its single-leaf reconciliation"
            );
        }
        assert_eq!(single.get("known_at"), whole.get("known_at"));
        every_reconciled &= account.get("reconciled") == Some(&Json::Bool(true));
    }
    assert_eq!(whole.get("reconciled"), Some(&Json::Bool(every_reconciled)));

    // A selection is order-free; unselected leaves are uncovered, not zero.
    let selected_events = f.ok(&portfolio_args(&at, &["--account", "4000,1000"]));
    let selected = data(&selected_events, "aging_portfolio_reconciled");
    // Repeated --account flags select the same leaves as a comma list, as in
    // the other gl subcommands; none of them is silently dropped.
    let repeated_events = f.ok(&portfolio_args(
        &at,
        &["--account", "4000", "--account", "1000"],
    ));
    assert_eq!(
        data(&repeated_events, "aging_portfolio_reconciled"),
        selected
    );
    assert_eq!(text(selected, "scope"), "selected");
    assert_eq!(account_codes(selected, "accounts"), ["1000", "4000"]);
    assert_eq!(account_codes(selected, "uncovered"), ["2000", "2001"]);
    assert_eq!(selected.get("complete"), Some(&Json::Bool(false)));
    for account in selected.get("accounts").and_then(Json::as_arr).unwrap() {
        assert!(
            accounts.contains(account),
            "a selected account reports what the whole book reports: {account:?}"
        );
    }
    for uncovered in selected.get("uncovered").and_then(Json::as_arr).unwrap() {
        assert_eq!(
            keys(uncovered),
            pinned_fields("shapes", "aging_portfolio_uncovered")
        );
    }

    for (selection, why) in [
        (vec!["--account", "1000,1000"], "a repeated leaf"),
        (vec!["--account", "1000,9999"], "an unknown leaf"),
        (vec!["--account", "1000,"], "an empty code"),
        (
            vec!["--account", "1000,2000", "--all-posting"],
            "two selections",
        ),
        (vec![], "a missing selection is never the whole book"),
    ] {
        let (exit, errors) = f.run(&portfolio_args(&at, &selection));
        assert_eq!(exit, 2, "{why}: {errors:?}");
        assert_eq!(errors.len(), 1, "{why}: {errors:?}");
        assert_eq!(text(&errors[0], "event"), "error");
    }
    let (exit, errors) = f.run(&["gl", "aging", "--as-of", "2026-01-31", "--all-posting"]);
    assert_eq!(exit, 2, "--all-posting without --reconcile: {errors:?}");
    for accounts in [
        vec!["--account", "1000", "--account", "4000"],
        vec!["--account", "1000,4000"],
    ] {
        let mut args = vec!["gl", "aging", "--as-of", "2026-01-31"];
        args.extend(accounts);
        let (exit, errors) = f.run(&args);
        assert_eq!(
            exit, 2,
            "plain aging takes one account, never silently the last: {errors:?}"
        );
    }
    assert_eq!(
        f.head(),
        before,
        "uncertified portfolios and refusals are reads"
    );

    let certified = f.ok(&portfolio_args(
        &at,
        &["--account", "4000,1000", "--certify"],
    ));
    assert_eq!(
        data(&certified, "aging_portfolio_reconciled"),
        selected,
        "certification reports the same portfolio"
    );
    let metadata = data(&certified, "report_certificate");
    assert_eq!(text(metadata, "output_format"), "fa:aging-portfolio:v1");
    let locator = format!("C:{}", text(metadata, "oid"));
    let generated = text(metadata, "replay_command")
        .split_once(" --expect '")
        .unwrap()
        .1
        .split_once("' --book")
        .unwrap()
        .0
        .to_string();
    let expectation = json::parse(&generated).unwrap();
    assert_eq!(text(&expectation, "kind"), "aging-portfolio");
    assert_eq!(text(&expectation, "scope"), "selected");
    assert_eq!(
        expectation
            .get("accounts")
            .and_then(Json::as_arr)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        expectation.get("known_at"),
        Some(&Json::Int(i128::from(f.source_head.0)))
    );
    let retained = f.head();
    let replayed = f.ok(&["replay", &locator, "--expect", &generated]);
    assert_eq!(
        text(data(&replayed, "report_replayed"), "family"),
        "aging-portfolio"
    );

    let (exit, errors) = f.run(&["replay", &locator]);
    assert_eq!(exit, 8, "{errors:?}");
    let refusal = data(&errors, "error");
    assert!(
        text(refusal, "message").contains("aging-portfolio report certificates replay only"),
        "{refusal:?}"
    );
    assert!(text(refusal, "fix").contains("--expect"), "{refusal:?}");
    let Json::Obj(fields) = &expectation else {
        panic!("expected an object");
    };
    let changed = |key: &str, value: Option<Json>| {
        Json::Obj(
            fields
                .iter()
                .filter_map(|(name, original)| {
                    if name == key {
                        value.clone().map(|value| (name.clone(), value))
                    } else {
                        Some((name.clone(), original.clone()))
                    }
                })
                .collect(),
        )
        .render()
    };
    let whole_scope = {
        let Json::Obj(mut fields) = expectation.clone() else {
            panic!("expected an object");
        };
        fields.retain(|(name, _)| name != "accounts");
        for (name, value) in &mut fields {
            if name == "scope" {
                *value = s("all-posting");
            }
        }
        Json::Obj(fields).render()
    };
    for (expect, exit, why) in [
        (
            changed("through", Some(s("2026-01-30"))),
            8,
            "a different cutoff",
        ),
        (whole_scope, 8, "the whole book is a different question"),
        (
            changed("known_at", Some(s("HEAD"))),
            2,
            "HEAD is never an expected prefix",
        ),
        (
            changed("accounts", None),
            2,
            "a selected scope without accounts",
        ),
    ] {
        let (code, errors) = f.run(&["replay", &locator, "--expect", &expect]);
        assert_eq!(code, exit, "{why}: {errors:?}");
        assert_eq!(errors.len(), 1, "{why}");
    }
    assert_eq!(f.head(), retained, "replays are reads");
}

/// The fields of one JSON object, as `Json::Obj` holds them.
type JsonFields = Vec<(String, Json)>;

fn cash_flow_args<'a>(at: &'a str, policy: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "gl",
        "cash-flow",
        "--account",
        "1000",
        "--from",
        "2026-01-01",
        "--to",
        "2026-01-31",
        "--as-known-at",
        at,
        "--policy",
        policy,
    ];
    args.extend_from_slice(extra);
    args
}

#[test]
fn rule_policy_cash_flow_equals_its_explicit_leg_assignments_and_replays_only_against_its_policy() {
    // Every posting is Dr 1000 (cash) / Cr 4000 (revenue), 1.00 USD each.
    let f = Fixture::new();
    let at = f.source_head.0.to_string();
    let before = f.head();
    let policy_path = f.dir.join("rule-policy.json");
    let policy_arg = policy_path.to_str().unwrap();
    let rules = || {
        Json::Arr(vec![obj(vec![
            ("account", s("4000")),
            ("activity", s("operating")),
        ])])
    };
    std::fs::write(
        &policy_path,
        obj(vec![
            ("name", s("cash-rules-v1")),
            ("account_rules", rules()),
        ])
        .render(),
    )
    .unwrap();
    let derived_events = f.ok(&cash_flow_args(&at, policy_arg, &[]));
    let derived = data(&derived_events, "policy_cash_flow");
    assert_eq!(keys(derived), pinned_fields("events", "policy_cash_flow"));
    assert_eq!(text(derived, "policy"), "cash-rules-v1");
    let decisions = derived.get("decisions").and_then(Json::as_arr).unwrap();
    assert_eq!(decisions.len(), 64, "one decision per selected cash leg");
    for decision in decisions {
        assert_eq!(
            keys(decision),
            pinned_fields("shapes", "cash_flow_decision")
        );
        assert_eq!(text(decision, "activity"), "operating");
        assert_eq!(text(decision, "basis"), "account_rules");
    }
    let derived_units = derived.get("units").and_then(Json::as_arr).unwrap();
    assert_eq!(derived_units.len(), 1);
    assert_eq!(
        text(derived_units[0].get("operating").unwrap(), "inflows"),
        "64.00 USD"
    );

    // Differential: the same legs assigned explicitly through the direct
    // format produce exactly the same cash flow.
    let assignments: Vec<Json> = decisions
        .iter()
        .map(|decision| {
            obj(vec![
                (
                    "entry_digest",
                    decision.get("entry_digest").unwrap().clone(),
                ),
                ("leg_index", decision.get("leg_index").unwrap().clone()),
                ("activity", decision.get("activity").unwrap().clone()),
            ])
        })
        .collect();
    std::fs::write(
        &policy_path,
        obj(vec![
            ("name", s("cash-rules-v1")),
            ("assignments", Json::Arr(assignments)),
        ])
        .render(),
    )
    .unwrap();
    let explicit_events = f.ok(&cash_flow_args(&at, policy_arg, &[]));
    let explicit = data(&explicit_events, "cash_flow");
    for field in [
        "policy",
        "label",
        "known_at",
        "effective_from",
        "effective_through",
        "cash_accounts",
        "units",
    ] {
        assert_eq!(
            derived.get(field),
            explicit.get(field),
            "{field}: a rule policy must equal its explicit leg assignments"
        );
    }

    // An explicit whole-leg override takes precedence over the account rule.
    let overridden = &decisions[0];
    let override_policy = || {
        obj(vec![
            ("name", s("cash-rules-v1")),
            ("account_rules", rules()),
            (
                "overrides",
                Json::Arr(vec![obj(vec![
                    (
                        "entry_digest",
                        overridden.get("entry_digest").unwrap().clone(),
                    ),
                    ("leg_index", overridden.get("leg_index").unwrap().clone()),
                    ("activity", s("financing")),
                ])]),
            ),
        ])
    };
    std::fs::write(&policy_path, override_policy().render()).unwrap();
    let with_override_events = f.ok(&cash_flow_args(&at, policy_arg, &[]));
    let with_override = data(&with_override_events, "policy_cash_flow");
    let override_decisions: Vec<&Json> = with_override
        .get("decisions")
        .and_then(Json::as_arr)
        .unwrap()
        .iter()
        .filter(|decision| text(decision, "basis") == "override")
        .collect();
    assert_eq!(override_decisions.len(), 1);
    assert_eq!(text(override_decisions[0], "activity"), "financing");
    assert_eq!(
        override_decisions[0].get("entry_digest"),
        overridden.get("entry_digest")
    );
    let unit = &with_override.get("units").and_then(Json::as_arr).unwrap()[0];
    assert_eq!(text(unit.get("operating").unwrap(), "inflows"), "63.00 USD");
    assert_eq!(text(unit.get("financing").unwrap(), "inflows"), "1.00 USD");

    let revenue_leg = obj(vec![
        (
            "entry_digest",
            overridden.get("entry_digest").unwrap().clone(),
        ),
        ("leg_index", Json::Int(1)),
        ("activity", s("operating")),
    ]);
    for (policy, extra, why) in [
        (
            obj(vec![
                ("account_rules", rules()),
                ("assignments", Json::Arr(Vec::new())),
            ]),
            vec![],
            "a rule policy cannot also carry assignments",
        ),
        (
            obj(vec![("overrides", Json::Arr(Vec::new()))]),
            vec![],
            "overrides belong to a rule policy",
        ),
        (
            obj(vec![(
                "account_rules",
                Json::Arr(vec![obj(vec![
                    ("account", s("4000")),
                    ("activity", s("operating")),
                    ("note", s("not a policy input")),
                ])]),
            )]),
            vec![],
            "unknown rule fields are refused, not discarded",
        ),
        (
            obj(vec![(
                "account_rules",
                Json::Arr(vec![obj(vec![
                    ("account", s("9999")),
                    ("activity", s("operating")),
                ])]),
            )]),
            vec![],
            "a rule must name an existing non-cash leaf",
        ),
        (
            obj(vec![(
                "account_rules",
                Json::Arr(vec![obj(vec![
                    ("account", s("4000")),
                    ("activity", s("internal_transfer")),
                ])]),
            )]),
            vec![],
            "an internal transfer is not an account rule",
        ),
        (
            obj(vec![
                ("account_rules", rules()),
                ("overrides", Json::Arr(vec![revenue_leg])),
            ]),
            vec![],
            "an override must name a selected cash leg",
        ),
        (
            obj(vec![("account_rules", rules())]),
            vec!["--indirect", "--income-period", "FY2026-P01"],
            "a rule policy does not combine with --indirect",
        ),
    ] {
        std::fs::write(&policy_path, policy.render()).unwrap();
        let (exit, errors) = f.run(&cash_flow_args(&at, policy_arg, &extra));
        assert_eq!(exit, 2, "{why}: {errors:?}");
        assert_eq!(errors.len(), 1, "{why}: {errors:?}");
        assert_eq!(text(&errors[0], "event"), "error");
    }
    assert_eq!(
        f.head(),
        before,
        "uncertified reports and refusals are reads"
    );

    std::fs::write(&policy_path, override_policy().render()).unwrap();
    let certified = f.ok(&cash_flow_args(&at, policy_arg, &["--certify"]));
    assert_eq!(
        data(&certified, "policy_cash_flow"),
        with_override,
        "certification reports the same cash flow"
    );
    let metadata = data(&certified, "report_certificate");
    assert_eq!(text(metadata, "output_format"), "fa:policy-cash-flow:v1");
    let locator = format!("C:{}", text(metadata, "oid"));
    let generated = text(metadata, "replay_command")
        .split_once(" --expect '")
        .unwrap()
        .1
        .split_once("' --book")
        .unwrap()
        .0
        .to_string();
    let expectation = json::parse(&generated).unwrap();
    assert_eq!(text(&expectation, "kind"), "policy-cash-flow");
    let expected_policy = expectation.get("policy").unwrap();
    assert_eq!(
        expected_policy
            .get("account_rules")
            .and_then(Json::as_arr)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        expected_policy
            .get("overrides")
            .and_then(Json::as_arr)
            .unwrap()
            .len(),
        1
    );
    let retained = f.head();
    let replayed = f.ok(&["replay", &locator, "--expect", &generated]);
    assert_eq!(
        text(data(&replayed, "report_replayed"), "family"),
        "policy-cash-flow"
    );
    let status = f.ok(&["certificate", "status", &locator, "--expect", &generated]);
    assert_eq!(
        text(data(&status, "certificate_status"), "status"),
        "Current"
    );
    let (exit, errors) = f.run(&["certificate", "status", &locator]);
    assert_eq!(
        exit, 8,
        "policy freshness requires independent expectations: {errors:?}"
    );
    assert_eq!(errors.len(), 1);

    let (exit, errors) = f.run(&["replay", &locator]);
    assert_eq!(exit, 8, "{errors:?}");
    let refusal = data(&errors, "error");
    assert!(
        text(refusal, "message").contains("policy-cash-flow report certificates replay only"),
        "{refusal:?}"
    );
    assert!(text(refusal, "fix").contains("--expect"), "{refusal:?}");
    let with_policy = |edit: &dyn Fn(&mut JsonFields)| {
        let Json::Obj(mut fields) = expectation.clone() else {
            panic!("expected an object");
        };
        for (name, value) in &mut fields {
            if name == "policy" {
                let Json::Obj(policy) = value else {
                    panic!("expected a policy object");
                };
                edit(policy);
            }
        }
        Json::Obj(fields).render()
    };
    let investing_rule = with_policy(&|policy: &mut JsonFields| {
        for (name, value) in policy.iter_mut() {
            if name == "account_rules" {
                *value = Json::Arr(vec![obj(vec![
                    ("account", s("4000")),
                    ("activity", s("investing")),
                ])]);
            }
        }
    });
    let no_overrides = with_policy(&|policy: &mut JsonFields| {
        for (name, value) in policy.iter_mut() {
            if name == "overrides" {
                *value = Json::Arr(Vec::new());
            }
        }
    });
    let unknown_field = with_policy(&|policy: &mut JsonFields| {
        policy.push(("assignments".into(), Json::Arr(Vec::new())));
    });
    for (expect, exit, why) in [
        (investing_rule, 8, "a different account rule"),
        (no_overrides, 8, "a dropped override"),
        (unknown_field, 2, "a direct-format field is never discarded"),
    ] {
        let (code, errors) = f.run(&["replay", &locator, "--expect", &expect]);
        assert_eq!(code, exit, "{why}: {errors:?}");
        assert_eq!(errors.len(), 1, "{why}");
        let (code, errors) = f.run(&["certificate", "status", &locator, "--expect", &expect]);
        assert_eq!(code, exit, "freshness also refuses {why}: {errors:?}");
        assert_eq!(errors.len(), 1, "no freshness verdict after {why}");
    }
    assert_eq!(f.head(), retained, "replays are reads");
    let mut book = f.open();
    post(&mut book, 64);
    let later_head = book.head().unwrap();
    drop(book);
    let status = f.ok(&["certificate", "status", &locator, "--expect", &generated]);
    let receipt = data(&status, "certificate_status");
    assert_eq!(text(receipt, "status"), "SupersededBy");
    assert_eq!(
        receipt
            .get("later_entries")
            .and_then(Json::as_arr)
            .unwrap()
            .len(),
        1
    );
    let replayed = f.ok(&["replay", &locator, "--expect", &generated]);
    assert_eq!(
        text(data(&replayed, "report_replayed"), "family"),
        "policy-cash-flow"
    );
    assert_eq!(
        f.head(),
        later_head,
        "freshness preserves the historical policy and journal"
    );
}

#[test]
fn split_cash_flow_preserves_original_units_and_replays_exact_portions_at_its_fixed_prefix() {
    let mut f = Fixture::new();
    let mut book = f.open();
    // A mixed principal/interest outflow follows the 64 one-dollar receipts.
    // A second currency shares the same scale; it must remain a separate stock.
    post_cash_movement(&mut book, 64, "USD", 100, Side::Credit);
    post_cash_movement(&mut book, 65, "EUR", 300, Side::Debit);
    f.source_head = book.head().unwrap();
    drop(book);
    let at = f.source_head.0.to_string();
    let baseline = f.ok(&[
        "gl",
        "detail",
        "--account",
        "1000",
        "--unit",
        "USD,EUR",
        "--from",
        "2026-01-01",
        "--to",
        "2026-01-31",
        "--as-known-at",
        &at,
    ]);
    let lines = data(&baseline, "general_ledger")
        .get("lines")
        .and_then(Json::as_arr)
        .unwrap();
    assert_eq!(lines.len(), 66);
    let portion =
        |activity: &str, amount: &str| obj(vec![("activity", s(activity)), ("amount", s(amount))]);
    let splits: Vec<Json> = lines
        .iter()
        .map(|line| {
            let (reason, portions) = if text(line, "credits") == "1.00 USD" {
                (
                    "Principal and interest",
                    vec![
                        portion("financing", "0.80 USD"),
                        portion("operating", "0.20 USD"),
                    ],
                )
            } else if text(line, "debits") == "3.00 EUR" {
                (
                    "Operating receipt and asset disposal",
                    vec![
                        portion("operating", "1.00 EUR"),
                        portion("investing", "2.00 EUR"),
                    ],
                )
            } else {
                assert_eq!(text(line, "debits"), "1.00 USD");
                ("Operating receipt", vec![portion("operating", "1.00 USD")])
            };
            obj(vec![
                ("entry_digest", line.get("entry_digest").unwrap().clone()),
                ("leg_index", line.get("leg_index").unwrap().clone()),
                ("reason", s(reason)),
                ("portions", Json::Arr(portions)),
            ])
        })
        .collect();
    let policy = obj(vec![
        ("name", s("mixed-payments-v1")),
        ("cash_accounts", Json::Arr(vec![s("1000")])),
        ("splits", Json::Arr(splits.clone())),
    ]);
    // Recipient inputs are independently constructed before producing an artifact.
    let expectation = obj(vec![
        ("kind", s("split-cash-flow")),
        ("accounts", Json::Arr(vec![s("1000")])),
        ("units", Json::Arr(vec![s("USD"), s("EUR")])),
        ("label", s("cash-flow")),
        ("from", s("2026-01-01")),
        ("through", s("2026-01-31")),
        ("known_at", Json::Int(i128::from(f.source_head.0))),
        ("policy", policy.clone()),
    ]);
    let policy_path = f.dir.join("split-policy.json");
    let policy_arg = policy_path.to_str().unwrap();
    std::fs::write(&policy_path, policy.render()).unwrap();
    let before = f.head();
    let original_events = f.ok(&cash_flow_args(&at, policy_arg, &["--unit", "USD,EUR"]));
    let original = data(&original_events, "split_cash_flow");
    assert_eq!(keys(original), pinned_fields("events", "split_cash_flow"));
    let rows = original.get("splits").and_then(Json::as_arr).unwrap();
    assert_eq!(
        rows.len(),
        lines.len(),
        "portions never synthesize original cash legs"
    );
    for split in rows {
        assert_eq!(keys(split), pinned_fields("shapes", "cash_flow_leg_split"));
        for part in split.get("portions").and_then(Json::as_arr).unwrap() {
            assert_eq!(keys(part), pinned_fields("shapes", "cash_flow_portion"));
        }
    }
    let units = original.get("units").and_then(Json::as_arr).unwrap();
    assert_eq!(units.len(), 2);
    let usd = units
        .iter()
        .find(|unit| text(unit, "unit") == "USD")
        .unwrap();
    assert_eq!(text(usd, "opening"), "0.00 USD");
    assert_eq!(text(usd, "closing"), "63.00 USD");
    assert_eq!(text(usd.get("operating").unwrap(), "inflows"), "64.00 USD");
    assert_eq!(text(usd.get("operating").unwrap(), "outflows"), "0.20 USD");
    assert_eq!(text(usd.get("financing").unwrap(), "outflows"), "0.80 USD");
    assert_eq!(text(usd.get("financing").unwrap(), "net"), "-0.80 USD");
    let eur = units
        .iter()
        .find(|unit| text(unit, "unit") == "EUR")
        .unwrap();
    assert_eq!(text(eur, "closing"), "3.00 EUR");
    assert_eq!(text(eur.get("operating").unwrap(), "net"), "1.00 EUR");
    assert_eq!(text(eur.get("investing").unwrap(), "net"), "2.00 EUR");

    let mut held_book = f.open();
    let held_events = held(
        &mut held_book,
        &f.dir,
        &cash_flow_args(&at, "-", &["--unit", "USD,EUR"]),
        Stdin::Forwarded(policy.render().into_bytes()),
    );
    assert_eq!(data(&held_events, "split_cash_flow"), original);
    drop(held_book);
    assert_eq!(
        f.head(),
        before,
        "ordinary direct and held reports are read-only"
    );

    fn replace(value: &Json, key: &str, replacement: Json) -> Json {
        let Json::Obj(mut fields) = value.clone() else {
            panic!("expected object")
        };
        let field = fields.iter_mut().find(|(name, _)| name == key).unwrap();
        field.1 = replacement;
        Json::Obj(fields)
    }
    let receipt_index = lines
        .iter()
        .position(|line| text(line, "debits") == "1.00 USD")
        .unwrap();
    let with_receipt = |replacement: Json| {
        let mut changed = splits.clone();
        changed[receipt_index] = replacement;
        replace(&policy, "splits", Json::Arr(changed))
    };
    let receipt = &splits[receipt_index];
    let currency_substitution = with_receipt(replace(
        receipt,
        "portions",
        Json::Arr(vec![portion("operating", "1.00 EUR")]),
    ));
    let mut unknown_fields = match policy.clone() {
        Json::Obj(fields) => fields,
        _ => unreachable!(),
    };
    unknown_fields.push(("account_rules".into(), Json::Arr(Vec::new())));
    let mut repeated = splits.clone();
    repeated.push(receipt.clone());
    let mut omitted = splits.clone();
    omitted.pop();
    let refusals = vec![
        (
            currency_substitution.clone(),
            vec![],
            "same-scale EUR cannot replace a USD leg",
        ),
        (
            with_receipt(replace(
                receipt,
                "portions",
                Json::Arr(vec![portion("operating", "0.99 USD")]),
            )),
            vec![],
            "the partition must total the original leg",
        ),
        (
            with_receipt(replace(
                receipt,
                "portions",
                Json::Arr(vec![
                    portion("operating", "0.50 USD"),
                    portion("operating", "0.50 USD"),
                ]),
            )),
            vec![],
            "each activity occurs once",
        ),
        (
            with_receipt(replace(receipt, "leg_index", Json::Int(1))),
            vec![],
            "a non-cash counterpart is outside scope",
        ),
        (
            with_receipt(replace(receipt, "reason", s(""))),
            vec![],
            "a split reason is mandatory",
        ),
        (
            with_receipt(replace(
                receipt,
                "portions",
                Json::Arr(vec![obj(vec![
                    ("activity", s("operating")),
                    ("amount", Json::Int(1)),
                ])]),
            )),
            vec![],
            "amounts must name the native unit",
        ),
        (
            replace(&policy, "splits", Json::Arr(repeated)),
            vec![],
            "a cash leg cannot be repeated",
        ),
        (
            replace(&policy, "splits", Json::Arr(omitted)),
            vec![],
            "every selected cash leg needs a split",
        ),
        (
            Json::Obj(unknown_fields),
            vec![],
            "formats cannot mix classification fields",
        ),
        (
            policy.clone(),
            vec!["--indirect", "--income-period", PERIOD],
            "split and indirect formats cannot mix",
        ),
    ];
    for (index, (invalid_policy, extra, why)) in refusals.into_iter().enumerate() {
        std::fs::write(&policy_path, invalid_policy.render()).unwrap();
        let path = f.dir.join(format!("refused-split-{index}.cert"));
        let mut args = cash_flow_args(&at, policy_arg, &["--unit", "USD,EUR"]);
        args.extend(["--certificate-out", path.to_str().unwrap()]);
        args.extend(extra);
        let (exit, errors) = f.run(&args);
        assert_eq!(exit, 2, "{why}: {errors:?}");
        assert_eq!(errors.len(), 1, "{why}: only the refusal is emitted");
        assert!(
            !path.exists(),
            "{why}: failed policy cannot create a certificate file"
        );
        assert_eq!(
            f.head(),
            before,
            "{why}: failed policy cannot retain a certificate"
        );
    }

    std::fs::write(&policy_path, policy.render()).unwrap();
    let cert_path = f.dir.join("split.cert");
    let certified = f.ok(&cash_flow_args(
        "HEAD",
        policy_arg,
        &[
            "--unit",
            "USD,EUR",
            "--certificate-out",
            cert_path.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        data(&certified, "split_cash_flow"),
        original,
        "HEAD was fixed before retention"
    );
    let metadata = data(&certified, "report_certificate");
    assert_eq!(text(metadata, "output_format"), "fa:cash-flow-split:v1");
    let bytes = std::fs::read(&cert_path).unwrap();
    assert_eq!(bytes, unhex(text(metadata, "bytes")));
    let certificate = fa::cash_flow_split::CashFlowSplitCertificate::decode(&bytes).unwrap();
    assert_eq!(certificate.known_at(), f.source_head);
    let locator = format!("C:{}", text(metadata, "oid"));
    let retained = f.head();
    let retry = f.ok(&cash_flow_args(
        &at,
        policy_arg,
        &["--unit", "USD,EUR", "--certify"],
    ));
    assert_eq!(
        text(data(&retry, "report_certificate"), "oid"),
        text(metadata, "oid")
    );
    assert_eq!(
        f.head(),
        retained,
        "same-prefix certification retry is idempotent"
    );

    for (index, input) in [locator.as_str(), cert_path.to_str().unwrap()]
        .into_iter()
        .enumerate()
    {
        let output = f.dir.join(format!("split-replay-{index}.bin"));
        let replayed = f.ok(&[
            "replay",
            input,
            "--expect",
            &expectation.render(),
            "--output",
            output.to_str().unwrap(),
        ]);
        assert_eq!(
            text(data(&replayed, "report_replayed"), "family"),
            "split-cash-flow"
        );
        assert_eq!(std::fs::read(output).unwrap(), certificate.output());
    }
    let current = f.ok(&[
        "certificate",
        "status",
        &locator,
        "--expect",
        &expectation.render(),
    ]);
    assert_eq!(
        text(data(&current, "certificate_status"), "status"),
        "Current"
    );
    let (exit, errors) = f.run(&["certificate", "status", &locator]);
    assert_eq!(
        exit, 8,
        "split freshness requires independent expectations: {errors:?}"
    );
    assert_eq!(errors.len(), 1);

    let (exit, errors) = f.run(&["replay", &locator]);
    assert_eq!(
        exit, 8,
        "a delivered split definition cannot supply recipient expectations: {errors:?}"
    );
    assert!(text(data(&errors, "error"), "fix").contains("--expect"));

    let changed_activity = with_receipt(replace(
        receipt,
        "portions",
        Json::Arr(vec![portion("financing", "1.00 USD")]),
    ));
    let changed_reason = with_receipt(replace(
        receipt,
        "reason",
        s("Different accounting judgment"),
    ));
    for (expected, code, why) in [
        (
            replace(&expectation, "policy", currency_substitution),
            8,
            "recipient EUR/USD substitution",
        ),
        (
            replace(&expectation, "policy", changed_activity),
            8,
            "same cash stock, different activity",
        ),
        (
            replace(&expectation, "policy", changed_reason),
            8,
            "same amounts, different reason",
        ),
        (
            replace(&expectation, "known_at", s("HEAD")),
            2,
            "recipient requires fixed prefix",
        ),
        (
            replace(&expectation, "through", s("2026-01-30")),
            8,
            "different date window",
        ),
    ] {
        let (actual, errors) = f.run(&["replay", &locator, "--expect", &expected.render()]);
        assert_eq!(actual, code, "{why}: {errors:?}");
        assert_eq!(errors.len(), 1, "{why}");
        let (actual, errors) = f.run(&[
            "certificate",
            "status",
            &locator,
            "--expect",
            &expected.render(),
        ]);
        assert_eq!(actual, code, "freshness refuses {why}: {errors:?}");
        assert_eq!(errors.len(), 1, "no freshness verdict after {why}");
    }
    assert_eq!(f.head(), retained, "all replays and refusals are read-only");
    let mut book = f.open();
    post(&mut book, 900);
    let later = book.head().unwrap();
    drop(book);
    let output = f.dir.join("split-after-backdate.bin");
    f.ok(&[
        "replay",
        &locator,
        "--expect",
        &expectation.render(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(std::fs::read(output).unwrap(), certificate.output());
    let changed_prefix = replace(&expectation, "known_at", Json::Int(i128::from(later.0)));
    let (exit, errors) = f.run(&["replay", &locator, "--expect", &changed_prefix.render()]);
    assert_eq!(
        exit, 8,
        "later native source is a different request: {errors:?}"
    );
    let status = f.ok(&[
        "certificate",
        "status",
        &locator,
        "--expect",
        &expectation.render(),
    ]);
    let receipt = data(&status, "certificate_status");
    assert_eq!(text(receipt, "status"), "SupersededBy");
    assert_eq!(
        receipt
            .get("later_entries")
            .and_then(Json::as_arr)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        receipt.get("checked_at"),
        Some(&Json::Int(i128::from(later.0)))
    );
    assert_eq!(f.head(), later, "freshness never publishes");
}

fn generated_expectation(metadata: &Json) -> String {
    text(metadata, "replay_command")
        .split_once(" --expect '")
        .unwrap()
        .1
        .split_once("' --book")
        .unwrap()
        .0
        .to_string()
}

#[test]
fn replay_workpapers_equal_the_library_export_and_never_overwrite_or_widen_families() {
    let f = Fixture::with_additional_cash_accounts(1);
    let at = f.source_head.0.to_string();
    let operator = fa_model::principal_vid("operator");
    let read_produce = Capability::embedded(operator, &["read", "produce"]).unwrap();

    // Aging portfolio: the file is exactly the library's export of the same
    // certificate and request, and writing it publishes nothing.
    let certified = f.ok(&portfolio_args(
        &at,
        &["--account", "4000,1000", "--certify"],
    ));
    let metadata = data(&certified, "report_certificate");
    let locator = format!("C:{}", text(metadata, "oid"));
    let expect = generated_expectation(metadata);
    let portfolio_path = f.dir.join("portfolio.jsonl");
    let retained = f.head();
    let events = f.ok(&[
        "replay",
        &locator,
        "--expect",
        &expect,
        "--workpaper-out",
        portfolio_path.to_str().unwrap(),
    ]);
    let exported = data(&events, "workpaper_exported");
    assert_eq!(
        keys(exported),
        pinned_fields("events", "workpaper_exported")
    );
    assert_eq!(text(exported, "family"), "aging-portfolio");
    assert_eq!(text(exported, "file"), portfolio_path.to_str().unwrap());
    let written = std::fs::read_to_string(&portfolio_path).unwrap();
    assert_eq!(
        exported.get("bytes"),
        Some(&Json::Int(written.len() as i128))
    );
    assert_eq!(
        exported.get("lines"),
        Some(&Json::Int(written.lines().count() as i128))
    );
    assert!(written.lines().count() > 1, "{written}");
    for line in written.lines() {
        assert!(matches!(json::parse(line), Ok(Json::Obj(_))), "{line}");
    }
    let certificate =
        fa::aging::portfolio::AgingPortfolioCertificate::decode(&unhex(text(metadata, "bytes")))
            .unwrap();
    {
        let book = f.open();
        let library = book
            .aging_portfolio_jsonl(
                operator,
                &read_produce,
                &certificate,
                &certificate.request().unwrap(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(written, library, "the CLI writes the library's export");
    }
    assert_eq!(exported.get("text"), Some(&Json::Null));
    // Inline: the same text in the event, which is the form MCP carries.
    let inline_events = f.ok(&["replay", &locator, "--expect", &expect, "--workpaper"]);
    let inline = data(&inline_events, "workpaper_exported");
    assert_eq!(inline.get("file"), Some(&Json::Null));
    assert_eq!(text(inline, "text"), written);
    let both = f.dir.join("both.jsonl");
    let (exit, _) = f.run(&[
        "replay",
        &locator,
        "--expect",
        &expect,
        "--workpaper",
        "--workpaper-out",
        both.to_str().unwrap(),
    ]);
    assert_eq!(exit, 2, "inline and file workpapers are one choice");
    assert!(!both.exists());
    assert_eq!(f.head(), retained, "exporting a workpaper is a read");

    // An existing file is never replaced; without its request the replay is
    // refused before any file appears.
    let (exit, _) = f.run(&[
        "replay",
        &locator,
        "--expect",
        &expect,
        "--workpaper-out",
        portfolio_path.to_str().unwrap(),
    ]);
    assert_eq!(exit, 2);
    assert_eq!(std::fs::read_to_string(&portfolio_path).unwrap(), written);
    let absent = f.dir.join("unexpected.jsonl");
    let (exit, _) = f.run(&[
        "replay",
        &locator,
        "--workpaper-out",
        absent.to_str().unwrap(),
    ]);
    assert_eq!(exit, 8);
    assert!(!absent.exists());

    // Effective-date aging: the receipt now carries its request, a supplied
    // request binds the replay, and the aging workpaper needs it.
    let certified = f.ok(&[
        "gl",
        "aging",
        "--account",
        "1000",
        "--as-of",
        "2026-01-31",
        "--bucket",
        "0,30,60",
        "--as-known-at",
        &at,
        "--certify",
    ]);
    let aging_metadata = data(&certified, "report_certificate");
    let aging_locator = format!("C:{}", text(aging_metadata, "oid"));
    let aging_expect = generated_expectation(aging_metadata);
    let aging_doc = json::parse(&aging_expect).unwrap();
    assert_eq!(text(&aging_doc, "kind"), "aging");
    assert_eq!(
        aging_doc.get("known_at"),
        Some(&Json::Int(i128::from(f.source_head.0)))
    );
    let as_supplied = f.ok(&["replay", &aging_locator]);
    let bound = f.ok(&["replay", &aging_locator, "--expect", &aging_expect]);
    assert_eq!(
        data(&bound, "aging"),
        data(&as_supplied, "aging"),
        "binding the recipient's request changes no amount"
    );
    let Json::Obj(fields) = aging_doc.clone() else {
        panic!("expected an object");
    };
    let earlier_cutoff = Json::Obj(
        fields
            .into_iter()
            .map(|(name, value)| {
                if name == "through" {
                    (name, s("2026-01-30"))
                } else {
                    (name, value)
                }
            })
            .collect(),
    )
    .render();
    let (exit, errors) = f.run(&["replay", &aging_locator, "--expect", &earlier_cutoff]);
    assert_eq!(exit, 8, "a different recipient question: {errors:?}");
    let (exit, errors) = f.run(&["replay", &locator, "--expect", &aging_expect]);
    assert_eq!(exit, 8, "{errors:?}");
    assert!(
        text(data(&errors, "error"), "message").contains("an aging expectation names"),
        "an aging request on another family is refused, never ignored: {errors:?}"
    );
    let aging_path = f.dir.join("aging.jsonl");
    let events = f.ok(&[
        "replay",
        &aging_locator,
        "--expect",
        &aging_expect,
        "--workpaper-out",
        aging_path.to_str().unwrap(),
    ]);
    assert_eq!(
        text(data(&events, "workpaper_exported"), "family"),
        "effective-date-aging"
    );
    let written_aging = std::fs::read_to_string(&aging_path).unwrap();
    let aging_certificate =
        fa::AgingCertificate::decode(&unhex(text(aging_metadata, "bytes"))).unwrap();
    {
        let book = f.open();
        let library = book
            .effective_date_aging_jsonl(
                operator,
                &read_produce,
                &aging_certificate,
                &aging_certificate.request().unwrap(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            written_aging, library,
            "the CLI writes the library's export"
        );
    }
    let unbound = f.dir.join("aging-unbound.jsonl");
    let (exit, _) = f.run(&[
        "replay",
        &aging_locator,
        "--workpaper-out",
        unbound.to_str().unwrap(),
    ]);
    assert_eq!(exit, 2, "an aging workpaper needs the recipient's request");
    assert!(!unbound.exists());

    // Direct cash flow: a policy classifies every cash leg, and the export
    // binds the request the receipt prints.
    let ledger = f.ok(&[
        "gl",
        "detail",
        "--account",
        "1000",
        "--unit",
        "USD",
        "--from",
        "2026-01-01",
        "--to",
        "2026-01-31",
        "--as-known-at",
        &at,
    ]);
    let assignments: Vec<Json> = data(&ledger, "general_ledger")
        .get("lines")
        .and_then(Json::as_arr)
        .unwrap()
        .iter()
        .map(|line| {
            obj(vec![
                ("entry_digest", line.get("entry_digest").unwrap().clone()),
                ("leg_index", line.get("leg_index").unwrap().clone()),
                ("activity", s("operating")),
            ])
        })
        .collect();
    assert_eq!(assignments.len(), 64);
    let policy_path = f.dir.join("workpaper-cash-policy.json");
    let policy = obj(vec![
        ("name", s("cash-policy")),
        ("cash_accounts", Json::Arr(vec![s("1000")])),
        ("assignments", Json::Arr(assignments)),
    ]);
    std::fs::write(&policy_path, policy.render()).unwrap();
    let certified = f.ok(&cash_flow_args(
        &at,
        policy_path.to_str().unwrap(),
        &["--certify"],
    ));
    let cash = data(&certified, "report_certificate");
    let cash_locator = format!("C:{}", text(cash, "oid"));
    let cash_expect = generated_expectation(cash);
    let cash_path = f.dir.join("cash.jsonl");
    let events = f.ok(&[
        "replay",
        &cash_locator,
        "--expect",
        &cash_expect,
        "--workpaper-out",
        cash_path.to_str().unwrap(),
    ]);
    assert_eq!(
        text(data(&events, "workpaper_exported"), "family"),
        "cash-flow"
    );
    let written_cash = std::fs::read_to_string(&cash_path).unwrap();
    assert!(written_cash.lines().count() > 1, "{written_cash}");
    let cash_certificate = fa::CashFlowCertificate::decode(&unhex(text(cash, "bytes"))).unwrap();
    {
        let book = f.open();
        let library = book
            .cash_flow_jsonl(
                operator,
                &read_produce,
                &cash_certificate,
                cash_certificate.request(),
                cash_certificate.definition(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(written_cash, library, "the CLI writes the library's export");
    }
    let unbound_cash = f.dir.join("cash-unbound.jsonl");
    let (exit, _) = f.run(&[
        "replay",
        &cash_locator,
        "--workpaper-out",
        unbound_cash.to_str().unwrap(),
    ]);
    assert_eq!(exit, 8, "cash flow replays only against its request");
    assert!(!unbound_cash.exists());

    // Ledger detail: a roll-forward source replayed with --view detail.
    let scope = [
        "--account",
        "1000",
        "--unit",
        "USD",
        "--from",
        "2026-01-01",
        "--to",
        "2026-01-31",
        "--label",
        "January detail",
        "--as-known-at",
        at.as_str(),
    ];
    let mut certify = vec!["gl", "detail"];
    certify.extend(scope);
    certify.push("--certify");
    let certified = f.ok(&certify);
    let detail_retained = f.head();
    let metadata = data(&certified, "report_certificate");
    let locator = format!("C:{}", text(metadata, "oid"));
    let detail_path = f.dir.join("detail.jsonl");
    let mut replay = vec!["replay", locator.as_str(), "--view", "detail"];
    replay.extend(scope);
    replay.extend(["--workpaper-out", detail_path.to_str().unwrap()]);
    let events = f.ok(&replay);
    assert_eq!(
        text(data(&events, "workpaper_exported"), "family"),
        "roll-forward"
    );
    let written = std::fs::read_to_string(&detail_path).unwrap();
    let source = fa::RollForwardCertificate::decode(&unhex(text(metadata, "bytes"))).unwrap();
    {
        let book = f.open();
        let library = book
            .general_ledger_jsonl(operator, &read_produce, &source, source.request())
            .unwrap()
            .unwrap();
        assert_eq!(written, library, "the CLI writes the library's export");
    }
    // Freshness parses the same expectations: an aging question on a
    // roll-forward is refused, never ignored as an as-supplied replay.
    let (exit, errors) = f.run(&["certificate", "status", &locator, "--expect", &aging_expect]);
    assert_eq!(exit, 8, "{errors:?}");
    assert!(
        text(data(&errors, "error"), "message").contains("an aging expectation names"),
        "{errors:?}"
    );

    // A family without an export is refused before replay and writes nothing:
    // the same roll-forward source without --view detail.
    let refused = f.dir.join("no-export.jsonl");
    let (exit, errors) = f.run(&[
        "replay",
        &locator,
        "--workpaper-out",
        refused.to_str().unwrap(),
    ]);
    assert_eq!(exit, 2, "{errors:?}");
    assert!(
        text(data(&errors, "error"), "message")
            .contains("roll-forward certificates have no JSONL workpaper export"),
        "{errors:?}"
    );
    assert!(!refused.exists());

    // A launch-bound session cannot name a host output path at all: the new
    // flag is in the shared host-path containment list.
    let authority = fa_cli::authority::LaunchAuthority::new(
        f.dir.clone(),
        None,
        "workpaper-reader",
        fa_cli::authority::LaunchProfile::Agent,
        &["read", "produce"],
    )
    .unwrap();
    let bound = f.dir.join("bound.jsonl");
    let args = [
        "replay",
        &locator,
        "--workpaper-out",
        bound.to_str().unwrap(),
        "--json",
    ]
    .map(String::from);
    let (code, captured) =
        fa_cli::entry::fa_with_authority(&args, Files::default(), &authority, true);
    assert_eq!(code, 2, "{}{}", captured.stdout, captured.stderr);
    assert!(
        captured
            .stdout
            .contains("--workpaper-out cannot name a host filesystem path"),
        "{}",
        captured.stdout
    );
    assert!(!bound.exists());
    assert_eq!(
        f.head(),
        detail_retained,
        "workpapers and refusals are reads"
    );
}

#[test]
fn aging_from_saved_certificates_reuses_them_byte_for_byte_and_answers_only_their_question() {
    // 1000 and 4000 carry 64 postings; 2000 is a zero-activity leaf.
    let f = Fixture::with_additional_cash_accounts(1);
    let at = f.source_head.0.to_string();
    let bytes_of = |events: &[Json]| unhex(text(data(events, "report_certificate"), "bytes"));
    let oid_of = |events: &[Json]| format!("C:{}", text(data(events, "report_certificate"), "oid"));
    let aging_at = |extra: &[&str]| {
        let mut args = vec![
            "gl",
            "aging",
            "--as-of",
            "2026-01-31",
            "--bucket",
            "0,30,60",
            "--as-known-at",
            at.as_str(),
        ];
        args.extend_from_slice(extra);
        f.ok(&args)
    };
    // The sources a producer certified and handed out at `at`.
    let open_items = f.ok(&[
        "open-items",
        "--account",
        "1000",
        "--as-known-at",
        &at,
        "--certify",
    ]);
    let aging = aging_at(&["--account", "1000", "--certify"]);
    let whole_aging = aging_at(&["--certify"]);
    let control = f.ok(&[
        "tb",
        "--as-of",
        "2026-01-31",
        "--as-known-at",
        &at,
        "--certify",
    ]);
    let other_date = f.ok(&[
        "tb",
        "--as-of",
        "2026-01-30",
        "--as-known-at",
        &at,
        "--certify",
    ]);
    // A later posting moves HEAD; the saved sources still answer `at`.
    let mut book = f.open();
    post(&mut book, 900);
    drop(book);

    // Aging from a saved open-items certificate is the aging at its prefix,
    // with that exact certificate as its source, by digest or by file.
    let saved_file = f.dir.join("open-items.cert");
    std::fs::write(&saved_file, bytes_of(&open_items)).unwrap();
    let from_source = |source: &str, extra: &[&str]| {
        let mut args = vec![
            "gl",
            "aging",
            "--from-source",
            source,
            "--as-of",
            "2026-01-31",
            "--bucket",
            "0,30,60",
        ];
        args.extend_from_slice(extra);
        f.run(&args)
    };
    let (exit, aged) = from_source(&oid_of(&open_items), &["--certify"]);
    assert_eq!(exit, 0, "{aged:?}");
    assert_eq!(data(&aged, "aging"), data(&aging, "aging"));
    let certificate = fa::AgingCertificate::decode(&bytes_of(&aged)).unwrap();
    assert_eq!(
        certificate.source(),
        &ReportCertificate::decode(&bytes_of(&open_items)).unwrap(),
        "the saved open-items certificate is the source, not a new fold"
    );
    let (exit, by_file) = from_source(saved_file.to_str().unwrap(), &["--certify"]);
    assert_eq!(exit, 0, "{by_file:?}");
    assert_eq!(
        text(data(&by_file, "report_certificate"), "oid"),
        &oid_of(&aged)[2..]
    );
    let (exit, stated) = from_source(&oid_of(&open_items), &["--account", "1000", "--certify"]);
    assert_eq!(exit, 0, "a matching stated account: {stated:?}");
    let replayed = f.ok(&[
        "replay",
        &oid_of(&aged),
        "--expect",
        &generated_expectation(data(&aged, "report_certificate")),
    ]);
    assert_eq!(data(&replayed, "aging"), data(&aging, "aging"));

    // Reconciliation from the saved aging and control certificates equals the
    // reconciliation at their prefix and keeps both of them as its sources.
    let question = |selection: &[&'static str]| {
        let mut args = portfolio_args(&at, selection);
        args.extend(["--bucket", "0,30,60"]);
        args
    };
    let single = question(&["--account", "1000"]);
    let plain = f.ok(&single);
    let mut saved_args = single.clone();
    let (aging_oid, control_oid) = (oid_of(&aging), oid_of(&control));
    saved_args.extend([
        "--aging-certificate",
        &aging_oid,
        "--control-certificate",
        &control_oid,
        "--certify",
    ]);
    let reconciled = f.ok(&saved_args);
    assert_eq!(
        data(&reconciled, "aging_reconciled"),
        data(&plain, "aging_reconciled")
    );
    let certificate = fa::AgingReconciliationCertificate::decode(&bytes_of(&reconciled)).unwrap();
    assert_eq!(
        certificate.aging_source(),
        &fa::AgingCertificate::decode(&bytes_of(&aging)).unwrap()
    );
    assert_eq!(
        certificate.control_source(),
        &ReportCertificate::decode(&bytes_of(&control)).unwrap()
    );
    f.ok(&[
        "replay",
        &oid_of(&reconciled),
        "--expect",
        &generated_expectation(data(&reconciled, "report_certificate")),
    ]);

    // The whole-book aging and the same control give the portfolio.
    let whole = question(&["--all-posting"]);
    let plain_portfolio = f.ok(&whole);
    let mut portfolio_saved = whole.clone();
    let whole_oid = oid_of(&whole_aging);
    portfolio_saved.extend([
        "--aging-certificate",
        &whole_oid,
        "--control-certificate",
        &control_oid,
        "--certify",
    ]);
    let portfolio = f.ok(&portfolio_saved);
    assert_eq!(
        data(&portfolio, "aging_portfolio_reconciled"),
        data(&plain_portfolio, "aging_portfolio_reconciled")
    );
    let certificate =
        fa::aging::portfolio::AgingPortfolioCertificate::decode(&bytes_of(&portfolio)).unwrap();
    assert_eq!(
        certificate.aging_source(),
        &fa::AgingCertificate::decode(&bytes_of(&whole_aging)).unwrap()
    );
    assert_eq!(
        certificate.control_source(),
        &ReportCertificate::decode(&bytes_of(&control)).unwrap()
    );

    // Planted refusals: none publishes.
    let retained = f.head();
    let open_items_oid = oid_of(&open_items);
    let control_file = f.dir.join("control.cert");
    std::fs::write(&control_file, bytes_of(&control)).unwrap();
    for (extra, exit, needle) in [
        (vec![], 2, "add --certify"),
        (
            vec!["--as-known-at", at.as_str(), "--certify"],
            2,
            "--as-known-at does not select it",
        ),
        (
            vec!["--reconcile", "--certify"],
            2,
            "--from-source ages one",
        ),
        (
            vec!["--account", "4000", "--certify"],
            8,
            "selects a different account",
        ),
    ] {
        let (code, errors) = from_source(&open_items_oid, &extra);
        assert_eq!(code, exit, "{needle}: {errors:?}");
        assert!(
            text(data(&errors, "error"), "message").contains(needle),
            "{needle}: {errors:?}"
        );
    }
    for (source, needle) in [
        (control_oid.as_str(), "OpenItems"),
        (aging_oid.as_str(), "--from-source"),
    ] {
        let (code, errors) = from_source(source, &["--certify"]);
        assert_eq!(code, 8, "a wrong source family: {errors:?}");
        assert!(
            text(data(&errors, "error"), "message").contains(needle),
            "{needle}: {errors:?}"
        );
    }
    let other_oid = oid_of(&other_date);
    let control_path = control_file.to_str().unwrap();
    for (args, exit, why) in [
        (
            [
                single.clone(),
                vec![
                    "--aging-certificate",
                    &aging_oid,
                    "--control-certificate",
                    &other_oid,
                    "--certify",
                ],
            ]
            .concat(),
            8,
            "a control certificate at another date",
        ),
        (
            [
                question(&["--account", "4000"]),
                vec![
                    "--aging-certificate",
                    &aging_oid,
                    "--control-certificate",
                    &control_oid,
                    "--certify",
                ],
            ]
            .concat(),
            8,
            "a different stated account",
        ),
        (
            [
                single.clone(),
                vec![
                    "--aging-certificate",
                    &whole_oid,
                    "--control-certificate",
                    &control_oid,
                    "--certify",
                ],
            ]
            .concat(),
            8,
            "a whole-book aging for one account",
        ),
        (
            [
                whole.clone(),
                vec![
                    "--aging-certificate",
                    &aging_oid,
                    "--control-certificate",
                    &control_oid,
                    "--certify",
                ],
            ]
            .concat(),
            8,
            "one account's aging for the whole book",
        ),
        (
            [
                single.clone(),
                vec!["--aging-certificate", &aging_oid, "--certify"],
            ]
            .concat(),
            2,
            "a single source",
        ),
        (
            [
                single.clone(),
                vec![
                    "--aging-certificate",
                    &aging_oid,
                    "--control-certificate",
                    &control_oid,
                ],
            ]
            .concat(),
            2,
            "uncertified",
        ),
        (
            vec![
                "gl",
                "aging",
                "--account",
                "1000",
                "--as-of",
                "2026-01-31",
                "--as-known-at",
                &at,
                "--aging-certificate",
                &aging_oid,
                "--control-certificate",
                &control_oid,
                "--certify",
            ],
            2,
            "without --reconcile",
        ),
        (
            vec![
                "gl",
                "aging",
                "--reconcile",
                "--account",
                "1000",
                "--as-of",
                "2026-01-31",
                "--bucket",
                "0,30,60",
                "--aging-certificate",
                &aging_oid,
                "--control-certificate",
                control_path,
                "--certify",
            ],
            2,
            "without a fixed --as-known-at",
        ),
    ] {
        let (code, errors) = f.run(&args);
        assert_eq!(code, exit, "{why}: {errors:?}");
        assert_eq!(errors.len(), 1, "{why}: {errors:?}");
    }
    assert_eq!(f.head(), retained, "refusals publish nothing");

    // A launch-bound session names retained digests only, never host files.
    let authority = fa_cli::authority::LaunchAuthority::new(
        f.dir.clone(),
        None,
        "aging-producer",
        fa_cli::authority::LaunchProfile::Agent,
        &["read", "produce"],
    )
    .unwrap();
    let args = [
        "gl",
        "aging",
        "--from-source",
        saved_file.to_str().unwrap(),
        "--as-of",
        "2026-01-31",
        "--certify",
        "--json",
    ]
    .map(String::from);
    let (code, captured) =
        fa_cli::entry::fa_with_authority(&args, Files::default(), &authority, true);
    assert_eq!(code, 2, "{}{}", captured.stdout, captured.stderr);
    assert!(
        captured
            .stdout
            .contains("--from-source cannot name a host filesystem path"),
        "{}",
        captured.stdout
    );
    assert_eq!(f.head(), retained);
}
