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
        originals.push((event_name, events, bytes, locator, file));
    }
    let mut book = f.open();
    post(&mut book, 64);
    let later = book.head().unwrap();
    drop(book);
    for (event_name, original, bytes, locator, file) in originals {
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
        retained.push((locator, bytes, artifact.output().to_vec(), expectation));
    }
    let mut book = f.open();
    post(&mut book, 64);
    let later_head = book.head().unwrap();
    for (locator, bytes, expected_output, expectation) in retained {
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
