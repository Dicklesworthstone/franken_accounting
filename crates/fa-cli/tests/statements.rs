//! Financial statements through the real CLI: exact native-unit columns,
//! shared historical coordinates, retained replay, and selector refusals.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

fn temporary() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let dir = std::env::temp_dir().join(format!(
            "fa-statements-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        match std::fs::create_dir(&dir) {
            Ok(()) => return dir,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create {}: {error}", dir.display()),
        }
    }
}

fn run(book: &Path, args: &[&str]) -> (i32, Vec<Json>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .output()
        .expect("run fa");
    let text = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let registry = fa_cli::verbs::registry().expect("verb registry");
    let events = text
        .lines()
        .map(|line| {
            registry
                .check_line(line)
                .unwrap_or_else(|error| panic!("args={args:?}: schema: {error:?}\n{line}"));
            json::parse(line).expect("robot JSON")
        })
        .collect();
    (
        output.status.code().unwrap_or(-1),
        events,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn ok(book: &Path, args: &[&str]) -> Vec<Json> {
    let (exit, events, stderr) = run(book, args);
    assert_eq!(exit, 0, "args={args:?}\n{events:?}\n{stderr}");
    events
}

fn data(event: &Json) -> &Json {
    event.get("data").expect("data")
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("{key}: {value:?}"))
}

fn array<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    value
        .get(key)
        .and_then(Json::as_arr)
        .unwrap_or_else(|| panic!("{key}: {value:?}"))
}

fn line<'a>(statement: &'a Json, code: &str, unit: &str) -> &'a [Json] {
    let row = array(statement, "lines")
        .iter()
        .find(|row| text(row, "code") == code && text(row, "unit") == unit)
        .unwrap_or_else(|| panic!("missing {code}/{unit}: {statement:?}"));
    array(row, "amounts")
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    evidence: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = temporary();
        let book = dir.join("book");
        ok(&book, &["book", "create", "--name", "Statement fixture"]);
        let chart = dir.join("chart.json");
        std::fs::write(&chart, r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"3000","name":"Capital","type":"Equity","unit":"USD"},{"code":"4000","name":"Sales","type":"Revenue","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"},{"code":"1100","name":"Yen cash","type":"Asset","unit":"JPY"},{"code":"4100","name":"Yen sales","type":"Revenue","unit":"JPY"},{"code":"6100","name":"Yen expense","type":"Expense","unit":"JPY"}]}"#).unwrap();
        ok(&book, &["chart", "import", chart.to_str().unwrap()]);
        ok(&book, &["period", "create", "--fiscal-year", "2026"]);
        for period in ["FY2026-P02", "FY2026-P03"] {
            ok(&book, &["period", "open", period]);
        }
        let source = dir.join("source.txt");
        std::fs::write(&source, b"Statement test source: capital, sales and rent").unwrap();
        let doc = ok(
            &book,
            &[
                "document",
                "add",
                source.to_str().unwrap(),
                "--kind",
                "Invoice",
                "--grade",
                "HumanUpload",
            ],
        );
        let fixture = Self {
            dir,
            book,
            evidence: text(data(&doc[0]), "oid").into(),
        };
        for (key, day, debit, credit, amount) in [
            ("capital", "2026-02-01", "1000", "3000", "200.00 USD"),
            ("feb-sale", "2026-02-10", "1000", "4000", "100.00 USD"),
            ("feb-rent", "2026-02-11", "6000", "1000", "25.00 USD"),
            ("mar-sale", "2026-03-10", "1000", "4000", "90.00 USD"),
            ("mar-rent", "2026-03-11", "6000", "1000", "10.00 USD"),
            ("yen-sale", "2026-03-10", "1100", "4100", "111 JPY"),
            ("yen-expense", "2026-03-11", "6100", "1100", "22 JPY"),
        ] {
            fixture.post(key, day, debit, credit, amount);
        }
        fixture
    }

    fn post(&self, key: &str, day: &str, debit: &str, credit: &str, amount: &str) {
        let path = self.dir.join(format!("{key}.json"));
        std::fs::write(&path, format!(r#"{{"idempotency_key":"{key}","effective_date":"{day}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount}"}},{{"side":"credit","account":"{credit}","amount":"{amount}"}}]}}"#)).unwrap();
        ok(
            &self.book,
            &[
                "post",
                "--intent",
                path.to_str().unwrap(),
                "--evidence",
                &self.evidence,
            ],
        );
    }
}

#[test]
fn statements_carry_opening_history_and_separate_exact_comparative_units() {
    let fixture = Fixture::new();
    let bs = ok(
        &fixture.book,
        &[
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
        ],
    );
    assert_eq!(text(&bs[0], "event"), "statement");
    let report = data(&bs[0]);
    assert_eq!(
        line(report, "assets", "USD"),
        &[
            Json::Str("355.00 USD".into()),
            Json::Str("275.00 USD".into())
        ]
    );
    assert_eq!(
        line(report, "balance_check", "USD"),
        &[Json::Str("0.00 USD".into()), Json::Str("0.00 USD".into())]
    );
    assert_eq!(
        line(report, "assets", "JPY"),
        &[Json::Str("89 JPY".into()), Json::Str("0 JPY".into())]
    );
    assert_eq!(array(report, "columns").len(), 2);
    assert_eq!(text(&array(report, "columns")[0], "mode"), "stock");
    assert_eq!(array(report, "mappings").len(), 7);

    let income = ok(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
        ],
    );
    let report = data(&income[0]);
    assert_eq!(
        line(report, "net_income", "USD"),
        &[Json::Str("80.00 USD".into()), Json::Str("75.00 USD".into())]
    );
    assert_eq!(
        line(report, "net_income", "JPY"),
        &[Json::Str("89 JPY".into()), Json::Str("0 JPY".into())]
    );
    assert_eq!(text(&array(report, "columns")[0], "mode"), "activity");
    assert_eq!(array(report, "mappings").len(), 4);
    assert_eq!(bs[0].get("certificate"), Some(&Json::Null));
    assert_eq!(income[0].get("certificate"), Some(&Json::Null));
}

#[test]
fn retained_statement_replay_preserves_both_columns_after_later_postings() {
    let fixture = Fixture::new();
    let original = ok(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
            "--certify",
        ],
    );
    assert_eq!(original.len(), 2);
    assert_eq!(text(&original[1], "event"), "report_certificate");
    let oid = text(data(&original[1]), "oid");
    let replay = ok(&fixture.book, &["replay", &format!("C:{oid}")]);
    assert_eq!(
        original[0], replay[0],
        "same original and replay robot envelope"
    );
    fixture.post("later-sale", "2026-03-20", "1000", "4000", "20.00 USD");
    assert_eq!(
        ok(&fixture.book, &["replay", &format!("C:{oid}")])[0],
        original[0]
    );
    let now = ok(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
        ],
    );
    assert_eq!(
        line(data(&now[0]), "net_income", "USD"),
        &[
            Json::Str("100.00 USD".into()),
            Json::Str("75.00 USD".into())
        ]
    );
    let known_at = data(&original[0]).get("known_at").unwrap().render();
    let historical = ok(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
            "--known-at",
            &known_at,
        ],
    );
    assert_eq!(data(&historical[0]), data(&original[0]));
    let alias = ok(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
            "--as-known-at",
            &known_at,
        ],
    );
    assert_eq!(historical, alias);
}

#[test]
fn statement_selectors_are_explicit_and_output_files_are_never_replaced() {
    let fixture = Fixture::new();
    for args in [
        vec!["statement", "balance-sheet"],
        vec!["statement", "cash-flow", "--for", "FY2026-P03"],
        vec![
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--for",
            "FY2026-P02",
        ],
        vec![
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--known-at",
            "HEAD",
            "--as-known-at",
            "HEAD",
        ],
        vec![
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--known-at",
            "18446744073709551616",
        ],
    ] {
        let (exit, events, _) = run(&fixture.book, &args);
        assert_eq!(exit, 2, "{args:?}: {events:?}");
        assert_eq!(events.len(), 1);
        assert_eq!(text(&events[0], "event"), "error");
    }
    let path = fixture.dir.join("statement.cert");
    let args = [
        "statement",
        "balance-sheet",
        "--for",
        "FY2026-P03",
        "--certificate-out",
        path.to_str().unwrap(),
    ];
    let certified = ok(&fixture.book, &args);
    assert_eq!(certified.len(), 2);
    let bytes = std::fs::read(&path).unwrap();
    let (exit, events, _) = run(&fixture.book, &args);
    assert_ne!(exit, 0);
    assert!(events.iter().all(|event| text(event, "event") == "error"));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert_eq!(
        ok(&fixture.book, &["replay", path.to_str().unwrap()])[0],
        certified[0]
    );
}


#[test]
fn certified_comparisons_and_traces_retain_the_complete_family_across_processes() {
    let fixture = Fixture::new();
    let snapshot = ok(
        &fixture.book,
        &["statement", "income-statement", "--for", "FY2026-P03"],
    );
    let before = data(&snapshot[0]).get("known_at").unwrap().render();
    fixture.post("bridge-sale", "2026-03-14", "1000", "4000", "17.00 USD");
    let snapshot = ok(
        &fixture.book,
        &["statement", "income-statement", "--for", "FY2026-P03"],
    );
    let after = data(&snapshot[0]).get("known_at").unwrap().render();
    let mut originals = Vec::new();
    for mode in ["diff", "trace"] {
        let path = fixture.dir.join(format!("{mode}.cert"));
        let args = [
            "statement",
            mode,
            "--definition",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--before",
            &before,
            "--after",
            &after,
            "--certify",
            "--certificate-out",
            path.to_str().unwrap(),
        ];
        let original = ok(&fixture.book, &args);
        assert_eq!(original.len(), 2, "{mode}: {original:?}");
        assert_eq!(text(&original[0], "event"), format!("statement_{mode}"));
        assert_eq!(text(&original[1], "event"), "report_certificate");
        let oid = text(data(&original[1]), "oid").to_string();
        assert_eq!(text(&original[0], "certificate"), oid);
        let bytes = std::fs::read(&path).unwrap();
        let artifact = fa::ReportArtifact::decode(&bytes).unwrap();
        assert_eq!(artifact.family().name(), format!("statement-{mode}"));
        assert_eq!(artifact.known_at().0.to_string(), after);
        let handle = format!("C:{oid}");
        assert_eq!(
            ok(&fixture.book, &["replay", &handle]),
            vec![original[0].clone()],
        );
        assert_eq!(
            ok(&fixture.book, &["replay", path.to_str().unwrap()]),
            vec![original[0].clone()],
        );
        let output_path = fixture.dir.join(format!("{mode}.report"));
        let replay = ok(
            &fixture.book,
            &["replay", &handle, "--output", output_path.to_str().unwrap()],
        );
        assert_eq!(replay.len(), 2);
        assert_eq!(replay[0], original[0]);
        assert_eq!(text(&replay[1], "event"), "report_replayed");
        assert_eq!(text(data(&replay[1]), "family"), artifact.family().name());
        assert_eq!(std::fs::read(&output_path).unwrap(), artifact.output());
        assert_eq!(
            data(&replay[1]).get("output_bytes"),
            Some(&Json::Int(artifact.output().len() as i128)),
        );
        assert_eq!(
            data(&replay[1]).get("output_digest"),
            data(&original[1]).get("output_digest"),
        );
        // Fixed endpoints produce the same certificate after retention
        // advances the metadata frontier. Exact retry publishes nothing.
        let retry = ok(
            &fixture.book,
            &[
                "statement",
                mode,
                "--definition",
                "income-statement",
                "--for",
                "FY2026-P03",
                "--before",
                &before,
                "--after",
                &after,
                "--certify",
            ],
        );
        assert_eq!(text(data(&retry[1]), "oid"), oid);
        assert_eq!(
            data(&retry[1]).get("recorded_at"),
            data(&original[1]).get("recorded_at"),
        );
        let status = ok(&fixture.book, &["certificate", "status", &handle]);
        assert_eq!(text(data(&status[0]), "status"), "Current");
        assert_eq!(text(data(&status[0]), "oid"), oid);
        assert_eq!(data(&status[0]).get("known_at").unwrap().render(), after);

        // Forge the derived output and recompute its unsigned content hash.
        // The container still decodes, so refusal must come from full source
        // replay and reconstruction of the bridge or publication attribution.
        let mut forged = bytes.clone();
        let body_end = forged.len() - 32;
        forged[body_end - 1] ^= 1;
        let domain: &[u8] = if mode == "diff" {
            b"fa:statement-diff-certificate-digest:v1"
        } else {
            b"fa:statement-trace-certificate-digest:v1"
        };
        let digest = fa_model::domain_digest(domain, &[&forged[..body_end]]);
        forged[body_end..].copy_from_slice(&digest);
        fa::ReportArtifact::decode(&forged)
            .expect("an intact unsigned container is not a replay proof");
        let forged_path = fixture.dir.join(format!("{mode}-forged.cert"));
        std::fs::write(&forged_path, forged).unwrap();
        let refused_output = fixture.dir.join(format!("{mode}-must-not-exist.report"));
        for command in [
            vec![
                "replay",
                forged_path.to_str().unwrap(),
                "--output",
                refused_output.to_str().unwrap(),
            ],
            vec!["certificate", "status", forged_path.to_str().unwrap()],
        ] {
            let (exit, events, _) = run(&fixture.book, &command);
            assert_eq!(exit, 8, "{command:?}: {events:?}");
            assert_eq!(events.len(), 1);
            assert_eq!(text(&events[0], "event"), "error");
            assert!(!refused_output.exists());
        }
        let (exit, events, _) = run(
            &fixture.book,
            &["replay", &handle, "--output", output_path.to_str().unwrap()],
        );
        assert_eq!(exit, 2);
        assert_eq!(events.len(), 1);
        assert_eq!(text(&events[0], "event"), "error");
        assert_eq!(std::fs::read(output_path).unwrap(), artifact.output());
        originals.push((handle, original[0].clone()));
    }
    // A late February entry does not affect this March activity selector.
    // A backdated March entry does, without changing the historical bytes.
    fixture.post(
        "unrelated-late-sale",
        "2026-02-14",
        "1000",
        "4000",
        "23.00 USD",
    );
    for (handle, _) in &originals {
        let status = ok(&fixture.book, &["certificate", "status", handle]);
        assert_eq!(text(data(&status[0]), "status"), "Current");
    }
    fixture.post("backdated-sale", "2026-03-12", "1000", "4000", "29.00 USD");
    for (handle, original) in &originals {
        let status = ok(&fixture.book, &["certificate", "status", handle]);
        assert_eq!(text(data(&status[0]), "status"), "SupersededBy");
        assert!(!array(data(&status[0]), "later_entries").is_empty());
        assert_eq!(
            ok(&fixture.book, &["replay", handle]),
            vec![original.clone()],
        );
    }
}

#[test]
fn comparison_scope_and_certification_authority_are_never_silently_ignored() {
    let fixture = Fixture::new();
    for extra in [
        vec!["--known-at", "HEAD"],
        vec!["--as-known-at", "HEAD"],
        vec!["--max-publications", "1"],
    ] {
        let mut args = vec![
            "statement",
            "diff",
            "--definition",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--before",
            "1",
        ];
        args.extend(extra);
        let (exit, events, _) = run(&fixture.book, &args);
        assert_eq!(exit, 2, "{args:?}: {events:?}");
        assert_eq!(events.len(), 1);
        assert_eq!(text(&events[0], "event"), "error");
    }
    let authority = fa_cli::authority::LaunchAuthority::new(
        fixture.book.clone(),
        None,
        "report-reader",
        fa_cli::authority::LaunchProfile::Agent,
        &["read"],
    )
    .unwrap();
    let args = [
        "statement",
        "diff",
        "--definition",
        "income-statement",
        "--for",
        "FY2026-P03",
        "--before",
        "1",
        "--certify",
        "--json",
    ]
    .map(String::from);
    let (exit, captured) = fa_cli::entry::fa_with_authority(
        &args,
        fa_cli::cli::Files::default(),
        &authority,
        true,
    );
    assert_eq!(exit, 7, "{}{}", captured.stdout, captured.stderr);
    let events: Vec<_> = captured
        .stdout
        .lines()
        .map(|line| json::parse(line).unwrap())
        .collect();
    assert_eq!(events.len(), 1);
    assert_eq!(text(&events[0], "event"), "error");
    assert!(captured.stdout.contains("produce"));
}


#[test]
fn generic_aging_artifacts_replay_by_digest_and_export_through_the_held_dispatcher() {
    let fixture = Fixture::new();
    let keys = fa::BookKeys::load(&fixture.book.join("book.keys")).unwrap();
    let mut book = fa::Book::open_dir(
        &fixture.book,
        keys.clone(),
        fa::Entropy::deterministic(117),
    )
    .unwrap();
    let principal = fa_model::principal_vid("aging-producer");
    let capability = fa::Capability::embedded(principal, &["read", "produce"]).unwrap();
    let certified = book
        .certify_effective_date_aging(
            principal,
            &capability,
            &fa::AgingRequest {
                account: None,
                effective_through: fa_time::DateDay::parse("2026-03-31").unwrap(),
                known_at: None,
                buckets: fa::AgingBuckets::thirty_day(),
            },
        )
        .unwrap()
        .unwrap();
    let artifact = fa::ReportArtifact::try_from(&certified.certificate).unwrap();
    let bytes = artifact.canonical_bytes().unwrap();
    let retained = book
        .retain_report_artifact(principal, &capability, &bytes, Some(artifact.digest()))
        .unwrap()
        .unwrap();
    assert_eq!(&retained.digest, artifact.digest());
    let handle = format!(
        "C:{}",
        artifact.digest().iter().map(|b| format!("{b:02x}")).collect::<String>(),
    );
    drop(book);
    let output = fixture.dir.join("aging.report");
    let replay = ok(
        &fixture.book,
        &["replay", &handle, "--output", output.to_str().unwrap()],
    );
    assert_eq!(replay.len(), 1);
    assert_eq!(text(&replay[0], "event"), "report_replayed");
    assert_eq!(text(data(&replay[0]), "family"), "effective-date-aging");
    assert_eq!(std::fs::read(output).unwrap(), artifact.output());
    let (exit, events, _) = run(&fixture.book, &["certificate", "status", &handle]);
    assert_eq!(exit, 8, "{events:?}");
    assert_eq!(events.len(), 1);
    assert_eq!(text(&events[0], "event"), "error");

    let mut book = fa::Book::open_dir(
        &fixture.book,
        keys,
        fa::Entropy::deterministic(118),
    )
    .unwrap();
    let original_head = book.head().unwrap();
    let args = ["replay".to_string(), handle.clone(), "--json".into()];
    let (exit, captured) = fa_cli::cli::run_for_daemon(
        &args,
        &mut book,
        fixture.book.clone(),
        None,
        None,
        fa_cli::cli::Stdin::Missing,
        true,
    );
    assert_eq!(exit, 0, "{}{}", captured.stdout, captured.stderr);
    let event = json::parse(captured.stdout.trim()).unwrap();
    fa_cli::verbs::registry().unwrap().check_line(captured.stdout.trim()).unwrap();
    assert_eq!(text(data(&event), "family"), "effective-date-aging");
    assert_eq!(data(&event).get("output_digest"), data(&replay[0]).get("output_digest"));
    assert_eq!(book.head().unwrap(), original_head);

    // The new output flag follows the same daemon file-containment admission
    // as every other output path, before the replay handler can create a file.
    let escaped = fixture.dir.join("daemon-must-not-create.report");
    let args = [
        "replay".to_string(),
        handle,
        "--output".into(),
        escaped.to_str().unwrap().into(),
        "--json".into(),
    ];
    let (exit, captured) = fa_cli::cli::run_for_daemon(
        &args,
        &mut book,
        fixture.book.clone(),
        None,
        None,
        fa_cli::cli::Stdin::Missing,
        true,
    );
    assert_eq!(exit, 2, "{}{}", captured.stdout, captured.stderr);
    assert_eq!(captured.stdout.lines().count(), 1);
    assert!(!escaped.exists());
    assert_eq!(book.head().unwrap(), original_head);
}
