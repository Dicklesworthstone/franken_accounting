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
