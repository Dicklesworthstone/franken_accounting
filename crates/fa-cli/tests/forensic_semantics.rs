//! fa-v0m2 (with fa-6l8g): the corrected party attribution survives the
//! public workflow. A real book built through the `fa` binary pays two
//! creditors' bills, A's 100.00 and B's 200.00, in one batched payment, and
//! takes two investors' subscriptions, A's 100.00 and B's 200.00, in one
//! batched receipt. `fa procedure run` and `fa finding record`, retained and
//! listed back, report exactly 100.00 and 200.00 to each, and a pool of 90.00
//! is shared 30.00/60.00. Version 2 of these procedures gave every party the
//! whole 300.00. The expected values are literals from the economic history.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

fn data(value: &Json) -> &Json {
    value.get("data").expect("robot data")
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value.get(key).and_then(Json::as_str).expect(key)
}

fn rows<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    value.get(key).and_then(Json::as_arr).expect(key)
}

fn integer(value: &Json, key: &str) -> i128 {
    match value.get(key).expect(key) {
        Json::Int(value) => *value,
        other => panic!("{key} is not an integer: {other:?}"),
    }
}

/// Runs `fa --book <book> <args> --json`; every line is checked against the
/// verb registry. Returns the exit code and the single envelope.
fn run(book: &Path, args: &[&str]) -> (i32, Json) {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .output()
        .expect("run fa");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let registry = fa_cli::verbs::registry().unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{args:?}: {stdout}\n{stderr}");
    registry
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("{args:?}: {error}\n{stdout}\n{stderr}"));
    (
        output.status.code().unwrap_or(-1),
        json::parse(lines[0]).unwrap(),
    )
}

fn ok(book: &Path, args: &[&str]) -> Json {
    let (code, out) = run(book, args);
    assert_eq!(code, 0, "{args:?}: {}", out.render());
    out
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    evidence: String,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let dir = std::env::temp_dir().join(format!(
                "fa-forensic-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            if std::fs::create_dir(&dir).is_ok() {
                break dir;
            }
        };
        let book = dir.join("book");
        ok(&book, &["book", "create", "--name", "Forensic semantics"]);
        let f = Self {
            dir,
            book,
            evidence: String::new(),
        };
        let chart = f.file(
            "chart.json",
            r#"{"accounts":[
{"code":"1000","name":"Operating cash","type":"Asset","unit":"USD","roles":["cash"]},
{"code":"2000","name":"Accounts payable","type":"Liability","unit":"USD"},
{"code":"3000","name":"Investor capital","type":"Equity","unit":"USD"},
{"code":"6000","name":"Rent","type":"Expense","unit":"USD"},
{"code":"7000","name":"Utilities","type":"Expense","unit":"USD"}]}"#,
        );
        ok(&f.book, &["chart", "import", &chart]);
        ok(&f.book, &["period", "create", "--fiscal-year", "2026"]);
        for period in ["FY2026-P01", "FY2026-P02", "FY2026-P04"] {
            ok(&f.book, &["period", "open", period]);
        }
        let source = f.file("support.txt", "Bills, payment and subscriptions.");
        let added = ok(
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
        );
        for (code, kind) in [
            ("VEND-A", "Vendor"),
            ("VEND-B", "Vendor"),
            ("INV-A", "Counterparty"),
            ("INV-B", "Counterparty"),
        ] {
            let party = f.file(
                &format!("{code}.json"),
                &format!(r#"{{"code":"{code}","kind":"{kind}","name":"{code}"}}"#),
            );
            ok(&f.book, &["party", "add", &party]);
        }
        Self {
            evidence: text(data(&added), "oid").into(),
            ..f
        }
    }

    fn file(&self, name: &str, content: &str) -> String {
        let path = self.dir.join(name);
        std::fs::write(&path, content).unwrap();
        path.display().to_string()
    }

    /// Posts `legs` (each `(side, account, amount, party)`) on `date`.
    fn post(&self, key: &str, date: &str, legs: &[(&str, &str, &str, Option<&str>)]) {
        let legs: Vec<String> = legs
            .iter()
            .map(|(side, account, amount, party)| {
                let party = party.map_or_else(String::new, |p| format!(r#","party":"{p}""#));
                format!(
                    r#"{{"side":"{side}","account":"{account}","amount":"{amount} USD"{party}}}"#
                )
            })
            .collect();
        let intent = self.file(
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":[{}]}}"#,
                legs.join(",")
            ),
        );
        ok(
            &self.book,
            &["post", "--intent", &intent, "--evidence", &self.evidence],
        );
    }
}

/// `(second word of the narrative, statistic value)` of each finding, sorted:
/// "creditor VEND-A (...", "investor INV-A: ...".
fn margins(findings: &[Json]) -> Vec<(String, i128)> {
    let mut out: Vec<(String, i128)> = findings
        .iter()
        .map(|f| {
            let who = text(f, "narrative")
                .split_whitespace()
                .nth(1)
                .unwrap()
                .trim_end_matches(':')
                .to_string();
            let statistic = f.get("statistic").expect("statistic");
            (who, integer(statistic, "value"))
        })
        .collect();
    out.sort();
    out
}

#[test]
fn creditor_and_investor_margins_survive_public_workflow() {
    let f = Fixture::new();
    f.post(
        "subscriptions",
        "2026-01-10",
        &[
            ("debit", "1000", "300.00", None),
            ("credit", "3000", "100.00", Some("INV-A")),
            ("credit", "3000", "200.00", Some("INV-B")),
        ],
    );
    f.post(
        "bill-a",
        "2026-02-01",
        &[
            ("debit", "6000", "100.00", Some("VEND-A")),
            ("credit", "2000", "100.00", Some("VEND-A")),
        ],
    );
    f.post(
        "bill-b",
        "2026-02-20",
        &[
            ("debit", "7000", "200.00", Some("VEND-B")),
            ("credit", "2000", "200.00", Some("VEND-B")),
        ],
    );
    f.post(
        "batched-payment",
        "2026-04-15",
        &[
            ("debit", "2000", "100.00", Some("VEND-A")),
            ("debit", "2000", "200.00", Some("VEND-B")),
            ("credit", "1000", "300.00", None),
        ],
    );

    // Preferences: each creditor's own 100.00 and 200.00, both outside the
    // contemporaneous window and with no later new value.
    let run_out = ok(
        &f.book,
        &[
            "procedure",
            "run",
            "lookback.preferences",
            "--effective-through",
            "2026-04-30",
        ],
    );
    let run_data = data(&run_out);
    assert_eq!(integer(run_data, "version"), 3);
    let expected = vec![
        ("VEND-A".to_string(), 10_000),
        ("VEND-B".to_string(), 20_000),
    ];
    assert_eq!(
        margins(rows(run_data, "findings")),
        expected,
        "{}",
        run_out.render()
    );

    // The same margins retained: a recorded run, listed back from the book.
    let recorded = ok(
        &f.book,
        &[
            "finding",
            "record",
            "lookback.preferences",
            "--effective-through",
            "2026-04-30",
        ],
    );
    let certificate = text(data(&recorded), "certificate").to_string();
    assert_eq!(integer(data(&recorded), "finding_count"), 2);
    let listed = ok(
        &f.book,
        &[
            "finding",
            "list",
            "--certificate",
            &format!("C:{certificate}"),
        ],
    );
    let retained: Vec<Json> = rows(data(&listed), "findings")
        .iter()
        .map(|row| row.get("finding").expect("finding").clone())
        .collect();
    assert_eq!(margins(&retained), expected, "{}", listed.render());

    // Net equity: each investor's own subscription.
    let ponzi = ok(&f.book, &["procedure", "run", "ponzi.net_investment"]);
    assert_eq!(
        margins(rows(data(&ponzi), "findings")),
        vec![("INV-A".to_string(), 10_000), ("INV-B".to_string(), 20_000)],
        "{}",
        ponzi.render()
    );

    // A pool of 90.00 shared by claims of 100.00 and 200.00: 30.00 and 60.00.
    let pro_rata = ok(
        &f.book,
        &[
            "procedure",
            "run",
            "distribution.pro_rata",
            "--param",
            "distributable_pool=9000",
        ],
    );
    assert_eq!(
        margins(rows(data(&pro_rata), "findings")),
        vec![("INV-A".to_string(), 3_000), ("INV-B".to_string(), 6_000)],
        "{}",
        pro_rata.render()
    );

    // Solvency maturity & valuation workflow on a fresh book (`fa-5dpd`, `fa-8j3g`, `fa-v0m2`):
    // 1. Balance-sheet solvency with contra-assets (1510 Equipment +100.00, 1590 Accumulated
    //    Depreciation -80.00 -> net assets 20.00 vs 2000 Liabilities 50.00 -> deficit 30.00),
    //    historical RegisterEquals non-override, and explicit dated valuation adjustment
    //    (+22.00 USD on 1510 effective 2026-04-30 -> valued assets 42.00 vs 50.00 -> deficit 8.00).
    // 2. Cash-flow solvency with authenticated obligation maturity (`obligation_maturity`):
    //    cash 100.00 at 2026-04-30, long-term debt 1000.00 booked 2026-01-01 due 2026-12-31
    //    plus short-term debts 40.00 (due 2026-05-15), 35.00 (due 2026-05-30), and 50.00
    //    (due 2026-05-31): 0 findings at 30 days (75.00 <= 100.00) and 25.00 shortfall at 31 days.
    let s = Fixture::new();
    let sol_chart = s.file(
        "sol_chart.json",
        r#"{"accounts":[
{"code":"1510","name":"Equipment","type":"Asset","unit":"USD"},
{"code":"1590","name":"Accumulated depreciation","type":"Asset","normal_balance":"credit","unit":"USD"}]}"#,
    );
    ok(&s.book, &["chart", "import", &sol_chart]);

    // Fund 100.00 cash on Jan 1 against 1000.00 long-term AP (due 2026-12-31) and 900.00 rent.
    let long_debt = s.file(
        "long-debt.json",
        r#"{"effective_date":"2026-01-10","idempotency_key":"long-debt","legs":[
{"side":"debit","account":"1000","amount":"100.00 USD"},
{"side":"debit","account":"6000","amount":"900.00 USD"},
{"side":"credit","account":"2000","amount":"1000.00 USD"}
],"obligation_maturity":[{"ordinal":2,"status":"contractual","installments":[{"due_date":"2026-12-31","amount":"1000.00 USD"}]}]}"#,
    );
    ok(
        &s.book,
        &["post", "--intent", &long_debt, "--evidence", &s.evidence],
    );

    // At 2026-04-30 with horizon_days=30, the 1000.00 debt due 2026-12-31 is deferred -> 0 findings.
    let cf_long_only = ok(
        &s.book,
        &[
            "procedure",
            "run",
            "solvency.cash_flow_test",
            "--effective-through",
            "2026-04-30",
            "--param",
            "horizon_days=30",
        ],
    );
    assert_eq!(integer(data(&cf_long_only), "finding_count"), 0);

    // Add inside-horizon and boundary obligations: 40.00 due May 15, 35.00 due May 30, 50.00 due May 31.
    for (key, due, amt) in [
        ("short-may15", "2026-05-15", "40.00 USD"),
        ("short-may30", "2026-05-30", "35.00 USD"),
        ("short-may31", "2026-05-31", "50.00 USD"),
    ] {
        let doc = s.file(
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"2026-04-10","idempotency_key":"{key}","legs":[
{{"side":"debit","account":"6000","amount":"{amt}"}},
{{"side":"credit","account":"2000","amount":"{amt}"}}
],"obligation_maturity":[{{"ordinal":1,"status":"contractual","installments":[{{"due_date":"{due}","amount":"{amt}"}}]}}]}}"#
            ),
        );
        ok(
            &s.book,
            &["post", "--intent", &doc, "--evidence", &s.evidence],
        );
    }

    // 30-day horizon (through May 30): 40.00 + 35.00 = 75.00 <= 100.00 cash -> 0 findings.
    let cf_30 = ok(
        &s.book,
        &[
            "procedure",
            "run",
            "solvency.cash_flow_test",
            "--effective-through",
            "2026-04-30",
            "--param",
            "horizon_days=30",
        ],
    );
    assert_eq!(integer(data(&cf_30), "finding_count"), 0);

    // 31-day horizon (through May 31): 75.00 + 50.00 = 125.00 > 100.00 cash -> 25.00 (2,500) shortfall.
    let cf_31 = ok(
        &s.book,
        &[
            "procedure",
            "run",
            "solvency.cash_flow_test",
            "--effective-through",
            "2026-04-30",
            "--param",
            "horizon_days=31",
        ],
    );
    assert_eq!(integer(data(&cf_31), "finding_count"), 1);
    let cf_finding = &rows(data(&cf_31), "findings")[0];
    assert_eq!(
        integer(cf_finding.get("statistic").unwrap(), "value"),
        2_500
    );

    // Record and replay the 31-day cash-flow solvency certificate.
    let cf_rec = ok(
        &s.book,
        &[
            "finding",
            "record",
            "solvency.cash_flow_test",
            "--effective-through",
            "2026-04-30",
            "--param",
            "horizon_days=31",
        ],
    );
    let cf_cert = text(data(&cf_rec), "certificate").to_string();
    let cf_replayed = ok(&s.book, &["replay", &format!("C:{cf_cert}")]);
    assert_eq!(data(&cf_replayed), data(&cf_31));

    // Balance-sheet solvency with contra-assets and explicit valuation adjustment on a dedicated book.
    let b = Fixture::new();
    let bs_chart = b.file(
        "bs_chart.json",
        r#"{"accounts":[
{"code":"1510","name":"Equipment","type":"Asset","unit":"USD"},
{"code":"1590","name":"Accumulated depreciation","type":"Asset","normal_balance":"credit","unit":"USD"}]}"#,
    );
    ok(&b.book, &["chart", "import", &bs_chart]);
    b.post(
        "equip-fund",
        "2026-04-01",
        &[
            ("debit", "1510", "100.00", None),
            ("credit", "2000", "50.00", None),
            ("credit", "3000", "50.00", None),
        ],
    );
    b.post(
        "equip-dep",
        "2026-04-15",
        &[
            ("debit", "6000", "80.00", None),
            ("credit", "1590", "80.00", None),
        ],
    );
    let bs_book = ok(
        &b.book,
        &[
            "procedure",
            "run",
            "solvency.balance_sheet_test",
            "--effective-through",
            "2026-04-30",
        ],
    );
    assert_eq!(integer(data(&bs_book), "finding_count"), 1);
    assert_eq!(
        integer(
            rows(data(&bs_book), "findings")[0]
                .get("statistic")
                .unwrap(),
            "value"
        ),
        3_000
    );

    // Post an entry carrying an authenticated valuation adjustment (+22.00 USD on 1510 at 2026-04-30).
    let val_entry = b.file(
        "val-entry.json",
        r#"{"effective_date":"2026-04-20","idempotency_key":"val-entry","legs":[
{"side":"debit","account":"6000","amount":"1.00 USD"},
{"side":"credit","account":"3000","amount":"1.00 USD"}
],"valuation_adjustments":[{"valuation_id":"VAL-EQUIP-2026Q2","account":"1510","basis_law":"signed_delta","effective_date":"2026-04-30","amount":"22.00 USD"}]}"#,
    );
    ok(
        &b.book,
        &["post", "--intent", &val_entry, "--evidence", &b.evidence],
    );
    let bs_valued = ok(
        &b.book,
        &[
            "procedure",
            "run",
            "solvency.balance_sheet_test",
            "--effective-through",
            "2026-04-30",
        ],
    );
    assert_eq!(integer(data(&bs_valued), "finding_count"), 1);
    let bs_val_finding = &rows(data(&bs_valued), "findings")[0];
    assert_eq!(
        integer(bs_val_finding.get("statistic").unwrap(), "value"),
        800,
        "net book assets 20.00 + valuation delta 22.00 = 42.00 vs 50.00 debt -> 8.00 deficit"
    );
    assert!(
        text(bs_val_finding, "narrative")
            .contains("VAL-EQUIP-2026Q2:signed_delta:exact_as_of(2026-04-30)")
    );
}
