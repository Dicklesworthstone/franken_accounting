//! Real CLI processes distinguish cumulative functional stock from period
//! activity and preserve each report's effective and recorded coordinates.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::Budget;
use asupersync::runtime::RuntimeBuilder;
use fa::{Book, BookKeys, Entropy};
use fa_cli::json::{self, Json};
use fa_model::symbols::{property, relation};
use fgdb::{Database, DatabaseKeys, ReadError, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, CommitSeq};

fn data(value: &Json) -> &Json {
    value.get("data").expect("robot data")
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value.get(key).and_then(Json::as_str).expect(key)
}

fn integer(value: &Json, key: &str) -> i128 {
    match value.get(key).expect(key) {
        Json::Int(value) => *value,
        other => panic!("{key} is not an integer: {other:?}"),
    }
}

fn rows<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    value.get(key).and_then(Json::as_arr).expect(key)
}

fn run(book: &Path, args: &[&str]) -> (i32, Json) {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(["--via", "direct"])
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .env_remove("FA_KEYS")
        .output()
        .expect("run fa");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{args:?}: {stdout}\n{stderr}");
    fa_cli::verbs::registry()
        .unwrap()
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("{args:?}: {error}\n{stdout}\n{stderr}"));
    (
        output.status.code().unwrap(),
        json::parse(lines[0]).unwrap(),
    )
}

fn ok(book: &Path, args: &[&str]) -> Json {
    let (status, output) = run(book, args);
    assert_eq!(status, 0, "{args:?}: {}", output.render());
    output
}

fn ok_many(book: &Path, args: &[&str]) -> Vec<Json> {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(["--via", "direct"])
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .env_remove("FA_KEYS")
        .output()
        .expect("run multi-event fa command");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{args:?}: {stdout}\n{stderr}");
    let registry = fa_cli::verbs::registry().unwrap();
    stdout
        .lines()
        .map(|line| {
            registry
                .check_line(line)
                .unwrap_or_else(|error| panic!("{args:?}: {error}\n{line}"));
            json::parse(line).unwrap()
        })
        .collect()
}

fn statement_amounts<'a>(report: &'a Json, code: &str, unit: &str) -> &'a [Json] {
    let line = rows(report, "lines")
        .iter()
        .find(|line| text(line, "code") == code && text(line, "unit") == unit)
        .unwrap_or_else(|| panic!("missing statement line {code}/{unit}: {report:?}"));
    rows(line, "amounts")
}

fn head(book: &Path) -> i128 {
    let info = ok(book, &["book", "info"]);
    integer(info.get("coordinate").unwrap(), "known_at")
}

/// AccessEvents recorded after `since` (fa-7dw): a read-only token's command
/// records one before it observes the book, refused or not.
fn access_events_since(book: &Path, since: i128) -> i128 {
    let log = ok(book, &["access", "log", "--since", &since.to_string()]);
    integer(log.get("data").unwrap(), "count")
}

fn total_debits(event: &Json) -> &str {
    text(data(event).get("totals").unwrap(), "debits")
}

fn db_keys(seed: u8) -> DatabaseKeys {
    DatabaseKeys::new(
        [seed; 32],
        DatabaseSecurityNamespaceId([seed.wrapping_add(1); 32]),
        [seed.wrapping_add(2); 32],
    )
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    evidence: String,
}

impl Fixture {
    fn new() -> Self {
        Self::create(None)
    }

    fn create(known_seed: Option<u8>) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let dir = std::env::temp_dir().join(format!(
                "fa-fx-stock-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => break dir,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create {}: {error}", dir.display()),
            }
        };
        let book = dir.join("book");
        if let Some(seed) = known_seed {
            let keys = BookKeys::for_development(seed);
            let created = Book::create_dir(
                &book,
                keys.clone(),
                fa_journal::BookSpec {
                    book_id: fa_model::Id128([seed; 16]),
                    name: "Cold cumulative FX history".into(),
                    base_unit: fa_money::UnitRegistry::embedded()
                        .unwrap()
                        .lookup("USD")
                        .unwrap(),
                    calendar: fa_time::FiscalCalendar::monthly("fx-stock-cold", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(u64::from(seed)),
            )
            .unwrap();
            drop(created);
            keys.save(&book.join("book.keys")).unwrap();
        } else {
            ok(&book, &["book", "create", "--name", "Carried FX balances"]);
        }
        let chart = dir.join("chart.json");
        std::fs::write(&chart, r#"{"accounts":[{"code":"1200","name":"EUR Receivable","type":"Asset","unit":"EUR"},{"code":"4000","name":"EUR Revenue","type":"Revenue","unit":"EUR"}]}"#).unwrap();
        ok(&book, &["chart", "import", chart.to_str().unwrap()]);
        ok(&book, &["period", "create", "--fiscal-year", "2026"]);
        for period in ["FY2026-P01", "FY2026-P02"] {
            ok(&book, &["period", "open", period]);
        }
        let source = dir.join("invoices.txt");
        std::fs::write(&source, "Retained January and February invoices.").unwrap();
        let evidence = ok(
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
        Self {
            dir,
            book,
            evidence: text(data(&evidence), "oid").into(),
        }
    }

    fn file(&self, name: &str, content: &str) -> String {
        let path = self.dir.join(name);
        std::fs::write(&path, content).unwrap();
        path.display().to_string()
    }

    fn rate(&self, name: &str, date: &str, numerator: u32) -> String {
        let path = self.file(
            &format!("{name}-rate.json"),
            &format!(r#"{{"base_unit":"USD","quote_unit":"EUR","rate_num":"{numerator}","rate_den":"10","rounding":"HalfEven","as_of":"{date}","retrieved_at_ns":1767571200000000000,"purpose":"spot_close","source":"{name}"}}"#),
        );
        let rate = ok(&self.book, &["fx", "rate", "add", "--from-json", &path]);
        text(data(&rate), "oid").into()
    }

    fn post(&self, key: &str, date: &str, amount: &str, numerator: u32) -> Json {
        let oid = self.rate(key, date, numerator);
        let path = self.file(
            &format!("{key}.json"),
            &format!(r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":[{{"side":"debit","account":"1200","amount":"{amount} EUR"}},{{"side":"credit","account":"4000","amount":"{amount} EUR"}}],"fx":{{"law":"SpotClose","rates":["D:{oid}"]}}}}"#),
        );
        ok(
            &self.book,
            &["post", "--intent", &path, "--evidence", &self.evidence],
        )
    }

    fn compact(&self, seed: u8) {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime
            .block_on(Database::open(
                &cx.commit(),
                &self.book.join("store"),
                db_keys(seed),
            ))
            .unwrap();
        let before = db.frontier().unwrap();
        runtime.block_on(db.compact(&cx.commit())).unwrap();
        assert_eq!(db.frontier().unwrap(), before);
        drop(db);
        let cold = runtime
            .block_on(Database::open(
                &cx.commit(),
                &self.book.join("store"),
                db_keys(seed),
            ))
            .unwrap();
        assert!(matches!(
            cold.delta_since(CommitSeq(0)),
            Err(ReadError::DeltaCursorRetired { .. })
        ));
        assert_eq!(cold.frontier().unwrap(), before);
    }

    fn forge_january_end(&self, seed: u8) -> CommitSeq {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime
            .block_on(Database::open(
                &cx.commit(),
                &self.book.join("store"),
                db_keys(seed),
            ))
            .unwrap();
        let period = fa_model::period_vid("fx-stock-cold", "FY2026-P01");
        let before = db.vertex(period).unwrap().unwrap();
        assert_eq!(
            fa_journal::rows::prop(&before, property::PERIOD_END),
            Some(&CanonicalScalar::Int(i64::from(
                fa_time::DateDay::from_ymd(2026, 2, 1).unwrap().0
            )))
        );
        let mut damage = WriteBatch::new(relation::IN_BOOK);
        damage.set_vertex_property(
            period,
            property::PERIOD_END,
            Some(CanonicalScalar::Int(i64::from(
                fa_time::DateDay::from_ymd(2026, 3, 1).unwrap().0,
            ))),
        );
        runtime.block_on(db.write(&cx.commit(), damage)).unwrap()
    }
}

#[test]
fn functional_stock_carries_prior_periods_without_changing_activity_or_native_currency_rows() {
    let f = Fixture::new();
    f.post("january", "2026-01-05", "100.00", 11);
    let february = f.post("february", "2026-02-05", "50.00", 12);
    let pin = integer(data(&february), "recorded_at").to_string();
    let stock = ok(&f.book, &["tb", "--functional", "--period", "FY2026-P02"]);
    assert_eq!(text(&stock, "event"), "functional_stock_balance");
    assert_eq!(text(data(&stock), "scope"), "stock");
    assert_eq!(text(data(&stock), "effective_through"), "2026-02-28");
    assert_eq!(text(data(&stock), "base_unit"), "USD");
    assert_eq!(total_debits(&stock), "170.00 USD");
    assert_eq!(integer(data(&stock), "entries"), 2);
    assert_eq!(data(&stock).get("balanced"), Some(&Json::Bool(true)));
    assert!(rows(data(&stock), "pending_rows").is_empty());
    let activity = ok(
        &f.book,
        &["tb", "--functional", "--activity", "--period", "FY2026-P02"],
    );
    assert_eq!(text(&activity, "event"), "functional_trial_balance");
    assert_eq!(text(data(&activity), "scope"), "period_activity");
    assert_eq!(total_debits(&activity), "60.00 USD");
    assert_eq!(integer(data(&activity), "entries"), 1);
    for (cutoff, expected) in [
        ("2026-01-04", "0.00 USD"),
        ("2026-01-05", "110.00 USD"),
        ("2026-02-04", "110.00 USD"),
        ("2026-02-05", "170.00 USD"),
    ] {
        let report = ok(&f.book, &["tb", "--functional", "--as-of", cutoff]);
        assert_eq!(text(data(&report), "effective_through"), cutoff);
        assert_eq!(total_debits(&report), expected);
    }

    f.post("late-january", "2026-01-20", "20.00", 13);
    let current = ok(&f.book, &["tb", "--functional", "--period", "FY2026-P02"]);
    assert_eq!(total_debits(&current), "196.00 USD");
    let january = ok(&f.book, &["tb", "--functional", "--as-of", "2026-01-31"]);
    assert_eq!(total_debits(&january), "136.00 USD");
    let historical = ok(
        &f.book,
        &[
            "tb",
            "--functional",
            "--period",
            "FY2026-P02",
            "--as-known-at",
            &pin,
        ],
    );
    assert_eq!(data(&historical), data(&stock));
    let native = ok(&f.book, &["tb", "--period", "FY2026-P02"]);
    let euro = rows(data(&native), "unit_totals")
        .iter()
        .find(|row| text(row, "unit") == "EUR")
        .unwrap();
    assert_eq!(text(euro, "debits"), "170.00 EUR");
    assert_eq!(text(euro, "credits"), "170.00 EUR");
    let receivable = rows(data(&current), "rows")
        .iter()
        .find(|row| text(row, "account") == "1200")
        .unwrap();
    assert_eq!(text(receivable, "net"), "196.00 USD");

    f.rate("later-quote", "2026-01-05", 90);
    let before_reads = head(&f.book);
    let unchanged = ok(&f.book, &["tb", "--functional", "--as-of", "2026-02-28"]);
    for field in [
        "rows",
        "pending_rows",
        "totals",
        "pending_totals",
        "entries",
    ] {
        assert_eq!(data(&unchanged).get(field), data(&current).get(field));
    }
    assert_eq!(head(&f.book), before_reads);
}

#[test]
fn known_at_bounded_reader_can_read_its_stock_prefix_after_later_period_postings() {
    let f = Fixture::new();
    let first = f.post("pinned-january", "2026-01-05", "100.00", 11);
    let pin = integer(data(&first), "recorded_at").to_string();
    let token = f.dir.join("stock-reader.token").display().to_string();
    ok(
        &f.book,
        &[
            "capability",
            "issue",
            "--holder",
            "stock-reader",
            "--profile",
            "human",
            "--op",
            "read",
            "--grant",
            "issue_capability",
            "--grant",
            "read",
            "--known-at-most",
            &pin,
            "--out",
            &token,
        ],
    );
    f.post("later-february", "2026-02-05", "50.00", 12);
    let before = head(&f.book);
    for selector in [["--period", "FY2026-P02"], ["--as-of", "2026-02-28"]] {
        let historical = ok(
            &f.book,
            &[
                "--token",
                &token,
                "tb",
                "--functional",
                selector[0],
                selector[1],
                "--as-known-at",
                &pin,
            ],
        );
        assert_eq!(total_debits(&historical), "110.00 USD");
        assert_eq!(integer(data(&historical), "known_at").to_string(), pin);
        let (status, denied) = run(
            &f.book,
            &[
                "--token",
                &token,
                "tb",
                "--functional",
                selector[0],
                selector[1],
            ],
        );
        assert_eq!(status, 7, "{}", denied.render());
        assert!(text(data(&denied), "message").contains("known_at"));
    }
    assert_eq!(
        head(&f.book),
        before + access_events_since(&f.book, before),
        "only the token session's AccessEvents were written"
    );
}

#[test]
fn historical_period_stock_hydrates_cold_compacted_history_before_resolving_the_period() {
    const SEED: u8 = 0xe7;
    let f = Fixture::create(Some(SEED));
    let first = f.post("cold-january", "2026-01-05", "100.00", 11);
    let pin = integer(data(&first), "recorded_at").to_string();
    let expected = ok(
        &f.book,
        &[
            "tb",
            "--functional",
            "--period",
            "FY2026-P02",
            "--as-known-at",
            &pin,
        ],
    );
    let token = f.dir.join("cold-stock-reader.token").display().to_string();
    ok(
        &f.book,
        &[
            "capability",
            "issue",
            "--holder",
            "cold-stock-reader",
            "--profile",
            "human",
            "--op",
            "read",
            "--grant",
            "issue_capability",
            "--grant",
            "read",
            "--known-at-most",
            &pin,
            "--out",
            &token,
        ],
    );
    f.post("cold-later-february", "2026-02-05", "50.00", 12);
    let before = head(&f.book);
    f.compact(SEED);
    let historical = ok(
        &f.book,
        &[
            "--token",
            &token,
            "tb",
            "--functional",
            "--period",
            "FY2026-P02",
            "--as-known-at",
            &pin,
        ],
    );
    assert_eq!(data(&historical), data(&expected));
    assert_eq!(total_debits(&historical), "110.00 USD");
    assert_eq!(integer(data(&historical), "entries"), 1);
    assert_eq!(
        head(&f.book),
        before + access_events_since(&f.book, before),
        "history hydration publishes nothing; the only writes are the token's AccessEvents"
    );
}

#[test]
fn forged_period_end_cannot_extend_current_stock_but_does_not_rewrite_an_earlier_prefix() {
    const SEED: u8 = 0xe8;
    let f = Fixture::create(Some(SEED));
    f.post("period-end-january", "2026-01-05", "100.00", 11);
    f.post("period-end-february", "2026-02-05", "50.00", 12);
    let expected = ok(&f.book, &["tb", "--functional", "--period", "FY2026-P01"]);
    let pin = integer(data(&expected), "known_at").to_string();
    assert_eq!(total_debits(&expected), "110.00 USD");
    let damaged_at = f.forge_january_end(SEED);
    let (status, refused) = run(&f.book, &["tb", "--functional", "--period", "FY2026-P01"]);
    assert_eq!(status, 8, "{}", refused.render());
    assert_eq!(text(&refused, "event"), "error");
    assert_eq!(text(data(&refused), "class"), "verification");

    let historical = ok(
        &f.book,
        &[
            "tb",
            "--functional",
            "--period",
            "FY2026-P01",
            "--as-known-at",
            &pin,
        ],
    );
    assert_eq!(data(&historical), data(&expected));
    let explicit = ok(&f.book, &["tb", "--functional", "--as-of", "2026-01-31"]);
    assert_eq!(text(data(&explicit), "effective_through"), "2026-01-31");
    assert_eq!(total_debits(&explicit), "110.00 USD");
    assert_eq!(integer(data(&explicit), "entries"), 1);
    assert_eq!(data(&explicit).get("rows"), data(&expected).get("rows"));
    assert_eq!(head(&f.book), i128::from(damaged_at.0));
}

#[test]
fn ambiguous_stock_and_activity_selections_refuse_before_opening_a_book() {
    let absent = std::env::temp_dir().join(format!("fa-fx-stock-absent-{}", std::process::id()));
    assert!(!absent.exists());
    for selection in [
        vec![
            "tb",
            "--functional",
            "--period",
            "FY2026-P01",
            "--period",
            "FY2026-P02",
        ],
        vec![
            "tb",
            "--functional",
            "--period",
            "FY2026-P01",
            "--as-of",
            "2026-02-28",
        ],
        vec!["tb", "--functional", "--activity", "--as-of", "2026-02-28"],
    ] {
        let (status, refused) = run(&absent, &selection);
        assert_eq!(status, 2, "{selection:?}: {}", refused.render());
        assert_eq!(text(data(&refused), "class"), "usage");
        assert_eq!(refused.get("book"), Some(&Json::Null));
    }
    assert!(!absent.exists());
}

#[test]
fn functional_statement_cli_reopens_cold_history_certifies_replays_and_tracks_backdates() {
    let seed = 0xe8;
    let fixture = Fixture::create(Some(seed));
    fixture.post("statement-january", "2026-01-05", "100.00", 11);
    fixture.post("statement-february", "2026-02-05", "200.00", 12);
    fixture.compact(seed);
    let before = head(&fixture.book);
    let native = ok(
        &fixture.book,
        &[
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P02",
            "--compare",
            "FY2026-P01",
        ],
    );
    assert_eq!(
        statement_amounts(data(&native), "assets", "EUR"),
        &[
            Json::Str("300.00 EUR".into()),
            Json::Str("100.00 EUR".into())
        ]
    );
    let balance = ok(
        &fixture.book,
        &[
            "statement",
            "balance-sheet",
            "--functional",
            "--for",
            "FY2026-P02",
            "--compare",
            "FY2026-P01",
        ],
    );
    assert_eq!(
        text(data(&balance), "scope"),
        "single-book-functional-currency"
    );
    assert_eq!(
        text(data(&balance), "valuation_basis"),
        "retained-base-amounts"
    );
    assert_eq!(text(data(&balance), "base_unit"), "USD");
    assert_eq!(data(&balance).get("functional"), Some(&Json::Bool(true)));
    assert_eq!(
        statement_amounts(data(&balance), "assets", "USD"),
        &[
            Json::Str("350.00 USD".into()),
            Json::Str("110.00 USD".into())
        ]
    );
    assert_eq!(
        statement_amounts(data(&balance), "balance_check", "USD"),
        &[Json::Str("0.00 USD".into()), Json::Str("0.00 USD".into())]
    );
    assert!(
        rows(data(&balance), "lines")
            .iter()
            .all(|line| text(line, "unit") == "USD")
    );
    assert_eq!(
        head(&fixture.book),
        before,
        "functional read must not publish a valuation"
    );

    let certificate_path = fixture.dir.join("functional-statement.cert");
    let original = ok_many(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--functional",
            "--for",
            "FY2026-P02",
            "--compare",
            "FY2026-P01",
            "--certificate-out",
            certificate_path.to_str().unwrap(),
            "--render",
            "md",
        ],
    );
    assert_eq!(original.len(), 3);
    assert_eq!(text(&original[0], "event"), "statement");
    assert_eq!(
        statement_amounts(data(&original[0]), "net_income", "USD"),
        &[
            Json::Str("240.00 USD".into()),
            Json::Str("110.00 USD".into())
        ]
    );
    assert_eq!(text(&original[1], "event"), "report_certificate");
    assert_eq!(text(&original[2], "event"), "rendered");
    assert!(
        text(data(&original[2]), "markdown").contains("Valuation basis: functional currency USD")
    );
    let certificate =
        fa::ReportCertificate::decode(&std::fs::read(&certificate_path).unwrap()).unwrap();
    assert!(matches!(
        certificate.selection,
        fa::ReportSelection::FunctionalStatement(_)
    ));
    let reference = format!("C:{}", text(data(&original[1]), "oid"));
    let replay = ok_many(&fixture.book, &["replay", &reference]);
    assert_eq!(
        replay[0], original[0],
        "retained replay keeps the explicit functional basis"
    );
    assert_eq!(
        text(
            data(&ok(&fixture.book, &["certificate", "status", &reference])),
            "status"
        ),
        "Current"
    );

    fixture.post("statement-backdate", "2026-01-20", "10.00", 13);
    let status = ok(&fixture.book, &["certificate", "status", &reference]);
    assert_eq!(text(data(&status), "status"), "SupersededBy");
    assert!(!rows(data(&status), "later_entries").is_empty());
    assert_eq!(
        ok_many(&fixture.book, &["replay", &reference])[0],
        original[0]
    );
    let historical = ok(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--functional",
            "--for",
            "FY2026-P02",
            "--compare",
            "FY2026-P01",
            "--as-known-at",
            &certificate.known_at.0.to_string(),
        ],
    );
    assert_eq!(data(&historical), data(&original[0]));
    let current = ok(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--functional",
            "--for",
            "FY2026-P02",
            "--compare",
            "FY2026-P01",
        ],
    );
    assert_eq!(
        statement_amounts(data(&current), "net_income", "USD"),
        &[
            Json::Str("240.00 USD".into()),
            Json::Str("123.00 USD".into())
        ]
    );
}

#[test]
fn functional_statement_cli_refuses_unsupported_workflows_and_unvalued_foreign_rows() {
    let fixture = Fixture::new();
    // A functional statement diff is a supported workflow (ef8b3dee8): it is
    // judged on the journal, so a frontier before the period existed is a
    // law refusal naming the period and the sequence, not a usage error.
    let (code, refused) = run(
        &fixture.book,
        &[
            "statement",
            "diff",
            "--functional",
            "--for",
            "FY2026-P01",
            "--definition",
            "balance-sheet",
            "--before",
            "1",
        ],
    );
    assert_eq!(code, 3, "{}", refused.render());
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-152");
    assert!(
        text(data(&refused), "message")
            .contains("unknown statement period `FY2026-P01` at sequence 1"),
        "{}",
        refused.render()
    );
    for args in [
        vec![
            "statement",
            "lint",
            "--functional",
            "--definition",
            "balance-sheet",
        ],
        vec![
            "statement",
            "balance-sheet",
            "--functional",
            "--for",
            "FY2026-P01",
            "--as-originally-reported",
        ],
        vec![
            "statement",
            "equity-roll-forward",
            "--functional",
            "--from",
            "2026-01-01",
            "--to",
            "2026-01-31",
        ],
    ] {
        assert_eq!(run(&fixture.book, &args).0, 2, "{args:?}");
    }
    let unvalued = fixture.file("unvalued-statement.json", r#"{"effective_date":"2026-02-05","idempotency_key":"unvalued-statement","legs":[{"side":"debit","account":"1200","amount":"10.00 EUR"},{"side":"credit","account":"4000","amount":"10.00 EUR"}]}"#);
    ok(
        &fixture.book,
        &[
            "post",
            "--intent",
            &unvalued,
            "--evidence",
            &fixture.evidence,
        ],
    );
    let before = head(&fixture.book);
    let (status, event) = run(
        &fixture.book,
        &[
            "statement",
            "balance-sheet",
            "--functional",
            "--for",
            "FY2026-P02",
        ],
    );
    assert_ne!(status, 0, "{}", event.render());
    assert_ne!(text(&event, "event"), "statement");
    assert_eq!(head(&fixture.book), before);
}

#[test]
fn functional_statement_file_at_cold_head_replays_and_reports_status_without_retention() {
    let seed = 0xe9;
    let fixture = Fixture::create(Some(seed));
    fixture.post("file-only-january", "2026-01-05", "100.00", 11);
    fixture.post("file-only-february", "2026-02-05", "200.00", 12);
    let before = head(&fixture.book);
    let mut book = Book::open_dir(
        &fixture.book,
        BookKeys::for_development(seed),
        Entropy::deterministic(991),
    )
    .unwrap();
    let capability = fa::Capability::embedded(fgdb_types::VId(1), &["read", "produce"]).unwrap();
    let certified = book
        .certify_functional_statement(
            capability.holder(),
            &capability,
            fa::StatementSelection {
                definition: fa::StatementDefinition::embedded("balance-sheet").unwrap(),
                periods: vec!["FY2026-P02".into()],
                comparative: vec!["FY2026-P01".into()],
            },
            None,
        )
        .unwrap()
        .unwrap();
    assert_eq!(book.head().unwrap(), certified.certificate.known_at);
    let path = fixture.dir.join("unretained-functional-statement.cert");
    std::fs::write(&path, certified.certificate.canonical_bytes().unwrap()).unwrap();
    drop(book);
    fixture.compact(seed);
    let replay = ok(&fixture.book, &["replay", path.to_str().unwrap()]);
    assert_eq!(
        text(data(&replay), "valuation_basis"),
        "retained-base-amounts"
    );
    assert_eq!(integer(data(&replay), "known_at"), before);
    assert_eq!(
        statement_amounts(data(&replay), "assets", "USD"),
        &[
            Json::Str("350.00 USD".into()),
            Json::Str("110.00 USD".into())
        ]
    );
    let status = ok(
        &fixture.book,
        &["certificate", "status", path.to_str().unwrap()],
    );
    assert_eq!(text(data(&status), "status"), "Current");
    assert_eq!(head(&fixture.book), before);
}
