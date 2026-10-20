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

fn head(book: &Path) -> i128 {
    let info = ok(book, &["book", "info"]);
    integer(info.get("coordinate").unwrap(), "known_at")
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
    assert_eq!(head(&f.book), before);
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
    assert_eq!(head(&f.book), before, "history hydration publishes nothing");
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
