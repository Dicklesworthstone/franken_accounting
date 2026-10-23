//! Retained rational Rate documents reach the live valuation and functional
//! fold through real CLI processes. Reopened native entries remain the oracle.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use fa::{Book, BookKeys, Entropy};
use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::{Files, Stdin};
use fa_cli::entry::fa_with_authority;
use fa_cli::json::{self, Json};
use fa_model::Entry;
use fgdb_types::VId;

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

fn run(book: &Path, args: &[&str], stdin: Option<&str>) -> (i32, Json) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run fa");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
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
    let (status, output) = run(book, args, None);
    assert_eq!(status, 0, "{args:?}: {}", output.render());
    output
}

fn head(book: &Path) -> i128 {
    let output = ok(book, &["book", "info"]);
    integer(output.get("coordinate").unwrap(), "known_at")
}

/// AccessEvents recorded after `since` (fa-7dw): a read-only token's command
/// records one before it observes the book, refused or not.
fn access_events_since(book: &Path, since: i128) -> i128 {
    let log = ok(book, &["access", "log", "--since", &since.to_string()]);
    integer(log.get("data").unwrap(), "count")
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    evidence: String,
}

impl Fixture {
    fn new() -> Self {
        Self::build(None)
    }

    /// `development_keys`: create the book in process with
    /// `BookKeys::for_development(seed)`, so a test can reopen its store
    /// directly (a planted defect); otherwise `fa book create` makes it.
    fn build(development_keys: Option<u8>) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let dir = std::env::temp_dir().join(format!(
                "fa-fx-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => break dir,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create retained fixture {}: {error}", dir.display()),
            }
        };
        let book = dir.join("book");
        match development_keys {
            None => {
                ok(&book, &["book", "create", "--name", "Exact FX"]);
            }
            Some(seed) => {
                let units = fa_money::UnitRegistry::embedded().unwrap();
                let keys = BookKeys::for_development(seed);
                let created = Book::create_dir(
                    &book,
                    keys.clone(),
                    fa_journal::BookSpec {
                        book_id: fa_model::Id128([seed; 16]),
                        name: "Exact FX".into(),
                        base_unit: units.lookup("USD").unwrap(),
                        calendar: fa_time::FiscalCalendar::monthly("fiscal", 1, 1).unwrap(),
                        time_zone_policy: None,
                        entities: Vec::new(),
                        opening_date: None,
                    },
                    Entropy::deterministic(u64::from(seed)),
                )
                .unwrap();
                keys.save(&book.join("book.keys")).unwrap();
                drop(created);
            }
        }
        let chart = dir.join("chart.json");
        std::fs::write(&chart, r#"{"accounts":[{"code":"1000","name":"EUR Cash","type":"Asset","unit":"EUR"},{"code":"1200","name":"EUR Receivable","type":"Asset","unit":"EUR"},{"code":"4000","name":"EUR Revenue","type":"Revenue","unit":"EUR"},{"code":"1100","name":"USD Cash","type":"Asset","unit":"USD"},{"code":"4100","name":"USD Revenue","type":"Revenue","unit":"USD"}]}"#).unwrap();
        ok(&book, &["chart", "import", chart.to_str().unwrap()]);
        ok(&book, &["period", "create", "--fiscal-year", "2026"]);
        ok(&book, &["period", "open", "FY2026-P03"]);
        let source = dir.join("receipt.txt");
        std::fs::write(&source, "Invoice supporting the exact FX fixture.").unwrap();
        let added = ok(
            &book,
            &[
                "document",
                "add",
                source.to_str().unwrap(),
                "--kind",
                "Receipt",
                "--grade",
                "HumanUpload",
            ],
        );
        Self {
            dir,
            book,
            evidence: text(data(&added), "oid").into(),
        }
    }

    fn file(&self, name: &str, content: &str) -> String {
        let path = self.dir.join(name);
        std::fs::write(&path, content).unwrap();
        path.display().to_string()
    }

    fn rate_source(
        &self,
        name: &str,
        purpose: &str,
        date: &str,
        num: &str,
        den: &str,
        rounding: &str,
    ) -> String {
        format!(
            r#"{{"base_unit":"USD","quote_unit":"EUR","rate_num":"{num}","rate_den":"{den}","rounding":"{rounding}","as_of":"{date}","retrieved_at_ns":1772712000000000000,"purpose":"{purpose}","source":"uploaded fixture {name}"}}"#
        )
    }

    fn rate(
        &self,
        name: &str,
        purpose: &str,
        date: &str,
        num: &str,
        den: &str,
        rounding: &str,
    ) -> Json {
        let path = self.file(
            &format!("{name}.json"),
            &self.rate_source(name, purpose, date, num, den, rounding),
        );
        ok(&self.book, &["fx", "rate", "add", "--from-json", &path])
    }

    fn intent(&self, key: &str, rate_oid: &str, law: &str) -> String {
        self.file(&format!("{key}.json"), &format!(r#"{{"effective_date":"2026-03-05","idempotency_key":"{key}","legs":[{{"side":"debit","account":"1000","amount":"100.00 EUR"}},{{"side":"credit","account":"4000","amount":"100.00 EUR"}}],"fx":{{"law":"{law}","rates":["D:{rate_oid}"]}}}}"#))
    }

    fn post(&self, path: &str) -> Json {
        ok(
            &self.book,
            &["post", "--intent", path, "--evidence", &self.evidence],
        )
    }

    fn entry(&self, vid: &str) -> Entry {
        let keys = BookKeys::load(&self.book.join("book.keys")).unwrap();
        let book = Book::open_dir(&self.book, keys, Entropy::production()).unwrap();
        book.read_entry(VId(u128::from_str_radix(vid, 16).unwrap()))
            .unwrap()
            .unwrap()
            .0
    }

    fn activity(&self) -> Json {
        ok(
            &self.book,
            &["tb", "--functional", "--activity", "--period", "FY2026-P03"],
        )
    }
}

#[test]
fn retained_spot_rate_values_native_entry_and_functional_activity_after_reopen() {
    let f = Fixture::new();
    let added = f.rate("spot", "spot_close", "2026-03-05", "110", "100", "HalfEven");
    assert_eq!(text(&added, "event"), "fx_rate_added");
    assert_eq!(text(data(&added), "rate_num"), "11");
    assert_eq!(text(data(&added), "rate_den"), "10");
    assert_eq!(text(data(&added), "grade"), "HumanUpload");
    let oid = text(data(&added), "oid");
    let before_retry = head(&f.book);
    let retry = f.rate("spot", "spot_close", "2026-03-05", "11", "10", "HalfEven");
    assert_eq!(
        data(&retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(data(&retry).get("oid"), data(&added).get("oid"));
    assert_eq!(head(&f.book), before_retry);

    let posted = f.post(&f.intent("sale", oid, "SpotClose"));
    let entry = f.entry(text(data(&posted), "vid"));
    let native = &entry.proposal;
    assert_eq!(native.legs.len(), 2);
    assert!(native.legs.iter().all(|leg| leg.amount.mantissa == 10_000));
    assert!(
        native
            .legs
            .iter()
            .all(|leg| leg.base_amount.unwrap().mantissa == 11_000)
    );
    let base = native.base_totals.as_ref().unwrap();
    assert_eq!((base.debits, base.credits), (11_000, 11_000));
    assert_eq!(base.fx_law_oid, fa::FxLawId::SpotClose.oid());
    assert_eq!(base.rate_doc_oids.len(), 1);
    assert!(
        native
            .evidence
            .iter()
            .any(|evidence| evidence.role == 3 && evidence.document_oid == base.rate_doc_oids[0])
    );

    let tb = ok(&f.book, &["tb", "--activity", "--period", "FY2026-P03"]);
    let euro = rows(data(&tb), "unit_totals")
        .iter()
        .find(|row| text(row, "unit") == "EUR")
        .unwrap();
    assert_eq!(text(euro, "debits"), "100.00 EUR");
    assert_eq!(text(euro, "credits"), "100.00 EUR");
    let activity = f.activity();
    assert_eq!(text(&activity, "event"), "functional_trial_balance");
    assert!(activity.get("book").is_some_and(|book| book != &Json::Null));
    assert!(
        activity
            .get("coordinate")
            .is_some_and(|coordinate| coordinate != &Json::Null)
    );
    assert_eq!(text(data(&activity), "scope"), "period_activity");
    assert_eq!(text(data(&activity), "base_unit"), "USD");
    assert_eq!(
        text(data(&activity).get("totals").unwrap(), "debits"),
        "110.00 USD"
    );
    assert_eq!(data(&activity).get("balanced"), Some(&Json::Bool(true)));
    assert_eq!(rows(data(&activity), "pending_rows").len(), 0);
    let cash = rows(data(&activity), "rows")
        .iter()
        .find(|row| text(row, "account") == "1000")
        .unwrap();
    assert_eq!(text(cash, "net"), "110.00 USD");

    // A later retained quote is not a new valuation of an old journal entry.
    f.rate("later", "spot_close", "2026-03-05", "9", "1", "HalfEven");
    let unchanged = f.activity();
    for field in ["rows", "totals", "entries", "fold_digest"] {
        assert_eq!(data(&unchanged).get(field), data(&activity).get(field));
    }
}

fn settlement_fixture() -> (Fixture, String, String) {
    let f = Fixture::new();
    let chart = f.file(
        "settlement-chart.json",
        r#"{"accounts":[{"code":"3900","name":"FX conversion","type":"Equity","unit":"any-currency"},{"code":"4900","name":"Realized FX","type":"Revenue","unit":"USD"}]}"#,
    );
    ok(&f.book, &["chart", "import", &chart]);
    let party = f.file(
        "customer.json",
        r#"{"code":"CUST","kind":"Customer","name":"Foreign customer"}"#,
    );
    ok(&f.book, &["party", "add", &party]);
    let spot = f.rate(
        "invoice-spot",
        "spot_close",
        "2026-03-05",
        "21",
        "20",
        "HalfEven",
    );
    let invoice_path = f.file(
        "foreign-invoice.json",
        &format!(
            r#"{{"effective_date":"2026-03-05","idempotency_key":"foreign-invoice","legs":[{{"side":"debit","account":"1200","party":"CUST","amount":"1000.00 EUR"}},{{"side":"credit","account":"4000","amount":"1000.00 EUR"}}],"fx":{{"law":"SpotClose","rates":["D:{}"]}}}}"#,
            text(data(&spot), "oid"),
        ),
    );
    let invoice = f.post(&invoice_path);
    let invoice_vid = text(data(&invoice), "vid").to_string();
    let rate = f.rate(
        "settlement",
        "settlement",
        "2026-03-06",
        "11",
        "10",
        "HalfEven",
    );
    let rate_oid = text(data(&rate), "oid").to_string();
    (f, invoice_vid, rate_oid)
}

#[test]
fn foreign_receipt_relief_is_derived_partial_final_reversed_and_retry_safe() {
    let (f, invoice, rate) = settlement_fixture();
    let receipt_args = |number: &str, foreign: &str, cash: &str| -> Vec<String> {
        [
            "receipt",
            "--party",
            "CUST",
            "--number",
            number,
            "--date",
            "2026-03-06",
            "--cash",
            "1100",
            "--receivable",
            "1200",
            "--amount",
            cash,
            "--applies",
            &format!("{invoice}:0={foreign}"),
            "--fx-rate",
            &rate,
            "--conversion",
            "3900",
            "--realized-fx",
            "4900",
            "--evidence",
            &f.evidence,
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    };
    let plan_path = f.dir.join("receipt.plan").display().to_string();
    let mut first = receipt_args("partial", "333.33 EUR", "366.66 USD");
    first.extend(["--dry-run".into(), "--plan-out".into(), plan_path.clone()]);
    let planned = ok(
        &f.book,
        &first.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(text(&planned, "event"), "plan");
    assert_eq!(rows(data(&planned), "legs").len(), 5);
    let commit = ["commit", "--plan", &plan_path, "--grant", "read"];
    let first_post = ok(&f.book, &commit);
    let first_vid = text(data(&first_post), "vid");
    let first_entry = f.entry(first_vid);
    let applied = first_entry
        .proposal
        .legs
        .iter()
        .find(|leg| !leg.settles.is_empty())
        .unwrap();
    assert_eq!(applied.amount.mantissa, 33_333);
    assert_eq!(applied.base_amount.unwrap().mantissa, 35_000);
    assert_eq!(
        applied.settles[0].target.vid,
        VId(u128::from_str_radix(&invoice, 16).unwrap())
    );
    let before_retry = head(&f.book);
    let retried = ok(&f.book, &commit);
    assert_eq!(text(data(&retried), "vid"), first_vid);
    assert_eq!(head(&f.book), before_retry);

    let last = receipt_args("final", "666.67 EUR", "733.34 USD");
    let final_post = ok(
        &f.book,
        &last.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    let final_entry = f.entry(text(data(&final_post), "vid"));
    let final_relief = final_entry
        .proposal
        .legs
        .iter()
        .find(|leg| !leg.settles.is_empty())
        .unwrap();
    assert_eq!(final_relief.base_amount.unwrap().mantissa, 70_000);
    let activity = f.activity();
    let net = |code: &str| {
        text(
            rows(data(&activity), "rows")
                .iter()
                .find(|row| text(row, "account") == code)
                .unwrap(),
            "net",
        )
    };
    assert_eq!(net("1200"), "0.00 USD");
    assert_eq!(net("3900"), "0.00 USD");
    assert_eq!(net("1100"), "1100.00 USD");
    assert_eq!(net("4900"), "-50.00 USD");

    ok(
        &f.book,
        &[
            "reverse",
            first_vid,
            "--reason",
            "WrongAmount",
            "--evidence",
            &f.evidence,
        ],
    );
    let replacement = receipt_args("reapplied", "333.33 EUR", "366.66 USD");
    let reapplied = ok(
        &f.book,
        &replacement.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    let restored = f.entry(text(data(&reapplied), "vid"));
    let relief = restored
        .proposal
        .legs
        .iter()
        .find(|leg| !leg.settles.is_empty())
        .unwrap();
    assert_eq!(relief.base_amount.unwrap().mantissa, 35_000);
    ok(&f.book, &["verify", "open-items"]);
    ok(&f.book, &["verify", "fx-conversion"]);
}

#[test]
fn foreign_receipt_refuses_unexplained_cash_and_incomplete_route_without_posting() {
    let (f, invoice, rate) = settlement_fixture();
    let before = head(&f.book);
    let (status, refusal) = run(
        &f.book,
        &[
            "receipt",
            "--party",
            "CUST",
            "--number",
            "wrong-cash",
            "--date",
            "2026-03-06",
            "--cash",
            "1100",
            "--receivable",
            "1200",
            "--amount",
            "1099.00 USD",
            "--applies",
            &format!("{invoice}:0=1000.00 EUR"),
            "--fx-rate",
            &rate,
            "--conversion",
            "3900",
            "--realized-fx",
            "4900",
            "--evidence",
            &f.evidence,
        ],
        None,
    );
    assert_ne!(status, 0, "{}", refusal.render());
    assert_eq!(head(&f.book), before);
    let (status, refusal) = run(
        &f.book,
        &[
            "receipt",
            "--party",
            "CUST",
            "--number",
            "missing-route",
            "--date",
            "2026-03-06",
            "--cash",
            "1100",
            "--receivable",
            "1200",
            "--amount",
            "1100.00 USD",
            "--applies",
            &format!("{invoice}:0=1000.00 EUR"),
            "--fx-rate",
            &rate,
            "--evidence",
            &f.evidence,
        ],
        None,
    );
    assert_eq!(status, 2, "{}", refusal.render());
    assert_eq!(head(&f.book), before);
}

#[test]
fn exact_fx_dry_run_commits_its_saved_plan_and_retries_without_new_publication() {
    let f = Fixture::new();
    let rate = f.rate(
        "planned",
        "spot_close",
        "2026-03-05",
        "11",
        "10",
        "HalfEven",
    );
    let path = f.intent("planned-sale", text(data(&rate), "oid"), "SpotClose");
    let plan_file = f.dir.join("sale.plan").display().to_string();
    let before = head(&f.book);
    let plan = ok(
        &f.book,
        &[
            "post",
            "--intent",
            &path,
            "--evidence",
            &f.evidence,
            "--dry-run",
            "--plan-out",
            &plan_file,
        ],
    );
    assert_eq!(head(&f.book), before);
    assert!(
        plan.get("next_actions")
            .unwrap()
            .render()
            .contains("--grant 'read'")
    );
    let committed = ok(
        &f.book,
        &["commit", "--plan", &plan_file, "--grant", "read"],
    );
    assert_eq!(
        f.entry(text(data(&committed), "vid"))
            .proposal
            .base_totals
            .unwrap()
            .debits,
        11_000
    );
    let after = head(&f.book);
    let retry = ok(
        &f.book,
        &["commit", "--plan", &plan_file, "--grant", "read"],
    );
    assert_eq!(
        data(&retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(head(&f.book), after);
}

#[test]
fn wrong_date_purpose_missing_or_untyped_rate_and_caller_base_values_never_post() {
    let f = Fixture::new();
    let good = f.rate("good", "spot_close", "2026-03-05", "11", "10", "HalfEven");
    let wrong_date = f.rate("old", "spot_close", "2026-03-04", "11", "10", "HalfEven");
    let average = f.rate(
        "average",
        "period_average",
        "2026-03-31",
        "11",
        "10",
        "HalfEven",
    );
    let wrong_rounding = f.rate("half-up", "spot_close", "2026-03-05", "11", "10", "HalfUp");
    let absent = "00".repeat(32);
    for (key, oid) in [
        ("wrong-date", text(data(&wrong_date), "oid")),
        ("wrong-purpose", text(data(&average), "oid")),
        ("wrong-rounding", text(data(&wrong_rounding), "oid")),
        ("missing-rate", absent.as_str()),
        ("wrong-kind", f.evidence.as_str()),
    ] {
        let path = f.intent(key, oid, "SpotClose");
        let before = head(&f.book);
        let (status, refused) = run(
            &f.book,
            &["post", "--intent", &path, "--evidence", &f.evidence],
            None,
        );
        assert_ne!(status, 0, "{}", refused.render());
        assert_eq!(head(&f.book), before, "{key} published an entry");
    }
    let oid = text(data(&good), "oid");
    let valid = std::fs::read_to_string(f.intent("tampered", oid, "SpotClose")).unwrap();
    for (name, source) in [
        (
            "base-total",
            valid.replacen("\"legs\":", "\"base_totals\":{},\"legs\":", 1),
        ),
        (
            "base-leg",
            valid.replacen(
                "\"side\":\"debit\"",
                "\"side\":\"debit\",\"base_amount\":\"999.00 USD\"",
                1,
            ),
        ),
        (
            "inline-rate",
            valid.replacen(
                "\"law\":\"SpotClose\"",
                "\"law\":\"SpotClose\",\"rate_num\":\"999\"",
                1,
            ),
        ),
        (
            "duplicate-law",
            valid.replacen(
                "\"law\":\"SpotClose\"",
                "\"law\":\"SpotClose\",\"law\":\"PeriodAverage\"",
                1,
            ),
        ),
    ] {
        let path = f.file(&format!("{name}.json"), &source);
        let before = head(&f.book);
        let (status, refused) = run(
            &f.book,
            &["post", "--intent", &path, "--evidence", &f.evidence],
            None,
        );
        assert_eq!(status, 2, "{name}: {}", refused.render());
        assert_eq!(head(&f.book), before);
    }
    // The same retained average rate succeeds only under its own law.
    f.post(&f.intent("average-sale", text(data(&average), "oid"), "PeriodAverage"));
    assert_eq!(
        text(data(&f.activity()).get("totals").unwrap(), "debits"),
        "110.00 USD"
    );
}

#[test]
fn conversion_residual_stays_in_the_converted_leg_and_reversal_preserves_it() {
    let f = Fixture::new();
    let rate = f.rate("round", "spot_close", "2026-03-05", "1", "2", "HalfEven");
    let oid = text(data(&rate), "oid");
    let path = f.file("split-cent.json", &format!(r#"{{"effective_date":"2026-03-05","idempotency_key":"split-cent","legs":[{{"side":"debit","account":"1000","amount":"0.03 EUR"}},{{"side":"debit","account":"1200","amount":"0.03 EUR"}},{{"side":"credit","account":"4000","amount":"0.06 EUR"}}],"fx":{{"law":"SpotClose","rates":["{oid}"]}}}}"#));
    let posted = f.post(&path);
    let vid = text(data(&posted), "vid");
    let original = f.entry(vid);
    let native = &original.proposal;
    assert_eq!(native.legs.len(), 3, "no native rounding plug");
    assert_eq!(
        (native.unit_totals[0].debits, native.unit_totals[0].credits),
        (6, 6)
    );
    let base = native.base_totals.as_ref().unwrap();
    assert_eq!((base.debits, base.credits), (4, 4));
    assert_eq!(base.residual.unwrap().leg_ordinal, 2);
    assert_eq!(base.residual.unwrap().amount.mantissa, 1);
    assert_eq!(native.legs[2].base_amount.unwrap().mantissa, 4);
    let original_prefix = integer(data(&posted), "recorded_at").to_string();
    let reversed = ok(&f.book, &["reverse", vid, "--reason", "WrongAccount"]);
    let reversal = f.entry(text(data(&reversed), "vid"));
    assert_eq!(reversal.proposal.base_totals.as_ref(), Some(base));
    assert!(
        reversal
            .proposal
            .evidence
            .iter()
            .any(|evidence| evidence.role == 3 && evidence.document_oid == base.rate_doc_oids[0])
    );
    for (old, undo) in native.legs.iter().zip(&reversal.proposal.legs) {
        assert_eq!(old.amount, undo.amount);
        assert_eq!(old.base_amount, undo.base_amount);
        assert_ne!(old.side, undo.side);
    }
    let activity = f.activity();
    assert!(
        rows(data(&activity), "rows")
            .iter()
            .all(|row| text(row, "net") == "0.00 USD")
    );
    let historical = ok(
        &f.book,
        &[
            "tb",
            "--functional",
            "--activity",
            "--period",
            "FY2026-P03",
            "--as-known-at",
            &original_prefix,
        ],
    );
    assert_eq!(
        text(data(&historical).get("totals").unwrap(), "debits"),
        "0.04 USD"
    );

    let rewrite = f.file("rewrite-reversal.json", &format!(r#"{{"class":"Reversal","effective_date":"2026-03-05","idempotency_key":"rewrite-fx","reverses":"{vid}","reason":"WrongAccount","fx":{{"law":"SpotClose","rates":["{oid}"]}}}}"#));
    let before = head(&f.book);
    assert_eq!(run(&f.book, &["post", "--intent", &rewrite], None).0, 2);
    assert_eq!(head(&f.book), before);
}

fn assert_inherited_reversal(target: &Entry, reversal: &Entry) {
    assert_eq!(reversal.proposal.class, fa_model::EntryClass::REVERSAL);
    assert_eq!(reversal.proposal.legs.len(), target.proposal.legs.len());
    assert_eq!(reversal.proposal.base_totals, target.proposal.base_totals);
    assert_eq!(reversal.proposal.supersession.len(), 1);
    assert_eq!(
        reversal.proposal.supersession[0].target.entry_digest,
        target.entry_digest
    );
    assert_eq!(
        reversal.proposal.supersession[0].kind,
        fa_model::SupersessionKind::Reverses
    );
    let rate_evidence = |entry: &Entry| {
        entry
            .proposal
            .evidence
            .iter()
            .filter(|evidence| evidence.role == fa_journal::fx::RATE_EVIDENCE_ROLE)
            .copied()
            .collect::<Vec<_>>()
    };
    assert_eq!(rate_evidence(target).len(), 1);
    assert_eq!(rate_evidence(reversal), rate_evidence(target));
    for (original, reversed) in target.proposal.legs.iter().zip(&reversal.proposal.legs) {
        let mut expected = original.clone();
        expected.side = match original.side {
            fa_money::Side::Debit => fa_money::Side::Credit,
            fa_money::Side::Credit => fa_money::Side::Debit,
        };
        assert_eq!(
            reversed, &expected,
            "only the side changes, including the residual leg's valuation"
        );
    }
}

fn functional_nets(report: &Json) -> BTreeMap<&str, &str> {
    rows(data(report), "rows")
        .iter()
        .map(|row| (text(row, "account"), text(row, "net")))
        .collect()
}

#[test]
fn later_date_and_period_reversals_preserve_original_fx_basis_and_residual_through_the_cli() {
    for (law, purpose, rate_date) in [
        ("SpotClose", "spot_close", "2026-03-05"),
        ("PeriodAverage", "period_average", "2026-03-31"),
    ] {
        for (reverse_date, reverse_period) in
            [("2026-03-06", "FY2026-P03"), ("2026-04-06", "FY2026-P04")]
        {
            let f = Fixture::new();
            ok(&f.book, &["period", "open", "FY2026-P04"]);
            let rate = f.rate("recognition-rate", purpose, rate_date, "1", "2", "HalfEven");
            let oid = text(data(&rate), "oid");
            let source = f.file("valued-source.json", &format!(r#"{{"effective_date":"2026-03-05","idempotency_key":"valued-source","legs":[{{"side":"debit","account":"1000","amount":"0.03 EUR"}},{{"side":"debit","account":"1200","amount":"0.03 EUR"}},{{"side":"credit","account":"4000","amount":"0.06 EUR"}}],"fx":{{"law":"{law}","rates":["D:{oid}"]}}}}"#));
            let posted = f.post(&source);
            let vid = text(data(&posted), "vid");
            let original = f.entry(vid);
            let base = original.proposal.base_totals.as_ref().unwrap();
            assert_eq!((base.debits, base.credits), (4, 4));
            assert_eq!(base.residual.unwrap().leg_ordinal, 2);
            assert_eq!(base.residual.unwrap().amount.mantissa, 1);
            assert_eq!(
                original
                    .proposal
                    .legs
                    .iter()
                    .map(|leg| leg.base_amount.unwrap().mantissa)
                    .collect::<Vec<_>>(),
                vec![2, 2, 4]
            );
            let source_prefix = integer(data(&posted), "recorded_at").to_string();
            // A different later quote cannot change the cost being reversed.
            f.rate(
                "later-market",
                "spot_close",
                reverse_date,
                "9",
                "1",
                "HalfEven",
            );
            let reverse_args = [
                "reverse",
                vid,
                "--reason",
                "WrongAccount",
                "--effective",
                reverse_date,
            ];
            let reversed = ok(&f.book, &reverse_args);
            assert_eq!(text(&reversed, "event"), "reversed");
            assert_eq!(text(data(&reversed), "period"), reverse_period);
            let reverse_vid = text(data(&reversed), "vid");
            let reversal = f.entry(reverse_vid);
            assert_eq!(reversal.proposal.effective_date.render(), reverse_date);
            assert_inherited_reversal(&original, &reversal);

            let zero = ok(&f.book, &["tb", "--functional", "--as-of", reverse_date]);
            assert_eq!(integer(data(&zero), "entries"), 2);
            assert_eq!(
                functional_nets(&zero),
                BTreeMap::from([
                    ("1000", "0.00 USD"),
                    ("1200", "0.00 USD"),
                    ("4000", "0.00 USD")
                ]),
                "{law}, reversal {reverse_date}"
            );
            for side in ["debits", "credits"] {
                assert_eq!(text(data(&zero).get("totals").unwrap(), side), "0.08 USD");
            }
            let historical = ok(
                &f.book,
                &[
                    "tb",
                    "--functional",
                    "--as-of",
                    reverse_date,
                    "--as-known-at",
                    &source_prefix,
                ],
            );
            assert_eq!(integer(data(&historical), "entries"), 1);
            assert_eq!(
                functional_nets(&historical),
                BTreeMap::from([
                    ("1000", "0.02 USD"),
                    ("1200", "0.02 USD"),
                    ("4000", "-0.04 USD")
                ]),
            );
            if reverse_period == "FY2026-P04" {
                // Period activity keeps the correction in April while stock
                // nets it against the March source across the period boundary.
                let march = f.activity();
                assert_eq!(functional_nets(&march), functional_nets(&historical));
                let april = ok(
                    &f.book,
                    &["tb", "--functional", "--activity", "--period", "FY2026-P04"],
                );
                assert_eq!(
                    functional_nets(&april),
                    BTreeMap::from([
                        ("1000", "-0.02 USD"),
                        ("1200", "-0.02 USD"),
                        ("4000", "0.04 USD")
                    ]),
                );
            }

            // A reversal of the reversal inherits the original March basis,
            // even though its immediate target has a later effective date.
            let restored = ok(
                &f.book,
                &[
                    "reverse",
                    reverse_vid,
                    "--reason",
                    "WrongAccount",
                    "--effective",
                    "2026-04-08",
                ],
            );
            let reinstated = f.entry(text(data(&restored), "vid"));
            assert_inherited_reversal(&reversal, &reinstated);
            assert_eq!(reinstated.proposal.legs, original.proposal.legs);
            assert_eq!(
                reinstated.proposal.base_totals,
                original.proposal.base_totals
            );
            let stock = ok(&f.book, &["tb", "--functional", "--as-of", "2026-04-08"]);
            assert_eq!(integer(data(&stock), "entries"), 3);
            assert_eq!(functional_nets(&stock), functional_nets(&historical));
            for side in ["debits", "credits"] {
                assert_eq!(text(data(&stock).get("totals").unwrap(), side), "0.12 USD");
            }
            let before_retry = head(&f.book);
            let retry = ok(&f.book, &reverse_args);
            assert_eq!(text(&retry, "event"), "recorded");
            assert_eq!(text(data(&retry), "vid"), reverse_vid);
            assert_eq!(
                integer(data(&retry), "recorded_at"),
                integer(data(&reversed), "recorded_at")
            );
            assert_eq!(head(&f.book), before_retry);
            assert_eq!(f.entry(vid), original);
            assert_eq!(f.entry(reverse_vid), reversal);
        }
    }
}

#[test]
fn functional_activity_requires_its_explicit_scope_and_refuses_unvalued_foreign_entries() {
    let f = Fixture::new();
    let before = head(&f.book);
    let stock = ok(&f.book, &["tb", "--functional", "--period", "FY2026-P03"]);
    assert_eq!(text(&stock, "event"), "functional_stock_balance");
    assert_eq!(text(data(&stock), "scope"), "stock");
    assert_eq!(text(data(&stock), "effective_through"), "2026-03-31");
    assert_eq!(head(&f.book), before);
    for selection in [
        vec!["--functional"],
        vec![
            "--functional",
            "--activity",
            "--period",
            "FY2026-P03",
            "--period",
            "FY2026-P04",
        ],
        vec![
            "--functional",
            "--activity",
            "--period",
            "FY2026-P03",
            "--summary",
        ],
        vec![
            "--functional",
            "--activity",
            "--period",
            "FY2026-P03",
            "--certify",
        ],
        vec![
            "--functional",
            "--activity",
            "--period",
            "FY2026-P03",
            "--as-of",
            "2026-03-05",
        ],
        vec!["--functional", "--activity", "--fiscal-year", "2026"],
    ] {
        let mut args = vec!["tb"];
        args.extend(selection);
        let (status, output) = run(&f.book, &args, None);
        assert_eq!(status, 2, "{}", output.render());
        assert_eq!(head(&f.book), before);
    }
    let unvalued = f.file("unvalued.json", r#"{"effective_date":"2026-03-05","idempotency_key":"unvalued","legs":[{"side":"debit","account":"1000","amount":"100.00 EUR"},{"side":"credit","account":"4000","amount":"100.00 EUR"}]}"#);
    f.post(&unvalued);
    let after = head(&f.book);
    let (status, refused) = run(
        &f.book,
        &["tb", "--functional", "--activity", "--period", "FY2026-P03"],
        None,
    );
    assert_ne!(status, 0, "{}", refused.render());
    assert!(refused.render().contains("base_amount") || refused.render().contains("valuation"));
    assert_eq!(head(&f.book), after);
    let historical = ok(
        &f.book,
        &[
            "tb",
            "--functional",
            "--activity",
            "--period",
            "FY2026-P03",
            "--as-known-at",
            &before.to_string(),
        ],
    );
    assert_eq!(
        text(data(&historical).get("totals").unwrap(), "debits"),
        "0.00 USD"
    );
}

#[test]
fn functional_activity_values_base_currency_at_par_and_excludes_opening_periods() {
    let f = Fixture::new();
    let path = f.file("dollars.json", r#"{"effective_date":"2026-03-05","idempotency_key":"dollars","legs":[{"side":"debit","account":"1100","amount":"25.00 USD"},{"side":"credit","account":"4100","amount":"25.00 USD"}]}"#);
    f.post(&path);
    assert_eq!(
        text(data(&f.activity()).get("totals").unwrap(), "debits"),
        "25.00 USD"
    );
    ok(&f.book, &["period", "open", "FY2026-P04"]);
    let april = ok(
        &f.book,
        &["tb", "--functional", "--activity", "--period", "FY2026-P04"],
    );
    assert_eq!(
        text(data(&april).get("totals").unwrap(), "debits"),
        "0.00 USD"
    );
    assert_eq!(integer(data(&april), "entries"), 0);
    let stock = ok(&f.book, &["tb", "--period", "FY2026-P04"]);
    let dollar = rows(data(&stock), "unit_totals")
        .iter()
        .find(|row| text(row, "unit") == "USD")
        .unwrap();
    assert_eq!(text(dollar, "debits"), "25.00 USD");
}

#[test]
fn a_known_at_bounded_token_reads_its_functional_prefix_but_never_head() {
    let f = Fixture::new();
    let rate = f.rate("pinned", "spot_close", "2026-03-05", "11", "10", "HalfEven");
    let posted = f.post(&f.intent("pinned-sale", text(data(&rate), "oid"), "SpotClose"));
    let pin = integer(data(&posted), "recorded_at").to_string();
    let token = f.dir.join("pinned.token").display().to_string();
    ok(
        &f.book,
        &[
            "capability",
            "issue",
            "--holder",
            "fx-pinned-reader",
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
    let before = head(&f.book);
    let historical = ok(
        &f.book,
        &[
            "--token",
            &token,
            "tb",
            "--functional",
            "--activity",
            "--period",
            "FY2026-P03",
            "--as-known-at",
            &pin,
        ],
    );
    assert_eq!(integer(data(&historical), "known_at").to_string(), pin);
    assert_eq!(
        text(data(&historical).get("totals").unwrap(), "debits"),
        "110.00 USD"
    );
    let (status, denied) = run(
        &f.book,
        &[
            "--token",
            &token,
            "tb",
            "--functional",
            "--activity",
            "--period",
            "FY2026-P03",
        ],
        None,
    );
    assert_eq!(status, 7, "{}", denied.render());
    assert!(text(data(&denied), "message").contains("known_at"));
    assert_eq!(
        head(&f.book),
        before + access_events_since(&f.book, before),
        "only the token session's AccessEvents were written"
    );
}

fn bound(authority: &LaunchAuthority, args: &[&str], input: Option<&str>) -> (u8, Json) {
    let mut argv: Vec<_> = args.iter().map(|arg| (*arg).to_string()).collect();
    argv.push("--json".into());
    let (status, captured) = fa_with_authority(
        &argv,
        Files {
            cwd: None,
            stdin: input.map_or(Stdin::Missing, |value| {
                Stdin::Forwarded(value.as_bytes().to_vec())
            }),
        },
        authority,
        true,
    );
    let lines: Vec<_> = captured.stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{captured:?}");
    fa_cli::verbs::registry()
        .unwrap()
        .check_line(lines[0])
        .unwrap();
    (status, json::parse(lines[0]).unwrap())
}

#[test]
fn authenticated_upload_grade_and_file_confinement_survive_fx_intake() {
    let f = Fixture::new();
    let source = f.rate_source("agent", "spot_close", "2026-03-05", "11", "10", "HalfEven");
    let agent = LaunchAuthority::new(
        f.book.clone(),
        None,
        "fx-agent",
        LaunchProfile::Agent,
        &["read", "post"],
    )
    .unwrap();
    let (status, added) = bound(
        &agent,
        &["fx", "rate", "add", "--from-json", "-"],
        Some(&source),
    );
    assert_eq!(status, 0, "{}", added.render());
    assert_eq!(text(data(&added), "grade"), "AgentUpload");
    let before = head(&f.book);
    let (status, repeated) = run(
        &f.book,
        &["fx", "rate", "add", "--from-json", "-"],
        Some(&source),
    );
    assert_eq!(status, 0, "{}", repeated.render());
    assert_eq!(text(data(&repeated), "grade"), "AgentUpload");
    assert_eq!(head(&f.book), before);
    let reader = LaunchAuthority::new(
        f.book.clone(),
        None,
        "fx-reader",
        LaunchProfile::Preparer,
        &["read"],
    )
    .unwrap();
    let (status, denied) = bound(
        &reader,
        &["fx", "rate", "add", "--from-json", "/absent/rate.json"],
        None,
    );
    assert_eq!(status, 7, "{}", denied.render());
    assert!(!denied.render().contains("No such file"));
    let path = f.file("host-rate.json", &source);
    let (status, refused) = bound(&agent, &["fx", "rate", "add", "--from-json", &path], None);
    assert_eq!(status, 2, "{}", refused.render());
    assert!(refused.render().contains("host filesystem path"));
    assert_eq!(head(&f.book), before);

    let forged = source.replacen("\"source\":", "\"grade\":\"HumanUpload\",\"source\":", 1);
    let (status, refused) = bound(
        &agent,
        &["fx", "rate", "add", "--from-json", "-"],
        Some(&forged),
    );
    assert_eq!(status, 2, "{}", refused.render());
    assert_eq!(head(&f.book), before);

    // An authenticated preparer with Post but without Read cannot use FX
    // intake references to observe even the book's current coordinate.
    let poster = LaunchAuthority::new(
        f.book.clone(),
        None,
        "fx-post-only",
        LaunchProfile::Preparer,
        &["post"],
    )
    .unwrap();
    let intent =
        std::fs::read_to_string(f.intent("not-readable", text(data(&added), "oid"), "SpotClose"))
            .unwrap();
    let (status, denied) = bound(&poster, &["post", "--intent", "-"], Some(&intent));
    assert_eq!(status, 7, "{}", denied.render());
    assert_eq!(denied.get("book"), Some(&Json::Null));
    assert_eq!(denied.get("coordinate"), Some(&Json::Null));
    assert_eq!(head(&f.book), before);
}

/// Rewrite the committed entry `target`'s payload through the substrate,
/// sealing `edit`'s proposal so its digests match (a planted defect only
/// recomputation can find), in a book created with development keys `seed`.
fn rewrite_entry(
    book: &Path,
    seed: u8,
    target: VId,
    edit: impl FnOnce(&mut fa_model::EntryPayload),
) {
    use fa_model::symbols::{property, relation};
    use fgdb_types::CanonicalScalar;
    let runtime = asupersync::runtime::RuntimeBuilder::new()
        .build()
        .expect("runtime");
    let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let ctx = fgdb_types::context::PurposeContexts::narrow_runtime_root(&root);
    let keys = fgdb::DatabaseKeys::new(
        [seed; 32],
        fgdb_types::ids::DatabaseSecurityNamespaceId([seed.wrapping_add(1); 32]),
        [seed.wrapping_add(2); 32],
    );
    let mut db = runtime
        .block_on(async { fgdb::Database::open(&ctx.commit(), &book.join("store"), keys).await })
        .expect("reopen the store through the substrate");
    let row = db.vertex(target).expect("read").expect("the entry");
    let raw = match row
        .props
        .iter()
        .find(|(k, _)| *k == property::FA_PAYLOAD)
        .map(|(_, v)| v)
    {
        Some(CanonicalScalar::Bytes(b)) => b.as_slice().to_vec(),
        other => panic!("unexpected payload property: {other:?}"),
    };
    let entry = Entry::decode(&raw).expect("decode entry");
    let mut proposal = entry.proposal;
    edit(&mut proposal);
    let forged = proposal
        .seal(entry.approvals, entry.plan_certificate)
        .expect("seal the rewritten entry");
    let mut batch = fgdb::WriteBatch::new(relation::DERIVED_FROM);
    for (property, bytes) in [
        (property::FA_PAYLOAD, forged.encode().expect("encode entry")),
        (property::FA_DIGEST, forged.entry_digest.to_vec()),
        (property::PROPOSAL_DIGEST, forged.proposal_digest.to_vec()),
    ] {
        batch.set_vertex_property(
            target,
            property,
            Some(CanonicalScalar::bytes(bytes).expect("scalar")),
        );
    }
    runtime
        .block_on(async { db.write(&ctx.commit(), batch).await })
        .expect("commit the planted rewrite");
}

/// fa-3ock (plan §6.4, §15.3; FA-INV-01 `base`): `fa verify fx-conversion`
/// recomputes every FX-valued entry from the Rate documents it cites under
/// the law it names, at the head or at an earlier prefix, and a valued
/// Reversal as the exact side-swap of its target. A valuation rewritten
/// in place, still balanced and with matching digests, is caught (exit 8)
/// naming the entry.
#[test]
fn fx_conversion_verification_recomputes_valued_entries_and_catches_a_rewritten_valuation() {
    const SEED: u8 = 0x5f;
    let f = Fixture::build(Some(SEED));
    let none = ok(&f.book, &["verify", "fx-conversion"]);
    assert_eq!(integer(data(&none), "valued_entries"), 0);

    let rate = f.rate("spot", "spot_close", "2026-03-05", "1", "2", "HalfEven");
    let oid = text(data(&rate), "oid").to_string();
    let first = f.post(&f.intent("valued-1", &oid, "SpotClose"));
    let first_vid = text(data(&first), "vid").to_string();
    let prefix = integer(data(&first), "recorded_at").to_string();
    let split = f.file("verify-split.json", &format!(r#"{{"effective_date":"2026-03-05","idempotency_key":"verify-split","legs":[{{"side":"debit","account":"1000","amount":"0.03 EUR"}},{{"side":"debit","account":"1200","amount":"0.03 EUR"}},{{"side":"credit","account":"4000","amount":"0.06 EUR"}}],"fx":{{"law":"SpotClose","rates":["{oid}"]}}}}"#));
    let second = f.post(&split);
    ok(
        &f.book,
        &[
            "reverse",
            text(data(&second), "vid"),
            "--reason",
            "WrongAccount",
        ],
    );

    let verified = ok(&f.book, &["verify", "fx-conversion"]);
    let v = data(&verified);
    assert_eq!(integer(v, "valued_entries"), 3, "{}", verified.render());
    assert_eq!(integer(v.get("by_law").unwrap(), "SpotClose"), 3);
    assert!(rows(v, "drift").is_empty());
    let historical = ok(
        &f.book,
        &["verify", "fx-conversion", "--as-known-at", &prefix],
    );
    assert_eq!(integer(data(&historical), "valued_entries"), 1);
    let (status, refused) = run(
        &f.book,
        &["verify", "fx-conversion", "--period", "FY2026-P03"],
        None,
    );
    assert_eq!(status, 2, "{}", refused.render());

    // Planted: one base cent moved onto both sides of the first entry (it
    // still balances, its digests are recomputed), so only recomputation
    // from the Rate document can see it.
    let target = VId(u128::from_str_radix(&first_vid, 16).unwrap());
    rewrite_entry(&f.book, SEED, target, |proposal| {
        for leg in &mut proposal.legs {
            let base = leg.base_amount.as_mut().expect("a valued leg");
            base.mantissa += 1;
        }
        let totals = proposal.base_totals.as_mut().expect("valued totals");
        totals.debits += 1;
        totals.credits += 1;
    });
    let (status, drift) = run(&f.book, &["verify", "fx-conversion"], None);
    assert_eq!(status, 8, "{}", drift.render());
    let rendered = drift.render();
    assert!(rendered.contains(&first_vid), "{rendered}");
    assert!(rendered.contains("SpotClose"), "{rendered}");
}
