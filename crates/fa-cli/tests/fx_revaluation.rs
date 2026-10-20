//! Real CLI revaluation retains its closing evidence and portable proposal,
//! posts only cumulative functional deltas, and rejects stale or unauthorized
//! source reads before publishing an adjustment.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use fa::{Book, BookKeys, Entropy, PostIntent, PostPlan};
use fa_cli::json::{self, Json};
use fa_journal::refusal::code;
use fa_model::entry::FX_REVALUATION_EXTENSION;
use fa_model::{Entry, EntryClass, FxRevaluationBasis};
use fa_money::{Amount, Side, UnitRegistry};
use fgdb_types::VId;

const PERIOD: &str = "FY2026-P01";

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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn run(book: &Path, args: &[&str], stdin: Option<&[u8]>) -> (i32, Json) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(["--via", "direct"])
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .env_remove("FA_KEYS")
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
        child.stdin.take().unwrap().write_all(input).unwrap();
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
    let info = ok(book, &["book", "info"]);
    integer(info.get("coordinate").unwrap(), "known_at")
}

fn leg_nets(review: &Json) -> BTreeMap<String, i128> {
    let units = UnitRegistry::embedded().unwrap();
    let mut nets = BTreeMap::<String, i128>::new();
    for leg in rows(data(review), "legs") {
        let amount = Amount::parse(text(leg, "amount"), &units).unwrap();
        assert_eq!(amount.unit, units.lookup("USD").unwrap());
        let signed = match text(leg, "side") {
            "debit" => amount.mantissa,
            "credit" => -amount.mantissa,
            side => panic!("unexpected side {side}"),
        };
        let net = nets.entry(text(leg, "account").into()).or_default();
        *net = net.checked_add(signed).unwrap();
    }
    nets
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    evidence: String,
    routes: Json,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let dir = std::env::temp_dir().join(format!(
                "fa-fx-revaluation-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => break dir,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create retained fixture {}: {error}", dir.display()),
            }
        };
        let book = dir.join("book");
        ok(&book, &["book", "create", "--name", "Retained FX closing"]);
        let chart = dir.join("chart.json");
        std::fs::write(&chart, r#"{"accounts":[{"code":"1200","name":"EUR Receivable","type":"Asset","unit":"EUR"},{"code":"1290","name":"Receivable Valuation","type":"Asset","unit":"USD"},{"code":"2200","name":"EUR Payable","type":"Liability","unit":"EUR"},{"code":"2290","name":"Payable Valuation","type":"Liability","unit":"USD"},{"code":"4000","name":"EUR Revenue","type":"Revenue","unit":"EUR"},{"code":"4700","name":"Unrealized Gain","type":"Revenue","unit":"USD"},{"code":"6000","name":"EUR Expense","type":"Expense","unit":"EUR"},{"code":"6700","name":"Unrealized Loss","type":"Expense","unit":"USD"}]}"#).unwrap();
        ok(&book, &["chart", "import", chart.to_str().unwrap()]);
        ok(&book, &["period", "create", "--fiscal-year", "2026"]);
        ok(&book, &["period", "open", PERIOD]);
        let source = dir.join("invoices.txt");
        std::fs::write(&source, "Retained customer and supplier invoices.").unwrap();
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
        let routes = ok(
            &book,
            &[
                "fx",
                "routes",
                "set",
                "--route",
                "1200:1290:4700",
                "--route",
                "2200:2290:6700",
                "--effective-from",
                "2026-01-01",
                "--key",
                "monetary-exposure-routes",
                "--yes",
            ],
        );
        assert_eq!(text(&routes, "event"), "fx_routes_recorded");
        assert_eq!(integer(data(&routes), "routes"), 2);
        Self {
            dir,
            book,
            evidence: text(data(&evidence), "oid").into(),
            routes,
        }
    }

    fn path(&self, name: &str) -> String {
        self.dir.join(name).display().to_string()
    }

    fn file(&self, name: &str, content: &str) -> String {
        let path = self.path(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    fn rate(&self, name: &str, purpose: &str, date: &str, numerator: u32, rounding: &str) -> Json {
        let path = self.file(
            &format!("{name}-rate.json"),
            &format!(r#"{{"base_unit":"USD","quote_unit":"EUR","rate_num":"{numerator}","rate_den":"10","rounding":"{rounding}","as_of":"{date}","retrieved_at_ns":1767571200000000000,"purpose":"{purpose}","source":"retained {name}"}}"#),
        );
        let added = ok(&self.book, &["fx", "rate", "add", "--from-json", &path]);
        assert_eq!(text(&added, "event"), "fx_rate_added");
        assert_eq!(text(data(&added), "grade"), "HumanUpload");
        added
    }

    fn closing_rate(&self, numerator: u32) -> Json {
        self.rate(
            &format!("closing-{numerator}"),
            "period_close",
            "2026-01-31",
            numerator,
            "HalfEven",
        )
    }

    fn post_source(&self, key: &str, liability: bool, amount: &str) -> Json {
        let rate = self.rate(key, "spot_close", "2026-01-05", 11, "HalfEven");
        let oid = text(data(&rate), "oid");
        let (debit, credit) = if liability {
            ("6000", "2200")
        } else {
            ("1200", "4000")
        };
        let path = self.file(
            &format!("{key}.json"),
            &format!(r#"{{"effective_date":"2026-01-05","idempotency_key":"{key}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount} EUR"}},{{"side":"credit","account":"{credit}","amount":"{amount} EUR"}}],"fx":{{"law":"SpotClose","rates":["D:{oid}"]}}}}"#),
        );
        ok(
            &self.book,
            &[
                "post",
                "--intent",
                &path,
                "--evidence",
                &self.evidence,
                "--yes",
            ],
        )
    }

    fn review(&self, key: &str, account: &str, rate: &str) -> Json {
        ok(
            &self.book,
            &[
                "fx",
                "revalue",
                "--period",
                PERIOD,
                "--account",
                account,
                "--rate",
                rate,
                "--key",
                key,
                "--review-only",
            ],
        )
    }

    fn save_review(&self, key: &str, account: &str, rate: &str) -> (String, Json) {
        let path = self.path(&format!("{key}.review"));
        let reviewed = ok(
            &self.book,
            &[
                "fx",
                "revalue",
                "--period",
                PERIOD,
                "--account",
                account,
                "--rate",
                rate,
                "--key",
                key,
                "--review-out",
                &path,
            ],
        );
        (path, reviewed)
    }

    fn save_plan(&self, key: &str, review: &str, digest: &str) -> String {
        let path = self.path(&format!("{key}.plan"));
        let planned = ok(
            &self.book,
            &[
                "fx",
                "revalue",
                "--review",
                review,
                "--digest",
                digest,
                "--dry-run",
                "--plan-out",
                &path,
            ],
        );
        assert_eq!(text(&planned, "event"), "plan");
        path
    }

    fn commit(&self, plan: &str) -> Json {
        ok(
            &self.book,
            &["commit", "--plan", plan, "--grant", "read", "--yes"],
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
}

#[test]
fn retained_review_plan_and_cli_post_preserve_signed_cumulative_adjustments_and_exact_retries() {
    let f = Fixture::new();
    let asset = f.post_source("customer-invoice", false, "100.00");
    let liability = f.post_source("supplier-invoice", true, "100.00");
    let original_asset = f.entry(text(data(&asset), "vid"));
    let original_liability = f.entry(text(data(&liability), "vid"));
    let closing = f.closing_rate(12);
    let rate = format!("D:{}", text(data(&closing), "oid"));
    let before = head(&f.book);
    let (review_file, reviewed) = f.save_review("asset-120", "1200", &rate);
    assert_eq!(text(&reviewed, "event"), "fx_revaluation_reviewed");
    assert_eq!(
        head(&f.book),
        before,
        "review publishes no entry or metadata"
    );
    for (field, expected) in [
        ("period", PERIOD),
        ("closing_date", "2026-01-31"),
        ("source_native_net", "100.00 EUR"),
        ("source_base_net", "110.00 USD"),
        ("prior_adjustment_net", "0.00 USD"),
        ("current_carrying_net", "110.00 USD"),
        ("target_base_net", "120.00 USD"),
        ("delta", "10.00 USD"),
    ] {
        assert_eq!(text(data(&reviewed), field), expected, "{field}");
    }
    assert_eq!(integer(data(&reviewed), "known_at"), before);
    assert_eq!(
        leg_nets(&reviewed),
        BTreeMap::from([("1290".into(), 1_000), ("4700".into(), -1_000)]),
    );
    let saved = std::fs::read(&review_file).unwrap();
    assert_eq!(saved, decode_hex(text(data(&reviewed), "bytes")));
    let intent = PostIntent::decode(&saved).unwrap();
    assert_eq!(intent.canonical_bytes().unwrap(), saved);
    assert_eq!(intent.proposal().class, EntryClass::REVALUATION);
    assert_eq!(
        hex(&intent.digest().unwrap()),
        text(data(&reviewed), "review_digest")
    );
    let basis = FxRevaluationBasis::decode(
        &intent
            .proposal()
            .extensions
            .iter()
            .find(|(tag, _)| *tag == FX_REVALUATION_EXTENSION)
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(hex(&basis.rate_document.0), text(data(&closing), "oid"));
    assert_eq!(hex(&basis.rate_commit), text(data(&closing), "doc_commit"));
    assert_eq!(hex(&basis.routes_digest), text(data(&f.routes), "digest"));
    assert_eq!(
        hex(&basis.source_digest),
        text(data(&reviewed), "source_digest")
    );
    assert_eq!(i128::from(basis.observed_at.0), before);
    let plan_file = f.save_plan(
        "asset-120",
        &review_file,
        text(data(&reviewed), "review_digest"),
    );
    let plan = PostPlan::decode(&std::fs::read(&plan_file).unwrap()).unwrap();
    assert_eq!(
        plan.proposal(),
        intent.proposal(),
        "sealed reviewed proposal survives reopening"
    );
    assert_eq!(head(&f.book), before, "planning publishes nothing");
    let posted = f.commit(&plan_file);
    assert_eq!(text(data(&posted), "class"), "Revaluation");
    assert_eq!(
        f.entry(text(data(&posted), "vid")).proposal,
        *intent.proposal()
    );

    let liability_review = f.review("liability-120", "2200", &rate);
    for (field, expected) in [
        ("source_native_net", "-100.00 EUR"),
        ("source_base_net", "-110.00 USD"),
        ("current_carrying_net", "-110.00 USD"),
        ("target_base_net", "-120.00 USD"),
        ("delta", "-10.00 USD"),
    ] {
        assert_eq!(text(data(&liability_review), field), expected, "{field}");
    }
    assert_eq!(
        leg_nets(&liability_review),
        BTreeMap::from([("2290".into(), -1_000), ("6700".into(), 1_000)]),
    );
    let liability_post = ok(
        &f.book,
        &[
            "fx",
            "revalue",
            "--review",
            text(data(&liability_review), "bytes"),
            "--digest",
            text(data(&liability_review), "review_digest"),
            "--yes",
        ],
    );
    assert_eq!(text(&liability_post, "event"), "posted");
    let liability_intent =
        PostIntent::decode(&decode_hex(text(data(&liability_review), "bytes"))).unwrap();
    assert_eq!(
        f.entry(text(data(&liability_post), "vid")).proposal,
        *liability_intent.proposal()
    );

    let before_noop = head(&f.book);
    for (account, carrying) in [("1200", "120.00 USD"), ("2200", "-120.00 USD")] {
        let noop = ok(
            &f.book,
            &[
                "fx",
                "revalue",
                "--period",
                PERIOD,
                "--account",
                account,
                "--rate",
                &rate,
                "--key",
                "no-empty-adjustment",
                "--yes",
            ],
        );
        assert_eq!(text(&noop, "event"), "fx_revaluation_noop");
        assert_eq!(text(data(&noop), "current_carrying_net"), carrying);
        assert_eq!(text(data(&noop), "target_base_net"), carrying);
        assert_eq!(head(&f.book), before_noop);
    }

    let next_quote = f.closing_rate(13);
    let next_rate = format!("D:{}", text(data(&next_quote), "oid"));
    for (account, sign) in [("1200", 1), ("2200", -1)] {
        let key = format!("{account}-130");
        let next = f.review(&key, account, &next_rate);
        let units = UnitRegistry::embedded().unwrap();
        for (field, expected) in [
            ("source_base_net", sign * 11_000),
            ("prior_adjustment_net", sign * 1_000),
            ("current_carrying_net", sign * 12_000),
            ("target_base_net", sign * 13_000),
            ("delta", sign * 1_000),
        ] {
            assert_eq!(
                Amount::parse(text(data(&next), field), &units)
                    .unwrap()
                    .mantissa,
                expected
            );
        }
        let later = ok(
            &f.book,
            &[
                "fx",
                "revalue",
                "--period",
                PERIOD,
                "--account",
                account,
                "--rate",
                &next_rate,
                "--key",
                &key,
                "--yes",
            ],
        );
        assert_eq!(text(&later, "event"), "posted");
        let entry = f.entry(text(data(&later), "vid"));
        assert_eq!(entry.proposal.legs.len(), 2);
        assert!(
            entry
                .proposal
                .legs
                .iter()
                .all(|leg| leg.amount.mantissa == 1_000)
        );
        assert_eq!(
            entry.proposal.legs[0].side,
            if sign == 1 { Side::Debit } else { Side::Credit }
        );
    }
    let before_retry = head(&f.book);
    let retry = f.commit(&plan_file);
    assert_eq!(
        data(&retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(text(data(&retry), "vid"), text(data(&posted), "vid"));
    let (status, restored_retry) = run(
        &f.book,
        &[
            "fx",
            "revalue",
            "--review",
            "-",
            "--digest",
            text(data(&liability_review), "review_digest"),
            "--yes",
        ],
        Some(&liability_intent.canonical_bytes().unwrap()),
    );
    assert_eq!(status, 0, "{}", restored_retry.render());
    assert_eq!(
        data(&restored_retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        text(data(&restored_retry), "vid"),
        text(data(&liability_post), "vid")
    );
    assert_eq!(head(&f.book), before_retry);
    assert_eq!(f.entry(text(data(&asset), "vid")), original_asset);
    assert_eq!(f.entry(text(data(&liability), "vid")), original_liability);

    let functional = ok(&f.book, &["tb", "--functional", "--period", PERIOD]);
    for side in ["debits", "credits"] {
        assert_eq!(
            text(data(&functional).get("totals").unwrap(), side),
            "260.00 USD"
        );
    }
    let native = ok(&f.book, &["tb", "--period", PERIOD]);
    for (unit, expected) in [("EUR", "200.00 EUR"), ("USD", "40.00 USD")] {
        let total = rows(data(&native), "unit_totals")
            .iter()
            .find(|row| text(row, "unit") == unit)
            .unwrap();
        assert_eq!(text(total, "debits"), expected);
        assert_eq!(text(total, "credits"), expected);
    }
    assert_eq!(head(&f.book), before_retry);
}

#[test]
fn a_later_invoice_invalidates_saved_review_and_plan_without_publishing_stale_amounts() {
    let f = Fixture::new();
    f.post_source("reviewed-exposure", false, "100.00");
    let closing = f.closing_rate(12);
    let rate = format!("D:{}", text(data(&closing), "oid"));
    let (review_file, review) = f.save_review("stale-close", "1200", &rate);
    let digest = text(data(&review), "review_digest");
    let plan = f.save_plan("stale-close", &review_file, digest);
    f.post_source("later-exposure", false, "50.00");
    let before = head(&f.book);
    let attempts = [
        vec![
            "fx",
            "revalue",
            "--review",
            &review_file,
            "--digest",
            digest,
            "--yes",
        ],
        vec![
            "fx",
            "revalue",
            "--review",
            &review_file,
            "--digest",
            digest,
            "--dry-run",
        ],
        vec!["commit", "--plan", &plan, "--grant", "read", "--yes"],
    ];
    for args in attempts {
        let (status, refused) = run(&f.book, &args, None);
        assert_eq!(status, 6, "{args:?}: {}", refused.render());
        assert_eq!(text(data(&refused), "refusal_id"), code::PLAN_INVALIDATED);
        assert_eq!(head(&f.book), before);
    }
    let fresh = f.review("fresh-close", "1200", &rate);
    assert_ne!(
        text(data(&fresh), "source_digest"),
        text(data(&review), "source_digest")
    );
    for (field, expected) in [
        ("source_native_net", "150.00 EUR"),
        ("source_base_net", "165.00 USD"),
        ("current_carrying_net", "165.00 USD"),
        ("target_base_net", "180.00 USD"),
        ("delta", "15.00 USD"),
    ] {
        assert_eq!(text(data(&fresh), field), expected, "{field}");
    }
    let fresh_plan = f.save_plan(
        "fresh-close",
        text(data(&fresh), "bytes"),
        text(data(&fresh), "review_digest"),
    );
    let posted = f.commit(&fresh_plan);
    assert_eq!(text(data(&posted), "class"), "Revaluation");
    assert!(
        f.entry(text(data(&posted), "vid"))
            .proposal
            .legs
            .iter()
            .all(|leg| leg.amount.mantissa == 1_500)
    );
}

#[test]
fn current_read_authority_precedes_rate_and_review_file_access_even_for_historical_routes() {
    let f = Fixture::new();
    let route_pin = integer(data(&f.routes), "recorded_at").to_string();
    let post_only = f.path("post-only.token");
    ok(
        &f.book,
        &[
            "capability",
            "issue",
            "--holder",
            "fx-poster",
            "--profile",
            "human",
            "--op",
            "post",
            "--grant",
            "issue_capability",
            "--grant",
            "post",
            "--out",
            &post_only,
        ],
    );
    let reader = f.path("route-reader.token");
    ok(
        &f.book,
        &[
            "capability",
            "issue",
            "--holder",
            "fx-route-reader",
            "--profile",
            "human",
            "--op",
            "read",
            "--grant",
            "issue_capability",
            "--grant",
            "read",
            "--known-at-most",
            &route_pin,
            "--out",
            &reader,
        ],
    );
    f.post_source("later-invoice", false, "100.00");
    let before = head(&f.book);
    let absent = format!("D:{}", "ff".repeat(32));
    let missing_review = f.path("no-such-review");
    let digest = "00".repeat(32);
    for args in [
        vec![
            "--token",
            &post_only,
            "fx",
            "revalue",
            "--period",
            PERIOD,
            "--account",
            "1200",
            "--rate",
            &absent,
            "--key",
            "denied",
            "--review-only",
        ],
        vec![
            "--token",
            &post_only,
            "fx",
            "revalue",
            "--review",
            &missing_review,
            "--digest",
            &digest,
            "--dry-run",
        ],
    ] {
        let (status, denied) = run(&f.book, &args, None);
        assert_eq!(status, 7, "{}", denied.render());
        assert_eq!(text(data(&denied), "refusal_id"), code::CAPABILITY);
        assert!(text(data(&denied), "message").contains("read"));
        assert_eq!(head(&f.book), before);
    }
    let historical = ok(
        &f.book,
        &[
            "--token",
            &reader,
            "fx",
            "routes",
            "show",
            "--as-of",
            "2026-01-31",
            "--as-known-at",
            &route_pin,
        ],
    );
    assert_eq!(text(&historical, "event"), "fx_routes");
    assert_eq!(data(&historical).get("found"), Some(&Json::Bool(true)));
    assert_eq!(
        integer(data(&historical), "known_at").to_string(),
        route_pin
    );
    assert_eq!(
        text(data(&historical), "digest"),
        text(data(&f.routes), "digest")
    );
    let route_codes: BTreeMap<_, _> = rows(data(&historical), "routes")
        .iter()
        .map(|route| {
            (
                text(route, "account"),
                (
                    text(route, "valuation_account"),
                    text(route, "unrealized_account"),
                ),
            )
        })
        .collect();
    assert_eq!(
        route_codes,
        BTreeMap::from([("1200", ("1290", "4700")), ("2200", ("2290", "6700"))])
    );
    let (status, denied) = run(
        &f.book,
        &[
            "--token",
            &reader,
            "fx",
            "routes",
            "show",
            "--as-of",
            "2026-01-31",
        ],
        None,
    );
    assert_eq!(status, 7, "{}", denied.render());
    assert!(text(data(&denied), "message").contains("known_at"));
    assert_eq!(head(&f.book), before);
}

#[test]
fn closing_rate_law_and_unambiguous_review_selectors_are_required_before_publication() {
    let f = Fixture::new();
    f.post_source("exposure", false, "100.00");
    let valid = f.closing_rate(12);
    let wrong_date = f.rate("wrong-date", "period_close", "2026-01-30", 12, "HalfEven");
    let wrong_purpose = f.rate("wrong-purpose", "spot_close", "2026-01-31", 12, "HalfEven");
    let wrong_rounding = f.rate("wrong-rounding", "period_close", "2026-01-31", 12, "HalfUp");
    let before = head(&f.book);
    for (key, rate) in [
        ("wrong-date", wrong_date),
        ("wrong-purpose", wrong_purpose),
        ("wrong-rounding", wrong_rounding),
    ] {
        let selected = format!("D:{}", text(data(&rate), "oid"));
        let (status, refused) = run(
            &f.book,
            &[
                "fx",
                "revalue",
                "--period",
                PERIOD,
                "--account",
                "1200",
                "--rate",
                &selected,
                "--key",
                key,
                "--review-only",
            ],
            None,
        );
        assert_eq!(status, 2, "{key}: {}", refused.render());
        assert_eq!(text(data(&refused), "refusal_id"), code::STRUCTURE);
        assert_eq!(head(&f.book), before);
    }
    let selected = format!("D:{}", text(data(&valid), "oid"));
    let good = f.review("valid-close", "1200", &selected);
    assert_eq!(text(data(&good), "delta"), "10.00 USD");
    let missing_book = f.dir.join("no-such-book");
    let missing_review = f.path("no-such-review");
    let digest = "00".repeat(32);
    for args in [
        vec![
            "fx",
            "revalue",
            "--period",
            PERIOD,
            "--account",
            "1200",
            "--rate",
            &selected,
            "--review-only",
        ],
        vec!["fx", "revalue", "--review", &missing_review, "--dry-run"],
        vec![
            "fx",
            "revalue",
            "--review",
            &missing_review,
            "--digest",
            &digest,
            "--period",
            PERIOD,
            "--dry-run",
        ],
        vec![
            "fx",
            "revalue",
            "--period",
            PERIOD,
            "--account",
            "1200",
            "--rate",
            &selected,
            "--key",
            "ambiguous",
            "--review-only",
            "--dry-run",
        ],
    ] {
        let (status, refused) = run(&missing_book, &args, None);
        assert_eq!(status, 2, "{args:?}: {}", refused.render());
    }
    assert!(!missing_book.exists());
    assert_eq!(head(&f.book), before);
}
