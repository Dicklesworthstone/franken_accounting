//! First close, delta reclose and independent approvals across real processes.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

fn run(book: &Path, args: &[&str]) -> (i32, Json) {
    let result = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .stdin(Stdio::null())
        .output()
        .expect("run fa");
    let stdout = String::from_utf8(result.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8_lossy(&result.stderr);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "args={args:?}\n{stdout}\n{stderr}");
    fa_cli::verbs::registry()
        .expect("registry")
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("args={args:?}: {error}\n{stdout}\n{stderr}"));
    (
        result.status.code().unwrap_or(-1),
        json::parse(lines[0]).expect("robot line"),
    )
}

fn ok(book: &Path, args: &[&str]) -> Json {
    let (code, line) = run(book, args);
    assert_eq!(code, 0, "args={args:?}: {}", line.render());
    line
}

fn get<'a>(value: &'a Json, key: &str) -> &'a Json {
    value
        .get("data")
        .and_then(|data| data.get(key))
        .or_else(|| value.get(key))
        .expect(key)
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    get(value, key).as_str().expect(key)
}

fn integer(value: &Json, key: &str) -> i128 {
    match get(value, key) {
        Json::Int(value) => *value,
        value => panic!("{key}: {value:?}"),
    }
}

fn head(book: &Path) -> i128 {
    integer(get(&ok(book, &["book", "info"]), "coordinate"), "known_at")
}

fn write(dir: &Path, name: &str, contents: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write fixture");
    path.display().to_string()
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    evidence: String,
}

impl Fixture {
    fn new(with_routes: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let next = NEXT.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("fa-closing-cli-{}-{next}", std::process::id()));
            match std::fs::create_dir(&dir) {
                Ok(()) => break dir,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create {}: {error}", dir.display()),
            }
        };
        let book = dir.join("book");
        ok(
            &book,
            &[
                "book",
                "create",
                "--name",
                "Closing Co",
                "--opening-date",
                "2026-01-01",
            ],
        );
        let chart = write(
            &dir,
            "chart.json",
            r#"{"accounts":[
            {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
            {"code":"3000","name":"Retained earnings","type":"Equity","unit":"USD"},
            {"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},
            {"code":"6000","name":"Expense","type":"Expense","unit":"USD"}
        ]}"#,
        );
        ok(&book, &["chart", "import", &chart]);
        ok(&book, &["period", "create", "--fiscal-year", "2026"]);
        ok(&book, &["period", "open", "FY2026-P12"]);
        ok(&book, &["period", "open", "FY2026-CLOSE"]);
        let source = write(
            &dir,
            "source.txt",
            "Reviewed workpaper documenting the sales, expenses and year-end closing computation.",
        );
        let document = ok(
            &book,
            &[
                "document",
                "add",
                &source,
                "--kind",
                "Workpaper",
                "--grade",
                "HumanUpload",
            ],
        );
        let fixture = Self {
            dir,
            book,
            evidence: text(&document, "oid").to_string(),
        };
        if with_routes {
            fixture.map();
        }
        fixture
    }

    fn map(&self) -> Json {
        ok(
            &self.book,
            &[
                "close",
                "map",
                "--route",
                "4000:3000",
                "--route",
                "6000:3000",
                "--effective-from",
                "2026-01-01",
                "--key",
                "routes-2026",
            ],
        )
    }

    fn post(&self, key: &str, debit: &str, credit: &str, amount: &str) {
        let intent = write(
            &self.dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"2026-12-30","description":"Actual underlying activity","idempotency_key":"{key}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount} USD"}},{{"side":"credit","account":"{credit}","amount":"{amount} USD"}}]}}"#
            ),
        );
        ok(
            &self.book,
            &["post", "--intent", &intent, "--evidence", &self.evidence],
        );
    }

    fn review(&self, key: &str) -> (String, Json) {
        let path = self.dir.join(format!("{key}.review")).display().to_string();
        let review = ok(
            &self.book,
            &[
                "close",
                "year-end",
                "--fiscal-year",
                "2026",
                "--period",
                "FY2026-CLOSE",
                "--key",
                key,
                "--evidence",
                &self.evidence,
                "--review-out",
                &path,
            ],
        );
        assert_eq!(text(&review, "event"), "closing_reviewed");
        (path, review)
    }

    fn close_now(&self, key: &str) -> Json {
        ok(
            &self.book,
            &[
                "close",
                "year-end",
                "--fiscal-year",
                "2026",
                "--period",
                "FY2026-CLOSE",
                "--key",
                key,
                "--evidence",
                &self.evidence,
                "--yes",
            ],
        )
    }

    fn commit(&self, plan: &str) -> Json {
        ok(
            &self.book,
            &[
                "commit", "--plan", plan, "--grant", "read", "--grant", "close",
            ],
        )
    }
}

fn leg_nets(event: &Json) -> BTreeMap<String, i128> {
    let units = fa_money::UnitRegistry::embedded().expect("units");
    let mut nets = BTreeMap::<String, i128>::new();
    for leg in get(event, "legs").as_arr().expect("legs") {
        let amount = fa_money::Amount::parse(text(leg, "amount"), &units).expect("exact amount");
        let signed = match text(leg, "side") {
            "debit" => amount.mantissa,
            "credit" => -amount.mantissa,
            side => panic!("side {side}"),
        };
        let total = nets.entry(text(leg, "account").to_string()).or_default();
        *total = total.checked_add(signed).expect("bounded fixture");
    }
    nets
}

#[test]
fn closing_binary_first_close_delta_reclose_zero_noop_and_exact_plan_retry() {
    let f = Fixture::new(true);
    f.post("sale", "1000", "4000", "100.00");
    f.post("expense", "6000", "1000", "20.00");
    let before = head(&f.book);
    let (path, reviewed) = f.review("first");
    assert_eq!(head(&f.book), before, "review publishes nothing");
    assert_eq!(
        leg_nets(&reviewed),
        BTreeMap::from([
            ("3000".into(), -8_000),
            ("4000".into(), 10_000),
            ("6000".into(), -2_000),
        ])
    );
    let review_bytes = std::fs::read(&path).expect("saved exact review");
    let intent = fa::PostIntent::decode(&review_bytes).expect("canonical PostIntent");
    assert_eq!(intent.proposal().class, fa_model::EntryClass::CLOSING);
    assert!(intent.approvals().is_empty());
    let plan_path = f.dir.join("first.plan").display().to_string();
    let planned = ok(
        &f.book,
        &[
            "close",
            "year-end",
            "--review",
            &path,
            "--digest",
            text(&reviewed, "review_digest"),
            "--dry-run",
            "--plan-out",
            &plan_path,
        ],
    );
    assert_eq!(text(&planned, "event"), "plan");
    assert_eq!(head(&f.book), before);
    let native_plan =
        fa::PostPlan::decode(&std::fs::read(&plan_path).expect("plan")).expect("native plan");
    assert_eq!(
        native_plan.proposal(),
        intent.proposal(),
        "reopening retains every sealed field"
    );
    let posted = f.commit(&plan_path);
    let after = head(&f.book);
    assert_eq!(after, before + 1, "entry and certificate publish together");
    let retry = f.commit(&plan_path);
    assert_eq!(get(&retry, "already_recorded"), &Json::Bool(true));
    assert_eq!(text(&retry, "vid"), text(&posted, "vid"));
    assert_eq!(head(&f.book), after);
    let verified = ok(&f.book, &["verify", "close", "FY2026"]);
    assert_eq!(text(&verified, "event"), "close_verified");
    assert_eq!(get(&verified, "nominal_zero_at_close"), &Json::Bool(true));
    assert_eq!(get(&verified, "needs_reclose"), &Json::Bool(false));

    f.post("late-sale", "1000", "4000", "10.00");
    assert_eq!(run(&f.book, &["verify", "close", "FY2026"]).0, 8);
    let original_close_at = after.to_string();
    let historical = ok(
        &f.book,
        &[
            "verify",
            "close",
            "FY2026",
            "--as-known-at",
            &original_close_at,
        ],
    );
    assert_eq!(integer(&historical, "known_at"), after);
    assert_eq!(integer(get(&historical, "coordinate"), "known_at"), after);
    assert_eq!(get(&historical, "needs_reclose"), &Json::Bool(false));
    let (_, delta) = f.review("delta");
    assert_eq!(
        leg_nets(&delta),
        BTreeMap::from([("3000".into(), -1_000), ("4000".into(), 1_000),])
    );
    let reclosed = f.close_now("delta-commit");
    assert_eq!(text(&reclosed, "class"), "Closing");
    ok(&f.book, &["verify", "close", "--fiscal-year", "2026"]);
    let before_noop = head(&f.book);
    let noop = f.close_now("zero");
    assert_eq!(text(&noop, "event"), "closing_noop");
    assert_eq!(head(&f.book), before_noop);
    let map = ok(&f.book, &["close", "routes", "--as-of", "2026-12-31"]);
    assert_eq!(get(&map, "found"), &Json::Bool(true));
    assert_eq!(get(&map, "routes").as_arr().expect("map").len(), 2);
    let same_map = f.map();
    assert_eq!(get(&same_map, "already_recorded"), &Json::Bool(true));
    assert_eq!(
        head(&f.book),
        before_noop,
        "fresh seals do not defeat a semantic map retry"
    );
}

#[test]
fn closing_binary_closed_reclose_preserves_review_across_independent_approval() {
    let f = Fixture::new(true);
    f.post("sale", "1000", "4000", "100.00");
    f.close_now("first");
    f.post("adjustment", "6000", "1000", "7.00");
    ok(&f.book, &["period", "soft-close", "FY2026-CLOSE"]);
    ok(
        &f.book,
        &[
            "period",
            "close",
            "FY2026-CLOSE",
            "--reason",
            "Scheduled",
            "--yes",
        ],
    );
    let (review_path, reviewed) = f.review("approved-reclose");
    let before_denial = head(&f.book);
    let (denied, _) = run(
        &f.book,
        &[
            "close",
            "year-end",
            "--review",
            &review_path,
            "--digest",
            text(&reviewed, "review_digest"),
            "--dry-run",
        ],
    );
    assert_ne!(
        denied, 0,
        "Closed period requires an actual independent approval"
    );
    assert_eq!(head(&f.book), before_denial);
    let approval = ok(
        &f.book,
        &[
            "approve",
            "--proposal",
            text(&reviewed, "proposal_digest"),
            "--as",
            "reviewer",
        ],
    );
    assert!(head(&f.book) > integer(&reviewed, "known_at"));
    let plan_path = f.dir.join("approved.plan").display().to_string();
    ok(
        &f.book,
        &[
            "close",
            "year-end",
            "--review",
            &review_path,
            "--digest",
            text(&reviewed, "review_digest"),
            "--approval",
            text(&approval, "approval_vid"),
            "--dry-run",
            "--plan-out",
            &plan_path,
        ],
    );
    f.commit(&plan_path);
    ok(&f.book, &["verify", "close", "FY2026"]);
}

#[test]
fn closing_binary_missing_routes_and_same_net_source_replacement_refuse_without_writes() {
    let f = Fixture::new(false);
    f.post("sale", "1000", "4000", "15.00");
    let before = head(&f.book);
    let (code, _) = run(
        &f.book,
        &[
            "close",
            "year-end",
            "--fiscal-year",
            "2026",
            "--period",
            "FY2026-CLOSE",
            "--key",
            "missing",
            "--review-only",
        ],
    );
    assert_ne!(code, 0);
    assert_eq!(head(&f.book), before);
    let (code, _) = run(
        &f.book,
        &[
            "close",
            "map",
            "--route",
            "4000:1000",
            "--effective-from",
            "2026-01-01",
            "--key",
            "bad-target",
        ],
    );
    assert_ne!(code, 0, "Cash cannot be the closing destination");
    assert_eq!(head(&f.book), before);
    f.map();
    let (path, review) = f.review("stale");
    f.post("net-add", "1000", "4000", "1.00");
    f.post("net-remove", "4000", "1000", "1.00");
    let after_source_change = head(&f.book);
    let (code, _) = run(
        &f.book,
        &[
            "close",
            "year-end",
            "--review",
            &path,
            "--digest",
            text(&review, "review_digest"),
            "--dry-run",
        ],
    );
    assert_ne!(code, 0, "equal net is not equal contribution provenance");
    assert_eq!(head(&f.book), after_source_change);
}
