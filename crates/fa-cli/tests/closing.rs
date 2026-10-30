//! First close, delta reclose and independent approvals across real processes.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

#[path = "closing/draft_review.rs"]
mod draft_review;
#[path = "closing/equity_certificate.rs"]
mod equity_certificate;
#[path = "closing/functional.rs"]
mod functional;

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

const CHART: &str = r#"{"accounts":[
            {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
            {"code":"3000","name":"Retained earnings","type":"Equity","unit":"USD"},
            {"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},
            {"code":"6000","name":"Expense","type":"Expense","unit":"USD"}
        ]}"#;

impl Fixture {
    fn new(with_routes: bool) -> Self {
        Self::with_chart(with_routes, CHART)
    }

    fn with_chart(with_routes: bool, chart: &str) -> Self {
        Self::with_chart_and_keys(with_routes, chart, None)
    }

    fn with_chart_and_keys(with_routes: bool, chart: &str, development_keys: Option<u8>) -> Self {
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
        if let Some(seed) = development_keys {
            let keys = fa::BookKeys::for_development(seed);
            let created = fa::Book::create_dir(
                &book,
                keys.clone(),
                fa_journal::BookSpec {
                    book_id: fa_model::Id128([seed; 16]),
                    name: "Closing Co".into(),
                    base_unit: fa_money::UnitRegistry::embedded()
                        .unwrap()
                        .lookup("USD")
                        .unwrap(),
                    calendar: fa_time::FiscalCalendar::monthly("closing-functional", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: Some(fa_time::DateDay::from_ymd(2026, 1, 1).unwrap()),
                },
                fa::Entropy::deterministic(u64::from(seed)),
            )
            .unwrap();
            keys.save(&book.join("book.keys")).unwrap();
            drop(created);
        } else {
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
        }
        let chart = write(&dir, "chart.json", chart);
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

fn closing_agent(f: &Fixture, grants: &[&str], args: &[&str]) -> (u8, Json) {
    let authority = fa_cli::authority::LaunchAuthority::new(
        f.book.clone(),
        None,
        "closing-agent",
        fa_cli::authority::LaunchProfile::Agent,
        grants,
    )
    .expect("fixed Agent authority");
    let mut argv: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
    argv.push("--json".into());
    let (code, output) = fa_cli::entry::fa_with_authority(
        &argv,
        fa_cli::cli::Files {
            cwd: None,
            stdin: fa_cli::cli::Stdin::Missing,
        },
        &authority,
        true,
    );
    let lines: Vec<_> = output.stdout.lines().collect();
    assert_eq!(lines.len(), 1, "args={args:?}: {output:?}");
    fa_cli::verbs::registry()
        .expect("registry")
        .check_line(lines[0])
        .expect("registered Agent closing result");
    (code, json::parse(lines[0]).expect("robot line"))
}

#[test]
fn closing_agent_review_rehearses_exact_draft_before_independent_close_promotion() {
    const DRAFT: &str = "reviewed-year-end";
    let f = Fixture::new(true);
    f.post("agent-sale", "1000", "4000", "100.00");
    f.post("agent-expense", "6000", "1000", "20.00");
    let original_rows = get(&ok(&f.book, &["tb", "--period", "FY2026-P12"]), "rows").clone();
    let (code, opened) = closing_agent(&f, &["read", "post"], &["draft", "new", DRAFT]);
    assert_eq!(code, 0, "{}", opened.render());
    let (code, reviewed) = closing_agent(
        &f,
        &["read", "post"],
        &[
            "close",
            "year-end",
            "--fiscal-year",
            "2026",
            "--period",
            "FY2026-CLOSE",
            "--key",
            "agent-year-end",
            "--evidence",
            &f.evidence,
            "--review-only",
        ],
    );
    assert_eq!(code, 0, "{}", reviewed.render());
    assert_eq!(text(&reviewed, "event"), "closing_reviewed");
    assert_eq!(
        leg_nets(&reviewed),
        BTreeMap::from([
            ("3000".into(), -8_000),
            ("4000".into(), 10_000),
            ("6000".into(), -2_000),
        ])
    );
    let append = [
        "close",
        "year-end",
        "--review",
        text(&reviewed, "bytes"),
        "--digest",
        text(&reviewed, "review_digest"),
        "--draft",
        DRAFT,
    ];
    let (code, planned) = closing_agent(&f, &["read", "post"], &append);
    assert_eq!(code, 0, "{}", planned.render());
    assert_eq!(text(&planned, "event"), "draft_planned");
    assert_eq!(
        text(&planned, "proposal_digest"),
        text(&reviewed, "proposal_digest")
    );
    let (code, retried) = closing_agent(&f, &["read", "post"], &append);
    assert_eq!(code, 0, "{}", retried.render());
    assert_eq!(get(&retried, "already_recorded"), &Json::Bool(true));
    assert_eq!(
        text(&retried, "control_entry"),
        text(&planned, "control_entry")
    );

    // Reopening the durable book checks the actual retained bytes and planner
    // capability, rather than trusting the CLI's description of its result.
    {
        let book = fa::Book::open_dir(
            &f.book,
            fa::BookKeys::load(&f.book.join("book.keys")).unwrap(),
            fa::Entropy::deterministic(930),
        )
        .unwrap();
        let view = book.draft(DRAFT).unwrap().unwrap();
        assert_eq!(view.intents.len(), 1);
        let retained = &view.intents[0];
        assert!(!retained.capability.holds(fa::Op::Close));
        let retained_hex: String = retained
            .intent
            .canonical_bytes()
            .unwrap()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(retained_hex, text(&reviewed, "bytes"));
    }
    assert_eq!(
        get(&ok(&f.book, &["tb", "--period", "FY2026-P12"]), "rows"),
        &original_rows
    );
    let before_rehearsal = head(&f.book);
    let rehearsed = ok(
        &f.book,
        &[
            "close",
            "dry-run",
            "--period",
            "FY2026-CLOSE",
            "--draft",
            DRAFT,
        ],
    );
    assert_eq!(text(&rehearsed, "event"), "draft_diff");
    assert_eq!(integer(&rehearsed, "plans"), 1);
    for (code, expected) in [
        ("4000", "100.00 USD"),
        ("6000", "-20.00 USD"),
        ("3000", "-80.00 USD"),
    ] {
        let row = get(&rehearsed, "rows")
            .as_arr()
            .unwrap()
            .iter()
            .find(|row| text(row, "code") == code)
            .expect("closing delta");
        assert_eq!(text(row, "delta"), expected);
    }
    assert_eq!(
        head(&f.book),
        before_rehearsal,
        "rehearsal publishes nothing"
    );
    assert_eq!(
        get(&ok(&f.book, &["tb", "--period", "FY2026-P12"]), "rows"),
        &original_rows
    );

    for args in [
        vec!["draft", "promote", DRAFT, "--as", "controller", "--yes"],
        vec![
            "draft",
            "promote",
            DRAFT,
            "--as",
            "closing-agent",
            "--grant",
            "close",
            "--yes",
        ],
    ] {
        let (code, refused) = run(&f.book, &args);
        assert_ne!(
            code,
            0,
            "independent Close authority is mandatory: {}",
            refused.render()
        );
        assert_eq!(head(&f.book), before_rehearsal);
    }
    let promote = [
        "draft",
        "promote",
        DRAFT,
        "--as",
        "controller",
        "--grant",
        "close",
        "--yes",
    ];
    let promoted = ok(&f.book, &promote);
    assert_eq!(text(&promoted, "event"), "draft_promoted");
    assert_eq!(get(&promoted, "entries").as_arr().unwrap().len(), 1);
    assert_eq!(
        get(&promoted, "entries").as_arr().unwrap()[0]
            .as_str()
            .unwrap(),
        text(&planned, "entry")
    );
    let verified = ok(&f.book, &["verify", "close", "FY2026"]);
    assert_eq!(get(&verified, "nominal_zero_at_close"), &Json::Bool(true));
    assert_eq!(get(&verified, "needs_reclose"), &Json::Bool(false));
    let after = head(&f.book);
    let retried = ok(&f.book, &promote);
    assert_eq!(get(&retried, "already_recorded"), &Json::Bool(true));
    assert_eq!(head(&f.book), after);
}

#[test]
fn closing_agent_review_requires_read_post_and_cannot_become_native_publication() {
    let f = Fixture::new(true);
    let review = [
        "close",
        "year-end",
        "--fiscal-year",
        "2026",
        "--period",
        "FY2026-CLOSE",
        "--key",
        "agent-review",
        "--evidence",
        &f.evidence,
        "--review-only",
    ];
    let before = head(&f.book);
    for grants in [&["read"][..], &["post"][..]] {
        let (code, refused) = closing_agent(&f, grants, &review);
        assert_ne!(code, 0, "{}", refused.render());
        assert_eq!(head(&f.book), before, "authority precedes observation");
    }
    let (code, noop) = closing_agent(&f, &["read", "post"], &review);
    assert_eq!(code, 0, "{}", noop.render());
    assert_eq!(text(&noop, "event"), "closing_noop");
    f.post("authority-sale", "1000", "4000", "10.00");
    let (code, reviewed) = closing_agent(&f, &["read", "post"], &review);
    assert_eq!(code, 0, "{}", reviewed.render());
    let before_denials = head(&f.book);
    let native = [
        "close",
        "year-end",
        "--review",
        text(&reviewed, "bytes"),
        "--digest",
        text(&reviewed, "review_digest"),
        "--dry-run",
    ];
    let (code, refused) = closing_agent(&f, &["read", "post"], &native);
    assert_ne!(
        code,
        0,
        "Agent cannot prepare a native Close plan: {}",
        refused.render()
    );
    assert_eq!(head(&f.book), before_denials);
    let (code, opened) = closing_agent(&f, &["read", "post"], &["draft", "new", "authority-close"]);
    assert_eq!(code, 0, "{}", opened.render());
    let before_denials = head(&f.book);
    for extra in ["--dry-run", "--review-only", "--certify"] {
        let args = [
            "close",
            "year-end",
            "--review",
            text(&reviewed, "bytes"),
            "--digest",
            text(&reviewed, "review_digest"),
            "--draft",
            "authority-close",
            extra,
        ];
        let (code, refused) = closing_agent(&f, &["read", "post"], &args);
        assert_ne!(code, 0, "invalid mixed route: {}", refused.render());
        assert_eq!(head(&f.book), before_denials);
    }
    let (code, refused) = closing_agent(
        &f,
        &["read", "post"],
        &[
            "close",
            "year-end",
            "--review",
            text(&reviewed, "bytes"),
            "--digest",
            &"00".repeat(32),
            "--draft",
            "authority-close",
        ],
    );
    assert_ne!(code, 0, "wrong review digest: {}", refused.render());
    assert_eq!(
        integer(
            get(&ok(&f.book, &["draft", "show", "authority-close"]), "draft"),
            "intents"
        ),
        0
    );
    assert_eq!(run(&f.book, &["verify", "close", "FY2026"]).0, 8);
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
fn closing_binary_rejects_a_plan_after_real_report_certification() {
    let f = Fixture::new(true);
    f.post("metadata-sale", "1000", "4000", "200.00");
    let (review_path, review) = f.review("metadata-prefix");
    let prepare = |path: &str| {
        ok(
            &f.book,
            &[
                "close",
                "year-end",
                "--review",
                &review_path,
                "--digest",
                text(&review, "review_digest"),
                "--dry-run",
                "--plan-out",
                path,
            ],
        )
    };
    let stale_path = f.dir.join("before-certificate.plan").display().to_string();
    let planned = prepare(&stale_path);
    let basis = integer(&planned, "snapshot_seq");
    assert_eq!(head(&f.book), basis);

    // Exercise genuine native certificate retention, not an injected graph
    // row. This command emits its report and its retained certificate.
    let certified = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&f.book)
        .args(["tb", "--period", "FY2026-P12", "--certify", "--json"])
        .env_remove("FA_BOOK")
        .stdin(Stdio::null())
        .output()
        .expect("certify the actual trial balance");
    let stdout = String::from_utf8(certified.stdout).expect("UTF-8 report");
    assert!(
        certified.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&certified.stderr)
    );
    let registry = fa_cli::verbs::registry().expect("registry");
    let lines: Vec<_> = stdout
        .lines()
        .map(|line| {
            registry.check_line(line).expect("registered robot output");
            json::parse(line).expect("report line")
        })
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(text(&lines[0], "event"), "trial_balance");
    assert_eq!(integer(&lines[0], "known_at"), basis);
    assert_eq!(text(&lines[1], "event"), "report_certificate");
    assert_eq!(integer(&lines[1], "recorded_at"), basis + 1);
    let before = head(&f.book);
    assert_eq!(before, basis + 1);

    let (code, refused) = run(
        &f.book,
        &[
            "commit",
            "--plan",
            &stale_path,
            "--grant",
            "read",
            "--grant",
            "close",
        ],
    );
    assert_eq!(code, 6, "{}", refused.render());
    assert_eq!(text(&refused, "refusal_id"), "FA-REF-034");
    assert_eq!(head(&f.book), before, "the stale close publishes nothing");

    let fresh_path = f.dir.join("after-certificate.plan").display().to_string();
    let fresh = prepare(&fresh_path);
    assert_eq!(integer(&fresh, "snapshot_seq"), before);
    let posted = f.commit(&fresh_path);
    assert_eq!(integer(&posted, "recorded_at"), before + 1);
    let verified = ok(&f.book, &["verify", "close", "FY2026"]);
    assert_eq!(get(&verified, "nominal_zero_at_close"), &Json::Bool(true));
    assert_eq!(get(&verified, "needs_reclose"), &Json::Bool(false));

    f.post("after-metadata-close", "1000", "4000", "1.00");
    let retry_head = head(&f.book);
    let retry = f.commit(&fresh_path);
    assert_eq!(get(&retry, "already_recorded"), &Json::Bool(true));
    assert_eq!(text(&retry, "vid"), text(&posted, "vid"));
    assert_eq!(
        integer(&retry, "recorded_at"),
        integer(&posted, "recorded_at")
    );
    assert_eq!(head(&f.book), retry_head);
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

/// The statement of changes in equity (plan §12.1) ties through a real
/// year-end close: before it, net income sits in unclosed earnings; the
/// Closing entry moves it into retained earnings as a closing transfer that
/// nets to zero, and every total stays the same. A read at the pre-close
/// frontier still answers that frontier, and a role the chart cannot carry
/// is refused before any output.
#[test]
fn equity_roll_forward_ties_issuances_distributions_and_net_income_through_a_year_end_close() {
    let f = Fixture::with_chart(
        true,
        r#"{"accounts":[
            {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
            {"code":"3000","name":"Retained earnings","type":"Equity","unit":"USD"},
            {"code":"3100","name":"Common stock","type":"Equity","unit":"USD"},
            {"code":"3200","name":"Dividends","type":"Equity","unit":"USD"},
            {"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},
            {"code":"6000","name":"Expense","type":"Expense","unit":"USD"}
        ]}"#,
    );
    f.post("issue", "1000", "3100", "500.00");
    f.post("sale", "1000", "4000", "100.00");
    f.post("expense", "6000", "1000", "20.00");
    f.post("dividend", "3200", "1000", "30.00");
    let base = [
        "statement",
        "equity-roll-forward",
        "--from",
        "2026-01-01",
        "--to",
        "2026-12-31",
        "--issuance",
        "3100",
        "--distribution",
        "3200",
    ];
    let equity = |extra: &[&str]| {
        let mut args = base.to_vec();
        args.extend_from_slice(extra);
        ok(&f.book, &args)
    };
    let check = |event: &Json, when: &str, expected: &[(&str, &str)]| {
        assert_eq!(text(event, "event"), "equity_roll_forward", "{when}");
        let units = get(event, "units").as_arr().expect("units");
        assert_eq!(units.len(), 1, "{when}: one unit, USD");
        for (field, value) in expected {
            assert_eq!(text(&units[0], field), *value, "{when}: {field}");
        }
    };
    let kinds = |event: &Json| -> Vec<(String, String, String)> {
        get(event, "movements")
            .as_arr()
            .expect("movements")
            .iter()
            .map(|m| {
                (
                    text(m, "kind").to_string(),
                    text(m, "account").to_string(),
                    format!("{} {}", text(m, "side"), text(m, "amount")),
                )
            })
            .collect()
    };
    let before_close = head(&f.book);
    let before = equity(&[]);
    let totals = [
        ("opening_total_equity", "0.00 USD"),
        ("net_income", "80.00 USD"),
        ("issuances", "500.00 USD"),
        ("distributions", "-30.00 USD"),
        ("other_equity_movements", "0.00 USD"),
        ("closing_transfers_net", "0.00 USD"),
        ("net_equity_change", "550.00 USD"),
        ("closing_total_equity", "550.00 USD"),
        ("tie_out_residual", "0.00 USD"),
    ];
    check(&before, "before the close", &totals);
    check(
        &before,
        "before the close",
        &[
            ("closing_contributed_equity", "470.00 USD"),
            ("closing_unclosed_earnings", "80.00 USD"),
        ],
    );
    // The closing stocks are the balance sheet's at --to: posted equity,
    // unclosed earnings and their total, all credit-normal.
    let ties_to_balance_sheet = |event: &Json, when: &str| {
        let sheet = ok(
            &f.book,
            &["statement", "balance-sheet", "--for", "FY2026-P12"],
        );
        let line = |code: &str| {
            let lines = get(&sheet, "lines").as_arr().expect("lines");
            let line = lines
                .iter()
                .find(|line| text(line, "code") == code)
                .unwrap_or_else(|| panic!("{when}: no {code} line in {}", sheet.render()));
            line.get("amounts").and_then(Json::as_arr).expect("amounts")[0]
                .as_str()
                .expect("an amount")
                .to_string()
        };
        let units = get(event, "units").as_arr().expect("units");
        for (statement, sheet_line) in [
            ("closing_contributed_equity", "equity"),
            ("closing_unclosed_earnings", "unclosed_earnings"),
            ("closing_total_equity", "total_equity"),
        ] {
            assert_eq!(
                text(&units[0], statement),
                line(sheet_line),
                "{when}: {statement} is the balance sheet's {sheet_line}"
            );
        }
    };
    ties_to_balance_sheet(&before, "before the close");
    let movement = |kind: &str, account: &str, amount: &str| {
        (kind.to_string(), account.to_string(), amount.to_string())
    };
    assert_eq!(
        kinds(&before),
        [
            movement("issuance", "3100", "credit 500.00 USD"),
            movement("distribution", "3200", "debit 30.00 USD"),
        ],
        "revenue and expense legs are net income, not equity movements"
    );
    assert_eq!(integer(&before, "movement_count"), 2);

    let closed = f.close_now("equity-close");
    assert_eq!(text(&closed, "class"), "Closing");
    let after = equity(&[]);
    check(&after, "after the close", &totals);
    check(
        &after,
        "after the close",
        &[
            ("closing_contributed_equity", "550.00 USD"),
            ("closing_unclosed_earnings", "0.00 USD"),
        ],
    );
    let mut transfers: Vec<_> = kinds(&after)
        .into_iter()
        .filter(|(kind, _, _)| kind == "closing_transfer")
        .map(|(_, account, amount)| (account, amount))
        .collect();
    transfers.sort();
    // The year-end close posts one leg per route into retained earnings
    // (revenue's credit and expense's debit), not their net.
    assert_eq!(
        transfers,
        [
            ("3000".to_string(), "credit 100.00 USD".to_string()),
            ("3000".to_string(), "debit 20.00 USD".to_string()),
            ("4000".to_string(), "debit 100.00 USD".to_string()),
            ("6000".to_string(), "credit 20.00 USD".to_string()),
        ],
        "every leg of the Closing entry is the closing transfer"
    );
    ties_to_balance_sheet(&after, "after the close");

    let as_known = equity(&["--as-known-at", &before_close.to_string()]);
    assert_eq!(integer(&as_known, "known_at"), before_close);
    check(&as_known, "at the pre-close frontier", &totals);
    assert_eq!(
        get(&as_known, "units"),
        get(&before, "units"),
        "a recorded frontier answers as it did"
    );

    let after_close = head(&f.book);
    for (why, args) in [
        (
            "an asset is not an equity account",
            &["--issuance", "1000"][..],
        ),
        (
            "an account the chart does not have",
            &["--issuance", "3999"][..],
        ),
        ("one account in two roles", &["--distribution", "3100"][..]),
        (
            "a date window, not a period code",
            &["--for", "FY2026-P12"][..],
        ),
        (
            "duplicate certificate paths",
            &[
                "--certificate-out",
                "first.cert",
                "--certificate-out",
                "second.cert",
            ][..],
        ),
    ] {
        let mut args_ = base.to_vec();
        args_.extend_from_slice(args);
        let (code, line) = run(&f.book, &args_);
        assert_eq!(code, 2, "{why}: {}", line.render());
        assert_eq!(text(&line, "event"), "error", "{why}");
    }
    assert_eq!(
        head(&f.book),
        after_close,
        "reads and refusals write nothing"
    );
}

/// fa-ficc: an analytic value (a cost center) closes with its account, so a
/// book whose expense account requires a cost center still closes its year;
/// a fund has no closing treatment yet and is refused, writing nothing.
#[test]
fn closing_binary_closes_cost_center_tagged_nominal_legs_with_their_account() {
    let tagged = |f: &Fixture, key: &str, dimension: &str, value: &str| {
        let intent = write(
            &f.dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"2026-12-30","idempotency_key":"{key}","legs":[{{"side":"debit","account":"6000","amount":"20.00 USD","dimensions":{{"{dimension}":"{value}"}}}},{{"side":"credit","account":"1000","amount":"20.00 USD"}}]}}"#
            ),
        );
        ok(
            &f.book,
            &["post", "--intent", &intent, "--evidence", &f.evidence],
        );
    };
    let f = Fixture::new(true);
    ok(
        &f.book,
        &["dimension", "add", "cost_center", "CC10", "--name", "Ops"],
    );
    ok(&f.book, &["dimension", "require", "cost_center", "6000"]);
    f.post("sale", "1000", "4000", "100.00");
    tagged(&f, "tagged-expense", "cost_center", "CC10");
    let closed = f.close_now("tagged-close");
    assert_eq!(text(&closed, "class"), "Closing");
    let verified = ok(&f.book, &["verify", "close", "FY2026"]);
    assert_eq!(get(&verified, "nominal_zero_at_close"), &Json::Bool(true));

    let g = Fixture::new(true);
    ok(
        &g.book,
        &["dimension", "add", "fund", "F1", "--name", "General"],
    );
    tagged(&g, "fund-expense", "fund", "F1");
    let before = head(&g.book);
    let (code, refused) = run(
        &g.book,
        &[
            "close",
            "year-end",
            "--fiscal-year",
            "2026",
            "--period",
            "FY2026-CLOSE",
            "--key",
            "fund-close",
            "--evidence",
            &g.evidence,
            "--yes",
        ],
    );
    assert_eq!(code, 3, "{}", refused.render());
    assert_eq!(head(&g.book), before);
}
