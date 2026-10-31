//! Financial statements through the real CLI: exact native-unit columns,
//! shared historical coordinates, retained replay, and selector refusals.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

#[path = "statements/custom.rs"]
mod custom;

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

/// A lot policy (SchemaChange 21) is a chart-install control that changes no
/// account membership, as an asset schedule (22) is: a statement certified
/// before it stays Current. Its status check used to refuse with "chart
/// install lacks its recorded chart body" (exit 8), because the scan's
/// allow-list stopped at kind 20.
#[test]
fn a_later_lot_policy_leaves_a_retained_statement_current() {
    let fixture = Fixture::new();
    let inventory = fixture.dir.join("inventory.json");
    std::fs::write(
        &inventory,
        r#"{"code":"1400","name":"Inventory","type":"Asset","unit":"any"}"#,
    )
    .unwrap();
    ok(
        &fixture.book,
        &[
            "chart",
            "open",
            inventory.to_str().unwrap(),
            "--opened",
            "2026-01-01",
        ],
    );
    let certified = ok(
        &fixture.book,
        &[
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--certify",
        ],
    );
    let certificate = certified
        .iter()
        .find(|event| text(event, "event") == "report_certificate")
        .unwrap();
    let oid = text(data(certificate), "oid").to_string();
    let status = ok(&fixture.book, &["certificate", "status", &oid]);
    assert_eq!(text(data(&status[0]), "status"), "Current");
    ok(
        &fixture.book,
        &[
            "chart",
            "lot-policy",
            "set",
            "--account",
            "1400",
            "--law",
            "FIFO",
            "--regime",
            "US-GAAP",
            "--date",
            "2026-03-01",
            "--key",
            "inventory-policy",
        ],
    );
    let status = ok(&fixture.book, &["certificate", "status", &oid]);
    assert_eq!(text(data(&status[0]), "status"), "Current");
    // A later posting still supersedes it: the scan is not blinded.
    fixture.post("late-sale", "2026-03-20", "1000", "4000", "5.00 USD");
    let status = ok(&fixture.book, &["certificate", "status", &oid]);
    assert_eq!(text(data(&status[0]), "status"), "SupersededBy");
}

#[test]
fn equity_roll_forward_shows_prior_period_adjustments_and_ties() {
    let dir = temporary();
    let book = dir.join("book");
    let invoke_result = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_fa"))
            .arg("--book")
            .arg(&book)
            .args(args)
            .arg("--json")
            .env_remove("FA_BOOK")
            .output()
            .expect("run the cross-year PPA workflow");
        let exit = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!(
            "PPA argv=fa --book {book:?} {args:?} --json exit={exit}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        let registry = fa_cli::verbs::registry().unwrap();
        let events = stdout
            .lines()
            .map(|line| {
                registry.check_line(line).unwrap();
                json::parse(line).unwrap()
            })
            .collect::<Vec<_>>();
        (exit, events)
    };
    let invoke = |args: &[&str]| {
        let (exit, events) = invoke_result(args);
        assert_eq!(exit, 0, "cross-year PPA step: {args:?}");
        events
    };
    invoke(&["book", "create", "--name", "Cross-year PPA"]);
    let chart = dir.join("chart.json");
    std::fs::write(
        &chart,
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"3000","name":"Retained earnings","type":"Equity","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    )
    .unwrap();
    invoke(&["chart", "import", chart.to_str().unwrap()]);
    invoke(&["chart", "role", "3000", "retained_earnings"]);
    for year in ["2025", "2026"] {
        invoke(&["period", "create", "--fiscal-year", year]);
    }
    for period in ["FY2025-P12", "FY2026-P01"] {
        invoke(&["period", "open", period]);
    }
    let source = dir.join("source.txt");
    std::fs::write(
        &source,
        b"Fixture bank advice: an omitted December 2025 receipt.",
    )
    .unwrap();
    let document = invoke(&[
        "document",
        "add",
        source.to_str().unwrap(),
        "--kind",
        "Receipt",
        "--grade",
        "HumanUpload",
    ]);
    let evidence = text(data(&document[0]), "oid");
    let opening = dir.join("opening.json");
    std::fs::write(&opening, r#"{"idempotency_key":"2025-capital","effective_date":"2025-12-01","legs":[{"side":"debit","account":"1000","amount":"100.00 USD"},{"side":"credit","account":"3000","amount":"100.00 USD"}]}"#).unwrap();
    invoke(&[
        "post",
        "--intent",
        opening.to_str().unwrap(),
        "--evidence",
        evidence,
    ]);
    invoke(&["period", "soft-close", "FY2025-P12"]);
    invoke(&[
        "period",
        "close",
        "FY2025-P12",
        "--reason",
        "Scheduled",
        "--yes",
    ]);

    // A Close admits audit adjustments; it is never an issuance anchor.
    let (exit, not_reported) = invoke_result(&[
        "statement",
        "equity-roll-forward",
        "--for",
        "FY2025-P12",
        "--as-originally-reported",
    ]);
    assert_eq!(exit, 3, "{not_reported:?}");
    assert_eq!(text(data(&not_reported[0]), "refusal_id"), "FA-REF-161");

    let equity_args = [
        "statement",
        "equity-roll-forward",
        "--from",
        "2026-01-01",
        "--to",
        "2026-12-31",
        "--unit",
        "USD",
        "--label",
        "FY2026 correction",
    ];
    let before_path = dir.join("before.cert");
    let mut before_args = equity_args.to_vec();
    before_args.extend(["--certificate-out", before_path.to_str().unwrap()]);
    let before = invoke(&before_args);
    let original = data(&before[0]).clone();
    let original_unit = &array(&original, "units")[0];
    assert_eq!(text(original_unit, "opening_total_equity"), "100.00 USD");
    assert_eq!(text(original_unit, "prior_period_adjustments"), "0.00 USD");
    let original_prefix = original.get("known_at").unwrap().render();

    // Record the real January statement that left the entity before the
    // correction. Its certified prefix, not its later publication, pins the
    // original equity view. The period remains open for the lawful PPA.
    let issued = invoke(&[
        "statement",
        "balance-sheet",
        "--for",
        "FY2026-P01",
        "--certify",
    ]);
    let issued_prefix = data(&issued[0]).get("known_at").unwrap().clone();
    let issued_certificate = issued
        .iter()
        .find(|event| text(event, "event") == "report_certificate")
        .unwrap();
    let issue = invoke(&[
        "statement",
        "issue",
        "--certificate",
        text(data(issued_certificate), "oid"),
        "--issued-to",
        "board",
        "--dry-run",
    ]);
    let issue_plan = dir.join("issue.plan");
    std::fs::write(&issue_plan, text(data(&issue[0]), "bytes")).unwrap();
    let issue_approval = invoke(&[
        "approve",
        "--proposal",
        text(data(&issue[0]), "proposal_digest"),
        "--as",
        "controller",
    ]);
    invoke(&[
        "statement",
        "issue",
        "--plan",
        issue_plan.to_str().unwrap(),
        "--approval",
        text(data(&issue_approval[0]), "approval_vid"),
    ]);

    invoke(&[
        "case",
        "open",
        "--kind",
        "PriorPeriodAdjustment",
        "--periods",
        "FY2025-P12",
        "--determined-on",
        "2026-01-02",
        "--authority",
        evidence,
    ]);
    invoke(&["scenario", "fork", "adjusted", "--as", "analyst"]);
    let intent = dir.join("adjustment.json");
    std::fs::write(&intent, format!(r#"{{"idempotency_key":"cross-year-ppa","effective_date":"2026-01-02","relates_to":"FY2025-P12","evidence":["{evidence}"],"legs":[{{"side":"debit","account":"1000","amount":"50.00 USD"}},{{"side":"credit","account":"3000","amount":"50.00 USD"}}]}}"#)).unwrap();
    invoke(&[
        "scenario",
        "run",
        "adjusted",
        "--intent",
        intent.to_str().unwrap(),
        "--as",
        "analyst",
    ]);
    let diff = dir.join("adjusted.diff");
    invoke(&[
        "scenario",
        "diff",
        "adjusted",
        "--period",
        "FY2025-P12",
        "--period",
        "FY2026-P01",
        "--certificate-out",
        diff.to_str().unwrap(),
    ]);
    invoke(&[
        "case",
        "rehearse",
        "1",
        "--certificate",
        diff.to_str().unwrap(),
    ]);
    let plan = invoke(&["case", "approve", "1", "--dry-run"]);
    let digest = text(data(&plan[0]), "digest");
    let mut approvals = Vec::new();
    for principal in ["controller", "auditor"] {
        let approved = invoke(&["approve", "--proposal", digest, "--as", principal]);
        approvals.push(text(data(&approved[0]), "approval_vid").to_string());
    }
    invoke(&[
        "case",
        "approve",
        "1",
        "--approval",
        &approvals[0],
        "--approval",
        &approvals[1],
    ]);
    let posted = invoke(&["case", "post", "1", "--yes"]);
    assert_eq!(
        data(&posted[0]).get("already_recorded"),
        Some(&Json::Bool(false))
    );
    let retry = invoke(&["case", "post", "1", "--yes"]);
    assert_eq!(
        data(&retry[0]).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    let posted_members = array(data(&posted[0]).get("case").unwrap(), "posted");
    assert_eq!(posted_members.len(), 1);
    assert_eq!(
        posted_members,
        array(data(&retry[0]).get("case").unwrap(), "posted"),
        "an exact retry returns the same plans, entries and entry digests"
    );

    let after_path = dir.join("after.cert");
    let mut after_args = equity_args.to_vec();
    after_args.extend([
        "--as-currently-stated",
        "--certificate-out",
        after_path.to_str().unwrap(),
    ]);
    let after = invoke(&after_args);
    let current = data(&after[0]);
    let unit = &array(current, "units")[0];
    for (field, amount) in [
        ("opening_total_equity", "100.00 USD"),
        ("prior_period_adjustments", "50.00 USD"),
        ("opening_equity_as_adjusted", "150.00 USD"),
        ("closing_total_equity", "150.00 USD"),
        ("net_income", "0.00 USD"),
        ("other_equity_movements", "0.00 USD"),
        ("tie_out_residual", "0.00 USD"),
    ] {
        assert_eq!(text(unit, field), amount, "{current:?}");
    }
    let movements = array(current, "movements");
    assert_eq!(movements.len(), 1);
    assert_eq!(text(&movements[0], "kind"), "prior_period_adjustment");
    assert_eq!(text(&movements[0], "relates_to"), "FY2025-P12");
    assert_eq!(text(&movements[0], "effective_date"), "2026-01-02");
    assert_eq!(text(&movements[0], "account"), "3000");
    assert_eq!(movements[0].get("case"), Some(&Json::Int(1)));
    let balance = invoke(&["statement", "balance-sheet", "--for", "FY2026-P12"]);
    assert_eq!(
        line(data(&balance[0]), "total_equity", "USD"),
        &[Json::Str("150.00 USD".into())]
    );

    let period_args = [
        "statement",
        "equity-roll-forward",
        "--for",
        "FY2026-P01",
        "--unit",
        "USD",
        "--label",
        "FY2026 correction",
    ];
    let originally_path = dir.join("originally-reported.cert");
    let mut originally_args = period_args.to_vec();
    originally_args.extend([
        "--as-originally-reported",
        "--certificate-out",
        originally_path.to_str().unwrap(),
    ]);
    let originally = invoke(&originally_args);
    let original_january = data(&originally[0]);
    assert_eq!(original_january.get("known_at"), Some(&issued_prefix));
    assert_eq!(text(original_january, "effective_from"), "2026-01-01");
    assert_eq!(text(original_january, "effective_through"), "2026-01-31");
    assert!(array(original_january, "movements").is_empty());
    let original_january_unit = &array(original_january, "units")[0];
    for (field, amount) in [
        ("opening_total_equity", "100.00 USD"),
        ("prior_period_adjustments", "0.00 USD"),
        ("opening_equity_as_adjusted", "100.00 USD"),
        ("closing_total_equity", "100.00 USD"),
        ("net_income", "0.00 USD"),
        ("tie_out_residual", "0.00 USD"),
    ] {
        assert_eq!(
            text(original_january_unit, field),
            amount,
            "{original_january:?}"
        );
    }
    let issued_prefix_text = issued_prefix.render();
    let mut at_issue_args = period_args.to_vec();
    at_issue_args.extend(["--known-at", &issued_prefix_text]);
    assert_eq!(data(&invoke(&at_issue_args)[0]), original_january);

    let mut current_period_args = period_args.to_vec();
    current_period_args.push("--as-currently-stated");
    let current_period = invoke(&current_period_args);
    let current_january = data(&current_period[0]);
    assert_eq!(text(current_january, "effective_through"), "2026-01-31");
    assert_eq!(array(current_january, "units"), array(current, "units"));
    assert_eq!(array(current_january, "movements"), movements);
    let expected = format!(
        r#"{{"kind":"equity-roll-forward","units":["USD"],"label":"FY2026 correction","from":"2026-01-01","through":"2026-01-31","known_at":{issued_prefix_text},"issuance_accounts":[],"distribution_accounts":[]}}"#
    );
    let replayed_original = invoke(&[
        "replay",
        originally_path.to_str().unwrap(),
        "--expect",
        &expected,
    ]);
    let replayed_original = replayed_original
        .iter()
        .find(|event| text(event, "event") == "equity_roll_forward")
        .unwrap();
    assert_eq!(data(replayed_original), original_january);

    for (path, report, prefix) in [
        (&before_path, &original, original_prefix),
        (
            &after_path,
            current,
            current.get("known_at").unwrap().render(),
        ),
    ] {
        let expected = format!(
            r#"{{"kind":"equity-roll-forward","units":["USD"],"label":"FY2026 correction","from":"2026-01-01","through":"2026-12-31","known_at":{prefix},"issuance_accounts":[],"distribution_accounts":[]}}"#
        );
        let replayed = invoke(&["replay", path.to_str().unwrap(), "--expect", &expected]);
        let replayed = replayed
            .iter()
            .find(|event| text(event, "event") == "equity_roll_forward")
            .unwrap();
        assert_eq!(
            data(replayed),
            report,
            "historical and adjusted certificates retain their own prefix"
        );
    }
}

#[test]
fn equity_current_view_rejects_historical_selectors_before_opening_a_book() {
    let dir = temporary();
    let book = dir.join("absent-book");
    for flag in ["--known-at", "--as-known-at"] {
        for value in ["HEAD", "0", "not-an-instant"] {
            let args = [
                "statement",
                "equity-roll-forward",
                "--from",
                "2026-01-01",
                "--to",
                "2026-12-31",
                "--unit",
                "USD",
                "--as-currently-stated",
                flag,
                value,
            ];
            let output = Command::new(env!("CARGO_BIN_EXE_fa"))
                .arg("--book")
                .arg(&book)
                .args(args)
                .arg("--json")
                .env_remove("FA_BOOK")
                .output()
                .expect("run the conflicting equity selectors");
            let stdout = String::from_utf8(output.stdout).unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!(
                "equity view argv=fa --book {book:?} {args:?} --json exit={:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
                output.status.code()
            );
            assert_eq!(output.status.code(), Some(2), "{args:?}");
            let registry = fa_cli::verbs::registry().unwrap();
            let events: Vec<Json> = stdout
                .lines()
                .map(|line| {
                    registry.check_line(line).unwrap();
                    json::parse(line).unwrap()
                })
                .collect();
            assert_eq!(events.len(), 1, "{events:?}");
            assert_eq!(text(&events[0], "event"), "error");
            assert!(stdout.contains("--as-currently-stated"), "{stdout}");
            assert!(stdout.contains("cannot be combined"), "{stdout}");
            assert!(stdout.contains(flag), "{stdout}");
            assert!(
                !book.exists(),
                "a conflicting selector must not open a book"
            );
        }
    }
}

#[test]
fn equity_period_views_require_an_unambiguous_selector_before_opening_a_book() {
    let dir = temporary();
    let book = dir.join("absent-period-book");
    for selectors in [
        vec!["--for", ""],
        vec!["--for", "FY2026-P01", "--for", "FY2026-P02"],
        vec!["--for", "FY2026-P01", "--from", "2026-01-01"],
        vec!["--for", "FY2026-P01", "--to", "2026-01-31"],
        vec![
            "--from",
            "2026-01-01",
            "--to",
            "2026-12-31",
            "--as-originally-reported",
        ],
    ] {
        let mut args = vec!["statement", "equity-roll-forward"];
        args.extend(selectors);
        let (exit, events, stderr) = run(&book, &args);
        eprintln!(
            "equity period argv=fa --book {book:?} {args:?} --json exit={exit}\nevents={events:?}\nstderr:\n{stderr}"
        );
        assert_eq!(exit, 2, "{args:?}\n{events:?}\n{stderr}");
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(text(&events[0], "event"), "error");
        assert!(!book.exists(), "ambiguous selectors must not open a book");
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn retained_statement_certificates_bridge_and_trace_without_reselecting_head() {
    let fixture = Fixture::new();
    let income = ["statement", "income-statement", "--for", "FY2026-P03"];
    let head = || {
        data(&ok(&fixture.book, &income)[0])
            .get("known_at")
            .unwrap()
            .render()
    };
    let first = ok(&fixture.book, &[&income[..], &["--certify"][..]].concat());
    let before_oid = text(data(&first[1]), "oid").to_string();
    let before = data(&first[0]).get("known_at").unwrap().render();
    fixture.post("bridge-sale", "2026-03-14", "1000", "4000", "17.00 USD");
    let after_path = fixture.dir.join("after.cert");
    let second = ok(
        &fixture.book,
        &[
            &income[..],
            &[
                "--certify",
                "--certificate-out",
                after_path.to_str().unwrap(),
            ][..],
        ]
        .concat(),
    );
    let after_oid = text(data(&second[1]), "oid").to_string();
    let after = data(&second[0]).get("known_at").unwrap().render();
    let balance = ok(
        &fixture.book,
        &[
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--certify",
        ],
    );
    let balance_oid = format!("C:{}", text(data(&balance[1]), "oid"));
    // The certificates fix the frontiers, so a later HEAD cannot leak in.
    fixture.post("later-sale", "2026-03-20", "1000", "4000", "20.00 USD");
    let (b, a) = (format!("C:{before_oid}"), format!("C:{after_oid}"));
    let sequence = |mode: &str| {
        ok(
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
            ],
        )
    };
    let by_sequence = sequence("diff");
    let at = head();
    let bridged = ok(
        &fixture.book,
        &[
            "statement",
            "diff",
            "--before-certificate",
            &b,
            "--after-certificate",
            &a,
        ],
    );
    assert_eq!(bridged, by_sequence);
    assert_eq!(bridged[0].get("certificate"), Some(&Json::Null));
    assert_eq!(
        data(&bridged[0]).get("after_known_at").unwrap().render(),
        after
    );
    // A bare digest and the saved file name the same certificates.
    assert_eq!(
        ok(
            &fixture.book,
            &[
                "statement",
                "diff",
                "--before-certificate",
                &before_oid,
                "--after-certificate",
                after_path.to_str().unwrap(),
            ],
        ),
        by_sequence
    );
    // Stating the statement one means is checked against the certificates.
    assert_eq!(
        ok(
            &fixture.book,
            &[
                "statement",
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--for",
                "FY2026-P03",
                "--definition",
                "income-statement",
            ],
        ),
        by_sequence
    );
    assert_eq!(head(), at, "an uncertified bridge writes nothing");

    let certified = ok(
        &fixture.book,
        &[
            "statement",
            "diff",
            "--before-certificate",
            &b,
            "--after-certificate",
            &a,
            "--certify",
        ],
    );
    assert_eq!(certified.len(), 2);
    assert_eq!(data(&certified[0]), data(&by_sequence[0]));
    let diff_oid = text(data(&certified[1]), "oid").to_string();
    assert_eq!(text(&certified[0], "certificate"), diff_oid);
    let comparison =
        fa::StatementDiffCertificate::decode(&unhex(text(data(&certified[1]), "bytes"))).unwrap();
    let (old, new) = comparison.sources();
    assert_eq!(hex(&old.digest), before_oid);
    assert_eq!(hex(&new.digest), after_oid);
    assert_eq!(
        new.canonical_bytes().unwrap(),
        std::fs::read(&after_path).unwrap(),
        "the comparison keeps the exact retained source, not a re-certification"
    );
    let diff_handle = format!("C:{diff_oid}");
    assert_eq!(
        ok(&fixture.book, &["replay", &diff_handle]),
        vec![certified[0].clone()]
    );

    let trace = ok(
        &fixture.book,
        &[
            "statement",
            "trace",
            "--from-diff",
            &diff_handle,
            "--for",
            "FY2026-P03",
            "--certify",
        ],
    );
    assert_eq!(trace.len(), 2);
    assert_eq!(text(&trace[0], "event"), "statement_trace");
    assert_eq!(data(&trace[0]), data(&sequence("trace")[0]));
    let attributed =
        fa::StatementTraceCertificate::decode(&unhex(text(data(&trace[1]), "bytes"))).unwrap();
    let sources = attributed.sources();
    assert_eq!(hex(&sources.first().unwrap().digest), before_oid);
    assert_eq!(hex(&sources.last().unwrap().digest), after_oid);
    let trace_handle = format!("C:{}", text(data(&trace[1]), "oid"));
    assert_eq!(
        ok(&fixture.book, &["replay", &trace_handle]),
        vec![trace[0].clone()]
    );

    // The comparison and its trace export the library's own workpapers, to a
    // new file or inline, and exporting is a read.
    let at = head();
    let diff_path = fixture.dir.join("bridge.jsonl");
    let trace_path = fixture.dir.join("trace.jsonl");
    for (handle, path, family) in [
        (&diff_handle, &diff_path, "statement-diff"),
        (&trace_handle, &trace_path, "statement-trace"),
    ] {
        let events = ok(
            &fixture.book,
            &["replay", handle, "--workpaper-out", path.to_str().unwrap()],
        );
        let exported = events.last().unwrap();
        assert_eq!(text(exported, "event"), "workpaper_exported");
        assert_eq!(text(data(exported), "family"), family);
        let written = std::fs::read_to_string(path).unwrap();
        assert!(written.lines().count() > 1, "{family}: {written}");
        let inline = ok(&fixture.book, &["replay", handle, "--workpaper"]);
        assert_eq!(
            text(data(inline.last().unwrap()), "text"),
            written,
            "{family}: the inline text is the file's text"
        );
    }
    {
        let keys = fa::BookKeys::load(&fixture.book.join("book.keys")).unwrap();
        let book =
            fa::Book::open_dir(&fixture.book, keys, fa::Entropy::deterministic(119)).unwrap();
        let reviewer = fa_model::principal_vid("statement-reviewer");
        let capability = fa::Capability::embedded(reviewer, &["read", "produce"]).unwrap();
        let package = book
            .statement_diff_workpaper(reviewer, &capability, &comparison)
            .unwrap()
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&diff_path).unwrap(),
            package.jsonl()
        );
        let trace_jsonl = book
            .statement_trace_jsonl(reviewer, &capability, &attributed)
            .unwrap()
            .unwrap();
        assert_eq!(std::fs::read_to_string(&trace_path).unwrap(), trace_jsonl);
    }
    assert_eq!(head(), at, "workpaper exports publish nothing");
    let refused = fixture.dir.join("bridge-again.jsonl");
    std::fs::copy(&diff_path, &refused).unwrap();
    let (exit, _, _) = run(
        &fixture.book,
        &[
            "replay",
            &diff_handle,
            "--workpaper-out",
            refused.to_str().unwrap(),
        ],
    );
    assert_eq!(exit, 2, "an existing workpaper file is never replaced");

    let at = head();
    for (args, exit, needle) in [
        (
            vec!["diff", "--before-certificate", &b],
            2,
            "needs both --before-certificate and --after-certificate",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--before",
                "1",
            ],
            2,
            "--before selects a frontier",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--branch",
                "scenario:what-if",
            ],
            2,
            "--branch selects a frontier",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--compare",
                "FY2026-P02",
            ],
            2,
            "--compare names the comparative column",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--for",
                "FY2026-P02",
            ],
            8,
            "the certificates answer income-statement for FY2026-P03 with no comparative",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--for",
                "FY2026-P03",
                "--compare",
                "FY2026-P02",
            ],
            8,
            "not the statement --for/--compare/--definition name",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--definition",
                "balance-sheet",
            ],
            8,
            "the certificates answer income-statement",
        ),
        (
            vec![
                "trace",
                "--from-diff",
                &diff_handle,
                "--for",
                "FY2026-P02",
                "--certify",
            ],
            8,
            "the certificates answer income-statement for FY2026-P03",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &b,
                "--after-certificate",
                &a,
                "--max-publications",
                "2",
            ],
            2,
            "start a statement trace",
        ),
        (
            vec!["income-statement", "--before-certificate", &b],
            2,
            "not statement income-statement",
        ),
        (
            vec!["trace", "--from-diff", &diff_handle],
            2,
            "add --certify",
        ),
        (
            vec![
                "trace",
                "--from-diff",
                &diff_handle,
                "--before-certificate",
                &b,
                "--certify",
            ],
            2,
            "one saved comparison",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &a,
                "--after-certificate",
                &b,
            ],
            8,
            "ordered frontiers",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &balance_oid,
                "--after-certificate",
                &a,
            ],
            8,
            "same sequence-selected trunk statement",
        ),
        (
            vec![
                "diff",
                "--before-certificate",
                &diff_handle,
                "--after-certificate",
                &a,
            ],
            8,
            "--before-certificate",
        ),
        (
            vec!["trace", "--from-diff", &a, "--certify"],
            8,
            "--from-diff",
        ),
    ] {
        let args = [&["statement"][..], &args[..]].concat();
        let (code, events, _) = run(&fixture.book, &args);
        assert_eq!(code, exit, "{args:?}: {events:?}");
        assert_eq!(events.len(), 1, "{args:?}: {events:?}");
        assert_eq!(text(&events[0], "event"), "error");
        assert!(events[0].render().contains(needle), "{args:?}: {events:?}");
    }
    assert_eq!(head(), at, "refusals publish nothing");

    // A launch-bound reader bridges retained certificates by digest, but
    // cannot name a host file for one or certify without produce.
    let authority = fa_cli::authority::LaunchAuthority::new(
        fixture.book.clone(),
        None,
        "report-reader",
        fa_cli::authority::LaunchProfile::Agent,
        &["read"],
    )
    .unwrap();
    let bound = |args: &[&str]| {
        let argv: Vec<String> = args
            .iter()
            .chain(&["--json"])
            .map(|arg| (*arg).to_string())
            .collect();
        fa_cli::entry::fa_with_authority(&argv, fa_cli::cli::Files::default(), &authority, true)
    };
    let pair = [
        "statement",
        "diff",
        "--before-certificate",
        &b,
        "--after-certificate",
        &a,
    ];
    let (code, captured) = bound(&pair);
    assert_eq!(code, 0, "{}{}", captured.stdout, captured.stderr);
    let event = json::parse(captured.stdout.lines().next().unwrap()).unwrap();
    assert_eq!(data(&event), data(&by_sequence[0]));
    // `head()` renders the known-at sequence.
    let at_seq: i128 = at.parse().expect("known_at is an integer sequence");
    let accesses = ok(
        &fixture.book,
        &["access", "log", "--since", &at.to_string()],
    );
    assert_eq!(data(&accesses[0]).get("count"), Some(&Json::Int(1)));
    let access = &data(&accesses[0])
        .get("events")
        .and_then(Json::as_arr)
        .unwrap()[0];
    // The registry has no statement subcommands: the command is its family,
    // while the digest binds the exact diff and both retained certificates.
    assert_eq!(text(access, "command"), "statement");
    let canonical_request = [
        "statement",
        "diff",
        "--after-certificate",
        &a,
        "--before-certificate",
        &b,
        "--json",
    ]
    .map(str::to_string);
    let expected_digest = fa::access_log::request_digest(&canonical_request);
    let expected_hex = expected_digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(text(access, "request_digest"), expected_hex);
    assert_eq!(text(access, "principal_name"), "report-reader");
    assert_eq!(access.get("observed_at"), Some(&Json::Int(at_seq)));
    assert_eq!(access.get("recorded_at"), Some(&Json::Int(at_seq + 1)));
    let (code, captured) = bound(&[
        "statement",
        "diff",
        "--before-certificate",
        &b,
        "--after-certificate",
        after_path.to_str().unwrap(),
    ]);
    assert_eq!(code, 2, "{}{}", captured.stdout, captured.stderr);
    assert!(
        captured
            .stdout
            .contains("--after-certificate cannot name a host filesystem path"),
        "{}",
        captured.stdout
    );
    let (code, captured) = bound(&[&pair[..], &["--certify"][..]].concat());
    assert_eq!(code, 7, "{}{}", captured.stdout, captured.stderr);
    assert!(captured.stdout.contains("produce"), "{}", captured.stdout);
    assert_eq!(
        head(),
        (at_seq + 1).to_string(),
        "only the admitted read's AccessEvent was published"
    );
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
    let (exit, captured) =
        fa_cli::entry::fa_with_authority(&args, fa_cli::cli::Files::default(), &authority, true);
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
    let mut book =
        fa::Book::open_dir(&fixture.book, keys.clone(), fa::Entropy::deterministic(117)).unwrap();
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
        artifact
            .digest()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    drop(book);
    let output = fixture.dir.join("aging.report");
    let replay = ok(
        &fixture.book,
        &["replay", &handle, "--output", output.to_str().unwrap()],
    );
    assert_eq!(replay.len(), 2);
    assert_eq!(text(&replay[0], "event"), "aging");
    assert_eq!(text(&replay[1], "event"), "report_replayed");
    assert_eq!(text(data(&replay[1]), "family"), "effective-date-aging");
    assert_eq!(std::fs::read(output).unwrap(), artifact.output());
    // Aging has a freshness law (9f30e90): nothing in its selector was
    // recorded after the certificate, so the retained artifact is Current.
    let (exit, events, _) = run(&fixture.book, &["certificate", "status", &handle]);
    assert_eq!(exit, 0, "{events:?}");
    assert_eq!(events.len(), 1);
    assert_eq!(text(&events[0], "event"), "certificate_status");
    assert_eq!(text(data(&events[0]), "status"), "Current");
    assert_eq!(
        data(&events[0]).get("later_entries"),
        Some(&Json::Arr(Vec::new()))
    );

    let mut book =
        fa::Book::open_dir(&fixture.book, keys, fa::Entropy::deterministic(118)).unwrap();
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
    let events: Vec<_> = captured
        .stdout
        .lines()
        .map(|line| {
            fa_cli::verbs::registry().unwrap().check_line(line).unwrap();
            json::parse(line).unwrap()
        })
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(text(&events[0], "event"), "aging");
    assert_eq!(data(&events[0]), data(&replay[0]));
    assert_eq!(text(data(&events[1]), "family"), "effective-date-aging");
    assert_eq!(
        data(&events[1]).get("output_digest"),
        data(&replay[1]).get("output_digest")
    );
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

/// `fa statement lint` (plan §12.1, FA-INV-04): a definition partitions the
/// chart a statement folds, or names the leaves it does not. The built-in
/// balance sheet maps whole account types; the small-company preset maps code
/// prefixes, so a liability numbered in the cash range is mapped twice.
#[test]
fn statement_lint_reports_the_mapping_partition_of_the_chart() {
    let f = Fixture::new();
    let lint = |book: &Path, args: &[&str]| -> Json {
        let mut argv = vec!["statement", "lint"];
        argv.extend_from_slice(args);
        let events = ok(book, &argv);
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(text(&events[0], "event"), "statement_lint");
        data(&events[0]).clone()
    };
    let strings = |value: &Json, key: &str| -> Vec<String> {
        array(value, key)
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    };
    let int = |value: &Json, key: &str| match value.get(key) {
        Some(Json::Int(n)) => *n,
        other => panic!("{key}: {other:?}"),
    };

    let builtin = lint(&f.book, &["--definition", "balance-sheet"]);
    assert_eq!(builtin.get("clean"), Some(&Json::Bool(true)));
    assert_eq!(
        (
            int(&builtin, "covered_leaves"),
            int(&builtin, "mapped_leaves")
        ),
        (7, 7)
    );
    assert!(
        array(&builtin, "mappings")
            .iter()
            .any(|m| text(m, "account") == "1000" && text(m, "line") == "assets")
    );

    let preset = lint(
        &f.book,
        &["--definition", "us_gaap_small_company_balance_sheet"],
    );
    assert_eq!(preset.get("clean"), Some(&Json::Bool(true)));
    assert_eq!(int(&preset, "mapped_leaves"), 7);
    assert_eq!(
        strings(&preset, "empty_lines"),
        [
            "inventory",
            "ppe_net",
            "accounts_payable",
            "accrued_liabilities",
            "long_term_debt"
        ]
    );

    // A book whose chart numbers a liability in the cash range.
    let dir = temporary();
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Lint fixture"]);
    let created = ok(&book, &["book", "info"]);
    let before_chart = int(created[0].get("coordinate").unwrap(), "known_at").to_string();
    let chart = dir.join("chart.json");
    std::fs::write(&chart, r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1050","name":"Customer deposits","type":"Liability","unit":"USD"},{"code":"3000","name":"Capital","type":"Equity","unit":"USD"}]}"#).unwrap();
    ok(&book, &["chart", "import", chart.to_str().unwrap()]);
    let found = lint(
        &book,
        &["--definition", "us_gaap_small_company_balance_sheet"],
    );
    assert_eq!(found.get("clean"), Some(&Json::Bool(false)));
    let overlaps = array(&found, "multiply_mapped_leaves");
    assert_eq!(overlaps.len(), 1, "{found:?}");
    assert_eq!(text(&overlaps[0], "account"), "1050");
    assert_eq!(strings(&overlaps[0], "lines"), ["cash", "long_term_debt"]);
    assert_eq!(int(&found, "mapped_leaves"), 2);
    // The built-in definition still partitions this chart by type.
    let typed = lint(&book, &["--definition", "balance-sheet"]);
    assert_eq!(typed.get("clean"), Some(&Json::Bool(true)));
    // Before the chart existed, nothing was covered.
    let empty = lint(
        &book,
        &[
            "--definition",
            "us_gaap_small_company_balance_sheet",
            "--as-known-at",
            &before_chart,
        ],
    );
    assert_eq!(int(&empty, "covered_leaves"), 0);
    assert_eq!(empty.get("clean"), Some(&Json::Bool(true)));

    // An unknown definition is refused; report flags are usage errors.
    let (exit, events, _) = run(&book, &["statement", "lint", "--definition", "cash-flow"]);
    assert_eq!(exit, 3, "{events:?}");
    assert!(text(data(&events[0]), "message").contains("us_gaap_small_company_balance_sheet"));
    let (exit, _, _) = run(
        &book,
        &[
            "statement",
            "lint",
            "--definition",
            "balance-sheet",
            "--for",
            "FY2026-P03",
        ],
    );
    assert_eq!(exit, 2);
    let (exit, _, _) = run(&book, &["statement", "lint"]);
    assert_eq!(exit, 2);
}

/// Plan §12.1 presentation rounding on the CLI: `--present-in units` adds a
/// statement_presented event after the exact statement. Unclosed revenue
/// 190.60 USD and expenses 35.40 USD present as 191 and 35 (HalfEven), while
/// their difference, 155.20 USD, presents as 155: an explicit -1
/// Presentation rounding line sits right before unclosed earnings, so the
/// presented column foots. Under Floor the parts sum to the total and no
/// residual line appears. JPY (scale 0) presents unchanged.
#[test]
fn statement_presented_in_units_foots_with_an_explicit_residual_line() {
    let f = Fixture::new();
    f.post("cents-sale", "2026-03-12", "1000", "4000", "0.60 USD");
    f.post("cents-rent", "2026-03-13", "6000", "1000", "0.40 USD");
    let present = |extra: &[&str]| -> (Json, Json) {
        let mut argv = vec!["statement", "balance-sheet", "--for", "FY2026-P03"];
        argv.extend_from_slice(extra);
        let events = ok(&f.book, &argv);
        let names: Vec<&str> = events.iter().map(|e| text(e, "event")).collect();
        assert_eq!(names, ["statement", "statement_presented"], "{events:?}");
        (events[0].clone(), data(&events[1]).clone())
    };
    let block = |presented: &Json, unit: &str| -> Json {
        array(presented, "units")
            .iter()
            .find(|u| text(u, "unit") == unit)
            .unwrap_or_else(|| panic!("no {unit} block"))
            .clone()
    };
    let ints = |line: &Json| -> Vec<i128> {
        array(line, "presented")
            .iter()
            .map(|v| match v {
                Json::Int(n) => *n,
                other => panic!("{other:?}"),
            })
            .collect()
    };
    let int = |value: &Json, key: &str| match value.get(key) {
        Some(Json::Int(n)) => *n,
        other => panic!("{key}: {other:?}"),
    };

    let (exact, presented) = present(&["--present-in", "units"]);
    assert_eq!(text(&presented, "present_in"), "units");
    assert_eq!(text(&presented, "rounding_law"), "HalfEven");
    assert_eq!(text(&presented, "definition"), "balance-sheet");
    let usd = block(&presented, "USD");
    assert_eq!(int(&usd, "divisor"), 100);
    let lines = array(&usd, "lines");
    let at = |code: &str| {
        lines
            .iter()
            .position(|l| text(l, "code") == code)
            .unwrap_or_else(|| panic!("no line {code}"))
    };
    let revenue = &lines[at("unclosed_revenue")];
    let expense = &lines[at("unclosed_expense")];
    let earnings = at("unclosed_earnings");
    let residual = at("unclosed_earnings_presentation_rounding");
    assert_eq!(ints(revenue), [191]);
    assert_eq!(ints(expense), [35]);
    assert_eq!(ints(&lines[earnings]), [155]);
    assert_eq!(
        residual + 1,
        earnings,
        "the residual line precedes its total"
    );
    assert_eq!(lines[residual].get("residual"), Some(&Json::Bool(true)));
    assert_eq!(ints(&lines[residual]), [-1]);
    assert_eq!(
        ints(revenue)[0] - ints(expense)[0] + ints(&lines[residual])[0],
        ints(&lines[earnings])[0],
        "the presented column foots"
    );
    assert_eq!(
        array(revenue, "rounding_error")[0].as_str(),
        Some("0.40 USD"),
        "191 presented against 190.60 exact"
    );
    assert!(
        lines
            .iter()
            .filter(|l| l.get("residual") == Some(&Json::Bool(true)))
            .count()
            == 1,
        "only the one total whose parts disagree gets a residual line"
    );
    let jpy = block(&presented, "JPY");
    assert_eq!(int(&jpy, "divisor"), 1);
    assert!(
        array(&jpy, "lines")
            .iter()
            .all(|l| l.get("residual") == Some(&Json::Bool(false)))
    );
    // The exact statement is the same with or without the presentation.
    let plain = ok(
        &f.book,
        &["statement", "balance-sheet", "--for", "FY2026-P03"],
    );
    assert_eq!(plain.len(), 1, "no presentation unless asked: {plain:?}");
    assert_eq!(data(&plain[0]), data(&exact));

    // Floor presents 190 and 35, whose difference is the presented 155.
    let (_, floor) = present(&["--present-in", "units", "--rounding", "Floor"]);
    assert_eq!(text(&floor, "rounding_law"), "Floor");
    assert!(
        array(&block(&floor, "USD"), "lines")
            .iter()
            .all(|l| l.get("residual") == Some(&Json::Bool(false)))
    );

    // Planted refusals publish nothing: usage, exit 2.
    for planted in [
        vec!["--rounding", "Floor"],
        vec!["--present-in", "dozens"],
        vec!["--present-in", "units", "--rounding", "Sideways"],
        vec!["--present-in", "units", "--render", "md"],
    ] {
        let mut argv = vec!["statement", "balance-sheet", "--for", "FY2026-P03"];
        argv.extend_from_slice(&planted);
        let (code, events, _) = run(&f.book, &argv);
        assert_eq!(code, 2, "{planted:?}: {events:?}");
        assert_eq!(events.len(), 1, "{planted:?}: {events:?}");
        assert_eq!(text(&events[0], "event"), "error");
    }
}

/// fa-doa9: the FFIEC 041 RC/RI and FR Y-9C HC schedules partition the
/// shipped us-bank-call-report chart. `fa statement lint` maps every covered
/// leaf to exactly one schedule line, including the leaves the earlier
/// two-digit convention misplaced:
/// - noninterest-bearing balances (1110) are RCON0081, not RCON0071;
/// - the allowance (1430) is RCON3123, subtracted, not added to loans;
/// - federal funds purchased (2210) are other liabilities, not deposits;
/// - common stock (3200) and surplus (3300) land on their lines;
/// - interest on balances due (4140) and realized AFS gains (4620) have
///   their own RI lines.
///
/// Planted negative: a revenue leaf the RI schedule has no line for (4630) is
/// reported unmapped, and the lint is not clean.
#[test]
fn call_report_schedules_partition_the_bank_template() {
    let dir = temporary();
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Call report"]);
    ok(
        &book,
        &["chart", "import", "--template", "us-bank-call-report"],
    );
    let lint = |book: &Path, definition: &str| -> Json {
        let events = ok(book, &["statement", "lint", "--definition", definition]);
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(text(&events[0], "event"), "statement_lint");
        data(&events[0]).clone()
    };
    let count = |value: &Json, key: &str| match value.get(key) {
        Some(Json::Int(n)) => *n,
        other => panic!("{key}: {other:?}"),
    };
    let line_of = |value: &Json, account: &str| -> String {
        array(value, "mappings")
            .iter()
            .find(|m| text(m, "account") == account)
            .map(|m| text(m, "line").to_string())
            .unwrap_or_default()
    };
    for (definition, expected) in [
        (
            "ffiec_041_schedule_rc_2026q1",
            &[
                ("1110", "RCON0081"),
                ("1120", "RCON0071"),
                ("1220", "RCON1773"),
                ("1410", "RCON2122"),
                ("1430", "RCON3123"),
                ("1310", "RCON2145"),
                ("2110", "RCON2200"),
                ("2210", "RCON2930"),
                ("2400", "RCON3190"),
                ("3200", "RCON3230"),
                ("3300", "RCON3839"),
                ("3400", "RCON3632"),
            ][..],
        ),
        (
            "fr_y9c_schedule_hc_2026q1",
            &[("1110", "BHCK0081"), ("2210", "BHCK2930")][..],
        ),
        (
            "ffiec_041_schedule_ri_2026q1",
            &[
                ("4110", "RIAD4010"),
                ("4140", "RIAD4115"),
                ("4150", "RIAD4065"),
                ("4170", "RIAD4020"),
                ("4520", "RIAD4079"),
                ("4610", "RIAD3521"),
                ("4620", "RIAD3196"),
                ("5220", "RIAD4180"),
                ("5240", "RIAD4200"),
                ("5400", "RIADJJ33"),
                ("5710", "RIAD4093"),
                ("5900", "RIAD4302"),
            ][..],
        ),
    ] {
        let report = lint(&book, definition);
        assert_eq!(
            report.get("clean"),
            Some(&Json::Bool(true)),
            "{definition}: {report:?}"
        );
        assert!(count(&report, "covered_leaves") > 0, "{definition}");
        assert_eq!(
            count(&report, "mapped_leaves"),
            count(&report, "covered_leaves"),
            "{definition}"
        );
        for (account, line) in expected {
            assert_eq!(line_of(&report, account), *line, "{definition}: {account}");
        }
    }

    // Planted: a revenue leaf the RI schedule has no line for.
    let extra = dir.join("extra.json");
    std::fs::write(
        &extra,
        r#"{"code":"4630","name":"Unrealized gains on equity securities","type":"Revenue","unit":"USD"}"#,
    )
    .unwrap();
    ok(
        &book,
        &[
            "chart",
            "open",
            extra.to_str().unwrap(),
            "--opened",
            "2026-01-01",
        ],
    );
    let report = lint(&book, "ffiec_041_schedule_ri_2026q1");
    assert_eq!(report.get("clean"), Some(&Json::Bool(false)), "{report:?}");
    let unmapped: Vec<&str> = array(&report, "unmapped_leaves")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(unmapped, ["4630"], "{report:?}");
}

/// fa-doa9: `fa statement regulatory` evaluates the FFIEC 041 RC and RI
/// schedules over a bank book built on the us-bank-call-report template,
/// certifies them, replays them byte for byte and reports later relevant
/// entries. Every amount below is hand-computed from the six entries:
/// - capital 1,000.00 into 1110;
/// - deposits 5,000.00 into 1120;
/// - a 4,000.00 loan out of 1120;
/// - a 40.00 provision into the allowance;
/// - 120.00 loan interest received;
/// - 30.00 deposit interest paid.
///
/// Planted negatives: a quarter without its own instructions and an
/// unregistered form are refused naming the registered schedules; a covered
/// revenue leaf the RI schedule has no line for refuses the schedule.
#[test]
fn call_report_rc_ri_certified() {
    let dir = temporary();
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Call report bank"]);
    ok(
        &book,
        &["chart", "import", "--template", "us-bank-call-report"],
    );
    ok(&book, &["period", "create", "--fiscal-year", "2026"]);
    for period in ["FY2026-P01", "FY2026-P02", "FY2026-P03", "FY2026-P04"] {
        ok(&book, &["period", "open", period]);
    }
    let source = dir.join("source.txt");
    std::fs::write(&source, b"Call report test source: bank ledger entries").unwrap();
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
    let evidence = text(data(&doc[0]), "oid").to_string();
    let post = |key: &str, day: &str, debit: &str, credit: &str, amount: &str| {
        let path = dir.join(format!("{key}.json"));
        std::fs::write(&path, format!(r#"{{"idempotency_key":"{key}","effective_date":"{day}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount}"}},{{"side":"credit","account":"{credit}","amount":"{amount}"}}]}}"#)).unwrap();
        ok(
            &book,
            &[
                "post",
                "--intent",
                path.to_str().unwrap(),
                "--evidence",
                &evidence,
            ],
        );
    };
    for (key, day, debit, credit, amount) in [
        ("capital", "2026-01-05", "1110", "3200", "1000.00 USD"),
        ("deposits", "2026-01-10", "1120", "2120", "5000.00 USD"),
        ("loan", "2026-02-01", "1420", "1120", "4000.00 USD"),
        ("provision", "2026-02-28", "5400", "1430", "40.00 USD"),
        (
            "interest-income",
            "2026-03-31",
            "1120",
            "4110",
            "120.00 USD",
        ),
        (
            "interest-expense",
            "2026-03-31",
            "5210",
            "1120",
            "30.00 USD",
        ),
    ] {
        post(key, day, debit, credit, amount);
    }
    let usd = |amount: &str| vec![Json::Str(format!("{amount} USD"))];
    let regulatory = |schedule: &str, periods: &[&str], certify: bool| -> Vec<Json> {
        let mut args = vec![
            "statement",
            "regulatory",
            "--form",
            "041",
            "--schedule",
            schedule,
            "--quarter",
            "2026Q1",
        ];
        for period in periods {
            args.extend(["--for", period]);
        }
        if certify {
            args.push("--certify");
        }
        ok(&book, &args)
    };

    // RC, stock through March 31, uncertified.
    let rc = regulatory("RC", &["FY2026-P03"], false);
    assert_eq!(rc.len(), 2, "{rc:?}");
    assert_eq!(text(&rc[0], "event"), "statement");
    assert_eq!(rc[0].get("certificate"), Some(&Json::Null));
    let statement = data(&rc[0]);
    assert_eq!(text(statement, "name"), "ffiec_041_schedule_rc_2026q1");
    assert_eq!(text(&array(statement, "columns")[0], "mode"), "stock");
    for (code, amount) in [
        ("RCON0081", "1000.00"),
        ("RCON0071", "1090.00"),
        ("RCON2122", "4000.00"),
        ("RCON3123", "40.00"),
        ("RCONB529", "3960.00"),
        ("RCON2170", "6050.00"),
        ("RCON2200", "5000.00"),
        ("RCON2948", "5000.00"),
        ("RCON3230", "1000.00"),
        ("RCON3632", "50.00"),
        ("RCON3210", "1050.00"),
        ("RCON3300", "6050.00"),
        ("rc_balance_check", "0.00"),
    ] {
        assert_eq!(line(statement, code, "USD"), usd(amount), "{code}");
    }
    assert_eq!(text(&rc[1], "event"), "regulatory_schedule");
    let schedule = data(&rc[1]);
    assert_eq!(text(schedule, "form"), "FFIEC041");
    assert_eq!(text(schedule, "schedule"), "RC");
    assert_eq!(text(schedule, "instruction_version"), "FFIEC-041-2026Q1");
    assert_eq!(text(schedule, "edit_selector"), "FFIEC041:RC@2026Q1");
    assert_eq!(schedule.get("edit_ids_published"), Some(&Json::Bool(false)));
    assert_eq!(
        schedule.get("instrument_inputs_read"),
        Some(&Json::Bool(false))
    );
    assert_eq!(array(schedule, "declared_inputs").len(), 2);
    assert_eq!(schedule.get("validity_failed"), Some(&Json::Int(0)));
    assert_eq!(schedule.get("quality_failed"), Some(&Json::Int(0)));
    let rows = array(schedule, "edit_rows");
    let quality = rows
        .iter()
        .find(|row| text(row, "edit_id") == "FFIEC041-RC-Q001" && text(row, "unit") == "USD")
        .unwrap_or_else(|| panic!("the loans-versus-allowance quality edit: {rows:?}"));
    assert_eq!(text(quality, "lhs"), "4000.00 USD");
    assert_eq!(text(quality, "rhs"), "40.00 USD");
    assert_eq!(text(quality, "delta"), "3960.00 USD");
    assert_eq!(quality.get("passed"), Some(&Json::Bool(true)));

    // Certified RC: the same two events, then the certificate; replay
    // re-runs both byte for byte.
    let certified = regulatory("RC", &["FY2026-P03"], true);
    assert_eq!(certified.len(), 3, "{certified:?}");
    assert_eq!(text(&certified[2], "event"), "report_certificate");
    let rc_oid = text(data(&certified[2]), "oid").to_string();
    assert_eq!(text(&certified[0], "certificate"), rc_oid);
    assert_eq!(data(&certified[0]), data(&rc[0]));
    assert_eq!(data(&certified[1]), data(&rc[1]));
    let rc_handle = format!("C:{rc_oid}");
    assert_eq!(
        ok(&book, &["replay", &rc_handle]),
        certified[..2].to_vec(),
        "replay prints the certified schedule byte for byte"
    );

    // RI, year to date: the activity of every --for period.
    let ri = regulatory("RI", &["FY2026-P01", "FY2026-P02", "FY2026-P03"], true);
    assert_eq!(ri.len(), 3, "{ri:?}");
    let income = data(&ri[0]);
    assert_eq!(text(income, "name"), "ffiec_041_schedule_ri_2026q1");
    let column = &array(income, "columns")[0];
    assert_eq!(text(column, "mode"), "activity");
    assert_eq!(array(column, "periods").len(), 3);
    for (code, amount) in [
        ("RIAD4010", "120.00"),
        ("RIAD4107", "120.00"),
        ("RIAD4170", "30.00"),
        ("RIAD4073", "30.00"),
        ("RIAD4074", "90.00"),
        ("RIADJJ33", "40.00"),
        ("RIAD4301", "50.00"),
        ("RIAD4302", "0.00"),
        ("RIAD4340", "50.00"),
    ] {
        assert_eq!(line(income, code, "USD"), usd(amount), "{code}");
    }
    // RI's net income is RC's unclosed earnings at the same frontier.
    assert_eq!(
        line(income, "RIAD4340", "USD"),
        line(statement, "RCON3632", "USD")
    );
    assert_eq!(data(&ri[1]).get("validity_failed"), Some(&Json::Int(0)));
    let ri_oid = text(data(&ri[2]), "oid").to_string();
    let ri_handle = format!("C:{ri_oid}");
    assert_eq!(ok(&book, &["replay", &ri_handle]), ri[..2].to_vec());

    // Status: an April entry is outside both; a March deposit changes RC
    // (stock) but not RI; backdated March interest changes both.
    let status = |handle: &str| -> String {
        let events = ok(&book, &["certificate", "status", handle]);
        text(data(&events[0]), "status").to_string()
    };
    assert_eq!(status(&rc_handle), "Current");
    assert_eq!(status(&ri_handle), "Current");
    post("april-deposit", "2026-04-02", "1110", "2110", "10.00 USD");
    assert_eq!(status(&rc_handle), "Current");
    assert_eq!(status(&ri_handle), "Current");
    post("march-deposit", "2026-03-15", "1110", "2110", "25.00 USD");
    assert_eq!(status(&rc_handle), "SupersededBy");
    assert_eq!(status(&ri_handle), "Current");
    post("march-interest", "2026-03-20", "1120", "4110", "5.00 USD");
    assert_eq!(status(&ri_handle), "SupersededBy");
    // Later entries never change a retained schedule's replay.
    assert_eq!(ok(&book, &["replay", &rc_handle]), certified[..2].to_vec());
    assert_eq!(ok(&book, &["replay", &ri_handle]), ri[..2].to_vec());

    // Planted: no quarter borrows another's instructions, and an
    // unregistered form is not guessed.
    for (form, quarter, needle) in [
        (
            "041",
            "2026Q3",
            "no 041 schedule RC is registered for 2026Q3",
        ),
        ("031", "2026Q1", "unknown regulatory form `031`"),
    ] {
        let (exit, events, _) = run(
            &book,
            &[
                "statement",
                "regulatory",
                "--form",
                form,
                "--schedule",
                "RC",
                "--quarter",
                quarter,
                "--for",
                "FY2026-P03",
            ],
        );
        assert_eq!(exit, 3, "{form} {quarter}: {events:?}");
        assert_eq!(events.len(), 1, "{events:?}");
        let error = data(&events[0]);
        assert!(text(error, "message").contains(needle), "{error:?}");
        assert!(
            text(error, "fix").contains("--form 041 --schedule RC --quarter 2026Q1"),
            "{error:?}"
        );
    }
    // Planted: a covered revenue leaf no RI line maps refuses the schedule.
    let extra = dir.join("extra.json");
    std::fs::write(
        &extra,
        r#"{"code":"4630","name":"Unrealized gains on equity securities","type":"Revenue","unit":"USD"}"#,
    )
    .unwrap();
    ok(
        &book,
        &[
            "chart",
            "open",
            extra.to_str().unwrap(),
            "--opened",
            "2026-01-01",
        ],
    );
    let (exit, events, _) = run(
        &book,
        &[
            "statement",
            "regulatory",
            "--form",
            "041",
            "--schedule",
            "RI",
            "--quarter",
            "2026Q1",
            "--for",
            "FY2026-P03",
        ],
    );
    assert_eq!(exit, 3, "{events:?}");
    assert!(
        text(data(&events[0]), "message").contains("4630"),
        "{events:?}"
    );
}

/// fa-doa9: the edits come from registries/regulatory_edits/, and `--edit`
/// runs only the registered edits it names. Planted: an edit id the
/// registry does not hold is refused (exit 3), naming the registered ids,
/// and `--edit` with `--certify` is a usage error, because a certified
/// schedule's replay runs every edit.
#[test]
fn call_report_edits_select_by_registered_id() {
    let dir = temporary();
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Call report edits"]);
    ok(
        &book,
        &["chart", "import", "--template", "us-bank-call-report"],
    );
    ok(&book, &["period", "create", "--fiscal-year", "2026"]);
    let rc = |extra: &[&str]| {
        let mut args = vec![
            "statement",
            "regulatory",
            "--form",
            "041",
            "--schedule",
            "RC",
            "--quarter",
            "2026Q1",
            "--for",
            "FY2026-P03",
        ];
        args.extend_from_slice(extra);
        run(&book, &args)
    };

    let (exit, all, _) = rc(&[]);
    assert_eq!(exit, 0, "{all:?}");
    let every = data(&all[1]);
    assert_eq!(text(every, "edit_selector"), "FFIEC041:RC@2026Q1");
    assert_eq!(every.get("edit_ids_published"), Some(&Json::Bool(false)));
    let ids = |schedule: &Json| -> Vec<String> {
        let mut ids: Vec<String> = array(schedule, "edit_rows")
            .iter()
            .map(|row| text(row, "edit_id").to_string())
            .collect();
        ids.dedup();
        ids
    };
    assert_eq!(
        ids(every),
        [
            "FFIEC041-RC-V001",
            "FFIEC041-RC-V002",
            "FFIEC041-RC-V003",
            "FFIEC041-RC-Q001"
        ]
    );

    let (exit, one, _) = rc(&["--edit", "FFIEC041-RC-Q001"]);
    assert_eq!(exit, 0, "{one:?}");
    let selected = data(&one[1]);
    assert_eq!(ids(selected), ["FFIEC041-RC-Q001"]);
    assert_eq!(selected.get("validity_passed"), Some(&Json::Int(0)));

    let (exit, refused, _) = rc(&["--edit", "FFIEC041-RC-V999"]);
    assert_eq!(exit, 3, "{refused:?}");
    let error = data(&refused[0]);
    assert!(
        text(error, "message")
            .contains("edit `FFIEC041-RC-V999` is not registered for FFIEC041:RC@2026Q1"),
        "{error:?}"
    );
    assert!(text(error, "fix").contains("FFIEC041-RC-Q001"), "{error:?}");

    let (exit, usage, _) = rc(&["--edit", "FFIEC041-RC-Q001", "--certify"]);
    assert_eq!(exit, 2, "{usage:?}");
}
