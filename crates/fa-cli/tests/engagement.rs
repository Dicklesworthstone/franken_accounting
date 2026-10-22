//! Real-binary audit engagements (fa-zgn, plan §11.12): an engagement with
//! stated materiality parameters, proposed adjustments that never post, a
//! proposal booked by the committed entry that makes its correction, a
//! proposal passed with a registered reason, exact retries, and a refusal
//! for every planted negative, each journaling nothing.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

fn data(value: &Json) -> &Json {
    value.get("data").expect("robot data")
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("missing string {key}: {}", value.render()))
}

fn int(value: &Json, key: &str) -> i128 {
    match value.get(key) {
        Some(Json::Int(n)) => *n,
        _ => panic!("missing integer {key}: {}", value.render()),
    }
}

fn rows<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    value
        .get(key)
        .and_then(Json::as_arr)
        .unwrap_or_else(|| panic!("missing array {key}: {}", value.render()))
}

fn run(dir: &Path, args: &[&str]) -> (i32, Json) {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .current_dir(dir)
        .args(["--book", "book"])
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .output()
        .expect("run fa");
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{args:?}: {stdout}\n{stderr}");
    let checked = fa_cli::verbs::registry()
        .expect("registry")
        .check_line(lines[0]);
    assert!(checked.is_ok(), "{args:?}: {checked:?}\n{stdout}\n{stderr}");
    (
        output.status.code().expect("exit code"),
        json::parse(lines[0]).expect("robot line"),
    )
}

struct Fixture {
    dir: PathBuf,
    evidence: String,
}

impl Fixture {
    /// A book with Cash, Accrued liabilities, Revenue and an Expenses
    /// summary with one leaf, March and April open, and one cited receipt.
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let dir = std::env::temp_dir().join(format!(
                "fa-engagement-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&dir) {
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                created => {
                    created.expect("create the fixture directory");
                    break dir;
                }
            }
        };
        let mut f = Self {
            dir,
            evidence: String::new(),
        };
        f.ok(&["book", "create", "--name", "Engagement Co"]);
        f.write(
            "chart.json",
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"2100","name":"Accrued liabilities","type":"Liability","leaf":true,"unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","leaf":true,"unit":"USD"},{"code":"6","name":"Expenses","type":"Expense","leaf":false,"unit":"USD"},{"code":"6000","name":"Professional fees","type":"Expense","leaf":true,"unit":"USD","parent":"6"}]}"#,
        );
        f.ok(&["chart", "import", "chart.json"]);
        f.ok(&["period", "create", "--fiscal-year", "2026"]);
        f.ok(&["period", "open", "FY2026-P03"]);
        f.ok(&["period", "open", "FY2026-P04"]);
        f.write("receipt.txt", "Receipts for March");
        let document = f.ok(&[
            "document",
            "add",
            "receipt.txt",
            "--kind",
            "Receipt",
            "--grade",
            "HumanUpload",
        ]);
        f.evidence = text(data(&document), "oid").to_string();
        f
    }

    fn write(&self, name: &str, body: &str) {
        std::fs::write(self.dir.join(name), body).expect("write fixture file");
    }

    fn run(&self, args: &[&str]) -> (i32, Json) {
        run(&self.dir, args)
    }

    fn ok(&self, args: &[&str]) -> Json {
        let (status, output) = self.run(args);
        assert_eq!(status, 0, "{args:?}: {}", output.render());
        output
    }

    /// Refused with `exit` and `refusal_id`, and nothing journaled but the
    /// AccessEvent a read-only Human session's command records before it
    /// observes the book, refused or not (fa-7dw).
    fn refused(&self, args: &[&str], exit: i32, id: &str) -> Json {
        let before = self.head();
        let (status, output) = self.run(args);
        assert_eq!(status, exit, "{args:?}: {}", output.render());
        assert_eq!(text(data(&output), "refusal_id"), id, "{}", output.render());
        assert_eq!(
            self.head(),
            before + self.access_events_since(before),
            "{args:?} journaled nothing but its AccessEvent"
        );
        output
    }

    /// AccessEvents recorded after `since` (fa-7dw).
    fn access_events_since(&self, since: i128) -> i128 {
        int(
            data(&self.ok(&["access", "log", "--since", &since.to_string()])),
            "count",
        )
    }

    fn head(&self) -> i128 {
        int(
            self.ok(&["book", "info"])
                .get("coordinate")
                .expect("coordinate"),
            "known_at",
        )
    }

    /// Post a balanced two-leg entry; its vid.
    fn post(&self, key: &str, date: &str, debit: &str, credit: &str, amount: &str) -> String {
        let name = format!("{key}.json");
        self.write(
            &name,
            &format!(
                r#"{{"idempotency_key":"{key}","effective_date":"{date}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount} USD"}},{{"side":"credit","account":"{credit}","amount":"{amount} USD"}}]}}"#
            ),
        );
        let posted = self.ok(&["post", "--intent", &name, "--evidence", &self.evidence]);
        text(data(&posted), "vid").to_string()
    }

    /// Write a proposal intent: a draft correcting entry.
    fn intent(&self, name: &str, date: &str, legs: &[(&str, &str, &str)]) {
        let legs: Vec<String> = legs
            .iter()
            .map(|(side, account, amount)| {
                format!(r#"{{"side":"{side}","account":"{account}","amount":"{amount} USD"}}"#)
            })
            .collect();
        self.write(
            name,
            &format!(
                r#"{{"effective_date":"{date}","description":"Unrecorded March fees","legs":[{}]}}"#,
                legs.join(",")
            ),
        );
    }

    fn tb(&self) -> Json {
        data(&self.ok(&["tb", "--period", "FY2026-P03"]))
            .get("rows")
            .expect("rows")
            .clone()
    }
}

const OPEN: &[&str] = &[
    "engagement",
    "open",
    "FY26-audit",
    "--kind",
    "audit",
    "--period",
    "FY2026-P03",
    "--period",
    "FY2026-P04",
    "--overall",
    "500.00 USD",
    "--performance",
    "375.00 USD",
    "--clearly-trivial",
    "25.00 USD",
];

#[test]
fn an_engagement_proposes_books_and_passes_adjustments_and_posts_nothing_itself() {
    let f = Fixture::new();
    f.post("sale", "2026-03-10", "1000", "4000", "900.00");
    let tb_before = f.tb();

    // Open: the stated parameters, journaled once; the identical retry
    // records nothing.
    let opened = f.ok(OPEN);
    assert_eq!(text(&opened, "event"), "engagement_opened");
    let summary = data(&opened).get("engagement").unwrap();
    assert_eq!(text(summary, "kind"), "audit");
    assert_eq!(text(summary, "overall"), "500.00 USD");
    assert_eq!(text(summary, "performance"), "375.00 USD");
    assert_eq!(text(summary, "clearly_trivial"), "25.00 USD");
    assert_eq!(
        rows(summary, "scope_periods"),
        &[json::s("FY2026-P03"), json::s("FY2026-P04")]
    );
    assert_eq!(int(summary, "next_proposal"), 1);
    let head = f.head();
    let again = f.ok(OPEN);
    assert_eq!(
        data(&again).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(f.head(), head, "an exact retry journals nothing");

    // Propose two corrections; neither posts.
    f.intent(
        "fees.json",
        "2026-03-31",
        &[("debit", "6000", "40.00"), ("credit", "2100", "40.00")],
    );
    let first = f.ok(&[
        "adjustment",
        "propose",
        "--engagement",
        "FY26-audit",
        "--intent",
        "fees.json",
    ]);
    let proposal = data(&first).get("proposal").unwrap();
    assert_eq!(text(&first, "event"), "adjustment_proposed");
    assert_eq!(int(proposal, "number"), 1);
    assert_eq!(text(proposal, "state"), "proposed");
    assert_eq!(proposal.get("decision"), Some(&Json::Null));
    assert_eq!(rows(proposal, "legs").len(), 2);
    assert_eq!(text(&rows(proposal, "legs")[0], "account"), "6000");
    let head = f.head();
    let retry = f.ok(&[
        "adjustment",
        "propose",
        "--engagement",
        "FY26-audit",
        "--intent",
        "fees.json",
    ]);
    assert_eq!(
        data(&retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(int(data(&retry).get("proposal").unwrap(), "number"), 1);
    assert_eq!(f.head(), head);
    f.intent(
        "rounding.json",
        "2026-04-02",
        &[("debit", "6000", "10.00"), ("credit", "2100", "10.00")],
    );
    let second = f.ok(&[
        "adjustment",
        "propose",
        "--engagement",
        "FY26-audit",
        "--intent",
        "rounding.json",
        "--key",
        "rounding",
    ]);
    assert_eq!(int(data(&second).get("proposal").unwrap(), "number"), 2);
    assert_eq!(f.tb(), tb_before, "a proposal never posts");

    // Planted negatives: each refused, nothing journaled.
    f.intent(
        "unbalanced.json",
        "2026-03-31",
        &[("debit", "6000", "40.00"), ("credit", "2100", "39.00")],
    );
    f.intent(
        "out-of-scope.json",
        "2026-05-15",
        &[("debit", "6000", "40.00"), ("credit", "2100", "40.00")],
    );
    f.intent(
        "summary.json",
        "2026-03-31",
        &[("debit", "6", "40.00"), ("credit", "2100", "40.00")],
    );
    for (intent, exit, id) in [
        ("unbalanced.json", 2, "FA-REF-100"),
        ("out-of-scope.json", 3, "FA-REF-183"),
        ("summary.json", 3, "FA-REF-002"),
    ] {
        f.refused(
            &[
                "adjustment",
                "propose",
                "--engagement",
                "FY26-audit",
                "--intent",
                intent,
                "--key",
                intent,
            ],
            exit,
            id,
        );
    }
    f.refused(
        &[
            "adjustment",
            "propose",
            "--engagement",
            "no-such-engagement",
            "--intent",
            "fees.json",
        ],
        3,
        "FA-REF-180",
    );
    let mut wrong_params = OPEN.to_vec();
    wrong_params[2] = "FY26-review";
    assert_eq!(wrong_params[11], "--performance");
    wrong_params[12] = "600.00 USD";
    let before = f.head();
    let (exit, error) = f.run(&wrong_params);
    assert_eq!(exit, 2, "performance above overall is a usage error");
    assert_eq!(text(data(&error), "class"), "usage", "{}", error.render());
    assert!(
        text(data(&error), "message").contains("clearly trivial <= performance <= overall"),
        "{}",
        error.render()
    );
    assert_eq!(f.head(), before);
    let mut unknown_period = OPEN.to_vec();
    unknown_period[2] = "FY99-audit";
    assert_eq!(unknown_period[5], "--period");
    unknown_period[6] = "FY2099-P01";
    f.refused(&unknown_period, 7, "FA-REF-021");

    // A third proposal with proposal 1's legs, before any correction posts.
    f.intent(
        "fees-again.json",
        "2026-03-30",
        &[("debit", "6000", "40.00"), ("credit", "2100", "40.00")],
    );
    let third = f.ok(&[
        "adjustment",
        "propose",
        "--engagement",
        "FY26-audit",
        "--intent",
        "fees-again.json",
    ]);
    assert_eq!(int(data(&third).get("proposal").unwrap(), "number"), 3);

    // The client books proposal 1 with its own posting; the booking names
    // that committed entry, whose legs equal the proposal's.
    let correction = f.post("fees-correction", "2026-03-31", "6000", "2100", "40.00");
    let booked = f.ok(&[
        "adjustment",
        "book",
        "--engagement",
        "FY26-audit",
        "--proposal",
        "1",
        "--entry",
        &format!("E:{correction}"),
    ]);
    assert_eq!(text(&booked, "event"), "adjustment_decided");
    let proposal = data(&booked).get("proposal").unwrap();
    assert_eq!(text(proposal, "state"), "booked");
    let decision = proposal.get("decision").unwrap();
    assert_eq!(text(decision, "kind"), "book");
    assert_eq!(text(decision, "entry"), correction);
    assert_eq!(decision.get("superseded_by"), Some(&Json::Null));
    // That entry does not make proposal 2's correction.
    f.refused(
        &[
            "adjustment",
            "book",
            "--engagement",
            "FY26-audit",
            "--proposal",
            "2",
            "--entry",
            &format!("E:{correction}"),
        ],
        3,
        "FA-REF-182",
    );

    // Proposal 2 is passed with a registered reason; a decided proposal is
    // never decided again, and an unregistered reason is a usage error.
    let passed = f.ok(&[
        "adjustment",
        "pass",
        "--engagement",
        "FY26-audit",
        "--proposal",
        "2",
        "--reason",
        "ClearlyTrivial",
    ]);
    let decision = data(&passed)
        .get("proposal")
        .unwrap()
        .get("decision")
        .unwrap();
    assert_eq!(text(decision, "kind"), "pass");
    assert_eq!(text(decision, "reason"), "ClearlyTrivial");
    f.refused(
        &[
            "adjustment",
            "pass",
            "--engagement",
            "FY26-audit",
            "--proposal",
            "1",
            "--reason",
            "Other",
            "--key",
            "second-decision",
        ],
        3,
        "FA-REF-181",
    );
    f.refused(
        &[
            "adjustment",
            "pass",
            "--engagement",
            "FY26-audit",
            "--proposal",
            "9",
            "--reason",
            "Other",
        ],
        3,
        "FA-REF-184",
    );
    let before = f.head();
    let (exit, error) = f.run(&[
        "adjustment",
        "pass",
        "--engagement",
        "FY26-audit",
        "--proposal",
        "2",
        "--reason",
        "Immaterial",
    ]);
    assert_eq!(exit, 2, "an unregistered reason is a usage error");
    assert_eq!(text(data(&error), "class"), "usage", "{}", error.render());
    assert!(
        text(data(&error), "message")
            .contains("`Immaterial` is not a registered adjustment_pass reason"),
        "{}",
        error.render()
    );
    assert_eq!(f.head(), before);

    // One committed entry makes one correction: the third proposal, with
    // the same legs and recorded before the correction, cannot be booked by
    // the entry that booked proposal 1.
    let refusal = f.refused(
        &[
            "adjustment",
            "book",
            "--engagement",
            "FY26-audit",
            "--proposal",
            "3",
            "--entry",
            &format!("E:{correction}"),
        ],
        3,
        "FA-REF-182",
    );
    assert!(
        text(data(&refusal), "message").contains("already books proposal 1"),
        "{}",
        refusal.render()
    );

    // The summary of uncorrected misstatements holds the passed proposal
    // only: had it been booked, income 10.00 lower and accrued liabilities
    // 10.00 higher, within every stated parameter.
    let sud = f.ok(&["engagement", "sud", "FY26-audit"]);
    let sud = data(&sud);
    let items = rows(sud, "items");
    assert_eq!(items.len(), 1, "{}", sud.render());
    assert_eq!(int(&items[0], "number"), 2);
    assert_eq!(text(&items[0], "reason"), "ClearlyTrivial");
    let effect = items[0].get("effect").unwrap();
    assert_eq!(text(effect, "income"), "-10.00 USD");
    assert_eq!(text(effect, "liabilities"), "10.00 USD");
    assert_eq!(text(effect, "assets"), "0.00 USD");
    assert_eq!(items[0].get("clearly_trivial"), Some(&Json::Bool(true)));
    assert_eq!(text(sud, "rollover_income"), "-10.00 USD");
    assert_eq!(
        text(sud.get("iron_curtain").unwrap(), "liabilities"),
        "10.00 USD"
    );
    assert_eq!(sud.get("exceeds_performance"), Some(&Json::Bool(false)));
    assert_eq!(sud.get("exceeds_overall"), Some(&Json::Bool(false)));
    assert_eq!(
        sud.get("prior_period_carry_forward"),
        Some(&Json::Bool(false))
    );
    // Per statement line: the passed accrual (Dr 6000 fees, Cr 2100 accrued
    // liabilities, 10.00) under each line's own sign, formula lines as the
    // statement computes them.
    let lines = |statement: &Json| -> Vec<(String, String)> {
        rows(statement, "lines")
            .iter()
            .map(|line| {
                (
                    text(line, "code").to_string(),
                    text(line, "amount").to_string(),
                )
            })
            .collect()
    };
    let pairs = |expected: &[(&str, &str)]| -> Vec<(String, String)> {
        expected
            .iter()
            .map(|(code, amount)| (code.to_string(), amount.to_string()))
            .collect()
    };
    let rollover = sud.get("rollover_lines").unwrap();
    assert_eq!(text(rollover, "definition"), "income-statement");
    assert_eq!(
        lines(rollover),
        pairs(&[
            ("revenue", "0.00 USD"),
            ("expense", "10.00 USD"),
            ("net_income", "-10.00 USD"),
        ])
    );
    let iron_curtain = sud.get("iron_curtain_lines").unwrap();
    assert_eq!(text(iron_curtain, "definition"), "balance-sheet");
    assert_eq!(
        lines(iron_curtain),
        pairs(&[
            ("assets", "0.00 USD"),
            ("liabilities", "10.00 USD"),
            ("equity", "0.00 USD"),
            ("unclosed_revenue", "0.00 USD"),
            ("unclosed_expense", "10.00 USD"),
            ("unclosed_earnings", "-10.00 USD"),
            ("total_equity", "-10.00 USD"),
            ("liabilities_and_equity", "0.00 USD"),
            ("balance_check", "0.00 USD"),
        ]),
        "a balanced correction leaves the balance check at zero"
    );
    // The classified presets name finer lines: 2100 is an accrued liability.
    let classified = f.ok(&[
        "engagement",
        "sud",
        "FY26-audit",
        "--definition",
        "us_gaap_small_company_balance_sheet",
        "--definition",
        "us_gaap_small_company_income_statement",
    ]);
    let classified = data(&classified);
    let by_code = |statement: &Json, code: &str| -> String {
        rows(statement, "lines")
            .iter()
            .find(|line| text(line, "code") == code)
            .map(|line| text(line, "amount").to_string())
            .unwrap_or_else(|| panic!("no line {code} in {}", statement.render()))
    };
    let classified_balance = classified.get("iron_curtain_lines").unwrap();
    assert_eq!(
        text(classified_balance, "definition"),
        "us_gaap_small_company_balance_sheet"
    );
    assert_eq!(
        by_code(classified_balance, "accrued_liabilities"),
        "10.00 USD"
    );
    assert_eq!(by_code(classified_balance, "accounts_payable"), "0.00 USD");
    let classified_income = classified.get("rollover_lines").unwrap();
    assert_eq!(by_code(classified_income, "net_income"), "-10.00 USD");
    assert_eq!(
        sud.get("items"),
        classified.get("items"),
        "the definitions only attribute the same items"
    );
    // Two balance sheets, or a name lint does not take, are refused.
    for definitions in [
        &["balance-sheet", "us_gaap_small_company_balance_sheet"][..],
        &["no-such-definition"][..],
    ] {
        let mut args = vec!["engagement", "sud", "FY26-audit"];
        for name in definitions {
            args.extend(["--definition", *name]);
        }
        let (status, output) = f.run(&args);
        assert_eq!(status, 2, "{definitions:?}: {}", output.render());
    }

    // Show and list: the journal states both decisions and the open third.
    let shown = f.ok(&["engagement", "show", "FY26-audit"]);
    let summary = data(&shown).get("engagement").unwrap();
    assert_eq!(
        (
            int(summary, "proposed"),
            int(summary, "booked"),
            int(summary, "passed")
        ),
        (1, 1, 1)
    );
    let states: Vec<&str> = rows(data(&shown), "proposals")
        .iter()
        .map(|p| text(p, "state"))
        .collect();
    assert_eq!(states, ["booked", "passed", "proposed"]);
    let listed = f.ok(&["engagement", "list"]);
    assert_eq!(rows(data(&listed), "engagements").len(), 1);
}

/// Booking names the correction that stands: recorded after its proposal,
/// effective in the proposal's period, never reversed. A booking whose
/// entry is reversed later is uncorrected again in the summary, with the
/// decision still on the record.
#[test]
fn booking_names_the_standing_correction_after_its_proposal_in_its_period() {
    let f = Fixture::new();
    f.ok(OPEN);
    let propose = |name: &str, date: &str, amount: &str| {
        f.intent(
            name,
            date,
            &[("debit", "6000", amount), ("credit", "2100", amount)],
        );
        let proposed = f.ok(&[
            "adjustment",
            "propose",
            "--engagement",
            "FY26-audit",
            "--intent",
            name,
        ]);
        int(data(&proposed).get("proposal").unwrap(), "number").to_string()
    };
    let book_args = |proposal: &str, entry: &str| -> Vec<String> {
        [
            "adjustment",
            "book",
            "--engagement",
            "FY26-audit",
            "--proposal",
            proposal,
            "--entry",
            &format!("E:{entry}"),
        ]
        .map(str::to_string)
        .to_vec()
    };
    let refuse_book = |proposal: &str, entry: &str, why: &str| {
        let args = book_args(proposal, entry);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let refusal = f.refused(&args, 3, "FA-REF-182");
        assert!(
            text(data(&refusal), "message").contains(why),
            "{why}: {}",
            refusal.render()
        );
    };

    // An entry recorded before the proposal is not its correction.
    let early = f.post("early", "2026-03-20", "6000", "2100", "15.00");
    let first = propose("proposal-early.json", "2026-03-20", "15.00");
    refuse_book(&first, &early, "before the proposal");

    // An entry effective in another scope period is not its correction.
    let second = propose("proposal-april.json", "2026-03-25", "12.00");
    let april = f.post("april", "2026-04-05", "6000", "2100", "12.00");
    refuse_book(&second, &april, "outside the proposal's period FY2026-P03");

    // A reversed entry no longer makes the correction.
    let third = propose("proposal-reversed.json", "2026-03-26", "13.00");
    let reversed = f.post("reversed", "2026-03-26", "6000", "2100", "13.00");
    f.ok(&["reverse", &reversed, "--reason", "WrongAmount"]);
    refuse_book(&third, &reversed, "superseded by entry");

    // A standing correction books; reversing it later makes the proposal
    // uncorrected again, its booking still on the record.
    let fourth = propose("proposal-standing.json", "2026-03-27", "14.00");
    let standing = f.post("standing", "2026-03-27", "6000", "2100", "14.00");
    let args = book_args(&fourth, &standing);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    f.ok(&args);
    let sud = f.ok(&["engagement", "sud", "FY26-audit"]);
    assert!(rows(data(&sud), "items").is_empty(), "{}", sud.render());
    let reversal = f.ok(&["reverse", &standing, "--reason", "WrongAmount"]);
    let reversal = text(data(&reversal), "vid").to_string();
    let sud = f.ok(&["engagement", "sud", "FY26-audit"]);
    let items = rows(data(&sud), "items");
    assert_eq!(items.len(), 1, "{}", sud.render());
    assert_eq!(int(&items[0], "number").to_string(), fourth);
    assert_eq!(items[0].get("reason"), Some(&Json::Null));
    assert_eq!(text(&items[0], "booked_entry"), standing);
    assert_eq!(text(&items[0], "superseded_by"), reversal);
    let effect = items[0].get("effect").unwrap();
    assert_eq!(text(effect, "income"), "-14.00 USD");
    assert_eq!(text(effect, "liabilities"), "14.00 USD");
    let shown = f.ok(&["engagement", "show", "FY26-audit"]);
    let booked = rows(data(&shown), "proposals")
        .iter()
        .find(|p| int(p, "number").to_string() == fourth)
        .unwrap();
    assert_eq!(text(booked, "state"), "booked");
    let decision = booked.get("decision").unwrap();
    assert_eq!(text(decision, "entry"), standing);
    assert_eq!(text(decision, "superseded_by"), reversal);
}

#[test]
fn engagement_records_need_produce_and_never_come_from_an_agent() {
    let f = Fixture::new();
    f.ok(OPEN);
    f.intent(
        "fees.json",
        "2026-03-31",
        &[("debit", "6000", "40.00"), ("credit", "2100", "40.00")],
    );
    let issue = |holder: &str, profile: &str, ops: &[&str]| {
        let token = format!("{holder}.token");
        let mut args = vec![
            "capability",
            "issue",
            "--holder",
            holder,
            "--profile",
            profile,
            "--out",
            &token,
            "--grant",
            "issue_capability",
        ];
        // The issuer must hold what it issues: never a widening.
        for op in ops {
            args.extend(["--op", op, "--grant", op]);
        }
        f.ok(&args);
        token
    };
    // A reader reads the engagement but proposes nothing (missing produce).
    let reader = issue("engagement-reader", "human", &["read"]);
    f.ok(&["--token", &reader, "engagement", "show", "FY26-audit"]);
    f.refused(
        &[
            "--token",
            &reader,
            "adjustment",
            "propose",
            "--engagement",
            "FY26-audit",
            "--intent",
            "fees.json",
        ],
        7,
        "FA-REF-011",
    );
    // The owner proposes twice and posts the first correction.
    for key in ["first", "second"] {
        f.ok(&[
            "adjustment",
            "propose",
            "--engagement",
            "FY26-audit",
            "--intent",
            "fees.json",
            "--key",
            key,
        ]);
    }
    let correction = f.post("fees-correction", "2026-03-31", "6000", "2100", "40.00");
    let entry = format!("E:{correction}");
    fn book<'a>(token: &'a str, entry: &'a str) -> Vec<&'a str> {
        vec![
            "--token",
            token,
            "adjustment",
            "book",
            "--engagement",
            "FY26-audit",
            "--proposal",
            "1",
            "--entry",
            entry,
        ]
    }
    fn pass(token: &str) -> Vec<&str> {
        vec![
            "--token",
            token,
            "adjustment",
            "pass",
            "--engagement",
            "FY26-audit",
            "--proposal",
            "2",
            "--reason",
            "Other",
        ]
    }

    // An Agent holding read and produce still journals no trunk record:
    // neither an engagement, a proposal, a booking nor a pass.
    let agent = issue("engagement-agent", "agent", &["read", "produce"]);
    let mut agent_open = vec!["--token", agent.as_str()];
    agent_open.extend(OPEN);
    agent_open[4] = "FY26-agent";
    f.refused(&agent_open, 7, "FA-REF-013");
    f.refused(
        &[
            "--token",
            &agent,
            "adjustment",
            "propose",
            "--engagement",
            "FY26-audit",
            "--intent",
            "fees.json",
        ],
        7,
        "FA-REF-013",
    );
    f.refused(&book(&agent, &entry), 7, "FA-REF-013");
    f.refused(&pass(&agent), 7, "FA-REF-013");

    // Produce alone passes (it reads nothing it does not own) but never
    // books: booking reads the entry it names, which needs read.
    let producer = issue("engagement-producer", "human", &["produce"]);
    f.refused(&book(&producer, &entry), 7, "FA-REF-011");
    f.ok(&pass(&producer));
    let booker = issue("engagement-booker", "human", &["read", "produce"]);
    f.ok(&book(&booker, &entry));
}

/// AS 1215.15/.16: documentation completes once, within 45 days after the
/// report release date; the workpaper index and the proposals stay
/// append-only, and every addition after the completion is marked.
#[test]
fn documentation_completes_once_within_45_days_and_marks_every_later_addition() {
    let f = Fixture::new();
    f.ok(OPEN);
    let workpaper = |name: &str| {
        f.write(name, &format!("Workpaper {name}"));
        let added = f.ok(&[
            "document",
            "add",
            name,
            "--kind",
            "Workpaper",
            "--grade",
            "HumanUpload",
        ]);
        text(data(&added), "oid").to_string()
    };
    let file = |oid: &str| f.ok(&["engagement", "file", "FY26-audit", "--document", oid]);
    let before = workpaper("planning.txt");
    let filed = file(&before);
    assert_eq!(text(&filed, "event"), "engagement_workpaper_filed");
    assert_eq!(
        data(&filed).get("added_after_completion"),
        Some(&Json::Bool(false))
    );
    assert_eq!(
        data(&file(&before)).get("already_recorded"),
        Some(&Json::Bool(true)),
        "a document is filed once"
    );
    f.refused(
        &[
            "engagement",
            "file",
            "FY26-audit",
            "--document",
            "1111111111111111111111111111111111111111111111111111111111111111",
        ],
        3,
        "FA-REF-081",
    );
    f.intent(
        "fees.json",
        "2026-03-31",
        &[("debit", "6000", "40.00"), ("credit", "2100", "40.00")],
    );
    let propose = |key: &str| {
        f.ok(&[
            "adjustment",
            "propose",
            "--engagement",
            "FY26-audit",
            "--intent",
            "fees.json",
            "--key",
            key,
        ])
    };
    propose("before");

    // The engagement was opened without a report release date, so the
    // completion names it; the completion date lies within 45 days after it.
    let complete = |extra: &[&'static str]| -> Vec<&'static str> {
        let mut args = vec!["engagement", "complete", "FY26-audit"];
        args.extend_from_slice(extra);
        args
    };
    f.refused(
        &complete(&["--completion-date", "2026-05-01"]),
        3,
        "FA-REF-190",
    );
    for late in ["2026-05-31", "2026-04-14"] {
        f.refused(
            &complete(&["--report-release", "2026-04-15", "--completion-date", late]),
            3,
            "FA-REF-190",
        );
    }
    let on_time = complete(&[
        "--report-release",
        "2026-04-15",
        "--completion-date",
        "2026-05-30",
    ]);
    let completed = f.ok(&on_time);
    assert_eq!(
        text(&completed, "event"),
        "engagement_documentation_completed"
    );
    let documentation = data(&completed).get("documentation").unwrap();
    assert_eq!(text(documentation, "report_release"), "2026-04-15");
    assert_eq!(text(documentation, "completion_date"), "2026-05-30");
    assert_eq!(
        data(&f.ok(&on_time)).get("already_recorded"),
        Some(&Json::Bool(true)),
        "the identical completion retried is the recorded one"
    );
    let mut again = on_time.clone();
    again.extend(["--key", "second"]);
    f.refused(&again, 3, "FA-REF-190");

    // After completion: a new workpaper, a new proposal and a decision are
    // additions, each marked; the earlier filing stays as it was.
    let after = workpaper("subsequent.txt");
    assert_eq!(
        data(&file(&after)).get("added_after_completion"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        data(&file(&before)).get("added_after_completion"),
        Some(&Json::Bool(false)),
        "retrying the earlier filing returns it as it was recorded"
    );
    propose("after");
    f.ok(&[
        "adjustment",
        "pass",
        "--engagement",
        "FY26-audit",
        "--proposal",
        "1",
        "--reason",
        "ClearlyTrivial",
    ]);

    let shown = f.ok(&["engagement", "show", "FY26-audit"]);
    let shown = data(&shown);
    assert_eq!(
        text(shown.get("engagement").unwrap(), "state"),
        "documentation_complete"
    );
    let documentation = shown.get("documentation").unwrap();
    assert_eq!(text(documentation, "completion_date"), "2026-05-30");
    let workpapers: Vec<(String, bool)> = rows(shown, "workpapers")
        .iter()
        .map(|w| {
            (
                text(w, "document").to_string(),
                w.get("added_after_completion") == Some(&Json::Bool(true)),
            )
        })
        .collect();
    assert_eq!(workpapers, [(before, false), (after, true)]);
    let proposals = rows(shown, "proposals");
    assert_eq!(proposals.len(), 2);
    assert_eq!(
        proposals[0].get("added_after_completion"),
        Some(&Json::Bool(false))
    );
    assert_eq!(
        proposals[0]
            .get("decision")
            .and_then(|d| d.get("added_after_completion")),
        Some(&Json::Bool(true)),
        "a decision recorded after the completion is an addition"
    );
    assert_eq!(
        proposals[1].get("added_after_completion"),
        Some(&Json::Bool(true))
    );
}

/// AS 2310 / AS 2805: the auditor attests what a party confirmed, management
/// attests its representations, and the engagement's workpaper index grades
/// a confirmation audit-grade only when its firm principal received it.
#[test]
fn confirmations_and_representations_are_attested_and_graded_in_the_workpaper_index() {
    let f = Fixture::new();
    f.ok(OPEN);
    f.write(
        "customer.json",
        r#"{"code":"C-1","kind":"Customer","name":"Big Customer"}"#,
    );
    f.ok(&["party", "add", "customer.json"]);
    let document = |name: &str, kind: &str, by: Option<&str>| {
        f.write(name, &format!("{kind} document {name}"));
        let mut args = vec![
            "document",
            "add",
            name,
            "--kind",
            kind,
            "--grade",
            "HumanUpload",
        ];
        if let Some(principal) = by {
            args.extend(["--as", principal]);
        }
        text(data(&f.ok(&args)), "oid").to_string()
    };
    // One confirmation came straight to the auditor; one was routed
    // through the client's controller.
    let direct = document("direct.txt", "Confirmation", None);
    let routed = document("routed.txt", "Confirmation", Some("client-controller"));
    let letter = document("letter.txt", "Representation", None);
    let confirm = |oid: &str, balance: &str| {
        vec![
            "document".to_string(),
            "attest".into(),
            "confirmed".into(),
            oid.to_string(),
            "--party".into(),
            "C-1".into(),
            "--balance".into(),
            balance.to_string(),
            "--as-of".into(),
            "2026-03-31".into(),
        ]
    };
    fn strs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }
    let confirmed = f.ok(&strs(&confirm(&direct, "1200.00 USD")));
    assert_eq!(text(data(&confirmed), "claim"), "Confirmed");
    assert_eq!(
        data(&f.ok(&strs(&confirm(&direct, "1200.00 USD")))).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    f.ok(&strs(&confirm(&routed, "800.00 USD")));
    // A receipt is not a confirmation, and the party must be one the book has.
    f.refused(&strs(&confirm(&f.evidence, "1.00 USD")), 3, "FA-REF-110");
    let mut unknown_party = confirm(&routed, "800.00 USD");
    unknown_party[5] = "NO-SUCH".into();
    f.refused(&strs(&unknown_party), 3, "FA-REF-110");
    let represented = f.ok(&[
        "document",
        "attest",
        "represented",
        &letter,
        "--claim",
        "All transactions are recorded",
        "--claim",
        "No fraud involving management is known",
        "--as-of",
        "2026-04-15",
    ]);
    assert_eq!(text(data(&represented), "claim"), "Represented");
    let (status, _) = f.run(&[
        "document",
        "attest",
        "represented",
        &letter,
        "--as-of",
        "2026-04-15",
    ]);
    assert_eq!(status, 2, "a representation states at least one claim");

    for oid in [&direct, &routed, &letter] {
        f.ok(&["engagement", "file", "FY26-audit", "--document", oid]);
    }
    let shown = f.ok(&["engagement", "show", "FY26-audit"]);
    let workpapers = rows(data(&shown), "workpapers");
    assert_eq!(workpapers.len(), 3);
    let confirmation = |i: usize| workpapers[i].get("confirmation").expect("confirmation");
    assert_eq!(text(confirmation(0), "balance"), "1200.00 USD");
    assert_eq!(
        confirmation(0).get("audit_grade"),
        Some(&Json::Bool(true)),
        "received by the engagement's firm principal"
    );
    assert_eq!(text(confirmation(1), "balance"), "800.00 USD");
    assert_eq!(
        confirmation(1).get("audit_grade"),
        Some(&Json::Bool(false)),
        "received by the client's controller, not the auditor"
    );
    assert_ne!(
        text(confirmation(1), "received_by"),
        text(confirmation(0), "received_by")
    );
    assert_eq!(workpapers[2].get("confirmation"), Some(&Json::Null));
    let representation = workpapers[2].get("representation").unwrap();
    assert_eq!(int(representation, "claims"), 2);
    assert_eq!(text(representation, "as_of"), "2026-04-15");
}

/// Plan §8.2, SAB 108: an immaterial prior-period error corrected in the
/// current period without a case is an Adjusting entry naming the earlier
/// period. It misstates this period's income, so the summary counts it under
/// the rollover method; the period-end balance sheet it corrected carries
/// nothing for it under the iron curtain. Once reversed it no longer counts.
#[test]
fn an_out_of_period_correction_misstates_rollover_income_until_it_is_reversed() {
    let f = Fixture::new();
    f.ok(OPEN);
    // February's unrecorded fees, 400.00, expensed in March.
    let adjusting = |key: &str, class: &str, relates_to: Option<&str>| -> String {
        let name = format!("{key}.json");
        let marker = relates_to
            .map(|period| format!(r#","prior_period_error":"{period}""#))
            .unwrap_or_default();
        f.write(
            &name,
            &format!(
                r#"{{"class":"{class}","idempotency_key":"{key}","effective_date":"2026-03-20"{marker},"legs":[{{"side":"debit","account":"6000","amount":"400.00 USD"}},{{"side":"credit","account":"2100","amount":"400.00 USD"}}]}}"#
            ),
        );
        name
    };
    // Planted negatives, nothing journaled: the marker names an earlier
    // period of the calendar, on an Adjusting entry only.
    for period in ["FY2026-P03", "FY2026-P04", "FY2026-P99"] {
        let intent = adjusting(&format!("bad-{period}"), "Adjusting", Some(period));
        f.refused(
            &["post", "--intent", &intent, "--evidence", &f.evidence],
            2,
            "FA-REF-100",
        );
    }
    let original = adjusting("original", "Original", None);
    let before = f.head();
    let (status, output) = f.run(&[
        "post",
        "--intent",
        &original,
        "--evidence",
        &f.evidence,
        "--prior-period-error",
        "FY2026-P02",
    ]);
    assert_eq!(status, 2, "{}", output.render());
    assert_eq!(f.head(), before + f.access_events_since(before));

    let intent = adjusting("out-of-period", "Adjusting", Some("FY2026-P02"));
    let posted = f.ok(&["post", "--intent", &intent, "--evidence", &f.evidence]);
    let entry = text(data(&posted), "vid").to_string();
    let sud = f.ok(&["engagement", "sud", "FY26-audit"]);
    let sud = data(&sud);
    assert!(rows(sud, "items").is_empty(), "{}", sud.render());
    let out_of_period = rows(sud, "out_of_period");
    assert_eq!(out_of_period.len(), 1, "{}", sud.render());
    assert_eq!(text(&out_of_period[0], "entry"), entry);
    assert_eq!(text(&out_of_period[0], "relates_to"), "FY2026-P02");
    let effect = out_of_period[0].get("effect").unwrap();
    assert_eq!(text(effect, "income"), "400.00 USD", "income understated");
    assert_eq!(
        text(effect, "equity"),
        "-400.00 USD",
        "against opening retained earnings"
    );
    assert_eq!(
        out_of_period[0].get("clearly_trivial"),
        Some(&Json::Bool(false))
    );
    assert_eq!(text(sud, "rollover_income"), "400.00 USD");
    let iron_curtain = sud.get("iron_curtain").unwrap();
    for line in ["income", "assets", "liabilities", "equity"] {
        assert_eq!(text(iron_curtain, line), "0.00 USD", "{line}");
    }
    // 400.00 under rollover: above performance (375.00), within overall.
    assert_eq!(sud.get("exceeds_performance"), Some(&Json::Bool(true)));
    assert_eq!(sud.get("exceeds_overall"), Some(&Json::Bool(false)));
    let lines = |statement: &Json| -> Vec<(String, String)> {
        rows(statement, "lines")
            .iter()
            .map(|line| {
                (
                    text(line, "code").to_string(),
                    text(line, "amount").to_string(),
                )
            })
            .collect()
    };
    let pairs = |expected: &[(&str, &str)]| -> Vec<(String, String)> {
        expected
            .iter()
            .map(|(code, amount)| (code.to_string(), amount.to_string()))
            .collect()
    };
    assert_eq!(
        lines(sud.get("rollover_lines").unwrap()),
        pairs(&[
            ("revenue", "0.00 USD"),
            ("expense", "-400.00 USD"),
            ("net_income", "400.00 USD"),
        ]),
        "this period's expense is overstated by last period's fees"
    );
    assert!(
        lines(sud.get("iron_curtain_lines").unwrap())
            .iter()
            .all(|(_, amount)| amount == "0.00 USD"),
        "{}",
        sud.render()
    );

    // Reversed, the correction no longer stands and no longer counts.
    f.ok(&["reverse", &entry, "--reason", "WrongPeriod"]);
    let sud = f.ok(&["engagement", "sud", "FY26-audit"]);
    let sud = data(&sud);
    assert!(rows(sud, "out_of_period").is_empty(), "{}", sud.render());
    assert_eq!(text(sud, "rollover_income"), "0.00 USD");
}

/// SAB 108 carry-forward: the auditor states which of the prior
/// engagement's uncorrected misstatements turned around in this period and
/// which an out-of-period correction here corrected; the rest are still
/// uncorrected at this period's end. The summary counts each under the
/// method its fate decides, and the latest carry-forward governs.
#[test]
fn a_carry_forward_brings_the_prior_engagements_misstatements_under_both_methods() {
    let f = Fixture::new();
    let open = |id: &str, period: &str| {
        f.ok(&[
            "engagement",
            "open",
            id,
            "--kind",
            "audit",
            "--period",
            period,
            "--overall",
            "500.00 USD",
            "--performance",
            "375.00 USD",
            "--clearly-trivial",
            "25.00 USD",
        ]);
    };
    open("march", "FY2026-P03");
    open("april", "FY2026-P04");
    // March left three fee accruals uncorrected: 10.00, 20.00 and 40.00.
    for (number, amount) in [("1", "10.00"), ("2", "20.00"), ("3", "40.00")] {
        let name = format!("accrual-{number}.json");
        f.intent(
            &name,
            "2026-03-31",
            &[("debit", "6000", amount), ("credit", "2100", amount)],
        );
        f.ok(&[
            "adjustment",
            "propose",
            "--engagement",
            "march",
            "--intent",
            &name,
            "--key",
            &name,
        ]);
        f.ok(&[
            "adjustment",
            "pass",
            "--engagement",
            "march",
            "--proposal",
            number,
            "--reason",
            "ClearlyTrivial",
        ]);
    }

    // Planted negatives, nothing journaled: itself, a prior that does not
    // precede, a proposal that is not an uncorrected one, an unknown prior,
    // and a proposal stated both turned around and corrected.
    let carry = |extra: &[&'static str]| -> Vec<&'static str> {
        let mut args = vec!["engagement", "carry-forward"];
        args.extend_from_slice(extra);
        args
    };
    f.refused(&carry(&["april", "--from", "april"]), 3, "FA-REF-191");
    f.refused(&carry(&["march", "--from", "april"]), 3, "FA-REF-191");
    f.refused(
        &carry(&["april", "--from", "march", "--turned-around", "9"]),
        3,
        "FA-REF-191",
    );
    f.refused(&carry(&["april", "--from", "no-such"]), 3, "FA-REF-180");
    f.refused(
        &carry(&[
            "april",
            "--from",
            "march",
            "--turned-around",
            "2",
            "--corrected",
            "2",
        ]),
        2,
        "FA-REF-100",
    );

    let carried = f.ok(&carry(&[
        "april",
        "--from",
        "march",
        "--turned-around",
        "2",
        "--corrected",
        "3",
    ]));
    assert_eq!(text(&carried, "event"), "engagement_carry_forward_recorded");
    assert_eq!(text(data(&carried), "prior"), "march");
    let sud = f.ok(&["engagement", "sud", "april"]);
    let sud = data(&sud);
    assert!(rows(sud, "items").is_empty(), "{}", sud.render());
    assert_eq!(text(sud, "carried_from"), "march");
    assert_eq!(
        sud.get("prior_period_carry_forward"),
        Some(&Json::Bool(true))
    );
    let carried = rows(sud, "carried");
    assert_eq!(
        carried
            .iter()
            .map(|c| (int(c, "prior_number"), text(c, "carried")))
            .collect::<Vec<_>>(),
        [(1, "Uncorrected"), (2, "TurnedAround"), (3, "Corrected")]
    );
    let effect = |i: usize, line: &str| text(carried[i].get("effect").unwrap(), line).to_string();
    // Still uncorrected: accrued liabilities 10.00 short at April's end,
    // March's expense now in opening retained earnings.
    assert_eq!(effect(0, "liabilities"), "10.00 USD");
    assert_eq!(effect(0, "equity"), "-10.00 USD");
    assert_eq!(effect(0, "income"), "0.00 USD");
    // Turned around: April's income took March's 20.00 of fees.
    assert_eq!(effect(1, "income"), "20.00 USD");
    assert_eq!(effect(1, "equity"), "-20.00 USD");
    assert_eq!(effect(2, "income"), "0.00 USD");
    assert_eq!(effect(2, "liabilities"), "0.00 USD");
    assert_eq!(text(sud, "rollover_income"), "20.00 USD");
    let iron_curtain = sud.get("iron_curtain").unwrap();
    assert_eq!(text(iron_curtain, "liabilities"), "10.00 USD");
    assert_eq!(text(iron_curtain, "equity"), "-10.00 USD");
    assert_eq!(text(iron_curtain, "income"), "0.00 USD");

    // A later carry-forward governs; the first stays on the record.
    f.ok(&carry(&["april", "--from", "march", "--key", "restated"]));
    let sud = f.ok(&["engagement", "sud", "april"]);
    let sud = data(&sud);
    assert_eq!(text(sud, "rollover_income"), "0.00 USD");
    assert_eq!(
        text(sud.get("iron_curtain").unwrap(), "liabilities"),
        "70.00 USD"
    );
    let shown = f.ok(&["engagement", "show", "april"]);
    let history = rows(data(&shown), "carry_forwards");
    assert_eq!(history.len(), 2, "{}", shown.render());
    assert_eq!(text(&history[0], "prior"), "march");
    assert_eq!(
        history[0].get("turned_around"),
        Some(&Json::Arr(vec![Json::Int(2)]))
    );
    assert_eq!(
        history[1].get("turned_around"),
        Some(&Json::Arr(Vec::new()))
    );
}

/// Plan §11.12: an engagement's findings join its index like its
/// workpapers, once each, and one filed after the documentation completion
/// is marked an addition after completion (AS 1215.16).
#[test]
fn findings_are_filed_in_the_index_once_and_marked_after_completion() {
    let f = Fixture::new();
    f.ok(OPEN);
    // Two weekend postings: jet.weekend observes each.
    f.post("saturday", "2026-03-14", "1000", "4000", "10.00");
    f.post("sunday", "2026-03-15", "1000", "4000", "20.00");
    let recorded = f.ok(&["finding", "record", "jet.weekend"]);
    let ids: Vec<String> = rows(data(&recorded), "finding_ids")
        .iter()
        .map(|id| id.as_str().expect("a finding id").to_string())
        .collect();
    assert_eq!(ids.len(), 2, "{}", recorded.render());
    let file = |id: &str| f.ok(&["engagement", "file", "FY26-audit", "--finding", id]);
    let first = file(&ids[0]);
    assert_eq!(text(&first, "event"), "engagement_finding_filed");
    assert_eq!(text(data(&first), "finding"), ids[0]);
    assert_eq!(
        data(&first).get("added_after_completion"),
        Some(&Json::Bool(false))
    );
    assert_eq!(
        data(&file(&ids[0])).get("already_recorded"),
        Some(&Json::Bool(true)),
        "the same filing retried is the recorded one"
    );
    // Planted negatives, nothing journaled: a vid that is no finding; the
    // same finding filed again under another key (its record's identity is
    // the finding's, so the other content conflicts with it).
    let none = "0".repeat(32);
    f.refused(
        &["engagement", "file", "FY26-audit", "--finding", &none],
        2,
        "FA-REF-100",
    );
    f.refused(
        &[
            "engagement",
            "file",
            "FY26-audit",
            "--finding",
            &ids[0],
            "--key",
            "again",
        ],
        6,
        "FA-REF-032",
    );
    let (status, output) = f.run(&[
        "engagement",
        "file",
        "FY26-audit",
        "--finding",
        &ids[1],
        "--document",
        &f.evidence,
    ]);
    assert_eq!(
        status,
        2,
        "one --document or one --finding: {}",
        output.render()
    );

    f.ok(&[
        "engagement",
        "complete",
        "FY26-audit",
        "--report-release",
        "2026-04-15",
        "--completion-date",
        "2026-04-30",
    ]);
    let later = file(&ids[1]);
    assert_eq!(
        data(&later).get("added_after_completion"),
        Some(&Json::Bool(true))
    );
    let shown = f.ok(&["engagement", "show", "FY26-audit"]);
    let findings = rows(data(&shown), "findings");
    assert_eq!(
        findings
            .iter()
            .map(|x| (
                text(x, "finding").to_string(),
                x.get("added_after_completion").cloned()
            ))
            .collect::<Vec<_>>(),
        [
            (ids[0].clone(), Some(Json::Bool(false))),
            (ids[1].clone(), Some(Json::Bool(true))),
        ]
    );
}
