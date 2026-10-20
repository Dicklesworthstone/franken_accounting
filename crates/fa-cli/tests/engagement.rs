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

    /// Refused with `exit` and `refusal_id`, and nothing journaled.
    fn refused(&self, args: &[&str], exit: i32, id: &str) -> Json {
        let before = self.head();
        let (status, output) = self.run(args);
        assert_eq!(status, exit, "{args:?}: {}", output.render());
        assert_eq!(text(data(&output), "refusal_id"), id, "{}", output.render());
        assert_eq!(self.head(), before, "{args:?} journaled nothing");
        output
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
