//! End-to-end native AR/AP subledgers through the real persisted CLI.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};
use fa_cli::verbs::registry;

#[path = "subledger/external.rs"]
mod external;

#[path = "subledger/external_portable.rs"]
mod external_portable;

#[path = "subledger/certificate.rs"]
mod certificate;

#[path = "subledger/portable.rs"]
mod portable;

#[path = "subledger/application.rs"]
mod application;

#[test]
fn bound_reader_can_reconcile_but_cannot_register_a_control() {
    use fa_cli::authority::{LaunchAuthority, LaunchProfile};
    use fa_cli::cli::{Books, Files, Stdin, run_with_authority};

    let f = Fixture::new();
    f.register("AR", "1200", "receivables");
    f.invoice("C-1", "READ-1", "25.00 USD");
    let authority = LaunchAuthority::new(
        f.book.clone(),
        None,
        "operator",
        LaunchProfile::Preparer,
        &["read"],
    )
    .unwrap();
    let run = |args: &[&str]| {
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
        let result = run_with_authority(
            &args,
            Books::Dir,
            Files {
                cwd: None,
                stdin: Stdin::Missing,
            },
            &authority,
            true,
        );
        for line in result.1.stdout.lines() {
            registry().unwrap().check_line(line).unwrap();
        }
        result
    };
    let (exit, output) = run(&[
        "subledger",
        "verify",
        "AR",
        "--as-of",
        "2026-03-31",
        "--json",
    ]);
    assert_eq!(exit, 0, "{output:?}");
    assert_eq!(
        data(&output.stdout).get("reconciled"),
        Some(&Json::Bool(true))
    );
    let before = f.head();
    let (exit, output) = run(&[
        "subledger",
        "add",
        "AP",
        "--control",
        "2000",
        "--kind",
        "payables",
        "--json",
    ]);
    assert_eq!(exit, 7, "{output:?}");
    let event = json::parse(output.stdout.lines().last().unwrap()).unwrap();
    assert_eq!(
        event.get("book"),
        Some(&Json::Null),
        "admit before observation"
    );
    assert_eq!(event.get("coordinate"), Some(&Json::Null));
    assert_eq!(f.head(), before, "refused registration publishes nothing");
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    evidence: String,
}

fn data(output: &str) -> Json {
    json::parse(output.lines().last().expect("robot event"))
        .expect("valid JSON")
        .get("data")
        .expect("event data")
        .clone()
}

fn text(value: &Json, field: &str) -> String {
    value
        .get(field)
        .and_then(Json::as_str)
        .expect(field)
        .to_string()
}

fn rows<'a>(value: &'a Json, field: &str) -> &'a [Json] {
    match value.get(field).expect(field) {
        Json::Arr(rows) => rows,
        other => panic!("{field} is not an array: {other:?}"),
    }
}

impl Fixture {
    fn new() -> Self {
        Self::with_additional_accounts(Vec::new())
    }

    fn with_additional_accounts(additional: Vec<Json>) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let path = std::env::temp_dir().join(format!(
                "fa-native-subledger-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("fixture: {error}"),
            }
        };
        let mut f = Self {
            book: dir.join("book"),
            dir,
            evidence: String::new(),
        };
        f.ok(&["book", "create", "--name", "Subledger Co"]);
        let chart = json::parse(r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1200","name":"Receivables","type":"Asset","unit":"USD"},{"code":"2000","name":"Payables","type":"Liability","unit":"USD"},{"code":"4000","name":"Sales","type":"Revenue","unit":"USD"},{"code":"6000","name":"Expense","type":"Expense","unit":"USD"}]}"#).unwrap();
        let accounts = chart.get("accounts").unwrap().as_arr().unwrap().to_vec();
        let chart = f.file(
            "chart.json",
            &Json::Obj(vec![("accounts".into(), Json::Arr(accounts))]).render(),
        );
        f.ok(&["chart", "import", &chart]);
        // Each import is one journaled schema record, so keep its retained
        // payload below the substrate's per-row limit.
        for (index, accounts) in additional.chunks(32).enumerate() {
            let chart = f.file(
                &format!("chart-additional-{index}.json"),
                &Json::Obj(vec![("accounts".into(), Json::Arr(accounts.to_vec()))]).render(),
            );
            f.ok(&["chart", "import", &chart]);
        }
        f.ok(&["period", "create", "--fiscal-year", "2026"]);
        f.ok(&["period", "open", "FY2026-P03"]);
        f.ok(&["period", "open", "FY2026-P04"]);
        for (code, kind) in [("C-1", "Customer"), ("C-2", "Customer"), ("V-1", "Vendor")] {
            let path = f.file(
                &format!("{code}.json"),
                &format!(r#"{{"code":"{code}","kind":"{kind}","name":"{code}"}}"#),
            );
            f.ok(&["party", "add", &path]);
        }
        let source = f.file(
            "source.txt",
            "Retained source for the subledger acceptance history.",
        );
        f.evidence = text(
            &data(&f.ok(&[
                "document",
                "add",
                &source,
                "--kind",
                "Invoice",
                "--grade",
                "HumanUpload",
            ])),
            "oid",
        );
        f
    }

    fn file(&self, name: &str, body: &str) -> String {
        let path = self.dir.join(name);
        std::fs::write(&path, body).expect("write fixture input");
        path.to_str().unwrap().to_string()
    }

    fn run(&self, args: &[&str]) -> (i32, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_fa"))
            .arg("--book")
            .arg(&self.book)
            .args(args)
            .arg("--json")
            .env_remove("FA_BOOK")
            .output()
            .expect("run fa");
        let stdout = String::from_utf8(output.stdout).expect("UTF-8");
        for line in stdout.lines() {
            registry()
                .unwrap()
                .check_line(line)
                .unwrap_or_else(|error| panic!("args={args:?}\n{error}\n{stdout}"));
        }
        (output.status.code().unwrap_or(-1), stdout)
    }

    fn ok(&self, args: &[&str]) -> String {
        let (status, output) = self.run(args);
        assert_eq!(status, 0, "args={args:?}\n{output}");
        output
    }

    fn head(&self) -> String {
        let event = json::parse(self.ok(&["book", "info"]).lines().last().unwrap()).unwrap();
        match event.get("coordinate").unwrap().get("known_at").unwrap() {
            Json::Int(seq) => seq.to_string(),
            other => panic!("sequence: {other:?}"),
        }
    }

    fn register(&self, code: &str, account: &str, kind: &str) -> String {
        self.ok(&[
            "subledger",
            "add",
            code,
            "--control",
            account,
            "--kind",
            kind,
        ])
    }

    fn invoice(&self, party: &str, number: &str, amount: &str) -> String {
        let line = format!("amount=\"{amount}\"");
        self.ok(&[
            "invoice",
            "--party",
            party,
            "--number",
            number,
            "--date",
            "2026-03-14",
            "--receivable",
            "1200",
            "--revenue",
            "4000",
            "--line",
            &line,
            "--evidence",
            &self.evidence,
        ])
    }

    fn verify(&self, code: &str, at: Option<&str>) -> Json {
        self.verify_as_of(code, "2026-03-31", at)
    }

    fn verify_as_of(&self, code: &str, as_of: &str, at: Option<&str>) -> Json {
        let mut args = vec!["subledger", "verify", code, "--as-of", as_of];
        if let Some(at) = at {
            args.extend(["--as-known-at", at]);
        }
        data(&self.ok(&args))
    }
}

/// A posting command's own recorded sequence.
fn recorded(output: &str) -> i128 {
    match data(output).get("recorded_at") {
        Some(Json::Int(seq)) => *seq,
        other => panic!("recorded_at: {other:?}\n{output}"),
    }
}

/// `cents` as the CLI renders a USD amount.
fn usd(cents: i128) -> String {
    let sign = if cents < 0 { "-" } else { "" };
    let cents = cents.abs();
    format!("{sign}{}.{:02} USD", cents / 100, cents % 100)
}

#[test]
fn party_balances_reconcile_after_partial_receipt_reversal_and_reopen() {
    let f = Fixture::new();
    let before_definition = f.head();
    f.register("AR", "1200", "receivables");
    let definition_head = f.head();
    let retry = data(&f.register("AR", "1200", "receivables"));
    assert_eq!(retry.get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(
        f.head(),
        definition_head,
        "registration retry writes nothing"
    );
    let old = data(&f.ok(&["subledger", "list", "--as-known-at", &before_definition]));
    assert!(
        rows(&old, "subledgers").is_empty(),
        "definition never travels backward"
    );
    let shown = data(&f.ok(&["subledger", "show", "AR"]));
    assert_eq!(
        text(&rows(&shown, "subledgers")[0], "control_account"),
        "1200"
    );

    let invoice = data(&f.invoice("C-1", "INV-1", "100.00 USD"));
    let invoice_vid = text(&invoice, "vid");
    f.invoice("C-2", "INV-2", "250.00 USD");
    let before_receipt = f.head();
    let receipt = data(&f.ok(&[
        "receipt",
        "--party",
        "C-1",
        "--number",
        "REC-1",
        "--date",
        "2026-03-20",
        "--cash",
        "1000",
        "--receivable",
        "1200",
        "--amount",
        "40.00 USD",
        "--applies",
        &invoice_vid,
        "--evidence",
        &f.evidence,
    ]));
    let receipt_vid = text(&receipt, "vid");
    let at_receipt = f.head();
    let report = f.verify("AR", None);
    assert_eq!(report.get("reconciled"), Some(&Json::Bool(true)));
    assert_eq!(rows(&report, "rows").len(), 2);
    let customer = rows(&report, "rows")
        .iter()
        .find(|r| text(r, "party") == "C-1")
        .unwrap();
    assert_eq!(text(customer, "net"), "60.00 USD");
    let total = &rows(&report, "totals")[0];
    assert_eq!(text(total, "detail_debits"), "350.00 USD");
    assert_eq!(text(total, "detail_credits"), "40.00 USD");
    assert_eq!(total.get("detail_debits"), total.get("control_debits"));
    assert_eq!(total.get("detail_credits"), total.get("control_credits"));
    assert_eq!(f.head(), at_receipt, "verification is read-only");

    let old = f.verify("AR", Some(&before_receipt));
    let old_customer = rows(&old, "rows")
        .iter()
        .find(|r| text(r, "party") == "C-1")
        .unwrap();
    assert_eq!(text(old_customer, "net"), "100.00 USD");
    f.ok(&[
        "reverse",
        &receipt_vid,
        "--effective",
        "2026-03-22",
        "--reason",
        "WrongAccount",
        "--evidence",
        &f.evidence,
    ]);
    let reversed = f.verify("AR", None);
    let restored = rows(&reversed, "rows")
        .iter()
        .find(|r| text(r, "party") == "C-1")
        .unwrap();
    assert_eq!(
        text(restored, "net"),
        "100.00 USD",
        "exact party relief is restored"
    );
    assert_eq!(reversed.get("reconciled"), Some(&Json::Bool(true)));
    assert_eq!(
        f.verify("AR", Some(&at_receipt)),
        report,
        "every command reopens the book; old results remain exact"
    );

    f.register("AP", "2000", "payables");
    f.ok(&[
        "bill",
        "--party",
        "V-1",
        "--number",
        "B-1",
        "--date",
        "2026-03-25",
        "--payable",
        "2000",
        "--expense",
        "6000",
        "--line",
        "amount=\"30.00 USD\"",
        "--evidence",
        &f.evidence,
    ]);
    let ap = f.verify("AP", None);
    assert_eq!(ap.get("reconciled"), Some(&Json::Bool(true)));
    assert_eq!(text(&rows(&ap, "rows")[0], "net"), "-30.00 USD");
}

/// FA-INV-12 core: from each subledger's registration to the head, at every
/// committed sequence and every effective date its history touches, the party
/// detail folds to the control account's register, and every party's net is
/// what an independent replay of the posted history predicts. The history
/// interleaves invoices, a receipt and its reversal, a post that touches no
/// control leaf, and a second subledger registered midway.
#[test]
fn party_detail_folds_to_the_control_register_at_every_committed_coordinate() {
    let f = Fixture::new();
    f.register("AR", "1200", "receivables");
    let ar_from: i128 = f.head().parse().unwrap();
    // (subledger, recorded sequence, effective date, party, signed cents)
    let mut history = Vec::new();
    let invoice = f.invoice("C-1", "INV-1", "100.00 USD");
    history.push(("AR", recorded(&invoice), "2026-03-14", "C-1", 10_000));
    let second = f.invoice("C-2", "INV-2", "250.00 USD");
    history.push(("AR", recorded(&second), "2026-03-14", "C-2", 25_000));
    let invoice_vid = text(&data(&invoice), "vid");
    let receipt = f.ok(&[
        "receipt",
        "--party",
        "C-1",
        "--number",
        "REC-1",
        "--date",
        "2026-03-20",
        "--cash",
        "1000",
        "--receivable",
        "1200",
        "--amount",
        "40.00 USD",
        "--applies",
        &invoice_vid,
        "--evidence",
        &f.evidence,
    ]);
    history.push(("AR", recorded(&receipt), "2026-03-20", "C-1", -4_000));
    let sale = f.file(
        "sale.json",
        r#"{"effective_date":"2026-03-21","idempotency_key":"cash-sale","legs":[{"side":"debit","account":"1000","amount":"5.00 USD"},{"side":"credit","account":"4000","amount":"5.00 USD"}]}"#,
    );
    f.ok(&["post", "--intent", &sale, "--evidence", &f.evidence]);
    let receipt_vid = text(&data(&receipt), "vid");
    let reversal = f.ok(&[
        "reverse",
        &receipt_vid,
        "--effective",
        "2026-03-22",
        "--reason",
        "WrongAccount",
        "--evidence",
        &f.evidence,
    ]);
    history.push(("AR", recorded(&reversal), "2026-03-22", "C-1", 4_000));
    f.register("AP", "2000", "payables");
    let ap_from: i128 = f.head().parse().unwrap();
    let bill = f.ok(&[
        "bill",
        "--party",
        "V-1",
        "--number",
        "B-1",
        "--date",
        "2026-03-25",
        "--payable",
        "2000",
        "--expense",
        "6000",
        "--line",
        "amount=\"30.00 USD\"",
        "--evidence",
        &f.evidence,
    ]);
    history.push(("AP", recorded(&bill), "2026-03-25", "V-1", -3_000));
    let head: i128 = f.head().parse().unwrap();

    let dates = [
        "2026-03-13",
        "2026-03-14",
        "2026-03-20",
        "2026-03-21",
        "2026-03-22",
        "2026-03-25",
        "2026-03-31",
    ];
    let mut judged = 0;
    let mut folds = BTreeSet::new();
    for (code, from) in [("AR", ar_from), ("AP", ap_from)] {
        for seq in from..=head {
            let at = seq.to_string();
            for as_of in dates {
                let mut nets = BTreeMap::new();
                for &(subledger, recorded_at, date, party, cents) in &history {
                    if subledger == code && recorded_at <= seq && date <= as_of {
                        *nets.entry(party.to_string()).or_insert(0) += cents;
                    }
                }
                let expected: BTreeMap<String, String> = nets
                    .into_iter()
                    .map(|(party, cents)| (party, usd(cents)))
                    .collect();
                let report = f.verify_as_of(code, as_of, Some(&at));
                let coordinate = format!("{code} known at {at}, as of {as_of}");
                assert_eq!(
                    report.get("reconciled"),
                    Some(&Json::Bool(true)),
                    "{coordinate}"
                );
                for total in rows(&report, "totals") {
                    for (detail, control) in [
                        ("detail_debits", "control_debits"),
                        ("detail_credits", "control_credits"),
                    ] {
                        assert_eq!(total.get(detail), total.get(control), "{coordinate}");
                    }
                }
                let actual: BTreeMap<String, String> = rows(&report, "rows")
                    .iter()
                    .map(|row| (text(row, "party"), text(row, "net")))
                    .collect();
                assert_eq!(actual, expected, "{coordinate}");
                judged += 1;
                folds.insert(format!("{code} {actual:?}"));
            }
        }
    }
    println!(
        "judged {judged} coordinates through head {head}: {} distinct party folds",
        folds.len()
    );
    // AR: none, C-1 alone, both invoices, after the receipt; AP: none, the bill.
    assert_eq!(folds.len(), 6, "{folds:#?}");
}

#[test]
fn partyless_posts_and_legacy_anonymous_registration_refuse_without_publication() {
    let f = Fixture::new();
    let intent = f.file("anonymous.json", r#"{"effective_date":"2026-03-14","idempotency_key":"anonymous","legs":[{"side":"debit","account":"1200","amount":"1.00 USD"},{"side":"credit","account":"4000","amount":"1.00 USD"}]}"#);
    f.register("AR", "1200", "AR");
    let before = f.head();
    let (status, output) = f.run(&["post", "--intent", &intent, "--evidence", &f.evidence]);
    assert_eq!(status, 3, "{output}");
    assert_eq!(text(&data(&output), "refusal_id"), "FA-REF-005");
    assert_eq!(f.head(), before);
    let (status, output) = f.run(&[
        "subledger",
        "add",
        "WRONG",
        "--control",
        "1200",
        "--kind",
        "AP",
    ]);
    assert_ne!(status, 0, "{output}");
    assert_eq!(f.head(), before);

    let legacy = Fixture::new();
    let intent = legacy.file("legacy.json", r#"{"effective_date":"2026-03-14","idempotency_key":"legacy","legs":[{"side":"debit","account":"1200","amount":"1.00 USD"},{"side":"credit","account":"4000","amount":"1.00 USD"}]}"#);
    legacy.ok(&["post", "--intent", &intent, "--evidence", &legacy.evidence]);
    let before = legacy.head();
    let (status, output) = legacy.run(&[
        "subledger",
        "add",
        "AR",
        "--control",
        "1200",
        "--kind",
        "AR",
    ]);
    assert_eq!(status, 3, "{output}");
    assert_eq!(legacy.head(), before);
    assert!(rows(&data(&legacy.ok(&["subledger", "list"])), "subledgers").is_empty());
}

#[test]
fn verify_requires_a_date_and_rejects_flags_that_would_be_silently_ignored() {
    let f = Fixture::new();
    f.register("AR", "1200", "AR");
    let before = f.head();
    for args in [
        vec!["subledger", "verify", "AR"],
        vec!["subledger", "list", "--as-of", "2026-03-31"],
        vec!["subledger", "show", "AR", "--kind", "AP"],
        vec![
            "subledger",
            "verify",
            "AR",
            "--as-of",
            "2026-03-31",
            "--as-of",
            "2026-04-30",
        ],
    ] {
        let (status, output) = f.run(&args);
        assert_eq!(status, 2, "args={args:?}\n{output}");
    }
    assert_eq!(f.head(), before);
}

fn declared_tax_fixture() -> Fixture {
    Fixture::with_additional_accounts(vec![
        json::parse(r#"{"code":"1300","name":"Declared input tax","type":"Asset","unit":"USD"}"#)
            .unwrap(),
        json::parse(
            r#"{"code":"2200","name":"Declared output tax","type":"Liability","unit":"USD"}"#,
        )
        .unwrap(),
    ])
}

#[test]
fn declared_invoice_and_bill_taxes_preserve_gross_plans_maturity_and_retries() {
    let f = declared_tax_fixture();
    f.register("AR", "1200", "receivables");
    f.register("AP", "2000", "payables");
    for (verb, party, control_flag, control, line_flag, account, subledger, lines, amounts, net) in [
        (
            "invoice",
            "C-1",
            "--receivable",
            "1200",
            "--revenue",
            "4000",
            "AR",
            [
                r#"qty=8 unit_price="0.125 USD" tax_amount="0.080 USD" tax_account=2200"#,
                r#"amount="31.5 USD" tax_amount="2.60 USD" tax_account=2200"#,
            ],
            [3518, 100, 3150, 8, 260],
            "35.18 USD",
        ),
        (
            "bill",
            "V-1",
            "--payable",
            "2000",
            "--expense",
            "6000",
            "AP",
            [
                r#"amount="300.25 USD" tax_amount="15.01 USD" tax_account=1300"#,
                r#"qty=3 unit_price="0.25 USD" tax_amount="0.04 USD" tax_account=1300"#,
            ],
            [31605, 30025, 75, 1501, 4],
            "-316.05 USD",
        ),
    ] {
        let args = vec![
            verb,
            "--party",
            party,
            "--number",
            "DECLARED-TAX-1",
            "--date",
            "2026-03-14",
            "--due-date",
            "2026-03-31",
            control_flag,
            control,
            line_flag,
            account,
            "--line",
            lines[0],
            "--line",
            lines[1],
            "--evidence",
            &f.evidence,
        ];
        let path = f.dir.join(format!("{verb}-declared-tax.plan"));
        let path = path.to_str().unwrap();
        let mut review = args.clone();
        review.extend(["--dry-run", "--plan-out", path]);
        let before = f.head();
        let planned = data(&f.ok(&review));
        assert_eq!(f.head(), before, "tax planning must publish nothing");
        let plan = fa::PostPlan::decode(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(
            plan.proposal().legs.len(),
            5,
            "gross, two net lines, two tax legs"
        );
        assert_eq!(
            plan.proposal().evidence.len(),
            1,
            "the source document remains bound"
        );
        for (leg, expected) in plan.proposal().legs.iter().zip(amounts) {
            assert_eq!(leg.amount.mantissa, expected);
        }
        let plan_legs = rows(&planned, "legs");
        assert_eq!(text(&plan_legs[0], "account"), control);
        assert_eq!(text(&plan_legs[1], "account"), account);
        assert_eq!(text(&plan_legs[2], "account"), account);
        let tax_account = if verb == "invoice" { "2200" } else { "1300" };
        for leg in &plan_legs[3..] {
            assert_eq!(text(leg, "account"), tax_account);
            assert_eq!(
                text(leg, "side"),
                if verb == "invoice" { "credit" } else { "debit" }
            );
        }
        let terms = plan
            .proposal()
            .extensions
            .iter()
            .find(|(tag, _)| *tag == fa_model::entry::OBLIGATION_MATURITY_EXTENSION)
            .expect("contractual maturity is part of the sealed proposal");
        let terms = fa_model::obligation::InlineObligationTerms::decode_list(&terms.1).unwrap();
        assert_eq!(terms.len(), 1);
        assert_eq!(terms[0].ordinal, 0);
        assert_eq!(terms[0].installments.len(), 1);
        assert_eq!(
            terms[0].installments[0].amount, amounts[0],
            "the entire gross amount falls due"
        );

        let posted = data(&f.ok(&["commit", "--plan", path]));
        let vid = text(&posted, "vid");
        let after = f.head();
        let shown = data(&f.ok(&["entry", "show", &vid]));
        assert_eq!(
            text(&shown, "proposal_digest"),
            text(&planned, "proposal_digest")
        );
        assert_eq!(text(&data(&f.ok(&args)), "vid"), vid);
        assert_eq!(text(&data(&f.ok(&["commit", "--plan", path])), "vid"), vid);
        assert_eq!(
            f.head(),
            after,
            "typed and saved-plan retries publish no duplicate tax"
        );

        let reconciled = f.verify(subledger, None);
        assert_eq!(reconciled.get("reconciled"), Some(&Json::Bool(true)));
        let party_row = rows(&reconciled, "rows")
            .iter()
            .find(|row| text(row, "party") == party)
            .expect("party gross balance");
        assert_eq!(text(party_row, "net"), net);
        let aging = data(&f.ok(&[
            "gl",
            "aging",
            "--account",
            control,
            "--basis",
            "due-date",
            "--as-of",
            "2026-04-01",
        ]));
        let items = rows(&aging, "items");
        assert_eq!(items.len(), 1);
        assert_eq!(text(&items[0], "due_date"), "2026-03-31");
        assert_eq!(text(&items[0], "open"), usd(amounts[0]));

        let mut changed = args.clone();
        let first_line = changed.iter().position(|value| *value == "--line").unwrap() + 1;
        changed[first_line] = if verb == "invoice" {
            r#"qty=8 unit_price="0.125 USD" tax_amount="0.09 USD" tax_account=2200"#
        } else {
            r#"amount="300.25 USD" tax_amount="15.02 USD" tax_account=1300"#
        };
        let (exit, refused) = f.run(&changed);
        assert_eq!(
            exit, 6,
            "changing a declared tax under the same key conflicts: {refused}"
        );
        assert_eq!(f.head(), after);
    }
    let tb = data(&f.ok(&["tb", "--period", "FY2026-P03"]));
    for (code, net) in [
        ("1200", "35.18 USD"),
        ("4000", "-32.50 USD"),
        ("2200", "-2.68 USD"),
        ("2000", "-316.05 USD"),
        ("6000", "301.00 USD"),
        ("1300", "15.05 USD"),
    ] {
        let row = rows(&tb, "rows")
            .iter()
            .find(|row| text(row, "code") == code)
            .unwrap();
        assert_eq!(text(row, "net"), net, "account {code}");
    }
}

#[test]
fn declared_tax_refuses_incomplete_ambiguous_inexact_and_overflowing_inputs_atomically() {
    let f = declared_tax_fixture();
    let before = f.head();
    let overflow = format!(
        r#"amount="{} USD" tax_amount="1 USD" tax_account=2200"#,
        i128::MAX
    );
    for line in [
        r#"amount="1.00 USD" tax_amount="0.08 USD""#,
        r#"amount="1.00 USD" tax_account=2200"#,
        r#"amount="1.00 USD" tax_amount="0.08 USD" tax_account=1200"#,
        r#"amount="1.00 USD" tax_amount="0.08 USD" tax_account=2200 tax=VAT20"#,
        r#"amount="1.00 USD" tax_amount="0.08 USD" tax_amount="0.09 USD" tax_account=2200"#,
        r#"amount="1.00 USD" tax_amount="0.08 USD" tax_account=2200 tax_account=1300"#,
        r#"amount="1.00 USD" tax_amount="0.08 USD" tax_account="""#,
        r#"amount="1.00 USD" tax_amount="-0.08 USD" tax_account=2200"#,
        r#"amount="1.00 USD" tax_amount="0.00 USD" tax_account=2200"#,
        r#"amount="1.00 USD" tax_amount="8e-2 USD" tax_account=2200"#,
        r#"amount="1.00 USD" tax_amount="0.08" tax_account=2200"#,
        r#"amount="1.00 USD" tax_amount="0.08 EUR" tax_account=2200"#,
        r#"amount="1.00 USD" tax_amount="0.001 USD" tax_account=2200"#,
        r#"qty=3 unit_price="0.125 USD" tax_amount="0.08 USD" tax_account=2200"#,
        r#"qty=1.5 unit_price="2.00 USD" tax_amount="0.08 USD" tax_account=2200"#,
        &overflow,
    ] {
        let (exit, output) = f.run(&[
            "invoice",
            "--party",
            "C-1",
            "--number",
            "INVALID-TAX",
            "--date",
            "2026-03-14",
            "--receivable",
            "1200",
            "--revenue",
            "4000",
            "--line",
            line,
            "--evidence",
            &f.evidence,
        ]);
        assert_eq!(exit, 2, "line={line}: {output}");
        assert_eq!(f.head(), before, "malformed taxes never publish: {line}");
    }
    let (exit, output) = f.run(&[
        "invoice",
        "--party",
        "C-1",
        "--number",
        "UNKNOWN-TAX-ACCOUNT",
        "--date",
        "2026-03-14",
        "--receivable",
        "1200",
        "--revenue",
        "4000",
        "--line",
        r#"amount="1.00 USD" tax_amount="0.08 USD" tax_account=UNKNOWN"#,
        "--evidence",
        &f.evidence,
    ]);
    assert_eq!(exit, 3, "an unregistered tax account refuses: {output}");
    assert!(output.contains("FA-REF-004"), "{output}");
    assert_eq!(f.head(), before, "an unknown tax account never publishes");
}

#[test]
fn declared_tax_drafts_promote_the_reviewed_gross_amount_and_reverse_exactly() {
    let f = declared_tax_fixture();
    f.register("AR", "1200", "receivables");
    f.ok(&["draft", "new", "declared-taxes", "--as", "tax-preparer"]);
    let baseline = data(&f.ok(&["tb", "--period", "FY2026-P03"]));
    let args = [
        "invoice",
        "--party",
        "C-1",
        "--number",
        "DRAFT-TAX",
        "--date",
        "2026-03-14",
        "--receivable",
        "1200",
        "--revenue",
        "4000",
        "--line",
        r#"amount="100.00 USD" tax_amount="8.25 USD" tax_account=2200"#,
        "--evidence",
        &f.evidence,
        "--draft",
        "declared-taxes",
        "--as",
        "tax-preparer",
    ];
    let planned = data(&f.ok(&args));
    let planned_at = f.head();
    let vid = text(&planned, "entry");
    assert_eq!(text(&data(&f.ok(&args)), "entry"), vid);
    assert_eq!(f.head(), planned_at, "draft retry records no second plan");
    assert_eq!(
        rows(&data(&f.ok(&["tb", "--period", "FY2026-P03"])), "rows"),
        rows(&baseline, "rows"),
        "draft tax does not affect trunk",
    );
    let rehearsed = data(&f.ok(&[
        "tb",
        "--period",
        "FY2026-P03",
        "--branch",
        "draft:declared-taxes",
    ]));
    let (exit, refused) = f.run(&[
        "draft",
        "promote",
        "declared-taxes",
        "--as",
        "tax-preparer",
        "--yes",
    ]);
    assert_eq!(exit, 7, "the tax preparer cannot self-promote: {refused}");
    assert_eq!(f.head(), planned_at);
    f.ok(&[
        "draft",
        "promote",
        "declared-taxes",
        "--as",
        "controller",
        "--yes",
    ]);
    let shown = data(&f.ok(&["entry", "show", &vid]));
    assert_eq!(
        text(&shown, "proposal_digest"),
        text(&planned, "proposal_digest")
    );
    assert_eq!(
        rows(&data(&f.ok(&["tb", "--period", "FY2026-P03"])), "rows"),
        rows(&rehearsed, "rows"),
        "promotion retains every net, tax and gross effect",
    );
    assert_eq!(
        text(&rows(&f.verify("AR", None), "rows")[0], "net"),
        "108.25 USD"
    );
    f.ok(&[
        "reverse",
        &vid,
        "--effective",
        "2026-03-20",
        "--reason",
        "WrongAmount",
        "--evidence",
        &f.evidence,
    ]);
    let tb = data(&f.ok(&["tb", "--period", "FY2026-P03"]));
    for row in rows(&tb, "rows") {
        assert_eq!(
            text(row, "net"),
            "0.00 USD",
            "reversal leaves no tax: {row:?}"
        );
    }
    let ar = f.verify("AR", None);
    assert_eq!(ar.get("reconciled"), Some(&Json::Bool(true)));
    assert!(
        rows(&ar, "rows")
            .iter()
            .all(|row| text(row, "net") == "0.00 USD")
    );
}

#[test]
fn declared_tax_on_inventory_invoices_preserves_line_ordinals_and_native_cost_relief() {
    let f = declared_tax_fixture();
    let chart = f.file(
        "stock-chart.json",
        r#"{"accounts":[
        {"code":"1400","name":"Inventory","type":"Asset","unit":"any"},
        {"code":"1499","name":"Quantity offset","type":"Equity","unit":"SHARE"},
        {"code":"5100","name":"Cost of goods sold","type":"Expense","unit":"USD"}
    ]}"#,
    );
    f.ok(&["chart", "import", &chart]);
    f.ok(&[
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
        "stock-policy",
    ]);
    let acquisition = f.file(
        "stock-acquisition.json",
        r#"{
        "effective_date":"2026-03-05","idempotency_key":"stock-acquisition","legs":[
        {"side":"debit","account":"1400","amount":"10.000000 SHARE"},
        {"side":"credit","account":"1499","amount":"10.000000 SHARE"},
        {"side":"debit","account":"1400","amount":"100.00 USD"},
        {"side":"credit","account":"1000","amount":"100.00 USD"}]}
    "#,
    );
    f.ok(&["post", "--intent", &acquisition, "--evidence", &f.evidence]);
    let args = [
        "invoice",
        "--party",
        "C-1",
        "--number",
        "TAXED-STOCK",
        "--date",
        "2026-03-14",
        "--receivable",
        "1200",
        "--revenue",
        "4000",
        "--line",
        r#"amount="10.00 USD" description=delivery tax_amount="0.80 USD" tax_account=2200"#,
        "--line",
        r#"qty=3 unit_price="25.00 USD" inventory=1400 quantity_unit=SHARE quantity_offset=1499 cost_offset=5100 lot_law=FIFO tax_amount="6.00 USD" tax_account=2200"#,
        "--evidence",
        &f.evidence,
    ];
    let path = f.dir.join("taxed-stock.plan");
    let path = path.to_str().unwrap();
    let before = f.head();
    let mut preview = args.to_vec();
    preview.extend(["--dry-run", "--plan-out", path]);
    f.ok(&preview);
    assert_eq!(f.head(), before);
    let plan = fa::BatchPlan::decode(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(plan.prepared_entries().len(), 2);
    let sale = plan
        .prepared_entries()
        .iter()
        .find(|entry| entry.proposal.lot_disposal_basis().unwrap().is_none())
        .unwrap();
    assert_eq!(
        sale.proposal
            .legs
            .iter()
            .map(|leg| leg.amount.mantissa)
            .collect::<Vec<_>>(),
        [9180, 1000, 7500, 80, 600],
        "tax legs never displace the stock line's ordinal"
    );
    let cost = plan
        .prepared_entries()
        .iter()
        .find(|entry| entry.proposal.lot_disposal_basis().unwrap().is_some())
        .unwrap();
    assert_eq!(cost.proposal.legs[0].amount.mantissa, 3_000_000);
    assert_eq!(
        cost.proposal.legs[2].amount.mantissa, 3_000,
        "tax and sale price never supply native lot cost"
    );
    f.ok(&["commit", "--plan", path, "--grant", "read"]);
    let after = f.head();
    f.ok(&args);
    assert_eq!(
        f.head(),
        after,
        "inventory retry publishes neither tax nor cost twice"
    );
    let tb = data(&f.ok(&["tb", "--period", "FY2026-P03"]));
    for (code, net) in [
        ("1200", "91.80 USD"),
        ("4000", "-85.00 USD"),
        ("2200", "-6.80 USD"),
        ("5100", "30.00 USD"),
    ] {
        let row = rows(&tb, "rows")
            .iter()
            .find(|row| text(row, "code") == code)
            .unwrap();
        assert_eq!(text(row, "net"), net, "account {code}");
    }
}
