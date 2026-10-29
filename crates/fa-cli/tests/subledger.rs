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

#[path = "subledger/certificate.rs"]
mod certificate;

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
