//! End-to-end native AR/AP subledgers through the real persisted CLI.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};
use fa_cli::verbs::registry;

#[path = "subledger/external.rs"]
mod external;

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
        let chart = f.file("chart.json", r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1200","name":"Receivables","type":"Asset","unit":"USD"},{"code":"2000","name":"Payables","type":"Liability","unit":"USD"},{"code":"4000","name":"Sales","type":"Revenue","unit":"USD"},{"code":"6000","name":"Expense","type":"Expense","unit":"USD"}]}"#);
        f.ok(&["chart", "import", &chart]);
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
        let mut args = vec!["subledger", "verify", code, "--as-of", "2026-03-31"];
        if let Some(at) = at {
            args.extend(["--as-known-at", at]);
        }
        data(&self.ok(&args))
    }
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
