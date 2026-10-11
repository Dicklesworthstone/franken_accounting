//! Chart templates on real persisted books (plan §4.3, bead fa-48m), and the
//! kernel's forest law for every chart: unique codes, no parent cycles.
//!
//! Every step logs what it ran and what it saw.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};
use fa_cli::verbs::registry;

fn run(book: Option<&Path>, args: &[&str]) -> (i32, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fa"));
    if let Some(book) = book {
        command.arg("--book").arg(book);
    }
    let result = command
        .args(args)
        .env_remove("FA_BOOK")
        .output()
        .expect("run fa");
    let code = result.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&result.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&result.stderr).into_owned();
    eprintln!(
        "[templates-test] fa {} → exit {code}\n  stdout: {}\n  stderr: {}",
        args.join(" "),
        stdout.trim(),
        stderr.trim()
    );
    if args.contains(&"--json") {
        let lines: Vec<_> = stdout.lines().collect();
        assert_eq!(lines.len(), 1, "args={args:?}: {stdout}\n{stderr}");
        let checked = registry().expect("verb registry").check_line(lines[0]);
        assert!(checked.is_ok(), "args={args:?}: {checked:?}\n{stdout}");
    }
    (code, stdout, stderr)
}

fn ok(book: &Path, args: &[&str]) -> Json {
    let (code, stdout, stderr) = run(Some(book), args);
    assert_eq!(code, 0, "args={args:?}\n{stdout}\n{stderr}");
    json::parse(stdout.trim()).expect("one JSON line")
}

fn data<'a>(line: &'a Json, key: &str) -> &'a Json {
    line.get("data")
        .and_then(|d| d.get(key))
        .expect("data field")
}

fn refused(book: &Path, args: &[&str]) -> (i32, String, String) {
    let (code, stdout, _) = run(Some(book), args);
    let line = json::parse(stdout.trim()).expect("one JSON line");
    assert_eq!(line.get("event").and_then(Json::as_str), Some("error"));
    let field = |k: &str| {
        line.get("data")
            .and_then(|d| d.get(k))
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_string()
    };
    (code, field("refusal_id"), field("message"))
}

fn fixture() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fa-templates-cli-{}-{id}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) => assert_eq!(
                error.kind(),
                std::io::ErrorKind::AlreadyExists,
                "create retained fixture {}: {error}",
                path.display()
            ),
        }
    }
}

fn write(dir: &Path, name: &str, contents: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write fixture");
    path.display().to_string()
}

fn unit_of(accounts: &[Json], code: &str) -> String {
    accounts
        .iter()
        .find(|a| a.get("code").and_then(Json::as_str) == Some(code))
        .and_then(|a| a.get("unit").and_then(Json::as_str))
        .unwrap_or_default()
        .to_string()
}

#[test]
fn templates_list_without_a_book_and_import_into_any_base_unit() {
    let (code, stdout, stderr) = run(None, &["chart", "templates", "--json"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let listed = json::parse(stdout.trim()).expect("one JSON line");
    assert_eq!(listed.get("book"), Some(&Json::Null));
    let templates = data(&listed, "templates").as_arr().expect("templates");
    let names: Vec<&str> = templates
        .iter()
        .map(|t| t.get("name").and_then(Json::as_str).unwrap_or_default())
        .collect();
    assert_eq!(names, ["ifrs-sme", "us-bank-call-report", "us-gaap-smb"]);

    let dir = fixture();
    for template in &names {
        let book = dir.join(format!("{template}-book"));
        ok(
            &book,
            &["book", "create", "--name", "Template Co", "--json"],
        );
        let installed = ok(
            &book,
            &["chart", "import", "--template", template, "--json"],
        );
        assert_eq!(data(&installed, "template").as_str(), Some(*template));
        let listed = templates
            .iter()
            .find(|t| t.get("name").and_then(Json::as_str) == Some(*template))
            .expect("listed");
        assert_eq!(
            data(&installed, "accounts"),
            listed.get("accounts").expect("count")
        );
        let accounts = ok(&book, &["chart", "list", "--json"]);
        let accounts = data(&accounts, "accounts").as_arr().expect("accounts");
        assert!(
            accounts
                .iter()
                .filter(|a| a.get("leaf") == Some(&Json::Bool(true)))
                .all(|a| a.get("unit").and_then(Json::as_str) == Some("USD")),
            "{template}: every leaf posts in the book's base unit"
        );
    }

    // A EUR book gets EUR leaves from the same template, and says so.
    let eur = dir.join("eur-book");
    ok(
        &eur,
        &[
            "book",
            "create",
            "--name",
            "Euro Co",
            "--base-unit",
            "EUR",
            "--json",
        ],
    );
    let info = ok(&eur, &["book", "info", "--json"]);
    assert_eq!(data(&info, "base_unit").as_str(), Some("EUR"));
    ok(
        &eur,
        &["chart", "import", "--template", "us-gaap-smb", "--json"],
    );
    let accounts = ok(&eur, &["chart", "list", "--json"]);
    let accounts = data(&accounts, "accounts").as_arr().expect("accounts");
    assert_eq!(unit_of(accounts, "1200"), "EUR");
    assert_eq!(unit_of(accounts, "1"), "any", "summaries take no legs");

    // The README's codes: post a sale to receivables and revenue, read it back.
    let book = dir.join("us-gaap-smb-book");
    ok(
        &book,
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    ok(&book, &["period", "open", "FY2026-P03", "--json"]);
    let receipt = write(
        &dir,
        "invoice.txt",
        "Invoice 10442: 10 widgets, 1,250.00 USD.",
    );
    let document = ok(
        &book,
        &[
            "document",
            "add",
            &receipt,
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
            "--json",
        ],
    );
    let oid = data(&document, "oid").as_str().expect("oid").to_string();
    let intent = write(
        &dir,
        "invoice.json",
        r#"{"effective_date":"2026-03-14","idempotency_key":"inv-10442","legs":[{"side":"debit","account":"1200","amount":"1250.00 USD"},{"side":"credit","account":"4000","amount":"1250.00 USD"}]}"#,
    );
    ok(
        &book,
        &["post", "--intent", &intent, "--evidence", &oid, "--json"],
    );
    let tb = ok(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    let rows = data(&tb, "rows").as_arr().expect("rows");
    let codes: Vec<&str> = rows
        .iter()
        .map(|r| r.get("code").and_then(Json::as_str).unwrap_or_default())
        .collect();
    assert_eq!(codes, ["1200", "4000"]);
    assert_eq!(data(&tb, "balanced"), &Json::Bool(true));
}

#[test]
fn a_template_imports_once_and_a_chart_must_be_a_forest_of_unique_codes() {
    let dir = fixture();
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Forest Co", "--json"]);
    ok(
        &book,
        &["chart", "import", "--template", "us-gaap-smb", "--json"],
    );

    // Its identity exists: a second import is refused, never doubled.
    let (code, id, message) = refused(
        &book,
        &["chart", "import", "--template", "us-gaap-smb", "--json"],
    );
    assert_eq!((code, id.as_str()), (2, "FA-REF-100"), "{message}");
    assert!(message.contains("already exists"), "{message}");

    // A file and a template, or an unknown template, are usage errors.
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"9000","name":"Suspense","type":"Asset","unit":"base"}]}"#,
    );
    let (code, _, message) = refused(
        &book,
        &[
            "chart",
            "import",
            &chart,
            "--template",
            "us-gaap-smb",
            "--json",
        ],
    );
    assert_eq!(code, 2, "{message}");
    let (code, _, message) = refused(
        &book,
        &["chart", "import", "--template", "us-gaap", "--json"],
    );
    assert_eq!(code, 2, "{message}");
    assert!(message.contains("unknown chart template"), "{message}");

    // The kernel refuses a duplicate code and a parent cycle before writing.
    let fresh = dir.join("fresh");
    ok(&fresh, &["book", "create", "--name", "Fresh Co", "--json"]);
    let duplicate = write(
        &dir,
        "duplicate.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"base"},{"code":"1000","name":"Cash again","type":"Asset","unit":"base"}]}"#,
    );
    let (code, id, message) = refused(&fresh, &["chart", "import", &duplicate, "--json"]);
    assert_eq!((code, id.as_str()), (2, "FA-REF-100"), "{message}");
    assert!(message.contains("more than once"), "{message}");
    let cycle = write(
        &dir,
        "cycle.json",
        r#"{"accounts":[{"code":"A","name":"A","type":"Asset","leaf":false,"parent":"B"},{"code":"B","name":"B","type":"Asset","leaf":false,"parent":"A"},{"code":"1000","name":"Cash","type":"Asset","unit":"base","parent":"A"}]}"#,
    );
    let (code, id, message) = refused(&fresh, &["chart", "import", &cycle, "--json"]);
    assert_eq!((code, id.as_str()), (2, "FA-REF-100"), "{message}");
    assert!(message.contains("its own ancestor"), "{message}");
    let own_parent = write(
        &dir,
        "own-parent.json",
        r#"{"accounts":[{"code":"S","name":"S","type":"Asset","leaf":false,"parent":"S"}]}"#,
    );
    let (code, id, message) = refused(&fresh, &["chart", "import", &own_parent, "--json"]);
    assert_eq!((code, id.as_str()), (2, "FA-REF-100"), "{message}");
    assert!(message.contains("its own ancestor"), "{message}");

    // Nothing was written by any refusal: the fresh book has no accounts.
    let accounts = ok(&fresh, &["chart", "list", "--json"]);
    assert!(
        data(&accounts, "accounts")
            .as_arr()
            .expect("accounts")
            .is_empty()
    );
    // And `base` in a file means the base unit too.
    let installed = ok(&fresh, &["chart", "import", &chart, "--json"]);
    assert_eq!(data(&installed, "template"), &Json::Null);
    let accounts = ok(&fresh, &["chart", "list", "--json"]);
    assert_eq!(
        unit_of(
            data(&accounts, "accounts").as_arr().expect("accounts"),
            "9000"
        ),
        "USD"
    );
}
