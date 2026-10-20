//! fa-715: a head trial balance says how it was answered (plan §5.3, §17).
//! Before any register is maintained the journal is folded and the reason
//! says how to change that; once `fa registers advance` has run, maintained
//! cells plus the exact tail answer with the same rows as the literal fold,
//! in a new process as well.

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
    let code = result.status.code().unwrap_or(-1);
    let stdout = String::from_utf8(result.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8_lossy(&result.stderr);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "args={args:?}\n{stdout}\n{stderr}");
    let checked = fa_cli::verbs::registry()
        .expect("registry")
        .check_line(lines[0]);
    assert!(
        checked.is_ok(),
        "args={args:?}: {checked:?}\n{stdout}\n{stderr}"
    );
    (code, json::parse(lines[0]).expect("one robot line"))
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
    let field = get(value, key);
    let Json::Int(number) = field else {
        assert!(
            matches!(field, Json::Int(_)),
            "{key} must be an integer: {field:?}"
        );
        return 0;
    };
    *number
}

fn write(dir: &Path, name: &str, contents: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write fixture");
    path.display().to_string()
}

/// A book with Cash and Revenue, FY2026's periods, March open, and one
/// receipt document to cite.
fn fixture() -> (PathBuf, PathBuf, String) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("fa-served-{}-{n}", std::process::id()));
        match std::fs::create_dir(&dir) {
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            created => {
                created.expect("create the fixture directory");
                break dir;
            }
        }
    };
    let book = dir.join("book");
    ok(&book, &["book", "create", "--name", "Served Co"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    );
    ok(&book, &["chart", "import", &chart]);
    ok(&book, &["period", "create", "--fiscal-year", "2026"]);
    ok(&book, &["period", "open", "FY2026-P03"]);
    let source = write(&dir, "receipt.txt", "Receipt for the served-read fixture.");
    let document = ok(
        &book,
        &[
            "document",
            "add",
            &source,
            "--kind",
            "Receipt",
            "--grade",
            "HumanUpload",
        ],
    );
    let evidence = text(&document, "oid").to_string();
    (dir, book, evidence)
}

fn post(dir: &Path, book: &Path, evidence: &str, key: &str, amount: &str) {
    let intent = write(
        dir,
        &format!("{key}.json"),
        &format!(
            r#"{{"effective_date":"2026-03-10","idempotency_key":"{key}","legs":[{{"side":"debit","account":"1000","amount":"{amount} USD"}},{{"side":"credit","account":"4000","amount":"{amount} USD"}}]}}"#
        ),
    );
    ok(book, &["post", "--intent", &intent, "--evidence", evidence]);
}

/// The same rows as a literal fold at the read's own head.
fn assert_literal_rows(book: &Path, read: &Json, activity: bool) {
    let known_at = integer(read, "known_at").to_string();
    let mut args = vec!["tb", "--period", "FY2026-P03", "--as-known-at", &known_at];
    if activity {
        args.push("--activity");
    }
    let literal = ok(book, &args);
    assert_eq!(get(&literal, "served"), &Json::Null, "{}", literal.render());
    assert_eq!(
        get(read, "rows"),
        get(&literal, "rows"),
        "{}",
        read.render()
    );
    assert_eq!(get(read, "unit_totals"), get(&literal, "unit_totals"));
}

#[test]
fn head_trial_balances_say_how_they_were_served_and_registers_answer_them() {
    let (dir, book, evidence) = fixture();
    post(&dir, &book, &evidence, "first", "5.00");

    let folded = ok(&book, &["tb", "--period", "FY2026-P03"]);
    let served = get(&folded, "served");
    assert_eq!(text(served, "mode"), "literal", "{}", folded.render());
    assert_eq!(get(served, "tail_length"), &Json::Null);
    let reason = text(served, "reason");
    assert!(
        reason.contains("FY2026-P03") && reason.contains("fa registers advance"),
        "{reason}"
    );
    assert_literal_rows(&book, &folded, false);

    // The one period with postings; the others contribute nothing.
    ok(&book, &["registers", "advance", "--period", "FY2026-P03"]);
    for activity in [false, true] {
        let mut args = vec!["tb", "--period", "FY2026-P03"];
        if activity {
            args.push("--activity");
        }
        let read = ok(&book, &args);
        let served = get(&read, "served");
        assert_eq!(text(served, "mode"), "maintained", "{}", read.render());
        assert_eq!(integer(served, "tail_length"), 0, "{}", read.render());
        assert_literal_rows(&book, &read, activity);
    }

    // A posting after the cursors is folded from the tail, once per
    // maintained contributing period, in a new process.
    post(&dir, &book, &evidence, "second", "7.00");
    let read = ok(&book, &["tb", "--period", "FY2026-P03"]);
    let served = get(&read, "served");
    assert_eq!(text(served, "mode"), "maintained", "{}", read.render());
    let periods = get(served, "periods").as_arr().expect("served periods");
    assert!(
        periods
            .iter()
            .any(|p| text(p, "period") == "FY2026-P03" && integer(p, "tail_entries") == 1),
        "{}",
        read.render()
    );
    assert!(
        periods.iter().all(|p| integer(p, "tail_entries") == 1),
        "{}",
        read.render()
    );
    assert_eq!(
        integer(served, "tail_length"),
        i128::try_from(periods.len()).expect("period count"),
    );
    assert_literal_rows(&book, &read, false);
}
