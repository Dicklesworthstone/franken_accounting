//! Binary-level regression tests for the agent contract (plan §15.3; fa-coa
//! examples): exit codes per refusal, stdout data / stderr diagnostics, empty
//! results exit 0, bare `fa` prints triage, typos get a suggestion.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fa(dir: Option<&Path>, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fa"));
    if let Some(d) = dir {
        cmd.arg("--book").arg(d);
    }
    cmd.args(args);
    cmd.env_remove("FA_BOOK");
    let out = cmd.output().expect("run fa");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("fa-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write(dir: &Path, name: &str, text: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, text).unwrap();
    p.display().to_string()
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\":");
    let i = line.find(&pat)? + pat.len();
    let rest = &line[i..];
    if let Some(r) = rest.strip_prefix('"') {
        r.split('"').next()
    } else {
        rest.split([',', '}']).next()
    }
}

#[test]
fn bare_fa_prints_triage_and_exits_zero_without_a_tui() {
    let (code, out, err) = fa(None, &[]);
    assert_eq!(code, 0);
    assert!(
        out.contains("fa book create") && out.contains("exit codes"),
        "{out}"
    );
    assert!(err.is_empty(), "stderr must be empty on success: {err}");
    let (code, out, _) = fa(None, &["--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("verify registers"));
}

#[test]
fn typos_are_usage_errors_with_a_suggestion_and_exit_2_never_1() {
    let (code, out, err) = fa(None, &["tb", "--jsno"]);
    assert_eq!(code, 2);
    assert!(
        out.is_empty(),
        "usage errors go to stderr in human mode: {out}"
    );
    assert!(err.contains("--json"), "{err}");
    let (code, out, _) = fa(None, &["perod", "--json"]);
    assert_eq!(code, 2);
    assert!(
        out.contains("\"event\":\"usage_error\"") && out.contains("fa period"),
        "{out}"
    );
    let (code, _, err) = fa(None, &["tb"]);
    assert_eq!(code, 2);
    assert!(err.contains("--book"));
}

#[test]
fn capabilities_and_robot_docs_are_in_tool() {
    let (code, out, _) = fa(None, &["capabilities", "--json"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("\"event\":\"capabilities\"")
            && out.contains("\"code\":8")
            && !out.contains("\"code\":1,"),
        "{out}"
    );
    let (code, out, _) = fa(None, &["robot-docs", "exit-codes"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("7 safety") && out.contains("8 verification"),
        "{out}"
    );
    let (code, _, _) = fa(None, &["robot-docs", "guide"]);
    assert_eq!(code, 0);
}

#[test]
fn the_genesis_workflow_end_to_end_with_the_exit_code_contract() {
    let dir = tmp("genesis");
    let book = dir.join("book");

    // No book yet: environment error, exit 4.
    let (code, out, _) = fa(Some(&book), &["book", "info", "--json"]);
    assert_eq!(code, 4, "{out}");
    assert!(out.contains("\"event\":\"error\""));

    let (code, out, err) = fa(
        Some(&book),
        &["book", "create", "--name", "Test Co", "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("\"event\":\"book_created\""));
    assert!(book.join("book.keys").exists() && book.join("store").exists());
    let (code, _, err) = fa(Some(&book), &["book", "create", "--name", "Test Co"]);
    assert_ne!(code, 0, "keys are never overwritten: {err}");

    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1","name":"Assets","type":"Asset","leaf":false,"unit":"USD"},{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD","parent":"1"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    let (code, out, err) = fa(Some(&book), &["chart", "import", &chart, "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("\"event\":\"chart_installed\"") && out.contains("\"accounts\":3"));
    let (code, out, _) = fa(Some(&book), &["chart", "list", "--json"]);
    assert_eq!(code, 0);
    assert!(out.contains("\"code\":\"1000\"") && out.contains("\"leaf\":false"));

    let (code, out, err) = fa(
        Some(&book),
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let (code, out, _) = fa(Some(&book), &["period", "list", "--json"]);
    assert_eq!(code, 0);
    assert!(out.contains("\"state\":\"Future\""));
    let march = "FY2026-P03";
    let (code, out, err) = fa(Some(&book), &["period", "open", march, "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("\"from\":\"Future\"") && out.contains("\"to\":\"Open\""));

    let intent = write(
        &dir,
        "entry.json",
        r#"{"class":"Original","effective_date":"2026-03-15","description":"March rent","idempotency_key":"inv-1001","legs":[{"side":"debit","account":"6000","amount":"1500.00 USD"},{"side":"credit","account":"1000","amount":"1500.00 USD"}]}"#,
    );
    let (code, out, err) = fa(Some(&book), &["post", "--intent", &intent, "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(
        out.contains("\"event\":\"posted\"") && out.contains(&format!("\"period\":\"{march}\"")),
        "{out}"
    );
    assert!(err.is_empty(), "stderr empty on success: {err}");
    let vid = field(&out, "vid").unwrap().to_string();
    let digest = field(&out, "entry_digest").unwrap().to_string();

    // Same intent again: recorded, exit 0, same digest.
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &intent, "--json"]);
    assert_eq!(code, 0);
    assert!(out.contains("\"event\":\"recorded\""), "{out}");
    assert_eq!(field(&out, "entry_digest"), Some(digest.as_str()));

    // Read it back by vid.
    let (code, out, _) = fa(Some(&book), &["entry", "show", &vid, "--json"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("\"found\":true") && out.contains("\"1500.00 USD\""),
        "{out}"
    );

    // Unbalanced: exit 3, refusal object on stdout, nothing invented.
    let bad = write(
        &dir,
        "bad.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"inv-1002","legs":[{"side":"debit","account":"6000","amount":"1500.00 USD"},{"side":"credit","account":"1000","amount":"1499.99 USD"}]}"#,
    );
    let (code, out, err) = fa(Some(&book), &["post", "--intent", &bad, "--json"]);
    assert_eq!(code, 3, "{out}\n{err}");
    assert!(
        out.contains("\"event\":\"refusal\"")
            && out.contains("\"code\":\"FA-REF-001\"")
            && out.contains("\"fix\":\""),
        "{out}"
    );
    assert!(
        err.contains("FA-REF-001"),
        "diagnostics on stderr too: {err}"
    );

    // A float amount is a usage error, not a rounding.
    let float = write(
        &dir,
        "float.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"inv-1003","legs":[{"side":"debit","account":"6000","amount":1500.5},{"side":"credit","account":"1000","amount":"1500.50 USD"}]}"#,
    );
    let (code, _, err) = fa(Some(&book), &["post", "--intent", &float]);
    assert_eq!(code, 2);
    assert!(err.contains("amounts as strings"), "{err}");

    // Trial balance nets to zero; registers verify; then a close makes posting a safety block.
    let (code, out, _) = fa(Some(&book), &["tb", "--period", march, "--json"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("\"balanced\":true") && out.contains("\"code\":\"6000\""),
        "{out}"
    );
    let (code, out, _) = fa(
        Some(&book),
        &["registers", "materialize", "--period", march, "--json"],
    );
    assert_eq!(code, 0, "{out}");
    let (code, out, _) = fa(
        Some(&book),
        &["verify", "registers", "--period", march, "--json"],
    );
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("\"event\":\"registers_verified\""));

    let late = write(
        &dir,
        "late.json",
        r#"{"effective_date":"2026-03-20","idempotency_key":"inv-2001","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    let (code, _, _) = fa(Some(&book), &["period", "soft-close", march]);
    assert_eq!(code, 0);
    let (code, _, _) = fa(Some(&book), &["period", "close", march]);
    assert_eq!(code, 0);
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &late, "--json"]);
    assert_eq!(code, 7, "{out}");
    assert!(
        out.contains("\"code\":\"FA-REF-010\"") && out.contains("Closed"),
        "{out}"
    );
    // An illegal transition is a safety block too; a stale register after a post is a verification failure (exit 8).
    let (code, out, _) = fa(Some(&book), &["period", "open", march, "--json"]);
    assert_eq!(code, 7, "{out}");
    let (code, _, _) = fa(Some(&book), &["period", "reopen", march, "--to", "open"]);
    assert_eq!(code, 0);
    let (code, _, _) = fa(Some(&book), &["post", "--intent", &late]);
    assert_eq!(code, 0);
    let (code, out, err) = fa(
        Some(&book),
        &["verify", "registers", "--period", march, "--json"],
    );
    assert_eq!(code, 8, "{out}\n{err}");
    assert!(out.contains("\"event\":\"verification_failed\""), "{out}");

    // Human mode on the same book: plain text, no JSON.
    let (code, out, _) = fa(Some(&book), &["book", "info"]);
    assert_eq!(code, 0);
    assert!(
        !out.contains("\"event\"") && out.contains("accounts"),
        "{out}"
    );
}
