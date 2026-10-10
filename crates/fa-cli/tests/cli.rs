//! Binary-level regression tests for the agent contract (plan §15.3; fa-coa
//! examples): exit codes per refusal, stdout data / stderr diagnostics, empty
//! results exit 0, bare `fa` prints triage, typos get a suggestion.
//!
//! Every call that passes `--json` is also a robot-schema conformance check:
//! each stdout line must match its event's schema in `registries/verbs.toml`
//! (what `fa robot-docs schema` prints), a success emits no error event, and
//! a failure emits exactly one, last, carrying the process's exit code.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};
use fa_cli::verbs::registry;

const ERROR_EVENTS: &[&str] = &["usage_error", "refusal", "error", "verification_failed"];

/// The robot-mode contract over one call's stdout; returns its event names.
fn check_robot_output(args: &[&str], code: i32, stdout: &str) -> Vec<String> {
    let reg = registry().expect("verbs.toml");
    let mut events = Vec::new();
    for line in stdout.lines() {
        let checked = reg.check_line(line);
        assert!(
            checked.is_ok(),
            "args={args:?}\n{}",
            checked.clone().err().unwrap_or_default()
        );
        events.push(checked.unwrap_or_default().to_string());
    }
    assert!(
        !events.is_empty(),
        "robot mode is never silent: args={args:?}"
    );
    let errors: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| ERROR_EVENTS.contains(&e.as_str()))
        .map(|(i, _)| i)
        .collect();
    if code == 0 {
        assert!(
            errors.is_empty(),
            "exit 0 with an error event: args={args:?}\n{stdout}"
        );
    } else {
        assert_eq!(
            errors,
            vec![events.len() - 1],
            "a failure emits exactly one error event, last: args={args:?}\n{stdout}"
        );
        let last = stdout.lines().last().unwrap_or_default();
        assert_eq!(
            field(last, "exit"),
            Some(code.to_string().as_str()),
            "the error event names the exit code: args={args:?}"
        );
    }
    events
}

fn fa(dir: Option<&Path>, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fa"));
    if let Some(d) = dir {
        cmd.arg("--book").arg(d);
    }
    cmd.args(args);
    cmd.env_remove("FA_BOOK");
    let out = cmd.output().expect("run fa");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if args.contains(&"--json") {
        check_robot_output(args, code, &stdout);
    }
    (
        code,
        stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn tmp(name: &str) -> std::io::Result<PathBuf> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("fa-cli-{}-{name}-{n}", std::process::id()));
        match std::fs::create_dir(&d) {
            Ok(()) => return Ok(d),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("create retained CLI fixture {}: {e}", d.display()),
                ));
            }
        }
    }
}

fn write(dir: &Path, name: &str, text: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, text).unwrap();
    p.display().to_string()
}

/// Record one source document in `book` and return its oid: the evidence an
/// Original, Pending, or Adjusting entry cites (`--evidence <oid>`).
fn source_doc(dir: &Path, book: &Path) -> String {
    let f = write(dir, "source.txt", "INVOICE (cli fixture source document)");
    let (code, out, err) = fa(
        Some(book),
        &[
            "document",
            "add",
            &f,
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let oid = field(&out, "oid").unwrap_or_default().to_string();
    assert_eq!(oid.len(), 64, "{out}");
    oid
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

fn report(book: &Path, args: &[&str]) -> String {
    let (code, out, err) = fa(Some(book), args);
    assert_eq!(code, 0, "args={args:?}\nstdout={out}\nstderr={err}");
    assert!(err.is_empty(), "args={args:?}\nstderr={err}");
    assert_eq!(field(&out, "event"), Some("trial_balance"), "{out}");
    out
}

fn assert_cash_credits(out: &str, expected: &str) {
    let cash = out
        .split('{')
        .find(|row| field(row, "code") == Some("1000"))
        .expect("cash row in trial balance");
    assert_eq!(field(cash, "debits"), Some("0.00 USD"), "{out}");
    assert_eq!(field(cash, "credits"), Some(expected), "{out}");
    assert_eq!(field(cash, "debits_pending"), Some("0.00 USD"), "{out}");
    assert_eq!(field(cash, "credits_pending"), Some("0.00 USD"), "{out}");
    assert_eq!(
        field(cash, "net"),
        Some(format!("-{expected}").as_str()),
        "{out}"
    );
    assert_eq!(field(out, "balanced"), Some("true"), "{out}");
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
fn the_genesis_workflow_end_to_end_with_the_exit_code_contract() -> std::io::Result<()> {
    let dir = tmp("genesis")?;
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
    let ev = source_doc(&dir, &book);

    let intent = write(
        &dir,
        "entry.json",
        r#"{"class":"Original","effective_date":"2026-03-15","description":"March rent","idempotency_key":"inv-1001","legs":[{"side":"debit","account":"6000","amount":"1500.00 USD"},{"side":"credit","account":"1000","amount":"1500.00 USD"}]}"#,
    );
    let (code, out, err) = fa(
        Some(&book),
        &["post", "--intent", &intent, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(
        out.contains("\"event\":\"posted\"") && out.contains(&format!("\"period\":\"{march}\"")),
        "{out}"
    );
    assert!(err.is_empty(), "stderr empty on success: {err}");
    let vid = field(&out, "vid").unwrap().to_string();
    let digest = field(&out, "entry_digest").unwrap().to_string();

    // Same intent again: recorded, exit 0, same digest.
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &intent, "--evidence", &ev, "--json"],
    );
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
    let (code, out, err) = fa(
        Some(&book),
        &["post", "--intent", &bad, "--evidence", &ev, "--json"],
    );
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
    let (code, _, err) = fa(
        Some(&book),
        &["post", "--intent", &float, "--evidence", &ev],
    );
    assert_eq!(code, 2);
    assert!(err.contains("amounts as strings"), "{err}");

    // Reopen the persistent book for every command. Stock carries the earlier
    // period's real posting; no invented opening entry is supplied to the report.
    let (code, out, err) = fa(Some(&book), &["period", "open", "FY2026-P02", "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    let opening = write(
        &dir,
        "february.json",
        r#"{"effective_date":"2026-02-20","idempotency_key":"february-rent","legs":[{"side":"debit","account":"6000","amount":"100.00 USD"},{"side":"credit","account":"1000","amount":"100.00 USD"}]}"#,
    );
    let (code, out, err) = fa(
        Some(&book),
        &["post", "--intent", &opening, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let future = write(
        &dir,
        "future-in-march.json",
        r#"{"effective_date":"2026-03-25","idempotency_key":"future-in-march","legs":[{"side":"debit","account":"6000","amount":"200.00 USD"},{"side":"credit","account":"1000","amount":"200.00 USD"}]}"#,
    );
    let (code, out, err) = fa(
        Some(&book),
        &["post", "--intent", &future, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let before_backdate = field(&out, "recorded_at").unwrap().to_string();
    let backdate = write(
        &dir,
        "late-recorded-backdate.json",
        r#"{"effective_date":"2026-03-10","idempotency_key":"late-recorded-backdate","legs":[{"side":"debit","account":"6000","amount":"300.00 USD"},{"side":"credit","account":"1000","amount":"300.00 USD"}]}"#,
    );
    let (code, out, err) = fa(
        Some(&book),
        &["post", "--intent", &backdate, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let after_backdate = field(&out, "recorded_at").unwrap().to_string();
    assert!(after_backdate.parse::<u64>().unwrap() > before_backdate.parse::<u64>().unwrap());

    let stock = report(&book, &["tb", "--period", march, "--json"]);
    assert!(
        stock.contains("\"pending_unit_totals\":[{\"credits_pending\":\"0.00 USD\",\"debits_pending\":\"0.00 USD\",\"unit\":\"USD\"}]"),
        "{stock}"
    );
    let (code, human, err) = fa(Some(&book), &["tb", "--period", march]);
    assert_eq!(code, 0, "{human}\n{err}");
    assert!(err.is_empty(), "{err}");
    assert!(
        human.contains("posted debits")
            && human.contains("posted credits")
            && human.contains("pending debits")
            && human.contains("pending credits"),
        "{human}"
    );
    assert_cash_credits(&stock, "2100.00 USD"); // 100 opening + 1500 + 200 + 300.
    assert_eq!(field(&stock, "mode"), Some("stock"));
    assert_eq!(field(&stock, "activity"), Some("false"));
    assert_eq!(field(&stock, "effective_through"), Some("2026-03-31"));
    assert_eq!(field(&stock, "known_at"), Some(after_backdate.as_str()));
    let duplicate_stock = report(
        &book,
        &["tb", "--period", march, "--period", march, "--json"],
    );
    assert_eq!(
        duplicate_stock, stock,
        "duplicate selectors must not count twice"
    );

    let old_stock = report(
        &book,
        &[
            "tb",
            "--period",
            march,
            "--as-known-at",
            &before_backdate,
            "--json",
        ],
    );
    assert_cash_credits(&old_stock, "1800.00 USD");
    assert_eq!(
        field(&old_stock, "known_at"),
        Some(before_backdate.as_str())
    );

    let activity = report(&book, &["tb", "--period", march, "--activity", "--json"]);
    assert_cash_credits(&activity, "2000.00 USD"); // The February opening is excluded.
    assert_eq!(field(&activity, "mode"), Some("activity"));
    assert_eq!(field(&activity, "activity"), Some("true"));
    assert_eq!(field(&activity, "effective_through"), Some("null"));
    let duplicate_activity = report(
        &book,
        &[
            "tb",
            "--period",
            march,
            "--period",
            march,
            "--activity",
            "--json",
        ],
    );
    assert_eq!(duplicate_activity, activity);

    let as_of = report(
        &book,
        &[
            "tb",
            "--as-of",
            "2026-03-15",
            "--as-known-at",
            "HEAD",
            "--json",
        ],
    );
    assert_cash_credits(&as_of, "1900.00 USD"); // Excludes the March 25 entry.
    assert_eq!(field(&as_of, "effective_through"), Some("2026-03-15"));
    assert_eq!(field(&as_of, "known_at"), Some(after_backdate.as_str()));
    let earlier = report(
        &book,
        &[
            "tb",
            "--as-of",
            "2026-03-15",
            "--as-known-at",
            &before_backdate,
            "--json",
        ],
    );
    assert_cash_credits(&earlier, "1600.00 USD"); // Also excludes the late recorded March 10 entry.
    assert_eq!(field(&earlier, "known_at"), Some(before_backdate.as_str()));
    let before_march = report(&book, &["tb", "--as-of", "2026-03-09", "--json"]);
    assert_cash_credits(&before_march, "100.00 USD");
    let old_activity = report(
        &book,
        &[
            "tb",
            "--period",
            march,
            "--activity",
            "--as-known-at",
            &before_backdate,
            "--json",
        ],
    );
    assert_cash_credits(&old_activity, "1700.00 USD");
    let fiscal_stock = report(&book, &["tb", "--fiscal-year", "2026", "--json"]);
    assert_cash_credits(&fiscal_stock, "2100.00 USD");
    assert_eq!(
        field(&fiscal_stock, "effective_through"),
        Some("2026-12-31")
    );
    let fiscal_activity = report(
        &book,
        &["tb", "--fiscal-year", "2026", "--activity", "--json"],
    );
    assert_cash_credits(&fiscal_activity, "2100.00 USD");

    // Every unsupported or ambiguous selector is a usage error, not an empty
    // success, a HEAD fallback or a silently converted instant.
    for args in [
        vec!["tb", "--period", "UNKNOWN", "--json"],
        vec!["tb", "--period", "UNKNOWN", "--activity", "--json"],
        vec!["tb", "--period", march, "--as-of", "2026-03-15", "--json"],
        vec![
            "tb",
            "--fiscal-year",
            "2026",
            "--as-of",
            "2026-03-15",
            "--json",
        ],
        vec!["tb", "--as-of", "2026-03-15", "--activity", "--json"],
        vec!["tb", "--period", march, "--fiscal-year", "2026", "--json"],
        vec!["tb", "--as-of", "2026-03-15T00:00:00Z", "--json"],
        vec!["tb", "--as-of", "2026-02-30", "--json"],
        vec![
            "tb",
            "--period",
            march,
            "--as-known-at",
            "2026-03-15T00:00:00Z",
            "--json",
        ],
        vec!["tb", "--period", march, "--as-known-at", "-1", "--json"],
        vec![
            "tb",
            "--period",
            march,
            "--as-known-at",
            "18446744073709551616",
            "--json",
        ],
        vec![
            "tb",
            "--period",
            march,
            "--as-known-at",
            "18446744073709551615",
            "--json",
        ],
        vec![
            "tb",
            "--period",
            march,
            "--as-known-at",
            "HEAD",
            "--as-known-at",
            &before_backdate,
            "--json",
        ],
        vec![
            "tb",
            "--as-of",
            "2026-03-15",
            "--as-of",
            "2026-03-16",
            "--json",
        ],
        vec!["book", "info", "--as-known-at", "HEAD", "--json"],
        vec![
            "verify",
            "registers",
            "--period",
            march,
            "--activity",
            "--json",
        ],
    ] {
        let (code, out, err) = fa(Some(&book), &args);
        assert_eq!(code, 2, "args={args:?}\nstdout={out}\nstderr={err}");
        assert!(
            !err.is_empty(),
            "refusal diagnostics missing: args={args:?}\n{out}"
        );
        assert_ne!(field(&out, "event"), Some("trial_balance"), "{out}");
        if args
            .iter()
            .any(|arg| arg.contains('T') && arg.contains(':'))
        {
            assert!(err.contains("instant selectors are unsupported"), "{err}");
        }
    }

    // Registers verify; then a close makes posting a safety block.
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
    assert!(out.contains("\"projection_errors\":[]"), "{out}");
    assert!(out.contains("\"pending_drift\":[]"), "{out}");

    let late = write(
        &dir,
        "late.json",
        r#"{"effective_date":"2026-03-20","idempotency_key":"inv-2001","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    let (code, _, _) = fa(Some(&book), &["period", "soft-close", march]);
    assert_eq!(code, 0);
    let (code, _, _) = fa(Some(&book), &["period", "close", march]);
    assert_eq!(code, 0);
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &late, "--evidence", &ev, "--json"],
    );
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
    let (code, _, _) = fa(Some(&book), &["post", "--intent", &late, "--evidence", &ev]);
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
    Ok(())
}

#[test]
fn reversals_by_target_and_idempotency_conflicts_follow_the_contract() -> std::io::Result<()> {
    let dir = tmp("reversal")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Rev Co"]).0,
        0
    );
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    assert_eq!(fa(Some(&book), &["chart", "import", &chart]).0, 0);
    assert_eq!(
        fa(Some(&book), &["period", "create", "--fiscal-year", "2026"]).0,
        0
    );
    assert_eq!(fa(Some(&book), &["period", "open", "FY2026-P03"]).0, 0);
    let ev = source_doc(&dir, &book);
    let intent = write(
        &dir,
        "entry.json",
        r#"{"effective_date":"2026-03-15","description":"rent","idempotency_key":"inv-1","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}]}"#,
    );
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &intent, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 0, "{out}");
    let vid = field(&out, "vid").unwrap().to_string();

    // Reverse by target: the CLI derives the side-swapped legs.
    let rev = write(
        &dir,
        "rev.json",
        &format!(
            r#"{{"class":"Reversal","reverses":"{vid}","effective_date":"2026-03-16","description":"undo","idempotency_key":"rev-1"}}"#
        ),
    );
    let (code, out, err) = fa(Some(&book), &["post", "--intent", &rev, "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("\"event\":\"posted\""), "{out}");
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &rev, "--json"]);
    assert_eq!(code, 0);
    assert!(out.contains("\"event\":\"recorded\""), "{out}");
    // A second, different reversal of the same target is a conflict (exit 6).
    let rev2 = write(
        &dir,
        "rev2.json",
        &format!(
            r#"{{"class":"Reversal","reverses":"{vid}","effective_date":"2026-03-17","idempotency_key":"rev-2"}}"#
        ),
    );
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &rev2, "--json"]);
    assert_eq!(code, 6, "{out}");
    assert!(out.contains("\"code\":\"FA-REF-052\""), "{out}");
    // Same idempotency key, different content: conflict (exit 6), nothing invented.
    let changed = write(
        &dir,
        "changed.json",
        r#"{"effective_date":"2026-03-15","description":"rent","idempotency_key":"inv-1","legs":[{"side":"debit","account":"6000","amount":"11.00 USD"},{"side":"credit","account":"1000","amount":"11.00 USD"}]}"#,
    );
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &changed, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 6, "{out}");
    assert!(out.contains("\"code\":\"FA-REF-032\""), "{out}");
    // An unsupported class is refused with the bead that lands it (exit 3).
    let repl = write(
        &dir,
        "repl.json",
        r#"{"class":"Replacement","effective_date":"2026-03-15","idempotency_key":"rp-1","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &repl, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 3, "{out}");
    assert!(
        out.contains("\"code\":\"FA-REF-102\"") && out.contains("fa-omi"),
        "{out}"
    );
    // The pair nets to zero.
    let (code, out, _) = fa(Some(&book), &["tb", "--period", "FY2026-P03", "--json"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("\"balanced\":true") && out.contains("\"net\":\"0.00 USD\""),
        "{out}"
    );
    Ok(())
}

#[test]
fn two_phase_reserve_and_resolve_follow_the_contract() -> std::io::Result<()> {
    let dir = tmp("two-phase")?;
    let book = dir.join("book");
    let (code, out, err) = fa(
        Some(&book),
        &["book", "create", "--name", "Hold Co", "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    let (code, out, err) = fa(Some(&book), &["chart", "import", &chart, "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    let (code, _, _) = fa(
        Some(&book),
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    assert_eq!(code, 0);
    let (code, _, _) = fa(Some(&book), &["period", "open", "FY2026-P03", "--json"]);
    assert_eq!(code, 0);
    let ev = source_doc(&dir, &book);
    let row = |out: &str, code: &str| -> String {
        let found = out
            .split('{')
            .find(|r| field(r, "code") == Some(code))
            .map(str::to_string);
        assert!(found.is_some(), "row {code} in {out}");
        found.unwrap_or_default()
    };

    // Reserve 80.00: the hold is a Pending; the trial balance shows it in the
    // pending columns and nothing posted.
    let hold = write(
        &dir,
        "hold.json",
        r#"{"effective_date":"2026-03-10","description":"PO 77 hold","idempotency_key":"hold-77","legs":[{"side":"debit","account":"6000","amount":"80.00 USD"},{"side":"credit","account":"1000","amount":"80.00 USD"}]}"#,
    );
    let (code, out, err) = fa(
        Some(&book),
        &["reserve", "--intent", &hold, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("posted"), "{out}");
    assert_eq!(field(&out, "class"), Some("Pending"), "{out}");
    let hold_vid = field(&out, "vid").unwrap().to_string();
    let tb = report(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    let rent = row(&tb, "6000");
    assert_eq!(field(&rent, "debits"), Some("0.00 USD"), "{tb}");
    assert_eq!(field(&rent, "debits_pending"), Some("80.00 USD"), "{tb}");
    // `--date` is a period-transition flag, never a balance selector: tb
    // refuses it instead of silently reporting the period-end stock.
    let (code, out, _) = fa(
        Some(&book),
        &[
            "tb",
            "--period",
            "FY2026-P03",
            "--date",
            "2026-03-09",
            "--json",
        ],
    );
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("--as-of"), "{out}");

    // A requested timeout is refused, never silently dropped into a
    // permanent hold; `source_ordinal` outside a Resolution(Posts) is refused.
    let timed = write(
        &dir,
        "timed.json",
        r#"{"effective_date":"2026-03-10","idempotency_key":"hold-t","timeout_ns":5,"legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    let (code, out, _) = fa(
        Some(&book),
        &["reserve", "--intent", &timed, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("timed holds"), "{out}");
    let stray = write(
        &dir,
        "stray.json",
        r#"{"effective_date":"2026-03-10","idempotency_key":"stray","legs":[{"side":"debit","account":"6000","amount":"1.00 USD","source_ordinal":0},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &stray, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("source_ordinal"), "{out}");
    // `fa reserve` refuses an intent that says it is something else.
    let not_a_hold = write(
        &dir,
        "orig.json",
        r#"{"class":"Original","effective_date":"2026-03-10","idempotency_key":"o-1","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    let (code, _, _) = fa(
        Some(&book),
        &[
            "reserve",
            "--intent",
            &not_a_hold,
            "--evidence",
            &ev,
            "--json",
        ],
    );
    assert_eq!(code, 2);

    // Post 60.00 of the hold (ordinals inferred from account + side): the
    // posted columns show 60.00 and the whole 80.00 reservation is released.
    let res = write(
        &dir,
        "res.json",
        &format!(
            r#"{{"resolves":"{hold_vid}","effective_date":"2026-03-20","description":"invoice 77","idempotency_key":"res-77","legs":[{{"side":"credit","account":"1000","amount":"60.00 USD"}},{{"side":"debit","account":"6000","amount":"60.00 USD"}}]}}"#
        ),
    );
    let (code, out, err) = fa(Some(&book), &["resolve", "--intent", &res, "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "class"), Some("Resolution"), "{out}");
    let res_vid = field(&out, "vid").unwrap().to_string();
    let tb = report(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    let rent = row(&tb, "6000");
    assert_eq!(field(&rent, "debits"), Some("60.00 USD"), "{tb}");
    assert_eq!(field(&rent, "debits_pending"), Some("0.00 USD"), "{tb}");
    assert_eq!(field(&tb, "balanced"), Some("true"), "{tb}");

    // One resolution per hold: a void after the post is a conflict (exit 6);
    // resolving something that is not a hold is a refusal (exit 3).
    let void = write(
        &dir,
        "void.json",
        &format!(
            r#"{{"resolves":"{hold_vid}","disposition":"voids","effective_date":"2026-03-21","idempotency_key":"void-77"}}"#
        ),
    );
    let (code, out, _) = fa(Some(&book), &["resolve", "--intent", &void, "--json"]);
    assert_eq!(code, 6, "{out}");
    assert_eq!(field(&out, "code"), Some("FA-REF-062"), "{out}");
    let not_a_hold = write(
        &dir,
        "res2.json",
        &format!(
            r#"{{"resolves":"{res_vid}","disposition":"voids","effective_date":"2026-03-21","idempotency_key":"void-78"}}"#
        ),
    );
    let (code, out, _) = fa(Some(&book), &["resolve", "--intent", &not_a_hold, "--json"]);
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "code"), Some("FA-REF-060"), "{out}");

    // A second hold, voided: reservation released, nothing posted.
    let hold_2 = write(
        &dir,
        "hold2.json",
        r#"{"class":"Pending","effective_date":"2026-03-12","idempotency_key":"hold-78","legs":[{"side":"debit","account":"6000","amount":"20.00 USD"},{"side":"credit","account":"1000","amount":"20.00 USD"}]}"#,
    );
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &hold_2, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 0, "{out}");
    let hold_2_vid = field(&out, "vid").unwrap().to_string();
    let tb = report(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    assert_eq!(
        field(&row(&tb, "6000"), "debits_pending"),
        Some("20.00 USD"),
        "{tb}"
    );
    // Materializing a period with holds reports the pending cells honestly.
    let (code, out, err) = fa(
        Some(&book),
        &[
            "registers",
            "materialize",
            "--period",
            "FY2026-P03",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "pending_cells"), Some("2"), "{out}");
    let (code, out, _) = fa(
        Some(&book),
        &["verify", "registers", "--period", "FY2026-P03", "--json"],
    );
    assert_eq!(code, 0, "{out}");
    let void_2 = write(
        &dir,
        "void2.json",
        &format!(
            r#"{{"resolves":"{hold_2_vid}","disposition":"voids","effective_date":"2026-03-22","idempotency_key":"void-79"}}"#
        ),
    );
    let (code, out, err) = fa(Some(&book), &["resolve", "--intent", &void_2, "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    let tb = report(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    let rent = row(&tb, "6000");
    assert_eq!(field(&rent, "debits"), Some("60.00 USD"), "{tb}");
    assert_eq!(field(&rent, "debits_pending"), Some("0.00 USD"), "{tb}");
    Ok(())
}

#[test]
fn applications_settle_open_items_and_reversals_reopen_them() -> std::io::Result<()> {
    let dir = tmp("open-items")?;
    let book = dir.join("book");
    let (code, out, err) = fa(
        Some(&book),
        &["book", "create", "--name", "AR Co", "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"1200","name":"Receivable","type":"Asset","leaf":true,"unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","leaf":true,"unit":"USD"}]}"#,
    );
    let (code, out, err) = fa(Some(&book), &["chart", "import", &chart, "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    let (code, _, _) = fa(
        Some(&book),
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    assert_eq!(code, 0);
    let (code, _, _) = fa(Some(&book), &["period", "open", "FY2026-P03", "--json"]);
    assert_eq!(code, 0);
    let ev = source_doc(&dir, &book);

    let invoice = write(
        &dir,
        "invoice.json",
        r#"{"effective_date":"2026-03-05","idempotency_key":"inv-9","legs":[{"side":"debit","account":"1200","amount":"500.00 USD"},{"side":"credit","account":"4000","amount":"500.00 USD"}]}"#,
    );
    let (code, out, err) = fa(
        Some(&book),
        &["post", "--intent", &invoice, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let inv_vid = field(&out, "vid").unwrap().to_string();
    let (code, out, _) = fa(Some(&book), &["open-items", "--account", "1200", "--json"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "event"), Some("open_items"), "{out}");
    assert_eq!(field(&out, "count"), Some("1"), "{out}");
    assert!(out.contains("\"open\":\"500.00 USD\""), "{out}");

    // A receipt for 300.00 applied to the invoice's debit leg.
    let receipt = write(
        &dir,
        "receipt.json",
        &format!(
            r#"{{"effective_date":"2026-03-20","idempotency_key":"rcpt-9","legs":[{{"side":"debit","account":"1000","amount":"300.00 USD"}},{{"side":"credit","account":"1200","amount":"300.00 USD","settles":[{{"entry":"{inv_vid}","ordinal":0,"amount":"300.00 USD"}}]}}]}}"#
        ),
    );
    let (code, out, err) = fa(
        Some(&book),
        &["post", "--intent", &receipt, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let rcpt_vid = field(&out, "vid").unwrap().to_string();
    let (code, out, _) = fa(Some(&book), &["open-items", "--account", "1200", "--json"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("\"applied\":\"300.00 USD\"") && out.contains("\"open\":\"200.00 USD\""),
        "{out}"
    );
    assert!(out.contains("\"live\":true"), "{out}");

    // Over-application is refused with the open amount; reversing the
    // invoice is refused while the receipt is applied.
    let over = write(
        &dir,
        "over.json",
        &format!(
            r#"{{"effective_date":"2026-03-21","idempotency_key":"rcpt-10","legs":[{{"side":"debit","account":"1000","amount":"250.00 USD"}},{{"side":"credit","account":"1200","amount":"250.00 USD","settles":[{{"entry":"{inv_vid}","ordinal":0,"amount":"250.00 USD"}}]}}]}}"#
        ),
    );
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &over, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "code"), Some("FA-REF-072"), "{out}");
    assert!(out.contains("20000"), "{out}");
    let rev_inv = write(
        &dir,
        "rev-inv.json",
        &format!(
            r#"{{"class":"Reversal","reverses":"{inv_vid}","effective_date":"2026-03-22","idempotency_key":"rev-inv"}}"#
        ),
    );
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &rev_inv, "--json"]);
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "code"), Some("FA-REF-073"), "{out}");

    // Reversing the receipt reopens the invoice; the mirrors verify.
    let rev_rcpt = write(
        &dir,
        "rev-rcpt.json",
        &format!(
            r#"{{"class":"Reversal","reverses":"{rcpt_vid}","effective_date":"2026-03-22","idempotency_key":"rev-rcpt"}}"#
        ),
    );
    let (code, out, err) = fa(Some(&book), &["post", "--intent", &rev_rcpt, "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    let (code, out, _) = fa(Some(&book), &["open-items", "--account", "1200", "--json"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("\"applied\":\"0.00 USD\"") && out.contains("\"open\":\"500.00 USD\""),
        "{out}"
    );
    assert!(out.contains("\"live\":false"), "{out}");
    let (code, out, err) = fa(Some(&book), &["verify", "open-items", "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("open_items_verified"), "{out}");
    let (code, out, _) = fa(Some(&book), &["open-items", "--as-known-at", "1", "--json"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "count"), Some("0"), "{out}");
    Ok(())
}

// ---------------------------------------------------------------------------
// fa-9xt: the verb registry, the robot-mode schema, and `fa explain balance`
// ---------------------------------------------------------------------------

/// The last stdout line, parsed (robot mode prints one result line here).
fn doc(out: &str) -> Json {
    let parsed = json::parse(out.lines().last().unwrap_or_default());
    assert!(parsed.is_ok(), "not JSON: {out}");
    parsed.unwrap_or(Json::Null)
}

fn arr<'a>(j: &'a Json, key: &str) -> &'a [Json] {
    j.get(key).and_then(Json::as_arr).unwrap_or_default()
}

fn text<'a>(j: &'a Json, key: &str) -> &'a str {
    j.get(key).and_then(Json::as_str).unwrap_or_default()
}

fn int(j: &Json, key: &str) -> Option<i128> {
    match j.get(key) {
        Some(Json::Int(n)) => Some(*n),
        _ => None,
    }
}

fn names(items: &[Json]) -> Vec<&str> {
    items.iter().map(|i| text(i, "name")).collect()
}

#[test]
fn verbs_toml_is_the_single_verb_registry_and_the_binary_agrees() -> std::io::Result<()> {
    let reg = registry().expect("verbs.toml");
    let nowhere = tmp("parity")?.join("not-a-book");

    // `fa capabilities` lists exactly the registry's verbs and aliases.
    let (code, out, _) = fa(None, &["capabilities", "--json"]);
    assert_eq!(code, 0, "{out}");
    let caps = doc(&out);
    let listed: Vec<&str> = arr(&caps, "verbs")
        .iter()
        .filter_map(Json::as_str)
        .collect();
    let registered: Vec<&str> = reg.verbs.iter().map(|v| v.name.as_str()).collect();
    assert_eq!(listed, registered);
    assert_eq!(
        names(arr(&caps, "aliases")),
        reg.aliases
            .iter()
            .map(|a| a.name.as_str())
            .collect::<Vec<_>>()
    );

    for verb in &reg.verbs {
        // Help comes from the registry row, in both modes.
        let (code, out, err) = fa(None, &[&verb.name, "--help", "--json"]);
        assert_eq!(code, 0, "{}: {out}\n{err}", verb.name);
        let help = doc(&out);
        assert_eq!(text(&help, "verb"), verb.name);
        let (code, human, _) = fa(None, &["help", &verb.name]);
        assert_eq!(code, 0, "{human}");
        for line in &verb.usage {
            assert!(
                text(&help, "text").contains(line.as_str()),
                "{}: {line}",
                verb.name
            );
            assert!(
                human.contains(line.as_str()),
                "{}: {line}\n{human}",
                verb.name
            );
        }
        // A handler answers every registered spelling: whatever it needs
        // next (an argument, a book) it says so, and it is never a parity
        // defect (exit 5, "has no handler") or an unknown command.
        let calls: Vec<Vec<&str>> = if verb.subcommands.is_empty() {
            vec![vec![verb.name.as_str()]]
        } else {
            verb.subcommands
                .iter()
                .map(|sub| vec![verb.name.as_str(), sub.as_str()])
                .collect()
        };
        for mut call in calls {
            call.push("--json");
            let (code, out, err) = fa(Some(&nowhere), &call);
            assert!(
                [0, 2, 4].contains(&code) && !out.contains("has no handler"),
                "{call:?}: exit {code}\n{out}\n{err}"
            );
            assert!(!out.contains("unknown command"), "{call:?}: {out}");
        }
        // A subcommand the registry lacks is a usage error naming the real ones.
        if !verb.subcommands.is_empty() {
            let (code, out, _) = fa(Some(&nowhere), &[&verb.name, "nosuchsub", "--json"]);
            assert_eq!(code, 2, "{out}");
            assert!(
                out.contains("has no subcommand") && out.contains(&verb.subcommands.join("|")),
                "{out}"
            );
        }
    }
    assert!(
        !nowhere.exists(),
        "no parity probe may create a book: {}",
        nowhere.display()
    );

    // Aliases expand to their registered verbs.
    for alias in &reg.aliases {
        let (code, out, _) = fa(None, &[&alias.name, "--help", "--json"]);
        assert_eq!(code, 0, "{out}");
        assert_eq!(
            Some(text(&doc(&out), "verb")),
            alias.expands.first().map(String::as_str)
        );
    }

    // Flags belong to verbs: another verb's flag is refused with this verb's
    // flags as the fix; a flag with no verb names the commands.
    let (code, out, _) = fa(None, &["verify", "open-items", "--activity", "--json"]);
    assert_eq!(code, 2, "{out}");
    let refused = doc(&out);
    assert!(
        text(&refused, "message").contains("--activity is not a flag of `fa verify`")
            && text(&refused, "fix").contains("--period"),
        "{out}"
    );
    let (code, out, _) = fa(None, &["--period", "FY2026-P03", "--json"]);
    assert_eq!(code, 2, "{out}");
    assert!(
        text(&doc(&out), "message").contains("needs a command"),
        "{out}"
    );
    // The flag list the parser corrects against is the registry's.
    let (code, _, err) = fa(None, &["explain", "balance", "1000", "--perod", "P"]);
    assert_eq!(code, 2);
    assert!(err.contains("--period"), "{err}");
    // Unknown verbs are corrected against verbs and aliases.
    let (code, out, _) = fa(None, &["trial-balanse", "--json"]);
    assert_eq!(code, 2, "{out}");
    assert!(
        text(&doc(&out), "fix").contains("fa trial-balance"),
        "{out}"
    );
    Ok(())
}

#[test]
fn robot_docs_schema_prints_the_envelope_and_every_event_from_the_registry() {
    let reg = registry().expect("verbs.toml");
    let (code, out, err) = fa(None, &["robot-docs", "schema", "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(err.is_empty(), "{err}");
    let schema = doc(&out);
    let envelope = schema.get("envelope").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&envelope, "discriminator"), "event");
    assert!(text(&envelope, "description").contains("one JSON object per line"));
    let fields_of = |item: &Json| -> Vec<(String, String)> {
        arr(item, "fields")
            .iter()
            .map(|f| (text(f, "name").to_string(), text(f, "type").to_string()))
            .collect()
    };
    let printed: Vec<(String, Vec<(String, String)>)> = arr(&schema, "events")
        .iter()
        .map(|e| (text(e, "name").to_string(), fields_of(e)))
        .collect();
    let expected: Vec<(String, Vec<(String, String)>)> = reg
        .events
        .iter()
        .map(|e| {
            (
                e.name.clone(),
                e.fields
                    .iter()
                    .map(|f| (f.name.clone(), f.type_text.clone()))
                    .collect(),
            )
        })
        .collect();
    assert_eq!(printed, expected);
    assert_eq!(
        names(arr(&schema, "shapes")),
        reg.shapes
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
    );
    for e in arr(&schema, "events") {
        let verbs: Vec<&str> = arr(e, "verbs").iter().filter_map(Json::as_str).collect();
        assert_eq!(verbs, reg.emitters(text(e, "name")), "{}", text(e, "name"));
    }

    // One event: it and exactly the shapes it references.
    let (code, out, _) = fa(
        None,
        &["robot-docs", "schema", "balance_explained", "--json"],
    );
    assert_eq!(code, 0, "{out}");
    let one = doc(&out);
    assert_eq!(names(arr(&one, "events")), vec!["balance_explained"]);
    let shapes: BTreeSet<&str> = names(arr(&one, "shapes")).into_iter().collect();
    let want: BTreeSet<&str> = [
        "explained_cell",
        "contribution",
        "lineage",
        "evidence_head",
        "cell_change",
    ]
    .into_iter()
    .collect();
    assert_eq!(shapes, want);

    // An unknown name is a usage error with the nearest real one.
    let (code, out, _) = fa(
        None,
        &["robot-docs", "schema", "balance_explaned", "--json"],
    );
    assert_eq!(code, 2, "{out}");
    assert!(
        text(&doc(&out), "fix").contains("fa robot-docs schema balance_explained"),
        "{out}"
    );

    // Human mode prints the same registry as text.
    let (code, human, _) = fa(None, &["robot-docs", "schema"]);
    assert_eq!(code, 0);
    assert!(
        human.contains("event balance_explained (explain)")
            && human.contains("  contributions: [contribution]")
            && human.contains("shape contribution"),
        "{human}"
    );
}

/// Parse an explanation's single USD cell into
/// (debits, credits, entry_count, debits_pending, credits_pending, pending_count).
fn usd_cell(ex: &Json) -> Option<(String, String, i128, String, String, i128)> {
    let cells = arr(ex, "cells");
    assert!(cells.len() <= 1, "one unit in this book: {cells:?}");
    cells.first().map(|c| {
        (
            text(c, "debits").to_string(),
            text(c, "credits").to_string(),
            int(c, "entry_count").unwrap_or(-1),
            text(c, "debits_pending").to_string(),
            text(c, "credits_pending").to_string(),
            int(c, "pending_count").unwrap_or(-1),
        )
    })
}

#[test]
fn explain_balance_lists_every_leg_re_adds_to_the_cell_and_replays_its_history()
-> std::io::Result<()> {
    let dir = tmp("explain")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    ok(&["book", "create", "--name", "Explain Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1","name":"Assets","type":"Asset","leaf":false,"unit":"USD"},{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD","parent":"1"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P02", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let ev = source_doc(&dir, &book);
    let post = |verb: &str, name: &str, body: &str| -> (String, i128) {
        let path = write(&dir, name, body);
        let posted = doc(&ok(&[verb, "--intent", &path, "--evidence", &ev, "--json"]));
        (
            text(&posted, "vid").to_string(),
            int(&posted, "recorded_at").unwrap_or(-1),
        )
    };
    let leg = |side: &str, account: &str, amount: &str| {
        format!(r#"{{"side":"{side}","account":"{account}","amount":"{amount} USD"}}"#)
    };
    let pair = |amount: &str| {
        format!(
            "[{},{}]",
            leg("debit", "6000", amount),
            leg("credit", "1000", amount)
        )
    };
    // February (another period: never in March's explanation).
    post(
        "post",
        "feb.json",
        &format!(
            r#"{{"effective_date":"2026-02-20","idempotency_key":"feb","legs":{}}}"#,
            pair("100.00")
        ),
    );
    let (rent, rent_at) = post(
        "post",
        "rent.json",
        &format!(
            r#"{{"effective_date":"2026-03-05","idempotency_key":"rent","legs":{}}}"#,
            pair("1500.00")
        ),
    );
    let (extra, extra_at) = post(
        "post",
        "extra.json",
        &format!(
            r#"{{"effective_date":"2026-03-10","idempotency_key":"extra","legs":{}}}"#,
            pair("200.00")
        ),
    );
    let (rev, rev_at) = post(
        "post",
        "rev.json",
        &format!(
            r#"{{"class":"Reversal","reverses":"{extra}","effective_date":"2026-03-11","idempotency_key":"rev"}}"#
        ),
    );
    let (hold, hold_at) = post(
        "reserve",
        "hold.json",
        &format!(
            r#"{{"effective_date":"2026-03-12","idempotency_key":"hold","legs":{}}}"#,
            pair("80.00")
        ),
    );
    let (res, res_at) = post(
        "resolve",
        "res.json",
        &format!(
            r#"{{"resolves":"{hold}","effective_date":"2026-03-20","idempotency_key":"res","legs":{}}}"#,
            pair("60.00")
        ),
    );
    let (hold2, hold2_at) = post(
        "reserve",
        "hold2.json",
        &format!(
            r#"{{"effective_date":"2026-03-25","idempotency_key":"hold2","legs":{}}}"#,
            pair("30.00")
        ),
    );

    let head = ok(&[
        "explain",
        "balance",
        "1000",
        "--period",
        "FY2026-P03",
        "--json",
    ]);
    let ex = doc(&head);
    assert_eq!(text(&ex, "account"), "1000");
    assert_eq!(text(&ex, "name"), "Cash");
    assert_eq!(text(&ex, "type"), "Asset");
    assert_eq!(ex.get("certificate"), Some(&Json::Null));
    // Posted: credits 1500 + 200 + 60, debits 200 (the reversal), four
    // entries; pending: the unresolved 30 hold. The resolved 80 hold is in
    // neither column.
    assert_eq!(
        usd_cell(&ex),
        Some((
            "200.00 USD".into(),
            "1760.00 USD".into(),
            4,
            "0.00 USD".into(),
            "30.00 USD".into(),
            1
        ))
    );
    assert_eq!(text(&arr(&ex, "cells")[0], "net"), "-1560.00 USD");
    let contributions = arr(&ex, "contributions");
    let summary: Vec<(String, i128, i128, String, String, String)> = contributions
        .iter()
        .map(|c| {
            (
                text(c, "entry").to_string(),
                int(c, "recorded_at").unwrap_or(-1),
                int(c, "ordinal").unwrap_or(-1),
                text(c, "side").to_string(),
                text(c, "amount").to_string(),
                text(c, "column").to_string(),
            )
        })
        .collect();
    let row = |vid: &str, at: i128, side: &str, amount: &str, column: &str| {
        (
            vid.to_string(),
            at,
            1,
            side.to_string(),
            format!("{amount} USD"),
            column.to_string(),
        )
    };
    assert_eq!(
        summary,
        vec![
            row(&rent, rent_at, "credit", "1500.00", "posted"),
            row(&extra, extra_at, "credit", "200.00", "posted"),
            row(&rev, rev_at, "debit", "200.00", "posted"),
            row(&hold, hold_at, "credit", "80.00", "released"),
            row(&res, res_at, "credit", "60.00", "posted"),
            row(&hold2, hold2_at, "credit", "30.00", "pending"),
        ],
        "{head}"
    );
    let by_entry = |vid: &str| contributions.iter().find(|c| text(c, "entry") == vid);
    // Every leg names its entry's evidence heads: the cited source document.
    for c in contributions {
        let heads: Vec<&str> = arr(c, "evidence")
            .iter()
            .map(|e| text(e, "document_oid"))
            .collect();
        assert_eq!(heads, vec![ev.as_str()], "{head}");
    }
    let reversal = by_entry(&rev).cloned().unwrap_or(Json::Null);
    assert_eq!(text(&reversal, "class"), "Reversal");
    let lineage = arr(&reversal, "supersedes");
    assert_eq!(lineage.len(), 1, "{head}");
    assert_eq!(
        (text(&lineage[0], "entry"), text(&lineage[0], "kind")),
        (extra.as_str(), "Reverses")
    );
    let released = by_entry(&hold).cloned().unwrap_or(Json::Null);
    assert_eq!(int(&released, "released_at"), Some(res_at));
    let resolution = by_entry(&res).cloned().unwrap_or(Json::Null);
    assert_eq!(text(&resolution, "resolves"), hold);
    assert_eq!(resolution.get("released_at"), Some(&Json::Null));

    // The same cell, from the trial balance's own fold: the explanation re-adds.
    let tb = ok(&["tb", "--period", "FY2026-P03", "--activity", "--json"]);
    let cash = arr(&doc(&tb), "rows")
        .iter()
        .find(|r| text(r, "code") == "1000")
        .cloned()
        .unwrap_or(Json::Null);
    let cell = usd_cell(&ex).unwrap_or_default();
    assert_eq!(
        (
            text(&cash, "debits"),
            text(&cash, "credits"),
            text(&cash, "credits_pending")
        ),
        (cell.0.as_str(), cell.1.as_str(), cell.4.as_str())
    );

    // The known-at history: one point per recorded sequence that touched the
    // cell, ending at the head's values; each point equals the explanation
    // as known at that sequence (a fresh read of the journal prefix).
    let history = arr(&ex, "history");
    let points: Vec<i128> = history
        .iter()
        .map(|h| int(h, "recorded_at").unwrap_or(-1))
        .collect();
    assert_eq!(
        points,
        vec![rent_at, extra_at, rev_at, hold_at, res_at, hold2_at]
    );
    assert_eq!(int(&ex, "last_changed_at"), Some(hold2_at));
    for h in history {
        let at = int(h, "recorded_at").unwrap_or(-1).to_string();
        let then = doc(&ok(&[
            "explain",
            "balance",
            "1000",
            "--period",
            "FY2026-P03",
            "--as-known-at",
            &at,
            "--json",
        ]));
        assert_eq!(
            int(&then, "known_at").map(|n| n.to_string()),
            Some(at.clone())
        );
        let (d, c, _, dp, cp, _) = usd_cell(&then).unwrap_or_default();
        assert_eq!(
            (d.as_str(), c.as_str(), dp.as_str(), cp.as_str()),
            (
                text(h, "debits"),
                text(h, "credits"),
                text(h, "debits_pending"),
                text(h, "credits_pending")
            ),
            "as known at {at}"
        );
    }
    // Before the reversal was recorded, it is not part of the explanation.
    let before = doc(&ok(&[
        "explain",
        "balance",
        "1000",
        "--period",
        "FY2026-P03",
        "--as-known-at",
        &extra_at.to_string(),
        "--json",
    ]));
    assert_eq!(arr(&before, "contributions").len(), 2);

    // Another period explains only its own legs; an untouched account in a
    // period is an empty result, exit 0.
    let feb = doc(&ok(&[
        "explain",
        "balance",
        "1000",
        "--period",
        "FY2026-P02",
        "--json",
    ]));
    assert_eq!(arr(&feb, "contributions").len(), 1);
    assert_eq!(text(&arr(&feb, "cells")[0], "credits"), "100.00 USD");
    let empty = doc(&ok(&[
        "explain",
        "balance",
        "6000",
        "--period",
        "FY2026-P01",
        "--json",
    ]));
    assert!(arr(&empty, "cells").is_empty() && arr(&empty, "contributions").is_empty());
    assert_eq!(empty.get("last_changed_at"), Some(&Json::Null));

    // The alias `fa balance` is the same read.
    assert_eq!(
        ok(&["balance", "1000", "--period", "FY2026-P03", "--json"]),
        head
    );
    // Human mode: plain text, the contributions table.
    let human = ok(&["explain", "balance", "1000", "--period", "FY2026-P03"]);
    assert!(
        human.contains("contributions (by recorded sequence)")
            && human.contains(&format!("released at {res_at}"))
            && !human.contains("\"event\""),
        "{human}"
    );

    // Refusals name the fix.
    for (args, needle) in [
        (
            vec!["explain", "balance", "100", "--period", "FY2026-P03"],
            "did you mean `1000`?",
        ),
        (
            vec!["explain", "balance", "1", "--period", "FY2026-P03"],
            "summary account",
        ),
        (
            vec!["explain", "balance", "1000", "--period", "FY2027-P03"],
            "--period FY2026-P03",
        ),
        (vec!["explain", "balance", "1000"], "--period"),
        (
            vec![
                "explain",
                "balance",
                "1000",
                "--period",
                "FY2026-P02",
                "--period",
                "FY2026-P03",
            ],
            "one period at a time",
        ),
        (
            vec![
                "explain",
                "balance",
                "1000",
                "--period",
                "FY2026-P03",
                "--as-known-at",
                "2026-03-15T00:00:00Z",
            ],
            "instant selectors are unsupported",
        ),
        (
            vec![
                "explain",
                "balance",
                "1000",
                "--period",
                "FY2026-P03",
                "--as-known-at",
                "18446744073709551615",
            ],
            "beyond book head",
        ),
        (vec!["explain"], "needs a subcommand: balance"),
        (vec!["explain", "balanse", "1000"], "fa explain balance"),
    ] {
        let mut args = args;
        args.push("--json");
        let (code, out, err) = fa(Some(&book), &args);
        assert_eq!(code, 2, "args={args:?}\n{out}\n{err}");
        assert!(
            out.contains(needle) && err.contains(needle),
            "args={args:?}: {needle}\n{out}\n{err}"
        );
    }
    Ok(())
}

#[test]
fn every_declared_event_is_emitted_by_the_binary() -> std::io::Result<()> {
    let reg = registry().expect("verbs.toml");
    let dir = tmp("events")?;
    let book = dir.join("book");
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut run = |with_book: bool, args: &[&str]| -> (i32, String) {
        let mut argv = args.to_vec();
        argv.push("--json");
        let (code, out, _) = fa(with_book.then_some(book.as_path()), &argv);
        seen.extend(check_robot_output(&argv, code, &out));
        (code, out)
    };
    assert_eq!(run(false, &["--version"]).0, 0);
    assert_eq!(run(false, &[]).0, 0);
    assert_eq!(run(false, &["--help"]).0, 0);
    assert_eq!(run(false, &["capabilities"]).0, 0);
    assert_eq!(run(false, &["robot-docs", "guide"]).0, 0);
    assert_eq!(run(false, &["robot-docs", "schema"]).0, 0);
    assert_eq!(run(false, &["nosuchverb"]).0, 2);
    assert_eq!(run(true, &["book", "info"]).0, 4);
    assert_eq!(run(true, &["book", "create", "--name", "Events Co"]).0, 0);
    assert_eq!(run(true, &["book", "info"]).0, 0);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    assert_eq!(run(true, &["chart", "import", &chart]).0, 0);
    assert_eq!(run(true, &["chart", "list"]).0, 0);
    assert_eq!(
        run(true, &["period", "create", "--fiscal-year", "2026"]).0,
        0
    );
    assert_eq!(run(true, &["period", "list"]).0, 0);
    assert_eq!(run(true, &["period", "open", "FY2026-P03"]).0, 0);
    let source = write(
        &dir,
        "source.txt",
        "INVOICE (event fixture source document)",
    );
    let (code, out) = run(
        true,
        &[
            "document",
            "add",
            &source,
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let ev = field(&out, "oid").unwrap_or_default().to_string();
    let rent = write(
        &dir,
        "rent.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"rent","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}]}"#,
    );
    let (code, out) = run(true, &["post", "--intent", &rent, "--evidence", &ev]);
    assert_eq!(code, 0, "{out}");
    let vid = field(&out, "vid").unwrap_or_default().to_string();
    assert_eq!(
        run(true, &["post", "--intent", &rent, "--evidence", &ev]).0,
        0
    );
    let bad = write(
        &dir,
        "bad.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"bad","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"9.99 USD"}]}"#,
    );
    assert_eq!(
        run(true, &["post", "--intent", &bad, "--evidence", &ev]).0,
        3
    );
    assert_eq!(run(true, &["tb", "--period", "FY2026-P03"]).0, 0);
    assert_eq!(run(true, &["open-items"]).0, 0);
    assert_eq!(run(true, &["entry", "show", &vid]).0, 0);
    assert_eq!(run(true, &["entry", "show", "00"]).0, 0);
    assert_eq!(
        run(
            true,
            &["explain", "balance", "1000", "--period", "FY2026-P03"]
        )
        .0,
        0
    );
    assert_eq!(
        run(
            true,
            &["registers", "materialize", "--period", "FY2026-P03"]
        )
        .0,
        0
    );
    assert_eq!(
        run(true, &["verify", "registers", "--period", "FY2026-P03"]).0,
        0
    );
    assert_eq!(run(true, &["verify", "open-items"]).0, 0);
    assert_eq!(run(true, &["verify", "availability"]).0, 0);
    let more = write(
        &dir,
        "more.json",
        r#"{"effective_date":"2026-03-16","idempotency_key":"more","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    assert_eq!(
        run(true, &["post", "--intent", &more, "--evidence", &ev]).0,
        0
    );
    assert_eq!(
        run(true, &["verify", "registers", "--period", "FY2026-P03"]).0,
        8
    );
    let declared: BTreeSet<String> = reg.events.iter().map(|e| e.name.clone()).collect();
    assert_eq!(
        seen, declared,
        "every declared event is emitted, and nothing undeclared is"
    );
    Ok(())
}

#[test]
fn balance_bounds_refuse_breaches_and_availability_verifies_by_refold() -> std::io::Result<()> {
    let dir = tmp("limits")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    ok(&["book", "create", "--name", "Limit Co", "--json"]);

    // A bound is an exact string in the account's single unit.
    for (name, chart, needle) in [
        (
            "any.json",
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"any","lower_bound":"0.00"}]}"#,
            "single unit",
        ),
        (
            "number.json",
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD","lower_bound":0}]}"#,
            "decimal string",
        ),
        (
            "scale.json",
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD","lower_bound":"0.001"}]}"#,
            "lower_bound",
        ),
    ] {
        let path = write(&dir, name, chart);
        let (code, out, _) = fa(Some(&book), &["chart", "import", &path, "--json"]);
        assert_eq!(code, 2, "{name}: {out}");
        assert!(out.contains(needle), "{name}: {out}");
    }
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD","lower_bound":"0.00"},{"code":"4000","name":"Sales","type":"Revenue","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    let listed = doc(&ok(&["chart", "list", "--json"]));
    let account = |code: &str| {
        arr(&listed, "accounts")
            .iter()
            .find(|a| text(a, "code") == code)
            .cloned()
            .unwrap_or(Json::Null)
    };
    assert_eq!(text(&account("1000"), "lower_bound"), "0.00 USD");
    assert_eq!(account("1000").get("upper_bound"), Some(&Json::Null));
    assert_eq!(account("6000").get("lower_bound"), Some(&Json::Null));
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let ev = source_doc(&dir, &book);

    let intent = |name: &str, key: &str, debit: &str, credit: &str, amount: &str| {
        write(
            &dir,
            name,
            &format!(
                r#"{{"effective_date":"2026-03-10","idempotency_key":"{key}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount} USD"}},{{"side":"credit","account":"{credit}","amount":"{amount} USD"}}]}}"#
            ),
        )
    };
    let sale = intent("sale.json", "sale", "1000", "4000", "100.00");
    ok(&["post", "--intent", &sale, "--evidence", &ev, "--json"]);
    // Cash may not go below its bound: 100 - 150 < 0.
    let big = intent("big.json", "big", "6000", "1000", "150.00");
    let (code, out, err) = fa(
        Some(&book),
        &["post", "--intent", &big, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 3, "{out}\n{err}");
    assert_eq!(field(&out, "code"), Some("FA-REF-090"), "{out}");
    let rent = intent("rent.json", "rent", "6000", "1000", "60.00");
    ok(&["post", "--intent", &rent, "--evidence", &ev, "--json"]);
    // A reservation is an outflow too: 40 available, 50 is refused, 30 holds.
    let hold = intent("hold.json", "hold", "6000", "1000", "50.00");
    let (code, out, _) = fa(
        Some(&book),
        &["reserve", "--intent", &hold, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "code"), Some("FA-REF-090"), "{out}");
    let small = intent("small.json", "small", "6000", "1000", "30.00");
    ok(&["reserve", "--intent", &small, "--evidence", &ev, "--json"]);

    let verified = doc(&ok(&["verify", "availability", "--json"]));
    assert_eq!(int(&verified, "accounts_checked"), Some(1));
    assert!(arr(&verified, "drift").is_empty());
    let cash = arr(&verified, "accounts")
        .first()
        .cloned()
        .unwrap_or(Json::Null);
    assert_eq!(
        (
            text(&cash, "account"),
            text(&cash, "normal"),
            text(&cash, "lower_bound"),
            text(&cash, "net"),
            text(&cash, "pending_out"),
            text(&cash, "pending_in"),
        ),
        (
            "1000",
            "debit",
            "0.00 USD",
            "40.00 USD",
            "30.00 USD",
            "0.00 USD"
        )
    );
    assert_eq!(cash.get("upper_bound"), Some(&Json::Null));
    let human = ok(&["verify", "availability"]);
    assert!(human.contains("1 limited accounts"), "{human}");
    Ok(())
}

#[test]
fn explain_balance_resolves_the_account_as_known_at_the_requested_sequence() -> std::io::Result<()>
{
    let dir = tmp("explain-history")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    ok(&["book", "create", "--name", "History Co", "--json"]);
    // Periods first: at this sequence the chart does not exist yet.
    let created = doc(&ok(&[
        "period",
        "create",
        "--fiscal-year",
        "2026",
        "--json",
    ]));
    let before_chart = int(&created, "recorded_at").unwrap_or(-1).to_string();
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    let installed = doc(&ok(&["chart", "import", &chart, "--json"]));
    let with_chart = int(&installed, "recorded_at").unwrap_or(-1).to_string();
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let ev = source_doc(&dir, &book);
    let rent = write(
        &dir,
        "rent.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"rent","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}]}"#,
    );
    ok(&["post", "--intent", &rent, "--evidence", &ev, "--json"]);

    // As known before the chart, Cash does not exist: refused with the
    // sequence it does exist from, never described with today's metadata.
    let (code, out, err) = fa(
        Some(&book),
        &[
            "explain",
            "balance",
            "1000",
            "--period",
            "FY2026-P03",
            "--as-known-at",
            &before_chart,
            "--json",
        ],
    );
    assert_eq!(code, 2, "{out}\n{err}");
    let refused = doc(&out);
    assert_eq!(text(&refused, "event"), "usage_error", "{out}");
    assert!(
        text(&refused, "message").contains(&format!("as known at {before_chart}"))
            && text(&refused, "fix").contains(&format!("--as-known-at {with_chart}")),
        "{out}"
    );
    // Positive control: as known at the chart's installation the account
    // exists, with today's posting not yet recorded.
    let then = doc(&ok(&[
        "explain",
        "balance",
        "1000",
        "--period",
        "FY2026-P03",
        "--as-known-at",
        &with_chart,
        "--json",
    ]));
    assert_eq!(
        (text(&then, "name"), text(&then, "type")),
        ("Cash", "Asset")
    );
    assert_eq!(
        int(&then, "known_at").map(|n| n.to_string()),
        Some(with_chart)
    );
    assert!(arr(&then, "contributions").is_empty() && arr(&then, "cells").is_empty());
    let now = doc(&ok(&[
        "explain",
        "balance",
        "1000",
        "--period",
        "FY2026-P03",
        "--json",
    ]));
    assert_eq!(arr(&now, "contributions").len(), 1);
    Ok(())
}

#[test]
fn human_explain_shows_released_only_history_and_an_untouched_account_is_empty()
-> std::io::Result<()> {
    let dir = tmp("released")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    ok(&["book", "create", "--name", "Released Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let ev = source_doc(&dir, &book);
    // Reserve 80, then void it: the hold's legs are released, nothing posts.
    let hold = write(
        &dir,
        "hold.json",
        r#"{"effective_date":"2026-03-12","idempotency_key":"hold","legs":[{"side":"debit","account":"6000","amount":"80.00 USD"},{"side":"credit","account":"1000","amount":"80.00 USD"}]}"#,
    );
    let held = doc(&ok(&[
        "reserve",
        "--intent",
        &hold,
        "--evidence",
        &ev,
        "--json",
    ]));
    let hold_vid = text(&held, "vid").to_string();
    let void = write(
        &dir,
        "void.json",
        &format!(
            r#"{{"resolves":"{hold_vid}","disposition":"voids","effective_date":"2026-03-21","idempotency_key":"void"}}"#
        ),
    );
    let voided = doc(&ok(&["resolve", "--intent", &void, "--json"]));
    let void_at = int(&voided, "recorded_at").unwrap_or(-1);

    let ex = doc(&ok(&[
        "explain",
        "balance",
        "1000",
        "--period",
        "FY2026-P03",
        "--json",
    ]));
    assert!(arr(&ex, "cells").is_empty(), "nothing posted or pending");
    let legs = arr(&ex, "contributions");
    assert_eq!(legs.len(), 1);
    assert_eq!(
        (text(&legs[0], "column"), int(&legs[0], "released_at")),
        ("released", Some(void_at))
    );
    assert_eq!(int(&ex, "last_changed_at"), Some(void_at));

    // Human mode shows the same released leg and history, never "no legs".
    let human = ok(&["explain", "balance", "1000", "--period", "FY2026-P03"]);
    assert!(!human.contains("no legs on this account"), "{human}");
    assert!(
        human.contains("every leg below is a released reservation")
            && human.contains(&hold_vid)
            && human.contains(&format!("released at {void_at}"))
            && human.contains(&format!("last changed at recorded sequence {void_at}")),
        "{human}"
    );
    // Control: an account no leg touched in the period is empty, exit 0.
    let empty = ok(&["explain", "balance", "1000", "--period", "FY2026-P04"]);
    assert!(
        empty.contains("no legs on this account in FY2026-P04") && !empty.contains("contributions"),
        "{empty}"
    );
    Ok(())
}
