//! Binary-level regression tests for the agent contract (plan §15.3; fa-coa
//! examples): exit codes per refusal, stdout data / stderr diagnostics, empty
//! results exit 0, bare `fa` prints triage, typos get a suggestion.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

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

    // Reopen the persistent book for every command. Stock carries the earlier
    // period's real posting; no invented opening entry is supplied to the report.
    let (code, out, err) = fa(Some(&book), &["period", "open", "FY2026-P02", "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    let opening = write(
        &dir,
        "february.json",
        r#"{"effective_date":"2026-02-20","idempotency_key":"february-rent","legs":[{"side":"debit","account":"6000","amount":"100.00 USD"},{"side":"credit","account":"1000","amount":"100.00 USD"}]}"#,
    );
    let (code, out, err) = fa(Some(&book), &["post", "--intent", &opening, "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    let future = write(
        &dir,
        "future-in-march.json",
        r#"{"effective_date":"2026-03-25","idempotency_key":"future-in-march","legs":[{"side":"debit","account":"6000","amount":"200.00 USD"},{"side":"credit","account":"1000","amount":"200.00 USD"}]}"#,
    );
    let (code, out, err) = fa(Some(&book), &["post", "--intent", &future, "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    let before_backdate = field(&out, "recorded_at").unwrap().to_string();
    let backdate = write(
        &dir,
        "late-recorded-backdate.json",
        r#"{"effective_date":"2026-03-10","idempotency_key":"late-recorded-backdate","legs":[{"side":"debit","account":"6000","amount":"300.00 USD"},{"side":"credit","account":"1000","amount":"300.00 USD"}]}"#,
    );
    let (code, out, err) = fa(Some(&book), &["post", "--intent", &backdate, "--json"]);
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
    let intent = write(
        &dir,
        "entry.json",
        r#"{"effective_date":"2026-03-15","description":"rent","idempotency_key":"inv-1","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}]}"#,
    );
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &intent, "--json"]);
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
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &changed, "--json"]);
    assert_eq!(code, 6, "{out}");
    assert!(out.contains("\"code\":\"FA-REF-032\""), "{out}");
    // An unsupported class is refused with the bead that lands it (exit 3).
    let repl = write(
        &dir,
        "repl.json",
        r#"{"class":"Replacement","effective_date":"2026-03-15","idempotency_key":"rp-1","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &repl, "--json"]);
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
    let (code, out, err) = fa(Some(&book), &["reserve", "--intent", &hold, "--json"]);
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
    let (code, out, _) = fa(Some(&book), &["reserve", "--intent", &timed, "--json"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("timed holds"), "{out}");
    let stray = write(
        &dir,
        "stray.json",
        r#"{"effective_date":"2026-03-10","idempotency_key":"stray","legs":[{"side":"debit","account":"6000","amount":"1.00 USD","source_ordinal":0},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &stray, "--json"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("source_ordinal"), "{out}");
    // `fa reserve` refuses an intent that says it is something else.
    let not_a_hold = write(
        &dir,
        "orig.json",
        r#"{"class":"Original","effective_date":"2026-03-10","idempotency_key":"o-1","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    let (code, _, _) = fa(Some(&book), &["reserve", "--intent", &not_a_hold, "--json"]);
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
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &hold_2, "--json"]);
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

    let invoice = write(
        &dir,
        "invoice.json",
        r#"{"effective_date":"2026-03-05","idempotency_key":"inv-9","legs":[{"side":"debit","account":"1200","amount":"500.00 USD"},{"side":"credit","account":"4000","amount":"500.00 USD"}]}"#,
    );
    let (code, out, err) = fa(Some(&book), &["post", "--intent", &invoice, "--json"]);
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
    let (code, out, err) = fa(Some(&book), &["post", "--intent", &receipt, "--json"]);
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
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &over, "--json"]);
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
