//! The Polish Bar regression suite (plan §15.1, §15.3, Appendix D; bead
//! fa-nmk4): the named agent-ergonomics checks, each driving the real `fa`
//! binary over a small posted book. Every case logs one JSON line
//! `{case, argv, exit, events, stdout_digest}` to the test's stdout.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

/// One run of the binary: exit code, stdout, stderr.
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn fa_env(book: Option<&Path>, args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fa"));
    if let Some(dir) = book {
        cmd.arg("--book").arg(dir);
    }
    cmd.args(args)
        .env_remove("FA_BOOK")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("run fa");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn fa(book: Option<&Path>, args: &[&str]) -> Run {
    fa_env(book, args, &[])
}

fn digest(text: &str) -> String {
    // FNV-1a over the bytes: a stable fingerprint for the log line only.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

fn events(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|l| json::parse(l).ok())
        .filter_map(|j| j.get("event").and_then(Json::as_str).map(str::to_string))
        .collect()
}

fn log(case: &str, args: &[&str], run: &Run) {
    let argv = args
        .iter()
        .map(|a| format!("\"{}\"", a.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(",");
    let events = events(&run.stdout)
        .iter()
        .map(|e| format!("\"{e}\""))
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "{{\"case\":\"{case}\",\"argv\":[{argv}],\"exit\":{},\"events\":[{events}],\"stdout_digest\":\"{}\"}}",
        run.code,
        digest(&run.stdout)
    );
}

fn tmp(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("fa-polish-{}-{name}-{n}", std::process::id()));
        match std::fs::create_dir(&d) {
            Ok(()) => return d,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => panic!("create fixture dir {}: {e}", d.display()),
        }
    }
}

fn write(dir: &Path, name: &str, text: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, text).expect("write fixture");
    p.display().to_string()
}

/// A book with a two-account chart, FY2026 created, FY2026-P03 open and one
/// posted rent entry with its evidence.
fn posted_book(name: &str) -> (PathBuf, PathBuf) {
    let dir = tmp(name);
    let book = dir.join("book");
    let ok = |args: &[&str]| {
        let run = fa(Some(&book), args);
        assert_eq!(run.code, 0, "{args:?}\n{}\n{}", run.stdout, run.stderr);
        run.stdout
    };
    ok(&["book", "create", "--name", "Polish Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let source = write(&dir, "source.txt", "INVOICE (polish bar fixture)");
    let added = ok(&[
        "document",
        "add",
        &source,
        "--kind",
        "Invoice",
        "--grade",
        "HumanUpload",
        "--json",
    ]);
    let oid = json::parse(added.lines().last().unwrap_or_default())
        .ok()
        .and_then(|j| {
            j.get("data")
                .and_then(|d| d.get("oid"))
                .and_then(Json::as_str)
                .map(str::to_string)
        })
        .expect("document oid");
    let rent = write(
        &dir,
        "rent.json",
        r#"{"effective_date":"2026-03-16","idempotency_key":"rent","legs":[{"side":"debit","account":"6000","amount":"12.50 USD"},{"side":"credit","account":"1000","amount":"12.50 USD"}]}"#,
    );
    ok(&["post", "--intent", &rent, "--evidence", &oid, "--json"]);
    // A register cache never advanced differs from its refold (fa-q2z):
    // advance March's before `verify registers` reads it.
    ok(&["registers", "advance", "--period", "FY2026-P03", "--json"]);
    (dir, book)
}

/// The read commands the suite judges, with `--json`.
const READS: &[&[&str]] = &[
    &["tb", "--period", "FY2026-P03", "--json"],
    &[
        "explain",
        "balance",
        "1000",
        "--period",
        "FY2026-P03",
        "--json",
    ],
    &[
        "gl",
        "detail",
        "--account",
        "6000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--json",
    ],
    &["period", "list", "--json"],
    &["chart", "list", "--json"],
    &["book", "info", "--json"],
    &["verify", "registers", "--period", "FY2026-P03", "--json"],
    &["capabilities", "--json"],
    &["law", "list", "--json"],
];

/// Plan Appendix D `verify-determinism`: every read twice, in separate
/// processes, under SOURCE_DATE_EPOCH, prints byte-identical stdout.
#[test]
fn verify_determinism() {
    let (_dir, book) = posted_book("determinism");
    for args in READS {
        let env = [("SOURCE_DATE_EPOCH", "1767225600")];
        let first = fa_env(Some(&book), args, &env);
        let second = fa_env(Some(&book), args, &env);
        log("determinism", args, &first);
        assert_eq!(
            first.code, 0,
            "{args:?}\n{}\n{}",
            first.stdout, first.stderr
        );
        assert_eq!(
            first.stdout, second.stdout,
            "{args:?} is not byte-deterministic"
        );
    }
}

/// Plan Appendix D `verify-stdout-stderr-split`: in robot mode stdout holds
/// only envelopes (one JSON object per line, each with `v` and `event`),
/// on success and failure alike; diagnostics never reach stdout.
#[test]
fn verify_stdout_stderr_split() {
    let (dir, book) = posted_book("split");
    let unbalanced = write(
        &dir,
        "unbalanced.json",
        r#"{"effective_date":"2026-03-17","idempotency_key":"bad","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"2.00 USD"}]}"#,
    );
    let cases: Vec<Vec<&str>> = READS
        .iter()
        .map(|a| a.to_vec())
        .chain([
            vec!["post", "--intent", unbalanced.as_str(), "--json"],
            vec!["tb", "--period", "FY2099-P01", "--json"],
            vec!["nosuchverb", "--json"],
        ])
        .collect();
    for args in &cases {
        let run = fa(Some(&book), args);
        log("split", args, &run);
        assert!(!run.stdout.is_empty(), "{args:?} printed nothing");
        for line in run.stdout.lines() {
            let parsed = json::parse(line);
            assert!(
                parsed.is_ok(),
                "{args:?}: a stdout line is not JSON: {line}"
            );
            let envelope = parsed.unwrap_or(Json::Null);
            assert!(
                envelope.get("v").is_some() && envelope.get("event").is_some(),
                "{args:?}: a stdout line is not an envelope: {line}"
            );
        }
        for line in run.stderr.lines() {
            assert!(
                json::parse(line)
                    .ok()
                    .and_then(|j| j.get("event").cloned())
                    .is_none(),
                "{args:?}: an envelope reached stderr: {line}"
            );
        }
    }
}

/// Plan Appendix D `verify-non-tty-discipline`: with NO_COLOR, CI=true or
/// TERM=dumb, and stdout not a terminal, human output carries no ANSI
/// styling, and nothing prompts: a command that needs confirmation refuses
/// instead of waiting for input on a closed stdin.
#[test]
fn verify_non_tty_discipline() {
    let (_dir, book) = posted_book("non-tty");
    let envs: [&[(&str, &str)]; 4] = [
        &[],
        &[("NO_COLOR", "1")],
        &[("CI", "true")],
        &[("TERM", "dumb")],
    ];
    let human: &[&[&str]] = &[
        &["tb", "--period", "FY2026-P03"],
        &["explain", "balance", "1000", "--period", "FY2026-P03"],
        &["period", "list"],
        &["nosuchverb"],
        &[],
    ];
    for env in envs {
        for args in human {
            let run = fa_env(Some(&book), args, env);
            log("non-tty", args, &run);
            assert!(
                !run.stdout.contains('\u{1b}') && !run.stderr.contains('\u{1b}'),
                "{args:?} under {env:?} printed ANSI escapes"
            );
        }
    }
    // A dangerous operation without --yes refuses (exit 7); it never prompts.
    let lock = ["period", "lock", "FY2026-P03"];
    let run = fa(Some(&book), &lock);
    log("non-tty", &lock, &run);
    assert_eq!(run.code, 7, "{}\n{}", run.stdout, run.stderr);
}

/// Plan §15.3 intent inference: the spellings agents try first.
#[test]
fn first_try_spellings_matrix() {
    let (dir, book) = posted_book("first-try");
    let canonical = fa(Some(&book), &["tb", "--period", "FY2026-P03", "--json"]);
    assert_eq!(canonical.code, 0, "{}", canonical.stderr);
    let tb_data = |stdout: &str| {
        stdout
            .lines()
            .filter_map(|l| json::parse(l).ok())
            .find(|j| j.get("event").and_then(Json::as_str) == Some("trial_balance"))
            .and_then(|j| j.get("data").cloned())
    };
    let expected = tb_data(&canonical.stdout).expect("trial_balance");
    // Registered synonyms run exactly as the canonical spelling.
    let same: &[&[&str]] = &[
        &["--robot", "tb", "--period", "FY2026-P03"],
        &["tb", "--robot", "--period", "FY2026-P03"],
        &["tb", "--for-period", "FY2026-P03", "--json"],
        &["trial-balance", "--period", "FY2026-P03", "--json"],
    ];
    for args in same {
        let run = fa(Some(&book), args);
        log("first-try", args, &run);
        assert_eq!(run.code, 0, "{args:?}\n{}\n{}", run.stdout, run.stderr);
        assert_eq!(tb_data(&run.stdout).as_ref(), Some(&expected), "{args:?}");
    }
    let run = fa(
        Some(&book),
        &["tb", "--effective-at", "2026-03-31", "--json"],
    );
    log("first-try", &["tb", "--effective-at"], &run);
    assert_eq!(run.code, 0, "{}\n{}", run.stdout, run.stderr);
    assert!(tb_data(&run.stdout).is_some(), "{}", run.stdout);
    // `fa gl` is `fa gl detail`; `fa balance` is `fa explain balance`.
    for (args, event) in [
        (
            &[
                "gl",
                "--account",
                "6000",
                "--from",
                "2026-03-01",
                "--to",
                "2026-03-31",
                "--json",
            ][..],
            "general_ledger",
        ),
        (
            &["balance", "1000", "--period", "FY2026-P03", "--json"][..],
            "balance_explained",
        ),
    ] {
        let run = fa(Some(&book), args);
        log("first-try", args, &run);
        assert_eq!(run.code, 0, "{args:?}\n{}\n{}", run.stdout, run.stderr);
        assert!(events(&run.stdout).iter().any(|e| e == event), "{args:?}");
    }
    // A one-edit flag typo on a read runs corrected, with a warning naming
    // the correction.
    let typo = ["tb", "--period", "FY2026-P03", "--jsno"];
    let run = fa(Some(&book), &typo);
    log("first-try", &typo, &run);
    assert_eq!(run.code, 0, "{}\n{}", run.stdout, run.stderr);
    assert_eq!(tb_data(&run.stdout).as_ref(), Some(&expected));
    assert!(
        run.stdout
            .contains("`--jsno` is not a flag; ran as `--json`"),
        "{}",
        run.stdout
    );
    // The same typo on a writing command never runs: usage, naming the fix.
    let rent = write(
        &dir,
        "more.json",
        r#"{"effective_date":"2026-03-18","idempotency_key":"more","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    let write_typo = ["post", "--intnt", rent.as_str(), "--json"];
    let run = fa(Some(&book), &write_typo);
    log("first-try", &write_typo, &run);
    assert_eq!(run.code, 2, "{}\n{}", run.stdout, run.stderr);
    assert!(run.stdout.contains("--intent"), "{}", run.stdout);
    // A misspelled verb is suggested, never run.
    let verb_typo = ["psot", "--intent", rent.as_str(), "--json"];
    let run = fa(Some(&book), &verb_typo);
    log("first-try", &verb_typo, &run);
    assert_eq!(run.code, 2, "{}\n{}", run.stdout, run.stderr);
    assert!(run.stdout.contains("fa post"), "{}", run.stdout);
}

/// Plan Appendix D: every non-zero exit emits exactly one `error` event
/// carrying `refusal_id`, `exit` and `class`, and its `exit` is the
/// process's exit code; `1` is never an exit code.
#[test]
fn exactly_one_error_event_per_nonzero_exit() {
    let (dir, book) = posted_book("errors");
    let unbalanced = write(
        &dir,
        "unbalanced.json",
        r#"{"effective_date":"2026-03-17","idempotency_key":"bad","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"2.00 USD"}]}"#,
    );
    let missing = dir.join("absent");
    let cases: Vec<(Option<&Path>, Vec<&str>)> = vec![
        (Some(&book), vec!["nosuchverb", "--json"]),
        (Some(&book), vec!["tb", "--json"]),
        (
            Some(&book),
            vec!["post", "--intent", unbalanced.as_str(), "--json"],
        ),
        (Some(&book), vec!["tb", "--period", "FY2099-P01", "--json"]),
        (Some(&book), vec!["period", "lock", "FY2026-P03", "--json"]),
        (
            Some(missing.as_path()),
            vec!["tb", "--period", "FY2026-P03", "--json"],
        ),
    ];
    let mut exits = std::collections::BTreeSet::new();
    for (where_, args) in &cases {
        let run = fa(*where_, args);
        log("errors", args, &run);
        assert_ne!(run.code, 0, "{args:?} succeeded:\n{}", run.stdout);
        assert_ne!(run.code, 1, "{args:?} exited 1");
        let errors: Vec<Json> = run
            .stdout
            .lines()
            .filter_map(|l| json::parse(l).ok())
            .filter(|j| j.get("event").and_then(Json::as_str) == Some("error"))
            .collect();
        assert_eq!(errors.len(), 1, "{args:?}:\n{}", run.stdout);
        let data = errors[0].get("data").cloned().unwrap_or(Json::Null);
        for key in ["refusal_id", "exit", "class"] {
            assert!(
                data.get(key).is_some(),
                "{args:?}: no {key}: {}",
                run.stdout
            );
        }
        let exit = match data.get("exit") {
            Some(Json::Int(n)) => Some(*n),
            _ => None,
        };
        assert_eq!(exit, Some(i128::from(run.code)), "{args:?}: {}", run.stdout);
        exits.insert(run.code);
    }
    assert!(
        exits.len() >= 3,
        "the cases reach several exit classes: {exits:?}"
    );
}

/// Plan §15.3: bare `fa` prints triage and exits 0; it never opens a TUI.
#[test]
fn bare_fa_prints_triage_and_exits_zero() {
    for args in [&[][..], &["--json"][..]] {
        let run = fa(None, args);
        log("bare", args, &run);
        assert_eq!(run.code, 0, "{}\n{}", run.stdout, run.stderr);
        assert!(!run.stdout.is_empty());
        assert!(!run.stdout.contains('\u{1b}'));
    }
    let run = fa(None, &["--json"]);
    assert_eq!(events(&run.stdout), ["triage"], "{}", run.stdout);
}
