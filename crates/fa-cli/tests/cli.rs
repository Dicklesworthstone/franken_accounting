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

/// The one event a non-zero exit emits (plan Appendix D).
const ERROR_EVENTS: &[&str] = &["error"];

/// An exit code's class: its name in exit_codes.toml.
fn exit_class(code: i32) -> String {
    let exits = fa_registry::ExitCodes::embedded().expect("exit_codes.toml");
    let row = exits.rows.iter().find(|row| i32::from(row.code) == code);
    assert!(row.is_some(), "exit {code} is not in exit_codes.toml");
    row.map(|row| row.name.clone()).unwrap_or_default()
}

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
        assert_eq!(
            field(last, "class"),
            Some(exit_class(code).as_str()),
            "the error event names the exit's class: args={args:?}"
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
fn retained_trial_balances_replay_exactly_and_report_later_relevant_entries() -> std::io::Result<()>
{
    use std::io::Write;
    use std::process::Stdio;

    let dir = tmp("report-certificate")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        assert!(err.is_empty(), "{err}");
        out
    };
    ok(&["book", "create", "--name", "Certificate Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let evidence = source_doc(&dir, &book);
    let rent = write(
        &dir,
        "rent.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"rent","legs":[{"side":"debit","account":"6000","amount":"100.00 USD"},{"side":"credit","account":"1000","amount":"100.00 USD"}]}"#,
    );
    ok(&["post", "--intent", &rent, "--evidence", &evidence, "--json"]);
    let before = report(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    let mut retained = Vec::new();

    for (name, selector) in [
        ("stock", vec!["--period", "FY2026-P03"]),
        ("asof", vec!["--as-of", "2026-03-15"]),
        ("activity", vec!["--period", "FY2026-P03", "--activity"]),
    ] {
        let path = dir.join(format!("{name}.cert")).display().to_string();
        let mut args = vec!["tb"];
        args.extend(selector);
        args.extend(["--certificate-out", path.as_str(), "--json"]);
        let certified = ok(&args);
        let lines: Vec<&str> = certified.lines().collect();
        assert_eq!(lines.len(), 2, "report and its retained certificate");
        assert_eq!(field(lines[0], "event"), Some("trial_balance"));
        assert_eq!(field(lines[1], "event"), Some("report_certificate"));
        let original = format!("{}\n", lines[0]);
        let certificate = doc(lines[1]);
        let oid = text(&certificate, "oid");
        assert_eq!(oid.len(), 64);
        assert_eq!(field(lines[0], "certificate"), Some(oid));
        assert_eq!(field(lines[1], "certificate"), Some(oid));
        assert_eq!(text(&certificate, "file"), path);
        assert_eq!(text(&certificate, "replay_scope"), "fa-fold-over-prefix");
        assert_eq!(text(&certificate, "authority"), "embedded-owner");
        assert_eq!(text(&certificate, "output_format"), "fa:trial-balance:v1");
        assert!(int(&certificate, "native_inputs").is_some_and(|n| n > 0));
        let bytes = std::fs::read(&path)?;
        let decoded = fa::ReportCertificate::decode(&bytes).expect("retained canonical bytes");
        assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
        let replayed = ok(&["replay", &path, "--json"]);
        assert_eq!(replayed, original, "{name}: complete robot line replays");
        let status = ok(&["certificate", "status", &path, "--json"]);
        let status = doc(&status);
        assert_eq!(text(&status, "status"), "Current");
        assert_eq!(int(&status, "known_at"), int(&certificate, "known_at"));
        assert_eq!(int(&status, "checked_at"), int(&certificate, "known_at"));
        assert!(arr(&status, "later_entries").is_empty());

        if name == "stock" {
            // Human-copyable hex and actual process stdin use the same decoder
            // as a saved binary certificate, without needing a certificate store.
            let mut child = Command::new(env!("CARGO_BIN_EXE_fa"))
                .arg("--book")
                .arg(&book)
                .args(["replay", "-", "--json"])
                .env_remove("FA_BOOK")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            child
                .stdin
                .take()
                .expect("piped stdin")
                .write_all(text(&certificate, "bytes").as_bytes())?;
            let output = child.wait_with_output()?;
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(output.status.success(), "{stdout}");
            check_robot_output(&["replay", "-", "--json"], 0, &stdout);
            assert_eq!(
                stdout, original,
                "hex stdin replays the complete robot line"
            );

            // An explicit output never truncates an existing certificate, and
            // its refusal does not emit a report that looks successfully retained.
            let (code, out, _) = fa(Some(&book), &args);
            assert_eq!(code, 2, "{out}");
            assert_eq!(out.lines().count(), 1, "{out}");
            assert!(out.contains("never overwritten"), "{out}");
            assert_eq!(std::fs::read(&path)?, bytes);

            let mut damaged = bytes.clone();
            *damaged.last_mut().unwrap() ^= 1;
            let tampered = dir.join("tampered.cert");
            std::fs::write(&tampered, damaged)?;
            for verb in [vec!["replay"], vec!["certificate", "status"]] {
                let tampered = tampered.display().to_string();
                let mut args = verb;
                args.extend([tampered.as_str(), "--json"]);
                let (code, out, _) = fa(Some(&book), &args);
                assert_eq!(code, 8, "{out}");
                assert_eq!(out.lines().count(), 1, "{out}");
                assert!(out.contains("FA-REF-150"), "{out}");
                assert_eq!(field(&out, "certificate"), Some("null"), "{out}");
            }

            let other = dir.join("other-book");
            let (code, out, _) = fa(
                Some(&other),
                &["book", "create", "--name", "Other", "--json"],
            );
            assert_eq!(code, 0, "{out}");
            let (code, out, _) = fa(Some(&other), &["replay", &path, "--json"]);
            assert_eq!(code, 8, "{out}");
            assert!(out.contains("different book"), "{out}");
        }
        retained.push((path, original));
    }
    assert_eq!(
        report(&book, &["tb", "--period", "FY2026-P03", "--json"]),
        before,
        "certification, status, replay and failed retention never publish journal writes"
    );

    let later = write(
        &dir,
        "later.json",
        r#"{"effective_date":"2026-03-14","idempotency_key":"later","legs":[{"side":"debit","account":"6000","amount":"25.00 USD"},{"side":"credit","account":"1000","amount":"25.00 USD"}]}"#,
    );
    let posted = ok(&[
        "post",
        "--intent",
        &later,
        "--evidence",
        &evidence,
        "--json",
    ]);
    let later_vid = field(&posted, "vid").unwrap();
    for (path, original) in retained {
        let status = doc(&ok(&["certificate", "status", &path, "--json"]));
        assert_eq!(text(&status, "status"), "SupersededBy");
        assert_eq!(
            arr(&status, "later_entries"),
            &[Json::Str(later_vid.to_string())]
        );
        assert!(int(&status, "checked_at") > int(&status, "known_at"));
        assert_eq!(ok(&["replay", &path, "--json"]), original);
    }
    assert_cash_credits(
        &report(&book, &["tb", "--period", "FY2026-P03", "--json"]),
        "125.00 USD",
    );
    Ok(())
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
        (out.contains("\"event\":\"error\"") && out.contains("\"class\":\"usage\""))
            && out.contains("fa period"),
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
    // The capability model (fa-llx): the closed op vocabulary, the profiles
    // and what each can never hold, and the embedded binding's trust boundary.
    let caps = doc(&out);
    // The invariant clauses this build enforces (fa-37f, MaroonSquirrel 3229).
    let invariants = caps.get("invariants").expect("invariants section");
    let live: Vec<&str> = arr(invariants, "live")
        .iter()
        .filter_map(Json::as_str)
        .collect();
    assert!(live.contains(&"FA-INV-01.per-unit"), "{live:?}");
    assert_eq!(arr(invariants, "gate_g1").len(), 18, "{out}");
    let model = caps.get("capability").expect("capability section");
    let ops: Vec<&str> = arr(model, "ops").iter().filter_map(Json::as_str).collect();
    assert_eq!(ops.len(), 21, "{ops:?}");
    assert!(ops.contains(&"post_closed") && ops.contains(&"rule_change"));
    let agent = arr(model, "profiles")
        .iter()
        .find(|p| text(p, "name") == "Agent")
        .expect("Agent profile");
    let forbidden: Vec<&str> = arr(agent, "forbidden_ops")
        .iter()
        .filter_map(Json::as_str)
        .collect();
    assert!(forbidden.contains(&"approve") && forbidden.contains(&"restate"));
    let binding = model.get("binding").expect("binding");
    assert_eq!(text(binding, "profile"), "Human");
    assert!(text(binding, "trust_boundary").contains("never authenticates"));
    assert_eq!(text(model, "policy_oid").len(), 64);
    let (code, out, _) = fa(None, &["robot-docs", "exit-codes"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("7 safety") && out.contains("8 verification"),
        "{out}"
    );
    let (code, _, _) = fa(None, &["robot-docs", "guide"]);
    assert_eq!(code, 0);
}

/// R4 (fa-llx): a Lock is dual-controlled, so the CLI plans it, a second
/// principal approves the plan's digest, and the commit cites that approval.
/// Without an approval it refuses 012; with the preparer's own approval, 008.
#[test]
fn a_lock_commits_from_its_plan_with_a_second_principals_approval() -> std::io::Result<()> {
    let dir = tmp("approve-lock")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Approve Co"]).0,
        0
    );
    assert_eq!(
        fa(Some(&book), &["period", "create", "--fiscal-year", "2026"]).0,
        0
    );
    let march = "FY2026-P03";
    assert_eq!(fa(Some(&book), &["period", "open", march]).0, 0);
    assert_eq!(fa(Some(&book), &["period", "close", march, "--yes"]).0, 0);
    // Confirmed with --yes, so the kernel's verdict is what refuses it.
    let (code, out, _) = fa(Some(&book), &["period", "lock", march, "--yes", "--json"]);
    assert_eq!(code, 7, "{out}");
    assert!(out.contains("\"refusal_id\":\"FA-REF-012\""), "{out}");
    let plan = dir.join("lock.plan").display().to_string();
    let (code, out, _) = fa(
        Some(&book),
        &["period", "lock", march, "--plan-out", &plan, "--json"],
    );
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("\"event\":\"period_planned\""), "{out}");
    assert!(out.contains("\"to\":\"Locked\""), "{out}");
    let digest = field(&out, "proposal_digest")
        .unwrap_or_default()
        .to_string();
    assert_eq!(digest.len(), 64, "{out}");
    // Planning committed nothing.
    let (_, out, _) = fa(Some(&book), &["period", "list", "--json"]);
    assert!(!out.contains("Locked"), "{out}");
    // An approval needs a plan to bind.
    let (code, out, _) = fa(
        Some(&book),
        &[
            "period",
            "lock",
            march,
            "--approval",
            &"0".repeat(32),
            "--yes",
            "--json",
        ],
    );
    assert_eq!(code, 2, "{out}");
    // The preparer's own approval is recorded, and refused as self-approval.
    let (code, out, _) = fa(Some(&book), &["approve", "--proposal", &digest, "--json"]);
    assert_eq!(code, 0, "{out}");
    let own = field(&out, "approval_vid").unwrap_or_default().to_string();
    let (code, out, _) = fa(
        Some(&book),
        &[
            "period",
            "lock",
            march,
            "--plan",
            &plan,
            "--approval",
            &own,
            "--json",
        ],
    );
    assert_eq!(code, 7, "{out}");
    assert!(out.contains("\"refusal_id\":\"FA-REF-008\""), "{out}");
    // A second principal approves; the lock commits citing it.
    let (code, out, _) = fa(
        Some(&book),
        &[
            "approve",
            "--proposal",
            &digest,
            "--as",
            "controller",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("\"event\":\"approved\""), "{out}");
    assert!(out.contains("\"already_recorded\":false"), "{out}");
    let approval = field(&out, "approval_vid").unwrap_or_default().to_string();
    let (code, out, _) = fa(
        Some(&book),
        &[
            "approve",
            "--proposal",
            &digest,
            "--as",
            "controller",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("\"already_recorded\":true"), "{out}");
    let (code, out, _) = fa(
        Some(&book),
        &[
            "period",
            "lock",
            march,
            "--plan",
            &plan,
            "--approval",
            &approval,
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("\"event\":\"period_transitioned\"") && out.contains("\"to\":\"Locked\""),
        "{out}"
    );
    // The plan is spent: the period is Locked now, so replaying it is an
    // illegal transition.
    let (code, out, _) = fa(
        Some(&book),
        &[
            "period",
            "lock",
            march,
            "--plan",
            &plan,
            "--approval",
            &approval,
            "--json",
        ],
    );
    assert_eq!(code, 7, "{out}");
    assert!(out.contains("\"refusal_id\":\"FA-REF-040\""), "{out}");
    Ok(())
}

#[test]
fn a_grant_typo_is_a_usage_error_naming_the_op_never_a_silently_held_string() -> std::io::Result<()>
{
    let dir = tmp("grant-typo")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Grant Co"]).0,
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
        r#"{"effective_date":"2026-03-15","description":"rent","idempotency_key":"g-1","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}]}"#,
    );
    let (code, out, _) = fa(
        Some(&book),
        &[
            "post",
            "--intent",
            &intent,
            "--evidence",
            &ev,
            "--grant",
            "post_clsoed",
            "--json",
        ],
    );
    assert_eq!(code, 2, "{out}");
    assert!(
        (out.contains("\"event\":\"error\"") && out.contains("\"class\":\"usage\"")),
        "{out}"
    );
    assert!(out.contains("did you mean `post_closed`"), "{out}");
    // Nothing was posted; the corrected grant posts.
    let (code, out, _) = fa(
        Some(&book),
        &[
            "post",
            "--intent",
            &intent,
            "--evidence",
            &ev,
            "--grant",
            "post_closed",
            "--yes",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("\"event\":\"posted\""), "{out}");
    Ok(())
}

/// fa-40l (rulings 171/173): the Book boundary anchors caller spellings;
/// the robot book remains its hex ID. Exercise the real binary from child
/// working directories without changing this test process's cwd. This is
/// a regression probe, not a claim that the old binary was executed here.
#[test]
fn book_path_aliases_have_byte_identical_robot_read_output() -> std::io::Result<()> {
    let dir = tmp("book-path-aliases")?;
    let caller = dir.join("caller");
    std::fs::create_dir(&caller)?;
    let book = dir.join("acme");
    assert!(book.is_absolute(), "absolute alias: {}", book.display());

    let run = |cwd: &Path, spelling: &Path, via_env: bool, args: &[&str]| -> Vec<u8> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fa"));
        cmd.current_dir(cwd).env_remove("FA_BOOK");
        if via_env {
            cmd.env("FA_BOOK", spelling);
        } else {
            cmd.arg("--book").arg(spelling);
        }
        let out = cmd.args(args).output().expect("run fa in child cwd");
        let code = out.status.code().unwrap_or(-1);
        let stdout = std::str::from_utf8(&out.stdout).expect("robot stdout is UTF-8");
        let stderr = String::from_utf8_lossy(&out.stderr);
        check_robot_output(args, code, stdout);
        assert_eq!(
            code, 0,
            "cwd={cwd:?} book={spelling:?} via_env={via_env} args={args:?}\nstdout={stdout}\nstderr={stderr}"
        );
        assert!(stderr.is_empty(), "success stderr: {stderr}");
        out.stdout
    };
    let parent_alias = Path::new("../acme");
    let created = run(
        &caller,
        parent_alias,
        false,
        &["book", "create", "--name", "Path Alias Co", "--json"],
    );
    let created_text = std::str::from_utf8(&created).unwrap();
    assert_eq!(text(&robot_line(created_text), "event"), "book_created");
    let created_data = doc(created_text);
    assert_eq!(text(&created_data, "name"), "Path Alias Co");
    let book_id = text(&created_data, "book_id").to_string();
    assert_eq!(book_id.len(), 32, "book ID: {created_text}");
    assert!(book_id.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(text(&robot_line(created_text), "book"), book_id);
    assert!(book.join("book.keys").is_file() && book.join("store").is_dir());

    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Alias Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"6000","name":"Alias Rent","type":"Expense","unit":"USD"}]}"#,
    );
    let installed = run(
        &caller,
        parent_alias,
        false,
        &["chart", "import", &chart, "--json"],
    );
    let installed_text = std::str::from_utf8(&installed).unwrap();
    assert_eq!(
        text(&robot_line(installed_text), "event"),
        "chart_installed"
    );
    assert_eq!(int(&doc(installed_text), "accounts"), Some(2));

    for (args, event) in [
        (["book", "info", "--json"], "book"),
        (["chart", "list", "--json"], "accounts"),
    ] {
        let absolute = run(&caller, &book, false, &args);
        let stdout = std::str::from_utf8(&absolute).unwrap();
        let envelope = robot_line(stdout);
        assert_eq!(text(&envelope, "event"), event, "{stdout}");
        assert_eq!(text(&envelope, "book"), book_id, "{stdout}");
        let coordinate = envelope.get("coordinate").expect("book coordinate");
        assert_eq!(text(coordinate, "branch"), "trunk", "{stdout}");
        assert!(int(coordinate, "known_at").is_some_and(|seq| seq > 0));
        let data = doc(stdout);
        if event == "book" {
            assert_eq!(text(&data, "book_id"), book_id, "{stdout}");
            assert_eq!(int(&data, "accounts"), Some(2), "{stdout}");
        } else {
            let accounts = arr(&data, "accounts");
            let actual: Vec<_> = accounts
                .iter()
                .map(|a| (text(a, "code"), text(a, "name"), text(a, "unit")))
                .collect();
            assert_eq!(
                actual,
                vec![("1000", "Alias Cash", "USD"), ("6000", "Alias Rent", "USD")],
                "{stdout}"
            );
        }
        for (cwd, spelling) in [
            (caller.as_path(), parent_alias),
            (dir.as_path(), Path::new("./acme")),
            (caller.as_path(), book.as_path()),
        ] {
            for via_env in [false, true] {
                let aliased = run(cwd, spelling, via_env, &args);
                assert_eq!(
                    aliased, absolute,
                    "complete stdout differs: cwd={cwd:?} book={spelling:?} via_env={via_env} args={args:?}"
                );
            }
        }
    }
    Ok(())
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
    let (code, next, err) = follow_next_action(&book, &out, march);
    assert_eq!(code, 0, "posted's next action: {next}\n{err}");
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
        out.contains("\"event\":\"error\"")
            && out.contains("\"class\":\"refusal\"")
            && out.contains("\"refusal_id\":\"FA-REF-001\"")
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
    let (code, next, err) = follow_next_action(&book, &out, march);
    assert_eq!(
        code, 0,
        "registers_materialized's next action: {next}\n{err}"
    );
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
    // A SoftClosed period still takes a post under `post_softclosed`; it lands
    // in March after the register was materialized. The checked prefix stays
    // valid and ordinary lag remains a successful verification.
    let (code, out, _) = fa(
        Some(&book),
        &[
            "post",
            "--intent",
            &late,
            "--evidence",
            &ev,
            "--grant",
            "post_softclosed",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let (code, out, err) = fa(
        Some(&book),
        &["verify", "registers", "--period", march, "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("registers_verified"));
    let verified = doc(&out);
    let checks = arr(&verified, "periods");
    assert_eq!(checks[0].get("stale"), Some(&Json::Bool(true)));
    assert!(int(&checks[0], "lag_entries").is_some_and(|n| n >= 1));
    assert!(out.contains("fa registers advance --period FY2026-P03 --json"));
    let (code, _, _) = fa(Some(&book), &["period", "close", march, "--yes"]);
    assert_eq!(code, 0);
    let later = write(
        &dir,
        "later.json",
        r#"{"effective_date":"2026-03-21","idempotency_key":"inv-2002","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &later, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 7, "{out}");
    assert!(
        out.contains("\"refusal_id\":\"FA-REF-010\"") && out.contains("Closed"),
        "{out}"
    );
    // An illegal transition is a safety block too.
    let (code, out, _) = fa(Some(&book), &["period", "open", march, "--json"]);
    assert_eq!(code, 7, "{out}");
    // Reopening a Closed period is case-bound (Appendix C W(reopen, 2, case)):
    // with no restatement case to decide the exclusion it is refused under
    // SoD, never exempted (fa-llx). Confirmed with --yes, so the kernel's
    // verdict, not the confirmation gate, is what refuses it.
    let (code, out, _) = fa(
        Some(&book),
        &["period", "reopen", march, "--to", "open", "--yes", "--json"],
    );
    assert_eq!(code, 7, "{out}");
    assert!(
        out.contains("\"refusal_id\":\"FA-REF-008\"")
            && out.contains("case_preparer")
            && out.contains("sod_policy.toml#period-reopen-closed")
            && out.contains("fa-oz3"),
        "{out}"
    );

    // Human mode on the same book: plain text, no JSON.
    let (code, out, _) = fa(Some(&book), &["book", "info"]);
    assert_eq!(code, 0);
    assert!(
        !out.contains("\"event\"") && out.contains("accounts"),
        "{out}"
    );
    Ok(())
}

/// Exercise the incremental engine through fresh binary invocations and a
/// real persisted book. A full-fold rebuild on every call cannot satisfy
/// the suffix decode count or the no-write retry below.
#[test]
fn register_advance_consumes_only_new_entries_and_refuses_damaged_cache() -> std::io::Result<()> {
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::types::Budget;
    use fa::{Book, BookKeys, Entropy};
    use fa_journal::BookSpec;
    use fa_model::Id128;
    use fa_model::symbols::{property, relation};
    use fgdb::{Database, DatabaseKeys, WriteBatch};
    use fgdb_types::CanonicalScalar;
    use fgdb_types::context::PurposeContexts;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    let dir = tmp("register-advance")?;
    let book = dir.join("book");
    let book_id = Id128([57; 16]);
    let keys = BookKeys::for_development(57);
    let handle = Book::create_dir(
        &book,
        keys.clone(),
        BookSpec {
            book_id,
            name: "Incremental registers".into(),
            base_unit: fa_money::UnitRegistry::embedded()
                .unwrap()
                .lookup("USD")
                .unwrap(),
            calendar: fa_time::FiscalCalendar::monthly("fiscal", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(57),
    )
    .unwrap();
    keys.save(&book.join("book.keys")).unwrap();
    drop(handle);
    let ok = |args: &[&str]| {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        assert!(err.is_empty(), "{err}");
        out
    };
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    let period = "FY2026-P03";
    ok(&["period", "open", period, "--json"]);
    let evidence = source_doc(&dir, &book);
    let first = write(
        &dir,
        "first.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"first","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}]}"#,
    );
    ok(&[
        "post",
        "--intent",
        &first,
        "--evidence",
        &evidence,
        "--json",
    ]);
    let advance = ["registers", "advance", "--period", period, "--json"];
    let initial_output = ok(&advance);
    let initial = doc(&initial_output);
    assert_eq!(initial.get("wrote"), Some(&Json::Bool(true)));
    assert_eq!(initial.get("rebuilt"), Some(&Json::Bool(false)));
    assert_eq!(int(&initial, "entries"), Some(1));
    assert_eq!(int(&initial, "cells"), Some(2));
    assert_eq!(int(&initial, "from"), Some(0));
    assert!(int(&initial, "entries_decoded").unwrap() > 0);
    let first_through = int(&initial, "through").unwrap();
    assert!(int(&initial, "recorded_at").unwrap() > first_through);
    // Follow the emitted next action after filling its documented selector;
    // a hint that omits the required period must fail through the real CLI.
    let envelope = robot_line(&initial_output);
    let actions = arr(&envelope, "next_actions");
    assert_eq!(actions.len(), 1, "{initial_output}");
    assert!(!text(&actions[0], "why").is_empty());
    let command = text(&actions[0], "command").replace("<code>", period);
    let mut words = command.split_whitespace();
    assert_eq!(words.next(), Some("fa"), "{command}");
    let verification = ok(&words.collect::<Vec<_>>());
    assert_eq!(field(&verification, "event"), Some("registers_verified"));

    // A separate valid cache will lag the next post. Mixed verification
    // must not suggest advancing when another selected cache is corrupt.
    ok(&["registers", "advance", "--period", "FY2026-P01", "--json"]);

    let second = write(
        &dir,
        "second.json",
        r#"{"effective_date":"2026-03-16","idempotency_key":"second","legs":[{"side":"debit","account":"6000","amount":"20.00 USD"},{"side":"credit","account":"1000","amount":"20.00 USD"}]}"#,
    );
    let posted = doc(&ok(&[
        "post",
        "--intent",
        &second,
        "--evidence",
        &evidence,
        "--json",
    ]));
    let current = doc(&ok(&advance));
    assert_eq!(int(&current, "from"), Some(first_through));
    assert_eq!(int(&current, "through"), int(&posted, "recorded_at"));
    assert_eq!(int(&current, "entries_decoded"), Some(1));
    assert_eq!(int(&current, "entries"), Some(2));
    assert_eq!(current.get("wrote"), Some(&Json::Bool(true)));
    assert_eq!(current.get("rebuilt"), Some(&Json::Bool(false)));
    ok(&["verify", "registers", "--period", period, "--json"]);
    let balance_before = report(&book, &["tb", "--period", period, "--json"]);
    assert_cash_credits(&balance_before, "30.00 USD");
    let no_op = doc(&ok(&advance));
    assert_eq!(no_op.get("wrote"), Some(&Json::Bool(false)));
    assert_eq!(no_op.get("recorded_at"), Some(&Json::Null));
    assert_eq!(int(&no_op, "entries_decoded"), Some(0));
    assert_eq!(int(&no_op, "from"), int(&current, "through"));
    assert_eq!(int(&no_op, "through"), int(&current, "through"));
    assert_eq!(text(&no_op, "fold_digest"), text(&current, "fold_digest"));
    assert_eq!(
        report(&book, &["tb", "--period", period, "--json"]),
        balance_before
    );
    assert!(ok(&["registers", "advance", "--period", period]).contains("already current"));

    // Mutate only disposable maintenance metadata via the real substrate.
    // Advancing must preserve the evidence of damage instead of repairing it.
    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let mut db = runtime
        .block_on(Database::open(
            &ctx.commit(),
            &book.join("store"),
            DatabaseKeys::new([57; 32], DatabaseSecurityNamespaceId([58; 32]), [59; 32]),
        ))
        .unwrap();
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    batch.set_vertex_property(
        fa_registers::maintainer::state_vid(book_id, period),
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(vec![0xff]).unwrap()),
    );
    let damaged_at = runtime.block_on(db.write(&ctx.commit(), batch)).unwrap();
    drop(db);
    let damaged_balance = report(&book, &["tb", "--period", period, "--json"]);
    assert_cash_credits(&damaged_balance, "30.00 USD");
    let (code, verification, err) = fa(
        Some(&book),
        &["verify", "registers", "--period", period, "--json"],
    );
    assert_eq!(code, 8, "{verification}\n{err}");
    let error = doc(&verification);
    let [check] = error.get("detail").unwrap().as_arr().unwrap() else {
        panic!("one corrupt period expected: {verification}");
    };
    assert_eq!(text(check, "cache_status"), "corrupt");
    assert_eq!(check.get("verified_through"), Some(&Json::Null));
    assert!(arr(&robot_line(&verification), "next_actions").is_empty());
    let (code, mixed, err) = fa(
        Some(&book),
        &[
            "verify",
            "registers",
            "--period",
            "FY2026-P01",
            "--period",
            period,
            "--json",
        ],
    );
    assert_eq!(code, 8, "{mixed}\n{err}");
    let error = doc(&mixed);
    let checks = arr(&error, "detail");
    assert_eq!(checks.len(), 2);
    assert_eq!(text(&checks[0], "period"), "FY2026-P01");
    assert_eq!(text(&checks[0], "cache_status"), "verified");
    assert_eq!(checks[0].get("stale"), Some(&Json::Bool(true)));
    assert_eq!(int(&checks[0], "lag_entries"), Some(1));
    assert_eq!(text(&checks[1], "cache_status"), "corrupt");
    assert!(arr(&robot_line(&mixed), "next_actions").is_empty());
    assert!(text(&error, "fix").contains("--period FY2026-P03 --yes --json"));
    assert!(!text(&error, "fix").contains("FY2026-P01"));
    let (code, out, err) = fa(Some(&book), &advance);
    assert_eq!(code, 8, "{out}\n{err}");
    let refusal = doc(&out);
    assert_eq!(text(&refusal, "class"), "verification");
    assert!(text(&refusal, "message").contains("register cache drift"));
    assert!(text(&refusal, "fix").contains("fa verify registers --period FY2026-P03 --json"));
    assert!(text(&refusal, "fix").contains("--yes"));
    assert_eq!(
        report(&book, &["tb", "--period", period, "--json"]),
        damaged_balance
    );
    let reopened = Book::open_dir(&book, keys.clone(), Entropy::deterministic(57)).unwrap();
    assert_eq!(
        reopened.head().unwrap(),
        damaged_at,
        "refusal published nothing"
    );
    assert!(!reopened.verify_registers(period).unwrap().is_green());
    drop(reopened);

    // A fiscal-year selector includes the three special periods as well as
    // the twelve normal periods, in canonical code order. The command
    // publishes each preceding period before the damaged March refusal.
    // Those successes remain durable; retrying must not duplicate writes.
    let year_periods = [
        "FY2026-A1",
        "FY2026-CLOSE",
        "FY2026-OPEN",
        "FY2026-P01",
        "FY2026-P02",
        "FY2026-P03",
        "FY2026-P04",
        "FY2026-P05",
        "FY2026-P06",
        "FY2026-P07",
        "FY2026-P08",
        "FY2026-P09",
        "FY2026-P10",
        "FY2026-P11",
        "FY2026-P12",
    ];
    let preceding = &year_periods[..5];
    assert_eq!(year_periods[preceding.len()], period);
    let yearly = ["registers", "advance", "--fiscal-year", "2026", "--json"];
    let (code, partial, err) = fa(Some(&book), &yearly);
    assert_eq!(code, 8, "{partial}\n{err}");
    let lines: Vec<_> = partial.lines().collect();
    assert_eq!(
        lines.len(),
        preceding.len() + 1,
        "special periods, January, February, then March refusal: {partial}"
    );
    let mut last_published = None;
    for (line, &earlier) in lines[..preceding.len()].iter().zip(preceding) {
        assert_eq!(field(line, "event"), Some("registers_advanced"));
        let data = doc(line);
        assert_eq!(text(&data, "period"), earlier);
        assert_eq!(data.get("wrote"), Some(&Json::Bool(true)));
        last_published = int(&data, "recorded_at");
        ok(&["verify", "registers", "--period", earlier, "--json"]);
    }
    let refusal_line = lines[preceding.len()];
    let failed = json::parse(refusal_line).unwrap();
    assert_eq!(field(refusal_line, "event"), Some("error"));
    assert_eq!(
        failed.get("coordinate").unwrap().get("effective"),
        Some(&Json::Str(format!("period:{period}")))
    );
    assert_eq!(
        text(doc(refusal_line).get("detail").unwrap(), "period"),
        period
    );
    let reopened = Book::open_dir(&book, keys, Entropy::deterministic(57)).unwrap();
    assert_eq!(
        Some(i128::from(reopened.head().unwrap().0)),
        last_published,
        "the failing March period published nothing after February"
    );
    assert!(!reopened.verify_registers(period).unwrap().is_green());
    drop(reopened);
    assert_eq!(
        fa(
            Some(&book),
            &["registers", "materialize", "--period", period, "--json"]
        )
        .0,
        7
    );
    ok(&[
        "registers",
        "materialize",
        "--period",
        period,
        "--yes",
        "--json",
    ]);
    ok(&["verify", "registers", "--period", period, "--json"]);
    assert_eq!(doc(&ok(&advance)).get("wrote"), Some(&Json::Bool(false)));
    let resumed = ok(&yearly);
    assert_eq!(resumed.lines().count(), year_periods.len(), "{resumed}");
    for (index, (line, expected_period)) in resumed.lines().zip(year_periods).enumerate() {
        assert_eq!(field(line, "event"), Some("registers_advanced"));
        let data = doc(line);
        assert_eq!(text(&data, "period"), expected_period);
        let already_maintained = index <= preceding.len();
        assert_eq!(data.get("wrote"), Some(&Json::Bool(!already_maintained)));
        if already_maintained {
            assert_eq!(data.get("recorded_at"), Some(&Json::Null));
        }
    }
    ok(&["verify", "registers", "--fiscal-year", "2026", "--json"]);
    // Both a wrong value and a malformed column are verification findings;
    // they carry a repair command, never an automatic advance suggestion.
    for bad_amount in [
        CanonicalScalar::bytes(2_999i128.to_le_bytes().to_vec()).unwrap(),
        CanonicalScalar::Int(2_999),
    ] {
        let malformed = matches!(&bad_amount, CanonicalScalar::Int(_));
        let mut db = runtime
            .block_on(Database::open(
                &ctx.commit(),
                &book.join("store"),
                DatabaseKeys::new([57; 32], DatabaseSecurityNamespaceId([58; 32]), [59; 32]),
            ))
            .unwrap();
        let key = fa_registers::CellKey {
            account: fa_model::account_vid(book_id, "1000"),
            unit_id: fa_money::UnitRegistry::embedded()
                .unwrap()
                .lookup("USD")
                .unwrap()
                .0,
            period: period.into(),
        };
        let mut batch = WriteBatch::new(relation::DERIVED_FROM);
        batch.set_vertex_property(
            fa_registers::register_vid(book_id, &key),
            property::CREDITS_POSTED,
            Some(bad_amount),
        );
        runtime.block_on(db.write(&ctx.commit(), batch)).unwrap();
        drop(db);
        let (code, verification, err) = fa(
            Some(&book),
            &["verify", "registers", "--period", period, "--json"],
        );
        assert_eq!(code, 8, "{verification}\n{err}");
        let error = doc(&verification);
        if malformed {
            assert!(text(error.get("detail").unwrap(), "problem").contains("expected Bytes"));
        } else {
            let check = &error.get("detail").unwrap().as_arr().unwrap()[0];
            assert_eq!(text(check, "cache_status"), "corrupt");
            assert_eq!(check.get("verified_through"), Some(&Json::Null));
            assert!(!arr(check, "drift").is_empty());
        }
        assert!(text(&error, "cite").contains("FA-INV-04"));
        assert!(
            text(&error, "fix")
                .contains("fa registers materialize --period FY2026-P03 --yes --json")
        );
        assert!(arr(&robot_line(&verification), "next_actions").is_empty());
        assert_eq!(
            fa(
                Some(&book),
                &["registers", "materialize", "--period", period, "--json"]
            )
            .0,
            7
        );
        ok(&[
            "registers",
            "materialize",
            "--period",
            period,
            "--yes",
            "--json",
        ]);
        ok(&["verify", "registers", "--period", period, "--json"]);
    }

    // An undecodable journal payload is a foundation error, not a cache
    // mismatch. Use an uninitialized new period so the verifier reads HEAD.
    ok(&["period", "create", "--fiscal-year", "2027", "--json"]);
    let verify_new = ["verify", "registers", "--period", "FY2027-P03", "--json"];
    let empty = ok(&verify_new);
    assert_eq!(
        text(&arr(&doc(&empty), "periods")[0], "cache_status"),
        "uninitialized"
    );
    assert!(empty.contains("initialize it with fa registers advance --period FY2027-P03 --json"));
    let mut db = runtime
        .block_on(Database::open(
            &ctx.commit(),
            &book.join("store"),
            DatabaseKeys::new([57; 32], DatabaseSecurityNamespaceId([58; 32]), [59; 32]),
        ))
        .unwrap();
    let entry = db
        .vertices()
        .unwrap()
        .into_iter()
        .find(|row| row.labels.contains(&fa_model::symbols::label::ENTRY))
        .unwrap()
        .vid;
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    batch.set_vertex_property(
        entry,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(vec![0xff]).unwrap()),
    );
    runtime.block_on(db.write(&ctx.commit(), batch)).unwrap();
    drop(db);
    let (code, refusal, err) = fa(Some(&book), &verify_new);
    assert_eq!(
        code, 5,
        "model decode stays a foundation failure: {refusal}\n{err}"
    );
    assert_eq!(text(&doc(&refusal), "class"), "foundation");
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

    // An explanation is required before a correction can enter the journal.
    // Every refusal leaves both the balances and the recorded frontier alone.
    let before = report(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    for (reason, expected) in [
        (None, "registered reason"),
        (Some("WrongAcount"), "did you mean `WrongAccount`"),
        (Some("0"), "not registered"),
        (Some("65535"), "not registered"),
        (Some("Other"), "requires a description"),
    ] {
        let mut args = vec!["reverse", vid.as_str(), "--json"];
        if let Some(reason) = reason {
            args.extend(["--reason", reason]);
        }
        let (code, out, err) = fa(Some(&book), &args);
        assert_eq!(code, 3, "{args:?}\n{out}\n{err}");
        assert_eq!(field(&out, "refusal_id"), Some("FA-REF-054"), "{out}");
        assert!(out.contains(expected), "{expected}: {out}");
    }
    let missing_reason = write(
        &dir,
        "missing-reason.json",
        &format!(
            r#"{{"class":"Reversal","reverses":"{vid}","effective_date":"2026-03-16","idempotency_key":"missing-reason"}}"#
        ),
    );
    let (code, out, err) = fa(
        Some(&book),
        &["post", "--intent", &missing_reason, "--json"],
    );
    assert_eq!(code, 3, "{out}\n{err}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-054"), "{out}");
    assert!(
        out.contains("WrongAccount") && out.contains("Duplicate"),
        "{out}"
    );
    assert_eq!(
        report(&book, &["tb", "--period", "FY2026-P03", "--json"]),
        before,
        "refused reasons must not publish anything"
    );

    // Reverse by target: the CLI derives the side-swapped legs.
    let rev = write(
        &dir,
        "rev.json",
        &format!(
            r#"{{"class":"Reversal","reverses":"{vid}","reason":"DataEntryError","effective_date":"2026-03-16","description":"undo","idempotency_key":"rev-1"}}"#
        ),
    );
    let (code, out, err) = fa(Some(&book), &["post", "--intent", &rev, "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("\"event\":\"posted\""), "{out}");
    let reversal_vid = field(&out, "vid").unwrap().to_string();
    let (code, shown, err) = fa(Some(&book), &["entry", "show", &reversal_vid, "--json"]);
    assert_eq!(code, 0, "{shown}\n{err}");
    let shown = doc(&shown);
    let lineage = arr(&shown, "supersedes");
    assert_eq!(lineage.len(), 1);
    assert_eq!(text(&lineage[0], "entry"), vid);
    assert_eq!(int(&lineage[0], "reason_code"), Some(1));
    assert_eq!(text(&lineage[0], "reason"), "DataEntryError");
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &rev, "--json"]);
    assert_eq!(code, 0);
    assert!(out.contains("\"event\":\"recorded\""), "{out}");
    // A second, different reversal of the same target is a conflict (exit 6).
    let rev2 = write(
        &dir,
        "rev2.json",
        &format!(
            r#"{{"class":"Reversal","reverses":"{vid}","reason":"WrongAmount","effective_date":"2026-03-17","idempotency_key":"rev-2"}}"#
        ),
    );
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &rev2, "--json"]);
    assert_eq!(code, 6, "{out}");
    assert!(out.contains("\"refusal_id\":\"FA-REF-052\""), "{out}");
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
    assert!(out.contains("\"refusal_id\":\"FA-REF-032\""), "{out}");
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
        out.contains("\"refusal_id\":\"FA-REF-102\"") && out.contains("fa-omi"),
        "{out}"
    );
    // The pair nets to zero.
    let (code, out, _) = fa(Some(&book), &["tb", "--period", "FY2026-P03", "--json"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("\"balanced\":true") && out.contains("\"net\":\"0.00 USD\""),
        "{out}"
    );

    // The typed verb accepts the displayed E: handle, derives all legs,
    // preserves the target's date by default, and retains its reason across
    // a directory-book reopen and exact retry. Reversing a reversal is explicit.
    let target = format!("E:{reversal_vid}");
    let args = [
        "reverse",
        target.as_str(),
        "--reason",
        "WrongAccount",
        "--json",
    ];
    let (code, out, err) = fa(Some(&book), &args);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("reversed"));
    assert_eq!(field(&out, "target"), Some(reversal_vid.as_str()));
    assert_eq!(field(&out, "reason"), Some("WrongAccount"));
    assert_eq!(field(&out, "reason_code"), Some("2"));
    let typed_vid = field(&out, "vid").unwrap().to_string();
    let digest = field(&out, "entry_digest").unwrap().to_string();
    let (code, out, err) = fa(Some(&book), &args);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("recorded"));
    assert_eq!(field(&out, "entry_digest"), Some(digest.as_str()));
    let (code, shown, err) = fa(Some(&book), &["entry", "show", &typed_vid, "--json"]);
    assert_eq!(code, 0, "{shown}\n{err}");
    let shown = doc(&shown);
    assert_eq!(text(&shown, "effective_date"), "2026-03-16");
    let lineage = arr(&shown, "supersedes");
    assert_eq!(text(&lineage[0], "reason"), "WrongAccount");
    assert_eq!(int(&lineage[0], "reason_code"), Some(2));
    let (code, human, err) = fa(Some(&book), &["entry", "show", &typed_vid]);
    assert_eq!(code, 0, "{human}\n{err}");
    assert!(
        human.contains("WrongAccount") && human.contains(&reversal_vid),
        "{human}"
    );
    let (code, out, err) = fa(
        Some(&book),
        &["reverse", &reversal_vid, "--reason", "Duplicate", "--json"],
    );
    assert_eq!(
        code, 6,
        "a changed reason is not the same retry: {out}\n{err}"
    );
    let (code, out, err) = fa(
        Some(&book),
        &[
            "reverse",
            &typed_vid,
            "--reason",
            "Other",
            "--description",
            "Undo the correction after reviewing the source invoice",
            "--effective",
            "2026-03-20",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "reason"), Some("Other"));
    Ok(())
}

#[test]
fn raw_reversal_retries_preserve_legacy_zero_reasons_without_admitting_new_ones()
-> std::io::Result<()> {
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::types::Budget;
    use fa::{Book, BookKeys, Entropy};
    use fa_journal::BookSpec;
    use fa_journal::rows::{edge_id, leg_vid, mantissa_scalar, reversal_vid};
    use fa_model::symbols::{label, property, relation};
    use fa_model::{
        EntryClass, EntryOrigin, EntryPayload, Id128, Oid, Supersession, SupersessionKind,
    };
    use fa_money::Side;
    use fa_time::DateDay;
    use fgdb::{Database, DatabaseKeys, WriteBatch};
    use fgdb_types::context::PurposeContexts;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;
    use fgdb_types::{CanonicalScalar, VId};

    let dir = tmp("legacy-reversal")?;
    let book = dir.join("book");
    let keys = BookKeys::for_development(0x75);
    let handle = Book::create_dir(
        &book,
        keys.clone(),
        BookSpec {
            book_id: Id128([0x75; 16]),
            name: "Legacy reversal retries".into(),
            base_unit: fa_money::UnitRegistry::embedded()
                .unwrap()
                .lookup("USD")
                .unwrap(),
            calendar: fa_time::FiscalCalendar::monthly("fiscal", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(0x75),
    )
    .unwrap();
    keys.save(&book.join("book.keys")).unwrap();
    drop(handle);
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let evidence = source_doc(&dir, &book);
    let mut targets = Vec::new();
    for key in ["legacy-target", "fresh-target"] {
        let intent = write(
            &dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"2026-03-15","idempotency_key":"{key}","legs":[{{"side":"debit","account":"6000","amount":"10.00 USD"}},{{"side":"credit","account":"1000","amount":"10.00 USD"}}]}}"#
            ),
        );
        let posted = ok(&[
            "post",
            "--intent",
            &intent,
            "--evidence",
            &evidence,
            "--json",
        ]);
        targets.push(field(&posted, "vid").unwrap().to_string());
    }

    // Retain the canonical form emitted by the previous CLI: reason_code 0.
    // Append it once through the substrate, including its mirrors and edges;
    // no existing journal object is rewritten and the new law is not relaxed.
    let handle = Book::open_dir(&book, keys.clone(), Entropy::deterministic(0x76)).unwrap();
    let context = handle.context().clone();
    let target_vid = VId(u128::from_str_radix(&targets[0], 16).unwrap());
    let target = handle.read_entry(target_vid).unwrap().unwrap().0;
    let mut proposal = target.proposal.clone();
    proposal.class = EntryClass::REVERSAL;
    proposal.effective_date = DateDay::parse("2026-03-16").unwrap();
    proposal.description = handle.seal_text("undo legacy entry").unwrap();
    proposal.idempotency_key = b"legacy-rev".to_vec();
    proposal.origin = EntryOrigin::Intent {
        intent_oid: Oid(fa_model::domain_digest(
            b"fa:intent:v1",
            &[
                &context.book_id.0,
                &proposal.principal_ref.0.to_le_bytes(),
                b"legacy-rev",
            ],
        )),
        intent_kind: 1,
    };
    proposal.evidence.clear();
    proposal.supersession = vec![Supersession {
        target: target.entry_ref(target_vid),
        kind: SupersessionKind::Reverses,
        reason_code: 0,
    }];
    for leg in &mut proposal.legs {
        leg.side = if leg.side == Side::Debit {
            Side::Credit
        } else {
            Side::Debit
        };
        leg.settles.clear();
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    let legacy = proposal.seal(Vec::new(), None).unwrap();
    drop(handle);
    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let purposes = PurposeContexts::narrow_runtime_root(&root);
    let mut db = runtime
        .block_on(Database::open(
            &purposes.commit(),
            &book.join("store"),
            DatabaseKeys::new(
                [0x75; 32],
                DatabaseSecurityNamespaceId([0x76; 32]),
                [0x77; 32],
            ),
        ))
        .unwrap();
    let vid = reversal_vid(target_vid);
    let mut has_leg = WriteBatch::new(relation::HAS_LEG);
    let mut posts_to = WriteBatch::new(relation::POSTS_TO);
    has_leg.create_vertex(
        vid,
        vec![label::ENTRY],
        fa_model::entry_mirrors(&legacy).unwrap(),
    );
    for (i, leg) in legacy.proposal.legs.iter().enumerate() {
        let ordinal = u16::try_from(i).unwrap();
        let lvid = leg_vid(vid, ordinal);
        let mut mirrors =
            fa_model::leg_mirrors(leg, ordinal, legacy.proposal.effective_date, &context.units)
                .unwrap();
        mirrors.push((property::APPLIED, mantissa_scalar("applied", 0).unwrap()));
        has_leg.create_vertex(lvid, vec![label::LEG], mirrors);
        has_leg.add_edge(
            edge_id(relation::HAS_LEG, vid, lvid),
            vid,
            lvid,
            vec![(property::ORDINAL, CanonicalScalar::Int(i64::from(ordinal)))],
        );
        posts_to.add_edge(
            edge_id(relation::POSTS_TO, lvid, leg.account_ref),
            lvid,
            leg.account_ref,
            vec![],
        );
    }
    let mut in_period = WriteBatch::new(relation::IN_PERIOD);
    let period = fa_model::period_vid(&context.calendar.id, "FY2026-P03");
    in_period.add_edge(
        edge_id(relation::IN_PERIOD, vid, period),
        vid,
        period,
        vec![],
    );
    let mut supersedes = WriteBatch::new(relation::SUPERSEDES);
    supersedes.add_edge(
        edge_id(relation::SUPERSEDES, vid, target_vid),
        vid,
        target_vid,
        vec![],
    );
    let txn_cx = purposes.txn();
    let mut transaction = db.begin(&txn_cx).unwrap();
    transaction
        .write_ordered(&mut db, vec![has_leg, posts_to, in_period, supersedes])
        .unwrap();
    let recorded_at = runtime
        .block_on(transaction.commit(&mut db, &purposes.commit()))
        .unwrap();
    drop(db);

    let raw = |name: &str, target: &str, key: &str, description: &str, reason: Option<&str>| {
        let reason = reason
            .map(|r| format!(",\"reason\":{r}"))
            .unwrap_or_default();
        write(
            &dir,
            name,
            &format!(
                r#"{{"class":"Reversal","reverses":"{target}","effective_date":"2026-03-16","description":"{description}","idempotency_key":"{key}"{reason}}}"#
            ),
        )
    };
    let before = report(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    let expected_vid = format!("{:032x}", vid.0);
    let expected_digest: String = legacy
        .entry_digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    for (i, reason) in [None, Some("\"0\""), Some("0")].into_iter().enumerate() {
        let retry = raw(
            &format!("retry-{i}.json"),
            &targets[0],
            "legacy-rev",
            "undo legacy entry",
            reason,
        );
        let outcome = ok(&["post", "--intent", &retry, "--json"]);
        assert_eq!(field(&outcome, "event"), Some("recorded"));
        assert_eq!(field(&outcome, "vid"), Some(expected_vid.as_str()));
        assert_eq!(
            field(&outcome, "entry_digest"),
            Some(expected_digest.as_str())
        );
        assert_eq!(
            int(&doc(&outcome), "recorded_at"),
            Some(i128::from(recorded_at.0))
        );

        let fresh = raw(
            &format!("fresh-{i}.json"),
            &targets[1],
            "fresh-rev",
            "undo legacy entry",
            reason,
        );
        let (code, out, _) = fa(Some(&book), &["post", "--intent", &fresh, "--json"]);
        assert_eq!(code, 3, "{out}");
        assert_eq!(field(&out, "refusal_id"), Some("FA-REF-054"), "{out}");
    }
    for (i, reason) in ["null", "\"WrongAcount\"", "\"65535\""]
        .into_iter()
        .enumerate()
    {
        let invalid = raw(
            &format!("invalid-{i}.json"),
            &targets[0],
            "legacy-rev",
            "undo legacy entry",
            Some(reason),
        );
        let (code, out, _) = fa(Some(&book), &["post", "--intent", &invalid, "--json"]);
        assert_eq!(code, 3, "{out}");
        assert_eq!(field(&out, "refusal_id"), Some("FA-REF-054"), "{out}");
    }
    for (key, description) in [
        ("legacy-rev", "changed explanation"),
        ("changed-key", "undo legacy entry"),
    ] {
        let changed = raw(
            &format!("{key}-changed.json"),
            &targets[0],
            key,
            description,
            None,
        );
        let (code, out, _) = fa(Some(&book), &["post", "--intent", &changed, "--json"]);
        assert_eq!(code, 6, "{out}");
        assert_eq!(field(&out, "refusal_id"), Some("FA-REF-052"), "{out}");
    }
    let retry = raw(
        "other-principal.json",
        &targets[0],
        "legacy-rev",
        "undo legacy entry",
        None,
    );
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &retry, "--as", "other", "--json"],
    );
    assert_eq!(code, 6, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-052"), "{out}");
    for reason in [None, Some("0")] {
        let mut args = vec!["reverse", targets[0].as_str(), "--json"];
        if let Some(reason) = reason {
            args.extend(["--reason", reason]);
        }
        let (code, out, _) = fa(Some(&book), &args);
        assert_eq!(code, 3, "{out}");
        assert_eq!(field(&out, "refusal_id"), Some("FA-REF-054"), "{out}");
    }
    let shown = doc(&ok(&["entry", "show", &expected_vid, "--json"]));
    assert_eq!(int(&arr(&shown, "supersedes")[0], "reason_code"), Some(0));
    assert_eq!(
        arr(&shown, "supersedes")[0].get("reason"),
        Some(&Json::Null)
    );
    assert_eq!(
        report(&book, &["tb", "--period", "FY2026-P03", "--json"]),
        before
    );
    let reopened = Book::open_dir(&book, keys, Entropy::deterministic(0x77)).unwrap();
    assert_eq!(
        reopened.head().unwrap(),
        recorded_at,
        "every retry/refusal is read-only"
    );
    assert_eq!(reopened.read_entry(vid).unwrap().unwrap().0, legacy);
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
    let (code, out, _) = fa(
        Some(&book),
        &["resolve", "--intent", &void, "--yes", "--json"],
    );
    assert_eq!(code, 6, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-062"), "{out}");
    let not_a_hold = write(
        &dir,
        "res2.json",
        &format!(
            r#"{{"resolves":"{res_vid}","disposition":"voids","effective_date":"2026-03-21","idempotency_key":"void-78"}}"#
        ),
    );
    let (code, out, _) = fa(
        Some(&book),
        &["resolve", "--intent", &not_a_hold, "--yes", "--json"],
    );
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-060"), "{out}");

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
    let (code, out, err) = fa(
        Some(&book),
        &["resolve", "--intent", &void_2, "--yes", "--json"],
    );
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
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-072"), "{out}");
    assert!(out.contains("20000"), "{out}");
    let rev_inv = write(
        &dir,
        "rev-inv.json",
        &format!(
            r#"{{"class":"Reversal","reverses":"{inv_vid}","reason":"WrongAmount","effective_date":"2026-03-22","idempotency_key":"rev-inv"}}"#
        ),
    );
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &rev_inv, "--json"]);
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-073"), "{out}");

    // Reversing the receipt reopens the invoice; the mirrors verify.
    let rev_rcpt = write(
        &dir,
        "rev-rcpt.json",
        &format!(
            r#"{{"class":"Reversal","reverses":"{rcpt_vid}","reason":"WrongAmount","effective_date":"2026-03-22","idempotency_key":"rev-rcpt"}}"#
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

/// The last stdout line's event fields (its `data`; robot mode prints one
/// result line here).
fn doc(out: &str) -> Json {
    let parsed = json::parse(out.lines().last().unwrap_or_default());
    assert!(parsed.is_ok(), "not JSON: {out}");
    let line = parsed.unwrap_or(Json::Null);
    let data = line.get("data").cloned();
    assert!(data.is_some(), "no data: {out}");
    data.unwrap_or(Json::Null)
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
            // Checkpoint publication admits its witness before opening a
            // book. Give this dispatch probe that authority so the absent
            // book remains its next required input. Missing-grant refusal
            // is independently covered by the checkpoint command tests.
            if verb.name == "checkpoint" {
                call.extend(["--grant", "witness"]);
            }
            // A dangerous operation's gate answers before its handler (exit
            // 7; the dangerous-operation tests cover it): confirm it so the
            // probe reaches the handler.
            if reg
                .dangerous_for(&verb.name, call.get(1).copied())
                .next()
                .is_some()
            {
                call.push("--yes");
            }
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
    // The envelope (Appendix D): its version, the fields every line carries
    // beside `event` and `data`, and the wire frames that carry none.
    assert_eq!(int(&envelope, "version"), Some(reg.envelope.version));
    assert_eq!(
        arr(&envelope, "fields")
            .iter()
            .map(|f| (text(f, "name"), text(f, "type")))
            .collect::<Vec<_>>(),
        reg.envelope
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.type_text.as_str()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        arr(&envelope, "frames")
            .iter()
            .filter_map(Json::as_str)
            .collect::<Vec<_>>(),
        vec!["fad_request", "fad_response"]
    );
    for e in arr(&schema, "events") {
        let declared = reg.event(text(e, "name")).map(|d| d.book);
        assert_eq!(
            e.get("book"),
            declared.map(Json::Bool).as_ref(),
            "{}",
            text(e, "name")
        );
    }
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
            r#"{{"class":"Reversal","reverses":"{extra}","reason":"Duplicate","effective_date":"2026-03-11","idempotency_key":"rev"}}"#
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
                "2026-03-15T00:00:00",
            ],
            "invalid --as-known-at selector",
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
    assert_eq!(
        run(true, &["checkpoint", "create", "--grant", "witness"]).0,
        0
    );
    assert_eq!(run(true, &["verify", "accumulator"]).0, 0);
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
    assert_eq!(run(true, &["verify", "projections"]).0, 0);
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
    let (code, stale) = run(true, &["verify", "registers", "--period", "FY2026-P03"]);
    assert_eq!(code, 0, "ordinary lag is not corruption: {stale}");
    let stale_data = doc(&stale);
    let checks = arr(&stale_data, "periods");
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].get("stale"), Some(&Json::Bool(true)));
    assert_eq!(int(&checks[0], "lag_entries"), Some(1));
    assert!(int(&checks[0], "verified_through").is_some());
    assert_eq!(text(&checks[0], "cache_status"), "verified");
    let envelope = json::parse(&stale).unwrap();
    let actions = arr(&envelope, "next_actions");
    assert_eq!(actions.len(), 1);
    assert_eq!(
        text(&actions[0], "command"),
        "fa registers advance --period FY2026-P03 --json"
    );
    let (code, out) = run(true, &["registers", "advance", "--period", "FY2026-P03"]);
    assert_eq!(code, 0, "{out}");
    let (code, current) = run(true, &["verify", "registers", "--period", "FY2026-P03"]);
    assert_eq!(code, 0, "{current}");
    let current_data = doc(&current);
    let checks = arr(&current_data, "periods");
    assert_eq!(checks[0].get("stale"), Some(&Json::Bool(false)));
    assert_eq!(int(&checks[0], "lag_entries"), Some(0));
    let envelope = json::parse(&current).unwrap();
    assert!(arr(&envelope, "next_actions").is_empty());
    assert_eq!(
        run(true, &["reverse", &vid, "--reason", "WrongAccount"]).0,
        0
    );
    let certificate = dir.join("events.cert").display().to_string();
    assert_eq!(
        run(
            true,
            &[
                "tb",
                "--period",
                "FY2026-P03",
                "--certificate-out",
                &certificate
            ]
        )
        .0,
        0
    );
    assert_eq!(run(true, &["replay", &certificate]).0, 0);
    assert_eq!(run(true, &["certificate", "status", &certificate]).0, 0);
    // A planned, approved lock (R4): `period_planned`, then `approved`.
    assert_eq!(run(true, &["period", "open", "FY2026-P04"]).0, 0);
    assert_eq!(run(true, &["period", "close", "FY2026-P04", "--yes"]).0, 0);
    let plan = dir.join("lock.plan").display().to_string();
    let (code, out) = run(true, &["period", "lock", "FY2026-P04", "--plan-out", &plan]);
    assert_eq!(code, 0, "{out}");
    let digest = field(&out, "proposal_digest")
        .unwrap_or_default()
        .to_string();
    let (code, out) = run(
        true,
        &["approve", "--proposal", &digest, "--as", "controller"],
    );
    assert_eq!(code, 0, "{out}");
    let approval = field(&out, "approval_vid").unwrap_or_default().to_string();
    assert_eq!(
        run(
            true,
            &[
                "period",
                "lock",
                "FY2026-P04",
                "--plan",
                &plan,
                "--approval",
                &approval
            ]
        )
        .0,
        0
    );
    // The daemon's frames and its own output are fad's to emit (crates/fad tests).
    let declared: BTreeSet<String> = reg
        .events
        .iter()
        .map(|e| e.name.clone())
        .filter(|name| !reg.daemon.events.contains(name))
        .collect();
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
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-090"), "{out}");
    let rent = intent("rent.json", "rent", "6000", "1000", "60.00");
    ok(&["post", "--intent", &rent, "--evidence", &ev, "--json"]);
    // A reservation is an outflow too: 40 available, 50 is refused, 30 holds.
    let hold = intent("hold.json", "hold", "6000", "1000", "50.00");
    let (code, out, _) = fa(
        Some(&book),
        &["reserve", "--intent", &hold, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-090"), "{out}");
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
    assert_eq!(text(&refused, "class"), "usage", "{out}");
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
    let voided = doc(&ok(&["resolve", "--intent", &void, "--yes", "--json"]));
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

/// Every policy refusal's fix names only verbs and flags this build
/// registers (fa-llx, review D-L1): a fix an agent copies must run. One
/// instance of every `fa_policy::Denial` variant; each `fa <verb>` must be a
/// registered verb, and each `--flag` a global flag or switch or one some verb
/// accepts. The match below is exhaustive, so a new variant fails to compile
/// until it is listed here.
#[test]
fn policy_refusal_fixes_name_only_registered_verbs_and_flags() {
    use fa_policy::{Denial, Op, Profile};
    use fgdb_types::{CommitSeq, VId};
    let reg = registry().expect("verbs.toml");
    let rule = || "adjusting-closed".to_string();
    let all = vec![
        Denial::NotHolder {
            holder: VId(1),
            principal: VId(2),
        },
        Denial::MissingOp {
            op: Op::PostClosed,
            what: "posting".into(),
        },
        Denial::AgentOnTrunk,
        Denial::Expired {
            expires_at: CommitSeq(3),
            at: CommitSeq(4),
        },
        Denial::CeilingExceeded {
            leg: 0,
            unit: fa_money::UnitId(0),
            mantissa: 2,
            ceiling: 1,
        },
        Denial::UnboundedUnit {
            leg: 0,
            unit: fa_money::UnitId(1),
        },
        Denial::SelfApproval {
            rule: rule(),
            approver: VId(1),
        },
        Denial::DuplicateApprover {
            rule: rule(),
            approver: VId(1),
        },
        Denial::ApproverProfile {
            rule: rule(),
            approver: VId(1),
            profile: Profile::Agent,
            allowed: vec!["Human".into()],
        },
        Denial::ApproverOp {
            rule: rule(),
            approver: VId(1),
            recorded: Op::Verify,
            required: "approve".into(),
        },
        Denial::HumanApproversRequired {
            rule: rule(),
            required: 1,
            supplied: 0,
        },
        Denial::UnsupportedExclusion {
            rule: rule(),
            exclusion: "case_preparer".into(),
        },
        Denial::TooFewApprovals {
            rule: rule(),
            required: 1,
            supplied: 0,
        },
        Denial::ApprovalBinding { index: 0 },
        Denial::UnknownApproval {
            index: 0,
            approval: VId(9),
        },
        Denial::StaleApproval {
            index: 0,
            recorded_epoch: 0,
            current_epoch: 1,
        },
        Denial::UnsupportedPolicy {
            cited: [0xab; 32],
            enforced: [0xcd; 32],
        },
        Denial::OutOfScope {
            caveat: "books",
            value: "0101".into(),
        },
        Denial::Revoked {
            revoked_at: CommitSeq(5),
        },
    ];
    // Exhaustiveness: listing a variant above is enforced by this match.
    for d in &all {
        match d {
            Denial::NotHolder { .. }
            | Denial::MissingOp { .. }
            | Denial::AgentOnTrunk
            | Denial::Expired { .. }
            | Denial::CeilingExceeded { .. }
            | Denial::UnboundedUnit { .. }
            | Denial::SelfApproval { .. }
            | Denial::DuplicateApprover { .. }
            | Denial::ApproverProfile { .. }
            | Denial::ApproverOp { .. }
            | Denial::HumanApproversRequired { .. }
            | Denial::UnsupportedExclusion { .. }
            | Denial::TooFewApprovals { .. }
            | Denial::ApprovalBinding { .. }
            | Denial::UnknownApproval { .. }
            | Denial::StaleApproval { .. }
            | Denial::UnsupportedPolicy { .. }
            | Denial::OutOfScope { .. }
            | Denial::Revoked { .. } => {}
        }
    }
    let verb_names: BTreeSet<&str> = reg.verbs.iter().map(|v| v.name.as_str()).collect();
    let flag_known = |flag: &str| {
        reg.global.flags.iter().any(|f| f == flag)
            || reg.global.switches.iter().any(|f| f == flag)
            || reg.verbs.iter().any(|v| v.accepts(flag))
    };
    let trim = |t: &str| {
        t.trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .to_string()
    };
    let mut verbs_named = 0;
    let mut flags_named = 0;
    for d in &all {
        let fix = d.fix();
        let tokens: Vec<String> = fix.split_whitespace().map(trim).collect();
        for (i, t) in tokens.iter().enumerate() {
            if t == "fa" {
                let verb = tokens.get(i + 1).map(String::as_str).unwrap_or("");
                assert!(
                    verb_names.contains(verb),
                    "{} fix names `fa {verb}`, which verbs.toml does not register: {fix}",
                    d.code()
                );
                verbs_named += 1;
            }
            if t.starts_with("--") {
                assert!(
                    flag_known(t),
                    "{} fix names `{t}`, which verbs.toml does not register: {fix}",
                    d.code()
                );
                flags_named += 1;
            }
        }
    }
    // The scan is not vacuous: today's fixes name `fa capabilities --json`,
    // `--as` and `--grant`.
    assert!(
        verbs_named >= 1 && flags_named >= 3,
        "{verbs_named} {flags_named}"
    );
    let agent = Denial::AgentOnTrunk;
    assert!(agent.cite().contains("fa-s7x"), "{}", agent.cite());
}

#[test]
fn budget_caps_bound_each_period_and_balancing_moves_what_the_limit_admits() -> std::io::Result<()>
{
    let dir = tmp("budget")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    ok(&["book", "create", "--name", "Budget Co", "--json"]);
    // A scope must be a known one, and must scope a bound.
    for (name, chart, needle) in [
        (
            "weekly.json",
            r#"{"accounts":[{"code":"6000","name":"Rent","type":"Expense","unit":"USD","upper_bound":"100.00","limit_scope":"weekly"}]}"#,
            "is not a scope",
        ),
        (
            "unbound.json",
            r#"{"accounts":[{"code":"6000","name":"Rent","type":"Expense","unit":"USD","limit_scope":"period"}]}"#,
            "names no bound",
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
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD","lower_bound":"0.00"},{"code":"4000","name":"Sales","type":"Revenue","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD","upper_bound":"100.00","limit_scope":"period"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    let listed = ok(&["chart", "list", "--json"]);
    for (code, scope) in [("1000", "lifetime"), ("6000", "period"), ("4000", "null")] {
        let row = listed
            .split('{')
            .find(|r| field(r, "code") == Some(code))
            .unwrap_or_default();
        assert_eq!(field(row, "limit_scope"), Some(scope), "{code}: {listed}");
    }
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    ok(&["period", "open", "FY2026-P04", "--json"]);
    let ev = source_doc(&dir, &book);
    let intent = |name: &str, key: &str, date: &str, debit: &str, credit: &str, amount: &str| {
        write(
            &dir,
            name,
            &format!(
                r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount} USD"}},{{"side":"credit","account":"{credit}","amount":"{amount} USD"}}]}}"#
            ),
        )
    };
    let sale = intent("sale.json", "sale", "2026-03-01", "1000", "4000", "1000.00");
    ok(&["post", "--intent", &sale, "--evidence", &ev, "--json"]);
    // The budget is per period: 80 of 100 in March, 30 more is refused there,
    // and April has its own 100.
    let march = intent("m80.json", "m80", "2026-03-05", "6000", "1000", "80.00");
    let posted = ok(&["post", "--intent", &march, "--evidence", &ev, "--json"]);
    assert!(posted.contains("\"requested\":null"), "{posted}");
    let over = intent("m30.json", "m30", "2026-03-06", "6000", "1000", "30.00");
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &over, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-091"), "{out}");
    let april = intent("a30.json", "a30", "2026-04-06", "6000", "1000", "30.00");
    ok(&["post", "--intent", &april, "--evidence", &ev, "--json"]);

    // Balancing on the Rent leg (leg 0): 50 asked, the March cap admits 20.
    let ask = intent("b50.json", "b50", "2026-03-07", "6000", "1000", "50.00");
    let balanced = ok(&[
        "post",
        "--intent",
        &ask,
        "--evidence",
        &ev,
        "--balancing",
        "0",
        "--json",
    ]);
    assert_eq!(field(&balanced, "event"), Some("posted"), "{balanced}");
    assert_eq!(
        field(&balanced, "requested"),
        Some("50.00 USD"),
        "{balanced}"
    );
    assert_eq!(field(&balanced, "moved"), Some("20.00 USD"), "{balanced}");
    // The request is the identity: the same request replays the recorded
    // outcome; another amount under the same key is a conflict.
    let again = ok(&[
        "post",
        "--intent",
        &ask,
        "--evidence",
        &ev,
        "--balancing",
        "0",
        "--json",
    ]);
    assert_eq!(field(&again, "event"), Some("recorded"), "{again}");
    assert_eq!(
        (field(&again, "requested"), field(&again, "moved")),
        (Some("50.00 USD"), Some("20.00 USD")),
        "{again}"
    );
    let other = intent("b60.json", "b50", "2026-03-07", "6000", "1000", "60.00");
    let (code, out, _) = fa(
        Some(&book),
        &[
            "post",
            "--intent",
            &other,
            "--evidence",
            &ev,
            "--balancing",
            "0",
            "--json",
        ],
    );
    assert_eq!(code, 6, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-032"), "{out}");
    let tb = ok(&["tb", "--period", "FY2026-P03", "--activity", "--json"]);
    let rent = tb
        .split('{')
        .find(|r| field(r, "code") == Some("6000"))
        .unwrap_or_default();
    assert_eq!(field(rent, "debits"), Some("100.00 USD"), "{tb}");

    // Shape and spelling refusals.
    let (code, out, _) = fa(
        Some(&book),
        &[
            "post",
            "--intent",
            &ask,
            "--evidence",
            &ev,
            "--balancing",
            "2",
            "--json",
        ],
    );
    assert_eq!(code, 2, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-093"), "{out}");
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &ask, "--balancing", "debit", "--json"],
    );
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("is not a leg ordinal"), "{out}");
    let (code, out, _) = fa(
        Some(&book),
        &["resolve", "--intent", &ask, "--balancing", "0", "--json"],
    );
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains("--balancing is not a flag of `fa resolve`"),
        "{out}"
    );

    // Verify reports each budget cell with its period.
    let verified = ok(&["verify", "availability", "--json"]);
    let cells: u64 = field(&verified, "cells_checked")
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    assert!(
        cells >= 2,
        "a lifetime cell plus the budget's period cells: {verified}"
    );
    let march_row = verified
        .split('{')
        .find(|r| field(r, "account") == Some("6000") && field(r, "period") == Some("FY2026-P03"))
        .unwrap_or_default();
    assert_eq!(field(march_row, "net"), Some("100.00 USD"), "{verified}");
    let april_row = verified
        .split('{')
        .find(|r| field(r, "account") == Some("6000") && field(r, "period") == Some("FY2026-P04"))
        .unwrap_or_default();
    assert_eq!(field(april_row, "net"), Some("30.00 USD"), "{verified}");
    let cash_row = verified
        .split('{')
        .find(|r| field(r, "account") == Some("1000"))
        .unwrap_or_default();
    assert_eq!(field(cash_row, "period"), Some("null"), "{verified}");
    Ok(())
}

// ---------------------------------------------------------------------------
// fa-12x slice 1: the plan Appendix D envelope, dangerous-operation gating,
// styling and determinism, correction distance.
// ---------------------------------------------------------------------------

/// The whole last stdout line, parsed (envelope and data).
fn robot_line(out: &str) -> Json {
    let parsed = json::parse(out.lines().last().unwrap_or_default());
    assert!(parsed.is_ok(), "not JSON: {out}");
    parsed.unwrap_or(Json::Null)
}

/// Run the first `next_actions` command of the robot line in `out` against
/// `book`, with its `<code>` placeholder bound to `period`: a suggested next
/// step must run as written once its placeholders are filled (the Polish
/// Bar's first-try rule; CobaltGull 3990).
fn follow_next_action(book: &Path, out: &str, period: &str) -> (i32, String, String) {
    let line = robot_line(out);
    let first = arr(&line, "next_actions").first().cloned();
    assert!(first.is_some(), "no next action: {out}");
    let command = text(&first.unwrap_or(Json::Null), "command").replace("<code>", period);
    assert!(!command.contains('<'), "an unfilled placeholder: {command}");
    let args: Vec<&str> = command.split_whitespace().collect();
    assert_eq!(args.first(), Some(&"fa"), "{command}");
    fa(Some(book), &args[1..])
}

/// `fa` with extra environment variables (robot output checked as `fa`).
fn fa_env(dir: Option<&Path>, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fa"));
    if let Some(d) = dir {
        cmd.arg("--book").arg(d);
    }
    cmd.args(args);
    cmd.env_remove("FA_BOOK");
    for (k, v) in env {
        cmd.env(k, v);
    }
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

/// A book with a chart (Cash, Rent), FY2026 created and March open, plus one
/// source document; returns the book, the document's oid, and the fixture
/// directory.
fn envelope_book(name: &str) -> std::io::Result<(PathBuf, String, PathBuf)> {
    let dir = tmp(name)?;
    let book = dir.join("book");
    let ok = |args: &[&str]| {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
    };
    ok(&["book", "create", "--name", "Envelope Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let ev = source_doc(&dir, &book);
    Ok((book, ev, dir))
}

/// Every robot line carries the plan Appendix D envelope: `v`; `book` and
/// `coordinate` (branch, the recorded sequence the line describes, its
/// effective selector) on a line about a book, null on a bookless one; the
/// certificate (null for ordinary, uncertified output); warnings; and the registry's next
/// actions. A write's coordinate is the head that write produced; a read's
/// is the coordinate it selected.
#[test]
fn every_robot_line_carries_the_appendix_d_envelope() -> std::io::Result<()> {
    // Bookless lines say null.
    let (code, out, _) = fa(None, &["--version", "--json"]);
    assert_eq!(code, 0, "{out}");
    let version = robot_line(&out);
    assert_eq!(version.get("v"), Some(&Json::Int(1)), "{out}");
    for key in ["book", "coordinate", "certificate"] {
        assert_eq!(version.get(key), Some(&Json::Null), "{key}: {out}");
    }
    assert_eq!(arr(&version, "warnings").len(), 0, "{out}");

    let dir = tmp("envelope")?;
    let book = dir.join("book");
    let (code, out, _) = fa(
        Some(&book),
        &["book", "create", "--name", "Envelope Co", "--json"],
    );
    assert_eq!(code, 0, "{out}");
    let created = robot_line(&out);
    let book_id = text(&doc(&out), "book_id").to_string();
    assert_eq!(text(&created, "book"), book_id, "{out}");
    let at_create = created.get("coordinate").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&at_create, "branch"), "trunk", "{out}");
    assert_eq!(text(&at_create, "effective"), "all", "{out}");
    let created_at = int(&at_create, "known_at").unwrap_or(-1);
    assert!(created_at > 0, "the head the create produced: {out}");
    // next_actions come from verbs.toml, command and why, without --book.
    let next = arr(&created, "next_actions");
    assert_eq!(
        next.first()
            .map(|n| (text(n, "command"), !text(n, "why").is_empty())),
        Some(("fa chart import <chart.json> --json", true)),
        "{out}"
    );

    // A write's coordinate moves to the head it produced.
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    let (code, out, _) = fa(Some(&book), &["chart", "import", &chart, "--json"]);
    assert_eq!(code, 0, "{out}");
    let installed = robot_line(&out);
    let installed_at = int(
        &installed.get("coordinate").cloned().unwrap_or(Json::Null),
        "known_at",
    )
    .unwrap_or(-1);
    assert!(installed_at > created_at, "{out}");
    assert_eq!(text(&installed, "book"), book_id);
    let (code, _, _) = fa(
        Some(&book),
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    assert_eq!(code, 0);
    let (code, out, _) = fa(Some(&book), &["period", "open", "FY2026-P03", "--json"]);
    assert_eq!(code, 0, "{out}");
    let opened = robot_line(&out);
    assert_eq!(
        text(
            &opened.get("coordinate").cloned().unwrap_or(Json::Null),
            "effective"
        ),
        "period:FY2026-P03",
        "{out}"
    );

    // A read names what it selected: the period and the recorded sequence.
    // Select the head the March open produced, then move the head on (open
    // April), so the selected sequence is strictly earlier than the head.
    let opened_at = int(
        &opened.get("coordinate").cloned().unwrap_or(Json::Null),
        "known_at",
    )
    .unwrap_or(-1);
    assert!(opened_at > installed_at, "{out}");
    let (code, out, _) = fa(Some(&book), &["period", "open", "FY2026-P04", "--json"]);
    assert_eq!(code, 0, "{out}");
    let head = int(
        &robot_line(&out)
            .get("coordinate")
            .cloned()
            .unwrap_or(Json::Null),
        "known_at",
    )
    .unwrap_or(-1);
    assert!(head > opened_at, "{out}");
    let at = opened_at.to_string();
    let (code, out, _) = fa(
        Some(&book),
        &[
            "tb",
            "--period",
            "FY2026-P03",
            "--as-known-at",
            &at,
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let read = robot_line(&out);
    let coordinate = read.get("coordinate").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&coordinate, "effective"), "period:FY2026-P03", "{out}");
    assert_eq!(int(&coordinate, "known_at"), Some(opened_at), "{out}");
    assert_eq!(int(&doc(&out), "known_at"), Some(opened_at), "{out}");

    // An error about this book carries the book; one before any book is
    // opened does not.
    let (code, out, _) = fa(Some(&book), &["tb", "--period", "FY2099-P01", "--json"]);
    assert_ne!(code, 0, "{out}");
    let refused = robot_line(&out);
    assert_eq!(text(&refused, "event"), "error", "{out}");
    assert_eq!(text(&refused, "book"), book_id, "{out}");
    let (code, out, _) = fa(None, &["nosuchverb", "--json"]);
    assert_eq!(code, 2, "{out}");
    assert_eq!(robot_line(&out).get("book"), Some(&Json::Null), "{out}");
    Ok(())
}

/// The plan's dangerous operations, each with the command line that does it
/// (verb, subcommand, condition as verbs.toml spells them).
const DANGEROUS: &[(&str, Option<&str>, &str)] = &[
    ("period", Some("close"), "always"),
    ("period", Some("lock"), "always"),
    ("period", Some("reopen"), "always"),
    ("post", None, "grant:post_closed"),
    ("resolve", None, "disposition:voids"),
    ("registers", Some("materialize"), "existing-cells"),
];

/// Every operation the plan calls dangerous has a `[[dangerous]]` row
/// (verbs.toml); the planted negative removes the lock row and the table
/// test names exactly that operation as ungated.
#[test]
fn the_dangerous_operation_table_names_every_dangerous_operation() {
    let reg = registry().expect("verbs.toml");
    assert_eq!(reg.ungated(DANGEROUS), Vec::new());
    assert_eq!(reg.dangerous.len(), DANGEROUS.len(), "no stray rows");
    let lock = "[[dangerous]]\nverb = \"period\"\nsubcommand = \"lock\"\n";
    let start = fa_cli::verbs::SOURCE.find(lock);
    assert!(start.is_some(), "the lock row is in verbs.toml");
    let start = start.unwrap_or_default();
    let end = fa_cli::verbs::SOURCE[start..]
        .find("\n\n")
        .map_or(fa_cli::verbs::SOURCE.len(), |n| start + n + 2);
    let mut planted = fa_cli::verbs::SOURCE.to_string();
    planted.replace_range(start..end, "");
    let without_lock = fa_cli::verbs::Registry::parse(&planted);
    assert!(without_lock.is_ok(), "{without_lock:?}");
    assert_eq!(
        without_lock
            .map(|r| r.ungated(DANGEROUS))
            .unwrap_or_default(),
        vec![("period", Some("lock"), "always")]
    );
}

/// A dangerous operation without --yes is refused with FA-REF-007 (exit 7,
/// class safety) naming its safe alternative, and nothing is written; with
/// --yes it proceeds to its own law (which may still refuse it, never with
/// 007). `fa capabilities --json` lists the operations; --yes on a command
/// that needs no confirmation is a warning, never a silent no-op.
#[test]
fn dangerous_operations_need_yes_and_name_the_safe_alternative() -> std::io::Result<()> {
    let (book, ev, dir) = envelope_book("dangerous")?;
    let fa_b = |args: &[&str]| fa(Some(&book), args);
    let unconfirmed = |args: &[&str], safe: &str| {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 7, "args={args:?}\n{out}\n{err}");
        let data = doc(&out);
        assert_eq!(text(&data, "class"), "safety", "{out}");
        assert_eq!(text(&data, "refusal_id"), "FA-REF-007", "{out}");
        assert!(text(&data, "fix").contains(safe), "{args:?}: {out}");
        assert!(
            text(&data, "message").contains("nothing was written"),
            "{out}"
        );
    };
    let confirmed = |args: &[&str]| {
        let (code, out, err) = fa(Some(&book), args);
        assert!(
            !out.contains("\"refusal_id\":\"FA-REF-007\""),
            "args={args:?}: --yes confirms\n{out}\n{err}"
        );
        (code, out)
    };
    let state = |period: &str| -> String {
        let (code, out, _) = fa(Some(&book), &["period", "list", "--json"]);
        assert_eq!(code, 0, "{out}");
        let row = out
            .split('{')
            .find(|r| field(r, "code") == Some(period))
            .unwrap_or_default()
            .to_string();
        field(&row, "state").unwrap_or_default().to_string()
    };

    // One posting, its registers materialized once (not dangerous).
    let entry = write(
        &dir,
        "rent.json",
        r#"{"effective_date":"2026-03-05","description":"March rent","idempotency_key":"rent-1","legs":[{"side":"debit","account":"6000","amount":"50.00 USD"},{"side":"credit","account":"1000","amount":"50.00 USD"}]}"#,
    );
    let (code, out, _) = fa_b(&["post", "--intent", &entry, "--evidence", &ev, "--json"]);
    assert_eq!(code, 0, "{out}");
    let (code, out, _) = fa_b(&[
        "registers",
        "materialize",
        "--period",
        "FY2026-P03",
        "--json",
    ]);
    assert_eq!(code, 0, "{out}");
    // Rematerializing over those cells is dangerous.
    unconfirmed(
        &[
            "registers",
            "materialize",
            "--period",
            "FY2026-P03",
            "--json",
        ],
        "fa verify registers",
    );
    let (code, out) = confirmed(&[
        "registers",
        "materialize",
        "--period",
        "FY2026-P03",
        "--yes",
        "--json",
    ]);
    assert_eq!(code, 0, "{out}");

    // Voiding a hold.
    let hold = write(
        &dir,
        "hold.json",
        r#"{"effective_date":"2026-03-10","description":"PO hold","idempotency_key":"hold-1","legs":[{"side":"debit","account":"6000","amount":"20.00 USD"},{"side":"credit","account":"1000","amount":"20.00 USD"}]}"#,
    );
    let (code, out, _) = fa_b(&["reserve", "--intent", &hold, "--evidence", &ev, "--json"]);
    assert_eq!(code, 0, "{out}");
    let hold_vid = field(&out, "vid").unwrap_or_default().to_string();
    let void = write(
        &dir,
        "void.json",
        &format!(
            r#"{{"resolves":"{hold_vid}","disposition":"voids","effective_date":"2026-03-11","idempotency_key":"void-1"}}"#
        ),
    );
    unconfirmed(
        &["resolve", "--intent", &void, "--json"],
        "disposition `posts`",
    );
    let tb = report(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    assert!(
        tb.contains("\"debits_pending\":\"20.00 USD\""),
        "still held: {tb}"
    );
    let (code, out) = confirmed(&["resolve", "--intent", &void, "--yes", "--json"]);
    assert_eq!(code, 0, "{out}");

    // Closing: refused, still SoftClosed; then closed with --yes.
    let (code, out, _) = fa_b(&["period", "soft-close", "FY2026-P03", "--json"]);
    assert_eq!(code, 0, "{out}");
    unconfirmed(
        &["period", "close", "FY2026-P03", "--json"],
        "fa period soft-close",
    );
    assert_eq!(state("FY2026-P03"), "SoftClosed");
    let (code, out) = confirmed(&["period", "close", "FY2026-P03", "--yes", "--json"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(state("FY2026-P03"), "Closed");

    // Posting into the closed period under post_closed.
    let late = write(
        &dir,
        "late.json",
        r#"{"effective_date":"2026-03-20","description":"late","idempotency_key":"late-1","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    unconfirmed(
        &[
            "post",
            "--intent",
            &late,
            "--evidence",
            &ev,
            "--grant",
            "post_closed",
            "--json",
        ],
        "keep its true effective date",
    );
    confirmed(&[
        "post",
        "--intent",
        &late,
        "--evidence",
        &ev,
        "--grant",
        "post_closed",
        "--yes",
        "--json",
    ]);

    // Locking and reopening: refused unconfirmed, the state unchanged; with
    // --yes each reaches its own law.
    unconfirmed(
        &["period", "lock", "FY2026-P03", "--json"],
        "leave the period Closed",
    );
    unconfirmed(
        &["period", "reopen", "FY2026-P03", "--to", "open", "--json"],
        "never re-date an entry",
    );
    // A safe alternative never suggests changing an entry's true effective
    // date to escape the period law (AGENTS.md; CobaltGull 3384).
    for d in &registry().expect("verbs.toml").dangerous {
        let safe = d.safe.to_lowercase();
        assert!(
            !safe.contains("date the entry in") && !safe.contains("dated in an open period"),
            "{} {:?}: {}",
            d.verb,
            d.subcommand,
            d.safe
        );
    }
    assert_eq!(state("FY2026-P03"), "Closed");
    confirmed(&[
        "period",
        "reopen",
        "FY2026-P03",
        "--to",
        "open",
        "--yes",
        "--json",
    ]);
    confirmed(&["period", "lock", "FY2026-P03", "--yes", "--json"]);

    // Human mode names the safe alternative on stderr.
    let (code, _, err) = fa_b(&["period", "close", "FY2026-P04"]);
    assert_eq!(code, 7, "{err}");
    assert!(
        err.contains("FA-REF-007") && err.contains("fa period soft-close"),
        "{err}"
    );

    // capabilities lists them; --yes on a command that needs none warns.
    let (code, out, _) = fa(None, &["capabilities", "--json"]);
    assert_eq!(code, 0, "{out}");
    let listed: Vec<(String, String)> = arr(&doc(&out), "dangerous")
        .iter()
        .map(|d| {
            (
                text(d, "verb").to_string(),
                text(d, "condition").to_string(),
            )
        })
        .collect();
    assert_eq!(listed.len(), DANGEROUS.len(), "{out}");
    for (verb, _, condition) in DANGEROUS {
        assert!(
            listed.iter().any(|(v, c)| v == verb && c == condition),
            "{verb} {condition}: {out}"
        );
    }
    let (code, out, _) = fa_b(&["tb", "--period", "FY2026-P03", "--yes", "--json"]);
    assert_eq!(code, 0, "{out}");
    let warnings = arr(&robot_line(&out), "warnings")
        .iter()
        .filter_map(Json::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("--yes confirms nothing") && w.contains("fa tb")),
        "{out}"
    );
    let (code, _, err) = fa_b(&["tb", "--period", "FY2026-P03", "--yes"]);
    assert_eq!(code, 0);
    assert!(err.contains("warning: --yes confirms nothing"), "{err}");
    Ok(())
}

/// Styling and determinism (plan Appendix D): with NO_COLOR, CI or TERM=dumb
/// (and always off a terminal) human output carries no escape bytes, and
/// SOURCE_DATE_EPOCH changes no byte of robot or human output (no data path
/// reads a clock).
#[test]
fn no_styling_off_a_terminal_and_no_clock_in_any_output() -> std::io::Result<()> {
    let (book, _, _) = envelope_book("style")?;
    for env in [
        vec![("NO_COLOR", "1")],
        vec![("CI", "true")],
        vec![("TERM", "dumb")],
        vec![],
    ] {
        let (code, out, err) = fa_env(Some(&book), &["tb", "--period", "FY2026-P03"], &env);
        assert_eq!(code, 0, "{env:?}: {err}");
        assert!(out.contains("posted debits"), "{out}");
        assert!(
            !out.contains('\u{1b}') && !err.contains('\u{1b}'),
            "{env:?}: {out}"
        );
    }
    let (code, styled_off, _) = fa_env(
        Some(&book),
        &["tb", "--period", "FY2026-P03", "--no-color"],
        &[],
    );
    assert_eq!(code, 0, "{styled_off}");
    assert!(!styled_off.contains('\u{1b}'), "{styled_off}");
    for args in [
        vec!["tb", "--period", "FY2026-P03", "--json"],
        vec!["tb", "--period", "FY2026-P03"],
        vec!["period", "list", "--json"],
        vec!["capabilities", "--json"],
    ] {
        let (_, early, _) = fa_env(Some(&book), &args, &[("SOURCE_DATE_EPOCH", "0")]);
        let (_, late, _) = fa_env(Some(&book), &args, &[("SOURCE_DATE_EPOCH", "1900000000")]);
        let (_, unset, _) = fa(Some(&book), &args);
        assert_eq!(early, late, "{args:?}");
        assert_eq!(early, unset, "{args:?}");
    }
    Ok(())
}

/// Correction spans the registry's distance (1): one edit gets a "did you
/// mean", two edits get the plain help pointer; a guess is never run.
#[test]
fn corrections_span_exactly_one_edit() {
    let (code, out, _) = fa(None, &["psot", "--json"]);
    assert_eq!(code, 2, "{out}");
    assert!(
        text(&doc(&out), "fix").contains("did you mean `fa post`"),
        "{out}"
    );
    let (code, out, _) = fa(None, &["tb", "--jsno"]);
    assert_eq!(code, 2, "{out}");
    let (code, out, _) = fa(None, &["pzzt", "--json"]);
    assert_eq!(code, 2, "{out}");
    let fix = text(&doc(&out), "fix").to_string();
    assert!(
        !fix.contains("did you mean"),
        "two edits are not corrected: {out}"
    );
    assert!(fix.contains("fa --help"), "{out}");
}

/// fa-40l: a host that is not the `fa` binary (fa-mcp, an embedding) names
/// the book and its keys file relative to its own working directory, which
/// it hands over as `Files::cwd`; this process's directory is another. Every
/// spelling opens the same book and reads byte-identically to the absolute
/// one, through the public `fa_with`, with this process's cwd and
/// environment untouched.
#[test]
fn a_hosts_relative_book_and_keys_resolve_against_its_files_cwd() -> std::io::Result<()> {
    let client = tmp("host-cwd")?;
    let nested = client.join("nested");
    std::fs::create_dir(&nested)?;
    std::fs::create_dir(client.join("keys"))?;
    let book = client.join("acme");
    let keys = client.join("keys").join("acme.keys");
    let (b, k) = (book.display().to_string(), keys.display().to_string());
    let host = |cwd: Option<&Path>, args: &[&str]| -> (u8, String, String) {
        let argv: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
        let files = fa_cli::cli::Files {
            cwd: cwd.map(Path::to_path_buf),
            stdin: fa_cli::cli::Stdin::Missing,
        };
        let (code, out) = fa_cli::entry::fa_with(&argv, files, true);
        (code, out.stdout, out.stderr)
    };
    let (code, out, err) = host(
        None,
        &[
            "book", "create", "--book", &b, "--keys", &k, "--name", "Host Co", "--json",
        ],
    );
    assert_eq!(code, 0, "{out}{err}");
    // The keys live outside the book, so every read below resolves `--keys` too.
    assert!(keys.is_file() && !book.join("book.keys").exists());
    let absolute = host(
        None,
        &["book", "info", "--book", &b, "--keys", &k, "--json"],
    );
    assert_eq!(absolute.0, 0, "{absolute:?}");
    assert_eq!(
        text(&robot_line(&absolute.1), "event"),
        "book",
        "{absolute:?}"
    );
    for (cwd, book_arg, keys_arg) in [
        (client.as_path(), "acme", "keys/acme.keys"),
        (client.as_path(), "./acme", "./keys/acme.keys"),
        (nested.as_path(), "../acme", "../keys/acme.keys"),
        (nested.as_path(), b.as_str(), k.as_str()),
    ] {
        let aliased = host(
            Some(cwd),
            &[
                "book", "info", "--book", book_arg, "--keys", keys_arg, "--json",
            ],
        );
        assert_eq!(
            aliased, absolute,
            "cwd={cwd:?} book={book_arg} keys={keys_arg}"
        );
    }
    // Without the host's cwd the same relative spelling names a path in this
    // process's directory, where no such book or keys file exists.
    let (code, out, _) = host(
        None,
        &[
            "book",
            "info",
            "--book",
            "acme",
            "--keys",
            "keys/acme.keys",
            "--json",
        ],
    );
    assert!(matches!(code, 4 | 5), "exit {code}: {out}");
    Ok(())
}

#[test]
fn instant_selected_cli_reports_retain_tick_evidence_and_replay() -> std::io::Result<()> {
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fa::book::{Book, BookKeys, Entropy};
    use fa_journal::{Capability, Ticked};
    use fgdb_types::{CommitSeq, VId};

    // Independent epoch constants, not values produced by the parser under
    // test: 2026-03-15 at 12:00:00Z, 12:00:05Z and 12:00:10Z.
    const LOWER_NS: u64 = 1_773_576_000_000_000_000;
    const REQUESTED_NS: u64 = 1_773_576_005_000_000_000;
    const UPPER_NS: u64 = 1_773_576_010_000_000_000;
    const INSTANT: &str = "2026-03-15T12:00:05Z";
    const CANONICAL_INSTANT: &str = "2026-03-15T12:00:05.000000000Z";
    const OFFSET_INSTANT: &str = "2026-03-15T08:00:05-04:00";
    const PERIOD: &str = "FY2026-P03";

    let dir = tmp("instant-reports")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        assert!(err.is_empty(), "{err}");
        out
    };
    ok(&["book", "create", "--name", "Time Evidence Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", PERIOD, "--json"]);
    let evidence = source_doc(&dir, &book);

    let keys = BookKeys::load(&book.join("book.keys")).unwrap();
    let open = || Book::open_dir(&book, keys.clone(), Entropy::production()).unwrap();
    let head = || open().head().unwrap();
    let before_evidence = head();
    for args in [
        vec!["tb", "--period", PERIOD, "--as-known-at", INSTANT, "--json"],
        vec![
            "open-items",
            "--account",
            "1000",
            "--as-known-at",
            INSTANT,
            "--json",
        ],
        vec![
            "explain",
            "balance",
            "1000",
            "--period",
            PERIOD,
            "--as-known-at",
            INSTANT,
            "--json",
        ],
    ] {
        let (code, out, err) = fa(Some(&book), &args);
        assert_eq!(code, 3, "args={args:?}\n{out}\n{err}");
        assert_eq!(text(&doc(&out), "refusal_id"), "FA-REF-151", "{out}");
        assert_eq!(out.lines().count(), 1);
    }
    assert_eq!(head(), before_evidence, "missing time evidence never writes");

    // Only this explicit, witness-authorized host records clock evidence.
    // The read-only CLI is not given a tick command or System authority.
    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let witness = Capability::embedded(VId(7), &["witness"]).unwrap();
    let tick = |observed_utc_ns| -> Ticked {
        let mut handle = open();
        runtime
            .block_on(handle.record_tick(&root, observed_utc_ns, true, &witness))
            .unwrap()
            .unwrap()
    };
    let lower = tick(LOWER_NS);
    let first_file = write(
        &dir,
        "first.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"first","legs":[{"side":"debit","account":"6000","amount":"100.00 USD"},{"side":"credit","account":"1000","amount":"100.00 USD"}]}"#,
    );
    let first = doc(&ok(&[
        "post",
        "--intent",
        &first_file,
        "--evidence",
        &evidence,
        "--json",
    ]));
    let first_seq = int(&first, "recorded_at").unwrap();
    let first_vid = text(&first, "vid").to_string();
    assert!(first_seq > i128::from(lower.recorded_at.0));

    let check_coordinate = |line: &str, frontier: CommitSeq, upper: Option<&Ticked>| {
        let envelope = json::parse(line).unwrap();
        let coordinate = envelope.get("coordinate").unwrap();
        assert_eq!(int(coordinate, "known_at"), Some(first_seq), "{line}");
        let time = coordinate.get("time_evidence").unwrap();
        assert_eq!(text(time, "requested_instant"), CANONICAL_INSTANT, "{line}");
        assert_eq!(int(time, "requested_utc_ns"), Some(i128::from(REQUESTED_NS)));
        assert_eq!(int(time, "frontier"), Some(i128::from(frontier.0)));
        assert_eq!(int(time, "resolved_seq"), Some(first_seq));
        assert_eq!(text(time, "precision"), "tick_bucket", "{line}");
        assert_eq!(text(time, "source_grade"), "corroborated_daemon_clock", "{line}");
        let observation = time.get("lower").unwrap();
        assert_eq!(
            text(observation, "entry"),
            format!("{:032x}", lower.entry_ref.vid.0)
        );
        assert_eq!(
            int(observation, "recorded_at"),
            Some(i128::from(lower.recorded_at.0))
        );
        assert_eq!(
            int(observation, "observed_utc_ns"),
            Some(i128::from(LOWER_NS))
        );
        assert_eq!(int(observation, "source"), Some(0));
        assert_eq!(observation.get("monotonic_ok"), Some(&Json::Bool(true)));
        match upper {
            Some(tick) => {
                let observation = time.get("upper").unwrap();
                assert_eq!(
                    text(observation, "entry"),
                    format!("{:032x}", tick.entry_ref.vid.0)
                );
                assert_eq!(
                    int(observation, "recorded_at"),
                    Some(i128::from(tick.recorded_at.0))
                );
                assert_eq!(
                    int(observation, "observed_utc_ns"),
                    Some(i128::from(UPPER_NS))
                );
                assert_eq!(observation.get("monotonic_ok"), Some(&Json::Bool(true)));
            }
            None => assert_eq!(time.get("upper"), Some(&Json::Null), "{line}"),
        }
    };

    let open_frontier = head();
    let path = dir.join("open-bucket.cert").display().to_string();
    let certified = ok(&[
        "tb",
        "--period",
        PERIOD,
        "--as-known-at",
        INSTANT,
        "--certificate-out",
        &path,
        "--json",
    ]);
    let lines: Vec<&str> = certified.lines().collect();
    assert_eq!(lines.len(), 2, "trial balance plus retained certificate");
    assert_eq!(field(lines[0], "event"), Some("trial_balance"));
    assert_cash_credits(lines[0], "100.00 USD");
    check_coordinate(lines[0], open_frontier, None);
    check_coordinate(lines[1], open_frontier, None);
    let retained_line = format!("{}\n", lines[0]);
    let retained = fa::ReportCertificate::decode(&std::fs::read(&path)?).unwrap();
    let bound_time = retained.time_selection.as_ref().unwrap();
    assert_eq!(bound_time.resolution.frontier, open_frontier.0);
    assert_eq!(bound_time.resolution.requested_utc_ns, REQUESTED_NS);
    assert!(bound_time.resolution.upper.is_none());
    assert_eq!(head(), open_frontier, "certifying an instant never posts a tick");

    let upper = tick(UPPER_NS);
    assert_eq!(
        i128::from(upper.recorded_at.0.checked_sub(1).unwrap()),
        first_seq,
        "the next tick closes the selected bucket before its own commit"
    );
    let later_file = write(
        &dir,
        "later.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"later","legs":[{"side":"debit","account":"6000","amount":"25.00 USD"},{"side":"credit","account":"1000","amount":"25.00 USD"}]}"#,
    );
    ok(&[
        "post",
        "--intent",
        &later_file,
        "--evidence",
        &evidence,
        "--json",
    ]);
    tick(1_773_576_020_000_000_000);
    let current_frontier = head();

    let selected = report(
        &book,
        &["tb", "--period", PERIOD, "--as-known-at", INSTANT, "--json"],
    );
    assert_cash_credits(&selected, "100.00 USD");
    check_coordinate(selected.trim_end(), current_frontier, Some(&upper));
    let equivalent = report(
        &book,
        &[
            "tb",
            "--period",
            PERIOD,
            "--as-known-at",
            OFFSET_INSTANT,
            "--json",
        ],
    );
    assert_eq!(selected, equivalent, "equivalent offsets canonicalize identically");

    let items_out = ok(&[
        "open-items",
        "--account",
        "1000",
        "--as-known-at",
        INSTANT,
        "--json",
    ]);
    check_coordinate(items_out.trim_end(), current_frontier, Some(&upper));
    let items = doc(&items_out);
    assert_eq!(int(&items, "count"), Some(1));
    let item = &arr(&items, "items")[0];
    assert_eq!(text(item, "entry"), first_vid);
    assert_eq!(text(item, "open"), "100.00 USD");

    let explained = ok(&[
        "explain",
        "balance",
        "1000",
        "--period",
        PERIOD,
        "--as-known-at",
        INSTANT,
        "--json",
    ]);
    check_coordinate(explained.trim_end(), current_frontier, Some(&upper));
    let explanation = doc(&explained);
    assert_eq!(arr(&explanation, "contributions").len(), 1);
    assert_eq!(text(&arr(&explanation, "contributions")[0], "entry"), first_vid);
    assert_eq!(text(&arr(&explanation, "cells")[0], "credits"), "100.00 USD");

    let replay = ok(&["replay", &path, "--json"]);
    assert_eq!(
        replay, retained_line,
        "replay retains the original frontier and open bracket after later ticks"
    );
    check_coordinate(replay.trim_end(), open_frontier, None);
    assert_cash_credits(
        &report(&book, &["tb", "--period", PERIOD, "--json"]),
        "125.00 USD",
    );
    assert_eq!(
        head(),
        current_frontier,
        "instant resolution, reports and replay leave the journal frontier unchanged"
    );
    Ok(())
}

#[test]
fn projection_verification_reports_drift_deterministically_without_writes() -> std::io::Result<()> {
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::types::Budget;
    use fa::{Book, BookKeys, Entropy};
    use fa_journal::BookSpec;
    use fa_model::Id128;
    use fa_model::symbols::{label, property, relation};
    use fgdb::{Database, DatabaseKeys, WriteBatch};
    use fgdb_types::CanonicalScalar;
    use fgdb_types::context::PurposeContexts;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    let dir = tmp("verify-projections")?;
    let book = dir.join("book");
    let keys = BookKeys::for_development(91);
    let handle = Book::create_dir(
        &book,
        keys.clone(),
        BookSpec {
            book_id: Id128([91; 16]),
            name: "Projection verification".into(),
            base_unit: fa_money::UnitRegistry::embedded()
                .unwrap()
                .lookup("USD")
                .unwrap(),
            calendar: fa_time::FiscalCalendar::monthly("fiscal", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(91),
    )
    .unwrap();
    keys.save(&book.join("book.keys")).unwrap();
    drop(handle);
    let ok = |args: &[&str]| {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        assert!(err.is_empty(), "{err}");
        out
    };
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let evidence = source_doc(&dir, &book);
    let intent = write(
        &dir,
        "entry.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"projection-entry","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}]}"#,
    );
    ok(&[
        "post",
        "--intent",
        &intent,
        "--evidence",
        &evidence,
        "--json",
    ]);
    let handle = Book::open_dir(&book, keys.clone(), Entropy::deterministic(91)).unwrap();
    let prefix = handle.head().unwrap();
    drop(handle);

    let verify = ["verify", "projections", "--json"];
    let green = ok(&verify);
    assert_eq!(green.lines().count(), 1, "{green}");
    assert_eq!(field(&green, "event"), Some("projections_verified"));
    let data = doc(&green);
    assert_eq!(int(&data, "known_at"), Some(i128::from(prefix.0)));
    assert!(int(&data, "entries_checked").unwrap() >= 1);
    assert_eq!(int(&data, "legs_checked"), Some(2));
    assert_eq!(int(&data, "edges_checked"), Some(6));
    assert!(arr(&data, "drift").is_empty());
    assert_eq!(
        int(robot_line(&green).get("coordinate").unwrap(), "known_at"),
        Some(i128::from(prefix.0))
    );
    assert_eq!(ok(&verify), green, "the same prefix has the same report");
    let handle = Book::open_dir(&book, keys.clone(), Entropy::deterministic(91)).unwrap();
    assert_eq!(handle.head().unwrap(), prefix, "green verification wrote nothing");
    drop(handle);

    // Plant a bad scalar mirror through the real substrate while leaving
    // the canonical payload and journal balances unchanged.
    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let mut db = runtime
        .block_on(Database::open(
            &cx.commit(),
            &book.join("store"),
            DatabaseKeys::new([91; 32], DatabaseSecurityNamespaceId([92; 32]), [93; 32]),
        ))
        .unwrap();
    let leg = db
        .vertices()
        .unwrap()
        .into_iter()
        .find(|row| row.labels.contains(&label::LEG))
        .expect("posted leg")
        .vid;
    let mut batch = WriteBatch::new(relation::HAS_LEG);
    batch.set_vertex_property(leg, property::SIDE, Some(CanonicalScalar::Int(99)));
    let damaged_at = runtime.block_on(db.write(&cx.commit(), batch)).unwrap();
    drop(db);

    let (code, red, err) = fa(Some(&book), &verify);
    assert_eq!(code, 8, "{red}\n{err}");
    assert_eq!(red.lines().count(), 1, "{red}");
    assert_eq!(field(&red, "event"), Some("error"));
    let error = doc(&red);
    assert_eq!(text(&error, "class"), "verification");
    let detail = error.get("detail").expect("projection report");
    assert_eq!(int(detail, "known_at"), Some(i128::from(damaged_at.0)));
    assert_eq!(
        int(robot_line(&red).get("coordinate").unwrap(), "known_at"),
        Some(i128::from(damaged_at.0))
    );
    let leg_hex = format!("{:032x}", leg.0);
    assert!(
        arr(detail, "drift")
            .iter()
            .filter_map(Json::as_str)
            .any(|finding| finding.contains(&leg_hex) && finding.contains("side mirror")),
        "{red}"
    );
    let repeated = fa(Some(&book), &verify);
    assert_eq!(repeated.0, 8, "{}\n{}", repeated.1, repeated.2);
    assert_eq!(repeated.1, red, "red verification is deterministic too");
    let handle = Book::open_dir(&book, keys, Entropy::deterministic(91)).unwrap();
    assert_eq!(
        handle.head().unwrap(),
        damaged_at,
        "red verification published nothing"
    );
    assert!(!handle.verify_projections(None).unwrap().is_green());
    assert!(
        handle
            .verify_projections(Some(prefix))
            .unwrap()
            .is_green(),
        "the earlier committed projection remains independently verifiable"
    );
    Ok(())
}

#[test]
fn projection_verification_refuses_filters_and_extra_arguments_before_opening() {
    let cases: &[&[&str]] = &[
        &["verify", "projections", "--period", "FY2026-P03", "--json"],
        &["verify", "projections", "--fiscal-year", "2026", "--json"],
        &["verify", "projections", "--as-known-at", "HEAD", "--json"],
        &["verify", "projections", "extra", "--json"],
    ];
    for args in cases {
        let (code, out, err) = fa(None, args);
        assert_eq!(code, 2, "args={args:?}\n{out}\n{err}");
        assert_eq!(text(&doc(&out), "class"), "usage");
        let envelope = robot_line(&out);
        assert_eq!(envelope.get("book"), Some(&Json::Null));
        assert_eq!(envelope.get("coordinate"), Some(&Json::Null));
    }
    let (code, help, err) = fa(None, &["verify", "--help", "--json"]);
    assert_eq!(code, 0, "{help}\n{err}");
    assert!(text(&doc(&help), "text").contains("verify projections"));
}

#[test]
fn directory_reopen_refuses_changed_or_missing_unit_facts_through_facade_and_cli()
-> std::io::Result<()> {
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::types::Budget;
    use fa::{Book, BookKeys, Entropy};
    use fa_journal::BookSpec;
    use fa_model::Id128;
    use fa_model::symbols::{property, relation};
    use fa_money::{RoundingLaw, UnitKind, UnitRegistry};
    use fgdb::{Database, DatabaseKeys, WriteBatch};
    use fgdb_types::CanonicalScalar;
    use fgdb_types::context::PurposeContexts;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    for damage in [
        "kind",
        "ISO",
        "rounding",
        "truncated",
        "major",
        "minor",
        "missing_payload",
        "missing_table",
    ] {
        let dir = tmp("unit-reopen")?;
        let book = dir.join("book");
        let book_id = Id128([57; 16]);
        let keys = BookKeys::for_development(57);
        let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
        let handle = Book::create_dir(
            &book,
            keys.clone(),
            BookSpec {
                book_id,
                name: "Journaled unit identity".into(),
                base_unit: usd,
                calendar: fa_time::FiscalCalendar::monthly("fiscal", 1, 1).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(57),
        )
        .unwrap();
        let original = handle.context().units.get(usd).unwrap().clone();
        keys.save(&book.join("book.keys")).unwrap();
        drop(handle);

        let reopened = Book::open_dir(&book, keys.clone(), Entropy::deterministic(57))
            .unwrap();
        assert_eq!(reopened.context().units.get(usd), Some(&original));
        drop(reopened);
        let (code, out, err) = fa(Some(&book), &["book", "info", "--json"]);
        assert_eq!(code, 0, "before {damage}: {out}\n{err}");

        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let ctx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime
            .block_on(Database::open(
                &ctx.commit(),
                &book.join("store"),
                DatabaseKeys::new([57; 32], DatabaseSecurityNamespaceId([58; 32]), [59; 32]),
            ))
            .unwrap();
        let vid = fa_model::unit_vid(book_id, "USD@v0");
        let row = db.vertex(vid).unwrap().unwrap();
        let payload = fa_journal::rows::bytes(&row, property::FA_PAYLOAD, "unit.payload")
            .unwrap();
        let mut definition = fa_model::UnitDefinition::decode(&payload).unwrap();
        let mut batch = WriteBatch::new(relation::IN_BOOK);
        match damage {
            "kind" | "ISO" | "rounding" => {
                match damage {
                    "kind" => definition.unit.kind = UnitKind::Custom,
                    "ISO" => definition.unit.kind = UnitKind::Currency { iso4217: 978 },
                    "rounding" => definition.unit.rounding_default = RoundingLaw::HalfUp,
                    _ => unreachable!(),
                }
                batch.set_vertex_property(
                    vid,
                    property::FA_PAYLOAD,
                    Some(CanonicalScalar::bytes(definition.canonical_bytes().unwrap()).unwrap()),
                );
            }
            "truncated" | "major" | "minor" => {
                let mut damaged = payload;
                match damage {
                    "truncated" => {
                        damaged.pop();
                    }
                    "major" => damaged[4] = 2,
                    "minor" => damaged[6] = 1,
                    _ => unreachable!(),
                }
                batch.set_vertex_property(
                    vid,
                    property::FA_PAYLOAD,
                    Some(CanonicalScalar::bytes(damaged).unwrap()),
                );
            }
            "missing_payload" => {
                batch.set_vertex_property(vid, property::FA_PAYLOAD, None);
            }
            "missing_table" => {
                batch.set_vertex_property(
                    fa_journal::rows::book_root(),
                    property::UNIT_TABLE_DIGEST,
                    None,
                );
            }
            _ => unreachable!(),
        }
        let damaged_at = runtime.block_on(db.write(&ctx.commit(), batch)).unwrap();
        drop(db);

        let error = Book::open_dir(&book, keys.clone(), Entropy::deterministic(57))
            .err()
            .expect("reopen must refuse changed historical unit facts");
        assert_eq!(error.exit(), 5, "{damage}: {error}");
        let expected = match damage {
            "kind" | "ISO" => "kind/ISO",
            "rounding" => "default rounding law",
            "major" => "unit.schema_major",
            "minor" => "unit.schema_minor",
            "missing_payload" | "missing_table" => "pre-payload",
            _ => "unit.",
        };
        assert!(
            error.to_string().contains(expected),
            "{damage}: expected {expected}: {error}"
        );
        let (code, out, err) = fa(Some(&book), &["book", "info", "--json"]);
        assert_eq!(code, 5, "{damage}: {out}\n{err}");
        assert!(out.contains(expected), "{damage}: {out}\n{err}");
        if damage.starts_with("missing") {
            assert!(out.contains("backfill"), "{out}");
            assert!(out.contains("not available yet"), "{out}");
        }

        let db = runtime
            .block_on(Database::open(
                &ctx.commit(),
                &book.join("store"),
                DatabaseKeys::new([57; 32], DatabaseSecurityNamespaceId([58; 32]), [59; 32]),
            ))
            .unwrap();
        assert_eq!(
            db.frontier().unwrap(),
            damaged_at,
            "{damage}: facade and CLI refusals must preserve the journal"
        );
    }
    Ok(())
}
