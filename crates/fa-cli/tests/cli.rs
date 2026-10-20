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

/// A trial balance line without its `served` disclosure (fa-715): how a
/// head read was answered is not part of the fold it answers, and a
/// historical read of the same coordinate always folds the journal.
fn without_served(out: &str) -> Json {
    let mut line = json::parse(out.trim()).expect("one robot line");
    if let Json::Obj(fields) = &mut line
        && let Some((_, Json::Obj(data))) = fields.iter_mut().find(|(key, _)| key == "data")
    {
        data.retain(|(key, _)| key != "served");
    }
    line
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

/// fa-l93 D13: an identical `fa period <t> --key K` retry is the recorded
/// outcome (exit 0, one `recorded` event naming the same control entry);
/// without the key, the second open is the state machine's refusal.
#[test]
fn an_identical_period_transition_retry_is_the_recorded_outcome() -> std::io::Result<()> {
    let dir = tmp("transition-retry")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    ok(&["book", "create", "--name", "Retry Co", "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    let open = [
        "period",
        "open",
        "FY2026-P03",
        "--key",
        "open-p03",
        "--json",
    ];
    let first = ok(&open);
    assert_eq!(
        field(&first, "event"),
        Some("period_transitioned"),
        "{first}"
    );
    let entry = field(&first, "control_entry")
        .unwrap_or_default()
        .to_string();
    assert_eq!(entry.len(), 32, "{first}");
    let again = ok(&open);
    assert_eq!(field(&again, "event"), Some("recorded"), "{again}");
    assert_eq!(field(&again, "vid"), Some(entry.as_str()), "{again}");
    assert_eq!(
        field(&again, "recorded_at"),
        field(&first, "recorded_at"),
        "{again}"
    );
    let (code, out, _) = fa(Some(&book), &["period", "open", "FY2026-P03", "--json"]);
    assert_eq!(code, 7, "a keyless second open is a new request: {out}");
    assert!(out.contains("\"refusal_id\":\"FA-REF-040\""), "{out}");
    Ok(())
}

/// fa-nl7: `fa post --intent` with a PostBatch intent commits every member
/// in one commit; an identical retry is the recorded outcome; the same key
/// with other members is a conflict (exit 6); a refused member names its
/// index and nothing of the batch is posted.
#[test]
fn a_batch_intent_posts_atomically_and_its_retry_is_the_recorded_outcome() -> std::io::Result<()> {
    let dir = tmp("batch-intent")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    ok(&["book", "create", "--name", "Batch Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let ev = source_doc(&dir, &book);
    let member = |key: &str, amount: &str| {
        format!(
            r#"{{"effective_date":"2026-03-15","idempotency_key":"{key}","evidence":["{ev}"],"legs":[{{"side":"debit","account":"6000","amount":"{amount} USD"}},{{"side":"credit","account":"1000","amount":"{amount} USD"}}]}}"#
        )
    };
    let batch = |key: &str, members: &[String]| {
        format!(
            r#"{{"idempotency_key":"{key}","intents":[{}]}}"#,
            members.join(",")
        )
    };
    let path = write(
        &dir,
        "batch.json",
        &batch("b1", &[member("m1", "10.00"), member("m2", "20.00")]),
    );
    let posted = ok(&["post", "--intent", &path, "--json"]);
    eprintln!("batch intent: {posted}");
    assert_eq!(field(&posted, "event"), Some("batch_posted"), "{posted}");
    let data = doc(&posted);
    assert_eq!(
        data.get("already_recorded"),
        Some(&Json::Bool(false)),
        "{posted}"
    );
    assert_eq!(arr(&data, "members").len(), 2, "{posted}");
    let recorded_at = int(&data, "recorded_at");
    let tb = ok(&["tb", "--period", "FY2026-P03", "--json"]);
    assert!(tb.contains("30.00 USD"), "both members folded: {tb}");

    let again = ok(&["post", "--intent", &path, "--json"]);
    let data = doc(&again);
    assert_eq!(
        data.get("already_recorded"),
        Some(&Json::Bool(true)),
        "{again}"
    );
    assert_eq!(int(&data, "recorded_at"), recorded_at, "{again}");

    let changed = write(&dir, "changed.json", &batch("b1", &[member("m3", "5.00")]));
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &changed, "--json"]);
    assert_eq!(code, 6, "same key, other members: {out}");
    assert!(out.contains("\"refusal_id\":\"FA-REF-032\""), "{out}");

    let refused = write(
        &dir,
        "refused.json",
        &batch(
            "b2",
            &[
                member("m4", "1.00"),
                member("m5", "1.00").replace("6000", "9999"),
            ],
        ),
    );
    let (code, out, _) = fa(Some(&book), &["post", "--intent", &refused, "--json"]);
    eprintln!("batch intent refused: {code} {out}");
    assert_ne!(code, 0, "{out}");
    assert!(out.contains("batch member 1"), "{out}");
    let tb_after = ok(&["tb", "--period", "FY2026-P03", "--json"]);
    assert!(
        !tb_after.contains("31.00 USD"),
        "member 0 was not posted: {tb_after}"
    );
    Ok(())
}

/// An invoice and its application can be reviewed before either exists.
/// The complete portable plan survives a refused later-member rehearsal,
/// commits in one publication, and recognizes the same bytes on retry.
#[test]
fn an_atomic_batch_plan_rehearses_in_order_and_commits_its_saved_bytes_once() -> std::io::Result<()>
{
    use fa::{Book, BookKeys, Entropy};

    let dir = tmp("batch-plan")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    ok(&["book", "create", "--name", "Batch Plan Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1200","name":"Receivables","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let evidence = source_doc(&dir, &book);
    let keys = BookKeys::load(&book.join("book.keys")).unwrap();
    let open = || Book::open_dir(&book, keys.clone(), Entropy::production()).unwrap();
    let actor = "batch-planner";
    let invoice_vid = fa_model::entry_vid(
        open().context().book_id,
        &fa_model::principal_vid(actor).0.to_le_bytes(),
        b"invoice-in-batch",
    );
    let invoice_hex = format!("{:032x}", invoice_vid.0);
    let invoice = format!(
        r#"{{"effective_date":"2026-03-15","idempotency_key":"invoice-in-batch","evidence":["{evidence}"],"legs":[{{"side":"debit","account":"1200","amount":"50.00 USD"}},{{"side":"credit","account":"4000","amount":"50.00 USD"}}]}}"#
    );
    let receipt = format!(
        r#"{{"effective_date":"2026-03-16","idempotency_key":"receipt-in-batch","evidence":["{evidence}"],"legs":[{{"side":"debit","account":"1000","amount":"20.00 USD"}},{{"side":"credit","account":"1200","amount":"20.00 USD","settles":[{{"entry":"{invoice_hex}","ordinal":0,"amount":"20.00 USD"}}]}}]}}"#
    );
    let intent = write(
        &dir,
        "invoice-and-receipt.json",
        &format!(r#"{{"idempotency_key":"invoice-and-receipt","intents":[{invoice},{receipt}]}}"#),
    );
    let plan_path = dir.join("invoice-and-receipt.plan").display().to_string();
    let before = open().head().unwrap();
    let before_balance = doc(&ok(&["tb", "--period", "FY2026-P03", "--json"]));
    let planned = ok(&[
        "post",
        "--intent",
        &intent,
        "--as",
        actor,
        "--dry-run",
        "--plan-out",
        &plan_path,
        "--json",
    ]);
    assert_eq!(planned.lines().count(), 1, "{planned}");
    assert_eq!(field(&planned, "event"), Some("batch_plan"));
    let plan_data = doc(&planned);
    assert_eq!(int(&plan_data, "snapshot_seq"), Some(i128::from(before.0)));
    assert_eq!(text(&plan_data, "intent_kind"), "PostBatch");
    assert_eq!(text(&plan_data, "scope"), "same-snapshot-batch");
    let members = arr(&plan_data, "members");
    assert_eq!(members.len(), 2, "{planned}");
    assert_eq!(text(&members[0], "vid"), invoice_hex);
    let applied = &arr(&arr(&members[1], "legs")[1], "settles")[0];
    assert_eq!(text(applied, "entry"), invoice_hex);
    assert_eq!(
        text(applied, "entry_digest"),
        text(&members[0], "entry_digest")
    );
    assert_eq!(text(applied, "amount"), "20.00 USD");
    let bytes = std::fs::read(&plan_path)?;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(text(&plan_data, "bytes"), hex);
    let restored = fa::BatchPlan::decode(&bytes).unwrap();
    assert_eq!(restored.prepared_entries().len(), 2);
    assert_eq!(restored.certificate().snapshot_seq, before);
    assert_eq!(
        restored.prepared_entries()[1].proposal.legs[1].settles[0]
            .target
            .vid,
        invoice_vid
    );
    assert_eq!(open().head().unwrap(), before, "planning never publishes");
    assert!(open().read_entry(invoice_vid).unwrap().is_none());
    assert_eq!(
        doc(&ok(&["tb", "--period", "FY2026-P03", "--json"])).get("rows"),
        before_balance.get("rows"),
        "neither preview member contributes to the journal"
    );

    // Fail only after the invoice has been staged. No successful plan or
    // output file can escape, and the saved good plan's basis stays valid.
    let unbalanced = format!(
        r#"{{"effective_date":"2026-03-16","idempotency_key":"bad-later-member","evidence":["{evidence}"],"legs":[{{"side":"debit","account":"1000","amount":"1.00 USD"}},{{"side":"credit","account":"4000","amount":"0.99 USD"}}]}}"#
    );
    let refused = write(
        &dir,
        "refused-batch.json",
        &format!(r#"{{"idempotency_key":"refused-batch","intents":[{invoice},{unbalanced}]}}"#),
    );
    let refused_plan = dir.join("must-not-exist.plan").display().to_string();
    let (code, failed, err) = fa(
        Some(&book),
        &[
            "post",
            "--intent",
            &refused,
            "--as",
            actor,
            "--dry-run",
            "--plan-out",
            &refused_plan,
            "--json",
        ],
    );
    assert_eq!(code, 3, "{failed}\n{err}");
    assert_eq!(failed.lines().count(), 1, "{failed}");
    assert_eq!(field(&failed, "event"), Some("error"));
    assert!(
        text(&doc(&failed), "message").contains("batch member 1"),
        "{failed}"
    );
    assert!(!Path::new(&refused_plan).exists());
    assert_eq!(open().head().unwrap(), before);
    assert!(open().read_entry(invoice_vid).unwrap().is_none());

    // Commit the stdout hex transport in a fresh process, then retry the
    // canonical binary artifact. Both must name the same atomic outcome.
    let hex_path = write(&dir, "invoice-and-receipt.hex", &hex);
    let committed = ok(&["commit", "--plan", &hex_path, "--as", actor, "--json"]);
    assert_eq!(field(&committed, "event"), Some("batch_plan_committed"));
    let committed_data = doc(&committed);
    assert_eq!(
        committed_data.get("already_recorded"),
        Some(&Json::Bool(false))
    );
    assert_eq!(
        int(&committed_data, "recorded_at"),
        Some(i128::from(before.0 + 1))
    );
    assert_eq!(
        text(&committed_data, "plan_digest"),
        text(&plan_data, "plan_digest")
    );
    assert_eq!(
        text(&committed_data, "certificate_digest"),
        text(&plan_data, "certificate_digest")
    );
    let committed_members = arr(&committed_data, "members");
    assert_eq!(committed_members.len(), members.len());
    for (committed, preview) in committed_members.iter().zip(members) {
        assert_eq!(text(committed, "vid"), text(preview, "vid"));
        assert_eq!(
            text(committed, "entry_digest"),
            text(preview, "entry_digest")
        );
        assert_eq!(text(committed, "period"), "FY2026-P03");
    }
    let posted_head = open().head().unwrap();
    assert_eq!(posted_head.0, before.0 + 1, "all effects share one commit");
    let open_items = doc(&ok(&["open-items", "--account", "1200", "--json"]));
    let invoice_item = arr(&open_items, "items")
        .iter()
        .find(|item| text(item, "entry") == invoice_hex)
        .expect("the batch invoice remains partly unpaid");
    assert_eq!(text(invoice_item, "original"), "50.00 USD");
    assert_eq!(text(invoice_item, "applied"), "20.00 USD");
    assert_eq!(text(invoice_item, "open"), "30.00 USD");
    let retry = ok(&["commit", "--plan", &plan_path, "--as", actor, "--json"]);
    let retry_data = doc(&retry);
    assert_eq!(retry_data.get("already_recorded"), Some(&Json::Bool(true)));
    for key in [
        "outcome",
        "recorded_at",
        "members",
        "plan_digest",
        "certificate_digest",
    ] {
        assert_eq!(
            retry_data.get(key),
            committed_data.get(key),
            "{key}: {retry}"
        );
    }
    assert_eq!(
        open().head().unwrap(),
        posted_head,
        "retry never republishes"
    );
    Ok(())
}

/// fa-ih4: posting ahead of the book's fiscal years is a safety refusal
/// (FA-REF-021, exit 7) naming the command that creates the year, never a
/// "corrupt row" foundation failure; following the fix admits the post.
#[test]
fn posting_into_an_uncreated_fiscal_year_names_the_period_create_command() -> std::io::Result<()> {
    let dir = tmp("uncreated-year")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    ok(&["book", "create", "--name", "Ahead Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    let evidence = source_doc(&dir, &book);
    let ahead = write(
        &dir,
        "ahead.json",
        r#"{"effective_date":"2028-02-10","idempotency_key":"ahead","legs":[{"side":"debit","account":"6000","amount":"5.00 USD"},{"side":"credit","account":"1000","amount":"5.00 USD"}]}"#,
    );
    let post = [
        "post",
        "--intent",
        &ahead,
        "--evidence",
        &evidence,
        "--json",
    ];
    let (code, out, err) = fa(Some(&book), &post);
    assert_eq!(code, 7, "{out}\n{err}");
    assert!(
        out.contains("\"event\":\"error\"")
            && out.contains("\"refusal_id\":\"FA-REF-021\"")
            && out.contains("fa period create --fiscal-year 2028, then fa period open FY2028-P02")
            && out.contains(r#""alternatives":["fa period open FY2028-P02"]"#),
        "{out}"
    );
    assert!(!out.contains("corrupt"), "{out}");
    ok(&["period", "create", "--fiscal-year", "2028", "--json"]);
    ok(&["period", "open", "FY2028-P02", "--json"]);
    let posted = ok(&post);
    assert_eq!(field(&posted, "event"), Some("posted"), "{posted}");
    Ok(())
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
    let known_at = int(&doc(&before), "known_at").unwrap().to_string();
    let mut retained = Vec::new();

    for (name, selector) in [
        ("stock", vec!["--period", "FY2026-P03"]),
        ("asof", vec!["--as-of", "2026-03-15"]),
        ("activity", vec!["--period", "FY2026-P03", "--activity"]),
    ] {
        let path = dir.join(format!("{name}.cert")).display().to_string();
        let mut args = vec!["tb"];
        args.extend(selector);
        args.extend([
            "--as-known-at",
            known_at.as_str(),
            "--certificate-out",
            path.as_str(),
            "--json",
        ]);
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
        assert!(int(&certificate, "recorded_at") > int(&certificate, "known_at"));
        assert!(text(&certificate, "replay_command").contains(&format!("C:{oid}")));
        assert!(int(&certificate, "native_inputs").is_some_and(|n| n > 0));
        let bytes = std::fs::read(&path)?;
        let decoded = fa::ReportCertificate::decode(&bytes).expect("retained canonical bytes");
        assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
        let replayed = ok(&["replay", &path, "--json"]);
        assert_eq!(replayed, original, "{name}: complete robot line replays");
        assert_eq!(ok(&["replay", oid, "--json"]), original);
        assert_eq!(ok(&["replay", &format!("C:{oid}"), "--json"]), original);
        let status = ok(&["certificate", "status", &path, "--json"]);
        let status = doc(&status);
        assert_eq!(text(&status, "status"), "Current");
        assert_eq!(int(&status, "known_at"), int(&certificate, "known_at"));
        assert_eq!(int(&status, "checked_at"), int(&certificate, "recorded_at"));
        assert!(arr(&status, "later_entries").is_empty());
        assert_eq!(
            doc(&ok(&[
                "certificate",
                "status",
                &format!("C:{oid}"),
                "--json"
            ])),
            status,
        );

        if name == "stock" {
            // Human-copyable hex and actual process stdin use the same decoder
            // as a saved binary certificate, independently of digest lookup.
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

            let frontier = report(&book, &["tb", "--period", "FY2026-P03", "--json"]);
            let repeated = ok(&[
                "tb",
                "--period",
                "FY2026-P03",
                "--as-known-at",
                known_at.as_str(),
                "--certify",
                "--json",
            ]);
            let repeated = doc(repeated.lines().nth(1).unwrap());
            assert_eq!(text(&repeated, "oid"), oid);
            assert_eq!(
                int(&repeated, "recorded_at"),
                int(&certificate, "recorded_at")
            );
            assert_eq!(
                report(&book, &["tb", "--period", "FY2026-P03", "--json"]),
                frontier,
                "retaining identical bytes reuses the stored object without publishing",
            );

            for missing in ["C:abcd".to_string(), format!("C:{}", "f".repeat(64))] {
                let (code, out, _) = fa(Some(&book), &["replay", &missing, "--json"]);
                assert_eq!(code, 8, "{out}");
                assert!(out.contains("FA-REF-150"), "{out}");
            }

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
            // The identity refusal precedes any prefix check: this book's head
            // is lower than the certificate's prefix.
            for verb in [vec!["replay"], vec!["certificate", "status"]] {
                let mut args = verb;
                args.extend([path.as_str(), "--json"]);
                let (code, out, _) = fa(Some(&other), &args);
                assert_eq!(code, 8, "{out}");
                assert!(out.contains("another book"), "{out}");
                assert!(out.contains("FA-REF-150"), "{out}");
            }
        }
        retained.push((oid.to_string(), original));
    }
    assert_eq!(
        without_served(&report(
            &book,
            &[
                "tb",
                "--period",
                "FY2026-P03",
                "--as-known-at",
                known_at.as_str(),
                "--json",
            ]
        )),
        without_served(&before),
        "certificate metadata never changes the certified accounting fold"
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
    for (oid, original) in retained {
        let status = doc(&ok(&["certificate", "status", &oid, "--json"]));
        assert_eq!(text(&status, "status"), "SupersededBy");
        assert_eq!(
            arr(&status, "later_entries"),
            &[Json::Str(later_vid.to_string())]
        );
        assert!(int(&status, "checked_at") > int(&status, "known_at"));
        assert_eq!(ok(&["replay", &oid, "--json"]), original);
    }
    assert_cash_credits(
        &report(&book, &["tb", "--period", "FY2026-P03", "--json"]),
        "125.00 USD",
    );
    Ok(())
}

#[test]
fn certified_explanations_and_open_items_replay_before_settlements_and_reversals()
-> std::io::Result<()> {
    use fa::{Book, BookKeys, Entropy};

    let dir = tmp("certified-report-families")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        assert!(err.is_empty(), "{err}");
        out
    };
    ok(&["book", "create", "--name", "Historical Reports", "--json"]);
    let keys = BookKeys::load(&book.join("book.keys")).unwrap();
    let head = || {
        Book::open_dir(&book, keys.clone(), Entropy::production())
            .unwrap()
            .head()
            .unwrap()
    };
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let before_chart = head().0.to_string();
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1200","name":"Receivables","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    let evidence = source_doc(&dir, &book);
    let invoice = write(
        &dir,
        "invoice.json",
        r#"{"effective_date":"2026-03-10","idempotency_key":"certified-invoice","legs":[{"side":"debit","account":"1200","amount":"500.00 USD"},{"side":"credit","account":"4000","amount":"500.00 USD"}]}"#,
    );
    let posted = doc(&ok(&[
        "post",
        "--intent",
        &invoice,
        "--evidence",
        &evidence,
        "--json",
    ]));
    let invoice_vid = text(&posted, "vid").to_string();
    let known_at = int(&posted, "recorded_at").unwrap().to_string();
    let mut retained = Vec::new();

    for (name, command, event, output_format) in [
        (
            "explanation",
            vec!["explain", "balance", "1200", "--period", "FY2026-P03"],
            "balance_explained",
            "fa:balance-explanation:v1",
        ),
        (
            "receivable-items",
            vec!["open-items", "--account", "1200"],
            "open_items",
            "fa:open-items:v1",
        ),
        (
            "all-items",
            vec!["open-items"],
            "open_items",
            "fa:open-items:v1",
        ),
        (
            "empty-cash",
            vec!["open-items", "--account", "1000"],
            "open_items",
            "fa:open-items:v1",
        ),
    ] {
        let mut args = command.clone();
        args.extend(["--as-known-at", known_at.as_str(), "--json"]);
        let frontier = head();
        let plain = ok(&args);
        assert_eq!(head(), frontier, "{name}: ordinary historical read wrote");
        let path = dir.join(format!("{name}.cert")).display().to_string();
        args.extend(["--certificate-out", path.as_str()]);
        let certified = ok(&args);
        let lines: Vec<&str> = certified.lines().collect();
        assert_eq!(lines.len(), 2, "{certified}");
        assert_eq!(field(lines[0], "event"), Some(event));
        assert_eq!(field(lines[1], "event"), Some("report_certificate"));
        let certificate = doc(lines[1]);
        let oid = text(&certificate, "oid");
        assert_eq!(field(lines[0], "certificate"), Some(oid));
        assert_eq!(field(lines[1], "certificate"), Some(oid));
        assert_eq!(text(&certificate, "output_format"), output_format);
        assert_eq!(int(&certificate, "known_at").unwrap().to_string(), known_at);
        assert_eq!(
            int(&certificate, "recorded_at"),
            Some(i128::from(frontier.0 + 1))
        );
        assert_eq!(head().0, frontier.0 + 1, "only retention publishes");

        let data = doc(lines[0]);
        let mut comparable = data.clone();
        if event == "balance_explained" {
            assert_eq!(text(&data, "certificate"), oid);
            let Json::Obj(fields) = &mut comparable else {
                panic!("explanation data must be an object");
            };
            fields
                .iter_mut()
                .find(|(key, _)| key == "certificate")
                .unwrap()
                .1 = Json::Null;
            assert_eq!(text(&arr(&data, "cells")[0], "debits"), "500.00 USD");
            assert_eq!(arr(&data, "contributions").len(), 1);
            assert_eq!(text(&arr(&data, "contributions")[0], "entry"), invoice_vid);
            assert_eq!(arr(&arr(&data, "contributions")[0], "evidence").len(), 1);
        } else {
            let expected_count = match name {
                "all-items" => 2,
                "empty-cash" => 0,
                _ => 1,
            };
            assert_eq!(int(&data, "count"), Some(expected_count));
            if name == "receivable-items" {
                let item = &arr(&data, "items")[0];
                assert_eq!(text(item, "entry"), invoice_vid);
                assert_eq!(text(item, "open"), "500.00 USD");
                assert!(arr(item, "applications").is_empty());
            }
            if name == "empty-cash" {
                assert_eq!(text(&data, "account"), "1000");
            }
        }
        assert_eq!(
            comparable,
            doc(&plain),
            "{name}: certification changed report data"
        );
        let bytes = std::fs::read(&path)?;
        assert!(bytes.starts_with(b"fa:report-certificate:v3"));
        let decoded = fa::ReportCertificate::decode(&bytes).unwrap();
        assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
        let original = format!("{}\n", lines[0]);
        for input in [path.as_str(), oid, &format!("C:{oid}")] {
            assert_eq!(ok(&["replay", input, "--json"]), original, "{name}");
        }
        let current = doc(&ok(&["certificate", "status", oid, "--json"]));
        assert_eq!(text(&current, "status"), "Current");
        assert!(arr(&current, "later_entries").is_empty());
        let stored_at = head();
        let mut retry = command;
        retry.extend(["--as-known-at", known_at.as_str(), "--certify", "--json"]);
        let retry = ok(&retry);
        assert_eq!(text(&doc(&retry), "oid"), oid);
        assert_eq!(head(), stored_at, "exact retained retry is idempotent");
        retained.push((oid.to_string(), original));
    }

    // Refuse unknown and not-yet-created identities before retaining a result.
    // A known empty account above is deliberately distinct from either case.
    let frontier = head();
    for (account, sequence) in [("9999", known_at.as_str()), ("1200", before_chart.as_str())] {
        for command in [
            vec!["explain", "balance", account, "--period", "FY2026-P03"],
            vec!["open-items", "--account", account],
        ] {
            for certified in [false, true] {
                let mut args = command.clone();
                args.extend(["--as-known-at", sequence, "--json"]);
                if certified {
                    args.push("--certify");
                }
                let (code, out, err) = fa(Some(&book), &args);
                assert_eq!(code, 2, "args={args:?}\n{out}\n{err}");
                assert_eq!(out.lines().count(), 1, "{out}");
                assert_eq!(field(&out, "event"), Some("error"));
                assert_eq!(field(&out, "certificate"), Some("null"));
                assert_eq!(head(), frontier, "refusal cannot retain a certificate");
            }
        }
    }

    let receipt = write(
        &dir,
        "receipt.json",
        &format!(
            r#"{{"effective_date":"2026-03-20","idempotency_key":"certified-receipt","legs":[{{"side":"debit","account":"1000","amount":"200.00 USD"}},{{"side":"credit","account":"1200","amount":"200.00 USD","settles":[{{"entry":"{invoice_vid}","ordinal":0,"amount":"200.00 USD"}}]}}]}}"#
        ),
    );
    let posted = doc(&ok(&[
        "post",
        "--intent",
        &receipt,
        "--evidence",
        &evidence,
        "--json",
    ]));
    let receipt_vid = text(&posted, "vid").to_string();
    let applied = doc(&ok(&["open-items", "--account", "1200", "--json"]));
    let invoice_item = arr(&applied, "items")
        .iter()
        .find(|item| text(item, "entry") == invoice_vid)
        .unwrap();
    assert_eq!(text(invoice_item, "open"), "300.00 USD");
    assert_eq!(
        arr(invoice_item, "applications")[0].get("live"),
        Some(&Json::Bool(true))
    );
    let reversed = doc(&ok(&[
        "reverse",
        &receipt_vid,
        "--reason",
        "WrongAmount",
        "--json",
    ]));
    let reversal_vid = text(&reversed, "vid").to_string();
    let reopened = doc(&ok(&["open-items", "--account", "1200", "--json"]));
    let invoice_item = arr(&reopened, "items")
        .iter()
        .find(|item| text(item, "entry") == invoice_vid)
        .unwrap();
    assert_eq!(text(invoice_item, "open"), "500.00 USD");
    assert_eq!(
        arr(invoice_item, "applications")[0].get("live"),
        Some(&Json::Bool(false))
    );

    let frontier = head();
    for (oid, original) in retained {
        let status = doc(&ok(&["certificate", "status", &oid, "--json"]));
        assert_eq!(text(&status, "status"), "SupersededBy");
        let later = arr(&status, "later_entries");
        assert_eq!(later.len(), 2, "{status:?}");
        assert!(later.contains(&Json::Str(receipt_vid.clone())));
        assert!(later.contains(&Json::Str(reversal_vid.clone())));
        assert_eq!(ok(&["replay", &oid, "--json"]), original);
    }
    assert_eq!(head(), frontier, "historical replay and status never write");
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
    // A writing command's flag typo is never run (a read's runs corrected
    // with a warning: polish_bar.rs first_try_spellings_matrix).
    let (code, out, err) = fa(None, &["post", "--jsno"]);
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
    // Every registered procedure with its claim class (fa-vpk): the same
    // set `fa procedure list` reports, and a digit test is statistical.
    let procedures = arr(&caps, "procedures");
    let registered = fa_lantern::catalog::registered().unwrap();
    assert_eq!(procedures.len(), registered.len(), "{out}");
    for (listed, row) in procedures.iter().zip(&registered) {
        assert_eq!(text(listed, "id"), row.id);
        assert_eq!(text(listed, "claim"), row.claim.name(), "{}", row.id);
    }
    let claim_of = |id: &str| {
        procedures
            .iter()
            .find(|row| text(row, "id") == id)
            .map(|row| text(row, "claim").to_string())
    };
    assert_eq!(
        claim_of("jet.round_amounts").as_deref(),
        Some("statistical")
    );
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
    assert_eq!(text(binding, "posture"), "embedded-owner");
    // fa-r3q: a daemon request carrying an issued token is bound to it.
    assert!(text(binding, "trust_boundary").contains("issued token"));
    assert!(text(binding, "trust_boundary").contains("does not authenticate the operator"));
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
    assert_eq!(
        fa(
            Some(&book),
            &["period", "close", march, "--reason", "Scheduled", "--yes"]
        )
        .0,
        0
    );
    // Confirmed with --yes, so the kernel's verdict is what refuses it.
    let (code, out, _) = fa(
        Some(&book),
        &[
            "period",
            "lock",
            march,
            "--reason",
            "Scheduled",
            "--yes",
            "--json",
        ],
    );
    assert_eq!(code, 7, "{out}");
    assert!(out.contains("\"refusal_id\":\"FA-REF-012\""), "{out}");
    let plan = dir.join("lock.plan").display().to_string();
    let (code, out, _) = fa(
        Some(&book),
        &[
            "period",
            "lock",
            march,
            "--reason",
            "Scheduled",
            "--plan-out",
            &plan,
            "--json",
        ],
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
            "--reason",
            "Scheduled",
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
    let locked = field(&out, "control_entry").unwrap_or_default().to_string();
    // Replaying the exact plan with the same approval is the identical
    // request (FA-INV-09, fa-l93 D13): it returns the recorded lock and
    // writes nothing, although the period is Locked now.
    let (_, before, _) = fa(Some(&book), &["book", "info", "--json"]);
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
    assert_eq!(field(&out, "event"), Some("recorded"), "{out}");
    assert_eq!(field(&out, "vid"), Some(locked.as_str()), "{out}");
    let (_, after, _) = fa(Some(&book), &["book", "info", "--json"]);
    assert_eq!(after, before, "the replay wrote nothing");
    // A different request after the lock is still the illegal transition.
    let (code, out, _) = fa(
        Some(&book),
        &[
            "period",
            "close",
            march,
            "--reason",
            "Scheduled",
            "--yes",
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
    let (code, _, _) = fa(
        Some(&book),
        &["period", "close", march, "--reason", "Scheduled", "--yes"],
    );
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
        &[
            "period",
            "reopen",
            march,
            "--reason",
            "LateTransactions",
            "--to",
            "open",
            "--yes",
            "--json",
        ],
    );
    assert_eq!(code, 7, "{out}");
    assert!(
        out.contains("\"refusal_id\":\"FA-REF-008\"")
            && out.contains("case_preparer")
            && out.contains("sod_policy.toml#period-reopen-closed")
            && out.contains("fa case approve"),
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

/// fa-giar: a correction is one atomic pair. `fa reverse --replace-with`
/// commits the exact reversal and the corrected Replacement at one sequence
/// under one reason; an exact retry writes nothing; unsupported drafts
/// are refused before anything is published; and a
/// Replacement posted alone names this command as its fix.
#[test]
fn reverse_with_a_replacement_posts_one_atomic_correction() -> std::io::Result<()> {
    let dir = tmp("correction")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Fix Co"]).0,
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
    let corrected = write(
        &dir,
        "corrected.json",
        r#"{"description":"rent, corrected","legs":[{"side":"debit","account":"6000","amount":"12.00 USD"},{"side":"credit","account":"1000","amount":"12.00 USD"}]}"#,
    );
    let with_class = write(
        &dir,
        "with-class.json",
        r#"{"class":"Original","legs":[{"side":"debit","account":"6000","amount":"12.00 USD"},{"side":"credit","account":"1000","amount":"12.00 USD"}]}"#,
    );

    // Refused before anything is published.
    let before = report(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    for (extra, replacement, expected) in [
        (
            vec!["--draft", "d1"],
            corrected.as_str(),
            "cannot be planned into a draft",
        ),
        (vec![], with_class.as_str(), "takes no `class`"),
    ] {
        let mut args = vec![
            "reverse",
            vid.as_str(),
            "--reason",
            "WrongAmount",
            "--replace-with",
            replacement,
            "--evidence",
            &ev,
            "--json",
        ];
        args.extend(extra);
        let (code, out, err) = fa(Some(&book), &args);
        assert_eq!(code, 2, "{args:?}\n{out}\n{err}");
        assert!(out.contains(expected), "{expected}: {out}");
    }
    assert_eq!(
        report(&book, &["tb", "--period", "FY2026-P03", "--json"]),
        before
    );

    let args = [
        "reverse",
        vid.as_str(),
        "--reason",
        "WrongAmount",
        "--replace-with",
        corrected.as_str(),
        "--evidence",
        &ev,
        "--json",
    ];
    let (code, out, err) = fa(Some(&book), &args);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("corrected"), "{out}");
    assert_eq!(field(&out, "target"), Some(vid.as_str()));
    assert_eq!(field(&out, "reason"), Some("WrongAmount"));
    assert_eq!(field(&out, "already_recorded"), Some("false"));
    assert_eq!(field(&out, "reversal_period"), Some("FY2026-P03"));
    assert_eq!(field(&out, "replacement_period"), Some("FY2026-P03"));
    let reversal = field(&out, "reversal").unwrap().to_string();
    let replacement = field(&out, "replacement").unwrap().to_string();
    let recorded_at = field(&out, "recorded_at").unwrap().to_string();
    assert_ne!(reversal, replacement);

    // Both entries cite the target, one as its reversal, one as its
    // replacement, under the same reason, and both landed at one sequence.
    for (entry, kind) in [(&reversal, "Reverses"), (&replacement, "Replaces")] {
        let (code, shown, err) = fa(Some(&book), &["entry", "show", entry, "--json"]);
        assert_eq!(code, 0, "{shown}\n{err}");
        let shown = doc(&shown);
        let lineage = arr(&shown, "supersedes");
        assert_eq!(lineage.len(), 1, "{entry}");
        assert_eq!(text(&lineage[0], "entry"), vid);
        assert_eq!(text(&lineage[0], "kind"), kind);
        assert_eq!(text(&lineage[0], "reason"), "WrongAmount");
        assert_eq!(
            int(&shown, "recorded_at").map(|n| n.to_string()),
            Some(recorded_at.clone()),
            "{entry}"
        );
    }
    // Only the corrected amount remains in effect.
    let tb = report(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    for (code_, debits, credits) in [
        ("1000", "10.00 USD", "22.00 USD"),
        ("6000", "22.00 USD", "10.00 USD"),
    ] {
        let row = tb
            .split('{')
            .find(|row| field(row, "code") == Some(code_))
            .expect("account row in trial balance");
        assert_eq!(field(row, "debits"), Some(debits), "{tb}");
        assert_eq!(field(row, "credits"), Some(credits), "{tb}");
    }

    // An exact retry writes nothing and names the recorded pair.
    let (code, out, err) = fa(Some(&book), &args);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("corrected"), "{out}");
    assert_eq!(field(&out, "already_recorded"), Some("true"));
    assert_eq!(field(&out, "reversal"), Some(reversal.as_str()));
    assert_eq!(field(&out, "replacement"), Some(replacement.as_str()));
    assert_eq!(field(&out, "replacement_period"), Some("null"));
    assert_eq!(
        report(&book, &["tb", "--period", "FY2026-P03", "--json"]),
        tb
    );

    // A Replacement alone is refused, and the refusal names this command.
    let alone = write(
        &dir,
        "alone.json",
        r#"{"class":"Replacement","effective_date":"2026-03-15","idempotency_key":"alone","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &alone, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-160"), "{out}");
    assert!(out.contains("--replace-with"), "{out}");
    Ok(())
}

/// Plan §4.3, §5.6: an account's life cycle after the chart is installed,
/// each step one journaled SchemaChange. `open` admits legs from its first
/// day. `close` needs a zero balance, then refuses legs on or after its day
/// while the history stays. `promote` turns a leaf into a summary account.
/// An exact retry records nothing new, and no date defaults to today.
#[test]
fn chart_open_close_and_promote_are_journaled_lifecycle_controls() -> std::io::Result<()> {
    let dir = tmp("chart-lifecycle")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Chart Co"]).0,
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
    let post = |key: &str, date: &str, account: &str| -> (i32, String) {
        let intent = write(
            &dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"{date}","description":"{key}","idempotency_key":"{key}","legs":[{{"side":"debit","account":"{account}","amount":"3.00 USD"}},{{"side":"credit","account":"1000","amount":"3.00 USD"}}]}}"#
            ),
        );
        let (code, out, _) = fa(
            Some(&book),
            &["post", "--intent", &intent, "--evidence", &ev, "--json"],
        );
        (code, out)
    };
    let office = write(
        &dir,
        "office.json",
        r#"{"code":"6100","name":"Office supplies","type":"Expense","unit":"USD"}"#,
    );

    // No date defaults to today; a chart is not an account.
    let (code, out, _) = fa(Some(&book), &["chart", "open", &office, "--json"]);
    assert_eq!(code, 2, "{out}");
    let (code, out, _) = fa(
        Some(&book),
        &["chart", "open", &chart, "--opened", "2026-03-01", "--json"],
    );
    assert_eq!(code, 2, "{out}");
    let (code, out) = post("before-open", "2026-03-05", "6100");
    assert_ne!(code, 0, "no account 6100 yet: {out}");

    let open = ["chart", "open", &office, "--opened", "2026-03-01", "--json"];
    let (code, out, err) = fa(Some(&book), &open);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("account_lifecycle"), "{out}");
    assert_eq!(field(&out, "action"), Some("open"));
    assert_eq!(field(&out, "code"), Some("6100"));
    assert_eq!(field(&out, "already_recorded"), Some("false"));
    let control = field(&out, "control_entry").unwrap().to_string();
    let (code, out, _) = fa(Some(&book), &open);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "already_recorded"), Some("true"));
    assert_eq!(field(&out, "control_entry"), Some(control.as_str()));
    let (code, listed, _) = fa(Some(&book), &["chart", "list", "--json"]);
    assert_eq!(code, 0, "{listed}");
    assert!(listed.contains("\"6100\""), "{listed}");
    let (code, out) = post("office-1", "2026-03-05", "6100");
    assert_eq!(code, 0, "{out}");
    let office_1 = field(&out, "vid").unwrap().to_string();

    // An account closes only at a zero balance in every unit (plan §5.6):
    // refused while office-1 stands, admitted once it is reversed. Closing
    // then refuses legs on or after the day.
    let close = ["chart", "close", "6100", "--on", "2026-03-20", "--json"];
    let (code, out, _) = fa(Some(&book), &close);
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("zero balance"), "{out}");
    let (code, out, _) = fa(
        Some(&book),
        &["reverse", &office_1, "--reason", "Duplicate", "--json"],
    );
    assert_eq!(code, 0, "{out}");
    let (code, out, _) = fa(Some(&book), &close);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "action"), Some("close"));
    let (code, out) = post("office-late", "2026-03-25", "6100");
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-002"), "{out}");
    assert!(out.contains("outside its effective interval"), "{out}");
    let (code, out, _) = fa(
        Some(&book),
        &["chart", "close", "9999", "--on", "2026-03-20", "--json"],
    );
    assert_eq!(code, 2, "{out}");

    // Promotion makes the leaf a summary: it takes no legs from that day.
    let (code, out, _) = fa(
        Some(&book),
        &["chart", "promote", "6000", "--on", "2026-03-01", "--json"],
    );
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "action"), Some("promote"));
    let (code, out) = post("rent-after", "2026-03-15", "6000");
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-002"), "{out}");
    Ok(())
}

/// fa-formats on the product surface (plan §8.6, §15.9): `fa export` writes
/// the trial balance's selection in every interop format. Each export
/// re-imports through fa-formats' own reader (to the same content digest
/// where formats.toml promises identity), its legs refold to `fa tb`, a
/// pending hold is not posted activity, and an --out path is never reused.
#[test]
fn export_writes_the_trial_balance_selection_in_every_interop_format() -> std::io::Result<()> {
    let dir = tmp("export")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Export Co"]).0,
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
    for (key, date, amount) in [
        ("rent-1", "2026-03-15", "10.00"),
        ("rent-2", "2026-03-20", "2.50"),
    ] {
        let intent = write(
            &dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"{date}","description":"rent {key}","idempotency_key":"{key}","legs":[{{"side":"debit","account":"6000","amount":"{amount} USD"}},{{"side":"credit","account":"1000","amount":"{amount} USD"}}]}}"#
            ),
        );
        let (code, out, _) = fa(
            Some(&book),
            &["post", "--intent", &intent, "--evidence", &ev, "--json"],
        );
        assert_eq!(code, 0, "{out}");
    }
    let hold = write(
        &dir,
        "hold.json",
        r#"{"effective_date":"2026-03-10","description":"PO hold","idempotency_key":"hold-1","legs":[{"side":"debit","account":"6000","amount":"80.00 USD"},{"side":"credit","account":"1000","amount":"80.00 USD"}]}"#,
    );
    let (code, out, _) = fa(
        Some(&book),
        &["reserve", "--intent", &hold, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 0, "{out}");

    // One selection, every format: the inline content re-imports through
    // fa-formats' own reader to the export's content digest.
    let units = fa_formats::UnitCatalog::embedded().expect("embedded units");
    let mut digests = BTreeSet::new();
    for format in ["ads", "saft", "csv-gl", "beancount", "hledger"] {
        let (code, out, err) = fa(
            Some(&book),
            &["export", format, "--period", "FY2026-P03", "--json"],
        );
        assert_eq!(code, 0, "{format}: {out}\n{err}");
        assert_eq!(field(&out, "event"), Some("journal_exported"), "{out}");
        let exported = doc(&out);
        let data = &exported;
        assert_eq!(text(data, "format"), format);
        assert_eq!(text(data, "effective_through"), "2026-03-31");
        assert_eq!(
            int(data, "entries"),
            Some(2),
            "the hold is not posted: {out}"
        );
        assert_eq!(int(data, "accounts"), Some(2));
        let content_digest = text(data, "content_digest").to_string();
        digests.insert(content_digest.clone());
        let files = arr(data, "files");
        let content = |name: &str| -> String {
            files
                .iter()
                .find(|f| text(f, "name") == name)
                .map(|f| text(f, "content").to_string())
                .unwrap_or_else(|| panic!("{format}: no file {name} in {out}"))
        };
        let reimported = match format {
            "ads" => {
                assert_eq!(files.len(), 4, "{out}");
                fa_formats::ads::read_ads_package(
                    &fa_formats::ads::AdsPackage {
                        chart_of_accounts: content("Chart_of_Accounts.txt"),
                        gl_detail: content("GL_Detail.txt"),
                        trial_balance: content("Trial_Balance.txt"),
                        certificate_toml: content("ADS_Coordinate_Certificate.toml"),
                    },
                    &units,
                )
            }
            "saft" => fa_formats::saft::read_saft_xml(&content("SAF-T.xml"), &units),
            "csv-gl" => fa_formats::csv_gl::read_csv_gl(&content("gl.csv"), &units),
            "beancount" => {
                fa_formats::beancount::read_beancount(&content("journal.beancount"), &units)
            }
            _ => fa_formats::beancount::read_hledger(&content("journal.hledger"), &units),
        }
        .unwrap_or_else(|e| panic!("{format} re-import: {e}"));
        // registries/formats.toml promises export→import identity for the
        // audit standards and the CSV extract; Beancount and hledger are
        // balance-differential formats, checked by the refold below.
        if matches!(format, "ads" | "saft" | "csv-gl") {
            assert_eq!(
                hex_of(&reimported.coordinate.content_digest),
                content_digest,
                "{format}: export→import identity"
            );
        }
        // The exported legs refold to the trial balance: 12.50 of rent
        // paid, and nothing of the 80.00 hold.
        let mut debits = 0i128;
        let mut credits = 0i128;
        for entry in &reimported.entries {
            for leg in &entry.legs {
                match (leg.account_code.as_str(), leg.side) {
                    ("6000", fa_money::Side::Debit) => debits += leg.amount.mantissa,
                    ("1000", fa_money::Side::Credit) => credits += leg.amount.mantissa,
                    other => panic!("{format}: unexpected leg {other:?}"),
                }
            }
        }
        assert_eq!((debits, credits), (1250, 1250), "{format}");
    }
    // The NDJSON GL stream has no reader: its own verifier checks the
    // header, one row per exported leg, and the footer's count; a
    // truncated stream (no footer) is refused.
    let (code, out, err) = fa(
        Some(&book),
        &["export", "ndjson", "--period", "FY2026-P03", "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let exported = doc(&out);
    digests.insert(text(&exported, "content_digest").to_string());
    let stream = arr(&exported, "files")
        .iter()
        .find(|f| text(f, "name") == "gl.ndjson")
        .map(|f| text(f, "content").to_string())
        .unwrap_or_else(|| panic!("no gl.ndjson in {out}"));
    assert_eq!(
        fa_formats::csv_gl::verify_ndjson_gl_stream(&stream).ok(),
        Some(4)
    );
    // The header carries what the certificate binds, so the certificate
    // digest is recomputed from the stream alone.
    let header = json::parse(stream.lines().next().unwrap_or_default()).unwrap_or(Json::Null);
    let hex32 = |key: &str| -> [u8; 32] {
        let h = text(&header, key);
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(h.get(2 * i..2 * i + 2).unwrap_or("zz"), 16).unwrap_or(0);
        }
        out
    };
    let int_of = |key: &str| {
        int(&header, key)
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(0)
    };
    let recomputed = fa_formats::ExportCoordinate::compute(
        text(&header, "book_name"),
        text(&header, "base_unit"),
        u8::try_from(int_of("base_unit_scale")).unwrap_or(0),
        fa_time::DateDay::parse(text(&header, "effective_through")).expect("a date"),
        int_of("known_at_seq"),
        int_of("entry_count"),
        hex32("content_digest"),
    );
    assert_eq!(
        recomputed.certificate_digest,
        hex32("certificate_digest"),
        "{stream}"
    );
    assert_eq!(
        text(&header, "content_digest"),
        text(&exported, "content_digest")
    );
    let first_row = json::parse(stream.lines().nth(1).unwrap_or_default()).unwrap_or(Json::Null);
    assert!(int(&first_row, "entry_class").is_some(), "{stream}");
    let truncated: String = stream
        .lines()
        .filter(|l| !l.contains("gl_stream_footer"))
        .map(|l| format!("{l}\n"))
        .collect();
    assert!(fa_formats::csv_gl::verify_ndjson_gl_stream(&truncated).is_err());
    assert_eq!(digests.len(), 1, "every format exports one selection");
    let tb = report(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    let rent = tb
        .split('{')
        .find(|row| field(row, "code") == Some("6000"))
        .expect("rent row");
    assert_eq!(field(rent, "debits"), Some("12.50 USD"), "{tb}");

    // --out writes new files (a new directory for ads) and never reuses a path.
    let package = dir.join("ads-out").display().to_string();
    let (code, out, err) = fa(
        Some(&book),
        &[
            "export",
            "ads",
            "--as-of",
            "2026-03-31",
            "--out",
            &package,
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    for name in [
        "Chart_of_Accounts.txt",
        "GL_Detail.txt",
        "Trial_Balance.txt",
        "ADS_Coordinate_Certificate.toml",
    ] {
        assert!(dir.join("ads-out").join(name).is_file(), "{name}");
    }
    assert!(
        !out.contains("GL_Account_Number|"),
        "content stays on disk: {out}"
    );
    let (code, out, _) = fa(
        Some(&book),
        &[
            "export",
            "ads",
            "--as-of",
            "2026-03-31",
            "--out",
            &package,
            "--json",
        ],
    );
    assert_eq!(code, 2, "{out}");
    let csv = dir.join("gl.csv").display().to_string();
    let (code, out, _) = fa(
        Some(&book),
        &[
            "export",
            "csv-gl",
            "--period",
            "FY2026-P03",
            "--out",
            &csv,
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let (code, out, _) = fa(
        Some(&book),
        &[
            "export",
            "csv-gl",
            "--period",
            "FY2026-P03",
            "--out",
            &csv,
            "--json",
        ],
    );
    assert_eq!(code, 2, "{out}");

    // Usage: one format, and exactly one of --period / --as-of.
    for args in [
        vec!["export", "pdf", "--period", "FY2026-P03", "--json"],
        vec!["export", "ads", "--json"],
        vec![
            "export",
            "ads",
            "--period",
            "FY2026-P03",
            "--as-of",
            "2026-03-31",
            "--json",
        ],
        vec!["export", "ads", "--period", "FY2099-P01", "--json"],
    ] {
        let (code, out, _) = fa(Some(&book), &args);
        assert_eq!(code, 2, "{args:?}: {out}");
    }
    Ok(())
}

fn hex_of(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Plan §7.4 `AS ORIGINALLY REPORTED`: a period's reads pin to its first
/// Lock (no StatementIssuance is journaled yet), never its first Close and
/// never HEAD. A period with no Lock refuses (FA-REF-161) rather than
/// silently answering as currently stated.
#[test]
fn tb_as_originally_reported_pins_the_first_lock_never_the_close() -> std::io::Result<()> {
    let dir = tmp("originally-reported")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Report Co"]).0,
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
    let march = "FY2026-P03";
    assert_eq!(fa(Some(&book), &["period", "open", march]).0, 0);
    assert_eq!(fa(Some(&book), &["period", "open", "FY2026-P04"]).0, 0);
    let ev = source_doc(&dir, &book);
    let intent = write(
        &dir,
        "entry.json",
        r#"{"effective_date":"2026-03-15","description":"rent","idempotency_key":"rent-1","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}]}"#,
    );
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &intent, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 0, "{out}");
    let originally = [
        "tb",
        "--period",
        march,
        "--as-originally-reported",
        "--json",
    ];

    // Usage errors: the switch fixes known-at itself and reads one period.
    for args in [
        vec![
            "tb",
            "--period",
            march,
            "--as-originally-reported",
            "--as-known-at",
            "HEAD",
            "--json",
        ],
        vec![
            "tb",
            "--period",
            march,
            "--period",
            "FY2026-P04",
            "--as-originally-reported",
            "--json",
        ],
        vec![
            "statement",
            "balance-sheet",
            "--for",
            march,
            "--as-originally-reported",
            "--known-at",
            "HEAD",
            "--json",
        ],
        vec![
            "statement",
            "diff",
            "--definition",
            "balance-sheet",
            "--for",
            march,
            "--before",
            "1",
            "--as-originally-reported",
            "--json",
        ],
        vec![
            "explain",
            "balance",
            "6000",
            "--period",
            march,
            "--as-originally-reported",
            "--as-known-at",
            "HEAD",
            "--json",
        ],
        // Balance-only switches are refused, never ignored, elsewhere.
        vec![
            "explain",
            "register",
            "6000",
            "--period",
            march,
            "--as-originally-reported",
            "--json",
        ],
        vec![
            "explain",
            "register",
            "6000",
            "--period",
            march,
            "--certify",
            "--json",
        ],
    ] {
        let (code, out, err) = fa(Some(&book), &args);
        assert_eq!(code, 2, "{args:?}\n{out}\n{err}");
    }
    let statement = [
        "statement",
        "income-statement",
        "--for",
        march,
        "--compare",
        "FY2026-P04",
        "--as-originally-reported",
        "--json",
    ];
    let explained = [
        "explain",
        "balance",
        "6000",
        "--period",
        march,
        "--as-originally-reported",
        "--json",
    ];
    // Open, then Closed: nothing was reported yet; never HEAD, never a Close.
    let (code, out, _) = fa(Some(&book), &originally);
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-161"), "{out}");
    assert!(out.contains("fa period lock FY2026-P03"), "{out}");
    for args in [&statement[..], &explained[..]] {
        let (code, out, _) = fa(Some(&book), args);
        assert_eq!(code, 3, "{args:?}\n{out}");
        assert_eq!(field(&out, "refusal_id"), Some("FA-REF-161"), "{out}");
    }
    let (code, out, _) = fa(
        Some(&book),
        &[
            "period",
            "close",
            march,
            "--reason",
            "Scheduled",
            "--yes",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let closed_at = field(&out, "recorded_at").unwrap().to_string();
    let (code, out, _) = fa(Some(&book), &originally);
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-161"), "{out}");

    // Lock under a second principal's approval.
    let plan = dir.join("lock.plan").display().to_string();
    let (code, out, _) = fa(
        Some(&book),
        &[
            "period",
            "lock",
            march,
            "--reason",
            "Scheduled",
            "--plan-out",
            &plan,
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let digest = field(&out, "proposal_digest").unwrap().to_string();
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
    let approval = field(&out, "approval_vid").unwrap().to_string();
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
    let locked_at = field(&out, "recorded_at").unwrap().to_string();
    assert_ne!(locked_at, closed_at);

    // Later activity elsewhere moves HEAD, not the reported coordinate.
    let april = write(
        &dir,
        "april.json",
        r#"{"effective_date":"2026-04-15","description":"rent","idempotency_key":"rent-4","legs":[{"side":"debit","account":"6000","amount":"7.00 USD"},{"side":"credit","account":"1000","amount":"7.00 USD"}]}"#,
    );
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &april, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 0, "{out}");
    let reported = report(&book, &originally);
    assert_eq!(field(&reported, "known_at"), Some(locked_at.as_str()));
    let current = report(&book, &["tb", "--period", march, "--json"]);
    assert_ne!(field(&current, "known_at"), Some(locked_at.as_str()));
    // The same period read explicitly at the lock is the same report.
    assert_eq!(
        report(
            &book,
            &[
                "tb",
                "--period",
                march,
                "--as-known-at",
                &locked_at,
                "--json"
            ]
        ),
        reported
    );

    // The statement and the balance explanation pin the same coordinate.
    // The April comparative is read at that snapshot too, so April's later
    // rent is absent as originally reported and present as currently stated.
    let pinned = |args: &[&str]| {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "{args:?}\n{out}\n{err}");
        assert_eq!(field(&out, "known_at"), Some(locked_at.as_str()), "{out}");
        out
    };
    let as_reported = pinned(&statement);
    assert!(!as_reported.contains("7.00 USD"), "{as_reported}");
    let mut at_lock = statement.to_vec();
    at_lock.retain(|arg| *arg != "--as-originally-reported");
    at_lock.splice(at_lock.len() - 1.., ["--known-at", &locked_at, "--json"]);
    assert_eq!(pinned(&at_lock), as_reported);
    at_lock.truncate(at_lock.len() - 3);
    at_lock.push("--json");
    let (code, current, _) = fa(Some(&book), &at_lock);
    assert_eq!(code, 0, "{current}");
    assert!(current.contains("7.00 USD"), "{current}");
    assert_eq!(
        pinned(&explained),
        pinned(&[
            "explain",
            "balance",
            "6000",
            "--period",
            march,
            "--as-known-at",
            &locked_at,
            "--json",
        ])
    );
    // A certified originally-reported statement replays at the pinned prefix.
    let certificate = dir.join("originally.cert").display().to_string();
    let mut certified = statement.to_vec();
    certified.splice(
        certified.len() - 1..,
        ["--certificate-out", &certificate, "--json"],
    );
    pinned(&certified);
    let (code, replayed, err) = fa(Some(&book), &["replay", &certificate, "--json"]);
    assert_eq!(code, 0, "{replayed}\n{err}");
    assert_eq!(field(&replayed, "event"), Some("statement"), "{replayed}");
    assert_eq!(
        field(&replayed, "known_at"),
        Some(locked_at.as_str()),
        "{replayed}"
    );
    Ok(())
}

/// fa-wrrw (plan §7.4, §12.5): `fa statement issue` journals a period's
/// StatementIssuance in two hands: the preparer plans it (`--dry-run`),
/// another principal approves the plan's digest, and the preparer commits
/// exactly that plan. From then on `--as-originally-reported` reads the
/// issued certificate's known-at, ahead of the period's later Lock, and a
/// second issuance never moves it.
#[test]
fn statement_issue_pins_as_originally_reported_to_the_issued_certificate() -> std::io::Result<()> {
    let dir = tmp("statement-issue")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Issuer Co"]).0,
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
    let march = "FY2026-P03";
    assert_eq!(fa(Some(&book), &["period", "open", march]).0, 0);
    let ev = source_doc(&dir, &book);
    let post = |key: &str, amount: &str| {
        let intent = write(
            &dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"2026-03-15","description":"rent","idempotency_key":"{key}","legs":[{{"side":"debit","account":"6000","amount":"{amount} USD"}},{{"side":"credit","account":"1000","amount":"{amount} USD"}}]}}"#
            ),
        );
        let (code, out, _) = fa(
            Some(&book),
            &["post", "--intent", &intent, "--evidence", &ev, "--json"],
        );
        assert_eq!(code, 0, "{out}");
    };
    post("rent-1", "10.00");
    let (code, out, _) = fa(
        Some(&book),
        &[
            "statement",
            "income-statement",
            "--for",
            march,
            "--certify",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let issued_oid = field(&out, "oid").unwrap_or_default().to_string();
    let certified_at = field(&out, "known_at").unwrap_or_default().to_string();
    // A later March posting, then the period's Lock: without an issuance,
    // as originally reported reads the Lock, which includes it.
    post("rent-2", "5.00");
    let (code, out, _) = fa(
        Some(&book),
        &["period", "close", march, "--reason", "Scheduled", "--yes"],
    );
    assert_eq!(code, 0, "{out}");
    let lock_plan = dir.join("lock.plan").display().to_string();
    let (code, out, _) = fa(
        Some(&book),
        &[
            "period",
            "lock",
            march,
            "--reason",
            "Scheduled",
            "--plan-out",
            &lock_plan,
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let digest = field(&out, "proposal_digest")
        .unwrap_or_default()
        .to_string();
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
    let approval = field(&out, "approval_vid").unwrap_or_default().to_string();
    assert_eq!(
        fa(
            Some(&book),
            &[
                "period",
                "lock",
                march,
                "--plan",
                &lock_plan,
                "--approval",
                &approval
            ]
        )
        .0,
        0
    );
    let originally = [
        "tb",
        "--period",
        march,
        "--as-originally-reported",
        "--json",
    ];
    let (code, at_lock, _) = fa(Some(&book), &originally);
    assert_eq!(code, 0, "{at_lock}");
    assert_ne!(field(&at_lock, "known_at"), Some(certified_at.as_str()));
    assert!(at_lock.contains("15.00 USD"), "{at_lock}");

    // Refused before anything is planned or written.
    let (code, out, _) = fa(
        Some(&book),
        &["tb", "--period", march, "--certify", "--json"],
    );
    assert_eq!(code, 0, "{out}");
    let tb_oid = field(&out, "oid").unwrap_or_default().to_string();
    let plan_args = |oid: &str| {
        vec![
            "statement".to_string(),
            "issue".into(),
            "--certificate".into(),
            format!("C:{oid}"),
            "--issued-to".into(),
            "auditor".into(),
            "--dry-run".into(),
            "--json".into(),
        ]
    };
    let run = |args: &[String]| {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        fa(Some(&book), &args)
    };
    let (code, out, _) = run(&plan_args(&tb_oid));
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-172"), "{out}");
    for bad in [
        vec!["statement", "issue", "--json"],
        vec![
            "statement",
            "issue",
            "--certificate",
            &issued_oid,
            "--issued-to",
            "shareholders",
            "--dry-run",
            "--json",
        ],
        vec![
            "statement",
            "issue",
            "--certificate",
            &issued_oid,
            "--issued-to",
            "auditor",
            "--dry-run",
            "--approval",
            &approval,
            "--json",
        ],
        vec![
            "statement",
            "issue",
            "--plan",
            &lock_plan,
            "--for",
            march,
            "--json",
        ],
        // Each statement command refuses the other's flags, never ignores them.
        vec![
            "statement",
            "issue",
            "--certificate",
            &issued_oid,
            "--issued-to",
            "auditor",
            "--compare",
            "FY2026-P02",
            "--dry-run",
            "--json",
        ],
        vec!["statement", "issuances", "--certify", "--json"],
        vec!["statement", "issuances", "--issued-to", "auditor", "--json"],
        vec![
            "statement",
            "income-statement",
            "--for",
            march,
            "--dry-run",
            "--json",
        ],
        vec![
            "statement",
            "income-statement",
            "--for",
            march,
            "--issued-to",
            "auditor",
            "--json",
        ],
    ] {
        let (code, out, err) = fa(Some(&book), &bad);
        assert_eq!(code, 2, "{bad:?}\n{out}\n{err}");
    }

    // Plan, approve in another hand, commit the exact plan.
    let (code, out, _) = run(&plan_args(&issued_oid));
    assert_eq!(code, 0, "{out}");
    let planned = doc(&out);
    let issuance = planned.get("issuance").cloned().unwrap_or(Json::Null);
    assert_eq!(int(&issuance, "ordinal"), Some(1), "{out}");
    assert_eq!(text(&issuance, "period"), march);
    assert_eq!(text(&issuance, "certificate"), issued_oid);
    assert_eq!(
        int(&issuance, "certified_at").map(|n| n.to_string()),
        Some(certified_at.clone())
    );
    assert_eq!(issuance.get("recorded_at"), Some(&Json::Null));
    let plan = write(&dir, "issue.plan", text(&planned, "bytes"));
    let digest = text(&planned, "proposal_digest").to_string();
    let (code, out, _) = fa(
        Some(&book),
        &["statement", "issue", "--plan", &plan, "--json"],
    );
    assert_eq!(code, 7, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-012"), "{out}");
    let (code, out, _) = fa(Some(&book), &["approve", "--proposal", &digest, "--json"]);
    assert_eq!(code, 0, "{out}");
    let own = field(&out, "approval_vid").unwrap_or_default().to_string();
    let (code, out, _) = fa(
        Some(&book),
        &[
            "statement",
            "issue",
            "--plan",
            &plan,
            "--approval",
            &own,
            "--json",
        ],
    );
    assert_eq!(code, 7, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-008"), "{out}");
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
    let approval = field(&out, "approval_vid").unwrap_or_default().to_string();
    let commit = [
        "statement",
        "issue",
        "--plan",
        &plan,
        "--approval",
        &approval,
        "--json",
    ];
    let (code, out, _) = fa(Some(&book), &commit);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "event"), Some("statement_issued"), "{out}");
    assert_eq!(field(&out, "already_recorded"), Some("false"), "{out}");
    let (code, out, _) = fa(Some(&book), &commit);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "already_recorded"), Some("true"), "{out}");

    // As originally reported is now the issued certificate's coordinate,
    // ahead of the Lock: rent-2 is absent, and the read is byte-identical to
    // the same read at that known-at.
    let (code, reported, _) = fa(Some(&book), &originally);
    assert_eq!(code, 0, "{reported}");
    assert_eq!(
        field(&reported, "known_at"),
        Some(certified_at.as_str()),
        "{reported}"
    );
    assert!(!reported.contains("15.00 USD"), "{reported}");
    let (code, at_certificate, _) = fa(
        Some(&book),
        &[
            "tb",
            "--period",
            march,
            "--as-known-at",
            &certified_at,
            "--json",
        ],
    );
    assert_eq!(code, 0, "{at_certificate}");
    assert_eq!(reported, at_certificate);

    // The restated statements (rent-2 included), issued to the lender, are
    // the period's second issuance; the pin stays on the first.
    let (code, out, _) = fa(
        Some(&book),
        &[
            "statement",
            "income-statement",
            "--for",
            march,
            "--certify",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let restated_oid = field(&out, "oid").unwrap_or_default().to_string();
    let restated_at = field(&out, "known_at").unwrap_or_default().to_string();
    assert_ne!(restated_at, certified_at);
    let mut lender = plan_args(&restated_oid);
    lender[5] = "lender".into();
    let (code, out, _) = run(&lender);
    assert_eq!(code, 0, "{out}");
    let planned = doc(&out);
    let second = planned.get("issuance").cloned().unwrap_or(Json::Null);
    assert_eq!(int(&second, "ordinal"), Some(2), "{out}");
    let plan2 = write(&dir, "issue2.plan", text(&planned, "bytes"));
    let digest = text(&planned, "proposal_digest").to_string();
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
    let approval = field(&out, "approval_vid").unwrap_or_default().to_string();
    let (code, out, _) = fa(
        Some(&book),
        &[
            "statement",
            "issue",
            "--plan",
            &plan2,
            "--approval",
            &approval,
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let (code, out, _) = fa(Some(&book), &originally);
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        field(&out, "known_at"),
        Some(certified_at.as_str()),
        "{out}"
    );
    let (code, out, _) = fa(
        Some(&book),
        &["statement", "issuances", "--for", march, "--json"],
    );
    assert_eq!(code, 0, "{out}");
    let listed = doc(&out);
    let rows = arr(&listed, "issuances");
    assert_eq!(
        rows.iter()
            .map(|r| (int(r, "ordinal"), text(r, "issued_to"), int(r, "approvals")))
            .collect::<Vec<_>>(),
        [(Some(1), "auditor", Some(1)), (Some(2), "lender", Some(1))]
    );

    // AS ISSUED TO and AS REPORTED IN pin the coordinate the issued or
    // named certificate reported, on tb, statement and explain balance.
    let view = |args: &[&str], at: &str, rent: &str| {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "{args:?}\n{out}\n{err}");
        assert_eq!(field(&out, "known_at"), Some(at), "{args:?}\n{out}");
        assert!(out.contains(rent), "{args:?}\n{out}");
        out
    };
    let restated_ref = format!("C:{restated_oid}");
    let issued_ref = format!("C:{issued_oid}");
    view(
        &[
            "tb",
            "--period",
            march,
            "--as-issued-to",
            "auditor",
            "--json",
        ],
        &certified_at,
        "10.00 USD",
    );
    let to_lender = view(
        &[
            "tb",
            "--period",
            march,
            "--as-issued-to",
            "lender",
            "--json",
        ],
        &restated_at,
        "15.00 USD",
    );
    let (code, at_restated, _) = fa(
        Some(&book),
        &[
            "tb",
            "--period",
            march,
            "--as-known-at",
            &restated_at,
            "--json",
        ],
    );
    assert_eq!(code, 0, "{at_restated}");
    assert_eq!(
        to_lender, at_restated,
        "byte-identical to the same known-at"
    );
    view(
        &[
            "statement",
            "income-statement",
            "--for",
            march,
            "--as-reported-in",
            &restated_ref,
            "--json",
        ],
        &restated_at,
        "15.00 USD",
    );
    view(
        &[
            "explain",
            "balance",
            "6000",
            "--period",
            march,
            "--as-reported-in",
            &issued_ref,
            "--json",
        ],
        &certified_at,
        "10.00 USD",
    );
    let tb_ref = format!("C:{tb_oid}");
    for (args, refusal) in [
        (
            vec!["tb", "--period", march, "--as-issued-to", "board", "--json"],
            "FA-REF-173",
        ),
        (
            vec![
                "tb",
                "--period",
                "FY2026-P04",
                "--as-reported-in",
                &issued_ref,
                "--json",
            ],
            "FA-REF-174",
        ),
        (
            vec![
                "tb",
                "--period",
                march,
                "--as-reported-in",
                &tb_ref,
                "--json",
            ],
            "FA-REF-174",
        ),
    ] {
        let (code, out, _) = fa(Some(&book), &args);
        assert_eq!(code, 3, "{args:?}\n{out}");
        assert_eq!(field(&out, "refusal_id"), Some(refusal), "{args:?}\n{out}");
    }
    for args in [
        vec![
            "tb",
            "--period",
            march,
            "--as-issued-to",
            "auditor",
            "--as-originally-reported",
            "--json",
        ],
        vec![
            "tb",
            "--period",
            march,
            "--as-reported-in",
            &issued_ref,
            "--as-known-at",
            "HEAD",
            "--json",
        ],
        vec![
            "tb",
            "--period",
            march,
            "--as-issued-to",
            "shareholders",
            "--json",
        ],
        vec![
            "explain",
            "register",
            "6000",
            "--period",
            march,
            "--as-issued-to",
            "auditor",
            "--json",
        ],
        vec![
            "statement",
            "diff",
            "--definition",
            "income-statement",
            "--for",
            march,
            "--before",
            "1",
            "--as-reported-in",
            &issued_ref,
            "--json",
        ],
        vec![
            "statement",
            "issue",
            "--certificate",
            &issued_oid,
            "--issued-to",
            "auditor",
            "--as-issued-to",
            "auditor",
            "--dry-run",
            "--json",
        ],
    ] {
        let (code, out, err) = fa(Some(&book), &args);
        assert_eq!(code, 2, "{args:?}\n{out}\n{err}");
    }
    Ok(())
}

/// fa-waow (plan §15.3 Proofs): `fa verify book` runs every book-level
/// verify target over a posted book, each emitting its own event, then one
/// green `book_verification` naming each target's pass.
#[test]
fn verify_book_runs_every_verify_target() -> std::io::Result<()> {
    let dir = tmp("verify-book")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    ok(&["book", "create", "--name", "Verify Co", "--json"]);
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
        r#"{"effective_date":"2026-03-16","idempotency_key":"rent","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    ok(&["post", "--intent", &rent, "--evidence", &evidence, "--json"]);
    // A register cache never advanced differs from its refold (fa-q2z):
    // advance March's so the registers target can pass.
    ok(&["registers", "advance", "--period", "FY2026-P03", "--json"]);
    let out = ok(&["verify", "book", "--json"]);
    for event in [
        "projections_verified",
        "periods_verified",
        "schedules_verified",
        "accumulator_verified",
        "open_items_verified",
        "availability_verified",
        "usage_verified",
        "entities_verified",
        "registers_verified",
        "replay_verified",
        "book_verification",
    ] {
        assert!(
            out.contains(&format!("\"event\":\"{event}\"")),
            "{event}: {out}"
        );
    }
    let verdict = doc(&out);
    assert_eq!(verdict.get("green"), Some(&Json::Bool(true)), "{out}");
    let targets = arr(&verdict, "targets");
    assert_eq!(targets.len(), 10, "{out}");
    assert!(
        targets.iter().all(|t| text(t, "verdict") == "pass"),
        "{out}"
    );
    let (code, out, _) = fa(
        Some(&book),
        &["verify", "book", "--fiscal-year", "2026", "--json"],
    );
    assert_eq!(code, 2, "{out}");
    Ok(())
}

/// fa-75j4 slice 4b: a Revision case corrects a Closed period from the CLI.
/// - The analyst plans the Revision in the case's scenario: `revises` names
///   the posting and the legs are the delta. Without restate the rehearsal is
///   refused by the period law (exit 7).
/// - Two Humans who planned nothing approve the manifest. `fa case post`
///   posts the Revision into the closed March, whose trial balance moves by
///   the delta, and lineage names Revises.
/// - The same intent posted outside the case is refused (FA-REF-178).
#[test]
fn a_revision_case_corrects_a_closed_period_from_the_cli() -> std::io::Result<()> {
    let dir = tmp("revision")?;
    let book = dir.join("book");
    let run = |args: &[&str]| -> (i32, String) {
        let (code, out, err) = fa(Some(&book), args);
        (code, format!("{out}{err}"))
    };
    let ok = |args: &[&str]| -> String {
        let (code, out) = run(args);
        assert_eq!(code, 0, "args={args:?}\n{out}");
        out
    };
    ok(&["book", "create", "--name", "Revision Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6100","name":"Office expense","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let evidence = source_doc(&dir, &book);
    let expense = write(
        &dir,
        "expense.json",
        r#"{"effective_date":"2026-03-16","idempotency_key":"exp","legs":[{"side":"debit","account":"6100","amount":"1000.00 USD"},{"side":"credit","account":"1000","amount":"1000.00 USD"}]}"#,
    );
    let out = ok(&[
        "post",
        "--intent",
        &expense,
        "--evidence",
        &evidence,
        "--json",
    ]);
    let target = field(&out, "vid").unwrap_or_default().to_string();
    ok(&[
        "period",
        "close",
        "FY2026-P03",
        "--reason",
        "Scheduled",
        "--yes",
        "--json",
    ]);
    let out = ok(&[
        "case",
        "open",
        "--kind",
        "Revision",
        "--periods",
        "FY2026-P03",
        "--determined-on",
        "2026-04-02",
        "--authority",
        &evidence,
        "--json",
    ]);
    let opened = doc(&out).get("case").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&opened, "state"), "Determined", "{out}");
    ok(&["scenario", "fork", "revised", "--as", "analyst", "--json"]);
    let revision = write(
        &dir,
        "revision.json",
        &format!(
            r#"{{"class":"Revision","revises":"{target}","reason":"WrongAmount","idempotency_key":"rev","legs":[{{"side":"debit","account":"6100","amount":"20.00 USD"}},{{"side":"credit","account":"1000","amount":"20.00 USD"}}]}}"#
        ),
    );
    let (code, out) = run(&[
        "scenario", "run", "revised", "--intent", &revision, "--as", "analyst", "--json",
    ]);
    assert_eq!(
        code, 7,
        "a Revision in a Closed period needs restate: {out}"
    );
    ok(&[
        "scenario", "run", "revised", "--intent", &revision, "--as", "analyst", "--grant",
        "restate", "--json",
    ]);
    let rehearsal = dir.join("rehearsal.cert").display().to_string();
    ok(&[
        "scenario",
        "diff",
        "revised",
        "--period",
        "FY2026-P03",
        "--certificate-out",
        &rehearsal,
        "--json",
    ]);
    ok(&[
        "case",
        "rehearse",
        "1",
        "--certificate",
        &rehearsal,
        "--json",
    ]);
    let digest = text(
        &doc(&ok(&["case", "approve", "1", "--dry-run", "--json"])),
        "digest",
    )
    .to_string();
    let approve = |who: &str| {
        text(
            &doc(&ok(&[
                "approve",
                "--proposal",
                &digest,
                "--as",
                who,
                "--json",
            ])),
            "approval_vid",
        )
        .to_string()
    };
    let (controller, auditor) = (approve("controller"), approve("auditor"));
    ok(&[
        "case",
        "approve",
        "1",
        "--approval",
        &controller,
        "--approval",
        &auditor,
        "--json",
    ]);
    let out = ok(&["case", "post", "1", "--json"]);
    let case = doc(&out).get("case").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&case, "state"), "Posted", "{out}");
    let entry = text(&arr(&case, "posted")[0], "entry").to_string();
    let explained = ok(&["explain", "entry", &entry, "--json"]);
    assert!(explained.contains("Revision"), "{explained}");
    let lineage = ok(&["explain", "lineage", &target, "--json"]);
    assert!(lineage.contains(&entry), "{lineage}");
    assert!(lineage.contains("Revises"), "{lineage}");
    let tb = ok(&["tb", "--period", "FY2026-P03", "--json"]);
    assert!(
        tb.contains("1020.00 USD"),
        "the closed March moves by the delta: {tb}"
    );
    // Outside its case a Revision is refused, even confirmed and with restate.
    let (code, out) = run(&[
        "post", "--intent", &revision, "--grant", "restate", "--yes", "--json",
    ]);
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("FA-REF-178"), "{out}");
    Ok(())
}

/// fa-xvba: `fa reclass` moves part of an entry's leg to another account
/// with the leg's side; the trial balance moves exactly, lineage names the
/// reclassification, a move beyond what remains is FA-REF-185, and a Closed
/// period needs post_closed (exit 7 without it).
#[test]
fn reclass_closed_period_requires_post_closed() -> std::io::Result<()> {
    let dir = tmp("reclass")?;
    let book = dir.join("book");
    let run = |args: &[&str]| -> (i32, String) {
        let (code, out, err) = fa(Some(&book), args);
        (code, format!("{out}{err}"))
    };
    let ok = |args: &[&str]| -> String {
        let (code, out) = run(args);
        assert_eq!(code, 0, "args={args:?}\n{out}");
        out
    };
    ok(&["book", "create", "--name", "Reclass Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6100","name":"Office expense","type":"Expense","unit":"USD"},{"code":"6200","name":"Travel expense","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let evidence = source_doc(&dir, &book);
    let expense = write(
        &dir,
        "expense.json",
        r#"{"effective_date":"2026-03-16","idempotency_key":"exp","legs":[{"side":"debit","account":"6100","amount":"1000.00 USD"},{"side":"credit","account":"1000","amount":"1000.00 USD"}]}"#,
    );
    let out = ok(&[
        "post",
        "--intent",
        &expense,
        "--evidence",
        &evidence,
        "--json",
    ]);
    let target = field(&out, "vid").unwrap_or_default().to_string();
    // The dry run previews the net effect: the target plus this delta.
    let plan = doc(&ok(&[
        "reclass",
        &target,
        "--from",
        "6100",
        "--to",
        "6200",
        "--amount",
        "300.00 USD",
        "--reason",
        "WrongAccount",
        "--dry-run",
        "--json",
    ]));
    let net: Vec<(&str, &str)> = arr(&plan, "net_effect")
        .iter()
        .map(|cell| (text(cell, "account"), text(cell, "net")))
        .collect();
    assert_eq!(
        net,
        [
            ("1000", "-1000.00 USD"),
            ("6100", "700.00 USD"),
            ("6200", "300.00 USD")
        ]
    );
    let out = ok(&[
        "reclass",
        &target,
        "--from",
        "6100",
        "--to",
        "6200",
        "--amount",
        "300.00 USD",
        "--reason",
        "WrongAccount",
        "--json",
    ]);
    assert_eq!(field(&out, "class"), Some("Reclassification"), "{out}");
    let reclass = field(&out, "vid").unwrap_or_default().to_string();
    let tb = ok(&["tb", "--period", "FY2026-P03", "--json"]);
    assert!(
        tb.contains("700.00 USD") && tb.contains("300.00 USD"),
        "{tb}"
    );
    let lineage = ok(&["explain", "lineage", &target, "--json"]);
    assert!(lineage.contains(&reclass), "{lineage}");
    assert!(lineage.contains("Reclassifies"), "{lineage}");
    // The same command records once.
    let out = ok(&[
        "reclass",
        &target,
        "--from",
        "6100",
        "--to",
        "6200",
        "--amount",
        "300.00 USD",
        "--reason",
        "WrongAccount",
        "--json",
    ]);
    assert!(out.contains("\"event\":\"recorded\""), "{out}");
    // 800 more exceeds the 700 left.
    let (code, out) = run(&[
        "reclass",
        &target,
        "--from",
        "6100",
        "--to",
        "6200",
        "--amount",
        "800.00 USD",
        "--reason",
        "WrongAccount",
        "--json",
    ]);
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("FA-REF-185"), "{out}");
    // No reason, an unregistered one: FA-REF-054.
    let (code, out) = run(&[
        "reclass", &target, "--from", "6100", "--to", "6200", "--amount", "1.00 USD", "--reason",
        "Whim", "--json",
    ]);
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("FA-REF-054"), "{out}");
    // Closed: a reclassification dated in the period needs post_closed.
    ok(&[
        "period",
        "close",
        "FY2026-P03",
        "--reason",
        "Scheduled",
        "--yes",
        "--json",
    ]);
    let (code, out) = run(&[
        "reclass",
        &target,
        "--from",
        "6100",
        "--to",
        "6200",
        "--amount",
        "100.00 USD",
        "--reason",
        "WrongAccount",
        "--json",
    ]);
    assert_eq!(code, 7, "{out}");
    assert!(out.contains("post_closed"), "{out}");
    Ok(())
}

/// `fa law list|show` and `fa unit list` (plan §6.2–§6.4, Appendix D): the
/// registered laws and unit versions, without a book.
#[test]
fn law_and_unit_listings_name_every_registered_law_and_unit() {
    let (code, out, _) = fa(None, &["law", "list", "--json"]);
    assert_eq!(code, 0, "{out}");
    let laws = doc(&out);
    let rows = arr(&laws, "laws");
    for (family, name) in [
        ("rounding", "HalfEven"),
        ("allocation", "LargestRemainder"),
        ("fx", "SpotClose"),
    ] {
        assert!(
            rows.iter()
                .any(|r| text(r, "family") == family && text(r, "name") == name),
            "{family} {name}: {out}"
        );
    }
    let families: BTreeSet<&str> = rows.iter().map(|r| text(r, "family")).collect();
    assert_eq!(
        families,
        [
            "allocation",
            "conversion",
            "fx",
            "lot",
            "rounding",
            "tracing"
        ]
        .into_iter()
        .collect()
    );
    let (code, out, _) = fa(None, &["law", "list", "--family", "rounding", "--json"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        arr(&doc(&out), "laws")
            .iter()
            .all(|r| text(r, "family") == "rounding"),
        "{out}"
    );
    let (code, out, _) = fa(None, &["law", "show", "HalfEven", "--json"]);
    assert_eq!(code, 0, "{out}");
    let law = doc(&out).get("law").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&law, "family"), "rounding");
    assert!(
        arr(&law, "attributes")
            .iter()
            .any(|a| text(a, "key") == "definition"),
        "{out}"
    );
    for bad in [
        vec!["law", "show", "NoSuchLaw", "--json"],
        vec!["law", "list", "--family", "tax", "--json"],
        vec!["law", "--json"],
        vec!["unit", "show", "USD", "--json"],
    ] {
        let (code, out, err) = fa(None, &bad);
        assert_eq!(code, 2, "{bad:?}\n{out}\n{err}");
    }
    let (code, out, _) = fa(None, &["unit", "list", "--json"]);
    assert_eq!(code, 0, "{out}");
    let units = doc(&out);
    let usd = arr(&units, "units")
        .iter()
        .find(|u| text(u, "code") == "USD")
        .cloned()
        .unwrap_or(Json::Null);
    assert_eq!(int(&usd, "scale"), Some(2), "{out}");
    assert_eq!(int(&usd, "iso4217"), Some(840), "{out}");
    assert_eq!(text(&usd, "rounding_default"), "HalfEven", "{out}");
}

/// fa-75j4 (plan §8.3): `fa case` journals a restatement case through the
/// real binary: numbered, Proposed, then Determined with its day and
/// authority document; the same command opens it once; every refusal names
/// its code and writes nothing.
#[test]
fn case_open_and_determine_journal_a_restatement_case() -> std::io::Result<()> {
    let dir = tmp("restatement-case")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Case Co"]).0,
        0
    );
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    );
    assert_eq!(fa(Some(&book), &["chart", "import", &chart]).0, 0);
    assert_eq!(
        fa(Some(&book), &["period", "create", "--fiscal-year", "2025"]).0,
        0
    );
    let memo = source_doc(&dir, &book);
    let open = [
        "case",
        "open",
        "--kind",
        "Restatement",
        "--periods",
        "FY2025-P12,FY2025-P11",
        "--narrative",
        &memo,
        "--json",
    ];
    let (code, out, _) = fa(Some(&book), &open);
    assert_eq!(code, 0, "{out}");
    let case = doc(&out).get("case").cloned().unwrap_or(Json::Null);
    assert_eq!(int(&case, "case"), Some(1), "{out}");
    assert_eq!(text(&case, "state"), "Proposed");
    assert_eq!(
        arr(&case, "periods")
            .iter()
            .filter_map(Json::as_str)
            .collect::<Vec<_>>(),
        ["FY2025-P11", "FY2025-P12"]
    );
    let (code, out, _) = fa(Some(&book), &open);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "already_recorded"), Some("true"), "{out}");

    // Refusals, each naming its code: no such case, the wrong state, an
    // unknown period, an unknown kind.
    let determine = |n: &str| {
        vec![
            "case".to_string(),
            "determine".into(),
            n.into(),
            "--on".into(),
            "2026-01-28".into(),
            "--authority".into(),
            memo.clone(),
            "--json".into(),
        ]
    };
    let run = |args: &[String]| {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        fa(Some(&book), &args)
    };
    let (code, out, _) = run(&determine("2"));
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-175"), "{out}");
    let (code, out, _) = run(&determine("1"));
    assert_eq!(code, 0, "{out}");
    let case = doc(&out).get("case").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&case, "state"), "Determined", "{out}");
    let determination = case.get("determination").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&determination, "day"), "2026-01-28");
    assert_eq!(text(&determination, "authority"), memo);
    let (code, out, _) = run(&[
        "case".into(),
        "determine".into(),
        "1".into(),
        "--on".into(),
        "2026-02-03".into(),
        "--authority".into(),
        memo.clone(),
        "--json".into(),
    ]);
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-176"), "{out}");
    let (code, out, _) = fa(
        Some(&book),
        &[
            "case",
            "open",
            "--kind",
            "Restatement",
            "--periods",
            "FY2099-P01",
            "--json",
        ],
    );
    assert_ne!(code, 0, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-021"), "{out}");
    for bad in [
        vec![
            "case",
            "open",
            "--kind",
            "Restated",
            "--periods",
            "FY2025-P12",
            "--json",
        ],
        vec!["case", "open", "--kind", "Restatement", "--json"],
        vec![
            "case",
            "open",
            "--kind",
            "Restatement",
            "--periods",
            "FY2025-P12",
            "--determined-on",
            "2026-01-28",
            "--json",
        ],
        vec!["case", "determine", "one", "--on", "2026-01-28", "--json"],
        vec!["case", "show", "--json"],
    ] {
        let (code, out, err) = fa(Some(&book), &bad);
        assert_eq!(code, 2, "{bad:?}\n{out}\n{err}");
    }

    let (code, out, _) = fa(Some(&book), &["case", "list", "--json"]);
    assert_eq!(code, 0, "{out}");
    let cases = doc(&out);
    let listed = arr(&cases, "cases");
    assert_eq!(listed.len(), 1, "{out}");
    assert_eq!(
        arr(&listed[0], "transitions")
            .iter()
            .map(|t| text(t, "to"))
            .collect::<Vec<_>>(),
        ["Proposed", "Determined"]
    );
    let (code, out, _) = fa(Some(&book), &["case", "show", "1", "--json"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "event"), Some("case"), "{out}");
    let (code, out, _) = fa(Some(&book), &["case", "show", "9", "--json"]);
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-175"), "{out}");
    Ok(())
}

/// `fa sample uniform|mus` (fa-kaf7, fa-vpk): a sample of one account's
/// normal-side open items, reproducible from the declared seed at a recorded
/// sequence; opposite-side open items are excluded and listed, never dropped.
#[test]
fn audit_samples_are_reproducible_from_the_seed_at_a_recorded_sequence() -> std::io::Result<()> {
    let dir = tmp("sample")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Sample Co"]).0,
        0
    );
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1200","name":"Receivables","type":"Asset","unit":"USD"},{"code":"1300","name":"Deposits","type":"Asset","unit":"USD"},{"code":"4000","name":"Sales","type":"Revenue","unit":"USD"}]}"#,
    );
    assert_eq!(fa(Some(&book), &["chart", "import", &chart]).0, 0);
    assert_eq!(
        fa(Some(&book), &["period", "create", "--fiscal-year", "2026"]).0,
        0
    );
    assert_eq!(fa(Some(&book), &["period", "open", "FY2026-P03"]).0, 0);
    let ev = source_doc(&dir, &book);
    let post = |key: &str, debit: &str, credit: &str, amount: &str| {
        let intent = write(
            &dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"2026-03-15","description":"{key}","idempotency_key":"{key}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount} USD"}},{{"side":"credit","account":"{credit}","amount":"{amount} USD"}}]}}"#
            ),
        );
        let (code, out, err) = fa(
            Some(&book),
            &["post", "--intent", &intent, "--evidence", &ev, "--json"],
        );
        assert_eq!(code, 0, "{out}\n{err}");
    };
    for (key, amount) in [
        ("inv-1", "100.00"),
        ("inv-2", "250.00"),
        ("inv-3", "50.00"),
        ("inv-4", "700.00"),
    ] {
        post(key, "1200", "4000", amount);
    }
    // An unapplied customer receipt: a credit open item in a debit-normal
    // account, outside the positive-value population.
    post("receipt-1", "1000", "1200", "30.00");
    let draw = |args: &[&str]| {
        let mut argv = vec!["sample"];
        argv.extend_from_slice(args);
        argv.push("--json");
        let (code, out, err) = fa(Some(&book), &argv);
        assert_eq!(code, 0, "{argv:?}\n{out}\n{err}");
        out
    };
    let uniform = ["uniform", "--account", "1200", "--seed", "7", "--size", "2"];
    let out = draw(&uniform);
    let data = doc(&out);
    assert_eq!(text(&data, "method"), "uniform");
    assert_eq!(text(&data, "unit"), "USD");
    assert_eq!(data.get("population_count"), Some(&Json::Int(4)), "{out}");
    assert_eq!(text(&data, "population_total"), "1100.00 USD");
    assert_eq!(data.get("selected_count"), Some(&Json::Int(2)), "{out}");
    assert_eq!(arr(&data, "selected").len(), 2, "{out}");
    let excluded = arr(&data, "excluded");
    assert_eq!(excluded.len(), 1, "{out}");
    assert_eq!(text(&excluded[0], "side"), "credit");
    assert_eq!(text(&excluded[0], "open"), "30.00 USD");
    // The data's known_at is the envelope coordinate's.
    let first = field(&out, "known_at").unwrap_or_default().to_string();
    assert_eq!(
        data.get("known_at"),
        Some(&Json::Int(first.parse::<i128>().unwrap_or(-1))),
        "{out}"
    );
    // The same seed at the same sequence is the same sample, byte for byte;
    // so is its replay command.
    assert_eq!(draw(&uniform), out);
    let replay = text(&data, "replay_command").to_string();
    let replay: Vec<&str> = replay.split_whitespace().skip(2).collect();
    assert_eq!(draw(&replay), out);
    // Another seed is another sample over the same population.
    let other = doc(&draw(&[
        "uniform",
        "--account",
        "1200",
        "--seed",
        "8",
        "--size",
        "2",
    ]));
    assert_eq!(
        text(&other, "population_digest"),
        text(&data, "population_digest")
    );
    assert_ne!(text(&other, "sample_digest"), text(&data, "sample_digest"));
    // A later invoice joins the population at HEAD, not at the recorded one.
    post("inv-5", "1200", "4000", "400.00");
    let head = doc(&draw(&uniform));
    assert_eq!(head.get("population_count"), Some(&Json::Int(5)));
    let mut pinned = uniform.to_vec();
    pinned.extend(["--as-known-at", first.as_str()]);
    assert_eq!(draw(&pinned), out);

    // MUS: an item at or above the interval is examined in the top stratum.
    let mus = doc(&draw(&[
        "mus",
        "--account",
        "1200",
        "--seed",
        "7",
        "--interval",
        "300.00 USD",
        "--as-known-at",
        first.as_str(),
    ]));
    assert_eq!(text(&mus, "interval"), "300.00 USD");
    assert_eq!(mus.get("top_stratum_count"), Some(&Json::Int(1)));
    let top: Vec<&Json> = arr(&mus, "selected")
        .iter()
        .filter(|row| text(row, "basis") == "top_stratum")
        .collect();
    assert_eq!(top.len(), 1, "{mus:?}");
    assert_eq!(text(top[0], "book_value"), "700.00 USD");
    assert!(
        arr(&mus, "selected")
            .iter()
            .filter(|row| text(row, "basis") == "systematic")
            .all(|row| !text(row, "hit").is_empty()),
        "{mus:?}"
    );

    // Planned from the auditor's inputs (plan §11.12): (1,500.00 - 100.00 x
    // 1.6) / 3.00 = 446.666..., rounded down to 446.66 at 95%. The draw is
    // the stated interval's, reports its inputs, and its replay command
    // restates them.
    let planned = doc(&draw(&[
        "mus",
        "--account",
        "1200",
        "--seed",
        "7",
        "--tolerable",
        "1500.00 USD",
        "--expected",
        "100.00 USD",
        "--confidence",
        "95",
        "--as-known-at",
        first.as_str(),
    ]));
    let stated = doc(&draw(&[
        "mus",
        "--account",
        "1200",
        "--seed",
        "7",
        "--interval",
        "446.66 USD",
        "--as-known-at",
        first.as_str(),
    ]));
    assert_eq!(text(&planned, "interval"), "446.66 USD");
    for key in [
        "population_digest",
        "sample_digest",
        "selected",
        "parameters",
    ] {
        assert_eq!(planned.get(key), stated.get(key), "{key}");
    }
    assert_eq!(text(&planned, "tolerable"), "1500.00 USD");
    assert_eq!(text(&planned, "expected"), "100.00 USD");
    assert_eq!(planned.get("confidence_percent"), Some(&Json::Int(95)));
    assert_eq!(stated.get("tolerable"), Some(&Json::Null));
    let replay = text(&planned, "replay_command");
    assert!(
        replay.contains(r#"--tolerable "1500.00 USD" --expected "100.00 USD" --confidence 95"#),
        "{replay}"
    );
    // Evaluating the planned sample plans the same interval: every item at
    // its book value leaves the basic precision, 446.66 x 3.00.
    let clean: Vec<String> = arr(&planned, "selected")
        .iter()
        .map(|row| {
            format!(
                r#"{{"item_id":"{}","audited":"{}"}}"#,
                text(row, "item_id"),
                text(row, "book_value")
            )
        })
        .collect();
    let clean = write(
        &dir,
        "planned-audited.json",
        &format!(r#"{{"items":[{}]}}"#, clean.join(",")),
    );
    let evaluated = doc(&draw(&[
        "evaluate",
        "--account",
        "1200",
        "--seed",
        "7",
        "--tolerable",
        "1500.00 USD",
        "--expected",
        "100.00 USD",
        "--confidence",
        "95",
        "--as-known-at",
        first.as_str(),
        "--audited",
        clean.as_str(),
    ]));
    assert_eq!(
        text(&evaluated, "sample_digest"),
        text(&planned, "sample_digest")
    );
    assert_eq!(text(&evaluated, "tolerable"), "1500.00 USD");
    assert_eq!(text(&evaluated, "upper_misstatement_limit"), "1339.98 USD");
    // Planning refusals (exit 2): no explicit --expected, no --confidence,
    // both forms at once, a confidence on a stated draw, an expected
    // misstatement that leaves nothing to plan for (1,000.00 x 1.6 =
    // 1,600.00 exceeds 1,500.00), and a confidence on a uniform draw.
    for args in [
        vec!["mus", "--tolerable", "1500.00 USD", "--confidence", "95"],
        vec![
            "mus",
            "--tolerable",
            "1500.00 USD",
            "--expected",
            "1.00 USD",
        ],
        vec![
            "mus",
            "--interval",
            "300.00 USD",
            "--tolerable",
            "1500.00 USD",
            "--expected",
            "0.00 USD",
            "--confidence",
            "95",
        ],
        vec!["mus", "--interval", "300.00 USD", "--confidence", "95"],
        vec![
            "mus",
            "--tolerable",
            "1500.00 USD",
            "--expected",
            "1000.00 USD",
            "--confidence",
            "95",
        ],
        vec!["uniform", "--size", "2", "--confidence", "95"],
    ] {
        let mut argv = vec!["sample", args[0], "--account", "1200", "--seed", "7"];
        argv.extend(&args[1..]);
        argv.push("--json");
        let (code, out, err) = fa(Some(&book), &argv);
        assert_eq!(code, 2, "{argv:?}\n{out}\n{err}");
    }

    // Evaluation re-draws that sample. The 700.00 top-stratum item is 10.00
    // overstated and the first systematic item 10% overstated; at 95%
    // (R0 = 3.00, R1 = 4.75) and a 300.00 interval: basic precision 900.00,
    // most likely error 10.00 + 300.00 x 1/10 = 40.00, incremental allowance
    // (4.75 - 3.00 - 1) x 30.00 = 22.50, upper limit 962.50, whichever
    // systematic item the seed hit.
    let mut tainted = false;
    let rows: Vec<String> = arr(&mus, "selected")
        .iter()
        .map(|row| {
            let book_value = text(row, "book_value");
            let audited = match (text(row, "basis"), book_value) {
                ("top_stratum", _) => "690.00 USD",
                ("systematic", "100.00 USD") if !tainted => "90.00 USD",
                ("systematic", "250.00 USD") if !tainted => "225.00 USD",
                ("systematic", "50.00 USD") if !tainted => "45.00 USD",
                _ => book_value,
            };
            tainted |= text(row, "basis") == "systematic";
            format!(
                r#"{{"item_id":"{}","audited":"{audited}"}}"#,
                text(row, "item_id")
            )
        })
        .collect();
    let audited = write(
        &dir,
        "audited.json",
        &format!(r#"{{"items":[{}]}}"#, rows.join(",")),
    );
    let evaluate = |audited: &str| {
        vec![
            "evaluate".to_string(),
            "--account".into(),
            "1200".into(),
            "--seed".into(),
            "7".into(),
            "--interval".into(),
            "300.00 USD".into(),
            "--as-known-at".into(),
            first.clone(),
            "--audited".into(),
            audited.to_string(),
            "--confidence".into(),
            "95".into(),
        ]
    };
    let argv = evaluate(&audited);
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let evaluated = doc(&draw(&argv));
    assert_eq!(text(&evaluated, "basic_precision"), "900.00 USD");
    assert_eq!(text(&evaluated, "top_stratum_misstatement"), "10.00 USD");
    assert_eq!(text(&evaluated, "most_likely_error"), "40.00 USD");
    assert_eq!(text(&evaluated, "incremental_allowance"), "22.50 USD");
    assert_eq!(text(&evaluated, "upper_misstatement_limit"), "962.50 USD");
    assert_eq!(
        text(&evaluated, "upper_misstatement_limit_exact"),
        "96250/1"
    );
    assert_eq!(evaluated.get("misstatement_count"), Some(&Json::Int(2)));
    assert_eq!(evaluated.get("understatement_count"), Some(&Json::Int(0)));
    assert_eq!(
        text(&evaluated, "sample_digest"),
        text(&mus, "sample_digest")
    );
    let taints: Vec<&str> = arr(&evaluated, "misstatements")
        .iter()
        .map(|row| text(row, "tainting"))
        .collect();
    assert!(taints.contains(&"1/10"), "{evaluated:?}");
    // An audited set that leaves out a selected item answers another sample
    // (exit 8), and evaluation needs the sample's recorded sequence (exit 2).
    let partial = write(
        &dir,
        "partial.json",
        &format!(r#"{{"items":[{}]}}"#, rows[1..].join(",")),
    );
    let argv = evaluate(&partial);
    let mut argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    argv.insert(0, "sample");
    argv.push("--json");
    let (code, out, err) = fa(Some(&book), &argv);
    assert_eq!(code, 8, "{out}\n{err}");
    assert!(out.contains("missing"), "{out}");
    // An audited value in another unit is refused for its unit (exit 2).
    let item = text(&arr(&mus, "selected")[0], "item_id").to_string();
    let mut other_unit = rows.clone();
    other_unit[0] = format!(r#"{{"item_id":"{item}","audited":"90.00 EUR"}}"#);
    let other_unit = write(
        &dir,
        "other-unit.json",
        &format!(r#"{{"items":[{}]}}"#, other_unit.join(",")),
    );
    let argv = evaluate(&other_unit);
    let mut argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    argv.insert(0, "sample");
    argv.push("--json");
    let (code, out, err) = fa(Some(&book), &argv);
    assert_eq!(code, 2, "{out}\n{err}");
    assert!(out.contains("not in the sample's unit USD"), "{out}");
    let mut argv = evaluate(&audited);
    assert_eq!(argv[7], "--as-known-at");
    argv.drain(7..9);
    let mut argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    argv.insert(0, "sample");
    argv.push("--json");
    let (code, out, err) = fa(Some(&book), &argv);
    assert_eq!(code, 2, "{out}\n{err}");

    // Usage errors (exit 2), nothing drawn.
    for args in [
        vec!["sample", "uniform", "--account", "1200", "--size", "2"],
        vec![
            "sample",
            "uniform",
            "--account",
            "1200",
            "--seed",
            "-1",
            "--size",
            "2",
        ],
        vec![
            "sample",
            "uniform",
            "--account",
            "1200",
            "--seed",
            "7",
            "--size",
            "0",
        ],
        vec![
            "sample",
            "uniform",
            "--account",
            "1200",
            "--seed",
            "7",
            "--size",
            "99",
        ],
        vec![
            "sample",
            "uniform",
            "--account",
            "1200",
            "--seed",
            "7",
            "--interval",
            "300.00 USD",
        ],
        vec![
            "sample",
            "mus",
            "--account",
            "1200",
            "--seed",
            "7",
            "--size",
            "2",
        ],
        // No normal-side open item to sample.
        vec![
            "sample",
            "uniform",
            "--account",
            "1300",
            "--seed",
            "7",
            "--size",
            "1",
        ],
        vec!["sample", "stratified", "--account", "1200", "--seed", "7"],
    ] {
        let mut argv = args.clone();
        argv.push("--json");
        let (code, out, err) = fa(Some(&book), &argv);
        assert_eq!(code, 2, "{argv:?}\n{out}\n{err}");
    }

    // The sample discloses the account's open items, so a token is judged
    // as `fa open-items` judges it, before the query (doctrine 8, fa-0x0):
    // confined to March, bounded to effective dates through March 31, or
    // pinned at the first sequence, the whole-book read is refused
    // (FA-REF-011, exit 7), and an evaluation is refused before its audited
    // values are read. Inside its caveats a token draws the owner's sample.
    let token = |holder: &str, scope: &[&str]| -> String {
        let path = dir.join(format!("{holder}.token")).display().to_string();
        let mut argv = vec![
            "capability",
            "issue",
            "--holder",
            holder,
            "--profile",
            "human",
            "--op",
            "read",
            "--out",
            path.as_str(),
            "--grant",
            "issue_capability",
            "--json",
        ];
        argv.extend_from_slice(scope);
        let (code, out, err) = fa(Some(&book), &argv);
        assert_eq!(code, 0, "{out}\n{err}");
        path
    };
    let march = token("auditor-march", &["--period", "FY2026-P03"]);
    let through = token("auditor-q1", &["--effective-through", "2026-03-31"]);
    let pinned = token("auditor-pinned", &["--known-at-most", &first]);
    let scoped = |token: &str, args: &[&str]| {
        let mut argv = vec!["--token", token, "sample"];
        argv.extend_from_slice(args);
        argv.push("--json");
        fa(Some(&book), &argv)
    };
    for (token, as_of, caveat) in [
        (march.as_str(), false, "`periods`"),
        (march.as_str(), true, "`periods`"),
        (through.as_str(), false, "`effective`"),
        (pinned.as_str(), false, "`known_at`"),
    ] {
        let mut args = uniform.to_vec();
        if as_of {
            args.extend(["--as-of", "2026-03-20"]);
        }
        let (code, out, err) = scoped(token, &args);
        assert_eq!(code, 7, "{args:?}\n{out}\n{err}");
        assert!(out.contains("FA-REF-011") && out.contains(caveat), "{out}");
    }
    // Audited values from stdin, which the test never supplies: the scope
    // refusal must come before the input is consumed.
    let argv = evaluate("-");
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let (code, out, err) = scoped(&march, &argv);
    assert_eq!(code, 7, "{out}\n{err}");
    assert!(
        out.contains("FA-REF-011") && out.contains("`periods`"),
        "{out}"
    );
    for (token, extra) in [
        (through.as_str(), ["--as-of", "2026-03-20"]),
        (pinned.as_str(), ["--as-known-at", first.as_str()]),
    ] {
        let mut args = uniform.to_vec();
        args.extend(extra);
        let (code, theirs, err) = scoped(token, &args);
        assert_eq!(code, 0, "{args:?}\n{theirs}\n{err}");
        let (theirs, ours) = (doc(&theirs), doc(&draw(&args)));
        for key in [
            "known_at",
            "population_count",
            "population_digest",
            "sample_digest",
            "selected",
        ] {
            assert_eq!(theirs.get(key), ours.get(key), "{key}");
        }
    }
    Ok(())
}

/// fa-k1ts: a stratified sample over book-value bands the auditor declares.
/// Every declared stratum is listed (an empty one included), allocation is
/// the decision card's pinned fallback (proportional) with its reason, the
/// population digest binds the bands, the parameters bind the allocation
/// and every stratum's counts, and the draw is reproducible from its replay
/// command. Malformed bands are usage errors.
#[test]
fn a_stratified_sample_draws_over_declared_bands_with_its_allocation_bound() -> std::io::Result<()>
{
    let dir = tmp("stratified")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Strata Co"]).0,
        0
    );
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1200","name":"Receivables","type":"Asset","unit":"USD"},{"code":"4000","name":"Sales","type":"Revenue","unit":"USD"}]}"#,
    );
    assert_eq!(fa(Some(&book), &["chart", "import", &chart]).0, 0);
    assert_eq!(
        fa(Some(&book), &["period", "create", "--fiscal-year", "2026"]).0,
        0
    );
    assert_eq!(fa(Some(&book), &["period", "open", "FY2026-P03"]).0, 0);
    let ev = source_doc(&dir, &book);
    for (key, amount) in [
        ("inv-1", "100.00"),
        ("inv-2", "250.00"),
        ("inv-3", "50.00"),
        ("inv-4", "700.00"),
    ] {
        let intent = write(
            &dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"2026-03-15","description":"{key}","idempotency_key":"{key}","legs":[{{"side":"debit","account":"1200","amount":"{amount} USD"}},{{"side":"credit","account":"4000","amount":"{amount} USD"}}]}}"#
            ),
        );
        let (code, out, err) = fa(
            Some(&book),
            &["post", "--intent", &intent, "--evidence", &ev, "--json"],
        );
        assert_eq!(code, 0, "{out}\n{err}");
    }
    let run = |args: &[&str]| {
        let mut argv = vec!["sample"];
        argv.extend_from_slice(args);
        argv.push("--json");
        fa(Some(&book), &argv)
    };
    // b01: at most 100.00 (100.00 and 50.00); b02: above 100.00, at most
    // 500.00 (250.00); b03: above 500.00 (700.00).
    let stratified = [
        "stratified",
        "--account",
        "1200",
        "--seed",
        "11",
        "--size",
        "4",
        "--band",
        "100.00 USD",
        "--band",
        "500.00 USD",
    ];
    let (code, out, err) = run(&stratified);
    assert_eq!(code, 0, "{out}\n{err}");
    let data = doc(&out);
    assert_eq!(text(&data, "method"), "stratified");
    assert_eq!(text(&data, "allocation"), "proportional");
    assert_eq!(text(&data, "decision_reason"), "policy_absent");
    assert_eq!(data.get("population_count"), Some(&Json::Int(4)), "{out}");
    let strata: Vec<(String, Json, Json, Json, Json)> = arr(&data, "strata")
        .iter()
        .map(|row| {
            (
                text(row, "stratum").to_string(),
                row.get("above").cloned().unwrap_or(Json::Null),
                row.get("at_most").cloned().unwrap_or(Json::Null),
                row.get("population_count").cloned().unwrap_or(Json::Null),
                row.get("allocated").cloned().unwrap_or(Json::Null),
            )
        })
        .collect();
    let usd = |amount: &str| Json::Str(format!("{amount} USD"));
    assert_eq!(
        strata,
        [
            (
                "b01".to_string(),
                Json::Null,
                usd("100.00"),
                Json::Int(2),
                Json::Int(2)
            ),
            (
                "b02".to_string(),
                usd("100.00"),
                usd("500.00"),
                Json::Int(1),
                Json::Int(1)
            ),
            (
                "b03".to_string(),
                usd("500.00"),
                Json::Null,
                Json::Int(1),
                Json::Int(1)
            ),
        ],
        "{out}"
    );
    // Each selected item carries its stratum, and each stratum's count is
    // its allocation.
    let selected = arr(&data, "selected");
    assert_eq!(selected.len(), 4, "{out}");
    let mut per: std::collections::BTreeMap<String, i128> = std::collections::BTreeMap::new();
    for item in selected {
        *per.entry(text(item, "stratum").to_string()).or_default() += 1;
    }
    assert_eq!(
        per.into_iter().collect::<Vec<_>>(),
        [
            ("b01".to_string(), 2),
            ("b02".to_string(), 1),
            ("b03".to_string(), 1)
        ]
    );
    assert_eq!(
        text(&data, "parameters"),
        "total_sample_size=4;basis=book_value_bands:100.00 USD,500.00 USD;allocation=proportional;policy_epoch=none;stratum=b01:2:2;stratum=b02:1:1;stratum=b03:1:1"
    );
    assert_eq!(text(&data, "decision_card_digest").len(), 64);
    // Reproducible, and replayed by its own command at its sequence.
    assert_eq!(run(&stratified).1, out);
    let known_at = data.get("known_at").cloned().unwrap_or(Json::Null);
    let Json::Int(known_at) = known_at else {
        panic!("{out}");
    };
    assert_eq!(
        text(&data, "replay_command"),
        format!(
            "fa sample stratified --account 1200 --seed 11 --size 4 --band \"100.00 USD\" --band \"500.00 USD\" --as-known-at {known_at}"
        )
    );
    let known_at = known_at.to_string();
    let mut replay = stratified.to_vec();
    replay.extend(["--as-known-at", known_at.as_str()]);
    assert_eq!(run(&replay).1, out);
    // The population digest binds the bands: the uniform population over
    // the same items digests differently.
    let (_, uniform, _) = run(&[
        "uniform",
        "--account",
        "1200",
        "--seed",
        "11",
        "--size",
        "4",
    ]);
    assert_ne!(
        text(&doc(&uniform), "population_digest"),
        text(&data, "population_digest")
    );
    // An empty declared stratum is listed with nothing to allocate.
    let (code, out, err) = run(&[
        "stratified",
        "--account",
        "1200",
        "--seed",
        "11",
        "--size",
        "3",
        "--band",
        "100.00 USD",
        "--band",
        "500.00 USD",
        "--band",
        "600.00 USD",
    ]);
    assert_eq!(code, 0, "{out}\n{err}");
    let data = doc(&out);
    let empty = &arr(&data, "strata")[2];
    assert_eq!(text(empty, "stratum"), "b03");
    assert_eq!(empty.get("population_count"), Some(&Json::Int(0)), "{out}");
    assert_eq!(empty.get("allocated"), Some(&Json::Int(0)), "{out}");
    assert_eq!(empty.get("std_dev"), Some(&Json::Null), "{out}");
    // Usage errors: no band, bands not ascending, a band in another unit, a
    // band on a uniform sample, and fewer items than non-empty strata.
    for args in [
        vec![
            "stratified",
            "--account",
            "1200",
            "--seed",
            "1",
            "--size",
            "3",
        ],
        vec![
            "stratified",
            "--account",
            "1200",
            "--seed",
            "1",
            "--size",
            "3",
            "--band",
            "500.00 USD",
            "--band",
            "100.00 USD",
        ],
        vec![
            "stratified",
            "--account",
            "1200",
            "--seed",
            "1",
            "--size",
            "3",
            "--band",
            "100.00 EUR",
        ],
        vec![
            "uniform",
            "--account",
            "1200",
            "--seed",
            "1",
            "--size",
            "3",
            "--band",
            "100.00 USD",
        ],
        vec![
            "stratified",
            "--account",
            "1200",
            "--seed",
            "1",
            "--size",
            "2",
            "--band",
            "100.00 USD",
            "--band",
            "500.00 USD",
        ],
    ] {
        let (code, out, err) = run(&args);
        assert_eq!(code, 2, "{args:?}\n{out}\n{err}");
        assert_eq!(text(&doc(&out), "class"), "usage", "{args:?}: {out}");
    }
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
        (Some("WrongAccout"), "did you mean `WrongAccount`"),
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
    // A Replacement posts only paired with its Reversal in one batch
    // (FA-INV-08.replacement-paired); alone it is refused (exit 3).
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
        out.contains("\"refusal_id\":\"FA-REF-160\"") && out.contains("paired Reversal"),
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
    // Append it once through the substrate, including its mirrors, edges and
    // the outcome claim every covered posting carries (fa-nl7); no existing
    // journal object is rewritten and the new law is not relaxed.
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
    assert!(
        fa_journal::outcome::stage_entry(&mut has_leg, &legacy, vid)
            .unwrap()
            .is_some(),
        "a Reversal is a covered class"
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
fn book_time_zone_rejects_unsupported_or_inapplicable_options_before_creation()
-> std::io::Result<()> {
    let dir = tmp("book-time-zone")?;
    for (index, args) in [
        vec![
            "book",
            "create",
            "--name",
            "Zone Co",
            "--time-zone",
            "America/New_York",
            "--json",
        ],
        vec![
            "book",
            "create",
            "--name",
            "Zone Co",
            "--time-zone",
            "utc",
            "--json",
        ],
        vec![
            "book",
            "create",
            "--name",
            "Zone Co",
            "--time-zone",
            "UTC",
            "--time-zone",
            "UTC",
            "--json",
        ],
        vec!["book", "info", "--time-zone", "UTC", "--json"],
    ]
    .iter()
    .enumerate()
    {
        let book = dir.join(format!("refused-{index}"));
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 2, "args={args:?}\n{out}\n{err}");
        assert!(
            !book.exists(),
            "invalid book policy must not create a directory or keys"
        );
    }
    Ok(())
}

#[test]
fn timed_cli_intents_preserve_their_requests_and_execute_under_recorded_ticks()
-> std::io::Result<()> {
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fa::{Book, BookKeys, Entropy};
    use fa_journal::{Capability, ReversalStatus};
    use fa_model::{Disposition, EntryClass};
    use fa_money::Side;
    use fa_policy::{Op, Profile};
    use fa_time::DateDay;
    use fgdb_types::VId;

    // Declared observations, independent of process wall time: March 15
    // noon and April 1 midnight UTC. Only the host fixture records ticks.
    const ANCHOR_NS: u64 = 1_773_576_000_000_000_000;
    const APRIL_NS: u64 = 1_775_001_600_000_000_000;
    let dir = tmp("timed-intents")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        assert!(err.is_empty(), "{err}");
        out
    };
    ok(&[
        "book",
        "create",
        "--name",
        "Timed Co",
        "--time-zone",
        "UTC",
        "--json",
    ]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    ok(&["period", "open", "FY2026-P04", "--json"]);
    let evidence = source_doc(&dir, &book);
    let keys = BookKeys::load(&book.join("book.keys")).unwrap();
    let open = || Book::open_dir(&book, keys.clone(), Entropy::production()).unwrap();
    let head = || open().head().unwrap();
    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let witness = Capability::embedded(VId(7), &["witness"]).unwrap();
    let tick = |ns| {
        let mut handle = open();
        runtime
            .block_on(handle.record_tick(&root, ns, true, &witness))
            .unwrap()
            .unwrap()
    };
    let system = fa_journal::rows::system_principal(open().context().book_id);
    let sweeper = Capability::new(system, Profile::System, &[Op::Post], system).unwrap();
    let anchor = tick(ANCHOR_NS);
    let intent = |key: &str, class: &str, extra: &str| {
        write(
            &dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"class":"{class}","effective_date":"2026-03-15","idempotency_key":"{key}","legs":[{{"side":"debit","account":"6000","amount":"1.00 USD"}},{{"side":"credit","account":"1000","amount":"1.00 USD"}}]{extra}}}"#
            ),
        )
    };
    // Typos, inapplicable fields, duplicate sources, and wrong types never
    // become permanent or unscheduled entries. Valid but inadmissible data
    // still reaches the kernel's registered refusal unchanged.
    /// `(class, extra intent fields, extra argv, exit, refusal id)`.
    type BadIntent = (
        &'static str,
        &'static str,
        &'static [&'static str],
        i32,
        Option<&'static str>,
    );
    let bad_intents: &[BadIntent] = &[
        ("Pending", r#","timeout_ns":-1"#, &[], 2, None),
        (
            "Pending",
            r#","timeout_ns":18446744073709551616"#,
            &[],
            2,
            None,
        ),
        ("Pending", r#","timeout_ns":"5""#, &[], 2, None),
        ("Pending", r#","timeout_ns":null"#, &[], 2, None),
        ("Pending", r#","timeout_ns":1.5"#, &[], 2, None),
        ("Pending", r#","timeout":5"#, &[], 2, None),
        ("Pending", r#","timeout_nss":5"#, &[], 2, None),
        ("Pending", r#","expires_at":"2026-04-01""#, &[], 2, None),
        ("Original", r#","timeout_ns":5"#, &[], 2, None),
        ("Resolution", r#","timeout_ns":5"#, &[], 2, None),
        ("Pending", r#","reverse_on":"2026-04-01""#, &[], 2, None),
        ("Original", r#","reverse_on":"2026-04-01""#, &[], 2, None),
        ("Adjusting", r#","reverse_on":5"#, &[], 2, None),
        ("Adjusting", r#","reverse_on":null"#, &[], 2, None),
        ("Adjusting", r#","reverse_on":"2026-02-30""#, &[], 2, None),
        (
            "Adjusting",
            r#","auto_reverse_on":"2026-04-01""#,
            &[],
            2,
            None,
        ),
        ("Pending", "", &["--timeout-ns", "-1"], 2, None),
        ("Pending", "", &["--timeout-ns", "+5"], 2, None),
        (
            "Pending",
            "",
            &["--timeout-ns", "18446744073709551616"],
            2,
            None,
        ),
        ("Original", "", &["--timeout-ns", "5"], 2, None),
        ("Original", "", &["--reverse-on", "2026-04-01"], 2, None),
        ("Adjusting", "", &["--reverse-on", "2026-04-31"], 2, None),
        (
            "Pending",
            "",
            &["--timeout-ns", "5", "--timeout-ns", "5"],
            2,
            None,
        ),
        (
            "Pending",
            r#","timeout_ns":5"#,
            &["--timeout-ns", "5"],
            2,
            None,
        ),
        (
            "Adjusting",
            r#","reverse_on":"2026-04-01""#,
            &["--reverse-on", "2026-04-01"],
            2,
            None,
        ),
        (
            "Adjusting",
            "",
            &["--reverse-on", "2026-04-01", "--reverse-on", "2026-04-01"],
            2,
            None,
        ),
        (
            "Pending",
            r#","timeout_ns":18446744073709551615"#,
            &[],
            3,
            Some("FA-REF-096"),
        ),
        (
            "Adjusting",
            r#","reverse_on":"2026-03-15""#,
            &[],
            2,
            Some("FA-REF-100"),
        ),
    ];
    let before_invalid = head();
    for (index, (class, extra, flags, expected_exit, refusal)) in bad_intents.iter().enumerate() {
        let path = intent(&format!("invalid-{index}"), class, extra);
        let mut args = vec!["post", "--intent", &path, "--evidence", &evidence, "--json"];
        args.extend_from_slice(flags);
        let (code, out, err) = fa(Some(&book), &args);
        assert_eq!(code, *expected_exit, "case {index}: {args:?}\n{out}\n{err}");
        if let Some(refusal) = refusal {
            assert_eq!(field(&out, "refusal_id"), Some(*refusal), "{out}");
        }
        assert_eq!(head(), before_invalid, "case {index} must publish nothing");
    }
    let vid = |out: &str| VId(u128::from_str_radix(text(&doc(out), "vid"), 16).unwrap());
    let mut holds = Vec::new();
    for (key, verb, extra, flag, timeout) in [
        ("hold-json", "reserve", r#","timeout_ns":5"#, None, 5),
        ("hold-flag", "reserve", "", Some("7"), 7),
        ("post-hold", "post", "", Some("9"), 9),
    ] {
        let path = intent(key, "Pending", extra);
        let mut args = vec![verb, "--intent", &path, "--evidence", &evidence, "--json"];
        if let Some(value) = flag {
            args.extend(["--timeout-ns", value]);
        }
        let before = head();
        let mut plan_args = args.clone();
        plan_args.push("--dry-run");
        assert_eq!(field(&ok(&plan_args), "event"), Some("plan"));
        assert_eq!(head(), before, "planning must not acquire a reservation");
        let out = ok(&args);
        let (entry, seq) = open().read_entry(vid(&out)).unwrap().unwrap();
        assert!(seq > anchor.recorded_at);
        assert_eq!(entry.proposal.class, EntryClass::PENDING);
        assert_eq!(
            entry.proposal.pending.as_ref().unwrap().timeout_ns,
            Some(timeout)
        );
        holds.push(entry.entry_ref(vid(&out)));
        let before = head();
        assert_eq!(field(&ok(&args), "event"), Some("recorded"));
        assert_eq!(head(), before, "an exact timed retry cannot reserve twice");
    }
    let reverse_day = DateDay::parse("2026-04-01").unwrap();
    let mut adjustments = Vec::new();
    for (key, extra, flag) in [
        ("adjust-json", r#","reverse_on":"2026-04-01""#, None),
        ("adjust-flag", "", Some("2026-04-01")),
    ] {
        let path = intent(key, "Adjusting", extra);
        let mut args = vec!["post", "--intent", &path, "--evidence", &evidence, "--json"];
        if let Some(value) = flag {
            args.extend(["--reverse-on", value]);
        }
        let out = ok(&args);
        let (entry, _) = open().read_entry(vid(&out)).unwrap().unwrap();
        assert_eq!(
            fa_journal::schedule::auto_reverse(&entry.proposal).unwrap(),
            Some((reverse_day, fa_journal::schedule::RULE_EXACT_NEGATION))
        );
        adjustments.push(entry.entry_ref(vid(&out)));
    }
    assert!(open().due_holds().unwrap().is_empty());
    assert!(open().due_reversals().unwrap().is_empty());

    // Being due does not itself release the money. Until the sweep commits,
    // the pending columns retain all three reservations.
    let reached = tick(ANCHOR_NS + 10);
    let due = open().due_holds().unwrap();
    assert_eq!(due.iter().map(|h| h.hold).collect::<Vec<_>>(), holds);
    assert_eq!(
        due.iter().map(|h| h.deadline_ns).collect::<Vec<_>>(),
        vec![ANCHOR_NS + 5, ANCHOR_NS + 7, ANCHOR_NS + 9]
    );
    let tb = doc(&report(&book, &["tb", "--period", "FY2026-P03", "--json"]));
    let cash = arr(&tb, "rows")
        .iter()
        .find(|row| text(row, "code") == "1000")
        .unwrap();
    assert_eq!(text(cash, "credits_pending"), "3.00 USD");
    let resolution = write(
        &dir,
        "too-late.json",
        &format!(
            r#"{{"effective_date":"2026-03-15","idempotency_key":"too-late","resolves":"{:032x}","disposition":"posts","legs":[{{"side":"debit","account":"6000","amount":"1.00 USD"}},{{"side":"credit","account":"1000","amount":"1.00 USD"}}]}}"#,
            holds[0].vid.0
        ),
    );
    let before = head();
    let (code, out, _) = fa(Some(&book), &["resolve", "--intent", &resolution, "--json"]);
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-097"), "{out}");
    assert_eq!(
        head(),
        before,
        "a due hold cannot be posted by a manual resolution"
    );
    {
        let mut handle = open();
        for (expected, remaining) in [(&holds[..2], 1), (&holds[2..], 0)] {
            let batch = runtime
                .block_on(handle.sweep_expiry(&root, &sweeper, 2))
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(batch.tick, reached.tick);
            assert_eq!(batch.remaining_due, remaining);
            assert_eq!(
                batch
                    .expired
                    .iter()
                    .map(|(hold, _)| *hold)
                    .collect::<Vec<_>>(),
                expected
            );
            for (_, expiry) in batch.expired {
                let (entry, _) = handle.read_entry(expiry.vid).unwrap().unwrap();
                assert_eq!(
                    entry.proposal.pending.as_ref().unwrap().disposition,
                    Some(Disposition::Expires {
                        at_tick: ANCHOR_NS + 10
                    })
                );
            }
        }
        assert!(handle.due_holds().unwrap().is_empty());
        let before = handle.head().unwrap();
        assert!(
            runtime
                .block_on(handle.sweep_expiry(&root, &sweeper, 2))
                .unwrap()
                .unwrap()
                .is_none()
        );
        assert_eq!(handle.head().unwrap(), before);
    }
    assert_cash_credits(
        &report(&book, &["tb", "--period", "FY2026-P03", "--json"]),
        "2.00 USD",
    );

    // The civil-date policy declared through book create enables real
    // schedule execution. Only this System host fixture invokes the sweeps.
    let april = tick(APRIL_NS);
    let mut handle = open();
    let due = handle.due_reversals().unwrap();
    assert_eq!(
        due.iter().map(|r| r.schedule.target).collect::<Vec<_>>(),
        adjustments
    );
    assert!(due.iter().all(|r| r.status == ReversalStatus::Due));
    let batch = runtime
        .block_on(handle.sweep_reversals(&root, &sweeper, 2))
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(batch.tick, april.tick);
    assert!(batch.blocked.is_empty());
    assert_eq!(batch.minted.len(), 2);
    for (target, reversal) in batch.minted {
        let (original, _) = handle.read_entry(target.vid).unwrap().unwrap();
        let (reversed, _) = handle.read_entry(reversal.vid).unwrap().unwrap();
        assert_eq!(reversed.proposal.class, EntryClass::REVERSAL);
        assert_eq!(reversed.proposal.effective_date, reverse_day);
        for (source, actual) in original.proposal.legs.iter().zip(&reversed.proposal.legs) {
            let mut expected = source.clone();
            expected.side = if source.side == Side::Debit {
                Side::Credit
            } else {
                Side::Debit
            };
            assert_eq!(
                *actual, expected,
                "the schedule retains the exact requested effects"
            );
        }
    }
    assert!(handle.due_reversals().unwrap().is_empty());
    let before = handle.head().unwrap();
    assert!(
        runtime
            .block_on(handle.sweep_reversals(&root, &sweeper, 2))
            .unwrap()
            .unwrap()
            .is_none()
    );
    assert_eq!(
        handle.head().unwrap(),
        before,
        "a schedule executes at most once"
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
    let scheduled = write(
        &dir,
        "without-zone.json",
        r#"{"class":"Adjusting","effective_date":"2026-03-10","reverse_on":"2026-04-01","idempotency_key":"without-zone","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    let (code, out, _) = fa(
        Some(&book),
        &["post", "--intent", &scheduled, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-102"), "{out}");
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

    // A requested timeout needs committed clock evidence, never a silently
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
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-095"), "{out}");
    assert!(out.contains("TimeEvidence"), "{out}");
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
    assert!(out.contains("but only 200.00 USD is open"), "{out}");
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
        human.contains("event balance_explained (replay, explain)")
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
    assert_eq!(run(false, &["chart", "templates"]).0, 0);
    assert_eq!(run(false, &["law", "list"]).0, 0);
    assert_eq!(run(false, &["law", "show", "HalfEven"]).0, 0);
    assert_eq!(run(false, &["unit", "list"]).0, 0);
    assert_eq!(run(false, &["nosuchverb"]).0, 2);
    assert_eq!(run(true, &["book", "info"]).0, 4);
    assert_eq!(run(true, &["book", "create", "--name", "Events Co"]).0, 0);
    assert_eq!(run(true, &["book", "info"]).0, 0);
    assert_eq!(run(true, &["doctor"]).0, 0);
    assert_eq!(run(true, &["triage"]).0, 0);
    assert_eq!(run(true, &["next"]).0, 0);
    assert_eq!(
        run(true, &["checkpoint", "create", "--grant", "witness"]).0,
        0
    );
    assert_eq!(run(true, &["verify", "accumulator"]).0, 0);
    // fa-waow: the chain the create above journaled, newest first.
    let (code, out) = run(true, &["checkpoint", "list"]);
    assert_eq!(code, 0, "{out}");
    let listed = doc(&out);
    let states = arr(&listed, "checkpoints");
    assert_eq!(states.len(), 1, "{out}");
    assert_eq!(states[0].get("prev_state_oid"), Some(&Json::Null), "{out}");
    assert_eq!(
        run(true, &["checkpoint", "list", "--period", "FY2026-P03"]).0,
        2
    );
    assert_eq!(run(true, &["recover", "projections", "--dry-run"]).0, 0);
    assert_eq!(run(true, &["recover", "outcomes", "--dry-run"]).0, 0);
    assert_eq!(run(true, &["proof", "signed-checkpoint"]).0, 0);
    assert_eq!(run(true, &["bundle", "produce"]).0, 0);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    assert_eq!(run(true, &["chart", "import", &chart]).0, 0);
    assert_eq!(run(true, &["chart", "list"]).0, 0);
    // fa-waow: no drafts or scenarios yet; trunk is implicit.
    let (code, out) = run(true, &["branch", "list"]);
    assert_eq!(code, 0, "{out}");
    let branches = doc(&out);
    assert!(arr(&branches, "drafts").is_empty(), "{out}");
    assert!(arr(&branches, "scenarios").is_empty(), "{out}");
    assert_eq!(run(true, &["branch", "show"]).0, 2);
    // fa-waow: one account with its place in the tree.
    let (code, out) = run(true, &["chart", "show", "1000"]);
    assert_eq!(code, 0, "{out}");
    let shown = doc(&out);
    let account = shown.get("account").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&account, "code"), "1000", "{out}");
    assert_eq!(text(&account, "normal_side"), "debit", "{out}");
    assert!(int(&account, "created_at").is_some(), "{out}");
    assert_eq!(run(true, &["chart", "show", "1001"]).0, 2);
    assert_eq!(run(true, &["chart", "show"]).0, 2);
    assert_eq!(
        run(true, &["period", "create", "--fiscal-year", "2026"]).0,
        0
    );
    assert_eq!(run(true, &["period", "list"]).0, 0);
    // fa-waow: the calendar's rule and its periods, created or not.
    let (code, out) = run(true, &["calendar", "show"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(text(&doc(&out), "kind"), "monthly", "{out}");
    let (code, out) = run(true, &["calendar", "periods", "--fiscal-year", "2027"]);
    assert_eq!(code, 0, "{out}");
    let previewed = doc(&out);
    let previewed = arr(&previewed, "periods");
    assert!(!previewed.is_empty(), "{out}");
    assert!(
        previewed
            .iter()
            .all(|p| p.get("created") == Some(&Json::Bool(false))),
        "{out}"
    );
    let (code, out) = run(true, &["calendar", "periods", "--fiscal-year", "2026"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        arr(&doc(&out), "periods")
            .iter()
            .any(|p| text(p, "code") == "FY2026-P03" && p.get("created") == Some(&Json::Bool(true))),
        "{out}"
    );
    assert_eq!(run(true, &["calendar", "periods"]).0, 2);
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
    // Rehearse and commit the complete batch artifact; its ordinary exact
    // retry also emits batch_posted without adding another posting.
    let batch = write(
        &dir,
        "batch.json",
        &format!(
            r#"{{"idempotency_key":"batch","intents":[{{"effective_date":"2026-03-15","idempotency_key":"batch-rent","evidence":["{ev}"],"legs":[{{"side":"debit","account":"6000","amount":"1.00 USD"}},{{"side":"credit","account":"1000","amount":"1.00 USD"}}]}}]}}"#
        ),
    );
    let batch_plan = dir.join("atomic-batch.plan").display().to_string();
    let (code, planned) = run(
        true,
        &[
            "post",
            "--intent",
            &batch,
            "--dry-run",
            "--plan-out",
            &batch_plan,
        ],
    );
    assert_eq!(code, 0, "{planned}");
    assert_eq!(field(&planned, "event"), Some("batch_plan"));
    let (code, committed) = run(true, &["commit", "--plan", &batch_plan]);
    assert_eq!(code, 0, "{committed}");
    assert_eq!(field(&committed, "event"), Some("batch_plan_committed"));
    assert_eq!(run(true, &["post", "--intent", &batch]).0, 0);
    // Drafts (fa-s7x): open, plan by --draft and by `draft plan`, inspect,
    // promote as another principal holding approve, and discard another.
    let draft_intent = |key: &str| {
        format!(
            r#"{{"effective_date":"2026-03-15","idempotency_key":"{key}","evidence":["{ev}"],"legs":[{{"side":"debit","account":"6000","amount":"2.00 USD"}},{{"side":"credit","account":"1000","amount":"2.00 USD"}}]}}"#
        )
    };
    let d1 = write(&dir, "draft1.json", &draft_intent("draft-rent-1"));
    let d2 = write(&dir, "draft2.json", &draft_intent("draft-rent-2"));
    assert_eq!(run(true, &["draft", "new", "close-03"]).0, 0);
    assert_eq!(
        run(true, &["post", "--intent", &d1, "--draft", "close-03"]).0,
        0
    );
    assert_eq!(
        run(true, &["draft", "plan", "close-03", "--intent", &d2]).0,
        0
    );
    assert_eq!(run(true, &["draft", "list"]).0, 0);
    assert_eq!(run(true, &["draft", "show", "close-03"]).0, 0);
    assert_eq!(
        run(
            true,
            &[
                "close",
                "dry-run",
                "--period",
                "FY2026-P03",
                "--draft",
                "close-03"
            ],
        )
        .0,
        0,
    );
    let (code, out) = run(
        true,
        &[
            "draft",
            "promote",
            "close-03",
            "--as",
            "controller",
            "--yes",
        ],
    );
    assert_eq!(code, 0, "{out}");
    assert_eq!(run(true, &["draft", "new", "scratch"]).0, 0);
    assert_eq!(
        run(
            true,
            &["draft", "discard", "scratch", "--reason", "superseded"]
        )
        .0,
        0
    );
    let s1 = write(&dir, "scenario1.json", &draft_intent("scenario-rent-1"));
    assert_eq!(run(true, &["scenario", "fork", "what-if"]).0, 0);
    assert_eq!(
        run(true, &["scenario", "run", "what-if", "--intent", &s1]).0,
        0
    );
    assert_eq!(run(true, &["scenario", "list"]).0, 0);
    assert_eq!(run(true, &["scenario", "show", "what-if"]).0, 0);
    assert_eq!(
        run(
            true,
            &["scenario", "diff", "what-if", "--period", "FY2026-P03"]
        )
        .0,
        0
    );
    assert_eq!(run(true, &["scenario", "discard", "what-if"]).0, 0);
    // Litigation productions (fa-6l9).
    assert_eq!(
        run(
            true,
            &[
                "production",
                "open",
                "events-matter",
                "--bates-prefix",
                "EVT"
            ]
        )
        .0,
        0
    );
    let volume = dir.join("events-volume").display().to_string();
    assert_eq!(
        run(
            true,
            &[
                "produce",
                "--matter",
                "events-matter",
                "--document",
                &ev,
                "--out",
                &volume
            ]
        )
        .0,
        0
    );
    assert_eq!(run(true, &["production", "list"]).0, 0);
    assert_eq!(run(true, &["production", "show", "events-matter"]).0, 0);
    assert_eq!(run(true, &["production", "document", &ev]).0, 0);
    // Audit engagements (fa-zgn): open, propose, pass, list and show.
    assert_eq!(
        run(
            true,
            &[
                "engagement",
                "open",
                "events-engagement",
                "--kind",
                "audit",
                "--period",
                "FY2026-P03",
                "--overall",
                "100.00 USD",
                "--performance",
                "75.00 USD",
                "--clearly-trivial",
                "5.00 USD"
            ]
        )
        .0,
        0
    );
    let adjustment = write(
        &dir,
        "adjustment.json",
        r#"{"effective_date":"2026-03-20","description":"Unrecorded rent","legs":[{"side":"debit","account":"6000","amount":"5.00 USD"},{"side":"credit","account":"1000","amount":"5.00 USD"}]}"#,
    );
    assert_eq!(
        run(
            true,
            &[
                "adjustment",
                "propose",
                "--engagement",
                "events-engagement",
                "--intent",
                &adjustment
            ]
        )
        .0,
        0
    );
    assert_eq!(
        run(
            true,
            &[
                "adjustment",
                "pass",
                "--engagement",
                "events-engagement",
                "--proposal",
                "1",
                "--reason",
                "ClearlyTrivial"
            ]
        )
        .0,
        0
    );
    assert_eq!(run(true, &["engagement", "list"]).0, 0);
    assert_eq!(run(true, &["engagement", "show", "events-engagement"]).0, 0);
    assert_eq!(run(true, &["engagement", "sud", "events-engagement"]).0, 0);
    assert_eq!(run(true, &["tb", "--period", "FY2026-P03"]).0, 0);
    assert_eq!(
        run(true, &["tb", "--period", "FY2026-P03", "--render", "md"]).0,
        0
    );
    assert_eq!(run(true, &["search", "rent"]).0, 0);
    assert_eq!(run(true, &["open-items"]).0, 0);
    assert_eq!(
        run(
            true,
            &[
                "sample",
                "uniform",
                "--account",
                "6000",
                "--seed",
                "7",
                "--size",
                "1"
            ]
        )
        .0,
        0
    );
    // An MUS draw, then its evaluation with every selected item at book.
    let (code, mus) = run(
        true,
        &[
            "sample",
            "mus",
            "--account",
            "6000",
            "--seed",
            "7",
            "--interval",
            "5.00 USD",
        ],
    );
    assert_eq!(code, 0, "{mus}");
    let drawn = doc(&mus);
    let audited: Vec<String> = arr(&drawn, "selected")
        .iter()
        .map(|row| {
            format!(
                r#"{{"item_id":"{}","audited":"{}"}}"#,
                text(row, "item_id"),
                text(row, "book_value")
            )
        })
        .collect();
    let audited = write(
        &dir,
        "audited.json",
        &format!(r#"{{"items":[{}]}}"#, audited.join(",")),
    );
    let drawn_at = field(&mus, "known_at").unwrap_or_default().to_string();
    let (code, evaluated) = run(
        true,
        &[
            "sample",
            "evaluate",
            "--account",
            "6000",
            "--seed",
            "7",
            "--interval",
            "5.00 USD",
            "--as-known-at",
            &drawn_at,
            "--audited",
            &audited,
            "--confidence",
            "95",
        ],
    );
    assert_eq!(code, 0, "{evaluated}");
    assert_eq!(run(true, &["procedure", "list"]).0, 0);
    assert_eq!(run(true, &["procedure", "run", "jet.round_amounts"]).0, 0);
    // Recorded findings: the Sunday rent is a jet.weekend observation; a
    // second principal reviews it; the canonical workpaper replays.
    let (code, out) = run(true, &["finding", "record", "jet.weekend"]);
    assert_eq!(code, 0, "{out}");
    let recorded = doc(&out);
    let certificate = text(&recorded, "certificate").to_string();
    let selected = format!(
        "F:{}",
        arr(&recorded, "finding_ids")
            .first()
            .and_then(Json::as_str)
            .unwrap_or_default()
    );
    assert_eq!(run(true, &["finding", "runs"]).0, 0);
    assert_eq!(
        run(true, &["finding", "list", "--certificate", &certificate]).0,
        0
    );
    assert_eq!(run(true, &["finding", "show", &selected]).0, 0);
    let (code, out) = run(
        true,
        &[
            "finding",
            "review",
            &selected,
            "--action",
            "acknowledge",
            "--note",
            "Weekend rent confirmed with the landlord",
            "--as",
            "reviewer",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let workpaper = dir.join("findings.fawp").display().to_string();
    assert_eq!(
        run(
            true,
            &[
                "finding",
                "export",
                "--certificate",
                &certificate,
                "--export-format",
                "canonical",
                "--out",
                &workpaper,
            ],
        )
        .0,
        0
    );
    assert_eq!(run(true, &["finding", "replay", &workpaper]).0, 0);
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
    assert_eq!(
        run(true, &["verify", "entities", "--period", "FY2026-P03"]).0,
        0
    );
    assert_eq!(run(true, &["verify", "open-items"]).0, 0);
    assert_eq!(run(true, &["verify", "replay"]).0, 0);
    assert_eq!(run(true, &["verify", "projections"]).0, 0);
    assert_eq!(run(true, &["verify", "availability"]).0, 0);
    let (code, out) = run(true, &["verify", "usage"]);
    assert_eq!(code, 0, "{out}");
    let usage = doc(&out);
    assert_eq!(int(&usage, "charges_checked"), Some(0));
    assert_eq!(int(&usage, "cells_checked"), Some(0));
    assert!(arr(&usage, "drift").is_empty());
    assert_eq!(run(true, &["verify", "schedules"]).0, 0);
    // FY2026 exists and FY2026-P03 was opened by a journaled transition.
    assert_eq!(run(true, &["verify", "periods"]).0, 0);
    // fa-waow: every target above in one call, each with its own event, then
    // one verdict.
    let (code, out) = run(true, &["verify", "book"]);
    assert_eq!(code, 0, "{out}");
    let verdict = doc(&out);
    assert_eq!(verdict.get("green"), Some(&Json::Bool(true)), "{out}");
    let ran: Vec<&str> = arr(&verdict, "targets")
        .iter()
        .map(|t| text(t, "target"))
        .collect();
    assert_eq!(
        ran,
        [
            "projections",
            "periods",
            "schedules",
            "accumulator",
            "open-items",
            "availability",
            "usage",
            "entities",
            "registers",
            "replay"
        ]
    );
    assert!(
        arr(&verdict, "targets")
            .iter()
            .all(|t| text(t, "verdict") == "pass"),
        "{out}"
    );
    for event in [
        "projections_verified",
        "registers_verified",
        "replay_verified",
    ] {
        assert!(
            out.contains(&format!("\"event\":\"{event}\"")),
            "{event}: {out}"
        );
    }
    assert_eq!(
        run(true, &["verify", "book", "--period", "FY2026-P03"]).0,
        2
    );
    let more = write(
        &dir,
        "more.json",
        r#"{"effective_date":"2026-03-16","idempotency_key":"more","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    let more_plan = dir.join("more.plan").display().to_string();
    assert_eq!(
        run(
            true,
            &[
                "post",
                "--intent",
                &more,
                "--evidence",
                &ev,
                "--dry-run",
                "--plan-out",
                &more_plan,
            ],
        )
        .0,
        0
    );
    assert_eq!(run(true, &["commit", "--plan", &more_plan]).0, 0);
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
    // A correction pair (corrected), an export (journal_exported), the chart
    // and REA controls (account_lifecycle, rea_recorded) and their lists
    // (parties, instruments).
    let rent2 = write(
        &dir,
        "rent2.json",
        r#"{"effective_date":"2026-03-16","idempotency_key":"rent-2","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}]}"#,
    );
    let (code, out) = run(true, &["post", "--intent", &rent2, "--evidence", &ev]);
    assert_eq!(code, 0, "{out}");
    let vid2 = field(&out, "vid").unwrap_or_default().to_string();
    let corrected = write(
        &dir,
        "corrected.json",
        r#"{"legs":[{"side":"debit","account":"6000","amount":"12.00 USD"},{"side":"credit","account":"1000","amount":"12.00 USD"}]}"#,
    );
    assert_eq!(
        run(
            true,
            &[
                "reverse",
                &vid2,
                "--reason",
                "WrongAmount",
                "--replace-with",
                &corrected,
                "--evidence",
                &ev,
            ],
        )
        .0,
        0
    );
    // Rehearse a separate correction and publish its complete pair artifact,
    // covering both additive plan events through the declared robot schema.
    let planned_original = write(
        &dir,
        "planned-correction-original.json",
        r#"{"effective_date":"2026-03-16","idempotency_key":"rent-pair-plan","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}]}"#,
    );
    let (code, original) = run(
        true,
        &["post", "--intent", &planned_original, "--evidence", &ev],
    );
    assert_eq!(code, 0, "{original}");
    let pair_path = dir.join("atomic-correction.plan").display().to_string();
    let (code, planned) = run(
        true,
        &[
            "reverse",
            field(&original, "vid").unwrap(),
            "--reason",
            "WrongAmount",
            "--replace-with",
            &corrected,
            "--evidence",
            &ev,
            "--dry-run",
            "--plan-out",
            &pair_path,
        ],
    );
    assert_eq!(code, 0, "{planned}");
    assert_eq!(field(&planned, "event"), Some("replacement_plan"));
    let (code, committed) = run(true, &["commit", "--plan", &pair_path]);
    assert_eq!(code, 0, "{committed}");
    assert_eq!(
        field(&committed, "event"),
        Some("replacement_plan_committed")
    );
    assert_eq!(
        run(true, &["export", "csv-gl", "--period", "FY2026-P03"]).0,
        0
    );
    let office = write(
        &dir,
        "office.json",
        r#"{"code":"6100","name":"Office","type":"Expense","unit":"USD"}"#,
    );
    assert_eq!(
        run(true, &["chart", "open", &office, "--opened", "2026-03-01"]).0,
        0
    );
    let bank = write(
        &dir,
        "bank-party.json",
        r#"{"code":"BANK-1","kind":"Bank","name":"First Bank"}"#,
    );
    assert_eq!(run(true, &["party", "add", &bank]).0, 0);
    assert_eq!(run(true, &["party", "list"]).0, 0);
    let holder = write(
        &dir,
        "holder-party.json",
        r#"{"code":"H-1","kind":"BeneficialOwner","name":"Holder"}"#,
    );
    assert_eq!(run(true, &["party", "add", &holder]).0, 0);
    assert_eq!(
        run(
            true,
            &[
                "party",
                "ownership",
                "H-1",
                "BANK-1",
                "--as-of",
                "2026-03-31"
            ]
        )
        .0,
        0
    );
    let account = write(
        &dir,
        "instrument.json",
        r#"{"code":"BA-1","name":"Operating","kind":"BankAccount","unit":"USD","held_at":"BANK-1","mirrors":"1000"}"#,
    );
    assert_eq!(run(true, &["instrument", "add", &account]).0, 0);
    assert_eq!(run(true, &["instrument", "list"]).0, 0);
    // A retained statement is matched to an actual cash leg. The exact
    // emitted command is independently confirmed and inventoried afterward.
    assert_eq!(run(true, &["entity", "list"]).0, 0);
    assert_eq!(run(true, &["document", "list"]).0, 0);
    let bank_cash = write(
        &dir,
        "events-bank-cash.json",
        r#"{"effective_date":"2026-03-05","idempotency_key":"events-bank-cash","legs":[{"side":"debit","account":"1000","amount":"10.00 USD","memo":"R-1"},{"side":"credit","account":"6000","amount":"10.00 USD"}]}"#,
    );
    let (code, out) = run(true, &["post", "--intent", &bank_cash, "--evidence", &ev]);
    assert_eq!(code, 0, "{out}");
    let statement = write(
        &dir,
        "events-statement.csv",
        "sequence_number,instrument_id,currency,statement_date,opening_balance,closing_balance,booking_date,value_date,side,amount,counterparty,reference\n\
1,BANK-1,USD,2026-03-31,0.00,10.00,2026-03-05,2026-03-05,CRDT,10.00,Payer,R-1\n",
    );
    let (code, out) = run(
        true,
        &[
            "bank",
            "import",
            &statement,
            "--bank-format",
            "csv",
            "--account",
            "1000",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let manifest = field(&out, "manifest_oid").unwrap_or_default().to_string();
    let (code, out) = run(
        true,
        &[
            "bank",
            "match",
            "--import",
            &manifest,
            "--grant",
            "privileged",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let bank_matches = doc(&out);
    let [bank_proposal] = arr(&bank_matches, "proposals") else {
        panic!("one retained bank line: {out}");
    };
    assert_eq!(int(bank_proposal, "eligible_candidate_count"), Some(1));
    assert_eq!(bank_proposal.get("ambiguous"), Some(&Json::Bool(false)));
    let mut confirmation_args: Vec<_> = text(bank_proposal, "confirmation_command")
        .strip_prefix("fa ")
        .expect("the actual proposal supplies its confirmation command")
        .split_ascii_whitespace()
        .filter(|argument| *argument != "--json")
        .collect();
    confirmation_args.extend(["--as", "event-bank-reviewer"]);
    let (code, out) = run(true, &confirmation_args);
    assert_eq!(code, 0, "{out}");
    let confirmed = doc(&out);
    assert_eq!(confirmed.get("entry_ref"), bank_proposal.get("entry_ref"));
    assert_eq!(
        text(&confirmed, "proposal_digest"),
        text(bank_proposal, "proposal_digest")
    );
    assert_eq!(
        text(&confirmed, "confirmed_by"),
        format!("{:032x}", fa_model::principal_vid("event-bank-reviewer").0)
    );
    let (code, out) = run(
        true,
        &[
            "bank",
            "status",
            "--import",
            &manifest,
            "--grant",
            "privileged",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let confirmation_status = doc(&out);
    assert_eq!(int(&confirmation_status, "confirmed_lines"), Some(1));
    assert_eq!(int(&confirmation_status, "remaining_lines"), Some(0));
    assert_eq!(
        confirmation_status.get("reconciled_through"),
        Some(&Json::Null)
    );
    let (code, out) = run(true, &["bank", "history", "--import", &manifest]);
    assert_eq!(code, 0, "{out}");
    let history = doc(&out);
    assert_eq!(int(&history, "confirmation_count"), Some(1));
    assert_eq!(int(&history, "active_count"), Some(1));
    let (code, out) = run(
        true,
        &[
            "bank",
            "unmatch",
            "--match",
            text(&confirmed, "match_vid"),
            "--digest",
            text(&confirmed, "match_digest"),
            "--yes",
        ],
    );
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        text(
            doc(&out)
                .get("target")
                .expect("exact released confirmation"),
            "vid"
        ),
        text(&confirmed, "match_vid")
    );
    let (code, out) = run(true, &["bank", "history", "--import", &manifest]);
    assert_eq!(code, 0, "{out}");
    let history = doc(&out);
    assert_eq!(int(&history, "confirmation_count"), Some(1));
    assert_eq!(int(&history, "unmatch_count"), Some(1));
    assert_eq!(int(&history, "active_count"), Some(0));
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
    // --output writes the replayed bytes and emits the `report_replayed` receipt.
    let replayed = dir.join("replayed.report").display().to_string();
    assert_eq!(
        run(true, &["replay", &certificate, "--output", &replayed]).0,
        0
    );
    assert_eq!(run(true, &["certificate", "status", &certificate]).0, 0);
    assert_eq!(
        run(true, &["statement", "balance-sheet", "--for", "FY2026-P03"]).0,
        0
    );
    // A restatement case (fa-75j4): opened, determined, read.
    assert_eq!(
        run(
            true,
            &[
                "case",
                "open",
                "--kind",
                "Restatement",
                "--periods",
                "FY2026-P03"
            ]
        )
        .0,
        0
    );
    assert_eq!(
        run(
            true,
            &[
                "case",
                "determine",
                "1",
                "--on",
                "2026-04-02",
                "--authority",
                &ev
            ]
        )
        .0,
        0
    );
    // Rehearsed on a scenario whose diff certificate covers the period.
    assert_eq!(
        run(true, &["scenario", "fork", "restated", "--as", "analyst"]).0,
        0
    );
    let restated = write(&dir, "restated.json", &draft_intent("restated-rent"));
    assert_eq!(
        run(
            true,
            &[
                "scenario", "run", "restated", "--intent", &restated, "--as", "analyst"
            ]
        )
        .0,
        0
    );
    let rehearsal = dir.join("rehearsal.cert").display().to_string();
    assert_eq!(
        run(
            true,
            &[
                "scenario",
                "diff",
                "restated",
                "--period",
                "FY2026-P03",
                "--certificate-out",
                &rehearsal
            ]
        )
        .0,
        0
    );
    let (code, out) = run(
        true,
        &["case", "rehearse", "1", "--certificate", &rehearsal],
    );
    assert_eq!(code, 0, "{out}");
    let rehearsed = doc(&out);
    let case = rehearsed.get("case").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&case, "state"), "Rehearsed", "{out}");
    let attached = case.get("rehearsal").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&attached, "scenario"), "restated", "{out}");
    assert_eq!(arr(&attached, "intents").len(), 1, "{out}");
    // Approved under dual control (fa-75j4 slice 3): the analyst planned
    // the case's entry, so the analyst's approval is refused.
    let (code, out) = run(true, &["case", "approve", "1", "--dry-run"]);
    assert_eq!(code, 0, "{out}");
    let manifest = doc(&out);
    assert_eq!(arr(&manifest, "entries").len(), 1, "{out}");
    let digest = text(&manifest, "digest").to_string();
    let mut approval = |who: &str| {
        let (code, out) = run(true, &["approve", "--proposal", &digest, "--as", who]);
        assert_eq!(code, 0, "{out}");
        text(&doc(&out), "approval_vid").to_string()
    };
    let by_analyst = approval("analyst");
    let by_controller = approval("controller");
    let by_auditor = approval("auditor");
    let (code, out) = run(
        true,
        &[
            "case",
            "approve",
            "1",
            "--approval",
            &by_analyst,
            "--approval",
            &by_controller,
        ],
    );
    assert_eq!(code, 7, "{out}");
    assert!(out.contains("prepared an entry in this case"), "{out}");
    let (code, out) = run(
        true,
        &[
            "case",
            "approve",
            "1",
            "--approval",
            &by_controller,
            "--approval",
            &by_auditor,
        ],
    );
    assert_eq!(code, 0, "{out}");
    let approved = doc(&out);
    let case = approved.get("case").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&case, "state"), "Approved", "{out}");
    assert_eq!(run(true, &["case", "approve", "1"]).0, 2);
    assert_eq!(run(true, &["case", "show", "1"]).0, 0);
    assert_eq!(run(true, &["case", "list"]).0, 0);
    // A PriorPeriodAdjustment case posts its approved entry (fa-75j4 slice
    // 4a): planned by the analyst on a scenario, approved by two Humans who
    // planned nothing, posted in one batch with its Post record, once.
    let (code, out) = run(
        true,
        &[
            "case",
            "open",
            "--kind",
            "PriorPeriodAdjustment",
            "--periods",
            "FY2026-P03",
            "--determined-on",
            "2026-04-02",
            "--authority",
            &ev,
        ],
    );
    assert_eq!(code, 0, "{out}");
    let opened = doc(&out).get("case").cloned().unwrap_or(Json::Null);
    assert_eq!(int(&opened, "case"), Some(2), "{out}");
    assert_eq!(text(&opened, "state"), "Determined", "{out}");
    assert_eq!(
        run(true, &["scenario", "fork", "adjusted", "--as", "analyst"]).0,
        0
    );
    let adjusted = write(&dir, "adjusted.json", &draft_intent("adjusted-rent"));
    assert_eq!(
        run(
            true,
            &[
                "scenario", "run", "adjusted", "--intent", &adjusted, "--as", "analyst"
            ]
        )
        .0,
        0
    );
    let adjusting = dir.join("adjusting.cert").display().to_string();
    assert_eq!(
        run(
            true,
            &[
                "scenario",
                "diff",
                "adjusted",
                "--period",
                "FY2026-P03",
                "--certificate-out",
                &adjusting
            ]
        )
        .0,
        0
    );
    let (code, out) = run(
        true,
        &["case", "rehearse", "2", "--certificate", &adjusting],
    );
    assert_eq!(code, 0, "{out}");
    let (code, out) = run(true, &["case", "approve", "2", "--dry-run"]);
    assert_eq!(code, 0, "{out}");
    let adjustment_digest = text(&doc(&out), "digest").to_string();
    let mut approve_adjustment = |who: &str| {
        let (code, out) = run(
            true,
            &["approve", "--proposal", &adjustment_digest, "--as", who],
        );
        assert_eq!(code, 0, "{out}");
        text(&doc(&out), "approval_vid").to_string()
    };
    let by_controller = approve_adjustment("controller");
    let by_auditor = approve_adjustment("auditor");
    let (code, out) = run(
        true,
        &[
            "case",
            "approve",
            "2",
            "--approval",
            &by_controller,
            "--approval",
            &by_auditor,
        ],
    );
    assert_eq!(code, 0, "{out}");
    // An approver may not post what they approved: the entry's own
    // PriorPeriodAdjustment row excludes its preparer.
    let (code, out) = run(true, &["case", "post", "2", "--as", "controller"]);
    assert_eq!(code, 7, "{out}");
    let (code, out) = run(true, &["case", "post", "2"]);
    assert_eq!(code, 0, "{out}");
    let posted = doc(&out);
    assert_eq!(posted.get("already_recorded"), Some(&Json::Bool(false)));
    let case = posted.get("case").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&case, "state"), "Posted", "{out}");
    let entries = arr(&case, "posted");
    assert_eq!(entries.len(), 1, "{out}");
    let entry = text(&entries[0], "entry").to_string();
    let (code, out) = run(true, &["explain", "entry", &entry]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("PriorPeriodAdjustment"), "{out}");
    let (code, out) = run(true, &["case", "post", "2"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(doc(&out).get("already_recorded"), Some(&Json::Bool(true)));
    // Disclosed in a Disclosure document once another principal reviewed
    // it (fa-75j4 slice 5), then closed.
    let note = write(
        &dir,
        "disclosure.txt",
        "Note 2: correction of an error in the prior period",
    );
    let (code, out) = run(
        true,
        &[
            "document",
            "add",
            &note,
            "--kind",
            "Disclosure",
            "--grade",
            "HumanUpload",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let note_oid = field(&out, "oid").unwrap_or_default().to_string();
    let (code, out) = run(true, &["case", "disclose", "2", "--document", &note_oid]);
    assert_eq!(code, 3, "an unreviewed disclosure is refused: {out}");
    assert!(out.contains("FA-REF-179"), "{out}");
    assert_eq!(
        run(true, &["attest", "review", &note_oid, "--as", "reviewer"]).0,
        0
    );
    let (code, out) = run(true, &["case", "disclose", "2", "--document", &note_oid]);
    assert_eq!(code, 0, "{out}");
    let case = doc(&out).get("case").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&case, "state"), "Disclosed", "{out}");
    let (code, out) = run(true, &["case", "close", "2"]);
    assert_eq!(code, 0, "{out}");
    let case = doc(&out).get("case").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&case, "state"), "Closed", "{out}");
    // A statement issuance (fa-wrrw): planned, approved in another hand,
    // committed from the exact plan, then listed.
    let (code, out) = run(
        true,
        &[
            "statement",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--certify",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let issued = field(&out, "oid").unwrap_or_default().to_string();
    let (code, out) = run(
        true,
        &[
            "statement",
            "issue",
            "--certificate",
            &issued,
            "--issued-to",
            "auditor",
            "--dry-run",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let issue_plan = write(&dir, "issue.plan", field(&out, "bytes").unwrap_or_default());
    let issue_digest = field(&out, "proposal_digest")
        .unwrap_or_default()
        .to_string();
    let (code, out) = run(
        true,
        &["approve", "--proposal", &issue_digest, "--as", "controller"],
    );
    assert_eq!(code, 0, "{out}");
    let issue_approval = field(&out, "approval_vid").unwrap_or_default().to_string();
    let (code, out) = run(
        true,
        &[
            "statement",
            "issue",
            "--plan",
            &issue_plan,
            "--approval",
            &issue_approval,
        ],
    );
    assert_eq!(code, 0, "{out}");
    assert_eq!(run(true, &["statement", "issuances"]).0, 0);
    assert_eq!(
        run(
            true,
            &["statement", "lint", "--definition", "balance-sheet"]
        )
        .0,
        0
    );
    let (code, out) = run(
        true,
        &[
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--present-in",
            "thousands",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let (code, out) = run(true, &["access", "log"]);
    assert_eq!(code, 0, "{out}");
    let (code, out) = run(true, &["registers", "advance", "--period", "FY2026-P03"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        run(true, &["verify", "registers", "--period", "FY2026-P03"]).0,
        0
    );
    // A planned, approved lock (R4): `period_planned`, then `approved`.
    assert_eq!(run(true, &["period", "open", "FY2026-P04"]).0, 0);
    assert_eq!(
        run(
            true,
            &[
                "period",
                "close",
                "FY2026-P04",
                "--reason",
                "Scheduled",
                "--yes"
            ]
        )
        .0,
        0
    );
    assert_eq!(
        run(
            true,
            &[
                "period",
                "lock",
                "FY2026-P04",
                "--reason",
                "Scheduled",
                "--dry-run"
            ]
        )
        .0,
        0
    );
    let plan = dir.join("lock.plan").display().to_string();
    let (code, out) = run(
        true,
        &[
            "period",
            "lock",
            "FY2026-P04",
            "--reason",
            "Scheduled",
            "--plan-out",
            &plan,
        ],
    );
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

    // Additional report, docket, steward, migration, allocation, and settlement events.
    let book2 = dir.join("book2");
    let mut run2 = |args: &[&str]| -> (i32, String) {
        let mut argv = args.to_vec();
        argv.push("--json");
        let (code, out, err) = fa(Some(book2.as_path()), &argv);
        assert_eq!(code, 0, "args={argv:?}\n{out}\n{err}");
        seen.extend(check_robot_output(&argv, code, &out));
        (code, out)
    };
    run2(&[
        "book",
        "create",
        "--name",
        "Events Co 2",
        "--opening-date",
        "2026-01-01",
    ]);
    let chart2 = write(
        &dir,
        "chart2.json",
        r#"{"accounts":[
            {"code":"100","name":"Assets","type":"Asset","leaf":false,"unit":"USD"},
            {"code":"1000","name":"Cash","type":"Asset","parent":"100","leaf":true,"unit":"USD"},
            {"code":"1400","name":"Inventory","type":"Asset","parent":"100","leaf":true,"unit":"any"},
            {"code":"3000","name":"Equity","type":"Equity","leaf":true,"unit":"USD"},
            {"code":"6000","name":"Rent","type":"Expense","leaf":true,"unit":"USD"}
        ]}"#,
    );
    run2(&["chart", "import", &chart2, "--date", "2026-01-01"]);
    run2(&["period", "create", "--fiscal-year", "2026"]);
    run2(&["period", "open", "FY2026-P01"]);
    let close_plan = dir.join("p01_close.plan").display().to_string();
    let (_, cp_out) = run2(&[
        "period",
        "close",
        "FY2026-P01",
        "--reason",
        "Scheduled",
        "--plan-out",
        &close_plan,
    ]);
    let cp_digest = field(&cp_out, "proposal_digest")
        .unwrap_or_default()
        .to_string();
    let (_, cp_app_out) = run2(&["approve", "--proposal", &cp_digest, "--as", "controller"]);
    let cp_app = field(&cp_app_out, "approval_vid")
        .unwrap_or_default()
        .to_string();
    run2(&[
        "period",
        "close",
        "FY2026-P01",
        "--plan",
        &close_plan,
        "--approval",
        &cp_app,
    ]);
    let lock_plan = dir.join("p01_lock.plan").display().to_string();
    let (_, lp_out) = run2(&[
        "period",
        "lock",
        "FY2026-P01",
        "--reason",
        "Scheduled",
        "--plan-out",
        &lock_plan,
    ]);
    let lp_digest = field(&lp_out, "proposal_digest")
        .unwrap_or_default()
        .to_string();
    let (_, lp_app_out) = run2(&["approve", "--proposal", &lp_digest, "--as", "controller"]);
    let lp_app = field(&lp_app_out, "approval_vid")
        .unwrap_or_default()
        .to_string();
    run2(&[
        "period",
        "lock",
        "FY2026-P01",
        "--plan",
        &lock_plan,
        "--approval",
        &lp_app,
    ]);
    run2(&["period", "open", "FY2026-P03"]);

    run2(&["tb", "--summary", "--period", "FY2026-P03"]);
    run2(&[
        "gl",
        "detail",
        "--account",
        "1000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
    ]);
    run2(&[
        "gl",
        "roll-forward",
        "--account",
        "1000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
    ]);
    run2(&["gl", "aging", "--as-of", "2026-03-25", "--account", "1000"]);
    run2(&[
        "aging",
        "--as-of",
        "2026-03-25",
        "--account",
        "1000",
        "--reconcile",
    ]);
    run2(&[
        "gl",
        "aging",
        "--as-of",
        "2026-03-25",
        "--all-posting",
        "--reconcile",
    ]);
    run2(&["lots", "--account", "1400"]);
    let cf_direct = write(
        &dir,
        "cf_direct.json",
        r#"{"name":"cf-d","cash_accounts":["1000"],"assignments":[]}"#,
    );
    run2(&[
        "gl",
        "cash-flow",
        "--account",
        "1000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--policy",
        &cf_direct,
    ]);
    let cf_rules = write(
        &dir,
        "cf_rules.json",
        r#"{"name":"cf-r","cash_accounts":["1000"],"account_rules":[{"account":"6000","activity":"operating"}]}"#,
    );
    run2(&[
        "gl",
        "cash-flow",
        "--account",
        "1000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--policy",
        &cf_rules,
    ]);
    let cf_split = write(
        &dir,
        "cf_split.json",
        r#"{"name":"cf-s","cash_accounts":["1000"],"splits":[]}"#,
    );
    run2(&[
        "gl",
        "cash-flow",
        "--account",
        "1000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--policy",
        &cf_split,
    ]);
    let cf_indirect = write(
        &dir,
        "cf_indirect.json",
        r#"{"name":"cf-i","cash_policy":"cf-d","cash_accounts":["1000"],"assignments":[],"adjustments":[]}"#,
    );
    run2(&[
        "gl",
        "cash-flow",
        "--indirect",
        "--income-period",
        "FY2026-P03",
        "--account",
        "1000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--policy",
        &cf_indirect,
    ]);
    run2(&["statement", "lint", "--definition", "balance-sheet"]);
    run2(&[
        "statement",
        "diff",
        "--definition",
        "balance-sheet",
        "--for",
        "FY2026-P03",
        "--before",
        "8",
        "--after",
        "HEAD",
    ]);
    run2(&[
        "statement",
        "trace",
        "--definition",
        "balance-sheet",
        "--for",
        "FY2026-P03",
        "--before",
        "8",
        "--after",
        "HEAD",
    ]);
    let trace_certificate = dir.join("trace.cert").display().to_string();
    run2(&[
        "statement",
        "trace",
        "--definition",
        "balance-sheet",
        "--for",
        "FY2026-P03",
        "--before",
        "8",
        "--after",
        "HEAD",
        "--certificate-out",
        &trace_certificate,
    ]);
    let trace_workpaper = dir.join("trace.jsonl").display().to_string();
    run2(&[
        "replay",
        &trace_certificate,
        "--workpaper-out",
        &trace_workpaper,
    ]);

    let mut bank_bytes = String::from("HEADER_PAGE_1_ACCOUNT_NUMBER_SECRET\n");
    while bank_bytes.len() < 4096 {
        bank_bytes.push('A');
    }
    bank_bytes.push_str("CHUNK_1_DISCLOSED_STATEMENT_LINES\n");
    let bank_path = write(&dir, "bank_ev.txt", &bank_bytes);
    let (_, added_bank) = run2(&[
        "document",
        "add",
        &bank_path,
        "--kind",
        "BankStatement",
        "--grade",
        "AgentUpload",
    ]);
    let bank_oid = field(&added_bank, "oid").unwrap_or_default().to_string();
    run2(&["document", "redact", &bank_oid, "--grant", "privileged"]);
    run2(&["document", "read", &bank_oid]);
    run2(&["document", "disclose", &bank_oid, "--chunk", "1"]);
    run2(&["document", "custody", &bank_oid, "--to", "records_clerk"]);
    run2(&["document", "custody", &bank_oid]);
    run2(&["attest", "review", &bank_oid, "--as", "reviewer"]);
    let fee_entry = write(
        &dir,
        "fee_ev.json",
        r#"{"effective_date":"2026-03-10","idempotency_key":"ev-fee","legs":[{"side":"debit","account":"6000","amount":"25.00 USD"},{"side":"credit","account":"1000","amount":"25.00 USD"}],"description":"Fee"}"#,
    );
    let (_, fee_posted) = run2(&["post", "--intent", &fee_entry, "--evidence", &bank_oid]);
    let fee_vid = field(&fee_posted, "vid").unwrap_or_default().to_string();
    run2(&["checkpoint", "create", "--grant", "witness"]);
    run2(&[
        "proof",
        "evidence-disclosure",
        "--entry",
        &fee_vid,
        "--document",
        &bank_oid,
        "--chunk",
        "1",
    ]);

    let order_path = write(&dir, "order_ev.txt", "PRESERVATION ORDER");
    let (_, added_order) = run2(&[
        "document",
        "add",
        &order_path,
        "--kind",
        "CourtOrder",
        "--grade",
        "HumanUpload",
    ]);
    let order_oid = field(&added_order, "oid").unwrap_or_default().to_string();
    let (_, placed_hold) = run2(&[
        "hold",
        "place",
        "--authority",
        &order_oid,
        "--subject",
        &bank_oid,
        "--effective",
        "2026-03-15",
        "--description",
        "Hold",
    ]);
    let hold_vid = field(&placed_hold, "hold_vid")
        .unwrap_or_default()
        .to_string();
    run2(&["hold", "show", &hold_vid]);
    run2(&["hold", "list", "--subject", &bank_oid]);
    let rel_plan = dir.join("rel_ev.plan").display().to_string();
    let (_, rel_planned) = run2(&[
        "hold",
        "release",
        &hold_vid,
        "--effective",
        "2026-03-20",
        "--plan-out",
        &rel_plan,
    ]);
    let rel_digest = field(&rel_planned, "proposal_digest")
        .unwrap_or_default()
        .to_string();
    let (_, rel_app_out) = run2(&[
        "approve",
        "--proposal",
        &rel_digest,
        "--as",
        "general_counsel",
    ]);
    let rel_app = field(&rel_app_out, "approval_vid")
        .unwrap_or_default()
        .to_string();
    run2(&[
        "hold",
        "release",
        &hold_vid,
        "--plan",
        &rel_plan,
        "--approval",
        &rel_app,
    ]);

    let tb_doc_path = write(&dir, "tb_ev.json", r#"{"legacy":"tb"}"#);
    let (_, added_tb) = run2(&[
        "document",
        "add",
        &tb_doc_path,
        "--kind",
        "Spreadsheet",
        "--grade",
        "HumanUpload",
    ]);
    let tb_oid = field(&added_tb, "oid").unwrap_or_default().to_string();
    let mig_open = write(
        &dir,
        "mig_open_ev.json",
        &format!(
            r#"{{
                "run_key":"mig-ev",
                "source_system":"legacy",
                "mode":"OpeningOnly",
                "trial_balance":"{tb_oid}",
                "opening_date":"2026-01-01",
                "lines":[
                    {{"account":"1000","unit":"USD","debit":"500.00"}},
                    {{"account":"3000","unit":"USD","credit":"500.00"}}
                ]
            }}"#
        ),
    );
    let (_, mig_opened) = run2(&["migrate", "open", "--intent", &mig_open]);
    let run_vid = field(&mig_opened, "run_vid")
        .unwrap_or_default()
        .to_string();
    run2(&["migrate", "show", &run_vid]);
    let mig_plan = dir.join("mig_ev.plan").display().to_string();
    run2(&["migrate", "abandon", "mig-ev", "--plan-out", &mig_plan]);

    let alloc_ev = write(
        &dir,
        "alloc_ev.json",
        r#"{"source":"6000","source_side":"credit","total":"1.00 USD","effective_date":"2026-03-20","idempotency_key":"alloc-ev","method":"largest_remainder","targets":[{"account":"1000","weight":1}]}"#,
    );
    run2(&["allocate", "--intent", &alloc_ev, "--review-only"]);
    let settle_ev = write(
        &dir,
        "settle_ev.json",
        &format!(
            r#"{{"effective_date":"2026-03-20","idempotency_key":"settle-ev","evidence":["{bank_oid}"],"legs":[{{"side":"debit","account":"1000","amount":"25.00 USD"}},{{"side":"credit","account":"6000","amount":"25.00 USD"}}],"payment_leg":0,"targets":[{{"entry":"{fee_vid}","ordinal":1}}]}}"#
        ),
    );
    run2(&["settle", "--intent", &settle_ev, "--review-only"]);
    run2(&["explain", "entry", &fee_vid]);
    run2(&["explain", "lineage", &fee_vid]);
    run2(&["document", "attach", &fee_vid, "--evidence", &bank_oid]);
    run2(&["explain", "evidence", &fee_vid]);
    run2(&["explain", "period", "FY2026-P03"]);
    run2(&["explain", "refusal", "FA-REF-001"]);
    run2(&[
        "explain",
        "register",
        "1000",
        "--period",
        "FY2026-P03",
        "--unit",
        "USD",
    ]);
    let (_, imp_ev) = run2(&[
        "document",
        "import",
        "run",
        &tb_doc_path,
        "--source",
        "Connector",
        "--key",
        "imp-ev",
    ]);
    let imp_vid = field(&imp_ev, "run_vid").unwrap_or_default().to_string();
    run2(&["document", "import", "receipt", &imp_vid]);
    run2(&[
        "event",
        "record",
        "--code",
        "EV-1001",
        "--kind",
        "sale",
        "--occurred-on",
        "2026-03-15",
        "--evidence",
        &bank_oid,
    ]);
    run2(&["event", "show", "EV-1001"]);
    run2(&["event", "list"]);
    run2(&["verify", "periods"]);
    run2(&[
        "capability",
        "revoke",
        "--commitment",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "--grant",
        "issue_capability",
        "--yes",
    ]);
    // Issuance (fa-v62): the issuer holds every op it grants.
    let ev_token = dir.join("ev-agent.token").display().to_string();
    let (_, issued) = run2(&[
        "capability",
        "issue",
        "--holder",
        "ev-agent",
        "--profile",
        "agent",
        "--op",
        "read",
        "--op",
        "post",
        "--out",
        &ev_token,
        "--grant",
        "issue_capability",
        "--grant",
        "read",
        "--grant",
        "post",
    ]);
    let ev_commitment = field(&issued, "commitment").unwrap_or_default().to_string();
    run2(&["capability", "list"]);
    run2(&["capability", "show", "--commitment", &ev_commitment]);
    let demo_dir = dir.join("demo-ev");
    let demo_args = [
        "demo",
        "init",
        "--scenario",
        "retail",
        "--seed",
        "7",
        "--json",
    ];
    let (dc, do_, derr) = fa(Some(&demo_dir), &demo_args);
    assert_eq!(dc, 0, "{do_}\n{derr}");
    seen.extend(check_robot_output(&demo_args, dc, &do_));

    // Year-end closing (fa-4o0): routes, review, close, verification and a
    // zero re-close, the workflow tests/closing.rs exercises in depth.
    let book3 = dir.join("book3");
    let mut run3 = |args: &[&str]| -> String {
        let mut argv = args.to_vec();
        argv.push("--json");
        let (code, out, err) = fa(Some(book3.as_path()), &argv);
        assert_eq!(code, 0, "args={argv:?}\n{out}\n{err}");
        seen.extend(check_robot_output(&argv, code, &out));
        out
    };
    run3(&[
        "book",
        "create",
        "--name",
        "Events Co 3",
        "--opening-date",
        "2026-01-01",
    ]);
    let chart3 = write(
        &dir,
        "chart3.json",
        r#"{"accounts":[
            {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
            {"code":"3000","name":"Retained earnings","type":"Equity","unit":"USD"},
            {"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}
        ]}"#,
    );
    run3(&["chart", "import", &chart3]);
    run3(&["period", "create", "--fiscal-year", "2026"]);
    run3(&["period", "open", "FY2026-P12"]);
    run3(&["period", "open", "FY2026-CLOSE"]);
    let workpaper = write(
        &dir,
        "workpaper.txt",
        "Reviewed workpaper documenting the year's sales and their closing computation.",
    );
    let added = run3(&[
        "document",
        "add",
        &workpaper,
        "--kind",
        "Workpaper",
        "--grade",
        "HumanUpload",
    ]);
    let workpaper_oid = field(&added, "oid").unwrap_or_default().to_string();
    run3(&[
        "close",
        "map",
        "--route",
        "4000:3000",
        "--effective-from",
        "2026-01-01",
        "--key",
        "routes-2026",
    ]);
    run3(&["close", "routes", "--as-of", "2026-12-31"]);
    let sale = write(
        &dir,
        "year-sale.json",
        r#"{"effective_date":"2026-12-30","idempotency_key":"year-sale","legs":[{"side":"debit","account":"1000","amount":"100.00 USD"},{"side":"credit","account":"4000","amount":"100.00 USD"}]}"#,
    );
    run3(&["post", "--intent", &sale, "--evidence", &workpaper_oid]);
    let review_out = dir.join("year-end.review").display().to_string();
    run3(&[
        "close",
        "year-end",
        "--fiscal-year",
        "2026",
        "--period",
        "FY2026-CLOSE",
        "--key",
        "first",
        "--evidence",
        &workpaper_oid,
        "--review-out",
        &review_out,
    ]);
    run3(&[
        "close",
        "year-end",
        "--fiscal-year",
        "2026",
        "--period",
        "FY2026-CLOSE",
        "--key",
        "first",
        "--evidence",
        &workpaper_oid,
        "--yes",
    ]);
    run3(&["verify", "close", "FY2026"]);
    let zero = run3(&[
        "close",
        "year-end",
        "--fiscal-year",
        "2026",
        "--period",
        "FY2026-CLOSE",
        "--key",
        "zero",
        "--evidence",
        &workpaper_oid,
        "--yes",
    ]);
    assert_eq!(field(&zero, "event"), Some("closing_noop"), "{zero}");

    // A mid-year book supplies a native locked Opening period. A distinct
    // retained source and trial balance produce one sealed migration chunk,
    // which two independent reviewers approve before staging.
    let book4 = dir.join("legacy-events-book");
    let mut run4 = |args: &[&str]| -> String {
        let mut argv = args.to_vec();
        argv.push("--json");
        let (code, out, err) = fa(Some(book4.as_path()), &argv);
        assert_eq!(code, 0, "args={argv:?}\n{out}\n{err}");
        seen.extend(check_robot_output(&argv, code, &out));
        out
    };
    run4(&[
        "book",
        "create",
        "--name",
        "Legacy source event coverage",
        "--opening-date",
        "2026-07-01",
    ]);
    let legacy_chart = write(
        &dir,
        "legacy-events-chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"3000","name":"Opening equity","type":"Equity","unit":"USD"}]}"#,
    );
    run4(&["chart", "import", &legacy_chart]);
    run4(&["period", "create", "--fiscal-year", "2026"]);
    let legacy_source = write(
        &dir,
        "legacy-events-source.csv",
        "Transaction ID,Date,Account,Debit,Credit,Currency,Memo/Description,Created At,Created By\n\
robot-opening,2025-12-20,Legacy Cash,125.50,,USD,Cash source,2025-12-20T12:30:00Z,legacy-author\n\
robot-opening,2025-12-20,Legacy Equity,,125.50,USD,Equity source,2025-12-20T12:30:00Z,legacy-author\n",
    );
    let source_added = run4(&[
        "document",
        "add",
        &legacy_source,
        "--kind",
        "Spreadsheet",
        "--mime",
        "text/csv",
        "--grade",
        "HumanUpload",
    ]);
    let legacy_source_oid = text(&doc(&source_added), "oid").to_string();
    let legacy_tb = write(
        &dir,
        "legacy-events-tb.csv",
        "account,unit,debit,credit\n1000,USD,125.50,\n3000,USD,,125.50\n",
    );
    let tb_added = run4(&[
        "document",
        "add",
        &legacy_tb,
        "--kind",
        "Spreadsheet",
        "--mime",
        "text/csv",
        "--grade",
        "HumanUpload",
    ]);
    let legacy_tb_oid = text(&doc(&tb_added), "oid").to_string();
    assert_ne!(legacy_source_oid, legacy_tb_oid);
    let legacy_run_intent = write(
        &dir,
        "legacy-events-run.json",
        &format!(
            r#"{{"run_key":"legacy-events","source_system":"quickbooks-csv","mode":"OpeningOnly","trial_balance":"{legacy_tb_oid}","opening_date":"2026-01-01","lines":[{{"account":"1000","unit":"USD","debit":"125.50"}},{{"account":"3000","unit":"USD","credit":"125.50"}}]}}"#
        ),
    );
    let opened = run4(&["migrate", "open", "--intent", &legacy_run_intent]);
    let legacy_run = text(&doc(&opened), "run_vid").to_string();
    let legacy_import_intent = write(
        &dir,
        "legacy-events-import.json",
        &format!(
            r#"{{"run":"MR:{legacy_run}","source":"D:{legacy_source_oid}","format":"quickbooks-csv","account_map":{{"Legacy Cash":"1000","Legacy Equity":"3000"}}}}"#
        ),
    );
    let prepared = doc(&run4(&[
        "migrate",
        "import",
        "--action",
        "prepare",
        "--intent",
        &legacy_import_intent,
    ]));
    assert_eq!(int(&prepared, "row_count"), Some(2));
    assert_eq!(int(&prepared, "chunk_count"), Some(1));
    assert_eq!(int(&prepared, "recorded_count"), Some(0));
    let package = text(&prepared, "package_oid").to_string();
    let [chunk] = arr(&prepared, "chunks") else {
        panic!("one complete source journal entry: {}", prepared.render());
    };
    let chunk_digest = text(chunk, "proposal_digest").to_string();
    let shown = doc(&run4(&[
        "migrate",
        "import",
        "--action",
        "show",
        "--package",
        &package,
    ]));
    assert_eq!(text(&shown, "package_oid"), package);
    assert_eq!(shown.get("chunks"), prepared.get("chunks"));
    let first_approval = doc(&run4(&[
        "approve",
        "--proposal",
        &chunk_digest,
        "--as",
        "legacy-event-reviewer-one",
    ]));
    let second_approval = doc(&run4(&[
        "approve",
        "--proposal",
        &chunk_digest,
        "--as",
        "legacy-event-reviewer-two",
    ]));
    let first_approval = text(&first_approval, "approval_vid");
    let second_approval = text(&second_approval, "approval_vid");
    assert_ne!(first_approval, second_approval);
    let staged = doc(&run4(&[
        "migrate",
        "import",
        "--action",
        "stage",
        "--package",
        &package,
        "--chunk",
        "0",
        "--approval",
        first_approval,
        "--approval",
        second_approval,
    ]));
    assert_eq!(text(&staged, "proposal_digest"), chunk_digest);
    assert_eq!(int(&staged, "recorded_count"), Some(1));
    assert_eq!(int(&staged, "chunk_count"), Some(1));
    assert_eq!(staged.get("already_recorded"), Some(&Json::Bool(false)));
    assert_eq!(staged.get("ready_to_finalize"), Some(&Json::Bool(true)));
    let opening_tb = doc(&run4(&["tb", "--period", "FY2026-OPEN"]));
    assert!(
        arr(&opening_tb, "rows").is_empty(),
        "staging remains invisible until native finalization"
    );

    // An exact statement close is exercised in its own book, so the preceding
    // event fixtures do not accidentally contribute unrelated cash activity.
    let book5 = dir.join("bank-close-events-book");
    let mut run5 = |args: &[&str]| -> String {
        let mut argv = args.to_vec();
        argv.push("--json");
        let (code, out, err) = fa(Some(book5.as_path()), &argv);
        assert_eq!(code, 0, "{argv:?}: {out}\n{err}");
        seen.extend(check_robot_output(&argv, code, &out));
        out
    };
    run5(&["book", "create", "--name", "Bank close events"]);
    let close_chart = write(
        &dir,
        "bank-close-chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    );
    run5(&["chart", "import", &close_chart]);
    run5(&["period", "create", "--fiscal-year", "2026"]);
    run5(&["period", "open", "FY2026-P03"]);
    let close_source = write(
        &dir,
        "bank-close-source.txt",
        "Receipt for the bank close fixture",
    );
    let close_evidence = doc(&run5(&[
        "document",
        "add",
        &close_source,
        "--kind",
        "Receipt",
        "--grade",
        "HumanUpload",
    ]));
    let close_evidence = text(&close_evidence, "oid");
    let close_cash = write(
        &dir,
        "bank-close-cash.json",
        r#"{"effective_date":"2026-03-05","idempotency_key":"events-bank-close-cash","legs":[{"side":"debit","account":"1000","amount":"10.00 USD","memo":"RECON-EVENT"},{"side":"credit","account":"4000","amount":"10.00 USD"}]}"#,
    );
    run5(&[
        "post",
        "--intent",
        &close_cash,
        "--evidence",
        close_evidence,
    ]);
    let close_statement = write(
        &dir,
        "bank-close-statement.csv",
        "sequence_number,instrument_id,currency,statement_date,opening_balance,closing_balance,booking_date,value_date,side,amount,counterparty,reference\n\
1,BANK-CLOSE,USD,2026-03-31,0.00,10.00,2026-03-05,2026-03-05,CRDT,10.00,Payer,RECON-EVENT\n",
    );
    let close_import = doc(&run5(&[
        "bank",
        "import",
        &close_statement,
        "--bank-format",
        "csv",
        "--account",
        "1000",
    ]));
    let close_manifest = text(&close_import, "manifest_oid");
    let close_matches = doc(&run5(&[
        "bank",
        "match",
        "--import",
        close_manifest,
        "--grant",
        "privileged",
    ]));
    let [close_proposal] = arr(&close_matches, "proposals") else {
        panic!("one closing statement line: {}", close_matches.render());
    };
    let mut close_confirmation_args: Vec<_> = text(close_proposal, "confirmation_command")
        .strip_prefix("fa ")
        .expect("the proposal supplies its native confirmation command")
        .split_ascii_whitespace()
        .filter(|argument| *argument != "--json")
        .collect();
    close_confirmation_args.extend(["--as", "event-close-reviewer"]);
    let close_confirmation = doc(&run5(&close_confirmation_args));
    let close_reviewed = int(&close_confirmation, "recorded_at").unwrap().to_string();
    let closed = doc(&run5(&[
        "bank",
        "reconcile",
        "--import",
        close_manifest,
        "--source-known-at",
        &close_reviewed,
        "--grant",
        "privileged",
        "--yes",
    ]));
    let reconciliation = closed.get("reconciliation").unwrap();
    assert_eq!(text(reconciliation, "cash_balance"), "10.00 USD");
    assert_eq!(
        reconciliation.get("already_recorded"),
        Some(&Json::Bool(false))
    );
    let close_status = doc(&run5(&[
        "bank",
        "reconciliation",
        "--import",
        close_manifest,
    ]));
    assert_eq!(int(&close_status, "reconciliation_count"), Some(1));
    assert_eq!(int(&close_status, "drifted_count"), Some(0));
    assert_eq!(text(&close_status, "reconciled_through"), "2026-03-31");

    let rate_path = write(
        &dir,
        "event-fx-rate.json",
        r#"{"base_unit":"USD","quote_unit":"EUR","rate_num":"11","rate_den":"10","rounding":"HalfEven","as_of":"2026-03-31","retrieved_at_ns":1774915200000000000,"purpose":"period_close","source":"event fixture uploaded rate"}"#,
    );
    let rate = doc(&run5(&["fx", "rate", "add", "--from-json", &rate_path]));
    assert_eq!(text(&rate, "kind"), "Rate");
    assert_eq!(text(&rate, "grade"), "HumanUpload");
    let functional_activity = doc(&run5(&[
        "tb",
        "--functional",
        "--activity",
        "--period",
        "FY2026-P03",
    ]));
    assert_eq!(text(&functional_activity, "scope"), "period_activity");
    assert_eq!(text(&functional_activity, "base_unit"), "USD");
    let functional_stock = doc(&run5(&["tb", "--functional", "--as-of", "2026-03-31"]));
    assert_eq!(text(&functional_stock, "scope"), "stock");
    assert_eq!(text(&functional_stock, "effective_through"), "2026-03-31");
    assert_eq!(functional_stock.get("balanced"), Some(&Json::Bool(true)));

    let fx_book = dir.join("fx-revaluation-events-book");
    let mut run_fx = |args: &[&str]| -> String {
        let mut argv = args.to_vec();
        argv.push("--json");
        let (code, out, err) = fa(Some(&fx_book), &argv);
        assert_eq!(code, 0, "{argv:?}: {out}\n{err}");
        seen.extend(check_robot_output(&argv, code, &out));
        out
    };
    run_fx(&["book", "create", "--name", "Revaluation event source"]);
    let fx_chart = write(
        &dir,
        "fx-revaluation-chart.json",
        r#"{"accounts":[{"code":"1200","name":"EUR receivable","type":"Asset","unit":"EUR"},{"code":"4000","name":"EUR revenue","type":"Revenue","unit":"EUR"},{"code":"1290","name":"AR valuation","type":"Asset","unit":"USD"},{"code":"4900","name":"Unrealized FX","type":"Revenue","unit":"USD"}]}"#,
    );
    run_fx(&["chart", "import", &fx_chart]);
    run_fx(&["period", "create", "--fiscal-year", "2026"]);
    run_fx(&["period", "open", "FY2026-P03"]);
    run_fx(&[
        "fx",
        "routes",
        "set",
        "--route",
        "1200:1290:4900",
        "--effective-from",
        "2026-01-01",
        "--key",
        "fx-route-events",
    ]);
    let routes = doc(&run_fx(&["fx", "routes", "show", "--as-of", "2026-03-31"]));
    assert_eq!(arr(&routes, "routes").len(), 1);
    let spot_path = write(
        &dir,
        "fx-revaluation-spot.json",
        r#"{"base_unit":"USD","quote_unit":"EUR","rate_num":"1","rate_den":"1","rounding":"HalfEven","as_of":"2026-03-05","retrieved_at_ns":1772668800000000000,"purpose":"spot_close","source":"retained transaction quote"}"#,
    );
    let spot = doc(&run_fx(&["fx", "rate", "add", "--from-json", &spot_path]));
    let fx_invoice = write(
        &dir,
        "fx-revaluation-invoice.txt",
        "Actual FX invoice fixture",
    );
    let fx_evidence = doc(&run_fx(&[
        "document",
        "add",
        &fx_invoice,
        "--kind",
        "Invoice",
        "--grade",
        "HumanUpload",
    ]));
    let fx_intent = write(
        &dir,
        "fx-revaluation-post.json",
        &format!(
            r#"{{"effective_date":"2026-03-05","idempotency_key":"fx-event-invoice","legs":[{{"side":"debit","account":"1200","amount":"100.00 EUR"}},{{"side":"credit","account":"4000","amount":"100.00 EUR"}}],"fx":{{"law":"SpotClose","rates":["D:{}"]}}}}"#,
            text(&spot, "oid")
        ),
    );
    run_fx(&[
        "post",
        "--intent",
        &fx_intent,
        "--evidence",
        text(&fx_evidence, "oid"),
    ]);
    let close_rate = doc(&run_fx(&["fx", "rate", "add", "--from-json", &rate_path]));
    let closing_oid = format!("D:{}", text(&close_rate, "oid"));
    let reviewed = doc(&run_fx(&[
        "fx",
        "revalue",
        "--period",
        "FY2026-P03",
        "--account",
        "1200",
        "--rate",
        &closing_oid,
        "--key",
        "fx-event-revalue",
        "--review-only",
    ]));
    assert_eq!(text(&reviewed, "source_native_net"), "100.00 EUR");
    assert_eq!(text(&reviewed, "current_carrying_net"), "100.00 USD");
    assert_eq!(text(&reviewed, "delta"), "10.00 USD");
    run_fx(&[
        "fx",
        "revalue",
        "--review",
        text(&reviewed, "bytes"),
        "--digest",
        text(&reviewed, "review_digest"),
        "--yes",
    ]);
    let noop = doc(&run_fx(&[
        "fx",
        "revalue",
        "--period",
        "FY2026-P03",
        "--account",
        "1200",
        "--rate",
        &closing_oid,
        "--key",
        "fx-event-noop",
        "--yes",
    ]));
    assert_eq!(text(&noop, "current_carrying_net"), "110.00 USD");
    assert_eq!(text(&noop, "target_base_net"), "110.00 USD");

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
        Denial::CasePreparer {
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
            | Denial::CasePreparer { .. }
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

/// Every refusal-catalog fix template, and every reversal target class's
/// corrective route (the Reverses refusal's fix), names only registered
/// verbs or aliases, and a registered subcommand wherever its verb has
/// subcommands (fa-s3wz; plan §15.3 "errors that teach"): a fix that points
/// at a surface this build does not have is not a fix.
#[test]
fn refusal_catalog_fixes_name_only_registered_commands() {
    let reg = registry().expect("verbs.toml");
    let catalog =
        fa_registry::refusal_catalog::RefusalCatalog::embedded().expect("refusal_catalog.toml");
    let classes = fa_registry::EntryClasses::embedded().expect("entry_classes.toml");
    let targets = fa_registry::g0::SupersessionKinds::embedded(&classes)
        .expect("supersession_kinds.toml")
        .target_classes;
    // Prose, not commands: "replay with the fa executable whose registries..."
    // and "`fa` sends the command to the serving fad".
    const PROSE: &[&str] = &["fa executable", "fa sends"];
    let word = |t: &str| {
        t.trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '<'))
            .to_string()
    };
    let unregistered = |fix: &str| -> Vec<String> {
        let tokens: Vec<String> = fix.split_whitespace().map(word).collect();
        let mut bad = Vec::new();
        for (i, t) in tokens.iter().enumerate() {
            let next = tokens.get(i + 1).map_or("", String::as_str);
            if t != "fa" || PROSE.contains(&format!("fa {next}").as_str()) {
                continue;
            }
            let after = tokens.get(i + 2).map_or("", String::as_str);
            // An alias that expands to a verb and its subcommand (`fa hold`
            // is `fa document hold`) leaves no subcommand to check.
            let (name, sub) = match reg.alias(next).map(|a| a.expands.as_slice()) {
                Some([verb]) => (verb.as_str(), after),
                Some([verb, ..]) => (verb.as_str(), ""),
                Some([]) | None => (next, after),
            };
            let Some(verb) = reg.verb(name) else {
                bad.push(format!("fa {next}"));
                continue;
            };
            let names_a_sub = sub.starts_with(|c: char| c.is_ascii_lowercase());
            if !verb.subcommands.is_empty()
                && names_a_sub
                && !verb.subcommands.iter().any(|s| s == sub)
            {
                bad.push(format!("fa {next} {sub}"));
            }
        }
        bad
    };
    let mut commands = 0;
    let fixes = catalog
        .rows
        .iter()
        .map(|row| (row.code.as_str(), row.fix.as_str()))
        .chain(
            targets
                .iter()
                .map(|row| (row.class.as_str(), row.corrective_route.as_str())),
        );
    for (whose, fix) in fixes {
        assert!(
            unregistered(fix).is_empty(),
            "{whose} fix names {:?}, which verbs.toml does not register: {fix}",
            unregistered(fix)
        );
        commands += fix.matches("fa ").count();
    }
    assert!(commands >= 45, "the scan is not vacuous: {commands}");
    // Planted negatives: an unregistered verb, a subcommand the verb does not
    // have, and the route this bead replaced. An alias still passes.
    assert!(
        !reg.verb("period")
            .unwrap()
            .subcommands
            .iter()
            .any(|s| s == "freeze")
    );
    assert_eq!(
        unregistered(
            "consolidate with fa concordat merge, or fa period freeze FY2026-P03, or advance the watermark via `fa sweep`"
        ),
        ["fa concordat", "fa period freeze", "fa sweep"]
    );
    assert!(unregistered("release it with `fa hold release <hold-vid>`").is_empty());
}

/// A legal entity in another functional currency is refused at book
/// creation, and the fix it prints creates that entity's own book (fa-s3wz).
#[test]
fn a_functional_unit_refusal_prints_a_book_create_that_runs() -> std::io::Result<()> {
    let dir = tmp("functional-unit-fix")?;
    let (code, out, err) = fa(
        Some(&dir.join("group")),
        &[
            "book",
            "create",
            "--name",
            "Group",
            "--base-unit",
            "USD",
            "--entity",
            "EU:EU Sub:EUR",
            "--json",
        ],
    );
    assert_eq!(code, 3, "{out}\n{err}");
    let refusal = doc(&out);
    assert_eq!(text(&refusal, "refusal_id"), "FA-REF-003");
    let fix = text(&refusal, "fix");
    assert!(
        !fix.contains("Concordat") && fix.contains("not available yet (fa-76hy)"),
        "{fix}"
    );
    let command = fix
        .split_once("(fa ")
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(command, _)| command)
        .unwrap_or_else(|| panic!("no command in {fix}"));
    let argv: Vec<String> = command
        .split_whitespace()
        .map(|t| t.replace("<name>", "EU-Sub"))
        .chain(["--json".to_string()])
        .collect();
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let (code, out, err) = fa(Some(&dir.join("eu")), &argv);
    assert_eq!(code, 0, "the printed fix {argv:?} must run:\n{out}\n{err}");
    Ok(())
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
    ("close", Some("year-end"), "always"),
    ("bank", Some("reconcile"), "always"),
    ("bank", Some("unmatch"), "always"),
    // A period-end revaluation commits a reviewed adjustment (fa-3ock).
    ("fx", Some("revalue"), "always"),
    ("post", None, "grant:post_closed"),
    ("reverse", None, "grant:post_closed"),
    ("reclass", None, "grant:post_closed"),
    // Every verb that posts to trunk is dangerous under a post_closed grant.
    ("invoice", None, "grant:post_closed"),
    ("bill", None, "grant:post_closed"),
    ("receipt", None, "grant:post_closed"),
    ("payment", None, "grant:post_closed"),
    ("reserve", None, "grant:post_closed"),
    ("resolve", None, "grant:post_closed"),
    ("allocate", None, "grant:post_closed"),
    ("settle", None, "grant:post_closed"),
    ("resolve", None, "disposition:voids"),
    ("registers", Some("materialize"), "existing-cells"),
    // Recovery rewrites projection rows at HEAD; its dry run writes nothing.
    ("recover", Some("projections"), "always"),
    ("recover", Some("outcomes"), "always"),
    ("capability", Some("revoke"), "always"),
    ("draft", Some("promote"), "always"),
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
    let (code, out) = confirmed(&[
        "period",
        "close",
        "FY2026-P03",
        "--reason",
        "Scheduled",
        "--yes",
        "--json",
    ]);
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
    // A draft's promotion posts every planned intent to trunk (fa-s7x).
    unconfirmed(
        &[
            "draft",
            "promote",
            "close-03",
            "--as",
            "controller",
            "--json",
        ],
        "fa draft show",
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
        "--reason",
        "LateTransactions",
        "--to",
        "open",
        "--yes",
        "--json",
    ]);
    confirmed(&[
        "period",
        "lock",
        "FY2026-P03",
        "--reason",
        "Scheduled",
        "--yes",
        "--json",
    ]);

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
    let (code, out, _) = fa(None, &["post", "--jsno"]);
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
    assert_eq!(
        head(),
        before_evidence,
        "missing time evidence never writes"
    );

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

    let check_coordinate =
        |line: &str, frontier: CommitSeq, upper: Option<&Ticked>, expected_seq: CommitSeq| {
            let envelope = json::parse(line).unwrap();
            let coordinate = envelope.get("coordinate").unwrap();
            assert_eq!(
                int(coordinate, "known_at"),
                Some(i128::from(expected_seq.0)),
                "{line}"
            );
            let time = coordinate.get("time_evidence").unwrap();
            assert_eq!(text(time, "requested_instant"), CANONICAL_INSTANT, "{line}");
            assert_eq!(
                int(time, "requested_utc_ns"),
                Some(i128::from(REQUESTED_NS))
            );
            assert_eq!(int(time, "frontier"), Some(i128::from(frontier.0)));
            assert_eq!(int(time, "resolved_seq"), Some(i128::from(expected_seq.0)));
            assert_eq!(text(time, "precision"), "tick_bucket", "{line}");
            assert_eq!(
                text(time, "source_grade"),
                "corroborated_daemon_clock",
                "{line}"
            );
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
    let uncertified = report(
        &book,
        &["tb", "--period", PERIOD, "--as-known-at", INSTANT, "--json"],
    );
    assert_cash_credits(&uncertified, "100.00 USD");
    check_coordinate(uncertified.trim_end(), open_frontier, None, open_frontier);
    assert_eq!(
        head(),
        open_frontier,
        "uncertified instant reads never publish"
    );
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
    check_coordinate(lines[0], open_frontier, None, open_frontier);
    check_coordinate(lines[1], open_frontier, None, open_frontier);
    let retained_line = format!("{}\n", lines[0]);
    let bytes = std::fs::read(&path)?;
    assert!(bytes.starts_with(fa::certificate::INSTANT_CERTIFICATE_FORMAT));
    let retained = fa::ReportCertificate::decode(&bytes).unwrap();
    let stored = doc(lines[1]);
    let oid = text(&stored, "oid");
    let stored_at = CommitSeq(u64::try_from(int(&stored, "recorded_at").unwrap()).unwrap());
    assert_eq!(
        stored_at.0,
        open_frontier.0 + 1,
        "only certificate metadata is published"
    );
    assert_eq!(
        open().read_certificate(&retained.digest).unwrap().unwrap(),
        retained
    );
    let bound_time = retained.time_selection.as_ref().unwrap();
    assert_eq!(bound_time.resolution.frontier, open_frontier.0);
    assert_eq!(bound_time.resolution.requested_utc_ns, REQUESTED_NS);
    assert!(bound_time.resolution.upper.is_none());
    assert_eq!(
        head(),
        stored_at,
        "retention adds the certificate, not a new clock tick"
    );

    let upper = tick(UPPER_NS);
    let closed_seq = CommitSeq(upper.recorded_at.0.checked_sub(1).unwrap());
    assert_eq!(
        closed_seq, stored_at,
        "the next tick closes the bucket after certificate metadata and before its own commit"
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
    check_coordinate(
        selected.trim_end(),
        current_frontier,
        Some(&upper),
        closed_seq,
    );
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
    assert_eq!(
        selected, equivalent,
        "equivalent offsets canonicalize identically"
    );

    let items_out = ok(&[
        "open-items",
        "--account",
        "1000",
        "--as-known-at",
        INSTANT,
        "--json",
    ]);
    check_coordinate(
        items_out.trim_end(),
        current_frontier,
        Some(&upper),
        closed_seq,
    );
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
    check_coordinate(
        explained.trim_end(),
        current_frontier,
        Some(&upper),
        closed_seq,
    );
    let explanation = doc(&explained);
    assert_eq!(arr(&explanation, "contributions").len(), 1);
    assert_eq!(
        text(&arr(&explanation, "contributions")[0], "entry"),
        first_vid
    );
    assert_eq!(
        text(&arr(&explanation, "cells")[0], "credits"),
        "100.00 USD"
    );

    let replay = ok(&["replay", &path, "--json"]);
    assert_eq!(
        replay, retained_line,
        "replay retains the original frontier and open bracket after later ticks"
    );
    check_coordinate(replay.trim_end(), open_frontier, None, open_frontier);
    assert_eq!(ok(&["replay", oid, "--json"]), retained_line);
    assert_eq!(
        ok(&["replay", &format!("C:{oid}"), "--json"]),
        retained_line
    );
    assert_cash_credits(
        &report(&book, &["tb", "--period", PERIOD, "--json"]),
        "125.00 USD",
    );
    assert_eq!(
        head(),
        current_frontier,
        "instant resolution, reports and replay leave the journal frontier unchanged"
    );

    // Generic certificates retain the same resolved bucket. Each independent
    // certification observes its own frontier and publishes only its metadata.
    let mut generic = Vec::new();
    for (name, command, event) in [
        (
            "explanation",
            vec!["explain", "balance", "1000", "--period", PERIOD],
            "balance_explained",
        ),
        (
            "open-items",
            vec!["open-items", "--account", "1000"],
            "open_items",
        ),
    ] {
        let observed = head();
        let path = dir
            .join(format!("instant-{name}.cert"))
            .display()
            .to_string();
        let mut args = command;
        args.extend([
            "--as-known-at",
            INSTANT,
            "--certificate-out",
            path.as_str(),
            "--json",
        ]);
        let certified = ok(&args);
        let lines: Vec<&str> = certified.lines().collect();
        assert_eq!(lines.len(), 2, "{certified}");
        assert_eq!(field(lines[0], "event"), Some(event));
        assert_eq!(field(lines[1], "event"), Some("report_certificate"));
        check_coordinate(lines[0], observed, Some(&upper), closed_seq);
        check_coordinate(lines[1], observed, Some(&upper), closed_seq);
        let data = doc(lines[0]);
        if event == "balance_explained" {
            assert_eq!(arr(&data, "contributions").len(), 1);
            assert_eq!(text(&arr(&data, "cells")[0], "credits"), "100.00 USD");
        } else {
            assert_eq!(int(&data, "count"), Some(1));
            assert_eq!(text(&arr(&data, "items")[0], "entry"), first_vid);
            assert_eq!(text(&arr(&data, "items")[0], "open"), "100.00 USD");
        }
        let stored = doc(lines[1]);
        assert_eq!(
            int(&stored, "recorded_at"),
            Some(i128::from(observed.0 + 1))
        );
        assert_eq!(
            head().0,
            observed.0 + 1,
            "retention cannot record a new tick"
        );
        let bytes = std::fs::read(&path)?;
        assert!(bytes.starts_with(b"fa:report-certificate:v3"));
        let certificate = fa::ReportCertificate::decode(&bytes).unwrap();
        let time = certificate.time_selection.as_ref().unwrap();
        assert_eq!(time.resolution.frontier, observed.0);
        assert_eq!(time.resolution.resolved_seq, closed_seq.0);
        let original = format!("{}\n", lines[0]);
        assert_eq!(ok(&["replay", &path, "--json"]), original);
        generic.push((text(&stored, "oid").to_string(), original, observed));
    }
    let retained_frontier = head();
    for (oid, original, observed) in generic {
        let replayed = ok(&["replay", &oid, "--json"]);
        assert_eq!(replayed, original);
        check_coordinate(replayed.trim_end(), observed, Some(&upper), closed_seq);
    }
    assert_eq!(head(), retained_frontier, "generic replay never publishes");
    Ok(())
}

#[test]
fn projection_verification_reports_drift_deterministically_without_writes() -> std::io::Result<()> {
    projection_verification_case("side")
}

#[test]
fn projection_verification_refuses_a_changed_amount_without_writes() -> std::io::Result<()> {
    projection_verification_case("amount")
}

#[test]
fn projection_verification_refuses_a_missing_has_leg_without_writes() -> std::io::Result<()> {
    projection_verification_case("missing-has-leg")
}

fn projection_verification_case(plant: &str) -> std::io::Result<()> {
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

    let dir = tmp(&format!("verify-projections-{plant}"))?;
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
    assert_eq!(
        handle.head().unwrap(),
        prefix,
        "green verification wrote nothing"
    );
    drop(handle);

    // Each case starts from a fresh, verified book. Change exactly one
    // projection through the real substrate; the immutable entry stays intact.
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
    let edge = db
        .edges()
        .unwrap()
        .into_iter()
        .find(|edge| edge.entry.relation == relation::HAS_LEG && edge.entry.dst == leg)
        .expect("the posted leg belongs to an entry");
    let entry = edge.entry.src;
    let payload = fa_journal::rows::bytes(
        &db.vertex(entry).unwrap().unwrap(),
        property::FA_PAYLOAD,
        "authoritative entry",
    )
    .unwrap();
    let mut batch = WriteBatch::new(relation::HAS_LEG);
    let (identity, expected_drift) = match plant {
        "side" => {
            batch.set_vertex_property(leg, property::SIDE, Some(CanonicalScalar::Int(99)));
            (leg.0, "side mirror")
        }
        "amount" => {
            let changed = fgdb_types::CanonicalDecimal::from_scaled_half_even(1_100, 2).unwrap();
            batch.set_vertex_property(
                leg,
                property::AMOUNT,
                Some(CanonicalScalar::Decimal(changed)),
            );
            (leg.0, "amount mirror")
        }
        "missing-has-leg" => {
            batch.delete_edge(edge.entry.eid);
            (edge.entry.eid.0, "missing HAS_LEG edge")
        }
        _ => unreachable!("unknown projection plant {plant}"),
    };
    let damaged_at = runtime.block_on(db.write(&cx.commit(), batch)).unwrap();
    assert_eq!(
        fa_journal::rows::bytes(
            &db.vertex(entry).unwrap().unwrap(),
            property::FA_PAYLOAD,
            "authoritative entry",
        )
        .unwrap(),
        payload,
        "{plant}: projection damage leaves the complete journal payload intact"
    );
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
    let identity_hex = format!("{identity:032x}");
    assert_eq!(arr(detail, "drift").len(), 1, "{plant}: {red}");
    assert!(
        arr(detail, "drift")
            .iter()
            .filter_map(Json::as_str)
            .any(|finding| finding.contains(&identity_hex) && finding.contains(expected_drift)),
        "{plant}: {red}"
    );
    let repeated = fa(Some(&book), &verify);
    assert_eq!(repeated.0, 8, "{}\n{}", repeated.1, repeated.2);
    assert_eq!(repeated.1, red, "red verification is deterministic too");
    let handle = Book::open_dir(&book, keys.clone(), Entropy::deterministic(91)).unwrap();
    assert_eq!(
        handle.head().unwrap(),
        damaged_at,
        "red verification published nothing"
    );
    assert!(!handle.verify_projections(None).unwrap().is_green());
    assert!(
        handle.verify_projections(Some(prefix)).unwrap().is_green(),
        "the earlier committed projection remains independently verifiable"
    );
    drop(handle);
    // `fa doctor` sees the drift and names the read-only preview next.
    let (code, out, err) = fa(Some(&book), &["doctor", "--json"]);
    assert_eq!(code, 8, "{out}\n{err}");
    assert!(
        doctor_checks(&out).contains(&("projections".into(), "fail".into())),
        "{out}"
    );
    assert!(
        out.contains("fa recover projections --dry-run --json"),
        "{out}"
    );

    // The finding names its recovery, which derives every change from the
    // journal: unconfirmed it writes nothing, a dry run previews at this head,
    // and a bound session can do neither.
    assert!(
        text(&error, "fix").contains("fa recover projections --dry-run --json"),
        "{red}"
    );
    let head = || {
        Book::open_dir(&book, keys.clone(), Entropy::deterministic(91))
            .unwrap()
            .head()
            .unwrap()
    };
    let (code, out, err) = fa(Some(&book), &["recover", "projections", "--json"]);
    assert_eq!(code, 7, "{out}\n{err}");
    let unconfirmed = doc(&out);
    assert_eq!(text(&unconfirmed, "refusal_id"), "FA-REF-007", "{out}");
    assert!(
        text(&unconfirmed, "fix").contains("fa recover projections --dry-run --json"),
        "{out}"
    );
    assert_eq!(head(), damaged_at, "an unconfirmed recovery wrote nothing");
    let dry_run = ["recover", "projections", "--dry-run", "--json"];
    let preview = ok(&dry_run);
    assert_eq!(preview.lines().count(), 1, "{preview}");
    assert_eq!(field(&preview, "event"), Some("projections_rebuilt"));
    let planned = doc(&preview);
    assert_eq!(planned.get("dry_run"), Some(&Json::Bool(true)), "{preview}");
    assert_eq!(planned.get("wrote"), Some(&Json::Bool(false)), "{preview}");
    assert_eq!(planned.get("recorded_at"), Some(&Json::Null), "{preview}");
    assert_eq!(int(&planned, "basis"), Some(i128::from(damaged_at.0)));
    assert!(int(&planned, "entries_checked").unwrap() >= 1, "{preview}");
    assert_eq!(int(&planned, "legs_checked"), Some(2), "{preview}");
    // A changed mirror repairs its one leg; a deleted HAS_LEG edge is the
    // one edge the journal says should exist.
    let (legs_repaired, edges_created) = if plant == "missing-has-leg" {
        (0, 1)
    } else {
        (1, 0)
    };
    assert_eq!(
        int(&planned, "legs_repaired"),
        Some(legs_repaired),
        "{preview}"
    );
    assert_eq!(
        int(&planned, "edges_created"),
        Some(edges_created),
        "{preview}"
    );
    for untouched in ["legs_created", "edges_repaired", "edges_retired"] {
        assert_eq!(int(&planned, untouched), Some(0), "{untouched}: {preview}");
    }
    assert_eq!(ok(&dry_run), preview, "a preview is deterministic");
    assert_eq!(head(), damaged_at, "a preview wrote nothing");

    let publish = ["recover", "projections", "--yes", "--json"];
    if plant == "missing-has-leg" {
        // The substrate never re-creates a spent edge identity: the repair
        // fails before publication and the finding stays reported.
        let (code, out, err) = fa(Some(&book), &publish);
        assert_eq!(code, 5, "{out}\n{err}");
        assert_eq!(field(&out, "event"), Some("error"), "{out}");
        assert_eq!(head(), damaged_at, "a failed repair published nothing");
        assert_eq!(fa(Some(&book), &verify).0, 8);
    } else {
        // Publishing binds to the preview: a basis the head no longer is
        // is refused as invalidated (exit 6) and writes nothing; a dry run
        // that also says --yes is a usage error.
        let stale = (damaged_at.0 - 1).to_string();
        let (code, out, err) = fa(
            Some(&book),
            &[
                "recover",
                "projections",
                "--yes",
                "--basis",
                &stale,
                "--json",
            ],
        );
        assert_eq!(code, 6, "{out}\n{err}");
        assert_eq!(text(&doc(&out), "refusal_id"), "FA-REF-034", "{out}");
        assert_eq!(head(), damaged_at, "a stale basis published nothing");
        let (code, out, err) = fa(
            Some(&book),
            &["recover", "projections", "--dry-run", "--yes", "--json"],
        );
        assert_eq!(code, 2, "{out}\n{err}");
        assert_eq!(head(), damaged_at);
        let basis = damaged_at.0.to_string();
        let repaired = ok(&[
            "recover",
            "projections",
            "--yes",
            "--basis",
            &basis,
            "--json",
        ]);
        assert_eq!(field(&repaired, "event"), Some("projections_rebuilt"));
        let data = doc(&repaired);
        assert_eq!(data.get("dry_run"), Some(&Json::Bool(false)), "{repaired}");
        assert_eq!(data.get("wrote"), Some(&Json::Bool(true)), "{repaired}");
        assert_eq!(int(&data, "basis"), Some(i128::from(damaged_at.0)));
        let published = i128::from(damaged_at.0) + 1;
        assert_eq!(int(&data, "recorded_at"), Some(published), "{repaired}");
        for counter in [
            "entries_checked",
            "legs_checked",
            "legs_created",
            "legs_repaired",
            "edges_created",
            "edges_repaired",
            "edges_retired",
        ] {
            assert_eq!(
                int(&data, counter),
                int(&planned, counter),
                "{counter}: the publication is the previewed repair"
            );
        }
        assert_eq!(
            int(robot_line(&repaired).get("coordinate").unwrap(), "known_at"),
            Some(published)
        );
        let repaired_head = head();
        assert_eq!(i128::from(repaired_head.0), published);
        let green = ok(&verify);
        assert_eq!(field(&green, "event"), Some("projections_verified"));
        assert!(arr(&doc(&green), "drift").is_empty(), "{green}");
        let (code, out, err) = fa(Some(&book), &["doctor", "--json"]);
        assert_eq!(code, 0, "{out}\n{err}");
        assert!(
            doctor_checks(&out).contains(&("projections".into(), "ok".into())),
            "{out}"
        );
        let db = runtime
            .block_on(Database::open(
                &cx.commit(),
                &book.join("store"),
                DatabaseKeys::new([91; 32], DatabaseSecurityNamespaceId([92; 32]), [93; 32]),
            ))
            .unwrap();
        assert_eq!(
            fa_journal::rows::bytes(
                &db.vertex(entry).unwrap().unwrap(),
                property::FA_PAYLOAD,
                "authoritative entry",
            )
            .unwrap(),
            payload,
            "{plant}: recovery never rewrites the journal payload"
        );
        drop(db);
        let handle = Book::open_dir(&book, keys.clone(), Entropy::deterministic(91)).unwrap();
        assert!(
            !handle
                .verify_projections(Some(damaged_at))
                .unwrap()
                .is_green(),
            "the damaged prefix stays on the record"
        );
        drop(handle);
        let again = doc(&ok(&publish));
        assert_eq!(again.get("wrote"), Some(&Json::Bool(false)));
        assert_eq!(again.get("recorded_at"), Some(&Json::Null));
        assert_eq!(int(&again, "legs_repaired"), Some(0));
        assert_eq!(head(), repaired_head, "a clean book publishes nothing");
    }

    // Host-only: no launch ceiling holds schema_change, so a token-bound
    // session (here a Human preparer with read and verify) can neither
    // preview a recovery nor confirm one.
    let token = dir.join("repairer.token").display().to_string();
    let (code, out, err) = fa(
        Some(&book),
        &[
            "capability",
            "issue",
            "--holder",
            "repairer",
            "--profile",
            "human",
            "--op",
            "read",
            "--op",
            "verify",
            "--out",
            &token,
            "--grant",
            "issue_capability",
            "--grant",
            "read",
            "--grant",
            "verify",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let issued = head();
    let mut bound = vec!["--token", token.as_str()];
    bound.extend_from_slice(&dry_run);
    let (code, out, err) = fa(Some(&book), &bound);
    assert_eq!(code, 7, "{out}\n{err}");
    let refused = doc(&out);
    assert_eq!(text(&refused, "refusal_id"), "FA-REF-011", "{out}");
    assert!(
        text(&refused, "message").contains("not admitted by the launch-bound"),
        "{out}"
    );
    let mut bound = vec!["--token", token.as_str()];
    bound.extend_from_slice(&publish);
    let (code, out, err) = fa(Some(&book), &bound);
    assert_eq!(code, 2, "{out}\n{err}");
    assert!(
        text(&doc(&out), "message").contains("--yes cannot be supplied by a launch-bound request"),
        "{out}"
    );
    assert_eq!(head(), issued, "a bound session recovers nothing");
    Ok(())
}

#[test]
fn outcome_recovery_is_explicit_basis_bound_and_a_noop_for_covered_books() -> std::io::Result<()> {
    use fa::{Book, BookKeys, Entropy};
    use fa_journal::BookSpec;
    use fa_model::Id128;

    let dir = tmp("recover-outcomes")?;
    let book = dir.join("book");
    let keys = BookKeys::for_development(197);
    let handle = Book::create_dir(
        &book,
        keys.clone(),
        BookSpec {
            book_id: Id128([197; 16]),
            name: "Outcome recovery".into(),
            base_unit: fa_money::UnitRegistry::embedded()
                .unwrap()
                .lookup("USD")
                .unwrap(),
            calendar: fa_time::FiscalCalendar::monthly("fiscal", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(197),
    )
    .unwrap();
    keys.save(&book.join("book.keys")).unwrap();
    let original = handle.head().unwrap();
    drop(handle);
    let head = || {
        Book::open_dir(&book, keys.clone(), Entropy::deterministic(197))
            .unwrap()
            .head()
            .unwrap()
    };
    let ok = |args: &[&str]| {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        assert!(err.is_empty(), "{err}");
        out
    };

    let (code, out, err) = fa(Some(&book), &["recover", "outcomes", "--json"]);
    assert_eq!(code, 7, "{out}\n{err}");
    assert_eq!(text(&doc(&out), "refusal_id"), "FA-REF-007");
    assert!(
        text(&doc(&out), "fix").contains("fa recover outcomes --dry-run --json"),
        "{out}"
    );
    assert_eq!(head(), original, "unconfirmed recovery published nothing");

    let dry_run = ["recover", "outcomes", "--dry-run", "--json"];
    let preview = ok(&dry_run);
    assert_eq!(field(&preview, "event"), Some("outcomes_rebuilt"));
    assert_eq!(preview.lines().count(), 1, "{preview}");
    let planned = doc(&preview);
    assert_eq!(planned.get("dry_run"), Some(&Json::Bool(true)));
    assert_eq!(planned.get("wrote"), Some(&Json::Bool(false)));
    assert_eq!(planned.get("recorded_at"), Some(&Json::Null));
    assert_eq!(planned.get("already_covered"), Some(&Json::Bool(true)));
    assert_eq!(int(&planned, "outcomes_created"), Some(0));
    assert_eq!(int(&planned, "basis"), Some(i128::from(original.0)));
    assert_eq!(
        ok(&dry_run),
        preview,
        "the same prefix has the same preview"
    );
    assert_eq!(head(), original, "preview and abort publish no sequence");

    let basis = original.0.to_string();
    let published = ok(&["recover", "outcomes", "--yes", "--basis", &basis, "--json"]);
    let data = doc(&published);
    assert_eq!(data.get("dry_run"), Some(&Json::Bool(false)));
    assert_eq!(data.get("already_covered"), Some(&Json::Bool(true)));
    assert_eq!(data.get("wrote"), Some(&Json::Bool(false)));
    assert_eq!(data.get("recorded_at"), Some(&Json::Null));
    assert_eq!(int(&data, "basis"), Some(i128::from(original.0)));
    assert_eq!(head(), original, "covered recovery is an actual no-op");

    // Even a no-op is bound to the reviewed head. A later native control
    // invalidates the old CLI preview instead of silently accepting it.
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    let later = head();
    assert!(later > original);
    let (code, out, err) = fa(
        Some(&book),
        &["recover", "outcomes", "--yes", "--basis", &basis, "--json"],
    );
    assert_eq!(code, 6, "{out}\n{err}");
    assert_eq!(text(&doc(&out), "refusal_id"), "FA-REF-034");
    assert_eq!(head(), later, "a stale recovery publishes nothing");
    let current = doc(&ok(&dry_run));
    assert_eq!(int(&current, "basis"), Some(i128::from(later.0)));
    assert_eq!(current.get("already_covered"), Some(&Json::Bool(true)));
    assert_eq!(head(), later);

    // A launch-bound reader cannot gain schema_change through this host
    // maintenance surface or confirm it with a request's --yes.
    let token = dir.join("reader.token").display().to_string();
    ok(&[
        "capability",
        "issue",
        "--holder",
        "outcome-reader",
        "--profile",
        "human",
        "--op",
        "read",
        "--out",
        &token,
        "--grant",
        "issue_capability",
        "--grant",
        "read",
        "--json",
    ]);
    let issued = head();
    let (code, out, err) = fa(
        Some(&book),
        &[
            "--token",
            &token,
            "recover",
            "outcomes",
            "--dry-run",
            "--json",
        ],
    );
    assert_eq!(code, 7, "{out}\n{err}");
    assert_eq!(text(&doc(&out), "refusal_id"), "FA-REF-011");
    assert!(
        text(&doc(&out), "message").contains("not admitted by the launch-bound"),
        "{out}"
    );
    let (code, out, err) = fa(
        Some(&book),
        &["--token", &token, "recover", "outcomes", "--yes", "--json"],
    );
    assert_eq!(code, 2, "{out}\n{err}");
    assert!(
        text(&doc(&out), "message").contains("--yes cannot be supplied by a launch-bound request"),
        "{out}"
    );
    assert_eq!(head(), issued, "bound recovery attempts publish nothing");
    Ok(())
}

#[test]
fn legacy_outcome_recovery_unblocks_posting_only_after_confirmed_publication() -> std::io::Result<()>
{
    use asupersync::fs::UnixVfs;
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::types::Budget;
    use fa::{Book, BookKeys, Entropy};
    use fa_journal::BookSpec;
    use fa_model::Id128;
    use fa_model::symbols::{label, relation};
    use fgdb::{Database, DatabaseKeys, WriteBatch};
    use fgdb_types::context::PurposeContexts;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    let dir = tmp("legacy-recover-outcomes")?;
    let source = dir.join("modern-genesis");
    let book = dir.join("legacy-book");
    let book_id = Id128([196; 16]);
    let keys = BookKeys::for_development(196);
    let native_keys =
        || DatabaseKeys::new([196; 32], DatabaseSecurityNamespaceId([197; 32]), [198; 32]);
    let modern = Book::create_dir(
        &source,
        keys.clone(),
        BookSpec {
            book_id,
            name: "Legacy outcome recovery".into(),
            base_unit: fa_money::UnitRegistry::embedded()
                .unwrap()
                .lookup("USD")
                .unwrap(),
            calendar: fa_time::FiscalCalendar::monthly("fiscal", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(196),
    )
    .unwrap();
    drop(modern);
    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let modern = runtime
        .block_on(Database::open(
            &cx.commit(),
            &source.join("store"),
            native_keys(),
        ))
        .unwrap();
    let prefix = modern.frontier().unwrap();
    let coverage_vid = fa_journal::outcome::coverage_vid(book_id);
    let (coverage, rows): (Vec<_>, Vec<_>) = modern
        .vertices_at(prefix)
        .unwrap()
        .into_iter()
        .partition(|row| row.vid == coverage_vid);
    assert_eq!(coverage.len(), 1);
    assert_eq!(coverage[0].labels.as_slice(), [label::INTENT_OUTCOME]);
    assert!(rows.iter().all(|row| {
        row.labels.as_slice() == [label::BOOK] || row.labels.as_slice() == [label::UNIT]
    }));
    // Construct a separate original Book/Unit genesis from the prior schema.
    // No immutable marker is removed from an existing native history.
    let mut genesis = WriteBatch::new(relation::IN_BOOK);
    for row in rows {
        genesis.create_vertex(row.vid, row.labels, row.props);
    }
    for edge in modern.edges_at(prefix).unwrap() {
        assert_eq!(edge.entry.relation, relation::IN_BOOK);
        assert_ne!(edge.entry.src, coverage_vid);
        assert_ne!(edge.entry.dst, coverage_vid);
        genesis.add_edge(edge.entry.eid, edge.entry.src, edge.entry.dst, edge.props);
    }
    drop(modern);
    std::fs::create_dir(&book)?;
    let mut legacy = runtime
        .block_on(Database::create_with_vfs(
            &cx.commit(),
            UnixVfs::new(),
            book.join("store"),
            native_keys(),
        ))
        .unwrap();
    runtime
        .block_on(legacy.write(&cx.commit(), genesis))
        .unwrap();
    assert!(legacy.vertex(coverage_vid).unwrap().is_none());
    drop(legacy);
    keys.save(&book.join("book.keys")).unwrap();
    let head = || {
        Book::open_dir(&book, keys.clone(), Entropy::deterministic(196))
            .unwrap()
            .head()
            .unwrap()
    };
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
        r#"{"effective_date":"2026-03-15","idempotency_key":"first-covered-legacy-post","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}]}"#,
    );
    let post = [
        "post",
        "--intent",
        &intent,
        "--evidence",
        &evidence,
        "--json",
    ];
    let before = head();
    let (code, out, err) = fa(Some(&book), &post);
    assert_eq!(code, 6, "{out}\n{err}");
    assert_eq!(text(&doc(&out), "refusal_id"), "FA-REF-034");
    assert!(text(&doc(&out), "fix").contains("fa recover outcomes"));
    assert_eq!(head(), before, "posting must not silently rebuild coverage");

    let dry_run = ["recover", "outcomes", "--dry-run", "--json"];
    let preview = ok(&dry_run);
    let planned = doc(&preview);
    assert_eq!(planned.get("already_covered"), Some(&Json::Bool(false)));
    assert_eq!(planned.get("wrote"), Some(&Json::Bool(false)));
    assert_eq!(planned.get("recorded_at"), Some(&Json::Null));
    assert_eq!(int(&planned, "outcomes_created"), Some(0));
    assert!(int(&planned, "entries_checked").unwrap() > 0);
    assert_eq!(int(&planned, "basis"), Some(i128::from(before.0)));
    assert_eq!(ok(&dry_run), preview, "legacy preview is deterministic");
    assert_eq!(head(), before, "legacy preview publishes nothing");
    assert_eq!(fa(Some(&book), &post).0, 6, "preview grants no coverage");
    assert_eq!(head(), before);

    let basis = before.0.to_string();
    let published = doc(&ok(&[
        "recover", "outcomes", "--yes", "--basis", &basis, "--json",
    ]));
    assert_eq!(published.get("already_covered"), Some(&Json::Bool(false)));
    assert_eq!(published.get("wrote"), Some(&Json::Bool(true)));
    assert_eq!(
        int(&published, "recorded_at"),
        Some(i128::from(before.0) + 1)
    );
    let recovered = head();
    assert_eq!(recovered.0, before.0 + 1);
    let covered = doc(&ok(&dry_run));
    assert_eq!(covered.get("already_covered"), Some(&Json::Bool(true)));
    assert_eq!(head(), recovered);

    let posted = ok(&post);
    assert_eq!(field(&posted, "event"), Some("posted"));
    let entry_vid = field(&posted, "vid").unwrap();
    assert_eq!(entry_vid.len(), 32);
    let posted_at = head();
    assert_eq!(posted_at.0, recovered.0 + 1);
    let retry = ok(&post);
    assert_eq!(field(&retry, "event"), Some("recorded"));
    assert_eq!(field(&retry, "vid"), Some(entry_vid));
    assert_eq!(
        field(&retry, "entry_digest"),
        field(&posted, "entry_digest")
    );
    assert_eq!(field(&retry, "recorded_at"), field(&posted, "recorded_at"));
    assert_eq!(head(), posted_at, "an exact retry consumes no sequence");
    Ok(())
}

#[test]
fn outcome_recovery_refuses_ambiguous_arguments_and_filters_before_opening() {
    let cases: &[&[&str]] = &[
        &["recover", "outcomes", "extra", "--dry-run", "--json"],
        &["recover", "outcomes", "--dry-run", "--yes", "--json"],
        &["recover", "outcomes", "--dry-run", "--basis", "1", "--json"],
        &["recover", "outcomes", "--yes", "--basis", "HEAD", "--json"],
        &[
            "recover", "outcomes", "--yes", "--basis", "1", "--basis", "2", "--json",
        ],
        &[
            "recover",
            "outcomes",
            "--dry-run",
            "--period",
            "FY2026-P03",
            "--json",
        ],
        &[
            "recover",
            "outcomes",
            "--dry-run",
            "--as-known-at",
            "1",
            "--json",
        ],
    ];
    for args in cases {
        let (code, out, err) = fa(None, args);
        assert_eq!(code, 2, "args={args:?}\n{out}\n{err}");
        assert_eq!(text(&doc(&out), "class"), "usage");
        let envelope = robot_line(&out);
        assert_eq!(envelope.get("book"), Some(&Json::Null));
        assert_eq!(envelope.get("coordinate"), Some(&Json::Null));
    }
    let (code, help, err) = fa(None, &["recover", "--help", "--json"]);
    assert_eq!(code, 0, "{help}\n{err}");
    assert!(text(&doc(&help), "text").contains("recover outcomes"));
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

        let reopened = Book::open_dir(&book, keys.clone(), Entropy::deterministic(57)).unwrap();
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
        let payload = fa_journal::rows::bytes(&row, property::FA_PAYLOAD, "unit.payload").unwrap();
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
                    other => {
                        assert_eq!(other, "minor");
                        damaged[6] = 1;
                    }
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
            .expect_err("reopen must refuse changed historical unit facts");
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
            assert!(out.contains("no backfill"), "{out}");
            assert!(out.contains("creating binary"), "{out}");
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

#[test]
fn solvency_contra_assets_have_a_certified_replayable_deficit() -> std::io::Result<()> {
    let dir = tmp("solvency-contra-assets")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let mut argv = args.to_vec();
        argv.push("--json");
        let (code, out, err) = fa(Some(&book), &argv);
        assert_eq!(code, 0, "{argv:?}\n{out}\n{err}");
        out
    };
    ok(&[
        "book",
        "create",
        "--name",
        "Synthetic signed solvency fixture",
    ]);
    ok(&["chart", "import", "--template", "us-gaap-smb"]);
    ok(&["period", "create", "--fiscal-year", "2026"]);
    ok(&["period", "open", "FY2026-P03"]);
    let evidence = source_doc(&dir, &book);
    let funding = write(
        &dir,
        "funding.json",
        r#"{"effective_date":"2026-03-01","idempotency_key":"funding","legs":[{"side":"debit","account":"1510","amount":"100.00 USD"},{"side":"credit","account":"2000","amount":"50.00 USD"},{"side":"credit","account":"3000","amount":"50.00 USD"}]}"#,
    );
    ok(&["post", "--intent", &funding, "--evidence", &evidence]);
    let procedure = [
        "procedure",
        "run",
        "solvency.balance_sheet_test",
        "--effective-through",
        "2026-03-31",
    ];
    assert_eq!(int(&doc(&ok(&procedure)), "finding_count"), Some(0));
    let depreciation = write(
        &dir,
        "depreciation.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"depreciation","legs":[{"side":"debit","account":"6000","amount":"80.00 USD"},{"side":"credit","account":"1590","amount":"80.00 USD"}]}"#,
    );
    let deducted = ok(&["post", "--intent", &depreciation, "--evidence", &evidence]);
    let deduction_vid = field(&deducted, "vid").unwrap().to_owned();
    let result = doc(&ok(&procedure));
    assert_eq!(int(&result, "version"), Some(2));
    assert_eq!(int(&result, "finding_count"), Some(1));
    let finding = &arr(&result, "findings")[0];
    let statistic = finding.get("statistic").unwrap();
    assert_eq!(text(statistic, "name"), "insolvency_deficit");
    assert_eq!(int(statistic, "value"), Some(3_000));
    assert!(
        arr(finding, "cites").iter().any(|cite| {
            cite.get("entry").and_then(Json::as_str) == Some(deduction_vid.as_str())
        })
    );
    assert!(text(finding, "narrative").contains("asset_basis=2000"));
    let recorded = doc(&ok(&[
        "finding",
        "record",
        "solvency.balance_sheet_test",
        "--effective-through",
        "2026-03-31",
    ]));
    let retained = text(&recorded, "certificate").to_owned();
    assert_eq!(int(&recorded, "finding_count"), Some(1));
    let saved = ok(&["replay", &format!("C:{retained}")]);
    assert_eq!(doc(&saved), result);

    // A later transaction removes today's deficit, without changing the
    // historical method, coordinate, exact finding or certificate replay.
    let recovery = write(
        &dir,
        "recovery.json",
        r#"{"effective_date":"2026-03-20","idempotency_key":"recovery","legs":[{"side":"debit","account":"2200","amount":"40.00 USD"},{"side":"credit","account":"3000","amount":"40.00 USD"}]}"#,
    );
    ok(&["post", "--intent", &recovery, "--evidence", &evidence]);
    assert_eq!(int(&doc(&ok(&procedure)), "finding_count"), Some(0));
    let replayed = ok(&["replay", &format!("C:{retained}")]);
    assert_eq!(replayed, saved);
    Ok(())
}

/// `fa procedure list|run`: Lantern over a persisted book through the CLI
/// (plan §11, Appendix D). The planted round amount is found and cited by
/// its posted vid; a parameter override changes the result; the registry
/// refuses what it does not know, naming the fix; historical folds refuse
/// to run without an effective date; a tracing law runs once its inputs
/// are passed by handle and refuses a source that never deposited.
#[test]
fn procedures_run_over_a_persisted_book_and_cite_resolving_handles() -> std::io::Result<()> {
    let dir = tmp("procedures")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let mut argv = args.to_vec();
        argv.push("--json");
        let (code, out, err) = fa(Some(&book), &argv);
        assert_eq!(code, 0, "{argv:?}\n{out}\n{err}");
        out
    };
    let refused = |args: &[&str]| -> (i32, String) {
        let mut argv = args.to_vec();
        argv.push("--json");
        let (code, out, _) = fa(Some(&book), &argv);
        (code, out)
    };
    ok(&["book", "create", "--name", "Procedures Co"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1010","name":"Bank B","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart]);
    ok(&["period", "create", "--fiscal-year", "2026"]);
    ok(&["period", "open", "FY2026-P03"]);
    let source = write(&dir, "source.txt", "INVOICE (procedure fixture)");
    let added = ok(&[
        "document",
        "add",
        &source,
        "--kind",
        "Invoice",
        "--grade",
        "HumanUpload",
    ]);
    let ev = field(&added, "oid").unwrap_or_default().to_string();
    let round = write(
        &dir,
        "round.json",
        r#"{"effective_date":"2026-03-10","idempotency_key":"round-rent","legs":[{"side":"debit","account":"6000","amount":"5000.00 USD"},{"side":"credit","account":"1000","amount":"5000.00 USD"}],"description":"March rent, round"}"#,
    );
    let posted = ok(&["post", "--intent", &round, "--evidence", &ev]);
    let round_vid = field(&posted, "vid").unwrap_or_default().to_string();
    let plain = write(
        &dir,
        "plain.json",
        r#"{"effective_date":"2026-03-11","idempotency_key":"plain-rent","legs":[{"side":"debit","account":"6000","amount":"1234.56 USD"},{"side":"credit","account":"1000","amount":"1234.56 USD"}],"description":"March rent, not round"}"#,
    );
    ok(&["post", "--intent", &plain, "--evidence", &ev]);

    // The registry is listed in full, with its pinned defaults.
    let listed = ok(&["procedure", "list"]);
    let listed_doc = doc(&listed);
    let rows = arr(&listed_doc, "procedures");
    assert_eq!(rows.len(), 61, "{listed}");
    for id in [
        "jet.round_amounts",
        "solvency.balance_sheet_test",
        "ponzi.net_investment",
        "damages.but_for",
        "recon.bank_statement_drift",
    ] {
        assert!(
            rows.iter()
                .any(|r| r.get("id").and_then(Json::as_str) == Some(id)),
            "{id}: {listed}"
        );
    }

    // The planted round amount is found, cited by the posted entry's vid.
    let out = ok(&["procedure", "run", "jet.round_amounts"]);
    let data = doc(&out);
    assert_eq!(text(&data, "procedure"), "jet.round_amounts");
    assert_eq!(text(&data, "claim"), "statistical");
    let findings = arr(&data, "findings");
    assert_eq!(findings.len(), 1, "{out}");
    let cites = findings[0]
        .get("cites")
        .and_then(Json::as_arr)
        .expect("cites");
    assert!(
        cites.iter().any(|c| {
            c.get("kind").and_then(Json::as_str) == Some("entry")
                && c.get("entry").and_then(Json::as_str) == Some(round_vid.as_str())
        }),
        "the finding cites the round entry by vid: {out}"
    );
    assert_eq!(int(&data, "finding_count"), Some(1));
    assert!(int(&data, "population").is_some_and(|n| n >= 2), "{out}");
    assert!(
        data.get("effective_through") == Some(&Json::Null),
        "no effective date was declared: {out}"
    );
    // A parameter override is honoured: at round_power 6 nothing is round.
    let none = ok(&[
        "procedure",
        "run",
        "jet.round_amounts",
        "--param",
        "round_power=6",
    ]);
    assert_eq!(int(&doc(&none), "finding_count"), Some(0), "{none}");
    assert_eq!(
        arr(&doc(&none), "parameters")
            .iter()
            .find(|p| p.get("name").and_then(Json::as_str) == Some("round_power"))
            .and_then(|p| int(p, "value")),
        Some(6)
    );
    // An effective date selects the historical folds; aging runs with it.
    let aged = ok(&[
        "procedure",
        "run",
        "aging.open_items",
        "--effective-through",
        "2026-04-30",
    ]);
    assert_eq!(text(&doc(&aged), "effective_through"), "2026-04-30");
    // A tracing law runs once its inputs are passed by handle: the round
    // rent is the deposit into 6000; the later rent is a clean inflow, so
    // the lowest intermediate balance never dips below the deposit.
    let traced = ok(&[
        "procedure",
        "run",
        "trace.libr",
        "--effective-through",
        "2026-04-30",
        "--account",
        "6000",
        "--source",
        &round_vid,
    ]);
    let traced_doc = doc(&traced);
    let traced_findings = arr(&traced_doc, "findings");
    assert_eq!(traced_findings.len(), 1, "{traced}");
    assert_eq!(
        traced_findings[0]
            .get("statistic")
            .and_then(|st| int(st, "value")),
        Some(500_000),
        "{traced}"
    );
    // Planted negatives, each naming the fix.
    let (code, out) = refused(&["procedure", "run", "aging.open_items"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("effective_through"), "{out}");
    let (code, out) = refused(&["procedure", "run", "graph.kiting"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("fa procedure list"), "{out}");
    let (code, out) = refused(&[
        "procedure",
        "run",
        "jet.round_amounts",
        "--param",
        "round_power=two",
    ]);
    assert_eq!(code, 2, "{out}");
    let (code, out) = refused(&[
        "procedure",
        "run",
        "jet.round_amounts",
        "--param",
        "no_such=1",
    ]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("not a registered parameter"), "{out}");
    let (code, out) = refused(&[
        "procedure",
        "run",
        "trace.libr",
        "--effective-through",
        "2026-04-30",
    ]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("account"), "{out}");
    let (code, out) = refused(&[
        "procedure",
        "run",
        "trace.libr",
        "--effective-through",
        "2026-04-30",
        "--account",
        "1000",
        "--source",
        &round_vid,
    ]);
    assert_eq!(code, 2, "a credit to cash is not a deposit into it: {out}");
    assert!(out.contains("source"), "{out}");
    Ok(())
}

/// The `fa doctor` checks in one report: (name, status).
fn doctor_checks(out: &str) -> Vec<(String, String)> {
    let line = out
        .lines()
        .find(|l| l.contains(r#""event":"doctor""#))
        .unwrap_or_default();
    let parsed = json::parse(line).unwrap_or(Json::Null);
    let data = parsed.get("data").cloned().unwrap_or(Json::Null);
    arr(&data, "checks")
        .iter()
        .map(|c| (text(c, "name").to_string(), text(c, "status").to_string()))
        .collect()
}

/// `fa doctor` (plan §15.3, bead fa-12x slice 2): every check with its
/// status and fix; exit 0 only when none failed, else the first failure's
/// class after the report. A missing book is environment (4) naming `fa
/// book create`; a key file others can read is a warning naming `chmod
/// 600`; registers behind the journal are a warning naming `fa registers
/// advance` (a verified basis is lag, never drift), and triage puts that
/// remedy first in next_actions.
#[test]
fn doctor_reports_every_check_and_its_fix_and_exits_with_the_first_failure() -> std::io::Result<()>
{
    // No book directory at all.
    let (code, out, _) = fa(None, &["doctor", "--json"]);
    assert_eq!(code, 4, "{out}");
    assert!(
        doctor_checks(&out).contains(&("book_dir".into(), "fail".into())),
        "{out}"
    );
    assert_eq!(
        field(out.lines().last().unwrap_or_default(), "class"),
        Some("environment")
    );
    let dir = tmp("doctor")?;
    let missing = dir.join("nowhere");
    let (code, out, _) = fa(Some(&missing), &["doctor", "--json"]);
    assert_eq!(code, 4, "{out}");
    assert!(out.contains("fa book create --name <name> --book"), "{out}");

    // A healthy book: every check ok, in order.
    let (book, ev, dir2) = envelope_book("doctor-book")?;
    let (code, out, err) = fa(Some(&book), &["doctor", "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "healthy"), Some("true"), "{out}");
    let checks = doctor_checks(&out);
    assert_eq!(
        checks.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
        vec![
            "registries",
            "book_dir",
            "keys",
            "writer_lease",
            "book",
            "registers",
            "projections",
            "availability",
            "accumulator"
        ],
        "{out}"
    );
    assert!(checks.iter().all(|(_, st)| st == "ok"), "{out}");
    // Human mode: one line per check, the verdict last.
    let (code, human, _) = fa(Some(&book), &["doctor"]);
    assert_eq!(code, 0);
    assert!(human.trim_end().ends_with("healthy"), "{human}");

    // A key file others can read: refused with FA-REF-155, exit 4, and the exact fix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let keys = book.join("book.keys");
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o644))?;
        let (code, out, _) = fa(Some(&book), &["doctor", "--json"]);
        assert_eq!(code, 4, "{out}");
        assert!(
            doctor_checks(&out).contains(&("keys".into(), "fail".into())),
            "{out}"
        );
        assert!(out.contains("FA-REF-155"), "{out}");
        assert!(
            out.contains(&format!("chmod 600 {}", keys.display())),
            "{out}"
        );
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o600))?;
    }

    // Registers behind the journal: materialize March, then post into it.
    let entry = write(
        &dir2,
        "rent.json",
        r#"{"effective_date":"2026-03-05","description":"rent","idempotency_key":"rent-d1","legs":[{"side":"debit","account":"6000","amount":"5.00 USD"},{"side":"credit","account":"1000","amount":"5.00 USD"}]}"#,
    );
    let ok = |args: &[&str]| {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
    };
    ok(&["post", "--intent", &entry, "--evidence", &ev, "--json"]);
    ok(&[
        "registers",
        "materialize",
        "--period",
        "FY2026-P03",
        "--yes",
        "--json",
    ]);
    let more = write(
        &dir2,
        "more.json",
        r#"{"effective_date":"2026-03-06","description":"more rent","idempotency_key":"rent-d2","legs":[{"side":"debit","account":"6000","amount":"7.00 USD"},{"side":"credit","account":"1000","amount":"7.00 USD"}]}"#,
    );
    ok(&["post", "--intent", &more, "--evidence", &ev, "--json"]);
    let (code, out, _) = fa(Some(&book), &["doctor", "--json"]);
    assert_eq!(code, 0, "lag is a warning, not a failure: {out}");
    assert!(
        doctor_checks(&out).contains(&("registers".into(), "warn".into())),
        "{out}"
    );
    assert!(
        out.contains("fa registers advance --period FY2026-P03"),
        "{out}"
    );
    // triage names the same remedy in next_actions, ahead of the routine read.
    let (code, out, _) = fa(Some(&book), &["triage", "--json"]);
    assert_eq!(code, 0, "{out}");
    let line = json::parse(out.lines().last().unwrap_or_default()).unwrap_or(Json::Null);
    let data = line.get("data").cloned().unwrap_or(Json::Null);
    assert_eq!(text(&data, "health"), "ok", "{out}");
    assert_eq!(text(&data, "daemon"), "absent", "{out}");
    let commands: Vec<&str> = arr(&line, "next_actions")
        .iter()
        .map(|n| text(n, "command"))
        .collect();
    assert_eq!(
        commands.first().copied(),
        Some("fa registers advance --period FY2026-P03 --json"),
        "{out}"
    );
    assert_eq!(
        commands.last().copied(),
        Some("fa tb --period FY2026-P03 --json"),
        "{out}"
    );
    // The remedy clears the warning.
    ok(&["registers", "advance", "--period", "FY2026-P03", "--json"]);
    let (code, out, _) = fa(Some(&book), &["doctor", "--json"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        doctor_checks(&out).iter().all(|(_, st)| st == "ok"),
        "{out}"
    );
    Ok(())
}

/// `fa triage` and `fa next` (plan §15.3): the book's state and the next
/// command, from a new book through to one ready to post.
#[test]
fn triage_names_the_next_step_from_the_books_state() -> std::io::Result<()> {
    let dir = tmp("triage")?;
    let book = dir.join("book");
    let next_of = |out: &str| -> (String, Vec<String>) {
        let line = json::parse(out.lines().last().unwrap_or_default()).unwrap_or(Json::Null);
        let data = line.get("data").cloned().unwrap_or(Json::Null);
        (
            text(&data, "health").to_string(),
            arr(&line, "next_actions")
                .iter()
                .map(|n| text(n, "command").to_string())
                .collect(),
        )
    };
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    ok(&["book", "create", "--name", "Triage Co", "--json"]);
    let (health, next) = next_of(&ok(&["triage", "--json"]));
    assert_eq!(health, "ok");
    assert_eq!(
        next.first().map(String::as_str),
        Some("fa chart import <chart.json> --json")
    );
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    let (_, next) = next_of(&ok(&["triage", "--json"]));
    assert_eq!(
        next.first().map(String::as_str),
        Some("fa period create --fiscal-year <N> --json")
    );
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    let (_, next) = next_of(&ok(&["triage", "--json"]));
    let open_first = next.first().map(String::as_str).unwrap_or_default();
    assert!(
        open_first.starts_with("fa period open FY2026-") && open_first.ends_with(" --json"),
        "the first Future period is the one to open: {next:?}"
    );
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let out = ok(&["triage", "--json"]);
    let (_, next) = next_of(&out);
    assert_eq!(
        next,
        vec!["fa tb --period FY2026-P03 --json".to_string()],
        "{out}"
    );
    assert!(out.contains(r#""open_periods":["FY2026-P03"]"#), "{out}");
    // No tick yet: nothing is due (FA-CFG-02).
    for key in ["due_holds", "due_reversals", "blocked_reversals"] {
        assert!(out.contains(&format!(r#""{key}":0"#)), "{key}: {out}");
    }
    // `fa next`: the same first step, as data.
    let out = ok(&["next", "--json"]);
    let d = doc(&out);
    assert_eq!(
        text(&d, "command"),
        "fa tb --period FY2026-P03 --json",
        "{out}"
    );
    assert!(!text(&d, "why").is_empty(), "{out}");
    // Human mode: one summary line.
    let human = ok(&["triage"]);
    assert!(human.contains("FY2026-P03"), "{human}");
    Ok(())
}

/// `fa-os2` (plan §7.1): retail 4-4-5 / 4-5-4 / 5-4-4 and 52/53-week fiscal
/// calendars create 52- and 53-week fiscal years, post and report end-to-end,
/// and invalid book specifications fail before creating the directory or keys.
#[test]
fn retail_and_weekly_52_53_calendars_and_book_create_validation() -> std::io::Result<()> {
    let dir = tmp("retail-calendar")?;

    // Planted negatives: invalid calendar, adjustment_periods > 4, and
    // oversized book name fail with exit 2 and never create the book dir.
    let bad_book = dir.join("never-created");
    for args in [
        vec![
            "book",
            "create",
            "--name",
            "Bad Calendar",
            "--calendar",
            "4-4-5:nearest:funday",
            "--json",
        ],
        vec![
            "book",
            "create",
            "--name",
            "Bad Adj",
            "--adjustment-periods",
            "5",
            "--json",
        ],
        vec![
            "book",
            "create",
            "--name",
            "Bad Conflict",
            "--calendar",
            "4-4-5:nearest:saturday:12",
            "--year-start-month",
            "1",
            "--json",
        ],
    ] {
        let (code, out, err) = fa(Some(&bad_book), &args);
        assert_eq!(code, 2, "args={args:?}\n{out}\n{err}");
        assert!(
            !bad_book.exists(),
            "failed book create must not leave directory or keys: {args:?}"
        );
    }
    let long_name = "N".repeat(257);
    let (code, out, err) = fa(
        Some(&bad_book),
        &["book", "create", "--name", &long_name, "--json"],
    );
    assert_eq!(code, 2, "{out}\n{err}");
    assert!(!bad_book.exists());

    // Positive: 4-4-5 retail calendar with Nearest Saturday in December and 1 adjustment period.
    // FY2025 under Nearest Saturday to Dec 31 ends on Saturday 2026-01-03 (a 53-week year:
    // 2024-12-29 ..= 2026-01-03, where P12 has 6 weeks = 42 days).
    let book = dir.join("retail-book");
    let (code, out, err) = fa(
        Some(&book),
        &[
            "book",
            "create",
            "--name",
            "Retail 445 Co",
            "--calendar",
            "4-4-5:nearest:saturday:12",
            "--adjustment-periods",
            "1",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let (code, info_out, err) = fa(Some(&book), &["book", "info", "--json"]);
    assert_eq!(code, 0, "{info_out}\n{err}");
    let info = doc(&info_out);
    assert_eq!(text(&info, "calendar"), "fiscal");

    let (code, out, err) = fa(
        Some(&book),
        &["period", "create", "--fiscal-year", "2025", "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let created = doc(&out);
    assert_eq!(arr(&created, "periods").len(), 15, "{out}");

    let (code, list_out, err) = fa(Some(&book), &["period", "list", "--json"]);
    assert_eq!(code, 0, "{list_out}\n{err}");
    let periods = doc(&list_out);
    let list = arr(&periods, "periods");
    assert_eq!(list.len(), 15, "{periods:?}");
    let p01 = &list[0];
    assert_eq!(text(p01, "code"), "FY2025-P01");
    assert_eq!(text(p01, "start"), "2024-12-29");
    assert_eq!(text(p01, "end"), "2025-01-26");
    let p12 = &list[11];
    assert_eq!(text(p12, "code"), "FY2025-P12");
    assert_eq!(text(p12, "start"), "2025-11-23");
    assert_eq!(text(p12, "end"), "2026-01-04");
    let adj = &list[13];
    assert_eq!(text(adj, "code"), "FY2025-A1");
    assert_eq!(text(adj, "start"), "2026-01-03");
    assert_eq!(text(adj, "end"), "2026-01-04");

    // Post in the 53rd week (2026-01-02 falls into FY2025-P12) and run Trial Balance.
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"4000","name":"Sales","type":"Revenue","leaf":true,"unit":"USD"}]}"#,
    );
    assert_eq!(fa(Some(&book), &["chart", "import", &chart, "--json"]).0, 0);
    assert_eq!(
        fa(Some(&book), &["period", "open", "FY2025-P12", "--json"]).0,
        0
    );
    let ev = source_doc(&dir, &book);
    let entry = write(
        &dir,
        "entry.json",
        r#"{"effective_date":"2026-01-02","description":"53rd week retail sales","idempotency_key":"wk53-1","legs":[{"side":"debit","account":"1000","amount":"530.00 USD"},{"side":"credit","account":"4000","amount":"530.00 USD"}]}"#,
    );
    let (code, out, err) = fa(
        Some(&book),
        &["post", "--intent", &entry, "--evidence", &ev, "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains(r#""period":"FY2025-P12""#), "{out}");

    let tb = report(&book, &["tb", "--period", "FY2025-P12", "--json"]);
    assert!(tb.contains(r#""effective_through":"2026-01-03""#), "{tb}");
    assert!(tb.contains(r#""530.00 USD""#), "{tb}");

    // Also verify 52-53 week calendar (13x4) via CLI.
    let wk_book = dir.join("weekly-book");
    let (code, out, err) = fa(
        Some(&wk_book),
        &[
            "book",
            "create",
            "--name",
            "Weekly 52-53 Co",
            "--calendar",
            "52-53:last:friday:12",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let (code, out, err) = fa(
        Some(&wk_book),
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(arr(&doc(&out), "periods").len(), 16, "{out}");
    Ok(())
}

/// fa-w5m6: GL detail, roll-forward, aging (+ reconciliation), direct/indirect
/// cash-flow, summary trial balance, statement diff/trace, and open-items --as-of
/// are wired end-to-end on the CLI and conform to the robot schema.
#[test]
fn gl_detail_roll_forward_aging_cash_flow_summary_tb_and_statement_diff_trace_end_to_end()
-> std::io::Result<()> {
    let dir = tmp("fa-w5m6-reports")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        assert!(err.is_empty(), "args={args:?}\nstderr={err}");
        out
    };

    ok(&["book", "create", "--name", "Reports & GL Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[
            {"code":"10","name":"Assets","type":"Asset","leaf":false,"unit":"USD"},
            {"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD","parent":"10"},
            {"code":"1200","name":"Accounts Receivable","type":"Asset","leaf":true,"unit":"USD","parent":"10"},
            {"code":"1500","name":"Equipment","type":"Asset","leaf":true,"unit":"USD","parent":"10"},
            {"code":"4000","name":"Sales Revenue","type":"Revenue","leaf":true,"unit":"USD"},
            {"code":"6000","name":"Depreciation Expense","type":"Expense","leaf":true,"unit":"USD"}
        ]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let ev = source_doc(&dir, &book);

    // Entry 1: Cash sale on 2026-03-05 (1000.00 USD)
    let e1 = write(
        &dir,
        "e1.json",
        r#"{"effective_date":"2026-03-05","description":"cash sale","idempotency_key":"w5m6-1","legs":[{"side":"debit","account":"1000","amount":"1000.00 USD"},{"side":"credit","account":"4000","amount":"1000.00 USD"}]}"#,
    );
    let posted_e1 = doc(&ok(&["post", "--intent", &e1, "--evidence", &ev, "--json"]));
    let e1_digest = text(&posted_e1, "entry_digest").to_string();

    // Entry 2: Credit invoice on 2026-03-10 (400.00 USD)
    let e2 = write(
        &dir,
        "e2.json",
        r#"{"effective_date":"2026-03-10","description":"credit invoice","idempotency_key":"w5m6-2","legs":[{"side":"debit","account":"1200","amount":"400.00 USD"},{"side":"credit","account":"4000","amount":"400.00 USD"}]}"#,
    );
    let posted_e2 = doc(&ok(&["post", "--intent", &e2, "--evidence", &ev, "--json"]));
    let e2_digest = text(&posted_e2, "entry_digest").to_string();
    let seq_before = int(&posted_e2, "recorded_at").unwrap().to_string();

    // Entry 3: Non-cash depreciation on 2026-03-20 (150.00 USD)
    let e3 = write(
        &dir,
        "e3.json",
        r#"{"effective_date":"2026-03-20","description":"depreciation","idempotency_key":"w5m6-3","legs":[{"side":"debit","account":"6000","amount":"150.00 USD"},{"side":"credit","account":"1500","amount":"150.00 USD"}]}"#,
    );
    let posted_e3 = doc(&ok(&["post", "--intent", &e3, "--evidence", &ev, "--json"]));
    let e3_digest = text(&posted_e3, "entry_digest").to_string();
    let seq_after = int(&posted_e3, "recorded_at").unwrap().to_string();

    // 1. Summary Trial Balance (`fa tb --summary` and `fa tb --summary --root 10`)
    let full_stb_out = ok(&["tb", "--period", "FY2026-P03", "--summary", "--json"]);
    assert_eq!(field(&full_stb_out, "event"), Some("summary_trial_balance"));
    let full_stb = doc(&full_stb_out);
    assert_eq!(
        full_stb.get("complete"),
        Some(&Json::Bool(true)),
        "{full_stb_out}"
    );
    assert_eq!(
        full_stb.get("balanced"),
        Some(&Json::Bool(true)),
        "{full_stb_out}"
    );

    let stb_out = ok(&[
        "tb",
        "--period",
        "FY2026-P03",
        "--summary",
        "--root",
        "10",
        "--json",
    ]);
    assert_eq!(field(&stb_out, "event"), Some("summary_trial_balance"));
    let stb = doc(&stb_out);
    assert_eq!(stb.get("complete"), Some(&Json::Bool(false)), "{stb_out}");
    let groups = arr(&stb, "groups");
    assert_eq!(groups.len(), 1, "{stb_out}");
    assert_eq!(text(&groups[0], "code"), "10");
    let group_rows = arr(&groups[0], "rows");
    assert_eq!(group_rows.len(), 1, "{stb_out}");
    assert_eq!(text(&group_rows[0], "net"), "1250.00 USD");
    let stb_human = ok(&["tb", "--period", "FY2026-P03", "--summary", "--root", "10"]);
    assert!(stb_human.contains("summary trial balance"), "{stb_human}");

    // 2. Statement Diff & Trace (`fa statement diff`, `fa statement trace`)
    let diff_out = ok(&[
        "statement",
        "diff",
        "--definition",
        "balance-sheet",
        "--for",
        "FY2026-P03",
        "--before",
        &seq_before,
        "--after",
        &seq_after,
        "--json",
    ]);
    assert_eq!(field(&diff_out, "event"), Some("statement_diff"));
    let sdiff = doc(&diff_out);
    assert_eq!(sdiff.get("amounts_changed"), Some(&Json::Bool(true)));
    assert_eq!(sdiff.get("unchanged"), Some(&Json::Bool(false)));
    assert!(!arr(&sdiff, "lines").is_empty(), "{diff_out}");
    let diff_human = ok(&[
        "statement",
        "diff",
        "--definition",
        "balance-sheet",
        "--for",
        "FY2026-P03",
        "--before",
        &seq_before,
        "--after",
        &seq_after,
    ]);
    assert!(diff_human.contains("balance-sheet diff"), "{diff_human}");

    let trace_out = ok(&[
        "statement",
        "trace",
        "--definition",
        "balance-sheet",
        "--for",
        "FY2026-P03",
        "--before",
        &seq_before,
        "--after",
        &seq_after,
        "--json",
    ]);
    assert_eq!(text(&robot_line(&trace_out), "event"), "statement_trace");
    let strace = doc(&trace_out);
    assert_eq!(strace.get("had_changes"), Some(&Json::Bool(true)));
    assert!(!arr(&strace, "publications").is_empty(), "{trace_out}");
    let trace_human = ok(&[
        "statement",
        "trace",
        "--definition",
        "balance-sheet",
        "--for",
        "FY2026-P03",
        "--before",
        &seq_before,
        "--after",
        &seq_after,
    ]);
    assert!(trace_human.contains("balance-sheet"), "{trace_human}");

    // 3. Open-Items `--as-of`
    let oi_early_raw = ok(&[
        "open-items",
        "--account",
        "1200",
        "--as-of",
        "2026-03-08",
        "--json",
    ]);
    let oi_early = doc(&oi_early_raw);
    assert_eq!(int(&oi_early, "count"), Some(0));
    assert!(oi_early_raw.contains(r#""effective":"as-of:2026-03-08""#));
    let oi_late_raw = ok(&[
        "open-items",
        "--account",
        "1200",
        "--as-of",
        "2026-03-15",
        "--json",
    ]);
    let oi_late = doc(&oi_late_raw);
    assert_eq!(int(&oi_late, "count"), Some(1));
    assert!(oi_late_raw.contains(r#""effective":"as-of:2026-03-15""#));

    // 4. GL Detail (`fa gl detail` and alias `fa gl-detail`)
    let gld_out = ok(&[
        "gl",
        "detail",
        "--account",
        "1000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--json",
    ]);
    assert_eq!(field(&gld_out, "event"), Some("general_ledger"));
    let gld = doc(&gld_out);
    let gld_cells = arr(&gld, "cells");
    assert_eq!(gld_cells.len(), 1);
    assert_eq!(text(&gld_cells[0], "account"), "1000");
    assert_eq!(text(&gld_cells[0], "closing"), "1000.00 USD");
    assert_eq!(int(&gld_cells[0], "line_count"), Some(1));
    let gld_alias = ok(&[
        "gl-detail",
        "--account",
        "1000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--json",
    ]);
    assert_eq!(gld_alias, gld_out);
    let gld_human = ok(&[
        "gl",
        "detail",
        "--account",
        "1000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
    ]);
    assert!(gld_human.contains("gl detail"), "{gld_human}");

    // 5. Roll-Forward (`fa gl roll-forward` and alias `fa roll-forward`)
    let rf_out = ok(&[
        "gl",
        "roll-forward",
        "--account",
        "1000,1200",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--json",
    ]);
    assert_eq!(field(&rf_out, "event"), Some("roll_forward"));
    let rf = doc(&rf_out);
    assert_eq!(arr(&rf, "rows").len(), 2);
    assert_eq!(int(&rf, "movement_count"), Some(2));
    let rf_alias = ok(&[
        "roll-forward",
        "--account",
        "1000,1200",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--json",
    ]);
    assert_eq!(rf_alias, rf_out);
    let rf_human = ok(&[
        "gl",
        "roll-forward",
        "--account",
        "1000,1200",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
    ]);
    assert!(rf_human.contains("roll-forward"), "{rf_human}");

    // 6. Aging & Reconciled Aging (`fa gl aging` and alias `fa aging`)
    let aging_out = ok(&[
        "gl",
        "aging",
        "--as-of",
        "2026-03-25",
        "--account",
        "1200",
        "--bucket",
        "0",
        "--bucket",
        "10",
        "--bucket",
        "30",
        "--json",
    ]);
    assert_eq!(field(&aging_out, "event"), Some("aging"));
    let aging = doc(&aging_out);
    assert_eq!(arr(&aging, "items").len(), 1);
    let aging_rec_out = ok(&[
        "aging",
        "--as-of",
        "2026-03-25",
        "--account",
        "1200",
        "--reconcile",
        "--json",
    ]);
    assert_eq!(field(&aging_rec_out, "event"), Some("aging_reconciled"));
    let aging_rec = doc(&aging_rec_out);
    assert_eq!(aging_rec.get("reconciled"), Some(&Json::Bool(true)));
    let rec_rows = arr(&aging_rec, "rows");
    assert_eq!(rec_rows.len(), 1);
    assert_eq!(text(&rec_rows[0], "open_net"), "400.00 USD");
    assert_eq!(text(&rec_rows[0], "posted_net"), "400.00 USD");
    assert_eq!(text(&rec_rows[0], "difference"), "0.00 USD");
    let aging_human = ok(&[
        "gl",
        "aging",
        "--as-of",
        "2026-03-25",
        "--account",
        "1200",
        "--reconcile",
    ]);
    assert!(aging_human.contains("reconciled=true"), "{aging_human}");

    // 7. Cash Flow — Direct & Indirect (`fa gl cash-flow` and alias `fa cash-flow`)
    let direct_policy = write(
        &dir,
        "direct_cf.json",
        &format!(
            r#"{{
                "name":"cf-direct-v1",
                "cash_accounts":["1000"],
                "assignments":[
                    {{"entry_digest":"{e1_digest}","leg_index":0,"activity":"operating"}}
                ]
            }}"#
        ),
    );
    let cf_out = ok(&[
        "gl",
        "cash-flow",
        "--account",
        "1000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--policy",
        &direct_policy,
        "--json",
    ]);
    assert_eq!(field(&cf_out, "event"), Some("cash_flow"));
    let cf = doc(&cf_out);
    assert_eq!(text(&cf, "policy"), "cf-direct-v1");
    let cf_units = arr(&cf, "units");
    assert_eq!(cf_units.len(), 1);
    assert_eq!(text(&cf_units[0], "net_change"), "1000.00 USD");
    assert_eq!(text(&cf_units[0], "closing"), "1000.00 USD");
    let cf_human = ok(&[
        "cash-flow",
        "--account",
        "1000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--policy",
        &direct_policy,
    ]);
    assert!(cf_human.contains("cash flow `cf-direct-v1`"), "{cf_human}");

    let indirect_policy = write(
        &dir,
        "indirect_cf.json",
        &format!(
            r#"{{
                "name":"cf-indirect-v1",
                "cash_policy":"cf-direct-v1",
                "cash_accounts":["1000"],
                "assignments":[
                    {{"entry_digest":"{e1_digest}","leg_index":0,"activity":"operating"}}
                ],
                "adjustments":[
                    {{"entry_digest":"{e3_digest}","leg_index":0,"category":"non_cash","sign":"debit_minus_credit","reason":"depreciation expense"}},
                    {{"entry_digest":"{e2_digest}","leg_index":0,"category":"working_capital","sign":"credit_minus_debit","reason":"increase in AR"}}
                ]
            }}"#
        ),
    );
    let icf_out = ok(&[
        "gl",
        "cash-flow",
        "--indirect",
        "--income-period",
        "FY2026-P03",
        "--account",
        "1000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--policy",
        &indirect_policy,
        "--json",
    ]);
    assert_eq!(field(&icf_out, "event"), Some("indirect_cash_flow"));
    let icf = doc(&icf_out);
    let icf_units = arr(&icf, "units");
    assert_eq!(icf_units.len(), 1);
    assert_eq!(text(&icf_units[0], "net_income"), "1250.00 USD");
    assert_eq!(text(&icf_units[0], "non_cash"), "150.00 USD");
    assert_eq!(text(&icf_units[0], "working_capital"), "-400.00 USD");
    assert_eq!(text(&icf_units[0], "operating"), "1000.00 USD");
    assert_eq!(text(&icf_units[0], "direct_operating"), "1000.00 USD");
    assert_eq!(text(&icf_units[0], "operating_residual"), "0.00 USD");
    assert_eq!(text(&icf_units[0], "net_change"), "1000.00 USD");
    assert_eq!(text(&icf_units[0], "closing"), "1000.00 USD");
    let icf_human = ok(&[
        "gl",
        "cash-flow",
        "--indirect",
        "--income-period",
        "FY2026-P03",
        "--account",
        "1000",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--policy",
        &indirect_policy,
    ]);
    assert!(
        icf_human.contains("indirect cash flow `cf-indirect-v1`"),
        "{icf_human}"
    );
    Ok(())
}

/// Docket, Steward & Migration controls end-to-end (bead fa-wk4h):
/// - `fa book create --opening-date`
/// - `fa document read|redact|disclose|custody`
/// - `fa hold place|show|release` (alias + `fa document hold ...`)
/// - `fa erase` (alias + `fa document erase ...`): refused with exit 7 (`FA-REF-117`)
///   under active legal hold, and exit 3 (`FA-REF-088`) once released
/// - `fa attest review|manual|register-equals` (alias + `fa document attest ...`)
/// - `fa proof evidence-disclosure`
/// - `fa migrate open|stage|show|finalize|abandon`
#[test]
fn docket_steward_and_migration_controls_round_trip() -> std::io::Result<()> {
    let dir = tmp("docket-steward-migrate")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "{args:?}\n{out}\n{err}");
        out
    };
    let fail = |args: &[&str], expected_code: i32| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, expected_code, "{args:?}\n{out}\n{err}");
        out
    };

    // 1. Create book with `--opening-date 2026-01-01`, chart, and periods
    ok(&[
        "book",
        "create",
        "--name",
        "Migration & Steward Co",
        "--opening-date",
        "2026-01-01",
        "--json",
    ]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[
            {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
            {"code":"3000","name":"Opening Equity","type":"Equity","unit":"USD"},
            {"code":"6000","name":"Bank Fees","type":"Expense","unit":"USD"}
        ]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-OPEN", "--json"]);
    ok(&["period", "soft-close", "FY2026-OPEN", "--json"]);
    ok(&[
        "period",
        "close",
        "FY2026-OPEN",
        "--reason",
        "Scheduled",
        "--yes",
        "--json",
    ]);
    let lock_plan = dir.join("lock_open.plan");
    let lock_plan_s = lock_plan.to_str().unwrap();
    let lock_planned = ok(&[
        "period",
        "lock",
        "FY2026-OPEN",
        "--reason",
        "Scheduled",
        "--plan-out",
        lock_plan_s,
        "--json",
    ]);
    let lock_digest = field(&lock_planned, "proposal_digest")
        .unwrap_or_default()
        .to_string();
    let lock_app = ok(&[
        "approve",
        "--proposal",
        &lock_digest,
        "--as",
        "controller",
        "--json",
    ]);
    let lock_app_vid = field(&lock_app, "approval_vid")
        .unwrap_or_default()
        .to_string();
    ok(&[
        "period",
        "lock",
        "FY2026-OPEN",
        "--plan",
        lock_plan_s,
        "--approval",
        &lock_app_vid,
        "--json",
    ]);
    ok(&["period", "open", "FY2026-P03", "--json"]);

    // 2. Add a 2-chunk BankStatement document (governed by redaction contract 1)
    let mut bank_bytes = String::from("HEADER_PAGE_1_ACCOUNT_NUMBER_SECRET\n");
    while bank_bytes.len() < 4096 {
        bank_bytes.push('A');
    }
    bank_bytes.push_str("CHUNK_1_DISCLOSED_STATEMENT_LINES\n");
    let bank_path = write(&dir, "bank_stmt.txt", &bank_bytes);
    let added_bank = ok(&[
        "document",
        "add",
        &bank_path,
        "--kind",
        "BankStatement",
        "--grade",
        "AgentUpload",
        "--json",
    ]);
    let bank_oid = field(&added_bank, "oid").unwrap_or_default().to_string();

    // Derive redacted view (`fa document redact`)
    let redacted_out = ok(&[
        "document",
        "redact",
        &bank_oid,
        "--grant",
        "privileged",
        "--json",
    ]);
    assert_eq!(field(&redacted_out, "event"), Some("redacted_view_derived"));
    assert_eq!(int(&doc(&redacted_out), "contract"), Some(1));

    // Read without `privileged` -> returns redacted view
    let read_redacted = ok(&["document", "read", &bank_oid, "--json"]);
    assert_eq!(field(&read_redacted, "event"), Some("document_read"));
    assert_eq!(field(&read_redacted, "view"), Some("redacted"));
    assert_eq!(int(&doc(&read_redacted), "disclosed_chunks"), Some(1));
    assert_eq!(int(&doc(&read_redacted), "withheld_chunks"), Some(1));

    // Read with `read` + `privileged` -> returns full view
    let read_full_path = dir.join("bank_full_copy.txt");
    let read_full = ok(&[
        "document",
        "read",
        &bank_oid,
        "--out",
        read_full_path.to_str().unwrap(),
        "--grant",
        "read",
        "--grant",
        "privileged",
        "--json",
    ]);
    assert_eq!(field(&read_full, "view"), Some("full"));
    assert!(read_full_path.exists());

    // Disclose chunk 1 (`fa document disclose`)
    let disclose_out = ok(&["document", "disclose", &bank_oid, "--chunk", "1", "--json"]);
    assert_eq!(
        field(&disclose_out, "event"),
        Some("document_disclosure_exported")
    );
    assert_eq!(field(&disclose_out, "access"), Some("redacted"));

    // Custody transfer & chain (`fa document custody`)
    let cust_xfer = ok(&[
        "document",
        "custody",
        &bank_oid,
        "--to",
        "records_clerk",
        "--json",
    ]);
    assert_eq!(field(&cust_xfer, "event"), Some("custody_transferred"));
    let cust_chain = ok(&["document", "custody", &bank_oid, "--json"]);
    assert_eq!(field(&cust_chain, "event"), Some("custody_chain"));
    assert_eq!(arr(&doc(&cust_chain), "events").len(), 2);

    // 3. Attestations (`fa attest review`, `fa attest manual`, `fa attest register-equals`)
    let rev_att = ok(&["attest", "review", &bank_oid, "--as", "reviewer", "--json"]);
    assert_eq!(field(&rev_att, "event"), Some("attestation_recorded"));
    assert_eq!(field(&rev_att, "claim"), Some("Reviewed"));

    // Post an entry citing `bank_oid` and export `fa proof evidence-disclosure`
    let fee_entry = write(
        &dir,
        "fee.json",
        r#"{"effective_date":"2026-03-10","idempotency_key":"march-bank-fee","legs":[{"side":"debit","account":"6000","amount":"25.00 USD"},{"side":"credit","account":"1000","amount":"25.00 USD"}],"description":"March wire fee"}"#,
    );
    let fee_posted = ok(&[
        "post",
        "--intent",
        &fee_entry,
        "--evidence",
        &bank_oid,
        "--json",
    ]);
    let fee_vid = field(&fee_posted, "vid").unwrap_or_default().to_string();

    // Create checkpoint & export `fa proof evidence-disclosure`
    ok(&["checkpoint", "create", "--grant", "witness", "--json"]);
    let ev_disc = ok(&[
        "proof",
        "evidence-disclosure",
        "--entry",
        &fee_vid,
        "--document",
        &bank_oid,
        "--chunk",
        "1",
        "--json",
    ]);
    assert_eq!(
        field(&ev_disc, "event"),
        Some("evidence_disclosure_exported")
    );
    assert_eq!(field(&ev_disc, "access"), Some("redacted"));

    // ManualAssertion attestation (`fa attest manual`)
    let manual_intent = write(
        &dir,
        "manual_fee.json",
        r#"{"effective_date":"2026-03-12","idempotency_key":"manual-fee-1","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}],"description":"Uninvoiced bank charge"}"#,
    );
    let man_att = ok(&[
        "attest",
        "manual",
        "--intent",
        &manual_intent,
        "--reason",
        "NoDocumentIssued",
        "--statement",
        "bank fee below invoice threshold",
        "--json",
    ]);
    assert_eq!(field(&man_att, "event"), Some("attestation_recorded"));
    assert_eq!(field(&man_att, "claim"), Some("ManualAssertion"));

    // RegisterEquals attestation (`fa attest register-equals`)
    let reg_att = ok(&[
        "attest",
        "register-equals",
        "--account",
        "1000",
        "--period",
        "FY2026-P03",
        "--evidence",
        &bank_oid,
        "--json",
    ]);
    assert_eq!(field(&reg_att, "event"), Some("attestation_recorded"));
    assert_eq!(field(&reg_att, "claim"), Some("RegisterEquals"));
    assert_eq!(doc(&reg_att).get("holds"), Some(&Json::Bool(true)));
    let reg_att_vid = field(&reg_att, "attestation_vid")
        .unwrap_or_default()
        .to_string();
    let reg_check = ok(&["attest", "register-equals", &reg_att_vid, "--json"]);
    assert_eq!(doc(&reg_check).get("holds"), Some(&Json::Bool(true)));

    // 4. Legal Holds & Erasure (`fa hold place|show|release` and `fa erase`)
    let court_order_path = write(&dir, "court_order.txt", "PRESERVATION ORDER 2026-CV-99");
    let added_order = ok(&[
        "document",
        "add",
        &court_order_path,
        "--kind",
        "CourtOrder",
        "--grade",
        "HumanUpload",
        "--json",
    ]);
    let order_oid = field(&added_order, "oid").unwrap_or_default().to_string();

    let placed_hold = ok(&[
        "hold",
        "place",
        "--authority",
        &order_oid,
        "--subject",
        &bank_oid,
        "--effective",
        "2026-03-15",
        "--description",
        "Subpoena preservation",
        "--json",
    ]);
    assert_eq!(field(&placed_hold, "event"), Some("legal_hold_placed"));
    let hold_vid = field(&placed_hold, "hold_vid")
        .unwrap_or_default()
        .to_string();

    let shown_hold = ok(&["hold", "show", &hold_vid, "--json"]);
    assert_eq!(field(&shown_hold, "event"), Some("legal_hold"));
    assert_eq!(doc(&shown_hold).get("active"), Some(&Json::Bool(true)));
    // The subject names its active hold: what blocks its erasure.
    let held = ok(&["hold", "list", "--subject", &bank_oid, "--json"]);
    assert_eq!(field(&held, "event"), Some("legal_holds"));
    assert_eq!(arr(&doc(&held), "holds"), [Json::Str(hold_vid.clone())]);
    let unheld = ok(&["hold", "list", "--subject", &order_oid, "--json"]);
    assert!(
        arr(&doc(&unheld), "holds").is_empty(),
        "the authority document is not itself held: {unheld}"
    );

    // Erase while under active legal hold -> refused with exit 7 (FA-REF-117)
    let erase_held = fail(&["erase", &bank_oid, "--yes", "--json"], 7);
    assert!(erase_held.contains("FA-REF-117"), "{erase_held}");

    // Plan and release legal hold with independent approver
    let rel_plan = dir.join("release.plan");
    let rel_plan_s = rel_plan.to_str().unwrap();
    let rel_planned = ok(&[
        "hold",
        "release",
        &hold_vid,
        "--effective",
        "2026-03-20",
        "--plan-out",
        rel_plan_s,
        "--json",
    ]);
    assert_eq!(
        field(&rel_planned, "event"),
        Some("legal_hold_release_planned")
    );
    let rel_digest = field(&rel_planned, "proposal_digest")
        .unwrap_or_default()
        .to_string();
    let rel_app = ok(&[
        "approve",
        "--proposal",
        &rel_digest,
        "--as",
        "general_counsel",
        "--json",
    ]);
    let rel_app_vid = field(&rel_app, "approval_vid")
        .unwrap_or_default()
        .to_string();
    let released = ok(&[
        "hold",
        "release",
        &hold_vid,
        "--plan",
        rel_plan_s,
        "--approval",
        &rel_app_vid,
        "--json",
    ]);
    assert_eq!(field(&released, "event"), Some("legal_hold_released"));
    let after_release = ok(&["hold", "list", "--subject", &bank_oid, "--json"]);
    assert!(
        arr(&doc(&after_release), "holds").is_empty(),
        "a released hold is no longer active: {after_release}"
    );

    // Erase after hold release -> refused with exit 3 (FA-REF-088: financial records not erasable)
    let erase_after = fail(&["erase", &bank_oid, "--yes", "--json"], 3);
    assert!(erase_after.contains("FA-REF-088"), "{erase_after}");

    // 5. Migration run (`fa migrate open|stage|show|finalize|abandon`)
    let tb_doc_path = write(&dir, "legacy_tb.json", r#"{"legacy":"tb-2026-01-01"}"#);
    let added_tb = ok(&[
        "document",
        "add",
        &tb_doc_path,
        "--kind",
        "Spreadsheet",
        "--grade",
        "HumanUpload",
        "--json",
    ]);
    let tb_oid = field(&added_tb, "oid").unwrap_or_default().to_string();

    let run_intent = write(
        &dir,
        "mig_open.json",
        &format!(
            r#"{{
                "run_key":"go-live-2026",
                "source_system":"netsuite",
                "mode":"OpeningOnly",
                "trial_balance":"{tb_oid}",
                "opening_date":"2026-01-01",
                "lines":[
                    {{"account":"1000","unit":"USD","debit":"500.00"}},
                    {{"account":"3000","unit":"USD","credit":"500.00"}}
                ]
            }}"#
        ),
    );
    let mig_opened = ok(&["migrate", "open", "--intent", &run_intent, "--json"]);
    assert_eq!(field(&mig_opened, "event"), Some("migration_controlled"));
    assert_eq!(field(&mig_opened, "to"), Some("Open"));
    let run_vid = field(&mig_opened, "run_vid")
        .unwrap_or_default()
        .to_string();

    // Stage migration chunk with two independent approvals
    let chunk_intent = write(
        &dir,
        "mig_chunk.json",
        &format!(
            r#"{{
                "effective_date":"2026-01-01",
                "effective_period":"FY2026-OPEN",
                "idempotency_key":"mig-chunk-1",
                "evidence":["{tb_oid}"],
                "legs":[
                    {{"side":"debit","account":"1000","amount":"500.00 USD"}},
                    {{"side":"credit","account":"3000","amount":"500.00 USD"}}
                ],
                "description":"Opening balance migration chunk"
            }}"#
        ),
    );
    let stage_plan_path = dir.join("mig_stage.plan");
    let stage_plan_s = stage_plan_path.to_str().unwrap();
    let stage_planned = ok(&[
        "migrate",
        "stage",
        "go-live-2026",
        "--intent",
        &chunk_intent,
        "--plan-out",
        stage_plan_s,
        "--json",
    ]);
    assert_eq!(field(&stage_planned, "event"), Some("migration_planned"));
    let stage_digest = field(&stage_planned, "proposal_digest")
        .unwrap_or_default()
        .to_string();
    let s_app1 = field(
        &ok(&[
            "approve",
            "--proposal",
            &stage_digest,
            "--as",
            "mig_approver_1",
            "--json",
        ]),
        "approval_vid",
    )
    .unwrap_or_default()
    .to_string();
    let s_app2 = field(
        &ok(&[
            "approve",
            "--proposal",
            &stage_digest,
            "--as",
            "mig_approver_2",
            "--json",
        ]),
        "approval_vid",
    )
    .unwrap_or_default()
    .to_string();
    let staged = ok(&[
        "migrate",
        "stage",
        "go-live-2026",
        "--plan",
        stage_plan_s,
        "--approval",
        &s_app1,
        "--approval",
        &s_app2,
        "--json",
    ]);
    assert_eq!(field(&staged, "event"), Some("posted"));

    // Show migration run (`fa migrate show`)
    let mig_shown = ok(&["migrate", "show", &run_vid, "--json"]);
    assert_eq!(field(&mig_shown, "event"), Some("migration_run"));
    assert_eq!(doc(&mig_shown).get("ties_out"), Some(&Json::Bool(true)));
    assert_eq!(int(&doc(&mig_shown), "chunk_count"), Some(1));

    // Finalize migration run with two independent approvals
    let fin_plan_path = dir.join("mig_fin.plan");
    let fin_plan_s = fin_plan_path.to_str().unwrap();
    let fin_planned = ok(&[
        "migrate",
        "finalize",
        "go-live-2026",
        "--plan-out",
        fin_plan_s,
        "--json",
    ]);
    assert_eq!(field(&fin_planned, "event"), Some("migration_planned"));
    let fin_digest = field(&fin_planned, "proposal_digest")
        .unwrap_or_default()
        .to_string();
    let f_app1 = field(
        &ok(&[
            "approve",
            "--proposal",
            &fin_digest,
            "--as",
            "fin_approver_1",
            "--json",
        ]),
        "approval_vid",
    )
    .unwrap_or_default()
    .to_string();
    let f_app2 = field(
        &ok(&[
            "approve",
            "--proposal",
            &fin_digest,
            "--as",
            "fin_approver_2",
            "--json",
        ]),
        "approval_vid",
    )
    .unwrap_or_default()
    .to_string();
    let finalized = ok(&[
        "migrate",
        "finalize",
        "go-live-2026",
        "--plan",
        fin_plan_s,
        "--approval",
        &f_app1,
        "--approval",
        &f_app2,
        "--json",
    ]);
    assert_eq!(field(&finalized, "event"), Some("migration_controlled"));
    assert_eq!(field(&finalized, "to"), Some("Finalized"));

    // 6. Batch import run and receipt (`fa import run` & `fa import receipt`)
    let imp_doc2_path = write(&dir, "imp_doc2.txt", "Batch Import Document #2");
    let imp_recorded = ok(&[
        "import",
        "run",
        "--source",
        "Connector",
        "--file",
        &tb_doc_path,
        "--file",
        &imp_doc2_path,
        "--kind",
        "Invoice",
        "--grade",
        "HumanUpload",
        "--date",
        "2026-03-15",
        "--description",
        "Batch connector intake",
        "--key",
        "imp-batch-1",
        "--json",
    ]);
    assert_eq!(field(&imp_recorded, "event"), Some("import_recorded"));
    assert_eq!(field(&imp_recorded, "source_kind"), Some("Connector"));
    assert_eq!(int(&doc(&imp_recorded), "document_count"), Some(2));
    let imp_run_vid = field(&imp_recorded, "run_vid")
        .unwrap_or_default()
        .to_string();
    let rec_oids: Vec<String> = arr(&doc(&imp_recorded), "recorded")
        .iter()
        .chain(arr(&doc(&imp_recorded), "already_held").iter())
        .filter_map(|j| j.as_str().map(str::to_string))
        .collect();
    let mut sorted_oids = rec_oids;
    sorted_oids.sort();
    assert_eq!(sorted_oids.len(), 2);

    // Inspect and verify receipt against the exact ascending OIDs
    let imp_receipt = ok(&[
        "import",
        "receipt",
        &imp_run_vid,
        "--evidence",
        &sorted_oids[0],
        "--evidence",
        &sorted_oids[1],
        "--json",
    ]);
    assert_eq!(field(&imp_receipt, "event"), Some("import_receipt"));
    assert_eq!(doc(&imp_receipt).get("verified"), Some(&Json::Bool(true)));

    // Negative receipt verification: missing an OID refuses with exit 8 (FA-REF-115)
    let bad_receipt = fail(
        &[
            "import",
            "receipt",
            &imp_run_vid,
            "--evidence",
            &sorted_oids[0],
            "--json",
        ],
        8,
    );
    assert!(bad_receipt.contains("FA-REF-115"), "{bad_receipt}");

    // Unregistered Scan source refuses with exit 2 (FA-REF-083)
    let bad_scan = fail(
        &[
            "import",
            "run",
            "--source",
            "Scan:unregistered-scanner",
            "--file",
            &imp_doc2_path,
            "--json",
        ],
        2,
    );
    assert!(bad_scan.contains("FA-REF-083"), "{bad_scan}");
    Ok(())
}

#[test]
fn allocate_and_settle_review_approve_plan_and_commit_workflows() -> std::io::Result<()> {
    let dir = tmp("allocate-and-settle-e2e")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        assert!(err.is_empty(), "{err}");
        out
    };

    ok(&["book", "create", "--name", "Alloc & Settle Co", "--json"]);
    let chart_path = write(
        &dir,
        "chart.json",
        r#"{"accounts":[
            {"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},
            {"code":"1100","name":"Accounts Receivable","type":"Asset","leaf":true,"unit":"USD"},
            {"code":"2100","name":"Unapplied Cash","type":"Liability","leaf":true,"unit":"USD"},
            {"code":"4000","name":"Service Revenue","type":"Revenue","leaf":true,"unit":"USD"},
            {"code":"6000","name":"Shared Rent Pool","type":"Expense","leaf":true,"unit":"USD"},
            {"code":"6010","name":"Rent Dept A","type":"Expense","leaf":true,"unit":"USD"},
            {"code":"6020","name":"Rent Dept B","type":"Expense","leaf":true,"unit":"USD"},
            {"code":"6099","name":"Allocation Residual","type":"Expense","leaf":true,"unit":"USD"}
        ]}"#,
    );
    ok(&[
        "chart",
        "import",
        &chart_path,
        "--date",
        "2026-01-01",
        "--json",
    ]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);

    let doc_file = write(&dir, "invoice1.txt", "Customer Invoice #101 and Rent Bill");
    let doc_added = ok(&[
        "document",
        "add",
        &doc_file,
        "--kind",
        "Invoice",
        "--mime",
        "text/plain",
        "--grade",
        "HumanUpload",
        "--json",
    ]);
    let doc_oid = field(&doc_added, "oid").unwrap_or_default().to_string();

    // 1. Post rent pool expense (100.00 USD to 6000) and two AR invoices (60.00 USD and 40.00 USD to 1100).
    let pool_intent = write(
        &dir,
        "pool.json",
        &format!(
            r#"{{
                "effective_date": "2026-03-05",
                "idempotency_key": "rent-pool-01",
                "description": "March shared rent pool",
                "evidence": ["{doc_oid}"],
                "legs": [
                    {{"side": "debit", "account": "6000", "amount": "100.00 USD"}},
                    {{"side": "credit", "account": "1000", "amount": "100.00 USD"}}
                ]
            }}"#
        ),
    );
    ok(&["post", "--intent", &pool_intent, "--json"]);

    let inv1_intent = write(
        &dir,
        "inv1.json",
        &format!(
            r#"{{
                "effective_date": "2026-03-06",
                "idempotency_key": "ar-inv-101",
                "description": "Invoice 101",
                "evidence": ["{doc_oid}"],
                "legs": [
                    {{"side": "debit", "account": "1100", "amount": "60.00 USD"}},
                    {{"side": "credit", "account": "4000", "amount": "60.00 USD"}}
                ]
            }}"#
        ),
    );
    let inv1_posted = ok(&["post", "--intent", &inv1_intent, "--json"]);
    let inv1_vid = field(&inv1_posted, "vid").unwrap_or_default().to_string();

    let inv2_intent = write(
        &dir,
        "inv2.json",
        &format!(
            r#"{{
                "effective_date": "2026-03-07",
                "idempotency_key": "ar-inv-102",
                "description": "Invoice 102",
                "evidence": ["{doc_oid}"],
                "legs": [
                    {{"side": "debit", "account": "1100", "amount": "40.00 USD"}},
                    {{"side": "credit", "account": "4000", "amount": "40.00 USD"}}
                ]
            }}"#
        ),
    );
    let inv2_posted = ok(&["post", "--intent", &inv2_intent, "--json"]);
    let inv2_vid = field(&inv2_posted, "vid").unwrap_or_default().to_string();

    // 2. Explicit allocation: review -> approve -> commit (40.00 USD from 6000 to 6010/6020)
    let explicit_alloc = write(
        &dir,
        "alloc_explicit.json",
        r#"{
            "source": "6000",
            "source_side": "credit",
            "total": "40.00 USD",
            "effective_date": "2026-03-10",
            "idempotency_key": "alloc-exp-01",
            "description": "Partial explicit rent allocation",
            "method": "largest_remainder",
            "targets": [
                {"account": "6010", "weight": 1},
                {"account": "6020", "weight": 3}
            ]
        }"#,
    );
    let alloc_rev_path = dir.join("alloc_exp.review");
    let alloc_rev_s = alloc_rev_path.to_str().unwrap();
    let alloc_reviewed = ok(&[
        "allocate",
        "--intent",
        &explicit_alloc,
        "--review-out",
        alloc_rev_s,
        "--json",
    ]);
    assert_eq!(field(&alloc_reviewed, "event"), Some("allocation_reviewed"));
    assert_eq!(field(&alloc_reviewed, "kind"), Some("explicit"));
    assert_eq!(field(&alloc_reviewed, "total"), Some("40.00 USD"));
    let alloc_rev_digest = field(&alloc_reviewed, "review_digest")
        .unwrap_or_default()
        .to_string();

    let alloc_approved = ok(&[
        "allocate",
        "approve",
        "--review",
        alloc_rev_s,
        "--digest",
        &alloc_rev_digest,
        "--as",
        "controller",
        "--json",
    ]);
    assert_eq!(field(&alloc_approved, "event"), Some("approved"));
    let alloc_app_vid = field(&alloc_approved, "approval_vid")
        .unwrap_or_default()
        .to_string();

    let alloc_posted = ok(&[
        "allocate",
        "--review",
        alloc_rev_s,
        "--digest",
        &alloc_rev_digest,
        "--approval",
        &alloc_app_vid,
        "--json",
    ]);
    assert_eq!(field(&alloc_posted, "event"), Some("posted"));
    assert_eq!(field(&alloc_posted, "class"), Some("Allocation"));

    // 3. Balance-derived allocation: allocate remaining 60.00 USD in 6000 for FY2026-P03
    let bal_alloc = write(
        &dir,
        "alloc_balance.json",
        r#"{
            "source": "6000",
            "source_period": "FY2026-P03",
            "effective_date": "2026-03-12",
            "idempotency_key": "alloc-bal-01",
            "description": "Allocate remaining rent pool balance",
            "method": "pro_rata_residual_to_named",
            "rounding": "TowardZero",
            "residual_account": "6099",
            "targets": [
                {"account": "6010", "weight": 1},
                {"account": "6020", "weight": 6},
                {"account": "6099", "weight": 0}
            ]
        }"#,
    );
    let bal_reviewed = ok(&[
        "allocate",
        "--intent",
        &bal_alloc,
        "--review-only",
        "--json",
    ]);
    assert_eq!(field(&bal_reviewed, "event"), Some("allocation_reviewed"));
    assert_eq!(field(&bal_reviewed, "kind"), Some("balance"));
    assert_eq!(field(&bal_reviewed, "total"), Some("60.00 USD"));
    let bal_rev_bytes = field(&bal_reviewed, "bytes")
        .unwrap_or_default()
        .to_string();
    let bal_rev_digest = field(&bal_reviewed, "review_digest")
        .unwrap_or_default()
        .to_string();

    let bal_approved = ok(&[
        "approve",
        "--review",
        &bal_rev_bytes,
        "--digest",
        &bal_rev_digest,
        "--as",
        "controller",
        "--json",
    ]);
    assert_eq!(field(&bal_approved, "event"), Some("approved"));
    let bal_app_vid = field(&bal_approved, "approval_vid")
        .unwrap_or_default()
        .to_string();

    let bal_posted = ok(&[
        "allocate",
        "--review",
        &bal_rev_bytes,
        "--digest",
        &bal_rev_digest,
        "--approval",
        &bal_app_vid,
        "--json",
    ]);
    assert_eq!(field(&bal_posted, "event"), Some("posted"));

    // 4. Single-leg settlement: review -> approve -> dry-run -> commit against Invoice 101
    let settle1 = write(
        &dir,
        "settle1.json",
        &format!(
            r#"{{
                "effective_date": "2026-03-15",
                "idempotency_key": "settle-inv-101",
                "description": "Cash receipt for Invoice 101",
                "evidence": ["{doc_oid}"],
                "legs": [
                    {{"side": "debit", "account": "1000", "amount": "60.00 USD"}},
                    {{"side": "credit", "account": "1100", "amount": "60.00 USD"}}
                ],
                "payment_leg": 1,
                "targets": [
                    {{"entry": "{inv1_vid}", "ordinal": 0}}
                ]
            }}"#
        ),
    );
    let settle_rev_path = dir.join("settle1.review");
    let settle_rev_s = settle_rev_path.to_str().unwrap();
    let settle_reviewed = ok(&[
        "settle",
        "--intent",
        &settle1,
        "--review-out",
        settle_rev_s,
        "--json",
    ]);
    assert_eq!(
        field(&settle_reviewed, "event"),
        Some("settlement_reviewed")
    );
    assert_eq!(field(&settle_reviewed, "kind"), Some("single"));
    let settle_rev_digest = field(&settle_reviewed, "review_digest")
        .unwrap_or_default()
        .to_string();

    let settle_approved = ok(&[
        "settle",
        "approve",
        "--review",
        settle_rev_s,
        "--digest",
        &settle_rev_digest,
        "--as",
        "controller",
        "--json",
    ]);
    assert_eq!(field(&settle_approved, "event"), Some("approved"));
    let settle_app_vid = field(&settle_approved, "approval_vid")
        .unwrap_or_default()
        .to_string();

    let settle_planned = ok(&[
        "settle",
        "--review",
        settle_rev_s,
        "--digest",
        &settle_rev_digest,
        "--approval",
        &settle_app_vid,
        "--dry-run",
        "--json",
    ]);
    assert_eq!(field(&settle_planned, "event"), Some("plan"));

    let settle_posted = ok(&[
        "settle",
        "--review",
        settle_rev_s,
        "--digest",
        &settle_rev_digest,
        "--approval",
        &settle_app_vid,
        "--json",
    ]);
    assert_eq!(field(&settle_posted, "event"), Some("posted"));

    // 5. Multi-leg settlement group: settle Invoice 102 (40.00 USD) with 50.00 USD cash and 10.00 USD unapplied to 2100
    let settle_group = write(
        &dir,
        "settle_group.json",
        &format!(
            r#"{{
                "effective_date": "2026-03-18",
                "idempotency_key": "settle-group-102",
                "description": "Multi-leg receipt settling Invoice 102 with unapplied excess",
                "evidence": ["{doc_oid}"],
                "legs": [
                    {{"side": "debit", "account": "1000", "amount": "50.00 USD"}},
                    {{"side": "credit", "account": "1100", "amount": "40.00 USD"}},
                    {{"side": "credit", "account": "2100", "amount": "10.00 USD"}}
                ],
                "payments": [
                    {{
                        "payment_leg": 1,
                        "targets": [
                            {{"entry": "{inv2_vid}", "ordinal": 0}}
                        ]
                    }}
                ]
            }}"#
        ),
    );
    let group_posted = ok(&["settle", "--intent", &settle_group, "--json"]);
    assert_eq!(field(&group_posted, "event"), Some("posted"));

    // Verify open items on 1100 are now all settled (every leg has 0.00 USD open)
    let open_ar = ok(&["open-items", "--account", "1100", "--json"]);
    let open_doc = doc(&open_ar);
    assert_eq!(int(&open_doc, "count"), Some(4));
    for item in arr(&open_doc, "items") {
        assert_eq!(text(item, "open"), "0.00 USD");
    }
    Ok(())
}

/// fa-y5yz (FA-INV-07 / Engineering Doctrine #6): `recorded_at` is the commit
/// stream's `CommitSeq` assignment and is never user-supplied across the
/// domain model, CLI flags, intent JSON payloads, or MCP tool schemas.
#[test]
fn recorded_time_is_never_user_supplied_across_model_cli_and_mcp() -> std::io::Result<()> {
    let dir = tmp("recorded-time-negative")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    ok(&["book", "create", "--name", "Recorded Time Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let doc_oid = source_doc(&dir, &book);

    // 1. CLI flags attempting to supply recorded time on write commands are refused (exit 2).
    let valid_intent = write(
        &dir,
        "valid.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"rt-valid","description":"valid","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}]}"#,
    );
    for bad_flag in [
        "--recorded-at",
        "--as-recorded",
        "--recorded-time",
        "--commit-seq",
    ] {
        let (code, out, err) = fa(
            Some(&book),
            &[
                "post",
                "--intent",
                &valid_intent,
                "--evidence",
                &doc_oid,
                bad_flag,
                "999",
                "--json",
            ],
        );
        assert_eq!(
            code, 2,
            "flag {bad_flag} must be refused as usage error: {out}\n{err}"
        );
        assert!(out.contains("\"class\":\"usage\""), "{out}");
    }

    // 2. Intent JSON payloads attempting to supply `recorded_at`, `recorded_time`, or `commit_seq` are refused (exit 2).
    for bad_field in ["recorded_at", "recorded_time", "commit_seq"] {
        let bad_intent = write(
            &dir,
            &format!("bad-{bad_field}.json"),
            &format!(
                r#"{{"effective_date":"2026-03-15","{bad_field}":42,"idempotency_key":"rt-{bad_field}","description":"bad","legs":[{{"side":"debit","account":"6000","amount":"10.00 USD"}},{{"side":"credit","account":"1000","amount":"10.00 USD"}}]}}"#
            ),
        );
        let (code, out, err) = fa(
            Some(&book),
            &[
                "post",
                "--intent",
                &bad_intent,
                "--evidence",
                &doc_oid,
                "--json",
            ],
        );
        assert_eq!(
            code, 2,
            "intent JSON field `{bad_field}` must be refused: {out}\n{err}"
        );
        assert!(
            out.contains(&format!("unknown field `{bad_field}`")),
            "{out}"
        );
    }

    // 3. Verb registry & MCP schema inspection: no write verb or MCP write tool accepts a `recorded_at` or `recorded_time` parameter.
    let reg = registry().expect("verbs.toml");
    for v in &reg.verbs {
        if v.writes {
            for flag in &v.flags {
                let flag_name = flag.as_str();
                assert!(
                    !matches!(
                        flag_name,
                        "--recorded-at" | "--as-recorded" | "--recorded-time" | "--commit-seq"
                    ),
                    "mutating verb `{}` must never accept `{flag_name}`",
                    v.name
                );
            }
        }
    }

    // 4. Source-level structural verification: `EntryPayload` in `fa-model` has no `recorded_at` field,
    // and `Entry.recorded_at` is populated solely from the commit sequence in `fa-journal`.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let model_entry = std::fs::read_to_string(root.join("crates/fa-model/src/entry.rs"))?;
    let payload_struct = model_entry
        .split("pub struct EntryPayload")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .expect("EntryPayload struct definition");
    assert!(
        !payload_struct.contains("recorded_at"),
        "EntryPayload must never carry a user-supplied recorded_at field"
    );
    assert!(
        !model_entry.contains("fn set_recorded_at") && !model_entry.contains("with_recorded_at"),
        "fa-model must never expose a recorded_at setter"
    );

    // 5. Commit assigns monotonic `recorded_at` from the commit stream.
    let posted1 = ok(&[
        "post",
        "--intent",
        &valid_intent,
        "--evidence",
        &doc_oid,
        "--json",
    ]);
    let seq1: u64 = field(&posted1, "recorded_at")
        .expect("recorded_at on posted")
        .parse()
        .expect("numeric CommitSeq");
    assert!(seq1 > 0);
    Ok(())
}

#[test]
fn explain_entry_evidence_refusal_period_and_register_round_trip() -> std::io::Result<()> {
    // 1. `fa explain refusal <code> --json` works without a book and covers every
    //    registered row in `registries/refusal_catalog.toml`.
    let catalog =
        fa_registry::refusal_catalog::RefusalCatalog::embedded().expect("refusal_catalog.toml");
    assert!(!catalog.rows.is_empty());
    for row in &catalog.rows {
        let (code, out, err) = fa(None, &["explain", "refusal", &row.code, "--json"]);
        assert_eq!(code, 0, "explain refusal {}: {out}\n{err}", row.code);
        assert_eq!(field(&out, "event"), Some("refusal_explained"));
        let d = doc(&out);
        assert_eq!(text(&d, "id"), row.code.as_str());
        assert_eq!(text(&d, "class"), row.exit_name.as_str());
        assert_eq!(d.get("exit"), Some(&Json::Int(i128::from(row.exit))));
        assert_eq!(text(&d, "cite"), row.cite.as_str());
        assert_eq!(text(&d, "fix"), row.fix.as_str());
        if row.code == "FA-REF-003" {
            assert!(!arr(&d, "admissibility_cells").is_empty());
        }
        if row.code == "FA-REF-016" {
            assert!(!arr(&d, "sod_rules").is_empty());
        }
    }
    // Lookup by constant name also works, and unknown code is exit 2 usage.
    let (code_name, out_name, _) = fa(None, &["explain", "refusal", "UNBALANCED", "--json"]);
    assert_eq!(code_name, 0);
    assert_eq!(field(&out_name, "id"), Some("FA-REF-001"));
    let (bad_code, bad_out, _) = fa(None, &["explain", "refusal", "FA-REF-999", "--json"]);
    assert_eq!(bad_code, 2, "{bad_out}");

    // 2. Set up a book, chart, periods, and post an entry with evidence.
    let dir = tmp("explain-verbs")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "fa {args:?} exited {code}:\n{out}\n{err}");
        out
    };
    ok(&["book", "create", "--name", "Acme Corp", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Expense","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);

    // 3. `fa explain period FY2026-P03 --json`
    let period_ex = ok(&["explain", "period", "FY2026-P03", "--json"]);
    assert_eq!(field(&period_ex, "event"), Some("period_explained"));
    assert_eq!(field(&period_ex, "code"), Some("FY2026-P03"));
    assert_eq!(field(&period_ex, "state"), Some("Open"));
    assert_eq!(field(&period_ex, "kind"), Some("Normal"));
    let period_doc = doc(&period_ex);
    assert_eq!(arr(&period_doc, "transitions").len(), 1);
    assert!(!arr(&period_doc, "admissible_classes").is_empty());

    // 4. Add a document, post an entry, attach a supplement, and reverse the entry.
    let inv_oid = source_doc(&dir, &book);

    let intent_path = write(
        &dir,
        "intent.json",
        r#"{
          "effective_date": "2026-03-15",
          "idempotency_key": "ex-entry-1",
          "description": "Office supplies",
          "legs": [
            {"side": "debit", "account": "6000", "amount": "125.00 USD"},
            {"side": "credit", "account": "1000", "amount": "125.00 USD"}
          ]
        }"#,
    );
    let posted = ok(&[
        "post",
        "--intent",
        &intent_path,
        "--evidence",
        &inv_oid,
        "--json",
    ]);
    let entry_vid = field(&posted, "vid").unwrap_or_default().to_string();

    // 5. `fa explain evidence <entry-vid> --json`
    let ev_ex = ok(&["explain", "evidence", &format!("E:{entry_vid}"), "--json"]);
    assert_eq!(field(&ev_ex, "event"), Some("evidence_explained"));
    assert_eq!(field(&ev_ex, "entry"), Some(entry_vid.as_str()));
    assert_eq!(field(&ev_ex, "class"), Some("Original"));
    let ev_doc = doc(&ev_ex);
    assert_eq!(ev_doc.get("satisfied"), Some(&Json::Bool(true)));
    assert_eq!(arr(&ev_doc, "documents").len(), 1);

    // 6. Reverse the entry and check `fa explain entry <vid> --json` (both `supersedes` and `superseded_by`).
    let rev_out = ok(&["reverse", &entry_vid, "--reason", "WrongAmount", "--json"]);
    let rev_vid = field(&rev_out, "vid").unwrap_or_default().to_string();

    let entry_ex = ok(&["explain", "entry", &format!("E:{entry_vid}"), "--json"]);
    assert_eq!(field(&entry_ex, "event"), Some("entry_explained"));
    assert_eq!(field(&entry_ex, "vid"), Some(entry_vid.as_str()));
    assert_eq!(field(&entry_ex, "period"), Some("FY2026-P03"));
    let entry_doc = doc(&entry_ex);
    assert_eq!(arr(&entry_doc, "superseded_by").len(), 1);

    let rev_ex = ok(&["explain", "entry", &rev_vid, "--json"]);
    let rev_doc = doc(&rev_ex);
    assert_eq!(arr(&rev_doc, "supersedes").len(), 1);

    // 7. `fa explain register 1000 --period FY2026-P03 --unit USD --json`
    ok(&["registers", "advance", "--period", "FY2026-P03", "--json"]);
    let reg_ex = ok(&[
        "explain",
        "register",
        "1000",
        "--period",
        "FY2026-P03",
        "--unit",
        "USD",
        "--json",
    ]);
    assert_eq!(field(&reg_ex, "event"), Some("register_explained"));
    assert_eq!(field(&reg_ex, "account"), Some("1000"));
    assert_eq!(field(&reg_ex, "period"), Some("FY2026-P03"));
    assert_eq!(field(&reg_ex, "unit"), Some("USD"));
    let reg_doc = doc(&reg_ex);
    assert_eq!(reg_doc.get("green"), Some(&Json::Bool(true)));
    assert_eq!(field(&reg_ex, "cache_status"), Some("verified"));
    assert_eq!(reg_doc.get("stale"), Some(&Json::Bool(false)));

    // 8. Replay the recorded `DecisionCard` from `register_explained` bit-for-bit.
    let card_hex = text(&reg_doc, "decision_card_bytes");
    let digest_hex = text(&reg_doc, "decision_card_digest");
    let card_bytes: Vec<u8> = (0..card_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&card_hex[i..i + 2], 16).unwrap())
        .collect();
    let card = fa::DecisionCard::decode(&card_bytes).expect("decode DecisionCard");
    assert_eq!(card.canonical_bytes().unwrap(), card_bytes);
    let steward = fa_policy::Steward::embedded().unwrap();
    let replayed_digest = card
        .verify_replay(steward.policy_oid)
        .expect("replay DecisionCard");
    let expected_hex: String = replayed_digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(expected_hex, digest_hex);
    Ok(())
}

#[test]
fn teller_truthfulness_gate_next_actions_and_refusal_fixes() -> std::io::Result<()> {
    let dir = tmp("teller-truthfulness")?;
    let book_dir = dir.join("book");
    let book_str = book_dir.display().to_string();

    let run_cmd = |words: &[&str]| -> (i32, String, String) { fa(Some(&book_dir), words) };

    // Seed a book with chart, FY2026 periods, an open period FY2026-P03, a document, and an entry.
    assert_eq!(
        run_cmd(&["book", "create", "--name", "Acme", "--json"]).0,
        0
    );
    let chart_file = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Expense","type":"Expense","unit":"USD"}]}"#,
    );
    assert_eq!(run_cmd(&["chart", "import", &chart_file, "--json"]).0, 0);
    assert_eq!(
        run_cmd(&["period", "create", "--fiscal-year", "2026", "--json"]).0,
        0
    );
    assert_eq!(run_cmd(&["period", "open", "FY2026-P03", "--json"]).0, 0);
    let doc_oid = source_doc(&dir, &book_dir);

    let intent_file = write(
        &dir,
        "intent.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"truth-1","legs":[{"side":"debit","account":"6000","amount":"50.00 USD"},{"side":"credit","account":"1000","amount":"50.00 USD"}]}"#,
    );
    let (code, post_out, _) = run_cmd(&[
        "post",
        "--intent",
        &intent_file,
        "--evidence",
        &doc_oid,
        "--json",
    ]);
    assert_eq!(code, 0);
    let entry_vid = field(&post_out, "vid").unwrap().to_string();
    assert_eq!(
        run_cmd(&[
            "registers",
            "materialize",
            "--period",
            "FY2026-P03",
            "--json"
        ])
        .0,
        0
    );

    // 1. Verify `fa book info --json` includes `entities` (promised by FA-REF-104)
    // and `fa verify schedules --json` succeeds (promised by fa_journal::schedule).
    let (code, info_out, _) = run_cmd(&["book", "info", "--json"]);
    assert_eq!(code, 0);
    let info_doc = doc(&info_out);
    assert_eq!(info_doc.get("entities"), Some(&Json::Arr(vec![])));

    let (code, sched_out, _) = run_cmd(&["verify", "schedules", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(field(&sched_out, "event"), Some("schedules_verified"));

    // 2. Validate a command template against the registry (and optionally execute it).
    let next_chart_file = write(
        &dir,
        "next_chart.json",
        r#"{"accounts":[{"code":"2000","name":"Payable","type":"Liability","unit":"USD"}]}"#,
    );
    let reg = registry().expect("embedded verb registry");
    let validate_template = |cmd: &str| -> Result<Vec<String>, String> {
        let period_code = if cmd.starts_with("fa period open ") {
            "FY2026-P04"
        } else {
            "FY2026-P03"
        };
        let substituted = cmd
            .replace("<chart.json>", &next_chart_file)
            .replace("<entry.json>", &intent_file)
            .replace("<intent.json>", &intent_file)
            .replace("<resolution.json>", &intent_file)
            .replace("<oid>", &doc_oid)
            .replace("<vid>", &entry_vid)
            .replace("<dir>", &book_str)
            .replace("<code>", period_code)
            .replace("<account>", "1000")
            .replace("<N>", "2027")
            .replace("<FY>", "2027")
            .replace("<seq>", "1");
        let tokens: Vec<String> = substituted
            .split_whitespace()
            .map(ToString::to_string)
            .collect();
        let Some((first, rest)) = tokens.split_first() else {
            return Err("empty command template".into());
        };
        if first != "fa" {
            return Err(format!(
                "expected command to start with `fa`, got `{first}`"
            ));
        }
        let parsed = fa_cli::args::parse(rest, &reg.value_flags(), &reg.switches())
            .map_err(|e| format!("parse error in `{cmd}`: {}", e.message))?;
        let Some(verb_word) = parsed.positional.first() else {
            return Ok(rest.to_vec());
        };
        let verb = reg
            .verb(verb_word)
            .or_else(|| {
                reg.alias(verb_word)
                    .and_then(|a| a.expands.first())
                    .and_then(|v| reg.verb(v))
            })
            .ok_or_else(|| format!("unknown verb `{verb_word}` in `{cmd}`"))?;
        if !verb.subcommands.is_empty() {
            let sub = parsed
                .positional
                .get(1)
                .ok_or_else(|| format!("missing subcommand for `{}` in `{cmd}`", verb.name))?;
            if !verb.subcommands.contains(sub) {
                return Err(format!(
                    "unknown subcommand `{sub}` for `{}` in `{cmd}`",
                    verb.name
                ));
            }
        }
        for flag in parsed.flags.keys() {
            if !reg.global.flags.contains(flag) && !verb.flags.contains(flag) {
                return Err(format!(
                    "flag `{flag}` not registered on `{}` in `{cmd}`",
                    verb.name
                ));
            }
        }
        for sw in &parsed.switches {
            if !reg.global.switches.contains(sw) && !verb.switches.contains(sw) {
                return Err(format!(
                    "switch `{sw}` not registered on `{}` in `{cmd}`",
                    verb.name
                ));
            }
        }
        // `fa tb` requires a period selector (`--period`, `--fiscal-year`, or `--as-of`).
        if verb.name == "tb"
            && !parsed.flags.contains_key("--period")
            && !parsed.flags.contains_key("--fiscal-year")
            && !parsed.flags.contains_key("--as-of")
        {
            return Err(format!(
                "`fa tb` in `{cmd}` omits required `--period`, `--fiscal-year`, or `--as-of`"
            ));
        }
        Ok(rest.to_vec())
    };

    // Planted negative tests: prove the gate catches bad flags, bad subcommands, and bare `fa tb`.
    assert!(
        validate_template("fa tb --period <code> --nonexistent-flag 1 --json").is_err(),
        "planted unregistered flag must fail the gate"
    );
    assert!(
        validate_template("fa verify imaginary --json").is_err(),
        "planted unknown subcommand must fail the gate"
    );
    assert!(
        validate_template("fa tb --json").is_err(),
        "planted selector-less `fa tb` must fail the gate"
    );

    // Every `[[next_action]]` in `verbs.toml` must pass structural validation AND execute cleanly
    // (or, for `resolve` on a non-hold intent, reach the kernel rather than failing on CLI usage).
    for event in &reg.events {
        for action in reg.next_actions_for(&event.name) {
            let argv = validate_template(&action.command).unwrap_or_else(|e| {
                panic!(
                    "next_action `{}` on event `{}` failed gate: {e}",
                    action.command, event.name
                )
            });
            let words: Vec<&str> = argv.iter().map(String::as_str).collect();
            let (code, stdout, stderr) = run_cmd(&words);
            if action.command.starts_with("fa resolve ") {
                // `intent.json` is an Original intent without `resolves`, so `fa resolve`
                // reaches the handler's intent validation rather than failing on unknown verb/flag.
                assert!(
                    !stderr.contains("unknown command") && !stderr.contains("unknown flag"),
                    "next_action `{}` failed CLI dispatch: {stderr}",
                    action.command
                );
            } else {
                assert_eq!(
                    code, 0,
                    "next_action `{}` on event `{}` exited with {code}: stdout={stdout} stderr={stderr}",
                    action.command, event.name
                );
            }
        }
    }

    // 3. Check `fa robot-docs guide` does not advertise unimplemented correction classes
    // (`Replacement`, `Reclassification`, `Revision`, `Restatement`, `PriorPeriodAdjustment`)
    // as live without noting `FA-REF-102`.
    let (_, guide_out, _) = run_cmd(&["robot-docs", "guide", "--json"]);
    let guide_doc = doc(&guide_out);
    let guide_text = text(&guide_doc, "text");
    for unimplemented in [
        "Replacement",
        "Reclassification",
        "Revision",
        "Restatement",
        "PriorPeriodAdjustment",
    ] {
        if guide_text.contains(unimplemented) {
            assert!(
                guide_text.contains("FA-REF-102"),
                "robot-docs guide mentions unimplemented class `{unimplemented}` without noting FA-REF-102"
            );
        }
    }

    // 4. On a launch-bound surface, a kernel refusal whose catalog fix mentions `--grant`
    // (`FA-REF-011`) rewrites its fix so that it never instructs the caller to pass `--grant`.
    let auth = fa_cli::authority::LaunchAuthority::new(
        book_dir.clone(),
        None,
        "agent-1",
        fa_cli::authority::LaunchProfile::Agent,
        &["read"],
    )
    .unwrap();
    let refusal = fa_journal::Refusal::new(
        "FA-REF-011",
        7,
        "missing Post capability",
        "plan §14.2",
        "issue a capability token with --grant <profile> or request elevation",
    );
    let (code, cap) = fa_cli::cli::refuse_with_authority(
        &["fa".into(), "post".into(), "--json".into()],
        refusal,
        &auth,
        true,
    );
    assert_eq!(code, 7);
    let err_fix = field(&cap.stdout, "fix").unwrap_or_default();
    assert!(
        !err_fix.contains("--grant"),
        "bound refusal fix must not suggest `--grant`: {err_fix}"
    );
    Ok(())
}

#[test]
fn verify_periods_reports_refolded_lifecycle_and_rejects_period_filters() -> std::io::Result<()> {
    let dir = tmp("verify-periods-ok")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    ok(&["book", "create", "--name", "Verify Periods Co", "--json"]);
    let created = ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    let birth = field(&created, "recorded_at").expect("period birth sequence");
    ok(&["period", "open", "FY2026-P03", "--reason", "1", "--json"]);
    ok(&[
        "period",
        "soft-close",
        "FY2026-P03",
        "--reason",
        "1",
        "--json",
    ]);

    let (code, out, err) = fa(Some(&book), &["verify", "periods", "--json"]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("periods_verified"));
    let d = doc(&out);
    assert_eq!(int(&d, "periods_checked"), Some(15));
    assert_eq!(int(&d, "legacy_periods"), Some(0));
    assert_eq!(int(&d, "transitions_checked"), Some(2));
    assert_eq!(int(&d, "history_entries_checked"), Some(3));
    assert_eq!(int(&d, "history_commits_checked"), int(&d, "known_at"));
    assert!(arr(&d, "drift").is_empty());
    let p03 = arr(&d, "periods")
        .iter()
        .find(|p| p.get("code").and_then(Json::as_str) == Some("FY2026-P03"))
        .expect("FY2026-P03 check row");
    assert_eq!(text(p03, "born_state"), "Future");
    assert_eq!(text(p03, "stored_state"), "SoftClosed");
    assert_eq!(text(p03, "refolded_state"), "SoftClosed");
    assert_eq!(int(p03, "transitions"), Some(2));
    assert_eq!(p03.get("green"), Some(&Json::Bool(true)));

    // The CLI reopens the real disk book for every command. An earlier
    // prefix must retain its own birth state despite later state versions.
    let earlier = ok(&["verify", "periods", "--as-known-at", birth, "--json"]);
    let historical = doc(&earlier);
    assert_eq!(int(&historical, "known_at"), birth.parse::<i128>().ok());
    assert_eq!(
        int(&historical, "history_commits_checked"),
        int(&historical, "known_at")
    );
    assert_eq!(int(&historical, "history_entries_checked"), Some(1));
    assert_eq!(int(&historical, "transitions_checked"), Some(0));
    let old_p03 = arr(&historical, "periods")
        .iter()
        .find(|p| p.get("code").and_then(Json::as_str) == Some("FY2026-P03"))
        .expect("historical FY2026-P03 check row");
    assert_eq!(text(old_p03, "stored_state"), "Future");
    assert_eq!(text(old_p03, "refolded_state"), "Future");

    // Period filters and extra arguments are rejected with exit 2 (usage).
    for bad in [
        &["verify", "periods", "--period", "FY2026-P03", "--json"][..],
        &["verify", "periods", "--fiscal-year", "2026", "--json"][..],
        &["verify", "periods", "extra", "--json"][..],
    ] {
        let (c, o, e) = fa(None, bad);
        assert_eq!(c, 2, "args={bad:?}: {o}\n{e}");
        assert_eq!(text(&doc(&o), "class"), "usage");
    }
    // A selector on an unsupported verification must not silently verify HEAD.
    // Reject it before opening a book, through the same surface MCP invokes.
    for target in ["projections", "replay"] {
        let (code, out, err) = fa(None, &["verify", target, "--as-known-at", "1", "--json"]);
        assert_eq!(code, 2, "target={target}: {out}\n{err}");
        let error = doc(&out);
        assert_eq!(text(&error, "class"), "usage");
        assert_eq!(
            text(&error, "message"),
            "--as-known-at is supported only by verify periods, verify close and verify usage"
        );
    }
    Ok(())
}

#[test]
fn verify_periods_exits_eight_on_mirror_drift_or_deleted_birth_history() -> std::io::Result<()> {
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::types::Budget;
    use fa::{Book, BookKeys, Entropy};
    use fa_journal::BookSpec;
    use fa_model::Id128;
    use fa_model::symbols::{property, relation};
    use fa_money::UnitRegistry;
    use fa_time::PeriodState;
    use fgdb::{Database, DatabaseKeys, WriteBatch};
    use fgdb_types::CanonicalScalar;
    use fgdb_types::context::PurposeContexts;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    let dir = tmp("verify-periods-drift")?;
    let book = dir.join("book");
    let book_id = Id128([63; 16]);
    let keys = BookKeys::for_development(63);
    let usd = UnitRegistry::embedded().unwrap().lookup("USD").unwrap();
    let mut handle = Book::create_dir(
        &book,
        keys.clone(),
        BookSpec {
            book_id,
            name: "Verify periods drift".into(),
            base_unit: usd,
            calendar: fa_time::FiscalCalendar::monthly("fiscal", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(63),
    )
    .unwrap();
    keys.save(&book.join("book.keys")).unwrap();
    let birth_control = fa_journal::period_creation::creation_vid(handle.context(), 2026);
    let (birth, definitions) = handle
        .create_periods(
            2026,
            fgdb_types::VId(1),
            &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"]).unwrap(),
        )
        .unwrap()
        .unwrap();
    drop(handle);

    let (code, out, err) = fa(
        Some(&book),
        &["period", "open", "FY2026-P03", "--reason", "1", "--json"],
    );
    assert_eq!(code, 0, "{out}\n{err}");

    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let mut db = runtime
        .block_on(Database::open(
            &ctx.commit(),
            &book.join("store"),
            DatabaseKeys::new([63; 32], DatabaseSecurityNamespaceId([64; 32]), [65; 32]),
        ))
        .unwrap();
    let pvid = fa_model::period_vid("fiscal", "FY2026-P03");
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.set_vertex_property(
        pvid,
        property::STATE,
        Some(CanonicalScalar::Int(i64::from(PeriodState::Closed.tag()))),
    );
    let damaged_at = runtime.block_on(db.write(&ctx.commit(), batch)).unwrap();
    drop(db);

    let (code, red, err) = fa(Some(&book), &["verify", "periods", "--json"]);
    assert_eq!(code, 8, "{red}\n{err}");
    assert_eq!(field(&red, "event"), Some("error"));
    let error = doc(&red);
    assert_eq!(text(&error, "class"), "verification");
    assert!(text(&error, "cite").contains("FA-INV-02"));
    let detail = error.get("detail").expect("periods verification detail");
    assert_eq!(int(detail, "known_at"), Some(i128::from(damaged_at.0)));
    assert!(
        arr(detail, "drift")
            .iter()
            .filter_map(Json::as_str)
            .any(|d| d.contains("FY2026-P03") && d.contains("Closed") && d.contains("Open")),
        "{red}"
    );

    // Remove the entire fiscal-year projection and its birth control.
    // A live-row-only verifier has no surviving declaration to discover.
    // The native history still proves that the immutable Entry was deleted.
    let mut db = runtime
        .block_on(Database::open(
            &ctx.commit(),
            &book.join("store"),
            DatabaseKeys::new([63; 32], DatabaseSecurityNamespaceId([64; 32]), [65; 32]),
        ))
        .unwrap();
    let mut deletion = WriteBatch::new(relation::IN_BOOK);
    for vid in definitions
        .iter()
        .map(|period| fa_model::period_vid("fiscal", &period.code))
        .chain(std::iter::once(birth_control))
    {
        deletion.delete_edge(fa_journal::rows::edge_id(
            relation::IN_BOOK,
            vid,
            fa_journal::rows::book_root(),
        ));
        deletion.delete_vertex(vid);
    }
    runtime.block_on(db.write(&ctx.commit(), deletion)).unwrap();
    drop(db);

    let (code, deleted, err) = fa(Some(&book), &["verify", "periods", "--json"]);
    assert_eq!(code, 8, "{deleted}\n{err}");
    assert!(
        !deleted.contains("\"event\":\"periods_verified\""),
        "{deleted}"
    );
    let error = doc(&deleted);
    assert_eq!(text(&error, "class"), "verification");
    assert!(text(&error, "cite").contains("FA-INV-02"));
    let detail = error.get("detail").expect("native history finding");
    assert!(text(detail, "problem").contains("Entry"), "{deleted}");

    let selected = birth.0.to_string();
    let (code, historical, err) = fa(
        Some(&book),
        &["verify", "periods", "--as-known-at", &selected, "--json"],
    );
    assert_eq!(code, 0, "{historical}\n{err}");
    let historical = doc(&historical);
    assert_eq!(int(&historical, "known_at"), Some(i128::from(birth.0)));
    assert_eq!(int(&historical, "periods_checked"), Some(15));
    assert_eq!(int(&historical, "history_entries_checked"), Some(1));
    assert!(arr(&historical, "drift").is_empty());
    Ok(())
}

#[test]
fn off_balance_commitment_and_statistical_headcount_cli_scenario() -> std::io::Result<()> {
    let dir = tmp("off-balance-statistical-cli")?;
    let book = dir.join("book");
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[
            {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
            {"code":"4000","name":"Sales Revenue","type":"Revenue","unit":"USD"},
            {"code":"8510","name":"LOC Commitment","type":"OffBalance","unit":"USD"},
            {"code":"8520","name":"LOC Counter","type":"OffBalance","unit":"USD"},
            {"code":"9100","name":"Engineering Headcount","type":"Statistical","unit":"EACH"}
        ]}"#,
    );
    let (c, o, e) = fa(
        Some(&book),
        &["book", "create", "--name", "OffBalStat Co", "--json"],
    );
    assert_eq!(c, 0, "{o}\n{e}");
    let (c, o, e) = fa(Some(&book), &["chart", "import", &chart, "--json"]);
    assert_eq!(c, 0, "{o}\n{e}");
    let (c, o, e) = fa(
        Some(&book),
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    assert_eq!(c, 0, "{o}\n{e}");
    let (c, o, e) = fa(Some(&book), &["period", "open", "FY2026-P03", "--json"]);
    assert_eq!(c, 0, "{o}\n{e}");

    let ev_oid = source_doc(&dir, &book);

    // 1. Cross-class Asset + OffBalance fails with exit 3 (FA-REF-001)
    let bad_cross = write(
        &dir,
        "bad_cross.json",
        r#"{"idempotency_key":"bad-cross","effective_date":"2026-03-15","description":"cross","legs":[
            {"side":"debit","account":"1000","amount":"500.00 USD"},
            {"side":"credit","account":"8520","amount":"500.00 USD"}
        ]}"#,
    );
    let (c, o, e) = fa(
        Some(&book),
        &[
            "post",
            "--intent",
            &bad_cross,
            "--evidence",
            &ev_oid,
            "--json",
        ],
    );
    assert_eq!(c, 3, "{o}\n{e}");
    assert!(o.contains("FA-REF-001"), "{o}");

    // 2. Post monetary revenue (1000.00 USD), OffBalance commitment (2500.00 USD),
    //    and single-sided Statistical headcount (17 EACH)
    let sale_intent = write(
        &dir,
        "sale.json",
        r#"{"idempotency_key":"sale-1","effective_date":"2026-03-15","description":"sale","legs":[
            {"side":"debit","account":"1000","amount":"1000.00 USD"},
            {"side":"credit","account":"4000","amount":"1000.00 USD"}
        ]}"#,
    );
    let offbal_intent = write(
        &dir,
        "offbal.json",
        r#"{"idempotency_key":"loc-1","effective_date":"2026-03-15","description":"LOC commitment","legs":[
            {"side":"debit","account":"8510","amount":"2500.00 USD"},
            {"side":"credit","account":"8520","amount":"2500.00 USD"}
        ]}"#,
    );
    let stat_intent = write(
        &dir,
        "stat.json",
        r#"{"idempotency_key":"hc-1","effective_date":"2026-03-15","description":"headcount","legs":[
            {"side":"debit","account":"9100","amount":"17 EACH"}
        ]}"#,
    );
    for intent in [&sale_intent, &offbal_intent, &stat_intent] {
        let (c, o, e) = fa(
            Some(&book),
            &["post", "--intent", intent, "--evidence", &ev_oid, "--json"],
        );
        assert_eq!(c, 0, "{o}\n{e}");
    }

    // 3. Trial balance shows all rows, but monetary footing (`totals`) includes only 1000.00 USD
    let (c, tb_out, e) = fa(Some(&book), &["tb", "--period", "FY2026-P03", "--json"]);
    assert_eq!(c, 0, "{tb_out}\n{e}");
    let tb_doc = doc(&tb_out);
    let tb_data = tb_doc.get("data").unwrap_or(&tb_doc);
    assert_eq!(tb_data.get("balanced"), Some(&Json::Bool(true)));
    let totals = arr(tb_data, "unit_totals");
    assert_eq!(totals.len(), 1, "{tb_out}");
    assert_eq!(text(&totals[0], "unit"), "USD");
    assert_eq!(text(&totals[0], "debits"), "1000.00 USD");
    assert_eq!(text(&totals[0], "credits"), "1000.00 USD");
    let rows = arr(tb_data, "rows");
    assert!(
        rows.iter()
            .any(|r| text(r, "code") == "8510" && text(r, "debits") == "2500.00 USD"),
        "{tb_out}"
    );
    assert!(
        rows.iter()
            .any(|r| text(r, "code") == "9100" && text(r, "debits") == "17 EACH"),
        "{tb_out}"
    );

    // 4. Financial statements exclude OffBalance and Statistical accounts from footing
    let (c, bs_out, e) = fa(
        Some(&book),
        &[
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--json",
        ],
    );
    assert_eq!(c, 0, "{bs_out}\n{e}");
    let bs_doc = doc(&bs_out);
    let bs_data = bs_doc.get("data").unwrap_or(&bs_doc);
    let bs_lines = arr(bs_data, "lines");
    let usd_assets = bs_lines
        .iter()
        .find(|l| text(l, "code") == "assets" && text(l, "unit") == "USD")
        .expect("usd assets line");
    assert_eq!(
        arr(usd_assets, "amounts"),
        &[Json::Str("1000.00 USD".into())]
    );
    let usd_check = bs_lines
        .iter()
        .find(|l| text(l, "code") == "balance_check" && text(l, "unit") == "USD")
        .expect("usd balance_check line");
    assert_eq!(arr(usd_check, "amounts"), &[Json::Str("0.00 USD".into())]);
    Ok(())
}

#[test]
fn toon_robot_output_format_and_differential_oracle() -> std::io::Result<()> {
    let dir = tmp("toon-format-cli")?;
    let book = dir.join("book");
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[
            {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
            {"code":"4000","name":"Sales Revenue","type":"Revenue","unit":"USD"}
        ]}"#,
    );
    let (c, o, e) = fa(
        Some(&book),
        &["book", "create", "--name", "Toon Co", "--json"],
    );
    assert_eq!(c, 0, "{o}\n{e}");
    let (c, o, e) = fa(Some(&book), &["chart", "import", &chart, "--json"]);
    assert_eq!(c, 0, "{o}\n{e}");
    let (c, o, e) = fa(
        Some(&book),
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    assert_eq!(c, 0, "{o}\n{e}");
    let (c, o, e) = fa(Some(&book), &["period", "open", "FY2026-P03", "--json"]);
    assert_eq!(c, 0, "{o}\n{e}");

    let ev_oid = source_doc(&dir, &book);
    let sale_intent = write(
        &dir,
        "sale.json",
        r#"{"idempotency_key":"toon-sale-1","effective_date":"2026-03-10","description":"Consulting invoice & payment","legs":[
            {"side":"debit","account":"1000","amount":"1500.00 USD"},
            {"side":"credit","account":"4000","amount":"1500.00 USD"}
        ]}"#,
    );
    let (c, out, err) = fa(
        Some(&book),
        &[
            "post",
            "--intent",
            &sale_intent,
            "--evidence",
            &ev_oid,
            "--format",
            "toon",
        ],
    );
    assert_eq!(c, 0, "{out}\n{err}");
    assert!(out.contains("event: posted\n"), "{out}");
    assert!(out.contains("v: 1\n"), "{out}");

    // Read verbs under `--format toon`: tb, chart list, period list, open-items,
    // explain balance, statement balance-sheet, robot-docs guide.
    let commands: &[(&str, &[&str])] = &[
        ("tb", &["tb", "--period", "FY2026-P03", "--format", "toon"]),
        ("chart_list", &["chart", "list", "--format=toon"]),
        ("period_list", &["period", "list", "--format", "toon"]),
        (
            "open_items",
            &["open-items", "--account", "1000", "--format", "toon"],
        ),
        (
            "explain_balance",
            &[
                "explain",
                "balance",
                "1000",
                "--period",
                "FY2026-P03",
                "--format",
                "toon",
            ],
        ),
        (
            "statement_bs",
            &[
                "statement",
                "balance-sheet",
                "--for",
                "FY2026-P03",
                "--format",
                "toon",
            ],
        ),
        (
            "robot_docs_guide",
            &["robot-docs", "guide", "--format", "toon"],
        ),
    ];

    let tru_available = std::process::Command::new("tru")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());

    for (label, args) in commands {
        let (c_toon, out_toon, err_toon) = fa(Some(&book), args);
        assert_eq!(c_toon, 0, "{label} toon failed: {out_toon}\n{err_toon}");
        assert!(
            out_toon.contains("v: 1\n"),
            "{label} should contain v: 1 header: {out_toon}"
        );
        assert!(
            out_toon.contains("\nevent: "),
            "{label} should contain event field: {out_toon}"
        );

        // Equivalent `--json` invocation for comparison
        let mut json_args: Vec<&str> = args
            .iter()
            .copied()
            .filter(|a| *a != "--format" && *a != "toon" && *a != "--format=toon")
            .collect();
        json_args.push("--json");
        let (c_json, out_json, err_json) = fa(Some(&book), &json_args);
        assert_eq!(c_json, 0, "{label} json failed: {out_json}\n{err_json}");

        // Verify that parsing the JSON output and calling render_toon() produces the exact CLI output
        let parsed_json = json::parse(out_json.trim()).expect("parse --json envelope");
        assert_eq!(
            out_toon.trim_end_matches('\n'),
            parsed_json.render_toon(),
            "{label} CLI --format toon output must equal Json::render_toon() of --json"
        );

        // If `tru` reference decoder is installed in PATH, run differential round-trip check
        if tru_available {
            let mut child = std::process::Command::new("tru")
                .arg("--decode")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?;
            {
                use std::io::Write;
                let stdin = child.stdin.as_mut().expect("tru stdin");
                stdin.write_all(out_toon.as_bytes())?;
            }
            let decoded = child.wait_with_output()?;
            assert!(
                decoded.status.success(),
                "tru --decode failed on {label}: {}",
                String::from_utf8_lossy(&decoded.stderr)
            );
            let decoded_str = String::from_utf8(decoded.stdout)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let roundtripped = json::parse(decoded_str.trim()).expect("parse tru --decode output");
            assert_eq!(
                roundtripped, parsed_json,
                "tru --decode round-trip mismatch on {label}"
            );
        }
    }

    if !tru_available {
        eprintln!(
            "NOTE: external `tru` binary not in PATH; differential decode check UNRUN (in-house TOON v3.0 golden spec fixtures verified in fa-verbs)."
        );
    }

    // Verify tabular array formatting in `tb --format toon` and that numeric account codes remain quoted strings
    let (_, tb_toon, _) = fa(
        Some(&book),
        &["tb", "--period", "FY2026-P03", "--format", "toon"],
    );
    assert!(
        tb_toon
            .contains("rows[2]{code,credits,credits_pending,debits,debits_pending,name,net,type}:"),
        "tb rows should use TOON tabular header: {tb_toon}"
    );
    assert!(
        tb_toon.contains("\"1000\",0.00 USD,0.00 USD,1500.00 USD,0.00 USD,Cash,1500.00 USD,Asset"),
        "account code '1000' must be quoted so it stays a string, while '1500.00 USD' is an unquoted string token: {tb_toon}"
    );
    assert!(
        tb_toon.contains(
            "\"4000\",1500.00 USD,0.00 USD,0.00 USD,0.00 USD,Sales Revenue,\"-1500.00 USD\",Revenue"
        ),
        "negative amount '-1500.00 USD' must be quoted in TOON v3.0: {tb_toon}"
    );

    // Verify `--format json` is an exact alias for `--json`
    let (c_fmt_json, out_fmt_json, _) = fa(
        Some(&book),
        &["tb", "--period", "FY2026-P03", "--format", "json"],
    );
    let (c_flag_json, out_flag_json, _) =
        fa(Some(&book), &["tb", "--period", "FY2026-P03", "--json"]);
    assert_eq!(c_fmt_json, 0);
    assert_eq!(c_flag_json, 0);
    assert_eq!(out_fmt_json, out_flag_json);

    // Verify `--format text` forces human table mode
    let (c_text, out_text, _) = fa(
        Some(&book),
        &["tb", "--period", "FY2026-P03", "--format", "text"],
    );
    assert_eq!(c_text, 0);
    assert!(
        !out_text.starts_with('{') && !out_text.contains("\nv: 1\n"),
        "text mode must emit human table: {out_text}"
    );

    // Verify error envelope under `--format toon` renders in TOON format
    let (c_err_toon, out_err_toon, _) = fa(
        Some(&book),
        &["tb", "--period", "UNKNOWN", "--format", "toon"],
    );
    assert_eq!(c_err_toon, 2, "{out_err_toon}");
    assert!(out_err_toon.contains("event: error\n"), "{out_err_toon}");
    assert!(out_err_toon.contains("  exit: 2\n"), "{out_err_toon}");

    // Verify conflicting `--json` and `--format toon` refuses with exit code 2
    let (c_conflict, out_conflict, _) = fa(
        Some(&book),
        &["tb", "--period", "FY2026-P03", "--json", "--format", "toon"],
    );
    assert_eq!(c_conflict, 2, "{out_conflict}");
    assert!(
        out_conflict.contains("--json and --format disagree"),
        "{out_conflict}"
    );

    // Verify unknown `--format yaml` refuses with exit code 2
    let (c_bad, out_bad, err_bad) = fa(
        Some(&book),
        &["tb", "--period", "FY2026-P03", "--format", "yaml"],
    );
    assert_eq!(c_bad, 2, "{out_bad}\n{err_bad}");
    assert!(
        err_bad.contains("unknown output format `yaml`"),
        "{out_bad}\n{err_bad}"
    );

    Ok(())
}

/// fa-1d6: `fa capabilities --as <principal> [--grant <op>]... --json` exposes
/// `data.capability.binding.commitment` (64-hex); `fa capability revoke`
/// requires `--yes` (FA-REF-007, exit 7) and `issue_capability` (FA-REF-011,
/// exit 7); a confirmed revocation journals a `PolicyControl` entry and is
/// idempotent on repeat; subsequent `post` and `period` transitions under the
/// revoked capability refuse with `FA-REF-023` (exit 7) naming `fa capabilities`.
#[test]
fn capability_revocation_journals_policy_control_and_refuses_revoked_tokens_idempotently()
-> std::io::Result<()> {
    let (book, ev, dir) = envelope_book("capability-revoke")?;
    let fa_b = |args: &[&str]| fa(Some(&book), args);

    // 1. Discover capability commitments via `fa capabilities --json`.
    let (code, caps_post_out, _) =
        fa_b(&["capabilities", "--as", "clerk", "--grant", "post", "--json"]);
    assert_eq!(code, 0, "{caps_post_out}");
    let clerk_post_commitment = text(
        &doc(&caps_post_out)
            .get("capability")
            .and_then(|c| c.get("binding"))
            .cloned()
            .unwrap_or(Json::Null),
        "commitment",
    )
    .to_string();
    assert_eq!(clerk_post_commitment.len(), 64, "{caps_post_out}");

    let (code, caps_close_out, _) = fa_b(&[
        "capabilities",
        "--as",
        "clerk",
        "--grant",
        "close",
        "--json",
    ]);
    assert_eq!(code, 0, "{caps_close_out}");
    let clerk_soft_close_commitment = text(
        &doc(&caps_close_out)
            .get("capability")
            .and_then(|c| c.get("binding"))
            .cloned()
            .unwrap_or(Json::Null),
        "commitment",
    )
    .to_string();
    assert_eq!(clerk_soft_close_commitment.len(), 64, "{caps_close_out}");
    assert_ne!(clerk_post_commitment, clerk_soft_close_commitment);

    // 2. Unconfirmed `fa capability revoke` refuses FA-REF-007 (exit 7).
    let (code, unconfirmed_out, _) = fa_b(&[
        "capability",
        "revoke",
        "--commitment",
        &clerk_post_commitment,
        "--as",
        "controller",
        "--grant",
        "issue_capability",
        "--json",
    ]);
    assert_eq!(code, 7, "{unconfirmed_out}");
    assert_eq!(text(&doc(&unconfirmed_out), "refusal_id"), "FA-REF-007");
    assert!(
        text(&doc(&unconfirmed_out), "fix").contains("fa capabilities --json"),
        "{unconfirmed_out}"
    );

    // Revoker without `issue_capability` refuses FA-REF-011 (exit 7).
    let (code, no_grant_out, _) = fa_b(&[
        "capability",
        "revoke",
        "--commitment",
        &clerk_post_commitment,
        "--as",
        "controller",
        "--yes",
        "--json",
    ]);
    assert_eq!(code, 7, "{no_grant_out}");
    assert_eq!(text(&doc(&no_grant_out), "refusal_id"), "FA-REF-011");

    // 3. Confirmed `fa capability revoke` journals PolicyControl and is idempotent.
    let (code, revoked_out, _) = fa_b(&[
        "capability",
        "revoke",
        "--commitment",
        &clerk_post_commitment,
        "--as",
        "controller",
        "--grant",
        "issue_capability",
        "--yes",
        "--json",
    ]);
    assert_eq!(code, 0, "{revoked_out}");
    assert_eq!(field(&revoked_out, "event"), Some("capability_revoked"));
    let first_data = doc(&revoked_out);
    assert_eq!(
        first_data.get("already_recorded"),
        Some(&Json::Bool(false)),
        "{revoked_out}"
    );
    let first_entry = text(&first_data, "control_entry").to_string();
    let first_seq = int(&first_data, "recorded_at").unwrap();

    let (code, repeat_out, _) = fa_b(&[
        "capability",
        "revoke",
        "--commitment",
        &clerk_post_commitment,
        "--as",
        "controller",
        "--grant",
        "issue_capability",
        "--yes",
        "--json",
    ]);
    assert_eq!(code, 0, "{repeat_out}");
    let repeat_data = doc(&repeat_out);
    assert_eq!(
        repeat_data.get("already_recorded"),
        Some(&Json::Bool(true)),
        "{repeat_out}"
    );
    assert_eq!(text(&repeat_data, "control_entry"), first_entry);
    assert_eq!(int(&repeat_data, "recorded_at"), Some(first_seq));

    // Also revoke clerk's soft_close capability.
    let (code, revoked_close_out, _) = fa_b(&[
        "capability",
        "revoke",
        "--commitment",
        &clerk_soft_close_commitment,
        "--as",
        "controller",
        "--grant",
        "issue_capability",
        "--yes",
        "--json",
    ]);
    assert_eq!(code, 0, "{revoked_close_out}");

    // 4. Subsequent `post` and `period` transition under the revoked capabilities
    // refuse with FA-REF-023 (exit 7) and name `fa capabilities` in `fix`.
    let entry = write(
        &dir,
        "rent.json",
        r#"{"effective_date":"2026-03-10","description":"March rent","idempotency_key":"rent-revoked","legs":[{"side":"debit","account":"6000","amount":"50.00 USD"},{"side":"credit","account":"1000","amount":"50.00 USD"}]}"#,
    );
    let (code, post_refused, _) = fa_b(&[
        "post",
        "--intent",
        &entry,
        "--evidence",
        &ev,
        "--as",
        "clerk",
        "--json",
    ]);
    assert_eq!(code, 7, "{post_refused}");
    let post_err = doc(&post_refused);
    assert_eq!(
        text(&post_err, "refusal_id"),
        "FA-REF-023",
        "{post_refused}"
    );
    assert!(
        text(&post_err, "fix").contains("fa capabilities"),
        "{post_refused}"
    );

    let (code, period_refused, _) = fa_b(&[
        "period",
        "soft-close",
        "FY2026-P03",
        "--as",
        "clerk",
        "--json",
    ]);
    assert_eq!(code, 7, "{period_refused}");
    let period_err = doc(&period_refused);
    assert_eq!(
        text(&period_err, "refusal_id"),
        "FA-REF-023",
        "{period_refused}"
    );
    assert!(
        text(&period_err, "fix").contains("fa capabilities"),
        "{period_refused}"
    );

    // Another principal's unrevoked capability still succeeds.
    let (code, posted_out, _) = fa_b(&[
        "post",
        "--intent",
        &entry,
        "--evidence",
        &ev,
        "--as",
        "senior-clerk",
        "--json",
    ]);
    assert_eq!(code, 0, "{posted_out}");
    assert_eq!(field(&posted_out, "event"), Some("posted"));

    Ok(())
}

/// fa-2ly: `fa lots` (`fa gl lots`) lists cost-basis lots on an `AnyUnit`
/// account, plans disposals under `FIFO`, `LIFO`, `WeightedAverage`, and
/// `SpecificId`, refuses `LIFO` under `IFRS` citing `IAS 2.25`, and refuses
/// over-relief with `FA-REF-072` naming `open_quantity`.
#[test]
fn lots_cli_fifo_lifo_wac_specific_id_ifrs_refusal_and_over_relief() -> std::io::Result<()> {
    let dir = tmp("lots-cli")?;
    let book = dir.join("book");
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    ok(&["book", "create", "--name", "Lots Co", "--json"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[
            {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
            {"code":"1400","name":"Crypto Inventory","type":"Asset","unit":"any"},
            {"code":"3999","name":"Position Clearing","type":"Equity","unit":"any"}
        ]}"#,
    );
    ok(&["chart", "import", &chart, "--json"]);
    ok(&["period", "create", "--fiscal-year", "2026", "--json"]);
    ok(&["period", "open", "FY2026-P03", "--json"]);
    let ev = source_doc(&dir, &book);

    // Acquire Lot 1: 2.00000000 BTC @ $100.00 USD
    let buy1 = write(
        &dir,
        "buy1.json",
        r#"{
            "effective_date":"2026-03-05",
            "idempotency_key":"buy-lot-1",
            "legs":[
                {"side":"debit","account":"1400","amount":"2.00000000 BTC"},
                {"side":"credit","account":"3999","amount":"2.00000000 BTC"},
                {"side":"debit","account":"1400","amount":"100.00 USD"},
                {"side":"credit","account":"1000","amount":"100.00 USD"}
            ]
        }"#,
    );
    let p1 = doc(&ok(&[
        "post",
        "--intent",
        &buy1,
        "--evidence",
        &ev,
        "--json",
    ]));
    let lot1_vid = text(&p1, "vid").to_string();

    // Acquire Lot 2: 3.00000000 BTC @ $240.00 USD
    let buy2 = write(
        &dir,
        "buy2.json",
        r#"{
            "effective_date":"2026-03-10",
            "idempotency_key":"buy-lot-2",
            "legs":[
                {"side":"debit","account":"1400","amount":"3.00000000 BTC"},
                {"side":"credit","account":"3999","amount":"3.00000000 BTC"},
                {"side":"debit","account":"1400","amount":"240.00 USD"},
                {"side":"credit","account":"1000","amount":"240.00 USD"}
            ]
        }"#,
    );
    let p2 = doc(&ok(&[
        "post",
        "--intent",
        &buy2,
        "--evidence",
        &ev,
        "--json",
    ]));
    let lot2_vid = text(&p2, "vid").to_string();

    // Plan FIFO disposal of 3.00000000 BTC -> takes all 2 BTC of Lot 1 ($100) + 1 BTC of Lot 2 ($80) = $180.00 USD
    let fifo = doc(&ok(&[
        "lots",
        "--account",
        "1400",
        "--relieve",
        "3.00000000 BTC",
        "--law",
        "FIFO",
        "--json",
    ]));
    assert_eq!(int(&fifo, "count"), Some(2));
    let fifo_plan = fifo.get("disposal_plan").expect("disposal_plan");
    assert_eq!(text(fifo_plan, "law"), "FIFO");
    assert_eq!(text(fifo_plan, "total_cost"), "180.00 USD");

    // Plan LIFO disposal of 3.00000000 BTC under US-GAAP -> takes all 3 BTC of Lot 2 ($240.00 USD)
    let lifo = doc(&ok(&[
        "gl",
        "lots",
        "--account",
        "1400",
        "--relieve",
        "3.00000000 BTC",
        "--law",
        "LIFO",
        "--regime",
        "US-GAAP",
        "--json",
    ]));
    let lifo_plan = lifo.get("disposal_plan").expect("disposal_plan");
    assert_eq!(text(lifo_plan, "total_cost"), "240.00 USD");

    // Plan SpecificId disposal of 1.50000000 BTC from Lot 2 ($120.00 USD) + 0.50000000 BTC from Lot 1 ($25.00 USD) = $145.00 USD
    let spec = doc(&ok(&[
        "lots",
        "--account",
        "1400",
        "--relieve",
        "2.00000000 BTC",
        "--law",
        "SpecificId",
        "--target",
        &format!("{lot2_vid}:0"),
        "--target",
        &format!("{lot1_vid}:0"),
        "--json",
    ]));
    let spec_plan = spec.get("disposal_plan").expect("disposal_plan");
    assert_eq!(text(spec_plan, "law"), "SpecificId");

    // LIFO under IFRS is refused citing IAS 2.25
    let (ifrs_code, ifrs_out, _) = fa(
        Some(&book),
        &[
            "lots",
            "--account",
            "1400",
            "--relieve",
            "1.00000000 BTC",
            "--law",
            "LIFO",
            "--regime",
            "IFRS",
            "--json",
        ],
    );
    assert_eq!(ifrs_code, 3, "{ifrs_out}");
    let ifrs_err = doc(&ifrs_out);
    assert!(
        text(&ifrs_err, "cite").contains("IAS 2.25")
            || text(&ifrs_err, "message").contains("IAS 2.25"),
        "{ifrs_out}"
    );

    // Over-relief (requesting 6.00000000 BTC when 5.00000000 BTC is open) refuses with FA-REF-072
    let (over_code, over_out, _) = fa(
        Some(&book),
        &[
            "lots",
            "--account",
            "1400",
            "--relieve",
            "6.00000000 BTC",
            "--law",
            "FIFO",
            "--json",
        ],
    );
    assert_eq!(over_code, 3, "{over_out}");
    let over_err = doc(&over_out);
    assert_eq!(text(&over_err, "refusal_id"), "FA-REF-072", "{over_out}");
    assert!(
        text(&over_err, "message").contains("5.00000000 BTC"),
        "{over_out}"
    );

    Ok(())
}

/// fa-oz3: `fa explain lineage <vid>` reports the complete `SUPERSEDES`
/// lineage component containing `<vid>`, each edge's registered `netting_law`
/// from `supersession_kinds.toml`, and the net economic effect per
/// `(account, unit)`.
#[test]
fn explain_lineage_cli_reports_supersession_component_and_net_effect() -> std::io::Result<()> {
    let (book, ev, dir) = envelope_book("explain-lineage")?;
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };
    let entry = write(
        &dir,
        "rent.json",
        r#"{"effective_date":"2026-03-10","description":"March rent","idempotency_key":"lin-rent","legs":[{"side":"debit","account":"6000","amount":"150.00 USD"},{"side":"credit","account":"1000","amount":"150.00 USD"}]}"#,
    );
    let posted = doc(&ok(&[
        "post",
        "--intent",
        &entry,
        "--evidence",
        &ev,
        "--json",
    ]));
    let orig_vid = text(&posted, "vid").to_string();

    // Before reversal, net effect is +150.00 USD on 6000 and -150.00 USD on 1000.
    let before = doc(&ok(&["explain", "lineage", &orig_vid, "--json"]));
    assert_eq!(text(&before, "query_entry"), orig_vid);
    assert_eq!(text(&before, "root_entry"), orig_vid);
    assert_eq!(before.get("fully_reversed"), Some(&Json::Bool(false)));
    assert_eq!(arr(&before, "steps").len(), 1);

    // Reverse the entry.
    let rev = doc(&ok(&[
        "reverse",
        &orig_vid,
        "--reason",
        "WrongAmount",
        "--json",
    ]));
    let rev_vid = text(&rev, "vid").to_string();

    // After reversal, querying either orig_vid or rev_vid returns the 2-step component
    // with `netting_law: "negation"` and 0.00 USD net effect on both accounts.
    let after = doc(&ok(&["explain", "lineage", &rev_vid, "--json"]));
    assert_eq!(text(&after, "query_entry"), rev_vid);
    assert_eq!(text(&after, "root_entry"), orig_vid);
    assert_eq!(after.get("fully_reversed"), Some(&Json::Bool(true)));
    let steps = arr(&after, "steps");
    assert_eq!(steps.len(), 2);
    let sups = arr(&steps[1], "supersedes");
    assert_eq!(sups.len(), 1);
    assert_eq!(text(&sups[0], "kind"), "Reverses");
    assert_eq!(text(&sups[0], "netting_law"), "negation");
    assert_eq!(text(&sups[0], "reason"), "WrongAmount");
    for cell in arr(&after, "net_effect") {
        assert_eq!(text(cell, "net"), "0.00 USD");
    }
    // Neither the original nor its reversal reverses a reversal.
    for step in steps {
        assert_eq!(step.get("reverses_reversal"), Some(&Json::Bool(false)));
    }

    // Reversing the reversal revives the original by parity, and the
    // lineage flags it (plan §8.2; fa-s3wz).
    let revived = doc(&ok(&[
        "reverse",
        &rev_vid,
        "--reason",
        "WrongAmount",
        "--json",
    ]));
    let revived_vid = text(&revived, "vid").to_string();
    let again = doc(&ok(&["explain", "lineage", &revived_vid, "--json"]));
    assert_eq!(text(&again, "root_entry"), orig_vid);
    assert_eq!(again.get("fully_reversed"), Some(&Json::Bool(false)));
    let steps = arr(&again, "steps");
    assert_eq!(steps.len(), 3);
    let flags: Vec<_> = steps
        .iter()
        .map(|step| {
            (
                text(step, "entry").to_string(),
                step.get("reverses_reversal"),
            )
        })
        .collect();
    assert_eq!(
        flags,
        [
            (orig_vid.clone(), Some(&Json::Bool(false))),
            (rev_vid, Some(&Json::Bool(false))),
            (revived_vid, Some(&Json::Bool(true))),
        ]
    );
    assert!(
        arr(&again, "net_effect")
            .iter()
            .all(|cell| text(cell, "net") != "0.00 USD"),
        "the original's effect is back"
    );

    Ok(())
}

/// Plan §4.1, §4.5: parties, instruments and relationships are journaled
/// REA controls a real book can now create from the CLI, so an event can
/// name its participants and resources. Names are sealed and read back as
/// untrusted text; ownership is an exact ratio, never a float; codes are
/// identities, so an exact retry records nothing new.
#[test]
fn parties_instruments_and_relationships_are_recorded_from_the_cli() -> std::io::Result<()> {
    let (book, ev, dir) = envelope_book("rea-parties")?;
    let run = |args: &[&str]| -> (i32, String) {
        let (code, out, _) = fa(Some(&book), args);
        (code, out)
    };
    let vendor = write(
        &dir,
        "vendor.json",
        r#"{"code":"V-17","kind":"Vendor","name":"Acme Supplies","identifiers":{"ein":"12-3456789"},"external_ids":[{"system":"qbo","id":"55"}]}"#,
    );
    let (code, out) = run(&["party", "add", &vendor, "--json"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "event"), Some("rea_recorded"));
    assert_eq!(field(&out, "object"), Some("party"));
    assert_eq!(field(&out, "already_recorded"), Some("false"));
    let vendor_vid = field(&out, "target").unwrap().to_string();
    let (code, out) = run(&["party", "add", &vendor, "--json"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "already_recorded"), Some("true"));
    assert_eq!(field(&out, "target"), Some(vendor_vid.as_str()));
    for (name, body) in [
        (
            "bank",
            r#"{"code":"BANK-1","kind":"Bank","name":"First Bank"}"#,
        ),
        (
            "owner",
            r#"{"code":"O-1","kind":"BeneficialOwner","name":"J. Doe"}"#,
        ),
    ] {
        let path = write(&dir, &format!("{name}.json"), body);
        let (code, out) = run(&["party", "add", &path, "--json"]);
        assert_eq!(code, 0, "{out}");
    }
    // Usage errors publish nothing: an unregistered kind, an unknown field.
    for body in [
        r#"{"code":"X-1","kind":"Friend","name":"X"}"#,
        r#"{"code":"X-2","kind":"Vendor","name":"X","nickname":"x"}"#,
    ] {
        let path = write(&dir, "bad-party.json", body);
        let (code, out) = run(&["party", "add", &path, "--json"]);
        assert_eq!(code, 2, "{out}");
    }

    // Ownership is an exact ratio under a registered basis.
    let relate = |extra: &[&str]| {
        let mut args = vec![
            "party",
            "relate",
            "O-1",
            "V-17",
            "--kind",
            "owns",
            "--basis",
            "beneficial_ownership",
            "--valid-from",
            "2026-01-01",
            "--json",
        ];
        args.extend_from_slice(extra);
        run(&args)
    };
    for bad in [vec![], vec!["--pct", "0.75"], vec!["--pct", "3/0"]] {
        let (code, out) = relate(&bad);
        assert_eq!(code, 2, "{bad:?}: {out}");
    }
    let (code, out) = relate(&["--pct", "3/4"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "object"), Some("relationship"));

    // An instrument is held at a party and mirrors a GL leaf.
    let account = write(
        &dir,
        "account.json",
        r#"{"code":"BA-1","name":"Operating account","kind":"BankAccount","unit":"USD","held_at":"BANK-1","mirrors":"1000"}"#,
    );
    let (code, out) = run(&["instrument", "add", &account, "--json"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "object"), Some("instrument"));
    let instrument_vid = field(&out, "target").unwrap().to_string();
    let (code, out) = run(&["instrument", "add", &account, "--json"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "already_recorded"), Some("true"));
    assert_eq!(field(&out, "target"), Some(instrument_vid.as_str()));
    let unmirrored = write(
        &dir,
        "unmirrored.json",
        r#"{"code":"BA-2","name":"Nowhere","kind":"BankAccount","unit":"USD","held_at":"BANK-1","mirrors":"9999"}"#,
    );
    let (code, out) = run(&["instrument", "add", &unmirrored, "--json"]);
    assert_eq!(code, 2, "{out}");

    let (code, out) = run(&["party", "list", "--json"]);
    assert_eq!(code, 0, "{out}");
    let listed = doc(&out);
    let parties = arr(&listed, "parties");
    assert_eq!(parties.len(), 3, "{out}");
    assert_eq!(int(&listed, "relationships"), Some(1));
    let acme = parties
        .iter()
        .find(|p| text(p, "code") == "V-17")
        .expect("vendor listed");
    assert_eq!(text(acme, "kind"), "Vendor");
    assert_eq!(text(acme, "vid"), vendor_vid);
    let name = acme.get("name").expect("opened name");
    assert_eq!(text(name, "untrusted_content"), "Acme Supplies");
    let (code, out) = run(&["instrument", "list", "--json"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(arr(&doc(&out), "instruments").len(), 1, "{out}");

    // The event names both: the participant and the instrument resource.
    let (code, out) = run(&[
        "event",
        "record",
        "--code",
        "EV-PAY-1",
        "--kind",
        "payment",
        "--occurred-on",
        "2026-03-12",
        "--evidence",
        &ev,
        "--participant",
        "V-17",
        "--resource",
        "cash_outflow:40.00 USD:BA-1",
        "--json",
    ]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "event"), Some("event_recorded"), "{out}");
    Ok(())
}

/// Plan §4.1, §4.5: a legal entity declared at book creation is lifted to
/// its full specification (jurisdiction, functional unit, life span) and new
/// ones are recorded; another system's identifier binds to exactly one
/// party, legal entity or instrument. Each is a journaled control; an exact
/// retry records nothing new.
#[test]
fn legal_entities_and_external_id_bindings_are_recorded_from_the_cli() -> std::io::Result<()> {
    let dir = tmp("entity")?;
    let book = dir.join("book");
    let (code, out, err) = fa(
        Some(&book),
        &[
            "book",
            "create",
            "--name",
            "Group Co",
            "--entity",
            "ACME:Acme Holdings",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let run = |args: &[&str]| {
        let mut full: Vec<&str> = args.to_vec();
        full.push("--json");
        fa(Some(&book), &full)
    };
    // Planted negative: a genesis entity keeps its declared name. Before the
    // lift, so the refusal is the name law's, not "already exists".
    let renamed = write(
        &dir,
        "renamed.json",
        r#"{"code":"ACME","name":"Acme Renamed","jurisdiction":"US-DE","functional_unit":"USD"}"#,
    );
    let (code, out, _) = run(&["entity", "add", &renamed, "--key", "entity:ACME:2"]);
    assert_eq!(code, 2, "{out}");
    assert!(
        out.contains("was declared at genesis with name"),
        "the genesis name law refuses it: {out}"
    );
    let lifted = write(
        &dir,
        "acme.json",
        r#"{"code":"ACME","name":"Acme Holdings","jurisdiction":"US-DE","functional_unit":"USD","formed":"2015-06-01"}"#,
    );
    let (code, out, err) = run(&["entity", "add", &lifted]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("rea_recorded"), "{out}");
    assert_eq!(field(&out, "object"), Some("legal_entity"));
    assert_eq!(field(&out, "already_recorded"), Some("false"));
    let acme = field(&out, "target").unwrap_or_default().to_string();
    let (code, again, _) = run(&["entity", "add", &lifted]);
    assert_eq!(code, 0, "{again}");
    assert_eq!(field(&again, "already_recorded"), Some("true"), "{again}");
    assert_eq!(field(&again, "target"), Some(acme.as_str()));

    // Planted negative: a dissolution is strictly after formation.
    let backwards = write(
        &dir,
        "backwards.json",
        r#"{"code":"ACME-DE","name":"Acme GmbH","jurisdiction":"DE","functional_unit":"EUR","formed":"2019-04-01","dissolved":"2018-01-01"}"#,
    );
    let (code, out, _) = run(&["entity", "add", &backwards]);
    assert_eq!(code, 2, "{out}");
    // One functional currency per book (plan §0.4): a EUR subsidiary is
    // its own book, consolidated.
    let euro = write(
        &dir,
        "euro.json",
        r#"{"code":"ACME-DE","name":"Acme GmbH","jurisdiction":"DE","functional_unit":"EUR","formed":"2019-04-01"}"#,
    );
    let (code, out, _) = run(&["entity", "add", &euro]);
    assert_eq!(code, 3, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-003"), "{out}");
    let gmbh = write(
        &dir,
        "gmbh.json",
        r#"{"code":"ACME-DE","name":"Acme GmbH","jurisdiction":"DE","functional_unit":"USD","formed":"2019-04-01"}"#,
    );
    let (code, out, err) = run(&["entity", "add", &gmbh]);
    assert_eq!(code, 0, "{out}\n{err}");

    let (code, out, _) = run(&["entity", "list"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "event"), Some("legal_entities"));
    let listed = doc(&out);
    let entities = arr(&listed, "entities");
    assert_eq!(entities.len(), 2, "{out}");
    assert_eq!(text(&entities[0], "code"), "ACME");
    assert_eq!(text(&entities[0], "jurisdiction"), "US-DE");
    assert_eq!(text(&entities[0], "formed"), "2015-06-01");
    assert_eq!(text(&entities[1], "code"), "ACME-DE");
    assert_eq!(text(&entities[1], "jurisdiction"), "DE");
    assert_eq!(text(&entities[1], "functional_unit"), "USD");

    // The holding owns the subsidiary: legal entities are relationship ends.
    let (code, out, err) = run(&[
        "party",
        "relate",
        "ACME",
        "ACME-DE",
        "--kind",
        "owns",
        "--basis",
        "equity_voting",
        "--valid-from",
        "2019-04-01",
        "--pct",
        "100/100",
    ]);
    assert_eq!(code, 0, "{out}\n{err}");

    // A vendor's QuickBooks id binds once; the same id cannot name another vertex.
    let vendor = write(
        &dir,
        "vendor.json",
        r#"{"code":"V-17","kind":"Vendor","name":"Acme Supplies"}"#,
    );
    assert_eq!(run(&["party", "add", &vendor]).0, 0);
    let (code, out, err) = run(&["party", "bind", "V-17", "--external-id", "qbo:55"]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "object"), Some("external_id"));
    assert_eq!(field(&out, "code"), Some("V-17"));
    assert!(
        !out.contains("qbo:55"),
        "the id is sealed, never echoed: {out}"
    );
    let (code, again, _) = run(&["party", "bind", "V-17", "--external-id", "qbo:55"]);
    assert_eq!(code, 0, "{again}");
    assert_eq!(field(&again, "already_recorded"), Some("true"), "{again}");
    let (code, out, _) = run(&["party", "bind", "ACME-DE", "--external-id", "qbo:55"]);
    assert_eq!(code, 6, "one (system, id) names one vertex: {out}");
    let (code, out, _) = run(&["party", "bind", "V-17", "--external-id", "qbo"]);
    assert_eq!(code, 2, "{out}");
    let (code, out, _) = run(&["party", "bind", "NOBODY", "--external-id", "qbo:56"]);
    assert_eq!(code, 2, "{out}");
    let (code, out, _) = run(&["party", "bind", "V-17", "--external-id", "qbo"]);
    assert!(
        code == 2 && !out.contains("`qbo`"),
        "a malformed id is not echoed: {out}"
    );
    // Codes are unique within a kind, not across kinds: a party coded like
    // the legal entity ACME makes the code ambiguous, and a vertex id names
    // exactly one target.
    let intercompany = write(
        &dir,
        "acme-party.json",
        r#"{"code":"ACME","kind":"RelatedEntity","name":"Acme Holdings"}"#,
    );
    let (code, out, err) = run(&["party", "add", &intercompany]);
    assert_eq!(code, 0, "{out}\n{err}");
    let (code, out, _) = run(&[
        "party",
        "bind",
        "ACME",
        "--external-id",
        "lei:5299001ABCDEF",
    ]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("more than one target"), "{out}");
    assert!(!out.contains("5299001ABCDEF"), "never echoed: {out}");
    let (code, out, err) = run(&["party", "bind", &acme, "--external-id", "lei:5299001ABCDEF"]);
    assert_eq!(code, 0, "{out}\n{err}");
    // `target` names the binding's external-id vertex; the vertex id bound
    // the legal entity, not the like-coded party.
    assert_eq!(field(&out, "code"), Some(acme.as_str()), "{out}");
    let (code, out, _) = run(&["entity", "list"]);
    assert_eq!(code, 0, "{out}");
    let listed = doc(&out);
    let bound = arr(&listed, "entities")
        .iter()
        .find(|e| text(e, "vid") == acme)
        .expect("the bound entity is listed");
    assert_eq!(bound.get("external_ids"), Some(&Json::Int(1)), "{out}");
    Ok(())
}

/// fa-lzrn: a party's identifier set (its bank details) is replaced under a
/// named change; the values are sealed and never echoed; an exact retry is
/// the recorded change; the same change id with other values is a conflict.
/// `fa party ownership` (plan §4.5): the effective stake is the exact sum
/// over simple OWNS paths of the product of their stakes, from relationships
/// valid on the day; --max-depth bounds the chains; nothing reaches before
/// the first relationship starts.
#[test]
fn effective_ownership_sums_owns_paths_exactly_on_a_day() -> std::io::Result<()> {
    let (book, _ev, dir) = envelope_book("rea-ownership")?;
    let run = |args: &[&str]| -> (i32, String) {
        let (code, out, _) = fa(Some(&book), args);
        (code, out)
    };
    for (code, kind) in [
        ("A", "BeneficialOwner"),
        ("H", "RelatedEntity"),
        ("S", "RelatedEntity"),
    ] {
        let path = write(
            &dir,
            &format!("{code}.json"),
            &format!(r#"{{"code":"{code}","kind":"{kind}","name":"Party {code}"}}"#),
        );
        let (status, out) = run(&["party", "add", &path, "--json"]);
        assert_eq!(status, 0, "{out}");
    }
    for (from, to, pct, basis, from_day) in [
        ("A", "H", "60/100", "beneficial_ownership", "2026-01-01"),
        ("H", "S", "50/100", "equity_voting", "2026-01-01"),
        ("A", "S", "10/100", "beneficial_ownership", "2026-03-01"),
    ] {
        let (status, out) = run(&[
            "party",
            "relate",
            from,
            to,
            "--kind",
            "owns",
            "--basis",
            basis,
            "--pct",
            pct,
            "--valid-from",
            from_day,
            "--json",
        ]);
        assert_eq!(status, 0, "{out}");
    }
    let stake = |extra: &[&str]| -> String {
        let mut args = vec!["party", "ownership", "A", "S", "--json"];
        args.extend_from_slice(extra);
        let (status, out) = run(&args);
        assert_eq!(status, 0, "{args:?}: {out}");
        assert_eq!(field(&out, "event"), Some("effective_ownership"), "{out}");
        field(&out, "stake").unwrap_or_default().to_string()
    };
    // Through H only: 6/10 x 5/10.
    assert_eq!(stake(&["--as-of", "2026-02-15"]), "3/10");
    // The direct tenth joins from March: 3/10 + 1/10.
    assert_eq!(stake(&["--as-of", "2026-03-15"]), "2/5");
    assert_eq!(
        stake(&["--as-of", "2026-03-15", "--max-depth", "1"]),
        "1/10"
    );
    assert_eq!(stake(&["--as-of", "2025-12-31"]), "0/1");
    // Usage: no day, the same party twice, a depth out of range, an
    // unknown party.
    for bad in [
        vec!["party", "ownership", "A", "S", "--json"],
        vec![
            "party",
            "ownership",
            "A",
            "A",
            "--as-of",
            "2026-03-15",
            "--json",
        ],
        vec![
            "party",
            "ownership",
            "A",
            "S",
            "--as-of",
            "2026-03-15",
            "--max-depth",
            "0",
            "--json",
        ],
        vec![
            "party",
            "ownership",
            "A",
            "Z",
            "--as-of",
            "2026-03-15",
            "--json",
        ],
    ] {
        let (status, out) = run(&bad);
        assert_eq!(status, 2, "{bad:?}: {out}");
    }
    Ok(())
}

#[test]
fn party_identifiers_are_replaced_under_a_named_change_and_never_echoed() -> std::io::Result<()> {
    let dir = tmp("identifiers")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Identifiers Co"]).0,
        0
    );
    let vendor = write(
        &dir,
        "vendor.json",
        r#"{"code":"V-17","kind":"Vendor","name":"Acme Supplies"}"#,
    );
    assert_eq!(fa(Some(&book), &["party", "add", &vendor, "--json"]).0, 0);
    let run = |args: &[&str]| {
        let mut full = args.to_vec();
        full.push("--json");
        fa(Some(&book), &full)
    };
    let change = [
        "party",
        "identifiers",
        "V-17",
        "--identifier",
        "bank_routing=021000021",
        "--identifier",
        "bank_account=4417123456",
        "--key",
        "chg-1",
    ];
    let (code, out, err) = run(&change);
    assert_eq!(code, 0, "{out}\n{err}");
    let recorded = doc(&out);
    assert_eq!(text(&recorded, "object"), "party_identifiers");
    assert_eq!(text(&recorded, "code"), "V-17");
    assert_eq!(recorded.get("already_recorded"), Some(&Json::Bool(false)));
    for secret in ["021000021", "4417123456"] {
        assert!(
            !out.contains(secret) && !err.contains(secret),
            "an identifier value is never echoed: {out}\n{err}"
        );
    }
    let (code, out, _) = run(&change);
    assert_eq!(code, 0, "{out}");
    assert_eq!(doc(&out).get("already_recorded"), Some(&Json::Bool(true)));
    let (code, out, err) = run(&[
        "party",
        "identifiers",
        "V-17",
        "--identifier",
        "bank_account=9999999999",
        "--key",
        "chg-1",
    ]);
    assert_eq!(code, 6, "one change id names one change: {out}\n{err}");
    assert!(!out.contains("9999999999") && !err.contains("9999999999"));
    let clear = ["party", "identifiers", "V-17", "--clear", "--key", "chg-2"];
    let (code, out, _) = run(&clear);
    assert_eq!(code, 0, "{out}");
    assert_eq!(doc(&out).get("already_recorded"), Some(&Json::Bool(false)));
    let (code, out, _) = run(&clear);
    assert_eq!(code, 0, "{out}");
    assert_eq!(doc(&out).get("already_recorded"), Some(&Json::Bool(true)));
    // A retry is judged against what its own change recorded, never the
    // party's current set: chg-1 is still its recorded change after the
    // clear, and chg-2 under chg-1's values is a conflict.
    let (code, out, _) = run(&change);
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        doc(&out).get("already_recorded"),
        Some(&Json::Bool(true)),
        "an exact retry after a later change is still the recorded change: {out}"
    );
    let (code, out, _) = run(&[
        "party",
        "identifiers",
        "V-17",
        "--identifier",
        "bank_routing=021000021",
        "--identifier",
        "bank_account=4417123456",
        "--key",
        "chg-2",
    ]);
    assert_eq!(code, 6, "chg-2 recorded a clear: {out}");
    for (args, why) in [
        (
            vec![
                "party",
                "identifiers",
                "V-17",
                "--identifier",
                "bank_account=1",
            ],
            "no --key",
        ),
        (
            vec!["party", "identifiers", "V-17", "--key", "chg-3"],
            "neither --identifier nor --clear",
        ),
        (
            vec![
                "party",
                "identifiers",
                "V-17",
                "--clear",
                "--identifier",
                "a=1",
                "--key",
                "chg-3",
            ],
            "both --identifier and --clear",
        ),
        (
            vec![
                "party",
                "identifiers",
                "V-17",
                "--identifier",
                "bank_account",
                "--key",
                "chg-3",
            ],
            "no value",
        ),
        (
            vec![
                "party",
                "identifiers",
                "V-17",
                "--identifier",
                "a=1",
                "--identifier",
                "a=2",
                "--key",
                "chg-3",
            ],
            "a name twice",
        ),
        (
            vec![
                "party",
                "identifiers",
                "NOPE",
                "--identifier",
                "a=1",
                "--key",
                "chg-3",
            ],
            "an unknown party",
        ),
    ] {
        let (code, out, _) = run(&args);
        assert_eq!(code, 2, "{why}: {out}");
    }
    Ok(())
}

/// The whole history's recorded rows replay into a fresh scratch book that
/// agrees with the source commit by commit (`fa verify replay`).
#[test]
fn verify_replay_re_performs_the_history_into_an_independent_book() -> std::io::Result<()> {
    let dir = tmp("replay")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Replay Co"]).0,
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
    let rent = write(
        &dir,
        "rent.json",
        &format!(
            r#"{{"effective_date":"2026-03-15","idempotency_key":"rent","evidence":["{ev}"],"legs":[{{"side":"debit","account":"6000","amount":"1500.00 USD"}},{{"side":"credit","account":"1000","amount":"1500.00 USD"}}]}}"#
        ),
    );
    assert_eq!(fa(Some(&book), &["post", "--intent", &rent]).0, 0);
    let run = |args: &[&str]| {
        let mut full = args.to_vec();
        full.push("--json");
        fa(Some(&book), &full)
    };
    let (code, out, err) = run(&["verify", "replay"]);
    assert_eq!(code, 0, "{out}\n{err}");
    let replayed = doc(&out);
    assert!(int(&replayed, "pairs_checked").unwrap_or(0) > 0, "{out}");
    assert!(int(&replayed, "entries_checked").unwrap_or(0) >= 1, "{out}");
    assert_eq!(
        int(&replayed, "pairs_checked"),
        int(&replayed, "commits"),
        "every replayed commit is checked: {out}"
    );
    assert_eq!(
        run(&["verify", "replay", "--period", "FY2026-P03"]).0,
        2,
        "replay covers the whole history; it takes no period filter"
    );
    Ok(())
}

/// Plan §15.3, Appendix B (bead fa-i7e, scoreboard WF-RQ-02): `fa invoice`
/// and `fa bill` build the Original entry from their lines (quantity times
/// unit price, exactly) and post it through `fa post`'s path: a dry run
/// returns the plan and writes nothing, the post lands, a retry is the
/// recorded entry, and the control leg names the party. Nothing is
/// inferred: no tax, no default account, no float.
#[test]
fn invoice_and_bill_post_typed_documents_through_the_post_path() -> std::io::Result<()> {
    let dir = tmp("typed")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Typed Co"]).0,
        0
    );
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1200","name":"Receivables","type":"Asset","unit":"USD"},{"code":"2000","name":"Payables","type":"Liability","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},{"code":"6000","name":"Hosting","type":"Expense","unit":"USD"}]}"#,
    );
    assert_eq!(fa(Some(&book), &["chart", "import", &chart]).0, 0);
    assert_eq!(
        fa(Some(&book), &["period", "create", "--fiscal-year", "2026"]).0,
        0
    );
    assert_eq!(fa(Some(&book), &["period", "open", "FY2026-P03"]).0, 0);
    let ev = source_doc(&dir, &book);
    // The evidence is listed as metadata (kind, grade, size), never bytes.
    let (code, out, _) = fa(
        Some(&book),
        &["document", "list", "--kind", "Invoice", "--json"],
    );
    assert_eq!(code, 0, "{out}");
    let listed = doc(&out);
    assert_eq!(int(&listed, "count"), Some(1), "{out}");
    let held = &arr(&listed, "documents")[0];
    assert_eq!(text(held, "oid"), ev);
    assert_eq!(text(held, "grade"), "HumanUpload");
    assert!(
        !out.contains("cli fixture source document"),
        "metadata only: {out}"
    );
    let (code, out, _) = fa(
        Some(&book),
        &["document", "list", "--kind", "Bill", "--json"],
    );
    assert_eq!(code, 0, "{out}");
    assert_eq!(int(&doc(&out), "count"), Some(0), "{out}");
    let (code, out, _) = fa(
        Some(&book),
        &["document", "list", "--kind", "Nope", "--json"],
    );
    assert_eq!(code, 2, "{out}");
    for (code, kind) in [("C-17", "Customer"), ("V-17", "Vendor"), ("V-18", "Vendor")] {
        let party = write(
            &dir,
            &format!("{code}.json"),
            &format!(r#"{{"code":"{code}","kind":"{kind}","name":"{code} Ltd"}}"#),
        );
        assert_eq!(fa(Some(&book), &["party", "add", &party, "--json"]).0, 0);
    }
    let invoice = |party: &str, extra: &[&str]| {
        let mut args = vec![
            "invoice",
            "--party",
            party,
            "--number",
            "10442",
            "--date",
            "2026-03-14",
            "--receivable",
            "1200",
            "--revenue",
            "4000",
            "--line",
            r#"qty=10 unit_price="125.00 USD" item=SKU-9 product=Widgets"#,
            "--line",
            r#"amount="40.00 USD" description=Delivery"#,
            "--evidence",
            ev.as_str(),
        ];
        args.extend_from_slice(extra);
        args.push("--json");
        fa(Some(&book), &args)
    };
    let tb = || report(&book, &["tb", "--period", "FY2026-P03", "--json"]);
    let before = tb();

    // The dry run is the plan: legs derived from the lines, nothing written.
    let (code, out, err) = invoice("C-17", &["--dry-run"]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("plan"), "{out}");
    let planned = doc(&out);
    let legs: Vec<(String, String, String)> = arr(&planned, "legs")
        .iter()
        .map(|l| {
            (
                text(l, "account").to_string(),
                text(l, "side").to_string(),
                text(l, "amount").to_string(),
            )
        })
        .collect();
    assert_eq!(
        legs,
        vec![
            ("1200".into(), "debit".into(), "1290.00 USD".into()),
            ("4000".into(), "credit".into(), "1250.00 USD".into()),
            ("4000".into(), "credit".into(), "40.00 USD".into()),
        ],
        "{out}"
    );
    assert_eq!(tb(), before, "a dry run writes nothing");

    let (code, out, err) = invoice("C-17", &[]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("posted"), "{out}");
    let vid = field(&out, "vid").unwrap_or_default().to_string();
    let (code, again, _) = invoice("C-17", &[]);
    assert_eq!(code, 0, "{again}");
    assert_eq!(field(&again, "event"), Some("recorded"), "{again}");
    let after = tb();
    let row = |code: &str| {
        after
            .split('{')
            .find(|row| field(row, "code") == Some(code))
            .map(str::to_string)
            .unwrap_or_default()
    };
    assert_eq!(field(&row("1200"), "net"), Some("1290.00 USD"), "{after}");
    assert_eq!(field(&row("4000"), "net"), Some("-1290.00 USD"), "{after}");
    let (code, shown, _) = fa(Some(&book), &["entry", "show", &vid, "--json"]);
    assert_eq!(code, 0, "{shown}");
    assert!(shown.contains("Invoice 10442, C-17"), "{shown}");

    // The control leg names the party, so an unknown party is refused by
    // the kernel before anything is written.
    let (code, out, _) = fa(
        Some(&book),
        &[
            "invoice",
            "--party",
            "NOBODY",
            "--number",
            "1",
            "--date",
            "2026-03-14",
            "--receivable",
            "1200",
            "--revenue",
            "4000",
            "--line",
            r#"amount="1.00 USD""#,
            "--evidence",
            ev.as_str(),
            "--json",
        ],
    );
    assert_eq!(code, 2, "{out}");

    let (code, out, err) = fa(
        Some(&book),
        &[
            "bill",
            "--party",
            "V-17",
            "--number",
            "B-77",
            "--date",
            "2026-03-20",
            "--payable",
            "2000",
            "--line",
            r#"amount="300.00 USD" account=6000 item=hosting"#,
            "--evidence",
            ev.as_str(),
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("posted"), "{out}");
    let after = tb();
    let net = |code: &str| {
        after
            .split('{')
            .find(|row| field(row, "code") == Some(code))
            .and_then(|row| field(row, "net").map(str::to_string))
    };
    assert_eq!(net("6000").as_deref(), Some("300.00 USD"), "{after}");
    assert_eq!(net("2000").as_deref(), Some("-300.00 USD"), "{after}");

    // A vendor numbers its own bills: another vendor's B-77 is another
    // document, never the first one's recorded entry. Lines with different
    // decimal places sum exactly.
    let (code, out, err) = fa(
        Some(&book),
        &[
            "bill",
            "--party",
            "V-18",
            "--number",
            "B-77",
            "--date",
            "2026-03-21",
            "--payable",
            "2000",
            "--expense",
            "6000",
            "--line",
            r#"amount="31.5 USD""#,
            "--line",
            r#"qty=3 unit_price="0.25 USD""#,
            "--evidence",
            ev.as_str(),
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(
        field(&out, "event"),
        Some("posted"),
        "another vendor's B-77: {out}"
    );
    let after = tb();
    let net = |code: &str| {
        after
            .split('{')
            .find(|row| field(row, "code") == Some(code))
            .and_then(|row| field(row, "net").map(str::to_string))
    };
    assert_eq!(net("6000").as_deref(), Some("332.25 USD"), "{after}");

    // A post_closed grant makes a typed document dangerous, as it makes
    // fa post: unconfirmed, it is refused before anything is written.
    let before = tb();
    let (code, out, _) = invoice("C-17", &["--key", "late-1", "--grant", "post_closed"]);
    assert_eq!(code, 7, "{out}");
    assert!(out.contains("FA-REF-007"), "{out}");
    assert_eq!(tb(), before, "an unconfirmed dangerous post writes nothing");

    // Planted negatives: nothing is inferred and nothing is written.
    for (line, extra, why) in [
        (
            r#"amount="1.00 USD" tax=VAT20"#,
            vec![],
            "tax needs a tax law",
        ),
        (r#"qty=2 unit_price="1.5e2 USD""#, vec![], "a float price"),
        (
            r#"qty=1.5 unit_price="2.00 USD""#,
            vec![],
            "a fractional quantity",
        ),
        (
            r#"amount="1.00 EUR""#,
            vec!["--line", r#"amount="1.00 USD""#],
            "two units",
        ),
        (
            r#"amount="1.00 USD" colour=red"#,
            vec![],
            "an unknown field",
        ),
        (r#"amount="0.00 USD""#, vec![], "a zero line"),
        (r#"amount="1.00 USD" item="#, vec![], "an empty value"),
        (
            r#"amount="1.00 USD""#,
            vec!["--entity", ""],
            "an empty legal entity",
        ),
    ] {
        let mut args = vec![
            "invoice",
            "--party",
            "C-17",
            "--number",
            "neg",
            "--date",
            "2026-03-14",
            "--receivable",
            "1200",
            "--revenue",
            "4000",
            "--line",
            line,
        ];
        args.extend(extra);
        args.extend(["--evidence", ev.as_str(), "--json"]);
        let (code, out, _) = fa(Some(&book), &args);
        assert_eq!(code, 2, "{why}: {out}");
    }
    let (code, out, _) = fa(
        Some(&book),
        &[
            "invoice",
            "--party",
            "C-17",
            "--date",
            "2026-03-14",
            "--receivable",
            "1200",
            "--revenue",
            "4000",
            "--line",
            r#"amount="1.00 USD""#,
            "--json",
        ],
    );
    assert_eq!(code, 2, "no number and no key: {out}");
    let (code, out, _) = fa(
        Some(&book),
        &[
            "bill",
            "--party",
            "V-17",
            "--number",
            "B-78",
            "--date",
            "2026-03-20",
            "--payable",
            "2000",
            "--line",
            r#"amount="1.00 USD""#,
            "--json",
        ],
    );
    assert_eq!(code, 2, "a line with no account and no --expense: {out}");
    assert_eq!(tb(), before, "refused documents write nothing");
    Ok(())
}

/// Plan §15.3, §12.5 (beads fa-i7e, fa-zbne): `fa receipt` and `fa payment`
/// settle an invoice and a bill against cash, each control leg applying
/// itself to the open item it names, and the bank statement that shows
/// both movements reconciles with exact matches on their references.
#[test]
fn receipt_and_payment_settle_open_items_and_match_the_bank() -> std::io::Result<()> {
    let dir = tmp("settle")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Settle Co"]).0,
        0
    );
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1200","name":"Receivables","type":"Asset","unit":"USD"},{"code":"2000","name":"Payables","type":"Liability","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},{"code":"6000","name":"Hosting","type":"Expense","unit":"USD"}]}"#,
    );
    assert_eq!(fa(Some(&book), &["chart", "import", &chart]).0, 0);
    assert_eq!(
        fa(Some(&book), &["period", "create", "--fiscal-year", "2026"]).0,
        0
    );
    assert_eq!(fa(Some(&book), &["period", "open", "FY2026-P03"]).0, 0);
    let ev = source_doc(&dir, &book);
    for (code, kind) in [("C-17", "Customer"), ("V-17", "Vendor")] {
        let party = write(
            &dir,
            &format!("{code}.json"),
            &format!(r#"{{"code":"{code}","kind":"{kind}","name":"{code} Ltd"}}"#),
        );
        assert_eq!(fa(Some(&book), &["party", "add", &party, "--json"]).0, 0);
    }
    let run = |args: &[&str]| {
        let mut full = args.to_vec();
        full.extend(["--evidence", ev.as_str(), "--json"]);
        let (code, out, err) = fa(Some(&book), &full);
        (code, out, err)
    };
    let (code, out, err) = run(&[
        "invoice",
        "--party",
        "C-17",
        "--number",
        "10442",
        "--date",
        "2026-03-04",
        "--receivable",
        "1200",
        "--revenue",
        "4000",
        "--line",
        r#"amount="1250.00 USD""#,
    ]);
    assert_eq!(code, 0, "{out}\n{err}");
    let invoice = field(&out, "vid").unwrap_or_default().to_string();
    let (code, out, err) = run(&[
        "bill",
        "--party",
        "V-17",
        "--number",
        "B-77",
        "--date",
        "2026-03-06",
        "--payable",
        "2000",
        "--expense",
        "6000",
        "--line",
        r#"amount="300.00 USD""#,
    ]);
    assert_eq!(code, 0, "{out}\n{err}");
    let bill = field(&out, "vid").unwrap_or_default().to_string();

    let (code, out, err) = run(&[
        "receipt",
        "--party",
        "C-17",
        "--number",
        "WIRE-IN-1",
        "--date",
        "2026-03-05",
        "--cash",
        "1000",
        "--receivable",
        "1200",
        "--amount",
        "1250.00 USD",
        "--applies",
        &invoice,
    ]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("posted"), "{out}");
    let receipt = field(&out, "vid").unwrap_or_default().to_string();
    let (code, out, err) = run(&[
        "payment",
        "--party",
        "V-17",
        "--number",
        "ACH-OUT-1",
        "--date",
        "2026-03-10",
        "--cash",
        "1000",
        "--payable",
        "2000",
        "--amount",
        "300.00 USD",
        "--applies",
        &format!("{bill}:0=300.00 USD"),
    ]);
    assert_eq!(code, 0, "{out}\n{err}");
    let payment = field(&out, "vid").unwrap_or_default().to_string();

    // Both open items are settled.
    for (account, entry) in [("1200", &invoice), ("2000", &bill)] {
        let (code, out, _) = fa(Some(&book), &["open-items", "--account", account, "--json"]);
        assert_eq!(code, 0, "{out}");
        let items = doc(&out);
        let item = arr(&items, "items")
            .iter()
            .find(|i| text(i, "entry") == entry.as_str())
            .cloned()
            .unwrap_or(Json::Null);
        assert_eq!(text(&item, "open"), "0.00 USD", "{account}: {out}");
    }

    // Planted negatives: more than is open, and an unknown reference form.
    let (code, out, _) = run(&[
        "receipt",
        "--party",
        "C-17",
        "--number",
        "EXTRA-1",
        "--date",
        "2026-03-12",
        "--cash",
        "1000",
        "--receivable",
        "1200",
        "--amount",
        "10.00 USD",
        "--applies",
        &invoice,
    ]);
    assert_eq!(code, 3, "nothing is open on the invoice: {out}");
    assert!(out.contains("FA-REF-072"), "{out}");
    let (code, out, _) = run(&[
        "receipt",
        "--party",
        "C-17",
        "--number",
        "ZERO-1",
        "--date",
        "2026-03-12",
        "--cash",
        "1000",
        "--receivable",
        "1200",
        "--amount",
        "0.00 USD",
    ]);
    assert_eq!(code, 2, "a zero receipt moves nothing: {out}");
    let (code, out, _) = run(&[
        "receipt",
        "--party",
        "C-17",
        "--number",
        "EXTRA-2",
        "--date",
        "2026-03-12",
        "--cash",
        "1000",
        "--receivable",
        "1200",
        "--amount",
        "10.00 USD",
        "--applies",
        &format!("{invoice}:x"),
    ]);
    assert_eq!(code, 2, "{out}");
    let (code, out, _) = run(&[
        "payment",
        "--party",
        "V-17",
        "--number",
        "EXTRA-3",
        "--date",
        "2026-03-12",
        "--cash",
        "1000",
        "--payable",
        "2000",
        "--amount",
        "10.0e1 USD",
    ]);
    assert_eq!(code, 2, "a float amount: {out}");

    // The bank shows both movements under their references. The receipt's
    // and the payment's numbers are their cash legs' memos, so fa bank
    // match proposes each line against exactly its entry.
    let stmt = write(
        &dir,
        "march-statement.csv",
        "sequence_number,instrument_id,currency,statement_date,opening_balance,closing_balance,booking_date,value_date,side,amount,counterparty,reference\n\
1,OPER,USD,2026-03-31,0.00,950.00,2026-03-06,2026-03-06,CRDT,1250.00,C-17 Ltd,WIRE-IN-1\n\
1,OPER,USD,2026-03-31,0.00,950.00,2026-03-11,2026-03-11,DBIT,300.00,V-17 Ltd,ACH-OUT-1\n",
    );
    let (code, out, err) = fa(
        Some(&book),
        &[
            "bank",
            "import",
            &stmt,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let manifest = text(&doc(&out), "manifest_oid").to_string();
    let (code, out, err) = fa(
        Some(&book),
        &[
            "bank",
            "match",
            "--import",
            &manifest,
            "--grant",
            "privileged",
            "--json",
        ],
    );
    assert_eq!(code, 0, "{out}\n{err}");
    let matched = doc(&out);
    assert_eq!(int(&matched, "proposed_count"), Some(2), "{out}");
    assert_eq!(int(&matched, "ambiguous_count"), Some(0), "{out}");
    assert_eq!(int(&matched, "unmatched_count"), Some(0), "{out}");
    let mut proposed: Vec<String> = arr(&matched, "proposals")
        .iter()
        .filter_map(|p| p.get("entry_ref").map(|r| text(r, "vid").to_string()))
        .collect();
    proposed.sort();
    let mut expected = vec![receipt, payment];
    expected.sort();
    assert_eq!(proposed, expected, "{out}");
    Ok(())
}

/// fa-k07b: a but-for scenario forks at a trunk sequence, runs counterfactual
/// intents only in its scratch materialization (every posting law runs
/// there again), and diffs exactly against trunk as known at the fork.
/// Trunk balances never move, and later trunk activity never leaks in.
#[test]
fn a_scenario_runs_counterfactual_intents_and_diffs_them_without_touching_trunk()
-> std::io::Result<()> {
    let dir = tmp("scenario")?;
    let book = dir.join("book");
    assert_eq!(
        fa(Some(&book), &["book", "create", "--name", "Scenario Co"]).0,
        0
    );
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},{"code":"6000","name":"Hosting","type":"Expense","unit":"USD"}]}"#,
    );
    assert_eq!(fa(Some(&book), &["chart", "import", &chart]).0, 0);
    assert_eq!(
        fa(Some(&book), &["period", "create", "--fiscal-year", "2026"]).0,
        0
    );
    assert_eq!(fa(Some(&book), &["period", "open", "FY2026-P03"]).0, 0);
    let ev = source_doc(&dir, &book);
    let intent = |name: &str, key: &str, date: &str, debit: &str, credit: &str, amount: &str| {
        write(
            &dir,
            name,
            &format!(
                r#"{{"effective_date":"{date}","idempotency_key":"{key}","evidence":["{ev}"],"legs":[{{"side":"debit","account":"{debit}","amount":"{amount} USD"}},{{"side":"credit","account":"{credit}","amount":"{amount} USD"}}]}}"#
            ),
        )
    };
    let run = |args: &[&str]| {
        let mut full = args.to_vec();
        full.push("--json");
        fa(Some(&book), &full)
    };
    let tb_rows = || {
        let (code, out, err) = run(&["tb", "--period", "FY2026-P03"]);
        assert_eq!(code, 0, "{out}\n{err}");
        arr(&doc(&out), "rows").to_vec()
    };
    let hosting = intent(
        "hosting.json",
        "hosting-1",
        "2026-03-02",
        "6000",
        "1000",
        "300.00",
    );
    let (code, out, err) = run(&["post", "--intent", &hosting]);
    assert_eq!(code, 0, "{out}\n{err}");
    let trunk_before = tb_rows();

    // Fork with an assumption document and a counterfactual start date; an
    // exact retry is the recorded fork at the same sequence.
    let fork = [
        "scenario",
        "fork",
        "but-for",
        "--from",
        "2026-03-10",
        "--evidence",
        ev.as_str(),
    ];
    let (code, out, err) = run(&fork);
    assert_eq!(code, 0, "{out}\n{err}");
    let forked = doc(&out);
    let fork_at = int(&forked, "fork_at");
    assert!(fork_at.is_some(), "{out}");
    assert_eq!(text(&forked, "from"), "2026-03-10");
    assert_eq!(arr(&forked, "assumptions"), [Json::Str(ev.clone())]);
    assert_eq!(forked.get("already_recorded"), Some(&Json::Bool(false)));
    let (code, out, _) = run(&fork);
    assert_eq!(code, 0, "{out}");
    let again = doc(&out);
    assert_eq!(again.get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(int(&again, "fork_at"), fork_at);

    // The counterfactual sale runs in the scenario, rehearsed there first.
    let sale = intent(
        "sale.json",
        "but-for-sale",
        "2026-03-15",
        "1000",
        "4000",
        "500.00",
    );
    let (code, out, err) = run(&["scenario", "run", "but-for", "--intent", &sale]);
    assert_eq!(code, 0, "{out}\n{err}");
    let ran = doc(&out);
    assert_eq!(int(&ran, "ordinal"), Some(1));
    assert_eq!(ran.get("rehearsed"), Some(&Json::Bool(true)));
    let (code, out, _) = run(&["scenario", "run", "but-for", "--intent", &sale]);
    assert_eq!(code, 0, "{out}");
    let retried = doc(&out);
    assert_eq!(retried.get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(retried.get("rehearsed"), Some(&Json::Bool(false)));
    assert_eq!(text(&retried, "entry"), text(&ran, "entry"));
    // Certified while the scenario holds one intent: the diff names its
    // certificate in the envelope, report_certificate follows, and the trunk
    // side is a native certificate at the fork.
    let (code, out, err) = run(&[
        "scenario",
        "diff",
        "but-for",
        "--period",
        "FY2026-P03",
        "--certify",
    ]);
    assert_eq!(code, 0, "{out}\n{err}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "{out}");
    assert_eq!(field(lines[0], "event"), Some("scenario_diff"));
    assert_eq!(field(lines[1], "event"), Some("report_certificate"));
    let certified = doc(lines[0]);
    let certificate = doc(lines[1]);
    let oid = text(&certificate, "oid").to_string();
    assert_eq!(oid.len(), 64, "{out}");
    assert_eq!(field(lines[0], "certificate"), Some(oid.as_str()));
    assert_eq!(text(&certificate, "output_format"), "fa:scenario-diff:v1");
    assert_eq!(
        int(&certificate, "known_at"),
        fork_at,
        "trunk certified at the fork"
    );
    assert_eq!(int(&certified, "intents"), Some(1));
    let one_intent: Vec<(&str, &str)> = arr(&certified, "rows")
        .iter()
        .map(|r| (text(r, "code"), text(r, "delta")))
        .collect();
    assert_eq!(
        one_intent,
        [("1000", "500.00 USD"), ("4000", "-500.00 USD")]
    );
    let certificate_hex = text(&certificate, "bytes").to_string();
    // Every posting verb reaches a scenario the same way: --scenario.
    let cost = intent(
        "cost.json",
        "but-for-cost",
        "2026-03-20",
        "6000",
        "1000",
        "120.00",
    );
    let (code, out, err) = run(&["post", "--intent", &cost, "--scenario", "but-for"]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(int(&doc(&out), "ordinal"), Some(2));
    let cost_record = text(&doc(&out), "control_entry").to_string();
    assert_eq!(tb_rows(), trunk_before, "a scenario never posts to trunk");
    // Trunk moves on after the fork; the scenario is fixed at its fork.
    let later = intent(
        "later.json",
        "hosting-2",
        "2026-03-25",
        "6000",
        "1000",
        "50.00",
    );
    assert_eq!(run(&["post", "--intent", &later]).0, 0);

    // The diff is exactly the counterfactual, against trunk at the fork.
    let (code, out, err) = run(&["scenario", "diff", "but-for", "--period", "FY2026-P03"]);
    assert_eq!(code, 0, "{out}\n{err}");
    let diff = doc(&out);
    let rows: Vec<(&str, &str)> = arr(&diff, "rows")
        .iter()
        .map(|r| (text(r, "code"), text(r, "delta")))
        .collect();
    assert_eq!(
        rows,
        [
            ("1000", "380.00 USD"),
            ("4000", "-500.00 USD"),
            ("6000", "120.00 USD")
        ],
        "{out}"
    );
    assert_eq!(int(&diff, "fork_at"), fork_at);
    assert_eq!(int(&diff, "intents"), Some(2));
    let hosting_row = &arr(&diff, "rows")[2];
    assert_eq!(
        text(hosting_row, "trunk_debits"),
        "300.00 USD",
        "trunk as known at the fork excludes the later bill"
    );
    assert_eq!(text(hosting_row, "scenario_debits"), "420.00 USD");
    assert_eq!(
        text(hosting_row, "pending_delta"),
        "0.00 USD",
        "pending amounts are diffed apart from posted ones"
    );
    let (code, repeat, _) = run(&["scenario", "diff", "but-for", "--period", "FY2026-P03"]);
    assert_eq!(code, 0, "{repeat}");
    assert_eq!(doc(&repeat), diff, "a diff is deterministic");
    // The certificate still replays the one intent it covered: the scenario
    // re-materializes with exactly that prefix, though it now holds two and
    // trunk has moved on. Certifying again covers both: another certificate.
    let (code, out, err) = run(&["replay", &format!("C:{oid}")]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(field(&out, "event"), Some("scenario_diff"), "{out}");
    assert_eq!(field(&out, "certificate"), Some(oid.as_str()));
    assert_eq!(
        doc(&out),
        certified,
        "the replay reproduces the certified diff"
    );
    let (code, out, err) = run(&[
        "scenario",
        "diff",
        "but-for",
        "--period",
        "FY2026-P03",
        "--certify",
    ]);
    assert_eq!(code, 0, "{out}\n{err}");
    let both = doc(out.lines().next().unwrap_or_default());
    assert_eq!(int(&both, "intents"), Some(2));
    assert_eq!(arr(&both, "rows"), arr(&diff, "rows"));
    let both_oid = text(&doc(&out), "oid").to_string();
    assert_ne!(both_oid, oid, "a different intent prefix");
    // Status follows re-certification: trunk is fixed at the fork, so
    // trunk's later bill supersedes nothing, while the scenario's second
    // Plan record supersedes the one-intent certificate, which still
    // replays. The certificate covering both intents is current.
    let (code, out, err) = run(&["certificate", "status", &format!("C:{oid}")]);
    assert_eq!(code, 0, "{out}\n{err}");
    let status = doc(&out);
    assert_eq!(text(&status, "status"), "SupersededBy", "{out}");
    let superseding: Vec<&str> = arr(&status, "later_entries")
        .iter()
        .filter_map(Json::as_str)
        .collect();
    assert_eq!(superseding, [cost_record.as_str()], "{out}");
    assert_eq!(int(&status, "known_at"), fork_at, "{out}");
    assert_eq!(field(&out, "certificate"), Some(oid.as_str()));
    let (code, out, err) = run(&["certificate", "status", &format!("C:{both_oid}")]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert_eq!(text(&doc(&out), "status"), "Current", "{out}");
    assert!(arr(&doc(&out), "later_entries").is_empty(), "{out}");
    // A certificate whose output was altered never replays (exit 8).
    let mut bytes: Vec<u8> = (0..certificate_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(certificate_hex.get(i..i + 2).unwrap_or("00"), 16).unwrap_or(0))
        .collect();
    let inside_output = bytes.len() - 40;
    bytes[inside_output] ^= 1;
    let tampered = dir.join("tampered-scenario-diff.cert");
    std::fs::write(&tampered, &bytes)?;
    let (code, out, _) = run(&["replay", &tampered.display().to_string()]);
    assert_eq!(code, 8, "{out}");
    let (code, out, _) = run(&["certificate", "status", &tampered.display().to_string()]);
    assert_eq!(
        code, 8,
        "status needs the whole certificate to verify: {out}"
    );

    // Reads select the scenario with --branch: the same command, on its
    // replay, with the branch in the envelope's coordinate.
    let branch = ["--branch", "scenario:but-for"];
    let (code, out, err) = run(&[&["tb", "--period", "FY2026-P03"][..], &branch].concat());
    assert_eq!(code, 0, "{out}\n{err}");
    let line = json::parse(out.lines().last().unwrap_or_default()).unwrap_or(Json::Null);
    assert_eq!(
        line.get("coordinate")
            .and_then(|c| c.get("branch"))
            .and_then(Json::as_str),
        Some("scenario:but-for"),
        "{out}"
    );
    let scenario_rows = arr(&doc(&out), "rows").to_vec();
    let revenue = scenario_rows.iter().find(|r| text(r, "code") == "4000");
    assert_eq!(
        revenue.map(|r| text(r, "credits")),
        Some("500.00 USD"),
        "{out}"
    );
    let (_, trunk_out, _) = run(&["tb", "--period", "FY2026-P03"]);
    let trunk_line =
        json::parse(trunk_out.lines().last().unwrap_or_default()).unwrap_or(Json::Null);
    assert_eq!(
        trunk_line
            .get("coordinate")
            .and_then(|c| c.get("branch"))
            .and_then(Json::as_str),
        Some("trunk")
    );
    let trunk_rows = arr(&doc(&trunk_out), "rows").to_vec();
    assert!(
        trunk_rows
            .iter()
            .filter(|r| text(r, "code") == "4000")
            .all(|r| text(r, "credits") == "0.00 USD"),
        "trunk never sees the scenario's revenue: {trunk_out}"
    );
    let (code, out, err) = run(&[
        &["statement", "income-statement", "--for", "FY2026-P03"][..],
        &branch,
    ]
    .concat());
    assert_eq!(code, 0, "{out}\n{err}");
    for refused in [
        &[
            "tb",
            "--period",
            "FY2026-P03",
            "--branch",
            "scenario:but-for",
            "--certify",
        ][..],
        &[
            "tb",
            "--period",
            "FY2026-P03",
            "--branch",
            "scenario:but-for",
            "--as-known-at",
            "HEAD",
        ],
        &["tb", "--period", "FY2026-P03", "--branch", "draft:close-03"],
        &[
            "post",
            "--intent",
            later.as_str(),
            "--branch",
            "scenario:but-for",
        ],
    ] {
        let (code, out, _) = run(refused);
        assert_eq!(code, 2, "{refused:?}: {out}");
    }
    let (code, out, _) = run(&["tb", "--period", "FY2026-P03", "--branch", "scenario:nope"]);
    assert_eq!(
        (code, field(&out, "refusal_id")),
        (3, Some("FA-REF-162")),
        "{out}"
    );

    // Planted negatives: none of them records anything.
    let early = intent(
        "early.json",
        "too-early",
        "2026-03-05",
        "1000",
        "4000",
        "1.00",
    );
    let (code, out, _) = run(&["scenario", "run", "but-for", "--intent", &early]);
    assert_eq!(
        (code, field(&out, "refusal_id")),
        (3, Some("FA-REF-164")),
        "{out}"
    );
    let april = intent("april.json", "april", "2026-04-10", "1000", "4000", "1.00");
    let (code, out, _) = run(&["scenario", "run", "but-for", "--intent", &april]);
    assert_eq!(
        (code, field(&out, "refusal_id")),
        (7, Some("FA-REF-010")),
        "the scenario's replay refuses a post to a Future period: {out}"
    );
    assert!(out.contains("intent #3"), "{out}");
    let (code, out, _) = run(&["scenario", "run", "nope", "--intent", &sale]);
    assert_eq!(
        (code, field(&out, "refusal_id")),
        (3, Some("FA-REF-162")),
        "{out}"
    );
    let (code, out, _) = run(&[
        "post",
        "--intent",
        &sale,
        "--scenario",
        "but-for",
        "--draft",
        "close-03",
    ]);
    assert_eq!(
        code, 2,
        "a draft and a scenario are different intent logs: {out}"
    );
    let (code, out, _) = run(&["scenario", "fork", "beyond", "--at", "999999"]);
    assert_eq!(code, 2, "a fork beyond the head: {out}");
    let unheld = "0".repeat(64);
    let (code, out, _) = run(&["scenario", "fork", "unsupported", "--evidence", &unheld]);
    assert_eq!(
        (code, field(&out, "refusal_id")),
        (3, Some("FA-REF-081")),
        "{out}"
    );
    let (code, out, _) = run(&["scenario", "show", "but-for"]);
    assert_eq!(code, 0, "{out}");
    let shown = doc(&out);
    let intents = arr(&shown, "intents");
    assert_eq!(
        intents.len(),
        2,
        "refused intents never enter the scenario: {out}"
    );
    assert_eq!(text(&intents[0], "entry"), text(&ran, "entry"));
    // Every check precedes the replay: another principal's intent, which
    // the replay would refuse for its Future period, is refused for not
    // owning the scenario, never rehearsed on it.
    let (code, out, _) = run(&[
        "scenario", "run", "but-for", "--intent", &april, "--as", "other",
    ]);
    assert_eq!(
        (code, field(&out, "refusal_id")),
        (7, Some("FA-REF-011")),
        "{out}"
    );
    assert!(!out.contains("intent #"), "nothing was rehearsed: {out}");

    // Discard closes it; its history stays and its diff stays reproducible.
    let (code, out, _) = run(&["scenario", "discard", "but-for", "--reason", "superseded"]);
    assert_eq!(code, 0, "{out}");
    let other = intent(
        "other.json",
        "after-discard",
        "2026-03-21",
        "6000",
        "1000",
        "1.00",
    );
    let (code, out, _) = run(&["scenario", "run", "but-for", "--intent", &other]);
    assert_eq!(
        (code, field(&out, "refusal_id")),
        (3, Some("FA-REF-163")),
        "{out}"
    );
    // A retry of an intent recorded before the discard still returns its
    // record (FA-INV-09), never the discarded-state refusal.
    let (code, out, _) = run(&["scenario", "run", "but-for", "--intent", &sale]);
    assert_eq!(code, 0, "{out}");
    let late_retry = doc(&out);
    assert_eq!(late_retry.get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(int(&late_retry, "ordinal"), Some(1));
    assert_eq!(text(&late_retry, "entry"), text(&ran, "entry"));
    let (code, out, _) = run(&["scenario", "list"]);
    assert_eq!(code, 0, "{out}");
    let listed = doc(&out);
    let all = arr(&listed, "scenarios");
    assert_eq!(all.len(), 1, "{out}");
    assert_eq!(text(&all[0], "state"), "discarded");
    assert_eq!(int(&all[0], "intents"), Some(2));
    assert_eq!(
        int(&all[0], "opened_at"),
        int(&forked, "recorded_at"),
        "opened_at is the fork's record, never the discard that changed the row: {out}"
    );
    let (code, out, _) = run(&["scenario", "diff", "but-for", "--period", "FY2026-P03"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(arr(&doc(&out), "rows"), arr(&diff, "rows"));
    let (code, out, _) = run(&["replay", &format!("C:{oid}")]);
    assert_eq!(
        code, 0,
        "a discarded scenario's certificate still replays: {out}"
    );
    assert_eq!(doc(&out), certified);
    Ok(())
}

/// fa-f3bo: `fa event record|show|list` journals and queries REA `Event`
/// vertices, `fa post --event` links entries via `DERIVED_FROM` and inherits
/// the event's evidence closure, `fa explain entry` reports the cited event,
/// and citing a missing event refuses with `FA-REF-030` (exit 3).
#[test]
fn rea_event_cli_record_show_list_and_post_provenance() -> std::io::Result<()> {
    let (book, ev, dir) = envelope_book("rea-event-cli")?;
    let ok = |args: &[&str]| -> String {
        let (code, out, err) = fa(Some(&book), args);
        assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
        out
    };

    let recorded = doc(&ok(&[
        "event",
        "record",
        "--code",
        "EV-SALE-42",
        "--kind",
        "sale",
        "--occurred-on",
        "2026-03-12",
        "--evidence",
        &ev,
        "--resource",
        "cash_inflow:250.00 USD",
        "--external-id",
        "stripe:ch_42",
        "--description",
        "Customer sale #42",
        "--json",
    ]));
    assert_eq!(text(&recorded, "code"), "EV-SALE-42");
    assert_eq!(text(&recorded, "kind"), "sale");
    assert_eq!(recorded.get("already_recorded"), Some(&Json::Bool(false)));
    let ev_vid = text(&recorded, "event_vid").to_string();

    let shown = doc(&ok(&["event", "show", "EV-SALE-42", "--json"]));
    let ev_obj = shown.get("detail").expect("event detail");
    assert_eq!(text(ev_obj, "vid"), ev_vid);
    assert_eq!(text(ev_obj, "code"), "EV-SALE-42");
    assert_eq!(text(ev_obj, "description"), "Customer sale #42");
    assert_eq!(arr(ev_obj, "resources").len(), 1);
    assert_eq!(arr(ev_obj, "external_ids").len(), 1);

    let listed = doc(&ok(&["event", "list", "--json"]));
    assert_eq!(listed.get("count"), Some(&Json::Int(1)));

    // Post an entry citing EV-SALE-42 without explicit `--evidence`: it inherits EV-SALE-42's evidence!
    let intent_path = write(
        &dir,
        "sale42.json",
        r#"{"effective_date":"2026-03-12","description":"Sale #42","idempotency_key":"sale-42","legs":[{"side":"debit","account":"1000","amount":"250.00 USD"},{"side":"credit","account":"6000","amount":"250.00 USD"}]}"#,
    );
    let posted = doc(&ok(&[
        "post",
        "--intent",
        &intent_path,
        "--event",
        "EV-SALE-42",
        "--json",
    ]));
    let entry_vid = text(&posted, "vid").to_string();

    let explained = doc(&ok(&["explain", "entry", &entry_vid, "--json"]));
    let cited_ev = explained
        .get("cited_event")
        .expect("cited_event field on entry_explained");
    assert_eq!(text(cited_ev, "vid"), ev_vid);
    assert_eq!(text(cited_ev, "code"), "EV-SALE-42");

    // Citing a nonexistent event is refused with FA-REF-030 (exit 3).
    let bad_intent = write(
        &dir,
        "bad_sale.json",
        r#"{"effective_date":"2026-03-12","description":"Missing event","idempotency_key":"bad-sale","legs":[{"side":"debit","account":"1000","amount":"50.00 USD"},{"side":"credit","account":"6000","amount":"50.00 USD"}]}"#,
    );
    let (bad_code, bad_out, _) = fa(
        Some(&book),
        &[
            "post",
            "--intent",
            &bad_intent,
            "--event",
            "EV-NO-SUCH-EVENT",
            "--evidence",
            &ev,
            "--json",
        ],
    );
    assert_eq!(bad_code, 3, "{bad_out}");
    let bad_err = doc(&bad_out);
    assert_eq!(text(&bad_err, "refusal_id"), "FA-REF-080", "{bad_out}");

    Ok(())
}

#[test]
fn book_create_entity_functional_unit_guard_e2e() -> std::io::Result<()> {
    let dir = tmp("book-entity-functional-unit")?;
    let bad_book = dir.join("bad-book");

    // 1. `fa book create` with an entity whose functional unit differs from base_unit exits 3
    // with FA-REF-003 naming the separate book's `fa book create` and creates no
    // directory or key file.
    let (code, out, _) = fa(
        Some(&bad_book),
        &[
            "book",
            "create",
            "--name",
            "Multi Currency Attempt",
            "--base-unit",
            "USD",
            "--entity",
            "HOLDCO:HoldCo Inc.:USD",
            "--entity",
            "SUB-EU:Sub EU GmbH:EUR",
            "--json",
        ],
    );
    assert_eq!(code, 3, "{out}");
    let err = doc(&out);
    assert_eq!(text(&err, "refusal_id"), "FA-REF-003", "{out}");
    assert_eq!(text(&err, "class"), "refusal", "{out}");
    let fix = text(&err, "fix");
    assert!(
        fix.contains("fa book create")
            && fix.contains("--base-unit EUR")
            && !fix.contains("Concordat"),
        "expected fix to name `fa book create --base-unit EUR`, got: {fix}"
    );
    assert!(
        !bad_book.exists(),
        "refused book create must not leave a book directory behind"
    );

    // 2. `fa book create` with entities sharing the book's base_unit succeeds and `book info`
    // lists the registered legal entity codes.
    let good_book = dir.join("good-book");
    let (ok_code, ok_out, _) = fa(
        Some(&good_book),
        &[
            "book",
            "create",
            "--name",
            "Single Functional Currency Group",
            "--base-unit",
            "USD",
            "--entity",
            "HOLDCO:HoldCo Inc.:USD",
            "--entity",
            "SUB-US:Sub US LLC",
            "--json",
        ],
    );
    assert_eq!(ok_code, 0, "{ok_out}");
    let (info_code, info_out, _) = fa(Some(&good_book), &["book", "info", "--json"]);
    assert_eq!(info_code, 0, "{info_out}");
    let info = doc(&info_out);
    let entities = arr(&info, "entities");
    assert_eq!(entities.len(), 2, "{info_out}");

    Ok(())
}

/// fa-s7x: a draft's intents reach trunk only through another principal's
/// promotion. Planning journals the rehearsed intent and posts nothing; the
/// owner cannot promote it (FA-REF-008) and an unconfirmed promotion is
/// refused (FA-REF-007); a controller's confirmed promotion posts the exact
/// planned entry, its retry is the recorded promotion, and the promoted
/// draft takes no further intents (FA-REF-158).
#[test]
fn a_draft_reaches_trunk_only_through_another_principals_promotion() -> std::io::Result<()> {
    let dir = tmp("draft-flow")?;
    let book = dir.join("book");
    let run = |args: &[&str]| -> (i32, String, String) {
        let mut argv = args.to_vec();
        argv.push("--json");
        let (code, out, err) = fa(Some(book.as_path()), &argv);
        eprintln!("$ fa {} -> {code}\n{out}{err}", argv.join(" "));
        (code, out, err)
    };
    assert_eq!(run(&["book", "create", "--name", "Draft Co"]).0, 0);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","leaf":true,"unit":"USD"}]}"#,
    );
    assert_eq!(run(&["chart", "import", &chart]).0, 0);
    assert_eq!(run(&["period", "create", "--fiscal-year", "2026"]).0, 0);
    assert_eq!(run(&["period", "open", "FY2026-P03"]).0, 0);
    let source = write(&dir, "invoice.txt", "INVOICE 1 (draft flow)");
    let (code, out, _) = run(&[
        "document",
        "add",
        &source,
        "--kind",
        "Invoice",
        "--grade",
        "HumanUpload",
    ]);
    assert_eq!(code, 0, "{out}");
    let ev = field(&out, "oid").unwrap_or_default().to_string();
    let intent = |key: &str| {
        format!(
            r#"{{"effective_date":"2026-03-15","idempotency_key":"{key}","evidence":["{ev}"],"legs":[{{"side":"debit","account":"6000","amount":"25.00 USD"}},{{"side":"credit","account":"1000","amount":"25.00 USD"}}]}}"#
        )
    };
    let rent = write(&dir, "rent.json", &intent("draft-flow-rent"));
    let (code, out, _) = run(&["draft", "new", "march", "--as", "preparer"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "event"), Some("draft_opened"));
    let (code, out, _) = run(&[
        "post", "--intent", &rent, "--draft", "march", "--as", "preparer",
    ]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "event"), Some("draft_planned"));
    let entry = field(&out, "entry").unwrap_or_default().to_string();
    assert_eq!(entry.len(), 32, "{out}");
    let (code, out, _) = run(&["entry", "show", &entry]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        field(&out, "found"),
        Some("false"),
        "a planned intent is not a trunk entry: {out}"
    );

    let (code, out, _) = run(&["draft", "promote", "march", "--as", "preparer", "--yes"]);
    assert_eq!(code, 7, "{out}");
    assert!(
        out.contains("FA-REF-008"),
        "the owner never promotes: {out}"
    );
    let (code, out, _) = run(&["draft", "promote", "march", "--as", "controller"]);
    assert_eq!(code, 7, "{out}");
    assert!(out.contains("FA-REF-007"), "promotion is confirmed: {out}");
    let (code, out, _) = run(&["draft", "promote", "march", "--as", "controller", "--yes"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "event"), Some("draft_promoted"));
    assert!(
        out.contains(&entry),
        "the planned entry is the promoted one: {out}"
    );
    assert_eq!(field(&out, "already_recorded"), Some("false"));
    let (code, out, _) = run(&["entry", "show", &entry]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "found"), Some("true"), "promoted: {out}");
    let (code, out, _) = run(&["draft", "promote", "march", "--as", "controller", "--yes"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "already_recorded"), Some("true"));
    let late = write(&dir, "late.json", &intent("draft-flow-late"));
    let (code, out, _) = run(&[
        "post", "--intent", &late, "--draft", "march", "--as", "preparer",
    ]);
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("FA-REF-158"), "{out}");
    let (code, out, _) = run(&["draft", "show", "march"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("\"state\":\"promoted\""), "{out}");
    Ok(())
}

/// fa-r3q: `fa --token <file>` without a daemon binds the command to the
/// token's principal and journaled capability: the envelope says
/// `issued-token`, an Agent token cannot post to trunk but can plan into its
/// own draft, `--as`/`--grant` beside a token are refused, and a revoked
/// token's next write is FA-REF-023.
#[test]
fn a_token_session_binds_the_cli_to_its_issued_capability() -> std::io::Result<()> {
    let dir = tmp("token-cli")?;
    // A token session confines host paths to its working directory
    // (relative paths only), so every command runs in `dir`.
    let run = |args: &[&str]| -> (i32, String, String) {
        let mut argv = vec!["--book", "book"];
        argv.extend_from_slice(args);
        argv.push("--json");
        let out = Command::new(env!("CARGO_BIN_EXE_fa"))
            .current_dir(&dir)
            .args(&argv)
            .env_remove("FA_BOOK")
            .output()
            .expect("run fa");
        let code = out.status.code().unwrap_or(-1);
        let (out, err) = (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        );
        check_robot_output(&argv, code, &out);
        eprintln!("$ fa {} -> {code}\n{out}{err}", argv.join(" "));
        (code, out, err)
    };
    assert_eq!(run(&["book", "create", "--name", "Token Co"]).0, 0);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","leaf":true,"unit":"USD"}]}"#,
    );
    assert_eq!(run(&["chart", "import", &chart]).0, 0);
    assert_eq!(run(&["period", "create", "--fiscal-year", "2026"]).0, 0);
    assert_eq!(run(&["period", "open", "FY2026-P03"]).0, 0);
    let source = write(&dir, "invoice.txt", "INVOICE 9 (token session)");
    let (code, out, _) = run(&[
        "document",
        "add",
        &source,
        "--kind",
        "Invoice",
        "--grade",
        "HumanUpload",
    ]);
    assert_eq!(code, 0, "{out}");
    let ev = field(&out, "oid").unwrap_or_default().to_string();
    let token = dir.join("agent-9.token").display().to_string();
    let (code, out, _) = run(&[
        "capability",
        "issue",
        "--holder",
        "agent-9",
        "--profile",
        "agent",
        "--op",
        "read",
        "--op",
        "post",
        "--out",
        &token,
        "--grant",
        "issue_capability",
        "--grant",
        "read",
        "--grant",
        "post",
    ]);
    assert_eq!(code, 0, "{out}");
    let commitment = field(&out, "commitment").unwrap_or_default().to_string();

    let (code, out, _) = run(&["--token", &token, "tb", "--period", "FY2026-P03"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("\"posture\":\"issued-token\""), "{out}");
    assert!(out.contains("\"principal\":\"agent-9\""), "{out}");
    write(
        &dir,
        "rent.json",
        &format!(
            r#"{{"effective_date":"2026-03-15","idempotency_key":"token-cli-rent","evidence":["{ev}"],"legs":[{{"side":"debit","account":"6000","amount":"4.00 USD"}},{{"side":"credit","account":"1000","amount":"4.00 USD"}}]}}"#
        ),
    );
    let (code, out, _) = run(&["--token", "agent-9.token", "post", "--intent", "rent.json"]);
    assert_eq!(code, 7, "{out}");
    assert!(out.contains("FA-REF-013"), "{out}");
    assert_eq!(run(&["--token", &token, "draft", "new", "agent-9"]).0, 0);
    let (code, out, _) = run(&[
        "--token",
        &token,
        "post",
        "--intent",
        "rent.json",
        "--draft",
        "agent-9",
    ]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(field(&out, "event"), Some("draft_planned"), "{out}");
    for flag in ["--as", "--grant"] {
        let (code, out, _) = run(&["--token", &token, flag, "post", "draft", "list"]);
        assert_eq!(code, 2, "{flag}: {out}");
    }
    let (code, out, _) = run(&[
        "capability",
        "revoke",
        "--commitment",
        &commitment,
        "--grant",
        "issue_capability",
        "--yes",
    ]);
    assert_eq!(code, 0, "{out}");
    let (code, out, _) = run(&["--token", &token, "draft", "new", "after"]);
    assert_eq!(code, 7, "{out}");
    assert!(out.contains("FA-REF-023"), "{out}");

    // fa-5npo: Auditor profile template requires redaction caveat and pins known_at <= S,
    // refusing reads at later frontiers.
    let (code, out, _) = run(&[
        "capability",
        "issue",
        "--holder",
        "auditor-missing-redaction",
        "--profile",
        "auditor",
        "--out",
        "auditor-bad.token",
        "--grant",
        "issue_capability",
        "--grant",
        "read",
        "--grant",
        "verify",
        "--grant",
        "produce",
        "--grant",
        "witness",
    ]);
    assert_eq!(
        code, 2,
        "Auditor without --redaction must be refused: {out}"
    );
    let (_, info, _) = run(&["book", "info"]);
    let pin_seq = field(&info, "known_at").unwrap_or("1").to_string();
    let auditor_token = "auditor-pinned.token";
    let (code, out, _) = run(&[
        "capability",
        "issue",
        "--holder",
        "auditor-1",
        "--profile",
        "auditor",
        "--op",
        "read",
        "--op",
        "verify",
        "--op",
        "produce",
        "--redaction",
        "1",
        "--known-at-most",
        &pin_seq,
        "--out",
        auditor_token,
        "--grant",
        "issue_capability",
        "--grant",
        "read",
        "--grant",
        "verify",
        "--grant",
        "produce",
    ]);
    assert_eq!(code, 0, "Auditor issuance: {out}");
    // Post a new entry after the pin, then verify the pinned Auditor token can read at <= pin_seq
    // and is refused at the new head.
    write(
        &dir,
        "after-pin.json",
        &format!(
            r#"{{"effective_date":"2026-03-16","idempotency_key":"after-auditor-pin","evidence":["{ev}"],"legs":[{{"side":"debit","account":"6000","amount":"5.00 USD"}},{{"side":"credit","account":"1000","amount":"5.00 USD"}}]}}"#
        ),
    );
    let (code, out, _) = run(&["post", "--intent", "after-pin.json", "--grant", "post"]);
    assert_eq!(code, 0, "{out}");
    let (code, out, _) = run(&[
        "--token",
        auditor_token,
        "tb",
        "--period",
        "FY2026-P03",
        "--as-known-at",
        &pin_seq,
    ]);
    assert_eq!(code, 0, "pinned Auditor reads at pin_seq: {out}");
    let (code, out, _) = run(&["--token", auditor_token, "tb", "--period", "FY2026-P03"]);
    assert_eq!(code, 7, "pinned Auditor refused at later head: {out}");
    assert!(out.contains("FA-REF-011"), "{out}");
    assert!(out.contains("the token is pinned at <="), "{out}");
    Ok(())
}

/// FA-INV-01 per-entity: in a multi-entity book `fa verify entities`
/// refolds each period's per-legal-entity register and proves it against
/// the journal; the kernel already refuses a leg without a declared entity
/// at commit, so the verification is the derived-state half.
#[test]
fn verify_entities_proves_each_legal_entitys_register_by_refold() -> std::io::Result<()> {
    let dir = tmp("entities")?;
    let book = dir.join("book");
    let run = |args: &[&str]| {
        let mut argv = args.to_vec();
        argv.push("--json");
        fa(Some(&book), &argv)
    };
    let (code, out, _) = run(&[
        "book",
        "create",
        "--name",
        "Two Entities",
        "--base-unit",
        "USD",
        "--entity",
        "HOLDCO:HoldCo Inc.:USD",
        "--entity",
        "SUB-US:Sub US LLC",
    ]);
    assert_eq!(code, 0, "{out}");
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Sales","type":"Revenue","unit":"USD"}]}"#,
    );
    assert_eq!(run(&["chart", "import", &chart]).0, 0);
    assert_eq!(run(&["period", "create", "--fiscal-year", "2026"]).0, 0);
    assert_eq!(run(&["period", "open", "FY2026-P03"]).0, 0);
    let source = write(&dir, "sales.txt", "Sales of both entities");
    let (code, out, _) = run(&[
        "document",
        "add",
        &source,
        "--kind",
        "Invoice",
        "--grade",
        "HumanUpload",
    ]);
    assert_eq!(code, 0, "{out}");
    let evidence = text(&doc(&out), "oid").to_string();
    let post = |key: &str, entity: Option<&str>, amount: &str| {
        let entity = entity.map_or(String::new(), |code| format!(r#","entity":"{code}""#));
        let intent = write(
            &dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"idempotency_key":"{key}","effective_date":"2026-03-10","legs":[{{"side":"debit","account":"1000","amount":"{amount} USD"{entity}}},{{"side":"credit","account":"4000","amount":"{amount} USD"{entity}}}]}}"#
            ),
        );
        run(&["post", "--intent", &intent, "--evidence", &evidence])
    };
    assert_eq!(post("holdco-sale", Some("HOLDCO"), "10.00").0, 0);
    assert_eq!(post("sub-sale", Some("SUB-US"), "4.00").0, 0);
    // The commit-time half: a leg naming no entity is refused.
    let (code, out, _) = post("no-entity", None, "1.00");
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("names no legal entity"), "{out}");

    let (code, out, _) = run(&["verify", "entities", "--period", "FY2026-P03"]);
    assert_eq!(code, 0, "{out}");
    let line = json::parse(out.lines().last().unwrap_or_default()).unwrap_or(Json::Null);
    assert_eq!(text(&line, "event"), "entities_verified", "{out}");
    let periods = arr(&doc(&out), "periods").to_vec();
    assert_eq!(periods.len(), 1, "{out}");
    let check = &periods[0];
    assert_eq!(text(check, "period"), "FY2026-P03");
    assert_eq!(check.get("green"), Some(&Json::Bool(true)), "{out}");
    assert_eq!(int(check, "entries_checked"), Some(2), "{out}");
    // Two accounts in two entities.
    assert_eq!(int(check, "cells_checked"), Some(4), "{out}");
    assert!(arr(check, "findings").is_empty(), "{out}");
    assert_eq!(text(check, "fold_digest").len(), 64, "{out}");

    // An unknown period is a usage error, not an empty green.
    let (code, out, _) = run(&["verify", "entities", "--period", "FY2099-P01"]);
    assert_ne!(code, 0, "{out}");
    Ok(())
}

/// Explaining a summary account names the command that answers it: the
/// summary trial balance rooted at that account, which runs as given.
#[test]
fn explaining_a_summary_account_points_at_its_roll_up_which_runs() -> std::io::Result<()> {
    let dir = tmp("summary-explain")?;
    let book = dir.join("book");
    let run = |args: &[&str]| {
        let mut argv = args.to_vec();
        argv.push("--json");
        fa(Some(&book), &argv)
    };
    assert_eq!(run(&["book", "create", "--name", "Summary Co"]).0, 0);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1","name":"Assets","type":"Asset","leaf":false,"unit":"USD"},{"code":"1000","name":"Cash","type":"Asset","leaf":true,"unit":"USD","parent":"1"},{"code":"4000","name":"Sales","type":"Revenue","unit":"USD"}]}"#,
    );
    assert_eq!(run(&["chart", "import", &chart]).0, 0);
    assert_eq!(run(&["period", "create", "--fiscal-year", "2026"]).0, 0);
    assert_eq!(run(&["period", "open", "FY2026-P03"]).0, 0);

    let (code, out, _) = run(&["explain", "balance", "1", "--period", "FY2026-P03"]);
    assert_eq!(code, 2, "{out}");
    let error = doc(&out);
    assert!(
        text(&error, "message").contains("is a summary account"),
        "{out}"
    );
    let fix = text(&error, "fix");
    let suggested = "fa tb --period FY2026-P03 --summary --root 1 --json";
    assert!(fix.starts_with(suggested), "{fix}");
    // The suggestion is a working command, not prose.
    let argv: Vec<&str> = suggested.split(' ').skip(1).collect();
    let (code, out, _) = fa(Some(&book), &argv);
    assert_eq!(code, 0, "{out}");
    Ok(())
}

/// `fa search` ranks entries by their description and leg memos, from an
/// index rebuilt from the journal at the selected frontier: an entry
/// recorded later is not found at an earlier frontier, the same prefix
/// rebuilds the same index, and a query nothing matches is an empty
/// success.
#[test]
fn search_finds_entries_by_their_text_at_a_recorded_frontier() -> std::io::Result<()> {
    let dir = tmp("search")?;
    let book = dir.join("book");
    let run = |args: &[&str]| {
        let mut argv = args.to_vec();
        argv.push("--json");
        fa(Some(&book), &argv)
    };
    assert_eq!(run(&["book", "create", "--name", "Search Co"]).0, 0);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Sales","type":"Revenue","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    assert_eq!(run(&["chart", "import", &chart]).0, 0);
    assert_eq!(run(&["period", "create", "--fiscal-year", "2026"]).0, 0);
    assert_eq!(run(&["period", "open", "FY2026-P03"]).0, 0);
    let source = write(&dir, "evidence.txt", "Lease and sales evidence");
    let (code, out, _) = run(&[
        "document",
        "add",
        &source,
        "--kind",
        "Invoice",
        "--grade",
        "HumanUpload",
    ]);
    assert_eq!(code, 0, "{out}");
    let evidence = text(&doc(&out), "oid").to_string();
    let post = |key: &str, description: &str, memo: &str, debit: &str, credit: &str| {
        let intent = write(
            &dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"idempotency_key":"{key}","effective_date":"2026-03-10","description":"{description}","legs":[{{"side":"debit","account":"{debit}","amount":"9.00 USD","memo":"{memo}"}},{{"side":"credit","account":"{credit}","amount":"9.00 USD"}}]}}"#
            ),
        );
        let (code, out, _) = run(&["post", "--intent", &intent, "--evidence", &evidence]);
        assert_eq!(code, 0, "{out}");
        text(&doc(&out), "vid").to_string()
    };
    let rent = post(
        "rent",
        "Office rent for March",
        "Harbor Street lease",
        "6000",
        "1000",
    );
    let (_, info, _) = run(&["book", "info"]);
    let before_sale = json::parse(info.lines().last().unwrap_or_default())
        .ok()
        .and_then(|line| line.get("coordinate").and_then(|c| int(c, "known_at")))
        .unwrap_or_default()
        .to_string();
    let sale = post(
        "sale",
        "Consulting sale to Acme",
        "Invoice A-17",
        "1000",
        "4000",
    );

    let search = |args: &[&str]| -> Json {
        let mut argv = vec!["search"];
        argv.extend_from_slice(args);
        let (code, out, _) = run(&argv);
        assert_eq!(code, 0, "{argv:?}: {out}");
        doc(&out)
    };
    let ids = |found: &Json| -> Vec<String> {
        arr(found, "hits")
            .iter()
            .map(|hit| text(hit, "id").to_string())
            .collect()
    };
    // A description and a leg memo are both searchable, and each entry is
    // found by its own text only (control entries may carry text too).
    let found = search(&["rent"]);
    let hits = ids(&found);
    assert_eq!(hits.first(), Some(&rent), "{found:?}");
    assert!(!hits.contains(&sale), "{found:?}");
    for (query, wanted, other) in [
        ("harbor", &rent, &sale),
        ("acme", &sale, &rent),
        ("A-17", &sale, &rent),
    ] {
        let hits = ids(&search(&[query]));
        assert!(hits.contains(wanted), "{query}: {hits:?}");
        assert!(!hits.contains(other), "{query}: {hits:?}");
    }
    // The same journal prefix rebuilds the same index.
    assert_eq!(
        text(&search(&["acme"]), "index_digest"),
        text(&found, "index_digest")
    );
    // At a frontier before the sale, the sale is not there to be found.
    let early = search(&["acme", "--as-known-at", &before_sale]);
    assert!(!ids(&early).contains(&sale), "{early:?}");
    assert_eq!(
        int(&found, "records").unwrap_or_default() - int(&early, "records").unwrap_or_default(),
        1,
        "exactly the sale was recorded after the earlier frontier"
    );
    // A query nothing matches is an empty success; a bad request is usage.
    assert!(ids(&search(&["zeppelin"])).is_empty());
    assert_eq!(run(&["search"]).0, 2);
    assert_eq!(run(&["search", "rent", "--limit", "0"]).0, 2);
    Ok(())
}
