//! `fad` with real processes and a real Unix socket (bead fa-i8j): the
//! writer lease is exclusive (a second daemon exits 6, FA-REF-018), `fa`
//! routes through the daemon that holds it and gets byte-identical answers,
//! every registered verb and subcommand is served by both hosts (the parity
//! gate), stdin and relative paths travel with the request, `stop` releases
//! the lease, and a crashed daemon (SIGKILL) leaves nothing that blocks the
//! next one. `fa` runs in-process through `fa_cli::entry::fa`, the same front
//! door the `fa` binary uses; every `--json` line and every frame is checked
//! against `registries/verbs.toml`.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::client;
use fa_cli::lease::Lease;
use fa_cli::verbs::registry;
use fa_cli::wire::{Op, Request};

fn tmp(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        // RCH's private TMPDIR may exceed sockaddr_un's path limit before
        // the real daemon can start. Keep these retained socket fixtures short.
        let d = Path::new("/tmp").join(format!("fad-{}-{name}-{n}", std::process::id()));
        if std::fs::create_dir(&d).is_ok() {
            let d = d.canonicalize().unwrap_or(d);
            assert!(
                d.join("book/fad.sock").as_os_str().as_encoded_bytes().len() < 104,
                "portable Unix socket fixture: {}",
                d.display()
            );
            return d;
        }
        assert!(n < 1_000, "cannot create a scratch directory");
    }
}

fn write(dir: &Path, name: &str, text: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, text).expect("write fixture");
    p.display().to_string()
}

/// Every robot-mode line names a declared event and carries exactly its fields.
fn checked(stdout: &str) -> Vec<String> {
    let reg = registry().expect("verbs.toml");
    stdout
        .lines()
        .map(|l| {
            let e = reg.check_line(l);
            assert!(e.is_ok(), "{}", e.clone().err().unwrap_or_default());
            e.unwrap_or_default().to_string()
        })
        .collect()
}

/// `fa`, in-process, through the front door: (exit, stdout, stderr).
fn fa(args: &[&str]) -> (u8, String, String) {
    let argv: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
    let (code, out) = fa_cli::entry::fa(&argv, true);
    if args.contains(&"--json") {
        checked(&out.stdout);
    }
    (code, out.stdout, out.stderr)
}

fn ok(args: &[&str]) -> String {
    let (code, out, err) = fa(args);
    assert_eq!(code, 0, "args={args:?}\n{out}\n{err}");
    out
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

/// A book with a chart, an open March, a source document, and one posting.
/// Returns (book dir, document oid).
fn book(dir: &Path) -> (PathBuf, String) {
    book_with_options(dir, &[])
}

fn book_with_options(dir: &Path, options: &[&str]) -> (PathBuf, String) {
    let book = dir.join("book");
    let b = book.display().to_string();
    let mut create = vec![
        "book",
        "create",
        "--book",
        &b,
        "--name",
        "Daemon Co",
        "--json",
    ];
    create.extend_from_slice(options);
    ok(&create);
    let chart = write(
        dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--book", &b, "--json"]);
    ok(&[
        "period",
        "create",
        "--fiscal-year",
        "2026",
        "--book",
        &b,
        "--json",
    ]);
    ok(&["period", "open", "FY2026-P03", "--book", &b, "--json"]);
    let source = write(dir, "source.txt", "INVOICE (fad fixture source document)");
    let added = ok(&[
        "document",
        "add",
        &source,
        "--kind",
        "Invoice",
        "--grade",
        "HumanUpload",
        "--book",
        &b,
        "--json",
    ]);
    let oid = field(&added, "oid").unwrap_or_default().to_string();
    let rent = write(
        dir,
        "rent.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"rent","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"1000","amount":"10.00 USD"}]}"#,
    );
    ok(&[
        "post",
        "--intent",
        &rent,
        "--evidence",
        &oid,
        "--book",
        &b,
        "--json",
    ]);
    (book, oid)
}

/// A running `fad serve`, its stdout kept open (the daemon writes to it again
/// on the way out), and its first line.
struct Daemon {
    child: Child,
    out: BufReader<ChildStdout>,
    serving: String,
}

fn fad(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_fad"))
        .args(args)
        .env_remove("FA_BOOK")
        .output()
        .expect("run fad");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if args.contains(&"--json") {
        checked(&stdout);
    }
    (
        out.status.code().unwrap_or(-1),
        stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn start(book: &Path) -> Daemon {
    start_with_timed_work(book, false)
}

fn start_without_files_root(book: &Path) -> Daemon {
    start_daemon(book, false, None, None)
}

fn start_with_timed_work(book: &Path, bootstrap: bool) -> Daemon {
    let files_root = book.parent().expect("book parent dir");
    start_daemon(book, bootstrap, Some(files_root), None)
}

fn start_daemon(
    book: &Path,
    bootstrap: bool,
    files_root: Option<&Path>,
    fiscal_year: Option<i32>,
) -> Daemon {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fad"));
    command.args(["serve", "--book", &book.display().to_string(), "--json"]);
    if let Some(root) = files_root {
        command.args(["--files-root", &root.display().to_string()]);
    }
    if bootstrap {
        command.arg("--bootstrap-system");
    }
    if let Some(year) = fiscal_year {
        command.args(["--register-fiscal-year", &year.to_string()]);
    }
    let mut child = command
        .env_remove("FA_BOOK")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn fad");
    let stdout = child.stdout.take().expect("piped stdout");
    let mut out = BufReader::new(stdout);
    let mut serving = String::new();
    let _ = out.read_line(&mut serving);
    assert_eq!(
        checked(serving.trim_end()),
        vec!["fad_serving"],
        "fad did not start: {serving}"
    );
    Daemon {
        child,
        out,
        serving,
    }
}

impl Daemon {
    /// Wait for the process to exit; its exit code and the rest of its stdout.
    fn finish(mut self) -> (i32, String) {
        let status = self.child.wait().expect("wait for fad");
        let mut rest = String::new();
        let _ = self.out.read_to_string(&mut rest);
        (status.code().unwrap_or(-1), rest)
    }
}

#[test]
fn fiscal_year_launch_maintains_future_created_periods_and_posted_amounts_over_the_real_socket() {
    use fa_cli::json::{self, Json};
    use std::time::{Duration, Instant};
    let dir = tmp("fiscal-cohort");
    let periods = write(
        &dir,
        "calendar.json",
        r#"{"years":[{"fiscal_year":2026,"periods":[{"start":"2026-01-01","end":"2026-01-31"},{"start":"2026-02-01","end":"2026-02-28"},{"start":"2026-03-01","end":"2026-12-31"}]},{"fiscal_year":2027,"periods":[{"start":"2027-01-01","end":"2027-12-31"}]},{"fiscal_year":2028,"periods":[{"start":"2028-01-01","end":"2028-12-31"}]}]}"#,
    );
    let (book, oid) = book_with_options(
        &dir,
        &[
            "--calendar",
            "custom",
            "--periods",
            &periods,
            "--adjustment-periods",
            "0",
        ],
    );
    let b = book.display().to_string();
    let daemon = start_daemon(&book, false, Some(&dir), Some(2027));
    // Always stop the owned process, including after an assertion failure.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let serving = json::parse(daemon.serving.trim()).unwrap();
        let data = serving.get("data").unwrap();
        assert_eq!(data.get("timed_work_enabled"), Some(&Json::Bool(false)));
        assert_eq!(data.get("timed_authority"), Some(&Json::Null));
        let states = data
            .get("register_maintenance")
            .unwrap()
            .get("periods")
            .unwrap()
            .as_arr()
            .unwrap();
        assert_eq!(
            states
                .iter()
                .map(|row| row.get("period").unwrap().as_str().unwrap())
                .collect::<Vec<_>>(),
            ["FY2027-P01", "FY2027-OPEN", "FY2027-CLOSE"]
        );
        assert!(
            states
                .iter()
                .all(|row| row.get("through") == Some(&Json::Null))
        );
        ok(&[
            "period",
            "create",
            "--fiscal-year",
            "2028",
            "--book",
            &b,
            "--json",
        ]);
        ok(&[
            "period",
            "create",
            "--fiscal-year",
            "2027",
            "--book",
            &b,
            "--json",
        ]);
        ok(&["period", "open", "FY2027-P01", "--book", &b, "--json"]);
        let reg = registry().unwrap();
        let posted = client::call(&book.join(&reg.daemon.socket), &Request {
            op: Op::Run,
            argv: ["post", "--intent", "-", "--evidence", &oid, "--book", &b, "--json"].into_iter().map(str::to_owned).collect(),
            cwd: None,
            stdin: Some(br#"{"effective_date":"2027-01-05","idempotency_key":"fiscal-cohort-rent","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#.to_vec()),
            token: None,
        }, &reg.daemon).unwrap();
        assert_eq!(posted.exit, 0, "{}{}", posted.stdout, posted.stderr);
        assert_eq!(checked(&posted.stdout), vec!["posted"]);
        let posted_at: i128 = field(&posted.stdout, "recorded_at")
            .unwrap()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let (code, out, err) = fad(&["status", "--book", &b, "--json"]);
            assert_eq!(code, 0, "{out}{err}");
            let status = json::parse(out.trim()).unwrap();
            let work = status
                .get("data")
                .unwrap()
                .get("register_maintenance")
                .unwrap();
            let state = &work.get("periods").unwrap().as_arr().unwrap()[0];
            if matches!(state.get("through"), Some(Json::Int(at)) if *at >= posted_at) {
                assert_eq!(state.get("error"), Some(&Json::Null));
                break;
            }
            assert!(
                Instant::now() < deadline,
                "P01 did not reach posting prefix {posted_at}: {out}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let verified = ok(&[
            "verify",
            "registers",
            "--period",
            "FY2027-P01",
            "--book",
            &b,
            "--json",
        ]);
        assert!(verified.contains("\"green\":true"), "{verified}");
        let tb = ok(&["tb", "--period", "FY2027-P01", "--book", &b, "--json"]);
        // Stock carries the fixture's 10 USD forward; selected-period activity
        // contains only the new 1 USD posting. Neither may lose prior history.
        assert!(tb.contains("\"debits\":\"11.00 USD\""), "{tb}");
        assert!(tb.contains("\"credits\":\"11.00 USD\""), "{tb}");
        let activity = ok(&[
            "tb",
            "--activity",
            "--period",
            "FY2027-P01",
            "--book",
            &b,
            "--json",
        ]);
        assert!(activity.contains("\"debits\":\"1.00 USD\""), "{activity}");
        assert!(activity.contains("\"credits\":\"1.00 USD\""), "{activity}");
        let other = ok(&[
            "verify",
            "registers",
            "--period",
            "FY2028-P01",
            "--book",
            &b,
            "--json",
        ]);
        assert!(
            other.contains("\"cache_status\":\"uninitialized\""),
            "{other}"
        );
    }));
    let stopped = fad(&["stop", "--book", &b, "--json"]);
    let finished = daemon.finish();
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
    assert_eq!(stopped.0, 0, "{}{}", stopped.1, stopped.2);
    assert_eq!(finished.0, 0, "{}", finished.1);
}

#[test]
fn one_daemon_per_book_and_fa_gets_byte_identical_answers_through_it() {
    let dir = tmp("serve");
    let (book, oid) = book(&dir);
    let b = book.display().to_string();
    let bad = write(
        &dir,
        "bad.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"bad","legs":[{"side":"debit","account":"6000","amount":"5.00 USD"},{"side":"credit","account":"1000","amount":"4.99 USD"}]}"#,
    );
    let asks: Vec<Vec<&str>> = vec![
        vec!["tb", "--period", "FY2026-P03", "--book", &b, "--json"],
        vec!["tb", "--period", "FY2026-P03", "--book", &b],
        vec![
            "explain",
            "balance",
            "1000",
            "--period",
            "FY2026-P03",
            "--book",
            &b,
            "--json",
        ],
        vec!["book", "info", "--book", &b, "--json"],
        vec![
            "post",
            "--intent",
            &bad,
            "--evidence",
            &oid,
            "--book",
            &b,
            "--json",
        ],
        vec!["post", "--intent", &bad, "--evidence", &oid, "--book", &b],
        vec!["entry", "show", "00", "--book", &b, "--json"],
        vec![
            "explain",
            "balance",
            "100",
            "--period",
            "FY2026-P03",
            "--book",
            &b,
            "--json",
        ],
    ];
    let direct: Vec<(u8, String, String)> = asks.iter().map(|a| fa(a)).collect();
    assert_eq!(
        direct[4].0, 3,
        "the unbalanced post is refused: {:?}",
        direct[4]
    );

    let daemon = start(&book);
    assert_eq!(field(&daemon.serving, "dir"), Some(b.as_str()));
    assert_eq!(field(&daemon.serving, "timed_work_enabled"), Some("false"));
    assert_eq!(field(&daemon.serving, "timed_authority"), Some("null"));
    // A second daemon for the same book is refused: the lease is held.
    let (code, out, err) = fad(&["serve", "--book", &b, "--json"]);
    assert_eq!(code, 6, "{out}\n{err}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-018"), "{out}");
    assert!(Lease::holder(&book, &registry().expect("verbs.toml").daemon.lease).is_some());

    // The same questions through the daemon: the same bytes and exit codes.
    let through: Vec<(u8, String, String)> = asks.iter().map(|a| fa(a)).collect();
    for ((ask, d), t) in asks.iter().zip(&direct).zip(&through) {
        assert_eq!(d, t, "direct vs through fad differ for {ask:?}");
    }
    // Insisting on a direct open while fad holds the lease is a conflict.
    let (code, out, _) = fa(&[
        "tb",
        "--period",
        "FY2026-P03",
        "--via",
        "direct",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 6, "{out}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-018"));
    // A write through the daemon.
    let more = write(
        &dir,
        "more.json",
        r#"{"effective_date":"2026-03-16","idempotency_key":"more","legs":[{"side":"debit","account":"6000","amount":"2.00 USD"},{"side":"credit","account":"1000","amount":"2.00 USD"}]}"#,
    );
    let posted = ok(&[
        "post",
        "--intent",
        &more,
        "--evidence",
        &oid,
        "--via",
        "fad",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(field(&posted, "event"), Some("posted"), "{posted}");

    let (code, status, _) = fad(&["status", "--book", &b, "--json"]);
    assert_eq!(code, 0, "{status}");
    assert_eq!(field(&status, "serving"), Some("true"), "{status}");
    let answered: u64 = field(&status, "requests")
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    assert!(answered > asks.len() as u64, "{status}");

    let (code, stopped, err) = fad(&["stop", "--book", &b, "--json"]);
    assert_eq!(code, 0, "{stopped}\n{err}");
    assert_eq!(field(&stopped, "event"), Some("fad_stopped"), "{stopped}");
    let (exit, rest) = daemon.finish();
    assert_eq!(exit, 0, "{rest}");
    assert_eq!(checked(&rest), vec!["fad_stopped"], "{rest}");

    // The lease is free again and the daemon's write is in the book.
    assert_eq!(
        Lease::holder(&book, &registry().expect("verbs.toml").daemon.lease),
        None
    );
    let tb = ok(&["tb", "--period", "FY2026-P03", "--book", &b, "--json"]);
    assert!(tb.contains("\"credits\":\"12.00 USD\""), "{tb}");
    let (code, out, _) = fad(&["stop", "--book", &b, "--json"]);
    assert_eq!(code, 4, "nothing left to stop: {out}");
}

/// What `fa doctor` and `fa triage` say about the host that answered:
/// (run directly, through fad).
fn host_report(verb: &str) -> Option<(&'static str, &'static str)> {
    match verb {
        "doctor" => Some((
            "held by this command for its duration; no fad serves the book",
            "held by the fad answering this command",
        )),
        "triage" => Some((r#""daemon":"absent""#, r#""daemon":"serving""#)),
        _ => None,
    }
}

#[test]
fn every_registered_verb_and_subcommand_is_served_by_both_hosts() {
    let dir = tmp("parity");
    let (book, _) = book(&dir);
    let b = book.display().to_string();
    let reg = registry().expect("verbs.toml");
    let mut asks: Vec<Vec<String>> = Vec::new();
    for verb in &reg.verbs {
        let calls: Vec<Vec<String>> = if verb.subcommands.is_empty() {
            vec![vec![verb.name.clone()]]
        } else {
            verb.subcommands
                .iter()
                .map(|sub| vec![verb.name.clone(), sub.clone()])
                .collect()
        };
        for mut call in calls {
            call.extend(["--book".to_string(), b.clone(), "--json".to_string()]);
            asks.push(call);
        }
    }
    let run = |a: &Vec<String>| {
        let refs: Vec<&str> = a.iter().map(String::as_str).collect();
        fa(&refs)
    };
    let direct: Vec<(u8, String, String)> = asks.iter().map(run).collect();
    let daemon = start(&book);
    let through: Vec<(u8, String, String)> = asks.iter().map(run).collect();
    let mut served = BTreeSet::new();
    for ((ask, d), t) in asks.iter().zip(&direct).zip(&through) {
        assert!(
            t.0 != 5 && !t.1.contains("has no handler"),
            "fad does not serve {ask:?}: {t:?}"
        );
        if ask[..2] == ["book".to_string(), "create".to_string()] {
            // A posture difference: a daemon serves an existing book.
            assert_eq!(t.0, 2, "{t:?}");
            assert!(t.1.contains("a daemon serves an existing one"), "{t:?}");
        } else if let Some((here, there)) = host_report(&ask[0]) {
            // The other: doctor and triage report the host that answered
            // (who holds the lease, whether a daemon serves). Each host
            // says its own; with that one value swapped, the answers match.
            assert!(d.1.contains(here), "direct {ask:?}: {d:?}");
            assert!(t.1.contains(there), "through fad {ask:?}: {t:?}");
            assert_eq!(
                d,
                &(t.0, t.1.replace(there, here), t.2.clone()),
                "direct vs through fad differ for {ask:?}"
            );
        } else {
            assert_eq!(d, t, "direct vs through fad differ for {ask:?}");
        }
        served.insert(ask[0].clone());
    }
    let registered: BTreeSet<String> = reg.verbs.iter().map(|v| v.name.clone()).collect();
    assert_eq!(served, registered);
    let (code, _, _) = fad(&["stop", "--book", &b, "--json"]);
    assert_eq!(code, 0);
    assert_eq!(daemon.finish().0, 0);
}

#[test]
fn stdin_and_relative_paths_travel_with_the_request() {
    let dir = tmp("files");
    let (book, oid) = book(&dir);
    let b = book
        .canonicalize()
        .unwrap_or(book.clone())
        .display()
        .to_string();
    let reg = registry().expect("verbs.toml");
    let daemon = start(&book);
    let socket = book.join(&reg.daemon.socket);
    let call = |argv: &[&str], cwd: Option<&Path>, stdin: Option<&str>| {
        let request = Request {
            op: Op::Run,
            argv: argv.iter().map(|a| (*a).to_string()).collect(),
            cwd: cwd.map(|c| c.display().to_string()),
            stdin: stdin.map(|s| s.as_bytes().to_vec()),
            token: None,
        };
        assert_eq!(
            reg.check_line(&request.to_json(reg.daemon.protocol).render()),
            Ok("fad_request")
        );
        let response = client::call(&socket, &request, &reg.daemon).expect("fad answers");
        assert_eq!(
            reg.check_line(&response.to_json(reg.daemon.protocol).render()),
            Ok("fad_response")
        );
        response
    };
    let piped = r#"{"effective_date":"2026-03-17","idempotency_key":"piped","legs":[{"side":"debit","account":"6000","amount":"3.00 USD"},{"side":"credit","account":"1000","amount":"3.00 USD"}]}"#;
    let r = call(
        &[
            "post",
            "--intent",
            "-",
            "--evidence",
            &oid,
            "--book",
            &b,
            "--json",
        ],
        None,
        Some(piped),
    );
    assert_eq!(
        (r.exit, field(&r.stdout, "event")),
        (0, Some("posted")),
        "{r:?}"
    );
    // `-` with nothing forwarded is a usage error: the daemon never reads its
    // own stdin on a client's behalf (that would hang the book's one writer).
    let r = call(
        &[
            "post",
            "--intent",
            "-",
            "--evidence",
            &oid,
            "--book",
            &b,
            "--json",
        ],
        None,
        None,
    );
    assert_eq!(r.exit, 2, "{r:?}");
    assert!(r.stdout.contains("no stdin reached the daemon"), "{r:?}");
    write(
        &dir,
        "relative.json",
        r#"{"effective_date":"2026-03-18","idempotency_key":"relative","legs":[{"side":"debit","account":"6000","amount":"4.00 USD"},{"side":"credit","account":"1000","amount":"4.00 USD"}]}"#,
    );
    let r = call(
        &[
            "post",
            "--intent",
            "relative.json",
            "--evidence",
            &oid,
            "--book",
            &b,
            "--json",
        ],
        Some(&dir),
        None,
    );
    assert_eq!(
        (r.exit, field(&r.stdout, "event")),
        (0, Some("posted")),
        "{r:?}"
    );
    // The book is a path in the client's directory too (fa-40l): a relative
    // `--book` resolves against the request's cwd, never the daemon's, and
    // answers exactly as the absolute spelling does. Checked once the daemon
    // has stopped, so a failure leaves no daemon running.
    let nested = dir.join("nested");
    std::fs::create_dir(&nested).expect("nested dir");
    let tb = |spelling: &str, cwd: Option<&Path>| {
        let r = call(
            &["tb", "--period", "FY2026-P03", "--book", spelling, "--json"],
            cwd,
            None,
        );
        (r.exit, r.stdout, r.stderr)
    };
    let absolute = tb(&b, None);
    let spelled: Vec<_> = [
        (dir.as_path(), "book"),
        (dir.as_path(), "./book"),
        (nested.as_path(), "../book"),
    ]
    .into_iter()
    .map(|(cwd, spelling)| (cwd.to_path_buf(), spelling, tb(spelling, Some(cwd))))
    .collect();
    // Without the client's cwd that relative path is in the daemon's own
    // directory, which holds no book.
    let unrooted = tb("book", None);
    // Another book's directory is not this daemon's to serve.
    let other = tmp("other");
    let r = call(
        &[
            "tb",
            "--period",
            "FY2026-P03",
            "--book",
            &other.display().to_string(),
            "--json",
        ],
        None,
        None,
    );
    assert_eq!(r.exit, 2, "{r:?}");
    assert!(r.stdout.contains("this fad serves"), "{r:?}");
    let (code, _, _) = fad(&["stop", "--book", &b, "--json"]);
    assert_eq!(code, 0);
    assert_eq!(daemon.finish().0, 0);
    assert_eq!(absolute.0, 0, "{absolute:?}");
    for (cwd, spelling, answer) in spelled {
        assert_eq!(answer, absolute, "cwd={cwd:?} book={spelling}");
    }
    assert_eq!(unrooted.0, 2, "{unrooted:?}");
    assert!(unrooted.1.contains("this fad serves"), "{unrooted:?}");
}

#[test]
fn a_killed_daemon_releases_the_lease_and_the_next_one_replaces_its_socket() {
    let dir = tmp("crash");
    let (book, _) = book(&dir);
    let b = book.display().to_string();
    let reg = registry().expect("verbs.toml");
    let mut daemon = start(&book);
    daemon.child.kill().expect("SIGKILL fad");
    let _ = daemon.child.wait();
    // The OS released the lock with the process; only a stale socket file remains.
    assert_eq!(Lease::holder(&book, &reg.daemon.lease), None);
    assert!(
        book.join(&reg.daemon.socket).exists(),
        "the crash left its socket"
    );
    let (code, status, _) = fad(&["status", "--book", &b, "--json"]);
    assert_eq!(code, 0);
    assert_eq!(field(&status, "serving"), Some("false"), "{status}");
    // `fa` takes the free lease and opens the book directly.
    let tb = ok(&["tb", "--period", "FY2026-P03", "--book", &b, "--json"]);
    assert!(tb.contains("\"credits\":\"10.00 USD\""), "{tb}");
    // The next daemon proves the socket stale (it holds the lease) and replaces it.
    let again = start(&book);
    let through = ok(&["tb", "--period", "FY2026-P03", "--book", &b, "--json"]);
    assert_eq!(through, tb);
    let (code, _, _) = fad(&["stop", "--book", &b, "--json"]);
    assert_eq!(code, 0);
    assert_eq!(again.finish().0, 0);
    assert!(
        !book.join(&reg.daemon.socket).exists(),
        "a clean stop removes its socket"
    );
}

/// Bare `fa` (plan §15.3; fa-g8em) names the book and whether a fad serves
/// it, from the lease and one status call, without opening the book: the
/// serving daemon keeps its lease and answers the next command.
#[test]
fn bare_fa_reports_whether_a_fad_serves_the_book() {
    let dir = tmp("bare");
    let (book, _) = book(&dir);
    let b = book.display().to_string();
    let daemon = start(&book);
    let served = ok(&["--book", &b, "--json"]);
    assert_eq!(field(&served, "event"), Some("triage"), "{served}");
    assert_eq!(field(&served, "daemon"), Some("serving"), "{served}");
    assert!(served.contains("a fad serves it"), "{served}");
    // The probe took nothing from the daemon: it still serves.
    let tb = ok(&["tb", "--period", "FY2026-P03", "--book", &b, "--json"]);
    assert!(tb.contains("\"credits\":\"10.00 USD\""), "{tb}");
    let (code, _, _) = fad(&["stop", "--book", &b, "--json"]);
    assert_eq!(code, 0);
    assert_eq!(daemon.finish().0, 0);
    let stopped = ok(&["--book", &b, "--json"]);
    assert_eq!(field(&stopped, "daemon"), Some("absent"), "{stopped}");
}

#[test]
fn every_daemon_event_is_emitted_and_fad_refuses_what_it_does_not_know() {
    let dir = tmp("events");
    let (book, _) = book(&dir);
    let b = book.display().to_string();
    let reg = registry().expect("verbs.toml");
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let (code, out, _) = fad(&["status", "--book", &b, "--json"]);
    assert_eq!(code, 0);
    seen.extend(checked(&out));
    let daemon = start(&book);
    seen.extend(checked(daemon.serving.trim_end()));
    let (code, out, _) = fad(&["status", "--book", &b, "--json"]);
    assert_eq!(code, 0);
    seen.extend(checked(&out));
    let request = Request {
        op: Op::Status,
        argv: vec!["--json".into()],
        cwd: None,
        stdin: None,
        token: None,
    };
    let response =
        client::call(&book.join(&reg.daemon.socket), &request, &reg.daemon).expect("fad answers");
    seen.extend(checked(&request.to_json(reg.daemon.protocol).render()));
    seen.extend(checked(&response.to_json(reg.daemon.protocol).render()));
    // fad's own usage errors follow the same contract.
    let (code, out, _) = fad(&["serv", "--book", &b, "--json"]);
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("did you mean `fad serve`?"), "{out}");
    let (code, out, _) = fad(&["serve", "--json"]);
    assert_eq!(code, 2, "{out}");
    let (code, out, _) = fad(&["stop", "--book", &b, "--json"]);
    assert_eq!(code, 0);
    seen.extend(checked(&out));
    let (exit, rest) = daemon.finish();
    assert_eq!(exit, 0);
    seen.extend(checked(&rest));
    let daemon_events: BTreeSet<String> = reg.daemon.events.iter().cloned().collect();
    assert!(
        daemon_events.is_subset(&seen),
        "not emitted: {:?}",
        daemon_events.difference(&seen).collect::<Vec<_>>()
    );
    // The schema documents the frames for agents.
    let (code, schema, _) = fa(&["robot-docs", "schema", "fad_request", "--json"]);
    assert_eq!(code, 0);
    assert!(schema.contains("\"name\":\"fad_request\""), "{schema}");
}

#[test]
fn explicit_key_bootstrap_records_ticks_and_clean_stop_releases_the_timed_book() {
    let dir = tmp("timed");
    let (book, _) = book(&dir);
    let b = book.display().to_string();
    let (code, refusal, _) = fad(&["status", "--book", &b, "--bootstrap-system", "--json"]);
    assert_eq!(code, 2, "{refusal}");
    assert!(refusal.contains("local daemon launch authority"));
    let daemon = start_with_timed_work(&book, true);
    let mut status = String::new();
    // Real process/lifecycle smoke only. Clock-drift and cancellation
    // behavior are deterministic lab scenarios in timed/tests.rs.
    for _ in 0..80 {
        let (_, observed, _) = fad(&["status", "--book", &b, "--json"]);
        status = observed;
        if field(&status, "timed_cycles")
            .and_then(|n| n.parse::<u64>().ok())
            .unwrap_or(0)
            >= 2
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let (stopped, stop_output, stop_error) = fad(&["stop", "--book", &b, "--json"]);
    let (exit, remaining) = daemon.finish();
    assert_eq!(stopped, 0, "{stop_output}\n{stop_error}");
    assert_eq!(exit, 0, "{remaining}");
    assert_eq!(
        field(&status, "timed_work_enabled"),
        Some("true"),
        "{status}"
    );
    assert_eq!(
        field(&status, "timed_authority"),
        Some("trusted-local-book-keys"),
        "{status}"
    );
    assert_eq!(
        field(&status, "last_tick_monotonic_ok"),
        Some("true"),
        "{status}"
    );
    assert_eq!(field(&status, "timed_work_error"), Some("null"), "{status}");
    // A corroborated cycle advanced the paged sweep index on the real book.
    assert_eq!(
        field(&status, "sweep_index_current"),
        Some("true"),
        "{status}"
    );
    assert_eq!(
        field(&status, "sweep_index_error"),
        Some("null"),
        "{status}"
    );
    assert_eq!(
        Lease::holder(&book, &registry().unwrap().daemon.lease),
        None
    );
    let reopened = fa::Book::open_dir(
        &book,
        fa::BookKeys::load(&book.join("book.keys")).unwrap(),
        fa::Entropy::deterministic(101),
    )
    .unwrap();
    let tick = reopened
        .latest_tick()
        .unwrap()
        .expect("daemon journaled real TimeEvidence");
    let (entry, _) = reopened.read_entry(tick.entry).unwrap().unwrap();
    assert!(matches!(
        entry.proposal.control,
        Some(fa_model::ControlPayload::TimeTick {
            source: 0,
            monotonic_ok: true,
            ..
        })
    ));
}

/// Never silent on a panic (fa-y9z): a panicking `fad` exits 5 with exactly
/// one FA-REF-153 error event, never Rust's 101. The panic is the debug
/// build's `FA_TEST_PANIC` trigger; a release build compiles it out.
#[test]
fn a_panicking_daemon_command_is_one_error_event_with_exit_5() {
    let dir = tmp("panic");
    let book = dir.join("book").display().to_string();
    let out = Command::new(env!("CARGO_BIN_EXE_fad"))
        .args(["status", "--book", &book, "--json"])
        .env_remove("FA_BOOK")
        .env("FA_TEST_PANIC", "1")
        .output()
        .expect("run fad");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(5), "{stdout}\n{stderr}");
    assert_eq!(checked(&stdout), vec!["error"], "{stdout}");
    assert!(stdout.contains("\"refusal_id\":\"FA-REF-153\""), "{stdout}");
    assert!(stdout.contains("FA_TEST_PANIC"), "{stdout}");
    assert!(stderr.contains("fad: internal error"), "{stderr}");
}

#[test]
fn concurrent_slow_client_does_not_starve_other_clients_and_unauthorized_stop_is_refused() {
    use fa_cli::wire::encode;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::time::Instant;

    let dir = tmp("concurrent");
    let (book, _) = book(&dir);
    let b = book.display().to_string();
    let reg = registry().expect("verbs.toml");
    let daemon = start(&book);
    let socket = book.join(&reg.daemon.socket);

    // Directory is 0700 and socket is 0600 (fa-een).
    let dir_mode = std::fs::metadata(&book)
        .expect("book meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        dir_mode, 0o700,
        "book directory must be 0700 (got {dir_mode:o})"
    );
    let sock_mode = std::fs::metadata(&socket)
        .expect("socket meta")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        sock_mode, 0o600,
        "daemon socket must be 0600 (got {sock_mode:o})"
    );

    // Client A connects and dribbles only 2 bytes of its 4-byte prefix, keeping its
    // connection open without completing a frame.
    let mut slow_client = StdUnixStream::connect(&socket).expect("connect slow client A");
    let req_a = Request {
        op: Op::Status,
        argv: vec!["--json".into()],
        cwd: None,
        stdin: None,
        token: None,
    };
    let frame_a = encode(
        req_a.to_json(reg.daemon.protocol).render().as_bytes(),
        reg.daemon.max_frame_bytes,
    )
    .expect("encode frame A");
    slow_client
        .write_all(&frame_a[..2])
        .expect("write partial prefix");
    slow_client.flush().expect("flush partial prefix");

    // While Client A is stalled mid-frame, Client B runs `fa tb` through fad and
    // completes within its deadline (never waiting for Client A's 30 s idle timeout).
    let start_b = Instant::now();
    let tb_out = ok(&[
        "tb",
        "--period",
        "FY2026-P03",
        "--via",
        "fad",
        "--book",
        &b,
        "--json",
    ]);
    let elapsed_b = start_b.elapsed();
    assert!(
        tb_out.contains("\"credits\":\"10.00 USD\""),
        "Client B got trial balance through fad: {tb_out}"
    );
    assert!(
        elapsed_b < std::time::Duration::from_secs(5),
        "Client B completed in {elapsed_b:?} while Client A was mid-frame"
    );

    // An unauthorized `fad stop` (missing/wrong keys or raw unauthenticated wire stop) is refused.
    let wrong_keys = write(
        &dir,
        "wrong.keys",
        "0101010101010101010101010101010101010101010101010101010101010101\n0202020202020202020202020202020202020202020202020202020202020202\n0303030303030303030303030303030303030303030303030303030303030303\n",
    );
    let (code, refused_out, _) = fad(&["stop", "--book", &b, "--keys", &wrong_keys, "--json"]);
    assert_eq!(code, 7, "unauthorized fad stop must exit 7: {refused_out}");
    assert_eq!(
        field(&refused_out, "refusal_id"),
        Some("FA-REF-011"),
        "{refused_out}"
    );
    assert!(
        refused_out.contains("stopping the daemon requires owner authority"),
        "{refused_out}"
    );

    let unauth_wire = client::call(
        &socket,
        &Request {
            op: Op::Stop,
            argv: vec!["--json".into()],
            cwd: None,
            stdin: None,
            token: None,
        },
        &reg.daemon,
    )
    .expect("fad answers unauthenticated wire stop with refusal");
    assert_eq!(unauth_wire.exit, 7, "{unauth_wire:?}");
    assert_eq!(
        field(&unauth_wire.stdout, "refusal_id"),
        Some("FA-REF-011"),
        "{}",
        unauth_wire.stdout
    );

    // The daemon is still serving after both refused stops.
    let (code, status, _) = fad(&["status", "--book", &b, "--json"]);
    assert_eq!(code, 0, "{status}");
    assert_eq!(field(&status, "serving"), Some("true"), "{status}");

    // Client A finishes its frame and receives its response.
    slow_client
        .write_all(&frame_a[2..])
        .expect("finish slow client A frame");
    slow_client.flush().expect("flush slow client A");
    let mut prefix = [0u8; 4];
    slow_client
        .read_exact(&mut prefix)
        .expect("read slow client A reply prefix");
    let len = u32::from_be_bytes(prefix) as usize;
    let mut payload = vec![0u8; len];
    slow_client
        .read_exact(&mut payload)
        .expect("read slow client A reply payload");
    let reply_str = String::from_utf8_lossy(&payload);
    let reply_json = fa_cli::json::parse(&reply_str).expect("parse slow client A reply json");
    let reply = fa_cli::wire::Response::from_json(&reply_json, reg.daemon.protocol)
        .expect("decode slow client A reply");
    assert_eq!(reply.exit, 0, "{reply:?}");
    assert!(
        reply.stdout.contains("\"serving\":true"),
        "{}",
        reply.stdout
    );
    drop(slow_client);

    // Through `fad`, `period ... --plan-out` on an existing file (including `book.keys`)
    // refuses with exit 2 and leaves the file byte-identical (fa-n8wm).
    let book_keys = book.join("book.keys");
    let keys_before = std::fs::read(&book_keys).expect("read book.keys before");
    let keys_path = book_keys.display().to_string();
    let (code, plan_err, _) = fa(&[
        "period",
        "close",
        "FY2026-P03",
        "--plan-out",
        &keys_path,
        "--via",
        "fad",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 2, "{plan_err}");
    assert_eq!(field(&plan_err, "class"), Some("usage"), "{plan_err}");
    assert!(
        plan_err.contains(&keys_path),
        "error must name {keys_path}: {plan_err}"
    );
    assert_eq!(
        std::fs::read(&book_keys).expect("read book.keys after"),
        keys_before,
        "book.keys must remain byte-identical through fad"
    );

    // Authorized owner `fad stop` succeeds and releases the lease.
    let (code, stopped, err) = fad(&["stop", "--book", &b, "--json"]);
    assert_eq!(code, 0, "{stopped}\n{err}");
    assert_eq!(field(&stopped, "event"), Some("fad_stopped"), "{stopped}");
    let (exit, rest) = daemon.finish();
    assert_eq!(exit, 0, "{rest}");
}

#[test]
fn fad_confinement_refuses_host_file_paths_without_files_root_and_rejects_escapes_symlinks_and_foreign_cwd()
 {
    let dir = tmp("confinement");
    let (book, _oid) = book(&dir);
    let b = book.display().to_string();
    let reg = registry().expect("verbs.toml");

    let outside_dir = tmp("confinement-outside");
    let secret = write(&outside_dir, "secret.txt", "TOP SECRET HOST FILE");
    let escape_out = outside_dir.join("escaped.out");

    // 1. Without `--files-root`, `fad serve` refuses host file reads and writes over the socket
    //    with a fix hint naming `-` (stdin) and `--files-root` (`fa-udti`).
    let inside_doc = write(&dir, "inside.txt", "INSIDE DOC");
    let daemon_no_root = start_without_files_root(&book);
    let (code, err_out, _) = fa(&[
        "document",
        "add",
        &inside_doc,
        "--kind",
        "Invoice",
        "--via",
        "fad",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 2, "{err_out}");
    assert!(
        err_out.contains("--files-root"),
        "must name --files-root when omitted: {err_out}"
    );
    assert!(
        err_out.contains("stdin with -"),
        "must name stdin (-): {err_out}"
    );

    // Non-file commands (and stdin `-`) still succeed without `--files-root`.
    let (code, tb_out, _) = fa(&[
        "tb",
        "--period",
        "FY2026-P03",
        "--via",
        "fad",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 0, "{tb_out}");

    let (code, stopped, _) = fad(&["stop", "--book", &b, "--json"]);
    assert_eq!(code, 0, "{stopped}");
    let (exit, _) = daemon_no_root.finish();
    assert_eq!(exit, 0);

    // 2. With `--files-root <dir>`, reading `/etc/passwd` (or `secret`), writing `../escape`,
    //    reading/writing through a symlink pointing outside `--files-root`, or sending a
    //    hostile `request.cwd` (`Some("/etc")`) are all refused before touching the target.
    let symlink_in = dir.join("symlink_to_secret.txt");
    std::os::unix::fs::symlink(&secret, &symlink_in).expect("create input symlink");
    let symlink_out_dir = dir.join("symlink_out_dir");
    std::os::unix::fs::symlink(&outside_dir, &symlink_out_dir).expect("create output dir symlink");

    let daemon = start(&book);
    let head_before = ok(&["book", "info", "--via", "fad", "--book", &b, "--json"]);

    // Attempt to read `/etc/passwd` and `secret` outside `--files-root`.
    for outside_target in ["/etc/passwd", secret.as_str()] {
        let (code, out, _) = fa(&[
            "document",
            "add",
            outside_target,
            "--kind",
            "Invoice",
            "--via",
            "fad",
            "--book",
            &b,
            "--json",
        ]);
        assert_eq!(code, 2, "must refuse {outside_target}: {out}");
        assert!(out.contains("--files-root"), "{out}");
    }

    // Every argument that reads a host file is confined, including an
    // account, party, instrument or entity object and a correction pair's
    // replacement intent (fa-ohe). Before, these five read any path the
    // daemon's user could read and were refused only afterwards, if at all.
    let outside_object = write(&outside_dir, "object.json", "{}");
    for argv in [
        vec![
            "chart",
            "open",
            outside_object.as_str(),
            "--opened",
            "2026-03-01",
        ],
        vec!["party", "add", outside_object.as_str()],
        vec!["instrument", "add", outside_object.as_str()],
        vec!["entity", "add", outside_object.as_str()],
        vec![
            "reverse",
            "00000000000000000000000000000001",
            "--reason",
            "WrongAmount",
            "--replace-with",
            outside_object.as_str(),
        ],
    ] {
        let mut argv = argv;
        argv.extend(["--via", "fad", "--book", b.as_str(), "--json"]);
        let (code, out, _) = fa(&argv);
        assert_eq!(code, 2, "must refuse {argv:?}: {out}");
        assert!(
            out.contains("outside the daemon --files-root"),
            "{argv:?}: {out}"
        );
    }

    // Attempt to write `--certificate-out ../escaped.cert`.
    let (code, out, _) = fa(&[
        "tb",
        "--period",
        "FY2026-P03",
        "--certificate-out",
        "../escaped.cert",
        "--via",
        "fad",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 2, "must refuse ../ traversal: {out}");
    assert!(out.contains(".."), "{out}");
    assert!(!dir.join("../escaped.cert").exists());

    // Attempt to read through a symlink inside `--files-root` pointing outside.
    let (code, out, _) = fa(&[
        "document",
        "add",
        &symlink_in.display().to_string(),
        "--kind",
        "Invoice",
        "--via",
        "fad",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 2, "must refuse symlink input: {out}");
    assert!(out.contains("symlink"), "{out}");

    // Attempt to write through a symlinked directory inside `--files-root` pointing outside.
    let symlink_escape_file = symlink_out_dir.join("pwned.cert");
    let (code, out, _) = fa(&[
        "tb",
        "--period",
        "FY2026-P03",
        "--certificate-out",
        &symlink_escape_file.display().to_string(),
        "--via",
        "fad",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 2, "must refuse symlink dir output: {out}");
    assert!(out.contains("symlink"), "{out}");
    assert!(!escape_out.exists() && !outside_dir.join("pwned.cert").exists());

    // Attempt to pass a hostile `request.cwd` (`Some("/etc")` or `Some(outside_dir)`) over the socket
    // with a relative filename (`secret.txt`).
    use std::io::Write;
    let sock_path = book.join(&reg.daemon.socket);
    let mut raw_client =
        std::os::unix::net::UnixStream::connect(&sock_path).expect("connect raw socket");
    let hostile_req = fa_cli::wire::Request {
        op: fa_cli::wire::Op::Run,
        argv: vec![
            "document".into(),
            "add".into(),
            "secret.txt".into(),
            "--kind".into(),
            "Invoice".into(),
            format!("--book={b}"),
            "--json".into(),
        ],
        cwd: Some(outside_dir.display().to_string()),
        stdin: None,
        token: None,
    };
    let wire_bytes = fa_cli::wire::encode(
        hostile_req.to_json(reg.daemon.protocol).render().as_bytes(),
        reg.daemon.max_frame_bytes,
    )
    .expect("encode hostile request");
    raw_client
        .write_all(&wire_bytes)
        .expect("write hostile request");
    raw_client.flush().expect("flush hostile request");
    let mut prefix = [0u8; 4];
    raw_client
        .read_exact(&mut prefix)
        .expect("read reply prefix");
    let len = u32::from_be_bytes(prefix) as usize;
    let mut payload = vec![0u8; len];
    raw_client
        .read_exact(&mut payload)
        .expect("read reply payload");
    let reply_json = fa_cli::json::parse(&String::from_utf8_lossy(&payload)).expect("parse reply");
    let reply = fa_cli::wire::Response::from_json(&reply_json, reg.daemon.protocol).unwrap();
    assert_eq!(
        reply.exit, 2,
        "hostile request.cwd must be refused: {}",
        reply.stdout
    );
    assert!(reply.stdout.contains("--files-root"), "{}", reply.stdout);
    drop(raw_client);

    // Book frontier is unchanged after all refused escape attempts.
    let head_after = ok(&["book", "info", "--via", "fad", "--book", &b, "--json"]);
    assert_eq!(head_before, head_after, "book state must remain unchanged");

    // Valid file inside `--files-root` succeeds.
    let valid_added = ok(&[
        "document",
        "add",
        &inside_doc,
        "--kind",
        "Invoice",
        "--via",
        "fad",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(field(&valid_added, "event"), Some("document"));

    let (code, stopped, _) = fad(&["stop", "--book", &b, "--json"]);
    assert_eq!(code, 0, "{stopped}");
    let (exit, _) = daemon.finish();
    assert_eq!(exit, 0);
}

/// fa-r3q: `fa --token <file>` sessions through a running fad. Two holders
/// with their own issued Agent tokens work through one daemon; each request
/// is bound to its token's principal and journaled capability (the envelope
/// says `issued-token`; each draft is its holder's). `--as` beside a token
/// is refused, a tampered token never reaches the book, and a token revoked
/// mid-session is refused at its next write (FA-REF-023).
#[test]
fn token_sessions_through_fad_bind_each_request_to_its_holder() {
    let dir = tmp("token-sessions");
    let (book, oid) = book(&dir);
    let b = book.display().to_string();
    let mut tokens = Vec::new();
    for holder in ["agent-a", "agent-b"] {
        let path = dir.join(format!("{holder}.token")).display().to_string();
        let issued = ok(&[
            "capability",
            "issue",
            "--holder",
            holder,
            "--profile",
            "agent",
            "--op",
            "read",
            "--op",
            "post",
            "--out",
            &path,
            "--grant",
            "issue_capability",
            "--grant",
            "read",
            "--grant",
            "post",
            "--book",
            &b,
            "--json",
        ]);
        let commitment = field(&issued, "commitment").unwrap_or_default().to_string();
        tokens.push((holder, path, commitment));
    }
    let mut prep_tokens = Vec::new();
    for holder in ["prep-a", "prep-b"] {
        let path = dir.join(format!("{holder}.token")).display().to_string();
        ok(&[
            "capability",
            "issue",
            "--holder",
            holder,
            "--profile",
            "preparer",
            "--out",
            &path,
            "--grant",
            "issue_capability",
            "--grant",
            "read",
            "--grant",
            "post",
            "--grant",
            "verify",
            "--book",
            &b,
            "--json",
        ]);
        prep_tokens.push((holder, path));
    }
    let daemon = start(&book);
    // Token sessions name host files relative to the daemon's --files-root.
    write(
        &dir,
        "draft-rent.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"token-rent","legs":[{"side":"debit","account":"6000","amount":"3.00 USD"},{"side":"credit","account":"1000","amount":"3.00 USD"}]}"#,
    );
    for (holder, token, _) in &tokens {
        let draft = format!("{holder}-draft");
        let opened = ok(&[
            "--token", token, "draft", "new", &draft, "--book", &b, "--json",
        ]);
        assert!(opened.contains("\"posture\":\"issued-token\""), "{opened}");
        assert!(
            opened.contains(&format!("\"principal\":\"{holder}\"")),
            "{opened}"
        );
        let planned = ok(&[
            "--token",
            token,
            "post",
            "--intent",
            "draft-rent.json",
            "--evidence",
            &oid,
            "--draft",
            &draft,
            "--book",
            &b,
            "--json",
        ]);
        assert_eq!(field(&planned, "event"), Some("draft_planned"), "{planned}");
        // An Agent token never posts to trunk, through fad or not.
        let (code, out, _) = fa(&[
            "--token",
            token,
            "post",
            "--intent",
            "draft-rent.json",
            "--evidence",
            &oid,
            "--book",
            &b,
            "--json",
        ]);
        assert_eq!(code, 7, "{out}");
        assert!(out.contains("FA-REF-013"), "{out}");
    }
    // Each draft is its holder's: one holder cannot plan into the other's.
    let (code, out, _) = fa(&[
        "--token",
        &tokens[0].1,
        "post",
        "--intent",
        "draft-rent.json",
        "--evidence",
        &oid,
        "--draft",
        "agent-b-draft",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 7, "{out}");
    assert!(out.contains("FA-REF-011"), "{out}");
    // Identity flags beside a token, and a tampered token, are refused.
    let (code, out, _) = fa(&[
        "--token",
        &tokens[0].1,
        "--as",
        "controller",
        "draft",
        "list",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 2, "{out}");
    let mut tampered = std::fs::read(&tokens[0].1).unwrap();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let bad = dir.join("tampered.token");
    std::fs::write(&bad, &tampered).unwrap();
    let (code, out, _) = fa(&[
        "--token",
        &bad.display().to_string(),
        "draft",
        "list",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 2, "{out}");
    // Revoked mid-session (by the owner, through the same daemon).
    ok(&[
        "capability",
        "revoke",
        "--commitment",
        &tokens[1].2,
        "--grant",
        "issue_capability",
        "--yes",
        "--book",
        &b,
        "--json",
    ]);
    let (code, out, _) = fa(&[
        "--token",
        &tokens[1].1,
        "draft",
        "new",
        "after-revocation",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 7, "{out}");
    assert!(out.contains("FA-REF-023"), "{out}");
    // The owner sees both drafts, each owned by its holder.
    let drafts = ok(&["draft", "list", "--book", &b, "--json"]);
    assert!(
        drafts.contains("agent-a-draft") && drafts.contains("agent-b-draft"),
        "{drafts}"
    );

    // `--as <principal>` on the daemon path without a token is refused with FA-REF-011 (exit 7).
    let (code, out, _) = fa(&[
        "--as",
        "controller",
        "tb",
        "--period",
        "FY2026-P03",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 7, "{out}");
    assert!(out.contains("FA-REF-011"), "{out}");
    assert!(
        out.contains("present a token: fa capability issue --holder <principal> --out <file>"),
        "{out}"
    );

    // Both Preparers post to trunk through fad: prep-a via `--token`, prep-b via `FA_TOKEN` fallback.
    write(
        &dir,
        "prep-a-post.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"prep-a-trunk","legs":[{"side":"debit","account":"6000","amount":"4.00 USD"},{"side":"credit","account":"1000","amount":"4.00 USD"}]}"#,
    );
    write(
        &dir,
        "prep-b-post.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"prep-b-trunk","legs":[{"side":"debit","account":"6000","amount":"5.00 USD"},{"side":"credit","account":"1000","amount":"5.00 USD"}]}"#,
    );
    let posted_a = ok(&[
        "--token",
        &prep_tokens[0].1,
        "post",
        "--intent",
        "prep-a-post.json",
        "--evidence",
        &oid,
        "--book",
        &b,
        "--json",
    ]);
    assert!(posted_a.contains("\"principal\":\"prep-a\""), "{posted_a}");
    let entry_a = field(&posted_a, "vid").unwrap_or_default().to_string();
    let argv_b: Vec<String> = [
        "post",
        "--intent",
        "prep-b-post.json",
        "--evidence",
        &oid,
        "--book",
        &b,
        "--json",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    let (code_b, out_b) = fa_cli::entry::fa_with_env_token(
        &argv_b,
        Some(&prep_tokens[1].1),
        fa_cli::cli::Files::default(),
        true,
    );
    assert_eq!(code_b, 0, "{}\n{}", out_b.stdout, out_b.stderr);
    checked(&out_b.stdout);
    assert!(
        out_b.stdout.contains("\"principal\":\"prep-b\""),
        "{}",
        out_b.stdout
    );
    let entry_b = field(&out_b.stdout, "vid").unwrap_or_default().to_string();

    // Provenance & SoD across sessions through fad:
    // 1) agent-a uploads a document through fad -> graded AgentUpload automatically (retrieved_by = agent-a).
    // 2) prep-a attempts to post to trunk citing the unreviewed AgentUpload -> refused (FA-REF-012).
    // 3) operator (a distinct principal from agent-a) reviews agent-a's upload through fad -> succeeds,
    //    whereas operator reviewing its own AgentUpload is refused by SoD (FA-REF-111).
    // 4) prep-a now posts to trunk citing the reviewed document -> succeeds.
    write(&dir, "agent-invoice.txt", "Agent-uploaded invoice 6.00 USD");
    let uploaded = ok(&[
        "--token",
        &tokens[0].1,
        "document",
        "add",
        "agent-invoice.txt",
        "--kind",
        "Invoice",
        "--book",
        &b,
        "--json",
    ]);
    assert!(uploaded.contains("\"grade\":\"AgentUpload\""), "{uploaded}");
    let agent_doc_oid = field(&uploaded, "oid").unwrap_or_default().to_string();
    write(
        &dir,
        "prep-a-agent-doc.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"prep-a-agent-doc","legs":[{"side":"debit","account":"6000","amount":"6.00 USD"},{"side":"credit","account":"1000","amount":"6.00 USD"}]}"#,
    );
    let (code, out, _) = fa(&[
        "--token",
        &prep_tokens[0].1,
        "post",
        "--intent",
        "prep-a-agent-doc.json",
        "--evidence",
        &agent_doc_oid,
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 3, "unreviewed AgentUpload must be refused: {out}");
    assert!(out.contains("FA-REF-086"), "{out}");

    write(&dir, "op-self.txt", "Operator self-uploaded schedule");
    let op_uploaded = ok(&[
        "document",
        "add",
        "op-self.txt",
        "--kind",
        "Invoice",
        "--grade",
        "AgentUpload",
        "--book",
        &b,
        "--json",
    ]);
    let op_doc_oid = field(&op_uploaded, "oid").unwrap_or_default().to_string();
    let (code, out, _) = fa(&[
        "document",
        "attest",
        "review",
        &op_doc_oid,
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 7, "self-review must be refused by SoD: {out}");
    assert!(out.contains("FA-REF-111"), "{out}");

    let reviewed = ok(&[
        "document",
        "attest",
        "review",
        &agent_doc_oid,
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(
        field(&reviewed, "event"),
        Some("attestation_recorded"),
        "{reviewed}"
    );
    let posted_after_review = ok(&[
        "--token",
        &prep_tokens[0].1,
        "post",
        "--intent",
        "prep-a-agent-doc.json",
        "--evidence",
        &agent_doc_oid,
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(
        field(&posted_after_review, "event"),
        Some("posted"),
        "{posted_after_review}"
    );

    // A valid token issued in another book is refused by fad with FA-REF-156 (exit 7).
    let other_dir = tmp("other-book");
    let (other_book, _) = self::book(&other_dir);
    let other_b = other_book.display().to_string();
    let foreign_token = dir.join("foreign.token").display().to_string();
    ok(&[
        "capability",
        "issue",
        "--holder",
        "prep-a",
        "--profile",
        "preparer",
        "--out",
        &foreign_token,
        "--grant",
        "issue_capability",
        "--grant",
        "read",
        "--grant",
        "post",
        "--grant",
        "verify",
        "--book",
        &other_b,
        "--json",
    ]);
    let (code, out, _) = fa(&[
        "--token",
        &foreign_token,
        "tb",
        "--period",
        "FY2026-P03",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 7, "{out}");
    assert!(out.contains("FA-REF-156"), "{out}");

    // Per-connection session token binding over the live Unix socket:
    // Frame 1 binds prep-a; Frame 2 with token=None inherits prep-a; Frame 3 with prep-b is refused FA-REF-011.
    {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let reg = registry().expect("verbs.toml");
        let socket = book.join(&reg.daemon.socket);
        let tok_a_bytes = std::fs::read(&prep_tokens[0].1).unwrap();
        let tok_b_bytes = std::fs::read(&prep_tokens[1].1).unwrap();
        let req1 = Request {
            op: Op::Run,
            argv: vec![
                "--period=FY2026-P03".into(),
                "--json".into(),
                "--".into(),
                "tb".into(),
            ],
            cwd: None,
            stdin: None,
            token: Some(tok_a_bytes),
        };
        let req2 = Request {
            op: Op::Run,
            argv: vec![
                "--period=FY2026-P03".into(),
                "--json".into(),
                "--".into(),
                "tb".into(),
            ],
            cwd: None,
            stdin: None,
            token: None,
        };
        let req3 = Request {
            op: Op::Run,
            argv: vec![
                "--period=FY2026-P03".into(),
                "--json".into(),
                "--".into(),
                "tb".into(),
            ],
            cwd: None,
            stdin: None,
            token: Some(tok_b_bytes),
        };
        let mut stream = UnixStream::connect(&socket).expect("connect to fad");
        for req in [&req1, &req2, &req3] {
            let encoded = fa_cli::wire::encode(
                req.to_json(1).render().as_bytes(),
                reg.daemon.max_frame_bytes,
            )
            .unwrap();
            stream.write_all(&encoded).unwrap();
        }
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).unwrap();
        let mut dec = fa_cli::wire::Decoder::new(reg.daemon.max_frame_bytes);
        dec.push(&raw);
        let mut replies = Vec::new();
        while let Ok(Some(frame)) = dec.next_frame() {
            let v = fa_cli::wire::canonical(&frame).unwrap();
            replies.push(fa_cli::wire::Response::from_json(&v, 1).unwrap());
        }
        assert_eq!(replies.len(), 3);
        assert_eq!(replies[0].exit, 0, "{}", replies[0].stdout);
        assert!(
            replies[0].stdout.contains("\"principal\":\"prep-a\""),
            "{}",
            replies[0].stdout
        );
        assert_eq!(replies[1].exit, 0, "{}", replies[1].stdout);
        assert!(
            replies[1].stdout.contains("\"principal\":\"prep-a\""),
            "subsequent frame on same connection inherits bound token: {}",
            replies[1].stdout
        );
        assert_eq!(replies[2].exit, 7, "{}", replies[2].stdout);
        assert!(
            replies[2].stdout.contains("FA-REF-011"),
            "{}",
            replies[2].stdout
        );
    }

    let (code, stopped, err) = fad(&["stop", "--book", &b, "--json"]);
    assert_eq!(code, 0, "{stopped}\n{err}");
    let (exit, rest) = daemon.finish();
    assert_eq!(exit, 0, "{rest}");

    // Verify journal attribution in the committed entries on disk: each token's holder is recorded as preparer.
    let keys = fa::book::BookKeys::load(&book.join("book.keys")).expect("load keys");
    let reopened =
        fa::book::Book::open_dir(&book, keys, fa::book::Entropy::production()).expect("open book");
    let vid_a = fgdb_types::VId(u128::from_str_radix(&entry_a, 16).expect("entry_a vid"));
    let vid_b = fgdb_types::VId(u128::from_str_radix(&entry_b, 16).expect("entry_b vid"));
    let (committed_a, _) = reopened
        .read_entry(vid_a)
        .expect("read_entry a")
        .expect("entry a");
    let (committed_b, _) = reopened
        .read_entry(vid_b)
        .expect("read_entry b")
        .expect("entry b");
    assert_eq!(
        committed_a.proposal.principal_ref,
        fa_model::principal_vid("prep-a")
    );
    assert_eq!(
        committed_b.proposal.principal_ref,
        fa_model::principal_vid("prep-b")
    );
}

/// fa-r3q / fa-yok: the same-uid compatibility route may still use the
/// embedded-owner posture, but a socket caller cannot widen that posture with
/// an unverified per-request grant. Authority elevation goes through an issued
/// token; ordinary untokened reads remain available until token-required
/// handshake compatibility is retired separately.
#[test]
fn untokened_fad_requests_cannot_self_grant_authority() {
    let dir = tmp("untokened-grant");
    let (book, _) = book(&dir);
    let b = book.display().to_string();
    let daemon = start(&book);

    let (code, out, err) = fa(&[
        "book",
        "info",
        "--grant",
        "privileged",
        "--via",
        "fad",
        "--book",
        &b,
        "--json",
    ]);
    assert_eq!(code, 7, "{out}\n{err}");
    assert_eq!(field(&out, "refusal_id"), Some("FA-REF-011"), "{out}");
    assert!(
        out.contains("`--grant` is not admitted on the daemon path"),
        "{out}"
    );
    assert!(out.contains("capability token"), "{out}");

    // Only revocation may add a grant here, and only issue_capability
    // (fa-b295): issuing a capability, or revoking with any other op, is
    // still a self-grant.
    let token = dir.join("escalated.token").display().to_string();
    for argv in [
        &[
            "capability",
            "issue",
            "--holder",
            "intruder",
            "--profile",
            "preparer",
            "--out",
            &token,
            "--grant",
            "issue_capability",
        ][..],
        &[
            "capability",
            "revoke",
            "--commitment",
            &"00".repeat(32),
            "--grant",
            "issue_capability",
            "--grant",
            "privileged",
            "--yes",
        ][..],
    ] {
        let mut argv = argv.to_vec();
        argv.extend(["--via", "fad", "--book", &b, "--json"]);
        let (code, out, err) = fa(&argv);
        assert_eq!(code, 7, "{argv:?}\n{out}\n{err}");
        assert_eq!(field(&out, "refusal_id"), Some("FA-REF-011"), "{out}");
        assert!(out.contains("`--grant` is not admitted"), "{out}");
    }
    assert!(!dir.join("escalated.token").exists());

    // The refusal is about caller-selected authority, not about disabling the
    // compatibility route wholesale: the same read without a grant still runs.
    let (code, allowed, err) = fa(&["book", "info", "--via", "fad", "--book", &b, "--json"]);
    assert_eq!(code, 0, "{allowed}\n{err}");
    assert_eq!(field(&allowed, "event"), Some("book"), "{allowed}");

    let (code, stopped, err) = fad(&["stop", "--book", &b, "--json"]);
    assert_eq!(code, 0, "{stopped}\n{err}");
    assert_eq!(daemon.finish().0, 0);
}
