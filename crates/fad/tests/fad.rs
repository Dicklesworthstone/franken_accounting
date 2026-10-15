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
        let d = std::env::temp_dir().join(format!("fad-{}-{name}-{n}", std::process::id()));
        if std::fs::create_dir(&d).is_ok() {
            return d.canonicalize().unwrap_or(d);
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
    let book = dir.join("book");
    let b = book.display().to_string();
    ok(&[
        "book",
        "create",
        "--book",
        &b,
        "--name",
        "Daemon Co",
        "--json",
    ]);
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

fn start_with_timed_work(book: &Path, bootstrap: bool) -> Daemon {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fad"));
    command.args(["serve", "--book", &book.display().to_string(), "--json"]);
    if bootstrap {
        command.arg("--bootstrap-system");
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
