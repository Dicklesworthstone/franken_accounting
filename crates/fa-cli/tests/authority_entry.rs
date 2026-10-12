//! The launch-bound front door never turns request text into authority or
//! downgrades that authority through the unauthenticated daemon protocol.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::{Captured, Files, Stdin};
use fa_cli::entry::fa_with_authority;
use fa_cli::json::{self, Json};
use fa_cli::lease::Lease;
use fa_cli::verbs::registry;

fn fixture(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fa-authority-entry-{}-{name}-{id}",
            std::process::id()
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
}

fn authority(book: PathBuf) -> LaunchAuthority {
    LaunchAuthority::new(book, None, "agent-7", LaunchProfile::Agent, &[])
        .expect("bounded launch authority")
}

fn run(authority: &LaunchAuthority, argv: &[&str]) -> (u8, Captured) {
    let argv: Vec<String> = argv.iter().map(|value| (*value).to_string()).collect();
    fa_with_authority(
        &argv,
        Files {
            cwd: None,
            stdin: Stdin::Missing,
        },
        authority,
        true,
    )
}

fn line(out: &Captured) -> Json {
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{out:?}");
    registry()
        .expect("verbs.toml")
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("{error}\n{out:?}"));
    let line = json::parse(lines[0]).expect("robot JSON");
    let authority = line
        .get("authority")
        .expect("every bound event has authority");
    assert_eq!(
        authority.get("posture").and_then(Json::as_str),
        Some("mcp-launch-config"),
        "{out:?}"
    );
    assert_eq!(
        authority.get("principal").and_then(Json::as_str),
        Some("agent-7"),
        "{out:?}"
    );
    line
}

#[test]
fn request_authority_overrides_are_refused_before_the_book_is_observed() {
    let book = fixture("overrides").join("missing-book");
    let authority = authority(book.clone());
    for (flag, value) in [
        ("--as", "controller"),
        ("--grant", "approve"),
        ("--book", "/another/book"),
        ("--keys", "/another/keys"),
        ("--via", "fad"),
        ("--principal", "controller"),
        ("--profile", "preparer"),
    ] {
        let equal = format!("{flag}={value}");
        for argv in [
            vec!["capabilities", flag, value, "--json"],
            vec!["capabilities", equal.as_str(), "--json"],
        ] {
            let (exit, out) = run(&authority, &argv);
            assert_eq!(exit, 2, "argv={argv:?}\n{out:?}");
            let line = line(&out);
            assert_eq!(line.get("event").and_then(Json::as_str), Some("error"));
            assert!(
                line.get("data")
                    .and_then(|data| data.get("message"))
                    .and_then(Json::as_str)
                    .is_some_and(|message| message.contains(flag)),
                "argv={argv:?}\n{out:?}"
            );
        }
    }
    let (exit, out) = run(&authority, &["capabilities", "--yes", "--json"]);
    assert_eq!(exit, 2, "{out:?}");
    assert_eq!(
        line(&out).get("event").and_then(Json::as_str),
        Some("error")
    );
    assert!(!book.exists(), "rejected requests must not create a book");
}

#[test]
fn discovery_and_parser_failures_preserve_authority_without_a_book() {
    let authority = authority(fixture("discovery").join("missing-book"));
    for argv in [
        vec!["capabilities", "--json"],
        vec!["robot-docs", "exit-codes", "--json"],
        vec!["--help", "--json"],
        vec!["--version", "--json"],
    ] {
        let (exit, out) = run(&authority, &argv);
        assert_eq!(exit, 0, "argv={argv:?}\n{out:?}");
        assert_ne!(
            line(&out).get("event").and_then(Json::as_str),
            Some("error")
        );
    }
    let (exit, out) = run(&authority, &["tb", "--unknown-flag", "--json"]);
    assert_eq!(exit, 2, "{out:?}");
    assert_eq!(
        line(&out).get("event").and_then(Json::as_str),
        Some("error")
    );
}

#[test]
fn planning_and_plan_commit_cannot_add_post_to_a_read_only_launch() {
    let book = fixture("read-only-plans");
    let authority = LaunchAuthority::new(book, None, "agent-7", LaunchProfile::Preparer, &["read"])
        .expect("read-only launch");
    for argv in [
        vec![
            "post",
            "--intent",
            "unread-entry.json",
            "--dry-run",
            "--json",
        ],
        vec!["commit", "--plan", "unread-plan.bin", "--json"],
    ] {
        let (exit, out) = run(&authority, &argv);
        assert_eq!(exit, 7, "argv={argv:?}\n{out:?}");
        let line = line(&out);
        assert_eq!(line.get("book"), Some(&Json::Null));
        assert_eq!(line.get("coordinate"), Some(&Json::Null));
        assert_eq!(
            line.get("data")
                .and_then(|data| data.get("refusal_id"))
                .and_then(Json::as_str),
            Some("FA-REF-011"),
            "authority must refuse before reading the absent input: {out:?}",
        );
    }
}

#[test]
fn a_missing_lease_directory_is_not_an_unleased_execution_fallback() {
    let book = fixture("missing-lease").join("missing-book");
    let authority = authority(book.clone());
    // `--as` is the value of --period, not an identity override. The parsed
    // request reaches lease admission, which must fail closed before open.
    let (exit, out) = run(&authority, &["tb", "--period", "--as", "--json"]);
    assert_eq!(exit, 4, "{out:?}");
    let line = line(&out);
    assert!(
        line.get("data")
            .and_then(|data| data.get("message"))
            .and_then(Json::as_str)
            .is_some_and(|message| message.contains("writer lease")),
        "{out:?}"
    );
    assert!(!book.exists());
}

#[cfg(unix)]
#[test]
fn a_held_lease_never_forwards_bound_authority_to_a_listening_daemon() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    let book = fixture("held");
    let authority = authority(book.clone());
    let daemon = &registry().expect("verbs.toml").daemon;
    let _lease = Lease::acquire(&book, &daemon.lease, "another writer").expect("lease");
    let listener = UnixListener::bind(book.join(&daemon.socket)).expect("daemon socket");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let finished = Arc::new(AtomicBool::new(false));
    let worker_finished = Arc::clone(&finished);
    let protocol = daemon.protocol;
    let max_frame_bytes = daemon.max_frame_bytes;
    // A joined responder prevents an accidental daemon fallback from hanging
    // the regression test; any connection is itself a containment failure.
    let responder = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !worker_finished.load(Ordering::Acquire) && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .expect("read timeout");
                    stream
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .expect("write timeout");
                    let mut prefix = [0; fa_cli::wire::PREFIX_BYTES];
                    stream.read_exact(&mut prefix).expect("request prefix");
                    let len =
                        fa_cli::wire::announced(prefix, max_frame_bytes).expect("bounded request");
                    let mut payload = vec![0; len];
                    stream.read_exact(&mut payload).expect("request payload");
                    let response = fa_cli::wire::Response {
                        op: fa_cli::wire::Op::Run,
                        exit: 0,
                        stdout: "unexpected daemon execution\n".into(),
                        stderr: String::new(),
                    }
                    .to_json(protocol)
                    .render();
                    let frame = fa_cli::wire::encode(response.as_bytes(), max_frame_bytes)
                        .expect("response frame");
                    stream.write_all(&frame).expect("response");
                    return true;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("accept daemon request: {error}"),
            }
        }
        false
    });
    let (exit, out) = run(&authority, &["tb", "--period", "P", "--json"]);
    finished.store(true, Ordering::Release);
    let contacted_daemon = responder.join().expect("joined daemon responder");
    assert!(
        !contacted_daemon,
        "bound authority crossed an unauthenticated transport"
    );
    assert_eq!(exit, 6, "{out:?}");
    let line = line(&out);
    let data = line.get("data").expect("error data");
    assert_eq!(
        data.get("refusal_id").and_then(Json::as_str),
        Some("FA-REF-018")
    );
    assert!(
        data.get("fix")
            .and_then(Json::as_str)
            .is_some_and(|fix| fix.contains("authenticated daemon sessions")),
        "{out:?}"
    );
}
