//! Real Unix-socket transport probes, without substituting a second dispatcher.
//! These tests check request/response fidelity, not native posting admission.
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use fa_cli::args;
use fa_cli::cli::{Files, Stdin};
use fa_cli::entry::fa_with;
use fa_cli::verbs;
use fa_cli::wire::{self, Op, Request, Response};
use fa_journal::exit;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn socket_peer() -> (PathBuf, thread::JoinHandle<Request>) {
    let dir = std::env::temp_dir().join(format!(
        "fa-route-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::create_dir(&dir).unwrap();
    let daemon = verbs::registry().unwrap().daemon.clone();
    let listener = UnixListener::bind(dir.join(&daemon.socket)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let peer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "client never sent a request");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut prefix = [0_u8; wire::PREFIX_BYTES];
        stream.read_exact(&mut prefix).unwrap();
        let size = wire::announced(prefix, daemon.max_frame_bytes).unwrap();
        let mut payload = vec![0; size];
        stream.read_exact(&mut payload).unwrap();
        let request =
            Request::from_json(&wire::canonical(&payload).unwrap(), daemon.protocol).unwrap();
        let response = Response {
            op: Op::Run,
            exit: exit::CONFLICT,
            stdout: "unchanged daemon output\n".into(),
            stderr: "unchanged diagnostic\n".into(),
        };
        let json = response.to_json(daemon.protocol).render();
        stream
            .write_all(&wire::encode(json.as_bytes(), daemon.max_frame_bytes).unwrap())
            .unwrap();
        stream.flush().unwrap();
        request
    });
    (dir, peer)
}

fn roundtrip(words: &[&str], files: Files) -> (PathBuf, Request) {
    let (dir, peer) = socket_peer();
    // Put transport flags before the user's possible terminator.
    let mut argv = vec!["--via=fad".into(), format!("--book={}", dir.display())];
    argv.extend(words.iter().map(|word| (*word).to_string()));
    let (status, output) = fa_with(&argv, files, true);
    let request = peer.join().unwrap();
    assert_eq!(status, exit::CONFLICT, "{}{}", output.stdout, output.stderr);
    assert_eq!(output.stdout, "unchanged daemon output\n");
    assert_eq!(output.stderr, "unchanged diagnostic\n");
    assert_eq!(request.op, Op::Run);
    let reg = verbs::registry().unwrap();
    let parsed = args::parse(&request.argv, &reg.value_flags(), &reg.switches()).unwrap();
    assert_eq!(parsed.flag_all("--book"), vec![dir.to_str().unwrap()]);
    assert!(parsed.flag_all("--via").is_empty());
    (dir, request)
}

#[test]
fn inline_and_separate_plan_stdin_cross_the_actual_client_socket_unchanged() {
    // Opaque binary transport fixture, not a claim of a valid PostPlan.
    let bytes = vec![0, 255, b'F', b'A', 13, 10, 0, 128];
    for words in [vec!["commit", "--plan=-"], vec!["commit", "--plan", "-"]] {
        let (_, request) = roundtrip(
            &words,
            Files {
                cwd: None,
                stdin: Stdin::Forwarded(bytes.clone()),
            },
        );
        assert_eq!(request.stdin, Some(bytes.clone()));
        assert_eq!(
            Path::new(request.cwd.as_deref().unwrap()),
            std::env::current_dir().unwrap()
        );
        let reg = verbs::registry().unwrap();
        let parsed = args::parse(&request.argv, &reg.value_flags(), &reg.switches()).unwrap();
        assert_eq!(parsed.positional, vec!["commit"]);
        assert_eq!(parsed.flag_all("--plan"), vec!["-"]);
    }
}

#[test]
fn daemon_request_preserves_flag_looking_values_and_literal_positionals() {
    let (_, request) = roundtrip(
        &[
            "reverse",
            "entry",
            "--description",
            "--book",
            "--key=--via=fad",
            "--grant=read",
            "--grant=post_closed",
            "--",
            "--book",
            "other",
            "--via=fad",
        ],
        Files {
            cwd: Some("relative-client".into()),
            stdin: Stdin::Missing,
        },
    );
    let reg = verbs::registry().unwrap();
    let parsed = args::parse(&request.argv, &reg.value_flags(), &reg.switches()).unwrap();
    assert_eq!(parsed.flag("--description"), Some("--book"));
    assert_eq!(parsed.flag("--key"), Some("--via=fad"));
    assert_eq!(parsed.flag_all("--grant"), vec!["read", "post_closed"]);
    assert_eq!(
        parsed.positional,
        vec!["reverse", "entry", "--book", "other", "--via=fad"]
    );
    assert_eq!(
        PathBuf::from(request.cwd.unwrap()),
        std::env::current_dir().unwrap().join("relative-client")
    );
    assert_eq!(request.stdin, None);
}

#[test]
fn a_read_without_stdin_does_not_send_unrelated_forwarded_bytes() {
    let (_, request) = roundtrip(
        &["book", "info"],
        Files {
            cwd: None,
            stdin: Stdin::Forwarded(b"private unused input".to_vec()),
        },
    );
    assert_eq!(request.stdin, None);
}
