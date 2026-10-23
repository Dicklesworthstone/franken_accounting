//! Real socket regressions for fa-y9ug. The peer's watchdog also bounds a
//! broken client, so removing the request deadline fails instead of hanging
//! the test process forever. Every peer is joined before the test returns.

use super::*;
use crate::wire::{Op, PREFIX_BYTES, encode};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream as StdStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const WATCHDOG: Duration = Duration::from_secs(3);

fn socket() -> (PathBuf, UnixListener) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        // RCH's retained TMPDIR can exceed sockaddr_un's path limit before
        // this suffix is added. Only these Unix socket fixtures need a short
        // root; the request/response and watchdog assertions stay unchanged.
        let dir = PathBuf::from("/tmp").join(format!("fa-client-{}-{n}", std::process::id()));
        if std::fs::create_dir(&dir).is_ok() {
            let path = dir.join("fad.sock");
            let listener = UnixListener::bind(&path).expect("listen");
            return (path, listener);
        }
        assert!(n < 1_000, "cannot create socket directory");
    }
}

fn daemon(timeout_ms: u64) -> Daemon {
    let mut daemon = crate::verbs::registry().expect("registry").daemon.clone();
    daemon.request_timeout_ms = timeout_ms;
    daemon
}

fn request() -> Request {
    Request {
        op: Op::Run,
        argv: vec!["post".into(), "--intent".into(), "-".into()],
        cwd: None,
        stdin: Some(b"{\"idempotency_key\":\"original-key\"}".to_vec()),
        token: None,
    }
}

fn accept(listener: &UnixListener) -> StdStream {
    listener.set_nonblocking(true).expect("accept bound");
    let expires = Instant::now() + WATCHDOG;
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < expires, "client never connected");
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("accept client: {error}"),
        }
    };
    stream.set_nonblocking(false).expect("blocking peer");
    stream.set_read_timeout(Some(WATCHDOG)).expect("read bound");
    stream
        .set_write_timeout(Some(WATCHDOG))
        .expect("write bound");
    stream
}

fn receive(stream: &mut StdStream, daemon: &Daemon) -> Request {
    let mut prefix = [0; PREFIX_BYTES];
    stream.read_exact(&mut prefix).expect("request prefix");
    let len = crate::wire::announced(prefix, daemon.max_frame_bytes).expect("request size");
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).expect("request payload");
    Request::from_json(&canonical(&bytes).expect("canonical"), daemon.protocol).expect("request")
}

#[test]
fn a_responding_peer_preserves_the_complete_response() {
    let (path, listener) = socket();
    let daemon = daemon(2_000);
    let request = request();
    let response = Response {
        op: request.op,
        exit: 6,
        stdout: "{\"event\":\"error\"}\n".into(),
        stderr: "a conflict, unchanged by the transport\n".into(),
    };
    std::thread::scope(|scope| {
        let peer = scope.spawn(|| {
            let mut stream = accept(&listener);
            assert_eq!(receive(&mut stream, &daemon), request);
            let frame = encode(
                response.to_json(daemon.protocol).render().as_bytes(),
                daemon.max_frame_bytes,
            )
            .unwrap();
            stream.write_all(&frame).expect("respond");
        });
        let actual = call(&path, &request, &daemon).expect("response before deadline");
        assert_eq!(actual, response);
        peer.join().expect("joined peer");
    });
}

#[test]
fn a_peer_that_accepts_a_write_but_never_replies_times_out_without_resending() {
    let (path, listener) = socket();
    let daemon = daemon(100);
    let request = request();
    let (release, released) = mpsc::channel();
    std::thread::scope(|scope| {
        let peer_daemon = &daemon;
        let peer_request = &request;
        let peer = scope.spawn(move || {
            let mut stream = accept(&listener);
            assert_eq!(&receive(&mut stream, peer_daemon), peer_request);
            // The complete request reached the daemon: timeout must not imply
            // rollback or resend it under another idempotency key.
            let _ = released.recv_timeout(WATCHDOG);
            listener.set_nonblocking(true).unwrap();
            assert!(matches!(
                listener.accept(),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            ));
        });
        let error = call(&path, &request, &daemon).expect_err("silent peer");
        let _ = release.send(());
        peer.join().expect("joined peer");
        assert!(
            matches!(
                error,
                ClientError::Timeout {
                    timeout_ms: 100,
                    phase: Phase::ReceivingResponse
                }
            ),
            "{error}"
        );
        let message = error.to_string();
        assert!(message.contains("may already have committed"), "{message}");
        assert!(message.contains("unchanged request"), "{message}");
        assert!(message.contains("original key"), "{message}");
        assert!(message.contains("fad status"), "{message}");
    });
}

#[test]
fn a_partial_response_does_not_disable_the_absolute_deadline() {
    for prefix_only in [true, false] {
        let (path, listener) = socket();
        let daemon = daemon(100);
        let request = request();
        let (release, released) = mpsc::channel();
        std::thread::scope(|scope| {
            let peer_daemon = &daemon;
            let peer_request = &request;
            let peer = scope.spawn(move || {
                let mut stream = accept(&listener);
                assert_eq!(&receive(&mut stream, peer_daemon), peer_request);
                if prefix_only {
                    stream.write_all(&[0, 0]).unwrap();
                } else {
                    stream.write_all(&64u32.to_be_bytes()).unwrap();
                    stream.write_all(b"{\"event\":").unwrap();
                }
                let _ = released.recv_timeout(WATCHDOG);
            });
            let result = call(&path, &request, &daemon);
            let _ = release.send(());
            peer.join().expect("joined peer");
            assert!(
                matches!(
                    result,
                    Err(ClientError::Timeout {
                        phase: Phase::ReceivingResponse,
                        ..
                    })
                ),
                "prefix_only={prefix_only}: {result:?}"
            );
        });
    }
}

#[test]
fn a_peer_that_never_reads_the_request_cannot_block_the_sender_forever() {
    let (path, listener) = socket();
    let daemon = daemon(300);
    let mut request = request();
    // Larger than a local socket's send buffer, but within the registered
    // frame bound. The peer deliberately reads nothing at all.
    request.stdin = Some(vec![b'x'; 4 * 1024 * 1024]);
    let (release, released) = mpsc::channel();
    std::thread::scope(|scope| {
        let peer = scope.spawn(move || {
            let _stream = accept(&listener);
            let _ = released.recv_timeout(WATCHDOG);
        });
        let result = call(&path, &request, &daemon);
        let _ = release.send(());
        peer.join().expect("joined peer");
        assert!(
            matches!(
                result,
                Err(ClientError::Timeout {
                    phase: Phase::SendingRequest,
                    ..
                })
            ),
            "{result:?}"
        );
    });
}

#[test]
fn disconnected_and_truncated_peers_keep_their_original_error_class() {
    let (path, listener) = socket();
    let daemon = daemon(2_000);
    let request = request();
    let result = call(&path.with_file_name("missing.sock"), &request, &daemon);
    assert!(matches!(result, Err(ClientError::Connect(_))), "{result:?}");
    std::thread::scope(|scope| {
        let peer = scope.spawn(|| {
            let mut stream = accept(&listener);
            assert_eq!(receive(&mut stream, &daemon), request);
            stream.write_all(&[0, 0]).unwrap();
        });
        let result = call(&path, &request, &daemon);
        peer.join().expect("joined peer");
        assert!(
            matches!(
                result,
                Err(ClientError::Frame(FrameError::Truncated {
                    got: 2,
                    expected: PREFIX_BYTES
                }))
            ),
            "{result:?}"
        );
    });
}

#[test]
fn request_deadlines_reject_invalid_durations_and_release_timer_registrations() {
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    for timeout_ms in [0, u64::MAX] {
        assert!(matches!(
            Deadline::new(&cx, timeout_ms),
            Err(ClientError::Runtime(_))
        ));
    }
    let driver = cx.timer_driver().unwrap();
    let before = driver.pending_count();
    let mut deadline = Deadline::new(&cx, 60_000).unwrap();
    let mut task = Context::from_waker(std::task::Waker::noop());
    assert!(Pin::new(&mut deadline).poll(&mut task).is_pending());
    assert_eq!(driver.pending_count(), before + 1);
    drop(deadline);
    assert_eq!(driver.pending_count(), before);
}
