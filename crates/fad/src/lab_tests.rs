//! The connection loop under asupersync's lab runtime (deterministic
//! scheduling, seeded; chaos on for the second half), over a virtual stream
//! pair. Real Unix sockets do not run under the lab reactor, so the socket
//! itself, the lease, and crash recovery are tested with real processes in
//! `tests/fad.rs`; everything the loop decides is tested here.

use super::*;
use asupersync::LabConfig;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::lab::{run_async_under_lab, run_async_under_lab_with_config};
use asupersync::net::tcp::VirtualTcpStream;
use fa_cli::wire::{Decoder, encode};

const MAX: usize = 4096;
const LIMITS: Limits = Limits {
    protocol: 1,
    max_frame_bytes: MAX,
    idle: None,
};

fn addr(port: u16) -> std::net::SocketAddr {
    ([127, 0, 0, 1], port).into()
}

fn request(op: Op, n: usize) -> Request {
    Request {
        op,
        argv: vec!["tb".into(), format!("--n={n}"), "--json".into()],
        cwd: None,
        stdin: None,
        token: None,
    }
}

fn frame(r: &Request) -> Vec<u8> {
    let payload = r.to_json(1).render();
    encode(payload.as_bytes(), MAX).unwrap_or_default()
}

/// What the server saw, how it ended, and the frames the client got back.
type Run = (Vec<Vec<String>>, Ended, Vec<Vec<u8>>);

/// The book directory the lab connections serve.
const BOOK: &str = "/books/lab";

/// Feed `bytes` to a fresh connection, serve it with an echo handler, and
/// collect everything the client receives.
async fn exchange(cx: Cx, bytes: Vec<u8>) -> Run {
    exchange_answering(cx, bytes, |r| r.argv.join(" ")).await
}

/// As [`exchange`], with a handler whose stdout is `answer(request)`.
async fn exchange_answering(cx: Cx, bytes: Vec<u8>, answer: fn(&Request) -> String) -> Run {
    let (mut server, mut client) = VirtualTcpStream::pair(addr(1), addr(2));
    let _ = client.write_all(&bytes).await;
    let _ = AsyncWriteExt::shutdown(&mut client).await;
    let mut seen: Vec<Vec<String>> = Vec::new();
    let mut handle = |r: Request| {
        seen.push(r.argv.clone());
        let next = if r.op == Op::Stop {
            Next::Stop
        } else {
            Next::Continue
        };
        (
            Response {
                op: r.op,
                exit: 0,
                stdout: answer(&r),
                stderr: String::new(),
            },
            next,
        )
    };
    let dir = std::path::Path::new(BOOK);
    let ended = serve_connection(&cx, &mut server, LIMITS, dir, &mut handle).await;
    drop(server);
    let mut received = Vec::new();
    let _ = client.read_to_end(&mut received).await;
    let mut decoder = Decoder::new(MAX);
    decoder.push(&received);
    let mut frames = Vec::new();
    while let Ok(Some(f)) = decoder.next_frame() {
        frames.push(f);
    }
    (seen, ended, frames)
}

fn responses(frames: &[Vec<u8>]) -> Vec<Response> {
    frames
        .iter()
        .map(|f| {
            let v = fa_cli::wire::canonical(f);
            assert!(v.is_ok(), "the daemon only writes canonical frames");
            let r = v.and_then(|v| Response::from_json(&v, 1));
            assert!(r.is_ok(), "{r:?}");
            r.unwrap_or(Response {
                op: Op::Run,
                exit: 255,
                stdout: String::new(),
                stderr: String::new(),
            })
        })
        .collect()
}

/// Every frame either side writes is a declared robot-schema event.
fn schema_checked(frames: &[Vec<u8>]) {
    let reg = fa_cli::verbs::registry().expect("verbs.toml");
    for f in frames {
        let text = String::from_utf8_lossy(f);
        assert_eq!(reg.check_line(&text), Ok("fad_response"), "{text}");
    }
}

#[test]
fn requests_are_answered_one_for_one_in_order() {
    for seed in 0..8 {
        let sent: Vec<Request> = (0..3).map(|n| request(Op::Run, n)).collect();
        let reg = fa_cli::verbs::registry().expect("verbs.toml");
        for r in &sent {
            assert_eq!(reg.check_line(&r.to_json(1).render()), Ok("fad_request"));
        }
        let bytes: Vec<u8> = sent.iter().flat_map(frame).collect();
        let ((seen, ended, frames), _) = run_async_under_lab(seed, move |cx| exchange(cx, bytes));
        assert_eq!(ended, Ended::Closed, "seed {seed}");
        assert_eq!(
            seen,
            sent.iter().map(|r| r.argv.clone()).collect::<Vec<_>>()
        );
        schema_checked(&frames);
        let got: Vec<String> = responses(&frames).into_iter().map(|r| r.stdout).collect();
        assert_eq!(
            got,
            sent.iter().map(|r| r.argv.join(" ")).collect::<Vec<_>>(),
            "seed {seed}"
        );
    }
}

#[test]
fn a_stop_is_answered_and_nothing_after_it_is_read() {
    let bytes: Vec<u8> = [
        request(Op::Run, 0),
        request(Op::Stop, 1),
        request(Op::Run, 2),
    ]
    .iter()
    .flat_map(frame)
    .collect();
    let ((seen, ended, frames), _) = run_async_under_lab(7, move |cx| exchange(cx, bytes));
    assert_eq!(ended, Ended::Stop);
    assert_eq!(seen.len(), 2, "the request after stop is never handled");
    assert_eq!(responses(&frames).len(), 2);
}

#[test]
fn a_frame_cut_short_ends_the_connection_without_reaching_the_handler() {
    let whole = frame(&request(Op::Run, 0));
    let second = frame(&request(Op::Run, 1));
    let half = second.len() / 2;
    assert!(half > 4, "the cut falls inside the payload");
    let mut bytes = whole;
    bytes.extend_from_slice(&second[..half]);
    let ((seen, ended, frames), _) = run_async_under_lab(3, move |cx| exchange(cx, bytes));
    assert_eq!(seen.len(), 1);
    assert_eq!(responses(&frames).len(), 1);
    assert_eq!(
        ended,
        Ended::Fault(FrameError::Truncated {
            got: half,
            expected: second.len()
        })
    );
}

#[test]
fn oversized_and_non_canonical_frames_get_a_structured_refusal_and_close() {
    let mut oversized = u32::try_from(MAX + 1)
        .unwrap_or(u32::MAX)
        .to_be_bytes()
        .to_vec();
    oversized.extend_from_slice(b"never read");
    let spaced = br#"{ "event":"fad_request","v":1}"#;
    let mut non_canonical = u32::try_from(spaced.len())
        .unwrap_or(0)
        .to_be_bytes()
        .to_vec();
    non_canonical.extend_from_slice(spaced);
    let mut wrong_protocol = Vec::new();
    let v2 = request(Op::Run, 0).to_json(2).render();
    wrong_protocol.extend(encode(v2.as_bytes(), MAX).unwrap_or_default());
    for (what, bytes) in [
        ("oversized", oversized),
        ("non-canonical", non_canonical),
        ("wrong protocol", wrong_protocol),
    ] {
        let ((seen, ended, frames), _) = run_async_under_lab(11, move |cx| exchange(cx, bytes));
        assert!(
            seen.is_empty(),
            "{what}: the handler never sees a bad frame"
        );
        assert!(matches!(ended, Ended::Fault(_)), "{what}: {ended:?}");
        schema_checked(&frames);
        let replies = responses(&frames);
        assert_eq!(replies.len(), 1, "{what}");
        assert_eq!(replies[0].exit, 2, "{what}");
        let reg = fa_cli::verbs::registry().expect("verbs.toml");
        let line = replies[0].stdout.trim_end();
        assert_eq!(reg.check_line(line), Ok("error"), "{what}: {line}");
        assert!(line.contains(r#""class":"usage""#), "{what}: {line}");
        assert!(line.contains("fad refused the frame"), "{what}: {line}");
    }
}

/// An answer too large for one frame is refused whole, never cut, and the
/// refusal's advice works while this daemon holds the writer lease: narrow
/// the command, or stop the daemon first (a direct run would be FA-REF-018).
#[test]
fn an_oversized_answer_is_refused_whole_with_advice_that_works() {
    let bytes = frame(&request(Op::Run, 0));
    let ((seen, ended, frames), _) = run_async_under_lab(13, move |cx| {
        exchange_answering(cx, bytes, |_| "x".repeat(MAX))
    });
    assert_eq!(seen.len(), 1, "the handler ran the request");
    assert_eq!(ended, Ended::Closed, "the connection stays usable");
    schema_checked(&frames);
    let replies = responses(&frames);
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].exit, 5);
    let line = replies[0].stdout.trim_end();
    assert!(!line.contains("xxxx"), "never a cut answer: {line}");
    let reg = fa_cli::verbs::registry().expect("verbs.toml");
    assert_eq!(reg.check_line(line), Ok("error"), "{line}");
    assert!(line.contains(r#""class":"foundation""#), "{line}");
    let advice = format!(
        "narrow the command, or stop the daemon with `fad stop --book {BOOK}` and run it directly"
    );
    assert!(line.contains(&advice), "{line}");
    assert!(
        !line.contains("narrow the command or run it directly"),
        "the unfollowable advice is gone: {line}"
    );
}

/// With the lab's light chaos (injected cancellation, delays, wake storms):
/// whatever happens, the handler only ever sees whole frames, in order, each
/// answered at most once, and the loop always returns.
#[test]
fn under_chaos_only_whole_frames_reach_the_handler() {
    for seed in 0..16 {
        let sent: Vec<Request> = (0..4).map(|n| request(Op::Run, n)).collect();
        let bytes: Vec<u8> = sent.iter().flat_map(frame).collect();
        let config = LabConfig::new(seed).with_light_chaos();
        let ((seen, ended, frames), _) =
            run_async_under_lab_with_config(config, move |cx| exchange(cx, bytes));
        let expected: Vec<Vec<String>> = sent.iter().map(|r| r.argv.clone()).collect();
        assert!(expected.starts_with(&seen), "seed {seed}: handled {seen:?}");
        let replies = responses(&frames);
        assert!(replies.len() <= seen.len(), "seed {seed}");
        if ended == Ended::Closed {
            assert_eq!(
                seen, expected,
                "seed {seed}: a clean close handled everything"
            );
        }
    }
}

#[test]
fn slow_client_sending_a_frame_every_29s_does_not_starve_other_clients_and_unauthorized_stop_is_refused()
 {
    use asupersync::Budget;
    use asupersync::lab::{AutoAdvanceTermination, LabRuntime};
    use asupersync::net::tcp::VirtualTcpListener;
    use std::sync::Arc;

    const DAEMON_UID: u32 = 1000;
    const FOREIGN_UID: u32 = 2000;
    const OWNER_TOKEN: [u8; 32] = [0xAB; 32];
    const SEC: u64 = 1_000_000_000;

    async fn sleep_ns(cx: &Cx, nanos: u64) {
        let at = clock::deadline_after(clock::timer(cx).unwrap().now(), nanos).unwrap();
        clock::Deadline::new(cx, at).unwrap().await.unwrap();
    }

    let mut lab = LabRuntime::new(LabConfig::new(42).with_auto_advance());
    let root = lab.state.create_root_region(Budget::INFINITE);
    let listener = Arc::new(VirtualTcpListener::new(addr(9000)));
    let listener_for_client = Arc::clone(&listener);

    let (server_task, mut server_handle) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().expect("lab server cx");
            let limits = Limits {
                protocol: 1,
                max_frame_bytes: MAX,
                idle: Some(Duration::from_secs(30)),
            };
            let mut seen: Vec<Vec<String>> = Vec::new();
            let mut handle = |r: Request| {
                seen.push(r.argv.clone());
                let next = if r.op == Op::Stop {
                    Next::Stop
                } else {
                    Next::Continue
                };
                (
                    Response {
                        op: r.op,
                        exit: 0,
                        stdout: r.argv.join(" "),
                        stderr: String::new(),
                    },
                    next,
                )
            };
            let timings = serve_listener(
                &cx,
                &*listener,
                limits,
                Path::new(BOOK),
                Some(DAEMON_UID),
                Some(OWNER_TOKEN),
                &mut handle,
            )
            .await
            .expect("serve_listener");
            (seen, timings)
        })
        .unwrap();

    let (client_task, mut client_handle) = lab
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().expect("lab client cx");
            let now_ns = || clock::timer(&cx).unwrap().now().as_nanos();

            // Client A connects at t = 0 s and sends only half of its first frame,
            // then dribbles/sends one frame every 29 s (under the 30 s idle timeout).
            let (server_a, mut client_a) = VirtualTcpStream::pair(addr(9000), addr(DAEMON_UID as u16));
            listener_for_client.inject_connection(server_a, addr(DAEMON_UID as u16));
            let frame_a1 = frame(&request(Op::Run, 10));
            let half = frame_a1.len() / 2;
            client_a.write_all(&frame_a1[..half]).await.unwrap();

            // At t = 1 s, Client B connects and sends a full request while Client A is mid-frame.
            sleep_ns(&cx, SEC).await;
            let b_start = now_ns();
            let (server_b, mut client_b) = VirtualTcpStream::pair(addr(9000), addr(DAEMON_UID as u16));
            listener_for_client.inject_connection(server_b, addr(DAEMON_UID as u16));
            client_b.write_all(&frame(&request(Op::Run, 20))).await.unwrap();
            let _ = AsyncWriteExt::shutdown(&mut client_b).await;
            let reply_b = read_frame(&cx, &mut client_b, MAX)
                .await
                .unwrap()
                .expect("client B reply");
            let resp_b = Response::from_json(&canonical(&reply_b).unwrap(), 1).unwrap();
            assert_eq!(resp_b.exit, 0);
            assert_eq!(resp_b.stdout, "tb --n=20 --json");
            let b_elapsed = now_ns() - b_start;
            assert!(
                b_elapsed < 5 * SEC,
                "Client B must complete within its 5 s deadline, not wait 29 s for Client A (elapsed={b_elapsed} ns)"
            );

            // At t = 2 s, a foreign-UID peer (uid 2000 != 1000) connects and sends unparseable
            // bytes; it must be refused with FA-REF-011 before any frame reading or parsing (fa-udti).
            sleep_ns(&cx, SEC).await;
            let (server_foreign, mut client_foreign) =
                VirtualTcpStream::pair(addr(9000), addr(FOREIGN_UID as u16));
            listener_for_client.inject_connection(server_foreign, addr(FOREIGN_UID as u16));
            client_foreign
                .write_all(b"\x00\x00\x00\x07NOTJSON")
                .await
                .unwrap();
            let reply_foreign = read_frame(&cx, &mut client_foreign, MAX)
                .await
                .unwrap()
                .expect("foreign peer refusal");
            let resp_foreign =
                Response::from_json(&canonical(&reply_foreign).unwrap(), 1).unwrap();
            assert_eq!(resp_foreign.exit, 7, "{resp_foreign:?}");
            assert!(
                resp_foreign.stdout.contains("\"refusal_id\":\"FA-REF-011\""),
                "{}",
                resp_foreign.stdout
            );
            assert!(
                resp_foreign.stdout.contains("peer uid 2000"),
                "{}",
                resp_foreign.stdout
            );

            // At t = 3 s, a same-UID peer without the owner token attempts Op::Stop.
            sleep_ns(&cx, SEC).await;
            let (server_unauth, mut client_unauth) =
                VirtualTcpStream::pair(addr(9000), addr(DAEMON_UID as u16));
            listener_for_client.inject_connection(server_unauth, addr(DAEMON_UID as u16));
            client_unauth
                .write_all(&frame(&request(Op::Stop, 98)))
                .await
                .unwrap();
            let _ = AsyncWriteExt::shutdown(&mut client_unauth).await;
            let reply_unauth = read_frame(&cx, &mut client_unauth, MAX)
                .await
                .unwrap()
                .expect("unauthorized stop refusal");
            let resp_unauth =
                Response::from_json(&canonical(&reply_unauth).unwrap(), 1).unwrap();
            assert_eq!(resp_unauth.exit, 7, "{resp_unauth:?}");
            assert!(
                resp_unauth.stdout.contains("\"refusal_id\":\"FA-REF-011\""),
                "{}",
                resp_unauth.stdout
            );
            assert!(
                resp_unauth
                    .stdout
                    .contains("stopping the daemon requires owner authority"),
                "{}",
                resp_unauth.stdout
            );

            // At t = 29 s (26 s later), Client A finishes its first frame and gets its answer.
            sleep_ns(&cx, 26 * SEC).await;
            assert_eq!(now_ns(), 29 * SEC);
            client_a.write_all(&frame_a1[half..]).await.unwrap();
            let reply_a1 = read_frame(&cx, &mut client_a, MAX)
                .await
                .unwrap()
                .expect("client A first reply");
            let resp_a1 = Response::from_json(&canonical(&reply_a1).unwrap(), 1).unwrap();
            assert_eq!(resp_a1.stdout, "tb --n=10 --json");

            // Client A stays open for another 29 s (until t = 58 s). Meanwhile at t = 40 s,
            // Client C connects and is served immediately while Client A sits idle.
            sleep_ns(&cx, 11 * SEC).await;
            let c_start = now_ns();
            let (server_c, mut client_c) = VirtualTcpStream::pair(addr(9000), addr(DAEMON_UID as u16));
            listener_for_client.inject_connection(server_c, addr(DAEMON_UID as u16));
            client_c.write_all(&frame(&request(Op::Run, 30))).await.unwrap();
            let _ = AsyncWriteExt::shutdown(&mut client_c).await;
            let reply_c = read_frame(&cx, &mut client_c, MAX)
                .await
                .unwrap()
                .expect("client C reply");
            let resp_c = Response::from_json(&canonical(&reply_c).unwrap(), 1).unwrap();
            assert_eq!(resp_c.stdout, "tb --n=30 --json");
            assert_eq!(now_ns() - c_start, 0);

            // At t = 58 s (18 s later, 29 s after Client A's first frame), Client A sends a second frame.
            sleep_ns(&cx, 18 * SEC).await;
            assert_eq!(now_ns(), 58 * SEC);
            client_a.write_all(&frame(&request(Op::Run, 11))).await.unwrap();
            let _ = AsyncWriteExt::shutdown(&mut client_a).await;
            let reply_a2 = read_frame(&cx, &mut client_a, MAX)
                .await
                .unwrap()
                .expect("client A second reply");
            let resp_a2 = Response::from_json(&canonical(&reply_a2).unwrap(), 1).unwrap();
            assert_eq!(resp_a2.stdout, "tb --n=11 --json");

            // At t = 59 s, an authorized owner sends Op::Stop with the owner token.
            sleep_ns(&cx, SEC).await;
            let (server_stop, mut client_stop) =
                VirtualTcpStream::pair(addr(9000), addr(DAEMON_UID as u16));
            listener_for_client.inject_connection(server_stop, addr(DAEMON_UID as u16));
            let auth_stop = Request {
                op: Op::Stop,
                argv: vec!["--json".into()],
                cwd: None,
                stdin: Some(OWNER_TOKEN.to_vec()),
            };
            client_stop.write_all(&frame(&auth_stop)).await.unwrap();
            let reply_stop = read_frame(&cx, &mut client_stop, MAX)
                .await
                .unwrap()
                .expect("authorized stop reply");
            let resp_stop = Response::from_json(&canonical(&reply_stop).unwrap(), 1).unwrap();
            assert_eq!(resp_stop.exit, 0);
        })
        .unwrap();

    {
        let mut sched = lab.scheduler.lock();
        sched.schedule(server_task, Budget::INFINITE.priority);
        sched.schedule(client_task, Budget::INFINITE.priority);
    }
    let advanced = lab.run_with_auto_advance();
    assert!(
        matches!(advanced.termination, AutoAdvanceTermination::Quiescent),
        "{advanced:?}"
    );
    assert!(lab.report().lab_test_passed(), "{:?}", lab.report());
    client_handle.try_join().unwrap().expect("client task");
    let (seen, timings) = server_handle.try_join().unwrap().expect("server task");
    assert_eq!(
        seen.len(),
        5,
        "B, A1, C, A2, and authorized Stop reached handler: {seen:?}"
    );
    assert_eq!(
        timings.len(),
        6,
        "6 connections recorded in timings: {timings:?}"
    );
    assert!(
        timings.iter().any(|t| matches!(
            t.ended,
            Ended::UnauthorizedPeer {
                peer_uid: FOREIGN_UID,
                daemon_uid: DAEMON_UID
            }
        )),
        "foreign peer refusal recorded in timings: {timings:?}"
    );
    assert!(
        timings
            .iter()
            .any(|t| t.conn_id == 1 && t.requests == 2 && t.elapsed_ns == 58 * SEC),
        "slow client A timing recorded: {timings:?}"
    );
}
