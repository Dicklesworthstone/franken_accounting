//! `fad` — the FrankenAccounting daemon (plan §1 posture (c), §5.10, §15.3,
//! Appendix D; bead fa-i8j).
//!
//! One `fad` per book directory. It holds the book's **writer lease**
//! (`fa_cli::lease`: an OS lock that a crash releases) for its whole life,
//! keeps the book open, and serves `fa` over a Unix socket in the book
//! directory. A request is an `fa` command line; the daemon runs it through
//! **the same registry-driven dispatcher the `fa` binary uses**
//! ([`fa_cli::cli::run`]) against the held book and answers with the exit
//! code and the exact stdout and stderr `fa` would have written, so a
//! refusal is byte-identical whichever way it was asked.
//!
//! Frames are `fa_cli::wire`: a 4-byte big-endian length and canonical JSON,
//! with the limit and timeouts from `registries/verbs.toml` `[daemon]`. The
//! accept loop and every connection run under an asupersync `Cx` in one
//! region; requests are answered one at a time (the book has one writer), and
//! nothing is detached. A malformed, oversized, or non-canonical frame is
//! answered with a structured usage error and the connection closes; a
//! truncated frame or a vanished peer just ends the connection. Neither ever
//! reaches the book.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use asupersync::Cx;
use asupersync::io::{AsyncRead, AsyncWrite};
use fa::book::Book;
use fa_cli::cli::{self, Books, Files, Stdin};
use fa_cli::json::{Json, obj, s};
use fa_cli::verbs::Daemon;
use fa_cli::wire::{FrameError, Op, Request, Response, canonical, read_frame, write_frame};

/// What the connection loop does after a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    Continue,
    /// The request was `stop`: answer it, then close everything.
    Stop,
}

/// How a connection ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ended {
    /// The peer closed between frames.
    Closed,
    /// A `stop` request was answered.
    Stop,
    /// The peer sat idle past the limit.
    Idle,
    /// A frame fault: answered (when it could be) and closed.
    Fault(FrameError),
}

/// The protocol limits a connection is held to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub protocol: i128,
    pub max_frame_bytes: usize,
    /// `None` waits forever between frames (lab tests); production uses the
    /// registry's idle timeout.
    pub idle: Option<Duration>,
}

impl Limits {
    #[must_use]
    pub fn from_registry(d: &Daemon) -> Self {
        Self {
            protocol: d.protocol,
            max_frame_bytes: d.max_frame_bytes,
            idle: Some(Duration::from_millis(d.idle_timeout_ms)),
        }
    }
}

/// The answer to a frame the daemon could not accept: a usage error, exactly
/// as `fa --json` renders one.
#[must_use]
pub fn protocol_fault(fault: &FrameError) -> Response {
    let (exit, out) = cli::usage_error(
        &["--json".to_string()],
        format!("fad refused the frame: {fault}"),
        "send one fad_request frame: a 4-byte big-endian length, then canonical JSON (fa robot-docs schema fad_request)",
        true,
    );
    Response {
        op: Op::Run,
        exit,
        stdout: out.stdout,
        stderr: out.stderr,
    }
}

/// Serve one connection for the book at `dir`: read requests, answer each
/// with `handle`, until the peer closes, a `stop` is answered, the peer idles
/// out, or a frame fault.
pub async fn serve_connection<S, H>(
    cx: &Cx,
    stream: &mut S,
    limits: Limits,
    dir: &Path,
    handle: &mut H,
) -> Ended
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: FnMut(Request) -> (Response, Next),
{
    loop {
        let read = Box::pin(read_frame(cx, stream, limits.max_frame_bytes));
        let frame = match limits.idle {
            None => read.await,
            Some(idle) => {
                match asupersync::time::timeout(asupersync::time::wall_now(), idle, read).await {
                    Ok(frame) => frame,
                    Err(_) => return Ended::Idle,
                }
            }
        };
        let payload = match frame {
            Ok(None) => return Ended::Closed,
            Ok(Some(payload)) => payload,
            Err(fault @ (FrameError::TooLarge { .. } | FrameError::Malformed(_))) => {
                let reply = protocol_fault(&fault).to_json(limits.protocol).render();
                let _ = write_frame(cx, stream, reply.as_bytes(), limits.max_frame_bytes).await;
                return Ended::Fault(fault);
            }
            Err(fault) => return Ended::Fault(fault),
        };
        let request = canonical(&payload).and_then(|v| Request::from_json(&v, limits.protocol));
        let request = match request {
            Ok(r) => r,
            Err(fault) => {
                let reply = protocol_fault(&fault).to_json(limits.protocol).render();
                let _ = write_frame(cx, stream, reply.as_bytes(), limits.max_frame_bytes).await;
                return Ended::Fault(fault);
            }
        };
        let (response, next) = handle(request);
        let mut reply = response.to_json(limits.protocol).render();
        if reply.len() > limits.max_frame_bytes {
            // An answer too large for one frame is refused as a whole, never
            // cut. A direct run needs the writer lease this daemon holds, so
            // the advice names stopping it first.
            let fault = FrameError::TooLarge {
                announced: reply.len(),
                max: limits.max_frame_bytes,
            };
            let (exit, out) = cli::foundation_error(
                &["--json".to_string()],
                format!(
                    "the answer ({} bytes) exceeds the daemon frame limit ({} bytes); narrow the command, or stop the daemon with `fad stop --book {}` and run it directly",
                    reply.len(),
                    limits.max_frame_bytes,
                    dir.display()
                ),
                true,
            );
            reply = Response {
                op: response.op,
                exit,
                stdout: out.stdout,
                stderr: out.stderr,
            }
            .to_json(limits.protocol)
            .render();
            if write_frame(cx, stream, reply.as_bytes(), limits.max_frame_bytes)
                .await
                .is_err()
            {
                return Ended::Fault(fault);
            }
        } else if let Err(fault) =
            write_frame(cx, stream, reply.as_bytes(), limits.max_frame_bytes).await
        {
            return Ended::Fault(fault);
        }
        if next == Next::Stop {
            return Ended::Stop;
        }
    }
}

/// The daemon's state: the held book and what it has answered.
pub struct Server<'a> {
    pub book: &'a mut Book,
    pub dir: PathBuf,
    pub socket: PathBuf,
    pub requests: u64,
}

impl Server<'_> {
    /// Answer one request.
    pub fn handle(&mut self, request: Request) -> (Response, Next) {
        self.requests = self.requests.saturating_add(1);
        let json = request.argv.iter().any(|a| a == "--json");
        match request.op {
            Op::Run => {
                let files = Files {
                    cwd: request.cwd.map(PathBuf::from),
                    stdin: request.stdin.map_or(Stdin::Missing, Stdin::Forwarded),
                };
                let books = Books::Held {
                    book: &mut *self.book,
                    dir: self.dir.clone(),
                };
                let (exit, out) = cli::run(&request.argv, books, files, true);
                (
                    Response {
                        op: Op::Run,
                        exit,
                        stdout: out.stdout,
                        stderr: out.stderr,
                    },
                    Next::Continue,
                )
            }
            Op::Status => (
                Response {
                    op: Op::Status,
                    exit: 0,
                    stdout: line(json, &self.status_event(), &self.status_text()),
                    stderr: String::new(),
                },
                Next::Continue,
            ),
            Op::Stop => (
                Response {
                    op: Op::Stop,
                    exit: 0,
                    stdout: line(json, &self.stopped_event(), &self.stopped_text()),
                    stderr: String::new(),
                },
                Next::Stop,
            ),
        }
    }

    #[must_use]
    pub fn status_event(&self) -> Json {
        obj(vec![
            ("event", s("fad_status")),
            ("serving", Json::Bool(true)),
            ("dir", s(self.dir.display().to_string())),
            ("socket", s(self.socket.display().to_string())),
            ("pid", Json::Int(i128::from(std::process::id()))),
            ("book_id", s(self.book.context().book_id.to_hex())),
            ("requests", Json::Int(i128::from(self.requests))),
            ("holder", Json::Null),
        ])
    }

    fn status_text(&self) -> String {
        format!(
            "fad serving {} (pid {}, book {}) on {} · {} requests answered",
            self.dir.display(),
            std::process::id(),
            self.book.context().book_id.to_hex(),
            self.socket.display(),
            self.requests
        )
    }

    #[must_use]
    pub fn stopped_event(&self) -> Json {
        obj(vec![
            ("event", s("fad_stopped")),
            ("dir", s(self.dir.display().to_string())),
            ("requests", Json::Int(i128::from(self.requests))),
        ])
    }

    fn stopped_text(&self) -> String {
        format!(
            "fad for {} stopped after {} requests; the writer lease is released",
            self.dir.display(),
            self.requests
        )
    }
}

/// One stdout line: the event in robot mode, the text otherwise.
#[must_use]
pub fn line(json: bool, event: &Json, text: &str) -> String {
    if json {
        format!("{}\n", event.render())
    } else {
        format!("{text}\n")
    }
}

/// Accept connections on `listener` for the book at `dir` and serve them one
/// at a time until a `stop` is answered. Returns how the last connection
/// ended.
pub async fn serve<H>(
    cx: &Cx,
    listener: &asupersync::net::unix::UnixListener,
    limits: Limits,
    dir: &Path,
    handle: &mut H,
) -> std::io::Result<()>
where
    H: FnMut(Request) -> (Response, Next),
{
    loop {
        cx.checkpoint()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Interrupted, format!("{e:?}")))?;
        let (mut stream, _) = listener.accept().await?;
        if serve_connection(cx, &mut stream, limits, dir, handle).await == Ended::Stop {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod lab_tests;
