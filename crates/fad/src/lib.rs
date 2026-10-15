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

pub mod clock;
pub mod timed;

use core::future::{Future, poll_fn};
use core::pin::{Pin, pin};
use core::task::{Context, Poll};
use std::path::{Path, PathBuf};
use std::time::Duration;

use asupersync::Cx;
use asupersync::cx::{ChildRegion, ChildRegionError, ChildRegionSpec};
use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
use asupersync::types::Time;
use fa::book::Book;
use fa_cli::cli::{self, Books, Files, Stdin};
use fa_cli::json::{Json, obj, s};
use fa_cli::verbs::Daemon;
use fa_cli::wire::{
    FrameError, Op, PREFIX_BYTES, Request, Response, announced, canonical, encode, read_frame,
    write_frame,
};
use fa_model::limits::MAX_DAEMON_CONNECTIONS;

/// Kernel-certified peer credentials (`SO_PEERCRED` / `LOCAL_PEERCRED` on Unix
/// sockets, or simulated peer credentials under the lab runtime; bead fa-een).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
}

/// Listener abstraction shared by [`asupersync::net::unix::UnixListener`] and
/// [`asupersync::net::tcp::VirtualTcpListener`] (for deterministic lab tests).
pub trait Listener {
    type Stream: AsyncRead + AsyncWrite + Unpin;

    fn poll_accept(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<(Self::Stream, Option<PeerCred>)>>;
}

impl Listener for asupersync::net::unix::UnixListener {
    type Stream = asupersync::net::unix::UnixStream;

    fn poll_accept(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<(Self::Stream, Option<PeerCred>)>> {
        match asupersync::net::unix::UnixListener::poll_accept(self, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok((stream, _addr))) => {
                let cred = stream.peer_cred().map(|c| PeerCred {
                    uid: c.uid,
                    gid: c.gid,
                    pid: c.pid,
                })?;
                Poll::Ready(Ok((stream, Some(cred))))
            }
        }
    }
}

impl Listener for asupersync::net::tcp::VirtualTcpListener {
    type Stream = asupersync::net::tcp::VirtualTcpStream;

    fn poll_accept(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<(Self::Stream, Option<PeerCred>)>> {
        use asupersync::net::tcp::TcpListenerApi;
        match TcpListenerApi::poll_accept(self, cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok((stream, addr))) => {
                let cred = Some(PeerCred {
                    uid: u32::from(addr.port()),
                    gid: u32::from(addr.port()),
                    pid: Some(i32::from(addr.port())),
                });
                Poll::Ready(Ok((stream, cred)))
            }
        }
    }
}

/// Kernel-certified effective UID of the current process via a self-connected
/// Unix socket pair (`SO_PEERCRED` / `LOCAL_PEERCRED`), with zero `unsafe`.
pub fn current_uid() -> std::io::Result<u32> {
    let (a, _b) = asupersync::net::unix::UnixStream::pair()?;
    Ok(a.peer_cred()?.uid)
}

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
    /// The peer's kernel UID did not match the daemon's UID and no owner token was presented.
    UnauthorizedPeer { peer_uid: u32, daemon_uid: u32 },
}

/// Per-connection timing and outcome record (fa-een).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionTiming {
    pub conn_id: u64,
    pub peer_uid: Option<u32>,
    pub peer_pid: Option<i32>,
    pub requests: u64,
    pub elapsed_ns: u64,
    pub ended: Ended,
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

/// Structured refusal when `Op::Stop` is requested without owner authority (fa-een).
#[must_use]
pub fn stop_refusal(argv: &[String], dir: &Path) -> Response {
    let refusal = fa_journal::Refusal::new(
        fa_journal::refusal::code::CAPABILITY,
        fa_journal::refusal::exit::SAFETY,
        format!(
            "fad refused stop for {}: stopping the daemon requires owner authority (possession of the book's key file)",
            dir.display()
        ),
        "plan §14.1, §15.3 (daemon owner authority)",
        format!(
            "fad stop --book {} --keys {}/book.keys",
            dir.display(),
            dir.display()
        ),
    );
    let (exit, out) = cli::refuse(argv, refusal, true);
    Response {
        op: Op::Stop,
        exit,
        stdout: out.stdout,
        stderr: out.stderr,
    }
}

/// Structured refusal when a socket peer's kernel UID does not match the daemon's UID (fa-een).
#[must_use]
pub fn peer_uid_refusal(
    request: &Request,
    peer_uid: u32,
    daemon_uid: u32,
    dir: &Path,
) -> Response {
    let refusal = fa_journal::Refusal::new(
        fa_journal::refusal::code::CAPABILITY,
        fa_journal::refusal::exit::SAFETY,
        format!(
            "fad refused connection from peer uid {peer_uid} (daemon runs as uid {daemon_uid})"
        ),
        "plan §14.1, §15.3 (daemon socket peer credential check)",
        format!(
            "connect as uid {daemon_uid} or supply the book owner token via `fad stop --book {} --keys {}/book.keys`",
            dir.display(),
            dir.display()
        ),
    );
    let argv: Vec<String> = if request.argv.iter().any(|a| a == "--json") {
        vec!["--json".to_string()]
    } else {
        Vec::new()
    };
    let (exit, out) = cli::refuse(&argv, refusal, true);
    Response {
        op: request.op,
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
    serve_connection_with(cx, stream, limits, dir, &mut Untimed::new(handle)).await
}

/// The same framing loop serves a real book with scheduled work and the
/// protocol-only lab handlers. Timing never owns a second book writer.
trait Service {
    fn daemon_uid(&self) -> Option<u32> {
        None
    }
    fn admits_foreign_peer(&self, _request: &Request) -> bool {
        false
    }
    fn handle(&mut self, request: Request) -> (Response, Next);
    fn deadline(&self) -> Option<Time>;
    async fn tick(&mut self, cx: &Cx);
    fn on_connection_closed(&mut self, _timing: ConnectionTiming) {}
}

struct Untimed<'a, H> {
    handle: &'a mut H,
    daemon_uid: Option<u32>,
    owner_token: Option<[u8; 32]>,
    dir: PathBuf,
    timings: Vec<ConnectionTiming>,
}

impl<'a, H> Untimed<'a, H> {
    fn new(handle: &'a mut H) -> Self {
        Self {
            handle,
            daemon_uid: None,
            owner_token: None,
            dir: PathBuf::new(),
            timings: Vec::new(),
        }
    }
}

impl<H: FnMut(Request) -> (Response, Next)> Service for Untimed<'_, H> {
    fn daemon_uid(&self) -> Option<u32> {
        self.daemon_uid
    }

    fn admits_foreign_peer(&self, request: &Request) -> bool {
        self.owner_token
            .is_some_and(|token| request.stdin.as_deref() == Some(&token[..]))
    }

    fn handle(&mut self, request: Request) -> (Response, Next) {
        if request.op == Op::Stop
            && let Some(token) = &self.owner_token
            && request.stdin.as_deref() != Some(&token[..])
        {
            return (stop_refusal(&request.argv, &self.dir), Next::Continue);
        }
        (self.handle)(request)
    }

    fn deadline(&self) -> Option<Time> {
        None
    }

    async fn tick(&mut self, _cx: &Cx) {}

    fn on_connection_closed(&mut self, timing: ConnectionTiming) {
        if self.timings.len() < MAX_DAEMON_CONNECTIONS {
            self.timings.push(timing);
        }
    }
}

#[derive(Debug)]
enum WaitError {
    Idle,
    Clock(clock::ClockError),
}

impl From<clock::ClockError> for WaitError {
    fn from(error: clock::ClockError) -> Self {
        Self::Clock(error)
    }
}

impl WaitError {
    fn frame(self) -> FrameError {
        match self {
            Self::Clock(clock::ClockError::Cancelled) => FrameError::Cancelled,
            Self::Clock(error) => FrameError::Io(std::io::ErrorKind::Other, error.to_string()),
            Self::Idle => FrameError::Io(std::io::ErrorKind::TimedOut, "idle connection".into()),
        }
    }
}

/// Keep one I/O future pinned while timer events are handled. In
/// particular a partially consumed frame prefix/payload stays inside its
/// original read_frame future until it completes or the connection ends.
async fn wait_io<F: Future, H: Service>(
    cx: &Cx,
    operation: F,
    idle: Option<Duration>,
    service: &mut H,
) -> Result<F::Output, WaitError> {
    let idle_deadline = match idle {
        Some(duration) => Some(clock::deadline_after(
            clock::timer(cx)?.now(),
            u64::try_from(duration.as_nanos()).map_err(|_| clock::ClockError::DeadlineOverflow)?,
        )?),
        None => None,
    };
    let mut operation = pin!(operation);
    loop {
        let next = match (idle_deadline, service.deadline()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let mut deadline = next.map(|at| clock::Deadline::new(cx, at)).transpose()?;
        enum Ready<T> {
            Io(T),
            Timer,
        }
        let ready = poll_fn(|task| {
            if cx.checkpoint().is_err() {
                return Poll::Ready(Err(WaitError::Clock(clock::ClockError::Cancelled)));
            }
            // Timer first: a stream of immediately-ready requests cannot
            // starve due work. After one cycle its next deadline is in the
            // future, so the retained I/O operation gets its turn.
            if let Some(timer) = deadline.as_mut()
                && let Poll::Ready(result) = Pin::new(timer).poll(task)
            {
                return Poll::Ready(result.map(|()| Ready::Timer).map_err(WaitError::Clock));
            }
            operation
                .as_mut()
                .poll(task)
                .map(|value| Ok(Ready::Io(value)))
        })
        .await?;
        match ready {
            Ready::Io(value) => return Ok(value),
            Ready::Timer => {
                if idle_deadline.is_some_and(|at| {
                    // A timer was constructed above, so the capability is
                    // present; failure below is handled before doing work.
                    cx.timer_driver().is_some_and(|timer| timer.now() >= at)
                }) {
                    return Err(WaitError::Idle);
                }
                clock::timer(cx)?;
                service.tick(cx).await;
            }
        }
    }
}

async fn write_served<S, H>(
    cx: &Cx,
    stream: &mut S,
    payload: &[u8],
    max: usize,
    service: &mut H,
) -> Result<(), FrameError>
where
    S: AsyncWrite + Unpin,
    H: Service,
{
    wait_io(cx, write_frame(cx, stream, payload, max), None, service)
        .await
        .map_err(WaitError::frame)?
}

async fn serve_connection_with<S, H>(
    cx: &Cx,
    stream: &mut S,
    limits: Limits,
    dir: &Path,
    service: &mut H,
) -> Ended
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: Service,
{
    loop {
        let frame = match wait_io(
            cx,
            read_frame(cx, stream, limits.max_frame_bytes),
            limits.idle,
            service,
        )
        .await
        {
            Ok(frame) => frame,
            Err(WaitError::Idle) => return Ended::Idle,
            Err(error) => return Ended::Fault(error.frame()),
        };
        let payload = match frame {
            Ok(None) => return Ended::Closed,
            Ok(Some(payload)) => payload,
            Err(fault @ (FrameError::TooLarge { .. } | FrameError::Malformed(_))) => {
                let reply = protocol_fault(&fault).to_json(limits.protocol).render();
                let _ = write_served(
                    cx,
                    stream,
                    reply.as_bytes(),
                    limits.max_frame_bytes,
                    service,
                )
                .await;
                return Ended::Fault(fault);
            }
            Err(fault) => return Ended::Fault(fault),
        };
        let request = canonical(&payload).and_then(|v| Request::from_json(&v, limits.protocol));
        let request = match request {
            Ok(r) => r,
            Err(fault) => {
                let reply = protocol_fault(&fault).to_json(limits.protocol).render();
                let _ = write_served(
                    cx,
                    stream,
                    reply.as_bytes(),
                    limits.max_frame_bytes,
                    service,
                )
                .await;
                return Ended::Fault(fault);
            }
        };
        let (response, next) = service.handle(request);
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
            let written = if next == Next::Stop {
                write_frame(cx, stream, reply.as_bytes(), limits.max_frame_bytes).await
            } else {
                write_served(
                    cx,
                    stream,
                    reply.as_bytes(),
                    limits.max_frame_bytes,
                    service,
                )
                .await
            };
            if written.is_err() {
                return Ended::Fault(fault);
            }
        } else {
            let written = if next == Next::Stop {
                // Once stop is accepted, no more automatic effects run.
                write_frame(cx, stream, reply.as_bytes(), limits.max_frame_bytes).await
            } else {
                write_served(
                    cx,
                    stream,
                    reply.as_bytes(),
                    limits.max_frame_bytes,
                    service,
                )
                .await
            };
            if let Err(fault) = written {
                return Ended::Fault(fault);
            }
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
    /// Present only after the local launcher explicitly authorizes a
    /// book-key System bootstrap. Wire requests never construct this.
    pub timed: Option<timed::TimedWork>,
    /// Kernel-certified effective UID of this daemon process (`SO_PEERCRED` / `LOCAL_PEERCRED`).
    pub daemon_uid: Option<u32>,
    /// Bounded ring of per-connection timings and outcomes (`fa-een`).
    pub timings: Vec<ConnectionTiming>,
}

impl Service for Server<'_> {
    fn daemon_uid(&self) -> Option<u32> {
        self.daemon_uid
    }

    fn admits_foreign_peer(&self, request: &Request) -> bool {
        let token = self.book.owner_token();
        request.stdin.as_deref() == Some(&token[..])
    }

    fn handle(&mut self, request: Request) -> (Response, Next) {
        Server::handle(self, request)
    }

    fn deadline(&self) -> Option<Time> {
        self.timed.as_ref().and_then(timed::TimedWork::deadline)
    }

    async fn tick(&mut self, cx: &Cx) {
        if let Some(work) = self.timed.as_mut() {
            work.run_due(cx, self.book).await;
        }
    }

    fn on_connection_closed(&mut self, timing: ConnectionTiming) {
        eprintln!(
            "fad connection #{} (uid={:?}, pid={:?}): {} requests in {} ns ({:?})",
            timing.conn_id, timing.peer_uid, timing.peer_pid, timing.requests, timing.elapsed_ns, timing.ended
        );
        if self.timings.len() >= MAX_DAEMON_CONNECTIONS {
            self.timings.remove(0);
        }
        self.timings.push(timing);
    }
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
                    stdout: line(
                        json,
                        "fad_status",
                        self.status_data(),
                        self.at().as_ref(),
                        &self.status_text(),
                    ),
                    stderr: String::new(),
                },
                Next::Continue,
            ),
            Op::Stop => {
                let expected = self.book.owner_token();
                if request.stdin.as_deref() != Some(&expected[..]) {
                    return (stop_refusal(&request.argv, &self.dir), Next::Continue);
                }
                (
                    Response {
                        op: Op::Stop,
                        exit: 0,
                        stdout: line(
                            json,
                            "fad_stopped",
                            self.stopped_data(),
                            None,
                            &self.stopped_text(),
                        ),
                        stderr: String::new(),
                    },
                    Next::Stop,
                )
            }
        }
    }

    /// The served book at its head, for the envelope of the daemon's own
    /// lines about it (null when the head cannot be read).
    #[must_use]
    pub fn at(&self) -> Option<cli::At> {
        self.book.head().ok().map(|known_at| cli::At {
            book: self.book.context().book_id.to_hex(),
            known_at,
            effective: "all".into(),
        })
    }

    /// `fad_status` data for a serving daemon.
    #[must_use]
    pub fn status_data(&self) -> Json {
        let mut fields = vec![
            ("serving", Json::Bool(true)),
            ("dir", s(self.dir.display().to_string())),
            ("socket", s(self.socket.display().to_string())),
            ("pid", Json::Int(i128::from(std::process::id()))),
            ("book_id", s(self.book.context().book_id.to_hex())),
            ("requests", Json::Int(i128::from(self.requests))),
            ("holder", Json::Null),
        ];
        fields.extend(timed::status_fields(self.timed.as_ref()));
        obj(fields)
    }

    fn status_text(&self) -> String {
        format!(
            "fad serving {} (pid {}, book {}) on {} · {} requests answered · {}",
            self.dir.display(),
            std::process::id(),
            self.book.context().book_id.to_hex(),
            self.socket.display(),
            self.requests,
            timed::status_text(self.timed.as_ref()),
        )
    }

    /// `fad_stopped` data: the requests answered before the lease was released.
    #[must_use]
    pub fn stopped_data(&self) -> Json {
        obj(vec![
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

/// One stdout line of the daemon's own: in robot mode the plan Appendix D
/// line (`data` the event's fields; `book` and `coordinate` when `at` names
/// the served book), the text otherwise.
#[must_use]
pub fn line(json: bool, event: &str, data: Json, at: Option<&cli::At>, text: &str) -> String {
    if json {
        format!("{}\n", cli::robot_line(event, data, at, &[]).render())
    } else {
        format!("{text}\n")
    }
}

enum ConnRegion {
    Owned(ChildRegion),
    Inherited,
}

impl ConnRegion {
    async fn open(parent: &Cx) -> std::io::Result<Self> {
        match parent.open_child_region(ChildRegionSpec::inherit()).await {
            Ok(region) => Ok(Self::Owned(region)),
            Err(ChildRegionError::NoRuntimeGateway) => Ok(Self::Inherited),
            Err(e) => Err(std::io::Error::other(format!("connection region: {e:?}"))),
        }
    }

    async fn close(self) {
        if let Self::Owned(region) = self {
            let _ = region.close().await;
        }
    }
}

#[derive(Clone, Debug)]
enum AfterWrite {
    Continue,
    OversizedContinue(FrameError),
    Close(Ended),
}

enum Phase {
    Reading {
        prefix: [u8; PREFIX_BYTES],
        got_prefix: usize,
        payload: Vec<u8>,
        filled: usize,
        deadline: Option<Time>,
    },
    Writing {
        frame: Vec<u8>,
        written: usize,
        flushed: bool,
        after: AfterWrite,
    },
}

impl Phase {
    fn new_reading(cx: &Cx, idle: Option<Duration>) -> Result<Self, clock::ClockError> {
        let deadline = match idle {
            Some(duration) => Some(clock::deadline_after(
                clock::timer(cx)?.now(),
                u64::try_from(duration.as_nanos()).map_err(|_| clock::ClockError::DeadlineOverflow)?,
            )?),
            None => None,
        };
        Ok(Self::Reading {
            prefix: [0u8; PREFIX_BYTES],
            got_prefix: 0,
            payload: Vec::new(),
            filled: 0,
            deadline,
        })
    }
}

enum ConnStep {
    FrameRead(Vec<u8>),
    ReadFault(FrameError),
    WriteDone,
    Ended(Ended),
}

struct ConnSlot<S> {
    id: u64,
    region: ConnRegion,
    stream: S,
    peer: Option<PeerCred>,
    started_ns: u64,
    requests: u64,
    phase: Phase,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ConnSlot<S> {
    fn deadline(&self) -> Option<Time> {
        match &self.phase {
            Phase::Reading { deadline, .. } => *deadline,
            Phase::Writing { .. } => None,
        }
    }

    fn queue_write(&mut self, payload: &[u8], max_frame_bytes: usize, after: AfterWrite) -> Result<(), Ended> {
        match encode(payload, max_frame_bytes) {
            Ok(frame) => {
                self.phase = Phase::Writing {
                    frame,
                    written: 0,
                    flushed: false,
                    after,
                };
                Ok(())
            }
            Err(fault) => Err(match after {
                AfterWrite::OversizedContinue(orig) | AfterWrite::Close(Ended::Fault(orig)) => {
                    Ended::Fault(orig)
                }
                _ => Ended::Fault(fault),
            }),
        }
    }

    fn poll_step(&mut self, task: &mut Context<'_>, max_frame_bytes: usize) -> Poll<ConnStep> {
        match &mut self.phase {
            Phase::Reading {
                prefix,
                got_prefix,
                payload,
                filled,
                ..
            } => {
                while *got_prefix < PREFIX_BYTES {
                    let mut buf = ReadBuf::new(&mut prefix[*got_prefix..]);
                    match Pin::new(&mut self.stream).poll_read(task, &mut buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            return Poll::Ready(ConnStep::Ended(Ended::Fault(FrameError::Io(
                                e.kind(),
                                e.to_string(),
                            ))));
                        }
                        Poll::Ready(Ok(())) => {
                            let n = buf.filled().len();
                            if n == 0 {
                                return if *got_prefix == 0 {
                                    Poll::Ready(ConnStep::Ended(Ended::Closed))
                                } else {
                                    Poll::Ready(ConnStep::Ended(Ended::Fault(
                                        FrameError::Truncated {
                                            got: *got_prefix,
                                            expected: PREFIX_BYTES,
                                        },
                                    )))
                                };
                            }
                            *got_prefix += n;
                            if *got_prefix == PREFIX_BYTES {
                                match announced(*prefix, max_frame_bytes) {
                                    Ok(len) => {
                                        *payload = vec![0u8; len];
                                        *filled = 0;
                                    }
                                    Err(fault) => return Poll::Ready(ConnStep::ReadFault(fault)),
                                }
                            }
                        }
                    }
                }
                while *filled < payload.len() {
                    let mut buf = ReadBuf::new(&mut payload[*filled..]);
                    match Pin::new(&mut self.stream).poll_read(task, &mut buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            return Poll::Ready(ConnStep::Ended(Ended::Fault(FrameError::Io(
                                e.kind(),
                                e.to_string(),
                            ))));
                        }
                        Poll::Ready(Ok(())) => {
                            let n = buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(ConnStep::Ended(Ended::Fault(
                                    FrameError::Truncated {
                                        got: PREFIX_BYTES + *filled,
                                        expected: PREFIX_BYTES + payload.len(),
                                    },
                                )));
                            }
                            *filled += n;
                        }
                    }
                }
                let bytes = core::mem::take(payload);
                Poll::Ready(ConnStep::FrameRead(bytes))
            }
            Phase::Writing {
                frame,
                written,
                flushed,
                after,
            } => {
                while *written < frame.len() {
                    match Pin::new(&mut self.stream).poll_write(task, &frame[*written..]) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            let ended = match after {
                                AfterWrite::OversizedContinue(fault)
                                | AfterWrite::Close(Ended::Fault(fault)) => {
                                    Ended::Fault(fault.clone())
                                }
                                _ => Ended::Fault(FrameError::Io(e.kind(), e.to_string())),
                            };
                            return Poll::Ready(ConnStep::Ended(ended));
                        }
                        Poll::Ready(Ok(0)) => {
                            let ended = match after {
                                AfterWrite::OversizedContinue(fault)
                                | AfterWrite::Close(Ended::Fault(fault)) => {
                                    Ended::Fault(fault.clone())
                                }
                                _ => Ended::Fault(FrameError::Io(
                                    std::io::ErrorKind::WriteZero,
                                    "write zero".into(),
                                )),
                            };
                            return Poll::Ready(ConnStep::Ended(ended));
                        }
                        Poll::Ready(Ok(n)) => {
                            *written += n;
                        }
                    }
                }
                if !*flushed {
                    match Pin::new(&mut self.stream).poll_flush(task) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            let ended = match after {
                                AfterWrite::OversizedContinue(fault)
                                | AfterWrite::Close(Ended::Fault(fault)) => {
                                    Ended::Fault(fault.clone())
                                }
                                _ => Ended::Fault(FrameError::Io(e.kind(), e.to_string())),
                            };
                            return Poll::Ready(ConnStep::Ended(ended));
                        }
                        Poll::Ready(Ok(())) => {
                            *flushed = true;
                        }
                    }
                }
                match after {
                    AfterWrite::Continue | AfterWrite::OversizedContinue(_) => {
                        Poll::Ready(ConnStep::WriteDone)
                    }
                    AfterWrite::Close(ended) => Poll::Ready(ConnStep::Ended(ended.clone())),
                }
            }
        }
    }
}

/// Accept connections on `listener` for the book at `dir` and serve them
/// concurrently until an authorized `stop` is answered.
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
    let mut service = Untimed::new(handle);
    service.dir = dir.to_path_buf();
    serve_with(cx, listener, limits, dir, &mut service).await
}

/// Accept connections on any [`Listener`] (Unix socket or virtual lab listener),
/// enforcing optional peer-UID and owner-token checks, and return per-connection
/// timings once an authorized `stop` is answered.
pub async fn serve_listener<L, H>(
    cx: &Cx,
    listener: &L,
    limits: Limits,
    dir: &Path,
    daemon_uid: Option<u32>,
    owner_token: Option<[u8; 32]>,
    handle: &mut H,
) -> std::io::Result<Vec<ConnectionTiming>>
where
    L: Listener,
    H: FnMut(Request) -> (Response, Next),
{
    let mut service = Untimed {
        handle,
        daemon_uid,
        owner_token,
        dir: dir.to_path_buf(),
        timings: Vec::new(),
    };
    serve_with(cx, listener, limits, dir, &mut service).await?;
    Ok(service.timings)
}

/// Serve the held book with its optional launch-configured timed work in
/// the same region and on the same writer as foreground requests.
pub async fn serve_book(
    cx: &Cx,
    listener: &asupersync::net::unix::UnixListener,
    limits: Limits,
    server: &mut Server<'_>,
) -> std::io::Result<()> {
    let dir = server.dir.clone();
    serve_with(cx, listener, limits, &dir, server).await
}

async fn finish_connection<S, H: Service>(
    cx: &Cx,
    conn: ConnSlot<S>,
    ended: Ended,
    service: &mut H,
) {
    let now_ns = clock::timer(cx).map_or(conn.started_ns, |t| t.now().as_nanos());
    service.on_connection_closed(ConnectionTiming {
        conn_id: conn.id,
        peer_uid: conn.peer.map(|p| p.uid),
        peer_pid: conn.peer.and_then(|p| p.pid),
        requests: conn.requests,
        elapsed_ns: now_ns.saturating_sub(conn.started_ns),
        ended,
    });
    conn.region.close().await;
}

async fn serve_with<L: Listener, H: Service>(
    cx: &Cx,
    listener: &L,
    limits: Limits,
    dir: &Path,
    service: &mut H,
) -> std::io::Result<()> {
    let mut connections: Vec<ConnSlot<L::Stream>> = Vec::new();
    let mut next_conn_id: u64 = 0;
    let mut rr_cursor: usize = 0;
    let mut accept_first = true;

    loop {
        if let Err(e) = cx.checkpoint() {
            for conn in connections.drain(..) {
                conn.region.close().await;
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                format!("{e:?}"),
            ));
        }

        let mut next_deadline = service.deadline();
        for conn in &connections {
            if let Some(d) = conn.deadline() {
                next_deadline = Some(match next_deadline {
                    Some(cur) => cur.min(d),
                    None => d,
                });
            }
        }
        let mut deadline = next_deadline
            .map(|at| clock::Deadline::new(cx, at))
            .transpose()
            .map_err(|e| std::io::Error::other(format!("{}", WaitError::Clock(e).frame())))?;

        enum Ready<S> {
            Timer,
            Accepted(S, Option<PeerCred>),
            Conn(usize, ConnStep),
        }

        let can_accept = connections.len() < MAX_DAEMON_CONNECTIONS;
        let cursor = if connections.is_empty() {
            0
        } else {
            rr_cursor % connections.len()
        };
        let try_accept_first = accept_first && can_accept;

        let ready = poll_fn(|task| {
            if cx.checkpoint().is_err() {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }
            if let Some(timer) = deadline.as_mut()
                && let Poll::Ready(result) = Pin::new(timer).poll(task)
            {
                return Poll::Ready(
                    result
                        .map(|()| Ready::Timer)
                        .map_err(|e| std::io::Error::other(format!("{}", WaitError::Clock(e).frame()))),
                );
            }
            if try_accept_first {
                match listener.poll_accept(task) {
                    Poll::Ready(Ok((stream, peer))) => {
                        return Poll::Ready(Ok(Ready::Accepted(stream, peer)));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
            }
            let len = connections.len();
            for offset in 0..len {
                let idx = (cursor + offset) % len;
                if let Poll::Ready(step) = connections[idx].poll_step(task, limits.max_frame_bytes)
                {
                    return Poll::Ready(Ok(Ready::Conn(idx, step)));
                }
            }
            if !try_accept_first && can_accept {
                match listener.poll_accept(task) {
                    Poll::Ready(Ok((stream, peer))) => {
                        return Poll::Ready(Ok(Ready::Accepted(stream, peer)));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        })
        .await;

        accept_first = !accept_first;

        let ready = match ready {
            Ok(r) => r,
            Err(e) => {
                for conn in connections.drain(..) {
                    conn.region.close().await;
                }
                return Err(e);
            }
        };

        match ready {
            Ready::Timer => {
                let now = clock::timer(cx)
                    .map_err(|e| std::io::Error::other(format!("{}", WaitError::Clock(e).frame())))?
                    .now();
                let mut i = 0;
                while i < connections.len() {
                    if connections[i].deadline().is_some_and(|at| now >= at) {
                        let expired = connections.remove(i);
                        finish_connection(cx, expired, Ended::Idle, service).await;
                    } else {
                        i += 1;
                    }
                }
                if service.deadline().is_some_and(|at| now >= at) {
                    service.tick(cx).await;
                }
            }
            Ready::Accepted(stream, peer) => {
                next_conn_id = next_conn_id.saturating_add(1);
                let region = ConnRegion::open(cx).await?;
                let started_ns = clock::timer(cx).map_or(0, |t| t.now().as_nanos());
                let phase = Phase::new_reading(cx, limits.idle).map_err(|e| {
                    std::io::Error::other(format!("{}", WaitError::Clock(e).frame()))
                })?;
                connections.push(ConnSlot {
                    id: next_conn_id,
                    region,
                    stream,
                    peer,
                    started_ns,
                    requests: 0,
                    phase,
                });
            }
            Ready::Conn(idx, step) => {
                rr_cursor = idx.wrapping_add(1);
                match step {
                    ConnStep::ReadFault(fault) => {
                        let reply = protocol_fault(&fault).to_json(limits.protocol).render();
                        let after = AfterWrite::Close(Ended::Fault(fault));
                        if let Err(ended) = connections[idx].queue_write(
                            reply.as_bytes(),
                            limits.max_frame_bytes,
                            after,
                        ) {
                            let conn = connections.remove(idx);
                            finish_connection(cx, conn, ended, service).await;
                        }
                    }
                    ConnStep::FrameRead(payload) => {
                        let parsed = canonical(&payload)
                            .and_then(|v| Request::from_json(&v, limits.protocol));
                        let request = match parsed {
                            Ok(r) => r,
                            Err(fault) => {
                                let reply =
                                    protocol_fault(&fault).to_json(limits.protocol).render();
                                let after = AfterWrite::Close(Ended::Fault(fault));
                                if let Err(ended) = connections[idx].queue_write(
                                    reply.as_bytes(),
                                    limits.max_frame_bytes,
                                    after,
                                ) {
                                    let conn = connections.remove(idx);
                                    finish_connection(cx, conn, ended, service).await;
                                }
                                continue;
                            }
                        };
                        if let (Some(peer), Some(daemon_uid)) =
                            (connections[idx].peer, service.daemon_uid())
                            && peer.uid != daemon_uid
                            && !service.admits_foreign_peer(&request)
                        {
                            let response =
                                peer_uid_refusal(&request, peer.uid, daemon_uid, dir);
                            let reply = response.to_json(limits.protocol).render();
                            let after = AfterWrite::Close(Ended::UnauthorizedPeer {
                                peer_uid: peer.uid,
                                daemon_uid,
                            });
                            if let Err(ended) = connections[idx].queue_write(
                                reply.as_bytes(),
                                limits.max_frame_bytes,
                                after,
                            ) {
                                let conn = connections.remove(idx);
                                finish_connection(cx, conn, ended, service).await;
                            }
                            continue;
                        }
                        connections[idx].requests = connections[idx].requests.saturating_add(1);
                        let (response, next) = service.handle(request);
                        let mut reply = response.to_json(limits.protocol).render();
                        let after = if reply.len() > limits.max_frame_bytes {
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
                            if next == Next::Stop {
                                AfterWrite::Close(Ended::Stop)
                            } else {
                                AfterWrite::OversizedContinue(fault)
                            }
                        } else if next == Next::Stop {
                            AfterWrite::Close(Ended::Stop)
                        } else {
                            AfterWrite::Continue
                        };
                        if let Err(ended) = connections[idx].queue_write(
                            reply.as_bytes(),
                            limits.max_frame_bytes,
                            after,
                        ) {
                            let conn = connections.remove(idx);
                            finish_connection(cx, conn, ended, service).await;
                        }
                    }
                    ConnStep::WriteDone => {
                        match Phase::new_reading(cx, limits.idle) {
                            Ok(phase) => connections[idx].phase = phase,
                            Err(e) => {
                                let conn = connections.remove(idx);
                                finish_connection(
                                    cx,
                                    conn,
                                    Ended::Fault(WaitError::Clock(e).frame()),
                                    service,
                                )
                                .await;
                            }
                        }
                    }
                    ConnStep::Ended(ended) => {
                        let is_stop = ended == Ended::Stop;
                        let conn = connections.remove(idx);
                        finish_connection(cx, conn, ended, service).await;
                        if is_stop {
                            for remaining in connections.drain(..) {
                                finish_connection(cx, remaining, Ended::Closed, service).await;
                            }
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod lab_tests;
