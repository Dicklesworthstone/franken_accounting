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
//! region and one serving task: it waits on the listener and on every open
//! connection's next frame at once (at most `max_connections`), takes ready
//! connections in turn so none waits behind another's idle or dribbling
//! peer, and answers one frame at a time (the book has one writer). Reads
//! and writes are each bounded by the idle timeout, and nothing is detached.
//! A malformed, oversized, or non-canonical frame is
//! answered with a structured usage error and the connection closes; a
//! truncated frame or a vanished peer just ends the connection. Neither ever
//! reaches the book.

#![forbid(unsafe_code)]

pub mod clock;
pub mod timed;

use core::future::{Future, poll_fn};
use core::pin::{Pin, pin};
use core::task::Poll;
use std::path::{Path, PathBuf};
use std::time::Duration;

use asupersync::Cx;
use asupersync::io::{AsyncRead, AsyncWrite};
use asupersync::types::Time;
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
    /// registry's idle timeout. It also bounds writing one answer.
    pub idle: Option<Duration>,
    /// The most connections served at once; the listener is not polled
    /// while this many are open.
    pub max_connections: usize,
}

impl Limits {
    #[must_use]
    pub fn from_registry(d: &Daemon) -> Self {
        Self {
            protocol: d.protocol,
            max_frame_bytes: d.max_frame_bytes,
            idle: Some(Duration::from_millis(d.idle_timeout_ms)),
            max_connections: d.max_connections,
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
    serve_connection_with(cx, stream, limits, dir, &mut Untimed(handle)).await
}

/// Timed work a wait keeps running: the served book's scheduled cycles, or
/// none while one connection waits for its own next frame.
trait Ticks {
    fn deadline(&self) -> Option<Time>;
    async fn tick(&mut self, cx: &Cx);
}

/// The same framing loop serves a real book with scheduled work and the
/// protocol-only lab handlers. Timing never owns a second book writer.
trait Service: Ticks {
    fn handle(&mut self, request: Request) -> (Response, Next);
}

/// No timed work.
struct NoTicks;

impl Ticks for NoTicks {
    fn deadline(&self) -> Option<Time> {
        None
    }

    async fn tick(&mut self, _cx: &Cx) {}
}

struct Untimed<'a, H>(&'a mut H);

impl<H: FnMut(Request) -> (Response, Next)> Service for Untimed<'_, H> {
    fn handle(&mut self, request: Request) -> (Response, Next) {
        self.0(request)
    }
}

impl<H> Ticks for Untimed<'_, H> {
    fn deadline(&self) -> Option<Time> {
        None
    }

    async fn tick(&mut self, _cx: &Cx) {}
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
async fn wait_io<F: Future, H: Ticks>(
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

/// Write one answer while `service`'s timed work keeps running; the write
/// is bounded by the idle timeout, so a peer that never reads cannot hold
/// the serving task.
async fn write_served<S, H>(
    cx: &Cx,
    stream: &mut S,
    payload: &[u8],
    limits: Limits,
    service: &mut H,
) -> Result<(), FrameError>
where
    S: AsyncWrite + Unpin,
    H: Ticks,
{
    wait_io(
        cx,
        write_frame(cx, stream, payload, limits.max_frame_bytes),
        limits.idle,
        service,
    )
    .await
    .map_err(WaitError::frame)?
}

/// What waiting for one connection's next frame produced.
type ReadOutcome = Result<Result<Option<Vec<u8>>, FrameError>, WaitError>;

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
        let frame = wait_io(
            cx,
            read_frame(cx, stream, limits.max_frame_bytes),
            limits.idle,
            service,
        )
        .await;
        if let Some(ended) = answer(cx, stream, frame, limits, dir, service).await {
            return ended;
        }
    }
}

/// Answer what one read produced on `stream`: `None` keeps the connection
/// for its next frame; otherwise how it ended.
async fn answer<S, H>(
    cx: &Cx,
    stream: &mut S,
    frame: ReadOutcome,
    limits: Limits,
    dir: &Path,
    service: &mut H,
) -> Option<Ended>
where
    S: AsyncWrite + Unpin,
    H: Service,
{
    let frame = match frame {
        Ok(frame) => frame,
        Err(WaitError::Idle) => return Some(Ended::Idle),
        Err(error) => return Some(Ended::Fault(error.frame())),
    };
    let payload = match frame {
        Ok(None) => return Some(Ended::Closed),
        Ok(Some(payload)) => payload,
        Err(fault @ (FrameError::TooLarge { .. } | FrameError::Malformed(_))) => {
            let reply = protocol_fault(&fault).to_json(limits.protocol).render();
            let _ = write_served(cx, stream, reply.as_bytes(), limits, service).await;
            return Some(Ended::Fault(fault));
        }
        Err(fault) => return Some(Ended::Fault(fault)),
    };
    let request = canonical(&payload).and_then(|v| Request::from_json(&v, limits.protocol));
    let request = match request {
        Ok(r) => r,
        Err(fault) => {
            let reply = protocol_fault(&fault).to_json(limits.protocol).render();
            let _ = write_served(cx, stream, reply.as_bytes(), limits, service).await;
            return Some(Ended::Fault(fault));
        }
    };
    let (response, next) = service.handle(request);
    let mut reply = response.to_json(limits.protocol).render();
    let mut oversized = None;
    if reply.len() > limits.max_frame_bytes {
        // An answer too large for one frame is refused as a whole, never
        // cut. A direct run needs the writer lease this daemon holds, so
        // the advice names stopping it first.
        oversized = Some(FrameError::TooLarge {
            announced: reply.len(),
            max: limits.max_frame_bytes,
        });
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
    }
    let written = if next == Next::Stop {
        // Once stop is accepted, no more automatic effects run.
        write_served(cx, stream, reply.as_bytes(), limits, &mut NoTicks).await
    } else {
        write_served(cx, stream, reply.as_bytes(), limits, service).await
    };
    if let Err(fault) = written {
        return Some(Ended::Fault(oversized.unwrap_or(fault)));
    }
    (next == Next::Stop).then_some(Ended::Stop)
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
}

impl Service for Server<'_> {
    fn handle(&mut self, request: Request) -> (Response, Next) {
        Server::handle(self, request)
    }
}

impl Ticks for Server<'_> {
    fn deadline(&self) -> Option<Time> {
        self.timed.as_ref().and_then(timed::TimedWork::deadline)
    }

    async fn tick(&mut self, cx: &Cx) {
        if let Some(work) = self.timed.as_mut() {
            work.run_due(cx, self.book).await;
        }
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
            Op::Stop => (
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
            ),
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

/// Accept connections on `listener` for the book at `dir` and serve them
/// all from this task, one frame at a time, until a `stop` is answered.
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
    serve_with(cx, listener, limits, dir, &mut Untimed(handle)).await
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

async fn serve_with<H: Service>(
    cx: &Cx,
    listener: &asupersync::net::unix::UnixListener,
    limits: Limits,
    dir: &Path,
    service: &mut H,
) -> std::io::Result<()> {
    let accept = move || async move { listener.accept().await.map(|(stream, _)| stream) };
    serve_many(cx, accept, limits, dir, service).await
}

/// One connection's next frame, read by a future that owns its stream, so
/// the serving task can wait on every open connection at once.
type NextFrame<'a, S> = Pin<Box<dyn Future<Output = (S, ReadOutcome)> + 'a>>;

fn next_frame<'a, S>(cx: &'a Cx, mut stream: S, limits: Limits) -> NextFrame<'a, S>
where
    S: AsyncRead + Unpin + 'a,
{
    Box::pin(async move {
        let read = read_frame(cx, &mut stream, limits.max_frame_bytes);
        let frame = wait_io(cx, read, limits.idle, &mut NoTicks).await;
        (stream, frame)
    })
}

fn wait_failed(error: clock::ClockError) -> std::io::Error {
    std::io::Error::other(format!("{}", WaitError::Clock(error).frame()))
}

/// Serve every connection `accept` yields from this one task until a `stop`
/// is answered: due timed work first, then ready connections in turn
/// (starting after the one last served, so a peer that always has a frame
/// cannot starve another), then the listener while fewer than
/// `max_connections` are open. A peer that idles or dribbles a frame holds
/// only its own connection, which its idle bound closes.
async fn serve_many<'a, S, A, F, H>(
    cx: &'a Cx,
    mut accept: A,
    limits: Limits,
    dir: &Path,
    service: &mut H,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + 'a,
    A: FnMut() -> F,
    F: Future<Output = std::io::Result<S>>,
    H: Service,
{
    enum Event<S> {
        Tick,
        Accepted(std::io::Result<S>),
        Frame(usize, (S, ReadOutcome)),
    }
    let mut open: Vec<NextFrame<'a, S>> = Vec::new();
    let mut accepting = Box::pin(accept());
    let mut turn = 0;
    loop {
        cx.checkpoint()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Interrupted, format!("{e:?}")))?;
        let mut deadline = service
            .deadline()
            .map(|at| clock::Deadline::new(cx, at))
            .transpose()
            .map_err(wait_failed)?;
        let event = poll_fn(|task| {
            if cx.checkpoint().is_err() {
                return Poll::Ready(Err(clock::ClockError::Cancelled));
            }
            if let Some(timer) = deadline.as_mut()
                && let Poll::Ready(result) = Pin::new(timer).poll(task)
            {
                return Poll::Ready(result.map(|()| Event::Tick));
            }
            let n = open.len();
            for k in 0..n {
                let i = (turn + k) % n;
                if let Poll::Ready(read) = open[i].as_mut().poll(task) {
                    return Poll::Ready(Ok(Event::Frame(i, read)));
                }
            }
            if n < limits.max_connections
                && let Poll::Ready(accepted) = accepting.as_mut().poll(task)
            {
                return Poll::Ready(Ok(Event::Accepted(accepted)));
            }
            Poll::Pending
        })
        .await
        .map_err(wait_failed)?;
        match event {
            Event::Tick => {
                clock::timer(cx).map_err(wait_failed)?;
                service.tick(cx).await;
            }
            Event::Accepted(stream) => {
                accepting = Box::pin(accept());
                open.push(next_frame(cx, stream?, limits));
            }
            Event::Frame(i, (mut stream, read)) => {
                drop(open.remove(i));
                turn = i;
                match answer(cx, &mut stream, read, limits, dir, service).await {
                    None => open.push(next_frame(cx, stream, limits)),
                    Some(Ended::Stop) => return Ok(()),
                    Some(_) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod lab_tests;
