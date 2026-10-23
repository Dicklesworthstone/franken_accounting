//! The `fa` side of the `fad` transport: connect to a book's daemon socket,
//! send one [`Request`], read its one [`Response`] (see [`crate::wire`]).
//! The socket I/O runs on an asupersync runtime under a request `Cx`.
//! One absolute, registered deadline bounds connection, request transmission
//! and response reception together. A timeout does not retry a write: fad
//! may already have committed it, so the caller must recover its outcome.

use std::cell::Cell;
use std::future::{Future, poll_fn};
use std::path::Path;
use std::pin::{Pin, pin};
use std::task::{Context, Poll};

use asupersync::net::unix::UnixStream;
use asupersync::runtime::RuntimeBuilder;
use asupersync::time::{TimerDriverHandle, TimerHandle};
use asupersync::types::Time;
use asupersync::{Budget, Cx};

use crate::verbs::Daemon;
use crate::wire::{FrameError, Request, Response, canonical, read_frame, write_frame};

/// The transport phase in which the request's deadline expired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Connecting,
    SendingRequest,
    ReceivingResponse,
}

impl core::fmt::Display for Phase {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Connecting => "connecting",
            Self::SendingRequest => "sending the request",
            Self::ReceivingResponse => "receiving the response",
        })
    }
}

/// Why a call did not produce a response.
#[derive(Debug)]
pub enum ClientError {
    /// Nothing accepted the connection: no daemon serves this socket.
    Connect(std::io::Error),
    /// The connection broke or a frame was refused.
    Frame(FrameError),
    /// The complete call exceeded the registered request deadline. Once
    /// transmission starts this does not establish whether a write committed.
    Timeout { timeout_ms: u64, phase: Phase },
    /// The local runtime could not start.
    Runtime(String),
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connect: {e}"),
            Self::Frame(e) => write!(f, "{e}"),
            Self::Timeout { timeout_ms, phase } => {
                write!(
                    f,
                    "request timed out after {timeout_ms} ms while {phase} ([daemon] request_timeout_ms); check `fad status --book <dir>`"
                )?;
                if *phase != Phase::Connecting {
                    f.write_str(
                        "; the request may already have committed: confirm its outcome before retrying; any idempotent retry must use the unchanged request and its original key",
                    )?;
                }
                Ok(())
            }
            Self::Runtime(e) => write!(f, "runtime: {e}"),
        }
    }
}

impl From<FrameError> for ClientError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

/// A timer tied to the request's actual capability, never an ambient timer
/// or a detached thread. Re-arm horizon wakes against the original deadline;
/// partial I/O cannot extend the call. Dropping either outcome cancels it.
struct Deadline {
    driver: TimerDriverHandle,
    at: Time,
    handle: Option<TimerHandle>,
}

impl Deadline {
    fn new(cx: &Cx, timeout_ms: u64) -> Result<Self, ClientError> {
        let driver = cx.timer_driver().ok_or_else(|| {
            ClientError::Runtime("a daemon call requires a Cx timer driver".into())
        })?;
        let nanos = timeout_ms.checked_mul(1_000_000).filter(|n| *n > 0);
        let at = nanos
            .and_then(|n| driver.now().as_nanos().checked_add(n))
            .map(Time::from_nanos)
            .ok_or_else(|| {
                ClientError::Runtime(
                    "[daemon] request_timeout_ms must be non-zero and fit the monotonic clock"
                        .into(),
                )
            })?;
        Ok(Self {
            driver,
            at,
            handle: None,
        })
    }
}

impl Future for Deadline {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, task: &mut Context<'_>) -> Poll<Self::Output> {
        if self.driver.now() >= self.at {
            return Poll::Ready(());
        }
        // The timer wheel may spend a handle at its horizon before the true
        // deadline. Cancel and register again rather than updating a spent one.
        if let Some(handle) = self.handle.take() {
            let _ = self.driver.cancel(&handle);
        }
        self.handle = Some(self.driver.register(self.at, task.waker().clone()));
        Poll::Pending
    }
}

impl Drop for Deadline {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = self.driver.cancel(&handle);
        }
    }
}

/// Send `request` to the daemon at `socket` and return its response.
pub fn call(socket: &Path, request: &Request, daemon: &Daemon) -> Result<Response, ClientError> {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .map_err(|e| ClientError::Runtime(format!("{e:?}")))?;
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let mut deadline = Deadline::new(&cx, daemon.request_timeout_ms)?;
    let phase = Cell::new(Phase::Connecting);
    let mut operation = pin!(async {
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(ClientError::Connect)?;
        phase.set(Phase::SendingRequest);
        let payload = request.to_json(daemon.protocol).render();
        write_frame(&cx, &mut stream, payload.as_bytes(), daemon.max_frame_bytes).await?;
        phase.set(Phase::ReceivingResponse);
        let reply = read_frame(&cx, &mut stream, daemon.max_frame_bytes)
            .await?
            .ok_or(FrameError::Truncated {
                got: 0,
                expected: crate::wire::PREFIX_BYTES,
            })?;
        Ok(Response::from_json(&canonical(&reply)?, daemon.protocol)?)
    });
    runtime.block_on(poll_fn(|task| {
        if Pin::new(&mut deadline).poll(task).is_ready() {
            return Poll::Ready(Err(ClientError::Timeout {
                timeout_ms: daemon.request_timeout_ms,
                phase: phase.get(),
            }));
        }
        operation.as_mut().poll(task)
    }))
}

#[cfg(test)]
mod tests;
