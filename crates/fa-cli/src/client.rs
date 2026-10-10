//! The `fa` side of the `fad` transport: connect to a book's daemon socket,
//! send one [`Request`], read its one [`Response`] (see [`crate::wire`]).
//! The socket I/O runs on an asupersync runtime under a request `Cx`.

use std::path::Path;

use asupersync::Budget;
use asupersync::net::unix::UnixStream;
use asupersync::runtime::RuntimeBuilder;

use crate::verbs::Daemon;
use crate::wire::{FrameError, Request, Response, canonical, read_frame, write_frame};

/// Why a call did not produce a response.
#[derive(Debug)]
pub enum ClientError {
    /// Nothing accepted the connection: no daemon serves this socket.
    Connect(std::io::Error),
    /// The connection broke or a frame was refused.
    Frame(FrameError),
    /// The local runtime could not start.
    Runtime(String),
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connect: {e}"),
            Self::Frame(e) => write!(f, "{e}"),
            Self::Runtime(e) => write!(f, "runtime: {e}"),
        }
    }
}

impl From<FrameError> for ClientError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

/// Send `request` to the daemon at `socket` and return its response.
pub fn call(socket: &Path, request: &Request, daemon: &Daemon) -> Result<Response, ClientError> {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .map_err(|e| ClientError::Runtime(format!("{e:?}")))?;
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    runtime.block_on(async {
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(ClientError::Connect)?;
        let payload = request.to_json(daemon.protocol).render();
        write_frame(&cx, &mut stream, payload.as_bytes(), daemon.max_frame_bytes).await?;
        let reply = read_frame(&cx, &mut stream, daemon.max_frame_bytes)
            .await?
            .ok_or(FrameError::Truncated {
                got: 0,
                expected: crate::wire::PREFIX_BYTES,
            })?;
        Ok(Response::from_json(&canonical(&reply)?, daemon.protocol)?)
    })
}
