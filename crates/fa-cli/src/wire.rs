//! The `fad` frame protocol (plan §15.3, Appendix D; bead fa-i8j).
//!
//! A frame is a 4-byte big-endian length followed by exactly that many bytes
//! of **canonical JSON**: UTF-8, integers only (no floats anywhere), object
//! keys sorted, no insignificant whitespace — the bytes [`Json::render`]
//! produces. A receiver re-renders what it parsed and refuses a payload that
//! is not byte-identical, so a frame has one spelling. The limit on a
//! payload's length (`[daemon] max_frame_bytes` in `registries/verbs.toml`)
//! is checked on the 4-byte prefix, before a single payload byte is read.
//!
//! The first frame on a connection is a [`Request`]; every request is
//! answered by exactly one [`Response`]. The codec is in-house (closed
//! dependency universe: no serde); the transport is any asupersync
//! `AsyncRead + AsyncWrite` stream — a Unix socket in production, a virtual
//! stream pair under the lab runtime.

use asupersync::Cx;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::json::{self, Json, obj, s};

/// The length prefix's size.
pub const PREFIX_BYTES: usize = 4;

/// Why a frame could not be read, written, or understood.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The prefix announces more than the limit (nothing after it was read).
    TooLarge { announced: usize, max: usize },
    /// The stream ended inside a frame, after `got` of `expected` bytes
    /// (prefix included).
    Truncated { got: usize, expected: usize },
    /// The payload is not canonical JSON, or not the expected object.
    Malformed(String),
    /// The task was cancelled between frames.
    Cancelled,
    /// The transport failed.
    Io(std::io::ErrorKind, String),
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge { announced, max } => {
                write!(f, "frame announces {announced} bytes; the limit is {max}")
            }
            Self::Truncated { got, expected } => write!(
                f,
                "the stream ended inside a frame ({got} of {expected} bytes)"
            ),
            Self::Malformed(why) => write!(f, "malformed frame: {why}"),
            Self::Cancelled => f.write_str("cancelled"),
            Self::Io(kind, what) => write!(f, "transport: {kind:?}: {what}"),
        }
    }
}

fn io(e: &std::io::Error) -> FrameError {
    FrameError::Io(e.kind(), e.to_string())
}

/// The prefix and payload of one frame.
pub fn encode(payload: &[u8], max: usize) -> Result<Vec<u8>, FrameError> {
    if payload.len() > max {
        return Err(FrameError::TooLarge {
            announced: payload.len(),
            max,
        });
    }
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge {
        announced: payload.len(),
        max,
    })?;
    let mut frame = Vec::with_capacity(PREFIX_BYTES + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// The payload length a prefix announces, refused above `max`.
pub fn announced(prefix: [u8; PREFIX_BYTES], max: usize) -> Result<usize, FrameError> {
    let announced = usize::try_from(u32::from_be_bytes(prefix)).unwrap_or(usize::MAX);
    if announced > max {
        return Err(FrameError::TooLarge { announced, max });
    }
    Ok(announced)
}

/// Parse a payload and require it to be canonical: what it parses to renders
/// back to exactly these bytes.
pub fn canonical(payload: &[u8]) -> Result<Json, FrameError> {
    let text = core::str::from_utf8(payload)
        .map_err(|_| FrameError::Malformed("payload is not UTF-8".into()))?;
    let value = json::parse(text).map_err(|e| FrameError::Malformed(e.to_string()))?;
    if value.render().as_bytes() != payload {
        return Err(FrameError::Malformed(
            "payload is not canonical JSON (sorted keys, no whitespace)".into(),
        ));
    }
    Ok(value)
}

/// An incremental decoder for bytes that arrive in arbitrary pieces.
#[derive(Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    max: usize,
}

impl Decoder {
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            buf: Vec::new(),
            max,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next complete payload, if one has arrived. An oversized prefix is
    /// an error as soon as its 4 bytes are present.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        let Some(prefix) = self.buf.first_chunk::<PREFIX_BYTES>() else {
            return Ok(None);
        };
        let len = announced(*prefix, self.max)?;
        if self.buf.len() < PREFIX_BYTES + len {
            return Ok(None);
        }
        let payload = self.buf[PREFIX_BYTES..PREFIX_BYTES + len].to_vec();
        self.buf.drain(..PREFIX_BYTES + len);
        Ok(Some(payload))
    }

    /// End of stream: anything left is a truncated frame.
    pub fn finish(self) -> Result<(), FrameError> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let expected = self
            .buf
            .first_chunk::<PREFIX_BYTES>()
            .map_or(PREFIX_BYTES, |p| {
                PREFIX_BYTES + usize::try_from(u32::from_be_bytes(*p)).unwrap_or(usize::MAX)
            });
        Err(FrameError::Truncated {
            got: self.buf.len(),
            expected,
        })
    }
}

/// Read one frame's payload. `Ok(None)` is a clean end of stream before a
/// frame began; an end inside a frame is [`FrameError::Truncated`].
pub async fn read_frame<S: AsyncRead + Unpin>(
    cx: &Cx,
    stream: &mut S,
    max: usize,
) -> Result<Option<Vec<u8>>, FrameError> {
    cx.checkpoint().map_err(|_| FrameError::Cancelled)?;
    let mut prefix = [0u8; PREFIX_BYTES];
    let mut got = 0;
    while got < PREFIX_BYTES {
        let n = stream.read(&mut prefix[got..]).await.map_err(|e| io(&e))?;
        if n == 0 {
            return if got == 0 {
                Ok(None)
            } else {
                Err(FrameError::Truncated {
                    got,
                    expected: PREFIX_BYTES,
                })
            };
        }
        got += n;
    }
    let len = announced(prefix, max)?;
    let mut payload = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        let n = stream
            .read(&mut payload[filled..])
            .await
            .map_err(|e| io(&e))?;
        if n == 0 {
            return Err(FrameError::Truncated {
                got: PREFIX_BYTES + filled,
                expected: PREFIX_BYTES + len,
            });
        }
        filled += n;
    }
    Ok(Some(payload))
}

/// Write one frame and flush it.
pub async fn write_frame<S: AsyncWrite + Unpin>(
    cx: &Cx,
    stream: &mut S,
    payload: &[u8],
    max: usize,
) -> Result<(), FrameError> {
    cx.checkpoint().map_err(|_| FrameError::Cancelled)?;
    let frame = encode(payload, max)?;
    stream.write_all(&frame).await.map_err(|e| io(&e))?;
    stream.flush().await.map_err(|e| io(&e))
}

/// What a request asks of the daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Run an `fa` command line against the held book.
    Run,
    /// Report the daemon's state.
    Status,
    /// Answer, then release the lease and exit.
    Stop,
}

impl Op {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Status => "status",
            Self::Stop => "stop",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "run" => Some(Self::Run),
            "status" => Some(Self::Status),
            "stop" => Some(Self::Stop),
            _ => None,
        }
    }
}

/// A `fad_request` frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub op: Op,
    pub argv: Vec<String>,
    /// The client's working directory: relative paths in `argv` resolve here.
    pub cwd: Option<String>,
    /// The client's stdin, for an argument `-`.
    pub stdin: Option<Vec<u8>>,
    /// A holder's issued capability token (`fa --token`, bead fa-r3q): the
    /// daemon binds this request to the token's principal and journaled
    /// capability instead of the embedded-owner posture.
    pub token: Option<Vec<u8>>,
}

/// A `fad_response` frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub op: Op,
    pub exit: u8,
    pub stdout: String,
    pub stderr: String,
}

fn field<'a>(v: &'a Json, key: &str) -> Result<&'a Json, FrameError> {
    v.get(key)
        .ok_or_else(|| FrameError::Malformed(format!("missing `{key}`")))
}

fn text<'a>(v: &'a Json, key: &str) -> Result<&'a str, FrameError> {
    field(v, key)?
        .as_str()
        .ok_or_else(|| FrameError::Malformed(format!("`{key}` must be a string")))
}

fn opt_text<'a>(v: &'a Json, key: &str) -> Result<Option<&'a str>, FrameError> {
    match field(v, key)? {
        Json::Null => Ok(None),
        Json::Str(t) => Ok(Some(t)),
        _ => Err(FrameError::Malformed(format!(
            "`{key}` must be a string or null"
        ))),
    }
}

fn header(v: &Json, event: &str, protocol: i128) -> Result<Op, FrameError> {
    if text(v, "event")? != event {
        return Err(FrameError::Malformed(format!("expected a {event} frame")));
    }
    match field(v, "v")? {
        Json::Int(n) if *n == protocol => {}
        other => {
            return Err(FrameError::Malformed(format!(
                "protocol {} is not this fad's {protocol}",
                other.render()
            )));
        }
    }
    let op = text(v, "op")?;
    Op::parse(op).ok_or_else(|| FrameError::Malformed(format!("unknown op `{op}`")))
}

/// Lowercase hexadecimal.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Bytes from lowercase hexadecimal.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            let pair = text.get(i..i + 2)?;
            if pair.bytes().any(|b| b.is_ascii_uppercase()) {
                return None;
            }
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

impl Request {
    #[must_use]
    pub fn to_json(&self, protocol: i128) -> Json {
        obj(vec![
            ("event", s("fad_request")),
            ("v", Json::Int(protocol)),
            ("op", s(self.op.name())),
            ("argv", Json::Arr(self.argv.iter().map(s).collect())),
            ("cwd", self.cwd.as_ref().map_or(Json::Null, s)),
            (
                "stdin",
                self.stdin.as_ref().map_or(Json::Null, |b| s(to_hex(b))),
            ),
            (
                "token",
                self.token.as_ref().map_or(Json::Null, |b| s(to_hex(b))),
            ),
        ])
    }

    pub fn from_json(v: &Json, protocol: i128) -> Result<Self, FrameError> {
        let op = header(v, "fad_request", protocol)?;
        let argv = field(v, "argv")?
            .as_arr()
            .ok_or_else(|| FrameError::Malformed("`argv` must be an array".into()))?
            .iter()
            .map(|a| {
                a.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| FrameError::Malformed("`argv` must hold strings".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let stdin = match opt_text(v, "stdin")? {
            None => None,
            Some(h) => Some(
                from_hex(h)
                    .ok_or_else(|| FrameError::Malformed("`stdin` must be lowercase hex".into()))?,
            ),
        };
        // An absent token is an owner-posture request from a client that
        // predates sessions (fa-r3q); null says the same.
        let token = match v.get("token") {
            None | Some(Json::Null) => None,
            Some(Json::Str(h)) => Some(
                from_hex(h)
                    .ok_or_else(|| FrameError::Malformed("`token` must be lowercase hex".into()))?,
            ),
            Some(_) => {
                return Err(FrameError::Malformed(
                    "`token` must be a string or null".into(),
                ));
            }
        };
        Ok(Self {
            op,
            argv,
            cwd: opt_text(v, "cwd")?.map(str::to_string),
            stdin,
            token,
        })
    }
}

impl Response {
    #[must_use]
    pub fn to_json(&self, protocol: i128) -> Json {
        obj(vec![
            ("event", s("fad_response")),
            ("v", Json::Int(protocol)),
            ("op", s(self.op.name())),
            ("exit", Json::Int(i128::from(self.exit))),
            ("stdout", s(&self.stdout)),
            ("stderr", s(&self.stderr)),
        ])
    }

    pub fn from_json(v: &Json, protocol: i128) -> Result<Self, FrameError> {
        let op = header(v, "fad_response", protocol)?;
        let exit = match field(v, "exit")? {
            Json::Int(n) => {
                u8::try_from(*n).map_err(|_| FrameError::Malformed("`exit` out of range".into()))?
            }
            _ => return Err(FrameError::Malformed("`exit` must be an integer".into())),
        };
        Ok(Self {
            op,
            exit,
            stdout: text(v, "stdout")?.to_string(),
            stderr: text(v, "stderr")?.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift64*: deterministic, dependency-free.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: u64) -> usize {
            usize::try_from(self.next() % n).unwrap_or(0)
        }
    }

    #[test]
    fn frames_round_trip_through_any_chunking() {
        let mut rng = Rng(0x0DDB_A11C_AFE5_EED5);
        for round in 0..200 {
            let max = 1 + rng.below(512);
            let payloads: Vec<Vec<u8>> = (0..rng.below(8))
                .map(|_| {
                    (0..rng.below(max as u64 + 1))
                        .map(|_| rng.next() as u8)
                        .collect()
                })
                .collect();
            let mut stream = Vec::new();
            for p in &payloads {
                stream.extend(encode(p, max).expect("within the limit"));
            }
            let mut decoder = Decoder::new(max);
            let mut got = Vec::new();
            let mut at = 0;
            while at < stream.len() {
                let step = 1 + rng.below(16);
                let end = (at + step).min(stream.len());
                decoder.push(&stream[at..end]);
                at = end;
                while let Some(frame) = decoder.next_frame().expect("valid stream") {
                    got.push(frame);
                }
            }
            assert_eq!(got, payloads, "round {round}");
            assert_eq!(decoder.finish(), Ok(()), "round {round}");
        }
    }

    #[test]
    fn oversized_and_truncated_frames_are_typed_errors() {
        assert_eq!(
            encode(&[0; 9], 8),
            Err(FrameError::TooLarge {
                announced: 9,
                max: 8
            })
        );
        // The limit is enforced on the prefix alone: no payload byte needed.
        let mut d = Decoder::new(8);
        d.push(&9u32.to_be_bytes());
        assert_eq!(
            d.next_frame(),
            Err(FrameError::TooLarge {
                announced: 9,
                max: 8
            })
        );
        let mut d = Decoder::new(8);
        d.push(&[0, 0, 0, 5, b'a', b'b']);
        assert_eq!(d.next_frame(), Ok(None));
        assert_eq!(
            d.finish(),
            Err(FrameError::Truncated {
                got: 6,
                expected: 9
            })
        );
        let mut d = Decoder::new(8);
        d.push(&[0, 0]);
        assert_eq!(
            d.finish(),
            Err(FrameError::Truncated {
                got: 2,
                expected: 4
            })
        );
        assert_eq!(
            announced(u32::MAX.to_be_bytes(), usize::MAX),
            Ok(usize::try_from(u32::MAX).unwrap_or(usize::MAX))
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic_the_decoder() {
        let mut rng = Rng(0xFEED_FACE_0BAD_C0DE);
        for _ in 0..2_000 {
            let mut d = Decoder::new(1 + rng.below(64));
            let bytes: Vec<u8> = (0..rng.below(96)).map(|_| rng.next() as u8).collect();
            d.push(&bytes);
            while let Ok(Some(p)) = d.next_frame() {
                assert!(p.len() <= 64);
            }
            let _ = canonical(&bytes);
        }
    }

    #[test]
    fn only_canonical_json_is_accepted() {
        assert!(canonical(br#"{"a":1,"b":[true,null]}"#).is_ok());
        for bad in [
            &br#"{"b":1,"a":2}"#[..],
            br#"{ "a":1}"#,
            br#"{"a":1.5}"#,
            br#"{"a":1}x"#,
            b"\xff",
        ] {
            assert!(
                matches!(canonical(bad), Err(FrameError::Malformed(_))),
                "{bad:?}"
            );
        }
    }

    /// fa-r3q: a token rides the request as hex; a frame without the key
    /// (an older client) or with null is an owner-posture request.
    #[test]
    fn a_session_token_round_trips_and_its_absence_is_the_owner_posture() {
        let req = Request {
            op: Op::Run,
            argv: vec!["tb".into()],
            cwd: None,
            stdin: None,
            token: Some(vec![0xfa, 0x00, 0x7e]),
        };
        let wire = req.to_json(1).render();
        assert!(wire.contains("\"token\":\"fa007e\""), "{wire}");
        let back = Request::from_json(&canonical(wire.as_bytes()).expect("canonical"), 1);
        assert_eq!(back, Ok(req));
        let legacy =
            br#"{"argv":[],"cwd":null,"event":"fad_request","op":"run","stdin":null,"v":1}"#;
        let back = Request::from_json(&canonical(legacy).expect("canonical"), 1).unwrap();
        assert_eq!(back.token, None);
        for bad in [
            &br#"{"argv":[],"cwd":null,"event":"fad_request","op":"run","stdin":null,"token":"FA","v":1}"#[..],
            br#"{"argv":[],"cwd":null,"event":"fad_request","op":"run","stdin":null,"token":7,"v":1}"#,
        ] {
            assert!(Request::from_json(&canonical(bad).expect("canonical"), 1).is_err());
        }
    }

    #[test]
    fn requests_and_responses_round_trip_and_refuse_strangers() {
        let req = Request {
            op: Op::Run,
            argv: vec!["tb".into(), "--json".into()],
            cwd: Some("/tmp/x".into()),
            stdin: Some(vec![0, 1, 0xfe]),
            token: None,
        };
        let wire = req.to_json(1).render();
        let back = Request::from_json(&canonical(wire.as_bytes()).expect("canonical"), 1);
        assert_eq!(back, Ok(req));
        let resp = Response {
            op: Op::Stop,
            exit: 6,
            stdout: "{\"event\":\"x\"}\n".into(),
            stderr: "refused\n".into(),
        };
        let wire = resp.to_json(1).render();
        let back = Response::from_json(&canonical(wire.as_bytes()).expect("canonical"), 1);
        assert_eq!(back, Ok(resp));
        let other_protocol = Request {
            op: Op::Status,
            argv: Vec::new(),
            cwd: None,
            stdin: None,
            token: None,
        }
        .to_json(2);
        assert!(Request::from_json(&other_protocol, 1).is_err());
        assert_eq!(from_hex("00ff10"), Some(vec![0, 255, 16]));
        assert_eq!(from_hex("0F"), None);
        assert_eq!(from_hex("abc"), None);
    }
}
