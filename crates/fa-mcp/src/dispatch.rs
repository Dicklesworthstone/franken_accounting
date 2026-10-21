//! Running one call through the `fa` front door and reading its robot lines.
//!
//! Every tool call and every resource read becomes an `fa … --json` command
//! line run by [`fa_cli::entry::fa_with_authority`] under the authority fixed
//! at trusted launch. It takes the book's writer lease and never forwards
//! to the unauthenticated `fad` protocol. The forwarded
//! stdin is the call's inline document; a call that forwarded none gets
//! [`Stdin::Missing`], so `-` can never read the server's own transport.
//!
//! The reply is read line by line against the robot schema
//! ([`fa_cli::verbs::Registry::check_line`]): a line outside it is a
//! foundation failure of the dispatcher, never a payload.

use fa_cli::authority::LaunchAuthority;
use fa_cli::cli::{Files, Stdin};
use fa_cli::json::{self, Json};
use fa_cli::verbs::Registry;
use fastmcp_rust::{JsonMap, JsonValue};

use crate::registry::Invocation;

/// One robot-mode line of the reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// The event the line's `data` is an instance of.
    pub event: String,
    /// The envelope's `data`.
    pub data: Json,
    /// The whole line (the envelope with `data`).
    pub line: Json,
}

/// What one command line produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub exit: u8,
    pub lines: Vec<Line>,
    pub stderr: String,
}

impl Reply {
    /// The `error` event a non-zero exit emits (exactly one, last).
    #[must_use]
    pub fn error(&self) -> Option<&Line> {
        self.lines.last().filter(|l| l.event == "error")
    }
}

/// Run `invocation` through the front door and parse its robot lines.
pub fn run(
    reg: &Registry,
    invocation: &Invocation,
    authority: &LaunchAuthority,
) -> Result<Reply, String> {
    let files = Files {
        cwd: None,
        stdin: match &invocation.stdin {
            Some(bytes) => Stdin::Forwarded(bytes.clone()),
            None => Stdin::Missing,
        },
    };
    let (exit, out) = fa_cli::entry::fa_with_authority(&invocation.argv, files, authority, true);
    let mut lines = Vec::new();
    for raw in out.stdout.lines() {
        let event = reg
            .check_line(raw)
            .map_err(|e| format!("the dispatcher emitted a line outside the robot schema: {e}"))?
            .to_string();
        let line = json::parse(raw)
            .map_err(|e| format!("the dispatcher emitted a line that is not JSON: {e}"))?;
        let data = line.get("data").cloned().unwrap_or(Json::Null);
        lines.push(Line { event, data, line });
    }
    Ok(Reply {
        exit,
        lines,
        stderr: out.stderr,
    })
}

/// The closed-universe JSON the CLI speaks, as the JSON the MCP boundary
/// speaks. Integers past `i64` travel as their decimal string, never a float.
#[must_use]
pub fn to_wire(j: &Json) -> JsonValue {
    match j {
        Json::Null => JsonValue::Null,
        Json::Bool(b) => JsonValue::Bool(*b),
        Json::Int(i) => match i64::try_from(*i) {
            Ok(n) => JsonValue::from(n),
            Err(_) => JsonValue::String(i.to_string()),
        },
        Json::Str(s) => JsonValue::String(s.clone()),
        Json::Arr(a) => JsonValue::Array(a.iter().map(to_wire).collect()),
        Json::Obj(fields) => {
            let mut m = JsonMap::new();
            for (k, v) in fields {
                m.insert(k.clone(), to_wire(v));
            }
            JsonValue::Object(m)
        }
    }
}

/// The MCP boundary's JSON as the closed-universe JSON the CLI speaks.
/// `None` when a value has no counterpart (a non-integer number: amounts are
/// strings; the detectors refuse floats before anything reaches here).
#[must_use]
pub fn from_wire(v: &JsonValue) -> Option<Json> {
    Some(match v {
        JsonValue::Null => Json::Null,
        JsonValue::Bool(b) => Json::Bool(*b),
        JsonValue::Number(n) => Json::Int(i128::from(
            n.as_i64()
                .or_else(|| n.as_u64().and_then(|u| i64::try_from(u).ok()))?,
        )),
        JsonValue::String(s) => Json::Str(s.clone()),
        JsonValue::Array(a) => Json::Arr(a.iter().map(from_wire).collect::<Option<Vec<_>>>()?),
        JsonValue::Object(o) => Json::Obj(
            o.iter()
                .map(|(k, v)| from_wire(v).map(|j| (k.clone(), j)))
                .collect::<Option<Vec<_>>>()?,
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_cli::authority::LaunchProfile;
    use fastmcp_rust::json;

    fn authority(book: std::path::PathBuf) -> LaunchAuthority {
        LaunchAuthority::new(book, None, "mcp-agent", LaunchProfile::Agent, &[])
            .expect("launch authority")
    }

    #[test]
    fn a_command_without_a_book_is_run_and_its_lines_are_schema_checked() {
        let reg = fa_cli::verbs::registry().expect("verbs.toml");
        let authority = authority("/nonexistent/book".into());
        let inv = Invocation {
            argv: vec!["capabilities".into(), "--json".into()],
            stdin: None,
        };
        let reply = run(reg, &inv, &authority).expect("ran");
        assert_eq!(reply.exit, 0, "{}", reply.stderr);
        assert_eq!(reply.lines.len(), 1);
        assert_eq!(reply.lines[0].event, "capabilities");
        assert!(reply.lines[0].data.get("verbs").is_some());
        assert!(reply.error().is_none());
        // A usage error: exactly one error line, last, with the exit's class
        // (a writing command: a read's one-edit flag typo runs corrected).
        let bad = Invocation {
            argv: vec!["post".into(), "--jsno".into(), "--json".into()],
            stdin: None,
        };
        let reply = run(reg, &bad, &authority).expect("ran");
        assert_eq!(reply.exit, 2);
        let err = reply.error().expect("an error line");
        assert_eq!(err.data.get("class").and_then(Json::as_str), Some("usage"));
        assert!(
            err.data
                .get("fix")
                .and_then(Json::as_str)
                .is_some_and(|f| f.contains("--json"))
        );
    }

    #[test]
    fn a_missing_stdin_never_reads_the_servers_transport() {
        let reg = fa_cli::verbs::registry().expect("verbs.toml");
        let dir = std::env::temp_dir().join(format!("fa-mcp-missing-stdin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("lease directory");
        let authority = authority(dir);
        let inv = Invocation {
            argv: vec![
                "post".into(),
                "--intent".into(),
                "-".into(),
                "--json".into(),
            ],
            stdin: None,
        };
        let reply = run(reg, &inv, &authority).expect("ran");
        assert_eq!(reply.exit, 2, "{:?}", reply.lines);
        let err = reply.error().expect("error");
        assert!(
            err.data
                .get("message")
                .and_then(Json::as_str)
                .is_some_and(|m| m.contains("no stdin")),
            "{:?}",
            err.data
        );
    }

    #[test]
    fn wire_conversion_round_trips_and_refuses_floats() {
        let j = Json::Obj(vec![
            ("a".into(), Json::Int(1)),
            (
                "b".into(),
                Json::Arr(vec![Json::Str("x".into()), Json::Null, Json::Bool(true)]),
            ),
            ("big".into(), Json::Int(i128::from(i64::MAX) + 1)),
        ]);
        let w = to_wire(&j);
        assert_eq!(w["big"], json!("9223372036854775808"));
        assert_eq!(w["a"], json!(1));
        assert_eq!(
            from_wire(&json!({"a": 1, "b": ["x", null, true]})).map(|j| j.render()),
            Some(r#"{"a":1,"b":["x",null,true]}"#.to_string())
        );
        assert_eq!(from_wire(&json!({"amount": 12.5})), None);
    }
}
