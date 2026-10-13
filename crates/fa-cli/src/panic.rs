//! Never silent on a panic (plan §15.3, bead fa-y9z): every non-zero exit
//! emits exactly one `error` event, and exit 1 or Rust's 101 is never the
//! answer. The front door catches an unwinding panic, records its message
//! and location through the panic hook, and refuses with FA-REF-153 (exit 5,
//! foundation) exactly as a command's refusal is rendered: one robot line in
//! `--json` mode, the text on stderr otherwise. `fa` and `fad` share the robot
//! contract and report through [`run_reporting`]; `fa-mcp`, whose stdout is
//! the JSON-RPC stream, reports the same refusal on stderr ([`catch`],
//! [`refusal`]).
//!
//! No-claim boundary: process-level reporting of an unwinding panic. An
//! abort (out-of-memory kill, a panic during a panic) cannot be reported.

use std::panic::UnwindSafe;
use std::sync::Mutex;

use fa_journal::{Refusal, exit};

use crate::cli;

/// Refusal codes this module issues (registries/refusal_catalog.toml).
pub mod code {
    /// The command panicked; the front door reports it instead of exiting 101.
    pub const INTERNAL_PANIC: &str = "FA-REF-153";
}

static LAST: Mutex<Option<String>> = Mutex::new(None);

/// Install the hook that records a panic's message and location (and
/// prints them on stderr, which carries diagnostics, prefixed by `binary`).
pub fn install(binary: &'static str) {
    std::panic::set_hook(Box::new(move |info| {
        let text = info.to_string();
        eprintln!("{binary}: internal error: {text}");
        if let Ok(mut last) = LAST.lock() {
            *last = Some(text);
        }
    }));
}

/// Run `command`; a panic is `Err` with the message and location the hook
/// recorded.
pub fn catch<T>(command: impl FnOnce() -> T + UnwindSafe) -> Result<T, String> {
    std::panic::catch_unwind(command).map_err(|_| {
        LAST.lock()
            .ok()
            .and_then(|last| last.clone())
            .unwrap_or_else(|| "a panic without a message".to_string())
    })
}

/// The FA-REF-153 refusal (exit 5) for a caught panic's text.
#[must_use]
pub fn refusal(text: &str) -> Refusal {
    Refusal::new(
        code::INTERNAL_PANIC,
        exit::FOUNDATION,
        format!("internal error: {text}"),
        "plan §15.3 (never silent: every non-zero exit emits exactly one error event)",
        "report the command line and this message; a write either committed before the panic or did not (run `fa verify registers` and `fa verify projections`)",
    )
}

/// Run `command`; a panic becomes one FA-REF-153 refusal for `argv` and
/// exit 5.
pub fn run_reporting(argv: &[String], command: impl FnOnce() -> u8 + UnwindSafe) -> u8 {
    match catch(command) {
        Ok(code) => code,
        Err(text) => cli::refuse(argv, refusal(&text), false).0,
    }
}
