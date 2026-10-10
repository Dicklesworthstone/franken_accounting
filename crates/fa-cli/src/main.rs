//! `fa` — the FrankenAccounting command line (plan §15.3, Appendix D). The
//! commands live in the `fa_cli` library, shared with the `fad` daemon; this
//! binary is the front door ([`fa_cli::entry::fa`]): it runs a command
//! directly under the book's writer lease, or through the `fad` that holds it.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (code, _) = fa_cli::entry::fa(&argv, false);
    ExitCode::from(code)
}
