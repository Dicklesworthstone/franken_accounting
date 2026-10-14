//! `fa` — the FrankenAccounting command line (plan §15.3, Appendix D). The
//! commands live in the `fa_cli` library, shared with the `fad` daemon; this
//! binary is the front door ([`fa_cli::entry::fa`]): it runs a command
//! directly under the book's writer lease, or through the `fad` that holds it.
//! A panic is reported as one error event with exit 5 ([`fa_cli::panic`]).

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    fa_cli::panic::install("fa");
    let code = fa_cli::panic::run_reporting(&argv, || {
        // Debug builds only: the never-silent-fail test's deliberate panic.
        #[cfg(debug_assertions)]
        if std::env::var_os("FA_TEST_PANIC").is_some() {
            std::panic::panic_any(
                "FA_TEST_PANIC: a deliberate panic for the never-silent-fail test",
            );
        }
        fa_cli::entry::fa(&argv, false).0
    });
    ExitCode::from(code)
}
