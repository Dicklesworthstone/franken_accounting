//! Never silent on a panic (bead fa-y9z): a command that panics exits 5 with
//! exactly one `error` event (FA-REF-153, class foundation) naming the panic
//! and its location, never Rust's exit 101 with nothing on stdout.
//!
//! The panic is the debug build's `FA_TEST_PANIC` trigger in the `fa`
//! binary; a release build compiles it out.

#![forbid(unsafe_code)]

use std::process::Command;

use fa_cli::json::{self, Json};
use fa_cli::verbs::registry;

fn fa(args: &[&str], panic: bool) -> (i32, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fa"));
    command.args(args).env_remove("FA_BOOK");
    if panic {
        command.env("FA_TEST_PANIC", "1");
    } else {
        command.env_remove("FA_TEST_PANIC");
    }
    let out = command.output().expect("run fa");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    eprintln!(
        "[panic-test] fa {} (panic={panic}) → exit {code}\n  stdout: {}\n  stderr: {}",
        args.join(" "),
        stdout.trim(),
        stderr.trim()
    );
    (code, stdout, stderr)
}

#[test]
fn a_panic_is_one_error_event_with_exit_5_never_exit_101() {
    // Without the trigger the same command succeeds: the panic is the only
    // difference between the two runs.
    let (code, _, _) = fa(&["capabilities", "--json"], false);
    assert_eq!(code, 0);

    let (code, stdout, stderr) = fa(&["capabilities", "--json"], true);
    assert_eq!(
        code, 5,
        "a panic is a foundation failure, never 101:\n{stdout}\n{stderr}"
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "exactly one robot line: {stdout}");
    let checked = registry().expect("verb registry").check_line(lines[0]);
    assert!(checked.is_ok(), "{checked:?}");
    let line = json::parse(lines[0]).expect("JSON");
    let data = line.get("data").expect("data");
    assert_eq!(line.get("event").and_then(Json::as_str), Some("error"));
    assert_eq!(
        data.get("refusal_id").and_then(Json::as_str),
        Some("FA-REF-153")
    );
    assert_eq!(data.get("class").and_then(Json::as_str), Some("foundation"));
    assert_eq!(data.get("exit"), Some(&Json::Int(5)));
    let message = data
        .get("message")
        .and_then(Json::as_str)
        .unwrap_or_default();
    assert!(message.contains("FA_TEST_PANIC"), "{message}");
    assert!(
        message.contains("main.rs"),
        "the panic's location: {message}"
    );
    assert!(stderr.contains("fa: internal error"), "{stderr}");

    // Human mode: the same exit, and the error on stderr.
    let (code, _, stderr) = fa(&["capabilities"], true);
    assert_eq!(code, 5);
    assert!(
        stderr.contains("FA-REF-153") || stderr.contains("internal error"),
        "{stderr}"
    );
}
