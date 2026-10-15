//! Launch syntax must fail before a lease, book key, socket or book is opened.
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_fad"))
        .env_remove("FA_BOOK")
        .args(args)
        .output()
        .expect("run fad")
}

#[test]
fn maintenance_is_launch_only_and_requires_explicit_bootstrap() {
    for args in [
        vec!["serve", "--register-period", "FY2026-P03"],
        vec!["status", "--bootstrap-system", "--register-period", "FY2026-P03"],
        vec!["stop", "--register-period", "FY2026-P03"],
    ] {
        let mut args = args;
        args.extend(["--book", "/this-book-must-not-be-opened/register-launch", "--json"]);
        let result = run(&args);
        assert_eq!(result.status.code(), Some(2));
    }
}

#[test]
fn malformed_duplicate_missing_and_excess_period_arguments_are_usage_errors() {
    let prefix = ["serve", "--bootstrap-system", "--book",
        "/this-book-must-not-be-opened/register-launch", "--json"];
    for tail in [
        vec!["--register-period="],
        vec!["--register-period", "FY2026-P03", "--register-period=FY2026-P03"],
        vec!["--register-period", "FY2026-P03 "],
        vec!["--register-period"],
        vec!["--register-period", "--json"],
    ] {
        let args: Vec<_> = prefix.into_iter().chain(tail).collect();
        assert_eq!(run(&args).status.code(), Some(2));
    }
    let mut args: Vec<String> = prefix.iter().map(|s| (*s).to_owned()).collect();
    for i in 0..65 { args.push(format!("--register-period=P{i}")); }
    assert_eq!(run(&args.iter().map(String::as_str).collect::<Vec<_>>()).status.code(), Some(2));
}

#[test]
fn registered_help_explains_explicit_period_selection() {
    let output = run(&["serve", "--help"]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("--register-period"));
    assert!(text.contains("--bootstrap-system"));
    assert!(text.contains("one period"));
}
