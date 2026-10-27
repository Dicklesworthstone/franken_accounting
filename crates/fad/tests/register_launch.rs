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
fn maintenance_is_a_serve_only_launch_choice_independent_of_bootstrap() {
    // 807e821f: `serve --register-period` no longer requires
    // --bootstrap-system (maintenance-only work holds no System capability;
    // see timed::tests). It is valid launch syntax, so the absent book refuses
    // it as environment (exit 4), never as usage, and nothing is created.
    let book = "/this-book-must-not-be-opened/register-launch";
    let result = run(&[
        "serve",
        "--register-period",
        "FY2026-P03",
        "--book",
        book,
        "--json",
    ]);
    assert_eq!(result.status.code(), Some(4));
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("\"class\":\"environment\""),
        "{result:?}"
    );
    assert!(!std::path::Path::new(book).exists());
    for args in [
        vec![
            "status",
            "--bootstrap-system",
            "--register-period",
            "FY2026-P03",
        ],
        vec!["status", "--register-period", "FY2026-P03"],
        vec!["stop", "--register-period", "FY2026-P03"],
    ] {
        let mut args = args;
        args.extend([
            "--book",
            "/this-book-must-not-be-opened/register-launch",
            "--json",
        ]);
        let result = run(&args);
        assert_eq!(result.status.code(), Some(2));
    }
}

#[test]
fn malformed_duplicate_missing_and_excess_period_arguments_are_usage_errors() {
    let prefix = [
        "serve",
        "--bootstrap-system",
        "--book",
        "/this-book-must-not-be-opened/register-launch",
        "--json",
    ];
    for tail in [
        vec!["--register-period="],
        vec![
            "--register-period",
            "FY2026-P03",
            "--register-period=FY2026-P03",
        ],
        vec!["--register-period", "FY2026-P03 "],
        vec!["--register-period"],
        vec!["--register-period", "--json"],
    ] {
        let args: Vec<_> = prefix.into_iter().chain(tail).collect();
        assert_eq!(run(&args).status.code(), Some(2));
    }
    let mut args: Vec<String> = prefix.iter().map(|s| (*s).to_owned()).collect();
    for i in 0..65 {
        args.push(format!("--register-period=P{i}"));
    }
    assert_eq!(
        run(&args.iter().map(String::as_str).collect::<Vec<_>>())
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn registered_help_explains_explicit_period_selection() {
    let output = run(&["serve", "--help"]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("--register-period"));
    assert!(text.contains("--register-fiscal-year"));
    assert!(text.contains("--bootstrap-system"));
    assert!(text.contains("--files-root"));
    assert!(text.contains("one period"));
}

#[test]
fn fiscal_year_launch_selection_is_serve_only_exclusive_and_parsed_before_book_access() {
    let book = "/this-book-must-not-be-opened/fiscal-year-launch";
    let valid = run(&[
        "serve",
        "--register-fiscal-year",
        "2026",
        "--book",
        book,
        "--json",
    ]);
    assert_eq!(valid.status.code(), Some(4), "{valid:?}");
    assert!(!std::path::Path::new(book).exists());
    for options in [
        vec!["status", "--register-fiscal-year", "2026"],
        vec!["stop", "--register-fiscal-year", "2026"],
        vec!["serve", "--register-fiscal-year", "not-a-year"],
        vec!["serve", "--register-fiscal-year", "2147483648"],
        vec!["serve", "--register-fiscal-year"],
        vec![
            "serve",
            "--register-fiscal-year",
            "2026",
            "--register-fiscal-year",
            "2027",
        ],
        vec![
            "serve",
            "--register-fiscal-year",
            "2026",
            "--register-period",
            "FY2026-P03",
        ],
    ] {
        let mut args = options;
        args.extend(["--book", book, "--json"]);
        assert_eq!(run(&args).status.code(), Some(2), "{args:?}");
        assert!(!std::path::Path::new(book).exists());
    }
}

#[test]
fn files_root_is_serve_only_and_rejects_missing_or_book_overlapping_dirs_before_book_open() {
    let book = "/this-book-must-not-be-opened/files-root-launch";
    for args in [
        vec!["status", "--files-root", "/tmp", "--book", book, "--json"],
        vec!["stop", "--files-root", "/tmp", "--book", book, "--json"],
        vec![
            "serve",
            "--files-root",
            "/tmp",
            "--files-root",
            "/tmp",
            "--book",
            book,
            "--json",
        ],
        vec![
            "serve",
            "--files-root",
            "/nonexistent-files-root-dir-fa-udti",
            "--book",
            book,
            "--json",
        ],
    ] {
        let result = run(&args);
        assert_eq!(result.status.code(), Some(2), "{args:?}");
    }
}
