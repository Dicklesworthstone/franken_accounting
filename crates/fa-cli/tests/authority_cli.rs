//! Launch-bound CLI admission is checked before input files or the book are
//! observed. A plan-output argument does not confer commit authority.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::{Books, Captured, Files, Stdin, run_with_authority};
use fa_cli::json::{self, Json};
use fa_cli::verbs::registry;

fn fixture() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fa-authority-cli-{}-{id}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
}

fn authority(profile: LaunchProfile, grants: &[&str]) -> LaunchAuthority {
    LaunchAuthority::new(
        fixture().join("missing-book"),
        None,
        "bound-7",
        profile,
        grants,
    )
    .expect("launch authority")
}

fn run(authority: &LaunchAuthority, argv: &[&str]) -> (u8, Captured) {
    let argv: Vec<String> = argv.iter().map(|value| (*value).to_string()).collect();
    run_with_authority(
        &argv,
        Books::Dir,
        Files {
            cwd: None,
            stdin: Stdin::Missing,
        },
        authority,
        true,
    )
}

fn event(authority: &LaunchAuthority, out: &Captured) -> Json {
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{out:?}");
    registry()
        .expect("verbs.toml")
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("{error}\n{out:?}"));
    let event = json::parse(lines[0]).expect("robot JSON");
    assert_eq!(
        event.get("authority"),
        Some(&authority.envelope_json()),
        "{out:?}"
    );
    event
}

fn refused_before_open(authority: &LaunchAuthority, argv: &[&str], refusal: &str) {
    let (exit, out) = run(authority, argv);
    assert_eq!(exit, 7, "argv={argv:?}\n{out:?}");
    let event = event(authority, &out);
    assert_eq!(event.get("event").and_then(Json::as_str), Some("error"));
    assert_eq!(event.get("book"), Some(&Json::Null), "{out:?}");
    assert_eq!(event.get("coordinate"), Some(&Json::Null), "{out:?}");
    assert_eq!(
        event
            .get("data")
            .and_then(|data| data.get("refusal_id"))
            .and_then(Json::as_str),
        Some(refusal),
        "argv={argv:?}\n{out:?}"
    );
    assert!(
        !authority.book().exists(),
        "preflight must not create a book"
    );
}

#[test]
fn owner_mutations_are_refused_before_input_files_or_book_creation() {
    let authority = authority(LaunchProfile::Preparer, &[]);
    for argv in [
        vec!["book", "create", "--name", "Forged book", "--json"],
        vec!["chart", "import", "unread-chart.json", "--json"],
        vec!["period", "create", "--fiscal-year", "2026", "--json"],
        vec![
            "period",
            "create",
            "--fiscal-year",
            "2026",
            "--plan-out",
            "true",
            "--json",
        ],
        vec!["period", "open", "FY2026-P03", "--json"],
        vec!["period", "soft-close", "FY2026-P03", "--json"],
        vec![
            "document",
            "add",
            "unread-evidence.pdf",
            "--grade",
            "HumanUpload",
            "--json",
        ],
    ] {
        refused_before_open(&authority, &argv, "FA-REF-011");
    }
}

#[test]
fn handlers_cannot_add_operations_omitted_from_the_launch_grant() {
    let reader = authority(LaunchProfile::Preparer, &["read"]);
    for argv in [
        vec!["post", "--intent", "-", "--json"],
        vec!["reserve", "--intent", "-", "--json"],
        vec!["resolve", "--intent", "-", "--json"],
        vec![
            "reverse",
            "not-yet-parsed",
            "--reason",
            "WrongAccount",
            "--json",
        ],
        vec!["approve", "--proposal", "not-yet-parsed", "--json"],
        vec!["checkpoint", "create", "--json"],
        vec!["verify", "registers", "--period", "FY2026-P03", "--json"],
        vec!["registers", "advance", "--period", "FY2026-P03", "--json"],
        vec![
            "registers",
            "materialize",
            "--period",
            "FY2026-P03",
            "--json",
        ],
    ] {
        refused_before_open(&reader, &argv, "FA-REF-011");
    }
    let verifier = authority(LaunchProfile::Agent, &["verify"]);
    for argv in [
        vec!["book", "info", "--json"],
        vec!["chart", "list", "--json"],
        vec!["period", "list", "--json"],
        vec!["tb", "--period", "FY2026-P03", "--json"],
        vec!["verify", "registers", "--period", "FY2026-P03", "--json"],
    ] {
        refused_before_open(&verifier, &argv, "FA-REF-011");
    }
}

#[test]
fn plan_files_and_plan_output_flags_cannot_confirm_a_dangerous_commit() {
    let authority = authority(LaunchProfile::Preparer, &[]);
    for transition in ["close", "lock", "reopen"] {
        for extra in [
            vec![],
            vec!["--plan", "false"],
            vec!["--plan-out", "true", "--plan", "false"],
            vec!["--plan-out=true", "--plan=false"],
            vec!["--plan-out", "true", "--approval", ""],
        ] {
            let mut argv = vec!["period", transition, "FY2026-P03"];
            argv.extend(extra);
            argv.push("--json");
            refused_before_open(&authority, &argv, "FA-REF-007");
        }
    }
}

#[test]
fn only_an_actual_read_authorized_period_plan_can_reach_the_book() {
    let reader = authority(LaunchProfile::Agent, &["read"]);
    let plan = reader
        .book()
        .parent()
        .expect("fixture parent")
        .join("review.plan");
    let path = plan.to_str().expect("UTF-8 fixture path");
    let argv = ["period", "lock", "FY2026-P03", "--plan-out", path, "--json"];
    let (exit, out) = run(&reader, &argv);
    assert_eq!(
        exit, 4,
        "a permitted plan reaches the missing book: {out:?}"
    );
    let event = event(&reader, &out);
    assert_eq!(
        event.get("data").and_then(|data| data.get("refusal_id")),
        Some(&Json::Null),
        "the failure is opening the fixture, not fabricated commit authority: {out:?}"
    );
    assert!(!plan.exists(), "no plan may be fabricated without a book");
    let poster = authority(LaunchProfile::Preparer, &["post"]);
    refused_before_open(&poster, &argv, "FA-REF-011");
}

#[test]
fn positional_flag_text_and_file_cwd_cannot_rebind_the_configured_book() {
    let authority = authority(LaunchProfile::Agent, &["read"]);
    let other = fixture();
    let argv: Vec<String> = ["book", "info", "--json", "--", "--book", "another-book"]
        .iter()
        .map(|value| (*value).to_string())
        .collect();
    let (exit, out) = run_with_authority(
        &argv,
        Books::Dir,
        Files {
            cwd: Some(other.clone()),
            stdin: Stdin::Missing,
        },
        &authority,
        true,
    );
    assert_eq!(exit, 4, "{out:?}");
    let event = event(&authority, &out);
    let message = event
        .get("data")
        .and_then(|data| data.get("message"))
        .and_then(Json::as_str)
        .expect("open failure");
    assert!(
        message.contains(&authority.book().display().to_string()),
        "{out:?}"
    );
    assert!(!message.contains(&other.display().to_string()), "{out:?}");
    assert!(!authority.book().exists());
    assert!(!other.join("another-book").exists());
}
