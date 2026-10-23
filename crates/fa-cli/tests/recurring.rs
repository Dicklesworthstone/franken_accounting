//! Recurring approval artifacts survive independent approval publications and
//! separate CLI processes; cancellation never rewrites the approved template.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};

fn run(book: &Path, args: &[&str]) -> (i32, Json) {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(["--via", "direct"])
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .env_remove("FA_KEYS")
        .stdin(Stdio::null())
        .output()
        .expect("run fa");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "args={args:?}\n{stdout}\n{stderr}");
    fa_cli::verbs::registry()
        .expect("registry")
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("args={args:?}: {error}\n{stdout}\n{stderr}"));
    (
        output.status.code().unwrap_or(-1),
        json::parse(lines[0]).expect("robot line"),
    )
}

fn ok(book: &Path, args: &[&str]) -> Json {
    let (code, line) = run(book, args);
    assert_eq!(code, 0, "args={args:?}: {}", line.render());
    line
}

fn get<'a>(value: &'a Json, key: &str) -> &'a Json {
    value
        .get("data")
        .and_then(|data| data.get(key))
        .or_else(|| value.get(key))
        .expect(key)
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    get(value, key).as_str().expect(key)
}

fn integer(value: &Json, key: &str) -> i128 {
    match get(value, key) {
        Json::Int(value) => *value,
        other => panic!("{key}: {other:?}"),
    }
}

fn head(book: &Path) -> i128 {
    integer(get(&ok(book, &["book", "info"]), "coordinate"), "known_at")
}

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let dir = std::env::temp_dir().join(format!(
            "fa-recurring-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&dir) {
            Ok(()) => return dir,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", dir.display()),
        }
    }
}

fn write(dir: &Path, name: &str, contents: &str) -> String {
    let file = dir.join(name);
    std::fs::write(&file, contents).expect("write retained fixture");
    file.display().to_string()
}

#[test]
fn a_saved_recurring_plan_requires_independent_approval_then_lists_and_cancels_across_reopens() {
    let dir = directory();
    let book = dir.join("book");
    ok(
        &book,
        &[
            "book",
            "create",
            "--name",
            "Monthly rent",
            "--opening-date",
            "2026-01-01",
            "--time-zone",
            "UTC",
        ],
    );
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&book, &["chart", "import", &chart]);
    let source = write(
        &dir,
        "lease.txt",
        "Reviewed annual lease: monthly rent 123.45 USD.",
    );
    let document = ok(
        &book,
        &[
            "document",
            "add",
            &source,
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
        ],
    );
    let template = write(
        &dir,
        "rent.json",
        &format!(
            r#"{{"effective_date":"2026-01-31","description":"Monthly lease payment","idempotency_key":"rent-template","evidence":["{}"],"legs":[{{"side":"debit","account":"6000","amount":"123.45 USD"}},{{"side":"credit","account":"1000","amount":"123.45 USD"}}]}}"#,
            text(&document, "oid")
        ),
    );
    let plan_file = dir.join("rent.plan").display().to_string();
    let before = head(&book);
    let plan = ok(
        &book,
        &[
            "schedule",
            "recurring",
            "create",
            "rent",
            "--template",
            &template,
            "--every-months",
            "1",
            "--month-end",
            "ClampToMonthEnd",
            "--end",
            "2026-12-31",
            "--dry-run",
            "--plan-out",
            &plan_file,
        ],
    );
    assert_eq!(text(&plan, "event"), "recurring_plan");
    assert_eq!(text(&plan, "scope"), "fixed-effects-approval");
    assert_eq!(
        head(&book),
        before,
        "planning does not activate the schedule"
    );
    let bytes = std::fs::read(&plan_file).unwrap();
    let decoded = fa::RecurringPlan::decode(&bytes).unwrap();
    assert_eq!(decoded.spec().name, "rent");
    assert_eq!(decoded.spec().template.legs.len(), 2);
    assert_eq!(decoded.spec().template.evidence.len(), 1);
    assert_eq!(decoded.encode().unwrap(), bytes);
    assert!(
        get(&ok(&book, &["schedule", "recurring", "list"]), "schedules")
            .as_arr()
            .unwrap()
            .is_empty()
    );
    let (status, missing) = run(
        &book,
        &[
            "schedule",
            "recurring",
            "create",
            "rent",
            "--plan",
            &plan_file,
        ],
    );
    assert_ne!(status, 0);
    assert_eq!(text(&missing, "event"), "error");
    assert_eq!(head(&book), before);
    // Approval is a separate publication. It does not stale this fixed-effect
    // artifact: the scheduled effects still undergo fresh admission when due.
    let approval = ok(
        &book,
        &[
            "approve",
            "--proposal",
            text(&plan, "proposal_digest"),
            "--as",
            "controller",
        ],
    );
    let approval_vid = text(&approval, "approval_vid");
    let before_create = head(&book);
    assert!(before_create > before);
    let (status, wrong_name) = run(
        &book,
        &[
            "schedule",
            "recurring",
            "create",
            "different-rent",
            "--plan",
            &plan_file,
            "--approval",
            approval_vid,
        ],
    );
    assert_eq!(status, 2);
    assert_eq!(text(&wrong_name, "event"), "error");
    assert_eq!(head(&book), before_create);
    let create_args = [
        "schedule",
        "recurring",
        "create",
        "rent",
        "--plan",
        &plan_file,
        "--approval",
        approval_vid,
    ];
    let created = ok(&book, &create_args);
    assert_eq!(text(&created, "event"), "recurring_recorded");
    assert_eq!(get(&created, "already_recorded"), &Json::Bool(false));
    let created_at = integer(&created, "recorded_at");
    assert!(created_at > before_create);
    let retry = ok(&book, &create_args);
    assert_eq!(get(&retry, "already_recorded"), &Json::Bool(true));
    assert_eq!(integer(&retry, "recorded_at"), created_at);
    assert_eq!(head(&book), created_at);
    let listed = ok(&book, &["schedule", "recurring", "list"]);
    let schedules = get(&listed, "schedules").as_arr().unwrap();
    assert_eq!(schedules.len(), 1);
    let row = &schedules[0];
    assert_eq!(text(row, "name"), "rent");
    assert_eq!(text(row, "schedule"), text(&created, "schedule"));
    assert_eq!(text(row, "next_date"), "2026-01-31");
    assert_eq!(integer(row, "next_index"), 0);
    assert_eq!(get(row, "cancelled_at"), &Json::Null);
    // A different poster cannot stop the approved schedule without Approve.
    let (status, unauthorized) = run(
        &book,
        &[
            "schedule",
            "recurring",
            "cancel",
            "rent",
            "--reason",
            "unapproved stop",
            "--as",
            "other-preparer",
        ],
    );
    assert_ne!(status, 0);
    assert_eq!(text(&unauthorized, "event"), "error");
    assert_eq!(head(&book), created_at);
    let cancelled = ok(
        &book,
        &[
            "schedule",
            "recurring",
            "cancel",
            "rent",
            "--reason",
            "lease ended",
        ],
    );
    assert_eq!(text(&cancelled, "event"), "recurring_cancelled");
    let cancelled_at = integer(&cancelled, "recorded_at");
    assert!(cancelled_at > created_at);
    let repeated = ok(
        &book,
        &[
            "schedule",
            "recurring",
            "cancel",
            "rent",
            "--reason",
            "lease ended",
        ],
    );
    assert_eq!(get(&repeated, "already_recorded"), &Json::Bool(true));
    assert_eq!(integer(&repeated, "recorded_at"), cancelled_at);
    assert_eq!(head(&book), cancelled_at);
    let listed = ok(&book, &["schedule", "recurring", "list"]);
    let schedules = get(&listed, "schedules").as_arr().unwrap();
    assert_eq!(integer(&schedules[0], "cancelled_at"), cancelled_at);
    assert_eq!(get(&schedules[0], "next_date"), &Json::Null);
    assert_eq!(integer(&schedules[0], "next_index"), 0);
    assert_eq!(std::fs::read(&plan_file).unwrap(), bytes);
}
