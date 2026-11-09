//! The task JSON, hypothetical verification, durable completion and native
//! terminal approval flow agree across separate real CLI processes.

use super::*;

const PERIOD: &str = "FY2026-CLOSE";
const CONTROLLER: &str = "checkpoint-controller";

fn start(f: &Fixture, name: &str, target: &str) -> Json {
    let tasks = format!(
        r#"[
        {{"id":"verify","verify_year_end_close":2026}},
        {{"id":"finish","depends_on":["verify"],"transition":"{target}"}}
    ]"#
    );
    ok(
        &f.book,
        &[
            "close", "start", "--run", name, "--period", PERIOD, "--tasks", &tasks, "--as",
            CONTROLLER,
        ],
    )
}

fn task<'a>(run: &'a Json, id: &str) -> &'a Json {
    get(run, "tasks")
        .as_arr()
        .unwrap()
        .iter()
        .find(|task| text(task, "id") == id)
        .unwrap()
}

fn status(f: &Fixture, name: &str) -> Json {
    get(&ok(&f.book, &["close", "status", "--run", name]), "run").clone()
}

#[test]
fn closing_checkpoint_cli_rehearses_then_locks_with_original_native_approval() {
    let f = Fixture::new(true);
    f.post("checkpoint-sale", "1000", "4000", "100.00");
    f.close_now("checkpoint-native-close");
    ok(
        &f.book,
        &["period", "close", PERIOD, "--reason", "Scheduled"],
    );
    let started = start(&f, "guarded-lock", "lock");
    let verify = task(get(&started, "run"), "verify");
    assert_eq!(text(verify, "kind"), "verify-year-end-close");
    assert_eq!(integer(verify, "fiscal_year"), 2026);
    let before = head(&f.book);
    let rehearsed = ok(&f.book, &["close", "dry-run", "--run", "guarded-lock"]);
    assert_eq!(head(&f.book), before);
    let verification = task(&rehearsed, "verify");
    assert_eq!(text(verification, "state"), "year-end-verified");
    assert_eq!(
        integer(get(verification, "verification"), "fiscal_year"),
        2026
    );
    assert_eq!(
        text(get(verification, "verification"), "source_digest").len(),
        64
    );
    assert_eq!(
        text(get(verification, "verification"), "review_basis").len(),
        64
    );
    let progress = ok(
        &f.book,
        &[
            "close",
            "run",
            "--run",
            "guarded-lock",
            "--as",
            CONTROLLER,
            "--yes",
        ],
    );
    assert_eq!(text(&progress, "state"), "transition-required");
    assert_eq!(get(&progress, "completed").as_arr().unwrap().len(), 1);
    assert_eq!(head(&f.book), before + 1);
    let original_receipt = get(task(get(&progress, "run"), "verify"), "completion").clone();
    let path = f.dir.join("checked-lock.plan").display().to_string();
    let plan = ok(
        &f.book,
        &[
            "close",
            "step",
            "--run",
            "guarded-lock",
            "--task",
            "finish",
            "--key",
            "checked-lock",
            "--reason",
            "AuditComplete",
            "--dry-run",
            "--plan-out",
            &path,
            "--as",
            CONTROLLER,
        ],
    );
    let lock = [
        "close",
        "step",
        "--run",
        "guarded-lock",
        "--task",
        "finish",
        "--plan",
        &path,
        "--as",
        CONTROLLER,
        "--yes",
    ];
    let before_approval = head(&f.book);
    assert_ne!(
        run(&f.book, &lock).0,
        0,
        "year-end verification is not native lock approval"
    );
    assert_eq!(head(&f.book), before_approval);
    let approval = ok(
        &f.book,
        &[
            "approve",
            "--proposal",
            text(&plan, "proposal_digest"),
            "--as",
            "checkpoint-auditor",
        ],
    );
    let mut approved = lock.to_vec();
    approved.extend(["--approval", text(&approval, "approval_vid")]);
    let finished = ok(&f.book, &approved);
    assert_eq!(get(get(&finished, "run"), "complete"), &Json::Bool(true));
    assert_eq!(
        get(task(get(&finished, "run"), "verify"), "completion"),
        &original_receipt
    );
    let before_retry = head(&f.book);
    let retried = ok(
        &f.book,
        &[
            "close",
            "step",
            "--run",
            "guarded-lock",
            "--task",
            "verify",
            "--as",
            CONTROLLER,
            "--yes",
        ],
    );
    assert_eq!(get(&retried, "receipt"), &original_receipt);
    assert_eq!(head(&f.book), before_retry);

    // December remains Open: new backdated activity makes the current year
    // need a reclose without invalidating this historical successful run.
    f.post("later-december", "1000", "4000", "1.00");
    assert_eq!(
        get(&status(&f, "guarded-lock"), "complete"),
        &Json::Bool(true)
    );
    assert_eq!(run(&f.book, &["verify", "close", "FY2026"]).0, 8);
}

#[test]
fn closing_checkpoint_cli_rejects_net_zero_source_changes_before_terminal_plan() {
    let f = Fixture::new(true);
    f.post("checkpoint-source", "1000", "4000", "100.00");
    f.close_now("checkpoint-close");
    start(&f, "stale-check", "close");
    let verified = ok(
        &f.book,
        &[
            "close",
            "step",
            "--run",
            "stale-check",
            "--task",
            "verify",
            "--as",
            CONTROLLER,
            "--yes",
        ],
    );
    f.post("offset-sale", "1000", "4000", "1.00");
    f.post("offset-return", "4000", "1000", "1.00");
    ok(&f.book, &["verify", "close", "FY2026"]);
    let before = head(&f.book);
    let (code, refused) = run(
        &f.book,
        &[
            "close",
            "step",
            "--run",
            "stale-check",
            "--task",
            "finish",
            "--key",
            "stale-finish",
            "--reason",
            "1",
            "--dry-run",
            "--as",
            CONTROLLER,
        ],
    );
    assert_eq!(code, 6);
    assert!(text(&refused, "message").contains("stale completion"));
    assert_eq!(head(&f.book), before);
    let view = status(&f, "stale-check");
    assert_eq!(
        get(task(&view, "verify"), "completion"),
        get(&verified, "receipt")
    );
    assert_eq!(get(task(&view, "finish"), "completion"), &Json::Null);
    assert_ne!(
        run(&f.book, &["close", "dry-run", "--run", "stale-check"]).0,
        0
    );
    assert_eq!(head(&f.book), before);
}

#[test]
fn closing_checkpoint_cli_rejects_ambiguous_or_unclosed_checks_without_publication() {
    let f = Fixture::new(true);
    let before = head(&f.book);
    for tasks in [
        r#"[{"id":"verify","verify_year_end_close":"2026"}]"#,
        r#"[{"id":"verify","verify_year_end_close":null}]"#,
        r#"[{"id":"verify","verify_year_end_close":2147483648}]"#,
        r#"[{"id":"verify","verify_year_end_close":2026,"transition":"close"}]"#,
        r#"[{"id":"verify","verify_year_end_close":2027}]"#,
        r#"[{"id":"verify","verify_year_end_close":2026},{"id":"again","verify_year_end_close":2026}]"#,
    ] {
        assert_ne!(
            run(
                &f.book,
                &[
                    "close", "start", "--run", "invalid", "--period", PERIOD, "--tasks", tasks,
                    "--as", CONTROLLER
                ]
            )
            .0,
            0
        );
        assert_eq!(head(&f.book), before);
    }
    start(&f, "missing-close", "close");
    let before = head(&f.book);
    assert_ne!(
        run(
            &f.book,
            &[
                "close",
                "step",
                "--run",
                "missing-close",
                "--task",
                "verify",
                "--as",
                CONTROLLER,
                "--yes"
            ]
        )
        .0,
        0
    );
    assert_eq!(head(&f.book), before);
    assert_eq!(
        get(task(&status(&f, "missing-close"), "verify"), "completion"),
        &Json::Null
    );
}
