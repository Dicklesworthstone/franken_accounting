//! Actual task effects, durable restart, independent approval and safe retry.

use super::*;

const PERIOD: &str = "FY2026-P12";
const PREPARER: &str = "close-task-preparer";
const CONTROLLER: &str = "close-task-controller";

fn append(f: &Fixture, draft: &str, key: &str, amount: &str) {
    let path = write(
        &f.dir,
        &format!("{key}.json"),
        &format!(
            r#"{{"effective_date":"2026-12-30","description":"Reviewed close expense","idempotency_key":"{key}","evidence":["{}"],"legs":[{{"side":"debit","account":"6000","amount":"{amount} USD"}},{{"side":"credit","account":"1000","amount":"{amount} USD"}}]}}"#,
            f.evidence,
        ),
    );
    ok(
        &f.book,
        &["draft", "plan", draft, "--intent", &path, "--as", PREPARER],
    );
}

fn reviewed_draft(f: &Fixture, draft: &str, amount: &str) -> String {
    ok(&f.book, &["draft", "new", draft, "--as", PREPARER]);
    append(f, draft, &format!("{draft}-entry"), amount);
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&f.book)
        .args([
            "close",
            "dry-run",
            "--draft",
            draft,
            "--period",
            PERIOD,
            "--certify",
            "--json",
        ])
        .env_remove("FA_BOOK")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let events: Vec<Json> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            fa_cli::verbs::registry().unwrap().check_line(line).unwrap();
            json::parse(line).unwrap()
        })
        .collect();
    let certificate = events
        .iter()
        .find(|event| text(event, "event") == "report_certificate")
        .unwrap();
    format!("C:{}", text(certificate, "oid"))
}

fn status(f: &Fixture, name: &str) -> Json {
    get(&ok(&f.book, &["close", "status", "--run", name]), "run").clone()
}

fn task<'a>(view: &'a Json, id: &str) -> &'a Json {
    get(view, "tasks")
        .as_arr()
        .unwrap()
        .iter()
        .find(|task| text(task, "id") == id)
        .unwrap()
}

#[test]
fn close_run_resumes_real_draft_tasks_then_closes_and_independently_locks_the_period() {
    let f = Fixture::new(false);
    f.post("source-sale", "1000", "4000", "100.00");
    let first = reviewed_draft(&f, "expense-a", "15.00");
    let second = reviewed_draft(&f, "expense-b", "5.00");
    let definition = format!(
        r#"[
        {{"id":"first","certificate":"{first}"}},
        {{"id":"second","depends_on":["first"],"certificate":"{second}"}},
        {{"id":"finish","depends_on":["second"],"transition":"close"}}
    ]"#
    );
    let started = ok(
        &f.book,
        &[
            "close",
            "start",
            "--run",
            "december",
            "--period",
            PERIOD,
            "--tasks",
            &definition,
            "--as",
            CONTROLLER,
        ],
    );
    let view = get(&started, "run");
    assert_eq!(get(task(view, "first"), "ready"), &Json::Bool(true));
    assert_eq!(get(task(view, "second"), "ready"), &Json::Bool(false));
    assert_eq!(get(view, "complete"), &Json::Bool(false));
    let (agent_code, agent_view) =
        closing_agent(&f, &["read"], &["close", "status", "--run", "december"]);
    assert_eq!(
        agent_code, 0,
        "an Agent reader can inspect readiness: {agent_view:?}"
    );
    assert_eq!(get(&agent_view, "run"), view);

    let step = |id: &'static str| {
        vec![
            "close", "step", "--run", "december", "--task", id, "--as", CONTROLLER, "--yes",
        ]
    };
    let before = head(&f.book);
    let (code, _) = run(&f.book, &step("second"));
    assert_ne!(code, 0, "dependency refusal must precede publication");
    assert_eq!(head(&f.book), before);
    let mut owner_step = step("first");
    owner_step[7] = PREPARER;
    assert_ne!(
        run(&f.book, &owner_step).0,
        0,
        "the draft owner cannot promote its own work"
    );
    assert_eq!(head(&f.book), before);

    let first_done = ok(&f.book, &step("first"));
    assert_eq!(get(&first_done, "already_recorded"), &Json::Bool(false));
    assert_eq!(
        head(&f.book),
        before + 1,
        "effect and receipt are one publication"
    );
    assert_eq!(
        integer(get(&first_done, "receipt"), "recorded_at"),
        before + 1
    );
    let reopened = status(&f, "december");
    assert_eq!(get(task(&reopened, "second"), "ready"), &Json::Bool(true));
    assert_eq!(
        get(task(&reopened, "first"), "completion"),
        get(&first_done, "receipt")
    );

    let retry_head = head(&f.book);
    let retry = ok(&f.book, &step("first"));
    assert_eq!(get(&retry, "already_recorded"), &Json::Bool(true));
    assert_eq!(get(&retry, "receipt"), get(&first_done, "receipt"));
    assert_eq!(
        head(&f.book),
        retry_head,
        "restart retry creates no duplicate entry or receipt"
    );
    ok(&f.book, &step("second"));
    let reopened = status(&f, "december");
    assert_eq!(get(task(&reopened, "finish"), "ready"), &Json::Bool(true));

    let plan_path = f.dir.join("period-close.plan").display().to_string();
    let before_plan = head(&f.book);
    ok(
        &f.book,
        &[
            "close",
            "step",
            "--run",
            "december",
            "--task",
            "finish",
            "--key",
            "december-period-close",
            "--reason",
            "AuditComplete",
            "--dry-run",
            "--plan-out",
            &plan_path,
            "--as",
            CONTROLLER,
        ],
    );
    assert_eq!(head(&f.book), before_plan);
    let execute = [
        "close", "step", "--run", "december", "--task", "finish", "--plan", &plan_path, "--as",
        CONTROLLER, "--yes",
    ];
    // Open -> Closed has no independent approver under the native registry.
    // The workflow preserves that law instead of inventing a new requirement.
    let finished = ok(&f.book, &execute);
    assert_eq!(head(&f.book), before_plan + 1);
    assert_eq!(get(get(&finished, "run"), "complete"), &Json::Bool(true));
    assert_eq!(status(&f, "december"), get(&finished, "run").clone());
    let retried = ok(&f.book, &execute);
    assert_eq!(get(&retried, "receipt"), get(&finished, "receipt"));
    assert_eq!(head(&f.book), before_plan + 1);

    // Closed -> Locked requires an independent approval of the exact plan.
    ok(
        &f.book,
        &[
            "close",
            "start",
            "--run",
            "december-lock",
            "--period",
            PERIOD,
            "--tasks",
            r#"[{"id":"lock","transition":"lock"}]"#,
            "--as",
            CONTROLLER,
        ],
    );
    let lock_path = f.dir.join("period-lock.plan").display().to_string();
    let before_lock_plan = head(&f.book);
    let plan = ok(
        &f.book,
        &[
            "close",
            "step",
            "--run",
            "december-lock",
            "--task",
            "lock",
            "--key",
            "december-period-lock",
            "--reason",
            "AuditComplete",
            "--dry-run",
            "--plan-out",
            &lock_path,
            "--as",
            CONTROLLER,
        ],
    );
    assert_eq!(head(&f.book), before_lock_plan);
    let lock = [
        "close",
        "step",
        "--run",
        "december-lock",
        "--task",
        "lock",
        "--plan",
        &lock_path,
        "--as",
        CONTROLLER,
        "--yes",
    ];
    assert_ne!(
        run(&f.book, &lock).0,
        0,
        "Lock still requires its native independent approval"
    );
    assert_eq!(head(&f.book), before_lock_plan);
    let approval = ok(
        &f.book,
        &[
            "approve",
            "--proposal",
            text(&plan, "proposal_digest"),
            "--as",
            "close-task-auditor",
        ],
    );
    let mut approved = lock.to_vec();
    approved.extend(["--approval", text(&approval, "approval_vid")]);
    let before_close = head(&f.book);
    let finished = ok(&f.book, &approved);
    assert_eq!(head(&f.book), before_close + 1);
    assert_eq!(get(get(&finished, "run"), "complete"), &Json::Bool(true));
    assert_eq!(status(&f, "december-lock"), get(&finished, "run").clone());
    let retried = ok(&f.book, &approved);
    assert_eq!(get(&retried, "receipt"), get(&finished, "receipt"));
    assert_eq!(head(&f.book), before_close + 1);
    let periods = ok(&f.book, &["period", "list"]);
    assert!(
        get(&periods, "periods")
            .as_arr()
            .unwrap()
            .iter()
            .any(|period| { text(period, "code") == PERIOD && text(period, "state") == "Locked" })
    );
}

#[test]
fn close_run_rejects_cyclic_graphs_and_changed_reviewed_draft_sources() {
    let f = Fixture::new(false);
    let first = reviewed_draft(&f, "reviewed-a", "1.00");
    let second = reviewed_draft(&f, "reviewed-b", "2.00");
    let cyclic = format!(
        r#"[
        {{"id":"a","depends_on":["b"],"certificate":"{first}"}},
        {{"id":"b","depends_on":["a"],"certificate":"{second}"}}
    ]"#
    );
    let before = head(&f.book);
    assert_ne!(
        run(
            &f.book,
            &[
                "close", "start", "--run", "cycle", "--period", PERIOD, "--tasks", &cyclic, "--as",
                CONTROLLER
            ]
        )
        .0,
        0
    );
    assert_eq!(head(&f.book), before);
    append(&f, "reviewed-a", "unreviewed-extra", "3.00");
    let before = head(&f.book);
    let stale = format!(r#"[{{"id":"a","certificate":"{first}"}}]"#);
    assert_ne!(
        run(
            &f.book,
            &[
                "close", "start", "--run", "stale", "--period", PERIOD, "--tasks", &stale, "--as",
                CONTROLLER
            ]
        )
        .0,
        0
    );
    assert_eq!(head(&f.book), before);
}

#[test]
fn close_run_command_executes_ready_tasks_resumes_and_waits_for_native_period_review() {
    let f = Fixture::new(false);
    f.post("run-source", "1000", "4000", "100.00");
    let first = reviewed_draft(&f, "run-first", "15.00");
    let second = reviewed_draft(&f, "run-second", "5.00");
    let definition = format!(
        r#"[
        {{"id":"z-first","certificate":"{first}"}},
        {{"id":"a-second","depends_on":["z-first"],"certificate":"{second}"}},
        {{"id":"finish","depends_on":["a-second"],"transition":"close"}}
    ]"#
    );
    ok(
        &f.book,
        &[
            "close",
            "start",
            "--run",
            "automatic",
            "--period",
            PERIOD,
            "--tasks",
            &definition,
            "--as",
            CONTROLLER,
        ],
    );
    let before = head(&f.book);
    assert_eq!(
        run(
            &f.book,
            &["close", "run", "--run", "automatic", "--as", CONTROLLER]
        )
        .0,
        7
    );
    assert_eq!(
        head(&f.book),
        before,
        "explicit execution confirmation remains mandatory"
    );
    assert_ne!(
        run(
            &f.book,
            &[
                "close",
                "run",
                "--run",
                "automatic",
                "--task",
                "z-first",
                "--key",
                "wrong-target",
                "--reason",
                "AuditComplete",
                "--as",
                CONTROLLER,
                "--yes"
            ]
        )
        .0,
        0
    );
    assert_eq!(
        head(&f.book),
        before,
        "a wrong transition target refuses before any task publishes"
    );

    let args = [
        "close",
        "run",
        "--run",
        "automatic",
        "--as",
        CONTROLLER,
        "--yes",
    ];
    let progress = ok(&f.book, &args);
    assert_eq!(text(&progress, "event"), "close_run_progress");
    assert_eq!(text(&progress, "state"), "transition-required");
    assert_eq!(text(&progress, "pending_task"), "finish");
    let completed = get(&progress, "completed").as_arr().unwrap();
    assert_eq!(completed.len(), 2);
    assert_eq!(text(&completed[0], "task"), "z-first");
    assert_eq!(text(&completed[1], "task"), "a-second");
    assert_eq!(
        head(&f.book),
        before + 2,
        "each effect and its receipt share one transaction"
    );
    let retried = ok(&f.book, &args);
    assert!(get(&retried, "completed").as_arr().unwrap().is_empty());
    assert_eq!(get(&retried, "run"), get(&progress, "run"));
    assert_eq!(
        head(&f.book),
        before + 2,
        "reopening cannot repeat completed effects"
    );

    let plan_path = f.dir.join("automatic-close.plan").display().to_string();
    ok(
        &f.book,
        &[
            "close",
            "step",
            "--run",
            "automatic",
            "--task",
            "finish",
            "--key",
            "automatic-finish",
            "--reason",
            "AuditComplete",
            "--dry-run",
            "--plan-out",
            &plan_path,
            "--as",
            CONTROLLER,
        ],
    );
    let execute = [
        "close",
        "run",
        "--run",
        "automatic",
        "--task",
        "finish",
        "--plan",
        &plan_path,
        "--as",
        CONTROLLER,
        "--yes",
    ];
    let finished = ok(&f.book, &execute);
    assert_eq!(text(&finished, "state"), "complete");
    assert_eq!(get(get(&finished, "run"), "complete"), &Json::Bool(true));
    assert_eq!(get(&finished, "completed").as_arr().unwrap().len(), 1);
    let completed_head = head(&f.book);
    let final_retry = ok(&f.book, &execute);
    assert!(get(&final_retry, "completed").as_arr().unwrap().is_empty());
    assert_eq!(get(&final_retry, "run"), get(&finished, "run"));
    assert_eq!(head(&f.book), completed_head);
}

#[test]
fn close_run_command_reports_durable_partial_progress_on_later_task_refusal() {
    let f = Fixture::new(false);
    let first = reviewed_draft(&f, "partial-first", "15.00");
    let second = reviewed_draft(&f, "partial-second", "5.00");
    let definition = format!(
        r#"[
        {{"id":"first","certificate":"{first}"}},
        {{"id":"second","depends_on":["first"],"certificate":"{second}"}}
    ]"#
    );
    ok(
        &f.book,
        &[
            "close",
            "start",
            "--run",
            "partial",
            "--period",
            PERIOD,
            "--tasks",
            &definition,
            "--as",
            CONTROLLER,
        ],
    );
    append(&f, "partial-second", "unreviewed-extra", "1.00");
    let before = head(&f.book);
    let args = [
        "close", "run", "--run", "partial", "--as", CONTROLLER, "--yes",
    ];
    let (code, refused) = run(&f.book, &args);
    assert_ne!(code, 0, "a stopped close never reports whole-run success");
    assert_eq!(text(&refused, "event"), "error");
    let detail = get(&refused, "detail");
    assert_eq!(text(detail, "state"), "refused");
    assert_eq!(text(detail, "pending_task"), "second");
    let completed = get(detail, "completed").as_arr().unwrap();
    assert_eq!(completed.len(), 1);
    assert_eq!(text(&completed[0], "task"), "first");
    assert_eq!(head(&f.book), before + 1);
    let durable = status(&f, "partial");
    assert_ne!(get(task(&durable, "first"), "completion"), &Json::Null);
    assert_eq!(get(task(&durable, "second"), "completion"), &Json::Null);
    assert_ne!(run(&f.book, &args).0, 0);
    assert_eq!(
        head(&f.book),
        before + 1,
        "retry preserves exactly the first task's one effect"
    );
}
