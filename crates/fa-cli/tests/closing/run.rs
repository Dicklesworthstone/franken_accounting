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
fn close_run_command_preflights_every_draft_before_publishing_the_first_task() {
    let f = Fixture::new(false);
    let first = reviewed_draft(&f, "preflight-first", "15.00");
    let second = reviewed_draft(&f, "preflight-second", "5.00");
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
            "preflight",
            "--period",
            PERIOD,
            "--tasks",
            &definition,
            "--as",
            CONTROLLER,
        ],
    );
    append(&f, "preflight-second", "unreviewed-preflight-extra", "1.00");
    let before = head(&f.book);
    let args = [
        "close",
        "run",
        "--run",
        "preflight",
        "--as",
        CONTROLLER,
        "--yes",
    ];
    for _ in 0..2 {
        let (code, refused) = run(&f.book, &args);
        assert_ne!(
            code, 0,
            "the changed later draft must refuse the invocation"
        );
        assert_eq!(text(&refused, "event"), "error");
        let detail = get(&refused, "detail");
        assert_eq!(text(detail, "pending_task"), "second");
        assert!(get(detail, "completed").as_arr().unwrap().is_empty());
        assert_eq!(head(&f.book), before);
        let durable = status(&f, "preflight");
        assert_eq!(get(task(&durable, "first"), "completion"), &Json::Null);
        assert_eq!(get(task(&durable, "second"), "completion"), &Json::Null);
    }
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
    ok(
        &f.book,
        &[
            "close", "step", "--run", "partial", "--task", "first", "--as", CONTROLLER, "--yes",
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
    assert!(completed.is_empty());
    assert_eq!(head(&f.book), before);
    let durable = status(&f, "partial");
    assert_ne!(get(task(&durable, "first"), "completion"), &Json::Null);
    assert_eq!(get(task(&durable, "second"), "completion"), &Json::Null);
    assert_ne!(run(&f.book, &args).0, 0);
    assert_eq!(
        head(&f.book),
        before,
        "retry preserves exactly the first task's one effect"
    );
}

fn close_events(f: &Fixture, args: &[&str]) -> Vec<Json> {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&f.book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "args={args:?}: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            fa_cli::verbs::registry().unwrap().check_line(line).unwrap();
            json::parse(line).unwrap()
        })
        .collect()
}

fn combined_certificate(f: &Fixture, name: &str) -> String {
    let events = close_events(f, &["close", "dry-run", "--run", name, "--certify"]);
    let certificate = events
        .iter()
        .find(|event| text(event, "event") == "report_certificate")
        .unwrap();
    format!("C:{}", text(certificate, "oid"))
}

#[test]
fn combined_close_rehearsal_retains_and_replays_after_real_execution() {
    let f = Fixture::new(false);
    f.post("combined-source", "1000", "4000", "100.00");
    let first = reviewed_draft(&f, "combined-first", "15.00");
    let second = reviewed_draft(&f, "combined-second", "5.00");
    let definition = format!(
        r#"[
        {{"id":"first","certificate":"{first}"}},
        {{"id":"second","depends_on":["first"],"certificate":"{second}"}},
        {{"id":"finish","depends_on":["second"],"transition":"close"}}
    ]"#
    );
    ok(
        &f.book,
        &[
            "close",
            "start",
            "--run",
            "combined",
            "--period",
            PERIOD,
            "--tasks",
            &definition,
            "--as",
            CONTROLLER,
        ],
    );
    let before = head(&f.book);
    let review = ok(
        &f.book,
        &["close", "dry-run", "--run", "combined", "--period", PERIOD],
    );
    assert_eq!(text(&review, "event"), "close_run_rehearsal");
    assert_eq!(
        head(&f.book),
        before,
        "plain combined rehearsal never publishes"
    );
    assert_eq!(get(&review, "complete_on_trunk"), &Json::Bool(false));
    let rows = get(&review, "rows").as_arr().unwrap();
    let expense = rows.iter().find(|row| text(row, "code") == "6000").unwrap();
    assert_eq!(text(expense, "delta"), "20.00 USD");
    let tasks = get(&review, "tasks").as_arr().unwrap();
    assert_eq!(tasks.len(), 3);
    assert_eq!(text(&tasks[0], "state"), "rehearsed");
    assert_eq!(text(&tasks[1], "state"), "rehearsed");
    assert_eq!(text(&tasks[2], "state"), "transition-review-required");

    let certificate_path = f.dir.join("combined.cert").display().to_string();
    let certified = close_events(
        &f,
        &[
            "close",
            "dry-run",
            "--run",
            "combined",
            "--certificate-out",
            &certificate_path,
        ],
    );
    assert_eq!(certified.len(), 2);
    let certificate_event = certified
        .iter()
        .find(|event| text(event, "event") == "report_certificate")
        .unwrap();
    let oid = format!("C:{}", text(certificate_event, "oid"));
    let original = std::fs::read(&certificate_path).unwrap();
    let certificate = fa::CloseRunRehearsalCertificate::decode(&original).unwrap();
    assert_eq!(
        fa::ReportArtifact::decode(&original).unwrap().family(),
        fa::ReportArtifactFamily::CloseRunRehearsal
    );
    assert_eq!(
        head(&f.book),
        before + 1,
        "only complete certificate retention publishes"
    );
    assert_eq!(
        get(task(&status(&f, "combined"), "first"), "completion"),
        &Json::Null
    );

    // Review generation after real posting is a writing command even with
    // --plan-out. It emits progress and a separate unexecuted native plan.
    let plan_path = f.dir.join("combined-close.plan").display().to_string();
    let executed = close_events(
        &f,
        &[
            "close",
            "run",
            "--run",
            "combined",
            "--rehearsal",
            &oid,
            "--task",
            "finish",
            "--key",
            "combined-finish",
            "--reason",
            "AuditComplete",
            "--plan-out",
            &plan_path,
            "--as",
            CONTROLLER,
            "--yes",
        ],
    );
    assert_eq!(executed.len(), 2);
    assert_eq!(text(&executed[0], "state"), "transition-review");
    assert_eq!(
        text(&executed[0], "rehearsal"),
        oid.strip_prefix("C:").unwrap()
    );
    assert_eq!(get(&executed[0], "completed").as_arr().unwrap().len(), 2);
    assert_eq!(text(&executed[1], "event"), "close_task_planned");
    assert_eq!(
        get(task(&status(&f, "combined"), "finish"), "completion"),
        &Json::Null
    );
    let remaining = combined_certificate(&f, "combined");
    let completed = ok(
        &f.book,
        &[
            "close",
            "run",
            "--run",
            "combined",
            "--rehearsal",
            &remaining,
            "--task",
            "finish",
            "--plan",
            &plan_path,
            "--as",
            CONTROLLER,
            "--yes",
        ],
    );
    assert_eq!(
        text(&completed, "rehearsal"),
        remaining.strip_prefix("C:").unwrap()
    );
    let after = head(&f.book);
    let output_path = f.dir.join("combined-replayed.bin").display().to_string();
    let replay = close_events(&f, &["replay", &oid, "--output", &output_path]);
    assert_eq!(replay.len(), 2);
    assert_eq!(text(&replay[0], "event"), "close_run_rehearsal");
    assert_eq!(get(&replay[0], "rows"), get(&review, "rows"));
    assert_eq!(get(&replay[0], "tasks"), get(&review, "tasks"));
    assert_eq!(
        get(&replay[0], "complete_on_trunk"),
        &Json::Bool(false),
        "historical rehearsal never substitutes current completion"
    );
    assert_eq!(std::fs::read(output_path).unwrap(), certificate.output());
    assert_eq!(head(&f.book), after, "replay is a read");
    assert_ne!(
        run(&f.book, &["certificate", "status", &oid]).0,
        0,
        "native baseline freshness cannot claim current close readiness"
    );
}

#[test]
fn combined_close_review_rejects_conflicting_selectors_before_retention() {
    let f = Fixture::new(false);
    let review = reviewed_draft(&f, "selector-draft", "1.00");
    let tasks = format!(r#"[{{"id":"one","certificate":"{review}"}}]"#);
    ok(
        &f.book,
        &[
            "close",
            "start",
            "--run",
            "selector-run",
            "--period",
            PERIOD,
            "--tasks",
            &tasks,
            "--as",
            CONTROLLER,
        ],
    );
    let before = head(&f.book);
    for flags in [
        vec!["--draft", "selector-draft"],
        vec!["--period", "FY2026-P11"],
        vec!["--certificate-out", "-"],
    ] {
        let mut args = vec!["close", "dry-run", "--run", "selector-run", "--certify"];
        args.extend(flags);
        assert_eq!(run(&f.book, &args).0, 2);
        assert_eq!(head(&f.book), before);
    }
}

#[test]
fn close_run_selected_rehearsal_rejects_offsetting_activity_and_accepts_a_fresh_review() {
    let f = Fixture::new(false);
    let first = reviewed_draft(&f, "selected-first", "15.00");
    let second = reviewed_draft(&f, "selected-second", "5.00");
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
            "selected",
            "--period",
            PERIOD,
            "--tasks",
            &definition,
            "--as",
            CONTROLLER,
        ],
    );
    let selected = combined_certificate(&f, "selected");
    f.post("selected-later", "1000", "4000", "2.00");
    f.post("selected-offset", "4000", "1000", "2.00");
    let before = head(&f.book);
    for _ in 0..2 {
        let (code, refusal) = run(
            &f.book,
            &[
                "close",
                "run",
                "--run",
                "selected",
                "--rehearsal",
                &selected,
                "--as",
                CONTROLLER,
                "--yes",
            ],
        );
        assert_eq!(
            code, 6,
            "a changed source requires a fresh review: {refusal:?}"
        );
        assert_eq!(head(&f.book), before);
        let view = status(&f, "selected");
        assert_eq!(get(task(&view, "first"), "completion"), &Json::Null);
        assert_eq!(get(task(&view, "second"), "completion"), &Json::Null);
    }
    let fresh = combined_certificate(&f, "selected");
    let before = head(&f.book);
    let args = [
        "close",
        "run",
        "--run",
        "selected",
        "--rehearsal",
        &fresh,
        "--as",
        CONTROLLER,
        "--yes",
    ];
    let progress = ok(&f.book, &args);
    assert_eq!(text(&progress, "state"), "complete");
    assert_eq!(text(&progress, "rehearsal"), fresh.strip_prefix("C:").unwrap());
    assert_eq!(get(&progress, "completed").as_arr().unwrap().len(), 2);
    assert_eq!(head(&f.book), before + 2);
    assert_eq!(run(&f.book, &args).0, 6);
    assert_eq!(
        head(&f.book),
        before + 2,
        "the completed review is stale and cannot repeat its effects"
    );

    let complete = combined_certificate(&f, "selected");
    let before = head(&f.book);
    let retried = ok(
        &f.book,
        &[
            "close",
            "run",
            "--run",
            "selected",
            "--rehearsal",
            &complete,
            "--as",
            CONTROLLER,
            "--yes",
        ],
    );
    assert_eq!(text(&retried, "state"), "complete");
    assert!(get(&retried, "completed").as_arr().unwrap().is_empty());
    assert_eq!(head(&f.book), before);
}

#[test]
fn close_run_selected_rehearsal_requires_the_exact_run_family_and_locator() {
    let f = Fixture::new(false);
    let first = reviewed_draft(&f, "binding-first", "15.00");
    let other = reviewed_draft(&f, "binding-other", "15.00");
    for (name, certificate) in [("binding", &first), ("other", &other)] {
        let definition = format!(r#"[{{"id":"one","certificate":"{certificate}"}}]"#);
        ok(
            &f.book,
            &[
                "close",
                "start",
                "--run",
                name,
                "--period",
                PERIOD,
                "--tasks",
                &definition,
                "--as",
                CONTROLLER,
            ],
        );
    }
    let selected = combined_certificate(&f, "binding");
    let unknown = format!("C:{}", "00".repeat(32));
    let before = head(&f.book);
    for (name, selector) in [
        ("binding", first.as_str()),
        ("binding", unknown.as_str()),
        ("binding", "C:invalid"),
        ("other", selected.as_str()),
    ] {
        assert_ne!(
            run(
                &f.book,
                &[
                    "close",
                    "run",
                    "--run",
                    name,
                    "--rehearsal",
                    selector,
                    "--as",
                    CONTROLLER,
                    "--yes",
                ],
            )
            .0,
            0,
            "wrong family, missing digest, malformed locator or another run must refuse",
        );
        assert_eq!(head(&f.book), before);
    }
    for name in ["binding", "other"] {
        assert_eq!(
            get(task(&status(&f, name), "one"), "completion"),
            &Json::Null
        );
    }
    assert_eq!(
        run(
            &f.book,
            &[
                "close",
                "run",
                "--run",
                "binding",
                "--rehearsal",
                &selected,
                "--rehearsal",
                &selected,
                "--as",
                CONTROLLER,
                "--yes",
            ],
        )
        .0,
        2,
        "a repeated selector cannot silently replace the operator's choice",
    );
    assert_eq!(
        run(
            &f.book,
            &["close", "status", "--run", "binding", "--rehearsal", &selected],
        )
        .0,
        2,
        "the execution selector belongs only to close run",
    );
    assert_eq!(head(&f.book), before);
}
