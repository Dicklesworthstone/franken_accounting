//! Durable close task execution and restart inspection.

use std::io::Read;

use fa::{CloseRunStop, CloseRunTransition, ReviewedCloseAction, ReviewedCloseTask};
use fa_journal::close_run::{CloseRunView, CloseTaskReceipt};
use fa_model::{ApprovalRef, CloseTaskBodyAction};
use fa_time::PeriodTransition;

use super::{options, required};
use crate::args::Args;
use crate::cli::{
    Ctx, Fail, Files, Stdin, hex, parse_digest, parse_vid, read_plan_bytes, usage, write_post_plan,
};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa close start --run december --period FY2026-P12 --tasks tasks.json";
const MAX_TASK_INPUT_BYTES: usize = 65_536;

fn task_input(files: &Files, input: &str) -> Result<String, Fail> {
    if input.trim_start().starts_with('[') {
        if input.len() > MAX_TASK_INPUT_BYTES {
            return Err(usage("close task input exceeds 64 KiB", EXAMPLE));
        }
        return Ok(input.to_string());
    }
    let read = |reader: &mut dyn Read| -> Result<Vec<u8>, Fail> {
        let mut bytes = Vec::new();
        reader
            .take(MAX_TASK_INPUT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| usage(format!("{input}: {error}"), EXAMPLE))?;
        Ok(bytes)
    };
    let bytes = if input == "-" {
        match &files.stdin {
            Stdin::Forwarded(bytes) if bytes.len() <= MAX_TASK_INPUT_BYTES => bytes.clone(),
            Stdin::Forwarded(_) => return Err(usage("close task input exceeds 64 KiB", EXAMPLE)),
            Stdin::Missing => return Err(usage("--tasks - needs JSON on stdin", EXAMPLE)),
            Stdin::Process => read(&mut std::io::stdin().lock())?,
        }
    } else {
        let mut file = std::fs::File::open(files.resolve(input))
            .map_err(|error| usage(format!("{input}: {error}"), EXAMPLE))?;
        read(&mut file)?
    };
    if bytes.len() > MAX_TASK_INPUT_BYTES {
        return Err(usage("close task input exceeds 64 KiB", EXAMPLE));
    }
    String::from_utf8(bytes).map_err(|_| usage("close task input must be UTF-8 JSON", EXAMPLE))
}

fn task_definition(text: &str) -> Result<Vec<ReviewedCloseTask>, Fail> {
    if text.len() > MAX_TASK_INPUT_BYTES {
        return Err(usage("close task input exceeds 64 KiB", EXAMPLE));
    }
    let value = crate::json::parse(text)
        .map_err(|error| usage(format!("invalid close task JSON: {error}"), EXAMPLE))?;
    let rows = value
        .as_arr()
        .ok_or_else(|| usage("--tasks is a JSON array of task objects", EXAMPLE))?;
    let mut tasks = Vec::with_capacity(rows.len());
    for row in rows {
        let Json::Obj(fields) = row else {
            return Err(usage("every close task must be an object", EXAMPLE));
        };
        if let Some((key, _)) = fields.iter().find(|(key, _)| {
            !matches!(
                key.as_str(),
                "id" | "depends_on" | "certificate" | "transition"
            )
        }) {
            return Err(usage(
                format!("unsupported close task field {key}"),
                EXAMPLE,
            ));
        }
        let string = |key: &str| {
            row.get(key)
                .and_then(Json::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    usage(
                        format!("close task {key} must be a nonempty string"),
                        EXAMPLE,
                    )
                })
        };
        let id = string("id")?.to_string();
        let depends_on = match row.get("depends_on") {
            None => Vec::new(),
            Some(Json::Arr(values)) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .filter(|value| !value.is_empty())
                        .map(String::from)
                        .ok_or_else(|| usage("each dependency must name a task ID", EXAMPLE))
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err(usage("depends_on must be an array of task IDs", EXAMPLE)),
        };
        let action = match (row.get("certificate"), row.get("transition")) {
            (Some(_), None) => {
                let certificate = string("certificate")?;
                let digest = certificate.strip_prefix("C:").unwrap_or(certificate);
                ReviewedCloseAction::DraftCertificate(parse_digest(digest, "certificate")?)
            }
            (None, Some(_)) => ReviewedCloseAction::PeriodTransition(match string("transition")? {
                "soft-close" => PeriodTransition::SoftClose,
                "close" => PeriodTransition::Close,
                "lock" => PeriodTransition::Lock,
                other => {
                    return Err(usage(
                        format!("unsupported close task transition {other}"),
                        "use soft-close, close or lock; posting tasks name a retained draft certificate",
                    ));
                }
            }),
            _ => {
                return Err(usage(
                    "each close task names exactly one certificate or transition",
                    EXAMPLE,
                ));
            }
        };
        tasks.push(ReviewedCloseTask {
            id,
            depends_on,
            action,
        });
    }
    Ok(tasks)
}

fn receipt_json(receipt: &CloseTaskReceipt) -> Json {
    obj(vec![
        ("record", s(format!("{:032x}", receipt.record.0))),
        ("effect", s(format!("{:032x}", receipt.effect.0))),
        ("recorded_at", Json::Int(i128::from(receipt.recorded_at.0))),
        ("principal", s(format!("{:032x}", receipt.principal.0))),
    ])
}

fn view_json(view: &CloseRunView) -> Json {
    let tasks = view
        .tasks
        .iter()
        .map(|task| {
            let definition = view
                .body
                .tasks
                .iter()
                .find(|definition| definition.id == task.id);
            let (kind, draft, certificate, transition) =
                match definition.map(|definition| &definition.action) {
                    Some(CloseTaskBodyAction::PromoteDraft {
                        name,
                        certificate_digest,
                        ..
                    }) => (
                        "promote-draft",
                        s(name),
                        s(format!("C:{}", hex(certificate_digest))),
                        Json::Null,
                    ),
                    Some(CloseTaskBodyAction::PeriodTransition { to }) => (
                        "period-transition",
                        Json::Null,
                        Json::Null,
                        s(match to {
                            2 => "soft-close",
                            3 => "close",
                            4 => "lock",
                            _ => "invalid",
                        }),
                    ),
                    None => ("invalid", Json::Null, Json::Null, Json::Null),
                };
            obj(vec![
                ("vid", s(format!("{:032x}", task.vid.0))),
                ("id", s(&task.id)),
                ("kind", s(kind)),
                ("draft", draft),
                ("certificate", certificate),
                ("transition", transition),
                (
                    "depends_on",
                    Json::Arr(definition.map_or_else(Vec::new, |definition| {
                        definition.depends_on.iter().map(s).collect()
                    })),
                ),
                ("ready", Json::Bool(task.ready)),
                (
                    "completion",
                    task.completion.as_ref().map_or(Json::Null, receipt_json),
                ),
            ])
        })
        .collect();
    obj(vec![
        ("vid", s(format!("{:032x}", view.vid.0))),
        ("name", s(&view.body.name)),
        ("period", s(&view.body.period)),
        ("owner", s(format!("{:032x}", view.body.owner.0))),
        ("opened_at", Json::Int(i128::from(view.opened_at.0))),
        ("complete", Json::Bool(view.complete)),
        ("tasks", Json::Arr(tasks)),
    ])
}

fn summary(view: &CloseRunView) -> String {
    let completed = view
        .tasks
        .iter()
        .filter(|task| task.completion.is_some())
        .count();
    let mut lines = vec![format!(
        "close {} for {}: {completed}/{} tasks complete{}",
        view.body.name,
        view.body.period,
        view.tasks.len(),
        if view.complete { " (complete)" } else { "" },
    )];
    for task in &view.tasks {
        let state = if task.completion.is_some() {
            "complete"
        } else if task.ready {
            "ready"
        } else {
            "blocked"
        };
        lines.push(format!("  {}: {state}", task.id));
    }
    lines.join("\n")
}

pub(super) fn start(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &["--run", "--period", "--tasks", "--description"],
        &[],
    )?;
    let name = required(args, "--run")?;
    let period = required(args, "--period")?;
    let input = required(args, "--tasks")?;
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read", "close"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        crate::rea::admit_read(book, principal, &capability)
    })?;
    let text = task_input(&ctx.files, input)?;
    let tasks = task_definition(&text)?;
    let description = args
        .flag("--description")
        .unwrap_or("start reviewed close run");
    let view = book.start_close_run(capability, name, period, tasks, description)??;
    ctx.out.at_book(&book)?;
    ctx.out.effective(format!("period:{}", view.body.period));
    ctx.out.event(
        "close_run",
        vec![("run", view_json(&view))],
        &summary(&view),
    );
    Ok(())
}

pub(super) fn status(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(args, &["--run"], &[])?;
    let name = required(args, "--run")?;
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        crate::rea::admit_read(book, principal, &capability)
    })?;
    let view = book
        .close_run_status(name, &capability)??
        .ok_or_else(|| usage(format!("close run {name} does not exist"), EXAMPLE))?;
    ctx.out.at_book(&book)?;
    ctx.out.effective(format!("period:{}", view.body.period));
    ctx.out.event(
        "close_run",
        vec![("run", view_json(&view))],
        &summary(&view),
    );
    Ok(())
}

/// Execute the ready graph, retaining every successful native task receipt.
/// A requested period plan is prepared only after its dependencies finish;
/// --plan-out therefore does not turn this command into a read-only preview.
pub(super) fn execute(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const RUN_EXAMPLE: &str = "fa close run --run december --as controller --yes";
    options(
        args,
        &[
            "--run",
            "--task",
            "--key",
            "--reason",
            "--description",
            "--plan",
            "--plan-out",
            "--approval",
        ],
        &[],
    )?;
    let name = required(args, "--run")?;
    let reviewing = args.flag("--key").is_some() || args.flag("--reason").is_some();
    let consuming = args.flag("--plan").is_some();
    if args
        .flag("--plan-out")
        .is_some_and(|path| path.is_empty() || path == "-")
    {
        return Err(usage(
            "--plan-out names a new file; omit it to receive complete inline plan bytes",
            RUN_EXAMPLE,
        ));
    }
    if consuming
        && (reviewing || args.flag("--plan-out").is_some() || args.flag("--description").is_some())
    {
        return Err(usage(
            "the supplied period plan already binds its key, reason and description",
            "use --task <period-task> --plan <file> [--approval <vid>]... --yes",
        ));
    }
    if !consuming && !args.flag_all("--approval").is_empty() {
        return Err(usage(
            "--approval requires the reviewed --plan",
            RUN_EXAMPLE,
        ));
    }
    if !reviewing
        && !consuming
        && (args.flag("--task").is_some() || args.flag("--plan-out").is_some())
    {
        return Err(usage(
            "a period task selection needs --key and --reason, or --plan",
            RUN_EXAMPLE,
        ));
    }
    if reviewing {
        required(args, "--task")?;
        required(args, "--key")?;
        required(args, "--reason")?;
    }
    if consuming {
        required(args, "--task")?;
    }
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read", "close", "approve"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        crate::rea::admit_read(book, principal, &capability)
    })?;
    let description = args
        .flag("--description")
        .unwrap_or("execute reviewed close run");
    let transition = if let Some(path) = args.flag("--plan") {
        let bytes = read_plan_bytes(&ctx.files, path, b"fa:period-plan", "close period task")?;
        let plan = fa_journal::TransitionPlan::decode(&bytes).map_err(|error| {
            usage(
                format!("invalid period plan: {error}"),
                "prepare the ready period task with close step --dry-run",
            )
        })?;
        let digest = book.plan_digest(&plan)??;
        let approvals = args
            .flag_all("--approval")
            .iter()
            .map(|value| {
                Ok(ApprovalRef {
                    approval_vid: parse_vid(value, "--approval")?,
                    approved_digest: digest,
                })
            })
            .collect::<Result<Vec<_>, Fail>>()?;
        Some(CloseRunTransition::Reviewed {
            task: required(args, "--task")?.into(),
            plan,
            approvals,
        })
    } else if reviewing {
        let task = required(args, "--task")?;
        let view = book
            .close_run_status(name, &capability)??
            .ok_or_else(|| usage(format!("close run {name} does not exist"), RUN_EXAMPLE))?;
        let to = transition_for_task(&view, task)?;
        Some(CloseRunTransition::Review {
            task: task.into(),
            reason_code: transition_reason(required(args, "--reason")?, to)?,
            idempotency_key: required(args, "--key")?.as_bytes().to_vec(),
        })
    } else {
        None
    };
    let execution = book.execute_close_run(name, capability, description, transition)??;
    ctx.out.at_book(&book)?;
    ctx.out
        .effective(format!("period:{}", execution.run.body.period));
    let (state, pending) = match &execution.stop {
        None => ("complete", Json::Null),
        Some(CloseRunStop::TransitionRequired { task, .. }) => ("transition-required", s(task)),
        Some(CloseRunStop::TransitionReview { task, .. }) => ("transition-review", s(task)),
        Some(CloseRunStop::Refused { task, .. }) => ("refused", s(task)),
    };
    let completed = execution
        .completed
        .iter()
        .map(|recorded| {
            obj(vec![
                ("task", s(&recorded.task)),
                ("receipt", receipt_json(&recorded.receipt)),
            ])
        })
        .collect();
    let fields = vec![
        ("run", view_json(&execution.run)),
        ("state", s(state)),
        ("completed", Json::Arr(completed)),
        ("pending_task", pending),
    ];
    if let Some(CloseRunStop::Refused { refusal, .. }) = &execution.stop {
        // A nonzero refusal carries durable partial progress, never a success
        // claim for the whole run and never a rollback claim for earlier tasks.
        return Err(Fail::RefusalDetail(Box::new((
            refusal.clone(),
            obj(fields),
        ))));
    }
    let mut human = summary(&execution.run);
    if let Some(CloseRunStop::TransitionRequired { task, .. }) = &execution.stop {
        human.push_str(&format!("\nReview the ready period task: fa close step --run {name} --task {task} --key <key> --reason <registered-reason> --dry-run --plan-out <file>. Then resume with close run --run {name} --task {task} --plan <file> and any required independent approvals."));
    }
    ctx.out.event("close_run_progress", fields, &human);
    if let Some(CloseRunStop::TransitionReview {
        task,
        plan,
        proposal_digest,
    }) = execution.stop
    {
        let bytes = plan
            .encode()
            .map_err(|error| Fail::Internal(error.to_string()))?;
        if let Some(path) = args.flag("--plan-out") {
            write_post_plan(&ctx.files, path, &bytes)?;
        }
        ctx.out.event("close_task_planned", vec![
            ("run", s(name)), ("task", s(&task)), ("period", s(&plan.period_code)),
            ("from", s(plan.from.name())), ("to", s(plan.to.name())),
            ("proposal_digest", s(hex(&proposal_digest))), ("bytes", s(hex(&bytes))),
            ("file", args.flag("--plan-out").map_or(Json::Null, s)),
        ], &format!("close {name}/{task}: {} → {}; review proposal {}, then resume with these unchanged plan bytes and the transition's required approvals", plan.from.name(), plan.to.name(), hex(&proposal_digest)));
    }
    Ok(())
}

fn transition_for_task(view: &CloseRunView, task: &str) -> Result<PeriodTransition, Fail> {
    match view
        .body
        .tasks
        .iter()
        .find(|definition| definition.id == task)
        .map(|definition| &definition.action)
    {
        Some(CloseTaskBodyAction::PeriodTransition { to: 2 }) => Ok(PeriodTransition::SoftClose),
        Some(CloseTaskBodyAction::PeriodTransition { to: 3 }) => Ok(PeriodTransition::Close),
        Some(CloseTaskBodyAction::PeriodTransition { to: 4 }) => Ok(PeriodTransition::Lock),
        _ => Err(usage(
            "only a period-transition task takes a native plan",
            "inspect close status; a draft task already binds its retained rehearsal certificate",
        )),
    }
}

fn transition_reason(text: &str, transition: PeriodTransition) -> Result<u16, Fail> {
    let reasons = fa_registry::reason_codes::ReasonCodes::embedded()
        .map_err(|error| Fail::Internal(error.to_string()))?;
    let scope = fa_journal::period::reason_scope(transition);
    text.parse::<u16>()
        .ok()
        .or_else(|| {
            reasons
                .rows
                .iter()
                .find(|reason| reason.scope == scope && reason.name == text)
                .map(|reason| reason.code)
        })
        .ok_or_else(|| {
            usage(
                format!("unregistered {scope} reason {text}"),
                reasons.listing(scope),
            )
        })
}

pub(super) fn step(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &[
            "--run",
            "--task",
            "--key",
            "--reason",
            "--description",
            "--plan",
            "--plan-out",
            "--approval",
        ],
        &["--dry-run"],
    )?;
    let name = required(args, "--run")?;
    let task = required(args, "--task")?;
    let preview = args.switch("--dry-run") || args.flag("--plan-out").is_some();
    if preview && (args.flag("--plan").is_some() || !args.flag_all("--approval").is_empty()) {
        return Err(usage(
            "a close task preview cannot consume a plan or approvals",
            "prepare the period task first, then execute its exact plan",
        ));
    }
    if args.flag("--plan").is_some()
        && (args.flag("--key").is_some()
            || args.flag("--reason").is_some()
            || args.flag("--description").is_some())
    {
        return Err(usage(
            "the plan already binds its key, reason and description",
            "pass --plan <file> and the approvals of its proposal_digest",
        ));
    }
    let principal = ctx.principal(args);
    let ops: &[&str] = if preview || args.flag("--plan").is_some() {
        &["read", "close"]
    } else {
        &["read", "close", "approve"]
    };
    let capability = ctx.capability(args, ops)?;
    let mut book = ctx.books.open_admitted(args, |book| {
        crate::rea::admit_read(book, principal, &capability)
    })?;
    let description = args
        .flag("--description")
        .unwrap_or("execute reviewed close task");
    if preview {
        let key = required(args, "--key")?;
        let view = book
            .close_run_status(name, &capability)??
            .ok_or_else(|| usage(format!("close run {name} does not exist"), EXAMPLE))?;
        let transition = match view
            .body
            .tasks
            .iter()
            .find(|definition| definition.id == task)
            .map(|definition| &definition.action)
        {
            Some(CloseTaskBodyAction::PeriodTransition { to: 2 }) => PeriodTransition::SoftClose,
            Some(CloseTaskBodyAction::PeriodTransition { to: 3 }) => PeriodTransition::Close,
            Some(CloseTaskBodyAction::PeriodTransition { to: 4 }) => PeriodTransition::Lock,
            _ => {
                return Err(usage(
                    "only a period-transition task takes a native plan",
                    "inspect close status; a draft task already binds its retained rehearsal certificate",
                ));
            }
        };
        let reason_text = required(args, "--reason")?;
        let reasons = fa_registry::reason_codes::ReasonCodes::embedded()
            .map_err(|error| Fail::Internal(error.to_string()))?;
        let scope = fa_journal::period::reason_scope(transition);
        let reason = reason_text
            .parse::<u16>()
            .ok()
            .or_else(|| {
                reasons
                    .rows
                    .iter()
                    .find(|reason| reason.scope == scope && reason.name == reason_text)
                    .map(|reason| reason.code)
            })
            .ok_or_else(|| {
                usage(
                    format!("unregistered {scope} reason {reason_text}"),
                    reasons.listing(scope),
                )
            })?;
        let plan = book.plan_close_task_transition(
            name,
            task,
            &capability,
            reason,
            key.as_bytes(),
            description,
        )??;
        let digest = book.plan_digest(&plan)??;
        let bytes = plan
            .encode()
            .map_err(|error| Fail::Internal(error.to_string()))?;
        if let Some(path) = args.flag("--plan-out") {
            write_post_plan(&ctx.files, path, &bytes)?;
        }
        ctx.out.at_book(&book)?;
        ctx.out.effective(format!("period:{}", plan.period_code));
        ctx.out.event("close_task_planned", vec![
            ("run", s(name)), ("task", s(task)), ("period", s(&plan.period_code)),
            ("from", s(plan.from.name())), ("to", s(plan.to.name())),
            ("proposal_digest", s(hex(&digest))), ("bytes", s(hex(&bytes))),
            ("file", args.flag("--plan-out").map_or(Json::Null, s)),
        ], &format!("close {name}/{task}: {} → {}; review proposal {}, then execute these unchanged plan bytes with the transition's required approvals", plan.from.name(), plan.to.name(), hex(&digest)));
        return Ok(());
    }
    let plan = args
        .flag("--plan")
        .map(|path| {
            let bytes = read_plan_bytes(&ctx.files, path, b"fa:period-plan", "close period task")?;
            fa_journal::TransitionPlan::decode(&bytes).map_err(|error| {
                usage(
                    format!("invalid period plan: {error}"),
                    "prepare with close step --dry-run --plan-out <file>",
                )
            })
        })
        .transpose()?;
    if plan.is_none() && (args.flag("--key").is_some() || args.flag("--reason").is_some()) {
        return Err(usage(
            "a draft close task uses its reviewed keys and reasons",
            "execute --run <name> --task <id> --yes; period tasks require --plan",
        ));
    }
    let approvals = if let Some(plan) = &plan {
        let digest = book.plan_digest(plan)??;
        args.flag_all("--approval")
            .iter()
            .map(|value| {
                Ok(ApprovalRef {
                    approval_vid: parse_vid(value, "--approval")?,
                    approved_digest: digest,
                })
            })
            .collect::<Result<Vec<_>, Fail>>()?
    } else {
        if !args.flag_all("--approval").is_empty() {
            return Err(usage(
                "draft tasks preserve their original reviewed approvals",
                "new approval flags apply only to a period task's --plan",
            ));
        }
        Vec::new()
    };
    let recorded =
        book.execute_close_task(name, task, capability, description, plan, approvals)??;
    ctx.out.at_book(&book)?;
    ctx.out
        .effective(format!("period:{}", recorded.run.body.period));
    ctx.out.event(
        "close_task_recorded",
        vec![
            ("run", view_json(&recorded.run)),
            ("task", s(&recorded.task)),
            ("receipt", receipt_json(&recorded.receipt)),
            ("already_recorded", Json::Bool(recorded.already_recorded)),
        ],
        &format!(
            "{}\n{} task {} at sequence {}",
            summary(&recorded.run),
            if recorded.already_recorded {
                "already completed"
            } else {
                "completed"
            },
            recorded.task,
            recorded.receipt.recorded_at.0
        ),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_task_input_refuses_ambiguous_or_unimplemented_actions() {
        for text in [
            "{}",
            "[false]",
            r#"[{"id":"x","transition":"depreciate"}]"#,
            r#"[{"id":"x","transition":"close","certificate":"C:00"}]"#,
            r#"[{"id":"x","transition":"close","depends_on":"y"}]"#,
            r#"[{"id":"x","transition":"close","done":true}]"#,
        ] {
            assert!(task_definition(text).is_err(), "{text}");
        }
        let tasks = match task_definition(
            r#"[{"id":"lock","depends_on":["accruals"],"transition":"lock"}]"#,
        ) {
            Ok(tasks) => tasks,
            Err(_) => panic!("a lock task depending on accruals parses"),
        };
        assert_eq!(tasks[0].depends_on, ["accruals"]);
        assert_eq!(
            tasks[0].action,
            ReviewedCloseAction::PeriodTransition(PeriodTransition::Lock)
        );
    }
}
