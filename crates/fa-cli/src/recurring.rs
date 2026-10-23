//! Approved recurring fixed entries. Time is supplied only by committed ticks.

use fa::{RecurringPlan, RecurringRecorded, RecurringSpec};
use fa_model::{ApprovalRef, EntryClass};
use fa_time::{DateDay, MonthEndPolicy};

use crate::args::Args;
use crate::cli::{
    Ctx, Fail, hex, parse_json, parse_vid, read_review_bytes, recurring_template, usage,
};
use crate::json::{Json, obj, s};

const HELP: &str = "fa schedule recurring create <name> --template <entry.json|-> --every-months N --month-end PreserveDay|ClampToMonthEnd|LastDayStaysLast [--end YYYY-MM-DD] --dry-run [--plan-out <new-file>]; then create <name> --plan <file|hex|-> --approval <vid>; or list; or cancel <name> --reason <text>";
const FLAGS: &[&str] = &[
    "--template",
    "--every-months",
    "--month-end",
    "--end",
    "--plan",
    "--plan-out",
    "--approval",
    "--reason",
];

fn options(args: &Args, allowed: &[&str], dry_run: bool) -> Result<(), Fail> {
    for flag in FLAGS {
        let values = args.flag_all(flag);
        if !values.is_empty() && !allowed.contains(flag) {
            return Err(usage(
                format!("{flag} is not used by this recurring operation"),
                HELP,
            ));
        }
        if values.len() > 1 && *flag != "--approval" {
            return Err(usage(format!("{flag} must be supplied only once"), HELP));
        }
    }
    if args.switch("--dry-run") && !dry_run {
        return Err(usage(
            "--dry-run prepares a recurring creation proposal only",
            HELP,
        ));
    }
    Ok(())
}

fn month_end(value: &str) -> Result<MonthEndPolicy, Fail> {
    match value {
        "PreserveDay" => Ok(MonthEndPolicy::PreserveDay),
        "ClampToMonthEnd" => Ok(MonthEndPolicy::ClampToMonthEnd),
        "LastDayStaysLast" => Ok(MonthEndPolicy::LastDayStaysLast),
        _ => Err(usage(
            "--month-end must name an explicit registered calendar policy",
            HELP,
        )),
    }
}

fn month_end_name(value: MonthEndPolicy) -> &'static str {
    match value {
        MonthEndPolicy::PreserveDay => "PreserveDay",
        MonthEndPolicy::ClampToMonthEnd => "ClampToMonthEnd",
        MonthEndPolicy::LastDayStaysLast => "LastDayStaysLast",
    }
}

fn recorded(name: &str, value: &RecurringRecorded) -> Vec<(&'static str, Json)> {
    vec![
        ("name", s(name)),
        ("schedule", s(format!("{:032x}", value.schedule.0))),
        (
            "control_entry",
            s(format!("{:032x}", value.control_entry.vid.0)),
        ),
        ("recorded_at", Json::Int(i128::from(value.recorded_at.0))),
        ("already_recorded", Json::Bool(value.already_recorded)),
    ]
}

pub(crate) fn schedule_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.get(1).map(String::as_str) != Some("recurring") {
        return Err(usage(
            "schedule needs recurring create, list or cancel",
            HELP,
        ));
    }
    match args.positional.get(2).map(String::as_str) {
        Some("create") => create(ctx, args),
        Some("list") => list(ctx, args),
        Some("cancel") => cancel(ctx, args),
        _ => Err(usage("recurring needs create, list or cancel", HELP)),
    }
}

fn create(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let [_, _, _, name] = args.positional.as_slice() else {
        return Err(usage(
            "recurring create needs exactly one schedule name",
            HELP,
        ));
    };
    options(
        args,
        &[
            "--template",
            "--every-months",
            "--month-end",
            "--end",
            "--plan",
            "--plan-out",
            "--approval",
        ],
        true,
    )?;
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read", "post"])?;
    let bound = ctx.authority().is_some();
    let mut book = ctx.books.open_admitted(args, |book| {
        fa_policy::require(
            &capability,
            fa_policy::Op::Post,
            "preparing or creating a recurring schedule",
        )
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        book.read_scope(principal, &capability)??;
        Ok(())
    })?;
    if let Some(source) = args.flag("--plan") {
        if args.switch("--dry-run")
            || [
                "--template",
                "--every-months",
                "--month-end",
                "--end",
                "--plan-out",
            ]
            .iter()
            .any(|flag| args.flag(flag).is_some())
        {
            return Err(usage(
                "a saved recurring plan carries the complete approved template and cadence",
                HELP,
            ));
        }
        let bytes = read_review_bytes(&ctx.files, source, bound)?;
        let plan = RecurringPlan::decode(&bytes)
            .map_err(|error| usage(format!("recurring plan: {error}"), HELP))?;
        if plan.spec().name != *name {
            return Err(usage(
                "the saved recurring plan names a different schedule",
                HELP,
            ));
        }
        let digest = plan.proposal_digest().map_err(fa::BookError::Kernel)?;
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
        let result = book.create_recurring(&capability, plan, approvals)??;
        ctx.out.at_book(&book)?;
        ctx.out.event(
            "recurring_recorded",
            recorded(name, &result),
            &format!(
                "Recurring schedule {name} recorded at sequence {}{}",
                result.recorded_at.0,
                if result.already_recorded {
                    " (already recorded)"
                } else {
                    ""
                }
            ),
        );
        return Ok(());
    }
    if !args.switch("--dry-run") || args.flag("--approval").is_some() {
        return Err(usage(
            "prepare a recurring plan with --dry-run, obtain its independent approval, then publish the unchanged --plan",
            HELP,
        ));
    }
    let input = args.require("--template", "entry.json (or - for stdin)")?;
    let text = ctx.files.read_text(input)?;
    let document = parse_json(input, &text)?;
    let template = recurring_template(
        &ctx.out,
        &mut book,
        args,
        &document,
        principal,
        capability.clone(),
    )?;
    if template.class != EntryClass::ORIGINAL {
        return Err(usage(
            "recurring templates must be Original fixed-entry intents",
            HELP,
        ));
    }
    let every_months = args
        .require("--every-months", "positive integer")?
        .parse::<u32>()
        .map_err(|_| usage("--every-months must be a positive integer", HELP))?;
    let policy = month_end(args.require("--month-end", "calendar policy")?)?;
    let end = args
        .flag("--end")
        .map(|text| DateDay::parse(text).map_err(|error| usage(format!("--end: {error}"), HELP)))
        .transpose()?;
    let plan = book.plan_recurring(
        &capability,
        RecurringSpec {
            name: name.clone(),
            template,
            every_months,
            month_end: policy,
            end,
        },
    )??;
    let bytes = plan.encode().map_err(fa::BookError::Kernel)?;
    let digest = hex(&plan.proposal_digest().map_err(fa::BookError::Kernel)?);
    if let Some(path) = args.flag("--plan-out") {
        if path.is_empty() || path == "-" {
            return Err(usage("--plan-out must name a new file", HELP));
        }
        crate::proof::write_new(
            &ctx.files.resolve(path),
            path,
            &bytes,
            "recurring plan",
            "--plan-out",
        )?;
    }
    ctx.out.at_book(&book)?;
    ctx.out.event("recurring_plan", vec![
        ("name", s(name)),
        ("proposal_digest", s(&digest)),
        ("start", s(plan.spec().template.effective_date.render())),
        ("end", end.map_or(Json::Null, |day| s(day.render()))),
        ("every_months", Json::Int(i128::from(every_months))),
        ("month_end", s(month_end_name(policy))),
        ("legs", Json::Int(plan.spec().template.legs.len() as i128)),
        ("bytes", s(hex(&bytes))),
        ("file", args.flag("--plan-out").map_or(Json::Null, s)),
        ("scope", s("fixed-effects-approval")),
    ], &format!("Prepared recurring schedule {name}; proposal {digest}. An independent Human approves this exact digest. Each occurrence will independently pass current posting and period laws."));
    Ok(())
}

fn list(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 3 {
        return Err(usage("recurring list takes no schedule name", HELP));
    }
    options(args, &[], false)?;
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read"])?;
    let book = ctx.books.open_admitted(args, |book| {
        book.read_scope(principal, &capability)??;
        Ok(())
    })?;
    let schedules = book.recurring_schedules(&capability)??;
    let rows = schedules
        .iter()
        .map(|row| {
            obj(vec![
                ("name", s(&row.name)),
                ("schedule", s(format!("{:032x}", row.schedule.0))),
                ("principal", s(format!("{:032x}", row.principal.0))),
                ("start", s(row.start.render())),
                ("end", row.end.map_or(Json::Null, |day| s(day.render()))),
                ("every_months", Json::Int(i128::from(row.every_months))),
                ("month_end", s(month_end_name(row.month_end))),
                ("created_at", Json::Int(i128::from(row.created_at.0))),
                (
                    "cancelled_at",
                    row.cancelled_at
                        .map_or(Json::Null, |seq| Json::Int(i128::from(seq.0))),
                ),
                ("next_index", Json::Int(i128::from(row.next_index))),
                (
                    "next_date",
                    row.next_date.map_or(Json::Null, |day| s(day.render())),
                ),
                ("blocked", row.blocked.as_ref().map_or(Json::Null, s)),
            ])
        })
        .collect();
    let human = schedules
        .iter()
        .map(|row| {
            format!(
                "{}: {} every {} month(s), next {}, {}",
                row.name,
                row.start,
                row.every_months,
                row.next_date.map_or_else(|| "none".into(), |d| d.render()),
                if row.cancelled_at.is_some() {
                    "cancelled"
                } else {
                    "active"
                }
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "recurring_schedules",
        vec![("schedules", Json::Arr(rows))],
        if human.is_empty() {
            "No recurring schedules."
        } else {
            &human
        },
    );
    Ok(())
}

fn cancel(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let [_, _, _, name] = args.positional.as_slice() else {
        return Err(usage(
            "recurring cancel needs exactly one schedule name",
            HELP,
        ));
    };
    options(args, &["--reason"], false)?;
    let reason = args.require("--reason", "why future occurrences should stop")?;
    if reason.trim().is_empty() {
        return Err(usage("--reason must not be empty", HELP));
    }
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read", "post"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        fa_policy::require(
            &capability,
            fa_policy::Op::Post,
            "cancelling a recurring schedule",
        )
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        book.read_scope(principal, &capability)??;
        Ok(())
    })?;
    let result = book.cancel_recurring(&capability, name, reason)??;
    ctx.out.at_book(&book)?;
    ctx.out.event("recurring_cancelled", recorded(name, &result),
        &format!("Recurring schedule {name} cancelled at sequence {}; existing entries remain journaled.", result.recorded_at.0));
    Ok(())
}
