//! Combined native rehearsal of an existing reviewed close graph.

use fa::{CloseRunRehearsal, CloseTaskRehearsalOutcome};
use fa_money::{Amount, UnitId};

use super::{options, required};
use crate::args::Args;
use crate::cli::{Ctx, Fail, Out, hex, render_amount, usage};
use crate::json::{Json, obj, s};

const EXAMPLE: &str =
    "fa close dry-run --run december [--certify | --certificate-out <new-file>] --json";

pub(super) fn run(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &["--run", "--period", "--certificate-out"],
        &["--certify"],
    )?;
    let name = required(args, "--run")?;
    if args
        .flag("--certificate-out")
        .is_some_and(|path| path.is_empty() || path == "-")
    {
        return Err(usage(
            "--certificate-out names a new file; use --certify for complete inline bytes",
            EXAMPLE,
        ));
    }
    let certify = args.switch("--certify") || args.flag("--certificate-out").is_some();
    let principal = ctx.principal(args);
    let ops: &[&str] = if certify {
        &["read", "produce"]
    } else {
        &["read"]
    };
    let capability = ctx.capability(args, ops)?;
    let mut book = ctx.books.open_admitted(args, |book| {
        crate::rea::admit_read(book, principal, &capability)
    })?;
    if let Some(period) = args.flag("--period") {
        let view = book
            .close_run_status(name, &capability)??
            .ok_or_else(|| usage(format!("close run {name} does not exist"), EXAMPLE))?;
        if view.body.period != period {
            return Err(usage(
                "--period differs from the close run's immutable period",
                EXAMPLE,
            ));
        }
    }
    if !certify {
        let report = book.close_run_rehearsal(principal, &capability, name)??;
        ctx.out.at_book(&book)?;
        return render(&ctx.out, &book, &report, None);
    }
    let certified = book.certify_close_run_rehearsal(principal, &capability, name)??;
    let retained =
        book.retain_close_run_rehearsal(principal, &capability, &certified.certificate)??;
    let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
    let bytes = artifact.canonical_bytes()?;
    if let Some(path) = args.flag("--certificate-out") {
        crate::cli::write_new_output_file(
            &ctx.files,
            path,
            &bytes,
            "certificate",
            "--certificate-out",
        )?;
    }
    ctx.out.at_book(&book)?;
    let digest = hex(artifact.digest());
    render(&ctx.out, &book, &certified.report, Some(&digest))?;
    crate::notary::emit_report_artifact(
        &ctx.out,
        args,
        &artifact,
        fa::CLOSE_RUN_REHEARSAL_OUTPUT_FORMAT,
        &bytes,
        &retained,
    );
    Ok(())
}

pub(crate) fn render(
    out: &Out,
    book: &fa::Book,
    report: &CloseRunRehearsal,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    let money = |unit: u32, mantissa: i128| {
        render_amount(Amount::new(UnitId(unit), mantissa), &book.context().units)
    };
    let mut human = vec![format!(
        "close {}: combined rehearsal for {} at trunk sequence {}; {} changed balance rows",
        report.name,
        report.period,
        report.source_known_at.0,
        report.rows.len(),
    )];
    let tasks = report
        .tasks
        .iter()
        .map(|task| {
            let (state, receipt, batch, at, entries, transition) = match &task.outcome {
                CloseTaskRehearsalOutcome::AlreadyCompleted(receipt) => (
                    "completed-on-trunk",
                    obj(vec![
                        ("record", s(format!("{:032x}", receipt.record.0))),
                        ("effect", s(format!("{:032x}", receipt.effect.0))),
                        ("recorded_at", Json::Int(i128::from(receipt.recorded_at.0))),
                        ("principal", s(format!("{:032x}", receipt.principal.0))),
                    ]),
                    Json::Null,
                    Json::Int(i128::from(receipt.recorded_at.0)),
                    Vec::new(),
                    Json::Null,
                ),
                CloseTaskRehearsalOutcome::Rehearsed {
                    batch_outcome,
                    recorded_at,
                    entries,
                } => (
                    "rehearsed",
                    Json::Null,
                    s(format!("{:032x}", batch_outcome.0)),
                    Json::Int(i128::from(recorded_at.0)),
                    entries
                        .iter()
                        .map(|entry| {
                            obj(vec![
                                ("vid", s(format!("{:032x}", entry.vid.0))),
                                ("digest", s(hex(&entry.entry_digest))),
                            ])
                        })
                        .collect(),
                    Json::Null,
                ),
                CloseTaskRehearsalOutcome::AwaitingNativeTransitionReview { to } => (
                    "transition-review-required",
                    Json::Null,
                    Json::Null,
                    Json::Null,
                    Vec::new(),
                    s(match to {
                        2 => "soft-close",
                        3 => "close",
                        4 => "lock",
                        _ => "invalid",
                    }),
                ),
            };
            human.push(format!("  {}: {state}", task.id));
            obj(vec![
                ("id", s(&task.id)),
                ("state", s(state)),
                ("receipt", receipt),
                ("batch_outcome", batch),
                ("recorded_at", at),
                ("entries", Json::Arr(entries)),
                ("transition", transition),
            ])
        })
        .collect();
    let mut rows = Vec::with_capacity(report.rows.len());
    for row in &report.rows {
        let delta = money(row.unit_id, row.delta)?;
        let pending_delta = money(row.unit_id, row.pending_delta)?;
        human.push(format!(
            "  {:<12} {:>20}  {} (pending change: {pending_delta})",
            row.code, delta, row.name
        ));
        rows.push(obj(vec![
            ("account", s(format!("{:032x}", row.account.0))),
            ("code", s(&row.code)),
            ("name", s(&row.name)),
            ("unit_id", Json::Int(i128::from(row.unit_id))),
            ("trunk_debits", s(money(row.unit_id, row.trunk_debits)?)),
            ("trunk_credits", s(money(row.unit_id, row.trunk_credits)?)),
            ("draft_debits", s(money(row.unit_id, row.draft_debits)?)),
            ("draft_credits", s(money(row.unit_id, row.draft_credits)?)),
            ("delta", s(delta)),
            (
                "trunk_debits_pending",
                s(money(row.unit_id, row.trunk_debits_pending)?),
            ),
            (
                "trunk_credits_pending",
                s(money(row.unit_id, row.trunk_credits_pending)?),
            ),
            (
                "draft_debits_pending",
                s(money(row.unit_id, row.draft_debits_pending)?),
            ),
            (
                "draft_credits_pending",
                s(money(row.unit_id, row.draft_credits_pending)?),
            ),
            ("pending_delta", s(pending_delta)),
        ]));
    }
    if report.tasks.iter().any(|task| {
        matches!(
            task.outcome,
            CloseTaskRehearsalOutcome::AwaitingNativeTransitionReview { .. }
        )
    }) {
        human.push("The final period transition still requires its native review and any independent approvals; this rehearsal changes no period state.".into());
    }
    out.known_at(report.source_known_at);
    out.effective(format!("period:{}", report.period));
    out.event_with_certificate(
        "close_run_rehearsal",
        vec![
            ("run", s(format!("{:032x}", report.run.0))),
            ("name", s(&report.name)),
            ("body_digest", s(hex(&report.body_digest))),
            ("period", s(&report.period)),
            ("opened_at", Json::Int(i128::from(report.opened_at.0))),
            (
                "source_known_at",
                Json::Int(i128::from(report.source_known_at.0)),
            ),
            (
                "seq_map_digest",
                report
                    .seq_map_digest
                    .as_ref()
                    .map_or(Json::Null, |digest| s(hex(digest))),
            ),
            (
                "rehearsal_known_at",
                Json::Int(i128::from(report.rehearsal_known_at.0)),
            ),
            ("complete_on_trunk", Json::Bool(report.complete_on_trunk)),
            ("tasks", Json::Arr(tasks)),
            ("rows", Json::Arr(rows)),
        ],
        &human.join("\n"),
        certificate,
    );
    Ok(())
}
