//! Combined native rehearsal of an existing reviewed close graph.

use std::collections::BTreeMap;

use fa::{CloseRunRehearsal, CloseTaskRehearsalOutcome, StatementDefinition, StatementSelection};
use fa_money::{Amount, UnitId};

use super::{options, required};
use crate::args::Args;
use crate::cli::{Ctx, Fail, Out, hex, render_amount, usage};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa close dry-run --run december [--statement balance-sheet --statement income-statement --comparative FY2025-P12] [--certify | --certificate-out <new-file>] --json";

pub(super) fn run(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &[
            "--run",
            "--period",
            "--certificate-out",
            "--statement",
            "--comparative",
        ],
        &["--certify"],
    )?;
    let name = required(args, "--run")?;
    let statement_names = args.flag_all("--statement");
    let comparative = args.flag_all("--comparative");
    if !comparative.is_empty() && statement_names.is_empty() {
        return Err(usage(
            "--comparative requires at least one --statement",
            EXAMPLE,
        ));
    }
    if statement_names.len() > fa::MAX_CLOSE_REHEARSAL_STATEMENTS {
        return Err(usage(
            "a close rehearsal accepts at most 16 statements",
            EXAMPLE,
        ));
    }
    if statement_names
        .iter()
        .any(|name| !matches!(*name, "balance-sheet" | "income-statement"))
    {
        return Err(usage(
            "--statement must be balance-sheet or income-statement",
            EXAMPLE,
        ));
    }
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
    let mut selections = Vec::new();
    if args.flag("--period").is_some() || !statement_names.is_empty() {
        let view = book
            .close_run_status(name, &capability)??
            .ok_or_else(|| usage(format!("close run {name} does not exist"), EXAMPLE))?;
        if args
            .flag("--period")
            .is_some_and(|period| view.body.period != period)
        {
            return Err(usage(
                "--period differs from the close run's immutable period",
                EXAMPLE,
            ));
        }
        for statement in statement_names {
            selections.push(StatementSelection {
                definition: StatementDefinition::embedded(statement)
                    .map_err(|error| Fail::Internal(format!("built-in statement: {error}")))?,
                periods: vec![view.body.period.clone()],
                comparative: comparative
                    .iter()
                    .map(|period| (*period).to_owned())
                    .collect(),
            });
        }
    }
    if !certify {
        let report =
            book.close_run_rehearsal_with_statements(principal, &capability, name, selections)??;
        ctx.out.at_book(&book)?;
        return render(&ctx.out, &book, &report, None);
    }
    let certified = book.certify_close_run_rehearsal_with_statements(
        principal,
        &capability,
        name,
        selections,
    )??;
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
        certified.report.output_format(),
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
            let (state, receipt, batch, at, entries, transition, verification, bank_verification) =
                match &task.outcome {
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
                        Json::Null,
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
                        Json::Null,
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
                        Json::Null,
                        Json::Null,
                    ),
                    CloseTaskRehearsalOutcome::VerifiedYearEndClose {
                        fiscal_year,
                        base_unit,
                        verified_at,
                        latest_close,
                        source_digest,
                        review_basis,
                    } => (
                        "year-end-verified",
                        Json::Null,
                        Json::Null,
                        Json::Int(i128::from(verified_at.0)),
                        Vec::new(),
                        Json::Null,
                        obj(vec![
                            ("fiscal_year", Json::Int(i128::from(*fiscal_year))),
                            ("base_unit", Json::Int(i128::from(*base_unit))),
                            ("verified_at", Json::Int(i128::from(verified_at.0))),
                            (
                                "latest_close",
                                obj(vec![
                                    ("vid", s(format!("{:032x}", latest_close.vid.0))),
                                    ("digest", s(hex(&latest_close.entry_digest))),
                                ]),
                            ),
                            ("source_digest", s(hex(source_digest))),
                            ("review_basis", s(hex(review_basis))),
                        ]),
                        Json::Null,
                    ),
                    CloseTaskRehearsalOutcome::CurrentStatementIssuance { checked_at, .. } => (
                        "statement-issuance-current",
                        Json::Null,
                        Json::Null,
                        Json::Int(i128::from(checked_at.0)),
                        Vec::new(),
                        Json::Null,
                        Json::Null,
                        Json::Null,
                    ),
                    CloseTaskRehearsalOutcome::VerifiedBankInstrumentCoverage {
                        verified_at,
                        ..
                    } => (
                        "bank-instrument-coverage-verified",
                        Json::Null,
                        Json::Null,
                        Json::Int(i128::from(verified_at.0)),
                        Vec::new(),
                        Json::Null,
                        Json::Null,
                        Json::Null,
                    ),
                    CloseTaskRehearsalOutcome::VerifiedBankReconciliation {
                        manifest_oid,
                        verified_at,
                        attestation,
                        statement_date,
                        account,
                        unit,
                        source_digest,
                    } => (
                        "bank-reconciliation-verified",
                        Json::Null,
                        Json::Null,
                        Json::Int(i128::from(verified_at.0)),
                        Vec::new(),
                        Json::Null,
                        Json::Null,
                        obj(vec![
                            ("manifest_oid", s(hex(&manifest_oid.0))),
                            ("verified_at", Json::Int(i128::from(verified_at.0))),
                            (
                                "attestation",
                                obj(vec![
                                    ("vid", s(format!("{:032x}", attestation.vid.0))),
                                    ("digest", s(hex(&attestation.digest))),
                                ]),
                            ),
                            ("statement_date", s(statement_date.render())),
                            ("account", s(format!("{:032x}", account.0))),
                            ("unit_id", Json::Int(i128::from(unit.0))),
                            ("source_digest", s(hex(source_digest))),
                        ]),
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
                ("verification", verification),
                ("bank_verification", bank_verification),
                (
                    "statement_issuance",
                    match &task.outcome {
                        CloseTaskRehearsalOutcome::CurrentStatementIssuance {
                            ordinal,
                            checked_at,
                            issuance,
                            certificate_digest,
                            certified_at,
                            source_digest,
                        } => obj(vec![
                            ("ordinal", Json::Int(i128::from(*ordinal))),
                            ("checked_at", Json::Int(i128::from(checked_at.0))),
                            ("issuance", s(format!("{:032x}", issuance.0))),
                            ("certificate", s(hex(certificate_digest))),
                            ("certified_at", Json::Int(i128::from(certified_at.0))),
                            ("source_digest", s(hex(source_digest))),
                        ]),
                        _ => Json::Null,
                    },
                ),
                (
                    "bank_instrument_coverage",
                    match &task.outcome {
                        CloseTaskRehearsalOutcome::VerifiedBankInstrumentCoverage {
                            verified_at,
                            inventory_digest,
                            source_digest,
                            instruments,
                        } => obj(vec![
                            ("verified_at", Json::Int(i128::from(verified_at.0))),
                            ("inventory_digest", s(hex(inventory_digest))),
                            ("source_digest", s(hex(source_digest))),
                            (
                                "instruments",
                                Json::Arr(
                                    instruments
                                        .iter()
                                        .map(|item| {
                                            obj(vec![
                                                (
                                                    "instrument",
                                                    s(format!("{:032x}", item.instrument.0)),
                                                ),
                                                ("code", s(&item.code)),
                                                ("account", s(format!("{:032x}", item.account.0))),
                                                ("unit_id", Json::Int(i128::from(item.unit.0))),
                                                ("manifest_oid", s(hex(&item.manifest_oid.0))),
                                                (
                                                    "attestation",
                                                    obj(vec![
                                                        (
                                                            "vid",
                                                            s(format!(
                                                                "{:032x}",
                                                                item.attestation.vid.0
                                                            )),
                                                        ),
                                                        (
                                                            "digest",
                                                            s(hex(&item.attestation.digest)),
                                                        ),
                                                    ]),
                                                ),
                                                ("statement_date", s(item.statement_date.render())),
                                                (
                                                    "checkpoint_digest",
                                                    s(hex(&item.checkpoint_digest)),
                                                ),
                                            ])
                                        })
                                        .collect(),
                                ),
                            ),
                        ]),
                        _ => Json::Null,
                    },
                ),
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
    let mut statements = Vec::with_capacity(report.statements.len());
    for statement in &report.statements {
        human.push(format!("  {}:", statement.selection.definition.title()));
        let columns = statement
            .after
            .columns
            .iter()
            .map(|column| {
                obj(vec![
                    ("label", s(&column.label)),
                    ("periods", Json::Arr(column.periods.iter().map(s).collect())),
                    (
                        "effective_from",
                        column
                            .effective_from
                            .map_or(Json::Null, |day| s(day.render())),
                    ),
                    ("effective_through", s(column.effective_through.render())),
                ])
            })
            .collect();
        let mut paired: BTreeMap<(String, u32), [Option<&fa::StatementLine>; 2]> = BTreeMap::new();
        for line in &statement.before.lines {
            paired.entry((line.code.clone(), line.unit_id)).or_default()[0] = Some(line);
        }
        for line in &statement.after.lines {
            paired.entry((line.code.clone(), line.unit_id)).or_default()[1] = Some(line);
        }
        let mut lines = Vec::with_capacity(paired.len());
        for ((code, unit_id), [before, after]) in paired {
            let label = after
                .or(before)
                .map_or(code.as_str(), |line| line.label.as_str());
            let mut values = Vec::with_capacity(statement.after.columns.len());
            for (index, column) in statement.after.columns.iter().enumerate() {
                let amount = |line: Option<&fa::StatementLine>| -> Result<i128, Fail> {
                    match line {
                        None => Ok(0),
                        Some(line) => line.amounts.get(index).copied().ok_or_else(|| {
                            Fail::Internal("close statement column is absent".into())
                        }),
                    }
                };
                let before = amount(before)?;
                let after = amount(after)?;
                let delta = after
                    .checked_sub(before)
                    .ok_or_else(|| Fail::Internal("close statement change exceeds i128".into()))?;
                let before = money(unit_id, before)?;
                let after = money(unit_id, after)?;
                let delta = money(unit_id, delta)?;
                human.push(format!(
                    "    {label} [{}]: {before} -> {after} (change {delta})",
                    column.label
                ));
                values.push(obj(vec![
                    ("before", s(before)),
                    ("after", s(after)),
                    ("delta", s(delta)),
                ]));
            }
            lines.push(obj(vec![
                ("code", s(&code)),
                ("label", s(label)),
                ("unit_id", Json::Int(i128::from(unit_id))),
                ("values", Json::Arr(values)),
            ]));
        }
        statements.push(obj(vec![
            ("definition", s(&statement.after.definition_name)),
            (
                "definition_version",
                Json::Int(i128::from(statement.after.definition_version)),
            ),
            (
                "definition_digest",
                s(hex(&statement.after.definition_digest)),
            ),
            (
                "before_known_at",
                Json::Int(i128::from(statement.before.known_at)),
            ),
            (
                "after_known_at",
                Json::Int(i128::from(statement.after.known_at)),
            ),
            ("columns", Json::Arr(columns)),
            ("lines", Json::Arr(lines)),
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
            ("statements", Json::Arr(statements)),
        ],
        &human.join("\n"),
        certificate,
    );
    Ok(())
}
