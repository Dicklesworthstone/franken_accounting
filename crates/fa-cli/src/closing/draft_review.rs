//! Atomic review of an existing draft; no CloseRun or task generation claim.

use fa_money::{Amount, UnitId};

use super::{options, required};
use crate::args::Args;
use crate::cli::{Ctx, Fail, Out, hex, render_amount, usage};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa close dry-run --period FY2026-P12 --draft close-12 [--certify] --json";

pub(super) fn run(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &["--draft", "--period", "--certificate-out"],
        &["--certify"],
    )?;
    let name = required(args, "--draft")?;
    let period = required(args, "--period")?;
    if let Some(path) = args.flag("--certificate-out")
        && (path.is_empty() || path == "-")
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
    if !certify {
        let diff = book.draft_diff(principal, &capability, name, period)??;
        ctx.out.at_book(&book)?;
        return render_draft_diff(&ctx.out, &book, &diff, None);
    }
    let certified = book.certify_draft_diff(principal, &capability, name, period)??;
    let retained = book.retain_draft_diff(principal, &capability, &certified.certificate)??;
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
    render_draft_diff(&ctx.out, &book, &certified.report, Some(&digest))?;
    crate::notary::emit_report_artifact(
        &ctx.out,
        args,
        &artifact,
        fa::DRAFT_DIFF_OUTPUT_FORMAT,
        &bytes,
        &retained,
    );
    Ok(())
}

pub(crate) fn render_draft_diff(
    out: &Out,
    book: &fa::Book,
    diff: &fa::DraftDiff,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    let money = |unit: u32, mantissa: i128| {
        render_amount(Amount::new(UnitId(unit), mantissa), &book.context().units)
    };
    let mut rows = Vec::with_capacity(diff.rows.len());
    let mut human = vec![format!(
        "draft {}: {} planned entries rehearsed atomically at trunk sequence {} for {}; {} changed balance rows",
        diff.name,
        diff.plans,
        diff.source_known_at.0,
        diff.period,
        diff.rows.len(),
    )];
    for row in &diff.rows {
        let delta = money(row.unit_id, row.delta)?;
        let pending_delta = money(row.unit_id, row.pending_delta)?;
        human.push(format!(
            "  {:<12} {:>20}  {} (pending change: {pending_delta})",
            row.code, delta, row.name,
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
    let entries = diff
        .entries
        .iter()
        .map(|entry| {
            obj(vec![
                ("vid", s(format!("{:032x}", entry.vid.0))),
                ("digest", s(hex(&entry.entry_digest))),
            ])
        })
        .collect();
    out.known_at(diff.source_known_at);
    out.effective(format!("period:{}", diff.period));
    out.event_with_certificate(
        "draft_diff",
        vec![
            ("draft", s(format!("{:032x}", diff.draft.0))),
            ("name", s(&diff.name)),
            ("owner", s(format!("{:032x}", diff.owner.0))),
            ("period", s(&diff.period)),
            (
                "source_known_at",
                Json::Int(i128::from(diff.source_known_at.0)),
            ),
            ("source_digest", s(hex(&diff.source_digest))),
            ("plans", Json::Int(diff.plans as i128)),
            ("seq_map_digest", s(hex(&diff.seq_map_digest))),
            (
                "rehearsal_known_at",
                Json::Int(i128::from(diff.rehearsal_known_at.0)),
            ),
            ("batch_outcome", s(format!("{:032x}", diff.batch_outcome.0))),
            ("entries", Json::Arr(entries)),
            ("rows", Json::Arr(rows)),
        ],
        &human.join("\n"),
        certificate,
    );
    Ok(())
}
