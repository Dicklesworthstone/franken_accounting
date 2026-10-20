//! Explicit common-idempotency recovery from verified native journal history.

use fa::BookError;
use fa_journal::{Refusal, exit};
use fgdb_types::CommitSeq;

use super::{Args, Ctx, Fail, Json, admit_whole_book_read, obj, s, usage};

pub(super) fn recover(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "unexpected recover outcomes argument",
            "fa recover outcomes --dry-run --book <dir> --json",
        ));
    }
    let dry_run = args.switch("--dry-run");
    if args.flag_all("--basis").len() > 1 {
        return Err(usage(
            "--basis may be supplied only once",
            "fa recover outcomes --yes --basis <the dry run's basis> --json",
        ));
    }
    let basis = args
        .flag("--basis")
        .map(|text| {
            text.parse::<u64>().map(CommitSeq).map_err(|_| {
                usage(
                    "--basis is the recorded sequence a dry run previewed",
                    "fa recover outcomes --yes --basis <the dry run's basis> --json",
                )
            })
        })
        .transpose()?;
    if dry_run && (args.switch("--yes") || basis.is_some()) {
        return Err(usage(
            "--dry-run previews and writes nothing; --yes and --basis publish",
            "fa recover outcomes --dry-run --json, then fa recover outcomes --yes --basis <its basis> --json",
        ));
    }

    let capability = ctx.capability(args, &["read", "schema_change"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        admit_whole_book_read(
            book,
            &capability,
            &[fa_policy::Op::SchemaChange],
            "recovering the common idempotency namespace",
        )
    })?;
    let prepared = book
        .prepare_outcome_rebuild(capability)
        .map_err(recovery_error)??;
    let preview = prepared.preview().clone();
    if let Some(expected) = basis {
        if expected != preview.basis {
            prepared.abort();
            return Err(Refusal::new(
                fa_journal::refusal::code::PLAN_INVALIDATED,
                exit::CONFLICT,
                format!(
                    "the head moved from the previewed basis {} to {}; preview the current history before publishing",
                    expected.0, preview.basis.0,
                ),
                "plan §5.9, FA-INV-09 (idempotency recovery publishes its exact verified basis)",
                "preview again with fa recover outcomes --dry-run --json, retain it, and publish with --yes --basis <its basis>",
            )
            .into());
        }
    }
    let (recorded_at, wrote) = if dry_run {
        prepared.abort();
        (None, false)
    } else {
        let report = book
            .publish_outcome_rebuild(prepared)
            .map_err(recovery_error)??;
        (report.wrote.then_some(report.recorded_at), report.wrote)
    };

    ctx.out.at_book(&book)?;
    ctx.out.event(
        "outcomes_rebuilt",
        vec![
            ("dry_run", Json::Bool(dry_run)),
            ("basis", Json::Int(i128::from(preview.basis.0))),
            (
                "recorded_at",
                recorded_at.map_or(Json::Null, |seq| Json::Int(i128::from(seq.0))),
            ),
            ("wrote", Json::Bool(wrote)),
            (
                "entries_checked",
                Json::Int(preview.entries_checked as i128),
            ),
            (
                "outcomes_created",
                Json::Int(preview.outcomes_created as i128),
            ),
            ("already_covered", Json::Bool(preview.already_covered)),
        ],
        &if preview.already_covered {
            format!(
                "idempotency outcomes already cover the journal at sequence {}; no changes",
                preview.basis.0,
            )
        } else if dry_run {
            format!(
                "would establish idempotency coverage with {} outcomes from {} verified entries at sequence {}; publish with fa recover outcomes --yes --basis {}",
                preview.outcomes_created,
                preview.entries_checked,
                preview.basis.0,
                preview.basis.0,
            )
        } else {
            format!(
                "established idempotency coverage with {} outcomes from {} verified entries at sequence {}",
                preview.outcomes_created,
                preview.entries_checked,
                recorded_at.unwrap_or(preview.basis).0,
            )
        },
    );
    Ok(())
}

fn recovery_error(error: BookError) -> Fail {
    match error {
        BookError::Kernel(fa_journal::KernelError::Corrupt(problem)) => Fail::Verification {
            message: format!("idempotency outcomes cannot be recovered from the journal: {problem}"),
            detail: obj(vec![("problem", s(&problem))]),
            cite: Some("plan §5.9, FA-INV-09 (one outcome per scoped idempotency key)".into()),
            fix: Some(
                "retain this finding and preserve the book for inspection; rewritten history or conflicting legacy keys cannot be assigned a new outcome by recovery"
                    .into(),
            ),
        },
        other => other.into(),
    }
}
