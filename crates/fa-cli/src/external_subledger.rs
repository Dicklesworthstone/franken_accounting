//! Canonical external detail, reviewed summary posting, and source reconciliation.

use fa::{Book, ExternalSubledgerBatch, ExternalSubledgerDetail};
use fa_model::{EntryClass, EntryPayload, Oid, account_vid};
use fa_money::{Amount, Side};
use fa_policy::Capability;
use fa_time::DateDay;

use crate::args::Args;
use crate::cli::{
    Ctx, Fail, hex, known_at_read_flag, parse_json, parse_vid, post_document, render_amount, usage,
};
use crate::json::{Json, obj, s};

const HELP: &str = "fa subledger detail --input <batch.json|-> [--out <new-file>]; retain the bytes as a Workpaper and obtain an independent Reviewed attestation; fa subledger feed --document D:<oid> --date YYYY-MM-DD --key K [--dry-run --plan-out <new-file>]; fa subledger verify-feed <entry> [--as-known-at <seq>]";
const FLAGS: &[&str] = &[
    "--input",
    "--out",
    "--document",
    "--date",
    "--key",
    "--description",
    "--plan-out",
    "--as-known-at",
    "--control",
    "--kind",
    "--name",
    "--as-of",
];

fn options(args: &Args, allowed: &[&str], dry_run: bool) -> Result<(), Fail> {
    for flag in FLAGS {
        let values = args.flag_all(flag);
        if !values.is_empty() && !allowed.contains(flag) {
            return Err(usage(
                format!("{flag} is not used by this external-feed operation"),
                HELP,
            ));
        }
        if values.len() > 1 {
            return Err(usage(format!("{flag} may be supplied only once"), HELP));
        }
    }
    if args.switch("--dry-run") && !dry_run {
        return Err(usage("--dry-run rehearses subledger feed only", HELP));
    }
    Ok(())
}

fn fields(value: &Json, allowed: &[&str], name: &str) -> Result<(), Fail> {
    let Json::Obj(values) = value else {
        return Err(usage(format!("{name} must be a JSON object"), HELP));
    };
    if let Some((field, _)) = values
        .iter()
        .find(|(field, _)| !allowed.contains(&field.as_str()))
    {
        return Err(usage(format!("{name}: unsupported field {field}"), HELP));
    }
    Ok(())
}

fn text<'a>(value: &'a Json, field: &str) -> Result<&'a str, Fail> {
    value
        .get(field)
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| usage(format!("{field} must be a nonempty string"), HELP))
}

fn parse_batch(value: &Json, book: &Book) -> Result<ExternalSubledgerBatch, Fail> {
    fields(
        value,
        &["feed", "batch_key", "effective_date", "rows"],
        "external detail",
    )?;
    let feed = text(value, "feed")?.to_string();
    let batch_key = text(value, "batch_key")?.to_string();
    let effective_date = DateDay::parse(text(value, "effective_date")?)
        .map_err(|error| usage(format!("effective_date: {error}"), HELP))?;
    let rows = value
        .get("rows")
        .and_then(Json::as_arr)
        .ok_or_else(|| usage("external detail rows must be an array", HELP))?;
    if rows.is_empty() || rows.len() > fa::MAX_EXTERNAL_DETAIL_ROWS {
        return Err(usage(
            "external detail requires 1 through 128 source rows",
            HELP,
        ));
    }
    let book_id = book.context().book_id;
    let mut detail = Vec::with_capacity(rows.len());
    for row in rows {
        fields(
            row,
            &[
                "source_digest",
                "account",
                "side",
                "amount",
                "entity",
                "party",
            ],
            "detail row",
        )?;
        let side = match text(row, "side")? {
            "debit" | "Debit" => Side::Debit,
            "credit" | "Credit" => Side::Credit,
            _ => return Err(usage("a detail side must be debit or credit", HELP)),
        };
        let amount = Amount::parse(text(row, "amount")?, &book.context().units)
            .map_err(|error| usage(format!("detail amount: {error}"), HELP))?;
        let mut dimensions = Vec::new();
        if row.get("entity").is_some() {
            dimensions.push((
                fa_model::LEGAL_ENTITY_DIMENSION,
                fa_model::entity_value_vid(book_id, text(row, "entity")?),
            ));
        }
        if row.get("party").is_some() {
            dimensions.push((
                fa_model::PARTY_DIMENSION,
                fa_model::party_value_vid(book_id, text(row, "party")?),
            ));
        }
        detail.push(ExternalSubledgerDetail {
            source_digest: crate::proof::fixed_hex(text(row, "source_digest")?, "source_digest")?,
            account: account_vid(book_id, text(row, "account")?),
            side,
            amount,
            dimensions,
        });
    }
    // Ordering is normalized, but duplicate row identities are never discarded.
    detail.sort_by_key(|row| row.source_digest);
    Ok(ExternalSubledgerBatch {
        book_id,
        feed,
        batch_key,
        effective_date,
        rows: detail,
    })
}

pub(crate) fn command(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("detail") => detail(ctx, args),
        Some("feed") => feed(ctx, args),
        Some("verify-feed") => verify(ctx, args),
        _ => Err(usage("unknown external-feed operation", HELP)),
    }
}

fn detail(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(args, &["--input", "--out"], false)?;
    if args.positional.len() != 2 {
        return Err(usage("subledger detail takes named inputs only", HELP));
    }
    let path = args.require("--input", "batch.json (or - for stdin)")?;
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read"])?;
    let book = ctx.books.open_admitted(args, |book| {
        crate::rea::admit_read(book, principal, &capability)
    })?;
    let source = ctx.files.read_text(path)?;
    let batch = parse_batch(&parse_json(path, &source)?, &book)?;
    let bytes = batch.canonical_bytes()?;
    let evidence = batch.evidence()?;
    let legs = batch.summary_legs()?;
    if let Some(path) = args.flag("--out") {
        if path.is_empty() || path == "-" {
            return Err(usage("--out must name a new binary file", HELP));
        }
        crate::proof::write_new(
            &ctx.files.resolve(path),
            path,
            &bytes,
            "external detail",
            "--out",
        )?;
    }
    ctx.out.at_book(&book)?;
    ctx.out.event("external_subledger_detail", vec![
        ("feed", s(&batch.feed)), ("batch_key", s(&batch.batch_key)),
        ("effective_date", s(batch.effective_date.render())),
        ("document_oid", s(hex(&evidence.document_oid.0))), ("doc_commit", s(hex(&evidence.doc_commit))),
        ("kind", s("Workpaper")), ("mime", s(fa::EXTERNAL_SUBLEDGER_MIME)),
        ("detail_rows", Json::Int(batch.rows.len() as i128)), ("summary_legs", Json::Int(legs.len() as i128)),
        ("bytes", s(hex(&bytes))), ("file", args.flag("--out").map_or(Json::Null, s)),
    ], &format!("Canonical detail {}/{}: {} source rows, {} gross summary legs. Retain these exact bytes as a Workpaper and have an independent principal attest Reviewed before posting.", batch.feed, batch.batch_key, batch.rows.len(), legs.len()));
    Ok(())
}

fn feed(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &[
            "--document",
            "--date",
            "--key",
            "--description",
            "--plan-out",
        ],
        true,
    )?;
    if args.positional.len() != 2 {
        return Err(usage("subledger feed takes named inputs only", HELP));
    }
    let document = args.require("--document", "D:<reviewed detail document oid>")?;
    let date = args.require("--date", "the detail batch's effective date")?;
    let key = args.require("--key", "stable posting idempotency key")?;
    let mut input = vec![
        ("class", s("Original")),
        ("effective_date", s(date)),
        ("idempotency_key", s(key)),
        ("external_subledger", s(document)),
    ];
    if let Some(description) = args.flag("--description") {
        input.push(("description", s(description)));
    }
    post_document(ctx, args, Some(EntryClass::ORIGINAL), obj(input))
}

/// Retained source reads are admitted by the shared posting front door before
/// this hook runs. The facade rechecks current authority after document I/O.
pub(crate) fn value_intent(
    book: &mut Book,
    capability: &Capability,
    input: &Json,
    template: EntryPayload,
) -> Result<EntryPayload, Fail> {
    let Some(source) = input.get("external_subledger") else {
        return Ok(template);
    };
    if input.get("fx").is_some() {
        return Err(usage(
            "external subledger detail currently declares native-unit effects without FX derivation",
            HELP,
        ));
    }
    let source = source
        .as_str()
        .ok_or_else(|| usage("external_subledger must be a retained D:<oid> string", HELP))?;
    let document = Oid(crate::proof::fixed_hex(
        source.strip_prefix("D:").unwrap_or(source),
        "external_subledger",
    )?);
    Ok(book.prepare_external_subledger(document, template, capability)??)
}

fn verify(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(args, &["--as-known-at"], false)?;
    let [_, _, source] = args.positional.as_slice() else {
        return Err(usage("verify-feed names exactly one summary entry", HELP));
    };
    let vid = parse_vid(source.strip_prefix("E:").unwrap_or(source), "summary entry")?;
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        book.read_scope(principal, &capability)??;
        Ok(())
    })?;
    let (known_at, _) = known_at_read_flag(args, &book, &ctx.out, &capability)?;
    book.prepare_report_history(principal, &capability, known_at)??;
    let Some((entry, _)) = book
        .read_scope(principal, &capability)??
        .read_entry(vid, known_at)??
    else {
        return Err(usage(
            "summary entry does not exist at the selected prefix",
            HELP,
        ));
    };
    let report =
        book.reconcile_external_subledger_feed(entry.entry_ref(vid), known_at, &capability)??;
    let legs = report
        .summary_legs
        .iter()
        .map(|leg| {
            Ok(obj(vec![
                ("account", s(format!("{:032x}", leg.account_ref.0))),
                (
                    "side",
                    s(match leg.side {
                        Side::Debit => "debit",
                        Side::Credit => "credit",
                    }),
                ),
                (
                    "amount",
                    s(render_amount(leg.amount, &book.context().units)?),
                ),
                (
                    "dimension_set",
                    Json::Arr(
                        leg.dimension_set
                            .iter()
                            .map(|(dimension, value)| {
                                obj(vec![
                                    ("dimension", Json::Int(i128::from(*dimension))),
                                    ("value", s(format!("{:032x}", value.0))),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    ctx.out.at_book(&book)?;
    if let Some(at) = known_at {
        ctx.out.known_at(at);
    }
    ctx.out.event(
        "external_subledger_reconciled",
        vec![
            ("entry", s(format!("{:032x}", report.entry.vid.0))),
            ("recorded_at", Json::Int(i128::from(report.recorded_at.0))),
            ("feed", s(&report.feed)),
            ("batch_key", s(&report.batch_key)),
            ("effective_date", s(report.effective_date.render())),
            ("document_oid", s(hex(&report.evidence.document_oid.0))),
            ("doc_commit", s(hex(&report.evidence.doc_commit))),
            ("reviewer", s(format!("{:032x}", report.review.reviewer.0))),
            ("review", s(format!("{:032x}", report.review.attestation.0))),
            ("detail_rows", Json::Int(report.detail_rows as i128)),
            ("summary_legs", Json::Arr(legs)),
            ("reconciled", Json::Bool(report.reconciled)),
        ],
        &format!(
            "External feed {}/{} reconciles {} detail rows to {} summary legs at sequence {}.",
            report.feed,
            report.batch_key,
            report.detail_rows,
            report.summary_legs.len(),
            report.recorded_at.0
        ),
    );
    Ok(())
}
