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

const HELP: &str = "fa subledger reconcile-feed <feed> --control <account> --as-of YYYY-MM-DD [--as-known-at <seq>] [--certify | --certificate-out <new-file>]; fa subledger detail --input <batch.json|-> [--out <new-file>]; retain the bytes as a Workpaper and obtain an independent Reviewed attestation; fa subledger feed --document D:<oid> --date YYYY-MM-DD --key K [--dry-run --plan-out <new-file>]; fa subledger verify-feed <entry> [--as-known-at <seq>]";
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
    "--certificate-out",
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
    if args.switch("--certify")
        && args.positional.get(1).map(String::as_str) != Some("reconcile-feed")
    {
        return Err(usage(
            "external-feed certification is available for reconcile-feed",
            HELP,
        ));
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
        Some("reconcile-feed") => reconcile_feed(ctx, args),
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
    book.prepare_external_feed_history(principal, &capability, known_at)??;
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

fn reconcile_feed(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &["--control", "--as-of", "--as-known-at", "--certificate-out"],
        false,
    )?;
    let [_, _, feed] = args.positional.as_slice() else {
        return Err(usage(
            "reconcile-feed names exactly one external feed",
            HELP,
        ));
    };
    let control = args.require("--control", "the GL control account code")?;
    let through = DateDay::parse(args.require("--as-of", "YYYY-MM-DD")?)
        .map_err(|error| usage(format!("invalid --as-of: {error}"), HELP))?;
    if args
        .flag("--as-known-at")
        .is_some_and(|value| value != "HEAD" && value.parse::<u64>().is_err())
    {
        return Err(usage(
            "external-feed reconciliation requires HEAD or a recorded sequence",
            HELP,
        ));
    }
    let certify = args.switch("--certify") || args.flag("--certificate-out").is_some();
    let principal = ctx.principal(args);
    let capability = ctx.capability(
        args,
        if certify {
            &["read", "produce"]
        } else {
            &["read"]
        },
    )?;
    let mut book = ctx.books.open_admitted(args, |book| {
        book.read_scope(principal, &capability)??;
        Ok(())
    })?;
    let (known_at, _) = known_at_read_flag(args, &book, &ctx.out, &capability)?;
    book.prepare_external_feed_history(principal, &capability, known_at)??;
    let mut request = fa::ExternalFeedRequest {
        feed: feed.clone(),
        control_account: account_vid(book.context().book_id, control),
        effective_through: through,
        known_at,
    };
    let (report, certificate) = if certify {
        let certified = book.certify_external_feed(principal, &capability, &request)??;
        (certified.report, Some(certified.certificate))
    } else {
        (
            book.reconcile_external_feed(principal, &capability, &request)??,
            None,
        )
    };
    request.known_at = Some(report.known_at);
    let retained = if let Some(certificate) = &certificate {
        let artifact = fa::ReportArtifact::try_from(certificate)?;
        let (bytes, retained) = crate::notary::retain_report_artifact_for(
            &mut book,
            &ctx.files,
            args,
            &artifact,
            &capability,
            fa::ReportArtifactExpectation::ExternalFeed(&request),
        )?;
        Some((artifact, bytes, retained))
    } else {
        None
    };
    ctx.out.at_book(&book)?;
    let digest = certificate
        .as_ref()
        .map(|certificate| hex(certificate.digest()));
    render_feed(&ctx.out, &book, &report, digest.as_deref())?;
    if let Some((artifact, bytes, retained)) = retained {
        let expected = crate::notary::external_feed_expectation_json(&request);
        crate::notary::emit_report_artifact_for(
            &ctx.out,
            args,
            &artifact,
            fa::EXTERNAL_FEED_REPORT_FORMAT,
            &bytes,
            &retained,
            &expected,
        );
    }
    Ok(())
}

pub(crate) fn render_feed(
    out: &crate::cli::Out,
    book: &Book,
    report: &fa::ExternalFeedReconciliation,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    let amount = |unit, mantissa| -> Result<Json, Fail> {
        Ok(s(render_amount(
            fa_money::Amount {
                unit: fa_money::UnitId(unit),
                mantissa,
            },
            &book.context().units,
        )?))
    };
    let dimensions = |set: &[(u32, fgdb_types::VId)]| {
        Json::Arr(
            set.iter()
                .map(|(dimension, value)| {
                    obj(vec![
                        ("dimension", Json::Int(i128::from(*dimension))),
                        ("value", s(format!("{:032x}", value.0))),
                    ])
                })
                .collect(),
        )
    };
    let rows = report
        .rows
        .iter()
        .map(|row| {
            Ok(obj(vec![
                ("unit_id", Json::Int(i128::from(row.unit_id))),
                ("dimension_set", dimensions(&row.dimension_set)),
                ("detail_debits", amount(row.unit_id, row.detail_debits)?),
                ("detail_credits", amount(row.unit_id, row.detail_credits)?),
                ("control_debits", amount(row.unit_id, row.control_debits)?),
                ("control_credits", amount(row.unit_id, row.control_credits)?),
                ("pending_debits", amount(row.unit_id, row.pending_debits)?),
                ("pending_credits", amount(row.unit_id, row.pending_credits)?),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let totals = report
        .totals
        .iter()
        .map(|row| {
            Ok(obj(vec![
                ("unit_id", Json::Int(i128::from(row.unit_id))),
                ("detail_debits", amount(row.unit_id, row.detail_debits)?),
                ("detail_credits", amount(row.unit_id, row.detail_credits)?),
                ("control_debits", amount(row.unit_id, row.control_debits)?),
                ("control_credits", amount(row.unit_id, row.control_credits)?),
                ("pending_debits", amount(row.unit_id, row.pending_debits)?),
                ("pending_credits", amount(row.unit_id, row.pending_credits)?),
                ("register_debits", amount(row.unit_id, row.register_debits)?),
                (
                    "register_credits",
                    amount(row.unit_id, row.register_credits)?,
                ),
                (
                    "register_debits_pending",
                    amount(row.unit_id, row.register_debits_pending)?,
                ),
                (
                    "register_credits_pending",
                    amount(row.unit_id, row.register_credits_pending)?,
                ),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let batches = report
        .batches
        .iter()
        .map(|batch| {
            obj(vec![
                ("entry", s(format!("{:032x}", batch.entry.vid.0))),
                ("entry_digest", s(hex(&batch.entry.entry_digest))),
                ("recorded_at", Json::Int(i128::from(batch.recorded_at.0))),
                ("batch_key", s(&batch.batch_key)),
                ("document_oid", s(hex(&batch.evidence.document_oid.0))),
                ("review", s(format!("{:032x}", batch.review.attestation.0))),
                ("detail_rows", Json::Int(batch.detail_rows as i128)),
            ])
        })
        .collect();
    let contributions = report
        .contributions
        .iter()
        .map(|entry| {
            obj(vec![
                ("entry", s(format!("{:032x}", entry.entry.vid.0))),
                ("entry_digest", s(hex(&entry.entry.entry_digest))),
                ("recorded_at", Json::Int(i128::from(entry.recorded_at.0))),
                ("effective_date", s(entry.effective_date.render())),
                ("source", s(format!("{:032x}", entry.source.vid.0))),
                ("source_digest", s(hex(&entry.source.entry_digest))),
                ("reversed", Json::Bool(entry.reversed)),
            ])
        })
        .collect();
    let unmatched = report
        .unattributed
        .iter()
        .map(|leg| {
            Ok(obj(vec![
                ("entry", s(format!("{:032x}", leg.entry.vid.0))),
                ("entry_digest", s(hex(&leg.entry.entry_digest))),
                ("ordinal", Json::Int(i128::from(leg.ordinal))),
                ("unit_id", Json::Int(i128::from(leg.unit.0))),
                (
                    "side",
                    s(match leg.side {
                        Side::Debit => "debit",
                        Side::Credit => "credit",
                    }),
                ),
                ("amount", amount(leg.unit.0, leg.amount)?),
                ("dimension_set", dimensions(&leg.dimension_set)),
                ("pending", Json::Bool(leg.pending)),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    out.known_at(report.known_at);
    out.event_with_certificate(
        "external_feed_reconciled",
        vec![
            ("feed", s(&report.feed)),
            ("control_account", s(format!("{:032x}", report.control_account.0))),
            ("known_at", Json::Int(i128::from(report.known_at.0))),
            ("effective_through", s(report.effective_through.render())),
            ("batches", Json::Arr(batches)),
            ("contributions", Json::Arr(contributions)),
            ("unattributed", Json::Arr(unmatched)),
            ("rows", Json::Arr(rows)),
            ("totals", Json::Arr(totals)),
            ("reconciled", Json::Bool(report.reconciled)),
        ],
        &format!("External feed {}: {} reviewed batches, {} attributable postings, {} unmatched control legs; reconciled={} at sequence {} through {}.",
            report.feed, report.batches.len(), report.contributions.len(), report.unattributed.len(),
            report.reconciled, report.known_at.0, report.effective_through.render()),
        certificate,
    );
    Ok(())
}
