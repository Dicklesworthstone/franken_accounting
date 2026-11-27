//! Preparation and live verification of a source's declared delivery population.

use super::{fields, options, text};
use crate::args::Args;
use crate::cli::{Ctx, Fail, hex, known_at_read_flag, parse_json, parse_vid, usage};
use crate::json::{Json, obj, s};
use fa_journal::external_subledger::manifest::{
    EXTERNAL_FEED_MANIFEST_MIME, ExternalFeedManifest, ExternalFeedManifestChild,
    ExternalFeedManifestStatus, ExternalFeedManifestTotal, MAX_EXTERNAL_MANIFEST_CHILDREN,
    MAX_EXTERNAL_MANIFEST_TOTALS,
};
use fa_model::{Oid, account_vid};
use fa_money::Amount;
use fa_time::DateDay;

const HELP: &str = "fa subledger manifest --input <source.json|-> [--out <new-file>]; fa subledger verify-manifest D:<reviewed-manifest-oid> [--as-known-at HEAD|<seq>]";

fn array<'a>(value: &'a Json, key: &str, max: usize) -> Result<&'a [Json], Fail> {
    value
        .get(key)
        .and_then(Json::as_arr)
        .filter(|items| items.len() <= max)
        .ok_or_else(|| {
            usage(
                format!("{key} requires an array of at most {max} elements"),
                HELP,
            )
        })
}

fn integer(value: &Json, key: &str) -> Result<i128, Fail> {
    match value.get(key) {
        Some(Json::Int(n)) => Ok(*n),
        _ => Err(usage(format!("{key} requires an integer"), HELP)),
    }
}

fn parse(value: &Json, book: &fa::Book) -> Result<ExternalFeedManifest, Fail> {
    fields(
        value,
        &[
            "feed",
            "extract_id",
            "from",
            "through",
            "detail_rows",
            "children",
            "totals",
        ],
        "manifest",
    )?;
    let mut children = Vec::new();
    for child in array(value, "children", MAX_EXTERNAL_MANIFEST_CHILDREN)? {
        fields(child, &["batch_key", "doc_commit"], "manifest child")?;
        children.push(ExternalFeedManifestChild {
            batch_key: text(child, "batch_key")?.into(),
            detail_commit: crate::proof::fixed_hex(text(child, "doc_commit")?, "doc_commit")?,
        });
    }
    children.sort_by(|a, b| a.batch_key.cmp(&b.batch_key));
    let mut totals = Vec::new();
    for cell in array(value, "totals", MAX_EXTERNAL_MANIFEST_TOTALS)? {
        fields(
            cell,
            &["account", "debits", "credits", "dimension_set"],
            "manifest total",
        )?;
        let gross = |key| {
            Amount::parse(text(cell, key)?, &book.context().units)
                .map_err(|error| usage(format!("{key}: {error}"), HELP))
        };
        let debits = gross("debits")?;
        let credits = gross("credits")?;
        if debits.unit != credits.unit {
            return Err(usage(
                "gross debit and credit totals must use the same unit",
                HELP,
            ));
        }
        let mut dimensions = Vec::new();
        if cell.get("dimension_set").is_some() {
            for dim in array(
                cell,
                "dimension_set",
                fa_model::limits::MAX_DIMENSIONS_PER_LEG,
            )? {
                fields(dim, &["dimension", "value"], "manifest dimension")?;
                let kind = u32::try_from(integer(dim, "dimension")?)
                    .map_err(|_| usage("dimension must fit u32", HELP))?;
                dimensions.push((kind, parse_vid(text(dim, "value")?, "dimension value")?));
            }
            dimensions.sort_unstable();
        }
        totals.push(ExternalFeedManifestTotal {
            account: account_vid(book.context().book_id, text(cell, "account")?),
            unit: debits.unit,
            dimensions,
            debits: debits.mantissa,
            credits: credits.mantissa,
        });
    }
    totals.sort_by(|a, b| {
        (a.account, a.unit, &a.dimensions).cmp(&(b.account, b.unit, &b.dimensions))
    });
    let date =
        |key| DateDay::parse(text(value, key)?).map_err(|e| usage(format!("{key}: {e}"), HELP));
    Ok(ExternalFeedManifest {
        book_id: book.context().book_id,
        feed: text(value, "feed")?.to_owned(),
        extract_id: text(value, "extract_id")?.to_owned(),
        effective_from: date("from")?,
        effective_through: date("through")?,
        detail_rows: u64::try_from(integer(value, "detail_rows")?)
            .map_err(|_| usage("detail_rows must fit u64", HELP))?,
        children,
        totals,
    })
}

pub(super) fn prepare(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(args, &["--input", "--out"], false)?;
    if args.positional.len() != 2 {
        return Err(usage("subledger manifest takes named inputs only", HELP));
    }
    let source = args.require("--input", "manifest.json or -")?;
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read"])?;
    let book = ctx.books.open_admitted(args, |book| {
        crate::rea::admit_read(book, principal, &capability)
    })?;
    let manifest = parse(&parse_json(source, &ctx.files.read_text(source)?)?, &book)?;
    let bytes = manifest.canonical_bytes()?;
    let evidence = manifest.evidence()?;
    if let Some(path) = args.flag("--out") {
        if path.is_empty() || path == "-" {
            return Err(usage("--out must name a new binary file", HELP));
        }
        crate::proof::write_new(
            &ctx.files.resolve(path),
            path,
            &bytes,
            "external feed manifest",
            "--out",
        )?;
    }
    ctx.out.at_book(&book)?;
    ctx.out.event("external_feed_manifest", vec![
        ("feed", s(&manifest.feed)), ("extract_id", s(&manifest.extract_id)),
        ("document_oid", s(hex(&evidence.document_oid.0))), ("mime", s(EXTERNAL_FEED_MANIFEST_MIME)),
        ("bytes", s(hex(&bytes))), ("file", args.flag("--out").map_or(Json::Null, s)),
    ], &format!("Prepared declaration for {} with {} children. Retain as a Workpaper with MIME {} and obtain an independent review.", manifest.feed, manifest.children.len(), EXTERNAL_FEED_MANIFEST_MIME));
    Ok(())
}

pub(super) fn verify(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(args, &["--as-known-at"], false)?;
    let [_, _, source] = args.positional.as_slice() else {
        return Err(usage(
            "verify-manifest requires one retained manifest document",
            HELP,
        ));
    };
    let oid = Oid(crate::proof::fixed_hex(
        source.strip_prefix("D:").unwrap_or(source),
        "manifest oid",
    )?);
    if args
        .flag("--as-known-at")
        .is_some_and(|v| v != "HEAD" && v.parse::<u64>().is_err())
    {
        return Err(usage("select HEAD or a recorded sequence", HELP));
    }
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        book.read_scope(principal, &capability)??;
        Ok(())
    })?;
    let (at, _) = known_at_read_flag(args, &book, &ctx.out, &capability)?;
    let verified = book.verify_external_feed_manifest(principal, &capability, oid, at)??;
    let report = &verified.comparison;
    let strings = |values: &[String]| Json::Arr(values.iter().map(s).collect());
    let digests = report
        .digest_mismatches
        .iter()
        .map(|d| {
            obj(vec![
                ("batch_key", s(&d.batch_key)),
                ("expected_commit", s(hex(&d.expected_commit))),
                ("actual_commit", s(hex(&d.actual_commit))),
            ])
        })
        .collect();
    let cells = report
        .totals
        .iter()
        .filter(|t| !t.matches())
        .map(|t| {
            obj(vec![
                ("account", s(format!("{:032x}", t.account.0))),
                ("unit_id", Json::Int(t.unit.0.into())),
                (
                    "dimension_set",
                    Json::Arr(
                        t.dimensions
                            .iter()
                            .map(|(kind, value)| {
                                obj(vec![
                                    ("dimension", Json::Int((*kind).into())),
                                    ("value", s(format!("{:032x}", value.0))),
                                ])
                            })
                            .collect(),
                    ),
                ),
                ("expected_debits", s(t.expected_debits.to_string())),
                ("expected_credits", s(t.expected_credits.to_string())),
                ("actual_debits", s(t.actual_debits.to_string())),
                ("actual_credits", s(t.actual_credits.to_string())),
            ])
        })
        .collect();
    ctx.out.at_book(&book)?;
    ctx.out.known_at(verified.known_at);
    ctx.out.event(
        "external_feed_manifest_verified",
        vec![
            ("document_oid", s(hex(&oid.0))),
            (
                "review",
                s(format!("{:032x}", verified.review.attestation.0)),
            ),
            ("feed", s(&report.manifest.feed)),
            ("extract_id", s(&report.manifest.extract_id)),
            ("from", s(report.manifest.effective_from.render())),
            ("through", s(report.manifest.effective_through.render())),
            ("status", s(report.status.as_str())),
            (
                "observed_children",
                Json::Int(report.children.len() as i128),
            ),
            (
                "expected_rows",
                Json::Int(report.manifest.detail_rows.into()),
            ),
            ("actual_rows", Json::Int(report.actual_detail_rows.into())),
            ("missing", strings(&report.missing)),
            ("unexpected", strings(&report.unexpected)),
            ("digest_mismatches", Json::Arr(digests)),
            ("cell_mismatches", Json::Arr(cells)),
        ],
        &format!(
            "Extract {} is {} at sequence {}: {} of {} declared rows.",
            report.manifest.extract_id,
            report.status.as_str(),
            verified.known_at.0,
            report.actual_detail_rows,
            report.manifest.detail_rows
        ),
    );
    if report.status != ExternalFeedManifestStatus::Complete {
        return Err(Fail::Verification {
            message: format!("external-feed population is {}", report.status.as_str()),
            detail: obj(vec![("document_oid", s(hex(&oid.0))), ("status", s(report.status.as_str()))]),
            cite: Some("plan §5.6".into()),
            fix: Some("Compare the reported child keys, commitments and gross cells with the reviewed extract at the selected sequence.".into()),
        });
    }
    Ok(())
}
