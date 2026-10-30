//! Source-bound, advisory purchase-order / receipt / invoice matching.
//!
//! The facade reads and authenticates all three retained documents. This
//! surface accepts document identities and an item selector, never monetary
//! assertions or a path from which a purported match could be reconstructed.

use fa::matching::{THREE_WAY_PROFILE, ThreeWayMatchRequest, ThreeWayMatchSource};
use fa_model::Oid;
use fa_policy::Op;
use fa_registers::reconciliation::ThreeWayMatchVerdict;
use fa_registry::evidence_policy::EvidencePolicy;
use fgdb_types::CommitSeq;

use crate::args::Args;
use crate::cli::{Ctx, Fail, hex, parse_digest, untrusted_text_json, usage};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa match three-way --purchase-order D:<oid> --receiving-report D:<oid> --invoice-document D:<oid> --item <exact-item-code> [--as-known-at HEAD|<seq>] [--expect-digest <retained-result-digest>] --json";

fn one<'a>(args: &'a Args, flag: &str) -> Result<Option<&'a str>, Fail> {
    if args.flag_all(flag).len() > 1 {
        return Err(usage(
            format!("match three-way takes only one {flag}"),
            EXAMPLE,
        ));
    }
    Ok(args.flag(flag))
}

fn required<'a>(args: &'a Args, flag: &str) -> Result<&'a str, Fail> {
    one(args, flag)?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| usage(format!("match three-way requires {flag}"), EXAMPLE))
}

fn source_json(source: &ThreeWayMatchSource, policy: &EvidencePolicy) -> Json {
    obj(vec![
        ("oid", s(hex(&source.oid.0))),
        ("doc_commit", s(hex(&source.doc_commit))),
        ("kind_id", Json::Int(i128::from(source.kind))),
        ("grade_id", Json::Int(i128::from(source.grade))),
        (
            "grade",
            s(policy
                .grade_by_tag(source.grade)
                .map_or("unknown", |grade| grade.name.as_str())),
        ),
        ("uploader", s(format!("{:032x}", source.uploader.0))),
        ("recorded_at", Json::Int(i128::from(source.recorded_at.0))),
        ("line_ordinal", Json::Int(i128::from(source.line_ordinal))),
    ])
}

pub(crate) fn match_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 || args.positional.get(1).map(String::as_str) != Some("three-way")
    {
        return Err(usage("match requires the three-way subcommand", EXAMPLE));
    }
    let purchase_order_oid = Oid(crate::document::hex32(
        required(args, "--purchase-order")?,
        "--purchase-order",
    )?);
    let receiving_report_oid = Oid(crate::document::hex32(
        required(args, "--receiving-report")?,
        "--receiving-report",
    )?);
    let invoice_oid = Oid(crate::document::hex32(
        required(args, "--invoice-document")?,
        "--invoice-document",
    )?);
    let item_code = required(args, "--item")?.to_string();
    let known_at = match one(args, "--as-known-at")? {
        None | Some("HEAD") => None,
        Some(value) => Some(CommitSeq(value.parse::<u64>().map_err(|_| {
            usage(
                "--as-known-at must be HEAD or a nonnegative commit sequence",
                EXAMPLE,
            )
        })?)),
    };
    let expected_digest = one(args, "--expect-digest")?
        .map(|value| parse_digest(value, "--expect-digest"))
        .transpose()?;
    if expected_digest.is_some() && known_at.is_none() {
        return Err(usage(
            "digest-bound matching replay requires the original numeric --as-known-at",
            "repeat the returned replay_argv on the same book; a changing HEAD cannot identify a retained result",
        ));
    }
    let capability = ctx.capability(args, &["read", "reconcile"])?;
    for op in [Op::Read, Op::Reconcile] {
        fa_policy::require(&capability, op, "matching retained purchase evidence")
            .map_err(|denied| Fail::Refusal(fa_journal::policy::refusal(&denied)))?;
    }
    fa_policy::reach(&capability, &fa_policy::Reach::whole_book(true), None)
        .map_err(|denied| Fail::Refusal(fa_journal::policy::refusal(&denied)))?;
    let mut book = ctx.books.open_admitted(args, |book| {
        book.read_scope(capability.holder(), &capability)??;
        Ok(())
    })?;
    let report = book.match_three_way(
        &capability,
        ThreeWayMatchRequest {
            purchase_order_oid,
            receiving_report_oid,
            invoice_oid,
            item_code,
            known_at,
            expected_digest,
        },
    )??;
    let render = |amount: fa_money::Amount| {
        amount
            .try_render(&book.context().units)
            .map(s)
            .map_err(|error| Fail::Internal(format!("matching result amount: {error}")))
    };
    let verdict = match report.result.verdict {
        ThreeWayMatchVerdict::Matched => "matched",
        ThreeWayMatchVerdict::QuantityVariance { .. } => "quantity_variance",
        ThreeWayMatchVerdict::PriceVariance { .. } => "price_variance",
        ThreeWayMatchVerdict::ExtensionMismatch { .. } => "extension_mismatch",
    };
    let expected_total = report
        .invoice
        .quantity_billed
        .checked_mul(report.invoice.unit_price_billed.mantissa)
        .ok_or_else(|| Fail::Internal("admitted invoice extension overflowed".into()))?;
    let card_bytes = report
        .result
        .decision_card
        .canonical_bytes()
        .map_err(|error| Fail::Internal(error.to_string()))?;
    let card_digest = report
        .result
        .decision_card
        .digest()
        .map_err(|error| Fail::Internal(error.to_string()))?;
    let result_digest = hex(&report.result_digest);
    let policy = EvidencePolicy::embedded()
        .map_err(|error| Fail::Internal(format!("matching evidence policy: {error}")))?;
    let replay_argv = vec![
        s("fa"),
        s("match"),
        s("three-way"),
        s("--purchase-order"),
        s(format!("D:{}", hex(&purchase_order_oid.0))),
        s("--receiving-report"),
        s(format!("D:{}", hex(&receiving_report_oid.0))),
        s("--invoice-document"),
        s(format!("D:{}", hex(&invoice_oid.0))),
        s("--item"),
        s(&report.item_code),
        s("--as-known-at"),
        s(report.known_at.0.to_string()),
        s("--expect-digest"),
        s(&result_digest),
        s("--json"),
    ];
    let fields = vec![
        ("profile", s(THREE_WAY_PROFILE)),
        ("known_at", Json::Int(i128::from(report.known_at.0))),
        ("verdict", s(verdict)),
        ("matched", Json::Bool(verdict == "matched")),
        ("advisory", Json::Bool(true)),
        ("confirmed", Json::Bool(false)),
        (
            "item_code",
            untrusted_text_json(
                Some(report.item_code.clone()),
                "retained purchase evidence".into(),
            ),
        ),
        (
            "vendor",
            untrusted_text_json(
                Some(report.purchase_order.vendor.clone()),
                format!("D:{}", hex(&purchase_order_oid.0)),
            ),
        ),
        (
            "quantity_ordered",
            s(report.purchase_order.quantity.to_string()),
        ),
        (
            "quantity_received",
            s(report.receiving_report.quantity_received.to_string()),
        ),
        (
            "quantity_billed",
            s(report.invoice.quantity_billed.to_string()),
        ),
        ("po_unit_price", render(report.purchase_order.unit_price)?),
        (
            "invoice_unit_price",
            render(report.invoice.unit_price_billed)?,
        ),
        ("invoice_total", render(report.invoice.total_billed)?),
        (
            "invoice_expected_total",
            render(fa_money::Amount::new(
                report.invoice.total_billed.unit,
                expected_total,
            ))?,
        ),
        (
            "purchase_order_source",
            source_json(&report.purchase_order_source, &policy),
        ),
        (
            "receiving_report_source",
            source_json(&report.receiving_report_source, &policy),
        ),
        (
            "invoice_source",
            source_json(&report.invoice_source, &policy),
        ),
        ("decision_card", s(hex(&card_bytes))),
        ("decision_card_digest", s(hex(&card_digest))),
        ("result_digest", s(result_digest)),
        ("replay_argv", Json::Arr(replay_argv)),
    ];
    ctx.out.at_book(&book)?;
    ctx.out.known_at(report.known_at);
    ctx.out.event("three_way_match", fields, &format!(
        "three-way match for {:?} at sequence {}: {verdict}; advisory comparison of retained sources, not a payment approval",
        report.item_code, report.known_at.0,
    ));
    Ok(())
}
