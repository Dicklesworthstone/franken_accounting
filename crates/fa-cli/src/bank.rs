//! Bank statement intake and exact, unconfirmed match proposals.
//!
//! The shared facade owns the retained parser/account binding and checks the
//! complete evidence closure on every match. This surface supplies no grades,
//! inferred exchange rates, confirmation side effects, or balancing entries.

use std::collections::BTreeSet;

use fa::bank::{BankFormat, BankImportRequest, BankMatchRequest};
use fa_model::{Oid, account_vid};
use fa_money::{Amount, Side};
use fa_policy::Op;

use crate::args::Args;
use crate::cli::{Ctx, Fail, hex, known_at_flag, untrusted_text_json, usage};
use crate::json::{Json, obj, s};

const IMPORT_EXAMPLE: &str = "fa bank import <statement|-> --bank-format camt053|camt052|bai2|ofx|mt940|csv --account <cash-account-code> --json";
const MATCH_EXAMPLE: &str = "fa bank match --import <manifest_oid> [--date-window <days>] [--as-known-at HEAD|<seq>|<RFC3339>] --json";

pub(crate) fn bank_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let sub = args.positional.get(1).map(String::as_str);
    let allowed: &[&str] = match sub {
        Some("import") => &["--bank-format", "--account"],
        Some("match") => &["--import", "--date-window", "--as-known-at"],
        _ => &[],
    };
    for flag in [
        "--bank-format",
        "--account",
        "--import",
        "--date-window",
        "--as-known-at",
    ] {
        if args.flag(flag).is_some() && !allowed.contains(&flag) {
            return Err(usage(
                format!("{flag} does not apply to bank {}", sub.unwrap_or("")),
                "bank import binds the parser and cash account; bank match requires only that import's manifest and optional date/known-at selectors",
            ));
        }
        one_flag(
            args,
            flag,
            if sub == Some("match") {
                MATCH_EXAMPLE
            } else {
                IMPORT_EXAMPLE
            },
        )?;
    }
    if args.switch("--dry-run") {
        return Err(usage(
            "bank import does not support --dry-run; bank match is already an unconfirmed read",
            "review the statement before importing it; bank match --import <manifest_oid> creates no match confirmation or monetary entry",
        ));
    }
    match args.positional.get(1).map(String::as_str) {
        Some("import") => import(ctx, args),
        Some("match") => match_statement(ctx, args),
        _ => Err(usage(
            "bank has the subcommands import and match",
            IMPORT_EXAMPLE,
        )),
    }
}

fn one_flag<'a>(args: &'a Args, flag: &str, example: &str) -> Result<Option<&'a str>, Fail> {
    if args.flag_all(flag).len() > 1 {
        return Err(usage(format!("bank takes only one {flag}"), example));
    }
    Ok(args.flag(flag))
}

fn required<'a>(args: &'a Args, flag: &str, example: &str) -> Result<&'a str, Fail> {
    one_flag(args, flag, example)?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| usage(format!("bank requires {flag}"), example))
}

fn admit(capability: &fa_policy::Capability, import: bool) -> Result<(), Fail> {
    for op in [Op::Read, Op::Reconcile] {
        fa_policy::require(capability, op, "working with bank statements")
            .map_err(|d| Fail::Refusal(fa_journal::policy::refusal(&d)))?;
    }
    if import {
        fa_policy::require(capability, Op::Post, "importing bank evidence")
            .map_err(|d| Fail::Refusal(fa_journal::policy::refusal(&d)))?;
    }
    fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None)
        .map_err(|d| Fail::Refusal(fa_journal::policy::refusal(&d)))
}

fn money(mantissa: i128, unit: fa_money::UnitId, book: &fa::Book) -> Result<Json, Fail> {
    Amount::new(unit, mantissa)
        .try_render(&book.context().units)
        .map(s)
        .map_err(|e| {
            Fail::Book(fa::BookError::Kernel(fa_journal::KernelError::Corrupt(
                format!("bank result has an unrenderable exact amount: {e}"),
            )))
        })
}

fn import(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let [_, _, path] = args.positional.as_slice() else {
        return Err(usage(
            "bank import requires one statement file (or - for stdin)",
            IMPORT_EXAMPLE,
        ));
    };
    let format_name = required(args, "--bank-format", IMPORT_EXAMPLE)?;
    let format = BankFormat::parse_name(format_name).ok_or_else(|| {
        usage(
            format!("unsupported bank format `{format_name}`"),
            IMPORT_EXAMPLE,
        )
    })?;
    let account_code = required(args, "--account", IMPORT_EXAMPLE)?;
    let capability = ctx.capability(args, &["read", "post", "reconcile"])?;
    admit(&capability, true)?;
    let mut book = ctx.books.open(args)?;
    // Current authority is checked before a host reads or consumes the input.
    // The import kernel checks it again and retains its publication witnesses.
    book.preflight_intake(&capability, fa::IntakeAction::ImportRun)??;
    let max_statement_bytes = fa_registry::evidence_policy::EvidencePolicy::embedded()
        .map_err(|error| Fail::Internal(format!("the embedded evidence policy: {error}")))?
        .max_document_bytes;
    let bytes = crate::intake::read_document_with_limit(&ctx.files, path, max_statement_bytes)?;
    let recorded = book.import_bank_statement(
        &capability,
        BankImportRequest {
            account: account_vid(book.context().book_id, account_code),
            format,
            bytes,
        },
    )??;
    let manifest = &recorded.manifest;
    let unit = book
        .context()
        .units
        .get(manifest.unit)
        .ok_or_else(|| Fail::Internal("bank manifest unit is absent from the book".into()))?;
    let unit_code = unit.code.clone();
    let opening = money(manifest.opening_balance, manifest.unit, &book)?;
    let closing = money(manifest.closing_balance, manifest.unit, &book)?;
    let oid = hex(&recorded.manifest_oid.0);
    ctx.out.at_book(&book)?;
    ctx.out.event("bank_imported", vec![
        ("manifest_oid", s(&oid)),
        ("statement_oid", s(hex(&manifest.statement_oid.0))),
        ("statement_commit", s(hex(&manifest.statement_commit))),
        ("bank_format", s(manifest.format.name())),
        ("parser_revision", Json::Int(1)),
        ("account", s(account_code)),
        ("account_ref", s(format!("{:032x}", manifest.account.0))),
        ("unit", s(unit_code)),
        ("sequence_number", Json::Int(i128::from(manifest.sequence_number))),
        ("statement_date", s(manifest.statement_date.render())),
        ("opening_balance", opening),
        ("closing_balance", closing),
        ("line_count", Json::Int(manifest.line_oids.len() as i128)),
        ("line_oids", Json::Arr(manifest.line_oids.iter().map(|oid| s(hex(&oid.0))).collect())),
        ("receipt_hash", s(hex(&recorded.receipt.receipt.receipt_hash))),
        ("recorded_at", Json::Int(i128::from(recorded.receipt.receipt.recorded_at.0))),
        ("already_recorded", Json::Bool(recorded.receipt.already_recorded)),
    ], &format!("{} bank statement #{} for {account_code}: {} lines; manifest {oid}; inspect exact proposals with fa bank match --import {oid}",
        if recorded.receipt.already_recorded { "already recorded" } else { "imported" },
        manifest.sequence_number, manifest.line_oids.len()));
    Ok(())
}

fn match_statement(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "bank match takes its retained manifest via --import",
            MATCH_EXAMPLE,
        ));
    }
    let oid = Oid(crate::document::hex32(
        required(args, "--import", MATCH_EXAMPLE)?,
        "--import",
    )?);
    let date_window_days =
        one_flag(args, "--date-window", MATCH_EXAMPLE)?.map_or(Ok(3_u32), |value| {
            value.parse::<u32>().map_err(|_| {
                usage(
                    "--date-window must be a nonnegative integer number of days",
                    MATCH_EXAMPLE,
                )
            })
        })?;
    let capability = ctx.capability(args, &["read", "reconcile"])?;
    admit(&capability, false)?;
    let mut book = ctx.books.open(args)?;
    // Admit current authority before an instant selector can inspect ticks.
    book.read_scope(capability.holder(), &capability)??;
    let (known_at, _) = known_at_flag(args, &book, &ctx.out)?;
    let report = book.match_bank_statement(
        &capability,
        BankMatchRequest {
            manifest_oid: oid,
            known_at,
            date_window_days,
        },
    )??;
    let mut consumed = BTreeSet::new();
    let mut rows = Vec::with_capacity(report.lines.len());
    for (index, (line, proposal)) in report.lines.iter().zip(&report.proposals).enumerate() {
        let selected = proposal.matched_entry_ordinal.and_then(|ordinal| {
            usize::try_from(ordinal)
                .ok()
                .and_then(|index| report.candidates.get(index))
        });
        if let Some(ordinal) = proposal.matched_entry_ordinal {
            consumed.insert(ordinal);
        }
        let card = proposal
            .decision_card
            .canonical_bytes()
            .map_err(|e| Fail::Internal(format!("bank decision card: {e}")))?;
        rows.push(obj(vec![
            ("line_ordinal", Json::Int(i128::from(line.line_ordinal))),
            (
                "line_document_oid",
                s(hex(&report.manifest.line_oids[index].0)),
            ),
            (
                "bank_line_id",
                s(hex(&line
                    .oid()
                    .map_err(|e| Fail::Internal(e.to_string()))?
                    .0)),
            ),
            ("booking_date", s(line.booking_date.render())),
            ("value_date", s(line.value_date.render())),
            (
                "direction",
                s(if line.side == Side::Credit {
                    "inflow"
                } else {
                    "outflow"
                }),
            ),
            (
                "amount",
                money(line.amount.mantissa, line.amount.unit, &book)?,
            ),
            (
                "counterparty",
                untrusted_text_json(
                    Some(line.counterparty.clone()),
                    format!("D:{}", hex(&report.manifest.line_oids[index].0)),
                ),
            ),
            (
                "reference",
                untrusted_text_json(
                    Some(line.reference.clone()),
                    format!("D:{}", hex(&report.manifest.line_oids[index].0)),
                ),
            ),
            (
                "status",
                s(if selected.is_some() {
                    "proposed"
                } else {
                    "unmatched"
                }),
            ),
            (
                "entry_ref",
                selected.map_or(Json::Null, |candidate| {
                    obj(vec![
                        (
                            "vid",
                            s(format!("{:032x}", candidate.candidate.entry_ref.vid.0)),
                        ),
                        (
                            "entry_digest",
                            s(hex(&candidate.candidate.entry_ref.entry_digest)),
                        ),
                    ])
                }),
            ),
            (
                "leg_ordinal",
                selected.map_or(Json::Null, |candidate| {
                    Json::Int(i128::from(candidate.leg_ordinal))
                }),
            ),
            (
                "candidate_ordinal",
                proposal
                    .matched_entry_ordinal
                    .map_or(Json::Null, |n| Json::Int(i128::from(n))),
            ),
            ("decision_card", s(hex(&card))),
            (
                "decision_card_digest",
                s(hex(&proposal
                    .decision_card
                    .digest()
                    .map_err(|e| Fail::Internal(e.to_string()))?)),
            ),
            (
                "proposal_digest",
                s(hex(&proposal
                    .oid()
                    .map_err(|e| Fail::Internal(e.to_string()))?
                    .0)),
            ),
        ]));
    }
    let mut outstanding = Vec::new();
    for candidate in &report.candidates {
        if consumed.contains(&candidate.candidate.entry_ordinal) {
            continue;
        }
        outstanding.push(obj(vec![
            (
                "entry_ref",
                obj(vec![
                    (
                        "vid",
                        s(format!("{:032x}", candidate.candidate.entry_ref.vid.0)),
                    ),
                    (
                        "entry_digest",
                        s(hex(&candidate.candidate.entry_ref.entry_digest)),
                    ),
                ]),
            ),
            ("leg_ordinal", Json::Int(i128::from(candidate.leg_ordinal))),
            (
                "effective_date",
                s(candidate.candidate.effective_date.render()),
            ),
            (
                "side",
                s(if candidate.candidate.side == Side::Debit {
                    "Debit"
                } else {
                    "Credit"
                }),
            ),
            (
                "amount",
                money(
                    candidate.candidate.amount.mantissa,
                    candidate.candidate.amount.unit,
                    &book,
                )?,
            ),
        ]));
    }
    let matched = consumed.len();
    let unit_code = book
        .context()
        .units
        .get(report.manifest.unit)
        .ok_or_else(|| Fail::Internal("bank result unit is absent from the book".into()))?
        .code
        .clone();
    let fields = vec![
        ("manifest_oid", s(hex(&report.manifest_oid.0))),
        ("statement_oid", s(hex(&report.manifest.statement_oid.0))),
        ("account", s(&report.account_code)),
        (
            "account_ref",
            s(format!("{:032x}", report.manifest.account.0)),
        ),
        ("unit", s(unit_code)),
        ("known_at", Json::Int(i128::from(report.known_at.0))),
        ("statement_date", s(report.manifest.statement_date.render())),
        (
            "date_window",
            Json::Int(i128::from(report.date_window_days)),
        ),
        (
            "candidate_from",
            report
                .candidate_from
                .map_or(Json::Null, |day| s(day.render())),
        ),
        (
            "candidate_through",
            report
                .candidate_through
                .map_or(Json::Null, |day| s(day.render())),
        ),
        ("outstanding_scope", s(report.outstanding_scope)),
        (
            "outstanding_complete",
            Json::Bool(report.outstanding_complete),
        ),
        ("decision_epoch", s(hex(&report.decision_epoch))),
        ("method", s("exact_amount_date_reference")),
        ("confirmed", Json::Bool(false)),
        ("line_count", Json::Int(report.lines.len() as i128)),
        ("proposed_count", Json::Int(matched as i128)),
        (
            "unmatched_count",
            Json::Int((report.lines.len() - matched) as i128),
        ),
        ("outstanding_count", Json::Int(outstanding.len() as i128)),
        (
            "statement_closing_balance",
            money(report.manifest.closing_balance, report.manifest.unit, &book)?,
        ),
        (
            "book_closing_balance",
            money(report.book_closing_balance, report.manifest.unit, &book)?,
        ),
        (
            "closing_difference",
            money(report.closing_difference, report.manifest.unit, &book)?,
        ),
        ("proposals", Json::Arr(rows)),
        ("outstanding", Json::Arr(outstanding)),
    ];
    let max_inline = crate::verbs::registry()
        .map_err(|e| Fail::Internal(e.into()))?
        .daemon
        .max_frame_bytes
        .saturating_sub(128 * 1024);
    if obj(fields.clone()).render().len() > max_inline {
        return Err(usage(
            "the complete bank match response exceeds the inline transport bound; no statement lines, decision cards or unmatched book candidates within the search window were omitted",
            "narrow --date-window or request a smaller statement from the bank",
        ));
    }
    ctx.out.at_book(&book)?;
    ctx.out.known_at(report.known_at);
    ctx.out.effective(format!(
        "through:{}",
        report.manifest.statement_date.render()
    ));
    let candidate_window = match (report.candidate_from, report.candidate_through) {
        (Some(from), Some(through)) => {
            format!("{} through {} inclusive", from.render(), through.render())
        }
        _ => "none (the statement contains no bank lines)".into(),
    };
    ctx.out.event("bank_matches_proposed", fields, &format!(
        "bank statement for {} at {}: {matched} exact proposals, {} unmatched bank lines, {} unmatched book candidates; candidate search: {candidate_window}; outstanding inventory completeness is unestablished; proposals are unconfirmed",
        report.account_code, report.known_at.0, report.lines.len() - matched,
        report.candidates.len() - matched,
    ));
    Ok(())
}
