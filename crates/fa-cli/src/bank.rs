//! Bank statement intake, exact proposals and immutable confirmations.
//!
//! The shared facade owns the retained parser/account binding and checks the
//! complete evidence closure on every match. This surface supplies no grades,
//! inferred exchange rates or balancing entries. Confirmation is explicit.

use std::collections::BTreeSet;

use fa::bank::{
    BankConfirmationRequest, BankFormat, BankImportManifest, BankImportRequest, BankMatchRecorded,
    BankMatchRequest, BankStatusRequest,
};
use fa_model::{Oid, account_vid};
use fa_money::{Amount, Side};
use fa_policy::Op;
use fa_registers::reconciliation::pinned_bank_candidate;

use crate::args::Args;
use crate::cli::{Ctx, Fail, hex, known_at_flag, untrusted_text_json, usage};
use crate::json::{Json, obj, s};

const IMPORT_EXAMPLE: &str = "fa bank import <statement|-> --bank-format camt053|camt052|bai2|ofx|mt940|csv --account <cash-account-code> [--previous-import <manifest_oid> --grant privileged] --json";
const MATCH_EXAMPLE: &str = "fa bank match --import <manifest_oid> --grant privileged [--date-window <days>] [--as-known-at HEAD|<seq>|<RFC3339>] --json (embedded-owner CLI with explicit full-source authority)";
const CONFIRM_EXAMPLE: &str = "fa bank confirm --import <manifest_oid> --line-ordinal <ordinal> --proposal-digest <hex64> --source-known-at <seq> --proposer <hex32> --date-window <days> --grant privileged --json (use the exact confirmation_command printed by bank match)";
const STATUS_EXAMPLE: &str = "fa bank status --import <manifest_oid> --grant privileged [--as-known-at HEAD|<seq>|<RFC3339>] --json";

pub(crate) fn bank_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let sub = args.positional.get(1).map(String::as_str);
    let allowed: &[&str] = match sub {
        Some("import") => &["--bank-format", "--account", "--previous-import"],
        Some("match") => &["--import", "--date-window", "--as-known-at"],
        Some("confirm") => &[
            "--import",
            "--line-ordinal",
            "--proposal-digest",
            "--source-known-at",
            "--date-window",
            "--proposer",
        ],
        Some("status") => &["--import", "--as-known-at"],
        _ => &[],
    };
    for flag in [
        "--bank-format",
        "--account",
        "--previous-import",
        "--import",
        "--date-window",
        "--as-known-at",
        "--line-ordinal",
        "--proposal-digest",
        "--source-known-at",
        "--proposer",
    ] {
        if args.flag(flag).is_some() && !allowed.contains(&flag) {
            return Err(usage(
                format!("{flag} does not apply to bank {}", sub.unwrap_or("")),
                "bank import binds the parser and cash account; match and status select the retained manifest; confirm selects one exact replayed proposal",
            ));
        }
        one_flag(
            args,
            flag,
            match sub {
                Some("match") => MATCH_EXAMPLE,
                Some("confirm") => CONFIRM_EXAMPLE,
                Some("status") => STATUS_EXAMPLE,
                _ => IMPORT_EXAMPLE,
            },
        )?;
    }
    if args.switch("--dry-run") {
        return Err(usage(
            "bank does not support --dry-run; match and status already read without publishing",
            "review bank match before explicitly confirming its exact selected proposal",
        ));
    }
    match args.positional.get(1).map(String::as_str) {
        Some("import") => import(ctx, args),
        Some("match") => match_statement(ctx, args),
        Some("confirm") => confirm_statement(ctx, args),
        Some("status") => confirmation_status(ctx, args),
        _ => Err(usage(
            "bank has the subcommands import, match, confirm and status",
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

fn predecessor_json(manifest: &BankImportManifest, book: &fa::Book) -> Result<Json, Fail> {
    let Some(previous) = &manifest.predecessor else {
        return Ok(Json::Null);
    };
    Ok(obj(vec![
        ("manifest_oid", s(hex(&previous.manifest_oid.0))),
        ("manifest_commit", s(hex(&previous.manifest_commit))),
        ("statement_oid", s(hex(&previous.statement_oid.0))),
        ("statement_commit", s(hex(&previous.statement_commit))),
        ("import_run", s(format!("{:032x}", previous.import_run.0))),
        ("receipt_hash", s(hex(&previous.receipt_hash))),
        ("recorded_at", Json::Int(i128::from(previous.recorded_at.0))),
        (
            "sequence_number",
            Json::Int(i128::from(previous.sequence_number)),
        ),
        ("statement_date", s(previous.statement_date.render())),
        (
            "closing_balance",
            money(previous.closing_balance, manifest.unit, book)?,
        ),
    ]))
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
    let previous_manifest = one_flag(args, "--previous-import", IMPORT_EXAMPLE)?
        .map(|value| crate::document::hex32(value, "--previous-import").map(Oid))
        .transpose()?;
    let capability = ctx.capability(args, &["read", "post", "reconcile"])?;
    admit(&capability, true)?;
    // Current authority precedes response metadata as well as source input.
    // The import kernel checks it again and retains its publication witnesses.
    let mut book = ctx.books.open_admitted(args, |book| {
        book.preflight_intake(&capability, fa::IntakeAction::BankImport)??;
        Ok(())
    })?;
    let max_statement_bytes = fa_registry::evidence_policy::EvidencePolicy::embedded()
        .map_err(|error| Fail::Internal(format!("the embedded evidence policy: {error}")))?
        .max_document_bytes;
    let bytes = crate::intake::read_document_with_limit(&ctx.files, path, max_statement_bytes)?;
    let account = account_vid(book.context().book_id, account_code);
    let recorded = book.import_bank_statement(
        &capability,
        BankImportRequest {
            account,
            format,
            bytes,
            previous_manifest,
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
        ("continuity", s(if manifest.predecessor.is_some() { "verified_predecessor" } else { "unlinked" })),
        ("verified_predecessors", Json::Int(recorded.verified_predecessors as i128)),
        ("predecessor", predecessor_json(manifest, &book)?),
    ], &format!("{} bank statement #{} for {account_code}: {} lines; {} predecessor links verified (the oldest manifest remains explicitly unlinked); manifest {oid}; inspect proposals with fa bank match --import {oid} --grant privileged",
        if recorded.receipt.already_recorded { "already recorded" } else { "imported" },
        manifest.sequence_number, manifest.line_oids.len(), recorded.verified_predecessors));
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
    // Admit current authority before response metadata or time evidence.
    let mut book = ctx.books.open_admitted(args, |book| {
        book.read_scope(capability.holder(), &capability)??;
        Ok(())
    })?;
    let (known_at, _) = known_at_flag(args, &book, &ctx.out)?;
    let report = book.match_bank_statement(
        &capability,
        BankMatchRequest {
            manifest_oid: oid,
            known_at,
            date_window_days,
        },
    )??;
    // Compute ambiguity before greedy consumption, so a losing statement
    // line still exposes its competition for an otherwise eligible cash leg.
    let mut eligible_counts = vec![0_usize; report.lines.len()];
    let mut competing = vec![false; report.lines.len()];
    let window = i32::try_from(report.date_window_days)
        .map_err(|_| Fail::Internal("admitted bank date window exceeds i32".into()))?;
    for candidate in &report.candidates {
        let mut first_line = None;
        for (index, line) in report.lines.iter().enumerate() {
            if pinned_bank_candidate(line, &candidate.candidate, window)
                .map_err(|error| Fail::Internal(format!("bank candidate law: {error}")))?
            {
                eligible_counts[index] += 1;
                if let Some(first) = first_line {
                    competing[first] = true;
                    competing[index] = true;
                } else {
                    first_line = Some(index);
                }
            }
        }
    }
    let ambiguous_count = eligible_counts
        .iter()
        .zip(&competing)
        .filter(|(count, contested)| **count > 1 || **contested)
        .count();
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
        let proposal_digest = hex(&proposal.oid().map_err(|e| Fail::Internal(e.to_string()))?.0);
        let proposer = format!("{:032x}", proposal.principal.0);
        let confirmation_command = if selected.is_some()
            && eligible_counts[index] == 1
            && !competing[index]
        {
            s(format!(
                "fa bank confirm --import {} --line-ordinal {} --proposal-digest {proposal_digest} --source-known-at {} --date-window {} --proposer {proposer} --grant privileged --json",
                hex(&report.manifest_oid.0),
                line.line_ordinal,
                report.known_at.0,
                report.date_window_days,
            ))
        } else {
            Json::Null
        };
        rows.push(obj(vec![
            ("line_ordinal", Json::Int(i128::from(line.line_ordinal))),
            (
                "eligible_candidate_count",
                Json::Int(eligible_counts[index] as i128),
            ),
            ("competing_bank_lines", Json::Bool(competing[index])),
            (
                "ambiguous",
                Json::Bool(eligible_counts[index] > 1 || competing[index]),
            ),
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
            ("proposal_digest", s(proposal_digest)),
            ("proposer", s(proposer)),
            ("confirmation_command", confirmation_command),
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
        (
            "continuity",
            s(if report.manifest.predecessor.is_some() {
                "verified_predecessor"
            } else {
                "unlinked"
            }),
        ),
        (
            "verified_predecessors",
            Json::Int(report.verified_predecessors as i128),
        ),
        ("predecessor", predecessor_json(&report.manifest, &book)?),
        ("line_count", Json::Int(report.lines.len() as i128)),
        ("proposed_count", Json::Int(matched as i128)),
        ("ambiguous_count", Json::Int(ambiguous_count as i128)),
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
        "bank statement for {} at {}: {matched} exact proposals, {ambiguous_count} ambiguous bank lines requiring review, {} unmatched bank lines, {} unmatched book candidates; candidate search: {candidate_window}; outstanding inventory completeness is unestablished; proposals are unconfirmed",
        report.account_code, report.known_at.0, report.lines.len() - matched,
        report.candidates.len() - matched,
    ));
    Ok(())
}

fn confirmation_fields(recorded: &BankMatchRecorded) -> Vec<(&'static str, Json)> {
    let confirmation = &recorded.confirmation;
    vec![
        ("match_vid", s(format!("{:032x}", recorded.match_vid.0))),
        ("match_digest", s(hex(&recorded.match_digest))),
        ("recorded_at", Json::Int(i128::from(recorded.recorded_at.0))),
        ("manifest_oid", s(hex(&confirmation.manifest_oid.0))),
        ("statement_oid", s(hex(&confirmation.statement_oid.0))),
        (
            "line_ordinal",
            Json::Int(i128::from(confirmation.line_ordinal)),
        ),
        (
            "line_document_oid",
            s(hex(&confirmation.line_document_oid.0)),
        ),
        ("bank_line_oid", s(hex(&confirmation.bank_line_oid.0))),
        ("account_ref", s(format!("{:032x}", confirmation.account.0))),
        (
            "entry_ref",
            obj(vec![
                ("vid", s(format!("{:032x}", confirmation.entry_ref.vid.0))),
                ("entry_digest", s(hex(&confirmation.entry_ref.entry_digest))),
            ]),
        ),
        (
            "leg_ordinal",
            Json::Int(i128::from(confirmation.leg_ordinal)),
        ),
        ("proposer", s(format!("{:032x}", confirmation.proposer.0))),
        (
            "confirmed_by",
            s(format!("{:032x}", confirmation.confirmed_by.0)),
        ),
        (
            "confirming_profile",
            s(confirmation.confirming_profile.name()),
        ),
        (
            "capability_commitment",
            s(hex(&confirmation.capability_commitment)),
        ),
        (
            "source_known_at",
            Json::Int(i128::from(confirmation.source_known_at.0)),
        ),
        (
            "date_window",
            Json::Int(i128::from(confirmation.date_window_days)),
        ),
        ("proposal_digest", s(hex(&confirmation.proposal_digest))),
        ("method", s("pinned_exact_one_to_one")),
    ]
}

fn confirm_statement(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "bank confirm takes its exact selection through flags",
            CONFIRM_EXAMPLE,
        ));
    }
    let manifest_oid = Oid(crate::document::hex32(
        required(args, "--import", CONFIRM_EXAMPLE)?,
        "--import",
    )?);
    let proposal_digest = crate::document::hex32(
        required(args, "--proposal-digest", CONFIRM_EXAMPLE)?,
        "--proposal-digest",
    )?;
    let line_ordinal = required(args, "--line-ordinal", CONFIRM_EXAMPLE)?
        .parse::<u32>()
        .map_err(|_| {
            usage(
                "--line-ordinal must be the proposal's unsigned line ordinal",
                CONFIRM_EXAMPLE,
            )
        })?;
    let source_known_at = required(args, "--source-known-at", CONFIRM_EXAMPLE)?
        .parse::<u64>()
        .map(fgdb_types::CommitSeq)
        .map_err(|_| usage("--source-known-at must be the proposal's numeric sequence, never HEAD or an instant", CONFIRM_EXAMPLE))?;
    let date_window_days = one_flag(args, "--date-window", CONFIRM_EXAMPLE)?
        .map_or(Ok(3_u32), |value| value.parse::<u32>())
        .map_err(|_| {
            usage(
                "--date-window must be the proposal's nonnegative integer day window",
                CONFIRM_EXAMPLE,
            )
        })?;
    let proposer_text = required(args, "--proposer", CONFIRM_EXAMPLE)?;
    if proposer_text.len() != 32 || !proposer_text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(usage(
            "--proposer must be the exact 32-hex principal in the proposal",
            CONFIRM_EXAMPLE,
        ));
    }
    let proposer = crate::cli::parse_vid(proposer_text, "--proposer")?;
    let capability = ctx.capability(args, &["read", "reconcile"])?;
    admit(&capability, false)?;
    let mut book = ctx.books.open_admitted(args, |book| {
        book.read_scope(capability.holder(), &capability)??;
        Ok(())
    })?;
    let recorded = book.confirm_bank_statement_match(
        &capability,
        BankConfirmationRequest {
            manifest_oid,
            line_ordinal,
            proposal_digest,
            source_known_at,
            date_window_days,
            proposer,
        },
    )??;
    let mut fields = confirmation_fields(&recorded);
    fields.push(("already_recorded", Json::Bool(recorded.already_recorded)));
    ctx.out.at_book(&book)?;
    ctx.out.event("bank_match_confirmed", fields, &format!(
        "{} bank line {} as match {:032x}; cash entry {:032x} leg {}, confirmed by {:032x} at {}; monetary entries are unchanged",
        if recorded.already_recorded { "already confirmed" } else { "confirmed" },
        recorded.confirmation.line_ordinal, recorded.match_vid.0,
        recorded.confirmation.entry_ref.vid.0, recorded.confirmation.leg_ordinal,
        recorded.confirmation.confirmed_by.0, recorded.recorded_at.0,
    ));
    Ok(())
}

fn confirmation_status(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "bank status selects one retained manifest through --import",
            STATUS_EXAMPLE,
        ));
    }
    let manifest_oid = Oid(crate::document::hex32(
        required(args, "--import", STATUS_EXAMPLE)?,
        "--import",
    )?);
    let capability = ctx.capability(args, &["read", "reconcile"])?;
    admit(&capability, false)?;
    let mut book = ctx.books.open_admitted(args, |book| {
        book.read_scope(capability.holder(), &capability)??;
        Ok(())
    })?;
    let (known_at, _) = known_at_flag(args, &book, &ctx.out)?;
    let status = book.bank_confirmation_status(
        &capability,
        BankStatusRequest {
            manifest_oid,
            known_at,
        },
    )??;
    let line_count = status.manifest.line_oids.len();
    let confirmed = status.confirmations.len();
    let fields = vec![
        ("manifest_oid", s(hex(&status.manifest_oid.0))),
        ("statement_oid", s(hex(&status.manifest.statement_oid.0))),
        (
            "account_ref",
            s(format!("{:032x}", status.manifest.account.0)),
        ),
        ("known_at", Json::Int(i128::from(status.known_at.0))),
        ("line_count", Json::Int(line_count as i128)),
        ("confirmed_lines", Json::Int(confirmed as i128)),
        (
            "remaining_lines",
            Json::Int((line_count - confirmed) as i128),
        ),
        ("scope", s("recorded_confirmations")),
        ("reconciled_through", Json::Null),
        (
            "confirmations",
            Json::Arr(
                status
                    .confirmations
                    .iter()
                    .map(|recorded| obj(confirmation_fields(recorded)))
                    .collect(),
            ),
        ),
    ];
    let max_inline = crate::verbs::registry()
        .map_err(|error| Fail::Internal(error.into()))?
        .daemon
        .max_frame_bytes
        .saturating_sub(128 * 1024);
    if obj(fields.clone()).render().len() > max_inline {
        return Err(usage(
            "the complete recorded confirmation inventory exceeds the inline transport bound; no lines were omitted",
            "select a smaller retained statement",
        ));
    }
    ctx.out.at_book(&book)?;
    ctx.out.known_at(status.known_at);
    ctx.out.event("bank_confirmation_status", fields, &format!(
        "{confirmed} of {line_count} bank lines have recorded confirmations at {}; {} remain; a closing-balance attestation and reconciliation lock are not established by these facts",
        status.known_at.0, line_count - confirmed,
    ));
    Ok(())
}
