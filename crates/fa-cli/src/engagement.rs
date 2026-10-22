//! `fa engagement open|list|show` and `fa adjustment propose|book|pass`
//! (plan §0.4 decision 3, §11.12; bead fa-zgn): an audit engagement's
//! mechanics in the journal.
//!
//! An engagement states its kind, scope periods and materiality parameters
//! (stated by the auditor, never judged here). A proposed adjustment is a
//! draft correcting entry that never posts; it is then booked (naming the
//! committed entry that makes the correction) or passed (left uncorrected,
//! with a registered reason), once. Writes need `produce`, which the Auditor
//! profile holds; an Agent writes none of them.

use std::collections::BTreeMap;

use fa_journal::refusal::{Refusal, code, exit};
use fa_journal::{
    AdjustmentDecision, EngagementKind, EngagementProfile, EngagementView, Materiality,
    ProposalLeg, ProposalView, Uncorrected,
};
use fa_model::account_vid;
use fa_money::{Amount, Side};
use fa_time::DateDay;
use fgdb_types::VId;

use crate::args::Args;
use crate::cli::{Ctx, Fail, Out, control_date, hex, registered_unit_code, render_amount, usage};
use crate::json::{Json, obj, s};

const OPEN_EXAMPLE: &str = "fa engagement open <id> --kind audit|review|examination|investigation|litigation --period <code>... --overall \"<amount> <UNIT>\" --performance \"<amount> <UNIT>\" --clearly-trivial \"<amount> <UNIT>\" [--report-release YYYY-MM-DD] --json";
const PROPOSE_EXAMPLE: &str = "fa adjustment propose --engagement <id> --intent <entry.json|-> --json, where entry.json is {\"effective_date\": \"YYYY-MM-DD\", \"description\": \"...\", \"legs\": [{\"side\": \"debit\", \"account\": \"6000\", \"amount\": \"10.00 USD\"}, {\"side\": \"credit\", \"account\": \"2100\", \"amount\": \"10.00 USD\"}]}";
const SUD_EXAMPLE: &str = "fa engagement sud <id> [--definition us_gaap_small_company_income_statement] [--definition us_gaap_small_company_balance_sheet] --json";
const DECIDE_EXAMPLE: &str = "fa adjustment book --engagement <id> --proposal <n> --entry E:<vid> --json, or fa adjustment pass --engagement <id> --proposal <n> --reason ClearlyTrivial|BelowPerformanceMateriality|ManagementDeclined|Other --json";

pub(crate) fn engagement_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("open") => open(ctx, args),
        Some("list") => list(ctx, args),
        Some("show") => show(ctx, args),
        Some("sud") => sud(ctx, args),
        Some("file") => file(ctx, args),
        Some("complete") => complete(ctx, args),
        _ => Err(usage(
            "engagement has the subcommands open, list, show, sud, file and complete",
            OPEN_EXAMPLE,
        )),
    }
}

const FILE_EXAMPLE: &str = "fa engagement file <id> --document <oid> [--key K] --json";
const COMPLETE_EXAMPLE: &str = "fa engagement complete <id> --completion-date YYYY-MM-DD [--report-release YYYY-MM-DD] [--key K] --json";

/// The one engagement id a file or complete takes.
fn engagement_arg(args: &Args, sub: &str, example: &str) -> Result<String, Fail> {
    match args.positional.as_slice() {
        [_, _, id] => Ok(id.clone()),
        _ => Err(usage(
            format!("engagement {sub} takes exactly one engagement id"),
            example,
        )),
    }
}

/// `fa engagement file <id> --document <oid>`: put a document the book
/// holds in the engagement's workpaper index, once. After the
/// documentation completion it is an addition after completion, and the
/// event says so (AS 1215.16).
fn file(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let engagement = engagement_arg(args, "file", FILE_EXAMPLE)?;
    let text = require_one(args, "--document", FILE_EXAMPLE)?;
    let document = crate::document::hex32(text, "--document").map(fa_model::Oid)?;
    let key = one_flag(args, "--key", FILE_EXAMPLE)?
        .unwrap_or("file")
        .to_string();
    let capability = ctx.capability(args, &["produce"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        admit_writer(book, &capability, "filing an engagement workpaper")
    })?;
    let date = control_date(args, &book)?;
    let filed = book.file_workpaper(capability, &engagement, document, date, key.as_bytes())??;
    ctx.out.at_book(&book)?;
    let human = format!(
        "engagement {engagement}: workpaper {} {}{}",
        hex(&document.0),
        if filed.already_recorded {
            "already filed"
        } else {
            "filed"
        },
        if filed.added_after_completion {
            ", added after documentation completion"
        } else {
            ""
        }
    );
    ctx.out.event(
        "engagement_workpaper_filed",
        vec![
            ("engagement", s(&engagement)),
            ("document", s(hex(&document.0))),
            ("control_entry", vid_hex(filed.control_entry)),
            ("recorded_at", seq(filed.recorded_at)),
            (
                "added_after_completion",
                Json::Bool(filed.added_after_completion),
            ),
            ("already_recorded", Json::Bool(filed.already_recorded)),
        ],
        &human,
    );
    Ok(())
}

/// `fa engagement complete <id> --completion-date D`: journal the
/// engagement's documentation completion, once, within 45 days after the
/// report release date (AS 1215.15).
fn complete(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let engagement = engagement_arg(args, "complete", COMPLETE_EXAMPLE)?;
    let day = |flag: &str, text: &str| {
        DateDay::parse(text).map_err(|e| usage(format!("{flag} `{text}`: {e}"), COMPLETE_EXAMPLE))
    };
    let completion_day = day(
        "--completion-date",
        require_one(args, "--completion-date", COMPLETE_EXAMPLE)?,
    )?;
    let report_release = one_flag(args, "--report-release", COMPLETE_EXAMPLE)?
        .map(|text| day("--report-release", text))
        .transpose()?;
    let key = one_flag(args, "--key", COMPLETE_EXAMPLE)?
        .unwrap_or("complete")
        .to_string();
    let capability = ctx.capability(args, &["produce"])?;
    let completed_by = capability.holder();
    let mut book = ctx.books.open_admitted(args, |book| {
        admit_writer(
            book,
            &capability,
            "completing an engagement's documentation",
        )
    })?;
    let date = control_date(args, &book)?;
    let completed = book.complete_documentation(
        capability,
        &engagement,
        report_release,
        completion_day,
        date,
        key.as_bytes(),
    )??;
    ctx.out.at_book(&book)?;
    let c = completed.completion;
    let human = format!(
        "engagement {engagement}: documentation complete on {} ({} days after the report release on {}){}",
        c.completion_day.render(),
        c.completion_day.0 - c.report_release_day.0,
        c.report_release_day.render(),
        if completed.already_recorded {
            ", already recorded"
        } else {
            ""
        }
    );
    ctx.out.event(
        "engagement_documentation_completed",
        vec![
            ("engagement", s(&engagement)),
            (
                "documentation",
                completion_json(
                    &c,
                    completed.control_entry,
                    completed.recorded_at,
                    completed_by,
                ),
            ),
            ("control_entry", vid_hex(completed.control_entry)),
            ("recorded_at", seq(completed.recorded_at)),
            ("already_recorded", Json::Bool(completed.already_recorded)),
        ],
        &human,
    );
    Ok(())
}

/// A journaled documentation completion: its dates, and its Complete record,
/// sequence and principal (shape `documentation_completion`).
fn completion_json(
    c: &fa_journal::DocumentationCompletion,
    record: VId,
    recorded_at: fgdb_types::CommitSeq,
    completed_by: VId,
) -> Json {
    obj(vec![
        ("report_release", s(c.report_release_day.render())),
        ("completion_date", s(c.completion_day.render())),
        ("record", vid_hex(record)),
        ("recorded_at", seq(recorded_at)),
        ("completed_by", vid_hex(completed_by)),
    ])
}

pub(crate) fn adjustment_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("propose") => propose(ctx, args),
        Some("book") => decide(ctx, args, true),
        Some("pass") => decide(ctx, args, false),
        _ => Err(usage(
            "adjustment has the subcommands propose, book and pass",
            PROPOSE_EXAMPLE,
        )),
    }
}

fn one_flag<'a>(args: &'a Args, flag: &str, example: &str) -> Result<Option<&'a str>, Fail> {
    if args.flag_all(flag).len() > 1 {
        return Err(usage(format!("{flag} is given once"), example));
    }
    Ok(args.flag(flag))
}

fn require_one<'a>(args: &'a Args, flag: &str, example: &str) -> Result<&'a str, Fail> {
    one_flag(args, flag, example)?.ok_or_else(|| usage(format!("{flag} is required"), example))
}

fn unknown(engagement: &str) -> Fail {
    Refusal::new(
        code::ENGAGEMENT_UNKNOWN,
        exit::REFUSAL,
        format!("this book has no engagement `{engagement}`"),
        "plan §11.12 (an Engagement is the unit an audit's mechanics attach to)",
        "list the book's engagements with `fa engagement list --json`",
    )
    .into()
}

fn vid_hex(v: VId) -> Json {
    s(format!("{:032x}", v.0))
}

fn seq(v: fgdb_types::CommitSeq) -> Json {
    Json::Int(i128::from(v.0))
}

/// Writes are the auditor's work product: current authority holding
/// `produce`, judged before anything else is read (doctrine 8).
fn admit_writer(book: &fa::Book, cap: &fa::Capability, purpose: &str) -> Result<(), Fail> {
    book.admit_current(cap)??;
    fa_policy::require(cap, fa_policy::Op::Produce, purpose)
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))
}

fn summary_json(view: &EngagementView, units: &fa_money::UnitRegistry) -> Result<Json, Fail> {
    let p = &view.profile;
    let amount = |m: i128| render_amount(Amount::new(p.unit, m), units).map(s);
    let count = |state: fa_journal::AdjustmentState| {
        Json::Int(view.proposals.iter().filter(|x| x.state == state).count() as i128)
    };
    Ok(obj(vec![
        ("engagement", s(&p.engagement)),
        ("vid", vid_hex(view.vid)),
        ("kind", s(p.kind.name())),
        ("firm_principal", vid_hex(p.firm_principal)),
        (
            "scope_periods",
            Json::Arr(p.scope_periods.iter().map(s).collect()),
        ),
        ("unit", s(registered_unit_code(p.unit, units)?)),
        ("overall", amount(p.materiality.overall)?),
        ("performance", amount(p.materiality.performance)?),
        ("clearly_trivial", amount(p.materiality.clearly_trivial)?),
        (
            "report_release",
            p.report_release_day.map_or(Json::Null, |d| s(d.render())),
        ),
        ("state", s(view.state.name())),
        ("opened_at", seq(view.opened_at)),
        ("opened_by", vid_hex(view.opened_by)),
        ("next_proposal", Json::Int(i128::from(view.next_proposal))),
        ("proposed", count(fa_journal::AdjustmentState::Proposed)),
        ("booked", count(fa_journal::AdjustmentState::Booked)),
        ("passed", count(fa_journal::AdjustmentState::Passed)),
    ]))
}

fn reason_name(code: u16) -> Result<String, Fail> {
    let reasons = fa_registry::reason_codes::ReasonCodes::embedded()
        .map_err(|e| Fail::Internal(format!("reason registry: {e}")))?;
    reasons
        .get("adjustment_pass", code)
        .map(|r| r.name.clone())
        .ok_or_else(|| Fail::Internal(format!("passed with unregistered reason {code}")))
}

fn proposal_json(
    p: &ProposalView,
    codes: &BTreeMap<u128, String>,
    units: &fa_money::UnitRegistry,
) -> Result<Json, Fail> {
    let legs = p
        .proposal
        .legs
        .iter()
        .map(|leg| {
            Ok(obj(vec![
                (
                    "side",
                    s(if leg.side == Side::Debit {
                        "debit"
                    } else {
                        "credit"
                    }),
                ),
                ("account", codes.get(&leg.account.0).map_or(Json::Null, s)),
                ("account_vid", vid_hex(leg.account)),
                ("amount", s(render_amount(leg.amount, units)?)),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let decision = match &p.decision {
        None => Json::Null,
        Some(d) => {
            let (kind, entry, reason) = match d.decision {
                AdjustmentDecision::Book { entry } => ("book", vid_hex(entry), Json::Null),
                AdjustmentDecision::Pass { reason_code } => {
                    ("pass", Json::Null, s(reason_name(reason_code)?))
                }
            };
            obj(vec![
                ("kind", s(kind)),
                ("entry", entry),
                ("reason", reason),
                ("record", vid_hex(d.record)),
                ("recorded_at", seq(d.recorded_at)),
                ("decided_by", vid_hex(d.decided_by)),
                ("superseded_by", d.superseded_by.map_or(Json::Null, vid_hex)),
                (
                    "added_after_completion",
                    Json::Bool(d.added_after_completion),
                ),
            ])
        }
    };
    Ok(obj(vec![
        ("engagement", s(&p.proposal.engagement)),
        ("number", Json::Int(i128::from(p.proposal.ordinal))),
        ("vid", vid_hex(p.vid)),
        ("effective_date", s(p.proposal.effective_date.render())),
        ("legs", Json::Arr(legs)),
        ("record", vid_hex(p.record)),
        ("proposed_at", seq(p.proposed_at)),
        ("proposed_by", vid_hex(p.proposed_by)),
        ("state", s(p.state.name())),
        ("decision", decision),
        (
            "added_after_completion",
            Json::Bool(p.added_after_completion),
        ),
    ]))
}

fn account_codes(book: &fa::Book) -> Result<BTreeMap<u128, String>, Fail> {
    Ok(book
        .accounts()?
        .into_iter()
        .map(|row| (row.vid.0, row.code))
        .collect())
}

fn parse_amount(text: &str, flag: &str, units: &fa_money::UnitRegistry) -> Result<Amount, Fail> {
    Amount::parse(text, units).map_err(|e| {
        usage(
            format!("{flag} `{text}`: {e}"),
            format!("{flag} \"50000.00 USD\" (in the book's base unit)"),
        )
    })
}

fn open(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let engagement = match args.positional.as_slice() {
        [_, _, id] => id.clone(),
        _ => {
            return Err(usage(
                "engagement open takes exactly one engagement id",
                OPEN_EXAMPLE,
            ));
        }
    };
    let kind_text = require_one(args, "--kind", OPEN_EXAMPLE)?;
    let kind = EngagementKind::from_name(kind_text).ok_or_else(|| {
        usage(
            format!("--kind `{kind_text}` is not an engagement kind"),
            "--kind audit|review|examination|investigation|litigation",
        )
    })?;
    let mut periods: Vec<String> = args
        .flag_all("--period")
        .into_iter()
        .flat_map(|codes| codes.split(','))
        .map(|code| code.trim().to_string())
        .collect();
    if periods.is_empty() {
        return Err(usage(
            "an engagement names its scope periods with --period",
            OPEN_EXAMPLE,
        ));
    }
    periods.sort();
    if periods.windows(2).any(|w| w[0] == w[1]) {
        return Err(usage("a scope period is named twice", OPEN_EXAMPLE));
    }
    let overall = require_one(args, "--overall", OPEN_EXAMPLE)?;
    let performance = require_one(args, "--performance", OPEN_EXAMPLE)?;
    let clearly_trivial = require_one(args, "--clearly-trivial", OPEN_EXAMPLE)?;
    let report_release = one_flag(args, "--report-release", OPEN_EXAMPLE)?
        .map(|text| {
            DateDay::parse(text).map_err(|e| {
                usage(
                    format!("--report-release `{text}`: {e}"),
                    "--report-release YYYY-MM-DD",
                )
            })
        })
        .transpose()?;
    let key = one_flag(args, "--key", OPEN_EXAMPLE)?
        .unwrap_or("open")
        .to_string();
    let capability = ctx.capability(args, &["produce"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        admit_writer(book, &capability, "opening an engagement")
    })?;
    let units = book.context().units.clone();
    let parsed = [
        ("--overall", parse_amount(overall, "--overall", &units)?),
        (
            "--performance",
            parse_amount(performance, "--performance", &units)?,
        ),
        (
            "--clearly-trivial",
            parse_amount(clearly_trivial, "--clearly-trivial", &units)?,
        ),
    ];
    let unit = parsed[0].1.unit;
    if let Some((flag, _)) = parsed.iter().find(|(_, a)| a.unit != unit) {
        return Err(usage(
            format!("{flag} is in another unit than --overall"),
            "state every materiality parameter in the book's base unit",
        ));
    }
    let commitment = capability
        .commitment()
        .map_err(|e| Fail::Internal(format!("capability commitment: {e:?}")))?;
    let date = control_date(args, &book)?;
    let profile = EngagementProfile {
        book_id: book.context().book_id,
        engagement: engagement.clone(),
        kind,
        firm_principal: capability.holder(),
        scope_periods: periods,
        unit,
        materiality: Materiality {
            overall: parsed[0].1.mantissa,
            performance: parsed[1].1.mantissa,
            clearly_trivial: parsed[2].1.mantissa,
        },
        report_release_day: report_release,
        capability_commitment: commitment,
    };
    let opened = book.open_engagement(capability, profile, date, key.as_bytes())??;
    let view = book
        .engagement(&engagement)?
        .ok_or_else(|| unknown(&engagement))?;
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "engagement_opened",
        vec![
            ("engagement", summary_json(&view, &units)?),
            ("control_entry", vid_hex(opened.control_entry)),
            ("recorded_at", seq(opened.recorded_at)),
            ("already_recorded", Json::Bool(opened.already_recorded)),
        ],
        &format!(
            "engagement {engagement} ({}) {} at sequence {}",
            view.profile.kind.name(),
            if opened.already_recorded {
                "was already open"
            } else {
                "opened"
            },
            opened.recorded_at.0
        ),
    );
    Ok(())
}

fn list(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "engagement list takes no argument",
            "fa engagement list --json",
        ));
    }
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let views = book.engagements()?;
    let units = book.context().units.clone();
    ctx.out.at_book(&book)?;
    let human = if views.is_empty() {
        "no engagements in this book".to_string()
    } else {
        views
            .iter()
            .map(|v| {
                format!(
                    "{} {} {} proposal(s)",
                    v.profile.engagement,
                    v.profile.kind.name(),
                    v.proposals.len()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let rows = views
        .iter()
        .map(|v| summary_json(v, &units))
        .collect::<Result<Vec<_>, Fail>>()?;
    ctx.out.event(
        "engagements",
        vec![("engagements", Json::Arr(rows))],
        &human,
    );
    Ok(())
}

fn show(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let engagement = match args.positional.as_slice() {
        [_, _, id] => id.clone(),
        _ => {
            return Err(usage(
                "engagement show takes exactly one engagement id",
                "fa engagement show <id> --json",
            ));
        }
    };
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let view = book
        .engagement(&engagement)?
        .ok_or_else(|| unknown(&engagement))?;
    let units = book.context().units.clone();
    let codes = account_codes(&book)?;
    ctx.out.at_book(&book)?;
    let mut human = vec![format!(
        "engagement {engagement} ({}), scope {}, {} proposal(s)",
        view.profile.kind.name(),
        view.profile.scope_periods.join(","),
        view.proposals.len()
    )];
    for p in &view.proposals {
        human.push(format!(
            "  #{} {} {}",
            p.proposal.ordinal,
            p.proposal.effective_date.render(),
            p.state.name()
        ));
    }
    for w in &view.workpapers {
        human.push(format!(
            "  workpaper {}{}",
            hex(&w.document.0),
            if w.added_after_completion {
                " (added after documentation completion)"
            } else {
                ""
            }
        ));
    }
    if let Some(c) = &view.documentation {
        human.push(format!(
            "  documentation complete on {} (report released {})",
            c.completion.completion_day.render(),
            c.completion.report_release_day.render()
        ));
    }
    let proposals = view
        .proposals
        .iter()
        .map(|p| proposal_json(p, &codes, &units))
        .collect::<Result<Vec<_>, Fail>>()?;
    let workpapers = view
        .workpapers
        .iter()
        .map(|w| {
            let confirmation = match &w.confirmation {
                None => Json::Null,
                Some(c) => obj(vec![
                    ("attestation", vid_hex(c.attestation)),
                    ("by_party", vid_hex(c.by_party)),
                    ("balance", s(render_amount(c.balance, &units)?)),
                    ("as_of", s(c.as_of.render())),
                    ("attested_by", vid_hex(c.attested_by)),
                    ("received_by", c.received_by.map_or(Json::Null, vid_hex)),
                    ("audit_grade", Json::Bool(c.audit_grade)),
                ]),
            };
            let representation = w.representation.as_ref().map_or(Json::Null, |r| {
                obj(vec![
                    ("attestation", vid_hex(r.attestation)),
                    ("claims", Json::Int(r.claims as i128)),
                    ("as_of", s(r.as_of.render())),
                    ("attested_by", vid_hex(r.attested_by)),
                ])
            });
            Ok(obj(vec![
                ("document", s(hex(&w.document.0))),
                ("record", vid_hex(w.record)),
                ("filed_at", seq(w.filed_at)),
                ("filed_by", vid_hex(w.filed_by)),
                (
                    "added_after_completion",
                    Json::Bool(w.added_after_completion),
                ),
                ("confirmation", confirmation),
                ("representation", representation),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let documentation = view.documentation.as_ref().map_or(Json::Null, |c| {
        completion_json(&c.completion, c.record, c.recorded_at, c.completed_by)
    });
    ctx.out.event(
        "engagement_detail",
        vec![
            ("engagement", summary_json(&view, &units)?),
            ("proposals", Json::Arr(proposals)),
            ("workpapers", Json::Arr(workpapers)),
            ("documentation", documentation),
        ],
        &human.join("\n"),
    );
    Ok(())
}

fn effect_json(
    effect: fa_journal::StatementEffect,
    unit: fa_money::UnitId,
    units: &fa_money::UnitRegistry,
) -> Result<Json, Fail> {
    let amount = |m: i128| render_amount(Amount::new(unit, m), units).map(s);
    Ok(obj(vec![
        ("income", amount(effect.income)?),
        ("assets", amount(effect.assets)?),
        ("liabilities", amount(effect.liabilities)?),
        ("equity", amount(effect.equity)?),
    ]))
}

/// One definition's lines of the summary, each under its own sign.
fn uncorrected_statement_json(
    statement: &fa::UncorrectedStatement,
    unit: fa_money::UnitId,
    units: &fa_money::UnitRegistry,
) -> Result<Json, Fail> {
    let lines = statement
        .lines
        .iter()
        .map(|line| {
            Ok(obj(vec![
                ("code", s(&line.code)),
                ("label", s(&line.label)),
                (
                    "amount",
                    s(render_amount(Amount::new(unit, line.amount), units)?),
                ),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    Ok(obj(vec![
        ("definition", s(&statement.definition)),
        ("title", s(&statement.title)),
        ("lines", Json::Arr(lines)),
    ]))
}

/// `fa engagement sud <id>`: the summary of uncorrected misstatements (plan
/// §11.12, `audit.sud`), every passed proposal's effect had it been booked,
/// against the engagement's stated parameters. The comparisons are
/// mechanical; the materiality judgment is the auditor's.
fn sud(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let engagement = match args.positional.as_slice() {
        [_, _, id] => id.clone(),
        _ => {
            return Err(usage(
                "engagement sud takes exactly one engagement id",
                SUD_EXAMPLE,
            ));
        }
    };
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let view = book
        .engagement(&engagement)?
        .ok_or_else(|| unknown(&engagement))?;
    let summary = book
        .uncorrected_misstatements(&engagement)?
        .ok_or_else(|| unknown(&engagement))?;
    // Each --definition names the income statement (rollover) or balance
    // sheet (iron curtain) whose lines the summary is attributed to; the
    // registered built-ins are the default.
    let mut income_statement = None;
    let mut balance_sheet = None;
    for name in args.flag_all("--definition") {
        let slot = match fa::statement_definition_kind(name) {
            Some(fa::StatementKind::IncomeStatement) => &mut income_statement,
            Some(fa::StatementKind::BalanceSheet) => &mut balance_sheet,
            None => {
                return Err(usage(
                    format!(
                        "unknown statement definition `{name}`; one of {}",
                        fa::statements::LINTABLE_DEFINITIONS.join(", ")
                    ),
                    SUD_EXAMPLE,
                ));
            }
        };
        if slot.replace(name).is_some() {
            return Err(usage(
                format!("--definition names a second definition of the kind `{name}` is"),
                SUD_EXAMPLE,
            ));
        }
    }
    let (rollover_lines, iron_curtain_lines) = book
        .uncorrected_by_line(
            &engagement,
            income_statement.unwrap_or("income-statement"),
            balance_sheet.unwrap_or("balance-sheet"),
        )??
        .ok_or_else(|| unknown(&engagement))?;
    let units = book.context().units.clone();
    let items = summary
        .items
        .iter()
        .map(|item| {
            let (reason, booked_entry, superseded_by) = match item.basis {
                Uncorrected::Passed { reason_code } => {
                    (s(reason_name(reason_code)?), Json::Null, Json::Null)
                }
                Uncorrected::Superseded { entry, by } => (Json::Null, vid_hex(entry), vid_hex(by)),
            };
            Ok(obj(vec![
                ("number", Json::Int(i128::from(item.ordinal))),
                ("effective_date", s(item.effective_date.render())),
                ("reason", reason),
                ("booked_entry", booked_entry),
                ("superseded_by", superseded_by),
                ("effect", effect_json(item.effect, summary.unit, &units)?),
                ("clearly_trivial", Json::Bool(item.clearly_trivial)),
                (
                    "other_units",
                    Json::Arr(
                        item.other_units
                            .iter()
                            .map(|u| registered_unit_code(*u, &units).map(s))
                            .collect::<Result<Vec<_>, Fail>>()?,
                    ),
                ),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let out_of_period = summary
        .out_of_period
        .iter()
        .map(|item| {
            Ok(obj(vec![
                ("entry", vid_hex(item.entry)),
                ("effective_date", s(item.effective_date.render())),
                ("relates_to", s(item.relates_to.code.as_str())),
                ("effect", effect_json(item.effect, summary.unit, &units)?),
                ("clearly_trivial", Json::Bool(item.clearly_trivial)),
                (
                    "other_units",
                    Json::Arr(
                        item.other_units
                            .iter()
                            .map(|u| registered_unit_code(*u, &units).map(s))
                            .collect::<Result<Vec<_>, Fail>>()?,
                    ),
                ),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let rollover = render_amount(Amount::new(summary.unit, summary.rollover_income), &units)?;
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "engagement_sud",
        vec![
            ("engagement", summary_json(&view, &units)?),
            ("unit", s(registered_unit_code(summary.unit, &units)?)),
            ("items", Json::Arr(items)),
            ("out_of_period", Json::Arr(out_of_period)),
            ("rollover_income", s(rollover.as_str())),
            (
                "iron_curtain",
                effect_json(summary.iron_curtain, summary.unit, &units)?,
            ),
            ("prior_period_carry_forward", Json::Bool(false)),
            (
                "exceeds_performance",
                Json::Bool(summary.exceeds_performance),
            ),
            ("exceeds_overall", Json::Bool(summary.exceeds_overall)),
            (
                "rollover_lines",
                uncorrected_statement_json(&rollover_lines, summary.unit, &units)?,
            ),
            (
                "iron_curtain_lines",
                uncorrected_statement_json(&iron_curtain_lines, summary.unit, &units)?,
            ),
        ],
        &format!(
            "engagement {engagement}: {} uncorrected misstatement(s), {} out-of-period correction(s); rollover income effect {rollover}; {} performance materiality, {} overall (mechanical comparisons; materiality is the auditor's judgment)",
            summary.items.len(),
            summary.out_of_period.len(),
            if summary.exceeds_performance {
                "exceeds"
            } else {
                "within"
            },
            if summary.exceeds_overall {
                "exceeds"
            } else {
                "within"
            },
        ),
    );
    Ok(())
}

/// The draft entry a proposal journals, read from `--intent`: exactly
/// `effective_date`, `description` and `legs` (each `side`, `account` code
/// and `amount`), every other field refused.
fn parse_intent(text: &str, book: &fa::Book) -> Result<(DateDay, String, Vec<ProposalLeg>), Fail> {
    let bad = |what: String| usage(what, PROPOSE_EXAMPLE);
    let doc = crate::json::parse(text).map_err(|e| bad(format!("invalid --intent JSON: {e}")))?;
    let Json::Obj(fields) = &doc else {
        return Err(bad("--intent is one JSON object".into()));
    };
    for (key, _) in fields {
        if !["effective_date", "description", "legs"].contains(&key.as_str()) {
            return Err(bad(format!(
                "--intent field `{key}` is not part of a proposal"
            )));
        }
    }
    let text_field = |key: &str| {
        doc.get(key)
            .and_then(Json::as_str)
            .ok_or_else(|| bad(format!("--intent needs a string `{key}`")))
    };
    let date_text = text_field("effective_date")?;
    let effective_date =
        DateDay::parse(date_text).map_err(|e| bad(format!("effective_date `{date_text}`: {e}")))?;
    let description = text_field("description")?.to_string();
    if description.trim().is_empty() {
        return Err(bad("a proposal's description says what it corrects".into()));
    }
    let rows = doc
        .get("legs")
        .and_then(Json::as_arr)
        .ok_or_else(|| bad("--intent needs a `legs` array".into()))?;
    let book_id = book.context().book_id;
    let units = &book.context().units;
    let mut legs = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        let Json::Obj(leg_fields) = row else {
            return Err(bad(format!("legs[{i}] is not an object")));
        };
        if leg_fields.len() != 3 {
            return Err(bad(format!(
                "legs[{i}] has exactly side, account and amount"
            )));
        }
        let field = |key: &str| {
            row.get(key)
                .and_then(Json::as_str)
                .ok_or_else(|| bad(format!("legs[{i}] needs a string `{key}`")))
        };
        let side = match field("side")? {
            "debit" => Side::Debit,
            "credit" => Side::Credit,
            other => return Err(bad(format!("legs[{i}].side `{other}` is debit or credit"))),
        };
        let account = account_vid(book_id, field("account")?);
        let amount_text = field("amount")?;
        let amount = Amount::parse(amount_text, units)
            .map_err(|e| bad(format!("legs[{i}].amount `{amount_text}`: {e}")))?;
        legs.push(ProposalLeg {
            side,
            account,
            amount,
        });
    }
    Ok((effective_date, description, legs))
}

/// `propose:<hex>` over the proposal's date, description and legs.
fn proposal_key(effective_date: DateDay, description: &str, legs: &[ProposalLeg]) -> String {
    let mut parts: Vec<Vec<u8>> = vec![
        effective_date.0.to_le_bytes().to_vec(),
        description.as_bytes().to_vec(),
    ];
    for leg in legs {
        let mut bytes = vec![u8::from(leg.side == Side::Credit)];
        bytes.extend_from_slice(&leg.account.0.to_le_bytes());
        bytes.extend_from_slice(&leg.amount.unit.0.to_le_bytes());
        bytes.extend_from_slice(&leg.amount.mantissa.to_le_bytes());
        parts.push(bytes);
    }
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let digest = fa_model::domain_digest(b"fa:cli:adjustment-proposal-key:v1", &refs);
    format!("propose:{}", crate::cli::hex(&digest[..16]))
}

fn propose(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "adjustment propose takes no positional argument",
            PROPOSE_EXAMPLE,
        ));
    }
    let engagement = require_one(args, "--engagement", PROPOSE_EXAMPLE)?.to_string();
    let intent = require_one(args, "--intent", PROPOSE_EXAMPLE)?;
    let stated_key = one_flag(args, "--key", PROPOSE_EXAMPLE)?;
    let capability = ctx.capability(args, &["produce"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        admit_writer(book, &capability, "proposing an audit adjustment")
    })?;
    let text = ctx.files.read_text(intent)?;
    let (effective_date, description, legs) = parse_intent(&text, &book)?;
    // The default key is the proposal's content: the identical proposal
    // retries exactly, and two different proposals never collide.
    let key = stated_key.map_or_else(
        || proposal_key(effective_date, &description, &legs),
        str::to_string,
    );
    let date = control_date(args, &book)?;
    let proposed = book.propose_adjustment(
        capability,
        &engagement,
        effective_date,
        legs,
        &description,
        date,
        key.as_bytes(),
    )??;
    emit_proposal(
        &ctx.out,
        &book,
        &engagement,
        proposed.proposal.ordinal,
        "adjustment_proposed",
        proposed.control_entry,
        proposed.recorded_at,
        proposed.already_recorded,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_proposal(
    out: &Out,
    book: &fa::Book,
    engagement: &str,
    ordinal: u32,
    event: &str,
    control_entry: VId,
    recorded_at: fgdb_types::CommitSeq,
    already_recorded: bool,
) -> Result<(), Fail> {
    let view = book
        .engagement(engagement)?
        .ok_or_else(|| unknown(engagement))?;
    let proposal = view
        .proposals
        .iter()
        .find(|p| p.proposal.ordinal == ordinal)
        .ok_or_else(|| Fail::Internal(format!("proposal {ordinal} vanished from its view")))?;
    let units = book.context().units.clone();
    let codes = account_codes(book)?;
    out.at_book(book)?;
    out.event(
        event,
        vec![
            ("proposal", proposal_json(proposal, &codes, &units)?),
            ("control_entry", vid_hex(control_entry)),
            ("recorded_at", seq(recorded_at)),
            ("already_recorded", Json::Bool(already_recorded)),
        ],
        &format!(
            "engagement {engagement} proposal #{ordinal}: {}{} at sequence {}",
            proposal.state.name(),
            if already_recorded {
                " (already recorded)"
            } else {
                ""
            },
            recorded_at.0
        ),
    );
    Ok(())
}

fn decide(ctx: &mut Ctx<'_>, args: &Args, book_it: bool) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "adjustment book|pass take no positional argument",
            DECIDE_EXAMPLE,
        ));
    }
    let engagement = require_one(args, "--engagement", DECIDE_EXAMPLE)?.to_string();
    let ordinal_text = require_one(args, "--proposal", DECIDE_EXAMPLE)?;
    let ordinal = ordinal_text
        .parse::<u32>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            usage(
                format!("--proposal `{ordinal_text}` is not a proposal number"),
                "--proposal <n>   (numbered from 1; fa engagement show <id> lists them)",
            )
        })?;
    let (entry, reason) = (
        one_flag(args, "--entry", DECIDE_EXAMPLE)?,
        one_flag(args, "--reason", DECIDE_EXAMPLE)?,
    );
    let decision = match (book_it, entry, reason) {
        (true, Some(text), None) => {
            let hexed = text.strip_prefix("E:").unwrap_or(text);
            let vid = u128::from_str_radix(hexed, 16)
                .ok()
                .filter(|_| hexed.len() == 32)
                .ok_or_else(|| {
                    usage(
                        format!("--entry `{text}` is not an entry vid"),
                        "--entry E:<32-hex vid>",
                    )
                })?;
            AdjustmentDecision::Book { entry: VId(vid) }
        }
        (false, None, Some(text)) => {
            let reasons = fa_registry::reason_codes::ReasonCodes::embedded()
                .map_err(|e| Fail::Internal(format!("reason registry: {e}")))?;
            let found = text
                .parse::<u16>()
                .ok()
                .and_then(|code| reasons.get("adjustment_pass", code))
                .or_else(|| {
                    reasons
                        .rows
                        .iter()
                        .find(|r| r.scope == "adjustment_pass" && r.name == text)
                });
            let reason = found.ok_or_else(|| {
                usage(
                    format!("--reason `{text}` is not a registered adjustment_pass reason"),
                    format!("--reason {}", reasons.listing("adjustment_pass")),
                )
            })?;
            AdjustmentDecision::Pass {
                reason_code: reason.code,
            }
        }
        (true, _, _) => {
            return Err(usage(
                "adjustment book names the committed entry with --entry, and takes no --reason",
                DECIDE_EXAMPLE,
            ));
        }
        (false, _, _) => {
            return Err(usage(
                "adjustment pass names its reason with --reason, and takes no --entry",
                DECIDE_EXAMPLE,
            ));
        }
    };
    let key = one_flag(args, "--key", DECIDE_EXAMPLE)?
        .unwrap_or(if book_it { "book" } else { "pass" })
        .to_string();
    // Booking reads the entry it names, so it needs read authority over the
    // whole book as well as produce; passing reads nothing it does not own.
    let who = ctx.principal(args);
    let ops: &[&str] = if book_it {
        &["read", "produce"]
    } else {
        &["produce"]
    };
    let capability = ctx.capability(args, ops)?;
    let mut book = ctx.books.open_admitted(args, |book| {
        admit_writer(book, &capability, "deciding an audit adjustment")?;
        if book_it {
            crate::rea::admit_read(book, who, &capability)?;
        }
        Ok(())
    })?;
    let date = control_date(args, &book)?;
    let decided = book.decide_adjustment(
        capability,
        &engagement,
        ordinal,
        decision,
        date,
        key.as_bytes(),
    )??;
    emit_proposal(
        &ctx.out,
        &book,
        &engagement,
        ordinal,
        "adjustment_decided",
        decided.control_entry,
        decided.recorded_at,
        decided.already_recorded,
    )
}
