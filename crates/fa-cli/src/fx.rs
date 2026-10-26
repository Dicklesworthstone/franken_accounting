//! Evidence-backed FX intake, intent valuation, and functional stock/activity.
//!
//! Input rates are exact rational assertions retained as Rate documents. Their
//! source and retrieval metadata do not authenticate a provider or a clock.
//! Monetary proposals always use the ordinary independently verifying kernel.

use std::collections::BTreeSet;

use fa::{Book, FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms};
use fa_journal::{Capability, KernelError};
use fa_model::{EntryClass, EntryPayload, Oid};
use fa_money::{Amount, RoundingLaw, UnitRegistry};
use fa_time::DateDay;

use crate::args::Args;
use crate::cli::{
    Ctx, Fail, Out, hex, known_at_read_flag, parse_json, registered_unit_code, render_amount, usage,
};
use crate::json::{Json, obj, s};
use crate::notary;

const RATE_USAGE: &str = "fa fx rate add --from-json rate.json (or - for stdin); rate_num and rate_den are positive decimal integer strings, base_unit is the book's functional currency, quote_unit is the foreign currency";
const ACTIVITY_USAGE: &str = "fa tb --functional --activity --period FY2026-P03 [--as-known-at HEAD|<seq>|<RFC3339>] [--certify | --certificate-out <new-file>]";
const STOCK_USAGE: &str = "fa tb --functional (--period FY2026-P03 | --as-of YYYY-MM-DD) [--as-known-at HEAD|<seq>|<RFC3339>] [--certify | --certificate-out <new-file>]; add --activity with one --period for period movement";
const INTENT_USAGE: &str = r#""fx":{"law":"SpotClose","rates":["D:<retained Rate document oid>"]}; current SpotClose and PeriodAverage laws require HalfEven. SpotClose as_of equals effective_date; PeriodAverage as_of is the posting period's last included day. Base amounts are calculated from retained evidence"#;

/// Embedded owners acquire the read operation needed to resolve selected Rate
/// bytes. Ctx::capability never adds these implied operations to a bound token.
pub(crate) fn posting_ops(doc: &Json) -> &'static [&'static str] {
    if needs_source_read(doc) {
        &["read", "post"]
    } else {
        &["post"]
    }
}

fn needs_source_read(doc: &Json) -> bool {
    doc.get("fx").is_some()
        || doc.get("external_subledger").is_some()
        || doc
            .get("intents")
            .and_then(Json::as_arr)
            .is_some_and(|members| members.iter().any(needs_source_read))
}

/// An evidence-backed intent observes retained sources. Admit that read before
/// even the book coordinate is stamped, including draft and batch routes.
pub(crate) fn admit_intent_sources(
    book: &Book,
    capability: &Capability,
    doc: &Json,
) -> Result<(), Fail> {
    if needs_source_read(doc) {
        fa_policy::admit_read(capability, capability.holder(), book.context().book_id)
            .and_then(|()| {
                fa_policy::require(
                    capability,
                    fa_policy::Op::Post,
                    "preparing an evidence-backed posting",
                )
            })
            .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        book.read_scope(capability.holder(), capability)??;
    } else {
        book.admit_current(capability)??;
    }
    Ok(())
}

pub(crate) fn fx_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args
        .positional
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["fx", "routes", "set"] => return crate::fx_revaluation::set_routes(ctx, args),
        ["fx", "routes", "show"] => return crate::fx_revaluation::show_routes(ctx, args),
        ["fx", "revalue"] => return crate::fx_revaluation::revalue(ctx, args),
        ["fx", "rate", "add"] => {}
        _ => {
            return Err(usage(
                "FX operations are rate add, routes set, routes show and revalue",
                RATE_USAGE,
            ));
        }
    }
    crate::fx_revaluation::options(args, &["--from-json"], &[])?;
    if args.flag_all("--from-json").len() != 1 {
        return Err(usage("supply exactly one --from-json source", RATE_USAGE));
    }
    let path = args.require("--from-json", "rate.json (or - for stdin)")?;
    let capability = ctx.capability(args, &["post"])?;
    // The authenticated capability determines the upload grade. Preflight
    // precedes opening even the caller's file, including the embedded route.
    let mut book = ctx.books.open_admitted(args, |book| {
        book.preflight_intake(&capability, fa::IntakeAction::Upload)??;
        Ok(())
    })?;
    let source = ctx.files.read_text(path)?;
    let doc = parse_json(path, &source)?;
    let rate = parse_rate(&doc, &book.context().units)?;
    let added = book.upload_fx_rate(&capability, &rate)??;
    let policy = fa_registry::evidence_policy::EvidencePolicy::embedded()
        .map_err(|error| Fail::Internal(format!("embedded evidence policy: {error}")))?;
    let grade = policy
        .grade_by_tag(added.grade)
        .ok_or_else(|| Fail::Internal(format!("unregistered intake grade {}", added.grade)))?;
    let base = registered_unit_code(rate.base_unit, &book.context().units)?;
    let quote = registered_unit_code(rate.quote_unit, &book.context().units)?;
    let oid = hex(&added.oid.0);
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "fx_rate_added",
        vec![
            ("oid", s(&oid)),
            ("doc_commit", s(hex(&added.doc_commit))),
            ("kind", s("Rate")),
            ("grade", s(&grade.name)),
            ("size", Json::Int(i128::from(added.size))),
            ("recorded_at", Json::Int(i128::from(added.recorded_at.0))),
            ("already_recorded", Json::Bool(added.already_recorded)),
            ("base_unit", s(&base)),
            ("quote_unit", s(&quote)),
            ("rate_num", s(rate.rate_num.to_string())),
            ("rate_den", s(rate.rate_den.to_string())),
            ("rounding", s(rate.rounding.name())),
            ("as_of", s(rate.as_of.render())),
            ("retrieved_at_ns", Json::Int(i128::from(rate.retrieved_at_ns))),
            ("purpose", s(rate.purpose.as_str())),
        ],
        &format!(
            "{} Rate D:{oid}: {}/{} {base} per {quote}, {} as of {}, {} ({})\nSource and retrieval metadata are uploaded assertions.",
            if added.already_recorded { "already recorded" } else { "recorded" },
            rate.rate_num,
            rate.rate_den,
            rate.rounding.name(),
            rate.as_of.render(),
            rate.purpose.as_str(),
            grade.name,
        ),
    );
    Ok(())
}

fn strict_object(doc: &Json, fields: &[&str], what: &str, fix: &str) -> Result<(), Fail> {
    let Json::Obj(supplied) = doc else {
        return Err(usage(format!("{what} must be an object"), fix));
    };
    let mut seen = BTreeSet::new();
    for (key, _) in supplied {
        if !fields.contains(&key.as_str()) || !seen.insert(key) {
            return Err(usage(
                format!("{what}: unknown or repeated field `{key}`"),
                fix,
            ));
        }
    }
    Ok(())
}

fn required_string<'a>(doc: &'a Json, name: &str, what: &str, fix: &str) -> Result<&'a str, Fail> {
    doc.get(name)
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| usage(format!("{what}: {name} must be a non-empty string"), fix))
}

fn parse_rate(doc: &Json, units: &UnitRegistry) -> Result<FxRateDocument, Fail> {
    strict_object(
        doc,
        &[
            "base_unit",
            "quote_unit",
            "rate_num",
            "rate_den",
            "rounding",
            "as_of",
            "retrieved_at_ns",
            "purpose",
            "source",
        ],
        "rate",
        RATE_USAGE,
    )?;
    let string = |field| required_string(doc, field, "rate", RATE_USAGE);
    let unit = |field| {
        let code = string(field)?;
        units
            .lookup(code)
            .ok_or_else(|| usage(format!("rate: unknown unit `{code}`"), RATE_USAGE))
    };
    let rational_term = |field| {
        let value = string(field)?;
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(usage(
                format!("rate: {field} must be a positive decimal integer string"),
                RATE_USAGE,
            ));
        }
        value
            .parse::<u128>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| {
                usage(
                    format!("rate: {field} must be from 1 through {}", u128::MAX),
                    RATE_USAGE,
                )
            })
    };
    let rounding = RoundingLaw::from_name(string("rounding")?).ok_or_else(|| {
        usage(
            "rate: unknown rounding law; use its exact registered name such as HalfEven or HalfUp",
            RATE_USAGE,
        )
    })?;
    let as_of = DateDay::parse(string("as_of")?)
        .map_err(|error| usage(format!("rate: as_of: {error}"), RATE_USAGE))?;
    let retrieved_at_ns = match doc.get("retrieved_at_ns") {
        Some(Json::Int(value)) => u64::try_from(*value).ok(),
        _ => None,
    }
    .ok_or_else(|| {
        usage(
            "rate: retrieved_at_ns must be a non-negative u64 integer",
            RATE_USAGE,
        )
    })?;
    let purpose = match string("purpose")? {
        "spot_close" => FxRatePurpose::SpotClose,
        "period_close" => FxRatePurpose::PeriodClose,
        "period_average" => FxRatePurpose::PeriodAverage,
        "settlement" => FxRatePurpose::Settlement,
        _ => {
            return Err(usage(
                "rate: purpose must be spot_close, period_close, period_average, or settlement",
                RATE_USAGE,
            ));
        }
    };
    Ok(FxRateDocument::new(
        FxRateTerms {
            base_unit: unit("base_unit")?,
            quote_unit: unit("quote_unit")?,
            rate_num: rational_term("rate_num")?,
            rate_den: rational_term("rate_den")?,
            rounding,
        },
        as_of,
        retrieved_at_ns,
        purpose,
        string("source")?.to_string(),
    )?)
}

/// Add only source-derived valuation. A reversal retains the target's exact
/// valuation and rate citations; a caller cannot select a replacement rate.
pub(crate) fn value_intent(
    book: &mut Book,
    capability: &Capability,
    doc: &Json,
    proposal: EntryPayload,
) -> Result<EntryPayload, Fail> {
    let Some(fx) = doc.get("fx") else {
        return Ok(proposal);
    };
    if proposal.class == EntryClass::REVERSAL || doc.get("reverses").is_some() {
        return Err(usage(
            "a Reversal retains the target's valuation; do not supply fx",
            INTENT_USAGE,
        ));
    }
    if fx.get("law").and_then(Json::as_str) == Some("SettlementCarryingBasis") {
        return settlement_intent(book, capability, fx, proposal);
    }
    strict_object(fx, &["law", "rates"], "intent.fx", INTENT_USAGE)?;
    let law = match required_string(fx, "law", "intent.fx", INTENT_USAGE)? {
        "SpotClose" => FxLawId::SpotClose,
        "PeriodAverage" => FxLawId::PeriodAverage,
        _ => {
            return Err(usage(
                "intent.fx.law must be SpotClose or PeriodAverage",
                INTENT_USAGE,
            ));
        }
    };
    let rates = fx
        .get("rates")
        .and_then(Json::as_arr)
        .filter(|rates| !rates.is_empty())
        .ok_or_else(|| {
            usage(
                "intent.fx.rates must be a non-empty array of retained Rate document OIDs",
                INTENT_USAGE,
            )
        })?;
    let mut oids = BTreeSet::new();
    for rate in rates {
        let text = rate.as_str().ok_or_else(|| {
            usage(
                "intent.fx.rates entries must be document OID strings",
                INTENT_USAGE,
            )
        })?;
        let oid = Oid(crate::document::hex32(text, "intent.fx.rates")?);
        if !oids.insert(oid) {
            return Err(usage(
                "intent.fx.rates repeats a document OID",
                INTENT_USAGE,
            ));
        }
    }
    Ok(book.value_fx_proposal(
        capability,
        proposal,
        law,
        &oids.into_iter().collect::<Vec<_>>(),
    )??)
}

/// Two declared economic legs are expanded into the explicitly requested FX
/// route. Their cash/native amounts, target, sides and dimensions are checked;
/// the carrying valuation comes exclusively from the journal.
fn settlement_intent(
    book: &mut Book,
    capability: &Capability,
    fx: &Json,
    mut proposal: EntryPayload,
) -> Result<EntryPayload, Fail> {
    const FIX: &str = "supply two legs (functional-currency cash and one fully applied foreign control leg), and fx:{law: SettlementCarryingBasis, rates:[D:oid], conversion_account:<code>, realized_fx_account:<code>}; receipt/payment accept --fx-rate, --conversion and --realized-fx with exactly one --applies <vid>:<leg>=<foreign amount>";
    strict_object(
        fx,
        &["law", "rates", "conversion_account", "realized_fx_account"],
        "intent.fx",
        FIX,
    )?;
    let rates = fx.get("rates").and_then(Json::as_arr).ok_or_else(|| {
        usage(
            "FX settlement requires one retained Settlement Rate document",
            FIX,
        )
    })?;
    let [rate] = rates else {
        return Err(usage(
            "FX settlement requires exactly one Rate document",
            FIX,
        ));
    };
    let rate = rate
        .as_str()
        .ok_or_else(|| usage("Rate must be a D:oid string", FIX))?;
    let rate_document = Oid(crate::document::hex32(rate, "intent.fx.rates")?);
    if proposal.legs.len() != 2 {
        return Err(usage(
            "FX settlement requires exactly two declared source legs",
            FIX,
        ));
    }
    let applying_index = proposal
        .legs
        .iter()
        .position(|leg| !leg.settles.is_empty())
        .ok_or_else(|| {
            usage(
                "FX settlement must name the invoice or bill it applies to",
                FIX,
            )
        })?;
    let applying = proposal.legs[applying_index].clone();
    let cash = proposal.legs[1 - applying_index].clone();
    let [application] = applying.settles.as_slice() else {
        return Err(usage(
            "FX settlement supports one target per applying leg",
            FIX,
        ));
    };
    if !cash.settles.is_empty()
        || application.amount != applying.amount
        || applying.side == cash.side
        || cash.amount.unit != book.spec()?.base_unit
        || applying.amount.unit == cash.amount.unit
    {
        return Err(usage(
            "FX settlement requires opposite cash/control sides, base-currency cash and a fully applied foreign leg",
            FIX,
        ));
    }
    let route = |field| {
        required_string(fx, field, "intent.fx", FIX)
            .map(|code| fa_model::account_vid(book.context().book_id, code))
    };
    let request = fa::FxSettlementRequest {
        target: application.target,
        target_ordinal: application.ordinal,
        amount: applying.amount,
        settlement_amount: cash.amount,
        settlement_account: cash.account_ref,
        conversion_account: route("conversion_account")?,
        realized_fx_account: route("realized_fx_account")?,
        rate_document,
    };
    proposal.legs.clear();
    proposal.unit_totals.clear();
    let prepared = book.prepare_fx_settlement(capability, &request, proposal)??;
    let carrying = prepared.carrying();
    if applying.account_ref != carrying.account
        || applying.side == carrying.side
        || applying.dimension_set != carrying.dimensions
    {
        return Err(usage(
            "the declared applying account, side or dimensions disagree with the retained open item",
            FIX,
        ));
    }
    let mut result = prepared.into_proposal();
    for leg in &mut result.legs {
        if !leg.settles.is_empty() {
            leg.memo = applying.memo.clone();
        }
        if leg.account_ref == cash.account_ref && leg.amount.unit == cash.amount.unit {
            leg.memo = cash.memo.clone();
            leg.dimension_set = cash.dimension_set.clone();
        }
    }
    Ok(result)
}

pub(crate) fn functional_tb(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if !args.switch("--activity") {
        return functional_stock(ctx, args);
    }
    if args.positional.len() != 1 || !args.switch("--activity") {
        return Err(usage(
            "functional trial balance requires an explicit --activity selection",
            ACTIVITY_USAGE,
        ));
    }
    let periods = args.flag_all("--period");
    if periods.len() != 1 || periods[0].is_empty() {
        return Err(usage(
            "functional period activity requires exactly one --period",
            ACTIVITY_USAGE,
        ));
    }
    for flag in [
        "--as-of",
        "--fiscal-year",
        "--root",
        "--branch",
        "--as-issued-to",
        "--as-reported-in",
    ] {
        if args.flag(flag).is_some() {
            return Err(usage(
                format!("{flag} is not supported by functional period activity"),
                ACTIVITY_USAGE,
            ));
        }
    }
    for flag in [
        "--summary",
        "--as-originally-reported",
        "--as-currently-stated",
    ] {
        if args.switch(flag) {
            return Err(usage(
                format!("{flag} is not supported by functional period activity"),
                ACTIVITY_USAGE,
            ));
        }
    }
    functional_selected(
        ctx,
        args,
        fa::TrialBalanceSelection::Activity(vec![periods[0].to_string()]),
    )
}

fn functional_stock(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let periods = args.flag_all("--period");
    let dates = args.flag_all("--as-of");
    if args.positional.len() != 1
        || !((periods.len() == 1 && dates.is_empty()) || (periods.is_empty() && dates.len() == 1))
    {
        return Err(usage(
            "functional stock requires exactly one --period or one --as-of date",
            STOCK_USAGE,
        ));
    }
    for flag in [
        "--fiscal-year",
        "--root",
        "--branch",
        "--as-issued-to",
        "--as-reported-in",
    ] {
        if args.flag(flag).is_some() {
            return Err(usage(
                format!("{flag} is not supported by functional stock"),
                STOCK_USAGE,
            ));
        }
    }
    for flag in [
        "--summary",
        "--as-originally-reported",
        "--as-currently-stated",
    ] {
        if args.switch(flag) {
            return Err(usage(
                format!("{flag} is not supported by functional stock"),
                STOCK_USAGE,
            ));
        }
    }
    let as_of = dates
        .first()
        .map(|date| {
            DateDay::parse(date).map_err(|error| {
                usage(
                    format!("--as-of must be a civil date: {error}"),
                    STOCK_USAGE,
                )
            })
        })
        .transpose()?;
    let selection = match as_of {
        Some(date) => fa::TrialBalanceSelection::AsOf(date),
        None => fa::TrialBalanceSelection::Periods(vec![periods[0].to_string()]),
    };
    functional_selected(ctx, args, selection)
}

fn functional_selected(
    ctx: &mut Ctx<'_>,
    args: &Args,
    selection: fa::TrialBalanceSelection,
) -> Result<(), Fail> {
    let certify = args.switch("--certify") || args.flag("--certificate-out").is_some();
    let capability = ctx.capability(
        args,
        if certify {
            &["read", "produce"]
        } else {
            &["read"]
        },
    )?;
    let mut book = ctx.books.open_admitted(args, |book| {
        fa_policy::admit_read(&capability, capability.holder(), book.context().book_id)
            .and_then(|()| {
                if certify {
                    fa_policy::require(
                        &capability,
                        fa_policy::Op::Produce,
                        "certifying a functional trial balance",
                    )
                } else {
                    Ok(())
                }
            })
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        book.read_scope(capability.holder(), &capability)??;
        Ok(())
    })?;
    let (known_at, requested_utc_ns) = known_at_read_flag(args, &book, &ctx.out, &capability)?;
    let (report, certificate) = if certify {
        let certified = match requested_utc_ns {
            Some(instant) => {
                book.certify_functional_trial_balance_at_instant(&capability, selection, instant)??
            }
            None => book.certify_functional_trial_balance(&capability, selection, known_at)??,
        };
        ctx.out
            .time_selection(certified.certificate.time_selection.as_ref());
        let fa::ReportOutput::FunctionalTrialBalance(report) = certified.report else {
            return Err(Fail::Internal(
                "functional trial-balance certification returned another report kind".into(),
            ));
        };
        (*report, Some(certified.certificate))
    } else {
        (
            book.functional_trial_balance(&capability, selection, known_at)??,
            None,
        )
    };
    // Validate every displayed cell and amount before publishing retention or
    // emitting success. Replay uses the same presentation and historical names.
    let presentation = functional_presentation(&report, &book.context().units)?;
    let retained = certificate
        .as_ref()
        .map(|certificate| {
            notary::retain_report_certificate(&mut book, &ctx.files, args, certificate, &capability)
        })
        .transpose()?;
    let digest = certificate
        .as_ref()
        .map(|certificate| hex(&certificate.digest));
    emit_functional_trial_balance(&ctx.out, &report, presentation, digest.as_deref());
    if let (Some(certificate), Some((bytes, retained))) = (certificate.as_ref(), retained) {
        notary::emit_report_certificate(&ctx.out, args, certificate, &bytes, &retained);
    }
    Ok(())
}

struct FunctionalPresentation {
    event: &'static str,
    effective: String,
    fields: Vec<(&'static str, Json)>,
    human: String,
}

fn functional_presentation(
    report: &fa::FunctionalTrialBalance,
    units: &UnitRegistry,
) -> Result<FunctionalPresentation, Fail> {
    let render = |amount| render_amount(Amount::new(report.base_unit, amount), units);
    let corrupt = || {
        Fail::Book(fa::BookError::Kernel(KernelError::Corrupt(
            "functional trial balance has an invalid selector, account, unit or total".into(),
        )))
    };
    let base = registered_unit_code(report.base_unit, units)?;
    let (event, effective, mut fields, heading) = match &report.selection {
        fa::TrialBalanceSelection::Activity(periods)
            if periods.len() == 1 && report.effective_through.is_none() =>
        {
            (
                "functional_trial_balance",
                format!("period:{}", periods[0]),
                vec![("scope", s("period_activity")), ("period", s(&periods[0]))],
                format!("functional period activity · {}", periods[0]),
            )
        }
        fa::TrialBalanceSelection::Periods(periods) if periods.len() == 1 => {
            let through = report.effective_through.ok_or_else(corrupt)?;
            (
                "functional_stock_balance",
                format!("through:{}", through.render()),
                vec![
                    ("scope", s("stock")),
                    ("effective_through", s(through.render())),
                ],
                format!("functional stock through {}", through.render()),
            )
        }
        fa::TrialBalanceSelection::AsOf(through) if report.effective_through == Some(*through) => (
            "functional_stock_balance",
            format!("through:{}", through.render()),
            vec![
                ("scope", s("stock")),
                ("effective_through", s(through.render())),
            ],
            format!("functional stock through {}", through.render()),
        ),
        _ => return Err(corrupt()),
    };
    let mut human = vec![format!(
        "{heading} · {base} · known at {}",
        report.known_at.0
    )];
    let mut column = |label: &str,
                      cells: &[fa::FunctionalTrialBalanceCell]|
     -> Result<(Json, Json, bool), Fail> {
        let mut rows = Vec::with_capacity(cells.len());
        let (mut debits, mut credits) = (0i128, 0i128);
        for cell in cells {
            if cell.unit_id != report.base_unit.0 {
                return Err(corrupt());
            }
            let account = &report.accounts.get(&cell.account).ok_or_else(corrupt)?.code;
            let net = cell.debits.checked_sub(cell.credits).ok_or_else(corrupt)?;
            debits = debits.checked_add(cell.debits).ok_or_else(corrupt)?;
            credits = credits.checked_add(cell.credits).ok_or_else(corrupt)?;
            rows.push(obj(vec![
                ("account", s(account)),
                ("account_ref", s(format!("{:032x}", cell.account.0))),
                ("entity", cell.entity.as_ref().map_or(Json::Null, s)),
                ("debits", s(render(cell.debits)?)),
                ("credits", s(render(cell.credits)?)),
                ("net", s(render(net)?)),
                ("entry_count", Json::Int(i128::from(cell.entry_count))),
            ]));
            human.push(format!(
                "{label} {account}{}  debit {}  credit {}  net {}",
                cell.entity
                    .as_ref()
                    .map_or(String::new(), |entity| format!(" [{entity}]")),
                render(cell.debits)?,
                render(cell.credits)?,
                render(net)?
            ));
        }
        let totals = obj(vec![
            ("debits", s(render(debits)?)),
            ("credits", s(render(credits)?)),
            (
                "net",
                s(render(debits.checked_sub(credits).ok_or_else(corrupt)?)?),
            ),
        ]);
        Ok((Json::Arr(rows), totals, debits == credits))
    };
    let (rows, totals, balanced) = column("posted", &report.cells)?;
    let (pending_rows, pending_totals, pending_balanced) = column("pending", &report.pending)?;
    fields.extend([
        ("base_unit", s(base)),
        ("known_at", Json::Int(i128::from(report.known_at.0))),
        (
            "watermark",
            report
                .watermark
                .map_or(Json::Null, |seq| Json::Int(i128::from(seq.0))),
        ),
        ("entries", Json::Int(i128::from(report.entries))),
        ("fold_digest", s(hex(&report.fold_digest))),
        ("rows", rows),
        ("pending_rows", pending_rows),
        ("totals", totals),
        ("pending_totals", pending_totals),
        ("balanced", Json::Bool(balanced)),
        ("pending_balanced", Json::Bool(pending_balanced)),
    ]);
    Ok(FunctionalPresentation {
        event,
        effective,
        fields,
        human: human.join("\n"),
    })
}

fn emit_functional_trial_balance(
    out: &Out,
    report: &fa::FunctionalTrialBalance,
    presentation: FunctionalPresentation,
    certificate: Option<&str>,
) {
    out.known_at(report.known_at);
    out.effective(presentation.effective);
    out.event_with_certificate(
        presentation.event,
        presentation.fields,
        &presentation.human,
        certificate,
    );
}

pub(crate) fn render_functional_trial_balance(
    out: &Out,
    book: &Book,
    report: &fa::FunctionalTrialBalance,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    let presentation = functional_presentation(report, &book.context().units)?;
    emit_functional_trial_balance(out, report, presentation, certificate);
    Ok(())
}
