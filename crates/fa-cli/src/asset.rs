//! Immutable asset-cost schedules and source-derived period charges.

use std::collections::BTreeSet;

use fa::{AssetChargeRequest, Book, PostIntent, StoredAssetSchedule};
use fa_model::{
    ApprovalRef, AssetCostKind, AssetScheduleSpec, ControlPayload, EntryClass, EntryOrigin,
    EntryPayload, EntryRef, Id128, Oid, PeriodRef, account_vid, domain_digest,
};
use fa_money::{Amount, RoundingLaw, Side};
use fa_policy::{Capability, Op};
use fa_time::DateDay;
use fgdb_types::VId;

use crate::args::Args;
use crate::cli::{
    Ctx, Fail, Files, Out, check_post_planning_options, emit_post_plan, emit_posted, hex,
    known_at_read_flag, parse_digest, parse_vid, read_review_bytes, render_amount, usage,
    write_review_file,
};
use crate::json::{Json, obj, s};

const SCHEDULE_USAGE: &str = "fa schedule asset create NAME --kind depreciation|amortization --acquisition VID --leg N --first-period FY2026-P01 --periods 36 --salvage '0 USD' --expense 6100 --accumulated 1590 --rounding-law HalfEven --date YYYY-MM-DD --key KEY [--review-only]; or schedule asset show NAME | list | register [--as-known-at SEQ]";
const REGISTER_BASIS: &str =
    "all schedule effects recorded through known_at; no effective-date cutoff";
const CHARGE_USAGE: &str = "fa depreciate|amortize --schedule NAME --period FY2026-P01 --key KEY --evidence D:<oid> [--review-only | --dry-run [--plan-out FILE]]; resume with --review <file|hex|-> --digest <review_digest> [--approval VID]";
const SCHEDULE_INPUTS: &[&str] = &[
    "--kind",
    "--acquisition",
    "--leg",
    "--first-period",
    "--periods",
    "--salvage",
    "--expense",
    "--accumulated",
    "--rounding-law",
    "--date",
    "--key",
    "--description",
];
const CHARGE_INPUTS: &[&str] = &[
    "--schedule",
    "--period",
    "--key",
    "--description",
    "--evidence",
];

fn required<'a>(args: &'a Args, name: &str) -> Result<&'a str, Fail> {
    args.flag(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| usage(format!("{name} is required"), SCHEDULE_USAGE))
}

fn options(args: &Args, flags: &[&str], switches: &[&str]) -> Result<(), Fail> {
    const GLOBAL: &[&str] = &[
        "--book", "--keys", "--as", "--via", "--format", "--token", "--grant",
    ];
    for (name, values) in &args.flags {
        if !flags.contains(&name.as_str()) && !GLOBAL.contains(&name.as_str()) {
            return Err(usage(
                format!("{name} is not used by this asset operation"),
                SCHEDULE_USAGE,
            ));
        }
        if values.len() > 1 && !matches!(name.as_str(), "--evidence" | "--approval" | "--grant") {
            return Err(usage(
                format!("{name} must be supplied only once"),
                SCHEDULE_USAGE,
            ));
        }
    }
    let mut seen = BTreeSet::new();
    for name in &args.switches {
        if (!switches.contains(&name.as_str())
            && !matches!(
                name.as_str(),
                "--json" | "--help" | "--version" | "--no-color" | "--yes"
            ))
            || !seen.insert(name)
        {
            return Err(usage(
                format!("unexpected or repeated switch {name}"),
                SCHEDULE_USAGE,
            ));
        }
    }
    Ok(())
}

fn admit(book: &Book, capability: &Capability, op: Op) -> Result<(), Fail> {
    fa_policy::admit_read(capability, capability.holder(), book.context().book_id)
        .and_then(|()| fa_policy::require(capability, op, "asset schedules and charges"))
        .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    book.read_scope(capability.holder(), capability)??
        .admit_whole_book(None)??;
    Ok(())
}

fn review_mode(args: &Args) -> Result<bool, Fail> {
    check_post_planning_options(args)?;
    let review = args.switch("--review-only") || args.flag("--review-out").is_some();
    if review && args.switch("--dry-run") {
        return Err(usage(
            "choose proposal review or native --dry-run",
            CHARGE_USAGE,
        ));
    }
    Ok(review)
}

fn restore(
    files: &Files,
    bound: bool,
    args: &Args,
    book: &Book,
    principal: VId,
    inputs: &[&str],
) -> Result<PostIntent, Fail> {
    if args.switch("--review-only")
        || args.flag("--review-out").is_some()
        || inputs.iter().any(|name| args.flag(name).is_some())
    {
        return Err(usage(
            "a restored review supplies the complete unchanged proposal",
            CHARGE_USAGE,
        ));
    }
    let bytes = read_review_bytes(files, required(args, "--review")?, bound)?;
    let intent = PostIntent::decode(&bytes)
        .map_err(|error| usage(format!("invalid asset review: {error}"), CHARGE_USAGE))?;
    let expected = parse_digest(required(args, "--digest")?, "review digest")?;
    if intent
        .canonical_bytes()
        .map_err(|error| Fail::Internal(error.to_string()))?
        != bytes
        || intent
            .digest()
            .map_err(|error| Fail::Internal(error.to_string()))?
            != expected
        || intent.proposal().book_id != book.context().book_id
        || intent.proposal().branch_id != Id128::TRUNK
        || intent.proposal().principal_ref != principal
        || !intent.approvals().is_empty()
    {
        return Err(usage(
            "asset review bytes, digest, book or acting principal do not match",
            "restore the exact review and its independently retained digest under the original principal",
        ));
    }
    Ok(intent)
}

fn approvals(args: &Args, proposal: &EntryPayload) -> Result<Vec<ApprovalRef>, Fail> {
    let digest = proposal
        .proposal_digest()
        .map_err(|error| Fail::Internal(error.to_string()))?;
    let mut seen = BTreeSet::new();
    args.flag_all("--approval")
        .into_iter()
        .map(|raw| {
            let approval_vid = parse_vid(raw, "--approval")?;
            if !seen.insert(approval_vid) {
                return Err(usage(
                    "the same approval is supplied more than once",
                    CHARGE_USAGE,
                ));
            }
            Ok(ApprovalRef {
                approval_vid,
                approved_digest: digest,
            })
        })
        .collect()
}

fn emit_review(
    out: &Out,
    files: &Files,
    args: &Args,
    book: &Book,
    intent: &PostIntent,
    event: &str,
    mut fields: Vec<(&str, Json)>,
) -> Result<(), Fail> {
    let bytes = intent
        .canonical_bytes()
        .map_err(|error| Fail::Internal(error.to_string()))?;
    let digest = intent
        .digest()
        .map_err(|error| Fail::Internal(error.to_string()))?;
    let proposal_digest = intent
        .proposal()
        .proposal_digest()
        .map_err(|error| Fail::Internal(error.to_string()))?;
    if let Some(path) = args.flag("--review-out") {
        write_review_file(files, path, &bytes)?;
    }
    fields.extend([
        ("review_digest", s(hex(&digest))),
        ("proposal_digest", s(hex(&proposal_digest))),
        ("bytes", s(hex(&bytes))),
        ("file", args.flag("--review-out").map_or(Json::Null, s)),
    ]);
    out.at_book(book)?;
    out.event(event, fields, &format!("Asset review {}\nProposal {}\nRetain the exact bytes for approval or posting. No accounting entry was published.", hex(&digest), hex(&proposal_digest)));
    Ok(())
}

fn spec_json(spec: &AssetScheduleSpec, book: &Book) -> Result<Json, Fail> {
    Ok(obj(vec![
        ("name", s(&spec.name)),
        ("kind", s(spec.kind.name())),
        ("acquisition", s(format!("{:032x}", spec.acquisition.vid.0))),
        ("acquisition_digest", s(hex(&spec.acquisition.entry_digest))),
        ("leg", Json::Int(i128::from(spec.acquisition_ordinal))),
        ("calendar", s(&spec.first_period.calendar)),
        ("first_period", s(&spec.first_period.code)),
        ("periods", Json::Int(i128::from(spec.useful_life_periods))),
        (
            "salvage",
            s(render_amount(spec.salvage, &book.context().units)?),
        ),
        (
            "expense_account",
            s(format!("{:032x}", spec.expense_account.0)),
        ),
        (
            "accumulated_account",
            s(format!("{:032x}", spec.accumulated_account.0)),
        ),
        ("rounding_law", s(spec.rounding_law.name())),
    ]))
}

fn stored_json(schedule: &StoredAssetSchedule, book: &Book) -> Result<Json, Fail> {
    Ok(obj(vec![
        ("entry", s(format!("{:032x}", schedule.entry.vid.0))),
        ("entry_digest", s(hex(&schedule.entry.entry_digest))),
        ("recorded_at", Json::Int(i128::from(schedule.recorded_at.0))),
        ("terms", spec_json(&schedule.spec, book)?),
    ]))
}

pub(crate) fn schedule_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(2).map(String::as_str) {
        Some("create") => create(ctx, args),
        Some("show" | "list") => show(ctx, args),
        Some("register") => register(ctx, args),
        _ => Err(usage(
            "asset schedules need create, show, list or register",
            SCHEDULE_USAGE,
        )),
    }
}

fn show(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let selected = if args.positional[2] == "show" && args.positional.len() == 4 {
        Some(args.positional[3].as_str())
    } else if args.positional[2] == "list" && args.positional.len() == 3 {
        None
    } else {
        return Err(usage(
            "show requires a name; list takes no operands",
            SCHEDULE_USAGE,
        ));
    };
    options(args, &["--as-known-at"], &[])?;
    let capability = ctx.capability(args, &["read"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        fa_policy::admit_read(&capability, capability.holder(), book.context().book_id)
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        book.read_scope(capability.holder(), &capability)??;
        Ok(())
    })?;
    let (requested, _) = known_at_read_flag(args, &book, &ctx.out, &capability)?;
    let at = book
        .read_scope(capability.holder(), &capability)??
        .admit_whole_book(requested)??;
    let schedules = book.asset_schedules(Some(at), &capability)??;
    let mut rows = Vec::new();
    let mut human = Vec::new();
    for schedule in &schedules {
        if selected.is_none_or(|name| name == schedule.spec.name) {
            rows.push(stored_json(schedule, &book)?);
            human.push(format!(
                "{}: {}, {} periods from {}, salvage {}",
                schedule.spec.name,
                schedule.spec.kind.name(),
                schedule.spec.useful_life_periods,
                schedule.spec.first_period.code,
                render_amount(schedule.spec.salvage, &book.context().units)?
            ));
        }
    }
    if human.is_empty() {
        human.push("No matching asset schedules at this recorded prefix.".into());
    }
    ctx.out.known_at(at);
    ctx.out.event(
        "asset_schedules",
        vec![
            ("known_at", Json::Int(i128::from(at.0))),
            ("schedules", Json::Arr(rows)),
        ],
        &human.join("\n"),
    );
    Ok(())
}

fn register(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 3 {
        return Err(usage("asset register takes no operands", SCHEDULE_USAGE));
    }
    options(args, &["--as-known-at"], &[])?;
    let capability = ctx.capability(args, &["read"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        fa_policy::admit_read(&capability, capability.holder(), book.context().book_id)
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        book.read_scope(capability.holder(), &capability)??;
        Ok(())
    })?;
    let (requested, _) = known_at_read_flag(args, &book, &ctx.out, &capability)?;
    let at = book
        .read_scope(capability.holder(), &capability)??
        .admit_whole_book(requested)??;
    let register = book.asset_register(Some(at), &capability)??;
    let mut rows = Vec::with_capacity(register.rows.len());
    let mut human = vec![format!(
        "Asset register at recorded prefix {} ({REGISTER_BASIS}).",
        register.known_at.0
    )];
    for row in &register.rows {
        let units = &book.context().units;
        let original_cost = render_amount(row.original_cost, units)?;
        let recognized = render_amount(row.recognized, units)?;
        let carrying = render_amount(row.carrying_amount, units)?;
        let remaining = render_amount(row.remaining_depreciable, units)?;
        human.push(format!(
            "{}: source {}, original cost {original_cost}, recognized {recognized}, carrying {carrying}, remaining depreciable {remaining}, covered through {}",
            row.schedule.spec.name,
            if row.source_live { "live" } else { "reversed" },
            row.covered_through
                .as_ref()
                .map_or("none", |period| period.code.as_str()),
        ));
        rows.push(obj(vec![
            ("schedule", stored_json(&row.schedule, &book)?),
            ("original_cost", s(original_cost)),
            ("source_live", Json::Bool(row.source_live)),
            ("recognized", s(recognized)),
            ("carrying_amount", s(carrying)),
            ("remaining_depreciable", s(remaining)),
            (
                "covered_through",
                row.covered_through
                    .as_ref()
                    .map_or(Json::Null, |period| s(&period.code)),
            ),
        ]));
    }
    if register.rows.is_empty() {
        human.push("No asset schedules at this recorded prefix.".into());
    }
    ctx.out.known_at(register.known_at);
    ctx.out.event(
        "asset_register",
        vec![
            ("known_at", Json::Int(i128::from(register.known_at.0))),
            ("basis", s(REGISTER_BASIS)),
            ("rows", Json::Arr(rows)),
        ],
        &human.join("\n"),
    );
    Ok(())
}

fn create(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 4 {
        return Err(usage(
            "asset schedule create requires exactly one name",
            SCHEDULE_USAGE,
        ));
    }
    let name = &args.positional[3];
    let mut flags = SCHEDULE_INPUTS.to_vec();
    flags.extend(["--review", "--digest", "--review-out", "--approval"]);
    options(args, &flags, &["--review-only"])?;
    let review_only = review_mode(args)?;
    let capability = ctx.capability(args, &["read", "schema_change"])?;
    let principal = ctx.principal(args);
    let bound = ctx.authority().is_some();
    let mut book = ctx
        .books
        .open_admitted(args, |book| admit(book, &capability, Op::SchemaChange))?;
    let intent = if args.flag("--review").is_some() {
        restore(&ctx.files, bound, args, &book, principal, SCHEDULE_INPUTS)?
    } else {
        if args.flag("--digest").is_some() || args.flag("--approval").is_some() {
            return Err(usage(
                "approvals and a digest require an unchanged --review",
                SCHEDULE_USAGE,
            ));
        }
        let vid = parse_vid(required(args, "--acquisition")?, "--acquisition")?;
        let (entry, _) = book
            .read_scope(principal, &capability)??
            .read_entry(vid, None)??
            .ok_or_else(|| usage("the acquisition entry does not exist", SCHEDULE_USAGE))?;
        let book_id = book.context().book_id;
        let spec = AssetScheduleSpec {
            name: name.clone(),
            kind: AssetCostKind::from_name(required(args, "--kind")?).ok_or_else(|| {
                usage(
                    "--kind must be depreciation or amortization",
                    SCHEDULE_USAGE,
                )
            })?,
            acquisition: EntryRef {
                vid,
                entry_digest: entry.entry_digest,
            },
            acquisition_ordinal: required(args, "--leg")?.parse().map_err(|_| {
                usage(
                    "--leg must be an unsigned acquisition-leg ordinal",
                    SCHEDULE_USAGE,
                )
            })?,
            first_period: PeriodRef {
                calendar: book.context().calendar.id.clone(),
                code: required(args, "--first-period")?.into(),
            },
            useful_life_periods: required(args, "--periods")?.parse().map_err(|_| {
                usage(
                    "--periods must be a positive integer at most 1200",
                    SCHEDULE_USAGE,
                )
            })?,
            salvage: Amount::parse(required(args, "--salvage")?, &book.context().units)
                .map_err(|error| usage(format!("--salvage: {error}"), SCHEDULE_USAGE))?,
            expense_account: account_vid(book_id, required(args, "--expense")?),
            accumulated_account: account_vid(book_id, required(args, "--accumulated")?),
            rounding_law: RoundingLaw::from_name(required(args, "--rounding-law")?)
                .ok_or_else(|| usage("unknown rounding law", SCHEDULE_USAGE))?,
        };
        let date = DateDay::parse(required(args, "--date")?)
            .map_err(|error| usage(format!("--date: {error}"), SCHEDULE_USAGE))?;
        let description = book.seal_text(
            args.flag("--description")
                .unwrap_or("Finite straight-line asset-cost schedule"),
        )?;
        let proposal = fa_journal::asset_cost::asset_schedule_proposal(
            book.context(),
            principal,
            &spec,
            date,
            required(args, "--key")?.as_bytes(),
            description,
        )
        .map_err(|error| usage(format!("asset schedule: {error}"), SCHEDULE_USAGE))?;
        PostIntent::new(proposal, Vec::new())
            .map_err(|error| usage(format!("asset schedule: {error}"), SCHEDULE_USAGE))?
    };
    let spec = match &intent.proposal().control {
        Some(ControlPayload::SchemaChange {
            kind,
            canonical_bytes,
        }) if *kind == fa_model::asset_cost::SCHEMA_CHANGE_ASSET_SCHEDULE
            && intent.proposal().class == EntryClass::SCHEMA_CONTROL =>
        {
            AssetScheduleSpec::decode(canonical_bytes)
                .map_err(|error| usage(format!("asset schedule: {error}"), SCHEDULE_USAGE))?
        }
        _ => {
            return Err(usage(
                "review is not an asset-schedule schema control",
                SCHEDULE_USAGE,
            ));
        }
    };
    if spec.name != *name {
        return Err(usage(
            "the review names a different schedule",
            SCHEDULE_USAGE,
        ));
    }
    if review_only {
        return emit_review(
            &ctx.out,
            &ctx.files,
            args,
            &book,
            &intent,
            "asset_schedule_review",
            vec![("terms", spec_json(&spec, &book)?)],
        );
    }
    let recorded = book.create_asset_schedule_proposal(
        intent.proposal().clone(),
        approvals(args, intent.proposal())?,
        &capability,
    )??;
    let stored = StoredAssetSchedule {
        entry: recorded.entry,
        spec,
        recorded_at: recorded.recorded_at,
    };
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "asset_schedule_recorded",
        vec![
            ("schedule", stored_json(&stored, &book)?),
            ("already_recorded", Json::Bool(recorded.already_recorded)),
        ],
        &format!(
            "Asset schedule {} recorded at {}",
            stored.spec.name, stored.recorded_at.0
        ),
    );
    Ok(())
}

fn template(
    book: &mut Book,
    args: &Args,
    principal: VId,
    period: &str,
    capability: &Capability,
) -> Result<EntryPayload, Fail> {
    let key = required(args, "--key")?.as_bytes().to_vec();
    let definition = book
        .read_scope(principal, capability)??
        .period_at(period, None)??
        .ok_or_else(|| {
            usage(
                "the selected period has not been materialized",
                "fa period add-year --year YYYY",
            )
        })?;
    let effective_date = definition
        .end
        .add_days(-1)
        .map_err(|error| usage(format!("--period: {error}"), CHARGE_USAGE))?;
    let book_id = book.context().book_id;
    Ok(EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ADJUSTING,
        effective_date,
        document_date: None,
        description: book.seal_text(
            args.flag("--description")
                .unwrap_or("Finite straight-line asset-cost charge"),
        )?,
        effective_period: Some(PeriodRef {
            calendar: book.context().calendar.id.clone(),
            code: period.into(),
        }),
        legs: Vec::new(),
        control: None,
        unit_totals: Vec::new(),
        base_totals: None,
        origin: EntryOrigin::Intent {
            intent_oid: Oid(domain_digest(
                b"fa:intent:v1",
                &[&book_id.0, &principal.0.to_le_bytes(), &key],
            )),
            intent_kind: 1,
        },
        idempotency_key: key,
        principal_ref: principal,
        session_ref: None,
        evidence: crate::document::parse_evidence(&obj(Vec::new()), args, book)?,
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    })
}

pub(crate) fn depreciate(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    charge(ctx, args, AssetCostKind::Depreciation)
}

pub(crate) fn amortize(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    charge(ctx, args, AssetCostKind::Amortization)
}

fn charge(ctx: &mut Ctx<'_>, args: &Args, kind: AssetCostKind) -> Result<(), Fail> {
    if args.positional.len() != 1 {
        return Err(usage(
            "asset charges take no positional operands",
            CHARGE_USAGE,
        ));
    }
    let mut flags = CHARGE_INPUTS.to_vec();
    flags.extend([
        "--review",
        "--digest",
        "--review-out",
        "--approval",
        "--plan-out",
    ]);
    options(args, &flags, &["--review-only", "--dry-run"])?;
    let review_only = review_mode(args)?;
    let capability = ctx.capability(args, &["read", "post"])?;
    let principal = ctx.principal(args);
    let bound = ctx.authority().is_some();
    let mut book = ctx
        .books
        .open_admitted(args, |book| admit(book, &capability, Op::Post))?;
    let mut preview_amounts = None;
    let intent = if args.flag("--review").is_some() {
        restore(&ctx.files, bound, args, &book, principal, CHARGE_INPUTS)?
    } else {
        if args.flag("--digest").is_some() || args.flag("--approval").is_some() {
            return Err(usage(
                "approvals and a digest require an unchanged --review",
                CHARGE_USAGE,
            ));
        }
        let name = required(args, "--schedule")?;
        let schedule = book
            .asset_schedules(None, &capability)??
            .into_iter()
            .find(|schedule| schedule.spec.name == name)
            .ok_or_else(|| {
                usage(
                    "the named asset schedule does not exist",
                    "fa schedule asset list",
                )
            })?;
        let period = required(args, "--period")?;
        let template = template(&mut book, args, principal, period, &capability)?;
        let request = AssetChargeRequest {
            schedule: schedule.entry,
            kind,
            through_period: PeriodRef {
                calendar: book.context().calendar.id.clone(),
                code: period.into(),
            },
        };
        let prepared = book.prepare_asset_charge(&capability, &request, &template)??;
        preview_amounts = Some((
            prepared.cost(),
            prepared.target(),
            prepared.recognized(),
            prepared.delta(),
        ));
        if prepared.is_noop() {
            let render = |amount| render_amount(amount, &book.context().units).map(s);
            ctx.out.at_book(&book)?;
            ctx.out.known_at(prepared.basis().known_at);
            ctx.out.effective(format!("period:{period}"));
            ctx.out.event("asset_charge_noop", vec![
                ("kind", s(kind.name())), ("schedule_entry", s(format!("{:032x}", schedule.entry.vid.0))),
                ("schedule_digest", s(hex(&schedule.entry.entry_digest))), ("period", s(period)),
                ("known_at", Json::Int(i128::from(prepared.basis().known_at.0))),
                ("cost", render(prepared.cost())?), ("target", render(prepared.target())?),
                ("recognized", render(prepared.recognized())?), ("delta", render(prepared.delta())?),
                ("reason", s("net recognized charges already equal the cumulative target; no entry was published")),
            ], "Net recognized charges already equal the cumulative target; no entry was published.");
            return Ok(());
        }
        PostIntent::new(prepared.proposal(template)?, Vec::new())
            .map_err(|error| usage(format!("asset charge: {error}"), CHARGE_USAGE))?
    };
    let basis = intent
        .proposal()
        .asset_charge_basis()
        .map_err(|error| usage(format!("asset charge: {error}"), CHARGE_USAGE))?
        .ok_or_else(|| usage("review has no native asset-charge basis", CHARGE_USAGE))?;
    if intent.proposal().class != EntryClass::ADJUSTING || intent.proposal().extensions.len() != 1 {
        return Err(usage(
            "review must be an Adjusting entry with one asset-charge basis",
            CHARGE_USAGE,
        ));
    }
    let schedule = book
        .asset_schedules(None, &capability)??
        .into_iter()
        .find(|schedule| schedule.entry == basis.schedule)
        .ok_or_else(|| {
            usage(
                "review's exact immutable asset schedule is missing",
                CHARGE_USAGE,
            )
        })?;
    if schedule.spec.kind != kind {
        return Err(usage(
            "the command does not match the schedule's depreciation/amortization kind",
            CHARGE_USAGE,
        ));
    }
    if review_only {
        let (cost, target, recognized, delta) = preview_amounts
            .ok_or_else(|| Fail::Internal("asset review is missing its derived amounts".into()))?;
        let render = |amount| render_amount(amount, &book.context().units).map(s);
        let legs = intent
            .proposal()
            .legs
            .iter()
            .enumerate()
            .map(|(ordinal, leg)| {
                Ok(obj(vec![
                    ("ordinal", Json::Int(ordinal as i128)),
                    ("account_vid", s(format!("{:032x}", leg.account_ref.0))),
                    (
                        "side",
                        s(if leg.side == Side::Debit {
                            "debit"
                        } else {
                            "credit"
                        }),
                    ),
                    (
                        "amount",
                        s(render_amount(leg.amount, &book.context().units)?),
                    ),
                ]))
            })
            .collect::<Result<Vec<_>, Fail>>()?;
        return emit_review(
            &ctx.out,
            &ctx.files,
            args,
            &book,
            &intent,
            "asset_charge_review",
            vec![
                ("kind", s(kind.name())),
                (
                    "schedule_entry",
                    s(format!("{:032x}", basis.schedule.vid.0)),
                ),
                ("schedule_digest", s(hex(&basis.schedule.entry_digest))),
                ("period", s(&basis.through_period.code)),
                ("known_at", Json::Int(i128::from(basis.known_at.0))),
                ("cost", render(cost)?),
                ("target", render(target)?),
                ("recognized", render(recognized)?),
                ("delta", render(delta)?),
                ("legs", Json::Arr(legs)),
            ],
        );
    }
    let intent = PostIntent::new(
        intent.proposal().clone(),
        approvals(args, intent.proposal())?,
    )
    .map_err(|error| usage(format!("asset approvals: {error}"), CHARGE_USAGE))?;
    if args.switch("--dry-run") {
        let plan = book.plan(intent, &capability)??;
        return emit_post_plan(&ctx.out, &book, &ctx.files, args, &plan, &capability);
    }
    let posted = book.post(fa_journal::PostRequest {
        proposal: intent.proposal().clone(),
        approvals: intent.approvals().to_vec(),
        capability,
        plan_certificate: None,
    })??;
    ctx.out.at_book(&book)?;
    emit_posted(&ctx.out, posted, "Adjusting", false, None, None)
}
