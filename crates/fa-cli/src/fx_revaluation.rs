//! Journal-derived period-end FX adjustments through ordinary posting.
//!
//! A portable review is an existing canonical PostIntent, retaining both its
//! sealed proposal and immutable source basis. Fresh native admission checks
//! that basis again; an exact recorded retry returns its original outcome.

use std::collections::{BTreeMap, BTreeSet};

use fa::{Book, FxRevaluationRequest, PostIntent, PreparedFxRevaluation};
use fa_model::entry::FX_REVALUATION_EXTENSION;
use fa_model::{
    ApprovalRef, EntryClass, EntryOrigin, EntryPayload, FxRevaluationBasis, Id128, Oid, PeriodRef,
    account_vid, domain_digest, entity_value_vid,
};
use fa_money::Side;
use fa_policy::{Capability, Op};
use fa_time::DateDay;
use fgdb_types::VId;

use crate::args::Args;
use crate::cli::{
    Ctx, Fail, check_post_planning_options, emit_post_plan, emit_posted, hex, known_at_read_flag,
    parse_digest, parse_vid, read_review_bytes, render_amount, usage, write_review_file,
};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa fx revalue --period FY2026-P03 --account 1200 --rate D:<oid> --key revalue-2026-03 --review-only";
const GLOBAL_FLAGS: &[&str] = &[
    "--book", "--keys", "--as", "--via", "--format", "--token", "--grant",
];
const GLOBAL_SWITCHES: &[&str] = &["--json", "--help", "--version", "--no-color", "--yes"];

/// The FX verb has several unrelated operations. Reject every supplied option
/// outside this operation's contract, including repeated scalar selectors.
pub(crate) fn options(args: &Args, flags: &[&str], switches: &[&str]) -> Result<(), Fail> {
    for (flag, values) in &args.flags {
        if !flags.contains(&flag.as_str()) && !GLOBAL_FLAGS.contains(&flag.as_str()) {
            return Err(usage(
                format!("{flag} is not used by this FX operation"),
                EXAMPLE,
            ));
        }
        if values.len() > 1
            && !matches!(
                flag.as_str(),
                "--route" | "--evidence" | "--approval" | "--grant"
            )
        {
            return Err(usage(format!("{flag} must be supplied only once"), EXAMPLE));
        }
    }
    let mut seen = BTreeSet::new();
    for switch in &args.switches {
        if !switches.contains(&switch.as_str()) && !GLOBAL_SWITCHES.contains(&switch.as_str()) {
            return Err(usage(
                format!("{switch} is not used by this FX operation"),
                EXAMPLE,
            ));
        }
        if !seen.insert(switch) {
            return Err(usage(
                format!("{switch} must be supplied only once"),
                EXAMPLE,
            ));
        }
    }
    Ok(())
}

fn required<'a>(args: &'a Args, flag: &str) -> Result<&'a str, Fail> {
    args.flag(flag)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| usage(format!("{flag} is required"), EXAMPLE))
}

fn day(args: &Args, flag: &str) -> Result<DateDay, Fail> {
    let value = required(args, flag)?;
    DateDay::parse(value).map_err(|error| {
        usage(
            format!("{flag} {value}: {error}"),
            format!("{flag} YYYY-MM-DD"),
        )
    })
}

fn require_ops(capability: &Capability, ops: &[Op]) -> Result<(), Fail> {
    for op in ops {
        fa_policy::require(capability, *op, "period-end FX revaluation")
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    }
    Ok(())
}

fn admit_read(book: &Book, capability: &Capability) -> Result<(), Fail> {
    fa_policy::admit_read(capability, capability.holder(), book.context().book_id)
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    book.read_scope(capability.holder(), capability)??;
    Ok(())
}

/// Whole-book admission precedes book-coordinate output and source/review I/O.
fn admit_current(book: &Book, capability: &Capability, op: Op) -> Result<(), Fail> {
    require_ops(capability, &[Op::Read, op])?;
    admit_read(book, capability)?;
    fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None)
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    book.read_scope(capability.holder(), capability)??
        .admit_whole_book(None)??;
    Ok(())
}

pub(crate) fn set_routes(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &["--route", "--effective-from", "--key", "--description"],
        &[],
    )?;
    let effective_from = day(args, "--effective-from")?;
    let key = required(args, "--key")?;
    let mut source_codes = BTreeSet::new();
    let mut supplied = Vec::new();
    for raw in args.flag_all("--route") {
        let fields: Vec<_> = raw.split(':').collect();
        if fields.len() != 3 || fields.iter().any(|field| field.is_empty()) {
            return Err(usage(
                "--route requires <source-account>:<valuation-account>:<unrealized-account>",
                "fa fx routes set --route 1200:1290:7100 --effective-from 2026-01-01 --key fx-routes-v1",
            ));
        }
        if !source_codes.insert(fields[0]) {
            return Err(usage("an FX route repeats a source account", EXAMPLE));
        }
        supplied.push((fields[0], fields[1], fields[2]));
    }
    if supplied.is_empty() {
        return Err(usage(
            "a complete FX route map requires at least one --route",
            "fa fx routes set --route 1200:1290:7100 --effective-from 2026-01-01 --key fx-routes-v1",
        ));
    }
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read", "schema_change"])?;
    require_ops(&capability, &[Op::Read, Op::SchemaChange])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        admit_current(book, &capability, Op::SchemaChange)
    })?;
    let book_id = book.context().book_id;
    let routes = supplied
        .into_iter()
        .map(|(source, valuation, unrealized)| {
            (
                account_vid(book_id, source),
                fa::FxRevaluationRoute {
                    valuation_account: account_vid(book_id, valuation),
                    unrealized_account: account_vid(book_id, unrealized),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let count = routes.len();
    let description = book.seal_text(
        args.flag("--description")
            .unwrap_or("Period-end FX revaluation routes"),
    )?;
    let recorded = book.set_fx_revaluation_routes(
        fa::FxRevaluationRoutesRequest {
            principal,
            effective_from,
            routes,
            idempotency_key: key.as_bytes().to_vec(),
            description,
        },
        &capability,
    )??;
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "fx_routes_recorded",
        vec![
            ("effective_from", s(effective_from.to_string())),
            ("routes", Json::Int(count as i128)),
            (
                "control_entry",
                s(format!("{:032x}", recorded.control_entry.0)),
            ),
            ("recorded_at", Json::Int(i128::from(recorded.recorded_at.0))),
            ("digest", s(hex(&recorded.digest))),
            ("already_recorded", Json::Bool(recorded.already_recorded)),
        ],
        &format!("FX routes: {count} exposure accounts, effective {effective_from}"),
    );
    Ok(())
}

pub(crate) fn show_routes(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(args, &["--as-of", "--as-known-at"], &[])?;
    let effective = day(args, "--as-of")?;
    let capability = ctx.capability(args, &["read"])?;
    require_ops(&capability, &[Op::Read])?;
    let mut selected = None;
    let out = &ctx.out;
    ctx.books.open_admitted(args, |book| {
        admit_read(book, &capability)?;
        let (requested_at, _) = known_at_read_flag(args, book, out, &capability)?;
        let at = book
            .read_scope(capability.holder(), &capability)??
            .admit_whole_book(requested_at)??;
        let routes = book.fx_revaluation_routes_at(effective, Some(at), &capability)??;
        let accounts = book.accounts_at(at, &capability)??;
        selected = Some((at, routes, accounts));
        Ok(())
    })?;
    let (at, routes, accounts) =
        selected.ok_or_else(|| Fail::Internal("FX route history is missing".into()))?;
    let accounts: BTreeMap<_, _> = accounts
        .into_iter()
        .map(|row| (row.vid, row.code))
        .collect();
    let mut rows = Vec::new();
    let mut human = vec![format!(
        "FX routes as of {effective}, recorded through {}",
        at.0
    )];
    if let Some(map) = &routes {
        let code = |vid: &VId| {
            accounts
                .get(vid)
                .ok_or_else(|| Fail::Internal("a retained FX route names a missing account".into()))
        };
        for (source, route) in &map.routes {
            human.push(format!(
                "{}: valuation {}, unrealized {}",
                code(source)?,
                code(&route.valuation_account)?,
                code(&route.unrealized_account)?
            ));
            rows.push(obj(vec![
                ("account", s(code(source)?)),
                ("account_vid", s(format!("{:032x}", source.0))),
                ("valuation_account", s(code(&route.valuation_account)?)),
                (
                    "valuation_vid",
                    s(format!("{:032x}", route.valuation_account.0)),
                ),
                ("unrealized_account", s(code(&route.unrealized_account)?)),
                (
                    "unrealized_vid",
                    s(format!("{:032x}", route.unrealized_account.0)),
                ),
            ]));
        }
    } else {
        human.push("No FX routes were effective at this recorded prefix.".into());
    }
    ctx.out.known_at(at);
    ctx.out.effective(format!("as-of:{effective}"));
    ctx.out.event(
        "fx_routes",
        vec![
            ("as_of", s(effective.to_string())),
            ("known_at", Json::Int(i128::from(at.0))),
            ("found", Json::Bool(routes.is_some())),
            (
                "effective_from",
                routes
                    .as_ref()
                    .map_or(Json::Null, |map| s(map.effective_from.to_string())),
            ),
            (
                "control_entry",
                routes
                    .as_ref()
                    .map_or(Json::Null, |map| s(format!("{:032x}", map.control_entry.0))),
            ),
            (
                "recorded_at",
                routes
                    .as_ref()
                    .map_or(Json::Null, |map| Json::Int(i128::from(map.recorded_at.0))),
            ),
            (
                "digest",
                routes
                    .as_ref()
                    .map_or(Json::Null, |map| s(hex(&map.digest))),
            ),
            ("routes", Json::Arr(rows)),
        ],
        &human.join("\n"),
    );
    Ok(())
}

fn leg_preview(
    proposal: &EntryPayload,
    book: &Book,
    capability: &Capability,
    prepared: &PreparedFxRevaluation,
) -> Result<Json, Fail> {
    let accounts: BTreeMap<_, _> = book
        .accounts_at(prepared.known_at(), capability)??
        .into_iter()
        .map(|row| (row.vid, row.code))
        .collect();
    Ok(Json::Arr(
        proposal
            .legs
            .iter()
            .enumerate()
            .map(|(ordinal, leg)| {
                let code = accounts.get(&leg.account_ref).ok_or_else(|| {
                    Fail::Internal("prepared FX leg names a missing account".into())
                })?;
                Ok(obj(vec![
                    ("ordinal", Json::Int(ordinal as i128)),
                    ("account", s(code)),
                    ("account_vid", s(format!("{:032x}", leg.account_ref.0))),
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
                        "dimensions",
                        crate::cli::plan_dimensions_json(&leg.dimension_set),
                    ),
                ]))
            })
            .collect::<Result<Vec<_>, Fail>>()?,
    ))
}

fn proposal(
    book: &mut Book,
    args: &Args,
    prepared: &PreparedFxRevaluation,
    principal: VId,
) -> Result<EntryPayload, Fail> {
    let key = required(args, "--key")?;
    let evidence = crate::document::parse_evidence(&obj(Vec::new()), args, book)?;
    let book_id = book.context().book_id;
    let description = args.flag("--description").map_or_else(
        || format!("Period-end FX revaluation {}", prepared.request().period),
        str::to_string,
    );
    Ok(prepared.proposal(EntryPayload {
        schema_minor: 1,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::REVALUATION,
        effective_date: prepared.closing_date(),
        document_date: None,
        description: book.seal_text(&description)?,
        effective_period: Some(PeriodRef {
            calendar: book.context().calendar.id.clone(),
            code: prepared.request().period.clone(),
        }),
        legs: Vec::new(),
        control: None,
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: key.as_bytes().to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid(domain_digest(
                b"fa:intent:v1",
                &[&book_id.0, &principal.0.to_le_bytes(), key.as_bytes()],
            )),
            intent_kind: 1,
        },
        principal_ref: principal,
        session_ref: None,
        evidence,
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    })?)
}

/// A saved review needs the same governed source read as fresh preparation.
/// Do not reprepare it: the native path must recognize exact recorded retries
/// before testing whether new source activity invalidates a fresh publication.
fn read_review_rate(
    book: &mut Book,
    capability: &Capability,
    review: &PostIntent,
) -> Result<(), Fail> {
    let basis = review
        .proposal()
        .extensions
        .iter()
        .find(|(tag, _)| *tag == FX_REVALUATION_EXTENSION)
        .ok_or_else(|| usage("the review has no native FX source basis", EXAMPLE))?;
    let basis = FxRevaluationBasis::decode(&basis.1)
        .map_err(|error| usage(format!("invalid FX source basis: {error}"), EXAMPLE))?;
    let document = match book.read_document_for(capability, &basis.rate_document)?? {
        fa_journal::DocumentRead::Full(document) => document,
        fa_journal::DocumentRead::Redacted(_) => {
            return Err(Fail::Refusal(fa_journal::Refusal::new(
                fa_journal::refusal::code::CAPABILITY,
                fa_journal::refusal::exit::SAFETY,
                "restoring an FX review requires its complete retained Rate document",
                "plan §6.4 / §9.6 (governed source bytes)",
                "use authority permitted to read the complete Rate under its governing redaction contract",
            )));
        }
    };
    if document.book_id != book.context().book_id
        || document.kind != fa_journal::fx::RATE_DOCUMENT_KIND
        || document.mime != fa::FX_RATE_MIME
        || document.oid() != basis.rate_document
        || document.doc_commit() != basis.rate_commit
    {
        return Err(Fail::Refusal(fa_journal::Refusal::new(
            fa_journal::refusal::code::STRUCTURE,
            fa_journal::refusal::exit::USAGE,
            "the FX review does not cite this book's exact canonical Rate document",
            "plan §6.4 (retained rate and computation basis)",
            "restore the unchanged review and its retained Rate evidence",
        )));
    }
    fa::FxRateDocument::decode(&document.bytes)?;
    admit_current(book, capability, Op::Post)
}

fn with_approvals(review: PostIntent, args: &Args) -> Result<PostIntent, Fail> {
    let digest = review
        .proposal()
        .proposal_digest()
        .map_err(|error| Fail::Internal(error.to_string()))?;
    let mut seen = BTreeSet::new();
    let mut approvals = Vec::new();
    for value in args.flag_all("--approval") {
        let approval_vid = parse_vid(value, "--approval")?;
        if !seen.insert(approval_vid) {
            return Err(usage(
                "the same approval is supplied more than once",
                EXAMPLE,
            ));
        }
        approvals.push(ApprovalRef {
            approval_vid,
            approved_digest: digest,
        });
    }
    PostIntent::new(review.proposal().clone(), approvals)
        .map_err(|error| usage(format!("FX approval references: {error}"), EXAMPLE))
}

pub(crate) fn revalue(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &[
            "--period",
            "--account",
            "--rate",
            "--key",
            "--entity",
            "--description",
            "--evidence",
            "--approval",
            "--review",
            "--review-out",
            "--digest",
            "--plan-out",
        ],
        &["--dry-run", "--review-only"],
    )?;
    check_post_planning_options(args)?;
    let review_only = args.switch("--review-only") || args.flag("--review-out").is_some();
    if review_only && args.switch("--dry-run") {
        return Err(usage(
            "choose a proposal review or a native --dry-run plan",
            EXAMPLE,
        ));
    }
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read", "post"])?;
    require_ops(&capability, &[Op::Read, Op::Post])?;
    let bound = ctx.authority().is_some();
    if let Some(path) = args.flag("--review") {
        if review_only
            || [
                "--period",
                "--account",
                "--rate",
                "--key",
                "--entity",
                "--description",
                "--evidence",
            ]
            .iter()
            .any(|flag| args.flag(flag).is_some())
        {
            return Err(usage(
                "a restored FX review supplies the complete unchanged proposal",
                "fa fx revalue --review <file|hex|-> --digest <review_digest> [--approval <vid>] [--dry-run]",
            ));
        }
        let expected = parse_digest(required(args, "--digest")?, "review digest")?;
        let mut book = ctx
            .books
            .open_admitted(args, |book| admit_current(book, &capability, Op::Post))?;
        let bytes = read_review_bytes(&ctx.files, path, bound)?;
        let review = PostIntent::decode(&bytes).map_err(|error| {
            usage(
                format!("invalid FX review: {error}"),
                "use the unchanged FX review bytes",
            )
        })?;
        if review
            .digest()
            .map_err(|error| Fail::Internal(error.to_string()))?
            != expected
            || review.proposal().class != EntryClass::REVALUATION
            || review.proposal().book_id != book.context().book_id
            || !review.approvals().is_empty()
        {
            return Err(usage(
                "FX review digest, book or type does not match",
                "use its independently retained review_digest",
            ));
        }
        read_review_rate(&mut book, &capability, &review)?;
        let intent = with_approvals(review, args)?;
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
        return emit_posted(&ctx.out, posted, "Revaluation", false, None, None);
    }
    if args.flag("--digest").is_some() || args.flag("--approval").is_some() {
        return Err(usage(
            "approvals and a digest require an unchanged --review",
            EXAMPLE,
        ));
    }
    let period = required(args, "--period")?;
    let source_code = required(args, "--account")?;
    let rate_text = required(args, "--rate")?;
    let rate_oid = rate_text.strip_prefix("D:").ok_or_else(|| {
        usage(
            "--rate requires a retained document reference D:<oid>",
            EXAMPLE,
        )
    })?;
    let rate_document = Oid(parse_digest(rate_oid, "--rate D:oid")?);
    let _ = required(args, "--key")?;
    if args.flag("--entity").is_some_and(str::is_empty) {
        return Err(usage("--entity must name a legal-entity code", EXAMPLE));
    }
    let mut prepared = None;
    let mut book = ctx.books.open_admitted(args, |book| {
        admit_current(book, &capability, Op::Post)?;
        let book_id = book.context().book_id;
        prepared = Some(
            book.prepare_fx_revaluation(
                &FxRevaluationRequest {
                    period: period.to_string(),
                    source_account: account_vid(book_id, source_code),
                    rate_document,
                    entity: args
                        .flag("--entity")
                        .map(|code| entity_value_vid(book_id, code)),
                },
                &capability,
            )??,
        );
        Ok(())
    })?;
    let prepared = prepared.ok_or_else(|| Fail::Internal("FX preparation is missing".into()))?;
    ctx.out.known_at(prepared.known_at());
    ctx.out.effective(format!("period:{period}"));
    let entity = prepared
        .basis()
        .entity
        .map_or(Json::Null, |vid| s(format!("{:032x}", vid.0)));
    if prepared.is_noop() {
        let render = |amount| render_amount(amount, &book.context().units).map(s);
        ctx.out.event(
            "fx_revaluation_noop",
            vec![
                ("period", s(period)),
                ("closing_date", s(prepared.closing_date().to_string())),
                ("known_at", Json::Int(i128::from(prepared.known_at().0))),
                ("account", s(source_code)),
                ("account_vid", s(format!("{:032x}", prepared.request().source_account.0))),
                ("entity", entity),
                ("source_native_net", render(prepared.source_native_net())?),
                ("current_carrying_net", render(prepared.current_carrying_net())?),
                ("target_base_net", render(prepared.target_base_net())?),
                ("reason", s("functional carrying value already equals the closing-rate target; no entry was published")),
            ],
            "FX carrying value already equals the closing-rate target; no entry was published",
        );
        return Ok(());
    }
    let proposal = proposal(&mut book, args, &prepared, principal)?;
    let intent = PostIntent::new(proposal, Vec::new())
        .map_err(|error| usage(format!("FX proposal: {error}"), EXAMPLE))?;
    if review_only {
        let bytes = intent
            .canonical_bytes()
            .map_err(|error| Fail::Internal(error.to_string()))?;
        let review_digest = intent
            .digest()
            .map_err(|error| Fail::Internal(error.to_string()))?;
        let proposal_digest = intent
            .proposal()
            .proposal_digest()
            .map_err(|error| Fail::Internal(error.to_string()))?;
        let legs = leg_preview(intent.proposal(), &book, &capability, &prepared)?;
        let render = |amount| render_amount(amount, &book.context().units).map(s);
        let fields = vec![
            ("period", s(period)),
            ("closing_date", s(prepared.closing_date().to_string())),
            ("known_at", Json::Int(i128::from(prepared.known_at().0))),
            ("account", s(source_code)),
            (
                "account_vid",
                s(format!("{:032x}", prepared.request().source_account.0)),
            ),
            ("entity", entity),
            ("rate_document", s(hex(&rate_document.0))),
            (
                "routes_entry",
                s(format!("{:032x}", prepared.basis().routes_entry.0)),
            ),
            ("routes_digest", s(hex(&prepared.basis().routes_digest))),
            ("source_digest", s(hex(&prepared.source_digest()))),
            ("source_native_net", render(prepared.source_native_net())?),
            ("source_base_net", render(prepared.source_base_net())?),
            (
                "prior_adjustment_net",
                render(prepared.prior_adjustment_net())?,
            ),
            (
                "current_carrying_net",
                render(prepared.current_carrying_net())?,
            ),
            ("target_base_net", render(prepared.target_base_net())?),
            ("delta", render(prepared.delta())?),
            ("legs", legs),
            ("review_digest", s(hex(&review_digest))),
            ("proposal_digest", s(hex(&proposal_digest))),
            ("bytes", s(hex(&bytes))),
            ("file", args.flag("--review-out").map_or(Json::Null, s)),
            ("scope", s("period-end-fx-revaluation-proposal")),
        ];
        let units = &book.context().units;
        let mut human = format!(
            "FX revaluation for {source_code} in {period}, closing {} at sequence {}\nForeign exposure: {}\nOriginal functional carrying: {}; prior adjustments: {}\nCurrent carrying: {}; closing-rate target: {}; adjustment: {}\nProposal {}\nReview {}\nNothing was published; retain the complete review bytes or file to approve, plan or post this unchanged proposal.",
            prepared.closing_date(),
            prepared.known_at().0,
            render_amount(prepared.source_native_net(), units)?,
            render_amount(prepared.source_base_net(), units)?,
            render_amount(prepared.prior_adjustment_net(), units)?,
            render_amount(prepared.current_carrying_net(), units)?,
            render_amount(prepared.target_base_net(), units)?,
            render_amount(prepared.delta(), units)?,
            hex(&proposal_digest),
            hex(&review_digest),
        );
        if let Some(path) = args.flag("--review-out") {
            write_review_file(&ctx.files, path, &bytes)?;
            human.push_str(&format!("\nReview file: {path}"));
        } else {
            human.push_str(&format!(
                "\nComplete canonical review bytes (hex):\n{}",
                hex(&bytes)
            ));
        }
        ctx.out.event("fx_revaluation_reviewed", fields, &human);
        return Ok(());
    }
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
    emit_posted(&ctx.out, posted, "Revaluation", false, None, None)
}
