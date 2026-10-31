//! Journaled lot policy and native, law-derived disposal posting.

use std::collections::BTreeSet;

use fa::{Book, LotDisposalPostRequest, LotPolicy, PostIntent, SchemaControlReview};
use fa_model::{
    ApprovalRef, EntryClass, EntryOrigin, EntryPayload, EntryRef, Id128, Oid, account_vid,
    domain_digest,
};
use fa_money::{AccountingRegime, LotLaw, RoundingLaw, Side};
use fa_policy::{Capability, Op};
use fa_time::DateDay;

use crate::args::Args;
use crate::cli::{
    Ctx, Fail, Files, Out, RetainedReview, check_post_planning_options, decode_hex_bytes,
    emit_post_plan, emit_posted, hex, known_at_read_flag, parse_digest, parse_vid,
    read_review_bytes, render_amount, usage, write_review_file,
};
use crate::json::{Json, obj, s};

const DISPOSE_USAGE: &str = "fa dispose --account 1400 --quantity \"3 SHARE\" --quantity-offset 1490 --cost-offset 5100 --date YYYY-MM-DD --key disposal-1 --evidence D:<oid> [--dry-run | --review-only | --review-out <new-file>]";
const POLICY_USAGE: &str = "fa chart lot-policy set --account 1400 --law FIFO|LIFO|SpecificId|WeightedAverage --regime US-GAAP|US-TAX|IFRS --date YYYY-MM-DD --key lot-policy-1 [--review-only | --review-out <new-file>]";

const BATCH_REVIEW_USAGE: &str = "prepare each disposal with --review-only at the same book prefix, then use batch members {\"review\":\"<bytes hex>\",\"review_digest\":\"<review_digest>\"}; only inline unchanged disposal reviews are accepted";

pub(crate) fn is_batch_review(doc: &Json) -> bool {
    doc.get("review").is_some() || doc.get("review_digest").is_some()
}

/// Restore a complete reviewed disposal without rebuilding its sealed fields
/// or interpreting bytes as a host path. The native batch law still checks
/// the source prefix, account independence, authority and every derived leg.
pub(crate) fn batch_review(
    doc: &Json,
    book_id: Id128,
    principal: fgdb_types::VId,
) -> Result<Option<PostIntent>, Fail> {
    if !is_batch_review(doc) {
        return Ok(None);
    }
    let Json::Obj(fields) = doc else {
        return Err(usage(
            "a disposal review member must be an object",
            BATCH_REVIEW_USAGE,
        ));
    };
    if fields.len() != 2
        || fields
            .iter()
            .any(|(name, _)| !matches!(name.as_str(), "review" | "review_digest"))
    {
        return Err(usage(
            "a disposal review member contains only review and review_digest",
            BATCH_REVIEW_USAGE,
        ));
    }
    let supplied = doc.get("review").and_then(Json::as_str).ok_or_else(|| {
        usage(
            "review must be the complete bytes hex string",
            BATCH_REVIEW_USAGE,
        )
    })?;
    if supplied.is_empty()
        || !supplied.len().is_multiple_of(2)
        || !supplied.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(usage(
            "a batch review accepts inline hex bytes only, never a filesystem path or stdin selector",
            BATCH_REVIEW_USAGE,
        ));
    }
    let expected = doc
        .get("review_digest")
        .and_then(Json::as_str)
        .ok_or_else(|| {
            usage(
                "review_digest must be the independently retained digest",
                BATCH_REVIEW_USAGE,
            )
        })?;
    let expected = parse_digest(expected, "review_digest")?;
    let bytes = decode_hex_bytes(supplied, "lot-disposal review")?;
    let intent = PostIntent::decode(&bytes).map_err(|error| {
        usage(
            format!("invalid disposal review: {error}"),
            BATCH_REVIEW_USAGE,
        )
    })?;
    if intent
        .canonical_bytes()
        .map_err(|error| Fail::Internal(error.to_string()))?
        != bytes
        || intent
            .digest()
            .map_err(|error| Fail::Internal(error.to_string()))?
            != expected
    {
        return Err(usage(
            "the disposal review bytes or digest differ from the retained review",
            BATCH_REVIEW_USAGE,
        ));
    }
    let proposal = intent.proposal();
    let basis = proposal
        .lot_disposal_basis()
        .map_err(|error| usage(format!("lot-disposal review: {error}"), BATCH_REVIEW_USAGE))?;
    if proposal.book_id != book_id
        || proposal.branch_id != Id128::TRUNK
        || proposal.principal_ref != principal
        || proposal.class != EntryClass::ORIGINAL
        || !intent.approvals().is_empty()
        || basis.is_none()
        || proposal.extensions.len() != 1
        || proposal.base_totals.is_some()
        || proposal.control.is_some()
        || proposal.pending.is_some()
        || !proposal.supersession.is_empty()
    {
        return Err(usage(
            "a batch review must be an approval-free Original lot disposal for this book and acting principal",
            BATCH_REVIEW_USAGE,
        ));
    }
    Ok(Some(intent))
}

fn required<'a>(args: &'a Args, name: &str) -> Result<&'a str, Fail> {
    args.flag(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| usage(format!("{name} is required"), DISPOSE_USAGE))
}

fn options(args: &Args, flags: &[&str], switches: &[&str]) -> Result<(), Fail> {
    const GLOBAL: &[&str] = &[
        "--book", "--keys", "--as", "--via", "--format", "--token", "--grant",
    ];
    for (name, values) in &args.flags {
        if !flags.contains(&name.as_str()) && !GLOBAL.contains(&name.as_str()) {
            return Err(usage(
                format!("{name} is not used by this lot operation"),
                DISPOSE_USAGE,
            ));
        }
        if values.len() > 1
            && !matches!(
                name.as_str(),
                "--target" | "--evidence" | "--approval" | "--grant"
            )
        {
            return Err(usage(
                format!("{name} must be supplied only once"),
                DISPOSE_USAGE,
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
                DISPOSE_USAGE,
            ));
        }
    }
    Ok(())
}

fn admit(book: &Book, capability: &Capability, op: Op) -> Result<(), Fail> {
    fa_policy::admit_read(capability, capability.holder(), book.context().book_id)
        .and_then(|()| fa_policy::require(capability, op, "lot policy and disposal"))
        .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    book.read_scope(capability.holder(), capability)??
        .admit_whole_book(None)??;
    Ok(())
}

fn date(args: &Args) -> Result<DateDay, Fail> {
    DateDay::parse(required(args, "--date")?)
        .map_err(|error| usage(format!("--date: {error}"), "--date YYYY-MM-DD"))
}

fn review_mode(args: &Args) -> Result<bool, Fail> {
    let review = args.switch("--review-only") || args.flag("--review-out").is_some();
    if review && args.switch("--dry-run") {
        return Err(usage(
            "choose proposal review or native --dry-run",
            DISPOSE_USAGE,
        ));
    }
    Ok(review)
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
                    POLICY_USAGE,
                ));
            }
            Ok(ApprovalRef {
                approval_vid,
                approved_digest: digest,
            })
        })
        .collect()
}

fn restore<R: RetainedReview>(
    files: &Files,
    bound: bool,
    args: &Args,
    book: &Book,
) -> Result<R, Fail> {
    let bytes = read_review_bytes(files, required(args, "--review")?, bound)?;
    let intent = R::decode_review(&bytes).map_err(|error| {
        usage(
            format!("invalid lot review: {error}"),
            "restore the unchanged review bytes",
        )
    })?;
    let expected = parse_digest(required(args, "--digest")?, "review digest")?;
    if intent
        .review_digest()
        .map_err(|error| Fail::Internal(error.to_string()))?
        != expected
        || intent.reviewed().book_id != book.context().book_id
        || intent.reviewed().branch_id != Id128::TRUNK
        || !intent.approval_free()
    {
        return Err(usage(
            "lot review digest, book or approval-free shape does not match",
            "supply the independently retained review_digest and exact original bytes",
        ));
    }
    Ok(intent)
}

fn emit_review<R: RetainedReview>(
    out: &Out,
    files: &Files,
    args: &Args,
    book: &Book,
    intent: &R,
    event: &str,
    mut fields: Vec<(&str, Json)>,
) -> Result<(), Fail> {
    let bytes = intent
        .review_bytes()
        .map_err(|error| Fail::Internal(error.to_string()))?;
    let digest = intent
        .review_digest()
        .map_err(|error| Fail::Internal(error.to_string()))?;
    let proposal_digest = intent
        .reviewed()
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
    out.event(event, fields, &format!("Lot review {}\nProposal {}\nRetain these exact bytes for approval or posting. No accounting entry was published.", hex(&digest), hex(&proposal_digest)));
    Ok(())
}

pub(crate) fn policy_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args
        .positional
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["chart", "lot-policy", "show"] => policy_show(ctx, args),
        ["chart", "lot-policy", "set"] => policy_set(ctx, args),
        _ => Err(usage("lot policy requires set or show", POLICY_USAGE)),
    }
}

fn policy_show(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(args, &["--account", "--as-known-at"], &[])?;
    let account = required(args, "--account")?;
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
    let account_id = account_vid(book.context().book_id, account);
    let policy = book.lot_policy_at(account_id, Some(at), &capability)??;
    ctx.out.at_book(&book)?;
    ctx.out.known_at(at);
    ctx.out.event(
        "lot_policy",
        vec![
            ("account", s(account)),
            ("known_at", Json::Int(i128::from(at.0))),
            ("found", Json::Bool(policy.is_some())),
            (
                "law",
                policy
                    .as_ref()
                    .map_or(Json::Null, |p| s(p.policy.law.name())),
            ),
            (
                "regime",
                policy
                    .as_ref()
                    .map_or(Json::Null, |p| s(p.policy.regime.as_str())),
            ),
            (
                "rounding_law",
                policy
                    .as_ref()
                    .map_or(Json::Null, |p| s(p.policy.rounding_law.name())),
            ),
            (
                "control_entry",
                policy
                    .as_ref()
                    .map_or(Json::Null, |p| s(format!("{:032x}", p.entry.vid.0))),
            ),
            (
                "entry_digest",
                policy
                    .as_ref()
                    .map_or(Json::Null, |p| s(hex(&p.entry.entry_digest))),
            ),
            (
                "recorded_at",
                policy
                    .as_ref()
                    .map_or(Json::Null, |p| Json::Int(i128::from(p.recorded_at.0))),
            ),
        ],
        &policy.as_ref().map_or_else(
            || format!("{account}: no lot policy at sequence {}", at.0),
            |p| {
                format!(
                    "{account}: {}, {}, {} (recorded at {})",
                    p.policy.law.name(),
                    p.policy.regime.as_str(),
                    p.policy.rounding_law.name(),
                    p.recorded_at.0
                )
            },
        ),
    );
    Ok(())
}

fn policy_set(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &[
            "--account",
            "--law",
            "--regime",
            "--rounding-law",
            "--date",
            "--key",
            "--description",
            "--review",
            "--digest",
            "--review-out",
            "--approval",
        ],
        &["--review-only"],
    )?;
    let review_only = review_mode(args)?;
    let capability = ctx.capability(args, &["read", "schema_change"])?;
    let principal = ctx.principal(args);
    let bound = ctx.authority().is_some();
    let mut book = ctx
        .books
        .open_admitted(args, |book| admit(book, &capability, Op::SchemaChange))?;
    let intent = if args.flag("--review").is_some() {
        if review_only
            || [
                "--account",
                "--law",
                "--regime",
                "--rounding-law",
                "--date",
                "--key",
                "--description",
            ]
            .iter()
            .any(|name| args.flag(name).is_some())
        {
            return Err(usage(
                "restoring a lot-policy review supplies every policy field",
                "fa chart lot-policy set --review <file|hex|-> --digest <review_digest> --approval <vid> --approval <vid>",
            ));
        }
        restore::<SchemaControlReview>(&ctx.files, bound, args, &book)?
    } else {
        if args.flag("--digest").is_some() || args.flag("--approval").is_some() {
            return Err(usage(
                "approvals require an unchanged policy --review",
                POLICY_USAGE,
            ));
        }
        let account = account_vid(book.context().book_id, required(args, "--account")?);
        let law = LotLaw::from_name(required(args, "--law")?)
            .ok_or_else(|| usage("unknown lot law", POLICY_USAGE))?;
        let regime = AccountingRegime::parse(required(args, "--regime")?)
            .ok_or_else(|| usage("unknown accounting regime", POLICY_USAGE))?;
        let rounding_law =
            RoundingLaw::from_name(args.flag("--rounding-law").unwrap_or("HalfEven"))
                .ok_or_else(|| usage("unknown rounding law", POLICY_USAGE))?;
        let policy = LotPolicy {
            account,
            law,
            regime,
            rounding_law,
        };
        let description = book.seal_text(
            args.flag("--description")
                .unwrap_or("Inventory lot cost-flow policy"),
        )?;
        let proposal = fa_journal::chart::lots::lot_policy_proposal(
            book.context(),
            principal,
            &policy,
            date(args)?,
            required(args, "--key")?.as_bytes(),
            description,
        )
        .map_err(fa::BookError::from)?;
        SchemaControlReview::new(proposal)
            .map_err(|error| usage(format!("lot-policy proposal: {error}"), POLICY_USAGE))?
    };
    let policy = match &intent.proposal().control {
        Some(fa_model::ControlPayload::SchemaChange {
            kind,
            canonical_bytes,
        }) if *kind == fa_journal::chart::lots::SCHEMA_CHANGE_LOT_POLICY => {
            LotPolicy::decode(canonical_bytes)
                .map_err(|error| usage(format!("lot policy: {error}"), POLICY_USAGE))?
        }
        _ => {
            return Err(usage(
                "review is not a lot-policy schema control",
                POLICY_USAGE,
            ));
        }
    };
    if review_only {
        return emit_review(
            &ctx.out,
            &ctx.files,
            args,
            &book,
            &intent,
            "lot_policy_review",
            vec![
                ("account_vid", s(format!("{:032x}", policy.account.0))),
                ("law", s(policy.law.name())),
                ("regime", s(policy.regime.as_str())),
                ("rounding_law", s(policy.rounding_law.name())),
            ],
        );
    }
    let recorded = book.set_lot_policy_proposal(
        intent.proposal().clone(),
        approvals(args, intent.proposal())?,
        &capability,
    )??;
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "lot_policy_recorded",
        vec![
            ("account_vid", s(format!("{:032x}", policy.account.0))),
            ("law", s(policy.law.name())),
            ("regime", s(policy.regime.as_str())),
            ("rounding_law", s(policy.rounding_law.name())),
            ("control_entry", s(format!("{:032x}", recorded.entry.vid.0))),
            ("entry_digest", s(hex(&recorded.entry.entry_digest))),
            ("recorded_at", Json::Int(i128::from(recorded.recorded_at.0))),
            ("already_recorded", Json::Bool(recorded.already_recorded)),
        ],
        &format!(
            "Lot policy: {} under {}, recorded at {}",
            policy.law.name(),
            policy.regime.as_str(),
            recorded.recorded_at.0
        ),
    );
    Ok(())
}

fn template(
    book: &mut Book,
    args: &Args,
    principal: fgdb_types::VId,
) -> Result<EntryPayload, Fail> {
    let key = required(args, "--key")?.as_bytes().to_vec();
    let book_id = book.context().book_id;
    Ok(EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL,
        effective_date: date(args)?,
        document_date: None,
        description: book.seal_text(
            args.flag("--description")
                .unwrap_or("Law-derived lot disposal"),
        )?,
        effective_period: None,
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

pub(crate) fn dispose_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 1 {
        return Err(usage("dispose has no positional operands", DISPOSE_USAGE));
    }
    options(
        args,
        &[
            "--account",
            "--quantity",
            "--quantity-offset",
            "--cost-offset",
            "--date",
            "--key",
            "--description",
            "--evidence",
            "--target",
            "--review",
            "--digest",
            "--review-out",
            "--plan-out",
        ],
        &["--dry-run", "--review-only"],
    )?;
    check_post_planning_options(args)?;
    let review_only = review_mode(args)?;
    let capability = ctx.capability(args, &["read", "post"])?;
    let principal = ctx.principal(args);
    let bound = ctx.authority().is_some();
    let mut book = ctx
        .books
        .open_admitted(args, |book| admit(book, &capability, Op::Post))?;
    let intent = if args.flag("--review").is_some() {
        if review_only
            || [
                "--account",
                "--quantity",
                "--quantity-offset",
                "--cost-offset",
                "--date",
                "--key",
                "--description",
                "--evidence",
                "--target",
            ]
            .iter()
            .any(|name| args.flag(name).is_some())
        {
            return Err(usage(
                "restoring a disposal review supplies the exact original proposal",
                "fa dispose --review <file|hex|-> --digest <review_digest> [--dry-run]",
            ));
        }
        restore::<PostIntent>(&ctx.files, bound, args, &book)?
    } else {
        if args.flag("--digest").is_some() {
            return Err(usage("--digest requires --review", DISPOSE_USAGE));
        }
        let units = &book.context().units;
        let quantity = fa_money::Amount::parse(required(args, "--quantity")?, units)
            .map_err(|error| usage(format!("--quantity: {error}"), DISPOSE_USAGE))?;
        let mut specific_ids = Vec::new();
        for raw in args.flag_all("--target") {
            let (id, ordinal) = raw.rsplit_once(':').ok_or_else(|| {
                usage(
                    "--target requires <entry-vid>:<quantity-leg-ordinal>",
                    DISPOSE_USAGE,
                )
            })?;
            let vid = parse_vid(id, "--target")?;
            let ordinal = ordinal
                .parse::<u16>()
                .map_err(|_| usage("invalid quantity-leg ordinal", DISPOSE_USAGE))?;
            let (entry, _) = book
                .read_scope(principal, &capability)??
                .read_entry(vid, None)??
                .ok_or_else(|| usage("the selected lot entry does not exist", DISPOSE_USAGE))?;
            specific_ids.push((
                EntryRef {
                    vid,
                    entry_digest: entry.entry_digest,
                },
                ordinal,
            ));
        }
        let book_id = book.context().book_id;
        let request = LotDisposalPostRequest {
            account: account_vid(book_id, required(args, "--account")?),
            quantity,
            quantity_offset_account: account_vid(book_id, required(args, "--quantity-offset")?),
            cost_offset_account: account_vid(book_id, required(args, "--cost-offset")?),
            specific_ids,
        };
        let template = template(&mut book, args, principal)?;
        let prepared = book.prepare_lot_disposal(&capability, &request, template)??;
        PostIntent::new(prepared.into_proposal(), Vec::new())
            .map_err(|error| usage(format!("disposal proposal: {error}"), DISPOSE_USAGE))?
    };
    let basis = intent
        .proposal()
        .lot_disposal_basis()
        .map_err(|error| usage(format!("lot disposal: {error}"), DISPOSE_USAGE))?
        .ok_or_else(|| usage("review has no lot-disposal basis", DISPOSE_USAGE))?;
    if intent.proposal().class != EntryClass::ORIGINAL {
        return Err(usage("review is not an Original disposal", DISPOSE_USAGE));
    }
    if review_only {
        let units = &book.context().units;
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
                    ("amount", s(render_amount(leg.amount, units)?)),
                    ("applications", Json::Int(leg.settles.len() as i128)),
                ]))
            })
            .collect::<Result<Vec<_>, Fail>>()?;
        return emit_review(
            &ctx.out,
            &ctx.files,
            args,
            &book,
            &intent,
            "lot_disposal_review",
            vec![
                ("account_vid", s(format!("{:032x}", basis.account.0))),
                ("known_at", Json::Int(i128::from(basis.known_at.0))),
                ("law", s(basis.law.name())),
                ("regime", s(basis.regime.as_str())),
                ("rounding_law", s(basis.rounding_law.name())),
                ("quantity", s(render_amount(basis.quantity, units)?)),
                ("policy_entry", s(format!("{:032x}", basis.policy.vid.0))),
                ("policy_digest", s(hex(&basis.policy.entry_digest))),
                ("legs", Json::Arr(legs)),
            ],
        );
    }
    if args.switch("--dry-run") {
        let plan = book.plan(intent, &capability)??;
        return emit_post_plan(&ctx.out, &book, &ctx.files, args, &plan, &capability);
    }
    let posted = book.post(fa_journal::PostRequest {
        proposal: intent.proposal().clone(),
        approvals: Vec::new(),
        capability,
        plan_certificate: None,
    })??;
    ctx.out.at_book(&book)?;
    emit_posted(&ctx.out, posted, "Original", false, None, None)
}
