//! Portable atomic batch rehearsal and commit on the shared CLI/MCP surface.

use std::collections::BTreeMap;

use fa::{BatchPlan, PostIntent};
use fa_model::{ControlPayload, Disposition, Entry, EntryClass, EntryPayload};
use fa_policy::Capability;
use fgdb_types::VId;

use super::{
    Args, Book, Condition, Ctx, Fail, Files, Json, Out, ReasonCodes, gate, hex, lineage_json, obj,
    parse_vid, render_amount, s, side_name, usage, write_post_plan,
};

pub(super) type PriorEntries = BTreeMap<VId, Entry>;

/// Existing immutable entries win on retries: rebuilding an intent can give
/// its private fields fresh seal salts without changing its semantic request.
/// Otherwise only an earlier member can supply a target. No forward lookup or
/// unchecked digest supplied by the caller is accepted here.
pub(super) fn target_entry(
    book: &Book,
    earlier: &PriorEntries,
    vid: VId,
) -> Result<Option<Entry>, Fail> {
    Ok(book
        .read_entry(vid)?
        .map(|(entry, _)| entry)
        .or_else(|| earlier.get(&vid).cloned()))
}

pub(super) fn proposal_vid(proposal: &EntryPayload) -> Result<VId, Fail> {
    match proposal.class {
        EntryClass::REVERSAL => proposal
            .supersession
            .first()
            .map(|link| fa_journal::rows::reversal_vid(link.target.vid)),
        EntryClass::RESOLUTION => proposal
            .pending
            .as_ref()
            .and_then(|pending| pending.resolution_of)
            .map(|target| fa_journal::rows::resolution_vid(target.vid)),
        _ => Some(fa_model::entry_vid(
            proposal.book_id,
            &proposal.principal_ref.0.to_le_bytes(),
            &proposal.idempotency_key,
        )),
    }
    .ok_or_else(|| {
        usage(
            "batch member has no identity target",
            "check reverses or resolves",
        )
    })
}

fn entry_vid(entry: &Entry) -> Result<VId, Fail> {
    proposal_vid(&entry.proposal)
}

/// Resolve unpublished targets from the owner's retained reviewed entries.
/// A capped request's original amount is not its admitted Entry: only the
/// retained native entries supply digests and legs for dependent requests.
/// Those targets survive discard or availability drift for exact retries;
/// the kernel still revalidates the complete draft before any new append.
/// Published targets need no draft lookup, preserving post-promotion retries.
pub(super) fn draft_entries(
    book: &mut Book,
    capability: &Capability,
    name: &str,
    doc: &Json,
) -> Result<PriorEntries, Fail> {
    let mut targets = Vec::new();
    for field in [
        "reverses",
        "resolves",
        "reclassifies",
        "revises",
        "restates",
    ] {
        if let Some(target) = doc.get(field).and_then(Json::as_str) {
            targets.push(parse_vid(target, field)?);
        }
    }
    if let Some(legs) = doc.get("legs").and_then(Json::as_arr) {
        for leg in legs {
            if let Some(settles) = leg.get("settles").and_then(Json::as_arr) {
                for settlement in settles {
                    if let Some(target) = settlement.get("entry").and_then(Json::as_str) {
                        targets.push(parse_vid(target, "settles.entry")?);
                    }
                }
            }
        }
    }
    if targets.is_empty() {
        return Ok(PriorEntries::new());
    }
    fa_policy::require(
        capability,
        fa_policy::Op::Post,
        "preparing a draft dependency",
    )
    .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
    .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    book.admit_current(capability)??;
    for target in targets {
        if book.read_entry(target)?.is_none() {
            let mut earlier = PriorEntries::new();
            for entry in book.draft_entries(capability, name)?? {
                let vid = entry_vid(&entry)?;
                if earlier.insert(vid, entry).is_some() {
                    return Err(Fail::Internal(
                        "a retained draft repeats an entry identity".into(),
                    ));
                }
            }
            return Ok(earlier);
        }
    }
    Ok(PriorEntries::new())
}

pub(super) fn remember(earlier: &mut PriorEntries, intent: &PostIntent) -> Result<(), Fail> {
    let entry = intent
        .proposal()
        .clone()
        .seal(intent.approvals().to_vec(), None)
        .map_err(|error| usage(format!("batch member: {error}"), "check the member intent"))?;
    let vid = entry_vid(&entry)?;
    if earlier.insert(vid, entry).is_some() {
        return Err(usage(
            format!(
                "two batch members target the same entry identity {:032x}",
                vid.0
            ),
            "give ordinary members distinct keys and reverse or resolve each target only once",
        ));
    }
    Ok(())
}

fn releases(entry: &Entry) -> bool {
    matches!(
        entry
            .proposal
            .pending
            .as_ref()
            .and_then(|p| p.disposition.as_ref()),
        Some(Disposition::Voids)
    ) || matches!(
        entry.proposal.control,
        Some(ControlPayload::ReservationRelease)
    )
}

pub(super) fn emit(
    out: &Out,
    book: &Book,
    files: &Files,
    args: &Args,
    plan: &BatchPlan,
) -> Result<(), Fail> {
    let encode = |error| Fail::Internal(format!("encode admitted batch plan: {error}"));
    let bytes = plan.canonical_bytes().map_err(encode)?;
    let plan_digest = hex(&plan.digest().map_err(encode)?);
    let certificate_digest = hex(&plan.certificate_digest().map_err(encode)?);
    let certificate = plan.certificate();
    let accounts: BTreeMap<_, _> = book.accounts()?.into_iter().map(|a| (a.vid, a)).collect();
    let reasons = ReasonCodes::embedded().map_err(|error| Fail::Internal(error.to_string()))?;
    let mut members = Vec::new();
    let mut human = format!(
        "Planned {} entries atomically at sequence {}; nothing was written.\nCertificate {certificate_digest}",
        plan.prepared_entries().len(),
        certificate.snapshot_seq.0
    );
    for (index, ((intent, entry), period)) in plan
        .batch()
        .members()
        .iter()
        .zip(plan.prepared_entries())
        .zip(plan.periods())
        .enumerate()
    {
        let proposal = &entry.proposal;
        let vid = entry_vid(entry)?;
        human.push_str(&format!(
            "\n{index}: {} {:032x}, effective {} in {period}:",
            proposal.class.name().unwrap_or("?"),
            vid.0,
            proposal.effective_date
        ));
        let mut legs = Vec::new();
        for (ordinal, leg) in proposal.legs.iter().enumerate() {
            let account = accounts
                .get(&leg.account_ref)
                .ok_or_else(|| Fail::Internal("an admitted batch account is absent".into()))?;
            let amount = render_amount(leg.amount, &book.context().units)?;
            human.push_str(&format!(
                "\n  {} {} {amount}",
                side_name(leg.side),
                account.code
            ));
            let mut settlements = Vec::new();
            for settlement in &leg.settles {
                let amount = render_amount(settlement.amount, &book.context().units)?;
                human.push_str(&format!(
                    "\n    applies {amount} to {:032x}:{}",
                    settlement.target.vid.0, settlement.ordinal
                ));
                settlements.push(obj(vec![
                    ("entry", s(format!("{:032x}", settlement.target.vid.0))),
                    ("entry_digest", s(hex(&settlement.target.entry_digest))),
                    ("ordinal", Json::Int(i128::from(settlement.ordinal))),
                    ("amount", s(amount)),
                ]));
            }
            legs.push(obj(vec![
                ("ordinal", Json::Int(ordinal as i128)),
                ("account", s(&account.code)),
                ("account_vid", s(format!("{:032x}", leg.account_ref.0))),
                ("side", s(side_name(leg.side))),
                ("amount", s(amount)),
                (
                    "base_amount",
                    leg.base_amount
                        .map(|amount| render_amount(amount, &book.context().units))
                        .transpose()?
                        .map_or(Json::Null, s),
                ),
                ("settles", Json::Arr(settlements)),
                (
                    "dimensions",
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
            ]));
        }
        let pending = proposal.pending.as_ref();
        members.push(obj(vec![
            ("index", Json::Int(index as i128)),
            ("vid", s(format!("{:032x}", vid.0))),
            ("class", s(proposal.class.name().unwrap_or("?"))),
            ("effective_date", s(proposal.effective_date.render())),
            ("period", s(period)),
            ("idempotency_key", s(hex(&proposal.idempotency_key))),
            ("intent_digest", s(hex(&intent.digest().map_err(encode)?))),
            ("proposal_digest", s(hex(&entry.proposal_digest))),
            ("entry_digest", s(hex(&entry.entry_digest))),
            ("legs", Json::Arr(legs)),
            (
                "resolves",
                pending
                    .and_then(|p| p.resolution_of)
                    .map_or(Json::Null, |target| s(format!("{:032x}", target.vid.0))),
            ),
            (
                "disposition",
                pending
                    .and_then(|p| p.disposition.as_ref())
                    .map_or(Json::Null, |d| {
                        s(match d {
                            Disposition::Posts { .. } => "posts",
                            Disposition::Voids => "voids",
                            Disposition::Expires { .. } => "expires",
                        })
                    }),
            ),
            (
                "supersedes",
                Json::Arr(
                    proposal
                        .supersession
                        .iter()
                        .map(|link| lineage_json(link, &reasons))
                        .collect(),
                ),
            ),
            (
                "evidence",
                Json::Arr(
                    proposal
                        .evidence
                        .iter()
                        .map(|evidence| {
                            obj(vec![
                                ("document_oid", s(hex(&evidence.document_oid.0))),
                                ("doc_commit", s(hex(&evidence.doc_commit))),
                                ("role", Json::Int(i128::from(evidence.role))),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("approvals", Json::Int(entry.approvals.len() as i128)),
        ]));
    }

    let rehearsal = out.is_bound_agent();
    let bound_release = !out.can_confirm() && plan.prepared_entries().iter().any(releases);
    let command = if !out.can_confirm() {
        "fa_post_commit_plan".to_string()
    } else if out.is_bound() {
        super::operator_command(
            args,
            &format!(
                "commit --plan {}",
                super::quoted_argument(args.flag("--plan-out").unwrap_or("-"))
            ),
        )
    } else {
        let quote = |word: &str| format!("'{}'", word.replace('\'', "'\\''"));
        let mut command = format!(
            "fa commit --plan {}",
            quote(args.flag("--plan-out").unwrap_or("-"))
        );
        for flag in ["--book", "--keys", "--as"] {
            if let Some(value) = args.flag(flag) {
                command.push_str(&format!(" {flag} {}", quote(value)));
            }
        }
        for grant in args.flag_all("--grant") {
            command.push_str(&format!(" --grant {}", quote(grant)));
        }
        if plan.prepared_entries().iter().any(|entry| {
            entry.proposal.base_totals.is_some() && entry.proposal.class != EntryClass::REVERSAL
        }) && !args.flag_all("--grant").contains(&"read")
        {
            command.push_str(" --grant 'read'");
        }
        command.push_str(" --json");
        command
    };
    let actions = if rehearsal || bound_release {
        let warning = if rehearsal {
            "This Agent-profile batch is a rehearsal and cannot commit to trunk (FA-REF-013). A Human must independently prepare and review the batch; atomic batch drafts are not supported."
        } else {
            "MCP cannot confirm a batch that releases a reservation. Ask the operator to independently prepare, review and confirm the complete batch."
        };
        out.warn(warning);
        human.push_str(&format!("\n{warning}"));
        Vec::new()
    } else {
        human.push_str(&format!("\nReview every member, then {command}"));
        vec![(command, if out.is_bound() && out.can_confirm() {
            super::OPERATOR_PLAN_GUIDANCE
        } else {
            "commit the complete artifact with the same independently supplied capability; forward data.bytes when the input is stdin"
        }.into())]
    };
    human.push_str(
        "\nAny intervening book publication requires a fresh plan before its first commit.",
    );
    let encoded = hex(&bytes);
    if let Some(path) = args.flag("--plan-out") {
        write_post_plan(files, path, &bytes)?;
    } else {
        human.push_str(&format!(
            "\nComplete canonical plan bytes (hex):\n{encoded}"
        ));
    }
    out.at_book(book)?;
    out.known_at(certificate.snapshot_seq);
    out.event_with_actions(
        "batch_plan",
        vec![
            ("intent_kind", s("PostBatch")),
            ("idempotency_key", s(hex(plan.batch().idempotency_key()))),
            ("principal", s(format!("{:032x}", certificate.principal.0))),
            ("intent_digest", s(hex(&certificate.intent_digest))),
            ("prepared_digest", s(hex(&certificate.prepared_digest))),
            ("effects_digest", s(hex(&certificate.effects_digest))),
            (
                "snapshot_seq",
                Json::Int(i128::from(certificate.snapshot_seq.0)),
            ),
            (
                "security_policy_epoch",
                Json::Int(i128::from(certificate.security_policy_epoch)),
            ),
            (
                "expires_at",
                certificate
                    .expires_at
                    .map_or(Json::Null, |seq| Json::Int(i128::from(seq.0))),
            ),
            (
                "capability_commitment",
                s(hex(&certificate.capability_commitment)),
            ),
            ("certificate_digest", s(certificate_digest)),
            ("plan_digest", s(plan_digest)),
            ("members", Json::Arr(members)),
            ("bytes", s(encoded)),
            ("file", args.flag("--plan-out").map_or(Json::Null, s)),
            ("scope", s("same-snapshot-batch")),
            ("authority", s(out.authority_posture())),
        ],
        &human,
        &actions,
    );
    Ok(())
}

pub(super) fn commit(ctx: &mut Ctx<'_>, args: &Args, plan: BatchPlan) -> Result<(), Fail> {
    // A portable artifact cannot grant the bound host independent dangerous-
    // operation confirmation. Inspect every member before opening the book.
    for entry in plan.prepared_entries() {
        if !ctx.out.can_confirm() && releases(entry) {
            gate(&ctx.out, args, "resolve", None, &Condition::Voids)?;
        }
        if entry.proposal.class == EntryClass::CLOSING {
            gate(
                &ctx.out,
                args,
                "close",
                Some("year-end"),
                &Condition::Always,
            )?;
        }
    }
    let encode = |error| {
        usage(
            format!("batch plan: {error}"),
            "pass the unchanged artifact from --dry-run",
        )
    };
    let plan_digest = hex(&plan.digest().map_err(encode)?);
    let certificate_digest = hex(&plan.certificate_digest().map_err(encode)?);
    let classes: Vec<_> = plan
        .prepared_entries()
        .iter()
        .map(|entry| entry.proposal.class)
        .collect();
    let capability = ctx.capability(args, &["post"])?;
    let mut book = ctx.books.open(args)?;
    let posted = match book.commit_batch_plan(plan.clone(), &capability)? {
        Ok(posted) => posted,
        Err(refusal) if refusal.code == fa_journal::refusal::code::PLAN_INVALIDATED => {
            let replanned = match book.replan_batch(&plan, &capability)? {
                Ok(replanned) => Ok(super::fresh_batch(replanned)?),
                Err(replan) => Err(replan),
            };
            return Err(super::stale_plan(refusal, replanned, &ctx.out, args));
        }
        Err(refusal) => return Err(refusal.into()),
    };
    let members = posted
        .entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            obj(vec![
                ("index", Json::Int(index as i128)),
                ("vid", s(format!("{:032x}", entry.vid.0))),
                ("entry_digest", s(hex(&entry.entry_digest))),
                (
                    "class",
                    classes
                        .get(index)
                        .and_then(|class| class.name())
                        .map_or(Json::Null, s),
                ),
                ("period", posted.periods.get(index).map_or(Json::Null, s)),
            ])
        })
        .collect();
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "batch_plan_committed",
        vec![
            ("outcome", s(format!("{:032x}", posted.outcome.0))),
            ("recorded_at", Json::Int(i128::from(posted.recorded_at.0))),
            ("already_recorded", Json::Bool(posted.already_recorded)),
            ("members", Json::Arr(members)),
            ("plan_digest", s(plan_digest)),
            ("certificate_digest", s(certificate_digest)),
        ],
        &format!(
            "{} atomic batch at sequence {}: {} entries, outcome {:032x}",
            if posted.already_recorded {
                "Already committed"
            } else {
                "Committed"
            },
            posted.recorded_at.0,
            posted.entries.len(),
            posted.outcome.0
        ),
    );
    Ok(())
}
