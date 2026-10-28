//! Retain an exact correction pair across independent approval publications.

use super::*;

const EXAMPLE: &str = "fa replace --review <file|hex|-> --digest <review_digest> [--approval <replacement-approval-vid>]... [--reversal-approval <reversal-approval-vid>]... [--dry-run [--plan-out <new-file>] | --draft <name>]";

/// All mode decisions precede file and target observation. A review contains
/// the complete proposal; restore never silently ignores caller overrides.
pub(super) fn options(args: &Args, restoring: bool) -> Result<(), Fail> {
    check_post_planning_options(args)?;
    for flag in ["--review", "--digest", "--review-out", "--draft"] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("a correction takes only one {flag}"),
                EXAMPLE,
            ));
        }
    }
    let creating = args.switch("--review-only") || args.flag("--review-out").is_some();
    if creating
        && (restoring
            || args.switch("--dry-run")
            || args.flag("--plan-out").is_some()
            || args.flag("--draft").is_some()
            || args.switch("--yes"))
    {
        return Err(usage(
            "create an unapproved correction review separately from restoration, planning, draft retention or confirmation; nothing was posted",
            "fa replace <vid> --reason <name> --intent <corrected.json|-> --review-only (or --review-out <new-file>)",
        ));
    }
    if args.flag("--draft").is_some()
        && (args.switch("--dry-run") || args.flag("--plan-out").is_some() || args.switch("--yes"))
    {
        return Err(usage(
            "--draft retains a correction for independent promotion and cannot be combined with --dry-run, --plan-out or --yes",
            "retain the pair with --draft <name>; the independent promoter later uses fa draft promote <name> --yes",
        ));
    }
    if restoring {
        for flag in [
            "--intent",
            "--replace-with",
            "--reason",
            "--effective",
            "--period",
            "--key",
            "--description",
            "--evidence",
        ] {
            if !args.flag_all(flag).is_empty() {
                return Err(usage(
                    format!(
                        "the correction review supplies both complete unchanged proposals; it takes no {flag}"
                    ),
                    EXAMPLE,
                ));
            }
        }
    } else if ["--digest", "--approval", "--reversal-approval"]
        .iter()
        .any(|flag| !args.flag_all(flag).is_empty())
    {
        return Err(usage(
            "correction approvals bind the exact sealed members of a retained review",
            EXAMPLE,
        ));
    }
    Ok(())
}

pub(super) fn restore(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(args, true)?;
    if !(1..=2).contains(&args.positional.len()) {
        return Err(usage(
            "a restored correction takes at most one optional target",
            EXAMPLE,
        ));
    }
    let expected = parse_digest(
        args.require("--digest", "<review_digest>")?,
        "review digest",
    )?;
    let path = args.require("--review", "<file|hex|->")?;
    let bytes = read_review_bytes(&ctx.files, path, ctx.out.is_bound())?;
    let review = ReplacementReview::decode(&bytes)
        .map_err(|error| usage(format!("invalid correction review: {error}"), EXAMPLE))?;
    if let Some(supplied) = args.positional.get(1) {
        let vid = parse_vid(
            supplied.strip_prefix("E:").unwrap_or(supplied),
            "correction target",
        )?;
        if vid != review.target().vid {
            return Err(usage(
                "the supplied target differs from the retained correction review",
                EXAMPLE,
            ));
        }
    }
    let approvals = |flag: &str, member: &PostIntent| -> Result<Vec<fa_model::ApprovalRef>, Fail> {
        let digest = member
            .proposal()
            .proposal_digest()
            .map_err(|error| Fail::Internal(format!("correction proposal digest: {error}")))?;
        args.flag_all(flag)
            .iter()
            .map(|value| {
                Ok(fa_model::ApprovalRef {
                    approval_vid: parse_vid(value, flag)?,
                    approved_digest: digest,
                })
            })
            .collect()
    };
    let (reversal, replacement) = review
        .with_approvals(
            expected,
            approvals("--reversal-approval", review.reversal())?,
            approvals("--approval", review.replacement())?,
        )
        .map_err(|error| {
            usage(
                format!("cannot restore correction review: {error}"),
                EXAMPLE,
            )
        })?;
    let capability = ctx.capability(args, &["post"])?;
    let out = &ctx.out;
    let mut book = ctx.books.open_admitted(args, |book| {
        // The artifact supplies no identity or authority. Current issuance,
        // expiry and revocation are checked before the book coordinate is
        // disclosed, and native pair admission checks every member afterwards.
        book.admit_current(&capability)??;
        fa_policy::require(
            &capability,
            fa_policy::Op::Post,
            "restoring a correction review",
        )
        .and_then(|()| fa_policy::reach(&capability, &fa_policy::Reach::whole_book(true), None))
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        Ok(())
    })?;
    let request = |intent: PostIntent| PostRequest {
        proposal: intent.proposal().clone(),
        approvals: intent.approvals().to_vec(),
        plan_certificate: None,
        capability: capability.clone(),
    };
    finish(
        out,
        &mut book,
        &ctx.files,
        args,
        request(reversal),
        request(replacement),
    )
}

/// New and restored pairs use precisely the same native paths. Creating an
/// unapproved review exits before the kernel; every actual rehearsal or write
/// uses the ordinary approval and period-law gates, without fabricated refs.
pub(super) fn finish(
    out: &Out,
    book: &mut Book,
    files: &Files,
    args: &Args,
    reversal_req: PostRequest,
    replacement_req: PostRequest,
) -> Result<(), Fail> {
    let capability = reversal_req.capability.clone();
    let reversal = PostIntent::new(
        reversal_req.proposal.clone(),
        reversal_req.approvals.clone(),
    )
    .map_err(|error| usage(format!("correction reversal: {error}"), EXAMPLE))?;
    let replacement = PostIntent::new(
        replacement_req.proposal.clone(),
        replacement_req.approvals.clone(),
    )
    .map_err(|error| usage(format!("correction replacement: {error}"), EXAMPLE))?;
    if args.switch("--review-only") || args.flag("--review-out").is_some() {
        let review = ReplacementReview::new(reversal, replacement)
            .map_err(|error| usage(format!("cannot retain correction review: {error}"), EXAMPLE))?;
        return emit(out, book, files, args, &review);
    }
    if let Some(name) = args.flag("--draft") {
        let planned = book.plan_correction_into_draft(
            capability,
            name,
            reversal.clone(),
            replacement.clone(),
        )??;
        return batch_plan::emit_draft_members(
            out,
            book,
            name,
            &[reversal, replacement],
            &planned,
            "atomic correction",
        );
    }
    if args.switch("--dry-run") || out.is_bound_agent() {
        let plan = book.plan_replacement(reversal, replacement, &capability)??;
        return emit_replacement_plan(out, book, files, args, &plan);
    }
    let target = reversal_req
        .proposal
        .supersession
        .first()
        .ok_or_else(|| Fail::Internal("a correction has no reversal target".into()))?;
    let target_hex = format!("{:032x}", target.target.vid.0);
    let reason = reversal_reason(Some(&s(target.reason_code.to_string())))?;
    let (reversal_posted, replacement_posted) =
        book.post_replacement_pair(reversal_req, replacement_req)??;
    out.at_book(book)?;
    let entry = |posted: &Posted| match posted {
        Posted::Committed {
            entry_ref, period, ..
        } => (*entry_ref, s(period.as_str())),
        Posted::AlreadyRecorded { entry_ref, .. } => (*entry_ref, Json::Null),
    };
    let (reversal_ref, reversal_period) = entry(&reversal_posted);
    let (replacement_ref, replacement_period) = entry(&replacement_posted);
    let already = matches!(replacement_posted, Posted::AlreadyRecorded { .. });
    let recorded_at = replacement_posted.recorded_at();
    out.event(
        "corrected",
        vec![
            ("target", s(&target_hex)),
            ("reason_code", Json::Int(i128::from(reason.code))),
            ("reason", s(&reason.name)),
            ("reversal", s(format!("{:032x}", reversal_ref.vid.0))),
            ("reversal_digest", s(hex(&reversal_ref.entry_digest))),
            ("replacement", s(format!("{:032x}", replacement_ref.vid.0))),
            ("replacement_digest", s(hex(&replacement_ref.entry_digest))),
            ("recorded_at", Json::Int(i128::from(recorded_at.0))),
            ("already_recorded", Json::Bool(already)),
            ("reversal_period", reversal_period),
            ("replacement_period", replacement_period),
        ],
        &if already {
            format!("correction of {target_hex} already recorded at {} (reversal {:032x}, replacement {:032x}); nothing new was written", recorded_at.0, reversal_ref.vid.0, replacement_ref.vid.0)
        } else {
            format!("corrected {target_hex}: reversal {:032x} and replacement {:032x}, recorded together at {} · reason {}", reversal_ref.vid.0, replacement_ref.vid.0, recorded_at.0, reason.name)
        },
    );
    Ok(())
}

fn emit(
    out: &Out,
    book: &Book,
    files: &Files,
    args: &Args,
    review: &ReplacementReview,
) -> Result<(), Fail> {
    let encode = |error| Fail::Internal(format!("correction review: {error}"));
    let bytes = review.canonical_bytes().map_err(encode)?;
    let digest = review.digest().map_err(encode)?;
    let accounts: std::collections::BTreeMap<_, _> = book
        .accounts()?
        .into_iter()
        .map(|account| (account.vid, account.code))
        .collect();
    let mut human = format!(
        "Retained the exact unapproved correction of {:032x}; neither correction entry was published.",
        review.target().vid.0
    );
    if out.is_bound() {
        human.push_str(
            " This bound delivery recorded its required AccessEvent before disclosing the review.",
        );
    }
    let mut members = Vec::new();
    for member in [review.reversal(), review.replacement()] {
        let proposal = member.proposal();
        let proposal_digest = proposal
            .proposal_digest()
            .map_err(|error| Fail::Internal(format!("correction proposal digest: {error}")))?;
        human.push_str(&format!(
            "\n{} effective {} · proposal {}:",
            proposal.class.name().unwrap_or("?"),
            proposal.effective_date,
            hex(&proposal_digest)
        ));
        let legs = proposal
            .legs
            .iter()
            .enumerate()
            .map(|(ordinal, leg)| {
                let account = accounts.get(&leg.account_ref).ok_or_else(|| {
                    Fail::Internal("a correction review account is absent".into())
                })?;
                let amount = render_amount(leg.amount, &book.context().units)?;
                human.push_str(&format!("\n  {} {account} {amount}", side_name(leg.side)));
                Ok(obj(vec![
                    ("ordinal", Json::Int(ordinal as i128)),
                    ("account", s(account)),
                    ("account_vid", s(format!("{:032x}", leg.account_ref.0))),
                    ("side", s(side_name(leg.side))),
                    ("amount", s(amount)),
                    ("dimensions", plan_dimensions_json(&leg.dimension_set)),
                ]))
            })
            .collect::<Result<Vec<_>, Fail>>()?;
        members.push(obj(vec![
            ("class", s(proposal.class.name().unwrap_or("?"))),
            ("effective_date", s(proposal.effective_date.render())),
            (
                "period",
                proposal
                    .effective_period
                    .as_ref()
                    .map_or(Json::Null, |period| s(&period.code)),
            ),
            ("idempotency_key", s(hex(&proposal.idempotency_key))),
            ("proposal_digest", s(hex(&proposal_digest))),
            ("legs", Json::Arr(legs)),
        ]));
    }
    if let Some(path) = args.flag("--review-out") {
        write_review_file(files, path, &bytes)?;
    }
    human.push_str(&format!(
        "\nApprove each required member's proposal_digest with fa approve --proposal <digest>. Restore the unchanged pair with fa replace --review <file|hex|-> --digest {} --approval <replacement-approval-vid> (and --reversal-approval for the reversal). The kernel will then check all current laws and approvals; this review is not a successful rehearsal or a posting permit.",
        hex(&digest)
    ));
    out.event(
        "replacement_reviewed",
        vec![
            ("target", s(format!("{:032x}", review.target().vid.0))),
            ("target_digest", s(hex(&review.target().entry_digest))),
            (
                "principal",
                s(format!(
                    "{:032x}",
                    review.reversal().proposal().principal_ref.0
                )),
            ),
            ("review_digest", s(hex(&digest))),
            ("members", Json::Arr(members)),
            ("bytes", s(hex(&bytes))),
            ("file", args.flag("--review-out").map_or(Json::Null, s)),
        ],
        &human,
    );
    Ok(())
}
