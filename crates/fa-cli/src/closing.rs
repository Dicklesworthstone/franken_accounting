//! Mechanical fiscal-year closing through the real posting kernel.
//!
//! A portable review is the existing canonical PostIntent: its sealed proposal
//! survives approval commits. The intrinsic basis is independently recomputed
//! during native planning; a PostPlan then guards the publication frontier.

mod draft_review;
pub(crate) use draft_review::render_draft_diff;

use std::collections::BTreeMap;

use fa::{Book, ClosingResidual, PostIntent, PreparedYearEndClose, YearEndCloseRequest};
use fa_model::{
    ApprovalRef, EntryClass, EntryOrigin, EntryPayload, Id128, Oid, PeriodRef, account_vid,
    domain_digest,
};
use fa_money::{Amount, Side};
use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

use crate::args::Args;
use crate::cli::{
    Ctx, Fail, check_post_planning_options, emit_post_plan, emit_posted, hex, parse_digest,
    parse_vid, read_review_bytes, render_amount, usage, write_review_file,
};
use crate::json::{Json, obj, s};

const EXAMPLE: &str =
    "fa close year-end --fiscal-year 2026 --period FY2026-CLOSE --key close-2026 --review-only";
const FLAGS: &[&str] = &[
    "--fiscal-year",
    "--period",
    "--key",
    "--description",
    "--evidence",
    "--approval",
    "--review",
    "--review-out",
    "--digest",
    "--plan-out",
    "--route",
    "--effective-from",
    "--as-of",
    "--as-known-at",
    "--draft",
    "--certificate-out",
];
const SWITCHES: &[&str] = &["--dry-run", "--review-only", "--certify"];

pub(crate) fn close_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "close needs one subcommand and named options",
            EXAMPLE,
        ));
    }
    match args.positional[1].as_str() {
        "map" => set_routes(ctx, args),
        "routes" => show_routes(ctx, args),
        "year-end" => year_end(ctx, args),
        "dry-run" => draft_review::run(ctx, args),
        _ => Err(usage(
            "close has map, routes, year-end and dry-run subcommands",
            EXAMPLE,
        )),
    }
}

fn options(args: &Args, flags: &[&str], switches: &[&str]) -> Result<(), Fail> {
    for flag in FLAGS {
        let values = args.flag_all(flag);
        if !values.is_empty() && !flags.contains(flag) {
            return Err(usage(
                format!("{flag} is not used by this close operation"),
                EXAMPLE,
            ));
        }
        if values.len() > 1 && !matches!(*flag, "--route" | "--evidence" | "--approval") {
            return Err(usage(format!("{flag} must be supplied only once"), EXAMPLE));
        }
    }
    for switch in SWITCHES {
        if args.switch(switch) && !switches.contains(switch) {
            return Err(usage(
                format!("{switch} is not used by this close operation"),
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
            format!("{flag} {value}: {error:?}"),
            format!("{flag} YYYY-MM-DD"),
        )
    })
}

fn fiscal_year(value: &str) -> Result<i32, Fail> {
    value
        .strip_prefix("FY")
        .unwrap_or(value)
        .parse()
        .map_err(|_| {
            usage(
                "fiscal year must be an integer or FY followed by an integer",
                EXAMPLE,
            )
        })
}

fn known_at(args: &Args) -> Result<Option<CommitSeq>, Fail> {
    args.flag("--as-known-at")
        .map(|value| {
            value.parse::<u64>().map(CommitSeq).map_err(|_| {
                usage(
                    "--as-known-at requires a recorded sequence",
                    "--as-known-at <sequence>",
                )
            })
        })
        .transpose()
}

fn require_ops(capability: &fa::Capability, ops: &[fa::Op]) -> Result<(), Fail> {
    for op in ops {
        fa_policy::require(capability, *op, "year-end closing")
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    }
    Ok(())
}

/// Admit current whole-book reads and their scope before the CLI stamps a
/// book coordinate or reads a caller-specified review file.
fn admit_history(book: &Book, capability: &fa::Capability) -> Result<(), Fail> {
    let _ = book.closing_routes_at(DateDay(0), None, capability)??;
    Ok(())
}

fn set_routes(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &["--route", "--effective-from", "--key", "--description"],
        &[],
    )?;
    let effective_from = day(args, "--effective-from")?;
    let key = required(args, "--key")?;
    let pairs = args.flag_all("--route");
    if pairs.is_empty() {
        return Err(usage(
            "a complete closing map needs at least one --route <nominal>:<equity>",
            "fa close map --route 4000:3000 --route 6000:3000 --effective-from 2026-01-01 --key close-map-2026",
        ));
    }
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read", "schema_change"])?;
    require_ops(&capability, &[fa::Op::Read, fa::Op::SchemaChange])?;
    let mut book = ctx
        .books
        .open_admitted(args, |book| admit_history(book, &capability))?;
    let mut routes = BTreeMap::new();
    for pair in pairs {
        let Some((source, equity)) = pair.split_once(':').filter(|(source, equity)| {
            !source.is_empty() && !equity.is_empty() && !equity.contains(':')
        }) else {
            return Err(usage(
                "--route requires <nominal-account-code>:<equity-account-code>",
                EXAMPLE,
            ));
        };
        let source = account_vid(book.context().book_id, source);
        let equity = account_vid(book.context().book_id, equity);
        if routes.insert(source, equity).is_some() {
            return Err(usage(
                "a closing map repeats a nominal account",
                "include each nominal account once",
            ));
        }
    }
    let count = routes.len();
    let description = book.seal_text(
        args.flag("--description")
            .unwrap_or("Year-end closing routes"),
    )?;
    let recorded = book.set_closing_routes(
        fa::ClosingRoutesRequest {
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
        "closing_routes_recorded",
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
        &format!("closing routes: {count} nominal accounts, effective {effective_from}"),
    );
    Ok(())
}

fn show_routes(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(args, &["--as-of", "--as-known-at"], &[])?;
    let effective = day(args, "--as-of")?;
    let requested_at = known_at(args)?;
    let capability = ctx.capability(args, &["read"])?;
    let mut selected = None;
    ctx.books.open_admitted(args, |book| {
        let routes = book.closing_routes_at(effective, requested_at, &capability)??;
        let at = match requested_at {
            Some(at) => at,
            None => book.head()?,
        };
        let accounts = book.accounts_at(at, &capability)??;
        selected = Some((at, routes, accounts));
        Ok(())
    })?;
    let (at, routes, accounts) =
        selected.ok_or_else(|| Fail::Internal("closing routing history is missing".into()))?;
    let accounts: BTreeMap<_, _> = accounts
        .into_iter()
        .map(|row| (row.vid, row.code))
        .collect();
    let rows = routes
        .as_ref()
        .map(|map| {
            map.routes
                .iter()
                .map(|(source, equity)| {
                    obj(vec![
                        (
                            "account",
                            s(accounts.get(source).map(String::as_str).unwrap_or("")),
                        ),
                        ("account_vid", s(format!("{:032x}", source.0))),
                        (
                            "closes_to",
                            s(accounts.get(equity).map(String::as_str).unwrap_or("")),
                        ),
                        ("equity_vid", s(format!("{:032x}", equity.0))),
                    ])
                })
                .collect()
        })
        .unwrap_or_default();
    ctx.out.known_at(at);
    ctx.out.effective(format!("as-of:{effective}"));
    ctx.out.event(
        "closing_routes",
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
        &format!(
            "closing routes as of {effective}, recorded through {}",
            at.0
        ),
    );
    Ok(())
}

fn residuals(rows: &[ClosingResidual], book: &Book) -> Result<Json, Fail> {
    Ok(Json::Arr(
        rows.iter()
            .map(|row| {
                Ok(obj(vec![
                    ("account", s(&row.account_code)),
                    ("account_vid", s(format!("{:032x}", row.account.0))),
                    ("closes_to", s(format!("{:032x}", row.closes_to.0))),
                    (
                        "entity",
                        row.entity
                            .map_or(Json::Null, |entity| s(format!("{:032x}", entity.0))),
                    ),
                    ("unit_id", Json::Int(i128::from(row.unit.0))),
                    (
                        "net",
                        s(render_amount(
                            Amount::new(row.unit, row.net),
                            &book.context().units,
                        )?),
                    ),
                ]))
            })
            .collect::<Result<Vec<_>, Fail>>()?,
    ))
}

fn leg_preview(proposal: &EntryPayload, book: &Book) -> Result<Json, Fail> {
    let accounts: BTreeMap<_, _> = book
        .accounts()?
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
                    Fail::Internal("prepared closing leg names a missing account".into())
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
                ]))
            })
            .collect::<Result<Vec<_>, Fail>>()?,
    ))
}

fn proposal(
    book: &mut Book,
    args: &Args,
    prepared: &PreparedYearEndClose,
    principal: VId,
) -> Result<EntryPayload, Fail> {
    let key = required(args, "--key")?;
    let evidence = crate::document::parse_evidence(&obj(Vec::new()), args, book)?;
    let book_id = book.context().book_id;
    let description = args.flag("--description").map_or_else(
        || format!("Year-end close FY{}", prepared.request().fiscal_year),
        str::to_string,
    );
    Ok(prepared.proposal(EntryPayload {
        schema_minor: 1,
        book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::CLOSING,
        effective_date: prepared.closing_date(),
        document_date: None,
        description: book.seal_text(&description)?,
        effective_period: Some(PeriodRef {
            calendar: book.context().calendar.id.clone(),
            code: prepared.request().closing_period.clone(),
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

fn year_end(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &[
            "--fiscal-year",
            "--period",
            "--key",
            "--description",
            "--evidence",
            "--approval",
            "--review",
            "--review-out",
            "--digest",
            "--plan-out",
        ],
        SWITCHES,
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
    let capability = ctx.capability(args, &["read", "post", "close"])?;
    require_ops(&capability, &[fa::Op::Read, fa::Op::Post, fa::Op::Close])?;
    let bound = ctx.authority().is_some();
    if let Some(path) = args.flag("--review") {
        if review_only
            || [
                "--fiscal-year",
                "--period",
                "--key",
                "--description",
                "--evidence",
            ]
            .iter()
            .any(|flag| args.flag(flag).is_some())
        {
            return Err(usage(
                "a restored closing review supplies the complete unchanged proposal",
                "fa close year-end --review <file|hex|-> --digest <review_digest> [--approval <vid>] --dry-run",
            ));
        }
        let expected = parse_digest(required(args, "--digest")?, "review digest")?;
        let mut book = ctx
            .books
            .open_admitted(args, |book| admit_history(book, &capability))?;
        let bytes = read_review_bytes(&ctx.files, path, bound)?;
        let review = PostIntent::decode(&bytes).map_err(|error| {
            usage(
                format!("invalid closing review: {error}"),
                "use the unchanged close review bytes",
            )
        })?;
        if review
            .digest()
            .map_err(|error| Fail::Internal(error.to_string()))?
            != expected
            || review.proposal().class != EntryClass::CLOSING
            || !review.approvals().is_empty()
        {
            return Err(usage(
                "closing review digest or type does not match",
                "use its independently retained review_digest",
            ));
        }
        let intent = with_approvals(review, args)?;
        let plan = book.plan(intent, &capability)??;
        if args.switch("--dry-run") {
            return emit_post_plan(&ctx.out, &book, &ctx.files, args, &plan);
        }
        let posted = book.commit_plan(plan, &capability)??;
        ctx.out.at_book(&book)?;
        return emit_posted(&ctx.out, posted, "Closing", false, None, None);
    }
    if args.flag("--digest").is_some() || args.flag("--approval").is_some() {
        return Err(usage(
            "approvals and a digest require an unchanged --review",
            EXAMPLE,
        ));
    }
    let request = YearEndCloseRequest {
        fiscal_year: fiscal_year(required(args, "--fiscal-year")?)?,
        closing_period: required(args, "--period")?.to_string(),
    };
    let _ = required(args, "--key")?;
    let mut preparation = None;
    let mut book = ctx.books.open_admitted(args, |book| {
        preparation = Some(book.prepare_year_end_close(&request, &capability)??);
        Ok(())
    })?;
    let prepared =
        preparation.ok_or_else(|| Fail::Internal("closing preparation is missing".into()))?;
    ctx.out
        .effective(format!("fiscal-year:{}", request.fiscal_year));
    if prepared.is_noop() {
        ctx.out.event(
            "closing_noop",
            vec![
                ("fiscal_year", Json::Int(i128::from(request.fiscal_year))),
                ("period", s(&request.closing_period)),
                ("known_at", Json::Int(i128::from(prepared.known_at().0))),
                (
                    "latest_close",
                    prepared.latest_close().map_or(Json::Null, |close| {
                        s(format!("{:032x}", close.entry_ref.vid.0))
                    }),
                ),
                (
                    "reason",
                    s("all selected nominal balances are zero; no entry was published"),
                ),
            ],
            "year-end close has no residual to transfer; no entry was published",
        );
        return Ok(());
    }
    let proposal = proposal(&mut book, args, &prepared, principal)?;
    let intent = PostIntent::new(proposal, Vec::new())
        .map_err(|error| usage(format!("closing proposal: {error}"), EXAMPLE))?;
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
        let legs = leg_preview(intent.proposal(), &book)?;
        let balances = residuals(prepared.residuals(), &book)?;
        if let Some(path) = args.flag("--review-out") {
            write_review_file(&ctx.files, path, &bytes)?;
        }
        ctx.out.event(
            "closing_reviewed",
            vec![
                ("fiscal_year", Json::Int(i128::from(request.fiscal_year))),
                ("period", s(&request.closing_period)),
                ("closing_date", s(prepared.closing_date().to_string())),
                ("known_at", Json::Int(i128::from(prepared.known_at().0))),
                (
                    "routes_entry",
                    s(format!("{:032x}", prepared.routes_entry().0)),
                ),
                ("routes_digest", s(hex(&prepared.routes_digest()))),
                ("source_digest", s(hex(&prepared.source_digest()))),
                (
                    "latest_close",
                    prepared.latest_close().map_or(Json::Null, |close| {
                        s(format!("{:032x}", close.entry_ref.vid.0))
                    }),
                ),
                ("residuals", balances),
                ("legs", legs),
                ("review_digest", s(hex(&review_digest))),
                ("proposal_digest", s(hex(&proposal_digest))),
                ("bytes", s(hex(&bytes))),
                ("file", args.flag("--review-out").map_or(Json::Null, s)),
                ("scope", s("year-end-close-proposal")),
            ],
            &format!(
                "review FY{} closing proposal {}; nothing was published",
                request.fiscal_year,
                hex(&proposal_digest)
            ),
        );
        return Ok(());
    }
    let plan = book.plan(intent, &capability)??;
    if args.switch("--dry-run") {
        return emit_post_plan(&ctx.out, &book, &ctx.files, args, &plan);
    }
    let posted = book.commit_plan(plan, &capability)??;
    ctx.out.at_book(&book)?;
    emit_posted(&ctx.out, posted, "Closing", false, None, None)
}

fn with_approvals(review: PostIntent, args: &Args) -> Result<PostIntent, Fail> {
    let digest = review
        .proposal()
        .proposal_digest()
        .map_err(|error| Fail::Internal(error.to_string()))?;
    let approvals = args
        .flag_all("--approval")
        .iter()
        .map(|value| {
            Ok(ApprovalRef {
                approval_vid: parse_vid(value, "--approval")?,
                approved_digest: digest,
            })
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    PostIntent::new(review.proposal().clone(), approvals)
        .map_err(|error| usage(format!("closing approval references: {error}"), EXAMPLE))
}

pub(crate) fn verify_close(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.flag("--period").is_some() || args.positional.len() > 3 {
        return Err(usage(
            "verify close selects one fiscal year",
            "fa verify close FY2026",
        ));
    }
    let supplied = args.positional.get(2).map(String::as_str);
    if supplied.is_some() && args.flag("--fiscal-year").is_some() {
        return Err(usage(
            "select the fiscal year once",
            "fa verify close FY2026",
        ));
    }
    let year = fiscal_year(
        supplied
            .or_else(|| args.flag("--fiscal-year"))
            .ok_or_else(|| {
                usage(
                    "verify close requires a fiscal year",
                    "fa verify close FY2026",
                )
            })?,
    )?;
    let requested_at = known_at(args)?;
    let capability = ctx.capability(args, &["read", "verify"])?;
    let mut verification = None;
    let book = ctx.books.open_admitted(args, |book| {
        verification = Some(book.verify_year_end_close(year, requested_at, &capability)??);
        Ok(())
    })?;
    let verification =
        verification.ok_or_else(|| Fail::Internal("close verification is missing".into()))?;
    ctx.out.known_at(verification.known_at);
    ctx.out.effective(format!("fiscal-year:{year}"));
    let fields = vec![
        ("fiscal_year", Json::Int(i128::from(year))),
        ("known_at", Json::Int(i128::from(verification.known_at.0))),
        (
            "latest_close",
            verification
                .latest_close
                .as_ref()
                .map_or(Json::Null, |close| {
                    s(format!("{:032x}", close.entry_ref.vid.0))
                }),
        ),
        (
            "last_closed_at",
            verification
                .latest_close
                .as_ref()
                .map_or(Json::Null, |close| {
                    Json::Int(i128::from(close.recorded_at.0))
                }),
        ),
        (
            "nominal_zero_at_close",
            verification
                .nominal_zero_at_close
                .map_or(Json::Null, Json::Bool),
        ),
        ("needs_reclose", Json::Bool(verification.needs_reclose)),
        ("residuals", residuals(&verification.residuals, &book)?),
    ];
    if !verification.is_green() || verification.needs_reclose {
        return Err(Fail::Verification {
            message: format!("FY{year} needs a valid closing entry or delta reclose"),
            detail: obj(fields),
            cite: Some("plan §7.5 (nominal balances at the last close and later deltas)".into()),
            fix: Some(format!(
                "prepare and review fa close year-end --fiscal-year {year} --period FY{year}-CLOSE --key <new-key> --review-only"
            )),
        });
    }
    ctx.out.event(
        "close_verified",
        fields,
        &format!("FY{year}: nominal accounts were zero at the last close and remain zero"),
    );
    Ok(())
}
