//! `fa statement issue` and `fa statement issuances` (plan §12.5, §7.4,
//! Appendix B `IssueStatements`; bead fa-wrrw): the journaled fact that a
//! certified statement package left the entity.
//!
//! An issuance takes two principals. The preparer plans it with `--dry-run`:
//! the retained statement certificate it issues, the period that
//! certificate reports, the audience and an optional transmittal document,
//! fixed at the period's next ordinal with the description sealed once. An
//! independent approver approves the plan's `proposal_digest` with `fa
//! approve --proposal`, and the preparer commits exactly that plan with
//! `--plan` and `--approval`. The period's first issuance is what `AS
//! ORIGINALLY REPORTED` reads from then on: the known-at of the certificate
//! it issued.

use fa_journal::{IssuancePlan, IssuanceRecord, IssuedTo, StatementIssuance};
use fa_model::Oid;

use crate::args::Args;
use crate::cli::{Ctx, Fail, control_date, hex, parse_vid, read_plan_bytes, usage};
use crate::json::{Json, obj, s};

const PLAN_EXAMPLE: &str = "fa statement issue --certificate C:<oid> [--for <period>] --issued-to board|auditor|lender|regulator|sec|tax-authority|other [--document <oid>] [--key K] [--date YYYY-MM-DD] --dry-run --json";
const COMMIT_EXAMPLE: &str =
    "fa statement issue --plan <file|-> --approval <vid> [--approval <vid>]... --json";
const LIST_EXAMPLE: &str = "fa statement issuances [--for <period>] --json";
/// What only planning names; the plan carries each into the commit.
const PLAN_FLAGS: [&str; 6] = [
    "--certificate",
    "--for",
    "--issued-to",
    "--document",
    "--key",
    "--date",
];
/// What only `fa statement issue` reads: a statement report refuses each,
/// never ignores it.
pub(crate) const ISSUE_ONLY: [&str; 8] = [
    "--certificate",
    "--issued-to",
    "--document",
    "--key",
    "--date",
    "--plan",
    "--approval",
    "--dry-run",
];
/// The statement verb's report flags and switches: `issue` and `issuances`
/// refuse each, never ignore it.
const REPORT_ONLY: [&str; 18] = [
    "--compare",
    "--definition",
    "--before",
    "--after",
    "--max-publications",
    "--known-at",
    "--as-known-at",
    "--certificate-out",
    "--branch",
    "--before-certificate",
    "--after-certificate",
    "--from-diff",
    "--certify",
    "--as-originally-reported",
    "--render",
    "--out",
    "--as-issued-to",
    "--as-reported-in",
];
/// The restatement views that fix a read's known-at themselves (plan §7.4).
pub(crate) const VIEW_FLAGS: [&str; 3] = [
    "--as-originally-reported",
    "--as-issued-to",
    "--as-reported-in",
];

/// A restatement view (plan §7.4): where it pins a period's reads.
pub(crate) enum ReportedView {
    /// The period's first issuance, else its first Lock.
    Originally,
    /// The period's first issuance to this audience.
    IssuedTo(IssuedTo),
    /// The known-at of this retained statement certificate.
    ReportedIn([u8; 32]),
}

/// The first restatement view flag on the command line, if any.
pub(crate) fn view_flag(args: &Args) -> Option<&'static str> {
    VIEW_FLAGS.into_iter().find(|flag| present(args, flag))
}

/// The restatement view this read selects: at most one, and never beside a
/// known-at selector, since it fixes the coordinate itself.
pub(crate) fn reported_view(args: &Args, example: &str) -> Result<Option<ReportedView>, Fail> {
    let given: Vec<&str> = VIEW_FLAGS
        .into_iter()
        .filter(|flag| present(args, flag))
        .collect();
    let flag = match given.as_slice() {
        [] => return Ok(None),
        [flag] => *flag,
        _ => {
            return Err(usage(
                format!(
                    "{} each fix the known-at coordinate; select one",
                    given.join(" and ")
                ),
                example,
            ));
        }
    };
    if present(args, "--as-known-at") || present(args, "--known-at") {
        return Err(usage(
            format!(
                "{flag} fixes the known-at coordinate itself; it cannot be combined with --as-known-at or --known-at"
            ),
            example,
        ));
    }
    Ok(Some(match flag {
        "--as-originally-reported" => ReportedView::Originally,
        "--as-issued-to" => {
            let names = IssuedTo::ALL.map(IssuedTo::name).join("|");
            let text = one_flag(args, flag, example)?.unwrap_or_default();
            ReportedView::IssuedTo(IssuedTo::parse(text).ok_or_else(|| {
                usage(
                    format!("--as-issued-to `{text}` is not a registered audience"),
                    format!("--as-issued-to {names}"),
                )
            })?)
        }
        _ => {
            let text = one_flag(args, flag, example)?.unwrap_or_default();
            ReportedView::ReportedIn(hex32(
                text.strip_prefix("C:").unwrap_or(text),
                flag,
                "name a retained statement certificate: --as-reported-in C:<64-hex>",
            )?)
        }
    }))
}

/// The known-at `view` pins a read of `period` at.
pub(crate) fn reported_known_at(
    book: &fa::Book,
    capability: &fa::Capability,
    view: &ReportedView,
    period: &str,
) -> Result<fgdb_types::CommitSeq, Fail> {
    Ok(match view {
        ReportedView::Originally => book.originally_reported(period)??.known_at,
        ReportedView::IssuedTo(audience) => {
            book.issued_to(period, *audience)??.issuance.certified_at
        }
        ReportedView::ReportedIn(certificate) => {
            book.reported_in(capability, certificate, period)??
        }
    })
}

/// Whether `flag` (a value flag or a switch) is on the command line.
pub(crate) fn present(args: &Args, flag: &str) -> bool {
    args.switch(flag) || !args.flag_all(flag).is_empty()
}

fn refuse_foreign(args: &Args, sub: &str, foreign: &[&str], example: &str) -> Result<(), Fail> {
    match foreign.iter().find(|flag| present(args, flag)) {
        Some(flag) => Err(usage(
            format!("{flag} does not apply to `fa statement {sub}`"),
            example,
        )),
        None => Ok(()),
    }
}

fn one_flag<'a>(args: &'a Args, flag: &str, example: &str) -> Result<Option<&'a str>, Fail> {
    if args.flag_all(flag).len() > 1 {
        return Err(usage(format!("{flag} is given once"), example));
    }
    Ok(args.flag(flag))
}

fn hex32(text: &str, flag: &str, fix: &str) -> Result<[u8; 32], Fail> {
    let bad = || usage(format!("{flag}: `{text}` is not 64 hex digits"), fix);
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

fn audience(args: &Args) -> Result<IssuedTo, Fail> {
    let names = IssuedTo::ALL.map(IssuedTo::name).join("|");
    let text = one_flag(args, "--issued-to", PLAN_EXAMPLE)?
        .ok_or_else(|| usage("statement issue --dry-run needs --issued-to", PLAN_EXAMPLE))?;
    IssuedTo::parse(text).ok_or_else(|| {
        usage(
            format!("--issued-to `{text}` is not a registered audience"),
            format!("--issued-to {names}"),
        )
    })
}

/// One issuance as robot data; the record fields are null for a plan.
fn issuance_json(issuance: &StatementIssuance, record: Option<&IssuanceRecord>) -> Json {
    let opt_vid = |v: Option<fgdb_types::VId>| v.map_or(Json::Null, |v| s(format!("{:032x}", v.0)));
    obj(vec![
        ("issuance", s(format!("{:032x}", issuance.vid().0))),
        ("period", s(&issuance.period)),
        ("ordinal", Json::Int(i128::from(issuance.ordinal))),
        ("definition", s(&issuance.definition_name)),
        (
            "definition_version",
            Json::Int(i128::from(issuance.definition_version)),
        ),
        ("definition_digest", s(hex(&issuance.definition_digest))),
        ("certificate", s(hex(&issuance.certificate))),
        (
            "certified_at",
            Json::Int(i128::from(issuance.certified_at.0)),
        ),
        ("issued_to", s(issuance.issued_to.name())),
        (
            "document",
            issuance.document.map_or(Json::Null, |d| s(hex(&d.0))),
        ),
        ("control_entry", opt_vid(record.map(|r| r.control_entry))),
        (
            "recorded_at",
            record.map_or(Json::Null, |r| Json::Int(i128::from(r.recorded_at.0))),
        ),
        (
            "principal",
            record.map_or(Json::Null, |r| s(format!("{:032x}", r.principal.0))),
        ),
        (
            "approvals",
            record.map_or(Json::Null, |r| Json::Int(r.approvals as i128)),
        ),
    ])
}

fn line(issuance: &StatementIssuance) -> String {
    format!(
        "{} #{}: {} v{} at known_at {} to {} (certificate C:{})",
        issuance.period,
        issuance.ordinal,
        issuance.definition_name,
        issuance.definition_version,
        issuance.certified_at.0,
        issuance.issued_to.name(),
        hex(&issuance.certificate)
    )
}

/// `fa statement issue`: plan with `--dry-run`, or commit a plan.
pub(crate) fn issue(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    refuse_foreign(args, "issue", &REPORT_ONLY, PLAN_EXAMPLE)?;
    let approvals = args.flag_all("--approval");
    match (
        args.switch("--dry-run"),
        one_flag(args, "--plan", COMMIT_EXAMPLE)?,
    ) {
        (true, None) if approvals.is_empty() => plan(ctx, args),
        (true, _) => Err(usage(
            "--dry-run plans an issuance and commits nothing; it takes no --plan or --approval",
            PLAN_EXAMPLE,
        )),
        (false, Some(path)) => {
            if let Some(flag) = PLAN_FLAGS.iter().find(|f| args.flag(f).is_some()) {
                return Err(usage(
                    format!(
                        "{flag} does not apply to --plan: the plan carries what its approvals bind"
                    ),
                    COMMIT_EXAMPLE,
                ));
            }
            commit(ctx, args, path, &approvals)
        }
        (false, None) => Err(usage(
            "statement issue needs --dry-run (to plan an issuance) or --plan (to commit an approved one)",
            format!(
                "{PLAN_EXAMPLE}; then `fa approve --proposal <proposal_digest> --as <approver>`; then {COMMIT_EXAMPLE}"
            ),
        )),
    }
}

fn plan(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    for flag in PLAN_FLAGS {
        one_flag(args, flag, PLAN_EXAMPLE)?;
    }
    let text = args.flag("--certificate").ok_or_else(|| {
        usage(
            "statement issue --dry-run needs --certificate",
            PLAN_EXAMPLE,
        )
    })?;
    let certificate = hex32(
        text.strip_prefix("C:").unwrap_or(text),
        "--certificate",
        "name a retained certificate by the oid `--certify` printed: --certificate C:<64-hex>",
    )?;
    let period = args.flag("--for");
    let issued_to = audience(args)?;
    let document = args
        .flag("--document")
        .map(|text| {
            hex32(
                text.strip_prefix("D:").unwrap_or(text),
                "--document",
                "copy the value `fa document add --json` printed",
            )
            .map(Oid)
        })
        .transpose()?;
    let key = match args.flag("--key") {
        Some(key) if key.len() > fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES => {
            return Err(usage(
                format!(
                    "--key is at most {} bytes",
                    fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES
                ),
                PLAN_EXAMPLE,
            ));
        }
        Some(key) => key.to_string(),
        // The request itself: planning the same issuance again names the same
        // record, so committing it twice records it once.
        None => hex(&fa_model::domain_digest(
            b"fa-cli:statement-issue-key:v1",
            &[
                &certificate,
                period.unwrap_or("").as_bytes(),
                &[issued_to.tag()],
                document.as_ref().map_or(&[][..], |d| &d.0[..]),
            ],
        )),
    };
    let capability = ctx.capability(args, &["close", "read"])?;
    let book = ctx.books.open(args)?;
    let date = control_date(args, &book)?;
    let plan = book.plan_statement_issuance(
        &capability,
        &certificate,
        period,
        issued_to,
        document,
        date,
        key.as_bytes(),
    )??;
    let digest = plan
        .proposal_digest(book.context())
        .map_err(|e| Fail::Internal(format!("issuance plan digest: {e}")))?;
    let encoded = hex(&plan
        .encode()
        .map_err(|e| Fail::Internal(format!("issuance plan encoding: {e}")))?);
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "statement_issuance_plan",
        vec![
            ("issuance", issuance_json(&plan.issuance, None)),
            ("principal", s(format!("{:032x}", plan.principal_ref.0))),
            ("proposal_digest", s(hex(&digest))),
            ("bytes", s(&encoded)),
            ("scope", s("statement-issuance-proposal")),
        ],
        &format!(
            "planned {}; nothing was written. An approver who is not the planner approves proposal {} (`fa approve --proposal {}`); commit with `fa statement issue --plan <file|-> --approval <vid>`.\nCanonical issuance plan bytes (hex):\n{encoded}",
            line(&plan.issuance),
            hex(&digest),
            hex(&digest)
        ),
    );
    Ok(())
}

fn commit(ctx: &mut Ctx<'_>, args: &Args, path: &str, approvals: &[&str]) -> Result<(), Fail> {
    let bytes = read_plan_bytes(
        &ctx.files,
        path,
        fa_journal::issuance::PLAN_DOMAIN,
        "statement issuance",
    )?;
    let plan = IssuancePlan::decode(&bytes).map_err(|e| {
        usage(
            format!("{path} is not a statement issuance plan: {e}"),
            PLAN_EXAMPLE,
        )
    })?;
    let capability = ctx.capability(args, &["close", "read"])?;
    let mut book = ctx.books.open(args)?;
    let digest = plan
        .proposal_digest(book.context())
        .map_err(|e| Fail::Internal(format!("issuance plan digest: {e}")))?;
    let approvals = approvals
        .iter()
        .map(|v| {
            Ok(fa_model::ApprovalRef {
                approval_vid: parse_vid(v, "--approval")?,
                approved_digest: digest,
            })
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let issued = book.issue_statements(&capability, plan, approvals)??;
    ctx.out.at_book(&book)?;
    let record = &issued.record;
    ctx.out.event(
        "statement_issued",
        vec![
            ("issuance", issuance_json(&record.issuance, Some(record))),
            ("already_recorded", Json::Bool(issued.already_recorded)),
        ],
        &format!(
            "{} {} (record {}); AS ORIGINALLY REPORTED {} reads {}",
            if issued.already_recorded {
                "already issued:"
            } else {
                "issued"
            },
            line(&record.issuance),
            record.recorded_at.0,
            record.issuance.period,
            if record.issuance.ordinal == 1 {
                "this issuance's certificate"
            } else {
                "the period's first issuance"
            }
        ),
    );
    Ok(())
}

/// `fa statement issuances [--for <period>]`.
pub(crate) fn issuances(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    refuse_foreign(args, "issuances", &REPORT_ONLY, LIST_EXAMPLE)?;
    refuse_foreign(args, "issuances", &ISSUE_ONLY, LIST_EXAMPLE)?;
    let period = one_flag(args, "--for", LIST_EXAMPLE)?;
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let records = book.statement_issuances(period)?;
    ctx.out.at_book(&book)?;
    let human = if records.is_empty() {
        format!(
            "no statement issuances{}",
            period.map_or_else(String::new, |p| format!(" for {p}"))
        )
    } else {
        records
            .iter()
            .map(|r| line(&r.issuance))
            .collect::<Vec<_>>()
            .join("\n")
    };
    ctx.out.event(
        "statement_issuances",
        vec![
            ("period", period.map_or(Json::Null, s)),
            (
                "issuances",
                Json::Arr(
                    records
                        .iter()
                        .map(|r| issuance_json(&r.issuance, Some(r)))
                        .collect(),
                ),
            ),
        ],
        &human,
    );
    Ok(())
}
