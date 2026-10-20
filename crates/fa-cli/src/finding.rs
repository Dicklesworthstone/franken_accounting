//! Certified finding publication, human review and source-preserving workpapers.
//!
//! Every observation comes from the native replay-backed finding APIs. The
//! run inventory pages one fixed publication frontier; a certificate-specific
//! listing reads that run. Reviews keep their own historical cutoff and never
//! rewrite the original observation. Exported canonical packages replay against
//! the book.

use std::collections::BTreeSet;
use std::io::Read;

use fa::findings::lookup::{FindingRunCursor, FindingRunPageRequest, MAX_FINDING_RUN_PAGE};
use fa::findings::review::workpaper::FindingReviewExpectation;
use fa::findings::review::{
    DismissalReason, FINDING_REVIEW_WORKPAPER_FORMAT, FindingReview, FindingReviewAction,
    FindingReviewHistory, FindingReviewRequest, FindingReviewStatus, FindingReviewWorkpaper,
    MAX_FINDING_REVIEW_WORKPAPER_BYTES,
};
use fa::findings::{FindingWorkpaper, MAX_FINDING_WORKPAPER_BYTES, RecordedFindings};
use fa::{Book, Capability, ProcedureCertificate, ProcedureRequest};
use fa_model::{Oid, account_vid};
use fa_policy::Op;
use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

use crate::args::Args;
use crate::cli::{Ctx, Fail, Files, Out, Stdin, finding_json, hex, usage, write_new_output_file};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa finding runs [--page-size 16] [--cursor <hex>] | record <procedure-id> | record --certificate C:<digest> | list --certificate C:<digest> | show F:<vid> | review F:<vid> --action acknowledge --note <text> | export --certificate C:<digest> --export-format md|jsonl|canonical | replay <workpaper-file|-> [--certificate C:<expected-digest> --known-at <exact-seq>]";
const RUNS_EXAMPLE: &str = "fa finding runs [--page-size 1..32] [--cursor <complete-hex>] [--known-at HEAD|<sequence>] --json";
// Native fa:finding-run-cursor:v1 has fixed framing. The CLI bounds and
// decodes its hex transport; only the native inventory validates its meaning.
const RUN_CURSOR_BYTES: usize = 96;
const LOCAL_FLAGS: &[&str] = &[
    "--page-size",
    "--cursor",
    "--certificate",
    "--param",
    "--account",
    "--source",
    "--effective-through",
    "--known-at",
    "--as-known-at",
    "--action",
    "--note",
    "--dismissal-reason",
    "--previous",
    "--evidence",
    "--export-format",
    "--out",
    "--file",
];

fn invalid(message: impl Into<String>) -> Fail {
    fa_journal::Refusal::new(
        fa::certificate::code::CERTIFICATE_INVALID,
        fa_journal::exit::VERIFICATION,
        message,
        "plan §11.8; immutable findings and complete native workpaper replay",
        "use the original complete canonical workpaper, retained certificate and book; do not edit findings, decisions or checksums",
    ).into()
}

fn fixed_hex<const N: usize>(text: &str, what: &str) -> Result<[u8; N], Fail> {
    if text.len() != N * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(usage(
            format!("{what} requires exactly {} hexadecimal digits", N * 2),
            EXAMPLE,
        ));
    }
    let mut result = [0; N];
    for (byte, pair) in result.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let pair =
            std::str::from_utf8(pair).map_err(|_| usage(format!("invalid {what}"), EXAMPLE))?;
        *byte =
            u8::from_str_radix(pair, 16).map_err(|_| usage(format!("invalid {what}"), EXAMPLE))?;
    }
    Ok(result)
}

fn certificate(args: &Args) -> Result<[u8; 32], Fail> {
    let text = args.require("--certificate", "C:<64-hex certificate digest>")?;
    fixed_hex(text.strip_prefix("C:").unwrap_or(text), "--certificate")
}

fn handle(text: &str, prefix: &str, what: &str) -> Result<VId, Fail> {
    Ok(VId(u128::from_be_bytes(fixed_hex::<16>(
        text.strip_prefix(prefix).unwrap_or(text),
        what,
    )?)))
}

/// No wall-clock lookup or implicit date conversion. The native reader checks
/// this inclusive cutoff against publication and the current retained frontier.
fn cutoff(args: &Args) -> Result<Option<CommitSeq>, Fail> {
    if args.flag("--known-at").is_some() && args.flag("--as-known-at").is_some() {
        return Err(usage(
            "use only one known-at spelling",
            "--known-at HEAD|<commit sequence>",
        ));
    }
    match args.flag("--known-at").or_else(|| args.flag("--as-known-at")) {
        None | Some("HEAD") => Ok(None),
        Some(text) => text.parse::<u64>().map(CommitSeq).map(Some).map_err(|_| {
            usage("finding known-at needs HEAD or a native commit sequence; an instant is not a sequence", "--known-at HEAD|<commit sequence>")
        }),
    }
}

fn has_cutoff(args: &Args) -> bool {
    args.flag("--known-at").is_some() || args.flag("--as-known-at").is_some()
}

fn check_options(args: &Args, sub: &str) -> Result<(), Fail> {
    let allowed: &[&str] = match sub {
        "runs" => &["--page-size", "--cursor", "--known-at", "--as-known-at"],
        "record" => &[
            "--certificate",
            "--param",
            "--account",
            "--source",
            "--effective-through",
            "--known-at",
            "--as-known-at",
        ],
        "list" => &["--certificate", "--known-at", "--as-known-at"],
        "show" => &["--known-at", "--as-known-at"],
        // --certificate and --file select a run review (review_run).
        "review" => &[
            "--action",
            "--note",
            "--dismissal-reason",
            "--previous",
            "--evidence",
            "--certificate",
            "--file",
        ],
        "export" => &[
            "--certificate",
            "--known-at",
            "--as-known-at",
            "--export-format",
            "--out",
        ],
        "replay" => &["--certificate", "--known-at", "--as-known-at"],
        _ => {
            return Err(usage(
                format!("unknown finding subcommand `{sub}`"),
                EXAMPLE,
            ));
        }
    };
    for flag in LOCAL_FLAGS {
        if args.flag(flag).is_some() && !allowed.contains(flag) {
            return Err(usage(
                format!("{flag} does not apply to finding {sub}"),
                EXAMPLE,
            ));
        }
        if !matches!(*flag, "--param" | "--evidence") && args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("finding {sub} takes only one {flag}"),
                EXAMPLE,
            ));
        }
    }
    if args.switch("--dry-run") {
        return Err(usage(
            "finding publication and review do not accept --dry-run",
            "use fa procedure run for an unrecorded observation, or fa finding show to inspect the current decision before confirming",
        ));
    }
    if args.switch("--include-reviews") && sub != "export" {
        return Err(usage(
            "--include-reviews applies only to finding export",
            EXAMPLE,
        ));
    }
    if args.switch("--yes") && !matches!(sub, "record" | "review") {
        return Err(usage(
            "--yes applies only to finding record or review",
            EXAMPLE,
        ));
    }
    if args
        .switches
        .iter()
        .filter(|flag| flag.as_str() == "--include-reviews")
        .count()
        > 1
    {
        return Err(usage("--include-reviews may be supplied once", EXAMPLE));
    }
    Ok(())
}

/// Current operation and whole-book scope checks precede protected input or
/// stored observation reads. The native methods repeat current-policy admission.
fn capability(ctx: &Ctx<'_>, args: &Args, ops: &[&str]) -> Result<Capability, Fail> {
    let cap = ctx.capability(args, ops)?;
    for op in ops {
        let op = Op::from_name(op)
            .ok_or_else(|| Fail::Internal("finding operation is not registered".into()))?;
        fa_policy::require(&cap, op, "finding operation")
            .map_err(|d| Fail::Refusal(fa_journal::policy::refusal(&d)))?;
    }
    fa_policy::reach(&cap, &fa_policy::Reach::whole_book(true), None)
        .map_err(|d| Fail::Refusal(fa_journal::policy::refusal(&d)))?;
    Ok(cap)
}

fn admit_book(book: &Book, who: VId, cap: &Capability) -> Result<(), Fail> {
    let _ = book.read_scope(who, cap)??;
    Ok(())
}

fn ensure_inline(fields: &[(&str, Json)], fix: &str) -> Result<(), Fail> {
    let max = crate::verbs::registry()
        .map_err(|e| Fail::Internal(e.into()))?
        .daemon
        .max_frame_bytes
        .saturating_sub(128 * 1024);
    if obj(fields.to_vec()).render().len() > max {
        return Err(usage(
            "the complete finding response exceeds the inline transport bound; no findings or decisions were omitted",
            fix,
        ));
    }
    Ok(())
}

fn select_source(out: &Out, run: &RecordedFindings) {
    out.known_at(run.report.coordinate.known_at);
    out.effective(
        run.report
            .coordinate
            .effective_through
            .map_or_else(|| "all".into(), |day| format!("through:{}", day.render())),
    );
}

pub(crate) fn finding_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let sub = args
        .positional
        .get(1)
        .map(String::as_str)
        .ok_or_else(|| usage("finding needs a subcommand", EXAMPLE))?;
    check_options(args, sub)?;
    match sub {
        "runs" => runs(ctx, args),
        "record" => record(ctx, args),
        "list" => list(ctx, args),
        "show" => show(ctx, args),
        "review" => review(ctx, args),
        "export" => export(ctx, args),
        "replay" => replay(ctx, args),
        _ => Err(usage("finding needs a supported subcommand", EXAMPLE)),
    }
}

fn runs(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "finding runs accepts no positional selector",
            RUNS_EXAMPLE,
        ));
    }
    let who = ctx.principal(args);
    let cap = capability(ctx, args, &["read"])?;
    let mut book = ctx
        .books
        .open_admitted(args, |book| admit_book(book, who, &cap))?;
    // Neither a historical selector nor a public continuation revives expired
    // authority. Decode these only after native current-policy admission.
    let mut request = FindingRunPageRequest {
        known_at: cutoff(args)?,
        ..Default::default()
    };
    if let Some(value) = args.flag("--page-size") {
        request.limit = value
            .parse::<usize>()
            .ok()
            .filter(|limit| (1..=MAX_FINDING_RUN_PAGE).contains(limit))
            .ok_or_else(|| usage("--page-size needs an integer in 1..32", RUNS_EXAMPLE))?;
    }
    request.after = args
        .flag("--cursor")
        .map(|text| -> Result<_, Fail> {
            let bytes = fixed_hex::<RUN_CURSOR_BYTES>(text, "--cursor")?;
            Ok(FindingRunCursor::decode(&bytes)?)
        })
        .transpose()?;
    let page = book.finding_runs(who, &cap, &request)??;
    let next_cursor = page
        .next_cursor
        .as_ref()
        .map(|cursor| cursor.canonical_bytes().map(|bytes| hex(&bytes)))
        .transpose()?;
    let rows = page
        .runs
        .iter()
        .map(|run| {
            obj(vec![
                ("run_vid", s(format!("{:032x}", run.run_vid.0))),
                ("certificate", s(hex(&run.certificate_digest))),
                ("recorded_at", Json::Int(i128::from(run.recorded_at.0))),
                ("producer", s(format!("{:032x}", run.producer.0))),
                (
                    "source_known_at",
                    Json::Int(i128::from(run.coordinate.known_at.0)),
                ),
                (
                    "effective_through",
                    run.coordinate
                        .effective_through
                        .map_or(Json::Null, |day| s(day.render())),
                ),
                ("procedure", s(&run.procedure)),
                ("version", Json::Int(i128::from(run.version))),
                ("finding_count", Json::Int(i128::from(run.finding_count))),
                ("findings_digest", s(hex(&run.findings_digest))),
            ])
        })
        .collect();
    let fields = vec![
        ("scope", s("recorded-runs")),
        ("known_at", Json::Int(i128::from(page.known_at.0))),
        (
            "checked_through",
            Json::Int(i128::from(page.checked_through.0)),
        ),
        ("inventory_digest", s(hex(&page.inventory_digest))),
        (
            "total_recorded_runs",
            Json::Int(i128::from(page.total_recorded_runs)),
        ),
        ("page_count", Json::Int(page.runs.len() as i128)),
        ("runs", Json::Arr(rows)),
        ("next_cursor", next_cursor.as_deref().map_or(Json::Null, s)),
    ];
    ensure_inline(&fields, "repeat fa finding runs with a smaller --page-size")?;
    let mut human = format!(
        "Recorded finding runs at sequence {}: {} of {}; native records checked through {}",
        page.known_at.0,
        page.runs.len(),
        page.total_recorded_runs,
        page.checked_through.0,
    );
    for run in &page.runs {
        human.push_str(&format!(
            "\n{} v{}: {} original finding(s), published at {}, source at {}, certificate C:{}",
            run.procedure,
            run.version,
            run.finding_count,
            run.recorded_at.0,
            run.coordinate.known_at.0,
            hex(&run.certificate_digest),
        ));
    }
    if let Some(cursor) = &next_cursor {
        human.push_str(&format!(
            "\nNext page: fa finding runs --page-size {} --cursor {cursor}",
            request.limit,
        ));
    } else {
        human.push_str("\nEnd of this recorded-run inventory. Review decisions are available with fa finding list --certificate C:<digest>.");
    }
    ctx.out.known_at(page.known_at);
    ctx.out.event("finding_runs", fields, &human);
    Ok(())
}

fn record(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let source = args
        .flag("--certificate")
        .map(|_| certificate(args))
        .transpose()?;
    let request_id = args.positional.get(2);
    if args.positional.len() > 3 || source.is_some() == request_id.is_some() {
        return Err(usage(
            "record needs either one procedure id or --certificate, exclusively",
            EXAMPLE,
        ));
    }
    if source.is_some()
        && (["--param", "--account", "--source", "--effective-through"]
            .iter()
            .any(|flag| args.flag(flag).is_some())
            || has_cutoff(args))
    {
        return Err(usage(
            "a retained certificate already fixes every procedure input and source coordinate",
            "fa finding record --certificate C:<digest>",
        ));
    }
    let at = cutoff(args)?;
    let effective = args
        .flag("--effective-through")
        .map(|text| {
            DateDay::parse(text).map_err(|e| {
                usage(
                    format!("--effective-through: {e}"),
                    "--effective-through YYYY-MM-DD",
                )
            })
        })
        .transpose()?;
    let mut parameters = request_id
        .map(|id| {
            fa_lantern::Params::defaults(id)
                .map_err(|e| usage(e.to_string(), "fa procedure list --json"))
        })
        .transpose()?;
    let mut names = BTreeSet::new();
    for item in args.flag_all("--param") {
        let (name, value) = item
            .split_once('=')
            .ok_or_else(|| usage("--param needs name=integer", "--param round_power=2"))?;
        let name = name.trim();
        if !names.insert(name) {
            return Err(usage(
                format!("duplicate procedure parameter `{name}`"),
                "supply each --param name once",
            ));
        }
        let value = value.trim().parse::<i128>().map_err(|_| {
            usage(
                format!("--param {name} needs an exact integer"),
                "--param round_power=2",
            )
        })?;
        parameters = Some(
            parameters
                .take()
                .ok_or_else(|| usage("--param requires a procedure id", EXAMPLE))?
                .set(name, value)
                .map_err(|e| usage(e.to_string(), "fa procedure list --json"))?,
        );
    }
    let source_entry = args
        .flag("--source")
        .map(|text| handle(text, "E:", "--source"))
        .transpose()?;
    let who = ctx.principal(args);
    let cap = capability(ctx, args, &["read", "produce"])?;
    let mut book = ctx
        .books
        .open_admitted(args, |book| admit_book(book, who, &cap))?;
    let before = book.head()?;
    let digest = if let Some(digest) = source {
        digest
    } else {
        let id = request_id.ok_or_else(|| usage("record needs a procedure id", EXAMPLE))?;
        let request = ProcedureRequest {
            procedure: id.clone(),
            parameters: parameters
                .ok_or_else(|| usage("record needs procedure parameters", EXAMPLE))?,
            inputs: fa_lantern::catalog::Inputs {
                account: args
                    .flag("--account")
                    .map(|code| account_vid(book.context().book_id, code)),
                source: source_entry,
            },
            known_at: at,
            effective_through: effective,
        };
        let certified = book.certify_procedure(who, &cap, &request)??;
        let bytes = certified.certificate.canonical_bytes()?;
        let digest = *certified.certificate.digest();
        book.retain_report_artifact(who, &cap, &bytes, Some(&digest))??;
        digest
    };
    let run = book.record_findings(who, &cap, &digest)??;
    let retry = format!("fa finding record --certificate C:{}", hex(&digest));
    ctx.out.at_book(&book)?;
    select_source(&ctx.out, &run);
    ctx.out.event_with_certificate(
        "findings_recorded",
        vec![
            ("certificate", s(hex(&digest))),
            ("run_vid", s(format!("{:032x}", run.run_vid.0))),
            ("recorded_at", Json::Int(i128::from(run.recorded_at.0))),
            ("producer", s(format!("{:032x}", run.producer.0))),
            ("procedure", s(&run.report.procedure)),
            ("version", Json::Int(i128::from(run.report.version))),
            (
                "source_known_at",
                Json::Int(i128::from(run.report.coordinate.known_at.0)),
            ),
            (
                "effective_through",
                run.report
                    .coordinate
                    .effective_through
                    .map_or(Json::Null, |d| s(d.render())),
            ),
            ("claim", s(run.report.claim.name())),
            ("finding_count", Json::Int(run.finding_ids.len() as i128)),
            ("findings_digest", s(hex(&run.report.findings_digest))),
            (
                "finding_ids",
                Json::Arr(
                    run.finding_ids
                        .iter()
                        .map(|id| s(format!("{:032x}", id.0)))
                        .collect(),
                ),
            ),
            ("already_recorded", Json::Bool(run.recorded_at <= before)),
            ("retry_command", s(&retry)),
        ],
        &format!(
            "{}: {} finding(s) recorded at sequence {}\nCertificate: C:{}\nExact retry: {retry}",
            run.report.procedure,
            run.finding_ids.len(),
            run.recorded_at.0,
            hex(&digest)
        ),
        Some(&hex(&digest)),
    );
    Ok(())
}

fn reason_name(reason: DismissalReason) -> &'static str {
    match reason {
        DismissalReason::Explained => "explained",
        DismissalReason::Duplicate => "duplicate",
        DismissalReason::DataQuality => "data-quality",
        DismissalReason::OutsideScope => "outside-scope",
        DismissalReason::Other => "other",
    }
}

fn action_name(action: FindingReviewAction) -> &'static str {
    match action {
        FindingReviewAction::Acknowledge => "acknowledge",
        FindingReviewAction::Dismiss(_) => "dismiss",
        FindingReviewAction::Reopen => "reopen",
    }
}

fn status_name(status: FindingReviewStatus) -> &'static str {
    match status {
        FindingReviewStatus::Open => "Open",
        FindingReviewStatus::Reviewed => "Reviewed",
        FindingReviewStatus::Dismissed { .. } => "Dismissed",
    }
}

fn review_json(review: &FindingReview) -> Json {
    obj(vec![
        (
            "finding_vid",
            s(format!("{:032x}", review.request.finding_vid.0)),
        ),
        ("review_vid", s(format!("{:032x}", review.review_vid.0))),
        ("ordinal", Json::Int(i128::from(review.ordinal))),
        ("recorded_at", Json::Int(i128::from(review.recorded_at.0))),
        ("principal", s(format!("{:032x}", review.principal.0))),
        (
            "capability_commitment",
            s(hex(&review.capability_commitment)),
        ),
        ("action", s(action_name(review.request.action))),
        (
            "reason",
            match review.request.action {
                FindingReviewAction::Dismiss(reason) => s(reason_name(reason)),
                _ => Json::Null,
            },
        ),
        (
            "previous",
            review
                .request
                .expected_previous
                .map_or(Json::Null, |id| s(format!("{:032x}", id.0))),
        ),
        ("note", s(&review.request.note)),
        (
            "evidence",
            Json::Arr(
                review
                    .request
                    .evidence
                    .iter()
                    .map(|oid| s(hex(&oid.0)))
                    .collect(),
            ),
        ),
    ])
}

fn row(history: &FindingReviewHistory) -> Json {
    let finding = &history.finding;
    obj(vec![
        ("finding_vid", s(format!("{:032x}", finding.finding_vid.0))),
        ("run_vid", s(format!("{:032x}", finding.run_vid.0))),
        ("certificate", s(hex(&finding.certificate_digest))),
        ("ordinal", Json::Int(i128::from(finding.ordinal))),
        ("recorded_at", Json::Int(i128::from(finding.recorded_at.0))),
        ("producer", s(format!("{:032x}", finding.producer.0))),
        (
            "source_known_at",
            Json::Int(i128::from(finding.coordinate.known_at.0)),
        ),
        (
            "effective_through",
            finding
                .coordinate
                .effective_through
                .map_or(Json::Null, |d| s(d.render())),
        ),
        ("status", s(status_name(history.status()))),
        (
            "latest_review",
            history
                .latest_review()
                .map_or(Json::Null, |id| s(format!("{:032x}", id.0))),
        ),
        ("finding", finding_json(&finding.finding)),
        (
            "reviews",
            Json::Arr(history.reviews.iter().map(review_json).collect()),
        ),
    ])
}

fn list(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "finding list selects a run with --certificate",
            EXAMPLE,
        ));
    }
    let digest = certificate(args)?;
    let at = cutoff(args)?;
    let who = ctx.principal(args);
    let cap = capability(ctx, args, &["read"])?;
    let mut book = ctx
        .books
        .open_admitted(args, |book| admit_book(book, who, &cap))?;
    let history = book.finding_run_review_history(who, &cap, &digest, at)??;
    let fields = vec![
        ("certificate", s(hex(&digest))),
        ("run_vid", s(format!("{:032x}", history.run.run_vid.0))),
        ("procedure", s(&history.run.report.procedure)),
        ("version", Json::Int(i128::from(history.run.report.version))),
        ("claim", s(history.run.report.claim.name())),
        ("known_at", Json::Int(i128::from(history.known_at.0))),
        (
            "checked_through",
            Json::Int(i128::from(history.checked_through.0)),
        ),
        (
            "source_known_at",
            Json::Int(i128::from(history.run.report.coordinate.known_at.0)),
        ),
        ("scope", s("certified-run")),
        ("finding_count", Json::Int(history.histories.len() as i128)),
        (
            "findings",
            Json::Arr(history.histories.iter().map(row).collect()),
        ),
    ];
    ensure_inline(
        &fields,
        "export the complete run with fa finding export --certificate C:<digest> --include-reviews --out <new-file>",
    )?;
    let mut human = format!(
        "{}: {} finding(s), review history through sequence {}",
        history.run.report.procedure,
        history.histories.len(),
        history.known_at.0
    );
    for item in &history.histories {
        human.push_str(&format!(
            "\nF:{:032x} {} {} {}",
            item.finding.finding_vid.0,
            status_name(item.status()),
            item.finding.finding.severity.name(),
            item.finding.finding.narrative
        ));
    }
    ctx.out.known_at(history.known_at);
    ctx.out
        .event_with_certificate("finding_list", fields, &human, Some(&hex(&digest)));
    Ok(())
}

fn show(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 3 {
        return Err(usage("finding show needs one F:<vid>", EXAMPLE));
    }
    let selected = handle(&args.positional[2], "F:", "finding")?;
    let at = cutoff(args)?;
    let who = ctx.principal(args);
    let cap = capability(ctx, args, &["read"])?;
    let mut book = ctx
        .books
        .open_admitted(args, |book| admit_book(book, who, &cap))?;
    let history = book.finding_review_history(who, &cap, selected, at)??;
    let fields = vec![
        ("certificate", s(hex(&history.finding.certificate_digest))),
        ("known_at", Json::Int(i128::from(history.known_at.0))),
        (
            "checked_through",
            Json::Int(i128::from(history.checked_through.0)),
        ),
        ("row", row(&history)),
    ];
    ensure_inline(&fields, "export the complete run to a new workpaper file")?;
    let mut human = format!(
        "F:{:032x} {} {}\n{}",
        selected.0,
        status_name(history.status()),
        history.finding.finding.severity.name(),
        history.finding.finding.narrative
    );
    for decision in &history.reviews {
        human.push_str(&format!(
            "\nR:{:032x} {} at {} by {:032x}: {}",
            decision.review_vid.0,
            action_name(decision.request.action),
            decision.recorded_at.0,
            decision.principal.0,
            decision.request.note
        ));
    }
    ctx.out.known_at(history.known_at);
    ctx.out.event_with_certificate(
        "finding_shown",
        fields,
        &human,
        Some(&hex(&history.finding.certificate_digest)),
    );
    Ok(())
}

fn review(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let run = args.flag("--certificate").is_some() || args.flag("--file").is_some();
    if run && args.positional.len() == 2 {
        // A run review needs both; review_run names whichever is missing.
        return review_run(ctx, args);
    }
    if run {
        return Err(usage(
            "--certificate and --file select a run review, which names no F:<vid>",
            REVIEW_RUN_EXAMPLE,
        ));
    }
    if args.positional.len() != 3 {
        return Err(usage("finding review needs one F:<vid>", EXAMPLE));
    }
    let selected = handle(&args.positional[2], "F:", "finding")?;
    let request = review_request(
        Source::Flags,
        selected,
        args.require("--action", "acknowledge|dismiss|reopen")?,
        args.flag("--dismissal-reason"),
        args.flag("--note"),
        args.flag("--previous"),
        &args.flag_all("--evidence"),
    )?;
    let action = request.action;
    let who = ctx.principal(args);
    let cap = capability(ctx, args, &["read", "approve"])?;
    let mut book = ctx
        .books
        .open_admitted(args, |book| admit_book(book, who, &cap))?;
    let before = book.head()?;
    let decision = book.review_finding(who, &cap, &request)??;
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "finding_reviewed",
        vec![
            ("review", review_json(&decision)),
            (
                "already_recorded",
                Json::Bool(decision.recorded_at <= before),
            ),
        ],
        &format!(
            "{} F:{:032x} at sequence {}\nReview: R:{:032x}",
            action_name(action),
            selected.0,
            decision.recorded_at.0,
            decision.review_vid.0
        ),
    );
    Ok(())
}

/// Where a review decision was written: the single review's flags, or one
/// item of a run review file. Refusals name what the caller wrote, so a fix
/// never points a run review at a flag it refuses.
#[derive(Clone, Copy)]
enum Source {
    Flags,
    File,
}

impl Source {
    /// The flag, or the run review field that carries the same value.
    fn name(self, flag: &'static str) -> &'static str {
        match (self, flag) {
            (Self::Flags, _) => flag,
            (Self::File, "--action") => "action",
            (Self::File, "--dismissal-reason") => "dismissal_reason",
            (Self::File, "--note") => "note",
            (Self::File, "--previous") => "previous",
            (Self::File, "--evidence") => "evidence",
            (Self::File, other) => other,
        }
    }

    fn fix(self, flags: &str, file: &str) -> String {
        match self {
            Self::Flags => flags.to_string(),
            Self::File => file.to_string(),
        }
    }
}

/// One review decision, validated the same way whether it comes from flags
/// (`finding review F:<vid>`) or from one item of a run review file.
fn review_request(
    source: Source,
    selected: VId,
    action: &str,
    dismissal: Option<&str>,
    note: Option<&str>,
    previous: Option<&str>,
    evidence: &[&str],
) -> Result<FindingReviewRequest, Fail> {
    let reasons = source.fix(
        "--dismissal-reason explained|duplicate|data-quality|outside-scope|other",
        r#""dismissal_reason":"explained|duplicate|data-quality|outside-scope|other""#,
    );
    let action = match action {
        "acknowledge" => FindingReviewAction::Acknowledge,
        "reopen" => FindingReviewAction::Reopen,
        "dismiss" => FindingReviewAction::Dismiss(
            match dismissal.ok_or_else(|| {
                usage(
                    format!("{} is required", source.name("--dismissal-reason")),
                    reasons.clone(),
                )
            })? {
                "explained" => DismissalReason::Explained,
                "duplicate" => DismissalReason::Duplicate,
                "data-quality" => DismissalReason::DataQuality,
                "outside-scope" => DismissalReason::OutsideScope,
                "other" => DismissalReason::Other,
                _ => {
                    return Err(usage("unregistered finding dismissal reason", reasons));
                }
            },
        ),
        _ => {
            return Err(usage(
                "unregistered finding review action",
                source.fix(
                    "--action acknowledge|dismiss|reopen",
                    r#""action":"acknowledge|dismiss|reopen""#,
                ),
            ));
        }
    };
    if !matches!(action, FindingReviewAction::Dismiss(_)) && dismissal.is_some() {
        return Err(usage(
            format!("{} belongs to a dismissal", source.name("--dismissal-reason")),
            source.fix(
                "use --note for every decision; add --dismissal-reason and --evidence for dismiss",
                r#"give every decision a "note"; add "dismissal_reason" and "evidence" only to a dismiss"#,
            ),
        ));
    }
    let note = note
        .ok_or_else(|| {
            usage(
                format!("{} is required", source.name("--note")),
                source.fix(
                    "--note <nonempty human explanation>",
                    r#""note":"<nonempty human explanation>""#,
                ),
            )
        })?
        .to_string();
    if note.trim().is_empty() || note.len() > fa::findings::review::MAX_REVIEW_NOTE_BYTES {
        return Err(usage(
            "review note is empty or exceeds its registered UTF-8 byte bound",
            source.fix(
                "--note <nonempty explanation of at most 2048 UTF-8 bytes>",
                r#""note":"<nonempty explanation of at most 2048 UTF-8 bytes>""#,
            ),
        ));
    }
    let previous = previous
        .map(|text| handle(text, "R:", source.name("--previous")))
        .transpose()?;
    let mut evidence = evidence
        .iter()
        .map(|text| {
            fixed_hex(
                text.strip_prefix("D:").unwrap_or(text),
                source.name("--evidence"),
            )
            .map(Oid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    evidence.sort();
    if evidence.len() > fa::findings::review::MAX_REVIEW_EVIDENCE
        || evidence.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(usage(
            "review evidence must contain at most 16 distinct retained documents",
            source.fix(
                "supply each --evidence document once",
                r#"list each "evidence" document once"#,
            ),
        ));
    }
    if matches!(action, FindingReviewAction::Dismiss(_)) && evidence.is_empty() {
        return Err(usage(
            "dismissing a finding requires retained evidence",
            source.fix(
                "--evidence <document oid>; import the actual supporting document with fa document add first",
                r#""evidence":["D:<document oid>"]; import the actual supporting document with fa document add first"#,
            ),
        ));
    }
    Ok(FindingReviewRequest {
        finding_vid: selected,
        expected_previous: previous,
        action,
        note,
        evidence,
    })
}

const REVIEW_RUN_EXAMPLE: &str = r#"fa finding review --certificate C:<run digest> --file reviews.json --json, where reviews.json is [{"finding":"F:<vid>","action":"acknowledge","note":"..."},{"finding":"F:<vid>","action":"dismiss","dismissal_reason":"explained","note":"...","evidence":["D:<oid>"]}]"#;

/// `finding review --certificate C:<run> --file <reviews.json|->`: an explicit
/// selection from ONE retained finding run, reviewed in one native transaction
/// (Book::review_finding_run). Each decision is validated exactly as a single
/// review; any refused decision refuses the whole set and publishes nothing.
fn review_run(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    for flag in [
        "--action",
        "--note",
        "--dismissal-reason",
        "--previous",
        "--evidence",
    ] {
        if args.flag(flag).is_some() {
            return Err(usage(
                format!(
                    "{flag} belongs to a single review; a run review reads every decision from --file"
                ),
                REVIEW_RUN_EXAMPLE,
            ));
        }
    }
    let digest = certificate(args)?;
    let file = args.require("--file", "<reviews.json|->")?;
    // Current authority and whole-book scope precede reading the decisions.
    let who = ctx.principal(args);
    let cap = capability(ctx, args, &["read", "approve"])?;
    let mut book = ctx
        .books
        .open_admitted(args, |book| admit_book(book, who, &cap))?;
    let text = ctx.files.read_text(file)?;
    let doc = crate::json::parse(&text).map_err(|error| {
        usage(
            format!("invalid run review JSON: {error}"),
            REVIEW_RUN_EXAMPLE,
        )
    })?;
    let Json::Arr(items) = doc else {
        return Err(usage(
            "a run review is a JSON array of decisions",
            REVIEW_RUN_EXAMPLE,
        ));
    };
    if items.is_empty() {
        return Err(usage(
            "a run review names at least one finding",
            REVIEW_RUN_EXAMPLE,
        ));
    }
    let requests = items
        .iter()
        .enumerate()
        .map(|(index, item)| run_review_item(index, item))
        .collect::<Result<Vec<_>, Fail>>()?;
    let before = book.head()?;
    let decisions = book.review_finding_run(who, &cap, &digest, &requests)??;
    ctx.out.at_book(&book)?;
    for decision in &decisions {
        ctx.out.event(
            "finding_reviewed",
            vec![
                ("review", review_json(decision)),
                (
                    "already_recorded",
                    Json::Bool(decision.recorded_at <= before),
                ),
            ],
            &format!(
                "{} F:{:032x} at sequence {}\nReview: R:{:032x}",
                action_name(decision.request.action),
                decision.request.finding_vid.0,
                decision.recorded_at.0,
                decision.review_vid.0
            ),
        );
    }
    Ok(())
}

fn item_text<'a>(item: &'a Json, index: usize, key: &str) -> Result<Option<&'a str>, Fail> {
    match item.get(key) {
        None => Ok(None),
        Some(Json::Str(text)) => Ok(Some(text.as_str())),
        Some(_) => Err(usage(
            format!("reviews[{index}].{key} must be a string"),
            REVIEW_RUN_EXAMPLE,
        )),
    }
}

/// One run-review decision. Field names mirror the single review's flags;
/// every error names the item it came from.
fn run_review_item(index: usize, item: &Json) -> Result<FindingReviewRequest, Fail> {
    // The hex parsers' fix is the single review's example; an item's errors
    // point at the run review's file form instead.
    let in_item = |fail: Fail| match fail {
        Fail::Usage(error) => usage(
            format!("reviews[{index}]: {}", error.message),
            if error.fix == EXAMPLE {
                REVIEW_RUN_EXAMPLE.to_string()
            } else {
                error.fix
            },
        ),
        other => other,
    };
    let Json::Obj(fields) = item else {
        return Err(usage(
            format!("reviews[{index}] must be a JSON object"),
            REVIEW_RUN_EXAMPLE,
        ));
    };
    for (name, _) in fields {
        if ![
            "finding",
            "action",
            "dismissal_reason",
            "note",
            "previous",
            "evidence",
        ]
        .contains(&name.as_str())
        {
            return Err(usage(
                format!("reviews[{index}]: unknown field '{name}'"),
                REVIEW_RUN_EXAMPLE,
            ));
        }
    }
    let Some(finding) = item_text(item, index, "finding")? else {
        return Err(usage(
            format!("reviews[{index}] names no finding"),
            REVIEW_RUN_EXAMPLE,
        ));
    };
    let Some(action) = item_text(item, index, "action")? else {
        return Err(usage(
            format!("reviews[{index}] names no action"),
            r#""action":"acknowledge|dismiss|reopen""#,
        ));
    };
    let evidence: Vec<&str> = match item.get("evidence") {
        None => Vec::new(),
        Some(Json::Arr(values)) => values
            .iter()
            .map(|value| match value {
                Json::Str(text) => Ok(text.as_str()),
                _ => Err(usage(
                    format!("reviews[{index}].evidence must contain document oids"),
                    REVIEW_RUN_EXAMPLE,
                )),
            })
            .collect::<Result<_, Fail>>()?,
        Some(_) => {
            return Err(usage(
                format!("reviews[{index}].evidence must be an array"),
                REVIEW_RUN_EXAMPLE,
            ));
        }
    };
    review_request(
        Source::File,
        handle(finding, "F:", "finding").map_err(in_item)?,
        action,
        item_text(item, index, "dismissal_reason")?,
        item_text(item, index, "note")?,
        item_text(item, index, "previous")?,
        &evidence,
    )
    .map_err(in_item)
}

fn export(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "finding export selects a run with --certificate",
            EXAMPLE,
        ));
    }
    let digest = certificate(args)?;
    let at = cutoff(args)?;
    let reviews = args.switch("--include-reviews");
    if has_cutoff(args) && !reviews {
        return Err(usage(
            "--known-at on an export selects human review history; the original observation already has its fixed source coordinate",
            "add --include-reviews, or omit --known-at to export the unchanged original workpaper",
        ));
    }
    let format = args.flag("--export-format").unwrap_or("md");
    if !matches!(format, "md" | "jsonl" | "canonical") {
        return Err(usage(
            "unknown finding export format",
            "--export-format md|jsonl|canonical",
        ));
    }
    let output = args.flag("--out");
    if output.is_some_and(|path| path.is_empty() || path == "-") {
        return Err(usage(
            "--out needs a new file path",
            "omit --out for complete inline content",
        ));
    }
    let who = ctx.principal(args);
    let cap = capability(ctx, args, &["read", "produce"])?;
    let mut book = ctx
        .books
        .open_admitted(args, |book| admit_book(book, who, &cap))?;
    let (id, package_digest, original, review_at, bytes) = if reviews {
        let paper = book.finding_review_workpaper(who, &cap, &digest, at)??;
        let original = paper.observation_workpaper().clone();
        let bytes = match format {
            "canonical" => paper.canonical_bytes()?,
            "jsonl" => format!("{}{}", original.jsonl(), paper.review_jsonl()).into_bytes(),
            _ => format!("{}\n{}", original.markdown(), paper.review_markdown()).into_bytes(),
        };
        (
            paper.id().to_string(),
            *paper.digest(),
            original,
            Some(paper.review_known_at()),
            bytes,
        )
    } else {
        let paper = book.finding_workpaper(who, &cap, &digest)??;
        let bytes = match format {
            "canonical" => paper.canonical_bytes()?,
            "jsonl" => paper.jsonl().as_bytes().to_vec(),
            _ => paper.markdown().as_bytes().to_vec(),
        };
        (paper.id().to_string(), *paper.digest(), paper, None, bytes)
    };
    let source = ProcedureCertificate::decode(original.certificate_bytes())?;
    let content = if output.is_some() || format == "canonical" {
        Json::Null
    } else {
        s(std::str::from_utf8(&bytes)
            .map_err(|_| invalid("native finding presentation is not UTF-8"))?)
    };
    let fields = vec![
        ("certificate", s(hex(&digest))),
        ("workpaper", s(&id)),
        ("workpaper_digest", s(hex(&package_digest))),
        (
            "recorded_at",
            Json::Int(i128::from(original.recorded_at().0)),
        ),
        (
            "source_known_at",
            Json::Int(i128::from(source.known_at().0)),
        ),
        (
            "review_known_at",
            review_at.map_or(Json::Null, |at| Json::Int(i128::from(at.0))),
        ),
        ("format", s(format)),
        ("includes_reviews", Json::Bool(reviews)),
        ("bytes", Json::Int(bytes.len() as i128)),
        (
            "content_digest",
            s(hex(&fa_model::domain_digest(
                b"fa:finding-export:v1",
                &[&bytes],
            ))),
        ),
        ("content", content),
        (
            "bytes_hex",
            if output.is_none() && format == "canonical" {
                s(hex(&bytes))
            } else {
                Json::Null
            },
        ),
        ("out", output.map_or(Json::Null, s)),
    ];
    ensure_inline(
        &fields,
        "use --out <new-file> to preserve the entire workpaper outside the inline transport",
    )?;
    if let Some(path) = output {
        write_new_output_file(&ctx.files, path, &bytes, "finding workpaper", "--out")?;
    }
    ctx.out.known_at(review_at.unwrap_or(source.known_at()));
    let human = if let Some(path) = output {
        format!("{id}: {} bytes written to {path}", bytes.len())
    } else if format == "canonical" {
        format!("{id}\n{}", hex(&bytes))
    } else {
        String::from_utf8(bytes).map_err(|_| invalid("native finding presentation is not UTF-8"))?
    };
    ctx.out
        .event_with_certificate("finding_exported", fields, &human, Some(&hex(&digest)));
    Ok(())
}

fn read_workpaper(files: &Files, path: &str) -> Result<Vec<u8>, Fail> {
    let canonical_limit = MAX_FINDING_WORKPAPER_BYTES.max(MAX_FINDING_REVIEW_WORKPAPER_BYTES);
    let limit = canonical_limit * 2 + 2;
    let read = |input: &mut dyn Read| -> Result<Vec<u8>, Fail> {
        let mut bytes = Vec::new();
        input
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| {
                usage(
                    format!("cannot read workpaper: {e}"),
                    "pass a readable canonical workpaper file or - for forwarded stdin",
                )
            })?;
        Ok(bytes)
    };
    let bytes = if path == "-" {
        match &files.stdin {
            Stdin::Forwarded(bytes) => {
                if bytes.len() > limit {
                    return Err(invalid("workpaper wire exceeds its byte bound"));
                }
                bytes.clone()
            }
            Stdin::Missing => {
                return Err(usage(
                    "no workpaper bytes were forwarded to stdin",
                    "forward canonical bytes or the complete bytes_hex string from finding export",
                ));
            }
            Stdin::Process => read(&mut std::io::stdin().lock())?,
        }
    } else {
        let mut file = std::fs::File::open(files.resolve(path))
            .map_err(|e| usage(format!("{path}: {e}"), "pass the canonical file saved by fa finding export --export-format canonical --out <file>"))?;
        read(&mut file)?
    };
    if bytes.len() > limit {
        return Err(invalid("workpaper wire exceeds its byte bound"));
    }
    if bytes
        .get(4..)
        .is_some_and(|body| body.starts_with(b"fa:finding-"))
    {
        if bytes.len() > canonical_limit {
            return Err(invalid("canonical workpaper exceeds its byte bound"));
        }
        return Ok(bytes);
    }
    let text = std::str::from_utf8(&bytes).ok().map(str::trim)
        .filter(|text| !text.is_empty() && text.len() % 2 == 0 && text.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| invalid("expected a complete canonical workpaper or its exact hexadecimal encoding; Markdown and JSONL presentations alone are not replay packages"))?;
    if text.len() / 2 > canonical_limit {
        return Err(invalid("canonical workpaper exceeds its byte bound"));
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair =
                std::str::from_utf8(pair).map_err(|_| invalid("workpaper hex is not UTF-8"))?;
            u8::from_str_radix(pair, 16).map_err(|_| invalid("workpaper hex is invalid"))
        })
        .collect()
}

fn replay(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 3 {
        return Err(usage(
            "finding replay needs one canonical workpaper file or -",
            EXAMPLE,
        ));
    }
    let expected_digest = args
        .flag("--certificate")
        .map(|_| certificate(args))
        .transpose()?;
    let expected_at = cutoff(args)?;
    if expected_digest.is_some() != has_cutoff(args) || has_cutoff(args) && expected_at.is_none() {
        return Err(usage(
            "recipient-bound replay requires --certificate and an exact --known-at sequence together; HEAD is not an independently fixed cutoff",
            "fa finding replay <canonical-file> --certificate C:<expected-digest> --known-at <exact-seq>",
        ));
    }
    let who = ctx.principal(args);
    let cap = capability(ctx, args, &["read"])?;
    let mut book = ctx
        .books
        .open_admitted(args, |book| admit_book(book, who, &cap))?;
    let bytes = read_workpaper(&ctx.files, &args.positional[2])?;
    let reviews = bytes
        .get(4..)
        .is_some_and(|body| body.starts_with(FINDING_REVIEW_WORKPAPER_FORMAT));
    if expected_digest.is_some() && !reviews {
        return Err(invalid(
            "the recipient requested a review workpaper, but the delivery is an observation-only package",
        ));
    }
    let (id, digest, run, at, checked_through) = if reviews {
        let history = if let (Some(certificate_digest), Some(review_known_at)) =
            (expected_digest, expected_at)
        {
            let expected = FindingReviewExpectation {
                book_id: book.context().book_id,
                certificate_digest,
                review_known_at,
            };
            book.replay_finding_review_workpaper_for(who, &cap, &bytes, &expected)??
        } else {
            book.replay_finding_review_workpaper(who, &cap, &bytes)??
        };
        let paper = FindingReviewWorkpaper::decode(&bytes)?;
        (
            paper.id().to_string(),
            *paper.digest(),
            history.run,
            Some(history.known_at),
            history.checked_through,
        )
    } else {
        let run = book.replay_finding_workpaper(who, &cap, &bytes)??;
        let paper = FindingWorkpaper::decode(&bytes)?;
        (
            paper.id().to_string(),
            *paper.digest(),
            run,
            None,
            book.head()?,
        )
    };
    ctx.out
        .known_at(at.unwrap_or(run.report.coordinate.known_at));
    ctx.out.event_with_certificate(
        "finding_replayed",
        vec![
            ("certificate", s(hex(&run.certificate_digest))),
            ("workpaper", s(&id)),
            ("workpaper_digest", s(hex(&digest))),
            ("recorded_at", Json::Int(i128::from(run.recorded_at.0))),
            (
                "source_known_at",
                Json::Int(i128::from(run.report.coordinate.known_at.0)),
            ),
            (
                "review_known_at",
                at.map_or(Json::Null, |at| Json::Int(i128::from(at.0))),
            ),
            ("includes_reviews", Json::Bool(reviews)),
            ("finding_count", Json::Int(run.finding_ids.len() as i128)),
            ("checked_through", Json::Int(i128::from(checked_through.0))),
            (
                "scope",
                s(if expected_digest.is_some() {
                    "recipient-bound"
                } else {
                    "as-supplied"
                }),
            ),
        ],
        &format!(
            "Replayed {id}: {} original finding(s){} ({})",
            run.finding_ids.len(),
            if reviews {
                " and their complete selected review histories"
            } else {
                ""
            },
            if expected_digest.is_some() {
                "independently requested source and cutoff"
            } else {
                "as-supplied historical scope"
            }
        ),
        Some(&hex(&run.certificate_digest)),
    );
    Ok(())
}
