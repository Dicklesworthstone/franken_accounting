//! `fa access log` (plan §9.7, §14.5; bead fa-7dw): who read what. Every
//! bound read and plan-only delivery commits an AccessEvent before it observes
//! the book, including Agent and write-capable sessions. This lists those
//! attempts, not a claim that every attempted response was delivered. Reading
//! the log records that query once, never recursively for its result rows.

use fgdb_types::CommitSeq;

use crate::args::Args;
use crate::cli::{Ctx, Fail, Out, hex, usage};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa access log [--since <exclusive-seq>] [--through <inclusive-seq>] [--reader <principal name>] [--certify] [--certificate-out <new-file>] --json";

pub(crate) fn access_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("log") => log(ctx, args),
        Some(other) => Err(usage(
            format!("unknown access subcommand `{other}`"),
            EXAMPLE,
        )),
        None => Err(usage("access needs a subcommand: log", EXAMPLE)),
    }
}

fn log(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if let Some(extra) = args.positional.get(2) {
        return Err(usage(format!("unexpected argument `{extra}`"), EXAMPLE));
    }
    for flag in ["--since", "--through", "--reader", "--certificate-out"] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(format!("{flag} may be supplied only once"), EXAMPLE));
        }
    }
    if args
        .flag("--branch")
        .is_some_and(|branch| branch != "trunk")
    {
        return Err(usage(
            "the access log selects trunk's recorded history",
            EXAMPLE,
        ));
    }
    let since = match args.flag("--since") {
        None => CommitSeq(0),
        Some(raw) => CommitSeq(raw.parse::<u64>().map_err(|_| {
            usage(
                format!("--since `{raw}` must be a recorded sequence"),
                "--since 0",
            )
        })?),
    };
    let through = match args.flag("--through") {
        None => None,
        Some(raw) => Some(CommitSeq(raw.parse::<u64>().map_err(|_| {
            usage(
                format!("--through `{raw}` must be a recorded sequence"),
                "--through 100",
            )
        })?)),
    };
    if through.is_some_and(|through| through.0 < since.0) {
        return Err(usage(
            "--through must be greater than or equal to --since",
            EXAMPLE,
        ));
    }
    let request = fa::AccessLogRequest {
        since,
        through,
        reader: args.flag("--reader").map(str::to_owned),
    };
    let certify = args.switch("--certify") || args.flag("--certificate-out").is_some();
    let who = ctx.principal(args);
    let capability = ctx.capability(
        args,
        if certify {
            &["read", "produce"]
        } else {
            &["read"]
        },
    )?;
    if certify {
        fa_policy::admit_direct_write(&capability)
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    }
    let mut book = ctx.books.open_admitted(args, |book| {
        let (_audit, check): (fa::access_log::AccessAuditRecord, _) =
            fa::access_log::audit_access_log_read(book.context().book_id, &capability);
        check.map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        fa_policy::reach(
            &capability,
            &fa_policy::Reach {
                observes: through.map_or(fa_policy::Observes::Head, fa_policy::Observes::At),
                ..fa_policy::Reach::whole_book(true)
            },
            None,
        )
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        book.read_scope(who, &capability)??;
        Ok(())
    })?;
    if let Some(at) = through {
        ctx.out.known_at(at);
    }
    book.prepare_report_history(who, &capability, through)??;
    if certify {
        let certified = book.certify_access_log(who, &capability, &request)??;
        let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
        let (bytes, retained) = crate::notary::retain_report_artifact(
            &mut book,
            &ctx.files,
            args,
            &artifact,
            &capability,
        )?;
        let digest = hex(artifact.digest());
        render(&ctx.out, &certified.report, Some(&digest));
        crate::notary::emit_report_artifact(
            &ctx.out,
            args,
            &artifact,
            fa::ACCESS_LOG_OUTPUT_FORMAT,
            &bytes,
            &retained,
        );
    } else {
        let report = book.read_access_log(who, &capability, &request)??;
        render(&ctx.out, &report, None);
    }
    Ok(())
}

/// Original and replayed selections share the same report event and coordinate.
pub(crate) fn render(out: &Out, report: &fa::AccessLogReport, certificate: Option<&str>) {
    let since = report.request.since;
    let through = report.request.through;
    let principal = report.request.reader.as_deref();
    let events = &report.events;
    out.known_at(report.known_at);
    out.effective("all".to_owned());
    let mut human = match through {
        Some(through) => format!(
            "{} access event(s) recorded in ({}, {}]",
            events.len(),
            since.0,
            through.0
        ),
        None => format!(
            "{} access event(s) recorded after sequence {}",
            events.len(),
            since.0
        ),
    };
    let rows = events
        .iter()
        .map(|e| {
            human.push_str(&format!(
                "\n  #{} {} ran `{}` (observed {})",
                e.recorded_at.0, e.record.principal_name, e.record.command, e.observed_at.0
            ));
            obj(vec![
                ("vid", s(format!("{:032x}", e.vid.0))),
                ("recorded_at", Json::Int(i128::from(e.recorded_at.0))),
                ("observed_at", Json::Int(i128::from(e.observed_at.0))),
                ("principal", s(format!("{:032x}", e.record.principal.0))),
                ("principal_name", s(&e.record.principal_name)),
                ("capability", s(hex(&e.record.capability_commitment))),
                ("ops", Json::Arr(e.record.ops.iter().map(s).collect())),
                ("command", s(&e.record.command)),
                ("request_digest", s(hex(&e.record.request_digest))),
                ("digest", s(hex(&e.digest))),
            ])
        })
        .collect::<Vec<_>>();
    out.event_with_certificate(
        "access_log",
        vec![
            ("since", Json::Int(i128::from(since.0))),
            (
                "through",
                through.map_or(Json::Null, |seq| Json::Int(i128::from(seq.0))),
            ),
            ("reader", principal.map_or(Json::Null, s)),
            (
                "count",
                Json::Int(i128::try_from(rows.len()).unwrap_or(i128::MAX)),
            ),
            ("events", Json::Arr(rows)),
        ],
        &human,
        certificate,
    );
}
