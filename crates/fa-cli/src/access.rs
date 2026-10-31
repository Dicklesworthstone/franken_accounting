//! `fa access log` (plan §9.7, §14.5; bead fa-7dw): who read what. Every
//! bound read and plan-only delivery commits an AccessEvent before it observes
//! the book, including Agent and write-capable sessions. This lists those
//! attempts, not a claim that every attempted response was delivered. Reading
//! the log records that query once, never recursively for its result rows.

use fa_model::principal_vid;
use fgdb_types::CommitSeq;

use crate::args::Args;
use crate::cli::{Ctx, Fail, hex, usage};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa access log [--since <exclusive-seq>] [--through <inclusive-seq>] [--reader <principal name>] --json";

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
    let principal = args.flag("--reader");
    let who = ctx.principal(args);
    let capability = ctx.capability(args, &["read"])?;
    let book = ctx.books.open_admitted(args, |book| {
        let (_audit, check): (fa::access_log::AccessAuditRecord, _) =
            fa::access_log::audit_access_log_read(book.context().book_id, &capability);
        check.map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        book.read_scope(who, &capability)??;
        Ok(())
    })?;
    let mut events = book.access_log(since)?;
    if let Some(through) = through {
        events.retain(|event| event.recorded_at <= through);
    }
    if let Some(name) = principal {
        let vid = principal_vid(name);
        events.retain(|e| e.record.principal == vid);
    }
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
    ctx.out.event(
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
    );
    Ok(())
}
