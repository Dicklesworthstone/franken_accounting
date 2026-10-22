//! `fa query "<statement>"` (plan §15.5, bead fa-5c1): a GQL statement in
//! the FrankenAccounting profile, compiled by `fa-query` and run as one
//! certified native read at one recorded sequence. `CALL fa.trial_balance`
//! is `fa tb` itself, with the statement's period and known-at.
//!
//! A query reads the whole graph, so it is admitted as a whole-book read
//! before anything is observed: a token carrying any scope caveat is
//! refused, never filtered.
//!
//! `--certify` (or `--certificate-out <new-file>`) also retains the result's
//! certificate, which needs produce as well: `fa replay C:<oid>` reproduces
//! the rows byte for byte and `fa certificate status` says whether the same
//! statement still answers the same at the head.

use fa::{QueryCell, QueryKnownAt, QueryRows, QuerySelection};
use fgdb_types::CommitSeq;

use crate::args::Args;
use crate::cli::{Ctx, Fail, Out, admit_whole_book_read, hex, usage};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa query \"MATCH (l:Leg)-[:POSTS_TO]->(a:Account) RETURN a.code, COUNT(*) AS legs FOR PERIOD 'FY2026-P03'\" --json";
const CERTIFY_EXAMPLE: &str =
    "fa query \"MATCH (a:Account) RETURN a.code AS KNOWN AT 12\" --certify --json";

pub(crate) fn query_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let text = match args.positional.as_slice() {
        [_, text] => text.as_str(),
        _ => {
            return Err(usage(
                "fa query takes exactly one statement (quote it)",
                EXAMPLE,
            ));
        }
    };
    let profiled = fa::compile_query(text).map_err(|r| Fail::Refusal(fa::profile_refusal(&r)))?;
    let native = match profiled.selection {
        QuerySelection::TrialBalance => {
            // The registered trial balance itself: the same command, so the
            // same admission, rows and certificate options as `fa tb`.
            let mut tb = args.clone();
            tb.positional = vec!["tb".to_string()];
            if let Some(code) = &profiled.period {
                tb.flags.insert("--period".to_string(), vec![code.clone()]);
            }
            match &profiled.known_at {
                QueryKnownAt::Head => {}
                QueryKnownAt::Seq(seq) => {
                    tb.flags
                        .insert("--as-known-at".to_string(), vec![seq.to_string()]);
                }
                QueryKnownAt::Instant(instant) => {
                    tb.flags
                        .insert("--as-known-at".to_string(), vec![instant.clone()]);
                }
            }
            return crate::cli::tb_cmd(ctx, &tb);
        }
        QuerySelection::Native(native) => native,
    };
    let certify = args.switch("--certify") || args.flag("--certificate-out").is_some();
    if args.flag_all("--certificate-out").len() > 1 {
        return Err(usage(
            "--certificate-out may be supplied only once",
            CERTIFY_EXAMPLE,
        ));
    }
    let capability = ctx.capability(
        args,
        if certify {
            &["read", "produce"]
        } else {
            &["read"]
        },
    )?;
    let mut book = ctx.books.open_admitted(args, |book| {
        if certify {
            admit_whole_book_read(
                book,
                &capability,
                &[fa_policy::Op::Produce],
                "certifying a query",
            )
        } else {
            admit_whole_book_read(book, &capability, &[], "querying the book's graph")
        }
    })?;
    let known_at = match &profiled.known_at {
        QueryKnownAt::Head => book.head()?,
        QueryKnownAt::Seq(seq) => CommitSeq(*seq),
        QueryKnownAt::Instant(raw) => {
            let instant = fa_time::UtcInstant::parse(raw).map_err(|error| {
                usage(
                    format!("AS KNOWN AT '{raw}': {error}"),
                    "AS KNOWN AT HEAD | <commit sequence> | '2026-03-15T00:00:00Z'",
                )
            })?;
            let time = book.resolve_known_at_instant(instant.unix_ns())??;
            if certify {
                return Err(usage(
                    "a query certificate binds a recorded sequence; this statement selects an instant",
                    format!(
                        "replace AS KNOWN AT '{raw}' with AS KNOWN AT {} to certify the resolved query",
                        time.resolution.resolved_seq
                    ),
                ));
            }
            ctx.out.time_selection(Some(&time));
            CommitSeq(time.resolution.resolved_seq)
        }
    };
    if certify {
        let holder = capability.holder();
        // Certifying replays retained history: the stock trial balance and
        // the native read at the statement's sequence.
        let pinned = match &profiled.known_at {
            QueryKnownAt::Seq(seq) => Some(CommitSeq(*seq)),
            _ => None,
        };
        book.prepare_report_history(holder, &capability, pinned)??;
        let certified = book.certify_query(holder, &capability, text)??;
        let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
        let (bytes, retained) = crate::notary::retain_report_artifact(
            &mut book,
            &ctx.files,
            args,
            &artifact,
            &capability,
        )?;
        let digest = hex(artifact.digest());
        render(
            &ctx.out,
            text,
            profiled.period.as_deref(),
            &certified.rows,
            Some(&digest),
        );
        crate::notary::emit_report_artifact(
            &ctx.out,
            args,
            &artifact,
            "fa:query-result:v1",
            &bytes,
            &retained,
        );
        return Ok(());
    }
    let rows = book.query_native(&native, known_at, profiled.period.as_deref())??;
    render(&ctx.out, text, profiled.period.as_deref(), &rows, None);
    Ok(())
}

/// The `query_rows` event: the statement, the native read that ran and its
/// rows, bound to their certificate when one was produced or replayed.
pub(crate) fn render(
    out: &Out,
    statement: &str,
    period: Option<&str>,
    rows: &QueryRows,
    certificate: Option<&str>,
) {
    out.known_at(rows.known_at);
    let rendered: Vec<Json> = rows
        .rows
        .iter()
        .map(|row| Json::Arr(row.iter().map(cell).collect()))
        .collect();
    let mut human = rows.columns.join("  ");
    for row in &rows.rows {
        human.push('\n');
        human.push_str(&row.iter().map(plain).collect::<Vec<_>>().join("  "));
    }
    human.push_str(&format!(
        "\n{} row(s) at known_at {}",
        rows.rows.len(),
        rows.known_at.0
    ));
    out.event_with_certificate(
        "query_rows",
        vec![
            ("statement", s(statement)),
            ("native", s(&rows.statement)),
            ("known_at", Json::Int(i128::from(rows.known_at.0))),
            ("period", period.map_or(Json::Null, s)),
            ("columns", Json::Arr(rows.columns.iter().map(s).collect())),
            ("row_count", Json::Int(rows.rows.len() as i128)),
            ("rows", Json::Arr(rendered)),
            ("result_digest", s(hex(&rows.result_digest))),
        ],
        &human,
        certificate,
    );
}

fn id(raw: u128) -> String {
    format!("{raw:032x}")
}

fn cell(value: &QueryCell) -> Json {
    match value {
        QueryCell::Null => Json::Null,
        QueryCell::Bool(b) => Json::Bool(*b),
        QueryCell::Int(n) | QueryCell::Timestamp(n) => Json::Int(*n),
        QueryCell::Decimal(text) | QueryCell::Float(text) | QueryCell::Text(text) => s(text),
        QueryCell::Fraction {
            numerator,
            denominator,
        } => obj(vec![
            ("numerator", Json::Int(*numerator)),
            ("denominator", Json::Int(i128::from(*denominator))),
        ]),
        QueryCell::Bytes(bytes) => s(hex(bytes)),
        QueryCell::Vertex(vid) => s(id(vid.0)),
        QueryCell::Edge(eid) => s(id(eid.0)),
        QueryCell::Path { start, steps } => obj(vec![
            ("start", s(id(start.0))),
            (
                "steps",
                Json::Arr(
                    steps
                        .iter()
                        .map(|(edge, vertex)| {
                            obj(vec![("edge", s(id(edge.0))), ("vertex", s(id(vertex.0)))])
                        })
                        .collect(),
                ),
            ),
        ]),
        QueryCell::List(values) => Json::Arr(values.iter().map(cell).collect()),
        QueryCell::Map(entries) => Json::Obj(
            entries
                .iter()
                .map(|(key, value)| (key.clone(), cell(value)))
                .collect(),
        ),
    }
}

fn plain(value: &QueryCell) -> String {
    match value {
        QueryCell::Null => "null".to_string(),
        QueryCell::Bool(b) => b.to_string(),
        QueryCell::Int(n) | QueryCell::Timestamp(n) => n.to_string(),
        QueryCell::Decimal(t) | QueryCell::Float(t) | QueryCell::Text(t) => t.clone(),
        QueryCell::Fraction {
            numerator,
            denominator,
        } => format!("{numerator}/{denominator}"),
        QueryCell::Bytes(bytes) => hex(bytes),
        QueryCell::Vertex(vid) => id(vid.0),
        QueryCell::Edge(eid) => id(eid.0),
        QueryCell::Path { .. } | QueryCell::List(_) | QueryCell::Map(_) => cell(value).render(),
    }
}
