//! `fa query "<statement>"` (plan §15.5, bead fa-5c1): a GQL statement in
//! the FrankenAccounting profile, compiled by `fa-query` and run as one
//! certified native read at one recorded sequence. `CALL fa.trial_balance`
//! is `fa tb` itself, with the statement's period and known-at.
//!
//! A query reads the whole graph, so it is admitted as a whole-book read
//! before anything is observed: a token carrying any scope caveat is
//! refused, never filtered.

use fa::{QueryCell, QueryKnownAt, QuerySelection};
use fgdb_types::CommitSeq;

use crate::args::Args;
use crate::cli::{Ctx, Fail, admit_whole_book_read, hex, usage};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa query \"MATCH (l:Leg)-[:POSTS_TO]->(a:Account) RETURN a.code, COUNT(*) AS legs FOR PERIOD 'FY2026-P03'\" --json";

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
    let capability = ctx.capability(args, &["read"])?;
    let book = ctx.books.open_admitted(args, |book| {
        admit_whole_book_read(book, &capability, &[], "querying the book's graph")
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
            ctx.out.time_selection(Some(&time));
            CommitSeq(time.resolution.resolved_seq)
        }
    };
    let rows = book.query_native(&native, known_at, profiled.period.as_deref())??;
    ctx.out.known_at(rows.known_at);
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
    ctx.out.event(
        "query_rows",
        vec![
            ("statement", s(text)),
            ("native", s(&rows.statement)),
            ("known_at", Json::Int(i128::from(rows.known_at.0))),
            ("period", profiled.period.as_deref().map_or(Json::Null, s)),
            ("columns", Json::Arr(rows.columns.iter().map(s).collect())),
            ("row_count", Json::Int(rows.rows.len() as i128)),
            ("rows", Json::Arr(rendered)),
            ("result_digest", s(hex(&rows.result_digest))),
        ],
        &human,
    );
    Ok(())
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
