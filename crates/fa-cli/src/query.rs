//! `fa query "<statement>"` (plan §15.5, bead fa-5c1): a GQL statement in
//! the FrankenAccounting profile, compiled by `fa-query` and run as one
//! certified native read at one recorded sequence. `CALL fa.trial_balance`
//! is `fa tb` itself, with the statement's period and known-at.
//!
//! A restatement view (`AS ORIGINALLY REPORTED`, `AS ISSUED TO '<audience>'`,
//! `AS REPORTED IN 'C:<certificate>'`) reads its `FOR PERIOD` at the sequence
//! `fa tb`'s view flag of the same name resolves; a native read is not
//! certified there (certify it AS KNOWN AT that sequence).
//!
//! A query reads the whole graph, so it is admitted as a whole-book read
//! before anything is observed: a token carrying any scope caveat is
//! refused, never filtered. `AT BRANCH 'scenario:<name>'` or
//! `'draft:<name>'` (or the same `--branch`) reads that replay, admitted on
//! trunk.
//!
//! `--certify`, `--certificate-out <new-file>` or a leading `EXPLAIN
//! (CERTIFICATE)` also retains the result's certificate, which needs
//! produce as well: `fa replay C:<oid>` reproduces
//! the rows byte for byte and `fa certificate status` says whether the same
//! statement still answers the same at the head.

use fa::{QueryCell, QueryKnownAt, QueryReported, QueryRows, QuerySelection};
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
    // AT BRANCH 'scenario:<name>' or 'draft:<name>' is the same --branch:
    // the book source admits authority on trunk, then reads the replay.
    let branched;
    let args = match &profiled.branch {
        Some(selector) => {
            if args.flag("--branch").is_some_and(|given| given != selector) {
                return Err(usage(
                    "AT BRANCH and --branch name different branches",
                    "name the branch once: AT BRANCH 'scenario:<name>' (or 'draft:<name>') in the statement, or --branch",
                ));
            }
            let mut with = args.clone();
            with.flags
                .insert("--branch".to_string(), vec![selector.clone()]);
            branched = with;
            &branched
        }
        None => args,
    };
    if args
        .flag("--branch")
        .is_some_and(|branch| branch != "trunk")
        && (profiled.certify || !matches!(profiled.known_at, QueryKnownAt::Head))
    {
        return Err(usage(
            "a scenario or draft read is its replay at its head: it is not certified, and AS KNOWN AT selects trunk's history",
            "drop EXPLAIN (CERTIFICATE) and AS KNOWN AT, or read trunk without --branch",
        ));
    }
    // A CALL is the registered read itself: the same command, so the same
    // admission, rows and certificate options as `fa tb`, `fa explain
    // balance`, `fa statement` or `fa open-items`.
    let native = match &profiled.selection {
        QuerySelection::Native(native) => native.clone(),
        QuerySelection::TrialBalance => {
            return crate::cli::tb_cmd(ctx, &procedure_args(args, &profiled, &["tb"]));
        }
        QuerySelection::ExplainBalance { account } => {
            let read = procedure_args(args, &profiled, &["explain", "balance", account]);
            return crate::cli::explain_cmd(ctx, &read);
        }
        QuerySelection::Statement { definition } => {
            let mut read = procedure_args(args, &profiled, &["statement", definition]);
            // `fa statement` names its period --for.
            if let Some(code) = read.flags.remove("--period") {
                read.flags.insert("--for".to_string(), code);
            }
            return crate::cli::statement_cmd(ctx, &read);
        }
        QuerySelection::OpenItems { account } => {
            let mut read = procedure_args(args, &profiled, &["open-items"]);
            if let Some(code) = account {
                read.flags
                    .insert("--account".to_string(), vec![code.clone()]);
            }
            return crate::cli::open_items_cmd(ctx, &read);
        }
        // The runtime graph's AccessEvents at trunk's head: the command's own
        // flags it cannot honour are refused, never passed on and ignored.
        QuerySelection::AccessLog { reader } => {
            if args.switch("--certify")
                || args.flag("--certificate-out").is_some()
                || args
                    .flag("--branch")
                    .is_some_and(|branch| branch != "trunk")
            {
                return Err(usage(
                    "CALL fa.access_log reads the access events at trunk's head; it has no certificate or branch",
                    "fa query \"CALL fa.access_log('<reader>')\" --json",
                ));
            }
            let mut read = args.clone();
            read.positional = vec!["access".to_string(), "log".to_string()];
            if let Some(name) = reader {
                read.flags
                    .insert("--reader".to_string(), vec![name.clone()]);
            }
            return crate::access::access_cmd(ctx, &read);
        }
    };
    let certify =
        profiled.certify || args.switch("--certify") || args.flag("--certificate-out").is_some();
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
        QueryKnownAt::Reported(view) => {
            // The profile refuses a view without FOR PERIOD.
            let period = profiled.period.as_deref().ok_or_else(|| {
                Fail::Internal("a restatement view compiled without its period".into())
            })?;
            let view = crate::issuance::query_view(view)?;
            let seq = crate::issuance::reported_known_at(&book, &capability, &view, period)?;
            if certify {
                return Err(usage(
                    "a query certificate binds a recorded sequence; this statement selects a restatement view",
                    format!(
                        "replace the view with AS KNOWN AT {} to certify the period as it was reported",
                        seq.0
                    ),
                ));
            }
            seq
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
            profiled.effective.as_ref(),
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
    render(
        &ctx.out,
        text,
        profiled.period.as_deref(),
        profiled.effective.as_ref(),
        &rows,
        None,
    );
    Ok(())
}

/// The coordinate's effective selector for a statement, named as the other
/// reads name theirs: `period:<code>` for FOR PERIOD, `as-of:<day>` for
/// EFFECTIVE AT, `between:<from>..<through>` for EFFECTIVE BETWEEN, joined by
/// `;` when a statement has both. None when it selects every effective day.
fn effective_label(
    period: Option<&str>,
    effective: Option<&fa_time::EffectiveSelector>,
) -> Option<String> {
    use fa_time::{DateDay, EffectiveSelector};
    let effective = effective.and_then(|selector| match selector {
        EffectiveSelector::AsOf(day) => Some(format!("as-of:{}", day.render())),
        EffectiveSelector::Range { start, end } => Some(format!(
            "between:{}..{}",
            start.render(),
            DateDay(end.0 - 1).render()
        )),
        _ => None,
    });
    match (period, effective) {
        (None, None) => None,
        (Some(code), None) => Some(format!("period:{code}")),
        (None, Some(effective)) => Some(effective),
        (Some(code), Some(effective)) => Some(format!("period:{code};{effective}")),
    }
}

/// The command a `CALL fa.<read>` runs: `positional`, with the statement's
/// period, known-at (or restatement view) and certification written as that
/// command's own flags.
fn procedure_args(args: &Args, profiled: &fa::ProfiledQuery, positional: &[&str]) -> Args {
    let mut read = args.clone();
    read.positional = positional.iter().map(|word| (*word).to_string()).collect();
    if profiled.certify && !read.switch("--certify") {
        read.switches.push("--certify".to_string());
    }
    if let Some(code) = &profiled.period {
        read.flags
            .insert("--period".to_string(), vec![code.clone()]);
    }
    match &profiled.known_at {
        QueryKnownAt::Head => {}
        QueryKnownAt::Seq(seq) => {
            read.flags
                .insert("--as-known-at".to_string(), vec![seq.to_string()]);
        }
        QueryKnownAt::Instant(instant) => {
            read.flags
                .insert("--as-known-at".to_string(), vec![instant.clone()]);
        }
        // A restatement view is the command's own view flag.
        QueryKnownAt::Reported(QueryReported::Originally) => {
            read.switches.push("--as-originally-reported".to_string());
        }
        QueryKnownAt::Reported(QueryReported::IssuedTo(audience)) => {
            read.flags
                .insert("--as-issued-to".to_string(), vec![audience.clone()]);
        }
        QueryKnownAt::Reported(QueryReported::In(certificate)) => {
            read.flags
                .insert("--as-reported-in".to_string(), vec![certificate.clone()]);
        }
    }
    read
}

/// The `query_rows` event: the statement, the native read that ran and its
/// rows, bound to their certificate when one was produced or replayed.
pub(crate) fn render(
    out: &Out,
    statement: &str,
    period: Option<&str>,
    effective: Option<&fa_time::EffectiveSelector>,
    rows: &QueryRows,
    certificate: Option<&str>,
) {
    out.known_at(rows.known_at);
    if let Some(label) = effective_label(period, effective) {
        out.effective(label);
    }
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
