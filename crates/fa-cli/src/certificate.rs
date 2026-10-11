//! Report certificates on the CLI (plan §13.6, fa-cqk): the certificate
//! `fa tb --json` carries, `fa replay`, and `fa certificate status`.
//!
//! A certificate travels as the lowercase hex of its canonical bytes (the
//! `certificate.bytes` field of `fa tb --json`), read from a file or from
//! stdin (`-`), so it crosses the daemon and the MCP server like any other
//! document. It is read and decoded before the book is opened: a malformed
//! certificate never observes a book.

use fa::{ReportCertificate, TrialBalanceRequest};

use crate::args::Args;
use crate::cli::{Ctx, Fail, hex, periods_selector, unhandled, usage};
use crate::json::{self, Json, obj, s};

/// The certificate summary in `fa tb --json`: its id, closure, digests, and
/// the bytes `fa replay` reads.
pub(crate) fn summary(certificate: &ReportCertificate) -> Result<Json, Fail> {
    let inputs = certificate
        .inputs
        .iter()
        .map(|input| {
            obj(vec![
                ("name", s(&input.name)),
                ("statement", s(&input.certificate.statement)),
                (
                    "snapshot_seq",
                    Json::Int(i128::from(input.certificate.plan.snapshot_seq.0)),
                ),
                (
                    "snapshot_identity",
                    s(hex(&input.certificate.snapshot_identity.0)),
                ),
                ("result_digest", s(hex(&input.certificate.result_digest.0))),
            ])
        })
        .collect();
    Ok(obj(vec![
        ("id", s(certificate.id_text()?)),
        ("definition", s(certificate.request.definition())),
        (
            "definition_version",
            Json::Int(i128::from(certificate.definition_version)),
        ),
        ("known_at", Json::Int(i128::from(certificate.known_at.0))),
        ("capability", s(&certificate.capability)),
        ("replay_scope", s(&certificate.replay_scope)),
        ("inputs", Json::Arr(inputs)),
        ("output_digest", s(hex(&certificate.output_digest))),
        ("rows", Json::Int(certificate.row_digests.len() as i128)),
        ("bytes", s(certificate.to_hex()?)),
    ]))
}

fn selector(request: &TrialBalanceRequest) -> String {
    match request {
        TrialBalanceRequest::Stock { periods } | TrialBalanceRequest::Activity { periods } => {
            periods_selector(periods)
        }
        TrialBalanceRequest::AsOf { day } => format!("as-of:{}", day.render()),
    }
}

/// The certificate named by positional `index`: a file (or `-` for stdin)
/// holding its hex, or holding the saved `fa tb --json` line that carries
/// it (`fa tb … --json > tb.json && fa replay tb.json`). Nothing else may
/// follow it.
fn read(
    ctx: &Ctx<'_>,
    args: &Args,
    index: usize,
    example: &str,
) -> Result<ReportCertificate, Fail> {
    if let Some(extra) = args.positional.get(index + 1) {
        return Err(usage(format!("unexpected argument `{extra}`"), example));
    }
    let Some(source) = args.positional.get(index) else {
        return Err(usage(
            "name the certificate: a file (or `-` for stdin) holding the hex of `certificate.bytes`, or the saved `fa tb --json` line",
            example,
        ));
    };
    let text = ctx.files.read_text(source)?;
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        // A saved robot line: exactly one trial_balance line, whose
        // certificate bytes are the certificate. Anything else is refused
        // as malformed, never searched for a plausible certificate.
        let bytes = json::parse(trimmed.trim_end())
            .ok()
            .filter(|line| line.get("event").and_then(Json::as_str) == Some("trial_balance"))
            .and_then(|line| {
                line.get("data")
                    .and_then(|d| d.get("certificate"))
                    .and_then(|c| c.get("bytes"))
                    .and_then(Json::as_str)
                    .map(str::to_string)
            });
        let Some(bytes) = bytes else {
            return Err(Fail::Refusal(fa::certificate::malformed(format!(
                "`{source}` holds JSON, but not one `fa tb --json` line with data.certificate.bytes"
            ))));
        };
        return ReportCertificate::from_text(&bytes).map_err(Fail::Refusal);
    }
    ReportCertificate::from_text(&text).map_err(Fail::Refusal)
}

/// `fa replay <certificate>`: re-execute every certified input through the
/// substrate and recompute the report; exit 0 only on byte-identical output.
pub(crate) fn replay_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const EXAMPLE: &str = "fa replay tb.cert --book <dir> --json";
    let certificate = read(ctx, args, 1, EXAMPLE)?;
    let book = ctx.books.open(args)?;
    let id = certificate.id_text()?;
    ctx.out.certificate(id.clone());
    ctx.out.known_at(certificate.known_at);
    ctx.out.effective(selector(&certificate.request));
    let replayed = book.replay_certificate(&certificate)??;
    ctx.out.event(
        "certificate_replayed",
        vec![
            ("certificate", s(&id)),
            ("definition", s(certificate.request.definition())),
            ("known_at", Json::Int(i128::from(certificate.known_at.0))),
            (
                "inputs_replayed",
                Json::Arr(replayed.inputs.iter().map(s).collect()),
            ),
            ("output_digest", s(hex(&certificate.output_digest))),
            ("rows", Json::Int(replayed.report.rows.len() as i128)),
            ("status", s("reproduced")),
        ],
        &format!(
            "Certificate {id} reproduced byte-for-byte: {} certified inputs replayed by the substrate at sequence {}, then {} refolded to {} rows (output digest {}).",
            replayed.inputs.len(),
            certificate.known_at.0,
            certificate.request.definition(),
            replayed.report.rows.len(),
            hex(&certificate.output_digest),
        ),
    );
    Ok(())
}

/// `fa certificate status <certificate>`: `Current`, or `SupersededBy` the
/// entries recorded since its known-at that its selector folds.
pub(crate) fn certificate_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.get(1).map(String::as_str) != Some("status") {
        return Err(unhandled(
            "certificate",
            args.positional.get(1).map(String::as_str),
        ));
    }
    const EXAMPLE: &str = "fa certificate status tb.cert --book <dir> --json";
    let certificate = read(ctx, args, 2, EXAMPLE)?;
    let book = ctx.books.open(args)?;
    let id = certificate.id_text()?;
    ctx.out.certificate(id.clone());
    ctx.out.effective(selector(&certificate.request));
    let status = book.certificate_status(&certificate)??;
    let verdict = if status.is_current() {
        "Current"
    } else {
        "SupersededBy"
    };
    let later: Vec<Json> = status
        .later
        .iter()
        .map(|entry| {
            obj(vec![
                ("entry", s(format!("{:032x}", entry.vid.0))),
                ("recorded_at", Json::Int(i128::from(entry.recorded_at.0))),
                ("effective_date", s(entry.effective_date.render())),
                ("class", Json::Int(i128::from(entry.class))),
            ])
        })
        .collect();
    let human = if status.is_current() {
        format!(
            "Certificate {id} is Current at head {}: nothing recorded since sequence {} changes what it selects.",
            status.head.0, certificate.known_at.0
        )
    } else {
        format!(
            "Certificate {id} is SupersededBy {} later entries inside its selector (figures changed: {}); it still replays at sequence {}.",
            status.later.len(),
            if status.figures_changed { "yes" } else { "no" },
            certificate.known_at.0
        )
    };
    ctx.out.event(
        "certificate_status",
        vec![
            ("certificate", s(&id)),
            ("definition", s(certificate.request.definition())),
            ("known_at", Json::Int(i128::from(certificate.known_at.0))),
            ("head", Json::Int(i128::from(status.head.0))),
            ("status", s(verdict)),
            ("later_entries", Json::Arr(later)),
            ("figures_changed", Json::Bool(status.figures_changed)),
        ],
        &human,
    );
    Ok(())
}
