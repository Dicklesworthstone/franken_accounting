//! Accumulator verification and retained report replay on the CLI (§13).
//!
//! These commands publish and recompute the existing Notary state objects.
//! Report certificates bind native historical reads and exact folds. Neither
//! surface issues a signed TransparencyCheckpoint or an outsider evidence bundle.

use std::io::Read;

use crate::json::{Json, obj, s};
use fa::certificate::{AUTHORITY, MAX_CERTIFICATE_BYTES, REPLAY_SCOPE};
use fa::{
    Book, CertificateStatus, ReportCertificate, ReportOutput, ReportSelection, RetainedCertificate,
    TrialBalanceSelection,
};
use fa_policy::Op;

use crate::args::Args;
use crate::cli::{
    Ctx, Fail, Files, Out, Stdin, hex, periods_selector, render_balance_explanation,
    render_open_items, render_trial_balance, unhandled, usage,
};

fn certificate_invalid(message: impl Into<String>) -> Fail {
    fa_journal::Refusal::new(
        fa::certificate::code::CERTIFICATE_INVALID,
        fa_journal::exit::VERIFICATION,
        message,
        "plan §13.6 / FA-INV-11 (the retained certificate must decode and replay exactly)",
        "pass the retained certificate's C:<oid>, its canonical file, or its complete `bytes` hex string from the report_certificate event; keep the original book and registry versions",
    ).into()
}

fn certificate_digest(text: &str) -> Result<Option<[u8; 32]>, Fail> {
    let explicit = text.strip_prefix("C:");
    let digits = explicit.unwrap_or(text);
    if digits.len() != 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return if explicit.is_some() {
            Err(certificate_invalid(
                "C: must be followed by a complete 64-hex certificate digest",
            ))
        } else {
            Ok(None)
        };
    }
    let mut digest = [0; 32];
    for (byte, pair) in digest.iter_mut().zip(digits.as_bytes().as_chunks::<2>().0) {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| certificate_invalid("invalid certificate digest hex"))?;
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|_| certificate_invalid("invalid certificate digest hex"))?;
    }
    Ok(Some(digest))
}

/// Resolve a retained digest, canonical binary file, or inline hex input.
/// A bare 64-hex argument is a digest; prefix a filename with ./ if it has
/// that shape. Bound file/stdin reads before allocating for them.
fn read_report_certificate(
    book: &Book,
    files: &Files,
    path: &str,
) -> Result<ReportCertificate, Fail> {
    if let Some(digest) = certificate_digest(path)? {
        return Ok(book.read_certificate(&digest)??);
    }
    let limit = MAX_CERTIFICATE_BYTES * 2 + 2; // hex plus a final CRLF
    let read = |reader: &mut dyn Read| -> Result<Vec<u8>, Fail> {
        let mut bytes = Vec::new();
        reader
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| {
                usage(
                    format!("{path}: {e}"),
                    "pass a readable certificate file or - for stdin",
                )
            })?;
        Ok(bytes)
    };
    let bytes = if path == "-" {
        match &files.stdin {
            Stdin::Forwarded(bytes) => {
                if bytes.len() > limit {
                    return Err(certificate_invalid(
                        "report certificate input exceeds its bounded wire size",
                    ));
                }
                bytes.clone()
            }
            Stdin::Missing => {
                return Err(usage(
                    "- names certificate stdin, but no bytes reached the command",
                    "forward the report_certificate event's bytes string, or pass its saved certificate file",
                ));
            }
            Stdin::Process => read(&mut std::io::stdin().lock())?,
        }
    } else {
        let mut file = std::fs::File::open(files.resolve(path)).map_err(|e| {
            usage(
                format!("{path}: {e}"),
                "pass the certificate file saved by fa tb --certificate-out",
            )
        })?;
        read(&mut file)?
    };
    if bytes.len() > limit {
        return Err(certificate_invalid(
            "report certificate input exceeds its bounded wire size",
        ));
    }
    if bytes.starts_with(b"fa:report-certificate:") {
        return ReportCertificate::decode(&bytes).map_err(Into::into);
    }
    let text = std::str::from_utf8(&bytes).ok().map(str::trim);
    if let Some(text) = text
        && let Some(digest) = certificate_digest(text)?
    {
        return Ok(book.read_certificate(&digest)??);
    }
    let Some(text) = text.filter(|text| {
        !text.is_empty() && text.len() % 2 == 0 && text.bytes().all(|b| b.is_ascii_hexdigit())
    }) else {
        return Err(certificate_invalid(
            "expected a canonical binary report certificate or its complete hex encoding",
        ));
    };
    if text.len() / 2 > MAX_CERTIFICATE_BYTES {
        return Err(certificate_invalid(
            "report certificate exceeds the 64 MiB format limit",
        ));
    }
    let decoded = text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digits = std::str::from_utf8(pair)
                .map_err(|_| certificate_invalid("invalid certificate hex"))?;
            u8::from_str_radix(digits, 16)
                .map_err(|_| certificate_invalid("invalid certificate hex"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ReportCertificate::decode(&decoded).map_err(Into::into)
}

/// Save an optional external copy, then retain the immutable certificate in
/// the book. A duplicate certificate reuses its original recorded sequence.
/// The metadata write advances the book frontier, never the accounting fold.
pub(crate) fn retain_report_certificate(
    book: &mut Book,
    files: &Files,
    args: &Args,
    certificate: &ReportCertificate,
    capability: &fa_journal::Capability,
) -> Result<(Vec<u8>, RetainedCertificate), Fail> {
    let bytes = certificate
        .canonical_bytes()
        .map_err(|e| Fail::Internal(format!("encode report certificate: {e}")))?;
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(certificate_invalid(
            "report certificate exceeds the 64 MiB format limit",
        ));
    }
    if let Some(path) = args.flag("--certificate-out") {
        if path.is_empty() || path == "-" {
            return Err(usage(
                "--certificate-out names a new file; - is not an output file",
                "use --certify to receive the complete certificate as hex on stdout",
            ));
        }
        crate::cli::write_new_output_file(files, path, &bytes, "certificate", "--certificate-out")?;
    }
    let retained = book.retain_certificate_authorized(certificate, capability)??;
    Ok((bytes, retained))
}

fn quoted_word(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

pub(crate) fn emit_report_certificate(
    out: &Out,
    args: &Args,
    certificate: &ReportCertificate,
    bytes: &[u8],
    retained: &RetainedCertificate,
) {
    let digest = hex(&certificate.digest);
    let encoded = hex(bytes);
    let file = args.flag("--certificate-out");
    let environment: String = ["--book", "--keys"]
        .iter()
        .filter_map(|flag| {
            args.flag(flag)
                .map(|path| format!(" {flag} {}", quoted_word(path)))
        })
        .collect();
    let command = format!("fa replay C:{digest}{environment} --json");
    let human = match file {
        Some(path) => format!(
            "Retained report certificate {digest} in the book at sequence {} and in {path}\n{command}",
            retained.recorded_at.0
        ),
        None => format!(
            "Retained report certificate {digest} in the book at sequence {} ({REPLAY_SCOPE}, {AUTHORITY})\n{command}\nCertificate bytes (hex): {encoded}",
            retained.recorded_at.0
        ),
    };
    out.event_with_certificate(
        "report_certificate",
        vec![
            ("oid", s(&digest)),
            ("known_at", Json::Int(i128::from(certificate.known_at.0))),
            ("recorded_at", Json::Int(i128::from(retained.recorded_at.0))),
            ("bytes", s(encoded)),
            ("file", file.map_or(Json::Null, s)),
            ("replay_command", s(command)),
            ("replay_scope", s(REPLAY_SCOPE)),
            ("authority", s(AUTHORITY)),
            ("output_format", s(certificate.output_format())),
            ("output_digest", s(hex(&certificate.output_digest))),
            ("native_inputs", Json::Int(certificate.inputs.len() as i128)),
            ("journal_root", s(hex(&certificate.journal_root))),
            (
                "journal_leaves",
                Json::Int(i128::from(certificate.journal_leaves)),
            ),
        ],
        &human,
        Some(&digest),
    );
}

pub(crate) fn replay_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "replay needs exactly one certificate digest, file or -",
            "fa replay <C:oid|oid|certificate-file|-> --book <dir> --json",
        ));
    }
    let book = ctx.books.open(args)?;
    let certificate = read_report_certificate(&book, &ctx.files, &args.positional[1])?;
    let report = book.replay_report(&certificate)??;
    ctx.out.time_selection(certificate.time_selection.as_ref());
    let digest = hex(&certificate.digest);
    match (&report, &certificate.selection) {
        (ReportOutput::TrialBalance(report), ReportSelection::TrialBalance(selection)) => {
            render_trial_balance(&ctx.out, &book, report, selection, Some(&digest))
        }
        (ReportOutput::ExplainBalance(report), ReportSelection::ExplainBalance { .. }) => {
            render_balance_explanation(&ctx.out, &book, report, Some(&digest))
        }
        (ReportOutput::OpenItems(report), ReportSelection::OpenItems { .. }) => {
            render_open_items(&ctx.out, &book, report, Some(&digest))
        }
        (ReportOutput::Statement(report), ReportSelection::Statement(_)) => {
            crate::cli::render_statement(&ctx.out, &book, report, Some(&digest))
        }
        _ => Err(certificate_invalid(
            "replayed report kind differs from the retained certificate selector",
        )),
    }
}

pub(crate) fn certificate_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.get(1).map(String::as_str) != Some("status") || args.positional.len() != 3 {
        return Err(usage(
            "certificate status needs exactly one certificate digest, file or -",
            "fa certificate status <C:oid|oid|certificate-file|-> --book <dir> --json",
        ));
    }
    let book = ctx.books.open(args)?;
    let certificate = read_report_certificate(&book, &ctx.files, &args.positional[2])?;
    let status = book.certificate_status(&certificate)??;
    let (name, checked_at, later_entries) = match status {
        CertificateStatus::Current { checked_at } => ("Current", checked_at, Vec::new()),
        CertificateStatus::SupersededBy {
            checked_at,
            later_entries,
        } => ("SupersededBy", checked_at, later_entries),
    };
    ctx.out.known_at(checked_at);
    match &certificate.selection {
        ReportSelection::TrialBalance(selection) => {
            ctx.out.effective(match selection {
                TrialBalanceSelection::AsOf(day) => format!("as-of:{day}"),
                TrialBalanceSelection::Periods(periods)
                | TrialBalanceSelection::Activity(periods) => periods_selector(periods),
            });
        }
        ReportSelection::ExplainBalance { period, .. } => {
            ctx.out.effective(format!("period:{period}"));
        }
        ReportSelection::OpenItems { .. } => {}
        ReportSelection::Statement(selection) => {
            ctx.out.effective(periods_selector(&selection.periods));
        }
    }
    let digest = hex(&certificate.digest);
    ctx.out.event_with_certificate(
        "certificate_status",
        vec![
            ("oid", s(&digest)),
            ("status", s(name)),
            ("known_at", Json::Int(i128::from(certificate.known_at.0))),
            ("checked_at", Json::Int(i128::from(checked_at.0))),
            ("later_entries", Json::Arr(later_entries.iter().map(|vid| s(format!("{:032x}", vid.0))).collect())),
            ("replay_scope", s(REPLAY_SCOPE)),
            ("authority", s(AUTHORITY)),
        ],
        &format!("Certificate {digest}: {name} (known at {}, checked at {}, {} later entries in its selector)", certificate.known_at.0, checked_at.0, later_entries.len()),
        Some(&digest),
    );
    Ok(())
}

fn arguments(args: &Args, example: &str) -> Result<(), Fail> {
    if let Some(extra) = args.positional.get(2) {
        return Err(usage(format!("unexpected argument `{extra}`"), example));
    }
    for flag in ["--period", "--fiscal-year"] {
        if args.flag(flag).is_some() {
            return Err(usage(
                format!(
                    "{flag} cannot select an accumulator checkpoint; each state covers an entry prefix"
                ),
                example,
            ));
        }
    }
    Ok(())
}

pub(crate) fn checkpoint_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.get(1).map(String::as_str) != Some("create") {
        return Err(unhandled(
            "checkpoint",
            args.positional.get(1).map(String::as_str),
        ));
    }
    const EXAMPLE: &str = "fa checkpoint create --grant witness --book <dir> --json";
    arguments(args, EXAMPLE)?;
    // Resolve the actor and capability from the execution posture. Bound
    // hosts preserve their launch capability; only the embedded owner path
    // constructs one from its explicit grants. Refuse a missing operation
    // before opening the book; the facade judges scope and current authority.
    let actor = ctx.principal(args);
    let capability = ctx.capability(args, &[])?;
    fa_policy::require(&capability, Op::Witness, "writing this intent (`witness`)")
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    let mut book = ctx.books.open(args)?;
    let created = book.checkpoint(actor, &capability)??;
    ctx.out.at_book(&book)?;
    let stored = &created.stored;
    let state = &stored.state;
    ctx.out.event(
        "checkpoint_created",
        vec![
            ("book", s(hex(&state.book_id.0))),
            ("branch", s(hex(&state.branch_id.0))),
            ("oid", s(hex(&stored.oid.0))),
            ("recorded_at", Json::Int(i128::from(stored.recorded_at.0))),
            ("through_seq", Json::Int(i128::from(state.through_seq.0))),
            ("leaf_count", Json::Int(i128::from(state.leaf_count))),
            ("root", s(hex(&state.root))),
            ("prev_state_oid", state.prev_state_oid.map_or(Json::Null, |oid| s(hex(&oid.0)))),
            ("signatures", s("ed25519")),
            ("checkpoint_oid", s(hex(&created.checkpoint.oid.0))),
            ("public_key", s(hex(&book.checkpoint_public_key()))),
            ("scope", s("entry_prefix")),
        ],
        &format!(
            "Created entry accumulator checkpoint {}: {} entries through sequence {}, recorded at {}. Root {}.\nSigned TransparencyCheckpoint {} (Ed25519 public key {}); export it with `fa proof signed-checkpoint` and check it with `fa-verify checkpoint <file> --key <public key>`.",
            hex(&stored.oid.0), state.leaf_count, state.through_seq.0,
            stored.recorded_at.0, hex(&state.root),
            hex(&created.checkpoint.oid.0), hex(&book.checkpoint_public_key()),
        ),
    );
    Ok(())
}

pub(crate) fn verify_accumulator(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    arguments(args, "fa verify accumulator --book <dir> --json")?;
    let book = ctx.books.open(args)?;
    let result = book.verify_accumulator()?;
    let green = result.is_green();
    let through = if green {
        result.states.first().map(|state| state.through_seq.0)
    } else {
        None
    };
    let status = if !green {
        "failed"
    } else if result.states.is_empty() {
        "no_checkpoints"
    } else {
        "verified"
    };
    let states = result
        .states
        .iter()
        .map(|state| {
            obj(vec![
                ("oid", s(hex(&state.oid.0))),
                ("through_seq", Json::Int(i128::from(state.through_seq.0))),
                ("recorded_at", Json::Int(i128::from(state.recorded_at.0))),
                ("leaf_count", Json::Int(i128::from(state.leaf_count))),
                ("finding", state.finding.as_ref().map_or(Json::Null, s)),
            ])
        })
        .collect();
    let fields = vec![
        ("status", s(status)),
        ("signatures", s("ed25519")),
        ("scope", s("entry_prefix")),
        ("states_checked", Json::Int(result.states.len() as i128)),
        ("broken", result.broken.as_ref().map_or(Json::Null, s)),
        (
            "verified_through",
            through.map_or(Json::Null, |seq| Json::Int(i128::from(seq))),
        ),
        ("states", Json::Arr(states)),
        (
            "unchained",
            Json::Arr(
                result
                    .unchained
                    .iter()
                    .map(|vid| s(format!("{:032x}", vid.0)))
                    .collect(),
            ),
        ),
    ];
    if !green {
        let findings = result
            .states
            .iter()
            .filter(|state| state.finding.is_some())
            .count();
        return Err(Fail::Verification {
            message: format!(
                "entry accumulator differs from the journal: {findings} state findings, {} unchained states{}",
                result.unchained.len(),
                result
                    .broken
                    .as_ref()
                    .map_or_else(String::new, |why| format!("; broken chain: {why}")),
            ),
            detail: obj(fields),
            cite: None,
            fix: None,
        });
    }
    let human = match through {
        None => "No accumulator checkpoints to verify; run `fa checkpoint create --grant witness`."
            .to_string(),
        Some(seq) => format!(
            "Entry accumulator verified by recomputation: {} checkpoints through sequence {seq}, each signed checkpoint reproduced from the journal and the book's key.",
            result.states.len(),
        ),
    };
    ctx.out.event("accumulator_verified", fields, &human);
    Ok(())
}
