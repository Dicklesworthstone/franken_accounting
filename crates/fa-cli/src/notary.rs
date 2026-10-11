//! Accumulator verification and retained report replay on the CLI (§13).
//!
//! These commands publish and recompute the existing Notary state objects.
//! Report certificates bind native historical reads and exact folds. Neither
//! surface issues a signed TransparencyCheckpoint or an outsider evidence bundle.

use std::io::{Read, Write};

use crate::json::{Json, obj, s};
use fa::certificate::{AUTHORITY, MAX_CERTIFICATE_BYTES, OUTPUT_FORMAT, REPLAY_SCOPE};
use fa::{CertificateStatus, ReportCertificate, TrialBalanceSelection};
use fa_policy::{Capability, Op};

use crate::args::Args;
use crate::cli::{
    Ctx, Fail, Files, Out, Stdin, hex, periods_selector, principal, render_trial_balance,
    unhandled, usage,
};

fn certificate_invalid(message: impl Into<String>) -> Fail {
    fa_journal::Refusal::new(
        fa::certificate::code::CERTIFICATE_INVALID,
        fa_journal::exit::VERIFICATION,
        message,
        "plan §13.6 / FA-INV-11 (the retained certificate must decode and replay exactly)",
        "pass the canonical certificate file or its complete `bytes` hex string from the report_certificate event; keep the original book and registry versions",
    ).into()
}

/// A retained certificate may be read as its canonical binary file or as
/// the hex text emitted on stdout. Bound the read before allocating for it;
/// the library then independently checks its wire size, digest and closure.
fn read_report_certificate(files: &Files, path: &str) -> Result<ReportCertificate, Fail> {
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
    if bytes.starts_with(fa::certificate::CERTIFICATE_FORMAT) {
        return ReportCertificate::decode(&bytes).map_err(Into::into);
    }
    let text = std::str::from_utf8(&bytes).ok().map(str::trim);
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
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair)
                .map_err(|_| certificate_invalid("invalid certificate hex"))?;
            u8::from_str_radix(digits, 16)
                .map_err(|_| certificate_invalid("invalid certificate hex"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    ReportCertificate::decode(&decoded).map_err(Into::into)
}

/// Save a requested certificate without replacing any existing artifact.
/// This never writes to the accounting journal and never changes its frontier.
pub(crate) fn retain_report_certificate(
    files: &Files,
    args: &Args,
    certificate: &ReportCertificate,
) -> Result<Vec<u8>, Fail> {
    let bytes = certificate
        .canonical_bytes()
        .map_err(|e| Fail::Internal(format!("encode report certificate: {e}")))?;
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(certificate_invalid(
            "report certificate exceeds the 64 MiB format limit",
        ));
    }
    if let Some(path) = args.flag("--certificate-out") {
        if path == "-" {
            return Err(usage(
                "--certificate-out names a new file; - is not an output file",
                "use --certify to receive the complete certificate as hex on stdout",
            ));
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(files.resolve(path)).map_err(|e| {
            usage(
                format!("cannot create certificate file {path}: {e}"),
                "choose a new --certificate-out path; an existing file is never overwritten",
            )
        })?;
        file.write_all(&bytes).and_then(|()| file.sync_all()).map_err(|e| {
            Fail::Environment(format!(
                "could not finish certificate file {path}: {e}; preserve the partial file and retry with a new output path"
            ))
        })?;
    }
    Ok(bytes)
}

fn quoted_word(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

pub(crate) fn emit_report_certificate(
    out: &Out,
    args: &Args,
    certificate: &ReportCertificate,
    bytes: &[u8],
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
    let command = format!(
        "fa replay {}{environment} --json",
        file.map_or_else(|| "-".to_string(), quoted_word)
    );
    let human = match file {
        Some(path) => format!("Retained report certificate {digest} in {path}\n{command}"),
        None => format!(
            "Report certificate {digest} ({REPLAY_SCOPE}, {AUTHORITY})\nCertificate bytes (hex): {encoded}\nFeed these hex bytes to: {command}"
        ),
    };
    out.event_with_certificate(
        "report_certificate",
        vec![
            ("oid", s(&digest)),
            ("known_at", Json::Int(i128::from(certificate.known_at.0))),
            ("bytes", s(encoded)),
            ("file", file.map_or(Json::Null, s)),
            ("replay_command", s(command)),
            ("replay_scope", s(REPLAY_SCOPE)),
            ("authority", s(AUTHORITY)),
            ("output_format", s(OUTPUT_FORMAT)),
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
            "replay needs exactly one certificate file or -",
            "fa replay <certificate-file|-> --book <dir> --json",
        ));
    }
    let certificate = read_report_certificate(&ctx.files, &args.positional[1])?;
    let book = ctx.books.open(args)?;
    let report = book.replay_trial_balance(&certificate)??;
    render_trial_balance(
        &ctx.out,
        &book,
        &report,
        &certificate.selection,
        Some(&hex(&certificate.digest)),
    )
}

pub(crate) fn certificate_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.get(1).map(String::as_str) != Some("status") || args.positional.len() != 3 {
        return Err(usage(
            "certificate status needs exactly one certificate file or -",
            "fa certificate status <certificate-file|-> --book <dir> --json",
        ));
    }
    let certificate = read_report_certificate(&ctx.files, &args.positional[2])?;
    let book = ctx.books.open(args)?;
    let status = book.certificate_status(&certificate)??;
    let (name, checked_at, later_entries) = match status {
        CertificateStatus::Current { checked_at } => ("Current", checked_at, Vec::new()),
        CertificateStatus::SupersededBy {
            checked_at,
            later_entries,
        } => ("SupersededBy", checked_at, later_entries),
    };
    ctx.out.known_at(checked_at);
    ctx.out.effective(match &certificate.selection {
        TrialBalanceSelection::AsOf(day) => format!("as-of:{day}"),
        TrialBalanceSelection::Periods(periods) | TrialBalanceSelection::Activity(periods) => {
            periods_selector(periods)
        }
    });
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
    // The local CLI binds an explicit grant to its operator, like posting.
    // Refuse missing authority before opening or observing the book; the
    // facade independently enforces the same boundary for library callers.
    let actor = principal(args);
    let capability = Capability::embedded(actor, &args.flag_all("--grant"))
        .map_err(|error| usage(error.to_string(), EXAMPLE))?;
    // The book is not open yet, so its id (the `books` caveat's subject) is
    // unknown here; a self-issued embedded capability is Human, the actor's,
    // and carries no `books` caveat, so admission reduces to the op check.
    // The facade's admission judges the whole intent, book included.
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
            ("signatures", s("unsigned")),
            ("scope", s("entry_prefix")),
        ],
        &format!(
            "Created unsigned entry accumulator checkpoint {}: {} entries through sequence {}, recorded at {}. Root {}.",
            hex(&stored.oid.0), state.leaf_count, state.through_seq.0,
            stored.recorded_at.0, hex(&state.root),
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
        ("signatures", s("unsigned")),
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
            "Entry accumulator verified by recomputation: {} checkpoints through sequence {seq} (unsigned).",
            result.states.len(),
        ),
    };
    ctx.out.event("accumulator_verified", fields, &human);
    Ok(())
}
