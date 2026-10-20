//! Accumulator verification and retained report replay on the CLI (§13).
//!
//! These commands publish and recompute the existing Notary state objects.
//! Report certificates bind native historical reads and exact folds. Neither
//! surface issues a signed TransparencyCheckpoint or an outsider evidence bundle.

mod expectations;
mod procedure;

pub(crate) use expectations::{
    cash_flow_expectation_json, indirect_expectation_json, policy_cash_flow_expectation_json,
    portfolio_expectation_json, reconciliation_expectation_json, split_cash_flow_expectation_json,
};

use std::io::Read;

use crate::json::{Json, obj, s};
use fa::certificate::{AUTHORITY, MAX_CERTIFICATE_BYTES, REPLAY_SCOPE};
use fa::{
    Book, CertificateStatus, ReportArtifact, ReportArtifactFamily, ReportCertificate, ReportOutput,
    ReportSelection, RetainedCertificate, TrialBalanceSelection,
};
use fa_policy::{Capability, Op};
use fgdb_types::VId;

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

/// A comparison or trace may reach earlier sources than its final displayed
/// coordinate. Prepare that actual retained prefix, never a sentinel cutoff.
fn prepare_artifact_history(
    book: &mut Book,
    principal: VId,
    capability: &Capability,
    artifact: &ReportArtifact,
    bytes: &[u8],
) -> Result<(), Fail> {
    let known_at = match artifact.family() {
        ReportArtifactFamily::StatementDiff => {
            let certificate = fa::StatementDiffCertificate::decode(bytes)?;
            let (before, after) = certificate.sources();
            before.known_at.min(after.known_at)
        }
        ReportArtifactFamily::StatementTrace => {
            let certificate = fa::StatementTraceCertificate::decode(bytes)?;
            certificate
                .sources()
                .iter()
                .map(|source| source.known_at)
                .min()
                .ok_or_else(|| certificate_invalid("a statement trace has no source prefix"))?
        }
        _ => artifact.known_at(),
    };
    book.prepare_report_history(principal, capability, Some(known_at))??;
    Ok(())
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

/// Resolve a retained digest, or a file/stdin containing canonical binary or hex.
/// A bare 64-hex argument is a digest; prefix a filename with ./ if it has
/// that shape. Bound file/stdin reads before allocating for them.
fn read_certificate_bytes(
    book: &Book,
    files: &Files,
    path: &str,
    principal: VId,
    capability: &Capability,
) -> Result<Vec<u8>, Fail> {
    if let Some(digest) = certificate_digest(path)? {
        return book
            .read_report_artifact(principal, capability, &digest)??
            .canonical_bytes()
            .map_err(Into::into);
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
                "pass the certificate file saved by fa tb --certificate-out or the procedure certificate API",
            )
        })?;
        read(&mut file)?
    };
    if bytes.len() > limit {
        return Err(certificate_invalid(
            "report certificate input exceeds its bounded wire size",
        ));
    }
    // This recognizes binary transport only. The selected family decoder
    // still validates its full format, bounds and digest before replay.
    if bytes.starts_with(b"fa:report-certificate:")
        || bytes.get(4..).is_some_and(|body| body.starts_with(b"fa:"))
    {
        return Ok(bytes);
    }
    let text = std::str::from_utf8(&bytes).ok().map(str::trim);
    if let Some(text) = text
        && let Some(digest) = certificate_digest(text)?
    {
        return book
            .read_report_artifact(principal, capability, &digest)??
            .canonical_bytes()
            .map_err(Into::into);
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
    Ok(decoded)
}

/// Save an optional external copy, then retain the immutable certificate in
/// the book. The copy is written only for a capability the retention admits
/// (holder, read, book, expiry and revocation at the head), so a refused
/// retention leaves no host file. A duplicate certificate reuses its original
/// recorded sequence. The metadata write advances the book frontier, never
/// the accounting fold.
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
        fa_policy::admit_read(capability, capability.holder(), book.context().book_id)
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        book.admit_current(capability)??;
        crate::cli::write_new_output_file(files, path, &bytes, "certificate", "--certificate-out")?;
    }
    let retained = book.retain_certificate_authorized(certificate, capability)??;
    Ok((bytes, retained))
}

/// Retain the complete outer family after replay under current authority.
/// An external copy never substitutes the last native source for a complete
/// comparison or the source chain of a publication trace.
pub(crate) fn retain_report_artifact(
    book: &mut Book,
    files: &Files,
    args: &Args,
    artifact: &ReportArtifact,
    capability: &Capability,
) -> Result<(Vec<u8>, RetainedCertificate), Fail> {
    retain_report_artifact_for(
        book,
        files,
        args,
        artifact,
        capability,
        fa::ReportArtifactExpectation::AsSupplied,
    )
}

/// Retain a complete artifact only after replay against the independently
/// selected request and policy required by its report family.
pub(crate) fn retain_report_artifact_for(
    book: &mut Book,
    files: &Files,
    args: &Args,
    artifact: &ReportArtifact,
    capability: &Capability,
    expected: fa::ReportArtifactExpectation<'_>,
) -> Result<(Vec<u8>, RetainedCertificate), Fail> {
    expectations::validate_generated(expected)?;
    let bytes = artifact.canonical_bytes()?;
    if let Some(path) = args.flag("--certificate-out") {
        if path.is_empty() || path == "-" {
            return Err(usage(
                "--certificate-out names a new file; - is not an output file",
                "use --certify to receive the complete certificate as hex on stdout",
            ));
        }
        book.replay_report_artifact_for(
            capability.holder(),
            capability,
            &bytes,
            Some(artifact.digest()),
            expected,
        )??;
        crate::cli::write_new_output_file(files, path, &bytes, "certificate", "--certificate-out")?;
    }
    let retained = book.retain_report_artifact_for(
        capability.holder(),
        capability,
        &bytes,
        Some(artifact.digest()),
        expected,
    )??;
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
    emit_certificate(
        out,
        args,
        CertificatePresentation {
            source: certificate,
            digest: &certificate.digest,
            output_format: certificate.output_format(),
            output_digest: certificate.output_digest,
            replay_expectation: None,
            replay_options: None,
        },
        bytes,
        retained,
    );
}

pub(crate) fn emit_report_artifact(
    out: &Out,
    args: &Args,
    artifact: &ReportArtifact,
    output_format: &str,
    bytes: &[u8],
    retained: &RetainedCertificate,
) {
    emit_certificate(
        out,
        args,
        CertificatePresentation {
            source: artifact.source_certificate(),
            digest: artifact.digest(),
            output_format,
            output_digest: artifact.output_digest(),
            replay_expectation: None,
            replay_options: None,
        },
        bytes,
        retained,
    );
}

pub(crate) fn emit_report_artifact_for(
    out: &Out,
    args: &Args,
    artifact: &ReportArtifact,
    output_format: &str,
    bytes: &[u8],
    retained: &RetainedCertificate,
    expected: &Json,
) {
    let expectation = expected.render();
    emit_certificate(
        out,
        args,
        CertificatePresentation {
            source: artifact.source_certificate(),
            digest: artifact.digest(),
            output_format,
            output_digest: artifact.output_digest(),
            replay_expectation: Some(&expectation),
            replay_options: None,
        },
        bytes,
        retained,
    );
}

pub(crate) fn general_ledger_replay_options(
    book: &Book,
    report: &fa::GeneralLedger,
) -> Result<String, Fail> {
    let mut options = String::from(" --view detail");
    for account in report.accounts() {
        options.push_str(&format!(" --account {}", quoted_word(&account.code)));
    }
    for unit in report.units() {
        let code =
            crate::cli::registered_unit_code(fa_money::UnitId(*unit), &book.context().units)?;
        options.push_str(&format!(" --unit {}", quoted_word(&code)));
    }
    options.push_str(&format!(
        " --from {} --to {} --label {} --as-known-at {}",
        report.effective_from(),
        report.effective_through(),
        quoted_word(report.label()),
        report.known_at().0,
    ));
    Ok(options)
}

pub(crate) fn emit_general_ledger_certificate(
    out: &Out,
    args: &Args,
    artifact: &ReportArtifact,
    bytes: &[u8],
    retained: &RetainedCertificate,
    replay_options: &str,
) {
    emit_certificate(
        out,
        args,
        CertificatePresentation {
            source: artifact.source_certificate(),
            digest: artifact.digest(),
            output_format: "fa:roll-forward:v1",
            output_digest: artifact.output_digest(),
            replay_expectation: None,
            replay_options: Some(replay_options),
        },
        bytes,
        retained,
    );
}

struct CertificatePresentation<'a> {
    source: &'a ReportCertificate,
    digest: &'a [u8; 32],
    output_format: &'a str,
    output_digest: [u8; 32],
    replay_expectation: Option<&'a str>,
    replay_options: Option<&'a str>,
}

fn emit_certificate(
    out: &Out,
    args: &Args,
    presentation: CertificatePresentation<'_>,
    bytes: &[u8],
    retained: &RetainedCertificate,
) {
    let certificate = presentation.source;
    let digest = hex(presentation.digest);
    let encoded = hex(bytes);
    let file = args.flag("--certificate-out");
    let environment: String = ["--book", "--keys"]
        .iter()
        .filter_map(|flag| {
            args.flag(flag)
                .map(|path| format!(" {flag} {}", quoted_word(path)))
        })
        .collect();
    let expectation = presentation
        .replay_expectation
        .map_or_else(String::new, |expected| {
            format!(" --expect {}", quoted_word(expected))
        });
    let options = presentation.replay_options.unwrap_or("");
    let command = format!("fa replay C:{digest}{expectation}{options}{environment} --json");
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
            ("output_format", s(presentation.output_format)),
            ("output_digest", s(hex(&presentation.output_digest))),
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
    if args.flag_all("--output").len() > 1
        || args
            .flag("--output")
            .is_some_and(|path| path.is_empty() || path == "-")
    {
        return Err(usage(
            "--output names exactly one new file for the replayed canonical report",
            "fa replay C:<oid> --output <new-file> --json",
        ));
    }
    let detail_view = match args.flag("--view") {
        None => false,
        Some("detail") if args.flag_all("--view").len() == 1 => true,
        Some(_) => {
            return Err(usage(
                "--view accepts only detail",
                "fa replay C:<oid> --view detail --account <code> --unit <CODE> --from YYYY-MM-DD --to YYYY-MM-DD --label <label> --as-known-at <seq>",
            ));
        }
    };
    if detail_view && args.flag("--expect").is_some() {
        return Err(usage(
            "--view detail and --expect are separate request formats and cannot be combined",
            "use the complete replay_command from the original certified ledger",
        ));
    }
    let detail_flags = [
        "--account",
        "--unit",
        "--from",
        "--to",
        "--label",
        "--as-known-at",
    ];
    if !detail_view && detail_flags.iter().any(|flag| args.flag(flag).is_some()) {
        return Err(usage(
            "explicit ledger-view expectations require --view detail",
            "use the complete replay_command from the original certified ledger",
        ));
    }
    if detail_view {
        for flag in ["--from", "--to", "--label", "--as-known-at"] {
            if args.flag_all(flag).len() != 1 {
                return Err(usage(
                    format!("detail replay requires exactly one {flag}"),
                    "use the independently reviewed account, unit, dates, label and recorded sequence from the original ledger request",
                ));
            }
        }
        if !args
            .flag_all("--unit")
            .into_iter()
            .flat_map(|units| units.split(','))
            .any(|unit| !unit.trim().is_empty())
            || args
                .flag("--as-known-at")
                .and_then(|seq| seq.parse::<u64>().ok())
                .is_none()
        {
            return Err(usage(
                "detail replay requires explicit units and a numeric --as-known-at sequence, never HEAD",
                "use the complete replay_command from the original certified ledger",
            ));
        }
    }
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read"])?;
    // Saved provenance grants no current authority. Admission precedes
    // stamping book metadata, fetching retained bytes or reading a file.
    let mut book = ctx.books.open_admitted(args, |book| {
        fa_policy::admit_read(&capability, principal, book.context().book_id)
            .and_then(|()| fa_policy::reach(&capability, &fa_policy::Reach::whole_book(true), None))
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        book.read_scope(principal, &capability)??;
        book.prepare_report_history(principal, &capability, None)??;
        Ok(())
    })?;
    let expected = expectations::parse(args, &book, principal, &capability)?;
    let detail_expected = if detail_view {
        Some(crate::cli::parse_gl_scope(
            args,
            &book,
            &ctx.out,
            "gl-detail",
            "use the complete replay_command from the original certified ledger",
        )?)
    } else {
        None
    };
    let bytes = read_certificate_bytes(
        &book,
        &ctx.files,
        &args.positional[1],
        principal,
        &capability,
    )?;
    let artifact = ReportArtifact::decode(&bytes)?;
    prepare_artifact_history(&mut book, principal, &capability, &artifact, &bytes)?;
    if detail_view && artifact.family() != ReportArtifactFamily::RollForward {
        return Err(certificate_invalid(
            "--view detail requires a roll-forward source certificate",
        ));
    }
    if artifact.family() == ReportArtifactFamily::ScenarioDiff {
        // Its replay re-materializes the scenario with exactly the intents it
        // covered (Book::replay_scenario_diff); no recipient expectation
        // applies to it.
        if args.flag("--expect").is_some() {
            return Err(usage(
                "--expect names a cash-flow or reconciliation request; a scenario diff replays as supplied",
                "fa replay C:<oid> --json",
            ));
        }
        let certificate = fa::ScenarioDiffCertificate::decode(&bytes)?;
        let diff = book.replay_scenario_diff(principal, &capability, &certificate)??;
        if let Some(path) = args.flag("--output") {
            crate::cli::write_new_output_file(
                &ctx.files,
                path,
                certificate.output(),
                "replayed report",
                "--output",
            )?;
        }
        let digest = hex(artifact.digest());
        return crate::scenario::render_scenario_diff(&ctx.out, &book, &diff, Some(&digest));
    }
    let replayed = book.replay_report_artifact_for(
        principal,
        &capability,
        &bytes,
        Some(artifact.digest()),
        expected.borrowed(),
    )??;
    // Resolve typed reports before an output file or success event is emitted.
    // A generic receipt always identifies the original family's exact bytes.
    let native = if artifact.family() == ReportArtifactFamily::Native {
        Some(book.replay_report(artifact.source_certificate())??)
    } else {
        None
    };
    let diff = if artifact.family() == ReportArtifactFamily::StatementDiff {
        let certificate = fa::StatementDiffCertificate::decode(&bytes)?;
        Some(book.replay_statement_diff(principal, &capability, &certificate)??)
    } else {
        None
    };
    let trace = if artifact.family() == ReportArtifactFamily::StatementTrace {
        let certificate = fa::StatementTraceCertificate::decode(&bytes)?;
        Some(book.replay_statement_trace(principal, &capability, &certificate)??)
    } else {
        None
    };
    let summary = if artifact.family() == ReportArtifactFamily::Summary {
        let certificate = fa::SummaryCertificate::decode(&bytes)?;
        Some(book.replay_summary_trial_balance(principal, &capability, &certificate)??)
    } else {
        None
    };
    let roll_forward = if !detail_view && artifact.family() == ReportArtifactFamily::RollForward {
        let certificate = fa::RollForwardCertificate::decode(&bytes)?;
        Some(book.replay_roll_forward(principal, &capability, &certificate)??)
    } else {
        None
    };
    let detail = if let Some(expected) = detail_expected {
        let source = fa::RollForwardCertificate::decode(&bytes)?;
        let report = book.replay_general_ledger(principal, &capability, &source, &expected)??;
        let presentation = crate::cli::general_ledger_presentation(&book, &report)?;
        Some((report, presentation))
    } else {
        None
    };
    let aging = if artifact.family() == ReportArtifactFamily::EffectiveDateAging {
        let certificate = fa::AgingCertificate::decode(&bytes)?;
        Some(book.replay_effective_date_aging(principal, &capability, &certificate)??)
    } else {
        None
    };
    let procedure = if artifact.family() == ReportArtifactFamily::Procedure {
        Some(fa::procedure_certificate::ProcedureCertificate::decode(
            &bytes,
        )?)
    } else {
        None
    };
    if let Some(path) = args.flag("--output") {
        crate::cli::write_new_output_file(
            &ctx.files,
            path,
            &replayed.output,
            "replayed report",
            "--output",
        )?;
    }
    let digest = hex(artifact.digest());
    let rendered = if let Some(report) = native {
        let certificate = artifact.source_certificate();
        ctx.out.time_selection(certificate.time_selection.as_ref());
        match (&report, &certificate.selection) {
            (ReportOutput::TrialBalance(report), ReportSelection::TrialBalance(selection)) => {
                render_trial_balance(&ctx.out, &book, report, selection, Some(&digest))?
            }
            (ReportOutput::ExplainBalance(report), ReportSelection::ExplainBalance { .. }) => {
                render_balance_explanation(&ctx.out, &book, report, Some(&digest))?
            }
            (ReportOutput::OpenItems(report), ReportSelection::OpenItems { .. }) => {
                render_open_items(&ctx.out, &book, report, Some(&digest))?
            }
            (ReportOutput::Statement(report), ReportSelection::Statement(_)) => {
                crate::cli::render_statement(&ctx.out, &book, report, Some(&digest))?
            }
            _ => {
                return Err(certificate_invalid(
                    "replayed report kind differs from the retained certificate selector",
                ));
            }
        }
        true
    } else if let Some(diff) = diff {
        crate::cli::render_statement_diff(&ctx.out, &book, &diff, Some(&digest))?;
        true
    } else if let Some(trace) = trace {
        crate::cli::render_statement_trace(&ctx.out, &book, &trace, Some(&digest))?;
        true
    } else if let Some(summary) = summary {
        let ReportSelection::TrialBalance(selection) = &artifact.source_certificate().selection
        else {
            return Err(certificate_invalid(
                "summary certificate has no trial-balance source selector",
            ));
        };
        crate::cli::render_summary_trial_balance(
            &ctx.out,
            &book,
            &summary,
            selection,
            Some(&digest),
        )?;
        true
    } else if let Some((report, presentation)) = detail {
        crate::cli::render_general_ledger(&ctx.out, &report, presentation, Some(&digest));
        true
    } else if let Some(report) = roll_forward {
        crate::cli::render_roll_forward(&ctx.out, &book, &report, Some(&digest))?;
        true
    } else if let Some(report) = aging {
        crate::cli::render_aging(&ctx.out, &book, &report, Some(&digest))?;
        true
    } else if let Some(certificate) = procedure {
        procedure::render(&ctx.out, certificate.report(), &digest);
        true
    } else {
        false
    };
    // Preserve the existing generic-family replay receipt while adding the
    // original report event, so callers can still compare canonical digests.
    if !rendered
        || args.flag("--output").is_some()
        || matches!(
            artifact.family(),
            ReportArtifactFamily::Summary
                | ReportArtifactFamily::RollForward
                | ReportArtifactFamily::EffectiveDateAging
        )
    {
        ctx.out.known_at(replayed.known_at);
        ctx.out.event_with_certificate(
            "report_replayed",
            vec![
                ("family", s(replayed.family.name())),
                ("known_at", Json::Int(i128::from(replayed.known_at.0))),
                ("output_bytes", Json::Int(replayed.output.len() as i128)),
                ("output_digest", s(hex(&artifact.output_digest()))),
                ("file", args.flag("--output").map_or(Json::Null, s)),
            ],
            &format!(
                "Replayed {} certificate {digest} at sequence {} ({} canonical output bytes)",
                replayed.family.name(),
                replayed.known_at.0,
                replayed.output.len(),
            ),
            Some(&digest),
        );
    }
    Ok(())
}

pub(crate) fn certificate_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.get(1).map(String::as_str) != Some("status") || args.positional.len() != 3 {
        return Err(usage(
            "certificate status needs exactly one certificate digest, file or -",
            "fa certificate status <C:oid|oid|certificate-file|-> --book <dir> --json",
        ));
    }
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        fa_policy::admit_read(&capability, principal, book.context().book_id)
            .and_then(|()| fa_policy::reach(&capability, &fa_policy::Reach::whole_book(true), None))
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        book.read_scope(principal, &capability)??;
        book.prepare_report_history(principal, &capability, None)??;
        Ok(())
    })?;
    let bytes = read_certificate_bytes(
        &book,
        &ctx.files,
        &args.positional[2],
        principal,
        &capability,
    )?;
    let artifact = ReportArtifact::decode(&bytes)?;
    prepare_artifact_history(&mut book, principal, &capability, &artifact, &bytes)?;
    // Status is meaningful only after the WHOLE artifact verifies. For a
    // comparison or trace, relevance starts at its final statement frontier;
    // a scenario diff is superseded only by Plan records its scenario gained
    // after the certified prefix (its trunk is fixed at the fork).
    let status = match artifact.family() {
        ReportArtifactFamily::ScenarioDiff => {
            if args.flag("--expect").is_some() {
                return Err(usage(
                    "scenario status uses its pinned intent prefix and does not accept report-policy expectations",
                    "fa certificate status C:<scenario-certificate> --json",
                ));
            }
            let certificate = fa::ScenarioDiffCertificate::decode(&bytes)?;
            book.scenario_diff_status(principal, &capability, &certificate)??
        }
        _ => {
            let expected = expectations::parse(args, &book, principal, &capability)?;
            book.report_artifact_status(
                principal,
                &capability,
                &bytes,
                Some(artifact.digest()),
                expected.borrowed(),
            )??
        }
    };
    let certificate = artifact.source_certificate();
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
    let digest = hex(artifact.digest());
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
            ("evidence_after_seq", evidence_after(state.evidence_after)),
            ("leaf_kinds", leaf_kinds(&created.leaf_kinds)),
            ("root", s(hex(&state.root))),
            ("prev_state_oid", state.prev_state_oid.map_or(Json::Null, |oid| s(hex(&oid.0)))),
            ("signatures", s("ed25519")),
            ("checkpoint_oid", s(hex(&created.checkpoint.oid.0))),
            ("public_key", s(hex(&book.checkpoint_public_key()))),
            ("scope", s("entry_prefix")),
        ],
        &format!(
            "Created entry accumulator checkpoint {}: {} leaves ({} entries, {} evidence records) through sequence {}, recorded at {}. Root {}.\nSigned TransparencyCheckpoint {} (Ed25519 public key {}); export it with `fa proof signed-checkpoint` and check it with `fa-verify checkpoint <file> --key <public key>`.",
            hex(&stored.oid.0), state.leaf_count, created.leaf_kinds.entries,
            state.leaf_count.saturating_sub(created.leaf_kinds.entries), state.through_seq.0,
            stored.recorded_at.0, hex(&state.root),
            hex(&created.checkpoint.oid.0), hex(&book.checkpoint_public_key()),
        ),
    );
    Ok(())
}

/// A state's evidence boundary: null for an entries-only state.
fn evidence_after(boundary: Option<fgdb_types::CommitSeq>) -> Json {
    boundary.map_or(Json::Null, |seq| Json::Int(i128::from(seq.0)))
}

/// An accumulator prefix's leaves by record kind.
fn leaf_kinds(kinds: &fa::LeafKinds) -> Json {
    obj(vec![
        ("entries", Json::Int(i128::from(kinds.entries))),
        ("attestations", Json::Int(i128::from(kinds.attestations))),
        (
            "import_receipts",
            Json::Int(i128::from(kinds.import_receipts)),
        ),
        (
            "custody_transfers",
            Json::Int(i128::from(kinds.custody_transfers)),
        ),
        (
            "supplemental_evidence",
            Json::Int(i128::from(kinds.supplemental_evidence)),
        ),
    ])
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
                ("evidence_after_seq", evidence_after(state.evidence_after)),
                (
                    "leaf_kinds",
                    state.leaf_kinds.as_ref().map_or(Json::Null, leaf_kinds),
                ),
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
