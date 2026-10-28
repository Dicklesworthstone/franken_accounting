//! Accumulator verification and retained report replay on the CLI (§13).
//!
//! These commands publish and recompute the existing Notary state objects.
//! Report certificates bind native historical reads and exact folds. Neither
//! surface issues a signed TransparencyCheckpoint or an outsider evidence bundle.

mod expectations;
mod procedure;

pub(crate) use expectations::{
    aging_expectation_json, cash_flow_expectation_json, due_date_aging_expectation_json,
    due_date_reconciliation_bundle_expectation, due_date_reconciliation_expectation_json,
    equity_expectation_json, external_feed_expectation_json, indirect_expectation_json,
    native_subledger_expectation_json, policy_cash_flow_expectation_json,
    portfolio_expectation_json, reconciliation_bundle_expectation, reconciliation_expectation_json,
    split_cash_flow_expectation_json,
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
pub(crate) fn prepare_artifact_history(
    book: &mut Book,
    principal: VId,
    capability: &Capability,
    artifact: &ReportArtifact,
    bytes: &[u8],
) -> Result<(), Fail> {
    // Another book's prefix means nothing here: refuse the certificate as
    // another book's before selecting any prefix of this one.
    if artifact.book_id() != book.context().book_id {
        return Err(certificate_invalid(
            "report artifact belongs to another book",
        ));
    }
    if artifact.uses_functional_valuations() {
        // Functional verification checks immutable Entry births and carrying
        // sources even when the supplied file selects HEAD. A compacted book
        // needs the complete retained history in that case too.
        book.replay_report_artifact_for_with_history(
            principal,
            capability,
            bytes,
            Some(artifact.digest()),
            fa::ReportArtifactExpectation::AsSupplied,
        )??;
        return Ok(());
    }
    if artifact.family() == ReportArtifactFamily::ExternalFeed {
        book.prepare_external_feed_history(principal, capability, Some(artifact.known_at()))??;
        return Ok(());
    }
    if artifact.family() == ReportArtifactFamily::Procedure {
        let certificate = fa::ProcedureCertificate::decode(bytes)?;
        book.prepare_procedure_history(
            principal,
            capability,
            &certificate.report().procedure,
            false,
        )??;
    }
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
pub(crate) fn read_certificate_bytes(
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

/// One certificate a command names in `flag` (a retained `C:<oid>`, a
/// canonical file, or `-` for stdin), decoded as the family `decode` reads.
/// A certificate of another family is refused under the flag that named it.
pub(crate) fn certificate_input<T>(
    book: &Book,
    files: &Files,
    flag: &str,
    value: &str,
    principal: VId,
    capability: &Capability,
    decode: impl FnOnce(&[u8]) -> Result<T, fa_journal::Refusal>,
) -> Result<T, Fail> {
    let bytes = read_certificate_bytes(book, files, value, principal, capability)?;
    decode(&bytes)
        .map_err(|refusal| certificate_invalid(format!("{flag} `{value}`: {}", refusal.message)))
}

/// Save an optional external copy, then retain the immutable certificate in
/// the book. The copy is written only for a capability the retention admits
/// (holder, read, produce, book, expiry and revocation at the head), so a refused
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
    fa_policy::admit_read(capability, capability.holder(), book.context().book_id)
        .and_then(|()| {
            fa_policy::require(
                capability,
                fa_policy::Op::Produce,
                "retaining a report certificate",
            )
        })
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    book.admit_current(capability)??;
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
    let retained = book.retain_certificate(capability.holder(), capability, certificate)??;
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

/// The `--view roll-forward` options that bind a replay of a certified
/// roll-forward to the certificate's canonical request, as
/// [`general_ledger_replay_options`] does for the ledger detail view, so
/// the receipt's replay command reaches the lead-schedule workpaper.
pub(crate) fn roll_forward_replay_options(
    book: &Book,
    certificate: &fa::RollForwardCertificate,
    report: &fa::RollForward,
) -> Result<String, Fail> {
    let request = certificate.request();
    let mut options = String::from(" --view roll-forward");
    for account in &request.accounts {
        let code = report
            .accounts
            .iter()
            .find(|row| row.id == account.0)
            .map(|row| row.code.as_str())
            .ok_or_else(|| {
                Fail::Internal("a certified roll-forward account is missing from its report".into())
            })?;
        options.push_str(&format!(" --account {}", quoted_word(code)));
    }
    for unit in &request.units {
        let code =
            crate::cli::registered_unit_code(fa_money::UnitId(*unit), &book.context().units)?;
        options.push_str(&format!(" --unit {}", quoted_word(&code)));
    }
    let known_at = request.known_at.ok_or_else(|| {
        Fail::Internal("a roll-forward certificate without its recorded prefix".into())
    })?;
    options.push_str(&format!(
        " --from {} --to {} --label {} --as-known-at {}",
        request.effective_from,
        request.effective_through,
        quoted_word(&request.label),
        known_at.0,
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

/// Families with a recipient-bound JSONL workpaper export (`--workpaper-out`).
/// A roll-forward source needs `--view detail` (ledger lines) or `--view
/// roll-forward` (the lead schedule); effective-date aging needs an aging
/// `--expect`, because each export binds the recipient's own request.
fn has_workpaper(family: ReportArtifactFamily, view_bound: bool, aging_expected: bool) -> bool {
    match family {
        ReportArtifactFamily::RollForward => view_bound,
        ReportArtifactFamily::EffectiveDateAging => aging_expected,
        ReportArtifactFamily::CashFlow
        | ReportArtifactFamily::AgingReconciliation
        | ReportArtifactFamily::AgingPortfolio
        | ReportArtifactFamily::StatementDiff
        | ReportArtifactFamily::StatementTrace => true,
        _ => false,
    }
}

fn unsupported_workpaper(family: ReportArtifactFamily) -> Fail {
    let message = match family {
        ReportArtifactFamily::RollForward => {
            "a roll-forward certificate's workpaper is bound to a view: replay it with --view detail or --view roll-forward".to_string()
        }
        ReportArtifactFamily::EffectiveDateAging => {
            "an effective-date-aging certificate's workpaper is bound to the recipient's aging --expect".to_string()
        }
        _ => format!(
            "{} certificates have no JSONL workpaper export",
            family.name()
        ),
    };
    usage(
        message,
        "--workpaper-out exports a roll-forward source's ledger detail or lead schedule (replay it with --view detail or --view roll-forward), effective-date aging (with its aging --expect), cash-flow, aging-reconciliation, aging-portfolio, statement-diff and statement-trace certificates",
    )
}

/// The library's workpaper export for one replayed family. Each export
/// replays the certificate again against the same independent request under
/// current read+produce authority and returns all of its text or none.
fn workpaper_jsonl(
    book: &Book,
    principal: VId,
    capability: &Capability,
    family: ReportArtifactFamily,
    bytes: &[u8],
    expected: &expectations::Expected,
    view: Option<(&str, &fa::RollForwardRequest)>,
) -> Result<String, Fail> {
    use expectations::Expected;
    Ok(match (family, expected, view) {
        (ReportArtifactFamily::RollForward, _, Some(("detail", request))) => book
            .general_ledger_jsonl(
                principal,
                capability,
                &fa::RollForwardCertificate::decode(bytes)?,
                request,
            )??,
        (ReportArtifactFamily::RollForward, _, Some((_, request))) => book.roll_forward_jsonl(
            principal,
            capability,
            &fa::RollForwardCertificate::decode(bytes)?,
            request,
        )??,
        (ReportArtifactFamily::CashFlow, Expected::CashFlow(request, definition), _) => book
            .cash_flow_jsonl(
                principal,
                capability,
                &fa::CashFlowCertificate::decode(bytes)?,
                request,
                definition,
            )??,
        (ReportArtifactFamily::AgingReconciliation, Expected::Reconciliation(request), _) => book
            .effective_date_aging_reconciliation_jsonl(
                principal,
                capability,
                &fa::AgingReconciliationCertificate::decode(bytes)?,
                request,
            )??,
        (ReportArtifactFamily::AgingPortfolio, Expected::Portfolio(request), _) => book
            .aging_portfolio_jsonl(
                principal,
                capability,
                &fa::aging::portfolio::AgingPortfolioCertificate::decode(bytes)?,
                request,
            )??,
        (ReportArtifactFamily::EffectiveDateAging, Expected::Aging(request), _) => book
            .effective_date_aging_jsonl(
                principal,
                capability,
                &fa::AgingCertificate::decode(bytes)?,
                request,
            )??,
        (ReportArtifactFamily::StatementTrace, Expected::AsSupplied, _) => book
            .statement_trace_jsonl(
                principal,
                capability,
                &fa::StatementTraceCertificate::decode(bytes)?,
            )??,
        // The library's statement review package also renders Markdown; the
        // replay surface exports its JSONL, like every other family.
        (ReportArtifactFamily::StatementDiff, Expected::AsSupplied, _) => book
            .statement_diff_workpaper(
                principal,
                capability,
                &fa::StatementDiffCertificate::decode(bytes)?,
            )??
            .jsonl()
            .to_string(),
        (family, _, _) => return Err(unsupported_workpaper(family)),
    })
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
    if args.flag_all("--workpaper-out").len() > 1
        || args
            .flag("--workpaper-out")
            .is_some_and(|path| path.is_empty() || path == "-")
    {
        return Err(usage(
            "--workpaper-out names exactly one new file for the replayed JSONL workpaper",
            "fa replay C:<oid> --expect '<JSON>' --workpaper-out <new-file> --json",
        ));
    }
    let workpaper_out = args.flag("--workpaper-out");
    // --workpaper returns the same text inline (the only form MCP can carry,
    // since it accepts no host paths); --workpaper-out writes a file.
    let workpaper_inline = args.switch("--workpaper");
    if workpaper_inline && workpaper_out.is_some() {
        return Err(usage(
            "--workpaper returns the workpaper inline and --workpaper-out writes it to a file; choose one",
            "fa replay C:<oid> --expect '<JSON>' --workpaper --json",
        ));
    }
    let workpaper_requested = workpaper_inline || workpaper_out.is_some();
    // A view binds a roll-forward source to an explicitly stated request and
    // replays its ledger lines (detail) or its lead schedule (roll-forward).
    let view = match args.flag("--view") {
        None => None,
        Some(view @ ("detail" | "roll-forward")) if args.flag_all("--view").len() == 1 => {
            Some(view)
        }
        Some(_) => {
            return Err(usage(
                "--view accepts detail or roll-forward",
                "fa replay C:<oid> --view detail|roll-forward --account <code> --unit <CODE> --from YYYY-MM-DD --to YYYY-MM-DD --label <label> --as-known-at <seq>",
            ));
        }
    };
    let detail_view = view == Some("detail");
    if view.is_some() && args.flag("--expect").is_some() {
        return Err(usage(
            "--view and --expect are separate request formats and cannot be combined",
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
    if view.is_none() && detail_flags.iter().any(|flag| args.flag(flag).is_some()) {
        return Err(usage(
            "explicit ledger-view expectations require --view detail or --view roll-forward",
            "use the complete replay_command from the original certified ledger",
        ));
    }
    if let Some(view) = view {
        for flag in ["--from", "--to", "--label", "--as-known-at"] {
            if args.flag_all(flag).len() != 1 {
                return Err(usage(
                    format!("{view} replay requires exactly one {flag}"),
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
                format!(
                    "{view} replay requires explicit units and a numeric --as-known-at sequence, never HEAD"
                ),
                "use the complete replay_command from the original certified ledger",
            ));
        }
    }
    let principal = ctx.principal(args);
    // A workpaper is a produced deliverable: it needs produce as well as read.
    let capability = ctx.capability(
        args,
        if workpaper_requested {
            &["read", "produce"]
        } else {
            &["read"]
        },
    )?;
    // Saved provenance grants no current authority. Admission precedes
    // stamping book metadata, fetching retained bytes or reading a file.
    let mut book = ctx.books.open_admitted(args, |book| {
        fa_policy::admit_read(&capability, principal, book.context().book_id)
            .and_then(|()| fa_policy::reach(&capability, &fa_policy::Reach::whole_book(true), None))
            .and_then(|()| {
                if workpaper_requested {
                    fa_policy::require(
                        &capability,
                        fa_policy::Op::Produce,
                        "exporting a replayed report workpaper",
                    )
                } else {
                    Ok(())
                }
            })
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        book.read_scope(principal, &capability)??;
        book.prepare_report_history(principal, &capability, None)??;
        Ok(())
    })?;
    if let Some(path) = workpaper_out {
        let target = ctx.files.resolve(path);
        if std::fs::symlink_metadata(&target).is_ok() {
            return Err(usage(
                format!("workpaper output {path} already exists"),
                "choose a new --workpaper-out path; an existing file is never overwritten",
            ));
        }
        // The report is written before the workpaper, so a workpaper target
        // that cannot be created is refused now: a failed export never
        // leaves the report file behind.
        if args
            .flag("--output")
            .is_some_and(|output| ctx.files.resolve(output) == target)
        {
            return Err(usage(
                format!("--output and --workpaper-out both name {path}"),
                "write the replayed report and its workpaper to two new paths",
            ));
        }
        if !target
            .parent()
            .is_some_and(|dir| dir.as_os_str().is_empty() || dir.is_dir())
        {
            return Err(usage(
                format!("the directory of workpaper output {path} does not exist"),
                "create the directory first, or choose a --workpaper-out path in an existing one",
            ));
        }
    }
    let expected = expectations::parse(args, &book, principal, &capability)?;
    let view_request = match view {
        Some(view) => Some(crate::cli::parse_gl_scope(
            args,
            &book,
            &capability,
            &ctx.out,
            if view == "detail" {
                "gl-detail"
            } else {
                "roll-forward"
            },
            "use the complete replay_command from the original certified ledger",
        )?),
        None => None,
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
    if let Some(view) = view
        && artifact.family() != ReportArtifactFamily::RollForward
    {
        return Err(certificate_invalid(format!(
            "--view {view} requires a roll-forward source certificate"
        )));
    }
    let aging_expected = matches!(expected, expectations::Expected::Aging(_));
    if aging_expected && artifact.family() != ReportArtifactFamily::EffectiveDateAging {
        return Err(certificate_invalid(format!(
            "an aging expectation names an effective-date-aging certificate, not {}",
            artifact.family().name()
        )));
    }
    if workpaper_requested && !has_workpaper(artifact.family(), view.is_some(), aging_expected) {
        return Err(unsupported_workpaper(artifact.family()));
    }
    if artifact.family() == ReportArtifactFamily::DraftDiff {
        if args.flag("--expect").is_some() {
            return Err(usage(
                "a draft rehearsal replays its exact retained draft, source prefix and period",
                "fa replay C:<oid> --json",
            ));
        }
        let certificate = fa::DraftDiffCertificate::decode(&bytes)?;
        let diff = book.replay_draft_diff(principal, &capability, &certificate)??;
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
        crate::closing::render_draft_diff(&ctx.out, &book, &diff, Some(&digest))?;
        if let Some(path) = args.flag("--output") {
            ctx.out.event_with_certificate(
                "report_replayed",
                vec![
                    ("family", s(artifact.family().name())),
                    ("known_at", Json::Int(i128::from(certificate.known_at().0))),
                    ("output_bytes", Json::Int(certificate.output().len() as i128)),
                    ("output_digest", s(hex(&artifact.output_digest()))),
                    ("file", s(path)),
                ],
                &format!(
                    "Replayed draft-diff certificate {digest} at sequence {} ({} canonical output bytes)",
                    certificate.known_at().0,
                    certificate.output().len(),
                ),
                Some(&digest),
            );
        }
        return Ok(());
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
    // The workpaper export replays the same certificate against the same
    // independent request; it is complete before any file is written.
    let workpaper = workpaper_requested
        .then(|| {
            workpaper_jsonl(
                &book,
                principal,
                &capability,
                artifact.family(),
                &bytes,
                &expected,
                view.zip(view_request.as_ref()),
            )
        })
        .transpose()?;
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
        // --view roll-forward binds the lead schedule to the stated request.
        Some(match &view_request {
            Some(expected) => {
                book.replay_roll_forward_for(principal, &capability, &certificate, expected)??
            }
            None => book.replay_roll_forward(principal, &capability, &certificate)??,
        })
    } else {
        None
    };
    let detail = match view_request {
        Some(expected) if detail_view => {
            let source = fa::RollForwardCertificate::decode(&bytes)?;
            let report =
                book.replay_general_ledger(principal, &capability, &source, &expected)??;
            let presentation = crate::cli::general_ledger_presentation(&book, &report)?;
            Some((report, presentation))
        }
        _ => None,
    };
    let aging = if artifact.family() == ReportArtifactFamily::EffectiveDateAging {
        let certificate = fa::AgingCertificate::decode(&bytes)?;
        Some(match &expected {
            // A supplied request binds the replay to the recipient's question.
            expectations::Expected::Aging(request) => book.replay_effective_date_aging_for(
                principal,
                &capability,
                &certificate,
                request,
            )??,
            _ => book.replay_effective_date_aging(principal, &capability, &certificate)??,
        })
    } else {
        None
    };
    let due_date_aging = if artifact.family() == ReportArtifactFamily::DueDateAging {
        let certificate = fa::DueDateAgingCertificate::decode(&bytes)?;
        Some(match &expected {
            expectations::Expected::DueDateAging(request) => {
                book.replay_due_date_aging_for(principal, &capability, &certificate, request)??
            }
            _ => book.replay_due_date_aging(principal, &capability, &certificate)??,
        })
    } else {
        None
    };
    let equity = if artifact.family() == ReportArtifactFamily::EquityRollForward {
        let expectations::Expected::Equity(request) = &expected else {
            return Err(certificate_invalid(
                "equity replay needs an independent equity-roll-forward expectation",
            ));
        };
        let certificate = fa::EquityRollForwardCertificate::decode(&bytes)?;
        Some(book.replay_equity_roll_forward(principal, &capability, &certificate, request)??)
    } else {
        None
    };
    let native_subledger = if artifact.family() == ReportArtifactFamily::NativeSubledger {
        let expectations::Expected::NativeSubledger(request) = &expected else {
            return Err(certificate_invalid(
                "native subledger replay needs an independent native-subledger-reconciliation expectation",
            ));
        };
        let certificate = fa::NativeSubledgerCertificate::decode(&bytes)?;
        let report =
            book.replay_native_subledger(principal, &capability, &certificate, request)??;
        let accounts = book.accounts_at(report.known_at, &capability)??;
        Some((report, accounts))
    } else {
        None
    };
    let external_feed = if artifact.family() == ReportArtifactFamily::ExternalFeed {
        let expectations::Expected::ExternalFeed(request) = &expected else {
            return Err(certificate_invalid(
                "external-feed replay needs an independent external-feed-reconciliation expectation",
            ));
        };
        let certificate = fa::ExternalFeedCertificate::decode(&bytes)?;
        Some(book.replay_external_feed(principal, &capability, &certificate, request)??)
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
    let query = if artifact.family() == ReportArtifactFamily::Query {
        let certificate = fa::QueryCertificate::decode(&bytes)?;
        let rows = book.replay_query(principal, &capability, &certificate)??;
        Some((certificate, rows))
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
    if let (Some(path), Some(text)) = (workpaper_out, &workpaper) {
        crate::cli::write_new_output_file(
            &ctx.files,
            path,
            text.as_bytes(),
            "replayed workpaper",
            "--workpaper-out",
        )?;
    }
    let digest = hex(artifact.digest());
    let rendered = if let Some(report) = native {
        let certificate = artifact.source_certificate();
        ctx.out.time_selection(certificate.time_selection.as_ref());
        match (&report, &certificate.selection) {
            (ReportOutput::TrialBalance(report), ReportSelection::TrialBalance(selection)) => {
                render_trial_balance(&ctx.out, &book, report, selection, Some(&digest), None)?
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
            (
                ReportOutput::FunctionalStatement(report),
                ReportSelection::FunctionalStatement(_),
            ) => crate::cli::render_functional_statement(&ctx.out, &book, report, Some(&digest))?,
            (
                ReportOutput::FunctionalTrialBalance(report),
                ReportSelection::FunctionalTrialBalance(_),
            ) => {
                crate::fx::render_functional_trial_balance(&ctx.out, &book, report, Some(&digest))?
            }
            (ReportOutput::Consolidation(report), ReportSelection::Consolidation { .. }) => {
                crate::consolidate::render_consolidation(&ctx.out, &book, report, Some(&digest))?
            }
            (
                ReportOutput::FunctionalConsolidation(report),
                ReportSelection::FunctionalConsolidation { .. },
            ) => crate::consolidate::render_functional_consolidation(
                &ctx.out,
                &book,
                report,
                Some(&digest),
            )?,
            (
                ReportOutput::DimensionTrialBalance(report),
                ReportSelection::DimensionTrialBalance { selection, .. },
            ) => crate::cli::render_tagged_trial_balance(
                &ctx.out,
                &book,
                &report.trial_balance,
                selection,
                &crate::cli::TbDimension {
                    dimension: &report.dimension,
                    value: &report.value,
                    values: &report.values,
                },
                Some(&digest),
            )?,
            (
                ReportOutput::RegulatorySchedule(report),
                ReportSelection::RegulatorySchedule(selection),
            ) => crate::regulatory::render_regulatory_schedule(
                &ctx.out,
                &book,
                &selection.schedule,
                report,
                Some(&digest),
            )?,
            (ReportOutput::CustomStatement(report), ReportSelection::CustomStatement(_)) => {
                crate::custom_statement::render(&ctx.out, &book, report, Some(&digest))?
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
    } else if let Some(report) = due_date_aging {
        crate::cli::render_due_date_aging(&ctx.out, &book, &report, Some(&digest))?;
        true
    } else if let Some(report) = equity {
        crate::cli::render_equity_roll_forward(&ctx.out, &book, &report, Some(&digest))?;
        true
    } else if let Some((report, accounts)) = native_subledger {
        crate::subledger::render_native(&ctx.out, &book, &report, &accounts, Some(&digest))?;
        true
    } else if let Some(report) = external_feed {
        crate::external_subledger::render_feed(&ctx.out, &book, &report, Some(&digest))?;
        true
    } else if let Some(certificate) = procedure {
        procedure::render(&ctx.out, certificate.report(), &digest);
        true
    } else if let Some((certificate, rows)) = query {
        let period = certificate.period()?;
        // A retained statement always compiles; its EFFECTIVE selector names
        // the coordinate as the original query did.
        let effective = fa::compile_query(certificate.statement())
            .ok()
            .and_then(|profiled| profiled.effective);
        crate::query::render(
            &ctx.out,
            certificate.statement(),
            period.as_deref(),
            effective.as_ref(),
            &rows,
            Some(&digest),
        );
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
                | ReportArtifactFamily::DueDateAging
                | ReportArtifactFamily::EquityRollForward
                | ReportArtifactFamily::ExternalFeed
                | ReportArtifactFamily::NativeSubledger
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
    if let Some(text) = workpaper {
        let lines = text.lines().count();
        let human = match workpaper_out {
            Some(path) => format!(
                "Wrote the {} JSONL workpaper ({lines} lines) to {path}",
                replayed.family.name()
            ),
            None => format!(
                "{} JSONL workpaper ({lines} lines):\n{text}",
                replayed.family.name()
            ),
        };
        ctx.out.event_with_certificate(
            "workpaper_exported",
            vec![
                ("family", s(replayed.family.name())),
                ("file", workpaper_out.map_or(Json::Null, s)),
                ("bytes", Json::Int(text.len() as i128)),
                ("lines", Json::Int(lines as i128)),
                (
                    "text",
                    if workpaper_inline {
                        s(&text)
                    } else {
                        Json::Null
                    },
                ),
            ],
            &human,
            Some(&digest),
        );
    }
    Ok(())
}

/// An entry-relevance status as the `certificate_status` event reports it.
fn entry_status(
    status: CertificateStatus,
) -> (
    &'static str,
    fgdb_types::CommitSeq,
    Vec<VId>,
    Vec<fa::CertificateSupersedingCase>,
) {
    match status {
        CertificateStatus::Current { checked_at } => {
            ("Current", checked_at, Vec::new(), Vec::new())
        }
        CertificateStatus::SupersededBy {
            checked_at,
            later_entries,
            cases,
        } => ("SupersededBy", checked_at, later_entries, cases),
    }
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
    // after the certified prefix (its trunk is fixed at the fork). A summary
    // trial balance is Changed when its selector no longer reproduces it at
    // HEAD; that law compares the report, so it names no later entries. A
    // query is Changed when its statement answers differently at HEAD.
    let status = match artifact.family() {
        ReportArtifactFamily::Summary => {
            if args.flag("--expect").is_some() {
                return Err(usage(
                    "summary status compares the certificate's own root and selector and does not accept report-policy expectations",
                    "fa certificate status C:<summary-certificate> --json",
                ));
            }
            let certificate = fa::SummaryCertificate::decode(&bytes)?;
            match book.summary_certificate_status(principal, &capability, &certificate)?? {
                fa::SummaryCertificateStatus::Current { checked_at } => {
                    ("Current", checked_at, Vec::new(), Vec::new())
                }
                fa::SummaryCertificateStatus::Changed { checked_at, .. } => {
                    ("Changed", checked_at, Vec::new(), Vec::new())
                }
            }
        }
        ReportArtifactFamily::Query => {
            if args.flag("--expect").is_some() {
                return Err(usage(
                    "query status runs the certificate's own statement at the head and does not accept report-policy expectations",
                    "fa certificate status C:<query-certificate> --json",
                ));
            }
            let certificate = fa::QueryCertificate::decode(&bytes)?;
            match book.query_certificate_status(principal, &capability, &certificate)?? {
                fa::QueryCertificateStatus::Current { checked_at } => {
                    ("Current", checked_at, Vec::new(), Vec::new())
                }
                fa::QueryCertificateStatus::Changed { checked_at, .. } => {
                    ("Changed", checked_at, Vec::new(), Vec::new())
                }
            }
        }
        ReportArtifactFamily::ScenarioDiff => {
            if args.flag("--expect").is_some() {
                return Err(usage(
                    "scenario status uses its pinned intent prefix and does not accept report-policy expectations",
                    "fa certificate status C:<scenario-certificate> --json",
                ));
            }
            let certificate = fa::ScenarioDiffCertificate::decode(&bytes)?;
            entry_status(book.scenario_diff_status(principal, &capability, &certificate)??)
        }
        _ => {
            let expected = expectations::parse(args, &book, principal, &capability)?;
            // The shared verifier replays aging as supplied. Bind a supplied
            // question before reporting freshness, just as `fa replay` does.
            if let expectations::Expected::Aging(request) = &expected {
                if artifact.family() != ReportArtifactFamily::EffectiveDateAging {
                    return Err(certificate_invalid(format!(
                        "an aging expectation names an effective-date-aging certificate, not {}",
                        artifact.family().name()
                    )));
                }
                book.replay_effective_date_aging_for(
                    principal,
                    &capability,
                    &fa::AgingCertificate::decode(&bytes)?,
                    request,
                )??;
            }
            entry_status(book.report_artifact_status(
                principal,
                &capability,
                &bytes,
                Some(artifact.digest()),
                expected.borrowed(),
            )??)
        }
    };
    let certificate = artifact.source_certificate();
    let (name, checked_at, later_entries, cases) = status;
    ctx.out.known_at(checked_at);
    match &certificate.selection {
        ReportSelection::TrialBalance(selection)
        | ReportSelection::FunctionalTrialBalance(selection)
        | ReportSelection::DimensionTrialBalance { selection, .. } => {
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
        ReportSelection::Statement(selection) | ReportSelection::FunctionalStatement(selection) => {
            ctx.out.effective(periods_selector(&selection.periods));
        }
        ReportSelection::RegulatorySchedule(selection) => {
            ctx.out.effective(periods_selector(&selection.periods));
        }
        ReportSelection::CustomStatement(selection) => {
            ctx.out.effective(periods_selector(&selection.periods));
        }
        ReportSelection::Consolidation { period }
        | ReportSelection::FunctionalConsolidation { period } => {
            ctx.out.effective(format!("period:{period}"));
        }
    }
    let digest = hex(artifact.digest());
    let case_summary = cases
        .iter()
        .map(|case| {
            let disclosure = case.disclosure_digest.map_or_else(
                || "disclosure not recorded at this prefix".to_owned(),
                |digest| format!("disclosure {}", hex(&digest)),
            );
            format!(
                "\n  Case {} ({}): {disclosure}",
                case.ordinal,
                case.kind.name()
            )
        })
        .collect::<String>();
    ctx.out.event_with_certificate(
        "certificate_status",
        vec![
            ("oid", s(&digest)),
            ("status", s(name)),
            ("known_at", Json::Int(i128::from(certificate.known_at.0))),
            ("checked_at", Json::Int(i128::from(checked_at.0))),
            ("later_entries", Json::Arr(later_entries.iter().map(|vid| s(format!("{:032x}", vid.0))).collect())),
            ("cases", Json::Arr(cases.iter().map(|case| obj(vec![
                ("ordinal", Json::Int(i128::from(case.ordinal))),
                ("kind", s(case.kind.name())),
                ("disclosure_document", case.disclosure_document.map_or(Json::Null, |oid| s(hex(&oid.0)))),
                ("disclosure_digest", case.disclosure_digest.map_or(Json::Null, |digest| s(hex(&digest)))),
            ])).collect())),
            ("replay_scope", s(REPLAY_SCOPE)),
            ("authority", s(AUTHORITY)),
        ],
        &format!("Certificate {digest}: {name} (known at {}, checked at {}, {} later entries in its selector){case_summary}", certificate.known_at.0, checked_at.0, later_entries.len()),
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

/// `fa checkpoint list` (plan §15.3 Proofs; fa-waow): the journaled
/// accumulator states, newest first, as `fa checkpoint create` recorded
/// them. It recomputes nothing; `fa verify accumulator` does.
fn checkpoint_list(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    arguments(args, "fa checkpoint list --book <dir> --json")?;
    let book = ctx.books.open(args)?;
    let states = book.checkpoints()?;
    let mut human = Vec::new();
    let rows = states
        .iter()
        .map(|stored| {
            let state = &stored.state;
            human.push(format!(
                "{} through sequence {}: {} leaves, recorded at {}",
                hex(&stored.oid.0),
                state.through_seq.0,
                state.leaf_count,
                stored.recorded_at.0
            ));
            obj(vec![
                ("oid", s(hex(&stored.oid.0))),
                ("recorded_at", Json::Int(i128::from(stored.recorded_at.0))),
                ("through_seq", Json::Int(i128::from(state.through_seq.0))),
                ("leaf_count", Json::Int(i128::from(state.leaf_count))),
                ("evidence_after_seq", evidence_after(state.evidence_after)),
                ("access_after_seq", evidence_after(state.access_after)),
                ("root", s(hex(&state.root))),
                (
                    "prev_state_oid",
                    state
                        .prev_state_oid
                        .map_or(Json::Null, |oid| s(hex(&oid.0))),
                ),
            ])
        })
        .collect();
    if human.is_empty() {
        human.push("no checkpoints: run `fa checkpoint create --grant witness`".to_string());
    }
    ctx.out.event(
        "checkpoints",
        vec![("checkpoints", Json::Arr(rows))],
        &human.join("\n"),
    );
    Ok(())
}

pub(crate) fn checkpoint_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("list") => return checkpoint_list(ctx, args),
        Some("witness") => return checkpoint_witness(ctx, args),
        Some("witness-key") => return witness_key(ctx, args),
        _ => {}
    }
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
            ("access_after_seq", evidence_after(state.access_after)),
            ("leaf_kinds", leaf_kinds(&created.leaf_kinds)),
            ("root", s(hex(&state.root))),
            ("prev_state_oid", state.prev_state_oid.map_or(Json::Null, |oid| s(hex(&oid.0)))),
            ("signatures", s("ed25519")),
            ("checkpoint_oid", s(hex(&created.checkpoint.oid.0))),
            ("public_key", s(hex(&book.checkpoint_public_key()))),
            ("scope", s("entry_prefix")),
        ],
        &format!(
            "Created entry accumulator checkpoint {}: {} leaves ({} entries, {} evidence records, {} access events) through sequence {}, recorded at {}. Root {}.\nSigned TransparencyCheckpoint {} (Ed25519 public key {}); export it with `fa proof signed-checkpoint` and check it with `fa-verify checkpoint <file> --key <public key>`.",
            hex(&stored.oid.0), state.leaf_count, created.leaf_kinds.entries,
            state.leaf_count.saturating_sub(created.leaf_kinds.entries).saturating_sub(created.leaf_kinds.access_events),
            created.leaf_kinds.access_events, state.through_seq.0,
            stored.recorded_at.0, hex(&state.root),
            hex(&created.checkpoint.oid.0), hex(&book.checkpoint_public_key()),
        ),
    );
    Ok(())
}

/// `fa checkpoint witness-key --out <new file>` (plan §13.5, fa-qtfd): a
/// new Ed25519 witness key from the operating system's entropy, its 32-byte
/// seed written as 64 hex characters to a new 0600 file. No book is opened:
/// the key is the witness's, never the book's.
fn witness_key(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const EXAMPLE: &str = "fa checkpoint witness-key --out <new file> --json";
    if args.positional.len() != 2 || args.flag_all("--out").len() != 1 {
        return Err(usage(
            "checkpoint witness-key takes exactly one --out and no other argument",
            EXAMPLE,
        ));
    }
    let out = args.require("--out", "a new file for the witness key")?;
    if out.is_empty() || out == "-" {
        return Err(usage(
            "--out names a new key file; a secret is never written to stdout",
            EXAMPLE,
        ));
    }
    let mut seed = [0u8; 32];
    fa::book::Entropy::production()
        .fill(&mut seed)
        .map_err(|e| Fail::Environment(format!("entropy for a witness key: {e:?}")))?;
    let public = fa::SigningKey::from_seed(&seed).public_key();
    crate::cli::write_new_output_file(
        &ctx.files,
        out,
        format!("{}\n", hex(&seed)).as_bytes(),
        "witness key",
        "--out",
    )?;
    let key_id = fa::signer_key_id(&public);
    ctx.out.event(
        "witness_key_created",
        vec![
            ("public_key", s(hex(&public))),
            ("signer_key_id", s(hex(&key_id))),
            ("out", s(out)),
        ],
        &format!(
            "Witness key written to {out} (0600). Public key {}: give it to whoever verifies your cosignatures (fa-verify checkpoint --witness <public key>).",
            hex(&public)
        ),
    );
    Ok(())
}

/// A witness key file: one line of 64 hex characters (the Ed25519 seed),
/// mode at most 0600 and owned by the caller, checked before it is read.
fn load_witness_key(files: &Files, path: &str) -> Result<fa::SigningKey, Fail> {
    let resolved = files.resolve(path);
    fa::book::BookKeys::check_permissions(&resolved)?;
    let text = files.read_text(path)?;
    let line = text.trim();
    let seed: Option<[u8; 32]> = (line.len() == 64 && line.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| {
            let mut seed = [0u8; 32];
            for (i, byte) in seed.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&line[2 * i..2 * i + 2], 16).ok()?;
            }
            Some(seed)
        })
        .flatten();
    seed.map(|seed| fa::SigningKey::from_seed(&seed))
        .ok_or_else(|| {
            usage(
                format!("{path} is not a witness key file (one line of 64 hex characters)"),
                "create one with fa checkpoint witness-key --out <new file>",
            )
        })
}

/// `fa checkpoint witness` (plan §13.5, fa-qtfd): cosign a recorded state's
/// signed checkpoint with a witness key, after the book proves its history
/// extends the statement the witness signed last (`--previous`). Nothing is
/// written to the book; the cosigned checkpoint goes to a new `--out` file.
fn checkpoint_witness(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const EXAMPLE: &str = "fa checkpoint witness --key <witness key file> [--state <oid>] [--previous <cosigned file>] [--onto <cosigned file>] --out <new file> --grant witness --book <dir> --json";
    if args.positional.len() != 2 {
        return Err(usage(
            "checkpoint witness takes no positional argument",
            EXAMPLE,
        ));
    }
    for flag in ["--key", "--state", "--previous", "--onto", "--out"] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("checkpoint witness takes only one {flag}"),
                EXAMPLE,
            ));
        }
    }
    let key_path = args.require("--key", "the witness key file (fa checkpoint witness-key)")?;
    let out = args.require("--out", "a new file for the cosigned checkpoint")?;
    if out.is_empty() || out == "-" {
        return Err(usage(
            "--out names a new file; - is not an output file",
            EXAMPLE,
        ));
    }
    let state = args
        .flag("--state")
        .map(|text| crate::proof::fixed_hex(text, "--state").map(fa_model::Oid))
        .transpose()?;
    let witness = load_witness_key(&ctx.files, key_path)?;
    let previous = args
        .flag("--previous")
        .map(|path| ctx.files.read_bytes(path))
        .transpose()?;
    let onto = args
        .flag("--onto")
        .map(|path| ctx.files.read_bytes(path))
        .transpose()?;
    let actor = ctx.principal(args);
    let capability = ctx.capability(args, &["read"])?;
    fa_policy::require(&capability, Op::Witness, "witnessing a checkpoint")
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    let book = ctx.books.open(args)?;
    let witnessed = book.witness_checkpoint(
        actor,
        &capability,
        &witness,
        fa::WitnessRequest {
            state,
            previous: previous.as_deref(),
            onto: onto.as_deref(),
        },
    )??;
    crate::cli::write_new_output_file(
        &ctx.files,
        out,
        &witnessed.cosigned,
        "cosigned checkpoint",
        "--out",
    )?;
    ctx.out.at_book(&book)?;
    let state = &witnessed.checkpoint;
    let statement = |remembered: &fa::AccumulatorStatement| {
        obj(vec![
            (
                "through_seq",
                Json::Int(i128::from(remembered.through_seq.0)),
            ),
            ("leaf_count", Json::Int(i128::from(remembered.leaf_count))),
            ("root", s(hex(&remembered.root))),
        ])
    };
    ctx.out.event(
        "checkpoint_witnessed",
        vec![
            ("state_oid", s(hex(&state.oid.0))),
            ("through_seq", Json::Int(i128::from(state.state.through_seq.0))),
            ("leaf_count", Json::Int(i128::from(state.state.leaf_count))),
            ("root", s(hex(&state.state.root))),
            ("checkpoint_oid", s(hex(&witnessed.cosigned_oid.0))),
            ("signer_key_id", s(hex(&witnessed.witness_key_id))),
            ("witness_public_key", s(hex(&witness.public_key()))),
            ("book_public_key", s(hex(&book.checkpoint_public_key()))),
            ("extends", witnessed.extends.as_ref().map_or(Json::Null, statement)),
            ("out", s(out)),
            ("claim", s("witnessed_detection")),
        ],
        &format!(
            "Cosigned checkpoint {} of state {} ({} leaves through sequence {}) written to {out}{}. A cosignature is detection, not prevention: checkpoints that later disagree expose a fork.",
            hex(&witnessed.cosigned_oid.0),
            hex(&state.oid.0),
            state.state.leaf_count,
            state.state.through_seq.0,
            witnessed.extends.as_ref().map_or_else(String::new, |p| format!(
                "; it extends the statement this key signed last ({} leaves through sequence {})",
                p.leaf_count, p.through_seq.0
            )),
        ),
    );
    Ok(())
}

/// A state's record-kind boundary: null when that kind is not accumulated.
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
        ("access_events", Json::Int(i128::from(kinds.access_events))),
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
                ("access_after_seq", evidence_after(state.access_after)),
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
