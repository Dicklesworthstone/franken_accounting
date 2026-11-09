//! A PPA's current-period equity bridge, bound to its immutable atomic Post.

use fa::{Book, CaseEquityComparisonSelection, CaseEquityDisclosureComparison};
use fa_policy::{Capability, Op};

use super::*;

const EXAMPLE: &str = "fa case diff <case> --equity --period <actual-posting-period> --unit <CODE> [--issuance <account>] [--distribution <account>] [--label <label>] [--certify] [--request-out <new-file>] --json";
const DISCLOSURE: &str = "fa case disclose <case> --document <oid> --certificate <required-statement-digest>... --equity-certificate <digest> --equity-request <saved-request-file> [--key K] --json";
const SELECTION_FLAGS: &[&str] = &[
    "--period",
    "--unit",
    "--issuance",
    "--distribution",
    "--label",
    "--request-out",
];

pub(super) fn validate_options(args: &Args, sub: Option<&str>) -> Result<(), Fail> {
    if args.switch("--equity") && args.switch("--statements") {
        return Err(usage(
            "select --equity or --statements in separate comparisons",
            EXAMPLE,
        ));
    }
    for flag in SELECTION_FLAGS {
        if !args.flag_all(flag).is_empty() && !(sub == Some("diff") && args.switch("--equity")) {
            return Err(usage(
                format!("{flag} requires case diff --equity"),
                EXAMPLE,
            ));
        }
    }
    for flag in ["--equity-certificate", "--equity-request"] {
        if !args.flag_all(flag).is_empty() && sub != Some("disclose") {
            return Err(usage(
                format!("{flag} belongs to case disclose"),
                DISCLOSURE,
            ));
        }
    }
    if sub == Some("disclose") {
        let certificates = args.flag_all("--equity-certificate");
        let requests = args.flag_all("--equity-request");
        if certificates.len() != requests.len()
            || certificates.len() > fa_journal::case::MAX_DISCLOSURE_COMPARISONS
            || requests.iter().filter(|path| **path == "-").count() > 1
        {
            return Err(usage(
                "pair each --equity-certificate with one --equity-request in the same order; at most one request may read stdin",
                DISCLOSURE,
            ));
        }
    }
    Ok(())
}

/// Complete current write admission precedes reading caller-selected request
/// files. The native disclosure path repeats its checks at publication.
pub(super) fn admit_disclosure(book: &Book, cap: &Capability) -> Result<(), Fail> {
    fa_policy::admit_base(
        cap,
        &fa_policy::Intent {
            principal: cap.holder(),
            trunk: true,
            op: Op::Restate,
            book: book.context().book_id,
            legs: &[],
        },
    )
    .and_then(|()| fa_policy::require_class(cap, Some(fa_model::EntryClass::CASE_CONTROL)))
    .map_err(|denial| fa_journal::policy::refusal(&denial))?;
    crate::cli::admit_whole_book_read(
        book,
        cap,
        &[Op::Restate],
        "disclosing a case with independently selected comparisons",
    )
}

pub(super) fn disclosure_comparisons(
    ctx: &Ctx<'_>,
    args: &Args,
) -> Result<Vec<CaseEquityDisclosureComparison>, Fail> {
    let mut domain = fa_model::Writer::new();
    domain.bytes(fa::EQUITY_DIFF_REQUEST_FORMAT);
    let domain = domain
        .finish()
        .map_err(|error| Fail::Internal(format!("equity request framing: {error}")))?;
    args.flag_all("--equity-certificate")
        .into_iter()
        .zip(args.flag_all("--equity-request"))
        .map(|(certificate, path)| {
            let certificate = crate::cli::parse_digest(
                certificate.strip_prefix("C:").unwrap_or(certificate),
                "--equity-certificate",
            )?;
            let bytes = crate::cli::read_bounded_plan_bytes(
                &ctx.files,
                path,
                &domain,
                "equity comparison request",
                fa::MAX_EQUITY_DIFF_REQUEST_BYTES,
            )?;
            let expected = fa::EquityRollForwardDiffRequest::decode(&bytes).map_err(|error| {
                Fail::Refusal(fa_journal::case::comparison_refused(error.message))
            })?;
            Ok(CaseEquityDisclosureComparison {
                certificate,
                expected,
            })
        })
        .collect()
}

fn account_roles(args: &Args, flag: &str, book: &Book) -> Result<Vec<fgdb_types::VId>, Fail> {
    args.flag_all(flag)
        .into_iter()
        .flat_map(|codes| codes.split(','))
        .map(|code| {
            let code = code.trim();
            if code.is_empty() {
                return Err(usage(
                    format!("{flag} contains an empty account code"),
                    EXAMPLE,
                ));
            }
            Ok(fa_model::account_vid(book.context().book_id, code))
        })
        .collect()
}

fn presentation(
    book: &Book,
    ordinal: u32,
    period: &str,
    expected: &fa::EquityRollForwardDiffRequest,
    report: &fa::EquityRollForwardDiff,
    request_bytes: &[u8],
    request_file: Option<&str>,
) -> Result<(Vec<(&'static str, Json)>, String), Fail> {
    let (units, human) = crate::cli::equity_diff_presentation(book, report)?;
    let before = expected.before.known_at.ok_or_else(|| {
        Fail::Internal("case equity request lost its fixed before frontier".into())
    })?;
    let registry = &book.context().units;
    Ok((
        vec![
            ("case", Json::Int(i128::from(ordinal))),
            ("period", s(period)),
            ("basis", s("before-post-impact")),
            ("label", s(&expected.before.label)),
            ("before_known_at", Json::Int(i128::from(before.0))),
            ("after_known_at", Json::Int(i128::from(expected.after.0))),
            ("effective_from", s(expected.before.effective_from.render())),
            (
                "effective_through",
                s(expected.before.effective_through.render()),
            ),
            ("units", Json::Arr(units)),
            (
                "before_movements",
                Json::Arr(crate::cli::equity_movements_json(
                    report.before(),
                    registry,
                )?),
            ),
            (
                "after_movements",
                Json::Arr(crate::cli::equity_movements_json(report.after(), registry)?),
            ),
            ("verification_request_hex", s(hex(request_bytes))),
            ("request_file", request_file.map_or(Json::Null, s)),
        ],
        format!(
            "case {ordinal} {period}: before-post-impact\n{human}\nThis comparison isolates the atomic Post; it is not an originally issued equity statement."
        ),
    ))
}

pub(super) fn diff(ctx: &mut Ctx<'_>, args: &Args, ordinal: u32) -> Result<(), Fail> {
    if let Some(flag) = ["--as-known-at", "--branch"]
        .into_iter()
        .find(|flag| args.flag(flag).is_some())
    {
        return Err(usage(
            format!("{flag} cannot replace the case's fixed trunk Post frontiers"),
            EXAMPLE,
        ));
    }
    let registry = crate::verbs::registry().map_err(|error| Fail::Internal(error.into()))?;
    let verb = registry
        .verb("case")
        .ok_or_else(|| Fail::Internal("case verb is missing".into()))?;
    for flag in &verb.flags {
        if !args.flag_all(flag).is_empty()
            && flag != "--grant"
            && !SELECTION_FLAGS.contains(&flag.as_str())
        {
            return Err(usage(
                format!("{flag} does not apply to case diff --equity"),
                EXAMPLE,
            ));
        }
    }
    for switch in &verb.switches {
        if args.switch(switch) && !["--equity", "--certify"].contains(&switch.as_str()) {
            return Err(usage(
                format!("{switch} does not apply to case diff --equity"),
                EXAMPLE,
            ));
        }
    }
    for flag in ["--period", "--label", "--request-out"] {
        one_flag(args, flag, EXAMPLE)?;
    }
    let period = args.require("--period", "the PPA case's actual current posting period")?;
    if period.trim().is_empty()
        || args.flag_all("--unit").is_empty()
        || args
            .flag_all("--unit")
            .iter()
            .any(|codes| codes.split(',').any(|code| code.trim().is_empty()))
    {
        return Err(usage(
            "case equity comparison requires an explicit period and nonempty --unit scope",
            EXAMPLE,
        ));
    }
    if args
        .flag("--request-out")
        .is_some_and(|path| path.is_empty() || path == "-")
    {
        return Err(usage(
            "--request-out names a new file; canonical request hex is also emitted",
            EXAMPLE,
        ));
    }
    let certify = args.switch("--certify");
    let who = ctx.principal(args);
    let capability = ctx.capability(
        args,
        if certify {
            &["read", "produce"]
        } else {
            &["read"]
        },
    )?;
    let mut book = ctx.books.open_admitted(args, |book| {
        crate::cli::admit_whole_book_read(
            book,
            &capability,
            if certify { &[Op::Produce] } else { &[] },
            "comparing a PPA case's current-period equity across its Post",
        )
    })?;
    let selection = CaseEquityComparisonSelection {
        period: period.to_string(),
        label: args
            .flag("--label")
            .map(str::to_string)
            .unwrap_or_else(|| format!("case-{ordinal}-equity")),
        units: crate::cli::parse_gl_units(args, &book, &capability, None)?,
        issuance_accounts: account_roles(args, "--issuance", &book)?,
        distribution_accounts: account_roles(args, "--distribution", &book)?,
    };
    let write_request = |bytes: &[u8]| -> Result<(), Fail> {
        if let Some(path) = args.flag("--request-out") {
            crate::cli::write_new_output_file(
                &ctx.files,
                path,
                bytes,
                "case equity verification request",
                "--request-out",
            )?;
        }
        Ok(())
    };
    if certify {
        let expected = book.case_equity_diff_request(who, &capability, ordinal, &selection)??;
        book.prepare_report_history(who, &capability, expected.before.known_at)??;
        let before = book.certify_equity_roll_forward(who, &capability, &expected.before)??;
        let mut after_request = expected.before.clone();
        after_request.known_at = Some(expected.after);
        let after = book.certify_equity_roll_forward(who, &capability, &after_request)??;
        let certified = book.compare_equity_roll_forward_certificates(
            who,
            &capability,
            &before.certificate,
            &after.certificate,
            &expected,
        )??;
        let request_bytes = expected.canonical_bytes()?;
        let (fields, human) = presentation(
            &book,
            ordinal,
            period,
            &expected,
            &certified.report,
            &request_bytes,
            args.flag("--request-out"),
        )?;
        write_request(&request_bytes)?;
        let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
        let (bytes, retained) = crate::notary::retain_report_artifact_for(
            &mut book,
            &ctx.files,
            args,
            &artifact,
            &capability,
            fa::ReportArtifactExpectation::EquityRollForwardDiff(&expected),
        )?;
        ctx.out.at_book(&book)?;
        ctx.out.known_at(expected.after);
        ctx.out.event_with_certificate(
            "case_equity_diff",
            fields,
            &human,
            Some(&hex(artifact.digest())),
        );
        let format = std::str::from_utf8(fa::EQUITY_DIFF_OUTPUT_FORMAT)
            .map_err(|error| Fail::Internal(format!("equity output format: {error}")))?;
        crate::notary::emit_report_artifact_for(
            &ctx.out,
            args,
            &artifact,
            format,
            &bytes,
            &retained,
            &crate::notary::equity_diff_expectation_json(&expected),
        );
    } else {
        let (expected, report) = book.case_equity_diff(who, &capability, ordinal, &selection)??;
        let request_bytes = expected.canonical_bytes()?;
        let (fields, human) = presentation(
            &book,
            ordinal,
            period,
            &expected,
            &report,
            &request_bytes,
            args.flag("--request-out"),
        )?;
        write_request(&request_bytes)?;
        ctx.out.at_book(&book)?;
        ctx.out.known_at(expected.after);
        ctx.out
            .event_with_certificate("case_equity_diff", fields, &human, None);
    }
    Ok(())
}
