//! `fa statement regulatory` (plan §12.6, bead fa-doa9): a registered FFIEC
//! 041 or FR Y-9C schedule evaluated from the same exact journal folds a
//! statement of its kind uses, mapped by account code, certified and
//! replayed like a statement, with the schedule's edits run over the result.
//!
//! The schedule records its instruction version and the Instrument inputs
//! its lines declare. This evaluation reads general-ledger folds only; it
//! does not read Instrument attributes, and says so in its output.

use fa::book::Book;
use fa::statements::{regulatory_edits_of, regulatory_schedule};
use fa::{RegulatoryScheduleDefinition, ReportOutput, ReportSelection, Statement};
use fa_money::Amount;

use crate::args::Args;
use crate::cli::{
    Ctx, Fail, Out, StatementPresentation, hex, known_at_read_flag,
    prepare_native_certificate_history, render_amount, render_statement, statement_presentation,
    usage,
};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa statement regulatory --form 041 --schedule RC --quarter 2026Q1 --for FY2026-P03 [--compare FY2025-P12] [--as-known-at <seq>] [--certify] --json";

/// Flags of the other `fa statement` modes, none of which selects or
/// changes a regulatory schedule.
const OTHER_MODES: &[&str] = &[
    "--definition",
    "--before",
    "--after",
    "--max-publications",
    "--branch",
    "--before-certificate",
    "--after-certificate",
    "--from-diff",
    "--certificate",
    "--issued-to",
    "--document",
    "--key",
    "--date",
    "--plan",
    "--approval",
    "--as-issued-to",
    "--as-reported-in",
    "--render",
    "--out",
    "--present-in",
    "--rounding",
    "--from",
    "--to",
    "--issuance",
    "--distribution",
    "--unit",
    "--label",
];

pub(crate) fn statement_regulatory(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    for flag in OTHER_MODES {
        if args.flag(flag).is_some() {
            return Err(usage(
                format!("{flag} does not apply to `fa statement regulatory`"),
                EXAMPLE,
            ));
        }
    }
    for switch in [
        "--as-originally-reported",
        "--as-currently-stated",
        "--dry-run",
        "--functional",
    ] {
        if args.switch(switch) {
            return Err(usage(
                format!(
                    "{switch} does not apply to `fa statement regulatory`, which reports native units at one recorded frontier"
                ),
                EXAMPLE,
            ));
        }
    }
    for flag in ["--form", "--schedule", "--quarter", "--certificate-out"] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(format!("{flag} may be supplied only once"), EXAMPLE));
        }
    }
    let form = args.require("--form", "041 (FFIEC 041) or Y9C (FR Y-9C)")?;
    let schedule_code = args.require("--schedule", "RC, RI or HC")?;
    let quarter = args.require("--quarter", "the report quarter, for example 2026Q1")?;
    let periods = period_list(args, "--for")?;
    if periods.is_empty() {
        return Err(usage(
            "--for names the schedule's period: repeat it for a year-to-date income schedule",
            EXAMPLE,
        ));
    }
    let comparative = period_list(args, "--compare")?;
    let schedule = regulatory_schedule(form, schedule_code, quarter)?;
    let selection = fa::RegulatorySelection {
        schedule: schedule.clone(),
        periods,
        comparative,
    };
    let certify = args.switch("--certify") || args.flag("--certificate-out").is_some();
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
        prepare_native_certificate_history(book, &capability, None)?;
        book.read_scope(who, &capability)??;
        Ok(())
    })?;
    let (known_at, requested_utc_ns) = known_at_read_flag(args, &book, &ctx.out, &capability)?;
    // Each column's reach is judged against the scope caveats before any
    // column is read (doctrine 8), as for a statement of the schedule's kind.
    let reach = ReportSelection::RegulatorySchedule(Box::new(selection.clone()));
    book.read_scope(who, &capability)??
        .admit_report(&reach, known_at)??;
    prepare_native_certificate_history(&mut book, &capability, known_at)?;
    let (statement, certificate) = if certify {
        let certified = match requested_utc_ns {
            Some(instant) => book.certify_report_at_instant(reach, instant)??,
            None => book.certify_report(reach, known_at)??,
        };
        ctx.out
            .time_selection(certified.certificate.time_selection.as_ref());
        let ReportOutput::RegulatorySchedule(statement) = certified.report else {
            return Err(Fail::Internal(
                "regulatory certification returned another report kind".into(),
            ));
        };
        (*statement, Some(certified.certificate))
    } else {
        if requested_utc_ns.is_some() {
            return Err(usage(
                "an uncertified regulatory schedule reads a recorded sequence: pass --as-known-at <seq>, or add --certify to retain the instant's TimeEvidence",
                EXAMPLE,
            ));
        }
        (book.regulatory_schedule(selection, known_at)??, None)
    };
    // Present every amount and run the edits before retaining a certificate
    // or emitting a success.
    statement_presentation(&statement, &book.context().units)?;
    let edits = edits_event(&book, &schedule, &statement)?;
    let retained = certificate
        .as_ref()
        .map(|certificate| {
            crate::notary::retain_report_certificate(
                &mut book,
                &ctx.files,
                args,
                certificate,
                &capability,
            )
        })
        .transpose()?;
    let digest = certificate
        .as_ref()
        .map(|certificate| hex(&certificate.digest));
    render_statement(&ctx.out, &book, &statement, digest.as_deref())?;
    let (fields, human) = edits;
    ctx.out.event("regulatory_schedule", fields, &human);
    if let (Some(certificate), Some((bytes, retained))) = (certificate.as_ref(), retained) {
        crate::notary::emit_report_certificate(&ctx.out, args, certificate, &bytes, &retained);
    }
    Ok(())
}

/// `fa replay C:<oid>` of a regulatory schedule certificate: the same two
/// events, from the replayed statement and the certificate's own schedule.
pub(crate) fn render_regulatory_schedule(
    out: &Out,
    book: &Book,
    schedule: &RegulatoryScheduleDefinition,
    statement: &Statement,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    let (fields, human) = edits_event(book, schedule, statement)?;
    render_statement(out, book, statement, certificate)?;
    out.event("regulatory_schedule", fields, &human);
    Ok(())
}

/// Each repeated `--for` (or `--compare`) is one period code.
fn period_list(args: &Args, flag: &str) -> Result<Vec<String>, Fail> {
    let periods = args.flag_all(flag);
    if periods.iter().any(|period| period.is_empty()) {
        return Err(usage(
            format!("{flag} names a period code, for example FY2026-P03"),
            EXAMPLE,
        ));
    }
    Ok(periods.into_iter().map(String::from).collect())
}

/// The `regulatory_schedule` event: what the schedule is, the Instrument
/// inputs it declares (not read by this evaluation), and every edit row.
fn edits_event(
    book: &Book,
    schedule: &RegulatoryScheduleDefinition,
    statement: &Statement,
) -> Result<StatementPresentation, Fail> {
    let units = &book.context().units;
    let schedule_digest = schedule
        .digest()
        .map_err(|error| Fail::Internal(format!("regulatory schedule digest: {error}")))?;
    let (selector, report) = regulatory_edits_of(schedule, statement)?;
    let mut rows = Vec::with_capacity(report.rows.len());
    for row in &report.rows {
        let unit = fa_money::UnitId(row.unit_id);
        let amount = |mantissa| render_amount(Amount::new(unit, mantissa), units);
        rows.push(obj(vec![
            ("edit_id", s(&row.edit_id)),
            ("kind", s(row.kind.as_str())),
            ("column", s(&row.column_label)),
            ("unit", s(crate::cli::registered_unit_code(unit, units)?)),
            ("lhs", s(amount(row.lhs_mantissa)?)),
            ("operator", s(row.operator.as_str())),
            ("rhs", s(amount(row.rhs_mantissa)?)),
            ("delta", s(amount(row.delta_mantissa)?)),
            ("passed", Json::Bool(row.passed)),
        ]));
    }
    let declared = schedule
        .declared_instrument_inputs
        .iter()
        .map(|input| {
            obj(vec![
                ("line", s(&input.line_code)),
                ("instrument_kind", s(&input.instrument_kind)),
                ("attribute", s(&input.attribute_name)),
            ])
        })
        .collect();
    let human = format!(
        "{} schedule {} ({}): validity edits {} passed, {} failed; quality edits {} passed, {} failed. Edit ids are illustrative, not FFIEC-published edit numbers.",
        schedule.form.as_str(),
        schedule.schedule_code,
        schedule.instruction_version,
        report.validity_passed,
        report.validity_failed,
        report.quality_passed,
        report.quality_failed
    );
    let count = |n: usize| Json::Int(i128::try_from(n).unwrap_or(i128::MAX));
    Ok((
        vec![
            ("form", s(schedule.form.as_str())),
            ("schedule", s(&schedule.schedule_code)),
            ("instruction_version", s(&schedule.instruction_version)),
            ("definition", s(&schedule.statement_definition.name)),
            ("schedule_digest", s(hex(&schedule_digest.0))),
            ("known_at", Json::Int(i128::from(statement.known_at))),
            ("declared_inputs", Json::Arr(declared)),
            ("instrument_inputs_read", Json::Bool(false)),
            ("edit_selector", s(selector)),
            ("edit_ids_published", Json::Bool(false)),
            ("validity_passed", count(report.validity_passed)),
            ("validity_failed", count(report.validity_failed)),
            ("quality_passed", count(report.quality_passed)),
            ("quality_failed", count(report.quality_failed)),
            ("edit_rows", Json::Arr(rows)),
        ],
        human,
    ))
}
