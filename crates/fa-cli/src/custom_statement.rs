//! Review, activate and report a company's own financial statement layout.

use fa::{Book, CustomStatementDefinition, CustomStatementReport, CustomStatementSelection};
use fa_model::ApprovalRef;
use fa_time::DateDay;

use crate::args::Args;
use crate::cli::{Ctx, Fail, hex, known_at_read_flag, parse_vid, usage};
use crate::json::{Json, obj, s};

const DEFINE: &str = "fa statement define --file layout.toml --from 2026-01-01 --key layout-v1 --plan-out layout.plan";
const ACTIVATE: &str = "fa statement activate --plan layout.plan --approval <vid> --approval <vid>";
const REPORT: &str = "fa statement custom --definition <name> --for FY2026-P03 [--compare FY2025-P03] [--functional] [--certify]";

pub(crate) fn command(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional[1].as_str() {
        "template" => template(ctx, args),
        "define" => define(ctx, args),
        "activate" => activate(ctx, args),
        "lint" => lint(ctx, args),
        "custom" => report(ctx, args),
        _ => Err(usage("unknown custom statement operation", REPORT)),
    }
}

fn options(args: &Args, allowed: &[&str], switches: &[&str], example: &str) -> Result<(), Fail> {
    let registry = crate::verbs::registry().map_err(|error| Fail::Internal(error.into()))?;
    let verb = registry
        .verbs
        .iter()
        .find(|verb| verb.name == "statement")
        .ok_or_else(|| Fail::Internal("statement verb is missing".into()))?;
    for flag in &verb.flags {
        let values = args.flag_all(flag);
        if !values.is_empty() && !allowed.contains(&flag.as_str()) {
            return Err(usage(
                format!("{flag} does not apply to statement {}", args.positional[1]),
                example,
            ));
        }
        if values.len() > 1 && flag != "--approval" {
            return Err(usage(format!("{flag} must occur only once"), example));
        }
    }
    for switch in &verb.switches {
        if args.switch(switch) && !switches.contains(&switch.as_str()) {
            return Err(usage(
                format!(
                    "{switch} does not apply to statement {}",
                    args.positional[1]
                ),
                example,
            ));
        }
    }
    Ok(())
}

fn file_definition(ctx: &Ctx<'_>, args: &Args) -> Result<CustomStatementDefinition, Fail> {
    let path = args.require(
        "--file",
        "a custom statement TOML file, or - for inline source",
    )?;
    let source = ctx.files.read_text(path)?;
    CustomStatementDefinition::from_toml(&source).map_err(|error| {
        usage(
            format!("statement definition: {error}"),
            "fa statement template --definition balance-sheet --out layout.toml",
        )
    })
}

fn template(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const EXAMPLE: &str =
        "fa statement template --definition balance-sheet|income-statement [--out layout.toml]";
    options(args, &["--definition", "--out"], &[], EXAMPLE)?;
    let name = args.require("--definition", "balance-sheet or income-statement")?;
    let builtin = fa::StatementDefinition::embedded(name)
        .map_err(|error| usage(error.to_string(), EXAMPLE))?;
    let definition = CustomStatementDefinition::from_builtin(&builtin);
    let source = definition
        .to_toml()
        .map_err(|error| usage(error.to_string(), EXAMPLE))?;
    if let Some(path) = args.flag("--out") {
        crate::cli::write_new_output_file(
            &ctx.files,
            path,
            source.as_bytes(),
            "statement template",
            "--out",
        )?;
    }
    ctx.out.event(
        "statement_definition_template",
        vec![
            ("definition", s(&definition.name)),
            ("source", s(&source)),
            ("path", args.flag("--out").map_or(Json::Null, s)),
        ],
        &source,
    );
    Ok(())
}

fn lint(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const EXAMPLE: &str = "fa statement lint --file layout.toml [--as-known-at <seq>] --json";
    options(
        args,
        &["--file", "--as-known-at", "--known-at"],
        &[],
        EXAMPLE,
    )?;
    let definition = file_definition(ctx, args)?;
    let cap = ctx.capability(args, &["read"])?;
    let who = ctx.principal(args);
    let mut book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let (known_at, _) = known_at_read_flag(args, &book, &ctx.out, &cap)?;
    crate::cli::prepare_native_certificate_history(&mut book, &cap, known_at)?;
    let at = known_at.unwrap_or(book.head()?);
    let lint = book.lint_statement_definition(&cap, &definition, at)??;
    ctx.out.at_book(&book)?;
    ctx.out.known_at(at);
    crate::cli::render_statement_lint(ctx, &lint, at)
}

fn define(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &["--file", "--from", "--key", "--plan-out"],
        &["--dry-run"],
        DEFINE,
    )?;
    let definition = file_definition(ctx, args)?;
    let from = args.require("--from", "the civil date the layout takes effect")?;
    let from = DateDay::parse(from).map_err(|e| usage(format!("--from: {e:?}"), DEFINE))?;
    let key = args.require("--key", "a stable activation intent key")?;
    let cap = ctx.capability(args, &["rule_change"])?;
    let who = ctx.principal(args);
    let book = ctx.books.open_admitted(args, |book| {
        book.admit_rule_change(who, &cap)??;
        Ok(())
    })?;
    let plan = book.plan_statement_definition(&cap, definition, from, key.as_bytes())??;
    let digest = plan
        .proposal_digest()
        .map_err(|e| Fail::Internal(format!("statement activation digest: {e}")))?;
    let bytes = plan
        .encode()
        .map_err(|e| Fail::Internal(format!("statement review encoding: {e}")))?;
    if let Some(path) = args.flag("--plan-out") {
        crate::cli::write_new_output_file(
            &ctx.files,
            path,
            &bytes,
            "statement activation review",
            "--plan-out",
        )?;
    }
    ctx.out.at_book(&book)?;
    ctx.out.event("statement_definition_plan", vec![
        ("definition", s(&plan.definition.name)),
        ("version", Json::Int(plan.definition.version.into())),
        ("definition_digest", s(hex(&plan.definition.digest().map_err(|e| Fail::Internal(e.to_string()))?.0))),
        ("effective_from", s(plan.effective_from.render())),
        ("chart_digest", s(hex(&plan.chart_digest))),
        ("principal", s(format!("{:032x}", plan.principal_ref.0))),
        ("proposal_digest", s(hex(&digest))),
        ("bytes", s(hex(&bytes))),
    ], &format!("Reviewed {} v{} from {}. Two independent Human approvers approve {} with fa approve --proposal <digest>; then {ACTIVATE}.\nCanonical review bytes:\n{}",
        plan.definition.name, plan.definition.version, plan.effective_from.render(), hex(&digest), hex(&bytes)));
    Ok(())
}

fn activate(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(args, &["--plan", "--file", "--approval"], &[], ACTIVATE)?;
    let path = match (args.flag("--plan"), args.flag("--file")) {
        (Some(path), None) | (None, Some(path)) => path,
        _ => {
            return Err(usage(
                "activation takes exactly one --plan (or inline --file -)",
                ACTIVATE,
            ));
        }
    };
    let bytes = crate::cli::read_plan_bytes(
        &ctx.files,
        path,
        fa::statement_definition::STATEMENT_DEFINITION_PLAN_FORMAT,
        "statement activation",
    )?;
    let plan = fa::statement_definition::StatementDefinitionPlan::decode(&bytes)
        .map_err(|e| usage(format!("invalid statement activation review: {e}"), DEFINE))?;
    let cap = ctx.capability(args, &["rule_change"])?;
    let who = ctx.principal(args);
    let mut book = ctx.books.open_admitted(args, |book| {
        book.admit_rule_change(who, &cap)??;
        Ok(())
    })?;
    let digest = plan
        .proposal_digest()
        .map_err(|e| Fail::Internal(format!("statement activation digest: {e}")))?;
    let approvals = args
        .flag_all("--approval")
        .iter()
        .map(|vid| {
            Ok(ApprovalRef {
                approval_vid: parse_vid(vid, "--approval")?,
                approved_digest: digest,
            })
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let activated = book.activate_statement_definition(&cap, plan, approvals)??;
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "statement_definition_activated",
        vec![
            ("definition", s(&activated.definition.name)),
            ("version", Json::Int(activated.definition.version.into())),
            ("definition_digest", s(hex(&activated.definition_oid.0))),
            ("activation", s(format!("{:032x}", activated.activation.0))),
            ("effective_from", s(activated.effective_from.render())),
            ("recorded_at", Json::Int(activated.recorded_at.0.into())),
            ("already_recorded", Json::Bool(activated.already_recorded)),
        ],
        &format!(
            "{} {} v{} from {} at sequence {}",
            if activated.already_recorded {
                "Already activated"
            } else {
                "Activated"
            },
            activated.definition.name,
            activated.definition.version,
            activated.effective_from.render(),
            activated.recorded_at.0
        ),
    );
    Ok(())
}

fn report(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &[
            "--definition",
            "--for",
            "--compare",
            "--known-at",
            "--as-known-at",
            "--certificate-out",
            "--scale-digits",
            "--rounding",
            "--residual-line",
            "--residual-label",
        ],
        &["--certify", "--functional"],
        REPORT,
    )?;
    let name = args.require("--definition", "the activated company layout's name")?;
    let period = args.require("--for", "the current fiscal period")?;
    let functional = args.switch("--functional");
    let certify = args.switch("--certify") || args.flag("--certificate-out").is_some();
    let cap = ctx.capability(
        args,
        if certify {
            &["read", "produce"]
        } else {
            &["read"]
        },
    )?;
    let who = ctx.principal(args);
    let mut book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let (known_at, instant) = known_at_read_flag(args, &book, &ctx.out, &cap)?;
    if instant.is_some() {
        return Err(usage(
            "custom statement reports currently select an explicit recorded sequence or HEAD",
            "--as-known-at HEAD|<seq>",
        ));
    }
    crate::cli::prepare_native_certificate_history(&mut book, &cap, known_at)?;
    let at = known_at.unwrap_or(book.head()?);
    let scope = book.read_scope(who, &cap)??;
    scope.admit_whole_book(Some(at))??;
    let row = scope.period_at(period, Some(at))??.ok_or_else(|| {
        usage(
            format!("period {period} does not exist at {}", at.0),
            REPORT,
        )
    })?;
    let day = DateDay(
        row.end
            .0
            .checked_sub(1)
            .ok_or_else(|| Fail::Internal("period end underflow".into()))?,
    );
    let active = book
        .active_statement_definition(&cap, name, day, at)??
        .ok_or_else(|| {
            usage(
                format!(
                    "no approved definition {name} is in force for {day} at {}",
                    at.0
                ),
                DEFINE,
            )
        })?;
    let rounding_spec = rounding(args)?;
    let selection = CustomStatementSelection {
        definition: active.definition,
        activation: active.activation,
        activated_at: active.recorded_at,
        functional,
        periods: vec![period.into()],
        comparative: args
            .flag("--compare")
            .into_iter()
            .map(str::to_string)
            .collect(),
        presentation: rounding_spec,
    };
    ctx.out.at_book(&book)?;
    ctx.out.known_at(at);
    ctx.out.effective(format!("period:{period}"));
    let (report, certificate) = if certify {
        let certified = if functional {
            book.certify_functional_custom_statement(&cap, selection, Some(at))??
        } else {
            book.certify_custom_statement(&cap, selection, Some(at))??
        };
        let fa::ReportOutput::CustomStatement(report) = certified.report else {
            return Err(Fail::Internal(
                "custom statement certificate returned another family".into(),
            ));
        };
        (*report, Some(certified.certificate))
    } else if functional {
        (
            book.functional_custom_statement(&cap, selection, Some(at))??,
            None,
        )
    } else {
        (book.custom_statement(&cap, selection, Some(at))??, None)
    };
    // Complete rendering before publishing a retained certificate.
    let rendered = presentation(&book, &report)?;
    let retained = certificate
        .as_ref()
        .map(|certificate| {
            crate::notary::retain_report_certificate(&mut book, &ctx.files, args, certificate, &cap)
        })
        .transpose()?;
    let digest = certificate
        .as_ref()
        .map(|certificate| hex(&certificate.digest));
    emit(&ctx.out, &report, rendered, digest.as_deref());
    if let (Some(certificate), Some((bytes, retained))) = (certificate.as_ref(), retained) {
        crate::notary::emit_report_certificate(&ctx.out, args, certificate, &bytes, &retained);
    }
    Ok(())
}

fn rounding(args: &Args) -> Result<Option<fa::PresentationRoundingSpec>, Fail> {
    let Some(digits) = args.flag("--scale-digits") else {
        if ["--rounding", "--residual-line", "--residual-label"]
            .iter()
            .any(|flag| args.flag(flag).is_some())
        {
            return Err(usage("presentation options require --scale-digits", REPORT));
        }
        return Ok(None);
    };
    let digits = digits.parse().map_err(|_| {
        usage(
            "--scale-digits must be an integer from 0 through 38",
            REPORT,
        )
    })?;
    let name = args.require(
        "--rounding",
        "the registered presentation law, for example HalfEven",
    )?;
    let law = fa_money::RoundingLaw::from_name(name)
        .ok_or_else(|| usage("unknown rounding law", "--rounding HalfEven"))?;
    let spec = fa::PresentationRoundingSpec {
        rounding_law: law,
        scale_reduction_digits: digits,
        residual_line_code: args
            .require("--residual-line", "the explicit residual line code")?
            .into(),
        residual_line_label: args
            .require("--residual-label", "the explicit residual line label")?
            .into(),
    };
    spec.validate().map_err(|e| usage(e.to_string(), REPORT))?;
    Ok(Some(spec))
}

type Rendered = (
    crate::cli::StatementPresentation,
    Vec<(&'static str, Json)>,
    String,
);

fn presentation(book: &Book, report: &CustomStatementReport) -> Result<Rendered, Fail> {
    let functional = report.functional_unit.is_some();
    let exact = crate::cli::statement_presentation_basis(
        &report.statement,
        &book.context().units,
        functional,
    )?;
    let mut fields = vec![
        ("definition", s(&report.statement.definition_name)),
        (
            "version",
            Json::Int(report.statement.definition_version.into()),
        ),
        (
            "definition_digest",
            s(hex(&report.statement.definition_digest)),
        ),
        ("activation", s(format!("{:032x}", report.activation.0))),
        ("known_at", Json::Int(report.statement.known_at.into())),
        ("rounded", Json::Bool(report.presented.is_some())),
    ];
    let human = match &report.presented {
        None => "Exact company statement; no presentation rounding requested".into(),
        Some(presented) => {
            let lines = presented
                .lines
                .iter()
                .map(|line| {
                    let unit = crate::cli::registered_unit_code(
                        fa_money::UnitId(line.unit_id),
                        &book.context().units,
                    )?;
                    Ok(obj(vec![
                        ("code", s(&line.code)),
                        ("label", s(&line.label)),
                        ("unit", s(unit)),
                        (
                            "amounts",
                            Json::Arr(
                                line.presented_amounts
                                    .iter()
                                    .copied()
                                    .map(Json::Int)
                                    .collect(),
                            ),
                        ),
                        (
                            "rounding_errors",
                            Json::Arr(
                                line.rounding_errors
                                    .iter()
                                    .copied()
                                    .map(Json::Int)
                                    .collect(),
                            ),
                        ),
                        ("residual", Json::Bool(line.is_residual_line)),
                    ]))
                })
                .collect::<Result<Vec<_>, Fail>>()?;
            fields.extend([
                ("divisor", Json::Int(presented.divisor)),
                ("rounding_law", s(format!("{:?}", presented.rounding_law))),
                ("lines", Json::Arr(lines)),
            ]);
            format!(
                "Company statement presented as mantissas / {} under {:?}\n{}",
                presented.divisor,
                presented.rounding_law,
                presented
                    .lines
                    .iter()
                    .map(|line| format!(
                        "{} [{}] {}{}",
                        line.label,
                        line.unit_id,
                        line.presented_amounts
                            .iter()
                            .map(i128::to_string)
                            .collect::<Vec<_>>()
                            .join("  "),
                        if line.is_residual_line {
                            " (rounding residual)"
                        } else {
                            ""
                        }
                    ))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        }
    };
    if report.presented.is_none() {
        fields.extend([
            ("divisor", Json::Null),
            ("rounding_law", Json::Null),
            ("lines", Json::Arr(Vec::new())),
        ]);
    }
    if let Some(unit) = report.functional_unit {
        fields.extend([
            ("functional", Json::Bool(true)),
            (
                "base_unit",
                s(crate::cli::registered_unit_code(
                    unit,
                    &book.context().units,
                )?),
            ),
            ("valuation_basis", s("retained-base-amounts")),
        ]);
    }
    Ok((exact, fields, human))
}

fn emit(
    out: &crate::cli::Out,
    report: &CustomStatementReport,
    (exact, fields, human): Rendered,
    certificate: Option<&str>,
) {
    out.event_with_certificate("statement", exact.0, &exact.1, certificate);
    out.event_with_certificate(
        if report.functional_unit.is_some() {
            "functional_custom_statement"
        } else {
            "custom_statement"
        },
        fields,
        &human,
        certificate,
    );
}

pub(crate) fn render(
    out: &crate::cli::Out,
    book: &Book,
    report: &CustomStatementReport,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    emit(out, report, presentation(book, report)?, certificate);
    Ok(())
}
