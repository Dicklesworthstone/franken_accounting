//! Review and activate reusable, versioned cash-flow classification rules.

use fa::cash_flow_policy_activation::{ActivatedCashFlowPolicy, CashFlowPolicyPlan};
use fa::{Book, CashFlowActivity};
use fa_model::{ApprovalRef, CashFlowPolicyDefinition};
use fa_policy::Capability;
use fa_time::DateDay;
use fgdb_types::CommitSeq;

use crate::args::Args;
use crate::cli::{Ctx, Fail, Out, hex, known_at_read_flag, parse_digest, parse_vid, usage};
use crate::json::{Json, obj, s};

const DEFINE: &str = "fa cash-policy define --file policy.json --version 1 --from 2026-01-01 --key policy-v1 [--plan-out policy.plan]";
const ACTIVATE: &str = "fa cash-policy activate --plan policy.plan --digest <proposal_digest> --approval <vid> --approval <vid> --yes";
const SHOW: &str =
    "fa cash-policy show --name <name> --from YYYY-MM-DD --to YYYY-MM-DD [--as-known-at <seq>]";

/// Named policy mode accepts only separate, explicit indirect adjustments.
/// No file field may replace the activated rule set or its cash account set.
pub(crate) fn validate_adjustments(doc: &Json) -> Result<(), Fail> {
    let Json::Obj(fields) = doc else {
        return Err(usage(
            "indirect adjustments must be a JSON object",
            r#"{"adjustments":[]}"#,
        ));
    };
    for (name, _) in fields {
        if !["name", "adjustments"].contains(&name.as_str()) {
            return Err(usage(
                format!("{name} cannot override the activated cash-flow policy"),
                r#"with --policy-name, --policy contains only {"name":"optional-report-name","adjustments":[...]}"#,
            ));
        }
    }
    crate::cli::validate_cash_flow_rules_policy_fields(doc, true)
}

pub(crate) fn command(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage("choose cash-policy define, activate or show", DEFINE));
    }
    match args.positional[1].as_str() {
        "define" => define(ctx, args),
        "activate" => activate(ctx, args),
        "show" => show(ctx, args),
        _ => Err(usage("unknown cash-policy operation", SHOW)),
    }
}

fn options(args: &Args, allowed: &[&str], example: &str) -> Result<(), Fail> {
    let registry = crate::verbs::registry().map_err(|error| Fail::Internal(error.into()))?;
    let verb = registry
        .verbs
        .iter()
        .find(|verb| verb.name == "cash-policy")
        .ok_or_else(|| Fail::Internal("cash-policy verb is missing".into()))?;
    for flag in &verb.flags {
        let values = args.flag_all(flag);
        if !values.is_empty() && !allowed.contains(&flag.as_str()) {
            return Err(usage(
                format!(
                    "{flag} does not apply to cash-policy {}",
                    args.positional[1]
                ),
                example,
            ));
        }
        if values.len() > 1 && flag != "--approval" {
            return Err(usage(format!("{flag} must occur only once"), example));
        }
    }
    Ok(())
}

fn date(args: &Args, flag: &str, example: &str) -> Result<DateDay, Fail> {
    DateDay::parse(args.require(flag, "a civil date YYYY-MM-DD")?)
        .map_err(|error| usage(format!("{flag}: {error}"), example))
}

fn define(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &["--file", "--version", "--from", "--key", "--plan-out"],
        DEFINE,
    )?;
    let cap = ctx.capability(args, &["rule_change"])?;
    // Admission precedes any caller-selected file or chart observation.
    let book = ctx.books.open_admitted(args, |book| {
        book.admit_cash_flow_policy(&cap, true)??;
        Ok(())
    })?;
    let path = args.require("--file", "a rule-policy JSON file, or - for inline source")?;
    let doc = crate::json::parse(&ctx.files.read_text(path)?)
        .map_err(|error| usage(format!("invalid cash-flow policy JSON: {error}"), DEFINE))?;
    crate::cli::validate_cash_flow_rules_policy_fields(&doc, false)?;
    let policy =
        crate::cli::parse_cash_flow_rules_policy(&doc, book.context().book_id, &[], "cash-flow")?;
    if !policy.overrides.is_empty() {
        return Err(usage(
            "an activated policy contains reusable account rules; per-entry overrides are report inputs",
            "omit overrides, or use gl cash-flow --policy for a report-specific classification",
        ));
    }
    let version = args
        .require("--version", "a positive policy version")?
        .parse::<u32>()
        .map_err(|_| usage("--version must be a positive u32", DEFINE))?;
    let mut definition = CashFlowPolicyDefinition {
        name: policy.name,
        version,
        cash_accounts: policy.cash_accounts,
        account_rules: policy.account_rules.into_iter().map(|rule| {
            let tag = match rule.activity {
                CashFlowActivity::Operating => 0,
                CashFlowActivity::Investing => 1,
                CashFlowActivity::Financing => 2,
                CashFlowActivity::ExchangeEffect => 3,
                CashFlowActivity::InternalTransfer => return Err(usage(
                    "internal transfers are derived from the selected cash accounts, not account rules",
                    DEFINE,
                )),
            };
            Ok((rule.account_id, tag))
        }).collect::<Result<_, Fail>>()?,
    };
    definition.cash_accounts.sort_unstable();
    definition.account_rules.sort_unstable();
    definition
        .validate()
        .map_err(|error| usage(error, DEFINE))?;
    let plan = book.plan_cash_flow_policy(
        &cap,
        definition,
        date(args, "--from", DEFINE)?,
        args.require("--key", "a stable activation intent key")?
            .as_bytes(),
    )??;
    let digest = plan
        .proposal_digest()
        .map_err(|error| Fail::Internal(format!("cash-policy proposal: {error}")))?;
    let definition_digest = plan
        .definition
        .digest()
        .map_err(|error| Fail::Internal(format!("cash-policy definition: {error}")))?;
    let bytes = plan
        .encode()
        .map_err(|error| Fail::Internal(format!("cash-policy review: {error}")))?;
    if let Some(path) = args.flag("--plan-out") {
        crate::cli::write_post_plan(&ctx.files, path, &bytes)?;
    }
    ctx.out.at_book(&book)?;
    ctx.out.event("cash_flow_policy_plan", vec![
        ("policy", s(&plan.definition.name)),
        ("version", Json::Int(plan.definition.version.into())),
        ("definition_digest", s(hex(&definition_digest))),
        ("effective_from", s(plan.effective_from.render())),
        ("chart_digest", s(hex(&plan.chart_digest))),
        ("principal", s(format!("{:032x}", plan.principal_ref.0))),
        ("proposal_digest", s(hex(&digest))),
        ("bytes", s(hex(&bytes))),
    ], &format!(
        "Reviewed cash policy {} v{} from {}. Two independent Human approvers approve {} with fa approve --proposal <digest>; then {ACTIVATE}.\nCanonical review bytes:\n{}",
        plan.definition.name, plan.definition.version, plan.effective_from.render(), hex(&digest), hex(&bytes),
    ));
    Ok(())
}

fn activate(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(
        args,
        &["--plan", "--file", "--digest", "--approval"],
        ACTIVATE,
    )?;
    let cap = ctx.capability(args, &["rule_change"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        book.admit_cash_flow_policy(&cap, false)??;
        Ok(())
    })?;
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
        fa::cash_flow_policy_activation::CASH_FLOW_POLICY_PLAN_FORMAT,
        "cash-flow policy activation",
    )?;
    let plan = CashFlowPolicyPlan::decode(&bytes)
        .map_err(|error| usage(format!("invalid cash-flow policy review: {error}"), DEFINE))?;
    let digest = plan
        .proposal_digest()
        .map_err(|error| Fail::Internal(format!("cash-policy proposal: {error}")))?;
    let expected = parse_digest(
        args.require("--digest", "the reviewed proposal digest")?,
        "--digest",
    )?;
    if digest != expected {
        return Err(usage(
            "cash-flow policy review does not match --digest",
            ACTIVATE,
        ));
    }
    let approvals = args
        .flag_all("--approval")
        .into_iter()
        .map(|id| {
            Ok(ApprovalRef {
                approval_vid: parse_vid(id, "--approval")?,
                approved_digest: digest,
            })
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let activated = book.activate_cash_flow_policy(&cap, plan, approvals)??;
    ctx.out.at_book(&book)?;
    let mut fields = activation_fields(&activated);
    fields.push(("already_recorded", Json::Bool(activated.already_recorded)));
    ctx.out.event(
        "cash_flow_policy_activated",
        fields,
        &format!(
            "{} cash policy {} v{} from {} at sequence {}",
            if activated.already_recorded {
                "Already activated"
            } else {
                "Activated"
            },
            activated.policy.name,
            activated.version,
            activated.effective_from.render(),
            activated.recorded_at.0,
        ),
    );
    Ok(())
}

pub(crate) fn select(
    book: &Book,
    capability: &Capability,
    name: &str,
    from: DateDay,
    through: DateDay,
    at: CommitSeq,
) -> Result<ActivatedCashFlowPolicy, Fail> {
    book.active_cash_flow_policy(capability, name, from, through, at)??
        .ok_or_else(|| usage(
            format!("cash-flow policy {name} is not active for this interval at sequence {}", at.0),
            "activate an approved policy effective by --from, or select its earlier recorded prefix",
        ))
}

fn activation_fields(activation: &ActivatedCashFlowPolicy) -> Vec<(&'static str, Json)> {
    vec![
        ("policy", s(&activation.policy.name)),
        ("version", Json::Int(activation.version.into())),
        ("definition_digest", s(hex(&activation.definition_digest))),
        ("activation", s(format!("{:032x}", activation.activation.0))),
        ("effective_from", s(activation.effective_from.render())),
        ("recorded_at", Json::Int(activation.recorded_at.0.into())),
        ("chart_digest", s(hex(&activation.chart_digest))),
    ]
}

pub(crate) fn emit_selected(
    out: &Out,
    activation: &ActivatedCashFlowPolicy,
    from: DateDay,
    through: DateDay,
    at: CommitSeq,
) {
    let mut fields = activation_fields(activation);
    fields.extend([
        ("from", s(from.render())),
        ("through", s(through.render())),
        ("known_at", Json::Int(at.0.into())),
        (
            "scope",
            s("native-approved-classification; report-certificate-proves-math"),
        ),
    ]);
    out.event("cash_flow_policy_selected", fields, &format!(
        "Using approved cash policy {} v{} (activation {:032x}) for {}..={} at sequence {}; report certificates prove classification inputs and arithmetic",
        activation.policy.name, activation.version, activation.activation.0, from.render(), through.render(), at.0,
    ));
}

fn show(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    options(args, &["--name", "--from", "--to", "--as-known-at"], SHOW)?;
    let cap = ctx.capability(args, &["read"])?;
    let who = ctx.principal(args);
    let mut book = ctx.books.open_admitted(args, |book| {
        book.read_scope(who, &cap)??;
        let (at, _) = known_at_read_flag(args, book, &ctx.out, &cap)?;
        book.prepare_report_history(who, &cap, at)??;
        Ok(())
    })?;
    let (at, _) = known_at_read_flag(args, &book, &ctx.out, &cap)?;
    book.prepare_report_history(who, &cap, at)??;
    let at = at.unwrap_or(book.head()?);
    let from = date(args, "--from", SHOW)?;
    let through = date(args, "--to", SHOW)?;
    let selected = select(
        &book,
        &cap,
        args.require("--name", "an activated policy name")?,
        from,
        through,
        at,
    )?;
    ctx.out.at_book(&book)?;
    ctx.out.known_at(at);
    emit_selected(&ctx.out, &selected, from, through, at);
    let mut fields = activation_fields(&selected);
    fields.extend([
        (
            "cash_accounts",
            Json::Arr(
                selected
                    .policy
                    .cash_accounts
                    .iter()
                    .map(|id| s(format!("{id:032x}")))
                    .collect(),
            ),
        ),
        (
            "account_rules",
            Json::Arr(
                selected
                    .policy
                    .account_rules
                    .iter()
                    .map(|rule| {
                        obj(vec![
                            ("account", s(format!("{:032x}", rule.account_id))),
                            (
                                "activity",
                                s(match rule.activity {
                                    CashFlowActivity::Operating => "operating",
                                    CashFlowActivity::Investing => "investing",
                                    CashFlowActivity::Financing => "financing",
                                    CashFlowActivity::ExchangeEffect => "exchange_effect",
                                    CashFlowActivity::InternalTransfer => "internal_transfer",
                                }),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]);
    ctx.out.event(
        "cash_flow_policy",
        fields,
        &format!(
            "{} v{}: {} cash accounts and {} counterpart rules",
            selected.policy.name,
            selected.version,
            selected.policy.cash_accounts.len(),
            selected.policy.account_rules.len(),
        ),
    );
    Ok(())
}
