//! Independent request and policy transport for retained report replay.
//! A delivered artifact never supplies its own recipient expectations.

use super::*;
use fa::aging::portfolio::{AgingAccountScope, AgingPortfolioRequest};
use fa::{
    AdjustmentCategory, AdjustmentSign, AgingBuckets, AgingReconciliationRequest, CashFlowActivity,
    CashFlowDefinition, IndirectCashFlowRequest, RollForwardRequest,
};
use fa_model::account_vid;
use fa_time::DateDay;
use fgdb_types::CommitSeq;

const MAX_EXPECTATION_BYTES: usize = 1024 * 1024;

pub(super) enum Expected {
    AsSupplied,
    CashFlow(RollForwardRequest, CashFlowDefinition),
    Indirect(IndirectCashFlowRequest),
    Reconciliation(AgingReconciliationRequest),
    Portfolio(AgingPortfolioRequest),
}

impl Expected {
    pub(super) fn borrowed(&self) -> fa::ReportArtifactExpectation<'_> {
        match self {
            Self::AsSupplied => fa::ReportArtifactExpectation::AsSupplied,
            Self::CashFlow(request, definition) => fa::ReportArtifactExpectation::CashFlow {
                request,
                definition,
            },
            Self::Indirect(request) => fa::ReportArtifactExpectation::IndirectCashFlow(request),
            Self::Reconciliation(request) => {
                fa::ReportArtifactExpectation::AgingReconciliation(request)
            }
            Self::Portfolio(request) => fa::ReportArtifactExpectation::AgingPortfolio(request),
        }
    }
}

fn invalid(message: impl Into<String>) -> Fail {
    usage(
        message,
        "pass --expect '<JSON>' with an independently retained kind, fixed known_at, scope and policy; the report_certificate replay_command carries the producer's original request",
    )
}

fn check_size(text: &str) -> Result<(), Fail> {
    if text.len() > MAX_EXPECTATION_BYTES {
        return Err(invalid(
            "replay expectation exceeds the 1 MiB transport limit; select a smaller report scope",
        ));
    }
    Ok(())
}

fn field<'a>(doc: &'a Json, key: &str) -> Result<&'a Json, Fail> {
    doc.get(key)
        .ok_or_else(|| invalid(format!("replay expectation requires '{key}'")))
}

fn string<'a>(doc: &'a Json, key: &str) -> Result<&'a str, Fail> {
    match field(doc, key)? {
        Json::Str(text) if !text.is_empty() => Ok(text),
        _ => Err(invalid(format!(
            "replay expectation '{key}' must be a nonempty string"
        ))),
    }
}

fn array<'a>(doc: &'a Json, key: &str) -> Result<&'a [Json], Fail> {
    match field(doc, key)? {
        Json::Arr(items) => Ok(items),
        _ => Err(invalid(format!(
            "replay expectation '{key}' must be an array"
        ))),
    }
}

fn exact_fields(doc: &Json, allowed: &[&str]) -> Result<(), Fail> {
    let Json::Obj(fields) = doc else {
        return Err(invalid("replay expectation must be a JSON object"));
    };
    for (name, _) in fields {
        if !allowed.contains(&name.as_str()) {
            return Err(invalid(format!(
                "unknown replay expectation field '{name}'"
            )));
        }
    }
    Ok(())
}

fn account(text: &str, book: &Book) -> Result<VId, Fail> {
    if text.is_empty() {
        return Err(invalid(
            "expected account must be a nonempty code or 32-hex id",
        ));
    }
    if text.len() == 32 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        u128::from_str_radix(text, 16)
            .map(VId)
            .map_err(|_| invalid("invalid expected account id"))
    } else {
        Ok(account_vid(book.context().book_id, text))
    }
}

fn fixed_prefix(doc: &Json) -> Result<CommitSeq, Fail> {
    match field(doc, "known_at")? {
        Json::Int(value) => u64::try_from(*value)
            .map(CommitSeq)
            .map_err(|_| invalid("expected known_at must be a nonnegative u64 sequence")),
        _ => Err(invalid(
            "expected known_at must be a fixed integer sequence; HEAD is not a replay expectation",
        )),
    }
}

fn day(doc: &Json, key: &str) -> Result<DateDay, Fail> {
    DateDay::parse(string(doc, key)?)
        .map_err(|error| invalid(format!("invalid expected {key} date: {error}")))
}

fn scope(doc: &Json, book: &Book) -> Result<RollForwardRequest, Fail> {
    let accounts = array(doc, "accounts")?
        .iter()
        .map(|item| match item {
            Json::Str(text) => account(text, book),
            _ => Err(invalid(
                "expected accounts must contain account codes or 32-hex ids",
            )),
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let units = array(doc, "units")?
        .iter()
        .map(|item| {
            let unit = match item {
                Json::Str(code) => book
                    .context()
                    .units
                    .lookup(code)
                    .ok_or_else(|| invalid(format!("unknown expected unit '{code}'")))?,
                Json::Int(value) => fa_money::UnitId(
                    u32::try_from(*value)
                        .map_err(|_| invalid("expected unit id must be a nonnegative u32"))?,
                ),
                _ => {
                    return Err(invalid(
                        "expected units must contain registered codes or integer ids",
                    ));
                }
            };
            if book.context().units.get(unit).is_none() {
                return Err(invalid(format!("unknown expected unit id {}", unit.0)));
            }
            Ok(unit.0)
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    if accounts.is_empty() || units.is_empty() {
        return Err(invalid("expected accounts and units must both be nonempty"));
    }
    Ok(RollForwardRequest {
        accounts,
        units,
        label: string(doc, "label")?.to_string(),
        effective_from: day(doc, "from")?,
        effective_through: day(doc, "through")?,
        known_at: Some(fixed_prefix(doc)?),
    })
}

fn policy_shape(policy: &Json, indirect: bool) -> Result<(), Fail> {
    crate::cli::validate_cash_flow_policy_fields(policy, indirect)?;
    string(policy, "name")?;
    for item in array(policy, "cash_accounts")? {
        if !matches!(item, Json::Str(code) if !code.is_empty()) {
            return Err(invalid(
                "expected cash_accounts must contain nonempty account codes or ids",
            ));
        }
    }
    array(policy, "assignments")?;
    if indirect {
        string(policy, "cash_policy")?;
        array(policy, "adjustments")?;
    }
    Ok(())
}

pub(super) fn parse(args: &Args, book: &Book) -> Result<Expected, Fail> {
    if args.flag_all("--expect").len() > 1 {
        return Err(invalid("--expect may be supplied only once"));
    }
    let Some(text) = args.flag("--expect") else {
        // The unified verifier refuses AsSupplied for these four families.
        return Ok(Expected::AsSupplied);
    };
    check_size(text)?;
    let doc = crate::json::parse(text)
        .map_err(|error| invalid(format!("invalid replay expectation JSON: {error}")))?;
    match string(&doc, "kind")? {
        kind @ ("cash-flow" | "indirect-cash-flow") => {
            let indirect = kind == "indirect-cash-flow";
            let mut allowed = vec![
                "kind", "accounts", "units", "label", "from", "through", "known_at", "policy",
            ];
            if indirect {
                allowed.push("income_periods");
            }
            exact_fields(&doc, &allowed)?;
            let request = scope(&doc, book)?;
            let policy = field(&doc, "policy")?;
            policy_shape(policy, indirect)?;
            let mut definition = crate::cli::parse_cash_flow_definition(
                policy,
                book.context().book_id,
                &request.accounts,
                "",
            )?;
            if !indirect {
                return Ok(Expected::CashFlow(request, definition));
            }
            let income_periods = array(&doc, "income_periods")?
                .iter()
                .map(|item| match item {
                    Json::Str(period) if !period.is_empty() => Ok(period.clone()),
                    _ => Err(invalid(
                        "expected income_periods must contain nonempty period codes",
                    )),
                })
                .collect::<Result<Vec<_>, Fail>>()?;
            if income_periods.is_empty() {
                return Err(invalid("expected income_periods must be nonempty"));
            }
            let (cash_policy, indirect) =
                crate::cli::parse_indirect_cash_flow_definition(policy, "")?;
            definition.name = cash_policy;
            Ok(Expected::Indirect(IndirectCashFlowRequest {
                cash: request,
                cash_definition: definition,
                income_periods,
                definition: indirect,
            }))
        }
        "aging-reconciliation" => {
            exact_fields(&doc, &["kind", "account", "through", "known_at", "buckets"])?;
            Ok(Expected::Reconciliation(AgingReconciliationRequest {
                account: account(string(&doc, "account")?, book)?,
                effective_through: day(&doc, "through")?,
                known_at: Some(fixed_prefix(&doc)?),
                buckets: aging_buckets(&doc)?,
            }))
        }
        "aging-portfolio" => {
            let selected = match string(&doc, "scope")? {
                "all-posting" => false,
                "selected" => true,
                other => {
                    return Err(invalid(format!(
                        "expected portfolio scope must be all-posting or selected, not '{other}'"
                    )));
                }
            };
            let mut allowed = vec!["kind", "scope", "through", "known_at", "buckets"];
            if selected {
                allowed.push("accounts");
            }
            exact_fields(&doc, &allowed)?;
            let scope = if selected {
                AgingAccountScope::Selected(
                    array(&doc, "accounts")?
                        .iter()
                        .map(|item| match item {
                            Json::Str(text) => account(text, book),
                            _ => Err(invalid(
                                "expected portfolio accounts must be codes or 32-hex ids",
                            )),
                        })
                        .collect::<Result<_, Fail>>()?,
                )
            } else {
                AgingAccountScope::AllPosting
            };
            Ok(Expected::Portfolio(AgingPortfolioRequest {
                scope,
                effective_through: day(&doc, "through")?,
                known_at: Some(fixed_prefix(&doc)?),
                buckets: aging_buckets(&doc)?,
            }))
        }
        other => Err(invalid(format!(
            "unsupported replay expectation kind '{other}'"
        ))),
    }
}

fn scope_fields(request: &RollForwardRequest) -> Vec<(&'static str, Json)> {
    vec![
        (
            "accounts",
            Json::Arr(
                request
                    .accounts
                    .iter()
                    .map(|id| s(format!("{:032x}", id.0)))
                    .collect(),
            ),
        ),
        (
            "units",
            Json::Arr(
                request
                    .units
                    .iter()
                    .map(|unit| Json::Int(i128::from(*unit)))
                    .collect(),
            ),
        ),
        ("label", s(&request.label)),
        ("from", s(request.effective_from.render())),
        ("through", s(request.effective_through.render())),
        (
            "known_at",
            request
                .known_at
                .map_or(Json::Null, |seq| Json::Int(i128::from(seq.0))),
        ),
    ]
}

fn policy_fields(definition: &CashFlowDefinition) -> Vec<(&'static str, Json)> {
    vec![
        ("name", s(&definition.name)),
        (
            "cash_accounts",
            Json::Arr(
                definition
                    .cash_accounts
                    .iter()
                    .map(|id| s(format!("{id:032x}")))
                    .collect(),
            ),
        ),
        (
            "assignments",
            Json::Arr(
                definition
                    .assignments
                    .iter()
                    .map(|assignment| {
                        obj(vec![
                            ("entry_digest", s(hex(&assignment.entry_digest))),
                            ("leg_index", Json::Int(i128::from(assignment.leg_index))),
                            (
                                "activity",
                                s(match assignment.activity {
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
    ]
}

pub(crate) fn cash_flow_expectation_json(
    request: &RollForwardRequest,
    definition: &CashFlowDefinition,
) -> Json {
    let mut fields = scope_fields(request);
    fields.push(("kind", s("cash-flow")));
    fields.push(("policy", obj(policy_fields(definition))));
    obj(fields)
}

pub(crate) fn indirect_expectation_json(request: &IndirectCashFlowRequest) -> Json {
    let mut fields = scope_fields(&request.cash);
    fields.push(("kind", s("indirect-cash-flow")));
    fields.push((
        "income_periods",
        Json::Arr(request.income_periods.iter().map(s).collect()),
    ));
    let mut policy = policy_fields(&request.cash_definition);
    for (name, value) in &mut policy {
        if *name == "name" {
            *value = s(&request.definition.name);
        }
    }
    policy.push(("cash_policy", s(&request.cash_definition.name)));
    policy.push((
        "adjustments",
        Json::Arr(
            request
                .definition
                .adjustments
                .iter()
                .map(|adjustment| {
                    obj(vec![
                        ("entry_digest", s(hex(&adjustment.entry_digest))),
                        ("leg_index", Json::Int(i128::from(adjustment.leg_index))),
                        ("reason", s(&adjustment.reason)),
                        (
                            "category",
                            s(match adjustment.category {
                                AdjustmentCategory::NonCash => "non_cash",
                                AdjustmentCategory::WorkingCapital => "working_capital",
                                AdjustmentCategory::NonOperating => "non_operating",
                            }),
                        ),
                        (
                            "sign",
                            s(match adjustment.sign {
                                AdjustmentSign::DebitMinusCredit => "debit_minus_credit",
                                AdjustmentSign::CreditMinusDebit => "credit_minus_debit",
                            }),
                        ),
                    ])
                })
                .collect(),
        ),
    ));
    fields.push(("policy", obj(policy)));
    obj(fields)
}

pub(crate) fn reconciliation_expectation_json(request: &AgingReconciliationRequest) -> Json {
    obj(vec![
        ("kind", s("aging-reconciliation")),
        ("account", s(format!("{:032x}", request.account.0))),
        ("through", s(request.effective_through.render())),
        ("known_at", known_at_json(request.known_at)),
        ("buckets", buckets_json(&request.buckets)),
    ])
}

pub(crate) fn portfolio_expectation_json(request: &AgingPortfolioRequest) -> Json {
    let mut fields = vec![("kind", s("aging-portfolio"))];
    match &request.scope {
        AgingAccountScope::AllPosting => fields.push(("scope", s("all-posting"))),
        AgingAccountScope::Selected(ids) => {
            fields.push(("scope", s("selected")));
            fields.push((
                "accounts",
                Json::Arr(ids.iter().map(|id| s(format!("{:032x}", id.0))).collect()),
            ));
        }
    }
    fields.push(("through", s(request.effective_through.render())));
    fields.push(("known_at", known_at_json(request.known_at)));
    fields.push(("buckets", buckets_json(&request.buckets)));
    obj(fields)
}

fn known_at_json(known_at: Option<CommitSeq>) -> Json {
    known_at.map_or(Json::Null, |seq| Json::Int(i128::from(seq.0)))
}

fn buckets_json(buckets: &AgingBuckets) -> Json {
    Json::Arr(
        buckets
            .upper_bounds()
            .iter()
            .map(|bound| Json::Int(i128::from(*bound)))
            .collect(),
    )
}

fn aging_buckets(doc: &Json) -> Result<AgingBuckets, Fail> {
    let bounds = array(doc, "buckets")?
        .iter()
        .map(|item| match item {
            Json::Int(value) => u32::try_from(*value)
                .map_err(|_| invalid("expected aging bounds must be nonnegative u32 days")),
            _ => Err(invalid("expected aging bounds must be integer days")),
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    AgingBuckets::new(bounds)
        .map_err(|error| invalid(format!("invalid expected aging buckets: {error}")))
}

/// Apply the same transport bound before retaining a producer's certificate.
/// Otherwise certification could publish a replay command the CLI must reject.
pub(super) fn validate_generated(expected: fa::ReportArtifactExpectation<'_>) -> Result<(), Fail> {
    let doc = match expected {
        fa::ReportArtifactExpectation::CashFlow {
            request,
            definition,
        } => cash_flow_expectation_json(request, definition),
        fa::ReportArtifactExpectation::IndirectCashFlow(request) => {
            indirect_expectation_json(request)
        }
        fa::ReportArtifactExpectation::AgingReconciliation(request) => {
            reconciliation_expectation_json(request)
        }
        fa::ReportArtifactExpectation::AgingPortfolio(request) => {
            portfolio_expectation_json(request)
        }
        _ => return Ok(()),
    };
    check_size(&doc.render())
}
