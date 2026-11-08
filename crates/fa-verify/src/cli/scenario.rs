//! Offline additive scenario mathematics with an independently fixed question.

use super::{
    Args, Check, Json, Read, Usage, Verdict, amount, checkpoint_check, day, h, key, load, n,
    s, subject, unhex, usage, verify_checkpoint,
};
use crate::scenario_report::{ScenarioExpectation, verify_scenario_math_expected};

pub(super) fn run(args: &Args, read: Read<'_>) -> Result<Vec<Check>, Usage> {
    let file = subject(args, "a scenario mathematical bundle")?;
    let question = args.one("--scenario-request").ok_or_else(|| {
        usage(
            "scenario verification requires the independently retained --scenario-request",
            "supply the original canonical question, retained before delivery; the bundle cannot choose its own fork, Plan prefix, periods, assumptions or method",
        )
    })?;
    let keys = args.all("--key");
    if keys.is_empty() {
        return Err(usage(
            "scenario verification requires a recipient-owned checkpoint key",
            "pass --key <64 hex> obtained from an independent trusted source",
        ));
    }
    let keys: Vec<[u8; 32]> = keys.into_iter().map(key).collect::<Result<_, _>>()?;
    let certificate_pin: Option<[u8; 32]> = args
        .one("--expect")
        .map(|raw| {
            unhex(raw)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    usage(
                        "--expect must contain exactly 64 hex characters",
                        "supply the independently retained outer ScenarioDiffCertificate digest",
                    )
                })
        })
        .transpose()?;
    if certificate_pin.is_none() && args.one("--receipt").is_none() {
        return Err(usage(
            "scenario mathematics requires a signed outer --receipt or an independent --expect certificate pin",
            "the checkpoint authenticates the journal; retain a receipt or certificate digest separately to bind the selected hypothetical computation",
        ));
    }
    let expected = ScenarioExpectation::decode(&load(read, question, args.hex)?)
        .map_err(|error| usage(format!("invalid scenario question: {error}"), "use the original canonical --request-out file"))?;
    let mut checks = Vec::new();
    let expected_checkpoint = if let Some(path) = args.one("--checkpoint") {
        let signed = verify_checkpoint(&load(read, path, args.hex)?, &keys);
        checks.push(checkpoint_check(&signed));
        match signed {
            Ok(signed) => Some(signed.checkpoint),
            Err(_) => return Ok(checks),
        }
    } else {
        None
    };
    let bytes = load(read, file, args.hex)?;
    let receipt = args
        .one("--receipt")
        .map(|path| load(read, path, args.hex))
        .transpose()?;
    let report = match verify_scenario_math_expected(
        &bytes,
        &keys,
        expected_checkpoint.as_ref(),
        receipt.as_deref(),
        &expected,
        certificate_pin.as_ref(),
    ) {
        Ok(report) => report,
        Err(error) => {
            checks.push(Check {
                name: error.predicate,
                scope: "conditional_additive_scenario_math",
                verdict: Verdict::Fail,
                detail: Vec::new(),
                reason: Some(error.detail),
            });
            return Ok(checks);
        }
    };
    checks.push(Check::pass(
        "scenario_math",
        report.scope,
        vec![
            ("bundle_digest", h(&report.bundle_digest)),
            ("certificate_digest", h(&report.certificate_digest)),
            ("method", s(report.method)),
            ("book", h(&report.expectation.book_id)),
            ("scenario", s(&report.expectation.name)),
            ("fork_at", n(report.expectation.fork_at)),
            ("intents", n(report.expectation.intents)),
            ("intents_digest", h(&report.expectation.intents_digest)),
            ("from", day(report.expectation.from)),
            ("activity", Json::Bool(report.expectation.activity)),
            (
                "periods",
                Json::List(report.expectation.periods.iter().map(s).collect()),
            ),
            (
                "assumptions",
                Json::List(report.expectation.assumptions.iter().map(|oid| h(oid)).collect()),
            ),
            ("checked_records", n(report.checked_records as u64)),
            ("checked_intents", n(report.checked_intents as u64)),
            ("checked_documents", n(report.checked_documents as u64)),
            ("changed_rows", n(report.rows.len() as u64)),
            ("signed_receipt", Json::Bool(report.receipt.is_some())),
            ("historical_admission", s(report.historical_admission)),
            ("native_marker_membership", s(report.native_marker_membership)),
            ("hypothetical_entries", s("assumed_effects_not_trunk_members")),
            ("economic_truth", s("not_judged")),
        ],
    ));
    for row in &report.rows {
        checks.push(Check::pass(
            "scenario_row",
            report.scope,
            vec![
                ("account", s(format!("{:032x}", row.account))),
                ("code", s(&row.code)),
                ("name", s(&row.name)),
                ("unit", n(u64::from(row.unit))),
                ("trunk_debits", amount(row.trunk_debits)),
                ("trunk_credits", amount(row.trunk_credits)),
                ("scenario_debits", amount(row.scenario_debits)),
                ("scenario_credits", amount(row.scenario_credits)),
                ("delta", amount(row.delta)),
                ("trunk_debits_pending", amount(row.trunk_debits_pending)),
                ("trunk_credits_pending", amount(row.trunk_credits_pending)),
                ("scenario_debits_pending", amount(row.scenario_debits_pending)),
                ("scenario_credits_pending", amount(row.scenario_credits_pending)),
                ("pending_delta", amount(row.pending_delta)),
            ],
        ));
    }
    Ok(checks)
}
