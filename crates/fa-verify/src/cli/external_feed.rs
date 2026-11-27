//! A recipient's fixed external-feed question and its exact mechanical result.

use super::{Args, Check, Json, Usage, amount, day, h, int, n, s, usage};
use crate::report::{ExternalFeedManifest, ExternalFeedRequest, VerifiedExternalFeed};

pub(super) fn population_check(
    manifest: &ExternalFeedManifest,
    report: &VerifiedExternalFeed,
) -> Check {
    let mut check = Check::pass(
        "external_feed_population",
        "declared_source_population",
        vec![
            ("extract", s(&manifest.extract)),
            ("manifest_digest", h(&manifest.digest)),
            ("from", day(Some(manifest.from))),
            ("through", day(Some(manifest.through))),
        ],
    );
    if let Err(reason) = manifest.verify(report) {
        check.verdict = super::Verdict::Fail;
        check.reason = Some(reason);
    }
    check
}

pub(super) fn request(args: &Args) -> Result<Option<ExternalFeedRequest>, Usage> {
    if !args.has("--external-feed") {
        return Ok(None);
    }
    if ["--control-account", "--through", "--known-at"]
        .iter()
        .any(|flag| !args.has(flag))
    {
        return Err(usage(
            "external-feed verification requires --external-feed, --control-account, --through and --known-at together",
            "supply the recipient's original feed, control vid, civil-day cutoff and fixed recorded sequence",
        ));
    }
    if [
        "--subledger",
        "--units",
        "--base-unit",
        "--equity-diff-request",
        "--view",
    ]
    .iter()
    .any(|flag| args.has(flag))
    {
        return Err(usage(
            "external-feed inputs cannot be combined with another report profile or --view",
            "retain the fixed external-feed question with the trusted key and optional checkpoint, receipt or digest pin",
        ));
    }
    let feed = args.one("--external-feed").unwrap_or_default();
    if feed.is_empty()
        || feed.len() > 64
        || !feed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
    {
        return Err(usage(
            "--external-feed requires 1 through 64 ASCII letters, digits or ._:/-",
            "supply the independently selected external feed identifier",
        ));
    }
    let raw = args.one("--control-account").unwrap_or_default();
    let control_account = match raw.strip_prefix("0x") {
        Some(hex) if !hex.is_empty() && hex.len() <= 32 => u128::from_str_radix(hex, 16).ok(),
        Some(_) => None,
        None => raw.parse::<u128>().ok(),
    }
    .ok_or_else(|| {
        usage(
            "--control-account requires a numeric account vid",
            "supply a decimal vid or 0x followed by up to 32 hex characters, not an account code",
        )
    })?;
    Ok(Some(ExternalFeedRequest {
        feed: feed.into(),
        control_account,
        effective_through: int(args, "--through", "external-feed verification")?,
        known_at: int(args, "--known-at", "external-feed verification")?,
    }))
}

fn dimensions(values: &[(u32, u128)]) -> Json {
    Json::List(
        values
            .iter()
            .map(|(kind, value)| {
                Json::Obj(vec![
                    ("kind", n(u64::from(*kind))),
                    ("value", s(format!("{value:032x}"))),
                ])
            })
            .collect(),
    )
}

pub(super) fn checks(report: &VerifiedExternalFeed) -> Vec<Check> {
    let mut checks = vec![Check::pass(
        "external_feed_reconciliation",
        "recomputation",
        vec![
            ("feed", s(&report.feed)),
            (
                "control_account",
                s(format!("{:032x}", report.control_account)),
            ),
            ("known_at", n(report.known_at)),
            ("effective_through", day(Some(report.effective_through))),
            (
                "source_certificate_digest",
                h(&report.source_certificate_digest),
            ),
            ("reconciled", Json::Bool(report.reconciled)),
            ("batches", n(report.batches.len() as u64)),
            ("unattributed_legs", n(report.unattributed.len() as u64)),
            (
                "measures",
                s(
                    "gross detail, control and pending debits and credits by dimensions and native unit",
                ),
            ),
            (
                "review_citations",
                s("authenticated_journal_at_summary_birth"),
            ),
            ("native_graph_mirrors", s("not_judged")),
            ("historical_posting_admission", s("not_judged")),
            ("source_system_completeness", s("not_judged")),
            ("human_review_independence", s("not_judged")),
            ("economic_truth", s("not_judged")),
        ],
    )];
    if let Some(parent) = &report.manifest_review {
        checks.push(Check::pass(
            "external_feed_manifest_review",
            "authenticated_journal_prefix",
            vec![
                ("document_oid", h(&parent.document_oid)),
                ("document_commitment", h(&parent.doc_commit)),
                ("received_by", s(format!("{:032x}", parent.received_by))),
                ("intake_seq", n(parent.intake_position.0)),
                ("intake_ordinal", n(u64::from(parent.intake_position.1))),
                ("reviewed_by", s(format!("{:032x}", parent.reviewed_by))),
                ("review_seq", n(parent.review_position.0)),
                ("review_ordinal", n(u64::from(parent.review_position.1))),
            ],
        ));
    }
    for batch in &report.batches {
        checks.push(Check::pass(
            "external_feed_batch",
            "recomputation",
            vec![
                ("entry", s(format!("{:032x}", batch.entry))),
                ("entry_digest", h(&batch.entry_digest)),
                ("recorded_at", n(batch.recorded_at)),
                ("batch_key", s(&batch.batch_key)),
                ("effective_date", day(Some(batch.effective_date))),
                ("document_oid", h(&batch.document_oid)),
                ("document_commitment", h(&batch.doc_commit)),
                (
                    "review_attestation",
                    s(format!("{:032x}", batch.review_attestation)),
                ),
                ("reviewer", s(format!("{:032x}", batch.reviewer))),
                ("detail_rows", n(batch.detail_rows as u64)),
                ("reconciled", Json::Bool(batch.reconciled)),
            ],
        ));
    }
    for contribution in &report.contributions {
        checks.push(Check::pass(
            "external_feed_contribution",
            "recomputation",
            vec![
                ("entry", s(format!("{:032x}", contribution.entry))),
                ("entry_digest", h(&contribution.entry_digest)),
                ("source", s(format!("{:032x}", contribution.source))),
                ("source_digest", h(&contribution.source_digest)),
                ("recorded_at", n(contribution.recorded_at)),
                ("effective_date", day(Some(contribution.effective_date))),
                ("reversed", Json::Bool(contribution.reversed)),
            ],
        ));
    }
    for leg in &report.unattributed {
        checks.push(Check::pass(
            "external_feed_unattributed_leg",
            "recomputation",
            vec![
                ("entry", s(format!("{:032x}", leg.entry))),
                ("entry_digest", h(&leg.entry_digest)),
                ("ordinal", n(u64::from(leg.ordinal))),
                ("unit", n(u64::from(leg.unit))),
                ("side", s(if leg.credit { "credit" } else { "debit" })),
                ("amount", amount(leg.amount)),
                ("dimensions", dimensions(&leg.dimension_set)),
                ("pending", Json::Bool(leg.pending)),
            ],
        ));
    }
    for row in &report.rows {
        checks.push(Check::pass(
            "external_feed_row",
            "recomputation",
            vec![
                ("unit", n(u64::from(row.unit_id))),
                ("dimensions", dimensions(&row.dimension_set)),
                ("detail_debits", amount(row.detail_debits)),
                ("detail_credits", amount(row.detail_credits)),
                ("control_debits", amount(row.control_debits)),
                ("control_credits", amount(row.control_credits)),
                ("pending_debits", amount(row.pending_debits)),
                ("pending_credits", amount(row.pending_credits)),
            ],
        ));
    }
    for total in &report.totals {
        checks.push(Check::pass(
            "external_feed_total",
            "recomputation",
            vec![
                ("unit", n(u64::from(total.unit_id))),
                ("detail_debits", amount(total.detail_debits)),
                ("detail_credits", amount(total.detail_credits)),
                ("control_debits", amount(total.control_debits)),
                ("control_credits", amount(total.control_credits)),
                ("pending_debits", amount(total.pending_debits)),
                ("pending_credits", amount(total.pending_credits)),
                ("register_debits", amount(total.register_debits)),
                ("register_credits", amount(total.register_credits)),
                (
                    "register_debits_pending",
                    amount(total.register_debits_pending),
                ),
                (
                    "register_credits_pending",
                    amount(total.register_credits_pending),
                ),
            ],
        ));
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::super::{EXIT_USAGE, parse, run};
    use super::*;

    #[test]
    fn complete_external_question_preserves_full_numeric_coordinates() {
        let args = [
            "report",
            "bundle",
            "--external-feed",
            "customer/ar-1",
            "--control-account",
            "0xffffffffffffffffffffffffffffffff",
            "--through",
            "-1",
            "--known-at",
            "18446744073709551615",
        ]
        .map(str::to_string);
        let parsed = parse(&args).unwrap_or_else(|e| panic!("{}", e.message));
        let actual = request(&parsed)
            .unwrap_or_else(|e| panic!("{}", e.message))
            .unwrap();
        assert_eq!(actual.feed, "customer/ar-1");
        assert_eq!(actual.control_account, u128::MAX);
        assert_eq!(actual.effective_through, -1);
        assert_eq!(actual.known_at, u64::MAX);
    }

    #[test]
    fn missing_invalid_or_conflicting_external_questions_refuse_before_io() {
        let no_read = |_: &str| -> std::io::Result<Vec<u8>> {
            panic!("question must refuse before file I/O")
        };
        let base = [
            "report",
            "missing",
            "--key",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ];
        let question = [
            "--external-feed",
            "customer-ar",
            "--control-account",
            "0x123",
            "--through",
            "0",
            "--known-at",
            "7",
        ];
        for omitted in 0..4 {
            let mut args: Vec<String> = base.iter().map(|v| (*v).into()).collect();
            for (index, pair) in question.chunks(2).enumerate() {
                if index != omitted {
                    args.extend(pair.iter().map(|v| (*v).into()));
                }
            }
            assert_eq!(run(&args, &no_read).exit, EXIT_USAGE);
        }
        for extra in [
            ["--subledger", "AR"],
            ["--units", "0"],
            ["--base-unit", "0"],
            ["--view", "detail"],
            ["--equity-diff-request", "request"],
            ["--external-feed", "again"],
        ] {
            let args = base
                .iter()
                .chain(question.iter())
                .chain(extra.iter())
                .map(|v| (*v).to_string())
                .collect::<Vec<_>>();
            assert_eq!(run(&args, &no_read).exit, EXIT_USAGE);
        }
        for (index, bad) in [
            (1, ""),
            (1, "customer ar"),
            (3, "12x"),
            (5, "2147483648"),
            (7, "HEAD"),
        ] {
            let mut bad_question = question;
            bad_question[index] = bad;
            let args = base
                .iter()
                .chain(bad_question.iter())
                .map(|v| (*v).to_string())
                .collect::<Vec<_>>();
            assert_eq!(run(&args, &no_read).exit, EXIT_USAGE);
        }
    }
}
