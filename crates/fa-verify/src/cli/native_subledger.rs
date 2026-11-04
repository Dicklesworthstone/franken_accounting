//! Recipient-selected native AR/AP questions and exact independent results.

use super::{Args, Check, Json, Usage, amount, day, h, int, n, s, usage};
use crate::report::{NativeSubledgerRequest, VerifiedNativeSubledger};

const FLAGS: [&str; 4] = [
    "--subledger",
    "--control-account",
    "--through",
    "--known-at",
];

pub(super) fn request(args: &Args) -> Result<Option<NativeSubledgerRequest>, Usage> {
    if !FLAGS.iter().any(|flag| args.has(flag)) {
        return Ok(None);
    }
    if !FLAGS.iter().all(|flag| args.has(flag)) {
        return Err(usage(
            "native subledger verification requires --subledger, --control-account, --through and --known-at together",
            "supply the recipient's original code, control vid, civil-day cutoff and fixed recorded sequence",
        ));
    }
    if ["--units", "--base-unit", "--equity-diff-request", "--view"]
        .iter()
        .any(|flag| args.has(flag))
    {
        return Err(usage(
            "native subledger inputs cannot be combined with another report profile or --view",
            "retain only --subledger, --control-account, --through and --known-at with the trusted key and optional checkpoint, receipt or digest pin",
        ));
    }
    let code = args.one("--subledger").unwrap_or_default();
    if code.is_empty() || code.len() > 64 {
        return Err(usage(
            "--subledger requires a code of 1 through 64 UTF-8 bytes",
            "supply the independently selected native subledger code",
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
    Ok(Some(NativeSubledgerRequest {
        code: code.into(),
        control_account,
        effective_through: int(args, "--through", "native subledger verification")?,
        known_at: int(args, "--known-at", "native subledger verification")?,
    }))
}

pub(super) fn checks(report: &VerifiedNativeSubledger) -> Vec<Check> {
    let mut checks = vec![Check::pass(
        "native_subledger_reconciliation",
        "recomputation",
        vec![
            ("code", s(&report.code)),
            ("name", s(&report.name)),
            ("kind", s(if report.kind == 1 { "AR" } else { "AP" })),
            ("subledger", s(format!("{:032x}", report.subledger_vid))),
            (
                "control_account",
                s(format!("{:032x}", report.control_account)),
            ),
            (
                "declaration_entry",
                s(format!("{:032x}", report.declaration_entry_vid)),
            ),
            ("declaration_digest", h(&report.declaration_entry_digest)),
            ("declared_at", n(report.declared_at)),
            ("known_at", n(report.known_at)),
            ("effective_through", day(Some(report.effective_through))),
            (
                "source_certificate_digest",
                h(&report.source_certificate_digest),
            ),
            ("reconciled", Json::Bool(report.reconciled)),
            (
                "measures",
                s("gross posted and pending debits and credits by party and native unit"),
            ),
            ("party_attribution", s("authenticated_journal")),
            ("native_graph_mirrors", s("not_judged")),
            ("historical_posting_admission", s("not_judged")),
            ("external_feed_completeness", s("not_judged")),
            ("economic_truth", s("not_judged")),
        ],
    )];
    for row in &report.rows {
        checks.push(Check::pass(
            "native_subledger_row",
            "recomputation",
            vec![
                ("party", s(format!("{:032x}", row.party))),
                ("party_value", s(format!("{:032x}", row.party_value))),
                ("party_code", s(&row.party_code)),
                ("unit", n(u64::from(row.unit))),
                ("debits", amount(row.debits)),
                ("credits", amount(row.credits)),
                ("debits_pending", amount(row.debits_pending)),
                ("credits_pending", amount(row.credits_pending)),
            ],
        ));
    }
    for total in &report.totals {
        checks.push(Check::pass(
            "native_subledger_total",
            "recomputation",
            vec![
                ("unit", n(u64::from(total.unit))),
                ("detail_debits", amount(total.detail_debits)),
                ("detail_credits", amount(total.detail_credits)),
                ("detail_debits_pending", amount(total.detail_debits_pending)),
                (
                    "detail_credits_pending",
                    amount(total.detail_credits_pending),
                ),
                ("control_debits", amount(total.control_debits)),
                ("control_credits", amount(total.control_credits)),
                (
                    "control_debits_pending",
                    amount(total.control_debits_pending),
                ),
                (
                    "control_credits_pending",
                    amount(total.control_credits_pending),
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
    fn complete_question_preserves_full_control_and_fixed_coordinates() {
        let args = [
            "report",
            "report.fab",
            "--subledger",
            "Trade AR",
            "--control-account",
            "0xffffffffffffffffffffffffffffffff",
            "--through",
            "-1",
            "--known-at",
            "18446744073709551615",
        ]
        .map(str::to_string);
        let parsed = parse(&args).unwrap_or_else(|failure| {
            panic!(
                "complete recipient question must parse: {}",
                failure.message
            )
        });
        let complete = request(&parsed).unwrap_or_else(|failure| {
            panic!(
                "complete recipient question must validate: {}",
                failure.message
            )
        });
        assert_eq!(
            complete,
            Some(NativeSubledgerRequest {
                code: "Trade AR".into(),
                control_account: u128::MAX,
                effective_through: -1,
                known_at: u64::MAX,
            })
        );
    }

    #[test]
    fn invalid_or_conflicting_questions_refuse_before_file_io() {
        let key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".to_string();
        let no_read = |_: &str| -> std::io::Result<Vec<u8>> {
            panic!("invalid recipient question must refuse before file I/O")
        };
        let question = [
            "--subledger",
            "AR",
            "--control-account",
            "0x123",
            "--through",
            "0",
            "--known-at",
            "7",
        ];
        for omitted in 0..4 {
            let mut args = vec![
                "report".into(),
                "missing".into(),
                "--key".into(),
                key.clone(),
            ];
            for (index, pair) in question.chunks(2).enumerate() {
                if index != omitted {
                    args.extend(pair.iter().map(|v| (*v).to_string()));
                }
            }
            assert_eq!(run(&args, &no_read).exit, EXIT_USAGE);
        }
        for extra in [
            ["--units", "0"],
            ["--base-unit", "1"],
            ["--view", "detail"],
            ["--equity-diff-request", "question"],
            ["--subledger", "again"],
        ] {
            let mut args = vec![
                "report".into(),
                "missing".into(),
                "--key".into(),
                key.clone(),
            ];
            args.extend(
                question
                    .iter()
                    .chain(extra.iter())
                    .map(|v| (*v).to_string()),
            );
            assert_eq!(run(&args, &no_read).exit, EXIT_USAGE);
        }
        for (index, bad) in [(1, ""), (3, "1200x"), (5, "2147483648"), (7, "HEAD")] {
            let mut args = vec![
                "report".into(),
                "missing".into(),
                "--key".into(),
                key.clone(),
            ];
            args.extend(question.iter().map(|v| (*v).to_string()));
            args[4 + index] = bad.into();
            assert_eq!(run(&args, &no_read).exit, EXIT_USAGE);
        }
        let mut wrong_verb = vec!["bundle".into(), "missing".into(), "--key".into(), key];
        wrong_verb.extend(question.iter().map(|v| (*v).to_string()));
        assert_eq!(run(&wrong_verb, &no_read).exit, EXIT_USAGE);
    }

    #[test]
    fn independent_rows_render_exact_gross_amounts_and_limited_assurance() {
        use crate::report::{VerifiedNativeSubledgerRow, VerifiedNativeSubledgerTotal};
        let exact = 9_007_199_254_740_993i128;
        let report = VerifiedNativeSubledger {
            book_id: [1; 16],
            known_at: 7,
            effective_through: 31,
            source_certificate_digest: [2; 32],
            subledger_vid: 3,
            code: "AR".into(),
            name: "Receivables".into(),
            kind: 1,
            control_account: u128::MAX,
            declaration_entry_vid: 5,
            declaration_entry_digest: [6; 32],
            declared_at: 2,
            rows: vec![VerifiedNativeSubledgerRow {
                party: 8,
                party_value: 9,
                party_code: "Customer A".into(),
                unit: 1,
                debits: exact,
                credits: exact - 1,
                debits_pending: 17,
                credits_pending: 19,
            }],
            totals: vec![VerifiedNativeSubledgerTotal {
                unit: 1,
                detail_debits: exact,
                detail_credits: exact - 1,
                detail_debits_pending: 17,
                detail_credits_pending: 19,
                control_debits: exact,
                control_credits: exact - 1,
                control_debits_pending: 17,
                control_credits_pending: 19,
            }],
            reconciled: true,
        };
        let checks = checks(&report);
        assert_eq!(
            checks.iter().map(|check| check.name).collect::<Vec<_>>(),
            [
                "native_subledger_reconciliation",
                "native_subledger_row",
                "native_subledger_total",
            ]
        );
        let mut output = String::new();
        for check in checks {
            check.json().write(&mut output);
        }
        for expected in [
            "\"debits\":\"9007199254740993\"",
            "\"credits\":\"9007199254740992\"",
            "\"detail_debits_pending\":\"17\"",
            "\"control_credits_pending\":\"19\"",
            "\"control_account\":\"ffffffffffffffffffffffffffffffff\"",
            "\"party_code\":\"Customer A\"",
            "\"reconciled\":true",
            "\"external_feed_completeness\":\"not_judged\"",
            "\"historical_posting_admission\":\"not_judged\"",
        ] {
            assert!(output.contains(expected), "{expected}: {output}");
        }
    }
}
