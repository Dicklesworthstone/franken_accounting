//! Portfolio exports preserve complete historical chart coverage and the exact
//! recipient question through the real producer and independent verifier CLI.

use super::*;

#[test]
fn retained_portfolios_export_all_posting_and_selected_coverage_with_outer_pins() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    let zero_chart = write(
        &fixture.dir,
        "portfolio-zero-chart.json",
        r#"{"accounts":[{"code":"1200","name":"Idle receivables","type":"Asset","unit":"USD"}]}"#,
    );
    ok(&fixture.book, &["chart", "import", &zero_chart]);
    fixture.post("portfolio-sale", "2026-03-10", "12.34", &evidence);
    let known_at = fixture.head();
    let at = known_at.to_string();
    let all_path = fixture.dir.join("all-posting.certificate");
    let all_metadata = aging::certify(
        &fixture,
        &[
            "aging",
            "--all-posting",
            "--reconcile",
            "--as-of",
            "2026-03-31",
            "--as-known-at",
            &at,
            "--bucket",
            "0",
            "--bucket",
            "30",
            "--certificate-out",
            all_path.to_str().unwrap(),
        ],
    );
    let selected_metadata = aging::certify(
        &fixture,
        &[
            "aging",
            "--account",
            "1000,4000",
            "--reconcile",
            "--as-of",
            "2026-03-31",
            "--as-known-at",
            &at,
            "--bucket",
            "0",
            "--bucket",
            "30",
        ],
    );
    assert_eq!(std::fs::read(&all_path).unwrap(), bytes(&all_metadata));
    let later_chart = write(
        &fixture.dir,
        "portfolio-later-chart.json",
        r#"{"accounts":[{"code":"1300","name":"Later zero account","type":"Asset","unit":"USD"}]}"#,
    );
    ok(&fixture.book, &["chart", "import", &later_chart]);
    fixture.post("portfolio-later-backdated", "2026-03-15", "2.00", &evidence);
    let state = fixture.checkpoint();
    let signed = exported(
        &fixture.book,
        &["signed-checkpoint", "--state", text(&state, "oid")],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let checkpoint = fa_verify::verify_checkpoint(&bytes(&signed), &[key]).unwrap();
    let before = fixture.head();
    for (metadata, all_posting) in [(&all_metadata, true), (&selected_metadata, false)] {
        assert_eq!(text(metadata, "output_format"), "fa:aging-portfolio:v1");
        let certificate =
            fa::aging::portfolio::AgingPortfolioCertificate::decode(&bytes(metadata)).unwrap();
        let locator = format!("C:{}", text(metadata, "oid"));
        let expected = if all_posting {
            format!(
                r#"{{"kind":"aging-portfolio","scope":"all-posting","through":"2026-03-31","known_at":{known_at},"buckets":[0,30]}}"#
            )
        } else {
            format!(
                r#"{{"kind":"aging-portfolio","scope":"selected","accounts":["1000","4000"],"through":"2026-03-31","known_at":{known_at},"buckets":[0,30]}}"#
            )
        };
        let (exit, _) = run(
            &fixture.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                &locator,
                "--state",
                text(&state, "oid"),
            ],
        );
        assert_eq!(
            exit, 2,
            "export requires an independently chosen portfolio request"
        );
        let wrong = expected.replace("2026-03-31", "2026-03-30");
        let (exit, _) = run(
            &fixture.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                &locator,
                "--expect",
                &wrong,
                "--state",
                text(&state, "oid"),
            ],
        );
        assert_eq!(
            exit, 8,
            "a valid certificate cannot answer a different cutoff question"
        );
        let source = if all_posting {
            all_path.to_str().unwrap()
        } else {
            &locator
        };
        let produced = ok(
            &fixture.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                source,
                "--expect",
                &expected,
                "--state",
                text(&state, "oid"),
            ],
        );
        let pin = fa_verify::blake3::hex(certificate.digest());
        assert!(text(&produced, "verify").contains(&format!("--expect {pin}")));
        let bundle = bytes(&produced);
        let receipt = unhex(text(&produced, "receipt"));
        let verified = fa_verify::report::verify_report_expected(
            &bundle,
            &[key],
            Some(&checkpoint.checkpoint),
            Some(&receipt),
            Some(certificate.digest()),
        )
        .expect("retained original portfolio independently verifies");
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.known_at, known_at);
        assert_eq!(verified.certificate_digest, *certificate.digest());
        let portfolio = verified.aging_portfolio.unwrap();
        assert_eq!(portfolio.accounts.len(), if all_posting { 3 } else { 2 });
        assert_eq!(
            portfolio.uncovered_accounts.len(),
            usize::from(!all_posting)
        );
        assert_eq!(portfolio.is_complete(), all_posting);
        assert!(portfolio.is_reconciled());
        assert!(!portfolio.accounts.iter().any(|a| a.account.code == "1300"));
        assert!(
            !portfolio
                .uncovered_accounts
                .iter()
                .any(|a| a.code == "1300")
        );
        if !all_posting {
            assert_eq!(portfolio.uncovered_accounts[0].code, "1200");
        }
        let cash = portfolio
            .accounts
            .iter()
            .find(|a| a.account.code == "1000")
            .unwrap();
        assert_eq!(
            cash.rows[0].posted_net, 1234,
            "later backdated activity cannot change the saved source"
        );
        let bundle_path = fixture.dir.join(if all_posting {
            "all.fab"
        } else {
            "selected.fab"
        });
        let receipt_path = fixture.dir.join(if all_posting {
            "all.receipt"
        } else {
            "selected.receipt"
        });
        std::fs::write(&bundle_path, &bundle).unwrap();
        std::fs::write(&receipt_path, &receipt).unwrap();
        let args = [
            "report",
            bundle_path.to_str().unwrap(),
            "--key",
            text(&signed, "checkpoint_public_key"),
            "--receipt",
            receipt_path.to_str().unwrap(),
            "--expect",
            &pin,
            "--json",
        ]
        .map(str::to_string);
        let output = fa_verify::cli::run(&args, &|path| std::fs::read(path));
        assert_eq!(output.exit, 0, "{}{}", output.stdout, output.stderr);
        assert!(
            output
                .stdout
                .contains("\"report_mode\":\"aging_portfolio\"")
        );
        assert!(output.stdout.contains("aging_portfolio_selected_account"));
        assert_eq!(
            output.stdout.contains("aging_portfolio_uncovered_account"),
            !all_posting
        );
        let mut wrong_pin = args;
        wrong_pin[7] = fa_verify::blake3::hex(&certificate.aging_source().source().digest);
        let refused = fa_verify::cli::run(&wrong_pin, &|path| std::fs::read(path));
        assert_eq!(refused.exit, 8, "{}{}", refused.stdout, refused.stderr);
        assert!(!refused.stdout.contains("\"verdict\":\"verified\""));
    }
    assert_eq!(
        fixture.head(),
        before,
        "portable export does not change the accounting book"
    );
}
