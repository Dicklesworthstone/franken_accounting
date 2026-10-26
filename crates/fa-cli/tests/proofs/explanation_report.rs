//! A retained explanation passes through the real CLI producer and the
//! independent verifier using only exported files and recipient anchors.

use super::*;

fn certify(f: &Fixture, known_at: u64) -> (String, fa::ReportCertificate, Json) {
    let at = known_at.to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&f.book)
        .args([
            "explain",
            "balance",
            "1000",
            "--period",
            "FY2026-P03",
            "--as-known-at",
            &at,
            "--certify",
            "--json",
        ])
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .env_remove("FA_KEYS")
        .output()
        .expect("certify retained balance explanation");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let registry = fa_cli::verbs::registry().unwrap();
    let events = stdout
        .lines()
        .map(|line| {
            registry.check_line(line).unwrap();
            json::parse(line).unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 2, "{stdout}");
    assert_eq!(text(&events[0], "event"), "balance_explained");
    assert_eq!(text(&events[1], "event"), "report_certificate");
    let certificate = fa::ReportCertificate::decode(&bytes(&events[1])).unwrap();
    assert_eq!(certificate.known_at.0, known_at);
    assert_eq!(certificate.output_format(), "fa:balance-explanation:v1");
    assert!(matches!(
        &certificate.selection,
        fa::ReportSelection::ExplainBalance { account, period }
            if *account == account_vid(BOOK_ID, "1000") && period == "FY2026-P03"
    ));
    (
        format!("C:{}", text(&events[1], "oid")),
        certificate,
        events[0].clone(),
    )
}

#[test]
fn explanation_cli_exports_historical_contributions_reason_meanings_and_committed_evidence() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    let original = f.post("explanation-original", "2026-03-10", "12.34", &evidence);
    let historical = certify(&f, f.head());
    ok(
        &f.book,
        &[
            "reverse",
            text(&original, "vid"),
            "--reason",
            "WrongAccount",
        ],
    );
    f.post(
        "explanation-later-backdated",
        "2026-03-01",
        "2.00",
        &evidence,
    );
    let current = certify(&f, f.head());
    let state = f.checkpoint();
    let signed = exported(
        &f.book,
        &["signed-checkpoint", "--state", text(&state, "oid")],
    );
    let checkpoint_path = f.dir.join("explanation.checkpoint");
    std::fs::write(&checkpoint_path, bytes(&signed)).unwrap();
    let trusted_key_hex = text(&signed, "checkpoint_public_key");
    let key: [u8; 32] = unhex(trusted_key_hex).try_into().unwrap();
    let anchor = fa_verify::verify_checkpoint(&bytes(&signed), &[key]).unwrap();
    let before = f.head();

    for (name, (locator, certificate, native), has_reversal, expected_contributions) in [
        ("historical", historical, false, 1),
        ("current", current, true, 3),
    ] {
        let Json::Arr(contributions) = get(&native, "contributions") else {
            panic!("native explanation contribution list");
        };
        assert_eq!(contributions.len(), expected_contributions);
        let Json::Arr(evidence_heads) = get(&contributions[0], "evidence") else {
            panic!("native committed evidence references");
        };
        assert_eq!(evidence_heads.len(), 1);
        let document_oid = text(&evidence_heads[0], "document_oid");
        let doc_commit = text(&evidence_heads[0], "doc_commit");
        let bundle_path = f.dir.join(format!("{name}-explanation.fab"));
        let receipt_path = f.dir.join(format!("{name}-explanation.receipt"));
        let produced = ok(
            &f.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                &locator,
                "--state",
                text(&state, "oid"),
                "--out",
                bundle_path.to_str().unwrap(),
                "--receipt-out",
                receipt_path.to_str().unwrap(),
            ],
        );
        assert_eq!(text(&produced, "scope"), "report");
        assert_eq!(get(&produced, "bytes"), &Json::Null);
        let expected = fa_verify::blake3::hex(&certificate.digest);
        assert!(text(&produced, "verify").contains(&format!("--expect {expected}")));
        let bundle = std::fs::read(&bundle_path).unwrap();
        let receipt = std::fs::read(&receipt_path).unwrap();
        let verified = fa_verify::report::verify_report_expected(
            &bundle,
            &[key],
            Some(&anchor.checkpoint),
            Some(&receipt),
            Some(&certificate.digest),
        )
        .expect("offline recomputation of the CLI's retained native explanation");
        assert_eq!(verified.output, certificate.output);
        assert_eq!(verified.known_at, certificate.known_at.0);
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
        assert!(verified.explanation.is_some());
        assert!(verified.rows.is_empty() && verified.statement.is_none());
        assert!(verified.checked_records as u64 >= certificate.journal_leaves);
        if !has_reversal {
            assert!(verified.checked_records as u64 > certificate.journal_leaves);
        }

        let args = [
            "report",
            bundle_path.to_str().unwrap(),
            "--key",
            trusted_key_hex,
            "--checkpoint",
            checkpoint_path.to_str().unwrap(),
            "--receipt",
            receipt_path.to_str().unwrap(),
            "--expect",
            &expected,
            "--json",
        ]
        .map(str::to_string);
        let offline = fa_verify::cli::run(&args, &|path| std::fs::read(path));
        assert_eq!(offline.exit, 0, "{}{}", offline.stdout, offline.stderr);
        assert!(offline.stdout.contains("\"verdict\":\"verified\""));
        for check in [
            "balance_explanation",
            "balance_explanation_fold",
            "balance_explanation_account",
            "balance_explanation_cell",
            "balance_contribution",
            "balance_history",
            "balance_contribution_evidence",
            "production_receipt",
        ] {
            assert!(
                offline.stdout.contains(&format!("\"check\":\"{check}\"")),
                "{check}: {}",
                offline.stdout
            );
        }
        assert!(offline.stdout.contains(&format!(
            "\"fold_digest\":\"{}\"",
            text(&native, "fold_digest")
        )));
        assert!(
            offline
                .stdout
                .contains(&format!("\"document_oid\":\"{document_oid}\""))
        );
        assert!(
            offline
                .stdout
                .contains(&format!("\"doc_commit\":\"{doc_commit}\""))
        );
        assert!(offline.stdout.contains("\"mantissa\":\"1234\""));
        assert_eq!(
            offline
                .stdout
                .contains("\"check\":\"balance_contribution_supersession\""),
            has_reversal
        );
        if has_reversal {
            assert!(offline.stdout.contains("\"reason_code\":2"));
            assert!(offline.stdout.contains("\"reason_name\":\"WrongAccount\""));
            assert!(
                offline.stdout.contains(
                    "\"reason_meaning\":\"the original posting used an incorrect account\""
                )
            );
        }

        // Matching signed checkpoints cannot substitute another recipient
        // question; the certificate pin is verified independently of replay.
        let mut wrong_question = args.clone();
        let pin = wrong_question
            .iter()
            .position(|arg| arg == "--expect")
            .unwrap()
            + 1;
        wrong_question[pin] = "00".repeat(32);
        let refused = fa_verify::cli::run(&wrong_question, &|path| std::fs::read(path));
        assert_eq!(refused.exit, 8, "{}{}", refused.stdout, refused.stderr);
        assert!(refused.stdout.contains("recipient_certificate"));
        assert!(!refused.stdout.contains("\"verdict\":\"verified\""));

        let repeated = ok(
            &f.book,
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
            bytes(&repeated),
            bundle,
            "reopened source produces deterministic explanation bytes"
        );
    }
    assert_eq!(
        f.head(),
        before,
        "file and inline report exports append no ledger effects"
    );
}
