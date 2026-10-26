//! A composed aging artifact stays recipient-bound over the real MCP transport.

use super::*;

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn retained_effective_date_aging_exports_and_recomputes_independently_over_stdio() {
    let dir = tmp("aging-bundle");
    let book = dir.join("book");
    let b = book.display().to_string();
    cli_data(&[
        "book",
        "create",
        "--book",
        &b,
        "--name",
        "Aging MCP",
        "--json",
    ]);
    let chart = dir.join("chart.json");
    std::fs::write(
        &chart,
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    )
    .unwrap();
    cli_data(&[
        "chart",
        "import",
        chart.to_str().unwrap(),
        "--book",
        &b,
        "--json",
    ]);
    cli_data(&[
        "period",
        "create",
        "--fiscal-year",
        "2026",
        "--book",
        &b,
        "--json",
    ]);
    cli_data(&["period", "open", "FY2026-P03", "--book", &b, "--json"]);
    let evidence = source_document(&dir, &b);
    let intent = dir.join("invoice.json");
    std::fs::write(
        &intent,
        r#"{"idempotency_key":"aging-mcp","effective_date":"2026-03-10","legs":[{"side":"debit","account":"1000","amount":"12.34 USD"},{"side":"credit","account":"4000","amount":"12.34 USD"}]}"#,
    )
    .unwrap();
    let posted: JsonValue = fastmcp_rust::serde_json::from_str(&cli_data(&[
        "post",
        "--intent",
        intent.to_str().unwrap(),
        "--evidence",
        &evidence,
        "--book",
        &b,
        "--json",
    ]))
    .unwrap();
    let grants = [
        "--cluster",
        "fa.proof",
        "--cluster",
        "fa.notary",
        "--grant",
        "read",
        "--grant",
        "produce",
    ];
    let mut producer = Mcp::start_with(&book, &grants);
    producer.discover();
    let (error, output, metadata) = call_tool(
        &mut producer,
        "fa_proof_gl",
        json!({
            "view": "aging",
            "account": "1000",
            "as_of": "2026-03-31",
            "bucket": ["0", "30"],
            "certify": true
        }),
    );
    assert!(!error, "{output}");
    let certified: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
    assert_eq!(certified.as_array().unwrap().len(), 2);
    assert_eq!(
        certified[1]["output_format"],
        json!("fa:effective-date-aging:v1")
    );
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(envelope["events"], json!(["aging", "report_certificate"]));
    assert_eq!(envelope["authority"]["profile"], json!("agent"));
    let certificate =
        fa::AgingCertificate::decode(&unhex(certified[1]["bytes"].as_str().unwrap())).unwrap();
    assert_eq!(
        fa_verify::blake3::hex(certificate.digest()),
        certified[1]["oid"].as_str().unwrap()
    );
    assert_eq!(producer.finish(), 0);

    // Reversing the live item cannot rewrite the older aging certificate.
    cli_data(&[
        "reverse",
        posted["vid"].as_str().unwrap(),
        "--reason",
        "WrongAccount",
        "--book",
        &b,
        "--json",
    ]);
    let checkpoint: JsonValue = fastmcp_rust::serde_json::from_str(&cli_data(&[
        "checkpoint",
        "create",
        "--grant",
        "witness",
        "--book",
        &b,
        "--json",
    ]))
    .unwrap();
    let before = cli_data(&["book", "info", "--book", &b, "--json"]);
    let mut producer = Mcp::start_with(&book, &grants);
    producer.discover();
    let mut original_bundle = None;
    for input in [
        format!("C:{}", certified[1]["oid"].as_str().unwrap()),
        certified[1]["bytes"].as_str().unwrap().to_string(),
    ] {
        let (error, output, metadata) = call_tool(
            &mut producer,
            "fa_notary_bundle",
            json!({"certificate": input, "state": checkpoint["oid"]}),
        );
        assert!(!error, "{output}");
        let produced: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
        assert_eq!(produced["scope"], json!("report"));
        assert!(produced["verify"].as_str().unwrap().contains(&format!(
            "--expect {}",
            fa_verify::blake3::hex(certificate.digest())
        )));
        let envelope: JsonValue =
            fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(envelope["events"], json!(["bundle_produced"]));
        let bundle = unhex(produced["bytes"].as_str().unwrap());
        let receipt = unhex(produced["receipt"].as_str().unwrap());
        let key: [u8; 32] = unhex(produced["checkpoint_public_key"].as_str().unwrap())
            .try_into()
            .unwrap();
        let verified = fa_verify::report::verify_report_expected(
            &bundle,
            &[key],
            None,
            Some(&receipt),
            Some(certificate.digest()),
        )
        .expect("independent verification of historical aging received over MCP");
        assert_eq!(verified.certificate_digest, *certificate.digest());
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.known_at, certificate.source().known_at.0);
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
        assert!(verified.rows.is_empty());
        assert!(verified.statement.is_none());
        assert!(verified.open_items.is_none());
        assert!(verified.receipt.is_some());
        let aging = verified.aging.unwrap();
        assert_eq!(aging.items.len(), 1);
        assert_eq!(aging.items[0].item.open, 1234);
        assert_eq!(aging.items[0].age_days, 21);
        assert_eq!(aging.items[0].bucket, 1);
        assert_eq!(aging.bands.len(), 3);
        assert_eq!(aging.source_certificate_digest, certificate.source().digest);
        assert!(
            fa_verify::report::verify_report_expected(
                &bundle,
                &[key],
                None,
                None,
                Some(&certificate.source().digest),
            )
            .is_err(),
            "the source OpenItems digest does not pin the aging question"
        );
        if let Some(expected) = &original_bundle {
            assert_eq!(
                &bundle, expected,
                "oid and inline bytes preserve the artifact"
            );
        } else {
            original_bundle = Some(bundle);
        }
    }
    assert_eq!(producer.finish(), 0);
    assert_eq!(
        cli_data(&["book", "info", "--book", &b, "--json"]),
        before,
        "MCP aging exports do not publish or advance the book",
    );
}

#[test]
fn reconciliation_bundle_binds_an_independent_request_and_both_sources_over_stdio() {
    let dir = tmp("aging-reconciliation-bundle");
    let book = dir.join("book");
    let b = book.display().to_string();
    cli_data(&[
        "book",
        "create",
        "--book",
        &b,
        "--name",
        "Reconciliation MCP",
        "--json",
    ]);
    let chart = dir.join("chart.json");
    std::fs::write(
        &chart,
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    )
    .unwrap();
    cli_data(&[
        "chart",
        "import",
        chart.to_str().unwrap(),
        "--book",
        &b,
        "--json",
    ]);
    cli_data(&[
        "period",
        "create",
        "--fiscal-year",
        "2026",
        "--book",
        &b,
        "--json",
    ]);
    cli_data(&["period", "open", "FY2026-P03", "--book", &b, "--json"]);
    let evidence = source_document(&dir, &b);
    let intent = dir.join("invoice.json");
    std::fs::write(
        &intent,
        r#"{"idempotency_key":"reconciliation-mcp","effective_date":"2026-03-10","legs":[{"side":"debit","account":"1000","amount":"12.34 USD"},{"side":"credit","account":"4000","amount":"12.34 USD"}]}"#,
    )
    .unwrap();
    let posted: JsonValue = fastmcp_rust::serde_json::from_str(&cli_data(&[
        "post",
        "--intent",
        intent.to_str().unwrap(),
        "--evidence",
        &evidence,
        "--book",
        &b,
        "--json",
    ]))
    .unwrap();
    let known_at = posted["recorded_at"].as_u64().unwrap();
    let expected = json!({
        "kind": "aging-reconciliation",
        "account": "1000",
        "through": "2026-03-31",
        "known_at": known_at,
        "buckets": [0, 30]
    })
    .to_string();
    let grants = [
        "--cluster",
        "fa.proof",
        "--cluster",
        "fa.notary",
        "--grant",
        "read",
        "--grant",
        "produce",
    ];
    let mut producer = Mcp::start_with(&book, &grants);
    producer.discover();
    let (error, output, metadata) = call_tool(
        &mut producer,
        "fa_proof_gl",
        json!({
            "view": "aging",
            "reconcile": true,
            "account": "1000",
            "as_of": "2026-03-31",
            "as_known_at": known_at.to_string(),
            "bucket": ["0", "30"],
            "certify": true
        }),
    );
    assert!(!error, "{output}");
    let certified: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
    assert_eq!(certified.as_array().unwrap().len(), 2);
    assert_eq!(
        certified[1]["output_format"],
        json!("fa:aging-control-reconciliation:v1")
    );
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(
        envelope["events"],
        json!(["aging_reconciled", "report_certificate"])
    );
    assert_eq!(envelope["authority"]["profile"], json!("agent"));
    let certificate =
        fa::AgingReconciliationCertificate::decode(&unhex(certified[1]["bytes"].as_str().unwrap()))
            .unwrap();
    assert_eq!(
        fa_verify::blake3::hex(certificate.digest()),
        certified[1]["oid"].as_str().unwrap()
    );
    assert_eq!(producer.finish(), 0);

    // Keep the independently chosen question while the live book advances.
    cli_data(&[
        "reverse",
        posted["vid"].as_str().unwrap(),
        "--reason",
        "WrongAccount",
        "--book",
        &b,
        "--json",
    ]);
    let checkpoint: JsonValue = fastmcp_rust::serde_json::from_str(&cli_data(&[
        "checkpoint",
        "create",
        "--grant",
        "witness",
        "--book",
        &b,
        "--json",
    ]))
    .unwrap();
    let before = cli_data(&["book", "info", "--book", &b, "--json"]);
    let mut producer = Mcp::start_with(&book, &grants);
    producer.discover();
    let locator = format!("C:{}", certified[1]["oid"].as_str().unwrap());
    let (error, output, _) = call_tool(
        &mut producer,
        "fa_notary_bundle",
        json!({"certificate": locator, "state": checkpoint["oid"]}),
    );
    assert!(
        error,
        "a delivered certificate cannot supply the request: {output}"
    );
    let (error, output, _) = call_tool(
        &mut producer,
        "fa_notary_bundle",
        json!({
            "certificate": locator,
            "state": checkpoint["oid"],
            "expect": expected.replace("2026-03-31", "2026-03-30")
        }),
    );
    assert!(
        error,
        "a different cutoff must not be exported as this request: {output}"
    );
    let mut original_bundle = None;
    for input in [locator, certified[1]["bytes"].as_str().unwrap().to_string()] {
        let (error, output, metadata) = call_tool(
            &mut producer,
            "fa_notary_bundle",
            json!({
                "certificate": input,
                "expect": expected,
                "state": checkpoint["oid"]
            }),
        );
        assert!(!error, "{output}");
        let produced: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
        assert_eq!(produced["scope"], json!("report"));
        assert!(produced["verify"].as_str().unwrap().contains(&format!(
            "--expect {}",
            fa_verify::blake3::hex(certificate.digest())
        )));
        let envelope: JsonValue =
            fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(envelope["events"], json!(["bundle_produced"]));
        let bundle = unhex(produced["bytes"].as_str().unwrap());
        let receipt = unhex(produced["receipt"].as_str().unwrap());
        let key: [u8; 32] = unhex(produced["checkpoint_public_key"].as_str().unwrap())
            .try_into()
            .unwrap();
        let verified = fa_verify::report::verify_report_expected(
            &bundle,
            &[key],
            None,
            Some(&receipt),
            Some(certificate.digest()),
        )
        .expect("both historical reconciliation sources independently verify over MCP");
        assert_eq!(verified.certificate_digest, *certificate.digest());
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.known_at, known_at);
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
        let reconciliation = verified.aging_reconciliation.unwrap();
        assert!(reconciliation.is_reconciled());
        assert_eq!(reconciliation.rows.len(), 1);
        assert_eq!(reconciliation.rows[0].posted_net, 1234);
        assert_eq!(reconciliation.rows[0].open_net, 1234);
        assert_eq!(reconciliation.rows[0].difference, 0);
        assert_eq!(reconciliation.aging.items.len(), 1);
        assert_eq!(reconciliation.control_rows.len(), 1);
        for wrong_pin in [
            certificate.aging_source().digest(),
            &certificate.control_source().digest,
        ] {
            assert!(
                fa_verify::report::verify_report_expected(
                    &bundle,
                    &[key],
                    None,
                    None,
                    Some(wrong_pin),
                )
                .is_err()
            );
        }
        if let Some(original) = &original_bundle {
            assert_eq!(&bundle, original);
        } else {
            original_bundle = Some(bundle);
        }
    }
    assert_eq!(producer.finish(), 0);
    assert_eq!(
        cli_data(&["book", "info", "--book", &b, "--json"]),
        before,
        "successful and refused reconciliation exports never publish",
    );
}
