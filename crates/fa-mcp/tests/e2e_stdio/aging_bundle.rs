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

#[test]
fn retained_due_date_workpapers_and_reconciliation_bind_requests_over_stdio() {
    let dir = tmp("due-date-workpapers");
    let book = dir.join("book");
    let b = book.display().to_string();
    cli_data(&[
        "book",
        "create",
        "--book",
        &b,
        "--name",
        "Due-date MCP",
        "--json",
    ]);
    let chart = dir.join("chart.json");
    std::fs::write(
        &chart,
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1100","name":"Receivables","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
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
    let post = |key: &str, mut intent: JsonValue| -> JsonValue {
        intent["idempotency_key"] = json!(key);
        let path = dir.join(format!("{key}.json"));
        std::fs::write(&path, intent.to_string()).unwrap();
        fastmcp_rust::serde_json::from_str(&cli_data(&[
            "post",
            "--intent",
            path.to_str().unwrap(),
            "--evidence",
            &evidence,
            "--book",
            &b,
            "--json",
        ]))
        .unwrap()
    };
    let invoice = post(
        "installment-invoice",
        json!({
            "effective_date": "2026-03-01",
            "legs": [
                {"side": "debit", "account": "1100", "amount": "100.00 USD"},
                {"side": "credit", "account": "4000", "amount": "100.00 USD"}
            ],
            "obligation_maturity": [{
                "ordinal": 0, "status": "contractual",
                "installments": [
                    {"due_date": "2026-03-31", "amount": "60.00 USD"},
                    {"due_date": "2026-04-30", "amount": "40.00 USD"}
                ]
            }]
        }),
    );
    post(
        "installment-receipt",
        json!({
            "effective_date": "2026-03-20",
            "legs": [
                {"side": "debit", "account": "1000", "amount": "25.00 USD"},
                {"side": "credit", "account": "1100", "amount": "25.00 USD",
                 "settles": [{"entry": invoice["vid"], "ordinal": 0, "amount": "25.00 USD"}]}
            ]
        }),
    );
    post(
        "unscheduled-invoice",
        json!({
            "effective_date": "2026-03-02",
            "legs": [
                {"side": "debit", "account": "1100", "amount": "10.00 USD"},
                {"side": "credit", "account": "4000", "amount": "10.00 USD"}
            ]
        }),
    );
    let known_at = head(&b);
    let grants = [
        "--cluster",
        "fa.proof",
        "--grant",
        "read",
        "--grant",
        "produce",
    ];
    let mut producer = Mcp::start_with(&book, &grants);
    producer.discover();
    let mut certificates = Vec::new();
    for (reconcile, family, output_format) in [
        (false, "due-date-aging", "fa:due-date-aging:v1"),
        (
            true,
            "due-date-aging-reconciliation",
            "fa:due-date-aging-control-reconciliation:v1",
        ),
    ] {
        // The recipient's question is retained independently of certificate
        // bytes, including the prefix before either certification's audit.
        let expected = json!({
            "kind": family, "account": "1100", "through": "2026-04-01",
            "known_at": known_at, "buckets": [0, 30]
        });
        let (error, output, _) = call_tool(
            &mut producer,
            "fa_proof_gl",
            json!({
                "view": "aging", "basis": "due-date", "reconcile": reconcile,
                "account": "1100", "as_of": "2026-04-01",
                "as_known_at": known_at.to_string(), "bucket": ["0", "30"],
                "certify": true
            }),
        );
        assert!(!error, "{output}");
        let certified: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
        assert_eq!(certified.as_array().unwrap().len(), 2, "{output}");
        assert_eq!(certified[1]["output_format"], json!(output_format));
        certificates.push((
            family,
            format!("C:{}", certified[1]["oid"].as_str().unwrap()),
            expected,
        ));
    }
    assert_eq!(producer.finish(), 0);

    // An entry recorded later but effective before the cutoff must not leak
    // into either the saved aging schedule or its GL control comparison.
    post(
        "later-backdated-invoice",
        json!({
            "effective_date": "2026-03-15",
            "legs": [
                {"side": "debit", "account": "1100", "amount": "7.00 USD"},
                {"side": "credit", "account": "4000", "amount": "7.00 USD"}
            ]
        }),
    );
    let before = head(&b);
    assert!(before > known_at);
    let mut cli_workpapers = Vec::new();
    for (family, locator, expected) in &certificates {
        let (exit, output) = cli(&[
            "replay",
            locator,
            "--expect",
            &expected.to_string(),
            "--workpaper",
            "--book",
            &b,
            "--json",
        ]);
        assert_eq!(exit, 0, "{output}");
        let events: Vec<JsonValue> = output
            .lines()
            .map(|line| fastmcp_rust::serde_json::from_str(line).unwrap())
            .collect();
        let exported = &events
            .iter()
            .find(|event| event["event"] == json!("workpaper_exported"))
            .unwrap()["data"];
        assert_eq!(exported["family"], json!(family));
        cli_workpapers.push(exported["text"].as_str().unwrap().to_string());
    }
    assert_eq!(head(&b), before, "owner CLI exports do not publish");
    assert!(
        cli_workpapers[1].starts_with(&cli_workpapers[0]),
        "the reconciliation preserves its complete aging workpaper prefix"
    );

    let mut producer = Mcp::start_with(&book, &grants);
    producer.discover();
    for ((family, locator, expected), cli_workpaper) in certificates.iter().zip(&cli_workpapers) {
        let (error, output, metadata) = call_tool(
            &mut producer,
            "fa_read_replay",
            json!({
                "certificate": locator, "expect": expected.to_string(), "workpaper": true
            }),
        );
        assert!(!error, "{output}");
        let replayed: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
        let exported = replayed
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event.get("text").is_some_and(JsonValue::is_string))
            .unwrap_or_else(|| panic!("no inline workpaper: {output}"));
        assert_eq!(exported["family"], json!(family));
        assert_eq!(exported["file"], JsonValue::Null);
        let workpaper = exported["text"].as_str().unwrap();
        assert_eq!(
            workpaper, cli_workpaper,
            "CLI and MCP export identical retained bytes"
        );
        assert_eq!(exported["bytes"], json!(workpaper.len()));
        assert_eq!(exported["lines"], json!(workpaper.lines().count()));
        let envelope: JsonValue =
            fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
                .unwrap();
        assert!(
            envelope["events"]
                .as_array()
                .unwrap()
                .contains(&json!("workpaper_exported"))
        );
        let rows: Vec<JsonValue> = workpaper
            .lines()
            .map(|line| fastmcp_rust::serde_json::from_str(line).unwrap())
            .collect();
        let rows_for = |event: &str| -> Vec<&JsonValue> {
            rows.iter()
                .filter(|row| row["event"] == json!(event))
                .collect()
        };
        assert_eq!(rows[0]["age_basis"], json!("due_date"));
        assert_eq!(rows[0]["known_at"], json!(known_at.to_string()));
        assert_eq!(rows[0]["effective_through"], json!("2026-04-01"));
        assert_eq!(rows_for("aging_open_item").len(), 2);
        assert_eq!(rows_for("aging_application").len(), 1);
        let installments = rows_for("due_date_aging_installment");
        assert_eq!(installments.len(), 2);
        for (date, amount, days) in [("2026-03-31", "3500", "1"), ("2026-04-30", "4000", "0")] {
            let row = installments
                .iter()
                .find(|row| row["due_date"] == json!(date))
                .unwrap();
            assert_eq!(row["open_mantissa"], json!(amount));
            assert_eq!(row["days_past_due"], json!(days));
        }
        let unscheduled = rows_for("due_date_aging_unscheduled");
        assert_eq!(unscheduled.len(), 1);
        assert_eq!(unscheduled[0]["reason"], json!("no_terms"));
        assert_eq!(unscheduled[0]["open_mantissa"], json!("1000"));
        assert!(unscheduled[0].get("due_date").is_none());
        assert_eq!(
            rows_for("due_date_aging_total")[0]["debit_mantissa"],
            json!("7500")
        );
        assert_eq!(
            rows_for("due_date_aging_unscheduled_total")[0]["debit_mantissa"],
            json!("1000")
        );
        if *family == "due-date-aging-reconciliation" {
            let control = rows_for("aging_control_row");
            assert_eq!(control.len(), 1);
            for (key, value) in [
                ("posted_debits", "11000"),
                ("posted_credits", "2500"),
                ("pending_debits", "0"),
                ("pending_credits", "0"),
                ("open_debits", "8500"),
                ("open_credits", "0"),
                ("open_item_count", "2"),
                ("posted_net", "8500"),
                ("open_net", "8500"),
                ("difference", "0"),
            ] {
                assert_eq!(control[0][key], json!(value));
            }
            let footer = rows_for("aging_control_reconciliation");
            assert_eq!(footer.len(), 1);
            assert_eq!(
                footer[0]["format"],
                json!("fa:due-date-aging-reconciliation-workpaper:v1")
            );
            assert_eq!(footer[0]["account"], rows[0]["account_filter"]);
            assert_eq!(footer[0]["known_at"], json!(known_at.to_string()));
            assert_eq!(footer[0]["reconciled"], json!(true));
            assert_eq!(
                footer[0]["certificate_digest"],
                json!(locator.strip_prefix("C:").unwrap())
            );
        }

        for (field, wrong) in [
            ("account", json!("1000")),
            ("through", json!("2026-04-02")),
            ("buckets", json!([0, 60])),
            ("known_at", json!(known_at - 1)),
        ] {
            let mut mismatch = expected.clone();
            mismatch[field] = wrong;
            let (error, output, metadata) = call_tool(
                &mut producer,
                "fa_read_replay",
                json!({
                    "certificate": locator, "expect": mismatch.to_string(), "workpaper": true
                }),
            );
            assert!(
                error,
                "{family} must bind independently supplied {field}: {output}"
            );
            let refused = structured_error(&output);
            assert_eq!(refused["exit"], json!(8), "{output}");
            assert_eq!(refused["refusal_id"], json!("FA-REF-150"), "{output}");
            assert_eq!(metadata["content"].as_array().unwrap().len(), 1);
            assert!(
                !output.contains("open_mantissa"),
                "a refusal cannot expose workpaper rows"
            );
        }
    }
    assert_eq!(producer.finish(), 0);
    assert_eq!(
        access_receipts_since(&b, before, "mcp-agent"),
        vec!["replay"; 10],
        "two exports and eight admitted mismatches publish only their access receipts",
    );

    let before_denials = head(&b);
    let mut reader = Mcp::start_with(&book, &["--grant", "read"]);
    reader.discover();
    for (family, locator, expected) in &certificates {
        let (error, output, metadata) = call_tool(
            &mut reader,
            "fa_read_replay",
            json!({
                "certificate": locator, "expect": expected.to_string(), "workpaper": true
            }),
        );
        assert!(error, "{family} workpapers require Produce: {output}");
        assert_eq!(structured_error(&output)["exit"], json!(7), "{output}");
        assert_eq!(metadata["content"].as_array().unwrap().len(), 1);
        assert!(!output.contains("open_mantissa"));
    }
    assert_eq!(reader.finish(), 0);
    assert_eq!(
        head(&b),
        before_denials,
        "missing Produce is refused before history is observed or an audit is published"
    );
}
