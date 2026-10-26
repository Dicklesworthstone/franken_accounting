//! A complete lead schedule survives retained and inline MCP transport.

use super::*;

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn post(dir: &Path, book: &str, evidence: &str, key: &str, day: &str, amount: &str) -> JsonValue {
    let intent = dir.join(format!("{key}.json"));
    std::fs::write(
        &intent,
        format!(
            r#"{{"idempotency_key":"{key}","effective_date":"{day}","legs":[{{"side":"debit","account":"1000","amount":"{amount} USD"}},{{"side":"credit","account":"4000","amount":"{amount} USD"}}]}}"#
        ),
    )
    .unwrap();
    fastmcp_rust::serde_json::from_str(&cli_data(&[
        "post",
        "--intent",
        intent.to_str().unwrap(),
        "--evidence",
        evidence,
        "--book",
        book,
        "--json",
    ]))
    .unwrap()
}

#[test]
fn retained_roll_forward_exports_every_movement_and_recomputes_over_stdio() {
    let dir = tmp("roll-forward-bundle");
    let book = dir.join("book");
    let b = book.display().to_string();
    cli_data(&[
        "book", "create", "--book", &b, "--name", "Lead MCP", "--json",
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
    post(&dir, &b, &evidence, "lead-opening", "2026-03-05", "10.00");
    let offset = post(&dir, &b, &evidence, "lead-offset", "2026-03-10", "12.34");
    post(&dir, &b, &evidence, "lead-activity", "2026-03-20", "7.66");
    cli_data(&[
        "reverse",
        offset["vid"].as_str().unwrap(),
        "--reason",
        "WrongAccount",
        "--book",
        &b,
        "--json",
    ]);
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
            "view": "roll-forward",
            "account": "1000",
            "unit": "USD",
            "from": "2026-03-10",
            "to": "2026-03-31",
            "label": "MCP cash lead",
            "certify": true
        }),
    );
    assert!(!error, "{output}");
    let certified: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
    assert_eq!(certified.as_array().unwrap().len(), 2);
    let certificate =
        fa::RollForwardCertificate::decode(&decode_hex(certified[1]["bytes"].as_str().unwrap()))
            .unwrap();
    let expected = fa_verify::blake3::hex(certificate.digest());
    assert_eq!(expected, certified[1]["oid"].as_str().unwrap());
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(
        envelope["events"],
        json!(["roll_forward", "report_certificate"])
    );
    assert_eq!(envelope["authority"]["profile"], json!("agent"));
    assert_eq!(producer.finish(), 0);

    // The delivered old schedule must retain its original prefix after drift.
    post(&dir, &b, &evidence, "lead-later", "2026-03-15", "99.00");
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
        assert!(
            produced["verify"]
                .as_str()
                .unwrap()
                .contains(&format!("--expect {expected}"))
        );
        let envelope: JsonValue =
            fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(envelope["events"], json!(["bundle_produced"]));
        let bundle = decode_hex(produced["bytes"].as_str().unwrap());
        let receipt = decode_hex(produced["receipt"].as_str().unwrap());
        let key: [u8; 32] = decode_hex(produced["checkpoint_public_key"].as_str().unwrap())
            .try_into()
            .unwrap();
        let verified = fa_verify::report::verify_report_expected(
            &bundle,
            &[key],
            None,
            Some(&receipt),
            Some(certificate.digest()),
        )
        .expect("independent verification of the retained lead schedule over MCP");
        assert_eq!(verified.certificate_digest, *certificate.digest());
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.known_at, certificate.known_at().0);
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
        assert!(verified.receipt.is_some());
        assert!(verified.rows.is_empty());
        let lead = verified.roll_forward.unwrap();
        assert_eq!(lead.label, "MCP cash lead");
        assert_eq!(lead.rows.len(), 1);
        assert_eq!(lead.rows[0].opening, 1000);
        assert_eq!(lead.rows[0].net_change, 766);
        assert_eq!(lead.rows[0].closing, 1766);
        assert_eq!(
            lead.movements.len(),
            3,
            "the offsetting pair must remain disclosed"
        );
        assert!(
            lead.movements
                .iter()
                .any(|m| m.debits == 1234 && m.credits == 0)
        );
        assert!(
            lead.movements
                .iter()
                .any(|m| m.debits == 0 && m.credits == 1234)
        );
        assert!(
            fa_verify::report::verify_report_expected(
                &bundle,
                &[key],
                None,
                None,
                Some(&certificate.source_certificate().digest),
            )
            .is_err(),
            "a nested closing-balance pin cannot authenticate the movement question"
        );
        if let Some(expected) = &original_bundle {
            assert_eq!(
                &bundle, expected,
                "OID and inline inputs preserve the whole artifact"
            );
        } else {
            original_bundle = Some(bundle);
        }
    }
    assert_eq!(producer.finish(), 0);
    assert_eq!(
        cli_data(&["book", "info", "--book", &b, "--json"]),
        before,
        "lead-schedule bundle export does not advance the book",
    );
}
