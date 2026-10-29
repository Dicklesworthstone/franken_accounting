//! Certified balance explanations cross MCP stdio with retained reasons and
//! independently reconstruct their original cells, lineage and recorded history.

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
fn retained_explanations_export_by_oid_and_hex_replay_history_and_reasons_over_stdio() {
    let dir = tmp("explanation-bundle");
    let book = dir.join("book");
    let b = book.display().to_string();
    cli_data(&[
        "book",
        "create",
        "--book",
        &b,
        "--name",
        "Balance explanation MCP",
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
    let intent = dir.join("original.json");
    std::fs::write(
        &intent,
        r#"{"idempotency_key":"explanation-mcp-original","effective_date":"2026-03-10","legs":[{"side":"debit","account":"1000","amount":"12.34 USD"},{"side":"credit","account":"4000","amount":"12.34 USD"}]}"#,
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
    let reversed: JsonValue = fastmcp_rust::serde_json::from_str(&cli_data(&[
        "reverse",
        posted["vid"].as_str().unwrap(),
        "--reason",
        "WrongAccount",
        "--book",
        &b,
        "--json",
    ]))
    .unwrap();
    let grants = [
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
        "fa_read_explain_balance",
        json!({"account": "1000", "period": "FY2026-P03", "certify": true}),
    );
    assert!(!error, "{output}");
    let certified: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
    assert_eq!(certified.as_array().unwrap().len(), 2);
    assert_eq!(certified[0]["account"], json!("1000"));
    assert_eq!(certified[0]["cells"][0]["net"], json!("0.00 USD"));
    assert_eq!(certified[0]["contributions"].as_array().unwrap().len(), 2);
    assert_eq!(
        certified[1]["output_format"],
        json!("fa:balance-explanation:v1")
    );
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(
        envelope["events"],
        json!(["balance_explained", "report_certificate"])
    );
    assert_eq!(envelope["authority"]["profile"], json!("agent"));
    let known_at = certified[1]["known_at"].as_u64().unwrap();
    let certificate_digest: [u8; 32] = unhex(certified[1]["oid"].as_str().unwrap())
        .try_into()
        .unwrap();
    let output_digest: [u8; 32] = unhex(certified[1]["output_digest"].as_str().unwrap())
        .try_into()
        .unwrap();
    assert_eq!(producer.finish(), 0);

    // A later backdated posting changes today's balance. The older certificate
    // and every point in its history must still reproduce the original report.
    let later = dir.join("later.json");
    std::fs::write(
        &later,
        r#"{"idempotency_key":"explanation-mcp-later","effective_date":"2026-03-05","legs":[{"side":"debit","account":"1000","amount":"2.00 USD"},{"side":"credit","account":"4000","amount":"2.00 USD"}]}"#,
    )
    .unwrap();
    cli_data(&[
        "post",
        "--intent",
        later.to_str().unwrap(),
        "--evidence",
        &evidence,
        "--book",
        &b,
        "--json",
    ]);
    let current: JsonValue = fastmcp_rust::serde_json::from_str(&cli_data(&[
        "explain",
        "balance",
        "1000",
        "--period",
        "FY2026-P03",
        "--book",
        &b,
        "--json",
    ]))
    .unwrap();
    assert_eq!(current["cells"][0]["net"], json!("2.00 USD"));
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
    for certificate in [
        format!("C:{}", certified[1]["oid"].as_str().unwrap()),
        certified[1]["bytes"].as_str().unwrap().to_string(),
    ] {
        let (error, output, metadata) = call_tool(
            &mut producer,
            "fa_notary_bundle",
            json!({"certificate": certificate, "state": checkpoint["oid"]}),
        );
        assert!(!error, "{output}");
        let produced: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
        assert_eq!(produced["scope"], json!("report"));
        let envelope: JsonValue =
            fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(envelope["events"], json!(["bundle_produced"]));
        let bundle = unhex(produced["bytes"].as_str().unwrap());
        let receipt = unhex(produced["receipt"].as_str().unwrap());
        let key: [u8; 32] = unhex(produced["checkpoint_public_key"].as_str().unwrap())
            .try_into()
            .unwrap();
        let verified = fa_verify::report::verify_report(&bundle, &[key], None, Some(&receipt))
            .expect("independent historical explanation verification of MCP export");
        assert_eq!(verified.certificate_digest, certificate_digest);
        assert_eq!(verified.output_digest, output_digest);
        assert_eq!(
            fa_verify::blake3::hash_parts(b"fa:report-output:v1", &[&verified.output]),
            output_digest,
        );
        assert_eq!(verified.known_at, known_at);
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
        assert!(verified.rows.is_empty());
        assert!(verified.statement.is_none());
        assert!(verified.open_items.is_none());
        let explanation = verified.explanation.as_ref().expect("balance explanation");
        assert_eq!(explanation.account_row.code, "1000");
        assert_eq!(explanation.cells.len(), 1);
        assert_eq!(explanation.cells[0].debits, 1234);
        assert_eq!(explanation.cells[0].credits, 1234);
        assert_eq!(explanation.cells[0].entry_count, 2);
        assert!(explanation.pending.is_empty());
        assert_eq!(explanation.contributions.len(), 2);
        assert_eq!(explanation.history.len(), 2);
        assert_eq!(
            explanation.last_changed_at(),
            reversed["recorded_at"].as_u64()
        );
        let reversal = explanation
            .contributions
            .iter()
            .find(|row| !row.supersedes.is_empty())
            .expect("committed reversal lineage");
        assert_eq!(reversal.supersedes[0].reason_code, 2);
        assert_eq!(explanation.supersession_reasons[&2].name, "WrongAccount");
        assert_eq!(
            reversal.supersedes[0].target,
            u128::from_str_radix(posted["vid"].as_str().unwrap(), 16).unwrap(),
        );
        let original = explanation
            .contributions
            .iter()
            .find(|row| {
                row.entry == u128::from_str_radix(posted["vid"].as_str().unwrap(), 16).unwrap()
            })
            .expect("the authenticated original supplies the reversal's why");
        assert_eq!(original.evidence.len(), 1);
        assert_eq!(
            original.evidence[0].document_oid.as_slice(),
            unhex(&evidence)
        );
        assert_eq!(reversal.supersedes.len(), 1);
        assert_eq!(reversal.supersedes[0].entry_digest, original.entry_digest);
        assert_eq!(
            reversal.supersedes[0].kind, 1,
            "Reverses, not a new assertion"
        );
        assert!(
            reversal.evidence.is_empty(),
            "the registered target minimum needs no duplicate document"
        );
        assert_eq!(reversal.mantissa, original.mantissa);
        assert_ne!(reversal.debit, original.debit);
        assert!(verified.receipt.is_some());
        assert!(
            fa_verify::report::verify_report_expected(
                &bundle,
                &[key],
                None,
                Some(&receipt),
                Some(&[0; 32]),
            )
            .is_err(),
            "a transport result cannot override an independently pinned certificate",
        );
        if let Some(expected) = &original_bundle {
            assert_eq!(
                &bundle, expected,
                "OID and hex retain identical report inputs"
            );
        } else {
            original_bundle = Some(bundle);
        }
    }
    assert_eq!(producer.finish(), 0);
    assert_eq!(
        cli_data(&["book", "info", "--book", &b, "--json"]),
        before,
        "MCP explanation exports do not publish or advance the book",
    );
}
