//! Historical OpenItems certificates cross the real MCP stdio transport and
//! are recomputed by the independent verifier using only inline export bytes.

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
fn retained_open_items_export_by_oid_and_hex_verify_independently_over_stdio() {
    let dir = tmp("open-items-bundle");
    let book = dir.join("book");
    let b = book.display().to_string();
    cli_data(&[
        "book",
        "create",
        "--book",
        &b,
        "--name",
        "Open items MCP",
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
        r#"{"idempotency_key":"open-items-mcp","effective_date":"2026-03-10","legs":[{"side":"debit","account":"1000","amount":"12.34 USD"},{"side":"credit","account":"4000","amount":"12.34 USD"}]}"#,
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
        "fa_read_open_items",
        json!({"account": "1000", "certify": true}),
    );
    assert!(!error, "{output}");
    let certified: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
    assert_eq!(certified.as_array().unwrap().len(), 2);
    assert_eq!(certified[0]["account"], json!("1000"));
    assert_eq!(certified[0]["items"].as_array().unwrap().len(), 1);
    assert_eq!(certified[1]["output_format"], json!("fa:open-items:v1"));
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(
        envelope["events"],
        json!(["open_items", "report_certificate"])
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

    // The export checkpoint includes a reversal recorded after certification.
    // It cannot erase the item from the older certificate's report.
    cli_data(&[
        "reverse",
        posted["vid"].as_str().unwrap(),
        "--reason",
        "WrongAccount",
        "--book",
        &b,
        "--json",
    ]);
    let current: JsonValue = fastmcp_rust::serde_json::from_str(&cli_data(&[
        "open-items",
        "--account",
        "1000",
        "--book",
        &b,
        "--json",
    ]))
    .unwrap();
    assert_eq!(current["items"], json!([]));
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
            .expect("independent historical OpenItems verification of MCP export");
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
        let report = verified.open_items.as_ref().expect("open-items result");
        assert_eq!(report.items.len(), 1, "the account filter excludes revenue");
        assert_eq!(report.items[0].open, 1234);
        assert!(verified.receipt.is_some());
        if let Some(expected) = &original_bundle {
            assert_eq!(
                &bundle, expected,
                "oid and hex retain identical report inputs"
            );
        } else {
            original_bundle = Some(bundle);
        }
    }
    assert_eq!(producer.finish(), 0);
    assert_eq!(
        cli_data(&["book", "info", "--book", &b, "--json"]),
        before,
        "MCP report exports do not publish or advance the book",
    );
}
