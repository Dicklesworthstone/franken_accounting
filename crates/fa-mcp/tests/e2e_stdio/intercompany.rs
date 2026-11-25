//! Declaration-aware reconciliation through the launch-bound MCP surface.
use super::*;

#[test]
fn intercompany_pairs_reconcile_and_certify_under_the_launch_capability() {
    let dir = tmp("intercompany");
    let book = dir.join("book");
    let b = book.display().to_string();
    cli_data(&[
        "book", "create", "--name", "Intercompany MCP",
        "--entity", "A:Alpha", "--entity", "B:Beta", "--book", &b, "--json",
    ]);
    let chart = dir.join("chart.json");
    std::fs::write(
        &chart,
        r#"{"accounts":[
            {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
            {"code":"1100","name":"Due from","type":"Asset","unit":"USD"},
            {"code":"4000","name":"Sales","type":"Revenue","unit":"USD"},
            {"code":"6000","name":"Expense","type":"Expense","unit":"USD"}
        ]}"#,
    )
    .unwrap();
    cli_data(&["chart", "import", chart.to_str().unwrap(), "--book", &b, "--json"]);
    cli_data(&["period", "create", "--fiscal-year", "2026", "--book", &b, "--json"]);
    cli_data(&["period", "open", "FY2026-P03", "--book", &b, "--json"]);
    let evidence = source_document(&dir, &b);
    let intent = dir.join("pair.json");
    std::fs::write(
        &intent,
        r#"{
            "effective_date":"2026-03-15",
            "idempotency_key":"mcp-declared-sale",
            "description":"Synthetic native intercompany sale",
            "intercompany_pairs":[
                {"pair_key":"sale-activity","left_leg":1,"right_leg":2},
                {"pair_key":"sale-balance","left_leg":0,"right_leg":3}
            ],
            "legs":[
                {"side":"debit","account":"1100","amount":"1.00 USD","entity":"A"},
                {"side":"credit","account":"4000","amount":"1.00 USD","entity":"A"},
                {"side":"debit","account":"6000","amount":"1.00 USD","entity":"B"},
                {"side":"credit","account":"1000","amount":"1.00 USD","entity":"B"}
            ]
        }"#,
    )
    .unwrap();
    cli_data(&[
        "post", "--intent", intent.to_str().unwrap(), "--evidence", &evidence,
        "--book", &b, "--json",
    ]);
    let frontier = head(&b).to_string();
    let expected = cli_data(&[
        "recon", "intercompany", "--known-at", &frontier,
        "--effective-through", "2026-03-31", "--book", &b, "--json",
    ]);
    let expected: JsonValue = fastmcp_rust::serde_json::from_str(&expected).unwrap();
    assert_eq!(expected["version"], json!(3));
    assert_eq!(expected["finding_count"], json!(0));

    let mut reader = Mcp::start_with(&book, &["--cluster", "fa.match", "--grant", "read"]);
    reader.discover();
    let (error, output, _) = call_tool(
        &mut reader,
        "fa_match_intercompany",
        json!({"known_at": frontier, "effective_through": "2026-03-31"}),
    );
    assert!(!error, "{output}");
    let actual: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
    assert_eq!(actual, expected);
    let before = head(&b);
    let (error, output, _) = call_tool(
        &mut reader,
        "fa_match_intercompany",
        json!({"known_at": frontier, "effective_through": "2026-03-31", "certify": true}),
    );
    assert!(error, "{output}");
    let denied = structured_error(&output);
    assert_eq!(denied["refusal_id"], json!("FA-REF-011"));
    assert!(output.contains("produce"), "{output}");
    assert_eq!(head(&b), before, "denied retention must not publish an access event");
    let (error, output, _) = call_tool(
        &mut reader,
        "fa_match_intercompany",
        json!({"grant": ["produce"], "certify": true}),
    );
    assert!(error, "{output}");
    assert_eq!(head(&b), before);
    assert_eq!(reader.finish(), 0);

    let mut producer = Mcp::start_with(
        &book,
        &["--cluster", "fa.match", "--grant", "read", "--grant", "produce"],
    );
    producer.discover();
    let (error, output, _) = call_tool(
        &mut producer,
        "fa_match_intercompany",
        json!({"known_at": frontier, "effective_through": "2026-03-31", "certify": true}),
    );
    assert!(!error, "{output}");
    let certified: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
    let rows = certified.as_array().expect("procedure plus retained certificate");
    assert_eq!(rows.len(), 2, "{certified}");
    assert_eq!(rows[0], expected);
    assert_eq!(rows[1]["family"], json!("procedure"));
    assert_eq!(rows[1]["file"], JsonValue::Null);
    let retained = format!("C:{}", rows[1]["oid"].as_str().unwrap());
    let (error, output, _) = call_tool(
        &mut producer,
        "fa_read_replay",
        json!({"certificate": retained}),
    );
    assert!(!error, "{output}");
    let replay: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
    assert_eq!(replay, expected);
    assert_eq!(producer.finish(), 0);
}
