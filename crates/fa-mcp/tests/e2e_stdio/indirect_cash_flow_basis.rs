//! The stdio route accepts a real split bank payment as an indirect cash basis.
//! The recipient supplies the original complete policy independently on replay.

use super::*;

fn post(
    dir: &Path,
    book: &str,
    evidence: &str,
    key: &str,
    day: &str,
    legs: JsonValue,
) -> JsonValue {
    let intent = dir.join(format!("{key}.json"));
    std::fs::write(
        &intent,
        json!({"idempotency_key":key,"effective_date":day,"legs":legs}).to_string(),
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

fn original<'a>(detail: &'a JsonValue, entry: &JsonValue, account: &str) -> &'a JsonValue {
    detail["lines"]
        .as_array()
        .unwrap()
        .iter()
        .find(|line| {
            line["entry_digest"] == entry["entry_digest"] && line["account"] == json!(account)
        })
        .expect("an original posted journal leg")
}

#[test]
fn mixed_principal_and_interest_reconcile_and_replay_through_mcp_after_reopen() {
    let dir = tmp("indirect-cash-basis");
    let book = dir.join("book");
    let b = book.display().to_string();
    cli_data(&[
        "book",
        "create",
        "--book",
        &b,
        "--name",
        "Indirect cash MCP",
        "--json",
    ]);
    let chart = dir.join("chart.json");
    std::fs::write(
        &chart,
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1590","name":"Accumulated depreciation","type":"Asset","unit":"USD"},{"code":"2000","name":"Loan","type":"Liability","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},{"code":"6100","name":"Interest","type":"Expense","unit":"USD"},{"code":"6200","name":"Depreciation","type":"Expense","unit":"USD"}]}"#,
    ).unwrap();
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
    for period in ["FY2026-P02", "FY2026-P03"] {
        cli_data(&["period", "open", period, "--book", &b, "--json"]);
    }
    let evidence = source_document(&dir, &b);
    post(
        &dir,
        &b,
        &evidence,
        "opening-loan",
        "2026-02-20",
        json!([
            {"side":"debit","account":"1000","amount":"1000.00 USD"},
            {"side":"credit","account":"2000","amount":"1000.00 USD"}
        ]),
    );
    let sale = post(
        &dir,
        &b,
        &evidence,
        "cash-sale",
        "2026-03-10",
        json!([
            {"side":"debit","account":"1000","amount":"200.00 USD"},
            {"side":"credit","account":"4000","amount":"200.00 USD"}
        ]),
    );
    let payment = post(
        &dir,
        &b,
        &evidence,
        "one-bank-payment",
        "2026-03-15",
        json!([
            {"side":"debit","account":"2000","amount":"100.00 USD"},
            {"side":"debit","account":"6100","amount":"10.00 USD"},
            {"side":"credit","account":"1000","amount":"110.00 USD"}
        ]),
    );
    let depreciation = post(
        &dir,
        &b,
        &evidence,
        "depreciation",
        "2026-03-31",
        json!([
            {"side":"debit","account":"6200","amount":"20.00 USD"},
            {"side":"credit","account":"1590","amount":"20.00 USD"}
        ]),
    );
    let detail: JsonValue = fastmcp_rust::serde_json::from_str(&cli_data(&[
        "gl",
        "detail",
        "--account",
        "1000,6200",
        "--unit",
        "USD",
        "--from",
        "2026-03-01",
        "--to",
        "2026-03-31",
        "--book",
        &b,
        "--json",
    ]))
    .unwrap();
    let sale = original(&detail, &sale, "1000");
    let payment = original(&detail, &payment, "1000");
    let depreciation = original(&detail, &depreciation, "6200");
    assert_eq!(payment["credits"], json!("110.00 USD"));
    let known_at = detail["known_at"].clone();
    let policy = json!({
        "name":"mcp-indirect-March","cash_policy":"mcp-documented-cash","cash_accounts":["1000"],
        "splits":[
            {"entry_digest":sale["entry_digest"],"leg_index":sale["leg_index"],
             "reason":"Cash revenue","portions":[{"activity":"operating","amount":"200.00 USD"}]},
            {"entry_digest":payment["entry_digest"],"leg_index":payment["leg_index"],
             "reason":"Documented principal and interest",
             "portions":[{"activity":"operating","amount":"10.00 USD"},
                         {"activity":"financing","amount":"100.00 USD"}]}
        ],
        "adjustments":[{
            "entry_digest":depreciation["entry_digest"],"leg_index":depreciation["leg_index"],
            "category":"non_cash","sign":"debit_minus_credit","reason":"Original depreciation expense"
        }]
    });
    let expected = json!({
        "kind":"indirect-cash-flow","accounts":["1000"],"units":["USD"],
        "label":"MCP March indirect","from":"2026-03-01","through":"2026-03-31",
        "known_at":known_at,"income_periods":["FY2026-P03"],"policy":policy.clone()
    });
    let question = json!({
        "view":"cash-flow","indirect":true,"income_period":["FY2026-P03"],
        "account":"1000","unit":"USD","from":"2026-03-01","to":"2026-03-31",
        "label":"MCP March indirect","as_known_at":known_at.to_string(),
        "policy":policy,"certify":true
    });
    let mut producer = Mcp::start_with(
        &book,
        &[
            "--cluster",
            "fa.proof",
            "--grant",
            "read",
            "--grant",
            "produce",
        ],
    );
    producer.discover();
    let (error, output, metadata) = call_tool(&mut producer, "fa_proof_gl", question.clone());
    assert!(!error, "{output}");
    let certified: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
    assert_eq!(certified.as_array().unwrap().len(), 2);
    assert_eq!(certified[0]["cash_policy"], json!("mcp-documented-cash"));
    assert_eq!(
        certified[1]["output_format"],
        json!("fa:indirect-cash-flow:v2")
    );
    for (field, amount) in [
        ("net_income", "170.00 USD"),
        ("non_cash", "20.00 USD"),
        ("operating", "190.00 USD"),
        ("direct_operating", "190.00 USD"),
        ("operating_residual", "0.00 USD"),
        ("opening", "1000.00 USD"),
        ("financing", "-100.00 USD"),
        ("net_change", "90.00 USD"),
        ("closing", "1090.00 USD"),
    ] {
        assert_eq!(certified[0]["units"][0][field], json!(amount), "{field}");
    }
    assert_eq!(certified[0]["contributions"].as_array().unwrap().len(), 1);
    assert_eq!(certified[0]["contributions"][0]["account"], json!("6200"));
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(
        envelope["events"],
        json!(["indirect_cash_flow", "report_certificate"])
    );
    let locator = format!("C:{}", certified[1]["oid"].as_str().unwrap());
    let (error, output, _) = call_tool(
        &mut producer,
        "fa_read_certificate_status",
        json!({"certificate":locator,"expect":expected.to_string()}),
    );
    assert!(!error, "{output}");
    let current: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
    assert_eq!(current["status"], json!("Current"));

    let mut conflicting = question;
    conflicting["policy"]["assignments"] = json!([]);
    let (error, output, _) = call_tool(&mut producer, "fa_proof_gl", conflicting);
    assert!(error, "two classification families were admitted: {output}");
    assert_eq!(structured_error(&output)["exit"], json!(2));
    assert_eq!(producer.finish(), 0);

    post(
        &dir,
        &b,
        &evidence,
        "later-backdated",
        "2026-03-20",
        json!([
            {"side":"debit","account":"1000","amount":"99.00 USD"},
            {"side":"credit","account":"4000","amount":"99.00 USD"}
        ]),
    );
    cli_data(&[
        "checkpoint",
        "create",
        "--grant",
        "witness",
        "--book",
        &b,
        "--json",
    ]);
    let before = cli_data(&["book", "info", "--book", &b, "--json"]);
    let mut reader = Mcp::start_with(&book, &["--cluster", "fa.proof", "--grant", "read"]);
    reader.discover();
    for certificate in [
        locator.clone(),
        certified[1]["bytes"].as_str().unwrap().to_string(),
    ] {
        let (error, output, _) = call_tool(
            &mut reader,
            "fa_read_replay",
            json!({"certificate":certificate,"expect":expected.to_string()}),
        );
        assert!(!error, "retained original basis: {output}");
        let replayed: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
        assert_eq!(replayed["family"], json!("indirect-cash-flow"));
        assert_eq!(replayed["output_digest"], certified[1]["output_digest"]);
    }
    let mut different_reason = expected.clone();
    different_reason["policy"]["splits"][1]["reason"] = json!("A different accounting judgment");
    let mut foreign_currency = expected.clone();
    foreign_currency["policy"]["splits"][1]["portions"][0]["amount"] = json!("10.00 EUR");
    foreign_currency["policy"]["splits"][1]["portions"][1]["amount"] = json!("100.00 EUR");
    for changed in [different_reason, foreign_currency] {
        for tool in ["fa_read_replay", "fa_read_certificate_status"] {
            let (error, output, _) = call_tool(
                &mut reader,
                tool,
                json!({"certificate":locator,"expect":changed.to_string()}),
            );
            assert!(error, "changed recipient basis: {output}");
            assert_eq!(structured_error(&output)["refusal_id"], json!("FA-REF-150"));
        }
    }
    assert_eq!(reader.finish(), 0);
    assert_eq!(cli_data(&["book", "info", "--book", &b, "--json"]), before);
}
