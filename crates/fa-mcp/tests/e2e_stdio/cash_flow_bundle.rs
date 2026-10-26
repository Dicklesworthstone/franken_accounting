//! Inline policy inputs and retained certificates preserve gross cash turnover.

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

fn post(
    dir: &Path,
    book: &str,
    evidence: &str,
    key: &str,
    day: &str,
    legs: (&str, &str, &str),
) -> JsonValue {
    let (debit, credit, amount) = legs;
    let intent = dir.join(format!("{key}.json"));
    std::fs::write(&intent, format!(
        r#"{{"idempotency_key":"{key}","effective_date":"{day}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount} USD"}},{{"side":"credit","account":"{credit}","amount":"{amount} USD"}}]}}"#,
    )).unwrap();
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
fn retained_policy_cash_flow_recomputes_gross_refunds_and_internal_transfers_over_stdio() {
    let dir = tmp("cash-flow-bundle");
    let book = dir.join("book");
    let b = book.display().to_string();
    cli_data(&[
        "book", "create", "--book", &b, "--name", "Cash MCP", "--json",
    ]);
    let chart = dir.join("chart.json");
    std::fs::write(&chart,
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1100","name":"Savings","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
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
    cli_data(&["period", "open", "FY2026-P03", "--book", &b, "--json"]);
    let evidence = source_document(&dir, &b);
    post(
        &dir,
        &b,
        &evidence,
        "cash-opening",
        "2026-03-05",
        ("1000", "4000", "10.00"),
    );
    let refunded = post(
        &dir,
        &b,
        &evidence,
        "cash-refund",
        "2026-03-10",
        ("1000", "4000", "12.34"),
    );
    post(
        &dir,
        &b,
        &evidence,
        "cash-sale",
        "2026-03-20",
        ("1000", "4000", "7.66"),
    );
    cli_data(&[
        "reverse",
        refunded["vid"].as_str().unwrap(),
        "--reason",
        "WrongAccount",
        "--book",
        &b,
        "--json",
    ]);
    post(
        &dir,
        &b,
        &evidence,
        "cash-transfer",
        "2026-03-21",
        ("1100", "1000", "5.00"),
    );
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
            "view":"cash-flow", "account":"1000,1100", "unit":"USD",
            "from":"2026-03-10", "to":"2026-03-31", "label":"MCP cash turnover",
            "policy":{
                "name":"mcp-operating-policy", "cash_accounts":["1000","1100"],
                "account_rules":[{"account":"4000","activity":"operating"}], "overrides":[]
            },
            "certify":true
        }),
    );
    assert!(!error, "{output}");
    let certified: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
    assert_eq!(certified.as_array().unwrap().len(), 2);
    let certificate = fa::cash_flow_policy::CashFlowPolicyCertificate::decode(&decode_hex(
        certified[1]["bytes"].as_str().unwrap(),
    ))
    .unwrap();
    assert_eq!(certificate.decisions().len(), 5);
    assert_eq!(
        certificate
            .decisions()
            .iter()
            .filter(|decision| decision.basis
                == fa::cash_flow_policy::CashFlowDecisionBasis::InternalTransfer)
            .count(),
        2
    );
    let expected = fa_verify::blake3::hex(certificate.digest());
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(
        envelope["events"],
        json!(["policy_cash_flow", "report_certificate"])
    );
    assert_eq!(envelope["authority"]["profile"], json!("agent"));
    assert_eq!(producer.finish(), 0);

    post(
        &dir,
        &b,
        &evidence,
        "cash-later",
        "2026-03-15",
        ("1000", "4000", "99.00"),
    );
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
            json!({"certificate":input,"state":checkpoint["oid"]}),
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
        .expect("offline cash classification and transfer derivation over MCP");
        assert_eq!(verified.certificate_digest, *certificate.digest());
        assert_eq!(verified.output, certificate.output().unwrap());
        assert_eq!(verified.known_at, certificate.known_at().0);
        assert!(verified.receipt.is_some());
        let cash = verified.cash_flow.unwrap();
        assert_eq!(cash.ledger.lines.len(), 5);
        assert_eq!(cash.units.len(), 1);
        let unit = &cash.units[0];
        assert_eq!(unit.opening, 1000);
        assert_eq!(unit.operating.inflows, 2000);
        assert_eq!(unit.operating.outflows, 1234);
        assert_eq!(unit.operating.net, 766);
        assert_eq!(unit.net_change, 766);
        assert_eq!(unit.closing, 1766);
        let policy = cash.policy.unwrap();
        assert_eq!(policy.decisions.len(), 5);
        assert_eq!(policy.policy.account_rules.len(), 1);
        for nested_pin in [
            certificate.source_certificate().digest(),
            certificate
                .source_certificate()
                .source_certificate()
                .digest(),
        ] {
            assert!(
                fa_verify::report::verify_report_expected(
                    &bundle,
                    &[key],
                    None,
                    Some(&receipt),
                    Some(nested_pin),
                )
                .is_err(),
                "neither nested cash totals nor their ledger fix the outer policy"
            );
        }
        if let Some(expected) = &original_bundle {
            assert_eq!(&bundle, expected);
        } else {
            original_bundle = Some(bundle);
        }
    }
    assert_eq!(producer.finish(), 0);
    assert_eq!(cli_data(&["book", "info", "--book", &b, "--json"]), before);
}
