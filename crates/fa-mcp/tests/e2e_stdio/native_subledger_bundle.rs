//! Native party detail and its fixed question survive authorized MCP export.

use super::*;

fn unhex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn invoice(book: &str, evidence: &str, number: &str, amount: &str) -> JsonValue {
    fastmcp_rust::serde_json::from_str(&cli_data(&[
        "invoice",
        "--party",
        "C-1",
        "--number",
        number,
        "--date",
        "2026-03-14",
        "--receivable",
        "1200",
        "--revenue",
        "4000",
        "--line",
        &format!("amount=\"{amount} USD\""),
        "--evidence",
        evidence,
        "--book",
        book,
        "--json",
    ]))
    .unwrap()
}

#[test]
fn retained_native_subledger_requires_an_independent_question_and_recomputes_over_stdio() {
    let dir = tmp("native-subledger-bundle");
    let book = dir.join("book");
    let b = book.display().to_string();
    cli_data(&[
        "book",
        "create",
        "--book",
        &b,
        "--name",
        "Native AR MCP",
        "--json",
    ]);
    let chart = dir.join("chart.json");
    std::fs::write(
        &chart,
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1200","name":"Receivables","type":"Asset","unit":"USD"},{"code":"4000","name":"Sales","type":"Revenue","unit":"USD"}]}"#,
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
    let party = dir.join("customer.json");
    std::fs::write(
        &party,
        r#"{"code":"C-1","kind":"Customer","name":"Customer One"}"#,
    )
    .unwrap();
    cli_data(&[
        "party",
        "add",
        party.to_str().unwrap(),
        "--book",
        &b,
        "--json",
    ]);
    let declared: JsonValue = fastmcp_rust::serde_json::from_str(&cli_data(&[
        "subledger",
        "add",
        "AR",
        "--control",
        "1200",
        "--kind",
        "receivables",
        "--book",
        &b,
        "--json",
    ]))
    .unwrap();
    let control_account =
        u128::from_str_radix(declared["subledger"]["control_vid"].as_str().unwrap(), 16).unwrap();
    let declaration_entry =
        u128::from_str_radix(declared["subledger"]["control_entry"].as_str().unwrap(), 16).unwrap();
    let evidence = source_document(&dir, &b);
    let posted = invoice(&b, &evidence, "MCP-AR-1", "123.45");
    cli_data(&[
        "receipt",
        "--party",
        "C-1",
        "--number",
        "MCP-AR-REC",
        "--date",
        "2026-03-20",
        "--cash",
        "1000",
        "--receivable",
        "1200",
        "--amount",
        "23.45 USD",
        "--applies",
        posted["vid"].as_str().unwrap(),
        "--evidence",
        &evidence,
        "--book",
        &b,
        "--json",
    ]);
    let hold = dir.join("hold.json");
    std::fs::write(
        &hold,
        r#"{"effective_date":"2026-03-25","idempotency_key":"mcp-native-hold","legs":[{"side":"debit","account":"1200","amount":"7.00 USD","party":"C-1"},{"side":"credit","account":"1000","amount":"7.00 USD"}]}"#,
    )
    .unwrap();
    cli_data(&[
        "reserve",
        "--intent",
        hold.to_str().unwrap(),
        "--evidence",
        &evidence,
        "--book",
        &b,
        "--json",
    ]);
    let known_at = head(&b);
    // These inputs come from the recipient's chosen question and the control
    // declaration, before receiving either certificate or portable bundle.
    let expected = fa_verify::report::NativeSubledgerRequest {
        code: "AR".into(),
        control_account,
        effective_through: 20_543, // 2026-03-31, days since 1970-01-01.
        known_at,
    };
    let expectation = json!({
        "kind": "native-subledger-reconciliation",
        "code": "AR",
        "control_account": "1200",
        "through": "2026-03-31",
        "known_at": known_at
    })
    .to_string();
    let grants = [
        "--cluster",
        "fa.subledger",
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
        "fa_subledger_verify",
        json!({
            "code": "AR",
            "as_of": "2026-03-31",
            "as_known_at": known_at.to_string(),
            "certify": true
        }),
    );
    assert!(!error, "{output}");
    let certified: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
    assert_eq!(certified.as_array().unwrap().len(), 2);
    let envelope: JsonValue =
        fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
            .unwrap();
    assert_eq!(
        envelope["events"],
        json!(["subledger_reconciled", "report_certificate"])
    );
    assert_eq!(envelope["authority"]["profile"], json!("agent"));
    let certificate =
        fa::NativeSubledgerCertificate::decode(&unhex(certified[1]["bytes"].as_str().unwrap()))
            .unwrap();
    let digest = fa_verify::blake3::hex(certificate.digest());
    assert_eq!(certified[1]["oid"], json!(digest));
    assert_eq!(producer.finish(), 0);

    // A later invoice changes live AR, but the exported historical report must
    // still include the original receipt and pending amount separately.
    invoice(&b, &evidence, "MCP-AR-LATER", "9.99");
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
    let before = head(&b);
    let locator = format!("C:{digest}");
    let mut producer = Mcp::start_with(&book, &grants);
    producer.discover();
    let (error, output, _) = call_tool(
        &mut producer,
        "fa_notary_bundle",
        json!({"certificate": locator, "state": checkpoint["oid"]}),
    );
    assert!(
        error,
        "the artifact cannot supply its own question: {output}"
    );
    let (error, output, _) = call_tool(
        &mut producer,
        "fa_notary_bundle",
        json!({
            "certificate": locator,
            "state": checkpoint["oid"],
            "expect": expectation.replace("2026-03-31", "2026-03-30")
        }),
    );
    assert!(error, "a different recipient cutoff must refuse: {output}");
    let mut original_bundle = None;
    for input in [locator, certified[1]["bytes"].as_str().unwrap().to_string()] {
        let (error, output, metadata) = call_tool(
            &mut producer,
            "fa_notary_bundle",
            json!({
                "certificate": input,
                "state": checkpoint["oid"],
                "expect": expectation
            }),
        );
        assert!(!error, "{output}");
        let produced: JsonValue = fastmcp_rust::serde_json::from_str(&output).unwrap();
        assert_eq!(produced["scope"], json!("report"));
        let command = produced["verify"].as_str().unwrap();
        assert!(command.contains(&format!("--expect {digest}")));
        assert!(command.contains("--subledger=AR"));
        let envelope: JsonValue =
            fastmcp_rust::serde_json::from_str(metadata["content"][1]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(envelope["events"], json!(["bundle_produced"]));
        assert_eq!(envelope["authority"]["profile"], json!("agent"));
        let bundle = unhex(produced["bytes"].as_str().unwrap());
        let receipt = unhex(produced["receipt"].as_str().unwrap());
        let key: [u8; 32] = unhex(produced["checkpoint_public_key"].as_str().unwrap())
            .try_into()
            .unwrap();
        let verified = fa_verify::report::verify_report_native_subledger_expected(
            &bundle,
            &[key],
            None,
            Some(&receipt),
            &expected,
            Some(certificate.digest()),
        )
        .expect("retained native party/control detail independently verifies over MCP");
        assert_eq!(verified.certificate_digest, *certificate.digest());
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.known_at, known_at);
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
        assert!(verified.receipt.is_some());
        let report = verified.native_subledger.unwrap();
        assert!(report.reconciled);
        assert_eq!(report.code, "AR");
        assert_eq!(report.kind, 1);
        assert_eq!(report.control_account, control_account);
        assert_eq!(report.declaration_entry_vid, declaration_entry);
        assert_eq!(report.rows.len(), 1);
        let row = &report.rows[0];
        assert_eq!(row.party_code, "C-1");
        assert_eq!(
            [
                row.debits,
                row.credits,
                row.debits_pending,
                row.credits_pending
            ],
            [12_345, 2_345, 700, 0]
        );
        assert_eq!(report.totals.len(), 1);
        let total = &report.totals[0];
        assert_eq!(total.unit, row.unit);
        assert_eq!(
            [
                total.detail_debits,
                total.detail_credits,
                total.detail_debits_pending,
                total.detail_credits_pending
            ],
            [12_345, 2_345, 700, 0]
        );
        assert_eq!(
            [
                total.control_debits,
                total.control_credits,
                total.control_debits_pending,
                total.control_credits_pending
            ],
            [12_345, 2_345, 700, 0]
        );
        assert!(
            fa_verify::report::verify_report_expected(
                &bundle,
                &[key],
                None,
                Some(&receipt),
                Some(certificate.digest()),
            )
            .is_err(),
            "even a trusted outer pin cannot supply the recipient's question"
        );
        assert!(
            fa_verify::report::verify_report_native_subledger_expected(
                &bundle,
                &[key],
                None,
                None,
                &expected,
                Some(&certificate.source_certificate().digest),
            )
            .is_err(),
            "a nested control trial balance cannot authenticate the party report"
        );
        if let Some(original) = &original_bundle {
            assert_eq!(&bundle, original, "retained and inline transport agree");
        } else {
            original_bundle = Some(bundle);
        }
    }
    assert_eq!(producer.finish(), 0);
    assert_eq!(
        head(&b),
        before,
        "successful and refused historical bundle exports never publish"
    );
}
