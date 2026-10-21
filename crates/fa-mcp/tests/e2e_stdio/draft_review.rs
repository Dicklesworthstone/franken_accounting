//! The registered close dry-run tool reviews the exact retained draft under
//! current launch authority, and retained certificates survive a new session.

use super::*;

const PERIOD: &str = "FY2026-P03";

fn wire(text: &str) -> JsonValue {
    fastmcp_rust::serde_json::from_str(text).expect("JSON tool data")
}

fn envelope(result: &JsonValue) -> JsonValue {
    // VerbTool returns the data and provenance envelope as separate text
    // blocks. These assertions exercise the actual stdio representation.
    assert_eq!(result["content"][1]["type"], json!("text"));
    wire(result["content"][1]["text"].as_str().unwrap())
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    book_arg: String,
    evidence: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = tmp("draft-review");
        let book = dir.join("book");
        let book_arg = book.display().to_string();
        cli_data(&[
            "book",
            "create",
            "--book",
            &book_arg,
            "--name",
            "Draft review MCP",
            "--json",
        ]);
        let chart = dir.join("chart.json");
        std::fs::write(
            &chart,
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
        )
        .unwrap();
        cli_data(&[
            "chart",
            "import",
            chart.to_str().unwrap(),
            "--book",
            &book_arg,
            "--json",
        ]);
        cli_data(&[
            "period",
            "create",
            "--fiscal-year",
            "2026",
            "--book",
            &book_arg,
            "--json",
        ]);
        cli_data(&["period", "open", PERIOD, "--book", &book_arg, "--json"]);
        let evidence = source_document(&dir, &book_arg);
        Self {
            dir,
            book,
            book_arg,
            evidence,
        }
    }

    fn dry_run(&self, name: &str) -> String {
        cli_data(&[
            "close",
            "dry-run",
            "--period",
            PERIOD,
            "--draft",
            name,
            "--book",
            &self.book_arg,
            "--json",
        ])
    }

    fn trial_balance(&self) -> String {
        cli_data(&["tb", "--period", PERIOD, "--book", &self.book_arg, "--json"])
    }

    fn draft(&self, name: &str) -> String {
        cli_data(&["draft", "show", name, "--book", &self.book_arg, "--json"])
    }

    fn assert_unposted(&self, entry: &str) {
        let shown = wire(&cli_data(&[
            "entry",
            "show",
            entry,
            "--book",
            &self.book_arg,
            "--json",
        ]));
        assert_eq!(
            shown["found"],
            json!(false),
            "a rehearsal never posts on trunk: {shown}"
        );
    }
}

fn intent(key: &str, amount: &str) -> JsonValue {
    json!({
        "class": "Original",
        "effective_date": "2026-03-15",
        "description": "Retained draft rent",
        "idempotency_key": key,
        "legs": [
            {"side": "debit", "account": "6000", "amount": amount},
            {"side": "credit", "account": "1000", "amount": amount},
        ],
    })
}

#[test]
fn draft_rehearsal_over_stdio_preserves_agent_plans_and_retained_replay() {
    let fixture = Fixture::new();
    let human_name = "human-close-review";
    let agent_name = "agent-close-review";
    cli_data(&[
        "draft",
        "new",
        human_name,
        "--as",
        "human-draft-preparer",
        "--book",
        &fixture.book_arg,
        "--json",
    ]);
    let human_intent = fixture.dir.join("human-intent.json");
    std::fs::write(
        &human_intent,
        intent("human-review-rent", "25.00 USD").to_string(),
    )
    .unwrap();
    let human_plan = wire(&cli_data(&[
        "post",
        "--intent",
        human_intent.to_str().unwrap(),
        "--evidence",
        &fixture.evidence,
        "--draft",
        human_name,
        "--as",
        "human-draft-preparer",
        "--book",
        &fixture.book_arg,
        "--json",
    ]));
    let human_entry = human_plan["entry"].as_str().unwrap().to_string();

    // Persist the second draft through the real Agent session; a later
    // Read-only reviewer must retain this original planner's authority.
    let mut planner = Mcp::start_with(
        &fixture.book,
        &[
            "--cluster",
            "fa.draft",
            "--principal",
            "agent-draft-preparer",
            "--grant",
            "read",
            "--grant",
            "post",
        ],
    );
    planner.discover();
    let (error, text, _) = call_tool(
        &mut planner,
        "fa_draft_manage",
        json!({"action": "new", "name": agent_name}),
    );
    assert!(!error, "{text}");
    let (error, text, _) = call_tool(
        &mut planner,
        "fa_post_post",
        json!({
            "draft": agent_name,
            "intent": intent("agent-review-rent", "42.00 USD"),
            "evidence": [fixture.evidence],
        }),
    );
    assert!(!error, "the real Agent plans into its draft: {text}");
    let agent_plan = wire(&text);
    let agent_entry = agent_plan["entry"].as_str().unwrap().to_string();
    assert_eq!(planner.finish(), 0);

    let names = [human_name, agent_name];
    let entries = [&human_entry, &agent_entry];
    let original_drafts = names.map(|name| fixture.draft(name));
    let original_trial_balance = fixture.trial_balance();
    let expected = names.map(|name| fixture.dry_run(name));
    assert_ne!(wire(&expected[0])["owner"], wire(&expected[1])["owner"]);
    for (report, entry) in expected.iter().zip(entries) {
        let report = wire(report);
        assert_eq!(report["plans"], json!(1));
        assert_eq!(report["entries"][0]["vid"], json!(entry));
        assert_eq!(report["rows"].as_array().unwrap().len(), 2);
        assert_eq!(
            report["rehearsal_known_at"].as_u64(),
            report["source_known_at"].as_u64().map(|at| at + 1)
        );
        fixture.assert_unposted(entry);
    }

    let mut reader = Mcp::start_with(
        &fixture.book,
        &[
            "--cluster",
            "fa.close",
            "--principal",
            "draft-review-reader",
            "--grant",
            "read",
        ],
    );
    reader.discover();
    let draft_resource = reader.result(
        "resources/read",
        json!({"uri": "resource://fa/drafts/default"}),
    );
    let draft_text = draft_resource["contents"][0]["text"].as_str().unwrap();
    assert_eq!(
        draft_text,
        cli_data(&["draft", "list", "--book", &fixture.book_arg, "--json"]),
        "the read-only session sees the journaled draft inventory",
    );
    let draft_inventory = wire(draft_text);
    let drafts = draft_inventory["drafts"].as_array().unwrap();
    assert_eq!(drafts.len(), 2);
    for (index, name) in names.iter().enumerate() {
        let actual = drafts
            .iter()
            .find(|draft| draft["name"] == json!(name))
            .expect("recorded draft");
        let original = wire(&original_drafts[index]);
        assert_eq!(actual, &original["draft"]);
        assert_eq!(actual["intents"], json!(1));
        assert_eq!(actual["owner"], wire(&expected[index])["owner"]);
    }
    let resource_authority = wire(draft_resource["contents"][1]["text"].as_str().unwrap());
    assert_eq!(resource_authority["authority"]["ops"], json!(["read"]));
    // fa-shw2: the read-only session reads the journaled cases (none
    // here); a bundle identifier still resolves to nothing.
    let cases = reader.result(
        "resources/read",
        json!({"uri": "resource://fa/cases/default"}),
    );
    assert_eq!(
        wire(cases["contents"][0]["text"].as_str().unwrap()),
        json!({"cases": []})
    );
    let response = reader.request(
        "resources/read",
        json!({"uri": "resource://fa/bundles/unknown"}),
    );
    assert!(
        response.get("error").is_some(),
        "unavailable bundles: {response}"
    );
    let listed = reader.result("tools/list", json!({}));
    let tool = listed["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == json!("fa_close_dry_run"))
        .expect("registered close dry-run tool");
    assert_eq!(
        tool["inputSchema"]["properties"]["certify"]["type"],
        json!("boolean")
    );
    for (index, name) in names.iter().enumerate() {
        let (error, text, result) = call_tool(
            &mut reader,
            "fa_close_dry_run",
            json!({"period": PERIOD, "draft": name}),
        );
        assert!(!error, "{name}: {text}");
        assert_eq!(
            text, expected[index],
            "MCP preserves the CLI's complete canonical report"
        );
        let metadata = envelope(&result);
        assert_eq!(metadata["events"], json!(["draft_diff"]));
        assert_eq!(metadata["certificate"], JsonValue::Null);
        assert_eq!(metadata["authority"]["ops"], json!(["read"]));
    }

    // An ordinary review has no publication. Produce admission for retained
    // output also precedes even an unknown draft's source lookup.
    for name in [human_name, agent_name, "unknown-close-review"] {
        let (error, text, _) = call_tool(
            &mut reader,
            "fa_close_dry_run",
            json!({"period": PERIOD, "draft": name, "certify": true}),
        );
        assert!(error, "read-only session must not retain: {text}");
        let refused = structured_error(&text);
        assert_eq!(refused["refusal_id"], json!("FA-REF-011"));
        assert_eq!(refused["authority"]["ops"], json!(["read"]));
        assert!(text.contains("produce"), "{text}");
    }
    assert_eq!(reader.finish(), 0);
    assert_eq!(
        fixture.trial_balance(),
        original_trial_balance,
        "known_at and balances stay unchanged: no certificate metadata was published"
    );
    for (index, name) in names.iter().enumerate() {
        assert_eq!(fixture.draft(name), original_drafts[index]);
        assert_eq!(fixture.dry_run(name), expected[index]);
    }

    let mut producer = Mcp::start_with(
        &fixture.book,
        &[
            "--cluster",
            "fa.close",
            "--principal",
            "draft-review-producer",
            "--grant",
            "read",
            "--grant",
            "produce",
        ],
    );
    producer.discover();
    let mut retained = Vec::new();
    for name in names {
        // The preceding certificate is a real maintenance publication. The
        // next review still retains the exact source commit coordinates.
        let expected_report = fixture.dry_run(name);
        let (error, text, result) = call_tool(
            &mut producer,
            "fa_close_dry_run",
            json!({"period": PERIOD, "draft": name, "certify": true}),
        );
        assert!(!error, "{name}: {text}");
        let data = wire(&text);
        assert_eq!(
            data.as_array().unwrap().len(),
            2,
            "report plus retained certificate"
        );
        assert_eq!(data[0], wire(&expected_report));
        let receipt = &data[1];
        let digest = receipt["oid"].as_str().unwrap().to_string();
        let bytes = receipt["bytes"].as_str().unwrap().to_string();
        assert_eq!(digest.len(), 64);
        assert!(!bytes.is_empty());
        assert_eq!(receipt["file"], JsonValue::Null);
        assert_eq!(receipt["output_format"], json!("fa:draft-diff:v1"));
        assert_eq!(receipt["known_at"], data[0]["source_known_at"]);
        assert!(receipt["recorded_at"].as_u64().unwrap() > receipt["known_at"].as_u64().unwrap());
        assert!(
            receipt["replay_command"]
                .as_str()
                .unwrap()
                .contains(&format!("C:{digest}"))
        );
        let metadata = envelope(&result);
        assert_eq!(
            metadata["events"],
            json!(["draft_diff", "report_certificate"])
        );
        assert_eq!(metadata["certificate"], json!(digest));
        assert_eq!(metadata["authority"]["ops"], json!(["read", "produce"]));
        let locator = format!("C:{digest}");
        for certificate in [&locator, &bytes] {
            let (error, replayed, result) = call_tool(
                &mut producer,
                "fa_read_replay",
                json!({"certificate": certificate}),
            );
            assert!(!error, "{replayed}");
            assert_eq!(replayed, expected_report);
            let replay_metadata = envelope(&result);
            assert_eq!(replay_metadata["events"], json!(["draft_diff"]));
            assert_eq!(replay_metadata["certificate"], json!(digest));
            assert_eq!(replay_metadata["coordinate"], metadata["coordinate"]);
        }
        retained.push((locator, expected_report, metadata["coordinate"].clone()));
    }
    assert_eq!(producer.finish(), 0);

    // A new read-only process recovers each retained C: object and performs
    // the original atomic rehearsal, including the older source prefix.
    let mut cold_reader = Mcp::start_with(
        &fixture.book,
        &["--principal", "cold-draft-review-reader", "--grant", "read"],
    );
    cold_reader.discover();
    for (locator, expected_report, coordinate) in retained {
        let (error, replayed, result) = call_tool(
            &mut cold_reader,
            "fa_read_replay",
            json!({"certificate": locator}),
        );
        assert!(!error, "cold retained replay: {replayed}");
        assert_eq!(replayed, expected_report);
        assert_eq!(envelope(&result)["coordinate"], coordinate);
    }
    assert_eq!(cold_reader.finish(), 0);

    let before = wire(&original_trial_balance);
    let mut after = wire(&fixture.trial_balance());
    assert!(after["known_at"].as_u64().unwrap() > before["known_at"].as_u64().unwrap());
    after["known_at"] = before["known_at"].clone();
    assert_eq!(after, before, "only certificate metadata was published");
    for (index, name) in names.iter().enumerate() {
        assert_eq!(fixture.draft(name), original_drafts[index]);
        fixture.assert_unposted(entries[index]);
    }
}
