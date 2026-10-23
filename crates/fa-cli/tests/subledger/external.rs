//! Retained, independently reviewed external detail through the real CLI.

use super::*;

#[test]
fn retained_reviewed_detail_plans_posts_and_reconciles_once() {
    let f = Fixture::new();
    // Intentionally unordered source identities exercise canonical ordering.
    // The two expense rows must aggregate, while the vendor attribution on
    // the complete payable counterpart must survive the summary and report.
    let input = f.file(
        "external-batch.json",
        &format!(
            r#"{{"feed":"vendor-ap","batch_key":"march-001","effective_date":"2026-03-15","rows":[{{"source_digest":"{}","account":"6000","side":"debit","amount":"60.00 USD"}},{{"source_digest":"{}","account":"2000","side":"credit","amount":"100.00 USD","party":"V-1"}},{{"source_digest":"{}","account":"6000","side":"debit","amount":"40.00 USD"}}]}}"#,
            "02".repeat(32),
            "03".repeat(32),
            "01".repeat(32),
        ),
    );
    let retained = f.dir.join("external-detail.bin");
    let retained = retained.to_str().unwrap();
    let before = f.head();
    let prepared = data(&f.ok(&["subledger", "detail", "--input", &input, "--out", retained]));
    assert_eq!(prepared.get("detail_rows"), Some(&Json::Int(3)));
    assert_eq!(prepared.get("summary_legs"), Some(&Json::Int(2)));
    assert_eq!(text(&prepared, "kind"), "Workpaper");
    assert_eq!(f.head(), before, "detail preparation does not publish");
    let document = data(&f.ok(&[
        "document",
        "add",
        retained,
        "--kind",
        "Workpaper",
        "--grade",
        "HumanUpload",
    ]));
    let oid = text(&document, "oid");
    assert_eq!(oid, text(&prepared, "document_oid"));
    let source = format!("D:{oid}");
    let args = [
        "subledger",
        "feed",
        "--document",
        &source,
        "--date",
        "2026-03-15",
        "--key",
        "external-summary-001",
    ];

    let (exit, refusal) = f.run(&args);
    assert_eq!(exit, 3, "unreviewed source must refuse: {refusal}");
    assert!(refusal.contains("FA-REF-192"), "{refusal}");
    f.ok(&["attest", "review", &oid, "--as", "reviewer"]);

    let reviewed = f.head();
    let mut dry_run = args.to_vec();
    dry_run.push("--dry-run");
    let rehearsal = f.ok(&dry_run);
    let event = json::parse(rehearsal.lines().last().unwrap()).unwrap();
    assert_eq!(event.get("event"), Some(&Json::Str("plan".into())));
    assert_eq!(rows(&data(&rehearsal), "legs").len(), 2);
    assert_eq!(f.head(), reviewed, "rehearsal does not publish");

    let posted = data(&f.ok(&args));
    let entry = text(&posted, "vid");
    let posted_at = f.head();
    let report = data(&f.ok(&["subledger", "verify-feed", &entry]));
    assert_eq!(report.get("reconciled"), Some(&Json::Bool(true)));
    assert_eq!(report.get("detail_rows"), Some(&Json::Int(3)));
    assert_eq!(text(&report, "feed"), "vendor-ap");
    assert_eq!(text(&report, "batch_key"), "march-001");
    assert_eq!(text(&report, "document_oid"), oid);
    assert_eq!(report.get("doc_commit"), prepared.get("doc_commit"));
    assert_eq!(rows(&report, "summary_legs").len(), 2);
    for leg in rows(&report, "summary_legs") {
        assert_eq!(text(leg, "amount"), "100.00 USD");
        let dimensions = rows(leg, "dimension_set");
        match text(leg, "side").as_str() {
            "debit" => assert!(dimensions.is_empty()),
            "credit" => {
                assert_eq!(dimensions.len(), 1);
                assert_eq!(
                    dimensions[0].get("dimension"),
                    Some(&Json::Int(i128::from(fa_model::PARTY_DIMENSION))),
                );
                assert_eq!(text(&dimensions[0], "value").len(), 32);
            }
            side => panic!("unexpected side {side}"),
        }
    }
    assert_eq!(f.head(), posted_at, "reconciliation is read-only");

    let retry = f.ok(&args);
    let retry = json::parse(retry.lines().last().unwrap()).unwrap();
    assert_eq!(retry.get("event"), Some(&Json::Str("recorded".into())));
    assert_eq!(f.head(), posted_at, "exact retry adds nothing");

    let mut duplicate = args;
    duplicate[7] = "another-posting-key";
    let (exit, refusal) = f.run(&duplicate);
    assert_eq!(exit, 3, "the source identity is unique: {refusal}");
    assert!(refusal.contains("FA-REF-192"), "{refusal}");
    assert_eq!(f.head(), posted_at, "duplicate source publishes nothing");
}

fn event_data(output: &str, expected: &str) -> Json {
    output
        .lines()
        .map(|line| json::parse(line).unwrap())
        .find(|event| event.get("event").and_then(Json::as_str) == Some(expected))
        .unwrap_or_else(|| panic!("missing {expected}: {output}"))
        .get("data")
        .unwrap()
        .clone()
}

#[test]
fn aggregate_feed_certificate_reopens_replays_and_exposes_zero_net_control_contamination() {
    let f = Fixture::new();
    let detail = f.file("aggregate-source.json", &format!(
        r#"{{"feed":"vendor-ap","batch_key":"aggregate-001","effective_date":"2026-03-15","rows":[{{"source_digest":"{}","account":"6000","side":"debit","amount":"100.00 USD"}},{{"source_digest":"{}","account":"2000","side":"credit","amount":"100.00 USD","party":"V-1"}}]}}"#,
        "01".repeat(32), "02".repeat(32),
    ));
    let detail_path = f.dir.join("aggregate-detail.bin");
    f.ok(&[
        "subledger",
        "detail",
        "--input",
        &detail,
        "--out",
        detail_path.to_str().unwrap(),
    ]);
    let document = data(&f.ok(&[
        "document",
        "add",
        detail_path.to_str().unwrap(),
        "--kind",
        "Workpaper",
        "--grade",
        "HumanUpload",
    ]));
    let oid = text(&document, "oid");
    f.ok(&["attest", "review", &oid, "--as", "reviewer"]);
    f.ok(&[
        "subledger",
        "feed",
        "--document",
        &format!("D:{oid}"),
        "--date",
        "2026-03-15",
        "--key",
        "aggregate-summary",
    ]);
    let at = f.head();
    let request = [
        "subledger",
        "reconcile-feed",
        "vendor-ap",
        "--control",
        "2000",
        "--as-of",
        "2026-03-31",
    ];
    let plain = data(&f.ok(&request));
    assert_eq!(plain.get("reconciled"), Some(&Json::Bool(true)));
    assert_eq!(rows(&plain, "batches").len(), 1);
    assert!(rows(&plain, "unattributed").is_empty());
    assert_eq!(
        text(&rows(&plain, "totals")[0], "detail_credits"),
        "100.00 USD"
    );
    assert_eq!(
        text(&rows(&plain, "totals")[0], "register_credits"),
        "100.00 USD"
    );
    assert_eq!(f.head(), at, "plain reconciliation does not publish");

    let path = f.dir.join("aggregate.cert");
    let mut certify = request.to_vec();
    certify.extend(["--certificate-out", path.to_str().unwrap()]);
    let produced = f.ok(&certify);
    assert_eq!(event_data(&produced, "external_feed_reconciled"), plain);
    let metadata = event_data(&produced, "report_certificate");
    let locator = format!("C:{}", text(&metadata, "oid"));
    assert!(text(&metadata, "replay_command").contains("--expect"));
    let bytes = std::fs::read(&path).unwrap();
    let artifact = fa::ReportArtifact::decode(&bytes).unwrap();
    assert_eq!(artifact.family(), fa::ReportArtifactFamily::ExternalFeed);
    let expected = format!(
        r#"{{"kind":"external-feed-reconciliation","feed":"vendor-ap","control_account":"2000","through":"2026-03-31","known_at":{at}}}"#,
    );
    assert_eq!(
        text(
            &data(&f.ok(&["certificate", "status", &locator, "--expect", &expected])),
            "status"
        ),
        "Current"
    );
    for wrong in [
        expected.replace("vendor-ap", "different-feed"),
        expected.replace("2000", "1200"),
        expected.replace("2026-03-31", "2026-03-30"),
    ] {
        let (exit, refusal) = f.run(&["replay", &locator, "--expect", &wrong]);
        assert_eq!(exit, 8, "wrong recipient request: {refusal}");
    }
    let (exit, refusal) = f.run(&["replay", &locator]);
    assert_eq!(
        exit, 8,
        "a delivered artifact cannot provide its own expected request: {refusal}"
    );

    // Equal debit and credit additions leave the net balance unchanged. They
    // still have no reviewed source in this feed and must never disappear.
    let contamination = f.file("unmatched-control.json", r#"{"effective_date":"2026-03-16","idempotency_key":"unmatched-control","legs":[{"side":"debit","account":"2000","amount":"10.00 USD","party":"V-1"},{"side":"credit","account":"2000","amount":"10.00 USD","party":"V-1"}]}"#);
    f.ok(&[
        "post",
        "--intent",
        &contamination,
        "--evidence",
        &f.evidence,
    ]);
    let current = data(&f.ok(&request));
    assert_eq!(current.get("reconciled"), Some(&Json::Bool(false)));
    assert_eq!(rows(&current, "unattributed").len(), 2);
    assert_eq!(
        text(&rows(&current, "totals")[0], "detail_credits"),
        "100.00 USD"
    );
    assert_eq!(
        text(&rows(&current, "totals")[0], "control_credits"),
        "110.00 USD"
    );
    assert_eq!(
        text(&rows(&current, "totals")[0], "control_debits"),
        "10.00 USD"
    );
    let status = data(&f.ok(&["certificate", "status", &locator, "--expect", &expected]));
    assert_eq!(text(&status, "status"), "SupersededBy");
    assert_eq!(rows(&status, "later_entries").len(), 1);
    let before = f.head();
    let output = f.dir.join("aggregate.replayed");
    let replayed = f.ok(&[
        "replay",
        &locator,
        "--expect",
        &expected,
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(event_data(&replayed, "external_feed_reconciled"), plain);
    assert_eq!(std::fs::read(&output).unwrap(), artifact.output());
    assert_eq!(f.head(), before, "historical replay does not publish");
}
