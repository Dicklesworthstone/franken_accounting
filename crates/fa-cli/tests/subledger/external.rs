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
