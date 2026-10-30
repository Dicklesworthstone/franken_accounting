//! Historical summary exports preserve both recipient roots and leaf coverage.

use super::*;

#[test]
fn summary_exports_preserve_partial_coverage_and_bind_the_outer_recipient_request() {
    let fixture = Fixture::new();
    let chart = write(
        &fixture.dir,
        "summary-chart.json",
        r#"{"accounts":[
            {"code":"10","name":"Assets","type":"Asset","leaf":false,"unit":"USD"},
            {"code":"1000","name":"Cash","type":"Asset","unit":"USD","parent":"10"},
            {"code":"1200","name":"Dormant receivable","type":"Asset","unit":"USD","parent":"10"},
            {"code":"2000","name":"Dormant payable","type":"Liability","unit":"USD"},
            {"code":"40","name":"Income","type":"Revenue","leaf":false,"unit":"USD"},
            {"code":"4000","name":"Revenue","type":"Revenue","unit":"USD","parent":"40"},
            {"code":"90","name":"Empty summary","type":"Asset","leaf":false,"unit":"USD"}
        ]}"#,
    );
    ok(&fixture.book, &["chart", "import", &chart]);
    ok(
        &fixture.book,
        &["period", "create", "--fiscal-year", "2026"],
    );
    ok(&fixture.book, &["period", "open", "FY2026-P03"]);
    let source = write(&fixture.dir, "summary-receipt.txt", "Summary sale receipt.");
    let document = ok(
        &fixture.book,
        &[
            "document",
            "add",
            &source,
            "--kind",
            "Receipt",
            "--grade",
            "HumanUpload",
        ],
    );
    let evidence = text(&document, "oid");
    fixture.post("summary-first-sale", "2026-03-10", "12.34", evidence);
    let known_at = fixture.head();
    let at = known_at.to_string();
    let all_metadata = aging::certify(
        &fixture,
        &[
            "tb",
            "--period",
            "FY2026-P03",
            "--summary",
            "--as-known-at",
            &at,
        ],
    );
    let certificate_path = fixture.dir.join("partial-summary.certificate");
    let partial_metadata = aging::certify(
        &fixture,
        &[
            "tb",
            "--period",
            "FY2026-P03",
            "--summary",
            "--root",
            "40",
            "--root",
            "10",
            "--as-known-at",
            &at,
            "--certificate-out",
            certificate_path.to_str().unwrap(),
        ],
    );
    let all = fa::SummaryCertificate::decode(&unhex(text(&all_metadata, "bytes"))).unwrap();
    let encoded = unhex(text(&partial_metadata, "bytes"));
    assert_eq!(std::fs::read(&certificate_path).unwrap(), encoded);
    let partial = fa::SummaryCertificate::decode(&encoded).unwrap();
    assert_ne!(all.digest(), partial.digest());
    assert_eq!(
        all.source_certificate().digest,
        partial.source_certificate().digest,
        "the root request changes independently of the shared whole-book source"
    );
    assert_ne!(partial.digest(), &partial.source_certificate().digest);
    let all_locator = format!("C:{}", text(&all_metadata, "oid"));
    let partial_locator = format!("C:{}", text(&partial_metadata, "oid"));
    let expected = fa_verify::blake3::hex(partial.digest());
    assert_eq!(text(&partial_metadata, "oid"), expected);

    // The later prefix has both a backdated amount and another dormant leaf.
    // Neither changes the report's original historical amounts or coverage.
    fixture.post("summary-later-sale", "2026-03-10", "99.00", evidence);
    let later_chart = write(
        &fixture.dir,
        "summary-later-chart.json",
        r#"{"accounts":[{"code":"2100","name":"Later payable","type":"Liability","unit":"USD"}]}"#,
    );
    ok(&fixture.book, &["chart", "import", &later_chart]);
    let checkpoint = fixture.checkpoint();
    let signed = exported(
        &fixture.book,
        &["signed-checkpoint", "--state", text(&checkpoint, "oid")],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let before = fixture.head();
    let mut partial_bundle = None;
    for (source, certificate, complete) in [
        (all_locator.as_str(), &all, true),
        (partial_locator.as_str(), &partial, false),
        (certificate_path.to_str().unwrap(), &partial, false),
    ] {
        let produced = ok(
            &fixture.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                source,
                "--state",
                text(&checkpoint, "oid"),
            ],
        );
        assert_eq!(text(&produced, "scope"), "report");
        assert!(text(&produced, "verify").contains(&format!(
            "--expect {}",
            fa_verify::blake3::hex(certificate.digest())
        )));
        let bundle = bytes(&produced);
        let receipt = unhex(text(&produced, "receipt"));
        let verified = fa_verify::report::verify_report_expected(
            &bundle,
            &[key],
            None,
            Some(&receipt),
            Some(certificate.digest()),
        )
        .expect("independent historical summary reconstruction");
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.certificate_digest, *certificate.digest());
        assert_eq!(verified.known_at, known_at);
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
        assert_eq!(verified.rows.len(), 2, "retain the full native drilldown");
        assert_eq!(verified.rows[0].code, "1000");
        assert_eq!(verified.rows[0].debits, 1234);
        assert_eq!(verified.rows[1].code, "4000");
        assert_eq!(verified.rows[1].credits, 1234);
        let summary = verified.summary.unwrap();
        assert_eq!(summary.book_id, BOOK_ID.0);
        assert_eq!(summary.known_at, known_at);
        assert_eq!(
            summary.source_certificate_digest,
            certificate.source_certificate().digest
        );
        assert_eq!(summary.is_complete(), complete);
        assert_eq!(
            summary.unit_totals.values().copied().collect::<Vec<_>>(),
            [(1234, 1234)],
            "numeric balance alone cannot prove complete leaf coverage"
        );
        let assets = summary
            .groups
            .iter()
            .find(|group| group.account.code == "10")
            .unwrap();
        assert_eq!(
            assets
                .leaves
                .iter()
                .map(|account| account.code.as_str())
                .collect::<Vec<_>>(),
            ["1000", "1200"],
            "zero-activity leaves still belong to the selected group"
        );
        assert_eq!(assets.rows.len(), 1);
        assert_eq!((assets.rows[0].debits, assets.rows[0].credits), (1234, 0));
        if complete {
            assert_eq!(summary.scope, fa_verify::report::SummaryScope::AllRoots);
            assert_eq!(summary.groups.len(), 4);
            let empty = summary
                .groups
                .iter()
                .find(|group| group.account.code == "90")
                .unwrap();
            assert!(empty.leaves.is_empty());
            assert!(empty.rows.is_empty(), "empty groups invent no currency row");
        } else {
            let mut roots = vec![account_vid(BOOK_ID, "10").0, account_vid(BOOK_ID, "40").0];
            roots.sort_unstable();
            assert_eq!(
                summary.scope,
                fa_verify::report::SummaryScope::Selected(roots)
            );
            assert_eq!(summary.groups.len(), 2);
            assert_eq!(
                summary
                    .uncovered_leaves
                    .iter()
                    .map(|account| account.code.as_str())
                    .collect::<Vec<_>>(),
                ["2000"]
            );
            for wrong_pin in [all.digest(), &partial.source_certificate().digest] {
                assert!(
                    fa_verify::report::verify_report_expected(
                        &bundle,
                        &[key],
                        None,
                        Some(&receipt),
                        Some(wrong_pin),
                    )
                    .is_err(),
                    "a valid source or another valid root request cannot substitute for the recipient's summary"
                );
            }
            fa_verify::report::verify_report_expected(
                &bundle,
                &[key],
                None,
                None,
                Some(partial.digest()),
            )
            .expect("the independent outer request pin is sufficient without a receipt");
            assert!(
                fa_verify::report::verify_report_expected(&bundle, &[key], None, None, None)
                    .is_err(),
                "major-2 registry reports require recipient binding"
            );
            if let Some(original) = &partial_bundle {
                assert_eq!(&bundle, original, "OID and file export the same closure");
            } else {
                partial_bundle = Some(bundle);
            }
        }
    }
    assert_eq!(
        fixture.head(),
        before,
        "owner exports append no journal rows"
    );

    let authority = LaunchAuthority::new(
        fixture.book.clone(),
        None,
        "summary-reader",
        LaunchProfile::Agent,
        &["read", "produce"],
    )
    .unwrap();
    let argv = [
        "bundle",
        "produce",
        "--certificate",
        "-",
        "--state",
        text(&checkpoint, "oid"),
        "--json",
    ]
    .map(str::to_string);
    let (exit, output) = fa_with_authority(
        &argv,
        Files {
            cwd: None,
            stdin: Stdin::Forwarded(encoded),
        },
        &authority,
        true,
    );
    assert_eq!(exit, 0, "{}{}", output.stdout, output.stderr);
    let produced = parse_line(&output.stdout, &output.stderr);
    assert_eq!(bytes(&produced), partial_bundle.unwrap());
    let bundle_path = fixture.dir.join("partial-summary.fab");
    let receipt_path = fixture.dir.join("partial-summary.receipt");
    std::fs::write(&bundle_path, bytes(&produced)).unwrap();
    std::fs::write(&receipt_path, unhex(text(&produced, "receipt"))).unwrap();
    let args = [
        "report",
        bundle_path.to_str().unwrap(),
        "--key",
        text(&signed, "checkpoint_public_key"),
        "--receipt",
        receipt_path.to_str().unwrap(),
        "--expect",
        &expected,
        "--json",
    ]
    .map(str::to_string);
    let result = fa_verify::cli::run(&args, &|path| std::fs::read(path));
    assert_eq!(result.exit, 0, "{}{}", result.stdout, result.stderr);
    let result_json = json::parse(result.stdout.trim()).unwrap();
    assert_eq!(text(&result_json, "verdict"), "verified");
    let checks = get(&result_json, "checks").as_arr().unwrap();
    let report = checks
        .iter()
        .find(|check| text(check, "check") == "report_bundle")
        .unwrap();
    assert_eq!(text(get(report, "detail"), "report_mode"), "summary_stock");
    let coverage = checks
        .iter()
        .find(|check| text(check, "check") == "summary_coverage")
        .unwrap();
    let detail = get(coverage, "detail");
    assert_eq!(get(detail, "complete"), &Json::Bool(false));
    assert_eq!(integer(detail, "group_count"), 2);
    assert_eq!(integer(detail, "uncovered_leaf_count"), 1);
    let mut wrong_pin = args;
    wrong_pin[7] = fa_verify::blake3::hex(&partial.source_certificate().digest);
    let refused = fa_verify::cli::run(&wrong_pin, &|path| std::fs::read(path));
    assert_eq!(refused.exit, 8, "{}{}", refused.stdout, refused.stderr);
    assert!(refused.stdout.contains("recipient_certificate"));
    fixture.assert_proof_accesses_since(before, "summary-reader", 1);
}
