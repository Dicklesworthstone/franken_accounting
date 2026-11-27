//! Persisted external-feed certificates exported after reopening, then checked
//! from only the delivered files by the dependency-free recipient verifier.

use super::*;

fn event(output: &str, name: &str) -> Json {
    output
        .lines()
        .map(|line| json::parse(line).unwrap())
        .find(|value| value.get("event").and_then(Json::as_str) == Some(name))
        .unwrap_or_else(|| panic!("missing {name}: {output}"))
        .get("data")
        .unwrap()
        .clone()
}

fn unhex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn expectation(at: &str) -> String {
    format!(
        r#"{{"kind":"external-feed-reconciliation","feed":"vendor-ap","control_account":"2000","through":"2026-03-31","known_at":{at}}}"#,
    )
}

fn certify(f: &Fixture, at: &str, name: &str) -> (String, fa::ExternalFeedCertificate) {
    let path = f.dir.join(format!("{name}.cert"));
    let result = f.ok(&[
        "subledger",
        "reconcile-feed",
        "vendor-ap",
        "--control",
        "2000",
        "--as-of",
        "2026-03-31",
        "--as-known-at",
        at,
        "--certificate-out",
        path.to_str().unwrap(),
    ]);
    let certificate = fa::ExternalFeedCertificate::decode(&std::fs::read(path).unwrap()).unwrap();
    let metadata = event(&result, "report_certificate");
    assert_eq!(
        text(&metadata, "oid"),
        fa_verify::blake3::hex(certificate.digest()),
    );
    (format!("C:{}", text(&metadata, "oid")), certificate)
}

#[test]
fn reopened_external_feed_export_preserves_historical_and_unreconciled_gross_reports() {
    let f = Fixture::new();
    let input = f.file(
        "portable-external.json",
        &format!(
            r#"{{"feed":"vendor-ap","batch_key":"portable-march-001","effective_date":"2026-03-15","rows":[{{"source_digest":"{}","account":"6000","side":"debit","amount":"60.00 USD"}},{{"source_digest":"{}","account":"2000","side":"credit","amount":"100.00 USD","party":"V-1"}},{{"source_digest":"{}","account":"6000","side":"debit","amount":"40.00 USD"}}]}}"#,
            "02".repeat(32), "03".repeat(32), "01".repeat(32),
        ),
    );
    let detail_path = f.dir.join("portable-external-detail.bin");
    let detail = data(&f.ok(&[
        "subledger",
        "detail",
        "--input",
        &input,
        "--out",
        detail_path.to_str().unwrap(),
    ]));
    let document = data(&f.ok(&[
        "document",
        "add",
        detail_path.to_str().unwrap(),
        "--kind",
        "Workpaper",
        "--grade",
        "HumanUpload",
    ]));
    let document_oid = text(&document, "oid");
    assert_eq!(document_oid, text(&detail, "document_oid"));
    f.ok(&["attest", "review", &document_oid, "--as", "reviewer"]);
    let posted = data(&f.ok(&[
        "subledger",
        "feed",
        "--document",
        &format!("D:{document_oid}"),
        "--date",
        "2026-03-15",
        "--key",
        "portable-external-summary",
    ]));
    let recorded = data(&f.ok(&["subledger", "verify-feed", &text(&posted, "vid")]));
    let payable = rows(&recorded, "summary_legs")
        .iter()
        .find(|leg| text(leg, "side") == "credit")
        .unwrap();
    let dimensions = payable.get("dimension_set").unwrap().render();
    let child_commit = text(&detail, "doc_commit");
    let parent_input = f.file("population.json", &format!(
        r#"{{"feed":"vendor-ap","extract_id":"source-march","from":"2026-03-01","through":"2026-03-31","detail_rows":3,"children":[{{"batch_key":"portable-march-001","doc_commit":"{child_commit}"}}],"totals":[{{"account":"6000","debits":"100.00 USD","credits":"0.00 USD"}},{{"account":"2000","debits":"0.00 USD","credits":"100.00 USD","dimension_set":{dimensions}}}]}}"#,
    ));
    let parent_path = f.dir.join("population.bin");
    let parent_path = parent_path.to_str().unwrap();
    let prepared = data(&f.ok(&[
        "subledger",
        "manifest",
        "--input",
        &parent_input,
        "--out",
        parent_path,
    ]));
    let parent = data(&f.ok(&[
        "document",
        "add",
        parent_path,
        "--kind",
        "Workpaper",
        "--grade",
        "HumanUpload",
        "--mime",
        &text(&prepared, "mime"),
    ]));
    let parent_oid = text(&parent, "oid");
    let original_at = f.head();
    let original = certify(&f, &original_at, "original-external");
    f.ok(&["attest", "review", &parent_oid, "--as", "reviewer"]);
    let review_at = f.head();

    // Both sides contaminate the same dimension cell. Their zero net effect
    // cannot hide the absence of corresponding reviewed external detail.
    let contamination = f.file(
        "portable-uncovered.json",
        r#"{"effective_date":"2026-03-16","idempotency_key":"portable-uncovered","legs":[{"side":"debit","account":"2000","amount":"10.00 USD","party":"V-1"},{"side":"credit","account":"2000","amount":"10.00 USD","party":"V-1"}]}"#,
    );
    f.ok(&[
        "post",
        "--intent",
        &contamination,
        "--evidence",
        &f.evidence,
    ]);
    let current_at = f.head();
    let current = certify(&f, &current_at, "current-external");
    let state = data(&f.ok(&["checkpoint", "create", "--grant", "witness"]));
    let before = f.head();

    // Refused exports must not create either delivery file, even when the
    // original artifact and a valid checkpoint are both available.
    let question = expectation(&original_at);
    let wrong_prefix = expectation(&(original_at.parse::<u64>().unwrap() + 1).to_string());
    for (index, (expected, exit)) in [
        (None, 2),
        (Some(question.replace("vendor-ap", "another-feed")), 8),
        (Some(question.replace("2000", "1200")), 8),
        (Some(question.replace("2026-03-31", "2026-03-30")), 8),
        (Some(wrong_prefix), 8),
        (Some(expectation("\"HEAD\"")), 2),
    ]
    .into_iter()
    .enumerate()
    {
        let bundle = f.dir.join(format!("refused-external-{index}.fab"));
        let receipt = f.dir.join(format!("refused-external-{index}.receipt"));
        let mut args = vec![
            "bundle",
            "produce",
            "--certificate",
            original.0.as_str(),
            "--out",
            bundle.to_str().unwrap(),
            "--receipt-out",
            receipt.to_str().unwrap(),
        ];
        if let Some(expected) = expected.as_deref() {
            args.extend(["--expect", expected]);
        }
        let (status, refused) = f.run(&args);
        assert_eq!(status, exit, "{refused}");
        assert!(!refused.contains("\"event\":\"bundle_produced\""));
        assert!(
            !bundle.exists() && !receipt.exists(),
            "refusal created output files"
        );
    }

    for ((locator, certificate), at, reconciled, control_debits, control_credits) in [
        (original, original_at, true, 0, 10_000),
        (current, current_at, false, 1_000, 11_000),
    ] {
        let bundle_path = f.dir.join(format!("external-{at}.fab"));
        let receipt_path = f.dir.join(format!("external-{at}.receipt"));
        let produced = data(&f.ok(&[
            "bundle",
            "produce",
            "--certificate",
            &locator,
            "--expect",
            &expectation(&at),
            "--state",
            &text(&state, "oid"),
            "--out",
            bundle_path.to_str().unwrap(),
            "--receipt-out",
            receipt_path.to_str().unwrap(),
        ]));
        assert_eq!(text(&produced, "scope"), "report");
        assert_eq!(produced.get("bytes"), Some(&Json::Null));
        let expected = fa_verify::report::ExternalFeedRequest {
            feed: "vendor-ap".into(),
            control_account: fa_model::account_vid(certificate.book_id(), "2000").0,
            effective_through: fa_time::DateDay::parse("2026-03-31").unwrap().0,
            known_at: at.parse().unwrap(),
        };
        let key_hex = text(&produced, "checkpoint_public_key");
        let key: [u8; 32] = unhex(&key_hex).try_into().unwrap();
        let bundle = std::fs::read(&bundle_path).unwrap();
        let receipt = std::fs::read(&receipt_path).unwrap();
        let verified = fa_verify::report::verify_report_external_feed_expected(
            &bundle,
            &[key],
            None,
            Some(&receipt),
            &expected,
            Some(certificate.digest()),
        )
        .unwrap();
        assert_eq!(verified.output, certificate.output());
        assert_eq!(&verified.certificate_digest, certificate.digest());
        let report = verified.external_feed.unwrap();
        assert_eq!(report.reconciled, reconciled);
        assert_eq!(report.known_at, expected.known_at);
        assert_eq!(report.batches.len(), 1);
        assert_eq!(report.batches[0].detail_rows, 3);
        assert_eq!(
            fa_verify::blake3::hex(&report.batches[0].document_oid),
            document_oid
        );
        assert_eq!(report.contributions.len(), 1);
        assert_eq!(report.unattributed.len(), if reconciled { 0 } else { 2 });
        assert_eq!(report.totals.len(), 1);
        let total = &report.totals[0];
        assert_eq!([total.detail_debits, total.detail_credits], [0, 10_000]);
        assert_eq!(
            [total.control_debits, total.control_credits],
            [control_debits, control_credits]
        );
        assert_eq!(
            [total.register_debits, total.register_credits],
            [control_debits, control_credits]
        );
        assert_eq!([total.pending_debits, total.pending_credits], [0, 0]);

        let control = format!("0x{:032x}", expected.control_account);
        let through = expected.effective_through.to_string();
        let digest = fa_verify::blake3::hex(certificate.digest());
        assert!(text(&produced, "verify").contains(&format!(
            "--external-feed=vendor-ap --control-account {control} --through {through} --known-at {at}",
        )));
        assert!(text(&produced, "verify").contains(&format!("--expect {digest}")));
        let args = [
            "report",
            bundle_path.to_str().unwrap(),
            "--key",
            &key_hex,
            "--receipt",
            receipt_path.to_str().unwrap(),
            "--expect",
            &digest,
            "--external-feed",
            "vendor-ap",
            "--control-account",
            &control,
            "--through",
            &through,
            "--known-at",
            &at,
            "--json",
        ]
        .map(str::to_string);
        // This callback is the verifier's entire I/O surface. No native book,
        // registry checkout, document store or certificate cache is available.
        let offline = |path: &str| {
            assert!(
                path == bundle_path.to_str().unwrap()
                    || path == receipt_path.to_str().unwrap()
                    || path == parent_path
            );
            std::fs::read(path)
        };
        let result = fa_verify::cli::run(&args, &offline);
        assert_eq!(result.exit, 0, "{}{}", result.stdout, result.stderr);
        assert!(
            result
                .stdout
                .contains("\"report_mode\":\"external_feed_reconciliation\"")
        );
        assert!(
            result
                .stdout
                .contains(&format!("\"reconciled\":{reconciled}"))
        );
        assert!(
            result
                .stdout
                .contains("\"native_graph_mirrors\":\"not_judged\"")
        );
        assert!(
            result
                .stdout
                .contains("\"source_system_completeness\":\"not_judged\"")
        );
        let mut with_parent = args.to_vec();
        with_parent.extend(["--reviewed-population-manifest".into(), parent_path.into()]);
        let result = fa_verify::cli::run(&with_parent, &offline);
        assert!(
            result.stdout.contains("external_feed_manifest_review"),
            "{}{}",
            result.stdout,
            result.stderr
        );
        if reconciled {
            // The signed checkpoint is newer than the report. Its later
            // review cannot satisfy the independently selected earlier prefix.
            assert_eq!(result.exit, 8, "{}", result.stdout);
        } else {
            assert_eq!(result.exit, 0, "{}{}", result.stdout, result.stderr);
            assert!(result.stdout.contains(&parent_oid));
            assert!(
                result
                    .stdout
                    .contains(&format!("\"review_seq\":{review_at}"))
            );
            assert!(result.stdout.contains("external_feed_population"));
            // Renaming the extract leaves every source total and child intact
            // but changes the exact Workpaper that needs its own review.
            let changed = |path: &str| {
                let mut bytes = offline(path)?;
                if path == parent_path {
                    let at = bytes
                        .windows(b"source-march".len())
                        .position(|s| s == b"source-march")
                        .unwrap();
                    bytes[at] = b'S';
                }
                Ok(bytes)
            };
            let result = fa_verify::cli::run(&with_parent, &changed);
            assert_eq!(result.exit, 8, "{}", result.stdout);
            assert!(result.stdout.contains("external_feed_manifest_review"));
            with_parent[args.len()] = "--population-manifest".into();
            assert_eq!(fa_verify::cli::run(&with_parent, &changed).exit, 0);
        }
        let generic = args[..8]
            .iter()
            .cloned()
            .chain(["--json".into()])
            .collect::<Vec<_>>();
        assert_eq!(fa_verify::cli::run(&generic, &offline).exit, 8);
        for (index, changed) in [
            (9, "another-feed".into()),
            (11, "0x1".into()),
            (13, (expected.effective_through + 1).to_string()),
            (15, (expected.known_at + 1).to_string()),
            (7, "00".repeat(32)),
        ] {
            let mut wrong = args.clone();
            wrong[index] = changed;
            let result = fa_verify::cli::run(&wrong, &offline);
            assert_eq!(result.exit, 8, "{}{}", result.stdout, result.stderr);
        }
    }
    assert_eq!(
        f.head(),
        before,
        "successful and refused exports leave the book unchanged"
    );
}
