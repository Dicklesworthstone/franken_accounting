//! Persisted aging certificates keep their outer request pin across export.

use super::*;

pub(super) fn certify(fixture: &Fixture, arguments: &[&str]) -> Json {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&fixture.book)
        .args(arguments)
        .args(["--certify", "--json"])
        .env_remove("FA_BOOK")
        .output()
        .expect("certify retained report");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let registry = fa_cli::verbs::registry().unwrap();
    let events: Vec<_> = stdout
        .lines()
        .map(|line| {
            registry.check_line(line).unwrap();
            json::parse(line).unwrap()
        })
        .collect();
    events
        .into_iter()
        .find(|event| text(event, "event") == "report_certificate")
        .expect("retained certificate event")
}

#[test]
fn retained_aging_exports_by_oid_file_and_stdin_with_the_outer_recipient_pin() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    let first = fixture.post("portable-aging-first", "2026-03-10", "12.34", &evidence);
    let known_at = fixture.head();
    let at = known_at.to_string();
    let certificate_path = fixture.dir.join("aging.certificate");
    let metadata = certify(
        &fixture,
        &[
            "aging",
            "--account",
            "1000",
            "--as-of",
            "2026-03-31",
            "--as-known-at",
            &at,
            "--bucket",
            "0",
            "--bucket",
            "30",
            "--certificate-out",
            certificate_path.to_str().unwrap(),
        ],
    );
    assert_eq!(
        text(&metadata, "output_format"),
        "fa:effective-date-aging:v1"
    );
    let encoded = unhex(text(&metadata, "bytes"));
    assert_eq!(std::fs::read(&certificate_path).unwrap(), encoded);
    let certificate = fa::AgingCertificate::decode(&encoded).unwrap();
    let locator = format!("C:{}", text(&metadata, "oid"));
    assert_eq!(
        text(&metadata, "oid"),
        fa_verify::blake3::hex(certificate.digest())
    );
    assert_ne!(certificate.digest(), &certificate.source().digest);
    // A later backdated post and reversal cannot change the saved aging.
    fixture.post("portable-aging-later", "2026-03-15", "2.00", &evidence);
    ok(
        &fixture.book,
        &["reverse", text(&first, "vid"), "--reason", "WrongAccount"],
    );
    let state = fixture.checkpoint();
    let signed = exported(
        &fixture.book,
        &["signed-checkpoint", "--state", text(&state, "oid")],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let checkpoint = fa_verify::verify_checkpoint(&bytes(&signed), &[key]).unwrap();
    let before = fixture.head();
    let mut original_bundle = None;
    for source in [locator.as_str(), certificate_path.to_str().unwrap()] {
        let produced = ok(
            &fixture.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                source,
                "--state",
                text(&state, "oid"),
            ],
        );
        assert_eq!(text(&produced, "scope"), "report");
        assert!(text(&produced, "verify").contains(&format!(
            "--expect {}",
            fa_verify::blake3::hex(certificate.digest())
        )));
        assert!(!text(&produced, "verify").contains(&format!(
            "--expect {}",
            fa_verify::blake3::hex(&certificate.source().digest)
        )));
        let bundle = bytes(&produced);
        let receipt = unhex(text(&produced, "receipt"));
        let verified = fa_verify::report::verify_report_expected(
            &bundle,
            &[key],
            Some(&checkpoint.checkpoint),
            Some(&receipt),
            Some(certificate.digest()),
        )
        .expect("the persisted producer's historical aging verifies offline");
        assert_eq!(verified.certificate_digest, *certificate.digest());
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.known_at, known_at);
        assert!(verified.rows.is_empty());
        assert!(verified.statement.is_none());
        assert!(verified.open_items.is_none());
        let aging = verified.aging.unwrap();
        assert_eq!(aging.items.len(), 1);
        assert_eq!(aging.items[0].item.open, 1234);
        assert_eq!(aging.items[0].age_days, 21);
        assert_eq!(aging.items[0].bucket, 1);
        if let Some(expected) = &original_bundle {
            assert_eq!(&bundle, expected, "oid and file have identical closure");
        } else {
            original_bundle = Some(bundle);
        }
    }
    // A bound caller forwards canonical bytes through stdin and keeps its
    // capability; the output pin is still the outer composed certificate.
    let authority = LaunchAuthority::new(
        fixture.book.clone(),
        None,
        "aging-reader",
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
        text(&state, "oid"),
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
    assert_eq!(bytes(&produced), original_bundle.unwrap());
    let bundle_path = fixture.dir.join("aging.fab");
    let receipt_path = fixture.dir.join("aging.receipt");
    std::fs::write(&bundle_path, bytes(&produced)).unwrap();
    std::fs::write(&receipt_path, unhex(text(&produced, "receipt"))).unwrap();
    let expected = fa_verify::blake3::hex(certificate.digest());
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
    assert!(result.stdout.contains("\"verdict\":\"verified\""));
    let mut wrong_pin = args;
    wrong_pin[7] = fa_verify::blake3::hex(&certificate.source().digest);
    let refused = fa_verify::cli::run(&wrong_pin, &|path| std::fs::read(path));
    assert_eq!(refused.exit, 8, "{}{}", refused.stdout, refused.stderr);
    assert!(!refused.stdout.contains("\"verdict\":\"verified\""));
    fixture.assert_proof_accesses_since(before, "aging-reader", 1);
}

#[test]
fn due_date_aging_bundle_verifies_offline() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    let chart = write(
        &fixture.dir,
        "payables-chart.json",
        r#"{"accounts":[{"code":"2000","name":"Payables","type":"Liability","unit":"USD"},{"code":"6000","name":"Expense","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&fixture.book, &["chart", "import", &chart]);
    let invoice = write(
        &fixture.dir,
        "due-invoice.json",
        r#"{"effective_date":"2026-03-01","idempotency_key":"due-invoice","legs":[{"side":"debit","account":"6000","amount":"100.00 USD"},{"side":"credit","account":"2000","amount":"100.00 USD"}],"obligation_maturity":[{"ordinal":1,"status":"contractual","installments":[{"due_date":"2026-03-31","amount":"60.00 USD"},{"due_date":"2026-04-30","amount":"40.00 USD"}]}]}"#,
    );
    let posted = ok(
        &fixture.book,
        &["post", "--intent", &invoice, "--evidence", &evidence],
    );
    let payment = write(
        &fixture.dir,
        "due-payment.json",
        &format!(
            r#"{{"effective_date":"2026-03-20","idempotency_key":"due-payment","legs":[{{"side":"debit","account":"2000","amount":"25.00 USD","settles":[{{"entry":"{}","ordinal":1,"amount":"25.00 USD"}}]}},{{"side":"credit","account":"1000","amount":"25.00 USD"}}]}}"#,
            text(&posted, "vid"),
        ),
    );
    ok(
        &fixture.book,
        &["post", "--intent", &payment, "--evidence", &evidence],
    );
    let at = fixture.head();
    let metadata = certify(
        &fixture,
        &[
            "gl",
            "aging",
            "--account",
            "2000",
            "--basis",
            "due-date",
            "--as-of",
            "2026-04-01",
        ],
    );
    assert_eq!(text(&metadata, "output_format"), "fa:due-date-aging:v1");
    assert!(text(&metadata, "replay_command").contains("due-date-aging"));
    let certificate =
        fa::DueDateAgingCertificate::decode(&unhex(text(&metadata, "bytes"))).unwrap();
    let locator = format!("C:{}", text(&metadata, "oid"));
    assert_eq!(certificate.source().known_at.0, at);
    let request = format!(
        r#"{{"kind":"due-date-aging","account":"2000","through":"2026-04-01","known_at":{at},"buckets":[0,30,60,90]}}"#,
    );
    // Every command opens the book again. Later backdated data must not
    // replace either the retained source or the recipient's fixed question.
    fixture.post("due-later-backdated", "2026-03-10", "9.00", &evidence);
    let replay_args = [
        "replay",
        locator.as_str(),
        "--expect",
        request.as_str(),
        "--json",
    ];
    let replayed = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&fixture.book)
        .args(replay_args)
        .env_remove("FA_BOOK")
        .output()
        .unwrap();
    let stdout = String::from_utf8(replayed.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&replayed.stderr);
    assert!(
        replayed.status.success(),
        "argv={replay_args:?}\n{stdout}\n{stderr}"
    );
    let registry = fa_cli::verbs::registry().unwrap();
    let events: Vec<_> = stdout
        .lines()
        .map(|line| {
            registry.check_line(line).unwrap();
            json::parse(line).unwrap()
        })
        .collect();
    assert_eq!(text(&events[0], "event"), "due_date_aging");
    assert_eq!(text(&events[1], "event"), "report_replayed");
    assert_eq!(text(&events[1], "family"), "due-date-aging");
    assert_eq!(integer(&events[0], "known_at"), i128::from(at));
    let Json::Arr(items) = get(&events[0], "items") else {
        panic!("due-date items");
    };
    assert_eq!(items.len(), 2);
    assert_eq!(
        (text(&items[0], "open"), integer(&items[0], "days_past_due")),
        ("40.00 USD", 0)
    );
    assert_eq!(
        (text(&items[1], "open"), integer(&items[1], "days_past_due")),
        ("35.00 USD", 1)
    );
    let wrong_basis = request.replace("due-date-aging", "aging");
    let (code, error) = run(
        &fixture.book,
        &["replay", &locator, "--expect", &wrong_basis],
    );
    assert_eq!(code, 8, "{}", error.render());
    let wrong_cutoff = request.replace("2026-04-01", "2026-04-02");
    let (code, error) = run(
        &fixture.book,
        &["replay", &locator, "--expect", &wrong_cutoff],
    );
    assert_eq!(code, 8, "{}", error.render());

    // A retained native prefix is a first-class input to due-date certification.
    let at_text = at.to_string();
    let source = certify(
        &fixture,
        &["open-items", "--account", "2000", "--as-known-at", &at_text],
    );
    let source_oid = format!("C:{}", text(&source, "oid"));
    let from_source = certify(
        &fixture,
        &[
            "gl",
            "aging",
            "--basis",
            "due-date",
            "--from-source",
            &source_oid,
            "--as-of",
            "2026-04-01",
        ],
    );
    let reused = fa::DueDateAgingCertificate::decode(&unhex(text(&from_source, "bytes"))).unwrap();
    assert_eq!(reused.source(), certificate.source());
    assert_eq!(reused.output(), certificate.output());

    let state = fixture.checkpoint();
    let signed = exported(
        &fixture.book,
        &["signed-checkpoint", "--state", text(&state, "oid")],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let produced = ok(
        &fixture.book,
        &[
            "bundle",
            "produce",
            "--certificate",
            &locator,
            "--state",
            text(&state, "oid"),
        ],
    );
    let verified = fa_verify::report::verify_report_expected(
        &bytes(&produced),
        &[key],
        None,
        Some(&unhex(text(&produced, "receipt"))),
        Some(certificate.digest()),
    )
    .unwrap();
    assert_eq!(verified.output, certificate.output());
    let aging = verified.due_date_aging.unwrap();
    assert_eq!(aging.known_at, at);
    assert_eq!(aging.totals[0].amounts.credits, 7_500);
    assert_eq!(aging.items[1].item.applied, 2_500);
    assert!(aging.unscheduled.is_empty());
    assert!(
        fa_verify::report::verify_report_expected(
            &bytes(&produced),
            &[key],
            None,
            None,
            Some(&certificate.source().digest),
        )
        .is_err(),
        "the source digest must not substitute for the due-date question"
    );

    // Reconciliation must carry unscheduled liabilities along with both
    // remaining installment buckets, then survive persistence and export.
    let unscheduled = write(
        &fixture.dir,
        "unscheduled-invoice.json",
        r#"{"effective_date":"2026-03-02","idempotency_key":"unscheduled-invoice","legs":[{"side":"debit","account":"6000","amount":"10.00 USD"},{"side":"credit","account":"2000","amount":"10.00 USD"}]}"#,
    );
    ok(
        &fixture.book,
        &["post", "--intent", &unscheduled, "--evidence", &evidence],
    );
    let rec_at = fixture.head();
    let rec_at_text = rec_at.to_string();
    let rec_metadata = certify(
        &fixture,
        &[
            "gl",
            "aging",
            "--basis",
            "due-date",
            "--reconcile",
            "--account",
            "2000",
            "--as-of",
            "2026-04-01",
            "--as-known-at",
            &rec_at_text,
        ],
    );
    assert_eq!(
        text(&rec_metadata, "output_format"),
        "fa:due-date-aging-control-reconciliation:v1"
    );
    assert!(text(&rec_metadata, "replay_command").contains("due-date-aging-reconciliation"));
    let reconciliation =
        fa::DueDateAgingReconciliationCertificate::decode(&unhex(text(&rec_metadata, "bytes")))
            .unwrap();
    let rec_locator = format!("C:{}", text(&rec_metadata, "oid"));
    let rec_expect = format!(
        r#"{{"kind":"due-date-aging-reconciliation","account":"2000","through":"2026-04-01","known_at":{rec_at},"buckets":[0,30,60,90]}}"#,
    );
    let replayed = ok(
        &fixture.book,
        &["replay", &rec_locator, "--expect", &rec_expect],
    );
    assert_eq!(text(&replayed, "family"), "due-date-aging-reconciliation");
    let status = ok(
        &fixture.book,
        &[
            "certificate",
            "status",
            &rec_locator,
            "--expect",
            &rec_expect,
        ],
    );
    assert_eq!(text(&status, "status"), "Current");
    for wrong in [
        rec_expect.replace("due-date-aging-reconciliation", "aging-reconciliation"),
        rec_expect.replace("2000", "1000"),
        rec_expect.replace("2026-04-01", "2026-04-02"),
    ] {
        let (code, error) = run(&fixture.book, &["replay", &rec_locator, "--expect", &wrong]);
        assert_eq!(code, 8, "{}", error.render());
    }
    let aging_path = fixture.dir.join("due-reconciliation-aging.certificate");
    let control_path = fixture.dir.join("due-reconciliation-control.certificate");
    std::fs::write(
        &aging_path,
        reconciliation.aging_source().canonical_bytes().unwrap(),
    )
    .unwrap();
    std::fs::write(
        &control_path,
        reconciliation.control_source().canonical_bytes().unwrap(),
    )
    .unwrap();
    let reused = certify(
        &fixture,
        &[
            "gl",
            "aging",
            "--basis",
            "due-date",
            "--reconcile",
            "--account",
            "2000",
            "--as-of",
            "2026-04-01",
            "--as-known-at",
            &rec_at_text,
            "--aging-certificate",
            aging_path.to_str().unwrap(),
            "--control-certificate",
            control_path.to_str().unwrap(),
        ],
    );
    assert_eq!(text(&reused, "bytes"), text(&rec_metadata, "bytes"));
    let state = fixture.checkpoint();
    let produced = ok(
        &fixture.book,
        &[
            "bundle",
            "produce",
            "--certificate",
            &rec_locator,
            "--expect",
            &rec_expect,
            "--state",
            text(&state, "oid"),
        ],
    );
    assert!(text(&produced, "verify").contains(text(&rec_metadata, "oid")));
    let verified = fa_verify::report::verify_report_expected(
        &bytes(&produced),
        &[key],
        None,
        Some(&unhex(text(&produced, "receipt"))),
        Some(reconciliation.digest()),
    )
    .unwrap();
    assert_eq!(verified.output, reconciliation.output());
    let report = verified.due_date_aging_reconciliation.unwrap();
    assert!(report.is_reconciled());
    assert_eq!(report.known_at, rec_at);
    assert_eq!(report.aging.items.len(), 2);
    assert_eq!(report.aging.unscheduled.len(), 1);
    assert_eq!(report.rows.len(), 1);
    assert_eq!(
        (report.rows[0].posted_net, report.rows[0].open_net),
        (-8_500, -8_500)
    );
    assert_eq!(
        report.rows[0].open_item_count, 2,
        "installments are parts of one original item"
    );
    let bundle_path = fixture.dir.join("due-reconciliation.fab");
    std::fs::write(&bundle_path, bytes(&produced)).unwrap();
    let expected_digest = fa_verify::blake3::hex(reconciliation.digest());
    let verify_args = [
        "report",
        bundle_path.to_str().unwrap(),
        "--key",
        text(&signed, "checkpoint_public_key"),
        "--expect",
        &expected_digest,
        "--json",
    ]
    .map(str::to_string);
    let result = fa_verify::cli::run(&verify_args, &|path| std::fs::read(path));
    assert_eq!(result.exit, 0, "{}{}", result.stdout, result.stderr);
    assert!(result.stdout.contains("due_date_aging_reconciliation_row"));
    for wrong in [
        reconciliation.aging_source().digest(),
        &reconciliation.control_source().digest,
    ] {
        assert!(
            fa_verify::report::verify_report_expected(
                &bytes(&produced),
                &[key],
                None,
                None,
                Some(wrong),
            )
            .is_err(),
            "neither nested source pin answers the reconciled due-date question"
        );
    }
    let (code, error) = run(
        &fixture.book,
        &["bundle", "produce", "--certificate", &rec_locator],
    );
    assert_eq!(code, 2, "{}", error.render());
    let wrong_export_basis =
        rec_expect.replace("due-date-aging-reconciliation", "aging-reconciliation");
    let (code, error) = run(
        &fixture.book,
        &[
            "bundle",
            "produce",
            "--certificate",
            &rec_locator,
            "--expect",
            &wrong_export_basis,
        ],
    );
    assert_eq!(code, 2, "{}", error.render());
    assert!(
        error
            .render()
            .contains("requires kind due-date-aging-reconciliation")
    );
    let (code, error) = run(
        &fixture.book,
        &[
            "gl",
            "aging",
            "--basis",
            "due-date",
            "--reconcile",
            "--all-posting",
            "--as-of",
            "2026-04-01",
        ],
    );
    assert_eq!(code, 2, "{}", error.render());
}

#[test]
fn receivable_due_date_aging_bundle_verifies_offline_with_partial_receipts() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    let chart = write(
        &fixture.dir,
        "receivables-chart.json",
        r#"{"accounts":[{"code":"1100","name":"Receivables","type":"Asset","unit":"USD"}]}"#,
    );
    ok(&fixture.book, &["chart", "import", &chart]);
    ok(&fixture.book, &["period", "open", "FY2026-P04"]);
    let invoice_json = r#"{"effective_date":"2026-03-01","idempotency_key":"net-30-receivable","legs":[{"side":"debit","account":"1100","amount":"100.00 USD"},{"side":"credit","account":"4000","amount":"100.00 USD"}],"obligation_maturity":[{"ordinal":0,"status":"contractual","installments":[{"due_date":"2026-03-31","amount":"100.00 USD"}]}]}"#;
    let invoice = write(&fixture.dir, "net-30-invoice.json", invoice_json);
    let posted = ok(
        &fixture.book,
        &["post", "--intent", &invoice, "--evidence", &evidence],
    );
    for (key, status, amount) in [
        ("ar-missing", "\"missing_maturity\"", "10.00"),
        ("ar-disputed", "\"disputed\",\"reason_code\":7", "20.00"),
    ] {
        let input = write(
            &fixture.dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"2026-03-02","idempotency_key":"{key}","legs":[{{"side":"debit","account":"1100","amount":"{amount} USD"}},{{"side":"credit","account":"4000","amount":"{amount} USD"}}],"obligation_maturity":[{{"ordinal":0,"status":{status}}}]}}"#,
            ),
        );
        ok(
            &fixture.book,
            &["post", "--intent", &input, "--evidence", &evidence],
        );
    }
    let before_receipt = fixture.head();
    let receipt = write(
        &fixture.dir,
        "partial-ar-receipt.json",
        &format!(
            r#"{{"effective_date":"2026-04-15","idempotency_key":"partial-ar-receipt","legs":[{{"side":"debit","account":"1000","amount":"25.00 USD"}},{{"side":"credit","account":"1100","amount":"25.00 USD","settles":[{{"entry":"{}","ordinal":0,"amount":"25.00 USD"}}]}}]}}"#,
            text(&posted, "vid"),
        ),
    );
    ok(
        &fixture.book,
        &["post", "--intent", &receipt, "--evidence", &evidence],
    );
    let after_receipt = fixture.head();
    let cases = [
        ("2026-03-31", after_receipt, 10_000, 0, 0),
        ("2026-04-01", after_receipt, 10_000, 1, 0),
        ("2026-05-01", after_receipt, 7_500, 31, 2_500),
        ("2026-05-01", before_receipt, 10_000, 31, 0),
    ];
    let certificates: Vec<_> = cases
        .iter()
        .map(|(through, known_at, _, _, _)| {
            certify(
                &fixture,
                &[
                    "gl",
                    "aging",
                    "--basis",
                    "due-date",
                    "--account",
                    "1100",
                    "--as-of",
                    through,
                    "--as-known-at",
                    &known_at.to_string(),
                ],
            )
        })
        .collect();
    // A later backdated receivable must not leak into any retained prefix.
    let later = write(
        &fixture.dir,
        "late-ar-invoice.json",
        &invoice_json.replace("net-30-receivable", "late-ar-receivable"),
    );
    ok(
        &fixture.book,
        &["post", "--intent", &later, "--evidence", &evidence],
    );
    let state = fixture.checkpoint();
    let key = fixture.open().checkpoint_public_key();
    for ((through, known_at, open, overdue, applied), metadata) in
        cases.into_iter().zip(certificates)
    {
        let certificate = fa::DueDateAgingCertificate::decode(&bytes(&metadata)).unwrap();
        let locator = format!("C:{}", text(&metadata, "oid"));
        let request = format!(
            r#"{{"kind":"due-date-aging","account":"1100","through":"{through}","known_at":{known_at},"buckets":[0,30,60,90]}}"#,
        );
        let produced = ok(
            &fixture.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                &locator,
                "--expect",
                &request,
                "--state",
                text(&state, "oid"),
            ],
        );
        let verified = fa_verify::report::verify_report_expected(
            &bytes(&produced),
            &[key],
            None,
            Some(&unhex(text(&produced, "receipt"))),
            Some(certificate.digest()),
        )
        .unwrap();
        assert_eq!(verified.output, certificate.output());
        let aging = verified.due_date_aging.unwrap();
        assert_eq!(aging.known_at, known_at);
        assert_eq!(aging.items.len(), 1);
        let item = &aging.items[0];
        assert!(item.item.debit);
        assert_eq!((item.open, item.days_past_due), (open, overdue));
        assert_eq!(item.item.applied, applied);
        assert_eq!(aging.totals[0].amounts.debits, open);
        assert_eq!(aging.totals[0].amounts.credits, 0);
        assert_eq!(aging.unscheduled.len(), 2);
        assert_eq!(aging.unscheduled_totals[0].amounts.debits, 3_000);
        assert!(aging.unscheduled.iter().any(|item| {
            item.reason == fa_verify::report::VerifiedUnscheduled::MissingMaturity
        }));
        assert!(aging.unscheduled.iter().any(|item| {
            item.reason == fa_verify::report::VerifiedUnscheduled::Disputed { reason_code: 7 }
        }));
    }

    let metadata = certify(
        &fixture,
        &[
            "gl",
            "aging",
            "--basis",
            "due-date",
            "--reconcile",
            "--account",
            "1100",
            "--as-of",
            "2026-05-01",
            "--as-known-at",
            &after_receipt.to_string(),
        ],
    );
    let certificate = fa::DueDateAgingReconciliationCertificate::decode(&bytes(&metadata)).unwrap();
    let locator = format!("C:{}", text(&metadata, "oid"));
    let request = format!(
        r#"{{"kind":"due-date-aging-reconciliation","account":"1100","through":"2026-05-01","known_at":{after_receipt},"buckets":[0,30,60,90]}}"#,
    );
    let state = fixture.checkpoint();
    let produced = ok(
        &fixture.book,
        &[
            "bundle",
            "produce",
            "--certificate",
            &locator,
            "--expect",
            &request,
            "--state",
            text(&state, "oid"),
        ],
    );
    let verified = fa_verify::report::verify_report_expected(
        &bytes(&produced),
        &[key],
        None,
        Some(&unhex(text(&produced, "receipt"))),
        Some(certificate.digest()),
    )
    .unwrap();
    let report = verified.due_date_aging_reconciliation.unwrap();
    assert!(report.is_reconciled());
    assert_eq!(report.rows.len(), 1);
    assert_eq!(
        (report.rows[0].posted_net, report.rows[0].open_net),
        (10_500, 10_500)
    );
    assert_eq!(report.rows[0].open_item_count, 3);
}

#[test]
fn retained_equity_exports_recompute_the_outer_report_and_require_its_pin() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    fixture.post("portable-equity", "2026-03-10", "5.00", &evidence);
    let metadata = certify(
        &fixture,
        &[
            "statement",
            "equity-roll-forward",
            "--from",
            "2026-03-01",
            "--to",
            "2026-03-31",
        ],
    );
    let artifact = fa::ReportArtifact::decode(&unhex(text(&metadata, "bytes"))).unwrap();
    assert_eq!(
        artifact.family(),
        fa::ReportArtifactFamily::EquityRollForward
    );
    let state = fixture.checkpoint();
    let signed = exported(
        &fixture.book,
        &["signed-checkpoint", "--state", text(&state, "oid")],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let before = fixture.head();
    let locator = format!("C:{}", text(&metadata, "oid"));
    let produced = ok(
        &fixture.book,
        &[
            "bundle",
            "produce",
            "--certificate",
            &locator,
            "--state",
            text(&state, "oid"),
        ],
    );
    let bundle = bytes(&produced);
    let receipt = unhex(text(&produced, "receipt"));
    let verified = fa_verify::report::verify_report_expected(
        &bundle,
        &[key],
        None,
        Some(&receipt),
        Some(artifact.digest()),
    )
    .unwrap();
    assert_eq!(verified.output, artifact.output());
    assert_eq!(verified.certificate_digest, *artifact.digest());
    let equity = verified.equity_roll_forward.unwrap();
    assert_eq!(equity.units.len(), 1);
    assert_eq!(equity.units[0].net_income, 500);
    assert_eq!(equity.units[0].closing_total_equity, 500);
    let certificate =
        fa::EquityRollForwardCertificate::decode(&unhex(text(&metadata, "bytes"))).unwrap();
    assert!(
        fa_verify::report::verify_report_expected(
            &bundle,
            &[key],
            None,
            Some(&receipt),
            Some(certificate.source_certificate().digest()),
        )
        .is_err()
    );
    assert_eq!(fixture.head(), before);
}

fn reconciliation_expectation(known_at: u64) -> String {
    format!(
        r#"{{"kind":"aging-reconciliation","account":"1000","through":"2026-03-31","known_at":{known_at},"buckets":[0,30]}}"#
    )
}

#[test]
fn retained_aging_reconciliation_exports_both_sources_and_the_outer_recipient_pin() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    let first = fixture.post("portable-reconciliation", "2026-03-10", "12.34", &evidence);
    let known_at = fixture.head();
    let at = known_at.to_string();
    let expected = reconciliation_expectation(known_at);
    let certificate_path = fixture.dir.join("aging-reconciliation.certificate");
    let metadata = certify(
        &fixture,
        &[
            "gl",
            "aging",
            "--reconcile",
            "--account",
            "1000",
            "--as-of",
            "2026-03-31",
            "--as-known-at",
            &at,
            "--bucket",
            "0",
            "--bucket",
            "30",
            "--certificate-out",
            certificate_path.to_str().unwrap(),
        ],
    );
    let encoded = unhex(text(&metadata, "bytes"));
    assert_eq!(std::fs::read(&certificate_path).unwrap(), encoded);
    let certificate = fa::AgingReconciliationCertificate::decode(&encoded).unwrap();
    assert_eq!(
        text(&metadata, "output_format"),
        "fa:aging-control-reconciliation:v1"
    );
    assert_eq!(
        text(&metadata, "oid"),
        fa_verify::blake3::hex(certificate.digest())
    );
    assert_ne!(certificate.digest(), certificate.aging_source().digest());
    assert_ne!(certificate.digest(), &certificate.control_source().digest);
    let locator = format!("C:{}", text(&metadata, "oid"));
    fixture.post("reconciliation-later", "2026-03-15", "2.00", &evidence);
    ok(
        &fixture.book,
        &["reverse", text(&first, "vid"), "--reason", "WrongAccount"],
    );
    let state = fixture.checkpoint();
    let signed = exported(
        &fixture.book,
        &["signed-checkpoint", "--state", text(&state, "oid")],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let checkpoint = fa_verify::verify_checkpoint(&bytes(&signed), &[key]).unwrap();
    let before = fixture.head();
    let mut original_bundle = None;
    for source in [locator.as_str(), certificate_path.to_str().unwrap()] {
        let produced = ok(
            &fixture.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                source,
                "--expect",
                &expected,
                "--state",
                text(&state, "oid"),
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
            Some(&checkpoint.checkpoint),
            Some(&receipt),
            Some(certificate.digest()),
        )
        .expect("both original reconciliation sources independently recompute");
        assert_eq!(verified.certificate_digest, *certificate.digest());
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.known_at, known_at);
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
        let reconciliation = verified.aging_reconciliation.unwrap();
        assert!(reconciliation.is_reconciled());
        assert_eq!(reconciliation.rows.len(), 1);
        assert_eq!(reconciliation.rows[0].posted_net, 1234);
        assert_eq!(reconciliation.rows[0].open_net, 1234);
        assert_eq!(reconciliation.rows[0].difference, 0);
        assert_eq!(reconciliation.aging.items.len(), 1);
        assert_eq!(reconciliation.control_rows.len(), 1);
        assert_eq!(
            reconciliation.aging_certificate_digest,
            *certificate.aging_source().digest()
        );
        assert_eq!(
            reconciliation.control_certificate_digest,
            certificate.control_source().digest
        );
        for wrong_pin in [
            certificate.aging_source().digest(),
            &certificate.control_source().digest,
        ] {
            assert!(
                fa_verify::report::verify_report_expected(
                    &bundle,
                    &[key],
                    None,
                    None,
                    Some(wrong_pin),
                )
                .is_err(),
                "neither embedded source independently pins the complete workpaper"
            );
        }
        if let Some(original) = &original_bundle {
            assert_eq!(&bundle, original);
        } else {
            original_bundle = Some(bundle);
        }
    }
    let authority = LaunchAuthority::new(
        fixture.book.clone(),
        None,
        "reconciliation-reader",
        LaunchProfile::Agent,
        &["read", "produce"],
    )
    .unwrap();
    let argv = [
        "bundle",
        "produce",
        "--certificate",
        "-",
        "--expect",
        &expected,
        "--state",
        text(&state, "oid"),
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
    assert_eq!(bytes(&produced), original_bundle.unwrap());
    fixture.assert_proof_accesses_since(before, "reconciliation-reader", 1);
}

#[test]
fn reconciliation_export_requires_an_independent_exact_request_before_success() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    fixture.post("reconciliation-request", "2026-03-10", "5.00", &evidence);
    let known_at = fixture.head();
    let metadata = certify(
        &fixture,
        &[
            "gl",
            "aging",
            "--reconcile",
            "--account",
            "1000",
            "--as-of",
            "2026-03-31",
            "--as-known-at",
            &known_at.to_string(),
            "--bucket",
            "0",
            "--bucket",
            "30",
        ],
    );
    fixture.checkpoint();
    let locator = format!("C:{}", text(&metadata, "oid"));
    let before = fixture.head();
    let missing = run(
        &fixture.book,
        &["bundle", "produce", "--certificate", &locator],
    );
    assert_eq!(missing.0, 2, "{}", missing.1.render());
    for expected in [
        format!(
            r#"{{"kind":"aging-reconciliation","account":"4000","through":"2026-03-31","known_at":{known_at},"buckets":[0,30]}}"#
        ),
        format!(
            r#"{{"kind":"aging-reconciliation","account":"1000","through":"2026-03-30","known_at":{known_at},"buckets":[0,30]}}"#
        ),
        format!(
            r#"{{"kind":"aging-reconciliation","account":"1000","through":"2026-03-31","known_at":{known_at},"buckets":[0,60]}}"#
        ),
        reconciliation_expectation(known_at - 1),
    ] {
        let (exit, refused) = run(
            &fixture.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                &locator,
                "--expect",
                &expected,
            ],
        );
        assert_eq!(exit, 8, "{}", refused.render());
        assert_eq!(text(&refused, "event"), "error");
    }
    for malformed in [
        r#"{"kind":"aging-reconciliation","account":"1000","through":"2026-03-31","known_at":"HEAD","buckets":[0,30]}"#,
        r#"{"kind":"aging","account":"1000","through":"2026-03-31","known_at":1,"buckets":[0,30]}"#,
        r#"{"kind":"aging-reconciliation","account":"1000","through":"2026-03-31","known_at":1,"buckets":[0,30],"extra":true}"#,
    ] {
        let (exit, refused) = run(
            &fixture.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                &locator,
                "--expect",
                malformed,
            ],
        );
        assert_eq!(exit, 2, "{}", refused.render());
    }
    let stray = run(
        &fixture.book,
        &[
            "bundle",
            "produce",
            "--expect",
            &reconciliation_expectation(known_at),
        ],
    );
    assert_eq!(stray.0, 2, "{}", stray.1.render());
    assert_eq!(fixture.head(), before, "refused exports do not publish");
}

fn receivable_events(fixture: &Fixture, args: &[&str], expected_exit: i32) -> Vec<Json> {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&fixture.book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .output()
        .expect("run the persisted receivable workflow");
    let exit = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        exit, expected_exit,
        "argv=fa --book {:?} {args:?} --json\nstdout:\n{stdout}\nstderr:\n{stderr}",
        fixture.book,
    );
    let registry = fa_cli::verbs::registry().unwrap();
    let events: Vec<_> = stdout
        .lines()
        .map(|line| {
            registry
                .check_line(line)
                .unwrap_or_else(|error| panic!("argv={args:?}: {error}\n{stdout}\n{stderr}"));
            json::parse(line)
                .unwrap_or_else(|error| panic!("argv={args:?}: {error:?}\n{stdout}\n{stderr}"))
        })
        .collect();
    assert!(!events.is_empty(), "argv={args:?}: no events\n{stderr}");
    eprintln!(
        "receivable argv=fa --book {:?} {args:?} --json exit={exit} events={:?}",
        fixture.book,
        events
            .iter()
            .map(|event| text(event, "event"))
            .collect::<Vec<_>>(),
    );
    for event in &events {
        if matches!(
            text(event, "event"),
            "due_date_aging" | "aging_reconciled" | "report_replayed" | "error"
        ) {
            eprintln!("{}", event.render());
        }
    }
    events
}

fn receivable_event<'a>(events: &'a [Json], name: &str) -> &'a Json {
    events
        .iter()
        .find(|event| text(event, "event") == name)
        .unwrap_or_else(|| panic!("missing {name} event: {events:?}"))
}

fn receivable_fixture() -> (Fixture, String) {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    let chart = write(
        &fixture.dir,
        "receivables-chart.json",
        r#"{"accounts":[{"code":"1100","name":"Receivables","type":"Asset","unit":"USD"}]}"#,
    );
    receivable_events(&fixture, &["chart", "import", &chart], 0);
    (fixture, evidence)
}

fn receivable_invoice(fixture: &Fixture, key: &str, amount: &str, terms: Option<&str>) -> String {
    let maturity = terms.map_or_else(String::new, |terms| {
        format!(r#", "obligation_maturity":{terms}"#)
    });
    write(
        &fixture.dir,
        &format!("{key}.json"),
        &format!(
            r#"{{"effective_date":"2026-03-01","idempotency_key":"{key}","legs":[{{"side":"debit","account":"1100","amount":"{amount} USD"}},{{"side":"credit","account":"4000","amount":"{amount} USD"}}]{maturity}}}"#,
        ),
    )
}

#[test]
fn receivable_due_date_aging_replays_and_verifies_offline() {
    let (fixture, evidence) = receivable_fixture();
    let invoice = receivable_invoice(
        &fixture,
        "receivable-contractual",
        "100.00",
        Some(
            r#"[{"ordinal":0,"status":"contractual","installments":[{"due_date":"2026-03-31","amount":"60.00 USD"},{"due_date":"2026-04-30","amount":"40.00 USD"}]}]"#,
        ),
    );
    let posted = receivable_events(
        &fixture,
        &["post", "--intent", &invoice, "--evidence", &evidence],
        0,
    );
    let receipt = write(
        &fixture.dir,
        "receivable-partial-receipt.json",
        &format!(
            r#"{{"effective_date":"2026-03-20","idempotency_key":"receivable-partial-receipt","legs":[{{"side":"debit","account":"1000","amount":"25.00 USD"}},{{"side":"credit","account":"1100","amount":"25.00 USD","settles":[{{"entry":"{}","ordinal":0,"amount":"25.00 USD"}}]}}]}}"#,
            text(&posted[0], "vid"),
        ),
    );
    receivable_events(
        &fixture,
        &["post", "--intent", &receipt, "--evidence", &evidence],
        0,
    );
    let at = fixture.head();
    let certified = receivable_events(
        &fixture,
        &[
            "gl",
            "aging",
            "--account",
            "1100",
            "--basis",
            "due-date",
            "--as-of",
            "2026-04-01",
            "--certify",
        ],
        0,
    );
    let scheduled = receivable_event(&certified, "due_date_aging");
    assert_eq!(integer(scheduled, "known_at"), i128::from(at));
    let items = get(scheduled, "items").as_arr().unwrap();
    assert_eq!(items.len(), 2, "{}", scheduled.render());
    for (item, due, open, days, bucket) in [
        (&items[0], "2026-04-30", "40.00 USD", 0, 0),
        (&items[1], "2026-03-31", "35.00 USD", 1, 1),
    ] {
        assert_eq!(text(item, "entry"), text(&posted[0], "vid"));
        assert_eq!(integer(item, "ordinal"), 0);
        assert_eq!(text(item, "side"), "debit");
        assert_eq!(text(item, "applied"), "25.00 USD");
        assert_eq!(text(item, "item_open"), "75.00 USD");
        assert_eq!(text(item, "due_date"), due);
        assert_eq!(text(item, "open"), open);
        assert_eq!(integer(item, "days_past_due"), days);
        assert_eq!(integer(item, "bucket"), bucket);
    }
    let totals = get(scheduled, "totals").as_arr().unwrap();
    assert_eq!(totals.len(), 1);
    assert_eq!(text(&totals[0], "debits"), "75.00 USD");
    assert_eq!(text(&totals[0], "credits"), "0.00 USD");
    assert!(get(scheduled, "unscheduled").as_arr().unwrap().is_empty());
    let metadata = receivable_event(&certified, "report_certificate");
    assert_eq!(text(metadata, "output_format"), "fa:due-date-aging:v1");
    let certificate = fa::DueDateAgingCertificate::decode(&bytes(metadata)).unwrap();
    assert_eq!(certificate.source().known_at.0, at);
    let locator = format!("C:{}", text(metadata, "oid"));
    let request = format!(
        r#"{{"kind":"due-date-aging","account":"1100","through":"2026-04-01","known_at":{at},"buckets":[0,30,60,90]}}"#,
    );

    // Omitted terms, explicitly missing maturity, and a disputed dated claim
    // all remain visible without inventing contractual due dates.
    for (key, amount, terms) in [
        ("receivable-no-terms", "10.00", None),
        (
            "receivable-missing-maturity",
            "7.00",
            Some(r#"[{"ordinal":0,"status":"missing_maturity"}]"#),
        ),
        (
            "receivable-disputed",
            "9.00",
            Some(
                r#"[{"ordinal":0,"status":"disputed","reason_code":7,"installments":[{"due_date":"2026-03-31","amount":"9.00 USD"}]}]"#,
            ),
        ),
    ] {
        let intent = receivable_invoice(&fixture, key, amount, terms);
        receivable_events(
            &fixture,
            &["post", "--intent", &intent, "--evidence", &evidence],
            0,
        );
    }
    let rec_at = fixture.head();
    let rec_at_text = rec_at.to_string();
    let reconciled = receivable_events(
        &fixture,
        &[
            "gl",
            "aging",
            "--account",
            "1100",
            "--basis",
            "due-date",
            "--as-of",
            "2026-04-01",
            "--as-known-at",
            &rec_at_text,
            "--reconcile",
            "--certify",
        ],
        0,
    );
    let aging = receivable_event(&reconciled, "due_date_aging");
    assert_eq!(get(aging, "items"), get(scheduled, "items"));
    let unscheduled = get(aging, "unscheduled").as_arr().unwrap();
    assert_eq!(unscheduled.len(), 3, "{}", aging.render());
    for (reason, open) in [
        ("no_terms", "10.00 USD"),
        ("missing_maturity", "7.00 USD"),
        ("disputed", "9.00 USD"),
    ] {
        let item = unscheduled
            .iter()
            .find(|item| text(item, "reason") == reason)
            .unwrap();
        assert_eq!(text(item, "side"), "debit");
        assert_eq!(text(item, "open"), open);
        if reason == "disputed" {
            assert_eq!(integer(item, "reason_code"), 7);
        } else {
            assert_eq!(get(item, "reason_code"), &Json::Null);
        }
    }
    let control = receivable_event(&reconciled, "aging_reconciled");
    let rows = get(control, "rows").as_arr().unwrap();
    assert_eq!(rows.len(), 1, "{}", control.render());
    assert_eq!(text(&rows[0], "posted_net"), "101.00 USD");
    assert_eq!(text(&rows[0], "open_net"), "101.00 USD");
    assert_eq!(text(&rows[0], "difference"), "0.00 USD");
    assert_eq!(integer(&rows[0], "open_item_count"), 4);
    let rec_metadata = receivable_event(&reconciled, "report_certificate");
    let reconciliation =
        fa::DueDateAgingReconciliationCertificate::decode(&bytes(rec_metadata)).unwrap();
    let rec_locator = format!("C:{}", text(rec_metadata, "oid"));
    let rec_request = format!(
        r#"{{"kind":"due-date-aging-reconciliation","account":"1100","through":"2026-04-01","known_at":{rec_at},"buckets":[0,30,60,90]}}"#,
    );

    // A later commit with an earlier effective date changes today's control,
    // while each retained question must still reproduce its original bytes.
    let later = receivable_invoice(&fixture, "receivable-later-backdated", "5.00", None);
    receivable_events(
        &fixture,
        &["post", "--intent", &later, "--evidence", &evidence],
        0,
    );
    let current = receivable_events(
        &fixture,
        &[
            "gl",
            "aging",
            "--account",
            "1100",
            "--basis",
            "due-date",
            "--as-of",
            "2026-04-01",
            "--reconcile",
        ],
        0,
    );
    let current_rows = get(receivable_event(&current, "aging_reconciled"), "rows")
        .as_arr()
        .unwrap();
    assert_eq!(text(&current_rows[0], "posted_net"), "106.00 USD");
    assert_eq!(text(&current_rows[0], "open_net"), "106.00 USD");
    let replayed = receivable_events(&fixture, &["replay", &locator, "--expect", &request], 0);
    assert_eq!(
        get(receivable_event(&replayed, "due_date_aging"), "data"),
        get(scheduled, "data"),
        "the retained receivable schedule must not absorb later backdated items",
    );
    let output_path = fixture.dir.join("receivable-reconciliation.replayed");
    let replayed = receivable_events(
        &fixture,
        &[
            "replay",
            &rec_locator,
            "--expect",
            &rec_request,
            "--output",
            output_path.to_str().unwrap(),
        ],
        0,
    );
    assert_eq!(
        integer(receivable_event(&replayed, "report_replayed"), "known_at"),
        i128::from(rec_at)
    );
    assert_eq!(
        std::fs::read(&output_path).unwrap(),
        reconciliation.output()
    );
    receivable_events(
        &fixture,
        &[
            "replay",
            &locator,
            "--expect",
            &request.replace("1100", "1000"),
        ],
        8,
    );

    let state = fixture.checkpoint();
    let signed = exported(
        &fixture.book,
        &["signed-checkpoint", "--state", text(&state, "oid")],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    for (name, locator, expectation, digest, canonical, known_at, is_reconciliation) in [
        (
            "receivable-aging",
            &locator,
            &request,
            certificate.digest(),
            certificate.output(),
            at,
            false,
        ),
        (
            "receivable-reconciliation",
            &rec_locator,
            &rec_request,
            reconciliation.digest(),
            reconciliation.output(),
            rec_at,
            true,
        ),
    ] {
        let mut export_args = vec![
            "bundle",
            "produce",
            "--certificate",
            locator.as_str(),
            "--state",
            text(&state, "oid"),
        ];
        if is_reconciliation {
            export_args.extend(["--expect", expectation.as_str()]);
        }
        let exported = receivable_events(&fixture, &export_args, 0);
        let produced = receivable_event(&exported, "bundle_produced");
        let verified = fa_verify::report::verify_report_expected(
            &bytes(produced),
            &[key],
            None,
            Some(&unhex(text(produced, "receipt"))),
            Some(digest),
        )
        .unwrap_or_else(|error| panic!("{name}: independent verification failed: {error:?}"));
        assert_eq!(
            verified.output, canonical,
            "{name}: canonical output changed"
        );
        let aging = if is_reconciliation {
            let report = verified.due_date_aging_reconciliation.as_ref().unwrap();
            assert!(report.is_reconciled());
            assert_eq!(report.known_at, known_at);
            assert_eq!(
                (report.rows[0].posted_net, report.rows[0].open_net),
                (10_100, 10_100)
            );
            assert_eq!(report.rows[0].open_item_count, 4);
            assert_eq!(report.aging.unscheduled_totals[0].amounts.debits, 2_600);
            assert_eq!(report.aging.unscheduled_totals[0].amounts.credits, 0);
            for reason in [
                fa_verify::report::VerifiedUnscheduled::NoTerms,
                fa_verify::report::VerifiedUnscheduled::MissingMaturity,
                fa_verify::report::VerifiedUnscheduled::Disputed { reason_code: 7 },
            ] {
                assert!(
                    report
                        .aging
                        .unscheduled
                        .iter()
                        .any(|item| item.reason == reason)
                );
            }
            &report.aging
        } else {
            let report = verified.due_date_aging.as_ref().unwrap();
            assert!(report.unscheduled.is_empty());
            report
        };
        assert_eq!(aging.known_at, known_at);
        assert_eq!(aging.totals[0].amounts.debits, 7_500);
        assert_eq!(aging.totals[0].amounts.credits, 0);
        assert_eq!(aging.items.len(), 2);
        assert_eq!(
            (aging.items[0].open, aging.items[0].days_past_due),
            (4_000, 0)
        );
        assert_eq!(
            (aging.items[1].open, aging.items[1].days_past_due),
            (3_500, 1)
        );
        assert!(
            aging.items.iter().all(|part| part.item.debit
                && part.item.applied == 2_500
                && part.item.open == 7_500)
        );

        let bundle_path = fixture.dir.join(format!("{name}.fab"));
        std::fs::write(&bundle_path, bytes(produced)).unwrap();
        let expected = fa_verify::blake3::hex(digest);
        let argv = [
            "report",
            bundle_path.to_str().unwrap(),
            "--key",
            text(&signed, "checkpoint_public_key"),
            "--expect",
            &expected,
            "--json",
        ]
        .map(str::to_string);
        let result = fa_verify::cli::run(&argv, &|path| std::fs::read(path));
        assert_eq!(
            result.exit, 0,
            "argv=fa-verify {argv:?}\n{}\n{}",
            result.stdout, result.stderr
        );
        let result_json = json::parse(&result.stdout).unwrap();
        eprintln!(
            "receivable offline argv=fa-verify {argv:?} exit={}",
            result.exit
        );
        assert_eq!(
            text(&result_json, "verdict"),
            "verified",
            "argv=fa-verify {argv:?}: {}",
            result.stdout,
        );
        let checks = get(&result_json, "checks").as_arr().unwrap();
        let total = checks
            .iter()
            .find(|check| text(check, "check") == "due_date_aging_total")
            .unwrap();
        assert_eq!(text(get(total, "detail"), "debits"), "7500");
        if is_reconciliation {
            let row = checks
                .iter()
                .find(|check| text(check, "check") == "due_date_aging_reconciliation_row")
                .unwrap();
            assert_eq!(text(get(row, "detail"), "posted_net"), "10100");
            assert_eq!(text(get(row, "detail"), "open_net"), "10100");
            assert_eq!(text(get(row, "detail"), "difference"), "0");
        }
    }
}

#[test]
fn receivable_maturity_refuses_invalid_terms_without_posting() {
    let (fixture, evidence) = receivable_fixture();
    let before = fixture.head();
    for (name, terms, refusal) in [
        (
            "duplicate-ordinal",
            r#"[{"ordinal":0,"status":"contractual","installments":[{"due_date":"2026-03-31","amount":"100.00 USD"}]},{"ordinal":0,"status":"missing_maturity"}]"#,
            "terms must be strictly ascending by leg ordinal",
        ),
        (
            "wrong-total",
            r#"[{"ordinal":0,"status":"contractual","installments":[{"due_date":"2026-03-31","amount":"99.99 USD"}]}]"#,
            "installments must total exactly the leg's amount",
        ),
        (
            "wrong-unit",
            r#"[{"ordinal":0,"status":"contractual","installments":[{"due_date":"2026-03-31","amount":"100.00 EUR"}]}]"#,
            "is not in leg 0's unit",
        ),
        (
            "contractual-without-installments",
            r#"[{"ordinal":0,"status":"contractual"}]"#,
            "a Contractual term declares at least one installment",
        ),
        (
            "empty-terms",
            "[]",
            "obligation_maturity is empty; omit it instead",
        ),
        (
            "missing-with-installments",
            r#"[{"ordinal":0,"status":"missing_maturity","installments":[{"due_date":"2026-03-31","amount":"100.00 USD"}]}]"#,
            "a MissingMaturity term declares no installment",
        ),
        (
            "disputed-without-reason",
            r#"[{"ordinal":0,"status":"disputed"}]"#,
            "a disputed obligation names its reason_code",
        ),
    ] {
        let intent = receivable_invoice(
            &fixture,
            &format!("receivable-invalid-{name}"),
            "100.00",
            Some(terms),
        );
        let events = receivable_events(
            &fixture,
            &["post", "--intent", &intent, "--evidence", &evidence],
            2,
        );
        let error = receivable_event(&events, "error");
        assert!(
            error.render().contains(refusal),
            "{name}: {}",
            error.render()
        );
        assert_eq!(
            fixture.head(),
            before,
            "{name}: invalid receivable terms must not publish"
        );
    }
}
