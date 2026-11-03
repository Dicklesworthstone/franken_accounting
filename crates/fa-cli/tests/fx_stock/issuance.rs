//! Issued built-in functional statements keep the complete saved question,
//! original carrying values and certificate across real process boundaries.

use super::*;

fn event<'a>(events: &'a [Json], name: &str) -> &'a Json {
    data(
        events
            .iter()
            .find(|event| text(event, "event") == name)
            .unwrap_or_else(|| panic!("missing {name}: {events:?}")),
    )
}

fn issue(fixture: &Fixture, reference: &str) {
    let issuance = ok(
        &fixture.book,
        &[
            "statement",
            "issue",
            "--certificate",
            reference,
            "--issued-to",
            "board",
            "--dry-run",
        ],
    );
    let plan = fixture.file("functional-issuance.plan", text(data(&issuance), "bytes"));
    let approval = ok(
        &fixture.book,
        &[
            "approve",
            "--proposal",
            text(data(&issuance), "proposal_digest"),
            "--as",
            "issuance-controller",
        ],
    );
    ok(
        &fixture.book,
        &[
            "statement",
            "issue",
            "--plan",
            &plan,
            "--approval",
            text(data(&approval), "approval_vid"),
        ],
    );
}

#[test]
fn functional_issued_statements_preserve_carrying_values_comparatives_and_portable_proof() {
    for (mode, line, original_amount, corrected_amount, native_amount, seed) in [
        (
            "balance-sheet",
            "assets",
            "350.00 USD",
            "370.00 USD",
            "300.00 EUR",
            0xb8,
        ),
        (
            "income-statement",
            "net_income",
            "240.00 USD",
            "260.00 USD",
            "200.00 EUR",
            0xb9,
        ),
    ] {
        let fixture = Fixture::create(Some(seed));
        fixture.post("issued-january", "2026-01-05", "100.00", 11);
        let february = fixture.post("issued-february", "2026-02-05", "200.00", 12);
        let original_path = fixture.dir.join("original-functional.cert");
        let original = ok_many(
            &fixture.book,
            &[
                "statement",
                mode,
                "--functional",
                "--for",
                "FY2026-P02",
                "--compare",
                "FY2026-P01",
                "--certificate-out",
                original_path.to_str().unwrap(),
            ],
        );
        let saved = event(&original, "statement");
        // Independent oracle: January is EUR100 * 1.1 = USD110;
        // February is EUR200 * 1.2 = USD240. Stock also carries January.
        assert_eq!(
            statement_amounts(saved, line, "USD"),
            &[
                Json::Str(original_amount.into()),
                Json::Str("110.00 USD".into())
            ]
        );
        let bytes = std::fs::read(&original_path).unwrap();
        assert!(bytes.starts_with(b"fa:report-certificate:v5"));
        let source = fa::ReportCertificate::decode(&bytes).unwrap();
        let reference = format!("C:{}", text(event(&original, "report_certificate"), "oid"));
        issue(&fixture, &reference);
        fixture.compact(seed);

        // Correct the original valuation with an inherited reversal and a
        // new supported valuation. Native EUR stays unchanged; USD increases
        // by 20. Neither an unused later quote nor the corrected source may
        // reprice the statement that was actually issued.
        ok(
            &fixture.book,
            &[
                "reverse",
                text(data(&february), "vid"),
                "--reason",
                "WrongAmount",
                "--evidence",
                &fixture.evidence,
            ],
        );
        fixture.post("corrected-february", "2026-02-05", "200.00", 13);
        fixture.rate("unused-later-quote", "2026-02-05", 99);
        fixture.compact(seed);
        let current = ok(
            &fixture.book,
            &[
                "statement",
                mode,
                "--functional",
                "--for",
                "FY2026-P02",
                "--compare",
                "FY2026-P01",
                "--as-currently-stated",
            ],
        );
        assert_eq!(
            statement_amounts(data(&current), line, "USD"),
            &[
                Json::Str(corrected_amount.into()),
                Json::Str("110.00 USD".into())
            ]
        );
        assert!(
            integer(current.get("coordinate").unwrap(), "known_at") > i128::from(source.known_at.0)
        );
        let native = ok(
            &fixture.book,
            &[
                "statement",
                mode,
                "--for",
                "FY2026-P02",
                "--compare",
                "FY2026-P01",
                "--as-currently-stated",
            ],
        );
        assert_eq!(
            statement_amounts(data(&native), line, "EUR"),
            &[
                Json::Str(native_amount.into()),
                Json::Str("100.00 EUR".into())
            ]
        );

        let before = head(&fixture.book);
        for (index, view) in [
            vec!["--as-originally-reported"],
            vec!["--as-issued-to", "board"],
            vec!["--as-reported-in", &reference],
            vec!["--as-reported-in", &reference, "--compare", "FY2026-P01"],
        ]
        .into_iter()
        .enumerate()
        {
            let path = fixture.dir.join(format!("reported-{index}.cert"));
            let mut args = vec![
                "statement",
                mode,
                "--functional",
                "--for",
                "FY2026-P02",
                "--certificate-out",
                path.to_str().unwrap(),
            ];
            args.extend(view);
            let reported = ok_many(&fixture.book, &args);
            assert_eq!(event(&reported, "statement"), saved);
            assert_eq!(std::fs::read(path).unwrap(), bytes);
            assert_eq!(
                text(event(&reported, "report_certificate"), "oid"),
                &reference[2..]
            );
        }
        assert_eq!(
            head(&fixture.book),
            before,
            "reusing an issued certificate publishes nothing"
        );
        let replay = ok_many(&fixture.book, &["replay", &reference]);
        assert_eq!(event(&replay, "statement"), saved);

        let checkpoint = ok(
            &fixture.book,
            &["checkpoint", "create", "--grant", "witness"],
        );
        let key: [u8; 32] = unhex(text(data(&checkpoint), "public_key"))
            .try_into()
            .unwrap();
        let bundle = fixture.dir.join("issued-functional.bundle");
        let receipt = fixture.dir.join("issued-functional.receipt");
        ok(
            &fixture.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                &reference,
                "--state",
                text(data(&checkpoint), "oid"),
                "--out",
                bundle.to_str().unwrap(),
                "--receipt-out",
                receipt.to_str().unwrap(),
            ],
        );
        let verified = fa_verify::report::verify_report_expected(
            &std::fs::read(bundle).unwrap(),
            &[key],
            None,
            Some(&std::fs::read(receipt).unwrap()),
            Some(&source.digest),
        )
        .unwrap();
        assert_eq!(verified.known_at, source.known_at.0);
        assert_eq!(verified.output, source.output);
        assert!(verified.functional_statement.is_some());
    }
}

#[test]
fn functional_issued_statement_views_refuse_changed_questions_and_native_basis() {
    let fixture = Fixture::new();
    fixture.post("issued-mismatch", "2026-02-05", "200.00", 12);
    let original = ok_many(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--functional",
            "--for",
            "FY2026-P02",
            "--compare",
            "FY2026-P01",
            "--certify",
        ],
    );
    let reference = format!("C:{}", text(event(&original, "report_certificate"), "oid"));
    issue(&fixture, &reference);
    let native = ok_many(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--for",
            "FY2026-P02",
            "--compare",
            "FY2026-P01",
            "--certify",
        ],
    );
    let native_reference = format!("C:{}", text(event(&native, "report_certificate"), "oid"));
    let output = fixture.dir.join("mismatched-question.cert");
    let before = head(&fixture.book);
    for (mode, period, source, compare) in [
        ("balance-sheet", "FY2026-P02", reference.as_str(), None),
        // P01 is a saved comparative, but cannot become the primary period.
        ("income-statement", "FY2026-P01", reference.as_str(), None),
        (
            "income-statement",
            "FY2026-P02",
            reference.as_str(),
            Some("FY2026-P02"),
        ),
        (
            "income-statement",
            "FY2026-P02",
            native_reference.as_str(),
            None,
        ),
    ] {
        let mut args = vec![
            "statement",
            mode,
            "--functional",
            "--for",
            period,
            "--as-reported-in",
            source,
            "--certificate-out",
            output.to_str().unwrap(),
        ];
        if let Some(compare) = compare {
            args.extend(["--compare", compare]);
        }
        let (status, refused) = run(&fixture.book, &args);
        assert_eq!(status, 8, "{args:?}: {}", refused.render());
        assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-150");
        assert_eq!(refused.get("certificate"), Some(&Json::Null));
        assert!(!output.exists());
    }
    let (status, refused) = run(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--functional",
            "--for",
            "FY2026-P02",
            "--as-reported-in",
            &reference,
            "--definition",
            "balance-sheet",
        ],
    );
    assert_eq!(status, 8, "{}", refused.render());
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-150");
    for extras in [
        vec![
            "--as-reported-in",
            reference.as_str(),
            "--as-known-at",
            "HEAD",
        ],
        vec!["--as-originally-reported", "--as-issued-to", "board"],
        vec!["--as-currently-stated", "--known-at", "1"],
        vec!["--branch", "scenario:not-a-trunk-statement"],
    ] {
        let mut args = vec![
            "statement",
            "income-statement",
            "--functional",
            "--for",
            "FY2026-P02",
        ];
        args.extend(extras);
        let (status, refused) = run(&fixture.book, &args);
        assert_eq!(status, 2, "{args:?}: {}", refused.render());
        assert_eq!(text(data(&refused), "class"), "usage");
    }
    assert_eq!(head(&fixture.book), before);
}

#[test]
fn functional_issued_statement_views_enforce_current_read_and_produce_authority() {
    let fixture = Fixture::new();
    fixture.post("issued-reader", "2026-02-05", "200.00", 12);
    let original = ok_many(
        &fixture.book,
        &[
            "statement",
            "income-statement",
            "--functional",
            "--for",
            "FY2026-P02",
            "--certify",
        ],
    );
    let reference = format!("C:{}", text(event(&original, "report_certificate"), "oid"));
    issue(&fixture, &reference);
    let token = fixture.dir.join("issued-reader.token");
    let issued = ok(
        &fixture.book,
        &[
            "capability",
            "issue",
            "--holder",
            "issued-reader",
            "--profile",
            "human",
            "--op",
            "read",
            "--grant",
            "issue_capability",
            "--grant",
            "read",
            "--out",
            token.to_str().unwrap(),
        ],
    );
    let read = vec![
        "--token",
        token.to_str().unwrap(),
        "statement",
        "income-statement",
        "--functional",
        "--for",
        "FY2026-P02",
        "--as-originally-reported",
    ];
    let reported = ok(&fixture.book, &read);
    assert_eq!(data(&reported), event(&original, "statement"));
    assert_eq!(reported.get("certificate"), Some(&Json::Null));

    let output = fixture.dir.join("denied-issued.cert");
    let rendered = fixture.dir.join("denied-issued.md");
    let before = head(&fixture.book);
    for retention in [
        vec!["--certify"],
        vec!["--certificate-out", output.to_str().unwrap()],
        vec![
            "--certify",
            "--render",
            "md",
            "--out",
            rendered.to_str().unwrap(),
        ],
    ] {
        let mut args = read.clone();
        args.extend(retention);
        let (status, refused) = run(&fixture.book, &args);
        assert_eq!(status, 7, "{}", refused.render());
        assert!(text(data(&refused), "message").contains("produce"));
        assert_eq!(refused.get("certificate"), Some(&Json::Null));
    }
    assert!(!output.exists());
    assert!(!rendered.exists());
    assert_eq!(
        head(&fixture.book),
        before + access_events_since(&fixture.book, before)
    );

    ok(
        &fixture.book,
        &[
            "capability",
            "revoke",
            "--commitment",
            text(data(&issued), "commitment"),
            "--grant",
            "issue_capability",
            "--grant",
            "read",
            "--yes",
        ],
    );
    for view in [
        vec!["--as-originally-reported"],
        vec!["--as-issued-to", "board"],
        vec!["--as-reported-in", reference.as_str()],
    ] {
        let mut args = vec![
            "--token",
            token.to_str().unwrap(),
            "statement",
            "income-statement",
            "--functional",
            "--for",
            "FY2026-P02",
        ];
        args.extend(view);
        let (status, refused) = run(&fixture.book, &args);
        assert_eq!(status, 7, "{}", refused.render());
        assert!(
            text(data(&refused), "message")
                .to_ascii_lowercase()
                .contains("revok")
        );
        assert_eq!(refused.get("certificate"), Some(&Json::Null));
    }
}

#[test]
fn functional_original_statement_without_issuance_uses_first_lock() {
    let fixture = Fixture::new();
    fixture.post("lock-original", "2026-01-05", "100.00", 11);
    ok(
        &fixture.book,
        &[
            "period",
            "close",
            "FY2026-P01",
            "--reason",
            "Scheduled",
            "--yes",
        ],
    );
    let closed_at = head(&fixture.book);
    let plan = fixture.dir.join("first-lock.plan");
    let planned = ok(
        &fixture.book,
        &[
            "period",
            "lock",
            "FY2026-P01",
            "--reason",
            "Scheduled",
            "--plan-out",
            plan.to_str().unwrap(),
        ],
    );
    let approved = ok(
        &fixture.book,
        &[
            "approve",
            "--proposal",
            text(data(&planned), "proposal_digest"),
            "--as",
            "lock-controller",
        ],
    );
    ok(
        &fixture.book,
        &[
            "period",
            "lock",
            "FY2026-P01",
            "--plan",
            plan.to_str().unwrap(),
            "--approval",
            text(data(&approved), "approval_vid"),
            "--yes",
        ],
    );
    let locked_at = head(&fixture.book);
    assert!(locked_at > closed_at);
    fixture.post("later-period", "2026-02-05", "200.00", 13);
    for (mode, line) in [
        ("balance-sheet", "assets"),
        ("income-statement", "net_income"),
    ] {
        let reported = ok_many(
            &fixture.book,
            &[
                "statement",
                mode,
                "--functional",
                "--for",
                "FY2026-P01",
                "--as-originally-reported",
                "--certify",
            ],
        );
        assert_eq!(
            statement_amounts(event(&reported, "statement"), line, "USD"),
            &[Json::Str("110.00 USD".into())]
        );
        let bytes = unhex(text(event(&reported, "report_certificate"), "bytes"));
        assert!(bytes.starts_with(b"fa:report-certificate:v5"));
        let source = fa::ReportCertificate::decode(&bytes).unwrap();
        assert_eq!(i128::from(source.known_at.0), locked_at);
    }
}
