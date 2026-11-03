//! Certify, retain and replay equity across real binary processes and book reopen.

use super::*;

fn many(book: &Path, args: &[&str]) -> (i32, Vec<Json>) {
    let result = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .stdin(Stdio::null())
        .output()
        .expect("run fa");
    let stdout = String::from_utf8(result.stdout).expect("UTF-8 stdout");
    let registry = fa_cli::verbs::registry().unwrap();
    assert!(
        !stdout.is_empty(),
        "args={args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let events = stdout
        .lines()
        .map(|line| {
            registry
                .check_line(line)
                .unwrap_or_else(|e| panic!("{e}: {line}"));
            json::parse(line).unwrap()
        })
        .collect();
    (result.status.code().unwrap_or(-1), events)
}

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn equity_certification_reopens_replays_and_tracks_backdated_changes() {
    let f = Fixture::with_chart(
        true,
        r#"{"accounts":[
        {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
        {"code":"3000","name":"Retained earnings","type":"Equity","unit":"USD"},
        {"code":"3100","name":"Common stock","type":"Equity","unit":"USD"},
        {"code":"3200","name":"Dividends","type":"Equity","unit":"USD"},
        {"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},
        {"code":"6000","name":"Expense","type":"Expense","unit":"USD"}
    ]}"#,
    );
    f.post("equity-issued", "1000", "3100", "500.00");
    f.post("equity-sale", "1000", "4000", "100.00");
    f.post("equity-dividend", "3200", "1000", "30.00");
    let at = head(&f.book);
    let path = f.dir.join("equity.cert");
    let args = [
        "statement",
        "equity-roll-forward",
        "--from",
        "2026-01-01",
        "--to",
        "2026-12-31",
        "--issuance",
        "3100",
        "--distribution",
        "3200",
        "--label",
        "Annual equity",
        "--certify",
        "--certificate-out",
        path.to_str().unwrap(),
    ];
    let (code, produced) = many(&f.book, &args);
    assert_eq!(code, 0, "{produced:?}");
    assert_eq!(produced.len(), 2);
    assert_eq!(text(&produced[0], "event"), "equity_roll_forward");
    assert_eq!(text(&produced[1], "event"), "report_certificate");
    let bytes = std::fs::read(&path).unwrap();
    let artifact = fa::ReportArtifact::decode(&bytes).unwrap();
    assert_eq!(
        artifact.family(),
        fa::ReportArtifactFamily::EquityRollForward
    );
    assert_eq!(
        text(&produced[1], "output_format"),
        fa::EQUITY_REPORT_FORMAT
    );
    assert!(text(&produced[1], "replay_command").contains("--expect"));
    let oid = format!("C:{}", text(&produced[1], "oid"));
    let expected = format!(
        r#"{{"kind":"equity-roll-forward","units":["USD"],"label":"Annual equity","from":"2026-01-01","through":"2026-12-31","known_at":{at},"issuance_accounts":["3100"],"distribution_accounts":["3200"]}}"#
    );
    let retained_at = head(&f.book);
    let current = ok(
        &f.book,
        &["certificate", "status", &oid, "--expect", &expected],
    );
    assert_eq!(text(&current, "status"), "Current");
    let output = f.dir.join("equity.replayed");
    let (code, replayed) = many(
        &f.book,
        &[
            "replay",
            &oid,
            "--expect",
            &expected,
            "--output",
            output.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "{replayed:?}");
    assert_eq!(get(&replayed[0], "data"), get(&produced[0], "data"));
    assert_eq!(std::fs::read(output).unwrap(), artifact.output());
    assert_eq!(
        head(&f.book),
        retained_at,
        "replay/status write no metadata"
    );
    let (code, refused) = many(&f.book, &["replay", &oid]);
    assert_eq!(code, 8, "{refused:?}");
    for wrong in [
        expected.replace(
            "\"issuance_accounts\":[\"3100\"]",
            "\"issuance_accounts\":[]",
        ),
        expected.replace("2026-12-31", "2026-12-30"),
        expected.replace("Annual equity", "Another statement"),
    ] {
        let (code, refused) = many(&f.book, &["replay", &oid, "--expect", &wrong]);
        assert_eq!(code, 8, "{refused:?}");
        let (code, refused) = many(
            &f.book,
            &["certificate", "status", &oid, "--expect", &wrong],
        );
        assert_eq!(code, 8, "{refused:?}");
    }
    let (code, refused) = many(&f.book, &args);
    assert_eq!(
        code, 2,
        "an existing certificate is not replaced: {refused:?}"
    );
    assert_eq!(head(&f.book), retained_at);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    f.post("equity-late-expense", "6000", "1000", "20.00");
    let status = ok(
        &f.book,
        &["certificate", "status", &oid, "--expect", &expected],
    );
    assert_eq!(text(&status, "status"), "SupersededBy");
    assert_eq!(get(&status, "later_entries").as_arr().unwrap().len(), 1);
    f.close_now("equity-certificate-close");
    let (code, replayed) = many(&f.book, &["replay", &oid, "--expect", &expected]);
    assert_eq!(code, 0, "{replayed:?}");
    assert_eq!(
        get(&replayed[0], "data"),
        get(&produced[0], "data"),
        "closing does not rewrite a retained statement"
    );

    // Certify the completed year after its Closing entry. Both retained and
    // file export routes carry an independently replayable owner movement
    // statement, including the income-to-retained-earnings transfer.
    let closed_at = head(&f.book);
    let closed_path = f.dir.join("closed-equity.cert");
    let mut closed_args = args.to_vec();
    *closed_args.last_mut().unwrap() = closed_path.to_str().unwrap();
    let (code, closed) = many(&f.book, &closed_args);
    assert_eq!(code, 0, "{closed:?}");
    assert_eq!(closed.len(), 2);
    let closed_bytes = std::fs::read(&closed_path).unwrap();
    let certificate = fa::EquityRollForwardCertificate::decode(&closed_bytes).unwrap();
    assert_eq!(certificate.known_at().0 as i128, closed_at);
    let locator = format!("C:{}", text(&closed[1], "oid"));
    let expected_digest = fa_verify::blake3::hex(certificate.digest());
    let checkpoint = ok(&f.book, &["checkpoint", "create", "--grant", "witness"]);
    let signed = ok(
        &f.book,
        &[
            "proof",
            "signed-checkpoint",
            "--state",
            text(&checkpoint, "oid"),
        ],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let before_exports = head(&f.book);
    let mut original_bundle = None;
    for source in [locator.as_str(), closed_path.to_str().unwrap()] {
        let produced = ok(
            &f.book,
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
        assert!(text(&produced, "verify").contains(&format!("--expect {expected_digest}")));
        let bundle = unhex(text(&produced, "bytes"));
        let receipt = unhex(text(&produced, "receipt"));
        let verified = fa_verify::report::verify_report_expected(
            &bundle,
            &[key],
            None,
            Some(&receipt),
            Some(certificate.digest()),
        )
        .expect("closed equity independently recomputes from signed native history");
        assert_eq!(verified.certificate_digest, *certificate.digest());
        assert_eq!(verified.known_at as i128, closed_at);
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
        let equity = verified.equity_roll_forward.unwrap();
        assert_eq!(equity.label, "Annual equity");
        assert_eq!(equity.units.len(), 1);
        let unit = &equity.units[0];
        assert_eq!(unit.opening_total_equity, 0);
        assert_eq!(unit.issuances, 50_000);
        assert_eq!(unit.distributions, -3_000);
        assert_eq!(unit.net_income, 8_000);
        assert_eq!(unit.closing_transfers_net, 0);
        assert_eq!(unit.net_equity_change, 55_000);
        assert_eq!(unit.closing_total_equity, 55_000);
        assert_eq!(unit.equity_tie_out_residual, 0);
        let transfers = equity
            .movements
            .iter()
            .filter(|movement| {
                movement.kind == fa_verify::report::EquityActivityKind::ClosingTransfer
            })
            .collect::<Vec<_>>();
        let accounts: std::collections::BTreeSet<u128> = transfers
            .iter()
            .map(|movement| movement.account_id)
            .collect();
        // Each closed nominal balance carries its own equity leg (0676d8514
        // closes retained carrying buckets one by one), so retained earnings
        // takes two legs here, one for the revenue and one for the expense.
        assert_eq!(
            transfers.len(),
            4,
            "one closing leg per route, before netting: {transfers:?}"
        );
        assert_eq!(
            accounts.len(),
            3,
            "revenue and expense each route separately into retained earnings"
        );
        let mut amounts = transfers
            .iter()
            .map(|movement| (movement.debits, movement.credits))
            .collect::<Vec<_>>();
        amounts.sort_unstable();
        assert_eq!(amounts, [(0, 2_000), (0, 10_000), (2_000, 0), (10_000, 0)]);
        let book_id = certificate
            .source_certificate()
            .source_certificate()
            .book_id;
        let mut routed = transfers
            .iter()
            .map(|movement| (movement.account_id, movement.debits, movement.credits))
            .collect::<Vec<_>>();
        routed.sort_unstable();
        let mut expected = [
            (fa_model::account_vid(book_id, "3000").0, 0, 10_000),
            (fa_model::account_vid(book_id, "3000").0, 2_000, 0),
            (fa_model::account_vid(book_id, "4000").0, 10_000, 0),
            (fa_model::account_vid(book_id, "6000").0, 0, 2_000),
        ];
        expected.sort_unstable();
        assert_eq!(routed, expected);
        assert_eq!(
            transfers
                .iter()
                .map(|movement| movement.credits - movement.debits)
                .sum::<i128>(),
            0
        );

        if let Some((expected_bundle, expected_receipt)) = &original_bundle {
            assert_eq!(&bundle, expected_bundle);
            assert_eq!(&receipt, expected_receipt);
        } else {
            original_bundle = Some((bundle.clone(), receipt.clone()));
        }
        let verifier_args = [
            "report",
            "equity.fab",
            "--key",
            text(&signed, "checkpoint_public_key"),
            "--receipt",
            "equity.receipt",
            "--expect",
            &expected_digest,
            "--json",
        ]
        .map(str::to_string);
        let read = |name: &str| match name {
            "equity.fab" => Ok(bundle.clone()),
            "equity.receipt" => Ok(receipt.clone()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                name.to_string(),
            )),
        };
        let checked = fa_verify::cli::run(&verifier_args, &read);
        assert_eq!(checked.exit, 0, "{}{}", checked.stdout, checked.stderr);
        assert!(checked.stdout.contains("\"verdict\":\"verified\""));
        assert!(checked.stdout.contains("equity_unit"));
        assert!(checked.stdout.contains("closing_transfer"));
        // The nested lead schedule does not authenticate the owner's choice
        // of issuance and distribution accounts; pin the outer certificate.
        let inner = certificate.source_certificate().digest();
        assert!(
            fa_verify::report::verify_report_expected(
                &bundle,
                &[key],
                None,
                Some(&receipt),
                Some(inner),
            )
            .is_err()
        );
        let mut wrong = verifier_args;
        wrong[7] = fa_verify::blake3::hex(inner);
        assert_eq!(fa_verify::cli::run(&wrong, &read).exit, 8);
    }
    assert_eq!(
        head(&f.book),
        before_exports,
        "owner proof exports publish nothing"
    );
    assert_eq!(std::fs::read(&closed_path).unwrap(), closed_bytes);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        bytes,
        "the original pre-close certificate remains exact"
    );
}

#[test]
fn equity_comparison_preserves_sources_request_and_portable_verification() {
    let f = Fixture::with_chart(
        true,
        r#"{"accounts":[
        {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
        {"code":"3000","name":"Retained earnings","type":"Equity","unit":"USD"},
        {"code":"3100","name":"Common stock","type":"Equity","unit":"USD"},
        {"code":"3200","name":"Dividends","type":"Equity","unit":"USD"},
        {"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},
        {"code":"6000","name":"Expense","type":"Expense","unit":"USD"}
    ]}"#,
    );
    f.post("comparison-issued", "1000", "3100", "500.00");
    f.post("comparison-sale", "1000", "4000", "100.00");
    f.post("comparison-dividend", "3200", "1000", "30.00");
    let certify_source = |path: &Path| {
        let (code, events) = many(
            &f.book,
            &[
                "statement",
                "equity-roll-forward",
                "--from",
                "2026-01-01",
                "--to",
                "2026-12-31",
                "--issuance",
                "3100",
                "--distribution",
                "3200",
                "--label",
                "Annual equity",
                "--certify",
                "--certificate-out",
                path.to_str().unwrap(),
            ],
        );
        assert_eq!(code, 0, "{events:?}");
        assert_eq!(events.len(), 2);
        events
    };
    let before_at = head(&f.book);
    let before_path = f.dir.join("comparison-before.cert");
    let before_events = certify_source(&before_path);
    let before_bytes = std::fs::read(&before_path).unwrap();
    let before_oid = format!("C:{}", text(&before_events[1], "oid"));
    f.post("comparison-late-expense", "6000", "1000", "20.00");
    f.close_now("comparison-close");
    let after_at = head(&f.book);
    let after_path = f.dir.join("comparison-after.cert");
    let after_events = certify_source(&after_path);
    let after_bytes = std::fs::read(&after_path).unwrap();
    let after_oid = format!("C:{}", text(&after_events[1], "oid"));
    let expected = format!(
        r#"{{"kind":"equity-roll-forward-diff","units":["USD"],"label":"Annual equity","from":"2026-01-01","through":"2026-12-31","known_at":{before_at},"after_known_at":{after_at},"issuance_accounts":["3100"],"distribution_accounts":["3200"]}}"#
    );
    let diff_path = f.dir.join("equity-diff.cert");
    let request_path = f.dir.join("equity-diff.request");
    let (code, events) = many(
        &f.book,
        &[
            "statement",
            "diff",
            "--before-certificate",
            &before_oid,
            "--after-certificate",
            after_path.to_str().unwrap(),
            "--expect",
            &expected,
            "--certify",
            "--certificate-out",
            diff_path.to_str().unwrap(),
            "--request-out",
            request_path.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "{events:?}");
    assert_eq!(events.len(), 2);
    assert_eq!(text(&events[0], "event"), "equity_roll_forward_diff");
    assert_eq!(integer(&events[0], "before_known_at"), before_at);
    assert_eq!(integer(&events[0], "after_known_at"), after_at);
    assert_eq!(
        text(&events[0], "before_certificate"),
        text(&before_events[1], "oid")
    );
    assert_eq!(
        text(&events[0], "after_certificate"),
        text(&after_events[1], "oid")
    );
    assert_eq!(
        get(&events[0], "before_movements"),
        get(&before_events[0], "movements")
    );
    assert_eq!(
        get(&events[0], "after_movements"),
        get(&after_events[0], "movements")
    );
    assert!(
        get(&events[0], "after_movements")
            .as_arr()
            .unwrap()
            .iter()
            .any(|m| { text(m, "kind") == "closing_transfer" && text(m, "class") == "Closing" })
    );
    let units = get(&events[0], "units").as_arr().unwrap();
    assert_eq!(units.len(), 1);
    assert_eq!(text(&units[0], "unit"), "USD");
    let lines = get(&units[0], "lines").as_arr().unwrap();
    assert_eq!(
        lines.len(),
        15,
        "zero deltas and reconciliation rows remain visible"
    );
    for (name, before, after, delta) in [
        (
            "opening_contributed_equity",
            "0.00 USD",
            "0.00 USD",
            "0.00 USD",
        ),
        (
            "opening_unclosed_earnings",
            "0.00 USD",
            "0.00 USD",
            "0.00 USD",
        ),
        ("opening_total_equity", "0.00 USD", "0.00 USD", "0.00 USD"),
        (
            "prior_period_adjustments",
            "0.00 USD",
            "0.00 USD",
            "0.00 USD",
        ),
        (
            "opening_equity_as_adjusted",
            "0.00 USD",
            "0.00 USD",
            "0.00 USD",
        ),
        ("net_income", "100.00 USD", "80.00 USD", "-20.00 USD"),
        ("issuances", "500.00 USD", "500.00 USD", "0.00 USD"),
        ("distributions", "-30.00 USD", "-30.00 USD", "0.00 USD"),
        ("other_equity_movements", "0.00 USD", "0.00 USD", "0.00 USD"),
        ("closing_transfers_net", "0.00 USD", "0.00 USD", "0.00 USD"),
        (
            "net_equity_change",
            "570.00 USD",
            "550.00 USD",
            "-20.00 USD",
        ),
        (
            "closing_contributed_equity",
            "470.00 USD",
            "550.00 USD",
            "80.00 USD",
        ),
        (
            "closing_unclosed_earnings",
            "100.00 USD",
            "0.00 USD",
            "-100.00 USD",
        ),
        (
            "closing_total_equity",
            "570.00 USD",
            "550.00 USD",
            "-20.00 USD",
        ),
        (
            "equity_tie_out_residual",
            "0.00 USD",
            "0.00 USD",
            "0.00 USD",
        ),
    ] {
        let line = lines
            .iter()
            .find(|line| text(line, "code") == name)
            .unwrap();
        assert_eq!(
            (
                text(line, "before"),
                text(line, "after"),
                text(line, "delta")
            ),
            (before, after, delta),
            "{name}"
        );
    }
    let bytes = std::fs::read(&diff_path).unwrap();
    let artifact = fa::ReportArtifact::decode(&bytes).unwrap();
    assert_eq!(
        artifact.family(),
        fa::ReportArtifactFamily::EquityRollForwardDiff
    );
    let certificate = artifact.equity_roll_forward_diff_certificate().unwrap();
    assert_eq!(
        certificate.sources().0.canonical_bytes().unwrap(),
        before_bytes
    );
    assert_eq!(
        certificate.sources().1.canonical_bytes().unwrap(),
        after_bytes
    );
    let request_bytes = std::fs::read(&request_path).unwrap();
    assert_eq!(
        unhex(text(&events[0], "verification_request_hex")),
        request_bytes
    );
    assert_eq!(
        text(&events[0], "request_file"),
        request_path.to_str().unwrap()
    );
    assert_eq!(
        fa::EquityRollForwardDiffRequest::decode(&request_bytes).unwrap(),
        certificate.request().unwrap()
    );
    let oid = format!("C:{}", text(&events[1], "oid"));
    assert!(text(&events[1], "replay_command").contains("equity-roll-forward-diff"));
    let reader_token = f.dir.join("equity-comparison-reader.token");
    ok(
        &f.book,
        &[
            "capability",
            "issue",
            "--holder",
            "equity-comparison-reader",
            "--profile",
            "human",
            "--op",
            "read",
            "--grant",
            "issue_capability",
            "--grant",
            "read",
            "--out",
            reader_token.to_str().unwrap(),
        ],
    );
    let before_read = head(&f.book);
    let current = ok(
        &f.book,
        &["certificate", "status", &oid, "--expect", &expected],
    );
    assert_eq!(text(&current, "status"), "Current");
    let (code, read_only) = many(
        &f.book,
        &[
            "statement",
            "diff",
            "--before-certificate",
            before_path.to_str().unwrap(),
            "--after-certificate",
            &after_oid,
            "--expect",
            &expected,
            "--token",
            reader_token.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "{read_only:?}");
    assert_eq!(read_only.len(), 1);
    let retained_at = head(&f.book);
    assert_eq!(
        retained_at,
        before_read + 1,
        "the admitted token read journals exactly its AccessEvent"
    );
    let (code, refused) = many(
        &f.book,
        &[
            "statement",
            "diff",
            "--before-certificate",
            before_path.to_str().unwrap(),
            "--after-certificate",
            &after_oid,
            "--expect",
            &expected,
            "--token",
            reader_token.to_str().unwrap(),
            "--certify",
        ],
    );
    assert_eq!(code, 7, "{refused:?}");
    assert_eq!(refused.len(), 1);
    assert_eq!(text(&refused[0], "event"), "error");
    assert_eq!(head(&f.book), retained_at);
    let output = f.dir.join("equity-diff.replayed");
    let (code, replayed) = many(
        &f.book,
        &[
            "replay",
            &oid,
            "--expect",
            &expected,
            "--output",
            output.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "{replayed:?}");
    for key in [
        "units",
        "before_certificate",
        "after_certificate",
        "before_movements",
        "after_movements",
        "verification_request_hex",
    ] {
        assert_eq!(get(&read_only[0], key), get(&events[0], key), "{key}");
        assert_eq!(get(&replayed[0], key), get(&events[0], key), "{key}");
    }
    assert_eq!(get(&replayed[0], "request_file"), &Json::Null);
    assert_eq!(std::fs::read(&output).unwrap(), certificate.output());
    assert_eq!(
        head(&f.book),
        retained_at,
        "comparison records only its AccessEvent; refused certification, replay and status publish nothing"
    );

    let refused_request = f.dir.join("refused-equity.request");
    for (wrong, wanted) in [
        (
            expected.replace(
                "\"issuance_accounts\":[\"3100\"]",
                "\"issuance_accounts\":[]",
            ),
            8,
        ),
        (expected.replace("2026-12-31", "2026-12-30"), 8),
        (expected.replace("Annual equity", "Another question"), 8),
        (
            expected.replace(
                &format!("\"after_known_at\":{after_at}"),
                &format!("\"after_known_at\":{}", after_at + 1),
            ),
            8,
        ),
        (
            expected.replace(
                &format!("\"known_at\":{before_at}"),
                "\"known_at\":\"HEAD\"",
            ),
            2,
        ),
        (
            expected.replace(
                &format!("\"after_known_at\":{after_at}"),
                "\"after_known_at\":\"HEAD\"",
            ),
            2,
        ),
        (
            expected.replace(&format!(",\"after_known_at\":{after_at}"), ""),
            2,
        ),
        (
            expected.replace(",\"distribution_accounts\":[\"3200\"]", ""),
            2,
        ),
        (
            expected.replace("\"label\":", "\"unknown\":0,\"label\":"),
            2,
        ),
    ] {
        let (code, refused) = many(
            &f.book,
            &[
                "statement",
                "diff",
                "--before-certificate",
                &before_oid,
                "--after-certificate",
                &after_oid,
                "--expect",
                &wrong,
                "--certify",
                "--request-out",
                refused_request.to_str().unwrap(),
            ],
        );
        assert_eq!(code, wanted, "{refused:?}");
        assert!(
            !refused_request.exists(),
            "a refused question writes no verification request"
        );
        assert_eq!(
            refused.len(),
            1,
            "a refused question emits no partial comparison"
        );
        let (code, refused) = many(&f.book, &["replay", &oid, "--expect", &wrong]);
        assert_eq!(code, wanted, "{refused:?}");
    }
    let (code, refused) = many(&f.book, &["replay", &oid]);
    assert_eq!(code, 8, "{refused:?}");
    let (code, refused) = many(
        &f.book,
        &[
            "statement",
            "diff",
            "--before-certificate",
            &before_oid,
            "--after-certificate",
            &after_oid,
            "--certify",
        ],
    );
    assert_eq!(code, 2, "{refused:?}");
    for extra in [
        vec!["--functional"],
        vec!["--for", "FY2026-P12"],
        vec!["--before", "1"],
        vec!["--request-out", request_path.to_str().unwrap()],
    ] {
        let mut args = vec![
            "statement",
            "diff",
            "--before-certificate",
            &before_oid,
            "--after-certificate",
            &after_oid,
            "--expect",
            &expected,
        ];
        args.extend(extra.iter().copied());
        let (code, refused) = many(&f.book, &args);
        assert_eq!(code, 2, "{refused:?}");
    }
    // Restrict the actual launch authority: an unbound --grant adds operations
    // to the command's implied read/produce set and cannot remove produce.
    let (code, refused) = closing_agent(
        &f,
        &["read"],
        &[
            "statement",
            "diff",
            "--before-certificate",
            &before_oid,
            "--after-certificate",
            &after_oid,
            "--expect",
            &expected,
            "--certify",
        ],
    );
    assert_eq!(code, 7, "{refused:?}");
    assert_eq!(
        head(&f.book),
        retained_at,
        "refused comparisons retain nothing"
    );
    assert_eq!(std::fs::read(&request_path).unwrap(), request_bytes);

    let (code, native) = many(&f.book, &["tb", "--certify"]);
    assert_eq!(code, 0, "{native:?}");
    let native_oid = format!("C:{}", text(native.last().unwrap(), "oid"));
    for (before, after, wanted) in [
        (&native_oid, &after_oid, 8),
        (&before_oid, &native_oid, 8),
        (&native_oid, &native_oid, 2),
    ] {
        let (code, refused) = many(
            &f.book,
            &[
                "statement",
                "diff",
                "--before-certificate",
                before,
                "--after-certificate",
                after,
                "--expect",
                &expected,
            ],
        );
        assert_eq!(code, wanted, "{refused:?}");
    }
    let checkpoint = ok(&f.book, &["checkpoint", "create", "--grant", "witness"]);
    let signed = ok(
        &f.book,
        &[
            "proof",
            "signed-checkpoint",
            "--state",
            text(&checkpoint, "oid"),
        ],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let recipient_request =
        fa_verify::report::EquityRollForwardDiffRequest::decode(&request_bytes).unwrap();
    let before_exports = head(&f.book);
    for source in [oid.as_str(), diff_path.to_str().unwrap()] {
        let (code, replayed) = many(&f.book, &["replay", source, "--expect", &expected]);
        assert_eq!(code, 0, "cold checkpoint replay: {replayed:?}");
        assert_eq!(integer(&replayed[0], "before_known_at"), before_at);
        assert_eq!(integer(&replayed[0], "after_known_at"), after_at);
        for field in ["units", "before_movements", "after_movements"] {
            assert_eq!(get(&replayed[0], field), get(&events[0], field), "{field}");
        }
    }
    let status = ok(
        &f.book,
        &["certificate", "status", &oid, "--expect", &expected],
    );
    assert_eq!(text(&status, "status"), "Current");
    let (code, refused) = many(
        &f.book,
        &[
            "bundle",
            "produce",
            "--certificate",
            &oid,
            "--state",
            text(&checkpoint, "oid"),
        ],
    );
    assert_eq!(
        code, 2,
        "portable comparison requires the independent request: {refused:?}"
    );
    let mut original_bundle = None;
    for source in [oid.as_str(), diff_path.to_str().unwrap()] {
        let exported = ok(
            &f.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                source,
                "--expect",
                &expected,
                "--state",
                text(&checkpoint, "oid"),
            ],
        );
        assert!(text(&exported, "verify").contains("--equity-diff-request"));
        let bundle = unhex(text(&exported, "bytes"));
        let receipt = unhex(text(&exported, "receipt"));
        let verified = fa_verify::report::verify_equity_roll_forward_diff_report_expected(
            &bundle,
            &[key],
            None,
            Some(&receipt),
            &recipient_request,
            Some(certificate.digest()),
        )
        .expect("both original equity statements and every delta independently recompute");
        assert_eq!(verified.output, certificate.output());
        let comparison = verified.equity_roll_forward_diff.unwrap();
        assert_eq!(
            comparison.before_digest,
            fa_model::domain_digest(
                b"fa:equity-roll-forward-diff-source:v1",
                &[certificate.sources().0.output()],
            ),
        );
        assert_eq!(
            comparison.after_digest,
            fa_model::domain_digest(
                b"fa:equity-roll-forward-diff-source:v1",
                &[certificate.sources().1.output()],
            ),
        );
        assert_eq!(comparison.units[0].lines.len(), 15);
        assert_eq!(
            comparison.units[0]
                .lines
                .iter()
                .find(|line| line.code == "net_income")
                .unwrap()
                .delta,
            -2_000
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
            "an authenticated certificate cannot choose the recipient's request"
        );
        assert!(
            fa_verify::report::verify_equity_roll_forward_diff_report_expected(
                &bundle,
                &[key],
                None,
                Some(&receipt),
                &recipient_request,
                Some(certificate.sources().1.digest()),
            )
            .is_err(),
            "the original after source is not the outer comparison"
        );
        let mut wrong = recipient_request.clone();
        wrong.issuance_accounts.clear();
        assert!(
            fa_verify::report::verify_equity_roll_forward_diff_report_expected(
                &bundle,
                &[key],
                None,
                Some(&receipt),
                &wrong,
                Some(certificate.digest()),
            )
            .is_err()
        );
        let read = |name: &str| match name {
            "equity-diff.fab" => Ok(bundle.clone()),
            "equity-diff.receipt" => Ok(receipt.clone()),
            "equity-diff.request" => Ok(request_bytes.clone()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                name.to_string(),
            )),
        };
        let verifier_args = [
            "report",
            "equity-diff.fab",
            "--key",
            text(&signed, "checkpoint_public_key"),
            "--receipt",
            "equity-diff.receipt",
            "--expect",
            &fa_verify::blake3::hex(certificate.digest()),
            "--equity-diff-request",
            "equity-diff.request",
            "--json",
        ]
        .map(str::to_string);
        let checked = fa_verify::cli::run(&verifier_args, &read);
        assert_eq!(checked.exit, 0, "{}{}", checked.stdout, checked.stderr);
        assert!(checked.stdout.contains("equity_roll_forward_diff"));
        if let Some((original, original_receipt)) = &original_bundle {
            assert_eq!(&bundle, original);
            assert_eq!(&receipt, original_receipt);
        } else {
            original_bundle = Some((bundle, receipt));
        }
    }
    assert_eq!(head(&f.book), before_exports);
    assert_eq!(std::fs::read(&before_path).unwrap(), before_bytes);
    assert_eq!(std::fs::read(&after_path).unwrap(), after_bytes);
    assert_eq!(std::fs::read(&diff_path).unwrap(), bytes);
}
