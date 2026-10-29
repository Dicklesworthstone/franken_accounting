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
