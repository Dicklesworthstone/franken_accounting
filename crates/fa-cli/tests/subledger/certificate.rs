//! Retained native reconciliation through real persisted CLI commands.
use super::*;

fn event_data(output: &str, event: &str) -> Json {
    output
        .lines()
        .map(|line| json::parse(line).unwrap())
        .find(|item| item.get("event").and_then(Json::as_str) == Some(event))
        .unwrap_or_else(|| panic!("missing {event}: {output}"))
        .get("data")
        .unwrap()
        .clone()
}

fn expected(code: &str, control: &str, at: &str) -> String {
    format!(
        r#"{{"kind":"native-subledger-reconciliation","code":"{code}","control_account":"{control}","through":"2026-03-31","known_at":{at}}}"#
    )
}

#[test]
fn pending_release_after_cutoff_and_equal_replacement_both_supersede() {
    let f = Fixture::new();
    f.register("AR", "1200", "receivables");
    f.invoice("C-1", "HOLD-INVOICE", "50.00 USD");
    let hold_json = r#"{"effective_date":"2026-03-10","idempotency_key":"native-hold","legs":[{"side":"debit","account":"1200","amount":"7.00 USD","party":"C-1"},{"side":"credit","account":"1000","amount":"7.00 USD"}]}"#;
    let hold = f.file("hold.json", hold_json);
    let held = data(&f.ok(&["reserve", "--intent", &hold, "--evidence", &f.evidence]));
    let at = f.head();
    let produced = f.ok(&[
        "subledger",
        "verify",
        "AR",
        "--as-of",
        "2026-03-31",
        "--certify",
    ]);
    let original = event_data(&produced, "subledger_reconciled");
    assert_eq!(
        text(&rows(&original, "totals")[0], "detail_debits"),
        "50.00 USD"
    );
    assert_eq!(
        text(&rows(&original, "totals")[0], "detail_debits_pending"),
        "7.00 USD"
    );
    let locator = format!(
        "C:{}",
        text(&event_data(&produced, "report_certificate"), "oid")
    );
    let expectation = expected("AR", "1200", &at);
    let release = f.file("release.json", &format!(r#"{{"resolves":"{}","disposition":"voids","effective_date":"2026-04-20","idempotency_key":"native-release"}}"#, text(&held, "vid")));
    let released = data(&f.ok(&["resolve", "--intent", &release, "--yes"]));
    let current = f.verify("AR", None);
    assert_eq!(
        text(&rows(&current, "totals")[0], "detail_debits"),
        "50.00 USD"
    );
    assert_eq!(
        text(&rows(&current, "totals")[0], "detail_debits_pending"),
        "0.00 USD"
    );
    let status = data(&f.ok(&["certificate", "status", &locator, "--expect", &expectation]));
    assert_eq!(text(&status, "status"), "SupersededBy");
    assert_eq!(
        rows(&status, "later_entries"),
        &[Json::Str(text(&released, "vid"))]
    );
    let replacement = f.file(
        "replacement.json",
        &hold_json.replace("native-hold", "native-replacement"),
    );
    let replaced = data(&f.ok(&[
        "reserve",
        "--intent",
        &replacement,
        "--evidence",
        &f.evidence,
    ]));
    let equal_columns = f.verify("AR", None);
    assert_eq!(equal_columns.get("rows"), original.get("rows"));
    assert_eq!(equal_columns.get("totals"), original.get("totals"));
    let status = data(&f.ok(&["certificate", "status", &locator, "--expect", &expectation]));
    assert_eq!(
        text(&status, "status"),
        "SupersededBy",
        "equal pending amounts cannot hide changed contributors"
    );
    let actual: BTreeSet<_> = rows(&status, "later_entries")
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        actual,
        BTreeSet::from([text(&released, "vid"), text(&replaced, "vid")])
    );
    assert_eq!(
        event_data(
            &f.ok(&["replay", &locator, "--expect", &expectation]),
            "subledger_reconciled"
        ),
        original
    );
}

#[test]
fn bound_certification_checks_produce_before_observation_or_audit_publication() {
    use fa_cli::authority::{LaunchAuthority, LaunchProfile};
    use fa_cli::cli::{Books, Files, Stdin, run_with_authority};
    let f = Fixture::new();
    f.register("AR", "1200", "receivables");
    let authority = LaunchAuthority::new(
        f.book.clone(),
        None,
        "operator",
        LaunchProfile::Preparer,
        &["read"],
    )
    .unwrap();
    let before = f.head();
    for extra in [
        vec!["--certify"],
        vec!["--certificate-out", "should-not-exist.cert"],
    ] {
        let mut args = vec![
            "subledger",
            "verify",
            "AR",
            "--as-of",
            "2026-03-31",
            "--json",
        ];
        args.extend(extra);
        let args: Vec<String> = args.into_iter().map(str::to_string).collect();
        let (exit, output) = run_with_authority(
            &args,
            Books::Dir,
            Files {
                cwd: None,
                stdin: Stdin::Missing,
            },
            &authority,
            true,
        );
        assert_eq!(exit, 7, "{output:?}");
        let event = json::parse(output.stdout.lines().last().unwrap()).unwrap();
        assert_eq!(event.get("book"), Some(&Json::Null));
        assert_eq!(event.get("coordinate"), Some(&Json::Null));
        assert_eq!(
            f.head(),
            before,
            "refused certification records neither access nor artifact"
        );
    }
}

#[test]
fn native_ar_and_ap_certificates_reopen_replay_and_distinguish_gross_scope_changes() {
    // The certificate embeds the trial-balance result, not every description
    // or journal payload. Distinct non-control cells exercise real fragments.
    let accounts = (0..256).map(|index| {
        json::parse(&format!(r#"{{"code":"CHUNK-{index:03}","name":"Fragment fixture asset {index}","type":"Asset","unit":"USD"}}"#)).unwrap()
    }).collect();
    let f = Fixture::with_additional_accounts(accounts);
    f.register("AR", "1200", "receivables");
    f.register("AP", "2000", "payables");
    let invoice = data(&f.invoice("C-1", "CERT-1", "100.00 USD"));
    f.invoice("C-2", "CERT-2", "250.00 USD");
    f.ok(&[
        "receipt",
        "--party",
        "C-1",
        "--number",
        "CERT-REC",
        "--date",
        "2026-03-20",
        "--cash",
        "1000",
        "--receivable",
        "1200",
        "--amount",
        "40.00 USD",
        "--applies",
        &text(&invoice, "vid"),
        "--evidence",
        &f.evidence,
    ]);
    f.ok(&[
        "bill",
        "--party",
        "V-1",
        "--number",
        "CERT-BILL",
        "--date",
        "2026-03-25",
        "--payable",
        "2000",
        "--expense",
        "6000",
        "--line",
        "amount=\"30.00 USD\"",
        "--evidence",
        &f.evidence,
    ]);
    // A large report spans many small committed entries; an oversized entry
    // itself would be refused before certificate fragmentation is exercised.
    for batch in 0..8 {
        let mut legs = (batch * 32..(batch + 1) * 32)
            .map(|index| {
                format!(r#"{{"side":"debit","account":"CHUNK-{index:03}","amount":"0.01 USD"}}"#)
            })
            .collect::<Vec<_>>();
        legs.push(r#"{"side":"credit","account":"1000","amount":"0.32 USD"}"#.into());
        let intent = f.file(&format!("certificate-cells-{batch}.json"), &format!(r#"{{"effective_date":"2026-03-15","idempotency_key":"certificate-cells-{batch}","legs":[{}]}}"#, legs.join(",")));
        f.ok(&["post", "--intent", &intent, "--evidence", &f.evidence]);
    }
    let at = f.head();
    let mut saved = Vec::new();
    for (code, control, debit, credit) in [
        ("AR", "1200", "350.00 USD", "40.00 USD"),
        ("AP", "2000", "0.00 USD", "30.00 USD"),
    ] {
        let ordinary = f.verify(code, Some(&at));
        let path = f.dir.join(format!("{code}.cert"));
        let produced = f.ok(&[
            "subledger",
            "verify",
            code,
            "--as-of",
            "2026-03-31",
            "--as-known-at",
            &at,
            "--certificate-out",
            path.to_str().unwrap(),
        ]);
        let report = event_data(&produced, "subledger_reconciled");
        assert_eq!(report, ordinary);
        let total = &rows(&report, "totals")[0];
        assert_eq!(text(total, "detail_debits"), debit);
        assert_eq!(text(total, "detail_credits"), credit);
        assert_eq!(total.get("detail_debits"), total.get("control_debits"));
        assert_eq!(total.get("detail_credits"), total.get("control_credits"));
        let metadata = event_data(&produced, "report_certificate");
        let locator = format!("C:{}", text(&metadata, "oid"));
        assert!(text(&metadata, "replay_command").contains("--expect"));
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            bytes.len() > 16 * 1024,
            "exercise chunked retained native sources: {} bytes",
            bytes.len()
        );
        assert!(bytes.len() > fa::MAX_INLINE_CERTIFICATE_BYTES);
        let certificate = fa::NativeSubledgerCertificate::decode(&bytes).unwrap();
        assert!(certificate.source_certificate().output.len() > 16 * 1024);
        assert_eq!(
            fa::ReportArtifact::decode(&bytes).unwrap().family(),
            fa::ReportArtifactFamily::NativeSubledger
        );
        assert_eq!(certificate.known_at().0.to_string(), at);
        let expectation = expected(code, control, &at);
        for source in [locator.as_str(), path.to_str().unwrap()] {
            let replayed = f.ok(&["replay", source, "--expect", &expectation]);
            assert_eq!(event_data(&replayed, "subledger_reconciled"), ordinary);
            assert_eq!(
                text(&event_data(&replayed, "report_replayed"), "family"),
                "native-subledger-reconciliation"
            );
        }
        assert_eq!(
            text(
                &data(&f.ok(&["certificate", "status", &locator, "--expect", &expectation])),
                "status"
            ),
            "Current"
        );
        saved.push((code, path, locator, expectation, ordinary, bytes));
    }
    let unrelated = f.file("unrelated.json", r#"{"effective_date":"2026-03-16","idempotency_key":"cert-unrelated","legs":[{"side":"debit","account":"1000","amount":"5.00 USD"},{"side":"credit","account":"4000","amount":"5.00 USD"}]}"#);
    f.ok(&["post", "--intent", &unrelated, "--evidence", &f.evidence]);
    let future = f.file("future-control.json", r#"{"effective_date":"2026-04-16","idempotency_key":"cert-future","legs":[{"side":"debit","account":"1200","amount":"2.00 USD","party":"C-1"},{"side":"credit","account":"4000","amount":"2.00 USD"}]}"#);
    f.ok(&["post", "--intent", &future, "--evidence", &f.evidence]);
    for (_, _, locator, expectation, _, _) in &saved {
        assert_eq!(
            text(
                &data(&f.ok(&["certificate", "status", locator, "--expect", expectation])),
                "status"
            ),
            "Current"
        );
    }
    let gross = f.file("gross-control.json", r#"{"effective_date":"2026-03-16","idempotency_key":"cert-zero-net","legs":[{"side":"debit","account":"1200","amount":"10.00 USD","party":"C-1"},{"side":"credit","account":"1200","amount":"10.00 USD","party":"C-1"}]}"#);
    let posted = data(&f.ok(&["post", "--intent", &gross, "--evidence", &f.evidence]));
    let current = f.verify("AR", None);
    assert_eq!(
        text(&rows(&current, "totals")[0], "detail_debits"),
        "360.00 USD"
    );
    assert_eq!(
        text(&rows(&current, "totals")[0], "detail_credits"),
        "50.00 USD"
    );
    assert_eq!(text(&rows(&current, "rows")[0], "net"), "60.00 USD");
    for (code, path, locator, expectation, original, bytes) in &saved {
        let status = data(&f.ok(&["certificate", "status", locator, "--expect", expectation]));
        assert_eq!(
            text(&status, "status"),
            if *code == "AR" {
                "SupersededBy"
            } else {
                "Current"
            }
        );
        if *code == "AR" {
            assert_eq!(
                rows(&status, "later_entries"),
                &[Json::Str(text(&posted, "vid"))]
            );
        }
        let output = f.dir.join(format!("{code}.replayed"));
        let before = f.head();
        let replayed = f.ok(&[
            "replay",
            locator,
            "--expect",
            expectation,
            "--output",
            output.to_str().unwrap(),
        ]);
        assert_eq!(&event_data(&replayed, "subledger_reconciled"), original);
        assert_eq!(
            std::fs::read(&output).unwrap(),
            fa::NativeSubledgerCertificate::decode(bytes)
                .unwrap()
                .output()
        );
        assert_eq!(&std::fs::read(path).unwrap(), bytes);
        assert_eq!(f.head(), before);
    }
    let (_, _, locator, expectation, _, _) = &saved[0];
    let before = f.head();
    let output = f.dir.join("wrong-scope.output");
    for wrong in [
        expectation.replace("\"AR\"", "\"AP\""),
        expectation.replace("1200", "1000"),
        expectation.replace("2026-03-31", "2026-03-30"),
        expectation.replace(&format!("\"known_at\":{at}"), "\"known_at\":0"),
    ] {
        assert_eq!(
            f.run(&[
                "replay",
                locator,
                "--expect",
                &wrong,
                "--output",
                output.to_str().unwrap()
            ])
            .0,
            8
        );
        assert!(!output.exists());
    }
    assert_eq!(f.run(&["replay", locator]).0, 8);
    assert_eq!(f.head(), before);
}
