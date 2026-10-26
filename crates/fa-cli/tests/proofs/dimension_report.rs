//! Real v8 producers and the independent, std-only dimension fold agree.
//! The verifier receives only exported bytes and recipient-selected anchors.

use super::*;

fn add_value(f: &Fixture, code: &str, parent: Option<&str>) {
    let mut args = vec!["dimension", "add", "cost_center", code, "--name", code];
    if let Some(parent) = parent {
        args.extend(["--parent", parent]);
    }
    ok(&f.book, &args);
}

fn tagged(
    f: &Fixture,
    verb: &str,
    key: &str,
    date: &str,
    value: &str,
    amount: &str,
    evidence: &str,
) -> Json {
    let path = write(
        &f.dir,
        &format!("{key}.json"),
        &format!(
            r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":[{{"side":"debit","account":"1000","amount":"{amount} USD","dimensions":{{"cost_center":"{value}"}}}},{{"side":"credit","account":"4000","amount":"{amount} USD"}}]}}"#,
        ),
    );
    ok(&f.book, &[verb, "--intent", &path, "--evidence", evidence])
}

fn certify(
    f: &Fixture,
    dimension: &str,
    selector: &[&str],
    known_at: u64,
) -> (String, fa::ReportCertificate) {
    let at = known_at.to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&f.book)
        .arg("tb")
        .args(selector)
        .args([
            "--dimension",
            dimension,
            "--as-known-at",
            &at,
            "--certify",
            "--json",
        ])
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .env_remove("FA_KEYS")
        .output()
        .expect("certify dimension trial balance");
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
    assert_eq!(events.len(), 2, "{stdout}");
    assert_eq!(text(&events[0], "event"), "trial_balance");
    assert_eq!(text(&events[1], "event"), "report_certificate");
    let encoded = bytes(&events[1]);
    assert!(encoded.starts_with(b"fa:report-certificate:v8"));
    let certificate = fa::ReportCertificate::decode(&encoded).unwrap();
    assert_eq!(certificate.known_at.0, known_at);
    assert_eq!(certificate.inputs.len(), 8);
    (format!("C:{}", text(&events[1], "oid")), certificate)
}

#[test]
fn dimension_reports_export_historical_stock_activity_as_of_and_empty_selections() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    ok(&f.book, &["period", "open", "FY2026-P02"]);
    add_value(&f, "CC", None);
    add_value(&f, "CC10", Some("CC"));
    add_value(&f, "OTHER", None);
    add_value(&f, "EMPTY", None);
    tagged(
        &f,
        "post",
        "prior-stock",
        "2026-02-20",
        "CC",
        "7.00",
        &evidence,
    );
    tagged(
        &f,
        "post",
        "child-sale",
        "2026-03-10",
        "CC10",
        "12.34",
        &evidence,
    );
    tagged(
        &f,
        "post",
        "other-sale",
        "2026-03-11",
        "OTHER",
        "2.00",
        &evidence,
    );
    f.post("untagged-sale", "2026-03-12", "3.00", &evidence);
    let hold = tagged(
        &f,
        "reserve",
        "child-hold",
        "2026-03-15",
        "CC10",
        "5.00",
        &evidence,
    );
    // Closing a value does not remove its recorded history from the subtree.
    ok(
        &f.book,
        &[
            "dimension",
            "close",
            "cost_center",
            "CC10",
            "--on",
            "2026-03-25",
        ],
    );
    let selected = f.head();
    let mut reports = Vec::new();
    for (name, dimension, selector, posted, pending, values) in [
        (
            "stock",
            "cost_center=CC",
            vec!["--period", "FY2026-P03"],
            1934,
            500,
            vec!["CC", "CC10"],
        ),
        (
            "activity",
            "cost_center=CC",
            vec!["--period", "FY2026-P03", "--activity"],
            1234,
            500,
            vec!["CC", "CC10"],
        ),
        (
            "as-of",
            "cost_center=CC",
            vec!["--as-of", "2026-03-11"],
            1934,
            0,
            vec!["CC", "CC10"],
        ),
        (
            "empty",
            "cost_center=EMPTY",
            vec!["--period", "FY2026-P03"],
            0,
            0,
            vec!["EMPTY"],
        ),
    ] {
        let (locator, certificate) = certify(&f, dimension, &selector, selected);
        reports.push((name, locator, certificate, posted, pending, values));
    }

    // A later descendant, a backdated posting and a pending release are all
    // present in the exported checkpoint, but cannot alter the old reports.
    add_value(&f, "CC20", Some("CC"));
    tagged(
        &f,
        "post",
        "later-child-sale",
        "2026-03-12",
        "CC20",
        "9.00",
        &evidence,
    );
    let release = write(
        &f.dir,
        "release.json",
        &format!(
            r#"{{"resolves":"{}","disposition":"voids","effective_date":"2026-03-20","idempotency_key":"release-child-hold"}}"#,
            text(&hold, "vid")
        ),
    );
    ok(&f.book, &["resolve", "--intent", &release, "--yes"]);
    let (locator, certificate) =
        certify(&f, "cost_center=CC", &["--period", "FY2026-P03"], f.head());
    reports.push((
        "current",
        locator,
        certificate,
        2834,
        0,
        vec!["CC", "CC10", "CC20"],
    ));

    let state = f.checkpoint();
    let state_oid = text(&state, "oid");
    let signed = exported(&f.book, &["signed-checkpoint", "--state", state_oid]);
    let key_hex = text(&signed, "checkpoint_public_key");
    let key: [u8; 32] = unhex(key_hex).try_into().unwrap();
    let checkpoint_bytes = bytes(&signed);
    let anchor = fa_verify::verify_checkpoint(&checkpoint_bytes, &[key]).unwrap();
    let checkpoint_path = f.dir.join("dimensions.checkpoint");
    std::fs::write(&checkpoint_path, checkpoint_bytes).unwrap();
    let before = f.head();

    for (name, locator, certificate, posted, pending, values) in reports {
        let bundle_path = f.dir.join(format!("{name}.fab"));
        let receipt_path = f.dir.join(format!("{name}.receipt"));
        let produced = ok(
            &f.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                &locator,
                "--state",
                state_oid,
                "--out",
                bundle_path.to_str().unwrap(),
                "--receipt-out",
                receipt_path.to_str().unwrap(),
            ],
        );
        assert_eq!(text(&produced, "scope"), "report");
        let bundle = std::fs::read(&bundle_path).unwrap();
        let receipt = std::fs::read(&receipt_path).unwrap();
        let verified = fa_verify::report::verify_report(
            &bundle,
            &[key],
            Some(&anchor.checkpoint),
            Some(&receipt),
        )
        .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(verified.scope, "recomputation");
        assert_eq!(verified.output, certificate.output, "{name}");
        assert_eq!(verified.certificate_digest, certificate.digest);
        assert_eq!(verified.known_at, certificate.known_at.0);
        if name == "current" {
            // The bundle carries every leaf of the checkpoint's prefix: the
            // current report's journal entries and the fixture's one
            // document receipt, an evidence leaf since fa-va02. A report
            // certificate's journal counts entries only.
            assert_eq!(
                verified.checked_records as u64,
                certificate.journal_leaves + 1,
                "{name}"
            );
        } else {
            assert!(verified.checked_records as u64 > certificate.journal_leaves);
        }
        assert!(verified.receipt.is_some());
        let selection = verified
            .dimension
            .as_ref()
            .expect("verified dimension selector");
        assert_eq!(selection.dimension, "cost_center");
        assert_eq!(
            selection.value,
            if name == "empty" { "EMPTY" } else { "CC" }
        );
        assert_eq!(selection.values, values);
        assert_eq!(verified.activity, name == "activity");
        if name == "empty" {
            assert!(verified.rows.is_empty());
        } else {
            assert_eq!(verified.rows.len(), 1, "only the tagged debit is selected");
            let row = &verified.rows[0];
            assert_eq!(row.code, "1000");
            assert_eq!((row.debits, row.credits), (posted, 0));
            assert_eq!((row.debits_pending, row.credits_pending), (pending, 0));
        }
        // Execute the public offline command with a reader that can access
        // only the three supplied artifacts, never the source book.
        let expected = fa_verify::blake3::hex(&certificate.digest);
        let args = [
            "report",
            bundle_path.to_str().unwrap(),
            "--key",
            key_hex,
            "--checkpoint",
            checkpoint_path.to_str().unwrap(),
            "--receipt",
            receipt_path.to_str().unwrap(),
            "--expect",
            &expected,
            "--json",
        ]
        .map(str::to_string);
        let allowed = [&bundle_path, &receipt_path, &checkpoint_path];
        let result = fa_verify::cli::run(&args, &|path| {
            assert!(
                allowed
                    .iter()
                    .any(|allowed| allowed.as_path() == Path::new(path))
            );
            std::fs::read(path)
        });
        assert_eq!(result.exit, 0, "{name}: {}{}", result.stdout, result.stderr);
        let robot = json::parse(result.stdout.trim()).unwrap();
        assert_eq!(text(&robot, "verdict"), "verified");
        let dimension_check = get(&robot, "checks")
            .as_arr()
            .unwrap()
            .iter()
            .find(|check| text(check, "check") == "dimension_filter")
            .expect("offline CLI reports its authenticated dimension selection");
        assert_eq!(text(dimension_check, "result"), "pass");
        assert_eq!(text(dimension_check, "scope"), "authenticated_journal");
        let detail = get(dimension_check, "detail");
        assert_eq!(text(detail, "dimension"), "cost_center");
        assert_eq!(text(detail, "value"), selection.value);
        assert_eq!(
            get(detail, "included_values"),
            &Json::Arr(
                values
                    .iter()
                    .map(|value| Json::Str((*value).into()))
                    .collect()
            )
        );
        assert_eq!(
            f.head(),
            before,
            "export and offline verification publish nothing"
        );
    }
}

#[test]
fn dimension_report_export_requires_produce_before_disclosing_or_writing() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    add_value(&f, "CC", None);
    tagged(
        &f,
        "post",
        "restricted-sale",
        "2026-03-10",
        "CC",
        "4.00",
        &evidence,
    );
    let (locator, _) = certify(&f, "cost_center=CC", &["--period", "FY2026-P03"], f.head());
    f.checkpoint();
    let before = f.head();
    let mut book = f.open();
    let principal = principal_vid("dimension-reader");
    let reader = Capability::embedded(principal, &["read"]).unwrap();
    let digest: [u8; 32] = unhex(locator.strip_prefix("C:").unwrap())
        .try_into()
        .unwrap();
    let certificate = book.read_certificate(&digest).unwrap().unwrap();
    let refused = book
        .produce_report_bundle(principal, &reader, None, &certificate)
        .unwrap()
        .unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-011", 7));
    assert!(refused.message.contains("produce"));
    assert_eq!(book.head().unwrap().0, before);
}
