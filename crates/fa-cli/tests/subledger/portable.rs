//! Real native certificates exported and checked without reopening the book.

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

fn expected(code: &str, control: &str, at: &str) -> String {
    format!(
        r#"{{"kind":"native-subledger-reconciliation","code":"{code}","control_account":"{control}","through":"2026-03-31","known_at":{at}}}"#
    )
}

fn certify(f: &Fixture, code: &str, at: &str) -> (String, fa::NativeSubledgerCertificate) {
    let output = f.ok(&[
        "subledger",
        "verify",
        code,
        "--as-of",
        "2026-03-31",
        "--as-known-at",
        at,
        "--certify",
    ]);
    let metadata = event(&output, "report_certificate");
    let certificate =
        fa::NativeSubledgerCertificate::decode(&unhex(&text(&metadata, "bytes"))).unwrap();
    (format!("C:{}", text(&metadata, "oid")), certificate)
}

#[test]
fn ar_and_ap_export_reopen_and_verify_every_gross_column_offline() {
    let f = Fixture::new();
    f.register("AR", "1200", "receivables");
    f.register("AP", "2000", "payables");
    let invoice = data(&f.invoice("C-1", "PORTABLE-1", "100.00 USD"));
    f.invoice("C-2", "PORTABLE-2", "250.00 USD");
    f.ok(&[
        "receipt",
        "--party",
        "C-1",
        "--number",
        "PORTABLE-REC",
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
    let bill = data(&f.ok(&[
        "bill",
        "--party",
        "V-1",
        "--number",
        "PORTABLE-BILL",
        "--date",
        "2026-03-15",
        "--payable",
        "2000",
        "--expense",
        "6000",
        "--line",
        "amount=\"90.00 USD\"",
        "--evidence",
        &f.evidence,
    ]));
    f.ok(&[
        "payment",
        "--party",
        "V-1",
        "--number",
        "PORTABLE-PAY",
        "--date",
        "2026-03-20",
        "--cash",
        "1000",
        "--payable",
        "2000",
        "--amount",
        "35.00 USD",
        "--applies",
        &text(&bill, "vid"),
        "--evidence",
        &f.evidence,
    ]);
    for (name, legs) in [
        (
            "ar-hold",
            r#"{"side":"debit","account":"1200","amount":"7.00 USD","party":"C-1"},{"side":"credit","account":"1000","amount":"7.00 USD"}"#,
        ),
        (
            "ap-hold",
            r#"{"side":"debit","account":"1000","amount":"5.00 USD"},{"side":"credit","account":"2000","amount":"5.00 USD","party":"V-1"}"#,
        ),
    ] {
        let path = f.file(
            &format!("{name}.json"),
            &format!(
                r#"{{"effective_date":"2026-03-25","idempotency_key":"{name}","legs":[{legs}]}}"#
            ),
        );
        f.ok(&["reserve", "--intent", &path, "--evidence", &f.evidence]);
    }
    let at = f.head();
    let ar = certify(&f, "AR", &at);
    let ap = certify(&f, "AP", &at);
    // The signed checkpoint is later than both certificates; the delivered
    // complete prefix must reproduce the original historical answer.
    f.invoice("C-1", "LATER-PORTABLE", "2.00 USD");
    let state = data(&f.ok(&["checkpoint", "create", "--grant", "witness"]));
    let before = f.head();
    for ((locator, certificate), code, control, amounts) in [
        (ar, "AR", "1200", [35_000, 4_000, 700, 0]),
        (ap, "AP", "2000", [3_500, 9_000, 0, 500]),
    ] {
        let bundle_path = f.dir.join(format!("{code}.fab"));
        let receipt_path = f.dir.join(format!("{code}.receipt"));
        let expectation = expected(code, control, &at);
        let produced = data(&f.ok(&[
            "bundle",
            "produce",
            "--certificate",
            &locator,
            "--expect",
            &expectation,
            "--state",
            &text(&state, "oid"),
            "--out",
            bundle_path.to_str().unwrap(),
            "--receipt-out",
            receipt_path.to_str().unwrap(),
        ]));
        assert_eq!(text(&produced, "scope"), "report");
        assert_eq!(produced.get("bytes"), Some(&Json::Null));
        let native_request = certificate.request().unwrap();
        let expected = fa_verify::report::NativeSubledgerRequest {
            code: code.into(),
            control_account: native_request.control_account.0,
            effective_through: native_request.effective_through.0,
            known_at: at.parse().unwrap(),
        };
        let key_hex = text(&produced, "checkpoint_public_key");
        let key: [u8; 32] = unhex(&key_hex).try_into().unwrap();
        let bundle = std::fs::read(&bundle_path).unwrap();
        let receipt = std::fs::read(&receipt_path).unwrap();
        let verified = fa_verify::report::verify_report_native_subledger_expected(
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
        let report = verified.native_subledger.unwrap();
        assert!(report.reconciled);
        assert_eq!(report.known_at, expected.known_at);
        assert_eq!(report.rows.len(), if code == "AR" { 2 } else { 1 });
        assert_eq!(report.totals.len(), 1);
        let total = &report.totals[0];
        assert_eq!(
            [
                total.detail_debits,
                total.detail_credits,
                total.detail_debits_pending,
                total.detail_credits_pending
            ],
            amounts
        );
        assert_eq!(
            [
                total.control_debits,
                total.control_credits,
                total.control_debits_pending,
                total.control_credits_pending
            ],
            amounts
        );
        let control_vid = format!("0x{:032x}", expected.control_account);
        let through = expected.effective_through.to_string();
        let digest = fa_verify::blake3::hex(certificate.digest());
        let args = [
            "report",
            bundle_path.to_str().unwrap(),
            "--key",
            &key_hex,
            "--receipt",
            receipt_path.to_str().unwrap(),
            "--expect",
            &digest,
            "--subledger",
            code,
            "--control-account",
            &control_vid,
            "--through",
            &through,
            "--known-at",
            &at,
            "--json",
        ]
        .map(str::to_string);
        let offline = |path: &str| {
            assert!(
                path == bundle_path.to_str().unwrap() || path == receipt_path.to_str().unwrap()
            );
            std::fs::read(path)
        };
        let result = fa_verify::cli::run(&args, &offline);
        assert_eq!(result.exit, 0, "{}{}", result.stdout, result.stderr);
        assert!(
            result
                .stdout
                .contains("\"report_mode\":\"native_subledger_reconciliation\"")
        );
        for check in [
            "native_subledger_reconciliation",
            "native_subledger_row",
            "native_subledger_total",
            "canonical_report",
            "production_receipt",
        ] {
            assert!(
                result.stdout.contains(&format!("\"check\":\"{check}\"")),
                "{}",
                result.stdout
            );
        }
        assert!(
            result
                .stdout
                .contains(&format!("\"detail_debits\":\"{}\"", amounts[0]))
        );
        assert!(text(&produced, "verify").contains(&format!(
            "--subledger={code} --control-account {control_vid} --through {through} --known-at {at}"
        )));
        // A signed receipt authenticates the assertion; it cannot choose the
        // recipient's control, date, subledger or historical prefix.
        let generic = args[..8]
            .iter()
            .cloned()
            .chain(["--json".into()])
            .collect::<Vec<_>>();
        assert_eq!(fa_verify::cli::run(&generic, &offline).exit, 8);
        for (index, changed) in [
            (9, "UNKNOWN".to_string()),
            (11, "0x1".to_string()),
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
        "exports read the original prefix without changing the book"
    );
}

#[test]
fn export_requires_the_independent_native_subledger_question() {
    let f = Fixture::new();
    f.register("AR", "1200", "receivables");
    f.invoice("C-1", "REQUEST-BOUND", "25.00 USD");
    let at = f.head();
    let (locator, _) = certify(&f, "AR", &at);
    f.ok(&["checkpoint", "create", "--grant", "witness"]);
    let before = f.head();
    assert_eq!(
        f.run(&["bundle", "produce", "--certificate", &locator]).0,
        2
    );
    let malformed = expected("AR", "1200", "\"HEAD\"");
    assert_eq!(
        f.run(&[
            "bundle",
            "produce",
            "--certificate",
            &locator,
            "--expect",
            &malformed
        ])
        .0,
        2
    );
    for wrong in [
        expected("AP", "1200", &at),
        expected("AR", "2000", &at),
        expected("AR", "1200", &at).replace("2026-03-31", "2026-03-30"),
    ] {
        let (exit, output) = f.run(&[
            "bundle",
            "produce",
            "--certificate",
            &locator,
            "--expect",
            &wrong,
        ]);
        assert_eq!(exit, 8, "{output}");
        assert!(!output.contains("\"event\":\"bundle_produced\""));
    }
    assert_eq!(
        f.head(),
        before,
        "refused exports publish no accounting or audit changes"
    );
}
