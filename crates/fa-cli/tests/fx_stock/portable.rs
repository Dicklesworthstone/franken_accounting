//! A real retained functional certificate travels through the public bundle
//! command and the standalone verifier, preserving its original question.

use super::*;

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn functional_certificates_export_from_retained_and_file_sources_and_verify_offline() {
    let fixture = Fixture::new();
    fixture.post("portable-cli-january", "2026-01-05", "100.00", 11);
    fixture.post("portable-cli-february", "2026-02-05", "50.00", 12);
    let pin = head(&fixture.book).to_string();
    let mut certificates = Vec::new();
    for (name, selection) in [
        ("date", vec!["--as-of", "2026-02-28"]),
        ("stock", vec!["--period", "FY2026-P02"]),
        ("activity", vec!["--activity", "--period", "FY2026-P02"]),
    ] {
        let file = fixture.dir.join(format!("portable-{name}.cert"));
        let mut args = vec!["tb", "--functional"];
        args.extend(selection);
        args.extend([
            "--as-known-at",
            &pin,
            "--certificate-out",
            file.to_str().unwrap(),
        ]);
        let events = ok_many(&fixture.book, &args);
        assert_eq!(events.len(), 2);
        let certificate = fa::ReportCertificate::decode(&std::fs::read(&file).unwrap()).unwrap();
        let reference = format!("C:{}", text(data(&events[1]), "oid"));
        certificates.push((file, reference, certificate));
    }
    fixture.rate("unused-newer-quote", "2026-01-05", 99);
    fixture.post("portable-cli-backdate", "2026-01-20", "20.00", 13);
    let checkpoint = ok(
        &fixture.book,
        &["checkpoint", "create", "--grant", "witness"],
    );
    let state = text(data(&checkpoint), "oid");
    let signed = ok(
        &fixture.book,
        &["proof", "signed-checkpoint", "--state", state],
    );
    let key_text = text(data(&signed), "checkpoint_public_key");
    let key: [u8; 32] = unhex(key_text).try_into().unwrap();
    let before = head(&fixture.book);
    for (file, reference, certificate) in certificates {
        let expected = fa_verify::blake3::hex(&certificate.digest);
        let mut first = None;
        for source in [reference.as_str(), file.to_str().unwrap()] {
            let event = ok(
                &fixture.book,
                &[
                    "bundle",
                    "produce",
                    "--certificate",
                    source,
                    "--state",
                    state,
                ],
            );
            let produced = data(&event);
            assert_eq!(text(produced, "scope"), "report");
            assert!(text(produced, "verify").contains(&format!("--expect {expected}")));
            let bundle = unhex(text(produced, "bytes"));
            let receipt = unhex(text(produced, "receipt"));
            let verified = fa_verify::report::verify_report_expected(
                &bundle,
                &[key],
                None,
                Some(&receipt),
                Some(&certificate.digest),
            )
            .unwrap();
            assert_eq!(verified.output, certificate.output);
            assert_eq!(verified.known_at.to_string(), pin);
            assert!(verified.functional_trial_balance.is_some());
            let args = [
                "report",
                "functional.fab",
                "--key",
                key_text,
                "--receipt",
                "functional.receipt",
                "--expect",
                &expected,
                "--json",
            ]
            .map(str::to_string);
            let read = |name: &str| match name {
                "functional.fab" => Ok(bundle.clone()),
                "functional.receipt" => Ok(receipt.clone()),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    name.to_string(),
                )),
            };
            let result = fa_verify::cli::run(&args, &read);
            assert_eq!(result.exit, 0, "{}{}", result.stdout, result.stderr);
            assert!(result.stdout.contains("\"verdict\":\"verified\""));
            if let Some((expected_bundle, expected_receipt)) = &first {
                assert_eq!(&bundle, expected_bundle);
                assert_eq!(&receipt, expected_receipt);
            } else {
                first = Some((bundle, receipt));
            }
        }
    }
    assert_eq!(
        head(&fixture.book),
        before,
        "owner exports do not publish new report or journal data"
    );
}

#[test]
fn functional_financial_statements_export_and_verify_from_retained_and_file_sources() {
    let fixture = Fixture::new();
    fixture.post("statement-export-cli-january", "2026-01-05", "100.00", 11);
    fixture.post("statement-export-cli-february", "2026-02-05", "200.00", 12);
    let known_at = head(&fixture.book).to_string();
    let mut certificates = Vec::new();
    for (definition, line, amounts) in [
        ("balance-sheet", "assets", vec![35_000, 11_000]),
        ("income-statement", "net_income", vec![24_000, 11_000]),
    ] {
        let file = fixture.dir.join(format!("portable-{definition}.cert"));
        let events = ok_many(
            &fixture.book,
            &[
                "statement",
                definition,
                "--functional",
                "--for",
                "FY2026-P02",
                "--compare",
                "FY2026-P01",
                "--as-known-at",
                &known_at,
                "--certificate-out",
                file.to_str().unwrap(),
            ],
        );
        assert_eq!(events.len(), 2);
        let certificate = fa::ReportCertificate::decode(&std::fs::read(&file).unwrap()).unwrap();
        let reference = format!("C:{}", text(data(&events[1]), "oid"));
        certificates.push((file, reference, certificate, line, amounts));
    }
    fixture.rate("statement-export-unused-quote", "2026-01-05", 99);
    fixture.post("statement-export-cli-backdate", "2026-01-20", "20.00", 13);
    let checkpoint = ok(
        &fixture.book,
        &["checkpoint", "create", "--grant", "witness"],
    );
    let state = text(data(&checkpoint), "oid");
    let signed = ok(
        &fixture.book,
        &["proof", "signed-checkpoint", "--state", state],
    );
    let key_text = text(data(&signed), "checkpoint_public_key");
    let key: [u8; 32] = unhex(key_text).try_into().unwrap();
    let before = head(&fixture.book);
    for (file, reference, certificate, line, amounts) in certificates {
        let expected = fa_verify::blake3::hex(&certificate.digest);
        for source in [reference.as_str(), file.to_str().unwrap()] {
            let event = ok(
                &fixture.book,
                &[
                    "bundle",
                    "produce",
                    "--certificate",
                    source,
                    "--state",
                    state,
                ],
            );
            let produced = data(&event);
            assert_eq!(text(produced, "scope"), "report");
            let bundle = unhex(text(produced, "bytes"));
            let receipt = unhex(text(produced, "receipt"));
            let verified = fa_verify::report::verify_report_expected(
                &bundle,
                &[key],
                None,
                Some(&receipt),
                Some(&certificate.digest),
            )
            .unwrap();
            assert_eq!(verified.output, certificate.output);
            assert_eq!(verified.known_at.to_string(), known_at);
            assert!(verified.statement.is_none());
            let functional = verified.functional_statement.unwrap();
            assert_eq!(functional.statement.columns.len(), 2);
            assert_eq!(
                functional
                    .statement
                    .lines
                    .iter()
                    .find(|row| row.code == line)
                    .unwrap()
                    .amounts,
                amounts
            );
            let args = [
                "report",
                "statement.fab",
                "--key",
                key_text,
                "--receipt",
                "statement.receipt",
                "--expect",
                &expected,
                "--json",
            ]
            .map(str::to_string);
            let result = fa_verify::cli::run(&args, &|name: &str| match name {
                "statement.fab" => Ok(bundle.clone()),
                "statement.receipt" => Ok(receipt.clone()),
                _ => Err(std::io::Error::new(std::io::ErrorKind::NotFound, name)),
            });
            assert_eq!(result.exit, 0, "{}{}", result.stdout, result.stderr);
            for marker in [
                "\"verdict\":\"verified\"",
                "\"report_mode\":\"functional_statement\"",
                "functional_statement_basis",
                "retained-base-amounts",
                "statement_column",
                "statement_line",
            ] {
                assert!(result.stdout.contains(marker), "{}", result.stdout);
            }
        }
    }
    assert_eq!(head(&fixture.book), before);
}
