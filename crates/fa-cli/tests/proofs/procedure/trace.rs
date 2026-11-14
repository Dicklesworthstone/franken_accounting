//! A retained tracing question, source evidence and exact amount cross the
//! real CLI producer and independent verifier boundary after reopening.

use super::*;

fn withdrawal(fixture: &Fixture, key: &str, date: &str, amount: &str, evidence: &str) {
    let intent = write(
        &fixture.dir,
        &format!("{key}.json"),
        &format!(
            r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":[{{"side":"debit","account":"4000","amount":"{amount} USD"}},{{"side":"credit","account":"1000","amount":"{amount} USD"}}]}}"#
        ),
    );
    ok(
        &fixture.book,
        &["post", "--intent", &intent, "--evidence", evidence],
    );
}

#[test]
fn libr_certificates_preserve_claim_dates_evidence_replenishment_and_wide_amounts_offline() {
    let fixture = Fixture::new();
    let source_evidence = fixture.chart_and_evidence();
    let unrelated = write(
        &fixture.dir,
        "unrelated-trace-receipt.txt",
        "Separate retained evidence for unrelated cash movements.",
    );
    let clean_evidence = text(
        &ok(
            &fixture.book,
            &[
                "document",
                "add",
                &unrelated,
                "--kind",
                "Receipt",
                "--grade",
                "HumanUpload",
            ],
        ),
        "oid",
    )
    .to_string();
    fixture.post("trace-opening", "2026-03-01", "50.00", &clean_evidence);
    // The source mantissa exceeds u64::MAX; a truncated count transport
    // cannot represent the first claim-date result.
    let source = fixture.post(
        "trace-source",
        "2026-03-02",
        "184467440737095516.17",
        &source_evidence,
    );
    let source_vid = text(&source, "vid").to_string();
    withdrawal(
        &fixture,
        "trace-withdrawal",
        "2026-03-03",
        "184467440737095526.17",
        &clean_evidence,
    );
    fixture.post("trace-clean", "2026-03-04", "100.00", &clean_evidence);
    fixture.post("trace-return", "2026-03-05", "20.00", &source_evidence);
    // This later effective withdrawal is retained in the authenticated
    // source, but must not reduce either earlier claim-date result.
    withdrawal(
        &fixture,
        "trace-after-claim",
        "2026-03-06",
        "200.00",
        &clean_evidence,
    );
    let known_at = fixture.head();
    let at = known_at.to_string();
    let mut saved = Vec::new();
    for (name, through, replenishment, expected, movements) in [
        (
            "at-deposit",
            "2026-03-02",
            "replenishment=0",
            i128::from(u64::MAX) + 2,
            2,
        ),
        ("never", "2026-03-05", "replenishment=0", 4_000, 5),
        ("on-evidence", "2026-03-05", "replenishment=1", 6_000, 5),
    ] {
        let path = fixture.dir.join(format!("trace-{name}.certificate"));
        let (report, metadata) = certified(
            &fixture,
            &[
                "procedure",
                "run",
                "trace.libr@2",
                "--known-at",
                &at,
                "--account",
                "1000",
                "--source",
                &source_vid,
                "--effective-through",
                through,
                "--param",
                "intraday_order=0",
                "--param",
                replenishment,
                "--certificate-out",
                path.to_str().unwrap(),
            ],
        );
        let certificate =
            fa::procedure_certificate::ProcedureCertificate::decode(&bytes(&metadata)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes(&metadata));
        assert_eq!(certificate.known_at().0, known_at);
        let run = certificate.report();
        assert_eq!(run.procedure, "trace.libr");
        assert_eq!(run.version, 2);
        assert_eq!(run.evidence, "FA-EVID-L15");
        assert_eq!(
            run.inputs,
            vec![
                (
                    "account".into(),
                    format!("{:032x}", account_vid(BOOK_ID, "1000").0)
                ),
                ("source".into(), source_vid.clone()),
            ]
        );
        assert_eq!(run.findings.len(), 1);
        let finding = &run.findings[0];
        assert_eq!(finding.statistic.name, "traced_mantissa");
        assert_eq!(finding.statistic.value, expected);
        assert_eq!(finding.statistic.scale, 2);
        assert_eq!(finding.statistic.population, movements);
        assert_eq!(
            finding.cites[0],
            fa_lantern::Cite::Account(account_vid(BOOK_ID, "1000"))
        );
        assert_eq!(
            finding.cites[1],
            fa_lantern::Cite::Entry(fgdb_types::VId(
                u128::from_str_radix(&source_vid, 16).unwrap()
            ))
        );
        let locator = format!("C:{}", text(&metadata, "oid"));
        saved.push((name, path, locator, report, certificate, expected));
    }

    // Later knowledge changes current tracing work/populations; each retained
    // result must still replay its original inputs and claim date exactly.
    fixture.post("trace-later-known", "2026-03-01", "1.00", &clean_evidence);
    for (_, path, locator, report, _, _) in &saved {
        for input in [locator.as_str(), path.to_str().unwrap()] {
            let replayed = ok(&fixture.book, &["replay", input]);
            assert_eq!(replayed.get("data"), report.get("data"));
            assert_eq!(replayed.get("coordinate"), report.get("coordinate"));
        }
        assert_eq!(
            text(
                &ok(&fixture.book, &["certificate", "status", locator]),
                "status"
            ),
            "Changed"
        );
    }
    let state = fixture.checkpoint();
    let signed = exported(
        &fixture.book,
        &["signed-checkpoint", "--state", text(&state, "oid")],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let anchor = fa_verify::verify_checkpoint(&bytes(&signed), &[key]).unwrap();
    let before_export = fixture.head();
    for (name, _, locator, _, certificate, expected) in &saved {
        let produced = ok(
            &fixture.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                locator,
                "--state",
                text(&state, "oid"),
            ],
        );
        let bundle = bytes(&produced);
        let receipt = unhex(text(&produced, "receipt"));
        let verified = fa_verify::report::verify_report_expected(
            &bundle,
            &[key],
            Some(&anchor.checkpoint),
            Some(&receipt),
            Some(certificate.digest()),
        )
        .expect("independent tracing from the complete historical source");
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.known_at, known_at);
        let independent = verified.procedure.unwrap();
        assert_eq!(independent.procedure, "trace.libr");
        assert_eq!(independent.version, 2);
        assert_eq!(independent.live_entries, certificate.report().work.entries);
        assert_eq!(independent.live_legs, certificate.report().work.legs);
        assert_eq!(
            independent.comparisons,
            certificate.report().work.comparisons
        );
        let filename = format!("trace-{name}.fab");
        let result = fa_verify::cli::run(
            &[
                "report",
                &filename,
                "--key",
                text(&signed, "checkpoint_public_key"),
                "--expect",
                &fa_verify::blake3::hex(certificate.digest()),
                "--json",
            ]
            .map(str::to_string),
            &|path| {
                assert_eq!(path, filename, "the verifier has no source-book access");
                Ok(bundle.clone())
            },
        );
        assert_eq!(result.exit, 0, "{}\n{}", result.stdout, result.stderr);
        let rendered = json::parse(&result.stdout).unwrap();
        let checks = get(&rendered, "checks").as_arr().unwrap();
        let finding = checks
            .iter()
            .find(|check| text(check, "check") == "procedure_finding")
            .expect("the verifier renders its reconstructed finding");
        let detail = get(finding, "detail");
        assert_eq!(text(detail, "statistic"), "traced_mantissa");
        assert_eq!(text(detail, "value"), expected.to_string());
        assert_eq!(integer(detail, "scale"), 2);
    }
    assert_eq!(
        fixture.head(),
        before_export,
        "proof export publishes no entry"
    );
}

#[test]
fn fifo_and_lifo_certificates_reopen_and_verify_offline_with_wide_native_amounts() {
    verify_wide_tracing(&[
        (
            "trace.fifo",
            "FA-EVID-L16",
            "2026-03-02",
            i128::from(u64::MAX) + 2,
        ),
        ("trace.fifo", "FA-EVID-L16", "2026-03-05", 4_000),
        (
            "trace.lifo",
            "FA-EVID-L17",
            "2026-03-02",
            i128::from(u64::MAX) + 2,
        ),
        ("trace.lifo", "FA-EVID-L17", "2026-03-05", 0),
    ]);
}

fn verify_wide_tracing(cases: &[(&str, &str, &str, i128)]) {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    fixture.post("ordered-opening", "2026-03-01", "50.00", &evidence);
    let source = fixture.post(
        "ordered-source",
        "2026-03-02",
        "184467440737095516.17",
        &evidence,
    );
    let source_vid = text(&source, "vid").to_string();
    withdrawal(
        &fixture,
        "ordered-withdrawal",
        "2026-03-03",
        "184467440737095526.17",
        &evidence,
    );
    fixture.post("ordered-clean", "2026-03-04", "100.00", &evidence);
    // Shared evidence does not authorize replenishment under either ordered law.
    fixture.post("ordered-return", "2026-03-05", "20.00", &evidence);
    withdrawal(
        &fixture,
        "ordered-after-claim",
        "2026-03-06",
        "200.00",
        &evidence,
    );
    let known_at = fixture.head();
    let at = known_at.to_string();
    let mut saved = Vec::new();
    for &(id, row, through, expected) in cases {
        let path = fixture.dir.join(format!("{id}-{through}.certificate"));
        let (report, metadata) = certified(
            &fixture,
            &[
                "procedure",
                "run",
                id,
                "--known-at",
                &at,
                "--account",
                "1000",
                "--source",
                &source_vid,
                "--effective-through",
                through,
                "--param",
                "intraday_order=0",
                "--certificate-out",
                path.to_str().unwrap(),
            ],
        );
        let certificate =
            fa::procedure_certificate::ProcedureCertificate::decode(&bytes(&metadata)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes(&metadata));
        assert_eq!(certificate.known_at().0, known_at);
        let run = certificate.report();
        assert_eq!(run.procedure, id);
        assert_eq!(run.version, 2);
        assert_eq!(run.evidence, row);
        assert_eq!(run.findings.len(), 1);
        assert_eq!(run.findings[0].statistic.value, expected);
        assert_eq!(run.findings[0].statistic.scale, 2);
        saved.push((
            path,
            format!("C:{}", text(&metadata, "oid")),
            report,
            certificate,
            expected,
        ));
    }
    fixture.post("ordered-later-knowledge", "2026-03-01", "1.00", &evidence);
    for (path, locator, report, _, _) in &saved {
        for input in [locator.as_str(), path.to_str().unwrap()] {
            let replayed = ok(&fixture.book, &["replay", input]);
            assert_eq!(replayed.get("data"), report.get("data"));
            assert_eq!(replayed.get("coordinate"), report.get("coordinate"));
        }
        assert_eq!(
            text(
                &ok(&fixture.book, &["certificate", "status", locator]),
                "status"
            ),
            "Changed"
        );
    }
    let state = fixture.checkpoint();
    let signed = exported(
        &fixture.book,
        &["signed-checkpoint", "--state", text(&state, "oid")],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let before = fixture.head();
    for (_, locator, _, certificate, expected) in &saved {
        let produced = ok(
            &fixture.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                locator,
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
            Some(certificate.digest()),
        )
        .expect("independent ordered tracing from authenticated history");
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.known_at, known_at);
        let independent = verified.procedure.unwrap();
        assert_eq!(independent.procedure, certificate.report().procedure);
        assert_eq!(independent.live_entries, certificate.report().work.entries);
        assert_eq!(independent.live_legs, certificate.report().work.legs);
        assert_eq!(
            independent.comparisons,
            certificate.report().work.comparisons
        );
        let result = fa_verify::cli::run(
            &[
                "report",
                "ordered.fab",
                "--key",
                text(&signed, "checkpoint_public_key"),
                "--expect",
                &fa_verify::blake3::hex(certificate.digest()),
                "--json",
            ]
            .map(str::to_string),
            &|path| {
                assert_eq!(
                    path, "ordered.fab",
                    "offline verification must not open the source book"
                );
                Ok(bundle.clone())
            },
        );
        assert_eq!(result.exit, 0, "{}\n{}", result.stdout, result.stderr);
        let rendered = json::parse(&result.stdout).unwrap();
        let finding = get(&rendered, "checks")
            .as_arr()
            .unwrap()
            .iter()
            .find(|check| text(check, "check") == "procedure_finding")
            .unwrap();
        let detail = get(finding, "detail");
        assert_eq!(text(detail, "statistic"), "traced_mantissa");
        assert_eq!(text(detail, "value"), expected.to_string());
        assert_eq!(integer(detail, "scale"), 2);
    }
    assert_eq!(fixture.head(), before, "export never changes the book");
}
