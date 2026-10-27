//! A retained lead schedule proves every movement as well as its end balances.

use super::*;

#[test]
fn retained_lead_schedule_and_detail_source_export_by_oid_file_and_bound_stdin() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    fixture.post("lead-opening", "2026-03-05", "10.00", &evidence);
    let offset = fixture.post("lead-offset", "2026-03-10", "12.34", &evidence);
    fixture.post("lead-activity", "2026-03-20", "7.66", &evidence);
    ok(
        &fixture.book,
        &["reverse", text(&offset, "vid"), "--reason", "WrongAccount"],
    );
    let known_at = fixture.head();
    let at = known_at.to_string();
    let certificate_path = fixture.dir.join("lead.certificate");
    let metadata = aging::certify(
        &fixture,
        &[
            "gl",
            "roll-forward",
            "--account",
            "1000",
            "--unit",
            "USD",
            "--from",
            "2026-03-10",
            "--to",
            "2026-03-31",
            "--label",
            "Cash lead schedule",
            "--as-known-at",
            &at,
            "--certificate-out",
            certificate_path.to_str().unwrap(),
        ],
    );
    let encoded = unhex(text(&metadata, "bytes"));
    assert_eq!(std::fs::read(&certificate_path).unwrap(), encoded);
    let certificate = fa::RollForwardCertificate::decode(&encoded).unwrap();
    let expected = fa_verify::blake3::hex(certificate.digest());
    assert_eq!(text(&metadata, "oid"), expected);
    assert_ne!(
        certificate.digest(),
        &certificate.source_certificate().digest
    );

    // GL detail deliberately retains this complete lead-schedule source. The
    // same independently fixed request must name the same portable artifact.
    let detail = aging::certify(
        &fixture,
        &[
            "gl",
            "detail",
            "--account",
            "1000",
            "--unit",
            "USD",
            "--from",
            "2026-03-10",
            "--to",
            "2026-03-31",
            "--label",
            "Cash lead schedule",
            "--as-known-at",
            &at,
        ],
    );
    assert_eq!(unhex(text(&detail, "bytes")), encoded);

    // A later posting inside the saved interval changes HEAD, not the report.
    fixture.post("lead-later-backdate", "2026-03-10", "99.00", &evidence);
    let checkpoint = fixture.checkpoint();
    let signed = exported(
        &fixture.book,
        &["signed-checkpoint", "--state", text(&checkpoint, "oid")],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let before = fixture.head();
    let locator = format!("C:{}", text(&metadata, "oid"));
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
                text(&checkpoint, "oid"),
            ],
        );
        assert_eq!(text(&produced, "scope"), "report");
        assert!(text(&produced, "verify").contains(&format!("--expect {expected}")));
        let bundle = bytes(&produced);
        let receipt = unhex(text(&produced, "receipt"));
        let verified = fa_verify::report::verify_report_expected(
            &bundle,
            &[key],
            None,
            Some(&receipt),
            Some(certificate.digest()),
        )
        .expect("independent verification of the historical lead schedule");
        assert_eq!(verified.certificate_digest, *certificate.digest());
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.known_at, known_at);
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
        assert!(verified.rows.is_empty());
        assert!(verified.aging.is_none());
        let lead = verified.roll_forward.unwrap();
        assert_eq!(lead.label, "Cash lead schedule");
        assert_eq!(lead.rows.len(), 1);
        assert_eq!(lead.rows[0].opening, 1000);
        assert_eq!(lead.rows[0].net_change, 766);
        assert_eq!(lead.rows[0].closing, 1766);
        assert_eq!(lead.movements.len(), 3);
        assert!(
            lead.movements
                .iter()
                .any(|m| m.debits == 1234 && m.credits == 0)
        );
        assert!(
            lead.movements
                .iter()
                .any(|m| m.debits == 0 && m.credits == 1234)
        );
        assert_eq!(
            lead.source_certificate_digest,
            certificate.source_certificate().digest
        );
        assert!(
            fa_verify::report::verify_report_expected(
                &bundle,
                &[key],
                None,
                Some(&receipt),
                Some(&certificate.source_certificate().digest),
            )
            .is_err(),
            "the closing TB alone does not pin the lead schedule's question"
        );
        if let Some(expected) = &original_bundle {
            assert_eq!(&bundle, expected, "OID and file have the same closure");
        } else {
            original_bundle = Some(bundle);
        }
    }

    let authority = LaunchAuthority::new(
        fixture.book.clone(),
        None,
        "lead-reader",
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
        text(&checkpoint, "oid"),
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
    let bundle_path = fixture.dir.join("lead.fab");
    let receipt_path = fixture.dir.join("lead.receipt");
    std::fs::write(&bundle_path, bytes(&produced)).unwrap();
    std::fs::write(&receipt_path, unhex(text(&produced, "receipt"))).unwrap();
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
    assert!(result.stdout.contains("Cash lead schedule"));
    let mut wrong_pin = args;
    wrong_pin[7] = fa_verify::blake3::hex(&certificate.source_certificate().digest);
    let result = fa_verify::cli::run(&wrong_pin, &|path| std::fs::read(path));
    assert_eq!(result.exit, 8, "{}{}", result.stdout, result.stderr);
    fixture.assert_proof_accesses_since(before, "lead-reader", 1);
}
