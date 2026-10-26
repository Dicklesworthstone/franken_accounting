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
    assert_eq!(fixture.head(), before, "all three exports are reads");
}

#[test]
fn other_composed_report_families_do_not_inherit_aging_bundle_support() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    fixture.post("not-portable-equity", "2026-03-10", "5.00", &evidence);
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
    fixture.checkpoint();
    let before = fixture.head();
    let locator = format!("C:{}", text(&metadata, "oid"));
    let (exit, refused) = run(
        &fixture.book,
        &["bundle", "produce", "--certificate", &locator],
    );
    assert_eq!(exit, 3, "{}", refused.render());
    assert!(
        refused
            .render()
            .contains("no independent portable report producer"),
        "{}",
        refused.render()
    );
    assert_eq!(fixture.head(), before);
}
