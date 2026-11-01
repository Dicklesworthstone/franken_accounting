//! Retained historical comparison exported through the real command surfaces.

use super::*;

/// A zero net comparison must not erase a temporary change or the publication
/// of evidence that changes no statement amount. Reopen the book at every CLI
/// step, then give only the signed bundle to the independent verifier.
#[test]
fn statement_trace_exports_every_publication_and_verifies_zero_net_history_offline() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    fixture.post("trace-opening-sale", "2026-03-10", "12.34", &evidence);
    let old_checkpoint = fixture.checkpoint();
    let before = fixture.head();
    let temporary = fixture.post("trace-temporary-sale", "2026-03-10", "2.00", &evidence);
    let note = write(
        &fixture.dir,
        "trace-note.txt",
        "An independently retained review note.",
    );
    ok(
        &fixture.book,
        &[
            "document",
            "add",
            &note,
            "--kind",
            "Receipt",
            "--grade",
            "HumanUpload",
        ],
    );
    ok(
        &fixture.book,
        &[
            "reverse",
            text(&temporary, "vid"),
            "--reason",
            "WrongAccount",
        ],
    );
    let after = fixture.head();
    let path = fixture.dir.join("statement-trace.certificate");
    let metadata = aging::certify(
        &fixture,
        &[
            "statement",
            "trace",
            "--definition",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--before",
            &before.to_string(),
            "--after",
            &after.to_string(),
            "--certificate-out",
            path.to_str().unwrap(),
        ],
    );
    let encoded = unhex(text(&metadata, "bytes"));
    assert_eq!(std::fs::read(&path).unwrap(), encoded);
    let certificate = fa::StatementTraceCertificate::decode(&encoded).unwrap();
    assert_eq!(certificate.sources().len() as u64, after - before + 1);
    let expected = fa_verify::blake3::hex(certificate.digest());
    assert_eq!(text(&metadata, "oid"), expected);
    let locator = format!("C:{expected}");
    let head = fixture.head();
    let (exit, refusal) = run(
        &fixture.book,
        &[
            "bundle",
            "produce",
            "--certificate",
            &locator,
            "--state",
            text(&old_checkpoint, "oid"),
        ],
    );
    assert_ne!(
        exit, 0,
        "an old checkpoint cannot prove later trace sources: {refusal:?}"
    );
    assert_eq!(fixture.head(), head, "a refused export publishes nothing");
    // A later backdated posting cannot substitute the historical trace's last
    // source, even when the proof is built from a newer complete checkpoint.
    fixture.post("trace-later-sale", "2026-03-10", "99.00", &evidence);
    let checkpoint = fixture.checkpoint();
    let signed = exported(
        &fixture.book,
        &["signed-checkpoint", "--state", text(&checkpoint, "oid")],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let mut original = None;
    let mut original_receipt = None;
    let head = fixture.head();
    for source in [locator.as_str(), path.to_str().unwrap()] {
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
        .unwrap();
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.certificate_digest, *certificate.digest());
        assert_eq!(verified.known_at, after);
        assert!(verified.statement.is_none());
        assert!(verified.statement_diff.is_none());
        let trace = verified.statement_trace.unwrap();
        assert_eq!(trace.summary.before_known_at, before);
        assert_eq!(trace.summary.after_known_at, after);
        assert!(trace.summary.lines.iter().all(|line| line.delta == [0]));
        assert_eq!(trace.publications.len() as u64, after - before);
        for (index, publication) in trace.publications.iter().enumerate() {
            assert_eq!(publication.recorded_at, before + index as u64 + 1);
        }
        assert!(
            trace
                .publications
                .iter()
                .any(|p| p.changes.iter().any(|line| line.delta == [200]))
        );
        assert!(
            trace
                .publications
                .iter()
                .any(|p| p.changes.iter().any(|line| line.delta == [-200]))
        );
        assert!(
            trace
                .publications
                .iter()
                .any(|p| p.changes.is_empty() && p.mapping_changes.is_empty())
        );
        assert!(trace.publications.iter().any(|p| p.entries.is_empty()));
        if let Some(original) = &original {
            assert_eq!(&bundle, original);
        } else {
            original = Some(bundle);
            original_receipt = Some(receipt);
        }
    }
    assert_eq!(fixture.head(), head, "owner proof export appends no rows");
    let authority = LaunchAuthority::new(
        fixture.book.clone(),
        None,
        "statement-trace-reader",
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
    assert_eq!(bytes(&produced), original.unwrap());
    let bundle_path = fixture.dir.join("statement-trace.fab");
    let receipt_path = fixture.dir.join("statement-trace.receipt");
    std::fs::write(&bundle_path, bytes(&produced)).unwrap();
    std::fs::write(&receipt_path, original_receipt.unwrap()).unwrap();
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
    assert!(
        result
            .stdout
            .contains("\"report_mode\":\"statement_trace\"")
    );
    assert!(result.stdout.contains("statement_trace_publication"));
    assert!(result.stdout.contains("\"unchanged\":true"));
    let mut wrong_pin = args;
    wrong_pin[7] = fa_verify::blake3::hex(&certificate.sources().last().unwrap().digest);
    let refused = fa_verify::cli::run(&wrong_pin, &|path| std::fs::read(path));
    assert_eq!(refused.exit, 8, "{}{}", refused.stdout, refused.stderr);
    fixture.assert_proof_accesses_since(head, "statement-trace-reader", 1);
}

#[test]
fn statement_diff_exports_by_oid_file_and_bound_stdin_and_verifies_offline() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    fixture.post("diff-initial-sale", "2026-03-10", "12.34", &evidence);
    let before = fixture.head().to_string();
    fixture.post("diff-backdated-sale", "2026-03-10", "2.00", &evidence);
    let after = fixture.head().to_string();
    let path = fixture.dir.join("statement-diff.certificate");
    let metadata = aging::certify(
        &fixture,
        &[
            "statement",
            "diff",
            "--definition",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--before",
            &before,
            "--after",
            &after,
            "--certificate-out",
            path.to_str().unwrap(),
        ],
    );
    let encoded = unhex(text(&metadata, "bytes"));
    assert_eq!(std::fs::read(&path).unwrap(), encoded);
    let certificate = fa::StatementDiffCertificate::decode(&encoded).unwrap();
    let expected = fa_verify::blake3::hex(certificate.digest());
    let locator = format!("C:{expected}");
    assert_eq!(text(&metadata, "oid"), expected);
    fixture.post("diff-later-backdate", "2026-03-10", "99.00", &evidence);
    let checkpoint = fixture.checkpoint();
    let signed = exported(
        &fixture.book,
        &["signed-checkpoint", "--state", text(&checkpoint, "oid")],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let head = fixture.head();
    let mut original = None;
    for source in [locator.as_str(), path.to_str().unwrap()] {
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
        .unwrap();
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.certificate_digest, *certificate.digest());
        assert_eq!(verified.known_at.to_string(), after);
        assert!(verified.statement.is_none());
        let diff = verified.statement_diff.unwrap();
        assert_eq!(diff.before_known_at.to_string(), before);
        assert_eq!(diff.after_known_at.to_string(), after);
        assert!(
            diff.lines
                .iter()
                .any(|line| line.before == [1234] && line.after == [1434] && line.delta == [200])
        );
        if let Some(original) = &original {
            assert_eq!(&bundle, original);
        } else {
            original = Some(bundle);
        }
    }
    assert_eq!(fixture.head(), head, "owner proof export appends no rows");
    let authority = LaunchAuthority::new(
        fixture.book.clone(),
        None,
        "statement-diff-reader",
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
    assert_eq!(bytes(&produced), original.unwrap());
    let bundle_path = fixture.dir.join("statement-diff.fab");
    let receipt_path = fixture.dir.join("statement-diff.receipt");
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
    assert!(result.stdout.contains("\"statement_diff\""));
    let mut wrong_pin = args;
    wrong_pin[7] = fa_verify::blake3::hex(&certificate.sources().1.digest);
    let refused = fa_verify::cli::run(&wrong_pin, &|path| std::fs::read(path));
    assert_eq!(refused.exit, 8, "{}{}", refused.stdout, refused.stderr);
    fixture.assert_proof_accesses_since(head, "statement-diff-reader", 1);
}
