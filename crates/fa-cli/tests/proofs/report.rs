//! Native retained report production checked by the independent std-only fold.
//! The fa process reopens the real book for each operation; verifier calls read
//! only the exported files. The CLI dispatcher is the one used by fa-verify.

use super::*;

fn certify(f: &Fixture, known_at: u64) -> (String, fa::ReportCertificate) {
    let at = known_at.to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&f.book)
        .args([
            "tb",
            "--period",
            "FY2026-P03",
            "--as-known-at",
            &at,
            "--certify",
            "--json",
        ])
        .env_remove("FA_BOOK")
        .output()
        .expect("certify native trial balance");
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
    let metadata = events
        .iter()
        .find(|event| text(event, "event") == "report_certificate")
        .expect("native certificate event");
    let certificate = fa::ReportCertificate::decode(&unhex(text(metadata, "bytes"))).unwrap();
    assert_eq!(certificate.known_at.0, known_at);
    (format!("C:{}", text(metadata, "oid")), certificate)
}

#[test]
fn certified_historical_trial_balance_survives_export_and_offline_recomputation() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    f.post("report-first-sale", "2026-03-10", "12.34", &evidence);
    let known_at = f.head();
    let (locator, certificate) = certify(&f, known_at);
    // A later posting, evidence record and checkpoint must not change the
    // historical answer. They remain in the complete authenticated closure.
    f.post("report-later-sale", "2026-03-20", "2.00", &evidence);
    let state = f.checkpoint();
    let state_oid = text(&state, "oid");
    let signed = exported(&f.book, &["signed-checkpoint", "--state", state_oid]);
    let trusted_key_hex = text(&signed, "checkpoint_public_key");
    let key: [u8; 32] = unhex(trusted_key_hex).try_into().unwrap();
    let checkpoint_bytes = bytes(&signed);
    let anchor = fa_verify::verify_checkpoint(&checkpoint_bytes, &[key]).unwrap();
    let checkpoint_path = f.dir.join("report.checkpoint");
    std::fs::write(&checkpoint_path, &checkpoint_bytes).unwrap();
    let bundle_path = f.dir.join("trial-balance.fab");
    let receipt_path = f.dir.join("trial-balance.receipt");
    let before = f.head();
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
    assert_eq!(get(&produced, "bytes"), &Json::Null);
    assert!(text(&produced, "verify").starts_with("fa-verify report "));
    let expected = fa_verify::blake3::hex(&certificate.digest);
    assert!(text(&produced, "verify").contains(&format!("--expect {expected}")));
    let bundle = std::fs::read(&bundle_path).unwrap();
    let receipt = std::fs::read(&receipt_path).unwrap();
    let verified =
        fa_verify::report::verify_report(&bundle, &[key], Some(&anchor.checkpoint), Some(&receipt))
            .expect("the real producer and independent report fold must agree");
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(verified.output, certificate.output);
    assert_eq!(verified.certificate_digest, certificate.digest);
    assert_eq!(verified.known_at, known_at);
    assert_eq!(verified.rows.len(), 2);
    assert_eq!(verified.rows[0].code, "1000");
    assert_eq!(verified.rows[0].name, "Cash");
    assert_eq!(verified.rows[0].debits, 1234);
    assert_eq!(verified.rows[1].code, "4000");
    assert_eq!(verified.rows[1].credits, 1234);
    assert!(verified.receipt.is_some());
    assert!(verified.checked_records as u64 > certificate.journal_leaves);
    assert_eq!(
        fa_verify::blake3::hex(&verified.bundle_digest),
        text(&produced, "digest")
    );
    // Check the standalone command grammar, exact recipient certificate,
    // independently supplied checkpoint, and detached production receipt.
    let args = [
        "report",
        bundle_path.to_str().unwrap(),
        "--key",
        trusted_key_hex,
        "--checkpoint",
        checkpoint_path.to_str().unwrap(),
        "--receipt",
        receipt_path.to_str().unwrap(),
        "--expect",
        &expected,
        "--json",
    ]
    .map(str::to_string);
    let verified_cli = fa_verify::cli::run(&args, &|path| std::fs::read(path));
    assert_eq!(
        verified_cli.exit, 0,
        "{}{}",
        verified_cli.stdout, verified_cli.stderr
    );
    assert!(verified_cli.stdout.contains("\"verdict\":\"verified\""));
    for predicate in ["report_bundle", "canonical_report", "production_receipt"] {
        assert!(
            verified_cli
                .stdout
                .contains(&format!("\"check\":\"{predicate}\""))
        );
    }
    let mut wrong_question = args.clone();
    wrong_question[9] = "00".repeat(32);
    let refused = fa_verify::cli::run(&wrong_question, &|path| std::fs::read(path));
    assert_eq!(refused.exit, 8, "{}{}", refused.stdout, refused.stderr);
    assert!(refused.stdout.contains("recipient_certificate"));
    assert!(!refused.stdout.contains("\"verdict\":\"verified\""));
    let mut corrupt_receipt = receipt.clone();
    *corrupt_receipt.last_mut().unwrap() ^= 1;
    assert_eq!(
        fa_verify::report::verify_report(&bundle, &[key], None, Some(&corrupt_receipt))
            .unwrap_err()
            .predicate,
        "production_receipt"
    );
    let mut another_checkpoint = anchor.checkpoint;
    another_checkpoint.through_seq += 1;
    assert_eq!(
        fa_verify::report::verify_report(&bundle, &[key], Some(&another_checkpoint), None)
            .unwrap_err()
            .predicate,
        "recipient_checkpoint"
    );
    let inline = ok(
        &f.book,
        &[
            "bundle",
            "produce",
            "--certificate",
            &locator,
            "--state",
            state_oid,
        ],
    );
    assert_eq!(unhex(text(&inline, "bytes")), bundle);
    assert_eq!(
        f.head(),
        before,
        "report production and verification are reads"
    );
}

#[test]
fn report_production_admits_authority_before_observing_certificate_files() {
    let dir = temp_dir();
    let missing_book = dir.join("absent-book");
    for grants in [&["read"][..], &["produce"][..], &[][..]] {
        let authority = LaunchAuthority::new(
            missing_book.clone(),
            None,
            "report-auditor",
            LaunchProfile::Agent,
            grants,
        )
        .unwrap();
        let (exit, refusal) = bound(
            &authority,
            &["bundle", "produce", "--certificate", "absent-certificate"],
        );
        assert_eq!(exit, 7, "{}", refusal.render());
    }
    assert!(!missing_book.exists());
}

fn certify_statement(f: &Fixture, name: &str, known_at: u64) -> (String, fa::ReportCertificate) {
    let at = known_at.to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&f.book)
        .args([
            "statement",
            name,
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
            "--as-known-at",
            &at,
            "--certify",
            "--json",
        ])
        .env_remove("FA_BOOK")
        .output()
        .expect("certify native statement");
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
    let metadata = events
        .iter()
        .find(|event| text(event, "event") == "report_certificate")
        .expect("statement certificate event");
    let certificate = fa::ReportCertificate::decode(&unhex(text(metadata, "bytes"))).unwrap();
    assert_eq!(certificate.known_at.0, known_at);
    assert!(matches!(
        &certificate.selection,
        fa::ReportSelection::Statement(_)
    ));
    (format!("C:{}", text(metadata, "oid")), certificate)
}

#[test]
fn native_statements_and_zero_comparatives_recompute_from_a_later_complete_checkpoint() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    f.post("statement-first-sale", "2026-03-10", "12.34", &evidence);
    let known_at = f.head();
    let certificates = ["balance-sheet", "income-statement"]
        .map(|name| (name, certify_statement(&f, name, known_at)));
    // A later backdated posting is inside the signed checkpoint but outside
    // each report's known-at. The comparative column is authentically zero.
    f.post("statement-later-sale", "2026-03-10", "2.00", &evidence);
    let state = f.checkpoint();
    let before = f.head();
    for (name, (locator, certificate)) in certificates {
        let produced = ok(
            &f.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                &locator,
                "--state",
                text(&state, "oid"),
            ],
        );
        let key: [u8; 32] = unhex(text(&produced, "checkpoint_public_key"))
            .try_into()
            .unwrap();
        let bundle = bytes(&produced);
        let receipt = unhex(text(&produced, "receipt"));
        let verified = fa_verify::report::verify_report(&bundle, &[key], None, Some(&receipt))
            .expect("independent native statement recomputation");
        assert_eq!(verified.output, certificate.output, "{name}");
        assert_eq!(verified.certificate_digest, certificate.digest);
        assert_eq!(verified.known_at, known_at);
        assert!(verified.rows.is_empty());
        let statement = verified.statement.as_ref().expect("statement result");
        assert_eq!(statement.definition_name, name);
        assert_eq!(statement.columns.len(), 2);
        assert_eq!(statement.columns[0].periods, ["FY2026-P03"]);
        assert_eq!(statement.columns[1].periods, ["FY2026-P02"]);
        let expected_line = if name == "balance-sheet" {
            "assets"
        } else {
            "revenue"
        };
        let actual = statement
            .lines
            .iter()
            .find(|line| line.code == expected_line && line.unit == 0)
            .expect("USD statement line");
        assert_eq!(actual.amounts, [1234, 0]);
        let expected_units = fa_money::UnitRegistry::embedded().unwrap().iter().count();
        assert_eq!(
            statement
                .lines
                .iter()
                .filter(|line| line.code == expected_line)
                .count(),
            expected_units
        );
        for line in &statement.lines {
            assert_eq!(
                line.amounts[1], 0,
                "comparative {} {}",
                line.code, line.unit
            );
            if line.unit != 0 {
                assert_eq!(line.amounts, [0, 0]);
            }
        }
        let inline_again = ok(
            &f.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                &locator,
                "--state",
                text(&state, "oid"),
            ],
        );
        assert_eq!(bytes(&inline_again), bundle, "deterministic {name} export");
    }
    assert_eq!(f.head(), before, "statement bundle production is read-only");
}

#[test]
fn certified_income_statement_exports_a_recipient_bound_offline_command() {
    let f = Fixture::new();
    let evidence = f.chart_and_evidence();
    f.post("portable-statement-sale", "2026-03-10", "12.34", &evidence);
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&f.book)
        .args([
            "statement",
            "income-statement",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
            "--certify",
            "--json",
        ])
        .env_remove("FA_BOOK")
        .output()
        .expect("certify a native income statement");
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
    let metadata = events
        .iter()
        .find(|event| text(event, "event") == "report_certificate")
        .expect("retained statement certificate");
    let certificate = fa::ReportCertificate::decode(&unhex(text(metadata, "bytes"))).unwrap();
    assert!(matches!(
        &certificate.selection,
        fa::ReportSelection::Statement(_)
    ));
    let locator = format!("C:{}", text(metadata, "oid"));
    let state = f.checkpoint();
    let state_oid = text(&state, "oid");
    let signed = exported(&f.book, &["signed-checkpoint", "--state", state_oid]);
    let key = text(&signed, "checkpoint_public_key");
    let checkpoint_path = f.dir.join("income-statement.checkpoint");
    let bundle_path = f.dir.join("income-statement.fab");
    let receipt_path = f.dir.join("income-statement.receipt");
    std::fs::write(&checkpoint_path, bytes(&signed)).unwrap();
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
    let units = f
        .open()
        .context()
        .units
        .iter()
        .map(|(id, _)| id.0.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let expected = fa_verify::blake3::hex(&certificate.digest);
    let command = text(&produced, "verify");
    assert!(command.contains("--units "), "{command}");
    assert!(command.contains(&units), "{command}");
    assert!(
        command.contains(&format!("--expect {expected}")),
        "{command}"
    );
    // Use the same actual offline dispatcher as the standalone fa-verify
    // binary. Its only inputs are the exported files and recipient premises.
    let args = [
        "report",
        bundle_path.to_str().unwrap(),
        "--key",
        key,
        "--checkpoint",
        checkpoint_path.to_str().unwrap(),
        "--receipt",
        receipt_path.to_str().unwrap(),
        "--expect",
        &expected,
        "--units",
        &units,
        "--json",
    ]
    .map(str::to_string);
    let verified = fa_verify::cli::run(&args, &|path| std::fs::read(path));
    assert_eq!(verified.exit, 0, "{}{}", verified.stdout, verified.stderr);
    assert!(verified.stdout.contains("\"verdict\":\"verified\""));
    let without_units: Vec<_> = args
        .iter()
        .enumerate()
        .filter_map(|(index, arg)| (!matches!(index, 10 | 11)).then_some(arg.clone()))
        .collect();
    // V2 carries the complete registry closure; explicit units remain an
    // optional equality check, while the pin or receipt authenticates inputs.
    let verified = fa_verify::cli::run(&without_units, &|path| std::fs::read(path));
    assert_eq!(verified.exit, 0, "{}{}", verified.stdout, verified.stderr);
    assert!(verified.stdout.contains("\"verdict\":\"verified\""));
    assert!(verified.stdout.contains("authenticated-registry"));
    let without_authority: Vec<_> = args
        .iter()
        .enumerate()
        .filter_map(|(index, arg)| (!matches!(index, 6 | 7 | 8 | 9)).then_some(arg.clone()))
        .collect();
    let refused = fa_verify::cli::run(&without_authority, &|path| std::fs::read(path));
    assert_eq!(refused.exit, 8, "{}{}", refused.stdout, refused.stderr);
    assert!(refused.stdout.contains("report_input_authority"));
    assert!(!refused.stdout.contains("\"verdict\":\"verified\""));
    let mut wrong_units = args.clone();
    wrong_units[11] = "4294967295".into();
    let refused = fa_verify::cli::run(&wrong_units, &|path| std::fs::read(path));
    assert_eq!(refused.exit, 8, "{}{}", refused.stdout, refused.stderr);
    assert!(refused.stdout.contains("statement_units"));
    assert!(!refused.stdout.contains("\"verdict\":\"verified\""));
}
