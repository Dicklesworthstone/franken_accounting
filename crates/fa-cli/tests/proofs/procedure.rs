//! Direct procedure certificates survive reopening and verify independently
//! without publishing a FindingRun or changing the accounting journal.

use super::*;

fn invoke(fixture: &Fixture, arguments: &[&str]) -> (i32, Vec<Json>) {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&fixture.book)
        .args(arguments)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .output()
        .expect("run direct procedure workflow");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let registry = fa_cli::verbs::registry().unwrap();
    let events: Vec<Json> = stdout
        .lines()
        .map(|line| {
            registry
                .check_line(line)
                .unwrap_or_else(|error| panic!("{error}\n{stdout}\n{stderr}"));
            json::parse(line).unwrap()
        })
        .collect();
    assert!(!events.is_empty(), "{arguments:?}: {stdout}\n{stderr}");
    assert_eq!(
        events
            .iter()
            .filter(|event| text(event, "event") == "error")
            .count(),
        usize::from(code != 0),
        "{arguments:?}: {stdout}\n{stderr}"
    );
    (code, events)
}

fn certified(fixture: &Fixture, arguments: &[&str]) -> (Json, Json) {
    let (code, mut events) = invoke(fixture, arguments);
    assert_eq!(code, 0, "{arguments:?}: {events:?}");
    assert_eq!(events.len(), 2, "{events:?}");
    let metadata = events.pop().unwrap();
    let report = events.pop().unwrap();
    assert_eq!(text(&report, "event"), "procedure_run");
    assert_eq!(text(&metadata, "event"), "report_certificate");
    assert_eq!(text(&report, "certificate"), text(&metadata, "oid"));
    (report, metadata)
}

#[test]
fn direct_procedure_certificates_replay_and_verify_without_recording_findings() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    fixture.post("ordinary", "2026-03-15", "1.23", &evidence);
    let selected = fixture.post("selected", "2026-03-29", "1000.00", &evidence);
    fixture.post("after-cutoff", "2026-03-31", "2000.00", &evidence);
    let known_at = fixture.head();
    let at = known_at.to_string();
    let balances = get(
        &ok(&fixture.book, &["tb", "--period", "FY2026-P03"]),
        "rows",
    )
    .clone();
    let mut saved = Vec::new();

    for (selector, id, parameter, explicit_certify) in [
        (
            "jet.round_amounts@2",
            "jet.round_amounts",
            "round_power=3",
            true,
        ),
        (
            "jet.period_end_timing",
            "jet.period_end_timing",
            "window_days=3",
            false,
        ),
    ] {
        let mut arguments = vec![
            "procedure",
            "run",
            selector,
            "--known-at",
            &at,
            "--effective-through",
            "2026-03-30",
            "--param",
            parameter,
        ];
        let before = fixture.head();
        let plain = ok(&fixture.book, &arguments);
        assert_eq!(integer(&plain, "finding_count"), 1);
        assert_eq!(
            text(get(&plain, "coordinate"), "effective"),
            "through:2026-03-30"
        );
        assert_eq!(
            fixture.head(),
            before,
            "plain procedure runs remain read-only"
        );

        let path = fixture.dir.join(format!("{id}.certificate"));
        arguments.extend(["--certificate-out", path.to_str().unwrap()]);
        if explicit_certify {
            arguments.push("--certify");
        }
        let (report, metadata) = certified(&fixture, &arguments);
        assert_eq!(report.get("data"), plain.get("data"));
        assert_eq!(report.get("coordinate"), plain.get("coordinate"));
        assert_eq!(text(&metadata, "output_format"), "fa:procedure-output:v1");
        assert_eq!(integer(&metadata, "known_at"), i128::from(known_at));
        let encoded = bytes(&metadata);
        assert_eq!(std::fs::read(&path).unwrap(), encoded);
        let certificate = fa::procedure_certificate::ProcedureCertificate::decode(&encoded)
            .expect("the complete retained procedure certificate");
        assert_eq!(certificate.report().procedure, id);
        assert_eq!(certificate.report().version, 2);
        assert_eq!(certificate.known_at().0, known_at);
        assert_eq!(
            certificate.report().coordinate.effective_through,
            Some(fa_time::DateDay::parse("2026-03-30").unwrap())
        );
        assert_eq!(
            text(&metadata, "oid"),
            fa_verify::blake3::hex(certificate.digest())
        );
        let locator = format!("C:{}", text(&metadata, "oid"));
        assert_eq!(
            integer(
                &ok(&fixture.book, &["finding", "runs"]),
                "total_recorded_runs"
            ),
            0,
            "certifying a report does not publish a FindingRun"
        );
        assert_eq!(
            get(
                &ok(&fixture.book, &["tb", "--period", "FY2026-P03"]),
                "rows"
            ),
            &balances,
            "retaining a certificate has no accounting effect"
        );
        saved.push((certificate, report, locator, path));
    }

    // These new facts change a fresh run; each saved run keeps the earlier
    // recorded prefix and the civil cutoff chosen before the new posting.
    fixture.post("later-backdated", "2026-03-30", "3000.00", &evidence);
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
    for (certificate, report, locator, path) in saved {
        let fresh = ok(
            &fixture.book,
            &[
                "procedure",
                "run",
                &certificate.report().procedure,
                "--effective-through",
                "2026-03-30",
            ],
        );
        assert_eq!(integer(&fresh, "finding_count"), 2);
        for source in [locator.as_str(), path.to_str().unwrap()] {
            let replayed = ok(&fixture.book, &["replay", source]);
            assert_eq!(text(&replayed, "event"), "procedure_run");
            assert_eq!(replayed.get("data"), report.get("data"));
            assert_eq!(replayed.get("coordinate"), report.get("coordinate"));
            assert_eq!(replayed.get("certificate"), report.get("certificate"));
        }
        assert_eq!(
            text(
                &ok(&fixture.book, &["certificate", "status", &locator]),
                "status"
            ),
            "Changed"
        );
        let produced = ok(
            &fixture.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                &locator,
                "--state",
                text(&state, "oid"),
            ],
        );
        assert_eq!(text(&produced, "scope"), "report");
        let bundle = bytes(&produced);
        let receipt = unhex(text(&produced, "receipt"));
        let verified = fa_verify::report::verify_report_expected(
            &bundle,
            &[key],
            Some(&checkpoint.checkpoint),
            Some(&receipt),
            Some(certificate.digest()),
        )
        .expect("the outsider recomputes the saved procedure from its complete source prefix");
        assert_eq!(verified.output, certificate.output());
        assert_eq!(verified.known_at, known_at);
        let independent = verified.procedure.unwrap();
        assert_eq!(independent.procedure, certificate.report().procedure);
        assert_eq!(independent.version, 2);
        assert_eq!(independent.findings.len(), 1);
        assert_eq!(
            independent.findings[0].entry,
            Some(u128::from_str_radix(text(&selected, "vid"), 16).unwrap())
        );
        assert_eq!(
            independent.effective_through,
            Some(fa_time::DateDay::parse("2026-03-30").unwrap().0)
        );

        let bundle_path = fixture.dir.join(format!("{}.fab", independent.procedure));
        let receipt_path = fixture
            .dir
            .join(format!("{}.receipt", independent.procedure));
        std::fs::write(&bundle_path, &bundle).unwrap();
        std::fs::write(&receipt_path, &receipt).unwrap();
        let pin = fa_verify::blake3::hex(certificate.digest());
        let arguments = [
            "report",
            bundle_path.to_str().unwrap(),
            "--key",
            text(&signed, "checkpoint_public_key"),
            "--receipt",
            receipt_path.to_str().unwrap(),
            "--expect",
            &pin,
            "--json",
        ]
        .map(str::to_string);
        let result = fa_verify::cli::run(&arguments, &|path| std::fs::read(path));
        assert_eq!(result.exit, 0, "{}{}", result.stdout, result.stderr);
    }
    assert_eq!(
        fixture.head(),
        before,
        "replay and export publish no new entries"
    );
    assert_eq!(
        integer(
            &ok(&fixture.book, &["finding", "runs"]),
            "total_recorded_runs"
        ),
        0
    );
}

#[test]
fn post_closing_certificate_exports_original_findings_after_reopening_and_reclosing() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    fixture.post("before-close", "2026-03-20", "10.00", &evidence);
    let closed = ok(&fixture.book, &["period", "soft-close", "FY2026-P03"]);
    let first_close = u64::try_from(integer(&closed, "recorded_at")).unwrap();
    let plan_path = fixture.dir.join("post-closing-reopen.plan");
    let planned = ok(
        &fixture.book,
        &[
            "period",
            "reopen",
            "FY2026-P03",
            "--to",
            "open",
            "--reason",
            "LateTransactions",
            "--plan-out",
            plan_path.to_str().unwrap(),
        ],
    );
    let approval = ok(
        &fixture.book,
        &[
            "approve",
            "--proposal",
            text(&planned, "proposal_digest"),
            "--as",
            "post-closing-reviewer",
        ],
    );
    let reopened = ok(
        &fixture.book,
        &[
            "period",
            "reopen",
            "FY2026-P03",
            "--to",
            "open",
            "--plan",
            plan_path.to_str().unwrap(),
            "--approval",
            text(&approval, "approval_vid"),
            "--yes",
        ],
    );
    assert_eq!(text(&reopened, "to"), "Open");
    let selected = fixture.post("after-reopen", "2026-03-02", "20.00", &evidence);
    let selected_at = u64::try_from(integer(&selected, "recorded_at")).unwrap();
    let known_at = fixture.head();
    let path = fixture.dir.join("post-closing.certificate");
    let (report, metadata) = certified(
        &fixture,
        &[
            "procedure",
            "run",
            "jet.post_closing@1",
            "--certificate-out",
            path.to_str().unwrap(),
        ],
    );
    assert_eq!(integer(&report, "finding_count"), 1);
    let certificate = fa::procedure_certificate::ProcedureCertificate::decode(&bytes(&metadata))
        .expect("retained post-closing certificate");
    assert_eq!(certificate.known_at().0, known_at);
    assert_eq!(certificate.report().version, 1);
    assert!(certificate.report().coordinate.effective_through.is_none());
    assert!(certificate.report().parameters.is_empty());
    assert_eq!(certificate.report().work.comparisons, 2);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        certificate.canonical_bytes().unwrap()
    );
    let locator = format!("C:{}", text(&metadata, "oid"));

    fixture.post("later-after-reopen", "2026-03-01", "30.00", &evidence);
    ok(
        &fixture.book,
        &[
            "period",
            "soft-close",
            "FY2026-P03",
            "--key",
            "post-closing-second-soft-close",
        ],
    );
    ok(
        &fixture.book,
        &[
            "period",
            "close",
            "FY2026-P03",
            "--reason",
            "Scheduled",
            "--yes",
        ],
    );
    let fresh = ok(&fixture.book, &["procedure", "run", "jet.post_closing"]);
    assert_eq!(integer(&fresh, "finding_count"), 2);
    for source in [locator.as_str(), path.to_str().unwrap()] {
        let replayed = ok(&fixture.book, &["replay", source]);
        assert_eq!(replayed.get("data"), report.get("data"));
        assert_eq!(replayed.get("coordinate"), report.get("coordinate"));
    }
    let state = fixture.checkpoint();
    let signed = exported(
        &fixture.book,
        &["signed-checkpoint", "--state", text(&state, "oid")],
    );
    let key: [u8; 32] = unhex(text(&signed, "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let checkpoint = fa_verify::verify_checkpoint(&bytes(&signed), &[key]).unwrap();
    let before_export = fixture.head();
    let produced = ok(
        &fixture.book,
        &[
            "bundle",
            "produce",
            "--certificate",
            &locator,
            "--state",
            text(&state, "oid"),
        ],
    );
    let bundle = bytes(&produced);
    let receipt = unhex(text(&produced, "receipt"));
    let verified = fa_verify::report::verify_report_expected(
        &bundle,
        &[key],
        Some(&checkpoint.checkpoint),
        Some(&receipt),
        Some(certificate.digest()),
    )
    .expect("the independent reader reproduces the first-close finding at its original frontier");
    assert_eq!(verified.output, certificate.output());
    assert_eq!(verified.known_at, known_at);
    let independent = verified.procedure.unwrap();
    assert_eq!(independent.findings.len(), 1);
    assert_eq!(
        independent.findings[0].entry,
        Some(u128::from_str_radix(text(&selected, "vid"), 16).unwrap())
    );
    assert_eq!(
        independent.findings[0].statistic,
        fa_verify::report::VerifiedProcedureStatistic::CommitsAfterClose {
            period: "FY2026-P03".into(),
            commits: selected_at - first_close,
        }
    );
    let pin = fa_verify::blake3::hex(certificate.digest());
    let result = fa_verify::cli::run(
        &[
            "report",
            "post-closing.fab",
            "--key",
            text(&signed, "checkpoint_public_key"),
            "--receipt",
            "post-closing.receipt",
            "--expect",
            &pin,
            "--json",
        ]
        .map(str::to_string),
        &|path| match path {
            "post-closing.fab" => Ok(bundle.clone()),
            "post-closing.receipt" => Ok(receipt.clone()),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "unexpected input",
            )),
        },
    );
    assert_eq!(result.exit, 0, "{}{}", result.stdout, result.stderr);
    assert!(result.stdout.contains("\"procedure\":\"jet.post_closing\""));
    assert!(result.stdout.contains("\"evidence\":\"FA-EVID-L03\""));
    assert!(result.stdout.contains("\"period\":\"FY2026-P03\""));
    assert!(result.stdout.contains("\"commits_after_close\""));
    assert_eq!(
        fixture.head(),
        before_export,
        "proof export does not post accounting entries"
    );
    assert_eq!(
        integer(
            &ok(&fixture.book, &["finding", "runs"]),
            "total_recorded_runs"
        ),
        0
    );
}

#[test]
fn constant_procedure_calls_retain_the_direct_certificate_and_replay_its_original_selection() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    fixture.post("ordinary", "2026-03-15", "1.23", &evidence);
    let selected = fixture.post("selected", "2026-03-29", "100.00", &evidence);
    fixture.post("after-cutoff", "2026-03-31", "200.00", &evidence);
    let known_at = fixture.head();
    let at = known_at.to_string();
    let direct_arguments = [
        "procedure",
        "run",
        "jet.round_amounts@2",
        "--known-at",
        &at,
        "--effective-through",
        "2026-03-30",
        "--param",
        "round_power=2",
        "--budget",
        "100000",
        "--certify",
    ];
    let (expected, direct_metadata) = certified(&fixture, &direct_arguments);
    assert_eq!(integer(&expected, "finding_count"), 1);
    let expected_bytes = bytes(&direct_metadata);
    let statement = format!(
        "CALL fa.jet('round_amounts@2', {{round_power: 2, budget: 100000}}) \
         EFFECTIVE AT '2026-03-30' AS KNOWN AT {known_at}"
    );
    let path = fixture.dir.join("query-procedure.certificate");
    for mode in ["certify", "file", "explain"] {
        let query = if mode == "explain" {
            format!("EXPLAIN (CERTIFICATE) {statement}")
        } else {
            statement.clone()
        };
        let mut arguments = vec!["query", query.as_str()];
        match mode {
            "certify" => arguments.push("--certify"),
            "file" => arguments.extend(["--certificate-out", path.to_str().unwrap()]),
            _ => {}
        }
        let before = fixture.head();
        let (report, metadata) = certified(&fixture, &arguments);
        assert_eq!(report.get("data"), expected.get("data"), "{mode}");
        assert_eq!(bytes(&metadata), expected_bytes, "{mode}");
        assert_eq!(text(&metadata, "output_format"), "fa:procedure-output:v1");
        assert_eq!(
            fixture.head(),
            before,
            "the query spelling reuses the exact retained direct artifact"
        );
    }
    assert_eq!(std::fs::read(&path).unwrap(), expected_bytes);
    let certificate =
        fa::procedure_certificate::ProcedureCertificate::decode(&expected_bytes).unwrap();
    assert_eq!(certificate.report().version, 2);
    assert_eq!(
        certificate.report().parameters,
        vec![("round_power".into(), 2)]
    );
    let locator = format!("C:{}", text(&direct_metadata, "oid"));

    // A retained v1 selection keeps its original no-cutoff algorithm instead
    // of silently using the current version named by the registry.
    let legacy_query = format!(
        "EXPLAIN (CERTIFICATE) CALL fa.jet('round_amounts@1', {{round_power: 2}}) \
         AS KNOWN AT {known_at}"
    );
    let (legacy_report, legacy_metadata) = certified(&fixture, &["query", &legacy_query]);
    let legacy =
        fa::procedure_certificate::ProcedureCertificate::decode(&bytes(&legacy_metadata)).unwrap();
    assert_eq!(legacy.report().version, 1);
    assert!(legacy.report().coordinate.effective_through.is_none());
    assert_eq!(integer(&legacy_report, "finding_count"), 2);
    let legacy_locator = format!("C:{}", text(&legacy_metadata, "oid"));

    fixture.post("later-backdated", "2026-03-30", "300.00", &evidence);
    for source in [locator.as_str(), path.to_str().unwrap()] {
        let replayed = ok(&fixture.book, &["replay", source]);
        assert_eq!(replayed.get("data"), expected.get("data"));
        assert_eq!(replayed.get("certificate"), expected.get("certificate"));
    }
    assert_eq!(
        ok(&fixture.book, &["replay", &legacy_locator]).get("data"),
        legacy_report.get("data")
    );
    assert_eq!(
        text(
            &ok(&fixture.book, &["certificate", "status", &locator]),
            "status"
        ),
        "Changed"
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
    let produced = ok(
        &fixture.book,
        &[
            "bundle",
            "produce",
            "--certificate",
            &locator,
            "--state",
            text(&state, "oid"),
        ],
    );
    let verified = fa_verify::report::verify_report_expected(
        &bytes(&produced),
        &[key],
        Some(&checkpoint.checkpoint),
        Some(&unhex(text(&produced, "receipt"))),
        Some(certificate.digest()),
    )
    .expect("the procedure CALL retains the independently verifiable direct certificate");
    assert_eq!(verified.output, certificate.output());
    assert_eq!(verified.known_at, known_at);
    let independent = verified.procedure.unwrap();
    assert_eq!(independent.version, 2);
    assert_eq!(independent.findings.len(), 1);
    assert_eq!(
        independent.findings[0].entry,
        Some(u128::from_str_radix(text(&selected, "vid"), 16).unwrap())
    );
    assert_eq!(fixture.head(), before);
    assert_eq!(
        integer(
            &ok(&fixture.book, &["finding", "runs"]),
            "total_recorded_runs"
        ),
        0
    );
}

#[test]
fn direct_procedure_certificate_output_refusals_publish_no_findings_or_metadata() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    fixture.post("round", "2026-03-29", "1000.00", &evidence);
    let existing = write(&fixture.dir, "existing.certificate", "preserve this file");
    let unused = fixture.dir.join("unused.certificate");
    let unused = unused.to_str().unwrap();
    let before = fixture.head();
    for arguments in [
        vec!["procedure", "list", "--certify"],
        vec!["procedure", "list", "--certificate-out", unused],
        vec![
            "procedure",
            "run",
            "jet.round_amounts",
            "--certificate-out",
            "-",
        ],
        vec![
            "procedure",
            "run",
            "jet.round_amounts",
            "--certificate-out",
            "",
        ],
        vec![
            "procedure",
            "run",
            "jet.round_amounts",
            "--certificate-out",
            &existing,
        ],
        vec![
            "procedure",
            "run",
            "jet.round_amounts",
            "--certify",
            "--budget",
            "0",
        ],
        vec![
            "procedure",
            "run",
            "jet.round_amounts",
            "--certificate-out",
            unused,
            "--certificate-out",
            unused,
        ],
        vec![
            "query",
            "CALL fa.jet('round_amounts')",
            "--certificate-out",
            "-",
        ],
        vec![
            "query",
            "CALL fa.jet('round_amounts')",
            "--certificate-out",
            &existing,
        ],
        vec![
            "query",
            "CALL fa.jet('round_amounts')",
            "--certificate-out",
            unused,
            "--certificate-out",
            unused,
        ],
        vec![
            "query",
            "EXPLAIN (CERTIFICATE) CALL fa.jet('round_amounts', {budget: 0})",
        ],
        vec![
            "query",
            "CALL fa.jet('round_amounts')",
            "--certify",
            "--branch",
            "scenario:forecast",
        ],
    ] {
        let (code, events) = invoke(&fixture, &arguments);
        assert_eq!(code, 2, "{arguments:?}: {events:?}");
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(text(&events[0], "event"), "error");
        assert_eq!(
            fixture.head(),
            before,
            "{arguments:?} must not retain metadata"
        );
    }
    assert_eq!(
        std::fs::read_to_string(existing).unwrap(),
        "preserve this file"
    );
    assert!(!Path::new(unused).exists());
    assert_eq!(
        integer(
            &ok(&fixture.book, &["finding", "runs"]),
            "total_recorded_runs"
        ),
        0
    );
}
