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

#[test]
fn different_date_duplicate_certificate_replays_and_verifies_its_original_population_offline() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    let first = fixture.post("different-first", "2026-03-01", "12.34", &evidence);
    let same_day = fixture.post("different-same-day", "2026-03-01", "12.34", &evidence);
    let later = fixture.post("different-later-first", "2026-03-03", "12.34", &evidence);
    let later_same_day = fixture.post("different-later-second", "2026-03-03", "12.34", &evidence);
    let last = fixture.post("different-last", "2026-03-05", "12.34", &evidence);
    fixture.post("different-outside-window", "2026-03-08", "12.34", &evidence);
    fixture.post("different-amount", "2026-03-03", "20.00", &evidence);
    let reversed = fixture.post("different-reversed", "2026-03-02", "12.34", &evidence);
    ok(
        &fixture.book,
        &[
            "reverse",
            text(&reversed, "vid"),
            "--reason",
            "WrongAmount",
            "--evidence",
            &evidence,
        ],
    );
    let known_at = fixture.head();
    let certificate_path = fixture.dir.join("different-dates.certificate");
    let (report, metadata) = certified(
        &fixture,
        &[
            "procedure",
            "run",
            "duplicates.same_same_different@1",
            "--param",
            "window_days=2",
            "--certificate-out",
            certificate_path.to_str().unwrap(),
        ],
    );
    assert_eq!(integer(&report, "finding_count"), 4);
    let certificate = fa::procedure_certificate::ProcedureCertificate::decode(&bytes(&metadata))
        .expect("retained different-date duplicate certificate");
    assert_eq!(certificate.known_at().0, known_at);
    assert_eq!(certificate.report().version, 1);
    let locator = format!("C:{}", text(&metadata, "oid"));

    fixture.post(
        "different-later-backdated",
        "2026-03-02",
        "12.34",
        &evidence,
    );
    assert_eq!(
        integer(
            &ok(
                &fixture.book,
                &[
                    "procedure",
                    "run",
                    "duplicates.same_same_different",
                    "--param",
                    "window_days=2",
                ],
            ),
            "finding_count",
        ),
        5,
    );
    for source in [locator.as_str(), certificate_path.to_str().unwrap()] {
        let replayed = ok(&fixture.book, &["replay", source]);
        assert_eq!(replayed.get("data"), report.get("data"));
        assert_eq!(replayed.get("coordinate"), report.get("coordinate"));
    }
    assert_eq!(
        text(
            &ok(&fixture.book, &["certificate", "status", &locator]),
            "status",
        ),
        "Changed",
    );
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
        Some(&anchor.checkpoint),
        Some(&receipt),
        Some(certificate.digest()),
    )
    .expect("independent duplicate replay over the original authenticated population");
    assert_eq!(verified.output, certificate.output());
    assert_eq!(verified.known_at, known_at);
    let independent = verified.procedure.unwrap();
    assert_eq!(independent.live_entries, 7);
    assert_eq!(independent.live_legs, 14);
    assert_eq!(
        independent.comparisons,
        certificate.report().work.comparisons
    );
    let mut actual: Vec<_> = independent
        .findings
        .iter()
        .map(|finding| {
            let fa_verify::report::VerifiedProcedureStatistic::DaysApart {
                earlier,
                later,
                days,
            } = finding.statistic
            else {
                panic!("different-date finding");
            };
            assert_eq!(finding.population, 7);
            (earlier, later, days)
        })
        .collect();
    let identity = |entry: &Json| u128::from_str_radix(text(entry, "vid"), 16).unwrap();
    let mut expected = vec![
        (identity(&first), identity(&later), 2),
        (identity(&same_day), identity(&later), 2),
        (identity(&later), identity(&last), 2),
        (identity(&later_same_day), identity(&last), 2),
    ];
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);

    // Removing a genuine contributing entry fails completeness under the same
    // recipient authority even when no detached receipt is supplied.
    fa_verify::report::verify_report_expected(
        &bundle,
        &[key],
        None,
        None,
        Some(certificate.digest()),
    )
    .unwrap();
    let omitted_digest: [u8; 32] = unhex(text(&later, "entry_digest")).try_into().unwrap();
    let mut reader = fa_model::Reader::new(&bundle);
    reader.bytes(64, "format").unwrap();
    assert_eq!(reader.u16("major").unwrap(), 2);
    reader.u16("minor").unwrap();
    let certificate_bytes = reader.bytes(64 * 1024 * 1024, "certificate").unwrap();
    let certificate_end = reader.offset();
    let certificate_start = certificate_end - certificate_bytes.len();
    reader.bytes(64 * 1024 * 1024, "checkpoint").unwrap();
    reader.bytes(64 * 1024 * 1024, "prefix").unwrap();
    let count_at = reader.offset();
    let count = reader.u32("record count").unwrap();
    let mut omitted = None;
    for _ in 0..count {
        let start = reader.offset();
        reader.u32("proposal length").unwrap();
        let payload = reader.bytes(64 * 1024 * 1024, "record").unwrap();
        if let Ok(entry) = fa_model::Entry::decode(payload)
            && entry.entry_digest == omitted_digest
        {
            assert!(omitted.replace((start, reader.offset())).is_none());
        }
    }
    let (start, end) = omitted.expect("the contributing posting is included in full");
    let mut missing = bundle[..start].to_vec();
    missing.extend_from_slice(&bundle[end..]);
    missing[count_at..count_at + 4].copy_from_slice(&(count - 1).to_le_bytes());
    assert_eq!(
        fa_verify::report::verify_report_expected(
            &missing,
            &[key],
            None,
            None,
            Some(certificate.digest()),
        )
        .unwrap_err()
        .predicate,
        "record_completeness",
    );

    // A self-consistent new certificate digest cannot make a false narrative
    // true. Keep every signed source byte, alter only a result, and rehash its
    // wrapper so refusal must come from independent computation.
    let mut forged_certificate = certificate_bytes.to_vec();
    let narrative = b"two entries share the same legs 2 day(s) apart (window 2)";
    let narrative_at = forged_certificate
        .windows(narrative.len())
        .position(|part| part == narrative)
        .expect("the actual procedure result is retained");
    let numeral_at = narrative.iter().position(|byte| *byte == b'2').unwrap();
    forged_certificate[narrative_at + numeral_at] = b'1';
    let digest_at = forged_certificate.len() - 32;
    let new_digest = fa_verify::blake3::hash_parts(
        b"fa:procedure-certificate-digest:v1",
        &[
            &u32::try_from(digest_at).unwrap().to_le_bytes(),
            &forged_certificate[..digest_at],
        ],
    );
    forged_certificate[digest_at..].copy_from_slice(&new_digest);
    let mut forged = bundle.clone();
    forged[certificate_start..certificate_end].copy_from_slice(&forged_certificate);
    assert_eq!(
        fa_verify::report::verify_report_expected(&forged, &[key], None, None, Some(&new_digest),)
            .unwrap_err()
            .predicate,
        "procedure_recomputation",
    );

    let pin = fa_verify::blake3::hex(certificate.digest());
    for (name, payload, expected_exit) in [
        ("different-dates.fab", &bundle, 0),
        ("missing-posting.fab", &missing, 8),
    ] {
        let result = fa_verify::cli::run(
            &[
                "report",
                name,
                "--key",
                text(&signed, "checkpoint_public_key"),
                "--expect",
                &pin,
                "--json",
            ]
            .map(str::to_string),
            &|path| {
                assert_eq!(path, name, "the verifier cannot open the live book");
                Ok(payload.to_vec())
            },
        );
        eprintln!(
            "different-date proof input={name} exit={} stdout={} stderr={}",
            result.exit, result.stdout, result.stderr,
        );
        assert_eq!(result.exit, expected_exit, "{}", result.stdout);
        if expected_exit == 0 {
            assert!(
                result
                    .stdout
                    .contains("\"procedure\":\"duplicates.same_same_different\"")
            );
            assert!(result.stdout.contains("\"evidence\":\"FA-EVID-L08\""));
            assert!(result.stdout.contains("\"statistic\":\"days_apart\""));
        }
    }
    assert_eq!(
        fixture.head(),
        before_export,
        "proof exports do not post entries"
    );
}

#[test]
fn round_density_certificate_replays_its_account_populations_and_verifies_offline() {
    let fixture = Fixture::new();
    let evidence = fixture.chart_and_evidence();
    let chart = write(
        &fixture.dir,
        "density-background-chart.json",
        r#"{"accounts":[{"code":"1100","name":"Other cash","type":"Asset","unit":"USD"},{"code":"4100","name":"Other revenue","type":"Revenue","unit":"USD"}]}"#,
    );
    ok(&fixture.book, &["chart", "import", &chart]);
    let mut round_entries = Vec::new();
    let mut baseline = Vec::new();
    for index in 0..4 {
        // Recording order and effective order deliberately disagree.
        round_entries.push(fixture.post(
            &format!("density-round-{index}"),
            &format!("2026-03-{:02}", 4 - index),
            "100.00",
            &evidence,
        ));
        let intent = write(
            &fixture.dir,
            &format!("density-background-{index}.json"),
            &format!(
                r#"{{"effective_date":"2026-03-05","idempotency_key":"density-background-{index}","legs":[{{"side":"debit","account":"1100","amount":"1.23 USD"}},{{"side":"credit","account":"4100","amount":"1.23 USD"}}]}}"#
            ),
        );
        baseline.push(ok(
            &fixture.book,
            &["post", "--intent", &intent, "--evidence", &evidence],
        ));
    }
    let known_at = fixture.head();
    let certificate_path = fixture.dir.join("round-density.certificate");
    let (report, metadata) = certified(
        &fixture,
        &[
            "procedure",
            "run",
            "numbers.round_amount_density@1",
            "--param",
            "min_legs=4",
            "--param",
            "round_power=2",
            "--param",
            "z_squared=4",
            "--certificate-out",
            certificate_path.to_str().unwrap(),
        ],
    );
    assert_eq!(integer(&report, "finding_count"), 2);
    let certificate = fa::procedure_certificate::ProcedureCertificate::decode(&bytes(&metadata))
        .expect("retained account round-density certificate");
    assert_eq!(certificate.known_at().0, known_at);
    assert_eq!(certificate.report().version, 1);
    assert_eq!(
        certificate.report().parameters,
        vec![
            ("min_legs".into(), 4),
            ("round_power".into(), 2),
            ("z_squared".into(), 4)
        ]
    );
    assert_eq!(std::fs::read(&certificate_path).unwrap(), bytes(&metadata));
    let locator = format!("C:{}", text(&metadata, "oid"));

    // The original two accounts each have x/n=4/4 versus X/N=8/16, z^2=4.
    // One later backdated nonround posting lowers each score below four.
    fixture.post("density-later-backdated", "2026-03-02", "1.23", &evidence);
    let fresh = ok(
        &fixture.book,
        &[
            "procedure",
            "run",
            "numbers.round_amount_density",
            "--param",
            "min_legs=4",
            "--param",
            "round_power=2",
            "--param",
            "z_squared=4",
        ],
    );
    assert_eq!(integer(&fresh, "finding_count"), 0);
    for source in [locator.as_str(), certificate_path.to_str().unwrap()] {
        let replayed = ok(&fixture.book, &["replay", source]);
        assert_eq!(replayed.get("data"), report.get("data"));
        assert_eq!(replayed.get("coordinate"), report.get("coordinate"));
    }
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
    let anchor = fa_verify::verify_checkpoint(&bytes(&signed), &[key]).unwrap();
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
        Some(&anchor.checkpoint),
        Some(&receipt),
        Some(certificate.digest()),
    )
    .expect("independent account counts and book baseline over the retained population");
    assert_eq!(verified.output, certificate.output());
    assert_eq!(verified.known_at, known_at);
    let independent = verified.procedure.unwrap();
    assert_eq!(
        (
            independent.live_entries,
            independent.live_legs,
            independent.comparisons
        ),
        (8, 16, 4)
    );
    assert_eq!(
        independent.comparisons,
        certificate.report().work.comparisons
    );
    let mut accounts = [
        account_vid(BOOK_ID, "1000").0,
        account_vid(BOOK_ID, "4000").0,
    ];
    accounts.sort_by_key(|account| account.to_le_bytes());
    assert_eq!(independent.findings.len(), accounts.len());
    for (finding, expected_account) in independent.findings.iter().zip(accounts) {
        let fa_verify::report::VerifiedProcedureStatistic::AccountRoundLegs {
            account,
            count,
            legs,
        } = &finding.statistic
        else {
            panic!("account round-density finding");
        };
        assert_eq!(
            (*account, *count, finding.population, finding.severity),
            (expected_account, 4, 4, 2)
        );
        assert_eq!(finding.entry, None);
        let ordinal = if *account == account_vid(BOOK_ID, "1000").0 {
            0
        } else {
            1
        };
        let expected: Vec<_> = round_entries
            .iter()
            .map(|entry| {
                (
                    u128::from_str_radix(text(entry, "vid"), 16).unwrap(),
                    ordinal,
                )
            })
            .collect();
        assert_eq!(legs, &expected);
    }

    // An uncited, nonround posting still establishes the baseline. Omitting it
    // would move z^2 from four to three, and must fail prefix completeness.
    let omitted_digest: [u8; 32] = unhex(text(&baseline[0], "entry_digest"))
        .try_into()
        .unwrap();
    let mut reader = fa_model::Reader::new(&bundle);
    reader.bytes(64, "format").unwrap();
    assert_eq!(reader.u16("major").unwrap(), 2);
    reader.u16("minor").unwrap();
    let certificate_bytes = reader.bytes(64 * 1024 * 1024, "certificate").unwrap();
    let certificate_end = reader.offset();
    let certificate_start = certificate_end - certificate_bytes.len();
    reader.bytes(64 * 1024 * 1024, "checkpoint").unwrap();
    reader.bytes(64 * 1024 * 1024, "prefix").unwrap();
    let count_at = reader.offset();
    let count = reader.u32("record count").unwrap();
    let mut omitted = None;
    for _ in 0..count {
        let start = reader.offset();
        reader.u32("proposal length").unwrap();
        let payload = reader.bytes(64 * 1024 * 1024, "record").unwrap();
        if let Ok(entry) = fa_model::Entry::decode(payload)
            && entry.entry_digest == omitted_digest
        {
            assert!(omitted.replace((start, reader.offset())).is_none());
        }
    }
    let (start, end) = omitted.expect("the uncited baseline posting is retained");
    let mut missing = bundle[..start].to_vec();
    missing.extend_from_slice(&bundle[end..]);
    missing[count_at..count_at + 4].copy_from_slice(&(count - 1).to_le_bytes());
    assert_eq!(
        fa_verify::report::verify_report_expected(
            &missing,
            &[key],
            None,
            None,
            Some(certificate.digest())
        )
        .unwrap_err()
        .predicate,
        "record_completeness"
    );

    // Alter the numerical finding, then recompute its outer commitment and
    // supply that new expected digest. Signed inputs remain unchanged, so the
    // false count can fail only after the result is independently recomputed.
    let mut output = fa_model::Reader::new(certificate.output());
    output.bytes(64, "output format").unwrap();
    output.str(128, "procedure id").unwrap();
    output.u16("version").unwrap();
    output.u8("claim").unwrap();
    output.str(128, "evidence").unwrap();
    output.fixed::<16>("book").unwrap();
    output.u64("known at").unwrap();
    assert_eq!(output.u8("cutoff").unwrap(), 0);
    assert_eq!(output.u32("parameters").unwrap(), 3);
    for _ in 0..3 {
        output.str(64, "parameter").unwrap();
        output.i128("value").unwrap();
    }
    assert_eq!(output.u32("handles").unwrap(), 0);
    output.fixed::<32>("parameters digest").unwrap();
    output.fixed::<32>("inputs digest").unwrap();
    for field in ["population", "entries", "legs", "comparisons"] {
        output.u64(field).unwrap();
    }
    assert_eq!(output.u32("findings").unwrap(), 2);
    output.str(128, "finding procedure").unwrap();
    output.u16("finding version").unwrap();
    output.u8("severity").unwrap();
    assert_eq!(output.str(64, "statistic").unwrap(), "round_legs");
    let statistic_at = output.offset();
    assert_eq!(output.i128("round count").unwrap(), 4);
    let mut forged_certificate = certificate_bytes.to_vec();
    let digest_at = forged_certificate.len() - 32;
    let output_start = digest_at - certificate.output().len();
    assert_eq!(
        &forged_certificate[output_start..digest_at],
        certificate.output()
    );
    forged_certificate[output_start + statistic_at..output_start + statistic_at + 16]
        .copy_from_slice(&3i128.to_le_bytes());
    let new_digest = fa_verify::blake3::hash_parts(
        b"fa:procedure-certificate-digest:v1",
        &[
            &u32::try_from(digest_at).unwrap().to_le_bytes(),
            &forged_certificate[..digest_at],
        ],
    );
    forged_certificate[digest_at..].copy_from_slice(&new_digest);
    let mut forged = bundle.clone();
    forged[certificate_start..certificate_end].copy_from_slice(&forged_certificate);
    assert_eq!(
        fa_verify::report::verify_report_expected(&forged, &[key], None, None, Some(&new_digest))
            .unwrap_err()
            .predicate,
        "procedure_recomputation"
    );

    let pin = fa_verify::blake3::hex(certificate.digest());
    let forged_pin = fa_verify::blake3::hex(&new_digest);
    for (name, payload, expected, expected_exit) in [
        ("round-density.fab", &bundle, &pin, 0),
        ("missing-density-baseline.fab", &missing, &pin, 8),
        ("forged-density-count.fab", &forged, &forged_pin, 8),
    ] {
        let result = fa_verify::cli::run(
            &[
                "report",
                name,
                "--key",
                text(&signed, "checkpoint_public_key"),
                "--expect",
                expected,
                "--json",
            ]
            .map(str::to_string),
            &|path| {
                assert_eq!(path, name, "the verifier cannot read the source book");
                Ok(payload.to_vec())
            },
        );
        eprintln!(
            "round-density proof input={name} exit={} stdout={} stderr={}",
            result.exit, result.stdout, result.stderr,
        );
        assert_eq!(result.exit, expected_exit, "{}", result.stdout);
        if expected_exit == 0 {
            assert!(
                result
                    .stdout
                    .contains("\"procedure\":\"numbers.round_amount_density\"")
            );
            assert!(result.stdout.contains("\"evidence\":\"FA-EVID-L64\""));
            assert!(result.stdout.contains("\"statistic\":\"round_legs\""));
            assert!(
                result
                    .stdout
                    .contains(&format!("\"account\":\"{:032x}\"", accounts[0]))
            );
            assert!(result.stdout.contains("\"legs\":["));
        }
    }
    assert_eq!(
        fixture.head(),
        before_export,
        "proof export does not post entries"
    );
}
