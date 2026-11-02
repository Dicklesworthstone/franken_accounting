use super::*;

fn event<'a>(events: &'a [Json], name: &str) -> &'a Json {
    data(
        events
            .iter()
            .find(|value| text(value, "event") == name)
            .unwrap_or_else(|| panic!("missing {name}: {events:?}")),
    )
}

fn approved_review(
    fixture: &Fixture,
    file: &Path,
    from: &str,
    key: &str,
) -> (PathBuf, String, String) {
    let plan = fixture.dir.join(format!("{key}.plan"));
    let result = ok(
        &fixture.book,
        &[
            "statement",
            "define",
            "--file",
            file.to_str().unwrap(),
            "--from",
            from,
            "--key",
            key,
            "--plan-out",
            plan.to_str().unwrap(),
        ],
    );
    let digest = text(
        event(&result, "statement_definition_plan"),
        "proposal_digest",
    );
    let approve = |who| {
        let approved = ok(
            &fixture.book,
            &["approve", "--proposal", digest, "--as", who],
        );
        text(data(&approved[0]), "approval_vid").to_string()
    };
    (
        plan,
        approve("statement-controller-a"),
        approve("statement-controller-b"),
    )
}

fn activate(fixture: &Fixture, plan: &Path, a: &str, b: &str) -> Vec<Json> {
    ok(
        &fixture.book,
        &[
            "statement",
            "activate",
            "--plan",
            plan.to_str().unwrap(),
            "--approval",
            a,
            "--approval",
            b,
        ],
    )
}

fn layout(fixture: &Fixture, version: u32) -> PathBuf {
    let mut definition = fa::CustomStatementDefinition::from_builtin(
        &fa::StatementDefinition::embedded("income-statement").unwrap(),
    );
    definition.name = "company-income".into();
    definition.version = version;
    definition.lines[0].label = format!("Company sales v{version}");
    let path = fixture.dir.join(format!("company-income-v{version}.toml"));
    std::fs::write(&path, definition.to_toml().unwrap()).unwrap();
    path
}

fn issue(fixture: &Fixture, certificate: &str) {
    let plan = ok(
        &fixture.book,
        &[
            "statement",
            "issue",
            "--certificate",
            certificate,
            "--issued-to",
            "board",
            "--dry-run",
        ],
    );
    let plan = event(&plan, "statement_issuance_plan");
    let path = fixture.dir.join("company-issuance.plan");
    std::fs::write(&path, text(plan, "bytes")).unwrap();
    let approved = ok(
        &fixture.book,
        &[
            "approve",
            "--proposal",
            text(plan, "proposal_digest"),
            "--as",
            "issuance-controller",
        ],
    );
    ok(
        &fixture.book,
        &[
            "statement",
            "issue",
            "--plan",
            path.to_str().unwrap(),
            "--approval",
            text(data(&approved[0]), "approval_vid"),
        ],
    );
}

#[test]
fn approved_company_layout_certifies_rounding_and_replays_after_postings_and_new_versions() {
    let fixture = Fixture::new();
    let source = layout(&fixture, 1);
    let lint = ok(
        &fixture.book,
        &["statement", "lint", "--file", source.to_str().unwrap()],
    );
    assert_eq!(
        event(&lint, "statement_lint").get("clean"),
        Some(&Json::Bool(true))
    );
    let (plan, a, b) = approved_review(&fixture, &source, "2026-01-01", "company-v1");
    let activated = activate(&fixture, &plan, &a, &b);
    let activation = text(
        event(&activated, "statement_definition_activated"),
        "activation",
    );
    let retry = activate(&fixture, &plan, &a, &b);
    assert_eq!(
        event(&retry, "statement_definition_activated").get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        text(
            event(&retry, "statement_definition_activated"),
            "activation"
        ),
        activation
    );

    let report = ok(
        &fixture.book,
        &[
            "statement",
            "custom",
            "--definition",
            "company-income",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
            "--certify",
            "--scale-digits",
            "3",
            "--rounding",
            "HalfEven",
            "--residual-line",
            "rounding",
            "--residual-label",
            "Presentation rounding",
        ],
    );
    let exact = event(&report, "statement").clone();
    assert_eq!(
        line(&exact, "net_income", "USD"),
        &[Json::Str("80.00 USD".into()), Json::Str("75.00 USD".into())]
    );
    let presented = event(&report, "custom_statement").clone();
    assert_eq!(presented.get("rounded"), Some(&Json::Bool(true)));
    assert_eq!(presented.get("divisor"), Some(&Json::Int(1000)));
    assert_eq!(text(&presented, "activation"), activation);
    let certificate = format!("C:{}", text(event(&report, "report_certificate"), "oid"));
    issue(&fixture, &certificate);

    fixture.post(
        "later-custom-sale",
        "2026-03-12",
        "1000",
        "4000",
        "5.00 USD",
    );
    let after = ok(
        &fixture.book,
        &[
            "statement",
            "custom",
            "--definition",
            "company-income",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
            "--certify",
            "--scale-digits",
            "3",
            "--rounding",
            "HalfEven",
            "--residual-line",
            "rounding",
            "--residual-label",
            "Presentation rounding",
        ],
    );
    let after_certificate = format!("C:{}", text(event(&after, "report_certificate"), "oid"));
    let v2 = layout(&fixture, 2);
    let (plan2, a2, b2) = approved_review(&fixture, &v2, "2026-02-01", "company-v2");
    activate(&fixture, &plan2, &a2, &b2);
    let current = ok(
        &fixture.book,
        &[
            "statement",
            "custom",
            "--definition",
            "company-income",
            "--for",
            "FY2026-P03",
            "--as-currently-stated",
            "--certify",
        ],
    );
    assert_eq!(
        event(&current, "custom_statement").get("version"),
        Some(&Json::Int(2))
    );
    assert_eq!(
        line(event(&current, "statement"), "net_income", "USD"),
        &[Json::Str("85.00 USD".into())]
    );
    let replay = ok(&fixture.book, &["replay", &certificate]);
    assert_eq!(event(&replay, "statement"), &exact);
    assert_eq!(event(&replay, "custom_statement"), &presented);
    // The saved question includes its comparative and presentation. Leaving
    // those flags out inherits them, including after v2 became active.
    let command = [
        "statement",
        "custom",
        "--definition",
        "company-income",
        "--for",
        "FY2026-P03",
    ];
    for view in [
        vec!["--as-originally-reported"],
        vec!["--as-issued-to", "board"],
        vec!["--as-reported-in", &certificate],
    ] {
        let original = ok(
            &fixture.book,
            &[&command[..], &view, &["--certify"]].concat(),
        );
        assert_eq!(event(&original, "statement"), &exact);
        assert_eq!(event(&original, "custom_statement"), &presented);
        assert_eq!(
            text(event(&original, "report_certificate"), "oid"),
            text(event(&report, "report_certificate"), "oid"),
            "the issued certificate is preserved, not regenerated"
        );
    }
    for mismatch in [
        vec!["--compare", "FY2026-P01"],
        vec!["--functional"],
        vec![
            "--scale-digits",
            "2",
            "--rounding",
            "HalfEven",
            "--residual-line",
            "rounding",
            "--residual-label",
            "Presentation rounding",
        ],
    ] {
        let (exit, events, _) = run(
            &fixture.book,
            &[
                &command[..],
                &["--as-reported-in", &certificate, "--certify"],
                &mismatch,
            ]
            .concat(),
        );
        assert_eq!(exit, 8, "{events:?}");
        assert_eq!(
            events.len(),
            1,
            "no statement or certificate before refusal"
        );
        assert_eq!(text(&events[0], "event"), "error");
    }
    // Both source certificates survive an unrelated later activation.
    // Their exact financial differences never use rounded displayed cells.
    let compared = ok(
        &fixture.book,
        &[
            "statement",
            "diff",
            "--before-certificate",
            &certificate,
            "--after-certificate",
            &after_certificate,
            "--definition",
            "company-income",
            "--for",
            "FY2026-P03",
            "--compare",
            "FY2026-P02",
            "--certify",
        ],
    );
    let diff = event(&compared, "statement_diff");
    let net = array(diff, "lines")
        .iter()
        .find(|line| text(line, "code") == "net_income" && text(line, "unit") == "USD")
        .unwrap();
    assert_eq!(
        array(net, "delta"),
        &[Json::Str("5.00 USD".into()), Json::Str("0.00 USD".into())]
    );
    let saved = event(&compared, "report_certificate");
    let decoded = fa::StatementDiffCertificate::decode(&unhex(text(saved, "bytes"))).unwrap();
    assert!(decoded.is_custom());
    assert_eq!(decoded.sources().0.selection, decoded.sources().1.selection);
    assert_eq!(hex(&decoded.sources().0.digest), &certificate[2..]);
    assert_eq!(hex(&decoded.sources().1.digest), &after_certificate[2..]);
    let diff_reference = format!("C:{}", text(saved, "oid"));
    assert_eq!(
        event(
            &ok(&fixture.book, &["replay", &diff_reference]),
            "statement_diff"
        ),
        diff
    );
    let current_certificate = format!("C:{}", text(event(&current, "report_certificate"), "oid"));
    let (exit, events, _) = run(
        &fixture.book,
        &[
            "statement",
            "diff",
            "--before-certificate",
            &certificate,
            "--after-certificate",
            &current_certificate,
            "--certify",
        ],
    );
    assert_eq!(
        exit, 8,
        "a changed layout cannot be compared silently: {events:?}"
    );
    assert_eq!(events.len(), 1);
    let traced = ok(
        &fixture.book,
        &[
            "statement",
            "trace",
            "--from-diff",
            &diff_reference,
            "--certify",
        ],
    );
    let trace = event(&traced, "statement_trace");
    assert_eq!(trace.get("lines"), diff.get("lines"));
    assert_eq!(trace.get("after_known_at"), diff.get("after_known_at"));
    assert_eq!(trace.get("definition_version"), Some(&Json::Int(1)));
    let trace_source = event(&traced, "report_certificate");
    assert_eq!(
        text(trace_source, "output_format"),
        "fa:custom-statement-trace:v1"
    );
    let attributed =
        fa::StatementTraceCertificate::decode(&unhex(text(trace_source, "bytes"))).unwrap();
    assert!(attributed.is_custom());
    assert_eq!(attributed.sources().first().unwrap(), decoded.sources().0);
    assert_eq!(attributed.sources().last().unwrap(), decoded.sources().1);
    assert_eq!(
        attributed.sources().len() as u64,
        decoded.sources().1.known_at.0 - decoded.sources().0.known_at.0 + 1
    );
    let trace_reference = format!("C:{}", text(trace_source, "oid"));
    let replayed = ok(&fixture.book, &["replay", &trace_reference, "--workpaper"]);
    assert_eq!(event(&replayed, "statement_trace"), trace);
    assert!(
        text(event(&replayed, "workpaper_exported"), "text")
            .contains("\"format\":\"fa:custom-statement-trace-jsonl:v1\"")
    );

    // Direct selection resolves v1 at BEFORE, even though v2 is active now.
    // It asks the same complete question and keeps exact unrounded deltas.
    let before = decoded.sources().0.known_at.0.to_string();
    let after = decoded.sources().1.known_at.0.to_string();
    let direct_args = [
        "statement",
        "trace",
        "--definition",
        "company-income",
        "--for",
        "FY2026-P03",
        "--compare",
        "FY2026-P02",
        "--before",
        &before,
        "--after",
        &after,
        "--scale-digits",
        "3",
        "--rounding",
        "HalfEven",
        "--residual-line",
        "rounding",
        "--residual-label",
        "Presentation rounding",
    ];
    let direct = ok(&fixture.book, &direct_args);
    assert_eq!(event(&direct, "statement_trace"), trace);
    assert_eq!(direct[0].get("certificate"), Some(&Json::Null));
    for (mismatch, expected_exit) in [
        (vec!["--definition", "another-layout"], 8),
        (vec!["--for", "FY2026-P01"], 8),
        (vec!["--functional"], 8),
        (vec!["--max-publications", "1"], 3),
        (vec!["--rounding", "HalfEven"], 2),
        (vec!["--unit", "EUR"], 2),
        (vec!["--from", "2020-01-01", "--to", "2020-12-31"], 2),
        (vec!["--issuance", "3000"], 2),
        (vec!["--form", "041"], 2),
        (vec!["--dry-run"], 2),
    ] {
        let (exit, events, _) = run(
            &fixture.book,
            &[
                &[
                    "statement",
                    "trace",
                    "--from-diff",
                    &diff_reference,
                    "--certify",
                ][..],
                &mismatch,
            ]
            .concat(),
        );
        assert_eq!(exit, expected_exit, "{mismatch:?}: {events:?}");
        assert_eq!(events.len(), 1, "no partial trace or certificate");
        assert_eq!(text(&events[0], "event"), "error");
    }
    let fa::ReportSelection::CustomStatement(question) = decoded.report_selection().unwrap() else {
        panic!("custom question")
    };
    let before_activation = (question.activated_at.0 - 1).to_string();
    let (exit, events, _) = run(
        &fixture.book,
        &[
            "statement",
            "trace",
            "--definition",
            "company-income",
            "--for",
            "FY2026-P03",
            "--before",
            &before_activation,
            "--after",
            &after,
            "--certify",
        ],
    );
    assert_eq!(exit, 2, "the layout must exist at BEFORE: {events:?}");
    assert_eq!(events.len(), 1);
    let status = ok(&fixture.book, &["certificate", "status", &certificate]);
    assert_eq!(
        text(event(&status, "certificate_status"), "status"),
        "SupersededBy"
    );
    ok(&fixture.book, &["verify", "projections"]);
}

#[test]
fn company_activation_refuses_single_approval_and_an_unmapped_chart() {
    let fixture = Fixture::new();
    let source = layout(&fixture, 1);
    let (plan, a, b) = approved_review(&fixture, &source, "2026-01-01", "approval-check");
    let (exit, refused, _) = run(
        &fixture.book,
        &[
            "statement",
            "activate",
            "--plan",
            plan.to_str().unwrap(),
            "--approval",
            &a,
        ],
    );
    assert_eq!(exit, 7, "{refused:?}");
    let (exit, missing, _) = run(
        &fixture.book,
        &[
            "statement",
            "custom",
            "--definition",
            "company-income",
            "--for",
            "FY2026-P03",
        ],
    );
    assert_eq!(exit, 2, "{missing:?}");
    activate(&fixture, &plan, &a, &b);

    let mut bad =
        fa::CustomStatementDefinition::from_toml(&std::fs::read_to_string(&source).unwrap())
            .unwrap();
    let fa::CustomLineSource::AccountSet { expr, .. } = &mut bad.lines[0].source else {
        panic!("revenue mapping")
    };
    *expr = fa::AccountSetExpr::AccountCodes(vec!["4000".into()]);
    let unmapped = fixture.dir.join("unmapped-company.toml");
    std::fs::write(&unmapped, bad.to_toml().unwrap()).unwrap();
    let lint = ok(
        &fixture.book,
        &["statement", "lint", "--file", unmapped.to_str().unwrap()],
    );
    assert_eq!(
        event(&lint, "statement_lint").get("clean"),
        Some(&Json::Bool(false))
    );
    assert_eq!(
        array(event(&lint, "statement_lint"), "unmapped_leaves"),
        &[Json::Str("4100".into())]
    );
    let (exit, refused, _) = run(
        &fixture.book,
        &[
            "statement",
            "define",
            "--file",
            unmapped.to_str().unwrap(),
            "--from",
            "2026-02-01",
            "--key",
            "unmapped",
        ],
    );
    // FA-REF-100 STRUCTURE exits usage, as refusal_catalog.toml registers it
    // (d83f19076 aligned statement_definition's `invalid()` to it).
    assert_eq!(exit, 2, "{refused:?}");
}

#[test]
fn company_statement_template_and_explicit_rounding_options_are_reachable() {
    let fixture = Fixture::new();
    let result = ok(
        &fixture.book,
        &["statement", "template", "--definition", "balance-sheet"],
    );
    let source = text(event(&result, "statement_definition_template"), "source");
    assert!(fa::CustomStatementDefinition::from_toml(source).is_ok());
    let (exit, errors, _) = run(
        &fixture.book,
        &[
            "statement",
            "custom",
            "--definition",
            "company-income",
            "--for",
            "FY2026-P03",
            "--branch",
            "unsupported-branch",
        ],
    );
    assert_eq!(exit, 2, "{errors:?}");
    let (exit, errors, _) = run(
        &fixture.book,
        &[
            "statement",
            "balance-sheet",
            "--for",
            "FY2026-P03",
            "--scale-digits",
            "3",
        ],
    );
    assert_eq!(exit, 2, "{errors:?}");
}
