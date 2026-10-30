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

    fixture.post(
        "later-custom-sale",
        "2026-03-12",
        "1000",
        "4000",
        "5.00 USD",
    );
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
