//! Approved layouts over retained functional amounts through separate CLI processes.

use super::*;

fn event<'a>(events: &'a [Json], name: &str) -> &'a Json {
    data(
        events
            .iter()
            .find(|value| text(value, "event") == name)
            .unwrap_or_else(|| panic!("missing {name}: {events:?}")),
    )
}

fn activate_layout(fixture: &Fixture, builtin: &str, name: &str, version: u32, from: &str) {
    let mut definition = fa::CustomStatementDefinition::from_builtin(
        &fa::StatementDefinition::embedded(builtin).unwrap(),
    );
    definition.name = name.into();
    definition.version = version;
    definition.title = format!("Company {name} v{version}");
    let source = fixture.file(
        &format!("{name}-{version}.toml"),
        &definition.to_toml().unwrap(),
    );
    let plan = fixture.dir.join(format!("{name}-{version}.plan"));
    let key = format!("{name}-{version}");
    let review = ok(
        &fixture.book,
        &[
            "statement",
            "define",
            "--file",
            &source,
            "--from",
            from,
            "--key",
            &key,
            "--plan-out",
            plan.to_str().unwrap(),
        ],
    );
    let digest = text(data(&review), "proposal_digest");
    let a = ok(
        &fixture.book,
        &["approve", "--proposal", digest, "--as", "layout-reviewer-a"],
    );
    let b = ok(
        &fixture.book,
        &["approve", "--proposal", digest, "--as", "layout-reviewer-b"],
    );
    ok(
        &fixture.book,
        &[
            "statement",
            "activate",
            "--plan",
            plan.to_str().unwrap(),
            "--approval",
            text(data(&a), "approval_vid"),
            "--approval",
            text(data(&b), "approval_vid"),
        ],
    );
}

fn native_sale(fixture: &Fixture, key: &str, date: &str, amount: &str) {
    let source = fixture.file(&format!("{key}.json"), &format!(
        r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":[{{"side":"debit","account":"1000","amount":"{amount} USD"}},{{"side":"credit","account":"4500","amount":"{amount} USD"}}]}}"#
    ));
    ok(
        &fixture.book,
        &["post", "--intent", &source, "--evidence", &fixture.evidence],
    );
}

#[test]
fn functional_company_statements_keep_carrying_values_rounding_and_cold_replay() {
    let seed = 0xb7;
    let fixture = Fixture::create(Some(seed));
    let chart = fixture.file("additional-accounts.json", r#"{"accounts":[{"code":"1000","name":"Dollar cash","type":"Asset","unit":"USD"},{"code":"4500","name":"Dollar sales","type":"Revenue","unit":"USD"},{"code":"5000","name":"Euro cost","type":"Expense","unit":"EUR"}]}"#);
    ok(&fixture.book, &["chart", "import", &chart]);
    fixture.post("company-january", "2026-01-05", "100.00", 11);
    fixture.post("company-february", "2026-02-05", "200.00", 12);
    native_sale(&fixture, "dollar-january", "2026-01-06", "7.00");
    native_sale(&fixture, "dollar-february", "2026-02-06", "3.00");
    // EUR0.42 at USD1.2/EUR retains USD0.50. Rounded whole-dollar
    // operands give243-0, while exact net242.50 rounds to242: residual-1.
    let rate = fixture.rate("cost", "2026-02-07", 12);
    let cost = fixture.file("company-cost.json", &format!(r#"{{"effective_date":"2026-02-07","idempotency_key":"company-cost","legs":[{{"side":"debit","account":"5000","amount":"0.42 EUR"}},{{"side":"credit","account":"1200","amount":"0.42 EUR"}}],"fx":{{"law":"SpotClose","rates":["D:{rate}"]}}}}"#));
    ok(
        &fixture.book,
        &["post", "--intent", &cost, "--evidence", &fixture.evidence],
    );
    activate_layout(
        &fixture,
        "balance-sheet",
        "company-balance",
        1,
        "2026-01-01",
    );
    activate_layout(
        &fixture,
        "income-statement",
        "company-income",
        1,
        "2026-01-01",
    );
    fixture.compact(seed);
    let before = head(&fixture.book);

    let balance = ok_many(
        &fixture.book,
        &[
            "statement",
            "custom",
            "--definition",
            "company-balance",
            "--functional",
            "--for",
            "FY2026-P02",
            "--compare",
            "FY2026-P01",
        ],
    );
    let exact = event(&balance, "statement");
    assert_eq!(text(exact, "scope"), "single-book-functional-currency");
    assert_eq!(text(exact, "base_unit"), "USD");
    assert_eq!(
        statement_amounts(exact, "assets", "USD"),
        &[
            Json::Str("359.50 USD".into()),
            Json::Str("117.00 USD".into())
        ]
    );
    assert_eq!(
        statement_amounts(exact, "balance_check", "USD"),
        &[Json::Str("0.00 USD".into()), Json::Str("0.00 USD".into())]
    );
    let native = ok_many(
        &fixture.book,
        &[
            "statement",
            "custom",
            "--definition",
            "company-balance",
            "--for",
            "FY2026-P02",
            "--compare",
            "FY2026-P01",
        ],
    );
    assert_eq!(
        statement_amounts(event(&native, "statement"), "assets", "EUR"),
        &[
            Json::Str("299.58 EUR".into()),
            Json::Str("100.00 EUR".into())
        ]
    );
    assert_eq!(
        statement_amounts(event(&native, "statement"), "assets", "USD"),
        &[Json::Str("10.00 USD".into()), Json::Str("7.00 USD".into())]
    );
    assert_eq!(
        head(&fixture.book),
        before,
        "reads never post a new valuation"
    );

    let path = fixture.dir.join("functional-company.cert");
    let original = ok_many(
        &fixture.book,
        &[
            "statement",
            "custom",
            "--definition",
            "company-income",
            "--functional",
            "--for",
            "FY2026-P02",
            "--compare",
            "FY2026-P01",
            "--certificate-out",
            path.to_str().unwrap(),
            "--scale-digits",
            "2",
            "--rounding",
            "HalfEven",
            "--residual-line",
            "rounding",
            "--residual-label",
            "Presentation rounding",
        ],
    );
    let exact = event(&original, "statement");
    assert_eq!(
        statement_amounts(exact, "net_income", "USD"),
        &[
            Json::Str("242.50 USD".into()),
            Json::Str("117.00 USD".into())
        ]
    );
    let presented = event(&original, "functional_custom_statement");
    assert_eq!(presented.get("functional"), Some(&Json::Bool(true)));
    assert_eq!(text(presented, "base_unit"), "USD");
    assert_eq!(text(presented, "valuation_basis"), "retained-base-amounts");
    assert_eq!(integer(presented, "divisor"), 100);
    let residual = rows(presented, "lines")
        .iter()
        .find(|line| text(line, "code") == "net_income_rounding")
        .expect("explicit functional rounding residual");
    assert_eq!(residual.get("residual"), Some(&Json::Bool(true)));
    assert_eq!(rows(residual, "amounts"), &[Json::Int(-1), Json::Int(0)]);
    let bytes = std::fs::read(&path).unwrap();
    assert!(bytes.starts_with(b"fa:report-certificate:v12"));
    let decoded = fa::ReportCertificate::decode(&bytes).unwrap();
    assert_eq!(decoded.output_format(), "fa:functional-custom-statement:v1");
    assert_eq!(decoded.inputs.len(), 13);
    let fa::ReportSelection::CustomStatement(selected) = &decoded.selection else {
        panic!("custom selector")
    };
    assert!(selected.functional);
    let reference = format!("C:{}", text(event(&original, "report_certificate"), "oid"));
    assert_eq!(
        text(
            data(&ok(&fixture.book, &["certificate", "status", &reference])),
            "status"
        ),
        "Current"
    );

    fixture.post("company-backdate", "2026-01-20", "10.00", 13);
    activate_layout(
        &fixture,
        "income-statement",
        "company-income",
        2,
        "2026-02-01",
    );
    let replay = ok_many(&fixture.book, &["replay", &reference]);
    assert_eq!(event(&replay, "statement"), exact);
    assert_eq!(event(&replay, "functional_custom_statement"), presented);
    assert_eq!(
        text(
            data(&ok(&fixture.book, &["certificate", "status", &reference])),
            "status"
        ),
        "SupersededBy"
    );
    let historical = ok_many(
        &fixture.book,
        &[
            "statement",
            "custom",
            "--definition",
            "company-income",
            "--functional",
            "--for",
            "FY2026-P02",
            "--compare",
            "FY2026-P01",
            "--as-known-at",
            &decoded.known_at.0.to_string(),
        ],
    );
    assert_eq!(event(&historical, "statement"), exact);
    let current = ok_many(
        &fixture.book,
        &[
            "statement",
            "custom",
            "--definition",
            "company-income",
            "--functional",
            "--for",
            "FY2026-P02",
            "--compare",
            "FY2026-P01",
        ],
    );
    assert_eq!(
        integer(event(&current, "functional_custom_statement"), "version"),
        2
    );
    assert_eq!(
        statement_amounts(event(&current, "statement"), "net_income", "USD"),
        &[
            Json::Str("242.50 USD".into()),
            Json::Str("130.00 USD".into())
        ]
    );
}

#[test]
fn functional_company_statement_refuses_unvalued_sources_before_certificate_retention() {
    let fixture = Fixture::new();
    let source = fixture.file("unvalued-company.json", r#"{"effective_date":"2026-02-05","idempotency_key":"unvalued-company","legs":[{"side":"debit","account":"1200","amount":"10.00 EUR"},{"side":"credit","account":"4000","amount":"10.00 EUR"}]}"#);
    ok(
        &fixture.book,
        &["post", "--intent", &source, "--evidence", &fixture.evidence],
    );
    activate_layout(
        &fixture,
        "income-statement",
        "company-income",
        1,
        "2026-01-01",
    );
    let before = head(&fixture.book);
    let output = fixture.dir.join("unvalued-company.cert");
    for certify in [false, true] {
        let mut args = vec![
            "statement",
            "custom",
            "--definition",
            "company-income",
            "--functional",
            "--for",
            "FY2026-P02",
        ];
        if certify {
            args.extend(["--certificate-out", output.to_str().unwrap()]);
        }
        let (status, refused) = run(&fixture.book, &args);
        assert_ne!(status, 0, "{}", refused.render());
        assert_ne!(text(&refused, "event"), "statement");
        assert!(
            !output.exists(),
            "a refused report must not publish a certificate file"
        );
        assert_eq!(head(&fixture.book), before);
    }
    let native = ok_many(
        &fixture.book,
        &[
            "statement",
            "custom",
            "--definition",
            "company-income",
            "--for",
            "FY2026-P02",
        ],
    );
    assert_eq!(
        statement_amounts(event(&native, "statement"), "net_income", "EUR"),
        &[Json::Str("10.00 EUR".into())]
    );
}
