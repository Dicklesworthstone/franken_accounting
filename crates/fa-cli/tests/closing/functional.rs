//! Retained carrying values survive closing, approvals and cold process opens.

use super::*;

const DEVELOPMENT_SEED: u8 = 0xea;

fn fixture(equity_unit: &str) -> Fixture {
    Fixture::with_chart_and_keys(
        true,
        &format!(
            r#"{{"accounts":[
                {{"code":"1000","name":"Cash","type":"Asset","unit":"any-currency"}},
                {{"code":"3000","name":"Retained earnings","type":"Equity","unit":"{equity_unit}"}},
                {{"code":"4000","name":"Revenue","type":"Revenue","unit":"any-currency"}},
                {{"code":"6000","name":"Expense","type":"Expense","unit":"any-currency"}}
            ]}}"#
        ),
        Some(DEVELOPMENT_SEED),
    )
}

fn compact(f: &Fixture) {
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fgdb::{Database, DatabaseKeys, ReadError};
    use fgdb_types::CommitSeq;
    use fgdb_types::context::PurposeContexts;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    let keys = || {
        DatabaseKeys::new(
            [DEVELOPMENT_SEED; 32],
            DatabaseSecurityNamespaceId([DEVELOPMENT_SEED.wrapping_add(1); 32]),
            [DEVELOPMENT_SEED.wrapping_add(2); 32],
        )
    };
    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let mut db = runtime
        .block_on(Database::open(&cx.commit(), &f.book.join("store"), keys()))
        .unwrap();
    let before = db.frontier().unwrap();
    runtime.block_on(db.compact(&cx.commit())).unwrap();
    assert_eq!(db.frontier().unwrap(), before);
    drop(db);
    let cold = runtime
        .block_on(Database::open(&cx.commit(), &f.book.join("store"), keys()))
        .unwrap();
    assert!(matches!(
        cold.delta_since(CommitSeq(0)),
        Err(ReadError::DeltaCursorRetired { .. })
    ));
    assert_eq!(cold.frontier().unwrap(), before);
}

fn post_foreign(
    f: &Fixture,
    key: &str,
    debit: &str,
    credit: &str,
    amount: &str,
    rate: Option<(u32, u32)>,
) -> Json {
    let valuation = rate.map_or_else(String::new, |(numerator, denominator)| {
        let path = write(
            &f.dir,
            &format!("{key}-rate.json"),
            &format!(r#"{{"base_unit":"USD","quote_unit":"EUR","rate_num":"{numerator}","rate_den":"{denominator}","rounding":"HalfEven","as_of":"2026-12-30","retrieved_at_ns":1767571200000000000,"purpose":"spot_close","source":"{key}"}}"#),
        );
        let retained = ok(&f.book, &["fx", "rate", "add", "--from-json", &path]);
        format!(r#", "fx":{{"law":"SpotClose","rates":["D:{}"]}}"#, text(&retained, "oid"))
    });
    let path = write(
        &f.dir,
        &format!("{key}.json"),
        &format!(
            r#"{{"effective_date":"2026-12-30","idempotency_key":"{key}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount} EUR"}},{{"side":"credit","account":"{credit}","amount":"{amount} EUR"}}]{valuation}}}"#
        ),
    );
    ok(
        &f.book,
        &["post", "--intent", &path, "--evidence", &f.evidence],
    )
}

fn statement(f: &Fixture, definition: &str) -> Json {
    ok(
        &f.book,
        &[
            "statement",
            definition,
            "--functional",
            "--for",
            "FY2026-P12",
        ],
    )
}

fn line(report: &Json, code: &str) -> String {
    let row = get(report, "lines")
        .as_arr()
        .unwrap()
        .iter()
        .find(|row| text(row, "code") == code && text(row, "unit") == "USD")
        .unwrap_or_else(|| panic!("missing {code}: {}", report.render()));
    get(row, "amounts").as_arr().unwrap()[0]
        .as_str()
        .unwrap()
        .to_string()
}

fn residual<'a>(review: &'a Json, account: &str, native: &str) -> &'a Json {
    get(review, "residuals")
        .as_arr()
        .unwrap()
        .iter()
        .find(|row| text(row, "account") == account && text(row, "net") == native)
        .unwrap_or_else(|| panic!("missing {account}/{native}: {}", review.render()))
}

fn restored_plan(
    f: &Fixture,
    path: &str,
    review: &Json,
    approval: Option<&str>,
    name: &str,
) -> (String, Json) {
    let plan_path = f.dir.join(name).display().to_string();
    let mut args = vec![
        "close",
        "year-end",
        "--review",
        path,
        "--digest",
        text(review, "review_digest"),
        "--dry-run",
        "--plan-out",
        &plan_path,
    ];
    if let Some(approval) = approval {
        args.extend(["--approval", approval]);
    }
    let plan = ok(&f.book, &args);
    (plan_path, plan)
}

#[test]
fn foreign_close_preserves_functional_income_and_reviewed_delta_across_approval() {
    let f = fixture("any-currency");
    post_foreign(&f, "foreign-sale", "1000", "4000", "100.00", Some((11, 10)));
    post_foreign(&f, "foreign-expense", "6000", "1000", "40.00", Some((5, 4)));
    f.post("native-expense", "6000", "1000", "10.00");
    assert_eq!(
        line(&statement(&f, "income-statement"), "net_income"),
        "50.00 USD"
    );

    let before = head(&f.book);
    let (review_path, review) = f.review("foreign-first-close");
    assert_eq!(head(&f.book), before, "review must not publish a valuation");
    assert_eq!(text(&review, "base_unit"), "USD");
    assert_eq!(
        text(&review, "valuation_basis"),
        "retained-carrying-amounts"
    );
    assert_eq!(
        text(residual(&review, "4000", "-100.00 EUR"), "base_net"),
        "-110.00 USD"
    );
    assert_eq!(
        text(residual(&review, "6000", "40.00 EUR"), "base_net"),
        "50.00 USD"
    );
    assert_eq!(
        text(residual(&review, "6000", "10.00 USD"), "base_net"),
        "10.00 USD"
    );
    assert!(
        get(&review, "legs")
            .as_arr()
            .unwrap()
            .iter()
            .all(|leg| get(leg, "base_amount").as_str().is_some())
    );

    let intent = fa::PostIntent::decode(&std::fs::read(&review_path).unwrap()).unwrap();
    let totals = intent.proposal().base_totals.as_ref().unwrap();
    assert_eq!(totals.fx_law_oid, fa::FxLawId::YearEndCloseCarrying.oid());
    assert_eq!((totals.debits, totals.credits), (17_000, 17_000));
    assert!(
        totals.rate_doc_oids.is_empty(),
        "closing chooses no new exchange rate"
    );
    compact(&f);
    let (plan_path, plan) = restored_plan(&f, &review_path, &review, None, "foreign-first.plan");
    let valuation = get(&plan, "valuation");
    assert_eq!(text(valuation, "law"), "YearEndCloseCarrying");
    assert_eq!(text(valuation, "debits"), "170.00 USD");
    assert_eq!(
        get(valuation, "legs").as_arr().unwrap().len(),
        intent.proposal().legs.len()
    );
    let decoded_plan = fa::PostPlan::decode(&std::fs::read(&plan_path).unwrap()).unwrap();
    assert_eq!(decoded_plan.proposal(), intent.proposal());
    f.commit(&plan_path);
    let first_close = head(&f.book);
    compact(&f);
    ok(&f.book, &["verify", "fx-conversion"]);
    let verified = ok(&f.book, &["verify", "close", "FY2026"]);
    assert_eq!(get(&verified, "needs_reclose"), &Json::Bool(false));
    assert_eq!(text(&verified, "base_unit"), "USD");
    assert_eq!(
        line(&statement(&f, "income-statement"), "net_income"),
        "50.00 USD"
    );
    let balance = statement(&f, "balance-sheet");
    assert_eq!(line(&balance, "equity"), "50.00 USD");
    assert_eq!(line(&balance, "unclosed_earnings"), "0.00 USD");
    assert_eq!(line(&balance, "balance_check"), "0.00 USD");

    // A later retained valuation adds only its own carrying amount to the reclose.
    post_foreign(
        &f,
        "foreign-late-sale",
        "1000",
        "4000",
        "10.00",
        Some((13, 10)),
    );
    assert_eq!(run(&f.book, &["verify", "close", "FY2026"]).0, 8);
    ok(
        &f.book,
        &[
            "verify",
            "close",
            "FY2026",
            "--as-known-at",
            &first_close.to_string(),
        ],
    );
    ok(&f.book, &["period", "soft-close", "FY2026-CLOSE"]);
    ok(
        &f.book,
        &[
            "period",
            "close",
            "FY2026-CLOSE",
            "--reason",
            "Scheduled",
            "--yes",
        ],
    );
    let (delta_path, delta) = f.review("foreign-delta-close");
    assert_eq!(
        text(residual(&delta, "4000", "-10.00 EUR"), "base_net"),
        "-13.00 USD"
    );
    assert_eq!(get(&delta, "legs").as_arr().unwrap().len(), 2);
    let before_denial = head(&f.book);
    assert_ne!(
        run(
            &f.book,
            &[
                "close",
                "year-end",
                "--review",
                &delta_path,
                "--digest",
                text(&delta, "review_digest"),
                "--dry-run"
            ]
        )
        .0,
        0
    );
    assert_eq!(head(&f.book), before_denial);
    let approval = ok(
        &f.book,
        &[
            "approve",
            "--proposal",
            text(&delta, "proposal_digest"),
            "--as",
            "reviewer",
        ],
    );
    compact(&f);
    let (delta_plan, plan) = restored_plan(
        &f,
        &delta_path,
        &delta,
        Some(text(&approval, "approval_vid")),
        "foreign-delta.plan",
    );
    assert_eq!(text(get(&plan, "valuation"), "debits"), "13.00 USD");
    f.commit(&delta_plan);
    ok(&f.book, &["verify", "close", "FY2026"]);
    ok(&f.book, &["verify", "fx-conversion"]);
    assert_eq!(line(&statement(&f, "balance-sheet"), "equity"), "63.00 USD");
    assert_eq!(
        line(&statement(&f, "income-statement"), "net_income"),
        "63.00 USD"
    );
    let before_noop = head(&f.book);
    assert_eq!(text(&f.close_now("foreign-noop"), "event"), "closing_noop");
    assert_eq!(head(&f.book), before_noop);
}

#[test]
fn zero_native_residual_closes_functional_value_and_recloses_source_reversals() {
    let f = fixture("any-currency");
    post_foreign(
        &f,
        "same-native-credit",
        "1000",
        "4000",
        "100.00",
        Some((11, 10)),
    );
    let source = post_foreign(
        &f,
        "same-native-debit",
        "4000",
        "1000",
        "100.00",
        Some((6, 5)),
    );
    let (_, review) = f.review("native-zero-review");
    assert_eq!(
        text(residual(&review, "4000", "0.00 EUR"), "base_net"),
        "10.00 USD"
    );
    assert_eq!(get(&review, "legs").as_arr().unwrap().len(), 4);
    assert_eq!(
        line(&statement(&f, "income-statement"), "net_income"),
        "-10.00 USD"
    );
    let closed = f.close_now("native-zero-close");
    assert_eq!(text(&closed, "class"), "Closing");
    ok(&f.book, &["verify", "close", "FY2026"]);
    let mut target = text(&source, "vid").to_string();
    for (key, equity_before, unclosed, expected_income, native_delta, base_delta) in [
        (
            "undo-valued-source",
            "-10.00 USD",
            "120.00 USD",
            "110.00 USD",
            "-100.00 EUR",
            "-120.00 USD",
        ),
        (
            "redo-valued-source",
            "110.00 USD",
            "-120.00 USD",
            "-10.00 USD",
            "100.00 EUR",
            "120.00 USD",
        ),
    ] {
        let reversed = ok(
            &f.book,
            &["reverse", &target, "--reason", "WrongAmount", "--key", key],
        );
        target = text(&reversed, "vid").to_string();
        ok(&f.book, &["verify", "fx-conversion"]);
        assert_eq!(run(&f.book, &["verify", "close", "FY2026"]).0, 8);
        assert_eq!(
            line(&statement(&f, "income-statement"), "net_income"),
            expected_income
        );
        let balance = statement(&f, "balance-sheet");
        assert_eq!(line(&balance, "equity"), equity_before);
        assert_eq!(line(&balance, "unclosed_earnings"), unclosed);
        assert_eq!(line(&balance, "balance_check"), "0.00 USD");
        let (_, delta) = f.review(&format!("{key}-review"));
        assert_eq!(
            text(residual(&delta, "4000", native_delta), "base_net"),
            base_delta
        );
        assert_eq!(get(&delta, "legs").as_arr().unwrap().len(), 2);
        f.close_now(&format!("{key}-reclose"));
        ok(&f.book, &["verify", "close", "FY2026"]);
        ok(&f.book, &["verify", "fx-conversion"]);
        assert_eq!(
            line(&statement(&f, "income-statement"), "net_income"),
            expected_income
        );
        let closed_balance = statement(&f, "balance-sheet");
        assert_eq!(line(&closed_balance, "equity"), expected_income);
        assert_eq!(line(&closed_balance, "unclosed_earnings"), "0.00 USD");
        assert_eq!(line(&closed_balance, "balance_check"), "0.00 USD");
    }
    assert_eq!(
        text(&f.close_now("native-zero-noop"), "event"),
        "closing_noop"
    );
}

#[test]
fn foreign_close_refuses_missing_valuation_and_incompatible_equity_units_without_writes() {
    for (equity_unit, rate) in [("any-currency", None), ("USD", Some((11, 10)))] {
        let f = fixture(equity_unit);
        post_foreign(
            &f,
            "unsupported-foreign-close",
            "1000",
            "4000",
            "100.00",
            rate,
        );
        let before = head(&f.book);
        let (exit, _) = run(
            &f.book,
            &[
                "close",
                "year-end",
                "--fiscal-year",
                "2026",
                "--period",
                "FY2026-CLOSE",
                "--key",
                "must-refuse",
                "--review-only",
            ],
        );
        assert_ne!(exit, 0);
        assert_eq!(head(&f.book), before);
    }
}
