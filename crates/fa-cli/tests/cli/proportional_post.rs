//! End-to-end proportional hold posting through the public binary.
use super::*;

#[test]
fn post_reserve_proportion_derives_a_multi_unit_hold_and_commits_its_plan() -> std::io::Result<()> {
    let dir = tmp("proportional-reserve")?;
    let book = dir.join("book");
    let run = |step: &str, args: &[&str]| {
        let (code, out, err) = fa(Some(&book), args);
        let envelope = json::parse(out.lines().last().unwrap_or_default()).unwrap_or(Json::Null);
        let known_at = envelope.get("coordinate").and_then(|c| c.get("known_at"));
        eprintln!(
            "{step}: argv={args:?} exit={code} event={:?} refusal={:?} known_at={known_at:?}",
            field(&out, "event"),
            field(&out, "code"),
        );
        (code, out, err)
    };
    let ok = |step: &str, args: &[&str]| {
        let (code, out, err) = run(step, args);
        assert_eq!(code, 0, "{step}: argv={args:?}\nstdout={out}\nstderr={err}");
        out
    };
    ok(
        "book",
        &["book", "create", "--name", "Proportional Co", "--json"],
    );
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"2000","name":"Payables","type":"Liability","unit":"USD"},{"code":"2200","name":"Euro payables","type":"Liability","unit":"EUR"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"},{"code":"6010","name":"Services","type":"Expense","unit":"USD"},{"code":"6200","name":"Euro expense","type":"Expense","unit":"EUR"}]}"#,
    );
    ok("chart", &["chart", "import", &chart, "--json"]);
    ok(
        "calendar",
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    ok("period", &["period", "open", "FY2026-P03", "--json"]);
    let evidence = source_doc(&dir, &book);
    let legs = r#"[{"side":"debit","account":"6000","amount":"60.01 USD"},{"side":"debit","account":"6010","amount":"39.99 USD"},{"side":"credit","account":"2000","amount":"100.00 USD"},{"side":"debit","account":"6200","amount":"3.01 EUR"},{"side":"credit","account":"2200","amount":"3.01 EUR"}]"#;
    let reserve = |key: &str| {
        let intent = write(
            &dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"2026-03-10","idempotency_key":"{key}","legs":{legs}}}"#
            ),
        );
        let out = ok(
            "reserve",
            &[
                "reserve",
                "--intent",
                &intent,
                "--evidence",
                &evidence,
                "--json",
            ],
        );
        field(&out, "vid").expect("held entry").to_string()
    };
    let frontier = || {
        let out = ok("frontier", &["book", "info", "--json"]);
        let envelope = json::parse(out.trim()).expect("book info envelope");
        envelope
            .get("coordinate")
            .and_then(|c| c.get("known_at"))
            .cloned()
            .expect("a real journal frontier, not an absent data field")
    };
    let hold = reserve("proportion-hold");
    let before = frontier();
    let plan_path = dir.join("proportional.plan").display().to_string();
    let plan_out = ok(
        "rehearse proportion",
        &[
            "post-reserve",
            &hold,
            "--date",
            "2026-03-20",
            "--proportion",
            "0.37",
            "--law",
            "BalancedLargestRemainder",
            "--dry-run",
            "--plan-out",
            &plan_path,
            "--json",
        ],
    );
    assert_eq!(field(&plan_out, "event"), Some("plan"), "{plan_out}");
    assert_eq!(
        frontier(),
        before,
        "a proportional rehearsal writes nothing"
    );
    let plan = doc(&plan_out);
    let basis = plan
        .get("proportional_post")
        .expect("the reviewed proportional law");
    assert_eq!(text(basis, "law"), "BalancedLargestRemainder");
    assert_eq!(int(basis, "version"), Some(1));
    assert_eq!(text(basis, "rate_numerator"), "37");
    assert_eq!(text(basis, "rate_denominator"), "100");
    assert_eq!(
        arr(basis, "source_ordinals"),
        &[
            Json::Int(0),
            Json::Int(1),
            Json::Int(2),
            Json::Int(3),
            Json::Int(4)
        ],
    );
    let actual: std::collections::BTreeMap<_, _> = arr(&plan, "legs")
        .iter()
        .map(|leg| (text(leg, "account"), text(leg, "amount")))
        .collect();
    assert_eq!(
        actual,
        [
            ("6000", "22.20 USD"),
            ("6010", "14.80 USD"),
            ("2000", "37.00 USD"),
            ("6200", "1.11 EUR"),
            ("2200", "1.11 EUR"),
        ]
        .into_iter()
        .collect(),
        "one rounded target per unit; every side receives exactly that target",
    );

    let committed = ok(
        "commit retained plan",
        &["commit", "--plan", &plan_path, "--json"],
    );
    assert_eq!(
        field(&committed, "event"),
        Some("plan_committed"),
        "{committed}"
    );
    let posted_head = frontier();
    let again = ok(
        "exact retry",
        &[
            "post-reserve",
            &hold,
            "--date",
            "2026-03-20",
            "--proportion",
            "0.37",
            "--law",
            "BalancedLargestRemainder",
            "--json",
        ],
    );
    assert_eq!(field(&again, "event"), Some("recorded"), "{again}");
    assert_eq!(frontier(), posted_head, "the same intent cannot post twice");
    let equivalent = ok(
        "equivalent exact ratio retry",
        &[
            "post-reserve",
            &hold,
            "--date",
            "2026-03-20",
            "--proportion",
            "37/100",
            "--law",
            "BalancedLargestRemainder",
            "--json",
        ],
    );
    assert_eq!(
        field(&equivalent, "event"),
        Some("recorded"),
        "{equivalent}"
    );
    assert_eq!(
        frontier(),
        posted_head,
        "equivalent rates keep one resolution"
    );

    let tb = doc(&ok(
        "posted and released",
        &["tb", "--period", "FY2026-P03", "--json"],
    ));
    for (account, measure, amount) in [
        ("6000", "debits", "22.20 USD"),
        ("6010", "debits", "14.80 USD"),
        ("2000", "credits", "37.00 USD"),
        ("6200", "debits", "1.11 EUR"),
        ("2200", "credits", "1.11 EUR"),
    ] {
        let row = arr(&tb, "rows")
            .iter()
            .find(|row| text(row, "code") == account)
            .expect("account row");
        assert_eq!(text(row, measure), amount, "{account}: {tb:?}");
        let zero = if amount.ends_with("EUR") {
            "0.00 EUR"
        } else {
            "0.00 USD"
        };
        assert_eq!(
            text(row, "debits_pending"),
            zero,
            "{account}: full hold release"
        );
        assert_eq!(
            text(row, "credits_pending"),
            zero,
            "{account}: full hold release"
        );
    }

    let negative_hold = reserve("proportion-refusals");
    let negative_head = frontier();
    for (step, extra) in [
        ("missing law", vec!["--proportion", "0.37"]),
        (
            "mixed selectors",
            vec![
                "--amount",
                "37.00 USD",
                "--proportion",
                "0.37",
                "--law",
                "BalancedLargestRemainder",
            ],
        ),
        (
            "above one",
            vec!["--proportion", "1.01", "--law", "BalancedLargestRemainder"],
        ),
        (
            "empty result",
            vec!["--proportion", "0", "--law", "BalancedLargestRemainder"],
        ),
        (
            "unknown law",
            vec!["--proportion", "0.37", "--law", "UnknownLaw"],
        ),
    ] {
        let mut args = vec![
            "post-reserve",
            negative_hold.as_str(),
            "--date",
            "2026-03-21",
        ];
        args.extend(extra);
        args.push("--json");
        let (code, out, err) = run(step, &args);
        assert!(matches!(code, 2 | 3), "{step}: argv={args:?}\n{out}\n{err}");
        assert_eq!(field(&out, "event"), Some("error"), "{step}: {out}");
        if step == "empty result" {
            assert!(
                out.contains("VoidReserve") || out.contains("void-reserve"),
                "{out}"
            );
        }
        assert_eq!(
            frontier(),
            negative_head,
            "{step}: refused requests append nothing"
        );
    }

    let conflicting = write(
        &dir,
        "conflicting-selection.json",
        &format!(
            r#"{{"effective_date":"2026-03-21","idempotency_key":"mixed-intent","resolves":"{negative_hold}","disposition":"posts","legs":{legs},"proportion":{{"law":"BalancedLargestRemainder","rate":"0.37"}}}}"#
        ),
    );
    let (code, out, err) = run(
        "generic mixed selectors",
        &["resolve", "--intent", &conflicting, "--json"],
    );
    assert_eq!(code, 2, "{out}\n{err}");
    assert_eq!(
        frontier(),
        negative_head,
        "generic intents cannot hide a second selector"
    );

    let (code, out, err) = run(
        "already resolved",
        &[
            "post-reserve",
            &hold,
            "--date",
            "2026-03-20",
            "--proportion",
            "0.5",
            "--law",
            "BalancedLargestRemainder",
            "--key",
            "different-resolution",
            "--json",
        ],
    );
    assert_ne!(code, 0, "{out}\n{err}");
    assert_eq!(
        frontier(),
        negative_head,
        "an original hold resolves only once"
    );
    Ok(())
}
