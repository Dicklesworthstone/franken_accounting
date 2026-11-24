//! A real scenario question, signed export and independent CLI replay.

use super::*;

#[test]
fn scenario_question_and_signed_math_bundle_travel_without_the_source_book() -> std::io::Result<()>
{
    let dir = tmp("portable-scenario-math")?;
    let book = dir.join("book");
    let run = |args: &[&str]| {
        let mut full = args.to_vec();
        full.push("--json");
        let (code, out, err) = fa(Some(&book), &full);
        assert_eq!(code, 0, "{args:?}\n{out}\n{err}");
        out
    };
    run(&["book", "create", "--name", "Scenario math export"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    );
    run(&["chart", "import", &chart]);
    run(&["period", "create", "--fiscal-year", "2026"]);
    run(&["period", "open", "FY2026-P03"]);
    let evidence = source_doc(&dir, &book);
    let intent = |name: &str, key: &str, date: &str, amount: &str| {
        write(
            &dir,
            name,
            &format!(
                r#"{{"effective_date":"{date}","idempotency_key":"{key}","evidence":["{evidence}"],"legs":[{{"side":"debit","account":"1000","amount":"{amount} USD"}},{{"side":"credit","account":"4000","amount":"{amount} USD"}}]}}"#,
            ),
        )
    };
    let trunk = intent("source.json", "source", "2026-03-02", "100.00");
    run(&["post", "--intent", &trunk]);
    run(&[
        "scenario",
        "fork",
        "but-for",
        "--from",
        "2026-03-10",
        "--evidence",
        &evidence,
    ]);
    let assumed = intent("assumed.json", "assumed", "2026-03-15", "500.00");
    run(&["scenario", "run", "but-for", "--intent", &assumed]);
    let certificate_file = dir.join("scenario.cert").display().to_string();
    let question_file = dir.join("scenario.question").display().to_string();
    let certified = run(&[
        "scenario",
        "diff",
        "but-for",
        "--period",
        "FY2026-P03",
        "--certificate-out",
        &certificate_file,
        "--request-out",
        &question_file,
    ]);
    assert_eq!(certified.lines().count(), 2);
    let artifact = doc(&certified);
    let expected_digest = text(&artifact, "oid").to_string();
    let question_bytes = std::fs::read(&question_file)?;
    let expected =
        fa_verify::scenario_report::ScenarioExpectation::decode(&question_bytes).unwrap();
    assert_eq!(expected.name, "but-for");
    assert_eq!(expected.periods, ["FY2026-P03"]);
    assert_eq!(expected.method, "native-original-additive:v1");
    assert_eq!(expected.intents, 1);
    assert_eq!(expected.assumptions.len(), 1);
    assert_eq!(expected.encode().unwrap(), question_bytes);

    // The old certificate pins one Plan even when a later Plan and later
    // trunk posting are visible to the newer signed checkpoint.
    let later = intent("later.json", "later", "2026-03-18", "7.00");
    run(&["scenario", "run", "but-for", "--intent", &later]);
    let actual = intent("actual.json", "actual", "2026-03-19", "11.00");
    run(&["post", "--intent", &actual]);
    let checkpoint = doc(&run(&["checkpoint", "create", "--grant", "witness"]));
    let bundle_file = dir.join("scenario.fab").display().to_string();
    let receipt_file = dir.join("scenario.receipt").display().to_string();
    let produced = doc(&run(&[
        "bundle",
        "produce",
        "--certificate",
        &certificate_file,
        "--state",
        text(&checkpoint, "oid"),
        "--out",
        &bundle_file,
        "--receipt-out",
        &receipt_file,
    ]));
    assert_eq!(
        text(&produced, "scope"),
        "conditional_additive_scenario_math"
    );
    assert_eq!(produced.get("inline_documents"), Some(&Json::Bool(true)));
    assert!(text(&produced, "verify").contains("fa-verify scenario "));
    assert!(text(&produced, "verify").contains("--scenario-request"));
    let bundle = std::fs::read(&bundle_file)?;
    let receipt = std::fs::read(&receipt_file)?;
    let argv = [
        "scenario",
        "delivered.fab",
        "--key",
        text(&produced, "checkpoint_public_key"),
        "--receipt",
        "delivered.receipt",
        "--expect",
        &expected_digest,
        "--scenario-request",
        "original.question",
        "--json",
    ]
    .map(str::to_string);
    // This reader exposes only the delivered files and the independently
    // retained question. No pathname or API can reach the producer book.
    let read = |name: &str| match name {
        "delivered.fab" => Ok(bundle.clone()),
        "delivered.receipt" => Ok(receipt.clone()),
        "original.question" => Ok(question_bytes.clone()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            name.to_string(),
        )),
    };
    let verified = fa_verify::cli::run(&argv, &read);
    assert_eq!(verified.exit, 0, "{}{}", verified.stdout, verified.stderr);
    assert!(
        verified
            .stdout
            .contains("\"scope\":\"conditional_additive_scenario_math\"")
    );
    assert!(verified.stdout.contains("\"checked_intents\":1"));
    assert!(verified.stdout.contains("\"scenario_debits\":\"60000\""));
    assert!(
        verified
            .stdout
            .contains("\"historical_admission\":\"not_judged\"")
    );
    assert!(
        verified
            .stdout
            .contains("\"native_marker_membership\":\"not_judged\"")
    );

    let mut other_question = expected.clone();
    other_question.assumptions.clear();
    let wrong = other_question.encode().unwrap();
    let changed_question = |name: &str| {
        if name == "original.question" {
            Ok(wrong.clone())
        } else {
            read(name)
        }
    };
    let refused = fa_verify::cli::run(&argv, &changed_question);
    assert_eq!(refused.exit, 8, "{}{}", refused.stdout, refused.stderr);

    let mut no_question = argv.to_vec();
    let index = no_question
        .iter()
        .position(|arg| arg == "--scenario-request")
        .unwrap();
    no_question.drain(index..index + 2);
    let no_read = |_name: &str| -> std::io::Result<Vec<u8>> {
        panic!("a missing independent question is refused before file I/O");
    };
    assert_eq!(fa_verify::cli::run(&no_question, &no_read).exit, 2);
    let mut mixed = argv.to_vec();
    mixed.extend(["--units".into(), "1".into()]);
    assert_eq!(fa_verify::cli::run(&mixed, &no_read).exit, 2);
    Ok(())
}

#[test]
fn large_scenario_plan_survives_reopen_retry_and_historical_certified_replay() -> std::io::Result<()>
{
    let dir = tmp("large-scenario-control")?;
    let book = dir.join("book");
    let run = |args: &[&str]| {
        let mut full = args.to_vec();
        full.push("--json");
        let (code, out, err) = fa(Some(&book), &full);
        assert_eq!(code, 0, "{args:?}\n{out}\n{err}");
        out
    };
    run(&["book", "create", "--name", "Large scenario review"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    );
    run(&["chart", "import", &chart]);
    run(&["period", "create", "--fiscal-year", "2026"]);
    run(&["period", "open", "FY2026-P03"]);
    let evidence = source_doc(&dir, &book);
    run(&["scenario", "fork", "large-plan", "--as", "analyst"]);
    let open = || {
        fa::Book::open_dir(
            &book,
            fa::BookKeys::load(&book.join("book.keys")).unwrap(),
            fa::Entropy::deterministic(0x5ca1),
        )
        .unwrap()
    };
    let head = || open().head().unwrap();
    let original_rows = doc(&run(&["tb", "--period", "FY2026-P03"]))
        .get("rows")
        .unwrap()
        .clone();
    let legs = (0..256)
        .flat_map(|_| {
            [
                r#"{"side":"debit","account":"1000","amount":"1.00 USD"}"#,
                r#"{"side":"credit","account":"4000","amount":"1.00 USD"}"#,
            ]
        })
        .collect::<Vec<_>>()
        .join(",");
    let intent = write(
        &dir,
        "large-plan.json",
        &format!(
            r#"{{"effective_date":"2026-03-15","idempotency_key":"large-scenario-entry","evidence":["{evidence}"],"legs":[{legs}]}}"#
        ),
    );
    let args = [
        "scenario",
        "run",
        "large-plan",
        "--intent",
        &intent,
        "--as",
        "analyst",
    ];
    let before = head();
    let planned = doc(&run(&args));
    assert_eq!(planned.get("already_recorded"), Some(&Json::Bool(false)));
    assert_eq!(
        head().0,
        before.0 + 1,
        "root, fragments and claim publish together"
    );
    let saved = {
        let reopened = open();
        let view = reopened.scenario("large-plan").unwrap().unwrap();
        assert_eq!(view.intents.len(), 1);
        assert!(view.intents[0].intent.canonical_bytes().unwrap().len() > 16_384);
        let (control, _) = reopened
            .read_entry(view.intents[0].record)
            .unwrap()
            .unwrap();
        assert!(
            control.encode().unwrap().len() > 16_384,
            "the actual ScenarioControl exceeds a native row"
        );
        assert_eq!(
            control.proposal.class,
            fa_model::EntryClass::SCENARIO_CONTROL
        );
        view.intents[0].clone()
    };
    let recorded = head();
    let retry = doc(&run(&args));
    assert_eq!(retry.get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(retry.get("control_entry"), planned.get("control_entry"));
    assert_eq!(head(), recorded);
    assert_eq!(
        open().scenario("large-plan").unwrap().unwrap().intents,
        [saved]
    );
    let certificate_file = dir.join("large-scenario.cert").display().to_string();
    let certified = run(&[
        "scenario",
        "diff",
        "large-plan",
        "--period",
        "FY2026-P03",
        "--certificate-out",
        &certificate_file,
    ]);
    assert_eq!(certified.lines().count(), 2);
    let first = json::parse(certified.lines().next().unwrap()).unwrap();
    let expected = first.get("data").unwrap().clone();
    assert_eq!(int(&expected, "intents"), Some(1));
    let rows = arr(&expected, "rows");
    assert_eq!(rows.len(), 2);
    let cash = rows.iter().find(|row| text(row, "code") == "1000").unwrap();
    assert_eq!(text(cash, "delta"), "256.00 USD");
    let retained_at = head();
    assert_eq!(
        retained_at.0,
        recorded.0 + 1,
        "certification retains its complete certificate in one metadata publication"
    );
    assert_eq!(
        int(&doc(&certified), "recorded_at"),
        Some(i128::from(retained_at.0))
    );
    assert_eq!(
        doc(&run(&["tb", "--period", "FY2026-P03"])).get("rows"),
        Some(&original_rows)
    );
    run(&["scenario", "discard", "large-plan", "--as", "analyst"]);
    let discarded = head();
    let replay = run(&["replay", &certificate_file]);
    let replayed = json::parse(replay.lines().next().unwrap()).unwrap();
    assert_eq!(replayed.get("data"), Some(&expected));
    assert_eq!(
        head(),
        discarded,
        "historical replay does not repeat scenario effects"
    );
    assert_eq!(
        doc(&run(&["tb", "--period", "FY2026-P03"])).get("rows"),
        Some(&original_rows)
    );
    Ok(())
}
