//! Scenario relief must use its own history and cannot become a trunk review.

use super::*;

fn dispose_args<'a>(evidence: &'a str, key: &'a str, quantity: &'a str) -> Vec<&'a str> {
    vec![
        "dispose",
        "--account",
        "1400",
        "--quantity",
        quantity,
        "--quantity-offset",
        "1499",
        "--cost-offset",
        "5100",
        "--date",
        "2026-03-15",
        "--key",
        key,
        "--evidence",
        evidence,
        "--json",
    ]
}

fn fork(book: &Path, name: &str) -> Json {
    doc(&ok(
        book,
        "fork inventory scenario",
        &["scenario", "fork", name, "--json"],
    ))
}

fn lots(book: &Path) -> Vec<Json> {
    arr(
        &doc(&ok(
            book,
            "read trunk lots",
            &["gl", "lots", "--account", "1400", "--json"],
        )),
        "lots",
    )
    .to_vec()
}

fn refused(book: &Path, args: &[&str]) -> String {
    let (status, out, err) = run(book, "refuse invalid scenario relief", args);
    assert!(status != 0, "unexpected success: {out}\n{err}");
    assert_eq!(field(&out, "event"), Some("error"), "{out}");
    out
}

#[test]
fn scenario_lot_disposal_keeps_fork_policy_and_certified_history_isolated() -> std::io::Result<()> {
    let (dir, book, evidence) = setup("FIFO")?;
    let forked = fork(&book, "stocking");
    let mut actual = dispose_args(&evidence, "shared-sale", "10.000000 SHARE");
    ok(&book, "trunk sale after scenario fork", &actual);
    let policy_path = dir.join("later-lifo.review").display().to_string();
    let policy_review = doc(&ok(
        &book,
        "review trunk policy change after fork",
        &[
            "chart",
            "lot-policy",
            "set",
            "--account",
            "1400",
            "--law",
            "LIFO",
            "--regime",
            "US-GAAP",
            "--date",
            "2026-03-15",
            "--key",
            "later-lifo",
            "--review-out",
            &policy_path,
            "--json",
        ],
    ));
    let mut approvals = Vec::new();
    for principal in ["controller", "reviewer"] {
        let approval = doc(&ok(
            &book,
            "approve later trunk lot policy",
            &[
                "approve",
                "--proposal",
                text(&policy_review, "proposal_digest"),
                "--as",
                principal,
                "--json",
            ],
        ));
        approvals.push(text(&approval, "approval_vid").to_string());
    }
    ok(
        &book,
        "publish later trunk lot policy",
        &[
            "chart",
            "lot-policy",
            "set",
            "--review",
            &policy_path,
            "--digest",
            text(&policy_review, "review_digest"),
            "--approval",
            &approvals[0],
            "--approval",
            &approvals[1],
            "--json",
        ],
    );
    let trunk_before = lots(&book);
    let review_path = dir.join("scenario-disposal.review").display().to_string();
    let mut scenario = dispose_args(&evidence, "shared-sale", "15.000000 SHARE");
    scenario.extend(["--scenario", "stocking", "--review-out", &review_path]);
    let before_review = frontier(&book);
    let review = doc(&ok(&book, "review FIFO relief at fork", &scenario));
    assert_eq!(
        frontier(&book),
        before_review,
        "preparation must be read only"
    );
    assert_eq!(text(&review, "law"), "FIFO");
    assert_eq!(
        arr(&review, "legs")
            .iter()
            .filter(|leg| text(leg, "amount") == "110.00 USD")
            .count(),
        2
    );
    let intent = fa::PostIntent::decode(&std::fs::read(&review_path)?).unwrap();
    let basis = intent.proposal().lot_disposal_basis().unwrap().unwrap();
    let scope = basis.scenario.unwrap();
    assert_eq!(Some(i128::from(scope.fork_at.0)), int(&forked, "fork_at"));
    assert_eq!(scope.ordinal, 1);
    let recorded = doc(&ok(
        &book,
        "run reviewed scenario relief",
        &[
            "dispose",
            "--review",
            &review_path,
            "--digest",
            text(&review, "review_digest"),
            "--scenario",
            "stocking",
            "--json",
        ],
    ));
    assert_eq!(int(&recorded, "ordinal"), Some(1));
    assert_eq!(recorded.get("rehearsed"), Some(&Json::Bool(true)));
    assert_eq!(
        lots(&book),
        trunk_before,
        "counterfactual relief never touches trunk lots"
    );
    let certified = ok(
        &book,
        "certify scenario relief",
        &[
            "scenario",
            "diff",
            "stocking",
            "--period",
            "FY2026-P03",
            "--certify",
            "--json",
        ],
    );
    let lines: Vec<_> = certified.lines().collect();
    assert_eq!(lines.len(), 2, "{certified}");
    let diff = doc(lines[0]);
    assert_eq!(
        text(
            arr(&diff, "rows")
                .iter()
                .find(|row| text(row, "code") == "5100")
                .unwrap(),
            "delta"
        ),
        "110.00 USD"
    );
    let certificate = doc(lines[1]);
    let handle = format!("C:{}", text(&certificate, "oid"));
    // Extend both histories. A historical certificate still reproduces its
    // own single disposal and its original fork-time policy.
    actual[4] = "1.000000 SHARE";
    actual[12] = "later-actual";
    ok(&book, "later actual relief", &actual);
    let mut later = dispose_args(&evidence, "later-scenario", "1.000000 SHARE");
    later.extend(["--scenario", "stocking"]);
    ok(&book, "later scenario relief", &later);
    let replayed = ok(
        &book,
        "replay certified scenario disposal",
        &["replay", &handle, "--json"],
    );
    assert_eq!(doc(&replayed), diff);
    let mut retry = dispose_args(&evidence, "shared-sale", "15.000000 SHARE");
    retry.extend(["--scenario", "stocking"]);
    let retried = doc(&ok(&book, "retry at original scenario position", &retry));
    assert_eq!(retried.get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(text(&retried, "entry"), text(&recorded, "entry"));
    Ok(())
}

#[test]
fn scenario_lot_disposal_uses_scenario_only_acquisitions_and_its_own_key_namespace()
-> std::io::Result<()> {
    let (dir, book, evidence) = setup("LIFO")?;
    fork(&book, "new-stock");
    fork(&book, "other-stock");
    let acquisition = write(
        &dir,
        "scenario-purchase.json",
        &format!(
            r#"{{"effective_date":"2026-03-12","idempotency_key":"counterfactual-purchase","evidence":["{evidence}"],"legs":[{{"side":"debit","account":"1400","amount":"10.000000 SHARE"}},{{"side":"credit","account":"1499","amount":"10.000000 SHARE"}},{{"side":"debit","account":"1400","amount":"40.00 USD"}},{{"side":"credit","account":"1000","amount":"40.00 USD"}}]}}"#,
        ),
    );
    ok(
        &book,
        "buy stock only in scenario",
        &[
            "post",
            "--intent",
            &acquisition,
            "--scenario",
            "new-stock",
            "--json",
        ],
    );
    let trunk_before = lots(&book);
    let mut request = dispose_args(&evidence, "same-key", "5.000000 SHARE");
    request.extend(["--scenario", "new-stock", "--review-only"]);
    let review = doc(&ok(&book, "derive scenario-only LIFO layer", &request));
    assert_eq!(
        arr(&review, "legs")
            .iter()
            .filter(|leg| text(leg, "amount") == "20.00 USD")
            .count(),
        2
    );
    request.pop();
    let first = doc(&ok(&book, "run scenario-only LIFO relief", &request));
    assert_eq!(int(&first, "ordinal"), Some(2));
    *request.last_mut().unwrap() = "other-stock";
    let other = doc(&ok(&book, "same user key in another scenario", &request));
    assert_ne!(text(&first, "entry"), text(&other, "entry"));
    assert_eq!(lots(&book), trunk_before);
    let diff = doc(&ok(
        &book,
        "scenario purchase and relief delta",
        &[
            "scenario",
            "diff",
            "new-stock",
            "--period",
            "FY2026-P03",
            "--json",
        ],
    ));
    assert_eq!(
        text(
            arr(&diff, "rows")
                .iter()
                .find(|row| text(row, "code") == "5100")
                .unwrap(),
            "delta"
        ),
        "20.00 USD"
    );
    Ok(())
}

#[test]
fn scenario_disposal_reviews_refuse_trunk_cross_scenario_and_excess_relief_without_writes()
-> std::io::Result<()> {
    let (dir, book, evidence) = setup("FIFO")?;
    fork(&book, "source");
    fork(&book, "other");
    ok(
        &book,
        "fork before the inventory chart and policy existed",
        &[
            "scenario",
            "fork",
            "before-inventory",
            "--at",
            "1",
            "--json",
        ],
    );
    let path = dir.join("bound-scenario.review").display().to_string();
    let mut request = dispose_args(&evidence, "reviewed", "5.000000 SHARE");
    request.extend(["--scenario", "source", "--review-out", &path]);
    let review = doc(&ok(&book, "retain scenario-only review", &request));
    let before = frontier(&book);
    let trunk = [
        "dispose",
        "--review",
        &path,
        "--digest",
        text(&review, "review_digest"),
        "--json",
    ];
    let error = refused(&book, &trunk);
    assert!(error.contains("bound scratch materialization"), "{error}");
    assert_eq!(frontier(&book), before);
    let mut wrong = trunk.to_vec();
    wrong.extend(["--scenario", "other"]);
    let error = refused(&book, &wrong);
    assert!(error.contains("does not bind this scenario"), "{error}");
    assert_eq!(frontier(&book), before);
    let mut too_much = dispose_args(&evidence, "excess", "21.000000 SHARE");
    too_much.extend(["--scenario", "source"]);
    refused(&book, &too_much);
    assert_eq!(frontier(&book), before);
    let mut absent = dispose_args(&evidence, "absent", "1.000000 SHARE");
    absent.extend(["--scenario", "before-inventory"]);
    let error = refused(&book, &absent);
    assert!(error.contains("no journaled lot policy"), "{error}");
    assert_eq!(frontier(&book), before);
    let mut publish = trunk.to_vec();
    publish.extend(["--scenario", "source"]);
    ok(&book, "correct scenario accepts its review", &publish);
    let committed = frontier(&book);
    let mut changed = dispose_args(&evidence, "reviewed", "4.000000 SHARE");
    changed.extend(["--scenario", "source"]);
    refused(&book, &changed);
    assert_eq!(
        frontier(&book),
        committed,
        "changed-key retry must not append an intent"
    );
    Ok(())
}
