//! A governed inventory disposal through the same public review/plan/commit path.

use super::*;

#[path = "lot_disposal/certified.rs"]
mod certified;

fn run(book: &Path, step: &str, args: &[&str]) -> (i32, String, String) {
    let (code, out, err) = fa(Some(book), args);
    let envelope = json::parse(out.lines().last().unwrap_or_default()).unwrap_or(Json::Null);
    let known_at = envelope
        .get("coordinate")
        .and_then(|coordinate| coordinate.get("known_at"));
    eprintln!(
        "{step}: argv={args:?} exit={code} event={:?} refusal={:?} known_at={known_at:?}",
        field(&out, "event"),
        field(&out, "refusal_id")
    );
    (code, out, err)
}

fn ok(book: &Path, step: &str, args: &[&str]) -> String {
    let (code, out, err) = run(book, step, args);
    assert_eq!(code, 0, "{step}: argv={args:?}\nstdout={out}\nstderr={err}");
    out
}

fn frontier(book: &Path) -> Json {
    let out = ok(book, "frontier", &["book", "info", "--json"]);
    json::parse(out.trim())
        .unwrap()
        .get("coordinate")
        .unwrap()
        .get("known_at")
        .unwrap()
        .clone()
}

fn setup(law: &str) -> std::io::Result<(PathBuf, PathBuf, String)> {
    let dir = tmp("law-bound-lot-disposal")?;
    let book = dir.join("book");
    ok(
        &book,
        "book",
        &["book", "create", "--name", "Inventory Co", "--json"],
    );
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[
        {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
        {"code":"1400","name":"Inventory","type":"Asset","unit":"any"},
        {"code":"1499","name":"Quantity offset","type":"Equity","unit":"SHARE"},
        {"code":"5100","name":"Cost of goods sold","type":"Expense","unit":"USD"}
    ]}"#,
    );
    ok(&book, "chart", &["chart", "import", &chart, "--json"]);
    ok(
        &book,
        "periods",
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    ok(&book, "open", &["period", "open", "FY2026-P03", "--json"]);
    let evidence = source_doc(&dir, &book);
    let policy = ok(
        &book,
        "govern inventory",
        &[
            "chart",
            "lot-policy",
            "set",
            "--account",
            "1400",
            "--law",
            law,
            "--regime",
            "US-GAAP",
            "--date",
            "2026-03-01",
            "--key",
            "inventory-policy",
            "--json",
        ],
    );
    assert_eq!(field(&policy, "event"), Some("lot_policy_recorded"));
    assert_eq!(text(&doc(&policy), "law"), law);
    for (key, date, cost) in [
        ("first-lot", "2026-03-05", "100.00"),
        ("second-lot", "2026-03-10", "20.00"),
    ] {
        let intent = write(
            &dir,
            &format!("{key}.json"),
            &format!(
                r#"{{
            "effective_date":"{date}","idempotency_key":"{key}","legs":[
                {{"side":"debit","account":"1400","amount":"10.000000 SHARE"}},
                {{"side":"credit","account":"1499","amount":"10.000000 SHARE"}},
                {{"side":"debit","account":"1400","amount":"{cost} USD"}},
                {{"side":"credit","account":"1000","amount":"{cost} USD"}}
            ]}}"#
            ),
        );
        ok(
            &book,
            "acquisition",
            &[
                "post",
                "--intent",
                &intent,
                "--evidence",
                &evidence,
                "--json",
            ],
        );
    }
    Ok((dir, book, evidence))
}

#[test]
fn disposal_review_native_plan_commit_retry_and_weighted_average_remainder_work_together()
-> std::io::Result<()> {
    let (dir, book, evidence) = setup("WeightedAverage")?;
    let before = frontier(&book);
    let review_path = dir.join("first-disposal.review").display().to_string();
    let review_out = ok(
        &book,
        "review disposal",
        &[
            "dispose",
            "--account",
            "1400",
            "--quantity",
            "10.000000 SHARE",
            "--quantity-offset",
            "1499",
            "--cost-offset",
            "5100",
            "--date",
            "2026-03-15",
            "--key",
            "first-disposal",
            "--evidence",
            &evidence,
            "--review-out",
            &review_path,
            "--json",
        ],
    );
    assert_eq!(field(&review_out, "event"), Some("lot_disposal_review"));
    let review = doc(&review_out);
    assert_eq!(text(&review, "law"), "WeightedAverage");
    assert_eq!(text(&review, "quantity"), "10.000000 SHARE");
    assert_eq!(
        arr(&review, "legs")
            .iter()
            .filter(|leg| text(leg, "amount") == "60.00 USD")
            .count(),
        2
    );
    assert_eq!(frontier(&book), before);
    let plan_path = dir.join("first-disposal.plan").display().to_string();
    let dry_run = ok(
        &book,
        "rehearse review",
        &[
            "dispose",
            "--review",
            &review_path,
            "--digest",
            text(&review, "review_digest"),
            "--dry-run",
            "--plan-out",
            &plan_path,
            "--json",
        ],
    );
    assert_eq!(field(&dry_run, "event"), Some("plan"));
    assert_eq!(frontier(&book), before);
    let committed = ok(
        &book,
        "commit plan",
        &["commit", "--plan", &plan_path, "--grant", "read", "--json"],
    );
    assert_eq!(field(&committed, "event"), Some("plan_committed"));
    let after = frontier(&book);
    let repeated = ok(
        &book,
        "retry original review",
        &[
            "dispose",
            "--review",
            &review_path,
            "--digest",
            text(&review, "review_digest"),
            "--json",
        ],
    );
    assert_eq!(field(&repeated, "event"), Some("recorded"));
    assert_eq!(frontier(&book), after);

    let remainder = doc(&ok(
        &book,
        "remaining weighted pool",
        &[
            "gl",
            "lots",
            "--account",
            "1400",
            "--relieve",
            "10.000000 SHARE",
            "--law",
            "WeightedAverage",
            "--json",
        ],
    ));
    assert_eq!(
        text(remainder.get("disposal_plan").unwrap(), "total_cost"),
        "60.00 USD"
    );
    let final_sale = ok(
        &book,
        "dispose remaining pool",
        &[
            "dispose",
            "--account",
            "1400",
            "--quantity",
            "10.000000 SHARE",
            "--quantity-offset",
            "1499",
            "--cost-offset",
            "5100",
            "--date",
            "2026-03-20",
            "--key",
            "last-disposal",
            "--evidence",
            &evidence,
            "--json",
        ],
    );
    assert_eq!(field(&final_sale, "event"), Some("posted"));
    let empty = doc(&ok(
        &book,
        "exhausted inventory",
        &["gl", "lots", "--account", "1400", "--json"],
    ));
    assert_eq!(arr(&empty, "lots").len(), 2);
    for lot in arr(&empty, "lots") {
        assert_eq!(text(lot, "open_quantity"), "0.000000 SHARE");
        assert_eq!(text(lot, "open_cost"), "0.00 USD");
    }
    assert!(
        arr(&empty, "lots")
            .iter()
            .flat_map(|lot| arr(lot, "relieves"))
            .any(|relief| {
                relief.get("qty_ordinal") == Some(&Json::Null)
                    && text(relief, "quantity") == "0.000000 SHARE"
                    && text(relief, "cost") == "40.00 USD"
            }),
        "cost-only applications remain visible in the public schedule"
    );
    Ok(())
}

#[test]
fn manual_cost_plugs_and_unapproved_policy_changes_fail_without_posting() -> std::io::Result<()> {
    let (dir, book, evidence) = setup("FIFO")?;
    let before = frontier(&book);
    let plug = write(
        &dir,
        "cost-plug.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"cost-plug","legs":[{"side":"debit","account":"5100","amount":"0.01 USD"},{"side":"credit","account":"1400","amount":"0.01 USD"}]}"#,
    );
    let (code, out, err) = run(
        &book,
        "manual cost plug",
        &["post", "--intent", &plug, "--evidence", &evidence, "--json"],
    );
    assert_eq!(code, 3, "{out}\n{err}");
    assert_eq!(text(&doc(&out), "refusal_id"), "FA-REF-071");
    assert_eq!(frontier(&book), before);
    let (code, out, err) = run(
        &book,
        "unapproved policy change",
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
            "2026-03-20",
            "--key",
            "change-law",
            "--json",
        ],
    );
    assert_eq!(code, 7, "{out}\n{err}");
    assert_eq!(frontier(&book), before);
    let path = dir.join("new-policy.review").display().to_string();
    let reviewed = doc(&ok(
        &book,
        "review policy change",
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
            "2026-03-20",
            "--key",
            "change-law",
            "--review-out",
            &path,
            "--json",
        ],
    ));
    assert_eq!(frontier(&book), before);
    let mut approvals = Vec::new();
    for principal in ["controller", "reviewer"] {
        let approval = doc(&ok(
            &book,
            "approve policy",
            &[
                "approve",
                "--proposal",
                text(&reviewed, "proposal_digest"),
                "--as",
                principal,
                "--json",
            ],
        ));
        approvals.push(text(&approval, "approval_vid").to_string());
    }
    ok(
        &book,
        "publish approved policy",
        &[
            "chart",
            "lot-policy",
            "set",
            "--review",
            &path,
            "--digest",
            text(&reviewed, "review_digest"),
            "--approval",
            &approvals[0],
            "--approval",
            &approvals[1],
            "--json",
        ],
    );
    let selected = doc(&ok(
        &book,
        "show current policy",
        &["chart", "lot-policy", "show", "--account", "1400", "--json"],
    ));
    assert_eq!(text(&selected, "law"), "LIFO");
    let current = doc(&ok(
        &book,
        "old effective date under current law",
        &[
            "dispose",
            "--account",
            "1400",
            "--quantity",
            "12.000000 SHARE",
            "--quantity-offset",
            "1499",
            "--cost-offset",
            "5100",
            "--date",
            "2026-03-15",
            "--key",
            "current-law",
            "--evidence",
            &evidence,
            "--review-only",
            "--json",
        ],
    ));
    assert_eq!(text(&current, "law"), "LIFO");
    assert_eq!(
        arr(&current, "legs")
            .iter()
            .filter(|leg| text(leg, "amount") == "40.00 USD")
            .count(),
        2
    );
    Ok(())
}
