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

fn disposal_review(book: &Path, evidence: &str, account: &str, key: &str) -> Json {
    doc(&ok(
        book,
        "retain disposal for batch",
        &[
            "dispose",
            "--account",
            account,
            "--quantity",
            "5.000000 SHARE",
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
            "--review-only",
            "--json",
        ],
    ))
}

fn review_member(review: &Json) -> Json {
    json::obj(vec![
        ("review", json::s(text(review, "bytes"))),
        ("review_digest", json::s(text(review, "review_digest"))),
    ])
}

fn retained_disposal(review: &Json) -> fa::PostIntent {
    let bytes = text(review, "bytes")
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    fa::PostIntent::decode(&bytes).unwrap()
}

fn intent_member(intent: &fa::PostIntent) -> Json {
    let bytes: String = intent
        .canonical_bytes()
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    json::obj(vec![
        ("review", json::s(bytes)),
        ("review_digest", json::s(hex_of(&intent.digest().unwrap()))),
    ])
}

fn batch_file(dir: &Path, key: &str, members: Vec<Json>) -> String {
    write(
        dir,
        &format!("{key}.json"),
        &json::obj(vec![
            ("idempotency_key", json::s(key)),
            ("intents", Json::Arr(members)),
        ])
        .render(),
    )
}

fn batch_fixture() -> std::io::Result<(PathBuf, PathBuf, String, Json, Json)> {
    let (dir, book, evidence) = setup("FIFO")?;
    let chart = write(
        &dir,
        "second-inventory.json",
        r#"{"accounts":[{"code":"1401","name":"Second inventory","type":"Asset","unit":"any"}]}"#,
    );
    ok(
        &book,
        "second inventory account",
        &[
            "chart",
            "import",
            &chart,
            "--key",
            "second-inventory-chart",
            "--json",
        ],
    );
    ok(
        &book,
        "second inventory policy",
        &[
            "chart",
            "lot-policy",
            "set",
            "--account",
            "1401",
            "--law",
            "FIFO",
            "--regime",
            "US-GAAP",
            "--date",
            "2026-03-01",
            "--key",
            "second-inventory-policy",
            "--json",
        ],
    );
    let acquisition = write(
        &dir,
        "second-inventory-acquisition.json",
        r#"{
        "effective_date":"2026-03-05","idempotency_key":"second-inventory-acquisition","legs":[
            {"side":"debit","account":"1401","amount":"10.000000 SHARE"},
            {"side":"credit","account":"1499","amount":"10.000000 SHARE"},
            {"side":"debit","account":"1401","amount":"50.00 USD"},
            {"side":"credit","account":"1000","amount":"50.00 USD"}
        ]}"#,
    );
    ok(
        &book,
        "second inventory acquisition",
        &[
            "post",
            "--intent",
            &acquisition,
            "--evidence",
            &evidence,
            "--json",
        ],
    );
    let before = frontier(&book);
    let first = disposal_review(&book, &evidence, "1400", "batch-first-disposal");
    let second = disposal_review(&book, &evidence, "1401", "batch-second-disposal");
    assert_eq!(first.get("known_at"), second.get("known_at"));
    assert_eq!(
        frontier(&book),
        before,
        "retaining both proposals must not publish"
    );
    Ok((dir, book, evidence, first, second))
}

fn remaining_lots(book: &Path, account: &str) -> Vec<(String, String)> {
    let lots = doc(&ok(
        book,
        "remaining lots",
        &["gl", "lots", "--account", account, "--json"],
    ));
    let mut remaining = arr(&lots, "lots")
        .iter()
        .map(|lot| {
            (
                text(lot, "open_quantity").to_string(),
                text(lot, "open_cost").to_string(),
            )
        })
        .collect::<Vec<_>>();
    remaining.sort();
    remaining
}

#[test]
fn inline_disposal_reviews_plan_commit_and_retry_one_atomic_batch() -> std::io::Result<()> {
    let (dir, book, evidence, first, second) = batch_fixture()?;
    let before = frontier(&book);
    let batch = batch_file(
        &dir,
        "two-inventories",
        vec![review_member(&first), review_member(&second)],
    );
    let plan = dir.join("two-inventories.plan").display().to_string();
    let preview = ok(
        &book,
        "plan both reviewed disposals",
        &[
            "batch",
            "--intent",
            &batch,
            "--dry-run",
            "--plan-out",
            &plan,
            "--json",
        ],
    );
    assert_eq!(field(&preview, "event"), Some("batch_plan"));
    assert_eq!(frontier(&book), before);
    let committed = ok(
        &book,
        "commit both reviewed disposals",
        &["commit", "--plan", &plan, "--grant", "read", "--json"],
    );
    assert_eq!(field(&committed, "event"), Some("batch_plan_committed"));
    assert_eq!(
        doc(&committed).get("already_recorded"),
        Some(&Json::Bool(false))
    );
    let after = frontier(&book);
    let Json::Int(before_seq) = before else {
        panic!("integer frontier");
    };
    assert_eq!(
        after,
        Json::Int(before_seq + 1),
        "both entries share one publication"
    );
    assert_eq!(
        remaining_lots(&book, "1400"),
        vec![
            ("10.000000 SHARE".into(), "20.00 USD".into()),
            ("5.000000 SHARE".into(), "50.00 USD".into()),
        ]
    );
    assert_eq!(
        remaining_lots(&book, "1401"),
        vec![("5.000000 SHARE".into(), "25.00 USD".into())]
    );
    let repeated = ok(
        &book,
        "retry unchanged review batch",
        &["batch", "--intent", &batch, "--json"],
    );
    assert_eq!(field(&repeated, "event"), Some("batch_posted"));
    assert_eq!(
        doc(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(arr(&doc(&repeated), "members").len(), 2);
    assert_eq!(frontier(&book), after);

    let fresh_first = disposal_review(&book, &evidence, "1400", "stale-batch-first");
    let fresh_second = disposal_review(&book, &evidence, "1401", "stale-batch-second");
    let stale = batch_file(
        &dir,
        "stale-batch",
        vec![review_member(&fresh_first), review_member(&fresh_second)],
    );
    let unrelated = write(
        &dir,
        "between-review-and-post.json",
        r#"{"effective_date":"2026-03-15","idempotency_key":"between-review-and-post","legs":[{"side":"debit","account":"5100","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
    );
    ok(
        &book,
        "intervening ordinary entry",
        &[
            "post",
            "--intent",
            &unrelated,
            "--evidence",
            &evidence,
            "--json",
        ],
    );
    let changed = frontier(&book);
    let (code, out, err) = run(
        &book,
        "refuse stale inline reviews",
        &["batch", "--intent", &stale, "--json"],
    );
    assert_eq!(code, 6, "{out}\n{err}");
    assert_eq!(frontier(&book), changed);
    let retry = ok(
        &book,
        "retry recorded batch after later activity",
        &["batch", "--intent", &batch, "--json"],
    );
    assert_eq!(doc(&retry).get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(frontier(&book), changed);
    Ok(())
}

#[test]
fn inline_disposal_batches_refuse_changed_reviews_and_later_poison_atomically()
-> std::io::Result<()> {
    let (dir, book, _evidence, first, second) = batch_fixture()?;
    let before = frontier(&book);
    let before_first = remaining_lots(&book, "1400");
    let before_second = remaining_lots(&book, "1401");
    let valid = retained_disposal(&second);
    let mut refusals = Vec::new();
    let wrong_digest = format!(
        "{}{}",
        if text(&second, "review_digest").starts_with('0') {
            "1"
        } else {
            "0"
        },
        &text(&second, "review_digest")[1..]
    );
    refusals.push((
        "wrong-digest",
        json::obj(vec![
            ("review", json::s(text(&second, "bytes"))),
            ("review_digest", json::s(wrong_digest)),
        ]),
        2,
    ));
    let path = write(&dir, "must-not-read.review", text(&second, "bytes"));
    for (name, review) in [("nested-host-path", path.as_str()), ("nested-stdin", "-")] {
        refusals.push((
            name,
            json::obj(vec![
                ("review", json::s(review)),
                ("review_digest", json::s(text(&second, "review_digest"))),
            ]),
            2,
        ));
    }
    refusals.push((
        "extra-member-field",
        json::obj(vec![
            ("review", json::s(text(&second, "bytes"))),
            ("review_digest", json::s(text(&second, "review_digest"))),
            ("idempotency_key", json::s("replace-sealed-key")),
        ]),
        2,
    ));
    for name in [
        "wrong-book",
        "wrong-principal",
        "wrong-branch",
        "wrong-class",
        "missing-basis",
    ] {
        let mut proposal = valid.proposal().clone();
        match name {
            "wrong-book" => proposal.book_id.0[0] ^= 1,
            "wrong-principal" => proposal.principal_ref.0 ^= 1,
            "wrong-branch" => proposal.branch_id.0[0] ^= 1,
            "wrong-class" => proposal.class = fa_model::EntryClass::ADJUSTING,
            "missing-basis" => proposal.extensions.clear(),
            _ => unreachable!(),
        }
        let intent = fa::PostIntent::new(proposal, vec![]).unwrap();
        refusals.push((name, intent_member(&intent), 2));
    }
    let with_approval = fa::PostIntent::new(
        valid.proposal().clone(),
        vec![fa_model::ApprovalRef {
            approval_vid: fgdb_types::VId(1),
            approved_digest: valid.proposal().proposal_digest().unwrap(),
        }],
    )
    .unwrap();
    refusals.push(("unexpected-approval", intent_member(&with_approval), 2));
    // This member passes the transport checks with canonical bytes and a new
    // matching digest. Only the independent kernel derivation can reject it,
    // after the first member has already been staged in the transaction.
    let mut poisoned = valid.proposal().clone();
    assert_eq!(poisoned.legs.len(), 4);
    poisoned.legs[2].amount.mantissa += 1;
    poisoned.legs[3].amount.mantissa += 1;
    poisoned.unit_totals = fa_model::EntryPayload::fold_unit_totals(&poisoned.legs).unwrap();
    let poisoned = fa::PostIntent::new(poisoned, vec![]).unwrap();
    refusals.push(("later-cost-plug", intent_member(&poisoned), 3));
    for (name, member, expected_exit) in refusals {
        let path = batch_file(&dir, name, vec![review_member(&first), member]);
        let (code, out, err) = run(&book, name, &["batch", "--intent", &path, "--json"]);
        assert_eq!(code, expected_exit, "{name}: {out}\n{err}");
        assert!(
            text(&doc(&out), "message").contains("member 1"),
            "{name}: {out}"
        );
        assert_eq!(
            frontier(&book),
            before,
            "{name} published part of the batch"
        );
        assert_eq!(remaining_lots(&book, "1400"), before_first, "{name}");
        assert_eq!(remaining_lots(&book, "1401"), before_second, "{name}");
    }
    let valid_batch = batch_file(
        &dir,
        "after-refusals",
        vec![review_member(&first), review_member(&second)],
    );
    let posted = ok(
        &book,
        "commit untouched reviews after every refusal",
        &["batch", "--intent", &valid_batch, "--json"],
    );
    assert_eq!(
        doc(&posted).get("already_recorded"),
        Some(&Json::Bool(false))
    );
    assert_eq!(
        remaining_lots(&book, "1401"),
        vec![("5.000000 SHARE".into(), "25.00 USD".into())]
    );
    Ok(())
}
