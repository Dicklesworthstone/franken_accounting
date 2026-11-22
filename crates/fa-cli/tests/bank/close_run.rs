//! A close dependency consumes authentic reconciliation history, not a manual
//! completion flag. Each command reopens the same native book in a new process.

use super::*;

const PERIOD: &str = "FY2026-P03";
const CONTROLLER: &str = "bank-close-controller";

fn imported(f: &Fixture, statement_date: &str) -> (String, Json) {
    f.post("close-bank-sale", "2026-03-10", "debit", "100.00", "SALE");
    let source = f.import(
        "close-bank.csv",
        "csv",
        &format!(
            "{CSV_HEADER}1,BANK-CLOSE,USD,{statement_date},0.00,100.00,2026-03-10,2026-03-10,CRDT,100.00,Customer,SALE\n"
        ),
    );
    let manifest = text(data(&source), "manifest_oid").to_string();
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", &manifest]);
    let confirmed = confirm_selection(
        &f.book,
        &confirmation_args(&matched, 0, "bank-close-confirmer"),
    );
    (manifest, confirmed)
}

fn reconcile(f: &Fixture, manifest: &str) -> String {
    let closed = reconcile_selection(&f.book, &reconciliation_args(manifest, head(&f.book)));
    text(
        data(&closed).get("reconciliation").unwrap(),
        "attestation_vid",
    )
    .to_string()
}

fn start(f: &Fixture, manifest: &str) -> Json {
    let tasks = format!(
        r#"[{{"id":"bank","verify_bank_reconciliation":"D:{manifest}"}},{{"id":"finish","depends_on":["bank"],"transition":"close"}}]"#
    );
    ok(
        &f.book,
        &[
            "close",
            "start",
            "--run",
            "march-cash",
            "--period",
            PERIOD,
            "--tasks",
            &tasks,
            "--as",
            CONTROLLER,
            "--grant",
            "reconcile",
        ],
    )
}

fn bank_task(view: &Json) -> &Json {
    rows(view, "tasks")
        .iter()
        .find(|task| text(task, "id") == "bank")
        .unwrap()
}

fn bank_step() -> Vec<&'static str> {
    vec![
        "close",
        "step",
        "--run",
        "march-cash",
        "--task",
        "bank",
        "--as",
        CONTROLLER,
        "--grant",
        "reconcile",
        "--yes",
    ]
}

#[test]
fn close_bank_checkpoint_rehearses_retries_and_allows_unrelated_later_cash() {
    let f = Fixture::new();
    let (manifest, _) = imported(&f, "2026-03-31");
    let attestation = reconcile(&f, &manifest);
    let opened = start(&f, &manifest);
    let bank = bank_task(data(&opened).get("run").unwrap());
    assert_eq!(text(bank, "kind"), "verify-bank-reconciliation");
    assert_eq!(text(bank, "bank_manifest_oid"), manifest);
    assert_eq!(bank.get("ready"), Some(&Json::Bool(true)));

    let before = head(&f.book);
    let (denied, _) = run(&f.book, &["close", "dry-run", "--run", "march-cash"]);
    assert_eq!(
        denied, 7,
        "bank evaluation requires an explicit reconcile grant"
    );
    assert_eq!(head(&f.book), before);
    let rehearsal = ok(
        &f.book,
        &[
            "close",
            "dry-run",
            "--run",
            "march-cash",
            "--grant",
            "reconcile",
        ],
    );
    let checked = bank_task(data(&rehearsal));
    assert_eq!(text(checked, "state"), "bank-reconciliation-verified");
    let basis = checked.get("bank_verification").unwrap();
    assert_eq!(text(basis, "manifest_oid"), manifest);
    assert_eq!(text(basis, "statement_date"), "2026-03-31");
    assert_eq!(text(basis.get("attestation").unwrap(), "vid"), attestation);
    assert_eq!(text(basis, "source_digest").len(), 64);
    assert_eq!(head(&f.book), before, "bank rehearsal writes nothing");

    let completed = ok(&f.book, &bank_step());
    let receipt = data(&completed).get("receipt").unwrap();
    assert_eq!(text(receipt, "effect"), attestation);
    assert_eq!(
        head(&f.book),
        before + 1,
        "one atomic completion publication"
    );
    let retry = ok(&f.book, &bank_step());
    assert_eq!(
        data(&retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(data(&retry).get("receipt"), Some(receipt));
    assert_eq!(head(&f.book), before + 1);

    // The requirement is March's cash source. A different month's genuine
    // transaction must not invalidate the retained March reconciliation.
    ok(&f.book, &["period", "open", "FY2026-P04"]);
    f.post("april-cash", "2026-04-01", "debit", "7.00", "APRIL");
    let plan = f.dir.join("march-close.plan").display().to_string();
    let before_transition = head(&f.book);
    ok(
        &f.book,
        &[
            "close",
            "step",
            "--run",
            "march-cash",
            "--task",
            "finish",
            "--key",
            "close-march-cash",
            "--reason",
            "AuditComplete",
            "--dry-run",
            "--plan-out",
            &plan,
            "--as",
            CONTROLLER,
            "--grant",
            "reconcile",
        ],
    );
    assert_eq!(head(&f.book), before_transition);
    let finished = ok(
        &f.book,
        &[
            "close",
            "step",
            "--run",
            "march-cash",
            "--task",
            "finish",
            "--plan",
            &plan,
            "--as",
            CONTROLLER,
            "--grant",
            "reconcile",
            "--yes",
        ],
    );
    assert_eq!(
        data(&finished).get("run").unwrap().get("complete"),
        Some(&Json::Bool(true))
    );
    assert_eq!(head(&f.book), before_transition + 1);
}

#[test]
fn close_bank_checkpoint_blocks_net_zero_cash_and_match_drift_after_completion() {
    for change in ["offsetting-cash", "released-match"] {
        let f = Fixture::new();
        let (manifest, confirmed) = imported(&f, "2026-03-31");
        reconcile(&f, &manifest);
        start(&f, &manifest);
        let completed = ok(&f.book, &bank_step());
        let original = data(&completed).get("receipt").unwrap();
        if change == "offsetting-cash" {
            for (key, cash_side, other_side, other_account) in [
                ("late-in", "debit", "credit", "4000"),
                ("late-out", "credit", "debit", "6000"),
            ] {
                let intent = f.file(
                    &format!("{key}.json"),
                    &format!(
                        r#"{{"effective_date":"2026-03-20","idempotency_key":"{key}","legs":[{{"side":"{cash_side}","account":"1000","amount":"1.00 USD"}},{{"side":"{other_side}","account":"{other_account}","amount":"1.00 USD"}}]}}"#
                    ),
                );
                ok(
                    &f.book,
                    &[
                        "post",
                        "--intent",
                        &intent,
                        "--evidence",
                        &f.evidence,
                        "--grant",
                        "reconcile",
                    ],
                );
            }
        } else {
            let mut release = unmatch_args(&confirmed);
            release.push("--yes".into());
            ok(
                &f.book,
                &release.iter().map(String::as_str).collect::<Vec<_>>(),
            );
        }
        let state = ok(&f.book, &["bank", "reconciliation", "--import", &manifest]);
        let drift = reconciliation_state(&state);
        assert_eq!(drift.get("balance_drift"), Some(&Json::Bool(false)));
        assert_eq!(
            drift.get(if change == "offsetting-cash" {
                "cash_drift"
            } else {
                "match_drift"
            }),
            Some(&Json::Bool(true)),
        );
        let before = head(&f.book);
        let (exit, refusal) = run(
            &f.book,
            &[
                "close",
                "step",
                "--run",
                "march-cash",
                "--task",
                "finish",
                "--key",
                "drifted-close",
                "--reason",
                "AuditComplete",
                "--dry-run",
                "--as",
                CONTROLLER,
                "--grant",
                "reconcile",
            ],
        );
        assert_ne!(exit, 0, "{change}: {}", refusal.render());
        assert_eq!(
            head(&f.book),
            before,
            "refusal cannot close or mark completion"
        );
        let status = ok(&f.book, &["close", "status", "--run", "march-cash"]);
        assert_eq!(
            bank_task(data(&status).get("run").unwrap()).get("completion"),
            Some(original),
            "later drift preserves the authentic historical completion",
        );
        let retried = ok(&f.book, &bank_step());
        assert_eq!(data(&retried).get("receipt"), Some(original));
        assert_eq!(head(&f.book), before);
    }
}

#[test]
fn close_bank_checkpoint_refuses_missing_attestation_and_wrong_statement_cutoff() {
    for closed_at in [None, Some("2026-03-15")] {
        let f = Fixture::new();
        let (manifest, _) = imported(&f, closed_at.unwrap_or("2026-03-31"));
        if closed_at.is_some() {
            reconcile(&f, &manifest);
        }
        start(&f, &manifest);
        let before = head(&f.book);
        let (exit, refused) = run(&f.book, &bank_step());
        assert_ne!(exit, 0, "{closed_at:?}: {}", refused.render());
        assert_eq!(head(&f.book), before);
        let status = ok(&f.book, &["close", "status", "--run", "march-cash"]);
        assert_eq!(
            bank_task(data(&status).get("run").unwrap()).get("completion"),
            Some(&Json::Null),
        );
    }
}
