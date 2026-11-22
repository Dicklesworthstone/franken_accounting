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

fn portfolio_fixture() -> Fixture {
    Fixture::with_chart(
        r#"{"accounts":[{"code":"1000","name":"Operating bank","type":"Asset","unit":"USD"},{"code":"1001","name":"Payroll bank","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},{"code":"6000","name":"Expenses","type":"Expense","unit":"USD"}]}"#,
    )
}

fn register_bank(f: &Fixture, code: &str, account: &str) -> String {
    let party = f.file(
        &format!("{code}-party.json"),
        &format!(r#"{{"code":"PARTY-{code}","kind":"Bank","name":"{code} bank"}}"#),
    );
    ok(&f.book, &["party", "add", &party]);
    let instrument = f.file(
        &format!("{code}-instrument.json"),
        &format!(r#"{{"code":"{code}","name":"{code} cash account","kind":"BankAccount","unit":"USD","held_at":"PARTY-{code}","mirrors":"{account}"}}"#),
    );
    let registered = ok(&f.book, &["instrument", "add", &instrument]);
    text(data(&registered), "target").into()
}

fn payroll_statement(f: &Fixture) -> String {
    let source = f.file(
        "payroll.mt940",
        ":20:PAYROLL-CLOSE\n:25:PAYROLL-ACCOUNT\n:28C:1\n:60F:C260301USD0,\n:62F:C260331USD0,\n",
    );
    let imported = ok(
        &f.book,
        &[
            "bank",
            "import",
            &source,
            "--bank-format",
            "mt940",
            "--account",
            "1001",
        ],
    );
    text(data(&imported), "manifest_oid").into()
}

fn start_portfolio(f: &Fixture, name: &str, manifests: &[&str]) -> Json {
    let selected = manifests
        .iter()
        .enumerate()
        .map(|(index, oid)| {
            // The public action accepts both document handles and bare full OIDs.
            format!("\"{}{oid}\"", if index == 0 { "D:" } else { "" })
        })
        .collect::<Vec<_>>()
        .join(",");
    let tasks = format!(
        r#"[{{"id":"bank","verify_bank_instrument_coverage":[{selected}]}},{{"id":"finish","depends_on":["bank"],"transition":"close"}}]"#,
    );
    ok(
        &f.book,
        &[
            "close",
            "start",
            "--run",
            name,
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

fn portfolio_final_plan(f: &Fixture, key: &str) -> String {
    let plan = f.dir.join(format!("{key}.plan")).display().to_string();
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
            key,
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
    plan
}

#[test]
fn close_bank_portfolio_requires_every_registered_instrument_and_renders_complete_basis() {
    let f = portfolio_fixture();
    let operating_vid = register_bank(&f, "OPERATING", "1000");
    let payroll_vid = register_bank(&f, "PAYROLL", "1001");
    let (operating, _) = imported(&f, "2026-03-31");
    let operating_attestation = reconcile(&f, &operating);
    let payroll = payroll_statement(&f);
    let payroll_attestation = reconcile(&f, &payroll);

    start_portfolio(&f, "omitted-bank", &[&operating]);
    let before = head(&f.book);
    let (exit, refusal) = run(
        &f.book,
        &[
            "close",
            "step",
            "--run",
            "omitted-bank",
            "--task",
            "bank",
            "--as",
            CONTROLLER,
            "--grant",
            "reconcile",
            "--yes",
        ],
    );
    assert_eq!(exit, 6, "{}", refusal.render());
    assert!(text(data(&refusal), "message").contains("registered bank instruments"));
    assert_eq!(head(&f.book), before);
    let omitted = ok(&f.book, &["close", "status", "--run", "omitted-bank"]);
    assert_eq!(
        bank_task(data(&omitted).get("run").unwrap()).get("completion"),
        Some(&Json::Null)
    );

    let opened = start_portfolio(&f, "march-cash", &[&payroll, &operating]);
    let bank = bank_task(data(&opened).get("run").unwrap());
    assert_eq!(text(bank, "kind"), "verify-bank-instrument-coverage");
    let mut expected = vec![Json::Str(payroll.clone()), Json::Str(operating.clone())];
    expected.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    assert_eq!(rows(bank, "bank_manifest_oids"), expected);
    let before = head(&f.book);
    let (denied, _) = run(&f.book, &["close", "dry-run", "--run", "march-cash"]);
    assert_eq!(
        denied, 7,
        "complete inventory evaluation also requires Reconcile"
    );
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
    assert_eq!(text(checked, "state"), "bank-instrument-coverage-verified");
    let coverage = checked.get("bank_instrument_coverage").unwrap();
    assert_eq!(integer(coverage, "verified_at"), before);
    assert_eq!(text(coverage, "inventory_digest").len(), 64);
    assert_eq!(text(coverage, "source_digest").len(), 64);
    let instruments = rows(coverage, "instruments");
    assert_eq!(instruments.len(), 2);
    for (code, vid, manifest, attestation) in [
        (
            "OPERATING",
            &operating_vid,
            &operating,
            &operating_attestation,
        ),
        ("PAYROLL", &payroll_vid, &payroll, &payroll_attestation),
    ] {
        let row = instruments
            .iter()
            .find(|row| text(row, "code") == code)
            .unwrap();
        assert_eq!(text(row, "instrument"), vid);
        assert_eq!(text(row, "manifest_oid"), manifest);
        assert_eq!(text(row.get("attestation").unwrap(), "vid"), attestation);
        assert_eq!(text(row.get("attestation").unwrap(), "digest").len(), 64);
        assert_eq!(text(row, "statement_date"), "2026-03-31");
        assert_eq!(text(row, "checkpoint_digest").len(), 64);
        assert_eq!(text(row, "account").len(), 32);
        assert!(matches!(row.get("unit_id"), Some(Json::Int(_))));
    }
    assert_eq!(
        head(&f.book),
        before,
        "rehearsal publishes no portfolio receipt"
    );
    let completed = ok(&f.book, &bank_step());
    let receipt = data(&completed).get("receipt").unwrap();
    assert_eq!(
        text(receipt, "effect"),
        format!("{:032x}", fa_journal::rows::book_root().0)
    );
    assert_eq!(head(&f.book), before + 1);
    let retry = ok(
        &f.book,
        &[
            "close",
            "step",
            "--run",
            "march-cash",
            "--task",
            "bank",
            "--as",
            CONTROLLER,
            "--yes",
        ],
    );
    assert_eq!(
        data(&retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(data(&retry).get("receipt"), Some(receipt));
    assert_eq!(head(&f.book), before + 1);
    let plan = portfolio_final_plan(&f, "portfolio-close");
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
    assert_eq!(head(&f.book), before + 2);
}

#[test]
fn a_new_registered_bank_blocks_terminal_close_and_preserves_original_portfolio_receipt() {
    let f = portfolio_fixture();
    register_bank(&f, "OPERATING", "1000");
    let (operating, _) = imported(&f, "2026-03-31");
    reconcile(&f, &operating);
    start_portfolio(&f, "march-cash", &[&operating]);
    let completed = ok(&f.book, &bank_step());
    let receipt = data(&completed).get("receipt").unwrap();
    let plan = portfolio_final_plan(&f, "before-new-bank");
    register_bank(&f, "LATE-PAYROLL", "1001");
    let before = head(&f.book);
    let (exit, refused) = run(
        &f.book,
        &[
            "close",
            "step",
            "--run",
            "march-cash",
            "--task",
            "finish",
            "--key",
            "after-new-bank",
            "--reason",
            "AuditComplete",
            "--dry-run",
            "--as",
            CONTROLLER,
            "--grant",
            "reconcile",
        ],
    );
    assert_eq!(exit, 6, "{}", refused.render());
    let (exit, refused) = run(
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
    assert_eq!(exit, 6, "{}", refused.render());
    let status = ok(&f.book, &["close", "status", "--run", "march-cash"]);
    assert_eq!(
        bank_task(data(&status).get("run").unwrap()).get("completion"),
        Some(receipt)
    );
    assert_eq!(
        data(&status).get("run").unwrap().get("complete"),
        Some(&Json::Bool(false))
    );
    let retried = ok(
        &f.book,
        &[
            "close",
            "step",
            "--run",
            "march-cash",
            "--task",
            "bank",
            "--as",
            CONTROLLER,
            "--yes",
        ],
    );
    assert_eq!(data(&retried).get("receipt"), Some(receipt));
    assert_eq!(
        data(&retried).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        head(&f.book),
        before,
        "inventory drift cannot close or rewrite completion"
    );
}
