//! Adjusted closes through the real CLI, including reopen and later clearance.

use super::*;

fn selector(posted: &Json, ordinal: u16) -> String {
    format!(
        "{}:{ordinal}:{}",
        text(data(posted), "vid"),
        text(data(posted), "entry_digest"),
    )
}

fn prepared() -> (Fixture, String, Json, Json, Json) {
    let f = Fixture::new();
    let sale = f.post("cleared-sale", "2026-03-10", "debit", "100.00", "CLEARED");
    let deposit = f.post("timing-deposit", "2026-03-12", "debit", "40.00", "DEPOSIT");
    let check = f.post("timing-check", "2026-03-13", "credit", "20.00", "CHECK");
    let imported = f.import("adjusted.csv", "csv", &format!(
        "{CSV_HEADER}1,BANK-ADJUSTED,USD,2026-03-15,0.00,100.00,2026-03-10,2026-03-10,CRDT,100.00,Private customer,CLEARED\n"
    ));
    let manifest = text(data(&imported), "manifest_oid").to_string();
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", &manifest]);
    confirm_selection(&f.book, &confirmation_args(&matched, 0, "cash-reviewer"));
    (f, manifest, sale, deposit, check)
}

fn adjusted_args(manifest: &str, reviewed: i128, selected: &[String]) -> Vec<String> {
    let mut args = reconciliation_args(manifest, reviewed);
    for item in selected {
        args.extend(["--outstanding".into(), item.clone()]);
    }
    args
}

#[test]
fn adjusted_close_preserves_selected_cash_legs_across_reopen_and_exact_retries() {
    let (f, manifest, _, deposit, check) = prepared();
    let reviewed = head(&f.book);
    let before = ok(&f.book, &["tb", "--as-of", "2026-03-15"]);
    let exact = reconciliation_args(&manifest, reviewed);
    assert_eq!(
        run_privileged(
            &f.book,
            &exact.iter().map(String::as_str).collect::<Vec<_>>()
        )
        .0,
        3
    );
    assert_eq!(head(&f.book), reviewed);

    let selections = [selector(&deposit, 0), selector(&check, 0)];
    let args = adjusted_args(&manifest, reviewed, &selections);
    let closed = reconcile_selection(&f.book, &args);
    let claim = data(&closed).get("reconciliation").unwrap();
    assert_eq!(text(claim, "scope"), "outstanding_adjusted_statement_close");
    assert_eq!(text(claim, "cash_balance"), "120.00 USD");
    assert_eq!(text(claim, "outstanding_total"), "20.00 USD");
    assert_eq!(text(claim, "adjusted_cash_balance"), "100.00 USD");
    assert_eq!(text(claim, "statement_balance"), "100.00 USD");
    assert_eq!(integer(claim, "recorded_at"), reviewed + 1);
    let selected = rows(claim, "outstanding");
    assert_eq!(selected.len(), 2);
    for (posted, kind, amount) in [
        (&deposit, "DepositInTransit", "40.00 USD"),
        (&check, "UnclearedPayment", "-20.00 USD"),
    ] {
        let row = selected
            .iter()
            .find(|row| text(row.get("entry_ref").unwrap(), "vid") == text(data(posted), "vid"))
            .unwrap();
        assert_eq!(text(row, "kind"), kind);
        assert_eq!(text(row, "signed_amount"), amount);
        assert_eq!(integer(row, "leg_ordinal"), 0);
        assert_eq!(
            text(row.get("entry_ref").unwrap(), "entry_digest"),
            text(data(posted), "entry_digest")
        );
    }
    let after = ok(&f.book, &["tb", "--as-of", "2026-03-15"]);
    assert_eq!(
        data(&before).get("rows"),
        data(&after).get("rows"),
        "closing posts no money"
    );
    let status = ok(&f.book, &["bank", "reconciliation", "--import", &manifest]);
    assert_eq!(integer(data(&status), "drifted_count"), 0);
    assert_eq!(
        reconciliation_state(&status).get("historical_claim_verified"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        reconciliation_state(&status).get("reconciliation"),
        Some(claim)
    );
    assert!(!status.render().contains("Private customer"));

    let after_close = head(&f.book);
    let reordered = adjusted_args(
        &manifest,
        reviewed,
        &[selections[1].clone(), selections[0].clone()],
    );
    let retry = reconcile_selection(&f.book, &reordered);
    let retry = data(&retry).get("reconciliation").unwrap();
    assert_eq!(retry.get("already_recorded"), Some(&Json::Bool(true)));
    for key in [
        "attestation_vid",
        "attestation_digest",
        "recorded_at",
        "outstanding",
        "cash_fold_digest",
    ] {
        assert_eq!(retry.get(key), claim.get(key), "{key}");
    }
    assert_eq!(head(&f.book), after_close);
    for changed in [
        exact,
        adjusted_args(&manifest, reviewed, &[selections[0].clone()]),
    ] {
        let (exit, refused) = run_privileged(
            &f.book,
            &changed.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        assert_eq!(exit, 6, "{refused:?}");
        assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-030");
        assert_eq!(
            head(&f.book),
            after_close,
            "changing the selected set is not an exact retry"
        );
    }
}

#[test]
fn later_clearance_and_a_successor_exact_close_preserve_the_adjusted_history() {
    let f = Fixture::new();
    f.post("first-cash", "2026-03-10", "debit", "100.00", "FIRST");
    let deposit = f.post("late-deposit", "2026-03-14", "debit", "20.00", "INTRANSIT");
    let first = f.import("first.csv", "csv", &format!(
        "{CSV_HEADER}1,BANK-CLEARANCE,USD,2026-03-15,0.00,100.00,2026-03-10,2026-03-10,CRDT,100.00,Customer,FIRST\n"
    ));
    let first_oid = text(data(&first), "manifest_oid");
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", first_oid]);
    confirm_selection(&f.book, &confirmation_args(&matched, 0, "first-confirmer"));
    let args = adjusted_args(first_oid, head(&f.book), &[selector(&deposit, 0)]);
    let closed = reconcile_selection(&f.book, &args);
    let claim = data(&closed).get("reconciliation").unwrap();

    let path = f.file("next.csv", &format!(
        "{CSV_HEADER}2,BANK-CLEARANCE,USD,2026-03-20,100.00,120.00,2026-03-16,2026-03-16,CRDT,20.00,Customer,INTRANSIT\n"
    ));
    let next = ok_privileged(
        &f.book,
        &[
            "bank",
            "import",
            &path,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--previous-import",
            first_oid,
        ],
    );
    let next_oid = text(data(&next), "manifest_oid");
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", next_oid]);
    confirm_selection(&f.book, &confirmation_args(&matched, 0, "next-confirmer"));
    let status = ok(&f.book, &["bank", "reconciliation", "--import", first_oid]);
    assert_eq!(integer(data(&status), "drifted_count"), 0);
    assert_eq!(
        reconciliation_state(&status).get("historical_claim_verified"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        reconciliation_state(&status).get("reconciliation"),
        Some(claim)
    );

    let next_close = reconcile_selection(&f.book, &reconciliation_args(next_oid, head(&f.book)));
    let next_claim = data(&next_close).get("reconciliation").unwrap();
    assert_eq!(text(next_claim, "scope"), "exact_statement_close");
    assert_eq!(text(next_claim, "cash_balance"), "120.00 USD");
    assert_eq!(text(next_claim, "outstanding_total"), "0.00 USD");
    assert!(rows(next_claim, "outstanding").is_empty());
    let before = head(&f.book);
    let retry = reconcile_selection(&f.book, &args);
    assert_eq!(
        data(&retry)
            .get("reconciliation")
            .unwrap()
            .get("outstanding"),
        claim.get("outstanding")
    );
    assert_eq!(head(&f.book), before);
}

#[test]
fn invalid_outstanding_selections_leave_the_book_and_close_inventory_unchanged() {
    let (f, manifest, sale, deposit, check) = prepared();
    let later = f.post("too-late", "2026-03-16", "debit", "40.00", "TOOLATE");
    let reviewed = head(&f.book);
    let bad_digest = format!("{}:0:{}", text(data(&deposit), "vid"), "00".repeat(32));
    for item in [
        selector(&sale, 0),
        selector(&deposit, 1),
        selector(&deposit, 2),
        selector(&later, 0),
        bad_digest,
    ] {
        let args = adjusted_args(&manifest, reviewed, &[item, selector(&check, 0)]);
        let (exit, refused) = run_privileged(
            &f.book,
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        assert_eq!(exit, 3, "{refused:?}");
        assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-168");
        assert_eq!(head(&f.book), reviewed);
    }
    let duplicate = adjusted_args(
        &manifest,
        reviewed,
        &[selector(&deposit, 0), selector(&deposit, 0)],
    );
    assert_eq!(
        run_privileged(
            &f.book,
            &duplicate.iter().map(String::as_str).collect::<Vec<_>>()
        )
        .0,
        2
    );
    let amount = format!("{}:10.00 USD", selector(&deposit, 0));
    let injected = adjusted_args(&manifest, reviewed, &[amount]);
    assert_eq!(
        run_privileged(
            &f.book,
            &injected.iter().map(String::as_str).collect::<Vec<_>>()
        )
        .0,
        2
    );
    assert_eq!(
        run(
            &f.book,
            &[
                "bank",
                "reconciliation",
                "--import",
                &manifest,
                "--outstanding",
                &selector(&deposit, 0)
            ]
        )
        .0,
        2
    );
    assert_eq!(head(&f.book), reviewed);
    let status = ok(&f.book, &["bank", "reconciliation", "--import", &manifest]);
    assert_eq!(integer(data(&status), "reconciliation_count"), 0);
    assert_eq!(data(&status).get("reconciled_through"), Some(&Json::Null));
}

#[test]
fn offsetting_timing_items_remain_visible_even_when_book_and_bank_totals_already_tie() {
    let f = Fixture::new();
    f.post("zero-sum-sale", "2026-03-10", "debit", "100.00", "CASH");
    let deposit = f.post(
        "zero-sum-deposit",
        "2026-03-12",
        "debit",
        "25.00",
        "UNCLEAREDIN",
    );
    let check = f.post(
        "zero-sum-check",
        "2026-03-13",
        "credit",
        "25.00",
        "UNCLEAREDOUT",
    );
    let imported = f.import("zero-sum.csv", "csv", &format!(
        "{CSV_HEADER}1,BANK-ZERO-SUM,USD,2026-03-15,0.00,100.00,2026-03-10,2026-03-10,CRDT,100.00,Customer,CASH\n"
    ));
    let manifest = text(data(&imported), "manifest_oid");
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    confirm_selection(
        &f.book,
        &confirmation_args(&matched, 0, "zero-sum-confirmer"),
    );
    let args = adjusted_args(
        manifest,
        head(&f.book),
        &[selector(&deposit, 0), selector(&check, 0)],
    );
    let closed = reconcile_selection(&f.book, &args);
    let claim = data(&closed).get("reconciliation").unwrap();
    assert_eq!(text(claim, "scope"), "outstanding_adjusted_statement_close");
    assert_eq!(text(claim, "cash_balance"), "100.00 USD");
    assert_eq!(text(claim, "outstanding_total"), "0.00 USD");
    assert_eq!(rows(claim, "outstanding").len(), 2);
    let status = ok(&f.book, &["bank", "reconciliation", "--import", manifest]);
    assert_eq!(
        rows(
            reconciliation_state(&status).get("reconciliation").unwrap(),
            "outstanding"
        )
        .len(),
        2
    );
}
