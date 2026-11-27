//! Credit-card reconciliation uses the original signed statement balance.
//! Charges, payments and overpayments share the native confirmation and close
//! laws; a credit-normal chart leaf never supplies an implicit sign reversal.

use super::*;

fn card_fixture() -> Fixture {
    Fixture::with_chart(
        r#"{"accounts":[{"code":"1000","name":"Credit card","type":"Liability","unit":"USD"},{"code":"1010","name":"Cash","type":"Asset","unit":"USD"},{"code":"6000","name":"Expenses","type":"Expense","unit":"USD"}]}"#,
    )
}

fn card_post(
    f: &Fixture,
    key: &str,
    date: &str,
    side: &str,
    amount: &str,
    contra: &str,
    reference: &str,
) -> Json {
    let other_side = if side == "credit" { "debit" } else { "credit" };
    let path = f.file(
        &format!("{key}.json"),
        &format!(
            r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":[{{"side":"{side}","account":"1000","amount":"{amount} USD","memo":"{reference}"}},{{"side":"{other_side}","account":"{contra}","amount":"{amount} USD"}}]}}"#
        ),
    );
    ok(
        &f.book,
        &["post", "--intent", &path, "--evidence", &f.evidence],
    )
}

fn card_statement(
    sequence: u64,
    opening: &str,
    closing: &str,
    date: &str,
    transactions: &[(&str, &str, &str)],
) -> String {
    let mut lines = String::new();
    for (booked, amount, reference) in transactions {
        lines.push_str(&format!(
            "<STMTTRN><DTPOSTED>{booked}</DTPOSTED><TRNAMT>{amount}</TRNAMT><FITID>{reference}</FITID></STMTTRN>"
        ));
    }
    format!(
        "<OFX><CREDITCARDMSGSRSV1><CCSTMTTRNRS><TRNUID>{sequence}</TRNUID><CCSTMTRS><CURDEF>USD</CURDEF><CCACCTFROM><ACCTID>CARD-123</ACCTID></CCACCTFROM><OPENBAL>{opening}</OPENBAL><BANKTRANLIST>{lines}</BANKTRANLIST><LEDGERBAL><BALAMT>{closing}</BALAMT><DTASOF>{date}</DTASOF></LEDGERBAL></CCSTMTRS></CCSTMTTRNRS></CREDITCARDMSGSRSV1></OFX>"
    )
}

#[test]
fn credit_card_statements_reconcile_signed_debt_and_overpayments() {
    let f = card_fixture();
    ok(&f.book, &["period", "open", "FY2026-P02"]);
    card_post(
        &f,
        "card-opening",
        "2026-02-28",
        "credit",
        "500.00",
        "6000",
        "OPENING",
    );
    card_post(
        &f,
        "card-purchase",
        "2026-03-10",
        "credit",
        "125.00",
        "6000",
        "PURCHASE",
    );
    card_post(
        &f,
        "card-payment",
        "2026-03-15",
        "debit",
        "200.00",
        "1010",
        "PAYMENT",
    );
    // Already recorded later activity cannot change the earlier close.
    card_post(
        &f,
        "card-later",
        "2026-03-25",
        "credit",
        "50.00",
        "6000",
        "LATER",
    );
    let source = card_statement(
        1,
        "-500.00",
        "-425.00",
        "2026-03-20",
        &[
            ("2026-03-10", "-125.00", "PURCHASE"),
            ("2026-03-15", "200.00", "PAYMENT"),
        ],
    );
    let imported = f.import("card.ofx", "ofx", &source);
    let manifest = text(data(&imported), "manifest_oid");
    assert_eq!(text(data(&imported), "closing_balance"), "-425.00 USD");
    let before = head(&f.book);
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    let report = data(&matched);
    assert_eq!(integer(report, "proposed_count"), 2);
    assert_eq!(integer(report, "unmatched_count"), 0);
    assert_eq!(text(report, "book_closing_balance"), "-425.00 USD");
    assert_eq!(text(report, "closing_difference"), "0.00 USD");
    assert_eq!(text(&rows(report, "proposals")[0], "direction"), "outflow");
    assert_eq!(text(&rows(report, "proposals")[1], "direction"), "inflow");
    assert_progress(
        &matched,
        [
            ("0.00", "0.00"),
            ("0.00", "0.00"),
            ("200.00", "125.00"),
            ("200.00", "125.00"),
            ("0.00", "0.00"),
            ("0.00", "0.00"),
        ],
        2,
        false,
        true,
    );
    assert_eq!(head(&f.book), before);
    for index in 0..2 {
        confirm_selection(
            &f.book,
            &confirmation_args(&matched, index, "card-reviewer"),
        );
    }
    let confirmed = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    assert_progress(
        &confirmed,
        [
            ("200.00", "125.00"),
            ("0.00", "0.00"),
            ("0.00", "0.00"),
            ("0.00", "0.00"),
            ("0.00", "0.00"),
            ("0.00", "0.00"),
        ],
        0,
        true,
        true,
    );
    let before_tb = ok(&f.book, &["tb", "--as-of", "2026-03-20"]);
    let args = reconciliation_args(manifest, head(&f.book));
    let closed = reconcile_selection(&f.book, &args);
    let original = data(&closed).get("reconciliation").unwrap();
    assert_eq!(text(original, "cash_balance"), "-425.00 USD");
    assert_eq!(rows(original, "matches").len(), 2);
    let closed_at = head(&f.book);
    let after_tb = ok(&f.book, &["tb", "--as-of", "2026-03-20"]);
    assert_eq!(data(&after_tb).get("rows"), data(&before_tb).get("rows"));
    let status = ok(&f.book, &["bank", "reconciliation", "--import", manifest]);
    assert_eq!(integer(data(&status), "drifted_count"), 0);
    assert_eq!(
        reconciliation_state(&status).get("historical_claim_verified"),
        Some(&Json::Bool(true))
    );
    let retry = reconcile_selection(&f.book, &args);
    let retry = data(&retry).get("reconciliation").unwrap();
    assert_eq!(retry.get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(
        retry.get("attestation_digest"),
        original.get("attestation_digest")
    );
    assert_eq!(head(&f.book), closed_at);

    // Liability closes protect backdated postings under the same native lock.
    let late = f.file(
        "late-card.json",
        r#"{"effective_date":"2026-03-11","idempotency_key":"late-card","legs":[{"side":"credit","account":"1000","amount":"1.00 USD"},{"side":"debit","account":"6000","amount":"1.00 USD"}]}"#,
    );
    let (exit, refused) = run(
        &f.book,
        &["post", "--intent", &late, "--evidence", &f.evidence],
    );
    assert_eq!(exit, 7, "{refused:?}");
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-011");
    assert!(text(data(&refused), "message").contains("reconcile"));
    assert_eq!(head(&f.book), closed_at);

    // An overpayment leaves a positive balance on the same credit-normal
    // liability. Neither matching nor closing may force it back to negative.
    card_post(
        &f,
        "card-overpayment",
        "2026-03-30",
        "debit",
        "575.00",
        "1010",
        "OVERPAY",
    );
    let source = card_statement(
        2,
        "-425.00",
        "100.00",
        "2026-03-31",
        &[
            ("2026-03-25", "-50.00", "LATER"),
            ("2026-03-30", "575.00", "OVERPAY"),
        ],
    );
    let path = f.file("card-next.ofx", &source);
    let next = ok_privileged(
        &f.book,
        &[
            "bank",
            "import",
            &path,
            "--bank-format",
            "ofx",
            "--account",
            "1000",
            "--previous-import",
            manifest,
        ],
    );
    let next_manifest = text(data(&next), "manifest_oid");
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", next_manifest]);
    assert_eq!(integer(data(&matched), "proposed_count"), 2);
    assert_eq!(text(data(&matched), "book_closing_balance"), "100.00 USD");
    assert_eq!(text(data(&matched), "closing_difference"), "0.00 USD");
    for index in 0..2 {
        confirm_selection(
            &f.book,
            &confirmation_args(&matched, index, "card-reviewer"),
        );
    }
    let next_args = reconciliation_args(next_manifest, head(&f.book));
    let closed = reconcile_selection(&f.book, &next_args);
    assert_eq!(
        text(data(&closed).get("reconciliation").unwrap(), "cash_balance"),
        "100.00 USD"
    );
    let original_status = ok(&f.book, &["bank", "reconciliation", "--import", manifest]);
    assert_eq!(integer(data(&original_status), "drifted_count"), 0);
    assert_eq!(
        text(reconciliation_state(&original_status), "cash_balance"),
        "-425.00 USD"
    );
    ok(&f.book, &["verify", "registers", "--fiscal-year", "2026"]);
}

#[test]
fn credit_card_reconciliation_never_guesses_a_source_polarity() {
    let f = card_fixture();
    card_post(
        &f,
        "card-charge",
        "2026-03-10",
        "credit",
        "10.00",
        "6000",
        "CHARGE",
    );
    // This source is internally balanced, but its positive transaction has
    // the wrong bank direction for the actual credit to the liability.
    let source = card_statement(
        1,
        "0.00",
        "10.00",
        "2026-03-31",
        &[("2026-03-10", "10.00", "CHARGE")],
    );
    let imported = f.import("wrong-polarity.ofx", "ofx", &source);
    let manifest = text(data(&imported), "manifest_oid");
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    assert_eq!(integer(data(&matched), "proposed_count"), 0);
    assert_eq!(integer(data(&matched), "unmatched_count"), 1);
    assert_eq!(text(data(&matched), "book_closing_balance"), "-10.00 USD");
    assert_eq!(text(data(&matched), "closing_difference"), "20.00 USD");
    let before = head(&f.book);
    let args = reconciliation_args(manifest, before);
    let (exit, refused) = run_privileged(
        &f.book,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(exit, 3, "{refused:?}");
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-168");
    assert!(text(data(&refused), "message").contains("active confirmation"));
    assert_eq!(head(&f.book), before);

    // Correct line polarity still cannot justify a different opening debt.
    let source = card_statement(
        2,
        "20.00",
        "10.00",
        "2026-03-31",
        &[("2026-03-10", "-10.00", "CHARGE")],
    );
    let imported = f.import("wrong-opening.ofx", "ofx", &source);
    let manifest = text(data(&imported), "manifest_oid");
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    assert_eq!(integer(data(&matched), "proposed_count"), 1);
    confirm_selection(&f.book, &confirmation_args(&matched, 0, "card-reviewer"));
    let before = head(&f.book);
    let args = reconciliation_args(manifest, before);
    let (exit, refused) = run_privileged(
        &f.book,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(exit, 3, "{refused:?}");
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-168");
    assert!(text(data(&refused), "message").contains("cumulative posted cash"));
    assert_eq!(head(&f.book), before);
    let status = ok(&f.book, &["bank", "reconciliation", "--import", manifest]);
    assert_eq!(integer(data(&status), "reconciliation_count"), 0);
}

#[test]
fn credit_card_currency_mismatch_publishes_no_import() {
    let f = Fixture::with_chart(
        r#"{"accounts":[{"code":"1000","name":"Euro card","type":"Liability","unit":"EUR"},{"code":"6000","name":"Expenses","type":"Expense","unit":"USD"}]}"#,
    );
    let source = card_statement(
        1,
        "0.00",
        "-10.00",
        "2026-03-31",
        &[("2026-03-10", "-10.00", "CHARGE")],
    );
    let path = f.file("wrong-currency.ofx", &source);
    let before = head(&f.book);
    let (exit, refused) = run(
        &f.book,
        &[
            "bank",
            "import",
            &path,
            "--bank-format",
            "ofx",
            "--account",
            "1000",
        ],
    );
    assert_eq!(exit, 3, "{refused:?}");
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-003");
    assert_eq!(head(&f.book), before);
}
