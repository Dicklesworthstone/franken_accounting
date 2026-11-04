//! Typed differences through saved plans, reopened books and exact reversals.

use super::*;
use fa_cli::json::{obj, s};

fn principal_open(f: &Fixture, account: &str, source: &str) -> String {
    let report = data(&f.ok(&["open-items", "--account", account]));
    let item = rows(&report, "items")
        .iter()
        .find(|item| text(item, "entry") == source)
        .expect("retained source item");
    text(item, "open")
}

fn receipt<'a>(f: &'a Fixture, target: &'a str, number: &'a str) -> Vec<&'a str> {
    vec![
        "receipt",
        "--party",
        "C-1",
        "--number",
        number,
        "--date",
        "2026-03-20",
        "--cash",
        "1000",
        "--receivable",
        "1200",
        "--amount",
        "97.00 USD",
        "--applies",
        target,
        "--evidence",
        &f.evidence,
    ]
}

#[test]
fn receipt_differences_survive_plan_commit_retry_reopen_and_reversal_chain() {
    let f = Fixture::new();
    f.register("AR", "1200", "receivables");
    let invoice = text(&data(&f.invoice("C-1", "DIFF-INV", "100.00 USD")), "vid");
    let target = format!("{invoice}:0=100.00 USD");
    let mut args = receipt(&f, &target, "DIFF-RECEIPT");
    args.extend([
        "--difference",
        r#"kind=Discount account=6000 amount="2.00 USD""#,
        "--difference",
        r#"kind=BankCharge account=6000 amount="1.00 USD""#,
    ]);
    let before = f.head();
    let path = f.dir.join("classified-receipt.plan");
    let path = path.to_str().unwrap();
    let mut review = args.clone();
    review.extend(["--dry-run", "--plan-out", path]);
    let plan = data(&f.ok(&review));
    assert_eq!(f.head(), before, "review never publishes a payment");
    let classification = plan.get("application").unwrap().clone();
    assert_eq!(text(&classification, "direction"), "Receipt");
    let differences = rows(&classification, "differences");
    assert_eq!(differences.len(), 2);
    assert_eq!(text(&differences[0], "kind"), "Discount");
    assert_eq!(text(&differences[1], "kind"), "BankCharge");
    let legs = rows(&plan, "legs");
    assert_eq!(legs.len(), 4);
    assert_eq!(text(&legs[0], "amount"), "97.00 USD");
    assert_eq!(text(&legs[1], "amount"), "100.00 USD");
    assert_eq!(text(&legs[2], "amount"), "2.00 USD");
    assert_eq!(text(&legs[3], "amount"), "1.00 USD");

    let posted = data(&f.ok(&["commit", "--plan", path]));
    let vid = text(&posted, "vid");
    let after = f.head();
    assert_eq!(principal_open(&f, "1200", &invoice), "0.00 USD");
    let shown = data(&f.ok(&["entry", "show", &vid]));
    assert_eq!(shown.get("application"), Some(&classification));
    assert_eq!(text(&data(&f.ok(&args)), "vid"), vid);
    assert_eq!(text(&data(&f.ok(&["commit", "--plan", path])), "vid"), vid);
    assert_eq!(
        f.head(),
        after,
        "both exact retry routes retain one publication"
    );

    let undone = text(
        &data(&f.ok(&[
            "reverse",
            &vid,
            "--effective",
            "2026-03-22",
            "--reason",
            "WrongAccount",
            "--evidence",
            &f.evidence,
        ])),
        "vid",
    );
    assert_eq!(principal_open(&f, "1200", &invoice), "100.00 USD");
    assert_eq!(
        data(&f.ok(&["entry", "show", &undone])).get("application"),
        Some(&classification),
    );
    f.ok(&[
        "reverse",
        &undone,
        "--effective",
        "2026-03-23",
        "--reason",
        "WrongAccount",
        "--evidence",
        &f.evidence,
    ]);
    assert_eq!(principal_open(&f, "1200", &invoice), "0.00 USD");
    assert_eq!(
        f.verify("AR", None).get("reconciled"),
        Some(&Json::Bool(true))
    );
}

#[test]
fn outgoing_bank_fees_reduce_principal_while_discounts_increase_it() {
    let f = Fixture::new();
    f.register("AP", "2000", "payables");
    let bill = text(
        &data(&f.ok(&[
            "bill",
            "--party",
            "V-1",
            "--number",
            "DIFF-BILL",
            "--date",
            "2026-03-14",
            "--payable",
            "2000",
            "--expense",
            "6000",
            "--line",
            r#"amount="100.00 USD""#,
            "--evidence",
            &f.evidence,
        ])),
        "vid",
    );
    let applied = format!("{bill}:0=100.00 USD");
    let args = [
        "payment",
        "--party",
        "V-1",
        "--number",
        "DIFF-PAYMENT",
        "--date",
        "2026-03-20",
        "--cash",
        "1000",
        "--payable",
        "2000",
        "--amount",
        "99.00 USD",
        "--applies",
        &applied,
        "--difference",
        r#"kind=Discount account=6000 amount="2.00 USD""#,
        "--difference",
        r#"kind=BankCharge account=6000 amount="1.00 USD""#,
        "--evidence",
        &f.evidence,
    ];
    let vid = text(&data(&f.ok(&args)), "vid");
    assert_eq!(principal_open(&f, "2000", &bill), "0.00 USD");
    let shown = data(&f.ok(&["entry", "show", &vid]));
    assert_eq!(
        text(shown.get("application").unwrap(), "direction"),
        "Payment"
    );
    let legs = rows(&shown, "legs");
    for (leg, side, amount) in [
        (&legs[0], "credit", "99.00 USD"),
        (&legs[1], "debit", "100.00 USD"),
        (&legs[2], "credit", "2.00 USD"),
        (&legs[3], "debit", "1.00 USD"),
    ] {
        assert_eq!(text(leg, "side"), side);
        assert_eq!(text(leg, "amount"), amount);
    }
    assert_eq!(
        f.verify("AP", None).get("reconciled"),
        Some(&Json::Bool(true))
    );
}

#[test]
fn malformed_or_unexplained_differences_publish_nothing_and_shortpay_stays_open() {
    let f = Fixture::new();
    let invoice = text(
        &data(&f.invoice("C-1", "DIFF-NEGATIVE", "100.00 USD")),
        "vid",
    );
    let explicit = format!("{invoice}:0=100.00 USD");
    let before = f.head();
    for difference in [
        r#"account=6000 amount="3.00 USD""#,
        r#"kind=Discount amount="3.00 USD""#,
        r#"kind=Unknown account=6000 amount="3.00 USD""#,
        r#"kind=ShortPay account=6000 amount="3.00 USD""#,
        r#"kind=RealizedFx account=6000 amount="3.00 USD""#,
        r#"kind=Discount account=6000 amount="0.00 USD""#,
        r#"kind=Discount account=6000 amount="-3.00 USD""#,
        r#"kind=Discount account=6000 amount="3.00 EUR""#,
        r#"kind=Discount account=1000 amount="3.00 USD""#,
        r#"kind=Discount account=1200 amount="3.00 USD""#,
        r#"kind=Discount account=6000 amount="2.00 USD""#,
        r#"kind=Discount kind=Writeoff account=6000 amount="3.00 USD""#,
        r#"kind=Discount account=6000 amount="3.00 USD" guessed=true"#,
    ] {
        let mut args = receipt(&f, &explicit, "DIFF-REFUSED");
        args.extend(["--difference", difference]);
        let (status, output) = f.run(&args);
        assert_eq!(status, 2, "{difference}: {output}");
        assert_eq!(f.head(), before);
    }
    let mut implicit = receipt(&f, &invoice, "DIFF-IMPLICIT");
    implicit.extend([
        "--difference",
        r#"kind=Discount account=6000 amount="3.00 USD""#,
    ]);
    assert_eq!(
        f.run(&implicit).0,
        2,
        "classified applications require explicit amounts"
    );
    assert_eq!(f.head(), before);

    // A short receipt is still an ordinary partial application. It cannot
    // erase the remaining principal under an invented ShortPay reduction.
    f.ok(&receipt(&f, &invoice, "DIFF-PARTIAL"));
    assert_eq!(principal_open(&f, "1200", &invoice), "3.00 USD");
    let remaining = format!("{invoice}:0=3.00 USD");
    let mut over = receipt(&f, &remaining, "DIFF-OVER");
    over.extend([
        "--difference",
        r#"kind=Writeoff account=6000 amount="3.00 USD""#,
    ]);
    let before = f.head();
    assert_eq!(
        f.run(&over).0,
        2,
        "declared principal must equal explicit applications"
    );
    assert_eq!(f.head(), before);
}

#[test]
fn raw_post_application_classification_is_kernel_checked_and_identity_bound() {
    let f = Fixture::new();
    let invoice = text(&data(&f.invoice("C-1", "DIFF-RAW", "100.00 USD")), "vid");
    let application = |direction: &str, kind: &str| {
        obj(vec![
            ("direction", s(direction)),
            ("cash_ordinal", Json::Int(0)),
            ("applying_ordinal", Json::Int(1)),
            (
                "differences",
                Json::Arr(vec![obj(vec![
                    ("leg_ordinal", Json::Int(2)),
                    ("kind", s(kind)),
                ])]),
            ),
        ])
    };
    let intent = |direction: &str, kind: &str| {
        obj(vec![
            ("effective_date", s("2026-03-20")),
            ("idempotency_key", s("classified-raw-post")),
            (
                "description",
                s("Explicit settlement with retained classification"),
            ),
            ("application", application(direction, kind)),
            (
                "legs",
                Json::Arr(vec![
                    obj(vec![
                        ("side", s("debit")),
                        ("account", s("1000")),
                        ("amount", s("97.00 USD")),
                    ]),
                    obj(vec![
                        ("side", s("credit")),
                        ("account", s("1200")),
                        ("amount", s("100.00 USD")),
                        ("party", s("C-1")),
                        (
                            "settles",
                            Json::Arr(vec![obj(vec![
                                ("entry", s(&invoice)),
                                ("ordinal", Json::Int(0)),
                                ("amount", s("100.00 USD")),
                            ])]),
                        ),
                    ]),
                    obj(vec![
                        ("side", s("debit")),
                        ("account", s("6000")),
                        ("amount", s("3.00 USD")),
                    ]),
                ]),
            ),
        ])
    };
    let before = f.head();
    let wrong = f.file(
        "application-wrong-direction.json",
        &intent("Payment", "BankCharge").render(),
    );
    let (status, output) = f.run(&["post", "--intent", &wrong, "--evidence", &f.evidence]);
    assert_eq!(status, 3, "{output}");
    assert!(output.contains("FA-REF-071"));
    assert_eq!(f.head(), before);

    let valid = f.file(
        "application-writeoff.json",
        &intent("Receipt", "Writeoff").render(),
    );
    let posted = data(&f.ok(&["post", "--intent", &valid, "--evidence", &f.evidence]));
    assert_eq!(principal_open(&f, "1200", &invoice), "0.00 USD");
    let shown = data(&f.ok(&["entry", "show", &text(&posted, "vid")]));
    assert_eq!(
        text(
            &rows(shown.get("application").unwrap(), "differences")[0],
            "kind"
        ),
        "Writeoff"
    );
    let after = f.head();
    let changed = f.file(
        "application-reclassified.json",
        &intent("Receipt", "Discount").render(),
    );
    let (status, output) = f.run(&["post", "--intent", &changed, "--evidence", &f.evidence]);
    assert_eq!(status, 6, "{output}");
    assert!(output.contains("FA-REF-009"));
    assert_eq!(
        f.head(),
        after,
        "a kind change is not the original idempotent request"
    );
}
