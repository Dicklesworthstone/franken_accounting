//! Real customer/vendor workflows separate bank fees and reductions from FX.

use super::*;

fn adjustment_accounts(f: &AllocatedFixture) {
    let chart = f.f.file(
        "cash-adjustments.json",
        r#"{"accounts":[{"code":"6300","name":"Settlement discounts","type":"Expense","unit":"USD"},{"code":"6310","name":"Settlement writeoffs","type":"Expense","unit":"USD"},{"code":"6320","name":"Bank charges","type":"Expense","unit":"USD"}]}"#,
    );
    ok(&f.f.book, &["chart", "import", &chart]);
}

fn with_adjustments(mut args: Vec<String>) -> Vec<String> {
    for difference in [
        "kind=Discount account=6300 amount=\"2.00 USD\"",
        "kind=Writeoff account=6310 amount=\"0.50 USD\"",
        "kind=BankCharge account=6320 amount=\"1.25 USD\"",
    ] {
        args.extend(["--difference".into(), difference.into()]);
    }
    args
}

fn net_cash_workflow(liability: bool, allocated: bool) {
    let f = AllocatedFixture::new(liability);
    adjustment_accounts(&f);
    if allocated {
        let closing = f.f.closing_rate(12);
        let rate = format!("D:{}", text(data(&closing), "oid"));
        ok(
            &f.f.book,
            &[
                "fx",
                "revalue",
                "--period",
                PERIOD,
                "--account",
                f.control(),
                "--rate",
                &rate,
                "--key",
                "net-cash-closing",
                "--allocate-open-items",
                "--yes",
            ],
        );
    }
    let sign = if liability { -1 } else { 1 };
    let cash = if liability {
        "128.75 USD"
    } else {
        "126.25 USD"
    };
    let law = if allocated {
        "SettlementAllocatedCarrying"
    } else {
        "SettlementCarryingBasis"
    };
    // Unexplained net cash cannot become a silently larger FX loss.
    f.refused_cash(&f.cash_args("undeclared-charge", "100.00 EUR", cash, law));
    let args = with_adjustments(f.cash_args("net-cash", "100.00 EUR", cash, law));
    let plan_path = f.f.path("net-cash.plan");
    let mut review_args = args.clone();
    review_args.extend(["--dry-run".into(), "--plan-out".into(), plan_path.clone()]);
    let before = head(&f.f.book);
    let reviewed = f.cash(&review_args);
    assert_eq!(text(&reviewed, "event"), "plan");
    assert_eq!(head(&f.f.book), before);
    let [classification] = rows(data(&reviewed), "fx_differences") else {
        panic!("one explicitly classified foreign application");
    };
    assert_eq!(integer(classification, "applying_ordinal"), 0);
    let kinds: Vec<_> = rows(classification, "differences")
        .iter()
        .map(|difference| text(difference, "kind"))
        .collect();
    assert_eq!(kinds, ["Discount", "Writeoff", "BankCharge"]);
    let plan = PostPlan::decode(&std::fs::read(&plan_path).unwrap()).unwrap();
    let terms = plan.proposal().fx_settlement_terms().unwrap().unwrap();
    assert!(plan.proposal().application_terms().unwrap().is_none());
    let posted = f.f.commit(&plan_path);
    let vid = text(data(&posted), "vid");
    let entry = f.f.entry(vid);
    assert_eq!(&entry.proposal, plan.proposal());
    let shown = ok(&f.f.book, &["entry", "show", vid]);
    assert_eq!(
        data(&shown).get("fx_differences"),
        data(&reviewed).get("fx_differences")
    );
    let stock = f.stock("2026-02-28");
    assert_eq!(net(&stock, f.control()), 0);
    assert_eq!(net(&stock, "3900"), 0, "conversion closes exactly");
    assert_eq!(
        net(&stock, "1100"),
        sign * if liability { 12_875 } else { 12_625 }
    );
    assert_eq!(net(&stock, "6300"), sign * 200);
    assert_eq!(net(&stock, "6310"), sign * 50);
    assert_eq!(
        net(&stock, "6320"),
        125,
        "bank charges are an expense in either direction"
    );
    assert_eq!(
        net(&stock, "4900"),
        -sign * 2_000,
        "FX uses gross quote less historical cost"
    );
    if allocated {
        assert_eq!(net(&stock, f.valuation()), 0);
        assert_eq!(net(&stock, f.unrealized()), 0);
        let basis = release(&entry);
        assert_eq!(basis.items[0].historical_relief.mantissa, 11_000);
        assert_eq!(basis.items[0].total_relief.mantissa, 12_000);
    }
    if allocated && !liability {
        let certificate_path = f.f.path("net-cash.cert");
        let (status, events) = run_many(
            &f.f.book,
            &[
                "tb",
                "--functional",
                "--as-of",
                "2026-02-28",
                "--certificate-out",
                &certificate_path,
            ],
            None,
        );
        assert_eq!(status, 0, "{events:?}");
        let certificate =
            fa::ReportCertificate::decode(&std::fs::read(&certificate_path).unwrap()).unwrap();
        let checkpoint = ok(&f.f.book, &["checkpoint", "create", "--grant", "witness"]);
        let exported = ok(
            &f.f.book,
            &[
                "bundle",
                "produce",
                "--certificate",
                &certificate_path,
                "--state",
                text(data(&checkpoint), "oid"),
            ],
        );
        let exported = data(&exported);
        let key: [u8; 32] = decode_hex(text(exported, "checkpoint_public_key"))
            .try_into()
            .unwrap();
        let verified = fa_verify::report::verify_report_expected(
            &decode_hex(text(exported, "bytes")),
            &[key],
            None,
            Some(&decode_hex(text(exported, "receipt"))),
            Some(&certificate.digest),
        )
        .unwrap();
        assert_eq!(
            verified.output, certificate.output,
            "real CLI effects independently reproduce the retained functional report"
        );
    }
    let after_post = head(&f.f.book);
    assert_eq!(
        data(&f.f.commit(&plan_path)).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    // Direct retries use fa post's recorded event; saved-plan commits above
    // carry the separate already_recorded field.
    let retried = f.cash(&args);
    assert_eq!(text(&retried, "event"), "recorded");
    assert_eq!(text(data(&retried), "vid"), vid);
    assert_eq!(f.f.entry(vid), entry);
    assert_eq!(head(&f.f.book), after_post);
    let undone = ok(
        &f.f.book,
        &[
            "reverse",
            vid,
            "--reason",
            "WrongAmount",
            "--effective",
            "2026-02-05",
            "--evidence",
            &f.f.evidence,
            "--grant",
            "read",
            "--yes",
        ],
    );
    let undo = f.f.entry(text(data(&undone), "vid"));
    assert_eq!(undo.proposal.fx_settlement_terms().unwrap().unwrap(), terms);
    for (restored, original) in undo.proposal.legs.iter().zip(&entry.proposal.legs) {
        assert_eq!(restored.amount, original.amount);
        assert_eq!(restored.base_amount, original.base_amount);
        assert_eq!(restored.account_ref, original.account_ref);
        assert_eq!(restored.dimension_set, original.dimension_set);
        assert_eq!(restored.side, original.side.flipped());
    }
    let restored = f.stock("2026-02-28");
    assert_eq!(net(&restored, f.control()), sign * 11_000);
    for account in ["1100", "3900", "4900", "6300", "6310", "6320"] {
        assert_eq!(net(&restored, account), 0, "undo restores {account}");
    }
    if allocated {
        assert_eq!(net(&restored, f.valuation()), sign * 1_000);
        assert_eq!(net(&restored, f.unrealized()), -sign * 1_000);
    }
}

#[test]
fn receipt_and_payment_keep_actual_cash_and_explicit_differences_separate_from_fx() {
    for liability in [false, true] {
        net_cash_workflow(liability, false);
    }
}

#[test]
fn allocated_receipt_and_payment_release_valuation_without_hiding_cash_adjustments() {
    for liability in [false, true] {
        net_cash_workflow(liability, true);
    }
}

#[test]
fn foreign_cash_differences_refuse_unexplained_units_reasons_routes_and_item_indices() {
    let f = AllocatedFixture::new(false);
    adjustment_accounts(&f);
    for difference in [
        "kind=BankCharge account=6320 amount=\"1.25 EUR\"",
        "kind=BankCharge account=6320 amount=\"0.00 USD\"",
        "kind=BankCharge account=3900 amount=\"1.25 USD\"",
        "kind=Discount account=4900 amount=\"1.25 USD\"",
        "kind=ShortPay account=6310 amount=\"1.25 USD\"",
        "kind=RealizedFx account=4900 amount=\"1.25 USD\"",
        "kind=BankCharge account=6320 amount=\"1.24 USD\"",
    ] {
        let mut args = f.cash_args(
            "bad-net-cash",
            "100.00 EUR",
            "128.75 USD",
            "SettlementCarryingBasis",
        );
        args.extend(["--difference".into(), difference.into()]);
        f.refused_cash(&args);
    }
    let invalid_item = f.f.file(
        "wrong-difference-item.json",
        &format!(
            r#"{{"effective_date":"2026-02-05","idempotency_key":"wrong-difference-item","legs":[{{"side":"debit","account":"1100","amount":"128.75 USD"}},{{"side":"credit","account":"1200","party":"PARTY","amount":"100.00 EUR","settles":[{{"entry":"{}","ordinal":0,"amount":"100.00 EUR"}}]}}],"fx":{{"law":"SettlementCarryingBasis","rates":["{}"],"conversion_account":"3900","realized_fx_account":"4900","differences":[{{"item":1,"kind":"BankCharge","account":"6320","amount":"1.25 USD"}}]}}}}"#,
            f.target, f.rate,
        ),
    );
    let before = head(&f.f.book);
    let (status, refused) = run(
        &f.f.book,
        &[
            "post",
            "--intent",
            &invalid_item,
            "--evidence",
            &f.f.evidence,
            "--yes",
        ],
        None,
    );
    assert_eq!(status, 2, "{}", refused.render());
    assert_eq!(head(&f.f.book), before);
}
