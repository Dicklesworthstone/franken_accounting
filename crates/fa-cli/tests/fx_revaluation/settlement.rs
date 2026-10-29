//! A retained item allocation reaches ordinary customer and supplier cash
//! workflows through real CLI processes, including portable plans and undo.

use super::*;
use fa::FxLawId;
use fa_model::FxSettlementValuationBasis;
use fa_model::entry::FX_SETTLEMENT_VALUATION_EXTENSION;

struct AllocatedFixture {
    f: Fixture,
    liability: bool,
    target: String,
    rate: String,
}

impl AllocatedFixture {
    fn new(liability: bool) -> Self {
        let f = Fixture::new();
        let chart = f.file(
            "settlement-accounts.json",
            r#"{"accounts":[{"code":"1100","name":"USD Cash","type":"Asset","unit":"USD"},{"code":"3900","name":"FX Conversion","type":"Equity","unit":"any-currency"},{"code":"4900","name":"Realized FX","type":"Revenue","unit":"USD"}]}"#,
        );
        ok(&f.book, &["chart", "import", &chart]);
        ok(&f.book, &["period", "open", "FY2026-P02"]);
        let party = f.file(
            "settlement-party.json",
            if liability {
                r#"{"code":"PARTY","kind":"Vendor","name":"Foreign supplier"}"#
            } else {
                r#"{"code":"PARTY","kind":"Customer","name":"Foreign customer"}"#
            },
        );
        ok(&f.book, &["party", "add", &party]);
        let spot = f.rate("item-spot", "spot_close", "2026-01-05", 11, "HalfEven");
        let (side, control, opposite, counter) = if liability {
            ("credit", "2200", "debit", "6000")
        } else {
            ("debit", "1200", "credit", "4000")
        };
        let source = f.file(
            "valued-party-item.json",
            &format!(
                r#"{{"effective_date":"2026-01-05","idempotency_key":"valued-party-item","legs":[{{"side":"{side}","account":"{control}","party":"PARTY","amount":"100.00 EUR"}},{{"side":"{opposite}","account":"{counter}","amount":"100.00 EUR"}}],"fx":{{"law":"SpotClose","rates":["D:{}"]}}}}"#,
                text(data(&spot), "oid"),
            ),
        );
        let posted = ok(
            &f.book,
            &[
                "post",
                "--intent",
                &source,
                "--evidence",
                &f.evidence,
                "--yes",
            ],
        );
        let target = text(data(&posted), "vid").to_string();
        let settlement = f.rate(
            "item-settlement",
            "settlement",
            "2026-02-05",
            13,
            "HalfEven",
        );
        let rate = format!("D:{}", text(data(&settlement), "oid"));
        Self {
            f,
            liability,
            target,
            rate,
        }
    }

    fn control(&self) -> &'static str {
        if self.liability { "2200" } else { "1200" }
    }

    fn valuation(&self) -> &'static str {
        if self.liability { "2290" } else { "1290" }
    }

    fn unrealized(&self) -> &'static str {
        if self.liability { "6700" } else { "4700" }
    }

    fn cash_args(&self, key: &str, foreign: &str, cash: &str, law: &str) -> Vec<String> {
        [
            if self.liability { "payment" } else { "receipt" },
            "--party",
            "PARTY",
            "--number",
            key,
            "--date",
            "2026-02-05",
            "--cash",
            "1100",
            if self.liability {
                "--payable"
            } else {
                "--receivable"
            },
            self.control(),
            "--amount",
            cash,
            "--applies",
            &format!("{}:0={foreign}", self.target),
            "--fx-rate",
            &self.rate,
            "--fx-law",
            law,
            "--conversion",
            "3900",
            "--realized-fx",
            "4900",
            "--evidence",
            &self.f.evidence,
            "--yes",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    fn cash(&self, args: &[String]) -> Json {
        ok(
            &self.f.book,
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
        )
    }

    fn refused_cash(&self, args: &[String]) {
        let before = head(&self.f.book);
        let (status, refusal) = run(
            &self.f.book,
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
            None,
        );
        assert_ne!(status, 0, "{}", refusal.render());
        assert_eq!(
            head(&self.f.book),
            before,
            "a wrong FX law publishes nothing"
        );
    }

    fn stock(&self, day: &str) -> Json {
        ok(&self.f.book, &["tb", "--functional", "--as-of", day])
    }
}

fn net(report: &Json, account: &str) -> i128 {
    let row = rows(data(report), "rows")
        .iter()
        .find(|row| text(row, "account") == account)
        .expect(account);
    Amount::parse(text(row, "net"), &UnitRegistry::embedded().unwrap())
        .unwrap()
        .mantissa
}

fn release(entry: &Entry) -> FxSettlementValuationBasis {
    assert_eq!(
        entry.proposal.base_totals.as_ref().unwrap().fx_law_oid,
        FxLawId::SettlementAllocatedCarrying.oid()
    );
    let (_, bytes) = entry
        .proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == FX_SETTLEMENT_VALUATION_EXTENSION)
        .unwrap();
    FxSettlementValuationBasis::decode(bytes).unwrap()
}

fn allocated_cash_workflow(liability: bool) {
    let f = AllocatedFixture::new(liability);
    let original = f.f.entry(&f.target);
    let source_side = if liability { Side::Credit } else { Side::Debit };
    let sign = if liability { -1 } else { 1 };
    assert_eq!(original.proposal.legs[0].side, source_side);
    assert!(
        !original.proposal.legs[0].dimension_set.is_empty(),
        "the party is authenticated"
    );

    // Selecting an allocated law cannot manufacture an allocation for an
    // ordinary historical-cost item.
    f.refused_cash(&f.cash_args(
        "unallocated",
        "33.33 EUR",
        "43.33 USD",
        "SettlementAllocatedCarrying",
    ));
    let closing = f.f.closing_rate(12);
    let rate = format!("D:{}", text(data(&closing), "oid"));
    let review_path = f.f.path("allocated.review");
    let before_review = head(&f.f.book);
    let reviewed = ok(
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
            "allocated-closing",
            "--allocate-open-items",
            "--review-out",
            &review_path,
        ],
    );
    assert_eq!(text(&reviewed, "event"), "fx_revaluation_reviewed");
    assert_eq!(head(&f.f.book), before_review);
    let allocation = data(&reviewed).get("item_allocation").unwrap();
    assert_eq!(text(allocation, "law"), "LargestRemainder:v1");
    let [item] = rows(allocation, "items") else {
        panic!("one complete open item");
    };
    assert_eq!(text(item, "target"), f.target);
    assert_eq!(text(item, "target_digest"), hex(&original.entry_digest));
    assert_eq!(integer(item, "ordinal"), 0);
    for (field, amount) in [
        ("open_native", "100.00 EUR"),
        ("historical_base", "110.00 USD"),
        ("prior_valuation", "0.00 USD"),
        ("target_base", "120.00 USD"),
        ("delta", "10.00 USD"),
    ] {
        assert_eq!(text(item, field), amount);
    }
    let review = PostIntent::decode(&std::fs::read(&review_path).unwrap()).unwrap();
    assert_eq!(
        review.proposal().schema_minor,
        fa_model::entry::FX_ITEM_CARRYING_SCHEMA_MINOR
    );
    assert_eq!(
        review.proposal().base_totals.as_ref().unwrap().fx_law_oid,
        FxLawId::PeriodEndItemRevaluation.oid()
    );
    assert!(
        review
            .proposal()
            .legs
            .iter()
            .all(|leg| leg.dimension_set == original.proposal.legs[0].dimension_set)
    );
    let preview = ok(
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
            "allocated-preview",
            "--allocate-open-items",
            "--review-only",
        ],
    );
    assert_eq!(data(&preview).get("item_allocation"), Some(allocation));
    assert_eq!(head(&f.f.book), before_review);

    let (status, refused) = run(
        &f.f.book,
        &[
            "fx",
            "revalue",
            "--review",
            &review_path,
            "--digest",
            text(data(&reviewed), "review_digest"),
            "--allocate-open-items",
            "--dry-run",
        ],
        None,
    );
    assert_eq!(status, 2, "{}", refused.render());
    assert_eq!(
        head(&f.f.book),
        before_review,
        "restored reviews cannot override selectors"
    );

    let plan_path = f.f.save_plan(
        "allocated-closing",
        &review_path,
        text(data(&reviewed), "review_digest"),
    );
    let plan = PostPlan::decode(&std::fs::read(&plan_path).unwrap()).unwrap();
    assert_eq!(plan.proposal(), review.proposal());
    assert_eq!(head(&f.f.book), before_review);
    let revalued = f.f.commit(&plan_path);
    assert_eq!(
        f.f.entry(text(data(&revalued), "vid")).proposal,
        *review.proposal()
    );
    let closing_prefix = head(&f.f.book).to_string();
    let january = f.stock("2026-01-31");
    assert_eq!(net(&january, f.control()), sign * 11_000);
    assert_eq!(net(&january, f.valuation()), sign * 1_000);
    assert_eq!(net(&january, f.unrealized()), -sign * 1_000);

    f.refused_cash(&f.cash_args(
        "wrong-historical-law",
        "33.33 EUR",
        "43.33 USD",
        "SettlementCarryingBasis",
    ));
    f.refused_cash(&f.cash_args("wrong-spot-law", "33.33 EUR", "43.33 USD", "SpotClose"));
    let cash_plan = f.f.path("partial-cash.plan");
    let mut partial = f.cash_args(
        "partial",
        "33.33 EUR",
        "43.33 USD",
        "SettlementAllocatedCarrying",
    );
    partial.extend(["--dry-run".into(), "--plan-out".into(), cash_plan.clone()]);
    let before_partial = head(&f.f.book);
    let planned = f.cash(&partial);
    assert_eq!(text(&planned, "event"), "plan");
    assert_eq!(head(&f.f.book), before_partial);
    let partial_plan = PostPlan::decode(&std::fs::read(&cash_plan).unwrap()).unwrap();
    let stale_path = f.f.path("competing-cash.plan");
    let mut competing = f.cash_args(
        "competing",
        "33.33 EUR",
        "43.33 USD",
        "SettlementAllocatedCarrying",
    );
    competing.extend(["--dry-run".into(), "--plan-out".into(), stale_path.clone()]);
    assert_eq!(text(&f.cash(&competing), "event"), "plan");
    assert_eq!(head(&f.f.book), before_partial);
    let partial_post = f.f.commit(&cash_plan);
    let partial_vid = text(data(&partial_post), "vid").to_string();
    let partial_entry = f.f.entry(&partial_vid);
    assert_eq!(partial_entry.proposal, *partial_plan.proposal());
    let after_partial = head(&f.f.book);
    let (status, invalidated) = run(
        &f.f.book,
        &["commit", "--plan", &stale_path, "--grant", "read", "--yes"],
        None,
    );
    assert_eq!(status, 6, "{}", invalidated.render());
    assert_eq!(
        text(data(&invalidated), "refusal_id"),
        code::PLAN_INVALIDATED
    );
    assert_eq!(
        head(&f.f.book),
        after_partial,
        "a restored unrecorded plan cannot reuse pre-application carrying"
    );
    let basis = release(&partial_entry);
    let [component] = basis.items.as_slice() else {
        panic!("one cash component");
    };
    assert_eq!(
        (
            component.historical_relief.mantissa,
            component.total_relief.mantissa,
            component.valuation_relief.mantissa
        ),
        (3_666, 4_000, 334)
    );
    let applying = &partial_entry.proposal.legs[usize::from(component.applying_ordinal)];
    assert_eq!(applying.side, source_side.flipped());
    assert_eq!(applying.amount.mantissa, 3_333);
    assert_eq!(applying.base_amount.unwrap().mantissa, 3_666);
    assert_eq!(
        applying.settles[0].target.entry_digest,
        original.entry_digest
    );
    let partial_stock = f.stock("2026-02-28");
    assert_eq!(net(&partial_stock, f.control()), sign * 7_334);
    assert_eq!(net(&partial_stock, f.valuation()), sign * 666);
    assert_eq!(net(&partial_stock, f.unrealized()), -sign * 666);
    assert_eq!(net(&partial_stock, "1100"), sign * 4_333);
    assert_eq!(net(&partial_stock, "4900"), -sign * 667);

    let final_post = f.cash(&f.cash_args(
        "final",
        "66.67 EUR",
        "86.67 USD",
        "SettlementAllocatedCarrying",
    ));
    let final_entry = f.f.entry(text(data(&final_post), "vid"));
    let final_basis = release(&final_entry);
    assert_eq!(
        (
            final_basis.items[0].historical_relief.mantissa,
            final_basis.items[0].total_relief.mantissa,
            final_basis.items[0].valuation_relief.mantissa
        ),
        (7_334, 8_000, 666)
    );
    let fully_settled = f.stock("2026-02-28");
    for account in [f.control(), f.valuation(), f.unrealized(), "3900"] {
        assert_eq!(net(&fully_settled, account), 0, "closed {account}");
    }
    assert_eq!(net(&fully_settled, "1100"), sign * 13_000);
    assert_eq!(net(&fully_settled, "4900"), -sign * 2_000);

    let before_retry = head(&f.f.book);
    let retry = f.f.commit(&cash_plan);
    assert_eq!(
        data(&retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(text(data(&retry), "vid"), partial_vid);
    let closing_retry = f.f.commit(&plan_path);
    assert_eq!(
        data(&closing_retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(head(&f.f.book), before_retry);

    let undone = ok(
        &f.f.book,
        &[
            "reverse",
            &partial_vid,
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
    assert_eq!(
        release(&undo),
        basis,
        "undo retains the exact allocation provenance"
    );
    assert_eq!(undo.proposal.legs.len(), partial_entry.proposal.legs.len());
    for (restored, original) in undo.proposal.legs.iter().zip(&partial_entry.proposal.legs) {
        assert_eq!(restored.account_ref, original.account_ref);
        assert_eq!(restored.amount, original.amount);
        assert_eq!(restored.base_amount, original.base_amount);
        assert_eq!(restored.dimension_set, original.dimension_set);
        assert_eq!(restored.side, original.side.flipped());
        assert!(
            restored.settles.is_empty(),
            "applications are restored through exact undo edges"
        );
    }
    let restored = f.stock("2026-02-28");
    assert_eq!(net(&restored, f.control()), sign * 3_666);
    assert_eq!(net(&restored, f.valuation()), sign * 334);
    assert_eq!(net(&restored, f.unrealized()), -sign * 334);
    assert_eq!(net(&restored, "1100"), sign * 8_667);
    // Re-applying by reversing an undo remains outside the native settlement
    // contract. A fresh application instead recomputes its complete source.
    let before_unsupported = head(&f.f.book);
    let (status, refusal) = run(
        &f.f.book,
        &[
            "reverse",
            text(data(&undone), "vid"),
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
        None,
    );
    assert_ne!(status, 0, "{}", refusal.render());
    assert_eq!(head(&f.f.book), before_unsupported);
    let (cash_side, applying_side) = if liability {
        ("credit", "debit")
    } else {
        ("debit", "credit")
    };
    let reapplied_intent = f.f.file(
        "reapplied.json",
        &format!(
            r#"{{"effective_date":"2026-02-05","idempotency_key":"reapplied-json","legs":[{{"side":"{cash_side}","account":"1100","amount":"43.33 USD"}},{{"side":"{applying_side}","account":"{}","party":"PARTY","amount":"33.33 EUR","settles":[{{"entry":"{}","ordinal":0,"amount":"33.33 EUR"}}]}}],"fx":{{"law":"SettlementAllocatedCarrying","rates":["{}"],"conversion_account":"3900","realized_fx_account":"4900"}}}}"#,
            f.control(), f.target, f.rate,
        ),
    );
    let reapplied = ok(
        &f.f.book,
        &[
            "post",
            "--intent",
            &reapplied_intent,
            "--evidence",
            &f.f.evidence,
            "--yes",
        ],
    );
    let replacement_basis = release(&f.f.entry(text(data(&reapplied), "vid")));
    assert_eq!(
        (
            replacement_basis.items[0].historical_relief.mantissa,
            replacement_basis.items[0].total_relief.mantissa,
            replacement_basis.items[0].valuation_relief.mantissa
        ),
        (3_666, 4_000, 334)
    );
    assert_ne!(
        replacement_basis.items[0].source_digest, component.source_digest,
        "the reapplied source binds the intervening full application and undo"
    );
    let settled_again = f.stock("2026-02-28");
    for account in [
        f.control(),
        f.valuation(),
        f.unrealized(),
        "1100",
        "3900",
        "4900",
    ] {
        assert_eq!(net(&settled_again, account), net(&fully_settled, account));
    }
    let unchanged_january = f.stock("2026-01-31");
    for field in ["rows", "totals", "entries", "fold_digest"] {
        assert_eq!(
            data(&unchanged_january).get(field),
            data(&january).get(field),
            "{field}"
        );
    }
    let historical = ok(
        &f.f.book,
        &[
            "tb",
            "--functional",
            "--as-of",
            "2026-01-31",
            "--as-known-at",
            &closing_prefix,
        ],
    );
    assert_eq!(data(&historical), data(&january));
    assert_eq!(
        f.f.entry(&f.target),
        original,
        "cash workflows never reprice the original item"
    );
    ok(&f.f.book, &["verify", "open-items"]);
    ok(&f.f.book, &["verify", "fx-conversion"]);
}

#[test]
fn allocated_receipt_releases_rounded_item_valuation_and_exact_undo_after_reopen() {
    allocated_cash_workflow(false);
}

#[test]
fn allocated_payment_releases_rounded_item_valuation_and_exact_undo_after_reopen() {
    allocated_cash_workflow(true);
}
