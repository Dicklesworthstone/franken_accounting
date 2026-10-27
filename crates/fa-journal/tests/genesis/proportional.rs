use super::*;
use fa_journal::proportional::{PROPORTIONAL_POST_EXTENSION, PROPORTIONAL_POST_SCHEMA_MINOR};
use fa_money::proportional_post::ProportionalPostLaw;
use fa_money::{ArithmeticBudget, BudgetLimits, Rate};

fn prepare(
    h: &Harness,
    hold: &EntryPayload,
    rate: &str,
) -> Result<PreparedProportionalPost, Refusal> {
    let arithmetic = h.root.restrict::<asupersync::cx::cap::None>();
    let mut budget = ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(10_000_000, 0), 8192);
    let rate = Rate::from_decimal(&mut budget, rate).unwrap();
    prepare_proportional_post(
        &mut budget,
        &fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap(),
        &h.book.units,
        hold,
        ProportionalPostLaw::BalancedLargestRemainder,
        &rate,
    )
}

fn proposal(
    h: &Harness,
    target: EntryRef,
    prepared: PreparedProportionalPost,
    key: &[u8],
) -> EntryPayload {
    let mut result = h.resolution_posts(target, prepared.legs, prepared.source_ordinals, key);
    result.schema_minor = PROPORTIONAL_POST_SCHEMA_MINOR;
    result.extensions = vec![(PROPORTIONAL_POST_EXTENSION, prepared.extension_bytes)];
    result
}

fn split(h: &Harness) -> Vec<LegPayload> {
    vec![
        LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, 6_001)),
        LegPayload::simple(Side::Debit, h.receivable, Amount::new(h.usd, 3_999)),
        LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 10_000)),
    ]
}

fn cash_period(h: &Harness, period: &str) -> LimitCell {
    let row =
        h.db.vertex(period_cell_vid(h.cash, period))
            .unwrap()
            .unwrap();
    LimitCell::decode_bound(&row, h.cash, Some(period)).unwrap()
}

#[test]
fn proportional_post_follows_the_registered_law_with_explicit_residual() {
    let mut h = harness();
    let eur = h.book.units.lookup("EUR").unwrap();
    let accounts =
        [("1290", 1, 0), ("4090", 4, 1)].map(|(code, account_type, normal_balance)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type,
            normal_balance,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(eur),
            parent_code: None,
            limit: None,
        });
    let ctx = h.ctx();
    let description = h
        .proposal(vec![], b"proportional-eur-chart", EntryClass::ORIGINAL)
        .description;
    let day = h.day();
    h.runtime
        .block_on(install_chart(
            &mut h.db,
            &ctx,
            &h.book,
            &accounts,
            PRINCIPAL,
            day,
            b"proportional-eur-chart",
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let mut legs = split(&h);
    legs.extend([
        LegPayload::simple(
            Side::Debit,
            account_vid(h.book.book_id, "1290"),
            Amount::new(eur, 101),
        ),
        LegPayload::simple(
            Side::Credit,
            account_vid(h.book.book_id, "4090"),
            Amount::new(eur, 50),
        ),
        LegPayload::simple(
            Side::Credit,
            account_vid(h.book.book_id, "4090"),
            Amount::new(eur, 51),
        ),
    ]);
    let held = h.pending(legs, b"proportional-two-units");
    let target = h
        .post(h.request(held.clone(), &["post"]))
        .unwrap()
        .entry_ref();
    let prepared = prepare(&h, &held, "0.37").unwrap();
    // Independent exact arithmetic: USD target 3700, EUR target 37.
    // EUR credit floors are 18,18; the 51-cent source has the larger remainder.
    assert_eq!(prepared.source_ordinals, [0, 1, 2, 3, 4, 5]);
    assert_eq!(
        prepared
            .legs
            .iter()
            .map(|l| l.amount.mantissa)
            .collect::<Vec<_>>(),
        [2220, 1480, 3700, 37, 18, 19]
    );
    assert_eq!(
        prepared
            .outcome
            .legs()
            .iter()
            .map(|l| l.released.mantissa)
            .collect::<Vec<_>>(),
        [3781, 2519, 6300, 64, 32, 32]
    );
    for (original, row) in held.legs.iter().zip(prepared.outcome.legs()) {
        assert_eq!(
            row.posted.mantissa + row.released.mantissa,
            original.amount.mantissa
        );
        assert_eq!(row.posted.unit, original.amount.unit);
    }
    let resolution = proposal(&h, target, prepared, b"proportional-two-units-post");
    let expected_basis = resolution.extensions.clone();
    let posted = h.post(h.request(resolution, &["post"])).unwrap();
    let stored = read_entry(&h.db, posted.entry_ref().vid)
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(stored.proposal.extensions, expected_basis);
    assert_eq!(stored.proposal.schema_minor, 2);
    for total in &stored.proposal.unit_totals {
        assert_eq!(total.debits, total.credits);
    }
    assert_eq!(
        fa_model::Entry::decode(&stored.encode().unwrap()).unwrap(),
        stored
    );
}

#[test]
fn proportional_post_releases_the_entire_original_period_reservation_exactly_once() {
    let mut h = harness_configured(
        Vec::new(),
        None,
        Some(BalanceLimit {
            lower: Some(-20_000),
            upper: None,
            scope: LimitScope::Period,
        }),
    );
    let held = h.pending(split(&h), b"proportional-full-release");
    let target = h
        .post(h.request(held.clone(), &["post"]))
        .unwrap()
        .entry_ref();
    assert_eq!(cash_period(&h, &h.march).credits_pending, 10_000);
    let april = h.april.clone();
    h.transition(&april, PeriodTransition::Open, b"proportional-open-april")
        .unwrap();
    let mut resolution = proposal(
        &h,
        target,
        prepare(&h, &held, "0.37").unwrap(),
        b"proportional-april",
    );
    resolution.effective_date = DateDay::from_ymd(2026, 4, 15).unwrap();
    let posted = h.post(h.request(resolution.clone(), &["post"])).unwrap();
    let march = cash_period(&h, &h.march);
    let april = cash_period(&h, &h.april);
    assert_eq!(
        (
            march.debits_pending,
            march.credits_pending,
            march.credits_posted
        ),
        (0, 0, 0)
    );
    assert_eq!(
        (
            april.debits_pending,
            april.credits_pending,
            april.credits_posted
        ),
        (0, 0, 3700)
    );
    let frontier = h.db.frontier().unwrap();
    let retry = h.post(h.request(resolution, &["post"])).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(h.db.frontier().unwrap(), frontier);
    assert_eq!(cash_period(&h, &h.march), march);
    assert_eq!(cash_period(&h, &h.april), april);
    let second = proposal(
        &h,
        target,
        prepare(&h, &held, "0.5").unwrap(),
        b"proportional-second",
    );
    assert_eq!(
        h.post(h.request(second, &["post"])).unwrap_err().code,
        "FA-REF-062"
    );
    assert_eq!(
        h.post(h.request(h.resolution_voids(target, b"proportional-void"), &["post"]))
            .unwrap_err()
            .code,
        "FA-REF-062"
    );
    assert_eq!(h.db.frontier().unwrap(), frontier);
}

#[test]
fn balanced_proportional_forgery_and_rebound_rate_are_refused_without_state_change() {
    let mut h = harness();
    let held = h.pending(split(&h), b"proportional-tamper-source");
    let target = h
        .post(h.request(held.clone(), &["post"]))
        .unwrap()
        .entry_ref();
    let valid = proposal(
        &h,
        target,
        prepare(&h, &held, "0.37").unwrap(),
        b"proportional-tamper",
    );
    let frontier = h.db.frontier().unwrap();
    let mut shifted = valid.clone();
    shifted.legs[0].amount.mantissa += 1;
    shifted.legs[1].amount.mantissa -= 1;
    shifted.unit_totals = EntryPayload::fold_unit_totals(&shifted.legs).unwrap();
    assert_eq!(
        shifted.unit_totals[0].debits,
        shifted.unit_totals[0].credits
    );
    let mut rebound = valid.clone();
    rebound.extensions[0].1 = prepare(&h, &held, "0.5").unwrap().extension_bytes;
    let mut noncanonical = valid.clone();
    // 74/200 equals 37/100 but is not canonical FAR1. Structural validation
    // permits the bounded frame; the kernel's metered Rate decoder refuses it.
    let bytes = &mut noncanonical.extensions[0].1;
    let length = bytes.len();
    bytes[length - 2] = 74;
    bytes[length - 1] = 200;
    for candidate in [shifted, rebound, noncanonical] {
        let refusal = h.post(h.request(candidate, &["post"])).unwrap_err();
        assert_eq!(refusal.code, "FA-REF-061", "{refusal}");
        assert_eq!(h.db.frontier().unwrap(), frontier);
        assert!(h.db.vertex(resolution_vid(target.vid)).unwrap().is_none());
    }
    h.post(h.request(valid, &["post"]))
        .expect("refusals did not consume the resolution or idempotency key");
}

#[test]
fn proportional_ties_keep_original_ordinals_when_zero_legs_are_omitted() {
    let mut h = harness();
    let held = h.pending(
        vec![
            LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, 1)),
            LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, 1)),
            LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, 1)),
            LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 3)),
        ],
        b"proportional-ties",
    );
    let target = h
        .post(h.request(held.clone(), &["post"]))
        .unwrap()
        .entry_ref();
    let prepared = prepare(&h, &held, "0.5").unwrap();
    assert_eq!(prepared.source_ordinals, [0, 1, 3]);
    assert_eq!(
        prepared
            .legs
            .iter()
            .map(|l| l.amount.mantissa)
            .collect::<Vec<_>>(),
        [1, 1, 2]
    );
    assert_eq!(prepared.outcome.legs()[2].released.mantissa, 1);
    let valid = proposal(&h, target, prepared, b"proportional-ties-post");
    let mut wrong_tie = valid.clone();
    wrong_tie.pending.as_mut().unwrap().disposition = Some(Disposition::Posts {
        source_ordinals: vec![0, 2, 3],
    });
    assert_eq!(
        h.post(h.request(wrong_tie, &["post"])).unwrap_err().code,
        "FA-REF-061"
    );
    h.post(h.request(valid, &["post"])).unwrap();
}

#[test]
fn proportional_zero_and_unknown_bases_fail_closed_and_do_not_turn_into_voids() {
    let mut h = harness();
    let held = h.pending(h.rent_legs(1), b"proportional-empty");
    let target = h
        .post(h.request(held.clone(), &["post"]))
        .unwrap()
        .entry_ref();
    for rate in ["0", "0.01", "0.5", "1.01"] {
        let refusal = prepare(&h, &held, rate).unwrap_err();
        assert_eq!(refusal.code, "FA-REF-061");
        assert!(refusal.fix.contains("VoidReserve"));
    }
    let valid = proposal(
        &h,
        target,
        prepare(&h, &held, "1").unwrap(),
        b"proportional-basis",
    );
    let frontier = h.db.frontier().unwrap();
    for (offset, value) in [(0, 2), (2, 99), (4, 2)] {
        let mut unknown = valid.clone();
        unknown.extensions[0].1[offset] = value;
        assert!(h.post(h.request(unknown, &["post"])).is_err());
        assert_eq!(h.db.frontier().unwrap(), frontier);
    }
    let arithmetic = h.root.restrict::<asupersync::cx::cap::None>();
    let mut budget = ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(10_000_000, 0), 8192);
    let mut zero = valid.clone();
    zero.extensions[0].1 = fa_model::ProportionalPostBasis {
        law: ProportionalPostLaw::BalancedLargestRemainder,
        rate_bytes: Rate::zero(&mut budget)
            .unwrap()
            .encode(&mut budget)
            .unwrap(),
    }
    .encode()
    .unwrap();
    let refusal = h.post(h.request(zero, &["post"])).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-061");
    assert!(refusal.fix.contains("VoidReserve"));
    assert_eq!(h.db.frontier().unwrap(), frontier);
    let mut earlier_minor = valid.clone();
    earlier_minor.schema_minor = 1;
    assert!(h.post(h.request(earlier_minor, &["post"])).is_err());
    assert!(h.db.vertex(resolution_vid(target.vid)).unwrap().is_none());
    h.post(h.request(valid, &["post"])).unwrap();
}

#[test]
fn proportional_preparation_refuses_unsupported_base_valuation_and_statistical_units() {
    let h = harness();
    let mut held = h.pending(h.rent_legs(100), b"proportional-domain");
    for leg in &mut held.legs {
        leg.base_amount = Some(leg.amount);
    }
    let refusal = prepare(&h, &held, "0.37").unwrap_err();
    assert!(refusal.message.contains("base-valued"), "{refusal}");
    for leg in &mut held.legs {
        leg.base_amount = None;
        leg.amount.unit = h.book.units.lookup("EACH").unwrap();
    }
    held.unit_totals = EntryPayload::fold_unit_totals(&held.legs).unwrap();
    let refusal = prepare(&h, &held, "0.37").unwrap_err();
    assert!(refusal.message.contains("statistical"), "{refusal}");
    held.class = EntryClass::ORIGINAL;
    held.pending = None;
    assert!(
        prepare(&h, &held, "0.37")
            .unwrap_err()
            .message
            .contains("Pending")
    );
}

#[test]
fn proportional_normalizes_a_single_entity_and_rounds_each_entity_separately() {
    let usd = UnitRegistry::with_defaults().lookup("USD").unwrap();
    let entity = |code: &str| LegalEntitySpec {
        code: code.into(),
        name: code.into(),
        functional_unit: usd,
    };
    let mut h = harness_with_entities(vec![entity("co")]);
    let mut explicit = LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, 1));
    explicit.dimension_set = vec![(
        fa_model::LEGAL_ENTITY_DIMENSION,
        fa_model::entity_value_vid(h.book.book_id, "co"),
    )];
    let held = h.pending(
        vec![
            LegPayload::simple(Side::Debit, h.rent, Amount::new(h.usd, 1)),
            explicit,
            LegPayload::simple(Side::Credit, h.cash, Amount::new(h.usd, 2)),
        ],
        b"proportional-default-entity",
    );
    let target = h
        .post(h.request(held.clone(), &["post"]))
        .unwrap()
        .entry_ref();
    let prepared = prepare(&h, &held, "0.5").unwrap();
    assert_eq!(prepared.source_ordinals, [0, 2]);
    h.post(h.request(
        proposal(&h, target, prepared, b"proportional-default-post"),
        &["post"],
    ))
    .unwrap();

    let mut h = harness_with_entities(vec![entity("a"), entity("b")]);
    let mut legs = Vec::new();
    for (code, amount) in [("a", 1), ("b", 3)] {
        let dimension = fa_model::entity_value_vid(h.book.book_id, code);
        for mut leg in h.rent_legs(amount) {
            leg.dimension_set = vec![(fa_model::LEGAL_ENTITY_DIMENSION, dimension)];
            legs.push(leg);
        }
    }
    let held = h.pending(legs, b"proportional-entity-partitions");
    let target = h
        .post(h.request(held.clone(), &["post"]))
        .unwrap()
        .entry_ref();
    let prepared = prepare(&h, &held, "0.5").unwrap();
    // HalfEven(1/2)=0 for a; HalfEven(3/2)=2 for b. Globally allocating
    // two cents by source order would instead post one cent for each entity.
    assert_eq!(prepared.source_ordinals, [2, 3]);
    assert_eq!(
        prepared
            .legs
            .iter()
            .map(|l| l.amount.mantissa)
            .collect::<Vec<_>>(),
        [2, 2]
    );
    h.post(h.request(
        proposal(&h, target, prepared, b"proportional-entities-post"),
        &["post"],
    ))
    .unwrap();
}

#[test]
fn proportional_post_does_not_bypass_expiry_or_locked_period_law() {
    let mut h = harness();
    h.tick(100, b"proportional-anchor", 51);
    let mut held = h.pending(split(&h), b"proportional-timed");
    held.pending.as_mut().unwrap().timeout_ns = Some(5);
    let target = h
        .post(h.request(held.clone(), &["post"]))
        .unwrap()
        .entry_ref();
    let resolution = proposal(
        &h,
        target,
        prepare(&h, &held, "0.37").unwrap(),
        b"proportional-expired-post",
    );
    h.tick(105, b"proportional-due", 52);
    let frontier = h.db.frontier().unwrap();
    let refusal = h.post(h.request(resolution, &["post"])).unwrap_err();
    assert_eq!(refusal.code, fa_journal::refusal::code::HOLD_DUE);
    assert_eq!(h.db.frontier().unwrap(), frontier);
    assert!(h.db.vertex(resolution_vid(target.vid)).unwrap().is_none());

    let held = h.pending(split(&h), b"proportional-locked");
    let target = h
        .post(h.request(held.clone(), &["post"]))
        .unwrap()
        .entry_ref();
    let resolution = proposal(
        &h,
        target,
        prepare(&h, &held, "0.37").unwrap(),
        b"proportional-locked-post",
    );
    h.transition(
        &h.march.clone(),
        PeriodTransition::SoftClose,
        b"proportional-soft",
    )
    .unwrap();
    h.transition(
        &h.march.clone(),
        PeriodTransition::Close,
        b"proportional-close",
    )
    .unwrap();
    h.transition(
        &h.march.clone(),
        PeriodTransition::Lock,
        b"proportional-lock",
    )
    .unwrap();
    let frontier = h.db.frontier().unwrap();
    assert_eq!(
        h.post(h.request(resolution, &["post", "post_closed"]))
            .unwrap_err()
            .code,
        "FA-REF-010"
    );
    assert_eq!(h.db.frontier().unwrap(), frontier);
    h.post(h.request(
        h.resolution_voids(target, b"proportional-locked-void"),
        &["post"],
    ))
    .unwrap();
}
