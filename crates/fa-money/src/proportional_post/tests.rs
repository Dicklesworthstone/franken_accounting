use super::*;
use crate::rate::{BudgetLimits, MeterError};

fn leg(ordinal: u16, unit: u32, entity: Option<u128>, side: Side, amount: i128) -> HeldLeg {
    HeldLeg {
        source_ordinal: ordinal,
        amount: Amount::new(UnitId(unit), amount),
        side,
        legal_entity: entity,
    }
}

fn request(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    rate: &str,
    legs: Vec<HeldLeg>,
) -> ProportionalPostRequest {
    ProportionalPostRequest {
        law: ProportionalPostLaw::BalancedLargestRemainder,
        rate: Rate::from_decimal(budget, rate).unwrap(),
        legs,
    }
}

fn simple(budget: &mut ArithmeticBudget<'_, impl Sized>, rate: &str) -> ProportionalPostRequest {
    request(
        budget,
        rate,
        vec![
            leg(0, 1, None, Side::Debit, 60),
            leg(1, 1, None, Side::Debit, 40),
            leg(2, 1, None, Side::Credit, 100),
        ],
    )
}

fn amounts(outcome: &ProportionalPostOutcome) -> Vec<i128> {
    outcome
        .legs()
        .iter()
        .map(|leg| leg.posted.mantissa)
        .collect()
}

#[test]
fn thirty_seven_percent_preserves_each_currency_and_entity_and_releases_every_original_leg() {
    let cx = asupersync::Cx::detached_cancel_context();
    let mut budget = crate::test_budget(&cx);
    let basis = request(
        &mut budget,
        "0.37",
        vec![
            leg(0, 1, Some(10), Side::Debit, 60),
            leg(1, 1, Some(10), Side::Debit, 40),
            leg(2, 1, Some(10), Side::Credit, 100),
            leg(3, 2, Some(10), Side::Debit, 7),
            leg(4, 2, Some(10), Side::Debit, 3),
            leg(5, 2, Some(10), Side::Credit, 10),
            leg(6, 1, Some(20), Side::Debit, 1),
            leg(7, 1, Some(20), Side::Debit, 2),
            leg(8, 1, Some(20), Side::Credit, 3),
        ],
    );
    let outcome = basis.execute(&mut budget).unwrap();
    assert_eq!(amounts(&outcome), [22, 15, 37, 3, 1, 4, 0, 1, 1]);
    assert_eq!(
        outcome
            .posted_legs()
            .map(|leg| leg.source_ordinal)
            .collect::<Vec<_>>(),
        [0, 1, 2, 3, 4, 5, 7, 8]
    );
    assert_eq!(
        outcome.partitions(),
        [
            ProportionalPostPartition {
                unit: UnitId(1),
                legal_entity: Some(10),
                held: 100,
                posted: 37,
                released: 63
            },
            ProportionalPostPartition {
                unit: UnitId(1),
                legal_entity: Some(20),
                held: 3,
                posted: 1,
                released: 2
            },
            ProportionalPostPartition {
                unit: UnitId(2),
                legal_entity: Some(10),
                held: 10,
                posted: 4,
                released: 6
            },
        ]
    );
    for (held, result) in basis.legs.iter().zip(outcome.legs()) {
        assert_eq!(
            result.posted.checked_add(result.released).unwrap(),
            held.amount
        );
        assert_eq!(
            result
                .floor
                .mantissa
                .checked_add(i128::from(result.rounding_increment)),
            Some(result.posted.mantissa)
        );
        assert!(result.rounding_increment <= 1);
        assert!(result.posted.mantissa >= 0 && result.posted.mantissa <= held.amount.mantissa);
    }
    assert_eq!(outcome.legs()[0].remainder_numerator, 20);
    assert_eq!(outcome.legs()[1].remainder_numerator, 80);
    assert_eq!(outcome.legs()[1].rounding_increment, 1);
    assert_eq!(
        outcome.legs()[6].released.mantissa,
        1,
        "an omitted zero share is fully released"
    );
}

#[test]
fn common_target_prevents_independent_rounding_imbalance_and_ties_use_original_ordinals() {
    let cx = asupersync::Cx::detached_cancel_context();
    let mut budget = crate::test_budget(&cx);
    let basis = request(
        &mut budget,
        "0.5",
        vec![
            leg(1, 1, None, Side::Debit, 1),
            leg(3, 1, None, Side::Debit, 1),
            leg(7, 1, None, Side::Debit, 1),
            leg(9, 1, None, Side::Credit, 3),
        ],
    );
    let outcome = basis.execute(&mut budget).unwrap();
    assert_eq!(amounts(&outcome), [1, 1, 0, 2]);
    assert_eq!(
        outcome
            .posted_legs()
            .map(|leg| leg.source_ordinal)
            .collect::<Vec<_>>(),
        [1, 3, 9]
    );
    let two_debits = request(
        &mut budget,
        "0.5",
        vec![
            leg(0, 1, None, Side::Debit, 1),
            leg(1, 1, None, Side::Debit, 1),
            leg(2, 1, None, Side::Credit, 2),
        ],
    );
    assert_eq!(
        amounts(&two_debits.execute(&mut budget).unwrap()),
        [1, 0, 1]
    );
}

#[test]
fn zero_rate_or_empty_rounding_never_becomes_a_silent_void_and_full_rate_keeps_every_leg() {
    let cx = asupersync::Cx::detached_cancel_context();
    let mut budget = crate::test_budget(&cx);
    for rate in ["0", "0.00001"] {
        let basis = simple(&mut budget, rate);
        let error = basis.execute(&mut budget).unwrap_err();
        assert_eq!(error, ProportionalPostError::EmptyResult);
        assert!(error.to_string().contains("VoidReserve"));
    }
    let basis = simple(&mut budget, "1");
    let outcome = basis.execute(&mut budget).unwrap();
    assert_eq!(amounts(&outcome), [60, 40, 100]);
    assert!(outcome.legs().iter().all(|leg| leg.released.mantissa == 0
        && leg.rounding_increment == 0
        && leg.remainder_numerator == 0));
}

#[test]
fn arbitrary_precision_rates_and_i128_boundary_amounts_keep_exact_half_even_targets() {
    let cx = asupersync::Cx::detached_cancel_context();
    let mut budget = crate::test_budget(&cx);
    let pennies = vec![
        leg(0, 1, None, Side::Debit, 1),
        leg(1, 1, None, Side::Credit, 1),
    ];
    let just_above = request(
        &mut budget,
        "0.500000000000000000000000000000000000000000000001",
        pennies.clone(),
    );
    assert!(just_above.rate.denominator().bits() > 128);
    assert_eq!(amounts(&just_above.execute(&mut budget).unwrap()), [1, 1]);
    for rate in ["0.499999999999999999999999999999999999999999999999", "0.5"] {
        let basis = request(&mut budget, rate, pennies.clone());
        assert_eq!(
            basis.execute(&mut budget),
            Err(ProportionalPostError::EmptyResult)
        );
    }
    let boundary = request(
        &mut budget,
        "0.5",
        vec![
            leg(0, 1, None, Side::Debit, i128::MAX - 1),
            leg(1, 1, None, Side::Debit, 1),
            leg(2, 1, None, Side::Credit, i128::MAX),
        ],
    );
    let outcome = boundary.execute(&mut budget).unwrap();
    assert_eq!(outcome.partitions()[0].posted, 1i128 << 126);
    assert_eq!(
        outcome.legs()[0]
            .posted
            .mantissa
            .checked_add(outcome.legs()[1].posted.mantissa),
        Some(1i128 << 126)
    );
    for (held, result) in boundary.legs.iter().zip(outcome.legs()) {
        assert_eq!(
            result.posted.checked_add(result.released).unwrap(),
            held.amount
        );
    }
}

#[test]
fn malformed_or_unbalanced_bases_and_rates_outside_the_law_domain_are_refused() {
    let cx = asupersync::Cx::detached_cancel_context();
    let mut budget = crate::test_budget(&cx);
    let too_much = simple(
        &mut budget,
        "1.000000000000000000000000000000000000000000001",
    );
    assert_eq!(
        too_much.execute(&mut budget),
        Err(ProportionalPostError::RateOutOfRange)
    );
    let valid = simple(&mut budget, "0.37");
    for bad in 0..6 {
        let mut basis = valid.clone();
        match bad {
            0 => basis.legs[0].amount.mantissa = 0,
            1 => basis.legs[0].amount.mantissa = -1,
            2 => basis.legs[1].source_ordinal = 0,
            3 => basis.legs.swap(0, 1),
            4 => basis.legs.clear(),
            5 => basis
                .legs
                .resize(MAX_PROPORTIONAL_POST_LEGS + 1, basis.legs[0]),
            _ => unreachable!(),
        }
        assert!(
            matches!(
                basis.execute(&mut budget),
                Err(ProportionalPostError::Invalid(_))
            ),
            "case {bad}"
        );
    }
    for change_unit in [false, true] {
        let mut basis = valid.clone();
        if change_unit {
            basis.legs[2].amount.unit = UnitId(2);
        } else {
            basis.legs[2].legal_entity = Some(7);
        }
        assert!(matches!(
            basis.execute(&mut budget),
            Err(ProportionalPostError::Unbalanced { .. })
        ));
    }
    let mut overflow = valid;
    overflow.legs[0].amount.mantissa = i128::MAX;
    assert_eq!(
        overflow.execute(&mut budget),
        Err(ProportionalPostError::Amount(AmountError::Overflow))
    );
}

#[test]
fn portable_receipts_replay_the_full_expected_basis_and_every_rounding_field() {
    let cx = asupersync::Cx::detached_cancel_context();
    let mut budget = crate::test_budget(&cx);
    let basis = simple(&mut budget, "0.37");
    let encoded = basis.canonical_bytes(&mut budget).unwrap();
    assert_eq!(
        ProportionalPostRequest::decode(&mut budget, &encoded).unwrap(),
        basis
    );
    let outcome = basis.execute(&mut budget).unwrap();
    let receipt = outcome.receipt_bytes(&mut budget).unwrap();
    assert_eq!(
        ProportionalPostOutcome::replay_receipt_for(&mut budget, &receipt, &basis).unwrap(),
        outcome
    );
    assert_eq!(outcome.receipt_bytes(&mut budget).unwrap(), receipt);
    // Every transported byte matters: capacities, rate, source ordinals,
    // floor, remainder, rounding winner, posted/released and partition totals.
    for index in 0..receipt.len() {
        let mut changed = receipt.clone();
        changed[index] ^= 1;
        assert!(
            ProportionalPostOutcome::replay_receipt_for(&mut budget, &changed, &basis).is_err(),
            "changed byte {index}"
        );
    }
    for kind in 0..4 {
        let mut other = basis.clone();
        match kind {
            0 => other.rate = Rate::from_decimal(&mut budget, "0.38").unwrap(),
            1 => {
                other.legs[0].amount.mantissa = 40;
                other.legs[1].amount.mantissa = 60;
            }
            2 => {
                for leg in &mut other.legs {
                    leg.legal_entity = Some(7);
                }
            }
            3 => {
                for leg in &mut other.legs {
                    leg.amount.unit = UnitId(2);
                }
            }
            _ => unreachable!(),
        }
        assert_eq!(
            ProportionalPostOutcome::replay_receipt_for(&mut budget, &receipt, &other),
            Err(ProportionalPostError::Mismatch)
        );
    }
}

#[test]
fn request_decoder_refuses_truncation_unknown_versions_and_hostile_counts() {
    let cx = asupersync::Cx::detached_cancel_context();
    let mut budget = crate::test_budget(&cx);
    let basis = simple(&mut budget, "0.37");
    let encoded = basis.canonical_bytes(&mut budget).unwrap();
    for length in 0..encoded.len() {
        assert!(
            ProportionalPostRequest::decode(&mut budget, &encoded[..length]).is_err(),
            "truncated at {length}"
        );
    }
    let magic = b"fa:proportional-post-request:v1\0".len();
    for index in [magic, magic + 2] {
        let mut bad = encoded.clone();
        bad[index] = 9;
        assert!(ProportionalPostRequest::decode(&mut budget, &bad).is_err());
    }
    let rate_len = basis.rate.encode(&mut budget).unwrap().len();
    let count_offset = magic + 8 + rate_len;
    let mut hostile = encoded.clone();
    hostile[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(ProportionalPostRequest::decode(&mut budget, &hostile).is_err());
    let mut trailing = encoded;
    trailing.push(0);
    assert!(ProportionalPostRequest::decode(&mut budget, &trailing).is_err());
}

#[test]
fn exhaustion_and_cancellation_never_return_a_partial_subvector() {
    let cx = asupersync::Cx::detached_cancel_context();
    let mut budget = crate::test_budget(&cx);
    let basis = simple(&mut budget, "0.37");
    let mut exhausted = ArithmeticBudget::new(&cx, BudgetLimits::uniform(0, 0), 8192);
    assert!(basis.execute(&mut exhausted).is_err());
    cx.set_cancel_requested(true);
    assert_eq!(
        basis.execute(&mut budget),
        Err(ProportionalPostError::Rate(RateError::Meter(
            MeterError::Cancelled
        )))
    );
    assert_eq!(
        basis.canonical_bytes(&mut budget),
        Err(ProportionalPostError::Rate(RateError::Meter(
            MeterError::Cancelled
        )))
    );
}

// Independent bounded integer oracle: no Rate multiplication, production
// rounding helper, U256 or allocation function participates in expected values.
#[allow(clippy::arithmetic_side_effects)]
fn oracle(total: i128, numerator: i128, denominator: i128, weights: &[i128]) -> (i128, Vec<i128>) {
    let quotient = total * numerator / denominator;
    let remainder = total * numerator % denominator;
    let target = quotient
        + i128::from(
            2 * remainder > denominator || (2 * remainder == denominator && quotient % 2 == 1),
        );
    let mut shares: Vec<_> = weights
        .iter()
        .map(|weight| target * weight / total)
        .collect();
    let mut ranked: Vec<_> = weights
        .iter()
        .enumerate()
        .map(|(index, weight)| (target * weight % total, index))
        .collect();
    ranked.sort_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    let residual = target - shares.iter().sum::<i128>();
    for (_, index) in ranked.into_iter().take(usize::try_from(residual).unwrap()) {
        shares[index] += 1;
    }
    (target, shares)
}

#[test]
#[allow(clippy::arithmetic_side_effects)]
fn complete_small_grid_agrees_with_an_independent_integer_oracle_and_capacity_bounds() {
    let cx = asupersync::Cx::detached_cancel_context();
    for a in 1..=4i128 {
        for b in 1..=4i128 {
            let total = a + b;
            for c in 1..total {
                for denominator in 1..=7i128 {
                    for numerator in 0..=denominator {
                        let mut budget = crate::test_budget(&cx);
                        let basis = ProportionalPostRequest {
                            law: ProportionalPostLaw::BalancedLargestRemainder,
                            rate: Rate::new(
                                &mut budget,
                                u128::try_from(numerator).unwrap(),
                                u128::try_from(denominator).unwrap(),
                            )
                            .unwrap(),
                            legs: vec![
                                leg(0, 1, None, Side::Debit, a),
                                leg(1, 1, None, Side::Debit, b),
                                leg(2, 1, None, Side::Credit, c),
                                leg(3, 1, None, Side::Credit, total - c),
                            ],
                        };
                        let (target, debit) = oracle(total, numerator, denominator, &[a, b]);
                        let (_, credit) = oracle(total, numerator, denominator, &[c, total - c]);
                        if target == 0 {
                            assert_eq!(
                                basis.execute(&mut budget),
                                Err(ProportionalPostError::EmptyResult)
                            );
                            continue;
                        }
                        let actual = basis.execute(&mut budget).unwrap();
                        assert_eq!(
                            amounts(&actual),
                            [debit[0], debit[1], credit[0], credit[1]],
                            "held={a},{b}/{c},{} rate={numerator}/{denominator}",
                            total - c
                        );
                        for (held, result) in basis.legs.iter().zip(actual.legs()) {
                            assert!((0..=held.amount.mantissa).contains(&result.posted.mantissa));
                            assert_eq!(
                                result.posted.mantissa + result.released.mantissa,
                                held.amount.mantissa
                            );
                        }
                    }
                }
            }
        }
    }
}
