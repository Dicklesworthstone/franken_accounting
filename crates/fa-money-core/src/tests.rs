use super::*;

fn rate(n: i128, d: u128) -> SignedRate {
    SignedRate::new(n, NonZeroU128::new(d).unwrap())
}

#[test]
fn reduction_and_signed_endpoints() {
    assert_eq!(rate(i128::MIN, 1 << 127), rate(-1, 1));
    assert_eq!(rate(0, u128::MAX), rate(0, 1));
    assert_eq!(rate(-750, 10_000), rate(-3, 40));
    let min = Amount::new(UnitId(1), i128::MIN);
    for law in RoundingLaw::ALL {
        assert_eq!(min.mul_signed_rate(rate(1, 1), law), Ok(min));
        assert_eq!(
            min.mul_signed_rate(rate(-1, 1), law),
            Err(AmountError::Overflow)
        );
        assert_eq!(Amount::decode(&min.encode()), min);
    }
}

#[test]
fn scaled_conversions_round_once_with_the_final_sign() {
    let from = UnitId(1);
    let to = UnitId(2);
    // 1.50 source at -0.1 target/source = -1.5 target minor units.
    let amount = Amount::new(from, 150);
    for (law, expected) in [
        (RoundingLaw::HalfEven, -2),
        (RoundingLaw::HalfUp, -1),
        (RoundingLaw::HalfDown, -2),
        (RoundingLaw::HalfAwayFromZero, -2),
        (RoundingLaw::HalfTowardZero, -1),
        (RoundingLaw::Ceiling, -1),
        (RoundingLaw::Floor, -2),
        (RoundingLaw::TowardZero, -1),
        (RoundingLaw::AwayFromZero, -2),
    ] {
        assert_eq!(
            amount.convert_signed_rate(to, 2, 1, rate(-1, 10), law),
            Ok(Amount::new(to, expected))
        );
    }
    // Even the *denominator* needs more than 128 bits.
    assert_eq!(
        Amount::new(from, i128::MAX).convert_signed_rate(
            to,
            38,
            0,
            rate(1, u128::MAX),
            RoundingLaw::Ceiling
        ),
        Ok(Amount::new(to, 1))
    );
    assert_eq!(
        amount.convert_signed_rate(to, 39, 0, rate(1, 1), RoundingLaw::TowardZero),
        Err(AmountError::InvalidScale(39))
    );
}

#[test]
fn wide_scale_up_can_fit_after_division() {
    let amount = Amount::new(UnitId(1), i128::MAX);
    let law = RoundingLaw::HalfEven;
    assert_eq!(
        amount.convert_signed_rate(UnitId(2), 0, 38, rate(1, i128::MAX as u128), law),
        Ok(Amount::new(UnitId(2), 10_i128.pow(38)))
    );
    assert_eq!(
        amount.convert_signed_rate(UnitId(2), 0, 38, rate(i128::MAX, u128::MAX), law),
        Err(AmountError::Overflow)
    );
}

#[cfg(feature = "alloc")]
#[test]
fn allocation_uses_the_full_weight_sum_and_preserves_negative_totals() {
    let amount = Amount::new(UnitId(9), -5);
    let shares = largest_remainder(amount, &[u128::MAX, u128::MAX, 0]).unwrap();
    assert_eq!(
        shares,
        [
            Amount::new(amount.unit, -3),
            Amount::new(amount.unit, -2),
            Amount::new(amount.unit, 0)
        ]
    );
    assert_eq!(
        largest_remainder(amount, &[0, 0]),
        Err(AmountError::ZeroWeights)
    );
}

#[test]
fn billing_step_rounding_respects_named_law_and_minimum() {
    let unit = UnitId(7);
    let quantity = |mantissa| Amount::new(unit, mantissa);
    // Quarter-hour increments in minutes; exact ties select the registered law.
    assert_eq!(
        step_round(quantity(22), 15, 0, RoundingLaw::HalfEven),
        Ok(quantity(15))
    );
    assert_eq!(
        step_round(quantity(23), 15, 0, RoundingLaw::HalfEven),
        Ok(quantity(30))
    );
    assert_eq!(
        step_round(quantity(22), 15, 0, RoundingLaw::Ceiling),
        Ok(quantity(30))
    );
    assert_eq!(
        step_round(quantity(22), 15, 0, RoundingLaw::Floor),
        Ok(quantity(15))
    );
    assert_eq!(
        step_round(quantity(0), 15, 16, RoundingLaw::TowardZero),
        Ok(quantity(30))
    );
    assert_eq!(
        step_round(quantity(30), 15, 16, RoundingLaw::HalfEven),
        Ok(quantity(30))
    );
    assert_eq!(
        step_round(quantity(0), 15, 0, RoundingLaw::HalfEven),
        Ok(quantity(0))
    );
    assert_eq!(
        step_round(quantity(1), 0, 0, RoundingLaw::HalfEven),
        Err(AmountError::InvariantViolation(
            "billing step must be nonzero"
        ))
    );
    assert_eq!(
        step_round(quantity(-1), 15, 0, RoundingLaw::HalfEven),
        Err(AmountError::InvariantViolation(
            "step rounding requires a nonnegative quantity"
        ))
    );
    assert_eq!(
        step_round(quantity(1), 1, u128::MAX, RoundingLaw::HalfEven),
        Err(AmountError::Overflow)
    );
    assert_eq!(
        step_round(quantity(i128::MAX), 2, 0, RoundingLaw::Ceiling),
        Err(AmountError::Overflow)
    );
    for law in RoundingLaw::ALL {
        assert_eq!(step_round(quantity(45), 15, 0, law), Ok(quantity(45)));
    }
}
