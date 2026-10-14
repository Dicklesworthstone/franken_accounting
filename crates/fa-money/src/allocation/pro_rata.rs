//! Exact pro-rata allocation with a caller-named residual recipient (§6.3).

use crate::amount::{Amount, AmountError, signed_magnitude};
use crate::rounding::RoundingLaw;
use crate::wide::U256;

/// An explicit rounding transcript, not a posting authorization or a proof
/// that the caller's driver weights are supported by evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProRataAllocation {
    pub total: Amount,
    pub rounding_law: RoundingLaw,
    pub residual_target: usize,
    /// Each exact weighted share rounded independently under rounding_law.
    pub rounded_shares: Vec<Amount>,
    /// total minus the exact sum of rounded_shares, in total.unit. This may
    /// oppose total's sign when independent rounding over-allocates.
    pub residual: Amount,
    /// rounded_shares with residual added only to residual_target. These
    /// sum exactly to total; neither a clamp nor a second distribution occurs.
    pub shares: Vec<Amount>,
}

/// Round every exact `total * weight / sum(weights)` under the named law,
/// then assign the entire signed rounding residual to `residual_target`.
/// All weights are unsigned; at least one must be nonzero. A zero-weight
/// target can receive a correction only when explicitly named as recipient.
/// Target order and the rounding law are part of the caller's replay basis.
///
/// The result preserves both the independently rounded shares and the signed
/// correction. With coarse units, the correction may exceed the recipient's
/// rounded share and reverse its sign: 1 split three ways under Ceiling,
/// with target 0, gives rounded [1, 1, 1], residual -2, final [-1, 1, 1].
/// That is an explicit consequence of this law, not a hidden auto-balance.
/// Callers must not discard the transcript or infer permission to post a
/// negative leg. LargestRemainder is a different, sign-preserving law.
///
/// Weight sums, products, remainders and the rounded aggregate remain U256.
/// In particular, an intermediate sum above i128::MAX does not invalidate a
/// representable final allocation. No float, rate approximation or narrowing
/// of the exact fractional remainder participates in a rounding decision.
pub fn pro_rata_residual_to_named(
    total: Amount,
    weights: &[u128],
    residual_target: usize,
    rounding_law: RoundingLaw,
) -> Result<ProRataAllocation, AmountError> {
    if residual_target >= weights.len() {
        return Err(AmountError::Malformed(
            "pro-rata residual target is outside the allocation target list".into(),
        ));
    }
    let denominator = weights
        .iter()
        .try_fold(U256::ZERO, |sum, weight| {
            sum.checked_add(U256::from_u128(*weight))
        })
        .ok_or(AmountError::Overflow)?;
    if denominator.is_zero() {
        return Err(AmountError::Malformed(
            "allocation weights sum to zero".into(),
        ));
    }
    let negative = total.mantissa < 0;
    let magnitude = U256::from_u128(total.mantissa.unsigned_abs());
    let mut rounded_sum = U256::ZERO;
    let mut rounded_shares = Vec::new();
    rounded_shares
        .try_reserve_exact(weights.len())
        .map_err(|_| AmountError::Overflow)?;
    for weight in weights {
        let (quotient, remainder) = magnitude
            .checked_mul_u128(*weight)
            .ok_or(AmountError::Overflow)?
            .checked_div_rem(denominator)
            .ok_or(AmountError::InvariantViolation("zero allocation divisor"))?;
        let complement =
            denominator
                .checked_sub(remainder)
                .ok_or(AmountError::InvariantViolation(
                    "allocation remainder exceeds its denominator",
                ))?;
        let rounded = rounding_law
            .apply_fraction(
                quotient.to_u128().ok_or(AmountError::Overflow)?,
                !remainder.is_zero(),
                remainder.cmp(&complement),
                negative,
            )
            .ok_or(AmountError::Overflow)?;
        rounded_sum = rounded_sum
            .checked_add(U256::from_u128(rounded))
            .ok_or(AmountError::Overflow)?;
        rounded_shares.push(Amount::new(
            total.unit,
            signed_magnitude(rounded, negative)?,
        ));
    }
    let (difference, residual_negative) = if magnitude >= rounded_sum {
        (magnitude.checked_sub(rounded_sum), negative)
    } else {
        (rounded_sum.checked_sub(magnitude), !negative)
    };
    let difference = difference
        .ok_or(AmountError::InvariantViolation(
            "invalid allocation difference",
        ))?
        .to_u128()
        .ok_or(AmountError::Overflow)?;
    let residual = Amount::new(total.unit, signed_magnitude(difference, residual_negative)?);
    let mut shares = Vec::new();
    shares
        .try_reserve_exact(rounded_shares.len())
        .map_err(|_| AmountError::Overflow)?;
    shares.extend_from_slice(&rounded_shares);
    shares[residual_target].mantissa = shares[residual_target]
        .mantissa
        .checked_add(residual.mantissa)
        .ok_or(AmountError::Overflow)?;
    Ok(ProRataAllocation {
        total,
        rounding_law,
        residual_target,
        rounded_shares,
        residual,
        shares,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::UnitId;

    fn values(shares: &[Amount]) -> Vec<i128> {
        shares.iter().map(|share| share.mantissa).collect()
    }

    fn allocate(
        total: i128,
        weights: &[u128],
        target: usize,
        law: RoundingLaw,
    ) -> ProRataAllocation {
        pro_rata_residual_to_named(Amount::new(UnitId(7), total), weights, target, law).unwrap()
    }

    #[test]
    fn every_signed_tie_law_keeps_its_registered_meaning() {
        let cases = [
            (RoundingLaw::HalfUp, 3, -2),
            (RoundingLaw::HalfDown, 2, -3),
            (RoundingLaw::HalfEven, 2, -2),
            (RoundingLaw::HalfAwayFromZero, 3, -3),
            (RoundingLaw::HalfTowardZero, 2, -2),
            (RoundingLaw::Ceiling, 3, -2),
            (RoundingLaw::Floor, 2, -3),
            (RoundingLaw::TowardZero, 2, -2),
            (RoundingLaw::AwayFromZero, 3, -3),
        ];
        for (law, positive, negative) in cases {
            for (total, rounded) in [(5, positive), (-5, negative)] {
                let allocation = allocate(total, &[1, 1], 1, law);
                assert_eq!(values(&allocation.rounded_shares), [rounded, rounded]);
                assert_eq!(allocation.residual.mantissa, total - 2 * rounded);
                assert_eq!(values(&allocation.shares), [rounded, total - rounded]);
                assert_eq!(allocation.rounding_law, law);
                assert_eq!(allocation.residual_target, 1);
                assert_eq!(allocation.total, Amount::new(UnitId(7), total));
            }
        }
    }

    #[test]
    fn named_residual_is_not_silently_clamped_or_redistributed() {
        let allocation = allocate(1, &[1, 1, 1], 0, RoundingLaw::Ceiling);
        assert_eq!(values(&allocation.rounded_shares), [1, 1, 1]);
        assert_eq!(allocation.residual.mantissa, -2);
        assert_eq!(values(&allocation.shares), [-1, 1, 1]);
        let negative = allocate(-1, &[1, 1, 1], 2, RoundingLaw::Floor);
        assert_eq!(values(&negative.rounded_shares), [-1, -1, -1]);
        assert_eq!(negative.residual.mantissa, 2);
        assert_eq!(values(&negative.shares), [-1, -1, 1]);
    }

    #[test]
    fn a_zero_weight_moves_only_when_explicitly_named() {
        let allocation = allocate(1, &[1, 1, 0, 0], 2, RoundingLaw::TowardZero);
        assert_eq!(values(&allocation.rounded_shares), [0, 0, 0, 0]);
        assert_eq!(values(&allocation.shares), [0, 0, 1, 0]);
        assert_eq!(allocation.residual, Amount::new(UnitId(7), 1));
    }

    #[test]
    fn wide_denominators_and_rounded_totals_do_not_narrow_early() {
        let allocation = allocate(7, &[u128::MAX, u128::MAX], 0, RoundingLaw::HalfEven);
        assert_eq!(values(&allocation.rounded_shares), [4, 4]);
        assert_eq!(values(&allocation.shares), [3, 4]);
        assert_eq!(allocation.residual.mantissa, -1);

        // The individually rounded sum is 2^127, one above i128::MAX.
        let allocation = allocate(i128::MAX, &[1, 1], 0, RoundingLaw::HalfEven);
        let half = 1i128 << 126;
        assert_eq!(values(&allocation.rounded_shares), [half, half]);
        assert_eq!(values(&allocation.shares), [half - 1, half]);
        assert_eq!(allocation.residual.mantissa, -1);

        // abs(MIN) / 3 has remainder 2: Floor produces an aggregate whose
        // magnitude exceeds abs(MIN). Only the final residual is narrowed.
        let allocation = allocate(i128::MIN, &[1, 1, 1], 1, RoundingLaw::Floor);
        let rounded = i128::MIN / 3 - 1;
        assert_eq!(values(&allocation.rounded_shares), [rounded; 3]);
        assert_eq!(allocation.residual.mantissa, 1);
        assert_eq!(values(&allocation.shares), [rounded, rounded + 1, rounded]);
        assert_eq!(
            allocation
                .shares
                .iter()
                .map(|share| share.mantissa)
                .sum::<i128>(),
            i128::MIN
        );
    }

    #[test]
    fn exact_values_and_single_targets_need_no_residual() {
        for total in [i128::MIN, -i128::MAX, -1, 0, 1, i128::MAX] {
            for law in RoundingLaw::ALL {
                let allocation = allocate(total, &[u128::MAX], 0, law);
                assert_eq!(values(&allocation.rounded_shares), [total]);
                assert_eq!(values(&allocation.shares), [total]);
                assert_eq!(allocation.residual, Amount::zero(UnitId(7)));
            }
        }
        for law in RoundingLaw::ALL {
            let allocation = allocate(-120, &[1, 2, 3], 2, law);
            assert_eq!(values(&allocation.rounded_shares), [-20, -40, -60]);
            assert_eq!(allocation.shares, allocation.rounded_shares);
            assert_eq!(allocation.residual.mantissa, 0);
        }
    }

    // Independent small-rational oracle: choose between the signed floor
    // and ceiling using exact distances, not the production magnitude path.
    fn round_small(numerator: i128, denominator: i128, law: RoundingLaw) -> i128 {
        let lower = numerator.div_euclid(denominator);
        let remainder = numerator.rem_euclid(denominator);
        if remainder == 0 {
            return lower;
        }
        let upper = lower + 1;
        match law {
            RoundingLaw::Floor => lower,
            RoundingLaw::Ceiling => upper,
            RoundingLaw::TowardZero => {
                if numerator < 0 {
                    upper
                } else {
                    lower
                }
            }
            RoundingLaw::AwayFromZero => {
                if numerator < 0 {
                    lower
                } else {
                    upper
                }
            }
            _ => match (2 * remainder).cmp(&denominator) {
                core::cmp::Ordering::Less => lower,
                core::cmp::Ordering::Greater => upper,
                core::cmp::Ordering::Equal => match law {
                    RoundingLaw::HalfUp => upper,
                    RoundingLaw::HalfDown => lower,
                    RoundingLaw::HalfEven => {
                        if lower % 2 == 0 {
                            lower
                        } else {
                            upper
                        }
                    }
                    RoundingLaw::HalfAwayFromZero => {
                        if numerator < 0 {
                            lower
                        } else {
                            upper
                        }
                    }
                    RoundingLaw::HalfTowardZero => {
                        if numerator < 0 {
                            upper
                        } else {
                            lower
                        }
                    }
                    _ => unreachable!("directed laws handled above"),
                },
            },
        }
    }

    #[test]
    fn complete_small_grid_matches_an_independent_signed_rational_oracle() {
        for a in 0u128..=3 {
            for b in 0u128..=3 {
                for c in 0u128..=3 {
                    let weights = [a, b, c];
                    if a + b + c == 0 {
                        continue;
                    }
                    let denominator = i128::try_from(a + b + c).unwrap();
                    for total in -13i128..=13 {
                        for law in RoundingLaw::ALL {
                            let expected: Vec<_> = weights
                                .iter()
                                .map(|weight| {
                                    round_small(
                                        total * i128::try_from(*weight).unwrap(),
                                        denominator,
                                        law,
                                    )
                                })
                                .collect();
                            let residual = total - expected.iter().sum::<i128>();
                            for target in 0..3 {
                                let allocation = allocate(total, &weights, target, law);
                                assert_eq!(values(&allocation.rounded_shares), expected);
                                assert_eq!(allocation.residual.mantissa, residual);
                                for (index, share) in allocation.shares.iter().enumerate() {
                                    let correction = if index == target { residual } else { 0 };
                                    assert_eq!(share.mantissa, expected[index] + correction);
                                    assert_eq!(share.unit, UnitId(7));
                                }
                                assert_eq!(
                                    allocation
                                        .shares
                                        .iter()
                                        .map(|share| share.mantissa)
                                        .sum::<i128>(),
                                    total
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn malformed_bases_and_out_of_range_recipients_are_refused() {
        for total in [0, 1, -1] {
            for (weights, target) in [
                (vec![], 0),
                (vec![0, 0], 0),
                (vec![1, 2], 2),
                (vec![1], usize::MAX),
            ] {
                assert!(matches!(
                    pro_rata_residual_to_named(
                        Amount::new(UnitId(7), total),
                        &weights,
                        target,
                        RoundingLaw::HalfEven
                    ),
                    Err(AmountError::Malformed(_))
                ));
            }
        }
    }
}
