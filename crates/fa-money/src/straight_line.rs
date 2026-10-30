//! Finite straight-line depreciation and amortization (plan §10.2, Appendix B).
//!
//! Round the cumulative cost allocation once under the named law. A native
//! posting derives its charge by subtracting previously recognized amounts
//! from this target. Consequently catch-up and regularly posted schedules
//! have the same cumulative amount, and the last target is exactly cost
//! less salvage. No independently rounded monthly installment can drift.

mod fraction;

use crate::{Amount, AmountError, RoundingLaw};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StraightLineError {
    Invalid(&'static str),
    Amount(AmountError),
}

impl core::fmt::Display for StraightLineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "invalid straight-line schedule: {reason}"),
            Self::Amount(error) => error.fmt(f),
        }
    }
}
impl core::error::Error for StraightLineError {}
impl From<AmountError> for StraightLineError {
    fn from(error: AmountError) -> Self {
        Self::Amount(error)
    }
}

/// Version-1 cumulative straight-line allocation in the acquisition's unit.
/// `elapsed_periods` counts complete scheduled fiscal periods, including the
/// first one, and must be in `0..=useful_life_periods`. Cost and salvage are
/// nonnegative; salvage cannot exceed cost. There is no inferred rounding.
///
/// The computation performs a fixed number of checked scalar operations,
/// allocates no memory and accepts the full nonnegative i128 amount range.
pub fn cumulative(
    cost: Amount,
    salvage: Amount,
    elapsed_periods: u32,
    useful_life_periods: u32,
    rounding: RoundingLaw,
) -> Result<Amount, StraightLineError> {
    if cost.unit != salvage.unit {
        return Err(AmountError::UnitMismatch {
            left: cost.unit,
            right: salvage.unit,
        }
        .into());
    }
    if cost.mantissa < 0 || salvage.mantissa < 0 || salvage.mantissa > cost.mantissa {
        return Err(StraightLineError::Invalid(
            "cost and salvage must satisfy 0 <= salvage <= cost",
        ));
    }
    if useful_life_periods == 0 || elapsed_periods > useful_life_periods {
        return Err(StraightLineError::Invalid(
            "life must be positive and elapsed periods cannot exceed life",
        ));
    }
    let basis = cost
        .mantissa
        .checked_sub(salvage.mantissa)
        .and_then(|value| u128::try_from(value).ok())
        .ok_or(AmountError::Overflow)?;
    let (quotient, remainder) =
        fraction::cumulative_fraction(basis, elapsed_periods, useful_life_periods)
            .ok_or(AmountError::Overflow)?;
    let rounded = rounding
        .apply_magnitude(quotient, remainder, u128::from(useful_life_periods), false)
        .ok_or(AmountError::Overflow)?;
    let mantissa = i128::try_from(rounded).map_err(|_| AmountError::Overflow)?;
    Ok(Amount::new(cost.unit, mantissa))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UnitId;

    fn amount(value: i128) -> Amount {
        Amount::new(UnitId(1), value)
    }

    fn scalar_oracle(basis: i128, elapsed: u32, life: u32, law: RoundingLaw) -> i128 {
        let numerator = basis.checked_mul(i128::from(elapsed)).unwrap();
        let denominator = i128::from(life);
        let q = numerator.checked_div(denominator).unwrap();
        let r = numerator.checked_rem(denominator).unwrap();
        let doubled = r.checked_mul(2).unwrap();
        let increase = match law {
            RoundingLaw::HalfUp | RoundingLaw::HalfAwayFromZero => doubled >= denominator,
            RoundingLaw::HalfDown | RoundingLaw::HalfTowardZero => doubled > denominator,
            RoundingLaw::HalfEven => {
                doubled > denominator || doubled == denominator && q.checked_rem(2).unwrap() == 1
            }
            RoundingLaw::Ceiling | RoundingLaw::AwayFromZero => r != 0,
            RoundingLaw::Floor | RoundingLaw::TowardZero => false,
        };
        q.checked_add(i128::from(increase)).unwrap()
    }

    #[test]
    fn every_named_rounding_law_matches_independent_scalar_oracle() {
        for basis in 0_i128..=31 {
            for salvage in [0, 13] {
                for life in 1..=12 {
                    for elapsed in 0..=life {
                        for law in RoundingLaw::ALL {
                            let cost = basis.checked_add(salvage).unwrap();
                            assert_eq!(
                                cumulative(amount(cost), amount(salvage), elapsed, life, law)
                                    .unwrap()
                                    .mantissa,
                                scalar_oracle(basis, elapsed, life, law),
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn cumulative_rounding_preserves_final_residual_and_catch_up() {
        let targets: Vec<_> = (0..=3)
            .map(|elapsed| {
                cumulative(amount(107), amount(7), elapsed, 3, RoundingLaw::HalfEven)
                    .unwrap()
                    .mantissa
            })
            .collect();
        assert_eq!(targets, [0, 33, 67, 100]);
        let charges: Vec<_> = targets
            .windows(2)
            .map(|pair| pair[1].checked_sub(pair[0]).unwrap())
            .collect();
        assert_eq!(charges, [33, 34, 33]);
        assert_eq!(
            targets[3].checked_sub(targets[1]).unwrap(),
            charges[1].checked_add(charges[2]).unwrap()
        );
    }

    #[test]
    fn all_laws_telescope_without_overdepreciating_full_width_cost() {
        let basis = i128::MAX.checked_sub(29).unwrap();
        for law in RoundingLaw::ALL {
            let mut prior = 0_i128;
            let mut recognized = 0_i128;
            for elapsed in 0..=1200 {
                let target = cumulative(amount(i128::MAX), amount(29), elapsed, 1200, law)
                    .unwrap()
                    .mantissa;
                assert!(prior <= target && target <= basis);
                recognized = recognized
                    .checked_add(target.checked_sub(prior).unwrap())
                    .unwrap();
                prior = target;
            }
            assert_eq!(recognized, basis);
        }
        assert_eq!(
            cumulative(
                amount(i128::MAX),
                amount(0),
                u32::MAX,
                u32::MAX,
                RoundingLaw::Ceiling
            )
            .unwrap(),
            amount(i128::MAX)
        );
    }

    #[test]
    fn invalid_basis_units_and_coordinates_are_refused() {
        for (cost, salvage, elapsed, life) in [
            (-1, 0, 1, 12),
            (1, -1, 1, 12),
            (1, 2, 1, 12),
            (1, 0, 0, 0),
            (1, 0, 13, 12),
        ] {
            assert!(
                cumulative(
                    amount(cost),
                    amount(salvage),
                    elapsed,
                    life,
                    RoundingLaw::HalfEven
                )
                .is_err()
            );
        }
        assert!(
            cumulative(
                amount(1),
                Amount::new(UnitId(2), 0),
                1,
                12,
                RoundingLaw::HalfEven
            )
            .is_err()
        );
        assert_eq!(
            cumulative(amount(7), amount(7), 12, 12, RoundingLaw::Ceiling).unwrap(),
            amount(0)
        );
    }
}
