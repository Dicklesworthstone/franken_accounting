//! Ordered allocation laws from plan §6.3. These are pure arithmetic: the
//! caller chooses the target order and records the law and basis in its
//! evidence. No target, residual account, or journal entry is inferred here.

use crate::amount::{Amount, AmountError, signed_magnitude};

/// Split equally by truncating each share toward zero, then give **all**
/// remaining native mantissa units to the first target.
///
/// This is deliberately not largest-remainder allocation with equal weights:
/// splitting 2 among 5 targets returns [2, 0, 0, 0, 0], not [1, 1, 0, 0, 0].
/// The first target is the caller's explicit residual recipient. Input order
/// is therefore part of the allocation basis and must be retained for replay.
/// Negative totals allocate their magnitude and restore the sign, including
/// i128::MIN. An empty target list refuses even when the total is zero.
pub fn equal_split_residual_first(
    total: Amount,
    target_count: usize,
) -> Result<Vec<Amount>, AmountError> {
    if target_count == 0 {
        return Err(AmountError::Malformed(
            "equal split requires at least one target".into(),
        ));
    }
    let count = u128::try_from(target_count).map_err(|_| AmountError::Overflow)?;
    let magnitude = total.mantissa.unsigned_abs();
    let quotient = magnitude / count;
    let remainder = magnitude % count;
    let negative = total.mantissa < 0;
    let ordinary = Amount::new(total.unit, signed_magnitude(quotient, negative)?);
    let first = quotient.checked_add(remainder).ok_or(AmountError::Overflow)?;
    let mut shares = vec![ordinary; target_count];
    shares[0] = Amount::new(total.unit, signed_magnitude(first, negative)?);
    Ok(shares)
}

/// Fill targets in caller-supplied priority order, up to each target's cap.
/// Caps are unsigned native mantissa magnitudes in `total.unit`; zero caps
/// are valid and receive zero. Negative totals use the same priority order
/// and caps, then restore the sign of each share.
///
/// The complete total must fit the supplied capacity. Insufficient capacity
/// is a refusal, never a partial allocation or an implicit overflow target.
/// No capacity sum is formed: even caps whose sum exceeds u128::MAX work.
/// An empty target list refuses even when the total is zero.
pub fn waterfall(total: Amount, caps: &[u128]) -> Result<Vec<Amount>, AmountError> {
    if caps.is_empty() {
        return Err(AmountError::Malformed(
            "waterfall requires at least one target".into(),
        ));
    }
    let magnitude = total.mantissa.unsigned_abs();
    let uncovered = caps
        .iter()
        .fold(magnitude, |remaining, cap| remaining.saturating_sub(*cap));
    if uncovered != 0 {
        return Err(AmountError::Malformed(format!(
            "waterfall capacity is short by {uncovered} native mantissa units"
        )));
    }
    let negative = total.mantissa < 0;
    let mut remaining = magnitude;
    let mut shares = Vec::with_capacity(caps.len());
    for cap in caps {
        let share = remaining.min(*cap);
        remaining -= share;
        shares.push(Amount::new(total.unit, signed_magnitude(share, negative)?));
    }
    Ok(shares)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allocation::largest_remainder;
    use crate::unit::UnitId;

    fn amounts(values: &[i128]) -> Vec<Amount> {
        values
            .iter()
            .map(|value| Amount::new(UnitId(7), *value))
            .collect()
    }

    #[test]
    fn equal_split_assigns_the_entire_residual_to_the_first_target() {
        assert_eq!(
            equal_split_residual_first(Amount::new(UnitId(7), 100), 3),
            Ok(amounts(&[34, 33, 33]))
        );
        assert_eq!(
            equal_split_residual_first(Amount::new(UnitId(7), 2), 5),
            Ok(amounts(&[2, 0, 0, 0, 0]))
        );
        assert_eq!(
            equal_split_residual_first(Amount::new(UnitId(7), -2), 5),
            Ok(amounts(&[-2, 0, 0, 0, 0]))
        );
        assert_eq!(
            largest_remainder(Amount::new(UnitId(7), 2), &[1; 5]),
            Ok(amounts(&[1, 1, 0, 0, 0]))
        );
    }

    #[test]
    fn equal_split_conserves_and_preserves_sign_on_a_grid() {
        for total in -100i128..=100 {
            for count in 1usize..=32 {
                let shares =
                    equal_split_residual_first(Amount::new(UnitId(7), total), count).unwrap();
                assert_eq!(shares.len(), count);
                assert_eq!(shares.iter().map(|share| share.mantissa).sum::<i128>(), total);
                let quotient = total / i128::try_from(count).unwrap();
                assert!(shares[1..].iter().all(|share| share.mantissa == quotient));
                assert_eq!(
                    shares[0].mantissa - quotient,
                    total % i128::try_from(count).unwrap()
                );
                assert!(shares.iter().all(|share| share.unit == UnitId(7)));
                assert!(shares.iter().all(|share| {
                    share.mantissa == 0 || share.mantissa.signum() == total.signum()
                }));
            }
        }
    }

    #[test]
    fn ordered_laws_handle_the_complete_signed_amount_domain() {
        for total in [i128::MIN, -i128::MAX, -1, 0, 1, i128::MAX] {
            let amount = Amount::new(UnitId(7), total);
            assert_eq!(equal_split_residual_first(amount, 1), Ok(vec![amount]));
            assert_eq!(waterfall(amount, &[u128::MAX]), Ok(vec![amount]));
            for count in [2usize, 3, 17] {
                let shares = equal_split_residual_first(amount, count).unwrap();
                assert_eq!(shares.iter().map(|share| share.mantissa).sum::<i128>(), total);
            }
            assert_eq!(
                waterfall(amount, &[0, u128::MAX, u128::MAX]),
                Ok(vec![Amount::zero(UnitId(7)), amount, Amount::zero(UnitId(7))])
            );
        }
    }

    #[test]
    fn waterfall_obeys_priority_and_zero_caps() {
        assert_eq!(
            waterfall(Amount::new(UnitId(7), 100), &[30, 0, 50, 100]),
            Ok(amounts(&[30, 0, 50, 20]))
        );
        assert_eq!(
            waterfall(Amount::new(UnitId(7), -100), &[30, 0, 50, 100]),
            Ok(amounts(&[-30, 0, -50, -20]))
        );
        assert_eq!(
            waterfall(Amount::zero(UnitId(7)), &[0, 0]),
            Ok(amounts(&[0, 0]))
        );
        assert!(waterfall(Amount::new(UnitId(7), 181), &[30, 50, 100]).is_err());
        assert!(waterfall(Amount::new(UnitId(7), -181), &[30, 50, 100]).is_err());
    }

    #[test]
    fn waterfall_matches_cumulative_capacity_intersections() {
        // Independent formulation: target i receives the length of the
        // intersection of [0, abs(total)) and its cumulative capacity band.
        for a in 0u128..=5 {
            for b in 0u128..=5 {
                for c in 0u128..=5 {
                    let caps = [a, b, c];
                    for total in -18i128..=18 {
                        let result = waterfall(Amount::new(UnitId(7), total), &caps);
                        if total.unsigned_abs() > a + b + c {
                            assert!(result.is_err());
                            continue;
                        }
                        let shares = result.unwrap();
                        let mut band_start = 0u128;
                        for (share, cap) in shares.iter().zip(caps) {
                            let band_end = band_start + cap;
                            let expected = total.unsigned_abs().min(band_end)
                                - total.unsigned_abs().min(band_start);
                            assert_eq!(share.mantissa.unsigned_abs(), expected);
                            assert_eq!(share.unit, UnitId(7));
                            assert!(
                                share.mantissa == 0 || share.mantissa.signum() == total.signum()
                            );
                            band_start = band_end;
                        }
                        assert_eq!(shares.iter().map(|share| share.mantissa).sum::<i128>(), total);
                    }
                }
            }
        }
    }

    #[test]
    fn empty_target_sets_are_refused_even_for_zero() {
        for total in [0, 1, -1] {
            let amount = Amount::new(UnitId(7), total);
            assert!(equal_split_residual_first(amount, 0).is_err());
            assert!(waterfall(amount, &[]).is_err());
        }
    }
}
