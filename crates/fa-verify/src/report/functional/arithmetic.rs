//! Exact positive rational conversion with bounded, dependency-free arithmetic.
//!
//! A native mantissa has at most 127 bits, a rate term at most 128 and a
//! decimal scale factor at most 127. Eight limbs cover every supported
//! intermediate; output narrowing happens only after HalfEven.

use super::super::{ReportError, failed};
use core::cmp::Ordering;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Wide([u64; 8]);

impl Wide {
    const ZERO: Self = Self([0; 8]);

    fn from_u128(value: u128) -> Self {
        let mut out = Self::ZERO;
        out.0[0] = value as u64;
        out.0[1] = (value >> 64) as u64;
        out
    }

    fn compare(self, other: Self) -> Ordering {
        for (a, b) in self.0.iter().zip(other.0).rev() {
            match a.cmp(&b) {
                Ordering::Equal => {}
                order => return order,
            }
        }
        Ordering::Equal
    }

    fn add(self, other: Self) -> Option<Self> {
        let mut out = Self::ZERO;
        let mut carry = false;
        for (index, (&a, &b)) in self.0.iter().zip(&other.0).enumerate() {
            let (sum, first) = a.overflowing_add(b);
            let (sum, second) = sum.overflowing_add(u64::from(carry));
            out.0[index] = sum;
            carry = first || second;
        }
        (!carry).then_some(out)
    }

    fn sub(self, other: Self) -> Self {
        debug_assert!(self.compare(other) != Ordering::Less);
        let mut out = Self::ZERO;
        let mut borrow = false;
        for (index, (&a, &b)) in self.0.iter().zip(&other.0).enumerate() {
            let (difference, first) = a.overflowing_sub(b);
            let (difference, second) = difference.overflowing_sub(u64::from(borrow));
            out.0[index] = difference;
            borrow = first || second;
        }
        debug_assert!(!borrow);
        out
    }

    fn shift(self) -> Option<Self> {
        let mut out = Self::ZERO;
        let mut carry = 0;
        for (index, word) in self.0.into_iter().enumerate() {
            out.0[index] = (word << 1) | carry;
            carry = word >> 63;
        }
        (carry == 0).then_some(out)
    }

    fn multiply(self, mut factor: u128) -> Option<Self> {
        let mut out = Self::ZERO;
        let mut term = self;
        while factor != 0 {
            if factor & 1 != 0 {
                out = out.add(term)?;
            }
            factor >>= 1;
            if factor != 0 {
                term = term.shift()?;
            }
        }
        Some(out)
    }

    fn div_rem(self, divisor: Self) -> Option<(Self, Self)> {
        if divisor == Self::ZERO {
            return None;
        }
        let mut quotient = Self::ZERO;
        let mut remainder = Self::ZERO;
        for bit in (0..512).rev() {
            remainder = remainder.shift()?;
            remainder.0[0] |= (self.0[bit / 64] >> (bit % 64)) & 1;
            if remainder.compare(divisor) != Ordering::Less {
                remainder = remainder.sub(divisor);
                quotient.0[bit / 64] |= 1u64 << (bit % 64);
            }
        }
        Some((quotient, remainder))
    }

    fn as_i128(self) -> Option<i128> {
        if self.0[2..].iter().any(|word| *word != 0) || self.0[1] >> 63 != 0 {
            return None;
        }
        Some(((u128::from(self.0[1]) << 64) | u128::from(self.0[0])) as i128)
    }
}

pub(super) fn convert(
    amount: i128,
    quote_scale: u8,
    base_scale: u8,
    numerator: u128,
    denominator: u128,
) -> Result<i128, ReportError> {
    let invalid = || {
        failed(
            "functional_arithmetic",
            "invalid or overflowing exact FX conversion",
        )
    };
    if amount < 0 || quote_scale > 38 || base_scale > 38 || numerator == 0 || denominator == 0 {
        return Err(invalid());
    }
    let mut top = Wide::from_u128(amount as u128)
        .multiply(numerator)
        .ok_or_else(invalid)?;
    let mut bottom = Wide::from_u128(denominator);
    if base_scale >= quote_scale {
        top = top
            .multiply(10u128.pow(u32::from(base_scale - quote_scale)))
            .ok_or_else(invalid)?;
    } else {
        bottom = bottom
            .multiply(10u128.pow(u32::from(quote_scale - base_scale)))
            .ok_or_else(invalid)?;
    }
    let (mut quotient, remainder) = top.div_rem(bottom).ok_or_else(invalid)?;
    let comparison = remainder.compare(bottom.sub(remainder));
    if comparison == Ordering::Greater || comparison == Ordering::Equal && quotient.0[0] & 1 != 0 {
        quotient = quotient.add(Wide::from_u128(1)).ok_or_else(invalid)?;
    }
    quotient.as_i128().ok_or_else(invalid)
}

/// Hamilton allocation of a nonnegative closing value over strictly positive
/// native open amounts. A shared exact denominator makes remainder ordering
/// independent of narrowing; equal remainders retain the caller's canonical
/// item order. This is independent of the producer's money implementation.
pub(super) fn largest_remainder(total: i128, weights: &[i128]) -> Result<Vec<i128>, ReportError> {
    let invalid = || {
        failed(
            "functional_allocation",
            "invalid or overflowing exact open-item allocation",
        )
    };
    if total < 0
        || weights.is_empty()
        || weights.len() > 2048
        || weights.iter().any(|weight| *weight <= 0)
    {
        return Err(invalid());
    }
    let denominator = weights.iter().try_fold(Wide::ZERO, |sum, weight| {
        sum.add(Wide::from_u128(*weight as u128))
            .ok_or_else(invalid)
    })?;
    let mut shares = Vec::with_capacity(weights.len());
    let mut remainders = Vec::with_capacity(weights.len());
    let mut distributed = 0i128;
    for (index, weight) in weights.iter().enumerate() {
        let numerator = Wide::from_u128(total as u128)
            .multiply(*weight as u128)
            .ok_or_else(invalid)?;
        let (quotient, remainder) = numerator.div_rem(denominator).ok_or_else(invalid)?;
        let share = quotient.as_i128().ok_or_else(invalid)?;
        distributed = distributed.checked_add(share).ok_or_else(invalid)?;
        shares.push(share);
        remainders.push((index, remainder));
    }
    let remaining = total.checked_sub(distributed).ok_or_else(invalid)?;
    let remaining = usize::try_from(remaining).map_err(|_| invalid())?;
    if remaining >= weights.len() {
        return Err(invalid());
    }
    remainders.sort_unstable_by(|(left_index, left), (right_index, right)| {
        right
            .compare(*left)
            .then_with(|| left_index.cmp(right_index))
    });
    for (index, _) in remainders.into_iter().take(remaining) {
        shares[index] = shares[index].checked_add(1).ok_or_else(invalid)?;
    }
    Ok(shares)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_even_and_decimal_scales_are_exact() {
        for (amount, expected) in [(1, 0), (3, 2), (5, 2), (7, 4)] {
            assert_eq!(convert(amount, 2, 2, 1, 2).unwrap(), expected);
        }
        assert_eq!(convert(123, 0, 2, 5, 4).unwrap(), 15_375);
        assert_eq!(convert(15_375, 2, 0, 4, 5).unwrap(), 123);
        assert_eq!(convert(100, 2, 0, 1, 2).unwrap(), 0);
        assert_eq!(convert(300, 2, 0, 1, 2).unwrap(), 2);
    }

    #[test]
    fn full_width_intermediates_narrow_only_after_division_and_rounding() {
        assert_eq!(
            convert(i128::MAX, 38, 38, u128::MAX, u128::MAX).unwrap(),
            i128::MAX
        );
        assert_eq!(convert(i128::MAX, 38, 0, u128::MAX, u128::MAX).unwrap(), 2);
        assert_eq!(convert(1, 0, 38, 1, 1).unwrap(), 10i128.pow(38));
        assert!(convert(2, 0, 38, 1, 1).is_err());
        assert!(convert(i128::MAX, 0, 0, 2, 1).is_err());
        assert!(convert(-1, 2, 2, 1, 1).is_err());
        assert!(convert(1, 2, 2, 1, 0).is_err());
    }

    #[test]
    fn bounded_small_domain_matches_an_independent_integer_oracle() {
        for amount in 0..32i128 {
            for numerator in 1..17u128 {
                for denominator in 1..19u128 {
                    let value = amount as u128 * numerator;
                    let quotient = value / denominator;
                    let remainder = value % denominator;
                    let expected = quotient
                        + u128::from(
                            2 * remainder > denominator
                                || 2 * remainder == denominator && quotient & 1 != 0,
                        );
                    assert_eq!(
                        convert(amount, 3, 3, numerator, denominator).unwrap(),
                        expected as i128
                    );
                }
            }
        }
    }
    #[test]
    fn item_allocations_conserve_exact_totals_with_canonical_ties() {
        assert_eq!(largest_remainder(100, &[1, 1, 1]).unwrap(), [34, 33, 33]);
        assert_eq!(largest_remainder(100, &[1, 2, 3]).unwrap(), [17, 33, 50]);
        assert_eq!(largest_remainder(11, &[2, 3, 7]).unwrap(), [2, 3, 6]);
        assert_eq!(largest_remainder(2, &[1, 1, 1, 1]).unwrap(), [1, 1, 0, 0]);
        assert_eq!(largest_remainder(0, &[1, 7]).unwrap(), [0, 0]);
        let large = i128::MAX;
        assert_eq!(
            largest_remainder(large, &[large, large]).unwrap(),
            [large / 2 + 1, large / 2]
        );
        assert_eq!(
            largest_remainder(large, &[1, large - 1]).unwrap(),
            [1, large - 1]
        );
    }

    #[test]
    fn item_allocations_match_a_small_integer_oracle_and_refuse_invalid_domains() {
        for total in 0..24i128 {
            for weights in [[1, 1, 1], [1, 2, 3], [2, 1, 5], [7, 3, 2], [3, 9, 6]] {
                let divisor: i128 = weights.iter().sum();
                let mut expected: Vec<_> = weights.iter().map(|w| total * w / divisor).collect();
                let remainder_count = total - expected.iter().sum::<i128>();
                let mut priority: Vec<_> = (0..weights.len()).collect();
                priority.sort_by_key(|index| (-(total * weights[*index] % divisor), *index));
                for index in priority.into_iter().take(remainder_count as usize) {
                    expected[index] += 1;
                }
                let actual = largest_remainder(total, &weights).unwrap();
                assert_eq!(actual, expected);
                assert_eq!(actual.iter().sum::<i128>(), total);
                for (share, weight) in actual.iter().zip(weights) {
                    let floor = total * weight / divisor;
                    assert!(*share == floor || *share == floor + 1);
                }
            }
        }
        assert!(largest_remainder(-1, &[1]).is_err());
        assert!(largest_remainder(1, &[]).is_err());
        assert!(largest_remainder(1, &[0, 1]).is_err());
        assert!(largest_remainder(1, &[-1, 2]).is_err());
        assert!(largest_remainder(1, &[1; 2049]).is_err());
        let boundary = largest_remainder(2047, &[1; 2048]).unwrap();
        assert_eq!(boundary[..2047], [1; 2047]);
        assert_eq!(boundary[2047], 0);
    }
}
