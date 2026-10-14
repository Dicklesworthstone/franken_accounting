//! Independent unsigned arithmetic for offline allocation checks. This is not
//! the producer's fa-money/U256 implementation: base-2^32 schoolbook products
//! and an aligned-divisor quotient over eight little-endian limbs.

use core::cmp::Ordering;
use super::AllocationError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Wide([u32; 8]);

impl Wide {
    pub(super) const ZERO: Self = Self([0; 8]);

    pub(super) fn of(value: u128) -> Self {
        let mut limbs = [0; 8];
        for (i, limb) in limbs.iter_mut().take(4).enumerate() {
            *limb = (value >> (32 * i)) as u32;
        }
        Self(limbs)
    }

    pub(super) fn add(self, rhs: Self) -> Result<Self, AllocationError> {
        let mut result = [0; 8];
        let mut carry = 0u64;
        for (i, limb) in result.iter_mut().enumerate() {
            let sum = u64::from(self.0[i]) + u64::from(rhs.0[i]) + carry;
            *limb = sum as u32;
            carry = sum >> 32;
        }
        if carry != 0 { return Err(AllocationError::Arithmetic); }
        Ok(Self(result))
    }

    pub(super) fn sub(self, rhs: Self) -> Result<Self, AllocationError> {
        let mut result = [0; 8];
        let mut borrow = 0u64;
        for (i, limb) in result.iter_mut().enumerate() {
            let left = u64::from(self.0[i]);
            let right = u64::from(rhs.0[i]) + borrow;
            *limb = left.wrapping_sub(right) as u32;
            borrow = u64::from(left < right);
        }
        if borrow != 0 { return Err(AllocationError::Arithmetic); }
        Ok(Self(result))
    }

    pub(super) fn product(left: u128, right: u128) -> Self {
        let a = Self::of(left);
        let b = Self::of(right);
        let mut limbs = [0u32; 8];
        for i in 0..4 {
            let mut carry = 0u64;
            for j in 0..4 {
                // (B-1)^2 + (B-1) + (B-1) <= u64::MAX, B=2^32.
                let value = u64::from(a.0[i]) * u64::from(b.0[j])
                    + u64::from(limbs[i + j]) + carry;
                limbs[i + j] = value as u32;
                carry = value >> 32;
            }
            // This cell has not been touched by any earlier outer iteration.
            limbs[i + 4] = carry as u32;
        }
        Self(limbs)
    }

    fn bits(self) -> usize {
        self.0.iter().rposition(|limb| *limb != 0)
            .map_or(0, |i| 32 * i + (32 - self.0[i].leading_zeros()) as usize)
    }

    fn shifted(self, bits: usize) -> Self {
        let mut limbs = [0u32; 8];
        let whole = bits / 32;
        let part = bits % 32;
        for i in whole..8 {
            limbs[i] = self.0[i - whole] << part;
            if part != 0 && i > whole {
                limbs[i] |= self.0[i - whole - 1] >> (32 - part);
            }
        }
        Self(limbs)
    }

    pub(super) fn div_rem(self, divisor: Self) -> Result<(Self, Self), AllocationError> {
        if divisor == Self::ZERO { return Err(AllocationError::Arithmetic); }
        let mut remainder = self;
        let mut quotient = Self::ZERO;
        if self < divisor { return Ok((quotient, remainder)); }
        let shift = self.bits() - divisor.bits();
        for bit in (0..=shift).rev() {
            // The initial alignment fits the dividend's highest bit; every
            // subsequent shift is smaller. No significant bit is truncated.
            let trial = divisor.shifted(bit);
            if remainder >= trial {
                remainder = remainder.sub(trial)?;
                quotient.0[bit / 32] |= 1u32 << (bit % 32);
            }
        }
        Ok((quotient, remainder))
    }

    pub(super) fn narrow(self) -> Result<u128, AllocationError> {
        if self.0[4..].iter().any(|limb| *limb != 0) {
            return Err(AllocationError::Arithmetic);
        }
        Ok(self.0[..4].iter().enumerate()
            .fold(0u128, |value, (i, limb)| value | (u128::from(*limb) << (32 * i))))
    }
}

impl Ord for Wide {
    fn cmp(&self, rhs: &Self) -> Ordering {
        self.0.iter().rev().cmp(rhs.0.iter().rev())
    }
}
impl PartialOrd for Wide {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> { Some(self.cmp(rhs)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_products_quotients_and_carries_cover_unsigned_boundaries() {
        let max = Wide::of(u128::MAX);
        let square = Wide::product(u128::MAX, u128::MAX);
        assert_eq!(square.div_rem(max).unwrap(), (max, Wide::ZERO));
        let sum = max.add(max).unwrap();
        assert_eq!(sum.div_rem(Wide::of(2)).unwrap(), (max, Wide::ZERO));
        assert_eq!(sum.sub(max).unwrap(), max);
        assert!(Wide::ZERO.sub(max).is_err());
        assert!(max.div_rem(Wide::ZERO).is_err());
        assert!(square.narrow().is_err());
        assert_eq!(square.div_rem(sum).unwrap(), (
            Wide::of(u128::MAX / 2), max,
        ));
        assert!(Wide([u32::MAX; 8]).add(Wide::of(1)).is_err());
    }

    #[test]
    fn bounded_products_and_division_match_native_arithmetic() {
        for left in [0u128, 1, 7, u64::MAX as u128, 1u128 << 64] {
            for right in [0u128, 1, 3, u32::MAX as u128] {
                let product = left * right;
                assert_eq!(Wide::product(left, right).narrow().unwrap(), product);
                for divisor in [1, 2, 7, u64::MAX as u128] {
                    let (q, r) = Wide::of(product).div_rem(Wide::of(divisor)).unwrap();
                    assert_eq!((q.narrow().unwrap(), r.narrow().unwrap()),
                        (product / divisor, product % divisor));
                }
            }
        }
    }
}
