//! Exact 256-bit intermediates for `mantissa × rate` and unit conversion.
//!
//! An `i128` mantissa times a `u128` numerator can need 256 bits; dividing that
//! by a `u128` denominator and rounding under a law needs the exact quotient
//! and remainder. Scale conversion and allocation weights can also require a
//! 256-bit denominator. This module provides checked multiplication, addition,
//! subtraction and division, comparison, and conversion back to `u128`.
//! Division uses shift-subtract arithmetic. Signs are handled by the callers.

use core::cmp::Ordering;

/// Unsigned 256-bit magnitude, `hi * 2^128 + lo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U256 {
    pub hi: u128,
    pub lo: u128,
}

impl U256 {
    pub const ZERO: Self = Self { hi: 0, lo: 0 };

    pub const fn from_u128(v: u128) -> Self {
        Self { hi: 0, lo: v }
    }

    pub const fn is_zero(self) -> bool {
        self.hi == 0 && self.lo == 0
    }

    /// `self * m`, or `None` on overflow past 256 bits.
    pub fn checked_mul_u128(self, m: u128) -> Option<Self> {
        let (lo_lo, lo_hi) = mul_u128(self.lo, m);
        let (hi_lo, hi_hi) = mul_u128(self.hi, m);
        if hi_hi != 0 {
            return None;
        }
        let hi = lo_hi.checked_add(hi_lo)?;
        Some(Self { hi, lo: lo_lo })
    }

    /// `self + o`, or `None` on overflow.
    pub fn checked_add(self, o: Self) -> Option<Self> {
        let (lo, carry) = self.lo.overflowing_add(o.lo);
        let hi = self.hi.checked_add(o.hi)?;
        let hi = hi.checked_add(u128::from(carry))?;
        Some(Self { hi, lo })
    }

    /// `self - o`, or `None` if `o > self`.
    pub fn checked_sub(self, o: Self) -> Option<Self> {
        if self < o {
            return None;
        }
        let (lo, borrow) = self.lo.overflowing_sub(o.lo);
        let hi = self.hi - o.hi - u128::from(borrow);
        Some(Self { hi, lo })
    }

    /// Exact `(quotient, remainder)` of `self / d`, or `None` for zero `d`.
    pub fn checked_div_rem(self, d: Self) -> Option<(Self, Self)> {
        if d.is_zero() {
            return None;
        }
        if self < d {
            return Some((Self::ZERO, self));
        }
        if self.hi == 0 && d.hi == 0 {
            return Some((
                Self::from_u128(self.lo / d.lo),
                Self::from_u128(self.lo % d.lo),
            ));
        }
        // Shift-subtract long division, one bit at a time, from the top.
        let mut quotient = Self::ZERO;
        let mut remainder = Self::ZERO;
        for i in (0..256).rev() {
            // The remainder never exceeds the already-consumed dividend
            // prefix. Before this shift that prefix has at most 255 bits,
            // so the next bit fits without an intermediate overflow.
            remainder.hi = (remainder.hi << 1) | (remainder.lo >> 127);
            remainder.lo = (remainder.lo << 1) | self.bit(i);
            if remainder >= d {
                remainder = remainder.checked_sub(d)?;
                quotient.set_bit(i);
            }
        }
        Some((quotient, remainder))
    }

    pub fn to_u128(self) -> Option<u128> {
        if self.hi == 0 { Some(self.lo) } else { None }
    }

    fn bit(self, i: u32) -> u128 {
        if i >= 128 {
            (self.hi >> (i - 128)) & 1
        } else {
            (self.lo >> i) & 1
        }
    }

    fn set_bit(&mut self, i: u32) {
        if i >= 128 {
            self.hi |= 1u128 << (i - 128);
        } else {
            self.lo |= 1u128 << i;
        }
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.hi, self.lo).cmp(&(other.hi, other.lo))
    }
}

/// Full 128×128 → 256 product as `(lo, hi)`.
fn mul_u128(a: u128, b: u128) -> (u128, u128) {
    const MASK: u128 = u64::MAX as u128;
    let (a0, a1) = (a & MASK, a >> 64);
    let (b0, b1) = (b & MASK, b >> 64);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    // middle = p01 + p10 + (p00 >> 64), may carry past 128 bits
    let (mid, c1) = p01.overflowing_add(p10);
    let (mid, c2) = mid.overflowing_add(p00 >> 64);
    let carry = u128::from(c1) + u128::from(c2);
    let lo = (p00 & MASK) | (mid << 64);
    let hi = p11 + (mid >> 64) + (carry << 64);
    (lo, hi)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgdb_bigint::{BigInt, LimbLimit, Sign};

    const ORACLE_LIMIT: LimbLimit = LimbLimit::new(16);

    fn bigint(value: U256) -> BigInt {
        let mut limbs = vec![
            value.lo as u64,
            (value.lo >> 64) as u64,
            value.hi as u64,
            (value.hi >> 64) as u64,
        ];
        while limbs.last() == Some(&0) {
            limbs.pop();
        }
        let sign = if limbs.is_empty() {
            Sign::Zero
        } else {
            Sign::Positive
        };
        BigInt::from_canonical_limbs(sign, limbs.into_boxed_slice(), ORACLE_LIMIT).unwrap()
    }

    fn narrow(value: &BigInt) -> Option<U256> {
        let limbs = value.magnitude_limbs_le();
        if value.is_negative() || limbs.len() > 4 {
            return None;
        }
        let limb = |i| u128::from(limbs.get(i).copied().unwrap_or(0));
        Some(U256 {
            lo: limb(0) | (limb(1) << 64),
            hi: limb(2) | (limb(3) << 64),
        })
    }

    fn compare_with_bigint(a: U256, b: U256) {
        let left = bigint(a);
        let right = bigint(b);
        assert_eq!(
            a.checked_add(b),
            narrow(&left.checked_add(&right, ORACLE_LIMIT).unwrap())
        );
        assert_eq!(
            a.checked_sub(b),
            narrow(&left.checked_sub(&right, ORACLE_LIMIT).unwrap())
        );
        let product = left
            .checked_mul(&BigInt::from_u128(b.lo), ORACLE_LIMIT)
            .unwrap();
        assert_eq!(a.checked_mul_u128(b.lo), narrow(&product));
        if b.is_zero() {
            assert_eq!(a.checked_div_rem(b), None);
            assert!(left.checked_div_rem(&right, ORACLE_LIMIT).is_err());
        } else {
            let (quotient, remainder) = left.checked_div_rem(&right, ORACLE_LIMIT).unwrap();
            assert_eq!(
                a.checked_div_rem(b),
                Some((narrow(&quotient).unwrap(), narrow(&remainder).unwrap()))
            );
        }
    }

    #[test]
    fn wide_operations_match_bigint_on_boundaries_and_seeded_values() {
        let boundary = [
            U256::ZERO,
            U256::from_u128(1),
            U256::from_u128(u128::MAX),
            U256 { hi: 1, lo: 0 },
            U256 {
                hi: 1,
                lo: u128::MAX,
            },
            U256 {
                hi: 1 << 127,
                lo: 0,
            },
            U256 {
                hi: u128::MAX,
                lo: u128::MAX,
            },
        ];
        for a in boundary {
            for b in boundary {
                compare_with_bigint(a, b);
            }
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            u128::from(state)
        };
        for _ in 0..512 {
            let a = U256 {
                hi: next() | (next() << 64),
                lo: next() | (next() << 64),
            };
            let b = U256 {
                hi: next() | (next() << 64),
                lo: next() | (next() << 64),
            };
            compare_with_bigint(a, b);
        }
    }

    #[test]
    fn mul_matches_u128_where_it_fits() {
        for &(a, b) in &[
            (0u128, 0u128),
            (1, u128::MAX),
            (u64::MAX as u128, u64::MAX as u128),
            (123_456_789, 987_654_321),
        ] {
            let (lo, hi) = mul_u128(a, b);
            if let Some(p) = a.checked_mul(b) {
                assert_eq!((lo, hi), (p, 0));
            } else {
                assert!(hi != 0);
            }
        }
    }

    #[test]
    fn div_rem_round_trips() {
        let cases: &[(u128, u128, u128)] = &[
            (u128::MAX, u128::MAX, 7),
            (u64::MAX as u128, 12345, 10),
            (1, 0, 3),
            (0, 1_000_000_007, 13),
            (u128::MAX, 0, u128::MAX),
        ];
        for &(a, m, d) in cases {
            let x = U256::from_u128(a).checked_mul_u128(m).unwrap();
            let (q, r) = x.checked_div_rem(U256::from_u128(d)).unwrap();
            assert!(r < U256::from_u128(d));
            let back = q.checked_mul_u128(d).unwrap().checked_add(r).unwrap();
            assert_eq!(
                back, x,
                "q*d + r must equal the dividend for a={a} m={m} d={d}"
            );
        }
    }

    #[test]
    fn overflow_is_detected() {
        let big = U256 {
            hi: u128::MAX,
            lo: u128::MAX,
        };
        assert!(big.checked_mul_u128(2).is_none());
        assert!(big.checked_add(U256::from_u128(1)).is_none());
        assert!(U256::ZERO.checked_sub(U256::from_u128(1)).is_none());
    }
}
