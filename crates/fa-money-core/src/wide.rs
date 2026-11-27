//! Exact 256-bit intermediates for allocation weights and bounded integer work.
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

    /// The full product `a * b`, which always fits in 256 bits.
    pub fn from_product(a: u128, b: u128) -> Self {
        let (lo, hi) = mul_u128(a, b);
        Self { hi, lo }
    }

    /// The integer square root: the largest `r` with `r * r <= self`. Every
    /// 256-bit value has its root below `2^128`.
    #[allow(clippy::arithmetic_side_effects)] // limb arithmetic bounded as each comment states
    pub fn isqrt(self) -> u128 {
        let (mut low, mut high) = (0u128, u128::MAX);
        while low < high {
            // The upper midpoint, so the search always advances.
            let mid = high - (high - low) / 2;
            if Self::from_product(mid, mid) <= self {
                low = mid;
            } else {
                high = mid - 1;
            }
        }
        low
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
    #[allow(clippy::arithmetic_side_effects)] // limb arithmetic bounded as each comment states
    pub fn checked_sub(self, o: Self) -> Option<Self> {
        if self < o {
            return None;
        }
        let (lo, borrow) = self.lo.overflowing_sub(o.lo);
        let hi = self.hi - o.hi - u128::from(borrow);
        Some(Self { hi, lo })
    }

    /// Exact `(quotient, remainder)` of `self / d`, or `None` for zero `d`.
    #[allow(clippy::arithmetic_side_effects)] // limb arithmetic bounded as each comment states
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

    #[allow(clippy::arithmetic_side_effects)] // limb arithmetic bounded as each comment states
    fn bit(self, i: u32) -> u128 {
        if i >= 128 {
            (self.hi >> (i - 128)) & 1
        } else {
            (self.lo >> i) & 1
        }
    }

    #[allow(clippy::arithmetic_side_effects)] // limb arithmetic bounded as each comment states
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

/// Full 128×128 → 256 product as `(lo, hi)`. Each partial product of 64-bit
/// halves fits 128 bits, and the high word of a 256-bit product cannot carry.
#[allow(clippy::arithmetic_side_effects)] // limb arithmetic bounded as each comment states
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
