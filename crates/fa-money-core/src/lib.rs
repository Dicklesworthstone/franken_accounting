//! Exact, allocation-free money arithmetic for deterministic pricing rules.
//! A unit identifier and its immutable decimal scale come from the calling
//! book. Each conversion rounds once, after applying both the rate and scales.
//!
//! A 7.5% rebate on a USD 12.50 charge, expressed in cents:
//!
//! ```
//! use core::num::NonZeroU128;
//! use fa_money_core::{Amount, RoundingLaw, SignedRate, UnitId};
//!
//! let charge = Amount::new(UnitId(1), 1250);
//! let rebate = SignedRate::new(-3, NonZeroU128::new(40).unwrap());
//! let adjustment = charge.mul_signed_rate(rebate, RoundingLaw::HalfEven).unwrap();
//! assert_eq!(adjustment.mantissa, -94);
//! ```
#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::disallowed_methods
)]

use core::fmt;
use core::num::NonZeroU128;

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod allocation;
#[cfg(feature = "alloc")]
pub use allocation::largest_remainder;

mod rounding;
pub mod wide;
pub use rounding::RoundingLaw;
use wide::U256;

/// Index into the book's unit registry. Stable for the life of the registry epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnitId(pub u32);

impl fmt::Display for UnitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unit#{}", self.0)
    }
}

/// A signed mantissa at the immutable scale of one unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Amount {
    pub unit: UnitId,
    pub mantissa: i128,
}

/// An exact ratio with a positive denominator, always stored in lowest terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SignedRate {
    numerator: i128,
    denominator: NonZeroU128,
}

impl SignedRate {
    pub fn new(numerator: i128, denominator: NonZeroU128) -> Self {
        let mut a = numerator.unsigned_abs();
        let mut b = denominator.get();
        while let Some(divisor) = NonZeroU128::new(b) {
            (a, b) = (b, a % divisor);
        }
        // a is the positive gcd. Divide in magnitudes to include i128::MIN.
        let gcd = NonZeroU128::new(a).expect("denominator is positive");
        let magnitude = numerator.unsigned_abs() / gcd;
        Self {
            numerator: signed(magnitude, numerator < 0).expect("reduction only shrinks"),
            denominator: NonZeroU128::new(denominator.get() / gcd).expect("positive quotient"),
        }
    }

    pub const fn numerator(self) -> i128 {
        self.numerator
    }

    pub const fn denominator(self) -> NonZeroU128 {
        self.denominator
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmountError {
    Overflow,
    InvalidScale(u8),
    ZeroWeights,
    InvariantViolation(&'static str),
}

impl fmt::Display for AmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroWeights => f.write_str("allocation weights sum to zero"),
            Self::InvariantViolation(why) => f.write_str(why),
            Self::Overflow => f.write_str("amount overflow"),
            Self::InvalidScale(scale) => write!(f, "unit scale {scale} exceeds 38"),
        }
    }
}

impl core::error::Error for AmountError {}

fn signed(magnitude: u128, negative: bool) -> Result<i128, AmountError> {
    if negative && magnitude == i128::MIN.unsigned_abs() {
        return Ok(i128::MIN);
    }
    let value = i128::try_from(magnitude).map_err(|_| AmountError::Overflow)?;
    if negative {
        value.checked_neg().ok_or(AmountError::Overflow)
    } else {
        Ok(value)
    }
}

impl Amount {
    pub const fn new(unit: UnitId, mantissa: i128) -> Self {
        Self { unit, mantissa }
    }

    pub fn mul_signed_rate(self, rate: SignedRate, law: RoundingLaw) -> Result<Self, AmountError> {
        self.convert_signed_rate(self.unit, 0, 0, rate, law)
    }

    /// Convert using units of target per whole source unit. Supply the
    /// registered decimal scale of each unit, in source then target order.
    pub fn convert_signed_rate(
        self,
        to: UnitId,
        from_scale: u8,
        to_scale: u8,
        rate: SignedRate,
        law: RoundingLaw,
    ) -> Result<Self, AmountError> {
        let max_scale = from_scale.max(to_scale);
        if max_scale > 38 {
            return Err(AmountError::InvalidScale(max_scale));
        }
        let factor = 10u128.pow(u32::from(from_scale.abs_diff(to_scale)));
        let mut dividend =
            U256::from_product(self.mantissa.unsigned_abs(), rate.numerator.unsigned_abs());
        let mut divisor = U256::from_u128(rate.denominator.get());
        if to_scale > from_scale {
            // If this overflows 256 bits, division by a u128 cannot bring
            // the quotient back into the signed amount domain.
            dividend = dividend
                .checked_mul_u128(factor)
                .ok_or(AmountError::Overflow)?;
        } else {
            divisor = U256::from_product(rate.denominator.get(), factor);
        }
        let (q, r) = dividend.checked_div_rem(divisor).expect("positive divisor");
        let q = q.to_u128().ok_or(AmountError::Overflow)?;
        let negative = (self.mantissa < 0) != (rate.numerator < 0);
        let half = r.cmp(&divisor.checked_sub(r).expect("remainder below divisor"));
        let magnitude = law
            .apply_fraction(q, !r.is_zero(), half, negative)
            .ok_or(AmountError::Overflow)?;
        Ok(Self::new(to, signed(magnitude, negative)?))
    }

    /// Canonical encoding: `unit_id: u32 LE ‖ mantissa: i128 LE` (plan §6.6).
    pub fn encode(self) -> [u8; 20] {
        let mut out = [0u8; 20];
        out[..4].copy_from_slice(&self.unit.0.to_le_bytes());
        out[4..].copy_from_slice(&self.mantissa.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8; 20]) -> Self {
        let mut u = [0u8; 4];
        u.copy_from_slice(&bytes[..4]);
        let mut m = [0u8; 16];
        m.copy_from_slice(&bytes[4..]);
        Self::new(UnitId(u32::from_le_bytes(u)), i128::from_le_bytes(m))
    }
}

#[cfg(test)]
mod tests;
