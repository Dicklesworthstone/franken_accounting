//! Exact non-negative rationals for rates, factors, and percentages.

use core::fmt;

use crate::wide::U256;

/// A reduced rational with a nonzero denominator and bounded coefficients.
/// Construction always validates and normalizes the value.
///
/// ```compile_fail
/// use fa_money::Rate;
/// let invalid = Rate { num: 1, den: 0 };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rate {
    /// Numerator, reduced.
    num: u128,
    /// Denominator, reduced, nonzero.
    den: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RateError {
    ZeroDenominator,
    Malformed(String),
    Overflow,
}

impl fmt::Display for RateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDenominator => f.write_str("rate denominator is zero"),
            Self::Malformed(s) => write!(f, "malformed rate `{s}`"),
            Self::Overflow => f.write_str("rate overflow"),
        }
    }
}

impl core::error::Error for RateError {}

fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

impl Rate {
    pub const ONE: Self = Self { num: 1, den: 1 };

    pub const fn numerator(self) -> u128 {
        self.num
    }

    pub const fn denominator(self) -> u128 {
        self.den
    }

    pub fn new(num: u128, den: u128) -> Result<Self, RateError> {
        if den == 0 {
            return Err(RateError::ZeroDenominator);
        }
        if num == 0 {
            return Ok(Self { num: 0, den: 1 });
        }
        let g = gcd(num, den);
        Ok(Self {
            num: num / g,
            den: den / g,
        })
    }

    /// Parse a decimal literal such as `"0.075"`, `"149.37"`, or `"1"` into an
    /// exact rational. Up to 38 fractional digits after trailing zeroes are
    /// removed. Only the reduced numerator and denominator must fit u128.
    pub fn from_decimal(text: &str) -> Result<Self, RateError> {
        let t = text.trim();
        let (int_part, frac_part) = t.split_once('.').unwrap_or((t, ""));
        if int_part.is_empty() && frac_part.is_empty()
            || !int_part.chars().all(|c| c.is_ascii_digit())
            || !frac_part.chars().all(|c| c.is_ascii_digit())
        {
            return Err(RateError::Malformed(text.into()));
        }
        let frac_part = frac_part.trim_end_matches('0');
        let mut den: u128 = 1;
        for _ in 0..frac_part.len() {
            den = den.checked_mul(10).ok_or(RateError::Overflow)?;
        }
        let mut num = U256::ZERO;
        for c in int_part.chars().chain(frac_part.chars()) {
            num = num
                .checked_mul_u128(10)
                .and_then(|n| n.checked_add(U256::from_u128(u128::from(c as u8 - b'0'))))
                .ok_or(RateError::Overflow)?;
        }
        let (_, remainder) = num
            .checked_div_rem(U256::from_u128(den))
            .ok_or(RateError::ZeroDenominator)?;
        let common = gcd(remainder.to_u128().ok_or(RateError::Overflow)?, den);
        let (reduced, _) = num
            .checked_div_rem(U256::from_u128(common))
            .ok_or(RateError::ZeroDenominator)?;
        Self::new(reduced.to_u128().ok_or(RateError::Overflow)?, den / common)
    }

    /// Basis points: `bps / 10_000`.
    pub fn basis_points(bps: u128) -> Self {
        Self::new(bps, 10_000).expect("nonzero denominator")
    }

    /// The reciprocal (`den/num`), or `None` for a zero rate. The inverse
    /// convention for FX (whether an inverted rate may be used at all, and at
    /// what precision) is a law in `fx_laws.toml`, not a property of `Rate`.
    pub fn inverse(self) -> Option<Self> {
        if self.num == 0 {
            None
        } else {
            Some(Self {
                num: self.den,
                den: self.num,
            })
        }
    }

    pub fn is_zero(self) -> bool {
        self.num == 0
    }

    /// Compose exact rates, cancelling cross factors before multiplication.
    /// Overflow means a reduced coefficient does not fit the bounded domain.
    pub fn checked_mul(self, other: Self) -> Result<Self, RateError> {
        let left = gcd(self.num, other.den);
        let right = gcd(other.num, self.den);
        let num = (self.num / left)
            .checked_mul(other.num / right)
            .ok_or(RateError::Overflow)?;
        let den = (self.den / right)
            .checked_mul(other.den / left)
            .ok_or(RateError::Overflow)?;
        Self::new(num, den)
    }

    /// Divide exact rates; a zero divisor has no reciprocal.
    pub fn checked_div(self, other: Self) -> Result<Self, RateError> {
        self.checked_mul(other.inverse().ok_or(RateError::ZeroDenominator)?)
    }
}

impl fmt::Display for Rate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.num, self.den)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_parsing_is_exact_and_reduced() {
        assert_eq!(
            Rate::from_decimal("0.075").unwrap(),
            Rate { num: 3, den: 40 }
        );
        assert_eq!(
            Rate::from_decimal("149.37").unwrap(),
            Rate {
                num: 14937,
                den: 100
            }
        );
        assert_eq!(Rate::from_decimal("1").unwrap(), Rate::ONE);
        assert_eq!(Rate::from_decimal("0.5").unwrap(), Rate { num: 1, den: 2 });
        assert!(Rate::from_decimal("abc").is_err());
        assert!(Rate::from_decimal(".").is_err());
        assert_eq!(Rate::new(1, 0), Err(RateError::ZeroDenominator));
    }

    #[test]
    fn inverse_and_bps() {
        assert_eq!(Rate::basis_points(25), Rate { num: 1, den: 400 });
        assert_eq!(
            Rate::new(2, 3).unwrap().inverse(),
            Some(Rate { num: 3, den: 2 })
        );
        assert_eq!(Rate::new(0, 5).unwrap().inverse(), None);
    }

    #[test]
    fn cross_rates_cancel_before_multiplying() {
        let rate = Rate::new(u128::MAX, u128::MAX - 1).unwrap();
        assert_eq!(rate.checked_mul(rate.inverse().unwrap()), Ok(Rate::ONE));
        assert_eq!(rate.checked_div(rate), Ok(Rate::ONE));
        assert_eq!(
            Rate::new(u128::MAX, 1)
                .unwrap()
                .checked_mul(Rate::new(2, 1).unwrap()),
            Err(RateError::Overflow)
        );
        let zero = Rate::new(0, u128::MAX).unwrap();
        assert_eq!(zero.checked_mul(rate), Ok(zero));
        assert_eq!(rate.checked_mul(zero), Ok(zero));
        assert_eq!(rate.checked_div(zero), Err(RateError::ZeroDenominator));
        assert_eq!(rate.numerator(), u128::MAX);
        assert_eq!(rate.denominator(), u128::MAX - 1);
    }

    #[test]
    fn decimal_coefficients_are_reduced_before_narrowing() {
        assert_eq!(
            Rate::from_decimal(&format!(
                "{}.0000000000000000000000000000000000000000",
                u128::MAX
            )),
            Rate::new(u128::MAX, 1)
        );
        // The decimal mantissa exceeds u128 but its reduced numerator fits.
        assert_eq!(
            Rate::from_decimal("17014118346046923173168730371588410572.75"),
            Rate::new(68_056_473_384_187_692_692_674_921_486_353_642_291, 4)
        );
    }
}
