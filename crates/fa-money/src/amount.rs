//! `Amount`: a unit-scaled integer mantissa. Signed in arithmetic; a leg's
//! mantissa must be non-negative (plan §4.4 — the side carries the sign and
//! every posting has exactly one representation).

use core::cmp::Ordering;
use core::fmt;

use crate::rate::Rate;
use crate::rounding::RoundingLaw;
use crate::unit::{UnitId, UnitRegistry, pow10};
use crate::wide::U256;

/// Debit or credit. Legs carry a side and a non-negative mantissa.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    Debit,
    Credit,
}

impl Side {
    pub fn flipped(self) -> Self {
        match self {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Amount {
    pub unit: UnitId,
    pub mantissa: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AmountError {
    UnitMismatch {
        left: UnitId,
        right: UnitId,
    },
    Overflow,
    UnknownUnit(String),
    /// The text had more fractional digits than the unit's scale. The caller
    /// must choose a rounding law explicitly (plan Appendix B).
    ExceedsScale {
        digits: usize,
        scale: u8,
    },
    Malformed(String),
    /// A leg mantissa was negative; express it as the other side instead.
    NegativeLeg {
        suggested_side: Side,
    },
}

impl fmt::Display for AmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnitMismatch { left, right } => write!(f, "unit mismatch: {left} vs {right}"),
            Self::Overflow => f.write_str("amount overflow"),
            Self::UnknownUnit(s) => write!(f, "unknown unit `{s}`"),
            Self::ExceedsScale { digits, scale } => {
                write!(
                    f,
                    "{digits} fractional digits exceed the unit scale {scale}; name a rounding law"
                )
            }
            Self::Malformed(s) => {
                write!(f, "malformed amount `{s}`; expected e.g. \"1234.56 USD\"")
            }
            Self::NegativeLeg { suggested_side } => {
                write!(
                    f,
                    "a leg mantissa cannot be negative; post it as a {suggested_side:?} instead"
                )
            }
        }
    }
}

impl core::error::Error for AmountError {}

impl Amount {
    pub const fn new(unit: UnitId, mantissa: i128) -> Self {
        Self { unit, mantissa }
    }

    pub const fn zero(unit: UnitId) -> Self {
        Self { unit, mantissa: 0 }
    }

    pub const fn is_zero(self) -> bool {
        self.mantissa == 0
    }

    pub const fn is_negative(self) -> bool {
        self.mantissa < 0
    }

    fn same_unit(self, o: Self) -> Result<(), AmountError> {
        if self.unit == o.unit {
            Ok(())
        } else {
            Err(AmountError::UnitMismatch {
                left: self.unit,
                right: o.unit,
            })
        }
    }

    pub fn checked_add(self, o: Self) -> Result<Self, AmountError> {
        self.same_unit(o)?;
        self.mantissa
            .checked_add(o.mantissa)
            .map(|m| Self::new(self.unit, m))
            .ok_or(AmountError::Overflow)
    }

    pub fn checked_sub(self, o: Self) -> Result<Self, AmountError> {
        self.same_unit(o)?;
        self.mantissa
            .checked_sub(o.mantissa)
            .map(|m| Self::new(self.unit, m))
            .ok_or(AmountError::Overflow)
    }

    pub fn checked_neg(self) -> Result<Self, AmountError> {
        self.mantissa
            .checked_neg()
            .map(|m| Self::new(self.unit, m))
            .ok_or(AmountError::Overflow)
    }

    pub fn checked_abs(self) -> Result<Self, AmountError> {
        self.mantissa
            .checked_abs()
            .map(|m| Self::new(self.unit, m))
            .ok_or(AmountError::Overflow)
    }

    /// Sum in canonical (given) order with checked operations; any
    /// intermediate overflow is a refusal.
    pub fn sum<I: IntoIterator<Item = Amount>>(
        unit: UnitId,
        amounts: I,
    ) -> Result<Self, AmountError> {
        let mut acc = Self::zero(unit);
        for a in amounts {
            acc = acc.checked_add(a)?;
        }
        Ok(acc)
    }

    /// Validate as a leg mantissa: non-negative. Zero is permitted here; the
    /// kernel refuses zero on monetary legs per the unit policy.
    pub fn as_leg(self, side: Side) -> Result<Self, AmountError> {
        if self.mantissa < 0 {
            Err(AmountError::NegativeLeg {
                suggested_side: side.flipped(),
            })
        } else {
            Ok(self)
        }
    }

    /// `self × rate`, rounded under `law`, in the same unit. Exact 256-bit
    /// intermediate; never a float.
    pub fn mul_rate(self, rate: Rate, law: RoundingLaw) -> Result<Self, AmountError> {
        let m = scaled_div(self.mantissa, rate.num, 1, rate.den, 1, law)?;
        Ok(Self::new(self.unit, m))
    }

    /// Convert to `to` at `rate` (units of `to` per unit of `self`), rounded
    /// under `law`. Rescales across the two units' scales exactly.
    pub fn convert(
        self,
        to: UnitId,
        rate: Rate,
        law: RoundingLaw,
        reg: &UnitRegistry,
    ) -> Result<Self, AmountError> {
        let from_scale = reg
            .get(self.unit)
            .ok_or_else(|| AmountError::UnknownUnit(self.unit.to_string()))?
            .scale;
        let to_scale = reg
            .get(to)
            .ok_or_else(|| AmountError::UnknownUnit(to.to_string()))?
            .scale;
        let m = scaled_div(
            self.mantissa,
            rate.num,
            pow10(to_scale) as u128,
            rate.den,
            pow10(from_scale) as u128,
            law,
        )?;
        Ok(Self::new(to, m))
    }

    /// Parse `"1234.56 USD"` exactly. A JSON number is never accepted; the
    /// text form is the contract (plan Appendix B).
    pub fn parse(text: &str, reg: &UnitRegistry) -> Result<Self, AmountError> {
        let t = text.trim();
        let (num, unit_s) = t
            .rsplit_once(' ')
            .ok_or_else(|| AmountError::Malformed(text.into()))?;
        let unit = reg
            .lookup(unit_s.trim())
            .ok_or_else(|| AmountError::UnknownUnit(unit_s.trim().into()))?;
        let scale = reg.get(unit).expect("registered").scale;
        let num = num.trim().replace('_', "");
        let (neg, body) = match num.strip_prefix('-') {
            Some(b) => (true, b),
            None => (false, num.strip_prefix('+').unwrap_or(&num)),
        };
        let (int_part, frac_part) = body.split_once('.').unwrap_or((body, ""));
        if int_part.is_empty() && frac_part.is_empty() {
            return Err(AmountError::Malformed(text.into()));
        }
        if !int_part.chars().all(|c| c.is_ascii_digit())
            || !frac_part.chars().all(|c| c.is_ascii_digit())
        {
            return Err(AmountError::Malformed(text.into()));
        }
        if frac_part.len() > usize::from(scale) {
            return Err(AmountError::ExceedsScale {
                digits: frac_part.len(),
                scale,
            });
        }
        let mut mantissa: i128 = 0;
        for c in int_part.chars().chain(frac_part.chars()) {
            mantissa = mantissa
                .checked_mul(10)
                .and_then(|m| m.checked_add(i128::from(c as u8 - b'0')))
                .ok_or(AmountError::Overflow)?;
        }
        for _ in frac_part.len()..usize::from(scale) {
            mantissa = mantissa.checked_mul(10).ok_or(AmountError::Overflow)?;
        }
        if neg {
            mantissa = -mantissa;
        }
        Ok(Self::new(unit, mantissa))
    }

    /// Render as `"1234.56 USD"` (sign, exact scale, unit spelling).
    pub fn render(self, reg: &UnitRegistry) -> String {
        let unit = reg.get(self.unit).expect("registered unit");
        let one = unit.one();
        let neg = self.mantissa < 0;
        let mag = self.mantissa.unsigned_abs();
        let (int, frac) = (mag / one.unsigned_abs(), mag % one.unsigned_abs());
        let mut s = String::new();
        if neg {
            s.push('-');
        }
        s.push_str(&int.to_string());
        if unit.scale > 0 {
            s.push('.');
            s.push_str(&format!("{frac:0width$}", width = usize::from(unit.scale)));
        }
        s.push(' ');
        s.push_str(&unit.spelling());
        s
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

impl PartialOrd for Amount {
    /// Amounts of different units are incomparable (`None`).
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.unit == other.unit {
            Some(self.mantissa.cmp(&other.mantissa))
        } else {
            None
        }
    }
}

/// `mantissa × a × b / (c × d)` rounded under `law`, with an exact 256-bit
/// intermediate. Shared by `mul_rate` and `convert`.
fn scaled_div(
    mantissa: i128,
    a: u128,
    b: u128,
    c: u128,
    d: u128,
    law: RoundingLaw,
) -> Result<i128, AmountError> {
    let negative = mantissa < 0;
    let mag = mantissa.unsigned_abs();
    let numer = U256::from_u128(mag)
        .checked_mul_u128(a)
        .and_then(|x| x.checked_mul_u128(b))
        .ok_or(AmountError::Overflow)?;
    let denom = c.checked_mul(d).ok_or(AmountError::Overflow)?;
    let (q, r) = numer.div_rem_u128(denom);
    let q = q.to_u128().ok_or(AmountError::Overflow)?;
    let rounded = law
        .apply_magnitude(q, r, denom, negative)
        .ok_or(AmountError::Overflow)?;
    let signed = i128::try_from(rounded).map_err(|_| AmountError::Overflow)?;
    Ok(if negative { -signed } else { signed })
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}·{}", self.mantissa, self.unit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> UnitRegistry {
        UnitRegistry::with_defaults()
    }

    #[test]
    fn parse_and_render_are_exact_inverses() {
        let r = reg();
        for text in [
            "1234.56 USD",
            "-0.01 EUR",
            "0 JPY",
            "123 JPY",
            "0.00000001 BTC",
            "1.000000000000000001 ETH",
            "2.500000 SHARE",
        ] {
            let a = Amount::parse(text, &r).expect(text);
            let back = a.render(&r);
            let again = Amount::parse(&back, &r).unwrap();
            assert_eq!(a, again, "{text} -> {back}");
        }
        assert_eq!(Amount::parse("1234.56 USD", &r).unwrap().mantissa, 123_456);
        assert_eq!(Amount::parse("5 JPY", &r).unwrap().mantissa, 5);
    }

    #[test]
    fn over_scale_is_refused_not_rounded() {
        let r = reg();
        assert_eq!(
            Amount::parse("1234.567 USD", &r),
            Err(AmountError::ExceedsScale {
                digits: 3,
                scale: 2
            })
        );
        assert!(matches!(
            Amount::parse("12.5 FOO", &r),
            Err(AmountError::UnknownUnit(_))
        ));
        assert!(matches!(
            Amount::parse("12,5 USD", &r),
            Err(AmountError::Malformed(_))
        ));
    }

    #[test]
    fn checked_arithmetic_refuses_overflow_and_unit_mixing() {
        let r = reg();
        let usd = r.lookup("USD").unwrap();
        let eur = r.lookup("EUR").unwrap();
        let max = Amount::new(usd, i128::MAX);
        assert_eq!(
            max.checked_add(Amount::new(usd, 1)),
            Err(AmountError::Overflow)
        );
        assert_eq!(
            Amount::new(usd, i128::MIN).checked_neg(),
            Err(AmountError::Overflow)
        );
        assert_eq!(
            Amount::new(usd, 1).checked_add(Amount::new(eur, 1)),
            Err(AmountError::UnitMismatch {
                left: usd,
                right: eur
            })
        );
        assert!(
            Amount::new(usd, 1)
                .partial_cmp(&Amount::new(eur, 1))
                .is_none()
        );
    }

    #[test]
    fn negative_legs_are_refused_with_the_other_side() {
        let r = reg();
        let usd = r.lookup("USD").unwrap();
        assert_eq!(
            Amount::new(usd, -5).as_leg(Side::Debit),
            Err(AmountError::NegativeLeg {
                suggested_side: Side::Credit
            })
        );
        assert!(Amount::new(usd, 5).as_leg(Side::Debit).is_ok());
    }

    #[test]
    fn mul_rate_and_convert_are_exact_then_rounded() {
        let r = reg();
        let usd = r.lookup("USD").unwrap();
        let jpy = r.lookup("JPY").unwrap();
        let a = Amount::parse("100.00 USD", &r).unwrap();
        // 7.5% tax: 7.50 exactly
        let tax = a
            .mul_rate(Rate::from_decimal("0.075").unwrap(), RoundingLaw::HalfEven)
            .unwrap();
        assert_eq!(tax.render(&r), "7.50 USD");
        // 1/3 of 100.00 = 33.333… → 33.33 HalfEven, 33.34 Ceiling
        let third = Rate::new(1, 3).unwrap();
        assert_eq!(
            a.mul_rate(third, RoundingLaw::HalfEven).unwrap().mantissa,
            3333
        );
        assert_eq!(
            a.mul_rate(third, RoundingLaw::Ceiling).unwrap().mantissa,
            3334
        );
        // 100.00 USD at 149.37 JPY/USD = 14937 JPY (scale 0)
        let jpy_rate = Rate::from_decimal("149.37").unwrap();
        assert_eq!(
            a.convert(jpy, jpy_rate, RoundingLaw::HalfEven, &r)
                .unwrap()
                .render(&r),
            "14937 JPY"
        );
        // and back: 14937 / 149.37 = 100.0000… → 100.00 USD
        let inv = Rate::new(100, 14937).unwrap();
        let back = Amount::new(jpy, 14937)
            .convert(usd, inv, RoundingLaw::HalfEven, &r)
            .unwrap();
        assert_eq!(back.render(&r), "100.00 USD");
        // negative amounts round symmetrically under HalfAwayFromZero
        let neg = Amount::new(usd, -5); // -0.05
        assert_eq!(
            neg.mul_rate(Rate::new(1, 2).unwrap(), RoundingLaw::HalfAwayFromZero)
                .unwrap()
                .mantissa,
            -3
        );
        assert_eq!(
            neg.mul_rate(Rate::new(1, 2).unwrap(), RoundingLaw::HalfEven)
                .unwrap()
                .mantissa,
            -2
        );
    }

    #[test]
    fn encoding_round_trips() {
        let a = Amount::new(UnitId(7), -123_456_789_012_345_678_901_234_567);
        assert_eq!(Amount::decode(&a.encode()), a);
    }
}
