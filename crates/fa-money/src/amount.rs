//! `Amount`: a unit-scaled integer mantissa. Signed in arithmetic; a leg's
//! mantissa must be non-negative (plan §4.4 — the side carries the sign and
//! every posting has exactly one representation).

use core::cmp::Ordering;
use core::fmt;

use crate::rate::{ArithmeticBudget, BigInt, BudgetMeter, Rate, RateError};
use crate::rounding::RoundingLaw;
use crate::unit::{UnitId, UnitRegistry, pow10};
use fsym_bigint::{metered_cmp, metered_div_rem, metered_multiply, metered_subtract};

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
    InvariantViolation(&'static str),
    Rate(RateError),
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
            Self::InvariantViolation(message) => {
                write!(f, "arithmetic invariant failed: {message}")
            }
            Self::Rate(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for AmountError {}

impl From<RateError> for AmountError {
    fn from(error: RateError) -> Self {
        Self::Rate(error)
    }
}

impl From<crate::rate::MeterError> for AmountError {
    fn from(error: crate::rate::MeterError) -> Self {
        Self::Rate(error.into())
    }
}

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

    /// `self × rate`, rounded under `law`, in the same unit. Exact metered
    /// intermediate; never a float.
    pub fn mul_rate(
        self,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        rate: &Rate,
        law: RoundingLaw,
    ) -> Result<Self, AmountError> {
        let m = scaled_div(
            budget,
            self.mantissa,
            rate.numerator(),
            1,
            rate.denominator(),
            1,
            law,
        )?;
        Ok(Self::new(self.unit, m))
    }

    /// Convert to `to` at `rate` (units of `to` per unit of `self`), rounded
    /// under `law`. Rescales across the two units' scales exactly.
    pub fn convert(
        self,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        to: UnitId,
        rate: &Rate,
        law: RoundingLaw,
        reg: &UnitRegistry,
    ) -> Result<Self, AmountError> {
        budget.checkpoint()?;
        let from_scale = reg
            .get(self.unit)
            .ok_or_else(|| AmountError::UnknownUnit(self.unit.to_string()))?
            .scale;
        let to_scale = reg
            .get(to)
            .ok_or_else(|| AmountError::UnknownUnit(to.to_string()))?
            .scale;
        // Cancel the common power of ten first. Equal scales then need no
        // rescaling at all; a downscale needs a wide denominator only.
        let (numer_scale, denom_scale) = if to_scale >= from_scale {
            (pow10(to_scale - from_scale) as u128, 1)
        } else {
            (1, pow10(from_scale - to_scale) as u128)
        };
        let m = scaled_div(
            budget,
            self.mantissa,
            rate.numerator(),
            numer_scale,
            rate.denominator(),
            denom_scale,
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
        let mut magnitude: u128 = 0;
        for c in int_part.chars().chain(frac_part.chars()) {
            magnitude = magnitude
                .checked_mul(10)
                .and_then(|m| m.checked_add(u128::from(c as u8 - b'0')))
                .ok_or(AmountError::Overflow)?;
        }
        for _ in frac_part.len()..usize::from(scale) {
            magnitude = magnitude.checked_mul(10).ok_or(AmountError::Overflow)?;
        }
        let mantissa = signed_magnitude(magnitude, neg)?;
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
        // A bare version-zero code would select the newest version on parse.
        // Preserve the old unit identity once a later version is registered.
        if unit.version == 0 && reg.lookup(&unit.code) != Some(self.unit) {
            s.push_str(&format!("{}@v0", unit.code));
        } else {
            s.push_str(&unit.spelling());
        }
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

/// `mantissa × a × b / (c × d)` rounded under `law`, with exact arbitrary-size
/// intermediate. Shared by `mul_rate` and `convert`.
fn scaled_div(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    mantissa: i128,
    a: &BigInt,
    b: u128,
    c: &BigInt,
    d: u128,
    law: RoundingLaw,
) -> Result<i128, AmountError> {
    let negative = mantissa < 0;
    budget.reserve(48, 3)?;
    let mag = BigInt::from_bytes_le(&mantissa.unsigned_abs().to_le_bytes());
    let b = BigInt::from_bytes_le(&b.to_le_bytes());
    let d = BigInt::from_bytes_le(&d.to_le_bytes());
    let product = metered_multiply(&mag, a, budget)?;
    let numer = metered_multiply(&product, &b, budget)?;
    let denom = metered_multiply(c, &d, budget)?;
    let (q, r) = metered_div_rem(&numer, &denom, budget)?
        .ok_or(AmountError::InvariantViolation("zero amount divisor"))?;
    if q.bits() > 128 {
        return Err(AmountError::Overflow);
    }
    budget.reserve(16, 1)?;
    let bytes = q.to_bytes_le();
    let mut magnitude = [0u8; 16];
    magnitude[..bytes.len()].copy_from_slice(&bytes);
    let q = u128::from_le_bytes(magnitude);
    let distance_to_next = metered_subtract(&denom, &r, budget)?;
    let cmp_half = metered_cmp(&r, &distance_to_next, budget)?;
    let rounded = law
        .apply_fraction(q, !r.is_zero(), cmp_half, negative)
        .ok_or(AmountError::Overflow)?;
    budget.checkpoint()?;
    signed_magnitude(rounded, negative)
}

/// Restore the sign without rejecting i128::MIN's representable magnitude.
pub(crate) fn signed_magnitude(magnitude: u128, negative: bool) -> Result<i128, AmountError> {
    if negative && magnitude == 1u128 << 127 {
        return Ok(i128::MIN);
    }
    let signed = i128::try_from(magnitude).map_err(|_| AmountError::Overflow)?;
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
    use fgdb_bigint::{BigInt, LimbLimit};

    // Independent arbitrary-precision calculation with a 16-limb test budget:
    // multiply BOTH powers of ten, then divide and compare 2*r with d. No
    // production cancellation, rounding helper or sign helper is used.
    fn oracle_conversion(
        mantissa: i128,
        numerator: u128,
        denominator: u128,
        from_scale: u8,
        to_scale: u8,
        law: RoundingLaw,
    ) -> Option<i128> {
        oracle_conversion_wide(
            mantissa,
            &BigInt::from_u128(numerator),
            &BigInt::from_u128(denominator),
            from_scale,
            to_scale,
            law,
        )
    }

    fn oracle_conversion_wide(
        mantissa: i128,
        numerator: &BigInt,
        denominator: &BigInt,
        from_scale: u8,
        to_scale: u8,
        law: RoundingLaw,
    ) -> Option<i128> {
        let limit = LimbLimit::new(16);
        let n = BigInt::from_u128(mantissa.unsigned_abs())
            .checked_mul(numerator, limit)
            .unwrap()
            .checked_mul(&BigInt::from_u128(10u128.pow(u32::from(to_scale))), limit)
            .unwrap();
        let d = denominator
            .checked_mul(&BigInt::from_u128(10u128.pow(u32::from(from_scale))), limit)
            .unwrap();
        let (mut q, r) = n.checked_div_rem(&d, limit).unwrap();
        if !r.is_zero() {
            let half = r.checked_mul(&BigInt::from_u64(2), limit).unwrap().cmp(&d);
            let negative = mantissa < 0;
            let odd = q
                .magnitude_limbs_le()
                .first()
                .is_some_and(|limb| limb & 1 != 0);
            let up = match law {
                RoundingLaw::TowardZero => false,
                RoundingLaw::AwayFromZero => true,
                RoundingLaw::Ceiling => !negative,
                RoundingLaw::Floor => negative,
                RoundingLaw::HalfUp => half.is_gt() || (half.is_eq() && !negative),
                RoundingLaw::HalfDown => half.is_gt() || (half.is_eq() && negative),
                RoundingLaw::HalfEven => half.is_gt() || (half.is_eq() && odd),
                RoundingLaw::HalfAwayFromZero => !half.is_lt(),
                RoundingLaw::HalfTowardZero => half.is_gt(),
            };
            if up {
                q = q.checked_add(&BigInt::from_u64(1), limit).unwrap();
            }
        }
        if mantissa < 0 {
            q = q.checked_neg(limit).unwrap();
        }
        q.to_i128()
    }

    // Parse the same source digits with the independent foundation's own
    // limbs. Neither the production parser nor its normalized coefficients
    // participate in the expected result.
    fn oracle_integer(text: &str) -> BigInt {
        text.bytes().fold(BigInt::zero(), |value, digit| {
            value
                .checked_mul(&BigInt::from_u64(10), LimbLimit::new(16))
                .unwrap()
                .checked_add(
                    &BigInt::from_u64(u64::from(digit - b'0')),
                    LimbLimit::new(16),
                )
                .unwrap()
        })
    }

    #[test]
    fn arbitrary_coefficients_match_independent_oracle_on_both_sides_of_ties() {
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let huge = format!("1{}", "0".repeat(80));
        let twice_huge = format!("2{}", "0".repeat(80));
        let above = format!("1{}1", "0".repeat(79));
        let below = "9".repeat(80);
        let rates = [
            (&above, &huge),
            (&below, &huge),
            (&above, &twice_huge),
            (&below, &twice_huge),
            (&huge, &above),
            (&above, &below),
        ];
        let mut registry = UnitRegistry::empty();
        let units = [0, 38].map(|scale| {
            registry
                .register(crate::unit::Unit {
                    code: format!("S{scale}"),
                    scale,
                    version: 0,
                    kind: crate::unit::UnitKind::Custom,
                    rounding_default: RoundingLaw::HalfEven,
                })
                .unwrap()
        });
        // 6 exact source ratios × 4 scale pairs × 8 signed amounts × 9 laws.
        let mut compared = 0;
        for (num, den) in rates {
            let rate = Rate::from_ratio(&mut budget, num, den).unwrap();
            assert!(rate.numerator().bits() > 128);
            let n = oracle_integer(num);
            let d = oracle_integer(den);
            for (from, from_scale) in units.into_iter().zip([0, 38]) {
                for (to, to_scale) in units.into_iter().zip([0, 38]) {
                    for mantissa in [i128::MIN, -i128::MAX, -5, -1, 1, 3, 5, i128::MAX] {
                        for law in RoundingLaw::ALL {
                            let expected =
                                oracle_conversion_wide(mantissa, &n, &d, from_scale, to_scale, law)
                                    .map(|m| Amount::new(to, m))
                                    .ok_or(AmountError::Overflow);
                            assert_eq!(
                                Amount::new(from, mantissa).convert(
                                    &mut budget,
                                    to,
                                    &rate,
                                    law,
                                    &registry
                                ),
                                expected,
                                "rate={num}/{den}, mantissa={mantissa}, scale={from_scale}->{to_scale}, law={law:?}"
                            );
                            compared += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(compared, 1728);
    }

    #[test]
    fn conversion_propagates_cancellation_and_exhaustion_without_a_result() {
        use crate::rate::{BudgetLimits, Dimension, MeterError};
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let rate = Rate::from_ratio(
            &mut budget,
            "100000000000000000000000000000000000000000000000001",
            "100000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let amount = Amount::new(UnitId(0), 5);
        let mut exhausted = ArithmeticBudget::new(&cx, BudgetLimits::uniform(0, 0), 8192);
        assert!(matches!(
            amount.mul_rate(&mut exhausted, &rate, RoundingLaw::HalfEven),
            Err(AmountError::Rate(RateError::Meter(MeterError::Budget(_))))
        ));
        let remaining = budget.remaining(Dimension::MemoryBytes);
        cx.set_cancel_requested(true);
        assert_eq!(
            amount.mul_rate(&mut budget, &rate, RoundingLaw::HalfEven),
            Err(AmountError::Rate(RateError::Meter(MeterError::Cancelled)))
        );
        assert_eq!(budget.remaining(Dimension::MemoryBytes), remaining);
    }

    #[test]
    fn conversions_match_bigint_at_scale_sign_and_rounding_boundaries() {
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let mut r = UnitRegistry::empty();
        let scales = [0, 2, 18, 38];
        let units = scales.map(|scale| {
            r.register(crate::unit::Unit {
                code: format!("S{scale}"),
                scale,
                version: 0,
                kind: crate::unit::UnitKind::Custom,
                rounding_default: RoundingLaw::HalfEven,
            })
            .unwrap()
        });
        let rates = [
            (0, 1),
            (1, 1),
            (1, 2),
            (3, 7),
            (u128::MAX, u128::MAX - 1),
            (u128::MAX - 1, u128::MAX),
            (u128::MAX, 1),
            (1, u128::MAX),
            (50, i128::MAX as u128),
            (150, i128::MAX as u128),
        ];
        for (from_index, from) in units.iter().enumerate() {
            for (to_index, to) in units.iter().enumerate() {
                for (num, den) in rates {
                    let rate = Rate::new(&mut budget, num, den).unwrap();
                    for mantissa in [i128::MIN, -i128::MAX, -50, -1, 0, 1, 50, i128::MAX] {
                        for law in RoundingLaw::ALL {
                            let expected = oracle_conversion(
                                mantissa,
                                num,
                                den,
                                scales[from_index],
                                scales[to_index],
                                law,
                            )
                            .map(|value| Amount::new(*to, value))
                            .ok_or(AmountError::Overflow);
                            assert_eq!(
                                Amount::new(*from, mantissa).convert(
                                    &mut budget,
                                    *to,
                                    &rate,
                                    law,
                                    &r
                                ),
                                expected,
                                "mantissa={mantissa}, rate={num}/{den}, scales={}→{}, law={law:?}",
                                scales[from_index],
                                scales[to_index]
                            );
                        }
                    }
                }
            }
            for mantissa in [i128::MIN, i128::MAX] {
                let amount = Amount::new(*from, mantissa);
                assert_eq!(Amount::parse(&amount.render(&r), &r), Ok(amount));
            }
        }
    }

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
    fn rendering_preserves_historical_unit_versions() {
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let one = Rate::one(&mut budget).unwrap();
        let mut registry = reg();
        let old_amount = Amount::parse("1.23 USD", &registry).unwrap();
        let new_unit = registry
            .register(crate::unit::Unit {
                code: "USD".into(),
                scale: 4,
                version: 1,
                kind: crate::unit::UnitKind::Currency { iso4217: 840 },
                rounding_default: RoundingLaw::HalfEven,
            })
            .unwrap();
        assert_eq!(old_amount.render(&registry), "1.23 USD@v0");
        assert_eq!(
            Amount::parse(&old_amount.render(&registry), &registry),
            Ok(old_amount)
        );
        let new_amount = Amount::parse("1.23 USD", &registry).unwrap();
        assert_eq!(new_amount, Amount::new(new_unit, 12_300));
        assert_eq!(new_amount.render(&registry), "1.2300 USD@v1");
        assert_eq!(
            old_amount.convert(
                &mut budget,
                new_unit,
                &one,
                RoundingLaw::HalfEven,
                &registry
            ),
            Ok(new_amount)
        );
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
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let r = reg();
        let usd = r.lookup("USD").unwrap();
        let jpy = r.lookup("JPY").unwrap();
        let a = Amount::parse("100.00 USD", &r).unwrap();
        // 7.5% tax: 7.50 exactly
        let tax_rate = Rate::from_decimal(&mut budget, "0.075").unwrap();
        let tax = a
            .mul_rate(&mut budget, &tax_rate, RoundingLaw::HalfEven)
            .unwrap();
        assert_eq!(tax.render(&r), "7.50 USD");
        // 1/3 of 100.00 = 33.333… → 33.33 HalfEven, 33.34 Ceiling
        let third = Rate::new(&mut budget, 1, 3).unwrap();
        assert_eq!(
            a.mul_rate(&mut budget, &third, RoundingLaw::HalfEven)
                .unwrap()
                .mantissa,
            3333
        );
        assert_eq!(
            a.mul_rate(&mut budget, &third, RoundingLaw::Ceiling)
                .unwrap()
                .mantissa,
            3334
        );
        // 100.00 USD at 149.37 JPY/USD = 14937 JPY (scale 0)
        let jpy_rate = Rate::from_decimal(&mut budget, "149.37").unwrap();
        assert_eq!(
            a.convert(&mut budget, jpy, &jpy_rate, RoundingLaw::HalfEven, &r)
                .unwrap()
                .render(&r),
            "14937 JPY"
        );
        // and back: 14937 / 149.37 = 100.0000… → 100.00 USD
        let inv = Rate::new(&mut budget, 100, 14937).unwrap();
        let back = Amount::new(jpy, 14937)
            .convert(&mut budget, usd, &inv, RoundingLaw::HalfEven, &r)
            .unwrap();
        assert_eq!(back.render(&r), "100.00 USD");
        // negative amounts round symmetrically under HalfAwayFromZero
        let neg = Amount::new(usd, -5); // -0.05
        let half = Rate::new(&mut budget, 1, 2).unwrap();
        assert_eq!(
            neg.mul_rate(&mut budget, &half, RoundingLaw::HalfAwayFromZero)
                .unwrap()
                .mantissa,
            -3
        );
        assert_eq!(
            neg.mul_rate(&mut budget, &half, RoundingLaw::HalfEven)
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

    #[test]
    fn regression_scaled_conversion_only_refuses_unrepresentable_results() {
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let r = reg();
        let usd = r.lookup("USD").unwrap();
        let eur = r.lookup("EUR").unwrap();
        let eth = r.lookup("ETH").unwrap();
        let jpy = r.lookup("JPY").unwrap();
        let almost_one = Rate::new(&mut budget, u128::MAX - 1, u128::MAX).unwrap();
        for mantissa in [1, i128::MAX] {
            // The exact result is less than half a minor unit below mantissa.
            assert_eq!(
                Amount::new(usd, mantissa).convert(
                    &mut budget,
                    eur,
                    &almost_one,
                    RoundingLaw::HalfEven,
                    &r
                ),
                Ok(Amount::new(eur, mantissa))
            );
        }
        let tiny = Rate::new(&mut budget, 1, u128::MAX).unwrap();
        assert_eq!(
            Amount::new(eth, i128::MAX).convert(&mut budget, jpy, &tiny, RoundingLaw::HalfEven, &r),
            Ok(Amount::zero(jpy))
        );
        assert_eq!(
            Amount::new(eth, i128::MAX).convert(&mut budget, jpy, &tiny, RoundingLaw::Ceiling, &r),
            Ok(Amount::new(jpy, 1))
        );
    }

    #[test]
    fn regression_minimum_amount_round_trips_text() {
        let r = reg();
        let jpy = r.lookup("JPY").unwrap();
        let minimum = Amount::new(jpy, i128::MIN);
        assert_eq!(Amount::parse(&minimum.render(&r), &r), Ok(minimum));
    }

    #[test]
    fn regression_minimum_amount_survives_identity_scaling() {
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let one = Rate::one(&mut budget).unwrap();
        let minimum = Amount::new(UnitId(0), i128::MIN);
        for law in RoundingLaw::ALL {
            assert_eq!(minimum.mul_rate(&mut budget, &one, law), Ok(minimum));
        }
    }

    #[test]
    fn values_outside_the_signed_amount_domain_are_still_refused() {
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let twice = Rate::new(&mut budget, 2, 1).unwrap();
        let r = reg();
        assert_eq!(
            Amount::parse("170141183460469231731687303715884105728 JPY", &r),
            Err(AmountError::Overflow)
        );
        assert_eq!(
            Amount::parse("-170141183460469231731687303715884105729 JPY", &r),
            Err(AmountError::Overflow)
        );
        for mantissa in [i128::MIN, i128::MAX] {
            assert_eq!(
                Amount::new(UnitId(0), mantissa).mul_rate(
                    &mut budget,
                    &twice,
                    RoundingLaw::TowardZero
                ),
                Err(AmountError::Overflow)
            );
        }
    }
}
