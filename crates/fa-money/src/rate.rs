//! Exact non-negative rationals with cancellation and deterministic work budgets.

use asupersync::Cx;
use core::fmt;
pub use fsym_bigint::BigInt;
use fsym_bigint::{metered_add, metered_multiply, metered_pow};
use fsym_budget::Budget;
pub use fsym_budget::{BudgetError, BudgetLimits, BudgetMeter, Dimension, MeterError};
use fsym_rational::BigRational;
pub use fsym_rational::RationalArithmeticError;

/// A caller-owned budget shared by every step of an arithmetic operation.
/// Cancellation comes from the supplied Cx; this adapter reads no clock,
/// entropy, filesystem or network. Limits and source inputs belong in the
/// caller's computation certificate. Memory is charged cumulatively, not as
/// peak RSS. No operation silently creates an unbounded meter.
pub struct ArithmeticBudget<'cx, Caps = asupersync::cx::cap::All> {
    cx: &'cx Cx<Caps>,
    budget: Budget,
    max_input_bytes: usize,
}

impl<'cx, Caps> ArithmeticBudget<'cx, Caps> {
    pub fn new(cx: &'cx Cx<Caps>, limits: BudgetLimits, max_input_bytes: usize) -> Self {
        Self {
            cx,
            budget: Budget::new(limits),
            max_input_bytes,
        }
    }

    pub fn remaining(&self, dimension: Dimension) -> u64 {
        self.budget.remaining(dimension)
    }

    fn admit_input(&mut self, bytes: usize) -> Result<(), RateError> {
        self.checkpoint()?;
        if bytes > self.max_input_bytes {
            return Err(RateError::InputTooLarge {
                bytes,
                limit: self.max_input_bytes,
            });
        }
        self.charge(
            Dimension::ComputeSteps,
            u64::try_from(bytes)
                .map_err(|_| RateError::Overflow)?
                .max(1),
        )?;
        Ok(())
    }

    pub(crate) fn reserve(&mut self, bytes: u64, allocations: u64) -> Result<(), RateError> {
        self.charge_batch(&[
            (Dimension::MemoryBytes, bytes.max(1)),
            (Dimension::AllocationCount, allocations),
        ])?;
        Ok(())
    }
}

impl<Caps> BudgetMeter for ArithmeticBudget<'_, Caps> {
    fn charge(&mut self, dimension: Dimension, amount: u64) -> Result<(), MeterError> {
        self.checkpoint()?;
        self.budget.charge(dimension, amount)
    }

    fn charge_batch(&mut self, charges: &[(Dimension, u64)]) -> Result<(), MeterError> {
        self.checkpoint()?;
        self.budget.charge_batch(charges)
    }

    fn checkpoint(&mut self) -> Result<(), MeterError> {
        if self.cx.is_cancelled() {
            Err(MeterError::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// A reduced rational with a positive denominator and arbitrary-size coefficients.
/// Construction and arithmetic are fallible and metered.
///
/// ```compile_fail
/// use fa_money::Rate;
/// let invalid = Rate { num: 1, den: 0 };
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Rate {
    value: BigRational,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RateError {
    ZeroDenominator,
    Malformed(String),
    Overflow,
    InputTooLarge { bytes: usize, limit: usize },
    Meter(MeterError),
    Arithmetic(RationalArithmeticError),
}

impl fmt::Display for RateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDenominator => f.write_str("rate denominator is zero"),
            Self::Malformed(s) => write!(f, "malformed rate `{s}`"),
            Self::Overflow => f.write_str("rate overflow"),
            Self::InputTooLarge { bytes, limit } => {
                write!(f, "rate input has {bytes} bytes, limit {limit}")
            }
            Self::Meter(error) => write!(f, "{error}"),
            Self::Arithmetic(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for RateError {}

impl From<MeterError> for RateError {
    fn from(error: MeterError) -> Self {
        Self::Meter(error)
    }
}

impl From<RationalArithmeticError> for RateError {
    fn from(error: RationalArithmeticError) -> Self {
        match error {
            RationalArithmeticError::DivisionByZero => Self::ZeroDenominator,
            RationalArithmeticError::Meter(error) => Self::Meter(error),
            other => Self::Arithmetic(other),
        }
    }
}

impl Rate {
    pub fn numerator(&self) -> &BigInt {
        self.value.numer()
    }

    pub fn denominator(&self) -> &BigInt {
        self.value.denom()
    }

    pub fn new(
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        num: u128,
        den: u128,
    ) -> Result<Self, RateError> {
        budget.reserve(32, 2)?;
        Self::from_integers(
            budget,
            &BigInt::from_bytes_le(&num.to_le_bytes()),
            &BigInt::from_bytes_le(&den.to_le_bytes()),
        )
    }

    pub fn zero(budget: &mut ArithmeticBudget<'_, impl Sized>) -> Result<Self, RateError> {
        Self::new(budget, 0, 1)
    }

    pub fn one(budget: &mut ArithmeticBudget<'_, impl Sized>) -> Result<Self, RateError> {
        Self::new(budget, 1, 1)
    }

    fn from_integers(
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        num: &BigInt,
        den: &BigInt,
    ) -> Result<Self, RateError> {
        Ok(Self {
            value: BigRational::metered_new(num, den, budget)?,
        })
    }

    /// Parse unsigned decimal integer coefficients, then reduce exactly.
    pub fn from_ratio(
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        num: &str,
        den: &str,
    ) -> Result<Self, RateError> {
        budget.admit_input(
            num.len()
                .checked_add(den.len())
                .ok_or(RateError::Overflow)?,
        )?;
        let num = parse_integer(budget, num)?;
        let den = parse_integer(budget, den)?;
        Self::from_integers(budget, &num, &den)
    }

    /// Parse a decimal literal such as `"0.075"`, `"149.37"`, or `"1"` into an
    /// exact rational. Input size and work are limited by the supplied budget,
    /// not by a machine-integer coefficient width.
    pub fn from_decimal(
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        text: &str,
    ) -> Result<Self, RateError> {
        budget.admit_input(text.len())?;
        let t = text.trim();
        let (int_part, frac_part) = t.split_once('.').unwrap_or((t, ""));
        if int_part.is_empty() && frac_part.is_empty()
            || !int_part.chars().all(|c| c.is_ascii_digit())
            || !frac_part.chars().all(|c| c.is_ascii_digit())
        {
            return Err(RateError::Malformed("expected unsigned decimal".into()));
        }
        let frac_part = frac_part.trim_end_matches('0');
        budget.reserve(16, 2)?;
        let ten = BigInt::from(10u64);
        let mut num = BigInt::zero();
        for c in int_part.bytes().chain(frac_part.bytes()) {
            num = push_digit(budget, &num, &ten, c)?;
        }
        let exponent = u32::try_from(frac_part.len()).map_err(|_| RateError::Overflow)?;
        let den = metered_pow(&ten, exponent, budget)?;
        Self::from_integers(budget, &num, &den)
    }

    /// Basis points: `bps / 10_000`.
    pub fn basis_points(
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        bps: u128,
    ) -> Result<Self, RateError> {
        Self::new(budget, bps, 10_000)
    }

    /// The reciprocal (`den/num`), refusing a zero rate. The inverse
    /// convention for FX (whether an inverted rate may be used at all, and at
    /// what precision) is a law in `fx_laws.toml`, not a property of `Rate`.
    pub fn inverse(
        &self,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
    ) -> Result<Self, RateError> {
        Self::from_integers(budget, self.denominator(), self.numerator())
    }

    pub fn is_zero(&self) -> bool {
        self.numerator().is_zero()
    }

    /// Add two exact non-negative rationals and reduce to lowest terms.
    pub fn checked_add(
        &self,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        other: &Self,
    ) -> Result<Self, RateError> {
        let lhs = metered_multiply(self.numerator(), other.denominator(), budget)?;
        let rhs = metered_multiply(other.numerator(), self.denominator(), budget)?;
        let num = metered_add(&lhs, &rhs, budget)?;
        let den = metered_multiply(self.denominator(), other.denominator(), budget)?;
        Self::from_integers(budget, &num, &den)
    }

    /// Subtract `other` from `self` as a non-negative rational, refusing if `self < other`.
    pub fn checked_sub(
        &self,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        other: &Self,
    ) -> Result<Self, RateError> {
        let lhs = metered_multiply(self.numerator(), other.denominator(), budget)?;
        let rhs = metered_multiply(other.numerator(), self.denominator(), budget)?;
        if fsym_bigint::metered_cmp(&lhs, &rhs, budget)?.is_lt() {
            return Err(RateError::Overflow);
        }
        let num = fsym_bigint::metered_subtract(&lhs, &rhs, budget)?;
        let den = metered_multiply(self.denominator(), other.denominator(), budget)?;
        Self::from_integers(budget, &num, &den)
    }

    /// Exact metered comparison of two non-negative rationals.
    pub fn metered_cmp(
        &self,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        other: &Self,
    ) -> Result<core::cmp::Ordering, RateError> {
        let lhs = metered_multiply(self.numerator(), other.denominator(), budget)?;
        let rhs = metered_multiply(other.numerator(), self.denominator(), budget)?;
        Ok(fsym_bigint::metered_cmp(&lhs, &rhs, budget)?)
    }

    /// Decompose `self = q + frac` into `q = floor(self)` as `u128` and `frac` in `[0, 1)`.
    pub fn floor_and_frac(
        &self,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
    ) -> Result<(u128, Self), RateError> {
        let (q_big, r_big) =
            fsym_bigint::metered_div_rem(self.numerator(), self.denominator(), budget)?
                .ok_or(RateError::ZeroDenominator)?;
        if q_big.bits() > 128 {
            return Err(RateError::Overflow);
        }
        budget.reserve(16, 1)?;
        let bytes = q_big.to_bytes_le();
        let mut mag = [0u8; 16];
        mag[..bytes.len()].copy_from_slice(&bytes);
        let q = u128::from_le_bytes(mag);
        let frac = Self::from_integers(budget, &r_big, self.denominator())?;
        Ok((q, frac))
    }

    /// Round a slice of exact non-negative rational shares whose exact sum is
    /// the non-negative integer `total` into integer `i128` shares under
    /// Hamilton's `LargestRemainder` law (floor each share, then distribute
    /// the integer residual `total - sum(floor)` to the largest fractional
    /// remainders, breaking ties by lowest index). Refuses if the exact sum
    /// of `shares` does not equal `total`.
    pub fn round_largest_remainder(
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        total: i128,
        shares: &[Self],
    ) -> Result<Vec<i128>, RateError> {
        if total < 0 {
            return Err(RateError::Overflow);
        }
        let total_u = u128::try_from(total).map_err(|_| RateError::Overflow)?;
        let mut sum_exact = Self::zero(budget)?;
        let mut floors: Vec<u128> = Vec::with_capacity(shares.len());
        let mut fracs: Vec<(Self, usize)> = Vec::with_capacity(shares.len());
        let mut floor_sum: u128 = 0;
        for (idx, share) in shares.iter().enumerate() {
            sum_exact = sum_exact.checked_add(budget, share)?;
            let (q, frac) = share.floor_and_frac(budget)?;
            floor_sum = floor_sum.checked_add(q).ok_or(RateError::Overflow)?;
            floors.push(q);
            fracs.push((frac, idx));
        }
        let expected = Self::new(budget, total_u, 1)?;
        if sum_exact != expected {
            return Err(RateError::Malformed(
                "exact rational shares do not sum to declared integer total".into(),
            ));
        }
        let mut residual = total_u.checked_sub(floor_sum).ok_or(RateError::Overflow)?;
        for i in 1..fracs.len() {
            let mut j = i;
            while j > 0 {
                let cmp_frac = fracs[j].0.metered_cmp(budget, &fracs[j - 1].0)?;
                let before = cmp_frac.is_gt() || (cmp_frac.is_eq() && fracs[j].1 < fracs[j - 1].1);
                if before {
                    fracs.swap(j - 1, j);
                    j -= 1;
                } else {
                    break;
                }
            }
        }
        for (frac, idx) in fracs {
            if residual == 0 {
                break;
            }
            if frac.is_zero() {
                break;
            }
            floors[idx] = floors[idx].checked_add(1).ok_or(RateError::Overflow)?;
            residual = residual.checked_sub(1).ok_or(RateError::Overflow)?;
        }
        if residual != 0 {
            return Err(RateError::Overflow);
        }
        floors
            .into_iter()
            .map(|v| i128::try_from(v).map_err(|_| RateError::Overflow))
            .collect()
    }

    /// Compose exact rates, cancelling cross factors before multiplication.
    pub fn checked_mul(
        &self,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        other: &Self,
    ) -> Result<Self, RateError> {
        Ok(Self {
            value: self.value.metered_mul(&other.value, budget)?,
        })
    }

    /// Divide exact rates; a zero divisor has no reciprocal.
    pub fn checked_div(
        &self,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        other: &Self,
    ) -> Result<Self, RateError> {
        Ok(Self {
            value: self.value.metered_div(&other.value, budget)?,
        })
    }

    /// Version 1: `FAR\x01`, u32 LE numerator length, u32 LE denominator
    /// length, then minimal unsigned LE magnitudes. Zero has an empty
    /// numerator and denominator 1. No serde representation is durable.
    pub fn encode(
        &self,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
    ) -> Result<Vec<u8>, RateError> {
        let n = usize::try_from(self.numerator().bits().div_ceil(8))
            .map_err(|_| RateError::Overflow)?;
        let d = usize::try_from(self.denominator().bits().div_ceil(8))
            .map_err(|_| RateError::Overflow)?;
        let size = n
            .checked_add(d)
            .and_then(|v| v.checked_add(12))
            .ok_or(RateError::Overflow)?;
        budget.admit_input(size)?;
        let n32 = u32::try_from(n).map_err(|_| RateError::Overflow)?;
        let d32 = u32::try_from(d).map_err(|_| RateError::Overflow)?;
        budget.reserve(
            u64::try_from(size)
                .map_err(|_| RateError::Overflow)?
                .checked_mul(2)
                .ok_or(RateError::Overflow)?,
            3,
        )?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| RateError::Arithmetic(RationalArithmeticError::AllocationFailure))?;
        bytes.extend_from_slice(b"FAR\x01");
        bytes.extend_from_slice(&n32.to_le_bytes());
        bytes.extend_from_slice(&d32.to_le_bytes());
        if n != 0 {
            bytes.extend_from_slice(&self.numerator().to_bytes_le());
        }
        bytes.extend_from_slice(&self.denominator().to_bytes_le());
        budget.checkpoint()?;
        Ok(bytes)
    }

    /// Refuse noncanonical input, including reducible fractions, leading
    /// zero magnitude bytes, unknown versions, truncation and trailing data.
    pub fn decode(
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        bytes: &[u8],
    ) -> Result<Self, RateError> {
        budget.admit_input(bytes.len())?;
        let malformed = || RateError::Malformed("noncanonical rate encoding".into());
        if bytes.len() < 12 || &bytes[..4] != b"FAR\x01" {
            return Err(malformed());
        }
        let n = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| malformed())?) as usize;
        let d = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| malformed())?) as usize;
        let split = 12usize.checked_add(n).ok_or_else(malformed)?;
        if split.checked_add(d) != Some(bytes.len()) || d == 0 {
            return Err(malformed());
        }
        let numerator = &bytes[12..split];
        let denominator = &bytes[split..];
        if numerator.last() == Some(&0) || denominator.last() == Some(&0) {
            return Err(malformed());
        }
        // Admission is shared with encode: no hidden foundation codec ceiling.
        // The byte constructor is safe after our checked frame/input bounds
        // and allocation charge. Round conservatively to 64-bit limbs even
        // on 32-bit hosts so budget decisions remain target-independent.
        let allocated = n
            .div_ceil(8)
            .checked_add(d.div_ceil(8))
            .and_then(|limbs| limbs.checked_mul(8))
            .ok_or(RateError::Overflow)?;
        budget.reserve(
            u64::try_from(allocated).map_err(|_| RateError::Overflow)?,
            2,
        )?;
        let num = BigInt::from_bytes_le(numerator);
        let den = BigInt::from_bytes_le(denominator);
        let rate = Self::from_integers(budget, &num, &den)?;
        if fsym_bigint::metered_cmp(rate.numerator(), &num, budget)?.is_ne()
            || fsym_bigint::metered_cmp(rate.denominator(), &den, budget)?.is_ne()
        {
            return Err(malformed());
        }
        budget.checkpoint()?;
        Ok(rate)
    }
}

fn push_digit(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    value: &BigInt,
    ten: &BigInt,
    digit: u8,
) -> Result<BigInt, RateError> {
    budget.reserve(8, 1)?;
    let digit = BigInt::from(u64::from(digit - b'0'));
    let shifted = metered_multiply(value, ten, budget)?;
    Ok(metered_add(&shifted, &digit, budget)?)
}

fn parse_integer(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    text: &str,
) -> Result<BigInt, RateError> {
    if text.is_empty() || !text.bytes().all(|c| c.is_ascii_digit()) {
        return Err(RateError::Malformed(
            "expected unsigned integer coefficient".into(),
        ));
    }
    budget.reserve(16, 2)?;
    let ten = BigInt::from(10u64);
    let mut value = BigInt::zero();
    for digit in text.bytes() {
        value = push_digit(budget, &value, &ten, digit)?;
    }
    Ok(value)
}

impl fmt::Display for Rate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.numerator(), self.denominator())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_parsing_is_exact_and_reduced() {
        let cx = Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        assert_eq!(
            Rate::from_decimal(&mut budget, "0.075").unwrap(),
            Rate::new(&mut budget, 3, 40).unwrap()
        );
        assert_eq!(
            Rate::from_decimal(&mut budget, "149.37").unwrap(),
            Rate::new(&mut budget, 14937, 100).unwrap()
        );
        assert_eq!(
            Rate::from_decimal(&mut budget, "1").unwrap(),
            Rate::one(&mut budget).unwrap()
        );
        assert_eq!(
            Rate::from_decimal(&mut budget, "0.5").unwrap(),
            Rate::new(&mut budget, 1, 2).unwrap()
        );
        for text in ["abc", ".", "-1", "+1", "1.2.3", "1e3", "NaN", ""] {
            assert!(Rate::from_decimal(&mut budget, text).is_err(), "{text}");
        }
        assert_eq!(
            Rate::new(&mut budget, 1, 0),
            Err(RateError::ZeroDenominator)
        );
    }

    #[test]
    fn inverse_and_bps() {
        let cx = Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        assert_eq!(
            Rate::basis_points(&mut budget, 25),
            Rate::new(&mut budget, 1, 400)
        );
        assert_eq!(
            Rate::new(&mut budget, 2, 3).unwrap().inverse(&mut budget),
            Rate::new(&mut budget, 3, 2)
        );
        assert_eq!(
            Rate::new(&mut budget, 0, 5).unwrap().inverse(&mut budget),
            Err(RateError::ZeroDenominator)
        );
    }

    #[test]
    fn cross_rates_cancel_before_multiplying() {
        let cx = Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let rate = Rate::new(&mut budget, u128::MAX, u128::MAX - 1).unwrap();
        let inverse = rate.inverse(&mut budget).unwrap();
        let one = Rate::one(&mut budget).unwrap();
        assert_eq!(rate.checked_mul(&mut budget, &inverse), Ok(one.clone()));
        assert_eq!(rate.checked_div(&mut budget, &rate), Ok(one));
        let two = Rate::new(&mut budget, 2, 1).unwrap();
        assert_eq!(
            Rate::new(&mut budget, u128::MAX, 1)
                .unwrap()
                .checked_mul(&mut budget, &two)
                .unwrap()
                .to_string(),
            "680564733841876926926749214863536422910/1"
        );
        let zero = Rate::new(&mut budget, 0, u128::MAX).unwrap();
        assert_eq!(zero.checked_mul(&mut budget, &rate), Ok(zero.clone()));
        assert_eq!(rate.checked_mul(&mut budget, &zero), Ok(zero.clone()));
        assert_eq!(
            rate.checked_div(&mut budget, &zero),
            Err(RateError::ZeroDenominator)
        );
        assert_eq!(
            rate.numerator(),
            &BigInt::from_bytes_le(&u128::MAX.to_le_bytes())
        );
        assert_eq!(
            rate.denominator(),
            &BigInt::from_bytes_le(&(u128::MAX - 1).to_le_bytes())
        );
    }

    #[test]
    fn decimal_coefficients_are_reduced_before_narrowing() {
        let cx = Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        assert_eq!(
            Rate::from_decimal(
                &mut budget,
                &format!("{}.0000000000000000000000000000000000000000", u128::MAX)
            ),
            Rate::new(&mut budget, u128::MAX, 1)
        );
        // The decimal mantissa exceeds u128 but its reduced numerator fits.
        assert_eq!(
            Rate::from_decimal(&mut budget, "17014118346046923173168730371588410572.75"),
            Rate::new(
                &mut budget,
                68_056_473_384_187_692_692_674_921_486_353_642_291,
                4
            )
        );
    }

    #[test]
    fn coefficients_and_decimal_precision_exceed_machine_integers() {
        let cx = Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let numerator = "1606938044258990275541962092341162602522202993782792835301377";
        let denominator = "1606938044258990275541962092341162602522202993782792835301376";
        let rate = Rate::from_ratio(&mut budget, numerator, denominator).unwrap();
        assert_eq!(rate.numerator().bits(), 201);
        assert_eq!(rate.denominator().bits(), 201);
        let inverse = rate.inverse(&mut budget).unwrap();
        let one = Rate::one(&mut budget).unwrap();
        assert_eq!(rate.checked_mul(&mut budget, &inverse), Ok(one.clone()));
        assert_eq!(rate.checked_div(&mut budget, &rate), Ok(one));
        let tiny = Rate::from_decimal(
            &mut budget,
            "0.00000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        assert!(tiny.denominator().bits() > 128);
        assert_eq!(
            tiny.to_string(),
            "1/100000000000000000000000000000000000000000000000000"
        );
        let reduced = Rate::from_ratio(
            &mut budget,
            &format!("3{}", "0".repeat(100)),
            &format!("40{}", "0".repeat(100)),
        )
        .unwrap();
        assert_eq!(reduced, Rate::new(&mut budget, 3, 40).unwrap());
        assert_eq!(
            Rate::from_ratio(&mut budget, "1", "0"),
            Err(RateError::ZeroDenominator)
        );
    }

    #[test]
    fn canonical_bytes_have_one_representation_and_round_trip_large_coefficients() {
        let cx = Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let half = Rate::new(&mut budget, 1, 2).unwrap();
        let golden = b"FAR\x01\x01\x00\x00\x00\x01\x00\x00\x00\x01\x02";
        assert_eq!(half.encode(&mut budget).unwrap(), golden);
        for rate in [half, Rate::new(&mut budget, 0, 7).unwrap(), Rate::from_decimal(&mut budget, "123456789012345678901234567890123456789012345678901.000000000000000000000000000000000000000000000000007").unwrap()] {
            let encoded = rate.encode(&mut budget).unwrap();
            assert_eq!(Rate::decode(&mut budget, &encoded), Ok(rate));
            for length in 0..encoded.len() {
                assert!(Rate::decode(&mut budget, &encoded[..length]).is_err());
            }
            let mut trailing = encoded;
            trailing.push(0);
            assert!(Rate::decode(&mut budget, &trailing).is_err());
        }
        for invalid in [
            &b"FAR\x02\x01\x00\x00\x00\x01\x00\x00\x00\x01\x02"[..],
            &b"FAR\x01\x01\x00\x00\x00\x01\x00\x00\x00\x02\x04"[..],
            &b"FAR\x01\x01\x00\x00\x00\x01\x00\x00\x00\x00\x01"[..],
            &b"FAR\x01\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00"[..],
            &b"FAR\x01\xff\xff\xff\xff\xff\xff\xff\xff"[..],
        ] {
            assert!(Rate::decode(&mut budget, invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn large_composition_matches_independent_integer_cross_products() {
        use fgdb_bigint::{BigInt as OracleInt, LimbLimit};
        let limit = LimbLimit::new(32);
        let integer = |text: &str| {
            text.bytes().fold(OracleInt::from_u64(0), |value, digit| {
                value
                    .checked_mul(&OracleInt::from_u64(10), limit)
                    .unwrap()
                    .checked_add(&OracleInt::from_u64(u64::from(digit - b'0')), limit)
                    .unwrap()
            })
        };
        let cx = Cx::detached_cancel_context();
        let mut budget = crate::test_budget(&cx);
        let (an, ad, bn, bd) = (
            "1606938044258990275541962092341162602522202993782792835301377",
            "340282366920938463463374607431768211457",
            "1393796574908163946345982392040522594123779",
            "680564733841876926926749214863536422919",
        );
        let a = Rate::from_ratio(&mut budget, an, ad).unwrap();
        let b = Rate::from_ratio(&mut budget, bn, bd).unwrap();
        for (actual, raw_num, raw_den) in [
            (
                a.checked_mul(&mut budget, &b).unwrap(),
                integer(an).checked_mul(&integer(bn), limit).unwrap(),
                integer(ad).checked_mul(&integer(bd), limit).unwrap(),
            ),
            (
                a.checked_div(&mut budget, &b).unwrap(),
                integer(an).checked_mul(&integer(bd), limit).unwrap(),
                integer(ad).checked_mul(&integer(bn), limit).unwrap(),
            ),
        ] {
            assert_eq!(
                integer(&actual.numerator().to_string())
                    .checked_mul(&raw_den, limit)
                    .unwrap(),
                integer(&actual.denominator().to_string())
                    .checked_mul(&raw_num, limit)
                    .unwrap()
            );
        }
    }

    #[test]
    fn decode_admits_rounded_limb_storage_before_materialization() {
        let cx = Cx::detached_cancel_context();
        let one = b"FAR\x01\x01\x00\x00\x00\x01\x00\x00\x00\x01\x01";
        let mut limits = BudgetLimits::uniform(1_000_000, 0);
        limits.dimensions[Dimension::MemoryBytes.index()] = 15;
        let mut budget = ArithmeticBudget::new(&cx, limits, 8192);
        assert!(matches!(
            Rate::decode(&mut budget, one),
            Err(RateError::Meter(MeterError::Budget(_)))
        ));
        assert_eq!(
            budget.remaining(Dimension::MemoryBytes),
            15,
            "two 8-byte limbs must be admitted atomically"
        );
        assert_eq!(budget.remaining(Dimension::AllocationCount), 1_000_000);
        assert_eq!(
            Rate::decode(&mut crate::test_budget(&cx), one)
                .unwrap()
                .to_string(),
            "1/1"
        );

        // A frame beyond the foundation's unrelated codec ceiling still
        // obeys this caller's policy: work reaches OUR allocation admission,
        // then refuses before lifting either coefficient with a zero budget.
        let n = fsym_bigint::MAX_DECODER_MAGNITUDE_BYTES + 1;
        let mut frame = b"FAR\x01".to_vec();
        frame.extend_from_slice(&(n as u32).to_le_bytes());
        frame.extend_from_slice(&1u32.to_le_bytes());
        frame.resize(12 + n, 1);
        frame.push(1);
        limits.dimensions[Dimension::ComputeSteps.index()] = 2_000_000;
        limits.dimensions[Dimension::MemoryBytes.index()] = 0;
        let mut budget = ArithmeticBudget::new(&cx, limits, frame.len());
        assert!(matches!(
            Rate::decode(&mut budget, &frame),
            Err(RateError::Meter(MeterError::Budget(_)))
        ));
        assert_eq!(budget.remaining(Dimension::AllocationCount), 1_000_000);
    }

    #[test]
    fn limits_refuse_before_allocation_and_cancellation_precedes_charges() {
        let cx = Cx::detached_cancel_context();
        let mut budget = ArithmeticBudget::new(&cx, BudgetLimits::uniform(1000, 0), 8);
        let memory = budget.remaining(Dimension::MemoryBytes);
        assert!(matches!(
            Rate::from_decimal(&mut budget, "123456789"),
            Err(RateError::InputTooLarge { .. })
        ));
        assert!(matches!(
            Rate::decode(&mut budget, &[0; 20]),
            Err(RateError::InputTooLarge { .. })
        ));
        assert_eq!(budget.remaining(Dimension::MemoryBytes), memory);
        let mut no_budget = ArithmeticBudget::new(&cx, BudgetLimits::uniform(0, 0), 8192);
        assert!(matches!(
            Rate::new(&mut no_budget, 1, 2),
            Err(RateError::Meter(MeterError::Budget(_)))
        ));
        cx.set_cancel_requested(true);
        assert_eq!(
            Rate::new(&mut budget, 1, 0),
            Err(RateError::Meter(MeterError::Cancelled))
        );
        assert_eq!(
            Rate::from_decimal(&mut budget, "1"),
            Err(RateError::Meter(MeterError::Cancelled))
        );
        assert_eq!(budget.remaining(Dimension::MemoryBytes), memory);
    }
}
