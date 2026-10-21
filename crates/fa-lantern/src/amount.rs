//! Checked arithmetic on amount mantissas (FA-INV-06; bead fa-4aym).
//!
//! Every amount a procedure folds is an `i128` mantissa. A sum, difference,
//! negation or ratio that leaves the representable range is a typed
//! [`LanternError::Overflow`] naming its accumulator, never a wrapped,
//! saturated or panicking value. Products of two amounts, and the
//! largest-remainder apportionment built on them, run in exact 256-bit
//! intermediates, so a valid large flow (an 18-decimal token, say) is
//! computed rather than refused. The crate denies
//! `clippy::arithmetic_side_effects` on 128-bit integers and disallows their
//! saturating and wrapping methods (`clippy.toml`), so raw amount arithmetic
//! does not pass the gate.

use core::cmp::Ordering;

use fa_money::Side;
use fa_money::wide::U256;
use fgdb_types::VId;

use crate::LanternError;

pub(crate) fn amount_sum(
    left: i128,
    right: i128,
    accumulator: &'static str,
) -> Result<i128, LanternError> {
    left.checked_add(right)
        .ok_or(LanternError::Overflow(accumulator))
}

pub(crate) fn amount_difference(
    left: i128,
    right: i128,
    accumulator: &'static str,
) -> Result<i128, LanternError> {
    left.checked_sub(right)
        .ok_or(LanternError::Overflow(accumulator))
}

pub(crate) fn amount_negated(value: i128, accumulator: &'static str) -> Result<i128, LanternError> {
    value
        .checked_neg()
        .ok_or(LanternError::Overflow(accumulator))
}

/// An amount's magnitude as a signed amount (`i128::MIN` has none).
pub(crate) fn amount_magnitude(value: i128, what: &'static str) -> Result<i128, LanternError> {
    i128::try_from(value.unsigned_abs()).map_err(|_| LanternError::Overflow(what))
}

/// A leg's signed contribution: its magnitude, negated for a credit.
pub(crate) fn signed_leg(side: Side, mantissa: i128) -> Result<i128, LanternError> {
    let magnitude = amount_magnitude(mantissa, "leg magnitude")?;
    match side {
        Side::Debit => Ok(magnitude),
        Side::Credit => amount_negated(magnitude, "leg magnitude"),
    }
}

/// `amount * bps / 10_000`, truncated, for a nonnegative amount and basis
/// points: exact in 256 bits, so a large amount is scaled, not refused.
pub(crate) fn amount_scaled_bps(
    amount: i128,
    bps: i128,
    what: &'static str,
) -> Result<i128, LanternError> {
    wide_product(amount, bps, what)?
        .checked_div_rem(U256::from_u128(10_000))
        .and_then(|(quotient, _)| quotient.to_u128())
        .and_then(|quotient| i128::try_from(quotient).ok())
        .ok_or(LanternError::Overflow(what))
}

/// Exact, truncated basis points. A valid large flow must not be refused merely
/// because multiplying its mantissa by 10,000 needs more than 128 bits.
pub(crate) fn amount_share_bps(
    numerator: i128,
    denominator: i128,
    statistic: &'static str,
) -> Result<i128, LanternError> {
    let numerator = u128::try_from(numerator).map_err(|_| LanternError::Overflow(statistic))?;
    let denominator = u128::try_from(denominator).map_err(|_| LanternError::Overflow(statistic))?;
    U256::from_u128(numerator)
        .checked_mul_u128(10_000)
        .and_then(|scaled| scaled.checked_div_rem(U256::from_u128(denominator)))
        .and_then(|(quotient, _)| quotient.to_u128())
        .and_then(|quotient| i128::try_from(quotient).ok())
        .ok_or(LanternError::Overflow(statistic))
}

/// The exact product of two nonnegative amounts.
pub(crate) fn wide_product(
    left: i128,
    right: i128,
    what: &'static str,
) -> Result<U256, LanternError> {
    let left = u128::try_from(left).map_err(|_| LanternError::Overflow(what))?;
    let right = u128::try_from(right).map_err(|_| LanternError::Overflow(what))?;
    Ok(U256::from_product(left, right))
}

/// Orders `a_num / a_den` against `b_num / b_den` exactly, by comparing the
/// cross products `a_num * b_den` and `b_num * a_den` in 256 bits.
pub(crate) fn ratio_cmp(a_num: u128, a_den: u128, b_num: u128, b_den: u128) -> Ordering {
    U256::from_product(a_num, b_den).cmp(&U256::from_product(b_num, a_den))
}

/// Largest-remainder apportionment of `pool` by the exact shares
/// `numerators[i] / denominator`, which sum to `pool`: each share's floor,
/// then one more unit to the largest remainders, ties to the smaller
/// `tie_breaks` handle.
pub(crate) fn largest_remainder(
    pool: i128,
    numerators: &[U256],
    denominator: i128,
    tie_breaks: &[VId],
) -> Result<Vec<i128>, LanternError> {
    if numerators.is_empty() || pool <= 0 || denominator <= 0 {
        return Ok(vec![0; numerators.len()]);
    }
    let divisor = U256::from_u128(denominator.unsigned_abs());
    let mut quotas = Vec::with_capacity(numerators.len());
    let mut remainders = Vec::with_capacity(numerators.len());
    let mut allocated = 0i128;
    for ((idx, numerator), &tie_break) in numerators.iter().enumerate().zip(tie_breaks) {
        let (quotient, remainder) = numerator
            .checked_div_rem(divisor)
            .ok_or(LanternError::Overflow("largest remainder divisor"))?;
        let quota = quotient
            .to_u128()
            .and_then(|q| i128::try_from(q).ok())
            .ok_or(LanternError::Overflow("largest remainder quota"))?;
        allocated = amount_sum(allocated, quota, "largest remainder quota sum")?;
        quotas.push(quota);
        remainders.push((idx, remainder, tie_break));
    }
    // Exact shares summing to the pool leave fewer missing units than shares.
    let shortfall = amount_difference(pool, allocated, "largest remainder shortfall")?;
    let shortfall = usize::try_from(shortfall)
        .ok()
        .filter(|&s| s < quotas.len())
        .ok_or(LanternError::Overflow("largest remainder shortfall"))?;
    remainders.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.2.cmp(&b.2)));
    for &(idx, _, _) in remainders.iter().take(shortfall) {
        quotas[idx] = amount_sum(quotas[idx], 1, "largest remainder increment")?;
    }
    Ok(quotas)
}
