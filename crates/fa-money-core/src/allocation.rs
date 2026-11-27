//! Conservation-preserving allocation for pricing clients with an allocator.

use alloc::vec::Vec;

use crate::{Amount, AmountError, signed, wide::U256};

/// Distribute `total` across `weights` (any non-negative integers; not all
/// zero) so the shares sum to `total` exactly. Ties on the fractional
/// remainder resolve to the lowest index, so the result is deterministic.
/// Negative totals allocate the magnitude and restore the sign.
pub fn largest_remainder(total: Amount, weights: &[u128]) -> Result<Vec<Amount>, AmountError> {
    let weight_sum = weights
        .iter()
        .try_fold(U256::ZERO, |acc, w| acc.checked_add(U256::from_u128(*w)))
        .ok_or(AmountError::Overflow)?;
    if weight_sum.is_zero() {
        return Err(AmountError::ZeroWeights);
    }
    let negative = total.mantissa < 0;
    let mag = total.mantissa.unsigned_abs();
    let mut shares: Vec<u128> = Vec::with_capacity(weights.len());
    let mut remainders: Vec<(U256, usize)> = Vec::with_capacity(weights.len());
    let mut allocated: u128 = 0;
    for (i, w) in weights.iter().enumerate() {
        let (q, r) = U256::from_u128(mag)
            .checked_mul_u128(*w)
            .ok_or(AmountError::Overflow)?
            .checked_div_rem(weight_sum)
            .ok_or(AmountError::InvariantViolation("zero allocation divisor"))?;
        let q = q.to_u128().ok_or(AmountError::Overflow)?;
        shares.push(q);
        remainders.push((r, i));
        allocated = allocated.checked_add(q).ok_or(AmountError::Overflow)?;
    }
    let mut residual = mag
        .checked_sub(allocated)
        .ok_or(AmountError::InvariantViolation(
            "allocation exceeded its total",
        ))?; // < weights.len() by construction
    // Largest remainder first; ties by lowest index.
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    for (r, i) in remainders {
        if residual == 0 {
            break;
        }
        if r.is_zero() {
            // No fractional remainder anywhere left — cannot happen while residual > 0,
            // but keep the loop total rather than trusting the arithmetic.
            break;
        }
        shares[i] = shares[i].checked_add(1).ok_or(AmountError::Overflow)?;
        residual = residual.checked_sub(1).ok_or(AmountError::Overflow)?;
    }
    if residual != 0 {
        return Err(AmountError::InvariantViolation(
            "allocation residual was not fully distributed",
        ));
    }
    shares
        .into_iter()
        .map(|s| Ok(Amount::new(total.unit, signed(s, negative)?)))
        .collect()
}
