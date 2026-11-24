//! Law 6: quantities establish Hamilton shares; values resolve residual ties.
//! A secondary value is an explicit ordering key, never a price multiplied
//! into the quantity, a fallback weight, or an authority to alter a floor.

use super::MAX_ALLOCATION_TARGETS;
use crate::amount::{Amount, AmountError, signed_magnitude};
use crate::wide::U256;

/// Allocate in proportion to nonnegative `quantities`. Floor each exact
/// magnitude share, then assign residual minor units by fractional remainder
/// descending, `values` descending on an equal remainder, and input order on
/// a remaining tie. Values must correspond one-for-one to quantities.
///
/// At least one quantity must be positive, even for a zero total. A zero
/// quantity receives zero regardless of its value. Negative totals allocate
/// the magnitude and restore the sign, including `i128::MIN`. This law does
/// not infer prices, multiply quantities by values, or choose a cost driver.
pub fn by_units_then_value(
    total: Amount,
    quantities: &[u128],
    values: &[u128],
) -> Result<Vec<Amount>, AmountError> {
    if quantities.is_empty()
        || quantities.len() > MAX_ALLOCATION_TARGETS
        || values.len() != quantities.len()
    {
        return Err(AmountError::Malformed(
            "two-key allocation requires one value per quantity and 1..=4096 targets".into(),
        ));
    }
    let denominator = quantities
        .iter()
        .try_fold(U256::ZERO, |sum, quantity| {
            sum.checked_add(U256::from_u128(*quantity))
        })
        .ok_or(AmountError::Overflow)?;
    if denominator.is_zero() {
        return Err(AmountError::Malformed(
            "allocation quantities sum to zero".into(),
        ));
    }
    let magnitude = total.mantissa.unsigned_abs();
    let mut shares = Vec::new();
    let mut ranks = Vec::new();
    shares
        .try_reserve_exact(quantities.len())
        .map_err(|_| AmountError::Overflow)?;
    ranks
        .try_reserve_exact(quantities.len())
        .map_err(|_| AmountError::Overflow)?;
    let mut allocated = 0u128;
    for (index, quantity) in quantities.iter().enumerate() {
        let (quotient, remainder) = U256::from_product(magnitude, *quantity)
            .checked_div_rem(denominator)
            .ok_or(AmountError::InvariantViolation("zero allocation divisor"))?;
        let share = quotient.to_u128().ok_or(AmountError::Overflow)?;
        allocated = allocated.checked_add(share).ok_or(AmountError::Overflow)?;
        shares.push(share);
        ranks.push((remainder, values[index], index));
    }
    let residual = magnitude
        .checked_sub(allocated)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(AmountError::InvariantViolation(
            "invalid allocation residual",
        ))?;
    if residual >= quantities.len() {
        return Err(AmountError::InvariantViolation(
            "invalid allocation residual",
        ));
    }
    ranks.sort_unstable_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.2.cmp(&b.2))
    });
    for (remainder, _, index) in ranks.into_iter().take(residual) {
        if remainder.is_zero() {
            return Err(AmountError::InvariantViolation(
                "a zero quantity or exact share cannot receive a residual unit",
            ));
        }
        shares[index] = shares[index].checked_add(1).ok_or(AmountError::Overflow)?;
    }
    shares
        .into_iter()
        .map(|share| {
            Ok(Amount::new(
                total.unit,
                signed_magnitude(share, total.mantissa < 0)?,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests;
