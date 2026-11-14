//! Progressive allocation: each marginal band has its own destination weights.
//! The complete source amount is conserved across the same ordered targets.

use super::{MAX_ALLOCATION_TARGETS, largest_remainder};
use crate::amount::{Amount, AmountError, signed_magnitude};

/// Bounds apply to the complete declared schedule, including unoccupied bands.
pub const MAX_ALLOCATION_BRACKETS: usize = 64;
pub const MAX_ALLOCATION_BRACKET_WEIGHTS: usize = 4096;

/// A progressive band ends at this cumulative native-mantissa magnitude.
/// Its lower bound is the preceding band's upper bound (zero for the first).
/// Weights align with the request's ordered destinations, including zeros.
/// Use `u128::MAX` as an explicit final unbounded upper limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationBracket {
    pub upper_bound: u128,
    pub weights: Vec<u128>,
}

pub(super) fn validate_brackets(
    brackets: &[AllocationBracket],
    target_count: usize,
) -> Result<(), AmountError> {
    if brackets.is_empty()
        || brackets.len() > MAX_ALLOCATION_BRACKETS
        || target_count == 0
        || target_count > MAX_ALLOCATION_TARGETS
        || brackets
            .len()
            .checked_mul(target_count)
            .is_none_or(|cells| cells > MAX_ALLOCATION_BRACKET_WEIGHTS)
    {
        return Err(AmountError::Malformed(
            "tiered allocation exceeds its bracket or weight-cell bound".into(),
        ));
    }
    let mut previous = 0;
    for bracket in brackets {
        if bracket.upper_bound <= previous {
            return Err(AmountError::Malformed(
                "tiered cumulative upper bounds must be positive and strictly increasing".into(),
            ));
        }
        if bracket.weights.len() != target_count || bracket.weights.iter().all(|w| *w == 0) {
            return Err(AmountError::Malformed(
                "each tiered bracket needs one weight per target and a nonzero weight sum".into(),
            ));
        }
        previous = bracket.upper_bound;
    }
    Ok(())
}

/// Allocate each occupied marginal band by LargestRemainder, then sum each
/// destination's band shares. Remainder ties use the declared target order
/// independently in every band. A later band's weights never reprice an
/// earlier band. All bands are validated, even for a zero or smaller total.
///
/// For example, gross 250 with bands through 100 at 9:1, through 200 at 8:2,
/// and thereafter at 7:3 produces 205 retained and 45 commission. The weights
/// are explicit relative shares; this law does not infer a tax jurisdiction,
/// percentage, target account or residual recipient.
///
/// Negative totals allocate the same magnitudes and restore the sign, including
/// `i128::MIN`. A total beyond the last declared upper bound is refused whole.
pub fn tiered(total: Amount, brackets: &[AllocationBracket]) -> Result<Vec<Amount>, AmountError> {
    let count = brackets.first().map_or(0, |bracket| bracket.weights.len());
    validate_brackets(brackets, count)?;
    let magnitude = total.mantissa.unsigned_abs();
    if brackets
        .last()
        .is_none_or(|last| last.upper_bound < magnitude)
    {
        return Err(AmountError::Malformed(
            "tiered brackets do not cover the complete allocation total".into(),
        ));
    }
    let mut shares = Vec::new();
    shares
        .try_reserve_exact(count)
        .map_err(|_| AmountError::Overflow)?;
    shares.resize(count, Amount::zero(total.unit));
    let mut lower = 0;
    for bracket in brackets {
        let upper = magnitude.min(bracket.upper_bound);
        let occupied = upper
            .checked_sub(magnitude.min(lower))
            .ok_or(AmountError::Overflow)?;
        if occupied != 0 {
            let band = Amount::new(total.unit, signed_magnitude(occupied, total.mantissa < 0)?);
            for (share, part) in shares
                .iter_mut()
                .zip(largest_remainder(band, &bracket.weights)?)
            {
                share.mantissa = share
                    .mantissa
                    .checked_add(part.mantissa)
                    .ok_or(AmountError::Overflow)?;
            }
        }
        lower = bracket.upper_bound;
    }
    Ok(shares)
}

#[cfg(test)]
mod tests;
