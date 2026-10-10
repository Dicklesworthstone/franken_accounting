//! Allocation laws (plan §6.3). `largest_remainder` is Hamilton's method:
//! floor every share, then hand the residual units to the largest fractional
//! remainders in deterministic order. Conservation (`Σ shares = total`) is a
//! theorem, and the test below checks it on a grid.

use crate::amount::{Amount, AmountError};
use crate::wide::U256;

/// Distribute `total` across `weights` (any non-negative integers; not all
/// zero) so the shares sum to `total` exactly. Ties on the fractional
/// remainder resolve to the lowest index, so the result is deterministic.
/// Negative totals allocate the magnitude and restore the sign.
pub fn largest_remainder(total: Amount, weights: &[u128]) -> Result<Vec<Amount>, AmountError> {
    let weight_sum: u128 = weights
        .iter()
        .try_fold(0u128, |acc, w| acc.checked_add(*w))
        .ok_or(AmountError::Overflow)?;
    if weight_sum == 0 {
        return Err(AmountError::Malformed(
            "allocation weights sum to zero".into(),
        ));
    }
    let negative = total.mantissa < 0;
    let mag = total.mantissa.unsigned_abs();
    let mut shares: Vec<u128> = Vec::with_capacity(weights.len());
    let mut remainders: Vec<(u128, usize)> = Vec::with_capacity(weights.len());
    let mut allocated: u128 = 0;
    for (i, w) in weights.iter().enumerate() {
        let (q, r) = U256::from_u128(mag)
            .checked_mul_u128(*w)
            .ok_or(AmountError::Overflow)?
            .div_rem_u128(weight_sum);
        let q = q.to_u128().ok_or(AmountError::Overflow)?;
        shares.push(q);
        remainders.push((r, i));
        allocated = allocated.checked_add(q).ok_or(AmountError::Overflow)?;
    }
    let mut residual = mag - allocated; // < weights.len() by construction
    // Largest remainder first; ties by lowest index.
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    for (r, i) in remainders {
        if residual == 0 {
            break;
        }
        if r == 0 {
            // No fractional remainder anywhere left — cannot happen while residual > 0,
            // but keep the loop total rather than trusting the arithmetic.
            break;
        }
        shares[i] += 1;
        residual -= 1;
    }
    debug_assert_eq!(
        residual, 0,
        "largest-remainder residual must be fully distributed"
    );
    shares
        .into_iter()
        .map(|s| {
            let m = i128::try_from(s).map_err(|_| AmountError::Overflow)?;
            Ok(Amount::new(total.unit, if negative { -m } else { m }))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::UnitId;

    #[test]
    fn conserves_total_on_a_grid() {
        let unit = UnitId(0);
        for total in [0i128, 1, 2, 7, 100, 101, 999, 1_000_003, -7, -101] {
            for weights in [
                vec![1u128, 1, 1],
                vec![1, 2, 3],
                vec![5, 0, 5],
                vec![7],
                vec![1, 1, 1, 1, 1, 1, 1],
                vec![3, 3, 3, 1],
            ] {
                let shares = largest_remainder(Amount::new(unit, total), &weights).unwrap();
                let sum: i128 = shares.iter().map(|a| a.mantissa).sum();
                assert_eq!(
                    sum, total,
                    "total={total} weights={weights:?} shares={shares:?}"
                );
                assert_eq!(shares.len(), weights.len());
            }
        }
    }

    #[test]
    fn deterministic_ties_go_to_the_lowest_index() {
        let unit = UnitId(0);
        // 100 across three equal weights: 33, 33, 33 with 1 left over -> index 0 gets it.
        let s = largest_remainder(Amount::new(unit, 100), &[1, 1, 1]).unwrap();
        assert_eq!(
            s.iter().map(|a| a.mantissa).collect::<Vec<_>>(),
            vec![34, 33, 33]
        );
        // 7 across 3,3,3,1: floors 2,2,2,0 (sum 6), remainders 1,1,1,7/10... exact: 7*3/10=2 r1 each; 7*1/10=0 r7 -> index 3 largest remainder
        let s = largest_remainder(Amount::new(unit, 7), &[3, 3, 3, 1]).unwrap();
        assert_eq!(
            s.iter().map(|a| a.mantissa).collect::<Vec<_>>(),
            vec![2, 2, 2, 1]
        );
    }

    #[test]
    fn zero_weights_are_refused() {
        assert!(largest_remainder(Amount::new(UnitId(0), 5), &[0, 0]).is_err());
    }
}
