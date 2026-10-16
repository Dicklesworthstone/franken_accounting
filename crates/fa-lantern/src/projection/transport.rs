//! Capacity-conserving composition of the registered largest-remainder law.
//!
//! A separate Hamilton allocation for every credit can overfill a debit
//! (two one-unit credits and two one-unit debits both award their tie to the
//! first debit). Allocate each credit against the *remaining* debit capacity
//! instead. Credit order and remainder ties follow account identity, never
//! input iteration order. Both margins, not only the credit total, reconcile.

use fa_money::allocation::largest_remainder;
use fa_money::wide::U256;
use fa_money::{Amount, UnitId};
use fgdb_types::VId;

use crate::LanternError;

/// One balanced unit of an entry, with nonnegative leg magnitudes. Repeated
/// accounts are deliberately retained: the caller owns the leg-grain policy.
/// Zero shares are omitted; they are not transfers and must not become graph
/// candidates or inflate contribution counts.
pub(super) fn allocate(
    unit: UnitId,
    mut credits: Vec<(VId, i128)>,
    mut debits: Vec<(VId, i128)>,
) -> Result<Vec<(VId, VId, i128)>, LanternError> {
    fn total(legs: &[(VId, i128)]) -> Result<U256, LanternError> {
        legs.iter().try_fold(U256::ZERO, |sum, (_, value)| {
            let magnitude = u128::try_from(*value)
                .map_err(|_| LanternError::Overflow("negative money-flow leg"))?;
            sum.checked_add(U256::from_u128(magnitude))
                .ok_or(LanternError::Overflow("money-flow margin"))
        })
    }

    let credit_total = total(&credits)?;
    if credit_total != total(&debits)? {
        return Err(LanternError::Overflow("unbalanced money-flow margins"));
    }
    if credit_total.is_zero() {
        return Ok(Vec::new());
    }
    // Sorting both sides also pins the allocation when a snapshot or a
    // proposal's independent legs are enumerated in a different order.
    credits.sort_unstable();
    debits.sort_unstable();
    let mut remaining: Vec<u128> = debits.iter().map(|(_, value)| *value as u128).collect();
    let mut out = Vec::new();
    for (from, amount) in credits {
        if amount == 0 {
            continue;
        }
        let shares = largest_remainder(Amount::new(unit, amount), &remaining)?;
        if shares.len() != remaining.len() {
            return Err(LanternError::Overflow("money-flow allocation shape"));
        }
        for (i, share) in shares.into_iter().enumerate() {
            let magnitude = u128::try_from(share.mantissa)
                .map_err(|_| LanternError::Overflow("negative money-flow share"))?;
            remaining[i] = remaining[i]
                .checked_sub(magnitude)
                .ok_or(LanternError::Overflow("money-flow debit capacity"))?;
            if share.mantissa != 0 {
                out.push((from, debits[i].0, share.mantissa));
            }
        }
    }
    if remaining.iter().any(|value| *value != 0) {
        return Err(LanternError::Overflow("unallocated money-flow debit"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn margins(edges: &[(VId, VId, i128)], credit: bool) -> BTreeMap<VId, U256> {
        let mut totals = BTreeMap::new();
        for (from, to, amount) in edges {
            assert!(*amount > 0);
            let slot = totals
                .entry(if credit { *from } else { *to })
                .or_insert(U256::ZERO);
            *slot = slot.checked_add(U256::from_u128(*amount as u128)).unwrap();
        }
        totals
    }

    fn expected(legs: &[(VId, i128)]) -> BTreeMap<VId, U256> {
        let mut totals = BTreeMap::new();
        for (account, amount) in legs.iter().filter(|(_, amount)| *amount != 0) {
            let slot = totals.entry(*account).or_insert(U256::ZERO);
            *slot = slot.checked_add(U256::from_u128(*amount as u128)).unwrap();
        }
        totals
    }

    #[test]
    fn independent_remainder_ties_cannot_overfill_the_first_debit() {
        let credits = vec![(VId(1), 1), (VId(2), 1)];
        let debits = vec![(VId(3), 1), (VId(4), 1)];
        let edges = allocate(UnitId(0), credits, debits).unwrap();
        assert_eq!(edges, vec![(VId(1), VId(3), 1), (VId(2), VId(4), 1)]);
    }

    #[test]
    fn every_margin_reconciles_over_a_deterministic_grid() {
        for a in 0..=19i128 {
            for b in 0..=19i128 {
                for left in 0..=a + b {
                    let credits = vec![(VId(2), b), (VId(1), a)];
                    let debits = vec![(VId(4), a + b - left), (VId(3), left)];
                    let edges = allocate(UnitId(7), credits.clone(), debits.clone()).unwrap();
                    assert_eq!(
                        margins(&edges, true),
                        expected(&credits),
                        "{credits:?} {debits:?}"
                    );
                    assert_eq!(
                        margins(&edges, false),
                        expected(&debits),
                        "{credits:?} {debits:?}"
                    );
                    let mut reversed_credits = credits;
                    let mut reversed_debits = debits;
                    reversed_credits.reverse();
                    reversed_debits.reverse();
                    assert_eq!(
                        edges,
                        allocate(UnitId(7), reversed_credits, reversed_debits).unwrap()
                    );
                }
            }
        }
    }

    #[test]
    fn wide_totals_repeated_accounts_and_zero_legs_remain_exact() {
        let credits = vec![(VId(1), i128::MAX), (VId(1), i128::MAX), (VId(9), 0)];
        let debits = vec![(VId(2), i128::MAX), (VId(3), i128::MAX)];
        let edges = allocate(UnitId(0), credits.clone(), debits.clone()).unwrap();
        assert_eq!(margins(&edges, true), expected(&credits));
        assert_eq!(margins(&edges, false), expected(&debits));
        assert!(allocate(UnitId(0), vec![], vec![]).unwrap().is_empty());
        assert!(
            allocate(UnitId(0), vec![(VId(1), 0)], vec![])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn corrupt_margins_are_refused_instead_of_inventing_value() {
        for (credits, debits) in [
            (vec![(VId(1), 1)], vec![]),
            (vec![], vec![(VId(2), 1)]),
            (vec![(VId(1), 2)], vec![(VId(2), 1)]),
            (vec![(VId(1), -1)], vec![(VId(2), -1)]),
            (vec![(VId(1), i128::MIN)], vec![(VId(2), i128::MIN)]),
        ] {
            assert!(allocate(UnitId(0), credits, debits).is_err());
        }
    }
}
