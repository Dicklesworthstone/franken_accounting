use super::*;
use crate::UnitId;

fn band(upper_bound: u128, weights: &[u128]) -> AllocationBracket {
    AllocationBracket {
        upper_bound,
        weights: weights.to_vec(),
    }
}

fn values(total: i128, brackets: &[AllocationBracket]) -> Vec<i128> {
    tiered(Amount::new(UnitId(7), total), brackets)
        .unwrap()
        .into_iter()
        .map(|share| share.mantissa)
        .collect()
}

#[test]
fn progressive_commission_allocates_each_marginal_band_without_repricing() {
    let brackets = [
        band(10_000, &[9, 1]),
        band(20_000, &[8, 2]),
        band(u128::MAX, &[7, 3]),
    ];
    for (total, expected) in [
        (0, [0, 0]),
        (5_000, [4_500, 500]),
        (10_000, [9_000, 1_000]),
        (15_000, [13_000, 2_000]),
        (20_000, [17_000, 3_000]),
        (25_000, [20_500, 4_500]),
    ] {
        assert_eq!(values(total, &brackets), expected);
        assert_eq!(values(-total, &brackets), expected.map(|share| -share));
    }
}

#[test]
fn each_band_has_its_own_exact_remainder_tie_and_zero_weight_targets() {
    let brackets = [band(1, &[1, 1, 0]), band(2, &[0, 1, 1])];
    assert_eq!(values(2, &brackets), [1, 1, 0]);
    assert_eq!(values(-2, &brackets), [-1, -1, 0]);
    assert_eq!(
        values(7, &[band(3, &[1, 1, 1]), band(7, &[0, 1, 1])]),
        [1, 3, 3]
    );
}

#[test]
fn signed_extremes_and_wide_weights_preserve_the_complete_total() {
    for total in [i128::MIN, -i128::MAX, -1, 0, 1, i128::MAX] {
        let amount = Amount::new(UnitId(7), total);
        for brackets in [
            vec![band(u128::MAX, &[u128::MAX])],
            vec![band(u128::MAX, &[u128::MAX, u128::MAX, 0])],
            vec![
                band(1, &[0, 1, 1]),
                band(10, &[u128::MAX, u128::MAX, u128::MAX]),
                band(u128::MAX, &[1, 0, 1]),
            ],
        ] {
            let shares = tiered(amount, &brackets).unwrap();
            assert_eq!(Amount::sum(amount.unit, shares.iter().copied()), Ok(amount));
            assert!(
                shares.iter().all(|share| {
                    share.mantissa == 0 || share.mantissa.signum() == total.signum()
                })
            );
        }
    }
}

#[test]
fn malformed_or_uncovered_schedules_refuse_even_unused_bands() {
    for brackets in [
        vec![],
        vec![band(0, &[1, 1])],
        vec![band(3, &[1, 1]), band(3, &[2, 1])],
        vec![band(4, &[1, 1]), band(3, &[2, 1])],
        vec![band(3, &[1, 1]), band(5, &[2])],
        vec![band(3, &[1, 1]), band(5, &[0, 0])],
        vec![band(3, &[])],
        (1..=65).map(|upper| band(upper, &[1])).collect(),
        vec![band(3, &vec![1; 4096]), band(5, &vec![1; 4096])],
    ] {
        for total in [0, 1] {
            assert!(tiered(Amount::new(UnitId(7), total), &brackets).is_err());
        }
    }
    for total in [-6, 6] {
        assert!(tiered(Amount::new(UnitId(7), total), &[band(5, &[1, 1])]).is_err());
    }
    let at_bound = vec![band(u128::MAX, &vec![1; MAX_ALLOCATION_BRACKET_WEIGHTS])];
    assert_eq!(values(7, &at_bound).iter().sum::<i128>(), 7);
}

#[test]
fn progressive_allocation_agrees_with_an_independent_integer_grid() {
    // Independent small-integer oracle: enumerate each band's floors and
    // exact fractional ranks, then combine their target columns.
    for first in 1u128..=5 {
        for second in first + 1..=first + 5 {
            for a in 0u128..=4 {
                for b in 1u128..=4 {
                    let brackets = [band(first, &[a, b]), band(second, &[b, a])];
                    for total in 0..=second {
                        let mut expected = [0i128; 2];
                        for (width, weights) in [
                            (total.min(first), [a, b]),
                            (total - total.min(first), [b, a]),
                        ] {
                            let denominator = a + b;
                            let mut share = weights.map(|weight| width * weight / denominator);
                            let fractions = weights.map(|weight| width * weight % denominator);
                            if share[0] + share[1] < width {
                                share[usize::from(fractions[1] > fractions[0])] += 1;
                            }
                            expected[0] += share[0] as i128;
                            expected[1] += share[1] as i128;
                        }
                        assert_eq!(values(total as i128, &brackets), expected);
                        assert_eq!(values(-(total as i128), &brackets), expected.map(|s| -s));
                    }
                }
            }
        }
    }
}
