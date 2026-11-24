use super::*;
use crate::UnitId;

fn shares(total: i128, quantities: &[u128], values: &[u128]) -> Vec<i128> {
    by_units_then_value(Amount::new(UnitId(7), total), quantities, values)
        .unwrap()
        .into_iter()
        .map(|amount| amount.mantissa)
        .collect()
}

#[test]
fn quantity_remainders_precede_value_and_declared_order_breaks_remaining_ties() {
    assert_eq!(shares(100, &[1, 1, 1], &[10, 30, 20]), [33, 34, 33]);
    assert_eq!(shares(100, &[1, 1, 1], &[30, 30, 20]), [34, 33, 33]);
    assert_eq!(shares(2, &[1, 1, 1], &[10, 30, 20]), [0, 1, 1]);
    // The last remainder is 7/10, the others 1/10. Its zero value must
    // still win: secondary values never override an unequal remainder.
    assert_eq!(
        shares(7, &[3, 3, 3, 1], &[u128::MAX, u128::MAX, u128::MAX, 0]),
        [2, 2, 2, 1]
    );
    assert_eq!(shares(6, &[1, 2, 3], &[u128::MAX, 0, 0]), [1, 2, 3]);
    assert_eq!(shares(7, &[0, 1, 1], &[u128::MAX, 0, 1]), [0, 3, 4]);
    assert_eq!(shares(-100, &[1, 1, 1], &[10, 30, 20]), [-33, -34, -33]);
}

#[test]
fn two_key_shape_and_zero_quantities_refuse_even_when_no_amount_is_allocated() {
    for total in [0, 1, -1] {
        for (quantities, values) in [
            (vec![], vec![]),
            (vec![1], vec![]),
            (vec![1], vec![1, 2]),
            (vec![0, 0], vec![1, u128::MAX]),
            (
                vec![1; MAX_ALLOCATION_TARGETS + 1],
                vec![1; MAX_ALLOCATION_TARGETS + 1],
            ),
        ] {
            assert!(
                by_units_then_value(Amount::new(UnitId(7), total), &quantities, &values).is_err()
            );
        }
    }
}

#[test]
fn two_key_signed_boundaries_and_large_quantities_conserve_every_minor_unit() {
    for total in [i128::MIN, -i128::MAX, -1, 0, 1, i128::MAX] {
        for (quantities, values) in [
            (vec![u128::MAX], vec![0]),
            (vec![u128::MAX; 3], vec![0, u128::MAX, 1]),
            (vec![0, u128::MAX, 1], vec![u128::MAX, 0, 1]),
        ] {
            let amounts =
                by_units_then_value(Amount::new(UnitId(7), total), &quantities, &values).unwrap();
            assert_eq!(
                Amount::sum(UnitId(7), amounts.iter().copied())
                    .unwrap()
                    .mantissa,
                total
            );
            for (quantity, amount) in quantities.iter().zip(&amounts) {
                assert_eq!(amount.unit, UnitId(7));
                if *quantity == 0 {
                    assert_eq!(amount.mantissa, 0);
                }
                assert!(amount.mantissa == 0 || amount.mantissa.signum() == total.signum());
            }
        }
    }
    assert_eq!(shares(i128::MIN, &[1], &[u128::MAX]), [i128::MIN]);
}

#[test]
fn two_key_small_integer_grid_matches_direct_rational_floors_and_rank_counts() {
    // This oracle uses bounded native integer arithmetic and counts how many
    // keys precede each target. It does not invoke either allocation sort.
    for total in -31i128..=31 {
        for quantities in [[1u128, 1, 1], [1, 2, 3], [3, 3, 3], [0, 1, 2], [4, 1, 1]] {
            for values in [[0u128, 0, 0], [0, 1, 2], [2, 1, 0], [1, 2, 1]] {
                let denominator: u128 = quantities.iter().sum();
                let products = quantities.map(|q| total.unsigned_abs() * q);
                let floors = products.map(|product| product / denominator);
                let remainders = products.map(|product| product % denominator);
                let residual = total.unsigned_abs() - floors.iter().sum::<u128>();
                let expected: Vec<i128> = (0..3)
                    .map(|i| {
                        let preceding = (0..3)
                            .filter(|&j| {
                                remainders[j] > remainders[i]
                                    || remainders[j] == remainders[i]
                                        && (values[j] > values[i]
                                            || values[j] == values[i] && j < i)
                            })
                            .count() as u128;
                        let magnitude = floors[i] + u128::from(preceding < residual);
                        i128::try_from(magnitude).unwrap() * total.signum()
                    })
                    .collect();
                assert_eq!(shares(total, &quantities, &values), expected);
            }
        }
    }
}
