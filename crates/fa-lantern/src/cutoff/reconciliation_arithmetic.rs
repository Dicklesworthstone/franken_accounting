//! Exact magnitude of a signed reconciliation difference. An i128 statistic
//! cannot represent every difference between two i128 balances. Such a result
//! must refuse, never panic on subtraction or wrap to a negative discrepancy.

pub(super) fn discrepancy(actual: i128, attested: i128) -> Option<i128> {
    i128::try_from(actual.abs_diff(attested)).ok()
}

#[cfg(test)]
mod tests {
    use super::discrepancy;

    #[test]
    fn signs_do_not_change_the_magnitude_or_count_equal_negative_balances_as_drift() {
        for (actual, attested, expected) in [
            (70, 0, 70), (0, 70, 70), (-70, 0, 70), (0, -70, 70),
            (-70, -20, 50), (-20, -70, 50), (70, -20, 90), (-70, 20, 90),
            (i128::MIN, i128::MIN, 0), (i128::MAX, i128::MAX, 0),
            (i128::MIN, -1, i128::MAX), (0, i128::MAX, i128::MAX),
        ] {
            assert_eq!(discrepancy(actual, attested), Some(expected));
            assert_eq!(discrepancy(attested, actual), Some(expected));
        }
    }

    #[test]
    fn every_unrepresentable_endpoint_difference_refuses_instead_of_wrapping() {
        for (actual, attested) in [
            (i128::MIN, 0), (i128::MAX, -1),
            (i128::MIN, i128::MAX), (i128::MIN + 1, 1),
        ] {
            assert_eq!(discrepancy(actual, attested), None);
            assert_eq!(discrepancy(attested, actual), None);
        }
    }

    #[test]
    fn full_width_grid_matches_an_independent_signed_difference_oracle() {
        let mut values = vec![i128::MIN, i128::MAX, 0, 1, -1];
        for bit in 1..127 {
            let value = 1i128 << bit;
            values.extend([value, -value, value - 1, 1 - value]);
        }
        for &actual in &values {
            for &attested in &values {
                // On opposite sides of zero the two unsigned magnitudes sum;
                // on the same side, subtract the lesser from the greater.
                // Every possible i128 endpoint difference fits u128 exactly.
                let (a, b) = (actual.unsigned_abs(), attested.unsigned_abs());
                let expected = if actual.is_negative() != attested.is_negative() {
                    a.checked_add(b).expect("signed endpoint difference fits u128")
                } else if a >= b { a - b } else { b - a };
                assert_eq!(discrepancy(actual, attested), i128::try_from(expected).ok());
            }
        }
    }
}
