//! Exact cumulative straight-line fraction, using bounded scalar arithmetic.
//!
//! This file deliberately depends only on the standard library. Its oracle
//! tests can also run directly with `rustc --test fraction.rs`.

/// Return the quotient and remainder of `basis * elapsed / life` without
/// constructing the potentially 160-bit product. The elapsed coordinate is
/// bounded by life, so the whole-number contribution cannot exceed `basis`;
/// the fractional contribution multiplies two values bounded by `u32::MAX`.
pub(crate) fn cumulative_fraction(basis: u128, elapsed: u32, life: u32) -> Option<(u128, u128)> {
    if life == 0 || elapsed > life {
        return None;
    }
    let denominator = u128::from(life);
    let elapsed = u128::from(elapsed);
    let whole = basis.checked_div(denominator)?.checked_mul(elapsed)?;
    let fractional = basis.checked_rem(denominator)?.checked_mul(elapsed)?;
    Some((
        whole.checked_add(fractional.checked_div(denominator)?)?,
        fractional.checked_rem(denominator)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::cumulative_fraction;

    /// Independent schoolbook multiplication and long division in base 2^32.
    /// No production wide arithmetic, quotient decomposition or rounding is
    /// called by this oracle. Every intermediate fits in one u64 word.
    fn word_oracle(basis: u128, elapsed: u32, life: u32) -> (u128, u128) {
        let bytes = basis.to_le_bytes();
        let mut words = [0_u32; 5];
        let mut carry = 0_u64;
        for (index, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
            let digit = u32::from_le_bytes(*chunk);
            let product = u64::from(digit)
                .checked_mul(u64::from(elapsed))
                .unwrap()
                .checked_add(carry)
                .unwrap();
            words[index] = u32::try_from(product & u64::from(u32::MAX)).unwrap();
            carry = product >> 32;
        }
        words[4] = u32::try_from(carry).unwrap();
        let mut remainder = 0_u64;
        for word in words.iter_mut().rev() {
            let dividend = (remainder << 32) | u64::from(*word);
            *word = u32::try_from(dividend.checked_div(u64::from(life)).unwrap()).unwrap();
            remainder = dividend.checked_rem(u64::from(life)).unwrap();
        }
        assert_eq!(words[4], 0);
        let quotient = words[..4]
            .iter()
            .rev()
            .fold(0_u128, |value, word| (value << 32) | u128::from(*word));
        (quotient, u128::from(remainder))
    }

    #[test]
    fn small_fractions_match_independent_direct_product() {
        for basis in 0_u128..=127 {
            for life in 1_u32..=32 {
                for elapsed in 0..=life {
                    let numerator = basis.checked_mul(u128::from(elapsed)).unwrap();
                    assert_eq!(
                        cumulative_fraction(basis, elapsed, life),
                        Some((
                            numerator.checked_div(u128::from(life)).unwrap(),
                            numerator.checked_rem(u128::from(life)).unwrap(),
                        ))
                    );
                }
            }
        }
    }

    #[test]
    fn full_width_fractions_match_independent_word_arithmetic() {
        let bases = [
            0,
            1,
            u128::from(u64::MAX),
            1_u128 << 100,
            u128::try_from(i128::MAX).unwrap(),
            u128::MAX,
        ];
        for basis in bases {
            for life in [1_u32, 2, 3, 7, 12, 1200, u32::from(u16::MAX), u32::MAX] {
                for elapsed in [0, 1, life / 2, life - 1, life] {
                    assert_eq!(
                        cumulative_fraction(basis, elapsed, life),
                        Some(word_oracle(basis, elapsed, life)),
                        "basis={basis} elapsed={elapsed} life={life}"
                    );
                }
            }
        }
    }

    #[test]
    fn zero_life_and_out_of_schedule_coordinates_are_refused() {
        assert_eq!(cumulative_fraction(1, 0, 0), None);
        assert_eq!(cumulative_fraction(1, 1, 0), None);
        assert_eq!(cumulative_fraction(1, 13, 12), None);
    }
}
