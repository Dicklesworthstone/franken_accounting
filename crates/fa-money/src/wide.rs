//! Exact stack-only wide arithmetic shared with bounded pricing clients.

pub use fa_money_core::wide::U256;

#[cfg(test)]
mod tests {
    use super::*;
    use fgdb_bigint::{BigInt, LimbLimit, Sign};

    const ORACLE_LIMIT: LimbLimit = LimbLimit::new(16);

    // Each limb is a 64-bit word of the value: the narrowing is the split.
    #[allow(clippy::cast_possible_truncation)]
    fn bigint(value: U256) -> BigInt {
        let mut limbs = vec![
            value.lo as u64,
            (value.lo >> 64) as u64,
            value.hi as u64,
            (value.hi >> 64) as u64,
        ];
        while limbs.last() == Some(&0) {
            limbs.pop();
        }
        let sign = if limbs.is_empty() {
            Sign::Zero
        } else {
            Sign::Positive
        };
        BigInt::from_canonical_limbs(sign, limbs.into_boxed_slice(), ORACLE_LIMIT).unwrap()
    }

    fn narrow(value: &BigInt) -> Option<U256> {
        let limbs = value.magnitude_limbs_le();
        if value.is_negative() || limbs.len() > 4 {
            return None;
        }
        let limb = |i| u128::from(limbs.get(i).copied().unwrap_or(0));
        Some(U256 {
            lo: limb(0) | (limb(1) << 64),
            hi: limb(2) | (limb(3) << 64),
        })
    }

    fn compare_with_bigint(a: U256, b: U256) {
        let left = bigint(a);
        let right = bigint(b);
        assert_eq!(
            a.checked_add(b),
            narrow(&left.checked_add(&right, ORACLE_LIMIT).unwrap())
        );
        assert_eq!(
            a.checked_sub(b),
            narrow(&left.checked_sub(&right, ORACLE_LIMIT).unwrap())
        );
        let product = left
            .checked_mul(&BigInt::from_u128(b.lo), ORACLE_LIMIT)
            .unwrap();
        assert_eq!(a.checked_mul_u128(b.lo), narrow(&product));
        let full = BigInt::from_u128(a.lo)
            .checked_mul(&BigInt::from_u128(b.hi), ORACLE_LIMIT)
            .unwrap();
        assert_eq!(Some(U256::from_product(a.lo, b.hi)), narrow(&full));
        let root = a.isqrt();
        assert!(U256::from_product(root, root) <= a);
        if let Some(next) = root.checked_add(1) {
            assert!(U256::from_product(next, next) > a);
        }
        if b.is_zero() {
            assert_eq!(a.checked_div_rem(b), None);
            assert!(left.checked_div_rem(&right, ORACLE_LIMIT).is_err());
        } else {
            let (quotient, remainder) = left.checked_div_rem(&right, ORACLE_LIMIT).unwrap();
            assert_eq!(
                a.checked_div_rem(b),
                Some((narrow(&quotient).unwrap(), narrow(&remainder).unwrap()))
            );
        }
        compare_with_frankensympy(a, b);
    }

    // A second oracle for the std U256 implementation. FrankenSymPy is
    // independent of that implementation, but is NOT an independent oracle
    // for the Rate/Amount operations it implements in production.
    fn compare_with_frankensympy(a: U256, b: U256) {
        use fsym_bigint::{
            BigInt as Exact, metered_add, metered_div_rem, metered_multiply, metered_subtract,
        };
        let integer = |value: U256| {
            let mut bytes = [0u8; 32];
            bytes[..16].copy_from_slice(&value.lo.to_le_bytes());
            bytes[16..].copy_from_slice(&value.hi.to_le_bytes());
            Exact::from_bytes_le(&bytes)
        };
        let narrow = |value: &Exact| {
            if value.is_negative() || value.bits() > 256 {
                return None;
            }
            let bytes = value.to_bytes_le();
            let mut padded = [0u8; 32];
            padded[..bytes.len()].copy_from_slice(&bytes);
            Some(U256 {
                lo: u128::from_le_bytes(padded[..16].try_into().unwrap()),
                hi: u128::from_le_bytes(padded[16..].try_into().unwrap()),
            })
        };
        let mut budget = fsym_budget::Budget::new(fsym_budget::BudgetLimits::uniform(1_000_000, 0));
        let left = integer(a);
        let right = integer(b);
        assert_eq!(
            a.checked_add(b),
            narrow(&metered_add(&left, &right, &mut budget).unwrap())
        );
        assert_eq!(
            a.checked_sub(b),
            narrow(&metered_subtract(&left, &right, &mut budget).unwrap())
        );
        assert_eq!(
            a.checked_mul_u128(b.lo),
            narrow(
                &metered_multiply(
                    &left,
                    &Exact::from_bytes_le(&b.lo.to_le_bytes()),
                    &mut budget
                )
                .unwrap()
            )
        );
        let division = metered_div_rem(&left, &right, &mut budget).unwrap();
        assert_eq!(
            a.checked_div_rem(b),
            division.map(|(q, r)| (narrow(&q).unwrap(), narrow(&r).unwrap()))
        );
    }

    #[test]
    fn wide_operations_match_bigint_on_boundaries_and_seeded_values() {
        let boundary = [
            U256::ZERO,
            U256::from_u128(1),
            U256::from_u128(u128::MAX),
            U256 { hi: 1, lo: 0 },
            U256 {
                hi: 1,
                lo: u128::MAX,
            },
            U256 {
                hi: 1 << 127,
                lo: 0,
            },
            U256 {
                hi: u128::MAX,
                lo: u128::MAX,
            },
        ];
        for a in boundary {
            for b in boundary {
                compare_with_bigint(a, b);
            }
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            u128::from(state)
        };
        for _ in 0..512 {
            let a = U256 {
                hi: next() | (next() << 64),
                lo: next() | (next() << 64),
            };
            let b = U256 {
                hi: next() | (next() << 64),
                lo: next() | (next() << 64),
            };
            compare_with_bigint(a, b);
        }
    }

    #[test]
    fn mul_matches_u128_where_it_fits() {
        for &(a, b) in &[
            (0u128, 0u128),
            (1, u128::MAX),
            (u64::MAX as u128, u64::MAX as u128),
            (123_456_789, 987_654_321),
        ] {
            let U256 { lo, hi } = U256::from_product(a, b);
            if let Some(p) = a.checked_mul(b) {
                assert_eq!((lo, hi), (p, 0));
            } else {
                assert!(hi != 0);
            }
        }
    }

    #[test]
    fn div_rem_round_trips() {
        let cases: &[(u128, u128, u128)] = &[
            (u128::MAX, u128::MAX, 7),
            (u64::MAX as u128, 12345, 10),
            (1, 0, 3),
            (0, 1_000_000_007, 13),
            (u128::MAX, 0, u128::MAX),
        ];
        for &(a, m, d) in cases {
            let x = U256::from_u128(a).checked_mul_u128(m).unwrap();
            let (q, r) = x.checked_div_rem(U256::from_u128(d)).unwrap();
            assert!(r < U256::from_u128(d));
            let back = q.checked_mul_u128(d).unwrap().checked_add(r).unwrap();
            assert_eq!(
                back, x,
                "q*d + r must equal the dividend for a={a} m={m} d={d}"
            );
        }
    }

    #[test]
    fn overflow_is_detected() {
        let big = U256 {
            hi: u128::MAX,
            lo: u128::MAX,
        };
        assert!(big.checked_mul_u128(2).is_none());
        assert!(big.checked_add(U256::from_u128(1)).is_none());
        assert!(U256::ZERO.checked_sub(U256::from_u128(1)).is_none());
    }
}
