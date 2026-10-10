//! Registered rounding laws (plan §6.2). Each law is a total function over the
//! exact `(quotient, remainder, denominator)` of a division, applied to the
//! magnitude with the sign known, so directed laws mean what they say for
//! negative values too.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RoundingLaw {
    HalfUp,
    HalfDown,
    HalfEven,
    HalfAwayFromZero,
    HalfTowardZero,
    Ceiling,
    Floor,
    TowardZero,
    AwayFromZero,
}

impl RoundingLaw {
    pub const ALL: [RoundingLaw; 9] = [
        Self::HalfUp,
        Self::HalfDown,
        Self::HalfEven,
        Self::HalfAwayFromZero,
        Self::HalfTowardZero,
        Self::Ceiling,
        Self::Floor,
        Self::TowardZero,
        Self::AwayFromZero,
    ];

    /// Registry id (stable; `rounding_laws.toml` row order).
    pub fn id(self) -> u16 {
        match self {
            Self::HalfUp => 1,
            Self::HalfDown => 2,
            Self::HalfEven => 3,
            Self::HalfAwayFromZero => 4,
            Self::HalfTowardZero => 5,
            Self::Ceiling => 6,
            Self::Floor => 7,
            Self::TowardZero => 8,
            Self::AwayFromZero => 9,
        }
    }

    pub fn from_id(id: u16) -> Option<Self> {
        Self::ALL.iter().copied().find(|l| l.id() == id)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::HalfUp => "HalfUp",
            Self::HalfDown => "HalfDown",
            Self::HalfEven => "HalfEven",
            Self::HalfAwayFromZero => "HalfAwayFromZero",
            Self::HalfTowardZero => "HalfTowardZero",
            Self::Ceiling => "Ceiling",
            Self::Floor => "Floor",
            Self::TowardZero => "TowardZero",
            Self::AwayFromZero => "AwayFromZero",
        }
    }

    /// Round the magnitude `q + r/d` where the true value's sign is given by
    /// `negative`. Returns the rounded magnitude, or `None` on overflow of
    /// `q + 1`.
    ///
    /// `HalfUp`/`HalfDown` are "toward +∞ / −∞ on a tie" (the signed meaning);
    /// `HalfAwayFromZero`/`HalfTowardZero` are magnitude-based; `HalfEven` is
    /// banker's rounding on the magnitude (even is sign-symmetric).
    pub fn apply_magnitude(self, q: u128, r: u128, d: u128, negative: bool) -> Option<u128> {
        if r == 0 {
            return Some(q);
        }
        let up = q.checked_add(1);
        // Compare 2r with d exactly without overflow: r < d <= u128::MAX.
        let twice = r.checked_mul(2);
        let cmp_half = match twice {
            Some(t) => t.cmp(&d),
            None => core::cmp::Ordering::Greater, // 2r overflowed, so 2r > d
        };
        use core::cmp::Ordering::*;
        let round_up_magnitude = match self {
            Self::TowardZero => false,
            Self::AwayFromZero => true,
            Self::Ceiling => !negative,
            Self::Floor => negative,
            Self::HalfAwayFromZero => cmp_half != Less,
            Self::HalfTowardZero => cmp_half == Greater,
            Self::HalfEven => match cmp_half {
                Greater => true,
                Less => false,
                Equal => q % 2 == 1,
            },
            Self::HalfUp => match cmp_half {
                Greater => true,
                Less => false,
                Equal => !negative,
            },
            Self::HalfDown => match cmp_half {
                Greater => true,
                Less => false,
                Equal => negative,
            },
        };
        if round_up_magnitude { up } else { Some(q) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // value = 2.5 (q=2, r=1, d=2) and -2.5; value = 3.5; value = 2.4; value = 2.6
    #[test]
    fn tie_behaviour_matches_the_registered_meanings() {
        let tie = |law: RoundingLaw, q: u128, negative: bool| {
            law.apply_magnitude(q, 1, 2, negative).unwrap()
        };
        assert_eq!(tie(RoundingLaw::HalfUp, 2, false), 3);
        assert_eq!(tie(RoundingLaw::HalfUp, 2, true), 2); // -2.5 -> -2 (toward +inf)
        assert_eq!(tie(RoundingLaw::HalfDown, 2, false), 2);
        assert_eq!(tie(RoundingLaw::HalfDown, 2, true), 3); // -2.5 -> -3
        assert_eq!(tie(RoundingLaw::HalfEven, 2, false), 2);
        assert_eq!(tie(RoundingLaw::HalfEven, 3, false), 4);
        assert_eq!(tie(RoundingLaw::HalfEven, 3, true), 4); // -3.5 -> -4
        assert_eq!(tie(RoundingLaw::HalfAwayFromZero, 2, true), 3);
        assert_eq!(tie(RoundingLaw::HalfTowardZero, 2, false), 2);
        assert_eq!(tie(RoundingLaw::Ceiling, 2, false), 3);
        assert_eq!(tie(RoundingLaw::Ceiling, 2, true), 2);
        assert_eq!(tie(RoundingLaw::Floor, 2, false), 2);
        assert_eq!(tie(RoundingLaw::Floor, 2, true), 3);
        assert_eq!(tie(RoundingLaw::TowardZero, 2, true), 2);
        assert_eq!(tie(RoundingLaw::AwayFromZero, 2, true), 3);
    }

    #[test]
    fn non_tie_fractions() {
        // 2.4 (q=2, r=2, d=5), 2.6 (q=2, r=3, d=5)
        for law in [
            RoundingLaw::HalfUp,
            RoundingLaw::HalfDown,
            RoundingLaw::HalfEven,
            RoundingLaw::HalfAwayFromZero,
            RoundingLaw::HalfTowardZero,
        ] {
            assert_eq!(law.apply_magnitude(2, 2, 5, false), Some(2), "{law:?} 2.4");
            assert_eq!(law.apply_magnitude(2, 3, 5, false), Some(3), "{law:?} 2.6");
        }
        assert_eq!(RoundingLaw::Floor.apply_magnitude(2, 3, 5, false), Some(2));
        assert_eq!(
            RoundingLaw::Ceiling.apply_magnitude(2, 1, 5, false),
            Some(3)
        );
    }

    #[test]
    fn exact_values_never_move_and_ids_round_trip() {
        for law in RoundingLaw::ALL {
            assert_eq!(law.apply_magnitude(7, 0, 3, true), Some(7));
            assert_eq!(RoundingLaw::from_id(law.id()), Some(law));
        }
        assert_eq!(
            RoundingLaw::AwayFromZero.apply_magnitude(u128::MAX, 1, 2, false),
            None
        );
    }

    #[test]
    fn error_bound_is_half_ulp_for_half_laws() {
        // For every half-law, |rounded - exact| <= 1/2 for a grid of fractions.
        for d in 1..=12u128 {
            for r in 0..d {
                for law in [
                    RoundingLaw::HalfUp,
                    RoundingLaw::HalfDown,
                    RoundingLaw::HalfEven,
                    RoundingLaw::HalfAwayFromZero,
                    RoundingLaw::HalfTowardZero,
                ] {
                    let rounded = law.apply_magnitude(10, r, d, false).unwrap();
                    // |rounded*d - (10*d + r)| <= d/2  <=> 2*|...| <= d
                    let exact2 = 2 * (10 * d + r);
                    let got2 = 2 * rounded * d;
                    let diff = got2.abs_diff(exact2);
                    assert!(diff <= d, "{law:?} r={r} d={d}");
                }
            }
        }
    }
}
