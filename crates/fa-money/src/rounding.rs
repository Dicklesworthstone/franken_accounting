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
    /// `q + 1`, a zero denominator, or a remainder outside `[0, d)`.
    ///
    /// `HalfUp`/`HalfDown` are "toward +∞ / −∞ on a tie" (the signed meaning);
    /// `HalfAwayFromZero`/`HalfTowardZero` are magnitude-based; `HalfEven` is
    /// banker's rounding on the magnitude (even is sign-symmetric).
    pub fn apply_magnitude(self, q: u128, r: u128, d: u128, negative: bool) -> Option<u128> {
        if d == 0 || r >= d {
            return None;
        }
        self.apply_fraction(q, r != 0, r.cmp(&(d - r)), negative)
    }

    /// Apply the law after an exact division. Comparing r with d-r allows
    /// callers with wider remainders to share the law without narrowing them.
    pub(crate) fn apply_fraction(
        self,
        q: u128,
        has_remainder: bool,
        cmp_half: core::cmp::Ordering,
        negative: bool,
    ) -> Option<u128> {
        if !has_remainder {
            return Some(q);
        }
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
        if round_up_magnitude {
            q.checked_add(1)
        } else {
            Some(q)
        }
    }
}

/// Every registry row must name one executable law, and every law must have
/// exactly one row. This belongs beside arithmetic, keeping fa-reference's
/// registry dependency independent of the production numeric backend.
pub(crate) fn validate_registry(
    rows: &[fa_registry::RoundingLawRow],
) -> Result<(), fa_registry::RegistryError> {
    let invalid = |message| fa_registry::RegistryError::Invalid {
        registry: "rounding_laws.toml",
        message,
    };
    for law in RoundingLaw::ALL {
        let matching: Vec<_> = rows.iter().filter(|row| row.id == law.id()).collect();
        if matching.len() != 1 || matching[0].name != law.name() {
            return Err(invalid(format!(
                "law {} must have exactly one row named {}",
                law.id(),
                law.name()
            )));
        }
    }
    for row in rows {
        if RoundingLaw::from_id(row.id).is_none() {
            return Err(invalid(format!(
                "registry law {} (id {}) has no code variant",
                row.name, row.id
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_requires_exact_correspondence_with_executable_laws() {
        let rows = fa_registry::rounding_laws_embedded().unwrap();
        validate_registry(&rows).unwrap();
        let mut missing = rows.clone();
        missing.pop();
        assert!(validate_registry(&missing).is_err());
        let mut duplicate = rows.clone();
        duplicate.push(rows[0].clone());
        assert!(validate_registry(&duplicate).is_err());
        let mut renamed = rows.clone();
        renamed[0].name = "Unimplemented".into();
        assert!(validate_registry(&renamed).is_err());
        let mut extra = rows;
        let mut unknown = extra[0].clone();
        unknown.id = u16::MAX;
        extra.push(unknown);
        assert!(validate_registry(&extra).is_err());
    }

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
        for law in RoundingLaw::ALL {
            assert_eq!(law.apply_magnitude(0, 0, 0, false), None);
            assert_eq!(law.apply_magnitude(0, 3, 3, false), None);
            assert_eq!(law.apply_magnitude(0, 4, 3, true), None);
        }
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
