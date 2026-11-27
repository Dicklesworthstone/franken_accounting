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

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|l| l.name() == name)
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
        self.apply_fraction(q, r != 0, r.cmp(&d.checked_sub(r)?), negative)
    }

    /// Apply the law after an exact division. Comparing r with d-r allows
    /// callers with wider remainders to share the law without narrowing them.
    pub fn apply_fraction(
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
