//! The harness's own exact amount arithmetic (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §3.1; bead fa-yugf.4, A1b).
//!
//! An amount literal is an optional `-`, digits, and exactly the unit's
//! scale of fractional digits (`"560000000.00"` for USD): no exponent, no
//! separators, no rounding. Values are integer minor units in `i128`, and
//! every sum is checked, never wrapped. This is fa-oracles' own code, never
//! fa-money's, so a shared arithmetic bug cannot make a tie-out agree.

use core::fmt;
use std::collections::BTreeMap;

/// Why an amount does not parse or sum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AmountError {
    /// Not `-?digits[.digits]`.
    Malformed(String),
    /// The fractional digits are not exactly the unit's scale.
    WrongScale { text: String, scale: u8 },
    /// The value or a sum does not fit in `i128` minor units.
    Overflow,
}

impl fmt::Display for AmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(text) => write!(f, "`{text}` is not a decimal amount"),
            Self::WrongScale { text, scale } => write!(
                f,
                "`{text}` must have exactly {scale} fractional digit(s), the unit's scale"
            ),
            Self::Overflow => f.write_str("the amount overflows i128 minor units"),
        }
    }
}

impl core::error::Error for AmountError {}

/// The literal's value in minor units at `scale`.
///
/// # Errors
///
/// [`AmountError`] when the text is not of the literal's form, has another
/// number of fractional digits, or does not fit in `i128`.
pub fn parse_amount(text: &str, scale: u8) -> Result<i128, AmountError> {
    let malformed = || AmountError::Malformed(text.to_string());
    let (negative, body) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (whole, frac) = match body.split_once('.') {
        Some((w, f)) => (w, Some(f)),
        None => (body, None),
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || frac.is_some_and(|f| !digits(f)) {
        return Err(malformed());
    }
    let frac = frac.unwrap_or("");
    if frac.len() != usize::from(scale) {
        return Err(AmountError::WrongScale {
            text: text.to_string(),
            scale,
        });
    }
    let mut value: i128 = 0;
    for b in whole.bytes().chain(frac.bytes()) {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(i128::from(b - b'0')))
            .ok_or(AmountError::Overflow)?;
    }
    Ok(if negative { -value } else { value })
}

/// `value` minor units rendered at `scale` (the inverse of [`parse_amount`]).
#[must_use]
pub fn format_amount(value: i128, scale: u8) -> String {
    let digits = value.unsigned_abs().to_string();
    let scale = usize::from(scale);
    let sign = if value < 0 { "-" } else { "" };
    if scale == 0 {
        return format!("{sign}{digits}");
    }
    let padded = format!("{digits:0>width$}", width = scale + 1);
    let (whole, frac) = padded.split_at(padded.len() - scale);
    format!("{sign}{whole}.{frac}")
}

/// Debit and credit totals per unit, summed with checked arithmetic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnitTotals {
    totals: BTreeMap<String, (i128, i128)>,
}

impl UnitTotals {
    /// Adds one leg's magnitude to its side of its unit.
    ///
    /// # Errors
    ///
    /// [`AmountError::Overflow`] when a side's sum leaves `i128`.
    pub fn add(&mut self, unit: &str, debit: bool, amount: i128) -> Result<(), AmountError> {
        let (dr, cr) = self.totals.entry(unit.to_string()).or_insert((0, 0));
        let side = if debit { dr } else { cr };
        *side = side.checked_add(amount).ok_or(AmountError::Overflow)?;
        Ok(())
    }

    /// The units whose debits and credits differ: (unit, debits, credits).
    #[must_use]
    pub fn unbalanced(&self) -> Vec<(&str, i128, i128)> {
        self.totals
            .iter()
            .filter(|(_, (dr, cr))| dr != cr)
            .map(|(unit, (dr, cr))| (unit.as_str(), *dr, *cr))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_parse_at_exactly_the_units_scale() {
        assert_eq!(parse_amount("560000000.00", 2), Ok(56_000_000_000));
        assert_eq!(parse_amount("-0.01", 2), Ok(-1));
        assert_eq!(parse_amount("98727", 0), Ok(98_727));
        assert_eq!(
            parse_amount("560000000.0", 2),
            Err(AmountError::WrongScale {
                text: "560000000.0".into(),
                scale: 2
            })
        );
        assert_eq!(
            parse_amount("1.00", 0),
            Err(AmountError::WrongScale {
                text: "1.00".into(),
                scale: 0
            })
        );
        for bad in ["", "-", "1,000.00", "1e3", "+1.00", ".50", "1.", " 1.00"] {
            assert!(
                matches!(parse_amount(bad, 2), Err(AmountError::Malformed(_))),
                "{bad:?}"
            );
        }
        let max = i128::MAX.to_string();
        assert_eq!(parse_amount(&max, 0), Ok(i128::MAX));
        assert_eq!(
            parse_amount(&format!("{max}0"), 0),
            Err(AmountError::Overflow)
        );
    }

    #[test]
    fn formatting_inverts_parsing() {
        for (v, scale) in [(56_000_000_000, 2), (-1, 2), (0, 2), (98_727, 0), (5, 3)] {
            assert_eq!(parse_amount(&format_amount(v, scale), scale), Ok(v));
        }
        assert_eq!(format_amount(-1, 2), "-0.01");
        assert_eq!(format_amount(1, 0), "1");
    }

    #[test]
    fn amount_sum_overflow_is_refused() {
        let mut t = UnitTotals::default();
        t.add("USD", true, i128::MAX).expect("one i128::MAX fits");
        assert_eq!(t.add("USD", true, 1), Err(AmountError::Overflow));
        let mut t = UnitTotals::default();
        t.add("USD", false, i128::MAX).expect("fits");
        assert_eq!(t.add("USD", false, i128::MAX), Err(AmountError::Overflow));
    }

    #[test]
    fn totals_name_each_unbalanced_unit() {
        let mut t = UnitTotals::default();
        t.add("USD", true, 56_000_000_000).expect("fits");
        t.add("USD", false, 55_999_999_999).expect("fits");
        t.add("EUR", true, 5).expect("fits");
        t.add("EUR", false, 5).expect("fits");
        assert_eq!(
            t.unbalanced(),
            vec![("USD", 56_000_000_000, 55_999_999_999)]
        );
    }
}
