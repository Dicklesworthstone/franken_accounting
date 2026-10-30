//! A C row's display band (docs/FORENSIC_CASE_STUDIES_PLAN.md §5.3, §8.3;
//! bead fa-yugf.65, L3): whether a value the harness computes from
//! certified reads agrees with a published figure within one display unit
//! of it, decided exactly in checked integers, never by rounding.
//!
//! A computed value is a fraction `num / den`; a published figure is an
//! integer `printed` at `scale` decimal places (13.9x is 139 at scale 1),
//! its display unit `unit` at the same places (0.1x is 1). The value
//! agrees when |num·10^scale − printed·den| ≤ unit·den, the plan's per-row
//! test |ΔP − d| ≤ one display unit, edges included. A sum is the fraction
//! over `den = 1` at the published value's own minor units (`scale = 0`).

/// Why a band test has no verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BandError {
    /// The denominator is zero or negative: the ratio is undefined, or its
    /// sign would flip the test.
    NonPositiveDenominator,
    /// An intermediate product left i128.
    Overflow,
}

/// One band test: whether it holds, and the exact distance it measured,
/// |num·10^scale − printed·den|, against its limit unit·den.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Band {
    pub within: bool,
    pub distance: i128,
    pub limit: i128,
}

fn pow10(scale: u32) -> Result<i128, BandError> {
    10i128.checked_pow(scale).ok_or(BandError::Overflow)
}

/// The band test of `num / den` against `printed` at `scale` places, within
/// `unit` at the same places.
///
/// # Errors
/// A non-positive `den`, or an intermediate that overflows i128.
pub fn within_display_band(
    num: i128,
    den: i128,
    printed: i128,
    scale: u32,
    unit: i128,
) -> Result<Band, BandError> {
    if den <= 0 {
        return Err(BandError::NonPositiveDenominator);
    }
    let lhs = num.checked_mul(pow10(scale)?).ok_or(BandError::Overflow)?;
    let rhs = printed.checked_mul(den).ok_or(BandError::Overflow)?;
    let distance = lhs
        .checked_sub(rhs)
        .and_then(i128::checked_abs)
        .ok_or(BandError::Overflow)?;
    let limit = unit.checked_mul(den).ok_or(BandError::Overflow)?;
    Ok(Band {
        within: distance <= limit,
        distance,
        limit,
    })
}

/// The detection interval of one numerator term: the values `x` the band
/// accepts with the rest of the numerator, `rest`, held fixed, both ends
/// inclusive. A change of the term inside it is not detected:
/// x ∈ [⌈(printed − unit)·den / 10^scale⌉ − rest, ⌊(printed + unit)·den / 10^scale⌋ − rest].
///
/// # Errors
/// A non-positive `den`, or an intermediate that overflows i128.
pub fn detection_interval(
    rest: i128,
    den: i128,
    printed: i128,
    scale: u32,
    unit: i128,
) -> Result<(i128, i128), BandError> {
    if den <= 0 {
        return Err(BandError::NonPositiveDenominator);
    }
    let p = pow10(scale)?;
    let edge = |offset: i128| {
        printed
            .checked_add(offset)
            .and_then(|v| v.checked_mul(den))
            .ok_or(BandError::Overflow)
    };
    let lo = edge(unit.checked_neg().ok_or(BandError::Overflow)?)?;
    let hi = edge(unit)?;
    // ⌈a / p⌉ and ⌊a / p⌋ for p > 0.
    let ceil = lo
        .div_euclid(p)
        .checked_add(i128::from(lo.rem_euclid(p) != 0))
        .ok_or(BandError::Overflow)?;
    let floor = hi.div_euclid(p);
    Ok((
        ceil.checked_sub(rest).ok_or(BandError::Overflow)?,
        floor.checked_sub(rest).ok_or(BandError::Overflow)?,
    ))
}
