//! Digit analytics (plan §11.3): the first-digit distribution of posted leg
//! magnitudes against Benford's law, in exact fixed-point integer arithmetic
//! (no float anywhere: the expected proportions are registered constants at
//! nine decimal places). The score is Nigrini's mean absolute deviation with
//! his first-digit conformity ranges as pinned thresholds; the chi-square
//! statistic and the nine counts ride in the narrative. Assumes naturally
//! occurring, multi-magnitude, non-assigned numbers (plan §11.9); below the
//! registered minimum population no conformity is claimed.

use fa_journal::KernelError;
use fa_journal::genesis::BookContext;

use crate::jet::{finding, procedure_boilerplate};
use crate::{Finding, LanternError, Params, Procedure, Severity, Snapshot, Statistic, Work};

/// `log10(1 + 1/d)` for d = 1..=9 at nine decimal places. The nine rounded
/// values sum to 1 000 000 001; the last is lowered by one unit so the table
/// sums to exactly 10^9 (checked by a test).
pub const BENFORD_1E9: [i128; 9] = [
    301_029_996,
    176_091_259,
    124_938_737,
    96_910_013,
    79_181_246,
    66_946_790,
    57_991_947,
    51_152_522,
    45_757_490,
];

/// The largest population the chi-square computation admits in `i128`.
pub const MAX_POPULATION: u64 = 1_000_000;

/// The leading decimal digit of a positive magnitude.
#[must_use]
pub fn first_digit(mut m: u128) -> u8 {
    while m >= 10 {
        m /= 10;
    }
    m as u8
}

/// Nigrini's MAD at nine decimal places: `Σ|O_d/N − P_d| / 9`.
pub fn mad_1e9(counts: &[u64; 9]) -> Result<i128, LanternError> {
    let n = i128::from(counts.iter().sum::<u64>());
    if n == 0 {
        return Ok(0);
    }
    let mut sum: i128 = 0;
    for (d, &c) in counts.iter().enumerate() {
        let observed = i128::from(c)
            .checked_mul(1_000_000_000)
            .ok_or(LanternError::Overflow("benford observed"))?;
        let expected = n
            .checked_mul(BENFORD_1E9[d])
            .ok_or(LanternError::Overflow("benford expected"))?;
        sum = sum
            .checked_add((observed - expected).abs())
            .ok_or(LanternError::Overflow("benford deviation"))?;
    }
    Ok(sum / (9 * n))
}

/// Pearson's chi-square at six decimal places: `Σ (O_d − E_d)² / E_d`.
pub fn chi_square_1e6(counts: &[u64; 9]) -> Result<i128, LanternError> {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return Ok(0);
    }
    if total > MAX_POPULATION {
        return Err(LanternError::Overflow("benford population above 10^6 legs"));
    }
    let n = i128::from(total);
    let mut sum: i128 = 0;
    for (d, &c) in counts.iter().enumerate() {
        // Work at 1e9: O·1e9 − N·P, squared, times 1e6, over N·P·1e9.
        let diff = i128::from(c) * 1_000_000_000 - n * BENFORD_1E9[d];
        let numerator = diff
            .checked_mul(diff)
            .and_then(|sq| sq.checked_mul(1_000_000))
            .ok_or(LanternError::Overflow("chi-square numerator"))?;
        let denominator = n * BENFORD_1E9[d] * 1_000_000_000;
        sum = sum
            .checked_add(numerator / denominator)
            .ok_or(LanternError::Overflow("chi-square sum"))?;
    }
    Ok(sum)
}

/// `benford.first_digit`.
pub struct FirstDigit {
    params: Params,
}
procedure_boilerplate!(FirstDigit, "benford.first_digit");

impl Procedure for FirstDigit {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        book: &BookContext,
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let min_population = u64::from(self.params.get_u32("min_population")?);
        let close = i128::from(self.params.get_u32("mad_close")?) * 1_000_000;
        let acceptable = i128::from(self.params.get_u32("mad_acceptable")?) * 1_000_000;
        let marginal = i128::from(self.params.get_u32("mad_marginal")?) * 1_000_000;
        let mut counts = [0u64; 9];
        for e in snapshot.entries.iter().filter(|e| e.posts()) {
            work.entry();
            for leg in &e.entry.proposal.legs {
                work.leg();
                let Some(unit) = book.units.get(leg.amount.unit) else {
                    return Err(
                        KernelError::Corrupt("a leg names an unregistered unit".into()).into(),
                    );
                };
                let magnitude = leg.amount.mantissa.unsigned_abs();
                if magnitude < unit.one().unsigned_abs() {
                    continue;
                }
                let d = first_digit(magnitude);
                counts[usize::from(d - 1)] += 1;
            }
        }
        let population: u64 = counts.iter().sum();
        if population < min_population {
            return Ok(vec![finding(
                Self::ID,
                Severity::Info,
                Statistic::count("population", population, population),
                Vec::new(),
                format!(
                    "population {population} is below the registered minimum {min_population}; no conformity is claimed"
                ),
            )]);
        }
        let mad = mad_1e9(&counts)?;
        let chi = chi_square_1e6(&counts)?;
        let severity = if mad <= close {
            Severity::Info
        } else if mad <= acceptable {
            Severity::Low
        } else if mad <= marginal {
            Severity::Medium
        } else {
            Severity::High
        };
        Ok(vec![finding(
            Self::ID,
            severity,
            Statistic {
                name: "mad".into(),
                value: mad,
                scale: 9,
                population,
            },
            Vec::new(),
            format!(
                "first-digit counts {counts:?} over {population} legs; MAD {mad}e-9 (close ≤ {close}e-9, acceptable ≤ {acceptable}e-9, marginal ≤ {marginal}e-9); chi-square {chi}e-6 with 8 degrees of freedom"
            ),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_expected_proportions_sum_to_one() {
        assert_eq!(BENFORD_1E9.iter().sum::<i128>(), 1_000_000_000);
        assert!(BENFORD_1E9.windows(2).all(|w| w[0] > w[1]));
    }

    #[test]
    fn first_digits_and_a_perfect_population_score_zero() {
        assert_eq!(first_digit(1), 1);
        assert_eq!(first_digit(9_999), 9);
        assert_eq!(first_digit(123_456_789_012), 1);
        // A population distributed exactly per the table (scaled by 1e9
        // legs) deviates by nothing but the table's own rounding.
        let counts: [u64; 9] = core::array::from_fn(|d| BENFORD_1E9[d] as u64);
        assert_eq!(mad_1e9(&counts).unwrap(), 0);
        // A uniform population is far from Benford: MAD ≈ 0.0684.
        let uniform = [100u64; 9];
        let mad = mad_1e9(&uniform).unwrap();
        assert!((68_000_000..69_000_000).contains(&mad), "{mad}");
        let chi = chi_square_1e6(&uniform).unwrap();
        // χ² for 900 uniform legs ≈ 155.6.
        assert!((155_000_000..156_000_000).contains(&chi), "{chi}");
        let mut too_many = [0u64; 9];
        too_many[0] = MAX_POPULATION + 1;
        assert!(matches!(
            chi_square_1e6(&too_many),
            Err(LanternError::Overflow(_))
        ));
    }
}
