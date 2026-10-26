//! Exact comparison statistics for the §17 benches (plan §17, fa-ykbp).
//!
//! Every decision is integer arithmetic over the raw samples, so the same
//! samples give the same verdict on every host and every replay:
//! - **Mann–Whitney U**, tie-corrected, judged two-sided at α = 0.05 by the
//!   normal approximation: `z² > 1.959964²`, compared as exact rationals;
//! - **Cliff's δ** as exact pair counts over `n·m`, classed by Romano et
//!   al.'s (2006) thresholds 0.147, 0.33 and 0.474;
//! - a **percentile bootstrap** interval of the median, resampled by a
//!   seeded splitmix64 stream.
//!
//! Samples are latencies, so "greater" means slower: a pair (incumbent `a`,
//! candidate `b`) with `b > a` is a pair the candidate loses.

use std::fmt;

/// Fewest samples per side the normal approximation is used with.
pub const MIN_SAMPLES: usize = 10;
/// Most samples per side; every product below then fits in `u128`.
pub const MAX_SAMPLES: usize = 100_000;
/// `1.959964²` (the two-sided 5% normal quantile, squared) in millionths.
const Z2_MILLIONTHS: u128 = 3_841_459;
/// Romano et al.'s |δ| thresholds, in thousandths.
const SMALL_MILLI: u128 = 147;
const MEDIUM_MILLI: u128 = 330;
const LARGE_MILLI: u128 = 474;

/// Why two sample sets cannot be compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatsError {
    /// A side has fewer than [`MIN_SAMPLES`] samples.
    TooFewSamples { side: &'static str, have: usize },
    /// A side has more than [`MAX_SAMPLES`] samples.
    TooManySamples { side: &'static str, have: usize },
}

impl fmt::Display for StatsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewSamples { side, have } => write!(
                f,
                "the {side} has {have} samples; a comparison needs at least {MIN_SAMPLES}"
            ),
            Self::TooManySamples { side, have } => write!(
                f,
                "the {side} has {have} samples; a comparison takes at most {MAX_SAMPLES}"
            ),
        }
    }
}

impl std::error::Error for StatsError {}

/// Cliff's δ magnitude class (Romano et al., 2006).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Magnitude {
    Negligible,
    Small,
    Medium,
    Large,
}

impl Magnitude {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Negligible => "negligible",
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
        }
    }
}

/// What a comparison says about the candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Significantly slower, by at least a medium effect.
    Regression,
    /// Significantly faster, by at least a medium effect.
    Improvement,
    /// Not significant, or a small or negligible effect.
    NoChange,
}

impl Verdict {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Regression => "regression",
            Self::Improvement => "improvement",
            Self::NoChange => "no_change",
        }
    }
}

/// An incumbent and a candidate compared sample against sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comparison {
    pub incumbent_samples: usize,
    pub candidate_samples: usize,
    /// Pairs whose candidate sample is greater (slower).
    pub slower_pairs: u128,
    /// Pairs whose candidate sample is smaller (faster).
    pub faster_pairs: u128,
    /// The candidate's Mann–Whitney U, doubled so a tied pair counts 1.
    pub u_doubled: u128,
    /// Whether U differs from `n·m/2` at α = 0.05, two-sided.
    pub significant: bool,
    pub magnitude: Magnitude,
    pub verdict: Verdict,
}

impl Comparison {
    /// Cliff's δ (slower minus faster pairs, over all pairs) in thousandths,
    /// truncated toward zero.
    #[must_use]
    pub fn delta_milli(&self) -> i128 {
        let pairs = (self.incumbent_samples as u128) * (self.candidate_samples as u128);
        let difference = self.slower_pairs.abs_diff(self.faster_pairs) * 1000 / pairs;
        let difference = i128::try_from(difference).unwrap_or(i128::MAX);
        if self.slower_pairs >= self.faster_pairs {
            difference
        } else {
            -difference
        }
    }
}

fn bounded(side: &'static str, samples: &[u64]) -> Result<(), StatsError> {
    if samples.len() < MIN_SAMPLES {
        return Err(StatsError::TooFewSamples {
            side,
            have: samples.len(),
        });
    }
    if samples.len() > MAX_SAMPLES {
        return Err(StatsError::TooManySamples {
            side,
            have: samples.len(),
        });
    }
    Ok(())
}

/// Compare `candidate` against `incumbent` (latencies, any order).
///
/// The candidate is a regression when U is significant and Cliff's δ is at
/// least medium in the slower direction, an improvement when the same holds
/// in the faster direction, and no change otherwise.
pub fn compare(incumbent: &[u64], candidate: &[u64]) -> Result<Comparison, StatsError> {
    bounded("incumbent", incumbent)?;
    bounded("candidate", candidate)?;
    let mut a = incumbent.to_vec();
    a.sort_unstable();
    let n = a.len() as u128;
    let m = candidate.len() as u128;
    let mut slower = 0u128;
    let mut faster = 0u128;
    for &b in candidate {
        let below = a.partition_point(|&x| x < b) as u128;
        let at_or_below = a.partition_point(|&x| x <= b) as u128;
        slower += below;
        faster += n - at_or_below;
    }
    let pairs = n * m;
    let ties = pairs - slower - faster;
    let u_doubled = 2 * slower + ties;

    // Tie correction over the pooled sample: T = Σ (t³ − t) per tie group.
    let mut pooled: Vec<u64> = a.iter().chain(candidate).copied().collect();
    pooled.sort_unstable();
    let mut tie_sum = 0u128;
    let mut i = 0;
    while i < pooled.len() {
        let j = pooled[i..].partition_point(|&x| x == pooled[i]) + i;
        let t = (j - i) as u128;
        tie_sum += t * t * t - t;
        i = j;
    }
    let total = n + m;
    // z² = (U − nm/2)² / σ², σ² = nm·((N+1)N(N−1) − T) / (12·N(N−1)).
    // With 2U: (2U − nm)²/4 · 12·N(N−1) > 1.959964² · nm·((N+1)N(N−1) − T),
    // i.e. (2U − nm)² · 3·10⁶ · N(N−1) > Z2_MILLIONTHS · nm · ((N+1)N(N−1) − T).
    let shift = u_doubled.abs_diff(pairs);
    let spread = (total + 1) * total * (total - 1) - tie_sum;
    let significant = spread > 0
        && shift * shift * 3_000_000 * total * (total - 1) > Z2_MILLIONTHS * pairs * spread;
    let difference = slower.abs_diff(faster) * 1000;
    let magnitude = if difference >= LARGE_MILLI * pairs {
        Magnitude::Large
    } else if difference >= MEDIUM_MILLI * pairs {
        Magnitude::Medium
    } else if difference >= SMALL_MILLI * pairs {
        Magnitude::Small
    } else {
        Magnitude::Negligible
    };
    let verdict = if significant && magnitude >= Magnitude::Medium {
        if slower > faster {
            Verdict::Regression
        } else {
            Verdict::Improvement
        }
    } else {
        Verdict::NoChange
    };
    Ok(Comparison {
        incumbent_samples: a.len(),
        candidate_samples: candidate.len(),
        slower_pairs: slower,
        faster_pairs: faster,
        u_doubled,
        significant,
        magnitude,
        verdict,
    })
}

/// splitmix64: a seeded, portable stream (Steele, Lea and Flood, 2014).
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..bound` by rejection, so no index is favoured.
    fn below(&mut self, bound: u64) -> u64 {
        let zone = u64::MAX - (u64::MAX % bound);
        loop {
            let x = self.next();
            if x < zone {
                return x % bound;
            }
        }
    }
}

/// The lower median, as [`crate::Distribution`] takes p50.
fn median(values: &mut [u64]) -> u64 {
    let at = (values.len() - 1) / 2;
    *values.select_nth_unstable(at).1
}

/// The 95% percentile-bootstrap interval of the median: `resamples`
/// resamples of `samples`, drawn with replacement by splitmix64 from
/// `seed`, and the 2.5th and 97.5th percentiles of their medians.
pub fn median_interval(
    samples: &[u64],
    seed: u64,
    resamples: usize,
) -> Result<(u64, u64), StatsError> {
    bounded("sample", samples)?;
    if resamples < MIN_SAMPLES {
        return Err(StatsError::TooFewSamples {
            side: "bootstrap",
            have: resamples,
        });
    }
    let mut stream = SplitMix64(seed);
    let len = samples.len() as u64;
    let mut draw = vec![0u64; samples.len()];
    let mut medians = Vec::with_capacity(resamples);
    for _ in 0..resamples {
        for slot in &mut draw {
            *slot = samples[stream.below(len) as usize];
        }
        medians.push(median(&mut draw));
    }
    medians.sort_unstable();
    let last = resamples - 1;
    Ok((medians[last * 25 / 1000], medians[last * 975 / 1000]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Latencies around `base` with a fixed, deterministic spread of ±25.
    fn around(base: u64, count: u64) -> Vec<u64> {
        (0..count).map(|i| base - 25 + (i * 37) % 50).collect()
    }

    #[test]
    fn pair_counts_match_a_hand_count() {
        // Incumbent 11, 12, 17, 20 against candidate 16, 19, 22, 24, 29
        // (and five more of 29 to reach the sample floor): 16 beats 11 and
        // 12; 19 beats three; 22, 24 and every 29 beat all four.
        let incumbent = [11, 12, 17, 20, 11, 12, 17, 20, 11, 12];
        let candidate = [16, 19, 22, 24, 29, 29, 29, 29, 29, 29];
        let c = compare(&incumbent, &candidate).unwrap();
        // 16 > {11,11,11,12,12,12} = 6; 19 > {11×3,12×3,17×2} = 8;
        // the other eight beat all ten.
        assert_eq!(c.slower_pairs, 6 + 8 + 8 * 10);
        assert_eq!(c.faster_pairs, 100 - 94);
        assert_eq!(c.u_doubled, 2 * 94);
        assert!(c.significant);
        assert_eq!(c.magnitude, Magnitude::Large);
        assert_eq!(c.delta_milli(), 880);
    }

    #[test]
    fn identical_sets_are_no_change_and_ties_count_half() {
        let samples = around(1000, 30);
        let c = compare(&samples, &samples).unwrap();
        assert_eq!(c.slower_pairs, c.faster_pairs);
        assert_eq!(c.u_doubled, 30 * 30);
        assert!(!c.significant);
        assert_eq!(c.magnitude, Magnitude::Negligible);
        assert_eq!(c.verdict, Verdict::NoChange);
        assert_eq!(c.delta_milli(), 0);
    }

    #[test]
    fn all_tied_samples_are_never_significant() {
        let flat = [500u64; 12];
        let c = compare(&flat, &flat).unwrap();
        assert!(!c.significant);
        assert_eq!(c.verdict, Verdict::NoChange);
    }

    #[test]
    fn too_few_samples_are_refused() {
        let few = [1u64; 9];
        let enough = [1u64; 10];
        assert_eq!(
            compare(&few, &enough),
            Err(StatsError::TooFewSamples {
                side: "incumbent",
                have: 9
            })
        );
        assert_eq!(
            compare(&enough, &few),
            Err(StatsError::TooFewSamples {
                side: "candidate",
                have: 9
            })
        );
    }

    #[test]
    fn a_small_shift_is_significant_but_not_a_regression() {
        // 3 µs slower within a ±25 µs spread: δ = 291/2500 exactly (the
        // pairs whose difference lies in -2..=3), negligible, though at
        // n = 400 the shift itself is significant.
        let incumbent = around(1000, 400);
        let candidate = around(1003, 400);
        let c = compare(&incumbent, &candidate).unwrap();
        assert_eq!(c.slower_pairs - c.faster_pairs, 291 * 400 * 400 / 2500);
        assert!(c.significant);
        assert_eq!(c.magnitude, Magnitude::Negligible);
        assert_eq!(c.verdict, Verdict::NoChange);
    }

    #[test]
    fn the_bootstrap_interval_is_seeded_and_brackets_the_median() {
        let samples = around(1000, 51);
        let mut sorted = samples.clone();
        let p50 = median(&mut sorted);
        let (lo, hi) = median_interval(&samples, 42, 1000).unwrap();
        assert!(lo <= p50 && p50 <= hi, "{lo} {p50} {hi}");
        assert!(hi - lo <= 50);
        assert_eq!(median_interval(&samples, 42, 1000).unwrap(), (lo, hi));
        // A constant sample has a degenerate interval.
        assert_eq!(median_interval(&[7; 20], 1, 100).unwrap(), (7, 7));
        assert!(median_interval(&samples, 42, 9).is_err());
    }
}
