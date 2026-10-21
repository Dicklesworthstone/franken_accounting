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
use fa_money::{Side, UnitKind};

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
        sum = observed
            .checked_sub(expected)
            .and_then(i128::checked_abs)
            .and_then(|deviation| sum.checked_add(deviation))
            .ok_or(LanternError::Overflow("benford deviation"))?;
    }
    n.checked_mul(9)
        .and_then(|cells| sum.checked_div(cells))
        .ok_or(LanternError::Overflow("benford mad"))
}

/// Pearson's chi-square at six decimal places: `Σ (O_d − E_d)² / E_d`.
pub fn chi_square_1e6(counts: &[u64; 9]) -> Result<i128, LanternError> {
    chi_square_table_1e6(counts, &BENFORD_1E9)
}

/// Exact-integer Benford expected counts (`n * P_d / 10^9`) law-rounded under
/// LargestRemainder (ties broken by ascending bucket index) so that
/// `sum(expected_counts) == n` (`fa-vpk`).
pub fn expected_counts_1e9(n: u64, expected_1e9: &[i128]) -> Result<Vec<u64>, LanternError> {
    let n_i = i128::from(n);
    let mut floors: Vec<u64> = Vec::with_capacity(expected_1e9.len());
    let mut remainders: Vec<(i128, usize)> = Vec::with_capacity(expected_1e9.len());
    let mut floor_sum: u64 = 0;

    for (idx, &p) in expected_1e9.iter().enumerate() {
        let prod = n_i
            .checked_mul(p)
            .ok_or(LanternError::Overflow("benford expected count product"))?;
        let q = u64::try_from(prod / 1_000_000_000)
            .map_err(|_| LanternError::Overflow("benford expected count floor"))?;
        let r = prod % 1_000_000_000;
        floors.push(q);
        floor_sum = floor_sum
            .checked_add(q)
            .ok_or(LanternError::Overflow("benford expected count sum"))?;
        remainders.push((r, idx));
    }

    let deficit = n.saturating_sub(floor_sum) as usize;
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for &(_, idx) in remainders.iter().take(deficit) {
        floors[idx] += 1;
    }
    Ok(floors)
}

/// First-digit (`1..=9`) exact-integer Benford expected counts summing to `n`.
pub fn first_digit_expected_counts(n: u64) -> Result<[u64; 9], LanternError> {
    let vec = expected_counts_1e9(n, &BENFORD_1E9)?;
    Ok(core::array::from_fn(|i| vec[i]))
}

/// Second-digit (`0..=9`) exact-integer Benford expected counts summing to `n`.
pub fn second_digit_expected_counts(n: u64) -> Result<[u64; 10], LanternError> {
    let vec = expected_counts_1e9(n, &BENFORD_SECOND_1E9)?;
    Ok(core::array::from_fn(|i| vec[i]))
}

/// First-two-digits (`10..=99`) exact-integer Benford expected counts summing to `n`.
pub fn first_two_digits_expected_counts(n: u64) -> Result<[u64; 90], LanternError> {
    let vec = expected_counts_1e9(n, &BENFORD_FIRST_TWO_1E9)?;
    Ok(core::array::from_fn(|i| vec[i]))
}

/// Kolmogorov-Smirnov supremum distance $D = \max_d |F_{\text{obs}}(d) - F_{\text{exp}}(d)|$
/// at nine decimal places (`10^9` scale) for the first-digit distribution (`fa-vpk`).
pub fn ks_1e9(counts: &[u64; 9]) -> Result<i128, LanternError> {
    ks_table_1e9(counts, &BENFORD_1E9)
}

/// Kolmogorov-Smirnov supremum distance $D = \max_k |F_{\text{obs}}(k) - F_{\text{exp}}(k)|$
/// at nine decimal places (`10^9` scale) over an expected-proportion table (`fa-vpk`).
pub fn ks_table_1e9(counts: &[u64], expected_1e9: &[i128]) -> Result<i128, LanternError> {
    let total: u64 = counts.iter().sum();
    if total == 0 || expected_1e9.is_empty() {
        return Ok(0);
    }
    let n = i128::from(total);
    let mut cum_obs: i128 = 0;
    let mut cum_exp: i128 = 0;
    let mut max_d: i128 = 0;
    for (&c, &p) in counts.iter().zip(expected_1e9.iter()) {
        cum_obs = cum_obs
            .checked_add(i128::from(c))
            .ok_or(LanternError::Overflow("ks cumulative observed"))?;
        cum_exp = cum_exp
            .checked_add(p)
            .ok_or(LanternError::Overflow("ks cumulative expected"))?;
        let obs_scaled = cum_obs
            .checked_mul(1_000_000_000)
            .ok_or(LanternError::Overflow("ks observed scale"))?;
        let exp_scaled = n
            .checked_mul(cum_exp)
            .ok_or(LanternError::Overflow("ks expected scale"))?;
        let diff = obs_scaled
            .checked_sub(exp_scaled)
            .and_then(i128::checked_abs)
            .and_then(|distance| distance.checked_div(n))
            .ok_or(LanternError::Overflow("ks distance"))?;
        if diff > max_d {
            max_d = diff;
        }
    }
    Ok(max_d)
}

/// Smirnov asymptotic critical value $c_\alpha / \sqrt{n}$ at `10^9` scale for
/// `alpha_bps` in `{1000 (10%), 500 (5%), 100 (1%)}`, evaluated in exact integer
/// arithmetic via `u128::isqrt`.
pub fn ks_critical_1e9(n: u64, alpha_bps: u32) -> Result<i128, LanternError> {
    if n == 0 {
        return Err(LanternError::Parameter {
            procedure: "benford.ks".into(),
            name: "n".into(),
            message: "population n must be positive".into(),
        });
    }
    let c_1e9: u128 = match alpha_bps {
        1_000 => 1_220_000_000,
        500 => 1_360_000_000,
        100 => 1_630_000_000,
        _ => {
            return Err(LanternError::Parameter {
                procedure: "benford.ks".into(),
                name: "alpha_bps".into(),
                message: "supported alpha_bps values are 1000 (10%), 500 (5%), or 100 (1%)".into(),
            });
        }
    };
    let crit = c_1e9
        .checked_mul(c_1e9)
        .and_then(|num_sq| num_sq.checked_div(u128::from(n)))
        .ok_or(LanternError::Overflow("ks critical value"))?
        .isqrt();
    i128::try_from(crit).map_err(|_| LanternError::Overflow("ks critical value"))
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
        let close = i128::from(u64::from(self.params.get_u32("mad_close")?) * 1_000_000);
        let acceptable = i128::from(u64::from(self.params.get_u32("mad_acceptable")?) * 1_000_000);
        let marginal = i128::from(u64::from(self.params.get_u32("mad_marginal")?) * 1_000_000);
        let currency = u16::try_from(self.params.get_u32("currency_iso4217")?).map_err(|_| {
            LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "currency_iso4217".into(),
                message: "must be an ISO 4217 numeric code in 1..=999".into(),
            }
        })?;
        if !(1..=999).contains(&currency) {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "currency_iso4217".into(),
                message: "must be an ISO 4217 numeric code in 1..=999".into(),
            });
        }
        let target_side = match self.params.get("side")? {
            0 => Side::Debit,
            1 => Side::Credit,
            _ => {
                return Err(LanternError::Parameter {
                    procedure: Self::ID.into(),
                    name: "side".into(),
                    message: "must be 0 (debit) or 1 (credit)".into(),
                });
            }
        };
        let mut counts = [0u64; 9];
        for e in snapshot.live_postings()? {
            work.entry();
            for leg in &e.entry.proposal.legs {
                work.leg();
                let Some(unit) = book.units.get(leg.amount.unit) else {
                    return Err(
                        KernelError::Corrupt("a leg names an unregistered unit".into()).into(),
                    );
                };
                if leg.side != target_side
                    || !matches!(unit.kind, UnitKind::Currency { iso4217 } if iso4217 == currency)
                {
                    continue;
                }
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
        let ks = ks_1e9(&counts)?;
        // The chi-square and KS ride in the narrative only; above the population
        // its exact i128 arithmetic admits, the scored MAD still stands and
        // the narrative says the chi-square was not computed.
        let chi = if population <= MAX_POPULATION {
            format!(
                "chi-square {}e-6 with 8 degrees of freedom, KS {ks}e-9",
                chi_square_1e6(&counts)?
            )
        } else {
            format!(
                "chi-square not computed above {MAX_POPULATION} legs (its exact arithmetic bound); KS {ks}e-9; MAD is the scored statistic"
            )
        };
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
                "first-digit counts {counts:?} over {population} legs; MAD {mad}e-9 (close ≤ {close}e-9, acceptable ≤ {acceptable}e-9, marginal ≤ {marginal}e-9); {chi}"
            ),
        )])
    }
}

/// Benford second-digit (`0..=9`) expected proportions at 10^9 scale, summing
/// to 10^9 and matching the column marginals of [`BENFORD_FIRST_TWO_1E9`].
pub const BENFORD_SECOND_1E9: [i128; 10] = [
    119_679_269,
    113_890_104,
    108_821_499,
    104_329_561,
    100_308_203,
    96_677_237,
    93_374_735,
    90_351_990,
    87_570_054,
    84_997_348,
];

/// Benford first-two-digits (`10..=99`) expected proportions at 10^9 scale,
/// summing to 10^9 and matching [`BENFORD_1E9`] row marginals and
/// [`BENFORD_SECOND_1E9`] column marginals.
pub const BENFORD_FIRST_TWO_1E9: [i128; 90] = [
    41_392_685, 37_788_561, 34_762_106, 32_184_683, 29_963_223, 28_028_724, 26_328_939, 24_823_584,
    23_481_096, 22_276_395, 21_189_299, 20_203_386, 19_305_155, 18_483_406, 17_728_767, 17_033_339,
    16_390_416, 15_794_267, 15_239_967, 14_723_257, 14_240_439, 13_788_284, 13_363_962, 12_964_977,
    12_589_127, 12_234_456, 11_899_223, 11_581_873, 11_281_010, 10_995_386, 10_723_865, 10_465_434,
    10_219_165, 9_984_221, 9_759_837, 9_545_318, 9_340_026, 9_143_379, 8_954_843, 8_773_925,
    8_600_172, 8_433_168, 8_272_526, 8_117_890, 7_968_930, 7_825_338, 7_686_829, 7_553_138,
    7_424_018, 7_299_237, 7_178_585, 7_061_854, 6_948_860, 6_839_425, 6_733_383, 6_630_579,
    6_530_867, 6_434_110, 6_340_178, 6_248_949, 6_160_309, 6_074_148, 5_990_364, 5_908_860,
    5_829_544, 5_752_329, 5_677_133, 5_603_878, 5_532_489, 5_462_893, 5_395_032, 5_328_834,
    5_264_240, 5_201_194, 5_139_640, 5_079_526, 5_020_801, 4_963_420, 4_907_334, 4_852_501,
    4_798_883, 4_746_435, 4_695_121, 4_644_905, 4_595_752, 4_547_628, 4_500_501, 4_454_341,
    4_409_119, 4_364_805,
];

/// The first two decimal digits (`10..=99`) of a magnitude `>= 10`.
#[must_use]
pub fn first_two_digits(mut m: u128) -> u8 {
    while m >= 100 {
        m /= 10;
    }
    m as u8
}

/// The second decimal digit (`0..=9`) of a magnitude `>= 10`.
#[must_use]
pub fn second_digit(m: u128) -> u8 {
    first_two_digits(m) % 10
}

/// Nigrini's MAD over a bucket table of expected proportions at 10^9 scale.
pub fn mad_table_1e9(counts: &[u64], expected_1e9: &[i128]) -> Result<i128, LanternError> {
    let k = i128::try_from(expected_1e9.len()).map_err(|_| LanternError::Overflow("buckets"))?;
    let n = i128::from(counts.iter().sum::<u64>());
    if n == 0 || k == 0 {
        return Ok(0);
    }
    let mut sum: i128 = 0;
    for (&c, &p) in counts.iter().zip(expected_1e9.iter()) {
        let observed = i128::from(c)
            .checked_mul(1_000_000_000)
            .ok_or(LanternError::Overflow("benford observed"))?;
        let expected = n
            .checked_mul(p)
            .ok_or(LanternError::Overflow("benford expected"))?;
        sum = observed
            .checked_sub(expected)
            .and_then(i128::checked_abs)
            .and_then(|deviation| sum.checked_add(deviation))
            .ok_or(LanternError::Overflow("benford deviation"))?;
    }
    k.checked_mul(n)
        .and_then(|cells| sum.checked_div(cells))
        .ok_or(LanternError::Overflow("benford mad"))
}

/// Pearson's chi-square at six decimal places over `expected_1e9`.
pub fn chi_square_table_1e6(counts: &[u64], expected_1e9: &[i128]) -> Result<i128, LanternError> {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return Ok(0);
    }
    if total > MAX_POPULATION {
        return Err(LanternError::Overflow("benford population above 10^6 legs"));
    }
    let n = i128::from(total);
    let mut sum: i128 = 0;
    for (&c, &p) in counts.iter().zip(expected_1e9.iter()) {
        let expected = n
            .checked_mul(p)
            .ok_or(LanternError::Overflow("chi-square expected"))?;
        let numerator = i128::from(c)
            .checked_mul(1_000_000_000)
            .and_then(|observed| observed.checked_sub(expected))
            .and_then(|diff| diff.checked_mul(diff))
            .and_then(|sq| sq.checked_mul(1_000_000))
            .ok_or(LanternError::Overflow("chi-square numerator"))?;
        sum = expected
            .checked_mul(1_000_000_000)
            .and_then(|denominator| numerator.checked_div(denominator))
            .and_then(|term| sum.checked_add(term))
            .ok_or(LanternError::Overflow("chi-square sum"))?;
    }
    Ok(sum)
}

/// Maximum per-bucket Nigrini Z-score at 3 decimal places (`1000 = 1.000`).
pub fn max_z_milli(counts: &[u64], expected_1e9: &[i128]) -> Result<i128, LanternError> {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return Ok(0);
    }
    let n = u128::from(total);
    let mut max_z: i128 = 0;
    for (&c, &p_i128) in counts.iter().zip(expected_1e9.iter()) {
        let overflow = || LanternError::Overflow("z-score");
        let p = u128::try_from(p_i128).map_err(|_| overflow())?;
        let obs_1e9 = u128::from(c)
            .checked_mul(1_000_000_000)
            .ok_or_else(overflow)?;
        let exp_1e9 = n.checked_mul(p).ok_or_else(overflow)?;
        let diff_1e9 = obs_1e9.abs_diff(exp_1e9);
        // The continuity correction never takes a deviation below zero: a
        // deliberate floor on a statistic (128-bit saturating methods are
        // disallowed in this crate).
        #[allow(clippy::manual_saturating_arithmetic)]
        let adj_diff_1e9 = diff_1e9.checked_sub(500_000_000).unwrap_or(0);
        let var_num = 1_000_000_000u128
            .checked_sub(p)
            .and_then(|q| exp_1e9.checked_mul(q))
            .ok_or_else(overflow)?;
        let denom = var_num.isqrt().max(1);
        let z_milli = adj_diff_1e9
            .checked_mul(1_000)
            .and_then(|scaled| scaled.checked_div(denom))
            .ok_or_else(overflow)?;
        let z_i128 = i128::try_from(z_milli).map_err(|_| LanternError::Overflow("z-score"))?;
        if z_i128 > max_z {
            max_z = z_i128;
        }
    }
    Ok(max_z)
}

/// `benford.second_digit`.
pub struct SecondDigit {
    params: Params,
}
procedure_boilerplate!(SecondDigit, "benford.second_digit");

impl Procedure for SecondDigit {
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
        let close = i128::from(u64::from(self.params.get_u32("mad_close")?) * 1_000_000);
        let acceptable = i128::from(u64::from(self.params.get_u32("mad_acceptable")?) * 1_000_000);
        let marginal = i128::from(u64::from(self.params.get_u32("mad_marginal")?) * 1_000_000);
        let currency = u16::try_from(self.params.get_u32("currency_iso4217")?).map_err(|_| {
            LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "currency_iso4217".into(),
                message: "must be an ISO 4217 numeric code in 1..=999".into(),
            }
        })?;
        if !(1..=999).contains(&currency) {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "currency_iso4217".into(),
                message: "must be an ISO 4217 numeric code in 1..=999".into(),
            });
        }
        let target_side = match self.params.get("side")? {
            0 => Side::Debit,
            1 => Side::Credit,
            _ => {
                return Err(LanternError::Parameter {
                    procedure: Self::ID.into(),
                    name: "side".into(),
                    message: "must be 0 (debit) or 1 (credit)".into(),
                });
            }
        };
        let mut counts = [0u64; 10];
        for e in snapshot.live_postings()? {
            work.entry();
            for leg in &e.entry.proposal.legs {
                work.leg();
                let Some(unit) = book.units.get(leg.amount.unit) else {
                    return Err(
                        KernelError::Corrupt("a leg names an unregistered unit".into()).into(),
                    );
                };
                if leg.side != target_side
                    || !matches!(unit.kind, UnitKind::Currency { iso4217 } if iso4217 == currency)
                {
                    continue;
                }
                let magnitude = leg.amount.mantissa.unsigned_abs();
                // A unit whose ten whole units exceed u128 admits no amount.
                let Some(min_mag) = unit.one().unsigned_abs().checked_mul(10) else {
                    continue;
                };
                if magnitude < min_mag.max(10) {
                    continue;
                }
                let d2 = second_digit(magnitude);
                counts[usize::from(d2)] += 1;
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
        let mad = mad_table_1e9(&counts, &BENFORD_SECOND_1E9)?;
        let max_z = max_z_milli(&counts, &BENFORD_SECOND_1E9)?;
        let ks = ks_table_1e9(&counts, &BENFORD_SECOND_1E9)?;
        let chi = if population <= MAX_POPULATION {
            format!(
                "chi-square {}e-6 with 9 degrees of freedom, KS {ks}e-9, max Z {}e-3",
                chi_square_table_1e6(&counts, &BENFORD_SECOND_1E9)?,
                max_z
            )
        } else {
            format!(
                "chi-square not computed above {MAX_POPULATION} legs; KS {ks}e-9; max Z {max_z}e-3; MAD is the scored statistic"
            )
        };
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
                "second-digit counts {counts:?} over {population} legs; MAD {mad}e-9 (close ≤ {close}e-9, acceptable ≤ {acceptable}e-9, marginal ≤ {marginal}e-9); {chi}"
            ),
        )])
    }
}

/// `benford.first_two_digits`.
pub struct FirstTwoDigits {
    params: Params,
}
procedure_boilerplate!(FirstTwoDigits, "benford.first_two_digits");

impl Procedure for FirstTwoDigits {
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
        let close = i128::from(u64::from(self.params.get_u32("mad_close")?) * 100_000);
        let acceptable = i128::from(u64::from(self.params.get_u32("mad_acceptable")?) * 100_000);
        let marginal = i128::from(u64::from(self.params.get_u32("mad_marginal")?) * 100_000);
        let currency = u16::try_from(self.params.get_u32("currency_iso4217")?).map_err(|_| {
            LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "currency_iso4217".into(),
                message: "must be an ISO 4217 numeric code in 1..=999".into(),
            }
        })?;
        if !(1..=999).contains(&currency) {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "currency_iso4217".into(),
                message: "must be an ISO 4217 numeric code in 1..=999".into(),
            });
        }
        let target_side = match self.params.get("side")? {
            0 => Side::Debit,
            1 => Side::Credit,
            _ => {
                return Err(LanternError::Parameter {
                    procedure: Self::ID.into(),
                    name: "side".into(),
                    message: "must be 0 (debit) or 1 (credit)".into(),
                });
            }
        };
        let mut counts = [0u64; 90];
        for e in snapshot.live_postings()? {
            work.entry();
            for leg in &e.entry.proposal.legs {
                work.leg();
                let Some(unit) = book.units.get(leg.amount.unit) else {
                    return Err(
                        KernelError::Corrupt("a leg names an unregistered unit".into()).into(),
                    );
                };
                if leg.side != target_side
                    || !matches!(unit.kind, UnitKind::Currency { iso4217 } if iso4217 == currency)
                {
                    continue;
                }
                let magnitude = leg.amount.mantissa.unsigned_abs();
                // A unit whose ten whole units exceed u128 admits no amount.
                let Some(min_mag) = unit.one().unsigned_abs().checked_mul(10) else {
                    continue;
                };
                if magnitude < min_mag.max(10) {
                    continue;
                }
                let d12 = first_two_digits(magnitude);
                if (10..=99).contains(&d12) {
                    counts[usize::from(d12 - 10)] += 1;
                }
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
        let mad = mad_table_1e9(&counts, &BENFORD_FIRST_TWO_1E9)?;
        let max_z = max_z_milli(&counts, &BENFORD_FIRST_TWO_1E9)?;
        let ks = ks_table_1e9(&counts, &BENFORD_FIRST_TWO_1E9)?;
        let chi = if population <= MAX_POPULATION {
            format!(
                "chi-square {}e-6 with 89 degrees of freedom, KS {ks}e-9, max Z {}e-3",
                chi_square_table_1e6(&counts, &BENFORD_FIRST_TWO_1E9)?,
                max_z
            )
        } else {
            format!(
                "chi-square not computed above {MAX_POPULATION} legs; KS {ks}e-9; max Z {max_z}e-3; MAD is the scored statistic"
            )
        };
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
                "first-two-digits over {population} legs; MAD {mad}e-9 (close ≤ {close}e-9, acceptable ≤ {acceptable}e-9, marginal ≤ {marginal}e-9); {chi}"
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
        assert_eq!(BENFORD_SECOND_1E9.iter().sum::<i128>(), 1_000_000_000);
        assert!(BENFORD_SECOND_1E9.windows(2).all(|w| w[0] > w[1]));
        assert_eq!(BENFORD_FIRST_TWO_1E9.iter().sum::<i128>(), 1_000_000_000);
        assert!(BENFORD_FIRST_TWO_1E9.windows(2).all(|w| w[0] > w[1]));
        for d1 in 0..9 {
            let row_sum: i128 = BENFORD_FIRST_TWO_1E9[d1 * 10..(d1 + 1) * 10].iter().sum();
            assert_eq!(row_sum, BENFORD_1E9[d1]);
        }
        for d2 in 0..10 {
            let col_sum: i128 = (0..9).map(|d1| BENFORD_FIRST_TWO_1E9[d1 * 10 + d2]).sum();
            assert_eq!(col_sum, BENFORD_SECOND_1E9[d2]);
        }
    }

    #[test]
    fn first_digits_and_a_perfect_population_score_zero() {
        assert_eq!(first_digit(1), 1);
        assert_eq!(first_digit(9_999), 9);
        assert_eq!(first_digit(123_456_789_012), 1);
        assert_eq!(first_two_digits(10), 10);
        assert_eq!(first_two_digits(98_765), 98);
        assert_eq!(second_digit(98_765), 8);
        // A population distributed exactly per the table (scaled by 1e9
        // legs) deviates by nothing but the table's own rounding.
        let counts: [u64; 9] = core::array::from_fn(|d| BENFORD_1E9[d] as u64);
        assert_eq!(mad_1e9(&counts).unwrap(), 0);
        let counts2: [u64; 10] = core::array::from_fn(|d| BENFORD_SECOND_1E9[d] as u64);
        assert_eq!(mad_table_1e9(&counts2, &BENFORD_SECOND_1E9).unwrap(), 0);
        let counts12: [u64; 90] = core::array::from_fn(|d| BENFORD_FIRST_TWO_1E9[d] as u64);
        assert_eq!(mad_table_1e9(&counts12, &BENFORD_FIRST_TWO_1E9).unwrap(), 0);
        // A uniform population is far from Benford: MAD = Σ|1/9 − P_d| / 9
        // ≈ 0.0597 (0.53745 / 9), exactly 59_717_035e-9 in this arithmetic.
        let uniform = [100u64; 9];
        let mad = mad_1e9(&uniform).unwrap();
        assert_eq!(mad, 59_717_035);
        let chi = chi_square_1e6(&uniform).unwrap();
        // χ² for 900 uniform legs = Σ (100 − 900·P_d)² / (900·P_d) ≈ 361.53.
        assert_eq!(chi, 361_528_463);
        let mut too_many = [0u64; 9];
        too_many[0] = MAX_POPULATION + 1;
        assert!(matches!(
            chi_square_1e6(&too_many),
            Err(LanternError::Overflow(_))
        ));
    }

    #[test]
    fn expected_counts_and_ks_match_naive_and_fsci_stats_reference_vectors() {
        use fa_reference::lantern::{
            naive_benford_expected_counts, naive_chi_square_table_1e6, naive_ks_table_1e9,
            naive_mad_table_1e9,
        };

        // 1. LargestRemainder integer expected counts sum to n and match the naive oracle.
        let exp_1000 = first_digit_expected_counts(1_000).unwrap();
        assert_eq!(exp_1000, [301, 176, 125, 97, 79, 67, 58, 51, 46]);
        assert_eq!(exp_1000.iter().sum::<u64>(), 1_000);
        assert_eq!(
            exp_1000.to_vec(),
            naive_benford_expected_counts(1_000, &BENFORD_1E9)
        );
        let exp2_1000 = second_digit_expected_counts(1_000).unwrap();
        assert_eq!(exp2_1000.iter().sum::<u64>(), 1_000);
        assert_eq!(
            exp2_1000.to_vec(),
            naive_benford_expected_counts(1_000, &BENFORD_SECOND_1E9)
        );
        let exp12_1000 = first_two_digits_expected_counts(1_000).unwrap();
        assert_eq!(exp12_1000.iter().sum::<u64>(), 1_000);
        assert_eq!(
            exp12_1000.to_vec(),
            naive_benford_expected_counts(1_000, &BENFORD_FIRST_TWO_1E9)
        );

        // 2. Uniform 9-bucket population [100; 9] (n = 900):
        // Pinned against `fsci_stats::chisquare` (361.528467 -> 361_528_467 at 1e6 scale;
        // integer floor truncation across 9 buckets differs by at most 9 units at 1e-6).
        let uniform = [100u64; 9];
        let ks_uni = ks_1e9(&uniform).unwrap();
        assert_eq!(ks_uni, 268_726_658);
        assert_eq!(ks_uni, naive_ks_table_1e9(&uniform, &BENFORD_1E9));
        let chi_uni = chi_square_1e6(&uniform).unwrap();
        assert_eq!(chi_uni, naive_chi_square_table_1e6(&uniform, &BENFORD_1E9));
        assert!((chi_uni - 361_528_467).abs() <= 9);

        // 3. Skewed leading-1 heavy population (n = 1000):
        // Pinned against `fsci_stats::chisquare` (198_818_611 at 1e6 scale) and step KS (198_970_004 at 1e9 scale).
        let skewed = [500u64, 100, 80, 70, 60, 50, 50, 45, 45];
        let ks_skew = ks_1e9(&skewed).unwrap();
        assert_eq!(ks_skew, 198_970_004);
        assert_eq!(ks_skew, naive_ks_table_1e9(&skewed, &BENFORD_1E9));
        let chi_skew = chi_square_1e6(&skewed).unwrap();
        assert_eq!(chi_skew, naive_chi_square_table_1e6(&skewed, &BENFORD_1E9));
        assert!((chi_skew - 198_818_611).abs() <= 9);
        assert_eq!(
            mad_1e9(&skewed).unwrap(),
            naive_mad_table_1e9(&skewed, &BENFORD_1E9)
        );

        // 4. Asymptotic Smirnov critical values at n = 10_000 (sqrt(n) = 100):
        assert_eq!(ks_critical_1e9(10_000, 1_000).unwrap(), 12_200_000);
        assert_eq!(ks_critical_1e9(10_000, 500).unwrap(), 13_600_000);
        assert_eq!(ks_critical_1e9(10_000, 100).unwrap(), 16_300_000);
    }
}
