//! Audit sampling: Monetary Unit Sampling (MUS), exact rational Stringer bound
//! evaluation, deterministic uniform selection, and stratified sampling with
//! Neyman optimal allocation (plan §11.7, §15.6; bead `fa-kaf7`).
//!
//! Constitutional guarantees:
//! - `#![forbid(unsafe_code)]`
//! - No entropy capability, no clock, no floats: every sample is a pure,
//!   deterministic function of `(population_digest, declared_seed, parameters)`
//!   using [`Pcg64Dxsm`].
//! - Stringer upper misstatement limits are computed in exact rationals
//!   ([`fa_money::Rate`]) and rounded conservatively upward (ceiling) to exact
//!   [`fa_money::Amount`] values.
//! - Stratified sample allocation under Neyman optimal allocation emits a
//!   replayable [`fa_policy::DecisionCard`] (`DecisionKind::SamplingStratification`).

use std::collections::BTreeMap;

use asupersync::Cx;
use fa_model::Oid;
use fa_money::{Amount, ArithmeticBudget, BudgetLimits, Rate, RateError, UnitId};
use fa_policy::{
    BenefitInterval, DecisionCandidate, DecisionCard, DecisionFeature, DecisionKind,
    evaluate_decision,
};
use fgdb_crypto::Hasher;
use fgdb_types::VId;

use crate::LanternError;

const POPULATION_DIGEST_DOMAIN: &[u8] = b"fa:lantern:sample-population:v1";
const SAMPLE_CERT_DOMAIN: &[u8] = b"fa:lantern:sample-certificate:v1";

const XSHIFT: u32 = 16;
const INIT_A: u32 = 0x43b0_d7e5;
const MULT_A: u32 = 0x931e_8875;
const INIT_B: u32 = 0x8b51_f9dd;
const MULT_B: u32 = 0x58f3_8ded;
const MIX_MULT_L: u32 = 0xca01_f9dd;
const MIX_MULT_R: u32 = 0x4973_f715;
const POOL_SIZE: usize = 4;
const CHEAP_MULTIPLIER: u64 = 0xda94_2042_e4dd_58b5;
const DEFAULT_MULTIPLIER: u128 = 0x2360_ed05_1fc6_5da4_4385_df64_9fcc_f645;

/// NumPy's default `SeedSequence` pool width in 32-bit words.
pub const DEFAULT_SEED_SEQUENCE_POOL_SIZE: usize = POOL_SIZE;

/// NumPy-compatible `SeedSequence` specialized to the canonical four-word pool
/// (`fnp-random-core`, bead `fa-vpk`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedSequence {
    pool: [u32; POOL_SIZE],
}

impl SeedSequence {
    /// Construct `SeedSequence(seed)` from an unsigned 64-bit integer.
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        Self::assemble(&entropy_words(seed), &[])
    }

    /// Construct `SeedSequence(entropy=seed, spawn_key=spawn_key)`.
    #[must_use]
    pub fn with_spawn_key(seed: u64, spawn_key: &[u32]) -> Self {
        Self::assemble(&entropy_words(seed), spawn_key)
    }

    /// Construct from NumPy-style little-endian entropy words.
    ///
    /// An empty entropy slice is normalized to the single word zero, matching
    /// integer seed zero rather than creating an unseeded host-entropy path.
    #[must_use]
    pub fn from_entropy_words(entropy: &[u32], spawn_key: &[u32]) -> Self {
        if entropy.is_empty() {
            Self::assemble(&[0], spawn_key)
        } else {
            Self::assemble(entropy, spawn_key)
        }
    }

    fn assemble(entropy: &[u32], spawn_key: &[u32]) -> Self {
        let mut assembled = entropy.to_vec();
        if !spawn_key.is_empty() && assembled.len() < POOL_SIZE {
            assembled.resize(POOL_SIZE, 0);
        }
        assembled.extend_from_slice(spawn_key);

        let mut pool = [0_u32; POOL_SIZE];
        let mut hash_const = INIT_A;
        for (index, slot) in pool.iter_mut().enumerate() {
            *slot = hashmix(assembled.get(index).copied().unwrap_or(0), &mut hash_const);
        }
        for source in 0..POOL_SIZE {
            for destination in 0..POOL_SIZE {
                if source != destination {
                    let hashed = hashmix(pool[source], &mut hash_const);
                    pool[destination] = mix(pool[destination], hashed);
                }
            }
        }
        for &extra in assembled.iter().skip(POOL_SIZE) {
            for slot in &mut pool {
                let hashed = hashmix(extra, &mut hash_const);
                *slot = mix(*slot, hashed);
            }
        }
        Self { pool }
    }

    /// Generate NumPy-compatible 32-bit state words.
    #[must_use]
    pub fn generate_state(&self, word_count: usize) -> Vec<u32> {
        let mut output = Vec::with_capacity(word_count);
        let mut hash_const = INIT_B;
        for index in 0..word_count {
            let mut value = self.pool[index % POOL_SIZE];
            value ^= hash_const;
            hash_const = hash_const.wrapping_mul(MULT_B);
            value = value.wrapping_mul(hash_const);
            value ^= value >> XSHIFT;
            output.push(value);
        }
        output
    }

    /// Generate NumPy-compatible 64-bit state words, pairing low word first.
    #[must_use]
    pub fn generate_state_u64(&self, word_count: usize) -> Vec<u64> {
        let state_word_count = word_count
            .checked_mul(2)
            .expect("SeedSequence u64 output word count overflow");
        let words = self.generate_state(state_word_count);
        words
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u64::from(pair[0]) | (u64::from(pair[1]) << 32))
            .collect()
    }
}

/// Deterministic NumPy-compatible `PCG64DXSM` pseudo-number generator seeded
/// from a declared `u64` input (`fnp-random-core`, no ambient entropy capability,
/// Doctrine 3).
///
/// # Python / NumPy Reproducibility Snippet
///
/// Every raw 64-bit word and bounded 128-bit integer drawn by [`Pcg64Dxsm`] matches
/// `numpy.random.PCG64DXSM(seed)` bit-for-bit:
///
/// ```text
/// import numpy as np
///
/// def next_bounded_u128(bg: np.random.PCG64DXSM, bound: int) -> int:
///     if bound <= 1:
///         return 0
///     u128_max = (1 << 128) - 1
///     zone = u128_max - (u128_max % bound)
///     while True:
///         hi = int(bg.random_raw())
///         lo = int(bg.random_raw())
///         v = (hi << 64) | lo
///         if v < zone:
///             return v % bound
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pcg64Dxsm {
    state: u128,
    increment: u128,
}

/// Compatibility alias matching `fnp-random-core`.
pub type Pcg64DxsmRng = Pcg64Dxsm;

impl Pcg64Dxsm {
    /// Construct a deterministic `Pcg64Dxsm` stream from `seed`, matching
    /// `numpy.random.PCG64DXSM(seed)`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self::from_seed(seed)
    }

    /// Seed from a NumPy-compatible [`SeedSequence`].
    #[must_use]
    pub fn from_seed_sequence(sequence: &SeedSequence) -> Self {
        let words = sequence.generate_state_u64(4);
        let initial_state = (u128::from(words[0]) << 64) | u128::from(words[1]);
        let initial_sequence = (u128::from(words[2]) << 64) | u128::from(words[3]);
        Self::seed(initial_state, initial_sequence)
    }

    /// Construct exactly as `numpy.random.PCG64DXSM(seed)`.
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        Self::from_seed_sequence(&SeedSequence::from_seed(seed))
    }

    /// Apply the standard PCG set-sequence seeding dance.
    #[must_use]
    pub fn seed(initial_state: u128, initial_sequence: u128) -> Self {
        let increment = (initial_sequence << 1) | 1;
        let mut generator = Self {
            state: 0,
            increment,
        };
        generator.seed_step();
        generator.state = generator.state.wrapping_add(initial_state);
        generator.seed_step();
        generator
    }

    /// Restore an exact raw state without running the seeding transform.
    #[must_use]
    pub const fn from_raw_state(state: u128, increment: u128) -> Self {
        Self { state, increment }
    }

    /// Return the exact `(state, increment)` pair.
    #[must_use]
    pub const fn raw_state(&self) -> (u128, u128) {
        (self.state, self.increment)
    }

    /// Return the split state form used by portable journals and manifests.
    #[must_use]
    pub const fn split_state(&self) -> ([u64; 2], [u64; 2]) {
        (
            [(self.state >> 64) as u64, self.state as u64],
            [(self.increment >> 64) as u64, self.increment as u64],
        )
    }

    /// Restore a state emitted by [`Self::split_state`].
    #[must_use]
    pub const fn from_split_state(state: [u64; 2], increment: [u64; 2]) -> Self {
        Self {
            state: (state[0] as u128) << 64 | state[1] as u128,
            increment: (increment[0] as u128) << 64 | increment[1] as u128,
        }
    }

    fn seed_step(&mut self) {
        self.state = self
            .state
            .wrapping_mul(DEFAULT_MULTIPLIER)
            .wrapping_add(self.increment);
    }

    #[inline]
    fn step(&mut self) {
        self.state = self
            .state
            .wrapping_mul(u128::from(CHEAP_MULTIPLIER))
            .wrapping_add(self.increment);
    }

    /// Generate the next raw 64-bit DXSM word, then advance the state.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let low = (self.state as u64) | 1;
        let mut high = (self.state >> 64) as u64;
        high ^= high >> 32;
        high = high.wrapping_mul(CHEAP_MULTIPLIER);
        high ^= high >> 48;
        high = high.wrapping_mul(low);
        self.step();
        high
    }

    /// Advance the state by `delta` steps (jump-ahead) in O(log delta)
    /// multiplications: the stream continues exactly as if `delta` values had
    /// been drawn.
    pub fn advance(&mut self, delta: u128) {
        self.state = lcg_advance_128(
            self.state,
            delta,
            u128::from(CHEAP_MULTIPLIER),
            self.increment,
        );
    }

    /// Draw an unbiased integer in `0..bound` via rejection over 128-bit raw draws.
    pub fn next_bounded_u128(&mut self, bound: u128) -> u128 {
        if bound <= 1 {
            return 0;
        }
        let zone = u128::MAX - (u128::MAX % bound);
        loop {
            let hi = u128::from(self.next_u64());
            let lo = u128::from(self.next_u64());
            let v = (hi << 64) | lo;
            if v < zone {
                return v % bound;
            }
        }
    }
}

/// The state of the 128-bit LCG `state' = mult * state + inc` after `delta` steps:
/// `mult^delta * state + (mult^delta - 1) / (mult - 1) * inc`, by repeated squaring in
/// O(log delta) multiplications (Brown, "Random Number Generation with Arbitrary Strides").
#[must_use]
pub fn lcg_advance_128(state: u128, mut delta: u128, mult: u128, inc: u128) -> u128 {
    let mut cur_mult: u128 = mult;
    let mut cur_plus: u128 = inc;
    let mut acc_mult: u128 = 1;
    let mut acc_plus: u128 = 0;
    while delta > 0 {
        if delta & 1 != 0 {
            acc_mult = acc_mult.wrapping_mul(cur_mult);
            acc_plus = acc_plus.wrapping_mul(cur_mult).wrapping_add(cur_plus);
        }
        delta >>= 1;
        if delta > 0 {
            cur_plus = cur_mult.wrapping_add(1).wrapping_mul(cur_plus);
            cur_mult = cur_mult.wrapping_mul(cur_mult);
        }
    }
    acc_mult.wrapping_mul(state).wrapping_add(acc_plus)
}

fn entropy_words(seed: u64) -> Vec<u32> {
    if seed == 0 {
        return vec![0];
    }
    let mut words = Vec::with_capacity(2);
    let mut value = seed;
    while value != 0 {
        words.push(value as u32);
        value >>= 32;
    }
    words
}

fn hashmix(value: u32, hash_const: &mut u32) -> u32 {
    let mut mixed = value ^ *hash_const;
    *hash_const = hash_const.wrapping_mul(MULT_A);
    mixed = mixed.wrapping_mul(*hash_const);
    mixed ^ (mixed >> XSHIFT)
}

fn mix(left: u32, right: u32) -> u32 {
    let mut mixed = left
        .wrapping_mul(MIX_MULT_L)
        .wrapping_sub(right.wrapping_mul(MIX_MULT_R));
    mixed ^= mixed >> XSHIFT;
    mixed
}

/// An item in an audit sampling population (an open item or GL detail leg).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PopulationItem {
    pub item_id: String,
    pub reference_vid: VId,
    pub stratum: Option<String>,
    pub book_value: Amount,
}

/// Canonical, content-addressed audit sampling population.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamplePopulation {
    pub name: String,
    pub unit: UnitId,
    pub items: Vec<PopulationItem>,
    pub total_book_value: Amount,
    pub population_digest: [u8; 32],
}

impl SamplePopulation {
    /// Construct and canonically sort a [`SamplePopulation`] by `(item_id, reference_vid)`,
    /// refusing empty populations, mixed units, or non-positive book values.
    pub fn new(
        name: impl Into<String>,
        unit: UnitId,
        mut items: Vec<PopulationItem>,
    ) -> Result<Self, LanternError> {
        let name = name.into();
        if items.is_empty() {
            return Err(LanternError::Parameter {
                procedure: "sample.population".into(),
                name: "items".into(),
                message: "sampling population must contain at least one positive-value item".into(),
            });
        }
        items.sort_by(|a, b| {
            a.item_id
                .cmp(&b.item_id)
                .then_with(|| a.reference_vid.0.cmp(&b.reference_vid.0))
        });
        let mut total: i128 = 0;
        for item in &items {
            if item.book_value.unit != unit {
                return Err(LanternError::Parameter {
                    procedure: "sample.population".into(),
                    name: "unit".into(),
                    message: format!(
                        "item `{}` has unit {:?}, expected {:?}",
                        item.item_id, item.book_value.unit, unit
                    ),
                });
            }
            if item.book_value.mantissa <= 0 {
                return Err(LanternError::Parameter {
                    procedure: "sample.population".into(),
                    name: "book_value".into(),
                    message: format!(
                        "item `{}` has non-positive book value {}",
                        item.item_id, item.book_value.mantissa
                    ),
                });
            }
            total = total
                .checked_add(item.book_value.mantissa)
                .ok_or(LanternError::Overflow("population total book value"))?;
        }

        let mut h = Hasher::new();
        h.update(POPULATION_DIGEST_DOMAIN);
        h.update(&(name.len() as u64).to_le_bytes());
        h.update(name.as_bytes());
        h.update(&unit.0.to_le_bytes());
        h.update(&(items.len() as u64).to_le_bytes());
        h.update(&total.to_le_bytes());
        for item in &items {
            h.update(&(item.item_id.len() as u64).to_le_bytes());
            h.update(item.item_id.as_bytes());
            h.update(&item.reference_vid.0.to_le_bytes());
            h.update(&item.book_value.mantissa.to_le_bytes());
            if let Some(s) = &item.stratum {
                h.update(&[1]);
                h.update(&(s.len() as u64).to_le_bytes());
                h.update(s.as_bytes());
            } else {
                h.update(&[0]);
            }
        }
        let population_digest = h.finalize().0;

        Ok(Self {
            name,
            unit,
            items,
            total_book_value: Amount::new(unit, total),
            population_digest,
        })
    }
}

/// Reason an item was selected in a Monetary Unit Sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MusSelectionBasis {
    /// `book_value >= interval`: examined 100% in the top stratum.
    TopStratumHighValue,
    /// Selected by systematic cumulative dollar hit at `hit_dollar_mantissa`.
    SystematicHit { hit_dollar_mantissa: i128 },
}

/// A selected item in an MUS sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MusSelectedItem {
    pub population_index: usize,
    pub item_id: String,
    pub reference_vid: VId,
    pub book_value: Amount,
    pub basis: MusSelectionBasis,
}

/// Reproducible certificate for a sample selection (`fa sample mus|uniform|stratified`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SampleCertificate {
    pub method: String,
    pub population_digest: [u8; 32],
    pub seed: u64,
    pub parameters_summary: String,
    pub selected_item_ids: Vec<String>,
    pub certificate_oid: Oid,
}

impl SampleCertificate {
    #[must_use]
    pub fn compute(
        method: &str,
        population_digest: [u8; 32],
        seed: u64,
        parameters_summary: &str,
        selected_item_ids: Vec<String>,
    ) -> Self {
        let mut h = Hasher::new();
        h.update(SAMPLE_CERT_DOMAIN);
        h.update(&(method.len() as u64).to_le_bytes());
        h.update(method.as_bytes());
        h.update(&population_digest);
        h.update(&seed.to_le_bytes());
        h.update(&(parameters_summary.len() as u64).to_le_bytes());
        h.update(parameters_summary.as_bytes());
        h.update(&(selected_item_ids.len() as u64).to_le_bytes());
        for id in &selected_item_ids {
            h.update(&(id.len() as u64).to_le_bytes());
            h.update(id.as_bytes());
        }
        let certificate_oid = Oid(h.finalize().0);
        Self {
            method: method.to_owned(),
            population_digest,
            seed,
            parameters_summary: parameters_summary.to_owned(),
            selected_item_ids,
            certificate_oid,
        }
    }
}

/// Output of a Monetary Unit Sample (`fa sample mus`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MusSamplePlan {
    pub population_digest: [u8; 32],
    pub seed: u64,
    pub interval: Amount,
    pub start_dollar_mantissa: i128,
    pub top_stratum_count: usize,
    pub systematic_sample_count: usize,
    pub selected: Vec<MusSelectedItem>,
    pub certificate: SampleCertificate,
}

/// The AICPA expansion factor for expected misstatement at a confidence
/// level (1 - risk of incorrect acceptance), in basis points.
fn expansion_factor_bps(confidence_level_bps: u32) -> Result<i128, LanternError> {
    match confidence_level_bps {
        9_000 => Ok(15_000),
        9_500 => Ok(16_000),
        9_900 => Ok(19_000),
        _ => Err(LanternError::Parameter {
            procedure: "sample.mus".into(),
            name: "confidence_level_bps".into(),
            message:
                "supported confidence_level_bps values are 9000 (90%), 9500 (95%), or 9900 (99%)"
                    .into(),
        }),
    }
}

/// The MUS sampling interval planned from its named inputs (plan §11.12):
/// `(tolerable - expected x expansion factor) / reliability factor`, where
/// the reliability factor is the zero-misstatement Poisson factor R(0) of
/// the Stringer evaluation at the same confidence. The interval is rounded
/// down to the unit, so the planned sample is never smaller than the
/// formula's. Tolerable and expected misstatement are parameters the
/// auditor states, never judgments this function makes.
pub fn mus_interval(
    tolerable: Amount,
    expected: Amount,
    confidence_level_bps: u32,
) -> Result<Amount, LanternError> {
    let parameter = |name: &str, message: String| LanternError::Parameter {
        procedure: "sample.mus".into(),
        name: name.into(),
        message,
    };
    if expected.unit != tolerable.unit {
        return Err(parameter(
            "expected",
            "expected misstatement must be in the tolerable misstatement's unit".into(),
        ));
    }
    if tolerable.mantissa <= 0 || expected.mantissa < 0 {
        return Err(parameter(
            "tolerable",
            "tolerable misstatement must be positive and expected misstatement non-negative".into(),
        ));
    }
    let expansion = expansion_factor_bps(confidence_level_bps)?;
    let reliability = i128::try_from(poisson_upper_factor_bps(confidence_level_bps, 0)?)
        .map_err(|_| LanternError::Overflow("mus reliability factor"))?;
    let room = tolerable
        .mantissa
        .checked_mul(10_000)
        .zip(expected.mantissa.checked_mul(expansion))
        .and_then(|(tolerable, expected)| tolerable.checked_sub(expected))
        .ok_or(LanternError::Overflow("mus planned interval"))?;
    let interval = room.div_euclid(reliability);
    if interval <= 0 {
        return Err(parameter(
            "expected",
            "expected misstatement times its expansion factor leaves no tolerable misstatement to plan a sample for".into(),
        ));
    }
    Ok(Amount::new(tolerable.unit, interval))
}

/// Execute a deterministic Monetary Unit Sample (`fa sample mus`) over `population`
/// with declared `seed` and `interval`.
pub fn sample_mus(
    population: &SamplePopulation,
    seed: u64,
    interval: Amount,
) -> Result<MusSamplePlan, LanternError> {
    if interval.unit != population.unit {
        return Err(LanternError::Parameter {
            procedure: "sample.mus".into(),
            name: "interval".into(),
            message: "sampling interval unit must match population unit".into(),
        });
    }
    if interval.mantissa <= 0 {
        return Err(LanternError::Parameter {
            procedure: "sample.mus".into(),
            name: "interval".into(),
            message: "sampling interval must be positive".into(),
        });
    }

    let mut prng = Pcg64Dxsm::new(seed);
    let step = interval.mantissa;
    let start_dollar_mantissa = (prng.next_bounded_u128(step as u128) as i128) + 1;

    let mut selected = Vec::new();
    let mut top_stratum_count = 0usize;
    let mut systematic_sample_count = 0usize;

    let mut cumulative: i128 = 0;
    let mut next_hit: i128 = start_dollar_mantissa;

    for (idx, item) in population.items.iter().enumerate() {
        if item.book_value.mantissa >= step {
            top_stratum_count += 1;
            selected.push(MusSelectedItem {
                population_index: idx,
                item_id: item.item_id.clone(),
                reference_vid: item.reference_vid,
                book_value: item.book_value,
                basis: MusSelectionBasis::TopStratumHighValue,
            });
            continue;
        }
        let next_cum = cumulative
            .checked_add(item.book_value.mantissa)
            .ok_or(LanternError::Overflow("MUS cumulative book value"))?;
        if next_hit <= next_cum {
            let hit = next_hit;
            systematic_sample_count += 1;
            selected.push(MusSelectedItem {
                population_index: idx,
                item_id: item.item_id.clone(),
                reference_vid: item.reference_vid,
                book_value: item.book_value,
                basis: MusSelectionBasis::SystematicHit {
                    hit_dollar_mantissa: hit,
                },
            });
            while next_hit <= next_cum {
                next_hit = next_hit
                    .checked_add(step)
                    .ok_or(LanternError::Overflow("MUS next_hit"))?;
            }
        }
        cumulative = next_cum;
    }

    let selected_ids: Vec<String> = selected.iter().map(|s| s.item_id.clone()).collect();
    let certificate = SampleCertificate::compute(
        "mus",
        population.population_digest,
        seed,
        &format!(
            "interval={};start={start_dollar_mantissa}",
            interval.mantissa
        ),
        selected_ids,
    );

    Ok(MusSamplePlan {
        population_digest: population.population_digest,
        seed,
        interval,
        start_dollar_mantissa,
        top_stratum_count,
        systematic_sample_count,
        selected,
        certificate,
    })
}

/// An audited sample item observation for Stringer bound evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditedSampleItem {
    pub item_id: String,
    pub book_value: Amount,
    pub audited_value: Amount,
}

/// Exact rational and law-rounded Stringer bound evaluation result (`fa-kaf7`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringerEvaluation {
    pub confidence_level_bps: u32,
    pub sampling_interval: Amount,
    pub misstatement_count: usize,
    /// Ranked overstatement taintings `(item_id, tainting_rate)` in descending order.
    pub ranked_taintings: Vec<(String, Rate)>,
    /// Exact dollar overstatement in top-stratum (`book_value >= interval`) items.
    pub top_stratum_misstatement: Amount,
    /// Basic precision $I \cdot R(0; 1-\alpha)$ rounded conservatively upward.
    pub basic_precision: Amount,
    /// Projected misstatement (most likely error) rounded conservatively upward.
    pub most_likely_error: Amount,
    /// Incremental allowance for sampling risk rounded conservatively upward.
    pub incremental_allowance: Amount,
    /// Total Stringer upper misstatement limit (UML), exact rational and Ceiling-rounded `Amount`.
    pub upper_misstatement_limit_exact: Rate,
    pub upper_misstatement_limit: Amount,
}

/// The most misstatements the registered Poisson factor tables cover.
pub const MAX_TABLED_MISSTATEMENTS: usize = 40;

/// The registered one-sided Poisson upper confidence factor R(k) for `k`
/// misstatements, in basis points: the exact limit (P(X <= k; R) = 1 -
/// confidence) rounded up to 0.01, so every bound built on it is
/// conservative. `poisson_factors_are_the_upper_limits_rounded_up_to_a_hundredth`
/// proves each entry in exact integer arithmetic. Beyond the table the
/// bound is refused, never extrapolated.
fn poisson_upper_factor_bps(confidence_level_bps: u32, k: usize) -> Result<u128, LanternError> {
    const FACTORS_90: [u128; MAX_TABLED_MISSTATEMENTS + 1] = [
        23_100, 38_900, 53_300, 66_900, 80_000, 92_800, 105_400, 117_800, 130_000, 142_100,
        154_100, 166_000, 177_900, 189_600, 201_300, 213_000, 224_600, 236_100, 247_600, 259_100,
        270_500, 281_900, 293_300, 304_600, 315_900, 327_200, 338_400, 349_600, 360_800, 372_000,
        383_200, 394_300, 405_500, 416_600, 427_700, 438_800, 449_800, 460_900, 471_900, 482_900,
        494_000,
    ];
    const FACTORS_95: [u128; MAX_TABLED_MISSTATEMENTS + 1] = [
        30_000, 47_500, 63_000, 77_600, 91_600, 105_200, 118_500, 131_500, 144_400, 157_100,
        169_700, 182_100, 194_500, 206_700, 218_900, 231_000, 243_100, 255_000, 267_000, 278_800,
        290_700, 302_500, 314_200, 325_900, 337_600, 349_200, 360_800, 372_400, 383_900, 395_500,
        407_000, 418_400, 429_900, 441_300, 452_700, 464_100, 475_500, 486_800, 498_100, 509_400,
        520_700,
    ];
    const FACTORS_99: [u128; MAX_TABLED_MISSTATEMENTS + 1] = [
        46_100, 66_400, 84_100, 100_500, 116_100, 131_100, 145_800, 160_000, 174_100, 187_900,
        201_500, 214_900, 228_300, 241_400, 254_500, 267_500, 280_400, 293_100, 305_900, 318_500,
        331_100, 343_600, 356_100, 368_500, 380_800, 393_100, 405_400, 417_600, 429_800, 441_900,
        454_100, 466_100, 478_200, 490_200, 502_200, 514_100, 526_100, 538_000, 549_800, 561_700,
        573_500,
    ];
    let table: &[u128] = match confidence_level_bps {
        9_000 => &FACTORS_90,
        9_500 => &FACTORS_95,
        9_900 => &FACTORS_99,
        _ => {
            return Err(LanternError::Parameter {
                procedure: "sample.stringer".into(),
                name: "confidence_level_bps".into(),
                message: "supported confidence_level_bps values are 9000 (90%), 9500 (95%), or 9900 (99%)"
                    .into(),
            });
        }
    };
    // The former fixed 1.30-per-misstatement extension understated R(k) at
    // 99% from k = 11 (21.45 against 21.4899...), and so the bound; the
    // table carries exact entries instead.
    table
        .get(k)
        .copied()
        .ok_or_else(|| LanternError::Parameter {
            procedure: "sample.stringer".into(),
            name: "misstatements".into(),
            message: format!(
                "{k} misstatements exceed the registered Poisson factor table (0..={MAX_TABLED_MISSTATEMENTS}); the Stringer bound is never extrapolated"
            ),
        })
}

fn rate_err(_e: RateError) -> LanternError {
    LanternError::Overflow("stringer exact rational arithmetic")
}

fn ceil_rate_to_i128(
    rate: &Rate,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Result<i128, LanternError> {
    let (q, frac) = rate.floor_and_frac(budget).map_err(rate_err)?;
    let ceil_u = if frac.is_zero() {
        q
    } else {
        q.checked_add(1)
            .ok_or(LanternError::Overflow("stringer ceiling"))?
    };
    i128::try_from(ceil_u).map_err(|_| LanternError::Overflow("stringer i128 conversion"))
}

/// Evaluate the Stringer upper misstatement limit (UML) in exact rationals
/// ([`Rate`]) and round conservatively upward (ceiling) to [`Amount`].
pub fn evaluate_stringer_bound(
    sampling_interval: Amount,
    confidence_level_bps: u32,
    audited_items: &[AuditedSampleItem],
) -> Result<StringerEvaluation, LanternError> {
    let unit = sampling_interval.unit;
    if sampling_interval.mantissa <= 0 {
        return Err(LanternError::Parameter {
            procedure: "sample.stringer".into(),
            name: "sampling_interval".into(),
            message: "sampling_interval must be positive".into(),
        });
    }
    let cx = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&cx, BudgetLimits::uniform(1_000_000, 0), 65_536);

    let interval_u = sampling_interval.mantissa as u128;
    let interval_rate = Rate::new(&mut budget, interval_u, 1).map_err(rate_err)?;
    let r0_bps = poisson_upper_factor_bps(confidence_level_bps, 0)?;
    let r0_rate = Rate::new(&mut budget, r0_bps, 10_000).map_err(rate_err)?;
    let bp_exact = interval_rate
        .checked_mul(&mut budget, &r0_rate)
        .map_err(rate_err)?;

    let mut top_stratum_overstatement: i128 = 0;
    let mut raw_taintings: Vec<(String, u128, u128, Rate)> = Vec::new();

    for item in audited_items {
        if item.book_value.unit != unit || item.audited_value.unit != unit {
            return Err(LanternError::Parameter {
                procedure: "sample.stringer".into(),
                name: "unit".into(),
                message: "all audited sample items must match sampling_interval unit".into(),
            });
        }
        if item.book_value.mantissa <= 0 {
            return Err(LanternError::Parameter {
                procedure: "sample.stringer".into(),
                name: "book_value".into(),
                message: "audited sample item book_value must be positive".into(),
            });
        }
        let overstatement = item
            .book_value
            .mantissa
            .checked_sub(item.audited_value.mantissa)
            .ok_or(LanternError::Overflow("overstatement difference"))?;
        if overstatement <= 0 {
            continue;
        }
        if item.book_value.mantissa >= sampling_interval.mantissa {
            top_stratum_overstatement = top_stratum_overstatement
                .checked_add(overstatement)
                .ok_or(LanternError::Overflow("top stratum overstatement"))?;
        } else {
            let over_u = overstatement as u128;
            let bv_u = item.book_value.mantissa as u128;
            let taint = Rate::new(&mut budget, over_u, bv_u).map_err(rate_err)?;
            raw_taintings.push((item.item_id.clone(), over_u, bv_u, taint));
        }
    }

    // Rank taintings in descending order t_1 >= t_2 >= ... >= t_m; break ties by item_id.
    raw_taintings.sort_by(|a, b| {
        let lhs = a.1.saturating_mul(b.2);
        let rhs = b.1.saturating_mul(a.2);
        rhs.cmp(&lhs).then_with(|| a.0.cmp(&b.0))
    });

    let mut projected_lower_exact = Rate::zero(&mut budget).map_err(rate_err)?;
    let mut incremental_exact = Rate::zero(&mut budget).map_err(rate_err)?;

    for (idx, (_, _, _, taint)) in raw_taintings.iter().enumerate() {
        let k = idx + 1;
        let rk_bps = poisson_upper_factor_bps(confidence_level_bps, k)?;
        let rk_prev_bps = poisson_upper_factor_bps(confidence_level_bps, k - 1)?;
        let delta_r_bps = rk_bps.saturating_sub(rk_prev_bps);

        let proj_k = interval_rate
            .checked_mul(&mut budget, taint)
            .map_err(rate_err)?;
        projected_lower_exact = projected_lower_exact
            .checked_add(&mut budget, &proj_k)
            .map_err(rate_err)?;

        let inc_bps = delta_r_bps.saturating_sub(10_000);
        let inc_factor = Rate::new(&mut budget, inc_bps, 10_000).map_err(rate_err)?;
        let inc_k = proj_k
            .checked_mul(&mut budget, &inc_factor)
            .map_err(rate_err)?;
        incremental_exact = incremental_exact
            .checked_add(&mut budget, &inc_k)
            .map_err(rate_err)?;
    }

    let top_exact =
        Rate::new(&mut budget, top_stratum_overstatement as u128, 1).map_err(rate_err)?;
    let mle_exact = top_exact
        .checked_add(&mut budget, &projected_lower_exact)
        .map_err(rate_err)?;
    let bp_plus_mle = bp_exact
        .checked_add(&mut budget, &mle_exact)
        .map_err(rate_err)?;
    let uml_exact = bp_plus_mle
        .checked_add(&mut budget, &incremental_exact)
        .map_err(rate_err)?;

    let basic_precision = Amount::new(unit, ceil_rate_to_i128(&bp_exact, &mut budget)?);
    let most_likely_error = Amount::new(unit, ceil_rate_to_i128(&mle_exact, &mut budget)?);
    let incremental_allowance =
        Amount::new(unit, ceil_rate_to_i128(&incremental_exact, &mut budget)?);
    let upper_misstatement_limit = Amount::new(unit, ceil_rate_to_i128(&uml_exact, &mut budget)?);

    let ranked_taintings: Vec<(String, Rate)> = raw_taintings
        .into_iter()
        .map(|(id, _, _, r)| (id, r))
        .collect();

    Ok(StringerEvaluation {
        confidence_level_bps,
        sampling_interval,
        misstatement_count: ranked_taintings.len() + usize::from(top_stratum_overstatement > 0),
        ranked_taintings,
        top_stratum_misstatement: Amount::new(unit, top_stratum_overstatement),
        basic_precision,
        most_likely_error,
        incremental_allowance,
        upper_misstatement_limit_exact: uml_exact,
        upper_misstatement_limit,
    })
}

/// Deterministic uniform sample without replacement (`fa sample uniform`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniformSamplePlan {
    pub population_digest: [u8; 32],
    pub seed: u64,
    pub sample_size: usize,
    pub selected: Vec<PopulationItem>,
    pub certificate: SampleCertificate,
}

/// Draw a reproducible uniform sample of `sample_size` items without replacement
/// from `population` using `Pcg64Dxsm::new(seed)`.
pub fn sample_uniform(
    population: &SamplePopulation,
    seed: u64,
    sample_size: usize,
) -> Result<UniformSamplePlan, LanternError> {
    if sample_size == 0 || sample_size > population.items.len() {
        return Err(LanternError::Parameter {
            procedure: "sample.uniform".into(),
            name: "sample_size".into(),
            message: format!(
                "sample_size {sample_size} must lie in 1..={}",
                population.items.len()
            ),
        });
    }
    let mut indices: Vec<usize> = (0..population.items.len()).collect();
    let mut prng = Pcg64Dxsm::new(seed);
    let n = indices.len();
    for i in 0..sample_size {
        let offset = prng.next_bounded_u128((n - i) as u128) as usize;
        indices.swap(i, i + offset);
    }
    let mut chosen = indices[..sample_size].to_vec();
    chosen.sort_unstable();
    let selected: Vec<PopulationItem> = chosen
        .into_iter()
        .map(|idx| population.items[idx].clone())
        .collect();
    let selected_ids: Vec<String> = selected.iter().map(|s| s.item_id.clone()).collect();
    let certificate = SampleCertificate::compute(
        "uniform",
        population.population_digest,
        seed,
        &format!("sample_size={sample_size}"),
        selected_ids,
    );
    Ok(UniformSamplePlan {
        population_digest: population.population_digest,
        seed,
        sample_size,
        selected,
        certificate,
    })
}

/// Allocation for a single stratum under stratified sampling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StratumAllocation {
    pub stratum: String,
    pub population_count: usize,
    pub std_dev_mantissa: i128,
    pub allocated_sample_size: usize,
}

/// Stratified sample plan with Neyman optimal allocation and replayable
/// [`DecisionCard`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StratifiedSamplePlan {
    pub population_digest: [u8; 32],
    pub seed: u64,
    pub total_sample_size: usize,
    pub strata: Vec<StratumAllocation>,
    pub selected: Vec<PopulationItem>,
    pub decision_card: DecisionCard,
    pub certificate: SampleCertificate,
}

/// Compute Neyman optimal stratum allocation and draw a stratified sample using
/// `Pcg64Dxsm::new(seed)`, emitting a replayable [`DecisionCard`] with
/// proportional allocation as the pinned deterministic fallback.
pub fn sample_stratified_neyman(
    population: &SamplePopulation,
    seed: u64,
    total_sample_size: usize,
    policy_epoch: Option<[u8; 32]>,
    enforced_policy_epoch: [u8; 32],
    _subject: VId,
) -> Result<StratifiedSamplePlan, LanternError> {
    let mut by_stratum: BTreeMap<String, Vec<&PopulationItem>> = BTreeMap::new();
    for item in &population.items {
        let key = item.stratum.clone().unwrap_or_else(|| "default".into());
        by_stratum.entry(key).or_default().push(item);
    }
    let h_count = by_stratum.len();
    if total_sample_size < h_count || total_sample_size > population.items.len() {
        return Err(LanternError::Parameter {
            procedure: "sample.stratified".into(),
            name: "total_sample_size".into(),
            message: format!(
                "total_sample_size {total_sample_size} must lie in {h_count}..={}",
                population.items.len()
            ),
        });
    }

    let mut stratum_stats: Vec<(String, usize, i128)> = Vec::with_capacity(h_count);
    for (name, items) in &by_stratum {
        let nh = items.len();
        let sum: i128 = items.iter().map(|i| i.book_value.mantissa).sum();
        let mean = sum / (nh as i128);
        let mut sq_sum: u128 = 0;
        for item in items {
            let diff = (item.book_value.mantissa - mean).unsigned_abs();
            sq_sum = sq_sum.saturating_add(diff.saturating_mul(diff));
        }
        let variance = sq_sum / (nh as u128);
        let sigma = (variance.isqrt() as i128).max(1);
        stratum_stats.push((name.clone(), nh, sigma));
    }

    let allocate_by_weights = |weights: &[i128]| -> Vec<usize> {
        let mut alloc = vec![1usize; h_count];
        let remaining = total_sample_size - h_count;
        let weight_sum: i128 = weights.iter().sum();
        if remaining > 0 && weight_sum > 0 {
            let mut quotas: Vec<(usize, i128)> = Vec::with_capacity(h_count);
            for (i, &w) in weights.iter().enumerate() {
                let cap = stratum_stats[i].1 - alloc[i];
                let exact_num = (remaining as i128) * w;
                let add = ((exact_num / weight_sum) as usize).min(cap);
                alloc[i] += add;
                let rem = exact_num % weight_sum;
                quotas.push((i, rem));
            }
            let used: usize = alloc.iter().sum();
            let mut left = total_sample_size.saturating_sub(used);
            quotas.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            for &(i, _) in &quotas {
                if left == 0 {
                    break;
                }
                if alloc[i] < stratum_stats[i].1 {
                    alloc[i] += 1;
                    left -= 1;
                }
            }
            for (i, stat) in stratum_stats.iter().enumerate() {
                while left > 0 && alloc[i] < stat.1 {
                    alloc[i] += 1;
                    left -= 1;
                }
            }
        }
        alloc
    };

    let neyman_weights: Vec<i128> = stratum_stats
        .iter()
        .map(|(_, nh, sigma)| (*nh as i128) * *sigma)
        .collect();
    let prop_weights: Vec<i128> = stratum_stats.iter().map(|(_, nh, _)| *nh as i128).collect();

    let neyman_alloc = allocate_by_weights(&neyman_weights);
    let prop_alloc = allocate_by_weights(&prop_weights);

    let candidates = vec![
        DecisionCandidate {
            action: "monetary_unit_fixed_strata".into(),
            parameter: 4,
            analytic_score: 50,
        },
        DecisionCandidate {
            action: "neyman_optimal_strata".into(),
            parameter: h_count as i128,
            analytic_score: 150,
        },
    ];
    let features: Vec<DecisionFeature> = stratum_stats
        .iter()
        .map(|(name, _, sigma)| DecisionFeature {
            name: format!("sigma_{name}"),
            value: *sigma,
            advisory: false,
        })
        .collect();

    let decision_card = evaluate_decision(
        policy_epoch,
        enforced_policy_epoch,
        DecisionKind::SamplingStratification,
        population.population_digest.to_vec(),
        candidates,
        features,
        BenefitInterval {
            lower_bps: 150,
            upper_bps: 650,
        },
    );

    let chosen_alloc = if decision_card.used_fallback() {
        &prop_alloc
    } else {
        &neyman_alloc
    };

    let mut prng = Pcg64Dxsm::new(seed);
    let mut strata_out = Vec::with_capacity(h_count);
    let mut selected = Vec::new();

    for ((name, nh, sigma), &nh_sample) in stratum_stats.into_iter().zip(chosen_alloc.iter()) {
        let items = &by_stratum[&name];
        let mut idx_pool: Vec<usize> = (0..nh).collect();
        for i in 0..nh_sample {
            let offset = prng.next_bounded_u128((nh - i) as u128) as usize;
            idx_pool.swap(i, i + offset);
        }
        let mut picked = idx_pool[..nh_sample].to_vec();
        picked.sort_unstable();
        for idx in picked {
            selected.push(items[idx].clone());
        }
        strata_out.push(StratumAllocation {
            stratum: name,
            population_count: nh,
            std_dev_mantissa: sigma,
            allocated_sample_size: nh_sample,
        });
    }

    let selected_ids: Vec<String> = selected.iter().map(|s| s.item_id.clone()).collect();
    let certificate = SampleCertificate::compute(
        "stratified_neyman",
        population.population_digest,
        seed,
        &format!("total_sample_size={total_sample_size}"),
        selected_ids,
    );

    Ok(StratifiedSamplePlan {
        population_digest: population.population_digest,
        seed,
        total_sample_size,
        strata: strata_out,
        selected,
        decision_card,
        certificate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_money::rate::BigInt;
    use fa_reference::lantern::{naive_sample_mus, naive_stringer_bound_mantissa};

    fn fixture_population() -> SamplePopulation {
        let usd = UnitId(1);
        let items = vec![
            PopulationItem {
                item_id: "AR-001".into(),
                reference_vid: VId(1),
                stratum: Some("small".into()),
                book_value: Amount::new(usd, 12_000),
            },
            PopulationItem {
                item_id: "AR-002".into(),
                reference_vid: VId(2),
                stratum: Some("small".into()),
                book_value: Amount::new(usd, 18_000),
            },
            PopulationItem {
                item_id: "AR-003".into(),
                reference_vid: VId(3),
                stratum: Some("small".into()),
                book_value: Amount::new(usd, 25_000),
            },
            PopulationItem {
                item_id: "AR-004".into(),
                reference_vid: VId(4),
                stratum: Some("large".into()),
                book_value: Amount::new(usd, 45_000),
            },
            PopulationItem {
                item_id: "AR-005".into(),
                reference_vid: VId(5),
                stratum: Some("large".into()),
                book_value: Amount::new(usd, 60_000),
            },
            PopulationItem {
                item_id: "AR-006".into(),
                reference_vid: VId(6),
                stratum: Some("large".into()),
                book_value: Amount::new(usd, 30_000),
            },
        ];
        SamplePopulation::new("ar-open", usd, items).unwrap()
    }

    #[test]
    fn mus_sample_is_bit_reproducible_and_matches_reference_oracle() {
        let pop = fixture_population();
        let usd = UnitId(1);
        let interval = Amount::new(usd, 50_000);
        let s1 = sample_mus(&pop, 20_260_115, interval).unwrap();
        let s2 = sample_mus(&pop, 20_260_115, interval).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(
            s1.certificate.certificate_oid,
            s2.certificate.certificate_oid
        );
        assert_eq!(s1.top_stratum_count, 1);

        let raw_items: Vec<(String, i128)> = pop
            .items
            .iter()
            .map(|i| (i.item_id.clone(), i.book_value.mantissa))
            .collect();
        let oracle_ids = naive_sample_mus(&raw_items, s1.start_dollar_mantissa, 50_000);
        let actual_ids: Vec<String> = s1.selected.iter().map(|i| i.item_id.clone()).collect();
        assert_eq!(actual_ids, oracle_ids);
    }

    #[test]
    fn stringer_bound_matches_textbook_example_and_reference_oracle() {
        let usd = UnitId(1);
        let interval = Amount::new(usd, 1_000_000);
        let audited = vec![
            AuditedSampleItem {
                item_id: "INV-2".into(),
                book_value: Amount::new(usd, 200_000),
                audited_value: Amount::new(usd, 180_000),
            },
            AuditedSampleItem {
                item_id: "INV-1".into(),
                book_value: Amount::new(usd, 500_000),
                audited_value: Amount::new(usd, 400_000),
            },
        ];
        let eval = evaluate_stringer_bound(interval, 9_500, &audited).unwrap();
        assert_eq!(eval.basic_precision.mantissa, 3_000_000);
        assert_eq!(eval.most_likely_error.mantissa, 300_000);
        assert_eq!(eval.incremental_allowance.mantissa, 205_000);
        assert_eq!(eval.upper_misstatement_limit.mantissa, 3_505_000);

        let oracle_uml = naive_stringer_bound_mantissa(
            1_000_000,
            9_500,
            &[(200_000, 180_000), (500_000, 400_000)],
        );
        assert_eq!(eval.upper_misstatement_limit.mantissa, oracle_uml);
    }

    #[test]
    fn uniform_and_stratified_neyman_samples_are_reproducible_and_emit_decision_cards() {
        let pop = fixture_population();
        let u1 = sample_uniform(&pop, 42, 3).unwrap();
        let u2 = sample_uniform(&pop, 42, 3).unwrap();
        assert_eq!(u1, u2);
        assert_eq!(u1.selected.len(), 3);

        let epoch = [0x55; 32];
        let strat = sample_stratified_neyman(&pop, 42, 4, Some(epoch), epoch, VId(99)).unwrap();
        assert_eq!(strat.selected.len(), 4);
        assert_eq!(
            strat.decision_card.verify_replay(epoch).unwrap(),
            strat.decision_card.digest().unwrap()
        );
    }

    #[test]
    fn numpy_seed_sequence_and_pcg64dxsm_vectors_are_bit_exact() {
        assert_eq!(
            SeedSequence::from_seed(0).generate_state(8),
            [
                0xb0f4_78be,
                0xdb2c_d7e7,
                0x2c71_ba49,
                0xabf4_641a,
                0x9d7b_8d41,
                0x20c6_ed6d,
                0x223c_39d4,
                0x2c40_99de,
            ]
        );
        assert_eq!(
            SeedSequence::from_seed(42).generate_state(8),
            [
                0xcd54_0ab7,
                0x9f1e_2e6d,
                0x79fb_94b6,
                0xd578_73dc,
                0x64d4_20b7,
                0x7d28_2a1b,
                0x4692_d5ff,
                0x3365_7971,
            ]
        );
        let mut generator = Pcg64Dxsm::from_seed(42);
        let actual: Vec<u64> = (0..8).map(|_| generator.next_u64()).collect();
        assert_eq!(
            actual,
            [
                0xab1c_5033_8e63_481d,
                0x01bd_f91d_548d_1872,
                0xa872_905d_0418_d0a1,
                0x5f0a_8427_0b80_eabc,
                0x34e8_2505_4db5_f685,
                0x319f_f93c_b20c_b433,
                0xc24f_b90e_b5d6_26af,
                0xf1c7_6bf8_e2e9_99a6,
            ]
        );

        let mut jumped = Pcg64Dxsm::from_seed(42);
        jumped.advance(8);
        assert_eq!(jumped.raw_state(), generator.raw_state());
        assert_eq!(jumped.next_u64(), generator.next_u64());

        let (state, increment) = generator.split_state();
        let mut restored = Pcg64Dxsm::from_split_state(state, increment);
        assert_eq!(generator.next_u64(), restored.next_u64());
        assert_eq!(generator.raw_state(), restored.raw_state());

        let left = SeedSequence::with_spawn_key(7, &[1, 2, 3]).generate_state(16);
        let repeated = SeedSequence::with_spawn_key(7, &[1, 2, 3]).generate_state(16);
        let reordered = SeedSequence::with_spawn_key(7, &[3, 2, 1]).generate_state(16);
        assert_eq!(left, repeated);
        assert_ne!(left, reordered);
        assert_eq!(
            SeedSequence::from_entropy_words(&[], &[]),
            SeedSequence::from_seed(0)
        );
    }

    #[test]
    fn sample_reproducibility_vectors_match_numpy_pcg64dxsm_snippet() {
        let pop = fixture_population();
        let usd = UnitId(1);
        // Pinned against `np.random.PCG64DXSM(20260115)` with 128-bit Lemire rejection:
        let mus = sample_mus(&pop, 20_260_115, Amount::new(usd, 50_000)).unwrap();
        assert_eq!(mus.start_dollar_mantissa, 25_653);
        let mus_indices: Vec<usize> = mus.selected.iter().map(|s| s.population_index).collect();
        assert_eq!(mus_indices, vec![1, 3, 4, 5]);
        assert_eq!(
            mus.certificate.selected_item_ids,
            vec!["AR-002", "AR-004", "AR-005", "AR-006"]
        );

        // Pinned against `np.random.PCG64DXSM(42)` partial Fisher-Yates (indices [0, 4, 5]):
        let uni = sample_uniform(&pop, 42, 3).unwrap();
        assert_eq!(
            uni.certificate.selected_item_ids,
            vec!["AR-001", "AR-005", "AR-006"]
        );
    }

    fn big(value: u128) -> BigInt {
        BigInt::from_bytes_le(&value.to_le_bytes())
    }

    /// `(D * S_k(x), D * E_N(x))` for `x = a / 10^4`, where `S_k(x) =
    /// sum_{j<=k} x^j / j!`, `E_N(x) = sum_{j<=N} x^j / j!` and `D =
    /// 10^(4N) * N!`, so every term `D * x^j / j! = a^j * 10^(4(N-j)) *
    /// N!/j!` is an integer.
    fn scaled_poisson_sums(a: u128, k: usize, n: usize) -> (BigInt, BigInt) {
        let mut falling = vec![big(1); n + 1];
        for j in (1..=n).rev() {
            falling[j - 1] = &falling[j] * &big(j as u128);
        }
        let mut tens = vec![big(1); n + 1];
        for i in 1..=n {
            tens[i] = &tens[i - 1] * &big(10_000);
        }
        let (mut partial, mut total, mut power) = (big(0), big(0), big(1));
        for j in 0..=n {
            let term = &(&power * &tens[n - j]) * &falling[j];
            if j <= k {
                partial = partial + &term;
            }
            total = total + &term;
            power = &power * &big(a);
        }
        (partial, total)
    }

    /// Every registered Poisson factor is its exact one-sided upper limit
    /// rounded up to 0.01, proved in integers. P(X <= k; x) = S_k(x) e^-x,
    /// and E_N(x) <= e^x <= E_N(x) + T_N(x) with the tail bound T_N(x) =
    /// x^(N+1) / (N+1)! * (N+2) / (N+2-x) for N + 2 > x. With 1 - c = 1/d:
    /// - d * S_k(R) <= E_N(R) proves P(X <= k; R) <= 1 - c: R is at or above
    ///   the limit, so the bound is conservative;
    /// - d * S_k(R - 0.01) > E_N + T_N there proves P > 1 - c: R - 0.01 is
    ///   below the limit, so R is exactly the limit rounded up to 0.01.
    #[test]
    fn poisson_factors_are_the_upper_limits_rounded_up_to_a_hundredth() {
        for (confidence, d) in [(9_000u32, 10u128), (9_500, 20), (9_900, 100)] {
            for k in 0..=MAX_TABLED_MISSTATEMENTS {
                let r = poisson_upper_factor_bps(confidence, k).unwrap();
                let n = usize::try_from(4 * r / 10_000).unwrap() + 40;
                let (partial, total) = scaled_poisson_sums(r, k, n);
                assert!(
                    &partial * &big(d) <= total,
                    "{confidence} k={k}: R={r} is below the exact limit"
                );
                let mu = r - 100;
                let (partial, total) = scaled_poisson_sums(mu, k, n);
                let n = n as u128;
                // D * T_N(mu) = mu^(N+1) * (N+2) / ((N+1) * (10^4 (N+2) - mu)).
                let tail_num = big(mu).pow(u32::try_from(n + 1).unwrap()) * big(n + 2);
                let tail_den = big(n + 1) * big(10_000 * (n + 2) - mu);
                assert!(
                    &(&partial * &big(d)) * &tail_den > &total * &tail_den + &tail_num,
                    "{confidence} k={k}: R - 0.01 = {mu} is not below the exact limit"
                );
            }
            assert!(
                matches!(
                    poisson_upper_factor_bps(confidence, MAX_TABLED_MISSTATEMENTS + 1),
                    Err(LanternError::Parameter { ref name, .. }) if name == "misstatements"
                ),
                "beyond the table the factor is refused, never extrapolated"
            );
        }
    }

    /// The planned interval is (TM - EM x EF) / R(0), rounded down: the
    /// AICPA guide's 50,000.00 tolerable, 5,000.00 expected at 95% plans
    /// (50,000 - 8,000) / 3.00 = 14,000.00; at 90%, 42,500 / 2.31 rounds
    /// down to 18,398.26; at 99%, 40,500 / 4.61 to 8,785.24.
    #[test]
    fn mus_interval_is_planned_from_tolerable_and_expected_misstatement() {
        let usd = UnitId(1);
        let tm = Amount::new(usd, 5_000_000);
        let em = Amount::new(usd, 500_000);
        for (confidence, interval) in [(9_500, 1_400_000), (9_000, 1_839_826), (9_900, 878_524)] {
            assert_eq!(
                mus_interval(tm, em, confidence).unwrap(),
                Amount::new(usd, interval),
                "{confidence}"
            );
        }
        // Expecting no misstatement plans the reliability factor alone.
        assert_eq!(
            mus_interval(tm, Amount::new(usd, 0), 9_500).unwrap(),
            Amount::new(usd, 1_666_666)
        );
        let refused = |result: Result<Amount, LanternError>, field: &str| {
            assert!(
                matches!(&result, Err(LanternError::Parameter { name, .. }) if name == field),
                "{field}: {result:?}"
            );
        };
        // EM x EF reaching TM leaves nothing to plan for.
        refused(
            mus_interval(tm, Amount::new(usd, 3_125_000), 9_500),
            "expected",
        );
        refused(
            mus_interval(tm, Amount::new(UnitId(2), 0), 9_500),
            "expected",
        );
        refused(
            mus_interval(Amount::new(usd, 0), Amount::new(usd, 0), 9_500),
            "tolerable",
        );
        refused(mus_interval(tm, Amount::new(usd, -1), 9_500), "tolerable");
        refused(mus_interval(tm, em, 8_000), "confidence_level_bps");
    }

    /// A sample with more misstatements than the factor table covers is
    /// refused; one at the table's end is evaluated.
    #[test]
    fn stringer_bound_is_refused_beyond_the_factor_table() {
        let usd = UnitId(1);
        let tainted = |count: usize| -> Vec<AuditedSampleItem> {
            (0..count)
                .map(|i| AuditedSampleItem {
                    item_id: format!("AR-{i:03}"),
                    book_value: Amount::new(usd, 10_000),
                    audited_value: Amount::new(usd, 9_000),
                })
                .collect()
        };
        let interval = Amount::new(usd, 100_000);
        for confidence in [9_000, 9_500, 9_900] {
            let at_end = evaluate_stringer_bound(interval, confidence, &tainted(40)).unwrap();
            assert_eq!(at_end.misstatement_count, 40);
            assert!(matches!(
                evaluate_stringer_bound(interval, confidence, &tainted(41)),
                Err(LanternError::Parameter { ref name, .. }) if name == "misstatements"
            ));
        }
    }
}
