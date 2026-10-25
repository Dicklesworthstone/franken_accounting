//! A dudect-style timing harness for the interim signer (bead fa-cs80;
//! Reparaz, Balasch and Verbauwhede, "Dude, is my code constant time?",
//! DATE 2017).
//!
//! Every measurement times one call on an input of one of two classes,
//! chosen per measurement by a seeded generator: a fixed input (zero, the
//! scalar whose every digit selects the identity) or a fresh random one.
//! Welch's t-test compares the two timing distributions, uncropped and
//! cropped below a ladder of upper percentiles taken from a discarded
//! calibration batch (dudect's defence against preemption tails), and the
//! verdict is the largest |t|. Running time that depends on the input
//! separates the classes, and |t| grows with the square root of the
//! measurement count; constant-time code keeps it small.
//!
//! The statistics are exact integers: the moments are integer sums of the
//! nanosecond timings, t is carried as its exact square, and the crop
//! percentiles are exact. fa-notary is an amount crate, where no float token
//! appears (scripts/doctrine_check.sh), and exact arithmetic makes every t a
//! campaign prints reproducible from its timings bit for bit.
//!
//! [`branchy_variant_detected`] plants a leak, a scalar multiplication
//! that skips the addition for a zero digit, and requires the harness to
//! flag it. [`signer_timing_tier2`] (ignored; release profile) measures the
//! shipped kernels and `sign` at 10^6 measurements each, printing t per
//! batch and the host fingerprint, with the planted leak as its power
//! control. A pass is `statistical` evidence about one build on one host,
//! never `invariant`.

use std::fmt;
use std::hint::black_box;
use std::time::Instant;

use fa_money::rate::BigInt;

use crate::SigningKey;
use crate::sign::ed25519::ct_targets;

/// dudect's "probably not constant time" bound, the bead's threshold:
/// |t| > 9/2, compared exactly as t² > 81/4.
const T_THRESHOLD: (u64, u64) = (9, 2);

/// Cropped tests beside the uncropped one.
const CROPS: usize = 20;
// The crop ladder's exponents 10(i+1)/CROPS are the half-integers (i+1)/2.
const _: () = assert!(CROPS == 20);

/// Measurements dropped at the head of every batch (cold caches).
const DISCARD: usize = 10;

/// SplitMix64: the class coins and the random inputs, replayable by seed.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes()[..chunk.len()]);
        }
        out
    }
}

/// Welch's t as its exact square `num / den` and the sign of the
/// difference. `den` is zero only for an infinite t (a difference with no
/// variance at all), when `num` is positive.
#[derive(Clone)]
struct T {
    negative: bool,
    num: BigInt,
    den: BigInt,
}

impl T {
    fn zero() -> Self {
        Self {
            negative: false,
            num: BigInt::zero(),
            den: BigInt::one(),
        }
    }

    /// |t|.
    fn magnitude(self) -> Self {
        Self {
            negative: false,
            ..self
        }
    }

    /// |self| > |other|, exactly: num·den' > num'·den. An infinite t is
    /// above every finite one and not above another infinite one.
    fn exceeds(&self, other: &Self) -> bool {
        &self.num * &other.den > &other.num * &self.den
    }

    /// |t| > p/q, exactly: num·q² > p²·den.
    fn above(&self, (p, q): (u64, u64)) -> bool {
        &self.num * BigInt::from(q * q) > BigInt::from(p * p) * &self.den
    }
}

/// t to three decimals, truncated: ⌊1000·|t|⌋ = ⌊√⌊10⁶·t²⌋⌋.
impl fmt::Display for T {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sign = if self.negative { "-" } else { "" };
        if self.den.is_zero() {
            return write!(f, "{sign}inf");
        }
        let milli = (&self.num * BigInt::from(1_000_000u64) / &self.den)
            .sqrt()
            .and_then(|m| u64::try_from(&m).ok())
            .ok_or(fmt::Error)?;
        write!(f, "{sign}{}.{:03}", milli / 1000, milli % 1000)
    }
}

/// The running sums of the two classes (0 fixed, 1 random): count, sum and
/// sum of squares of the timings in nanoseconds.
#[derive(Clone, Copy, Default)]
struct Welch {
    n: [u64; 2],
    sum: [u128; 2],
    sum_sq: [u128; 2],
}

impl Welch {
    fn push(&mut self, class: usize, x: u64) {
        let x = u128::from(x);
        self.n[class] += 1;
        self.sum[class] = self.sum[class]
            .checked_add(x)
            .expect("timing sum fits u128");
        // x < 2^64, so x² < 2^128.
        self.sum_sq[class] = self.sum_sq[class]
            .checked_add(x * x)
            .expect("timing sum of squares fits u128");
    }

    fn min_n(&self) -> u64 {
        self.n[0].min(self.n[1])
    }

    /// Welch's t of fixed minus random, exactly; zero until each class has
    /// two measurements. With Sc, Qc and nc a class's sum, sum of squares
    /// and count, D = S0·n1 − S1·n0 is n0·n1 times the difference of the
    /// means, and Vc = nc·Qc − Sc² is nc²(nc−1) times the squared standard
    /// error of class c's mean, so
    /// t² = D²(n0−1)(n1−1) / (V0·n1²(n1−1) + V1·n0²(n0−1)).
    fn t(&self) -> T {
        if self.min_n() < 2 {
            return T::zero();
        }
        let big = |v: u128| BigInt::from_bytes_le(&v.to_le_bytes());
        let one = BigInt::one();
        let n = self.n.map(|c| big(u128::from(c)));
        let s = self.sum.map(big);
        let q = self.sum_sq.map(big);
        let d = &s[0] * &n[1] - &s[1] * &n[0];
        let v = |c: usize| &n[c] * &q[c] - &s[c] * &s[c];
        let num = &d * &d * (&n[0] - &one) * (&n[1] - &one);
        let den = v(0) * &n[1] * &n[1] * (&n[1] - &one) + v(1) * &n[0] * &n[0] * (&n[0] - &one);
        if num.is_zero() {
            return T::zero();
        }
        T {
            negative: d.is_negative(),
            num,
            den,
        }
    }
}

/// ⌊last·(1 − 2^(−e/2))⌋ = last − ⌈last / 2^(e/2)⌉, exactly. For odd
/// e = 2m+1 the ceiling is the least c with 2·4^m·c² ≥ last².
fn crop_index(last: usize, e: u32) -> usize {
    let last = last as u128;
    let m = e / 2;
    let c = if e.is_multiple_of(2) {
        last.div_ceil(1 << m)
    } else {
        let scale = 2u128 << (2 * m);
        let target = last * last;
        let mut c = (target / scale).isqrt();
        while scale * c * c < target {
            c += 1;
        }
        c
    };
    usize::try_from(last - c).expect("an index below last")
}

/// The uncropped test (index 0) and one test per percentile crop.
struct Campaign {
    cutoffs: [u64; CROPS],
    tests: [Welch; CROPS + 1],
}

impl Campaign {
    /// dudect's crop ladder, percentiles `1 − 0.5^(10(i+1)/CROPS)` of a
    /// calibration batch: the order statistic at `crop_index`.
    fn calibrated(mut samples: Vec<u64>) -> Self {
        samples.sort_unstable();
        let last = samples.len() - 1;
        let cutoffs = std::array::from_fn(|i| {
            let e = u32::try_from(i + 1).expect("CROPS fits u32");
            samples[crop_index(last, e)]
        });
        Self {
            cutoffs,
            tests: [Welch::default(); CROPS + 1],
        }
    }

    fn push(&mut self, class: usize, dt: u64) {
        self.tests[0].push(class, dt);
        for (test, cutoff) in self.tests[1..].iter_mut().zip(self.cutoffs) {
            if dt < cutoff {
                test.push(class, dt);
            }
        }
    }

    /// The largest |t| among the tests holding at least `min` measurements
    /// of each class, and which test it is.
    fn verdict(&self, min: u64) -> (T, usize) {
        let mut best = (T::zero(), 0);
        for (i, w) in self.tests.iter().enumerate() {
            if w.min_n() < min {
                continue;
            }
            let t = w.t().magnitude();
            if t.exceeds(&best.0) {
                best = (t, i);
            }
        }
        best
    }
}

/// What one campaign measured.
struct Report {
    measurements: u64,
    max_t: T,
    test: usize,
}

/// Times `call` over `batches` batches of `batch_len` inputs, after one
/// calibration batch that is discarded. Each input is of the fixed class
/// or a fresh random one by a coin from `rng`; inputs are built before the
/// batch is timed, so only `call` is measured. With `log`, the verdict so
/// far is printed after every batch.
#[allow(clippy::too_many_arguments)]
fn campaign<I, O>(
    name: &str,
    rng: &mut SplitMix,
    batches: usize,
    batch_len: usize,
    min: u64,
    log: bool,
    fixed: impl Fn() -> I,
    mut random: impl FnMut(&mut SplitMix) -> I,
    call: impl Fn(&I) -> O,
) -> Report {
    let mut measure = |rng: &mut SplitMix| -> Vec<(usize, u64)> {
        let classes: Vec<usize> = (0..batch_len).map(|_| (rng.next() & 1) as usize).collect();
        let inputs: Vec<I> = classes
            .iter()
            .map(|&c| if c == 0 { fixed() } else { random(rng) })
            .collect();
        let mut out = Vec::with_capacity(batch_len);
        for (class, input) in classes.into_iter().zip(&inputs) {
            let start = Instant::now();
            black_box(call(black_box(input)));
            let dt = start.elapsed().as_nanos();
            out.push((class, u64::try_from(dt).unwrap_or(u64::MAX)));
        }
        out
    };
    let calibration = measure(rng).into_iter().map(|(_, dt)| dt).collect();
    let mut campaign = Campaign::calibrated(calibration);
    let mut measurements = 0u64;
    for batch in 1..=batches {
        for (class, dt) in measure(rng).into_iter().skip(DISCARD) {
            campaign.push(class, dt);
            measurements += 1;
        }
        if log {
            let (t, test) = campaign.verdict(min);
            println!(
                "ct_harness target={name} batch={batch} measurements={measurements} \
                 max_abs_t={t} test={test} uncropped_t={}",
                campaign.tests[0].t()
            );
        }
    }
    let (max_t, test) = campaign.verdict(min);
    Report {
        measurements,
        max_t,
        test,
    }
}

/// Which machine and build produced a timing artifact.
fn host_fingerprint() -> String {
    let read = |path: &str| {
        std::fs::read_to_string(path).map_or_else(
            |e| format!("unreadable({:?})", e.kind()),
            |s| s.trim().to_owned(),
        )
    };
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|info| {
            info.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_owned())
        })
        .unwrap_or_else(|| "unknown".to_owned());
    let threads = std::thread::available_parallelism().map_or(0, std::num::NonZero::get);
    format!(
        "host={} kernel={} arch={} cpu=\"{cpu}\" threads={threads} governor={} profile={}",
        read("/proc/sys/kernel/hostname"),
        read("/proc/sys/kernel/osrelease"),
        std::env::consts::ARCH,
        read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
    )
}

#[test]
fn welch_t_matches_a_hand_computation() {
    let mut w = Welch::default();
    for x in [1, 2, 3, 4] {
        w.push(0, x);
    }
    for x in [2, 4, 6, 8] {
        w.push(1, x);
    }
    // Means 2.5 and 5, variances 5/3 and 20/3: t = −2.5 / √(25/12) = −√3,
    // so t² = 3 exactly and ⌊1000·√3⌋ = 1732.
    let t = w.t();
    assert!(t.negative);
    assert_eq!(
        t.num,
        &t.den * BigInt::from(3u64),
        "t² = {} / {}",
        t.num,
        t.den
    );
    assert_eq!(t.to_string(), "-1.732");
    assert!(t.above((17, 10)) && !t.above((18, 10)), "1.7 < √3 < 1.8");

    let mut same = Welch::default();
    for x in [3, 5, 7] {
        same.push(0, x);
        same.push(1, x);
    }
    assert_eq!(same.t().to_string(), "0.000");
    assert!(!same.t().exceeds(&T::zero()));

    let mut apart = Welch::default();
    for _ in 0..3 {
        apart.push(0, 1);
        apart.push(1, 2);
    }
    let infinite = apart.t();
    assert_eq!(infinite.to_string(), "-inf");
    assert!(infinite.exceeds(&t) && !t.exceeds(&infinite));
    assert!(!infinite.exceeds(&infinite.clone()));
    assert!(infinite.above(T_THRESHOLD));
}

/// The exact crop ladder: `crop_index` is ⌊last·(1 − 2^(−e/2))⌋, checked
/// against the bracket 2^(−e/2) ∈ (k/1000, (k+1)/1000) at every rung.
#[test]
fn crop_indices_are_exact_percentiles() {
    // ⌊1000·2^(−e/2)⌋ for e = 1..=20.
    const MILLI: [u128; 20] = [
        707, 500, 353, 250, 176, 125, 88, 62, 44, 31, 22, 15, 11, 7, 5, 3, 2, 1, 1, 0,
    ];
    for last in [1usize, 2, 999, 10_009, 1_000_000] {
        for (rung, &k) in MILLI.iter().enumerate() {
            let e = u32::try_from(rung + 1).unwrap();
            let index = crop_index(last, e);
            // last − index = ⌈last·2^(−e/2)⌉, which lies within
            // [⌈last·k/1000⌉, ⌈last·(k+1)/1000⌉].
            let gap = (last - index) as u128;
            let last = last as u128;
            assert!(
                gap >= (last * k).div_ceil(1000) && gap <= (last * (k + 1)).div_ceil(1000),
                "last {last}, e {e}: index {index}"
            );
        }
    }
    assert_eq!(crop_index(999, 1), 292, "999 − ⌈999/√2⌉ = 999 − 707");
    assert_eq!(crop_index(999, 20), 998, "999 − ⌈999/1024⌉");
}

/// The crop ladder climbs toward the calibration maximum, and a
/// preemption-sized outlier reaches only the uncropped test.
#[test]
fn crops_exclude_the_tail() {
    let mut c = Campaign::calibrated((1..=1000).collect());
    assert!(c.cutoffs.windows(2).all(|w| w[0] <= w[1]));
    assert_eq!(c.cutoffs[0], 293, "p = 1 − 0.5^0.5 of 1..=1000");
    assert_eq!(c.cutoffs[CROPS - 1], 999, "p = 1 − 0.5^10");
    c.push(0, 1_000_000);
    c.push(1, 10);
    assert_eq!(c.tests[0].n, [1, 1]);
    for test in &c.tests[1..] {
        assert_eq!(test.n, [0, 1]);
    }
}

/// The planted negative (bead fa-cs80): the harness flags a scalar
/// multiplication whose running time counts the scalar's nonzero digits.
#[test]
fn branchy_variant_detected() {
    let mut rng = SplitMix(0xfa_c580);
    let leak = campaign(
        "mul_base_skipping_zero_digits",
        &mut rng,
        4,
        512,
        100,
        false,
        || [0u8; 32],
        SplitMix::bytes::<32>,
        ct_targets::mul_base_skipping_zero_digits_x,
    );
    assert!(
        leak.max_t.above(T_THRESHOLD),
        "the planted leak went undetected: |t| = {} (test {}) over {} measurements",
        leak.max_t,
        leak.test,
        leak.measurements
    );
}

/// The positive run (bead fa-cs80), on the release profile:
/// `cargo test --release -p fa-notary ct_harness -- --ignored --nocapture`.
/// 10^6 measurements per target after calibration, t printed per batch and
/// the host fingerprint first. The planted leak runs too, as the control
/// that the harness has power on this host and build.
#[test]
#[ignore = "tier-2 timing artifact: release profile, minutes of measurement"]
fn signer_timing_tier2() -> Result<(), String> {
    if cfg!(debug_assertions) {
        return Err("the timing artifact measures release codegen: run \
             `cargo test --release -p fa-notary ct_harness -- --ignored --nocapture`"
            .into());
    }
    const BATCHES: usize = 100;
    const LEN: usize = 10_000 + DISCARD;
    const MIN: u64 = 10_000;
    println!("ct_harness {}", host_fingerprint());
    let mut rng = SplitMix(0xfa_c580_7172);
    let message = b"fa-cs80: one fixed message for both classes";
    let reports = [
        (
            "mul_base",
            campaign(
                "mul_base",
                &mut rng,
                BATCHES,
                LEN,
                MIN,
                true,
                || [0u8; 32],
                SplitMix::bytes::<32>,
                ct_targets::mul_base_x,
            ),
        ),
        (
            "reduce_512",
            campaign(
                "reduce_512",
                &mut rng,
                BATCHES,
                LEN,
                MIN,
                true,
                || [0u8; 64],
                SplitMix::bytes::<64>,
                ct_targets::reduce,
            ),
        ),
        (
            "sign",
            campaign(
                "sign",
                &mut rng,
                BATCHES,
                LEN,
                MIN,
                true,
                || SigningKey::from_seed(&[0; 32]),
                |r| SigningKey::from_seed(&r.bytes::<32>()),
                |key| key.sign(message),
            ),
        ),
    ];
    let leak = campaign(
        "mul_base_skipping_zero_digits",
        &mut rng,
        10,
        LEN,
        MIN,
        true,
        || [0u8; 32],
        SplitMix::bytes::<32>,
        ct_targets::mul_base_skipping_zero_digits_x,
    );
    let (p, q) = T_THRESHOLD;
    let verdict = |name: &str, r: &Report| {
        println!(
            "ct_harness verdict target={name} measurements={} max_abs_t={} test={} \
             threshold={p}/{q}",
            r.measurements, r.max_t, r.test
        );
    };
    for (name, r) in &reports {
        verdict(name, r);
    }
    verdict("planted_leak", &leak);
    assert!(
        leak.max_t.above(T_THRESHOLD),
        "the planted leak went undetected (|t| = {}): the harness has no power here",
        leak.max_t
    );
    for (name, r) in &reports {
        assert!(
            !r.max_t.above(T_THRESHOLD),
            "{name}: |t| = {} (test {}) over {} measurements exceeds {p}/{q}",
            r.max_t,
            r.test,
            r.measurements
        );
    }
    Ok(())
}
