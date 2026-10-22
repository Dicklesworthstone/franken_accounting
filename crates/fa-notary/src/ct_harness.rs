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
//! [`branchy_variant_detected`] plants a leak, a scalar multiplication
//! that skips the addition for a zero digit, and requires the harness to
//! flag it. [`signer_timing_tier2`] (ignored; release profile) measures the
//! shipped kernels and `sign` at 10^6 measurements each, printing t per
//! batch and the host fingerprint, with the planted leak as its power
//! control. A pass is `statistical` evidence about one build on one host,
//! never `invariant`.

use std::hint::black_box;
use std::time::Instant;

use crate::SigningKey;
use crate::sign::ed25519::ct_targets;

/// dudect's "probably not constant time" bound, the bead's threshold.
const T_THRESHOLD: f64 = 4.5;

/// Cropped tests beside the uncropped one.
const CROPS: usize = 20;

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

/// Welford's running moments of the two classes (0 fixed, 1 random).
#[derive(Clone, Copy, Default)]
struct Welch {
    n: [f64; 2],
    mean: [f64; 2],
    m2: [f64; 2],
}

impl Welch {
    fn push(&mut self, class: usize, x: f64) {
        self.n[class] += 1.0;
        let delta = x - self.mean[class];
        self.mean[class] += delta / self.n[class];
        self.m2[class] += delta * (x - self.mean[class]);
    }

    fn min_n(&self) -> f64 {
        self.n[0].min(self.n[1])
    }

    /// Welch's t of fixed minus random; zero until each class has two
    /// measurements, infinite for a difference with no variance at all.
    fn t(&self) -> f64 {
        if self.min_n() < 2.0 {
            return 0.0;
        }
        let var = |c: usize| self.m2[c] / (self.n[c] - 1.0);
        let se = (var(0) / self.n[0] + var(1) / self.n[1]).sqrt();
        let diff = self.mean[0] - self.mean[1];
        if se > 0.0 {
            diff / se
        } else if diff == 0.0 {
            0.0
        } else {
            diff.signum() * f64::INFINITY
        }
    }
}

/// The uncropped test (index 0) and one test per percentile crop.
struct Campaign {
    cutoffs: [u64; CROPS],
    tests: [Welch; CROPS + 1],
}

impl Campaign {
    /// dudect's crop ladder, percentiles `1 − 0.5^(10(i+1)/CROPS)` of a
    /// calibration batch.
    fn calibrated(mut samples: Vec<u64>) -> Self {
        samples.sort_unstable();
        let last = samples.len() - 1;
        let cutoffs = std::array::from_fn(|i| {
            let p = 1.0 - 0.5f64.powf(10.0 * (i + 1) as f64 / CROPS as f64);
            samples[((p * last as f64) as usize).min(last)]
        });
        Self {
            cutoffs,
            tests: [Welch::default(); CROPS + 1],
        }
    }

    fn push(&mut self, class: usize, dt: u64) {
        let x = dt as f64;
        self.tests[0].push(class, x);
        for (test, cutoff) in self.tests[1..].iter_mut().zip(self.cutoffs) {
            if dt < cutoff {
                test.push(class, x);
            }
        }
    }

    /// The largest |t| among the tests holding at least `min` measurements
    /// of each class, and which test it is.
    fn verdict(&self, min: f64) -> (f64, usize) {
        self.tests
            .iter()
            .enumerate()
            .filter(|(_, w)| w.min_n() >= min)
            .map(|(i, w)| (w.t().abs(), i))
            .fold((0.0, 0), |best, x| if x.0 > best.0 { x } else { best })
    }
}

/// What one campaign measured.
struct Report {
    measurements: u64,
    max_t: f64,
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
    min: f64,
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
                 max_abs_t={t:.3} test={test} uncropped_t={:.3}",
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
    for x in [1.0, 2.0, 3.0, 4.0] {
        w.push(0, x);
    }
    for x in [2.0, 4.0, 6.0, 8.0] {
        w.push(1, x);
    }
    // Means 2.5 and 5, variances 5/3 and 20/3: t = −2.5 / √(25/12) = −√3.
    assert!((w.t() + 3f64.sqrt()).abs() < 1e-12, "t = {}", w.t());

    let mut same = Welch::default();
    for x in [3.0, 5.0, 7.0] {
        same.push(0, x);
        same.push(1, x);
    }
    assert_eq!(same.t(), 0.0);

    let mut apart = Welch::default();
    for _ in 0..3 {
        apart.push(0, 1.0);
        apart.push(1, 2.0);
    }
    assert_eq!(apart.t(), f64::NEG_INFINITY);
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
    assert_eq!(c.tests[0].n, [1.0, 1.0]);
    for test in &c.tests[1..] {
        assert_eq!(test.n, [0.0, 1.0]);
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
        100.0,
        false,
        || [0u8; 32],
        SplitMix::bytes::<32>,
        ct_targets::mul_base_skipping_zero_digits_x,
    );
    assert!(
        leak.max_t > T_THRESHOLD,
        "the planted leak went undetected: |t| = {:.3} (test {}) over {} measurements",
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
    const MIN: f64 = 10_000.0;
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
    let verdict = |name: &str, r: &Report| {
        println!(
            "ct_harness verdict target={name} measurements={} max_abs_t={:.3} test={} \
             threshold={T_THRESHOLD}",
            r.measurements, r.max_t, r.test
        );
    };
    for (name, r) in &reports {
        verdict(name, r);
    }
    verdict("planted_leak", &leak);
    assert!(
        leak.max_t > T_THRESHOLD,
        "the planted leak went undetected (|t| = {:.3}): the harness has no power here",
        leak.max_t
    );
    for (name, r) in &reports {
        assert!(
            r.max_t < T_THRESHOLD,
            "{name}: |t| = {:.3} (test {}) over {} measurements exceeds {T_THRESHOLD}",
            r.max_t,
            r.test,
            r.measurements
        );
    }
    Ok(())
}
