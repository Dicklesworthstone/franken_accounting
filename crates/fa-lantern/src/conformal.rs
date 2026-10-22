//! Split-conformal false-positive calibration, exact integer Wilson confidence
//! intervals, and threshold decision cards for Lantern detectors
//! (plan §11.9 claim typing, G3 measured precision/recall; bead `fa-dh9g`).
//!
//! Constitutional guarantees:
//! - `#![forbid(unsafe_code)]`
//! - No floating-point types or operations anywhere (`f32`/`f64` forbidden).
//! - Every statistical bound (conformal quantile index, empirical FPR, precision,
//!   recall, and 95% Wilson confidence intervals) is computed in exact integer
//!   arithmetic (`i128` / `u128` / `u128::isqrt`).
//! - Every detector threshold decision emits a replayable [`fa_policy::DecisionCard`]
//!   (`DecisionKind::LanternThreshold`) with claim class [`Claim::Statistical`]
//!   and a conservative deterministic pinned fallback.

use fa_policy::{
    BenefitInterval, DecisionCandidate, DecisionCard, DecisionFeature, DecisionKind,
    evaluate_decision,
};
use fa_registry::procedures::Claim;
use fgdb_crypto::Hasher;
use fgdb_types::VId;

use fa_money::wide::U256;

use crate::{LanternError, Params};

/// Scale for basis-point probabilities and intervals (`10_000 == 100.00%`).
pub const BPS_SCALE: i128 = 10_000;

/// Finite-sample split-conformal calibration result over clean nonconformity scores.
///
/// Under exchangeability of calibration scores $S_1, \dots, S_n$ and a fresh clean
/// test item $S_{n+1}$, the split-conformal quantile $\hat{q}_{1-\alpha} = S_{(k)}$
/// at order statistic
/// $$k = \lceil (n + 1)(1 - \alpha) \rceil$$
/// satisfies the exact finite-sample marginal false-positive guarantee:
/// $$\mathbb{P}(S_{n+1} > \hat{q}_{1-\alpha}) \le \alpha.$$
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitConformalBound {
    /// Number of clean calibration items $n$.
    pub calibration_n: usize,
    /// Target miscoverage $\alpha$ in basis points ($1 \dots 9999$, e.g. $500 = 5.00\%$).
    pub target_alpha_bps: u32,
    /// Confidence parameter $\delta$ in basis points for conditional coverage concentration.
    pub delta_bps: u32,
    /// 1-based order-statistic index $k = \lceil (n + 1)(1 - \alpha) \rceil$.
    pub quantile_rank_1based: usize,
    /// Calibrated threshold $\hat{q}_{1-\alpha}$ (or `i128::MAX` when $(n+1)(1-\alpha) > n$).
    pub calibrated_threshold: i128,
    /// Upper bound on marginal false-positive rate in basis points:
    /// $\lfloor 10000 \cdot (n + 1 - k) / (n + 1) \rfloor$.
    pub marginal_fpr_bound_bps: u32,
    /// Empirical false-positive rate on the calibration sample at `calibrated_threshold` (bps).
    pub empirical_clean_fpr_bps: u32,
}

/// Compute the exact finite-sample split-conformal quantile and false-positive
/// guarantee over `clean_scores` at target miscoverage `target_alpha_bps` ($1 \dots 9999$).
pub fn calibrate_split_conformal(
    clean_scores: &[i128],
    target_alpha_bps: u32,
    delta_bps: u32,
) -> Result<SplitConformalBound, LanternError> {
    if clean_scores.is_empty() {
        return Err(LanternError::Parameter {
            procedure: "lantern.conformal".into(),
            name: "clean_scores".into(),
            message: "calibration corpus must contain at least one clean item".into(),
        });
    }
    if target_alpha_bps == 0 || target_alpha_bps >= 10_000 {
        return Err(LanternError::Parameter {
            procedure: "lantern.conformal".into(),
            name: "target_alpha_bps".into(),
            message: "target_alpha_bps must lie in 1..=9999".into(),
        });
    }
    if delta_bps == 0 || delta_bps >= 10_000 {
        return Err(LanternError::Parameter {
            procedure: "lantern.conformal".into(),
            name: "delta_bps".into(),
            message: "delta_bps must lie in 1..=9999".into(),
        });
    }

    let mut sorted = clean_scores.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();

    let overflow = || LanternError::Overflow("conformal quantile");
    let n_plus_1 = u128::try_from(n)
        .ok()
        .and_then(|n| n.checked_add(1))
        .ok_or_else(overflow)?;
    let num = 10_000u128
        .checked_sub(u128::from(target_alpha_bps))
        .and_then(|one_minus_alpha| n_plus_1.checked_mul(one_minus_alpha))
        .ok_or_else(overflow)?;
    let k = usize::try_from(num.div_ceil(10_000)).map_err(|_| overflow())?;

    let (quantile_rank_1based, calibrated_threshold, marginal_fpr_bound_bps) = if k == 0 {
        (1, sorted[0], target_alpha_bps)
    } else if k <= n {
        let thresh = sorted[k - 1];
        let tail = n_plus_1
            .checked_sub(u128::try_from(k).map_err(|_| overflow())?)
            .ok_or_else(overflow)?;
        let bound_bps = tail
            .checked_mul(10_000)
            .and_then(|scaled| scaled.checked_div(n_plus_1))
            .and_then(|bps| u32::try_from(bps).ok())
            .ok_or_else(overflow)?;
        (k, thresh, bound_bps)
    } else {
        (n + 1, i128::MAX, 0)
    };

    let clean_flagged = sorted.iter().filter(|&&s| s > calibrated_threshold).count() as u128;
    let empirical_clean_fpr_bps = clean_flagged
        .checked_mul(10_000)
        .and_then(|scaled| scaled.checked_div(u128::try_from(n).ok()?))
        .and_then(|bps| u32::try_from(bps).ok())
        .ok_or_else(overflow)?;

    Ok(SplitConformalBound {
        calibration_n: n,
        target_alpha_bps,
        delta_bps,
        quantile_rank_1based,
        calibrated_threshold,
        marginal_fpr_bound_bps,
        empirical_clean_fpr_bps,
    })
}

/// Exact integer Wilson score 95% confidence interval (`z = 1.96 = 196/100`)
/// in basis points ($0 \dots 10_000$).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WilsonIntervalBps {
    pub successes: u64,
    pub trials: u64,
    pub point_estimate_bps: u32,
    pub lower_bps: u32,
    pub upper_bps: u32,
}

/// Compute the 95% Wilson score confidence interval (`z = 196 / 100`) in basis
/// points ($0 \dots 10_000$) using exact integer arithmetic: the products are
/// exact 256-bit values, so every pair of `u64` counts has its interval.
#[must_use]
pub fn wilson_interval_95_bps(successes: u64, trials: u64) -> WilsonIntervalBps {
    // The interval that claims nothing: never narrower than the truth.
    let vacuous = WilsonIntervalBps {
        successes,
        trials,
        point_estimate_bps: 0,
        lower_bps: 0,
        upper_bps: 10_000,
    };
    if trials == 0 {
        return WilsonIntervalBps {
            successes: 0,
            trials: 0,
            ..vacuous
        };
    }
    // With k <= n < 2^64 every intermediate is below 2^210, so each checked
    // step below succeeds; were one ever to fail, the vacuous interval is the
    // answer, never a narrower one.
    wilson_exact(successes, trials).unwrap_or(vacuous)
}

/// The Wilson interval of `successes` out of `trials > 0`, every product in
/// exact 256-bit arithmetic (fa-4aym: the u128 form overflowed, and so
/// panicked, beyond about 3 * 10^11 trials).
fn wilson_exact(successes: u64, trials: u64) -> Option<WilsonIntervalBps> {
    let k = u128::from(successes.min(trials));
    let n = u128::from(trials);
    let quotient = |num: U256, den: U256| -> Option<u128> { num.checked_div_rem(den)?.0.to_u128() };
    let point = quotient(U256::from_product(k, 10_000), U256::from_u128(n))?;
    // denom = n (10_000 n + 38_416)
    let denom = U256::from_product(n, n.checked_mul(10_000)?.checked_add(38_416)?);
    // center = 10_000 n (10_000 k + 19_208)
    let center = U256::from_product(
        n.checked_mul(10_000)?,
        k.checked_mul(10_000)?.checked_add(19_208)?,
    );
    // radicand = n (40_000 k (n - k) + 38_416 n)
    let radicand = U256::from_product(k.checked_mul(40_000)?, n.checked_sub(k)?)
        .checked_add(U256::from_product(38_416, n))?
        .checked_mul_u128(n)?;
    // half = 10_000 * 98 * sqrt(radicand), z/2 = 98/100 scaled by 10_000.
    let half = U256::from_product(980_000, radicand.isqrt());
    let lower = match center.checked_sub(half) {
        Some(below) => quotient(below, denom)?,
        None => 0,
    };
    let (upper, rest) = center.checked_add(half)?.checked_div_rem(denom)?;
    let upper = upper.to_u128()?;
    let upper = if rest.is_zero() {
        upper
    } else {
        upper.checked_add(1)?
    };
    let point = u32::try_from(point).ok()?;
    let lower = u32::try_from(lower).ok()?;
    let upper = u32::try_from(upper.min(10_000)).ok()?;
    Some(WilsonIntervalBps {
        successes,
        trials,
        point_estimate_bps: point,
        lower_bps: lower.min(point),
        upper_bps: upper.max(point),
    })
}

/// Precision and recall evaluation with 95% Wilson confidence intervals on a
/// labeled corpus (`fa-gen`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LabeledDetectorMetrics {
    pub true_positives: u64,
    pub false_positives: u64,
    pub true_negatives: u64,
    pub false_negatives: u64,
    pub precision: WilsonIntervalBps,
    pub recall: WilsonIntervalBps,
    pub clean_fpr: WilsonIntervalBps,
}

impl LabeledDetectorMetrics {
    /// Compute precision, recall, and clean FPR with 95% Wilson confidence intervals.
    #[must_use]
    pub fn from_counts(
        true_positives: u64,
        false_positives: u64,
        true_negatives: u64,
        false_negatives: u64,
    ) -> Self {
        let precision = wilson_interval_95_bps(true_positives, true_positives + false_positives);
        let recall = wilson_interval_95_bps(true_positives, true_positives + false_negatives);
        let clean_fpr = wilson_interval_95_bps(false_positives, false_positives + true_negatives);
        Self {
            true_positives,
            false_positives,
            true_negatives,
            false_negatives,
            precision,
            recall,
            clean_fpr,
        }
    }
}

/// A candidate threshold evaluated on clean calibration scores and labeled fraud items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdCandidateEvaluation {
    pub threshold: i128,
    pub metrics: LabeledDetectorMetrics,
    pub satisfies_conformal_bound: bool,
}

/// Calibrated detector threshold decision card with conformal guarantee and
/// Wilson precision/recall intervals (bead `fa-dh9g`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectorThresholdCard {
    pub procedure_id: String,
    pub parameter_name: String,
    pub claim_class: Claim,
    pub pinned_fallback_threshold: i128,
    pub selected_threshold: i128,
    pub conformal_bound: SplitConformalBound,
    pub selected_metrics: LabeledDetectorMetrics,
    pub candidates: Vec<ThresholdCandidateEvaluation>,
    pub decision_card: DecisionCard,
    pub decision_card_digest: [u8; 32],
}

/// Calibrate a thresholded detector on clean nonconformity scores and labeled
/// fraud scenario items `(score, is_planted_anomaly)`, producing a replayable
/// [`DetectorThresholdCard`] with claim class [`Claim::Statistical`].
#[allow(clippy::too_many_arguments)]
pub fn calibrate_detector_threshold(
    procedure_id: &str,
    parameter_name: &str,
    clean_calibration_scores: &[i128],
    labeled_eval_items: &[(i128, bool)],
    candidate_thresholds: &[i128],
    target_alpha_bps: u32,
    delta_bps: u32,
    policy_epoch: Option<[u8; 32]>,
    enforced_policy_epoch: [u8; 32],
    subject: VId,
) -> Result<DetectorThresholdCard, LanternError> {
    let defaults = Params::defaults(procedure_id)?;
    let pinned_fallback_threshold = defaults.get(parameter_name)?;

    let conformal_bound =
        calibrate_split_conformal(clean_calibration_scores, target_alpha_bps, delta_bps)?;

    let mut all_thresholds: Vec<i128> = candidate_thresholds.to_vec();
    all_thresholds.push(pinned_fallback_threshold);
    if conformal_bound.calibrated_threshold < i128::MAX {
        all_thresholds.push(conformal_bound.calibrated_threshold);
    }
    all_thresholds.sort_unstable();
    all_thresholds.dedup();

    let evaluate_at = |thresh: i128| -> LabeledDetectorMetrics {
        let mut tp = 0u64;
        let mut fp = 0u64;
        let mut tn = 0u64;
        let mut fn_count = 0u64;
        for &(score, is_anomaly) in labeled_eval_items {
            let flagged = score > thresh;
            match (flagged, is_anomaly) {
                (true, true) => tp += 1,
                (true, false) => fp += 1,
                (false, false) => tn += 1,
                (false, true) => fn_count += 1,
            }
        }
        LabeledDetectorMetrics::from_counts(tp, fp, tn, fn_count)
    };

    let mut evaluations = Vec::with_capacity(all_thresholds.len());
    let mut card_candidates = Vec::with_capacity(all_thresholds.len() + 1);

    // Always include the registered pinned fallback candidate.
    card_candidates.push(DecisionCandidate {
        action: "registry_default".into(),
        parameter: 0,
        analytic_score: 100,
    });

    for &t in &all_thresholds {
        let metrics = evaluate_at(t);
        let satisfies = t >= conformal_bound.calibrated_threshold
            && metrics.clean_fpr.point_estimate_bps <= target_alpha_bps;
        let utility = if satisfies {
            i128::from(
                i64::from(metrics.recall.point_estimate_bps)
                    - i64::from(metrics.clean_fpr.point_estimate_bps),
            )
            .max(101)
        } else {
            0
        };

        card_candidates.push(DecisionCandidate {
            action: format!("conformal.{parameter_name}"),
            parameter: t,
            analytic_score: utility,
        });
        evaluations.push(ThresholdCandidateEvaluation {
            threshold: t,
            metrics,
            satisfies_conformal_bound: satisfies,
        });
    }

    let mut state_hasher = Hasher::new();
    state_hasher.update(b"fa:lantern:conformal-state:v1");
    state_hasher.update(procedure_id.as_bytes());
    state_hasher.update(parameter_name.as_bytes());
    state_hasher.update(&subject.0.to_le_bytes());
    state_hasher.update(&(clean_calibration_scores.len() as u64).to_le_bytes());
    for &s in clean_calibration_scores {
        state_hasher.update(&s.to_le_bytes());
    }
    state_hasher.update(&target_alpha_bps.to_le_bytes());
    state_hasher.update(&delta_bps.to_le_bytes());
    let state_space_digest = state_hasher.finalize().0;

    let preliminary_card = evaluate_decision(
        policy_epoch,
        enforced_policy_epoch,
        DecisionKind::LanternThreshold,
        state_space_digest.to_vec(),
        card_candidates.clone(),
        vec![DecisionFeature {
            name: "calibration_n".into(),
            value: clean_calibration_scores.len() as i128,
            advisory: false,
        }],
        BenefitInterval {
            lower_bps: 200,
            upper_bps: 800,
        },
    );

    let selected_threshold = if preliminary_card.used_fallback() {
        pinned_fallback_threshold
    } else {
        preliminary_card.chosen.parameter
    };
    let selected_metrics = evaluate_at(selected_threshold);

    let features = vec![
        DecisionFeature {
            name: "calibration_n".into(),
            value: clean_calibration_scores.len() as i128,
            advisory: false,
        },
        DecisionFeature {
            name: "target_alpha_bps".into(),
            value: i128::from(target_alpha_bps),
            advisory: false,
        },
        DecisionFeature {
            name: "delta_bps".into(),
            value: i128::from(delta_bps),
            advisory: false,
        },
        DecisionFeature {
            name: "conformal_quantile_threshold".into(),
            value: conformal_bound.calibrated_threshold,
            advisory: false,
        },
        DecisionFeature {
            name: "marginal_fpr_bound_bps".into(),
            value: i128::from(conformal_bound.marginal_fpr_bound_bps),
            advisory: false,
        },
        DecisionFeature {
            name: "precision_bps".into(),
            value: i128::from(selected_metrics.precision.point_estimate_bps),
            advisory: false,
        },
        DecisionFeature {
            name: "precision_wilson_lo_bps".into(),
            value: i128::from(selected_metrics.precision.lower_bps),
            advisory: false,
        },
        DecisionFeature {
            name: "precision_wilson_hi_bps".into(),
            value: i128::from(selected_metrics.precision.upper_bps),
            advisory: false,
        },
        DecisionFeature {
            name: "recall_bps".into(),
            value: i128::from(selected_metrics.recall.point_estimate_bps),
            advisory: false,
        },
        DecisionFeature {
            name: "recall_wilson_lo_bps".into(),
            value: i128::from(selected_metrics.recall.lower_bps),
            advisory: false,
        },
        DecisionFeature {
            name: "recall_wilson_hi_bps".into(),
            value: i128::from(selected_metrics.recall.upper_bps),
            advisory: false,
        },
    ];

    let decision_card = evaluate_decision(
        policy_epoch,
        enforced_policy_epoch,
        DecisionKind::LanternThreshold,
        state_space_digest.to_vec(),
        card_candidates,
        features,
        BenefitInterval {
            lower_bps: 200,
            upper_bps: 800,
        },
    );
    let decision_card_digest = decision_card.digest()?;

    Ok(DetectorThresholdCard {
        procedure_id: procedure_id.to_owned(),
        parameter_name: parameter_name.to_owned(),
        claim_class: Claim::Statistical,
        pinned_fallback_threshold,
        selected_threshold,
        conformal_bound,
        selected_metrics,
        candidates: evaluations,
        decision_card,
        decision_card_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_reference::lantern::{naive_split_conformal_quantile, naive_wilson_interval_bps};

    #[test]
    fn split_conformal_calibration_holds_finite_sample_coverage_and_matches_oracle() {
        let clean: Vec<i128> = (1..=99).collect();
        let bound = calibrate_split_conformal(&clean, 500, 500).unwrap();
        assert_eq!(bound.quantile_rank_1based, 95);
        assert_eq!(bound.calibrated_threshold, 95);
        assert!(bound.marginal_fpr_bound_bps <= 500);
        assert!(bound.empirical_clean_fpr_bps <= 500);

        let (oracle_k, oracle_q) = naive_split_conformal_quantile(&clean, 500);
        assert_eq!(bound.quantile_rank_1based, oracle_k);
        assert_eq!(bound.calibrated_threshold, oracle_q);

        let held_out_clean: Vec<i128> = (1..=100).collect();
        let false_positives = held_out_clean
            .iter()
            .filter(|&&s| s > bound.calibrated_threshold)
            .count();
        assert!(
            false_positives <= 5,
            "held-out FPR {false_positives}/100 exceeded 5% conformal bound"
        );
    }

    #[test]
    fn wilson_confidence_interval_is_exact_and_matches_reference_oracle() {
        for (k, n) in [(0, 10), (5, 10), (18, 20), (95, 100), (100, 100)] {
            let w = wilson_interval_95_bps(k, n);
            let (oracle_pt, oracle_lo, oracle_hi) = naive_wilson_interval_bps(k, n);
            assert_eq!(w.point_estimate_bps, oracle_pt);
            assert_eq!(w.lower_bps, oracle_lo);
            assert_eq!(w.upper_bps, oracle_hi);
            assert!(w.lower_bps <= w.point_estimate_bps);
            assert!(w.point_estimate_bps <= w.upper_bps);
            assert!(w.upper_bps <= 10_000);
        }
    }

    /// fa-4aym: every pair of u64 counts has its interval. The u128 form
    /// overflowed, and so panicked, beyond about 3 * 10^11 trials; below
    /// that bound the 256-bit form agrees with the reference oracle exactly.
    #[test]
    fn wilson_interval_is_total_over_u64_counts_and_agrees_with_the_oracle_below_its_bound() {
        for n in [1u64, 2, 3, 7, 1_000, 999_983, 100_000_000_000] {
            for k in [0, 1, n / 3, n / 2, n - 1, n] {
                let w = wilson_interval_95_bps(k, n);
                assert_eq!(
                    (w.point_estimate_bps, w.lower_bps, w.upper_bps),
                    naive_wilson_interval_bps(k, n),
                    "{k}/{n}"
                );
            }
        }
        for (k, n) in [
            (0, u64::MAX),
            (1, u64::MAX),
            (u64::MAX / 2, u64::MAX),
            (u64::MAX, u64::MAX),
        ] {
            let w = wilson_interval_95_bps(k, n);
            assert!(
                w.lower_bps <= w.point_estimate_bps
                    && w.point_estimate_bps <= w.upper_bps
                    && w.upper_bps <= 10_000,
                "{w:?}"
            );
            assert!(
                w.upper_bps - w.lower_bps <= 2,
                "nearly degenerate at 2^64 trials: {w:?}"
            );
        }
        let half = wilson_interval_95_bps(u64::MAX / 2, u64::MAX);
        assert_eq!(half.point_estimate_bps, 4_999, "(2^63 - 1) / (2^64 - 1)");
        assert_eq!(wilson_interval_95_bps(0, u64::MAX).lower_bps, 0);
        assert_eq!(wilson_interval_95_bps(u64::MAX, u64::MAX).upper_bps, 10_000);
    }

    #[test]
    fn detector_threshold_card_replays_bit_for_bit_and_pins_fallback_when_epoch_absent() {
        let clean: Vec<i128> = (10..=109).collect();
        let mut labeled: Vec<(i128, bool)> = clean.iter().map(|&s| (s, false)).collect();
        for fraud_score in [150, 180, 210, 250, 300] {
            labeled.push((fraud_score, true));
        }

        let epoch = [0x42; 32];
        let candidates = [80, 100, 105, 120, 200];
        let card = calibrate_detector_threshold(
            "benford.first_digit",
            "mad_marginal",
            &clean,
            &labeled,
            &candidates,
            500,
            500,
            Some(epoch),
            epoch,
            VId(77),
        )
        .unwrap();

        assert_eq!(card.claim_class, Claim::Statistical);
        assert_eq!(card.pinned_fallback_threshold, 15);
        assert_eq!(card.selected_threshold, 120);
        assert_eq!(card.selected_metrics.recall.point_estimate_bps, 10_000);
        assert_eq!(card.selected_metrics.clean_fpr.point_estimate_bps, 0);

        let replayed = card
            .decision_card
            .verify_replay(epoch)
            .expect("replay succeeds");
        assert_eq!(replayed, card.decision_card_digest);

        let fallback_card = calibrate_detector_threshold(
            "benford.first_digit",
            "mad_marginal",
            &clean,
            &labeled,
            &candidates,
            500,
            500,
            None,
            epoch,
            VId(77),
        )
        .unwrap();
        assert_eq!(
            fallback_card.selected_threshold,
            fallback_card.pinned_fallback_threshold
        );
    }
}
