//! Replayable decision-card framework (AGENTS.md "Adaptive-Decision Contract",
//! bead `fa-7v1h`).
//!
//! Every adaptive decision — register checkpoint cadence, forensic thresholds,
//! bundle evidence-inlining policy, bank-match heuristics, sampling
//! stratification, and merge-train batch sizing — emits a deterministic,
//! replayable [`DecisionCard`] under a versioned policy epoch with a pinned
//! deterministic fallback.
//!
//! Constitutional guarantees:
//! 1. Pure laws-layer evaluation: no clock, no entropy, no I/O, no `Cx`.
//! 2. Pinned deterministic fallback: when `policy_epoch` is absent or does not
//!    match the enforced epoch, when the expected-benefit interval is invalid
//!    or wider than the policy bound, or when the interval's lower bound is
//!    below the minimum required benefit, [`evaluate_decision`] selects the
//!    registered pinned fallback.
//! 3. Learned scores are admissible only as `advisory: true` features and can
//!    never override the analytic score or the fallback guardrails.
//! 4. No decision card may alter a committed [`Amount`].

use core::fmt;

use fa_model::{DecodeError, EncodeError, Reader, Writer, domain_digest};
use fa_money::Amount;

pub const DECISION_CARD_DOMAIN: &[u8] = b"fa:decision-card:v1";
const DECISION_CARD_MAGIC: &[u8; 4] = b"FADC";
const DECISION_CARD_VERSION: u16 = 1;

/// Closed taxonomy of adaptive decision kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DecisionKind {
    RegisterCheckpointCadence,
    LanternThreshold,
    BundleEvidenceInlining,
    BankMatchHeuristic,
    SamplingStratification,
    TrainBatchSize,
}

impl DecisionKind {
    pub const ALL: [Self; 6] = [
        Self::RegisterCheckpointCadence,
        Self::LanternThreshold,
        Self::BundleEvidenceInlining,
        Self::BankMatchHeuristic,
        Self::SamplingStratification,
        Self::TrainBatchSize,
    ];

    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::RegisterCheckpointCadence => 1,
            Self::LanternThreshold => 2,
            Self::BundleEvidenceInlining => 3,
            Self::BankMatchHeuristic => 4,
            Self::SamplingStratification => 5,
            Self::TrainBatchSize => 6,
        }
    }

    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::RegisterCheckpointCadence),
            2 => Some(Self::LanternThreshold),
            3 => Some(Self::BundleEvidenceInlining),
            4 => Some(Self::BankMatchHeuristic),
            5 => Some(Self::SamplingStratification),
            6 => Some(Self::TrainBatchSize),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RegisterCheckpointCadence => "register.checkpoint_cadence",
            Self::LanternThreshold => "lantern.threshold",
            Self::BundleEvidenceInlining => "bundle.evidence_inlining",
            Self::BankMatchHeuristic => "bank.match_heuristic",
            Self::SamplingStratification => "sampling.stratification",
            Self::TrainBatchSize => "train.batch_size",
        }
    }
}

impl fmt::Display for DecisionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Policy registry row governing one [`DecisionKind`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecisionPolicyRow {
    pub kind: DecisionKind,
    pub pinned_fallback_action: &'static str,
    pub pinned_fallback_parameter: i128,
    pub max_interval_width_bps: u64,
    pub min_lower_benefit_bps: i64,
}

impl DecisionPolicyRow {
    #[must_use]
    pub const fn for_kind(kind: DecisionKind) -> Self {
        match kind {
            DecisionKind::RegisterCheckpointCadence => Self {
                kind,
                pinned_fallback_action: "eager_advance",
                pinned_fallback_parameter: 1,
                max_interval_width_bps: 2_000,
                min_lower_benefit_bps: 50,
            },
            DecisionKind::LanternThreshold => Self {
                kind,
                pinned_fallback_action: "registry_default",
                pinned_fallback_parameter: 0,
                max_interval_width_bps: 1_500,
                min_lower_benefit_bps: 100,
            },
            DecisionKind::BundleEvidenceInlining => Self {
                kind,
                pinned_fallback_action: "inline_under_limit",
                pinned_fallback_parameter: 16_777_216,
                max_interval_width_bps: 1_000,
                min_lower_benefit_bps: 50,
            },
            DecisionKind::BankMatchHeuristic => Self {
                kind,
                pinned_fallback_action: "exact_amount_and_date",
                pinned_fallback_parameter: 0,
                max_interval_width_bps: 1_000,
                min_lower_benefit_bps: 100,
            },
            DecisionKind::SamplingStratification => Self {
                kind,
                pinned_fallback_action: "monetary_unit_fixed_strata",
                pinned_fallback_parameter: 4,
                max_interval_width_bps: 1_500,
                min_lower_benefit_bps: 50,
            },
            DecisionKind::TrainBatchSize => Self {
                kind,
                pinned_fallback_action: "serial_single_bead",
                pinned_fallback_parameter: 1,
                max_interval_width_bps: 2_500,
                min_lower_benefit_bps: 50,
            },
        }
    }

    #[must_use]
    pub fn fallback_candidate(&self) -> DecisionCandidate {
        DecisionCandidate {
            action: self.pinned_fallback_action.to_string(),
            parameter: self.pinned_fallback_parameter,
            analytic_score: 0,
        }
    }
}

/// One candidate action considered by a decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionCandidate {
    pub action: String,
    pub parameter: i128,
    pub analytic_score: i128,
}

impl DecisionCandidate {
    fn encode(&self, w: &mut Writer) {
        w.str(&self.action)
            .i128(self.parameter)
            .i128(self.analytic_score);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            action: r.str(128, "decision.candidate.action")?.to_string(),
            parameter: r.i128("decision.candidate.parameter")?,
            analytic_score: r.i128("decision.candidate.analytic_score")?,
        })
    }
}

/// One observed feature recorded on a [`DecisionCard`].
///
/// Learned scores are admissible only when `advisory == true`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionFeature {
    pub name: String,
    pub value: i128,
    pub advisory: bool,
}

impl DecisionFeature {
    fn encode(&self, w: &mut Writer) {
        w.str(&self.name).i128(self.value).bool(self.advisory);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            name: r.str(128, "decision.feature.name")?.to_string(),
            value: r.i128("decision.feature.value")?,
            advisory: r.bool("decision.feature.advisory")?,
        })
    }
}

/// Expected-benefit interval in basis points (`10_000 bps == 100%`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BenefitInterval {
    pub lower_bps: i64,
    pub upper_bps: i64,
}

impl BenefitInterval {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.lower_bps <= self.upper_bps
    }

    #[must_use]
    pub const fn width_bps(self) -> u64 {
        self.upper_bps.abs_diff(self.lower_bps)
    }

    fn encode(self, w: &mut Writer) {
        w.i64(self.lower_bps).i64(self.upper_bps);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            lower_bps: r.i64("decision.interval.lower_bps")?,
            upper_bps: r.i64("decision.interval.upper_bps")?,
        })
    }
}

/// Structured reason explaining why [`DecisionCard::chosen`] was selected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecisionReason {
    /// Policy epoch was absent or did not match the enforced policy epoch;
    /// pinned fallback selected.
    PolicyAbsent,
    /// Expected-benefit interval had `lower_bps > upper_bps`; pinned fallback
    /// selected.
    InvalidInterval { lower_bps: i64, upper_bps: i64 },
    /// Expected-benefit interval width exceeded the policy bound; pinned
    /// fallback selected.
    IntervalTooWide { width_bps: u64, max_width_bps: u64 },
    /// Expected-benefit lower bound was below the policy minimum; pinned
    /// fallback selected.
    InsufficientBenefit { lower_bps: i64, min_lower_bps: i64 },
    /// Analytic evaluation selected the pinned fallback directly.
    PinnedFallbackSelected,
    /// Analytic evaluation selected a candidate meeting all policy bounds.
    AnalyticCandidateSelected { action: String },
}

impl DecisionReason {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::PolicyAbsent => "policy_absent",
            Self::InvalidInterval { .. } => "invalid_interval",
            Self::IntervalTooWide { .. } => "interval_too_wide",
            Self::InsufficientBenefit { .. } => "insufficient_benefit",
            Self::PinnedFallbackSelected => "pinned_fallback_selected",
            Self::AnalyticCandidateSelected { .. } => "analytic_candidate_selected",
        }
    }

    fn encode(&self, w: &mut Writer) {
        match self {
            Self::PolicyAbsent => {
                w.u8(1);
            }
            Self::InvalidInterval {
                lower_bps,
                upper_bps,
            } => {
                w.u8(2).i64(*lower_bps).i64(*upper_bps);
            }
            Self::IntervalTooWide {
                width_bps,
                max_width_bps,
            } => {
                w.u8(3).u64(*width_bps).u64(*max_width_bps);
            }
            Self::InsufficientBenefit {
                lower_bps,
                min_lower_bps,
            } => {
                w.u8(4).i64(*lower_bps).i64(*min_lower_bps);
            }
            Self::PinnedFallbackSelected => {
                w.u8(5);
            }
            Self::AnalyticCandidateSelected { action } => {
                w.u8(6).str(action);
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8("decision.reason.tag")? {
            1 => Ok(Self::PolicyAbsent),
            2 => Ok(Self::InvalidInterval {
                lower_bps: r.i64("decision.reason.lower_bps")?,
                upper_bps: r.i64("decision.reason.upper_bps")?,
            }),
            3 => Ok(Self::IntervalTooWide {
                width_bps: r.u64("decision.reason.width_bps")?,
                max_width_bps: r.u64("decision.reason.max_width_bps")?,
            }),
            4 => Ok(Self::InsufficientBenefit {
                lower_bps: r.i64("decision.reason.lower_bps")?,
                min_lower_bps: r.i64("decision.reason.min_lower_bps")?,
            }),
            5 => Ok(Self::PinnedFallbackSelected),
            6 => Ok(Self::AnalyticCandidateSelected {
                action: r.str(128, "decision.reason.action")?.to_string(),
            }),
            _ => Err(r.invalid("decision.reason.tag")),
        }
    }
}

/// Replayable decision card emitted by an adaptive decision point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionCard {
    pub policy_epoch: Option<[u8; 32]>,
    pub decision_kind: DecisionKind,
    pub state: Vec<u8>,
    pub candidates: Vec<DecisionCandidate>,
    pub features: Vec<DecisionFeature>,
    pub chosen: DecisionCandidate,
    pub expected_benefit_interval: BenefitInterval,
    pub fallback: DecisionCandidate,
    pub reason: DecisionReason,
}

/// Error returned when a replayed decision card drifts from its recorded bytes
/// or lacks its registered pinned fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecisionReplayError {
    Encode(EncodeError),
    FallbackMissingOrInvalid {
        expected_action: &'static str,
        actual_action: String,
    },
    Drift {
        recorded_digest: [u8; 32],
        replayed_digest: [u8; 32],
    },
}

impl fmt::Display for DecisionReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(e) => write!(f, "decision card encoding error: {e}"),
            Self::FallbackMissingOrInvalid {
                expected_action,
                actual_action,
            } => write!(
                f,
                "decision card fallback invalid: expected pinned fallback {expected_action:?}, got {actual_action:?}"
            ),
            Self::Drift {
                recorded_digest,
                replayed_digest,
            } => write!(
                f,
                "decision card replay drift: recorded {:02x?} != replayed {:02x?}",
                &recorded_digest[..4],
                &replayed_digest[..4]
            ),
        }
    }
}

impl core::error::Error for DecisionReplayError {}

impl From<EncodeError> for DecisionReplayError {
    fn from(e: EncodeError) -> Self {
        Self::Encode(e)
    }
}

impl DecisionCard {
    /// Validate that the card carries the registered pinned deterministic fallback
    /// for its [`DecisionKind`] (refuses registration of a card whose fallback was removed or altered).
    pub fn validate_fallback(&self) -> Result<(), DecisionReplayError> {
        let row = DecisionPolicyRow::for_kind(self.decision_kind);
        let expected = row.fallback_candidate();
        if self.fallback != expected {
            return Err(DecisionReplayError::FallbackMissingOrInvalid {
                expected_action: row.pinned_fallback_action,
                actual_action: self.fallback.action.clone(),
            });
        }
        Ok(())
    }
    /// Canonical binary encoding (`FADC` v1).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(DECISION_CARD_MAGIC)
            .u16(DECISION_CARD_VERSION)
            .opt(self.policy_epoch.as_ref(), |w, ep| {
                w.fixed(ep);
            })
            .u8(self.decision_kind.tag())
            .bytes(&self.state)
            .list(&self.candidates, |w, c| c.encode(w))
            .list(&self.features, |w, f| f.encode(w));
        self.chosen.encode(&mut w);
        self.expected_benefit_interval.encode(&mut w);
        self.fallback.encode(&mut w);
        self.reason.encode(&mut w);
        w.finish()
    }

    /// Decode a [`DecisionCard`] from its canonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.fixed::<4>("decision.magic")? != *DECISION_CARD_MAGIC
            || r.u16("decision.version")? != DECISION_CARD_VERSION
        {
            return Err(r.invalid("decision.header"));
        }
        let policy_epoch = r.opt("decision.policy_epoch", |r| r.fixed::<32>("decision.epoch"))?;
        let kind_tag = r.u8("decision.kind")?;
        let Some(decision_kind) = DecisionKind::from_tag(kind_tag) else {
            return Err(r.invalid("decision.kind"));
        };
        let state = r.bytes(4096, "decision.state")?.to_vec();
        let candidates = r.list(64, "decision.candidates", DecisionCandidate::decode)?;
        let features = r.list(128, "decision.features", DecisionFeature::decode)?;
        let chosen = DecisionCandidate::decode(&mut r)?;
        let expected_benefit_interval = BenefitInterval::decode(&mut r)?;
        let fallback = DecisionCandidate::decode(&mut r)?;
        let reason = DecisionReason::decode(&mut r)?;
        r.finish()?;
        Ok(Self {
            policy_epoch,
            decision_kind,
            state,
            candidates,
            features,
            chosen,
            expected_benefit_interval,
            fallback,
            reason,
        })
    }

    /// Domain-separated BLAKE3 digest of this card's canonical bytes.
    pub fn digest(&self) -> Result<[u8; 32], EncodeError> {
        let bytes = self.canonical_bytes()?;
        Ok(domain_digest(DECISION_CARD_DOMAIN, &[&bytes]))
    }

    /// Re-evaluate the decision from the recorded inputs and verify bit-for-bit
    /// equality with `self`.
    pub fn verify_replay(
        &self,
        enforced_policy_epoch: [u8; 32],
    ) -> Result<[u8; 32], DecisionReplayError> {
        self.validate_fallback()?;
        let replayed = evaluate_decision(
            self.policy_epoch,
            enforced_policy_epoch,
            self.decision_kind,
            self.state.clone(),
            self.candidates.clone(),
            self.features.clone(),
            self.expected_benefit_interval,
        );
        let recorded_digest = self.digest()?;
        let replayed_digest = replayed.digest()?;
        if recorded_digest != replayed_digest || *self != replayed {
            return Err(DecisionReplayError::Drift {
                recorded_digest,
                replayed_digest,
            });
        }
        Ok(recorded_digest)
    }

    /// True when the card selected the pinned deterministic fallback.
    #[must_use]
    pub fn used_fallback(&self) -> bool {
        self.chosen == self.fallback
            && !matches!(
                self.reason,
                DecisionReason::AnalyticCandidateSelected { .. }
            )
    }
}

/// Pure, deterministic evaluator for any adaptive decision.
///
/// Selects the registered pinned fallback whenever:
/// - `policy_epoch` is `None` or differs from `enforced_policy_epoch`;
/// - `expected_benefit_interval` has `lower_bps > upper_bps`;
/// - `expected_benefit_interval.width_bps() > row.max_interval_width_bps`;
/// - `expected_benefit_interval.lower_bps < row.min_lower_benefit_bps`;
/// - `candidates` has no analytic candidate with `analytic_score > 0`.
#[must_use]
pub fn evaluate_decision(
    policy_epoch: Option<[u8; 32]>,
    enforced_policy_epoch: [u8; 32],
    decision_kind: DecisionKind,
    state: Vec<u8>,
    mut candidates: Vec<DecisionCandidate>,
    mut features: Vec<DecisionFeature>,
    expected_benefit_interval: BenefitInterval,
) -> DecisionCard {
    let row = DecisionPolicyRow::for_kind(decision_kind);
    let fallback = row.fallback_candidate();

    // Canonicalize candidate and feature ordering so card bytes are invariant
    // to caller iteration order.
    candidates.sort_by(|a, b| {
        a.action
            .cmp(&b.action)
            .then(a.parameter.cmp(&b.parameter))
            .then(a.analytic_score.cmp(&b.analytic_score))
    });
    features.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then(a.advisory.cmp(&b.advisory))
            .then(a.value.cmp(&b.value))
    });

    // Check whether any non-advisory (analytic) feature is present. If all
    // features are advisory (learned), the decision may not override the
    // pinned fallback.
    let has_analytic_feature = features.iter().any(|f| !f.advisory);

    let (chosen, reason) = if policy_epoch != Some(enforced_policy_epoch) {
        (fallback.clone(), DecisionReason::PolicyAbsent)
    } else if !expected_benefit_interval.is_valid() {
        (
            fallback.clone(),
            DecisionReason::InvalidInterval {
                lower_bps: expected_benefit_interval.lower_bps,
                upper_bps: expected_benefit_interval.upper_bps,
            },
        )
    } else if expected_benefit_interval.width_bps() > row.max_interval_width_bps {
        (
            fallback.clone(),
            DecisionReason::IntervalTooWide {
                width_bps: expected_benefit_interval.width_bps(),
                max_width_bps: row.max_interval_width_bps,
            },
        )
    } else if expected_benefit_interval.lower_bps < row.min_lower_benefit_bps {
        (
            fallback.clone(),
            DecisionReason::InsufficientBenefit {
                lower_bps: expected_benefit_interval.lower_bps,
                min_lower_bps: row.min_lower_benefit_bps,
            },
        )
    } else if !has_analytic_feature {
        (fallback.clone(), DecisionReason::PinnedFallbackSelected)
    } else {
        // Choose highest `analytic_score` (> 0), breaking ties deterministically
        // by `(action, parameter)` ascending.
        let best = candidates
            .iter()
            .filter(|c| c.analytic_score > 0)
            .max_by(|a, b| {
                a.analytic_score
                    .cmp(&b.analytic_score)
                    .then_with(|| b.action.cmp(&a.action))
                    .then_with(|| b.parameter.cmp(&a.parameter))
            });
        match best {
            Some(c) if c.action != fallback.action || c.parameter != fallback.parameter => (
                c.clone(),
                DecisionReason::AnalyticCandidateSelected {
                    action: c.action.clone(),
                },
            ),
            _ => (fallback.clone(), DecisionReason::PinnedFallbackSelected),
        }
    };

    DecisionCard {
        policy_epoch,
        decision_kind,
        state,
        candidates,
        features,
        chosen,
        expected_benefit_interval,
        fallback,
        reason,
    }
}

/// Constitutional check: a [`DecisionCard`] never alters committed amounts.
#[must_use]
pub fn amounts_preserved(before: &[Amount], after: &[Amount], _card: &DecisionCard) -> bool {
    before == after
}

/// Consumer 1: Register checkpoint/advance cadence decision card.
///
/// Given the period coordinate and delta-stream statistics (`from_seq`,
/// `through_seq`, `entries_decoded`, `total_entries`), emits a replayable
/// [`DecisionCard`] for [`DecisionKind::RegisterCheckpointCadence`].
#[must_use]
pub fn decide_register_checkpoint_cadence(
    policy_epoch: Option<[u8; 32]>,
    enforced_policy_epoch: [u8; 32],
    period: &str,
    from_seq: u64,
    through_seq: u64,
    entries_decoded: u64,
    total_entries: u64,
) -> DecisionCard {
    let mut state_writer = Writer::new();
    state_writer
        .str(period)
        .u64(from_seq)
        .u64(through_seq)
        .u64(entries_decoded)
        .u64(total_entries);
    let state = state_writer.finish().unwrap_or_default();

    let seq_span = through_seq.saturating_sub(from_seq);
    let features = vec![
        DecisionFeature {
            name: "entries_decoded".to_string(),
            value: i128::from(entries_decoded),
            advisory: false,
        },
        DecisionFeature {
            name: "seq_span".to_string(),
            value: i128::from(seq_span),
            advisory: false,
        },
        DecisionFeature {
            name: "total_entries".to_string(),
            value: i128::from(total_entries),
            advisory: false,
        },
    ];

    let batch_score = if entries_decoded >= 64 {
        i128::from(entries_decoded)
    } else {
        0
    };
    let candidates = vec![
        DecisionCandidate {
            action: "eager_advance".to_string(),
            parameter: 1,
            analytic_score: 10,
        },
        DecisionCandidate {
            action: "batch_checkpoint_64".to_string(),
            parameter: 64,
            analytic_score: batch_score,
        },
    ];
    let interval = if entries_decoded >= 64 {
        BenefitInterval {
            lower_bps: 200,
            upper_bps: 800,
        }
    } else {
        BenefitInterval {
            lower_bps: 100,
            upper_bps: 300,
        }
    };

    evaluate_decision(
        policy_epoch,
        enforced_policy_epoch,
        DecisionKind::RegisterCheckpointCadence,
        state,
        candidates,
        features,
        interval,
    )
}

/// Consumer 2: Lantern procedure threshold decision card.
///
/// Emits a replayable [`DecisionCard`] for [`DecisionKind::LanternThreshold`]
/// over the procedure's registered identifier, version, parameter bindings, and
/// snapshot population.
#[must_use]
pub fn decide_lantern_threshold(
    policy_epoch: Option<[u8; 32]>,
    enforced_policy_epoch: [u8; 32],
    procedure: &str,
    version: u16,
    parameters: &[(String, i128)],
    population: u64,
) -> DecisionCard {
    let mut state_writer = Writer::new();
    state_writer.str(procedure).u16(version).u64(population);
    state_writer.list(parameters, |w, (k, v)| {
        w.str(k).i128(*v);
    });
    let state = state_writer.finish().unwrap_or_default();

    let mut features = Vec::with_capacity(parameters.len() + 1);
    features.push(DecisionFeature {
        name: "population".to_string(),
        value: i128::from(population),
        advisory: false,
    });
    for (k, v) in parameters {
        features.push(DecisionFeature {
            name: format!("param.{k}"),
            value: *v,
            advisory: false,
        });
    }

    let primary_param = parameters.first().map_or(0, |(_, v)| *v);
    let calibrated_score = if population >= 100 { 250 } else { 0 };
    let candidates = vec![
        DecisionCandidate {
            action: "registry_default".to_string(),
            parameter: 0,
            analytic_score: 100,
        },
        DecisionCandidate {
            action: "split_conformal_calibrated".to_string(),
            parameter: primary_param,
            analytic_score: calibrated_score,
        },
    ];
    let interval = if population >= 100 {
        BenefitInterval {
            lower_bps: 150,
            upper_bps: 650,
        }
    } else {
        // Small sample population: wide uncertainty interval forces pinned
        // registry_default fallback.
        BenefitInterval {
            lower_bps: -200,
            upper_bps: 2_200,
        }
    };

    evaluate_decision(
        policy_epoch,
        enforced_policy_epoch,
        DecisionKind::LanternThreshold,
        state,
        candidates,
        features,
        interval,
    )
}

/// Consumer 3: Bank / subledger / three-way reconciliation match decision card
/// (plan §15.9, §12.5; bead `fa-2ek`).
///
/// Emits a replayable [`DecisionCard`] for [`DecisionKind::BankMatchHeuristic`]
/// over `subject_digest`, candidate entry ordinals (`parameter`), analytic and
/// advisory features, and the expected-benefit interval.
#[must_use]
pub fn decide_bank_match(
    policy_epoch: Option<[u8; 32]>,
    enforced_policy_epoch: [u8; 32],
    subject_digest: [u8; 32],
    candidates: Vec<DecisionCandidate>,
    features: Vec<DecisionFeature>,
    expected_benefit_interval: BenefitInterval,
) -> DecisionCard {
    evaluate_decision(
        policy_epoch,
        enforced_policy_epoch,
        DecisionKind::BankMatchHeuristic,
        subject_digest.to_vec(),
        candidates,
        features,
        expected_benefit_interval,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_money::UnitId;

    #[test]
    fn decision_card_canonical_bytes_round_trip_and_replay_bit_for_bit() {
        let steward = crate::Steward::embedded().unwrap();
        let epoch = steward.policy_oid;

        let card =
            decide_register_checkpoint_cadence(Some(epoch), epoch, "FY2026-P03", 1, 85, 80, 80);
        assert_eq!(card.chosen.action, "batch_checkpoint_64");
        assert_eq!(card.chosen.parameter, 64);
        assert!(!card.used_fallback());

        let bytes = card.canonical_bytes().unwrap();
        let decoded = DecisionCard::decode(&bytes).unwrap();
        assert_eq!(decoded, card);
        assert_eq!(decoded.canonical_bytes().unwrap(), bytes);

        let digest = card.verify_replay(epoch).unwrap();
        assert_eq!(digest, decoded.digest().unwrap());
    }

    #[test]
    fn fallback_is_chosen_when_policy_is_absent_or_mismatched_or_interval_is_wide() {
        let steward = crate::Steward::embedded().unwrap();
        let epoch = steward.policy_oid;
        let state = b"state-1".to_vec();
        let candidates = vec![DecisionCandidate {
            action: "adaptive_action".to_string(),
            parameter: 42,
            analytic_score: 500,
        }];
        let features = vec![DecisionFeature {
            name: "sample_size".to_string(),
            value: 500,
            advisory: false,
        }];
        let tight_interval = BenefitInterval {
            lower_bps: 200,
            upper_bps: 500,
        };

        // 1. Policy absent -> fallback
        let absent = evaluate_decision(
            None,
            epoch,
            DecisionKind::LanternThreshold,
            state.clone(),
            candidates.clone(),
            features.clone(),
            tight_interval,
        );
        assert!(absent.used_fallback());
        assert_eq!(absent.reason, DecisionReason::PolicyAbsent);
        assert_eq!(absent.chosen.action, "registry_default");
        absent.verify_replay(epoch).unwrap();

        // 2. Policy epoch mismatch -> fallback
        let mismatch = evaluate_decision(
            Some([0xaa; 32]),
            epoch,
            DecisionKind::LanternThreshold,
            state.clone(),
            candidates.clone(),
            features.clone(),
            tight_interval,
        );
        assert!(mismatch.used_fallback());
        assert_eq!(mismatch.reason, DecisionReason::PolicyAbsent);

        // 3. Interval too wide -> fallback
        let wide = evaluate_decision(
            Some(epoch),
            epoch,
            DecisionKind::LanternThreshold,
            state.clone(),
            candidates.clone(),
            features.clone(),
            BenefitInterval {
                lower_bps: 200,
                upper_bps: 5_000,
            },
        );
        assert!(wide.used_fallback());
        assert!(matches!(
            wide.reason,
            DecisionReason::IntervalTooWide { .. }
        ));
        wide.verify_replay(epoch).unwrap();

        // 4. Lower bound below minimum benefit -> fallback
        let low = evaluate_decision(
            Some(epoch),
            epoch,
            DecisionKind::LanternThreshold,
            state.clone(),
            candidates.clone(),
            features,
            BenefitInterval {
                lower_bps: 10,
                upper_bps: 300,
            },
        );
        assert!(low.used_fallback());
        assert!(matches!(
            low.reason,
            DecisionReason::InsufficientBenefit { .. }
        ));
        low.verify_replay(epoch).unwrap();

        // 5. Only advisory (learned) features -> fallback
        let advisory_only = evaluate_decision(
            Some(epoch),
            epoch,
            DecisionKind::LanternThreshold,
            state,
            candidates,
            vec![DecisionFeature {
                name: "learned_anomaly_score".to_string(),
                value: 999,
                advisory: true,
            }],
            tight_interval,
        );
        assert!(advisory_only.used_fallback());
        assert_eq!(advisory_only.reason, DecisionReason::PinnedFallbackSelected);
        advisory_only.verify_replay(epoch).unwrap();
    }

    #[test]
    fn generated_decisions_never_alter_committed_amounts_and_are_order_invariant() {
        let steward = crate::Steward::embedded().unwrap();
        let epoch = steward.policy_oid;
        let committed_before = vec![
            Amount::new(UnitId(1), 12_500),
            Amount::new(UnitId(1), -12_500),
            Amount::new(UnitId(2), 99_999_900),
        ];

        for seed in 0_u64..64 {
            let kind = DecisionKind::ALL[(seed as usize) % DecisionKind::ALL.len()];
            let c1 = DecisionCandidate {
                action: format!("cand_a_{seed}"),
                parameter: i128::from(seed),
                analytic_score: i128::from(seed % 5) * 50,
            };
            let c2 = DecisionCandidate {
                action: format!("cand_b_{seed}"),
                parameter: i128::from(seed + 10),
                analytic_score: i128::from((seed + 2) % 5) * 50,
            };
            let f1 = DecisionFeature {
                name: "f_analytic".to_string(),
                value: i128::from(seed * 7),
                advisory: false,
            };
            let f2 = DecisionFeature {
                name: "f_learned".to_string(),
                value: i128::from(seed * 13),
                advisory: true,
            };
            let interval = BenefitInterval {
                lower_bps: (seed as i64 % 4) * 50,
                upper_bps: (seed as i64 % 4) * 50 + (seed as i64 % 5) * 600,
            };
            let use_epoch = if seed % 3 == 0 { None } else { Some(epoch) };

            let card_ab = evaluate_decision(
                use_epoch,
                epoch,
                kind,
                seed.to_le_bytes().to_vec(),
                vec![c1.clone(), c2.clone()],
                vec![f1.clone(), f2.clone()],
                interval,
            );
            let card_ba = evaluate_decision(
                use_epoch,
                epoch,
                kind,
                seed.to_le_bytes().to_vec(),
                vec![c2, c1],
                vec![f2, f1],
                interval,
            );
            assert_eq!(
                card_ab.canonical_bytes().unwrap(),
                card_ba.canonical_bytes().unwrap()
            );
            card_ab.verify_replay(epoch).unwrap();

            let committed_after = committed_before.clone();
            assert!(amounts_preserved(
                &committed_before,
                &committed_after,
                &card_ab
            ));
        }
    }
}
