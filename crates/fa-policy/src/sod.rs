//! Segregation of duties (plan §14.3, FA-INV-10 clause `sod`) over the rows
//! of `registries/sod_policy.toml`.
//!
//! The kernel hands this module the preparer and the approvals it
//! point-read inside the posting transaction; the verdict is decided here,
//! from data, at commit. Precedence (the reference oracle mirrors it):
//! 1. every exclusion and vocabulary item of the rule must be decidable
//!    (fail closed);
//! 2. each approval in transcript order: not the preparer, a permitted
//!    profile, the rule's op, a principal not already counted, and (under
//!    `case_preparer`) no preparer of an entry in the case;
//! 3. at least `max(matrix approvals, rule approvers)` approvals;
//! 4. agent-prepared work: at least `agent_prepared_human_approvers` Human
//!    approvers.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fa_model::{Id128, Writer, domain_digest};
use fa_money::UnitId;
use fa_registry::sod_policy::{SodKey, SodRequirement};
use fa_time::PeriodState;
use fgdb_types::{CommitSeq, VId};

use crate::admit::{current, require, scope};
use crate::approval::Approval;
use crate::capability::{Capability, CapabilityError, Profile};
use crate::denial::Denial;
use crate::op::Op;

/// Exclusions this evaluator decides. Any other registered exclusion makes
/// its rule refuse until the slice that can decide it lands.
pub const DECIDED_EXCLUSIONS: &[&str] = &["duplicate", "preparer"];

/// The preparer: the principal the entry names and the profile of the
/// capability it acted under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Party {
    pub principal: VId,
    pub profile: Profile,
}

impl Party {
    /// Construct a `Party` for SoD evaluation from `principal` and `capability`,
    /// using [`Capability::sod_profile`] so an MCP `Preparer` (`Profile::Human`
    /// with `OperatorKind::Agent`) is evaluated as `Profile::Agent` (plan §14.4).
    #[must_use]
    pub fn for_capability(principal: VId, capability: &Capability) -> Self {
        Self {
            principal,
            profile: capability.sod_profile(),
        }
    }
}

/// One approval, as the kernel witnessed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Approver {
    pub principal: VId,
    pub profile: Profile,
    pub op: Op,
}

impl From<&Approval> for Approver {
    fn from(a: &Approval) -> Self {
        Self {
            principal: a.principal,
            profile: a.profile,
            op: a.op,
        }
    }
}

/// The SoD key of a posting entry: `posts` is true for `Resolution(Posts)`.
#[must_use]
pub fn posting_key(class: &str, state: PeriodState, posts: bool) -> SodKey {
    SodKey {
        class: class.to_string(),
        state: Some(state),
        disposition: (class == "Resolution" && posts).then(|| "Posts".to_string()),
        transition: None,
    }
}

/// The SoD key of a control entry.
#[must_use]
pub fn control_key(class: &str, state: Option<PeriodState>, transition: &str) -> SodKey {
    SodKey {
        class: class.to_string(),
        state,
        disposition: None,
        transition: Some(transition.to_string()),
    }
}

/// Evaluate rule `rule` (`req`) over the preparer and the witnessed
/// approvals. `matrix_approvals` is the admissibility cell's count (0 for
/// `admit` cells and for controls). No case is in scope, so a rule with the
/// `case_preparer` exclusion refuses ([`evaluate_in`] decides it).
pub fn evaluate(
    rule: &str,
    req: &SodRequirement,
    matrix_approvals: u8,
    preparer: Party,
    approvers: &[Approver],
) -> Result<(), Denial> {
    evaluate_in(rule, req, matrix_approvals, preparer, approvers, None)
}

/// [`evaluate`] for work that belongs to a case: `case_preparers` are the
/// principals who prepared any entry in it, which decides the
/// `case_preparer` exclusion (an approver is none of them). `None` leaves
/// that exclusion undecidable, so a rule naming it refuses (fail closed).
pub fn evaluate_in(
    rule: &str,
    req: &SodRequirement,
    matrix_approvals: u8,
    preparer: Party,
    approvers: &[Approver],
    case_preparers: Option<&BTreeSet<VId>>,
) -> Result<(), Denial> {
    let in_case = req.exclusions.iter().any(|e| e == "case_preparer");
    for exclusion in &req.exclusions {
        let decided = DECIDED_EXCLUSIONS.contains(&exclusion.as_str())
            || (exclusion == "case_preparer" && case_preparers.is_some());
        if !decided {
            return Err(Denial::UnsupportedExclusion {
                rule: rule.to_string(),
                exclusion: exclusion.clone(),
            });
        }
    }
    let Some(op) = Op::from_name(&req.approver_op) else {
        return Err(Denial::UnsupportedExclusion {
            rule: rule.to_string(),
            exclusion: format!("approver_op `{}`", req.approver_op),
        });
    };
    let mut allowed = BTreeSet::new();
    for name in &req.approver_profiles {
        let Some(p) = Profile::from_name(name) else {
            return Err(Denial::UnsupportedExclusion {
                rule: rule.to_string(),
                exclusion: format!("approver profile `{name}`"),
            });
        };
        allowed.insert(p);
    }
    let mut counted: BTreeSet<VId> = BTreeSet::new();
    for a in approvers {
        if a.principal == preparer.principal {
            return Err(Denial::SelfApproval {
                rule: rule.to_string(),
                approver: a.principal,
            });
        }
        if !allowed.contains(&a.profile) {
            return Err(Denial::ApproverProfile {
                rule: rule.to_string(),
                approver: a.principal,
                profile: a.profile,
                allowed: req.approver_profiles.clone(),
            });
        }
        if a.op != op {
            return Err(Denial::ApproverOp {
                rule: rule.to_string(),
                approver: a.principal,
                recorded: a.op,
                required: req.approver_op.clone(),
            });
        }
        if !counted.insert(a.principal) {
            return Err(Denial::DuplicateApprover {
                rule: rule.to_string(),
                approver: a.principal,
            });
        }
        if in_case && case_preparers.is_some_and(|p| p.contains(&a.principal)) {
            return Err(Denial::CasePreparer {
                rule: rule.to_string(),
                approver: a.principal,
            });
        }
    }
    let required = matrix_approvals.max(req.approvers);
    if counted.len() < usize::from(required) {
        return Err(Denial::TooFewApprovals {
            rule: rule.to_string(),
            required,
            supplied: counted.len(),
        });
    }
    if preparer.profile == Profile::Agent {
        let humans = approvers
            .iter()
            .filter(|a| a.profile == Profile::Human)
            .count();
        if humans < usize::from(req.agent_prepared_human_approvers) {
            return Err(Denial::HumanApproversRequired {
                rule: rule.to_string(),
                required: req.agent_prepared_human_approvers,
                supplied: humans,
            });
        }
    }
    Ok(())
}

// ============================================================================
// Steward Authority Laws (`fa-s30`):
// 1. Conserved rights (`held + available + spent == total`)
// 2. Single-use permits bound to an immutable payload (`confirm_plan`)
// 3. Judgment caching with commit-range emptiness witnesses (`PlanInvalidated`)
// 4. Authority-graph dominators & minimum vertex cut SoD proof
// ============================================================================

pub const PERMIT_DOMAIN: &[u8] = b"fa:steward-permit:v1";
pub const EMPTINESS_WITNESS_DOMAIN: &[u8] = b"fa:emptiness-witness:v1";
pub const DECISION_CLOSURE_DOMAIN: &[u8] = b"fa:steward-decision-closure:v1";
pub const SOD_GRAPH_PROOF_DOMAIN: &[u8] = b"fa:sod-graph-proof:v1";

/// Violation of the Steward conserved-rights invariant
/// (`held + available + spent == total`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RightViolation {
    /// Total capacity or a requested delta is non-positive (`<= 0`).
    NonPositiveAmount { amount: i128 },
    /// Checked integer arithmetic overflowed `i128`.
    ArithmeticOverflow,
    /// Attempted to reserve or spend more than `available`.
    InsufficientAvailable { requested: i128, available: i128 },
    /// Attempted to reserve under an already-active `hold_id`.
    DuplicateHold { hold_id: Id128 },
    /// Attempted to release or commit an unknown `hold_id`.
    UnknownHold { hold_id: Id128 },
    /// Attempted to release or commit more than the hold's reserved amount.
    ExceedsHeld {
        hold_id: Id128,
        requested: i128,
        held: i128,
    },
    /// Attempted to record a duplicate direct spend receipt.
    DuplicateReceipt { receipt_id: Id128 },
    /// Conservation equation `held + available + spent == total` was broken.
    ConservationBroken {
        held: i128,
        available: i128,
        spent: i128,
        total: i128,
    },
}

/// Conserved-rights pool for a capability root's bounded ceiling / escrow
/// capacity in a single `UnitId` (`held + available + spent == total`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConservedRightsPool {
    root_commitment: [u8; 32],
    unit: UnitId,
    total: i128,
    available: i128,
    held: i128,
    spent: i128,
    holds: BTreeMap<Id128, i128>,
    receipts: BTreeMap<Id128, i128>,
}

impl ConservedRightsPool {
    /// Create a conserved-rights pool with positive `total` capacity.
    /// Initially `available = total`, `held = 0`, `spent = 0`.
    pub fn new(
        root_commitment: [u8; 32],
        unit: UnitId,
        total: i128,
    ) -> Result<Self, RightViolation> {
        if total <= 0 {
            return Err(RightViolation::NonPositiveAmount { amount: total });
        }
        Ok(Self {
            root_commitment,
            unit,
            total,
            available: total,
            held: 0,
            spent: 0,
            holds: BTreeMap::new(),
            receipts: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn root_commitment(&self) -> [u8; 32] {
        self.root_commitment
    }

    #[must_use]
    pub fn unit(&self) -> UnitId {
        self.unit
    }

    #[must_use]
    pub fn total(&self) -> i128 {
        self.total
    }

    #[must_use]
    pub fn available(&self) -> i128 {
        self.available
    }

    #[must_use]
    pub fn held(&self) -> i128 {
        self.held
    }

    #[must_use]
    pub fn spent(&self) -> i128 {
        self.spent
    }

    #[must_use]
    pub fn holds(&self) -> &BTreeMap<Id128, i128> {
        &self.holds
    }

    #[must_use]
    pub fn receipts(&self) -> &BTreeMap<Id128, i128> {
        &self.receipts
    }

    /// Reserve `amount` (`> 0`) from `available` into escrow hold `hold_id`.
    pub fn reserve(&mut self, hold_id: Id128, amount: i128) -> Result<(), RightViolation> {
        if amount <= 0 {
            return Err(RightViolation::NonPositiveAmount { amount });
        }
        if self.holds.contains_key(&hold_id) {
            return Err(RightViolation::DuplicateHold { hold_id });
        }
        if amount > self.available {
            return Err(RightViolation::InsufficientAvailable {
                requested: amount,
                available: self.available,
            });
        }
        let next_available = self
            .available
            .checked_sub(amount)
            .ok_or(RightViolation::ArithmeticOverflow)?;
        let next_held = self
            .held
            .checked_add(amount)
            .ok_or(RightViolation::ArithmeticOverflow)?;
        self.available = next_available;
        self.held = next_held;
        self.holds.insert(hold_id, amount);
        self.check_invariant()
    }

    /// Release `amount` (`> 0`) from escrow hold `hold_id` back to `available`.
    pub fn release(&mut self, hold_id: Id128, amount: i128) -> Result<(), RightViolation> {
        if amount <= 0 {
            return Err(RightViolation::NonPositiveAmount { amount });
        }
        let held_by_id = *self
            .holds
            .get(&hold_id)
            .ok_or(RightViolation::UnknownHold { hold_id })?;
        if amount > held_by_id {
            return Err(RightViolation::ExceedsHeld {
                hold_id,
                requested: amount,
                held: held_by_id,
            });
        }
        let next_held = self
            .held
            .checked_sub(amount)
            .ok_or(RightViolation::ArithmeticOverflow)?;
        let next_available = self
            .available
            .checked_add(amount)
            .ok_or(RightViolation::ArithmeticOverflow)?;
        let remaining = held_by_id - amount;
        self.held = next_held;
        self.available = next_available;
        if remaining == 0 {
            self.holds.remove(&hold_id);
        } else {
            self.holds.insert(hold_id, remaining);
        }
        self.check_invariant()
    }

    /// Convert an active escrow hold `hold_id` into a committed spend of
    /// `spend_amount` (`> 0` and `<= held_by_id`), returning any unused
    /// remainder `held_by_id - spend_amount` back to `available`.
    pub fn commit_hold(
        &mut self,
        hold_id: Id128,
        spend_amount: i128,
    ) -> Result<(), RightViolation> {
        if spend_amount <= 0 {
            return Err(RightViolation::NonPositiveAmount {
                amount: spend_amount,
            });
        }
        if self.receipts.contains_key(&hold_id) {
            return Err(RightViolation::DuplicateReceipt {
                receipt_id: hold_id,
            });
        }
        let held_by_id = *self
            .holds
            .get(&hold_id)
            .ok_or(RightViolation::UnknownHold { hold_id })?;
        if spend_amount > held_by_id {
            return Err(RightViolation::ExceedsHeld {
                hold_id,
                requested: spend_amount,
                held: held_by_id,
            });
        }
        let refund = held_by_id - spend_amount;
        let next_held = self
            .held
            .checked_sub(held_by_id)
            .ok_or(RightViolation::ArithmeticOverflow)?;
        let next_spent = self
            .spent
            .checked_add(spend_amount)
            .ok_or(RightViolation::ArithmeticOverflow)?;
        let next_available = self
            .available
            .checked_add(refund)
            .ok_or(RightViolation::ArithmeticOverflow)?;
        self.holds.remove(&hold_id);
        self.receipts.insert(hold_id, spend_amount);
        self.held = next_held;
        self.spent = next_spent;
        self.available = next_available;
        self.check_invariant()
    }

    /// Directly charge `amount` (`> 0`) from `available` to `spent` under
    /// `receipt_id` (`UsageCell` / `UsageDebit`).
    pub fn spend_direct(&mut self, receipt_id: Id128, amount: i128) -> Result<(), RightViolation> {
        if amount <= 0 {
            return Err(RightViolation::NonPositiveAmount { amount });
        }
        if self.receipts.contains_key(&receipt_id) || self.holds.contains_key(&receipt_id) {
            return Err(RightViolation::DuplicateReceipt { receipt_id });
        }
        if amount > self.available {
            return Err(RightViolation::InsufficientAvailable {
                requested: amount,
                available: self.available,
            });
        }
        let next_available = self
            .available
            .checked_sub(amount)
            .ok_or(RightViolation::ArithmeticOverflow)?;
        let next_spent = self
            .spent
            .checked_add(amount)
            .ok_or(RightViolation::ArithmeticOverflow)?;
        self.available = next_available;
        self.spent = next_spent;
        self.receipts.insert(receipt_id, amount);
        self.check_invariant()
    }

    /// Verify the conservation invariant:
    /// `held >= 0`, `available >= 0`, `spent >= 0`, `sum(holds) == held`,
    /// `sum(receipts) == spent`, and `held + available + spent == total`.
    pub fn check_invariant(&self) -> Result<(), RightViolation> {
        if self.total <= 0 || self.held < 0 || self.available < 0 || self.spent < 0 {
            return Err(RightViolation::ConservationBroken {
                held: self.held,
                available: self.available,
                spent: self.spent,
                total: self.total,
            });
        }
        let mut holds_sum: i128 = 0;
        for &v in self.holds.values() {
            if v <= 0 {
                return Err(RightViolation::NonPositiveAmount { amount: v });
            }
            holds_sum = holds_sum
                .checked_add(v)
                .ok_or(RightViolation::ArithmeticOverflow)?;
        }
        let mut receipts_sum: i128 = 0;
        for &v in self.receipts.values() {
            if v <= 0 {
                return Err(RightViolation::NonPositiveAmount { amount: v });
            }
            receipts_sum = receipts_sum
                .checked_add(v)
                .ok_or(RightViolation::ArithmeticOverflow)?;
        }
        let sum = self
            .held
            .checked_add(self.available)
            .and_then(|s| s.checked_add(self.spent))
            .ok_or(RightViolation::ArithmeticOverflow)?;
        if holds_sum != self.held || receipts_sum != self.spent || sum != self.total {
            return Err(RightViolation::ConservationBroken {
                held: self.held,
                available: self.available,
                spent: self.spent,
                total: self.total,
            });
        }
        Ok(())
    }
}

/// Witness proving that the half-open commit range `(planned_at, commit_at]`
/// contains no mutations to a cached judgment's watched keys and no security
/// policy epoch transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmptinessWitness {
    pub judgment_id: Id128,
    pub planned_at: CommitSeq,
    pub commit_at: CommitSeq,
    pub security_policy_epoch: u64,
    pub watched_keys_digest: [u8; 32],
    pub witness_digest: [u8; 32],
}

/// Cached authorization / plan judgment recorded at `planned_at` over an
/// explicit set of watched state keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedJudgment {
    pub judgment_id: Id128,
    pub book_id: Id128,
    pub payload_digest: [u8; 32],
    pub planned_at: CommitSeq,
    pub security_policy_epoch: u64,
    pub watched_keys: BTreeSet<[u8; 32]>,
}

impl CachedJudgment {
    #[must_use]
    pub fn watched_keys_digest(&self) -> [u8; 32] {
        let mut w = Writer::with_capacity(4 + self.watched_keys.len() * 32);
        let keys: Vec<[u8; 32]> = self.watched_keys.iter().copied().collect();
        w.list(&keys, |w, k| {
            w.fixed(k);
        });
        let bytes = w.finish().expect("bounded watched keys");
        domain_digest(EMPTINESS_WITNESS_DOMAIN, &[b"watched_keys", &bytes])
    }
}

/// Judgment cache tracking cached plan judgments and commit-stream mutation
/// events `(CommitSeq, mutated_keys, security_policy_epoch)` to issue
/// range-emptiness witnesses or `PlanInvalidated` refusals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JudgmentCache {
    judgments: BTreeMap<Id128, CachedJudgment>,
    commits: BTreeMap<CommitSeq, (BTreeSet<[u8; 32]>, u64)>,
}

impl JudgmentCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a cached judgment at `judgment.planned_at`.
    pub fn insert_judgment(&mut self, judgment: CachedJudgment) {
        self.judgments.insert(judgment.judgment_id, judgment);
    }

    /// Record the mutated state keys and active `security_policy_epoch` at `seq`.
    pub fn record_commit(
        &mut self,
        seq: CommitSeq,
        mutated_keys: BTreeSet<[u8; 32]>,
        security_policy_epoch: u64,
    ) {
        self.commits
            .insert(seq, (mutated_keys, security_policy_epoch));
    }

    /// Verify that the half-open commit interval `(planned_at, commit_at]` is
    /// empty of any mutation touching `judgment.watched_keys` and that
    /// `current_epoch == judgment.security_policy_epoch`.
    pub fn verify_emptiness(
        &self,
        judgment_id: Id128,
        commit_at: CommitSeq,
        current_epoch: u64,
    ) -> Result<EmptinessWitness, PermitDenial> {
        let j = self
            .judgments
            .get(&judgment_id)
            .ok_or(PermitDenial::UnknownJudgment { judgment_id })?;
        if commit_at < j.planned_at {
            return Err(PermitDenial::RegressionAtCommit {
                planned_at: j.planned_at,
                commit_at,
            });
        }
        if current_epoch != j.security_policy_epoch {
            return Err(PermitDenial::EpochMismatch {
                permit_epoch: j.security_policy_epoch,
                current_epoch,
            });
        }
        for (&seq, (mutated, epoch)) in &self.commits {
            if seq > j.planned_at && seq <= commit_at {
                if *epoch != j.security_policy_epoch {
                    return Err(PermitDenial::EpochMismatch {
                        permit_epoch: j.security_policy_epoch,
                        current_epoch: *epoch,
                    });
                }
                if let Some(&key) = j.watched_keys.intersection(mutated).next() {
                    return Err(PermitDenial::InvalidatedByMutation {
                        judgment_id,
                        conflicting_seq: seq,
                        conflicting_key: key,
                    });
                }
            }
        }
        let watched_keys_digest = j.watched_keys_digest();
        let witness_digest = domain_digest(
            EMPTINESS_WITNESS_DOMAIN,
            &[
                &j.judgment_id.0,
                &j.book_id.0,
                &j.payload_digest,
                &j.planned_at.0.to_le_bytes(),
                &commit_at.0.to_le_bytes(),
                &j.security_policy_epoch.to_le_bytes(),
                &watched_keys_digest,
            ],
        );
        Ok(EmptinessWitness {
            judgment_id,
            planned_at: j.planned_at,
            commit_at,
            security_policy_epoch: j.security_policy_epoch,
            watched_keys_digest,
            witness_digest,
        })
    }
}

/// One-shot permit bound to an immutable payload (`confirm_plan`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleUsePermit {
    pub permit_id: Id128,
    pub book_id: Id128,
    pub holder: VId,
    pub profile: Profile,
    pub op: Op,
    pub capability_commitment: [u8; 32],
    pub payload_digest: [u8; 32],
    pub judgment_id: Id128,
    pub security_policy_epoch: u64,
    pub issued_at: CommitSeq,
    pub expires_at: Option<CommitSeq>,
}

/// Refusal when issuing or consuming a [`SingleUsePermit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PermitDenial {
    /// Underlying admission or capability check refused the permit.
    Policy(Denial),
    /// The permit has already been consumed at `consumed_at` (one-shot law).
    AlreadyConsumed {
        permit_digest: [u8; 32],
        consumed_at: CommitSeq,
    },
    /// The presented payload, book, holder, or op does not match the permit's
    /// bound payload (`confirm_plan` immutability law).
    PayloadMismatch {
        expected_payload: [u8; 32],
        presented_payload: [u8; 32],
    },
    /// The presented book does not match the permit's bound book.
    BookMismatch {
        expected_book: Id128,
        presented_book: Id128,
    },
    /// The acting principal or op does not match the permit.
    ActorOrOpMismatch {
        expected_holder: VId,
        presented_holder: VId,
        expected_op: Op,
        presented_op: Op,
    },
    /// The security policy epoch changed since the permit / judgment was minted.
    EpochMismatch {
        permit_epoch: u64,
        current_epoch: u64,
    },
    /// The permit expired at or before `commit_at`.
    Expired {
        expires_at: CommitSeq,
        commit_at: CommitSeq,
    },
    /// The cached judgment referenced by the permit is unknown.
    UnknownJudgment { judgment_id: Id128 },
    /// Commit sequence regressed below `planned_at`.
    RegressionAtCommit {
        planned_at: CommitSeq,
        commit_at: CommitSeq,
    },
    /// A commit in `(planned_at, commit_at]` mutated a watched key (`PlanInvalidated`).
    InvalidatedByMutation {
        judgment_id: Id128,
        conflicting_seq: CommitSeq,
        conflicting_key: [u8; 32],
    },
}

/// Certified decision closure emitted when a [`SingleUsePermit`] is consumed
/// together with a valid [`EmptinessWitness`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionClosure {
    pub permit_digest: [u8; 32],
    pub payload_digest: [u8; 32],
    pub book_id: Id128,
    pub holder: VId,
    pub op: Op,
    pub commit_at: CommitSeq,
    pub security_policy_epoch: u64,
    pub emptiness_witness_digest: [u8; 32],
    pub closure_digest: [u8; 32],
}

impl SingleUsePermit {
    /// Issue a one-shot permit bound to `judgment` (`book_id`, `payload_digest`,
    /// `judgment_id`, `security_policy_epoch`) under `cap` at `issued_at`. An
    /// `Agent`-profile capability is refused on trunk write permits
    /// (`Denial::AgentOnTrunk`).
    pub fn issue(
        cap: &Capability,
        permit_id: Id128,
        op: Op,
        judgment: &CachedJudgment,
        issued_at: CommitSeq,
    ) -> Result<Result<Self, PermitDenial>, CapabilityError> {
        if cap.profile() == Profile::Agent && op != Op::Read && op != Op::Verify {
            return Ok(Err(PermitDenial::Policy(Denial::AgentOnTrunk)));
        }
        if let Err(d) = require(cap, op, "issuing a one-shot permit") {
            return Ok(Err(PermitDenial::Policy(d)));
        }
        if let Err(d) = scope(cap, judgment.book_id) {
            return Ok(Err(PermitDenial::Policy(d)));
        }
        if let Err(d) = current(cap, issued_at) {
            return Ok(Err(PermitDenial::Policy(d)));
        }
        Ok(Ok(Self {
            permit_id,
            book_id: judgment.book_id,
            holder: cap.holder(),
            profile: cap.profile(),
            op,
            capability_commitment: cap.commitment()?,
            payload_digest: judgment.payload_digest,
            judgment_id: judgment.judgment_id,
            security_policy_epoch: judgment.security_policy_epoch,
            issued_at,
            expires_at: cap.expires_at(),
        }))
    }

    /// Canonical BLAKE3 digest of this permit under [`PERMIT_DOMAIN`].
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let expires_tag = [u8::from(self.expires_at.is_some())];
        let expires_seq = self.expires_at.map_or(0_u64, |s| s.0).to_le_bytes();
        domain_digest(
            PERMIT_DOMAIN,
            &[
                &self.permit_id.0,
                &self.book_id.0,
                &self.holder.0.to_le_bytes(),
                &[self.profile.tag()],
                &[self.op.tag()],
                &self.capability_commitment,
                &self.payload_digest,
                &self.judgment_id.0,
                &self.security_policy_epoch.to_le_bytes(),
                &self.issued_at.0.to_le_bytes(),
                &expires_tag,
                &expires_seq,
            ],
        )
    }
}

/// Target effect context presented when consuming a [`SingleUsePermit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermitTarget {
    pub book_id: Id128,
    pub actor: VId,
    pub op: Op,
    pub payload_digest: [u8; 32],
    pub commit_at: CommitSeq,
    pub current_epoch: u64,
}

/// Gate enforcing one-shot consumption and payload immutability of
/// [`SingleUsePermit`]s.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PermitGate {
    consumed: BTreeMap<[u8; 32], CommitSeq>,
}

impl PermitGate {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `permit_digest` has already been consumed.
    #[must_use]
    pub fn is_consumed(&self, permit_digest: &[u8; 32]) -> Option<CommitSeq> {
        self.consumed.get(permit_digest).copied()
    }

    /// Consume `permit` against `target`, verifying the cached judgment's
    /// range-emptiness witness before recording consumption.
    pub fn consume(
        &mut self,
        permit: &SingleUsePermit,
        target: &PermitTarget,
        cache: &JudgmentCache,
    ) -> Result<DecisionClosure, PermitDenial> {
        let permit_digest = permit.digest();
        if let Some(consumed_at) = self.consumed.get(&permit_digest).copied() {
            return Err(PermitDenial::AlreadyConsumed {
                permit_digest,
                consumed_at,
            });
        }
        if permit.book_id != target.book_id {
            return Err(PermitDenial::BookMismatch {
                expected_book: permit.book_id,
                presented_book: target.book_id,
            });
        }
        if permit.holder != target.actor || permit.op != target.op {
            return Err(PermitDenial::ActorOrOpMismatch {
                expected_holder: permit.holder,
                presented_holder: target.actor,
                expected_op: permit.op,
                presented_op: target.op,
            });
        }
        if permit.payload_digest != target.payload_digest {
            return Err(PermitDenial::PayloadMismatch {
                expected_payload: permit.payload_digest,
                presented_payload: target.payload_digest,
            });
        }
        if permit.security_policy_epoch != target.current_epoch {
            return Err(PermitDenial::EpochMismatch {
                permit_epoch: permit.security_policy_epoch,
                current_epoch: target.current_epoch,
            });
        }
        if let Some(expires_at) = permit.expires_at
            && target.commit_at >= expires_at
        {
            return Err(PermitDenial::Expired {
                expires_at,
                commit_at: target.commit_at,
            });
        }
        let witness =
            cache.verify_emptiness(permit.judgment_id, target.commit_at, target.current_epoch)?;
        self.consumed.insert(permit_digest, target.commit_at);
        let closure_digest = domain_digest(
            DECISION_CLOSURE_DOMAIN,
            &[
                &permit_digest,
                &target.payload_digest,
                &target.book_id.0,
                &target.actor.0.to_le_bytes(),
                &[target.op.tag()],
                &target.commit_at.0.to_le_bytes(),
                &target.current_epoch.to_le_bytes(),
                &witness.witness_digest,
            ],
        );
        Ok(DecisionClosure {
            permit_digest,
            payload_digest: target.payload_digest,
            book_id: target.book_id,
            holder: target.actor,
            op: target.op,
            commit_at: target.commit_at,
            security_policy_epoch: target.current_epoch,
            emptiness_witness_digest: witness.witness_digest,
            closure_digest,
        })
    }
}

/// Vertex in the Steward authority graph (`fa-s30`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorityVertex {
    /// A principal (`Human`, `Agent`, or `System`).
    Principal { vid: VId, profile: Profile },
    /// A capability held by `holder` with `profile` and granted `ops`.
    CapabilityNode {
        id: Id128,
        holder: VId,
        profile: Profile,
        ops: BTreeSet<Op>,
    },
    /// An approval gate binding `proposal_digest` under `approver` (`profile`, `op`).
    ApprovalGate {
        approval_vid: VId,
        approver: VId,
        profile: Profile,
        op: Op,
        proposal_digest: [u8; 32],
    },
    /// A guarded trunk effect (`post`, `close`, `reopen`, `restate`, etc.)
    /// bound to `proposal_digest`.
    TargetEffect {
        effect_vid: VId,
        op: Op,
        proposal_digest: [u8; 32],
    },
}

impl AuthorityVertex {
    /// The vertex identifier in the authority graph.
    #[must_use]
    pub fn vid(&self) -> VId {
        match self {
            Self::Principal { vid, .. } => *vid,
            Self::CapabilityNode { id, .. } => VId(u128::from_le_bytes(id.0)),
            Self::ApprovalGate { approval_vid, .. } => *approval_vid,
            Self::TargetEffect { effect_vid, .. } => *effect_vid,
        }
    }
}

/// Separation-of-duties violation detected on an [`AuthorityGraph`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SodBypassViolation {
    /// Either the source principal or the target effect vertex is missing.
    MissingEndpoint { endpoint: VId },
    /// The target effect is completely unreachable from the source principal.
    UnreachableTarget { source: VId, target: VId },
    /// A path from `source` to `target` bypasses all admissible `Human`
    /// `ApprovalGate` vertices (for example, a direct capability edge, a
    /// self-approved gate, a non-Human approval gate, or a gate bound to a
    /// different proposal digest).
    BypassPath {
        source: VId,
        target: VId,
        bypass_path: Vec<VId>,
    },
    /// No single admissible `ApprovalGate` dominates `target` along all paths,
    /// or fewer than `required_dominators` approval gates dominate `target`.
    InsufficientDominatingApprovals {
        required: usize,
        dominating: Vec<VId>,
    },
    /// Fewer distinct `Human` approver principals exist on the minimum cut /
    /// dominating chain than required.
    InsufficientDistinctHumanApprovers {
        required: usize,
        approvers: Vec<VId>,
    },
}

/// Certified dominator + minimum-cut Separation-of-Duties proof over an
/// [`AuthorityGraph`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SodGraphProof {
    pub source_principal: VId,
    pub source_profile: Profile,
    pub target_effect: VId,
    pub target_op: Op,
    pub proposal_digest: [u8; 32],
    /// Admissible `ApprovalGate` vertices that strictly dominate `target_effect`
    /// on every path from `source_principal`, in topological / dominator order.
    pub dominating_approvals: Vec<VId>,
    /// Minimum `s-t` vertex cut composed of admissible `ApprovalGate` vertices
    /// whose removal disconnects `source_principal` from `target_effect`.
    pub min_approval_cut: Vec<VId>,
    /// Distinct `Human` approver principals across the dominating / cut gates.
    pub distinct_human_approvers: Vec<VId>,
    /// Canonical BLAKE3 proof digest under [`SOD_GRAPH_PROOF_DOMAIN`].
    pub proof_digest: [u8; 32],
}

/// Directed authority graph over principals, capabilities, approval gates, and
/// guarded effects (`fa-s30`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthorityGraph {
    vertices: BTreeMap<VId, AuthorityVertex>,
    edges: BTreeMap<VId, BTreeSet<VId>>,
}

impl AuthorityGraph {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a vertex into the authority graph.
    pub fn add_vertex(&mut self, vertex: AuthorityVertex) -> VId {
        let v = vertex.vid();
        self.vertices.insert(v, vertex);
        self.edges.entry(v).or_default();
        v
    }

    /// Add a directed authority edge `from -> to`.
    pub fn add_edge(&mut self, from: VId, to: VId) {
        self.edges.entry(from).or_default().insert(to);
        self.edges.entry(to).or_default();
    }

    #[must_use]
    pub fn vertices(&self) -> &BTreeMap<VId, AuthorityVertex> {
        &self.vertices
    }

    #[must_use]
    pub fn edges(&self) -> &BTreeMap<VId, BTreeSet<VId>> {
        &self.edges
    }

    /// Whether `gate_vid` is an admissible SoD approval gate for
    /// `(source_principal, proposal_digest)`:
    /// - must be an `AuthorityVertex::ApprovalGate`,
    /// - `approver != source_principal` (no self-approval),
    /// - `profile == Profile::Human` (attributable human judgment),
    /// - `op == Op::Approve`,
    /// - `gate.proposal_digest == proposal_digest` (bound to the exact proposal).
    #[must_use]
    pub fn is_admissible_approval_gate(
        &self,
        gate_vid: VId,
        source_principal: VId,
        proposal_digest: &[u8; 32],
    ) -> Option<VId> {
        match self.vertices.get(&gate_vid) {
            Some(AuthorityVertex::ApprovalGate {
                approver,
                profile: Profile::Human,
                op: Op::Approve,
                proposal_digest: bound_digest,
                ..
            }) if *approver != source_principal && bound_digest == proposal_digest => {
                Some(*approver)
            }
            _ => None,
        }
    }

    /// Compute the exact dominator map `dom[v]` for all vertices reachable from
    /// `source` using iterative dataflow intersection in deterministic `VId`
    /// order.
    #[must_use]
    pub fn dominators_from(&self, source: VId) -> BTreeMap<VId, BTreeSet<VId>> {
        let mut reachable = BTreeSet::new();
        let mut queue = VecDeque::new();
        if self.vertices.contains_key(&source) {
            reachable.insert(source);
            queue.push_back(source);
        }
        while let Some(u) = queue.pop_front() {
            if let Some(succs) = self.edges.get(&u) {
                for &v in succs {
                    if self.vertices.contains_key(&v) && reachable.insert(v) {
                        queue.push_back(v);
                    }
                }
            }
        }
        let mut preds: BTreeMap<VId, Vec<VId>> = BTreeMap::new();
        for &u in &reachable {
            preds.entry(u).or_default();
        }
        for &u in &reachable {
            if let Some(succs) = self.edges.get(&u) {
                for &v in succs {
                    if reachable.contains(&v) {
                        preds.entry(v).or_default().push(u);
                    }
                }
            }
        }
        let mut dom: BTreeMap<VId, BTreeSet<VId>> = BTreeMap::new();
        for &v in &reachable {
            if v == source {
                dom.insert(v, BTreeSet::from([source]));
            } else {
                dom.insert(v, reachable.clone());
            }
        }
        let mut changed = true;
        while changed {
            changed = false;
            for &v in &reachable {
                if v == source {
                    continue;
                }
                let Some(ps) = preds.get(&v) else {
                    continue;
                };
                let mut iter = ps.iter().filter_map(|p| dom.get(p));
                let Some(first) = iter.next() else {
                    continue;
                };
                let mut next_dom = first.clone();
                for other in iter {
                    next_dom = next_dom.intersection(other).copied().collect();
                }
                next_dom.insert(v);
                if dom.get(&v) != Some(&next_dom) {
                    dom.insert(v, next_dom);
                    changed = true;
                }
            }
        }
        dom
    }

    /// Shortest path from `source` to `target` avoiding `forbidden` vertices.
    fn shortest_path_avoiding(
        &self,
        source: VId,
        target: VId,
        forbidden: &BTreeSet<VId>,
    ) -> Option<Vec<VId>> {
        if forbidden.contains(&source) || forbidden.contains(&target) {
            return None;
        }
        let mut parent: BTreeMap<VId, VId> = BTreeMap::new();
        let mut visited: BTreeSet<VId> = BTreeSet::from([source]);
        let mut queue = VecDeque::from([source]);
        while let Some(u) = queue.pop_front() {
            if u == target {
                let mut path = vec![target];
                let mut cur = target;
                while let Some(&p) = parent.get(&cur) {
                    path.push(p);
                    if p == source {
                        break;
                    }
                    cur = p;
                }
                path.reverse();
                return Some(path);
            }
            if let Some(succs) = self.edges.get(&u) {
                for &v in succs {
                    if self.vertices.contains_key(&v)
                        && !forbidden.contains(&v)
                        && visited.insert(v)
                    {
                        parent.insert(v, u);
                        queue.push_back(v);
                    }
                }
            }
        }
        None
    }

    /// Compute the minimum `s-t` vertex cut over `admissible_gates` using
    /// deterministic Edmonds-Karp max-flow / min-cut on the node-split network.
    ///
    /// Every vertex `v` in `admissible_gates` has split capacity `1`
    /// (`v_in -> v_out`); all other vertices and edges have unbounded capacity
    /// (`usize::MAX / 4`), because caller has already verified no 0-gate bypass
    /// path exists.
    fn min_approval_vertex_cut(
        &self,
        source: VId,
        target: VId,
        admissible_gates: &BTreeSet<VId>,
    ) -> Vec<VId> {
        let vertices: Vec<VId> = self.vertices.keys().copied().collect();
        let n = vertices.len();
        let idx_of: BTreeMap<VId, usize> = vertices
            .iter()
            .copied()
            .enumerate()
            .map(|(i, v)| (v, i))
            .collect();
        let (Some(&s_idx), Some(&t_idx)) = (idx_of.get(&source), idx_of.get(&target)) else {
            return Vec::new();
        };
        // Node-split indexing: for vertex index `i`, `in_node = 2 * i`, `out_node = 2 * i + 1`.
        let total_nodes = 2 * n;
        let inf = n + 1;
        let mut cap = vec![vec![0_usize; total_nodes]; total_nodes];
        for (i, &v) in vertices.iter().enumerate() {
            let v_in = 2 * i;
            let v_out = 2 * i + 1;
            cap[v_in][v_out] = if admissible_gates.contains(&v) {
                1
            } else {
                inf
            };
        }
        for (&u, succs) in &self.edges {
            let Some(&u_i) = idx_of.get(&u) else {
                continue;
            };
            for &v in succs {
                if let Some(&v_i) = idx_of.get(&v) {
                    cap[2 * u_i + 1][2 * v_i] = inf;
                }
            }
        }
        let s_out = 2 * s_idx + 1;
        let t_in = 2 * t_idx;
        let mut flow = vec![vec![0_isize; total_nodes]; total_nodes];

        loop {
            let mut parent: Vec<Option<usize>> = vec![None; total_nodes];
            let mut queue = VecDeque::new();
            parent[s_out] = Some(s_out);
            queue.push_back(s_out);
            while let Some(u) = queue.pop_front() {
                if u == t_in {
                    break;
                }
                for v in 0..total_nodes {
                    let residual = cap[u][v] as isize - flow[u][v];
                    if parent[v].is_none() && residual > 0 {
                        parent[v] = Some(u);
                        queue.push_back(v);
                    }
                }
            }
            if parent[t_in].is_none() {
                break;
            }
            let mut push = inf as isize;
            let mut cur = t_in;
            while cur != s_out {
                let p = parent[cur].expect("path parent");
                let residual = cap[p][cur] as isize - flow[p][cur];
                push = push.min(residual);
                cur = p;
            }
            let mut cur = t_in;
            while cur != s_out {
                let p = parent[cur].expect("path parent");
                flow[p][cur] += push;
                flow[cur][p] -= push;
                cur = p;
            }
        }

        // Reachable set in the residual network from `s_out`.
        let mut visited = vec![false; total_nodes];
        let mut queue = VecDeque::from([s_out]);
        visited[s_out] = true;
        while let Some(u) = queue.pop_front() {
            for v in 0..total_nodes {
                let residual = cap[u][v] as isize - flow[u][v];
                if !visited[v] && residual > 0 {
                    visited[v] = true;
                    queue.push_back(v);
                }
            }
        }

        let mut cut = Vec::new();
        for (i, &v) in vertices.iter().enumerate() {
            if admissible_gates.contains(&v) && visited[2 * i] && !visited[2 * i + 1] {
                cut.push(v);
            }
        }
        cut
    }

    /// Prove Separation of Duties between `source_principal` and `target_effect`:
    /// 1. `target_effect` is reachable from `source_principal`;
    /// 2. Removing all admissible `Human` `Op::Approve` gates bound to
    ///    `target_effect.proposal_digest` with `approver != source_principal`
    ///    leaves **zero** bypass paths (`SodBypassViolation::BypassPath` returns
    ///    the shortest bypass path when one exists);
    /// 3. At least `required_dominators` admissible approval gates strictly
    ///    dominate `target_effect` on all paths from `source_principal`;
    /// 4. At least `required_distinct_humans` distinct `Human` approver
    ///    principals participate in the dominating / min-cut approval gates.
    pub fn prove_sod(
        &self,
        source_principal: VId,
        target_effect: VId,
        required_dominators: usize,
        required_distinct_humans: usize,
    ) -> Result<SodGraphProof, SodBypassViolation> {
        let Some(AuthorityVertex::Principal {
            profile: source_profile,
            ..
        }) = self.vertices.get(&source_principal)
        else {
            return Err(SodBypassViolation::MissingEndpoint {
                endpoint: source_principal,
            });
        };
        let Some(AuthorityVertex::TargetEffect {
            op: target_op,
            proposal_digest,
            ..
        }) = self.vertices.get(&target_effect)
        else {
            return Err(SodBypassViolation::MissingEndpoint {
                endpoint: target_effect,
            });
        };

        let dom_map = self.dominators_from(source_principal);
        let Some(target_doms) = dom_map.get(&target_effect) else {
            return Err(SodBypassViolation::UnreachableTarget {
                source: source_principal,
                target: target_effect,
            });
        };

        let mut admissible_gates = BTreeSet::new();
        for &v in self.vertices.keys() {
            if self
                .is_admissible_approval_gate(v, source_principal, proposal_digest)
                .is_some()
            {
                admissible_gates.insert(v);
            }
        }

        // Check if any path from `source_principal` to `target_effect` avoids all admissible gates.
        if let Some(bypass_path) =
            self.shortest_path_avoiding(source_principal, target_effect, &admissible_gates)
        {
            return Err(SodBypassViolation::BypassPath {
                source: source_principal,
                target: target_effect,
                bypass_path,
            });
        }

        // Dominating approval gates ordered by dominator depth (number of dominators).
        let mut dominating_approvals: Vec<VId> = target_doms
            .iter()
            .copied()
            .filter(|v| admissible_gates.contains(v))
            .collect();
        dominating_approvals.sort_by_key(|v| (dom_map.get(v).map_or(0, BTreeSet::len), v.0));

        if dominating_approvals.len() < required_dominators {
            return Err(SodBypassViolation::InsufficientDominatingApprovals {
                required: required_dominators,
                dominating: dominating_approvals,
            });
        }

        let min_approval_cut =
            self.min_approval_vertex_cut(source_principal, target_effect, &admissible_gates);

        let mut human_approver_set = BTreeSet::new();
        for &gate_vid in dominating_approvals.iter().chain(min_approval_cut.iter()) {
            if let Some(approver) =
                self.is_admissible_approval_gate(gate_vid, source_principal, proposal_digest)
            {
                human_approver_set.insert(approver);
            }
        }
        let distinct_human_approvers: Vec<VId> = human_approver_set.into_iter().collect();
        if distinct_human_approvers.len() < required_distinct_humans {
            return Err(SodBypassViolation::InsufficientDistinctHumanApprovers {
                required: required_distinct_humans,
                approvers: distinct_human_approvers,
            });
        }

        let mut w = Writer::with_capacity(
            16 + 1
                + 16
                + 1
                + 32
                + 4
                + dominating_approvals.len() * 16
                + 4
                + min_approval_cut.len() * 16,
        );
        w.u128(source_principal.0)
            .u8(source_profile.tag())
            .u128(target_effect.0)
            .u8(target_op.tag())
            .fixed(proposal_digest)
            .list(&dominating_approvals, |w, v| {
                w.u128(v.0);
            })
            .list(&min_approval_cut, |w, v| {
                w.u128(v.0);
            })
            .list(&distinct_human_approvers, |w, v| {
                w.u128(v.0);
            });
        let proof_bytes = w.finish().expect("bounded SoD graph proof");
        let proof_digest = domain_digest(SOD_GRAPH_PROOF_DOMAIN, &[&proof_bytes]);

        Ok(SodGraphProof {
            source_principal,
            source_profile: *source_profile,
            target_effect,
            target_op: *target_op,
            proposal_digest: *proposal_digest,
            dominating_approvals,
            min_approval_cut,
            distinct_human_approvers,
            proof_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(approvers: u8, agent_humans: u8, exclusions: &[&str]) -> SodRequirement {
        SodRequirement {
            approvers,
            approver_op: "approve".into(),
            approver_profiles: vec!["Human".into()],
            agent_prepared_human_approvers: agent_humans,
            exclusions: exclusions.iter().map(|s| (*s).to_string()).collect(),
            cite: "test".into(),
        }
    }

    const PREP: Party = Party {
        principal: VId(1),
        profile: Profile::Human,
    };

    fn human(p: u128) -> Approver {
        Approver {
            principal: VId(p),
            profile: Profile::Human,
            op: Op::Approve,
        }
    }

    #[test]
    fn self_approval_duplicates_and_counts_are_refused_with_the_rule_cited() {
        let r = req(1, 0, &["duplicate", "preparer"]);
        assert_eq!(evaluate("x", &r, 0, PREP, &[human(2)]), Ok(()));
        let d = evaluate("x", &r, 0, PREP, &[human(1)]).unwrap_err();
        assert_eq!((d.code(), d.kind()), ("FA-REF-008", "self_approval"));
        assert_eq!(d.cite(), "sod_policy.toml#x");
        let d = evaluate("x", &r, 0, PREP, &[human(2), human(2)]).unwrap_err();
        assert_eq!(d.kind(), "duplicate_approver");
        let d = evaluate("x", &r, 0, PREP, &[]).unwrap_err();
        assert_eq!((d.code(), d.kind()), ("FA-REF-012", "too_few_approvals"));
        // The matrix count is honoured when it exceeds the rule's.
        let d = evaluate("x", &r, 2, PREP, &[human(2)]).unwrap_err();
        assert_eq!(
            d,
            Denial::TooFewApprovals {
                rule: "x".into(),
                required: 2,
                supplied: 1
            }
        );
    }

    #[test]
    fn approver_profile_and_op_are_the_rules() {
        let r = req(0, 0, &["duplicate", "preparer"]);
        let agent = Approver {
            principal: VId(3),
            profile: Profile::Agent,
            op: Op::Approve,
        };
        assert_eq!(
            evaluate("x", &r, 0, PREP, &[agent]).unwrap_err().kind(),
            "approver_profile"
        );
        let wrong_op = Approver {
            op: Op::Verify,
            ..human(3)
        };
        assert_eq!(
            evaluate("x", &r, 0, PREP, &[wrong_op]).unwrap_err().kind(),
            "approver_op"
        );
    }

    #[test]
    fn agent_prepared_work_needs_human_approvers_and_undecidable_exclusions_fail_closed() {
        let r = req(0, 1, &["duplicate", "preparer"]);
        let agent_prep = Party {
            principal: VId(1),
            profile: Profile::Agent,
        };
        assert_eq!(evaluate("x", &r, 0, PREP, &[]), Ok(()));
        assert_eq!(
            evaluate("x", &r, 0, agent_prep, &[]).unwrap_err().kind(),
            "human_approvers"
        );
        assert_eq!(evaluate("x", &r, 0, agent_prep, &[human(2)]), Ok(()));
        let case = req(2, 0, &["case_preparer", "duplicate", "preparer"]);
        let d = evaluate("x", &case, 0, PREP, &[human(2), human(3)]).unwrap_err();
        assert_eq!(
            (d.code(), d.kind()),
            ("FA-REF-008", "unsupported_exclusion")
        );
        // With the case's preparers known the exclusion is decided: an
        // approver who prepared a case entry is refused, others count.
        let preparers: BTreeSet<VId> = [VId(3)].into_iter().collect();
        let d =
            evaluate_in("x", &case, 0, PREP, &[human(2), human(3)], Some(&preparers)).unwrap_err();
        assert_eq!((d.code(), d.kind()), ("FA-REF-008", "case_preparer"));
        assert_eq!(
            evaluate_in("x", &case, 0, PREP, &[human(2), human(4)], Some(&preparers)),
            Ok(())
        );
        // A rule without the exclusion ignores the case's preparers.
        let plain = req(2, 0, &["duplicate", "preparer"]);
        assert_eq!(
            evaluate_in(
                "x",
                &plain,
                0,
                PREP,
                &[human(2), human(3)],
                Some(&preparers)
            ),
            Ok(())
        );
    }

    #[test]
    fn keys_carry_the_disposition_only_for_resolution_posts() {
        assert_eq!(
            posting_key("Resolution", PeriodState::Closed, true)
                .disposition
                .as_deref(),
            Some("Posts")
        );
        assert_eq!(
            posting_key("Resolution", PeriodState::Closed, false).disposition,
            None
        );
        assert_eq!(
            posting_key("Reversal", PeriodState::Closed, true).disposition,
            None
        );
        assert_eq!(
            control_key("PolicyControl", None, "Activate")
                .transition
                .as_deref(),
            Some("Activate")
        );
    }
}
