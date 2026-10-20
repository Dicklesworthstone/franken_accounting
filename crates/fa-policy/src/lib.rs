//! Steward's laws (plan §14, FA-INV-10): capabilities, admission, expiry,
//! approvals, and segregation of duties.
//!
//! This is a laws-layer crate: pure functions of explicit inputs. It reads
//! no clock, no storage, no entropy, and takes no `Cx`; it depends on the
//! model and the registries and on nothing above them. The kernel calls
//! *down* into it — admission before any storage observation (post step
//! 1a), expiry at the admission point the kernel observed, and SoD at
//! commit over the approvals the kernel point-read — and maps each
//! [`Denial`] one-to-one onto its refusal envelope. Nothing here calls up.
//!
//! Layout:
//! - [`op`] — the closed op vocabulary.
//! - [`capability`] — `Profile`, the typed `Capability`, `fa:capability:v1`.
//! - [`admit`] — pre-observation admission, expiry, op requirements, and
//!   the scope caveats' reach.
//! - [`approval`] — the `fa:approval:v1` object and its binding law.
//! - [`sod`] — the SoD predicate over `sod_policy.toml` rows.
//! - [`denial`] — typed denials with code, exit, cite, and fix.

#![forbid(unsafe_code)]

pub mod admit;
pub mod approval;
pub mod bank_matching;
pub mod capability;
pub mod decision;
pub mod denial;
pub mod op;
pub mod sod;

pub use admit::{
    AccountScope, Intent, Observes, Reach, admit, admit_base, admit_base_for_plan, admit_read,
    admit_within, current, reach, require, scope,
};
pub use approval::Approval;
pub use capability::{
    Capability, CapabilityError, CapabilityToken, OperatorKind, Profile, ProfileTemplate,
    possession_digest,
};
pub use decision::{
    BenefitInterval, DECISION_CARD_DOMAIN, DecisionCandidate, DecisionCard, DecisionFeature,
    DecisionKind, DecisionPolicyRow, DecisionReason, DecisionReplayError, amounts_preserved,
    decide_bank_match, decide_lantern_threshold, decide_register_checkpoint_cadence,
    evaluate_decision,
};
pub use denial::Denial;
pub use op::Op;
pub use sod::{
    Approver, AuthorityGraph, AuthorityVertex, CachedJudgment, ConservedRightsPool,
    DECISION_CLOSURE_DOMAIN, DecisionClosure, EMPTINESS_WITNESS_DOMAIN, EmptinessWitness,
    JudgmentCache, PERMIT_DOMAIN, Party, PermitDenial, PermitGate, PermitTarget, RightViolation,
    SOD_GRAPH_PROOF_DOMAIN, SingleUsePermit, SodBypassViolation, SodGraphProof,
};

use fa_model::domain_digest;
use fa_registry::sod_policy::{SodKey, SodPolicy};
use fa_registry::{Admissibility, EntryClasses, RegistryError};

pub const POLICY_DOMAIN: &[u8] = b"fa:policy:v1";

/// The policy this build enforces: the SoD rows and their digest, the oid a
/// `PolicyActivation` journals.
#[derive(Clone, Debug)]
pub struct Steward {
    pub sod: SodPolicy,
    pub policy_oid: [u8; 32],
}

impl Steward {
    /// Load and cross-check the embedded policy.
    pub fn embedded() -> Result<Self, RegistryError> {
        let classes = EntryClasses::embedded()?;
        let matrix = Admissibility::embedded(&classes)?;
        let sod = SodPolicy::embedded(&classes, &matrix)?;
        let policy_oid = domain_digest(POLICY_DOMAIN, &[&sod.canonical_bytes()]);
        Ok(Self { sod, policy_oid })
    }

    /// SoD for the entry `key` names: its rule (or the default) over the
    /// preparer and the witnessed approvals.
    pub fn segregate(
        &self,
        key: &SodKey,
        matrix_approvals: u8,
        preparer: Party,
        approvers: &[Approver],
    ) -> Result<(), Denial> {
        let (rule, req) = self.sod.requirement(key);
        sod::evaluate(rule, req, matrix_approvals, preparer, approvers)
    }

    /// The op a control rule requires of its preparer (`None` when no rule
    /// governs `key` or the rule names no op).
    pub fn preparer_op(&self, key: &SodKey) -> Option<Op> {
        self.sod
            .rule(key)
            .and_then(|r| r.preparer_op.as_deref())
            .and_then(Op::from_name)
    }

    /// The op a control's preparer needs for `transition`, from the SoD rows
    /// (every row of one transition agrees, so this is decidable before the
    /// from-state is read). `None` when no row registers the transition: the
    /// kernel refuses it rather than treating it as unconstrained.
    pub fn transition_op(&self, class: &str, transition: &str) -> Option<Op> {
        self.sod
            .transition_op(class, transition)
            .and_then(Op::from_name)
    }

    /// A `PolicyActivation` may name only the policy this build enforces:
    /// journaling any other digest would record rules the kernel never
    /// applies (fail closed until loaded, versioned policies land).
    pub fn check_activation(&self, policy_oid: &[u8; 32]) -> Result<(), Denial> {
        if *policy_oid == self.policy_oid {
            Ok(())
        } else {
            Err(Denial::UnsupportedPolicy {
                cited: *policy_oid,
                enforced: self.policy_oid,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_enforced_policy_can_be_activated() {
        let steward = Steward::embedded().unwrap();
        assert_eq!(steward.check_activation(&steward.policy_oid), Ok(()));
        let d = steward.check_activation(&[0xab; 32]).unwrap_err();
        assert_eq!(
            (d.code(), d.kind(), d.exit()),
            ("FA-REF-019", "unsupported_policy", 7)
        );
        assert!(d.message().contains(&"ab".repeat(32)), "{}", d.message());
        assert!(d.fix().contains("capability.policy_oid"), "{}", d.fix());
    }
}
