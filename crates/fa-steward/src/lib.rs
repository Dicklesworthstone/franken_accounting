#![forbid(unsafe_code)]
//! Steward — capabilities, caveats, profiles, SoD policy, policy epoch
//! activation, capability revocation, access audit, legal holds, and erasure
//! governance (plan §14).

pub use fa_docket::{
    HoldReach, LegalHold, LegalHoldPlaced, LegalHoldReleased, LegalHoldRequest, Pinned,
    RedactedView, ReleasePlan, ViewChunk, ViewDerived, active_legal_holds, derive_redacted_view,
    place_legal_hold, plan_release, read_legal_hold, redacted_view_vid, release_legal_hold,
};
pub use fa_journal::{
    ActivationRequest, ApprovalRequest, Approved, PolicyActivated, RevocationRequest, Revoked,
    activate_policy, activation_proposal, record_approval, revoke_capability,
    security_policy_epoch,
};
use fa_model::Id128;
pub use fa_policy::{
    AccountScope, Approval, Approver, BenefitInterval, Capability, CapabilityError,
    DECISION_CARD_DOMAIN, DecisionCandidate, DecisionCard, DecisionFeature, DecisionKind,
    DecisionPolicyRow, DecisionReason, DecisionReplayError, Denial, Intent, Observes, Op, Party,
    Profile, Reach, Steward, admit, admit_base, admit_read, admit_within, amounts_preserved,
    current, decide_lantern_threshold, decide_register_checkpoint_cadence, evaluate_decision,
    reach, require, scope,
};
use fgdb_types::VId;

/// Standard default operations granted to a named role profile (plan §14.2).
#[must_use]
pub fn profile_default_ops(profile: Profile) -> &'static [Op] {
    match profile {
        Profile::Agent => &[Op::Read, Op::Post, Op::Produce, Op::Verify],
        Profile::Human => &[
            Op::Read,
            Op::Post,
            Op::PostSoftclosed,
            Op::PostClosed,
            Op::Approve,
            Op::Reconcile,
            Op::Close,
            Op::Reopen,
            Op::Restate,
            Op::Produce,
            Op::Verify,
        ],
        Profile::System => &[Op::Read, Op::Post, Op::Witness, Op::Produce, Op::Verify],
    }
}

/// Deterministic access-audit decision record for capability admission (plan §14.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessAuditRecord {
    pub book_id: Id128,
    pub holder: VId,
    pub profile: Profile,
    pub op: Op,
    pub action: String,
    pub admitted: bool,
    pub refusal_reason: Option<String>,
}

/// Evaluate whether `capability` admits `op` on `book_id` and return a
/// structured [`AccessAuditRecord`] alongside the admission result.
pub fn audit_capability_op(
    book_id: Id128,
    capability: &Capability,
    op: Op,
    action: &str,
) -> (AccessAuditRecord, Result<(), Denial>) {
    let check = fa_policy::admit_read(capability, capability.holder(), book_id)
        .and_then(|()| fa_policy::require(capability, op, action));
    let record = AccessAuditRecord {
        book_id,
        holder: capability.holder(),
        profile: capability.profile(),
        op,
        action: action.to_string(),
        admitted: check.is_ok(),
        refusal_reason: check.as_ref().err().map(ToString::to_string),
    };
    (record, check)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steward_profile_default_ops_separate_agent_human_and_system() {
        let agent_ops = profile_default_ops(Profile::Agent);
        assert!(agent_ops.contains(&Op::Post));
        assert!(!agent_ops.contains(&Op::Approve));
        assert!(!agent_ops.contains(&Op::Close));

        let human_ops = profile_default_ops(Profile::Human);
        assert!(human_ops.contains(&Op::Approve));
        assert!(human_ops.contains(&Op::Close));

        let system_ops = profile_default_ops(Profile::System);
        assert!(system_ops.contains(&Op::Witness));
        assert!(!system_ops.contains(&Op::Approve));
    }
}
