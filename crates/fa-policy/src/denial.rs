//! Typed denials: the lawful "no" of the laws layer.
//!
//! A [`Denial`] carries everything the kernel's refusal envelope needs —
//! the catalog code, the exit class, what failed, the policy row or clause
//! cited, and the exact fix — so the kernel maps it one-to-one and never
//! re-words a policy decision. Codes this crate owns are listed in [`code`];
//! `FA-REF-011`/`012` are the kernel's existing capability/approval-count
//! codes, reused so a client sees one code per failure kind.

use fa_money::UnitId;
use fgdb_types::{CommitSeq, VId};

use crate::capability::Profile;
use crate::op::Op;

/// Refusal codes. The kernel's `refusal::code` module and the reference
/// oracle keep their own copies; tests assert they agree.
pub mod code {
    /// Segregation of duties: self-approval, a duplicate approver, an
    /// approver outside the rule's profiles or op, too few Human approvers
    /// of agent-prepared work, or an exclusion this slice cannot decide.
    pub const SOD: &str = "FA-REF-008";
    /// The capability lacks the op, or is not the acting principal's.
    pub const CAPABILITY: &str = "FA-REF-011";
    /// Fewer valid approvals than the matrix cell and the SoD rule require.
    pub const APPROVALS: &str = "FA-REF-012";
    /// An Agent-profile capability tried to write trunk.
    pub const AGENT_TRUNK: &str = "FA-REF-013";
    /// The capability's declared expiry bound has passed at the admission point.
    pub const EXPIRED: &str = "FA-REF-014";
    /// A leg exceeds the capability's amount ceiling for its unit, or names
    /// a unit a ceiling-bearing capability does not bound.
    pub const CEILING: &str = "FA-REF-015";
    /// An `ApprovalRef` binds a digest other than this proposal's.
    pub const APPROVAL_BINDING: &str = "FA-REF-016";
    /// An `ApprovalRef` names no recorded approval of this book.
    pub const UNKNOWN_APPROVAL: &str = "FA-REF-017";
    /// The approval was recorded under a security policy epoch that is no
    /// longer current. (FA-REF-018 is plan Appendix D's "daemon holds the
    /// writer lease"; this code moved off it, review D-I1.)
    pub const STALE_APPROVAL: &str = "FA-REF-022";
    /// A policy activation names policy content this build does not embed,
    /// so it could journal rules the kernel would not enforce.
    pub const UNSUPPORTED_POLICY: &str = "FA-REF-019";
    /// The capability was revoked by a journaled `CapabilityEvent`.
    pub const REVOKED: &str = "FA-REF-023";
}

/// Exit classes (`registries/exit_codes.toml`); `tests/policy.rs` checks them.
pub mod exit {
    pub const USAGE: u8 = 2;
    pub const CONFLICT: u8 = 6;
    pub const SAFETY: u8 = 7;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Denial {
    /// The capability is held by someone other than the acting principal.
    NotHolder {
        holder: VId,
        principal: VId,
    },
    /// The capability lacks `op`; `what` names the act that needed it.
    MissingOp {
        op: Op,
        what: String,
    },
    /// An Agent-profile capability writes only to its draft (plan §14.4).
    AgentOnTrunk,
    Expired {
        expires_at: CommitSeq,
        at: CommitSeq,
    },
    CeilingExceeded {
        leg: usize,
        unit: UnitId,
        mantissa: i128,
        ceiling: i128,
    },
    /// A ceiling-bearing capability met a unit it does not bound.
    UnboundedUnit {
        leg: usize,
        unit: UnitId,
    },
    SelfApproval {
        rule: String,
        approver: VId,
    },
    DuplicateApprover {
        rule: String,
        approver: VId,
    },
    ApproverProfile {
        rule: String,
        approver: VId,
        profile: Profile,
        allowed: Vec<String>,
    },
    ApproverOp {
        rule: String,
        approver: VId,
        recorded: Op,
        required: String,
    },
    HumanApproversRequired {
        rule: String,
        required: u8,
        supplied: usize,
    },
    /// The rule names an exclusion this slice cannot decide (fail closed).
    UnsupportedExclusion {
        rule: String,
        exclusion: String,
    },
    TooFewApprovals {
        rule: String,
        required: u8,
        supplied: usize,
    },
    ApprovalBinding {
        index: usize,
    },
    UnknownApproval {
        index: usize,
        approval: VId,
    },
    StaleApproval {
        index: usize,
        recorded_epoch: u64,
        current_epoch: u64,
    },
    /// The activation names a policy digest other than the one this build
    /// enforces (`Steward::policy_oid`).
    UnsupportedPolicy {
        cited: [u8; 32],
        enforced: [u8; 32],
    },
    /// A caveat (`books`, …) confines the capability elsewhere.
    OutOfScope {
        caveat: &'static str,
        value: String,
    },
    /// A journaled revocation names this capability's commitment.
    Revoked {
        revoked_at: CommitSeq,
    },
}

impl Denial {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotHolder { .. } | Self::MissingOp { .. } | Self::OutOfScope { .. } => {
                code::CAPABILITY
            }
            Self::AgentOnTrunk => code::AGENT_TRUNK,
            Self::Expired { .. } => code::EXPIRED,
            Self::CeilingExceeded { .. } | Self::UnboundedUnit { .. } => code::CEILING,
            Self::SelfApproval { .. }
            | Self::DuplicateApprover { .. }
            | Self::ApproverProfile { .. }
            | Self::ApproverOp { .. }
            | Self::HumanApproversRequired { .. }
            | Self::UnsupportedExclusion { .. } => code::SOD,
            Self::TooFewApprovals { .. } => code::APPROVALS,
            Self::ApprovalBinding { .. } => code::APPROVAL_BINDING,
            Self::UnknownApproval { .. } => code::UNKNOWN_APPROVAL,
            Self::StaleApproval { .. } => code::STALE_APPROVAL,
            Self::UnsupportedPolicy { .. } => code::UNSUPPORTED_POLICY,
            Self::Revoked { .. } => code::REVOKED,
        }
    }

    /// A stable machine-readable discriminator, finer than the code (the
    /// SoD oracle differential compares on it).
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotHolder { .. } => "not_holder",
            Self::MissingOp { .. } => "missing_op",
            Self::AgentOnTrunk => "agent_on_trunk",
            Self::Expired { .. } => "expired",
            Self::CeilingExceeded { .. } => "ceiling",
            Self::UnboundedUnit { .. } => "unbounded_unit",
            Self::SelfApproval { .. } => "self_approval",
            Self::DuplicateApprover { .. } => "duplicate_approver",
            Self::ApproverProfile { .. } => "approver_profile",
            Self::ApproverOp { .. } => "approver_op",
            Self::HumanApproversRequired { .. } => "human_approvers",
            Self::UnsupportedExclusion { .. } => "unsupported_exclusion",
            Self::TooFewApprovals { .. } => "too_few_approvals",
            Self::ApprovalBinding { .. } => "approval_binding",
            Self::UnknownApproval { .. } => "unknown_approval",
            Self::StaleApproval { .. } => "stale_approval",
            Self::UnsupportedPolicy { .. } => "unsupported_policy",
            Self::OutOfScope { .. } => "out_of_scope",
            Self::Revoked { .. } => "revoked",
        }
    }

    #[must_use]
    pub fn exit(&self) -> u8 {
        match self {
            Self::StaleApproval { .. } => exit::CONFLICT,
            _ => exit::SAFETY,
        }
    }

    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::NotHolder { holder, principal } => format!(
                "the capability is held by principal {:032x}, but the intent acts as {:032x}",
                holder.0, principal.0
            ),
            Self::MissingOp { op, what } => {
                format!("{what} requires capability op `{op}`, which the principal does not hold")
            }
            Self::AgentOnTrunk => "an Agent-profile capability cannot write to trunk".to_string(),
            Self::Expired { expires_at, at } => format!(
                "the capability expired at commit sequence {}; the book head is {}",
                expires_at.0, at.0
            ),
            Self::CeilingExceeded {
                leg,
                unit,
                mantissa,
                ceiling,
            } => format!(
                "leg {leg} carries mantissa {mantissa} in unit {}, above the capability's ceiling {ceiling}",
                unit.0
            ),
            Self::UnboundedUnit { leg, unit } => format!(
                "leg {leg} is in unit {}, which this ceiling-bearing capability does not bound",
                unit.0
            ),
            Self::SelfApproval { approver, .. } => format!(
                "principal {:032x} prepared this entry and cannot approve it",
                approver.0
            ),
            Self::DuplicateApprover { approver, .. } => format!(
                "principal {:032x} approves more than once; approvers are distinct principals",
                approver.0
            ),
            Self::ApproverProfile {
                approver, profile, ..
            } => format!(
                "approver {:032x} acted under a {profile}-profile capability, which this rule does not admit",
                approver.0
            ),
            Self::ApproverOp {
                approver,
                recorded,
                required,
                ..
            } => format!(
                "approver {:032x} recorded its approval under `{recorded}`; this rule requires `{required}`",
                approver.0
            ),
            Self::HumanApproversRequired {
                required, supplied, ..
            } => format!(
                "agent-prepared work requires {required} Human approver(s); {supplied} supplied"
            ),
            Self::UnsupportedExclusion { exclusion, .. } => format!(
                "the rule's `{exclusion}` exclusion cannot be decided by this slice, so the entry is refused"
            ),
            Self::TooFewApprovals {
                required, supplied, ..
            } => format!("requires {required} approval(s); {supplied} valid approval(s) supplied"),
            Self::ApprovalBinding { index } => {
                format!("approval {index} binds a different proposal digest than this entry's")
            }
            Self::UnknownApproval { index, approval } => format!(
                "approval {index} names {:032x}, which is not a recorded approval of this book",
                approval.0
            ),
            Self::StaleApproval {
                index,
                recorded_epoch,
                current_epoch,
            } => format!(
                "approval {index} was recorded under security policy epoch {recorded_epoch}; the book is at epoch {current_epoch}"
            ),
            Self::UnsupportedPolicy { cited, enforced } => format!(
                "the activation names policy {}, but this build enforces only policy {}",
                hex(cited),
                hex(enforced)
            ),
            Self::OutOfScope { caveat, value } => {
                format!("the capability's `{caveat}` caveat does not admit {value}")
            }
            Self::Revoked { revoked_at } => format!(
                "the capability was revoked at commit sequence {}",
                revoked_at.0
            ),
        }
    }

    #[must_use]
    pub fn cite(&self) -> String {
        match self {
            Self::NotHolder { .. } => "plan §14.2 (a capability authorizes its holder only)".into(),
            Self::MissingOp { .. } => "plan §14.2 (capability caveats)".into(),
            Self::AgentOnTrunk => {
                "plan §14.4 Agent profile (branch-confined); drafts and promotion: fa-s7x".into()
            }
            Self::Expired { .. } => {
                "plan §14.2 (authority is evaluated against current policy)".into()
            }
            Self::CeilingExceeded { .. } | Self::UnboundedUnit { .. } => {
                "plan §14.2 (`amount ≤ A` bounds every leg's mantissa in its unit)".into()
            }
            Self::SelfApproval { rule, .. }
            | Self::DuplicateApprover { rule, .. }
            | Self::ApproverProfile { rule, .. }
            | Self::ApproverOp { rule, .. }
            | Self::HumanApproversRequired { rule, .. }
            | Self::UnsupportedExclusion { rule, .. }
            | Self::TooFewApprovals { rule, .. } => format!("sod_policy.toml#{rule}"),
            Self::ApprovalBinding { .. } | Self::UnknownApproval { .. } => {
                "FA-INV-10 approval-binds-proposal".into()
            }
            Self::StaleApproval { .. } => "FA-INV-10 current-policy".into(),
            Self::UnsupportedPolicy { .. } => {
                "plan §14.2 (authority is evaluated against current policy); a journaled activation must name the rules the kernel enforces".into()
            }
            Self::OutOfScope { .. } => {
                "plan §14.2 (caveats are conjunctive and attenuable only)".into()
            }
            Self::Revoked { .. } => {
                "plan §14.2 (revocation is a journaled control entry; authority is evaluated against current policy at commit)".into()
            }
        }
    }

    #[must_use]
    pub fn fix(&self) -> String {
        match self {
            Self::NotHolder { .. } => {
                "act as the capability's holder (--as <holder>), or obtain a capability issued to this principal".into()
            }
            Self::MissingOp { op, .. } => format!(
                "obtain `{op}` from the book's steward (embedded posture: --grant {op})"
            ),
            Self::AgentOnTrunk => {
                "drafts are not yet available (fa-s7x): ask a Human principal to post this intent, or post it under a Human-profile capability".into()
            }
            Self::Expired { .. } => {
                "obtain a fresh capability; an expired token is never extended".into()
            }
            Self::CeilingExceeded { ceiling, unit, .. } => format!(
                "split the work so each leg's mantissa in unit {} is at most {ceiling}, or have a principal with a higher ceiling post it",
                unit.0
            ),
            Self::UnboundedUnit { .. } => {
                "obtain a capability whose ceilings name this unit".into()
            }
            Self::SelfApproval { .. } | Self::DuplicateApprover { .. } => {
                "collect the approval from a different principal: record_approval over this proposal digest, acting as the approver".into()
            }
            Self::ApproverProfile { allowed, .. } => format!(
                "collect the approval from a principal acting under one of: {}",
                allowed.join(", ")
            ),
            Self::ApproverOp { required, .. } => format!(
                "re-approve under a capability holding `{required}`"
            ),
            Self::HumanApproversRequired { .. } => {
                "add approvals from Human principals over the same proposal digest".into()
            }
            Self::UnsupportedExclusion { exclusion, .. } if exclusion == "case_preparer" => {
                "a restatement case decides this exclusion and none can exist yet: restatement cases land with fa-oz3 (Palimpsest slice 2); nothing was written".into()
            }
            Self::UnsupportedExclusion { .. } => {
                "this class lands with the case slice that can decide the exclusion; nothing was written".into()
            }
            Self::TooFewApprovals { .. } => {
                "record the approvals over this proposal digest (record_approval, one per distinct approver) and resubmit citing them".into()
            }
            Self::ApprovalBinding { .. } => {
                "approve this proposal's digest; an approval never transfers to another proposal".into()
            }
            Self::UnknownApproval { .. } => {
                "record the approval first (record_approval), then cite the approval vid it returns".into()
            }
            Self::StaleApproval { .. } => {
                "the security policy changed after the approval; re-approve under the current epoch and resubmit".into()
            }
            Self::UnsupportedPolicy { enforced, .. } => format!(
                "activate the policy this build enforces ({}, `fa capabilities --json` capability.policy_oid); different rules need a build that embeds them",
                hex(enforced)
            ),
            Self::OutOfScope { caveat, .. } => format!(
                "use a capability whose `{caveat}` caveat names this target"
            ),
            Self::Revoked { .. } => {
                "obtain a fresh capability from the book's steward; a revoked token is never reinstated".into()
            }
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl core::fmt::Display for Denial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} (exit {}): {} [{}] fix: {}",
            self.code(),
            self.exit(),
            self.message(),
            self.cite(),
            self.fix()
        )
    }
}
