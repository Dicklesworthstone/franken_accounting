//! Segregation of duties (plan §14.3, FA-INV-10 clause `sod`) over the rows
//! of `registries/sod_policy.toml`.
//!
//! The kernel hands this module the preparer and the approvals it
//! point-read inside the posting transaction; the verdict is decided here,
//! from data, at commit. Precedence (the reference oracle mirrors it):
//! 1. every exclusion and vocabulary item of the rule must be decidable
//!    (fail closed);
//! 2. each approval in transcript order: not the preparer, a permitted
//!    profile, the rule's op, a principal not already counted;
//! 3. at least `max(matrix approvals, rule approvers)` approvals;
//! 4. agent-prepared work: at least `agent_prepared_human_approvers` Human
//!    approvers.

use std::collections::BTreeSet;

use fa_registry::sod_policy::{SodKey, SodRequirement};
use fa_time::PeriodState;
use fgdb_types::VId;

use crate::approval::Approval;
use crate::capability::Profile;
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
/// `admit` cells and for controls).
pub fn evaluate(
    rule: &str,
    req: &SodRequirement,
    matrix_approvals: u8,
    preparer: Party,
    approvers: &[Approver],
) -> Result<(), Denial> {
    for exclusion in &req.exclusions {
        if !DECIDED_EXCLUSIONS.contains(&exclusion.as_str()) {
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
