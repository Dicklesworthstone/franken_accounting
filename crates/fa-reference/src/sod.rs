//! The segregation-of-duties oracle (plan §14.3, §16.2).
//!
//! An independent, deliberately literal model of the SoD predicate over a
//! `sod_policy.toml` requirement. It shares only the registry rows with
//! `fa-policy`; the evaluation is written from the policy text, not from
//! the engine's code, and returns `(code, kind)` pairs as its own string
//! constants so a renumbering or a re-ordering on either side is a
//! differential failure. Principals are plain integers, profiles and ops
//! plain names: no engine type crosses this boundary.

use std::collections::BTreeMap;

use fa_registry::sod_policy::SodRequirement;

pub const SOD: &str = "FA-REF-008";
pub const APPROVALS: &str = "FA-REF-012";

/// One witnessed approval: who, under which profile, exercising which op.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approval {
    pub principal: u128,
    pub profile: String,
    pub op: String,
}

/// The oracle's verdict: `None` admits; otherwise `(code, kind)`. No case is
/// in scope.
pub fn verdict(
    req: &SodRequirement,
    matrix_approvals: u8,
    preparer: u128,
    preparer_profile: &str,
    approvals: &[Approval],
) -> Option<(&'static str, &'static str)> {
    verdict_in(
        req,
        matrix_approvals,
        preparer,
        preparer_profile,
        approvals,
        None,
        None,
    )
}

/// The verdict with what was read beyond the entry. `case_preparers`, the
/// principals who prepared the case's entries, makes `case_preparer`
/// decidable: an approver among them is refused. `lineages`, one list per
/// approval in order of the principals who issued (directly or further up
/// the chain) the capability it approved under, makes `session_lineage`
/// decidable: an approval is refused when its list names the preparer, a
/// case preparer, or another approver of the work. A list of the wrong
/// length decides nothing.
pub fn verdict_in(
    req: &SodRequirement,
    matrix_approvals: u8,
    preparer: u128,
    preparer_profile: &str,
    approvals: &[Approval],
    case_preparers: Option<&[u128]>,
    lineages: Option<&[Vec<u128>]>,
) -> Option<(&'static str, &'static str)> {
    // 1. The rule must be decidable as written.
    let lineages_known = match lineages {
        Some(l) => l.len() == approvals.len(),
        None => false,
    };
    let decidable = |e: &String| {
        e == "preparer"
            || e == "duplicate"
            || (e == "case_preparer" && case_preparers.is_some())
            || (e == "session_lineage" && lineages_known)
    };
    let case_bound = req.exclusions.iter().any(|e| e == "case_preparer");
    let lineage_bound = req.exclusions.iter().any(|e| e == "session_lineage");
    if !req.exclusions.iter().all(decidable) {
        return Some((SOD, "unsupported_exclusion"));
    }
    const OPS: [&str; 21] = [
        "read",
        "post",
        "post_softclosed",
        "post_closed",
        "approve",
        "reconcile",
        "close",
        "reopen",
        "restate",
        "migrate",
        "schema_change",
        "rule_change",
        "issue_capability",
        "witness",
        "verify",
        "produce",
        "hold",
        "erase",
        "privileged",
        "receivership",
        "partial_view",
    ];
    if !OPS.contains(&req.approver_op.as_str()) {
        return Some((SOD, "unsupported_exclusion"));
    }
    if !req
        .approver_profiles
        .iter()
        .all(|p| matches!(p.as_str(), "Human" | "Agent" | "System"))
    {
        return Some((SOD, "unsupported_exclusion"));
    }
    // 2. Each approval in order; the first fault in the first faulty
    //    approval decides. A principal seen earlier in the transcript is a
    //    duplicate.
    let mut times_seen: BTreeMap<u128, usize> = BTreeMap::new();
    for (i, a) in approvals.iter().enumerate() {
        // Under session_lineage: does approval i's issuer list name someone
        // else who is a party to the work?
        let mut issued_by_a_party = false;
        if lineage_bound && let Some(lists) = lineages {
            for issuer in &lists[i] {
                if *issuer == a.principal {
                    continue;
                }
                let mut party = *issuer == preparer;
                if let Some(case) = case_preparers {
                    party = party || case.contains(issuer);
                }
                for other in approvals {
                    party = party || other.principal == *issuer;
                }
                issued_by_a_party = issued_by_a_party || party;
            }
        }
        let fault = if a.principal == preparer {
            Some("self_approval")
        } else if !req.approver_profiles.contains(&a.profile) {
            Some("approver_profile")
        } else if a.op != req.approver_op {
            Some("approver_op")
        } else if times_seen.get(&a.principal).copied().unwrap_or(0) > 0 {
            Some("duplicate_approver")
        } else if case_bound && case_preparers.is_some_and(|p| p.contains(&a.principal)) {
            Some("case_preparer")
        } else if issued_by_a_party {
            Some("session_lineage")
        } else {
            None
        };
        if let Some(kind) = fault {
            return Some((SOD, kind));
        }
        *times_seen.entry(a.principal).or_insert(0) += 1;
    }
    // 3. The count: the larger of the matrix cell and the rule.
    let need = if matrix_approvals > req.approvers {
        matrix_approvals
    } else {
        req.approvers
    };
    if times_seen.len() < usize::from(need) {
        return Some((APPROVALS, "too_few_approvals"));
    }
    // 4. Agent-prepared work needs Human approvers.
    if preparer_profile == "Agent" {
        let mut humans = 0usize;
        for a in approvals {
            if a.profile == "Human" {
                humans += 1;
            }
        }
        if humans < usize::from(req.agent_prepared_human_approvers) {
            return Some((SOD, "human_approvers"));
        }
    }
    None
}
