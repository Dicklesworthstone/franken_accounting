//! Parity between fa-policy's closed vocabularies and the registries that
//! cite them (plan §14.2: "every capability name the admissibility matrix,
//! the profiles, or any verb cites resolves to this list").

use fa_policy::denial::{code, exit};
use fa_policy::{Op, Profile, Steward};
use fa_registry::sod_policy::PROFILES;
use fa_registry::{Admissibility, Decision, EntryClasses, ExitCodes};
use fa_time::PeriodState;

const STATES: [PeriodState; 5] = [
    PeriodState::Future,
    PeriodState::Open,
    PeriodState::SoftClosed,
    PeriodState::Closed,
    PeriodState::Locked,
];

#[test]
fn every_op_the_matrix_cites_is_in_the_closed_vocabulary() {
    let classes = EntryClasses::embedded().unwrap();
    let matrix = Admissibility::embedded(&classes).unwrap();
    let mut cited = 0;
    for class in classes.posting() {
        for state in STATES {
            for release in [false, true] {
                if let Some(Decision::With { op, .. }) =
                    matrix.decide_disposition(&class.name, state, release)
                {
                    assert!(
                        Op::from_name(&op).is_some(),
                        "admissibility.toml ({}, {}) cites `{op}`, which is not an op",
                        class.name,
                        state.name()
                    );
                    cited += 1;
                }
            }
        }
    }
    assert!(cited > 0, "the matrix cites ops");
}

#[test]
fn every_op_and_profile_the_sod_policy_cites_resolves() {
    let steward = Steward::embedded().expect("policy");
    let reqs = std::iter::once(&steward.sod.default)
        .chain(steward.sod.rules.iter().map(|r| &r.requirement));
    for req in reqs {
        assert!(
            Op::from_name(&req.approver_op).is_some(),
            "{}",
            req.approver_op
        );
        for p in &req.approver_profiles {
            assert!(Profile::from_name(p).is_some(), "{p}");
        }
    }
    for r in &steward.sod.rules {
        if let Some(op) = &r.preparer_op {
            assert!(Op::from_name(op).is_some(), "{}: {op}", r.name);
        }
    }
    let names: Vec<&str> = Profile::ALL.iter().map(|p| p.name()).collect();
    assert_eq!(names, PROFILES, "fa-registry's profile list is fa-policy's");
    // Every approver profile a rule admits can actually hold the approver op.
    for req in std::iter::once(&steward.sod.default)
        .chain(steward.sod.rules.iter().map(|r| &r.requirement))
    {
        let op = Op::from_name(&req.approver_op).unwrap();
        for p in &req.approver_profiles {
            let p = Profile::from_name(p).unwrap();
            assert!(
                !p.forbidden_ops().contains(&op),
                "a rule admits {p} approvers, but {p} can never hold `{op}`"
            );
        }
    }
}

#[test]
fn exit_classes_agree_with_the_registry_and_codes_are_distinct() {
    let exits = ExitCodes::embedded().unwrap();
    assert_eq!(exits.code("usage"), Some(exit::USAGE));
    assert_eq!(exits.code("conflict"), Some(exit::CONFLICT));
    assert_eq!(exits.code("safety"), Some(exit::SAFETY));
    let all = [
        code::SOD,
        code::CAPABILITY,
        code::APPROVALS,
        code::AGENT_TRUNK,
        code::EXPIRED,
        code::CEILING,
        code::APPROVAL_BINDING,
        code::UNKNOWN_APPROVAL,
        code::STALE_APPROVAL,
    ];
    let mut seen = std::collections::BTreeSet::new();
    for c in all {
        assert!(c.starts_with("FA-REF-") && c.len() == 10, "{c}");
        assert!(seen.insert(c), "{c} assigned twice");
    }
}

#[test]
fn the_policy_oid_is_a_stable_digest_of_the_rows() {
    let a = Steward::embedded().unwrap();
    let b = Steward::embedded().unwrap();
    assert_eq!(a.policy_oid, b.policy_oid);
    assert_ne!(a.policy_oid, [0; 32]);
    let key = fa_policy::sod::control_key("PolicyControl", None, "Activate");
    assert_eq!(a.preparer_op(&key), Some(Op::RuleChange));
    let lock = fa_policy::sod::control_key("PeriodControl", Some(PeriodState::Closed), "Lock");
    assert_eq!(a.preparer_op(&lock), Some(Op::Close));
}
