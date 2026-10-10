//! fa-policy's SoD predicate against fa-reference's independent oracle,
//! exhaustively over a bounded universe (plan §16.2 differential): every
//! registered rule plus synthetic requirements, every matrix count 0..=2,
//! every preparer profile, and every approval transcript of length ≤ 3 over
//! three principals × three profiles × two ops. Agreement is on the refusal
//! code *and* the finer kind, so a reordered precedence fails here.

use fa_policy::sod::{Approver, Party, evaluate};
use fa_policy::{Op, Profile, Steward};
use fa_reference::sod as oracle;
use fa_registry::sod_policy::SodRequirement;
use fgdb_types::VId;

const PRINCIPALS: [u128; 3] = [1, 2, 3];
const OPS: [Op; 2] = [Op::Approve, Op::Verify];

fn slots() -> Vec<Approver> {
    let mut out = Vec::new();
    for p in PRINCIPALS {
        for profile in Profile::ALL {
            for op in OPS {
                out.push(Approver {
                    principal: VId(p),
                    profile,
                    op,
                });
            }
        }
    }
    out
}

fn transcripts() -> Vec<Vec<Approver>> {
    let s = slots();
    let mut out = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..3 {
        let mut next = Vec::new();
        for t in &frontier {
            for a in &s {
                let mut t2: Vec<Approver> = t.clone();
                t2.push(*a);
                next.push(t2);
            }
        }
        out.extend(next.iter().cloned());
        frontier = next;
    }
    out
}

fn requirements() -> Vec<(String, SodRequirement)> {
    let steward = Steward::embedded().expect("policy");
    let mut out = vec![("default".to_string(), steward.sod.default.clone())];
    for r in &steward.sod.rules {
        out.push((r.name.clone(), r.requirement.clone()));
    }
    let profile_sets: [&[&str]; 3] = [&["Human"], &["Agent", "Human"], &["Human", "System"]];
    for approvers in 0..=2u8 {
        for humans in 0..=2u8 {
            for profiles in profile_sets {
                out.push((
                    format!("synthetic-{approvers}-{humans}-{}", profiles.join("+")),
                    SodRequirement {
                        approvers,
                        approver_op: "approve".into(),
                        approver_profiles: profiles.iter().map(|p| (*p).to_string()).collect(),
                        agent_prepared_human_approvers: humans,
                        exclusions: vec!["duplicate".into(), "preparer".into()],
                        cite: "synthetic".into(),
                    },
                ));
            }
        }
    }
    out
}

#[test]
fn engine_and_oracle_codes_are_the_same_strings() {
    assert_eq!(fa_policy::denial::code::SOD, oracle::SOD);
    assert_eq!(fa_policy::denial::code::APPROVALS, oracle::APPROVALS);
}

#[test]
fn engine_and_oracle_agree_on_every_transcript() {
    let transcripts = transcripts();
    assert_eq!(transcripts.len(), 1 + 18 + 18 * 18 + 18 * 18 * 18);
    let literal: Vec<Vec<oracle::Approval>> = transcripts
        .iter()
        .map(|t| {
            t.iter()
                .map(|a| oracle::Approval {
                    principal: a.principal.0,
                    profile: a.profile.name().to_string(),
                    op: a.op.name().to_string(),
                })
                .collect()
        })
        .collect();
    let reqs = requirements();
    let mut admitted = 0usize;
    let mut refused = std::collections::BTreeMap::<&'static str, usize>::new();
    for (name, req) in &reqs {
        for matrix in 0..=2u8 {
            for preparer_profile in Profile::ALL {
                let preparer = Party {
                    principal: VId(1),
                    profile: preparer_profile,
                };
                for (t, lit) in transcripts.iter().zip(&literal) {
                    let engine = evaluate(name, req, matrix, preparer, t).err();
                    let expected = oracle::verdict(req, matrix, 1, preparer_profile.name(), lit);
                    let got = engine.as_ref().map(|d| (d.code(), d.kind()));
                    assert_eq!(
                        got, expected,
                        "rule {name}, matrix {matrix}, preparer {preparer_profile}, transcript {t:?}"
                    );
                    match engine {
                        None => admitted += 1,
                        Some(d) => *refused.entry(d.kind()).or_insert(0) += 1,
                    }
                }
            }
        }
    }
    // The universe exercises every verdict, so agreement is not vacuous.
    assert!(admitted > 0);
    for kind in [
        "self_approval",
        "approver_profile",
        "approver_op",
        "duplicate_approver",
        "too_few_approvals",
        "human_approvers",
        "unsupported_exclusion",
    ] {
        assert!(
            refused.get(kind).copied().unwrap_or(0) > 0,
            "no case reached {kind}"
        );
    }
}

/// A planted mutation in the oracle's input (an approver count one lower)
/// must show up as disagreement: the differential can fail.
#[test]
fn a_loosened_rule_is_caught_by_the_differential() {
    let steward = Steward::embedded().unwrap();
    let rule = steward
        .sod
        .rules
        .iter()
        .find(|r| r.name == "restatement-locked")
        .expect("rule");
    let mut loosened = rule.requirement.clone();
    loosened.approvers -= 1;
    loosened.exclusions = vec!["duplicate".into(), "preparer".into()];
    let mut strict = rule.requirement.clone();
    strict.exclusions = loosened.exclusions.clone();
    let one = vec![Approver {
        principal: VId(2),
        profile: Profile::Human,
        op: Op::Approve,
    }];
    let prep = Party {
        principal: VId(1),
        profile: Profile::Human,
    };
    let engine = evaluate("restatement-locked", &strict, 0, prep, &one)
        .err()
        .map(|d| (d.code(), d.kind()));
    let lit = vec![oracle::Approval {
        principal: 2,
        profile: "Human".into(),
        op: "approve".into(),
    }];
    let mutated = oracle::verdict(&loosened, 0, 1, "Human", &lit);
    assert_eq!(engine, Some(("FA-REF-012", "too_few_approvals")));
    assert_ne!(engine, mutated, "a one-approver loosening must disagree");
}
