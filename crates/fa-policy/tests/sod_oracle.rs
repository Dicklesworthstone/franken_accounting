//! fa-policy's SoD predicate against fa-reference's independent oracle,
//! exhaustively over a bounded universe (plan §16.2 differential): every
//! registered rule plus synthetic requirements, every matrix count 0..=2,
//! every preparer profile, and every approval transcript of length ≤ 3 over
//! three principals × three profiles × two ops. Agreement is on the refusal
//! code *and* the finer kind, so a reordered precedence fails here.

use std::collections::BTreeSet;

use fa_policy::sod::{Approver, Party, Witnessed, evaluate, evaluate_in};
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

/// The case-bound rules with their case's preparers known: every
/// transcript under no preparers, one preparer (principal 2) and two (2 and
/// 3) agrees with the oracle, and the `case_preparer` refusal is reached.
#[test]
fn engine_and_oracle_agree_on_case_bound_rules_with_known_preparers() {
    let transcripts = transcripts();
    let reqs: Vec<(String, SodRequirement)> = requirements()
        .into_iter()
        .filter(|(_, r)| r.exclusions.iter().any(|e| e == "case_preparer"))
        .map(|(name, mut r)| {
            // No lineages are supplied here, so session_lineage would refuse
            // every transcript; drop it so the case exclusion itself is
            // exercised (the next test decides session_lineage).
            r.exclusions.retain(|e| e != "session_lineage");
            (name, r)
        })
        .collect();
    assert!(!reqs.is_empty(), "the registry has case-bound rules");
    let scopes: [&[u128]; 3] = [&[], &[2], &[2, 3]];
    let mut reached = 0usize;
    for (name, req) in &reqs {
        for scope in scopes {
            let preparers: BTreeSet<VId> = scope.iter().map(|p| VId(*p)).collect();
            for preparer_profile in Profile::ALL {
                let preparer = Party {
                    principal: VId(1),
                    profile: preparer_profile,
                };
                for t in &transcripts {
                    let lit: Vec<oracle::Approval> = t
                        .iter()
                        .map(|a| oracle::Approval {
                            principal: a.principal.0,
                            profile: a.profile.name().to_string(),
                            op: a.op.name().to_string(),
                        })
                        .collect();
                    let witnessed = Witnessed {
                        case_preparers: Some(&preparers),
                        lineages: None,
                    };
                    let got = evaluate_in(name, req, 0, preparer, t, witnessed)
                        .err()
                        .map(|d| (d.code(), d.kind()));
                    let expected = oracle::verdict_in(
                        req,
                        0,
                        1,
                        preparer_profile.name(),
                        &lit,
                        Some(scope),
                        None,
                    );
                    assert_eq!(
                        got, expected,
                        "rule {name}, preparers {scope:?}, preparer {preparer_profile}, transcript {t:?}"
                    );
                    if got.map(|(_, kind)| kind) == Some("case_preparer") {
                        reached += 1;
                    }
                }
            }
        }
    }
    assert!(reached > 0, "no transcript reached case_preparer");
}

/// `session_lineage` decided over authority lineages (fa-651f): every
/// Human `approve` transcript of length ≤ 3 over principals 1 (the
/// preparer) to 4, each approval with every lineage from a small set (none,
/// the preparer, each other principal, two of them, the approver itself),
/// under every lineage-bearing rule, with and without known case preparers.
/// Engine and oracle agree on code and kind, both verdicts are reached, and
/// lineages of the wrong length decide nothing.
#[test]
fn engine_and_oracle_agree_on_session_lineage() {
    let steward = Steward::embedded().expect("policy");
    let mut reqs: Vec<(String, SodRequirement)> = steward
        .sod
        .rules
        .iter()
        .filter(|r| {
            r.requirement
                .exclusions
                .iter()
                .any(|e| e == "session_lineage")
        })
        .map(|r| (r.name.clone(), r.requirement.clone()))
        .collect();
    assert!(!reqs.is_empty(), "the registry has lineage-bound rules");
    for approvers in 0..=2u8 {
        for case in [false, true] {
            let mut exclusions = vec![
                "preparer".to_string(),
                "duplicate".to_string(),
                "session_lineage".to_string(),
            ];
            if case {
                exclusions.push("case_preparer".into());
            }
            reqs.push((
                format!("synthetic-lineage-{approvers}-{case}"),
                SodRequirement {
                    approvers,
                    approver_op: "approve".into(),
                    approver_profiles: vec!["Human".into()],
                    agent_prepared_human_approvers: 0,
                    exclusions,
                    cite: "synthetic".into(),
                },
            ));
        }
    }
    let lineage_options: [&[u128]; 6] = [&[], &[1], &[2], &[3], &[4], &[3, 4]];
    let mut cases: Vec<(Vec<Approver>, Vec<BTreeSet<VId>>)> = vec![(Vec::new(), Vec::new())];
    let mut frontier = cases.clone();
    for _ in 0..3 {
        let mut next = Vec::new();
        for (t, l) in &frontier {
            for p in [1u128, 2, 3, 4] {
                for option in lineage_options {
                    let mut t2 = t.clone();
                    t2.push(Approver {
                        principal: VId(p),
                        profile: Profile::Human,
                        op: Op::Approve,
                    });
                    let mut l2 = l.clone();
                    l2.push(option.iter().map(|q| VId(*q)).collect());
                    next.push((t2, l2));
                }
            }
        }
        cases.extend(next.iter().cloned());
        frontier = next;
    }
    let scopes: [Option<&[u128]>; 3] = [None, Some(&[]), Some(&[3])];
    let mut admitted = 0usize;
    let mut lineage_refusals = 0usize;
    for (name, req) in &reqs {
        for scope in scopes {
            let preparers: Option<BTreeSet<VId>> =
                scope.map(|s| s.iter().map(|p| VId(*p)).collect());
            let preparer = Party {
                principal: VId(1),
                profile: Profile::Human,
            };
            for (t, lineages) in &cases {
                let lit: Vec<oracle::Approval> = t
                    .iter()
                    .map(|a| oracle::Approval {
                        principal: a.principal.0,
                        profile: a.profile.name().to_string(),
                        op: a.op.name().to_string(),
                    })
                    .collect();
                let lit_lineages: Vec<Vec<u128>> = lineages
                    .iter()
                    .map(|l| l.iter().map(|p| p.0).collect())
                    .collect();
                let witnessed = Witnessed {
                    case_preparers: preparers.as_ref(),
                    lineages: Some(lineages),
                };
                let got = evaluate_in(name, req, 0, preparer, t, witnessed)
                    .err()
                    .map(|d| (d.code(), d.kind()));
                let expected =
                    oracle::verdict_in(req, 0, 1, "Human", &lit, scope, Some(&lit_lineages));
                assert_eq!(
                    got, expected,
                    "rule {name}, preparers {scope:?}, transcript {t:?}, lineages {lineages:?}"
                );
                match got {
                    None => admitted += 1,
                    Some((_, "session_lineage")) => lineage_refusals += 1,
                    Some(_) => {}
                }
                // One lineage short decides nothing, on both sides.
                if let Some((_, shorter)) = lineages.split_last() {
                    let short = Witnessed {
                        case_preparers: preparers.as_ref(),
                        lineages: Some(shorter),
                    };
                    let got = evaluate_in(name, req, 0, preparer, t, short)
                        .err()
                        .map(|d| (d.code(), d.kind()));
                    let expected = oracle::verdict_in(
                        req,
                        0,
                        1,
                        "Human",
                        &lit,
                        scope,
                        Some(&lit_lineages[..lit_lineages.len() - 1]),
                    );
                    assert_eq!(got, expected);
                    assert_eq!(got, Some(("FA-REF-008", "unsupported_exclusion")));
                }
            }
        }
    }
    assert!(admitted > 0, "no transcript was admitted");
    assert!(
        lineage_refusals > 0,
        "no transcript reached session_lineage"
    );
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
