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
        code::UNSUPPORTED_POLICY,
        code::REVOKED,
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

#[derive(Clone, Copy)]
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn next_range(&mut self, max_exclusive: u64) -> u64 {
        if max_exclusive <= 1 {
            0
        } else {
            self.next_u64() % max_exclusive
        }
    }
}

#[test]
fn steward_conserved_rights_property_suite() {
    use fa_model::Id128;
    use fa_money::UnitId;
    use fa_policy::{ConservedRightsPool, RightViolation};

    const USD: UnitId = UnitId(0);
    let root = [0x42; 32];

    // Planted negatives: non-positive total, duplicate hold, release/commit above held,
    // spend above available.
    assert_eq!(
        ConservedRightsPool::new(root, USD, 0),
        Err(RightViolation::NonPositiveAmount { amount: 0 })
    );
    let mut pool = ConservedRightsPool::new(root, USD, 1_000).unwrap();
    assert_eq!(pool.check_invariant(), Ok(()));
    let hold_a = Id128([1; 16]);
    pool.reserve(hold_a, 400).unwrap();
    assert_eq!(
        (pool.held(), pool.available(), pool.spent(), pool.total()),
        (400, 600, 0, 1_000)
    );
    assert_eq!(
        pool.reserve(hold_a, 100),
        Err(RightViolation::DuplicateHold { hold_id: hold_a })
    );
    assert_eq!(
        pool.reserve(Id128([2; 16]), 601),
        Err(RightViolation::InsufficientAvailable {
            requested: 601,
            available: 600,
        })
    );
    assert_eq!(
        pool.release(hold_a, 401),
        Err(RightViolation::ExceedsHeld {
            hold_id: hold_a,
            requested: 401,
            held: 400,
        })
    );
    pool.commit_hold(hold_a, 250).unwrap();
    assert_eq!(
        (pool.held(), pool.available(), pool.spent(), pool.total()),
        (0, 750, 250, 1_000)
    );
    assert_eq!(pool.check_invariant(), Ok(()));

    // Property campaign: 64 deterministic seeds × 60 operations.
    for seed in 1_u64..=64 {
        let mut rng = SplitMix64(seed);
        let total = i128::from(500 + rng.next_range(50_000));
        let mut p = ConservedRightsPool::new(root, USD, total).unwrap();
        let mut active_holds: Vec<Id128> = Vec::new();
        let mut next_id: u128 = 1;

        for _step in 0..60 {
            let before = p.clone();
            let action = rng.next_range(4);
            let outcome = match action {
                0 => {
                    let id = Id128(next_id.to_le_bytes());
                    next_id += 1;
                    let amount = i128::from(rng.next_range(1_000));
                    let res = p.reserve(id, amount);
                    if res.is_ok() {
                        active_holds.push(id);
                    }
                    res
                }
                1 => {
                    if active_holds.is_empty() {
                        let id = Id128(next_id.to_le_bytes());
                        next_id += 1;
                        p.release(id, 10)
                    } else {
                        let idx = rng.next_range(active_holds.len() as u64) as usize;
                        let id = active_holds[idx];
                        let held_amt = p.holds().get(&id).copied().unwrap_or(0);
                        let req_amt =
                            i128::from(rng.next_range((held_amt as u64).saturating_add(50)));
                        let res = p.release(id, req_amt);
                        if res.is_ok() && !p.holds().contains_key(&id) {
                            active_holds.swap_remove(idx);
                        }
                        res
                    }
                }
                2 => {
                    if active_holds.is_empty() {
                        let id = Id128(next_id.to_le_bytes());
                        next_id += 1;
                        p.commit_hold(id, 10)
                    } else {
                        let idx = rng.next_range(active_holds.len() as u64) as usize;
                        let id = active_holds[idx];
                        let held_amt = p.holds().get(&id).copied().unwrap_or(0);
                        let spend_amt =
                            i128::from(rng.next_range((held_amt as u64).saturating_add(50)));
                        let res = p.commit_hold(id, spend_amt);
                        if res.is_ok() {
                            active_holds.swap_remove(idx);
                        }
                        res
                    }
                }
                _ => {
                    let id = Id128(next_id.to_le_bytes());
                    next_id += 1;
                    let amount = i128::from(rng.next_range(1_000));
                    p.spend_direct(id, amount)
                }
            };
            if outcome.is_err() {
                assert_eq!(p, before, "failed operation must leave pool unchanged");
            }
            assert_eq!(p.check_invariant(), Ok(()));
            assert_eq!(p.held() + p.available() + p.spent(), total);
        }
    }
}

#[test]
fn steward_single_use_permits_and_judgment_cache_property_suite() {
    use std::collections::BTreeSet;

    use fa_model::Id128;
    use fa_policy::{
        CachedJudgment, Capability, Denial, JudgmentCache, Op, PermitDenial, PermitGate,
        PermitTarget, Profile, SingleUsePermit,
    };
    use fgdb_types::{CommitSeq, VId};

    let book = Id128([9; 16]);
    let human = Capability::embedded(VId(7), &["post", "close"])
        .unwrap()
        .for_books(&[book])
        .unwrap()
        .expiring_at(CommitSeq(100));
    let agent = Capability::new(VId(8), Profile::Agent, &[Op::Post], VId(1)).unwrap();

    let dummy_judgment = CachedJudgment {
        judgment_id: Id128([2; 16]),
        book_id: book,
        payload_digest: [0xaa; 32],
        planned_at: CommitSeq(10),
        security_policy_epoch: 3,
        watched_keys: BTreeSet::new(),
    };

    // Agent cannot mint a trunk write permit.
    let agent_attempt = SingleUsePermit::issue(
        &agent,
        Id128([1; 16]),
        Op::Post,
        &dummy_judgment,
        CommitSeq(10),
    )
    .unwrap();
    assert_eq!(
        agent_attempt,
        Err(PermitDenial::Policy(Denial::AgentOnTrunk))
    );

    // Property campaign: 48 seeds testing single-use enforcement, payload immutability,
    // and range-emptiness witness invalidation.
    for seed in 1_u64..=48 {
        let mut rng = SplitMix64(seed);
        let permit_id = Id128((seed as u128).to_le_bytes());
        let judgment_id = Id128(((seed + 1_000) as u128).to_le_bytes());
        let mut payload = [0_u8; 32];
        payload[0..8].copy_from_slice(&rng.next_u64().to_le_bytes());
        let planned_at = CommitSeq(10 + (seed % 20));
        let commit_at = CommitSeq(planned_at.0 + 1 + (seed % 10));
        let epoch = 5_u64;

        let watched_key_a = [0x11; 32];
        let watched_key_b = [0x22; 32];
        let unwatched_key = [0x99; 32];

        let judgment = CachedJudgment {
            judgment_id,
            book_id: book,
            payload_digest: payload,
            planned_at,
            security_policy_epoch: epoch,
            watched_keys: BTreeSet::from([watched_key_a, watched_key_b]),
        };

        let mut cache = JudgmentCache::new();
        cache.insert_judgment(judgment.clone());
        // Unwatched mutation inside (planned_at, commit_at] preserves emptiness.
        cache.record_commit(
            CommitSeq(planned_at.0 + 1),
            BTreeSet::from([unwatched_key]),
            epoch,
        );

        let permit = SingleUsePermit::issue(&human, permit_id, Op::Post, &judgment, planned_at)
            .unwrap()
            .unwrap();

        let mut gate = PermitGate::new();
        let valid_target = PermitTarget {
            book_id: book,
            actor: VId(7),
            op: Op::Post,
            payload_digest: payload,
            commit_at,
            current_epoch: epoch,
        };

        // 1. Mutated payload is refused and does NOT consume the permit.
        let mut tampered_payload = payload;
        tampered_payload[0] ^= 0xff;
        assert_eq!(
            gate.consume(
                &permit,
                &PermitTarget {
                    payload_digest: tampered_payload,
                    ..valid_target
                },
                &cache,
            ),
            Err(PermitDenial::PayloadMismatch {
                expected_payload: payload,
                presented_payload: tampered_payload,
            })
        );
        assert_eq!(gate.is_consumed(&permit.digest()), None);

        // 2. Wrong epoch is refused and does NOT consume the permit.
        assert_eq!(
            gate.consume(
                &permit,
                &PermitTarget {
                    current_epoch: epoch + 1,
                    ..valid_target
                },
                &cache,
            ),
            Err(PermitDenial::EpochMismatch {
                permit_epoch: epoch,
                current_epoch: epoch + 1,
            })
        );
        assert_eq!(gate.is_consumed(&permit.digest()), None);

        // 3. Exact payload + empty watched range succeeds once.
        let closure = gate.consume(&permit, &valid_target, &cache).unwrap();
        assert_eq!(closure.permit_digest, permit.digest());
        assert_eq!(closure.payload_digest, payload);
        assert_eq!(gate.is_consumed(&permit.digest()), Some(commit_at));

        // 4. Replay of the same permit is deterministically refused (one-shot law).
        assert_eq!(
            gate.consume(
                &permit,
                &PermitTarget {
                    commit_at: CommitSeq(commit_at.0 + 1),
                    ..valid_target
                },
                &cache,
            ),
            Err(PermitDenial::AlreadyConsumed {
                permit_digest: permit.digest(),
                consumed_at: commit_at,
            })
        );

        // 5. Mutating a watched key inside (planned_at, commit_at] invalidates the cached judgment.
        let mut invalidated_cache = cache.clone();
        let conflict_seq = CommitSeq(planned_at.0 + 1);
        invalidated_cache.record_commit(conflict_seq, BTreeSet::from([watched_key_b]), epoch);
        let mut fresh_gate = PermitGate::new();
        assert_eq!(
            fresh_gate.consume(&permit, &valid_target, &invalidated_cache),
            Err(PermitDenial::InvalidatedByMutation {
                judgment_id,
                conflicting_seq: conflict_seq,
                conflicting_key: watched_key_b,
            })
        );
    }
}

#[test]
fn steward_authority_graph_sod_dominator_and_min_cut_detects_planted_bypass() {
    use std::collections::BTreeSet;

    use fa_model::Id128;
    use fa_policy::{AuthorityGraph, AuthorityVertex, Op, Profile, SodBypassViolation};
    use fgdb_types::VId;

    let proposal = [0x5a; 32];
    let agent_principal = VId(10);
    let human_reviewer_1 = VId(20);
    let human_reviewer_2 = VId(21);
    let human_controller = VId(22);

    let draft_cap_id = Id128(100_u128.to_le_bytes());
    let draft_cap_vid = VId(100);
    let gate_1 = VId(201);
    let gate_2 = VId(202);
    let gate_controller = VId(203);
    let target_close = VId(900);

    let mut graph = AuthorityGraph::new();
    graph.add_vertex(AuthorityVertex::Principal {
        vid: agent_principal,
        profile: Profile::Agent,
    });
    graph.add_vertex(AuthorityVertex::Principal {
        vid: human_reviewer_1,
        profile: Profile::Human,
    });
    graph.add_vertex(AuthorityVertex::Principal {
        vid: human_reviewer_2,
        profile: Profile::Human,
    });
    graph.add_vertex(AuthorityVertex::Principal {
        vid: human_controller,
        profile: Profile::Human,
    });
    graph.add_vertex(AuthorityVertex::CapabilityNode {
        id: draft_cap_id,
        holder: agent_principal,
        profile: Profile::Agent,
        ops: BTreeSet::from([Op::Post]),
    });
    graph.add_vertex(AuthorityVertex::ApprovalGate {
        approval_vid: gate_1,
        approver: human_reviewer_1,
        profile: Profile::Human,
        op: Op::Approve,
        proposal_digest: proposal,
    });
    graph.add_vertex(AuthorityVertex::ApprovalGate {
        approval_vid: gate_2,
        approver: human_reviewer_2,
        profile: Profile::Human,
        op: Op::Approve,
        proposal_digest: proposal,
    });
    graph.add_vertex(AuthorityVertex::ApprovalGate {
        approval_vid: gate_controller,
        approver: human_controller,
        profile: Profile::Human,
        op: Op::Approve,
        proposal_digest: proposal,
    });
    graph.add_vertex(AuthorityVertex::TargetEffect {
        effect_vid: target_close,
        op: Op::Close,
        proposal_digest: proposal,
    });

    // 1. Sequential dual-control chain: Agent -> Capability -> Gate 1 -> Gate 2 -> Controller Gate -> TargetEffect(Close).
    graph.add_edge(agent_principal, draft_cap_vid);
    graph.add_edge(draft_cap_vid, gate_1);
    graph.add_edge(gate_1, gate_2);
    graph.add_edge(gate_2, gate_controller);
    graph.add_edge(gate_controller, target_close);

    let proof = graph
        .prove_sod(agent_principal, target_close, 2, 2)
        .expect("sequential dual-control authority graph must satisfy SoD");
    assert_eq!(
        proof.dominating_approvals,
        vec![gate_1, gate_2, gate_controller]
    );
    assert_eq!(proof.min_approval_cut.len(), 1);
    assert_eq!(
        proof.distinct_human_approvers,
        vec![human_reviewer_1, human_reviewer_2, human_controller]
    );
    assert_ne!(proof.proof_digest, [0; 32]);

    // 2. Parallel redundant approval lanes: Agent -> Capability -> {Gate 1, Gate 2} -> TargetEffect(Close).
    // Neither Gate 1 nor Gate 2 alone dominates TargetEffect, but the minimum approval vertex cut
    // has size 2 ([Gate 1, Gate 2]) and requires 2 distinct Human approvers to sever all paths.
    let mut parallel_graph = graph.clone();
    parallel_graph.add_edge(draft_cap_vid, gate_2);
    parallel_graph.add_edge(gate_1, target_close);
    parallel_graph.add_edge(gate_2, target_close);
    let parallel_proof = parallel_graph
        .prove_sod(agent_principal, target_close, 0, 2)
        .expect("parallel approval lanes cut requires both human gates");
    assert_eq!(parallel_proof.min_approval_cut, vec![gate_1, gate_2]);

    // 3. Planted bypass path #1: direct edge from draft capability to TargetEffect.
    let mut direct_bypass = graph.clone();
    direct_bypass.add_edge(draft_cap_vid, target_close);
    assert_eq!(
        direct_bypass.prove_sod(agent_principal, target_close, 1, 1),
        Err(SodBypassViolation::BypassPath {
            source: agent_principal,
            target: target_close,
            bypass_path: vec![agent_principal, draft_cap_vid, target_close],
        })
    );

    // 4. Planted bypass path #2: self-approval gate (approver == source_principal) bypassing Human gates.
    let self_gate = VId(299);
    let mut self_bypass = graph.clone();
    self_bypass.add_vertex(AuthorityVertex::ApprovalGate {
        approval_vid: self_gate,
        approver: agent_principal,
        profile: Profile::Human,
        op: Op::Approve,
        proposal_digest: proposal,
    });
    self_bypass.add_edge(draft_cap_vid, self_gate);
    self_bypass.add_edge(self_gate, target_close);
    assert_eq!(
        self_bypass.prove_sod(agent_principal, target_close, 1, 1),
        Err(SodBypassViolation::BypassPath {
            source: agent_principal,
            target: target_close,
            bypass_path: vec![agent_principal, draft_cap_vid, self_gate, target_close],
        })
    );

    // 5. Planted bypass path #3: approval gate bound to a different proposal digest.
    let wrong_digest_gate = VId(298);
    let mut digest_bypass = graph;
    digest_bypass.add_vertex(AuthorityVertex::ApprovalGate {
        approval_vid: wrong_digest_gate,
        approver: human_reviewer_1,
        profile: Profile::Human,
        op: Op::Approve,
        proposal_digest: [0xee; 32],
    });
    digest_bypass.add_edge(draft_cap_vid, wrong_digest_gate);
    digest_bypass.add_edge(wrong_digest_gate, target_close);
    assert_eq!(
        digest_bypass.prove_sod(agent_principal, target_close, 1, 1),
        Err(SodBypassViolation::BypassPath {
            source: agent_principal,
            target: target_close,
            bypass_path: vec![
                agent_principal,
                draft_cap_vid,
                wrong_digest_gate,
                target_close
            ],
        })
    );
}
