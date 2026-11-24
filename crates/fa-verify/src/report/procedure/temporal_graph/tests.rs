use super::*;
use crate::blake3::hash_parts;
use crate::codec::Writer;
use crate::report::procedure::{
    DIGEST_DOMAIN, EXTENDED_FORMAT, TraceContext, TraceEntryFacts, VerifiedProcedure,
    decode as certificate, framed_hash, recompute_version,
};

struct Fixture {
    entries: Vec<Entry>,
    registry: Registry,
}

impl Fixture {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            registry: Registry {
                unit_scales: BTreeMap::from([(1, 2), (2, 0)]),
                unit_currencies: BTreeMap::new(),
                account_types: BTreeMap::from([(10, 1), (20, 1), (30, 1), (40, 3), (50, 5)]),
                account_codes: BTreeMap::new(),
                account_roles: BTreeMap::new(),
                leg_parties: BTreeMap::new(),
                entry_facts: BTreeMap::new(),
                trace: Some(TraceContext::default()),
                open_items: None,
                policy_oid: [7; 32],
            },
        }
    }

    fn legs(&mut self, id: u128, day: i32, legs: &[(u128, bool, u32, i128, Option<u128>)]) {
        self.registry.trace.as_mut().unwrap().entries.insert(
            id,
            TraceEntryFacts {
                entities: legs.iter().map(|leg| leg.4.into_iter().collect()).collect(),
                evidence: BTreeSet::new(),
            },
        );
        self.entries.push(Entry {
            identity: id,
            digest: hash_parts(b"temporal-graph-test", &[&id.to_le_bytes()]),
            recorded_at: id as u64,
            effective: Some(day),
            class: 1,
            legs: legs.iter().map(|leg| (leg.2, leg.3)).collect(),
            leg_accounts: legs.iter().map(|leg| (leg.0, leg.1)).collect(),
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: None,
            transition: None,
        });
    }

    fn movement(&mut self, id: u128, day: i32, from: u128, to: u128, amount: i128) {
        self.legs(
            id,
            day,
            &[(from, false, 1, amount, None), (to, true, 1, amount, None)],
        );
    }

    fn run(&self, profile: VerifiedProcedureParameters) -> (VerifiedProcedure, Vec<u8>) {
        recompute_version(
            [1; 16],
            100,
            if matches!(profile, VerifiedProcedureParameters::GraphLayering { .. }) {
                3
            } else {
                2
            },
            None,
            profile,
            self.entries.clone(),
            &self.registry,
        )
        .unwrap()
    }
}

fn cycle() -> VerifiedProcedureParameters {
    VerifiedProcedureParameters::GraphCircularFlows {
        max_hops: 6,
        min_retention_bps: 7_000,
        window_days: 14,
    }
}

fn chain() -> VerifiedProcedureParameters {
    VerifiedProcedureParameters::GraphLayering {
        min_hops: 3,
        min_passthrough_bps: 8_500,
        window_days: 10,
    }
}

fn paths(report: &VerifiedProcedure) -> Vec<Vec<(u128, u128)>> {
    report
        .findings
        .iter()
        .map(|finding| match &finding.statistic {
            VerifiedProcedureStatistic::CircularFlow { hops, .. }
            | VerifiedProcedureStatistic::LayeredFlow { hops, .. } => hops.clone(),
            _ => panic!("wrong statistic"),
        })
        .collect()
}

fn wrap(output: &[u8]) -> Vec<u8> {
    let mut writer = Writer::default();
    writer
        .bytes(EXTENDED_FORMAT)
        .bytes(b"native source")
        .bytes(b"native approval")
        .count(6);
    for _ in 0..6 {
        writer.bytes(b"opaque native witness");
    }
    writer.fixed(&[2; 32]).u128(7).fixed(&[3; 32]).bytes(output);
    writer.fixed(&framed_hash(DIGEST_DOMAIN, &writer.buf));
    writer.buf
}

#[test]
fn ratios_are_exact_at_monetary_limits_and_threshold_boundaries() {
    for denominator in 1..=113i128 {
        for numerator in 0..=denominator {
            assert_eq!(
                basis_points(numerator, denominator).unwrap(),
                numerator * 10_000 / denominator
            );
        }
    }
    let whole_tens = i128::MAX - 7;
    let retained = whole_tens / 10 * 7;
    assert_eq!(basis_points(retained, whole_tens).unwrap(), 7_000);
    assert_eq!(basis_points(retained - 1, whole_tens).unwrap(), 6_999);
    assert_eq!(basis_points(i128::MAX, i128::MAX).unwrap(), 10_000);
    assert_eq!(basis_points(i128::MAX - 1, i128::MAX).unwrap(), 9_999);
    assert!(basis_points(-1, 1).is_err());
    assert!(basis_points(1, 0).is_err());
    assert!(basis_points(2, 1).is_err());
}

#[test]
fn circular_flows_keep_the_first_closing_attempt_and_complete_population() {
    let mut f = Fixture::new();
    for (id, day, from, to, amount) in [
        (1, 0, 10, 20, 100),
        (2, 1, 20, 30, 95),
        (3, 2, 30, 10, 80),
        (4, 3, 10, 20, 100),
        (5, 4, 20, 10, 69),
        (6, 5, 20, 10, 100),
        (7, 6, 40, 50, 99),
        (8, 7, 10, 10, 5),
    ] {
        f.movement(id, day, from, to, amount);
    }
    let (run, output) = f.run(cycle());
    assert_eq!(paths(&run), [vec![(1, 10), (2, 20), (3, 30)]]);
    assert_eq!(run.findings[0].statistic.value(), 80);
    assert_eq!(
        run.findings[0].population, 8,
        "self flows and acyclic partitions remain population"
    );
    assert_eq!(
        (run.live_entries, run.live_legs, run.comparisons),
        (0, 8, 12)
    );
    assert!(
        run.findings[0]
            .narrative
            .contains("8000 bps, cgse_witness=")
    );
    let bytes = wrap(&output);
    let decoded = certificate(&bytes).unwrap();
    assert_eq!(decoded.parameters, cycle());
    assert_eq!(
        super::super::replay(&decoded, [1; 16], 100, f.entries.clone(), &f.registry)
            .unwrap()
            .1,
        output
    );
    f.entries.reverse();
    assert_eq!(
        f.run(cycle()).1,
        output,
        "source order does not substitute for recorded chronology"
    );
    assert!(
        f.run(VerifiedProcedureParameters::GraphCircularFlows {
            max_hops: 6,
            min_retention_bps: 10_001,
            window_days: u32::MAX
        })
        .0
        .findings
        .is_empty()
    );
}

#[test]
fn layering_v3_advances_after_each_same_day_hop_and_ignores_shortest_path_depth() {
    let mut f = Fixture::new();
    f.movement(1, 0, 10, 20, 100);
    f.movement(2, 0, 30, 40, 90);
    f.movement(3, 0, 20, 30, 90);
    assert!(
        f.run(chain()).0.findings.is_empty(),
        "the earlier terminal transfer cannot be reused later in a path"
    );
    f.movement(4, 0, 30, 40, 81);
    f.movement(5, 0, 10, 40, 100);
    let (run, output) = f.run(chain());
    assert_eq!(paths(&run), [vec![(1, 10), (3, 20), (4, 30)]]);
    assert!(matches!(
        run.findings[0].statistic,
        VerifiedProcedureStatistic::LayeredFlow {
            destination: 40,
            mantissa: 81,
            scale: 2,
            ..
        }
    ));
    assert_eq!(
        (run.live_entries, run.live_legs, run.comparisons),
        (0, 5, 9)
    );
    let bytes = wrap(&output);
    let decoded = certificate(&bytes).unwrap();
    assert_eq!(decoded.parameters, chain());
    assert_eq!(
        super::super::replay(&decoded, [1; 16], 100, f.entries, &f.registry)
            .unwrap()
            .1,
        output
    );
}

#[test]
fn layering_has_inclusive_time_and_ratio_boundaries_without_amount_overflow() {
    let mut f = Fixture::new();
    let amount = (i128::MAX / 100) * 100;
    f.movement(1, 0, 10, 20, amount);
    f.movement(2, 5, 20, 30, amount / 10 * 9);
    f.movement(3, 10, 30, 40, amount / 100 * 81);
    let profile = VerifiedProcedureParameters::GraphLayering {
        min_hops: 3,
        min_passthrough_bps: 9_000,
        window_days: 10,
    };
    let (run, _) = f.run(profile);
    assert_eq!(run.findings.len(), 1);
    assert_eq!(run.findings[0].statistic.value(), amount / 100 * 81);
    assert!(
        f.run(VerifiedProcedureParameters::GraphLayering {
            min_hops: 3,
            min_passthrough_bps: 9_001,
            window_days: 10
        })
        .0
        .findings
        .is_empty()
    );
    assert!(
        f.run(VerifiedProcedureParameters::GraphLayering {
            min_hops: 3,
            min_passthrough_bps: 9_000,
            window_days: 9
        })
        .0
        .findings
        .is_empty()
    );
}

#[test]
fn temporal_flows_preserve_original_unit_entity_and_account_identity() {
    let mut f = Fixture::new();
    for (id, from, to, unit, entity) in [
        (1, 10, 20, 1, 7),
        (2, 20, 30, 1, 8),
        (3, 30, 10, 1, 7),
        (4, 20, 30, 2, 7),
    ] {
        f.legs(
            id,
            0,
            &[
                (from, false, unit, 100, Some(entity)),
                (to, true, unit, 100, Some(entity)),
            ],
        );
    }
    assert!(f.run(cycle()).0.findings.is_empty());
    f.legs(
        5,
        1,
        &[(20, false, 1, 100, Some(7)), (30, true, 1, 100, Some(7))],
    );
    // The prior C->A hop is too early after B->C; a new closing hop is needed.
    assert!(f.run(cycle()).0.findings.is_empty());
    f.legs(
        6,
        1,
        &[(30, false, 1, 80, Some(7)), (10, true, 1, 80, Some(7))],
    );
    let (run, _) = f.run(cycle());
    assert_eq!(paths(&run), [vec![(1, 10), (5, 20), (6, 30)]]);
    assert!(matches!(
        run.findings[0].statistic,
        VerifiedProcedureStatistic::CircularFlow {
            entity: Some(7),
            unit: 1,
            ..
        }
    ));
    f.registry.account_types.remove(&30);
    assert_eq!(
        replay(cycle(), &f.entries.iter().collect::<Vec<_>>(), &f.registry)
            .unwrap_err()
            .predicate,
        "procedure_profile"
    );
}

#[test]
fn allocated_flows_require_a_distinct_closing_entry_and_preserve_self_flow_population() {
    let mut f = Fixture::new();
    f.legs(
        1,
        0,
        &[
            (10, false, 1, 4, None),
            (20, false, 1, 4, None),
            (10, true, 1, 4, None),
            (20, true, 1, 4, None),
        ],
    );
    assert!(f.run(cycle()).0.findings.is_empty());
    f.movement(2, 1, 20, 10, 2);
    let (run, _) = f.run(cycle());
    assert_eq!(paths(&run), [vec![(1, 10), (2, 20)]]);
    assert_eq!(run.findings[0].statistic.value(), 2);
    assert_eq!(run.findings[0].population, 5);
}

#[test]
fn graph_traversal_is_iterative_and_budget_exhaustion_never_returns_partial_components() {
    let transfers: Vec<_> = (0..3_000u128)
        .map(|from| Transfer {
            entry: from,
            recorded: from as u64,
            effective: 0,
            from,
            to: (from + 1) % 3_000,
            unit: 1,
            entity: None,
            amount: 1,
        })
        .collect();
    let legs: Vec<_> = transfers.iter().collect();
    let graph = Graph::new(&legs, &mut Budget(MAX_GRAPH_VISITS)).unwrap();
    let (components, sizes) = graph.components(&mut Budget(MAX_GRAPH_VISITS)).unwrap();
    assert_eq!(sizes, [3_000]);
    assert!(components.iter().all(|&component| component == 0));
    assert_eq!(
        graph.components(&mut Budget(10)).unwrap_err().predicate,
        "bounded_input"
    );
    assert!(graph.has_reachable(0, 8, &mut Budget(100)).unwrap());
    assert_eq!(
        graph
            .has_reachable(0, 8, &mut Budget(0))
            .unwrap_err()
            .predicate,
        "bounded_input"
    );
}

#[test]
fn decoder_rejects_historical_layering_wrong_versions_cutoffs_and_parameter_ranges() {
    let mut f = Fixture::new();
    f.movement(1, 0, 10, 20, 100);
    for profile in [cycle(), chain()] {
        for version in [0, 1, 2, 3, 4] {
            if version == if profile == cycle() { 2 } else { 3 } {
                continue;
            }
            let (_, output) = recompute_version(
                [1; 16],
                100,
                version,
                None,
                profile,
                f.entries.clone(),
                &f.registry,
            )
            .unwrap();
            assert_eq!(
                certificate(&wrap(&output)).err().unwrap().predicate,
                "procedure_profile"
            );
        }
        let (_, output) = recompute_version(
            [1; 16],
            100,
            if profile == cycle() { 2 } else { 3 },
            Some(0),
            profile,
            f.entries.clone(),
            &f.registry,
        )
        .unwrap();
        assert_eq!(
            certificate(&wrap(&output)).err().unwrap().predicate,
            "procedure_profile"
        );
    }
    for circular in [false, true] {
        for hops in [1, 9] {
            let mut writer = Writer::default();
            writer.count(3);
            let defaults = if circular {
                CIRCULAR_DEFAULTS
            } else {
                LAYERING_DEFAULTS
            };
            for (index, (name, value)) in defaults.iter().enumerate() {
                writer.bytes(name.as_bytes()).i128(if index == 0 {
                    hops
                } else {
                    i128::from(*value)
                });
            }
            assert_eq!(
                decode(&mut Reader::new(&writer.buf), circular)
                    .unwrap_err()
                    .predicate,
                "procedure_profile"
            );
        }
    }
}
