use super::*;
use crate::blake3::hash_parts;
use crate::codec::Writer;
use crate::report::procedure::{
    DIGEST_DOMAIN, EntryPeriod, FORMAT, TraceContext, TraceEntryFacts, VerifiedProcedure,
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
                account_types: BTreeMap::from([(10, 1), (20, 1), (30, 1), (40, 3)]),
                leg_parties: BTreeMap::new(),
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
            digest: hash_parts(b"round-trip-test", &[&id.to_le_bytes()]),
            recorded_at: id as u64,
            effective: Some(day),
            class: 1,
            legs: legs.iter().map(|leg| (leg.2, leg.3)).collect(),
            leg_accounts: legs.iter().map(|leg| (leg.0, leg.1)).collect(),
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: Some(EntryPeriod {
                code: "P".into(),
                effective: day,
                end: 31,
                document: None,
            }),
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

    fn run(&self, days: u32) -> (VerifiedProcedure, Vec<u8>) {
        self.run_profile(profile(days)).unwrap()
    }

    fn run_profile(
        &self,
        profile: VerifiedProcedureParameters,
    ) -> Result<(VerifiedProcedure, Vec<u8>), ReportError> {
        recompute_version(
            [1; 16],
            100,
            2,
            None,
            profile,
            self.entries.clone(),
            &self.registry,
        )
    }
}

fn profile(window_days: u32) -> VerifiedProcedureParameters {
    VerifiedProcedureParameters::GraphRoundTrips {
        max_hops: 2,
        max_search_steps: 250_000,
        period_end_days: 7,
        window_days,
    }
}

fn cycle_profile(
    max_hops: u32,
    window_days: u32,
    max_search_steps: u32,
) -> VerifiedProcedureParameters {
    VerifiedProcedureParameters::GraphRoundTrips {
        max_hops,
        max_search_steps,
        period_end_days: 7,
        window_days,
    }
}

fn paths(report: &VerifiedProcedure) -> Vec<Vec<(u128, u128)>> {
    let mut paths: Vec<_> = report
        .findings
        .iter()
        .map(|finding| match &finding.statistic {
            VerifiedProcedureStatistic::RoundTripCycle { hops, .. } => hops.clone(),
            _ => panic!("wrong statistic"),
        })
        .collect();
    paths.sort();
    paths
}

fn pairs(report: &VerifiedProcedure) -> Vec<(u128, u128)> {
    let mut pairs: Vec<_> = report
        .findings
        .iter()
        .map(|finding| match finding.statistic {
            VerifiedProcedureStatistic::RoundTrip {
                outbound, returned, ..
            } => (outbound, returned),
            _ => panic!("wrong statistic"),
        })
        .collect();
    pairs.sort_unstable();
    pairs
}

fn wrap(output: &[u8]) -> Vec<u8> {
    let mut writer = Writer::default();
    writer
        .bytes(FORMAT)
        .bytes(b"native source")
        .bytes(b"native approval")
        .fixed(&[2; 32])
        .u128(7)
        .fixed(&[3; 32])
        .bytes(output);
    writer.fixed(&framed_hash(DIGEST_DOMAIN, &writer.buf));
    writer.buf
}

#[test]
fn round_trips_pair_earliest_unused_returns_and_include_the_exact_window_boundary() {
    let mut f = Fixture::new();
    f.movement(1, 0, 10, 20, 100);
    f.movement(2, 1, 10, 20, 100);
    f.movement(3, 5, 20, 10, 100);
    f.movement(4, 6, 20, 10, 100);
    let (run, output) = f.run(5);
    assert_eq!(pairs(&run), [(1, 3), (2, 4)]);
    assert_eq!(
        (run.live_entries, run.live_legs, run.comparisons),
        (0, 4, 11)
    );
    assert!(
        run.findings
            .iter()
            .all(|finding| finding.population == 4 && finding.severity == 2)
    );
    // One day less excludes the first outward movement, but still pairs the
    // second with its earliest qualifying return. A transfer cannot be reused.
    assert_eq!(pairs(&f.run(4).0), [(2, 3)]);
    let mut reversed = f.entries.clone();
    reversed.reverse();
    let (_, reordered) =
        recompute_version([1; 16], 100, 2, None, profile(5), reversed, &f.registry).unwrap();
    assert_eq!(reordered, output);
    let bytes = wrap(&output);
    let decoded = certificate(&bytes).unwrap();
    assert_eq!(decoded.parameters, profile(5));
    assert_eq!(
        super::super::replay(&decoded, [1; 16], 100, f.entries, &f.registry)
            .unwrap()
            .1,
        output
    );
}

#[test]
fn round_trips_refuse_same_entry_cycles_and_charge_skipped_candidates() {
    let mut f = Fixture::new();
    f.legs(
        1,
        0,
        &[
            (10, false, 1, 8, None),
            (20, false, 1, 8, None),
            (10, true, 1, 8, None),
            (20, true, 1, 8, None),
        ],
    );
    assert!(f.run(5).0.findings.is_empty());
    f.movement(2, 5, 20, 10, 4);
    let (run, _) = f.run(5);
    assert_eq!(pairs(&run), [(1, 2)]);
    assert_eq!((run.live_legs, run.comparisons), (5, 6));
    assert_eq!(run.findings[0].statistic.value(), 4);
    assert_eq!(run.findings[0].population, 3);
}

#[test]
fn round_trips_preserve_units_entities_amounts_and_authenticated_asset_types() {
    let mut f = Fixture::new();
    for (id, from, to, unit, amount, entity) in [
        (1, 10, 20, 1, 100, Some(7)),
        (2, 20, 10, 1, 100, Some(8)),
        (3, 20, 10, 2, 100, Some(7)),
        (4, 20, 10, 1, 101, Some(7)),
        (5, 10, 40, 1, 100, Some(7)),
        (6, 40, 10, 1, 100, Some(7)),
    ] {
        f.legs(
            id,
            25,
            &[
                (from, false, unit, amount, entity),
                (to, true, unit, amount, entity),
            ],
        );
    }
    assert!(f.run(0).0.findings.is_empty());
    f.legs(
        7,
        25,
        &[(20, false, 1, 100, Some(7)), (10, true, 1, 100, Some(7))],
    );
    let (run, _) = f.run(0);
    assert_eq!(pairs(&run), [(1, 7)]);
    assert_eq!(run.findings[0].severity, 3);
    assert_eq!(run.findings[0].population, 5);
    assert!(matches!(
        run.findings[0].statistic,
        VerifiedProcedureStatistic::RoundTrip {
            entity: Some(7),
            unit: 1,
            scale: 2,
            ..
        }
    ));
    // The original historical chart decides eligibility, not a narrative.
    f.registry.account_types.insert(20, 3);
    assert!(f.run(0).0.findings.is_empty());
}

#[test]
fn round_trips_retain_full_width_amounts_and_authenticated_period_severity() {
    let mut f = Fixture::new();
    f.movement(1, 23, 10, 20, i128::MAX);
    f.movement(2, 24, 20, 10, i128::MAX);
    let (run, _) = f.run(1);
    assert_eq!(run.findings[0].statistic.value(), i128::MAX);
    assert_eq!(run.findings[0].severity, 3);
    assert!(
        run.findings[0]
            .narrative
            .contains("outbound 7 and return 6 day(s)")
    );
    for entry in &mut f.entries {
        entry.period.as_mut().unwrap().end = 100;
    }
    assert_eq!(f.run(1).0.findings[0].severity, 2);
}

#[test]
fn round_trips_decoder_admits_bounded_hops_and_rejects_malformed_parameter_inventories() {
    for max_hops in 2..=8 {
        let mut writer = Writer::default();
        writer.count(4);
        for ((name, _), value) in DEFAULTS.iter().zip([max_hops, 250_000, 7, 5]) {
            writer.bytes(name.as_bytes()).i128(value);
        }
        assert_eq!(
            decode(&mut Reader::new(&writer.buf)).unwrap(),
            cycle_profile(max_hops as u32, 5, 250_000),
        );
    }
    for values in [
        [1i128, 250_000, 7, 5],
        [9, 250_000, 7, 5],
        [2, 0, 7, 5],
        [2, 10_000_001, 7, 5],
        [2, 250_000, -1, 5],
        [2, 250_000, 7, i128::from(u32::MAX) + 1],
    ] {
        let mut writer = Writer::default();
        writer.count(4);
        for ((name, _), value) in DEFAULTS.iter().zip(values) {
            writer.bytes(name.as_bytes()).i128(value);
        }
        assert_eq!(
            decode(&mut Reader::new(&writer.buf)).unwrap_err().predicate,
            "procedure_profile"
        );
    }
    for names in [
        ["max_hops", "max_hops", "period_end_days", "window_days"],
        [
            "max_hops",
            "max_search_steps",
            "window_days",
            "period_end_days",
        ],
    ] {
        let mut writer = Writer::default();
        writer.count(4);
        for (name, (_, value)) in names.into_iter().zip(DEFAULTS) {
            writer.bytes(name.as_bytes()).i128(i128::from(value));
        }
        assert_eq!(
            decode(&mut Reader::new(&writer.buf)).unwrap_err().predicate,
            "procedure_profile"
        );
    }
}

#[test]
fn round_trip_cycles_backtrack_and_consume_the_first_complete_temporal_path() {
    let mut f = Fixture::new();
    f.registry.account_types.insert(40, 1);
    f.movement(1, 0, 10, 20, 100);
    f.movement(2, 1, 20, 30, 100); // Earlier alternative is a dead end.
    f.movement(3, 1, 20, 40, 100);
    f.movement(4, 2, 40, 10, 100);
    f.movement(5, 3, 20, 10, 100); // Direct return loses to the earlier chain.
    f.movement(6, 4, 10, 20, 100);
    f.movement(7, 5, 20, 10, 100);
    let profile = cycle_profile(3, 5, 250_000);
    let (run, output) = f.run_profile(profile).unwrap();
    assert_eq!(
        paths(&run),
        [vec![(1, 10), (3, 20), (4, 40)], vec![(5, 20), (6, 10)]],
    );
    assert_eq!(
        (run.live_entries, run.live_legs, run.comparisons),
        (0, 7, 25)
    );
    assert!(run.findings.iter().all(|finding| finding.population == 7));
    assert!(
        run.findings[0]
            .narrative
            .contains("through 3 asset accounts")
    );
    // Input iteration does not choose the path or the finding/citation order.
    f.entries.reverse();
    assert_eq!(f.run_profile(profile).unwrap().1, output);
    let bytes = wrap(&output);
    let decoded = certificate(&bytes).unwrap();
    assert_eq!(decoded.parameters, profile);
    assert_eq!(
        super::super::replay(&decoded, [1; 16], 100, f.entries, &f.registry)
            .unwrap()
            .1,
        output,
    );
}

#[test]
fn round_trip_cycles_enforce_eight_hop_boundary_and_preserve_full_width_amounts() {
    let mut f = Fixture::new();
    for index in 0..8u128 {
        let from = (index + 1) * 10;
        let to = ((index + 1) % 8 + 1) * 10;
        f.registry.account_types.insert(from, 1);
        f.movement(index + 1, 23 + index as i32, from, to, i128::MAX);
    }
    assert!(
        f.run_profile(cycle_profile(7, 7, 100))
            .unwrap()
            .0
            .findings
            .is_empty()
    );
    assert!(
        f.run_profile(cycle_profile(8, 6, 100))
            .unwrap()
            .0
            .findings
            .is_empty()
    );
    let (run, _) = f.run_profile(cycle_profile(8, 7, 100)).unwrap();
    assert_eq!(run.findings.len(), 1);
    assert_eq!(paths(&run)[0].len(), 8);
    assert_eq!(run.findings[0].statistic.value(), i128::MAX);
    assert_eq!(run.findings[0].statistic.scale(), 2);
    assert_eq!(run.findings[0].severity, 3);
    assert_eq!(run.findings[0].population, 8);
    assert_eq!(
        (run.live_entries, run.live_legs, run.comparisons),
        (0, 8, 39)
    );
    // An intermediate account's historical type is part of eligibility.
    f.registry.account_types.insert(50, 3);
    assert!(
        f.run_profile(cycle_profile(8, 7, 100))
            .unwrap()
            .0
            .findings
            .is_empty()
    );
}

#[test]
fn round_trip_cycles_refuse_all_results_after_search_budget_exhaustion() {
    let mut f = Fixture::new();
    f.movement(1, 0, 10, 20, 100);
    f.movement(2, 1, 20, 30, 100);
    f.movement(3, 2, 30, 10, 100);
    // The path completes on step three, but all three outer starts must also
    // be accounted for. A successful partial finding is never returned.
    for max_search_steps in [1, 3, 4] {
        assert_eq!(
            f.run_profile(cycle_profile(3, 2, max_search_steps))
                .unwrap_err()
                .predicate,
            "procedure_search_limit",
        );
    }
    let (run, _) = f.run_profile(cycle_profile(3, 2, 5)).unwrap();
    assert_eq!(paths(&run), [vec![(1, 10), (2, 20), (3, 30)]]);
    assert_eq!(run.comparisons, 8);
    assert!(
        Fixture::new()
            .run_profile(cycle_profile(8, 0, 1))
            .unwrap()
            .0
            .findings
            .is_empty()
    );
}

#[test]
fn round_trip_cycles_do_not_cross_entity_unit_amount_or_temporal_boundaries() {
    let mut f = Fixture::new();
    for (id, day, from, to, unit, amount, entity) in [
        (1, 0, 10, 20, 1, 100, 7),
        (2, 1, 20, 30, 1, 100, 8),
        (3, 1, 30, 10, 1, 100, 7),
        (4, 1, 20, 30, 2, 100, 7),
        (5, 1, 20, 30, 1, 101, 7),
        (6, 2, 20, 30, 1, 100, 7),
    ] {
        f.legs(
            id,
            day,
            &[
                (from, false, unit, amount, Some(entity)),
                (to, true, unit, amount, Some(entity)),
            ],
        );
    }
    let profile = cycle_profile(3, 3, 100);
    assert!(f.run_profile(profile).unwrap().0.findings.is_empty());
    f.legs(
        7,
        3,
        &[(30, false, 1, 100, Some(7)), (10, true, 1, 100, Some(7))],
    );
    let (run, _) = f.run_profile(profile).unwrap();
    assert_eq!(paths(&run), [vec![(1, 10), (6, 20), (7, 30)]]);
    assert!(matches!(
        run.findings[0].statistic,
        VerifiedProcedureStatistic::RoundTripCycle {
            entity: Some(7),
            unit: 1,
            mantissa: 100,
            ..
        }
    ));
}
