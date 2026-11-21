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
        recompute_version(
            [1; 16],
            100,
            2,
            None,
            profile(days),
            self.entries.clone(),
            &self.registry,
        )
        .unwrap()
    }
}

fn profile(window_days: u32) -> VerifiedProcedureParameters {
    VerifiedProcedureParameters::GraphRoundTrips {
        max_search_steps: 250_000,
        period_end_days: 7,
        window_days,
    }
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
fn round_trips_decoder_rejects_multihop_and_malformed_parameter_inventories() {
    for values in [
        [3i128, 250_000, 7, 5],
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
