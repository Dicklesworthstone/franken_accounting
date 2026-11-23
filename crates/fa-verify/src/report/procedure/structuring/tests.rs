use super::*;
use crate::blake3::hash_parts;
use crate::codec::Writer;
use crate::report::procedure::{
    DIGEST_DOMAIN, EXTENDED_FORMAT, FORMAT, TraceContext, TraceEntryFacts, VerifiedProcedure,
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
                unit_scales: BTreeMap::from([(1, 2), (2, 0), (3, 2)]),
                unit_currencies: BTreeMap::from([(1, 840), (2, 392), (3, 840)]),
                account_types: BTreeMap::new(),
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

    fn legs(&mut self, identity: u128, day: i32, legs: &[(u128, bool, u32, i128, Option<u128>)]) {
        self.registry.trace.as_mut().unwrap().entries.insert(
            identity,
            TraceEntryFacts {
                entities: legs.iter().map(|leg| leg.4.into_iter().collect()).collect(),
                evidence: BTreeSet::new(),
            },
        );
        self.entries.push(Entry {
            identity,
            digest: hash_parts(b"structuring-test", &[&identity.to_le_bytes()]),
            recorded_at: identity as u64,
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

    fn movement(
        &mut self,
        identity: u128,
        day: i32,
        amount: i128,
        unit: u32,
        entity: Option<u128>,
    ) {
        self.legs(
            identity,
            day,
            &[
                (10, false, unit, amount, entity),
                (20, true, unit, amount, entity),
            ],
        );
    }

    fn reverse(&mut self, identity: u128, target: u128) {
        let mut entry = self
            .entries
            .iter()
            .find(|entry| entry.identity == target)
            .unwrap()
            .clone();
        entry.supersession = vec![(target, entry.digest, 1)];
        entry.class = 4;
        entry.identity = identity;
        entry.recorded_at = identity as u64;
        entry.digest = hash_parts(b"structuring-test", &[&identity.to_le_bytes()]);
        for (_, debit) in &mut entry.leg_accounts {
            *debit = !*debit;
        }
        let context = self.registry.trace.as_mut().unwrap();
        context
            .entries
            .insert(identity, context.entries[&target].clone());
        self.entries.push(entry);
    }

    fn run(
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

    fn flow(&self) -> Result<Vec<Transfer>, ReportError> {
        flow(&self.entries.iter().collect::<Vec<_>>(), &self.registry)
    }
}

fn profile(window_days: u32) -> VerifiedProcedureParameters {
    VerifiedProcedureParameters::GraphStructuring {
        currency_iso4217: 840,
        floor: 80,
        min_count: 3,
        threshold: 100,
        window_days,
    }
}

fn wrap(output: &[u8], extended: bool) -> Vec<u8> {
    let mut writer = Writer::default();
    writer
        .bytes(if extended { EXTENDED_FORMAT } else { FORMAT })
        .bytes(b"native source")
        .bytes(b"opaque approval witness");
    if extended {
        writer.count(6);
        for _ in 0..6 {
            writer.bytes(b"opaque extended witness");
        }
    }
    writer.fixed(&[2; 32]).u128(7).fixed(&[3; 32]).bytes(output);
    let digest = framed_hash(DIGEST_DOMAIN, &writer.buf);
    writer.fixed(&digest);
    writer.buf
}

#[test]
fn graph_allocation_conserves_both_margins_instead_of_repeating_remainder_ties() {
    let mut f = Fixture::new();
    f.legs(
        1,
        0,
        &[
            (1, false, 1, 1, None),
            (2, false, 1, 1, None),
            (3, true, 1, 1, None),
            (4, true, 1, 1, None),
        ],
    );
    let actual = f.flow().unwrap();
    assert_eq!(
        actual
            .iter()
            .map(|t| (t.from, t.to, t.amount))
            .collect::<Vec<_>>(),
        [(1, 3, 1), (2, 4, 1)]
    );
    f.entries[0].legs.reverse();
    f.entries[0].leg_accounts.reverse();
    assert_eq!(f.flow().unwrap(), actual);

    let mut wide = Fixture::new();
    wide.legs(
        1,
        0,
        &[
            (1, false, 1, i128::MAX, None),
            (2, false, 1, i128::MAX, None),
            (3, true, 1, i128::MAX, None),
            (4, true, 1, i128::MAX, None),
        ],
    );
    let flow = wide.flow().unwrap();
    let half = i128::MAX / 2;
    assert_eq!(
        flow.iter()
            .map(|t| (t.from, t.to, t.amount))
            .collect::<Vec<_>>(),
        [
            (1, 3, half + 1),
            (1, 4, half),
            (2, 3, half),
            (2, 4, half + 1),
        ]
    );
}

#[test]
fn graph_chains_use_consecutive_gaps_and_complete_transfer_populations() {
    let mut f = Fixture::new();
    for (identity, day, amount) in [
        (1, 0, 80),
        (2, 5, 81),
        (3, 10, 82),
        (4, 16, 83),
        (5, 11, 79),
        (6, 11, 100),
    ] {
        f.movement(identity, day, amount, 1, None);
    }
    f.movement(7, 1, 90, 2, None);
    f.movement(8, 2, 90, 3, None);
    f.legs(9, 1, &[(10, false, 1, 90, None), (10, true, 1, 90, None)]);
    let (run, output) = f.run(profile(5)).unwrap();
    assert_eq!(
        (
            run.population,
            run.live_entries,
            run.live_legs,
            run.comparisons
        ),
        (9, 0, 9, 5)
    );
    assert_eq!(run.findings.len(), 1);
    assert_eq!(run.findings[0].population, 5);
    assert_eq!(run.findings[0].severity, 3);
    assert!(matches!(&run.findings[0].statistic,
        VerifiedProcedureStatistic::StructuredTransfers { from: 10, to: 20, unit: 1, entity: None, transfers: 3, mantissa: 243, entries, .. }
        if entries == &[1, 2, 3]));
    assert!(
        run.findings[0]
            .narrative
            .contains("within 10 day(s) summing to 243")
    );
    let bytes = wrap(&output, false);
    let decoded = certificate(&bytes).unwrap();
    super::super::replay(&decoded, [1; 16], 100, f.entries.clone(), &f.registry).unwrap();

    let (zero, _) = f.run(profile(0)).unwrap();
    assert!(zero.findings.is_empty());
    assert_eq!(
        (zero.population, zero.live_legs, zero.comparisons),
        (9, 9, 5)
    );
    assert!(
        Fixture::new()
            .run(profile(5))
            .unwrap()
            .0
            .findings
            .is_empty()
    );
}

#[test]
fn graph_entity_and_currency_partitions_cannot_pool_subthreshold_populations() {
    let mut f = Fixture::new();
    for (identity, unit, entity) in [
        (1, 1, 7),
        (2, 1, 7),
        (3, 1, 9),
        (4, 1, 9),
        (5, 3, 7),
        (6, 3, 7),
        (7, 2, 7),
        (8, 2, 7),
    ] {
        f.movement(identity, 0, 80, unit, Some(entity));
    }
    assert!(f.run(profile(5)).unwrap().0.findings.is_empty());
    f.movement(9, 1, 80, 1, Some(7));
    let run = f.run(profile(5)).unwrap().0;
    assert_eq!(run.findings.len(), 1);
    assert_eq!(run.findings[0].population, 7);
    assert!(matches!(&run.findings[0].statistic,
        VerifiedProcedureStatistic::StructuredTransfers { entity: Some(7), unit: 1, entries, .. }
        if entries == &[1, 2, 9]));
    f.movement(10, 1, 80, 1, None);
    assert_eq!(
        f.run(profile(5)).unwrap_err().predicate,
        "procedure_profile"
    );

    let mut single = Fixture::new();
    for identity in 1..=3 {
        single.movement(identity, 0, 80, 1, (identity == 2).then_some(7));
    }
    assert!(matches!(
        single.run(profile(5)).unwrap().0.findings[0].statistic,
        VerifiedProcedureStatistic::StructuredTransfers {
            entity: Some(7),
            ..
        }
    ));
}

#[test]
fn graph_reversals_and_source_changes_cannot_be_hidden_by_resealed_output() {
    let mut f = Fixture::new();
    for identity in 1..=3 {
        f.movement(identity, 0, 80, 1, None);
    }
    let (original, output) = f.run(profile(5)).unwrap();
    let bytes = wrap(&output, false);
    let request = certificate(&bytes).unwrap();
    f.reverse(4, 1);
    assert!(f.run(profile(5)).unwrap().0.findings.is_empty());
    assert_eq!(
        super::super::replay(&request, [1; 16], 100, f.entries.clone(), &f.registry)
            .unwrap_err()
            .predicate,
        "procedure_recomputation"
    );
    f.reverse(5, 4);
    let restored = f.run(profile(5)).unwrap().0;
    assert_eq!(restored.findings, original.findings);
    assert_eq!(
        (
            restored.population,
            restored.live_legs,
            restored.comparisons
        ),
        (5, 3, 3)
    );

    let mut forged = Fixture::new();
    for identity in 1..=3 {
        forged.movement(identity, 0, 81, 1, None);
    }
    let changed = wrap(&forged.run(profile(5)).unwrap().1, false);
    let changed = certificate(&changed).unwrap();
    assert_eq!(
        super::super::replay(&changed, [1; 16], 100, f.entries[..3].to_vec(), &f.registry)
            .unwrap_err()
            .predicate,
        "procedure_recomputation"
    );
}

#[test]
fn graph_full_width_thresholds_and_long_day_spans_remain_exact() {
    let mut f = Fixture::new();
    f.movement(1, i32::MIN, i128::MAX / 2, 1, None);
    f.movement(2, i32::MAX, i128::MAX / 2 + 1, 1, None);
    let profile = VerifiedProcedureParameters::GraphStructuring {
        currency_iso4217: 840,
        floor: 0,
        min_count: 2,
        threshold: i128::MAX,
        window_days: u32::MAX,
    };
    let (run, output) = f.run(profile).unwrap();
    assert_eq!(run.findings.len(), 1);
    assert_eq!(run.findings[0].severity, 2);
    assert_eq!(run.findings[0].statistic.value(), i128::MAX);
    assert!(
        run.findings[0]
            .narrative
            .contains("within 4294967295 day(s)")
    );
    assert_eq!(
        certificate(&wrap(&output, false)).unwrap().parameters,
        profile
    );
    f.movement(3, 0, 1, 1, None);
    assert_eq!(
        f.run(profile).unwrap_err().predicate,
        "procedure_arithmetic"
    );
}

#[test]
fn graph_corrupt_margins_entities_and_quadratic_expansion_are_refused() {
    for legs in [
        vec![(10, false, 1, 80, Some(7)), (20, true, 1, 80, Some(9))],
        vec![(10, false, 1, 80, None), (20, true, 1, 79, None)],
        vec![(10, false, 1, -80, None), (20, true, 1, -80, None)],
    ] {
        let mut f = Fixture::new();
        f.legs(1, 0, &legs);
        assert_eq!(
            f.run(profile(5)).unwrap_err().predicate,
            "procedure_profile"
        );
    }
    let mut duplicate = Fixture::new();
    duplicate.movement(1, 0, 80, 1, None);
    duplicate
        .registry
        .trace
        .as_mut()
        .unwrap()
        .entries
        .get_mut(&1)
        .unwrap()
        .entities[0] = vec![7, 9];
    assert!(duplicate.run(profile(5)).is_err());
    assert!(allocation_budget(MAX_ALLOCATION_CELLS, 1).is_err());
    assert!(allocation_budget(u64::MAX, 1).is_err());
    assert_eq!(
        allocation_budget(MAX_ALLOCATION_CELLS - 1, 1).unwrap(),
        MAX_ALLOCATION_CELLS
    );
    let mut expanded = Fixture::new();
    let mut legs = Vec::new();
    for account in 1..=2048 {
        legs.push((account, false, 1, 1, None));
        legs.push((account + 2048, true, 1, 1, None));
    }
    expanded.legs(1, 0, &legs);
    assert_eq!(
        expanded.run(profile(5)).unwrap_err().predicate,
        "bounded_input"
    );
}

#[test]
fn graph_profile_refuses_wrong_versions_formats_cutoffs_and_parameter_inventories() {
    let f = Fixture::new();
    let output = f.run(profile(5)).unwrap().1;
    assert_eq!(
        certificate(&wrap(&output, true)).err().unwrap().predicate,
        "procedure_profile"
    );
    for (version, cutoff) in [(1, None), (3, None), (2, Some(0))] {
        let output = recompute_version(
            [1; 16],
            100,
            version,
            cutoff,
            profile(5),
            Vec::new(),
            &f.registry,
        )
        .unwrap()
        .1;
        assert_eq!(
            certificate(&wrap(&output, false)).err().unwrap().predicate,
            "procedure_profile"
        );
    }
    let values: Vec<_> = DEFAULTS
        .iter()
        .map(|(name, value)| (*name, i128::from(*value)))
        .collect();
    for (index, value) in [
        (0, 0),
        (0, 1000),
        (1, -1),
        (1, 1_000_000),
        (2, 0),
        (2, i128::from(u32::MAX) + 1),
        (3, 0),
        (4, -1),
    ] {
        let mut parameters = values.clone();
        parameters[index].1 = value;
        let mut writer = Writer::default();
        writer.count(parameters.len());
        for (name, value) in parameters {
            writer.bytes(name.as_bytes()).i128(value);
        }
        assert!(decode(&mut Reader::new(&writer.buf)).is_err());
    }
    for parameters in [
        values[..4].to_vec(),
        vec![values[0], values[0], values[2], values[3], values[4]],
        vec![values[1], values[0], values[2], values[3], values[4]],
    ] {
        let mut writer = Writer::default();
        writer.count(parameters.len());
        for (name, value) in parameters {
            writer.bytes(name.as_bytes()).i128(value);
        }
        assert!(decode(&mut Reader::new(&writer.buf)).is_err());
    }
}

#[test]
fn graph_split_legs_count_transfers_but_cite_each_entry_only_once() {
    let mut f = Fixture::new();
    f.legs(
        1,
        0,
        &[
            (10, false, 1, 240, None),
            (20, true, 1, 80, None),
            (20, true, 1, 80, None),
            (20, true, 1, 80, None),
        ],
    );
    let run = f.run(profile(5)).unwrap().0;
    assert_eq!((run.live_legs, run.comparisons), (3, 3));
    assert_eq!(run.findings.len(), 1);
    assert!(matches!(&run.findings[0].statistic,
        VerifiedProcedureStatistic::StructuredTransfers { transfers: 3, mantissa: 240, entries, .. }
        if entries == &[1]));
}
