use super::super::{
    TraceContext, TraceEntryFacts, VerifiedProcedure, decode as decode_certificate, framed_hash,
    recompute_version, replay as replay_certificate,
};
use super::*;
use crate::blake3::hash_parts;
use crate::codec::Writer;
use std::collections::BTreeMap;

fn selection(lifo: bool, source: u128, order: u32) -> VerifiedProcedureParameters {
    if lifo {
        VerifiedProcedureParameters::TraceLifo {
            intraday_order: order,
            account: 7,
            source,
        }
    } else {
        VerifiedProcedureParameters::TraceFifo {
            intraday_order: order,
            account: 7,
            source,
        }
    }
}

struct Population {
    entries: Vec<Entry>,
    registry: Registry,
}

impl Population {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            registry: Registry {
                unit_scales: BTreeMap::from([(1, 2), (2, 0)]),
                unit_currencies: BTreeMap::new(),
                account_types: BTreeMap::new(),
                trace: Some(TraceContext {
                    account_normal_balances: BTreeMap::from([(7, 0), (99, 1)]),
                    entries: BTreeMap::new(),
                }),
                policy_oid: [7; 32],
            },
        }
    }

    fn add(&mut self, id: u128, day: i32, recorded: u64, amount: i128, inflow: bool) {
        self.entries.push(Entry {
            identity: id,
            digest: hash_parts(b"ordered-tracing-test-entry", &[&id.to_le_bytes()]),
            recorded_at: recorded,
            effective: Some(day),
            class: 1,
            legs: vec![(1, amount), (1, amount)],
            leg_accounts: vec![(7, inflow), (99, !inflow)],
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: None,
            transition: None,
        });
        self.registry.trace.as_mut().unwrap().entries.insert(
            id,
            TraceEntryFacts {
                entities: vec![Vec::new(), Vec::new()],
                evidence: BTreeSet::new(),
            },
        );
    }

    fn entry(&mut self, id: u128) -> &mut Entry {
        self.entries
            .iter_mut()
            .find(|entry| entry.identity == id)
            .unwrap()
    }

    fn facts(&mut self, id: u128) -> &mut TraceEntryFacts {
        self.registry
            .trace
            .as_mut()
            .unwrap()
            .entries
            .get_mut(&id)
            .unwrap()
    }

    fn run(
        &self,
        profile: VerifiedProcedureParameters,
        claim: i32,
    ) -> Result<(VerifiedProcedure, Vec<u8>), ReportError> {
        recompute_version(
            [1; 16],
            100_000,
            2,
            Some(claim),
            profile,
            self.entries.clone(),
            &self.registry,
        )
    }
}

fn mixed_money() -> Population {
    let mut population = Population::new();
    for (id, day, amount, inflow) in [
        (500, 0, 30, true),
        (257, 1, 100, true),
        (256, 2, 80, true),
        (4, 3, 60, false),
        (5, 4, 40, false),
    ] {
        population.add(id, day, day as u64 + 1, amount, inflow);
    }
    population
}

fn amount(report: &VerifiedProcedure) -> i128 {
    assert_eq!(report.findings.len(), 1);
    report.findings[0].statistic.value()
}

fn citations(report: &VerifiedProcedure) -> &[u128] {
    let VerifiedProcedureStatistic::TracedAmount { entries, .. } = &report.findings[0].statistic
    else {
        panic!("ordered tracing amount statistic");
    };
    entries
}

#[test]
fn fifo_and_lifo_independently_consume_older_and_newer_money() {
    let mut population = mixed_money();
    for (lifo, retained, carried, count, cites, name) in [
        (false, 30, 70, 2, vec![257, 4, 5], "FIFO (Clayton)"),
        (true, 80, 20, 1, vec![257, 5], "LIFO"),
    ] {
        let (report, output) = population.run(selection(lifo, 257, 0), 4).unwrap();
        assert_eq!(amount(&report), retained);
        assert_eq!(citations(&report), cites);
        assert_eq!(
            report.procedure,
            if lifo { "trace.lifo" } else { "trace.fifo" }
        );
        assert_eq!(
            (
                report.population,
                report.live_entries,
                report.live_legs,
                report.comparisons
            ),
            (5, 5, 4, 10)
        );
        let finding = &report.findings[0];
        assert_eq!(
            (finding.entry, finding.severity, finding.population),
            (None, 0, 5)
        );
        assert_eq!(finding.statistic.scale(), 2);
        assert_eq!(
            finding.narrative,
            format!(
                "{name}: 100 (mantissa) deposited 1970-01-02; 3 later movement(s) through 1970-01-05; lowest balance after the deposit 110; {count} withdrawal(s) carried {carried} tainted; traced {retained}; implicit book entity"
            )
        );
        population.entries.reverse();
        assert_eq!(
            population.run(selection(lifo, 257, 0), 4).unwrap().1,
            output
        );
    }
}

#[test]
fn ordered_tracing_respects_intraday_order_and_recording_sequence() {
    let mut population = Population::new();
    population.add(50, 0, 1, 20, true);
    population.add(256, 1, 2, 100, true);
    population.add(1, 1, 3, 90, false);
    population.add(9, 1, 4, 70, true);
    for (order, fifo, lifo) in [(0, 30, 10), (2, 30, 30), (3, 30, 80)] {
        assert_eq!(
            amount(&population.run(selection(false, 256, order), 1).unwrap().0),
            fifo
        );
        assert_eq!(
            amount(&population.run(selection(true, 256, order), 1).unwrap().0),
            lifo
        );
    }
    // Numeric identities, not their little-endian bytes, break same-commit ties.
    population.entries.retain(|entry| entry.identity != 9);
    population.entry(1).recorded_at = 2;
    for lifo in [false, true] {
        let report = population.run(selection(lifo, 256, 0), 1).unwrap().0;
        assert_eq!(amount(&report), 30);
        assert_eq!(citations(&report), [256]);
        assert!(
            report.findings[0]
                .narrative
                .contains("; 0 later movement(s)")
        );
    }
}

#[test]
fn ordered_tracing_preserves_signed_overdrafts_and_never_replenishes_taint() {
    for lifo in [false, true] {
        let mut population = Population::new();
        population.add(1, 0, 1, 80, false);
        population.add(2, 1, 2, 100, true);
        population.add(3, 2, 3, 30, false);
        population.add(4, 3, 4, 50, true);
        for id in [2, 4] {
            population.facts(id).evidence.insert([1; 32]);
        }
        let report = population.run(selection(lifo, 2, 0), 3).unwrap().0;
        assert_eq!(amount(&report), 0);
        assert_eq!(citations(&report), [2, 3]);
        assert!(
            report.findings[0].narrative.contains(
                "lowest balance after the deposit -10; 1 withdrawal(s) carried 20 tainted"
            )
        );

        // A representable i128::MIN opening balance is not negated to recover
        // its magnitude: repayment still cannot create held funds.
        let mut minimum = Population::new();
        minimum.add(1, 0, 1, i128::MAX, false);
        minimum.add(2, 1, 2, 1, false);
        minimum.add(3, 2, 3, i128::MAX, true);
        minimum.add(4, 3, 4, 1, true);
        assert_eq!(amount(&minimum.run(selection(lifo, 3, 0), 3).unwrap().0), 0);
    }
}

#[test]
fn ordered_tracing_turnover_does_not_accumulate_spent_clean_money() {
    for lifo in [false, true] {
        let mut population = Population::new();
        population.add(1, 0, 1, 1, true);
        for index in 1..=20u128 {
            population.add(
                index * 2,
                index as i32 * 2,
                index as u64 * 2,
                i128::MAX - 1,
                true,
            );
            population.add(
                index * 2 + 1,
                index as i32 * 2 + 1,
                index as u64 * 2 + 1,
                i128::MAX - 1,
                false,
            );
        }
        let report = population.run(selection(lifo, 1, 0), 100).unwrap().0;
        assert_eq!(amount(&report), i128::from(lifo));
        assert!(
            report.findings[0]
                .narrative
                .contains("lowest balance after the deposit 1;")
        );
        population.add(100, 101, 100, i128::MAX, true);
        assert_eq!(
            population
                .run(selection(lifo, 1, 0), 101)
                .unwrap_err()
                .predicate,
            "procedure_arithmetic"
        );
    }
}

#[test]
fn ordered_tracing_filters_effective_time_before_reversal_liveness() {
    for lifo in [false, true] {
        let mut population = mixed_money();
        population.add(8, 5, 6, 500, false);
        let report = population.run(selection(lifo, 257, 0), 4).unwrap().0;
        assert_eq!(amount(&report), if lifo { 80 } else { 30 });
        assert_eq!((report.population, report.live_entries), (6, 5));
        let original = population.entry(257).clone();
        population.add(9, 6, 7, 100, false);
        let reversal = population.entry(9);
        reversal.class = 4;
        reversal.supersession = vec![(257, original.digest, 1)];
        assert_eq!(
            amount(&population.run(selection(lifo, 257, 0), 4).unwrap().0),
            amount(&report)
        );
        assert_eq!(
            population
                .run(selection(lifo, 257, 0), 6)
                .unwrap_err()
                .predicate,
            "procedure_source"
        );
    }
}

#[test]
fn ordered_tracing_isolates_source_entities_units_and_credit_normal_accounts() {
    for lifo in [false, true] {
        let mut population = mixed_money();
        for entry in &mut population.entries {
            for (_, debit) in &mut entry.leg_accounts {
                *debit = !*debit;
            }
        }
        let trace = population.registry.trace.as_mut().unwrap();
        trace.account_normal_balances.insert(7, 1);
        for facts in trace.entries.values_mut() {
            facts.entities = vec![vec![10], vec![10]];
        }
        population.add(8, 3, 6, 10_000, true);
        population.facts(8).entities = vec![vec![20], vec![20]];
        population.add(9, 3, 7, 10_000, true);
        population.facts(9).entities = vec![vec![10], vec![10]];
        for leg in &mut population.entry(9).legs {
            leg.0 = 2;
        }
        let report = population.run(selection(lifo, 257, 0), 4).unwrap().0;
        assert_eq!(amount(&report), if lifo { 80 } else { 30 });
        assert_eq!(
            (report.population, report.live_entries, report.live_legs),
            (7, 7, 4)
        );
        assert!(
            report.findings[0]
                .narrative
                .ends_with("entity 0000000000000000000000000000000a")
        );
        population.facts(257).entities[0].clear();
        assert_eq!(
            population
                .run(selection(lifo, 257, 0), 4)
                .unwrap_err()
                .predicate,
            "procedure_entities"
        );
    }
}

fn encoded(output: &[u8]) -> Vec<u8> {
    let mut certificate = Writer::default();
    certificate
        .bytes(super::super::FORMAT)
        .bytes(b"source certificate")
        .bytes(&[])
        .fixed(&[2; 32])
        .u128(3)
        .fixed(&[4; 32])
        .bytes(output);
    let digest = framed_hash(super::super::DIGEST_DOMAIN, &certificate.buf);
    certificate.fixed(&digest);
    certificate.buf
}

fn bindings(parameters: &[(&str, i128)], inputs: &[(&str, &str)]) -> Vec<u8> {
    let mut bytes = Writer::default();
    bytes.count(parameters.len());
    for &(name, value) in parameters {
        bytes.bytes(name.as_bytes()).i128(value);
    }
    bytes.count(inputs.len());
    for &(name, value) in inputs {
        bytes.bytes(name.as_bytes()).bytes(value.as_bytes());
    }
    bytes.buf
}

#[test]
fn ordered_tracing_refuses_unknown_laws_noncanonical_handles_and_missing_dates() {
    let inputs = [
        ("account", "00000000000000000000000000000007"),
        ("source", "00000000000000000000000000000101"),
    ];
    for lifo in [false, true] {
        for order in [0, 2, 3] {
            let encoded = bindings(&[("intraday_order", order)], &inputs);
            assert_eq!(
                decode(&mut Reader::new(&encoded), lifo).unwrap(),
                selection(lifo, 257, order as u32)
            );
        }
        for parameters in [
            vec![],
            vec![("intraday_order", 1)],
            vec![("intraday_order", -1)],
            vec![("intraday_order", 4)],
            vec![("intraday_order", i128::from(u32::MAX) + 1)],
            vec![("replenishment", 0)],
            vec![("intraday_order", 0), ("replenishment", 0)],
        ] {
            assert!(decode(&mut Reader::new(&bindings(&parameters, &inputs)), lifo).is_err());
        }
        for handles in [
            vec![],
            vec![inputs[0]],
            vec![inputs[1], inputs[0]],
            vec![inputs[0], inputs[0]],
            vec![("account", "7"), inputs[1]],
            vec![inputs[0], ("source", "0000000000000000000000000000000A")],
        ] {
            assert!(
                decode(
                    &mut Reader::new(&bindings(&[("intraday_order", 0)], &handles)),
                    lifo
                )
                .is_err()
            );
        }
        let profile = selection(lifo, 257, 0);
        for (version, claim) in [(1, Some(4)), (3, Some(4)), (2, None)] {
            let mut question = Writer::default();
            question
                .bytes(super::super::OUTPUT_FORMAT)
                .bytes(profile.id().as_bytes())
                .u16(version)
                .u8(0)
                .bytes(profile.evidence().as_bytes())
                .fixed(&[1; 16])
                .u64(100_000);
            super::super::cutoff(&mut question, claim);
            question.fixed(&bindings(&[("intraday_order", 0)], &inputs));
            assert_eq!(
                decode_certificate(&encoded(&question.buf))
                    .err()
                    .expect("unsupported tracing question")
                    .predicate,
                "procedure_profile"
            );
        }
        let mut population = mixed_money();
        population.registry.trace = None;
        assert_eq!(
            population.run(profile, 4).unwrap_err().predicate,
            "procedure_source"
        );
    }
}

#[test]
fn ordered_tracing_rejects_rehashed_forgery_and_uncited_population_omissions() {
    for lifo in [false, true] {
        let population = mixed_money();
        let (expected, output) = population.run(selection(lifo, 257, 0), 4).unwrap();
        let bytes = encoded(&output);
        let request = decode_certificate(&bytes).unwrap();
        assert_eq!(
            replay_certificate(
                &request,
                [1; 16],
                100_000,
                population.entries.clone(),
                &population.registry
            )
            .unwrap()
            .0,
            expected
        );

        let mut label = Writer::default();
        label.bytes(b"traced_mantissa");
        let at = output
            .windows(label.buf.len())
            .position(|window| window == label.buf)
            .unwrap()
            + label.buf.len();
        let mut changed = output.clone();
        changed[at..at + 16].copy_from_slice(&(amount(&expected) + 1).to_le_bytes());
        let changed = encoded(&changed);
        let changed = decode_certificate(&changed).unwrap();
        assert_eq!(
            replay_certificate(
                &changed,
                [1; 16],
                100_000,
                population.entries.clone(),
                &population.registry
            )
            .unwrap_err()
            .predicate,
            "procedure_recomputation"
        );

        // The clean deposit is part of the population even though no finding
        // cites it; its omission changes both the law and the input commitment.
        assert!(!citations(&expected).contains(&256));
        let mut missing = population.entries.clone();
        missing.retain(|entry| entry.identity != 256);
        assert_eq!(
            replay_certificate(&request, [1; 16], 100_000, missing, &population.registry)
                .unwrap_err()
                .predicate,
            "procedure_recomputation"
        );

        let handle = format!("{:032x}", 257);
        let at = output
            .windows(32)
            .position(|window| window == handle.as_bytes())
            .unwrap();
        let mut changed = output.clone();
        changed[at..at + 32].copy_from_slice(format!("{:032x}", 256).as_bytes());
        let changed = encoded(&changed);
        let changed = decode_certificate(&changed).unwrap();
        assert_eq!(
            replay_certificate(
                &changed,
                [1; 16],
                100_000,
                population.entries.clone(),
                &population.registry
            )
            .unwrap_err()
            .predicate,
            "procedure_recomputation"
        );
    }
}

#[test]
fn ordered_tracing_caps_citations_without_truncating_the_amount_or_carrier_count() {
    for lifo in [false, true] {
        let mut population = Population::new();
        population.add(90_000, 0, 1, (MAX_CITES * 2) as i128, true);
        for index in 1..=MAX_CITES + 2 {
            population.add(index as u128, index as i32, index as u64 + 1, 1, false);
        }
        let report = population
            .run(selection(lifo, 90_000, 0), 10_000)
            .unwrap()
            .0;
        assert_eq!(amount(&report), (MAX_CITES - 2) as i128);
        assert_eq!(citations(&report).len(), MAX_CITES - 1);
        assert_eq!(citations(&report)[0], 90_000);
        assert_eq!(citations(&report)[1], 1);
        assert_eq!(citations(&report)[MAX_CITES - 2], (MAX_CITES - 2) as u128);
        assert!(report.findings[0].narrative.contains(&format!(
            "{} withdrawal(s) carried {} tainted",
            MAX_CITES + 2,
            MAX_CITES + 2
        )));
        assert_eq!(report.findings[0].population, (MAX_CITES + 3) as u64);
    }
}
