use super::super::{
    Certificate, TraceContext, TraceEntryFacts, VerifiedProcedure, decode as decode_certificate,
    framed_hash, recompute_version, replay as replay_certificate,
};
use super::*;
use crate::blake3::hash_parts;
use crate::codec::Writer;

fn selection(source: u128, order: u32, replenishment: u32) -> VerifiedProcedureParameters {
    VerifiedProcedureParameters::TraceLibr {
        intraday_order: order,
        replenishment,
        account: 7,
        source,
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
                unit_scales: BTreeMap::from([(1, 2), (2, 0), (3, 38)]),
                unit_currencies: BTreeMap::new(),
                account_types: BTreeMap::new(),
                trace: Some(TraceContext {
                    account_normal_balances: BTreeMap::from([(7, 0), (8, 0), (99, 1)]),
                    entries: BTreeMap::new(),
                }),
                policy_oid: [7; 32],
            },
        }
    }

    fn add(&mut self, id: u128, day: i32, recorded: u64, amount: i128, inflow: bool) {
        self.entries.push(Entry {
            identity: id,
            digest: hash_parts(b"libr-test-entry", &[&id.to_le_bytes()]),
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

    fn entity(&mut self, id: u128, entity: u128) {
        let legs = self.entry(id).legs.len();
        self.facts(id).entities = vec![vec![entity]; legs];
    }

    fn unit(&mut self, id: u128, unit: u32) {
        for leg in &mut self.entry(id).legs {
            leg.0 = unit;
        }
    }

    fn reversal(&mut self, id: u128, target: u128, day: i32, recorded: u64) {
        let original = self.entry(target).clone();
        self.add(id, day, recorded, 0, true);
        let entry = self.entry(id);
        entry.class = 4;
        entry.legs = original.legs;
        entry.leg_accounts = original
            .leg_accounts
            .into_iter()
            .map(|(account, debit)| (account, !debit))
            .collect();
        entry.supersession.push((target, original.digest, 1));
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

fn amount(report: &VerifiedProcedure) -> i128 {
    assert_eq!(report.findings.len(), 1);
    report.findings[0].statistic.value()
}

fn citations(report: &VerifiedProcedure) -> &[u128] {
    let VerifiedProcedureStatistic::TracedAmount { entries, .. } = &report.findings[0].statistic
    else {
        panic!("LIBR amount statistic");
    };
    entries
}

fn replenishing_population() -> Population {
    let mut population = Population::new();
    for (id, day, amount, inflow) in [
        (500, 1, 30, true),
        (257, 2, 100, true),
        (2, 3, 110, false),
        (256, 4, 80, true),
        (7, 5, 40, true),
        (300, 6, 100, true),
        (8, 6, 500, true),
    ] {
        population.add(id, day, day as u64, amount, inflow);
    }
    population.entry(8).leg_accounts[0].0 = 8;
    for id in [257, 7, 300] {
        population.facts(id).evidence.insert([1; 32]);
    }
    population.facts(256).evidence.insert([2; 32]);
    population
}

#[test]
fn libr_replays_evidence_replenishment_exact_citations_and_complete_work() {
    let mut population = replenishing_population();
    let never = population.run(selection(257, 0, 0), 6).unwrap().0;
    assert_eq!(amount(&never), 20);
    assert_eq!(citations(&never), [257, 2]);
    let (restored, output) = population.run(selection(257, 0, 1), 6).unwrap();
    assert_eq!(amount(&restored), 100);
    assert_eq!(citations(&restored), [257, 2, 7, 300]);
    assert_eq!(
        (
            restored.population,
            restored.live_entries,
            restored.live_legs,
            restored.comparisons
        ),
        (7, 7, 5, 12)
    );
    let finding = &restored.findings[0];
    assert_eq!(
        (finding.entry, finding.severity, finding.population),
        (None, 0, 6)
    );
    assert_eq!(finding.statistic.scale(), 2);
    assert_eq!(
        finding.narrative,
        "LIBR: 100 (mantissa) deposited 1970-01-03; 4 later movement(s) through 1970-01-07; lowest balance after the deposit 20; 0 withdrawal(s) carried 0 tainted; traced 100; implicit book entity"
    );
    population.entries.reverse();
    assert_eq!(population.run(selection(257, 0, 1), 6).unwrap().1, output);

    // A transfer referencing the source also qualifies, even with a different
    // original document. The clean deposit remains in the balance population.
    population.facts(7).evidence.clear();
    let source_digest = population.entry(257).digest;
    population
        .entry(7)
        .supersession
        .push((257, source_digest, 3));
    assert_eq!(
        population.run(selection(257, 0, 1), 6).unwrap().0.findings,
        restored.findings
    );
    population.entry(7).supersession.clear();
    population.facts(300).evidence.clear();
    assert_eq!(
        amount(&population.run(selection(257, 0, 1), 6).unwrap().0),
        20
    );
}

#[test]
fn libr_intraday_laws_use_numeric_identity_and_strict_lowest_citations() {
    let mut population = Population::new();
    population.add(50, 0, 1, 20, true);
    population.add(256, 1, 2, 100, true);
    population.add(1, 1, 3, 90, false);
    population.add(9, 1, 4, 70, true);
    for (order, expected, expected_cites, later) in [
        (0, 30, vec![256, 1], 2),
        (2, 30, vec![256], 1),
        (3, 100, vec![256, 1], 2),
    ] {
        let report = population.run(selection(256, order, 0), 1).unwrap().0;
        assert_eq!(amount(&report), expected);
        assert_eq!(citations(&report), expected_cites);
        assert_eq!(
            (report.live_entries, report.live_legs, report.comparisons),
            (4, 3, 8)
        );
        assert!(
            report.findings[0]
                .narrative
                .contains(&format!("; {later} later movement(s)"))
        );
    }
    // At one recording sequence, numeric VID 1 precedes VID 256 although its
    // little-endian canonical bytes would sort after them.
    population.entries.retain(|entry| entry.identity != 9);
    population.entry(1).recorded_at = 2;
    let report = population.run(selection(256, 0, 0), 1).unwrap().0;
    assert_eq!(amount(&report), 30);
    assert_eq!(citations(&report), [256]);
    assert!(
        report.findings[0]
            .narrative
            .contains("; 0 later movement(s)")
    );

    // Returning to the same low does not replace the first strictly lower
    // withdrawal citation. Deposits at the cap are not replenishers either.
    let mut population = Population::new();
    population.add(10, 1, 1, 100, true);
    population.add(20, 2, 2, 60, false);
    population.add(30, 3, 3, 20, true);
    population.add(40, 4, 4, 20, false);
    assert_eq!(
        citations(&population.run(selection(10, 0, 0), 4).unwrap().0),
        [10, 20]
    );
}

#[test]
fn libr_scopes_units_entities_and_credit_normal_signed_amounts() {
    let mut population = Population::new();
    for (id, day, amount, inflow, entity) in [
        (1, 0, 100, true, 11),
        (2, 1, 100, true, 11),
        (3, 2, 150, false, 11),
        (4, 0, 1000, true, 22),
        (5, 2, 1000, false, 22),
        (6, 2, 1000, false, 11),
    ] {
        population.add(id, day, id as u64, amount, inflow);
        population.entity(id, entity);
    }
    population.unit(6, 2);
    population.add(7, 2, 7, 500, true);
    population.entry(7).leg_accounts[0].0 = 8;
    let debit = population.run(selection(2, 0, 0), 2).unwrap().0;
    assert_eq!(amount(&debit), 50);
    assert_eq!(
        (debit.live_entries, debit.live_legs, debit.comparisons),
        (7, 2, 3)
    );
    assert_eq!(debit.findings[0].population, 3);
    assert!(
        debit.findings[0]
            .narrative
            .ends_with("entity 0000000000000000000000000000000b")
    );
    population
        .registry
        .trace
        .as_mut()
        .unwrap()
        .account_normal_balances
        .insert(7, 1);
    for entry in &mut population.entries {
        for (_, debit) in &mut entry.leg_accounts {
            *debit = !*debit;
        }
        for (_, amount) in &mut entry.legs {
            *amount = -*amount;
        }
    }
    assert_eq!(
        population.run(selection(2, 0, 0), 2).unwrap().0.findings,
        debit.findings
    );
}

#[test]
fn libr_entity_normalization_uses_all_and_only_live_cutoff_legs() {
    let mut population = Population::new();
    population.add(1, 1, 1, 100, true);
    population.add(2, 2, 2, 20, false);
    population.add(3, 3, 3, 50, true);
    population.entry(3).leg_accounts[0].0 = 8;
    population.entity(3, 11);
    let implicit = population.run(selection(1, 0, 0), 2).unwrap().0;
    assert!(
        implicit.findings[0]
            .narrative
            .ends_with("implicit book entity")
    );
    let named = population.run(selection(1, 0, 0), 3).unwrap().0;
    assert_eq!(amount(&named), 80);
    assert!(
        named.findings[0]
            .narrative
            .ends_with("entity 0000000000000000000000000000000b")
    );
    population.add(4, 4, 4, 50, true);
    population.entry(4).leg_accounts[0].0 = 8;
    population.entity(4, 22);
    assert_eq!(
        population.run(selection(1, 0, 0), 3).unwrap().0.findings,
        named.findings
    );
    assert_eq!(
        population.run(selection(1, 0, 0), 4).unwrap_err().predicate,
        "procedure_entities"
    );
    population.entity(1, 11);
    population.entity(2, 11);
    assert_eq!(
        amount(&population.run(selection(1, 0, 0), 4).unwrap().0),
        80
    );
    population.facts(4).entities[1].push(22);
    assert_eq!(
        population.run(selection(1, 0, 0), 4).unwrap_err().predicate,
        "procedure_entities",
        "even unrelated live legs cannot name two legal entities"
    );
}

#[test]
fn libr_refuses_ambiguous_or_zero_net_sources_and_missing_authenticated_facts() {
    let mut population = Population::new();
    population.add(1, 1, 1, 100, true);
    population.entry(1).legs.push((2, 0));
    population.entry(1).leg_accounts.push((7, true));
    population.facts(1).entities.push(Vec::new());
    assert_eq!(
        population.run(selection(1, 0, 0), 1).unwrap_err().predicate,
        "procedure_source",
        "even a zero inflow leg selects its unit before netting"
    );
    population.entry(1).legs[2].0 = 1;
    population.facts(1).entities = vec![vec![11], vec![11], vec![22]];
    assert_eq!(
        population.run(selection(1, 0, 0), 1).unwrap_err().predicate,
        "procedure_source",
        "zero inflow in another entity remains ambiguous"
    );
    population.facts(1).entities = vec![Vec::new(); 3];
    population.entry(1).legs[2].1 = 100;
    population.entry(1).leg_accounts[2].1 = false;
    assert_eq!(
        population.run(selection(1, 0, 0), 1).unwrap_err().predicate,
        "procedure_source",
        "offsetting source legs have no positive net deposit"
    );
    population.entry(1).legs[2].1 = 0;
    assert_eq!(
        amount(&population.run(selection(1, 0, 0), 1).unwrap().0),
        100
    );
    population.facts(1).entities.pop();
    assert_eq!(
        population.run(selection(1, 0, 0), 1).unwrap_err().predicate,
        "procedure_source"
    );
    population.facts(1).entities.push(Vec::new());
    population
        .registry
        .trace
        .as_mut()
        .unwrap()
        .account_normal_balances
        .clear();
    assert_eq!(
        population.run(selection(1, 0, 0), 1).unwrap_err().predicate,
        "procedure_source"
    );
    population.registry.trace = None;
    assert_eq!(
        population.run(selection(1, 0, 0), 1).unwrap_err().predicate,
        "procedure_source"
    );
}

#[test]
fn libr_claim_cutoff_precedes_reversal_parity_and_retains_full_population() {
    let mut population = Population::new();
    population.add(1, 1, 1, 100, true);
    population.add(2, 2, 2, 60, false);
    population.reversal(3, 2, 10, 3);
    population.reversal(4, 1, 11, 4);
    population.reversal(5, 4, 12, 5);
    population.add(6, 2, 6, 900, false);
    population.entry(6).class = 2;
    population.add(7, 2, 7, 0, true);
    population.add(8, 2, 8, 0, true);
    population.entry(8).legs.clear();
    population.entry(8).leg_accounts.clear();
    population.entry(8).class = 8;
    for (claim, expected, live, legs, comparisons) in
        [(5, 40, 3, 1, 2), (10, 100, 2, 0, 0), (12, 100, 2, 0, 0)]
    {
        let report = population.run(selection(1, 0, 0), claim).unwrap().0;
        assert_eq!(amount(&report), expected);
        assert_eq!(
            (
                report.population,
                report.live_entries,
                report.live_legs,
                report.comparisons
            ),
            (8, live, legs, comparisons)
        );
        assert_eq!(report.findings[0].population, legs + 1);
    }
    assert_eq!(
        population.run(selection(1, 0, 0), 0).unwrap_err().predicate,
        "procedure_source"
    );
    assert_eq!(
        population
            .run(selection(1, 0, 0), 11)
            .unwrap_err()
            .predicate,
        "procedure_source"
    );
}

#[test]
fn libr_preserves_wide_amounts_and_replenishes_only_funds_held_after_overdrafts() {
    let mut wide = Population::new();
    wide.add(1, 1, 1, i128::MAX, true);
    wide.unit(1, 3);
    let report = wide.run(selection(1, 0, 0), 1).unwrap().0;
    assert_eq!(amount(&report), i128::MAX);
    assert_eq!(report.findings[0].statistic.scale(), 38);

    let mut minimum = Population::new();
    minimum.add(1, 0, 1, i128::MAX, false);
    minimum.add(2, 0, 2, 1, false);
    minimum.add(3, 1, 3, 1, true);
    minimum.add(4, 2, 4, i128::MAX, true);
    minimum.facts(3).evidence.insert([1; 32]);
    minimum.facts(4).evidence.insert([1; 32]);
    assert_eq!(
        amount(&minimum.run(selection(3, 0, 1), 2).unwrap().0),
        0,
        "the signed i128::MIN opening balance is valid; no magnitude conversion is needed"
    );

    for (opening_debt, withdrawal, returned, expected) in
        [(0, 150, 60, 10), (150, 0, 200, 0), (40, 30, 100, 60)]
    {
        let mut population = Population::new();
        population.add(1, 0, 1, opening_debt, false);
        population.add(2, 1, 2, 100, true);
        population.add(3, 2, 3, withdrawal, false);
        population.add(4, 3, 4, returned, true);
        population.facts(2).evidence.insert([1; 32]);
        population.facts(4).evidence.insert([1; 32]);
        assert_eq!(
            amount(&population.run(selection(2, 0, 1), 3).unwrap().0),
            expected
        );
    }
}

#[test]
fn libr_exact_arithmetic_refuses_unrepresentable_movements_and_balances() {
    let mut magnitude = Population::new();
    magnitude.add(1, 1, 1, i128::MIN, true);
    assert_eq!(
        magnitude.run(selection(1, 0, 0), 1).unwrap_err().predicate,
        "procedure_arithmetic"
    );
    magnitude.entry(1).legs = vec![(1, i128::MAX), (1, i128::MAX), (1, 1)];
    magnitude.entry(1).leg_accounts.push((7, true));
    magnitude.facts(1).entities.push(Vec::new());
    assert_eq!(
        magnitude.run(selection(1, 0, 0), 1).unwrap_err().predicate,
        "procedure_arithmetic",
        "one entry's net cannot overflow"
    );

    let mut balance = Population::new();
    balance.add(1, 0, 1, i128::MAX, true);
    balance.add(2, 1, 2, 1, true);
    assert_eq!(
        balance.run(selection(2, 0, 0), 1).unwrap_err().predicate,
        "procedure_arithmetic"
    );
    balance.entry(1).leg_accounts[0].1 = false;
    balance.entry(2).legs = vec![(1, 2), (1, 2)];
    balance.entry(2).leg_accounts[0].1 = false;
    balance.add(3, 2, 3, 1, true);
    assert_eq!(
        balance.run(selection(3, 0, 0), 2).unwrap_err().predicate,
        "procedure_arithmetic"
    );

    // Unselected amounts do not enter this exact one-account calculation.
    let mut unrelated = Population::new();
    unrelated.add(1, 1, 1, 100, true);
    unrelated.add(2, 2, 2, i128::MIN, true);
    unrelated.entry(2).leg_accounts[0].0 = 8;
    assert_eq!(
        amount(&unrelated.run(selection(1, 0, 0), 2).unwrap().0),
        100
    );
}

#[test]
fn libr_caps_supporting_citations_without_truncating_population_or_work() {
    let mut population = Population::new();
    population.add(1, 0, 1, 1, true);
    population.facts(1).evidence.insert([1; 32]);
    for index in 0..4097u128 {
        let withdrawal = index * 2 + 2;
        let returned = withdrawal + 1;
        population.add(withdrawal, 1, withdrawal as u64, 1, false);
        population.add(returned, 1, returned as u64, 1, true);
        population.facts(returned).evidence.insert([1; 32]);
    }
    let report = population.run(selection(1, 0, 1), 1).unwrap().0;
    assert_eq!(amount(&report), 1);
    assert_eq!(
        (
            report.population,
            report.live_entries,
            report.live_legs,
            report.comparisons
        ),
        (8195, 8195, 8194, 106535)
    );
    assert_eq!(report.findings[0].population, 8195);
    let cited = citations(&report);
    assert_eq!(
        cited.len(),
        MAX_CITES - 1,
        "the account occupies the other citation slot"
    );
    assert_eq!(&cited[..4], [1, 2, 3, 5]);
    assert_eq!(cited.last(), Some(&8187));
}

fn encoded(output: &[u8]) -> Vec<u8> {
    let mut certificate = Writer::default();
    certificate
        .bytes(super::super::FORMAT)
        .bytes(&[])
        .bytes(&[])
        .fixed(&[0; 32])
        .u128(1)
        .fixed(&[0; 32])
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
fn libr_profile_requires_exact_version_claim_laws_and_canonical_handles() {
    let parameters = [("intraday_order", 0), ("replenishment", 0)];
    let inputs = [
        ("account", "00000000000000000000000000000007"),
        ("source", "00000000000000000000000000000101"),
    ];
    for order in [0, 2, 3] {
        for replenishment in [0, 1] {
            let bindings = bindings(
                &[("intraday_order", order), ("replenishment", replenishment)],
                &inputs,
            );
            assert_eq!(
                decode(&mut Reader::new(&bindings)).unwrap(),
                selection(257, order as u32, replenishment as u32)
            );
        }
    }
    for invalid in [
        vec![("intraday_order", 1), ("replenishment", 0)],
        vec![("intraday_order", -1), ("replenishment", 0)],
        vec![("intraday_order", 4), ("replenishment", 0)],
        vec![("intraday_order", 0), ("replenishment", 2)],
        vec![
            ("intraday_order", 0),
            ("replenishment", i128::from(u32::MAX) + 1),
        ],
        vec![parameters[0]],
        vec![parameters[1], parameters[0]],
        vec![parameters[0], parameters[0]],
    ] {
        assert!(decode(&mut Reader::new(&bindings(&invalid, &inputs))).is_err());
    }
    for invalid in [
        Vec::new(),
        vec![inputs[0]],
        vec![inputs[1], inputs[0]],
        vec![inputs[0], inputs[0]],
        vec![inputs[0], inputs[1], ("extra", inputs[1].1)],
        vec![("account", "7"), inputs[1]],
        vec![inputs[0], ("source", "0000000000000000000000000000000A")],
        vec![inputs[0], ("source", "0000000000000000000000000000000g")],
    ] {
        assert!(decode(&mut Reader::new(&bindings(&parameters, &invalid))).is_err());
    }
    for (version, claim) in [(1, Some(6)), (3, Some(6)), (2, None)] {
        let mut question = Writer::default();
        question
            .bytes(super::super::OUTPUT_FORMAT)
            .bytes(b"trace.libr")
            .u16(version)
            .u8(0)
            .bytes(b"FA-EVID-L15")
            .fixed(&[1; 16])
            .u64(100_000);
        super::super::cutoff(&mut question, claim);
        question.fixed(&bindings(&parameters, &inputs));
        assert_eq!(
            decode_certificate(&encoded(&question.buf))
                .err()
                .expect("unsupported LIBR question")
                .predicate,
            "procedure_profile"
        );
    }
}

#[test]
fn libr_rejects_rehashed_output_changed_handles_and_uncited_balance_omissions() {
    let population = replenishing_population();
    let profile = selection(257, 0, 1);
    let (expected, output) = population.run(profile, 6).unwrap();
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

    let mut amount_label = Writer::default();
    amount_label.bytes(b"traced_mantissa");
    let value_at = output
        .windows(amount_label.buf.len())
        .position(|window| window == amount_label.buf)
        .unwrap()
        + amount_label.buf.len();
    let mut forged = output.clone();
    forged[value_at..value_at + 16].copy_from_slice(&101i128.to_le_bytes());
    let forged = encoded(&forged);
    let forged = decode_certificate(&forged).unwrap();
    assert_eq!(
        replay_certificate(
            &forged,
            [1; 16],
            100_000,
            population.entries.clone(),
            &population.registry
        )
        .unwrap_err()
        .predicate,
        "procedure_recomputation"
    );

    let original_handle = format!("{:032x}", 257);
    let alternate_handle = format!("{:032x}", 256);
    let at = output
        .windows(32)
        .position(|window| window == original_handle.as_bytes())
        .unwrap();
    let mut changed = output.clone();
    changed[at..at + 32].copy_from_slice(alternate_handle.as_bytes());
    let changed = encoded(&changed);
    let changed = decode_certificate(&changed).unwrap();
    assert_eq!(changed.parameters, selection(256, 0, 1));
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

    // The clean 80-unit deposit is deliberately uncited, but removing it
    // changes the committed population, movements, work and input transcript.
    assert!(!citations(&expected).contains(&256));
    let mut missing = population.entries.clone();
    missing.retain(|entry| entry.identity != 256);
    assert_eq!(
        replay_certificate(&request, [1; 16], 100_000, missing, &population.registry)
            .unwrap_err()
            .predicate,
        "procedure_recomputation"
    );
    let mut changed = population.entries.clone();
    changed
        .iter_mut()
        .find(|entry| entry.identity == 256)
        .unwrap()
        .legs = vec![(1, 0), (1, 0)];
    assert_eq!(
        replay_certificate(&request, [1; 16], 100_000, changed, &population.registry)
            .unwrap_err()
            .predicate,
        "procedure_recomputation"
    );

    // An otherwise valid alternative question never inherits the original
    // source's parameter commitment merely because its final amount agrees.
    let other = Certificate {
        parameters: selection(7, 0, 1),
        ..request
    };
    assert_eq!(
        replay_certificate(
            &other,
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
