use super::*;
use std::collections::BTreeSet;

use crate::blake3::hash_parts;
use crate::codec::Writer;
use crate::report::procedure::{
    DIGEST_DOMAIN, EXTENDED_FORMAT, FORMAT, TraceContext, TraceEntryFacts, VerifiedProcedure,
    VerifiedProcedureParameters, VerifiedProcedureStatistic, decode, framed_hash,
    recompute_version, replay,
};

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
                account_types: BTreeMap::from([(1, 1), (2, 1), (3, 1), (4, 1)]),
                account_codes: BTreeMap::new(),
                account_roles: BTreeMap::new(),
                leg_parties: BTreeMap::new(),
                entry_facts: BTreeMap::new(),
                trace: Some(TraceContext {
                    paid: Some(Context {
                        codes: BTreeMap::from([
                            (10, "A".into()),
                            (20, "B".into()),
                            (30, "C".into()),
                            (40, "D".into()),
                        ]),
                        dimensions: BTreeMap::from([(110, 10), (120, 20), (130, 30), (140, 40)]),
                        legs: BTreeMap::new(),
                    }),
                    ..TraceContext::default()
                }),
                open_items: None,
                policy_oid: [7; 32],
            },
        }
    }

    fn add(&mut self, id: u128, day: i32, legs: &[(u128, bool, i128, &[u128])]) {
        self.entries.push(Entry {
            identity: id,
            digest: hash_parts(b"paid-entry-test", &[&id.to_le_bytes()]),
            recorded_at: id as u64,
            effective: Some(day),
            class: 1,
            legs: legs.iter().map(|leg| (1, leg.2)).collect(),
            leg_accounts: legs.iter().map(|leg| (leg.0, leg.1)).collect(),
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: None,
            transition: None,
        });
        let context = self.registry.trace.as_mut().unwrap();
        context.entries.insert(
            id,
            TraceEntryFacts {
                entities: vec![Vec::new(); legs.len()],
                evidence: BTreeSet::new(),
            },
        );
        context
            .paid
            .as_mut()
            .unwrap()
            .legs
            .insert(id, legs.iter().map(|leg| leg.3.to_vec()).collect());
    }

    fn transfer(&mut self, id: u128, day: i32, from: &[u128], to: &[u128], amount: i128) {
        self.add(id, day, &[(1, false, amount, from), (1, true, amount, to)]);
    }

    fn reverse(&mut self, id: u128, target: u128) {
        let mut entry = self
            .entries
            .iter()
            .find(|entry| entry.identity == target)
            .unwrap()
            .clone();
        let digest = entry.digest;
        entry.identity = id;
        entry.digest = hash_parts(b"paid-entry-test", &[&id.to_le_bytes()]);
        entry.recorded_at = id as u64;
        entry.effective = Some(id as i32);
        entry.class = 4;
        entry.supersession = vec![(target, digest, 1)];
        for (_, debit) in &mut entry.leg_accounts {
            *debit = !*debit;
        }
        let context = self.registry.trace.as_mut().unwrap();
        context.entries.insert(id, context.entries[&target].clone());
        let paid = context.paid.as_mut().unwrap();
        paid.legs.insert(id, paid.legs[&target].clone());
        self.entries.push(entry);
    }

    fn run(&self, profile: VerifiedProcedureParameters) -> (VerifiedProcedure, Vec<u8>) {
        recompute_version(
            [1; 16],
            1000,
            version(profile),
            None,
            profile,
            self.entries.clone(),
            &self.registry,
        )
        .unwrap()
    }
}

fn cycle() -> VerifiedProcedureParameters {
    VerifiedProcedureParameters::GraphPartyCircularFlows {
        max_hops: 6,
        min_retention_bps: 7000,
        window_days: 14,
    }
}

fn chain() -> VerifiedProcedureParameters {
    VerifiedProcedureParameters::GraphPartyLayering {
        min_hops: 3,
        min_passthrough_bps: 8500,
        window_days: 10,
    }
}

fn version(profile: VerifiedProcedureParameters) -> u16 {
    if matches!(
        profile,
        VerifiedProcedureParameters::GraphPartyLayering { .. }
            | VerifiedProcedureParameters::GraphLayering { .. }
    ) {
        3
    } else {
        2
    }
}

fn wrap(output: &[u8], extended: bool) -> Vec<u8> {
    let mut writer = Writer::default();
    writer
        .bytes(if extended { EXTENDED_FORMAT } else { FORMAT })
        .bytes(b"native source")
        .bytes(b"native approvals");
    if extended {
        writer.count(6);
        for _ in 0..6 {
            writer.bytes(b"native witness is not authority");
        }
    }
    writer.fixed(&[2; 32]).u128(7).fixed(&[3; 32]).bytes(output);
    writer.fixed(&framed_hash(DIGEST_DOMAIN, &writer.buf));
    writer.buf
}

fn party_body(code: &str) -> Vec<u8> {
    let mut writer = Writer::default();
    writer
        .bytes(code.as_bytes())
        .u8(1)
        .fixed(&[0; 32])
        .u8(0)
        .fixed(&[0; 24])
        .bytes(&[])
        .count(0)
        .count(0);
    writer.buf
}

#[test]
fn historical_party_bindings_preserve_raw_cardinality_and_literal_unknown_nodes() {
    let book = [1; 16];
    let mut context = Context::default();
    let body = party_body("COUNTERPARTY");
    context.declare(&book, &body).unwrap();
    let party = metadata::framed_identity(b"fa:vid:party:v1", &[&book, b"COUNTERPARTY"]);
    let value = dimension::value_vid(&book, "party", "COUNTERPARTY");
    assert_eq!(context.node(&[value]), party);
    assert_eq!(context.node(&[party]), party);
    assert_eq!(context.label(party), "COUNTERPARTY");
    assert_eq!(context.node(&[]), 0);
    assert_eq!(
        context.node(&[value, party]),
        0,
        "raw aliases are still two mentions"
    );
    assert_eq!(
        context.node(&[value, value]),
        0,
        "raw cardinality is never deduplicated"
    );
    assert_eq!(context.node(&[77]), 77);
    assert_eq!(context.label(77), format!("{:032x}", 77));
    assert_eq!(context.label(0), "book");
    assert!(context.declare(&book, &body).is_err());
    let mut malformed = party_body("OTHER");
    malformed.push(0);
    assert!(Context::default().declare(&book, &malformed).is_err());
    assert!(Context::default().declare(&book, &party_body("")).is_err());
}

#[test]
fn paid_projects_original_legs_before_hamilton_ties_and_drops_self_flows_after_allocation() {
    let mut p = Population::new();
    p.add(
        1,
        0,
        &[
            (1, false, 1, &[120]),
            (2, false, 1, &[110]),
            (3, true, 1, &[130]),
            (4, true, 1, &[140]),
        ],
    );
    let live: Vec<_> = p.entries.iter().collect();
    let flows = flow(&live, &p.registry).unwrap();
    assert_eq!(
        flows
            .iter()
            .map(|leg| (leg.from, leg.to, leg.amount))
            .collect::<Vec<_>>(),
        [(10, 30, 1), (20, 40, 1)]
    );
    let account = structuring::flow(&live, &p.registry).unwrap();
    assert_eq!(
        account
            .iter()
            .map(|leg| (leg.from, leg.to))
            .collect::<Vec<_>>(),
        [(1, 3), (2, 4)],
        "relabeling these gives the wrong parties"
    );
    p.add(
        2,
        1,
        &[
            (1, false, 1, &[110]),
            (1, false, 1, &[120]),
            (1, true, 1, &[110]),
            (1, true, 1, &[130]),
        ],
    );
    let flows = flow(&p.entries.iter().collect::<Vec<_>>(), &p.registry).unwrap();
    assert_eq!(
        flows
            .iter()
            .filter(|leg| leg.entry == 2)
            .map(|leg| (leg.from, leg.to, leg.amount))
            .collect::<Vec<_>>(),
        [(20, 30, 1)]
    );
}

#[test]
fn clearing_account_cycles_are_party_findings_with_exact_population_names_and_citations() {
    let mut p = Population::new();
    p.transfer(1, 0, &[110], &[120], 100);
    p.transfer(2, 1, &[120], &[130], 95);
    p.transfer(3, 2, &[130], &[110], 80);
    p.transfer(4, 3, &[], &[], 100);
    p.transfer(5, 3, &[110], &[110], 100);
    assert!(
        p.run(VerifiedProcedureParameters::GraphCircularFlows {
            max_hops: 6,
            min_retention_bps: 7000,
            window_days: 14
        })
        .0
        .findings
        .is_empty()
    );
    let (run, output) = p.run(cycle());
    assert_eq!(
        (run.live_entries, run.live_legs, run.comparisons),
        (0, 3, 5)
    );
    assert_eq!(run.findings.len(), 1);
    let finding = &run.findings[0];
    assert_eq!(finding.population, 3);
    assert!(
        matches!(&finding.statistic, VerifiedProcedureStatistic::PartyCircularFlow { hops, account_citations, mantissa:80, .. } if hops == &[(1,10),(2,20),(3,30)] && account_citations.is_empty())
    );
    assert!(finding.narrative.starts_with("3-hop directed cycle in SCC retaining 80 of 100 through parties A -> B -> C -> A (8000 bps, cgse_witness="));
    assert_eq!(
        finding.citation_order(),
        [1u128, 2, 3].map(|entry| {
            let mut cite = vec![1];
            cite.extend(entry.to_le_bytes());
            cite
        })
    );
    let certificate = wrap(&output, true);
    let decoded = decode(&certificate).unwrap();
    assert_eq!(
        replay(&decoded, [1; 16], 1000, p.entries.clone(), &p.registry)
            .unwrap()
            .1,
        output
    );
    p.entries.reverse();
    assert_eq!(
        p.run(cycle()).1,
        output,
        "source storage order cannot change the chronological result"
    );
}

#[test]
fn party_layering_keeps_v3_chronology_despite_shortcuts() {
    let mut p = Population::new();
    p.transfer(1, 0, &[110], &[120], 100);
    p.transfer(2, 0, &[130], &[140], 90);
    p.transfer(3, 0, &[120], &[130], 90);
    assert!(p.run(chain()).0.findings.is_empty());
    p.transfer(4, 0, &[130], &[140], 90);
    p.transfer(5, 0, &[110], &[140], 100);
    let (run, _) = p.run(chain());
    assert_eq!(run.findings.len(), 1);
    assert!(
        matches!(&run.findings[0].statistic, VerifiedProcedureStatistic::PartyLayeredFlow { hops, destination:40, mantissa:90, .. } if hops == &[(1,10),(3,20),(4,30)])
    );
    assert!(
        run.findings[0]
            .narrative
            .contains("through parties A -> B -> C -> D (cgse_witness=")
    );
}

#[test]
fn ambiguous_legs_are_book_nodes_and_literal_account_nodes_keep_native_citations() {
    let mut p = Population::new();
    p.transfer(1, 0, &[110], &[110, 10], 100);
    p.transfer(2, 1, &[], &[120], 95);
    p.transfer(3, 2, &[120], &[110], 80);
    let run = p.run(cycle()).0;
    assert_eq!(run.findings.len(), 1);
    assert!(
        run.findings[0]
            .narrative
            .contains("through parties A -> book -> B -> A")
    );
    let mut p = Population::new();
    p.transfer(1, 0, &[110], &[2], 100);
    p.transfer(2, 1, &[2], &[120], 95);
    p.transfer(3, 2, &[120], &[3], 90);
    let run = p.run(chain()).0;
    assert!(
        matches!(&run.findings[0].statistic, VerifiedProcedureStatistic::PartyLayeredFlow { account_citations, destination:3, .. } if account_citations == &BTreeSet::from([2,3]))
    );
    let expected = [(1u8, 1u128), (1, 2), (3, 2), (1, 3), (3, 3)].map(|(tag, id)| {
        let mut cite = vec![tag];
        cite.extend(id.to_le_bytes());
        cite
    });
    assert_eq!(run.findings[0].citation_order(), expected);
    assert!(
        run.findings[0]
            .narrative
            .contains(&format!("A -> {:032x} -> B -> {:032x}", 2, 3))
    );
}

#[test]
fn paid_keeps_legal_entities_units_and_historical_reversal_liveness() {
    for different_unit in [false, true] {
        let mut p = Population::new();
        p.transfer(1, 0, &[110], &[120], 100);
        p.transfer(2, 1, &[120], &[130], 95);
        p.transfer(3, 2, &[130], &[110], 80);
        if different_unit {
            for leg in &mut p.entries[1].legs {
                leg.0 = 2;
            }
        } else {
            let facts = &mut p.registry.trace.as_mut().unwrap().entries;
            for (id, entity) in [(1, 7), (2, 8), (3, 7)] {
                facts.get_mut(&id).unwrap().entities = vec![vec![entity]; 2];
            }
        }
        assert!(p.run(cycle()).0.findings.is_empty());
    }
    let mut p = Population::new();
    p.transfer(1, 0, &[110], &[120], 100);
    p.transfer(2, 1, &[120], &[130], 95);
    p.transfer(3, 2, &[130], &[110], 80);
    let original = p.run(cycle()).0.findings;
    p.reverse(4, 1);
    assert!(p.run(cycle()).0.findings.is_empty());
    p.reverse(5, 4);
    assert_eq!(p.run(cycle()).0.findings, original);
}

#[test]
fn paid_refuses_incomplete_dimensions_accounts_and_entity_margins() {
    for variant in 0..5 {
        let mut p = Population::new();
        p.transfer(1, 0, &[110], &[120], 100);
        match variant {
            0 => p.registry.trace.as_mut().unwrap().paid = None,
            1 => {
                p.registry
                    .trace
                    .as_mut()
                    .unwrap()
                    .paid
                    .as_mut()
                    .unwrap()
                    .legs
                    .clear();
            }
            2 => {
                p.registry
                    .trace
                    .as_mut()
                    .unwrap()
                    .paid
                    .as_mut()
                    .unwrap()
                    .legs
                    .get_mut(&1)
                    .unwrap()
                    .pop();
            }
            3 => {
                p.registry.account_types.remove(&1);
            }
            _ => {
                p.registry
                    .trace
                    .as_mut()
                    .unwrap()
                    .entries
                    .get_mut(&1)
                    .unwrap()
                    .entities = vec![vec![7], vec![8]];
            }
        }
        assert_eq!(
            flow(&p.entries.iter().collect::<Vec<_>>(), &p.registry)
                .unwrap_err()
                .predicate,
            "procedure_profile",
            "variant {variant}"
        );
    }
}

#[test]
fn paid_certificates_refuse_wrong_versions_cutoffs_and_changed_historical_facts() {
    let mut p = Population::new();
    p.transfer(1, 0, &[110], &[120], 100);
    p.transfer(2, 1, &[120], &[130], 95);
    p.transfer(3, 2, &[130], &[110], 80);
    for profile in [cycle(), chain()] {
        let (_, output) = p.run(profile);
        assert!(decode(&wrap(&output, false)).is_err());
        for wrong in (0..=6).filter(|wrong| *wrong != version(profile)) {
            let (_, output) = recompute_version(
                [1; 16],
                1000,
                wrong,
                None,
                profile,
                p.entries.clone(),
                &p.registry,
            )
            .unwrap();
            assert_eq!(
                decode(&wrap(&output, true)).err().unwrap().predicate,
                "procedure_profile"
            );
        }
        let (_, output) = recompute_version(
            [1; 16],
            1000,
            version(profile),
            Some(2),
            profile,
            p.entries.clone(),
            &p.registry,
        )
        .unwrap();
        assert!(decode(&wrap(&output, true)).is_err());
    }
    let (_, output) = p.run(cycle());
    let certificate = wrap(&output, true);
    let decoded = decode(&certificate).unwrap();
    p.registry
        .trace
        .as_mut()
        .unwrap()
        .paid
        .as_mut()
        .unwrap()
        .codes
        .insert(10, "RENAMED".into());
    assert_eq!(
        replay(&decoded, [1; 16], 1000, p.entries.clone(), &p.registry)
            .unwrap_err()
            .predicate,
        "procedure_recomputation"
    );
    p.registry
        .trace
        .as_mut()
        .unwrap()
        .paid
        .as_mut()
        .unwrap()
        .codes
        .insert(10, "A".into());
    p.registry
        .trace
        .as_mut()
        .unwrap()
        .paid
        .as_mut()
        .unwrap()
        .legs
        .get_mut(&2)
        .unwrap()[0] = vec![110];
    assert_eq!(
        replay(&decoded, [1; 16], 1000, p.entries.clone(), &p.registry)
            .unwrap_err()
            .predicate,
        "procedure_recomputation"
    );
}
