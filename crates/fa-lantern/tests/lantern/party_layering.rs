//! fa-b6xs: the PAID projection and `graph.party_layering`. A chain of
//! transfers between counterparties through one clearing account is
//! invisible to the account graph, where every hop is a 1010 -> 1010
//! self-flow, and is found through the parties. An entry naming no party adds
//! no PAID edge, and the projection equals a literal fold of the entries.

use super::*;
use fa_lantern::graph::{Layering, PartyLayering};
use fa_lantern::projection::{BOOK_NODE, paid, party_flow_legs};
use fa_model::{EntryClass, PARTY_DIMENSION};

/// Registers a party in the snapshot: its vid and its dimension value.
fn party(h: &Harness, snapshot: &mut Snapshot, code: &str) -> (VId, VId) {
    let party = fa_model::party_vid(h.book.book_id, code);
    let value = fa_model::party_value_vid(h.book.book_id, code);
    snapshot.rea.parties.insert(
        party,
        fa_journal::rea::PartyRow {
            vid: party,
            dimension_value_vid: value,
            code: code.into(),
            kind: fa_model::PartyKind::Counterparty,
            name: Erasable::seal(
                &code.to_string(),
                None,
                &h.book.seal_key,
                [0x61; 32],
                [0x62; 24],
            ),
            identifiers: Vec::new(),
            external_ids: Vec::new(),
            created_at: CommitSeq(1),
        },
    );
    (party, value)
}

/// Dr `debit` tagged `to` / Cr `credit` tagged `from` (party dimension
/// values; `None` names no party).
#[allow(clippy::too_many_arguments)]
fn transfer(
    h: &mut Harness,
    vid: u128,
    date: DateDay,
    debit: &str,
    to: Option<VId>,
    credit: &str,
    from: Option<VId>,
    cents: i128,
) -> fa_lantern::SnapshotEntry {
    let period = h.period_code(date);
    let usd = h.usd;
    let mut e = make_snapshot_entry(
        h,
        VId(vid),
        CommitSeq(u64::try_from(vid).unwrap()),
        date,
        &period,
        EntryClass::ORIGINAL,
        vec![
            (debit, Side::Debit, usd, cents),
            (credit, Side::Credit, usd, cents),
        ],
        Vec::new(),
        None,
        Some(date),
        None,
        Vec::new(),
    );
    for leg in &mut e.entry.proposal.legs {
        let tag = match leg.side {
            Side::Debit => to,
            Side::Credit => from,
        };
        if let Some(value) = tag {
            leg.dimension_set.push((PARTY_DIMENSION, value));
            leg.dimension_set.sort();
        }
    }
    e
}

#[test]
fn a_counterparty_chain_through_one_clearing_account_is_found_through_parties() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    snapshot.coordinate.effective_through = None;
    let (a, a_val) = party(&h, &mut snapshot, "SHELL-A");
    let (b, b_val) = party(&h, &mut snapshot, "SHELL-B");
    let (c, c_val) = party(&h, &mut snapshot, "SHELL-C");
    let (d, d_val) = party(&h, &mut snapshot, "SHELL-D");
    // A -> B -> C -> D through clearing account 1010, each hop forwarding at
    // least 85% of the one before; then a receipt from A (A -> book) and a
    // sale that names no party.
    let ab = transfer(
        &mut h,
        901,
        day(2026, 1, 5),
        "1010",
        Some(b_val),
        "1010",
        Some(a_val),
        100_000,
    );
    let bc = transfer(
        &mut h,
        902,
        day(2026, 1, 6),
        "1010",
        Some(c_val),
        "1010",
        Some(b_val),
        95_000,
    );
    let cd = transfer(
        &mut h,
        903,
        day(2026, 1, 7),
        "1010",
        Some(d_val),
        "1010",
        Some(c_val),
        90_000,
    );
    let receipt = transfer(
        &mut h,
        904,
        day(2026, 1, 8),
        "1000",
        None,
        "1200",
        Some(a_val),
        30_000,
    );
    let sale = transfer(
        &mut h,
        905,
        day(2026, 1, 9),
        "1000",
        None,
        "4000",
        None,
        12_000,
    );
    let (ab_vid, bc_vid, cd_vid, receipt_vid, sale_vid) =
        (ab.vid, bc.vid, cd.vid, receipt.vid, sale.vid);
    snapshot.entries = vec![ab, bc, cd, receipt, sale];

    // Accounts: each hop is a self-flow, so the account graph has no chain.
    let accounts = run_over(&snapshot, &h.book, &Layering::new().unwrap()).unwrap();
    assert!(accounts.findings.is_empty(), "{:?}", accounts.findings);

    // PAID legs equal a literal fold written from the rule: a two-leg
    // entry's edge runs from its credit leg's party to its debit leg's, the
    // book standing for a leg that names none, and equal ends add nothing.
    let parties = BTreeMap::from([(a_val, a), (b_val, b), (c_val, c), (d_val, d)]);
    let mut literal = Vec::new();
    for e in &snapshot.entries {
        let node = |side: Side| {
            let leg = e
                .entry
                .proposal
                .legs
                .iter()
                .find(|l| l.side == side)
                .unwrap();
            leg.dimension_set
                .iter()
                .find(|(dimension, _)| *dimension == PARTY_DIMENSION)
                .map_or(BOOK_NODE, |(_, value)| parties[value])
        };
        let (from, to) = (node(Side::Credit), node(Side::Debit));
        if from != to {
            literal.push((e.vid, from, to, e.entry.proposal.legs[0].amount.mantissa));
        }
    }
    let legs = party_flow_legs(&snapshot).unwrap();
    let folded: Vec<(VId, VId, VId, i128)> = legs
        .iter()
        .map(|s| (s.leg.entry, s.leg.from, s.leg.to, s.leg.mantissa))
        .collect();
    assert_eq!(folded, literal);
    assert_eq!(
        folded,
        vec![
            (ab_vid, a, b, 100_000),
            (bc_vid, b, c, 95_000),
            (cd_vid, c, d, 90_000),
            (receipt_vid, a, BOOK_NODE, 30_000),
        ]
    );
    assert!(
        legs.iter().all(|s| s.leg.entry != sale_vid),
        "an entry naming no party adds no PAID edge"
    );

    // The PAID fold is deterministic, and a different journal changes it.
    let projection = paid(&snapshot).unwrap();
    assert_eq!(projection, paid(&snapshot).unwrap());
    assert_eq!(projection.edges.len(), 4);
    assert_eq!(projection.entries, 5);

    // Parties: the chain is found, naming the parties and citing its hops.
    let found = run_over(&snapshot, &h.book, &PartyLayering::new().unwrap()).unwrap();
    assert_eq!(found.findings.len(), 1, "{:?}", found.findings);
    let finding = &found.findings[0];
    assert_eq!(finding.procedure, "graph.party_layering");
    assert!(
        finding
            .narrative
            .contains("3-hop pass-through chain forwarding 90000 of 100000"),
        "{}",
        finding.narrative
    );
    assert!(
        finding
            .narrative
            .contains("through parties SHELL-A -> SHELL-B -> SHELL-C -> SHELL-D"),
        "{}",
        finding.narrative
    );
    assert!(finding.narrative.contains("cgse_witness="));
    let cited: Vec<VId> = finding
        .cites
        .iter()
        .filter_map(|cite| match cite {
            Cite::Entry(vid) => Some(*vid),
            _ => None,
        })
        .collect();
    assert_eq!(cited, vec![ab_vid, bc_vid, cd_vid]);
    witness::determinism(&snapshot, &h.book, &PartyLayering::new().unwrap()).unwrap();

    // Planted: a last hop forwarding under 85% leaves a two-hop chain, below
    // min_hops, and nothing is flagged; the PAID digest moves with it.
    let mut weaker = snapshot.clone();
    for leg in &mut weaker.entries[2].entry.proposal.legs {
        leg.amount = Amount::new(h.usd, 70_000);
    }
    assert_ne!(paid(&weaker).unwrap().digest, projection.digest);
    let none = run_over(&weaker, &h.book, &PartyLayering::new().unwrap()).unwrap();
    assert!(none.findings.is_empty(), "{:?}", none.findings);
}

/// fa-b6xs slice 2: money that returns to a counterparty through others,
/// A -> B -> C -> A, every hop through clearing account 1010, is a cycle of
/// self-flows the account graph drops and a 3-hop cycle between parties.
/// Planted: a closing hop that keeps under 70% of the first is not flagged.
#[test]
fn a_counterparty_cycle_through_one_clearing_account_is_found_through_parties() {
    use fa_lantern::graph::{CircularFlows, PartyCircularFlows};
    let mut h = harness();
    let mut snapshot = h.snapshot();
    snapshot.coordinate.effective_through = None;
    let (_, a_val) = party(&h, &mut snapshot, "SHELL-A");
    let (_, b_val) = party(&h, &mut snapshot, "SHELL-B");
    let (_, c_val) = party(&h, &mut snapshot, "SHELL-C");
    let ab = transfer(
        &mut h,
        911,
        day(2026, 1, 5),
        "1010",
        Some(b_val),
        "1010",
        Some(a_val),
        100_000,
    );
    let bc = transfer(
        &mut h,
        912,
        day(2026, 1, 6),
        "1010",
        Some(c_val),
        "1010",
        Some(b_val),
        95_000,
    );
    let ca = transfer(
        &mut h,
        913,
        day(2026, 1, 7),
        "1010",
        Some(a_val),
        "1010",
        Some(c_val),
        90_000,
    );
    let (ab_vid, bc_vid, ca_vid) = (ab.vid, bc.vid, ca.vid);
    snapshot.entries = vec![ab, bc, ca];

    let accounts = run_over(&snapshot, &h.book, &CircularFlows::new().unwrap()).unwrap();
    assert!(accounts.findings.is_empty(), "{:?}", accounts.findings);

    let found = run_over(&snapshot, &h.book, &PartyCircularFlows::new().unwrap()).unwrap();
    assert_eq!(found.findings.len(), 1, "{:?}", found.findings);
    let finding = &found.findings[0];
    assert_eq!(finding.procedure, "graph.party_circular_flows");
    assert!(
        finding.narrative.contains(
            "3-hop directed cycle in SCC retaining 90000 of 100000 through parties SHELL-A -> SHELL-B -> SHELL-C -> SHELL-A (9000 bps"
        ),
        "{}",
        finding.narrative
    );
    let cited: Vec<VId> = finding
        .cites
        .iter()
        .filter_map(|cite| match cite {
            Cite::Entry(vid) => Some(*vid),
            _ => None,
        })
        .collect();
    assert_eq!(cited, vec![ab_vid, bc_vid, ca_vid]);
    witness::determinism(&snapshot, &h.book, &PartyCircularFlows::new().unwrap()).unwrap();

    let mut leaky = snapshot.clone();
    for leg in &mut leaky.entries[2].entry.proposal.legs {
        leg.amount = Amount::new(h.usd, 60_000);
    }
    let none = run_over(&leaky, &h.book, &PartyCircularFlows::new().unwrap()).unwrap();
    assert!(none.findings.is_empty(), "{:?}", none.findings);
}

/// fa-b6xs acceptance 1 (the differential half): the PAID projection equals
/// fa-reference's literal fold (`paid_fold`, its own limb arithmetic) over
/// seeded generated histories: one or two units, an implicit, a single named
/// or two named legal entities, several legs a side, and legs naming a
/// registered party, an unregistered value, none, the same value twice or two
/// values. fa-gen's corpora name no party, so they would compare nothing;
/// these histories exercise every node rule. Planted negative: a reference
/// that gives a two-value leg its first party instead of the book disagrees,
/// so the comparison is not vacuous.
#[test]
fn party_paid_projection_matches_reference() {
    use fa_model::LEGAL_ENTITY_DIMENSION;
    use fa_reference::lantern::{PAID_BOOK, PaidLeg, paid_fold};

    /// xorshift64*, seeded: the test owns its randomness.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }
    /// `total` split into `k` positive parts.
    fn split(rng: &mut Rng, total: i128, k: usize) -> Vec<i128> {
        let mut parts = Vec::with_capacity(k);
        let mut left = total;
        for i in 0..k {
            let rest = i128::try_from(k - i - 1).unwrap();
            let part = if rest == 0 {
                left
            } else {
                let room = u64::try_from((left - rest).min(i128::from(u32::MAX))).unwrap();
                1 + i128::from(rng.below(room))
            };
            parts.push(part);
            left -= part;
        }
        parts
    }

    assert_eq!(BOOK_NODE.0, PAID_BOOK);
    let accounts = [
        "1000", "1010", "1020", "1200", "2000", "4000", "6000", "7000",
    ];
    let (mut edges, mut via_unregistered, mut cross_unit, mut entity_scoped) = (0, 0, 0, 0);
    let mut disagreements = 0;
    for seed in 1..=24u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let mut h = harness();
        let mut snapshot = h.snapshot();
        snapshot.coordinate.effective_through = None;
        let jpy = h.book.units.lookup("JPY").unwrap();
        let usd = h.usd;
        let mut values = Vec::new();
        let mut parties = BTreeMap::new();
        for code in ["P-A", "P-B", "P-C", "P-D"] {
            let (party_vid, value) = party(&h, &mut snapshot, code);
            parties.insert(value.0, party_vid.0);
            values.push(value);
        }
        let unregistered = VId(0xE0E0);
        let entities = [
            fa_model::entity_value_vid(h.book.book_id, "E1"),
            fa_model::entity_value_vid(h.book.book_id, "E2"),
        ];
        // 0: no entity named; 1: one entity, named on some legs; 2: two, on every leg.
        let entity_mode = seed % 3;
        let mut reference = Vec::new();
        let mut first_party_reference = Vec::new();
        for n in 0..20u64 {
            let date = day(2026, 1, 5 + u8::try_from(n).unwrap());
            let period = h.period_code(date);
            let mut legs: Vec<(&str, Side, UnitId, i128)> = Vec::new();
            let mut tags: Vec<(Vec<VId>, Option<VId>)> = Vec::new();
            let units = if rng.below(3) == 0 {
                vec![usd, jpy]
            } else {
                vec![usd]
            };
            for unit in units {
                let entity = match entity_mode {
                    2 => Some(entities[usize::try_from(rng.below(2)).unwrap()]),
                    _ => None,
                };
                // At least 3, so every one of up to 3 legs a side is positive;
                // seed 24 runs past 2^64 into the wide arithmetic.
                let total = if seed == 24 {
                    (1 + i128::from(rng.below(1 << 40))) << 60
                } else {
                    3 + i128::from(rng.below(10_000_000))
                };
                for (side, k) in [
                    (Side::Credit, 1 + rng.below(3)),
                    (Side::Debit, 1 + rng.below(3)),
                ] {
                    for part in split(&mut rng, total, usize::try_from(k).unwrap()) {
                        let account = accounts[usize::try_from(rng.below(8)).unwrap()];
                        legs.push((account, side, unit, part));
                        let named = match rng.below(10) {
                            0..=3 => vec![values[usize::try_from(rng.below(4)).unwrap()]],
                            4 => vec![unregistered],
                            5 => {
                                let v = values[usize::try_from(rng.below(4)).unwrap()];
                                vec![v, v]
                            }
                            6 => vec![values[0], values[1]],
                            _ => Vec::new(),
                        };
                        let leg_entity = match entity_mode {
                            1 if rng.below(2) == 0 => Some(entities[0]),
                            _ => entity,
                        };
                        tags.push((named, leg_entity));
                    }
                }
            }
            let mut e = make_snapshot_entry(
                &mut h,
                VId((u128::from(seed) << 32) | u128::from(n + 1)),
                CommitSeq(n + 1),
                date,
                &period,
                EntryClass::ORIGINAL,
                legs.clone(),
                Vec::new(),
                None,
                Some(date),
                None,
                Vec::new(),
            );
            let mut paid_legs = Vec::new();
            let mut first_party_legs = Vec::new();
            for ((leg, (named, entity)), (_, side, unit, mantissa)) in
                e.entry.proposal.legs.iter_mut().zip(&tags).zip(&legs)
            {
                for value in named {
                    leg.dimension_set.push((PARTY_DIMENSION, *value));
                }
                if let Some(entity) = entity {
                    leg.dimension_set.push((LEGAL_ENTITY_DIMENSION, *entity));
                }
                leg.dimension_set.sort();
                let paid_leg = PaidLeg {
                    debit: *side == Side::Debit,
                    party_values: named.iter().map(|v| v.0).collect(),
                    unit: unit.0,
                    entity: entity.map(|e| e.0),
                    mantissa: *mantissa,
                };
                let mut first = paid_leg.clone();
                first.party_values.truncate(1);
                first_party_legs.push(first);
                paid_legs.push(paid_leg);
            }
            reference.push(paid_legs);
            first_party_reference.push(first_party_legs);
            snapshot.entries.push(e);
        }

        let mut projected: BTreeMap<(u128, u128, u32, Option<u128>), i128> = BTreeMap::new();
        for s in party_flow_legs(&snapshot).unwrap() {
            let key = (
                s.leg.from.0,
                s.leg.to.0,
                s.leg.unit_id,
                s.legal_entity.map(|e| e.0),
            );
            let slot = projected.entry(key).or_insert(0);
            *slot = slot.checked_add(s.leg.mantissa).unwrap();
        }
        let literal = paid_fold(&reference, &parties).unwrap();
        assert_eq!(projected, literal, "seed {seed}");
        assert!(!projected.is_empty(), "seed {seed}: no PAID edge at all");
        edges += projected.len();
        via_unregistered += projected
            .keys()
            .filter(|(from, to, ..)| *from == unregistered.0 || *to == unregistered.0)
            .count();
        cross_unit += projected
            .keys()
            .filter(|(.., unit, _)| *unit == jpy.0)
            .count();
        entity_scoped += projected.keys().filter(|(.., e)| e.is_some()).count();
        if paid_fold(&first_party_reference, &parties).unwrap() != literal {
            disagreements += 1;
        }
    }
    println!(
        "PAID differential: {edges} edges over 24 seeds ({via_unregistered} via an unregistered value, {cross_unit} in JPY, {entity_scoped} entity-scoped); the planted first-party rule disagrees on {disagreements} seeds"
    );
    assert!(via_unregistered > 0 && cross_unit > 0 && entity_scoped > 0);
    assert!(
        disagreements > 0,
        "the planted rule change was never observed"
    );
}

/// fa-b6xs: `graph.party_communities` groups counterparties by amount. A, B
/// and C move 1,200,000 among themselves through clearing account 1010,
/// where the account graph sees only self-flows. A also pays D 10,000 and A
/// sends the book 20,000, so the community keeps 1,200,000 of 1,230,000
/// incident (9,756 bps). D and E trade 200,000 between themselves: a second
/// community, below the default size of 3, flagged once the size is 2.
#[test]
fn parties_that_move_money_among_themselves_form_a_community() {
    use fa_lantern::graph::{Communities, PartyCommunities};

    let mut h = harness();
    let mut snapshot = h.snapshot();
    snapshot.coordinate.effective_through = None;
    let (_, a) = party(&h, &mut snapshot, "SHELL-A");
    let (_, b) = party(&h, &mut snapshot, "SHELL-B");
    let (_, c) = party(&h, &mut snapshot, "SHELL-C");
    let (_, d) = party(&h, &mut snapshot, "SHELL-D");
    let (_, e) = party(&h, &mut snapshot, "SHELL-E");
    let hops = [
        (1001, 5, a, b, 500_000),
        (1002, 6, b, c, 400_000),
        (1003, 7, c, a, 300_000),
        (1004, 8, a, d, 10_000),
        (1005, 9, d, e, 200_000),
    ];
    let mut internal_entries = Vec::new();
    for (vid, dd, from, to, cents) in hops {
        let entry = transfer(
            &mut h,
            vid,
            day(2026, 1, dd),
            "1010",
            Some(to),
            "1010",
            Some(from),
            cents,
        );
        if vid <= 1003 {
            internal_entries.push(entry.vid);
        }
        snapshot.entries.push(entry);
    }
    let receipt = transfer(
        &mut h,
        1006,
        day(2026, 1, 10),
        "1000",
        None,
        "1200",
        Some(a),
        20_000,
    );
    snapshot.entries.push(receipt);

    // The account graph sees one clearing account trading with itself.
    let accounts = run_over(&snapshot, &h.book, &Communities::new().unwrap()).unwrap();
    assert!(
        accounts
            .findings
            .iter()
            .all(|f| !f.narrative.contains("SHELL")),
        "{:?}",
        accounts.findings
    );

    let procedure = PartyCommunities::new().unwrap();
    let r = run_over(&snapshot, &h.book, &procedure).unwrap();
    println!("party communities: {:?}", r.findings);
    assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
    let f = &r.findings[0];
    assert_eq!(f.statistic.name, "internal_share_bps");
    assert_eq!(f.statistic.value, 9_756);
    assert!(
        f.narrative.contains("3-party community")
            && f.narrative.contains("(1200000 of 1230000)")
            && f.narrative.contains("[SHELL-A, SHELL-B, SHELL-C]"),
        "{}",
        f.narrative
    );
    internal_entries.sort();
    assert_eq!(
        f.cites,
        internal_entries
            .iter()
            .copied()
            .map(Cite::Entry)
            .collect::<Vec<_>>()
    );
    let row = fa_lantern::bind(PartyCommunities::ID).unwrap();
    assert!(
        r.work.within_registered_bound(&row.complexity, &snapshot),
        "{:?}",
        r.work
    );
    assert!(
        determinism(&snapshot, &h.book, &procedure)
            .unwrap()
            .deterministic()
    );

    // At size 2, D and E (200,000 of 210,000 incident: 9,523 bps) join.
    let two = PartyCommunities::with(
        Params::defaults(PartyCommunities::ID)
            .unwrap()
            .set("min_community_size", 2)
            .unwrap(),
    );
    let r = run_over(&snapshot, &h.book, &two).unwrap();
    assert_eq!(r.findings.len(), 2, "{:?}", r.findings);
    assert!(
        r.findings
            .iter()
            .any(|f| f.statistic.value == 9_523 && f.narrative.contains("[SHELL-D, SHELL-E]")),
        "{:?}",
        r.findings
    );
}
