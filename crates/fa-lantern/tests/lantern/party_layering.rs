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
