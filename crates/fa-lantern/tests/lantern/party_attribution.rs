//! fa-6l8g: party-attributed amounts are conserved. One payment that settles
//! A's 100 and B's 200 pays A 100 and B 200, each dated by its own invoice,
//! never 300 to each; one subscription of A's 100 and B's 200 gives them
//! claims of 100 and 200, so a pool of 90 is shared 30/60. Cash that no one
//! party's own legs account for is reported unresolved and given to no one.
//! The expected margins are literals written from the economic history, not
//! from the implementation.

use super::*;
use fa_lantern::cutoff::{
    DistributionProRata, DistributionRisingTide, LookbackPreferences, PonziNetInvestment,
};
use fa_model::{EntryClass, EntryRef, PARTY_DIMENSION, Settlement};

/// Registers a party; its dimension value.
fn party(h: &Harness, snapshot: &mut Snapshot, code: &str) -> VId {
    let party = fa_model::party_vid(h.book.book_id, code);
    let value = fa_model::party_value_vid(h.book.book_id, code);
    snapshot.rea.parties.insert(
        party,
        fa_journal::rea::PartyRow {
            vid: party,
            dimension_value_vid: value,
            code: code.into(),
            kind: fa_model::PartyKind::Vendor,
            name: Erasable::seal(
                &code.to_string(),
                None,
                &h.book.seal_key,
                [0x71; 32],
                [0x72; 24],
            ),
            identifiers: Vec::new(),
            external_ids: Vec::new(),
            created_at: CommitSeq(1),
        },
    );
    value
}

/// One leg: account, side, cents, the party value it names, and the entry
/// it settles.
type L = (&'static str, Side, i128, Option<VId>, Option<VId>);

fn entry(
    h: &mut Harness,
    vid: u128,
    date: DateDay,
    document_date: Option<DateDay>,
    legs: &[L],
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
        legs.iter()
            .map(|(code, side, cents, _, _)| (*code, *side, usd, *cents))
            .collect(),
        Vec::new(),
        None,
        document_date,
        None,
        Vec::new(),
    );
    for (leg, (_, _, cents, named, settles)) in e.entry.proposal.legs.iter_mut().zip(legs) {
        if let Some(value) = named {
            leg.dimension_set.push((PARTY_DIMENSION, *value));
            leg.dimension_set.sort();
        }
        if let Some(target) = settles {
            leg.settles.push(Settlement {
                target: EntryRef {
                    vid: *target,
                    entry_digest: [0; 32],
                },
                ordinal: 0,
                amount: Amount::new(usd, *cents),
            });
        }
    }
    e
}

fn assign(h: &Harness, snapshot: &mut Snapshot, roles: &[(&str, &str)]) {
    for (seq, (code, role)) in roles.iter().enumerate() {
        snapshot.entries.push(role_entry(
            h,
            h.account(code),
            role,
            CommitSeq(990 + u64::try_from(seq).unwrap()),
        ));
    }
    snapshot.fold_roles().unwrap();
}

/// `(statistic, value, narrative)` of each finding about `code` (its
/// narrative's second word: "creditor VEND-A (...", "investor INV-A: ..."),
/// in emission order.
fn of<'a>(findings: &'a [Finding], code: &str) -> Vec<(&'a str, i128, &'a str)> {
    findings
        .iter()
        .filter(|f| {
            f.narrative
                .split_whitespace()
                .nth(1)
                .map(|word| word.trim_end_matches(':'))
                == Some(code)
        })
        .map(|f| {
            (
                f.statistic.name.as_str(),
                f.statistic.value,
                f.narrative.as_str(),
            )
        })
        .collect()
}

fn preferences(contemporaneous_days: i128) -> LookbackPreferences {
    LookbackPreferences::with(
        Params::defaults(LookbackPreferences::ID)
            .unwrap()
            .set("contemporaneous_days", contemporaneous_days)
            .unwrap(),
    )
}

/// Two bills, A 100 on Feb 1 and B 200 on Feb 20, paid on Apr 15: the
/// batched history in one entry, or the split history in two.
fn creditors(batched: bool) -> (Harness, Snapshot) {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    snapshot.coordinate.effective_through = Some(day(2026, 4, 30));
    let a = party(&h, &mut snapshot, "VEND-A");
    let b = party(&h, &mut snapshot, "VEND-B");
    let bill_a = entry(
        &mut h,
        1101,
        day(2026, 2, 1),
        Some(day(2026, 2, 1)),
        &[
            ("6000", Side::Debit, 10_000, Some(a), None),
            ("2000", Side::Credit, 10_000, Some(a), None),
        ],
    );
    let bill_b = entry(
        &mut h,
        1102,
        day(2026, 2, 20),
        Some(day(2026, 2, 20)),
        &[
            ("7000", Side::Debit, 20_000, Some(b), None),
            ("2000", Side::Credit, 20_000, Some(b), None),
        ],
    );
    let (bill_a_vid, bill_b_vid) = (bill_a.vid, bill_b.vid);
    snapshot.entries = vec![bill_a, bill_b];
    if batched {
        let paid = entry(
            &mut h,
            1103,
            day(2026, 4, 15),
            None,
            &[
                ("2000", Side::Debit, 10_000, Some(a), Some(bill_a_vid)),
                ("2000", Side::Debit, 20_000, Some(b), Some(bill_b_vid)),
                ("1000", Side::Credit, 30_000, None, None),
            ],
        );
        snapshot.entries.push(paid);
    } else {
        let paid_a = entry(
            &mut h,
            1103,
            day(2026, 4, 15),
            None,
            &[
                ("2000", Side::Debit, 10_000, Some(a), Some(bill_a_vid)),
                ("1000", Side::Credit, 10_000, None, None),
            ],
        );
        let paid_b = entry(
            &mut h,
            1104,
            day(2026, 4, 15),
            None,
            &[
                ("2000", Side::Debit, 20_000, Some(b), Some(bill_b_vid)),
                ("1000", Side::Credit, 20_000, None, None),
            ],
        );
        snapshot.entries.extend([paid_a, paid_b]);
    }
    assign(&h, &mut snapshot, &[("1000", "cash")]);
    (h, snapshot)
}

#[test]
fn preference_batch_preserves_creditor_margins() {
    let (mut h, mut snapshot) = creditors(true);
    let r = run_over(&snapshot, &h.book, &preferences(5)).unwrap();
    println!("batched preferences: {:?}", r.findings);
    // A is paid 100 and B 200 (version 2 paid each of them 300); both are
    // outside the 5-day contemporaneous window.
    assert_eq!(r.findings.len(), 2, "{:?}", r.findings);
    let a = of(&r.findings, "VEND-A");
    let b = of(&r.findings, "VEND-B");
    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);
    assert_eq!((a[0].0, a[0].1), ("net_preference_exposure", 10_000));
    assert_eq!((b[0].0, b[0].1), ("net_preference_exposure", 20_000));
    assert!(
        a[0].2.contains("gross_preference=10000") && a[0].2.contains("attribution=complete"),
        "{}",
        a[0].2
    );
    assert!(
        b[0].2.contains("gross_preference=20000") && b[0].2.contains("attribution=complete"),
        "{}",
        b[0].2
    );
    for f in &r.findings {
        assert_eq!(f.version, 3);
    }

    // Each invoice keeps its own date: paid on Apr 15, B's (Feb 20) is 54
    // days old and A's (Feb 1) 73. Within 60 days B's payment is a
    // contemporaneous exchange and A's is not; one shared earliest date
    // (Feb 1) would leave B's exposed too.
    let r = run_over(&snapshot, &h.book, &preferences(60)).unwrap();
    assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
    assert_eq!(of(&r.findings, "VEND-A")[0].1, 10_000);
    assert!(of(&r.findings, "VEND-B").is_empty(), "{:?}", r.findings);

    // A short payment over both creditors (a 50 discount covers the rest)
    // says nobody's share: its 250 is unresolved, and both exposures are
    // marked incomplete.
    let a = fa_model::party_value_vid(h.book.book_id, "VEND-A");
    let b = fa_model::party_value_vid(h.book.book_id, "VEND-B");
    let short = entry(
        &mut h,
        1105,
        day(2026, 4, 20),
        None,
        &[
            ("2000", Side::Debit, 10_000, Some(a), None),
            ("2000", Side::Debit, 20_000, Some(b), None),
            ("1000", Side::Credit, 25_000, None, None),
            ("4000", Side::Credit, 5_000, None, None),
        ],
    );
    let short_vid = short.vid;
    snapshot.entries.push(short);
    let r = run_over(&snapshot, &h.book, &preferences(5)).unwrap();
    println!("with a short payment: {:?}", r.findings);
    assert_eq!(r.findings.len(), 3, "{:?}", r.findings);
    assert_eq!(of(&r.findings, "VEND-A")[0].1, 10_000);
    assert_eq!(of(&r.findings, "VEND-B")[0].1, 20_000);
    assert!(
        of(&r.findings, "VEND-A")[0]
            .2
            .contains("attribution=incomplete")
    );
    assert!(
        of(&r.findings, "VEND-B")[0]
            .2
            .contains("attribution=incomplete")
    );
    let unresolved = r
        .findings
        .iter()
        .find(|f| f.statistic.name == "unresolved_attribution")
        .expect("an unresolved finding");
    assert_eq!(unresolved.statistic.value, 25_000);
    assert_eq!(unresolved.cites.first(), Some(&Cite::Entry(short_vid)));
    assert!(
        unresolved
            .narrative
            .contains("parties named: [VEND-A, VEND-B]"),
        "{}",
        unresolved.narrative
    );
}

#[test]
fn split_and_batched_history_agree() {
    let mut outcomes = Vec::new();
    for batched in [true, false] {
        let (h, snapshot) = creditors(batched);
        let r = run_over(&snapshot, &h.book, &preferences(5)).unwrap();
        let mut rows: Vec<(String, i128)> = r
            .findings
            .iter()
            .map(|f| {
                let creditor = f.narrative.split_whitespace().nth(1).unwrap().to_string();
                (creditor, f.statistic.value)
            })
            .collect();
        rows.sort();
        outcomes.push(rows);
    }
    let literal = vec![
        ("VEND-A".to_string(), 10_000),
        ("VEND-B".to_string(), 20_000),
    ];
    assert_eq!(outcomes[0], literal, "batched");
    assert_eq!(outcomes[1], literal, "split");

    // The same for subscriptions: one entry of A 100 and B 200, or two.
    let mut claims = Vec::new();
    for batched in [true, false] {
        let (h, snapshot) = investors(batched);
        let r = run_over(&snapshot, &h.book, &PonziNetInvestment::new().unwrap()).unwrap();
        let mut rows: Vec<(String, i128)> = r
            .findings
            .iter()
            .map(|f| {
                let investor = f.narrative.split_whitespace().nth(1).unwrap().to_string();
                (investor, f.statistic.value)
            })
            .collect();
        rows.sort();
        claims.push(rows);
    }
    let literal = vec![("INV-A".to_string(), 10_000), ("INV-B".to_string(), 20_000)];
    assert_eq!(claims[0], literal, "batched");
    assert_eq!(claims[1], literal, "split");
}

/// A subscribes 100 and B 200 on Jan 10: in one entry, or in two.
fn investors(batched: bool) -> (Harness, Snapshot) {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    snapshot.coordinate.effective_through = None;
    let a = party(&h, &mut snapshot, "INV-A");
    let b = party(&h, &mut snapshot, "INV-B");
    if batched {
        let both = entry(
            &mut h,
            1201,
            day(2026, 1, 10),
            None,
            &[
                ("1000", Side::Debit, 30_000, None, None),
                ("2000", Side::Credit, 10_000, Some(a), None),
                ("2000", Side::Credit, 20_000, Some(b), None),
            ],
        );
        snapshot.entries = vec![both];
    } else {
        let one = entry(
            &mut h,
            1201,
            day(2026, 1, 10),
            None,
            &[
                ("1000", Side::Debit, 10_000, None, None),
                ("2000", Side::Credit, 10_000, Some(a), None),
            ],
        );
        let two = entry(
            &mut h,
            1202,
            day(2026, 1, 10),
            None,
            &[
                ("1000", Side::Debit, 20_000, None, None),
                ("2000", Side::Credit, 20_000, Some(b), None),
            ],
        );
        snapshot.entries = vec![one, two];
    }
    assign(
        &h,
        &mut snapshot,
        &[("1000", "cash"), ("2000", "investor_capital")],
    );
    (h, snapshot)
}

#[test]
fn ponzi_and_distribution_preserve_investor_margins() {
    let (mut h, mut snapshot) = investors(true);
    let pool = |id: &str| {
        Params::defaults(id)
            .unwrap()
            .set("distributable_pool", 9_000)
            .unwrap()
    };

    // Net equity: A 100 and B 200 (version 2 credited each with 300).
    let r = run_over(&snapshot, &h.book, &PonziNetInvestment::new().unwrap()).unwrap();
    println!("ponzi: {:?}", r.findings);
    assert_eq!(r.findings.len(), 2, "{:?}", r.findings);
    let a = of(&r.findings, "INV-A");
    let b = of(&r.findings, "INV-B");
    assert_eq!((a[0].0, a[0].1), ("net_equity_claim", 10_000));
    assert_eq!((b[0].0, b[0].1), ("net_equity_claim", 20_000));
    assert!(a[0].2.contains("cash_in=10000") && a[0].2.contains("attribution=complete"));
    assert!(b[0].2.contains("cash_in=20000") && b[0].2.contains("attribution=complete"));

    // A pool of 90 is shared 30/60 under both laws (neither has withdrawn,
    // so the rising tide is pro rata here); version 2 split it 45/45.
    for procedure in [
        Box::new(DistributionProRata::with(pool(DistributionProRata::ID))) as Box<dyn Procedure>,
        Box::new(DistributionRisingTide::with(pool(
            DistributionRisingTide::ID,
        ))),
    ] {
        let r = run_over(&snapshot, &h.book, procedure.as_ref()).unwrap();
        println!("{}: {:?}", procedure.id(), r.findings);
        assert_eq!(r.findings.len(), 2, "{:?}", r.findings);
        assert_eq!(of(&r.findings, "INV-A")[0].1, 3_000, "{}", procedure.id());
        assert_eq!(of(&r.findings, "INV-B")[0].1, 6_000, "{}", procedure.id());
        assert!(r.findings.iter().all(|f| f.version == 3));
    }

    // A subscription whose 40 of cash covers only part of A's 20 and B's 30
    // (a 10 fee is the rest) says neither's share: no distribution is
    // computed for the unit, which reports the unresolved 40 instead.
    let a = fa_model::party_value_vid(h.book.book_id, "INV-A");
    let b = fa_model::party_value_vid(h.book.book_id, "INV-B");
    let short = entry(
        &mut h,
        1203,
        day(2026, 1, 20),
        None,
        &[
            ("1000", Side::Debit, 4_000, None, None),
            ("6000", Side::Debit, 1_000, None, None),
            ("2000", Side::Credit, 2_000, Some(a), None),
            ("2000", Side::Credit, 3_000, Some(b), None),
        ],
    );
    let short_vid = short.vid;
    snapshot.entries.push(short);
    let r = run_over(
        &snapshot,
        &h.book,
        &DistributionProRata::with(pool(DistributionProRata::ID)),
    )
    .unwrap();
    println!("pro rata with unresolved cash: {:?}", r.findings);
    assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
    assert_eq!(r.findings[0].statistic.name, "unresolved_attribution");
    assert_eq!(r.findings[0].statistic.value, 4_000);
    assert_eq!(r.findings[0].cites.first(), Some(&Cite::Entry(short_vid)));
    // The net-equity schedule still reports both, marked incomplete.
    let r = run_over(&snapshot, &h.book, &PonziNetInvestment::new().unwrap()).unwrap();
    assert_eq!(r.findings.len(), 3, "{:?}", r.findings);
    assert_eq!(of(&r.findings, "INV-A")[0].1, 10_000);
    assert!(
        of(&r.findings, "INV-A")[0]
            .2
            .contains("attribution=incomplete")
    );
    assert!(
        of(&r.findings, "INV-B")[0]
            .2
            .contains("attribution=incomplete")
    );
}
