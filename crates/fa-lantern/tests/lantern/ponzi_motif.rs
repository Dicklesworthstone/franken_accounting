//! fa-m35p: `graph.ponzi_motif` (plan §11.4) flags the windows in which new
//! investors' money funds payouts to earlier investors, by cohort of first
//! subscription, and leaves alone windows the new money does not cover.

use super::*;
use fa_lantern::cutoff::PonziMotif;
use fa_model::{EntryClass, PARTY_DIMENSION};

fn with(name: &str, value: i128) -> PonziMotif {
    PonziMotif::with(
        Params::defaults(PonziMotif::ID)
            .unwrap()
            .set(name, value)
            .unwrap(),
    )
}

/// Registers an investor party in the snapshot; its dimension value.
fn investor(h: &Harness, snapshot: &mut Snapshot, code: &str) -> VId {
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
                [0x41; 32],
                [0x42; 24],
            ),
            identifiers: Vec::new(),
            external_ids: Vec::new(),
            created_at: CommitSeq(1),
        },
    );
    value
}

/// A two-leg entry on `date`, every leg tagged with `parties`.
fn movement(
    h: &mut Harness,
    vid: u128,
    date: DateDay,
    debit: &str,
    credit: &str,
    cents: i128,
    parties: &[VId],
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
        for &party in parties {
            leg.dimension_set.push((PARTY_DIMENSION, party));
        }
        leg.dimension_set.sort();
    }
    e
}

#[test]
fn ponzi_motif_flags_new_money_funding_earlier_investors() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    snapshot.coordinate.effective_through = None;
    let a = investor(&h, &mut snapshot, "INV-A");
    let b = investor(&h, &mut snapshot, "INV-B");
    let c = investor(&h, &mut snapshot, "INV-C");
    // Cash is 1000; investor capital is the 2000 liability; revenue is 4000.
    // With 30-day windows from Jan 5: W0 Jan 5..Feb 3, W1 Feb 4..Mar 5,
    // W2 Mar 6..Apr 4.
    let a_in = movement(&mut h, 801, day(2026, 1, 5), "1000", "2000", 100_000, &[a]);
    let sales_w0 = movement(&mut h, 802, day(2026, 1, 20), "1000", "4000", 5_000, &[]);
    // W1: B is new (60_000); A, an earlier investor, is paid 50_000 booked
    // as an expense. No operating cash comes in: the payout can only be B's
    // money.
    let b_in = movement(&mut h, 803, day(2026, 2, 10), "1000", "2000", 60_000, &[b]);
    let a_paid = movement(&mut h, 804, day(2026, 2, 15), "6000", "1000", 50_000, &[a]);
    // W2: C is new (20_000); B redeems 30_000; 40_000 of sales come in. A
    // payment naming two parties is attributed to neither.
    let c_in = movement(&mut h, 805, day(2026, 3, 10), "1000", "2000", 20_000, &[c]);
    let b_out = movement(&mut h, 806, day(2026, 3, 20), "2000", "1000", 30_000, &[b]);
    let sales_w2 = movement(&mut h, 807, day(2026, 3, 25), "1000", "4000", 40_000, &[]);
    let shared = movement(
        &mut h,
        808,
        day(2026, 3, 26),
        "6000",
        "1000",
        7_000,
        &[a, c],
    );
    let (a_paid_vid, b_in_vid, b_out_vid, c_in_vid) = (a_paid.vid, b_in.vid, b_out.vid, c_in.vid);
    snapshot.entries = vec![a_in, sales_w0, b_in, a_paid, c_in, b_out, sales_w2, shared];

    // Without the cash role the procedure is refused, never run over
    // nothing.
    let refused = run_over(&snapshot, &h.book, &with("window_days", 30));
    assert!(
        matches!(&refused, Err(LanternError::RoleUnassigned { role, .. }) if role == "cash"),
        "{refused:?}"
    );
    snapshot.entries.extend([
        role_entry(&h, h.account("1000"), "cash", CommitSeq(900)),
        role_entry(&h, h.account("2000"), "investor_capital", CommitSeq(901)),
    ]);
    snapshot.fold_roles().unwrap();

    let procedure = with("window_days", 30);
    let r = run_over(&snapshot, &h.book, &procedure).unwrap();
    // The entries are built into the snapshot, not journaled, so a cited
    // entry is one the snapshot holds.
    for f in &r.findings {
        for c in &f.cites {
            assert!(
                matches!(c, Cite::Entry(v) if snapshot.entries.iter().any(|e| e.vid == *v)),
                "{c:?} is not a snapshot entry"
            );
        }
    }
    println!("ponzi motif findings={:?}", r.findings);
    // W1 only: 60_000 of new money is 12_000 bps of the 50_000 paid to A,
    // with no operating cash in. W0 has no redemption; in W2 new money is
    // 20_000 of 30_000 (6_666 bps), under the default 10_000.
    assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
    let f = &r.findings[0];
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.statistic.name, "new_money_to_redemptions_bps");
    assert_eq!(f.statistic.value, 12_000);
    // Five single-party movements; sales and the shared payment are not.
    assert_eq!(f.statistic.population, 5);
    assert_eq!(
        f.cites,
        vec![Cite::Entry(a_paid_vid), Cite::Entry(b_in_vid)]
    );
    assert!(
        f.narrative.contains("new investors [INV-B] paid in 60000")
            && f.narrative
                .contains("earlier investors [INV-A] received 50000"),
        "{}",
        f.narrative
    );
    let row = fa_lantern::bind(PonziMotif::ID).unwrap();
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

    // At 6_000 bps W2 is flagged too, Medium: its 40_000 of sales could
    // have paid B's 30_000. Had the shared 7_000 been counted, W2 would be
    // 20_000 of 37_000 (5_405 bps) and stay unflagged.
    let low = PonziMotif::with(
        Params::defaults(PonziMotif::ID)
            .unwrap()
            .set("window_days", 30)
            .unwrap()
            .set("min_coverage_bps", 6_000)
            .unwrap(),
    );
    let r = run_over(&snapshot, &h.book, &low).unwrap();
    assert_eq!(r.findings.len(), 2, "{:?}", r.findings);
    let w2 = r
        .findings
        .iter()
        .find(|f| f.statistic.value == 6_666)
        .expect("W2 at 6_666 bps");
    assert_eq!(w2.severity, Severity::Medium);
    assert_eq!(
        w2.cites,
        vec![Cite::Entry(b_out_vid), Cite::Entry(c_in_vid)]
    );

    // One 90-day window (the default) holds every subscription: nobody is
    // an earlier investor, so nothing is flagged.
    let r = run_over(&snapshot, &h.book, &PonziMotif::new().unwrap()).unwrap();
    assert!(r.findings.is_empty(), "{:?}", r.findings);

    // Out-of-range parameters are refused, never clamped.
    for name in ["window_days", "min_coverage_bps"] {
        let refused = run_over(&snapshot, &h.book, &with(name, 0));
        assert!(
            matches!(&refused, Err(LanternError::Parameter { name: n, .. }) if n == name),
            "{name}: {refused:?}"
        );
    }
}
