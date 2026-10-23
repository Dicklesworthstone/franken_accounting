//! Boundary regressions for procedure amounts; native fixtures are used where
//! the overflow can arise from individually valid postings.

use super::*;
use fa_lantern::graph::{Communities, Concentration, RelatedPartyExposure, ShellSignature};

#[test]
fn concentration_preserves_exact_basis_points_near_i128_max() {
    let mut h = harness();
    h.post(&Spec::simple(day(2026, 1, 5), "1010", "1000", i128::MAX));
    let before = h.db.frontier().unwrap();
    let snapshot = Snapshot::read(&h.db, &h.ctx().query(), &h.book, None, None).unwrap();
    let result = run_over(&snapshot, &h.book, &Concentration::new().unwrap()).unwrap();
    assert_eq!(result.findings.len(), 2);
    assert!(result.findings.iter().all(|finding| {
        finding.statistic.name == "flow_share_bps" && finding.statistic.value == 10_000
    }));
    assert_eq!(h.db.frontier().unwrap(), before, "a procedure never writes");

    let mut split = harness();
    split.post(&Spec::simple(
        day(2026, 1, 5),
        "1010",
        "1000",
        i128::MAX / 2,
    ));
    split.post(&Spec::simple(
        day(2026, 1, 6),
        "6000",
        "4000",
        i128::MAX / 2 + 1,
    ));
    let snapshot =
        Snapshot::read(&split.db, &split.ctx().query(), &split.book, None, None).unwrap();
    let procedure = Concentration::with(
        Params::defaults(Concentration::ID)
            .unwrap()
            .set("min_share_bps", 1)
            .unwrap(),
    );
    let result = run_over(&snapshot, &split.book, &procedure).unwrap();
    // The denominator is odd: one half rounds down to 4,999 bps and the
    // other to 5,000. Both products require exact wide intermediates.
    assert_eq!(
        result
            .findings
            .iter()
            .map(|finding| finding.statistic.value)
            .collect::<Vec<_>>(),
        vec![5_000, 5_000, 4_999, 4_999]
    );
}

#[test]
fn concentration_overflow_is_refused() {
    let mut h = harness();
    // Separate accounts and edges keep every individual posting and account
    // within range. The procedure's total unit volume alone exceeds MAX.
    h.post(&Spec::simple(day(2026, 1, 5), "1010", "1000", i128::MAX));
    h.post(&Spec::simple(day(2026, 1, 6), "6000", "4000", 1));
    let before = h.db.frontier().unwrap();
    let snapshot = Snapshot::read(&h.db, &h.ctx().query(), &h.book, None, None).unwrap();
    let error = run_over(&snapshot, &h.book, &Concentration::new().unwrap()).unwrap_err();
    assert!(matches!(
        error,
        LanternError::Overflow("graph.concentration unit volume")
    ));
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn communities_refuse_undirected_edge_overflow() {
    let mut h = harness();
    // Each directed edge fits. Folding the two directions into the
    // community procedure's single undirected edge must not clamp to MAX.
    h.post(&Spec::simple(day(2026, 1, 5), "1010", "1000", i128::MAX));
    h.post(&Spec::simple(day(2026, 1, 6), "1000", "1010", 1));
    let snapshot = Snapshot::read(&h.db, &h.ctx().query(), &h.book, None, None).unwrap();
    let error = run_over(&snapshot, &h.book, &Communities::new().unwrap()).unwrap_err();
    assert!(matches!(
        error,
        LanternError::Overflow("graph.communities edge volume")
    ));
}

#[test]
fn shell_signature_refuses_inflow_overflow() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    let period = h.period_code(day(2026, 1, 5));
    let usd = h.usd;
    for (vid, credit, amount) in [(81_001, "4000", i128::MAX), (81_002, "6000", 1)] {
        snapshot.entries.push(make_snapshot_entry(
            &mut h,
            VId(vid),
            CommitSeq(501),
            day(2026, 1, 5),
            &period,
            EntryClass::ORIGINAL,
            vec![
                ("1000", Side::Debit, usd, amount),
                (credit, Side::Credit, usd, amount),
            ],
            Vec::new(),
            None,
            None,
            None,
            Vec::new(),
        ));
    }
    let error = run_over(&snapshot, &h.book, &ShellSignature::new().unwrap()).unwrap_err();
    assert!(matches!(
        error,
        LanternError::Overflow("graph.shell_signature account inflow")
    ));
}

#[test]
fn related_party_exposure_overflow_is_refused() {
    let mut h = harness();
    let mut snapshot = h.snapshot();
    let period = h.period_code(day(2026, 1, 5));
    let usd = h.usd;
    let mut entry = make_snapshot_entry(
        &mut h,
        VId(82_001),
        CommitSeq(501),
        day(2026, 1, 5),
        &period,
        EntryClass::ORIGINAL,
        vec![
            ("1010", Side::Debit, usd, i128::MAX),
            ("1000", Side::Credit, usd, i128::MAX),
        ],
        Vec::new(),
        None,
        None,
        None,
        Vec::new(),
    );
    // The public run_over API also accepts supplied snapshots. An adversarial
    // body must refuse rather than return a saturated exposure, even though
    // native posting independently prevents such a per-unit debit total.
    entry.entry.proposal.legs.push(LegPayload::simple(
        Side::Debit,
        h.account("6000"),
        Amount::new(usd, 1),
    ));
    snapshot.entries.push(entry);
    snapshot
        .rea
        .relationships
        .push(fa_journal::rea::RelationshipRow {
            eid: fgdb_types::EId(1),
            spec: fa_model::RelationshipSpec {
                from: VId(91),
                to: VId(92),
                kind: fa_model::RelationshipKind::Controls,
                basis: "overflow fixture".into(),
                valid_from: day(2026, 1, 1),
                valid_to: None,
            },
            recorded_at: CommitSeq(1),
            control_entry: VId(93),
        });
    let error = run_over(&snapshot, &h.book, &RelatedPartyExposure::new().unwrap()).unwrap_err();
    assert!(matches!(
        error,
        LanternError::Overflow("graph.related_party_exposure debit exposure")
    ));
}
