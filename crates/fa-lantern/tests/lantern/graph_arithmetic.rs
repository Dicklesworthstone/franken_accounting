//! Boundary regressions for procedure amounts and civil-day windows. Native
//! postings establish ordinary controls; extreme dates are arithmetic inputs.

use super::*;
use fa_lantern::graph::{Communities, Concentration, RelatedPartyExposure, ShellSignature};

#[test]
fn native_layering_advances_each_same_day_hop_and_preserves_version_two() {
    use fa_lantern::graph::Layering;

    for (order, current_finds_chain, retained_finds_chain) in [
        (
            [("1000", "1010"), ("1010", "1020"), ("1020", "1200")],
            true,
            true,
        ),
        // The last hop was posted before the middle one.
        (
            [("1000", "1010"), ("1020", "1200"), ("1010", "1020")],
            false,
            true,
        ),
        // Neither version may start with a transfer recorded later than
        // its middle hop: that guard already existed before this repair.
        (
            [("1010", "1020"), ("1000", "1010"), ("1020", "1200")],
            false,
            false,
        ),
    ] {
        let mut h = harness();
        let mut posted = BTreeMap::new();
        for (from, to) in order {
            let vid = h.post(&Spec::simple(day(2026, 1, 5), to, from, 10_000));
            let recorded = h.posted.last().unwrap().1;
            posted.insert(from, (vid, recorded));
        }
        assert!(h.posted.windows(2).all(|pair| pair[0].1 < pair[1].1));
        let path: Vec<_> = ["1000", "1010", "1020"]
            .into_iter()
            .map(|from| posted[from])
            .collect();
        assert_eq!(
            path.windows(2).all(|pair| pair[0].1 < pair[1].1),
            current_finds_chain
        );
        let before = h.db.frontier().unwrap();
        let snapshot = h.snapshot();
        for (version, expected) in [(2, retained_finds_chain), (3, current_finds_chain)] {
            let procedure = fa_lantern::catalog::build_version(
                Layering::ID,
                version,
                Params::defaults(Layering::ID).unwrap(),
                fa_lantern::catalog::Inputs::default(),
            )
            .unwrap();
            let result = run_over(&snapshot, &h.book, procedure.as_ref()).unwrap();
            assert_eq!(result.version, version);
            assert_eq!(result.findings.len(), usize::from(expected));
            if expected {
                let finding = &result.findings[0];
                assert_eq!(finding.version, version);
                assert_eq!(finding.severity, Severity::High);
                assert_eq!(
                    finding.statistic,
                    Statistic {
                        name: "layered_mantissa".into(),
                        value: 10_000,
                        scale: 2,
                        population: 3,
                    }
                );
                let cites: Vec<_> = finding
                    .cites
                    .iter()
                    .filter_map(|cite| {
                        if let Cite::Entry(vid) = cite {
                            Some(*vid)
                        } else {
                            None
                        }
                    })
                    .collect();
                assert_eq!(cites, path.iter().map(|(vid, _)| *vid).collect::<Vec<_>>());
                h.assert_cites_resolve(&result);
            }
            assert!(
                witness::determinism(&snapshot, &h.book, procedure.as_ref())
                    .unwrap()
                    .deterministic()
            );
        }
        for unsupported in [1, 4] {
            assert!(matches!(
                fa_lantern::catalog::build_version(
                    Layering::ID,
                    unsupported,
                    Params::defaults(Layering::ID).unwrap(),
                    fa_lantern::catalog::Inputs::default(),
                ),
                Err(LanternError::Version { .. })
            ));
        }
        assert_eq!(h.db.frontier().unwrap(), before);
    }
}

#[test]
fn round_trips_accept_u32_windows_in_pair_and_cycle_searches() {
    let mut h = harness();
    let outbound = h.post(&Spec::simple(day(2026, 1, 30), "1010", "1000", 10_000));
    let returned = h.post(&Spec::simple(day(2026, 2, 1), "1000", "1010", 10_000));
    let before = h.db.frontier().unwrap();
    let snapshot = h.snapshot();
    let expected = Statistic {
        name: "round_trip_mantissa".into(),
        value: 10_000,
        scale: 2,
        population: 2,
    };
    let default = run_over(&snapshot, &h.book, &RoundTrips::new().unwrap()).unwrap();
    assert_eq!(default.findings.len(), 1);
    assert_eq!(default.findings[0].statistic, expected);
    assert_eq!(default.findings[0].severity, Severity::High);
    for max_hops in [2_i128, 3] {
        for (window, period_window, severity) in [
            (0, 7, None),
            (1, 7, None),
            (2, 7, Some(Severity::High)),
            (4_294_967_295, 7, Some(Severity::High)),
            (4_294_967_295, 4_294_967_295, Some(Severity::High)),
            (2, 0, Some(Severity::Medium)),
        ] {
            let procedure = RoundTrips::with(
                Params::defaults(RoundTrips::ID)
                    .unwrap()
                    .set("window_days", window)
                    .unwrap()
                    .set("period_end_days", period_window)
                    .unwrap()
                    .set("max_hops", max_hops)
                    .unwrap(),
            );
            let result = run_over(&snapshot, &h.book, &procedure).unwrap();
            assert_eq!(result.findings.len(), usize::from(severity.is_some()));
            if let Some(severity) = severity {
                let finding = &result.findings[0];
                assert_eq!(finding.statistic, expected);
                assert_eq!(finding.severity, severity);
                let entries: BTreeSet<_> = finding
                    .cites
                    .iter()
                    .filter_map(|cite| match cite {
                        Cite::Entry(vid) => Some(*vid),
                        _ => None,
                    })
                    .collect();
                assert_eq!(entries, BTreeSet::from([outbound, returned]));
                h.assert_cites_resolve(&result);
                assert!(
                    witness::determinism(&snapshot, &h.book, &procedure)
                        .unwrap()
                        .deterministic()
                );
            }
        }
    }
    for invalid in [-1, 4_294_967_296] {
        let procedure = RoundTrips::with(
            Params::defaults(RoundTrips::ID)
                .unwrap()
                .set("period_end_days", invalid)
                .unwrap(),
        );
        assert!(matches!(
            run_over(&snapshot, &h.book, &procedure),
            Err(LanternError::Parameter { name, .. }) if name == "period_end_days"
        ));
    }

    // Date-only perturbations of the admitted pair exercise arithmetic, not
    // extreme-date posting admission, period law or certificate validity.
    let mut wide = snapshot.clone();
    wide.coordinate.effective_through = Some(DateDay(i32::MAX));
    for entry in &mut wide.entries {
        if entry.vid == outbound {
            entry.entry.proposal.effective_date = DateDay(i32::MIN);
        } else if entry.vid == returned {
            entry.entry.proposal.effective_date = DateDay(i32::MAX);
        }
    }
    wide.fold_roles().unwrap();
    for max_hops in [2_i128, 3] {
        for (window, count) in [(4_294_967_294, 0), (4_294_967_295, 1)] {
            let procedure = RoundTrips::with(
                Params::defaults(RoundTrips::ID)
                    .unwrap()
                    .set("window_days", window)
                    .unwrap()
                    .set("period_end_days", 4_294_967_295)
                    .unwrap()
                    .set("max_hops", max_hops)
                    .unwrap(),
            );
            let result = run_over(&wide, &h.book, &procedure).unwrap();
            assert_eq!(result.findings.len(), count);
            if count == 1 {
                assert_eq!(result.findings[0].statistic, expected);
            }
        }
    }
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn all_graph_day_helper_consumers_accept_u32_windows_and_refuse_invalid_domains() {
    let mut h = harness();
    h.post(&Spec::simple(day(2026, 1, 30), "1010", "1000", 10_000));
    h.post(&Spec::simple(day(2026, 2, 1), "1000", "1010", 10_000));
    let before = h.db.frontier().unwrap();
    let snapshot = h.snapshot();
    for id in [
        "graph.round_trips",
        "graph.structuring",
        "graph.circular_flows",
        "graph.party_circular_flows",
        "graph.layering",
        "graph.party_layering",
    ] {
        let evaluate = |window| {
            let procedure = fa_lantern::catalog::build(
                id,
                Params::defaults(id)
                    .unwrap()
                    .set("window_days", window)
                    .unwrap(),
                fa_lantern::catalog::Inputs::default(),
            )
            .unwrap();
            run_over(&snapshot, &h.book, procedure.as_ref())
        };
        let baseline = evaluate(Params::defaults(id).unwrap().get("window_days").unwrap()).unwrap();
        let maximum = evaluate(4_294_967_295).unwrap();
        let meaning = |run: &ProcedureRun| {
            run.findings
                .iter()
                .map(|finding| {
                    (
                        finding.severity.name(),
                        finding.statistic.clone(),
                        finding.cites.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        // Every supplied transfer is within the default window already.
        // Widening it preserves findings; narratives may name the parameter.
        assert_eq!(meaning(&maximum), meaning(&baseline), "{id}");
        for invalid in [-1, 4_294_967_296] {
            assert!(
                matches!(
                    evaluate(invalid),
                    Err(LanternError::Parameter { name, .. }) if name == "window_days"
                ),
                "{id}"
            );
        }
    }
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn native_layering_windows_preserve_positive_paths_and_widen_date_subtraction() {
    use fa_lantern::graph::Layering;

    let mut h = harness();
    let entries = [
        h.post(&Spec::simple(day(2026, 1, 30), "1010", "1000", 10_000)),
        h.post(&Spec::simple(day(2026, 1, 31), "1020", "1010", 10_000)),
        h.post(&Spec::simple(day(2026, 2, 1), "1200", "1020", 10_000)),
    ];
    let before = h.db.frontier().unwrap();
    let snapshot = h.snapshot();
    let procedure = |window| {
        Layering::with(
            Params::defaults(Layering::ID)
                .unwrap()
                .set("window_days", window)
                .unwrap(),
        )
    };
    for (window, count) in [(0, 0), (1, 0), (2, 1), (10, 1), (4_294_967_295, 1)] {
        let result = run_over(&snapshot, &h.book, &procedure(window)).unwrap();
        assert_eq!(result.findings.len(), count);
        if count == 1 {
            assert_eq!(result.findings[0].severity, Severity::High);
            assert_eq!(
                result.findings[0].statistic,
                Statistic {
                    name: "layered_mantissa".into(),
                    value: 10_000,
                    scale: 2,
                    population: 3,
                }
            );
            let cited: BTreeSet<_> = result.findings[0]
                .cites
                .iter()
                .filter_map(|cite| {
                    if let Cite::Entry(vid) = cite {
                        Some(*vid)
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(cited, BTreeSet::from(entries));
            h.assert_cites_resolve(&result);
            assert!(
                witness::determinism(&snapshot, &h.book, &procedure(window))
                    .unwrap()
                    .deterministic()
            );
        }
    }
    // These date perturbations retain the native recorded coordinates, but
    // do not claim admission or certification of the resulting periods.
    let mut wide = snapshot.clone();
    wide.coordinate.effective_through = Some(DateDay(i32::MAX));
    for (vid, date) in entries.into_iter().zip([i32::MIN, 0, i32::MAX]) {
        wide.entries
            .iter_mut()
            .find(|entry| entry.vid == vid)
            .unwrap()
            .entry
            .proposal
            .effective_date = DateDay(date);
    }
    wide.fold_roles().unwrap();
    for (window, count) in [(4_294_967_294, 0), (4_294_967_295, 1)] {
        let result = run_over(&wide, &h.book, &procedure(window)).unwrap();
        assert_eq!(result.findings.len(), count);
        if count == 1 {
            assert_eq!(result.findings[0].statistic.value, 10_000);
            assert_eq!(result.findings[0].statistic.population, 3);
        }
    }
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn native_structuring_windows_keep_distinct_transfers_within_the_u32_domain() {
    let mut h = harness();
    let entries = [
        h.post(&Spec::simple(day(2026, 1, 30), "1010", "1000", 900_000)),
        h.post(&Spec::simple(day(2026, 1, 31), "1010", "1000", 900_000)),
        h.post(&Spec::simple(day(2026, 2, 1), "1010", "1000", 900_000)),
    ];
    let before = h.db.frontier().unwrap();
    let snapshot = h.snapshot();
    for (window, count) in [(0, 0), (7, 1), (4_294_967_295, 1)] {
        let procedure = Structuring::with(
            Params::defaults(Structuring::ID)
                .unwrap()
                .set("window_days", window)
                .unwrap(),
        );
        let result = run_over(&snapshot, &h.book, &procedure).unwrap();
        assert_eq!(result.findings.len(), count);
        if count == 1 {
            assert_eq!(result.findings[0].severity, Severity::High);
            assert_eq!(
                result.findings[0].statistic,
                Statistic {
                    name: "chain_mantissa".into(),
                    value: 2_700_000,
                    scale: 2,
                    population: 3,
                }
            );
            let cited: BTreeSet<_> = result.findings[0]
                .cites
                .iter()
                .filter_map(|cite| {
                    if let Cite::Entry(vid) = cite {
                        Some(*vid)
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(cited, BTreeSet::from(entries));
            h.assert_cites_resolve(&result);
            assert!(
                witness::determinism(&snapshot, &h.book, &procedure)
                    .unwrap()
                    .deterministic()
            );
        }
    }
    assert_eq!(h.db.frontier().unwrap(), before);
}

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
