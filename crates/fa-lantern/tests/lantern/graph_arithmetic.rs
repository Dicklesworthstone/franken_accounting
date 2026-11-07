//! Boundary regressions for procedure amounts and civil-day windows. Native
//! postings establish ordinary controls; extreme dates are arithmetic inputs.

use super::*;
use fa_lantern::graph::{Communities, Concentration, RelatedPartyExposure, ShellSignature};

fn lapping_harness() -> (Harness, [VId; 2]) {
    let mut h = harness();
    let ctx = h.ctx();
    let role = AccountRoleSpec {
        account: h.account("1200"),
        role: "receivable".into(),
        assigned: true,
    };
    let description = h.seal("native lapping compatibility role");
    h.runtime
        .block_on(record_account_role(
            &mut h.db,
            &ctx,
            &h.book,
            &role,
            PREPARER,
            b"lapping-version-role",
            description,
            &Capability::embedded(PREPARER, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let mut parties = Vec::new();
    for code in ["REPLAY-LAP-A", "REPLAY-LAP-B"] {
        let spec = fa_model::PartySpec {
            code: code.into(),
            kind: fa_model::PartyKind::Counterparty,
            name: h.seal(code),
            identifiers: Vec::new(),
            external_ids: Vec::new(),
        };
        let description = h.seal("native lapping compatibility party");
        h.runtime
            .block_on(create_party(
                &mut h.db,
                &ctx,
                &h.book,
                &spec,
                PREPARER,
                day(2026, 1, 5),
                code.as_bytes(),
                description,
                &Capability::embedded(PREPARER, &["schema_change"]).unwrap(),
            ))
            .unwrap()
            .unwrap();
        parties.push(fa_model::party_value_vid(h.book.book_id, code));
    }
    (h, [parties[0], parties[1]])
}

fn post_lapping_movement(
    h: &mut Harness,
    date: u8,
    debit: &'static str,
    credit: &'static str,
    party: VId,
) -> VId {
    let ctx = h.ctx();
    let mut proposal = h.proposal(&Spec::simple(day(2026, 1, date), debit, credit, 50_000));
    for leg in &mut proposal.legs {
        if leg.account_ref == h.account("1200") {
            leg.dimension_set.push((fa_model::PARTY_DIMENSION, party));
        }
    }
    let request = PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: Capability::embedded(PREPARER, &["post"]).unwrap(),
    };
    let Posted::Committed {
        entry_ref,
        recorded_at,
        ..
    } = h
        .runtime
        .block_on(post(&mut h.db, &ctx, &h.book, request))
        .unwrap()
        .unwrap()
    else {
        panic!("a fresh native lapping movement must commit")
    };
    h.posted.push((entry_ref.vid, recorded_at));
    entry_ref.vid
}

#[test]
fn native_lapping_windows_keep_successful_v2_results_and_version_the_wide_fix() {
    use fa_lantern::cutoff::ReconLapping;

    let (mut h, parties) = lapping_harness();
    let mut entries = Vec::new();
    for (date, debit, credit, party) in [
        (10, "1200", "4000", parties[0]),
        (12, "1000", "1200", parties[1]),
        (15, "1000", "1200", parties[0]),
    ] {
        entries.push(post_lapping_movement(&mut h, date, debit, credit, party));
    }
    let before = h.db.frontier().unwrap();
    let snapshot = h.snapshot();
    let current = run_over(&snapshot, &h.book, &ReconLapping::new().unwrap()).unwrap();
    assert_eq!(current.version, 4);
    assert_eq!(current.findings.len(), 1);
    assert_eq!(current.findings[0].version, 4);
    assert_eq!(current.work.comparisons, 10);
    assert_eq!(current.findings[0].severity, Severity::High);
    assert_eq!(
        current.findings[0].statistic,
        Statistic::count("settlement_delay_days", 5, 3)
    );
    let mut cites = vec![Cite::Account(h.account("1200"))];
    cites.extend(entries.into_iter().map(Cite::Entry));
    assert_eq!(current.findings[0].cites, cites);
    h.assert_cites_resolve(&current);
    for (window, current_count, retained_count) in [
        (2, 0, 0),
        (3, 1, 1),
        (10, 1, 1),
        (2_147_483_647, 1, 1),
        (2_147_483_648, 1, 0),
        (4_294_967_295, 1, 0),
    ] {
        for (version, count) in [(2, retained_count), (3, current_count), (4, current_count)] {
            let procedure = fa_lantern::catalog::build_version(
                ReconLapping::ID,
                version,
                Params::defaults(ReconLapping::ID)
                    .unwrap()
                    .set("window_days", window)
                    .unwrap(),
                fa_lantern::catalog::Inputs::default(),
            )
            .unwrap();
            let result = run_over(&snapshot, &h.book, procedure.as_ref()).unwrap();
            assert_eq!(result.version, version);
            assert_eq!(result.findings.len(), count);
            assert_eq!(result.work.comparisons, if version == 4 { 10 } else { 3 });
            if count == 1 {
                let mut expected = current.findings[0].clone();
                expected.version = version;
                assert_eq!(result.findings, vec![expected]);
            }
            assert!(
                witness::determinism(&snapshot, &h.book, procedure.as_ref())
                    .unwrap()
                    .deterministic()
            );
        }
    }
    for unavailable in [1, 5] {
        assert!(matches!(
            fa_lantern::bind_version(ReconLapping::ID, unavailable),
            Err(LanternError::Version { .. })
        ));
    }
    assert_eq!(
        h.db.frontier().unwrap(),
        before,
        "read-only lapping cannot post"
    );
}

#[test]
fn native_lapping_index_counts_candidates_and_stops_without_partial_findings() {
    use fa_lantern::cutoff::ReconLapping;

    let (mut h, parties) = lapping_harness();
    for _ in 0..16 {
        post_lapping_movement(&mut h, 10, "1200", "4000", parties[0]);
    }
    for _ in 0..16 {
        post_lapping_movement(&mut h, 11, "1000", "1200", parties[1]);
    }
    let before = h.db.frontier().unwrap();
    let unmatched = h.snapshot();
    let build = |version| {
        fa_lantern::catalog::build_version(
            ReconLapping::ID,
            version,
            Params::defaults(ReconLapping::ID).unwrap(),
            fa_lantern::catalog::Inputs::default(),
        )
        .unwrap()
    };
    // These real posted streams used to do 16*16*15/2 unreported k-visits.
    // With no matching A credit, v4 builds the index and skips each invoice.
    for version in [2, 3, 4] {
        let run = run_over(&unmatched, &h.book, build(version).as_ref()).unwrap();
        assert!(run.findings.is_empty());
        assert_eq!(run.work.comparisons, if version == 4 { 64 } else { 32 });
        assert!(
            run.work.within_registered_bound(
                &fa_lantern::bind_version(ReconLapping::ID, version)
                    .unwrap()
                    .complexity,
                &unmatched
            )
        );
    }
    assert_eq!(h.db.frontier().unwrap(), before);

    post_lapping_movement(&mut h, 12, "1000", "1200", parties[0]);
    let before = h.db.frontier().unwrap();
    let snapshot = h.snapshot();
    let current = run_over(&snapshot, &h.book, build(4).as_ref()).unwrap();
    assert_eq!(current.findings.len(), 256);
    assert_eq!(current.work.comparisons, 970);
    assert!(current.work.within_registered_bound(
        &fa_lantern::bind(ReconLapping::ID).unwrap().complexity,
        &snapshot
    ));
    for finding in &current.findings {
        assert_eq!(
            finding.statistic,
            Statistic::count("settlement_delay_days", 2, 33)
        );
    }
    for version in [2, 3] {
        let mut retained = run_over(&snapshot, &h.book, build(version).as_ref()).unwrap();
        assert_eq!(retained.work.comparisons, 33);
        for finding in &mut retained.findings {
            finding.version = 4;
        }
        assert_eq!(retained.findings, current.findings);
    }
    let limited =
        fa_lantern::run_over_metered(&snapshot, &h.book, build(4).as_ref(), Some(1_000), None)
            .unwrap_err();
    assert!(matches!(
        limited,
        LanternError::BudgetExhausted {
            used: 1_001,
            budget: 1_000,
            ..
        }
    ));

    struct CancelAtThird(std::cell::Cell<usize>);
    impl fa_lantern::Cancellation for CancelAtThird {
        fn cancelled(&self) -> bool {
            let checks = self.0.get() + 1;
            self.0.set(checks);
            checks >= 3
        }
    }
    for version in [2, 3, 4] {
        let cancelled = CancelAtThird(std::cell::Cell::new(0));
        let error = fa_lantern::run_over_metered(
            &snapshot,
            &h.book,
            build(version).as_ref(),
            None,
            Some(&cancelled),
        )
        .unwrap_err();
        let LanternError::Cancelled { used, .. } = error else {
            panic!("expected cancellation: {error:?}")
        };
        if version == 4 {
            assert_eq!(used, 1 + fa_lantern::CANCELLATION_INTERVAL);
        } else {
            assert_eq!(used, current.work.entries + current.work.legs + 1);
        }
        assert_eq!(cancelled.0.get(), 3);
    }
    assert!(
        witness::determinism(&snapshot, &h.book, build(4).as_ref())
            .unwrap()
            .deterministic()
    );
    h.assert_cites_resolve(&current);
    assert_eq!(
        h.db.frontier().unwrap(),
        before,
        "bounded/cancelled screens never publish"
    );
}

#[test]
fn native_lookbacks_preserve_full_u32_windows_and_retained_versions() {
    use fa_lantern::cutoff::{LookbackFraudulentTransfer, LookbackPreferences};

    let mut h = harness();
    let ctx = h.ctx();
    let role = AccountRoleSpec {
        account: h.account("1000"),
        role: "cash".into(),
        assigned: true,
    };
    let description = h.seal("native lookback window role");
    h.runtime
        .block_on(record_account_role(
            &mut h.db,
            &ctx,
            &h.book,
            &role,
            PREPARER,
            b"lookback-window-role",
            description,
            &Capability::embedded(PREPARER, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let name = h.seal("native lookback creditor");
    let description = h.seal("native lookback window party");
    let party = fa_model::PartySpec {
        code: "WINDOW-CREDITOR".into(),
        kind: fa_model::PartyKind::Counterparty,
        name,
        identifiers: Vec::new(),
        external_ids: Vec::new(),
    };
    h.runtime
        .block_on(create_party(
            &mut h.db,
            &ctx,
            &h.book,
            &party,
            PREPARER,
            day(2026, 3, 20),
            b"lookback-window-party",
            description,
            &Capability::embedded(PREPARER, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let mut proposal = h.proposal(&Spec::simple(day(2026, 3, 20), "6000", "1000", 100_000));
    let value = fa_model::party_value_vid(h.book.book_id, &party.code);
    for leg in &mut proposal.legs {
        leg.dimension_set.push((fa_model::PARTY_DIMENSION, value));
    }
    let request = PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: Capability::embedded(PREPARER, &["post"]).unwrap(),
    };
    let Posted::Committed {
        entry_ref,
        recorded_at,
        ..
    } = h
        .runtime
        .block_on(post(&mut h.db, &ctx, &h.book, request))
        .unwrap()
        .unwrap()
    else {
        panic!("a fresh native lookback payment must commit")
    };
    h.posted.push((entry_ref.vid, recorded_at));
    let before = h.db.frontier().unwrap();
    let snapshot = h.snapshot();
    for (id, current, retained, windows, statistic) in [
        (
            LookbackPreferences::ID,
            4,
            3,
            ["window_days", "insider_window_days"],
            "net_preference_exposure",
        ),
        (
            LookbackFraudulentTransfer::ID,
            2,
            1,
            ["section_548_days", "uvta_days"],
            "fraudulent_transfer_amount",
        ),
    ] {
        let defaults = Params::defaults(id).unwrap();
        let ordinary = fa_lantern::catalog::build_version(
            id,
            current,
            defaults.clone(),
            fa_lantern::catalog::Inputs::default(),
        )
        .unwrap();
        let normal = run_over(&snapshot, &h.book, ordinary.as_ref()).unwrap();
        assert_eq!(normal.version, current);
        assert_eq!(normal.findings.len(), 1, "{id}");
        let expected = &normal.findings[0];
        assert_eq!(expected.version, current);
        assert_eq!(expected.severity, Severity::High);
        assert_eq!(expected.statistic.name, statistic);
        assert_eq!(expected.statistic.value, 100_000);
        assert_eq!(expected.statistic.scale, 2);
        assert_eq!(expected.statistic.population, 1);
        assert!(expected.cites.contains(&Cite::Entry(entry_ref.vid)));
        for duration in [
            i128::from(i32::MAX),
            i128::from(i32::MAX) + 1,
            i128::from(u32::MAX),
        ] {
            let params = defaults
                .clone()
                .set(windows[0], duration)
                .unwrap()
                .set(windows[1], duration)
                .unwrap();
            for version in [current, retained] {
                let procedure = fa_lantern::catalog::build_version(
                    id,
                    version,
                    params.clone(),
                    fa_lantern::catalog::Inputs::default(),
                )
                .unwrap();
                let result = run_over(&snapshot, &h.book, procedure.as_ref()).unwrap();
                assert_eq!(result.version, version);
                if version == retained && duration > i128::from(i32::MAX) {
                    assert!(result.findings.is_empty(), "{id} v{version}: {duration}");
                } else {
                    let mut finding = expected.clone();
                    finding.version = version;
                    assert_eq!(
                        result.findings,
                        vec![finding],
                        "{id} v{version}: {duration}"
                    );
                }
                assert!(
                    witness::determinism(&snapshot, &h.book, procedure.as_ref())
                        .unwrap()
                        .deterministic()
                );
            }
        }
        for invalid in [-1, 0, i128::from(u32::MAX) + 1] {
            let procedure = fa_lantern::catalog::build_version(
                id,
                current,
                defaults.clone().set(windows[0], invalid).unwrap(),
                fa_lantern::catalog::Inputs::default(),
            )
            .unwrap();
            assert!(matches!(
                run_over(&snapshot, &h.book, procedure.as_ref()),
                Err(LanternError::Parameter { .. })
            ));
        }
        for unavailable in [retained - 1, current + 1] {
            assert!(matches!(
                fa_lantern::bind_version(id, unavailable),
                Err(LanternError::Version { .. })
            ));
        }
    }
    assert_eq!(
        h.db.frontier().unwrap(),
        before,
        "read-only lookbacks cannot post"
    );
}

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
