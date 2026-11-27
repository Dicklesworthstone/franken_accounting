//! Native declaration coverage and the retained v2 aggregate screen.
use super::*;
use fa_journal::genesis::LegalEntitySpec;
use fa_lantern::cutoff::ReconIntercompany;
use fa_model::{EntryRef, IntercompanyPair, IntercompanyPairs, Supersession};

fn group() -> Harness {
    harness_with_entities(
        ["A", "B"]
            .into_iter()
            .map(|code| LegalEntitySpec {
                code: code.into(),
                name: code.into(),
                functional_unit: UnitId(0),
            })
            .collect(),
    )
}

fn proposal(h: &mut Harness, date: DateDay, key: Option<&str>) -> EntryPayload {
    let mut spec = Spec::simple(date, "1000", "2000", 100);
    spec.legs = vec![
        ("1000", Side::Debit, 100),
        ("2000", Side::Credit, 100),
        ("4000", Side::Credit, 100),
        ("1200", Side::Debit, 100),
    ];
    let mut proposal = h.proposal(&spec);
    for (leg, code) in proposal.legs.iter_mut().zip(["A", "A", "B", "B"]) {
        leg.dimension_set = vec![(
            fa_model::LEGAL_ENTITY_DIMENSION,
            fa_model::entity_value_vid(h.book.book_id, code),
        )];
    }
    if let Some(key) = key {
        proposal
            .set_intercompany_pairs(&IntercompanyPairs {
                pairs: vec![IntercompanyPair {
                    pair_key: key.into(),
                    left_leg: 1,
                    right_leg: 3,
                }],
            })
            .unwrap();
    }
    proposal
}

fn commit(h: &mut Harness, proposal: EntryPayload) -> EntryRef {
    let request = PostRequest {
        proposal,
        approvals: Vec::new(),
        plan_certificate: None,
        capability: Capability::embedded(PREPARER, &["post"]).unwrap(),
    };
    let ctx = h.ctx();
    let posted = h
        .runtime
        .block_on(post(&mut h.db, &ctx, &h.book, request))
        .unwrap()
        .unwrap();
    let reference = posted.entry_ref();
    h.posted.push((reference.vid, posted.recorded_at()));
    reference
}

fn reverse(h: &mut Harness, target: EntryRef, date: DateDay) -> EntryRef {
    let (original, _) = read_entry(&h.db, target.vid).unwrap().unwrap();
    let mut reversal = original.proposal.clone();
    h.next_key += 1;
    reversal.idempotency_key = h.next_key.to_le_bytes().to_vec();
    reversal.class = EntryClass::REVERSAL;
    reversal.effective_date = date;
    reversal.description = h.seal("exact intercompany reversal");
    reversal.supersession = vec![Supersession {
        target,
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    }];
    for leg in &mut reversal.legs {
        leg.side = leg.side.flipped();
        leg.settles.clear();
    }
    reversal.unit_totals = EntryPayload::fold_unit_totals(&reversal.legs).unwrap();
    commit(h, reversal)
}

fn run(snapshot: &Snapshot, h: &Harness) -> ProcedureRun {
    run_over(snapshot, &h.book, &ReconIntercompany::new().unwrap()).unwrap()
}

#[test]
fn declared_pairs_need_no_roles_and_unrelated_zero_net_legs_remain_uncovered() {
    let mut h = group();
    let paired = proposal(&mut h, day(2026, 3, 1), Some("declared"));
    let paired = commit(&mut h, paired);
    let without_roles = h.snapshot();
    assert!(run(&without_roles, &h).findings.is_empty());
    assert!(
        determinism(&without_roles, &h.book, &ReconIntercompany::new().unwrap())
            .unwrap()
            .deterministic()
    );
    h.assign_role("2000", "intercompany");
    h.assign_role("1200", "intercompany");
    let before_uncovered = h.db.frontier().unwrap();
    let uncovered = proposal(&mut h, day(2026, 3, 2), None);
    let uncovered = commit(&mut h, uncovered);
    let snapshot = h.snapshot();
    let result = run(&snapshot, &h);
    assert_eq!(result.version, 3);
    assert_eq!(result.findings.len(), 2);
    for finding in &result.findings {
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(
            finding.statistic,
            Statistic {
                name: "intercompany_undeclared".into(),
                value: 100,
                scale: 2,
                population: 4,
            }
        );
        assert!(finding.cites.contains(&Cite::Entry(uncovered.vid)));
        assert!(!finding.cites.contains(&Cite::Entry(paired.vid)));
        assert!(finding.cites.iter().any(|cite| matches!(
            cite,
            Cite::Leg { entry, ordinal: 1 | 3 } if *entry == uncovered.vid
        )));
    }
    h.assert_cites_resolve(&result);
    let past = Snapshot::read(
        &h.db,
        &h.ctx().query(),
        &h.book,
        Some(before_uncovered),
        Some(day(2026, 4, 30)),
    )
    .unwrap();
    assert!(run(&past, &h).findings.is_empty());

    // Historical v2 has exactly its old zero-net answer and work transcript.
    let legacy = fa_lantern::catalog::build_version(
        ReconIntercompany::ID,
        2,
        Params::defaults(ReconIntercompany::ID).unwrap(),
        Default::default(),
    )
    .unwrap();
    let old = run_over(&snapshot, &h.book, legacy.as_ref()).unwrap();
    assert_eq!(old.version, 2);
    assert!(old.findings.is_empty());
    assert_eq!(old.work.entries, 2);
    assert_eq!(old.work.legs, 8);
    assert_eq!(old.work.comparisons, 1);

    // Every inspected prefix row/leg and candidate visit is charged.
    let entries = u64::try_from(snapshot.entries.len()).unwrap();
    let legs: u64 = snapshot
        .entries
        .iter()
        .map(|entry| u64::try_from(entry.entry.proposal.legs.len()).unwrap())
        .sum();
    assert_eq!(result.work.entries, entries);
    assert_eq!(result.work.legs, legs);
    assert_eq!(result.work.comparisons, entries + 1 + 2 + 8);
    assert!(
        result
            .work
            .within_registered_bound("O(legs log legs)", &snapshot)
    );
    assert!(matches!(
        fa_lantern::run_over_metered(
            &snapshot,
            &h.book,
            &ReconIntercompany::new().unwrap(),
            Some(result.work.total() - 1),
            None,
        ),
        Err(LanternError::BudgetExhausted { .. })
    ));
}

#[test]
fn partial_pair_coverage_does_not_hide_other_legs_or_count_covered_roles_twice() {
    let mut h = group();
    h.assign_role("2000", "intercompany");
    h.assign_role("1200", "intercompany");
    let mut entry = proposal(&mut h, day(2026, 3, 1), Some("partial"));
    for (account, side) in [("1200", Side::Debit), ("2000", Side::Credit)] {
        let mut leg = LegPayload::simple(side, h.account(account), Amount::new(h.usd, 50));
        leg.dimension_set = vec![(
            fa_model::LEGAL_ENTITY_DIMENSION,
            fa_model::entity_value_vid(h.book.book_id, "A"),
        )];
        entry.legs.push(leg);
    }
    entry.unit_totals = EntryPayload::fold_unit_totals(&entry.legs).unwrap();
    let reference = commit(&mut h, entry);
    let snapshot = h.snapshot();
    let result = run(&snapshot, &h);
    assert_eq!(result.findings.len(), 2);
    for finding in &result.findings {
        assert_eq!(finding.statistic.population, 4);
        assert_eq!(finding.statistic.value, 50);
        assert!(finding.cites.iter().any(|cite| matches!(
            cite,
            Cite::Leg { entry, ordinal: 4 | 5 } if *entry == reference.vid
        )));
    }
    assert!(
        determinism(&snapshot, &h.book, &ReconIntercompany::new().unwrap())
            .unwrap()
            .deterministic()
    );
}

#[test]
fn intercompany_activity_roles_require_declared_pairs_too() {
    let mut h = group();
    h.assign_role("4000", "intercompany_activity");
    h.assign_role("6000", "intercompany_activity");
    let mut entry = proposal(&mut h, day(2026, 3, 1), None);
    entry.legs[0].account_ref = h.account("1200");
    entry.legs[1].account_ref = h.account("4000");
    entry.legs[2].account_ref = h.account("1000");
    entry.legs[3].account_ref = h.account("6000");
    let reference = commit(&mut h, entry);
    let snapshot = h.snapshot();
    let result = run(&snapshot, &h);
    assert_eq!(result.findings.len(), 2);
    assert!(result.findings.iter().all(|finding| {
        finding.statistic.population == 2
            && finding.statistic.value == 100
            && finding.cites.contains(&Cite::Entry(reference.vid))
    }));
    let legacy = fa_lantern::catalog::build_version(
        ReconIntercompany::ID,
        2,
        Params::defaults(ReconIntercompany::ID).unwrap(),
        Default::default(),
    )
    .unwrap();
    assert!(matches!(
        run_over(&snapshot, &h.book, legacy.as_ref()),
        Err(LanternError::RoleUnassigned { role, .. }) if role == "intercompany"
    ));
}

#[test]
fn declaration_cutoff_precedes_reversal_liveness_and_restoration() {
    let mut h = group();
    let entry = proposal(&mut h, day(2026, 3, 15), Some("lasting-key"));
    let original = commit(&mut h, entry);
    let reversal = reverse(&mut h, original, day(2026, 4, 1));
    let mut snapshot = h.snapshot();
    // The declared population exists even when its entire effect is reversed.
    let canceled = run(&snapshot, &h);
    assert!(canceled.findings.is_empty());
    let entries = u64::try_from(snapshot.entries.len()).unwrap();
    assert_eq!(canceled.work.comparisons, entries + 2 + 4 + 4);
    snapshot.coordinate.effective_through = Some(day(2026, 3, 31));
    let earlier = run(&snapshot, &h);
    assert!(earlier.findings.is_empty());
    assert_eq!(earlier.work.comparisons, entries + 2 + 4 + 4 + 4);
    snapshot.coordinate.effective_through = Some(day(2026, 3, 1));
    let missing_population =
        run_over(&snapshot, &h.book, &ReconIntercompany::new().unwrap()).unwrap_err();
    assert!(matches!(
        &missing_population,
        LanternError::RoleUnassigned { .. }
    ));
    let fix = missing_population.fix_hint().unwrap();
    assert!(fix.contains("fa chart role <account> intercompany_activity"));
    assert!(!fix.contains("fa chart role <account> intercompany or"));

    reverse(&mut h, reversal, day(2026, 4, 10));
    let restored = h.snapshot();
    let result = run(&restored, &h);
    assert!(result.findings.is_empty());
    let entries = u64::try_from(restored.entries.len()).unwrap();
    assert_eq!(result.work.comparisons, entries + 3 + 8 + 6 + 4);
    assert!(
        determinism(&restored, &h.book, &ReconIntercompany::new().unwrap())
            .unwrap()
            .deterministic()
    );
}

#[test]
fn invalid_pair_history_refuses_instead_of_returning_a_clean_reconciliation() {
    let mut h = group();
    let entry = proposal(&mut h, day(2026, 3, 15), Some("immutable-key"));
    let original = commit(&mut h, entry);
    let reversal = reverse(&mut h, original, day(2026, 4, 1));
    let snapshot = h.snapshot();
    let original_index = snapshot
        .entries
        .iter()
        .position(|entry| entry.vid == original.vid)
        .unwrap();
    let reversal_index = snapshot
        .entries
        .iter()
        .position(|entry| entry.vid == reversal.vid)
        .unwrap();
    for plant in 0..11 {
        let mut altered = snapshot.clone();
        match plant {
            0 => {
                // A key remains spent even after its original was reversed.
                let mut duplicate = altered.entries[original_index].clone();
                duplicate.vid = VId(u128::MAX);
                altered.entries.push(duplicate);
            }
            1 => {
                altered.entries[original_index].entry.proposal.legs[3]
                    .amount
                    .mantissa = 101;
            }
            2 => {
                altered.entries[original_index].entry.proposal.legs[3].dimension_set =
                    altered.entries[original_index].entry.proposal.legs[1]
                        .dimension_set
                        .clone();
            }
            3 => {
                altered.entries[reversal_index]
                    .entry
                    .proposal
                    .extensions
                    .retain(|(tag, _)| *tag != fa_model::entry::INTERCOMPANY_PAIRS_EXTENSION);
            }
            4 => {
                let declaration = IntercompanyPairs {
                    pairs: vec![IntercompanyPair {
                        pair_key: "changed-key".into(),
                        left_leg: 1,
                        right_leg: 3,
                    }],
                };
                altered.entries[reversal_index]
                    .entry
                    .proposal
                    .set_intercompany_pairs(&declaration)
                    .unwrap();
            }
            5 => {
                altered.entries[reversal_index].entry.proposal.legs[0].account_ref =
                    h.account("1010");
            }
            6 => {
                // The reciprocal endpoints are intact; a counterleg has
                // lost the legal entity required by the whole-entry law.
                altered.entries[original_index].entry.proposal.legs[0]
                    .dimension_set
                    .clear();
            }
            7 => {
                altered.entries[original_index].entry.proposal.legs[0].dimension_set[0].1 =
                    VId(u128::MAX);
            }
            8 => {
                altered.entries[original_index].entry.proposal.legs[0]
                    .amount
                    .mantissa = -1;
            }
            9 => {
                altered.entries[original_index].entry.proposal.legs[0]
                    .amount
                    .mantissa = 101;
            }
            _ => {
                let dimensions = altered.entries[original_index].entry.proposal.legs[0]
                    .dimension_set
                    .clone();
                for (account, side) in [("1000", Side::Debit), ("2000", Side::Credit)] {
                    let mut leg =
                        LegPayload::simple(side, h.account(account), Amount::new(h.usd, i128::MAX));
                    leg.dimension_set = dimensions.clone();
                    altered.entries[original_index]
                        .entry
                        .proposal
                        .legs
                        .push(leg);
                }
            }
        }
        // The malformed record need not be in the effective window to fail.
        altered.coordinate.effective_through = Some(day(2026, 3, 1));
        assert!(
            matches!(
                run_over(&altered, &h.book, &ReconIntercompany::new().unwrap()),
                Err(LanternError::Kernel(KernelError::Corrupt(_)))
            ),
            "plant {plant} must refuse the full run"
        );
    }
}
