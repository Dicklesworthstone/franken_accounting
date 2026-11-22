//! Multiyear SUD tests use independent source identities and explicit expected
//! amounts, including the failure that a third engagement previously exposed.

use super::*;

fn accrual(ordinal: u32, amount: i128) -> ProposalView {
    ProposalView {
        vid: VId(u128::from(ordinal)),
        record: VId(100 + u128::from(ordinal)),
        proposal: ProposedAdjustment {
            engagement: "source".into(),
            ordinal,
            effective_date: DateDay(10),
            legs: vec![
                ProposalLeg {
                    side: Side::Debit,
                    account: VId(5),
                    amount: Amount::new(UnitId(1), amount),
                },
                ProposalLeg {
                    side: Side::Credit,
                    account: VId(2),
                    amount: Amount::new(UnitId(1), amount),
                },
            ],
        },
        state: AdjustmentState::Passed,
        proposed_at: CommitSeq(2),
        proposed_by: VId(9),
        decision: Some(RecordedDecision {
            decision: AdjustmentDecision::Pass { reason_code: 3 },
            record: VId(300),
            recorded_at: CommitSeq(3),
            decided_by: VId(9),
            superseded_by: None,
            added_after_completion: false,
        }),
        added_after_completion: false,
    }
}

fn engagement(name: &str, start: i32, mut proposals: Vec<ProposalView>) -> EngagementView {
    let profile = EngagementProfile {
        book_id: Id128([71; 16]),
        engagement: name.into(),
        kind: EngagementKind::Audit,
        firm_principal: VId(9),
        scope_periods: vec![start.to_string()],
        unit: UnitId(1),
        materiality: Materiality {
            overall: 10_000,
            performance: 5_000,
            clearly_trivial: 100,
        },
        report_release_day: None,
        capability_commitment: [3; 32],
    };
    for proposal in &mut proposals {
        proposal.proposal.engagement = name.into();
        proposal.proposal.effective_date = DateDay(start);
    }
    EngagementView {
        vid: profile.vid(),
        profile,
        state: EngagementState::Open,
        opened_at: CommitSeq(1),
        opened_by: VId(9),
        next_proposal: u32::try_from(proposals.len()).unwrap() + 1,
        proposals,
        workpapers: Vec::new(),
        documentation: None,
        carry_forwards: Vec::new(),
        findings: Vec::new(),
    }
}

fn source(view: &EngagementView, ordinal: u32) -> CarryForwardSource {
    CarryForwardSource {
        engagement: view.vid,
        ordinal,
    }
}

fn carry(prior: VId) -> CarryForward {
    CarryForward {
        prior,
        turned_around: Vec::new(),
        corrected: Vec::new(),
        turned_around_sources: Vec::new(),
        corrected_sources: Vec::new(),
    }
}

fn apply_carry(view: &mut EngagementView, carry_forward: CarryForward) {
    view.carry_forwards.push(CarryForwardView {
        carry_forward,
        record: VId(900 + view.carry_forwards.len() as u128),
        recorded_at: CommitSeq(10 + view.carry_forwards.len() as u64),
        recorded_by: VId(9),
        added_after_completion: false,
    });
}

fn chart(account: VId) -> Option<fa_model::AccountType> {
    match account.0 {
        2 => Some(fa_model::AccountType::LIABILITY),
        5 => Some(fa_model::AccountType::EXPENSE),
        _ => None,
    }
}

fn bounds(profile: &EngagementProfile) -> Option<(DateDay, DateDay)> {
    let start: i32 = profile.scope_periods.first()?.parse().ok()?;
    Some((DateDay(start), DateDay(start.checked_add(10)?)))
}

fn chain(
    root: &EngagementView,
    sources: &[EngagementView],
) -> Result<Vec<EngagementView>, KernelError> {
    carry_forward_chain(
        root.clone(),
        |vid| Ok(sources.iter().find(|view| view.vid == vid).cloned()),
        bounds,
    )
}

fn correction(ordinal: u32, amount: i128, date: i32) -> OutOfPeriodCorrection {
    OutOfPeriodCorrection {
        entry: VId(800 + u128::from(ordinal)),
        effective_date: DateDay(date),
        relates_to: PeriodRef {
            calendar: "audit".into(),
            code: "prior".into(),
        },
        legs: accrual(ordinal, amount).proposal.legs,
    }
}

#[test]
fn unresolved_sources_survive_four_periods_without_readding_income_to_equity() {
    let a = engagement("year-a", 10, vec![accrual(1, 1_000), accrual(2, 3_000)]);
    let mut b = engagement("year-b", 20, vec![accrual(1, 2_000)]);
    apply_carry(&mut b, carry(a.vid));
    let mut c = engagement("year-c", 30, Vec::new());
    apply_carry(&mut c, carry(b.vid));
    let mut d = engagement("year-d", 40, Vec::new());
    apply_carry(&mut d, carry(c.vid));
    let sources = [a.clone(), b.clone(), c.clone()];
    let normalized = chain(&d, &sources).unwrap();
    assert_eq!(
        normalized.iter().map(|v| v.vid).collect::<Vec<_>>(),
        [a.vid, b.vid, c.vid, d.vid]
    );
    let expected_sources = BTreeSet::from([source(&a, 1), source(&a, 2), source(&b, 1)]);
    assert_eq!(unresolved_sources(&normalized).unwrap(), expected_sources);
    let mut summary = None;
    for view in &normalized {
        summary = Some(uncorrected_misstatements(view, &[], summary.as_ref(), chart).unwrap());
        if view.vid == c.vid || view.vid == d.vid {
            let summary = summary.as_ref().unwrap();
            assert_eq!(summary.rollover_income, 0);
            assert_eq!(
                summary.iron_curtain,
                StatementEffect {
                    liabilities: 6_000,
                    equity: -6_000,
                    ..StatementEffect::default()
                }
            );
            assert_eq!(
                summary
                    .carried
                    .iter()
                    .map(|item| item.source)
                    .collect::<BTreeSet<_>>(),
                expected_sources
            );
            assert_eq!(
                summary
                    .carried
                    .iter()
                    .filter(|item| item.prior_ordinal == 1)
                    .count(),
                2
            );
            assert_eq!(
                summary
                    .carried
                    .iter()
                    .find(|item| item.source == source(&a, 1))
                    .unwrap()
                    .original_effect
                    .income,
                -1_000
            );
            assert!(summary.exceeds_performance);
            assert!(!summary.exceeds_overall);
        }
    }
}

#[test]
fn third_period_disposes_of_original_sources_and_never_inherits_prior_rollover_corrections() {
    let a = engagement(
        "year-a",
        10,
        vec![accrual(1, 1_000), accrual(2, 3_000), accrual(3, 4_000)],
    );
    let a_summary = uncorrected_misstatements(&a, &[], None, chart).unwrap();
    let mut b = engagement("year-b", 20, vec![accrual(1, 2_000)]);
    let mut into_b = carry(a.vid);
    into_b.corrected.push(3);
    apply_carry(&mut b, into_b);
    let b_summary =
        uncorrected_misstatements(&b, &[correction(3, 4_000, 20)], Some(&a_summary), chart)
            .unwrap();
    assert_eq!(b_summary.rollover_income, 2_000);
    assert_eq!(b_summary.iron_curtain.liabilities, 6_000);

    let mut c = engagement("year-c", 30, Vec::new());
    let mut into_c = carry(b.vid);
    into_c.turned_around.push(1); // B:1, not A:1.
    into_c.turned_around_sources.push(source(&a, 1));
    into_c.corrected_sources.push(source(&a, 2));
    apply_carry(&mut c, into_c);
    let c_summary =
        uncorrected_misstatements(&c, &[correction(2, 3_000, 30)], Some(&b_summary), chart)
            .unwrap();
    assert_eq!(c_summary.rollover_income, 6_000); // 2,000 + original 1,000 + current 3,000.
    assert_eq!(c_summary.iron_curtain, StatementEffect::default());
    assert_eq!(c_summary.carried.len(), 3);
    assert!(
        !c_summary
            .carried
            .iter()
            .any(|item| item.source == source(&a, 3))
    );
    let a1 = c_summary
        .carried
        .iter()
        .find(|item| item.source == source(&a, 1))
        .unwrap();
    assert_eq!(a1.carried, Carried::TurnedAround);
    assert_eq!(a1.effect.income, 1_000);
    assert_eq!(a1.effect.equity, -1_000);
    assert_eq!(a1.original_effect.income, -1_000);

    let mut d = engagement("year-d", 40, Vec::new());
    apply_carry(&mut d, carry(c.vid));
    let d_summary = uncorrected_misstatements(&d, &[], Some(&c_summary), chart).unwrap();
    assert!(d_summary.carried.is_empty());
    assert!(d_summary.out_of_period.is_empty());
    assert_eq!(d_summary.rollover_income, 0);
    assert_eq!(d_summary.iron_curtain, StatementEffect::default());
    assert!(
        unresolved_sources(&chain(&d, &[a, b, c]).unwrap())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn disposition_requires_the_named_prior_summary_and_an_unresolved_source() {
    let a = engagement("year-a", 10, vec![accrual(1, 1_000)]);
    let a_summary = uncorrected_misstatements(&a, &[], None, chart).unwrap();
    let mut b = engagement("year-b", 20, Vec::new());
    let mut into_b = carry(a.vid);
    into_b.turned_around.push(1);
    apply_carry(&mut b, into_b);
    let b_summary = uncorrected_misstatements(&b, &[], Some(&a_summary), chart).unwrap();
    let mut c = engagement("year-c", 30, Vec::new());
    let mut into_c = carry(b.vid);
    into_c.corrected_sources.push(source(&a, 1));
    apply_carry(&mut c, into_c);
    assert!(
        uncorrected_misstatements(&c, &[], Some(&b_summary), chart).is_err(),
        "A:1 already turned around in B"
    );
    assert!(
        uncorrected_misstatements(&c, &[], Some(&a_summary), chart).is_err(),
        "A's summary cannot be substituted for B's"
    );
    assert!(unresolved_sources(&chain(&c, &[a.clone(), b]).unwrap()).is_err());
    let mut bad = a_summary;
    bad.unit = UnitId(2);
    assert!(uncorrected_misstatements(&c, &[], Some(&bad), chart).is_err());
}

#[test]
fn later_ancestor_resolution_requires_a_fresh_descendant_review_without_claiming_corruption() {
    let a = engagement("year-a", 10, vec![accrual(1, 1_000)]);
    let a_summary = uncorrected_misstatements(&a, &[], None, chart).unwrap();
    let mut b = engagement("year-b", 20, Vec::new());
    apply_carry(&mut b, carry(a.vid));
    b.carry_forwards.last_mut().unwrap().recorded_at = CommitSeq(20);
    let original_b = uncorrected_misstatements(&b, &[], Some(&a_summary), chart).unwrap();
    let mut c = engagement("year-c", 30, Vec::new());
    let mut into_c = carry(b.vid);
    into_c.turned_around_sources.push(source(&a, 1));
    apply_carry(&mut c, into_c);
    c.carry_forwards.last_mut().unwrap().recorded_at = CommitSeq(30);
    assert_eq!(
        uncorrected_misstatements(&c, &[], Some(&original_b), chart)
            .unwrap()
            .rollover_income,
        1_000
    );

    // B's later addition changes the source C actually reviewed. The
    // existing immutable C record must not be silently ignored or rewritten.
    let mut revised_b = carry(a.vid);
    revised_b.corrected.push(1);
    apply_carry(&mut b, revised_b);
    b.carry_forwards.last_mut().unwrap().recorded_at = CommitSeq(40);
    let updated_b = uncorrected_misstatements(&b, &[], Some(&a_summary), chart).unwrap();
    assert!(matches!(
        uncorrected_misstatements(&c, &[], Some(&updated_b), chart),
        Err(KernelError::EngagementSourceChanged { engagement, prior, .. })
            if engagement == "year-c" && prior == b.vid
    ));
    assert!(matches!(
        unresolved_sources(&chain(&c, &[a.clone(), b.clone()]).unwrap()),
        Err(KernelError::EngagementSourceChanged { .. })
    ));

    // Unavailable sources are refused without asserting an original valid
    // state, whether the source was resolved earlier or is unknown entirely.
    let mut invalid = c.clone();
    invalid.carry_forwards.last_mut().unwrap().recorded_at = CommitSeq(50);
    assert!(matches!(
        uncorrected_misstatements(&invalid, &[], Some(&updated_b), chart),
        Err(KernelError::EngagementSourceChanged { .. })
    ));
    invalid
        .carry_forwards
        .last_mut()
        .unwrap()
        .carry_forward
        .turned_around_sources[0]
        .engagement = VId(999);
    assert!(matches!(
        uncorrected_misstatements(&invalid, &[], Some(&updated_b), chart),
        Err(KernelError::EngagementSourceChanged { .. })
    ));

    // A fresh review explicitly replaces C's stale disposition. No amount
    // from B's old unresolved summary is left in either method.
    apply_carry(&mut c, carry(b.vid));
    c.carry_forwards.last_mut().unwrap().recorded_at = CommitSeq(50);
    let refreshed = uncorrected_misstatements(&c, &[], Some(&updated_b), chart).unwrap();
    assert!(refreshed.carried.is_empty());
    assert_eq!(refreshed.rollover_income, 0);
    assert_eq!(refreshed.iron_curtain, StatementEffect::default());
    assert!(
        unresolved_sources(&chain(&c, &[a, b]).unwrap())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn reparented_ancestor_refuses_unavailable_descendant_sources_without_returning_amounts() {
    let a = engagement("original-source", 10, vec![accrual(1, 1_000)]);
    let other = engagement("revised-source", 10, vec![accrual(1, 7_000)]);
    let a_summary = uncorrected_misstatements(&a, &[], None, chart).unwrap();
    let mut b = engagement("middle", 20, Vec::new());
    apply_carry(&mut b, carry(a.vid));
    let original_b = uncorrected_misstatements(&b, &[], Some(&a_summary), chart).unwrap();
    let mut c = engagement("current", 30, Vec::new());
    let mut into_c = carry(b.vid);
    into_c.turned_around_sources.push(source(&a, 1));
    apply_carry(&mut c, into_c);
    assert_eq!(
        uncorrected_misstatements(&c, &[], Some(&original_b), chart)
            .unwrap()
            .rollover_income,
        1_000
    );

    apply_carry(&mut b, carry(other.vid));
    let other_summary = uncorrected_misstatements(&other, &[], None, chart).unwrap();
    let revised_b = uncorrected_misstatements(&b, &[], Some(&other_summary), chart).unwrap();
    assert!(matches!(
        uncorrected_misstatements(&c, &[], Some(&revised_b), chart),
        Err(KernelError::EngagementSourceChanged { .. })
    ));
    assert!(matches!(
        unresolved_sources(&chain(&c, &[a, b.clone(), other.clone()]).unwrap()),
        Err(KernelError::EngagementSourceChanged { .. })
    ));
    apply_carry(&mut c, carry(b.vid));
    let refreshed = uncorrected_misstatements(&c, &[], Some(&revised_b), chart).unwrap();
    assert_eq!(refreshed.rollover_income, 0);
    assert_eq!(refreshed.iron_curtain.liabilities, 7_000);
    assert_eq!(refreshed.iron_curtain.equity, -7_000);
    assert_eq!(refreshed.carried[0].source, source(&other, 1));
}

#[test]
fn legacy_carry_bytes_are_unchanged_and_qualified_bytes_round_trip() {
    let mut legacy = carry(VId(51));
    legacy.turned_around = vec![1, 4];
    legacy.corrected = vec![2];
    let mut expected = Writer::new();
    expected.u16(1).u128(51).u32(2).u32(1).u32(4).u32(1).u32(2);
    let expected = expected.finish().unwrap();
    assert_eq!(legacy.canonical_bytes().unwrap(), expected);
    assert_eq!(
        legacy.digest().unwrap(),
        domain_digest(b"fa:engagement-carry-forward:v1", &[&expected])
    );
    assert_eq!(CarryForward::decode(&expected).unwrap(), legacy);
    let mut qualified = legacy.clone();
    qualified.corrected_sources.push(CarryForwardSource {
        engagement: VId(50),
        ordinal: 1,
    });
    let raw = qualified.canonical_bytes().unwrap();
    assert_eq!(&raw[..2], &2u16.to_le_bytes());
    assert_eq!(CarryForward::decode(&raw).unwrap(), qualified);
    assert_ne!(legacy.digest().unwrap(), qualified.digest().unwrap());
    let mut trailing = raw;
    trailing.push(0);
    assert!(CarryForward::decode(&trailing).is_err());
    let mut empty_v2 = expected;
    empty_v2[..2].copy_from_slice(&2u16.to_le_bytes());
    empty_v2.extend_from_slice(&[0; 8]);
    assert!(
        CarryForward::decode(&empty_v2).is_err(),
        "v2 without qualified sources is noncanonical"
    );
}

#[test]
fn qualified_dispositions_refuse_aliases_order_zero_and_the_shared_byte_budget() {
    let mut record = carry(VId(51));
    record.turned_around.push(1);
    for (same_disposition, source) in [
        (
            true,
            CarryForwardSource {
                engagement: VId(51),
                ordinal: 1,
            },
        ),
        (
            false,
            CarryForwardSource {
                engagement: VId(51),
                ordinal: 1,
            },
        ),
        (
            false,
            CarryForwardSource {
                engagement: VId(50),
                ordinal: 0,
            },
        ),
    ] {
        let mut bad = record.clone();
        if same_disposition {
            bad.turned_around_sources.push(source);
        } else {
            bad.corrected_sources.push(source);
        }
        assert!(bad.check().is_err());
        assert!(CarryForward::decode(&bad.canonical_bytes().unwrap()).is_err());
    }
    let older = CarryForwardSource {
        engagement: VId(50),
        ordinal: 1,
    };
    record.turned_around_sources.push(older);
    record.corrected_sources.push(older);
    assert!(record.check().is_err());
    record.corrected_sources.clear();
    record.turned_around_sources.push(older);
    assert!(record.check().is_err());
    record.turned_around_sources = vec![
        CarryForwardSource {
            engagement: VId(50),
            ordinal: 2,
        },
        older,
    ];
    assert!(record.check().is_err());
    let mut oversized = carry(VId(51));
    oversized.corrected_sources = (1..=MAX_CARRIED_ORDINALS)
        .map(|ordinal| CarryForwardSource {
            engagement: VId(50),
            ordinal: u32::try_from(ordinal).unwrap(),
        })
        .collect();
    assert!(oversized.canonical_bytes().unwrap().len() > fa_model::limits::MAX_EXTENSION_BYTES);
    assert!(oversized.check().is_err());
    assert!(CarryForward::decode(&oversized.canonical_bytes().unwrap()).is_err());
}

#[test]
fn ancestry_refuses_cycles_missing_sources_overlapping_scopes_and_mixed_units() {
    let a = engagement("a", 10, vec![accrual(1, 1_000)]);
    let mut b = engagement("b", 20, Vec::new());
    apply_carry(&mut b, carry(a.vid));
    assert!(chain(&b, &[]).is_err());
    let mut cycle = a.clone();
    apply_carry(&mut cycle, carry(b.vid));
    let cycle_error = chain(&b, &[cycle, b.clone()]).unwrap_err();
    assert!(cycle_error.to_string().contains("repeats engagement"));
    let mut overlap = a.clone();
    overlap.profile.scope_periods = vec!["15".into()];
    assert!(chain(&b, &[overlap]).is_err());
    let mut unit = a.clone();
    unit.profile.unit = UnitId(2);
    assert!(chain(&b, &[unit]).is_err());
    let mut identity = a.clone();
    identity.profile.book_id = Id128([72; 16]);
    assert!(chain(&b, &[identity]).is_err());
    let mut absent_period = a.clone();
    absent_period.profile.scope_periods.clear();
    assert!(chain(&b, &[absent_period]).is_err());
    assert!(
        carry_forward_chain(
            b,
            |_| Ok(Some(engagement("impostor", 10, Vec::new()))),
            bounds
        )
        .is_err()
    );
}

#[test]
fn ancestry_depth_is_bounded_before_loading_another_engagement() {
    let mut views: Vec<EngagementView> = Vec::new();
    for i in 0..=MAX_CARRY_FORWARD_DEPTH {
        let mut view = engagement(
            &format!("year-{i}"),
            10 * i32::try_from(i).unwrap(),
            Vec::new(),
        );
        if let Some(prior) = views.last() {
            apply_carry(&mut view, carry(prior.vid));
        }
        views.push(view);
    }
    assert_eq!(
        chain(&views[MAX_CARRY_FORWARD_DEPTH - 1], &views)
            .unwrap()
            .len(),
        MAX_CARRY_FORWARD_DEPTH
    );
    let mut reads = 0;
    let result = carry_forward_chain(
        views[MAX_CARRY_FORWARD_DEPTH].clone(),
        |vid| {
            reads += 1;
            Ok(views.iter().find(|view| view.vid == vid).cloned())
        },
        bounds,
    );
    assert!(result.is_err());
    assert_eq!(reads, MAX_CARRY_FORWARD_DEPTH - 1);
}

#[test]
fn ancestry_total_proposal_budget_includes_every_year() {
    let proposals = |count| {
        (1..=count)
            .map(|ordinal| accrual(u32::try_from(ordinal).unwrap(), 1))
            .collect()
    };
    let a = engagement("a", 10, proposals(MAX_UNCORRECTED_SOURCES / 2));
    let mut b = engagement("b", 20, proposals(MAX_UNCORRECTED_SOURCES / 2 + 1));
    apply_carry(&mut b, carry(a.vid));
    assert!(
        chain(&b, &[a])
            .unwrap_err()
            .to_string()
            .contains("source proposals")
    );
}
