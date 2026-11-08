//! fa-m35p: `numbers.round_amount_density` (plan §11.3) flags the account
//! whose share of round legs stands out from the book's own share, and leaves
//! alone the accounts at or below it.

use super::*;

fn with(name: &str, value: i128) -> RoundAmountDensity {
    RoundAmountDensity::with(
        Params::defaults(RoundAmountDensity::ID)
            .unwrap()
            .set(name, value)
            .unwrap(),
    )
}

#[test]
fn threshold_splitting_accepts_u32_windows_and_widens_day_subtraction() {
    use fa_lantern::numbers::ThresholdSplitting;

    let mut h = harness();
    let a = h.post(&Spec::simple(day(2026, 1, 10), "6000", "1000", 900_000));
    let b = h.post(&Spec::simple(day(2026, 1, 11), "6000", "1000", 900_000));
    let before = h.db.frontier().unwrap();
    let snapshot = h.snapshot();
    let procedure = |window| {
        ThresholdSplitting::with(
            Params::defaults(ThresholdSplitting::ID)
                .unwrap()
                .set("window_days", window)
                .unwrap(),
        )
    };
    let mut entries = [a, b];
    entries.sort_unstable();
    let cites: Vec<_> = entries.into_iter().map(Cite::Entry).collect();
    for (window, expected) in [(0, false), (1, true), (4_294_967_295, true)] {
        let result = run_over(&snapshot, &h.book, &procedure(window)).unwrap();
        assert_eq!(result.findings.len(), usize::from(expected));
        if expected {
            assert_eq!(result.findings[0].cites, cites);
            assert_eq!(result.findings[0].severity, Severity::High);
            assert_eq!(
                result.findings[0].statistic,
                Statistic {
                    name: "split_total".into(),
                    value: 1_800_000,
                    scale: 2,
                    population: 2
                }
            );
        }
    }
    for invalid in [-1, 4_294_967_296] {
        assert!(matches!(
            run_over(&snapshot, &h.book, &procedure(invalid)),
            Err(LanternError::Parameter { .. })
        ));
    }
    assert!(
        determinism(&snapshot, &h.book, &procedure(4_294_967_295))
            .unwrap()
            .deterministic()
    );

    // Arithmetic-only variants of the native pair above, with authentic
    // recorded sequences and no claim of extreme-date posting admission.
    let mut wide = snapshot.clone();
    wide.coordinate.effective_through = None;
    for entry in &mut wide.entries {
        if entry.vid == a {
            entry.entry.proposal.effective_date = DateDay(i32::MIN);
        } else if entry.vid == b {
            entry.entry.proposal.effective_date = DateDay(i32::MAX);
        }
    }
    let result = run_over(&wide, &h.book, &procedure(4_294_967_295)).unwrap();
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].cites, cites);
    assert_eq!(result.findings[0].statistic.value, 1_800_000);
    assert!(
        run_over(&wide, &h.book, &procedure(4_294_967_294))
            .unwrap()
            .findings
            .is_empty()
    );
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn threshold_splitting_preserves_greedy_windows_and_exact_work() {
    use fa_lantern::numbers::ThresholdSplitting;

    let mut h = harness();
    let entries: Vec<_> = [
        (1, 1),
        (2, 4),
        (3, 4),
        (4, 4),
        (6, 2),
        (7, 3),
        (8, 6),
        (9, 3),
    ]
    .into_iter()
    .map(|(date, amount)| h.post(&Spec::simple(day(2026, 1, date), "6000", "1000", amount)))
    .collect();
    let before = h.db.frontier().unwrap();
    let snapshot = h.snapshot();
    let procedure = ThresholdSplitting::with(
        Params::defaults(ThresholdSplitting::ID)
            .unwrap()
            .set("floor", 1)
            .unwrap()
            .set("threshold", 10)
            .unwrap()
            .set("window_days", 2)
            .unwrap(),
    );
    let result = run_over(&snapshot, &h.book, &procedure).unwrap();
    assert_eq!(result.version, 1);
    assert_eq!(result.findings.len(), 2);
    // The first window totals only 9. Advancing one anchor then takes the
    // ENTIRE next window, followed by a disjoint full-window group.
    for (finding, (members, total)) in result
        .findings
        .iter()
        .zip([(&entries[1..4], 12), (&entries[4..7], 11)])
    {
        let mut members = members.to_vec();
        members.sort_unstable();
        assert_eq!(
            finding.cites,
            members.into_iter().map(Cite::Entry).collect::<Vec<_>>()
        );
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.version, 1);
        assert_eq!(
            finding.statistic,
            Statistic {
                name: "split_total".into(),
                value: total,
                scale: 2,
                population: 8,
            }
        );
    }
    assert_eq!(
        result.work,
        fa_lantern::Work {
            entries: 8,
            legs: 16,
            comparisons: 8,
        }
    );
    assert_eq!(
        fa_lantern::run_over_metered(&snapshot, &h.book, &procedure, Some(32), None).unwrap(),
        result,
        "the historical exact work budget retains the full output"
    );
    assert!(matches!(
        fa_lantern::run_over_metered(&snapshot, &h.book, &procedure, Some(31), None),
        Err(LanternError::BudgetExhausted {
            used: 32,
            budget: 31,
            ..
        })
    ));
    h.assert_cites_resolve(&result);
    assert!(
        determinism(&snapshot, &h.book, &procedure)
            .unwrap()
            .deterministic()
    );
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn threshold_splitting_refuses_overflow_and_cancels_unmatched_windows() {
    use fa_lantern::numbers::ThresholdSplitting;

    let mut h = harness();
    let entries: Vec<_> = (0..64)
        .map(|_| h.post(&Spec::simple(day(2026, 1, 10), "6000", "1000", 1)))
        .collect();
    let before = h.db.frontier().unwrap();
    let snapshot = h.snapshot();
    let params = Params::defaults(ThresholdSplitting::ID)
        .unwrap()
        .set("floor", 1)
        .unwrap();
    let procedure = ThresholdSplitting::with(params.clone());
    struct Polls {
        count: std::cell::Cell<usize>,
        cancel_at: Option<usize>,
    }
    impl fa_lantern::Cancellation for Polls {
        fn cancelled(&self) -> bool {
            let count = self.count.get() + 1;
            self.count.set(count);
            self.cancel_at.is_some_and(|limit| count >= limit)
        }
    }
    // The same native population and bulk work, but no window search. This
    // measures runner boundary checks rather than guessing their number.
    let baseline = Polls {
        count: std::cell::Cell::new(0),
        cancel_at: None,
    };
    let skipped = ThresholdSplitting::with(params.clone().set("min_count", 65).unwrap());
    let skipped =
        fa_lantern::run_over_metered(&snapshot, &h.book, &skipped, None, Some(&baseline)).unwrap();
    assert!(skipped.findings.is_empty());
    assert_eq!(
        skipped.work,
        fa_lantern::Work {
            entries: 64,
            legs: 128,
            comparisons: 64
        }
    );
    assert_eq!(baseline.count.get(), 4);
    let polls = Polls {
        count: std::cell::Cell::new(0),
        cancel_at: None,
    };
    let result =
        fa_lantern::run_over_metered(&snapshot, &h.book, &procedure, None, Some(&polls)).unwrap();
    assert!(result.findings.is_empty());
    assert_eq!(result.work, skipped.work);
    assert!(polls.count.get() > baseline.count.get());
    assert!(polls.count.get() <= baseline.count.get() + 2 * entries.len());
    let cancelled = Polls {
        count: std::cell::Cell::new(0),
        cancel_at: Some(baseline.count.get() + 1),
    };
    let error =
        fa_lantern::run_over_metered(&snapshot, &h.book, &procedure, None, Some(&cancelled))
            .unwrap_err();
    assert!(matches!(error, LanternError::Cancelled { used: 256, .. }));
    assert_eq!(cancelled.count.get(), baseline.count.get() + 1);

    // Arithmetic-only variants of genuine postings, not a claim that the
    // kernel admits these extreme cumulative balances. Separate windows
    // must not overflow merely because a whole-series prefix sum would.
    let mut extreme = snapshot.clone();
    extreme
        .entries
        .retain(|entry| entries[..2].contains(&entry.vid));
    for entry in &mut extreme.entries {
        let proposal = &mut entry.entry.proposal;
        for leg in &mut proposal.legs {
            leg.amount.mantissa = i128::MAX - 1;
        }
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        proposal.effective_date = if entry.vid == entries[0] {
            day(2026, 1, 10)
        } else {
            day(2026, 1, 20)
        };
    }
    let procedure = ThresholdSplitting::with(params.set("threshold", i128::MAX).unwrap());
    assert!(
        run_over(&extreme, &h.book, &procedure)
            .unwrap()
            .findings
            .is_empty()
    );
    for entry in &mut extreme.entries {
        entry.entry.proposal.effective_date = day(2026, 1, 10);
    }
    assert!(matches!(
        run_over(&extreme, &h.book, &procedure),
        Err(LanternError::Overflow("split window sum"))
    ));
    assert_eq!(h.db.frontier().unwrap(), before);
}

#[test]
fn round_amount_density_flags_the_account_whose_round_share_stands_out() {
    let mut h = harness();
    // Rent: 10 of its 20 legs are multiples of 100.00. Utilities: 2 of 40.
    // Cash takes the other side of all 60, so 12 of its 60 are round. The
    // book is 24 round legs of 120.
    let mut rent_round = Vec::new();
    for i in 0..20u8 {
        let cents = if i % 2 == 0 { 50_000 } else { 12_345 };
        let vid = h.post(&Spec::simple(day(2026, 1, 1 + i), "6000", "1000", cents));
        if cents == 50_000 {
            rent_round.push(vid);
        }
    }
    for i in 0..40u8 {
        let cents = if i < 2 { 30_000 } else { 4_567 };
        h.post(&Spec::simple(
            day(2026, 2, 1 + i % 28),
            "7000",
            "1000",
            cents,
        ));
    }
    let snapshot = h.snapshot();
    let procedure = RoundAmountDensity::new().unwrap();
    let r = run_over(&snapshot, &h.book, &procedure).unwrap();
    h.assert_cites_resolve(&r);
    println!("round density findings={:?}", r.findings);
    // Rent: z^2 = (10*120 - 20*24)^2 / (20*24*96) = 11.25 >= 9. Utilities is
    // below the book's rate and cash is exactly at it.
    assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
    let f = &r.findings[0];
    assert_eq!(f.severity, Severity::Medium, "z^2 11.25 is under 4 * 9");
    assert_eq!(f.statistic, Statistic::count("round_legs", 10, 20));
    assert_eq!(f.cites[0], Cite::Account(h.account("6000")));
    let cited: Vec<VId> = f.cites[1..]
        .iter()
        .map(|c| match c {
            Cite::Leg { entry, .. } => *entry,
            other => panic!("a round rent leg, got {other:?}"),
        })
        .collect();
    assert_eq!(cited, rent_round, "the round rent legs, in recorded order");
    assert!(f.narrative.contains("against 24 of 120"), "{}", f.narrative);
    let row = fa_lantern::bind(RoundAmountDensity::ID).unwrap();
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

    // The threshold is exact: 11.25 clears 11 and not 12.
    let at = run_over(&snapshot, &h.book, &with("z_squared", 11)).unwrap();
    assert_eq!(at.findings.len(), 1, "{:?}", at.findings);
    let above = run_over(&snapshot, &h.book, &with("z_squared", 12)).unwrap();
    assert!(above.findings.is_empty(), "{:?}", above.findings);
    // At z^2 = 2 the excess is more than four times the threshold: High.
    let high = run_over(&snapshot, &h.book, &with("z_squared", 2)).unwrap();
    assert_eq!(high.findings.len(), 1, "{:?}", high.findings);
    assert_eq!(high.findings[0].severity, Severity::High);
    // An account below min_legs is not tested at all.
    let sparse = run_over(&snapshot, &h.book, &with("min_legs", 21)).unwrap();
    assert!(sparse.findings.is_empty(), "{:?}", sparse.findings);
    // Out-of-range parameters are refused, never clamped.
    for (name, value) in [("z_squared", 0), ("round_power", 31)] {
        let refused = run_over(&snapshot, &h.book, &with(name, value));
        assert!(
            matches!(&refused, Err(LanternError::Parameter { name: n, .. }) if n == name),
            "{name}={value}: {refused:?}"
        );
    }
}
