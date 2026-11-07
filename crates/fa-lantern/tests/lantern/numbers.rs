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
