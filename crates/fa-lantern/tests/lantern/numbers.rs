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
