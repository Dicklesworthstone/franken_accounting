//! Law-state regressions. These exercise the production law evaluator;
//! they are not substitutes for the real-journal integration corpus.

use super::*;

const LAWS: [Law; 4] = [Law::Libr, Law::Fifo, Law::Lifo, Law::ProRata];

fn stream(moves: &[(bool, i128)], source_at: usize) -> Stream {
    Stream {
        unit: UnitId(0),
        entity: None,
        moves: moves.iter().enumerate().map(|(i, (inflow, magnitude))| Movement {
            entry: VId(i as u128 + 1),
            date: DateDay(i as i32),
            recorded: i as u64,
            inflow: *inflow,
            magnitude: *magnitude,
        }).collect(),
        source_at,
    }
}

#[test]
fn repeated_clean_turnover_does_not_overflow_an_unused_law_pool() {
    let stream = stream(&[
        (true, 1), (false, 1),
        (true, i128::MAX), (false, i128::MAX),
        (true, i128::MAX), (false, i128::MAX),
    ], 0);
    for law in LAWS {
        let traced = run_law(law, &stream, &mut Work::default()).unwrap();
        assert_eq!(traced.traced, 0, "{law:?}");
        assert_eq!(traced.lowest.0, 0, "{law:?}");
        if law != Law::Libr {
            assert_eq!(traced.carriers.values().sum::<i128>(), 1, "{law:?}");
        }
    }
}

#[test]
fn the_minimum_signed_opening_balance_can_be_repaid_without_negation() {
    let stream = stream(&[
        (false, i128::MAX), (false, 1), // opening = i128::MIN
        (true, 1),                    // claimant repays one unit of debt
        (true, i128::MAX),            // the remainder is repaid, nothing held
    ], 2);
    for law in LAWS {
        let traced = run_law(law, &stream, &mut Work::default()).unwrap();
        assert_eq!(traced.traced, 0, "{law:?}");
        assert_eq!(traced.deposit, 1, "{law:?}");
        assert!(traced.carriers.is_empty(), "{law:?}");
    }
}

#[test]
fn overdrafts_after_the_deposit_do_not_replenish_tainted_money() {
    let stream = stream(&[
        (true, 10), (false, 15), (true, 8), (false, 1),
    ], 0);
    for law in LAWS {
        let traced = run_law(law, &stream, &mut Work::default()).unwrap();
        assert_eq!(traced.traced, 0, "{law:?}");
        assert_eq!(traced.lowest.0, -5, "{law:?}");
    }
}

#[test]
fn named_laws_keep_their_distinct_consumption_orders() {
    let stream = stream(&[
        (true, 3), (true, 10), (false, 5), (true, 4), (false, 6),
    ], 1);
    // Hamilton ties stay on the tainted pool, as in the registered law.
    for (law, expected) in [(Law::Libr, 6), (Law::Fifo, 2), (Law::Lifo, 3), (Law::ProRata, 3)] {
        let traced = run_law(law, &stream, &mut Work::default()).unwrap();
        assert_eq!(traced.traced, expected, "{law:?}");
        assert_eq!(traced.lowest.0, 6, "{law:?}");
    }
}

#[test]
fn unrepresentable_net_magnitude_is_a_typed_error_not_abs_overflow() {
    assert!(Movement::from_net(VId(1), DateDay(0), 1, i128::MIN).is_err());
    let movement = Movement::from_net(VId(1), DateDay(0), 1, -i128::MAX).unwrap();
    assert!(!movement.inflow);
    assert_eq!(movement.magnitude, i128::MAX);
}
