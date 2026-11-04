//! Reclassification conservation through the independent oracle's public path.

use super::*;

fn leg(side: Side, account: &str, unit: u32, mantissa: i128) -> Leg {
    Leg {
        side,
        account: account.into(),
        unit,
        entity: None,
        mantissa,
    }
}

fn intent(class: &str, legs: Vec<Leg>, key: &str) -> Intent {
    Intent {
        class: class.into(),
        date: DateDay::from_ymd(2026, 3, 15).unwrap(),
        discriminator: None,
        legs,
        key: key.as_bytes().to_vec(),
        ops: vec!["post".into()],
        approvals: 0,
        reverses: None,
        supersession_reason: 1,
        resolves: None,
        settles: Vec::new(),
    }
}

fn fixture(target: Vec<Leg>, entities: &[&str]) -> Oracle {
    let mut oracle = Oracle::new(FiscalCalendar::monthly("cal", 1, 1).unwrap());
    for account in [
        "1000", "1100", "2000", "6000", "6100", "6200", "7000", "7100",
    ] {
        oracle.add_account(Account {
            code: account.into(),
            is_leaf: true,
            unit: None,
        });
    }
    oracle.declare_entities(entities);
    oracle.create_periods(2026);
    oracle
        .transition("FY2026-P03", PeriodTransition::Open)
        .unwrap();
    assert_eq!(
        oracle.post(&intent("Original", target, "target")),
        Verdict::Posted {
            index: 0,
            period: "FY2026-P03".into(),
        }
    );
    oracle
}

#[test]
fn reclassification_refuses_balanced_unrelated_or_cross_unit_destinations_without_recording_a_key()
{
    use Side::{Credit as C, Debit as D};
    let target = || vec![leg(D, "6000", 0, 100), leg(C, "1000", 0, 100)];
    let invalid = [
        vec![
            leg(C, "6000", 0, 1),
            leg(D, "6100", 0, 1),
            leg(D, "6200", 0, 50_000),
            leg(C, "1000", 0, 50_000),
        ],
        vec![
            leg(C, "6000", 0, 40),
            leg(D, "1000", 0, 40),
            leg(D, "6100", 1, 40),
            leg(C, "1100", 1, 40),
        ],
        vec![
            leg(C, "6000", 0, 1),
            leg(D, "6100", 0, 1),
            leg(D, "6200", 1, 50_000),
            leg(C, "1100", 1, 50_000),
        ],
    ];
    for legs in invalid {
        let mut oracle = fixture(target(), &[]);
        let before = oracle.fold("FY2026-P03");
        assert_eq!(
            oracle.reclassify(&intent("Reclassification", legs, "move"), 0),
            Verdict::Refused {
                code: code::RECLASSIFICATION_SHAPE,
            }
        );
        assert_eq!(oracle.journal_len(), 1);
        assert_eq!(oracle.fold("FY2026-P03"), before);

        // The rejected shape consumed neither source amounts nor its key.
        let corrected = intent(
            "Reclassification",
            vec![leg(C, "6000", 0, 40), leg(D, "6100", 0, 40)],
            "move",
        );
        assert_eq!(
            oracle.reclassify(&corrected, 0),
            Verdict::Posted {
                index: 1,
                period: "FY2026-P03".into(),
            }
        );
        assert_eq!(
            oracle.reclassify(&corrected, 0),
            Verdict::Recorded { index: 1 }
        );
    }
}

#[test]
fn reclassification_conserves_split_multi_unit_and_two_sided_moves_with_remaining_limits() {
    use Side::{Credit as C, Debit as D};
    let mut oracle = fixture(
        vec![
            leg(D, "6000", 0, 20),
            leg(D, "6000", 0, 80),
            leg(C, "1000", 0, 100),
            leg(D, "7000", 1, 90),
            leg(C, "2000", 1, 90),
        ],
        &[],
    );
    let movement = intent(
        "Reclassification",
        vec![
            leg(C, "6000", 0, 10),
            leg(C, "6000", 0, 60),
            leg(D, "6100", 0, 20),
            leg(D, "6200", 0, 50),
            leg(D, "1000", 0, 30),
            leg(C, "1100", 0, 30),
            leg(C, "7000", 1, 9),
            leg(D, "7100", 1, 9),
        ],
        "split",
    );
    assert_eq!(
        oracle.reclassify(&movement, 0),
        Verdict::Posted {
            index: 1,
            period: "FY2026-P03".into(),
        }
    );
    let before = oracle.fold("FY2026-P03");
    assert_eq!(
        oracle.reclassify(
            &intent(
                "Reclassification",
                vec![leg(C, "6000", 0, 31), leg(D, "6100", 0, 31)],
                "remaining",
            ),
            0,
        ),
        Verdict::Refused {
            code: code::RECLASSIFICATION_SHAPE,
        }
    );
    assert_eq!(oracle.fold("FY2026-P03"), before);
    assert_eq!(oracle.journal_len(), 2);
    assert_eq!(
        oracle.reclassify(
            &intent(
                "Reclassification",
                vec![leg(C, "6000", 0, 30), leg(D, "6100", 0, 30)],
                "remaining",
            ),
            0,
        ),
        Verdict::Posted {
            index: 2,
            period: "FY2026-P03".into(),
        }
    );
}

#[test]
fn reclassification_moves_both_sides_between_dimensions_without_changing_the_amounts() {
    use Side::{Credit as C, Debit as D};
    let entity = |mut leg: Leg, code: &str| {
        leg.entity = Some(code.into());
        leg
    };
    let mut oracle = fixture(
        vec![
            entity(leg(D, "6000", 0, 100), "A"),
            entity(leg(C, "1000", 0, 100), "A"),
        ],
        &["A", "B"],
    );
    let movement = intent(
        "Reclassification",
        vec![
            entity(leg(C, "6000", 0, 37), "A"),
            entity(leg(D, "6000", 0, 37), "B"),
            entity(leg(D, "1000", 0, 37), "A"),
            entity(leg(C, "1000", 0, 37), "B"),
        ],
        "dimension-move",
    );
    assert_eq!(
        oracle.reclassify(&movement, 0),
        Verdict::Posted {
            index: 1,
            period: "FY2026-P03".into(),
        }
    );
    assert_eq!(
        oracle.reclassify(&movement, 0),
        Verdict::Recorded { index: 1 }
    );
    let before = oracle.fold_by_entity("FY2026-P03");
    let mut back = movement;
    back.key = b"no-dimension-change".to_vec();
    for leg in &mut back.legs {
        leg.entity = Some("A".into());
    }
    assert_eq!(
        oracle.reclassify(&back, 0),
        Verdict::Refused {
            code: code::RECLASSIFICATION_SHAPE,
        }
    );
    assert_eq!(oracle.journal_len(), 2);
    assert_eq!(oracle.fold_by_entity("FY2026-P03"), before);
}
