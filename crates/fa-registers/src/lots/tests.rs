use super::*;
use crate::open_items::Application;

fn item(
    entry: u128,
    ordinal: u16,
    unit: u32,
    original: i128,
    applications: Vec<Application>,
) -> OpenItem {
    let applied = applications
        .iter()
        .filter(|application| application.live)
        .try_fold(0i128, |sum, application| {
            sum.checked_add(application.amount)
        })
        .unwrap();
    OpenItem {
        entry: VId(entry),
        ordinal,
        account: VId(100),
        unit_id: unit,
        side: Side::Debit,
        effective_date: DateDay(1),
        recorded_at: CommitSeq(1),
        original,
        applied,
        applied_out: 0,
        open: original.checked_sub(applied).unwrap(),
        applications,
    }
}

fn application(entry: u128, ordinal: u16, amount: i128, live: bool) -> Application {
    Application {
        entry: VId(entry),
        ordinal,
        amount,
        recorded_at: CommitSeq(10),
        live,
    }
}

fn historical_report() -> LotsReport {
    // The earlier sale relieved ten quantity units and 60 cost units from
    // lot 1. Its remaining 40 cost units are still part of the WAC pool.
    let items = vec![
        item(1, 0, 2, 10, vec![application(10, 1, 10, true)]),
        item(1, 2, 1, 100, vec![application(10, 3, 60, true)]),
        item(2, 0, 2, 10, vec![]),
        item(2, 2, 1, 20, vec![]),
        // A different quantity unit shares this AnyUnit account but has its
        // own cost pool, even though the cost unit is the same.
        item(3, 0, 3, 10, vec![]),
        item(3, 2, 1, 1_000, vec![]),
    ];
    let digests = BTreeMap::from([(VId(1), [1; 32]), (VId(2), [2; 32]), (VId(3), [3; 32])]);
    LotsReport {
        book_id: Id128([1; 16]),
        known_at: CommitSeq(10),
        effective_through: None,
        account: VId(100),
        account_code: "inventory".into(),
        account_name: "Inventory".into(),
        base_unit: UnitId(1),
        dimensioned: false,
        lots: fold_lots_from_open_items(&items, &digests, UnitId(1)).unwrap(),
    }
}

#[test]
fn weighted_average_planner_keeps_residual_cost_and_independent_settlement_vectors() {
    let report = historical_report();
    let plan = report
        .plan_disposal(&LotDisposalRequest {
            quantity: Amount::new(UnitId(2), 10),
            dimensions: Vec::new(),
            law: LotLaw::WeightedAverage,
            regime: AccountingRegime::Ifrs,
            rounding_law: RoundingLaw::HalfEven,
            targets: vec![],
        })
        .unwrap();
    assert_eq!(plan.total_cost, Amount::new(UnitId(1), 60));
    let quantity = plan.quantity_settlements();
    assert_eq!(quantity.len(), 1);
    assert_eq!(quantity[0].target.vid, VId(2));
    assert_eq!(quantity[0].amount.mantissa, 10);
    let cost = plan.cost_settlements();
    assert_eq!(cost.len(), 2);
    assert_eq!((cost[0].target.vid, cost[0].amount.mantissa), (VId(1), 40));
    assert_eq!((cost[1].target.vid, cost[1].amount.mantissa), (VId(2), 20));
    assert_eq!(plan.slices[0].quantity_relieved.mantissa, 0);
    assert!(plan.slices.iter().all(
        |slice| slice.open_quantity_after.mantissa == 0 && slice.open_cost_after.mantissa == 0
    ));
}

#[test]
fn switching_away_from_pooled_cost_cannot_hide_the_residual_layer() {
    let result = historical_report().plan_disposal(&LotDisposalRequest {
        quantity: Amount::new(UnitId(2), 10),
        dimensions: Vec::new(),
        law: LotLaw::Fifo,
        regime: AccountingRegime::UsGaap,
        rounding_law: RoundingLaw::HalfEven,
        targets: vec![],
    });
    assert!(matches!(result, Err(LotError::InvalidCandidate(_))));
}

#[test]
fn cost_only_relief_and_its_reversal_remain_visible_in_the_lot_history() {
    for live in [true, false] {
        let items = vec![
            item(1, 0, 2, 10, vec![application(10, 1, 10, true)]),
            item(
                1,
                2,
                1,
                100,
                vec![application(10, 3, 60, true), application(20, 3, 40, live)],
            ),
        ];
        let digests = BTreeMap::from([(VId(1), [1; 32])]);
        let lots = fold_lots_from_open_items(&items, &digests, UnitId(1)).unwrap();
        assert_eq!(lots.len(), 1);
        assert_eq!(lots[0].open_quantity.mantissa, 0);
        assert_eq!(lots[0].open_cost.mantissa, if live { 0 } else { 40 });
        assert_eq!(lots[0].relieves.len(), 2);
        assert_eq!(lots[0].relieves[0].qty_ordinal, Some(1));
        let cost_only = &lots[0].relieves[1];
        assert_eq!(cost_only.disposal_entry, VId(20));
        assert_eq!(cost_only.qty_ordinal, None);
        assert_eq!(cost_only.cost_ordinal, Some(3));
        assert_eq!(cost_only.quantity.mantissa, 0);
        assert_eq!(cost_only.cost.mantissa, 40);
        assert_eq!(cost_only.live, live);
    }
}

#[test]
fn lot_partitions_pair_reordered_costs_and_plan_only_the_complete_dimension_set() {
    let north = vec![(1, VId(11)), (2, VId(21))];
    let south = vec![(1, VId(12)), (2, VId(22))];
    let items = vec![
        item(1, 0, 2, 10, vec![]),
        item(1, 1, 2, 10, vec![]),
        // Cost ordinals deliberately cross the quantity ordering.
        item(1, 2, 1, 20, vec![]),
        item(1, 3, 1, 100, vec![]),
    ];
    let digests = BTreeMap::from([(VId(1), [1; 32])]);
    let dimensions = BTreeMap::from([
        ((VId(1), 0), north.clone()),
        ((VId(1), 1), south.clone()),
        ((VId(1), 2), south.clone()),
        ((VId(1), 3), north.clone()),
    ]);
    let lots = fold_lots_from_open_items_with_dimensions(&items, &digests, UnitId(1), &dimensions)
        .unwrap();
    assert_eq!(lots.len(), 2);
    assert_eq!((lots[0].qty_ordinal, lots[0].cost_ordinal), (0, 3));
    assert_eq!((lots[1].qty_ordinal, lots[1].cost_ordinal), (1, 2));
    assert_eq!(lots[0].dimensions, north);
    assert_eq!(lots[1].dimensions, south);
    let mut report = historical_report();
    report.lots = lots;
    report.dimensioned = true;
    for (partition, expected) in [(north.clone(), 60), (south.clone(), 12)] {
        for law in [LotLaw::Fifo, LotLaw::WeightedAverage] {
            let request = LotDisposalRequest {
                quantity: Amount::new(UnitId(2), 6),
                dimensions: partition.clone(),
                law,
                regime: AccountingRegime::UsGaap,
                rounding_law: RoundingLaw::HalfEven,
                targets: vec![],
            };
            let plan = report.plan_disposal(&request).unwrap();
            assert_eq!(plan.total_cost, Amount::new(UnitId(1), expected));
            assert_eq!(plan.dimensions, partition);
            let mut partial = request.clone();
            partial.dimensions.truncate(1);
            assert!(report.plan_disposal(&partial).is_err());
            let mut over = request;
            over.quantity.mantissa = 11;
            assert!(matches!(
                report.plan_disposal(&over),
                Err(LotError::OverRelief { .. })
            ));
        }
    }
    let mut missing = dimensions.clone();
    missing.remove(&(VId(1), 3));
    assert!(
        fold_lots_from_open_items_with_dimensions(&items, &digests, UnitId(1), &missing).is_err()
    );
    let mut wrong = dimensions;
    wrong.insert((VId(1), 3), south);
    assert!(
        fold_lots_from_open_items_with_dimensions(&items, &digests, UnitId(1), &wrong).is_err()
    );
}
