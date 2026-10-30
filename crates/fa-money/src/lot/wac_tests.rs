//! Sequential pool checks: a cost layer survives exhaustion of its quantity.

use super::*;

fn layer(id: u128, quantity: i128, cost: i128) -> LotCandidate {
    LotCandidate {
        entry_id: id,
        qty_ordinal: 0,
        cost_ordinal: 2,
        effective_day: 10,
        recorded_seq: 2,
        open_quantity: quantity,
        open_cost: cost,
    }
}

fn wac(layers: &[LotCandidate], quantity: i128) -> LotReliefOutcome {
    relieve_lots(
        layers,
        quantity,
        LotLaw::WeightedAverage,
        AccountingRegime::Ifrs,
        RoundingLaw::HalfEven,
        None,
    )
    .unwrap()
}

fn apply(layers: &mut [LotCandidate], outcome: &LotReliefOutcome) {
    let mut quantity = 0i128;
    let mut cost = 0i128;
    for slice in &outcome.slices {
        let layer = layers
            .iter_mut()
            .find(|layer| layer.entry_id == slice.entry_id)
            .unwrap();
        assert_eq!(layer.open_quantity, slice.open_quantity_before);
        assert_eq!(layer.open_cost, slice.open_cost_before);
        assert!(slice.relieved_quantity > 0 || slice.relieved_cost > 0);
        assert!(slice.relieved_quantity >= 0 && slice.relieved_cost >= 0);
        assert!(slice.open_quantity_after >= 0 && slice.open_cost_after >= 0);
        layer.open_quantity = layer
            .open_quantity
            .checked_sub(slice.relieved_quantity)
            .unwrap();
        layer.open_cost = layer.open_cost.checked_sub(slice.relieved_cost).unwrap();
        assert_eq!(layer.open_quantity, slice.open_quantity_after);
        assert_eq!(layer.open_cost, slice.open_cost_after);
        quantity = quantity.checked_add(slice.relieved_quantity).unwrap();
        cost = cost.checked_add(slice.relieved_cost).unwrap();
    }
    assert_eq!(quantity, outcome.requested_quantity);
    assert_eq!(cost, outcome.total_relieved_cost);
}

#[test]
fn weighted_average_preserves_cost_after_its_quantity_layer_is_exhausted() {
    let mut layers = vec![layer(1, 10, 100), layer(2, 10, 20)];
    let first = wac(&layers, 10);
    assert_eq!(first.total_relieved_cost, 60);
    apply(&mut layers, &first);
    assert_eq!((layers[0].open_quantity, layers[0].open_cost), (0, 40));

    // This used to drop the first layer's remaining 40 from the pool and
    // price the next unit at 2 instead of 6.
    let second = wac(&layers, 1);
    assert_eq!(second.total_open_quantity, 10);
    assert_eq!(second.total_open_cost, 60);
    assert_eq!(second.total_relieved_cost, 6);
    assert!(second.slices.iter().any(|slice| {
        slice.entry_id == 1 && slice.relieved_quantity == 0 && slice.relieved_cost == 6
    }));
    apply(&mut layers, &second);

    let final_sale = wac(&layers, 9);
    assert_eq!(final_sale.total_relieved_cost, 54);
    assert_eq!(final_sale.wac_residual_numerator, 0);
    apply(&mut layers, &final_sale);
    assert!(
        layers
            .iter()
            .all(|layer| layer.open_quantity == 0 && layer.open_cost == 0)
    );
}

#[test]
fn final_quantity_exhaustion_also_relieves_every_cost_only_layer() {
    let mut layers = vec![layer(3, 0, 7), layer(1, 0, 5), layer(2, 4, 8)];
    let result = wac(&layers, 4);
    assert_eq!(result.total_relieved_cost, 20);
    assert_eq!(result.slices.len(), 3);
    assert_eq!(result.slices[0].entry_id, 1);
    assert_eq!(result.slices[0].relieved_quantity, 0);
    assert_eq!(result.slices[0].relieved_cost, 5);
    let mut reordered = layers.clone();
    reordered.reverse();
    assert_eq!(wac(&reordered, 4), result);
    apply(&mut layers, &result);
    assert!(
        layers
            .iter()
            .all(|layer| layer.open_quantity == 0 && layer.open_cost == 0)
    );
}

#[test]
fn successive_weighted_average_sales_match_independent_small_integer_pool_arithmetic() {
    // These exact small vectors use ordinary integer division as a separate
    // pooled-price oracle, independently of the production U256 arithmetic
    // and its per-layer cost assignment. Every sale recomputes the remaining
    // pool; the last sale must consume the whole remaining acquisition cost.
    for quantity1 in [1i128, 3, 7] {
        for quantity2 in [1i128, 4, 9] {
            for cost1 in [1i128, 7, 50] {
                for cost2 in [1i128, 8, 13] {
                    let mut layers = vec![layer(1, quantity1, cost1), layer(2, quantity2, cost2)];
                    let mut quantity = quantity1.checked_add(quantity2).unwrap();
                    let mut cost = cost1.checked_add(cost2).unwrap();
                    while quantity > 0 {
                        let quotient = cost.checked_div(quantity).unwrap();
                        let remainder = cost.checked_rem(quantity).unwrap();
                        let twice = remainder.checked_mul(2).unwrap();
                        let round_up = twice > quantity
                            || (twice == quantity && quotient.checked_rem(2).unwrap() == 1);
                        let expected = quotient.checked_add(i128::from(round_up)).unwrap();
                        let result = wac(&layers, 1);
                        assert_eq!(result.total_open_quantity, quantity);
                        assert_eq!(result.total_open_cost, cost);
                        assert_eq!(result.total_relieved_cost, expected);
                        apply(&mut layers, &result);
                        quantity = quantity.checked_sub(1).unwrap();
                        cost = cost.checked_sub(expected).unwrap();
                    }
                    assert_eq!(cost, 0);
                    assert!(
                        layers
                            .iter()
                            .all(|layer| layer.open_quantity == 0 && layer.open_cost == 0)
                    );
                }
            }
        }
    }
}

#[test]
fn every_rounding_law_conserves_the_pool_over_successive_sales() {
    for rounding_law in RoundingLaw::ALL {
        let mut layers = vec![layer(1, 3, 41), layer(2, 7, 2), layer(3, 2, 11)];
        let mut relieved_cost = 0i128;
        for quantity in [3, 1, 5, 3] {
            let result = relieve_lots(
                &layers,
                quantity,
                LotLaw::WeightedAverage,
                AccountingRegime::UsGaap,
                rounding_law,
                None,
            )
            .unwrap();
            relieved_cost = relieved_cost
                .checked_add(result.total_relieved_cost)
                .unwrap();
            apply(&mut layers, &result);
        }
        assert_eq!(relieved_cost, 54, "{rounding_law:?}");
        assert!(
            layers
                .iter()
                .all(|layer| layer.open_quantity == 0 && layer.open_cost == 0)
        );
    }
}

#[test]
fn nonpooled_laws_refuse_to_discard_residual_pooled_cost() {
    let layers = vec![layer(1, 0, 40), layer(2, 10, 20)];
    for law in [LotLaw::Fifo, LotLaw::Lifo, LotLaw::SpecificId] {
        let result = relieve_lots(
            &layers,
            10,
            law,
            AccountingRegime::UsGaap,
            RoundingLaw::HalfEven,
            (law == LotLaw::SpecificId).then_some(&[(2, 0)][..]),
        );
        assert!(
            matches!(result, Err(LotError::InvalidCandidate(_))),
            "{law:?}"
        );
    }
}

#[test]
fn residual_cost_is_counted_for_overflow_and_cannot_supply_quantity() {
    let overflow = wac_result(&[layer(1, 0, i128::MAX), layer(2, 1, 1)], 1);
    assert_eq!(overflow, Err(LotError::Overflow));
    assert_eq!(
        wac_result(&[layer(1, 0, 40)], 1),
        Err(LotError::OverRelief {
            requested: 1,
            open_quantity: 0
        })
    );
}

fn wac_result(layers: &[LotCandidate], quantity: i128) -> Result<LotReliefOutcome, LotError> {
    relieve_lots(
        layers,
        quantity,
        LotLaw::WeightedAverage,
        AccountingRegime::Ifrs,
        RoundingLaw::HalfEven,
        None,
    )
}
