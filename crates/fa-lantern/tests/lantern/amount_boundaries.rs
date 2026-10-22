//! Audit-sampling results at 18-decimal-token scale (fa-4aym). Scaling every
//! amount by a factor scales a Stringer bound by that factor and leaves a
//! Neyman allocation unchanged; at this scale the products the procedures
//! rank and weigh by exceed `u128`, so a clamped intermediate would change
//! the answer without refusing.

use super::*;
use fa_lantern::sample::{
    AuditedSampleItem, PopulationItem, SamplePopulation, StratifiedSamplePlan,
    evaluate_stringer_bound, sample_stratified_neyman,
};

const FACTOR: i128 = 1_000_000_000_000_000_000_000_000_000_000; // 10^30

#[test]
fn stringer_ranking_and_bound_are_exact_for_wide_mantissas() {
    let usd = UnitId(1);
    // The textbook pair, renamed so the higher tainting has the later item id:
    // a tie in the ranking would order by id and misstate the bound.
    let audited = |scale: i128| {
        vec![
            AuditedSampleItem {
                item_id: "A-low".into(),
                book_value: Amount::new(usd, 200_000 * scale),
                audited_value: Amount::new(usd, 180_000 * scale),
            },
            AuditedSampleItem {
                item_id: "B-high".into(),
                book_value: Amount::new(usd, 500_000 * scale),
                audited_value: Amount::new(usd, 400_000 * scale),
            },
        ]
    };
    let small = evaluate_stringer_bound(Amount::new(usd, 1_000_000), 9_500, &audited(1)).unwrap();
    let wide = evaluate_stringer_bound(
        Amount::new(usd, 1_000_000 * FACTOR),
        9_500,
        &audited(FACTOR),
    )
    .unwrap();
    let ranked = |eval: &fa_lantern::sample::StringerEvaluation| {
        eval.ranked_taintings
            .iter()
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(ranked(&small), ["B-high", "A-low"]);
    assert_eq!(ranked(&wide), ranked(&small));
    assert_eq!(small.upper_misstatement_limit.mantissa, 3_505_000);
    assert_eq!(wide.upper_misstatement_limit.mantissa, 3_505_000 * FACTOR);
    assert_eq!(
        wide.incremental_allowance.mantissa,
        small.incremental_allowance.mantissa * FACTOR
    );
}

fn population(scale: i128) -> SamplePopulation {
    let usd = UnitId(1);
    // Stratum "narrow" alternates 1 and 3 (sigma 1), "wide" alternates 1 and 9
    // (sigma 4): Neyman weights 4 : 16, with exact square roots at any scale.
    let items = [("narrow", [1, 3, 1, 3]), ("wide", [1, 9, 1, 9])]
        .into_iter()
        .flat_map(|(stratum, values)| {
            values
                .into_iter()
                .enumerate()
                .map(move |(i, value)| (stratum, i, value))
        })
        .enumerate()
        .map(|(n, (stratum, i, value))| PopulationItem {
            item_id: format!("{stratum}-{i}"),
            reference_vid: VId(u128::try_from(n).unwrap() + 1),
            stratum: Some(stratum.into()),
            book_value: Amount::new(usd, value * scale),
        })
        .collect();
    SamplePopulation::new("strata", usd, items).unwrap()
}

/// A population whose book values sum past `i128` is refused, never
/// saturated: every sampling method (stratified included) is drawn over a
/// population that holds its exact total (fa-k1ts).
#[test]
fn a_population_whose_total_exceeds_i128_is_refused_not_saturated() {
    let usd = UnitId(1);
    let item = |n: u128| PopulationItem {
        item_id: format!("wide-{n}"),
        reference_vid: VId(n),
        stratum: Some("wide".into()),
        book_value: Amount::new(usd, i128::MAX / 2 + 1),
    };
    let refused = SamplePopulation::new("overflow", usd, vec![item(1), item(2)]);
    assert!(
        matches!(
            refused,
            Err(fa_lantern::LanternError::Overflow(
                "population total book value"
            ))
        ),
        "{refused:?}"
    );
    // One item fewer is exact.
    assert!(SamplePopulation::new("exact", usd, vec![item(1)]).is_ok());
}

#[test]
fn stratified_neyman_allocation_is_scale_invariant_for_wide_mantissas() {
    let epoch = [0x55; 32];
    let plan = |scale| -> StratifiedSamplePlan {
        sample_stratified_neyman(
            &population(scale),
            7,
            6,
            "fixture",
            Some(epoch),
            epoch,
            VId(99),
        )
        .unwrap()
    };
    let allocation = |plan: &StratifiedSamplePlan| {
        plan.strata
            .iter()
            .map(|s| {
                (
                    s.stratum.clone(),
                    s.allocated_sample_size,
                    s.std_dev_mantissa,
                )
            })
            .collect::<Vec<_>>()
    };
    let small = plan(1);
    let wide = plan(FACTOR);
    // Weights 4 : 16 over 4 units beyond the one-per-stratum floor: floors 0
    // and 3, and the larger remainder (narrow) takes the last unit.
    assert_eq!(
        allocation(&small),
        [("narrow".to_string(), 2, 1), ("wide".to_string(), 4, 4)]
    );
    assert_eq!(
        allocation(&wide),
        [
            ("narrow".to_string(), 2, FACTOR),
            ("wide".to_string(), 4, 4 * FACTOR)
        ]
    );
}
