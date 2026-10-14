use super::*;
use crate::UnitId;

fn request(total: i128, method: AllocationMethod, basis: &[u128]) -> AllocationRequest {
    AllocationRequest {
        total: Amount::new(UnitId(7), total),
        method,
        targets: basis
            .iter()
            .enumerate()
            .map(|(index, basis)| AllocationTarget {
                id: 100 + index as u128,
                basis: *basis,
            })
            .collect(),
    }
}

fn values(outcome: &AllocationOutcome) -> Vec<i128> {
    outcome
        .shares()
        .iter()
        .map(|share| share.mantissa)
        .collect()
}

#[test]
fn registered_laws_have_distinct_golden_accounting_results() {
    let examples = [
        (
            10_000,
            AllocationMethod::LargestRemainder,
            vec![1, 1, 1],
            vec![3334, 3333, 3333],
        ),
        (
            2,
            AllocationMethod::EqualSplitResidualFirst,
            vec![1; 5],
            vec![2, 0, 0, 0, 0],
        ),
        (
            -7,
            AllocationMethod::Waterfall,
            vec![0, 3, 8],
            vec![0, -3, -4],
        ),
        (
            1,
            AllocationMethod::ProRataResidualToNamed {
                rounding: RoundingLaw::Ceiling,
                recipient: 101,
            },
            vec![1; 3],
            vec![1, -1, 1],
        ),
    ];
    for (total, method, basis, expected) in examples {
        let request = request(total, method, &basis);
        let outcome = request.execute().unwrap();
        assert_eq!(values(&outcome), expected);
        assert_eq!(outcome.request(), &request);
        assert!(outcome.shares().iter().all(|share| share.unit == UnitId(7)));
        outcome.verify_for(&request).unwrap();
    }
}

#[test]
fn recipient_is_bound_by_identity_and_order_is_preserved() {
    let mut input = request(
        1,
        AllocationMethod::ProRataResidualToNamed {
            rounding: RoundingLaw::Ceiling,
            recipient: 101,
        },
        &[1; 3],
    );
    input.targets.swap(0, 1);
    let outcome = input.execute().unwrap();
    assert_eq!(values(&outcome), [-1, 1, 1]);
    let transcript = outcome.pro_rata().unwrap();
    assert_eq!(transcript.residual_target, 0);
    assert_eq!(transcript.residual.mantissa, -2);
    assert_eq!(
        transcript
            .rounded_shares
            .iter()
            .map(|a| a.mantissa)
            .collect::<Vec<_>>(),
        [1, 1, 1]
    );
    assert_eq!(outcome.request().targets[0].id, 101);

    let mut equal = request(2, AllocationMethod::EqualSplitResidualFirst, &[1; 3]);
    let first = equal.execute().unwrap();
    equal.targets.swap(0, 1);
    let second = equal.execute().unwrap();
    assert_eq!(values(&first), [2, 0, 0]);
    assert_eq!(values(&second), [2, 0, 0]);
    assert_ne!(
        first.request().targets[0].id,
        second.request().targets[0].id
    );
    assert!(
        first.verify_for(&equal).is_err(),
        "same amounts are not the same ordered request"
    );
}

#[test]
fn shape_refusals_precede_execution_including_zero_totals() {
    for total in [0, 1] {
        assert!(
            request(total, AllocationMethod::LargestRemainder, &[])
                .execute()
                .is_err()
        );
        assert!(
            request(total, AllocationMethod::LargestRemainder, &[0, 0])
                .execute()
                .is_err()
        );
        assert!(
            request(total, AllocationMethod::EqualSplitResidualFirst, &[1, 2])
                .execute()
                .is_err()
        );
        let mut duplicate = request(total, AllocationMethod::Waterfall, &[1, 1]);
        duplicate.targets[1].id = duplicate.targets[0].id;
        assert!(duplicate.execute().is_err());
        assert!(
            request(
                total,
                AllocationMethod::ProRataResidualToNamed {
                    rounding: RoundingLaw::HalfEven,
                    recipient: 99,
                },
                &[1, 1]
            )
            .execute()
            .is_err()
        );
    }
    assert!(
        request(3, AllocationMethod::Waterfall, &[1, 1])
            .execute()
            .is_err()
    );
    let too_many = vec![1; super::super::MAX_ALLOCATION_TARGETS + 1];
    assert!(
        request(0, AllocationMethod::LargestRemainder, &too_many)
            .execute()
            .is_err()
    );
}

#[test]
fn registered_lower_target_bound_is_enforced() {
    let text = include_str!("../../../../../registries/allocation_laws.toml")
        .replace("max_targets = 4096", "max_targets = 2");
    let catalog = AllocationCatalog::parse(&text).unwrap();
    assert!(
        request(3, AllocationMethod::LargestRemainder, &[1; 3])
            .execute_with(&catalog)
            .is_err()
    );
    assert_eq!(
        values(
            &request(3, AllocationMethod::LargestRemainder, &[1; 2])
                .execute_with(&catalog)
                .unwrap()
        ),
        [2, 1]
    );
}

#[test]
fn same_total_does_not_authenticate_a_changed_outcome() {
    let original = request(7, AllocationMethod::LargestRemainder, &[1, 1, 1]);
    let mut tampered = original.execute().unwrap();
    tampered.shares.swap(0, 1);
    assert!(tampered.verify_for(&original).is_err());
    let outcome = original.execute().unwrap();
    let mut wrong_basis = original.clone();
    wrong_basis.targets[0].basis = 2;
    assert!(outcome.verify_for(&wrong_basis).is_err());
    let mut wrong_unit = original.clone();
    wrong_unit.total.unit = UnitId(8);
    assert!(outcome.verify_for(&wrong_unit).is_err());

    let input = request(
        1,
        AllocationMethod::ProRataResidualToNamed {
            rounding: RoundingLaw::Ceiling,
            recipient: 100,
        },
        &[1; 3],
    );
    let mut outcome = input.execute().unwrap();
    outcome.pro_rata.as_mut().unwrap().residual = Amount::zero(UnitId(7));
    assert!(
        outcome.verify_for(&input).is_err(),
        "rounding transcript must replay too"
    );
}

#[test]
fn boundaries_keep_wide_intermediates_and_minimum_signed_total() {
    for total in [i128::MIN, -i128::MAX, -1, 0, 1, i128::MAX] {
        for method in [
            AllocationMethod::LargestRemainder,
            AllocationMethod::Waterfall,
        ] {
            let outcome = request(total, method, &[u128::MAX; 3]).execute().unwrap();
            assert!(conserves(outcome.request.total, outcome.shares()).unwrap());
        }
        let equal = request(total, AllocationMethod::EqualSplitResidualFirst, &[1; 3])
            .execute()
            .unwrap();
        assert!(conserves(equal.request.total, equal.shares()).unwrap());
        for rounding in RoundingLaw::ALL {
            let input = request(
                total,
                AllocationMethod::ProRataResidualToNamed {
                    rounding,
                    recipient: 102,
                },
                &[u128::MAX; 3],
            );
            let outcome = input.execute().unwrap();
            assert!(conserves(input.total, outcome.shares()).unwrap());
        }
    }
    // A naïve signed i128 running sum would overflow before cancellation.
    let unit = UnitId(7);
    assert!(
        conserves(
            Amount::new(unit, i128::MAX),
            &[
                Amount::new(unit, i128::MAX),
                Amount::new(unit, 1),
                Amount::new(unit, -1),
            ]
        )
        .unwrap()
    );
    assert!(!conserves(Amount::zero(unit), &[Amount::zero(UnitId(8))]).unwrap());
}

#[test]
fn generated_law_requests_conserve_and_preserve_every_target() {
    let mut seed = 0x6a09_e667_f3bc_c909u64;
    for iteration in 0..10_000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let total = i128::from(seed % 2001) - 1000;
        let basis = [
            u128::from(seed % 17),
            u128::from((seed >> 8) % 17) + 1,
            u128::from((seed >> 16) % 17),
        ];
        let method = match iteration % 3 {
            0 => AllocationMethod::LargestRemainder,
            1 => AllocationMethod::ProRataResidualToNamed {
                rounding: RoundingLaw::ALL[((seed >> 24) % 9) as usize],
                recipient: 100 + u128::from(seed % 3),
            },
            _ => AllocationMethod::Waterfall,
        };
        let caps = [0, total.unsigned_abs() / 2, total.unsigned_abs()];
        let input = request(
            total,
            method,
            if method == AllocationMethod::Waterfall {
                &caps
            } else {
                &basis
            },
        );
        let result = input.execute().unwrap();
        assert_eq!(
            result
                .shares()
                .iter()
                .map(|share| share.mantissa)
                .sum::<i128>(),
            total
        );
        assert_eq!(result.shares().len(), input.targets.len());
        assert_eq!(result.request(), &input);
    }
}
