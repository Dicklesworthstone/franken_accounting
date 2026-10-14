use super::*;

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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn request_layout_matches_an_independently_encoded_vector() {
    let input = request(10_000, AllocationMethod::LargestRemainder, &[1; 3]);
    let expected = concat!(
        "46412d414c4c4f432d5245515545535400010000000100010007000000102700",
        "0000000000000000000000000003000000640000000000000000000000000000",
        "0001000000000000000000000000000000650000000000000000000000000000",
        "0001000000000000000000000000000000660000000000000000000000000000",
        "0001000000000000000000000000000000"
    );
    assert_eq!(hex(&input.canonical_bytes().unwrap()), expected);
    assert_eq!(
        AllocationRequest::decode(&input.canonical_bytes().unwrap()).unwrap(),
        input
    );
}

#[test]
fn every_method_and_signed_boundary_roundtrips_and_replays() {
    for total in [i128::MIN, -7, 0, 7, i128::MAX] {
        let mut inputs = vec![
            request(total, AllocationMethod::LargestRemainder, &[u128::MAX; 3]),
            request(
                total,
                AllocationMethod::Waterfall,
                &[0, u128::MAX, u128::MAX],
            ),
            request(total, AllocationMethod::EqualSplitResidualFirst, &[1; 3]),
        ];
        for rounding in RoundingLaw::ALL {
            inputs.push(request(
                total,
                AllocationMethod::ProRataResidualToNamed {
                    rounding,
                    recipient: 101,
                },
                &[u128::MAX; 3],
            ));
        }
        for input in inputs {
            let saved = input.canonical_bytes().unwrap();
            let decoded = AllocationRequest::decode(&saved).unwrap();
            assert_eq!(decoded, input);
            assert_eq!(decoded.canonical_bytes().unwrap(), saved);
            let outcome = input.execute().unwrap();
            let receipt = outcome.receipt_bytes().unwrap();
            let replayed = AllocationOutcome::replay_receipt_for(&receipt, &input).unwrap();
            assert_eq!(replayed, outcome);
            assert_eq!(replayed.receipt_bytes().unwrap(), receipt);
        }
    }
}

#[test]
fn every_request_truncation_and_trailing_byte_is_rejected() {
    for method in [
        AllocationMethod::LargestRemainder,
        AllocationMethod::ProRataResidualToNamed {
            rounding: RoundingLaw::HalfEven,
            recipient: 100,
        },
    ] {
        let bytes = request(5, method, &[1; 3]).canonical_bytes().unwrap();
        for cut in 0..bytes.len() {
            assert!(
                AllocationRequest::decode(&bytes[..cut]).is_err(),
                "cut={cut}"
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(AllocationRequest::decode(&trailing).is_err());
    }
}

#[test]
fn unknown_versions_laws_rounding_and_hostile_counts_are_refused() {
    let bytes = request(5, AllocationMethod::LargestRemainder, &[1; 3])
        .canonical_bytes()
        .unwrap();
    for (offset, replacement) in [
        (17, 2u16), // format major
        (19, 1u16), // unsupported minor
        (21, 4u16), // unimplemented Tiered law
        (21, 6u16), // unimplemented two-key law
        (23, 2u16), // law version
    ] {
        let mut bad = bytes.clone();
        bad[offset..offset + 2].copy_from_slice(&replacement.to_le_bytes());
        assert!(AllocationRequest::decode(&bad).is_err());
    }
    for count in [0, 2, 4, 4097, u32::MAX] {
        let mut bad = bytes.clone();
        bad[45..49].copy_from_slice(&count.to_le_bytes());
        assert!(AllocationRequest::decode(&bad).is_err());
    }
    let mut duplicate = bytes;
    duplicate[81..97].copy_from_slice(&100u128.to_le_bytes());
    assert!(AllocationRequest::decode(&duplicate).is_err());

    let mut pro_rata = request(
        5,
        AllocationMethod::ProRataResidualToNamed {
            rounding: RoundingLaw::HalfEven,
            recipient: 100,
        },
        &[1; 3],
    )
    .canonical_bytes()
    .unwrap();
    pro_rata[45..47].copy_from_slice(&10u16.to_le_bytes());
    assert!(AllocationRequest::decode(&pro_rata).is_err());
    assert!(AllocationRequest::decode(&vec![0; MAX_ALLOCATION_REQUEST_BYTES + 1]).is_err());
}

#[test]
fn receipt_rejects_same_total_substitutions_and_changed_review_inputs() {
    let input = request(7, AllocationMethod::LargestRemainder, &[1; 3]);
    let receipt = input.execute().unwrap().receipt_bytes().unwrap();
    let mut altered = receipt.clone();
    let first = 25 + input.canonical_bytes().unwrap().len() + 4;
    let left: [u8; 16] = altered[first..first + 16].try_into().unwrap();
    let right: [u8; 16] = altered[first + 16..first + 32].try_into().unwrap();
    altered[first..first + 16].copy_from_slice(&right);
    altered[first + 16..first + 32].copy_from_slice(&left);
    assert!(
        AllocationOutcome::replay_receipt_for(&altered, &input).is_err(),
        "sum still 7"
    );

    let mut wrong = input.clone();
    wrong.targets.swap(0, 1);
    assert!(AllocationOutcome::replay_receipt_for(&receipt, &wrong).is_err());
    wrong = input.clone();
    wrong.targets[0].basis = 2;
    assert!(AllocationOutcome::replay_receipt_for(&receipt, &wrong).is_err());
    wrong = input.clone();
    wrong.total.unit = UnitId(8);
    assert!(AllocationOutcome::replay_receipt_for(&receipt, &wrong).is_err());
    wrong = input.clone();
    wrong.method = AllocationMethod::EqualSplitResidualFirst;
    assert!(AllocationOutcome::replay_receipt_for(&receipt, &wrong).is_err());
}

#[test]
fn receipt_binds_zero_targets_and_the_full_signed_rounding_transcript() {
    let input = request(
        1,
        AllocationMethod::ProRataResidualToNamed {
            rounding: RoundingLaw::Ceiling,
            recipient: 100,
        },
        &[1; 3],
    );
    let bytes = input.execute().unwrap().receipt_bytes().unwrap();
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1;
        assert!(
            AllocationOutcome::replay_receipt_for(&changed, &input).is_err(),
            "byte={index}"
        );
    }
    let zero = request(
        0,
        AllocationMethod::ProRataResidualToNamed {
            rounding: RoundingLaw::Ceiling,
            recipient: 100,
        },
        &[1; 3],
    );
    let receipt = zero.execute().unwrap().receipt_bytes().unwrap();
    let mut substituted = zero.clone();
    substituted.method = AllocationMethod::ProRataResidualToNamed {
        rounding: RoundingLaw::Ceiling,
        recipient: 101,
    };
    assert!(AllocationOutcome::replay_receipt_for(&receipt, &substituted).is_err());
    let mut shortened = zero;
    shortened.targets.pop();
    assert!(AllocationOutcome::replay_receipt_for(&receipt, &shortened).is_err());
}

#[test]
fn receipt_truncation_surplus_and_size_limit_fail_without_partial_results() {
    let input = request(7, AllocationMethod::LargestRemainder, &[1; 3]);
    let bytes = input.execute().unwrap().receipt_bytes().unwrap();
    for cut in 0..bytes.len() {
        assert!(AllocationOutcome::replay_receipt_for(&bytes[..cut], &input).is_err());
    }
    let mut surplus = bytes;
    surplus.push(0);
    assert!(AllocationOutcome::replay_receipt_for(&surplus, &input).is_err());
    assert!(
        AllocationOutcome::replay_receipt_for(&vec![0; MAX_ALLOCATION_RECEIPT_BYTES + 1], &input,)
            .is_err()
    );
}

#[test]
fn maximum_target_request_stays_inside_both_allocation_bounds() {
    let input = request(
        0,
        AllocationMethod::ProRataResidualToNamed {
            rounding: RoundingLaw::HalfEven,
            recipient: 100,
        },
        &vec![1; MAX_ALLOCATION_TARGETS],
    );
    let bytes = input.canonical_bytes().unwrap();
    assert_eq!(bytes.len(), 67 + 32 * MAX_ALLOCATION_TARGETS);
    assert!(bytes.len() <= MAX_ALLOCATION_REQUEST_BYTES);
    assert_eq!(AllocationRequest::decode(&bytes).unwrap(), input);
    let receipt = input.execute().unwrap().receipt_bytes().unwrap();
    assert!(receipt.len() <= MAX_ALLOCATION_RECEIPT_BYTES);
    assert_eq!(
        AllocationOutcome::replay_receipt_for(&receipt, &input)
            .unwrap()
            .request(),
        &input
    );
}
