use super::*;
use fa_model::{EntryClass, EntryOrigin, Erasable, Id128, Oid, SealKey};
use fa_money::allocation::{AllocationMethod, AllocationTarget};
use fa_money::{Amount, RoundingLaw, UnitId};
use fa_time::DateDay;

fn posting(total: i128, method: AllocationMethod, weights: &[u128]) -> AllocationPosting {
    AllocationPosting {
        source: VId(10), source_side: Side::Credit, dimensions: Vec::new(),
        request: AllocationRequest {
            total: Amount::new(UnitId(7), total), method,
            targets: weights.iter().enumerate().map(|(i, weight)| AllocationTarget {
                id: 20 + i as u128, basis: *weight,
            }).collect(),
        },
    }
}

fn template(posting: &AllocationPosting, key: &[u8]) -> EntryPayload {
    EntryPayload {
        schema_minor: 1, book_id: Id128([1; 16]), branch_id: Id128::TRUNK,
        class: EntryClass::ALLOCATION, effective_date: DateDay(20_527), document_date: None,
        description: Erasable::seal(&"private review description".to_string(), None, &SealKey([3; 32]), [4; 32], [5; 24]),
        effective_period: None, legs: Vec::new(), control: None, unit_totals: Vec::new(),
        base_totals: None, idempotency_key: key.to_vec(),
        origin: EntryOrigin::Intent { intent_oid: Oid([6; 32]), intent_kind: 1 },
        principal_ref: VId(7), session_ref: None,
        evidence: vec![posting.driver_evidence(Id128([1; 16])).unwrap()],
        supersession: Vec::new(), pending: None, external_ids: Vec::new(),
        extensions: Vec::new(), tags: Vec::new(),
    }
}

fn review(posting: AllocationPosting) -> AllocationReview {
    let template = template(&posting, b"review");
    AllocationReview::new(posting, template).unwrap()
}

#[test]
fn all_laws_preserve_the_exact_proposal_through_transport() {
    let mut cases = vec![
        posting(101, AllocationMethod::LargestRemainder, &[1, 2, 3]),
        posting(7, AllocationMethod::Waterfall, &[2, 0, 9]),
        posting(2, AllocationMethod::EqualSplitResidualFirst, &[1; 5]),
        posting(i128::MAX, AllocationMethod::LargestRemainder, &[u128::MAX; 3]),
    ];
    for rounding in RoundingLaw::ALL {
        for recipient in 20..23 {
            cases.push(posting(1, AllocationMethod::ProRataResidualToNamed { rounding, recipient }, &[1; 3]));
        }
    }
    for mut basis in cases {
        for side in [Side::Debit, Side::Credit] {
            basis.source_side = side;
            let review = review(basis.clone());
            let bytes = review.canonical_bytes().unwrap();
            let decoded = AllocationReview::decode(&bytes).unwrap();
            assert_eq!(decoded, review);
            assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
            assert_eq!(decoded.outcome().unwrap(), basis.request.execute().unwrap());
            assert_eq!(decoded.proposal_digest().unwrap(), review.proposal().proposal_digest().unwrap());
            decoded.verify_for(&review.digest().unwrap()).unwrap();
            assert!(decoded.intent.approvals().is_empty());
        }
    }
}

#[test]
fn same_result_driver_substitution_is_not_the_same_review() {
    let basis = posting(9, AllocationMethod::LargestRemainder, &[1, 2]);
    let original = review(basis.clone());
    let mut changed = basis;
    changed.request.targets[0].basis = 2;
    changed.request.targets[1].basis = 4;
    assert_eq!(changed.request.execute().unwrap().shares(), original.outcome().unwrap().shares());
    assert!(AllocationReview::from_proposal(changed.clone(), original.proposal().clone()).is_err());
    let replacement = review(changed);
    assert!(matches!(replacement.verify_for(&original.digest().unwrap()), Err(AllocationReviewError::Mismatch)));
    assert_ne!(original.proposal_digest().unwrap(), replacement.proposal_digest().unwrap());
}

#[test]
fn balanced_resealed_shares_and_extra_effects_cannot_be_adopted() {
    let review = review(posting(10, AllocationMethod::LargestRemainder, &[1; 3]));
    let original = review.proposal();
    let mut bad = original.clone();
    bad.legs[1].amount.mantissa -= 1;
    bad.legs[2].amount.mantissa += 1;
    bad.unit_totals = EntryPayload::fold_unit_totals(&bad.legs).unwrap();
    assert!(PostIntent::new(bad.clone(), Vec::new()).is_ok(), "outer structure and balance are insufficient");
    assert!(AllocationReview::from_proposal(review.posting.clone(), bad).is_err());
    let mut bad = original.clone(); bad.legs[1].memo = Some(original.description.clone());
    assert!(AllocationReview::from_proposal(review.posting.clone(), bad).is_err());
    let mut bad = original.clone(); bad.extensions.push((6, Vec::new()));
    assert!(AllocationReview::from_proposal(review.posting.clone(), bad).is_err());
    let mut bad = original.clone(); bad.evidence.clear();
    assert!(AllocationReview::from_proposal(review.posting.clone(), bad).is_err());
    let mut bad = original.clone(); bad.class = EntryClass::ORIGINAL;
    assert!(AllocationReview::from_proposal(review.posting.clone(), bad).is_err());
}

#[test]
fn review_identity_binds_metadata_not_only_arithmetic() {
    let original = review(posting(9, AllocationMethod::LargestRemainder, &[1; 3]));
    let digest = original.digest().unwrap();
    for field in 0..5 {
        let mut changed = original.proposal().clone();
        match field {
            0 => changed.effective_date = DateDay(20_528),
            1 => changed.principal_ref = VId(8),
            2 => changed.idempotency_key = b"different-key".to_vec(),
            3 => changed.session_ref = Some(VId(99)),
            _ => changed.description = Erasable::seal(
                &"different text".to_string(), None, &SealKey([3; 32]), [8; 32], [9; 24],
            ),
        }
        let changed = AllocationReview::from_proposal(original.posting.clone(), changed).unwrap();
        assert_eq!(changed.outcome().unwrap(), original.outcome().unwrap());
        assert!(matches!(changed.verify_for(&digest), Err(AllocationReviewError::Mismatch)));
        assert_ne!(changed.proposal_digest().unwrap(), original.proposal_digest().unwrap());
    }
}

#[test]
fn review_container_has_an_independent_fixed_layout() {
    let mut basis = posting(7, AllocationMethod::Waterfall, &[2, 0, 9]);
    basis.dimensions = vec![(1, VId(55)), (4, VId(u128::MAX))];
    let review = review(basis);
    let request = review.posting.request.canonical_bytes().unwrap();
    let intent = review.intent.canonical_bytes().unwrap();
    let mut expected = b"FA-ALLOC-REVIEW\0".to_vec();
    expected.extend_from_slice(&[1, 0, 0, 0]);
    expected.extend_from_slice(&10u128.to_le_bytes());
    expected.push(1);
    expected.extend_from_slice(&2u32.to_le_bytes());
    for (id, value) in [(1u32, 55u128), (4, u128::MAX)] {
        expected.extend_from_slice(&id.to_le_bytes());
        expected.extend_from_slice(&value.to_le_bytes());
    }
    for part in [&request, &intent] {
        expected.extend_from_slice(&u32::try_from(part.len()).unwrap().to_le_bytes());
        expected.extend_from_slice(part);
    }
    assert_eq!(expected, review.canonical_bytes().unwrap());
    assert_eq!(AllocationReview::decode(&expected).unwrap(), review);
}

#[test]
fn truncated_hostile_and_inconsistent_containers_refuse() {
    let review = review(posting(7, AllocationMethod::LargestRemainder, &[1, 0, 2]));
    let bytes = review.canonical_bytes().unwrap();
    for cut in 0..bytes.len() {
        assert!(AllocationReview::decode(&bytes[..cut]).is_err(), "cut {cut}");
    }
    for offset in [0, 16, 18, 20, 36, 37, 41] {
        let mut changed = bytes.clone(); changed[offset] ^= 0xff;
        assert!(AllocationReview::decode(&changed).is_err(), "offset {offset}");
    }
    let mut changed = bytes.clone(); changed[37..41].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(AllocationReview::decode(&changed).is_err());
    let mut changed = bytes; changed.push(0);
    assert!(AllocationReview::decode(&changed).is_err());
    assert!(matches!(AllocationReview::decode(&vec![0; MAX_ALLOCATION_REVIEW_BYTES + 1]),
        Err(AllocationReviewError::TooLarge { .. })));
}

#[test]
fn maximum_targets_and_dimensions_keep_zero_shares_and_fit_the_bound() {
    let mut basis = posting(1, AllocationMethod::EqualSplitResidualFirst, &vec![1; 1024]);
    basis.dimensions = (0..64).map(|id| (id, VId(u128::from(id) + 1))).collect();
    let review = review(basis);
    let encoded = review.canonical_bytes().unwrap();
    assert!(encoded.len() < MAX_ALLOCATION_REVIEW_BYTES);
    let decoded = AllocationReview::decode(&encoded).unwrap();
    assert_eq!(decoded.posting().request.targets.len(), 1024);
    assert_eq!(decoded.posting().dimensions.len(), 64);
    assert_eq!(decoded.proposal().legs.len(), 2);
    assert_eq!(decoded.outcome().unwrap().shares().iter().filter(|share| share.mantissa == 0).count(), 1023);
    assert_eq!(decoded, review);
}

#[test]
fn diagnostics_do_not_dump_driver_or_proposal_bytes() {
    let review = review(posting(7, AllocationMethod::LargestRemainder, &[123456789, 1]));
    let diagnostic = format!("{review:?}");
    assert!(diagnostic.contains("AllocationReview"));
    for sensitive in ["123456789", "private review description", "idempotency_key", "ciphertext", "posting:"] {
        assert!(!diagnostic.contains(sensitive));
    }
}
