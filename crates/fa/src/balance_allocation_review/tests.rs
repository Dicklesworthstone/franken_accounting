use super::*;
use fa_journal::AllocationPosting;
use fa_model::{EntryClass, EntryOrigin, Erasable, Id128, Oid, SealKey};
use fa_money::allocation::{AllocationMethod, AllocationRequest, AllocationTarget};
use fa_money::{Amount, RoundingLaw, Side, UnitId};
use fa_time::DateDay;
use fgdb_types::VId;

// Deliberately synthetic, untrusted source expectations: codec tests do not
// pretend to have queried a journal. Real preparation lives in integration tests.
fn artifact(total: i128, method: AllocationMethod, weights: &[u128]) -> BalanceAllocationReview {
    let posting = AllocationPosting {
        source: VId(10), source_side: Side::Credit, dimensions: vec![(1, VId(31))],
        request: AllocationRequest {
            total: Amount::new(UnitId(7), total), method,
            targets: weights.iter().enumerate().map(|(i, weight)| AllocationTarget {
                id: 20 + i as u128, basis: *weight,
            }).collect(),
        },
    };
    let template = EntryPayload {
        schema_minor: 1, book_id: Id128([1; 16]), branch_id: Id128::TRUNK,
        class: EntryClass::ALLOCATION, effective_date: DateDay(20_527), document_date: None,
        description: Erasable::seal(
            &"private source review".to_string(), None, &SealKey([3; 32]), [4; 32], [5; 24],
        ),
        effective_period: None, legs: Vec::new(), control: None, unit_totals: Vec::new(),
        base_totals: None, idempotency_key: b"source-review-key".to_vec(),
        origin: EntryOrigin::Intent { intent_oid: Oid([6; 32]), intent_kind: 1 },
        principal_ref: VId(7), session_ref: None,
        evidence: vec![posting.driver_evidence(Id128([1; 16])).unwrap()],
        supersession: Vec::new(), pending: None, external_ids: Vec::new(),
        extensions: Vec::new(), tags: Vec::new(),
    };
    BalanceAllocationReview {
        source_period: "FY2026-P03".into(), source_digest: [9; 32],
        review: AllocationReview::new(posting, template).unwrap(),
    }
}

#[test]
fn compound_transport_has_an_independent_fixed_layout() {
    let original = artifact(101, AllocationMethod::LargestRemainder, &[1, 2, 3]);
    let nested = original.review.canonical_bytes().unwrap();
    let mut expected = b"FA-BAL-REVIEW\0".to_vec();
    expected.extend_from_slice(&[1, 0, 0, 0]);
    expected.extend_from_slice(&10_u32.to_le_bytes());
    expected.extend_from_slice(b"FY2026-P03");
    expected.extend_from_slice(&[9; 32]);
    expected.extend_from_slice(&u32::try_from(nested.len()).unwrap().to_le_bytes());
    expected.extend_from_slice(&nested);
    assert_eq!(expected, original.canonical_bytes().unwrap());
    let restored = BalanceAllocationReview::decode(&expected).unwrap();
    assert_eq!(restored, original);
    assert_eq!(restored.review().canonical_bytes().unwrap(), nested);
    assert_eq!(restored.review().proposal(), original.review().proposal());
    restored.verify_for(&original.digest().unwrap()).unwrap();
    for wrong_identity in [
        original.source_digest(), original.review().digest().unwrap(),
        original.review().proposal_digest().unwrap(),
    ] {
        assert!(matches!(restored.verify_for(&wrong_identity), Err(AllocationReviewError::Mismatch)));
    }
}

#[test]
fn all_registered_methods_preserve_order_and_source_selection() {
    let mut cases = vec![
        artifact(101, AllocationMethod::LargestRemainder, &[1, 2, 3]),
        artifact(7, AllocationMethod::Waterfall, &[2, 0, 9]),
        artifact(2, AllocationMethod::EqualSplitResidualFirst, &[1; 5]),
        artifact(i128::MAX, AllocationMethod::LargestRemainder, &[u128::MAX; 3]),
    ];
    for rounding in RoundingLaw::ALL {
        for recipient in 20..23 {
            cases.push(artifact(1, AllocationMethod::ProRataResidualToNamed {
                rounding, recipient,
            }, &[1; 3]));
        }
    }
    for original in cases {
        let restored = BalanceAllocationReview::decode(&original.canonical_bytes().unwrap()).unwrap();
        let request = restored.request();
        let posting = original.review().posting();
        assert_eq!(request.source, posting.source);
        assert_eq!(request.period, "FY2026-P03");
        assert_eq!(request.unit, posting.request.total.unit);
        assert_eq!(request.dimensions, posting.dimensions);
        assert_eq!(request.method, posting.request.method);
        assert_eq!(request.targets, posting.request.targets);
        assert_eq!(restored.review().outcome().unwrap(), original.review().outcome().unwrap());
        assert_eq!(restored.review().proposal_digest().unwrap(), original.review().proposal_digest().unwrap());
    }
}

#[test]
fn source_period_and_history_are_bound_even_with_identical_proposal() {
    let original = artifact(101, AllocationMethod::LargestRemainder, &[1, 2, 3]);
    for field in 0..2 {
        let mut different = original.clone();
        match field {
            0 => different.source_period = "FY2026-P04".into(),
            _ => different.source_digest[0] ^= 1,
        }
        assert_eq!(different.review(), original.review());
        assert_eq!(different.review().proposal_digest().unwrap(), original.review().proposal_digest().unwrap());
        // These are syntactically valid claims, NOT observations. The recipient
        // expectation and subsequent live-source check are both indispensable.
        let restored = BalanceAllocationReview::decode(&different.canonical_bytes().unwrap()).unwrap();
        assert!(matches!(restored.verify_for(&original.digest().unwrap()), Err(AllocationReviewError::Mismatch)));
    }
}

#[test]
fn same_result_driver_and_sealed_metadata_substitutions_change_identity() {
    let original = artifact(9, AllocationMethod::LargestRemainder, &[1, 2]);
    let replacement = artifact(9, AllocationMethod::LargestRemainder, &[2, 4]);
    assert_eq!(original.review().outcome().unwrap().shares(), replacement.review().outcome().unwrap().shares());
    assert!(matches!(replacement.verify_for(&original.digest().unwrap()), Err(AllocationReviewError::Mismatch)));
    for field in 0..4 {
        let mut different = original.clone();
        let mut proposal = original.review().proposal().clone();
        match field {
            0 => proposal.effective_date = DateDay(20_528),
            1 => proposal.principal_ref = VId(8),
            2 => proposal.idempotency_key = b"another-key".to_vec(),
            _ => proposal.description = Erasable::seal(
                &"other text".to_string(), None, &SealKey([3; 32]), [8; 32], [9; 24],
            ),
        }
        different.review = AllocationReview::from_proposal(original.review().posting().clone(), proposal).unwrap();
        assert!(matches!(different.verify_for(&original.digest().unwrap()), Err(AllocationReviewError::Mismatch)));
    }
}

#[test]
fn every_truncation_unknown_header_and_trailing_data_refuse() {
    let original = artifact(7, AllocationMethod::LargestRemainder, &[1, 0, 2]);
    let bytes = original.canonical_bytes().unwrap();
    for cut in 0..bytes.len() {
        assert!(BalanceAllocationReview::decode(&bytes[..cut]).is_err(), "cut {cut}");
    }
    for offset in [0, MAGIC.len(), MAGIC.len() + 2] {
        let mut bad = bytes.clone();
        bad[offset] ^= 0xff;
        assert!(BalanceAllocationReview::decode(&bad).is_err(), "offset {offset}");
    }
    let mut bad = bytes;
    bad.push(0);
    assert!(BalanceAllocationReview::decode(&bad).is_err());
}

#[test]
fn excessive_lengths_invalid_utf8_and_malformed_nested_review_refuse() {
    let original = artifact(7, AllocationMethod::LargestRemainder, &[1, 0, 2]);
    let bytes = original.canonical_bytes().unwrap();
    let period_length_at = MAGIC.len() + 4;
    let period_at = period_length_at + 4;
    let nested_length_at = period_at + original.source_period.len() + 32;
    for offset in [period_length_at, nested_length_at] {
        let mut bad = bytes.clone();
        bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(BalanceAllocationReview::decode(&bad).is_err());
    }
    let mut bad = bytes.clone();
    bad[period_at] = 0xff;
    assert!(BalanceAllocationReview::decode(&bad).is_err());
    let mut bad = bytes;
    bad[nested_length_at + 4] ^= 0xff;
    assert!(BalanceAllocationReview::decode(&bad).is_err());
    assert!(matches!(BalanceAllocationReview::decode(&vec![0; MAX_BALANCE_ALLOCATION_REVIEW_BYTES + 1]),
        Err(AllocationReviewError::TooLarge { .. })));
    for period in [String::new(), "x".repeat(MAX_SOURCE_PERIOD_BYTES + 1)] {
        let bad = BalanceAllocationReview { source_period: period, ..original.clone() };
        assert!(bad.canonical_bytes().is_err());
    }
}

#[test]
fn maximum_source_period_and_declared_zero_targets_round_trip() {
    let mut original = artifact(1, AllocationMethod::EqualSplitResidualFirst, &[1; 1024]);
    original.source_period = "x".repeat(MAX_SOURCE_PERIOD_BYTES);
    let bytes = original.canonical_bytes().unwrap();
    assert!(bytes.len() <= MAX_BALANCE_ALLOCATION_REVIEW_BYTES);
    let restored = BalanceAllocationReview::decode(&bytes).unwrap();
    assert_eq!(restored, original);
    assert_eq!(restored.request().targets.len(), 1024);
    assert_eq!(restored.review().proposal().legs.len(), 2);
    assert_eq!(restored.review().outcome().unwrap().shares().iter().filter(|s| s.mantissa == 0).count(), 1023);
}

#[test]
fn diagnostics_do_not_disclose_source_selector_driver_or_sealed_data() {
    let mut original = artifact(7, AllocationMethod::LargestRemainder, &[123456789, 1]);
    original.source_period = "private-source-period".into();
    let diagnostic = format!("{original:?}");
    assert!(diagnostic.contains("BalanceAllocationReview"));
    for secret in ["private-source-period", "123456789", "private source review", "source-review-key", "ciphertext"] {
        assert!(!diagnostic.contains(secret));
    }
}
