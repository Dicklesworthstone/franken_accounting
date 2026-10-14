//! Missing-entry attacks must fail even when every supplied membership passes.

#[path = "support/production.rs"]
mod fixture;

use fa_verify::proof::production::{
    MAX_PRODUCTION_BYTES, MAX_PRODUCTION_LEAVES, MAX_PRODUCTION_RECORDS,
    ProductionError, ProductionScope, verify_production_for,
};
use fa_verify::proof::{PREFIX_FORMAT, RecordCheck, VerifyError, verify_inclusion};
use fixture::{Fixture, SECRET, Wire, borrowed, record};

fn scope() -> ProductionScope {
    ProductionScope { first_seq: 0, known_at: 5, account: Some(10), effective_days: Some((10, 20)) }
}

#[test]
fn exact_selection_preserves_batch_ordinals_and_retroactive_entries() {
    let f = Fixture::mixed();
    let proofs = f.inclusions(&[0, 2, 3]);
    for proof in &proofs {
        assert_eq!(verify_inclusion(proof, &f.checkpoint).unwrap().record, RecordCheck::Recomputed);
    }
    let report = verify_production_for(&f.prefix(), &borrowed(&proofs), &f.checkpoint, &scope()).unwrap();
    assert_eq!(report.scope, "seq_range_complete");
    assert_eq!(report.requested, scope());
    assert_eq!(report.entries.iter().map(|r| r.leaf_index).collect::<Vec<_>>(), [0, 2, 3]);
    assert_eq!(report.entries[1].envelope.position(), (2, 1));
    assert_eq!(report.entries[1].envelope.class, 2);
    assert_eq!(report.entries[2].envelope.class, 12);
}

#[test]
fn omitted_extra_duplicate_and_reordered_genuine_proofs_are_not_complete_production() {
    let f = Fixture::mixed();
    let prefix = f.prefix();
    let good = f.inclusions(&[0, 2, 3]);
    assert!(verify_production_for(&prefix, &borrowed(&good), &f.checkpoint, &scope()).is_ok());
    for indexes in [vec![], vec![0, 2], vec![0, 3], vec![2, 3], vec![0, 2, 3, 4],
        vec![0, 0, 3], vec![0, 3, 2], vec![0, 2, 4], vec![1, 2, 3]]
    {
        let proofs = f.inclusions(&indexes);
        // Positive controls: none of these failures is a bad inclusion path.
        for proof in &proofs { assert!(verify_inclusion(proof, &f.checkpoint).is_ok()); }
        assert!(matches!(verify_production_for(&prefix, &borrowed(&proofs), &f.checkpoint, &scope()),
            Err(ProductionError::RecordCount { .. } | ProductionError::Position { .. })), "{indexes:?}");
    }
}

#[test]
fn empty_results_require_a_genuine_complete_prefix_and_the_exact_question() {
    for f in [Fixture::new(Vec::new(), 10), Fixture::mixed()] {
        let request = ProductionScope { account: Some(999), ..scope() };
        let result = verify_production_for(&f.prefix(), &[], &f.checkpoint, &request).unwrap();
        assert!(result.entries.is_empty());
        let mut wrong_anchor = f.checkpoint;
        wrong_anchor.root[0] ^= 1;
        assert!(matches!(verify_production_for(&f.prefix(), &[], &wrong_anchor, &request),
            Err(ProductionError::Prefix(VerifyError::NotTrusted { .. }))));
        assert!(verify_production_for(&[], &[], &f.checkpoint, &request).is_err());
    }
    let f = Fixture::mixed();
    assert_eq!(verify_production_for(&f.prefix(), &[], &f.checkpoint, &scope()),
        Err(ProductionError::RecordCount { expected: 3, actual: 0 }));
}

#[test]
fn recipient_filters_are_independent_inclusive_and_not_fiscal_or_subtree_selectors() {
    let f = Fixture::mixed();
    for (request, indexes) in [
        (ProductionScope { first_seq: 2, known_at: 2, account: None, effective_days: None }, vec![1, 2]),
        (ProductionScope { first_seq: 0, known_at: 10, account: None, effective_days: None }, vec![0, 1, 2, 3, 4, 5, 6]),
        (ProductionScope { first_seq: 0, known_at: 10, account: None, effective_days: Some((10, 20)) }, vec![0, 1, 2, 3, 6]),
        (ProductionScope { first_seq: 0, known_at: 10, account: Some(11), effective_days: None }, vec![0, 2, 3, 4]),
    ] {
        let proofs = f.inclusions(&indexes);
        let result = verify_production_for(&f.prefix(), &borrowed(&proofs), &f.checkpoint, &request).unwrap();
        assert_eq!(result.requested, request);
        assert_eq!(result.entries.len(), indexes.len());
    }
    let extreme = Fixture::new(vec![record(u64::MAX, u32::MAX, 1, i32::MIN, Some(10))], u64::MAX);
    let request = ProductionScope { first_seq: u64::MAX, known_at: u64::MAX,
        account: Some(10), effective_days: Some((i32::MIN, i32::MAX)) };
    assert!(verify_production_for(&extreme.prefix(), &[&extreme.inclusion(0, true)],
        &extreme.checkpoint, &request).is_ok());
}

#[test]
fn bad_request_and_resource_limits_precede_untrusted_decoding() {
    let f = Fixture::mixed();
    for request in [ProductionScope { first_seq: 6, ..scope() },
        ProductionScope { known_at: 11, ..scope() },
        ProductionScope { effective_days: Some((21, 20)), ..scope() }]
    {
        assert!(matches!(verify_production_for(&[], &[], &f.checkpoint, &request),
            Err(ProductionError::Request(_))));
    }
    let too_many = vec![&[][..]; MAX_PRODUCTION_RECORDS + 1];
    assert!(matches!(verify_production_for(&[], &too_many, &f.checkpoint, &scope()),
        Err(ProductionError::Limit("record count"))));
    let over_budget = vec![0; MAX_PRODUCTION_BYTES + 1];
    assert!(matches!(verify_production_for(&over_budget, &[], &f.checkpoint, &scope()),
        Err(ProductionError::Limit("aggregate encoded bytes"))));
    // Individually legal-sized buffers still exceed the aggregate policy.
    assert!(matches!(verify_production_for(&over_budget[..MAX_PRODUCTION_BYTES], &[&[0]],
        &f.checkpoint, &scope()), Err(ProductionError::Limit("aggregate encoded bytes"))));
    let mut declared = Wire::default();
    declared.bytes(PREFIX_FORMAT).fixed(&f.checkpoint.encode()).u32(MAX_PRODUCTION_LEAVES as u32 + 1);
    assert!(matches!(verify_production_for(&declared.0, &[], &f.checkpoint, &scope()),
        Err(ProductionError::Prefix(VerifyError::Decode(_)))));
}

#[test]
fn envelope_only_and_corrupted_last_payload_never_return_partial_success() {
    let f = Fixture::mixed();
    let mut proofs = f.inclusions(&[0, 2, 3]);
    assert!(verify_production_for(&f.prefix(), &borrowed(&proofs), &f.checkpoint, &scope()).is_ok());
    proofs[2] = f.inclusion(3, false);
    assert!(verify_inclusion(&proofs[2], &f.checkpoint).is_ok());
    assert_eq!(verify_production_for(&f.prefix(), &borrowed(&proofs), &f.checkpoint, &scope()),
        Err(ProductionError::PayloadRequired { index: 3 }));
    proofs[2] = f.inclusion(3, true);
    let offset = proofs[2].windows(SECRET.len()).position(|bytes| bytes == SECRET).unwrap();
    proofs[2][offset] ^= 1;
    assert!(matches!(verify_production_for(&f.prefix(), &borrowed(&proofs), &f.checkpoint, &scope()),
        Err(ProductionError::Record { position: 2, error: VerifyError::Record(_) })));
}

#[test]
fn the_whole_prefix_is_load_bearing_even_when_its_changed_leaf_is_outside_scope() {
    let f = Fixture::mixed();
    let proofs = f.inclusions(&[0, 2, 3]);
    let prefix = f.prefix();
    for end in [0, 1, prefix.len() / 2, prefix.len() - 1] {
        assert!(verify_production_for(&prefix[..end], &borrowed(&proofs), &f.checkpoint, &scope()).is_err());
    }
    let mut trailing = prefix.clone();
    trailing.push(0);
    assert!(verify_production_for(&trailing, &borrowed(&proofs), &f.checkpoint, &scope()).is_err());
    let mut changed = Fixture::mixed();
    changed.records[6].envelope.record_digest[0] ^= 1;
    assert!(matches!(verify_production_for(&changed.prefix(), &borrowed(&proofs), &f.checkpoint, &scope()),
        Err(ProductionError::Prefix(VerifyError::Root))));
    let mut reordered = Fixture::mixed();
    reordered.records.swap(5, 6);
    assert!(matches!(verify_production_for(&reordered.prefix(), &borrowed(&proofs), &f.checkpoint, &scope()),
        Err(ProductionError::Prefix(VerifyError::Order { .. }))));
    let mut omitted = Fixture::mixed();
    assert!(omitted.records.pop().is_some());
    assert!(matches!(verify_production_for(&omitted.prefix(), &borrowed(&proofs), &f.checkpoint, &scope()),
        Err(ProductionError::Prefix(VerifyError::LeafCount { .. }))));
}

#[test]
fn distinct_authentic_checkpoint_proofs_cannot_be_spliced_into_one_production() {
    let f = Fixture::mixed();
    let other = Fixture::new(vec![record(1, 0, 1, 20, Some(10))], 5);
    let authentic = other.inclusion(0, true);
    assert!(verify_inclusion(&authentic, &other.checkpoint).is_ok());
    let mut proofs = f.inclusions(&[0, 2, 3]);
    proofs[0] = authentic;
    assert!(matches!(verify_production_for(&f.prefix(), &borrowed(&proofs), &f.checkpoint, &scope()),
        Err(ProductionError::Record { error: VerifyError::NotTrusted { .. }, .. })));
}
