//! Complete-scope evidence inventories, not merely valid individual entries.

#[path = "support/evidence_inventory.rs"]
mod fixture;
#[path = "support/evidence_production.rs"]
mod production_fixture;

use fa_verify::evidence::EvidenceError;
use fa_verify::evidence::inventory::production::{
    EvidenceProductionError, MAX_PRODUCTION_CITATIONS, verify_evidence_production_for,
};
use fa_verify::proof::production::{
    MAX_PRODUCTION_BYTES, MAX_PRODUCTION_RECORDS, ProductionError, verify_production_for,
};
use production_fixture::{entry, journal};

#[test]
fn complete_map_keeps_empty_entries_repeated_documents_and_all_role_associations() {
    let citations = fixture::citations();
    let j = journal(&[entry(&citations, 7, 10), entry(&[], 11, 10), entry(&citations, 30, 10)]);
    let report = verify_evidence_production_for(
        &j.prefix, &j.records(), &j.checkpoint, &j.scope(),
    ).unwrap();
    assert_eq!(report.scope, "seq_range_complete");
    assert_eq!(report.checkpoint, j.checkpoint);
    assert_eq!(report.requested, j.scope());
    assert_eq!(report.entries.len(), 3);
    assert_eq!(report.citation_count, 6); // not three deduplicated documents
    assert_eq!(report.entries[0].citations, citations);
    assert!(report.entries[1].citations.is_empty());
    assert_eq!(report.entries[2].citations, citations);
    for (index, inventory) in report.entries.iter().enumerate() {
        assert_eq!(inventory.entry.leaf_index, index as u64);
    }
}

#[test]
fn selection_is_recipient_owned_and_historical_not_the_producers_first_and_last_rows() {
    let citations = fixture::citations();
    let j = journal(&[entry(&citations, 7, 10), entry(&[], 11, 20), entry(&citations, 30, 10)]);
    let mut scope = j.scope();
    scope.account = Some(10);
    scope.effective_days = Some((10, 10));
    let records = j.records();
    let report = verify_evidence_production_for(
        &j.prefix, &[records[0], records[2]], &j.checkpoint, &scope,
    ).unwrap();
    assert_eq!(report.entries.iter().map(|e| e.entry.leaf_index).collect::<Vec<_>>(), [0, 2]);
    // A late-recorded, early-effective entry is still required at known-at 30.
    assert!(verify_evidence_production_for(&j.prefix, &[records[0]], &j.checkpoint, &scope).is_err());
    scope.known_at = 11;
    assert_eq!(verify_evidence_production_for(
        &j.prefix, &[records[0]], &j.checkpoint, &scope,
    ).unwrap().entries.len(), 1);
    scope.first_seq = 8;
    assert!(verify_evidence_production_for(
        &j.prefix, &[], &j.checkpoint, &scope,
    ).unwrap().entries.is_empty());
    scope = j.scope();
    scope.account = Some(99);
    assert!(verify_evidence_production_for(&j.prefix, &[], &j.checkpoint, &scope).is_ok());
    assert!(verify_evidence_production_for(&j.prefix, &records, &j.checkpoint, &scope).is_err());
}

#[test]
fn genuine_inclusions_cannot_be_omitted_repeated_reordered_or_added() {
    let citations = fixture::citations();
    let j = journal(&[entry(&citations, 7, 10), entry(&[], 11, 10), entry(&citations, 30, 10)]);
    let p = j.records();
    for records in [
        vec![p[0], p[2]], vec![p[0], p[0], p[2]], vec![p[2], p[1], p[0]],
        vec![p[0], p[1], p[2], p[2]],
    ] {
        assert!(verify_evidence_production_for(&j.prefix, &records, &j.checkpoint, &j.scope()).is_err());
    }
}

#[test]
fn authentic_entry_production_does_not_excuse_a_false_citation_in_the_last_record() {
    let mut citations = fixture::citations();
    let good = entry(&citations, 7, 10);
    citations.last_mut().unwrap().document_oid[0] ^= 1;
    citations.sort();
    let j = journal(&[good, entry(&citations, 11, 10)]);
    // Rehashed record and valid root pass ordinary ENTRY production.
    assert!(verify_production_for(&j.prefix, &j.records(), &j.checkpoint, &j.scope()).is_ok());
    assert!(matches!(verify_evidence_production_for(
        &j.prefix, &j.records(), &j.checkpoint, &j.scope(),
    ), Err(EvidenceProductionError::Evidence { leaf_index: 1, error: EvidenceError::DocumentIdentity })));
}

#[test]
fn rehashed_malformed_citation_lists_envelopes_and_tail_frames_never_yield_partial_success() {
    let citations = fixture::citations();
    let mut reversed = citations.clone();
    reversed.reverse();
    let mut trailing = entry(&citations, 11, 10);
    trailing.proposal.push(0);
    let mut envelope = entry(&citations, 11, 10);
    envelope.entry_envelope = vec![2, 0, 0, 0, 0];
    for bad in [
        entry(&reversed, 11, 10), entry(&[citations[0], citations[0]], 11, 10), trailing, envelope,
    ] {
        let j = journal(&[entry(&citations, 7, 10), bad]);
        assert!(verify_production_for(&j.prefix, &j.records(), &j.checkpoint, &j.scope()).is_ok());
        assert!(matches!(verify_evidence_production_for(
            &j.prefix, &j.records(), &j.checkpoint, &j.scope(),
        ), Err(EvidenceProductionError::Evidence { leaf_index: 1, .. })));
    }
}

#[test]
fn empty_production_needs_a_verified_empty_scope_and_malformed_requests_fail_first() {
    let j = journal(&[]);
    let report = verify_evidence_production_for(&j.prefix, &[], &j.checkpoint, &j.scope()).unwrap();
    assert_eq!(report.citation_count, 0);
    assert!(report.entries.is_empty());
    assert!(verify_evidence_production_for(&[], &[], &j.checkpoint, &j.scope()).is_err());
    let mut bad = j.scope();
    bad.first_seq = 1;
    assert!(matches!(verify_evidence_production_for(b"invalid", &[], &j.checkpoint, &bad),
        Err(EvidenceProductionError::Production(ProductionError::Request(_)))));
    bad = j.scope();
    bad.known_at = 1; // no authenticated later frontier
    assert!(matches!(verify_evidence_production_for(b"invalid", &[], &j.checkpoint, &bad),
        Err(EvidenceProductionError::Production(ProductionError::Request(_)))));
    bad = j.scope();
    bad.effective_days = Some((20, 10));
    assert!(matches!(verify_evidence_production_for(b"invalid", &[], &j.checkpoint, &bad),
        Err(EvidenceProductionError::Production(ProductionError::Request(_)))));
}

#[test]
fn only_selected_payloads_are_required_but_every_selected_payload_is_mandatory() {
    let citations = fixture::citations();
    let good = entry(&citations, 7, 10);
    let mut missing = entry(&citations, 11, 20);
    missing.include_record = false;
    let j = journal(&[good, missing]);
    let mut scope = j.scope();
    scope.effective_days = Some((10, 10));
    assert!(verify_evidence_production_for(&j.prefix, &[&j.records[0]], &j.checkpoint, &scope).is_ok());
    assert!(matches!(verify_evidence_production_for(
        &j.prefix, &j.records(), &j.checkpoint, &j.scope(),
    ), Err(EvidenceProductionError::Production(ProductionError::PayloadRequired { index: 1 }))));
}

#[test]
fn wrong_anchors_other_histories_and_corrupted_prefixes_cannot_authorize_an_inventory() {
    let citations = fixture::citations();
    let j = journal(&[entry(&citations, 7, 10), entry(&[], 11, 10)]);
    let other = journal(&[entry(&[], 7, 10), entry(&citations, 11, 10)]);
    assert!(verify_evidence_production_for(&j.prefix, &other.records(), &j.checkpoint, &j.scope()).is_err());
    let mut wrong = j.checkpoint;
    wrong.root[0] ^= 1;
    assert!(verify_evidence_production_for(&j.prefix, &j.records(), &wrong, &j.scope()).is_err());
    for end in 0..j.prefix.len() {
        assert!(verify_evidence_production_for(&j.prefix[..end], &j.records(), &j.checkpoint, &j.scope()).is_err());
    }
    let mut trailing = j.prefix.clone();
    trailing.push(0);
    assert!(verify_evidence_production_for(&trailing, &j.records(), &j.checkpoint, &j.scope()).is_err());
}

#[test]
fn record_and_total_byte_budgets_apply_to_the_composition_not_individual_files_only() {
    let j = journal(&[]);
    let too_many = vec![&[][..]; MAX_PRODUCTION_RECORDS + 1];
    assert!(matches!(verify_evidence_production_for(&j.prefix, &too_many, &j.checkpoint, &j.scope()),
        Err(EvidenceProductionError::Production(ProductionError::Limit("record count")))));
    // Reuse the same borrowed buffer: individually admitted slices together
    // exceed the composition's byte budget without a 64 MiB allocation.
    let chunk = vec![0; MAX_PRODUCTION_BYTES / MAX_PRODUCTION_RECORDS];
    let too_large = vec![chunk.as_slice(); MAX_PRODUCTION_RECORDS];
    assert!(matches!(verify_evidence_production_for(&j.prefix, &too_large, &j.checkpoint, &j.scope()),
        Err(EvidenceProductionError::Production(ProductionError::Limit("aggregate encoded bytes")))));
}

#[test]
fn aggregate_citation_boundary_retains_associations_and_refuses_one_more_row() {
    let mut citations: Vec<_> = (0..1024u64).map(|index| {
        let mut commitment = [0; 32];
        commitment[..8].copy_from_slice(&index.to_le_bytes());
        fixture::citation(commitment, 3)
    }).collect();
    citations.sort();
    let mut entries: Vec<_> = (0..64).map(|index| entry(&citations, index + 1, 10)).collect();
    let j = journal(&entries);
    let report = verify_evidence_production_for(&j.prefix, &j.records(), &j.checkpoint, &j.scope()).unwrap();
    assert_eq!(report.citation_count, MAX_PRODUCTION_CITATIONS);
    assert_eq!(report.entries.len(), 64);
    entries.push(entry(&citations[..1], 65, 10));
    let j = journal(&entries);
    assert!(matches!(verify_evidence_production_for(&j.prefix, &j.records(), &j.checkpoint, &j.scope()),
        Err(EvidenceProductionError::Limit("aggregate citation count"))));
}

#[test]
fn envelope_only_scope_selection_does_not_invent_control_dates_or_posted_semantics() {
    // Deliberately a wire-only fixture, not a kernel-admissible control entry.
    let mut control = entry(&fixture::citations(), 7, 10);
    control.proposal[36..38].copy_from_slice(&19u16.to_le_bytes());
    let j = journal(&[control]);
    assert!(verify_evidence_production_for(&j.prefix, &j.records(), &j.checkpoint, &j.scope()).is_ok());
    let mut dated = j.scope();
    dated.effective_days = Some((i32::MIN, i32::MAX));
    assert!(verify_evidence_production_for(&j.prefix, &[], &j.checkpoint, &dated).unwrap().entries.is_empty());
    assert!(verify_evidence_production_for(&j.prefix, &j.records(), &j.checkpoint, &dated).is_err());
}

#[test]
fn one_entry_composition_agrees_with_the_existing_independently_requested_inventory() {
    let citations = fixture::citations();
    let p = fixture::proposal(&citations);
    let f = fixture::proof(&p.bytes, true, 7);
    let original = fa_verify::evidence::inventory::verify_evidence_inventory_for(
        &f.proof, &f.checkpoint, &f.entry_digest,
    ).unwrap();
    let j = journal(&[entry(&citations, 7, 20_527)]);
    let composed = verify_evidence_production_for(
        &j.prefix, &j.records(), &j.checkpoint, &j.scope(),
    ).unwrap();
    assert_eq!(composed.entries[0].entry.envelope, original.inclusion.envelope);
    assert_eq!(composed.entries[0].citations, original.citations);
    // Keep per-entry count and tail validation active inside a production,
    // even when the producer recomputes both digests and the checkpoint root.
    for offset in [p.count_offset, p.tail_offset + 4] {
        let mut malformed = entry(&citations, 7, 20_527);
        if offset == p.count_offset {
            malformed.proposal[offset..offset + 4].copy_from_slice(&1025u32.to_le_bytes());
        } else {
            malformed.proposal[offset] = 2; // invalid optional pending tag
        }
        let j = journal(&[malformed]);
        assert!(verify_evidence_production_for(&j.prefix, &j.records(), &j.checkpoint, &j.scope()).is_err());
    }
}
