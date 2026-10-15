//! One authenticated native prefix replaces redundant per-entry proof copies.
//! Existing independent encoders and the existing multi-proof path are oracles.

#[path = "support/production.rs"]
mod entry_fixture;
#[path = "support/evidence_inventory.rs"]
mod fixture;
#[path = "support/evidence_production.rs"]
mod production_fixture;

use fa_verify::evidence::inventory::production::prefix::verify_evidence_prefix_for;
use fa_verify::evidence::inventory::production::{
    EvidenceProductionError, MAX_PRODUCTION_CITATIONS, verify_evidence_production_for,
};
use fa_verify::proof::production::{
    MAX_PRODUCTION_BYTES, MAX_PRODUCTION_RECORDS, ProductionError, ProductionScope,
};
use fa_verify::proof::{PREFIX_FORMAT, VerifyError};
use production_fixture::{entry, journal};

#[test]
fn direct_and_separate_proof_inventories_are_identical_for_recipient_scopes() {
    let citations = fixture::citations();
    let j = journal(&[
        entry(&citations[..1], 7, 10),
        entry(&[], 11, 20),
        entry(&citations[1..], 30, 10),
    ]);
    let records = j.records();
    for first in [0, 7, 8, 11, 12, 30] {
        for known in [7, 11, 29, 30] {
            if first > known {
                continue;
            }
            for account in [None, Some(10), Some(20), Some(99)] {
                for days in [None, Some((10, 10)), Some((20, 20)), Some((11, 19))] {
                    let scope = ProductionScope {
                        first_seq: first,
                        known_at: known,
                        account,
                        effective_days: days,
                    };
                    let selected: Vec<_> = [(7, 10), (11, 20), (30, 10)]
                        .into_iter()
                        .enumerate()
                        .filter(|(_, (seq, day))| {
                            first <= *seq
                                && *seq <= known
                                && account != Some(99)
                                && days.is_none_or(|(start, end)| start <= *day && *day <= end)
                        })
                        .map(|(index, _)| records[index])
                        .collect();
                    let prior =
                        verify_evidence_production_for(&j.prefix, &selected, &j.checkpoint, &scope)
                            .unwrap();
                    let direct =
                        verify_evidence_prefix_for(&j.prefix, &j.checkpoint, &scope).unwrap();
                    assert_eq!(direct, prior, "{scope:?}");
                }
            }
        }
    }
}

#[test]
fn empty_scopes_and_undated_controls_still_authenticate_the_entire_prefix() {
    let empty = journal(&[]);
    assert!(
        verify_evidence_prefix_for(&empty.prefix, &empty.checkpoint, &empty.scope())
            .unwrap()
            .entries
            .is_empty()
    );
    let mut control = entry(&fixture::citations(), 7, 10);
    control.proposal[36..38].copy_from_slice(&19u16.to_le_bytes());
    let j = journal(&[control]);
    assert_eq!(
        verify_evidence_prefix_for(&j.prefix, &j.checkpoint, &j.scope())
            .unwrap()
            .entries
            .len(),
        1
    );
    let scope = ProductionScope {
        effective_days: Some((i32::MIN, i32::MAX)),
        ..j.scope()
    };
    assert!(
        verify_evidence_prefix_for(&j.prefix, &j.checkpoint, &scope)
            .unwrap()
            .entries
            .is_empty()
    );
    for end in [0, 1, j.prefix.len() / 2, j.prefix.len() - 1] {
        assert!(verify_evidence_prefix_for(&j.prefix[..end], &j.checkpoint, &scope).is_err());
    }
    let mut trailing = j.prefix.clone();
    trailing.push(0);
    assert!(verify_evidence_prefix_for(&trailing, &j.checkpoint, &scope).is_err());
    let mut wrong = j.checkpoint;
    wrong.root[0] ^= 1;
    assert!(verify_evidence_prefix_for(&j.prefix, &wrong, &scope).is_err());
}

#[test]
fn a_committed_false_exclusion_selector_is_rejected_even_for_an_empty_selection() {
    let mut f = entry_fixture::Fixture::mixed();
    f.records[6].envelope.effective_day = Some(-99);
    let leaves: Vec<_> = f
        .records
        .iter()
        .map(|r| fa_verify::tree::leaf_hash(&r.envelope.encode()))
        .collect();
    f.checkpoint.root = fa_verify::tree::root_of(&leaves);
    let scope = ProductionScope {
        first_seq: 0,
        known_at: 10,
        account: Some(999),
        effective_days: None,
    };
    // The synthetic trust premise commits the dishonest envelope, not its
    // correctness. Recomputing every payload must expose the false selector.
    assert!(matches!(
        verify_evidence_prefix_for(&f.prefix(), &f.checkpoint, &scope),
        Err(EvidenceProductionError::Production(
            ProductionError::Prefix(VerifyError::Record(_))
        ))
    ));
}

#[test]
fn selected_citation_and_entry_frames_are_checked_not_just_record_digests() {
    let citations = fixture::citations();
    let mut invalid_identity = citations.clone();
    invalid_identity[0].document_oid[0] ^= 1;
    invalid_identity.sort();
    let mut invalid_frame = entry(&citations, 11, 10);
    invalid_frame.entry_envelope = vec![2, 0, 0, 0, 0];
    let mut invalid_tail = entry(&citations, 11, 10);
    invalid_tail.proposal.push(0);
    for bad in [
        entry(&invalid_identity, 11, 10),
        invalid_frame,
        invalid_tail,
    ] {
        let j = journal(&[entry(&citations, 7, 10), bad]);
        // Payload hashes and selector derivation alone accept these rehashed
        // frames. Neither inventory path may publish a partial first entry.
        fa_verify::proof::production::derivation::verify_prefix_with_records(
            &j.prefix,
            &j.checkpoint,
        )
        .unwrap();
        assert!(
            verify_evidence_production_for(&j.prefix, &j.records(), &j.checkpoint, &j.scope())
                .is_err()
        );
        assert!(matches!(
            verify_evidence_prefix_for(&j.prefix, &j.checkpoint, &j.scope()),
            Err(EvidenceProductionError::Evidence { leaf_index: 1, .. })
        ));
    }
}

fn legacy(j: &production_fixture::Journal) -> Vec<u8> {
    let read = |at| u32::from_le_bytes(j.prefix[at..at + 4].try_into().unwrap()) as usize;
    let tag_len = read(0);
    assert_eq!(tag_len, PREFIX_FORMAT.len());
    let mut at = 4 + tag_len + 80;
    let count = read(at);
    at += 4;
    for _ in 0..count {
        at += 4 + read(at);
    }
    let mut bytes = j.prefix[..at].to_vec();
    bytes[4..4 + tag_len].copy_from_slice(PREFIX_FORMAT);
    bytes
}

#[test]
fn native_mode_never_silently_downgrades_legacy_or_inclusion_inputs() {
    let j = journal(&[entry(&fixture::citations(), 7, 10)]);
    let legacy = legacy(&j);
    verify_evidence_production_for(&legacy, &j.records(), &j.checkpoint, &j.scope()).unwrap();
    for proof in [&legacy, &j.records[0]] {
        assert!(matches!(
            verify_evidence_prefix_for(proof, &j.checkpoint, &j.scope()),
            Err(EvidenceProductionError::Production(
                ProductionError::Prefix(VerifyError::Format { .. })
            ))
        ));
    }
}

#[test]
fn request_and_byte_limits_precede_decode_and_selected_record_limit_is_exact() {
    let j = journal(&[]);
    let invalid = ProductionScope {
        known_at: 1,
        ..j.scope()
    };
    assert!(matches!(
        verify_evidence_prefix_for(b"invalid", &j.checkpoint, &invalid),
        Err(EvidenceProductionError::Production(
            ProductionError::Request(_)
        ))
    ));
    let excessive = vec![0; MAX_PRODUCTION_BYTES + 1];
    assert!(matches!(
        verify_evidence_prefix_for(&excessive, &j.checkpoint, &j.scope()),
        Err(EvidenceProductionError::Production(ProductionError::Limit(
            "aggregate encoded bytes"
        )))
    ));
    let make = |count: usize| {
        entry_fixture::Fixture::new(
            (0..count)
                .map(|index| entry_fixture::record(index as u64 + 1, 0, 1, 10, Some(10)))
                .collect(),
            count as u64,
        )
    };
    let boundary = make(MAX_PRODUCTION_RECORDS);
    let scope = ProductionScope {
        first_seq: 0,
        known_at: boundary.checkpoint.through_seq,
        account: None,
        effective_days: None,
    };
    assert_eq!(
        verify_evidence_prefix_for(&boundary.prefix(), &boundary.checkpoint, &scope)
            .unwrap()
            .entries
            .len(),
        MAX_PRODUCTION_RECORDS
    );
    let excessive = make(MAX_PRODUCTION_RECORDS + 1);
    let scope = ProductionScope {
        known_at: excessive.checkpoint.through_seq,
        ..scope
    };
    assert!(matches!(
        verify_evidence_prefix_for(&excessive.prefix(), &excessive.checkpoint, &scope),
        Err(EvidenceProductionError::Production(ProductionError::Limit(
            "selected record count"
        )))
    ));
}

#[test]
fn aggregate_citation_limit_counts_associations_not_distinct_documents() {
    let mut citations: Vec<_> = (0..1024u64)
        .map(|index| {
            let mut digest = [0; 32];
            digest[..8].copy_from_slice(&index.to_le_bytes());
            fixture::citation(digest, 3)
        })
        .collect();
    citations.sort();
    let mut rows: Vec<_> = (0..64)
        .map(|index| entry(&citations, index + 1, 10))
        .collect();
    let j = journal(&rows);
    assert_eq!(
        verify_evidence_prefix_for(&j.prefix, &j.checkpoint, &j.scope())
            .unwrap()
            .citation_count,
        MAX_PRODUCTION_CITATIONS
    );
    rows.push(entry(&citations[..1], 65, 10));
    let j = journal(&rows);
    assert!(matches!(
        verify_evidence_prefix_for(&j.prefix, &j.checkpoint, &j.scope()),
        Err(EvidenceProductionError::Limit("aggregate citation count"))
    ));
}
