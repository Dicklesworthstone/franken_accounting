//! Producer-independent supplemental evidence and document productions.
//!
//! Every negative fixture repairs the supplemental record digest and the
//! prefix root. A valid commitment alone must never substitute for the
//! target join, known-at boundary, complete citation set or document bytes.

#[path = "support/evidence_inventory.rs"]
mod fixture;
#[path = "support/evidence_supplements.rs"]
mod supplement_fixture;

use fa_verify::document::doc_commit;
use fa_verify::evidence::EvidenceCitation;
use fa_verify::evidence::inventory::production::documents::{
    DocumentContent, DocumentProductionError, MAX_PRODUCTION_DOCUMENTS,
};
use fa_verify::evidence::inventory::production::prefix::verify_evidence_prefix_for;
use fa_verify::evidence::inventory::production::supplements::{
    verify_supplemented_document_prefix_for, verify_supplemented_evidence_prefix_for,
};
use fa_verify::evidence::inventory::production::{
    EvidenceProductionError, MAX_PRODUCTION_CITATIONS,
};
use fa_verify::proof::production::ProductionScope;
use fa_verify::proof::production::derivation::verify_prefix_with_records;
use supplement_fixture::{Journal, Target, posting, supplement, supplement_body};

const PRIVATE_DOCUMENT: &[u8] = b"SUPPLEMENT_CONTENT_MUST_NOT_APPEAR_IN_METADATA";

fn document(kind: u8, bytes: &[u8]) -> DocumentContent<'_> {
    let citation = fixture::citation(doc_commit(kind, bytes), 3);
    DocumentContent {
        document_oid: citation.document_oid,
        kind,
        bytes,
    }
}

fn citation(document: DocumentContent<'_>, role: u8) -> EvidenceCitation {
    fixture::citation(doc_commit(document.kind, document.bytes), role)
}

fn sorted(mut citations: Vec<EvidenceCitation>) -> Vec<EvidenceCitation> {
    citations.sort();
    citations
}

fn distinct_citations(count: usize) -> Vec<EvidenceCitation> {
    sorted(
        (0..count)
            .map(|index| {
                let mut commitment = [0; 32];
                commitment[..8].copy_from_slice(&(index as u64).to_le_bytes());
                fixture::citation(commitment, 3)
            })
            .collect(),
    )
}

#[test]
fn original_lists_stay_unchanged_while_each_later_attachment_is_attributed() {
    let one = document(1, PRIVATE_DOCUMENT);
    let two = document(255, &[]);
    let original = vec![citation(one, 3)];
    let later = sorted(vec![citation(one, 4), citation(two, 255)]);
    let (entry, target) = posting(7, 7, 10, &original);
    let first = supplement(target, &later, 11, 91);
    let second = supplement(target, &original, 30, 92);
    let first_digest = first.envelope.record_digest;
    let second_digest = second.envelope.record_digest;
    let j = Journal::new(&[entry, first, second], 30);
    let prior = verify_evidence_prefix_for(&j.prefix, &j.checkpoint, &j.scope()).unwrap();
    let result =
        verify_supplemented_evidence_prefix_for(&j.prefix, &j.checkpoint, &j.scope()).unwrap();
    assert_eq!(result.inventory, prior);
    assert_eq!(result.inventory.citation_count, 1);
    assert_eq!(result.inventory.entries[0].citations, original);
    assert_eq!(result.citation_count, 4);
    assert_eq!(result.supplements.len(), 2);
    for (row, leaf, seq, digest, author, cites) in [
        (&result.supplements[0], 1, 11, first_digest, 91, &later),
        (&result.supplements[1], 2, 30, second_digest, 92, &original),
    ] {
        assert_eq!(row.leaf_index, leaf);
        assert_eq!(row.recorded_at, seq);
        assert_eq!(row.record_digest, digest);
        assert_eq!(row.entry_vid, target.vid);
        assert_eq!(row.entry_digest, target.digest);
        assert_eq!(row.attached_by, author);
        assert_eq!(&row.citations, cites);
    }
    let mut documents = [one, two];
    documents.sort_by_key(|doc| doc.document_oid);
    let report =
        verify_supplemented_document_prefix_for(&j.prefix, &documents, &j.checkpoint, &j.scope())
            .unwrap();
    assert_eq!(report.inventory, result);
    assert_eq!(report.document_scope, "recomputation");
    assert_eq!(report.documents.len(), 2);
    assert_eq!(report.document_byte_count, PRIVATE_DOCUMENT.len() as u64);
    for verified in &report.documents {
        let expected = if verified.document_oid == one.document_oid {
            3
        } else {
            1
        };
        assert_eq!(verified.citation_count, expected);
    }
    let debug = format!("{report:?}");
    assert!(!debug.contains(std::str::from_utf8(PRIVATE_DOCUMENT).unwrap()));
    assert!(!debug.contains(std::str::from_utf8(fixture::SECRET).unwrap()));
}

#[test]
fn recipient_scope_selects_targets_and_known_at_selects_their_attachments() {
    let cites = fixture::citations()[..1].to_vec();
    let (first, first_target) = posting(1, 7, 10, &cites);
    let (second, second_target) = posting(2, 11, 20, &[]);
    let j = Journal::new(
        &[
            first,
            supplement(first_target, &cites, 8, 8),
            second,
            supplement(second_target, &cites, 20, 20),
            supplement(first_target, &cites, 30, 30),
        ],
        30,
    );
    for known in [7, 8, 11, 19, 20, 29, 30] {
        for first_seq in [0, 7, 8, 11, 12] {
            if first_seq > known {
                continue;
            }
            for account in [None, Some(10), Some(99)] {
                for days in [None, Some((10, 10)), Some((20, 20)), Some((11, 19))] {
                    let scope = ProductionScope {
                        first_seq,
                        known_at: known,
                        account,
                        effective_days: days,
                    };
                    let selects = |seq, day| {
                        first_seq <= seq
                            && seq <= known
                            && account != Some(99)
                            && days.is_none_or(|(start, end)| start <= day && day <= end)
                    };
                    let first_selected = selects(7, 10);
                    let second_selected = selects(11, 20);
                    let expected: Vec<_> = [
                        (1, 8, first_target, first_selected),
                        (3, 20, second_target, second_selected),
                        (4, 30, first_target, first_selected),
                    ]
                    .into_iter()
                    .filter(|(_, seq, _, selected)| *selected && *seq <= known)
                    .map(|(leaf, seq, target, _)| (leaf, seq, target.vid))
                    .collect();
                    let result =
                        verify_supplemented_evidence_prefix_for(&j.prefix, &j.checkpoint, &scope)
                            .unwrap();
                    assert_eq!(
                        result
                            .supplements
                            .iter()
                            .map(|row| (row.leaf_index, row.recorded_at, row.entry_vid))
                            .collect::<Vec<_>>(),
                        expected,
                        "{scope:?}",
                    );
                    assert_eq!(
                        result.inventory.entries.len(),
                        usize::from(first_selected) + usize::from(second_selected),
                    );
                    assert_eq!(
                        result.citation_count,
                        usize::from(first_selected) + expected.len(),
                    );
                }
            }
        }
    }
}

#[test]
fn rehashed_orphan_wrong_digest_future_and_ambiguous_targets_are_refused() {
    let cites = fixture::citations()[..1].to_vec();
    let (entry, target) = posting(1, 7, 10, &[]);
    let mut wrong_digest = target;
    wrong_digest.digest[0] ^= 1;
    let (future, future_target) = posting(2, 20, 10, &[]);
    let (duplicate, _) = posting(1, 8, 10, &[]);
    let cases = [
        vec![
            entry.clone(),
            supplement(
                Target {
                    vid: target.vid ^ 1,
                    ..target
                },
                &cites,
                11,
                8,
            ),
        ],
        vec![entry.clone(), supplement(wrong_digest, &cites, 11, 8)],
        vec![supplement(future_target, &cites, 11, 8), future],
        vec![entry, duplicate, supplement(target, &cites, 11, 8)],
    ];
    for records in cases {
        let j = Journal::new(&records, 30);
        // These are authentic and well-framed records. Their reference graph
        // is invalid, including when the requested selection would be empty.
        verify_prefix_with_records(&j.prefix, &j.checkpoint).unwrap();
        for account in [None, Some(99)] {
            let scope = ProductionScope {
                account,
                ..j.scope()
            };
            assert!(
                verify_supplemented_evidence_prefix_for(&j.prefix, &j.checkpoint, &scope).is_err(),
                "invalid target was accepted for {scope:?}",
            );
        }
    }
}

#[test]
fn a_supplement_requires_a_target_from_an_earlier_commit() {
    let cites = fixture::citations()[..1].to_vec();
    let (entry, target) = posting(1, 7, 10, &[]);
    let mut same_commit = supplement(target, &cites, 7, 8);
    same_commit.envelope.within_commit_ordinal = 1;
    let j = Journal::new(&[entry, same_commit], 7);
    verify_prefix_with_records(&j.prefix, &j.checkpoint).unwrap();
    assert!(verify_supplemented_evidence_prefix_for(&j.prefix, &j.checkpoint, &j.scope()).is_err());
}

#[test]
fn future_reference_defects_are_outside_the_known_at_claim_but_not_authentication() {
    let cites = fixture::citations()[..1].to_vec();
    let (entry, target) = posting(1, 7, 10, &[]);
    let wrong = Target {
        vid: target.vid ^ 1,
        ..target
    };
    let j = Journal::new(&[entry, supplement(wrong, &cites, 30, 8)], 30);
    let scope = ProductionScope {
        known_at: 7,
        ..j.scope()
    };
    let result = verify_supplemented_evidence_prefix_for(&j.prefix, &j.checkpoint, &scope).unwrap();
    assert_eq!(result.inventory.entries.len(), 1);
    assert!(result.supplements.is_empty());
    assert!(verify_supplemented_evidence_prefix_for(&j.prefix, &j.checkpoint, &j.scope()).is_err());
    let mut corrupt = j.prefix.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(verify_supplemented_evidence_prefix_for(&corrupt, &j.checkpoint, &scope).is_err());
}

#[test]
fn duplicate_record_identities_never_multiply_supplement_citation_counts() {
    let cites = fixture::citations()[..1].to_vec();
    let (entry, target) = posting(1, 7, 10, &[]);
    let first = supplement(target, &cites, 11, 8);
    let second = supplement(target, &cites, 20, 8);
    assert_eq!(first.envelope.record_digest, second.envelope.record_digest);
    let j = Journal::new(&[entry, first, second], 20);
    verify_prefix_with_records(&j.prefix, &j.checkpoint).unwrap();
    assert!(verify_supplemented_evidence_prefix_for(&j.prefix, &j.checkpoint, &j.scope()).is_err());
}

#[test]
fn citation_identity_order_uniqueness_and_nonempty_bounds_survive_rehashing() {
    let (entry, target) = posting(1, 7, 10, &[]);
    let valid = fixture::citations();
    let mut wrong_identity = valid[..1].to_vec();
    wrong_identity[0].document_oid[0] ^= 1;
    let j = Journal::new(
        &[entry.clone(), supplement(target, &wrong_identity, 11, 8)],
        11,
    );
    verify_prefix_with_records(&j.prefix, &j.checkpoint).unwrap();
    assert!(verify_supplemented_evidence_prefix_for(&j.prefix, &j.checkpoint, &j.scope()).is_err());

    let mut reversed = valid.clone();
    reversed.reverse();
    for cites in [
        vec![],
        vec![valid[0], valid[0]],
        reversed,
        distinct_citations(1025),
    ] {
        let j = Journal::new(&[entry.clone(), supplement(target, &cites, 11, 8)], 11);
        assert!(
            verify_supplemented_evidence_prefix_for(&j.prefix, &j.checkpoint, &j.scope()).is_err()
        );
    }
    let original = supplement(target, &valid, 11, 8);
    let mut wrong_version = original.payload[..original.split].to_vec();
    wrong_version[..2].copy_from_slice(&2u16.to_le_bytes());
    let mut trailing = original.payload[..original.split].to_vec();
    trailing.push(0);
    for body in [wrong_version, trailing] {
        let j = Journal::new(&[entry.clone(), supplement_body(body, 11, 0)], 11);
        assert!(
            verify_supplemented_evidence_prefix_for(&j.prefix, &j.checkpoint, &j.scope()).is_err()
        );
    }
}

#[test]
fn combined_citation_budget_counts_original_and_supplement_associations() {
    let cites = distinct_citations(1024);
    let (entry, target) = posting(1, 1, 10, &cites);
    let mut records = vec![entry];
    for seq in 2..=64 {
        records.push(supplement(target, &cites, seq, u128::from(seq)));
    }
    let boundary = Journal::new(&records, 64);
    let result = verify_supplemented_evidence_prefix_for(
        &boundary.prefix,
        &boundary.checkpoint,
        &boundary.scope(),
    )
    .unwrap();
    assert_eq!(result.inventory.citation_count, 1024);
    assert_eq!(result.supplements.len(), 63);
    assert_eq!(result.citation_count, MAX_PRODUCTION_CITATIONS);
    records.push(supplement(target, &cites[..1], 65, 65));
    let excessive = Journal::new(&records, 65);
    assert!(matches!(
        verify_supplemented_evidence_prefix_for(
            &excessive.prefix,
            &excessive.checkpoint,
            &excessive.scope(),
        ),
        Err(EvidenceProductionError::Limit("aggregate citation count")),
    ));
}

#[test]
fn supplemental_documents_require_the_exact_distinct_union_and_complete_bytes() {
    let one = document(1, b"original");
    let two = document(2, b"late invoice");
    let extra = document(3, b"uncited");
    let (entry, target) = posting(1, 7, 10, &[citation(one, 3)]);
    let j = Journal::new(&[entry, supplement(target, &[citation(two, 4)], 11, 8)], 11);
    let mut docs = [one, two];
    docs.sort_by_key(|doc| doc.document_oid);
    verify_supplemented_document_prefix_for(&j.prefix, &docs, &j.checkpoint, &j.scope()).unwrap();
    for mut supplied in [vec![], vec![one], vec![two], vec![one, two, extra]] {
        supplied.sort_by_key(|doc| doc.document_oid);
        assert!(matches!(
            verify_supplemented_document_prefix_for(
                &j.prefix,
                &supplied,
                &j.checkpoint,
                &j.scope(),
            ),
            Err(DocumentProductionError::DocumentCount { .. }),
        ));
    }
    for supplied in [[docs[0], docs[0]], [docs[1], docs[0]]] {
        assert!(matches!(
            verify_supplemented_document_prefix_for(
                &j.prefix,
                &supplied,
                &j.checkpoint,
                &j.scope(),
            ),
            Err(DocumentProductionError::Order { .. }),
        ));
    }
    let mut substituted = [one, extra];
    substituted.sort_by_key(|doc| doc.document_oid);
    assert!(
        verify_supplemented_document_prefix_for(
            &j.prefix, &substituted, &j.checkpoint, &j.scope(),
        ).is_err()
    );
    for bad in [
        DocumentContent {
            bytes: b"changed",
            ..two
        },
        DocumentContent { kind: 99, ..two },
        DocumentContent { bytes: &[], ..two },
    ] {
        let mut supplied = [one, bad];
        supplied.sort_by_key(|doc| doc.document_oid);
        assert!(matches!(
            verify_supplemented_document_prefix_for(
                &j.prefix,
                &supplied,
                &j.checkpoint,
                &j.scope(),
            ),
            Err(DocumentProductionError::Commitment { .. }),
        ));
    }
}

#[test]
fn a_supplement_can_be_the_only_source_of_an_empty_document_citation() {
    let doc = document(0, &[]);
    let (entry, target) = posting(1, 7, 10, &[]);
    let j = Journal::new(
        &[entry, supplement(target, &[citation(doc, 255)], 11, 8)],
        11,
    );
    assert!(matches!(
        verify_supplemented_document_prefix_for(&j.prefix, &[], &j.checkpoint, &j.scope()),
        Err(DocumentProductionError::DocumentCount {
            expected: 1,
            actual: 0
        }),
    ));
    let report =
        verify_supplemented_document_prefix_for(&j.prefix, &[doc], &j.checkpoint, &j.scope())
            .unwrap();
    assert_eq!(report.inventory.inventory.citation_count, 0);
    assert_eq!(report.inventory.citation_count, 1);
    assert_eq!(report.documents.len(), 1);
    assert_eq!(report.document_byte_count, 0);
}

#[test]
fn authentication_and_independent_request_validation_hold_for_empty_selections() {
    let (entry, target) = posting(1, 7, 10, &[]);
    let j = Journal::new(
        &[entry, supplement(target, &fixture::citations(), 11, 8)],
        11,
    );
    let scope = ProductionScope {
        account: Some(99),
        ..j.scope()
    };
    let result =
        verify_supplemented_document_prefix_for(&j.prefix, &[], &j.checkpoint, &scope).unwrap();
    assert!(result.inventory.inventory.entries.is_empty());
    assert!(result.inventory.supplements.is_empty());
    assert!(result.documents.is_empty());
    for end in [0, 1, j.prefix.len() / 2, j.prefix.len() - 1] {
        assert!(
            verify_supplemented_evidence_prefix_for(&j.prefix[..end], &j.checkpoint, &scope)
                .is_err()
        );
    }
    let mut trailing = j.prefix.clone();
    trailing.push(0);
    assert!(verify_supplemented_evidence_prefix_for(&trailing, &j.checkpoint, &scope).is_err());
    let mut wrong = j.checkpoint;
    wrong.root[0] ^= 1;
    assert!(verify_supplemented_evidence_prefix_for(&j.prefix, &wrong, &scope).is_err());
    for bad in [
        ProductionScope {
            known_at: 12,
            ..scope
        },
        ProductionScope {
            first_seq: 12,
            ..scope
        },
        ProductionScope {
            effective_days: Some((2, 1)),
            ..scope
        },
    ] {
        assert!(matches!(
            verify_supplemented_evidence_prefix_for(b"invalid", &j.checkpoint, &bad),
            Err(EvidenceProductionError::Production(
                fa_verify::proof::production::ProductionError::Request(_),
            )),
        ));
    }
}

#[test]
fn document_byte_and_count_limits_are_enforced_before_prefix_authentication() {
    let j = Journal::new(&[], 0);
    let bytes = [0; 1024];
    let doc = DocumentContent {
        document_oid: [0; 32],
        kind: 1,
        bytes: &bytes,
    };
    let shared = vec![doc; MAX_PRODUCTION_DOCUMENTS];
    assert!(matches!(
        verify_supplemented_document_prefix_for(b"invalid", &shared, &j.checkpoint, &j.scope(),),
        Err(DocumentProductionError::Limit("aggregate input bytes")),
    ));
    let too_many = vec![DocumentContent { bytes: &[], ..doc }; MAX_PRODUCTION_DOCUMENTS + 1];
    assert!(matches!(
        verify_supplemented_document_prefix_for(b"invalid", &too_many, &j.checkpoint, &j.scope(),),
        Err(DocumentProductionError::Limit("document count")),
    ));
}

fn framed_vid(domain: &[u8], parts: &[&[u8]]) -> u128 {
    let mut wire = fixture::Wire::default();
    for part in parts {
        wire.bytes(part);
    }
    let digest = fa_verify::blake3::hash_parts(domain, &[&wire.0]);
    u128::from_le_bytes(digest[..16].try_into().unwrap())
}

fn intent_origin() -> Vec<u8> {
    let mut wire = fixture::Wire::default();
    wire.u8(0).fixed(&[9; 32]).u16(1);
    wire.0
}

fn identity_proposal(
    class: u16,
    origin: &[u8],
    pending: &[u8],
    extensions: &[(u16, &[u8])],
) -> Vec<u8> {
    let original = fixture::proposal(&[]);
    // This independent fixture's Intent origin is 1 + 32 + 2 bytes. Preserve
    // its key, principal, entry framing and zero original citation list.
    let origin_end = original.count_offset - 17;
    let mut proposal = original.bytes[..origin_end - 35].to_vec();
    proposal[36..38].copy_from_slice(&class.to_le_bytes());
    proposal.extend_from_slice(origin);
    proposal.extend_from_slice(&original.bytes[origin_end..original.tail_offset]);
    let mut tail = fixture::Wire::default();
    tail.u32(0) // supersession
        .fixed(pending)
        .u32(0) // external IDs
        .u32(0) // tags
        .u32(extensions.len() as u32);
    for (tag, bytes) in extensions {
        tail.u16(*tag).bytes(bytes);
    }
    proposal.extend_from_slice(&tail.0);
    proposal
}

fn identity_journal(proposal: Vec<u8>, vid: u128) -> Journal {
    let record = supplement_fixture::proposal_record(proposal, 7);
    let target = Target {
        vid,
        digest: record.envelope.record_digest,
    };
    Journal::new(
        &[record, supplement(target, &fixture::citations(), 11, 8)],
        11,
    )
}

fn assert_specialized_identity(proposal: Vec<u8>, expected_vid: u128) {
    let correct = identity_journal(proposal.clone(), expected_vid);
    let report = verify_supplemented_evidence_prefix_for(
        &correct.prefix,
        &correct.checkpoint,
        &correct.scope(),
    )
    .unwrap();
    assert_eq!(report.supplements[0].entry_vid, expected_vid);
    let (_, ordinary) = posting(7, 7, 20_527, &[]);
    assert_ne!(ordinary.vid, expected_vid);
    let false_identity = identity_journal(proposal, ordinary.vid);
    verify_prefix_with_records(&false_identity.prefix, &false_identity.checkpoint).unwrap();
    assert!(
        verify_supplemented_evidence_prefix_for(
            &false_identity.prefix,
            &false_identity.checkpoint,
            &false_identity.scope(),
        )
        .is_err()
    );
}

#[test]
fn migrated_targets_use_the_migration_run_namespace_not_the_preparer_key() {
    let run = 601u128;
    let mut origin = fixture::Wire::default();
    origin
        .u8(2)
        .u128(run)
        .bytes(b"legacy")
        .fixed(&[0; 32]) // source ID: canonical erasable string
        .u8(0)
        .fixed(&[0; 24])
        .bytes(b"legacy-row")
        .u8(0) // source-recorded timestamp
        .u8(0) // source preparer
        .u8(0) // source approver
        .fixed(&[21; 32]); // import batch
    let vid = framed_vid(
        b"fa:vid:migration-entry:v1",
        &[&fixture::BOOK, &run.to_le_bytes(), b"evidence-inventory"],
    );
    assert_specialized_identity(identity_proposal(12, &origin.0, &[0], &[]), vid);
    // A valid origin cannot silently turn an ordinary Original into a
    // Migration target. The immutable class is part of this identity law.
    let wrong_class = identity_journal(identity_proposal(1, &origin.0, &[0], &[]), vid);
    verify_prefix_with_records(&wrong_class.prefix, &wrong_class.checkpoint).unwrap();
    assert!(
        verify_supplemented_evidence_prefix_for(
            &wrong_class.prefix,
            &wrong_class.checkpoint,
            &wrong_class.scope(),
        )
        .is_err()
    );
}

#[test]
fn resolution_targets_use_the_pending_target_identity_not_the_preparer_key() {
    let pending_target = 602u128;
    let mut pending = fixture::Wire::default();
    pending
        .u8(1)
        .u8(0) // no timeout on the resolution
        .u8(1)
        .u128(pending_target)
        .fixed(&[22; 32])
        .u8(1)
        .u8(3) // Posts: both original ordinals
        .u32(2)
        .u16(0)
        .u16(1);
    let digest =
        fa_verify::blake3::hash_parts(b"fa:vid:resolution:v1", &[&pending_target.to_le_bytes()]);
    let vid = u128::from_le_bytes(digest[..16].try_into().unwrap());
    assert_specialized_identity(identity_proposal(3, &intent_origin(), &pending.0, &[]), vid);
    let missing = identity_journal(identity_proposal(3, &intent_origin(), &[0], &[]), vid);
    verify_prefix_with_records(&missing.prefix, &missing.checkpoint).unwrap();
    assert!(
        verify_supplemented_evidence_prefix_for(
            &missing.prefix,
            &missing.checkpoint,
            &missing.scope()
        )
        .is_err()
    );
}

#[test]
fn recurring_targets_bind_the_occurrence_index_and_matching_schedule_origin() {
    let schedule = 603u128;
    let index = 41u64;
    let tick = 604u128;
    let mut origin = fixture::Wire::default();
    origin.u8(5).u128(schedule).u8(0).u128(tick);
    let mut occurrence = fixture::Wire::default();
    occurrence.u16(1).u128(schedule).u64(index).u128(tick);
    let vid = framed_vid(
        b"fa:vid:recurring:v1",
        &[&schedule.to_le_bytes(), &index.to_le_bytes()],
    );
    assert_specialized_identity(
        identity_proposal(1, &origin.0, &[0], &[(31, &occurrence.0)]),
        vid,
    );
    let mut other_origin = fixture::Wire::default();
    other_origin.u8(5).u128(schedule).u8(0).u128(tick + 1);
    for proposal in [
        identity_proposal(1, &other_origin.0, &[0], &[(31, &occurrence.0)]),
        identity_proposal(1, &origin.0, &[0], &[]),
    ] {
        let wrong = identity_journal(proposal, vid);
        verify_prefix_with_records(&wrong.prefix, &wrong.checkpoint).unwrap();
        assert!(
            verify_supplemented_evidence_prefix_for(
                &wrong.prefix,
                &wrong.checkpoint,
                &wrong.scope()
            )
            .is_err()
        );
    }
}

#[test]
fn replacement_and_control_targets_refuse_instead_of_guessing_a_key_identity() {
    let (_, ordinary) = posting(7, 7, 20_527, &[]);
    for (class, proposal) in [
        (5, identity_proposal(5, &intent_origin(), &[0], &[])),
        (19, fixture::control_proposal(&[], 19).bytes),
    ] {
        let unrelated = Journal::new(
            &[supplement_fixture::proposal_record(proposal.clone(), 7)],
            7,
        );
        assert!(
            verify_supplemented_evidence_prefix_for(
                &unrelated.prefix,
                &unrelated.checkpoint,
                &unrelated.scope(),
            )
            .unwrap()
            .supplements
            .is_empty()
        );
        // Even a digest-correct claim of the historical ordinary-key VID is
        // insufficient for a family whose target identity is unsupported.
        let referenced = identity_journal(proposal, ordinary.vid);
        verify_prefix_with_records(&referenced.prefix, &referenced.checkpoint).unwrap();
        assert!(matches!(
            verify_supplemented_evidence_prefix_for(
                &referenced.prefix,
                &referenced.checkpoint,
                &referenced.scope(),
            ),
            Err(EvidenceProductionError::UnsupportedTargetIdentity {
                class: actual,
                ..
            }) if actual == class,
        ));
    }
}

/// Wire-only receipt with an explicit discount: Dr cash 121, Dr discount 2,
/// Cr AR 123 applying the complete invoice. Extension 41 only names the roles
/// of the actual legs; the entry's ordinary key identity is unchanged.
fn application_terms_proposal(minor: u16, invoice: Target) -> Vec<u8> {
    let mut terms = fixture::Wire::default();
    terms
        .u16(1) // application terms version
        .u8(1) // Receipt
        .u16(0) // cash ordinal
        .u16(1) // applying ordinal
        .u32(1) // one named difference
        .u16(2)
        .u8(1); // Discount
    let mut p = fixture::Wire::default();
    p.u16(1)
        .u16(minor)
        .fixed(&fixture::BOOK)
        .fixed(&[0; 16])
        .u16(1) // Original
        .fixed(&20_527i32.to_le_bytes())
        .u8(0) // document date
        .fixed(&[0; 32]) // description digest
        .u8(0) // description subject
        .fixed(&[0; 24])
        .bytes(fixture::SECRET)
        .u8(0) // effective period
        .u32(3);
    for (ordinal, side, account, amount) in [(0, 0, 30, 121), (1, 1, 10, 123), (2, 0, 40, 2)] {
        p.u8(side)
            .u128(account)
            .u32(1)
            .i128(amount)
            .u8(0) // base valuation
            .u32(0) // dimensions
            .u8(0) // memo
            .u32(u32::from(ordinal == 1));
        if ordinal == 1 {
            p.u128(invoice.vid)
                .fixed(&invoice.digest)
                .u16(0)
                .u32(1)
                .i128(123);
        }
    }
    p.u8(0) // control
        .u32(1) // unit totals
        .u32(1)
        .i128(123)
        .i128(123)
        .u8(0) // base totals
        .bytes(b"evidence-inventory")
        .fixed(&intent_origin())
        .u128(7)
        .u8(0) // session
        .u32(0) // original evidence
        .u32(0) // supersession
        .u8(0) // pending
        .u32(0) // external IDs
        .u32(0) // tags
        .u32(1) // extensions
        .u16(41)
        .bytes(&terms.0);
    p.0
}

#[test]
fn minor_nine_application_terms_preserve_target_identity_but_future_minors_refuse() {
    let (invoice, invoice_target) = posting(8, 3, 20_527, &[]);
    let (_, ordinary_target) = posting(7, 7, 20_527, &[]);
    for minor in [9, 10] {
        let receipt = supplement_fixture::proposal_record(
            application_terms_proposal(minor, invoice_target),
            7,
        );
        let receipt_target = Target {
            vid: ordinary_target.vid,
            digest: receipt.envelope.record_digest,
        };
        let j = Journal::new(
            &[
                invoice.clone(),
                receipt,
                supplement(receipt_target, &fixture::citations(), 11, 8),
            ],
            11,
        );
        // Generic membership and original-only citation framing still accept
        // additive extensions. Target identity is the narrower supported claim.
        verify_prefix_with_records(&j.prefix, &j.checkpoint).unwrap();
        let original = verify_evidence_prefix_for(&j.prefix, &j.checkpoint, &j.scope()).unwrap();
        let verified =
            verify_supplemented_evidence_prefix_for(&j.prefix, &j.checkpoint, &j.scope());
        if minor == 9 {
            let verified = verified.unwrap();
            assert_eq!(verified.inventory, original);
            assert_eq!(verified.supplements.len(), 1);
            assert_eq!(verified.supplements[0].entry_vid, ordinary_target.vid);
            assert_eq!(verified.supplements[0].entry_digest, receipt_target.digest);
            assert_eq!(verified.supplements[0].citations, fixture::citations());
        } else {
            assert!(matches!(
                verified,
                Err(EvidenceProductionError::UnsupportedTargetIdentity {
                    leaf_index: 1,
                    class: 1,
                }),
            ));
        }
    }
}
