//! Full original-cited document productions: entry and byte omission attacks.

#[path = "support/evidence_inventory.rs"]
mod fixture;
#[path = "support/evidence_production.rs"]
mod production_fixture;
#[path = "evidence_documents/cli.rs"]
mod cli;

use fa_verify::document::{DOC_CHUNK_BYTES, doc_commit};
use fa_verify::evidence::EvidenceCitation;
use fa_verify::evidence::inventory::production::documents::{
    DocumentContent, DocumentProductionError, MAX_PRODUCTION_DOCUMENTS,
    verify_document_production_for,
};
use fa_verify::proof::production::MAX_PRODUCTION_BYTES;
use production_fixture::{entry, journal};

const DOCUMENT_SECRET: &[u8] = b"NEVER_PRINT_CITED_DOCUMENT_BYTES";

fn document(kind: u8, bytes: &[u8]) -> DocumentContent<'_> {
    let citation = fixture::citation(doc_commit(kind, bytes), 3);
    DocumentContent { document_oid: citation.document_oid, kind, bytes }
}

fn citations(documents: &[DocumentContent<'_>], role: u8) -> Vec<EvidenceCitation> {
    let mut result: Vec<_> = documents.iter().map(|doc| {
        fixture::citation(doc_commit(doc.kind, doc.bytes), role)
    }).collect();
    result.sort();
    result
}

#[test]
fn complete_bytes_preserve_shared_documents_every_role_and_zero_citation_entries() {
    let mut docs = [document(1, DOCUMENT_SECRET), document(2, &[])];
    docs.sort_by_key(|doc| doc.document_oid);
    let mut refs = citations(&docs, 3);
    refs.extend(citations(&docs[..1], 4));
    refs.sort();
    let j = journal(&[entry(&refs, 7, 10), entry(&[], 11, 10), entry(&refs, 30, 10)]);
    let report = verify_document_production_for(
        &j.prefix, &j.records(), &docs, &j.checkpoint, &j.scope(),
    ).unwrap();
    assert_eq!(report.inventory.scope, "seq_range_complete");
    assert_eq!(report.document_scope, "recomputation");
    assert_eq!(report.inventory.citation_count, 6);
    assert_eq!(report.inventory.entries.len(), 3);
    assert!(report.inventory.entries[1].citations.is_empty());
    assert_eq!(report.inventory.entries[0].citations, refs);
    assert_eq!(report.inventory.entries[2].citations, refs);
    assert_eq!(report.documents.len(), 2);
    assert_eq!(report.documents[0].citation_count, 4);
    assert_eq!(report.documents[1].citation_count, 2);
    assert_eq!(report.document_byte_count, DOCUMENT_SECRET.len() as u64);
    for (metadata, original) in report.documents.iter().zip(&docs) {
        assert_eq!(metadata.document_oid, original.document_oid);
        assert_eq!(metadata.kind, original.kind);
        assert_eq!(metadata.byte_length, original.bytes.len() as u64);
    }
    assert!(!format!("{report:?}").contains(std::str::from_utf8(DOCUMENT_SECRET).unwrap()));
    assert!(!format!("{report:?}").contains(std::str::from_utf8(fixture::SECRET).unwrap()));
}

#[test]
fn one_empty_document_is_not_the_same_as_no_documents() {
    let doc = document(0, &[]);
    let j = journal(&[entry(&citations(&[doc], 3), 7, 10)]);
    assert!(matches!(verify_document_production_for(
        &j.prefix, &j.records(), &[], &j.checkpoint, &j.scope(),
    ), Err(DocumentProductionError::DocumentCount { expected: 1, actual: 0 })));
    let report = verify_document_production_for(
        &j.prefix, &j.records(), &[doc], &j.checkpoint, &j.scope(),
    ).unwrap();
    assert_eq!(report.documents[0].byte_length, 0);
    assert_eq!(report.document_byte_count, 0);
    let wrong_kind = DocumentContent { kind: 1, ..doc };
    assert!(matches!(verify_document_production_for(
        &j.prefix, &j.records(), &[wrong_kind], &j.checkpoint, &j.scope(),
    ), Err(DocumentProductionError::Commitment { position: 0 })));
}

#[test]
fn omission_addition_duplication_and_reordering_are_not_repaired() {
    let mut docs = [document(1, b"one"), document(2, b"two"), document(3, b"three")];
    docs.sort_by_key(|doc| doc.document_oid);
    let j = journal(&[entry(&citations(&docs[..2], 3), 7, 10)]);
    for supplied in [vec![docs[0]], docs.to_vec(), vec![]] {
        assert!(matches!(verify_document_production_for(
            &j.prefix, &j.records(), &supplied, &j.checkpoint, &j.scope(),
        ), Err(DocumentProductionError::DocumentCount { .. })));
    }
    for supplied in [[docs[0], docs[0]], [docs[1], docs[0]]] {
        assert!(matches!(verify_document_production_for(
            &j.prefix, &j.records(), &supplied, &j.checkpoint, &j.scope(),
        ), Err(DocumentProductionError::Order { position: 1 })));
    }
    // Same count, valid bytes and canonical order, but an uncited locator.
    assert!(matches!(verify_document_production_for(
        &j.prefix, &j.records(), &[docs[0], docs[2]], &j.checkpoint, &j.scope(),
    ), Err(DocumentProductionError::DocumentIdentity { position: 1 })));
}

#[test]
fn every_chunk_kind_length_and_empty_tail_are_bound_to_the_citation() {
    // Odd five-chunk tree, including a short final chunk.
    let bytes: Vec<_> = (0..DOC_CHUNK_BYTES * 4 + 7).map(|i| (i % 251) as u8).collect();
    let original = document(255, &bytes);
    let j = journal(&[entry(&citations(&[original], 3), 7, 10)]);
    assert!(verify_document_production_for(
        &j.prefix, &j.records(), &[original], &j.checkpoint, &j.scope(),
    ).is_ok());
    for offset in [0, DOC_CHUNK_BYTES - 1, DOC_CHUNK_BYTES, bytes.len() - 1] {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        let supplied = DocumentContent { bytes: &corrupt, ..original };
        assert!(matches!(verify_document_production_for(
            &j.prefix, &j.records(), &[supplied], &j.checkpoint, &j.scope(),
        ), Err(DocumentProductionError::Commitment { position: 0 })));
    }
    let mut appended = bytes.clone();
    appended.push(0);
    for supplied in [
        DocumentContent { bytes: &bytes[..bytes.len() - 1], ..original },
        DocumentContent { bytes: &appended, ..original },
        DocumentContent { kind: 0, ..original },
        DocumentContent { bytes: &[], ..original },
    ] {
        assert!(matches!(verify_document_production_for(
            &j.prefix, &j.records(), &[supplied], &j.checkpoint, &j.scope(),
        ), Err(DocumentProductionError::Commitment { position: 0 })));
    }
}

#[test]
fn equal_bytes_under_different_kinds_are_distinct_cited_documents() {
    let mut docs = [document(1, b"same bytes"), document(2, b"same bytes")];
    docs.sort_by_key(|doc| doc.document_oid);
    assert_ne!(docs[0].document_oid, docs[1].document_oid);
    let j = journal(&[entry(&citations(&docs, 3), 7, 10)]);
    let report = verify_document_production_for(
        &j.prefix, &j.records(), &docs, &j.checkpoint, &j.scope(),
    ).unwrap();
    assert_eq!(report.documents.len(), 2);
    assert_eq!(report.document_byte_count, 20);
}

#[test]
fn last_document_failure_cannot_return_a_partial_production() {
    let mut docs = [document(1, b"first"), document(2, b"last")];
    docs.sort_by_key(|doc| doc.document_oid);
    let j = journal(&[entry(&citations(&docs, 3), 7, 10)]);
    docs[1].bytes = b"substituted";
    let error = verify_document_production_for(
        &j.prefix, &j.records(), &docs, &j.checkpoint, &j.scope(),
    ).unwrap_err();
    assert_eq!(error, DocumentProductionError::Commitment { position: 1 });
    assert!(!error.to_string().contains("substituted"));
}

#[test]
fn document_set_is_derived_only_from_entries_inside_the_recipient_horizon() {
    let one = document(1, b"earlier invoice");
    let two = document(2, b"later backdated invoice");
    let j = journal(&[
        entry(&citations(&[one], 3), 7, 10), entry(&citations(&[two], 3), 30, 10),
    ]);
    let mut scope = j.scope();
    scope.known_at = 7;
    scope.effective_days = Some((10, 10));
    assert!(verify_document_production_for(
        &j.prefix, &[&j.records[0]], &[one], &j.checkpoint, &scope,
    ).is_ok());
    scope.known_at = 30;
    // Later known-at requires the late-effective ENTRY, not just its document.
    assert!(matches!(verify_document_production_for(
        &j.prefix, &[&j.records[0]], &[one], &j.checkpoint, &scope,
    ), Err(DocumentProductionError::Evidence(_))));
    assert!(matches!(verify_document_production_for(
        &j.prefix, &j.records(), &[one], &j.checkpoint, &scope,
    ), Err(DocumentProductionError::DocumentCount { expected: 2, actual: 1 })));
    scope.account = Some(99);
    let empty = verify_document_production_for(&j.prefix, &[], &[], &j.checkpoint, &scope).unwrap();
    assert!(empty.documents.is_empty());
    assert!(empty.inventory.entries.is_empty());
    assert!(verify_document_production_for(&j.prefix, &[], &[two], &j.checkpoint, &scope).is_err());
}

#[test]
fn empty_content_success_requires_authentic_complete_entry_and_citation_evidence() {
    for j in [journal(&[]), journal(&[entry(&[], 7, 10)])] {
        let report = verify_document_production_for(
            &j.prefix, &j.records(), &[], &j.checkpoint, &j.scope(),
        ).unwrap();
        assert!(report.documents.is_empty());
        assert_eq!(report.inventory.entries.len(), j.records.len());
        assert!(verify_document_production_for(
            &[], &j.records(), &[], &j.checkpoint, &j.scope(),
        ).is_err());
    }
    // A cryptographically genuine entry with a false document locator is
    // not evidence for a document, even if its raw bytes hash correctly.
    let doc = document(1, b"valid bytes");
    let mut refs = citations(&[doc], 3);
    refs[0].document_oid[0] ^= 1;
    let j = journal(&[entry(&refs, 7, 10)]);
    assert!(matches!(verify_document_production_for(
        &j.prefix, &j.records(), &[doc], &j.checkpoint, &j.scope(),
    ), Err(DocumentProductionError::Evidence(_))));
}

#[test]
fn foreign_anchors_and_malformed_selected_records_never_authenticate_document_bytes() {
    let doc = document(1, b"invoice");
    let refs = citations(&[doc], 3);
    let mut malformed = entry(&refs, 7, 10);
    malformed.proposal.push(0);
    for input in [malformed, {
        let mut missing = entry(&refs, 7, 10);
        missing.include_record = false;
        missing
    }] {
        let j = journal(&[input]);
        assert!(matches!(verify_document_production_for(
            &j.prefix, &j.records(), &[doc], &j.checkpoint, &j.scope(),
        ), Err(DocumentProductionError::Evidence(_))));
    }
    let j = journal(&[entry(&refs, 7, 10)]);
    let mut other = j.checkpoint;
    other.book_id[0] ^= 1;
    assert!(matches!(verify_document_production_for(
        &j.prefix, &j.records(), &[doc], &other, &j.scope(),
    ), Err(DocumentProductionError::Evidence(_))));
}

#[test]
fn one_budget_covers_proofs_and_all_document_bytes_before_hashing() {
    let j = journal(&[]);
    let shared = vec![0; 1024];
    let doc = DocumentContent { document_oid: [0; 32], kind: 1, bytes: &shared };
    // Borrow one KiB 65536 times; input byte budget counts every supplied
    // document, even shared buffers, and includes the prefix proof as well.
    let docs = vec![doc; MAX_PRODUCTION_DOCUMENTS];
    assert!(matches!(verify_document_production_for(
        &j.prefix, &[], &docs, &j.checkpoint, &j.scope(),
    ), Err(DocumentProductionError::Limit("aggregate input bytes"))));
    let too_many = vec![DocumentContent { bytes: &[], ..doc }; MAX_PRODUCTION_DOCUMENTS + 1];
    assert!(matches!(verify_document_production_for(
        &j.prefix, &[], &too_many, &j.checkpoint, &j.scope(),
    ), Err(DocumentProductionError::Limit("document count"))));
    let record = vec![0; MAX_PRODUCTION_BYTES / 4096];
    let records = vec![record.as_slice(); 4096];
    assert!(matches!(verify_document_production_for(
        &[], &records, &[doc], &j.checkpoint, &j.scope(),
    ), Err(DocumentProductionError::Limit("aggregate input bytes"))));
}

#[test]
fn malformed_or_unanchored_scopes_fail_before_artifact_processing() {
    let j = journal(&[]);
    let mut bad = j.scope();
    bad.first_seq = 1;
    assert!(matches!(verify_document_production_for(b"bad", &[], &[], &j.checkpoint, &bad),
        Err(DocumentProductionError::Evidence(_))));
    bad = j.scope();
    bad.known_at = 1;
    assert!(matches!(verify_document_production_for(b"bad", &[], &[], &j.checkpoint, &bad),
        Err(DocumentProductionError::Evidence(_))));
    bad = j.scope();
    bad.effective_days = Some((2, 1));
    assert!(matches!(verify_document_production_for(b"bad", &[], &[], &j.checkpoint, &bad),
        Err(DocumentProductionError::Evidence(_))));
}

#[test]
fn same_entry_inventory_agrees_and_rehashed_bad_frames_still_fail() {
    let doc = document(1, b"invoice");
    let refs = citations(&[doc], 3);
    let p = fixture::proposal(&refs);
    let f = fixture::proof(&p.bytes, true, 7);
    let inventory = fa_verify::evidence::inventory::verify_evidence_inventory_for(
        &f.proof, &f.checkpoint, &f.entry_digest,
    ).unwrap();
    let j = journal(&[entry(&refs, 7, 20_527)]);
    let report = verify_document_production_for(
        &j.prefix, &j.records(), &[doc], &j.checkpoint, &j.scope(),
    ).unwrap();
    assert_eq!(report.inventory.entries[0].citations, inventory.citations);
    assert_eq!(report.inventory.entries[0].entry.envelope, inventory.inclusion.envelope);
    for offset in [p.count_offset, p.tail_offset + 4] {
        let mut bad = entry(&refs, 7, 20_527);
        if offset == p.count_offset {
            bad.proposal[offset..offset + 4].copy_from_slice(&1025u32.to_le_bytes());
        } else {
            bad.proposal[offset] = 2; // invalid optional-pending tag
        }
        let j = journal(&[bad]);
        assert!(matches!(verify_document_production_for(
            &j.prefix, &j.records(), &[doc], &j.checkpoint, &j.scope(),
        ), Err(DocumentProductionError::Evidence(_))));
    }
}

#[test]
fn authentic_citations_do_not_vouch_for_unchecked_document_contents() {
    // These are genuine entry citations with arbitrary commitments, not
    // commitments derived from the supplied bytes. Inventory alone passes.
    let refs = fixture::citations();
    let j = journal(&[entry(&refs, 7, 10)]);
    assert!(fa_verify::evidence::inventory::production::verify_evidence_production_for(
        &j.prefix, &j.records(), &j.checkpoint, &j.scope(),
    ).is_ok());
    let mut docs: Vec<_> = refs.iter().map(|citation| DocumentContent {
        document_oid: citation.document_oid, kind: 1, bytes: b"uncited bytes",
    }).collect();
    docs.dedup_by_key(|doc| doc.document_oid);
    assert!(matches!(verify_document_production_for(
        &j.prefix, &j.records(), &docs, &j.checkpoint, &j.scope(),
    ), Err(DocumentProductionError::Commitment { position: 0 })));
}
