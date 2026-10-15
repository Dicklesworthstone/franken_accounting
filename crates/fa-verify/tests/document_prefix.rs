//! Native prefix -> original citations -> full document bytes, without a
//! second exported copy of each selected entry. No producer dependency.

#[path = "support/evidence_inventory.rs"]
mod fixture;
#[path = "support/evidence_production.rs"]
mod production_fixture;

use fa_verify::document::doc_commit;
use fa_verify::evidence::inventory::production::EvidenceProductionError;
use fa_verify::evidence::inventory::production::documents::{
    DocumentContent, DocumentProductionError, MAX_PRODUCTION_DOCUMENTS,
    verify_document_prefix_for, verify_document_production_for,
};
use fa_verify::proof::production::{MAX_PRODUCTION_BYTES, ProductionError};
use production_fixture::{entry, journal};

fn documents<'a>(contents: &[&'a [u8]]) -> Vec<DocumentContent<'a>> {
    let mut documents: Vec<_> = contents.iter().map(|bytes| DocumentContent {
        document_oid: fixture::citation(doc_commit(1, bytes), 3).document_oid,
        kind: 1,
        bytes,
    }).collect();
    documents.sort_by_key(|document| document.document_oid);
    documents
}

#[test]
fn direct_and_multi_proof_reports_match_with_shared_roles_empty_files_and_history() {
    let chunked = vec![71; 4096 * 3 + 11];
    let content: [&[u8]; 3] = [b"invoice A", &chunked, b""];
    let a = fixture::citation(doc_commit(1, content[0]), 3);
    let a_second_role = fixture::citation(a.doc_commit, 4);
    let b = fixture::citation(doc_commit(1, content[1]), 3);
    let empty = fixture::citation(doc_commit(1, content[2]), 3);
    let mut last = vec![a, a_second_role, empty];
    last.sort();
    let j = journal(&[entry(&[a], 7, 10), entry(&[b], 11, 20), entry(&last, 30, 10)]);
    let records = j.records();
    let docs = documents(&content);
    let old = verify_document_production_for(&j.prefix, &records, &docs, &j.checkpoint, &j.scope()).unwrap();
    let direct = verify_document_prefix_for(&j.prefix, &docs, &j.checkpoint, &j.scope()).unwrap();
    assert_eq!(direct, old);
    assert_eq!(direct.inventory.citation_count, 5);
    assert_eq!(direct.documents.len(), 3);
    assert_eq!(direct.document_byte_count, (content[0].len() + content[1].len()) as u64);
    let repeated = direct.documents.iter().find(|document| document.document_oid == a.document_oid).unwrap();
    assert_eq!(repeated.citation_count, 3);
    let empty_document = direct.documents.iter().find(|document| document.document_oid == empty.document_oid).unwrap();
    assert_eq!(empty_document.byte_length, 0);
    assert_eq!(direct.inventory.entries[2].citations, last);

    let mut scope = j.scope();
    scope.known_at = 11;
    scope.effective_days = Some((10, 10));
    let historical_docs = documents(&content[..1]);
    let historical = verify_document_prefix_for(&j.prefix, &historical_docs, &j.checkpoint, &scope).unwrap();
    assert_eq!(historical, verify_document_production_for(
        &j.prefix, &[records[0]], &historical_docs, &j.checkpoint, &scope,
    ).unwrap());
    assert_eq!(historical.inventory.entries.len(), 1);
    assert_eq!(historical.inventory.entries[0].citations, vec![a]);
    assert!(verify_document_prefix_for(&j.prefix, &docs, &j.checkpoint, &scope).is_err());
    scope.account = Some(99);
    let no_matches = verify_document_prefix_for(&j.prefix, &[], &j.checkpoint, &scope).unwrap();
    assert!(no_matches.inventory.entries.is_empty());
    assert!(no_matches.documents.is_empty());
    assert!(verify_document_prefix_for(&j.prefix, &historical_docs, &j.checkpoint, &scope).is_err());
}

#[test]
fn missing_extra_repeated_reordered_and_empty_document_omission_fail_closed() {
    let content: [&[u8]; 3] = [b"invoice", b"receipt", b""];
    let mut citations: Vec<_> = content.iter().map(|bytes| fixture::citation(doc_commit(1, bytes), 3)).collect();
    citations.sort();
    let j = journal(&[entry(&citations, 7, 10)]);
    let good = documents(&content);
    verify_document_prefix_for(&j.prefix, &good, &j.checkpoint, &j.scope()).unwrap();
    for omitted in 0..good.len() {
        let missing: Vec<_> = good.iter().enumerate().filter(|(index, _)| *index != omitted).map(|(_, document)| *document).collect();
        assert!(matches!(verify_document_prefix_for(&j.prefix, &missing, &j.checkpoint, &j.scope()),
            Err(DocumentProductionError::DocumentCount { expected: 3, actual: 2 })));
    }
    let extra = documents(&[content[0], content[1], content[2], b"uncited"]);
    assert!(matches!(verify_document_prefix_for(&j.prefix, &extra, &j.checkpoint, &j.scope()),
        Err(DocumentProductionError::DocumentCount { expected: 3, actual: 4 })));
    let mut duplicate = good.clone();
    duplicate.insert(1, good[0]);
    assert!(matches!(verify_document_prefix_for(&j.prefix, &duplicate, &j.checkpoint, &j.scope()),
        Err(DocumentProductionError::Order { .. })));
    let mut reversed = good;
    reversed.reverse();
    assert!(matches!(verify_document_prefix_for(&j.prefix, &reversed, &j.checkpoint, &j.scope()),
        Err(DocumentProductionError::Order { .. })));
}

#[test]
fn document_identity_kind_length_and_every_byte_are_bound_to_original_citations() {
    let content: [&[u8]; 1] = [b"document payload must never be printed"];
    let docs = documents(&content);
    let citation = fixture::citation(doc_commit(1, content[0]), 3);
    let j = journal(&[entry(&[citation], 7, 10)]);
    let mut changed = content[0].to_vec();
    *changed.last_mut().unwrap() ^= 1;
    for bad in [
        DocumentContent { document_oid: [0; 32], ..docs[0] },
        DocumentContent { kind: 2, ..docs[0] },
        DocumentContent { bytes: &content[0][..content[0].len() - 1], ..docs[0] },
        DocumentContent { bytes: &changed, ..docs[0] },
    ] {
        assert!(verify_document_prefix_for(&j.prefix, &[bad], &j.checkpoint, &j.scope()).is_err());
    }
    let mut bad_citation = citation;
    bad_citation.document_oid[0] ^= 1;
    let unbound = journal(&[entry(&[citation], 7, 10), entry(&[bad_citation], 11, 10)]);
    assert!(matches!(verify_document_prefix_for(&unbound.prefix, &docs, &unbound.checkpoint, &unbound.scope()),
        Err(DocumentProductionError::Evidence(EvidenceProductionError::Evidence { leaf_index: 1, .. }))));
}

#[test]
fn empty_citation_sets_do_not_allow_unauthenticated_prefixes_or_future_horizons() {
    for j in [journal(&[]), journal(&[entry(&[], 7, 10)])] {
        let verified = verify_document_prefix_for(&j.prefix, &[], &j.checkpoint, &j.scope()).unwrap();
        assert!(verified.documents.is_empty());
        assert_eq!(verified.document_byte_count, 0);
        for end in [0, 1, j.prefix.len() - 1] {
            assert!(verify_document_prefix_for(&j.prefix[..end], &[], &j.checkpoint, &j.scope()).is_err());
        }
        let mut wrong = j.checkpoint;
        wrong.root[0] ^= 1;
        assert!(verify_document_prefix_for(&j.prefix, &[], &wrong, &j.scope()).is_err());
        let mut future = j.scope();
        future.known_at += 1;
        assert!(matches!(verify_document_prefix_for(b"invalid", &[], &j.checkpoint, &future),
            Err(DocumentProductionError::Evidence(EvidenceProductionError::Production(ProductionError::Request(_))))));
    }
}

#[test]
fn total_input_budget_and_document_count_are_checked_before_crypto_or_hashing() {
    let j = journal(&[]);
    let chunk = vec![0; MAX_PRODUCTION_BYTES / 1024];
    let mut docs: Vec<_> = (0..1024u64).map(|index| {
        let mut oid = [0; 32];
        oid[..8].copy_from_slice(&index.to_be_bytes());
        DocumentContent { document_oid: oid, kind: 1, bytes: &chunk }
    }).collect();
    assert_eq!(verify_document_prefix_for(b"invalid", &docs, &j.checkpoint, &j.scope()),
        Err(DocumentProductionError::Limit("aggregate input bytes")));
    // Exactly the bound passes size preflight and reaches invalid-prefix
    // decoding. Repeated slices count at full size, not once per allocation.
    docs[0].bytes = &chunk[..chunk.len() - b"invalid".len()];
    assert!(matches!(verify_document_prefix_for(b"invalid", &docs, &j.checkpoint, &j.scope()),
        Err(DocumentProductionError::Evidence(EvidenceProductionError::Production(ProductionError::Prefix(_))))));
    let excessive = vec![DocumentContent { document_oid: [0; 32], kind: 1, bytes: &[] }; MAX_PRODUCTION_DOCUMENTS + 1];
    assert_eq!(verify_document_prefix_for(b"invalid", &excessive, &j.checkpoint, &j.scope()),
        Err(DocumentProductionError::Limit("document count")));
}
