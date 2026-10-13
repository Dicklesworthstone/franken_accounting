//! Actual kernel-produced RedactedView bytes against the std-only verifier.
//! The producer uses fgdb-crypto; the verifier shares no hash, codec or tree.
//! These tests do not treat a self-consistent view as its own trust anchor.

use fa_journal::evidence::{CHUNK_BYTES, Document};
use fa_journal::redaction::{RedactedView, ViewChunk};
use fa_model::Id128;
use fa_verify::redaction::{ViewError, verify_view_for};
use fgdb_types::VId;

fn document(length: usize, kind: u8) -> Document {
    Document {
        book_id: Id128([0x5a; 16]),
        kind,
        mime: "application/octet-stream".into(),
        grade: 1,
        retrieved_by: VId(5),
        bytes: (0..length)
            .map(|i| ((i * 17 + i / CHUNK_BYTES) % 251) as u8)
            .collect(),
    }
}

// Choose the expected disclosure independently, then make the kernel's
// redaction ranges withhold exactly its complement. No expected index is
// learned by examining the untrusted view returned by the producer.
fn view_for(doc: &Document, requested: &[u64]) -> RedactedView {
    let count = doc.bytes.len().div_ceil(CHUNK_BYTES).max(1);
    let ranges: Vec<_> = (0..count)
        .filter(|i| !requested.contains(&(*i as u64)))
        .map(|i| (i as u64 * CHUNK_BYTES as u64, 1))
        .collect();
    RedactedView::derive(doc, 7, &ranges)
}

fn check(doc: &Document, requested: &[u64]) {
    let view = view_for(doc, requested);
    view.verify().expect("kernel view verifies");
    let bytes = view.canonical_bytes().unwrap();
    let trusted = doc.doc_commit();
    let report = verify_view_for(&bytes, &trusted, requested).unwrap();
    assert_eq!(report.scope, "membership_only");
    assert_eq!(report.doc_commit, trusted);
    assert_eq!(report.kind, doc.kind);
    assert_eq!(report.size, doc.bytes.len() as u64);
    assert_eq!(report.view_commit, view.view_commit().unwrap());
    assert_eq!(report.unverified_metadata.original, doc.oid().0);
    assert_eq!(report.unverified_metadata.contract, 7);
    assert_eq!(report.disclosed.len(), requested.len());
    assert_eq!(
        report.withheld_chunks as usize,
        view.chunks.len() - requested.len()
    );
    for (chunk, expected) in report.disclosed.iter().zip(requested) {
        let start = *expected as usize * CHUNK_BYTES;
        let end = (start + CHUNK_BYTES).min(doc.bytes.len());
        assert_eq!(chunk.index, *expected);
        assert_eq!(chunk.bytes, &doc.bytes[start..end]);
    }
}

#[test]
fn every_nonempty_subset_through_eight_chunks_interoperates() {
    for n in 1..=8usize {
        let doc = document((n - 1) * CHUNK_BYTES + 7, 1);
        for mask in 1u64..(1u64 << n) {
            let requested: Vec<_> = (0..n)
                .filter(|i| mask & (1u64 << *i) != 0)
                .map(|i| i as u64)
                .collect();
            check(&doc, &requested);
        }
    }
    for length in [0, 1, CHUNK_BYTES - 1, CHUNK_BYTES, 2 * CHUNK_BYTES] {
        let doc = document(length, 9);
        let requested: Vec<_> = (0..length.div_ceil(CHUNK_BYTES).max(1))
            .map(|i| i as u64)
            .collect();
        check(&doc, &requested);
    }
}

#[test]
fn range_crossing_a_chunk_boundary_withholds_both_chunks() {
    let doc = document(3 * CHUNK_BYTES + 9, 9);
    let ranges = [(CHUNK_BYTES as u64 - 1, 2), (u64::MAX - 1, 10), (42, 0)];
    let view = RedactedView::derive(&doc, 7, &ranges);
    let bytes = view.canonical_bytes().unwrap();
    let report = verify_view_for(&bytes, &doc.doc_commit(), &[2, 3]).unwrap();
    assert_eq!(report.withheld_chunks, 2);
    assert_eq!(report.disclosed[0].bytes, &doc.bytes[8192..12288]);
    assert_eq!(report.disclosed[1].bytes, &doc.bytes[12288..]);
    assert!(verify_view_for(&bytes, &doc.doc_commit(), &[0, 2, 3]).is_err());
}

#[test]
fn producer_self_consistency_does_not_authorize_document_substitution() {
    let doc = document(8193, 1);
    let mut other = doc.clone();
    other.bytes[3] ^= 42;
    let mut forged = view_for(&other, &[0, 2]);
    forged.original = doc.oid();
    // Even a view claiming the intended locator can verify against its own
    // embedded commitment. The separately trusted original catches it.
    assert!(forged.verify().is_ok());
    let bytes = forged.canonical_bytes().unwrap();
    assert_eq!(
        verify_view_for(&bytes, &doc.doc_commit(), &[0, 2]),
        Err(ViewError::Commitment)
    );
}

#[test]
fn valid_kernel_views_cannot_omit_or_add_requested_chunks() {
    let doc = document(4 * CHUNK_BYTES, 1);
    for actual in [&[0u64][..], &[0, 1, 3], &[0, 2], &[3]] {
        let view = view_for(&doc, actual);
        assert!(view.verify().is_ok());
        let bytes = view.canonical_bytes().unwrap();
        assert!(verify_view_for(&bytes, &doc.doc_commit(), actual).is_ok());
        assert!(matches!(
            verify_view_for(&bytes, &doc.doc_commit(), &[0, 3]),
            Err(ViewError::Disclosure { .. })
        ));
    }
}

#[test]
fn withheld_hash_and_final_disclosure_corruption_are_rejected() {
    let doc = document(8193, 1);
    let original = view_for(&doc, &[0, 2]);
    let mut withheld = original.clone();
    assert!(
        matches!(withheld.chunks[1], ViewChunk::Withheld(_)),
        "chunk one was withheld"
    );
    if let ViewChunk::Withheld(digest) = &mut withheld.chunks[1] {
        digest[0] ^= 1;
    }
    let bytes = withheld.canonical_bytes().unwrap();
    assert_eq!(
        verify_view_for(&bytes, &doc.doc_commit(), &[0, 2]),
        Err(ViewError::Commitment)
    );
    let mut final_chunk = original;
    assert!(
        matches!(final_chunk.chunks[2], ViewChunk::Disclosed(_)),
        "final chunk was disclosed"
    );
    if let ViewChunk::Disclosed(bytes) = &mut final_chunk.chunks[2] {
        bytes.push(0);
    }
    let bytes = final_chunk.canonical_bytes().unwrap();
    assert!(matches!(
        verify_view_for(&bytes, &doc.doc_commit(), &[0, 2]),
        Err(ViewError::ChunkLength {
            index: 2,
            expected: 1,
            actual: 2
        })
    ));
}
