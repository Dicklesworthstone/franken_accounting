//! Kernel-derived redactions converted to compact proofs without original bytes.
//! The independent verifier receives a separately computed kernel commitment.

use fa_journal::{Document, RedactedView, ViewChunk};
use fa_model::Id128;
use fa_notary::disclosure::{DisclosureExportError, MAX_DISCLOSURE_CHUNKS, disclosure_from_view};
use fa_notary::document::DocumentProofTree;
use fa_verify::disclosure::verify;
use fgdb_types::VId;

fn document(size: usize) -> Document {
    Document {
        book_id: Id128([5; 16]), kind: 5, mime: "text/plain".into(), grade: 3,
        retrieved_by: VId(7),
        bytes: (0..size).map(|i| ((i * 31 + i / 4096) % 251) as u8).collect(),
    }
}

#[test]
fn redacted_paths_are_byte_identical_to_full_document_paths_for_every_readable_chunk() {
    for size in [0, 1, 4095, 4096, 4097, 8192, 8193, 16391, 28673] {
        let doc = document(size);
        // Withhold the second chunk and the fourth, where they exist.
        let view = RedactedView::derive(&doc, 7, &[(4096, 1), (12289, 1)]);
        view.verify().unwrap();
        let indexes: Vec<_> = view.chunks.iter().enumerate()
            .filter_map(|(i, c)| matches!(c, ViewChunk::Disclosed(_)).then_some(i as u64))
            .collect();
        let tree = DocumentProofTree::new(doc.kind, &doc.bytes).unwrap();
        for wanted in [indexes.clone(), vec![*indexes.last().unwrap()]] {
            let bytes = disclosure_from_view(&view, &wanted, &doc.doc_commit()).unwrap();
            assert_eq!(bytes, tree.disclosure_bytes(&wanted).unwrap());
            let report = verify(&bytes, &wanted, &doc.doc_commit()).unwrap();
            assert_eq!(report.scope, "membership_only");
            assert_eq!(report.document_length, size as u64);
            assert_eq!(report.chunks.iter().map(|c| c.index).collect::<Vec<_>>(), wanted);
        }
    }
}

#[test]
fn conversion_works_after_original_is_dropped_and_never_exports_unrequested_readable_bytes() {
    let mut doc = document(4096 * 5);
    doc.bytes[0..4096].fill(b'S');
    doc.bytes[4096..8192].fill(b'P');
    doc.bytes[8192..12288].fill(b'R');
    let anchor = doc.doc_commit();
    let view = RedactedView::derive(&doc, 7, &[(1, 1)]);
    let expected = DocumentProofTree::new(doc.kind, &doc.bytes).unwrap()
        .disclosure_bytes(&[1]).unwrap();
    drop(doc);
    let bytes = disclosure_from_view(&view, &[1], &anchor).unwrap();
    assert_eq!(bytes, expected);
    verify(&bytes, &[1], &anchor).unwrap();
    assert!(!bytes.windows(128).any(|s| s == [b'S'; 128]));
    assert!(!bytes.windows(128).any(|s| s == [b'R'; 128]));
    assert!(bytes.windows(128).any(|s| s == [b'P'; 128]));
    assert_eq!(disclosure_from_view(&view, &[0, 1], &anchor),
        Err(DisclosureExportError::Withheld { index: 0 }));
    assert_eq!(disclosure_from_view(&view, &[1, 2, 4], &anchor).unwrap(),
        disclosure_from_view(&view, &[1, 2, 4], &anchor).unwrap());
}

#[test]
fn malformed_requests_and_view_shapes_are_refused_before_path_construction() {
    let doc = document(8193);
    let view = RedactedView::derive(&doc, 7, &[(4096, 1)]);
    let anchor = doc.doc_commit();
    assert_eq!(disclosure_from_view(&view, &[], &anchor), Err(DisclosureExportError::EmptyRequest));
    for indexes in [&[0, 0][..], &[2, 0][..]] {
        assert_eq!(disclosure_from_view(&view, indexes, &anchor), Err(DisclosureExportError::RequestOrder));
    }
    assert!(matches!(disclosure_from_view(&view, &vec![0; MAX_DISCLOSURE_CHUNKS + 1], &anchor),
        Err(DisclosureExportError::CountLimit { .. })));
    assert!(matches!(disclosure_from_view(&view, &[u64::MAX], &anchor),
        Err(DisclosureExportError::Proof(_))));
    assert_eq!(disclosure_from_view(&view, &[0, 1], &anchor),
        Err(DisclosureExportError::Withheld { index: 1 }));
    let mut missing = view.clone();
    missing.chunks.pop();
    let mut extra = view.clone();
    extra.chunks.push(ViewChunk::Disclosed(Vec::new()));
    let mut oversized = view.clone();
    oversized.size = u64::MAX;
    let mut short = view.clone();
    short.chunks[0] = ViewChunk::Disclosed(vec![1]);
    for bad in [missing, extra, oversized, short] {
        assert!(matches!(disclosure_from_view(&bad, &[0], &anchor),
            Err(DisclosureExportError::View(_))));
    }
}

#[test]
fn tampered_hidden_hashes_unselected_bytes_and_separate_anchors_fail_closed() {
    let doc = document(16391);
    let view = RedactedView::derive(&doc, 7, &[(4096, 1)]);
    let anchor = doc.doc_commit();
    let mut hidden = view.clone();
    if let ViewChunk::Withheld(hash) = &mut hidden.chunks[1] { hash[0] ^= 1; }
    let mut readable = view.clone();
    if let ViewChunk::Disclosed(bytes) = &mut readable.chunks[2] { bytes[0] ^= 1; }
    let mut wrong_kind = view.clone();
    wrong_kind.kind += 1;
    for bad in [hidden, readable, wrong_kind] {
        assert_eq!(disclosure_from_view(&bad, &[0], &anchor), Err(DisclosureExportError::Commitment));
    }
    let mut other_anchor = anchor;
    other_anchor[0] ^= 1;
    assert_eq!(disclosure_from_view(&view, &[0], &other_anchor), Err(DisclosureExportError::Commitment));
    // Locator/contract are intentionally outside compact membership proofs.
    // The facade authenticates them through its existing protected read gate.
    let mut relabeled = view.clone();
    relabeled.original.0[0] ^= 1;
    relabeled.contract += 1;
    assert_eq!(disclosure_from_view(&relabeled, &[0], &anchor).unwrap(),
        disclosure_from_view(&view, &[0], &anchor).unwrap());
}
