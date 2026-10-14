//! Portable producer bytes checked by the independent standard-library verifier.
//! The trusted commitment comes from kernel intake, not from the artifact.

use fa_notary::disclosure::{DisclosureExportError, FORMAT, MAX_DISCLOSURE_CHUNKS};
use fa_notary::document::DocumentProofTree;
use fa_verify::disclosure::{DisclosureProofError, verify};

#[test]
fn empty_document_encoding_is_pinned_and_has_no_embedded_trust_anchor() {
    let tree = DocumentProofTree::new(18, &[]).unwrap();
    let proof = tree.disclosure_bytes(&[0]).unwrap();
    let mut expected = (FORMAT.len() as u32).to_le_bytes().to_vec();
    expected.extend_from_slice(b"fa:document-disclosure:v1");
    expected.push(18);
    expected.extend_from_slice(&0u64.to_le_bytes());
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&0u64.to_le_bytes());
    expected.extend_from_slice(&0u32.to_le_bytes());
    expected.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(proof, expected);
    let trusted = fa_journal::evidence::doc_commit(18, &[]);
    let verified = verify(&proof, &[0], &trusted).unwrap();
    assert_eq!(verified.scope, "membership_only");
    assert_eq!(verified.kind, 18);
    assert_eq!(verified.chunks[0].byte_length, 0);
    assert_eq!(fa_verify::disclosure::FORMAT, FORMAT);
    assert_eq!(
        fa_verify::disclosure::MAX_DISCLOSURE_CHUNKS,
        MAX_DISCLOSURE_CHUNKS
    );
    assert_eq!(
        fa_verify::disclosure::MAX_PROOF_BYTES,
        fa_notary::disclosure::MAX_PROOF_BYTES
    );
}

#[test]
fn odd_even_partial_and_full_disclosures_verify_without_undisclosed_bytes() {
    for length in [0, 1, 4095, 4096, 4097, 8192, 16391, 65537] {
        let document: Vec<_> = (0..length).map(|i| ((i * 29 + 7) % 251) as u8).collect();
        for kind in [1, 9, 18] {
            let tree = DocumentProofTree::new(kind, &document).unwrap();
            let trusted = fa_journal::evidence::doc_commit(kind, &document);
            let all: Vec<_> = (0..tree.chunk_count()).collect();
            let alternate: Vec<_> = all.iter().copied().step_by(2).collect();
            for indexes in [all, alternate, vec![tree.chunk_count() - 1]] {
                let proof = tree.disclosure_bytes(&indexes).unwrap();
                assert_eq!(proof, tree.disclosure_bytes(&indexes).unwrap());
                let verified = verify(&proof, &indexes, &trusted).unwrap();
                assert_eq!(verified.kind, kind);
                assert_eq!(verified.document_length, length as u64);
                assert_eq!(
                    verified.chunks.iter().map(|c| c.index).collect::<Vec<_>>(),
                    indexes
                );
                assert!(verified.chunks.iter().all(|c| c.scope == "membership_only"));
            }
        }
    }
    let document = vec![42; 4096 * 4 + 7];
    let tree = DocumentProofTree::new(1, &document).unwrap();
    let last = tree.disclosure_bytes(&[4]).unwrap();
    // A fifth leaf needs one left-subtree hash, not the undisclosed 16 KiB.
    assert_eq!(last.len(), 4 + FORMAT.len() + 1 + 8 + 4 + 16 + 7 + 32);
}

#[test]
fn exact_recipient_requests_reject_omission_substitution_and_added_chunks() {
    let document = vec![7; 4096 * 5];
    let tree = DocumentProofTree::new(1, &document).unwrap();
    let trusted = fa_journal::evidence::doc_commit(1, &document);
    let proof = tree.disclosure_bytes(&[0, 4]).unwrap();
    verify(&proof, &[0, 4], &trusted).unwrap();
    for request in [
        vec![],
        vec![0],
        vec![0, 3],
        vec![0, 1, 4],
        vec![4, 0],
        vec![0, 0],
    ] {
        assert!(verify(&proof, &request, &trusted).is_err(), "{request:?}");
    }
    let other = fa_journal::evidence::doc_commit(1, &vec![8; document.len()]);
    assert!(verify(&proof, &[0, 4], &other).is_err());
    let mut trailing = proof.clone();
    trailing.extend_from_slice(&proof);
    assert!(verify(&trailing, &[0, 4], &trusted).is_err());
    // A valid first chunk does not produce partial success after corruption
    // of the last chunk's proof. The API returns no chunk reports on error.
    let mut damaged = proof;
    *damaged.last_mut().unwrap() ^= 1;
    assert!(matches!(
        verify(&damaged, &[0, 4], &trusted),
        Err(DisclosureProofError::Disclosure(_))
    ));
}

#[test]
fn malformed_requests_are_refused_and_every_wire_byte_of_a_single_chunk_is_bound() {
    let document = b"source bytes with a newline\n";
    let tree = DocumentProofTree::new(1, document).unwrap();
    assert_eq!(
        tree.disclosure_bytes(&[]),
        Err(DisclosureExportError::EmptyRequest)
    );
    assert_eq!(
        tree.disclosure_bytes(&[0, 0]),
        Err(DisclosureExportError::RequestOrder)
    );
    assert_eq!(
        tree.disclosure_bytes(&[1, 0]),
        Err(DisclosureExportError::RequestOrder)
    );
    assert!(matches!(
        tree.disclosure_bytes(&[u64::MAX]),
        Err(DisclosureExportError::Proof(_))
    ));
    assert!(matches!(
        tree.disclosure_bytes(&vec![0; MAX_DISCLOSURE_CHUNKS + 1]),
        Err(DisclosureExportError::CountLimit { .. })
    ));
    let proof = tree.disclosure_bytes(&[0]).unwrap();
    let trusted = fa_journal::evidence::doc_commit(1, document);
    for i in 0..proof.len() {
        let mut changed = proof.clone();
        changed[i] ^= 1;
        assert!(
            verify(&changed, &[0], &trusted).is_err(),
            "changed byte {i}"
        );
        assert!(
            verify(&proof[..i], &[0], &trusted).is_err(),
            "truncated at {i}"
        );
    }
}
