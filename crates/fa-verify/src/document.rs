//! A document's public commitment, recomputed from its bytes (plan §9.1).
//!
//! ```text
//! doc_commit = BLAKE3("fa:doc:v1" ‖ kind u8 ‖ length u64 ‖ chunk_root)
//! leaf i     = BLAKE3("fa:doc:leaf:v1" ‖ i u64 ‖ chunk_len u64 ‖ chunk)   (4 KiB chunks)
//! node       = BLAKE3("fa:doc:node:v1" ‖ left ‖ right)
//! ```
//!
//! The chunk tree is built bottom-up, pairing left to right and promoting an
//! unpaired last node unchanged; empty input is one empty leaf. An entry's
//! evidence cites `doc_commit`, so an outsider handed the document's bytes
//! and kind checks the citation with nothing but this crate.

use crate::blake3::hash_parts;

pub const DOC_CHUNK_BYTES: usize = 4096;
pub const DOC_DOMAIN: &[u8] = b"fa:doc:v1";
pub const DOC_LEAF_DOMAIN: &[u8] = b"fa:doc:leaf:v1";
pub const DOC_NODE_DOMAIN: &[u8] = b"fa:doc:node:v1";

fn le64(n: usize) -> [u8; 8] {
    u64::try_from(n).unwrap_or(u64::MAX).to_le_bytes()
}

fn leaf(index: usize, chunk: &[u8]) -> [u8; 32] {
    hash_parts(DOC_LEAF_DOMAIN, &[&le64(index), &le64(chunk.len()), chunk])
}

/// The Merkle root over the document's 4 KiB chunks.
#[must_use]
pub fn chunk_root(bytes: &[u8]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = if bytes.is_empty() {
        vec![leaf(0, &[])]
    } else {
        bytes
            .chunks(DOC_CHUNK_BYTES)
            .enumerate()
            .map(|(i, c)| leaf(i, c))
            .collect()
    };
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let (pairs, unpaired) = level.as_chunks::<2>();
        for [left, right] in pairs {
            next.push(hash_parts(DOC_NODE_DOMAIN, &[left, right]));
        }
        next.extend_from_slice(unpaired);
        level = next;
    }
    level.first().copied().unwrap_or([0; 32])
}

/// `BLAKE3("fa:doc:v1" ‖ kind ‖ length ‖ chunk_root)`.
#[must_use]
pub fn doc_commit(kind: u8, bytes: &[u8]) -> [u8; 32] {
    hash_parts(
        DOC_DOMAIN,
        &[&[kind], &le64(bytes.len()), &chunk_root(bytes)],
    )
}

/// A chunk proof authenticates disclosed bytes, not the undisclosed document,
/// its provenance, the sender's authority, or the completeness of a production.
pub const SCOPE_CHUNK_MEMBERSHIP: &str = "membership_only";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChunkProofError {
    Index { index: u64, chunk_count: u64 },
    ChunkLength { expected: usize, actual: usize },
    PathLength { expected: usize, actual: usize },
    Commitment,
}

impl core::fmt::Display for ChunkProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Index { index, chunk_count } => {
                write!(f, "document chunk {index} is outside {chunk_count} chunks")
            }
            Self::ChunkLength { expected, actual } => {
                write!(f, "document chunk requires {expected} bytes, got {actual}")
            }
            Self::PathLength { expected, actual } => {
                write!(f, "document chunk path requires {expected} siblings, got {actual}")
            }
            Self::Commitment => write!(f, "document chunk does not match the trusted doc_commit"),
        }
    }
}

impl core::error::Error for ChunkProofError {}

/// One whole canonical chunk was authenticated against a separately supplied
/// public document commitment. Other chunks remain undisclosed and unchecked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedChunk {
    pub scope: &'static str,
    pub kind: u8,
    pub document_length: u64,
    pub index: u64,
    pub byte_length: usize,
}

/// Verify a selectively disclosed document chunk (plan §9.1).
///
/// `trusted_doc_commit` must come from independently authenticated evidence,
/// not merely from the producer's proof. This checks membership in that
/// commitment, not its origin, a journal inclusion, or economic truth.
///
/// Siblings run from leaf to root. Their sides and count are derived from
/// `index` and `document_length`; an unpaired last node is promoted unchanged
/// and consumes NO sibling. Every supplied hash must be consumed exactly.
/// The last chunk has its exact remainder length; an empty document has one
/// empty chunk at index zero. Partial/sub-chunk redactions are not provable
/// by this API and are refused as a length or commitment mismatch.
///
/// Verification hashes at most one 4 KiB chunk plus 52 tree levels, even for
/// a claimed u64::MAX-byte document. No whole-document allocation is made.
/// Existing whole-document commitments and their canonical bytes are unchanged.
pub fn verify_chunk(
    kind: u8,
    document_length: u64,
    index: u64,
    chunk: &[u8],
    siblings: &[[u8; 32]],
    trusted_doc_commit: &[u8; 32],
) -> Result<VerifiedChunk, ChunkProofError> {
    let chunk_size = DOC_CHUNK_BYTES as u64;
    // div_ceil avoids document_length + chunk_size - 1 overflowing at u64::MAX.
    let count = document_length.div_ceil(chunk_size).max(1);
    if index >= count {
        return Err(ChunkProofError::Index {
            index,
            chunk_count: count,
        });
    }
    let remainder = document_length % chunk_size;
    let expected = if document_length == 0 {
        0
    } else if index == count - 1 && remainder != 0 {
        remainder as usize // strictly less than the 4096-byte chunk size
    } else {
        DOC_CHUNK_BYTES
    };
    if chunk.len() != expected {
        return Err(ChunkProofError::ChunkLength {
            expected,
            actual: chunk.len(),
        });
    }

    // Validate the path's exact shape before hashing or consuming any hashes.
    let (mut width, mut position, mut required) = (count, index, 0usize);
    while width > 1 {
        if (position ^ 1) < width {
            required += 1;
        }
        position /= 2;
        width = width.div_ceil(2);
    }
    if siblings.len() != required {
        return Err(ChunkProofError::PathLength {
            expected: required,
            actual: siblings.len(),
        });
    }

    let mut root = hash_parts(
        DOC_LEAF_DOMAIN,
        &[&index.to_le_bytes(), &le64(chunk.len()), chunk],
    );
    let (mut width, mut position, mut used) = (count, index, 0usize);
    while width > 1 {
        if (position ^ 1) < width {
            let sibling = &siblings[used];
            root = if position % 2 == 0 {
                hash_parts(DOC_NODE_DOMAIN, &[&root, sibling])
            } else {
                hash_parts(DOC_NODE_DOMAIN, &[sibling, &root])
            };
            used += 1;
        }
        position /= 2;
        width = width.div_ceil(2);
    }
    let commitment = hash_parts(
        DOC_DOMAIN,
        &[&[kind], &document_length.to_le_bytes(), &root],
    );
    if &commitment != trusted_doc_commit {
        return Err(ChunkProofError::Commitment);
    }
    Ok(VerifiedChunk {
        scope: SCOPE_CHUNK_MEMBERSHIP,
        kind,
        document_length,
        index,
        byte_length: chunk.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
        hash_parts(DOC_NODE_DOMAIN, &[l, r])
    }

    #[test]
    fn the_chunk_tree_is_the_literal_bottom_up_tree() {
        assert_eq!(chunk_root(&[]), leaf(0, &[]));
        let one = vec![9u8; 10];
        assert_eq!(chunk_root(&one), leaf(0, &one));
        // Five chunks: ((l0 l1) (l2 l3)) l4 — the unpaired leaf is promoted.
        let five: Vec<u8> = (0..DOC_CHUNK_BYTES * 4 + 7)
            .map(|i| (i % 253) as u8)
            .collect();
        let l: Vec<[u8; 32]> = five
            .chunks(DOC_CHUNK_BYTES)
            .enumerate()
            .map(|(i, c)| leaf(i, c))
            .collect();
        assert_eq!(l.len(), 5);
        let expected = node(&node(&node(&l[0], &l[1]), &node(&l[2], &l[3])), &l[4]);
        assert_eq!(chunk_root(&five), expected);
        // Three: (l0 l1) l2.
        let three = &five[..DOC_CHUNK_BYTES * 2 + 1];
        let l3: Vec<[u8; 32]> = three
            .chunks(DOC_CHUNK_BYTES)
            .enumerate()
            .map(|(i, c)| leaf(i, c))
            .collect();
        assert_eq!(chunk_root(three), node(&node(&l3[0], &l3[1]), &l3[2]));
    }

    #[test]
    fn kind_length_and_every_chunk_are_bound() {
        let a = vec![7u8; DOC_CHUNK_BYTES * 3 + 5];
        let base = doc_commit(1, &a);
        assert_ne!(base, doc_commit(2, &a));
        for i in [
            0,
            DOC_CHUNK_BYTES - 1,
            DOC_CHUNK_BYTES,
            DOC_CHUNK_BYTES * 3 + 4,
        ] {
            let mut b = a.clone();
            b[i] ^= 1;
            assert_ne!(base, doc_commit(1, &b), "byte {i}");
        }
        let mut longer = a.clone();
        longer.push(7);
        assert_ne!(base, doc_commit(1, &longer));
        assert_ne!(doc_commit(1, &[]), doc_commit(1, &[0]));
    }
}

#[cfg(test)]
mod chunk_proof_tests {
    use super::*;

    // Full-tree construction is deliberately separate from the single-path
    // verifier: each level is materialized and siblings are read from it.
    fn path(bytes: &[u8], mut index: usize) -> Vec<[u8; 32]> {
        let mut level = if bytes.is_empty() {
            vec![leaf(0, &[])]
        } else {
            bytes.chunks(DOC_CHUNK_BYTES).enumerate()
                .map(|(i, bytes)| leaf(i, bytes)).collect::<Vec<_>>()
        };
        let mut path = Vec::new();
        while level.len() > 1 {
            if let Some(sibling) = level.get(index ^ 1) {
                path.push(*sibling);
            }
            level = level.chunks(2).map(|pair| {
                if pair.len() == 2 {
                    hash_parts(DOC_NODE_DOMAIN, &[&pair[0], &pair[1]])
                } else {
                    pair[0]
                }
            }).collect();
            index /= 2;
        }
        path
    }

    fn data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn every_chunk_of_even_odd_and_partial_trees_matches_the_existing_commitment() {
        let mut sizes = vec![0, 1, DOC_CHUNK_BYTES - 1];
        for chunks in 1..=17 {
            sizes.extend([chunks * DOC_CHUNK_BYTES, chunks * DOC_CHUNK_BYTES + 7]);
        }
        for size in sizes {
            let bytes = data(size);
            let trusted = doc_commit(3, &bytes);
            let count = size.div_ceil(DOC_CHUNK_BYTES).max(1);
            for index in 0..count {
                let start = index * DOC_CHUNK_BYTES;
                let end = (start + DOC_CHUNK_BYTES).min(size);
                let chunk = &bytes[start..end];
                let result = verify_chunk(
                    3, size as u64, index as u64, chunk, &path(&bytes, index), &trusted,
                ).unwrap();
                assert_eq!(result.scope, "membership_only");
                assert_eq!(result.index, index as u64);
                assert_eq!(result.byte_length, end - start);
                assert_eq!(result.document_length, size as u64);
                assert_eq!(result.kind, 3);
            }
        }
    }

    #[test]
    fn literal_five_chunk_paths_promote_the_last_leaf_without_synthetic_siblings() {
        let bytes = data(DOC_CHUNK_BYTES * 4 + 7);
        let chunks = bytes.chunks(DOC_CHUNK_BYTES).collect::<Vec<_>>();
        let hashes = chunks.iter().enumerate().map(|(i, c)| leaf(i, c)).collect::<Vec<_>>();
        let left = hash_parts(DOC_NODE_DOMAIN, &[
            &hash_parts(DOC_NODE_DOMAIN, &[&hashes[0], &hashes[1]]),
            &hash_parts(DOC_NODE_DOMAIN, &[&hashes[2], &hashes[3]]),
        ]);
        let trusted = doc_commit(1, &bytes);
        // Leaf 4 is promoted twice; its entire canonical path is one hash.
        verify_chunk(1, bytes.len() as u64, 4, chunks[4], &[left], &trusted).unwrap();
        assert_eq!(
            verify_chunk(1, bytes.len() as u64, 4, chunks[4], &[[0; 32], left], &trusted),
            Err(ChunkProofError::PathLength { expected: 1, actual: 2 }),
        );
        let first_path = [hashes[1], hash_parts(DOC_NODE_DOMAIN, &[&hashes[2], &hashes[3]]), hashes[4]];
        verify_chunk(1, bytes.len() as u64, 0, chunks[0], &first_path, &trusted).unwrap();
        let mut reordered = first_path;
        reordered.swap(0, 1);
        assert_eq!(
            verify_chunk(1, bytes.len() as u64, 0, chunks[0], &reordered, &trusted),
            Err(ChunkProofError::Commitment),
        );
    }

    #[test]
    fn changed_bytes_kind_length_index_siblings_and_anchor_are_rejected() {
        // Equal chunk bytes do not permit moving a chunk to another index:
        // the leaf transcript authenticates its position as well as its bytes.
        let bytes = vec![7; DOC_CHUNK_BYTES * 4 + 9];
        let chunk = &bytes[..DOC_CHUNK_BYTES];
        let siblings = path(&bytes, 0);
        let trusted = doc_commit(1, &bytes);
        verify_chunk(1, bytes.len() as u64, 0, chunk, &siblings, &trusted).unwrap();
        for (kind, length, index) in [
            (2, bytes.len() as u64, 0),
            (1, bytes.len() as u64 + 1, 0),
            (1, bytes.len() as u64, 1),
        ] {
            assert!(verify_chunk(kind, length, index, chunk, &siblings, &trusted).is_err());
        }
        let mut changed = chunk.to_vec();
        changed[123] ^= 1;
        assert_eq!(verify_chunk(1, bytes.len() as u64, 0, &changed, &siblings, &trusted), Err(ChunkProofError::Commitment));
        let mut wrong_anchor = trusted;
        wrong_anchor[0] ^= 1;
        assert_eq!(verify_chunk(1, bytes.len() as u64, 0, chunk, &siblings, &wrong_anchor), Err(ChunkProofError::Commitment));
        for i in 0..siblings.len() {
            let mut changed = siblings.clone();
            changed[i][0] ^= 1;
            assert_eq!(verify_chunk(1, bytes.len() as u64, 0, chunk, &changed, &trusted), Err(ChunkProofError::Commitment));
        }
        assert!(matches!(verify_chunk(1, bytes.len() as u64, 0, chunk, &siblings[1..], &trusted), Err(ChunkProofError::PathLength { .. })));
        let mut extra = siblings.clone();
        extra.push([0; 32]);
        assert!(matches!(verify_chunk(1, bytes.len() as u64, 0, chunk, &extra, &trusted), Err(ChunkProofError::PathLength { .. })));
    }

    #[test]
    fn empty_documents_and_final_chunks_have_one_exact_shape() {
        let trusted = doc_commit(1, &[]);
        verify_chunk(1, 0, 0, &[], &[], &trusted).unwrap();
        assert_eq!(verify_chunk(1, 0, 1, &[], &[], &trusted), Err(ChunkProofError::Index { index: 1, chunk_count: 1 }));
        assert_eq!(verify_chunk(1, 0, 0, &[0], &[], &trusted), Err(ChunkProofError::ChunkLength { expected: 0, actual: 1 }));
        assert_eq!(verify_chunk(1, 0, 0, &[], &[[0; 32]], &trusted), Err(ChunkProofError::PathLength { expected: 0, actual: 1 }));
        let bytes = data(DOC_CHUNK_BYTES + 5);
        let trusted = doc_commit(1, &bytes);
        for supplied in [0, 4, 6, DOC_CHUNK_BYTES] {
            let chunk = vec![0; supplied];
            assert_eq!(
                verify_chunk(1, bytes.len() as u64, 1, &chunk, &path(&bytes, 1), &trusted),
                Err(ChunkProofError::ChunkLength { expected: 5, actual: supplied }),
            );
        }
        // A partial redaction inside a non-final chunk cannot claim proof.
        assert_eq!(verify_chunk(1, bytes.len() as u64, 0, &bytes[..100], &path(&bytes, 0), &trusted), Err(ChunkProofError::ChunkLength { expected: DOC_CHUNK_BYTES, actual: 100 }));
    }

    #[test]
    fn hostile_u64_lengths_are_bounded_without_overflow_or_allocation() {
        let count = 1u64 << 52;
        assert_eq!(verify_chunk(1, u64::MAX, count, &[], &[], &[0; 32]), Err(ChunkProofError::Index { index: count, chunk_count: count }));
        assert_eq!(verify_chunk(1, u64::MAX, u64::MAX, &[], &[], &[0; 32]), Err(ChunkProofError::Index { index: u64::MAX, chunk_count: count }));
        let first = [0; DOC_CHUNK_BYTES];
        assert_eq!(verify_chunk(1, u64::MAX, 0, &first, &[], &[0; 32]), Err(ChunkProofError::PathLength { expected: 52, actual: 0 }));
        let last = [0; DOC_CHUNK_BYTES - 1];
        assert_eq!(verify_chunk(1, u64::MAX, count - 1, &last, &[[0; 32]; 52], &[0; 32]), Err(ChunkProofError::Commitment));
    }
}
