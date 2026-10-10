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
