//! Notary — the journal accumulator (plan §13.2, FA-INV-14).
//!
//! Every committed entry — posting and control classes alike — is one leaf
//! of a Merkle Mountain Range, in commit order, over a domain-separated
//! leaf envelope that binds the entry's digest, its recorded commit
//! sequence, and its selection fields ([`journal`]). The accumulator is a
//! derived, rebuildable structure: its root at any sequence is a pure
//! function of the journal prefix, recomputed from the authoritative
//! payloads, never maintained inside the posting transaction ([`tree`]).
//!
//! The notary journals [`AccumulatorState`] objects — content-addressed,
//! chained by `prev_state_oid` under a compare-and-set on the book's head
//! pointer — and [`verify_accumulator`] recomputes every one of them from
//! the journal. Proofs are issued only against a state the journal
//! reproduces, in the byte formats the dependency-free `fa-verify` checks:
//! inclusion of an entry (optionally with its own payload), consistency
//! between two states, and the complete prefix (`SeqRangeComplete`).
//!
//! Not here yet, by name: signed and witnessed `TransparencyCheckpoint`s
//! (plan §13.5), the scope index and `ScopeIndexComplete` (plan §13.1), the
//! substrate chain-commitment cross-anchor (R-MMR), and bundles.

#![forbid(unsafe_code)]

pub mod disclosure;
pub mod journal;
pub mod migration_balance;
pub mod prefix;
pub mod state;
pub mod tree;

use fa_model::{Id128, Writer};
use fgdb_types::CommitSeq;

pub use journal::{Journal, Leaf, LeafEnvelope};
pub use migration_balance::prove_balance_with_migrations;
pub use state::{
    AccumulatorState, AccumulatorVerification, Checkpointed, StateCheck, StoredState, chain,
    checkpoint, latest, prove_balance, prove_consistency, prove_inclusion, prove_prefix, state_oid,
    state_vid, verify_accumulator,
};

/// Refusal codes the notary issues (`FA-REF-12x`).
pub mod code {
    /// The entry is not in the selected accumulator prefix.
    pub const NOT_IN_PREFIX: &str = "FA-REF-120";
    /// The journal does not reproduce or extend a journaled state.
    pub const ACCUMULATOR_DRIFT: &str = "FA-REF-121";
    /// Another state was published from the same head.
    pub const HEAD_MOVED: &str = "FA-REF-122";
    /// The book moved while the accumulator was computed.
    pub const BASIS_MOVED: &str = "FA-REF-123";
    /// A later state does not extend an earlier one.
    pub const NOT_EXTENDED: &str = "FA-REF-124";
    /// The selected known-at sequence is beyond the head.
    pub const BEYOND_HEAD: &str = "FA-REF-125";
    /// A balance proof would count a migration chunk with unsupported
    /// visibility: its run has no Finalize in the prefix, or it predates
    /// the run's opening date. The latter may be summarized history or
    /// sole-source detail; v1 cannot authenticate that distinction (fa-e00).
    /// Missing or contradictory migration records also fail closed.
    pub const MIGRATION_STAGED: &str = "FA-REF-133";
}

/// What a checkpoint commits: the root over the first `leaf_count` leaves
/// of a book branch's journal — exactly the entries recorded at or before
/// `through_seq`. Encoded as `book_id ‖ branch_id ‖ through_seq u64 ‖
/// leaf_count u64 ‖ root` (80 bytes), the form every proof embeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statement {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub through_seq: CommitSeq,
    pub leaf_count: u64,
    pub root: [u8; 32],
}

impl Statement {
    pub fn encode(&self, w: &mut Writer) {
        w.fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u64(self.through_seq.0)
            .u64(self.leaf_count)
            .fixed(&self.root);
    }
}

/// Selective evidence disclosure against the existing public document
/// commitment (plan §9.1). This module constructs proofs; it grants no right
/// to disclose bytes. Authorization and redaction policy stay with the caller.
pub mod document {
    use fgdb_crypto::Hasher;

    const CHUNK_BYTES: usize = fa_journal::evidence::CHUNK_BYTES;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum DocumentProofError {
        Length,
        Index { index: u64, chunk_count: u64 },
    }

    impl core::fmt::Display for DocumentProofError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::Length => write!(f, "document length exceeds the canonical u64 range"),
                Self::Index { index, chunk_count } => {
                    write!(f, "document chunk {index} is outside {chunk_count} chunks")
                }
            }
        }
    }

    impl core::error::Error for DocumentProofError {}

    /// The selected whole chunk and its canonical leaf-to-root sibling path.
    /// No unselected bytes are included. The recipient must independently
    /// obtain the trusted document commitment; this proof cannot supply it.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ChunkProof<'a> {
        pub kind: u8,
        pub document_length: u64,
        pub index: u64,
        pub bytes: &'a [u8],
        pub siblings: Vec<[u8; 32]>,
    }

    /// A derived, in-memory proof index over one immutable borrowed document.
    /// Build once in O(document bytes) time and O(chunks) hash storage, then
    /// issue each path in O(log chunks). No journal object or policy is changed.
    /// This uses the producer's crypto implementation, never fa-verify's.
    pub struct DocumentProofTree<'a> {
        kind: u8,
        bytes: &'a [u8],
        document_length: u64,
        commitment: [u8; 32],
        levels: Vec<Vec<[u8; 32]>>,
    }

    fn digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(domain);
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().0
    }

    fn leaf(index: usize, bytes: &[u8]) -> [u8; 32] {
        // Construction already checked that the entire input length fits u64;
        // a chunk index and a chunk length can therefore be represented too.
        digest(
            b"fa:doc:leaf:v1",
            &[&(index as u64).to_le_bytes(), &(bytes.len() as u64).to_le_bytes(), bytes],
        )
    }

    fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        digest(b"fa:doc:node:v1", &[left, right])
    }

    impl<'a> DocumentProofTree<'a> {
        /// The input must already have passed the caller's document-size and
        /// disclosure-authorization limits. Pure construction does not perform
        /// storage reads or bypass the kernel's protected-document boundary.
        pub fn new(kind: u8, bytes: &'a [u8]) -> Result<Self, DocumentProofError> {
            let document_length = u64::try_from(bytes.len()).map_err(|_| DocumentProofError::Length)?;
            let mut level = if bytes.is_empty() {
                vec![leaf(0, &[])]
            } else {
                bytes.chunks(CHUNK_BYTES).enumerate()
                    .map(|(i, chunk)| leaf(i, chunk)).collect::<Vec<_>>()
            };
            let mut levels = Vec::new();
            while level.len() > 1 {
                let next = level.chunks(2).map(|pair| match pair {
                    [left, right] => node(left, right),
                    _ => pair[0],
                }).collect::<Vec<_>>();
                levels.push(level);
                level = next;
            }
            // There is always at least the empty leaf; no fabricated root.
            let root = level[0];
            levels.push(level);
            let commitment = digest(
                b"fa:doc:v1",
                &[&[kind], &document_length.to_le_bytes(), &root],
            );
            Ok(Self { kind, bytes, document_length, commitment, levels })
        }

        /// Recomputed from all input bytes, suitable for comparison with the
        /// kernel's retained citation. A caller must not treat this producer-
        /// selected value itself as an independently trusted anchor.
        #[must_use]
        pub fn doc_commit(&self) -> [u8; 32] {
            self.commitment
        }

        #[must_use]
        pub fn chunk_count(&self) -> u64 {
            self.levels[0].len() as u64
        }

        /// Disclose exactly one whole chunk. No sibling is emitted for an
        /// unpaired node; the independent verifier derives those promotions.
        /// Byte ranges smaller than a chunk need a disclosure_only policy,
        /// not a false proof over replacement or omitted bytes.
        pub fn prove(&self, index: u64) -> Result<ChunkProof<'a>, DocumentProofError> {
            let bad_index = || DocumentProofError::Index {
                index,
                chunk_count: self.chunk_count(),
            };
            let position = usize::try_from(index).map_err(|_| bad_index())?;
            if position >= self.levels[0].len() {
                return Err(bad_index());
            }
            let start = position.checked_mul(CHUNK_BYTES).ok_or_else(bad_index)?;
            let end = start.saturating_add(CHUNK_BYTES).min(self.bytes.len());
            let bytes = self.bytes.get(start..end).ok_or_else(bad_index)?;
            let mut siblings = Vec::with_capacity(self.levels.len() - 1);
            let mut position = position;
            for level in &self.levels[..self.levels.len() - 1] {
                if let Some(sibling) = level.get(position ^ 1) {
                    siblings.push(*sibling);
                }
                position /= 2;
            }
            Ok(ChunkProof {
                kind: self.kind,
                document_length: self.document_length,
                index,
                bytes,
                siblings,
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use fa_verify::document::{ChunkProofError, verify_chunk};

        fn verify(proof: &ChunkProof<'_>, trusted: &[u8; 32]) -> Result<(), ChunkProofError> {
            let report = verify_chunk(
                proof.kind, proof.document_length, proof.index,
                proof.bytes, &proof.siblings, trusted,
            )?;
            assert_eq!(report.scope, "membership_only");
            Ok(())
        }

        fn bytes(size: usize) -> Vec<u8> {
            (0..size).map(|i| ((i * 37 + 19) % 251) as u8).collect()
        }

        #[test]
        fn producer_paths_match_kernel_commitments_and_the_independent_verifier() {
            let mut sizes = vec![0, 1, CHUNK_BYTES - 1];
            for count in 1..=33 {
                sizes.extend([count * CHUNK_BYTES, count * CHUNK_BYTES + 3]);
            }
            for size in sizes {
                let bytes = bytes(size);
                for kind in [1, 2, 9] {
                    let tree = DocumentProofTree::new(kind, &bytes).unwrap();
                    let kernel = fa_journal::evidence::doc_commit(kind, &bytes);
                    assert_eq!(tree.doc_commit(), kernel, "length {size}, kind {kind}");
                    assert_eq!(fa_verify::document::doc_commit(kind, &bytes), kernel);
                    for index in 0..tree.chunk_count() {
                        let proof = tree.prove(index).unwrap();
                        verify(&proof, &kernel).unwrap();
                        assert_eq!(proof, tree.prove(index).unwrap());
                        assert!(proof.bytes.len() <= CHUNK_BYTES);
                    }
                }
            }
        }

        #[test]
        fn the_fifth_chunk_discloses_only_its_bytes_and_one_left_subtree() {
            let bytes = bytes(CHUNK_BYTES * 4 + 7);
            let tree = DocumentProofTree::new(1, &bytes).unwrap();
            let proof = tree.prove(4).unwrap();
            assert_eq!(proof.bytes, &bytes[CHUNK_BYTES * 4..]);
            let expected = fa_journal::evidence::chunk_root(&bytes[..CHUNK_BYTES * 4]);
            assert_eq!(proof.siblings, vec![expected]);
            verify(&proof, &fa_journal::evidence::doc_commit(1, &bytes)).unwrap();
            assert_eq!(tree.prove(0).unwrap().siblings.len(), 3);
        }

        #[test]
        fn produced_proofs_cannot_be_retargeted_or_spliced_into_another_document() {
            let bytes = bytes(CHUNK_BYTES * 3 + 11);
            let tree = DocumentProofTree::new(1, &bytes).unwrap();
            let trusted = fa_journal::evidence::doc_commit(1, &bytes);
            let good = tree.prove(0).unwrap();
            verify(&good, &trusted).unwrap();
            let mut bad = good.clone();
            bad.index = 1;
            assert!(verify(&bad, &trusted).is_err());
            bad = good.clone();
            bad.kind = 2;
            assert!(verify(&bad, &trusted).is_err());
            bad = good.clone();
            bad.document_length += 1;
            assert!(verify(&bad, &trusted).is_err());
            bad = good.clone();
            bad.siblings[0][0] ^= 1;
            assert!(verify(&bad, &trusted).is_err());
            let other = vec![42; bytes.len()];
            let other_tree = DocumentProofTree::new(1, &other).unwrap();
            assert!(verify(&other_tree.prove(0).unwrap(), &trusted).is_err());
        }

        #[test]
        fn empty_documents_have_one_chunk_and_invalid_indexes_never_panic() {
            let tree = DocumentProofTree::new(1, &[]).unwrap();
            assert_eq!(tree.chunk_count(), 1);
            let proof = tree.prove(0).unwrap();
            assert!(proof.bytes.is_empty());
            assert!(proof.siblings.is_empty());
            verify(&proof, &fa_journal::evidence::doc_commit(1, &[])).unwrap();
            for index in [1, u64::MAX] {
                assert_eq!(tree.prove(index), Err(DocumentProofError::Index { index, chunk_count: 1 }));
            }
            let bytes = bytes(CHUNK_BYTES * 5);
            let tree = DocumentProofTree::new(1, &bytes).unwrap();
            for index in [5, u64::MAX] {
                assert_eq!(tree.prove(index), Err(DocumentProofError::Index { index, chunk_count: 5 }));
            }
        }
    }
}
