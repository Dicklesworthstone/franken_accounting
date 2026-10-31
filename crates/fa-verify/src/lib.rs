//! `fa-verify` — the dependency-free verifier (plan §13.3).
//!
//! An outsider holding a proof and a checkpoint they trust can check, with
//! nothing but this crate and `std`, that:
//!
//! - an entry's leaf envelope — and, when supplied, the entry's own payload
//!   bytes — was recorded in a book's journal at a given position within
//!   the checkpoint's prefix ([`verify_inclusion`], scope `inclusion`);
//! - a later checkpoint the producer claims — read from its state object
//!   with [`verify_state`] — extends the trusted one without rewriting
//!   history ([`verify_consistency`], scope `consistency`);
//! - a list of leaf envelopes is the *complete* prefix the checkpoint
//!   commits, without attesting correct derivation of its selector fields
//!   ([`verify_prefix`], scope `seq_range_complete`);
//! - an account's posted debits and credits in one unit, through a cutoff,
//!   are the fold of exactly the authenticated in-scope entries when every
//!   prefix payload is checked ([`verify_balance`], scope `recomputation`);
//!   legacy proofs with excluded payloads are only `membership_only`;
//! - a verified balance answers the recipient's independently specified
//!   account, unit, cutoff and optional exact amounts ([`verify_balance_for`]);
//! - a document's bytes and kind produce the public `doc_commit` an
//!   entry's evidence cites ([`document::doc_commit`]);
//! - a `TransparencyCheckpoint` was signed by keys the caller trusts
//!   ([`verify_checkpoint`], Ed25519);
//! - one account's entries with an effective day in an interval are all
//!   listed, against that checkpoint's signed scope-index root
//!   ([`verify_scope`], scope `scope_index_complete`), with the premise
//!   labelled: the signers, or the index recomputed from the complete
//!   prefix;
//! - an evidence bundle (`.fab`) is what its manifest says — its entries
//!   exactly the scope's leaves with their payloads, each entry's cited
//!   documents present and, when included, matching their commitments,
//!   its balances recomputed under the fold law they name — and its
//!   detached production receipt was signed over it ([`verify_bundle`],
//!   each predicate graded on its own);
//! - requested redacted chunks belong to the document cited, with the
//!   requested role, by an included entry ([`verify_evidence_view_for`]).
//!
//! What it does not prove (plan §13.1): that an entry reflects what
//! actually happened, that a signer's key belongs to anyone in particular
//! (the caller names the keys it trusts; there is no trust-anchor set or
//! witness policy yet), or anything about a known-at later than the
//! checkpoint's `through_seq`.
//!
//! The crate carries its own BLAKE3 ([`blake3`]), SHA-512 ([`sha512`]),
//! Ed25519 verification ([`ed25519`]), canonical reader, and tree
//! arithmetic, and links no FrankenAccounting or substrate crate: the
//! producer and the verifier are independent implementations of one
//! specification, checked against each other by fa-notary's differential
//! tests and pinned to shared golden vectors (RFC 8032 and RFC 6234 for the
//! signature scheme). Independence makes a shared bug less likely and the
//! differential makes a divergence visible; neither proves the
//! specification itself sound.

#![forbid(unsafe_code)]

pub mod access_log;
pub mod ads;
pub mod balance;
pub mod balance_request;
pub mod blake3;
pub mod bundle;
pub mod checkpoint;
pub mod cli;
pub mod codec;
pub mod disclosure;
pub mod document;
pub mod ed25519;
pub mod envelope;
pub mod evidence;
pub mod migration_balance;
pub mod proof;
pub mod report;
pub mod saft;
pub mod scope;
pub mod sha512;
pub mod state;
pub mod tree;

pub use access_log::{
    AccessLogError, AccessLogRequest, VerifiedAccessEvent, VerifiedAccessLog, verify_access_log,
};
pub use balance::{Balance, BalanceClaim};
pub use balance_request::{
    BalanceAmounts, BalanceExpectation, BalanceExpectationError, BalanceScope, verify_balance_for,
};
pub use bundle::{
    BundleCheck, BundleError, BundleReport, BundleScope, Completeness, Grade, Manifest,
    ReceiptFacts, Summary, verify_bundle,
};
pub use checkpoint::{CheckpointError, SignedCheckpoint, verify_checkpoint};
pub use codec::DecodeError;
pub use envelope::{LeafEnvelope, RecordError};
pub use evidence::{
    EvidenceCitation, EvidenceError, EvidenceExpectation, VerifiedEvidenceView,
    verify_evidence_view_for,
};
pub use proof::{
    Checkpoint, Consistency, Inclusion, Prefix, RecordCheck, VerifyError, verify_consistency,
    verify_inclusion, verify_prefix,
};
pub use scope::{IndexDerivation, ScopeClaim, ScopeReport, recompute_index, verify_scope};
pub use state::{Signatures, State, verify_state};

/// Verify a supported balance format against an independently trusted checkpoint.
/// V3 requires every prefix payload, independently derives the scope, and
/// authenticates migration visibility. V1/v2 remain byte-compatible, but
/// return `membership_only` when excluded payloads leave indexing unverified.
/// No version accepts a checkpoint merely because the proof supplies it.
pub fn verify_balance(
    proof: &[u8],
    trusted_checkpoint: &Checkpoint,
) -> Result<Balance, VerifyError> {
    let mut reader = codec::Reader::new(proof);
    let format = reader.bytes(128, "proof.format")?;
    if format == migration_balance::BALANCE_FORMAT_V2
        || format == migration_balance::BALANCE_FORMAT_V3
    {
        migration_balance::verify_balance(proof, trusted_checkpoint)
    } else {
        balance::verify_balance(proof, trusted_checkpoint)
    }
}

/// Independent verification of the kernel's existing `RedactedView` v1 bytes.
///
/// This is the complete ordered chunk-list format in plan §9.6, not a new
/// bundle or a compact path format. Verification needs a separately trusted
/// document commitment and a nonempty, exact recipient-owned disclosure set.
/// It proves chunk membership only, never the redaction policy, provenance,
/// authority to disclose, journal inclusion, or production-wide completeness.
pub mod redaction {
    use crate::blake3::hash_parts;
    use crate::codec::{DecodeError, Reader, Reason};
    use crate::document::{DOC_CHUNK_BYTES, DOC_DOMAIN, DOC_LEAF_DOMAIN, DOC_NODE_DOMAIN};

    pub const VIEW_DOMAIN: &[u8] = b"fa:redacted-view:v1";
    /// Match the shipped kernel decoder's 64 MiB document ceiling.
    pub const MAX_VIEW_CHUNKS: usize = 64 * 1024 * 1024 / DOC_CHUNK_BYTES;
    /// Header plus the largest canonical encoding of every permitted chunk.
    /// Framing makes a fully disclosed 64 MiB document larger than 64 MiB.
    pub const MAX_VIEW_BYTES: usize = 81 + MAX_VIEW_CHUNKS * (5 + DOC_CHUNK_BYTES);

    /// Parsed for transparency, NOT authenticated by the document commitment.
    /// The kernel binds these through book state and its authorization checks;
    /// an offline chunk proof cannot inherit those checks from two wire fields.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct UnverifiedMetadata {
        pub original: [u8; 32],
        pub contract: u16,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DisclosedChunk<'a> {
        pub index: u64,
        /// Verified bytes, borrowed from the canonical view at this index.
        pub bytes: &'a [u8],
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct VerifiedView<'a> {
        pub scope: &'static str,
        pub kind: u8,
        pub size: u64,
        pub doc_commit: [u8; 32],
        /// Computed artifact identity, not an independently authenticated seal.
        pub view_commit: [u8; 32],
        pub unverified_metadata: UnverifiedMetadata,
        pub disclosed: Vec<DisclosedChunk<'a>>,
        pub withheld_chunks: u64,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ViewError {
        Decode(DecodeError),
        Version(u16),
        Bound(&'static str),
        Request(&'static str),
        ChunkCount {
            expected: usize,
            actual: usize,
        },
        ChunkLength {
            index: u64,
            expected: usize,
            actual: usize,
        },
        Disclosure {
            expected: Option<u64>,
            actual: Option<u64>,
        },
        Commitment,
    }

    impl core::fmt::Display for ViewError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::Decode(error) => write!(f, "{error}"),
                Self::Version(version) => {
                    write!(f, "unsupported redacted-view version {version}")
                }
                Self::Bound(field) => write!(f, "redacted-view {field} exceeds the decoder bound"),
                Self::Request(why) => write!(f, "invalid disclosure request: {why}"),
                Self::ChunkCount { expected, actual } => {
                    write!(
                        f,
                        "document requires {expected} chunks; view carries {actual}"
                    )
                }
                Self::ChunkLength {
                    index,
                    expected,
                    actual,
                } => {
                    write!(
                        f,
                        "chunk {index} requires {expected} bytes; view carries {actual}"
                    )
                }
                Self::Disclosure { expected, actual } => {
                    write!(
                        f,
                        "disclosure set mismatch: expected next chunk {expected:?}, got {actual:?}"
                    )
                }
                Self::Commitment => write!(
                    f,
                    "view does not reproduce the independently trusted document commitment"
                ),
            }
        }
    }

    impl core::error::Error for ViewError {
        fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
            match self {
                Self::Decode(error) => Some(error),
                _ => None,
            }
        }
    }

    impl From<DecodeError> for ViewError {
        fn from(error: DecodeError) -> Self {
            Self::Decode(error)
        }
    }

    /// Verify actual kernel-produced view bytes. `requested` is the exact
    /// strictly ascending set the recipient expects to see, not a list copied
    /// from the view. Empty requests are refused: a wholly withheld document
    /// proves no disclosed bytes. An empty DOCUMENT still has chunk zero.
    ///
    /// The complete chunk layout, exact final length, every withheld digest,
    /// and the separate trusted commitment are checked before any report is
    /// returned. Neither a producer-supplied root nor a valid partial response
    /// can satisfy this request. No withheld bytes are fetched or fabricated.
    pub fn verify_view_for<'a>(
        bytes: &'a [u8],
        trusted_doc_commit: &[u8; 32],
        requested: &[u64],
    ) -> Result<VerifiedView<'a>, ViewError> {
        if requested.is_empty() || requested.len() > MAX_VIEW_CHUNKS {
            return Err(ViewError::Request(
                "name between one and MAX_VIEW_CHUNKS chunks",
            ));
        }
        if requested.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ViewError::Request(
                "indices must be strictly ascending, with no duplicates",
            ));
        }
        if bytes.len() > MAX_VIEW_BYTES {
            return Err(ViewError::Bound("encoded bytes"));
        }
        let mut r = Reader::new(bytes);
        let version = r.u16("view.version")?;
        if version != 1 {
            return Err(ViewError::Version(version));
        }
        let unverified_metadata = UnverifiedMetadata {
            original: r.fixed("view.original")?,
            contract: r.u16("view.contract")?,
        };
        let kind = r.u8("view.kind")?;
        let size = r.u64("view.size")?;
        if size > (MAX_VIEW_CHUNKS * DOC_CHUNK_BYTES) as u64 {
            return Err(ViewError::Bound("document size"));
        }
        let doc_commit: [u8; 32] = r.fixed("view.doc_commit")?;
        if doc_commit != *trusted_doc_commit {
            return Err(ViewError::Commitment);
        }
        // The size bound makes these conversions exact even on 32-bit hosts.
        let expected = (size as usize).div_ceil(DOC_CHUNK_BYTES).max(1);
        if requested
            .last()
            .is_some_and(|index| *index >= expected as u64)
        {
            return Err(ViewError::Request("an index is outside the document"));
        }
        let count = r.count(MAX_VIEW_CHUNKS, 5, "view.chunks")?;
        if count != expected {
            return Err(ViewError::ChunkCount {
                expected,
                actual: count,
            });
        }
        let mut leaves = Vec::with_capacity(count);
        let mut disclosed = Vec::with_capacity(requested.len());
        for i in 0..count {
            let index = i as u64;
            let digest = match r.u8("view.chunk")? {
                0 => {
                    let chunk = r.bytes(DOC_CHUNK_BYTES, "view.chunk.bytes")?;
                    let expected = (size as usize)
                        .saturating_sub(i * DOC_CHUNK_BYTES)
                        .min(DOC_CHUNK_BYTES);
                    if chunk.len() != expected {
                        return Err(ViewError::ChunkLength {
                            index,
                            expected,
                            actual: chunk.len(),
                        });
                    }
                    if requested.get(disclosed.len()).copied() != Some(index) {
                        return Err(ViewError::Disclosure {
                            expected: requested.get(disclosed.len()).copied(),
                            actual: Some(index),
                        });
                    }
                    disclosed.push(DisclosedChunk {
                        index,
                        bytes: chunk,
                    });
                    hash_parts(
                        DOC_LEAF_DOMAIN,
                        &[
                            &index.to_le_bytes(),
                            &(chunk.len() as u64).to_le_bytes(),
                            chunk,
                        ],
                    )
                }
                1 => r.fixed("view.chunk.leaf")?,
                tag => return Err(r.error("view.chunk", Reason::BadTag(tag)).into()),
            };
            leaves.push(digest);
        }
        r.finish("redacted view")?;
        if disclosed.len() != requested.len() {
            return Err(ViewError::Disclosure {
                expected: requested.get(disclosed.len()).copied(),
                actual: None,
            });
        }
        // Collapse in place, promoting an odd last node unchanged. The
        // nonzero authenticated shape above makes leaves[0] well-defined.
        let mut width = leaves.len();
        while width > 1 {
            for (out, left) in (0..width).step_by(2).enumerate() {
                let digest = if left + 1 < width {
                    hash_parts(DOC_NODE_DOMAIN, &[&leaves[left], &leaves[left + 1]])
                } else {
                    leaves[left]
                };
                leaves[out] = digest;
            }
            width = width.div_ceil(2);
        }
        if hash_parts(DOC_DOMAIN, &[&[kind], &size.to_le_bytes(), &leaves[0]]) != doc_commit {
            return Err(ViewError::Commitment);
        }
        // Unlike the document tree's raw transcripts, the kernel derives
        // this identity with fa_model::domain_digest: each part has a u32
        // byte-length prefix. MAX_VIEW_BYTES already bounds this conversion.
        let view_length =
            u32::try_from(bytes.len()).map_err(|_| ViewError::Bound("encoded bytes"))?;
        Ok(VerifiedView {
            scope: "membership_only",
            kind,
            size,
            doc_commit,
            view_commit: hash_parts(VIEW_DOMAIN, &[&view_length.to_le_bytes(), bytes]),
            unverified_metadata,
            withheld_chunks: (count - disclosed.len()) as u64,
            disclosed,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::codec::Writer;
        use crate::document::doc_commit;

        // Literal existing kernel wire format, independently encoded here.
        // The trusted commitment comes from the full document, not this view.
        fn encode(doc: &[u8], kind: u8, shown: &[u64]) -> Vec<u8> {
            let chunks: Vec<&[u8]> = if doc.is_empty() {
                vec![&[]]
            } else {
                doc.chunks(DOC_CHUNK_BYTES).collect()
            };
            let mut w = Writer::default();
            w.u16(1)
                .fixed(&[17; 32])
                .u16(7)
                .u8(kind)
                .u64(doc.len() as u64)
                .fixed(&doc_commit(kind, doc))
                .count(chunks.len());
            for (i, chunk) in chunks.iter().enumerate() {
                if shown.contains(&(i as u64)) {
                    w.u8(0).bytes(chunk);
                } else {
                    w.u8(1).fixed(&hash_parts(
                        DOC_LEAF_DOMAIN,
                        &[
                            &(i as u64).to_le_bytes(),
                            &(chunk.len() as u64).to_le_bytes(),
                            chunk,
                        ],
                    ));
                }
            }
            w.buf
        }

        fn document(len: usize) -> Vec<u8> {
            (0..len)
                .map(|i| ((i * 17 + i / DOC_CHUNK_BYTES) % 251) as u8)
                .collect()
        }

        #[test]
        fn view_identity_uses_model_length_framing_not_the_raw_tree_transcript() {
            // Existing wire format: original [17; 32], contract 7, kind 1.
            // Goldens independently calculated with a Python BLAKE3 model
            // checked against the repository's official-convention vectors.
            for (doc, shown, expected) in [
                (
                    Vec::new(),
                    vec![0],
                    "3f0c42ba104ed3e9c08d79d58146bc32c667665caba76ce4680eb0be9f0c86da",
                ),
                (
                    b"abc".to_vec(),
                    vec![0],
                    "2eb7705bf26d6dcb9a683af37aded44f06e8fdba7902dcc30a282958da47be64",
                ),
                (
                    document(8193),
                    vec![0, 2],
                    "8e18d8cd374945329a705b3e07e6e2315a66b8067301c96209870a63c5232c02",
                ),
            ] {
                let bytes = encode(&doc, 1, &shown);
                let report = verify_view_for(&bytes, &doc_commit(1, &doc), &shown).unwrap();
                let mut transcript = VIEW_DOMAIN.to_vec();
                let length = u32::try_from(bytes.len()).unwrap().to_le_bytes();
                transcript.extend_from_slice(&length);
                transcript.extend_from_slice(&bytes);
                assert_eq!(report.view_commit, crate::blake3::hash(&transcript));
                assert_ne!(report.view_commit, hash_parts(VIEW_DOMAIN, &[&bytes]));
                assert_eq!(crate::blake3::hex(&report.view_commit), expected);
            }
        }

        #[test]
        fn exact_disclosures_verify_empty_partial_even_and_odd_documents() {
            for len in [0, 1, 4095, 4096, 4097, 8192, 8193, 16385, 28673] {
                let doc = document(len);
                let count = len.div_ceil(DOC_CHUNK_BYTES).max(1);
                let shown: Vec<u64> = (0..count)
                    .filter(|i| i % 2 == 0)
                    .map(|i| i as u64)
                    .collect();
                for kind in [1, 9] {
                    let bytes = encode(&doc, kind, &shown);
                    let report = verify_view_for(&bytes, &doc_commit(kind, &doc), &shown).unwrap();
                    assert_eq!(report.scope, "membership_only");
                    assert_eq!(report.kind, kind);
                    assert_eq!(report.size, len as u64);
                    assert_eq!(report.withheld_chunks, (count - shown.len()) as u64);
                    for (chunk, wanted) in report.disclosed.iter().zip(&shown) {
                        let start = *wanted as usize * DOC_CHUNK_BYTES;
                        assert_eq!(chunk.index, *wanted);
                        assert_eq!(chunk.bytes, &doc[start..(start + DOC_CHUNK_BYTES).min(len)]);
                    }
                }
            }
        }

        #[test]
        fn valid_membership_cannot_hide_an_incomplete_or_extra_response() {
            let doc = document(3 * DOC_CHUNK_BYTES);
            let anchor = doc_commit(1, &doc);
            for shown in [&[0u64][..], &[0, 1, 2], &[1, 2], &[0, 1]] {
                let bytes = encode(&doc, 1, shown);
                assert!(verify_view_for(&bytes, &anchor, shown).is_ok());
                assert!(matches!(
                    verify_view_for(&bytes, &anchor, &[0, 2]),
                    Err(ViewError::Disclosure { .. })
                ));
            }
            let bytes = encode(&doc, 1, &[0, 2]);
            assert!(verify_view_for(&bytes, &anchor, &[0, 2]).is_ok());
        }

        #[test]
        fn empty_duplicate_unsorted_and_out_of_range_requests_fail() {
            let doc = document(8193);
            let bytes = encode(&doc, 1, &[0, 2]);
            let anchor = doc_commit(1, &doc);
            for requested in [&[][..], &[0, 0], &[2, 0], &[3], &[u64::MAX]] {
                assert!(matches!(
                    verify_view_for(&bytes, &anchor, requested),
                    Err(ViewError::Request(_))
                ));
            }
            let wholly_withheld = encode(&doc, 1, &[]);
            assert!(verify_view_for(&wholly_withheld, &anchor, &[]).is_err());
            assert!(verify_view_for(&wholly_withheld, &anchor, &[0]).is_err());
        }

        #[test]
        fn every_chunk_and_the_separate_trusted_anchor_are_load_bearing() {
            let doc = document(8193);
            let anchor = doc_commit(1, &doc);
            let bytes = encode(&doc, 1, &[0, 2]);
            // Header is 81 bytes. First record is 5+4096; next is a
            // withheld tag+hash. Last record is 5+1 disclosed bytes.
            for offset in [86, 81 + 4101 + 1, bytes.len() - 1, 36, 45] {
                let mut corrupt = bytes.clone();
                corrupt[offset] ^= 1;
                assert!(
                    verify_view_for(&corrupt, &anchor, &[0, 2]).is_err(),
                    "offset {offset}"
                );
            }
            let wrong_anchor = doc_commit(2, &doc);
            assert_eq!(
                verify_view_for(&bytes, &wrong_anchor, &[0, 2]),
                Err(ViewError::Commitment)
            );
            let mut replaced = bytes.clone();
            replaced[45..77].copy_from_slice(&wrong_anchor);
            assert_eq!(
                verify_view_for(&replaced, &anchor, &[0, 2]),
                Err(ViewError::Commitment)
            );
        }

        #[test]
        fn locator_and_contract_are_explicitly_unverified_not_proof_authority() {
            let doc = document(11);
            let bytes = encode(&doc, 1, &[0]);
            let anchor = doc_commit(1, &doc);
            let original = verify_view_for(&bytes, &anchor, &[0]).unwrap();
            let mut relabeled = bytes.clone();
            relabeled[2] ^= 1;
            relabeled[34] ^= 1;
            let report = verify_view_for(&relabeled, &anchor, &[0]).unwrap();
            assert_eq!(report.disclosed, original.disclosed);
            assert_eq!(report.doc_commit, original.doc_commit);
            assert_ne!(report.unverified_metadata, original.unverified_metadata);
            assert_ne!(report.view_commit, original.view_commit);
            assert_eq!(report.scope, "membership_only");
        }

        #[test]
        fn malformed_framing_never_returns_a_partial_report() {
            let doc = document(17);
            let bytes = encode(&doc, 1, &[0]);
            let anchor = doc_commit(1, &doc);
            for end in 0..bytes.len() {
                assert!(
                    verify_view_for(&bytes[..end], &anchor, &[0]).is_err(),
                    "prefix {end}"
                );
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(verify_view_for(&trailing, &anchor, &[0]).is_err());
            for (offset, field) in [
                (0, 2u16.to_le_bytes().to_vec()),
                (37, u64::MAX.to_le_bytes().to_vec()),
                (77, 0u32.to_le_bytes().to_vec()),
                (77, u32::MAX.to_le_bytes().to_vec()),
                (81, vec![2]),
                (82, 4097u32.to_le_bytes().to_vec()),
            ] {
                let mut invalid = bytes.clone();
                invalid[offset..offset + field.len()].copy_from_slice(&field);
                assert!(
                    verify_view_for(&invalid, &anchor, &[0]).is_err(),
                    "field {offset}"
                );
            }
            let mut short = bytes.clone();
            short[82..86].copy_from_slice(&16u32.to_le_bytes());
            let _ = short.pop();
            assert!(matches!(
                verify_view_for(&short, &anchor, &[0]),
                Err(ViewError::ChunkLength { .. })
            ));
        }
    }
}

#[cfg(test)]
mod balance_dispatch_tests {
    use super::*;

    #[test]
    fn public_balance_verifier_accepts_all_versions_without_changing_v1() {
        let checkpoint = Checkpoint {
            book_id: [1; 16],
            branch_id: [0; 16],
            through_seq: 0,
            leaf_count: 0,
            root: tree::empty_root(),
        };
        for format in [
            balance::BALANCE_FORMAT,
            migration_balance::BALANCE_FORMAT_V2,
            migration_balance::BALANCE_FORMAT_V3,
        ] {
            let mut w = codec::Writer::default();
            w.bytes(format)
                .fixed(&checkpoint.encode())
                .u128(10)
                .u32(1)
                .u8(0)
                .i128(0)
                .i128(0)
                .count(0)
                .count(0);
            if format != balance::BALANCE_FORMAT {
                w.count(0);
            }
            let report = verify_balance(&w.buf, &checkpoint).unwrap();
            assert_eq!(report.scope, "recomputation");
            assert!(report.contributing.is_empty());
            assert_eq!((report.claim.debits, report.claim.credits), (0, 0));
            if format == balance::BALANCE_FORMAT {
                assert_eq!(
                    balance::verify_balance(&w.buf, &checkpoint).unwrap(),
                    report
                );
            }
        }
    }
}
