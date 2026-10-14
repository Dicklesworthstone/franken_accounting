//! Portable whole-chunk document disclosures (plan §9.1 / §13.3).
//!
//! ```text
//! bytes("fa:document-disclosure:v1") || kind u8 || document_length u64
//! || list(index u64 || bytes(chunk) || list(sibling [u8;32]))
//! ```
//!
//! Integers are little-endian; byte strings and lists have u32 lengths.
//! The separately trusted document commitment and recipient's requested
//! indexes are deliberately NOT in the artifact. A producer cannot choose
//! the trust anchor or silently replace the question being answered.
//!
//! Decoding is bounded before allocation. Disclosed bytes borrow the input;
//! at most 52 sibling hashes per chunk are copied. The complete frame and
//! exact requested index set are checked before any membership verification.
//! Success discloses metadata only, not the document bytes themselves.

use crate::codec::{DecodeError, Reader};
use crate::document::{
    ChunkDisclosure, DOC_CHUNK_BYTES, DisclosureError, SCOPE_CHUNK_MEMBERSHIP, VerifiedChunk,
    verify_disclosure_for,
};

pub const FORMAT: &[u8] = b"fa:document-disclosure:v1";
pub const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_DISCLOSURE_CHUNKS: usize = 16_384;
/// ceil(log2(ceil(u64::MAX / 4096))) = 52, including odd-node promotions.
pub const MAX_SIBLINGS: usize = 52;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisclosureProofError {
    Format,
    InputLimit { maximum: usize, actual: usize },
    RequestLimit { maximum: usize, actual: usize },
    Count { requested: usize, supplied: usize },
    Decode(DecodeError),
    Disclosure(DisclosureError),
}

impl core::fmt::Display for DisclosureProofError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Format => write!(f, "unsupported document disclosure format"),
            Self::InputLimit { maximum, actual } => {
                write!(
                    f,
                    "document disclosure has {actual} bytes; maximum is {maximum}"
                )
            }
            Self::RequestLimit { maximum, actual } => {
                write!(
                    f,
                    "document request has {actual} chunks; maximum is {maximum}"
                )
            }
            Self::Count {
                requested,
                supplied,
            } => {
                write!(
                    f,
                    "document request needs {requested} chunks, proof supplies {supplied}"
                )
            }
            Self::Decode(error) => write!(f, "{error}"),
            Self::Disclosure(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for DisclosureProofError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            Self::Disclosure(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DecodeError> for DisclosureProofError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

impl From<DisclosureError> for DisclosureProofError {
    fn from(error: DisclosureError) -> Self {
        Self::Disclosure(error)
    }
}

/// Every returned chunk belongs to the same independently trusted document
/// and matches the recipient's exact request. This remains membership-only:
/// no signature, provenance, authorization or production completeness claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDisclosure {
    pub scope: &'static str,
    pub kind: u8,
    pub document_length: u64,
    pub chunks: Vec<VerifiedChunk>,
}

/// Validate the recipient-owned request without reading an artifact.
/// Order is significant; duplicates and unsorted indexes are not normalized.
pub fn validate_request(indexes: &[u64]) -> Result<(), DisclosureProofError> {
    if indexes.is_empty() {
        return Err(DisclosureError::EmptyRequest.into());
    }
    if indexes.len() > MAX_DISCLOSURE_CHUNKS {
        return Err(DisclosureProofError::RequestLimit {
            maximum: MAX_DISCLOSURE_CHUNKS,
            actual: indexes.len(),
        });
    }
    if indexes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DisclosureError::RequestOrder.into());
    }
    Ok(())
}

/// Decode and verify an exported disclosure, all-or-nothing.
/// The caller supplies both the trusted commitment and requested indexes
/// independently of the file. No result escapes for a malformed later chunk,
/// a trailing suffix, a different request or a failed membership proof.
pub fn verify(
    proof: &[u8],
    requested_indexes: &[u64],
    trusted_doc_commit: &[u8; 32],
) -> Result<VerifiedDisclosure, DisclosureProofError> {
    validate_request(requested_indexes)?;
    if proof.len() > MAX_PROOF_BYTES {
        return Err(DisclosureProofError::InputLimit {
            maximum: MAX_PROOF_BYTES,
            actual: proof.len(),
        });
    }
    let mut reader = Reader::new(proof);
    if reader.bytes(128, "disclosure.format")? != FORMAT {
        return Err(DisclosureProofError::Format);
    }
    let kind = reader.u8("disclosure.kind")?;
    let document_length = reader.u64("disclosure.document_length")?;
    let count = reader.count(MAX_DISCLOSURE_CHUNKS, 16, "disclosure.chunks")?;
    if count != requested_indexes.len() {
        return Err(DisclosureProofError::Count {
            requested: requested_indexes.len(),
            supplied: count,
        });
    }
    let mut decoded = Vec::with_capacity(count);
    for (position, expected) in requested_indexes.iter().enumerate() {
        let index = reader.u64("chunk.index")?;
        if index != *expected {
            return Err(DisclosureError::Set {
                position,
                expected: Some(*expected),
                actual: Some(index),
            }
            .into());
        }
        let bytes = reader.bytes(DOC_CHUNK_BYTES, "chunk.bytes")?;
        let count = reader.count(MAX_SIBLINGS, 32, "chunk.siblings")?;
        let mut siblings = Vec::with_capacity(count);
        for _ in 0..count {
            siblings.push(reader.fixed::<32>("chunk.sibling")?);
        }
        decoded.push((index, bytes, siblings));
    }
    reader.finish("document disclosure")?;
    let chunks: Vec<_> = decoded
        .iter()
        .map(|(index, bytes, siblings)| ChunkDisclosure {
            index: *index,
            bytes,
            siblings,
        })
        .collect();
    let chunks = verify_disclosure_for(
        kind,
        document_length,
        &chunks,
        requested_indexes,
        trusted_doc_commit,
    )?;
    Ok(VerifiedDisclosure {
        scope: SCOPE_CHUNK_MEMBERSHIP,
        kind,
        document_length,
        chunks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Reason, Writer};
    use crate::document::doc_commit;

    fn header(length: u64, count: usize) -> Writer {
        let mut w = Writer::default();
        w.bytes(FORMAT).u8(1).u64(length).count(count);
        w
    }

    fn empty() -> Vec<u8> {
        let mut w = header(0, 1);
        w.u64(0).bytes(&[]).count(0);
        w.buf
    }

    #[test]
    fn empty_document_is_a_real_authenticated_chunk_not_an_empty_request() {
        let proof = empty();
        let report = verify(&proof, &[0], &doc_commit(1, &[])).unwrap();
        assert_eq!(report.scope, "membership_only");
        assert_eq!(report.document_length, 0);
        assert_eq!(report.chunks.len(), 1);
        assert_eq!(report.chunks[0].byte_length, 0);
        assert!(verify(&proof, &[], &doc_commit(1, &[])).is_err());
        assert!(verify(&proof, &[0], &doc_commit(1, &[0])).is_err());
    }

    #[test]
    fn truncation_trailing_bytes_unknown_formats_and_resource_claims_refuse() {
        let proof = empty();
        let trusted = doc_commit(1, &[]);
        for length in 0..proof.len() {
            assert!(verify(&proof[..length], &[0], &trusted).is_err());
        }
        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(matches!(
            verify(&trailing, &[0], &trusted),
            Err(DisclosureProofError::Decode(DecodeError {
                reason: Reason::Trailing,
                ..
            }))
        ));
        let mut wrong_format = proof;
        wrong_format[4] ^= 1;
        assert_eq!(
            verify(&wrong_format, &[0], &trusted),
            Err(DisclosureProofError::Format)
        );
        let mut overlong = header(4097, 1);
        overlong.u64(0).bytes(&vec![0; 4097]).count(0);
        assert!(matches!(
            verify(&overlong.buf, &[0], &trusted),
            Err(DisclosureProofError::Decode(DecodeError {
                reason: Reason::TooLong { .. },
                ..
            }))
        ));
        let mut path = header(1, 1);
        path.u64(0).bytes(&[0]).count(MAX_SIBLINGS + 1);
        assert!(matches!(
            verify(&path.buf, &[0], &trusted),
            Err(DisclosureProofError::Decode(DecodeError {
                reason: Reason::TooLong { .. },
                ..
            }))
        ));
        let malicious_count = header(0, MAX_DISCLOSURE_CHUNKS + 1);
        assert!(matches!(
            verify(&malicious_count.buf, &[0], &trusted),
            Err(DisclosureProofError::Decode(DecodeError {
                reason: Reason::TooLong { .. },
                ..
            }))
        ));
    }

    #[test]
    fn the_entire_recipient_request_is_checked_before_membership_work() {
        let mut w = header(8192, 2);
        // First chunk is intentionally not a valid membership proof. The
        // second index still determines the set mismatch before hashing.
        w.u64(0).bytes(&[]).count(0).u64(3).bytes(&[]).count(0);
        assert!(matches!(
            verify(&w.buf, &[0, 1], &[0; 32]),
            Err(DisclosureProofError::Disclosure(DisclosureError::Set {
                position: 1,
                ..
            }))
        ));
        assert!(matches!(
            verify(&w.buf, &[0], &[0; 32]),
            Err(DisclosureProofError::Count {
                requested: 1,
                supplied: 2
            })
        ));
        assert!(matches!(
            verify(&[], &[1, 0], &[0; 32]),
            Err(DisclosureProofError::Disclosure(
                DisclosureError::RequestOrder
            ))
        ));
        assert!(matches!(
            verify(&[], &[0, 0], &[0; 32]),
            Err(DisclosureProofError::Disclosure(
                DisclosureError::RequestOrder
            ))
        ));
        assert!(matches!(
            validate_request(&vec![0; MAX_DISCLOSURE_CHUNKS + 1]),
            Err(DisclosureProofError::RequestLimit { .. })
        ));
    }
}
