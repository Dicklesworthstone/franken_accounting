//! Export existing document membership proofs as a bounded portable artifact.
//!
//! The recipient supplies the trusted document commitment and exact chunk
//! request separately. This format contains neither an embedded trust anchor
//! nor a claim of authorization or production-wide completeness (plan §9.1).

use fa_model::{EncodeError, Writer};

use crate::document::{DocumentProofError, DocumentProofTree};

pub const FORMAT: &[u8] = b"fa:document-disclosure:v1";
pub const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_DISCLOSURE_CHUNKS: usize = 16_384;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisclosureExportError {
    EmptyRequest,
    RequestOrder,
    CountLimit { maximum: usize, actual: usize },
    ByteLimit { maximum: usize },
    Proof(DocumentProofError),
    Encode(EncodeError),
}

impl core::fmt::Display for DisclosureExportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyRequest => write!(f, "a disclosure must name at least one chunk"),
            Self::RequestOrder => write!(
                f,
                "disclosure indexes must be strictly ascending and unique"
            ),
            Self::CountLimit { maximum, actual } => {
                write!(
                    f,
                    "disclosure requests {actual} chunks; maximum is {maximum}"
                )
            }
            Self::ByteLimit { maximum } => {
                write!(f, "disclosure exceeds the {maximum}-byte transport limit")
            }
            Self::Proof(error) => write!(f, "{error}"),
            Self::Encode(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for DisclosureExportError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Proof(error) => Some(error),
            Self::Encode(error) => Some(error),
            _ => None,
        }
    }
}

impl DocumentProofTree<'_> {
    /// Export exactly the requested whole chunks, in canonical index order.
    /// The caller must have authorization to disclose these bytes. A parsed
    /// recipient request is not an access capability. Empty, repeated,
    /// unordered, out-of-range or over-budget requests fail without output.
    ///
    /// Wire format (independently decoded by fa-verify): length-prefixed
    /// format tag, kind u8, total document length u64, then a u32-counted
    /// list of index u64, length-prefixed chunk, and u32-counted sibling hashes.
    /// Every integer is little-endian. Neither commitment nor request authority
    /// is taken from the export by the verifier.
    pub fn disclosure_bytes(
        &self,
        requested_indexes: &[u64],
    ) -> Result<Vec<u8>, DisclosureExportError> {
        if requested_indexes.is_empty() {
            return Err(DisclosureExportError::EmptyRequest);
        }
        if requested_indexes.len() > MAX_DISCLOSURE_CHUNKS {
            return Err(DisclosureExportError::CountLimit {
                maximum: MAX_DISCLOSURE_CHUNKS,
                actual: requested_indexes.len(),
            });
        }
        if requested_indexes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(DisclosureExportError::RequestOrder);
        }
        let limit = || DisclosureExportError::ByteLimit {
            maximum: MAX_PROOF_BYTES,
        };
        // Bound the entire encoding before allocating the output. Proof
        // bytes borrow the original document; only bounded paths are copied.
        let mut size = 4 + FORMAT.len() + 1 + 8 + 4;
        let mut proofs = Vec::with_capacity(requested_indexes.len());
        for index in requested_indexes {
            let proof = self.prove(*index).map_err(DisclosureExportError::Proof)?;
            let hashes = proof.siblings.len().checked_mul(32).ok_or_else(limit)?;
            size = size
                .checked_add(16)
                .and_then(|n| n.checked_add(proof.bytes.len()))
                .and_then(|n| n.checked_add(hashes))
                .filter(|n| *n <= MAX_PROOF_BYTES)
                .ok_or_else(limit)?;
            proofs.push(proof);
        }
        let first = proofs.first().ok_or(DisclosureExportError::EmptyRequest)?;
        let mut w = Writer::with_capacity(size);
        w.bytes(FORMAT).u8(first.kind).u64(first.document_length);
        w.list(&proofs, |w, proof| {
            w.u64(proof.index)
                .bytes(proof.bytes)
                .list(&proof.siblings, |w, sibling| {
                    w.fixed(sibling);
                });
        });
        w.finish().map_err(DisclosureExportError::Encode)
    }
}
