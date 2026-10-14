//! Export existing document membership proofs as a bounded portable artifact.
//!
//! The recipient supplies the trusted document commitment and exact chunk
//! request separately. This format contains neither an embedded trust anchor
//! nor a claim of authorization or production-wide completeness (plan §9.1).

use fa_journal::{RedactedView, ViewChunk};
use fa_model::{EncodeError, Writer};
use fgdb_crypto::Hasher;

use crate::document::{ChunkProof, DocumentProofError, DocumentProofTree};

pub const FORMAT: &[u8] = b"fa:document-disclosure:v1";
pub const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_DISCLOSURE_CHUNKS: usize = 16_384;
const CHUNK_BYTES: usize = fa_journal::evidence::CHUNK_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisclosureExportError {
    EmptyRequest,
    RequestOrder,
    CountLimit {
        maximum: usize,
        actual: usize,
    },
    ByteLimit {
        maximum: usize,
    },
    Proof(DocumentProofError),
    Encode(EncodeError),
    /// The supplied view has an invalid document/chunk shape.
    View(String),
    /// The view does not rebuild the separately supplied document commitment.
    Commitment,
    /// Requested bytes are not present in the already-authorized view.
    Withheld {
        index: u64,
    },
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
            Self::View(why) => write!(f, "invalid disclosure view: {why}"),
            Self::Commitment => write!(f, "disclosure view does not match the document commitment"),
            Self::Withheld { index } => {
                write!(f, "document chunk {index} is withheld by the supplied view")
            }
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

/// Check request framing without reading a document. Callers still admit
/// authority before this check; an index request is never a capability.
pub fn validate_request(requested_indexes: &[u64]) -> Result<(), DisclosureExportError> {
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
    Ok(())
}

fn encode_proofs<'a>(
    requested_indexes: &[u64],
    mut prove: impl FnMut(u64) -> Result<ChunkProof<'a>, DisclosureExportError>,
) -> Result<Vec<u8>, DisclosureExportError> {
    validate_request(requested_indexes)?;
    let limit = || DisclosureExportError::ByteLimit {
        maximum: MAX_PROOF_BYTES,
    };
    // Bound the entire encoding before allocating the output. Chunk bytes
    // borrow the source; only bounded paths are copied before serialization.
    let mut size = 4 + FORMAT.len() + 1 + 8 + 4;
    let mut proofs = Vec::with_capacity(requested_indexes.len());
    for index in requested_indexes {
        let proof = prove(*index)?;
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
        encode_proofs(requested_indexes, |index| {
            self.prove(index).map_err(DisclosureExportError::Proof)
        })
    }
}

fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(domain);
    for part in parts {
        h.update(part);
    }
    h.finalize().0
}

/// Export a subset of an already-authorized kernel RedactedView without
/// fetching the original or disclosing other readable chunks. Withheld
/// hashes suffice to build canonical sibling paths, including odd-node
/// promotions. Requesting even one withheld chunk refuses the whole export.
///
/// The supplied commitment must have been authenticated separately by the
/// caller (the book facade does this through its protected read). The view's
/// locator and contract are NOT authenticated by this pure producer. It
/// neither grants disclosure authority nor substitutes a weaker contract.
/// Kernel views are bounded to 64 MiB documents. Existing compact bytes are
/// unchanged: a permitted request produces exactly the full tree's encoding.
pub fn disclosure_from_view(
    view: &RedactedView,
    requested_indexes: &[u64],
    document_commitment: &[u8; 32],
) -> Result<Vec<u8>, DisclosureExportError> {
    validate_request(requested_indexes)?;
    if view.doc_commit != *document_commitment {
        return Err(DisclosureExportError::Commitment);
    }
    if view.size > (MAX_DISCLOSURE_CHUNKS * CHUNK_BYTES) as u64 {
        return Err(DisclosureExportError::View(
            "document exceeds the kernel view bound".into(),
        ));
    }
    let count = view.size.div_ceil(CHUNK_BYTES as u64).max(1);
    if view.chunks.len() as u64 != count {
        return Err(DisclosureExportError::View(
            "chunk count disagrees with document size".into(),
        ));
    }
    for index in requested_indexes {
        if *index >= count {
            return Err(DisclosureExportError::Proof(DocumentProofError::Index {
                index: *index,
                chunk_count: count,
            }));
        }
        if matches!(&view.chunks[*index as usize], ViewChunk::Withheld(_)) {
            return Err(DisclosureExportError::Withheld { index: *index });
        }
    }
    // Only the bounded view is read. Undisclosed original bytes do not exist
    // in this API, and unrequested readable bytes never enter the wire output.
    let mut level = Vec::with_capacity(view.chunks.len());
    for (index, chunk) in view.chunks.iter().enumerate() {
        level.push(match chunk {
            ViewChunk::Withheld(digest) => *digest,
            ViewChunk::Disclosed(bytes) => {
                let expected = view
                    .size
                    .saturating_sub(index as u64 * CHUNK_BYTES as u64)
                    .min(CHUNK_BYTES as u64);
                if bytes.len() as u64 != expected {
                    return Err(DisclosureExportError::View(format!(
                        "chunk {index} has an invalid length"
                    )));
                }
                hash(
                    b"fa:doc:leaf:v1",
                    &[
                        &(index as u64).to_le_bytes(),
                        &(bytes.len() as u64).to_le_bytes(),
                        bytes,
                    ],
                )
            }
        });
    }
    let mut levels = Vec::new();
    while level.len() > 1 {
        let next = level
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => hash(b"fa:doc:node:v1", &[left, right]),
                _ => pair[0],
            })
            .collect();
        levels.push(level);
        level = next;
    }
    let root = level[0]; // The authenticated shape always has at least one leaf.
    levels.push(level);
    if hash(
        b"fa:doc:v1",
        &[&[view.kind], &view.size.to_le_bytes(), &root],
    ) != *document_commitment
    {
        return Err(DisclosureExportError::Commitment);
    }
    encode_proofs(requested_indexes, |index| {
        let ViewChunk::Disclosed(bytes) = &view.chunks[index as usize] else {
            return Err(DisclosureExportError::Withheld { index });
        };
        let mut position = index as usize;
        let mut siblings = Vec::with_capacity(levels.len() - 1);
        for level in &levels[..levels.len() - 1] {
            if let Some(sibling) = level.get(position ^ 1) {
                siblings.push(*sibling);
            }
            position /= 2;
        }
        Ok(ChunkProof {
            kind: view.kind,
            document_length: view.size,
            index,
            bytes,
            siblings,
        })
    })
}
