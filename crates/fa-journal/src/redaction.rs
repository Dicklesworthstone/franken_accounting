//! Redacted views of documents (plan §9.6; fa-txf part C2).
//!
//! A view discloses some of a document's 4 KiB chunks and withholds the
//! others as their leaf hashes. Anyone holding the view alone recomputes the
//! original's public commitment — kind, size and the chunk tree's root — so
//! a view proves it is a projection of exactly the document an entry cites,
//! without the privileged bytes. A chunk that any privileged range touches
//! is withheld whole: the commitment hashes whole chunks, so a partly
//! disclosed chunk could not be proven.
//!
//! The view's own identity is its commitment,
//! `view_commit = H("fa:redacted-view:v1" ‖ canonical bytes)`; its lineage
//! to the original is the `original` oid and `doc_commit` it carries.
//!
//! No-claim boundary: a view proves which bytes it discloses belong to the
//! committed document at their offsets, and nothing about what the withheld
//! chunks say. Amounts, dates, accounts and lineage are never in a
//! document's bytes' redaction scope: a view changes no entry.

use fa_model::{DecodeError, Oid, Reader, Writer, domain_digest};

use crate::evidence::{CHUNK_BYTES, Document, commitment, leaf, tree_root};
use crate::refusal::KernelError;

/// Domain of `view_commit`.
pub const VIEW_DOMAIN: &[u8] = b"fa:redacted-view:v1";
const VIEW_VERSION: u16 = 1;
const DISCLOSED: u8 = 0;
const WITHHELD: u8 = 1;
/// The decoder's bound on a view's chunk count: the document decoder's
/// 64 MiB ceiling in 4 KiB chunks.
const MAX_VIEW_CHUNKS: usize = 64 * 1024 * 1024 / CHUNK_BYTES;

/// One chunk of a view, in the original's chunk order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViewChunk {
    /// The chunk's bytes, disclosed.
    Disclosed(Vec<u8>),
    /// The chunk's leaf hash: the bytes are withheld.
    Withheld([u8; 32]),
}

/// A redacted view of one document under one redaction contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactedView {
    /// The document the view projects.
    pub original: Oid,
    /// The redaction contract that chose what to withhold.
    pub contract: u16,
    /// The original's kind and size, both inside its commitment.
    pub kind: u8,
    pub size: u64,
    /// The original's public commitment, which the view reproduces.
    pub doc_commit: [u8; 32],
    pub chunks: Vec<ViewChunk>,
}

/// The number of chunks a document of `size` bytes commits to (an empty
/// document is one empty chunk).
fn chunk_count(size: u64) -> u64 {
    let chunk = CHUNK_BYTES as u64;
    size.div_ceil(chunk).max(1)
}

/// The length of chunk `index` of a `size`-byte document.
fn chunk_len(size: u64, index: u64) -> u64 {
    let chunk = CHUNK_BYTES as u64;
    size.saturating_sub(index.saturating_mul(chunk)).min(chunk)
}

impl RedactedView {
    /// The view of `doc` under `contract` that withholds every chunk any of
    /// the `privileged` byte ranges `(offset, length)` touches. A range past
    /// the end touches nothing beyond it; a zero-length range touches
    /// nothing.
    #[must_use]
    pub fn derive(doc: &Document, contract: u16, privileged: &[(u64, u64)]) -> Self {
        let chunk = CHUNK_BYTES as u64;
        let touched = |index: u64| {
            let start = index * chunk;
            let end = start + chunk;
            privileged.iter().any(|(offset, length)| {
                *length > 0 && *offset < end && offset.saturating_add(*length) > start
            })
        };
        let chunks = if doc.bytes.is_empty() {
            vec![if touched(0) {
                ViewChunk::Withheld(leaf(0, &[]))
            } else {
                ViewChunk::Disclosed(Vec::new())
            }]
        } else {
            doc.bytes
                .chunks(CHUNK_BYTES)
                .enumerate()
                .map(|(i, bytes)| {
                    if touched(i as u64) {
                        ViewChunk::Withheld(leaf(i, bytes))
                    } else {
                        ViewChunk::Disclosed(bytes.to_vec())
                    }
                })
                .collect()
        };
        Self {
            original: doc.oid(),
            contract,
            kind: doc.kind,
            size: doc.bytes.len() as u64,
            doc_commit: doc.doc_commit(),
            chunks,
        }
    }

    /// `u16 version ‖ oid ‖ u16 contract ‖ u8 kind ‖ u64 size ‖ doc_commit ‖
    /// list(0u8 ‖ bytes | 1u8 ‖ leaf hash)`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.u16(VIEW_VERSION)
            .fixed(&self.original.0)
            .u16(self.contract)
            .u8(self.kind)
            .u64(self.size)
            .fixed(&self.doc_commit)
            .list(&self.chunks, |w, c| match c {
                ViewChunk::Disclosed(bytes) => {
                    w.u8(DISCLOSED).bytes(bytes);
                }
                ViewChunk::Withheld(hash) => {
                    w.u8(WITHHELD).fixed(hash);
                }
            });
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    /// Decode a view's bytes (structure only; [`RedactedView::verify`] is
    /// the proof).
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u16("view.version")? != VIEW_VERSION {
            return Err(r.invalid("view.version"));
        }
        let view = Self {
            original: Oid(r.fixed("view.original")?),
            contract: r.u16("view.contract")?,
            kind: r.u8("view.kind")?,
            size: r.u64("view.size")?,
            doc_commit: r.fixed("view.doc_commit")?,
            chunks: r.list(MAX_VIEW_CHUNKS, "view.chunks", |r| {
                Ok(match r.u8("view.chunk")? {
                    DISCLOSED => {
                        ViewChunk::Disclosed(r.bytes(CHUNK_BYTES, "view.chunk.bytes")?.to_vec())
                    }
                    WITHHELD => ViewChunk::Withheld(r.fixed("view.chunk.leaf")?),
                    t => return Err(r.bad_tag("view.chunk", t)),
                })
            })?,
        };
        r.finish()?;
        Ok(view)
    }

    /// `H("fa:redacted-view:v1" ‖ canonical bytes)`: the view's own identity.
    pub fn view_commit(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(VIEW_DOMAIN, &[&self.canonical_bytes()?]))
    }

    /// The proof: the view has the original's chunk shape, and its disclosed
    /// chunks and withheld leaves rebuild the original's commitment.
    /// Otherwise names what disagrees.
    pub fn verify(&self) -> Result<(), String> {
        let count = chunk_count(self.size);
        if self.chunks.len() as u64 != count {
            return Err(format!(
                "a {}-byte document has {count} chunks; the view carries {}",
                self.size,
                self.chunks.len()
            ));
        }
        let mut leaves = Vec::with_capacity(self.chunks.len());
        for (i, c) in self.chunks.iter().enumerate() {
            leaves.push(match c {
                ViewChunk::Disclosed(bytes) => {
                    let want = chunk_len(self.size, i as u64);
                    if bytes.len() as u64 != want {
                        return Err(format!(
                            "disclosed chunk {i} is {} bytes; the document's is {want}",
                            bytes.len()
                        ));
                    }
                    leaf(i, bytes)
                }
                ViewChunk::Withheld(hash) => *hash,
            });
        }
        let rebuilt = commitment(self.kind, self.size, &tree_root(leaves));
        if rebuilt != self.doc_commit {
            return Err(format!(
                "the view rebuilds commitment {}, not the original's {}",
                crate::evidence::hex(&rebuilt),
                crate::evidence::hex(&self.doc_commit)
            ));
        }
        Ok(())
    }

    /// The disclosed bytes with their offsets in the original.
    pub fn disclosed(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.chunks.iter().enumerate().filter_map(|(i, c)| match c {
            ViewChunk::Disclosed(bytes) => Some((i as u64 * CHUNK_BYTES as u64, bytes.as_slice())),
            ViewChunk::Withheld(_) => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::doc_commit;
    use fa_model::Id128;
    use fgdb_types::VId;

    fn doc(size: usize) -> Document {
        Document {
            book_id: Id128([5; 16]),
            kind: 5,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: VId(7),
            bytes: (0..size).map(|i| (i % 251) as u8).collect(),
        }
    }

    const C: u64 = CHUNK_BYTES as u64;

    #[test]
    fn a_view_rebuilds_the_commitment_and_discloses_only_untouched_chunks() {
        let ranges: [&[(u64, u64)]; 6] = [
            &[],
            &[(0, 1)],
            &[(C + 10, 5)],
            &[(C - 1, 2)],
            &[(0, 10 * C)],
            &[(3 * C, 0), (9 * C, 7)],
        ];
        for size in [0, 1, CHUNK_BYTES, CHUNK_BYTES + 1, 3 * CHUNK_BYTES + 5] {
            let d = doc(size);
            for privileged in ranges {
                let v = RedactedView::derive(&d, 2, privileged);
                assert_eq!(v.verify(), Ok(()), "size {size}, ranges {privileged:?}");
                assert_eq!(v.doc_commit, doc_commit(d.kind, &d.bytes));
                assert_eq!(v.chunks.len() as u64, chunk_count(size as u64));
                for (offset, bytes) in v.disclosed() {
                    let o = usize::try_from(offset).unwrap();
                    assert_eq!(&d.bytes[o..o + bytes.len()], bytes, "disclosed at {offset}");
                    assert!(
                        privileged
                            .iter()
                            .all(|(p, l)| *l == 0 || p + l <= offset || *p >= offset + C),
                        "a touched chunk was disclosed at {offset}"
                    );
                }
            }
        }
        // A range straddling a chunk boundary withholds both chunks.
        let v = RedactedView::derive(&doc(3 * CHUNK_BYTES), 2, &[(C - 1, 2)]);
        let withheld: Vec<usize> = v
            .chunks
            .iter()
            .enumerate()
            .filter(|(_, c)| matches!(c, ViewChunk::Withheld(_)))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(withheld, [0, 1]);
    }

    #[test]
    fn a_tampered_view_does_not_rebuild_the_commitment() {
        let d = doc(3 * CHUNK_BYTES + 5);
        let v = RedactedView::derive(&d, 2, &[(C + 3, 1)]);
        let mut byte = v.clone();
        if let ViewChunk::Disclosed(b) = &mut byte.chunks[0] {
            b[0] ^= 1;
        }
        let mut hash = v.clone();
        if let ViewChunk::Withheld(h) = &mut hash.chunks[1] {
            h[0] ^= 1;
        }
        let mut short = v.clone();
        short.chunks.pop();
        let mut size = v.clone();
        size.size += 1;
        let mut kind = v.clone();
        kind.kind ^= 1;
        let mut truncated = v.clone();
        if let ViewChunk::Disclosed(b) = &mut truncated.chunks[3] {
            b.pop();
        }
        let mut swapped = v.clone();
        swapped.chunks.swap(0, 2);
        for (what, t) in [
            ("a disclosed byte", byte),
            ("a withheld leaf", hash),
            ("a dropped chunk", short),
            ("the size", size),
            ("the kind", kind),
            ("a short last chunk", truncated),
            ("two chunks swapped", swapped),
        ] {
            assert!(t.verify().is_err(), "{what}");
        }
    }

    #[test]
    fn views_round_trip_and_their_commitment_binds_every_byte() {
        let v = RedactedView::derive(&doc(2 * CHUNK_BYTES + 9), 3, &[(0, 1)]);
        let bytes = v.canonical_bytes().unwrap();
        assert_eq!(RedactedView::decode(&bytes).unwrap(), v);
        let commit = v.view_commit().unwrap();
        for i in (0..bytes.len()).step_by(97) {
            let mut x = bytes.clone();
            x[i] ^= 0x01;
            if let Ok(back) = RedactedView::decode(&x) {
                assert_ne!(back.view_commit().unwrap(), commit, "byte {i}");
            }
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(RedactedView::decode(&trailing).is_err());
        // Another contract over the same document is another view.
        let other = RedactedView::derive(&doc(2 * CHUNK_BYTES + 9), 4, &[(0, 1)]);
        assert_ne!(other.view_commit().unwrap(), commit);
    }
}
