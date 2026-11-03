//! Immutable source population for a prepared legacy migration.
//!
//! The native binding authenticates this ordered population against the retained
//! package. It proves which sealed proposals must be staged; the parser's source
//! row count remains declared provenance, not a second CSV parser in the kernel.

use std::collections::BTreeSet;

use fgdb_types::VId;

use crate::{DecodeError, EncodeError, Id128, Oid, Reader, Writer, domain_digest};

pub const SOURCE_MANIFEST_FORMAT: &[u8] = b"FA-MIGRATION-SOURCE\0";
pub const SOURCE_MANIFEST_VERSION: u16 = 1;
pub const SOURCE_MANIFEST_DOMAIN: &[u8] = b"fa:migration-source:v1";
pub const MAX_SOURCE_CHUNKS: usize = 4096;
pub const MAX_SOURCE_MANIFEST_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceChunk {
    pub entry_vid: VId,
    pub proposal_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceManifest {
    pub book_id: Id128,
    pub run_ref: VId,
    pub run_body_digest: [u8; 32],
    pub source_oid: Oid,
    pub source_commit: [u8; 32],
    /// Native binding requires a distinct retained package, whose bytes contain
    /// the original source citation and the entire prepared proposal population.
    pub package_oid: Oid,
    pub package_commit: [u8; 32],
    pub source_rows: u64,
    /// Exact retained package order, not a set sorted by entry identity.
    pub chunks: Vec<SourceChunk>,
}

/// One native manifest identity per run. A different preparer cannot replace it.
#[must_use]
pub fn source_manifest_vid(book: Id128, run: VId) -> VId {
    let digest = domain_digest(
        b"fa:vid:migration-source:v1",
        &[&book.0, &run.0.to_le_bytes()],
    );
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    VId(u128::from_le_bytes(bytes))
}

impl SourceManifest {
    #[must_use]
    pub fn vid(&self) -> VId {
        source_manifest_vid(self.book_id, self.run_ref)
    }

    #[must_use]
    pub fn problem(&self) -> Option<&'static str> {
        if self.chunks.is_empty() || self.chunks.len() > MAX_SOURCE_CHUNKS {
            return Some("source manifest needs 1..=4096 chunks");
        }
        if self.source_rows < self.chunks.len() as u64 {
            return Some("source row count is smaller than its chunk population");
        }
        let mut identities = BTreeSet::new();
        if self
            .chunks
            .iter()
            .any(|chunk| !identities.insert(chunk.entry_vid))
        {
            return Some("source manifest repeats a chunk identity");
        }
        None
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut writer = Writer::new();
        writer
            .fixed(SOURCE_MANIFEST_FORMAT)
            .u16(SOURCE_MANIFEST_VERSION)
            .fixed(&self.book_id.0)
            .u128(self.run_ref.0)
            .fixed(&self.run_body_digest)
            .fixed(&self.source_oid.0)
            .fixed(&self.source_commit)
            .fixed(&self.package_oid.0)
            .fixed(&self.package_commit)
            .u64(self.source_rows)
            .list(&self.chunks, |writer, chunk| {
                writer.u128(chunk.entry_vid.0).fixed(&chunk.proposal_digest);
            });
        writer.finish()
    }

    pub fn digest(&self) -> Result<[u8; 32], EncodeError> {
        Ok(domain_digest(
            SOURCE_MANIFEST_DOMAIN,
            &[&self.canonical_bytes()?],
        ))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        if bytes.len() > MAX_SOURCE_MANIFEST_BYTES {
            return Err(reader.invalid("migration_source.bytes"));
        }
        if reader
            .fixed::<{ SOURCE_MANIFEST_FORMAT.len() }>("migration_source.format")?
            .as_slice()
            != SOURCE_MANIFEST_FORMAT
            || reader.u16("migration_source.version")? != SOURCE_MANIFEST_VERSION
        {
            return Err(reader.invalid("migration_source.version"));
        }
        let value = Self {
            book_id: Id128(reader.fixed("migration_source.book")?),
            run_ref: VId(reader.u128("migration_source.run")?),
            run_body_digest: reader.fixed("migration_source.run_body")?,
            source_oid: Oid(reader.fixed("migration_source.source")?),
            source_commit: reader.fixed("migration_source.source_commit")?,
            package_oid: Oid(reader.fixed("migration_source.package")?),
            package_commit: reader.fixed("migration_source.package_commit")?,
            source_rows: reader.u64("migration_source.source_rows")?,
            chunks: reader.list(MAX_SOURCE_CHUNKS, "migration_source.chunks", |reader| {
                Ok(SourceChunk {
                    entry_vid: VId(reader.u128("migration_source.chunk.entry")?),
                    proposal_digest: reader.fixed("migration_source.chunk.proposal")?,
                })
            })?,
        };
        if value.problem().is_some() {
            return Err(reader.invalid("migration_source.population"));
        }
        reader.finish()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> SourceManifest {
        SourceManifest {
            book_id: Id128([1; 16]),
            run_ref: VId(2),
            run_body_digest: [3; 32],
            source_oid: Oid([4; 32]),
            source_commit: [5; 32],
            package_oid: Oid([6; 32]),
            package_commit: [7; 32],
            source_rows: 4,
            chunks: vec![
                SourceChunk {
                    entry_vid: VId(9),
                    proposal_digest: [10; 32],
                },
                SourceChunk {
                    entry_vid: VId(8),
                    proposal_digest: [11; 32],
                },
            ],
        }
    }

    #[test]
    fn source_manifest_round_trip_preserves_order_and_authenticates_every_field() {
        let value = manifest();
        let bytes = value.canonical_bytes().unwrap();
        assert_eq!(SourceManifest::decode(&bytes).unwrap(), value);
        let mut changed = value.clone();
        changed.chunks.reverse();
        assert_ne!(changed.digest().unwrap(), value.digest().unwrap());
        changed = value.clone();
        changed.source_rows += 1;
        assert_ne!(changed.digest().unwrap(), value.digest().unwrap());
        changed = value.clone();
        changed.package_commit[0] ^= 1;
        assert_ne!(changed.digest().unwrap(), value.digest().unwrap());
        assert_eq!(changed.vid(), value.vid());
    }

    #[test]
    fn source_manifest_refuses_gaps_in_shape_duplicates_trailing_and_unknown_version() {
        let value = manifest();
        let bytes = value.canonical_bytes().unwrap();
        assert!(SourceManifest::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(SourceManifest::decode(&trailing).is_err());
        let mut future = bytes;
        future[SOURCE_MANIFEST_FORMAT.len()] = 2;
        assert!(SourceManifest::decode(&future).is_err());
        let mut duplicate = value.clone();
        duplicate.chunks[1].entry_vid = duplicate.chunks[0].entry_vid;
        assert!(SourceManifest::decode(&duplicate.canonical_bytes().unwrap()).is_err());
        let mut empty = value.clone();
        empty.chunks.clear();
        assert!(SourceManifest::decode(&empty.canonical_bytes().unwrap()).is_err());
        let mut count = value;
        count.source_rows = 1;
        assert!(SourceManifest::decode(&count.canonical_bytes().unwrap()).is_err());
    }

    #[test]
    fn source_manifest_accepts_the_entire_existing_package_population_bound() {
        let mut value = manifest();
        value.source_rows = MAX_SOURCE_CHUNKS as u64;
        value.chunks = (0..MAX_SOURCE_CHUNKS)
            .map(|ordinal| SourceChunk {
                entry_vid: VId(ordinal as u128),
                proposal_digest: [13; 32],
            })
            .collect();
        let bytes = value.canonical_bytes().unwrap();
        assert!(
            bytes.len() > 16 * 1024,
            "native storage must fragment this population"
        );
        assert!(bytes.len() <= MAX_SOURCE_MANIFEST_BYTES);
        assert_eq!(SourceManifest::decode(&bytes).unwrap(), value);
        value.chunks.push(SourceChunk {
            entry_vid: VId(MAX_SOURCE_CHUNKS as u128),
            proposal_digest: [14; 32],
        });
        value.source_rows += 1;
        assert!(SourceManifest::decode(&value.canonical_bytes().unwrap()).is_err());
    }
}
