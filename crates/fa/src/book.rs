//! `Book`: the handle to one FrankenAccounting book on FrankenGraphDB.
//!
//! Genesis slice (plan §19). A `Book` owns the production asupersync runtime,
//! the root `Cx` it was granted, and the substrate `Database`. Every effectful
//! call narrows the root `Cx` to the substrate's purpose context for that
//! effect (`CommitCx` for writes, `QueryCx` for reads) — plan §1 constraint 3.
//!
//! What exists in this slice: in-memory open, a probe write through the real
//! commit path, a probe read. The posting kernel (§5), chart install, and the
//! directory-backed open with the three-line key file land as later slices of
//! this module; this is a subset of the final `Book`, never a substitute.

use core::fmt;

use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::{Budget, Cx};
use fgdb::{Database, DatabaseKeys, MemVfs, WriteBatch};
use fgdb_delta_types::{PropertyKeyId, RelationId};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, VId};

/// The relation id reserved for the Genesis probe. Real relation ids come from
/// `registries/symbols.toml` once `fa-model` lands (plan Appendix H R-SYM).
const PROBE_RELATION: RelationId = RelationId(1);
/// The property key reserved for the Genesis probe (same provenance rule).
const PROBE_PROPERTY: PropertyKeyId = PropertyKeyId(1);
/// The probe vertex. Real vertex identities are identity-derived (plan §4.9).
const PROBE_VID: VId = VId(1);
/// The value the probe writes and expects to read back.
const PROBE_VALUE: i64 = 42;

/// The three secrets a book directory needs: the object-identity key, the
/// security namespace, and the data-encryption key (the substrate's
/// `DatabaseKeys`). On disk these are the three 64-hex lines of the key file.
#[derive(Clone)]
pub struct BookKeys(DatabaseKeys);

impl BookKeys {
    /// Keys from raw material. The caller owns their entropy and custody.
    pub fn from_raw(k_oid: [u8; 32], namespace: [u8; 32], dek: [u8; 32]) -> Self {
        Self(DatabaseKeys::new(k_oid, DatabaseSecurityNamespaceId(namespace), dek))
    }

    /// Deterministic keys for examples and tests. **Never** for a real book:
    /// every byte of every key is `seed`.
    pub fn for_development(seed: u8) -> Self {
        Self::from_raw([seed; 32], [seed.wrapping_add(1); 32], [seed.wrapping_add(2); 32])
    }
}

impl fmt::Debug for BookKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keys are never printed, even in debug output.
        f.write_str("BookKeys(<redacted>)")
    }
}

/// Errors a `Book` can return. Each maps to one exit-code class in the CLI
/// contract (plan Appendix D): runtime and open failures are environment or
/// foundation errors; write and read failures are foundation errors.
#[derive(Debug)]
pub enum BookError {
    /// The asupersync runtime could not be built.
    Runtime(String),
    /// The substrate refused to open or create the book.
    Open(fgdb::OpenError),
    /// The substrate refused a write.
    Write(fgdb::WriteError),
    /// The substrate refused a read.
    Read(fgdb::ReadError),
    /// The probe read back something other than what it wrote.
    ProbeMismatch { expected: i64, found: Option<String> },
}

impl fmt::Display for BookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(e) => write!(f, "runtime: {e}"),
            Self::Open(e) => write!(f, "open: {e:?}"),
            Self::Write(e) => write!(f, "write: {e:?}"),
            Self::Read(e) => write!(f, "read: {e:?}"),
            Self::ProbeMismatch { expected, found } => {
                write!(f, "probe mismatch: expected {expected}, found {found:?}")
            }
        }
    }
}

impl core::error::Error for BookError {}

impl From<fgdb::OpenError> for BookError {
    fn from(e: fgdb::OpenError) -> Self {
        Self::Open(e)
    }
}
impl From<fgdb::WriteError> for BookError {
    fn from(e: fgdb::WriteError) -> Self {
        Self::Write(e)
    }
}
impl From<fgdb::ReadError> for BookError {
    fn from(e: fgdb::ReadError) -> Self {
        Self::Read(e)
    }
}

/// One open book. In this slice the store is the substrate's in-memory VFS;
/// the directory-backed store is the next slice of this same type.
pub struct Book {
    runtime: Runtime,
    root: Cx,
    db: Database<MemVfs>,
}

impl Book {
    /// Open an in-memory book under the production runtime (no lab scheduler,
    /// no `test-internals`): the runtime grants a root `Cx` with an infinite
    /// budget, which is narrowed per effect below.
    pub fn open_memory(keys: BookKeys) -> Result<Self, BookError> {
        let runtime = RuntimeBuilder::new()
            .build()
            .map_err(|e| BookError::Runtime(format!("{e:?}")))?;
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root).commit();
        let db = runtime.block_on(async { Database::open_memory(&cx, keys.0).await })?;
        Ok(Self { runtime, root, db })
    }

    /// Write the probe vertex through the real commit path. Returns the
    /// substrate's commit sequence — the only "recorded time" this system has
    /// (plan §1 constraint 6).
    pub fn genesis_probe(&mut self) -> Result<u64, BookError> {
        let cx = PurposeContexts::narrow_runtime_root(&self.root).commit();
        let mut batch = WriteBatch::new(PROBE_RELATION);
        batch.create_vertex(
            PROBE_VID,
            vec![],
            vec![(PROBE_PROPERTY, CanonicalScalar::Int(PROBE_VALUE))],
        );
        let db = &mut self.db;
        let seq = self
            .runtime
            .block_on(async move { db.write(&cx, batch).await })?;
        Ok(seq.0)
    }

    /// Read the probe vertex back and render it. Fails if the stored value is
    /// not the one `genesis_probe` wrote.
    pub fn read_probe(&self) -> Result<String, BookError> {
        let row = self.db.vertex(PROBE_VID)?;
        let rendered = row.as_ref().map(|r| format!("{r:?}"));
        let ok = row.as_ref().is_some_and(|r| {
            r.props
                .iter()
                .any(|(k, v)| *k == PROBE_PROPERTY && *v == CanonicalScalar::Int(PROBE_VALUE))
        });
        if ok {
            Ok(rendered.unwrap_or_default())
        } else {
            Err(BookError::ProbeMismatch { expected: PROBE_VALUE, found: rendered })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_round_trip_in_memory() {
        let mut book = Book::open_memory(BookKeys::for_development(0x11)).expect("open");
        let seq = book.genesis_probe().expect("write");
        assert!(seq >= 1, "the first commit must have a positive sequence, got {seq}");
        let rendered = book.read_probe().expect("read back");
        assert!(rendered.contains("42"), "rendered row should carry the probe value: {rendered}");
    }

    #[test]
    fn keys_never_print() {
        let keys = BookKeys::for_development(0x22);
        assert_eq!(format!("{keys:?}"), "BookKeys(<redacted>)");
    }
}
