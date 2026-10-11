//! A book's blob store: where a document too large to ride inline keeps its
//! bytes (plan §9.1 `storage: External`; fa-txf part B).
//!
//! The pinned substrate has no object store (Appendix H), so the book owns a
//! directory of content-addressed blobs beside its database — `<book
//! dir>/blobs` for a directory book, a memory VFS for a memory book — under a
//! store descriptor registered in `document_stores.toml`. The locator is the
//! document commitment's lowercase hex, so a blob names the bytes it must
//! hold and the same bytes are one blob. The store is never an authority:
//! every read recomputes the commitment from the bytes (fa-journal
//! `evidence::fetch_document`), so a missing blob is a typed refusal and a
//! changed one is drift, never a silent substitute.
//!
//! A blob is published durably before anything names it (WhiteCreek 3440):
//! the bytes go to a staged file of the call's own that is synced, the file
//! is renamed into place, and then every directory on the blob's ancestor
//! chain is synced, the blob's own first — the barrier fgdb-chronicle's
//! `sync_created_entry` uses, extended to the whole chain so directories an
//! interrupted earlier put created are fenced too. Only after
//! `put` returns does the kernel commit the journal row that names the blob,
//! so a crash cannot leave a reference to a lost blob. A reader never sees a
//! partial blob, and a blob orphaned by a refused or failed intake is
//! harmless (content-addressed, unreferenced). Every operation runs under
//! the caller's purpose context (`CommitCx` to publish, `QueryCx` to read).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::fs::{OpenOptions, Vfs, VfsFile};
use asupersync::io::AsyncWriteExt;
use fa_registry::document_stores::DocumentStores;
use fgdb_types::context::{CommitCx, QueryCx};

use crate::evidence::hex;
use crate::refusal::KernelError;

/// One registered store over a VFS.
#[derive(Clone, Debug)]
pub struct BlobStore<V> {
    id: u16,
    max_document_bytes: u64,
    vfs: V,
    dir: PathBuf,
}

/// The locator of the blob holding the bytes committed to `doc_commit`.
#[must_use]
pub fn locator_of(doc_commit: &[u8; 32]) -> String {
    hex(doc_commit)
}

fn is_locator(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl<V: asupersync::fs::Vfs + Clone> BlobStore<V> {
    /// The registered store `id` over `vfs`, rooted at `dir`.
    pub fn open(id: u16, vfs: V, dir: impl Into<PathBuf>) -> Result<Self, KernelError> {
        let stores = DocumentStores::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
        let store = stores.get(id).ok_or_else(|| {
            KernelError::Corrupt(format!(
                "document store {id} is not registered in document_stores.toml"
            ))
        })?;
        if store.kind != "content_addressed" {
            return Err(KernelError::Corrupt(format!(
                "document store {id} has kind `{}`, which this build cannot address",
                store.kind
            )));
        }
        Ok(Self {
            id,
            max_document_bytes: store.max_document_bytes,
            vfs,
            dir: dir.into(),
        })
    }

    #[must_use]
    pub fn id(&self) -> u16 {
        self.id
    }

    /// The largest document this store accepts.
    #[must_use]
    pub fn max_document_bytes(&self) -> u64 {
        self.max_document_bytes
    }

    fn path(&self, locator: &str) -> io::Result<PathBuf> {
        if !is_locator(locator) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("`{locator}` is not a content-addressed locator"),
            ));
        }
        Ok(self.dir.join(&locator[..2]).join(locator))
    }

    /// Publish `bytes` under `locator`, durable before this returns, under
    /// `cx`'s commit authority:
    /// 1. the directories the blob needs are created;
    /// 2. the bytes go to a staged file whose name is this call's own
    ///    (`<locator>.<pid>-<n>.tmp`, opened create-new), so two puts never
    ///    share an inode, and the file is synced;
    /// 3. the staged file is renamed into place (content-addressed: a
    ///    concurrent put of the same locator renames the same bytes);
    /// 4. every directory on the blob's ancestor chain is synced, the blob's
    ///    own first and the VFS root last — whichever call created them, so
    ///    a retry after an interrupted put (whose directories exist but were
    ///    never synced) fences them too (WhiteCreek 3459).
    pub async fn put(&self, cx: &CommitCx, locator: &str, bytes: &[u8]) -> io::Result<()> {
        static STAGED: AtomicU64 = AtomicU64::new(0);
        let path = self.path(locator)?;
        let parent = path
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| self.dir.clone());
        let staged = parent.join(format!(
            "{locator}.{}-{}.tmp",
            std::process::id(),
            STAGED.fetch_add(1, Ordering::Relaxed)
        ));
        cx.with_restriction_async(async {
            self.vfs.create_dir_all(&parent).await?;
            let mut file = self
                .vfs
                .open(&staged, &OpenOptions::new().write(true).create_new(true))
                .await?;
            file.write_all(bytes).await?;
            sync_file(&mut file).await?;
            drop(file);
            self.vfs.rename(&staged, &path).await?;
            for dir in parent.ancestors() {
                sync_directory(&self.vfs, dir).await?;
            }
            Ok(())
        })
        .await
    }

    /// The bytes under `locator`, or `None` when the store has none. Under
    /// `cx`'s read authority.
    pub async fn get(&self, cx: &QueryCx, locator: &str) -> io::Result<Option<Vec<u8>>> {
        let path = self.path(locator)?;
        cx.with_restriction_async(async {
            match self.vfs.read(&path).await {
                Ok(bytes) => Ok(Some(bytes)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await
    }
}

/// Sync one open file. Borrowed `&mut`: a `VfsFile` is `Send` but not `Sync`
/// (fgdb-chronicle `sync_file`).
async fn sync_file<F: VfsFile>(file: &mut F) -> io::Result<()> {
    file.sync_all().await
}

/// Make the entries of `directory` durable: open it read-only and sync it
/// (fgdb-chronicle `sync_directory`). The path is spelled exactly as
/// `Path::ancestors` gives it — for a relative store root the last one is
/// the empty path, the VFS root — because a directory's pending entries are
/// owed to that spelling.
async fn sync_directory<V: Vfs>(vfs: &V, directory: &Path) -> io::Result<()> {
    let handle = vfs.open(directory, &OpenOptions::new().read(true)).await?;
    handle.sync_all().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locators_are_the_commitment_hex_and_nothing_else() {
        let l = locator_of(&[0xab; 32]);
        assert_eq!(l.len(), 64);
        assert!(is_locator(&l));
        for bad in [
            "",
            "AB",
            "../../etc/passwd",
            &"g".repeat(64),
            &"a".repeat(63),
        ] {
            assert!(!is_locator(bad), "{bad}");
        }
    }

    #[test]
    fn only_registered_content_addressed_stores_open() {
        let vfs = fgdb::MemVfs::new().expect("memvfs");
        assert!(BlobStore::open(1, vfs.clone(), "/blobs").is_ok());
        assert!(BlobStore::open(2, vfs, "/blobs").is_err());
    }
}
