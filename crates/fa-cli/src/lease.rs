//! The book's writer lease (plan §5.10; Appendix D, FA-REF-018).
//!
//! One writer per book directory at a time: a `fad` daemon for its whole
//! life, or one direct `fa` command for its duration. The lease is an OS
//! advisory lock on `<book>/<lease>` (the name comes from
//! `registries/verbs.toml` `[daemon] lease`), taken with
//! [`std::fs::File::try_lock`]. The operating system releases it when the
//! holding process exits for any reason, so a crashed writer never leaves a
//! lease behind and nothing has to be cleaned up. The file's text is only a
//! note for messages ("who holds it"); the lock is the lease.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fa_journal::{Refusal, exit};

/// The refusal catalog code for a held writer lease (plan Appendix D).
pub const LEASE_HELD: &str = "FA-REF-018";

/// A held writer lease. Dropping it (or the process ending) releases it.
#[derive(Debug)]
pub struct Lease {
    file: File,
    path: PathBuf,
}

/// Why a lease could not be taken.
#[derive(Debug)]
pub enum LeaseError {
    /// Another writer holds it; `holder` is its note, when readable.
    Held { path: PathBuf, holder: String },
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
}

impl core::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Held { path, holder } => write!(
                f,
                "the book's writer lease {} is held ({})",
                path.display(),
                if holder.is_empty() {
                    "holder unknown"
                } else {
                    holder.as_str()
                }
            ),
            Self::Io { path, error } => write!(f, "{}: {error}", path.display()),
        }
    }
}

impl LeaseError {
    /// The structured refusal for a held lease (exit 6, conflict).
    #[must_use]
    pub fn refusal(&self, dir: &Path) -> Refusal {
        Refusal::new(
            LEASE_HELD,
            exit::CONFLICT,
            self.to_string(),
            "plan §5.10 (one writer per book) · Appendix D FA-REF-018",
            format!(
                "`fa` routes through a serving fad by itself; otherwise wait for the holder and retry, or see `fad status --book {}`",
                dir.display()
            ),
        )
    }
}

fn io_error(path: &Path) -> impl FnOnce(std::io::Error) -> LeaseError + '_ {
    move |error| LeaseError::Io {
        path: path.to_path_buf(),
        error,
    }
}

impl Lease {
    /// Take the lease of the book directory `dir` (which must exist) without
    /// waiting, recording `note` as the holder's description.
    pub fn acquire(dir: &Path, lease_file: &str, note: &str) -> Result<Self, LeaseError> {
        let path = dir.join(lease_file);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(io_error(&path))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(LeaseError::Held {
                    holder: read_note(&mut file),
                    path,
                });
            }
            Err(TryLockError::Error(error)) => return Err(LeaseError::Io { path, error }),
        }
        file.set_len(0).map_err(io_error(&path))?;
        file.seek(SeekFrom::Start(0)).map_err(io_error(&path))?;
        file.write_all(format!("{note}\n").as_bytes())
            .map_err(io_error(&path))?;
        file.flush().map_err(io_error(&path))?;
        Ok(Self { file, path })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The note of whoever holds `dir`'s lease now, or `None` when it is free.
    #[must_use]
    pub fn holder(dir: &Path, lease_file: &str) -> Option<String> {
        let path = dir.join(lease_file);
        let mut file = OpenOptions::new().read(true).open(&path).ok()?;
        match file.try_lock_shared() {
            Ok(()) => {
                // Free: nobody holds it exclusively. Our shared lock ends here.
                let _ = file.unlock();
                None
            }
            Err(TryLockError::WouldBlock) => Some(read_note(&mut file)),
            Err(TryLockError::Error(_)) => None,
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // Closing the file releases the lock too; unlocking first makes the
        // release immediate even if the descriptor were shared.
        let _ = self.file.unlock();
    }
}

fn read_note(file: &mut File) -> String {
    let mut text = String::new();
    let _ = file.seek(SeekFrom::Start(0));
    let _ = file.take(4096).read_to_string(&mut text);
    text.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fa-lease-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&d).expect("temp dir");
        d
    }

    #[test]
    fn one_holder_at_a_time_and_release_on_drop() {
        let d = dir("exclusive");
        assert_eq!(Lease::holder(&d, "fad.lease"), None);
        let first = Lease::acquire(&d, "fad.lease", "first writer").expect("free lease");
        // A second open file description in the same process is refused, as
        // another process would be.
        let second = Lease::acquire(&d, "fad.lease", "second writer");
        assert!(
            matches!(&second, Err(LeaseError::Held { holder, .. }) if holder == "first writer"),
            "{second:?}"
        );
        assert_eq!(
            Lease::holder(&d, "fad.lease").as_deref(),
            Some("first writer")
        );
        let refusal = second.err().map(|e| e.refusal(&d));
        assert_eq!(
            refusal.as_ref().map(|r| (r.code, r.exit)),
            Some((LEASE_HELD, exit::CONFLICT))
        );
        drop(first);
        assert_eq!(Lease::holder(&d, "fad.lease"), None);
        let third = Lease::acquire(&d, "fad.lease", "third writer").expect("released");
        assert_eq!(third.path(), d.join("fad.lease"));
    }

    #[test]
    fn a_missing_directory_is_an_io_error_not_a_hold() {
        let d = dir("missing").join("not-there");
        assert!(matches!(
            Lease::acquire(&d, "fad.lease", "x"),
            Err(LeaseError::Io { .. })
        ));
    }
}
