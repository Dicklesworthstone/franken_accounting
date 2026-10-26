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
//! Inspection and publication share the locked descriptor. Unix leases must
//! have exactly one link and retain their path identity and mode 0600. The
//! book directory must remain trusted: an advisory lock cannot stop an actor
//! with directory-write authority from unlinking an active lease.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use fa_journal::{Refusal, exit};

mod checked;

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

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
const O_NOFOLLOW_FLAG: i32 = 0x0100 | 0x0004; // O_NOFOLLOW | O_NONBLOCK

#[cfg(target_os = "linux")]
const O_NOFOLLOW_FLAG: i32 = 0x20000 | 0x0800; // O_NOFOLLOW | O_NONBLOCK

fn apply_no_follow(opts: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "linux"
    ))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(O_NOFOLLOW_FLAG);
    }
    opts
}

/// Query `symlink_metadata` through `asupersync`'s filesystem (`UnixVfs`).
fn vfs_symlink_metadata(path: &Path) -> std::io::Result<asupersync::fs::Metadata> {
    use asupersync::fs::{UnixVfs, Vfs};
    let runtime = asupersync::runtime::RuntimeBuilder::new()
        .build()
        .map_err(|e| std::io::Error::other(format!("runtime: {e:?}")))?;
    runtime.block_on(UnixVfs.symlink_metadata(path))
}

fn validate_lease_file_name(path: &Path, lease_file: &str) -> Result<(), LeaseError> {
    use std::path::Component;
    let mut components = Path::new(lease_file).components();
    let valid = matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
        && Path::new(lease_file)
            .extension()
            .is_some_and(|ext| ext == "lease");
    if !valid {
        return Err(LeaseError::Io {
            path: path.to_path_buf(),
            error: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("`{lease_file}` is not a valid writer lease file name"),
            ),
        });
    }
    Ok(())
}

fn is_existing_lease_note(text: &[u8]) -> bool {
    if text.is_empty() {
        return true;
    }
    if text.len() > 256 {
        return false;
    }
    let Ok(s) = core::str::from_utf8(text) else {
        return false;
    };
    let Some(line) = s.strip_suffix('\n') else {
        return false;
    };
    if line.is_empty() || line.contains('\n') || line.contains('\r') || line.contains('\0') {
        return false;
    }
    line.starts_with("fa pid=")
        || line.starts_with("fad pid=")
        || line.starts_with("fa-mcp pid=")
        || line.ends_with(" writer")
        || line.ends_with(" creator")
}

impl Lease {
    /// True when `dir` is a real (non-symlink) directory containing a real
    /// (non-symlink) `store` directory created at book genesis.
    #[must_use]
    pub fn is_book_dir(dir: &Path) -> bool {
        let Ok(dir_meta) = vfs_symlink_metadata(dir) else {
            return false;
        };
        if dir_meta.is_symlink() || !dir_meta.is_dir() {
            return false;
        }
        let Ok(store_meta) = vfs_symlink_metadata(&dir.join("store")) else {
            return false;
        };
        !store_meta.is_symlink() && store_meta.is_dir()
    }

    /// True when `dir` is a real (non-symlink) directory that is either empty
    /// or contains only `lease_file` (an uninitialized genesis directory).
    #[must_use]
    pub fn is_empty_or_lease_only(dir: &Path, lease_file: &str) -> bool {
        let Ok(dir_meta) = vfs_symlink_metadata(dir) else {
            return false;
        };
        if dir_meta.is_symlink() || !dir_meta.is_dir() {
            return false;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            if entry.file_name() != std::ffi::OsStr::new(lease_file) {
                return false;
            }
        }
        true
    }

    /// Take the lease of the book directory `dir` (which must exist) without
    /// waiting, recording `note` as the holder's description.
    pub fn acquire(dir: &Path, lease_file: &str, note: &str) -> Result<Self, LeaseError> {
        let path = dir.join(lease_file);
        validate_lease_file_name(&path, lease_file)?;

        let dir_meta = vfs_symlink_metadata(dir).map_err(io_error(&path))?;
        if dir_meta.is_symlink() || !dir_meta.is_dir() {
            return Err(LeaseError::Io {
                path,
                error: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "{} is not a real directory (symlinks are refused)",
                        dir.display()
                    ),
                ),
            });
        }
        if let Some(holder) = Self::holder(dir, lease_file) {
            return Err(LeaseError::Held { path, holder });
        }
        if !Self::is_book_dir(dir) && !Self::is_empty_or_lease_only(dir, lease_file) {
            return Err(LeaseError::Io {
                path,
                error: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "{} is not a FrankenAccounting book directory",
                        dir.display()
                    ),
                ),
            });
        }

        let mut file = checked::open_writer(&path).map_err(io_error(&path))?;

        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                checked::validate_file(&path, &file).map_err(io_error(&path))?;
                return Err(LeaseError::Held {
                    holder: checked::holder_note(&mut file),
                    path,
                });
            }
            Err(TryLockError::Error(error)) => return Err(LeaseError::Io { path, error }),
        }
        checked::inspect_locked(&path, &mut file).map_err(io_error(&path))?;
        file.set_len(0).map_err(io_error(&path))?;
        file.seek(SeekFrom::Start(0)).map_err(io_error(&path))?;
        file.write_all(format!("{note}\n").as_bytes())
            .map_err(io_error(&path))?;
        file.flush().map_err(io_error(&path))?;
        checked::validate_file(&path, &file).map_err(io_error(&path))?;
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
        validate_lease_file_name(&path, lease_file).ok()?;
        let mut file = checked::open_reader(&path).ok()?;
        match file.try_lock_shared() {
            Ok(()) => {
                // Free: nobody holds it exclusively. Our shared lock ends here.
                let _ = file.unlock();
                None
            }
            Err(TryLockError::WouldBlock) => {
                checked::validate_file(&path, &file).ok()?;
                Some(checked::holder_note(&mut file))
            }
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
