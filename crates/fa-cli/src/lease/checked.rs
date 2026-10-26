//! Bind inspection, locking and note publication to one open file description.
//! Lease directories still require trusted ownership: advisory locking cannot
//! stop a process with directory-write authority from unlinking a live lease.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use super::{apply_no_follow, is_existing_lease_note};

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// The parent performs book-directory and lease-name admission. Neither path
/// below truncates. A concurrent creator is opened and judged by the same
/// descriptor checks and OS lock as a previously existing lease.
pub(super) fn open_writer(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match apply_no_follow(&mut options).open(path) {
        Ok(file) => {
            validate_file(path, &file)?;
            Ok(file)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => open_existing(path, true),
        Err(error) => Err(error),
    }
}

pub(super) fn open_reader(path: &Path) -> io::Result<File> {
    open_existing(path, false)
}

fn open_existing(path: &Path, write: bool) -> io::Result<File> {
    // Refuse obvious special files before opening; the handle is checked again
    // afterwards. O_NONBLOCK on supported Unix targets also prevents a raced
    // replacement by a FIFO from waiting indefinitely at open.
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(invalid("writer lease path is not a regular non-symlink file"));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(write).create(false).truncate(false);
    let file = apply_no_follow(&mut options).open(path)?;
    validate_file(path, &file)?;
    Ok(file)
}

/// Check the descriptor that will actually be read or written, not metadata
/// from an earlier open. Unix identity/link checks exclude path substitution
/// and hard-link aliases, including aliases to another book's live lease.
pub(super) fn validate_file(path: &Path, file: &File) -> io::Result<()> {
    let held = file.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    if !held.is_file() || !named.file_type().is_file() {
        return Err(invalid("writer lease must remain a regular non-symlink file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if held.dev() != named.dev() || held.ino() != named.ino() {
            return Err(invalid("writer lease path changed after opening"));
        }
        if held.nlink() != 1 || named.nlink() != 1 {
            return Err(invalid("writer lease must have exactly one filesystem link"));
        }
        if held.permissions().mode() & 0o7777 != 0o600
            || named.permissions().mode() & 0o7777 != 0o600
        {
            return Err(invalid("writer lease must retain mode 0600"));
        }
    }
    Ok(())
}

/// Call only while holding the exclusive lock. Inspection and subsequent
/// truncation use this SAME descriptor. A failed check never writes anything.
pub(super) fn inspect_locked(path: &Path, file: &mut File) -> io::Result<()> {
    validate_file(path, file)?;
    let bytes = note_bytes(file)?;
    if !is_existing_lease_note(&bytes) {
        return Err(invalid("existing file is not a writer lease; refusing to truncate"));
    }
    validate_file(path, file)
}

fn note_bytes(file: &mut File) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    Read::by_ref(file).take(257).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The OS lock is authoritative even if its diagnostic note is temporarily
/// empty, corrupt, or partially written. Never disclose arbitrary file bytes
/// as a holder message, or treat a malformed note as an unlocked lease.
pub(super) fn holder_note(file: &mut File) -> String {
    let Ok(bytes) = note_bytes(file) else {
        return String::new();
    };
    if !is_existing_lease_note(&bytes) {
        return String::new();
    }
    String::from_utf8(bytes).map(|text| text.trim().to_string()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn path() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let dir = std::env::temp_dir().join(format!(
                "fa-checked-lease-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => return dir.join("fad.lease"),
                Err(error) => assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{error}"),
            }
        }
    }

    #[test]
    fn inspect_uses_the_locked_handle_and_does_not_change_contents() {
        let path = path();
        let mut file = open_writer(&path).unwrap();
        std::fs::write(&path, b"previous writer\n").unwrap();
        file.try_lock().unwrap();
        inspect_locked(&path, &mut file).unwrap();
        assert_eq!(holder_note(&mut file), "previous writer");
        assert_eq!(std::fs::read(&path).unwrap(), b"previous writer\n");
    }

    #[test]
    fn unrelated_or_oversized_contents_are_preserved_and_not_disclosed() {
        for bytes in [b"PRIVATE KEY DATA".to_vec(), vec![b'x'; 4096], vec![0xff]] {
            let path = path();
            let mut file = open_writer(&path).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            file.try_lock().unwrap();
            assert!(inspect_locked(&path, &mut file).is_err());
            assert!(holder_note(&mut file).is_empty());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
    }

    #[test]
    fn concurrent_creation_path_opens_the_same_lock_instead_of_overwriting() {
        let path = path();
        let first = open_writer(&path).unwrap();
        first.try_lock().unwrap();
        let second = open_writer(&path).unwrap();
        assert!(matches!(second.try_lock(), Err(std::fs::TryLockError::WouldBlock)));
        drop(first);
        second.try_lock().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn hard_link_aliases_cannot_be_opened_or_reclassified_as_leases() {
        let path = path();
        let mut held = open_writer(&path).unwrap();
        std::fs::write(&path, b"previous writer\n").unwrap();
        let alias = path.with_file_name("alias.lease");
        std::fs::hard_link(&path, &alias).unwrap();
        held.try_lock().unwrap();
        assert!(inspect_locked(&path, &mut held).is_err());
        assert!(open_writer(&alias).is_err());
        assert!(open_reader(&alias).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"previous writer\n");
        assert_eq!(std::fs::read(&alias).unwrap(), b"previous writer\n");
    }

    #[cfg(unix)]
    #[test]
    fn a_replaced_path_is_not_the_already_open_locked_file() {
        let path = path();
        let mut held = open_writer(&path).unwrap();
        std::fs::write(&path, b"original writer\n").unwrap();
        held.try_lock().unwrap();
        let moved = path.with_file_name("original.lease");
        std::fs::rename(&path, &moved).unwrap();
        let replacement = open_writer(&path).unwrap();
        std::fs::write(&path, b"replacement writer\n").unwrap();
        assert!(inspect_locked(&path, &mut held).is_err());
        validate_file(&path, &replacement).unwrap();
        assert_eq!(std::fs::read(&moved).unwrap(), b"original writer\n");
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement writer\n");
    }

    #[cfg(unix)]
    #[test]
    fn mode_changes_are_checked_on_the_open_descriptor() {
        use std::os::unix::fs::PermissionsExt;
        let path = path();
        let mut held = open_writer(&path).unwrap();
        held.try_lock().unwrap();
        held.set_permissions(std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(inspect_locked(&path, &mut held).is_err());
        assert!(open_reader(&path).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0o640);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_directory_targets_are_never_opened_as_leases() {
        use std::os::unix::fs::symlink;
        let target = path();
        let file = open_writer(&target).unwrap();
        std::fs::write(&target, b"original writer\n").unwrap();
        let alias = target.with_file_name("symlink.lease");
        symlink(&target, &alias).unwrap();
        assert!(open_writer(&alias).is_err());
        assert!(open_reader(&alias).is_err());
        assert!(open_writer(target.parent().unwrap()).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"original writer\n");
        validate_file(&target, &file).unwrap();
    }
}
