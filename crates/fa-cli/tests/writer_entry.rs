//! Real front-door calls must never open or create a book after lease failure.
//! Fixtures retain their files so a failed assertion preserves its evidence.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fa::{Book, BookKeys, Entropy};
use fa_cli::cli::{Captured, Files};
use fa_cli::entry::fa_with;
use fa_cli::lease::Lease;
use fa_cli::verbs;
use fa_journal::exit;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn fresh(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "fa-writer-entry-{}-{}-{name}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    assert!(!path.exists(), "fixture already exists: {}", path.display());
    path
}

fn call(dir: &Path, command: &[&str], direct: bool) -> (u8, Captured) {
    let mut argv: Vec<String> = command.iter().map(|word| (*word).to_string()).collect();
    argv.extend(["--book".into(), dir.display().to_string(), "--json".into()]);
    if direct {
        argv.extend(["--via".into(), "direct".into()]);
    }
    fa_with(&argv, Files::default(), true)
}

fn created(name: &str) -> PathBuf {
    let dir = fresh(name);
    let (status, output) = call(&dir, &["book", "create", "--name", name], true);
    assert_eq!(status, exit::SUCCESS, "{}{}", output.stdout, output.stderr);
    dir
}

fn head(dir: &Path) -> u64 {
    let keys = BookKeys::load(&dir.join("book.keys")).unwrap();
    let book = Book::open_dir(dir, keys, Entropy::deterministic(221)).unwrap();
    book.head().unwrap().0
}

fn block_lease(dir: &Path) {
    let lease = dir.join(&verbs::registry().unwrap().daemon.lease);
    // Preserve a previously written note; do not remove it or the book.
    if lease.is_file() {
        std::fs::rename(&lease, dir.join("previous-writer-lease-note")).unwrap();
    }
    std::fs::create_dir(&lease).unwrap();
}

#[test]
fn genesis_creates_and_releases_the_same_lease_used_by_later_writers() {
    let dir = created("genesis");
    let reg = verbs::registry().unwrap();
    let path = dir.join(&reg.daemon.lease);
    assert!(path.is_file(), "genesis must not bypass the writer lease");
    assert!(std::fs::read_to_string(path).unwrap().starts_with("fa pid="));
    assert!(dir.join("book.keys").is_file());
    assert!(dir.join("store").is_dir());
    assert_eq!(Lease::holder(&dir, &reg.daemon.lease), None);
    let lease = Lease::acquire(&dir, &reg.daemon.lease, "next writer").unwrap();
    drop(lease);
}

#[test]
fn lease_io_failure_refuses_both_reads_and_writes_without_publication() {
    let dir = created("io-failure");
    let before = head(&dir);
    block_lease(&dir);
    for direct in [false, true] {
        for command in [
            vec!["book", "info"],
            vec!["period", "create", "--fiscal-year", "2026"],
        ] {
            let (status, output) = call(&dir, &command, direct);
            assert_eq!(status, exit::ENVIRONMENT, "{}{}", output.stdout, output.stderr);
            assert!(output.stdout.contains("cannot acquire the book's writer lease"));
            assert!(!output.stdout.contains("\"event\":\"book\""));
            assert!(!output.stdout.contains("\"event\":\"periods_created\""));
            assert_eq!(head(&dir), before, "refused admission must not advance the book");
        }
    }
}

#[test]
fn a_broken_lease_cannot_be_used_to_initialize_an_empty_directory() {
    let dir = fresh("broken-genesis");
    std::fs::create_dir(&dir).unwrap();
    block_lease(&dir);
    let (status, output) = call(&dir, &["book", "create", "--name", "blocked"], true);
    assert_eq!(status, exit::ENVIRONMENT, "{}{}", output.stdout, output.stderr);
    assert!(!dir.join("book.keys").exists());
    assert!(!dir.join("store").exists());
}

#[test]
fn a_competing_writer_prevents_genesis_before_keys_or_store_are_created() {
    let dir = fresh("held-genesis");
    std::fs::create_dir(&dir).unwrap();
    let reg = verbs::registry().unwrap();
    let held = Lease::acquire(&dir, &reg.daemon.lease, "first creator").unwrap();
    let (status, output) = call(&dir, &["book", "create", "--name", "second"], true);
    assert_eq!(status, exit::CONFLICT, "{}{}", output.stdout, output.stderr);
    assert!(output.stdout.contains("FA-REF-018"));
    assert!(!dir.join("book.keys").exists());
    assert!(!dir.join("store").exists());
    assert_eq!(Lease::holder(&dir, &reg.daemon.lease).as_deref(), Some("first creator"));
    drop(held);
    let (status, output) = call(&dir, &["book", "create", "--name", "after release"], true);
    assert_eq!(status, exit::SUCCESS, "{}{}", output.stdout, output.stderr);
}

#[test]
fn an_existing_book_command_never_creates_a_missing_directory() {
    let dir = fresh("missing");
    let (status, output) = call(&dir, &["book", "info"], true);
    assert_eq!(status, exit::ENVIRONMENT, "{}{}", output.stdout, output.stderr);
    assert!(!dir.exists());
}

#[test]
fn discovery_needs_no_book_and_does_not_create_one() {
    let dir = fresh("discovery");
    for command in [
        vec!["book", "create", "--help"],
        vec!["help", "book"],
        vec!["capabilities"],
    ] {
        let (status, output) = call(&dir, &command, true);
        assert_eq!(status, exit::SUCCESS, "{}{}", output.stdout, output.stderr);
        assert!(!dir.exists(), "discovery must not create a directory or keys");
    }
}

#[test]
fn a_flag_looking_book_name_is_not_a_discovery_escape() {
    let dir = fresh("name-is-data");
    let (status, output) = call(&dir, &["book", "create", "--name", "--help"], true);
    assert_eq!(status, exit::SUCCESS, "{}{}", output.stdout, output.stderr);
    assert!(dir.join(&verbs::registry().unwrap().daemon.lease).is_file());
    assert!(dir.join("store").is_dir());
}

#[test]
fn directory_preparation_errors_do_not_overwrite_a_file_or_open_the_book() {
    let dir = fresh("not-directory");
    std::fs::write(&dir, b"preserve this file").unwrap();
    let (status, output) = call(&dir, &["book", "create", "--name", "blocked"], true);
    assert_eq!(status, exit::ENVIRONMENT, "{}{}", output.stdout, output.stderr);
    assert_eq!(std::fs::read(&dir).unwrap(), b"preserve this file");
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct EntrySnapshot {
    rel: String,
    is_dir: bool,
    is_symlink: bool,
    mode: u32,
    mtime: std::time::SystemTime,
    digest: [u8; 32],
}

#[cfg(unix)]
fn snapshot_dir(root: &Path) -> Vec<EntrySnapshot> {
    use std::os::unix::fs::PermissionsExt;
    fn walk(root: &Path, cur: &Path, out: &mut Vec<EntrySnapshot>) {
        let meta = std::fs::symlink_metadata(cur).unwrap();
        let ft = meta.file_type();
        let rel = cur
            .strip_prefix(root)
            .unwrap_or(cur)
            .to_string_lossy()
            .into_owned();
        let digest = if ft.is_file() {
            let bytes = std::fs::read(cur).unwrap();
            fa_model::domain_digest(b"test-snapshot", &[&bytes])
        } else if ft.is_symlink() {
            let target = std::fs::read_link(cur).unwrap();
            let target_str = target.to_string_lossy();
            fa_model::domain_digest(b"test-symlink", &[target_str.as_bytes()])
        } else {
            [0u8; 32]
        };
        out.push(EntrySnapshot {
            rel,
            is_dir: ft.is_dir(),
            is_symlink: ft.is_symlink(),
            mode: meta.permissions().mode() & 0o777,
            mtime: meta.modified().unwrap(),
            digest,
        });
        if ft.is_dir() {
            let mut entries: Vec<_> = std::fs::read_dir(cur)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            entries.sort();
            for entry in entries {
                walk(root, &entry, out);
            }
        }
    }
    let mut out = Vec::new();
    if root.exists() {
        walk(root, root, &mut out);
    }
    out
}

#[cfg(unix)]
#[test]
fn key_file_at_0644_refuses_with_fa_ref_155_and_leaves_filesystem_unchanged() {
    use std::os::unix::fs::PermissionsExt;
    let dir = created("keys-0644");
    let keys_path = dir.join("book.keys");
    std::fs::set_permissions(&keys_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let observed_mode = std::fs::symlink_metadata(&keys_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(observed_mode, 0o644);

    // Embedded BookKeys::load refuses 0644 with FA-REF-155.
    let err = BookKeys::load(&keys_path).unwrap_err();
    let refusal = err.refusal().expect("KeyFilePermissions maps to FA-REF-155");
    eprintln!(
        "path={} observed_mode={:04o} decision=refuse refusal_id={}",
        keys_path.display(),
        observed_mode,
        refusal.code
    );
    assert_eq!(refusal.code, "FA-REF-155");
    assert_eq!(err.exit(), exit::ENVIRONMENT);

    // Wait briefly so any unintended write to fad.lease would advance mtime,
    // then verify CLI commands leave all directory hashes and mtimes unchanged.
    let before = snapshot_dir(&dir);
    for command in [
        vec!["book", "info"],
        vec!["doctor"],
        vec!["period", "create", "--fiscal-year", "2026"],
    ] {
        let (status, output) = call(&dir, &command, true);
        eprintln!(
            "cmd={:?} path={} observed_mode={:04o} decision=exit({}) refusal_id=FA-REF-155",
            command,
            keys_path.display(),
            observed_mode,
            status
        );
        assert_eq!(status, exit::ENVIRONMENT, "{}{}", output.stdout, output.stderr);
        assert!(output.stdout.contains("FA-REF-155"), "{}", output.stdout);
        assert!(
            output.stdout.contains(&format!("chmod 600 {}", keys_path.display())),
            "{}",
            output.stdout
        );
        let after = snapshot_dir(&dir);
        assert_eq!(
            before, after,
            "failed invocation with 0644 key file must not modify hashes or mtimes in {}",
            dir.display()
        );
    }
}

#[cfg(unix)]
#[test]
fn non_book_directory_and_discovery_never_create_lease_files() {
    let dir = fresh("non-book-dir");
    std::fs::create_dir_all(&dir).unwrap();
    let unrelated = dir.join("notes.txt");
    std::fs::write(&unrelated, b"unrelated directory contents").unwrap();
    let reg = verbs::registry().unwrap();
    let lease_path = dir.join(&reg.daemon.lease);
    let before = snapshot_dir(&dir);

    for command in [
        vec!["book", "info"],
        vec!["doctor"],
        vec!["tb", "--period", "FY2026-P01"],
        vec!["book", "create", "--name", "refused-in-populated-dir"],
        vec!["--help"],
        vec!["help"],
        vec!["capabilities"],
    ] {
        let (status, output) = call(&dir, &command, true);
        eprintln!(
            "cmd={:?} path={} observed_mode=0755 decision=exit({}) refusal_id=none",
            command,
            dir.display(),
            status
        );
        if matches!(command.first().copied(), Some("--help" | "help" | "capabilities")) {
            assert_eq!(status, exit::SUCCESS, "{}{}", output.stdout, output.stderr);
        } else {
            assert_eq!(status, exit::ENVIRONMENT, "{}{}", output.stdout, output.stderr);
        }
        assert!(
            !lease_path.exists(),
            "must never create {} in non-book directory for {:?}",
            lease_path.display(),
            command
        );
        let after = snapshot_dir(&dir);
        assert_eq!(
            before, after,
            "non-book directory hashes and mtimes must be unchanged after {:?}",
            command
        );
    }

    // Also test an empty existing directory with non-create commands.
    let empty_dir = fresh("empty-non-book-dir");
    std::fs::create_dir_all(&empty_dir).unwrap();
    let empty_before = snapshot_dir(&empty_dir);
    let (status, output) = call(&empty_dir, &["book", "info"], true);
    assert_eq!(status, exit::ENVIRONMENT, "{}{}", output.stdout, output.stderr);
    assert!(!empty_dir.join(&reg.daemon.lease).exists());
    assert_eq!(empty_before, snapshot_dir(&empty_dir));
}

#[cfg(unix)]
#[test]
fn symlinked_and_non_lease_files_are_refused_without_truncation() {
    use std::os::unix::fs::PermissionsExt;
    let reg = verbs::registry().unwrap();

    // 1. Existing non-lease file at fad.lease is refused without truncation.
    let dir = created("non-lease-file");
    let lease_path = dir.join(&reg.daemon.lease);
    std::fs::write(&lease_path, b"precious user file - not a lease\n").unwrap();
    let before = snapshot_dir(&dir);
    let observed_mode = std::fs::symlink_metadata(&lease_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let (status, output) = call(&dir, &["book", "info"], true);
    eprintln!(
        "path={} observed_mode={:04o} decision=refuse_non_lease exit={} refusal_id=none",
        lease_path.display(),
        observed_mode,
        status
    );
    assert_eq!(status, exit::ENVIRONMENT, "{}{}", output.stdout, output.stderr);
    assert_eq!(
        std::fs::read(&lease_path).unwrap(),
        b"precious user file - not a lease\n"
    );
    assert_eq!(before, snapshot_dir(&dir));

    // 2. Symlink at fad.lease is refused without modifying or truncating target.
    let sym_dir = created("symlink-lease");
    let sym_lease = sym_dir.join(&reg.daemon.lease);
    let target = fresh("symlink-target");
    std::fs::write(&target, b"target file must not be truncated").unwrap();
    let target_before_meta = std::fs::symlink_metadata(&target).unwrap();
    let target_before_mtime = target_before_meta.modified().unwrap();
    // Move original fad.lease aside without deleting (Rule 1 compliance).
    std::fs::rename(&sym_lease, sym_dir.join("original-lease-backup")).unwrap();
    std::os::unix::fs::symlink(&target, &sym_lease).unwrap();
    let sym_before = snapshot_dir(&sym_dir);
    let (status, output) = call(&sym_dir, &["book", "info"], true);
    eprintln!(
        "path={} observed_mode=symlink decision=refuse_symlink exit={} refusal_id=none",
        sym_lease.display(),
        status
    );
    assert_eq!(status, exit::ENVIRONMENT, "{}{}", output.stdout, output.stderr);
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"target file must not be truncated"
    );
    assert_eq!(
        std::fs::symlink_metadata(&target).unwrap().modified().unwrap(),
        target_before_mtime
    );
    assert_eq!(sym_before, snapshot_dir(&sym_dir));
}

