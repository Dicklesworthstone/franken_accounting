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
