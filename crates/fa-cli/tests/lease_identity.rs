//! Public lease admission on real files and across independent processes.
//! Test-created directories are preserved for inspection on failure.
#![cfg(unix)]

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;

use fa_cli::lease::{LEASE_HELD, Lease, LeaseError};

const NAME: &str = "fad.lease";
const CHILD_DIR: &str = "FA_LEASE_IDENTITY_TEST_CHILD_DIR";
const READY: &str = "FA_LEASE_IDENTITY_CHILD_READY";

fn book_dir() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let dir = std::env::temp_dir().join(format!(
            "fa-lease-identity-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&dir) {
            Ok(()) => {
                fs::create_dir(dir.join("store")).unwrap();
                return dir;
            }
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists, "{error}"),
        }
    }
}

fn note(path: &Path, bytes: &[u8]) -> File {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file
}

#[test]
fn public_admission_preserves_hard_linked_files_even_with_valid_note_bytes() {
    for bytes in [b"previous writer\n".as_slice(), b""] {
        let dir = book_dir();
        let source = dir.join("unrelated-data");
        let _file = note(&source, bytes);
        let lease_path = dir.join(NAME);
        fs::hard_link(&source, &lease_path).unwrap();
        let before = fs::metadata(&source).unwrap();
        assert!(matches!(
            Lease::acquire(&dir, NAME, "next writer"),
            Err(LeaseError::Io { .. })
        ));
        assert_eq!(Lease::holder(&dir, NAME), None);
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert_eq!(fs::read(&lease_path).unwrap(), bytes);
        assert_eq!(
            fs::metadata(&source).unwrap().modified().unwrap(),
            before.modified().unwrap()
        );
    }
}

#[test]
fn another_books_live_lease_cannot_be_used_as_a_hard_link_alias() {
    let first_dir = book_dir();
    let second_dir = book_dir();
    let first = Lease::acquire(&first_dir, NAME, "original writer").unwrap();
    fs::hard_link(first.path(), second_dir.join(NAME)).unwrap();
    assert!(matches!(
        Lease::acquire(&second_dir, NAME, "second writer"),
        Err(LeaseError::Io { .. })
    ));
    assert_eq!(fs::read(first.path()).unwrap(), b"original writer\n");
    drop(first);
    assert!(matches!(
        Lease::acquire(&second_dir, NAME, "second writer"),
        Err(LeaseError::Io { .. })
    ));
}

#[test]
fn malformed_diagnostics_do_not_hide_an_os_held_lease_or_disclose_contents() {
    let dir = book_dir();
    let path = dir.join(NAME);
    let secret = b"PRIVATE FILE CONTENT MUST NOT BECOME A HOLDER MESSAGE";
    let held = note(&path, secret);
    held.try_lock().unwrap();
    assert_eq!(Lease::holder(&dir, NAME), Some(String::new()));
    let error = Lease::acquire(&dir, NAME, "next writer").unwrap_err();
    assert!(matches!(&error, LeaseError::Held { holder, .. } if holder.is_empty()));
    let refusal = error.refusal(&dir);
    assert_eq!((refusal.code, refusal.exit), (LEASE_HELD, 6));
    assert!(!refusal.message.contains("PRIVATE FILE CONTENT"));
    assert_eq!(fs::read(&path).unwrap(), secret);
    drop(held);
    assert_eq!(Lease::holder(&dir, NAME), None);
    assert!(matches!(
        Lease::acquire(&dir, NAME, "next writer"),
        Err(LeaseError::Io { .. })
    ));
    assert_eq!(fs::read(&path).unwrap(), secret);
}

#[test]
fn public_admission_never_rewrites_symlink_targets_or_repairs_foreign_modes() {
    let dir = book_dir();
    let source = dir.join("source");
    let _source = note(&source, b"previous writer\n");
    symlink(&source, dir.join(NAME)).unwrap();
    assert!(matches!(
        Lease::acquire(&dir, NAME, "next writer"),
        Err(LeaseError::Io { .. })
    ));
    assert_eq!(fs::read(&source).unwrap(), b"previous writer\n");

    let dir = book_dir();
    let path = dir.join(NAME);
    let file = note(&path, b"previous writer\n");
    file.set_permissions(fs::Permissions::from_mode(0o640))
        .unwrap();
    assert!(matches!(
        Lease::acquire(&dir, NAME, "next writer"),
        Err(LeaseError::Io { .. })
    ));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o640
    );
    assert_eq!(fs::read(&path).unwrap(), b"previous writer\n");
}

#[test]
fn simultaneous_first_creators_return_one_lease_and_one_held_refusal() {
    let dir = book_dir();
    let barrier = Arc::new(Barrier::new(3));
    let handles: Vec<_> = ["first creator", "second creator"]
        .into_iter()
        .map(|description| {
            let dir = dir.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                Lease::acquire(&dir, NAME, description)
            })
        })
        .collect();
    barrier.wait();
    // Retain the winning Lease while joining the other contender.
    let results: Vec<_> = handles
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "{results:?}"
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(LeaseError::Held { .. })))
            .count(),
        1,
        "{results:?}"
    );
    drop(results);
    assert!(Lease::acquire(&dir, NAME, "subsequent writer").is_ok());
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            // Only this test's explicitly spawned child; never another writer.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
fn child_holds_writer_lease() {
    let Some(dir) = std::env::var_os(CHILD_DIR) else {
        return;
    };
    let held = Lease::acquire(Path::new(&dir), NAME, "child writer").unwrap();
    println!("{READY}");
    std::io::stdout().flush().unwrap();
    let mut release = [0];
    std::io::stdin().read_exact(&mut release).unwrap();
    assert_eq!(release, [b'R']);
    drop(held);
}

#[test]
fn independent_process_holds_the_writer_lease_until_explicit_release() {
    let dir = book_dir();
    let mut child = OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "child_holds_writer_lease", "--nocapture"])
            .env(CHILD_DIR, &dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let output = child.0.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut output = BufReader::new(output);
        for _ in 0..64 {
            let mut line = String::new();
            match output.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) if line.contains(READY) => {
                    // Keep the pipe open while the test harness prints its result.
                    let _ = sender.send(Some(output));
                    return;
                }
                Ok(_) => {}
            }
        }
        let _ = sender.send(None);
    });
    let _output = receiver
        .recv_timeout(Duration::from_secs(15))
        .unwrap()
        .expect("child acquired its lease before signalling");
    reader.join().unwrap();
    assert_eq!(Lease::holder(&dir, NAME).as_deref(), Some("child writer"));
    assert!(matches!(
        Lease::acquire(&dir, NAME, "parent writer"),
        Err(LeaseError::Held { .. })
    ));
    child.0.stdin.take().unwrap().write_all(b"R").unwrap();
    assert!(child.0.wait().unwrap().success());
    assert_eq!(Lease::holder(&dir, NAME), None);
    let parent = Lease::acquire(&dir, NAME, "parent writer").unwrap();
    assert_eq!(fs::read(parent.path()).unwrap(), b"parent writer\n");
}
