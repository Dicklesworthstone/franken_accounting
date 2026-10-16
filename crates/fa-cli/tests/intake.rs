//! Real CLI/host ingestion regressions: admission before input consumption,
//! bounded file and batch reads, and exact receipts after a mixed-storage run.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::{Books, Files, Stdin, run_with_authority};
use fa_cli::verbs::registry;

const LIMIT: u64 = 64 * 1024 * 1024;

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let path = std::env::temp_dir().join(format!(
                "fa-intake-cli-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create test directory: {error}"),
            }
        };
        let fixture = Self { book: dir.join("book"), dir };
        fixture.ok(&["book", "create", "--name", "Bounded intake", "--json"]);
        fixture
    }

    fn command(&self, args: &[&str]) -> (i32, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_fa"))
            .arg("--book")
            .arg(&self.book)
            .args(args)
            .env_remove("FA_BOOK")
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        for line in stdout.lines() {
            let verdict = registry().unwrap().check_line(line);
            assert!(verdict.is_ok(), "args={args:?}; {verdict:?}\n{line}\n{stderr}");
        }
        (output.status.code().unwrap_or(-1), stdout)
    }

    fn ok(&self, args: &[&str]) -> String {
        let (status, out) = self.command(args);
        assert_eq!(status, 0, "args={args:?}: {out}");
        out
    }

    fn head(&self) -> String {
        field(&self.ok(&["book", "info", "--json"]), "known_at")
            .expect("book coordinate")
            .to_string()
    }

    fn sparse(&self, name: &str, size: u64) -> String {
        let path = self.dir.join(name);
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        file.set_len(size).unwrap();
        path.to_str().unwrap().to_string()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let rest = &line[line.find(&needle)? + needle.len()..];
    if let Some(text) = rest.strip_prefix('"') {
        text.split('"').next()
    } else {
        rest.split([',', '}']).next()
    }
}

#[test]
fn oversized_single_document_has_no_receipt_or_journal_publication() {
    let fixture = Fixture::new();
    let path = fixture.sparse("too-large", LIMIT + 1);
    let before = fixture.head();
    let (status, output) = fixture.command(&["document", "add", &path, "--kind", "Invoice", "--json"]);
    assert_eq!(status, 2, "{output}");
    assert_eq!(field(&output, "refusal_id"), Some("FA-REF-083"));
    assert!(output.contains("budget"), "{output}");
    assert!(!output.contains("\"event\":\"document\""));
    assert_eq!(fixture.head(), before);
}

#[test]
fn individually_admissible_files_cannot_exhaust_memory_as_an_unbounded_batch() {
    let fixture = Fixture::new();
    let first = fixture.sparse("first", LIMIT / 2 + 1);
    let second = fixture.sparse("second", LIMIT / 2 + 2);
    let before = fixture.head();
    let (status, output) = fixture.command(&[
        "document", "import", "run", "--file", &first, "--file", &second,
        "--kind", "Invoice", "--key", "over-budget", "--json",
    ]);
    assert_eq!(status, 2, "{output}");
    assert_eq!(field(&output, "refusal_id"), Some("FA-REF-083"));
    assert!(output.contains("budget"), "{output}");
    assert!(!output.contains("\"event\":\"import_recorded\""));
    assert_eq!(fixture.head(), before);
}

#[test]
fn duplicate_stdin_is_rejected_before_trying_to_open_any_input() {
    let fixture = Fixture::new();
    let missing = fixture.dir.join("never-created");
    let before = fixture.head();
    let (status, output) = fixture.command(&[
        "document", "import", "run", "--file", missing.to_str().unwrap(),
        "--file", "-", "--file", "-", "--json",
    ]);
    assert_eq!(status, 2, "{output}");
    assert!(output.contains("stdin only once"), "{output}");
    assert!(!output.contains("No such file"), "{output}");
    assert_eq!(fixture.head(), before);
}

#[test]
fn bound_agent_import_refuses_before_consuming_missing_stdin() {
    let fixture = Fixture::new();
    let authority = LaunchAuthority::new(
        fixture.book.clone(), None, "bounded-agent", LaunchProfile::Agent, &["post"],
    ).unwrap();
    let before = fixture.head();
    let args: Vec<String> = ["document", "import", "run", "--file", "-", "--json"]
        .into_iter().map(String::from).collect();
    let (status, captured) = run_with_authority(
        &args, Books::Dir, Files { cwd: None, stdin: Stdin::Missing }, &authority, true,
    );
    assert_eq!(status, 7, "{}\n{}", captured.stdout, captured.stderr);
    assert_eq!(field(&captured.stdout, "refusal_id"), Some("FA-REF-013"));
    assert_eq!(fixture.head(), before);
}

#[test]
fn bounded_mixed_storage_import_preserves_receipt_retry_and_existing_provenance() {
    let fixture = Fixture::new();
    let small = fixture.dir.join("small");
    std::fs::write(&small, b"existing human invoice").unwrap();
    let small = small.to_str().unwrap();
    let original = fixture.ok(&[
        "document", "add", small, "--kind", "Invoice", "--grade", "HumanUpload", "--json",
    ]);
    let policy = fa_registry::evidence_policy::EvidencePolicy::embedded().unwrap();
    let inline = fa_journal::evidence::inline_document_bound(&policy);
    assert!(inline + 1 < LIMIT);
    let large = fixture.sparse("external", inline + 1);
    let args = [
        "document", "import", "run", "--source", "Upload", "--file", small,
        "--file", &large, "--kind", "Invoice", "--grade", "AgentUpload",
        "--key", "bounded-mixed-storage", "--json",
    ];
    let imported = fixture.ok(&args);
    assert_eq!(field(&imported, "document_count"), Some("2"));
    let head = fixture.head();
    let retried = fixture.ok(&args);
    assert_eq!(field(&retried, "already_recorded"), Some("true"));
    assert_eq!(field(&retried, "receipt_hash"), field(&imported, "receipt_hash"));
    assert_eq!(field(&retried, "run_vid"), field(&imported, "run_vid"));
    assert_eq!(fixture.head(), head);
    let duplicate = fixture.ok(&["document", "add", small, "--kind", "Invoice", "--json"]);
    assert_eq!(field(&duplicate, "grade"), Some("HumanUpload"));
    assert_eq!(field(&duplicate, "oid"), field(&original, "oid"));
    assert_eq!(fixture.head(), head);
    // The configured blob directory remains available after the separate
    // CLI processes reopened the book for its import, retry and duplicate.
    assert!(fixture.book.join("blobs").is_dir());
}
