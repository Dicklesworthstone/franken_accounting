//! Exercise the actual executable, including dispatch, file bounds, exit
//! classification and NDJSON. Fixtures retain their files for diagnosis.
//! The expected commitment is computed from the original document, never
//! recovered from the view by the executable.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::blake3::{hash_parts, hex};
use fa_verify::document::{DOC_CHUNK_BYTES, DOC_LEAF_DOMAIN, doc_commit};
use fa_verify::redaction::MAX_VIEW_BYTES;

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-redacted-view-process-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create {}: {error}", path.display()),
        }
    }
}

fn view(doc: &[u8], disclosed: &[u64]) -> (Vec<u8>, [u8; 32]) {
    let anchor = doc_commit(1, doc);
    let chunks: Vec<&[u8]> = if doc.is_empty() {
        vec![&[]]
    } else {
        doc.chunks(DOC_CHUNK_BYTES).collect()
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&[17; 32]);
    bytes.extend_from_slice(&7u16.to_le_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&(doc.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&anchor);
    bytes.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
    for (index, chunk) in chunks.iter().enumerate() {
        if disclosed.contains(&(index as u64)) {
            bytes.push(0);
            bytes.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
            bytes.extend_from_slice(chunk);
        } else {
            bytes.push(1);
            bytes.extend_from_slice(&hash_parts(
                DOC_LEAF_DOMAIN,
                &[
                    &(index as u64).to_le_bytes(),
                    &(chunk.len() as u64).to_le_bytes(),
                    chunk,
                ],
            ));
        }
    }
    (bytes, anchor)
}

fn run(path: &Path, anchor: &[u8; 32], requested: &str, json: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fa-verify"));
    command
        .arg("redacted-view")
        .arg("--view")
        .arg(path)
        .arg("--document-commit")
        .arg(hex(anchor))
        .arg("--expect-chunks")
        .arg(requested);
    if json {
        command.arg("--json");
    }
    command.output().expect("run standalone verifier")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("UTF-8 report")
}

fn failure(output: &Output, exit: i32, class: &str) {
    let text = stdout(output);
    assert_eq!(output.status.code(), Some(exit), "{text}");
    assert!(!output.stderr.is_empty(), "failure has diagnostics");
    assert_eq!(text.lines().count(), 1, "one NDJSON error: {text}");
    assert!(text.contains("\"event\":\"error\""), "{text}");
    assert!(text.contains("\"verified\":false"), "{text}");
    assert!(text.contains(&format!("\"class\":\"{class}\"")), "{text}");
    assert!(
        !text.contains("proof_verified"),
        "no partial success: {text}"
    );
}

#[test]
fn valid_partial_and_empty_views_verify_without_printing_evidence() {
    let dir = directory();
    let secret = b"DO-NOT-ECHO-EVIDENCE";
    let mut doc = vec![7; 2 * DOC_CHUNK_BYTES + secret.len()];
    doc[..secret.len()].copy_from_slice(secret);
    doc[2 * DOC_CHUNK_BYTES..].copy_from_slice(secret);
    let (bytes, anchor) = view(&doc, &[0, 2]);
    let path = dir.join("partial.view");
    fs::write(&path, bytes).unwrap();
    let output = run(&path, &anchor, "0,2", true);
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{text}");
    assert!(output.stderr.is_empty());
    assert_eq!(text.lines().count(), 1);
    for field in [
        "\"proof_kind\":\"redacted_view\"",
        "\"scope\":\"membership_only\"",
        "\"verified\":true",
        "\"withheld_chunks\":1",
        "operator_trusted_document_commitment",
        "not_authenticated_by_document_commitment",
        "computed_not_authenticated",
    ] {
        assert!(text.contains(field), "missing {field}: {text}");
    }
    assert!(text.contains(&format!(
        "\"index\":2,\"offset\":{},\"length\":{}",
        2 * DOC_CHUNK_BYTES,
        secret.len()
    )));
    assert!(!text.contains(std::str::from_utf8(secret).unwrap()));
    assert!(!text.contains("operator_trusted_checkpoint"));
    let human = run(&path, &anchor, "0,2", false);
    assert_eq!(human.status.code(), Some(0));
    assert!(stdout(&human).contains("unverified metadata"));
    assert!(!stdout(&human).contains(std::str::from_utf8(secret).unwrap()));

    let (bytes, anchor) = view(&[], &[0]);
    let empty = dir.join("empty.view");
    fs::write(&empty, bytes).unwrap();
    let output = run(&empty, &anchor, "0", true);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
    assert!(stdout(&output).contains("\"index\":0,\"offset\":0,\"length\":0"));
}

#[test]
fn wrong_anchor_wrong_request_and_corrupt_later_chunk_fail_with_exit_eight() {
    let dir = directory();
    let doc = vec![13; 8193];
    let (bytes, anchor) = view(&doc, &[0, 2]);
    let path = dir.join("valid.view");
    fs::write(&path, &bytes).unwrap();
    for request in ["0", "0,1,2", "1,2", "0,3"] {
        failure(&run(&path, &anchor, request, true), 8, "verification");
    }
    let mut wrong = anchor;
    wrong[0] ^= 1;
    failure(&run(&path, &wrong, "0,2", true), 8, "verification");
    let mut corrupt = bytes.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let mut trailing = bytes.clone();
    trailing.push(0);
    let mut wrong_tag = bytes.clone();
    wrong_tag[81] = 2;
    for (name, data) in [
        ("last-chunk", corrupt),
        ("trailing", trailing),
        ("tag", wrong_tag),
        ("truncated", bytes[..bytes.len() - 1].to_vec()),
        ("empty", Vec::new()),
    ] {
        let path = dir.join(format!("{name}.view"));
        fs::write(&path, data).unwrap();
        failure(&run(&path, &anchor, "0,2", true), 8, "verification");
    }
}

#[test]
fn invalid_invocations_are_usage_before_io_and_missing_files_are_io() {
    let dir = directory();
    let missing = dir.join("never-created.view");
    for request in ["", "0,0", "2,0", "0,", "+0", "16384"] {
        failure(&run(&missing, &[0; 32], request, true), 2, "usage");
    }
    failure(&run(&missing, &[0; 32], "0", true), 5, "foundation");
    let output = Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .args(["redacted-view", "--view"])
        .arg(&missing)
        .args(["--expect-chunks", "0", "--json"])
        .output()
        .unwrap();
    failure(&output, 2, "usage");
    let output = Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .args([
            "redacted-view",
            "--checkpoint",
            "not-a-document-anchor",
            "--json",
        ])
        .output()
        .unwrap();
    failure(&output, 2, "usage");
}

#[test]
fn overlarge_view_is_refused_before_reading_its_payload() {
    let dir = directory();
    let path = dir.join("sparse-over-bound.view");
    let file = File::create(&path).unwrap();
    file.set_len(MAX_VIEW_BYTES as u64 + 1).unwrap();
    drop(file);
    failure(&run(&path, &[0; 32], "0", true), 8, "verification");
}

#[cfg(unix)]
#[test]
fn non_utf8_view_paths_remain_usable() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let dir = directory();
    let path = dir.join(OsString::from_vec(b"view-\xff.bin".to_vec()));
    let (bytes, anchor) = view(b"legitimate filename", &[0]);
    fs::write(&path, bytes).unwrap();
    let output = run(&path, &anchor, "0", true);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
    assert!(output.stderr.is_empty());
}
