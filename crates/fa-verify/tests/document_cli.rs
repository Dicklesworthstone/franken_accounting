//! The actual offline binary reads portable document disclosures. Crypto
//! cross-implementation coverage lives in fa-notary/tests/disclosure.rs;
//! this file exercises wire, recipient-request, process and output boundaries.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::blake3::hash_parts;
use fa_verify::disclosure::{FORMAT, MAX_PROOF_BYTES};
use fa_verify::document::{DOC_LEAF_DOMAIN, DOC_NODE_DOMAIN, doc_commit};

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "fa-document-disclosure-cli-{}-{index}",
            std::process::id()
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn wire(kind: u8, length: u64, chunks: &[(u64, &[u8], Vec<[u8; 32]>)]) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, FORMAT);
    out.push(kind);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
    for (index, bytes, siblings) in chunks {
        out.extend_from_slice(&index.to_le_bytes());
        put_bytes(&mut out, bytes);
        out.extend_from_slice(&(siblings.len() as u32).to_le_bytes());
        for sibling in siblings {
            out.extend_from_slice(sibling);
        }
    }
    out
}

fn run(proof: &Path, commitment: &Path, chunks: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .arg("document")
        .arg("--proof")
        .arg(proof)
        .arg("--document-commit")
        .arg(commitment)
        .args(["--chunks", chunks, "--json"])
        .output()
        .expect("run actual offline verifier")
}

fn check(output: &Output, exit: i32) -> String {
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(exit), "{stdout}\n{stderr}");
    assert_eq!(
        stdout.lines().count(),
        1,
        "exactly one complete result: {stdout}"
    );
    if exit == 0 {
        assert!(stderr.is_empty(), "{stderr}");
        assert!(stdout.contains("\"event\":\"proof_verified\""), "{stdout}");
        assert!(stdout.contains("\"scope\":\"membership_only\""), "{stdout}");
    } else {
        assert!(stdout.contains("\"event\":\"error\""), "{stdout}");
        assert!(stdout.contains("\"verified\":false"), "{stdout}");
        assert!(
            !stdout.contains("proof_verified"),
            "no partial success: {stdout}"
        );
    }
    stdout
}

#[test]
fn document_command_verifies_a_raw_export_without_echoing_disclosed_content() {
    let dir = directory();
    let proof = dir.join("proof.bin");
    let commitment = dir.join("commitment.bin");
    let content = b"DO_NOT_ECHO_DISCLOSED_SOURCE_CONTENT";
    std::fs::write(
        &proof,
        wire(18, content.len() as u64, &[(0, content, vec![])]),
    )
    .unwrap();
    std::fs::write(&commitment, doc_commit(18, content)).unwrap();
    let stdout = check(&run(&proof, &commitment, "0"), 0);
    assert!(stdout.contains("\"proof_kind\":\"document\""));
    assert!(stdout.contains("operator_trusted_document_commitment"));
    assert!(stdout.contains("\"index\":\"0\""));
    assert!(!stdout.contains(std::str::from_utf8(content).unwrap()));
    assert!(!stdout.contains(&fa_verify::blake3::hex(content)));
    let human = Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .arg("document")
        .arg("--proof")
        .arg(&proof)
        .arg("--document-commit")
        .arg(&commitment)
        .args(["--chunks", "0"])
        .output()
        .unwrap();
    assert_eq!(human.status.code(), Some(0));
    let human = String::from_utf8(human.stdout).unwrap();
    assert!(human.contains("membership_only"));
    assert!(human.contains("production completeness were not verified"));
    assert!(!human.contains(std::str::from_utf8(content).unwrap()));
}

#[test]
fn omitted_substituted_and_damaged_later_chunks_never_yield_partial_success() {
    let dir = directory();
    let proof = dir.join("proof.bin");
    let commitment = dir.join("commitment.bin");
    let chunks = [vec![17; 4096], vec![34; 4096], b"tail".to_vec()];
    let document = chunks.concat();
    let leaves: Vec<_> = chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| {
            hash_parts(
                DOC_LEAF_DOMAIN,
                &[
                    &(i as u64).to_le_bytes(),
                    &(chunk.len() as u64).to_le_bytes(),
                    chunk,
                ],
            )
        })
        .collect();
    let left = hash_parts(DOC_NODE_DOMAIN, &[&leaves[0], &leaves[1]]);
    let bytes = wire(
        9,
        document.len() as u64,
        &[
            (0, &chunks[0], vec![leaves[1], leaves[2]]),
            (2, &chunks[2], vec![left]),
        ],
    );
    std::fs::write(&proof, &bytes).unwrap();
    std::fs::write(&commitment, doc_commit(9, &document)).unwrap();
    check(&run(&proof, &commitment, "0,2"), 0);
    for request in ["0", "0,1", "0,1,2"] {
        check(&run(&proof, &commitment, request), 8);
    }
    let mut damaged = bytes.clone();
    *damaged.last_mut().unwrap() ^= 1;
    std::fs::write(&proof, damaged).unwrap();
    check(&run(&proof, &commitment, "0,2"), 8);
    let mut trailing = bytes;
    trailing.push(0);
    std::fs::write(&proof, trailing).unwrap();
    check(&run(&proof, &commitment, "0,2"), 8);
}

#[test]
fn usage_io_anchor_and_proof_failures_keep_their_distinct_exit_classes() {
    let dir = directory();
    let proof = dir.join("proof.bin");
    let commitment = dir.join("commitment.bin");
    // Invalid requests fail before either nonexistent path is opened.
    for request in ["", "0,0", "2,0", "0,", "-1", "18446744073709551616"] {
        check(&run(&proof, &commitment, request), 2);
    }
    check(&run(&proof, &commitment, "0"), 5);
    std::fs::write(&proof, wire(1, 0, &[(0, &[], vec![])])).unwrap();
    for anchor in [
        vec![],
        vec![0; 31],
        vec![0; 33],
        vec![b'a'; 64],
        vec![0; 32],
    ] {
        std::fs::write(&commitment, anchor).unwrap();
        check(&run(&proof, &commitment, "0"), 8);
    }
    std::fs::write(&commitment, doc_commit(1, &[])).unwrap();
    check(&run(&proof, &commitment, "0"), 0);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&proof)
        .unwrap();
    file.set_len(MAX_PROOF_BYTES as u64 + 1).unwrap();
    check(&run(&proof, &commitment, "0"), 8);
}

#[cfg(unix)]
#[test]
fn non_utf8_proof_and_commitment_paths_remain_usable() {
    use std::os::unix::ffi::OsStringExt;
    let dir = directory();
    let proof = dir.join(std::ffi::OsString::from_vec(b"proof-\xff".to_vec()));
    let commitment = dir.join(std::ffi::OsString::from_vec(b"commitment-\xfe".to_vec()));
    std::fs::write(&proof, wire(1, 0, &[(0, &[], vec![])])).unwrap();
    std::fs::write(&commitment, doc_commit(1, &[])).unwrap();
    check(&run(&proof, &commitment, "0"), 0);
}
