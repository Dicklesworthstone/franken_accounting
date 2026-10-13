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
            "fa-document-disclosure-cli-{}-{index}", std::process::id()
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
        .arg("document").arg("--proof").arg(proof)
        .arg("--document-commit").arg(commitment)
        .args(["--chunks", chunks, "--json"])
        .output().expect("run actual offline verifier")
}

fn check(output: &Output, exit: i32) -> String {
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(exit), "{stdout}\n{stderr}");
    assert_eq!(stdout.lines().count(), 1, "exactly one complete result: {stdout}");
    if exit == 0 {
        assert!(stderr.is_empty(), "{stderr}");
        assert!(stdout.contains("\"event\":\"proof_verified\""), "{stdout}");
        assert!(stdout.contains("\"scope\":\"membership_only\""), "{stdout}");
    } else {
        assert!(stdout.contains("\"event\":\"error\""), "{stdout}");
        assert!(stdout.contains("\"verified\":false"), "{stdout}");
        assert!(!stdout.contains("proof_verified"), "no partial success: {stdout}");
    }
    stdout
}

#[test]
fn document_command_verifies_a_raw_export_without_echoing_disclosed_content() {
    let dir = directory();
    let proof = dir.join("proof.bin");
    let commitment = dir.join("commitment.bin");
    let content = b"DO_NOT_ECHO_DISCLOSED_SOURCE_CONTENT";
    std::fs::write(&proof, wire(18, content.len() as u64, &[(0, content, vec![])])).unwrap();
    std::fs::write(&commitment, doc_commit(18, content)).unwrap();
    let stdout = check(&run(&proof, &commitment, "0"), 0);
    assert!(stdout.contains("\"proof_kind\":\"document\""));
    assert!(stdout.contains("operator_trusted_document_commitment"));
    assert!(stdout.contains("\"index\":\"0\""));
    assert!(!stdout.contains(std::str::from_utf8(content).unwrap()));
    assert!(!stdout.contains(&fa_verify::blake3::hex(content)));
    let human = Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .arg("document").arg("--proof").arg(&proof)
        .arg("--document-commit").arg(&commitment).args(["--chunks", "0"])
        .output().unwrap();
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
    let leaves: Vec<_> = chunks.iter().enumerate().map(|(i, chunk)| {
        hash_parts(DOC_LEAF_DOMAIN, &[&(i as u64).to_le_bytes(), &(chunk.len() as u64).to_le_bytes(), chunk])
    }).collect();
    let left = hash_parts(DOC_NODE_DOMAIN, &[&leaves[0], &leaves[1]]);
    let bytes = wire(9, document.len() as u64, &[
        (0, &chunks[0], vec![leaves[1], leaves[2]]),
        (2, &chunks[2], vec![left]),
    ]);
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
    for anchor in [vec![], vec![0; 31], vec![0; 33], vec![b'a'; 64], vec![0; 32]] {
        std::fs::write(&commitment, anchor).unwrap();
        check(&run(&proof, &commitment, "0"), 8);
    }
    std::fs::write(&commitment, doc_commit(1, &[])).unwrap();
    check(&run(&proof, &commitment, "0"), 0);
    let file = std::fs::OpenOptions::new().write(true).open(&proof).unwrap();
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

// Entry/citation framing is independent of the producer. Actual model and
// Journal encodings are covered by fa-notary/tests/evidence_view_interop.rs.
// These fixtures exercise the process boundary, not kernel admission laws.
struct CitedDocument {
    entry_proof: Vec<u8>,
    checkpoint: fa_verify::Checkpoint,
    expected: fa_verify::EvidenceExpectation,
}

fn cited_document(commitment: [u8; 32], minor: u16, include_record: bool) -> CitedDocument {
    use fa_verify::codec::Writer;
    use fa_verify::envelope::{ENTRY_DIGEST_DOMAIN, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry};
    use fa_verify::proof::INCLUSION_FORMAT;

    let book = [0x42; 16];
    let oid = hash_parts(b"fa:oid:document:v1", &[
        &16u32.to_le_bytes(), &book, &32u32.to_le_bytes(), &commitment,
    ]);
    let mut w = Writer::default();
    w.u16(1).u16(minor).fixed(&book).fixed(&[0; 16]).u16(1).i32(20_527).u8(0);
    // Sealed description framing. It does not feed any disclosed metadata.
    w.fixed(&[0; 32]).u8(0).fixed(&[0; 24]).bytes(&[]).u8(0).count(2);
    for (side, account) in [(0, 10), (1, 20)] {
        w.u8(side).u128(account).u32(1).i128(123).u8(0).count(0).u8(0).count(0);
    }
    w.u8(0).count(1).u32(1).i128(123).i128(123).u8(0).bytes(b"cli-evidence")
        .u8(0).fixed(&[9; 32]).u16(1).u128(7).u8(0)
        .count(1).fixed(&oid).fixed(&commitment).u8(3)
        .count(0).u8(0).count(0).count(0);
    if minor >= 1 { w.count(0); }
    let proposal = w.buf;
    let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&proposal]);
    let mut w = Writer::default();
    w.u8(1).fixed(&[0x55; 32]).count(1).u128(88).fixed(&proposal_digest);
    let entry_envelope = w.buf;
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &entry_envelope]);
    let mut payload = proposal.clone();
    payload.extend_from_slice(&entry_envelope);
    payload.extend_from_slice(&proposal_digest);
    payload.extend_from_slice(&digest);
    let envelope = envelope_of_entry(&payload, proposal.len(), 7, 0).unwrap().encode();
    let checkpoint = fa_verify::Checkpoint {
        book_id: book, branch_id: [0; 16], through_seq: 11, leaf_count: 1,
        root: fa_verify::tree::leaf_hash(&envelope),
    };
    let mut w = Writer::default();
    w.bytes(INCLUSION_FORMAT).fixed(&checkpoint.encode()).u64(0).bytes(&envelope)
        .u8(u8::from(include_record));
    if include_record {
        w.u32(u32::try_from(proposal.len()).unwrap()).bytes(&payload);
    }
    w.count(0);
    CitedDocument {
        entry_proof: w.buf,
        checkpoint,
        expected: fa_verify::EvidenceExpectation { entry_digest: digest, document_oid: oid, role: 3 },
    }
}

fn compact_document(doc: &[u8], requested: &[usize]) -> Vec<u8> {
    let chunks: Vec<_> = if doc.is_empty() { vec![&[][..]] } else { doc.chunks(4096).collect() };
    let leaves: Vec<_> = chunks.iter().enumerate().map(|(i, chunk)| {
        hash_parts(DOC_LEAF_DOMAIN, &[
            &(i as u64).to_le_bytes(), &(chunk.len() as u64).to_le_bytes(), chunk,
        ])
    }).collect();
    let mut proofs = Vec::new();
    for index in requested {
        let (mut level, mut position, mut path) = (leaves.clone(), *index, Vec::new());
        while level.len() > 1 {
            if let Some(sibling) = level.get(position ^ 1) { path.push(*sibling); }
            level = level.chunks(2).map(|pair| match pair {
                [left, right] => hash_parts(DOC_NODE_DOMAIN, &[left, right]),
                _ => pair[0],
            }).collect();
            position /= 2;
        }
        proofs.push((*index as u64, chunks[*index], path));
    }
    wire(1, doc.len() as u64, &proofs)
}

fn install_citation(dir: &Path, citation: &CitedDocument, disclosure: &[u8]) {
    std::fs::write(dir.join("entry.bin"), &citation.entry_proof).unwrap();
    std::fs::write(dir.join("checkpoint.bin"), citation.checkpoint.encode()).unwrap();
    std::fs::write(dir.join("disclosure.bin"), disclosure).unwrap();
}

fn evidence_command(dir: &Path, expected: &fa_verify::EvidenceExpectation, chunks: &str, json: bool) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fa-verify"));
    command.arg("document")
        .arg("--proof").arg(dir.join("disclosure.bin"))
        .arg("--entry-proof").arg(dir.join("entry.bin"))
        .arg("--checkpoint").arg(dir.join("checkpoint.bin"))
        .arg("--expect-entry").arg(fa_verify::blake3::hex(&expected.entry_digest))
        .arg("--expect-document").arg(fa_verify::blake3::hex(&expected.document_oid))
        .arg("--expect-role").arg(expected.role.to_string())
        .args(["--chunks", chunks]);
    if json { command.arg("--json"); }
    command
}

fn check_evidence(dir: &Path, expected: &fa_verify::EvidenceExpectation, chunks: &str, exit: i32) -> String {
    check(&evidence_command(dir, expected, chunks, true).output().unwrap(), exit)
}

#[test]
fn cited_document_cli_verifies_the_whole_chain_with_separate_scopes_and_no_payload_output() {
    for minor in [0, 1] {
        for length in [0, 35, 4096, 8193, 20_481] {
            let dir = directory();
            let doc: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
            let last = doc.len().saturating_sub(1) / 4096;
            let compact = compact_document(&doc, &[last]);
            let citation = cited_document(doc_commit(1, &doc), minor, true);
            install_citation(&dir, &citation, &compact);
            let request = last.to_string();
            let stdout = check_evidence(&dir, &citation.expected, &request, 0);
            for required in [
                "\"proof_kind\":\"evidence_document\"", "operator_trusted_checkpoint",
                "\"scopes\":{\"entry\":\"inclusion\",\"disclosure\":\"membership_only\"}",
                "\"record_check\":\"recomputed\"", "requested_document_and_role",
                "\"signature_verification\":\"not_performed\"", "citation_role_truth",
                "redaction_policy", "production_completeness",
            ] { assert!(stdout.contains(required), "{stdout}"); }
            // Repeated invocations produce identical metadata bytes.
            assert_eq!(stdout, check_evidence(&dir, &citation.expected, &request, 0));
        }
    }
    let dir = directory();
    let secret = b"PRIVATE_EVIDENCE_MUST_NEVER_REACH_STDOUT";
    let citation = cited_document(doc_commit(1, secret), 1, true);
    install_citation(&dir, &citation, &compact_document(secret, &[0]));
    for json in [false, true] {
        let output = evidence_command(&dir, &citation.expected, "0", json).output().unwrap();
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(!stdout.contains(std::str::from_utf8(secret).unwrap()));
        assert!(!stdout.contains(&fa_verify::blake3::hex(secret)));
        assert!(stdout.contains("inclusion") && stdout.contains("membership_only"));
    }
}

#[test]
fn valid_but_unrelated_artifacts_or_recipient_questions_cannot_be_composed_by_the_cli() {
    let dir = directory();
    let doc = vec![17; 8193];
    let good = compact_document(&doc, &[2]);
    let citation = cited_document(doc_commit(1, &doc), 1, true);
    install_citation(&dir, &citation, &good);
    check_evidence(&dir, &citation.expected, "2", 0);
    let mut wrong_entry = citation.expected;
    wrong_entry.entry_digest[0] ^= 1;
    let mut wrong_document = citation.expected;
    wrong_document.document_oid[0] ^= 1;
    let mut wrong_role = citation.expected;
    wrong_role.role = 4;
    for wrong in [wrong_entry, wrong_document, wrong_role] {
        check_evidence(&dir, &wrong, "2", 8);
    }
    for request in ["0", "0,2", "1,2"] {
        check_evidence(&dir, &citation.expected, request, 8);
    }
    std::fs::write(dir.join("disclosure.bin"), compact_document(&vec![18; 8193], &[2])).unwrap();
    check_evidence(&dir, &citation.expected, "2", 8);
    std::fs::write(dir.join("disclosure.bin"), &good).unwrap();
    let no_record = cited_document(doc_commit(1, &doc), 1, false);
    std::fs::write(dir.join("entry.bin"), no_record.entry_proof).unwrap();
    let failure = check_evidence(&dir, &citation.expected, "2", 8);
    assert!(failure.contains("requires the entry payload"));
}

#[test]
fn malformed_later_artifact_bytes_and_each_input_size_bound_fail_without_partial_success() {
    let dir = directory();
    let doc = vec![19; 8193];
    let compact = compact_document(&doc, &[0, 2]);
    let citation = cited_document(doc_commit(1, &doc), 1, true);
    install_citation(&dir, &citation, &compact);
    for (path, bytes, maximum) in [
        ("checkpoint.bin", citation.checkpoint.encode(), 80usize),
        ("entry.bin", citation.entry_proof.clone(), MAX_PROOF_BYTES),
        ("disclosure.bin", compact.clone(), MAX_PROOF_BYTES),
    ] {
        for end in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            std::fs::write(dir.join(path), &bytes[..end]).unwrap();
            check_evidence(&dir, &citation.expected, "0,2", 8);
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        std::fs::write(dir.join(path), trailing).unwrap();
        check_evidence(&dir, &citation.expected, "0,2", 8);
        let mut altered = bytes.clone();
        *altered.last_mut().unwrap() ^= 1;
        std::fs::write(dir.join(path), altered).unwrap();
        check_evidence(&dir, &citation.expected, "0,2", 8);
        let oversized = std::fs::OpenOptions::new().write(true).open(dir.join(path)).unwrap();
        oversized.set_len(maximum as u64 + 1).unwrap();
        check_evidence(&dir, &citation.expected, "0,2", 8);
        drop(oversized);
        std::fs::write(dir.join(path), bytes).unwrap();
    }
    check_evidence(&dir, &citation.expected, "0,2", 0);
}

#[test]
fn incomplete_or_mixed_anchor_modes_fail_as_usage_before_missing_input_files() {
    let dir = directory();
    let citation = cited_document(doc_commit(1, &[]), 1, true);
    // Syntactically correct invocation reaches I/O; invalid invocations do not.
    check_evidence(&dir, &citation.expected, "0", 5);
    for extra in [
        vec!["--document-commit", "absent"], vec!["--json"],
        vec!["--expect-role", "3"], vec!["--checkpoint", "absent"],
        vec!["--next-checkpoint", "absent"], vec!["--bogus"],
    ] {
        let output = evidence_command(&dir, &citation.expected, "0", true).args(extra).output().unwrap();
        check(&output, 2);
    }
    for chunks in ["", "0,0", "2,0", "0,", "-1", "18446744073709551616"] {
        check_evidence(&dir, &citation.expected, chunks, 2);
    }
    // Every one of the five journal options is mandatory, even with --json.
    let base = evidence_command(&dir, &citation.expected, "0", true);
    let args: Vec<_> = base.get_args().map(|arg| arg.to_os_string()).collect();
    for name in ["--entry-proof", "--checkpoint", "--expect-entry", "--expect-document", "--expect-role"] {
        let mut missing = args.clone();
        let index = missing.iter().position(|arg| arg == name).unwrap();
        drop(missing.drain(index..index + 2));
        let output = Command::new(env!("CARGO_BIN_EXE_fa-verify")).args(missing).output().unwrap();
        check(&output, 2);
    }
}

#[test]
fn sparse_authenticated_chunk_indexes_and_lengths_are_not_truncated_in_json() {
    use fa_verify::document::DOC_DOMAIN;
    // u64::MAX bytes has 2^52 chunks: the last has 4095 bytes and 52 siblings.
    // No giant file is allocated; this is a membership predicate only.
    let size = u64::MAX;
    let index = size.div_ceil(4096) - 1;
    let chunk = vec![42; 4095];
    let siblings = vec![[7; 32]; 52];
    let mut root = hash_parts(DOC_LEAF_DOMAIN, &[
        &index.to_le_bytes(), &(chunk.len() as u64).to_le_bytes(), &chunk,
    ]);
    for sibling in &siblings { root = hash_parts(DOC_NODE_DOMAIN, &[sibling, &root]); }
    let commitment = hash_parts(DOC_DOMAIN, &[&[1], &size.to_le_bytes(), &root]);
    let citation = cited_document(commitment, 1, true);
    let dir = directory();
    install_citation(&dir, &citation, &wire(1, size, &[(index, &chunk, siblings)]));
    let stdout = check_evidence(&dir, &citation.expected, &index.to_string(), 0);
    assert!(stdout.contains("\"document_length_bytes\":\"18446744073709551615\""));
    assert!(stdout.contains("\"index\":\"4503599627370495\""));
    assert!(stdout.contains("\"byte_length\":4095"));
}

#[cfg(unix)]
#[test]
fn journal_authenticated_mode_accepts_non_utf8_paths_without_lossy_conversion() {
    use std::os::unix::ffi::OsStringExt;
    let dir = directory().join(std::ffi::OsString::from_vec(b"evidence-\xff".to_vec()));
    std::fs::create_dir(&dir).unwrap();
    let citation = cited_document(doc_commit(1, &[]), 1, true);
    install_citation(&dir, &citation, &compact_document(&[], &[0]));
    check_evidence(&dir, &citation.expected, "0", 0);
}

#[test]
fn document_help_explains_independent_expectations_and_does_not_open_a_book() {
    let output = Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .args(["document", "--help"]).output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    for required in ["--entry-proof", "--checkpoint", "--expect-entry", "--expect-document", "--expect-role",
        "All five options are required together", "membership_only", "No book, keys or network"] {
        assert!(text.contains(required), "{text}");
    }
}
