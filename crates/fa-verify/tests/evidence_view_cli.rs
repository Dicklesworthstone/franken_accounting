//! Journal-authenticated kernel views, with compact-proof compatibility controls.
//! No producer dependency is imported: cross-implementation coverage stays
//! in fa-notary. These tests run the actual Cargo-built offline executable.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::Checkpoint;
use fa_verify::blake3::{hash_parts, hex};
use fa_verify::document::{DOC_CHUNK_BYTES, DOC_LEAF_DOMAIN, DOC_NODE_DOMAIN, doc_commit};
use fa_verify::envelope::{ENTRY_DIGEST_DOMAIN, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry};
use fa_verify::proof::INCLUSION_FORMAT;

const BOOK: [u8; 16] = [0x42; 16];
const SECRET: &[u8] = b"DO_NOT_ECHO_EVIDENCE_PAYLOAD";

// The independent test encoder writes only the existing v1 field layouts.
#[derive(Default)]
struct Wire(Vec<u8>);

impl Wire {
    fn fixed(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }
    fn u8(&mut self, value: u8) -> &mut Self {
        self.fixed(&[value])
    }
    fn u16(&mut self, value: u16) -> &mut Self {
        self.fixed(&value.to_le_bytes())
    }
    fn u32(&mut self, value: u32) -> &mut Self {
        self.fixed(&value.to_le_bytes())
    }
    fn u64(&mut self, value: u64) -> &mut Self {
        self.fixed(&value.to_le_bytes())
    }
    fn u128(&mut self, value: u128) -> &mut Self {
        self.fixed(&value.to_le_bytes())
    }
    fn i128(&mut self, value: i128) -> &mut Self {
        self.fixed(&value.to_le_bytes())
    }
    fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.u32(u32::try_from(bytes.len()).unwrap()).fixed(bytes)
    }
}

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-evidence-view-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
}

fn document_oid(commitment: &[u8; 32]) -> [u8; 32] {
    hash_parts(
        b"fa:oid:document:v1",
        &[
            &16u32.to_le_bytes(),
            &BOOK,
            &32u32.to_le_bytes(),
            commitment,
        ],
    )
}

fn entry_proof(doc: &[u8], include_payload: bool) -> (Vec<u8>, Checkpoint, [u8; 32]) {
    let commitment = doc_commit(1, doc);
    let mut p = Wire::default();
    p.u16(1)
        .u16(1)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u16(1)
        .fixed(&20_527i32.to_le_bytes())
        .u8(0)
        .fixed(&[0; 32])
        .u8(0)
        .fixed(&[0; 24])
        .bytes(&[]) // erasable description
        .u8(0)
        .u32(2); // no period; two legs
    for (side, account) in [(0, 10), (1, 20)] {
        p.u8(side)
            .u128(account)
            .u32(1)
            .i128(123)
            .u8(0)
            .u32(0)
            .u8(0)
            .u32(0);
    }
    p.u8(0)
        .u32(1)
        .u32(1)
        .i128(123)
        .i128(123)
        .u8(0)
        .bytes(b"offline-evidence")
        .u8(0)
        .fixed(&[9; 32])
        .u16(1)
        .u128(7)
        .u8(0)
        .u32(1)
        .fixed(&document_oid(&commitment))
        .fixed(&commitment)
        .u8(3)
        .u32(0)
        .u8(0)
        .u32(0)
        .u32(0)
        .u32(0);
    let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&p.0]);
    let entry_digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &[0; 5]]);
    let mut payload = p.0.clone();
    payload.extend_from_slice(&[0; 5]); // no certificate or approvals
    payload.extend_from_slice(&proposal_digest);
    payload.extend_from_slice(&entry_digest);
    let envelope = envelope_of_entry(&payload, p.0.len(), 7, 0)
        .unwrap()
        .encode();
    let checkpoint = Checkpoint {
        book_id: BOOK,
        branch_id: [0; 16],
        through_seq: 9,
        leaf_count: 1,
        root: fa_verify::tree::root_of(&[fa_verify::tree::leaf_hash(&envelope)]),
    };
    let mut proof = Wire::default();
    proof
        .bytes(INCLUSION_FORMAT)
        .fixed(&checkpoint.encode())
        .u64(0)
        .bytes(&envelope)
        .u8(u8::from(include_payload));
    if include_payload {
        proof.u32(u32::try_from(p.0.len()).unwrap()).bytes(&payload);
    }
    proof.u32(0); // singleton tree, no siblings
    (proof.0, checkpoint, entry_digest)
}

fn disclosure(doc: &[u8], shown: &[u64], compact: bool) -> Vec<u8> {
    let chunks: Vec<&[u8]> = if doc.is_empty() {
        vec![&[]]
    } else {
        doc.chunks(DOC_CHUNK_BYTES).collect()
    };
    let leaves: Vec<_> = chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            hash_parts(
                DOC_LEAF_DOMAIN,
                &[
                    &(index as u64).to_le_bytes(),
                    &(chunk.len() as u64).to_le_bytes(),
                    chunk,
                ],
            )
        })
        .collect();
    let commitment = doc_commit(1, doc);
    let mut w = Wire::default();
    if compact {
        w.bytes(fa_verify::disclosure::FORMAT)
            .u8(1)
            .u64(doc.len() as u64)
            .u32(u32::try_from(shown.len()).unwrap());
        for index in shown {
            let mut position = *index as usize;
            let mut level = leaves.clone();
            let mut siblings = Vec::new();
            while level.len() > 1 {
                if (position ^ 1) < level.len() {
                    siblings.push(level[position ^ 1]);
                }
                level = level
                    .chunks(2)
                    .map(|pair| {
                        if pair.len() == 1 {
                            pair[0]
                        } else {
                            hash_parts(DOC_NODE_DOMAIN, &[&pair[0], &pair[1]])
                        }
                    })
                    .collect();
                position /= 2;
            }
            w.u64(*index)
                .bytes(chunks[*index as usize])
                .u32(u32::try_from(siblings.len()).unwrap());
            for sibling in siblings {
                w.fixed(&sibling);
            }
        }
    } else {
        w.u16(1)
            .fixed(&document_oid(&commitment))
            .u16(7)
            .u8(1)
            .u64(doc.len() as u64)
            .fixed(&commitment)
            .u32(u32::try_from(chunks.len()).unwrap());
        for (index, chunk) in chunks.iter().enumerate() {
            if shown.contains(&(index as u64)) {
                w.u8(0).bytes(chunk);
            } else {
                w.u8(1).fixed(&leaves[index]);
            }
        }
    }
    w.0
}

struct Fixture {
    dir: PathBuf,
    doc: Vec<u8>,
    entry: Vec<u8>,
    checkpoint: Checkpoint,
    entry_digest: [u8; 32],
}

impl Fixture {
    fn new(length: usize) -> Self {
        let dir = directory();
        let doc: Vec<u8> = (0..length)
            .map(|index| SECRET[index % SECRET.len()])
            .collect();
        let (entry, checkpoint, entry_digest) = entry_proof(&doc, true);
        std::fs::write(dir.join("entry"), &entry).unwrap();
        std::fs::write(dir.join("checkpoint"), checkpoint.encode()).unwrap();
        Self {
            dir,
            doc,
            entry,
            checkpoint,
            entry_digest,
        }
    }

    fn args(&self, compact: bool, shown: &[u64]) -> Vec<OsString> {
        std::fs::write(
            self.dir.join("artifact"),
            disclosure(&self.doc, shown, compact),
        )
        .unwrap();
        let mut args: Vec<OsString> = ["document", "--entry-proof"].map(OsString::from).into();
        args.push(self.dir.join("entry").into_os_string());
        args.push("--checkpoint".into());
        args.push(self.dir.join("checkpoint").into_os_string());
        args.extend([
            "--expect-entry".into(),
            hex(&self.entry_digest).into(),
            "--expect-document".into(),
            hex(&document_oid(&doc_commit(1, &self.doc))).into(),
            "--expect-role".into(),
            "3".into(),
            "--chunks".into(),
            shown
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",")
                .into(),
            if compact {
                "--proof".into()
            } else {
                "--view".into()
            },
            self.dir.join("artifact").into_os_string(),
            "--json".into(),
        ]);
        args
    }
}

fn run(args: &[OsString]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .args(args)
        .output()
        .expect("execute offline binary")
}

fn result(output: Output, exit: i32) -> String {
    let out = String::from_utf8(output.stdout).unwrap();
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(exit), "{out}\n{err}");
    assert_eq!(out.lines().count(), 1, "one atomic JSON result: {out}");
    for text in [&out[..], &err[..]] {
        assert!(
            !text.contains(std::str::from_utf8(SECRET).unwrap()),
            "payload leak"
        );
        assert!(!text.contains(&hex(SECRET)), "hex payload leak");
    }
    if exit == 0 {
        assert!(err.is_empty(), "{err}");
        assert!(out.contains("\"event\":\"proof_verified\""));
        assert!(out.contains("\"proof_kind\":\"evidence_document\""));
        assert!(out.contains("\"entry\":\"inclusion\""));
        assert!(out.contains("\"disclosure\":\"membership_only\""));
        assert!(out.contains("\"signature_verification\":\"not_performed\""));
    } else {
        assert!(out.contains("\"event\":\"error\""));
        assert!(out.contains("\"verified\":false"));
        assert!(!out.contains("proof_verified"), "partial success: {out}");
    }
    out
}

fn replace(args: &mut [OsString], flag: &str, value: OsString) {
    let index = args.iter().position(|arg| arg == flag).unwrap();
    args[index + 1] = value;
}

#[test]
fn both_existing_formats_are_usable_from_the_binary_with_exact_scopes_and_no_payload_output() {
    for length in [0, 1, 4095, 4096, 4097, 8193] {
        let f = Fixture::new(length);
        let shown: Vec<_> = (0..length.div_ceil(4096).max(1))
            .step_by(2)
            .map(|i| i as u64)
            .collect();
        for compact in [false, true] {
            let args = f.args(compact, &shown);
            let before = std::fs::read(f.dir.join("artifact")).unwrap();
            let out = result(run(&args), 0);
            assert!(out.contains(&hex(&f.entry_digest)));
            assert!(out.contains(&format!("\"document_length_bytes\":\"{length}\"")));
            assert!(out.contains("\"recorded_at\":\"7\""));
            if !compact {
                assert!(out.contains("redacted_view_v1"));
            }
            assert_eq!(std::fs::read(f.dir.join("artifact")).unwrap(), before);
            assert_eq!(std::fs::read(f.dir.join("entry")).unwrap(), f.entry);
            assert_eq!(
                std::fs::read(f.dir.join("checkpoint")).unwrap(),
                f.checkpoint.encode()
            );
        }
    }
}

#[test]
fn wrong_recipient_questions_anchors_and_genuine_unrelated_artifacts_fail() {
    let f = Fixture::new(8193);
    for compact in [false, true] {
        let args = f.args(compact, &[0, 2]);
        result(run(&args), 0);
        for (flag, value) in [
            ("--expect-entry", "aa".repeat(32)),
            ("--expect-document", "bb".repeat(32)),
            ("--expect-role", "4".into()),
            ("--chunks", "0,1".into()),
            ("--chunks", "0".into()),
            ("--chunks", "0,1,2".into()),
        ] {
            let mut wrong = args.clone();
            replace(&mut wrong, flag, value.into());
            result(run(&wrong), 8);
        }
        let mut checkpoint = f.checkpoint;
        checkpoint.root[0] ^= 1;
        std::fs::write(f.dir.join("checkpoint"), checkpoint.encode()).unwrap();
        result(run(&args), 8);
        std::fs::write(f.dir.join("checkpoint"), f.checkpoint.encode()).unwrap();
        std::fs::write(f.dir.join("entry"), entry_proof(&f.doc, false).0).unwrap();
        result(run(&args), 8);
        std::fs::write(f.dir.join("entry"), &f.entry).unwrap();
        let unrelated = vec![42; 8193];
        std::fs::write(
            f.dir.join("artifact"),
            disclosure(&unrelated, &[0, 2], compact),
        )
        .unwrap();
        result(run(&args), 8);
    }
}

#[test]
fn malformed_or_over_budget_artifacts_never_emit_a_success_prefix() {
    let f = Fixture::new(8193);
    for compact in [false, true] {
        let args = f.args(compact, &[0, 2]);
        result(run(&args), 0);
        let good = std::fs::read(f.dir.join("artifact")).unwrap();
        for end in [0, 1, good.len() / 2, good.len() - 1] {
            std::fs::write(f.dir.join("artifact"), &good[..end]).unwrap();
            result(run(&args), 8);
        }
        let mut corrupt = good.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        std::fs::write(f.dir.join("artifact"), &corrupt).unwrap();
        result(run(&args), 8);
        let mut trailing = good.clone();
        trailing.push(0);
        std::fs::write(f.dir.join("artifact"), trailing).unwrap();
        result(run(&args), 8);
        std::fs::write(
            f.dir.join("artifact"),
            disclosure(&f.doc, &[0, 2], !compact),
        )
        .unwrap();
        result(run(&args), 8); // flags never guess/fallback to another format
        let limit = if compact {
            fa_verify::disclosure::MAX_PROOF_BYTES
        } else {
            fa_verify::redaction::MAX_VIEW_BYTES
        };
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(f.dir.join("artifact"))
            .unwrap();
        file.set_len(limit as u64 + 1).unwrap();
        result(run(&args), 8);
        std::fs::write(f.dir.join("artifact"), good).unwrap();
        for end in [0, 31, f.entry.len() - 1] {
            std::fs::write(f.dir.join("entry"), &f.entry[..end]).unwrap();
            result(run(&args), 8);
        }
        std::fs::write(f.dir.join("entry"), &f.entry).unwrap();
    }
}

#[test]
fn no_optional_anchor_fallback_and_usage_is_decided_before_missing_files() {
    let f = Fixture::new(1);
    let args = f.args(false, &[0]);
    for flag in [
        "--checkpoint",
        "--entry-proof",
        "--expect-entry",
        "--expect-document",
        "--expect-role",
        "--chunks",
    ] {
        let mut missing = args.clone();
        let index = missing.iter().position(|arg| arg == flag).unwrap();
        drop(missing.drain(index..index + 2));
        replace(
            &mut missing,
            "--view",
            f.dir.join("missing-artifact").into_os_string(),
        );
        result(run(&missing), 2);
    }
    for extra in [
        vec!["--document-commit", "other-anchor"],
        vec!["--proof", "other-proof"],
        vec!["--view", "other-view"],
        vec!["--json"],
    ] {
        let mut invalid = args.clone();
        invalid.extend(extra.into_iter().map(OsString::from));
        result(run(&invalid), 2);
    }
    let mut absent = args;
    replace(
        &mut absent,
        "--view",
        f.dir.join("missing-artifact").into_os_string(),
    );
    result(run(&absent), 5);
}

#[test]
fn human_output_and_command_help_expose_limits_without_echoing_bytes() {
    for words in [vec!["document", "--help"], vec!["document", "-h"]] {
        let out = run(&words.into_iter().map(OsString::from).collect::<Vec<_>>());
        assert_eq!(out.status.code(), Some(0));
        assert!(out.stderr.is_empty());
        assert!(String::from_utf8(out.stdout).unwrap().contains("evidence"));
    }
    let f = Fixture::new(8193);
    let mut args = f.args(false, &[0, 2]);
    assert_eq!(args.pop(), Some("--json".into()));
    let out = run(&args);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty());
    let out = String::from_utf8(out.stdout).unwrap();
    assert!(out.contains("scope: inclusion"));
    assert!(out.contains("scope: membership_only"));
    assert!(out.contains("production completeness were not checked"));
    assert!(!out.contains(std::str::from_utf8(SECRET).unwrap()));
    assert!(!out.contains(&hex(SECRET)));
}

#[cfg(unix)]
#[test]
fn binary_paths_remain_os_strings_but_recipient_scalars_must_be_ascii() {
    use std::os::unix::ffi::OsStringExt;
    let f = Fixture::new(1);
    let mut args = f.args(false, &[0]);
    for (flag, name) in [
        ("--view", "artifact"),
        ("--entry-proof", "entry"),
        ("--checkpoint", "checkpoint"),
    ] {
        let path = f.dir.join(OsString::from_vec(
            format!("{name}-").bytes().chain([255]).collect(),
        ));
        std::fs::copy(f.dir.join(name), &path).unwrap();
        replace(&mut args, flag, path.into_os_string());
    }
    result(run(&args), 0);
    replace(&mut args, "--expect-role", OsString::from_vec(vec![255]));
    result(run(&args), 2);
}

#[test]
fn the_view_locator_is_authenticated_but_its_contract_does_not_become_authority() {
    let f = Fixture::new(8193);
    let args = f.args(false, &[0, 2]);
    let good = std::fs::read(f.dir.join("artifact")).unwrap();
    let original = result(run(&args), 0);
    assert!(original.contains("authenticated_view_locator"));
    assert!(original.contains("\"contract\":7"));
    assert!(original.contains("not_authenticated_by_entry_or_document_commitment"));
    let mut wrong_locator = good.clone();
    // Version is u16; the following 32 bytes are the original document OID.
    wrong_locator[2] ^= 1;
    std::fs::write(f.dir.join("artifact"), wrong_locator).unwrap();
    let refused = result(run(&args), 8);
    assert!(refused.contains("different original locator"));

    let mut changed_contract = good;
    changed_contract[34..36].copy_from_slice(&99u16.to_le_bytes());
    std::fs::write(f.dir.join("artifact"), changed_contract).unwrap();
    let changed = result(run(&args), 0);
    assert!(changed.contains("\"contract\":99"));
    assert!(changed.contains("not_authenticated_by_entry_or_document_commitment"));
    assert!(changed.contains("computed_not_authenticated"));
    assert!(changed.contains("\"authorization\""));
    assert!(changed.contains("\"redaction_policy\""));
}
