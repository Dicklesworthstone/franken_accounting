//! Existing v3 balance exports as complete-prefix evidence in real CLI calls.
//! Synthetic canonical inputs, independently trusted anchors, no live books.

#[path = "fixtures/complete_balance.rs"]
mod fixture;

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::codec::Writer;
use fa_verify::proof::{Checkpoint, INCLUSION_FORMAT, PREFIX_FORMAT};

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-production-balance-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
}

fn u32_at(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
}

fn parts(bytes: &[u8], anchor: &Checkpoint) -> (Vec<u8>, Vec<u8>) {
    // The existing fixture has an unbounded day selector and exactly one
    // complete record. These offsets are asserted, not a production decoder.
    let mut at = 4 + u32_at(bytes, 0) + Checkpoint::ENCODED_LEN + 16 + 4 + 1 + 32;
    assert_eq!(u32_at(bytes, at), 1);
    at += 4;
    let len = u32_at(bytes, at);
    at += 4;
    let envelope = &bytes[at..at + len];
    at += len;
    assert_eq!(u32_at(bytes, at), 1);
    at += 4;
    assert_eq!(&bytes[at..at + 8], &0u64.to_le_bytes());
    at += 8;
    let split = u32_at(bytes, at);
    at += 4;
    let len = u32_at(bytes, at);
    at += 4;
    let payload = &bytes[at..at + len];
    let mut inclusion = Writer::default();
    inclusion
        .bytes(INCLUSION_FORMAT)
        .fixed(&anchor.encode())
        .u64(0)
        .bytes(envelope)
        .u8(1)
        .u32(u32::try_from(split).unwrap())
        .bytes(payload)
        .count(0);
    let mut legacy = Writer::default();
    legacy
        .bytes(PREFIX_FORMAT)
        .fixed(&anchor.encode())
        .count(1)
        .bytes(envelope);
    (inclusion.buf, legacy.buf)
}

fn run(
    prefix: &[u8],
    anchor: &Checkpoint,
    record: Option<&[u8]>,
    account: u128,
    documents: bool,
) -> Output {
    let dir = directory();
    fs::write(dir.join("prefix"), prefix).unwrap();
    fs::write(dir.join("anchor"), anchor.encode()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_fa-verify"));
    command.args(["evidence", "production"]);
    if documents {
        command.arg("documents");
    }
    command
        .arg("--prefix")
        .arg(dir.join("prefix"))
        .arg("--checkpoint")
        .arg(dir.join("anchor"))
        .args(["--expect-first-seq", "0", "--expect-known-at", "1"])
        .arg("--expect-account")
        .arg(format!("{account:032x}"))
        .args(["--expect-days", "20527:20527", "--json"]);
    if let Some(record) = record {
        fs::write(dir.join("record"), record).unwrap();
        command.arg("--record").arg(dir.join("record"));
    }
    command.output().expect("execute fa-verify")
}

fn result(output: Output, code: i32) -> String {
    let out = String::from_utf8(output.stdout).unwrap();
    let err = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(code), "{out}\n{err}");
    assert_eq!(out.lines().count(), 1, "{out}");
    if code == 0 {
        assert!(err.is_empty());
        assert!(out.contains("\"verified\":true"));
        assert!(out.contains("\"scope\":\"seq_range_complete\""));
    } else {
        assert!(out.contains("\"verified\":false"));
        assert!(!out.contains("proof_verified"));
        assert!(!out.contains("\"entries\":["));
    }
    out
}

#[test]
fn production_and_document_modes_reuse_the_same_complete_native_wire_contract() {
    let (bytes, anchor) = fixture::fixture();
    let (inclusion, _) = parts(&bytes, &anchor);
    for documents in [false, true] {
        // The balance was for cash 0x30; this independent production asks
        // about counterpart 0x20 and a different effective-date scope.
        let out = result(run(&bytes, &anchor, Some(&inclusion), 0x20, documents), 0);
        assert!(out.contains("\"entry_count\":1"));
        assert!(out.contains("\"citation_count\":0"));
        assert!(!out.contains(&fa_verify::blake3::hex(&bytes)));
        let empty = result(run(&bytes, &anchor, None, 99, documents), 0);
        assert!(empty.contains("\"entry_count\":0"));
        result(run(&bytes, &anchor, None, 0x20, documents), 8);
    }
}

#[test]
fn incomplete_legacy_and_invalid_balance_witnesses_fail_even_for_empty_requests() {
    let (bytes, anchor) = fixture::fixture();
    let (_, legacy) = parts(&bytes, &anchor);
    let credits = 4 + u32_at(&bytes, 0) + Checkpoint::ENCODED_LEN + 16 + 4 + 1 + 16;
    let mut wrong = bytes.clone();
    wrong[credits..credits + 16].copy_from_slice(&0i128.to_le_bytes());
    for documents in [false, true] {
        let out = result(run(&legacy, &anchor, None, 99, documents), 8);
        assert!(out.contains("unverified scope selectors"));
        result(run(&wrong, &anchor, None, 99, documents), 8);
        result(
            run(&bytes[..bytes.len() - 1], &anchor, None, 99, documents),
            8,
        );
        let mut other = anchor;
        other.root[0] ^= 1;
        result(run(&bytes, &other, None, 99, documents), 8);
    }
}
