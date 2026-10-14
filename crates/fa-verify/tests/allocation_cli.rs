//! Actual-process coverage for recipient-bound offline allocation verification.
//! The raw fixtures use no producer crate, book keys or running book.

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::Checkpoint;
use fa_verify::blake3::{hash_parts, hex};
use fa_verify::envelope::{ENTRY_DIGEST_DOMAIN, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry};
use fa_verify::evidence::inventory::allocation::{MAX_ALLOCATION_INPUT_BYTES, MAX_BASIS_BYTES};
use fa_verify::proof::INCLUSION_FORMAT;
use fa_verify::tree::leaf_hash;

const BOOK: [u8; 16] = [0x42; 16];
const SECRET: &[u8] = b"NEVER_PRINT_ALLOCATION_DESCRIPTION";
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct Wire(Vec<u8>);
impl Wire {
    fn raw(&mut self, value: &[u8]) -> &mut Self { self.0.extend_from_slice(value); self }
    fn u8(&mut self, value: u8) -> &mut Self { self.raw(&[value]) }
    fn u16(&mut self, value: u16) -> &mut Self { self.raw(&value.to_le_bytes()) }
    fn u32(&mut self, value: u32) -> &mut Self { self.raw(&value.to_le_bytes()) }
    fn u64(&mut self, value: u64) -> &mut Self { self.raw(&value.to_le_bytes()) }
    fn u128(&mut self, value: u128) -> &mut Self { self.raw(&value.to_le_bytes()) }
    fn i128(&mut self, value: i128) -> &mut Self { self.raw(&value.to_le_bytes()) }
    fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.u32(u32::try_from(value.len()).unwrap()).raw(value)
    }
}

struct Fixture {
    basis: Vec<u8>,
    proof: Vec<u8>,
    checkpoint: Checkpoint,
    digest: [u8; 32],
}

fn fixture(law: u16, total: i128, weights: &[u128], shares: &[i128], record: bool, seq: u64) -> Fixture {
    let mut req = Wire::default();
    req.raw(b"FA-ALLOC-REQUEST\0").u16(1).u16(0).u16(law).u16(1).u32(1).i128(total);
    if law == 2 { req.u16(6).u128(20); } // Ceiling, residual to target 20.
    req.u32(weights.len() as u32);
    for (i, weight) in weights.iter().enumerate() { req.u128(20 + i as u128).u128(*weight); }
    let mut b = Wire::default();
    b.raw(b"FA-ALLOC-BASIS\0").u16(1).u128(10).u8(0).u32(0).bytes(&req.0);
    let basis = b.0;
    assert!(basis.len() < 4096, "this fixture's document commitment is one chunk");
    let length = (basis.len() as u64).to_le_bytes();
    let leaf = hash_parts(b"fa:doc:leaf:v1", &[&0u64.to_le_bytes(), &length, &basis]);
    let commit = hash_parts(b"fa:doc:v1", &[&[21], &length, &leaf]);
    let oid = hash_parts(b"fa:oid:document:v1", &[
        &16u32.to_le_bytes(), &BOOK, &32u32.to_le_bytes(), &commit,
    ]);
    let law_digest = hash_parts(b"fa:allocation-law:v1", &[
        &2u32.to_le_bytes(), &law.to_le_bytes(), &2u32.to_le_bytes(), &1u16.to_le_bytes(),
    ]);
    let basis_digest = hash_parts(b"fa:allocation-basis:v1", &[&(basis.len() as u32).to_le_bytes(), &basis]);
    let mut p = Wire::default();
    p.u16(1).u16(2).raw(&BOOK).raw(&[0; 16]).u16(9).raw(&20_527i32.to_le_bytes()).u8(0)
        .raw(&[0; 32]).u8(0).raw(&[0; 24]).bytes(SECRET).u8(0)
        .u32(1 + shares.iter().filter(|share| **share != 0).count() as u32);
    let legs = core::iter::once((10, total, 0)).chain(
        shares.iter().enumerate().filter(|(_, share)| **share != 0)
            .map(|(i, share)| (20 + i as u128, share.checked_abs().unwrap(), u8::from(*share > 0))),
    );
    for (account, amount, side) in legs {
        p.u8(side).u128(account).u32(1).i128(amount).u8(0).u32(0).u8(0).u32(0);
    }
    let turnover: i128 = shares.iter().filter(|share| **share > 0).sum();
    p.u8(0).u32(1).u32(1).i128(turnover).i128(turnover).u8(0)
        .bytes(b"offline-allocation").u8(0).raw(&[9; 32]).u16(1).u128(7).u8(0)
        .u32(1).raw(&oid).raw(&commit).u8(1).u32(0).u8(0).u32(0).u32(0).u32(1).u16(5);
    let mut extension = Wire::default();
    extension.raw(b"FA-ALLOC-POST\0").u16(1).bytes(&basis).raw(&law_digest).raw(&basis_digest);
    p.bytes(&extension.0);
    let pd = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&p.0]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&pd, &[0; 5]]);
    let proposal_len = p.0.len();
    p.raw(&[0; 5]).raw(&pd).raw(&digest);
    let envelope = envelope_of_entry(&p.0, proposal_len, seq, 0).unwrap().encode();
    let checkpoint = Checkpoint { book_id: BOOK, branch_id: [0; 16], through_seq: seq,
        leaf_count: 1, root: leaf_hash(&envelope) };
    let mut proof = Wire::default();
    proof.bytes(INCLUSION_FORMAT).raw(&checkpoint.encode()).u64(0).bytes(&envelope).u8(u8::from(record));
    if record { proof.u32(proposal_len as u32).bytes(&p.0); }
    proof.u32(0);
    Fixture { basis, proof: proof.0, checkpoint, digest }
}

struct Files { dir: PathBuf, args: Vec<OsString> }
impl Files {
    fn new(f: &Fixture) -> Self {
        let dir = std::env::temp_dir().join(format!("fa-allocation-cli-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&dir).unwrap(); // Never reuse or overwrite an existing directory.
        fs::write(dir.join("proof"), &f.proof).unwrap();
        fs::write(dir.join("checkpoint"), f.checkpoint.encode()).unwrap();
        fs::write(dir.join("basis"), &f.basis).unwrap();
        let args = vec!["evidence".into(), "allocation".into(), "--proof".into(), dir.join("proof").into(),
            "--checkpoint".into(), dir.join("checkpoint").into(), "--expect-entry".into(), hex(&f.digest).into(),
            "--expect-basis".into(), dir.join("basis").into(), "--json".into()];
        Self { dir, args }
    }
    fn run(&self) -> Output { run(&self.args) }
}
impl Drop for Files {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.dir); }
}
fn run(args: &[OsString]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fa-verify")).args(args).output().unwrap()
}
fn text(out: &Output) -> String { String::from_utf8(out.stdout.clone()).unwrap() }
fn code(out: &Output, expected: i32) {
    assert_eq!(out.status.code(), Some(expected), "stdout={} stderr={}", text(out), String::from_utf8_lossy(&out.stderr));
}

#[test]
fn actual_binary_verifies_all_four_laws_and_keeps_zero_and_negative_shares() {
    for (law, total, weights, shares) in [
        (1, 10_000, vec![1, 1, 1], vec![3334, 3333, 3333]),
        (2, 1, vec![1, 1, 1], vec![-1, 1, 1]),
        (3, 10, vec![4, 0, 9], vec![4, 0, 6]),
        (5, 2, vec![1; 5], vec![2, 0, 0, 0, 0]),
    ] {
        let f = fixture(law, total, &weights, &shares, true, 7);
        let files = Files::new(&f);
        let out = files.run(); code(&out, 0);
        let output = text(&out);
        assert_eq!(output.lines().count(), 1);
        assert!(output.contains("\"proof_kind\":\"allocation\""));
        assert!(output.contains("\"request_check\":\"entry_and_exact_driver\""));
        for share in &shares { assert!(output.contains(&format!("\"signed_share\":\"{share}\""))); }
        assert_eq!(output.matches("\"signed_share\"").count(), shares.len());
        if shares.contains(&0) { assert!(output.contains("\"posting_side\":null")); }
        assert!(!output.contains(std::str::from_utf8(SECRET).unwrap()));
        assert!(!output.contains("\"basis\":"));
        assert!(!output.contains("\"weights\":"));
        assert!(output.contains("\"driver_provenance\""));
        assert!(out.stderr.is_empty());
    }
}

#[test]
fn large_native_mantissas_and_sequence_numbers_are_exact_decimal_strings() {
    let total = i128::MAX;
    let shares = [total / 2 + 1, total / 2];
    let files = Files::new(&fixture(1, total, &[1, 1], &shares, true, u64::MAX));
    let out = files.run(); code(&out, 0);
    let output = text(&out);
    assert!(output.contains(&format!("\"total_mantissa\":\"{total}\"")));
    assert!(output.contains(&format!("\"recorded_at\":\"{}\"", u64::MAX)));
    for share in shares { assert!(output.contains(&format!("\"signed_share\":\"{share}\""))); }
}

#[test]
fn balanced_but_wrong_rehashed_entry_and_same_result_driver_substitutions_fail() {
    let wrong = Files::new(&fixture(1, 100, &[1, 1], &[49, 51], true, 7));
    let out = wrong.run(); code(&out, 8);
    assert!(!text(&out).contains("\"targets\""));
    let f = fixture(1, 100, &[1, 1], &[50, 50], true, 7);
    let files = Files::new(&f);
    let other = fixture(1, 100, &[2, 2], &[50, 50], true, 7);
    fs::write(files.dir.join("basis"), &other.basis).unwrap();
    let out = files.run(); code(&out, 8);
    assert!(!text(&out).contains("\"verified\":true"));
    fs::write(files.dir.join("basis"), &f.basis).unwrap();
    let mut args = files.args.clone(); args[7] = "00".repeat(32).into();
    code(&run(&args), 8);
}

#[test]
fn missing_record_and_truncated_files_never_emit_success() {
    let files = Files::new(&fixture(1, 7, &[1, 1], &[4, 3], false, 7));
    code(&files.run(), 8);
    let f = fixture(1, 7, &[1, 1], &[4, 3], true, 7);
    let files = Files::new(&f);
    fs::write(files.dir.join("proof"), &f.proof[..f.proof.len() - 1]).unwrap();
    code(&files.run(), 8);
    fs::write(files.dir.join("proof"), &f.proof).unwrap();
    fs::write(files.dir.join("basis"), &f.basis[..f.basis.len() - 1]).unwrap();
    code(&files.run(), 8);
}

#[test]
fn all_required_options_and_invalid_arguments_are_checked_before_io() {
    let files = Files::new(&fixture(1, 7, &[1, 1], &[4, 3], true, 7));
    let mut base = files.args.clone();
    for (index, name) in [(3, "missing-proof"), (5, "missing-checkpoint"), (9, "missing-basis")] {
        base[index] = files.dir.join(name).into();
    }
    for pair in [2usize, 4, 6, 8] {
        let mut args = base.clone(); args.drain(pair..pair + 2); code(&run(&args), 2);
    }
    for extra in [vec!["--json"], vec!["--proof", "other"], vec!["--expect-citation", "other"], vec!["unexpected"]] {
        let mut args = base.clone(); args.extend(extra.into_iter().map(OsString::from)); code(&run(&args), 2);
    }
    let mut invalid = base.clone(); invalid[7] = "λ".repeat(32).into(); code(&run(&invalid), 2);
    // The fully valid invocation finally reaches I/O and reports a missing file.
    code(&run(&base), 5);
}

#[test]
fn driver_and_combined_proof_budgets_are_enforced_at_the_file_boundary() {
    let f = fixture(1, 7, &[1, 1], &[4, 3], true, 7);
    let files = Files::new(&f);
    let file = fs::File::create(files.dir.join("basis")).unwrap();
    file.set_len((MAX_BASIS_BYTES + 1) as u64).unwrap(); drop(file);
    code(&files.run(), 8);
    fs::write(files.dir.join("basis"), &f.basis).unwrap();
    let file = fs::File::create(files.dir.join("proof")).unwrap();
    file.set_len((MAX_ALLOCATION_INPUT_BYTES - f.basis.len() + 1) as u64).unwrap(); drop(file);
    let out = files.run(); code(&out, 8);
    assert!(text(&out).contains("input exceeds"));
    assert!(!text(&out).contains("\"targets\""));
}

#[test]
fn help_and_human_output_explain_scope_without_claiming_accounting_admission() {
    let out = run(&["evidence".into(), "allocation".into(), "--help".into()]); code(&out, 0);
    assert!(text(&out).contains("--expect-basis"));
    assert!(text(&out).contains("does NOT verify"));
    let mut files = Files::new(&fixture(1, 7, &[1, 1], &[4, 3], true, 7));
    files.args.pop();
    let out = files.run(); code(&out, 0);
    assert!(text(&out).contains("Verified allocation:"));
    assert!(text(&out).contains("signed_share 4 posting Credit"));
    assert!(!text(&out).contains(std::str::from_utf8(SECRET).unwrap()));
}

#[cfg(unix)]
#[test]
fn non_utf8_driver_and_proof_filenames_are_not_mistaken_for_invalid_selectors() {
    use std::os::unix::ffi::OsStringExt;
    let f = fixture(1, 7, &[1, 1], &[4, 3], true, 7);
    let mut files = Files::new(&f);
    let proof = files.dir.join(OsString::from_vec(b"proof-\xff".to_vec()));
    let basis = files.dir.join(OsString::from_vec(b"basis-\xfe".to_vec()));
    fs::write(&proof, &f.proof).unwrap(); fs::write(&basis, &f.basis).unwrap();
    files.args[3] = proof.into(); files.args[9] = basis.into();
    code(&files.run(), 0);
}
