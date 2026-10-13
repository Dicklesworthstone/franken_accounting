//! Verifier-side containment of legacy migration claims (fa-e00).
//!
//! These are record/proof-level adversarial fixtures, not a native migration
//! lifecycle simulation. They deliberately assemble the proof independently
//! of fa-notary, whose refusal must not be the outsider's safety boundary.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::balance::{BALANCE_FORMAT, CLASS_MIGRATION};
use fa_verify::blake3::hash_parts;
use fa_verify::envelope::{
    ENTRY_DIGEST_DOMAIN, PROPOSAL_DIGEST_DOMAIN, check_record, envelope_of_entry,
};
use fa_verify::proof::{INCLUSION_FORMAT, PREFIX_FORMAT};
use fa_verify::tree::leaf_hash;
use fa_verify::{
    BalanceClaim, Checkpoint, LeafEnvelope, RecordCheck, VerifyError, verify_balance,
    verify_inclusion, verify_prefix,
};

fn take<'a>(input: &mut &'a [u8], size: usize) -> &'a [u8] {
    let (value, rest) = input.split_at(size);
    *input = rest;
    value
}

fn u32_value(input: &mut &[u8]) -> u32 {
    u32::from_le_bytes(take(input, 4).try_into().unwrap())
}

fn bytes<'a>(input: &mut &'a [u8]) -> &'a [u8] {
    let size = usize::try_from(u32_value(input)).unwrap();
    take(input, size)
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
    out.extend_from_slice(value);
}

struct Fixture {
    envelope: LeafEnvelope,
    payload: Vec<u8>,
    proposal_len: usize,
    checkpoint: Checkpoint,
}

impl Fixture {
    fn new(class: u16) -> Self {
        let hex = include_str!("fixtures/accumulator_v1.txt")
            .lines()
            .find_map(|line| line.strip_prefix("inclusion "))
            .unwrap();
        let original: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let mut input = original.as_slice();
        assert_eq!(bytes(&mut input), INCLUSION_FORMAT);
        let checkpoint = Checkpoint::decode(take(&mut input, Checkpoint::ENCODED_LEN)).unwrap();
        assert_eq!(
            verify_inclusion(&original, &checkpoint).unwrap().record,
            RecordCheck::Recomputed,
            "the unmodified producer fixture is valid"
        );
        let _leaf_index = take(&mut input, 8);
        let original_envelope = LeafEnvelope::decode(bytes(&mut input)).unwrap();
        assert_eq!(take(&mut input, 1), &[1]);
        let proposal_len = usize::try_from(u32_value(&mut input)).unwrap();
        let mut payload = bytes(&mut input).to_vec();
        assert_eq!(original_envelope.class, 1);
        // schema_major/minor (4), book (16), branch (16), then class u16.
        assert_eq!(&payload[36..38], &1u16.to_le_bytes());
        payload[36..38].copy_from_slice(&class.to_le_bytes());
        let end = payload.len();
        let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&payload[..proposal_len]]);
        let record_digest = hash_parts(
            ENTRY_DIGEST_DOMAIN,
            &[&proposal_digest, &payload[proposal_len..end - 64]],
        );
        payload[end - 64..end - 32].copy_from_slice(&proposal_digest);
        payload[end - 32..].copy_from_slice(&record_digest);
        let envelope = envelope_of_entry(&payload, proposal_len, 5, 0).unwrap();
        let legs = check_record(&envelope, &payload, proposal_len).unwrap();
        let cash: Vec<_> = legs
            .iter()
            .filter(|leg| leg.account == 0x30 && leg.unit == 1)
            .collect();
        assert_eq!(cash.len(), 1);
        assert!(!cash[0].debit);
        assert_eq!(cash[0].mantissa, 550);
        let checkpoint = Checkpoint {
            book_id: envelope.book_id,
            branch_id: envelope.branch_id,
            through_seq: 5,
            leaf_count: 1,
            root: leaf_hash(&envelope.encode()),
        };
        Self {
            envelope,
            payload,
            proposal_len,
            checkpoint,
        }
    }

    fn header(&self, format: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_bytes(&mut out, format);
        out.extend_from_slice(&self.checkpoint.encode());
        out
    }

    fn prefix(&self) -> Vec<u8> {
        let mut out = self.header(PREFIX_FORMAT);
        out.extend_from_slice(&1u32.to_le_bytes());
        put_bytes(&mut out, &self.envelope.encode());
        out
    }

    fn inclusion(&self) -> Vec<u8> {
        let mut out = self.header(INCLUSION_FORMAT);
        out.extend_from_slice(&0u64.to_le_bytes());
        put_bytes(&mut out, &self.envelope.encode());
        out.push(1);
        out.extend_from_slice(&u32::try_from(self.proposal_len).unwrap().to_le_bytes());
        put_bytes(&mut out, &self.payload);
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    fn balance(&self, claim: BalanceClaim, include_record: bool) -> Vec<u8> {
        let mut out = self.header(BALANCE_FORMAT);
        out.extend_from_slice(&claim.account.to_le_bytes());
        out.extend_from_slice(&claim.unit.to_le_bytes());
        match claim.effective_through {
            Some(day) => {
                out.push(1);
                out.extend_from_slice(&day.to_le_bytes());
            }
            None => out.push(0),
        }
        out.extend_from_slice(&claim.debits.to_le_bytes());
        out.extend_from_slice(&claim.credits.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        put_bytes(&mut out, &self.envelope.encode());
        let count = if include_record { 1u32 } else { 0 };
        out.extend_from_slice(&count.to_le_bytes());
        if include_record {
            out.extend_from_slice(&0u64.to_le_bytes());
            out.extend_from_slice(&u32::try_from(self.proposal_len).unwrap().to_le_bytes());
            put_bytes(&mut out, &self.payload);
        }
        out
    }
}

fn cash_claim() -> BalanceClaim {
    BalanceClaim {
        account: 0x30,
        unit: 1,
        effective_through: None,
        debits: 0,
        credits: 550,
    }
}

#[test]
fn ordinary_v1_amounts_still_verify_with_exact_record_recomputation() {
    let fixture = Fixture::new(1);
    let report = verify_balance(&fixture.balance(cash_claim(), true), &fixture.checkpoint).unwrap();
    assert_eq!(report.claim, cash_claim());
    assert_eq!(report.contributing, vec![0]);
    let wrong = BalanceClaim {
        credits: 551,
        ..cash_claim()
    };
    assert_eq!(
        verify_balance(&fixture.balance(wrong, true), &fixture.checkpoint),
        Err(VerifyError::Claim {
            debits: 0,
            credits: 550,
        })
    );
}

#[test]
fn authenticated_migration_inclusion_does_not_prove_posted_visibility() {
    let fixture = Fixture::new(CLASS_MIGRATION);
    assert_eq!(
        verify_prefix(&fixture.prefix(), &fixture.checkpoint)
            .unwrap()
            .envelopes
            .len(),
        1
    );
    assert_eq!(
        verify_inclusion(&fixture.inclusion(), &fixture.checkpoint)
            .unwrap()
            .record,
        RecordCheck::Recomputed
    );
    // All preexisting cryptographic and record-set checks pass. Removing
    // only the visibility guard admits this claim in the legacy verifier.
    let error =
        verify_balance(&fixture.balance(cash_claim(), true), &fixture.checkpoint).unwrap_err();
    assert_eq!(error, VerifyError::MigrationVisibility { index: 0 });
    assert!(error.to_string().contains("authenticated lifecycle"));
}

#[test]
fn omitting_migration_payload_or_claiming_zero_cannot_hide_the_candidate() {
    let fixture = Fixture::new(CLASS_MIGRATION);
    for include_record in [false, true] {
        for credits in [0, 550] {
            let claim = BalanceClaim {
                credits,
                ..cash_claim()
            };
            assert_eq!(
                verify_balance(&fixture.balance(claim, include_record), &fixture.checkpoint),
                Err(VerifyError::MigrationVisibility { index: 0 })
            );
        }
    }
}

#[test]
fn unrelated_accounts_units_and_earlier_cutoffs_remain_provable() {
    let fixture = Fixture::new(CLASS_MIGRATION);
    let empty = BalanceClaim {
        credits: 0,
        ..cash_claim()
    };
    for claim in [
        BalanceClaim {
            account: 0x99,
            ..empty
        },
        BalanceClaim { unit: 99, ..empty },
        BalanceClaim {
            effective_through: Some(20_526),
            ..empty
        },
    ] {
        let result = verify_balance(&fixture.balance(claim, false), &fixture.checkpoint).unwrap();
        assert_eq!(result.claim, claim);
        assert!(result.contributing.is_empty());
    }
    let at_boundary = BalanceClaim {
        effective_through: Some(20_527),
        ..cash_claim()
    };
    assert_eq!(
        verify_balance(&fixture.balance(at_boundary, true), &fixture.checkpoint),
        Err(VerifyError::MigrationVisibility { index: 0 })
    );
}

#[test]
fn prefix_authentication_precedes_the_visibility_diagnostic() {
    let mut fixture = Fixture::new(CLASS_MIGRATION);
    fixture.checkpoint.root[0] ^= 1;
    assert_eq!(
        verify_balance(&fixture.balance(cash_claim(), true), &fixture.checkpoint),
        Err(VerifyError::Root)
    );
}

fn retained_directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fa-verify-migration-{}-{id}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create {}: {error}", path.display()),
        }
    }
}

#[test]
fn standalone_binary_refuses_the_assembled_claim_without_a_success_event() {
    let fixture = Fixture::new(CLASS_MIGRATION);
    let dir = retained_directory();
    let proof = dir.join("migration.proof");
    let checkpoint = dir.join("trusted.checkpoint");
    std::fs::write(&proof, fixture.balance(cash_claim(), true)).unwrap();
    std::fs::write(&checkpoint, fixture.checkpoint.encode()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .arg("balance")
        .arg("--proof")
        .arg(&proof)
        .arg("--checkpoint")
        .arg(&checkpoint)
        .arg("--json")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(output.status.code(), Some(8), "{stdout}\n{stderr}");
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(stdout.contains("\"verified\":false"), "{stdout}");
    assert!(stdout.contains("migration visibility"), "{stdout}");
    assert!(!stdout.contains("\"verified\":true"), "{stdout}");
}
