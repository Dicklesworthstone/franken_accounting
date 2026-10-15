//! Real Notary v3 output reused as production evidence, not another exporter.
//! Model-encoded journals test interoperability, not kernel admission.

use fa_model::{Entry, Id128};
use fa_notary::{AccumulatorState, Journal};
use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};
use fa_verify::proof::production::{ProductionError, ProductionScope, verify_production_for};
use fa_verify::proof::production::derivation::verify_prefix_with_records;

fn u32_at(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
}

fn source_entry() -> Entry {
    // Preserve the frozen producer vector. Extract its genuine model payload,
    // then build a new independently anchored journal; never reuse its root.
    let text = include_str!("../../fa-verify/tests/fixtures/accumulator_v1.txt")
        .lines().find_map(|line| line.strip_prefix("inclusion ")).unwrap();
    let bytes: Vec<_> = (0..text.len()).step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap()).collect();
    let mut at = 4 + u32_at(&bytes, 0) + 80 + 8;
    at += 4 + u32_at(&bytes, at);
    assert_eq!(bytes[at], 1);
    at += 1;
    let split = u32_at(&bytes, at);
    at += 4;
    let length = u32_at(&bytes, at);
    at += 4;
    let entry = Entry::decode(&bytes[at..at + length]).unwrap();
    assert_eq!(entry.proposal.canonical_bytes().unwrap().len(), split);
    entry
}

fn journal() -> Journal {
    let first = source_entry();
    let mut later = first.proposal.clone();
    later.effective_date = DateDay(20_528);
    later.idempotency_key = b"later-production-entry".to_vec();
    Journal::from_records(Id128([0x5a; 16]), CommitSeq(2), vec![
        (VId(1), first, CommitSeq(1)),
        (VId(2), later.seal(Vec::new(), None).unwrap(), CommitSeq(2)),
    ]).unwrap()
}

fn scope() -> ProductionScope {
    // Different account AND effective scope from the balance witness.
    ProductionScope { first_seq: 0, known_at: 2,
        account: Some(0x20), effective_days: Some((20_528, 20_528)) }
}

#[test]
fn native_balance_witness_proves_an_independently_requested_extract() {
    let journal = journal();
    let state = AccumulatorState::of_journal(&journal, None);
    let checkpoint = fa_verify::verify_state(&state.canonical_bytes().unwrap()).unwrap().checkpoint;
    let witness = journal.balance_proof_complete(VId(0x30), 1, Some(20_527), &[]).unwrap().unwrap();
    let prefix = verify_prefix_with_records(&witness, &checkpoint).unwrap();
    assert_eq!(prefix.envelopes.len(), 2);
    let selected = journal.inclusion_proof(VId(2), true).unwrap().unwrap();
    let report = verify_production_for(&witness, &[&selected], &checkpoint, &scope()).unwrap();
    assert_eq!(report.scope, "seq_range_complete");
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].leaf_index, 1);
    assert_eq!(report.entries[0].envelope.record_digest, journal.leaves[1].envelope.record_digest);
    assert!(verify_production_for(&witness, &[], &checkpoint, &scope()).is_err());
    assert!(verify_production_for(&witness, &[&selected, &selected], &checkpoint, &scope()).is_err());
    let inventory = fa_verify::evidence::inventory::production::verify_evidence_production_for(
        &witness, &[&selected], &checkpoint, &scope()).unwrap();
    assert_eq!(inventory.entries[0].entry, report.entries[0]);
    assert_eq!(AccumulatorState::of_journal(&journal, None), state);
}

#[test]
fn reuse_verifies_the_whole_balance_not_just_a_parseable_prefix() {
    let journal = journal();
    let state = AccumulatorState::of_journal(&journal, None);
    let checkpoint = fa_verify::verify_state(&state.canonical_bytes().unwrap()).unwrap().checkpoint;
    let mut witness = journal.balance_proof_complete(VId(0x30), 1, Some(20_527), &[]).unwrap().unwrap();
    let empty = ProductionScope { account: Some(999), ..scope() };
    assert!(verify_production_for(&witness, &[], &checkpoint, &empty).unwrap().entries.is_empty());
    let credits = 4 + fa_verify::migration_balance::BALANCE_FORMAT_V3.len() + 80 + 16 + 4 + 5 + 16;
    witness[credits..credits + 16].copy_from_slice(&0i128.to_le_bytes());
    assert!(matches!(verify_production_for(&witness, &[], &checkpoint, &empty),
        Err(ProductionError::Prefix(fa_verify::VerifyError::Claim { .. }))));
    let legacy = journal.balance_proof(VId(0x30), 1, Some(20_527)).unwrap().unwrap();
    assert!(verify_prefix_with_records(&legacy, &checkpoint).is_err());
}
