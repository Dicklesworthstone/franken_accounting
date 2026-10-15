//! Native full-prefix export, independently consumed without balance semantics.
//! Model-encoded journals test the proof contract, not kernel admission.

use fa_model::{ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin, Id128, Oid};
use fa_notary::prefix::{MAX_PREFIX_LEAVES, PREFIX_FORMAT_V2};
use fa_notary::{AccumulatorState, Journal, code};
use fa_time::DateDay;
use fa_verify::proof::production::derivation::verify_prefix_with_records;
use fa_verify::proof::production::{ProductionScope, verify_production_for};
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0x5a; 16]);

fn u32_at(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
}

fn entry() -> Entry {
    // Preserve the frozen v1 vectors. Extract a genuine producer payload,
    // then build a separately anchored journal for these new-format tests.
    let text = include_str!("../../fa-verify/tests/fixtures/accumulator_v1.txt")
        .lines()
        .find_map(|line| line.strip_prefix("inclusion "))
        .unwrap();
    let bytes: Vec<_> = (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect();
    let mut at = 4 + u32_at(&bytes, 0) + 80 + 8;
    at += 4 + u32_at(&bytes, at);
    assert_eq!(bytes[at], 1);
    at += 5; // present tag and proposal split
    let length = u32_at(&bytes, at);
    Entry::decode(&bytes[at + 4..at + 4 + length]).unwrap()
}

fn schema_control() -> Entry {
    let mut proposal = entry().proposal;
    proposal.class = EntryClass::SCHEMA_CONTROL;
    proposal.legs.clear();
    proposal.unit_totals.clear();
    proposal.control = Some(ControlPayload::SchemaChange {
        kind: 1,
        canonical_bytes: vec![1, 2, 3],
    });
    proposal.origin = EntryOrigin::Control {
        control_kind: ControlKind::CHART_INSTALL,
        spec_body_digest: [9; 32],
    };
    proposal.idempotency_key = b"prefix-chart".to_vec();
    proposal.seal(Vec::new(), None).unwrap()
}

fn staged() -> Entry {
    let mut proposal = entry().proposal;
    proposal.class = EntryClass::MIGRATION;
    proposal.effective_date = DateDay(20_526);
    proposal.origin = EntryOrigin::Migration {
        run_ref: VId(42),
        source_system: "legacy".into(),
        source_id: proposal.description.clone(),
        source_recorded_at_ns: None,
        source_entered_by: None,
        source_approved_by: None,
        batch_oid: Oid([8; 32]),
    };
    proposal.idempotency_key = b"staged-prefix-entry".to_vec();
    proposal.seal(Vec::new(), None).unwrap()
}

fn history() -> Journal {
    let mut future = entry().proposal;
    future.effective_date = DateDay(20_528);
    future.idempotency_key = b"future-prefix-entry".to_vec();
    Journal::from_records(
        BOOK,
        CommitSeq(5),
        vec![
            (VId(1), schema_control(), CommitSeq(1)),
            (VId(2), entry(), CommitSeq(2)),
            (VId(3), staged(), CommitSeq(3)),
            (VId(4), future.seal(Vec::new(), None).unwrap(), CommitSeq(3)),
        ],
    )
    .unwrap()
}

fn anchor(journal: &Journal) -> fa_verify::Checkpoint {
    let state = AccumulatorState::of_journal(journal, None);
    fa_verify::verify_state(&state.canonical_bytes().unwrap())
        .unwrap()
        .checkpoint
}

#[test]
fn native_prefixes_support_empty_and_control_only_books_without_an_account_or_unit() {
    for rows in [vec![], vec![(VId(1), schema_control(), CommitSeq(1))]] {
        let journal = Journal::from_records(BOOK, CommitSeq(1), rows).unwrap();
        let old = journal.prefix_proof().unwrap();
        let proof = journal.prefix_proof_with_records().unwrap().unwrap();
        assert_eq!(&proof[4..4 + PREFIX_FORMAT_V2.len()], PREFIX_FORMAT_V2);
        let verified = verify_prefix_with_records(&proof, &anchor(&journal)).unwrap();
        assert_eq!(verified.envelopes.len(), journal.leaves.len());
        assert_eq!(verified.scope, "seq_range_complete");
        assert_eq!(proof, journal.prefix_proof_with_records().unwrap().unwrap());
        assert_eq!(old, journal.prefix_proof().unwrap());
        assert_eq!(
            fa_verify::verify_prefix(&old, &anchor(&journal))
                .unwrap()
                .envelopes,
            verified.envelopes
        );
    }
}

#[test]
fn staged_migrations_and_future_entries_are_records_not_a_balance_visibility_claim() {
    let journal = history();
    let before = journal.clone();
    let proof = journal.prefix_proof_with_records().unwrap().unwrap();
    let checkpoint = anchor(&journal);
    let prefix = verify_prefix_with_records(&proof, &checkpoint).unwrap();
    assert_eq!(prefix.envelopes.len(), 4);
    assert_eq!(prefix.envelopes[0].effective_day, None);
    assert_eq!(prefix.envelopes[2].class, EntryClass::MIGRATION.0);
    assert_eq!(prefix.envelopes[3].position(), (3, 1));
    // The unrelated missing run body blocks this balance proof, but must not
    // block authentication of the complete journal's existing entry bytes.
    assert!(
        journal
            .balance_proof_complete(VId(0x30), 1, None, &[])
            .unwrap()
            .is_err()
    );
    let requested = ProductionScope {
        first_seq: 0,
        known_at: 5,
        account: Some(0x30),
        effective_days: Some((20_527, 20_527)),
    };
    let inclusion = journal.inclusion_proof(VId(2), true).unwrap().unwrap();
    let production = verify_production_for(&proof, &[&inclusion], &checkpoint, &requested).unwrap();
    assert_eq!(production.entries.len(), 1);
    assert_eq!(production.entries[0].leaf_index, 1);
    assert!(verify_production_for(&proof, &[], &checkpoint, &requested).is_err());
    let empty = ProductionScope {
        account: Some(999),
        ..requested
    };
    assert!(
        verify_production_for(&proof, &[], &checkpoint, &empty)
            .unwrap()
            .entries
            .is_empty()
    );
    assert_eq!(journal, before);
}

#[test]
fn public_journal_fields_cannot_rebind_or_silently_drop_prefix_records() {
    for field in 0..8 {
        let mut journal = history();
        match field {
            0 => journal.leaves[0].envelope.account_vids = vec![VId(99)],
            1 => journal.leaves[0].proposal_len = usize::MAX,
            2 => journal.leaves[0].hash[0] ^= 1,
            3 => journal.leaves[0].envelope_bytes[0] ^= 1,
            4 => journal.leaves[0].envelope.commit_seq = CommitSeq(6),
            5 => {
                journal.leaves.swap(0, 1);
            }
            6 => {
                assert!(journal.leaves.pop().is_some());
            }
            _ => journal.leaves[0].envelope.book_id = Id128([7; 16]),
        }
        let refusal = journal.prefix_proof_with_records().unwrap().unwrap_err();
        assert_eq!(refusal.code, code::ACCUMULATOR_DRIFT, "field {field}");
    }
    let mut journal = history();
    *journal.leaves[1].payload.last_mut().unwrap() ^= 1;
    assert!(journal.prefix_proof_with_records().is_err());
}

#[test]
fn payload_and_leaf_limits_fail_before_attempting_to_decode_oversized_inputs() {
    let mut journal = history();
    journal.leaves[0].payload.resize(8 * 1024 * 1024 + 1, 0);
    assert_eq!(
        journal
            .prefix_proof_with_records()
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-127"
    );
    let mut journal = history();
    let mut leaf = journal.leaves[0].clone();
    leaf.payload.clear();
    leaf.envelope_bytes.clear();
    journal.leaves = vec![leaf; MAX_PREFIX_LEAVES + 1];
    assert_eq!(
        journal
            .prefix_proof_with_records()
            .unwrap()
            .unwrap_err()
            .code,
        "FA-REF-127"
    );
}

#[test]
fn framing_is_exact_and_the_independently_trusted_coordinate_is_load_bearing() {
    let journal = history();
    let proof = journal.prefix_proof_with_records().unwrap().unwrap();
    let checkpoint = anchor(&journal);
    let expected_size = 4
        + PREFIX_FORMAT_V2.len()
        + 80
        + 8
        + journal
            .leaves
            .iter()
            .map(|leaf| 4 + leaf.envelope_bytes.len() + 16 + leaf.payload.len())
            .sum::<usize>();
    assert_eq!(proof.len(), expected_size);
    for end in [0, 4, proof.len() / 2, proof.len() - 1] {
        assert!(verify_prefix_with_records(&proof[..end], &checkpoint).is_err());
    }
    let mut trailing = proof.clone();
    trailing.push(0);
    assert!(verify_prefix_with_records(&trailing, &checkpoint).is_err());
    let mut wrong = checkpoint;
    wrong.through_seq += 1;
    assert!(matches!(
        verify_prefix_with_records(&proof, &wrong),
        Err(fa_verify::VerifyError::NotTrusted { .. })
    ));
}
