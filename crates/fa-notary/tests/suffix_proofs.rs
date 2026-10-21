//! Complete suffix production into the independent retained-index verifier.
//! Synthetic journals bypass posting admission; these are proof/transport tests.

use fa_model::{
    Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, LegPayload, Oid, SealKey,
};
use fa_money::{Amount, Side, UnitId};
use fa_notary::checkpoint::{CheckpointBody, TransparencyCheckpoint};
use fa_notary::prefix::MAX_PREFIX_PROOF_BYTES;
use fa_notary::{Journal, ScopeIndex, SigningKey};
use fa_time::DateDay;
use fa_verify::checkpoint::witness::{RecipientWitnessPolicy, verify_witnessed_checkpoint};
use fa_verify::scope::payloads::incremental::IncrementalPayloadIndex;
use fa_verify::scope::payloads::{verify_payload_index, verify_scope_with_payload_index};
use fa_verify::{IndexDerivation, RecordCheck, ScopeClaim};
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0x42; 16]);

fn record(key: usize, day: i32) -> Entry {
    let legs = vec![
        LegPayload::simple(Side::Debit, VId(10), Amount::new(UnitId(1), 123)),
        LegPayload::simple(Side::Credit, VId(20), Amount::new(UnitId(1), 123)),
    ];
    EntryPayload {
        schema_minor: 1, book_id: BOOK, branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL, effective_date: DateDay(day), document_date: None,
        description: Erasable::seal(&"private suffix payload".to_string(), None,
            &SealKey([3; 32]), [1; 32], [2; 24]),
        effective_period: None, unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs, control: None, base_totals: None,
        idempotency_key: format!("suffix-{key}").into_bytes(),
        origin: EntryOrigin::Intent { intent_oid: Oid([4; 32]), intent_kind: 1 },
        principal_ref: VId(7), session_ref: None, evidence: vec![], supersession: vec![],
        pending: None, external_ids: vec![], extensions: vec![], tags: vec![],
    }.seal(vec![], None).unwrap()
}

fn journal(rows: &[(u64, i32)], through: u64) -> Journal {
    Journal::from_records(BOOK, CommitSeq(through), rows.iter().enumerate().map(|(i, (seq, day))| {
        (VId(100 + i as u128), record(i, *day), CommitSeq(*seq))
    }).collect()).unwrap()
}

fn signed(journal: &Journal) -> Vec<u8> {
    let publisher = SigningKey::from_seed(&[0x11; 32]);
    let a = SigningKey::from_seed(&[0x12; 32]);
    let b = SigningKey::from_seed(&[0x13; 32]);
    TransparencyCheckpoint::sign(CheckpointBody {
        statement: journal.statement(), state_oid: Oid([0x22; 32]),
        scope_index_root: ScopeIndex::of(journal).root(), substrate_chain_commitment: [0x44; 32],
        witness_policy_oid: Some(Oid([0x55; 32])), time_evidence_oid: None,
    }, &[&publisher, &a, &b]).unwrap().canonical_bytes().unwrap()
}

fn retained(journal: &Journal) -> IncrementalPayloadIndex {
    let publisher = SigningKey::from_seed(&[0x11; 32]);
    let a = SigningKey::from_seed(&[0x12; 32]);
    let b = SigningKey::from_seed(&[0x13; 32]);
    let policy = RecipientWitnessPolicy::new(BOOK.0, [0; 16], [0x55; 32],
        publisher.public_key(), &[a.public_key(), b.public_key()], 2).unwrap();
    let pin = verify_witnessed_checkpoint(&signed(journal), &policy).unwrap();
    IncrementalPayloadIndex::verify(&journal.prefix_proof_with_records().unwrap().unwrap(), &pin).unwrap()
}

#[test]
fn complete_suffix_is_byte_identical_to_existing_inclusions_and_matches_full_rebuild() {
    let old = journal(&[(7, 100)], 10);
    let state = retained(&old);
    let next = journal(&[(7, 100), (11, 200), (11, -10), (30, -20)], 30);
    let suffix = next.suffix_proofs_with_records(&old.statement(), MAX_PREFIX_PROOF_BYTES)
        .unwrap().unwrap();
    assert_eq!(suffix.previous(), &old.statement());
    assert_eq!(suffix.checkpoint(), &next.statement());
    assert_eq!(suffix.records().len(), 3);
    for (offset, proof) in suffix.records().iter().enumerate() {
        assert_eq!(*proof, next.inclusion_proof(VId(101 + offset as u128), true).unwrap().unwrap());
    }
    assert_eq!(suffix.consistency_proof(), next.consistency_proof(&old.statement()).unwrap().unwrap());
    let records: Vec<_> = suffix.records().iter().map(Vec::as_slice).collect();
    let advanced = state.advance(&signed(&next), suffix.consistency_proof(), &records).unwrap();
    let full = verify_payload_index(&next.prefix_proof_with_records().unwrap().unwrap(),
        advanced.checkpoint().signed_checkpoint()).unwrap();
    assert_eq!(advanced.index().root(), full.root());
    assert_eq!(advanced.index().tuple_count(), full.tuple_count());
    for (account, from, to, count) in [(10, -20, -10, 2), (20, 0, 99, 0), (99, -100, 300, 0)] {
        let range = ScopeIndex::of(&next).proof(&next, account, from, to).unwrap();
        let verified = verify_scope_with_payload_index(&range, advanced.checkpoint().signed_checkpoint(),
            &ScopeClaim { account, from, to }, advanced.index()).unwrap();
        assert_eq!(verified.index_derivation, IndexDerivation::Recomputed);
        assert_eq!(verified.leaves.len(), count);
    }
    assert_eq!(state.index().checkpoint().through_seq, 10);
}

#[test]
fn exact_aggregate_size_includes_consistency_and_every_record_frame() {
    let old = journal(&[(7, 10)], 7);
    let next = journal(&[(7, 10), (11, -1), (20, 30)], 20);
    let suffix = next.suffix_proofs_with_records(&old.statement(), MAX_PREFIX_PROOF_BYTES)
        .unwrap().unwrap();
    let size = suffix.consistency_proof().len() + suffix.records().iter().map(Vec::len).sum::<usize>();
    assert_eq!(suffix.encoded_bytes(), size);
    assert!(next.suffix_proofs_with_records(&old.statement(), size).unwrap().is_ok());
    assert!(next.suffix_proofs_with_records(&old.statement(), size - 1).unwrap().is_err());
    assert!(next.suffix_proofs_with_records(&old.statement(), MAX_PREFIX_PROOF_BYTES + 1)
        .unwrap().is_err());
}

#[test]
fn retained_boundary_refuses_backfills_same_commit_additions_and_hidden_future_records() {
    let old = journal(&[(7, 100)], 10);
    for rows in [vec![(7, 100), (8, -10)], vec![(7, 100), (10, -10)]] {
        let next = journal(&rows, 20);
        assert!(next.consistency_proof(&old.statement()).unwrap().is_some());
        assert!(next.suffix_proofs_with_records(&old.statement(), MAX_PREFIX_PROOF_BYTES)
            .unwrap().is_err());
    }
    let old = journal(&[(7, 100)], 7);
    let same_commit = journal(&[(7, 100), (7, -10)], 20);
    assert!(same_commit.suffix_proofs_with_records(&old.statement(), MAX_PREFIX_PROOF_BYTES)
        .unwrap().is_err());
    let next = journal(&[(7, 100), (11, -10)], 20);
    let mut false_boundary = old.statement();
    false_boundary.through_seq = CommitSeq(6);
    assert!(next.suffix_proofs_with_records(&false_boundary, MAX_PREFIX_PROOF_BYTES).unwrap().is_err());
}

#[test]
fn foreign_coordinates_forks_and_newer_retained_statements_refuse() {
    let old = journal(&[(7, 100)], 10);
    let next = journal(&[(7, 100), (11, -10)], 20);
    let good = old.statement();
    let mut wrong = good;
    wrong.book_id = Id128([0x43; 16]);
    assert!(next.suffix_proofs_with_records(&wrong, MAX_PREFIX_PROOF_BYTES).unwrap().is_err());
    wrong = good;
    wrong.branch_id = Id128([1; 16]);
    assert!(next.suffix_proofs_with_records(&wrong, MAX_PREFIX_PROOF_BYTES).unwrap().is_err());
    wrong = good;
    wrong.through_seq = CommitSeq(21);
    assert!(next.suffix_proofs_with_records(&wrong, MAX_PREFIX_PROOF_BYTES).unwrap().is_err());
    wrong = good;
    wrong.leaf_count = u64::MAX;
    assert!(next.suffix_proofs_with_records(&wrong, MAX_PREFIX_PROOF_BYTES).unwrap().is_err());
    let fork = journal(&[(7, 101), (11, -10)], 20);
    assert!(fork.suffix_proofs_with_records(&good, MAX_PREFIX_PROOF_BYTES).unwrap().is_err());
}

#[test]
fn empty_and_unchanged_histories_still_have_explicit_consistency() {
    for rows in [vec![], vec![(7, 100)]] {
        let old = journal(&rows, 10);
        let state = retained(&old);
        for through in [10, 20] {
            let next = journal(&rows, through);
            let suffix = next.suffix_proofs_with_records(&old.statement(), MAX_PREFIX_PROOF_BYTES)
                .unwrap().unwrap();
            assert!(suffix.records().is_empty());
            assert!(!suffix.consistency_proof().is_empty());
            let advanced = state.advance(&signed(&next), suffix.consistency_proof(), &[]).unwrap();
            assert_eq!(advanced.index().checkpoint().through_seq, through);
            assert!(next.suffix_proofs_with_records(&old.statement(), 0).unwrap().is_err());
        }
    }
}

#[test]
fn corrupted_last_payload_or_cached_envelope_never_returns_partial_transport() {
    let old = journal(&[(7, 100)], 7);
    let good = journal(&[(7, 100), (11, -10), (20, 40)], 20);
    for what in 0..5 {
        let mut corrupt = good.clone();
        match what {
            0 => { *corrupt.leaves[2].payload.last_mut().unwrap() ^= 1; }
            1 => { corrupt.leaves[2].proposal_len += 1; }
            2 => { corrupt.leaves[2].hash[0] ^= 1; }
            3 => { corrupt.leaves[0].envelope_bytes[0] ^= 1; }
            _ => { corrupt.leaves[2].envelope.record_digest[0] ^= 1; }
        }
        assert!(!matches!(corrupt.suffix_proofs_with_records(&old.statement(), MAX_PREFIX_PROOF_BYTES),
            Ok(Ok(_))), "accepted corruption {what}");
    }
    assert!(good.suffix_proofs_with_records(&old.statement(), MAX_PREFIX_PROOF_BYTES).unwrap().is_ok());
}

#[test]
fn exact_leaf_positions_do_not_depend_on_vertex_lookup_and_record_count_is_bounded() {
    let old = journal(&[(7, 100)], 7);
    let mut next = journal(&[(7, 100), (11, -10)], 11);
    // VID is not part of the proof transcript. A duplicate cached VID must not
    // make a suffix encoder accidentally return the first record's proof.
    next.leaves[1].vid = next.leaves[0].vid;
    let suffix = next.suffix_proofs_with_records(&old.statement(), MAX_PREFIX_PROOF_BYTES).unwrap().unwrap();
    let pin = retained(&next);
    let report = fa_verify::verify_inclusion(&suffix.records()[0],
        &pin.checkpoint().signed_checkpoint().checkpoint).unwrap();
    assert_eq!(report.leaf_index, 1);
    assert_eq!(report.record, RecordCheck::Recomputed);
    let many = journal(&vec![(11, 0); 4097], 11);
    let empty = journal(&[], 0);
    assert!(many.suffix_proofs_with_records(&empty.statement(), MAX_PREFIX_PROOF_BYTES).unwrap().is_err());
}

#[test]
fn zero_tuple_custody_leaves_are_exported_and_required_by_the_independent_verifier() {
    use fa_journal::custody::{CustodyBody, CustodyEvent};
    use fa_notary::Record;

    let old = journal(&[(7, 100)], 7);
    let state = retained(&old);
    let transfer = CustodyEvent {
        book_id: BOOK, document_oid: Oid([9; 32]), index: 1, prev_digest: [8; 32],
        body: CustodyBody::Transfer { from: VId(7), to: VId(8) },
    };
    let next = Journal::from_records_with_evidence(BOOK, CommitSeq(20), Some(CommitSeq(7)), vec![
        (VId(100), Record::from(record(0, 100)), CommitSeq(7)),
        (VId(101), Record::Custody(transfer), CommitSeq(11)),
        (VId(102), Record::from(record(2, -10)), CommitSeq(20)),
    ]).unwrap();
    let suffix = next.suffix_proofs_with_records(&old.statement(), MAX_PREFIX_PROOF_BYTES).unwrap().unwrap();
    assert_eq!(suffix.records().len(), 2);
    let records: Vec<_> = suffix.records().iter().map(Vec::as_slice).collect();
    let candidate = signed(&next);
    let advanced = state.advance(&candidate, suffix.consistency_proof(), &records).unwrap();
    assert_eq!(advanced.index().tuple_count(), 4);
    assert_eq!(advanced.index().checkpoint().leaf_count, 3);
    assert!(state.advance(&candidate, suffix.consistency_proof(), &records[1..]).is_err());
    let custody = fa_verify::verify_inclusion(records[0], advanced.index().checkpoint()).unwrap();
    assert_eq!(custody.envelope.kind, fa_notary::journal::KIND_CUSTODY_TRANSFER);
    assert!(custody.envelope.account_vids.is_empty());
    assert_eq!(custody.record, RecordCheck::Recomputed);
}
