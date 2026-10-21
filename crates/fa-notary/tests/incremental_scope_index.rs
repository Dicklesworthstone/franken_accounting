//! Actual Notary encoders/signers against the independent incremental verifier.
//! Pure journals bypass posting admission: this is not an accounting-law test.

use fa_model::{
    Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, LegPayload, Oid, SealKey,
};
use fa_money::{Amount, Side, UnitId};
use fa_notary::checkpoint::{CheckpointBody, TransparencyCheckpoint};
use fa_notary::{Journal, ScopeIndex, SigningKey};
use fa_time::DateDay;
use fa_verify::checkpoint::witness::{
    RecipientWitnessPolicy, WitnessedCheckpoint, verify_witnessed_checkpoint,
};
use fa_verify::scope::payloads::incremental::{IncrementalPayloadIndex, IndexAdvanceError};
use fa_verify::scope::payloads::{PayloadIndexError, verify_payload_index, verify_scope_with_payload_index};
use fa_verify::{IndexDerivation, ScopeClaim};
use fgdb_types::{CommitSeq, VId};

const BOOK: Id128 = Id128([0x42; 16]);

fn record(key: &str, day: i32) -> Entry {
    let legs = vec![
        LegPayload::simple(Side::Debit, VId(10), Amount::new(UnitId(1), 123)),
        LegPayload::simple(Side::Credit, VId(20), Amount::new(UnitId(1), 123)),
    ];
    EntryPayload {
        schema_minor: 1, book_id: BOOK, branch_id: Id128::TRUNK,
        class: EntryClass::ORIGINAL, effective_date: DateDay(day), document_date: None,
        description: Erasable::seal(&"private source".to_string(), None,
            &SealKey([3; 32]), [1; 32], [2; 24]),
        effective_period: None, unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs, control: None, base_totals: None, idempotency_key: key.as_bytes().to_vec(),
        origin: EntryOrigin::Intent { intent_oid: Oid([4; 32]), intent_kind: 1 },
        principal_ref: VId(7), session_ref: None, evidence: vec![], supersession: vec![],
        pending: None, external_ids: vec![], extensions: vec![], tags: vec![],
    }.seal(vec![], None).unwrap()
}

fn journal(entries: &[(u64, i32)], through: u64) -> Journal {
    Journal::from_records(BOOK, CommitSeq(through), entries.iter().enumerate()
        .map(|(i, (sequence, day))| (VId(100 + i as u128),
            record(&format!("entry-{i}"), *day), CommitSeq(*sequence)))
        .collect()).unwrap()
}

fn signed(journal: &Journal, root: [u8; 32], publisher_only: bool) -> Vec<u8> {
    let publisher = SigningKey::from_seed(&[0x11; 32]);
    let a = SigningKey::from_seed(&[0x12; 32]);
    let b = SigningKey::from_seed(&[0x13; 32]);
    let body = CheckpointBody {
        statement: journal.statement(), state_oid: Oid([0x22; 32]), scope_index_root: root,
        substrate_chain_commitment: [0x44; 32], witness_policy_oid: Some(Oid([0x55; 32])),
        time_evidence_oid: None,
    };
    let checkpoint = if publisher_only {
        TransparencyCheckpoint::sign(body, &[&publisher])
    } else {
        TransparencyCheckpoint::sign(body, &[&publisher, &a, &b])
    }.unwrap();
    checkpoint.canonical_bytes().unwrap()
}

fn pin(bytes: &[u8]) -> WitnessedCheckpoint {
    let publisher = SigningKey::from_seed(&[0x11; 32]);
    let a = SigningKey::from_seed(&[0x12; 32]);
    let b = SigningKey::from_seed(&[0x13; 32]);
    let policy = RecipientWitnessPolicy::new(BOOK.0, [0; 16], [0x55; 32],
        publisher.public_key(), &[a.public_key(), b.public_key()], 2).unwrap();
    verify_witnessed_checkpoint(bytes, &policy).unwrap()
}

fn baseline(journal: &Journal) -> (IncrementalPayloadIndex, Vec<u8>) {
    let bytes = signed(journal, ScopeIndex::of(journal).root(), false);
    let prefix = journal.prefix_proof_with_records().unwrap().unwrap();
    (IncrementalPayloadIndex::verify(&prefix, &pin(&bytes)).unwrap(), bytes)
}

fn suffix(journal: &Journal, from: usize) -> Vec<Vec<u8>> {
    journal.leaves.iter().skip(from)
        .map(|leaf| journal.inclusion_proof(leaf.vid, true).unwrap().unwrap()).collect()
}

fn slices(proofs: &[Vec<u8>]) -> Vec<&[u8]> {
    proofs.iter().map(Vec::as_slice).collect()
}

#[test]
fn genuine_producer_deltas_match_full_rebuilds_and_reuse_exact_range_checks() {
    let old = journal(&[(7, 100)], 7);
    let (state, _) = baseline(&old);
    let next = journal(&[(7, 100), (11, 200), (30, -10)], 30);
    let candidate = signed(&next, ScopeIndex::of(&next).root(), false);
    let consistency = next.consistency_proof(&old.statement()).unwrap().unwrap();
    let proofs = suffix(&next, 1);
    let advanced = state.advance(&candidate, &consistency, &slices(&proofs)).unwrap();
    let full = next.prefix_proof_with_records().unwrap().unwrap();
    let rebuilt = verify_payload_index(&full, advanced.checkpoint().signed_checkpoint()).unwrap();
    assert_eq!(advanced.index().root(), rebuilt.root());
    assert_eq!(advanced.index().tuple_count(), rebuilt.tuple_count());
    assert_eq!(advanced.index().checkpoint(), rebuilt.checkpoint());
    assert_eq!(advanced.index().encoded_bytes(), state.index().encoded_bytes()
        + candidate.len() + consistency.len() + proofs.iter().map(Vec::len).sum::<usize>());
    assert_eq!(state.index().checkpoint().through_seq, 7);
    for (account, from, to, count) in [(10, -10, -10, 1), (20, 0, 99, 0), (99, i32::MIN, i32::MAX, 0)] {
        let proof = ScopeIndex::of(&next).proof(&next, account, from, to).unwrap();
        let report = verify_scope_with_payload_index(&proof, advanced.checkpoint().signed_checkpoint(),
            &ScopeClaim { account, from, to }, advanced.index()).unwrap();
        assert_eq!(report.index_derivation, IndexDerivation::Recomputed);
        assert_eq!(report.leaves.len(), count);
    }
    let later = journal(&[(7, 100), (11, 200), (30, -10), (40, -20)], 40);
    let further = advanced.advance(&signed(&later, ScopeIndex::of(&later).root(), false),
        &later.consistency_proof(&next.statement()).unwrap().unwrap(), &slices(&suffix(&later, 3))).unwrap();
    assert_eq!(*further.index().root(), ScopeIndex::of(&later).root());
    assert_eq!(further.index().tuple_count(), 8);
}

#[test]
fn genuine_signatures_do_not_excuse_missing_records_or_an_inconsistent_new_index() {
    let old = journal(&[(7, 100)], 7);
    let (state, _) = baseline(&old);
    let next = journal(&[(7, 100), (30, -10)], 30);
    let consistency = next.consistency_proof(&old.statement()).unwrap().unwrap();
    let candidate = signed(&next, ScopeIndex::of(&next).root(), false);
    assert!(matches!(state.advance(&candidate, &consistency, &[]),
        Err(IndexAdvanceError::RecordCount { expected: 1, actual: 0 })));
    let bare = next.inclusion_proof(VId(101), false).unwrap().unwrap();
    assert!(matches!(state.advance(&candidate, &consistency, &[&bare]),
        Err(IndexAdvanceError::PayloadRequired { leaf_index: 1 })));
    let wrong_index = signed(&next, ScopeIndex::of(&old).root(), false);
    assert!(matches!(state.advance(&wrong_index, &consistency, &slices(&suffix(&next, 1))),
        Err(IndexAdvanceError::Derivation(PayloadIndexError::Root))));
    assert_eq!(*state.index().root(), ScopeIndex::of(&old).root());
    assert!(state.advance(&candidate, &consistency, &slices(&suffix(&next, 1))).is_ok());
}

#[test]
fn retained_quorum_and_consistency_cannot_be_replaced_with_publisher_only_or_forked_history() {
    let old = journal(&[(7, 100)], 7);
    let (state, _) = baseline(&old);
    let next = journal(&[(7, 100), (30, -10)], 30);
    let consistency = next.consistency_proof(&old.statement()).unwrap().unwrap();
    let records = suffix(&next, 1);
    let weak = signed(&next, ScopeIndex::of(&next).root(), true);
    assert!(matches!(state.advance(&weak, &consistency, &slices(&records)),
        Err(IndexAdvanceError::Continuity(_))));
    let fork = journal(&[(7, 101), (30, -10)], 30);
    let forked = signed(&fork, ScopeIndex::of(&fork).root(), false);
    assert!(matches!(state.advance(&forked, &consistency, &slices(&suffix(&fork, 1))),
        Err(IndexAdvanceError::Continuity(_))));
    let candidate = signed(&next, ScopeIndex::of(&next).root(), false);
    assert!(matches!(state.advance(&candidate, b"", &slices(&records)),
        Err(IndexAdvanceError::Continuity(_))));
    let advanced = state.advance(&candidate, &consistency, &slices(&records)).unwrap();
    let old_bytes = signed(&old, ScopeIndex::of(&old).root(), false);
    assert!(matches!(advanced.advance(&old_bytes, &consistency, &[]),
        Err(IndexAdvanceError::Continuity(_))));
}

#[test]
fn an_append_proof_cannot_insert_a_leaf_into_the_previously_accepted_recorded_frontier() {
    let old = journal(&[(7, 100)], 20);
    let (state, _) = baseline(&old);
    let next = journal(&[(7, 100), (15, -10)], 30);
    // Tree extension is genuine; its new record contradicts the old frontier.
    let consistency = next.consistency_proof(&old.statement()).unwrap().unwrap();
    let candidate = signed(&next, ScopeIndex::of(&next).root(), false);
    assert!(matches!(state.advance(&candidate, &consistency, &slices(&suffix(&next, 1))),
        Err(IndexAdvanceError::RecordedOrder { leaf_index: 1 })));
    assert_eq!(state.index().checkpoint().through_seq, 20);
}

#[test]
fn same_tree_advances_and_empty_bootstrap_do_not_skip_payload_or_index_obligations() {
    let empty = journal(&[], 0);
    let (state, bytes) = baseline(&empty);
    assert!(IncrementalPayloadIndex::verify(&empty.prefix_proof().unwrap(), &pin(&bytes)).is_err());
    let consistency = empty.consistency_proof(&empty.statement()).unwrap().unwrap();
    assert!(state.advance(&bytes, &consistency, &[]).is_ok());
    let later = journal(&[], 10);
    let consistency = later.consistency_proof(&empty.statement()).unwrap().unwrap();
    let same_index = signed(&later, ScopeIndex::of(&later).root(), false);
    let advanced = state.advance(&same_index, &consistency, &[]).unwrap();
    assert_eq!(advanced.index().checkpoint().through_seq, 10);
    let different_index = signed(&later, [0x99; 32], false);
    assert!(matches!(state.advance(&different_index, &consistency, &[]),
        Err(IndexAdvanceError::Derivation(PayloadIndexError::Root))));
}
