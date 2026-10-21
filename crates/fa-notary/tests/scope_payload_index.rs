//! Actual producer v3 proofs and signed scope roots through the independent
//! verifier. This is not a posting-admission or export-authorization test.

use fa_model::{Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, LegPayload, Oid, SealKey};
use fa_money::{Amount, Side, UnitId};
use fa_notary::checkpoint::{CheckpointBody, TransparencyCheckpoint};
use fa_notary::{Journal, ScopeIndex, SigningKey};
use fa_time::DateDay;
use fa_verify::checkpoint::witness::{RecipientWitnessPolicy, WitnessedCheckpoint, verify_witnessed_checkpoint};
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
        description: Erasable::seal(&"private source".to_string(), None, &SealKey([3; 32]), [1; 32], [2; 24]),
        effective_period: None, unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs, control: None, base_totals: None, idempotency_key: key.as_bytes().to_vec(),
        origin: EntryOrigin::Intent { intent_oid: Oid([4; 32]), intent_kind: 1 },
        principal_ref: VId(7), session_ref: None, evidence: vec![], supersession: vec![],
        pending: None, external_ids: vec![], extensions: vec![], tags: vec![],
    }.seal(vec![], None).unwrap()
}

fn journal() -> Journal {
    Journal::from_records(BOOK, CommitSeq(30), vec![
        (VId(100), record("earlier", 100), CommitSeq(7)),
        (VId(101), record("late-effective", -10), CommitSeq(30)),
    ]).unwrap()
}

fn anchor(journal: &Journal, root: [u8; 32]) -> WitnessedCheckpoint {
    let publisher = SigningKey::from_seed(&[0x11; 32]);
    let a = SigningKey::from_seed(&[0x12; 32]);
    let b = SigningKey::from_seed(&[0x13; 32]);
    let checkpoint = TransparencyCheckpoint::sign(CheckpointBody {
        statement: journal.statement(), state_oid: Oid([0x22; 32]), scope_index_root: root,
        substrate_chain_commitment: [0x44; 32], witness_policy_oid: Some(Oid([0x55; 32])),
        time_evidence_oid: None,
    }, &[&publisher, &a, &b]).unwrap();
    let policy = RecipientWitnessPolicy::new(BOOK.0, [0; 16], [0x55; 32], publisher.public_key(),
        &[a.public_key(), b.public_key()], 2).unwrap();
    verify_witnessed_checkpoint(&checkpoint.canonical_bytes().unwrap(), &policy).unwrap()
}

#[test]
fn native_v3_export_reconstructs_the_producer_index_and_authenticates_empty_boundaries() {
    let journal = journal();
    let index = ScopeIndex::of(&journal);
    let pin = anchor(&journal, index.root());
    let complete = journal.balance_proof_complete(VId(10), 1, None, &[]).unwrap().unwrap();
    let derived = verify_payload_index(&complete, pin.signed_checkpoint()).unwrap();
    assert_eq!(derived.tuple_count(), index.tuples().len());
    assert_eq!(*derived.root(), index.root());
    for (account, from, to, expected) in [
        (10, -10, 100, 2), (20, -10, -10, 1), (99, i32::MIN, i32::MAX, 0), (10, 0, 99, 0),
    ] {
        let proof = index.proof(&journal, account, from, to).unwrap();
        let report = verify_scope_with_payload_index(&proof, pin.signed_checkpoint(),
            &ScopeClaim { account, from, to }, &derived).unwrap();
        assert_eq!(report.index_derivation, IndexDerivation::Recomputed);
        assert_eq!(report.leaves.len(), expected);
    }
    assert!(verify_payload_index(&journal.prefix_proof().unwrap(), pin.signed_checkpoint()).is_err());
}

#[test]
fn genuine_publisher_and_witness_signatures_cannot_validate_an_omitted_account_index() {
    let journal = journal();
    let mut omitted = journal.clone();
    for leaf in &mut omitted.leaves {
        leaf.envelope.account_vids.retain(|account| *account != VId(20));
    }
    // Signing an inconsistent index is possible; the verifier must detect it.
    let false_root = ScopeIndex::of(&omitted).root();
    assert_ne!(false_root, ScopeIndex::of(&journal).root());
    let pin = anchor(&journal, false_root);
    let complete = journal.balance_proof_complete(VId(10), 1, None, &[]).unwrap().unwrap();
    assert_eq!(verify_payload_index(&complete, pin.signed_checkpoint()), Err(PayloadIndexError::Root));
}

#[test]
fn using_a_native_balance_as_index_evidence_does_not_skip_its_fold_verification() {
    let journal = journal();
    let pin = anchor(&journal, ScopeIndex::of(&journal).root());
    let mut complete = journal.balance_proof_complete(VId(10), 1, None, &[]).unwrap().unwrap();
    assert!(verify_payload_index(&complete, pin.signed_checkpoint()).is_ok());
    let format_len = u32::from_le_bytes(complete[..4].try_into().unwrap()) as usize;
    // bytes(format), checkpoint, account, unit, absent-cutoff tag, debits.
    let debit = 4 + format_len + fa_verify::Checkpoint::ENCODED_LEN + 16 + 4 + 1;
    complete[debit] ^= 1;
    assert!(matches!(verify_payload_index(&complete, pin.signed_checkpoint()),
        Err(PayloadIndexError::Proof(_))));
}
