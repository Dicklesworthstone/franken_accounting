//! Actual producer checkpoint encodings/signatures through the independent
//! recipient-policy verifier. Synthetic bodies do not claim ledger validity,
//! registered policy objects, witness authorization or network collection.

use fa_model::{Id128, Oid};
use fa_notary::checkpoint::{CheckpointBody, TransparencyCheckpoint};
use fa_notary::{CheckpointSigner, SigningKey, Statement};
use fa_verify::checkpoint::witness::{
    AdvanceError, AdvanceStatus, RecipientWitnessPolicy, WitnessError,
    verify_checkpoint_advance, verify_witnessed_checkpoint,
};
use fgdb_types::CommitSeq;

fn body() -> CheckpointBody {
    CheckpointBody {
        statement: Statement {
            book_id: Id128([0x11; 16]), branch_id: Id128::TRUNK,
            through_seq: CommitSeq(7), leaf_count: 1, root: [0xa1; 32],
        },
        state_oid: Oid([0x22; 32]), scope_index_root: [0x33; 32],
        substrate_chain_commitment: [0x44; 32],
        witness_policy_oid: Some(Oid([0x55; 32])),
        time_evidence_oid: Some(Oid([0x66; 32])),
    }
}

fn keys() -> [SigningKey; 5] {
    [17, 18, 19, 20, 21].map(|seed| SigningKey::from_seed(&[seed; 32]))
}

fn policy(keys: &[SigningKey; 5], quorum: usize) -> RecipientWitnessPolicy {
    RecipientWitnessPolicy::new(
        [0x11; 16], [0; 16], [0x55; 32], keys[0].public_key(),
        &[keys[1].public_key(), keys[2].public_key(), keys[3].public_key()], quorum,
    ).unwrap()
}

fn signed(body: CheckpointBody, keys: &[SigningKey; 5], selected: &[usize]) -> TransparencyCheckpoint {
    let signers: Vec<&dyn CheckpointSigner> = selected.iter()
        .map(|index| &keys[*index] as &dyn CheckpointSigner).collect();
    TransparencyCheckpoint::sign(body, &signers).unwrap()
}

// Empty-path v1 consistency frame for the SAME tree, encoded from the actual
// producer's two statement bytes. This is not a producer delta/export test.
fn same_tree_proof(old: &CheckpointBody, new: &CheckpointBody) -> Vec<u8> {
    let format = fa_verify::proof::CONSISTENCY_FORMAT;
    let mut bytes = (format.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(format);
    bytes.extend_from_slice(&old.canonical_bytes().unwrap()[4..84]);
    bytes.extend_from_slice(&new.canonical_bytes().unwrap()[4..84]);
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes
}

#[test]
fn real_notary_signers_and_both_optional_fields_match_the_independent_quorum_verifier() {
    let keys = keys();
    let cp = signed(body(), &keys, &[4, 2, 0, 3, 1]);
    let bytes = cp.canonical_bytes().unwrap();
    let report = verify_witnessed_checkpoint(&bytes, &policy(&keys, 2)).unwrap();
    assert_eq!(report.signed_checkpoint().body_digest, cp.body.digest().unwrap());
    assert_eq!(report.signed_checkpoint().oid, cp.oid().unwrap().0);
    assert_eq!(report.signed_checkpoint().time_evidence_oid, Some([0x66; 32]));
    assert_eq!(report.witnesses().len(), 3);
    assert_eq!(report.signed_checkpoint().not_judged.len(), 1);
    let mut altered = bytes;
    altered[212] ^= 1; // authenticated policy bytes, not a signature-list mutation
    assert!(verify_witnessed_checkpoint(&altered, &policy(&keys, 2)).is_err());
}

#[test]
fn producer_deduplication_unknown_signers_and_missing_publishers_do_not_supply_votes() {
    let keys = keys();
    let recipient = policy(&keys, 2);
    let duplicates = signed(body(), &keys, &[0, 1, 1, 1, 4]);
    assert_eq!(duplicates.signatures.len(), 3);
    assert_eq!(verify_witnessed_checkpoint(&duplicates.canonical_bytes().unwrap(), &recipient),
        Err(WitnessError::Quorum { required: 2, verified: 1 }));
    let absent = signed(body(), &keys, &[1, 2, 3]);
    assert_eq!(verify_witnessed_checkpoint(&absent.canonical_bytes().unwrap(), &recipient),
        Err(WitnessError::PublisherMissing));
    let sufficient = signed(body(), &keys, &[0, 1, 2]);
    assert!(verify_witnessed_checkpoint(&sufficient.canonical_bytes().unwrap(), &recipient).is_ok());
}

#[test]
fn producer_resigning_advances_only_with_the_same_policy_and_nonconflicting_signed_body() {
    let keys = keys();
    let original = signed(body(), &keys, &[0, 1, 2]);
    let previous = verify_witnessed_checkpoint(&original.canonical_bytes().unwrap(), &policy(&keys, 2)).unwrap();
    let again = signed(body(), &keys, &[0, 2, 3]);
    let proof = same_tree_proof(&original.body, &again.body);
    let update = verify_checkpoint_advance(&previous, &again.canonical_bytes().unwrap(), &proof).unwrap();
    assert_eq!(update.status(), AdvanceStatus::Unchanged);
    assert_ne!(previous.signed_checkpoint().oid, update.checkpoint().signed_checkpoint().oid);

    let mut later = body();
    later.statement.through_seq = CommitSeq(8);
    later.state_oid = Oid([0x77; 32]);
    let cp = signed(later, &keys, &[0, 1, 3]);
    let proof = same_tree_proof(&original.body, &cp.body);
    assert_eq!(verify_checkpoint_advance(&previous, &cp.canonical_bytes().unwrap(), &proof)
        .unwrap().status(), AdvanceStatus::Advanced);

    let mut conflict = body();
    conflict.scope_index_root[0] ^= 1;
    let cp = signed(conflict, &keys, &[0, 1, 2, 3]);
    let proof = same_tree_proof(&original.body, &cp.body);
    assert!(verify_witnessed_checkpoint(&cp.canonical_bytes().unwrap(), &policy(&keys, 2)).is_ok());
    assert_eq!(verify_checkpoint_advance(&previous, &cp.canonical_bytes().unwrap(), &proof),
        Err(AdvanceError::Equivocation));
}
