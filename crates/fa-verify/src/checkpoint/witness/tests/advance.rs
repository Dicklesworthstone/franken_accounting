use super::{fixture, policy, retain_signers};
use crate::checkpoint::witness::{
    AdvanceError, AdvanceStatus, MAX_WITNESS_CONSISTENCY_BYTES, WitnessError,
    verify_checkpoint_advance, verify_witnessed_checkpoint,
};
use crate::proof::verify_consistency;

fn vector(name: &str) -> Vec<u8> {
    let text = include_str!("../../../../tests/fixtures/checkpoint_witness_advance_v1.txt");
    let hex = text.lines().find_map(|line| {
        line.strip_prefix(name).and_then(|tail| tail.strip_prefix(' '))
    }).expect("named continuity fixture");
    (0..hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn a_quorum_signed_extension_advances_without_mutating_the_previous_pin() {
    let previous = verify_witnessed_checkpoint(&fixture("initial"), &policy(2)).unwrap();
    let retained = previous.clone();
    let advanced = verify_checkpoint_advance(&previous, &vector("extended"), &vector("extend_proof")).unwrap();
    assert_eq!(advanced.status(), AdvanceStatus::Advanced);
    assert_eq!(advanced.checkpoint().signed_checkpoint().checkpoint.through_seq, 9);
    assert_eq!(advanced.checkpoint().signed_checkpoint().checkpoint.leaf_count, 2);
    assert_eq!(advanced.checkpoint().required_witnesses(), 2);
    assert_eq!(previous, retained);
    let installed = advanced.clone().into_checkpoint();
    assert_eq!(&installed, advanced.checkpoint());
}

#[test]
fn a_different_sufficient_signature_set_on_the_same_body_is_not_equivocation() {
    let bytes = fixture("initial");
    let first = retain_signers(&bytes, &["publisher", "witness_a", "witness_b"]);
    let second = retain_signers(&bytes, &["publisher", "witness_b", "witness_c"]);
    let previous = verify_witnessed_checkpoint(&first, &policy(2)).unwrap();
    let result = verify_checkpoint_advance(&previous, &second, &vector("same_proof")).unwrap();
    assert_eq!(result.status(), AdvanceStatus::Unchanged);
    assert_eq!(previous.signed_checkpoint().body_digest, result.checkpoint().signed_checkpoint().body_digest);
    assert_ne!(previous.signed_checkpoint().oid, result.checkpoint().signed_checkpoint().oid);
    assert_ne!(previous.witnesses(), result.checkpoint().witnesses());
}

#[test]
fn same_sequence_body_conflicts_refuse_even_when_the_accumulator_tree_agrees() {
    let previous = verify_witnessed_checkpoint(&fixture("initial"), &policy(2)).unwrap();
    for name in ["changed_state", "changed_index", "changed_chain"] {
        let bytes = vector(name);
        let signed = verify_witnessed_checkpoint(&bytes, &policy(2)).unwrap();
        let proof = vector("same_proof");
        // Tree continuity alone cannot detect altered non-tree signed metadata.
        assert!(verify_consistency(&proof, &previous.signed_checkpoint().checkpoint,
            &signed.signed_checkpoint().checkpoint).is_ok());
        assert_eq!(verify_checkpoint_advance(&previous, &bytes, &proof), Err(AdvanceError::Equivocation));
    }
}

#[test]
fn genuine_signatures_cannot_authorize_rollback_or_a_smaller_tree() {
    let previous = verify_witnessed_checkpoint(&vector("extended"), &policy(2)).unwrap();
    let retained = previous.clone();
    for (candidate, proof) in [
        (fixture("initial"), vector("rollback_proof")),
        (vector("regression"), vector("regression_proof")),
    ] {
        assert!(verify_witnessed_checkpoint(&candidate, &policy(2)).is_ok());
        assert_eq!(verify_checkpoint_advance(&previous, &candidate, &proof), Err(AdvanceError::Regression));
        assert_eq!(previous, retained);
    }
}

#[test]
fn signed_forks_and_proofs_for_different_endpoints_do_not_advance() {
    let previous = verify_witnessed_checkpoint(&fixture("initial"), &policy(2)).unwrap();
    let fork = vector("fork");
    assert!(verify_witnessed_checkpoint(&fork, &policy(2)).is_ok());
    assert!(matches!(verify_checkpoint_advance(&previous, &fork, &vector("fork_proof")),
        Err(AdvanceError::Consistency(_))));
    for proof in [vector("same_proof"), vector("empty_proof"), vector("rollback_proof")] {
        assert!(matches!(verify_checkpoint_advance(&previous, &vector("extended"), &proof),
            Err(AdvanceError::Consistency(_))));
    }
}

#[test]
fn empty_trees_and_later_sequences_without_new_leaves_follow_the_same_rules() {
    let empty = verify_witnessed_checkpoint(&vector("empty"), &policy(2)).unwrap();
    let initial = verify_checkpoint_advance(&empty, &fixture("initial"), &vector("empty_proof"))
        .unwrap().into_checkpoint();
    let later = verify_checkpoint_advance(&initial, &vector("later_same_tree"),
        &vector("later_same_tree_proof")).unwrap();
    assert_eq!(later.status(), AdvanceStatus::Advanced);
    assert_eq!(later.checkpoint().signed_checkpoint().checkpoint.through_seq, 8);
    assert_eq!(later.checkpoint().signed_checkpoint().checkpoint.root,
        initial.signed_checkpoint().checkpoint.root);
}

#[test]
fn the_retained_policy_cannot_be_silently_weakened_or_replaced_by_a_candidate() {
    let previous = verify_witnessed_checkpoint(&fixture("initial"), &policy(2)).unwrap();
    let too_few = retain_signers(&vector("extended"), &["publisher", "witness_a", "outsider"]);
    assert!(verify_witnessed_checkpoint(&too_few, &policy(1)).is_ok());
    assert_eq!(verify_checkpoint_advance(&previous, &too_few, &vector("extend_proof")),
        Err(AdvanceError::Witness(WitnessError::Quorum { required: 2, verified: 1 })));
    for name in ["other_policy", "missing_policy"] {
        assert_eq!(verify_checkpoint_advance(&previous, &fixture(name), &vector("same_proof")),
            Err(AdvanceError::Witness(WitnessError::PolicyIdentity)));
    }
    for name in ["foreign_book", "foreign_branch"] {
        assert_eq!(verify_checkpoint_advance(&previous, &fixture(name), &vector("same_proof")),
            Err(AdvanceError::Witness(WitnessError::Coordinate)));
    }
}

#[test]
fn consistency_is_mandatory_exact_and_bounded_even_for_an_unchanged_checkpoint() {
    let bytes = fixture("initial");
    let previous = verify_witnessed_checkpoint(&bytes, &policy(2)).unwrap();
    let proof = vector("same_proof");
    assert_eq!(verify_checkpoint_advance(&previous, &bytes, &proof).unwrap().status(), AdvanceStatus::Unchanged);
    for end in [0, 3, 10, proof.len() / 2, proof.len() - 1] {
        assert!(matches!(verify_checkpoint_advance(&previous, &bytes, &proof[..end]),
            Err(AdvanceError::Consistency(_))));
    }
    let mut trailing = proof;
    trailing.push(0);
    assert!(matches!(verify_checkpoint_advance(&previous, &bytes, &trailing),
        Err(AdvanceError::Consistency(_))));
    let oversized = vec![0; MAX_WITNESS_CONSISTENCY_BYTES + 1];
    // Bound refusal precedes even decoding the invalid candidate.
    assert_eq!(verify_checkpoint_advance(&previous, b"invalid", &oversized), Err(AdvanceError::ProofLimit));
}
