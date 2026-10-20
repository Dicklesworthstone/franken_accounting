use super::*;

fn fixture(name: &str) -> Vec<u8> {
    let text = include_str!("../../../tests/fixtures/checkpoint_witness_v1.txt");
    let hex = text.lines().find_map(|line| {
        line.strip_prefix(name).and_then(|tail| tail.strip_prefix(' '))
    }).expect("named fixed fixture");
    (0..hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}

fn key(name: &str) -> [u8; 32] {
    fixture(name).try_into().unwrap()
}

fn policy(quorum: usize) -> RecipientWitnessPolicy {
    RecipientWitnessPolicy::new(
        [0x11; 16], [0; 16], [0x55; 32], key("publisher"),
        &[key("witness_a"), key("witness_b"), key("witness_c")], quorum,
    ).unwrap()
}

// The fixed policy-present/no-time-evidence body is 214 bytes. The canonical
// signature rows are 32-byte ID, u16 scheme, u32 length and 64-byte Ed25519.
// The signature list is outside the signed body; filtering never re-signs it.
fn retain_signers(bytes: &[u8], names: &[&str]) -> Vec<u8> {
    let ids: BTreeSet<_> = names.iter().map(|name| signer_key_id(&key(name))).collect();
    let rows: Vec<_> = bytes[218..].as_chunks::<102>().0.iter()
        .filter(|row| ids.contains(&<[u8; 32]>::try_from(&row[..32]).unwrap())).collect();
    let mut result = bytes[..214].to_vec();
    result.extend_from_slice(&(rows.len() as u32).to_le_bytes());
    for row in rows { result.extend_from_slice(row); }
    result
}

#[test]
fn real_signatures_require_publisher_and_distinct_witnesses_under_exact_coordinates() {
    let report = verify_witnessed_checkpoint(&fixture("initial"), &policy(2)).unwrap();
    let expected: BTreeSet<_> = ["witness_a", "witness_b", "witness_c"].iter()
        .map(|name| signer_key_id(&key(name))).collect();
    assert_eq!(report.witnesses().iter().copied().collect::<BTreeSet<_>>(), expected);
    assert_eq!(report.required_witnesses(), 2);
    assert_eq!(report.signed_checkpoint().checkpoint.through_seq, 7);
    assert_eq!(report.signed_checkpoint().witness_policy_oid, Some([0x55; 32]));
    assert_eq!(report.signed_checkpoint().not_judged, vec![signer_key_id(&key("outsider"))]);
    let subset = retain_signers(&fixture("initial"), &["publisher", "witness_a", "witness_b"]);
    assert_eq!(verify_witnessed_checkpoint(&subset, &policy(2)).unwrap().witnesses().len(), 2);
}

#[test]
fn valid_signatures_from_publisher_or_unconfigured_keys_cannot_fill_witness_slots() {
    let bytes = fixture("initial");
    for names in [vec!["publisher"], vec!["publisher", "outsider"]] {
        let selected = retain_signers(&bytes, &names);
        // The old interface intentionally remains an any-trusted-signer check.
        assert!(verify_checkpoint(&selected, &[key("publisher")]).is_ok());
        assert_eq!(verify_witnessed_checkpoint(&selected, &policy(2)),
            Err(WitnessError::Quorum { required: 2, verified: 0 }));
    }
    let insufficient = retain_signers(&bytes, &["publisher", "witness_a", "outsider"]);
    assert_eq!(verify_witnessed_checkpoint(&insufficient, &policy(2)),
        Err(WitnessError::Quorum { required: 2, verified: 1 }));
    let no_publisher = retain_signers(&bytes, &["witness_a", "witness_b", "witness_c"]);
    assert_eq!(verify_witnessed_checkpoint(&no_publisher, &policy(2)),
        Err(WitnessError::PublisherMissing));
}

#[test]
fn zero_or_impossible_quorums_duplicate_keys_and_role_overlap_are_not_normalized() {
    let publisher = key("publisher");
    let a = key("witness_a");
    let b = key("witness_b");
    for (witnesses, threshold) in [
        (vec![], 1), (vec![a, b], 0), (vec![a, b], 3),
        (vec![a, a], 1), (vec![a, publisher], 1), (vec![a; 64], 1),
    ] {
        assert!(matches!(RecipientWitnessPolicy::new(
            [0x11; 16], [0; 16], [0x55; 32], publisher, &witnesses, threshold,
        ), Err(WitnessError::Policy(_))));
    }
}

#[test]
fn invalid_trusted_keys_are_rejected_even_when_not_needed_for_the_threshold() {
    let mut identity = [0; 32];
    identity[0] = 1;
    for (publisher, witnesses) in [
        (identity, vec![key("witness_a")]),
        (key("publisher"), vec![key("witness_a"), identity]),
    ] {
        assert!(matches!(RecipientWitnessPolicy::new(
            [0x11; 16], [0; 16], [0x55; 32], publisher, &witnesses, 1,
        ), Err(WitnessError::Verification(VerifyError::Checkpoint(
            CheckpointError::TrustedKey { .. }
        )))));
    }
}

#[test]
fn genuine_signatures_for_other_books_branches_or_policies_do_not_satisfy_the_request() {
    for name in ["foreign_book", "foreign_branch"] {
        assert!(verify_checkpoint(&fixture(name), &[key("publisher")]).is_ok());
        assert_eq!(verify_witnessed_checkpoint(&fixture(name), &policy(2)),
            Err(WitnessError::Coordinate));
    }
    for name in ["other_policy", "missing_policy"] {
        assert!(verify_checkpoint(&fixture(name), &[key("publisher")]).is_ok());
        assert_eq!(verify_witnessed_checkpoint(&fixture(name), &policy(2)),
            Err(WitnessError::PolicyIdentity));
    }
}

#[test]
fn a_bad_configured_signature_fails_even_after_enough_other_witnesses_signed() {
    let mut bytes = fixture("initial");
    let id = signer_key_id(&key("witness_c"));
    let row = bytes[218..].as_chunks_mut::<102>().0.iter_mut().find(|row| row[..32] == id).unwrap();
    row[101] ^= 1;
    assert!(matches!(verify_witnessed_checkpoint(&bytes, &policy(1)),
        Err(WitnessError::Verification(_))));
    // An unknown signature is explicitly not judged, never a quorum vote.
    let mut bytes = fixture("initial");
    let id = signer_key_id(&key("outsider"));
    let row = bytes[218..].as_chunks_mut::<102>().0.iter_mut().find(|row| row[..32] == id).unwrap();
    row[101] ^= 1;
    assert_eq!(verify_witnessed_checkpoint(&bytes, &policy(3)).unwrap().witnesses().len(), 3);
}

#[test]
fn duplicate_signature_rows_cannot_be_counted_as_separate_witnesses() {
    let original = retain_signers(&fixture("initial"), &["publisher", "witness_a"]);
    let mut rows: Vec<_> = original[218..].as_chunks::<102>().0.iter().map(|row| row.to_vec()).collect();
    let id = signer_key_id(&key("witness_a"));
    let witness = rows.iter().find(|row| row[..32] == id).unwrap().clone();
    rows.push(witness);
    rows.sort();
    let mut repeated = original[..214].to_vec();
    repeated.extend_from_slice(&(rows.len() as u32).to_le_bytes());
    for row in rows { repeated.extend_from_slice(&row); }
    assert!(matches!(verify_witnessed_checkpoint(&repeated, &policy(2)),
        Err(WitnessError::Verification(_))));
}

#[test]
fn oversized_truncated_trailing_and_tampered_frames_never_return_a_quorum_report() {
    let policy = policy(2);
    let bytes = fixture("initial");
    for end in [0, 3, 4, 83, 180, 213, 214, 217, 218, bytes.len() - 1] {
        assert!(verify_witnessed_checkpoint(&bytes[..end], &policy).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(verify_witnessed_checkpoint(&trailing, &policy).is_err());
    for offset in [4, 20, 36, 44, 52, 84, 116, 148, 181] {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(verify_witnessed_checkpoint(&changed, &policy).is_err());
    }
    let oversized = vec![0; MAX_WITNESSED_CHECKPOINT_BYTES + 1];
    assert_eq!(verify_witnessed_checkpoint(&oversized, &policy),
        Err(WitnessError::InputLimit("signed checkpoint")));
}
