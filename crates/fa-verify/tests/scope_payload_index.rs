//! Payload-derived scope indexes. Signature/assembler interoperability lives
//! in fa-notary; these tests explicitly supply a trusted statement directly.

#[path = "support/evidence_inventory.rs"]
mod fixture;
#[path = "support/evidence_production.rs"]
mod production;

use fa_verify::blake3::hash_parts;
use fa_verify::envelope::LeafEnvelope;
use fa_verify::proof::PREFIX_FORMAT;
use fa_verify::proof::production::derivation::{MAX_PREFIX_PROOF_BYTES, PREFIX_FORMAT_V2};
use fa_verify::scope::payloads::{
    PayloadIndexError, verify_payload_index, verify_scope_with_payload_index,
};
use fa_verify::scope::{SCOPE_FORMAT, SCOPE_LEAF_DOMAIN, SCOPE_NODE_DOMAIN, SCOPE_ROOT_DOMAIN};
use fa_verify::tree::{leaf_hash, root_of, root_of_with};
use fa_verify::{Checkpoint, IndexDerivation, ScopeClaim, SignedCheckpoint};
use production::{entry, journal};

fn u32_at(bytes: &[u8], at: &mut usize) -> usize {
    let value = u32::from_le_bytes(bytes[*at..*at + 4].try_into().unwrap()) as usize;
    *at += 4;
    value
}

fn split(prefix: &[u8]) -> (Vec<LeafEnvelope>, &[u8]) {
    let mut at = 0;
    let length = u32_at(prefix, &mut at);
    at += length + Checkpoint::ENCODED_LEN;
    let count = u32_at(prefix, &mut at);
    let mut envelopes = Vec::new();
    for _ in 0..count {
        let length = u32_at(prefix, &mut at);
        envelopes.push(LeafEnvelope::decode(&prefix[at..at + length]).unwrap());
        at += length;
    }
    (envelopes, &prefix[at..])
}

fn index_root(cp: &Checkpoint, envelopes: &[LeafEnvelope]) -> [u8; 32] {
    let mut tuples = Vec::new();
    for (i, envelope) in envelopes.iter().enumerate() {
        if let Some(day) = envelope.effective_day {
            for account in &envelope.account_vids {
                tuples.push((*account, day, i as u64));
            }
        }
    }
    tuples.sort_unstable();
    let leaves: Vec<_> = tuples
        .iter()
        .map(|(account, day, index)| {
            hash_parts(
                SCOPE_LEAF_DOMAIN,
                &[
                    &cp.book_id,
                    &cp.branch_id,
                    &account.to_le_bytes(),
                    &day.to_le_bytes(),
                    &index.to_le_bytes(),
                ],
            )
        })
        .collect();
    let root = root_of_with(
        |left, right| hash_parts(SCOPE_NODE_DOMAIN, &[left, right]),
        &leaves,
    );
    hash_parts(
        SCOPE_ROOT_DOMAIN,
        &[&(tuples.len() as u64).to_le_bytes(), &root],
    )
}

fn signed(cp: Checkpoint, envelopes: &[LeafEnvelope]) -> SignedCheckpoint {
    SignedCheckpoint {
        checkpoint: cp,
        scope_index_root: index_root(&cp, envelopes),
        state_oid: [1; 32],
        substrate_chain_commitment: [2; 32],
        witness_policy_oid: None,
        time_evidence_oid: None,
        body_digest: [3; 32],
        oid: [4; 32],
        signed_by: vec![],
        not_judged: vec![],
    }
}

fn encoded_prefix(
    format: &[u8],
    cp: &Checkpoint,
    envelopes: &[LeafEnvelope],
    tail: &[u8],
) -> Vec<u8> {
    let mut w = fixture::Wire::default();
    w.bytes(format)
        .fixed(&cp.encode())
        .u32(envelopes.len() as u32);
    for envelope in envelopes {
        w.bytes(&envelope.encode());
    }
    w.fixed(tail);
    w.0
}

#[test]
fn complete_payloads_derive_both_accounts_with_late_effective_and_undated_records() {
    let mut control = entry(&[], 11, 999);
    control.proposal[36..38].copy_from_slice(&17u16.to_le_bytes());
    let j = journal(&[entry(&[], 7, 100), control, entry(&[], 30, -10)]);
    let (envelopes, _) = split(&j.prefix);
    let signed = signed(j.checkpoint, &envelopes);
    let index = verify_payload_index(&j.prefix, &signed).unwrap();
    assert_eq!(index.checkpoint(), &j.checkpoint);
    assert_eq!(index.root(), &signed.scope_index_root);
    assert_eq!(index.tuple_count(), 4); // two dated entries, two accounts each
    assert_eq!(index.encoded_bytes(), j.prefix.len());
    assert!(index.matches(&signed));
    let metadata = format!("{index:?}");
    assert!(!metadata.contains(std::str::from_utf8(fixture::SECRET).unwrap()));
}

#[test]
fn an_authentic_prefix_cannot_excuse_an_index_that_omits_an_entire_account() {
    let j = journal(&[entry(&[], 7, 100), entry(&[], 30, -10)]);
    let (envelopes, _) = split(&j.prefix);
    let mut signed = signed(j.checkpoint, &envelopes);
    assert!(verify_payload_index(&j.prefix, &signed).is_ok());
    let mut incomplete = envelopes;
    for envelope in &mut incomplete {
        envelope.account_vids.retain(|account| *account != 20);
    }
    signed.scope_index_root = index_root(&j.checkpoint, &incomplete);
    assert_eq!(
        verify_payload_index(&j.prefix, &signed),
        Err(PayloadIndexError::Root)
    );
}

#[test]
fn a_self_consistent_envelope_index_does_not_authenticate_forged_payload_selectors() {
    let j = journal(&[entry(&[], 7, 100), entry(&[], 30, -10)]);
    let (original, tail) = split(&j.prefix);
    for field in 0..4 {
        let mut envelopes = original.clone();
        match field {
            0 => envelopes[1].account_vids = vec![99],
            1 => envelopes[1].effective_day = Some(200),
            2 => envelopes[1].class = 2,
            _ => envelopes[1].unit_ids = vec![99],
        }
        // Even a checkpoint consistent with the false envelopes cannot make
        // their selectors agree with the original authenticated record bytes.
        let leaves: Vec<_> = envelopes.iter().map(|e| leaf_hash(&e.encode())).collect();
        let cp = Checkpoint {
            root: root_of(&leaves),
            ..j.checkpoint
        };
        let signed = signed(cp, &envelopes);
        let legacy = encoded_prefix(PREFIX_FORMAT, &cp, &envelopes, &[]);
        assert!(fa_verify::scope::recompute_index(&legacy, &signed).is_ok());
        let complete = encoded_prefix(PREFIX_FORMAT_V2, &cp, &envelopes, tail);
        assert!(matches!(
            verify_payload_index(&complete, &signed),
            Err(PayloadIndexError::Proof(_))
        ));
    }
}

#[test]
fn legacy_envelopes_never_satisfy_payload_derivation_even_for_an_empty_prefix() {
    for j in [journal(&[]), journal(&[entry(&[], 7, 10)])] {
        let (envelopes, _) = split(&j.prefix);
        let signed = signed(j.checkpoint, &envelopes);
        assert!(verify_payload_index(&j.prefix, &signed).is_ok());
        let legacy = encoded_prefix(PREFIX_FORMAT, &j.checkpoint, &envelopes, &[]);
        assert!(fa_verify::scope::recompute_index(&legacy, &signed).is_ok());
        assert!(matches!(
            verify_payload_index(&legacy, &signed),
            Err(PayloadIndexError::Proof(_))
        ));
    }
}

#[test]
fn missing_reordered_tampered_and_late_invalid_record_frames_refuse_atomically() {
    let j = journal(&[entry(&[], 7, 10), entry(&[], 30, 20)]);
    let (envelopes, tail) = split(&j.prefix);
    let signed = signed(j.checkpoint, &envelopes);
    assert!(verify_payload_index(&j.prefix, &signed).is_ok());
    let mut missing = tail.to_vec();
    missing[..4].copy_from_slice(&1u32.to_le_bytes());
    let mut reordered = tail.to_vec();
    reordered[4..12].copy_from_slice(&1u64.to_le_bytes());
    let mut tampered = tail.to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    for bad in [
        missing,
        reordered,
        tampered,
        tail[..tail.len() - 1].to_vec(),
    ] {
        let bytes = encoded_prefix(PREFIX_FORMAT_V2, &j.checkpoint, &envelopes, &bad);
        assert!(verify_payload_index(&bytes, &signed).is_err());
    }
    for end in [0, 1, j.prefix.len() / 2, j.prefix.len() - 1] {
        assert!(verify_payload_index(&j.prefix[..end], &signed).is_err());
    }
    let mut trailing = j.prefix;
    trailing.push(0);
    assert!(verify_payload_index(&trailing, &signed).is_err());
}

#[test]
fn sealed_derivations_bind_coordinate_and_root_without_claiming_signature_freshness() {
    let j = journal(&[]);
    let signed = signed(j.checkpoint, &[]);
    let index = verify_payload_index(&j.prefix, &signed).unwrap();
    for field in 0..6 {
        let mut changed = signed.clone();
        match field {
            0 => changed.checkpoint.book_id[0] ^= 1,
            1 => changed.checkpoint.branch_id[0] ^= 1,
            2 => changed.checkpoint.through_seq += 1,
            3 => changed.checkpoint.leaf_count += 1,
            4 => changed.checkpoint.root[0] ^= 1,
            _ => changed.scope_index_root[0] ^= 1,
        }
        assert!(!index.matches(&changed));
        assert_eq!(
            verify_scope_with_payload_index(
                b"invalid",
                &changed,
                &ScopeClaim {
                    account: 1,
                    from: 0,
                    to: 0
                },
                &index
            ),
            Err(PayloadIndexError::Anchor)
        );
    }
    let mut same_content = signed;
    same_content.oid[0] ^= 1;
    assert!(index.matches(&same_content)); // bundle artifact binding is separate
}

#[test]
fn empty_interval_proofs_still_check_range_claim_and_membership() {
    let j = journal(&[]);
    let signed = signed(j.checkpoint, &[]);
    let index = verify_payload_index(&j.prefix, &signed).unwrap();
    let claim = ScopeClaim {
        account: 99,
        from: i32::MIN,
        to: i32::MAX,
    };
    let mut w = fixture::Wire::default();
    w.bytes(SCOPE_FORMAT)
        .fixed(&j.checkpoint.encode())
        .u64(0)
        .u128(claim.account)
        .fixed(&claim.from.to_le_bytes())
        .fixed(&claim.to.to_le_bytes())
        .u64(0)
        .u32(0)
        .u8(0)
        .u8(0);
    let report = verify_scope_with_payload_index(&w.0, &signed, &claim, &index).unwrap();
    assert_eq!(report.index_derivation, IndexDerivation::Recomputed);
    assert!(report.leaves.is_empty());
    assert!(
        verify_scope_with_payload_index(
            &w.0,
            &signed,
            &ScopeClaim {
                account: 100,
                ..claim
            },
            &index
        )
        .is_err()
    );
    w.0.push(0);
    assert!(verify_scope_with_payload_index(&w.0, &signed, &claim, &index).is_err());
}

#[test]
fn malformed_and_oversized_inputs_do_not_create_reusable_evidence() {
    let j = journal(&[]);
    let signed = signed(j.checkpoint, &[]);
    let too_large = vec![0; MAX_PREFIX_PROOF_BYTES + 1];
    assert!(verify_payload_index(&too_large, &signed).is_err());
    let mut wrong_root = signed.clone();
    wrong_root.checkpoint.root[0] ^= 1;
    assert!(verify_payload_index(&j.prefix, &wrong_root).is_err());
    let mut wrong_count = j.prefix;
    let offset = 4 + PREFIX_FORMAT_V2.len() + Checkpoint::ENCODED_LEN;
    wrong_count[offset..offset + 4].copy_from_slice(&65_537u32.to_le_bytes());
    assert!(verify_payload_index(&wrong_count, &signed).is_err());
}
