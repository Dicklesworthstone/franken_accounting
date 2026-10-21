//! Unsigned synthetic statements exercise the record/index layer only.
//! fa-notary interoperability tests exercise the public quorum/continuity path.

use super::*;
use crate::blake3::hash_parts;
use crate::codec::Writer;
use crate::envelope::{
    ENTRY_DIGEST_DOMAIN, LeafEnvelope, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry,
};
use crate::proof::production::derivation::PREFIX_FORMAT_V2;
use crate::proof::{Checkpoint, INCLUSION_FORMAT};
use crate::scope::{SCOPE_LEAF_DOMAIN, SCOPE_NODE_DOMAIN, SCOPE_ROOT_DOMAIN};
use crate::tree::{Digest, leaf_hash, root_of, root_of_with};

const SECRET: &[u8] = b"incremental-record-not-for-reporting";

struct Entry {
    seq: u64,
    ordinal: u32,
    day: i32,
    class: u16,
    accounts: [u128; 2],
}

fn entry(seq: u64, day: i32) -> Entry {
    Entry {
        seq,
        day,
        ordinal: 0,
        class: 1,
        accounts: [10, 20],
    }
}

struct Journal {
    signed: SignedCheckpoint,
    envelopes: Vec<LeafEnvelope>,
    payloads: Vec<(usize, Vec<u8>)>,
}

fn index_root(cp: &Checkpoint, envelopes: &[LeafEnvelope]) -> Digest {
    let mut tuples = Vec::new();
    for (index, envelope) in envelopes.iter().enumerate() {
        if let Some(day) = envelope.effective_day {
            for account in &envelope.account_vids {
                tuples.push((*account, day, index as u64));
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

fn path(leaves: &[Digest], index: usize) -> Vec<Digest> {
    if leaves.len() == 1 {
        return vec![];
    }
    let mut split = 1;
    while split * 2 < leaves.len() {
        split *= 2;
    }
    let (mut result, sibling) = if index < split {
        (path(&leaves[..split], index), root_of(&leaves[split..]))
    } else {
        (
            path(&leaves[split..], index - split),
            root_of(&leaves[..split]),
        )
    };
    result.push(sibling);
    result
}

fn journal(entries: &[Entry], through_seq: u64) -> Journal {
    let mut envelopes = Vec::new();
    let mut payloads = Vec::new();
    for e in entries {
        let mut w = Writer::default();
        w.u16(1)
            .u16(1)
            .fixed(&[0x42; 16])
            .fixed(&[0; 16])
            .u16(e.class)
            .i32(e.day)
            .u8(0)
            .fixed(&[0; 32])
            .u8(0)
            .fixed(&[0; 24])
            .bytes(SECRET)
            .u8(0)
            .count(2);
        for (side, account) in e.accounts.iter().enumerate() {
            w.u8(side as u8)
                .u128(*account)
                .u32(1)
                .i128(123)
                .u8(0)
                .count(0)
                .u8(0)
                .count(0);
        }
        w.u8(0)
            .count(1)
            .u32(1)
            .i128(123)
            .i128(123)
            .u8(0)
            .bytes(&e.seq.to_le_bytes())
            .u8(0)
            .fixed(&[9; 32])
            .u16(1)
            .u128(7)
            .u8(0)
            .count(0)
            .count(0)
            .u8(0)
            .count(0)
            .count(0)
            .count(0);
        let split = w.buf.len();
        let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.buf]);
        let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &[0; 5]]);
        w.fixed(&[0; 5]).fixed(&proposal_digest).fixed(&digest);
        envelopes.push(envelope_of_entry(&w.buf, split, e.seq, e.ordinal).unwrap());
        payloads.push((split, w.buf));
    }
    let cp = Checkpoint {
        book_id: [0x42; 16],
        branch_id: [0; 16],
        through_seq,
        leaf_count: envelopes.len() as u64,
        root: root_of(
            &envelopes
                .iter()
                .map(|e| leaf_hash(&e.encode()))
                .collect::<Vec<_>>(),
        ),
    };
    Journal {
        signed: SignedCheckpoint {
            checkpoint: cp,
            scope_index_root: index_root(&cp, &envelopes),
            state_oid: [1; 32],
            substrate_chain_commitment: [2; 32],
            witness_policy_oid: None,
            time_evidence_oid: None,
            body_digest: [3; 32],
            oid: [4; 32],
            signed_by: vec![],
            not_judged: vec![],
        },
        envelopes,
        payloads,
    }
}

impl Journal {
    fn prefix(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(PREFIX_FORMAT_V2)
            .fixed(&self.signed.checkpoint.encode())
            .count(self.envelopes.len());
        for e in &self.envelopes {
            w.bytes(&e.encode());
        }
        w.count(self.payloads.len());
        for (i, (split, payload)) in self.payloads.iter().enumerate() {
            w.u64(i as u64).u32(*split as u32).bytes(payload);
        }
        w.buf
    }

    fn proof(&self, index: usize, payload: bool) -> Vec<u8> {
        let hashes: Vec<_> = self
            .envelopes
            .iter()
            .map(|e| leaf_hash(&e.encode()))
            .collect();
        let mut w = Writer::default();
        w.bytes(INCLUSION_FORMAT)
            .fixed(&self.signed.checkpoint.encode())
            .u64(index as u64)
            .bytes(&self.envelopes[index].encode())
            .u8(u8::from(payload));
        if payload {
            w.u32(self.payloads[index].0 as u32)
                .bytes(&self.payloads[index].1);
        }
        let siblings = path(&hashes, index);
        w.count(siblings.len());
        for sibling in siblings {
            w.fixed(&sibling);
        }
        w.buf
    }

    fn baseline(&self) -> (PayloadIndex, Vec<IndexTuple>) {
        derive_with_tuples(&self.prefix(), &self.signed).unwrap()
    }
}

#[test]
fn incremental_metadata_equals_full_derivation_after_late_effective_and_undated_records() {
    let old = journal(&[entry(7, 100)], 7);
    let (index, retained) = old.baseline();
    let mut control = entry(11, 999);
    control.class = 17; // undated synthetic record; no accounting-admission claim
    let mut last = entry(30, i32::MIN);
    last.ordinal = 1;
    last.accounts = [30, 40];
    let next = journal(&[entry(7, 100), control, entry(30, -10), last], 30);
    let proofs: Vec<_> = (1..4).map(|i| next.proof(i, true)).collect();
    let records: Vec<_> = proofs.iter().map(Vec::as_slice).collect();
    let bytes = witness_budget(index.encoded_bytes, 10, 20, &records).unwrap();
    let (advanced, tuples) = extend(&index, &retained, &next.signed, &records, bytes).unwrap();
    let (full, expected_tuples) = next.baseline();
    assert_eq!(advanced.checkpoint(), full.checkpoint());
    assert_eq!(advanced.root(), full.root());
    assert_eq!(advanced.tuple_count(), 6);
    assert_eq!(tuples, expected_tuples);
    assert_eq!(advanced.encoded_bytes(), bytes);
    assert!(
        tuples
            .iter()
            .any(|(_, day, leaf)| *day == -10 && *leaf == 2)
    );
    assert_eq!(old.baseline(), (index, retained)); // original state remains intact
}

#[test]
fn exact_suffix_rejects_missing_extra_duplicate_reordered_and_replayed_old_leaves() {
    let (index, retained) = journal(&[entry(7, 100)], 7).baseline();
    let next = journal(&[entry(7, 100), entry(11, 10), entry(30, -10)], 30);
    let proofs: Vec<_> = (0..3).map(|i| next.proof(i, true)).collect();
    assert!(
        extend(
            &index,
            &retained,
            &next.signed,
            &[&proofs[1], &proofs[2]],
            0
        )
        .is_ok()
    );
    for records in [
        vec![],
        vec![proofs[1].as_slice()],
        vec![&proofs[0], &proofs[1], &proofs[2]],
    ] {
        assert!(matches!(
            extend(&index, &retained, &next.signed, &records, 0),
            Err(IndexAdvanceError::RecordCount { .. })
        ));
    }
    for records in [
        [&proofs[1][..], &proofs[1][..]],
        [&proofs[2], &proofs[1]],
        [&proofs[0], &proofs[2]],
    ] {
        assert!(matches!(
            extend(&index, &retained, &next.signed, &records, 0),
            Err(IndexAdvanceError::Position { .. })
        ));
    }
}

#[test]
fn every_appended_payload_is_required_even_when_it_contributes_no_tuples() {
    let (index, retained) = journal(&[entry(7, 100)], 7).baseline();
    let mut control = entry(11, 200);
    control.class = 17;
    let next = journal(&[entry(7, 100), control], 11);
    let full = next.proof(1, true);
    assert!(extend(&index, &retained, &next.signed, &[&full], 0).is_ok());
    let bare = next.proof(1, false);
    assert_eq!(
        extend(&index, &retained, &next.signed, &[&bare], 0),
        Err(IndexAdvanceError::PayloadRequired { leaf_index: 1 })
    );
    for end in [0, 1, full.len() / 2, full.len() - 1] {
        assert!(extend(&index, &retained, &next.signed, &[&full[..end]], 0).is_err());
    }
    let mut tampered = full.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(extend(&index, &retained, &next.signed, &[&tampered], 0).is_err());
    let mut trailing = full;
    trailing.push(0);
    assert!(extend(&index, &retained, &next.signed, &[&trailing], 0).is_err());
}

#[test]
fn signed_roots_cannot_excuse_false_payload_selectors_or_an_omitted_account() {
    let (index, retained) = journal(&[entry(7, 100)], 7).baseline();
    let mut next = journal(&[entry(7, 100), entry(11, 10)], 11);
    next.envelopes[1].account_vids = vec![99];
    next.signed.checkpoint.root = root_of(
        &next
            .envelopes
            .iter()
            .map(|e| leaf_hash(&e.encode()))
            .collect::<Vec<_>>(),
    );
    next.signed.scope_index_root = index_root(&next.signed.checkpoint, &next.envelopes);
    assert!(matches!(
        extend(&index, &retained, &next.signed, &[&next.proof(1, true)], 0),
        Err(IndexAdvanceError::Record { .. })
    ));
    let mut next = journal(&[entry(7, 100), entry(11, 10)], 11);
    let mut omitted = next.envelopes.clone();
    for envelope in &mut omitted {
        envelope.account_vids.retain(|a| *a != 20);
    }
    next.signed.scope_index_root = index_root(&next.signed.checkpoint, &omitted);
    assert_eq!(
        extend(&index, &retained, &next.signed, &[&next.proof(1, true)], 0),
        Err(IndexAdvanceError::Derivation(PayloadIndexError::Root))
    );
}

#[test]
fn tree_append_is_insufficient_for_recorded_frontier_and_ordinal_consistency() {
    let (index, retained) = journal(&[entry(7, 100)], 9).baseline();
    for sequence in [7, 8, 9] {
        let next = journal(&[entry(7, 100), entry(sequence, 10)], 30);
        assert_eq!(
            extend(&index, &retained, &next.signed, &[&next.proof(1, true)], 0),
            Err(IndexAdvanceError::RecordedOrder { leaf_index: 1 })
        );
    }
    for [first, second] in [
        [entry(20, 10), entry(11, -10)],
        [entry(11, 10), entry(11, -10)],
    ] {
        let next = journal(&[entry(7, 100), first, second], 30);
        assert_eq!(
            extend(
                &index,
                &retained,
                &next.signed,
                &[&next.proof(1, true), &next.proof(2, true)],
                0
            ),
            Err(IndexAdvanceError::RecordedOrder { leaf_index: 2 })
        );
    }
}

#[test]
fn empty_growth_requires_the_same_index_and_maximum_sequence_is_not_incremented() {
    let (index, retained) = journal(&[entry(u64::MAX - 1, 10)], u64::MAX - 1).baseline();
    let next = journal(&[entry(u64::MAX - 1, 10), entry(u64::MAX, -10)], u64::MAX);
    let (advanced, tuples) =
        extend(&index, &retained, &next.signed, &[&next.proof(1, true)], 0).unwrap();
    assert_eq!(advanced.checkpoint.through_seq, u64::MAX);
    assert!(extend(&advanced, &tuples, &next.signed, &[], 0).is_ok());
    let mut false_root = next.signed;
    false_root.scope_index_root[0] ^= 1;
    assert_eq!(
        extend(&advanced, &tuples, &false_root, &[], 0),
        Err(IndexAdvanceError::Derivation(PayloadIndexError::Root))
    );
    let empty = journal(&[], 0);
    let (index, retained) = empty.baseline();
    assert!(extend(&index, &retained, &empty.signed, &[], 0).is_ok());
}

#[test]
fn byte_record_and_retained_leaf_limits_are_enforced_without_large_allocations() {
    assert_eq!(
        witness_budget(MAX_PRODUCTION_BYTES, 0, 0, &[]).unwrap(),
        MAX_PRODUCTION_BYTES
    );
    for (old, candidate, consistency) in [
        (MAX_PRODUCTION_BYTES, 1, 0),
        (usize::MAX, 1, 0),
        (0, 0, usize::MAX),
    ] {
        assert!(matches!(
            witness_budget(old, candidate, consistency, &[]),
            Err(IndexAdvanceError::Limit(_))
        ));
    }
    let empty: &[u8] = &[];
    assert!(matches!(
        witness_budget(0, 0, 0, &vec![empty; MAX_PRODUCTION_RECORDS + 1]),
        Err(IndexAdvanceError::Limit("delta record count"))
    ));
    let old = journal(&[], 0);
    let (index, retained) = old.baseline();
    let mut next = old.signed;
    next.checkpoint.leaf_count = MAX_PRODUCTION_LEAVES as u64 + 1;
    assert_eq!(
        extend(&index, &retained, &next, &[], 0),
        Err(IndexAdvanceError::Limit("retained leaf count"))
    );
}
