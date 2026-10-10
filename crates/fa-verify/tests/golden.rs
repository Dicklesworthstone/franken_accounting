//! The pinned accumulator vectors, verified with nothing but this crate.
//!
//! `fixtures/accumulator_v1.txt` holds two journaled states (a 2-leaf
//! prefix through seq 4, and the 4-leaf prefix through seq 6 that names it
//! as its predecessor), an inclusion proof with its entry payload, a
//! consistency proof between the two states, and the complete prefix. The
//! producer (`fa-notary`) must reproduce these bytes exactly; here the
//! verifier must accept them — and refuse every one of them once altered.

use fa_verify::{
    Checkpoint, RecordCheck, VerifyError, verify_consistency, verify_inclusion, verify_prefix,
    verify_state,
};

const FIXTURE: &str = include_str!("fixtures/accumulator_v1.txt");

/// Whether a verifier accepts a vector as the one pinned.
type Accepts<'a> = &'a dyn Fn(&[u8]) -> bool;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn vector(name: &str) -> Vec<u8> {
    let line = FIXTURE
        .lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
        .unwrap_or("");
    assert!(!line.is_empty(), "fixture has no `{name}` vector");
    unhex(line)
}

#[test]
fn the_pinned_states_chain_and_commit_their_checkpoints() {
    let old = verify_state(&vector("old_state")).expect("old state verifies");
    let new = verify_state(&vector("state")).expect("state verifies");
    assert_eq!(old.prev_state_oid, None);
    assert_eq!(
        new.prev_state_oid,
        Some(old.oid),
        "the state chains to its predecessor"
    );
    assert_eq!(
        (old.checkpoint.through_seq, old.checkpoint.leaf_count),
        (4, 2)
    );
    assert_eq!(
        (new.checkpoint.through_seq, new.checkpoint.leaf_count),
        (6, 4)
    );
    assert_eq!(new.checkpoint.book_id, [0x5a; 16]);
    assert_eq!(new.checkpoint.branch_id, [0; 16]);
    assert_eq!(new.peaks.len(), 1);
    assert_eq!(old.peaks.len(), 1);
}

#[test]
fn the_pinned_inclusion_proof_verifies_with_its_record() {
    let state = verify_state(&vector("state")).unwrap();
    let report = verify_inclusion(&vector("inclusion"), &state.checkpoint).expect("verifies");
    assert_eq!(report.scope, "inclusion");
    assert_eq!(report.leaf_index, 3);
    assert_eq!(report.record, RecordCheck::Recomputed);
    let e = &report.envelope;
    assert_eq!((e.commit_seq, e.within_commit_ordinal), (5, 1));
    assert_eq!(e.class, 1);
    assert_eq!(e.effective_day, Some(20_527));
    assert_eq!(e.account_vids, vec![0x10, 0x20, 0x30]);
    assert_eq!(e.unit_ids, vec![1, 2]);

    // Against the earlier state it is a different checkpoint; against a
    // checkpoint with one altered field it is not trusted.
    let old = verify_state(&vector("old_state")).unwrap();
    assert!(matches!(
        verify_inclusion(&vector("inclusion"), &old.checkpoint),
        Err(VerifyError::NotTrusted { .. })
    ));
    let mut moved = state.checkpoint;
    moved.through_seq += 1;
    assert!(matches!(
        verify_inclusion(&vector("inclusion"), &moved),
        Err(VerifyError::NotTrusted { .. })
    ));
}

#[test]
fn the_pinned_consistency_and_prefix_proofs_verify() {
    let old = verify_state(&vector("old_state")).unwrap();
    let new = verify_state(&vector("state")).unwrap();
    let report = verify_consistency(&vector("consistency"), &old.checkpoint, &new.checkpoint)
        .expect("extends");
    assert_eq!(report.extended, new.checkpoint);

    let prefix = verify_prefix(&vector("prefix"), &new.checkpoint).expect("complete");
    assert_eq!(prefix.envelopes.len(), 4);
    let positions: Vec<(u64, u32)> = prefix
        .envelopes
        .iter()
        .map(|e| (e.commit_seq, e.within_commit_ordinal))
        .collect();
    assert_eq!(positions, vec![(2, 0), (4, 0), (5, 0), (5, 1)]);
    // The schema control is undated; everything else carries its day.
    assert_eq!(prefix.envelopes[0].effective_day, None);
    assert!(
        prefix.envelopes[1..]
            .iter()
            .all(|e| e.effective_day.is_some())
    );
}

/// Every single-bit change to any pinned vector is refused.
#[test]
fn every_pinned_vector_refuses_every_flipped_bit() {
    // A state is trusted by its oid: any altered byte is another object.
    let old_state = verify_state(&vector("old_state")).unwrap();
    let new_state = verify_state(&vector("state")).unwrap();
    let (old, new) = (old_state.checkpoint, new_state.checkpoint);
    let s3 = verify_state(&vector("state_3")).unwrap();
    let s5 = verify_state(&vector("state_5")).unwrap();
    let checks: [(&str, Accepts<'_>); 8] = [
        ("old_state", &|b| {
            verify_state(b).is_ok_and(|s| s.oid == old_state.oid)
        }),
        ("state", &|b| {
            verify_state(b).is_ok_and(|s| s.oid == new_state.oid)
        }),
        ("inclusion", &|b| verify_inclusion(b, &new).is_ok()),
        ("consistency", &|b| {
            verify_consistency(b, &old, &new).is_ok()
        }),
        ("prefix", &|b| verify_prefix(b, &new).is_ok()),
        ("state_3", &|b| {
            verify_state(b).is_ok_and(|s| s.oid == s3.oid)
        }),
        ("state_5", &|b| {
            verify_state(b).is_ok_and(|s| s.oid == s5.oid)
        }),
        ("consistency_3_5", &|b| {
            verify_consistency(b, &s3.checkpoint, &s5.checkpoint).is_ok()
        }),
    ];
    for (name, accepts) in checks {
        let bytes = vector(name);
        assert!(accepts(&bytes), "{name} must verify unaltered");
        for i in 0..bytes.len() {
            for bit in [0x01u8, 0x10, 0x80] {
                let mut t = bytes.clone();
                t[i] ^= bit;
                assert!(
                    !accepts(&t),
                    "{name}: byte {i} bit {bit:#x} flipped and still accepted"
                );
            }
        }
    }
}

#[test]
fn a_checkpoint_encodes_to_its_80_bytes() {
    let state = verify_state(&vector("state")).unwrap();
    let cp: Checkpoint = state.checkpoint;
    let bytes = cp.encode();
    assert_eq!(bytes.len(), Checkpoint::ENCODED_LEN);
    // Every proof embeds the checkpoint right after its format string.
    let inclusion = vector("inclusion");
    let at = 4 + b"fa:acc-inclusion-proof:v1".len();
    assert_eq!(&inclusion[at..at + Checkpoint::ENCODED_LEN], &bytes[..]);
}

/// The 3 → 5 vector takes the non-power-of-two branch of RFC 9162
/// consistency verification; it must hold there too, and only there.
#[test]
fn the_pinned_odd_sized_consistency_proof_verifies() {
    let s3 = verify_state(&vector("state_3")).expect("3-leaf state");
    let s5 = verify_state(&vector("state_5")).expect("5-leaf state");
    assert_eq!(s5.prev_state_oid, Some(s3.oid));
    assert_eq!(
        (
            s3.checkpoint.through_seq,
            s3.checkpoint.leaf_count,
            s3.peaks.len()
        ),
        (3, 3, 2)
    );
    assert_eq!(
        (
            s5.checkpoint.through_seq,
            s5.checkpoint.leaf_count,
            s5.peaks.len()
        ),
        (5, 5, 2)
    );
    let proof = vector("consistency_3_5");
    let report = verify_consistency(&proof, &s3.checkpoint, &s5.checkpoint).expect("extends");
    assert_eq!(report.extended, s5.checkpoint);
    // The same path against the 2→4 pair names other checkpoints.
    let old = verify_state(&vector("old_state")).unwrap();
    assert!(matches!(
        verify_consistency(&proof, &old.checkpoint, &s5.checkpoint),
        Err(VerifyError::NotTrusted { .. })
    ));
}
