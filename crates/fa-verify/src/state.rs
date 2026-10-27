//! The journaled `AccumulatorState` object (plan §13.2, Appendix A).
//!
//! ```text
//! AccumulatorState = schema_major u16 (= 1) ‖ schema_minor u16 (= 0 | 1 | 2)
//!                    ‖ book_id [16] ‖ branch_id [16] ‖ through_seq u64
//!                    ‖ leaf_count u64 ‖ root [32] ‖ list([32] peaks)
//!                    ‖ opt([32] prev_state_oid)
//!                    ‖ evidence_after_seq u64                         (minor >= 1)
//!                    ‖ access_after_seq u64                           (minor = 2)
//! oid              = BLAKE3("fa:accumulator-state:v1" ‖ canonical bytes)
//! ```
//!
//! The state is content-addressed and self-checking: its peaks are the
//! roots of the perfect subtrees of `leaf_count`'s binary decomposition and
//! must bag to `root`. An outsider who trusts a state's oid (published,
//! witnessed, or reached through `prev_state_oid` links from one they
//! trust) gets the [`Checkpoint`] to verify proofs against.
//!
//! The state object itself is unsigned, and [`State::signatures`] says so.
//! The signed object is the `TransparencyCheckpoint` journaled beside it,
//! which names this state's oid: [`crate::verify_checkpoint`].

use crate::blake3::hash_parts;
use crate::codec::{DecodeError, Reader, Reason};
use crate::proof::{Checkpoint, VerifyError};
use crate::tree::{Digest, bag_peaks};

pub const STATE_OID_DOMAIN: &[u8] = b"fa:accumulator-state:v1";
pub const STATE_SCHEMA_MAJOR: u16 = 1;
pub const STATE_SCHEMA_MINOR: u16 = 0;
pub const STATE_SCHEMA_MINOR_BOUNDARY: u16 = 1;
pub const STATE_SCHEMA_MINOR_ACCESS_BOUNDARY: u16 = 2;

/// Whether the checkpoint carries signatures a verifier checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signatures {
    /// The state object carries no signature: on its own it is exactly as
    /// trustworthy as the channel its oid came through. A signed
    /// `TransparencyCheckpoint` naming its oid is what binds it to a key
    /// ([`crate::verify_checkpoint`]).
    Unsigned,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub checkpoint: Checkpoint,
    pub peaks: Vec<Digest>,
    pub prev_state_oid: Option<Digest>,
    pub oid: Digest,
    pub signatures: Signatures,
}

/// `BLAKE3("fa:accumulator-state:v1" ‖ bytes)`.
#[must_use]
pub fn state_oid(bytes: &[u8]) -> Digest {
    hash_parts(STATE_OID_DOMAIN, &[bytes])
}

fn decode(bytes: &[u8]) -> Result<(Checkpoint, Vec<Digest>, Option<Digest>), DecodeError> {
    let mut r = Reader::new(bytes);
    let major = r.u16("state.schema_major")?;
    if major != STATE_SCHEMA_MAJOR {
        return Err(r.error("state.schema_major", Reason::BadTag(major.to_le_bytes()[0])));
    }
    let minor = r.u16("state.schema_minor")?;
    if minor > STATE_SCHEMA_MINOR_ACCESS_BOUNDARY {
        return Err(r.error("state.schema_minor", Reason::BadTag(minor.to_le_bytes()[0])));
    }
    let checkpoint = Checkpoint {
        book_id: r.fixed("state.book_id")?,
        branch_id: r.fixed("state.branch_id")?,
        through_seq: r.u64("state.through_seq")?,
        leaf_count: r.u64("state.leaf_count")?,
        root: r.fixed("state.root")?,
    };
    let n = r.count(64, 32, "state.peaks")?;
    let mut peaks = Vec::with_capacity(n);
    for _ in 0..n {
        peaks.push(r.fixed("state.peak")?);
    }
    let prev_state_oid = if r.present("state.prev_state_oid")? {
        Some(r.fixed("state.prev_state_oid")?)
    } else {
        None
    };
    let evidence_after_seq = if minor >= STATE_SCHEMA_MINOR_BOUNDARY {
        let boundary = r.u64("state.evidence_after_seq")?;
        if boundary == 0 || boundary > checkpoint.through_seq {
            return Err(r.error("state.evidence_after_seq", Reason::BadTag(0)));
        }
        boundary
    } else {
        0
    };
    if minor == STATE_SCHEMA_MINOR_ACCESS_BOUNDARY {
        let boundary = r.u64("state.access_after_seq")?;
        if boundary == 0 || boundary > checkpoint.through_seq || boundary < evidence_after_seq {
            return Err(r.error("state.access_after_seq", Reason::BadTag(0)));
        }
    }
    r.finish("accumulator state")?;
    Ok((checkpoint, peaks, prev_state_oid))
}

/// Decode a state and check it is internally consistent: one peak per set
/// bit of `leaf_count`, bagging to `root`, and valid versioned coverage cuts.
/// A standalone state does not authenticate transitions from its predecessors.
pub fn verify_state(bytes: &[u8]) -> Result<State, VerifyError> {
    let (checkpoint, peaks, prev_state_oid) = decode(bytes)?;
    if u64::try_from(peaks.len()).ok() != Some(u64::from(checkpoint.leaf_count.count_ones()))
        || bag_peaks(&peaks) != checkpoint.root
    {
        return Err(VerifyError::Root);
    }
    Ok(State {
        checkpoint,
        peaks,
        prev_state_oid,
        oid: state_oid(bytes),
        signatures: Signatures::Unsigned,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Writer;
    use crate::tree::{empty_root, leaf_hash, node_hash};

    fn encode(cp: &Checkpoint, peaks: &[Digest], prev: Option<Digest>) -> Vec<u8> {
        let mut w = Writer::default();
        w.u16(1)
            .u16(0)
            .fixed(&cp.book_id)
            .fixed(&cp.branch_id)
            .u64(cp.through_seq)
            .u64(cp.leaf_count)
            .fixed(&cp.root)
            .count(peaks.len());
        for p in peaks {
            w.fixed(p);
        }
        match prev {
            None => {
                w.u8(0);
            }
            Some(o) => {
                w.u8(1).fixed(&o);
            }
        }
        w.buf
    }

    #[test]
    fn a_state_verifies_only_when_its_peaks_bag_to_its_root() {
        let (a, b, c) = (leaf_hash(b"a"), leaf_hash(b"b"), leaf_hash(b"c"));
        let ab = node_hash(&a, &b);
        let cp = Checkpoint {
            book_id: [8; 16],
            branch_id: [0; 16],
            through_seq: 9,
            leaf_count: 3,
            root: node_hash(&ab, &c),
        };
        let bytes = encode(&cp, &[ab, c], Some([4; 32]));
        let state = verify_state(&bytes).unwrap();
        assert_eq!(state.checkpoint, cp);
        assert_eq!(state.prev_state_oid, Some([4; 32]));
        assert_eq!(state.oid, state_oid(&bytes));
        assert_eq!(state.signatures, Signatures::Unsigned);

        // A wrong peak, a missing peak, or a size the peaks do not fit.
        assert_eq!(
            verify_state(&encode(&cp, &[ab, a], None)),
            Err(VerifyError::Root)
        );
        assert_eq!(
            verify_state(&encode(&cp, &[ab], None)),
            Err(VerifyError::Root)
        );
        let mut four = cp;
        four.leaf_count = 4;
        assert_eq!(
            verify_state(&encode(&four, &[ab, c], None)),
            Err(VerifyError::Root)
        );

        let empty = Checkpoint {
            leaf_count: 0,
            root: empty_root(),
            ..cp
        };
        assert!(verify_state(&encode(&empty, &[], None)).is_ok());

        let mut future = bytes.clone();
        future[2] = 3;
        assert!(matches!(verify_state(&future), Err(VerifyError::Decode(_))));
        let mut long = bytes;
        long.push(0);
        assert!(matches!(verify_state(&long), Err(VerifyError::Decode(_))));
    }

    fn versioned(base: &[u8], minor: u16, boundaries: &[u64]) -> Vec<u8> {
        let mut bytes = base.to_vec();
        bytes[2..4].copy_from_slice(&minor.to_le_bytes());
        for boundary in boundaries {
            bytes.extend_from_slice(&boundary.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn access_coverage_states_preserve_legacy_bytes_and_bind_both_boundaries() {
        let peak = leaf_hash(b"access event");
        let cp = Checkpoint {
            book_id: [8; 16],
            branch_id: [0; 16],
            through_seq: 42,
            leaf_count: 1,
            root: peak,
        };
        let base = encode(&cp, &[peak], Some([7; 32]));
        let legacy = verify_state(&base).unwrap();
        let evidence_bytes = versioned(&base, 1, &[5]);
        let evidence = verify_state(&evidence_bytes).unwrap();
        assert_eq!(evidence.checkpoint, legacy.checkpoint);
        assert_eq!(evidence.prev_state_oid, legacy.prev_state_oid);
        assert_ne!(evidence.oid, legacy.oid);
        assert_eq!(&evidence_bytes[..2], &base[..2]);
        assert_eq!(&evidence_bytes[4..base.len()], &base[4..]);

        let mut oids = std::collections::BTreeSet::new();
        for boundaries in [[1, 1], [1, 42], [42, 42], [5, 9], [5, 10], [4, 9]] {
            let bytes = versioned(&base, 2, &boundaries);
            let state = verify_state(&bytes).unwrap();
            assert_eq!(state.checkpoint, cp);
            assert_eq!(state.peaks, vec![peak]);
            assert_eq!(state.prev_state_oid, Some([7; 32]));
            assert_eq!(state.signatures, Signatures::Unsigned);
            assert_eq!(state.oid, hash_parts(STATE_OID_DOMAIN, &[&bytes]));
            assert_ne!(state.oid, legacy.oid);
            assert_ne!(state.oid, evidence.oid);
            assert!(
                oids.insert(state.oid),
                "both appended boundaries affect identity"
            );
            assert_eq!(&bytes[..2], &base[..2]);
            assert_eq!(&bytes[4..base.len()], &base[4..]);
        }
    }

    #[test]
    fn access_coverage_states_refuse_invalid_missing_or_out_of_order_boundaries() {
        let cp = Checkpoint {
            book_id: [8; 16],
            branch_id: [0; 16],
            through_seq: 42,
            leaf_count: 0,
            root: empty_root(),
        };
        let base = encode(&cp, &[], None);
        for (boundaries, field) in [
            ([0, 1], "state.evidence_after_seq"),
            ([43, 43], "state.evidence_after_seq"),
            ([u64::MAX, u64::MAX], "state.evidence_after_seq"),
            ([1, 0], "state.access_after_seq"),
            ([6, 5], "state.access_after_seq"),
            ([1, 43], "state.access_after_seq"),
            ([1, u64::MAX], "state.access_after_seq"),
        ] {
            let Err(VerifyError::Decode(error)) = verify_state(&versioned(&base, 2, &boundaries))
            else {
                panic!("invalid boundaries must refuse: {boundaries:?}");
            };
            assert_eq!(error.what, field);
        }
        for (minor, boundaries) in [(1, vec![]), (2, vec![]), (2, vec![1])] {
            assert!(matches!(
                verify_state(&versioned(&base, minor, &boundaries)),
                Err(VerifyError::Decode(_))
            ));
        }
        for (minor, boundaries) in [
            (0, vec![1]),
            (1, vec![1, 2]),
            (2, vec![1, 2, 3]),
            (3, vec![1, 2]),
        ] {
            assert!(matches!(
                verify_state(&versioned(&base, minor, &boundaries)),
                Err(VerifyError::Decode(_))
            ));
        }
        let valid = versioned(&base, 2, &[1, 42]);
        for end in 0..valid.len() {
            assert!(
                matches!(verify_state(&valid[..end]), Err(VerifyError::Decode(_))),
                "truncation at {end}"
            );
        }
        let zero = encode(
            &Checkpoint {
                through_seq: 0,
                ..cp
            },
            &[],
            None,
        );
        assert!(matches!(
            verify_state(&versioned(&zero, 2, &[1, 1])),
            Err(VerifyError::Decode(_))
        ));
    }
}
