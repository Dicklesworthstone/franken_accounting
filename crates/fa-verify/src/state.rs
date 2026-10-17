//! The journaled `AccumulatorState` object (plan §13.2, Appendix A).
//!
//! ```text
//! AccumulatorState = schema_major u16 (= 1) ‖ schema_minor u16 (= 0)
//!                    ‖ book_id [16] ‖ branch_id [16] ‖ through_seq u64
//!                    ‖ leaf_count u64 ‖ root [32] ‖ list([32] peaks)
//!                    ‖ opt([32] prev_state_oid)
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
    if minor > STATE_SCHEMA_MINOR_BOUNDARY {
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
    if minor == STATE_SCHEMA_MINOR_BOUNDARY {
        let boundary = r.u64("state.evidence_after_seq")?;
        if boundary == 0 || boundary > checkpoint.through_seq {
            return Err(r.error("state.evidence_after_seq", Reason::BadTag(0)));
        }
    }
    r.finish("accumulator state")?;
    Ok((checkpoint, peaks, prev_state_oid))
}

/// Decode a state and check it is internally consistent: one peak per set
/// bit of `leaf_count`, bagging to `root`.
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
        future[2] = 1;
        assert!(matches!(verify_state(&future), Err(VerifyError::Decode(_))));
        let mut long = bytes;
        long.push(0);
        assert!(matches!(verify_state(&long), Err(VerifyError::Decode(_))));
    }
}
