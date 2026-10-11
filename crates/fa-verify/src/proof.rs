//! The pinned proof formats and their verification (plan §13.1–§13.3).
//!
//! Every format is canonical bytes under the model's codec laws and opens
//! with its own format string, so a proof of one kind cannot be read as
//! another. A proof never carries its own trust: the caller supplies the
//! checkpoint it trusts (from a signed checkpoint, a witness, or an earlier
//! verified consistency proof), and the proof must name exactly that
//! checkpoint.
//!
//! ```text
//! Checkpoint       = book_id [16] ‖ branch_id [16] ‖ through_seq u64
//!                    ‖ leaf_count u64 ‖ root [32]                       (80 bytes)
//!
//! InclusionProof   = bytes("fa:acc-inclusion-proof:v1") ‖ Checkpoint
//!                    ‖ leaf_index u64 ‖ bytes(LeafEnvelope)
//!                    ‖ opt(proposal_len u32 ‖ bytes(record))  ‖ list([32] path)
//!
//! ConsistencyProof = bytes("fa:acc-consistency-proof:v1") ‖ Checkpoint old
//!                    ‖ Checkpoint new ‖ list([32] path)
//!
//! PrefixProof      = bytes("fa:acc-prefix-proof:v1") ‖ Checkpoint
//!                    ‖ list(bytes(LeafEnvelope))                         (every leaf)
//! ```
//!
//! What each proves, by scope label:
//!
//! - `inclusion`: the envelope (and, when the record is supplied, the
//!   record it was rebuilt from) is leaf `leaf_index` of the tree the
//!   trusted checkpoint names, recorded at or before `through_seq`.
//! - `consistency`: the claimed checkpoint's tree — its `leaf_count`
//!   leaves under its `root` — extends the trusted one's without rewriting
//!   any leaf, on the same book and branch. The tree cannot authenticate
//!   the `through_seq` a producer pairs with a size; that pairing comes from
//!   the state object the claim was read from (`verify_state`), so the
//!   caller names the checkpoint it was shown and the proof must match it.
//!   Nor can it show that the appended leaves were recorded after the old
//!   `through_seq` — their envelopes are not in it; known-at completeness
//!   across states needs the complete-prefix proof. What it does refuse is
//!   a later claim that contradicts the trusted one about the same
//!   sequence: more (or different) leaves at an equal `through_seq`.
//! - `seq_range_complete`: the listed envelopes are *every* leaf of the
//!   trusted checkpoint's prefix, in journal order, so a scope predicate
//!   over them is complete for that prefix — and for no later known-at.

use core::fmt;

use crate::blake3::hex;
use crate::codec::{DecodeError, Reader, Writer};
use crate::envelope::{LeafEnvelope, MAX_RECORD_BYTES, RecordError, check_record};
use crate::tree::{Digest, consistent, leaf_hash, root_from_inclusion, root_of};

pub const INCLUSION_FORMAT: &[u8] = b"fa:acc-inclusion-proof:v1";
pub const CONSISTENCY_FORMAT: &[u8] = b"fa:acc-consistency-proof:v1";
pub const PREFIX_FORMAT: &[u8] = b"fa:acc-prefix-proof:v1";

pub const SCOPE_INCLUSION: &str = "inclusion";
pub const SCOPE_CONSISTENCY: &str = "consistency";
pub const SCOPE_SEQ_RANGE_COMPLETE: &str = "seq_range_complete";

/// A path is at most one node per tree level.
const MAX_PATH: usize = 64;
/// A prefix proof lists every leaf; the bound only guards allocation (the
/// reader also refuses a count the input cannot hold).
const MAX_PREFIX_LEAVES: usize = 1 << 24;
pub(crate) const MAX_ENVELOPE_BYTES: usize =
    1 + 16 + 16 + 8 + 4 + 32 + 2 + 5 + 4 + 4 + 4096 * (16 + 4);

/// What a checkpoint commits: the root over the first `leaf_count` leaves
/// of one book branch's journal, which are exactly the records committed at
/// or before `through_seq`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub book_id: [u8; 16],
    pub branch_id: [u8; 16],
    pub through_seq: u64,
    pub leaf_count: u64,
    pub root: Digest,
}

impl Checkpoint {
    pub const ENCODED_LEN: usize = 16 + 16 + 8 + 8 + 32;

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            book_id: r.fixed("checkpoint.book_id")?,
            branch_id: r.fixed("checkpoint.branch_id")?,
            through_seq: r.u64("checkpoint.through_seq")?,
            leaf_count: r.u64("checkpoint.leaf_count")?,
            root: r.fixed("checkpoint.root")?,
        })
    }

    /// The canonical bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.fixed(&self.book_id)
            .fixed(&self.branch_id)
            .u64(self.through_seq)
            .u64(self.leaf_count)
            .fixed(&self.root);
        w.buf
    }
}

impl fmt::Display for Checkpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "book {} branch {} through seq {} ({} leaves) root {}",
            hex(&self.book_id),
            hex(&self.branch_id),
            self.through_seq,
            self.leaf_count,
            hex(&self.root)
        )
    }
}

/// Why a proof does not verify. Every variant is a refusal of the claim,
/// never a partial pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    Decode(DecodeError),
    /// The bytes open with another format string.
    Format {
        expected: &'static [u8],
    },
    /// The proof names a checkpoint other than the one the caller trusts.
    NotTrusted {
        proof: Box<Checkpoint>,
    },
    /// The proof extends to a checkpoint other than the one claimed.
    NotClaimed {
        proof: Box<Checkpoint>,
    },
    /// A leaf belongs to another book or branch than the checkpoint.
    Coordinate,
    /// A leaf was recorded after the checkpoint's prefix: its inclusion
    /// cannot be proved against it (and a known-at beyond `through_seq`
    /// needs a verified extension).
    AfterCheckpoint {
        commit_seq: u64,
        through_seq: u64,
    },
    /// The path does not lead from the leaf to the checkpoint's root.
    Inclusion,
    /// The path does not prove the new tree extends the trusted one.
    Consistency,
    /// The new checkpoint moves backwards, changes book or branch, or
    /// claims different leaves at the trusted checkpoint's own sequence.
    Regression,
    /// A complete-prefix proof lists a different number of leaves.
    LeafCount {
        listed: u64,
        expected: u64,
    },
    /// Leaves are not in strictly increasing `(commit_seq, ordinal)` order.
    Order {
        index: u64,
    },
    /// The complete prefix does not hash to the checkpoint's root.
    Root,
    /// The supplied record does not support the envelope.
    Record(RecordError),
    /// A balance proof's records are not exactly the in-scope leaves: the
    /// first leaf index that is missing or should not be there.
    RecordSet {
        index: u64,
    },
    /// A leg amount is negative or a sum overflowed `i128`.
    Arithmetic,
    /// The refold differs from the claim; these are the refolded sums.
    Claim {
        debits: i128,
        credits: i128,
    },
    /// The checkpoint's signatures do not verify ([`crate::checkpoint`]).
    Checkpoint(crate::checkpoint::CheckpointError),
    /// The scope proof answers another scope than the one asked.
    ScopeClaim,
    /// The scope proof's paths do not open the checkpoint's signed
    /// scope-index root.
    ScopeRoot,
    /// The scope proof does not show a gap-free run: positions not
    /// consecutive, a neighbour missing or inside the interval, or a run
    /// claimed to touch an end of the index it does not touch.
    ScopeRun,
    /// An in-scope tuple is outside the interval, out of order, or not
    /// what its leaf envelope says (the account or the effective day).
    ScopeTuple {
        leaf_index: u64,
    },
    /// The scope index recomputed from the complete prefix is not the one
    /// the checkpoint signs.
    ScopeIndexDerivation,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "{e}"),
            Self::Format { expected } => {
                write!(f, "not a `{}` proof", String::from_utf8_lossy(expected))
            }
            Self::NotTrusted { proof } => {
                write!(
                    f,
                    "the proof is against a checkpoint you did not trust: {proof}"
                )
            }
            Self::NotClaimed { proof } => {
                write!(
                    f,
                    "the proof extends to a checkpoint other than the one claimed: {proof}"
                )
            }
            Self::Coordinate => write!(f, "a leaf belongs to another book or branch"),
            Self::AfterCheckpoint {
                commit_seq,
                through_seq,
            } => write!(
                f,
                "the leaf was recorded at seq {commit_seq}, after the checkpoint's prefix (through seq {through_seq}); verify against a later checkpoint and a consistency proof"
            ),
            Self::Inclusion => write!(f, "the inclusion path does not reach the checkpoint's root"),
            Self::Consistency => write!(
                f,
                "the consistency path does not show the new tree extends the trusted one"
            ),
            Self::Regression => write!(
                f,
                "the new checkpoint is earlier than the trusted one, names another book or branch, or claims other leaves at the same sequence"
            ),
            Self::LeafCount { listed, expected } => write!(
                f,
                "the prefix lists {listed} leaves; the checkpoint commits {expected}"
            ),
            Self::Order { index } => write!(
                f,
                "leaf {index} is not after its predecessor in (commit_seq, ordinal) order"
            ),
            Self::Root => write!(f, "the listed leaves do not hash to the checkpoint's root"),
            Self::Record(RecordError::Decode(e)) => write!(f, "record: {e}"),
            Self::Record(RecordError::Split) => {
                write!(
                    f,
                    "record: the proposal length leaves no room for its envelope digests"
                )
            }
            Self::Record(RecordError::Digest { which }) => {
                write!(
                    f,
                    "record: {which} does not match its recomputation from the bytes"
                )
            }
            Self::Record(RecordError::Envelope) => {
                write!(
                    f,
                    "record: the envelope differs from the one its record determines"
                )
            }
            Self::RecordSet { index } => write!(
                f,
                "the records are not exactly the in-scope leaves (leaf {index} is missing or extra)"
            ),
            Self::Arithmetic => write!(f, "a leg amount is negative or a sum overflowed"),
            Self::Claim { debits, credits } => write!(
                f,
                "the journal refolds to debits {debits}, credits {credits}, not the claimed amounts"
            ),
            Self::Checkpoint(e) => write!(f, "checkpoint: {e}"),
            Self::ScopeClaim => write!(
                f,
                "the scope proof answers another scope than the one asked"
            ),
            Self::ScopeRoot => write!(
                f,
                "the scope paths do not open the checkpoint's signed scope-index root"
            ),
            Self::ScopeRun => write!(
                f,
                "the scope proof does not show a gap-free run with its neighbours outside the interval"
            ),
            Self::ScopeTuple { leaf_index } => write!(
                f,
                "the scope tuple for leaf {leaf_index} is outside the interval, out of order, or not what its envelope says"
            ),
            Self::ScopeIndexDerivation => write!(
                f,
                "the scope index recomputed from the complete prefix is not the one the checkpoint signs"
            ),
        }
    }
}

impl core::error::Error for VerifyError {}

impl From<DecodeError> for VerifyError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

/// Whether the record behind an included envelope was checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordCheck {
    /// Only the envelope was proved; the record was not supplied.
    NotSupplied,
    /// The record was supplied, its digests recomputed, and the envelope
    /// rebuilt from it byte-for-byte.
    Recomputed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inclusion {
    pub scope: &'static str,
    pub checkpoint: Checkpoint,
    pub leaf_index: u64,
    pub envelope: LeafEnvelope,
    pub record: RecordCheck,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Consistency {
    pub scope: &'static str,
    pub trusted: Checkpoint,
    /// The claimed checkpoint, whose tree is proved to extend `trusted`'s.
    pub extended: Checkpoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub scope: &'static str,
    pub checkpoint: Checkpoint,
    /// Every leaf of the prefix, in journal order.
    pub envelopes: Vec<LeafEnvelope>,
}

pub(crate) fn open<'a>(bytes: &'a [u8], format: &'static [u8]) -> Result<Reader<'a>, VerifyError> {
    let mut r = Reader::new(bytes);
    let tag = r.bytes(64, "proof.format")?;
    if tag != format {
        return Err(VerifyError::Format { expected: format });
    }
    Ok(r)
}

pub(crate) fn trusted(proof: Checkpoint, trusted: &Checkpoint) -> Result<Checkpoint, VerifyError> {
    if proof != *trusted {
        return Err(VerifyError::NotTrusted {
            proof: Box::new(proof),
        });
    }
    Ok(proof)
}

pub(crate) fn read_path(r: &mut Reader<'_>) -> Result<Vec<Digest>, DecodeError> {
    let n = r.count(MAX_PATH, 32, "proof.path")?;
    let mut path = Vec::with_capacity(n);
    for _ in 0..n {
        path.push(r.fixed("proof.path.node")?);
    }
    Ok(path)
}

pub(crate) fn within(envelope: &LeafEnvelope, cp: &Checkpoint) -> Result<(), VerifyError> {
    if envelope.book_id != cp.book_id || envelope.branch_id != cp.branch_id {
        return Err(VerifyError::Coordinate);
    }
    if envelope.commit_seq > cp.through_seq {
        return Err(VerifyError::AfterCheckpoint {
            commit_seq: envelope.commit_seq,
            through_seq: cp.through_seq,
        });
    }
    Ok(())
}

/// Verify an inclusion proof against the checkpoint the caller trusts.
pub fn verify_inclusion(
    proof: &[u8],
    trusted_checkpoint: &Checkpoint,
) -> Result<Inclusion, VerifyError> {
    let mut r = open(proof, INCLUSION_FORMAT)?;
    let checkpoint = trusted(Checkpoint::read(&mut r)?, trusted_checkpoint)?;
    let leaf_index = r.u64("proof.leaf_index")?;
    let envelope_bytes = r.bytes(MAX_ENVELOPE_BYTES, "proof.envelope")?;
    let record = if r.present("proof.record")? {
        let proposal_len =
            usize::try_from(r.u32("proof.record.proposal_len")?).unwrap_or(usize::MAX);
        Some((proposal_len, r.bytes(MAX_RECORD_BYTES, "proof.record")?))
    } else {
        None
    };
    let path = read_path(&mut r)?;
    r.finish("inclusion proof")?;

    let envelope = LeafEnvelope::decode(envelope_bytes)?;
    within(&envelope, &checkpoint)?;
    let root = root_from_inclusion(
        leaf_index,
        checkpoint.leaf_count,
        &leaf_hash(envelope_bytes),
        &path,
    );
    if root != Some(checkpoint.root) {
        return Err(VerifyError::Inclusion);
    }
    let record = match record {
        None => RecordCheck::NotSupplied,
        Some((proposal_len, payload)) => {
            check_record(&envelope, payload, proposal_len).map_err(VerifyError::Record)?;
            RecordCheck::Recomputed
        }
    };
    Ok(Inclusion {
        scope: SCOPE_INCLUSION,
        checkpoint,
        leaf_index,
        envelope,
        record,
    })
}

/// Verify that `claimed` — a later checkpoint, read from the state object
/// a producer presents — extends the one the caller trusts.
pub fn verify_consistency(
    proof: &[u8],
    trusted_checkpoint: &Checkpoint,
    claimed: &Checkpoint,
) -> Result<Consistency, VerifyError> {
    let mut r = open(proof, CONSISTENCY_FORMAT)?;
    let old = trusted(Checkpoint::read(&mut r)?, trusted_checkpoint)?;
    let new = Checkpoint::read(&mut r)?;
    if new != *claimed {
        return Err(VerifyError::NotClaimed {
            proof: Box::new(new),
        });
    }
    let path = read_path(&mut r)?;
    r.finish("consistency proof")?;
    // A checkpoint says its leaves are exactly the records through its
    // sequence, so at an equal sequence the two must be the same tree: more
    // leaves need a later sequence.
    let same_seq_other_tree = new.through_seq == old.through_seq
        && (new.leaf_count, new.root) != (old.leaf_count, old.root);
    if new.book_id != old.book_id
        || new.branch_id != old.branch_id
        || new.through_seq < old.through_seq
        || new.leaf_count < old.leaf_count
        || same_seq_other_tree
    {
        return Err(VerifyError::Regression);
    }
    if !consistent(old.leaf_count, new.leaf_count, &old.root, &new.root, &path) {
        return Err(VerifyError::Consistency);
    }
    Ok(Consistency {
        scope: SCOPE_CONSISTENCY,
        trusted: old,
        extended: new,
    })
}

/// Verify a complete-prefix proof: every leaf of the trusted checkpoint, in
/// journal order, hashing to its root.
pub fn verify_prefix(proof: &[u8], trusted_checkpoint: &Checkpoint) -> Result<Prefix, VerifyError> {
    let mut r = open(proof, PREFIX_FORMAT)?;
    let checkpoint = trusted(Checkpoint::read(&mut r)?, trusted_checkpoint)?;
    let raw = read_envelopes(&mut r)?;
    r.finish("prefix proof")?;
    let envelopes = complete_prefix(&raw, &checkpoint)?;
    Ok(Prefix {
        scope: SCOPE_SEQ_RANGE_COMPLETE,
        checkpoint,
        envelopes,
    })
}

/// A list of encoded leaf envelopes.
pub(crate) fn read_envelopes<'a>(r: &mut Reader<'a>) -> Result<Vec<&'a [u8]>, DecodeError> {
    let n = r.count(MAX_PREFIX_LEAVES, 4, "proof.envelopes")?;
    let mut raw = Vec::with_capacity(n);
    for _ in 0..n {
        raw.push(r.bytes(MAX_ENVELOPE_BYTES, "proof.envelope")?);
    }
    Ok(raw)
}

/// Check that `raw` is every leaf of `checkpoint`'s prefix, in journal
/// order, on its book and branch, hashing to its root; return the decoded
/// envelopes.
pub(crate) fn complete_prefix(
    raw: &[&[u8]],
    checkpoint: &Checkpoint,
) -> Result<Vec<LeafEnvelope>, VerifyError> {
    let n = raw.len();
    let listed = u64::try_from(n).unwrap_or(u64::MAX);
    if listed != checkpoint.leaf_count {
        return Err(VerifyError::LeafCount {
            listed,
            expected: checkpoint.leaf_count,
        });
    }
    let mut envelopes = Vec::with_capacity(n);
    let mut leaves = Vec::with_capacity(n);
    for (i, bytes) in raw.iter().enumerate() {
        let envelope = LeafEnvelope::decode(bytes)?;
        within(&envelope, checkpoint)?;
        if let Some(prev) = envelopes.last().map(LeafEnvelope::position)
            && prev >= envelope.position()
        {
            return Err(VerifyError::Order {
                index: u64::try_from(i).unwrap_or(u64::MAX),
            });
        }
        leaves.push(leaf_hash(bytes));
        envelopes.push(envelope);
    }
    if root_of(&leaves) != checkpoint.root {
        return Err(VerifyError::Root);
    }
    Ok(envelopes)
}
