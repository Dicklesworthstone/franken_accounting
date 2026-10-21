//! `ScopeIndexComplete` (plan §13.1): one account's entries with an
//! effective day in an inclusive interval, proved complete against a signed
//! checkpoint's scope-index root.
//!
//! ```text
//! tuple = book_id [16] ‖ branch_id [16] ‖ account u128 ‖ effective_day i32 ‖ leaf_index u64
//!         one per (leaf with an effective day, account in its envelope),
//!         sorted by (account, effective_day, leaf_index)
//! leaf  = BLAKE3("fa:scope-leaf:v1" ‖ tuple)
//! node  = BLAKE3("fa:scope-node:v1" ‖ left ‖ right)          (the RFC 9162 tree shape)
//! root  = BLAKE3("fa:scope-root:v1" ‖ count u64 ‖ tree_root)  (tree_root = 32 zero bytes when count = 0)
//!
//! proof = bytes("fa:scope-proof:v1") ‖ Checkpoint (80) ‖ count u64
//!       ‖ account u128 ‖ from i32 ‖ to i32 ‖ lo u64
//!       ‖ list(day i32 ‖ leaf_index u64 ‖ list([32] scope path)
//!              ‖ bytes(leaf envelope) ‖ list([32] accumulator path))
//!       ‖ opt(left:  account u128 ‖ day i32 ‖ leaf_index u64 ‖ list([32] scope path))
//!       ‖ opt(right: account u128 ‖ day i32 ‖ leaf_index u64 ‖ list([32] scope path))
//! ```
//!
//! [`verify_scope`] checks that the listed tuples sit at consecutive
//! positions `[lo, hi)` of the signed index, that the neighbours at `lo − 1`
//! and `hi` exist exactly when the run does not touch that end and fall
//! outside the interval, that every tuple is in the interval and ascending,
//! and that each one's leaf envelope names the account and the day and is
//! included under the checkpoint's accumulator root. An empty interval is
//! the same check with `lo = hi`.
//!
//! The premise is labelled (plan §13.2): an index root is signed, not
//! self-evidently derived from the journal. With the complete prefix the
//! verifier recomputes the index ([`IndexDerivation::Recomputed`]);
//! without it the report names the signers it rests on
//! ([`IndexDerivation::Signed`]).

pub mod payloads;

use crate::blake3::hash_parts;
use crate::checkpoint::SignedCheckpoint;
use crate::codec::DecodeError;
use crate::envelope::LeafEnvelope;
use crate::proof::{
    Checkpoint, MAX_ENVELOPE_BYTES, VerifyError, open, read_path, trusted, verify_prefix, within,
};
use crate::tree::{Digest, leaf_hash, root_from_inclusion, root_from_inclusion_with, root_of_with};

pub const SCOPE_FORMAT: &[u8] = b"fa:scope-proof:v1";
pub const SCOPE_LEAF_DOMAIN: &[u8] = b"fa:scope-leaf:v1";
pub const SCOPE_NODE_DOMAIN: &[u8] = b"fa:scope-node:v1";
pub const SCOPE_ROOT_DOMAIN: &[u8] = b"fa:scope-root:v1";

pub const SCOPE_INDEX_COMPLETE: &str = "scope_index_complete";

/// Bound on listed in-scope tuples (allocation guard; the reader also
/// refuses a count the input cannot hold).
const MAX_SCOPE_TUPLES: usize = 1 << 24;

fn scope_node(left: &Digest, right: &Digest) -> Digest {
    hash_parts(SCOPE_NODE_DOMAIN, &[left, right])
}

fn tuple_leaf(cp: &Checkpoint, account: u128, day: i32, leaf_index: u64) -> Digest {
    hash_parts(
        SCOPE_LEAF_DOMAIN,
        &[
            &cp.book_id,
            &cp.branch_id,
            &account.to_le_bytes(),
            &day.to_le_bytes(),
            &leaf_index.to_le_bytes(),
        ],
    )
}

fn scope_root(count: u64, tree_root: &Digest) -> Digest {
    hash_parts(SCOPE_ROOT_DOMAIN, &[&count.to_le_bytes(), tree_root])
}

/// What the completeness of the index rests on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexDerivation {
    /// The index root is the one these keys signed; its derivation from
    /// the journal was not recomputed (a weaker, named premise).
    Signed { by: Vec<Digest> },
    /// The index was recomputed from the verified complete prefix and
    /// equals the signed root (FA-INV-14's recomputation).
    Recomputed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeReport {
    pub scope: &'static str,
    pub checkpoint: Checkpoint,
    pub account: u128,
    pub from: i32,
    pub to: i32,
    /// Every in-scope leaf with its index, ascending by (day, leaf index).
    pub leaves: Vec<(u64, LeafEnvelope)>,
    pub index_derivation: IndexDerivation,
}

struct Neighbour {
    account: u128,
    day: i32,
    leaf_index: u64,
    path: Vec<Digest>,
}

fn read_neighbour(r: &mut crate::codec::Reader<'_>) -> Result<Option<Neighbour>, DecodeError> {
    if !r.present("scope.neighbour")? {
        return Ok(None);
    }
    Ok(Some(Neighbour {
        account: r.u128("scope.neighbour.account")?,
        day: r.i32("scope.neighbour.day")?,
        leaf_index: r.u64("scope.neighbour.leaf_index")?,
        path: read_path(r)?,
    }))
}

/// The scope an outsider asks to have proved complete: one account's
/// entries with an effective day in `[from, to]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeClaim {
    pub account: u128,
    pub from: i32,
    pub to: i32,
}

/// Verify that `proof` shows `claim` complete against a checkpoint whose
/// signatures verified. The caller states the scope, as it states the
/// checkpoint it trusts: a proof of any other scope — even a true one — is
/// refused. With `complete_prefix` (a `seq_range_complete` proof of the
/// same checkpoint) the index is also recomputed and the premise becomes
/// [`IndexDerivation::Recomputed`].
pub fn verify_scope(
    proof: &[u8],
    signed: &SignedCheckpoint,
    claim: &ScopeClaim,
    complete_prefix: Option<&[u8]>,
) -> Result<ScopeReport, VerifyError> {
    let mut r = open(proof, SCOPE_FORMAT)?;
    let cp = trusted(Checkpoint::read(&mut r)?, &signed.checkpoint)?;
    let count = r.u64("scope.count")?;
    let account = r.u128("scope.account")?;
    let from = r.i32("scope.from")?;
    let to = r.i32("scope.to")?;
    if (ScopeClaim { account, from, to }) != *claim {
        return Err(VerifyError::ScopeClaim);
    }
    let lo = r.u64("scope.lo")?;
    let n = r.count(MAX_SCOPE_TUPLES, 4 + 8 + 4 + 4 + 4, "scope.tuples")?;
    let mut items = Vec::with_capacity(n);
    for _ in 0..n {
        let day = r.i32("scope.day")?;
        let leaf_index = r.u64("scope.leaf_index")?;
        let path = read_path(&mut r)?;
        let envelope = r.bytes(MAX_ENVELOPE_BYTES, "scope.envelope")?;
        let acc_path = read_path(&mut r)?;
        items.push((day, leaf_index, path, envelope, acc_path));
    }
    let left = read_neighbour(&mut r)?;
    let right = read_neighbour(&mut r)?;
    r.finish("scope")?;
    if from > to {
        return Err(VerifyError::ScopeRun);
    }

    // Positions: the run is [lo, hi), the neighbours exactly at lo − 1 and
    // hi when those exist.
    let hi = lo
        .checked_add(items.len() as u64)
        .ok_or(VerifyError::ScopeRun)?;
    if hi > count || left.is_some() != (lo > 0) || right.is_some() != (hi < count) {
        return Err(VerifyError::ScopeRun);
    }

    // Every listed tuple opens the same tree; that tree under `count` is
    // the signed root. With no tuples at all the index must be empty.
    let mut tree_root: Option<Digest> = None;
    let mut open_at = |position: u64, leaf: Digest, path: &[Digest]| -> Result<(), VerifyError> {
        let root = root_from_inclusion_with(scope_node, position, count, &leaf, path)
            .ok_or(VerifyError::ScopeRoot)?;
        match tree_root {
            Some(t) if t != root => Err(VerifyError::ScopeRoot),
            _ => {
                tree_root = Some(root);
                Ok(())
            }
        }
    };
    for (i, (day, leaf_index, path, _, _)) in items.iter().enumerate() {
        open_at(
            lo + i as u64,
            tuple_leaf(&cp, account, *day, *leaf_index),
            path,
        )?;
    }
    if let Some(l) = &left {
        open_at(
            lo - 1,
            tuple_leaf(&cp, l.account, l.day, l.leaf_index),
            &l.path,
        )?;
    }
    if let Some(rn) = &right {
        open_at(
            hi,
            tuple_leaf(&cp, rn.account, rn.day, rn.leaf_index),
            &rn.path,
        )?;
    }
    let tree_root = match tree_root {
        Some(t) => t,
        None if count == 0 => [0; 32],
        None => return Err(VerifyError::ScopeRun),
    };
    if scope_root(count, &tree_root) != signed.scope_index_root {
        return Err(VerifyError::ScopeRoot);
    }

    // Order and the interval: left < (account, from) ≤ run ≤ (account, to) < right.
    if let Some(l) = &left
        && (l.account, l.day) >= (account, from)
    {
        return Err(VerifyError::ScopeRun);
    }
    if let Some(rn) = &right
        && (rn.account, rn.day) <= (account, to)
    {
        return Err(VerifyError::ScopeRun);
    }
    let mut previous: Option<(i32, u64)> = None;
    let mut leaves = Vec::with_capacity(items.len());
    for (day, leaf_index, _, envelope_bytes, acc_path) in &items {
        let out_of_place =
            *day < from || *day > to || previous.is_some_and(|p| p >= (*day, *leaf_index));
        if out_of_place {
            return Err(VerifyError::ScopeTuple {
                leaf_index: *leaf_index,
            });
        }
        previous = Some((*day, *leaf_index));
        let envelope = LeafEnvelope::decode(envelope_bytes)?;
        within(&envelope, &cp)?;
        if envelope.effective_day != Some(*day)
            || envelope.account_vids.binary_search(&account).is_err()
        {
            return Err(VerifyError::ScopeTuple {
                leaf_index: *leaf_index,
            });
        }
        if root_from_inclusion(
            *leaf_index,
            cp.leaf_count,
            &leaf_hash(envelope_bytes),
            acc_path,
        ) != Some(cp.root)
        {
            return Err(VerifyError::Inclusion);
        }
        leaves.push((*leaf_index, envelope));
    }

    let index_derivation = match complete_prefix {
        None => IndexDerivation::Signed {
            by: signed.signed_by.clone(),
        },
        Some(prefix) => {
            recompute_index(prefix, signed)?;
            IndexDerivation::Recomputed
        }
    };
    Ok(ScopeReport {
        scope: SCOPE_INDEX_COMPLETE,
        checkpoint: cp,
        account,
        from,
        to,
        leaves,
        index_derivation,
    })
}

/// Rebuild the scope index from a verified complete prefix of the signed
/// checkpoint and require it to equal the signed root.
pub fn recompute_index(
    complete_prefix: &[u8],
    signed: &SignedCheckpoint,
) -> Result<(), VerifyError> {
    let prefix = verify_prefix(complete_prefix, &signed.checkpoint)?;
    let mut tuples: Vec<(u128, i32, u64)> = Vec::new();
    for (i, e) in prefix.envelopes.iter().enumerate() {
        if let Some(day) = e.effective_day {
            for account in &e.account_vids {
                tuples.push((*account, day, i as u64));
            }
        }
    }
    tuples.sort_unstable();
    let cp = &signed.checkpoint;
    let leaves: Vec<Digest> = tuples
        .iter()
        .map(|(a, d, i)| tuple_leaf(cp, *a, *d, *i))
        .collect();
    let tree_root = root_of_with(scope_node, &leaves);
    if scope_root(tuples.len() as u64, &tree_root) != signed.scope_index_root {
        return Err(VerifyError::ScopeIndexDerivation);
    }
    Ok(())
}
