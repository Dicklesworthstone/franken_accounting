//! The scope index and `ScopeIndexComplete` proofs (plan §13.1, Appendix A
//! `ScopeIndex`).
//!
//! An accumulator proves sequence ranges; a filter by account and effective
//! day is complete only if nothing in scope can hide. The scope index makes
//! one such filter provable: every journal leaf with an effective day
//! contributes one tuple per account its envelope names,
//!
//! ```text
//! tuple = book_id [16] ‖ branch_id [16] ‖ account_vid u128 ‖ effective_day i32 ‖ leaf_index u64
//!         (60 bytes, little-endian), sorted by (account_vid, effective_day, leaf_index)
//! leaf  = BLAKE3("fa:scope-leaf:v1" ‖ tuple)
//! node  = BLAKE3("fa:scope-node:v1" ‖ left ‖ right)          (the RFC 9162 tree shape)
//! root  = BLAKE3("fa:scope-root:v1" ‖ count u64 ‖ tree_root)  (tree_root = 32 zero bytes when count = 0)
//! ```
//!
//! and every `TransparencyCheckpoint` commits the root of its prefix's
//! index. In that order one account's days form one contiguous run, so an
//! exact-account, inclusive day interval is proved complete by the run's
//! tuples at consecutive positions plus the neighbours on either side (or
//! the index's ends), each with its path. A whole-book interval or a set of
//! accounts is not one run and is refused (FA-REF-126): their honest forms
//! are the complete prefix (`SeqRangeComplete`) or a membership-only claim.
//!
//! The index is derived and rebuilt from the journal prefix every time; it
//! is never stored. No-claim boundary (plan §13.2): an index root a
//! checkpoint signer committed is not proof the index was derived
//! correctly. A verifier who wants that recomputes it from a verified
//! complete prefix; one who does not states the signer as the premise.

use fa_journal::KernelError;
use fa_journal::refusal::{Outcome, Refusal, exit};
use fa_model::{EncodeError, Id128, Writer};
use fgdb_crypto::Hasher;
use fgdb_types::VId;

use crate::code;
use crate::journal::Journal;
use crate::tree::{Digest, Tree};

pub const SCOPE_LEAF_DOMAIN: &[u8] = b"fa:scope-leaf:v1";
pub const SCOPE_NODE_DOMAIN: &[u8] = b"fa:scope-node:v1";
pub const SCOPE_ROOT_DOMAIN: &[u8] = b"fa:scope-root:v1";
pub const SCOPE_FORMAT: &[u8] = b"fa:scope-proof:v1";

/// One index tuple; the derived order is the index order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScopeTuple {
    pub account: u128,
    pub day: i32,
    pub leaf_index: u64,
}

impl ScopeTuple {
    #[must_use]
    pub fn bytes(&self, book_id: Id128, branch_id: Id128) -> [u8; 60] {
        let mut out = [0u8; 60];
        out[..16].copy_from_slice(&book_id.0);
        out[16..32].copy_from_slice(&branch_id.0);
        out[32..48].copy_from_slice(&self.account.to_le_bytes());
        out[48..52].copy_from_slice(&self.day.to_le_bytes());
        out[52..].copy_from_slice(&self.leaf_index.to_le_bytes());
        out
    }
}

fn hash(domain: &[u8], parts: &[&[u8]]) -> Digest {
    let mut h = Hasher::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    h.finalize().0
}

/// The committed root over `count` tuples whose tree root is `tree_root`.
#[must_use]
pub fn scope_root(count: u64, tree_root: &Digest) -> Digest {
    hash(SCOPE_ROOT_DOMAIN, &[&count.to_le_bytes(), tree_root])
}

/// A journal prefix's scope index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeIndex {
    book_id: Id128,
    branch_id: Id128,
    tuples: Vec<ScopeTuple>,
    tree: Tree,
}

impl ScopeIndex {
    /// Derive the index of `journal`'s prefix.
    #[must_use]
    pub fn of(journal: &Journal) -> Self {
        let mut tuples = Vec::new();
        for (i, leaf) in journal.leaves.iter().enumerate() {
            let Some(day) = leaf.envelope.effective_day else {
                continue;
            };
            for account in &leaf.envelope.account_vids {
                tuples.push(ScopeTuple {
                    account: account.0,
                    day,
                    leaf_index: i as u64,
                });
            }
        }
        tuples.sort_unstable();
        let mut tree = Tree::with_node_domain(SCOPE_NODE_DOMAIN);
        for t in &tuples {
            tree.push(hash(
                SCOPE_LEAF_DOMAIN,
                &[&t.bytes(journal.book_id, journal.branch_id)],
            ));
        }
        Self {
            book_id: journal.book_id,
            branch_id: journal.branch_id,
            tuples,
            tree,
        }
    }

    #[must_use]
    pub fn tuples(&self) -> &[ScopeTuple] {
        &self.tuples
    }

    /// The root a checkpoint commits.
    #[must_use]
    pub fn root(&self) -> Digest {
        let tree_root = if self.tuples.is_empty() {
            [0u8; 32]
        } else {
            self.tree.root()
        };
        scope_root(self.tuples.len() as u64, &tree_root)
    }

    /// Positions `[lo, hi)` of `account`'s tuples with `from ≤ day ≤ to`.
    #[must_use]
    pub fn range(&self, account: u128, from: i32, to: i32) -> (usize, usize) {
        let lo = self
            .tuples
            .partition_point(|t| (t.account, t.day) < (account, from));
        let hi = self
            .tuples
            .partition_point(|t| (t.account, t.day) <= (account, to));
        (lo, hi.max(lo))
    }

    fn path(&self, position: usize) -> Result<Vec<Digest>, KernelError> {
        self.tree
            .inclusion_path(position, self.tuples.len())
            .ok_or_else(|| KernelError::Corrupt("scope path outside the index".into()))
    }

    /// The `ScopeIndexComplete` proof of `account`'s entries with an
    /// effective day in `[from, to]` against `journal`'s statement:
    ///
    /// ```text
    /// bytes("fa:scope-proof:v1") ‖ Statement (80) ‖ count u64
    /// ‖ account u128 ‖ from i32 ‖ to i32 ‖ lo u64
    /// ‖ list(in-scope: day i32 ‖ leaf_index u64 ‖ list([32] scope path)
    ///        ‖ bytes(leaf envelope) ‖ list([32] accumulator path))
    /// ‖ opt(left neighbour:  account u128 ‖ day i32 ‖ leaf_index u64 ‖ list([32] scope path))
    /// ‖ opt(right neighbour: account u128 ‖ day i32 ‖ leaf_index u64 ‖ list([32] scope path))
    /// ```
    ///
    /// The neighbours are present exactly when the run does not touch that
    /// end of the index.
    pub fn proof(
        &self,
        journal: &Journal,
        account: u128,
        from: i32,
        to: i32,
    ) -> Result<Vec<u8>, KernelError> {
        let encode = |e: EncodeError| KernelError::Model(fa_model::EntryError::Encode(e));
        let (lo, hi) = self.range(account, from, to);
        let mut items = Vec::with_capacity(hi - lo);
        for position in lo..hi {
            let t = self.tuples[position];
            let leaf_at = usize::try_from(t.leaf_index)
                .map_err(|_| KernelError::Corrupt("leaf index beyond usize".into()))?;
            let leaf = journal
                .leaves
                .get(leaf_at)
                .ok_or_else(|| KernelError::Corrupt("scope tuple names no leaf".into()))?;
            let acc_path = journal
                .leaf_path(leaf_at)
                .ok_or_else(|| KernelError::Corrupt("inclusion path outside the tree".into()))?;
            items.push((
                t,
                self.path(position)?,
                leaf.envelope_bytes.as_slice(),
                acc_path,
            ));
        }
        let neighbour =
            |position: Option<usize>| -> Result<Option<(ScopeTuple, Vec<Digest>)>, KernelError> {
                match position {
                    Some(p) if p < self.tuples.len() => Ok(Some((self.tuples[p], self.path(p)?))),
                    _ => Ok(None),
                }
            };
        let left = neighbour(lo.checked_sub(1))?;
        let right = neighbour(Some(hi))?;
        let write_path = |w: &mut Writer, path: &Vec<Digest>| {
            w.list(path, |w, d| {
                w.fixed(d);
            });
        };
        let mut w = Writer::with_capacity(256 + items.len() * 1024);
        w.bytes(SCOPE_FORMAT);
        journal.statement().encode(&mut w);
        w.u64(self.tuples.len() as u64)
            .u128(account)
            .i32(from)
            .i32(to)
            .u64(lo as u64);
        w.list(&items, |w, (t, path, envelope, acc_path)| {
            w.i32(t.day).u64(t.leaf_index);
            write_path(w, path);
            w.bytes(envelope);
            write_path(w, acc_path);
        });
        for side in [&left, &right] {
            w.opt(side.as_ref(), |w, (t, path)| {
                w.u128(t.account).i32(t.day).u64(t.leaf_index);
                write_path(w, path);
            });
        }
        w.finish().map_err(encode)
    }
}

/// What a caller asks to prove complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeRequest {
    /// One account's entries with an effective day in `[from, to]`: one
    /// contiguous run of the index, provable as `ScopeIndexComplete`.
    Account { account: VId, from: i32, to: i32 },
    /// Every account's entries in `[from, to]`: not one run.
    Book { from: i32, to: i32 },
    /// A set of accounts (a list, a subtree) in `[from, to]`: per-account
    /// runs prove nothing about the accounts not named.
    Accounts {
        accounts: Vec<VId>,
        from: i32,
        to: i32,
    },
}

fn unsupported(message: String) -> Refusal {
    Refusal::new(
        code::SCOPE_UNSUPPORTED,
        exit::REFUSAL,
        message,
        "plan §13.1 (ScopeIndexComplete is admissible only for an exact-account effective-day interval)",
        "prove the complete prefix instead (`prove_prefix`, SeqRangeComplete) and apply the predicate to its envelopes, or claim membership only",
    )
}

/// The `ScopeIndexComplete` proof `request` asks for, against `journal`.
pub fn prove(journal: &Journal, request: &ScopeRequest) -> Outcome<Vec<u8>> {
    match request {
        ScopeRequest::Account { account, from, to } if from <= to => Ok(Ok(ScopeIndex::of(
            journal,
        )
        .proof(journal, account.0, *from, *to)?)),
        ScopeRequest::Account { from, to, .. } => Ok(Err(unsupported(format!(
            "the effective-day interval [{from}, {to}] is inverted"
        )))),
        ScopeRequest::Book { from, to } => Ok(Err(unsupported(format!(
            "a whole-book interval [{from}, {to}] is not one run of the scope index"
        )))),
        ScopeRequest::Accounts { accounts, from, to } => Ok(Err(unsupported(format!(
            "{} accounts in [{from}, {to}] are not one run of the scope index, and per-account proofs say nothing about the accounts not named",
            accounts.len()
        )))),
    }
}
