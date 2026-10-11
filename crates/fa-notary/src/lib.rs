//! Notary — the journal accumulator (plan §13.2, FA-INV-14).
//!
//! Every committed entry — posting and control classes alike — is one leaf
//! of a Merkle Mountain Range, in commit order, over a domain-separated
//! leaf envelope that binds the entry's digest, its recorded commit
//! sequence, and its selection fields ([`journal`]). The accumulator is a
//! derived, rebuildable structure: its root at any sequence is a pure
//! function of the journal prefix, recomputed from the authoritative
//! payloads, never maintained inside the posting transaction ([`tree`]).
//!
//! The notary journals [`AccumulatorState`] objects — content-addressed,
//! chained by `prev_state_oid` under a compare-and-set on the book's head
//! pointer — and [`verify_accumulator`] recomputes every one of them from
//! the journal. Proofs are issued only against a state the journal
//! reproduces, in the byte formats the dependency-free `fa-verify` checks:
//! inclusion of an entry (optionally with its own payload), consistency
//! between two states, the complete prefix (`SeqRangeComplete`), and one
//! account's effective-day interval (`ScopeIndexComplete`, [`scope`]).
//!
//! Beside each state stands a [`checkpoint::TransparencyCheckpoint`]
//! signed by the book's key ([`sign`]): the state's statement, the prefix's
//! scope-index root, and the substrate's chain commitment at the same
//! sequence.
//!
//! A production is an evidence [`bundle`] (`.fab`): a deterministic body
//! carrying the signed checkpoint, the completeness proof of its scope, the
//! in-scope entries' payloads with their cited documents, and balance
//! proofs under a named fold law — and a detached [`ProductionReceipt`]
//! the book's key signs over the body's digest.
//!
//! Not here yet, by name: witness signatures and `WitnessPolicy`, the
//! `TrustAnchorSet` and key rotation (the verifier is given the book's
//! public key out of band), and the MMR cross-anchor (R-MMR) replacing the
//! chain commitment.

#![forbid(unsafe_code)]

pub mod bundle;
pub mod checkpoint;
pub mod journal;
pub mod scope;
pub mod sign;
pub mod state;
pub mod tree;

use fa_model::{Id128, Writer};
use fgdb_types::CommitSeq;

pub use bundle::{
    BalanceRequest, Bundle, BundleRequest, BundleScope, DocumentStub, ProductionReceipt,
    ReceiptBody,
};
pub use checkpoint::TransparencyCheckpoint;
pub use journal::{Journal, Leaf, LeafEnvelope};
pub use scope::{ScopeIndex, ScopeRequest};
pub use sign::{CheckpointSigner, SigningKey};
pub use state::{
    AccumulatorState, AccumulatorVerification, Checkpointed, StateCheck, StoredCheckpoint,
    StoredState, bundle_basis, chain, checkpoint, latest, prove_balance, prove_consistency,
    prove_inclusion, prove_prefix, prove_scope, state_oid, state_vid, stored_checkpoint,
    verify_accumulator,
};

/// Refusal codes the notary issues (`FA-REF-12x`).
pub mod code {
    /// The entry is not in the selected accumulator prefix.
    pub const NOT_IN_PREFIX: &str = "FA-REF-120";
    /// The journal does not reproduce or extend a journaled state.
    pub const ACCUMULATOR_DRIFT: &str = "FA-REF-121";
    /// Another state was published from the same head.
    pub const HEAD_MOVED: &str = "FA-REF-122";
    /// The book moved while the accumulator was computed.
    pub const BASIS_MOVED: &str = "FA-REF-123";
    /// A later state does not extend an earlier one.
    pub const NOT_EXTENDED: &str = "FA-REF-124";
    /// The selected known-at sequence is beyond the head.
    pub const BEYOND_HEAD: &str = "FA-REF-125";
    /// The requested scope is not one run of the scope index.
    pub const SCOPE_UNSUPPORTED: &str = "FA-REF-126";
    /// A journaled checkpoint is not what the journal and the book's key
    /// reproduce.
    pub const CHECKPOINT_INVALID: &str = "FA-REF-127";
    /// A bundle would inline a document its capability reads only as a
    /// redacted view.
    pub const INLINE_WITHHELD: &str = "FA-REF-128";
    /// A balance proof would count a migration chunk with unsupported
    /// visibility: its run has no Finalize in the prefix, or it predates
    /// the run's opening date. The latter may be summarized history or
    /// sole-source detail; v1 cannot authenticate that distinction (fa-e00).
    /// Missing or contradictory migration records also fail closed.
    pub const MIGRATION_STAGED: &str = "FA-REF-133";
}

/// What a checkpoint commits: the root over the first `leaf_count` leaves
/// of a book branch's journal — exactly the entries recorded at or before
/// `through_seq`. Encoded as `book_id ‖ branch_id ‖ through_seq u64 ‖
/// leaf_count u64 ‖ root` (80 bytes), the form every proof embeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statement {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub through_seq: CommitSeq,
    pub leaf_count: u64,
    pub root: [u8; 32],
}

impl Statement {
    pub fn encode(&self, w: &mut Writer) {
        w.fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u64(self.through_seq.0)
            .u64(self.leaf_count)
            .fixed(&self.root);
    }
}
