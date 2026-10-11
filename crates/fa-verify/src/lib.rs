//! `fa-verify` — the dependency-free verifier (plan §13.3).
//!
//! An outsider holding a proof and a checkpoint they trust can check, with
//! nothing but this crate and `std`, that:
//!
//! - an entry's leaf envelope — and, when supplied, the entry's own payload
//!   bytes — was recorded in a book's journal at a given position within
//!   the checkpoint's prefix ([`verify_inclusion`], scope `inclusion`);
//! - a later checkpoint the producer claims — read from its state object
//!   with [`verify_state`] — extends the trusted one without rewriting
//!   history ([`verify_consistency`], scope `consistency`);
//! - a list of leaf envelopes is the *complete* prefix the checkpoint
//!   commits, so a scope predicate over it is complete for that prefix
//!   ([`verify_prefix`], scope `seq_range_complete`);
//! - an account's posted debits and credits in one unit, through a cutoff,
//!   are the fold of exactly the authenticated in-scope entries
//!   ([`verify_balance`], scope `recomputation`);
//! - a document's bytes and kind produce the public `doc_commit` an
//!   entry's evidence cites ([`document::doc_commit`]);
//! - a `TransparencyCheckpoint` was signed by keys the caller trusts
//!   ([`verify_checkpoint`], Ed25519);
//! - one account's entries with an effective day in an interval are all
//!   listed, against that checkpoint's signed scope-index root
//!   ([`verify_scope`], scope `scope_index_complete`), with the premise
//!   labelled: the signers, or the index recomputed from the complete
//!   prefix.
//!
//! What it does not prove (plan §13.1): that an entry reflects what
//! actually happened, that a signer's key belongs to anyone in particular
//! (the caller names the keys it trusts; there is no trust-anchor set or
//! witness policy yet), or anything about a known-at later than the
//! checkpoint's `through_seq`.
//!
//! The crate carries its own BLAKE3 ([`blake3`]), SHA-512 ([`sha512`]),
//! Ed25519 verification ([`ed25519`]), canonical reader, and tree
//! arithmetic, and links no FrankenAccounting or substrate crate: the
//! producer and the verifier are independent implementations of one
//! specification, checked against each other by fa-notary's differential
//! tests and pinned to shared golden vectors (RFC 8032 and RFC 6234 for the
//! signature scheme). Independence makes a shared bug less likely and the
//! differential makes a divergence visible; neither proves the
//! specification itself sound.

#![forbid(unsafe_code)]

pub mod balance;
pub mod blake3;
pub mod checkpoint;
pub mod codec;
pub mod document;
pub mod ed25519;
pub mod envelope;
pub mod proof;
pub mod scope;
pub mod sha512;
pub mod state;
pub mod tree;

pub use balance::{Balance, BalanceClaim, verify_balance};
pub use checkpoint::{CheckpointError, SignedCheckpoint, verify_checkpoint};
pub use codec::DecodeError;
pub use envelope::{LeafEnvelope, RecordError};
pub use proof::{
    Checkpoint, Consistency, Inclusion, Prefix, RecordCheck, VerifyError, verify_consistency,
    verify_inclusion, verify_prefix,
};
pub use scope::{IndexDerivation, ScopeClaim, ScopeReport, recompute_index, verify_scope};
pub use state::{Signatures, State, verify_state};
