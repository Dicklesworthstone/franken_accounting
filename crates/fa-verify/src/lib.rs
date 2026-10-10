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
//!   entry's evidence cites ([`document::doc_commit`]).
//!
//! What it does not prove (plan §13.1): that an entry reflects what
//! actually happened, that a checkpoint was signed by anyone (signatures and
//! witnesses are not in this crate yet), or anything about a known-at later
//! than the checkpoint's `through_seq`.
//!
//! The crate carries its own BLAKE3 ([`blake3`]), its own canonical reader,
//! and its own tree arithmetic, and links no FrankenAccounting or substrate
//! crate: the producer and the verifier are independent implementations of
//! one specification, checked against each other by fa-notary's
//! differential tests and pinned to shared golden vectors. Independence
//! makes a shared bug less likely and the differential makes a divergence
//! visible; neither proves the specification itself sound.

#![forbid(unsafe_code)]

pub mod balance;
pub mod blake3;
pub mod codec;
pub mod document;
pub mod envelope;
pub mod proof;
pub mod state;
pub mod tree;

pub use balance::{Balance, BalanceClaim, verify_balance};
pub use codec::DecodeError;
pub use envelope::{LeafEnvelope, RecordError};
pub use proof::{
    Checkpoint, Consistency, Inclusion, Prefix, RecordCheck, VerifyError, verify_consistency,
    verify_inclusion, verify_prefix,
};
pub use state::{Signatures, State, verify_state};
