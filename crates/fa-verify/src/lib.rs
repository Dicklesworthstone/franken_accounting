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
//!   prefix;
//! - an evidence bundle (`.fab`) is what its manifest says — its entries
//!   exactly the scope's leaves with their payloads, each entry's cited
//!   documents present and, when included, matching their commitments,
//!   its balances recomputed under the fold law they name — and its
//!   detached production receipt was signed over it ([`verify_bundle`],
//!   each predicate graded on its own).
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
pub mod bundle;
pub mod checkpoint;
pub mod cli;
pub mod codec;
pub mod document;
pub mod ed25519;
pub mod envelope;
pub mod migration_balance;
pub mod proof;
pub mod scope;
pub mod sha512;
pub mod state;
pub mod tree;

pub use balance::{Balance, BalanceClaim};
pub use bundle::{
    BundleCheck, BundleError, BundleReport, BundleScope, Completeness, Grade, Manifest,
    ReceiptFacts, Summary, verify_bundle,
};
pub use checkpoint::{CheckpointError, SignedCheckpoint, verify_checkpoint};
pub use codec::DecodeError;
pub use envelope::{LeafEnvelope, RecordError};
pub use proof::{
    Checkpoint, Consistency, Inclusion, Prefix, RecordCheck, VerifyError, verify_consistency,
    verify_inclusion, verify_prefix,
};
pub use scope::{IndexDerivation, ScopeClaim, ScopeReport, recompute_index, verify_scope};
pub use state::{Signatures, State, verify_state};

/// Verify either supported balance format against an independently trusted
/// checkpoint. V1 remains byte-compatible for non-migration scopes; v2
/// authenticates the migration lifecycle and required run-body policies.
/// Neither format accepts a checkpoint merely because the proof supplies it.
pub fn verify_balance(
    proof: &[u8],
    trusted_checkpoint: &Checkpoint,
) -> Result<Balance, VerifyError> {
    let mut reader = codec::Reader::new(proof);
    if reader.bytes(128, "proof.format")? == migration_balance::BALANCE_FORMAT_V2 {
        migration_balance::verify_balance(proof, trusted_checkpoint)
    } else {
        balance::verify_balance(proof, trusted_checkpoint)
    }
}

#[cfg(test)]
mod balance_dispatch_tests {
    use super::*;

    #[test]
    fn public_balance_verifier_accepts_both_versions_without_changing_v1() {
        let checkpoint = Checkpoint {
            book_id: [1; 16],
            branch_id: [0; 16],
            through_seq: 0,
            leaf_count: 0,
            root: tree::empty_root(),
        };
        for format in [balance::BALANCE_FORMAT, migration_balance::BALANCE_FORMAT_V2] {
            let mut w = codec::Writer::default();
            w.bytes(format)
                .fixed(&checkpoint.encode())
                .u128(10)
                .u32(1)
                .u8(0)
                .i128(0)
                .i128(0)
                .count(0)
                .count(0);
            if format == migration_balance::BALANCE_FORMAT_V2 {
                w.count(0);
            }
            let report = verify_balance(&w.buf, &checkpoint).unwrap();
            assert_eq!(report.scope, "recomputation");
            assert!(report.contributing.is_empty());
            assert_eq!((report.claim.debits, report.claim.credits), (0, 0));
            if format == balance::BALANCE_FORMAT {
                assert_eq!(balance::verify_balance(&w.buf, &checkpoint).unwrap(), report);
            }
        }
    }
}
