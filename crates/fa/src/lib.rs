//! FrankenAccounting — the embedded library (`fa`).
//!
//! [`Book`] creates and opens memory or persisted books on FrankenGraphDB,
//! installs charts, transitions periods, admits postings, folds historical
//! reports, and verifies derived registers. It also publishes unsigned entry
//! accumulator checkpoints under witness authority and recomputes their
//! journal prefixes. These checkpoints do not certify later postings or
//! document receipts.
//!
//! [`AsyncBook`] takes the caller's purpose contexts and filesystem; [`Book`]
//! supplies a production runtime and delegates to the same implementation.
//! Recorded time comes from the substrate's commit stream.
//! Sessions, dry-run plans, certified reports, drafts, signed transparency
//! checkpoints and bundles remain later slices of the embedded API described
//! in `COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md` (§15.2).

#![forbid(unsafe_code)]

pub mod async_book;
pub mod book;

pub use async_book::AsyncBook;
pub use book::{Book, BookError, BookKeys, Entropy, Outcome};
pub use fa_notary::{AccumulatorVerification, Checkpointed};
pub use fa_policy::{Capability, Op, Profile};
pub use fa_registers::Advance;
