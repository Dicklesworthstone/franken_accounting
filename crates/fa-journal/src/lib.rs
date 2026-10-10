//! Folio — the posting kernel (plan §5, §7.3, §8.4).
//!
//! The kernel is a set of async functions over the substrate's `Database`
//! and the purpose-typed contexts it requires. It owns no runtime: the `fa`
//! facade drives it under asupersync and the daemon drives it under the lab
//! runtime. Every function here either commits exactly one substrate
//! transaction or refuses with a typed [`Refusal`] that names the law, the
//! cell, and the fix — a refusal is a value, never a panic and never a
//! partial write.
//!
//! Constitution honoured here (plan §1): recorded time is the commit sequence
//! the substrate assigns; the journal is append-only (no edit-in-place, no
//! void bit); period law is checked inside the transaction that reads the
//! period's state, so a post racing a close is a first-committer-wins
//! conflict; identities are derived, never allocated; a suggested residual leg
//! appears in a refusal, never in a commit.

#![forbid(unsafe_code)]

pub mod evidence;
pub mod genesis;
pub mod limit;
pub mod period;
pub mod policy;
pub mod post;
pub mod refusal;
pub mod rows;

pub use evidence::{Document, DocumentAdded, add_document, read_document};
pub use genesis::{
    AccountSpec, BookContext, BookSpec, ChartInstalled, UnitPolicy, create_book, create_periods,
    install_chart,
};
pub use limit::{BalanceLimit, LimitCell, cell_account, limit_cell_vid};
pub use period::{Transitioned, transition_period};
pub use policy::{
    ActivationRequest, ApprovalRequest, Approved, PolicyActivated, activate_policy,
    activation_proposal, record_approval, security_policy_epoch,
};
pub use post::{Capability, PostRequest, Posted, post};
pub use refusal::{KernelError, Refusal, exit};
pub use rows::{AccountRow, PeriodRow};
