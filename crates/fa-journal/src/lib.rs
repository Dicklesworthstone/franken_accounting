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

pub mod attestation;
pub mod blob;
pub mod custody;
pub mod entity;
pub mod evidence;
pub mod genesis;
pub mod import;
pub mod limit;
pub mod migration;
pub mod period;
pub mod policy;
pub mod post;
pub mod refusal;
pub mod rows;
pub mod schedule;
pub mod scratch;
pub mod sweep;

pub use attestation::{
    AttestationClaim, Attested, read_attestation, record_manual_assertion, record_review,
};
pub use blob::BlobStore;
pub use custody::{CustodyBody, CustodyEvent, CustodyMoved, custody_chain, transfer_custody};
pub use evidence::{
    Document, DocumentAdded, DocumentRecord, Storage, add_document, add_document_external,
    document_record, fetch_document, read_document,
};
pub use genesis::{
    AccountSpec, BookContext, BookSpec, ChartInstalled, LegalEntitySpec, TimeZonePolicy,
    UnitPolicy, create_book, create_periods, install_chart,
};
// `import::read_run` stays module-qualified: `migration::read_run` reads a
// different object (CobaltGull 3474).
pub use import::{
    ImportRecorded, ImportRequest, RunReceipt, import_run, verify_receipt, verify_receipt_in,
};
pub use limit::{
    BalanceLimit, Balanced, LimitCell, LimitScope, cell_account, limit_cell_vid, period_cell_vid,
    post_balancing,
};
pub use migration::{
    Run, RunBody, RunChunk, RunControlRequest, RunControlled, RunMode, RunState, TieOut,
    TrialBalanceLine, open_proposal, open_run, plan_run_transition, tie_out, transition_run,
    visible_at,
};
pub use period::{
    TransitionPlan, Transitioned, plan_transition, transition_name, transition_period,
    transition_proposal,
};
pub use policy::{
    ActivationRequest, ApprovalRequest, Approved, PolicyActivated, RevocationRequest, Revoked,
    activate_policy, activation_proposal, record_approval, revoke_capability,
    security_policy_epoch,
};
pub use post::{Capability, PostRequest, Posted, post};
pub use refusal::{KernelError, Refusal, exit};
pub use rows::{AccountRow, PeriodRow};
pub use schedule::{
    DueReversal, ReversalBatch, ReversalStatus, Schedule, ScheduleVerification, due_reversals,
    sweep_reversals_batch, verify_schedules, with_auto_reverse,
};
pub use scratch::{SeqMap, SeqPair, replay_into};
pub use sweep::{
    DueHold, Op, Profile, SweepBatch, SweepRequest, Swept, Tick, TickRequest, Ticked, due_holds,
    latest_tick, record_tick, sweep, sweep_batch,
};
