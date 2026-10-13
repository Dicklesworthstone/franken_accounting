//! FrankenAccounting — the embedded library (`fa`).
//!
//! [`Book`] creates and opens memory or persisted books on FrankenGraphDB,
//! installs charts, transitions periods, admits postings, folds historical
//! reports, and verifies derived registers. It also publishes signed entry
//! accumulator checkpoints under witness authority, recomputes their journal
//! prefixes, and produces evidence bundles with detached production receipts.
//! Checkpoints cover their recorded prefixes, not later postings.
//!
//! [`AsyncBook`] takes the caller's purpose contexts and filesystem; [`Book`]
//! supplies a production runtime and delegates to the same implementation.
//! Recorded time comes from the substrate's commit stream.
//! [`AsyncBook`] also folds historical open-item snapshots and effective-date
//! aging with explicit buckets; those projections are not certified reports.
//! Summary trial balances preserve historical chart membership, exact native
//! units and leaf drilldown under a current whole-book read capability.
//! Trial balances, balance explanations and open items can carry retained-history
//! replay certificates binding the native reads, journal prefix, report selector,
//! historical account metadata, registries and exact output. Certificates may be
//! retained in the book and retrieved by their full content digest after reopen.
//! Typed posting intents can be rehearsed through the real kernel and
//! committed from an authenticated portable plan under current authority.
//! Their graph certificates are retained atomically with the resulting entry;
//! this slice requires an unchanged book sequence and existing approvals.
//! Sessions and drafts remain later slices of the embedded API described
//! in `COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md` (§15.2).

#![forbid(unsafe_code)]

pub mod aging;
pub mod async_book;
pub mod book;
pub mod certificate;
mod certificate_store;
pub mod proof;
pub mod statements;
pub mod summary;
pub mod upload;

pub use aging::{
    AgedOpenItem, AgingAmounts, AgingBand, AgingBuckets, AgingCell, AgingTotal, EffectiveDateAging,
    OpenItemSnapshot,
};
pub use async_book::AsyncBook;
pub use book::{Book, BookError, BookKeys, Entropy, Outcome, ProducedBundle};
pub use certificate::{
    CertificateStatus, CertifiedReport, CertifiedTrialBalance, ReportCertificate, ReportOutput,
    ReportSelection, TrialBalanceSelection,
};
pub use certificate_store::RetainedCertificate;
pub use fa_intents::{IntentError, MAX_PLAN_BYTES, PlanCertificate, PostIntent, PostPlan};
pub use fa_journal::{InstantSelection, UploadRequest};
pub use fa_notary::{
    AccumulatorVerification, BalanceRequest, BundleRequest, BundleScope, Checkpointed,
};
pub use fa_policy::{Capability, Op, Profile};
pub use fa_registers::Advance;
pub use fa_registers::open_items::OpenItemsReport;
pub use fa_statements::{
    AccountMapping, Column as StatementColumn, Statement, StatementDefinition, StatementKind,
    StatementLine,
};
pub use proof::{MAX_PROOF_BYTES, ProofArtifact, ProofKind, ProofRequest};
pub use statements::{CertifiedStatement, StatementSelection};
pub use summary::{SummaryGroup, SummaryRequest, SummaryScope, SummaryTrialBalance};
