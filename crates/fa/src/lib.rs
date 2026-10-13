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
//! [`AsyncBook`] also folds historical open-item snapshots and effective-date
//! aging with explicit buckets; those projections are not certified reports.
//! Summary trial balances preserve historical chart membership, exact native
//! units and leaf drilldown under a current whole-book read capability.
//! [`SummaryCertificate`] composes a retained-history source certificate with
//! the root selector and exact summary output; AsyncBook can certify and replay
//! it under caller authority without publishing a journal object.
//! Trial balances, balance explanations and open items can carry retained-history
//! replay certificates binding the native reads, journal prefix, report selector,
//! historical account metadata, registries and exact output. Certificates may be
//! retained in the book and retrieved by their full content digest after reopen.
//! Typed posting intents can be rehearsed through the real kernel and
//! committed from an authenticated portable plan under current authority.
//! Their graph certificates are retained atomically with the resulting entry;
//! this slice requires an unchanged book sequence and existing approvals.
//! Explicit receivable/payable allocations can be prepared for approval and
//! rehearsed through that same kernel with [`SettlementPostRequest`]. The
//! unchanged portable plan supports atomic publication and exact retries.
//! [`SettlementGroupRequest`] prepares disjoint selections on multiple legs of
//! one complete entry; the kernel publishes all applications atomically.
//! [`SettlementReview`] preserves the sealed proposal and observed allocations
//! across approval publications and process restarts. Explicit revalidation
//! requires the same proposal and amounts; a review itself grants no authority.
//! [`Book::export_document_disclosure`] and its async counterpart export only
//! requested permitted chunks under current read/produce authority, retaining
//! the protected reader's governed redactions for offline membership checks.
//! [`Book::export_evidence_disclosure`] binds that protected export to an exact
//! journal entry and citation role, with its independent inclusion proof.
//! Sessions, drafts, signed transparency
//! checkpoints and bundles remain later slices of the embedded API described
//! in `COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md` (§15.2).

#![forbid(unsafe_code)]

pub mod aging;
pub mod allocation_review;
pub mod async_book;
pub mod balance_allocation;
pub mod book;
pub mod certificate;
mod certificate_store;
pub mod document_disclosure;
pub mod evidence_disclosure;
pub mod general_ledger;
pub mod proof;
pub mod roll_forward;
pub mod settlement;
pub mod settlement_group;
pub mod settlement_group_review;
pub mod settlement_review;
pub mod statement_diff;
pub mod statement_diff_workpaper;
pub mod statement_trace;
pub mod statements;
pub mod summary;
pub mod summary_certificate;
pub mod upload;

pub use aging::{
    AgedOpenItem, AgingAmounts, AgingBand, AgingBuckets, AgingCell, AgingTotal, EffectiveDateAging,
    OpenItemSnapshot,
};
pub use allocation_review::{AllocationReview, AllocationReviewError, MAX_ALLOCATION_REVIEW_BYTES};
pub use async_book::AsyncBook;
pub use balance_allocation::{
    BalanceAllocationRequest, MAX_BALANCE_ALLOCATION_CONTRIBUTIONS, PreparedBalanceAllocation,
};
pub use book::{Book, BookError, BookKeys, Entropy, Outcome};
pub use certificate::{
    CertificateStatus, CertifiedReport, CertifiedTrialBalance, ReportCertificate, ReportOutput,
    ReportSelection, TrialBalanceSelection,
};
pub use certificate_store::RetainedCertificate;
pub use document_disclosure::{DisclosureAccess, DocumentDisclosureArtifact};
pub use evidence_disclosure::{EvidenceDisclosureArtifact, EvidenceDisclosureRequest};
pub use fa_intents::{IntentError, MAX_PLAN_BYTES, PlanCertificate, PostIntent, PostPlan};
pub use fa_journal::{AllocationPosting, InstantSelection, UploadRequest};
pub use fa_notary::{AccumulatorVerification, Checkpointed};
pub use fa_policy::{Capability, Op, Profile};
pub use fa_registers::Advance;
pub use fa_registers::open_items::OpenItemsReport;
pub use fa_statements::{
    AccountMapping, Column as StatementColumn, Statement, StatementDefinition, StatementKind,
    StatementLine,
};
pub use general_ledger::{
    GENERAL_LEDGER_FORMAT, GeneralLedger, GeneralLedgerCell, GeneralLedgerLine,
    MAX_GENERAL_LEDGER_BYTES, MAX_GENERAL_LEDGER_CELLS, MAX_GENERAL_LEDGER_LINES,
};
pub use proof::{MAX_PROOF_BYTES, ProofArtifact, ProofKind, ProofRequest};
pub use roll_forward::{RollForward, RollForwardRequest};
pub use settlement::{PreparedSettlement, SettlementPostPlan, SettlementPostRequest};
pub use settlement_group::{
    MAX_SETTLEMENT_GROUP_LEGS, MAX_SETTLEMENT_GROUP_TARGETS, PreparedSettlementGroup,
    SettlementGroupPostPlan, SettlementGroupRequest, SettlementLegAllocation, SettlementLegSelection,
};
pub use settlement_group_review::{MAX_SETTLEMENT_GROUP_REVIEW_BYTES, SettlementGroupReview};
pub use settlement_review::{
    MAX_SETTLEMENT_REVIEW_BYTES, SettlementReview, SettlementReviewError,
};
pub use statement_diff::{
    CertifiedStatementDiff, MAX_STATEMENT_DIFF_CERTIFICATE_BYTES, StatementDiff,
    StatementDiffCertificate, StatementDiffRequest, StatementLineChange, StatementMappingChange,
};
pub use statement_diff_workpaper::{MAX_STATEMENT_DIFF_WORKPAPER_BYTES, StatementDiffWorkpaper};
pub use statement_trace::{
    CertifiedStatementTrace, MAX_STATEMENT_TRACE_BYTES, MAX_STATEMENT_TRACE_CERTIFICATE_BYTES,
    MAX_STATEMENT_TRACE_PUBLICATIONS, StatementEntryEvent,
    StatementEntryLink, StatementPublication, StatementTrace, StatementTraceCertificate, StatementTraceRequest,
};
pub use statements::{CertifiedStatement, StatementSelection};
pub use summary::{SummaryGroup, SummaryRequest, SummaryScope, SummaryTrialBalance};
pub use summary_certificate::{
    CertifiedSummaryTrialBalance, MAX_SUMMARY_CERTIFICATE_BYTES, SummaryCertificate,
    SummaryCertificateStatus,
};
