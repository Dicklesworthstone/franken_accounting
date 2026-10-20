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
//! [`BalanceAllocationReview`] retains a journal-derived allocation
//! source selector and expectation together with the exact sealed proposal.
//! Its bounded transport survives process restarts without recreating a
//! trusted source observation or granting approval/posting authority.
//! [`CashFlowCertificate`] binds explicit cash classifications and exact output
//! to a retained native ledger closure. Replay checks current authority and the
//! recipient's independently selected fixed scope and classification inputs.
//! Existing draft intent logs can be rehearsed atomically for review.
//! [`DraftDiffCertificate`] binds their complete historical source and exact
//! balance comparison without promoting the draft or changing trunk (§15.2).

#![forbid(unsafe_code)]

pub mod aging;
pub mod allocation_review;
pub mod async_book;
pub mod balance_allocation;
pub mod balance_allocation_review;
pub mod bank;
pub mod book;
pub mod cash_flow_certificate;
pub mod cash_flow_policy;
pub mod cash_flow_split;
pub mod certificate;
mod certificate_store;
pub mod document_disclosure;
pub mod draft_review;
pub mod evidence_disclosure;
pub mod findings;
pub mod fx;
pub mod fx_revaluation;
pub mod general_ledger;
pub mod indirect_cash_flow;
pub mod intake;
pub mod interop;
pub mod procedure_certificate;
pub mod production;
pub mod projections;
pub mod proof;
pub mod report_artifact;
pub mod roll_forward;
pub mod scenario;
pub mod search;
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

#[cfg(test)]
mod period_history_tests;

pub use aging::{
    AGING_CERTIFICATE_FORMAT, AGING_OUTPUT_FORMAT, AgedOpenItem, AgingAmounts, AgingBand,
    AgingBuckets, AgingCell, AgingCertificate, AgingReconciliation, AgingReconciliationCertificate,
    AgingReconciliationRequest, AgingReconciliationRow, AgingRequest, AgingTotal, CertifiedAging,
    CertifiedAgingReconciliation, EffectiveDateAging, MAX_AGING_BUCKET_BOUNDS,
    MAX_AGING_CERTIFICATE_BYTES, MAX_AGING_RECONCILIATION_BYTES, OpenItemSnapshot,
};
pub use allocation_review::{AllocationReview, AllocationReviewError, MAX_ALLOCATION_REVIEW_BYTES};
pub use async_book::AsyncBook;
pub use balance_allocation::{
    BalanceAllocationRequest, MAX_BALANCE_ALLOCATION_CONTRIBUTIONS, PreparedBalanceAllocation,
};
pub use balance_allocation_review::{BalanceAllocationReview, MAX_BALANCE_ALLOCATION_REVIEW_BYTES};
pub use bank::{
    BankConfirmationRequest, BankConfirmationStatus, BankDecisionRef, BankMatchConfirmation,
    BankMatchHistory, BankMatchLineage, BankMatchRecorded, BankStatusRequest, BankUnmatchRecorded,
    BankUnmatchRequest,
};
pub use book::{Book, BookError, BookKeys, Entropy, Outcome, ProducedBundle, ReadScope};
pub use cash_flow_certificate::{
    CASH_FLOW_CERTIFICATE_FORMAT, CashFlowCertificate, CertifiedCashFlow,
    MAX_CASH_FLOW_CERTIFICATE_BYTES,
};
pub use certificate::{
    CertificateStatus, CertifiedReport, CertifiedTrialBalance, ReportCertificate, ReportOutput,
    ReportSelection, TrialBalanceSelection,
};
pub use certificate_store::{MAX_INLINE_CERTIFICATE_BYTES, RetainedCertificate};
pub use document_disclosure::{DisclosureAccess, DocumentDisclosureArtifact};
pub use draft_review::{
    CertifiedDraftDiff, DRAFT_DIFF_CERTIFICATE_FORMAT, DRAFT_DIFF_OUTPUT_FORMAT, DraftDiff,
    DraftDiffCertificate, DraftDiffRow, MAX_DRAFT_DIFF_CERTIFICATE_BYTES, MAX_DRAFT_DIFF_ROWS,
};
pub use evidence_disclosure::{EvidenceDisclosureArtifact, EvidenceDisclosureRequest};
pub use fa_docket::search::{SearchHit, SearchRecordId, SearchRecordKind};
pub use fa_intents::{
    IntentError, MAX_BATCH_BYTES, MAX_PLAN_BYTES, PlanCertificate, PostBatch, PostIntent, PostPlan,
    ReplacementPlan,
};
pub use fa_journal::chart::{ClosingRoutes, ClosingRoutesRecorded, ClosingRoutesRequest};
pub use fa_journal::closing::{
    ClosingRecord, ClosingResidual, PreparedYearEndClose, YearEndCloseRequest,
    YearEndCloseVerification,
};
pub use fa_journal::{
    AccountEffectivity, AccountLifecycleRecorded, AllocationPosting, DocumentEvidenceSummary,
    EventRow, EvidenceExplanation, ExternalIdRow, InstantSelection, InstrumentRow, LegalEntityRow,
    LineageEdgeSummary, LineageEntrySummary, LineageReport, ManualAssertionSummary, NetPosition,
    NettingLaw, PartyRow, PeriodBalance, PeriodCheck, PeriodHistoryVerification,
    PeriodTransitionRecord, PeriodVerification, ReaControlRecorded, ReaSnapshot, RelatedPartyHit,
    RelationshipRow, ReviewedSummary, RevocationRequest, Revoked, Run, RunBody, RunChunk,
    RunControlRequest, RunControlled, RunMode, RunState, ScheduleVerification, SupplementSummary,
    TieOut, TieOutLine, TrialBalanceLine, UploadRequest, UsageVerification,
};
pub use fa_model::{
    EventKind, EventResource, EventSpec, InstrumentKind, InstrumentSpec, PartyKind, PartySpec,
    event_vid, instrument_vid, party_vid,
};
pub use fa_money::allocation::{
    AllocationMethod, AllocationOutcome, AllocationRequest, AllocationTarget,
};
pub use fa_notary::{
    AccumulatorVerification, BalanceRequest, BundleRequest, BundleScope, Checkpointed, LeafKinds,
    ScopeRequest,
};
pub use fa_policy::{
    BenefitInterval, Capability, DECISION_CARD_DOMAIN, DecisionCandidate, DecisionCard,
    DecisionFeature, DecisionKind, DecisionPolicyRow, DecisionReason, DecisionReplayError, Op,
    Profile, amounts_preserved, decide_lantern_threshold, decide_register_checkpoint_cadence,
    evaluate_decision,
};
pub use fa_registers::open_items::OpenItemsReport;
pub use fa_registers::{
    Advance, EntityCell, EntityCellKey, EntityFold, EntityVerification, LotDisposalPlan,
    LotDisposalRequest, LotDisposalSlice, LotItem, LotReliefEdge, LotsReport, RegisterEquals,
};
pub use fa_statements::markdown::{
    StatementMarkdownIr, TrialBalanceIrInput, TrialBalanceIrRow, UnitFormatSpec,
    render_statement_ir, render_trial_balance_ir,
};
pub use fa_statements::render::{
    StatementRenderFormat, format_utc_epoch_iso8601, render_html, render_pdf, render_pdfa,
    render_svg, validate_pdfa2b,
};
pub use fa_statements::{
    AccountMapping, Column as StatementColumn, Statement, StatementDefinition, StatementError,
    StatementKind, StatementLine,
};
pub use findings::{RecordedFindings, finding_run_vid, finding_vid};
pub use fx::{FX_RATE_MIME, FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms};
pub use fx_revaluation::{
    FxRevaluationRequest, FxRevaluationRoute, FxRevaluationRoutes, FxRevaluationRoutesRecorded,
    FxRevaluationRoutesRequest, PreparedFxRevaluation,
};
pub use general_ledger::{
    CASH_FLOW_FORMAT, CashFlow, CashFlowActivity, CashFlowAssignment, CashFlowDefinition,
    CashFlowSection, CashFlowUnit, CertifiedGeneralLedger, GENERAL_LEDGER_FORMAT,
    GENERAL_LEDGER_WORKPAPER_FORMAT, GeneralLedger, GeneralLedgerCell, GeneralLedgerLine,
    MAX_GENERAL_LEDGER_BYTES, MAX_GENERAL_LEDGER_CELLS, MAX_GENERAL_LEDGER_LINES,
};
pub use indirect_cash_flow::{
    AdjustmentCategory, AdjustmentSign, CertifiedIndirectCashFlow,
    INDIRECT_CASH_FLOW_CERTIFICATE_FORMAT, INDIRECT_CASH_FLOW_FORMAT, IndirectCashFlow,
    IndirectCashFlowAdjustment, IndirectCashFlowCertificate, IndirectCashFlowContribution,
    IndirectCashFlowDefinition, IndirectCashFlowRequest, IndirectCashFlowUnit,
    MAX_INDIRECT_CASH_FLOW_BYTES, MAX_INDIRECT_CASH_FLOW_CERTIFICATE_BYTES,
};
pub use intake::IntakeAction;
pub use procedure_certificate::{
    BANK_PROCEDURE_CERTIFICATE_FORMAT, CERTIFIABLE_PROCEDURES, CertifiedProcedure,
    MAX_PROCEDURE_CERTIFICATE_BYTES, PROCEDURE_CERTIFICATE_FORMAT, PROCEDURE_OUTPUT_FORMAT,
    ProcedureCertificate, ProcedureRequest,
};
pub use production::{
    BundleDelivery, DEFAULT_VOLUME as DEFAULT_PRODUCTION_VOLUME, PrivilegeClaims, PrivilegeEntry,
    ProductionVolume,
};
pub use projections::{PreparedProjectionRebuild, ProjectionRebuild};
pub use proof::{MAX_PROOF_BYTES, ProofArtifact, ProofKind, ProofRequest};
pub use report_artifact::{
    MAX_REPORT_ARTIFACT_BYTES, ReplayedReportArtifact, ReportArtifact, ReportArtifactExpectation,
    ReportArtifactFamily,
};
pub use roll_forward::{
    CertifiedRollForward, MAX_ROLL_FORWARD_CERTIFICATE_BYTES, MAX_ROLL_FORWARD_WORKPAPER_BYTES,
    ROLL_FORWARD_CERTIFICATE_FORMAT, RollForward, RollForwardCertificate, RollForwardRequest,
};
pub use scenario::{
    CertifiedScenarioDiff, LEGACY_SCENARIO_DIFF_CERTIFICATE_FORMAT,
    SCENARIO_DIFF_CERTIFICATE_FORMAT, SCENARIO_DIFF_OUTPUT_FORMAT, ScenarioBook, ScenarioDiff,
    ScenarioDiffCertificate, ScenarioDiffRow, ScenarioRun,
};
pub use search::SearchResults;
pub use settlement::{PreparedSettlement, SettlementPostPlan, SettlementPostRequest};
pub use settlement_group::{
    MAX_SETTLEMENT_GROUP_LEGS, MAX_SETTLEMENT_GROUP_TARGETS, PreparedSettlementGroup,
    SettlementGroupPostPlan, SettlementGroupRequest, SettlementLegAllocation,
    SettlementLegSelection,
};
pub use settlement_group_review::{MAX_SETTLEMENT_GROUP_REVIEW_BYTES, SettlementGroupReview};
pub use settlement_review::{MAX_SETTLEMENT_REVIEW_BYTES, SettlementReview, SettlementReviewError};
pub use statement_diff::{
    CertifiedStatementDiff, MAX_STATEMENT_DIFF_CERTIFICATE_BYTES, StatementDiff,
    StatementDiffCertificate, StatementDiffRequest, StatementLineChange, StatementMappingChange,
};
pub use statement_diff_workpaper::{MAX_STATEMENT_DIFF_WORKPAPER_BYTES, StatementDiffWorkpaper};
pub use statement_trace::{
    CertifiedStatementTrace, MAX_STATEMENT_TRACE_BYTES, MAX_STATEMENT_TRACE_CERTIFICATE_BYTES,
    MAX_STATEMENT_TRACE_PUBLICATIONS, StatementEntryEvent, StatementEntryLink,
    StatementPublication, StatementTrace, StatementTraceCertificate, StatementTraceRequest,
};
pub use statements::{CertifiedStatement, StatementSelection};
pub use summary::{SummaryGroup, SummaryRequest, SummaryScope, SummaryTrialBalance};
pub use summary_certificate::{
    CertifiedSummaryTrialBalance, MAX_SUMMARY_CERTIFICATE_BYTES, SummaryCertificate,
    SummaryCertificateStatus,
};
