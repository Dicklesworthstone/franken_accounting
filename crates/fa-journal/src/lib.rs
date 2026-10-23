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

pub mod account_role;
pub mod allocation;
pub mod attestation;
pub mod bank;
pub mod batch;
pub mod blob;
pub mod carrying;
pub mod case;
pub mod chart;
pub mod closing;
pub mod custody;
pub mod draft;
pub mod engagement;
pub mod entity;
pub mod entry_history;
pub mod evidence;
pub mod finding_history;
pub mod fx;
pub mod genesis;
pub mod import;
pub mod issuance;
pub mod legal_hold;
pub mod limit;
pub mod migration;
pub mod object;
pub mod outcome;
pub mod period;
pub mod period_creation;
pub mod period_history;
pub mod plan;
pub mod policy;
pub mod post;
pub mod production;
pub mod projections;
pub mod rea;
pub mod redaction;
pub mod refusal;
pub mod revaluation;
pub mod rows;
pub mod scenario;
pub mod schedule;
pub mod scratch;
pub mod subledger;
pub mod sweep;
pub mod temporal;
pub mod upload;
pub mod usage;

pub use account_role::{
    AccountRoleControl, AccountRoleRecorded, AccountRoleSpec, AccountRoles, account_roles_at,
    record_account_role, role_control,
};
pub use allocation::AllocationPosting;
pub use attestation::{
    AttestationClaim, Attested, confirmation_received_by, confirmed_vid, read_attestation,
    record_confirmation, record_manual_assertion, record_representation, record_review,
    represented_vid,
};
pub use batch::{
    BatchPosted, OutcomeBody, commit_batch_plan, outcome_vid, plan_batch, plan_batch_with_history,
    post_batch, post_batch_with_crash, read_outcome, request_digest,
};
pub use blob::BlobStore;
pub use carrying::{
    CarryingOpenItem, FxSettlementRequest, PreparedFxSettlement, open_item_carrying_at,
    prepare_fx_settlement, remaining_carrying_relief,
};
pub use case::{
    CaseApproval, CaseBody, CaseKind, CaseManifest, CaseMember, CaseRecorded, CaseRequest,
    CaseState, CaseTransition, CaseView, Determination, Disclosure, ManifestEntry, PostedEntry,
    Rehearsal, approve_case, case_manifest, close_case, derive_member, determine_case,
    disclose_case, list_cases, open_case, post_case, posting_class, read_case, rehearse_case,
};
pub use chart::{
    AccountEffectivity, AccountLifecycleRecorded, ChartSnapshot, close_account, open_account,
    promote_to_summary,
};
pub use custody::{CustodyBody, CustodyEvent, CustodyMoved, custody_chain, transfer_custody};
pub use draft::{
    DraftBody, DraftClosure, DraftPlanned, DraftPromoted, DraftRecorded, DraftRehearsal,
    DraftRehearsalRequest, DraftRehearsalSource, DraftRequest, DraftSourceRecord, DraftState,
    DraftView, PlannedIntent, discard_draft, list_drafts, open_draft, plan_into_draft,
    promote_draft, read_draft, rehearse_draft_into,
};
pub use engagement::{
    AdjustmentDecided, AdjustmentDecision, AdjustmentProposed, AdjustmentState, Carried,
    CarriedForward, CarriedItem, CarryForward, CarryForwardView, CompletionView,
    DocumentationCompleted, DocumentationCompletion, EngagementKind, EngagementOpened,
    EngagementProfile, EngagementRequest, EngagementState, EngagementView, FindingFiled,
    FindingInIndex, Materiality, OutOfPeriodCorrection, OutOfPeriodItem, ProposalLeg, ProposalView,
    ProposedAdjustment, RecordedDecision, StatementEffect, Uncorrected, UncorrectedItem,
    UncorrectedSummary, WorkpaperConfirmation, WorkpaperFiled, WorkpaperRepresentation,
    WorkpaperView, carry_forward, complete_documentation, decide_adjustment, file_finding,
    file_workpaper, list_engagements, open_engagement, prior_period_error, propose_adjustment,
    read_engagement, superseder_at, uncorrected_misstatements, with_prior_period_error,
};
pub use entry_history::{EntryHistoryVerification, verify_entry_history};
pub use evidence::{
    DerivedExtractionInfo, DerivedFromDocumentSummary, Document, DocumentAdded,
    DocumentEvidenceSummary, DocumentRecord, EvidenceExplanation, ManualAssertionSummary,
    ReviewedSummary, Storage, SupplementSummary, add_document, add_document_external,
    document_record, explain_entry_evidence, fetch_document, fetch_document_with, read_document,
};
pub use fa_intents::{BatchPlan, BatchPlanCertificate, PostBatch, PostIntent, ReplacementPlan};
pub use fa_palimpsest::{
    LineageEdgeSummary, LineageEntrySummary, LineageReport, NetPosition, NettingLaw,
};
pub use fx::{
    FxConversionDrift, FxConversionVerification, FxLawId, FxRateDocument, FxRatePurpose,
    FxRateTerms, RATE_DOCUMENT_KIND, RATE_EVIDENCE_ROLE, fx_law_oid, is_registered_fx_law_oid,
    plan_realized_fx_settlement, plan_revaluation, value_proposal, verify_fx_conversions,
};
pub use genesis::{
    AccountSpec, BookContext, BookSpec, ChartInstalled, LegalEntitySpec, TimeZonePolicy,
    UnitPolicy, check_entity_functional_unit, create_book, create_periods, install_chart,
};
pub use import::{
    DerivedExtractionMetadata, ExtractionMethod, ImportRecorded, ImportRequest, RunReceipt,
    decode_derivation, decode_extraction_derivation, document_sources, encode_derivation,
    encode_extraction_derivation, import_run, verify_receipt, verify_receipt_in,
};
pub use issuance::{
    IssuancePlan, IssuanceRecord, IssuedTo, StatementIssuance, StatementsIssued, first_issuance,
    first_issued_to, issuances, issue_statements, list_issuances, plan_issuance,
};
pub use legal_hold::{
    HoldReach, LegalHold, LegalHoldPlaced, LegalHoldReleased, LegalHoldRequest, Pinned,
    ReleasePlan, active_legal_holds, place_legal_hold, plan_release, read_legal_hold,
    release_legal_hold,
};
pub use limit::{
    BalanceLimit, Balanced, LimitCell, LimitScope, cell_account, limit_cell_vid, period_cell_vid,
    post_balancing,
};
pub use migration::{
    PeriodBalance, Run, RunBody, RunChunk, RunControlRequest, RunControlled, RunMode, RunState,
    TieOut, TieOutLine, TrialBalanceLine, open_proposal, open_run, plan_run_transition,
    run_entries, tie_out, transition_run, visible_at,
};
pub use outcome::{
    OutcomeRebuild, OutcomeRebuildPreview, PreparedOutcomeRebuild, prepare_outcome_rebuild,
    publish_outcome_rebuild,
};
pub use period::{
    OriginallyReported, PeriodCheck, PeriodTransitionRecord, PeriodVerification,
    PreparedTransition, ReportedBasis, TransitionPlan, Transitioned, originally_reported,
    period_transitions, plan_transition, prepare_transition, transition_name, transition_period,
    transition_proposal, verify_periods,
};
pub use period_history::{PeriodHistoryVerification, verify_periods_with_history};
pub use plan::{
    commit_plan, commit_replacement_plan, plan_certificate_vid, plan_post, plan_post_with_history,
    plan_replacement, plan_replacement_with_history,
};
pub use policy::{
    ActivationRequest, ApprovalRequest, Approved, IssuanceRequest, Issued, IssuedCapability,
    PolicyActivated, RevocationRequest, Revoked, activate_policy, activation_proposal,
    issuance_vid, issue_capability, list_issued, read_issued, record_approval, revoke_capability,
    security_policy_epoch,
};
pub use post::{
    Capability, PostPreparation, PostRequest, Posted, PreparedPost, decide_admissibility_cell,
    explain_entry_lineage, post, post_replacement_pair, prepare_post, superseded_by,
};
pub use production::{
    BatesRange, Produced, ProducedDocument, ProducedRange, ProductionOpened, ProductionProfile,
    ProductionRequest, ProductionState, ProductionView, RecordedRange, document_ranges,
    list_productions, open_production, produce, read_production,
};
pub use rea::{
    DIMENSION_KIND_PARTY, EventRow, ExternalIdRow, InstrumentRow, LegalEntityRow, PartyRow,
    ReaControlRecorded, ReaSnapshot, RelatedPartyHit, RelationshipRow, bind_external_id,
    create_instrument, create_legal_entity, create_party, read_rea_at, record_event,
    record_relationship, relationship_edge_id, update_party_identifiers,
};
pub use redaction::{
    DocumentRead, RedactedView, ViewChunk, ViewDerived, derive_redacted_view, read_document_for,
    read_document_for_with, redacted_view_vid,
};
pub use refusal::{FieldChange, KernelError, Locus, Refusal, RefusalDetail, Why, exit};
pub use revaluation::{FxRevaluationRequest, PreparedFxRevaluation, prepare_fx_revaluation};
pub use rows::{AccountRow, PeriodRow};
pub use scenario::{
    RECEIVERSHIP, ReceivershipForked, ScenarioBody, ScenarioClosure, ScenarioFork,
    ScenarioRecorded, ScenarioRequest, ScenarioState, ScenarioView, discard_scenario,
    fork_receivership, list_scenarios, open_scenario, plan_into_scenario, read_scenario,
};
pub use schedule::{
    DueReversal, ReversalBatch, ReversalStatus, Schedule, ScheduleVerification, due_reversals,
    sweep_reversals_batch, verify_schedules, with_auto_reverse,
};
pub use scratch::{SeqMap, SeqPair, replay_into};
pub use subledger::{
    NativeSubledger, NativeSubledgerKind, NativeSubledgerRecorded, NativeSubledgerSpec,
    create_native_subledger, native_subledger_vid, native_subledgers_at,
};
pub use sweep::{
    DueHold, Op, Profile, SweepBatch, SweepRequest, Swept, Tick, TickRequest, Ticked, due_holds,
    latest_tick, record_tick, sweep, sweep_batch,
};
pub use temporal::{InstantSelection, resolve_instant_at};
pub use upload::{
    PreparedUpload, UploadPreparation, UploadRequest, prepare_upload, upload_document,
};
pub use usage::{UsageCell, UsageDebit, UsageKey, UsageVerification, verify_usage};

pub use projections::{ProjectionVerification, verify_projections};
