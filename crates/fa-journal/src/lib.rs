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

pub mod allocation;
pub mod attestation;
pub mod blob;
pub mod chart;
pub mod custody;
pub mod entity;
pub mod entry_history;
pub mod evidence;
pub mod fx;
pub mod genesis;
pub mod import;
pub mod legal_hold;
pub mod limit;
pub mod migration;
pub mod period;
pub mod plan;
pub mod policy;
pub mod post;
pub mod projections;
pub mod redaction;
pub mod refusal;
pub mod rows;
pub mod schedule;
pub mod scratch;
pub mod sweep;
pub mod temporal;
pub mod upload;

pub use allocation::AllocationPosting;
pub use attestation::{
    AttestationClaim, Attested, read_attestation, record_manual_assertion, record_review,
};
pub use blob::BlobStore;
pub use custody::{CustodyBody, CustodyEvent, CustodyMoved, custody_chain, transfer_custody};
pub use entry_history::{EntryHistoryVerification, verify_entry_history};
pub use evidence::{
    Document, DocumentAdded, DocumentEvidenceSummary, DocumentRecord, EvidenceExplanation,
    ManualAssertionSummary, ReviewedSummary, Storage, SupplementSummary, add_document,
    add_document_external, document_record, explain_entry_evidence, fetch_document,
    fetch_document_with, read_document,
};
pub use fa_palimpsest::{
    LineageEdgeSummary, LineageEntrySummary, LineageReport, NetPosition, NettingLaw,
};
pub use fx::{
    FxLawId, FxRateDocument, FxRatePurpose, RATE_DOCUMENT_KIND, RATE_EVIDENCE_ROLE, fx_law_oid,
    is_registered_fx_law_oid, plan_realized_fx_settlement, plan_revaluation, value_proposal,
};
pub use genesis::{
    AccountSpec, BookContext, BookSpec, ChartInstalled, LegalEntitySpec, TimeZonePolicy,
    UnitPolicy, create_book, create_periods, install_chart,
};
pub use import::{
    ImportRecorded, ImportRequest, RunReceipt, import_run, verify_receipt, verify_receipt_in,
};
pub use legal_hold::{
    LegalHold, LegalHoldPlaced, LegalHoldReleased, LegalHoldRequest, Pinned, ReleasePlan,
    active_legal_holds, place_legal_hold, plan_release, read_legal_hold, release_legal_hold,
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
pub use period::{
    PeriodCheck, PeriodTransitionRecord, PeriodVerification, PreparedTransition, TransitionPlan,
    Transitioned, period_transitions, plan_transition, prepare_transition, transition_name,
    transition_period, transition_proposal, verify_periods,
};
pub use plan::{commit_plan, plan_certificate_vid, plan_post};
pub use policy::{
    ActivationRequest, ApprovalRequest, Approved, PolicyActivated, RevocationRequest, Revoked,
    activate_policy, activation_proposal, record_approval, revoke_capability,
    security_policy_epoch,
};
pub use post::{
    Capability, PostPreparation, PostRequest, Posted, PreparedPost, decide_admissibility_cell,
    explain_entry_lineage, post, post_replacement_pair, prepare_post, superseded_by,
};
pub use redaction::{
    DocumentRead, RedactedView, ViewChunk, ViewDerived, derive_redacted_view, read_document_for,
    read_document_for_with, redacted_view_vid,
};
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
pub use temporal::{InstantSelection, resolve_instant_at};
pub use upload::{
    PreparedUpload, UploadPreparation, UploadRequest, prepare_upload, upload_document,
};

pub use projections::{ProjectionVerification, verify_projections};
